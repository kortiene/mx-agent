//! Signed `exec` request routing and authorization (architecture §7.2, §13).
//!
//! Raw `exec` is the most privileged remote operation: it runs an arbitrary
//! command on the target agent's host. A caller builds a
//! `com.mxagent.exec.request.v1` timeline event, signs its content with the
//! daemon's Ed25519 key (see [`crate::signing`]), and sends it into a workspace
//! room with [`send_exec_request`]. Matrix federates the event to the target
//! agent's daemon, which receives it through `/sync`.
//!
//! Before spawning anything, the receiving daemon runs the verification
//! pipeline in [`authorize_exec_request`]:
//!
//! 1. **Signature** — the content must carry a valid detached signature over
//!    its [canonical JSON][mx_agent_protocol::canonical_json] (the `signature`
//!    field excluded). Missing signatures are [`ExecRejection::Unsigned`];
//!    invalid ones are [`ExecRejection::InvalidSignature`].
//! 2. **Routing** — the request's `target_agent` must name this daemon's local
//!    agent; misrouted requests are [`ExecRejection::WrongTarget`].
//! 3. **Trust** — the signing key must be present and trusted in the daemon's
//!    local [`TrustStore`]. Unknown or revoked keys are
//!    [`ExecRejection::UntrustedKey`].
//! 4. **Policy** — the requested command must be permitted for the requesting
//!    agent in the request's room by the local [`Policy`]. Denials are
//!    [`ExecRejection::PolicyDenied`].
//!
//! Only when all checks pass is the request authorized. The daemon then emits a
//! `com.mxagent.exec.accepted.v1` and creates an invocation state record; on
//! any rejection it emits a `com.mxagent.exec.rejected.v1` carrying a stable,
//! machine-readable reason and spawns nothing.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ed25519_dalek::{SigningKey, VerifyingKey};
use matrix_sdk::Room;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use mx_agent_policy::{
    Allowance, DenyReason, ExecContext, NetworkPolicy, Outcome, Policy, Sandbox,
};
use mx_agent_protocol::events::state::INVOCATION;
use mx_agent_protocol::events::timeline::{
    EXEC_ACCEPTED, EXEC_CANCEL, EXEC_CANCELLED, EXEC_FINISHED, EXEC_REJECTED, EXEC_REQUEST,
    EXEC_STDIN, PTY_RESIZE, STREAM_ARTIFACT, STREAM_CHUNK,
};
use mx_agent_protocol::schema::{
    AgentState, ExecAccepted, ExecCancel, ExecCancelled, ExecFinished, ExecRejected, ExecRequest,
    ExecStdin, InvocationState, PtyResize, Signature, StreamChunk, StreamKind,
};
use mx_agent_protocol::signing::{self, SignatureError, SIGNATURE_FIELD};

use crate::audit::{append_audit, AuditRecord};
use crate::pty::{PtySession, PtyWinsize};
use crate::runner::{
    build_command, kill_process_group, terminate_process_group, RunOutput, RunSpec,
};
use crate::stream::{
    capture_child_output, CaptureLimiter, CaptureSummary, OutputCaps, StreamCaptureConfig,
};
use crate::trust::TrustStore;
use crate::workspace::{send_workspace_state, WorkspaceError};

type StdinFrame = Option<Vec<u8>>;

#[derive(Debug, Clone)]
struct LiveExecControl {
    requester_agent: String,
    stdin: tokio::sync::mpsc::Sender<StdinFrame>,
    cancel: tokio::sync::watch::Sender<Option<String>>,
    /// Live terminal-resize channel for an interactive PTY invocation; `None`
    /// for non-PTY exec, which has no terminal to resize.
    resize: Option<tokio::sync::mpsc::Sender<PtyWinsize>>,
    /// Nonces of control frames (`exec.stdin` / `exec.cancel` / `pty.resize`)
    /// already applied to this live session. Shared across clones — handlers
    /// operate on a clone of the control — so a re-delivered (replayed) frame
    /// carrying a previously seen nonce is dropped for the session lifetime
    /// (issue #305). In-memory only and not persisted: a daemon restart kills
    /// every live session, so a post-restart control replay is already dropped
    /// at the no-live-control guard.
    seen_control_nonces: Arc<Mutex<HashSet<String>>>,
}

static LIVE_EXEC_CONTROLS: OnceLock<Mutex<HashMap<String, LiveExecControl>>> = OnceLock::new();

fn live_exec_controls() -> &'static Mutex<HashMap<String, LiveExecControl>> {
    LIVE_EXEC_CONTROLS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn insert_live_exec_control(invocation_id: String, control: LiveExecControl) {
    live_exec_controls()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(invocation_id, control);
}

fn remove_live_exec_control(invocation_id: &str) {
    live_exec_controls()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(invocation_id);
}

fn live_exec_control(invocation_id: &str) -> Option<LiveExecControl> {
    live_exec_controls()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(invocation_id)
        .cloned()
}

/// Record `nonce` as seen for this live session, returning `true` when it is
/// fresh (first seen this session) and `false` when it is a replay.
///
/// Only frames that already passed [`authorize_live_control`] (signature →
/// trust → ownership) reach here, so an attacker cannot pre-seed the seen-set to
/// block a legitimate requester's future (random) nonce, and a denied frame
/// leaves the set unchanged — mirroring the replay cache's side-effect-free
/// denials. Per-session dedup (rather than the router's bounded, persistent
/// request-plane cache) avoids thrashing that cache and evicting legitimate
/// `exec.request` / `call.request` nonces when an interactive PTY emits a
/// control frame per keystroke (issue #305).
fn admit_control_nonce(control: &LiveExecControl, nonce: &str) -> bool {
    control
        .seen_control_nonces
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(nonce.to_string())
}

/// A live exec child's process-group id plus a cheap liveness discriminator.
///
/// The pgid equals the child's pid (children are spawned in their own process
/// group; see [`crate::runner::build_command`]). `started_unix` records when the
/// child was spawned so a reaper has a discriminator against the pgid-reuse
/// race (a pgid could be recycled by an unrelated process after the child dies).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
struct LivePgid {
    /// Process-group id (== child pid) to signal with `killpg`.
    pgid: u32,
    /// Spawn time in Unix seconds (liveness discriminator / forensics).
    started_unix: u64,
}

/// Process-wide registry of live exec child process groups, keyed by
/// `invocation_id` (issue #316).
///
/// `kill_on_drop` only reaps the *immediate* child and never fires on a SIGKILL
/// of the daemon, so an in-flight exec child (and its grandchildren) would
/// otherwise orphan on `daemon stop`'s force-kill escalation or a daemon crash.
/// This registry lets the graceful-shutdown path signal every live child's whole
/// process group, and it is mirrored to a `0600` sidecar so the SIGKILL-path
/// reaper (`daemon stop`, a different process) and the restart janitor can reap
/// groups this process can no longer reach via `Drop`.
static LIVE_PGIDS: OnceLock<Mutex<BTreeMap<String, LivePgid>>> = OnceLock::new();

fn live_pgids() -> &'static Mutex<BTreeMap<String, LivePgid>> {
    LIVE_PGIDS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

/// Path to the `0600` JSON sidecar mirroring [`LIVE_PGIDS`].
fn live_pgids_file(paths: &crate::SessionPaths) -> PathBuf {
    paths.data_dir.join("live-pgids.json")
}

/// Atomically persist the in-memory live-pgid map to the sidecar (`0600`).
///
/// Contains only integers (pgids + spawn timestamps) — no secrets. Best-effort:
/// a write failure is non-fatal to running the command, so callers ignore the
/// `Err`.
fn persist_live_pgids(paths: &crate::SessionPaths, map: &BTreeMap<String, LivePgid>) {
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt as _;
    if paths.ensure_data_dir().is_err() {
        return;
    }
    let Ok(bytes) = serde_json::to_vec(map) else {
        return;
    };
    let file = live_pgids_file(paths);
    let tmp = file.with_extension("json.tmp");
    let write = || -> std::io::Result<()> {
        let mut f = std::fs::File::create(&tmp)?;
        f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        f.write_all(&bytes)?;
        f.flush()?;
        std::fs::rename(&tmp, &file)
    };
    if let Err(e) = write() {
        tracing::debug!(error = %e, "could not persist live-pgids sidecar");
    }
}

/// Load the persisted live-pgid records, returning an empty vec when the sidecar
/// is missing or unreadable.
fn load_live_pgids(paths: &crate::SessionPaths) -> Vec<LivePgid> {
    match std::fs::read(live_pgids_file(paths)) {
        Ok(bytes) => serde_json::from_slice::<BTreeMap<String, LivePgid>>(&bytes)
            .map(|m| m.into_values().collect())
            .unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}

/// Remove the live-pgid sidecar (best-effort; missing is success).
fn clear_live_pgids_file(paths: &crate::SessionPaths) {
    let _ = std::fs::remove_file(live_pgids_file(paths));
}

/// RAII guard registering one live exec child's process group for its lifetime.
///
/// Constructing it (on spawn) records the pgid in the in-memory registry and the
/// sidecar; dropping it (on every terminal path — finished, cancelled, errored,
/// or panicked) deregisters it, mirroring [`crate::inflight::InflightGuard`].
struct LivePgidGuard {
    invocation_id: String,
    paths: crate::SessionPaths,
}

impl LivePgidGuard {
    /// Register `pgid` (== child pid) for `invocation_id`.
    fn register(invocation_id: &str, pgid: u32) -> Self {
        let paths = crate::SessionPaths::resolve();
        {
            let mut map = live_pgids().lock().unwrap_or_else(|e| e.into_inner());
            map.insert(
                invocation_id.to_string(),
                LivePgid {
                    pgid,
                    started_unix: now_unix(),
                },
            );
            persist_live_pgids(&paths, &map);
        }
        Self {
            invocation_id: invocation_id.to_string(),
            paths,
        }
    }
}

impl Drop for LivePgidGuard {
    fn drop(&mut self) {
        let mut map = live_pgids().lock().unwrap_or_else(|e| e.into_inner());
        map.remove(&self.invocation_id);
        if map.is_empty() {
            clear_live_pgids_file(&self.paths);
        } else {
            persist_live_pgids(&self.paths, &map);
        }
    }
}

/// Whether the process-group leader (pid == pgid) is currently alive.
#[cfg(unix)]
fn process_group_alive(pgid: u32) -> bool {
    use nix::sys::signal::kill;
    use nix::unistd::Pid;
    matches!(
        kill(Pid::from_raw(pgid as i32), None),
        Ok(()) | Err(nix::errno::Errno::EPERM)
    )
}

/// Terminate every live exec child process group registered in *this* process,
/// SIGTERM then SIGKILL after `grace`, for the graceful daemon-shutdown path
/// (issue #316).
///
/// Called from [`crate::lifecycle::run_foreground`] after the shutdown signal so
/// the common `daemon stop` path leaves no orphaned children. Clears the sidecar
/// afterwards (the groups are being torn down here, so the SIGKILL-path reaper
/// has nothing left to do).
pub fn terminate_live_exec_children(paths: &crate::SessionPaths, grace: Duration) {
    let pgids: Vec<u32> = live_pgids()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .values()
        .map(|r| r.pgid)
        .collect();
    if pgids.is_empty() {
        return;
    }
    tracing::info!(
        count = pgids.len(),
        "terminating in-flight exec child process groups on shutdown"
    );
    for pgid in &pgids {
        terminate_process_group(*pgid);
    }
    std::thread::sleep(grace);
    for pgid in &pgids {
        kill_process_group(*pgid);
    }
    clear_live_pgids_file(paths);
}

/// SIGKILL every *persisted* live exec child process group (issue #316).
///
/// Used by `daemon stop`'s SIGKILL escalation: it runs in the CLI process (a
/// different process from the daemon, so the in-memory registry is empty) and
/// reads the sidecar the force-killed daemon left behind. The daemon is being
/// force-killed in the same breath, so the pgid-reuse window is negligible.
pub fn kill_persisted_live_exec_children(paths: &crate::SessionPaths) {
    for rec in load_live_pgids(paths) {
        kill_process_group(rec.pgid);
    }
    clear_live_pgids_file(paths);
}

/// Restart janitor: reap any exec child process groups left alive by a previous
/// daemon run, then clear the sidecar (issue #316).
///
/// Best-effort and reconcile-first: it only signals a recorded pgid whose group
/// leader is still alive, accepting the documented pgid-reuse caveat (a recycled
/// pgid could belong to an unrelated process). The authoritative teardown is the
/// graceful in-process path ([`terminate_live_exec_children`]); this only mops up
/// after a crash or force-kill.
pub fn reap_orphaned_live_exec_children(paths: &crate::SessionPaths) {
    let records = load_live_pgids(paths);
    if records.is_empty() {
        return;
    }
    tracing::info!(
        count = records.len(),
        "reaping exec child process groups left by a previous daemon run"
    );
    for rec in &records {
        #[cfg(unix)]
        if process_group_alive(rec.pgid) {
            kill_process_group(rec.pgid);
        }
    }
    clear_live_pgids_file(paths);
}

/// Why an incoming `com.mxagent.exec.request.v1` was rejected.
///
/// Every variant maps to a stable, machine-readable reason string via
/// [`ExecRejection::reason`], which is what the emitted
/// `com.mxagent.exec.rejected.v1` carries in its `reason` field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecRejection {
    /// The request content was not a JSON object, so it cannot be verified.
    Malformed,
    /// The request carried no `signature` field.
    Unsigned,
    /// The signature was present but did not verify against the signing key.
    InvalidSignature,
    /// The request's `target_agent` does not name this daemon's local agent.
    WrongTarget {
        /// The `target_agent` named in the request.
        target: String,
    },
    /// The signing key is unknown to or revoked in the local trust store.
    UntrustedKey {
        /// The signing key identifier that was rejected.
        key_id: String,
    },
    /// The local policy denied the requested command for this room/agent.
    PolicyDenied(DenyReason),
    /// Policy required a verified sending device (`require_verified_device`) but
    /// the originating Matrix device is not verified (issue #240). This gate is
    /// applied *after* the authoritative signature → trust → policy checks pass;
    /// it can only add a denial, never authorize execution.
    UnverifiedDevice,
    /// A held `requires_approval` exec was **denied** by an operator's approval
    /// decision (issue #306). A terminal, post-policy outcome surfaced to the
    /// requester so a held invocation does not hang silently on a deny.
    ApprovalDenied,
    /// A held `requires_approval` exec **expired** without a decision and was
    /// swept fail-closed (issue #306). A terminal, post-policy outcome surfaced
    /// to the requester so a held invocation does not hang silently on expiry.
    ApprovalExpired,
}

impl ExecRejection {
    /// A stable, machine-readable reason string for use in an [`ExecRejected`].
    pub fn reason(&self) -> String {
        match self {
            Self::Malformed => "malformed_request".to_string(),
            Self::Unsigned => "unsigned".to_string(),
            Self::InvalidSignature => "invalid_signature".to_string(),
            Self::WrongTarget { .. } => "wrong_target".to_string(),
            Self::UntrustedKey { .. } => "untrusted_key".to_string(),
            Self::PolicyDenied(_) => "policy_denied".to_string(),
            Self::UnverifiedDevice => "unverified_device".to_string(),
            Self::ApprovalDenied => "approval_denied".to_string(),
            Self::ApprovalExpired => "approval_expired".to_string(),
        }
    }
}

impl std::fmt::Display for ExecRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed => write!(f, "exec request content is not a JSON object"),
            Self::Unsigned => write!(f, "exec request is unsigned"),
            Self::InvalidSignature => write!(f, "exec request signature is invalid"),
            Self::WrongTarget { target } => {
                write!(f, "exec request is addressed to {target:?}, not this agent")
            }
            Self::UntrustedKey { key_id } => {
                write!(f, "signing key {key_id:?} is not trusted")
            }
            Self::PolicyDenied(reason) => write!(f, "policy denied exec: {reason}"),
            Self::UnverifiedDevice => {
                write!(f, "policy requires a verified sending device")
            }
            Self::ApprovalDenied => write!(f, "approval-required exec was denied"),
            Self::ApprovalExpired => {
                write!(f, "approval-required exec expired without a decision")
            }
        }
    }
}

impl std::error::Error for ExecRejection {}

/// Additive verified-device gate, applied *after* the signature → trust →
/// policy execution gate (issue #240).
///
/// When `allowance.require_verified_device` is set, the request executes only if
/// the originating Matrix device is known to be verified (`device_verified ==
/// Some(true)`). An unverified device (`Some(false)`) or an indeterminate one
/// (`None`, e.g. the crypto store has not yet seen the device) is denied with
/// [`ExecRejection::UnverifiedDevice`]. When the knob is off this is a no-op, so
/// the default behaviour — authority derives solely from signing + trust +
/// policy — is unchanged. This function can only *deny*; it never grants.
pub fn enforce_verified_device(
    allowance: &Allowance,
    device_verified: Option<bool>,
) -> Result<(), ExecRejection> {
    if allowance.require_verified_device && device_verified != Some(true) {
        return Err(ExecRejection::UnverifiedDevice);
    }
    Ok(())
}

/// Read the detached [`Signature`] embedded in `content`, if present and
/// well-formed. Returns `None` when there is no `signature` field at all
/// (an unsigned request) and an error when the field is malformed.
fn read_signature(content: &Value) -> Result<Option<Signature>, ExecRejection> {
    let obj = content.as_object().ok_or(ExecRejection::Malformed)?;
    match obj.get(SIGNATURE_FIELD) {
        None => Ok(None),
        Some(Value::Null) => Ok(None),
        Some(value) => serde_json::from_value::<Signature>(value.clone())
            .map(Some)
            .map_err(|_| ExecRejection::InvalidSignature),
    }
}

/// Options describing the command an [`ExecRequest`] should run.
///
/// These are the request-specific fields a caller chooses; the protocol
/// bookkeeping fields (`invocation_id`, `request_id`, `nonce`, timestamps, and
/// the signature) are filled in by [`build_signed_exec_request`].
#[derive(Debug, Clone)]
pub struct ExecRequestOptions {
    /// Agent expected to run the command.
    pub target_agent: String,
    /// Agent issuing the request.
    pub requesting_agent: String,
    /// Command argv (program followed by arguments).
    pub command: Vec<String>,
    /// Working directory.
    pub cwd: String,
    /// Environment overrides.
    pub env: BTreeMap<String, String>,
    /// Whether stdin will be streamed.
    pub stdin: bool,
    /// Whether output should be streamed.
    pub stream: bool,
    /// Whether to allocate a PTY.
    pub pty: bool,
    /// Timeout in milliseconds.
    pub timeout_ms: u64,
    /// Owning task identifier, if any.
    pub task_id: Option<String>,
}

/// Build and sign a `com.mxagent.exec.request.v1` content value.
///
/// Constructs an [`ExecRequest`] from `options` and the supplied identifiers,
/// then signs the content with `signing_key`, embedding the detached signature
/// under the `signature` field. The returned JSON value is ready to be sent as
/// the timeline event's content.
#[allow(clippy::too_many_arguments)]
pub fn build_signed_exec_request(
    signing_key: &SigningKey,
    key_id: impl Into<String>,
    invocation_id: impl Into<String>,
    request_id: impl Into<String>,
    nonce: impl Into<String>,
    created_at: impl Into<String>,
    expires_at: impl Into<String>,
    options: &ExecRequestOptions,
) -> Result<Value, SignatureError> {
    let invocation_id = invocation_id.into();
    let idempotency_key = format!("exec:{invocation_id}");
    // Build the unsigned content with a placeholder signature, then sign it in
    // place. `sign_into` excludes the `signature` field from the signed bytes,
    // so the placeholder does not affect the result.
    let request = ExecRequest {
        invocation_id,
        request_id: request_id.into(),
        target_agent: options.target_agent.clone(),
        requesting_agent: options.requesting_agent.clone(),
        command: options.command.clone(),
        cwd: options.cwd.clone(),
        env: options.env.clone(),
        stdin: options.stdin,
        stream: options.stream,
        pty: options.pty,
        timeout_ms: options.timeout_ms,
        task_id: options.task_id.clone(),
        created_at: created_at.into(),
        expires_at: expires_at.into(),
        nonce: nonce.into(),
        idempotency_key,
        signature: Signature {
            alg: signing::ALG_ED25519.to_string(),
            key_id: key_id.into(),
            sig: String::new(),
        },
        extra: Default::default(),
    };
    let mut content =
        serde_json::to_value(&request).expect("ExecRequest serializes to a JSON object");
    let key_id = request.signature.key_id;
    signing::sign_into(signing_key, key_id, &mut content)?;
    Ok(content)
}

/// Send a signed `com.mxagent.exec.request.v1` timeline event into `room`.
///
/// Builds and signs the request with [`build_signed_exec_request`], then sends
/// it as a Matrix timeline event so it federates to the target agent. Returns
/// the parsed [`ExecRequest`] that was sent (including its embedded signature).
#[allow(clippy::too_many_arguments)]
pub async fn send_exec_request(
    room: &Room,
    signing_key: &SigningKey,
    key_id: impl Into<String>,
    invocation_id: impl Into<String>,
    request_id: impl Into<String>,
    nonce: impl Into<String>,
    created_at: impl Into<String>,
    expires_at: impl Into<String>,
    options: &ExecRequestOptions,
) -> Result<ExecRequest, WorkspaceError> {
    // Signing only fails when the content is not a JSON object; the content we
    // build here is always an object, so this cannot fail in practice.
    let content = build_signed_exec_request(
        signing_key,
        key_id,
        invocation_id,
        request_id,
        nonce,
        created_at,
        expires_at,
        options,
    )
    .expect("ExecRequest content is always a JSON object");
    room.send_raw(EXEC_REQUEST, content.clone())
        .await
        .map_err(WorkspaceError::from)?;
    serde_json::from_value::<ExecRequest>(content)
        .map_err(|e| WorkspaceError::from(matrix_sdk::Error::SerdeJson(e)))
}

/// Verify and authorize an incoming `com.mxagent.exec.request.v1`.
///
/// Runs the full receive-side pipeline (architecture §13.1): signature, then
/// routing, then trust, then policy. On success the parsed [`ExecRequest`] is
/// returned; on failure the first failing check is reported as an
/// [`ExecRejection`] and **no process is spawned** — the policy engine is a
/// pure function and this routine never starts anything.
///
/// `verifying_key` is the public key the caller has resolved for the request's
/// signing key (for example from the requesting agent's published key);
/// `local_agent` is this daemon's own agent identity, used to confirm the
/// request was routed to us; the trust check confirms the key id is locally
/// trusted; and the policy check confirms the command is permitted for
/// `requesting_agent` in `room_id`.
pub fn authorize_exec_request(
    content: &Value,
    verifying_key: &VerifyingKey,
    trust: &TrustStore,
    policy: &Policy,
    room_id: &str,
    requesting_agent: &str,
    local_agent: &str,
) -> Result<ExecRequest, ExecRejection> {
    authorize_exec_request_with_allowance(
        content,
        verifying_key,
        trust,
        policy,
        room_id,
        requesting_agent,
        local_agent,
    )
    .map(|(request, _allowance)| request)
}

/// Like [`authorize_exec_request`] but also returns the resolved [`Allowance`].
///
/// The allowance carries the limits the runner must enforce — including the
/// `requires_approval` flag the caller consults (via
/// [`crate::approval::disposition_for_exec`]) to decide whether the request may
/// run immediately or must be queued for approval. Authorizing a request never
/// spawns a process.
pub fn authorize_exec_request_with_allowance(
    content: &Value,
    verifying_key: &VerifyingKey,
    trust: &TrustStore,
    policy: &Policy,
    room_id: &str,
    requesting_agent: &str,
    local_agent: &str,
) -> Result<(ExecRequest, Allowance), ExecRejection> {
    // 1. Signature must be present and valid.
    let signature = read_signature(content)?.ok_or(ExecRejection::Unsigned)?;
    signing::verify(verifying_key, content).map_err(|e| match e {
        SignatureError::MissingSignature => ExecRejection::Unsigned,
        SignatureError::NotAnObject => ExecRejection::Malformed,
        _ => ExecRejection::InvalidSignature,
    })?;

    let request: ExecRequest =
        serde_json::from_value(content.clone()).map_err(|_| ExecRejection::Malformed)?;

    // 2. The request must be addressed to this agent.
    if request.target_agent != local_agent {
        return Err(ExecRejection::WrongTarget {
            target: request.target_agent,
        });
    }

    // 3. The signing key must be locally trusted.
    if !trust.is_key_trusted(&signature.key_id) {
        return Err(ExecRejection::UntrustedKey {
            key_id: signature.key_id,
        });
    }

    // 4. The local policy must permit the command for this room/agent.
    let outcome = policy.evaluate_exec(&ExecContext {
        room_id,
        requesting_agent,
        command: &request.command,
        cwd: &request.cwd,
    });
    match outcome.allowance() {
        Some(allowance) => Ok((request, allowance.clone())),
        None => Err(ExecRejection::PolicyDenied(
            outcome.deny_reason().expect("denied outcome has a reason"),
        )),
    }
}

/// Build a `com.mxagent.invocation.v1` state record for an authorized request.
///
/// The invocation starts in the `accepted` state; the runner advances it to
/// `running`, then to a terminal state when the process exits.
pub fn invocation_state_for(request: &ExecRequest, now: impl Into<String>) -> InvocationState {
    let now = now.into();
    InvocationState {
        invocation_id: request.invocation_id.clone(),
        task_id: request.task_id.clone(),
        requester: request.requesting_agent.clone(),
        target: request.target_agent.clone(),
        state: "accepted".to_string(),
        created_at: now.clone(),
        updated_at: now,
        exit_code: None,
        state_rev: 0,
        extra: Default::default(),
    }
}

/// Emit a `com.mxagent.exec.accepted.v1` timeline event into `room`.
pub async fn emit_exec_accepted(
    room: &Room,
    invocation_id: impl Into<String>,
) -> Result<(), WorkspaceError> {
    let accepted = ExecAccepted {
        invocation_id: invocation_id.into(),
        extra: Default::default(),
    };
    let content = serde_json::to_value(&accepted)
        .map_err(|e| WorkspaceError::from(matrix_sdk::Error::SerdeJson(e)))?;
    room.send_raw(EXEC_ACCEPTED, content)
        .await
        .map_err(WorkspaceError::from)?;
    Ok(())
}

/// Emit a `com.mxagent.exec.rejected.v1` timeline event into `room`.
///
/// Carries the stable, machine-readable [`ExecRejection::reason`]. Emitting a
/// rejection never spawns a process.
pub async fn emit_exec_rejected(
    room: &Room,
    invocation_id: impl Into<String>,
    rejection: &ExecRejection,
) -> Result<(), WorkspaceError> {
    let rejected = ExecRejected {
        invocation_id: invocation_id.into(),
        reason: rejection.reason(),
        extra: Default::default(),
    };
    let content = serde_json::to_value(&rejected)
        .map_err(|e| WorkspaceError::from(matrix_sdk::Error::SerdeJson(e)))?;
    room.send_raw(EXEC_REJECTED, content)
        .await
        .map_err(WorkspaceError::from)?;
    Ok(())
}

/// Publish a `com.mxagent.invocation.v1` state event keyed by `invocation_id`.
pub async fn publish_invocation_state(
    room: &Room,
    state: &InvocationState,
) -> Result<(), WorkspaceError> {
    let content = serde_json::to_value(state)
        .map_err(|e| WorkspaceError::from(matrix_sdk::Error::SerdeJson(e)))?;
    send_workspace_state(room, INVOCATION, &state.invocation_id, content).await?;
    Ok(())
}

/// Handle a routed live Matrix `exec.request` on the target daemon.
///
/// The handler is intentionally conservative: it ignores requests not addressed
/// to one of this daemon's registered agents, and for local targets it verifies
/// the requester public key, signature, trust store, replay/expiry (already
/// enforced by the router for `exec.request`), and local policy before spawning
/// anything.
pub async fn handle_live_exec_request(
    client: &matrix_sdk::Client,
    paths: &crate::SessionPaths,
    meta: &crate::event_router::EventMeta,
    request: &ExecRequest,
) {
    let room_id = match matrix_sdk::ruma::RoomId::parse(&meta.room_id) {
        Ok(id) => id,
        Err(e) => {
            tracing::warn!(error = %e, room = %meta.room_id, "invalid room id in routed exec request");
            return;
        }
    };
    let Some(room) = client.get_room(&room_id) else {
        tracing::warn!(room = %meta.room_id, "room for routed exec request is unavailable");
        return;
    };

    let local_user = client.user_id().map(|u| u.to_string()).unwrap_or_default();
    let is_local_target = match crate::agent::read_agent_state(&room, &request.target_agent).await {
        Ok(Some(agent)) => agent.matrix_user_id == local_user,
        Ok(None) => false,
        Err(e) => {
            tracing::warn!(error = %e, target_agent = %request.target_agent, "could not read target agent state");
            false
        }
    };
    if !is_local_target {
        return;
    }

    // The idempotency key is fully derived from the invocation id (`exec:<id>`)
    // and is part of the signed content, so it can carry no out-of-band value.
    // Reject a mismatch as a malformed request before doing any work, so the
    // field cannot smuggle a foreign key (issue #316).
    if request.idempotency_key != format!("exec:{}", request.invocation_id) {
        if let Err(e) = emit_exec_rejected(
            &room,
            request.invocation_id.clone(),
            &ExecRejection::Malformed,
        )
        .await
        {
            tracing::warn!(error = %e, invocation_id = %request.invocation_id, "failed to emit exec rejection for malformed idempotency key");
        }
        return;
    }

    let content = match serde_json::to_value(request) {
        Ok(value) => value,
        Err(e) => {
            tracing::warn!(error = %e, "could not reserialize exec request");
            return;
        }
    };

    let authorized = match authorize_live_exec(&room, paths, &content, request, &meta.room_id).await
    {
        Ok(value) => value,
        Err(rejection) => {
            match &rejection {
                // Policy denials keep their detailed DenyReason via the policy
                // Outcome path.
                ExecRejection::PolicyDenied(reason) => audit_exec_decision(
                    paths,
                    &meta.room_id,
                    request,
                    &Outcome::Deny(reason.clone()),
                ),
                // The post-policy verified-device gate denial is audited too, so
                // a require_verified_device rejection is "denied … and audited"
                // like any other privileged denial (issue #240).
                ExecRejection::UnverifiedDevice => {
                    audit_exec_rejection(paths, &meta.room_id, request, &rejection)
                }
                // Pre-policy authentication failures (unsigned, bad signature,
                // wrong target, untrusted key, malformed) are not attributable
                // to a trusted requester and are intentionally not audited.
                _ => {}
            }
            if let Err(e) =
                emit_exec_rejected(&room, request.invocation_id.clone(), &rejection).await
            {
                tracing::warn!(error = %e, invocation_id = %request.invocation_id, "failed to emit exec rejection");
            }
            return;
        }
    };
    let (request, allowance) = authorized;

    // De-duplicate a replayed exec request by its idempotency key (issue #316):
    // if this invocation already has a live control registered, a second child
    // must not be spawned. Re-emit the existing `exec.accepted` instead of
    // running the command twice. (The router's replay cache already drops a
    // byte-identical re-delivery; this guards a re-send carrying a fresh nonce
    // but the same — fully derived — invocation id / idempotency key.)
    if live_exec_control(&request.invocation_id).is_some() {
        tracing::info!(
            invocation_id = %request.invocation_id,
            "duplicate exec request for a live invocation; re-emitting accepted instead of spawning again"
        );
        if let Err(e) = emit_exec_accepted(&room, request.invocation_id.clone()).await {
            tracing::warn!(error = %e, invocation_id = %request.invocation_id, "failed to re-emit exec accepted for duplicate request");
        }
        return;
    }

    match crate::approval::disposition_for_exec(request.clone(), &allowance) {
        crate::approval::ExecDisposition::RequiresApproval { approval, .. } => {
            // Authorized but held pending an operator decision (architecture §12):
            // audit *held* (not allow-and-ran) and persist the original signed
            // request so an approving decision can re-authorize and spawn it. The
            // held request stays out of the emitted, no-leak `ApprovalRequest`.
            audit_exec_held(paths, &meta.room_id, &request, &allowance);
            let mut queue = crate::approval::ApprovalQueue::load(paths).unwrap_or_default();
            queue.enqueue(crate::approval::PendingApproval {
                room_id: meta.room_id.clone(),
                request: approval.clone(),
                held_request: Some(crate::approval::HeldRequest::Exec(request.clone())),
            });
            if let Err(e) = queue.save(paths) {
                tracing::warn!(error = %e, request_id = %approval.request_id, "failed to persist approval request");
            }
            if let Err(e) = crate::approval::emit_approval_request(&room, &approval).await {
                tracing::warn!(error = %e, request_id = %approval.request_id, "failed to emit approval request");
            }
            return;
        }
        crate::approval::ExecDisposition::Execute(_) => {}
    }

    // Allowed and running immediately (allow-and-ran).
    audit_exec_decision(
        paths,
        &meta.room_id,
        &request,
        &Outcome::Allow(allowance.clone()),
    );
    spawn_authorized_live_exec(client, &room, request, allowance).await;
}

/// Spawn an authorized live `exec` invocation: emit accepted → running, register
/// the live-control channels, drive the PTY or controlled run to completion, and
/// publish invocation state throughout (architecture §7.2–§7.5).
///
/// Extracted from [`handle_live_exec_request`] so both the direct live dispatch
/// and the approval-release path ([`release_held_exec`]) produce byte-for-byte
/// the same lifecycle. Behaviour-preserving: the non-approval path is unchanged.
pub(crate) async fn spawn_authorized_live_exec(
    client: &matrix_sdk::Client,
    room: &Room,
    request: ExecRequest,
    allowance: Allowance,
) {
    if let Err(e) = emit_exec_accepted(room, request.invocation_id.clone()).await {
        tracing::warn!(error = %e, invocation_id = %request.invocation_id, "failed to emit exec accepted");
    }
    let now = rfc3339_now();
    let mut state = invocation_state_for(&request, now.clone());
    if let Err(e) = publish_invocation_state(room, &state).await {
        tracing::warn!(error = %e, invocation_id = %request.invocation_id, "failed to publish accepted invocation state");
    }
    state.state = crate::invocation::STATE_RUNNING.to_string();
    state.updated_at = rfc3339_now();
    state.state_rev = state.state_rev.saturating_add(1);
    if let Err(e) = publish_invocation_state(room, &state).await {
        tracing::warn!(error = %e, invocation_id = %request.invocation_id, "failed to publish running invocation state");
    }

    // Register the live-exec control *synchronously*, before spawning the run
    // task, so a stdin or cancel frame routed in the same (or a later) sync
    // batch always finds this invocation. Registering inside the spawned task
    // left a window where early stdin — including its EOF — was silently
    // dropped by `handle_live_exec_stdin`, hanging stdin-consuming commands
    // such as `cat` until their timeout.
    let (stdin_tx, stdin_rx) = tokio::sync::mpsc::channel::<StdinFrame>(64);
    let (cancel_tx, cancel_rx) = tokio::sync::watch::channel::<Option<String>>(None);
    let (resize_tx, resize_rx) = tokio::sync::mpsc::channel::<PtyWinsize>(16);
    insert_live_exec_control(
        request.invocation_id.clone(),
        LiveExecControl {
            requester_agent: request.requesting_agent.clone(),
            stdin: stdin_tx,
            cancel: cancel_tx,
            resize: request.pty.then_some(resize_tx),
            seen_control_nonces: Arc::new(Mutex::new(HashSet::new())),
        },
    );

    // Interactive PTY exec takes a dedicated live-streaming path: the daemon
    // allocates a pseudo-terminal, streams the merged master output as
    // `stream:"pty"` chunks as it is produced, and applies signed stdin / cancel
    // and (sender-authorized) resize controls (issue #238).
    if request.pty {
        let room = room.clone();
        tokio::spawn(async move {
            // Count this invocation as in-flight for the executing (local) agent
            // for its whole lifetime (issue #312). The guard is created *inside*
            // the spawned task and dropped when it ends — finished, cancelled,
            // rejected, errored, or panicked — so the live load count is released
            // on every terminal path without per-path bookkeeping.
            let _inflight = crate::inflight::InflightGuard::enter(&request.target_agent);
            run_pty_exec_task(
                room, request, allowance, stdin_rx, resize_rx, cancel_rx, state,
            )
            .await;
        });
        return;
    }

    let client = client.clone();
    let room = room.clone();
    tokio::spawn(async move {
        // In-flight accounting for the non-PTY run (issue #312); see the PTY arm.
        let _inflight = crate::inflight::InflightGuard::enter(&request.target_agent);
        let started = std::time::Instant::now();
        let result = run_controlled_exec(&request, &allowance, stdin_rx, cancel_rx).await;
        remove_live_exec_control(&request.invocation_id);
        let output = match result {
            Ok(ControlledExecResult::Finished(output)) => output,
            Ok(ControlledExecResult::Cancelled {
                mut output,
                killed_process_group,
            }) => {
                // `exec.cancelled` carries no `truncated` field, so the capture
                // summary is intentionally discarded here.
                let _ = emit_output_events(
                    &client,
                    &room,
                    &request.invocation_id,
                    &output.stdout,
                    &output.stderr,
                    &allowance,
                )
                .await;
                let finished_at = rfc3339_now();
                let _ = emit_exec_cancelled(
                    &room,
                    request.invocation_id.clone(),
                    crate::runner::CANCEL_SIGNAL,
                    killed_process_group,
                    finished_at.clone(),
                )
                .await;
                state.state = crate::invocation::STATE_CANCELLED.to_string();
                state.exit_code = output.exit_code;
                state.updated_at = finished_at;
                state.state_rev = state.state_rev.saturating_add(1);
                let _ = publish_invocation_state(&room, &state).await;
                output.stdout.clear();
                output.stderr.clear();
                return;
            }
            Err(err) => {
                let rejection = ExecRejection::PolicyDenied(DenyReason::CommandNotAllowed {
                    command: err.to_string(),
                });
                let _ = emit_exec_rejected(&room, request.invocation_id.clone(), &rejection).await;
                return;
            }
        };

        let summary = emit_output_events(
            &client,
            &room,
            &request.invocation_id,
            &output.stdout,
            &output.stderr,
            &allowance,
        )
        .await;

        let exit_code = output.exit_code;
        let finished = ExecFinished {
            invocation_id: request.invocation_id.clone(),
            exit_code,
            signal: output.signal.and_then(signal_name),
            duration_ms: started.elapsed().as_millis() as u64,
            stdout_bytes: output.stdout.len() as u64,
            stderr_bytes: output.stderr.len() as u64,
            truncated: summary.truncated,
            artifact_mxc: None,
            extra: Default::default(),
        };
        if let Ok(content) = serde_json::to_value(&finished) {
            if let Err(e) = room.send_raw(EXEC_FINISHED, content).await {
                tracing::warn!(error = %e, invocation_id = %request.invocation_id, "failed to emit exec.finished");
            }
        }

        state.state = match exit_code {
            Some(code) => crate::invocation::terminal_state_for_exit(code).to_string(),
            None => crate::invocation::STATE_FAILED.to_string(),
        };
        state.exit_code = exit_code;
        state.updated_at = rfc3339_now();
        state.state_rev = state.state_rev.saturating_add(1);
        let _ = publish_invocation_state(&room, &state).await;
    });
}

/// Re-authorize a previously-held `exec` request and, if it still passes the
/// **full** pipeline, spawn it; otherwise emit a terminal rejection (issue #306).
///
/// Called by the live approval-decision handler on an *approved* decision. It
/// re-runs [`authorize_live_exec`] (signature → trust → deny-by-default policy →
/// verified-device gate) against the recovered original request, so a stale
/// hold, a since-revoked key, or a since-tightened policy is denied at release —
/// room membership is never execution permission. On success it audits *released*
/// and spawns via [`spawn_authorized_live_exec`]; on denial it audits and emits
/// `exec.rejected`. The hold has already been removed from the queue by the
/// caller, so any failure fails closed (never runs).
pub(crate) async fn release_held_exec(
    client: &matrix_sdk::Client,
    paths: &crate::SessionPaths,
    room: &Room,
    room_id: &str,
    request: ExecRequest,
) {
    let content = match serde_json::to_value(&request) {
        Ok(value) => value,
        Err(e) => {
            tracing::warn!(error = %e, invocation_id = %request.invocation_id, "could not reserialize held exec request for release");
            return;
        }
    };
    match authorize_live_exec(room, paths, &content, &request, room_id).await {
        Ok((request, allowance)) => {
            audit_exec_released(paths, room_id, &request, &allowance);
            spawn_authorized_live_exec(client, room, request, allowance).await;
        }
        Err(rejection) => {
            match &rejection {
                ExecRejection::PolicyDenied(reason) => {
                    audit_exec_decision(paths, room_id, &request, &Outcome::Deny(reason.clone()))
                }
                ExecRejection::UnverifiedDevice => {
                    audit_exec_rejection(paths, room_id, &request, &rejection)
                }
                _ => {}
            }
            if let Err(e) =
                emit_exec_rejected(room, request.invocation_id.clone(), &rejection).await
            {
                tracing::warn!(error = %e, invocation_id = %request.invocation_id, "failed to emit exec rejection on release");
            }
        }
    }
}

/// Terminally reject a held `exec` whose approval was **denied** by an operator
/// (issue #306): audit denied-while-held and emit `exec.rejected`
/// (`approval_denied`). Never runs the command.
pub(crate) async fn deny_held_exec(
    room: &Room,
    paths: &crate::SessionPaths,
    room_id: &str,
    request: &ExecRequest,
) {
    audit_exec_rejection(paths, room_id, request, &ExecRejection::ApprovalDenied);
    if let Err(e) = emit_exec_rejected(
        room,
        request.invocation_id.clone(),
        &ExecRejection::ApprovalDenied,
    )
    .await
    {
        tracing::warn!(error = %e, invocation_id = %request.invocation_id, "failed to emit exec.rejected for denied hold");
    }
}

/// Terminally reject a held `exec` whose approval window **expired** without a
/// decision (issue #306): audit *expired-while-held* and emit `exec.rejected`
/// (`approval_expired`). Never runs the command.
pub(crate) async fn expire_held_exec(
    room: &Room,
    paths: &crate::SessionPaths,
    room_id: &str,
    request: &ExecRequest,
) {
    audit_exec_expired(paths, room_id, request);
    if let Err(e) = emit_exec_rejected(
        room,
        request.invocation_id.clone(),
        &ExecRejection::ApprovalExpired,
    )
    .await
    {
        tracing::warn!(error = %e, invocation_id = %request.invocation_id, "failed to emit exec.rejected for expired hold");
    }
}

/// Handle a routed signed stdin frame for a live invocation running on this daemon.
pub async fn handle_live_exec_stdin(
    room: &Room,
    paths: &crate::SessionPaths,
    content: &Value,
    stdin: &ExecStdin,
) {
    let Some(control) = live_exec_control(&stdin.invocation_id) else {
        return;
    };
    if authorize_live_control(
        room,
        paths,
        content,
        &stdin.signature.key_id,
        &control.requester_agent,
    )
    .await
    .is_err()
    {
        tracing::warn!(
            invocation_id = %stdin.invocation_id,
            requester_agent = %control.requester_agent,
            "rejected unauthorized exec stdin control"
        );
        return;
    }
    // Replay-check per session, after authorization and before applying the
    // frame: a re-delivered stdin frame carrying a previously seen nonce is
    // dropped so a room actor cannot replay already-authorized bytes (e.g. a
    // duplicate stdin line or a premature EOF) into a still-live session (#305).
    if !admit_control_nonce(&control, &stdin.nonce) {
        tracing::warn!(
            invocation_id = %stdin.invocation_id,
            "dropped replayed exec stdin control frame (nonce already seen this session)"
        );
        return;
    }
    use base64::Engine as _;
    let data = match base64::engine::general_purpose::STANDARD.decode(&stdin.data) {
        Ok(data) => data,
        Err(_) => {
            tracing::warn!(invocation_id = %stdin.invocation_id, "rejected malformed exec stdin data");
            return;
        }
    };
    if !data.is_empty() && control.stdin.send(Some(data)).await.is_err() {
        tracing::debug!(invocation_id = %stdin.invocation_id, "stdin receiver is closed");
    }
    if stdin.eof {
        let _ = control.stdin.send(None).await;
    }
}

/// Handle a routed signed cancellation for a live invocation running on this daemon.
pub async fn handle_live_exec_cancel(
    room: &Room,
    paths: &crate::SessionPaths,
    content: &Value,
    cancel: &ExecCancel,
) {
    let Some(control) = live_exec_control(&cancel.invocation_id) else {
        return;
    };
    if authorize_live_control(
        room,
        paths,
        content,
        &cancel.signature.key_id,
        &control.requester_agent,
    )
    .await
    .is_err()
    {
        tracing::warn!(
            invocation_id = %cancel.invocation_id,
            requester_agent = %control.requester_agent,
            "rejected unauthorized exec cancel control"
        );
        return;
    }
    // Replay-check per session: a re-delivered cancel carrying a seen nonce is
    // dropped so a replayed control frame cannot re-signal an already-handled
    // (or still-live) session (issue #305).
    if !admit_control_nonce(&control, &cancel.nonce) {
        tracing::warn!(
            invocation_id = %cancel.invocation_id,
            "dropped replayed exec cancel control frame (nonce already seen this session)"
        );
        return;
    }
    let _ = control.cancel.send(Some(cancel.reason.clone()));
}

/// Verify that a signed control frame (stdin / cancel) was sent by the agent
/// identified by `requester_agent_id`.
///
/// The previous implementation searched *all* agents for one whose
/// `signing_key_id` matched the frame's `key_id`, then compared the result
/// against the expected requester. When two agents share a signing key (which
/// happens in the integration-test harness where both daemons load the same key
/// from a shared data directory), `find` non-deterministically returns
/// whichever agent the homeserver lists first. If it returns the *target* agent
/// instead of the requester, the requester-match check fails and the frame is
/// silently dropped — causing stdin-consuming commands to hang until timeout.
///
/// Fix: look up the *specific* requester agent by id, then verify that its
/// registered key matches the frame's `key_id`. This is deterministic regardless
/// of key uniqueness.
async fn authorize_live_control(
    room: &Room,
    paths: &crate::SessionPaths,
    content: &Value,
    key_id: &str,
    requester_agent_id: &str,
) -> Result<(), ()> {
    let agents = crate::agent::read_all_agent_states(room)
        .await
        .map_err(|_| ())?;
    let trust = TrustStore::load(paths).unwrap_or_default();
    authorize_control_from_states(&agents, requester_agent_id, content, key_id, &trust)
}

/// Pure core of [`authorize_live_control`]: given every agent state in the room,
/// decide whether a signed control frame (stdin / cancel) is authorized.
///
/// The requester is resolved by **agent id**, never by signing key. Resolving by
/// key was the cause of a heisenbug: when two agents publish the same
/// `signing_key_id` (e.g. the integration-test harness loads one key from a
/// shared data dir), a key search returns an arbitrary agent. If it returned the
/// *target* rather than the requester, the owner check failed and the frame —
/// including stdin EOF — was silently dropped, hanging the command until
/// timeout. Looking the requester up by id is deterministic regardless of
/// whether agents share keys, and the frame's `key_id` is still required to
/// match that specific requester's registered key.
fn authorize_control_from_states(
    agents: &[AgentState],
    requester_agent_id: &str,
    content: &Value,
    key_id: &str,
    trust: &TrustStore,
) -> Result<(), ()> {
    let agent = agents
        .iter()
        .find(|agent| agent.agent_id == requester_agent_id)
        .ok_or(())?;
    if agent.signing_key_id != key_id {
        return Err(());
    }
    let verifying_key = crate::call::verifying_key_from_agent_state(agent).map_err(|_| ())?;
    signing::verify(&verifying_key, content).map_err(|_| ())?;
    if !trust.is_key_trusted(key_id) {
        return Err(());
    }
    Ok(())
}

async fn authorize_live_exec(
    room: &Room,
    paths: &crate::SessionPaths,
    content: &Value,
    request: &ExecRequest,
    room_id: &str,
) -> Result<(ExecRequest, Allowance), ExecRejection> {
    let requester = crate::agent::read_agent_state(room, &request.requesting_agent)
        .await
        .map_err(|_| ExecRejection::Malformed)?
        .ok_or_else(|| ExecRejection::UntrustedKey {
            key_id: request.signature.key_id.clone(),
        })?;
    if requester.signing_key_id != request.signature.key_id {
        return Err(ExecRejection::InvalidSignature);
    }
    let verifying_key = crate::call::verifying_key_from_agent_state(&requester)
        .map_err(|_| ExecRejection::InvalidSignature)?;
    let trust = TrustStore::load(paths).unwrap_or_default();
    let policy = Policy::default_path()
        .and_then(|path| Policy::load(path).ok())
        .unwrap_or_default();
    let (request, allowance) = authorize_exec_request_with_allowance(
        content,
        &verifying_key,
        &trust,
        &policy,
        room_id,
        &request.requesting_agent,
        &request.target_agent,
    )?;

    // Two-trust-layer interaction (architecture §1.2, issue #240): the execution
    // gate above (signature → trust → policy) is authoritative. The optional
    // `require_verified_device` knob layers an *additive* transport check on top:
    // when set, the originating Matrix device must be verified. By default the
    // knob is off, so a trusted-but-unverified device still executes (TOFU on the
    // device; authority comes from the signing key) — we only log an advisory.
    let device_verified =
        crate::verification::sender_verified(&room.client(), &requester.matrix_user_id).await;
    if allowance.require_verified_device {
        enforce_verified_device(&allowance, device_verified)?;
    } else if device_verified == Some(false) {
        tracing::info!(
            invocation_id = %request.invocation_id,
            requesting_agent = %request.requesting_agent,
            "executing privileged request from an unverified Matrix device (authority from signing key; require_verified_device is off)"
        );
    }
    Ok((request, allowance))
}

/// Stream a finished command's captured output to `room` and report whether it
/// was truncated to honour the per-invocation byte cap.
///
/// Large outputs are offloaded as artifacts (the full log is preserved, so
/// nothing is truncated); otherwise the output is chunked under
/// `allowance.max_output_bytes` and the returned [`CaptureSummary`] carries the
/// real `truncated` flag so the caller can populate `exec.finished` truthfully
/// (issue #268).
async fn emit_output_events(
    client: &matrix_sdk::Client,
    room: &Room,
    invocation_id: &str,
    stdout: &[u8],
    stderr: &[u8],
    allowance: &Allowance,
) -> CaptureSummary {
    let total = stdout.len() + stderr.len();
    let artifact_config = crate::ArtifactConfig::default();
    if artifact_config.should_switch(total) {
        // In an `--e2ee on` room the artifact media is encrypted end to end
        // (ciphertext on the homeserver); in a plaintext room it is uploaded as
        // cleartext as before (issue #308).
        let encrypted = room.encryption_state().is_encrypted();
        for (stream, data) in [(StreamKind::Stdout, stdout), (StreamKind::Stderr, stderr)] {
            if data.is_empty() {
                continue;
            }
            let prepared =
                crate::prepare_artifact(invocation_id, stream, data, &artifact_config).await;
            match crate::upload_artifact(client, prepared, encrypted).await {
                Ok(event) => {
                    if let Ok(content) = serde_json::to_value(&event) {
                        let _ = room.send_raw(STREAM_ARTIFACT, content).await;
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, invocation_id, "failed to upload exec output artifact")
                }
            }
        }
        // The full log is preserved in the artifact, so nothing was truncated.
        return CaptureSummary {
            truncated: false,
            output_bytes: total as u64,
        };
    }

    let (tx, mut rx) = tokio::sync::mpsc::channel(256);
    let stdout_bytes = stdout.to_vec();
    let stderr_bytes = stderr.to_vec();
    let invocation = invocation_id.to_string();
    let config = StreamCaptureConfig::batch().with_caps(OutputCaps {
        max_output_bytes: allowance.max_output_bytes,
        max_events_per_second: None,
    });
    let capture = tokio::spawn(async move {
        capture_child_output(
            &stdout_bytes[..],
            &stderr_bytes[..],
            &invocation,
            config,
            tx,
        )
        .await
    });
    while let Some(chunk) = rx.recv().await {
        if let Ok(content) = serde_json::to_value(&chunk) {
            if let Err(e) = room.send_raw(STREAM_CHUNK, content).await {
                tracing::warn!(error = %e, invocation_id, "failed to emit stream.chunk");
                break;
            }
        }
    }
    capture.await.unwrap_or_default()
}

enum ControlledExecResult {
    Finished(RunOutput),
    Cancelled {
        output: RunOutput,
        killed_process_group: bool,
    },
}

/// Run an authorized exec under live stdin/cancel control.
///
/// The caller (`handle_live_exec_request`) creates the stdin/cancel channels
/// and registers the [`LiveExecControl`] *before* spawning this future, so that
/// control frames routed concurrently are never lost. This function therefore
/// receives the receiver halves rather than creating them itself; frames queued
/// onto the channels before the child process drains them are still delivered.
async fn run_controlled_exec(
    request: &ExecRequest,
    allowance: &Allowance,
    mut stdin_rx: tokio::sync::mpsc::Receiver<StdinFrame>,
    mut cancel_rx: tokio::sync::watch::Receiver<Option<String>>,
) -> Result<ControlledExecResult, crate::runner::RunError> {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let spec = RunSpec {
        command: request.command.clone(),
        cwd: PathBuf::from(&request.cwd),
        env: request.env.clone(),
        env_allowlist: allowance.env_allowlist.clone(),
        stdin: request.stdin.then(Vec::new),
        timeout: Some(Duration::from_millis(
            allowance.max_runtime_ms.unwrap_or(request.timeout_ms),
        )),
        sandbox: sandbox_backend(allowance.sandbox),
        network: network_for(allowance.network),
        read_only_paths: allowance.read_only_paths.clone(),
        writable_paths: allowance.writable_paths.clone(),
        container_runtime: container_runtime_for(allowance.sandbox),
        container_image: allowance.container_image.clone(),
        ..Default::default()
    };
    let mut command = build_command(&spec)?;
    let mut child = command.spawn().map_err(crate::runner::RunError::Spawn)?;
    let pid = child.id();
    // Register the child's process group so a daemon shutdown/force-kill can reap
    // it instead of orphaning it (issue #316). Dropped when this function returns
    // (the child has exited by then), deregistering it on every terminal path.
    let _pgid_guard = pid.map(|p| LivePgidGuard::register(&request.invocation_id, p));

    let stdin_task = if request.stdin {
        child.stdin.take().map(|mut pipe| {
            tokio::spawn(async move {
                while let Some(frame) = stdin_rx.recv().await {
                    match frame {
                        Some(bytes) => {
                            if pipe.write_all(&bytes).await.is_err() {
                                break;
                            }
                            let _ = pipe.flush().await;
                        }
                        None => break,
                    }
                }
            })
        })
    } else {
        None
    };

    let stdout_pipe = child.stdout.take();
    let stderr_pipe = child.stderr.take();
    let stdout_task = tokio::spawn(async move {
        let mut buf = Vec::new();
        if let Some(mut pipe) = stdout_pipe {
            let _ = pipe.read_to_end(&mut buf).await;
        }
        buf
    });
    let stderr_task = tokio::spawn(async move {
        let mut buf = Vec::new();
        if let Some(mut pipe) = stderr_pipe {
            let _ = pipe.read_to_end(&mut buf).await;
        }
        buf
    });

    let mut cancelled = false;
    let mut killed_process_group = false;
    let wait = child.wait();
    tokio::pin!(wait);
    let status = tokio::select! {
        status = &mut wait => status.map_err(crate::runner::RunError::Spawn)?,
        _ = cancel_rx.changed() => {
            cancelled = true;
            if let Some(pid) = pid {
                terminate_process_group(pid);
                match tokio::time::timeout(spec.grace_period, &mut wait).await {
                    Ok(status) => status.map_err(crate::runner::RunError::Spawn)?,
                    Err(_) => {
                        killed_process_group = true;
                        kill_process_group(pid);
                        wait.await.map_err(crate::runner::RunError::Spawn)?
                    }
                }
            } else {
                wait.await.map_err(crate::runner::RunError::Spawn)?
            }
        }
        _ = tokio::time::sleep(spec.timeout.unwrap_or(Duration::from_secs(u64::MAX))) => {
            if let Some(pid) = pid {
                terminate_process_group(pid);
                match tokio::time::timeout(spec.grace_period, &mut wait).await {
                    Ok(status) => status.map_err(crate::runner::RunError::Spawn)?,
                    Err(_) => {
                        kill_process_group(pid);
                        wait.await.map_err(crate::runner::RunError::Spawn)?
                    }
                }
            } else {
                wait.await.map_err(crate::runner::RunError::Spawn)?
            }
        }
    };

    if let Some(task) = stdin_task {
        let _ = task.await;
    }
    let stdout = stdout_task.await.unwrap_or_default();
    let stderr = stderr_task.await.unwrap_or_default();
    #[cfg(unix)]
    let signal = {
        use std::os::unix::process::ExitStatusExt as _;
        status.signal()
    };
    #[cfg(not(unix))]
    let signal = None;
    let output = RunOutput {
        exit_code: status.code(),
        signal,
        stdout,
        stderr,
        timed_out: false,
    };
    if cancelled {
        Ok(ControlledExecResult::Cancelled {
            output,
            killed_process_group,
        })
    } else {
        Ok(ControlledExecResult::Finished(output))
    }
}

/// The terminal outcome of an interactive PTY invocation.
struct PtyExecOutcome {
    exit_code: Option<i32>,
    signal: Option<i32>,
    cancelled: bool,
    killed_process_group: bool,
    output_bytes: u64,
    /// Whether forwarded PTY output was capped to honour the per-invocation
    /// byte budget (`allowance.max_output_bytes`).
    truncated: bool,
}

/// Drive an interactive PTY invocation to completion, emitting the terminal
/// `exec.finished` / `exec.cancelled` event and invocation state (issue #238).
///
/// Live merged output is streamed as `stream:"pty"` chunks by
/// [`run_controlled_pty_exec`] while the command runs; this wraps that with the
/// same finalization shape as the non-PTY live path.
#[allow(clippy::too_many_arguments)]
async fn run_pty_exec_task(
    room: Room,
    request: ExecRequest,
    allowance: Allowance,
    stdin_rx: tokio::sync::mpsc::Receiver<StdinFrame>,
    resize_rx: tokio::sync::mpsc::Receiver<PtyWinsize>,
    cancel_rx: tokio::sync::watch::Receiver<Option<String>>,
    mut state: InvocationState,
) {
    let started = std::time::Instant::now();
    let outcome =
        run_controlled_pty_exec(&request, &allowance, &room, stdin_rx, resize_rx, cancel_rx).await;
    remove_live_exec_control(&request.invocation_id);
    let outcome = match outcome {
        Ok(outcome) => outcome,
        Err(err) => {
            let rejection = ExecRejection::PolicyDenied(DenyReason::CommandNotAllowed {
                command: err.to_string(),
            });
            let _ = emit_exec_rejected(&room, request.invocation_id.clone(), &rejection).await;
            return;
        }
    };

    if outcome.cancelled {
        let finished_at = rfc3339_now();
        let _ = emit_exec_cancelled(
            &room,
            request.invocation_id.clone(),
            crate::runner::CANCEL_SIGNAL,
            outcome.killed_process_group,
            finished_at.clone(),
        )
        .await;
        state.state = crate::invocation::STATE_CANCELLED.to_string();
        state.exit_code = outcome.exit_code;
        state.updated_at = finished_at;
        state.state_rev = state.state_rev.saturating_add(1);
        let _ = publish_invocation_state(&room, &state).await;
        return;
    }

    let finished = ExecFinished {
        invocation_id: request.invocation_id.clone(),
        exit_code: outcome.exit_code,
        signal: outcome.signal.and_then(signal_name),
        duration_ms: started.elapsed().as_millis() as u64,
        // A PTY is a single merged stream, so all bytes are reported under
        // stdout and stderr is zero (architecture §7.3).
        stdout_bytes: outcome.output_bytes,
        stderr_bytes: 0,
        truncated: outcome.truncated,
        artifact_mxc: None,
        extra: Default::default(),
    };
    if let Ok(content) = serde_json::to_value(&finished) {
        if let Err(e) = room.send_raw(EXEC_FINISHED, content).await {
            tracing::warn!(error = %e, invocation_id = %request.invocation_id, "failed to emit exec.finished for pty");
        }
    }
    state.state = match outcome.exit_code {
        Some(code) => crate::invocation::terminal_state_for_exit(code).to_string(),
        None => crate::invocation::STATE_FAILED.to_string(),
    };
    state.exit_code = outcome.exit_code;
    state.updated_at = rfc3339_now();
    state.state_rev = state.state_rev.saturating_add(1);
    let _ = publish_invocation_state(&room, &state).await;
}

/// Run an authorized interactive PTY exec under live stdin/resize/cancel control,
/// streaming the merged terminal output to `room` as `stream:"pty"` chunks.
///
/// PTY master I/O is blocking, so the read/write/resize loops run on dedicated
/// OS threads that bridge to the async chunker and the control channels. The
/// child runs in its own process group, so a cancel or timeout signals the whole
/// group (architecture §7.4/§7.5).
async fn run_controlled_pty_exec(
    request: &ExecRequest,
    allowance: &Allowance,
    room: &Room,
    stdin_rx: tokio::sync::mpsc::Receiver<StdinFrame>,
    resize_rx: tokio::sync::mpsc::Receiver<PtyWinsize>,
    mut cancel_rx: tokio::sync::watch::Receiver<Option<String>>,
) -> Result<PtyExecOutcome, crate::runner::RunError> {
    use std::io::{Read as _, Write as _};

    let spec = RunSpec {
        command: request.command.clone(),
        cwd: PathBuf::from(&request.cwd),
        env: request.env.clone(),
        env_allowlist: allowance.env_allowlist.clone(),
        timeout: Some(Duration::from_millis(
            allowance.max_runtime_ms.unwrap_or(request.timeout_ms),
        )),
        sandbox: sandbox_backend(allowance.sandbox),
        network: network_for(allowance.network),
        read_only_paths: allowance.read_only_paths.clone(),
        writable_paths: allowance.writable_paths.clone(),
        container_runtime: container_runtime_for(allowance.sandbox),
        container_image: allowance.container_image.clone(),
        ..Default::default()
    };
    // The requester sends an initial `pty.resize` with the real terminal size
    // immediately, so the conventional 24x80 is only the pre-resize default.
    let session = PtySession::spawn(&spec, PtyWinsize::default())?;
    let pid = Some(session.id());
    // Register the PTY child's process group for shutdown/force-kill reaping
    // (issue #316); dropped when this function returns (the child has exited).
    let _pgid_guard = pid.map(|p| LivePgidGuard::register(&request.invocation_id, p));
    let reader = session
        .try_clone_reader()
        .map_err(crate::runner::RunError::Spawn)?;
    let stdin_writer = session
        .try_clone_writer()
        .map_err(crate::runner::RunError::Spawn)?;
    let resize_fd = session
        .try_clone_writer()
        .map_err(crate::runner::RunError::Spawn)?;

    // Output: a blocking reader thread feeds the async chunker over an mpsc.
    let (out_tx, mut out_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
    std::thread::spawn(move || {
        let mut reader = reader;
        let mut buf = [0u8; 8192];
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if out_tx.blocking_send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
                // A PTY master reports EIO once the slave is gone; treat any read
                // error as end-of-stream.
                Err(_) => break,
            }
        }
    });
    // Stdin: drain the control channel, writing keystrokes to the master.
    std::thread::spawn(move || {
        let mut writer = stdin_writer;
        let mut rx = stdin_rx;
        while let Some(frame) = rx.blocking_recv() {
            match frame {
                Some(bytes) => {
                    if writer.write_all(&bytes).is_err() {
                        break;
                    }
                    let _ = writer.flush();
                }
                // For a PTY, end-of-input is the literal Ctrl-D byte; stop
                // forwarding rather than closing the master (which would kill the
                // session).
                None => break,
            }
        }
    });
    // Resize: apply each new window size to the master.
    std::thread::spawn(move || {
        let fd = resize_fd;
        let mut rx = resize_rx;
        while let Some(size) = rx.blocking_recv() {
            let _ = rustix::termios::tcsetwinsize(&fd, size.into());
        }
    });

    // Chunker: forward merged output to the room as `stream:"pty"` chunks until
    // the reader thread closes the channel (the child exited), then emit EOF.
    // The merged PTY stream honours the same per-invocation byte budget as the
    // non-PTY path so a runaway program cannot flood the Matrix timeline
    // unbounded (issue #268). A single-stream `CaptureLimiter` reuses the exact
    // truncation accounting used by the capture stage.
    let chunk_room = room.clone();
    let chunk_invocation = request.invocation_id.clone();
    let limiter = CaptureLimiter::new(OutputCaps {
        max_output_bytes: allowance.max_output_bytes,
        max_events_per_second: None,
    });
    let chunker = tokio::spawn(async move {
        let mut seq = 0u64;
        let mut total = 0u64;
        while let Some(bytes) = out_rx.recv().await {
            total += bytes.len() as u64;
            let allowed = limiter.reserve(bytes.len());
            if allowed > 0 {
                emit_pty_chunk(
                    &chunk_room,
                    &chunk_invocation,
                    &bytes[..allowed],
                    false,
                    &mut seq,
                )
                .await;
            }
            // Once the budget is exhausted `allowed` is 0: stop forwarding but
            // keep draining `out_rx` so the blocking reader thread never blocks
            // on a full channel (which would stall the master read and the
            // child). The child is still bounded by the exec timeout.
        }
        // The EOF chunk always terminates the stream, even after truncation.
        emit_pty_chunk(&chunk_room, &chunk_invocation, &[], true, &mut seq).await;
        (total, limiter.truncated())
    });

    let grace = spec.grace_period;
    let timeout = spec.timeout.unwrap_or(Duration::from_secs(u64::MAX));
    let mut wait = tokio::task::spawn_blocking(move || {
        let mut session = session;
        session.wait()
    });
    let mut cancelled = false;
    let mut killed_process_group = false;
    let status = tokio::select! {
        res = &mut wait => join_wait(res)?,
        _ = cancel_rx.changed() => {
            cancelled = true;
            terminate_then_kill(pid, grace, &mut wait, &mut killed_process_group).await?
        }
        _ = tokio::time::sleep(timeout) => {
            terminate_then_kill(pid, grace, &mut wait, &mut killed_process_group).await?
        }
    };
    // `output_bytes` stays the total *produced*; `truncated` reflects that
    // *forwarded* bytes were capped (matching the non-PTY contract).
    let (output_bytes, truncated) = chunker.await.unwrap_or((0, false));

    let signal = {
        use std::os::unix::process::ExitStatusExt as _;
        status.signal()
    };
    Ok(PtyExecOutcome {
        exit_code: status.code(),
        signal,
        cancelled,
        killed_process_group,
        output_bytes,
        truncated,
    })
}

/// Resolve a blocking-wait join result into the child's exit status.
fn join_wait(
    res: Result<std::io::Result<std::process::ExitStatus>, tokio::task::JoinError>,
) -> Result<std::process::ExitStatus, crate::runner::RunError> {
    match res {
        Ok(Ok(status)) => Ok(status),
        Ok(Err(e)) => Err(crate::runner::RunError::Spawn(e)),
        Err(e) => Err(crate::runner::RunError::Spawn(std::io::Error::other(e))),
    }
}

/// SIGTERM the child's process group, then escalate to SIGKILL after `grace`,
/// returning the child's final exit status.
async fn terminate_then_kill(
    pid: Option<u32>,
    grace: Duration,
    wait: &mut tokio::task::JoinHandle<std::io::Result<std::process::ExitStatus>>,
    killed_process_group: &mut bool,
) -> Result<std::process::ExitStatus, crate::runner::RunError> {
    let Some(pid) = pid else {
        return join_wait(wait.await);
    };
    terminate_process_group(pid);
    match tokio::time::timeout(grace, &mut *wait).await {
        Ok(res) => join_wait(res),
        Err(_) => {
            *killed_process_group = true;
            kill_process_group(pid);
            join_wait(wait.await)
        }
    }
}

/// Emit one `com.mxagent.stream.chunk.v1` of merged PTY output (base64) into
/// `room`, advancing `seq`.
async fn emit_pty_chunk(room: &Room, invocation_id: &str, data: &[u8], eof: bool, seq: &mut u64) {
    use base64::Engine as _;
    use sha2::{Digest as _, Sha256};
    // Populate the per-chunk integrity digest over the raw bytes (the same bytes
    // the CLI reconstructs by base64-decoding `data`), so a tampered chunk fails
    // the CLI's strict `sha256` check (issue #304). The EOF marker has no payload.
    let sha256 = (!data.is_empty())
        .then(|| base64::engine::general_purpose::STANDARD.encode(Sha256::digest(data)));
    let chunk = StreamChunk {
        invocation_id: invocation_id.to_string(),
        stream: StreamKind::Pty,
        seq: *seq,
        encoding: "base64".to_string(),
        data: base64::engine::general_purpose::STANDARD.encode(data),
        eof,
        compressed: false,
        sha256,
        timestamp: rfc3339_now(),
        extra: Default::default(),
    };
    *seq += 1;
    if let Ok(content) = serde_json::to_value(&chunk) {
        if let Err(e) = room.send_raw(STREAM_CHUNK, content).await {
            tracing::warn!(error = %e, invocation_id, "failed to emit pty stream.chunk");
        }
    }
}

/// Build and sign a `com.mxagent.pty.resize.v1` content value.
///
/// Constructs a [`PtyResize`] for `invocation_id` carrying the new terminal
/// `size`, then signs the content with `signing_key`, embedding the detached
/// signature under the `signature` field. The returned JSON value is ready to be
/// sent as the timeline event's content. Resize is a signed control event like
/// [`build_signed_exec_stdin`] / [`build_signed_exec_cancel`].
pub fn build_signed_pty_resize(
    signing_key: &SigningKey,
    key_id: impl Into<String>,
    invocation_id: impl Into<String>,
    size: PtyWinsize,
    created_at: impl Into<String>,
    nonce: impl Into<String>,
) -> Result<Value, SignatureError> {
    // Build the unsigned content with a placeholder signature, then sign it in
    // place. `sign_into` excludes the `signature` field from the signed bytes,
    // so the placeholder does not affect the result.
    let resize = PtyResize {
        invocation_id: invocation_id.into(),
        rows: size.rows,
        cols: size.cols,
        pixel_width: size.pixel_width,
        pixel_height: size.pixel_height,
        created_at: created_at.into(),
        nonce: nonce.into(),
        signature: Signature {
            alg: signing::ALG_ED25519.to_string(),
            key_id: key_id.into(),
            sig: String::new(),
        },
        extra: Default::default(),
    };
    let mut content = serde_json::to_value(&resize).expect("PtyResize serializes to a JSON object");
    let key_id = resize.signature.key_id;
    signing::sign_into(signing_key, key_id, &mut content)?;
    Ok(content)
}

/// Send a signed `com.mxagent.pty.resize.v1` window-size control into `room`.
///
/// Resize is signed like `exec.stdin` / `exec.cancel`: it changes only the
/// window size of an already-authorized, running invocation and can execute
/// nothing, but it is still verified against a locally trusted signing key owned
/// by the requester (see [`handle_live_pty_resize`]) so a spoofed sender cannot
/// jam another invocation's terminal. Builds and signs the resize with
/// [`build_signed_pty_resize`], then emits it as a Matrix timeline event.
pub async fn send_pty_resize(
    room: &Room,
    signing_key: &SigningKey,
    key_id: impl Into<String>,
    invocation_id: impl Into<String>,
    size: PtyWinsize,
) -> Result<(), WorkspaceError> {
    // Signing only fails when the content is not a JSON object; the content we
    // build here is always an object, so this cannot fail in practice.
    let content = build_signed_pty_resize(
        signing_key,
        key_id,
        invocation_id,
        size,
        rfc3339_now(),
        random_control_nonce(),
    )
    .expect("PtyResize content is always a JSON object");
    room.send_raw(PTY_RESIZE, content)
        .await
        .map_err(WorkspaceError::from)?;
    Ok(())
}

/// Handle a routed `com.mxagent.pty.resize.v1` for a live PTY invocation on this
/// daemon.
///
/// Resize is a signed control event, so it is authorized through the same
/// `authorize_live_control` gate (signature → trust → ownership) as
/// `exec.stdin` / `exec.cancel`: only the invocation's original requester, using
/// a locally trusted signing key, may resize its terminal. Room membership or a
/// spoofed Matrix sender alone never resizes another agent's session, and a
/// resize for an unknown or non-PTY invocation is silently ignored. Like the
/// other live controls, resize is **replay-checked per session** (issue #305): a
/// re-delivered frame carrying a nonce already seen this session is dropped
/// rather than re-applied.
pub async fn handle_live_pty_resize(
    room: &Room,
    paths: &crate::SessionPaths,
    content: &Value,
    resize: &PtyResize,
) {
    let Some(control) = live_exec_control(&resize.invocation_id) else {
        return;
    };
    if authorize_live_control(
        room,
        paths,
        content,
        &resize.signature.key_id,
        &control.requester_agent,
    )
    .await
    .is_err()
    {
        tracing::warn!(
            invocation_id = %resize.invocation_id,
            requester_agent = %control.requester_agent,
            "rejected unauthorized pty resize control"
        );
        return;
    }
    // Replay-check per session: a re-delivered resize carrying a seen nonce is
    // dropped so a replayed frame cannot flap an already-running terminal (#305).
    if !admit_control_nonce(&control, &resize.nonce) {
        tracing::warn!(
            invocation_id = %resize.invocation_id,
            "dropped replayed pty resize control frame (nonce already seen this session)"
        );
        return;
    }
    if let Some(resize_tx) = &control.resize {
        let size = PtyWinsize {
            rows: resize.rows,
            cols: resize.cols,
            pixel_width: resize.pixel_width,
            pixel_height: resize.pixel_height,
        };
        let _ = resize_tx.send(size).await;
    }
}

/// Map the policy sandbox selection to the sandbox-layer
/// [`Backend`][mx_agent_sandbox::Backend].
///
/// The currently-unimplemented `firejail` / `chroot` policy values, and an
/// unset selection, fall back to [`Backend::None`][mx_agent_sandbox::Backend::None]
/// (no isolation) — pre-existing behavior. Shared with the task-dispatch path so
/// both the direct `exec` and auto-executed task paths resolve the backend the
/// same way (architecture §13.5).
pub(crate) fn sandbox_backend(sandbox: Option<Sandbox>) -> mx_agent_sandbox::Backend {
    match sandbox {
        Some(Sandbox::Bubblewrap) => mx_agent_sandbox::Backend::Bubblewrap,
        Some(Sandbox::Docker | Sandbox::Podman) => mx_agent_sandbox::Backend::Container,
        _ => mx_agent_sandbox::Backend::None,
    }
}

/// Map the policy sandbox value to the container [`Runtime`][mx_agent_sandbox::Runtime]
/// the [`Backend::Container`][mx_agent_sandbox::Backend::Container] backend
/// launches through (issue #310).
///
/// `podman` selects [`Runtime::Podman`][mx_agent_sandbox::Runtime::Podman]; every
/// other value (including `docker` and the non-container backends, which ignore
/// the runtime) maps to [`Runtime::Docker`][mx_agent_sandbox::Runtime::Docker].
/// Shared with the task-dispatch and loopback paths so they all resolve the
/// runtime the same way.
pub(crate) fn container_runtime_for(sandbox: Option<Sandbox>) -> mx_agent_sandbox::Runtime {
    match sandbox {
        Some(Sandbox::Podman) => mx_agent_sandbox::Runtime::Podman,
        _ => mx_agent_sandbox::Runtime::Docker,
    }
}

/// Map the policy network decision to the sandbox-layer
/// [`Network`][mx_agent_sandbox::Network] setting,
/// failing closed: an unset (or `deny`) policy network denies, and only an
/// explicit `network = "allow"` removes network isolation (architecture §13.5).
///
/// Shared with the task-dispatch path so both the direct `exec` and
/// auto-executed task paths resolve the network decision the same way.
pub(crate) fn network_for(network: Option<NetworkPolicy>) -> mx_agent_sandbox::Network {
    match network {
        Some(NetworkPolicy::Allow) => mx_agent_sandbox::Network::Allow,
        Some(NetworkPolicy::Deny) | None => mx_agent_sandbox::Network::Deny,
    }
}

fn signal_name(n: i32) -> Option<String> {
    Some(
        match n {
            1 => "SIGHUP",
            2 => "SIGINT",
            3 => "SIGQUIT",
            6 => "SIGABRT",
            8 => "SIGFPE",
            9 => "SIGKILL",
            11 => "SIGSEGV",
            13 => "SIGPIPE",
            14 => "SIGALRM",
            15 => "SIGTERM",
            _ => return None,
        }
        .to_string(),
    )
}

fn audit_exec_decision(
    paths: &crate::SessionPaths,
    room_id: &str,
    request: &ExecRequest,
    outcome: &Outcome,
) {
    let record = AuditRecord::for_exec(
        room_id,
        &request.requesting_agent,
        &request.target_agent,
        Some(&request.invocation_id),
        &request.command,
        outcome,
    );
    append_audit(paths, &request.invocation_id, record);
}

/// Audit an exec rejection from a gate that runs *after* the policy engine —
/// currently only the verified-device gate (issue #240).
///
/// Policy denials carry a richer [`DenyReason`] and are audited via
/// [`audit_exec_decision`] with the policy [`Outcome`]; routing one here would
/// flatten it to `"policy_denied"`. This is reserved for post-policy gate
/// denials whose reason is not a policy decision, so the audit trail records
/// *every* privileged denial (issue #240 spec: "denied … and audited"), not
/// just policy ones.
fn audit_exec_rejection(
    paths: &crate::SessionPaths,
    room_id: &str,
    request: &ExecRequest,
    rejection: &ExecRejection,
) {
    let record = AuditRecord::for_exec_denied(
        room_id,
        &request.requesting_agent,
        &request.target_agent,
        Some(&request.invocation_id),
        &request.command,
        &rejection.reason(),
    );
    append_audit(paths, &request.invocation_id, record);
}

/// Audit an authorized exec that is **held** pending an approval decision
/// (issue #306): `decision = held`, allow-family rule, resolved sandbox.
fn audit_exec_held(
    paths: &crate::SessionPaths,
    room_id: &str,
    request: &ExecRequest,
    allowance: &Allowance,
) {
    let record = AuditRecord::for_exec_held(
        room_id,
        &request.requesting_agent,
        &request.target_agent,
        Some(&request.invocation_id),
        &request.command,
        &Outcome::Allow(allowance.clone()),
    );
    append_audit(paths, &request.invocation_id, record);
}

/// Audit a held exec that was **released** to run after an approving decision
/// re-authorized it (issue #306): `decision = released`.
fn audit_exec_released(
    paths: &crate::SessionPaths,
    room_id: &str,
    request: &ExecRequest,
    allowance: &Allowance,
) {
    let record = AuditRecord::for_exec_released(
        room_id,
        &request.requesting_agent,
        &request.target_agent,
        Some(&request.invocation_id),
        &request.command,
        &Outcome::Allow(allowance.clone()),
    );
    append_audit(paths, &request.invocation_id, record);
}

/// Audit a held exec that **expired** without a decision and was swept
/// fail-closed (issue #306): `decision = expired`, no sandbox (nothing ran).
fn audit_exec_expired(paths: &crate::SessionPaths, room_id: &str, request: &ExecRequest) {
    let record = AuditRecord::for_exec_expired(
        room_id,
        &request.requesting_agent,
        &request.target_agent,
        Some(&request.invocation_id),
        &request.command,
    );
    append_audit(paths, &request.invocation_id, record);
}

/// Current time in Unix seconds (used as the live-pgid liveness discriminator).
fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn rfc3339_now() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let days = (secs / 86_400) as i64;
    let tod = (secs % 86_400) as i64;
    let (hour, minute, second) = (tod / 3600, (tod % 3600) / 60, tod % 60);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = mp + if mp < 10 { 3 } else { -9 };
    let year = y + if m <= 2 { 1 } else { 0 };
    format!("{year:04}-{m:02}-{d:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Why an incoming `com.mxagent.exec.cancel.v1` was rejected (architecture §7.5,
/// §13.1).
///
/// Cancellation authorization is narrower than a fresh exec: there is no policy
/// or routing check, but the requester must prove they own the invocation they
/// are cancelling. Every variant maps to a stable, machine-readable reason via
/// [`CancelRejection::reason`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CancelRejection {
    /// The cancel content was not a JSON object, so it cannot be verified.
    Malformed,
    /// The cancel carried no `signature` field.
    Unsigned,
    /// The signature was present but did not verify against the signing key.
    InvalidSignature,
    /// The cancel names a different invocation than the one being authorized.
    InvocationMismatch {
        /// The `invocation_id` named in the cancel request.
        requested: String,
    },
    /// The signing key is unknown to or revoked in the local trust store.
    UntrustedKey {
        /// The signing key identifier that was rejected.
        key_id: String,
    },
    /// The requester does not own the invocation, so may not cancel it.
    Unauthorized {
        /// The agent that owns (requested) the invocation.
        owner: String,
    },
}

impl CancelRejection {
    /// A stable, machine-readable reason string.
    pub fn reason(&self) -> String {
        match self {
            Self::Malformed => "malformed_request".to_string(),
            Self::Unsigned => "unsigned".to_string(),
            Self::InvalidSignature => "invalid_signature".to_string(),
            Self::InvocationMismatch { .. } => "invocation_mismatch".to_string(),
            Self::UntrustedKey { .. } => "untrusted_key".to_string(),
            Self::Unauthorized { .. } => "unauthorized".to_string(),
        }
    }
}

impl std::fmt::Display for CancelRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed => write!(f, "cancel request content is not a JSON object"),
            Self::Unsigned => write!(f, "cancel request is unsigned"),
            Self::InvalidSignature => write!(f, "cancel request signature is invalid"),
            Self::InvocationMismatch { requested } => {
                write!(f, "cancel request names invocation {requested:?}")
            }
            Self::UntrustedKey { key_id } => {
                write!(f, "signing key {key_id:?} is not trusted")
            }
            Self::Unauthorized { owner } => {
                write!(f, "only the requester {owner:?} may cancel this invocation")
            }
        }
    }
}

impl std::error::Error for CancelRejection {}

/// Build and sign a `com.mxagent.exec.stdin.v1` content value.
///
/// `data` is base64 encoded inside the signed content; `eof` closes stdin after
/// the target writes any bytes in this frame.
pub fn build_signed_exec_stdin(
    signing_key: &SigningKey,
    key_id: impl Into<String>,
    invocation_id: impl Into<String>,
    data: &[u8],
    eof: bool,
    created_at: impl Into<String>,
    nonce: impl Into<String>,
) -> Result<Value, SignatureError> {
    use base64::Engine as _;

    let stdin = ExecStdin {
        invocation_id: invocation_id.into(),
        data: base64::engine::general_purpose::STANDARD.encode(data),
        eof,
        created_at: created_at.into(),
        nonce: nonce.into(),
        signature: Signature {
            alg: signing::ALG_ED25519.to_string(),
            key_id: key_id.into(),
            sig: String::new(),
        },
        extra: Default::default(),
    };
    let mut content = serde_json::to_value(&stdin).expect("ExecStdin serializes to a JSON object");
    let key_id = stdin.signature.key_id;
    signing::sign_into(signing_key, key_id, &mut content)?;
    Ok(content)
}

/// Send a signed `com.mxagent.exec.stdin.v1` timeline event into `room`.
pub async fn send_exec_stdin(
    room: &Room,
    signing_key: &SigningKey,
    key_id: impl Into<String>,
    invocation_id: impl Into<String>,
    data: &[u8],
    eof: bool,
) -> Result<ExecStdin, WorkspaceError> {
    let content = build_signed_exec_stdin(
        signing_key,
        key_id,
        invocation_id,
        data,
        eof,
        rfc3339_now(),
        random_control_nonce(),
    )
    .expect("ExecStdin content is always a JSON object");
    room.send_raw(EXEC_STDIN, content.clone())
        .await
        .map_err(WorkspaceError::from)?;
    serde_json::from_value::<ExecStdin>(content)
        .map_err(|e| WorkspaceError::from(matrix_sdk::Error::SerdeJson(e)))
}

fn random_control_nonce() -> String {
    use base64::Engine as _;
    let mut bytes = [0u8; 16];
    if getrandom::fill(&mut bytes).is_err() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default();
        bytes.copy_from_slice(&nanos.to_le_bytes());
    }
    base64::engine::general_purpose::STANDARD_NO_PAD.encode(bytes)
}

/// Build and sign a `com.mxagent.exec.cancel.v1` content value.
///
/// Constructs an [`ExecCancel`] for `invocation_id` carrying a human-readable
/// `reason`, then signs the content with `signing_key`, embedding the detached
/// signature under the `signature` field. The returned JSON value is ready to be
/// sent as the timeline event's content.
pub fn build_signed_exec_cancel(
    signing_key: &SigningKey,
    key_id: impl Into<String>,
    invocation_id: impl Into<String>,
    reason: impl Into<String>,
    created_at: impl Into<String>,
    nonce: impl Into<String>,
) -> Result<Value, SignatureError> {
    // Build the unsigned content with a placeholder signature, then sign it in
    // place. `sign_into` excludes the `signature` field from the signed bytes,
    // so the placeholder does not affect the result.
    let cancel = ExecCancel {
        invocation_id: invocation_id.into(),
        reason: reason.into(),
        created_at: created_at.into(),
        nonce: nonce.into(),
        signature: Signature {
            alg: signing::ALG_ED25519.to_string(),
            key_id: key_id.into(),
            sig: String::new(),
        },
        extra: Default::default(),
    };
    let mut content =
        serde_json::to_value(&cancel).expect("ExecCancel serializes to a JSON object");
    let key_id = cancel.signature.key_id;
    signing::sign_into(signing_key, key_id, &mut content)?;
    Ok(content)
}

/// Send a signed `com.mxagent.exec.cancel.v1` timeline event into `room`.
///
/// Builds and signs the cancel with [`build_signed_exec_cancel`], then sends it
/// as a Matrix timeline event so it federates to the target agent. Returns the
/// parsed [`ExecCancel`] that was sent (including its embedded signature).
pub async fn send_exec_cancel(
    room: &Room,
    signing_key: &SigningKey,
    key_id: impl Into<String>,
    invocation_id: impl Into<String>,
    reason: impl Into<String>,
    created_at: impl Into<String>,
    nonce: impl Into<String>,
) -> Result<ExecCancel, WorkspaceError> {
    // Signing only fails when the content is not a JSON object; the content we
    // build here is always an object, so this cannot fail in practice.
    let content = build_signed_exec_cancel(
        signing_key,
        key_id,
        invocation_id,
        reason,
        created_at,
        nonce,
    )
    .expect("ExecCancel content is always a JSON object");
    room.send_raw(EXEC_CANCEL, content.clone())
        .await
        .map_err(WorkspaceError::from)?;
    serde_json::from_value::<ExecCancel>(content)
        .map_err(|e| WorkspaceError::from(matrix_sdk::Error::SerdeJson(e)))
}

/// Verify and authorize an incoming `com.mxagent.exec.cancel.v1` against the
/// `invocation` it targets (architecture §7.5, §13.1).
///
/// Runs the receive-side pipeline: signature, then invocation match, then trust,
/// then ownership. On success the parsed [`ExecCancel`] is returned; on failure
/// the first failing check is reported as a [`CancelRejection`] and **nothing is
/// terminated** — this routine never signals a process.
///
/// `verifying_key` is the public key resolved for the cancel's signing key;
/// `requesting_agent` is the agent identity the cancel was sent from (resolved
/// from the Matrix event sender). Authorization requires that this agent owns
/// the invocation — i.e. it is the invocation's original `requester` — so a peer
/// cannot cancel another agent's running command.
pub fn authorize_exec_cancel(
    content: &Value,
    verifying_key: &VerifyingKey,
    trust: &TrustStore,
    invocation: &InvocationState,
    requesting_agent: &str,
) -> Result<ExecCancel, CancelRejection> {
    // 1. Signature must be present and valid.
    let signature = read_cancel_signature(content)?.ok_or(CancelRejection::Unsigned)?;
    signing::verify(verifying_key, content).map_err(|e| match e {
        SignatureError::MissingSignature => CancelRejection::Unsigned,
        SignatureError::NotAnObject => CancelRejection::Malformed,
        _ => CancelRejection::InvalidSignature,
    })?;

    let cancel: ExecCancel =
        serde_json::from_value(content.clone()).map_err(|_| CancelRejection::Malformed)?;

    // 2. The cancel must name the invocation being authorized.
    if cancel.invocation_id != invocation.invocation_id {
        return Err(CancelRejection::InvocationMismatch {
            requested: cancel.invocation_id,
        });
    }

    // 3. The signing key must be locally trusted.
    if !trust.is_key_trusted(&signature.key_id) {
        return Err(CancelRejection::UntrustedKey {
            key_id: signature.key_id,
        });
    }

    // 4. The requester must own the invocation they are cancelling.
    if requesting_agent != invocation.requester {
        return Err(CancelRejection::Unauthorized {
            owner: invocation.requester.clone(),
        });
    }

    Ok(cancel)
}

/// Read the detached [`Signature`] embedded in a cancel `content`, mirroring
/// [`read_signature`] but mapping failures to [`CancelRejection`].
fn read_cancel_signature(content: &Value) -> Result<Option<Signature>, CancelRejection> {
    let obj = content.as_object().ok_or(CancelRejection::Malformed)?;
    match obj.get(SIGNATURE_FIELD) {
        None => Ok(None),
        Some(Value::Null) => Ok(None),
        Some(value) => serde_json::from_value::<Signature>(value.clone())
            .map(Some)
            .map_err(|_| CancelRejection::InvalidSignature),
    }
}

/// Emit a `com.mxagent.exec.cancelled.v1` timeline event into `room`.
///
/// Confirms that a cancellation tore down the invocation's process group:
/// `signal_sent` names the delivered signal (see [`crate::runner::CANCEL_SIGNAL`])
/// and `killed_process_group` records whether the whole group was signalled.
pub async fn emit_exec_cancelled(
    room: &Room,
    invocation_id: impl Into<String>,
    signal_sent: impl Into<String>,
    killed_process_group: bool,
    finished_at: impl Into<String>,
) -> Result<(), WorkspaceError> {
    let cancelled = ExecCancelled {
        invocation_id: invocation_id.into(),
        signal_sent: signal_sent.into(),
        killed_process_group,
        finished_at: finished_at.into(),
        extra: Default::default(),
    };
    let content = serde_json::to_value(&cancelled)
        .map_err(|e| WorkspaceError::from(matrix_sdk::Error::SerdeJson(e)))?;
    room.send_raw(EXEC_CANCELLED, content)
        .await
        .map_err(WorkspaceError::from)?;
    Ok(())
}

// `Outcome` does not expose its deny reason directly; provide a small helper.
trait OutcomeExt {
    fn deny_reason(&self) -> Option<DenyReason>;
}

impl OutcomeExt for mx_agent_policy::Outcome {
    fn deny_reason(&self) -> Option<DenyReason> {
        match self {
            mx_agent_policy::Outcome::Allow(_) => None,
            mx_agent_policy::Outcome::Deny(reason) => Some(reason.clone()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use serde_json::json;

    /// A unique, per-call data dir resolved via [`crate::SessionPaths::for_data_dir`].
    ///
    /// Avoids touching `MX_AGENT_DATA_DIR` so tests that spawn threads can share
    /// one explicit data dir without conflicting over the process environment.
    fn unique_temp_dir(tag: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "mx-agent-exec-{}-{}-{}",
            tag,
            std::process::id(),
            n,
        ))
    }

    /// Deterministic signing key from a fixed seed.
    fn test_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn key_id_for(key: &SigningKey) -> String {
        use base64::Engine as _;
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(key.verifying_key().as_bytes());
        let b64 = base64::engine::general_purpose::STANDARD_NO_PAD.encode(digest);
        format!("{}:{b64}", crate::signing::KEY_ID_PREFIX)
    }

    const ROOM: &str = "!abc:matrix.org";
    const AGENT: &str = "@claude:matrix.org";
    const TARGET: &str = "developer-pi";

    fn policy() -> Policy {
        let toml = r#"
[rooms."!abc:matrix.org"]
trusted = true

[rooms."!abc:matrix.org".agents."@claude:matrix.org"]
allow_exec = true
allow_commands = ["cargo"]
allow_cwd = ["/home/me/code/project"]
"#;
        Policy::parse(toml).expect("policy parses")
    }

    fn trust_with(key_id: &str) -> TrustStore {
        let mut store = TrustStore::default();
        store.approve(AGENT, key_id, None, None, None);
        store
    }

    fn options(command: &[&str], cwd: &str) -> ExecRequestOptions {
        ExecRequestOptions {
            target_agent: TARGET.to_string(),
            requesting_agent: AGENT.to_string(),
            command: command.iter().map(|s| s.to_string()).collect(),
            cwd: cwd.to_string(),
            env: BTreeMap::new(),
            stdin: false,
            stream: true,
            pty: false,
            timeout_ms: 600_000,
            task_id: None,
        }
    }

    fn signed_request(key: &SigningKey, opts: &ExecRequestOptions) -> Value {
        build_signed_exec_request(
            key,
            key_id_for(key),
            "inv_01HZ",
            "req_01HZ",
            "base64-nonce",
            "2026-06-02T12:00:00Z",
            "2026-06-02T12:05:00Z",
            opts,
        )
        .expect("signs")
    }

    fn authorize(
        content: &Value,
        key: &SigningKey,
        trust: &TrustStore,
    ) -> Result<ExecRequest, ExecRejection> {
        authorize_exec_request(
            content,
            &key.verifying_key(),
            trust,
            &policy(),
            ROOM,
            AGENT,
            TARGET,
        )
    }

    #[test]
    fn build_sets_idempotency_key_from_invocation() {
        let key = test_key();
        let content = signed_request(&key, &options(&["cargo", "test"], "/home/me/code/project"));
        let request: ExecRequest = serde_json::from_value(content).unwrap();
        assert_eq!(request.idempotency_key, "exec:inv_01HZ");
        assert_eq!(request.target_agent, TARGET);
        assert_eq!(request.command, vec!["cargo", "test"]);
    }

    #[test]
    fn allowed_request_authorizes() {
        // Acceptance: target daemon accepts allowed exec requests.
        let key = test_key();
        let content = signed_request(&key, &options(&["cargo", "test"], "/home/me/code/project"));
        let trust = trust_with(&key_id_for(&key));
        let request = authorize(&content, &key, &trust).expect("authorized");
        assert_eq!(request.invocation_id, "inv_01HZ");
        assert_eq!(request.command, vec!["cargo", "test"]);
    }

    /// A control-frame nonce is admitted once per live session; a re-delivered
    /// (replayed) frame carrying a seen nonce is dropped, and the seen-set is
    /// shared across clones (handlers operate on a clone of the control).
    #[test]
    fn replayed_control_nonce_is_dropped() {
        let (stdin_tx, _stdin_rx) = tokio::sync::mpsc::channel::<StdinFrame>(1);
        let (cancel_tx, _cancel_rx) = tokio::sync::watch::channel::<Option<String>>(None);
        let control = LiveExecControl {
            requester_agent: AGENT.to_string(),
            stdin: stdin_tx,
            cancel: cancel_tx,
            resize: None,
            seen_control_nonces: Arc::new(Mutex::new(HashSet::new())),
        };

        // First sight of a nonce is fresh; the same nonce again is a replay.
        assert!(admit_control_nonce(&control, "nonce-1"));
        assert!(!admit_control_nonce(&control, "nonce-1"));
        // A distinct nonce is still fresh.
        assert!(admit_control_nonce(&control, "nonce-2"));

        // A clone shares the seen-set: already-seen nonces stay denied through it,
        // and a fresh nonce recorded via the clone is denied on the original.
        let cloned = control.clone();
        assert!(!admit_control_nonce(&cloned, "nonce-1"));
        assert!(!admit_control_nonce(&cloned, "nonce-2"));
        assert!(admit_control_nonce(&cloned, "nonce-3"));
        assert!(!admit_control_nonce(&control, "nonce-3"));
    }

    /// Regression test for the stdin-registration race: stdin (and its EOF)
    /// queued onto the control channel *before* the child process drains it must
    /// still reach the command. Previously the control was registered inside the
    /// spawned run task, so a stdin frame routed first was silently dropped and a
    /// `cat`-style command hung until timeout. `handle_live_exec_request` now
    /// registers the control and creates these channels before spawning, so this
    /// path delivers pre-queued stdin deterministically.
    #[tokio::test]
    async fn prequeued_stdin_reaches_the_command() {
        let key = test_key();
        let mut opts = options(&["cat"], "/");
        opts.stdin = true;
        let content = signed_request(&key, &opts);
        let request: ExecRequest = serde_json::from_value(content).unwrap();

        let allowance = Allowance {
            max_runtime_ms: Some(30_000),
            max_output_bytes: Some(1_000_000),
            sandbox: None,
            network: None,
            requires_approval: false,
            env_allowlist: Vec::new(),
            ..Allowance::default()
        };

        // Queue stdin and EOF before run_controlled_exec is even polled — the
        // exact ordering the old code lost.
        let (stdin_tx, stdin_rx) = tokio::sync::mpsc::channel::<StdinFrame>(64);
        let (_cancel_tx, cancel_rx) = tokio::sync::watch::channel::<Option<String>>(None);
        stdin_tx
            .send(Some(b"race-proof stdin\n".to_vec()))
            .await
            .expect("queue stdin");
        stdin_tx.send(None).await.expect("queue eof");
        drop(stdin_tx);

        let result = run_controlled_exec(&request, &allowance, stdin_rx, cancel_rx)
            .await
            .expect("exec runs");
        match result {
            ControlledExecResult::Finished(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                assert!(
                    stdout.contains("race-proof stdin"),
                    "cat should echo stdin queued before the process drained it; got {stdout:?}"
                );
                assert_eq!(output.exit_code, Some(0));
            }
            ControlledExecResult::Cancelled { .. } => {
                panic!("exec should have finished, not been cancelled")
            }
        }
    }

    /// Build an agent state whose published key matches `key`.
    fn agent_with(agent_id: &str, key: &SigningKey) -> AgentState {
        use mx_agent_protocol::schema::{AgentLoad, AgentWorkspace};
        let vk = key.verifying_key();
        AgentState {
            agent_id: agent_id.to_string(),
            kind: "pi".to_string(),
            matrix_user_id: format!("{agent_id}:matrix.org"),
            device_id: "DEV".to_string(),
            signing_key_id: crate::signing::key_id_for_verifying_key(&vk),
            signing_public_key: Some(crate::signing::encode_verifying_key(&vk)),
            status: "active".to_string(),
            capabilities: vec!["exec".to_string()],
            tools: vec![],
            workspace: AgentWorkspace {
                cwd: "/tmp".to_string(),
                project_id: String::new(),
                git_commit: String::new(),
            },
            load: AgentLoad {
                running_invocations: 0,
                max_invocations: 1,
            },
            last_seen_ts: 0,
            state_rev: 1,
            extra: Default::default(),
        }
    }

    /// A signed `exec.stdin` control frame from `key`.
    fn signed_stdin(key: &SigningKey) -> Value {
        build_signed_exec_stdin(
            key,
            crate::signing::key_id_for_verifying_key(&key.verifying_key()),
            "inv_01HZ",
            b"hello\n",
            true,
            "2026-06-02T12:00:00Z",
            "base64-nonce",
        )
        .expect("signs stdin")
    }

    #[test]
    fn control_authorized_by_requester_id_even_when_agents_share_a_key() {
        // Regression for the flaky live exec test: when the target and requester
        // publish the same signing key (the test harness loads one key from a
        // shared data dir), the requester must still be resolved by agent id.
        // The old key-search returned whichever agent the homeserver listed
        // first; if that was the target, the owner check failed and stdin (with
        // EOF) was dropped, hanging the command.
        let key = test_key();
        let key_id = crate::signing::key_id_for_verifying_key(&key.verifying_key());
        let trust = trust_with(&key_id);
        let content = signed_stdin(&key);

        let target = agent_with("developer-pi", &key);
        let requester = agent_with("@bob:matrix.org", &key);

        for agents in [
            vec![target.clone(), requester.clone()],
            vec![requester.clone(), target.clone()],
        ] {
            assert!(
                authorize_control_from_states(
                    &agents,
                    "@bob:matrix.org",
                    &content,
                    &key_id,
                    &trust
                )
                .is_ok(),
                "the real requester must authorize regardless of agent ordering"
            );
        }
    }

    #[test]
    fn control_rejected_when_frame_key_is_not_the_requesters_key() {
        let requester_key = test_key();
        let other_key = SigningKey::from_bytes(&[9u8; 32]);
        let requester_key_id =
            crate::signing::key_id_for_verifying_key(&requester_key.verifying_key());
        let other_key_id = crate::signing::key_id_for_verifying_key(&other_key.verifying_key());

        let content = signed_stdin(&other_key);
        let mut trust = TrustStore::default();
        trust.approve("@bob:matrix.org", &requester_key_id, None, None, None);
        trust.approve("@bob:matrix.org", &other_key_id, None, None, None);

        let agents = vec![agent_with("@bob:matrix.org", &requester_key)];
        assert!(
            authorize_control_from_states(
                &agents,
                "@bob:matrix.org",
                &content,
                &other_key_id,
                &trust
            )
            .is_err(),
            "a frame bearing a key other than the requester's registered key must be rejected"
        );
    }

    #[test]
    fn control_rejected_when_key_untrusted() {
        let key = test_key();
        let key_id = crate::signing::key_id_for_verifying_key(&key.verifying_key());
        let content = signed_stdin(&key);
        let agents = vec![agent_with("@bob:matrix.org", &key)];
        let trust = TrustStore::default();
        assert!(
            authorize_control_from_states(&agents, "@bob:matrix.org", &content, &key_id, &trust)
                .is_err(),
            "an untrusted key must be rejected"
        );
    }

    #[test]
    fn control_rejected_when_requester_not_in_room() {
        let key = test_key();
        let key_id = crate::signing::key_id_for_verifying_key(&key.verifying_key());
        let trust = trust_with(&key_id);
        let content = signed_stdin(&key);
        let agents = vec![agent_with("developer-pi", &key)];
        assert!(
            authorize_control_from_states(&agents, "@bob:matrix.org", &content, &key_id, &trust)
                .is_err(),
            "an unknown requester id must be rejected"
        );
    }

    /// A signed `pty.resize` control frame from `key`.
    fn signed_resize(key: &SigningKey) -> Value {
        build_signed_pty_resize(
            key,
            crate::signing::key_id_for_verifying_key(&key.verifying_key()),
            "inv_01HZ",
            PtyWinsize::new(50, 132),
            "2026-06-02T12:00:00Z",
            "base64-nonce",
        )
        .expect("signs resize")
    }

    #[test]
    fn build_signed_pty_resize_is_verifiable_by_owner() {
        // A resize built by the requester verifies through the same
        // signature → trust → ownership gate as stdin/cancel.
        let key = test_key();
        let key_id = crate::signing::key_id_for_verifying_key(&key.verifying_key());
        let trust = trust_with(&key_id);
        let content = signed_resize(&key);
        let agents = vec![agent_with("@bob:matrix.org", &key)];
        assert!(
            authorize_control_from_states(&agents, "@bob:matrix.org", &content, &key_id, &trust)
                .is_ok(),
            "a signed resize from the trusted owner must authorize"
        );
    }

    #[test]
    fn unsigned_resize_is_rejected() {
        let key = test_key();
        let key_id = crate::signing::key_id_for_verifying_key(&key.verifying_key());
        let trust = trust_with(&key_id);
        let mut content = signed_resize(&key);
        // Strip the signature: an unsigned resize must not authorize, unlike the
        // pre-#244 sender-authorized hint.
        content
            .as_object_mut()
            .unwrap()
            .remove(SIGNATURE_FIELD)
            .unwrap();
        assert!(
            authorize_control_from_states(
                &agents_with_owner(&key),
                "@bob:matrix.org",
                &content,
                &key_id,
                &trust
            )
            .is_err(),
            "an unsigned resize must be rejected"
        );
    }

    #[test]
    fn resize_from_untrusted_key_is_rejected() {
        let key = test_key();
        let key_id = crate::signing::key_id_for_verifying_key(&key.verifying_key());
        let content = signed_resize(&key);
        let trust = TrustStore::default();
        assert!(
            authorize_control_from_states(
                &agents_with_owner(&key),
                "@bob:matrix.org",
                &content,
                &key_id,
                &trust
            )
            .is_err(),
            "a resize signed by an untrusted key must be rejected"
        );
    }

    #[test]
    fn resize_from_non_owner_is_rejected() {
        // The signature verifies and the key is trusted, but the requester id is
        // not the invocation's owner.
        let key = test_key();
        let key_id = crate::signing::key_id_for_verifying_key(&key.verifying_key());
        let trust = trust_with(&key_id);
        let content = signed_resize(&key);
        let agents = vec![agent_with("@mallory:matrix.org", &key)];
        assert!(
            authorize_control_from_states(&agents, "@bob:matrix.org", &content, &key_id, &trust)
                .is_err(),
            "a resize from an agent that is not the requester must be rejected"
        );
    }

    #[test]
    fn tampered_resize_fails_signature_check() {
        let key = test_key();
        let key_id = crate::signing::key_id_for_verifying_key(&key.verifying_key());
        let trust = trust_with(&key_id);
        let mut content = signed_resize(&key);
        // Mutate a signed field after signing: verification must fail.
        content.as_object_mut().unwrap()["rows"] = serde_json::json!(200);
        assert!(
            authorize_control_from_states(
                &agents_with_owner(&key),
                "@bob:matrix.org",
                &content,
                &key_id,
                &trust
            )
            .is_err(),
            "a resize whose signed content was altered must be rejected"
        );
    }

    /// The room as seen by a resize handler: the requester `@bob` published `key`.
    fn agents_with_owner(key: &SigningKey) -> Vec<AgentState> {
        vec![agent_with("@bob:matrix.org", key)]
    }

    #[test]
    fn unsigned_request_is_rejected() {
        let key = test_key();
        let mut content =
            signed_request(&key, &options(&["cargo", "test"], "/home/me/code/project"));
        content
            .as_object_mut()
            .unwrap()
            .remove(SIGNATURE_FIELD)
            .unwrap();
        let trust = trust_with(&key_id_for(&key));
        let err = authorize(&content, &key, &trust).unwrap_err();
        assert_eq!(err, ExecRejection::Unsigned);
        assert_eq!(err.reason(), "unsigned");
    }

    #[test]
    fn null_signature_is_treated_as_unsigned() {
        let key = test_key();
        let mut content =
            signed_request(&key, &options(&["cargo", "test"], "/home/me/code/project"));
        content.as_object_mut().unwrap()[SIGNATURE_FIELD] = Value::Null;
        let trust = trust_with(&key_id_for(&key));
        let err = authorize(&content, &key, &trust).unwrap_err();
        assert_eq!(err, ExecRejection::Unsigned);
    }

    #[test]
    fn tampered_payload_fails_signature_check() {
        let key = test_key();
        let mut content =
            signed_request(&key, &options(&["cargo", "test"], "/home/me/code/project"));
        content["command"] = json!(["cargo", "publish"]);
        let trust = trust_with(&key_id_for(&key));
        let err = authorize(&content, &key, &trust).unwrap_err();
        assert_eq!(err, ExecRejection::InvalidSignature);
    }

    #[test]
    fn wrong_target_is_rejected() {
        // Routing: a request addressed to another agent is not run here.
        let key = test_key();
        let mut opts = options(&["cargo", "test"], "/home/me/code/project");
        opts.target_agent = "some-other-agent".to_string();
        let content = signed_request(&key, &opts);
        let trust = trust_with(&key_id_for(&key));
        let err = authorize(&content, &key, &trust).unwrap_err();
        assert_eq!(
            err,
            ExecRejection::WrongTarget {
                target: "some-other-agent".to_string()
            }
        );
        assert_eq!(err.reason(), "wrong_target");
    }

    #[test]
    fn untrusted_key_is_rejected() {
        let key = test_key();
        let content = signed_request(&key, &options(&["cargo", "test"], "/home/me/code/project"));
        let trust = TrustStore::default();
        let err = authorize(&content, &key, &trust).unwrap_err();
        assert_eq!(
            err,
            ExecRejection::UntrustedKey {
                key_id: key_id_for(&key)
            }
        );
        assert_eq!(err.reason(), "untrusted_key");
    }

    #[test]
    fn revoked_key_is_rejected() {
        let key = test_key();
        let content = signed_request(&key, &options(&["cargo", "test"], "/home/me/code/project"));
        let mut trust = trust_with(&key_id_for(&key));
        trust.revoke(AGENT, &key_id_for(&key));
        let err = authorize(&content, &key, &trust).unwrap_err();
        assert!(matches!(err, ExecRejection::UntrustedKey { .. }));
    }

    #[test]
    fn policy_denied_command_is_rejected_without_spawning() {
        // Acceptance: disallowed requests emit rejection without spawning. This
        // routine never spawns; a denied command simply yields a rejection.
        let key = test_key();
        let content = signed_request(&key, &options(&["rm", "-rf", "/"], "/home/me/code/project"));
        let trust = trust_with(&key_id_for(&key));
        let err = authorize(&content, &key, &trust).unwrap_err();
        assert!(matches!(err, ExecRejection::PolicyDenied(_)));
        assert_eq!(err.reason(), "policy_denied");
    }

    #[test]
    fn pipeline_order_signature_before_trust() {
        // A tampered request from an untrusted key fails on the signature first.
        let key = test_key();
        let mut content =
            signed_request(&key, &options(&["cargo", "test"], "/home/me/code/project"));
        content["command"] = json!(["cargo", "publish"]);
        let trust = TrustStore::default();
        let err = authorize(&content, &key, &trust).unwrap_err();
        assert_eq!(err, ExecRejection::InvalidSignature);
    }

    #[test]
    fn malformed_content_is_rejected() {
        let key = test_key();
        let trust = trust_with(&key_id_for(&key));
        let content = json!([1, 2, 3]);
        let err = authorize(&content, &key, &trust).unwrap_err();
        assert_eq!(err, ExecRejection::Malformed);
    }

    #[test]
    fn invocation_state_is_built_in_accepted_state() {
        let key = test_key();
        let content = signed_request(&key, &options(&["cargo", "test"], "/home/me/code/project"));
        let request: ExecRequest = serde_json::from_value(content).unwrap();
        let state = invocation_state_for(&request, "2026-06-02T12:00:01Z");
        assert_eq!(state.invocation_id, "inv_01HZ");
        assert_eq!(state.requester, AGENT);
        assert_eq!(state.target, TARGET);
        assert_eq!(state.state, "accepted");
        assert_eq!(state.created_at, "2026-06-02T12:00:01Z");
        assert_eq!(state.updated_at, "2026-06-02T12:00:01Z");
        assert!(state.exit_code.is_none());
    }

    // --- cancellation (#48) ---

    /// A `running` invocation owned by [`AGENT`], the canonical cancel target.
    fn running_invocation() -> InvocationState {
        InvocationState {
            invocation_id: "inv_01HZ".to_string(),
            task_id: None,
            requester: AGENT.to_string(),
            target: TARGET.to_string(),
            state: "running".to_string(),
            created_at: "2026-06-02T12:00:00Z".to_string(),
            updated_at: "2026-06-02T12:00:01Z".to_string(),
            exit_code: None,
            state_rev: 1,
            extra: Default::default(),
        }
    }

    fn signed_cancel(key: &SigningKey, invocation_id: &str) -> Value {
        build_signed_exec_cancel(
            key,
            key_id_for(key),
            invocation_id,
            "user requested",
            "2026-06-02T12:01:00Z",
            "base64-nonce",
        )
        .expect("signs")
    }

    #[test]
    fn owner_can_cancel_running_invocation() {
        // Acceptance: `invocation cancel` is authorized for the running command's
        // own requester.
        let key = test_key();
        let content = signed_cancel(&key, "inv_01HZ");
        let trust = trust_with(&key_id_for(&key));
        let cancel = authorize_exec_cancel(
            &content,
            &key.verifying_key(),
            &trust,
            &running_invocation(),
            AGENT,
        )
        .expect("authorized");
        assert_eq!(cancel.invocation_id, "inv_01HZ");
        assert_eq!(cancel.reason, "user requested");
    }

    #[test]
    fn unsigned_cancel_is_rejected() {
        let key = test_key();
        let mut content = signed_cancel(&key, "inv_01HZ");
        content
            .as_object_mut()
            .unwrap()
            .remove(SIGNATURE_FIELD)
            .unwrap();
        let trust = trust_with(&key_id_for(&key));
        let err = authorize_exec_cancel(
            &content,
            &key.verifying_key(),
            &trust,
            &running_invocation(),
            AGENT,
        )
        .unwrap_err();
        assert_eq!(err, CancelRejection::Unsigned);
        assert_eq!(err.reason(), "unsigned");
    }

    #[test]
    fn tampered_cancel_fails_signature_check() {
        let key = test_key();
        let mut content = signed_cancel(&key, "inv_01HZ");
        content["reason"] = json!("something else");
        let trust = trust_with(&key_id_for(&key));
        let err = authorize_exec_cancel(
            &content,
            &key.verifying_key(),
            &trust,
            &running_invocation(),
            AGENT,
        )
        .unwrap_err();
        assert_eq!(err, CancelRejection::InvalidSignature);
    }

    #[test]
    fn cancel_for_other_invocation_is_rejected() {
        let key = test_key();
        let content = signed_cancel(&key, "inv_other");
        let trust = trust_with(&key_id_for(&key));
        let err = authorize_exec_cancel(
            &content,
            &key.verifying_key(),
            &trust,
            &running_invocation(),
            AGENT,
        )
        .unwrap_err();
        assert_eq!(
            err,
            CancelRejection::InvocationMismatch {
                requested: "inv_other".to_string()
            }
        );
    }

    #[test]
    fn cancel_from_untrusted_key_is_rejected() {
        let key = test_key();
        let content = signed_cancel(&key, "inv_01HZ");
        let trust = TrustStore::default();
        let err = authorize_exec_cancel(
            &content,
            &key.verifying_key(),
            &trust,
            &running_invocation(),
            AGENT,
        )
        .unwrap_err();
        assert_eq!(
            err,
            CancelRejection::UntrustedKey {
                key_id: key_id_for(&key)
            }
        );
    }

    #[test]
    fn cancel_from_non_owner_is_rejected() {
        // Acceptance: unauthorized cancellation is rejected. A trusted peer that
        // does not own the invocation may not cancel it.
        let key = test_key();
        let content = signed_cancel(&key, "inv_01HZ");
        let trust = trust_with(&key_id_for(&key));
        let err = authorize_exec_cancel(
            &content,
            &key.verifying_key(),
            &trust,
            &running_invocation(),
            "@someone-else:matrix.org",
        )
        .unwrap_err();
        assert_eq!(
            err,
            CancelRejection::Unauthorized {
                owner: AGENT.to_string()
            }
        );
        assert_eq!(err.reason(), "unauthorized");
    }

    #[test]
    fn cancel_pipeline_checks_signature_before_ownership() {
        // A tampered cancel from a non-owner fails on the signature first, so the
        // rejection does not leak the ownership relationship.
        let key = test_key();
        let mut content = signed_cancel(&key, "inv_01HZ");
        content["reason"] = json!("tampered");
        let trust = trust_with(&key_id_for(&key));
        let err = authorize_exec_cancel(
            &content,
            &key.verifying_key(),
            &trust,
            &running_invocation(),
            "@someone-else:matrix.org",
        )
        .unwrap_err();
        assert_eq!(err, CancelRejection::InvalidSignature);
    }

    // --- network_for and sandbox_backend mapping tests (issue #248) ----------

    #[test]
    fn network_for_allow_maps_to_allow() {
        assert_eq!(
            network_for(Some(NetworkPolicy::Allow)),
            mx_agent_sandbox::Network::Allow,
            "NetworkPolicy::Allow must map to Network::Allow"
        );
    }

    #[test]
    fn network_for_deny_maps_to_deny() {
        assert_eq!(
            network_for(Some(NetworkPolicy::Deny)),
            mx_agent_sandbox::Network::Deny,
            "NetworkPolicy::Deny must map to Network::Deny"
        );
    }

    #[test]
    fn network_for_none_fails_closed() {
        // An unset policy network must default to Deny — fail-closed means no
        // network access unless explicitly permitted (architecture §13.5).
        assert_eq!(
            network_for(None),
            mx_agent_sandbox::Network::Deny,
            "unset network must fail closed to Network::Deny"
        );
    }

    #[test]
    fn sandbox_backend_maps_policy_sandbox_values() {
        // Bubblewrap maps to the bubblewrap backend.
        assert_eq!(
            sandbox_backend(Some(Sandbox::Bubblewrap)),
            mx_agent_sandbox::Backend::Bubblewrap
        );
        // Docker and Podman both map to the container backend.
        assert_eq!(
            sandbox_backend(Some(Sandbox::Docker)),
            mx_agent_sandbox::Backend::Container
        );
        assert_eq!(
            sandbox_backend(Some(Sandbox::Podman)),
            mx_agent_sandbox::Backend::Container
        );
        // The explicit `none` policy value and an unset sandbox both map to the
        // baseline `Backend::None`.
        assert_eq!(
            sandbox_backend(Some(Sandbox::None)),
            mx_agent_sandbox::Backend::None
        );
        assert_eq!(
            sandbox_backend(None),
            mx_agent_sandbox::Backend::None,
            "unset sandbox must default to Backend::None"
        );
        // Firejail/Chroot can no longer reach this mapping: `Policy::validate`
        // rejects them at load time (issue #310), so they never appear in a
        // resolved allowance. The mapping's defensive fallback to `Backend::None`
        // (rather than a silent isolating backend) remains as belt-and-suspenders.
        assert_eq!(
            sandbox_backend(Some(Sandbox::Firejail)),
            mx_agent_sandbox::Backend::None,
            "firejail must never silently widen to an isolating backend"
        );
        assert_eq!(
            sandbox_backend(Some(Sandbox::Chroot)),
            mx_agent_sandbox::Backend::None,
            "chroot must never silently widen to an isolating backend"
        );
    }

    #[test]
    fn container_runtime_for_maps_podman_else_docker() {
        // The container runtime is implied by the policy sandbox value: only
        // `podman` selects the Podman runtime (issue #310).
        assert_eq!(
            container_runtime_for(Some(Sandbox::Podman)),
            mx_agent_sandbox::Runtime::Podman
        );
        for sandbox in [
            Some(Sandbox::Docker),
            Some(Sandbox::Bubblewrap),
            Some(Sandbox::None),
            None,
        ] {
            assert_eq!(
                container_runtime_for(sandbox),
                mx_agent_sandbox::Runtime::Docker,
                "{sandbox:?} must map to the Docker runtime"
            );
        }
    }

    // --- enforce_verified_device (issue #240) ---

    #[test]
    fn enforce_verified_device_off_allows_any_device_status() {
        // When require_verified_device is false (the default), device verification
        // status never affects the outcome — authority comes from signing+trust+policy.
        let off = Allowance {
            require_verified_device: false,
            ..Allowance::default()
        };
        assert!(enforce_verified_device(&off, None).is_ok());
        assert!(enforce_verified_device(&off, Some(false)).is_ok());
        assert!(enforce_verified_device(&off, Some(true)).is_ok());
    }

    #[test]
    fn enforce_verified_device_on_allows_verified_device() {
        let on = Allowance {
            require_verified_device: true,
            ..Allowance::default()
        };
        assert!(
            enforce_verified_device(&on, Some(true)).is_ok(),
            "a verified device must be allowed when the knob is on"
        );
    }

    #[test]
    fn enforce_verified_device_on_denies_unverified_device() {
        let on = Allowance {
            require_verified_device: true,
            ..Allowance::default()
        };
        let err = enforce_verified_device(&on, Some(false)).unwrap_err();
        assert_eq!(err, ExecRejection::UnverifiedDevice);
        assert_eq!(err.reason(), "unverified_device");
    }

    #[test]
    fn enforce_verified_device_on_denies_indeterminate_status() {
        // None means the crypto store has not yet seen the device — treated as
        // unverified so the gate fails safe rather than open.
        let on = Allowance {
            require_verified_device: true,
            ..Allowance::default()
        };
        let err = enforce_verified_device(&on, None).unwrap_err();
        assert_eq!(err, ExecRejection::UnverifiedDevice);
        assert_eq!(err.reason(), "unverified_device");
    }

    #[test]
    fn unverified_device_rejection_has_stable_reason_and_message() {
        let rejection = ExecRejection::UnverifiedDevice;
        assert_eq!(rejection.reason(), "unverified_device");
        let msg = rejection.to_string();
        assert!(
            msg.contains("verified"),
            "display should mention 'verified': {msg}"
        );
    }

    #[test]
    fn approval_outcome_rejections_have_stable_reasons() {
        // Issue #306: the terminal post-policy outcomes surfaced to a held
        // exec's requester carry stable, machine-readable reason strings so the
        // emitted `exec.rejected` is parseable.
        assert_eq!(ExecRejection::ApprovalDenied.reason(), "approval_denied");
        assert_eq!(ExecRejection::ApprovalExpired.reason(), "approval_expired");
        assert!(ExecRejection::ApprovalDenied.to_string().contains("denied"));
        assert!(ExecRejection::ApprovalExpired
            .to_string()
            .contains("expired"));
    }

    // ── Issue #316: live-pgid sidecar ──────────────────────────────────────────

    /// The live-pgid sidecar persists and reloads correctly, and clearing it
    /// results in an empty load. This verifies the round-trip that lets
    /// `kill_persisted_live_exec_children` and `reap_orphaned_live_exec_children`
    /// find orphaned process groups after a daemon force-kill or crash.
    #[test]
    fn live_pgids_sidecar_round_trips() {
        let dir = unique_temp_dir("pgid-sidecar");
        let paths = crate::session::SessionPaths::for_data_dir(dir.clone());
        paths.ensure_data_dir().unwrap();

        // No sidecar yet → empty vec.
        assert!(
            load_live_pgids(&paths).is_empty(),
            "missing sidecar must load as empty"
        );

        // Persist two pgid entries and reload them.
        let mut map = BTreeMap::new();
        map.insert(
            "inv_aaa".to_string(),
            LivePgid {
                pgid: 12345,
                started_unix: 1_000_000,
            },
        );
        map.insert(
            "inv_bbb".to_string(),
            LivePgid {
                pgid: 67890,
                started_unix: 1_000_001,
            },
        );
        persist_live_pgids(&paths, &map);

        let loaded = load_live_pgids(&paths);
        assert_eq!(loaded.len(), 2, "both pgids must round-trip");
        let pgids: std::collections::HashSet<u32> = loaded.iter().map(|r| r.pgid).collect();
        assert!(pgids.contains(&12345));
        assert!(pgids.contains(&67890));

        // Clearing removes the sidecar; next load is empty.
        clear_live_pgids_file(&paths);
        assert!(
            load_live_pgids(&paths).is_empty(),
            "cleared sidecar must load as empty"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `kill_persisted_live_exec_children` and `reap_orphaned_live_exec_children`
    /// must be no-ops when no sidecar file exists (issue #316: these are called on
    /// every daemon start and on `daemon stop` SIGKILL escalation).
    #[test]
    fn kill_persisted_and_reap_orphaned_children_with_no_sidecar_are_noops() {
        let dir = unique_temp_dir("pgid-nofile");
        let paths = crate::session::SessionPaths::for_data_dir(dir.clone());
        paths.ensure_data_dir().unwrap();

        // Neither must panic when the sidecar is absent.
        kill_persisted_live_exec_children(&paths);
        reap_orphaned_live_exec_children(&paths);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `kill_persisted_live_exec_children` actually delivers SIGKILL to a real
    /// process group, not just to a fake pgid stored in a JSON file (issue #316).
    ///
    /// This is the process-level e2e proof that `daemon stop`'s SIGKILL escalation
    /// path does not orphan in-flight exec children: a real `sleep 300` is spawned
    /// in its own process group, its pgid is recorded in the sidecar, and
    /// `kill_persisted_live_exec_children` kills it within the grace period.
    #[test]
    fn kill_persisted_live_exec_children_kills_real_process_group() {
        use nix::sys::signal;
        use nix::sys::wait::waitpid;
        use nix::unistd::Pid;
        use std::os::unix::process::CommandExt as _;
        use std::process::Command;

        let dir = unique_temp_dir("pgid-real-kill");
        let paths = crate::session::SessionPaths::for_data_dir(dir.clone());
        paths.ensure_data_dir().unwrap();

        // Spawn `sleep 300` in its own process group (setsid == pgid = child pid).
        let mut child = Command::new("sleep")
            .arg("300")
            .process_group(0) // new process group; pgid == child pid
            .spawn()
            .expect("spawn sleep 300 for orphan-kill test");
        let child_pid = child.id();
        let pgid = child_pid; // setsid → pgid == child pid

        // Register the child's pgid in the sidecar, mirroring what the exec
        // runner does before delegating to the child process.
        let mut map = std::collections::BTreeMap::new();
        map.insert(
            "inv_orphan_test".to_string(),
            LivePgid {
                pgid,
                started_unix: 0,
            },
        );
        persist_live_pgids(&paths, &map);
        assert!(
            load_live_pgids(&paths).iter().any(|r| r.pgid == pgid),
            "pgid must appear in the sidecar before the kill call"
        );

        // Verify the child is alive before we kill it.
        let target = Pid::from_raw(child_pid as i32);
        assert!(
            signal::kill(target, None).is_ok(),
            "child must be alive before kill_persisted_live_exec_children"
        );

        // This is the `daemon stop` SIGKILL-escalation path: the CLI process
        // (a different process from the daemon) reads the sidecar and kills
        // every recorded process group.
        kill_persisted_live_exec_children(&paths);

        // Wait for the child to actually exit (bounded by the SIGKILL).
        let _ = child.wait(); // reap the zombie
        let wait_result = waitpid(target, None);
        // Either the child was already waited above (Ok(WaitStatus::Exited)) or
        // waitpid returns ECHILD because it was already reaped — either way the
        // child is gone.
        match wait_result {
            Ok(_) | Err(nix::errno::Errno::ECHILD) => {}
            Err(e) => panic!("unexpected waitpid error: {e}"),
        }

        // The process must no longer be alive.
        assert!(
            !process_group_alive(pgid),
            "exec child process group (pgid={pgid}) must be dead after \
             kill_persisted_live_exec_children"
        );

        // The sidecar must have been cleared by the kill function.
        assert!(
            load_live_pgids(&paths).is_empty(),
            "live-pgids sidecar must be cleared after kill_persisted_live_exec_children"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An idempotency key derived from `build_signed_exec_request` always equals
    /// `exec:<invocation_id>`, matching the validation in `handle_live_exec_request`.
    /// A different format would cause the live handler to reject the request as
    /// `Malformed` (issue #316 receive-side de-dup).
    #[test]
    fn idempotency_key_derivation_matches_live_handler_check() {
        let key = test_key();
        for invocation_id in ["inv_01HZ", "01JABCDEFGH", "custom-id-42"] {
            let content = build_signed_exec_request(
                &key,
                key_id_for(&key),
                invocation_id,
                "req_x",
                "nonce_x",
                "2026-06-14T00:00:00Z",
                "2026-06-14T00:05:00Z",
                &options(&["cargo", "test"], "/home/me/code/project"),
            )
            .expect("signs");
            let req: ExecRequest = serde_json::from_value(content).unwrap();
            // This is the exact check the live handler performs before allowing
            // the request to proceed (live handler line: if request.idempotency_key
            // != format!("exec:{}", request.invocation_id)).
            assert_eq!(
                req.idempotency_key,
                format!("exec:{}", req.invocation_id),
                "builder must always produce idempotency_key = exec:<invocation_id> \
                 so the live handler's validation passes"
            );
        }
    }
}
