//! Local IPC contract and loopback execution for `mx-agent exec` (issue #155).
//!
//! The stateless CLI must not run processes itself: the daemon owns process
//! supervision (and, for the live flow, the Matrix client, signing key, policy,
//! and trust context — see [`crate::exec`]). This module defines the
//! `exec.start` IPC method's parameters and result, plus a **local-loopback**
//! executor that runs the command in-process inside the daemon and returns the
//! captured output as a sequence of [`ExecFrame`]s.
//!
//! Loopback is a stepping stone: it moves `exec` onto the IPC path now — so the
//! CLI no longer links the process runner — before the signed Matrix transport
//! to a *remote* daemon (the rest of #155) is wired in. When the live flow lands
//! it replaces [`start_exec_loopback`] behind the same `exec.start` method, so
//! the CLI does not change again.
//!
//! Today's loopback runs the command to completion and returns every frame in
//! one response, exactly matching the previous CLI behavior (which also ran to
//! completion before rendering). Live partial-output streaming is deferred to
//! the remote path.
//!
//! # Security
//!
//! - This is *not* a new capability and *not* a remote path: it runs the literal
//!   command on the local host exactly as the CLI did before, but now inside the
//!   daemon so the CLI stays stateless.
//! - The command, cwd, and stdin can carry sensitive data and are never logged
//!   here.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use mx_agent_policy::Allowance;
use mx_agent_protocol::events::timeline::EXEC_REQUEST;
use mx_agent_protocol::id::{generate_invocation_id, generate_request_id};
use mx_agent_protocol::schema::{
    ExecAccepted, ExecCancelled, ExecFinished, ExecRejected, StreamArtifact, StreamChunk,
    StreamKind,
};

use crate::artifact::{prepare_artifact, ArtifactConfig};
use crate::exec::{network_for, sandbox_backend};
use crate::exec_subscribers::{ExecSubscriberRegistry, ExecSubscriptionKey, ForwardedExecEvent};
use crate::runner::{run, RunError, RunSpec};
use crate::stream::{
    capture_child_output, OutputCaps, StreamCaptureConfig, DEFAULT_PTY_OUTPUT_CAP_BYTES,
};

/// Default wall-clock timeout applied to a **loopback** batch exec when the
/// resolved policy carries no per-agent runtime cap (issue #307).
///
/// `Policy::execution_allowance()` only carries the workspace execution-level
/// defaults, never the per-agent `max_runtime_ms`, so a loopback command would
/// otherwise run unbounded. This mirrors the remote exec request default
/// (`timeout_ms: 600_000`) so a runaway local command is terminated by the
/// runner's process-group timeout rather than running forever — the timeout is
/// the mitigation for the synchronous loopback path having no live cancel.
pub const DEFAULT_LOOPBACK_EXEC_TIMEOUT_MS: u64 = 600_000;

/// Default wall-clock timeout (ms) for a **remote** exec request when the caller
/// supplies none (issue #314). The receiver still clamps the effective timeout to
/// `min(policy cap, requested)`, so this is only the request's upper bound.
pub const DEFAULT_REMOTE_EXEC_TIMEOUT_MS: u64 = 600_000;

/// Grace period added to the caller's requested timeout when deciding how long
/// the requester waits for a remote result before abandoning (issue #314).
///
/// The receiver's own timeout (≤ the requested value) fires first and emits
/// `exec.finished`, so under normal operation the requester never reaches this
/// deadline; it only bounds a remote that hangs past its own timeout.
pub const REQUESTER_TIMEOUT_GRACE: Duration = Duration::from_secs(30);

/// Parameters for the `exec.start` IPC method.
///
/// `room`, `agent`, and `task` identify the remote target for the live Matrix
/// flow; the local-loopback executor accepts them for forward compatibility but
/// does not use them. `pty` is likewise accepted but ignored by the loopback
/// (interactive PTY exec takes a dedicated path).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecStartParams {
    /// Workspace room to target, if any.
    #[serde(default)]
    pub room: Option<String>,
    /// Target agent name, if any.
    #[serde(default)]
    pub agent: Option<String>,
    /// Command argv: program followed by its arguments.
    pub command: Vec<String>,
    /// Working directory to run the command in.
    #[serde(default)]
    pub cwd: Option<PathBuf>,
    /// Buffered stdin bytes to feed the command, if any. `None` connects stdin
    /// to `/dev/null`; `Some(bytes)` writes the bytes and closes the pipe.
    #[serde(default)]
    pub stdin: Option<Vec<u8>>,
    /// Whether the caller requested live streaming. The loopback always runs to
    /// completion, so this is accepted for forward compatibility.
    #[serde(default)]
    pub stream: bool,
    /// Whether the caller requested an interactive PTY (ignored by loopback).
    #[serde(default)]
    pub pty: bool,
    /// Associated task ID, if any.
    #[serde(default)]
    pub task: Option<String>,
    /// Whether the caller requested strict stream integrity. Rendering happens
    /// in the CLI; carried for forward compatibility.
    #[serde(default)]
    pub strict_stream: bool,
    /// Preset invocation id to run the exec under. `None` mints a fresh id (the
    /// default for direct CLI `exec`); task dispatch sets it so the published
    /// `exec.request`, the resulting `com.mxagent.invocation.v1` state, and the
    /// owning task's recorded `invocation_id` are a single unified id (issue
    /// #239).
    #[serde(default)]
    pub invocation_id: Option<String>,
    /// Caller-supplied environment overrides for the command (issue #314).
    ///
    /// Carried on the signed exec request and layered on the receiver's sanitized
    /// env. Subordinate to the receiver's policy: secret-named variables are still
    /// scrubbed and the `env_allowlist` still applies. Empty by default.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// Caller-requested wall-clock timeout in milliseconds (issue #314).
    ///
    /// `None` uses [`DEFAULT_REMOTE_EXEC_TIMEOUT_MS`]. The receiver clamps the
    /// effective timeout to `min(policy cap, requested)`, so this can only tighten
    /// the bound, never exceed the operator's `max_runtime_ms`.
    #[serde(default)]
    pub timeout_ms: Option<u64>,
}

/// One frame in the forwarded exec output stream.
///
/// Internally tagged by `kind` so the wire form is `{"kind":"chunk",...}` /
/// `{"kind":"artifact",...}` / `{"kind":"finished",...}`. Mirrors the CLI's
/// renderer input so the CLI can convert each frame and render it unchanged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ExecFrame {
    /// A chunk of stdout/stderr output.
    Chunk(StreamChunk),
    /// A reference to a large output stream uploaded as an artifact
    /// (architecture §8.4). In loopback there is no homeserver, so the
    /// `mxc_uri` is empty.
    Artifact(StreamArtifact),
    /// The terminal frame carrying the exit status.
    Finished(ExecFinished),
}

/// Stable, machine-readable kind of an exec invocation failure.
///
/// These distinguish failures to *invoke* the command from a command that ran
/// and exited nonzero (which is a successful [`ExecOutcome::Ok`] with a
/// `Finished` frame). The CLI maps each kind to an exit code per architecture
/// §5.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecErrorKind {
    /// The command program or working directory was not found.
    NotFound,
    /// The argv was empty, so there was no program to run.
    EmptyCommand,
    /// The child process could not be spawned for another reason.
    Spawn,
    /// A live Matrix-backed remote exec failed or was rejected.
    Remote,
    /// The requester gave up waiting for a remote exec result past its deadline
    /// and sent a signed cancel (issue #314). The CLI maps this to exit 129.
    Timeout,
}

/// The outcome of an `exec.start` invocation.
///
/// Internally tagged by `status` so the wire form is `{"status":"ok",...}` /
/// `{"status":"error",...}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ExecOutcome {
    /// The command ran (possibly exiting nonzero); the frames carry its output
    /// and a terminal `Finished` frame with the exit status.
    Ok {
        /// Output frames in order, ending with exactly one `Finished` frame.
        frames: Vec<ExecFrame>,
    },
    /// The command could not be invoked at all.
    Error {
        /// Machine-readable failure kind.
        kind: ExecErrorKind,
        /// Human-readable failure message (no secrets).
        message: String,
    },
}

/// The result of the `exec.start` IPC method.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecStartResult {
    /// Generated invocation identifier (`inv_...`).
    pub invocation_id: String,
    /// Generated request identifier (`req_...`).
    pub request_id: String,
    /// The execution outcome.
    pub outcome: ExecOutcome,
}

/// Parameters for the `exec.stdin` IPC method.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecStdinParams {
    /// Workspace room that owns the live invocation.
    #[serde(default)]
    pub room: Option<String>,
    /// Invocation receiving stdin.
    pub invocation_id: String,
    /// Raw stdin bytes for this frame.
    #[serde(default)]
    pub data: Vec<u8>,
    /// Whether this frame closes stdin.
    #[serde(default)]
    pub eof: bool,
}

/// Parameters for the `exec.cancel` IPC method.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecCancelParams {
    /// Workspace room that owns the live invocation.
    #[serde(default)]
    pub room: Option<String>,
    /// Invocation to cancel.
    pub invocation_id: String,
    /// Human-readable cancellation reason.
    #[serde(default)]
    pub reason: Option<String>,
}

/// Result for fire-and-forget exec control methods (`exec.stdin`, `exec.cancel`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecControlResult {
    /// Invocation the control request addressed.
    pub invocation_id: String,
    /// Whether a live invocation accepted the control request.
    pub accepted: bool,
    /// Non-sensitive status message.
    pub message: String,
}

/// Daemon-to-CLI exec notification payloads for streaming transports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "method", content = "params", rename_all = "snake_case")]
pub enum ExecNotification {
    /// The daemon accepted an exec request.
    ExecAccepted(ExecAccepted),
    /// The daemon rejected an exec request before spawning.
    ExecRejected(ExecRejected),
    /// A stdout/stderr/artifact/finished frame.
    Frame(ExecFrame),
    /// The daemon cancelled an invocation.
    ExecCancelled(ExecCancelled),
}

/// Human-readable explanation returned when a live exec control method
/// (`exec.stdin` / `exec.cancel`) is attempted without a remote `--room` target.
///
/// Loopback batch exec runs to completion in a single IPC request, so there is no
/// concurrent control channel and no live invocation table to address: mid-run
/// stdin and cancel apply only to the remote (`--room`/`--agent`) path. Runaway
/// loopback commands are bounded by the default timeout instead
/// ([`DEFAULT_LOOPBACK_EXEC_TIMEOUT_MS`]); interactive local sessions use
/// `exec --pty` (issue #307).
pub const LOOPBACK_CONTROL_UNSUPPORTED: &str =
    "exec control (stdin/cancel) requires a remote --room/--agent target; \
local loopback exec is synchronous and cannot be controlled mid-run \
(use `exec --pty` for an interactive local session)";

/// Send an `exec.stdin` IPC request over Matrix when `room` is supplied.
///
/// Without `room` this is a usage error — synchronous loopback exec has no live
/// stdin pipe — surfaced as a non-accepted result carrying
/// [`LOOPBACK_CONTROL_UNSUPPORTED`]. The daemon dispatch rejects the no-`--room`
/// case with a JSON-RPC error before reaching here; this guard keeps the helper
/// honest if called directly.
pub async fn send_exec_stdin_matrix(params: &ExecStdinParams) -> ExecControlResult {
    let Some(room_target) = params.room.as_deref() else {
        return ExecControlResult {
            invocation_id: params.invocation_id.clone(),
            accepted: false,
            message: LOOPBACK_CONTROL_UNSUPPORTED.to_string(),
        };
    };
    match send_control_room(room_target).await {
        Ok((room, signing)) => match crate::send_exec_stdin(
            &room,
            signing.signing_key(),
            signing.key_id(),
            &params.invocation_id,
            &params.data,
            params.eof,
        )
        .await
        {
            Ok(_) => ExecControlResult {
                invocation_id: params.invocation_id.clone(),
                accepted: true,
                message: "stdin sent over Matrix".to_string(),
            },
            Err(e) => ExecControlResult {
                invocation_id: params.invocation_id.clone(),
                accepted: false,
                message: e.to_string(),
            },
        },
        Err(message) => ExecControlResult {
            invocation_id: params.invocation_id.clone(),
            accepted: false,
            message,
        },
    }
}

/// Send an `exec.cancel` IPC request over Matrix when `room` is supplied.
///
/// Without `room` this is a usage error — synchronous loopback exec has no live
/// process handle — surfaced as a non-accepted result carrying
/// [`LOOPBACK_CONTROL_UNSUPPORTED`]. The daemon dispatch rejects the no-`--room`
/// case with a JSON-RPC error before reaching here; this guard keeps the helper
/// honest if called directly.
pub async fn send_exec_cancel_matrix(params: &ExecCancelParams) -> ExecControlResult {
    let Some(room_target) = params.room.as_deref() else {
        return ExecControlResult {
            invocation_id: params.invocation_id.clone(),
            accepted: false,
            message: LOOPBACK_CONTROL_UNSUPPORTED.to_string(),
        };
    };
    match send_control_room(room_target).await {
        Ok((room, signing)) => match crate::send_exec_cancel(
            &room,
            signing.signing_key(),
            signing.key_id(),
            &params.invocation_id,
            params.reason.as_deref().unwrap_or("cancelled by operator"),
            rfc3339_after(Duration::ZERO),
            generate_request_id(),
        )
        .await
        {
            Ok(_) => ExecControlResult {
                invocation_id: params.invocation_id.clone(),
                accepted: true,
                message: "cancel sent over Matrix".to_string(),
            },
            Err(e) => ExecControlResult {
                invocation_id: params.invocation_id.clone(),
                accepted: false,
                message: e.to_string(),
            },
        },
        Err(message) => ExecControlResult {
            invocation_id: params.invocation_id.clone(),
            accepted: false,
            message,
        },
    }
}

async fn send_control_room(
    room_target: &str,
) -> Result<(matrix_sdk::Room, crate::signing::DaemonSigningKey), String> {
    use matrix_sdk::config::SyncSettings;

    let paths = crate::SessionPaths::resolve();
    let session = crate::load_session(&paths)
        .map_err(|e| format!("could not read daemon session: {e}"))?
        .ok_or_else(|| "not logged in; run `mx-agent auth login` first".to_string())?;
    let client = crate::matrix::restore_client(&session)
        .await
        .map_err(|e| e.to_string())?;
    client
        .sync_once(SyncSettings::default())
        .await
        .map_err(|e| e.to_string())?;
    let id = crate::workspace::parse_room_or_alias(room_target).map_err(|e| e.to_string())?;
    let room_id = crate::workspace::resolve_room_id(&client, &id)
        .await
        .map_err(|e| e.to_string())?;
    let room = client
        .get_room(&room_id)
        .ok_or_else(|| format!("room not found: {room_target}"))?;
    let signing = crate::load_or_create_signing_key(&paths).map_err(|e| e.to_string())?;
    Ok((room, signing))
}

/// Map a Unix signal number to its name, for reporting signal death.
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

fn error_kind_for(err: &RunError) -> ExecErrorKind {
    match err {
        RunError::EmptyCommand => ExecErrorKind::EmptyCommand,
        RunError::MissingCwd(_) => ExecErrorKind::NotFound,
        RunError::Spawn(io) if io.kind() == std::io::ErrorKind::NotFound => ExecErrorKind::NotFound,
        RunError::Spawn(_) => ExecErrorKind::Spawn,
    }
}

/// Execute an `exec.start` request locally (loopback), without Matrix.
///
/// Mints fresh `invocation_id`/`request_id`, runs the command through the
/// daemon's process runner, and packages the captured output as ordered
/// [`ExecFrame`]s ending in a single `Finished` frame. High-output commands
/// switch to artifact mode (architecture §8.4); the loopback has no homeserver,
/// so the artifact is finalized with an empty `mxc_uri`. A command that runs and
/// exits nonzero still yields [`ExecOutcome::Ok`]; only a failure to *invoke*
/// yields [`ExecOutcome::Error`].
/// Start a live Matrix-backed remote exec and wait for terminal result events.
///
/// This is used behind the same `exec.start` IPC method as loopback when both
/// `room` and `agent` targeting fields are present. The CLI still receives the
/// same [`ExecStartResult`] shape and renders [`ExecFrame`]s normally.
pub async fn start_exec_matrix(
    params: &ExecStartParams,
    subscribers: &ExecSubscriberRegistry,
) -> ExecStartResult {
    let invocation_id = params
        .invocation_id
        .clone()
        .unwrap_or_else(generate_invocation_id);
    let request_id = generate_request_id();
    let outcome =
        match start_exec_matrix_inner(params, subscribers, &invocation_id, &request_id).await {
            Ok(outcome) => outcome,
            Err(message) => ExecOutcome::Error {
                kind: ExecErrorKind::Remote,
                message,
            },
        };
    ExecStartResult {
        invocation_id,
        request_id,
        outcome,
    }
}

async fn start_exec_matrix_inner(
    params: &ExecStartParams,
    subscribers: &ExecSubscriberRegistry,
    invocation_id: &str,
    request_id: &str,
) -> Result<ExecOutcome, String> {
    use matrix_sdk::config::SyncSettings;

    let Some(room_target) = params.room.as_deref() else {
        return Err("remote exec requires --room".to_string());
    };
    let Some(target_agent) = params.agent.clone() else {
        return Err("remote exec requires --agent".to_string());
    };
    let paths = crate::SessionPaths::resolve();
    let session = crate::load_session(&paths)
        .map_err(|e| format!("could not read daemon session: {e}"))?
        .ok_or_else(|| "not logged in; run `mx-agent auth login` first".to_string())?;
    let client = crate::matrix::restore_client(&session)
        .await
        .map_err(|e| e.to_string())?;
    client
        .sync_once(SyncSettings::default())
        .await
        .map_err(|e| e.to_string())?;
    let id = crate::workspace::parse_room_or_alias(room_target).map_err(|e| e.to_string())?;
    let room_id = crate::workspace::resolve_room_id(&client, &id)
        .await
        .map_err(|e| e.to_string())?;
    let room = client
        .get_room(&room_id)
        .ok_or_else(|| format!("room not found: {room_target}"))?;

    let local_user = client.user_id().map(|u| u.to_string()).unwrap_or_default();
    let requester = crate::agent::read_all_agent_states(&room)
        .await
        .map_err(|e| e.to_string())?
        .into_iter()
        .filter(|agent| agent.matrix_user_id == local_user)
        .min_by(|a, b| a.agent_id.cmp(&b.agent_id))
        .ok_or_else(|| "local agent is not registered in the target room".to_string())?;

    // Resolve the executing agent's Matrix user id so the result subscription is
    // pinned to it: only stream/result events the target actually sends are
    // delivered, dropping anything forged by another room member (issue #304).
    // Fail closed when the target agent is not registered in the room.
    let expected_sender = crate::agent::read_agent_state(&room, &target_agent)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("target agent {target_agent:?} is not registered in the room"))?
        .matrix_user_id;

    let signing = crate::load_or_create_signing_key(&paths).map_err(|e| e.to_string())?;
    let created_at = rfc3339_after(Duration::ZERO);
    let expires_at = rfc3339_after(Duration::from_secs(300));
    let cwd = params
        .cwd
        .as_ref()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    let requested_timeout_ms = params.timeout_ms.unwrap_or(DEFAULT_REMOTE_EXEC_TIMEOUT_MS);
    let options = crate::ExecRequestOptions {
        target_agent,
        requesting_agent: requester.agent_id,
        command: params.command.clone(),
        cwd,
        env: params.env.clone(),
        stdin: params.stdin.is_some(),
        stream: params.stream,
        pty: params.pty,
        timeout_ms: requested_timeout_ms,
        task_id: params.task.clone(),
    };
    let content = crate::build_signed_exec_request(
        signing.signing_key(),
        signing.key_id(),
        invocation_id,
        request_id,
        generate_request_id(),
        created_at,
        expires_at,
        &options,
    )
    .map_err(|e| e.to_string())?;

    let mut subscription = subscribers.subscribe(
        ExecSubscriptionKey::Invocation(invocation_id.to_string()),
        expected_sender,
    );
    room.send_raw(EXEC_REQUEST, content)
        .await
        .map_err(|e| e.to_string())?;
    if let Some(stdin) = &params.stdin {
        crate::send_exec_stdin(
            &room,
            signing.signing_key(),
            signing.key_id(),
            invocation_id,
            stdin,
            true,
        )
        .await
        .map_err(|e| e.to_string())?;
    }

    let mut frames = Vec::new();
    // Wait long enough to cover the timeout the remote was actually told to honor,
    // plus a grace window, instead of a fixed 120 s that could abandon a healthy
    // long run (issue #314). The receiver's own timeout (≤ requested) fires first
    // and emits `exec.finished`, so this deadline only bounds a remote that hangs.
    let deadline = tokio::time::Instant::now()
        + Duration::from_millis(requested_timeout_ms)
        + REQUESTER_TIMEOUT_GRACE;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            // Abandon the run, but first tell the remote to stop: send a signed
            // `exec.cancel` (verified on receipt) so a runaway is not left running
            // unsupervised. Map the requester-side timeout to a distinct kind the
            // CLI renders as exit 129 (issue #314).
            let _ = crate::send_exec_cancel(
                &room,
                signing.signing_key(),
                signing.key_id(),
                invocation_id,
                "requester timed out waiting for result",
                rfc3339_after(Duration::ZERO),
                generate_request_id(),
            )
            .await;
            return Ok(ExecOutcome::Error {
                kind: ExecErrorKind::Timeout,
                message: "timed out waiting for remote exec result; sent cancel".to_string(),
            });
        }
        // Cap each receive at a short poll window so the deadline is re-checked,
        // but a window expiring with no event just loops — it does not abandon.
        let event =
            match tokio::time::timeout(remaining.min(Duration::from_secs(5)), subscription.recv())
                .await
            {
                Ok(Some(event)) => event,
                Ok(None) => return Err("remote exec subscriber closed".to_string()),
                Err(_elapsed) => continue,
            };
        match event {
            ForwardedExecEvent::StreamChunk(chunk) => frames.push(ExecFrame::Chunk(chunk)),
            ForwardedExecEvent::StreamArtifact(artifact) => {
                frames.push(ExecFrame::Artifact(artifact))
            }
            ForwardedExecEvent::ExecFinished(finished) => {
                frames.push(ExecFrame::Finished(finished));
                return Ok(ExecOutcome::Ok { frames });
            }
            ForwardedExecEvent::ExecRejected(rejected) => {
                return Ok(ExecOutcome::Error {
                    kind: ExecErrorKind::Remote,
                    message: rejected.reason,
                });
            }
            ForwardedExecEvent::ExecCancelled(cancelled) => {
                return Ok(ExecOutcome::Error {
                    kind: ExecErrorKind::Remote,
                    message: format!("remote exec cancelled ({})", cancelled.signal_sent),
                });
            }
            ForwardedExecEvent::CallResponse(_) => {}
        }
    }
}

/// Format an RFC 3339 UTC timestamp `offset` after the current wall-clock time.
///
/// Shared by the exec and call request builders to stamp `created_at` /
/// `expires_at` consistently.
pub(crate) fn rfc3339_after(offset: Duration) -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .saturating_add(offset)
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

/// Resolve the operator's execution-level confinement floor for a loopback exec,
/// exactly as [`crate::call_ipc`]'s live `call` path does: load the policy if one
/// exists and fall back to the safe defaults otherwise.
///
/// The returned [`Allowance`] carries the workspace `sandbox` / `network` /
/// `env_allowlist` / read-only / writable binds; the per-agent `max_runtime_ms` /
/// `max_output_bytes` stay `None` (loopback has no remote requester to evaluate),
/// so [`loopback_run_spec`] supplies a default timeout and the cap defaults to
/// [`DEFAULT_PTY_OUTPUT_CAP_BYTES`].
///
/// Shared with the loopback PTY path ([`crate::pty_ipc`]) so both loopback exec
/// entry points apply the identical confinement floor.
pub(crate) fn loopback_execution_allowance() -> Allowance {
    crate::policy::resolve_policy_for_enforcement("exec_ipc.floor").execution_allowance()
}

/// Build the confined [`RunSpec`] for a loopback batch exec from `params` and the
/// resolved confinement floor `allowance` (issue #307).
///
/// Maps `sandbox` / `network` / `env_allowlist` / read-only / writable binds onto
/// the spec exactly as the live exec path does ([`crate::exec`]'s
/// `run_controlled_exec`), and applies a default wall-clock timeout
/// ([`DEFAULT_LOOPBACK_EXEC_TIMEOUT_MS`]) when the allowance sets no per-agent
/// runtime cap. Kept pure so the allowance-wiring is unit-testable without
/// spawning, mirroring `call_ipc::run_loopback_with`.
fn loopback_run_spec(params: &ExecStartParams, allowance: &Allowance) -> RunSpec {
    let cwd = match &params.cwd {
        Some(cwd) => cwd.clone(),
        None => PathBuf::new(),
    };
    let backend = sandbox_backend(allowance.sandbox);
    let (run_uid, run_gid) = crate::exec::container_run_identity(backend);
    RunSpec {
        command: params.command.clone(),
        cwd,
        stdin: params.stdin.clone(),
        // Honor the caller's `--env` overrides on the loopback path too, layered
        // on the sanitized env (secrets still scrubbed) so `exec --env K=V` is
        // consistent local and remote (issue #314).
        env: params.env.clone(),
        env_allowlist: allowance.env_allowlist.clone(),
        // Caller `--timeout` wins, then a policy runtime cap, then the default.
        timeout: Some(Duration::from_millis(
            params
                .timeout_ms
                .or(allowance.max_runtime_ms)
                .unwrap_or(DEFAULT_LOOPBACK_EXEC_TIMEOUT_MS),
        )),
        sandbox: backend,
        network: network_for(allowance.network),
        read_only_paths: allowance.read_only_paths.clone(),
        writable_paths: allowance.writable_paths.clone(),
        container_runtime: crate::exec::container_runtime_for(allowance.sandbox),
        container_image: allowance.container_image.clone(),
        // Confinement floor (issue #349): resource caps + seccomp + the container
        // uid mapping apply to the loopback path too.
        resources: crate::exec::resource_limits_for(allowance),
        seccomp: crate::exec::seccomp_for(allowance.seccomp),
        run_uid,
        run_gid,
        ..Default::default()
    }
}

/// Execute an `exec.start` request locally (loopback), without Matrix.
///
/// Mints fresh `invocation_id`/`request_id`, runs the command through the
/// daemon's process runner under the operator's execution-level confinement floor
/// ([`Policy::execution_allowance`], resolved like loopback `call`), and packages
/// the captured output as ordered [`ExecFrame`]s ending in a single `Finished`
/// frame carrying the real `duration_ms` and the truthful `truncated` flag.
pub async fn start_exec_loopback(params: &ExecStartParams) -> ExecStartResult {
    let invocation_id = params
        .invocation_id
        .clone()
        .unwrap_or_else(generate_invocation_id);
    let request_id = generate_request_id();
    let allowance = loopback_execution_allowance();
    let outcome = run_loopback_with(&invocation_id, params, &allowance).await;
    ExecStartResult {
        invocation_id,
        request_id,
        outcome,
    }
}

/// Core loopback executor with the confinement floor `allowance` injected.
///
/// Separated from [`start_exec_loopback`] so the output-cap/truncation behavior
/// can be driven in tests with a small `max_output_bytes` without a policy file,
/// mirroring `call_ipc::run_loopback_with`.
async fn run_loopback_with(
    invocation_id: &str,
    params: &ExecStartParams,
    allowance: &Allowance,
) -> ExecOutcome {
    // Sandbox floor (issue #349): the loopback path honors
    // `execution.require_sandbox` too — deny fail-closed when the resolved
    // backend is `none`, otherwise the shared gate warns it runs unsandboxed.
    if crate::exec::check_sandbox_floor(
        allowance,
        &crate::exec::SandboxFloorContext::local("loopback exec", Some(invocation_id)),
    )
    .is_err()
    {
        return ExecOutcome::Error {
            kind: ExecErrorKind::Spawn,
            message: "refusing to run unsandboxed: execution.require_sandbox is set but the \
                      resolved sandbox backend is none"
                .to_string(),
        };
    }
    let spec = loopback_run_spec(params, allowance);
    let started = Instant::now();
    let output = match run(&spec).await {
        Ok(output) => output,
        Err(err) => {
            return ExecOutcome::Error {
                kind: error_kind_for(&err),
                message: err.to_string(),
            };
        }
    };
    let duration_ms = started.elapsed().as_millis() as u64;

    let artifact_config = ArtifactConfig::default();
    let total_output = output.stdout.len() + output.stderr.len();
    // Cap the inline-chunk path at the policy's per-invocation byte budget,
    // falling back to the same generous 64 MiB cap as the loopback PTY when the
    // floor allowance sets none (issue #307). The artifact path preserves the
    // full log, so it is never truncated.
    let output_cap = allowance
        .max_output_bytes
        .unwrap_or(DEFAULT_PTY_OUTPUT_CAP_BYTES);

    let mut frames = Vec::new();
    let (truncated, artifact_mxc) = if artifact_config.should_switch(total_output) {
        // High-output commands package the full log as an artifact and show a
        // tail preview rather than streaming every byte (architecture §8.4).
        let mut artifact_mxc = None;
        for (stream, data) in [
            (StreamKind::Stdout, &output.stdout),
            (StreamKind::Stderr, &output.stderr),
        ] {
            if data.is_empty() {
                continue;
            }
            let prepared = prepare_artifact(invocation_id, stream, data, &artifact_config).await;
            let event = prepared.into_event(String::new());
            if stream == StreamKind::Stdout {
                artifact_mxc = Some(event.mxc_uri.clone());
            }
            frames.push(ExecFrame::Artifact(event));
        }
        // The full log is preserved in the artifact, so nothing was truncated.
        (false, artifact_mxc)
    } else {
        let (tx, mut rx) = tokio::sync::mpsc::channel(256);
        let stdout_bytes = output.stdout.clone();
        let stderr_bytes = output.stderr.clone();
        let invocation = invocation_id.to_string();
        // Capture concurrently so a full channel never deadlocks the drain.
        let config = StreamCaptureConfig::batch().with_caps(OutputCaps {
            max_output_bytes: Some(output_cap),
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
            frames.push(ExecFrame::Chunk(chunk));
        }
        let summary = capture.await.unwrap_or_default();
        (summary.truncated, None)
    };

    frames.push(ExecFrame::Finished(ExecFinished {
        invocation_id: invocation_id.to_string(),
        exit_code: output.exit_code,
        signal: output.signal.and_then(signal_name),
        duration_ms,
        stdout_bytes: output.stdout.len() as u64,
        stderr_bytes: output.stderr.len() as u64,
        truncated,
        artifact_mxc,
        signature: None,
        extra: Default::default(),
    }));

    ExecOutcome::Ok { frames }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mx_agent_policy::Policy;
    use mx_agent_protocol::id::{validate, IdKind};

    fn params(command: &[&str]) -> ExecStartParams {
        ExecStartParams {
            room: Some("!room:server".to_string()),
            agent: Some("developer-pi".to_string()),
            command: command.iter().map(|s| s.to_string()).collect(),
            cwd: Some(std::env::temp_dir()),
            stdin: None,
            stream: true,
            pty: false,
            task: None,
            strict_stream: false,
            invocation_id: None,
            env: BTreeMap::new(),
            timeout_ms: None,
        }
    }

    fn finished(outcome: &ExecOutcome) -> &ExecFinished {
        match outcome {
            ExecOutcome::Ok { frames } => match frames.last() {
                Some(ExecFrame::Finished(f)) => f,
                other => panic!("expected trailing Finished frame, got {other:?}"),
            },
            other => panic!("expected Ok outcome, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn loopback_mints_well_formed_ids() {
        let result = start_exec_loopback(&params(&["true"])).await;
        assert!(validate(IdKind::Invocation, &result.invocation_id).is_ok());
        assert!(validate(IdKind::Request, &result.request_id).is_ok());
    }

    #[tokio::test]
    async fn loopback_honors_preset_invocation_id() {
        // Task dispatch presets the orchestrator's invocation id so the exec runs
        // under the unified id; absence still mints a fresh one (issue #239).
        let mut p = params(&["true"]);
        p.invocation_id = Some("inv_preset".to_string());
        let result = start_exec_loopback(&p).await;
        assert_eq!(result.invocation_id, "inv_preset");
    }

    #[tokio::test]
    async fn successful_command_finishes_zero() {
        let result = start_exec_loopback(&params(&["true"])).await;
        let f = finished(&result.outcome);
        assert_eq!(f.exit_code, Some(0));
        assert_eq!(f.invocation_id, result.invocation_id);
    }

    #[tokio::test]
    async fn nonzero_exit_is_ok_outcome() {
        let result = start_exec_loopback(&params(&["false"])).await;
        let f = finished(&result.outcome);
        assert_eq!(f.exit_code, Some(1));
    }

    #[tokio::test]
    async fn stdout_is_captured_as_chunks() {
        let result = start_exec_loopback(&params(&["echo", "hello"])).await;
        match &result.outcome {
            ExecOutcome::Ok { frames } => {
                let has_stdout = frames.iter().any(|frame| match frame {
                    ExecFrame::Chunk(chunk) => {
                        chunk.stream == StreamKind::Stdout && chunk.data.contains("hello")
                    }
                    _ => false,
                });
                assert!(has_stdout, "expected a stdout chunk containing 'hello'");
            }
            other => panic!("expected Ok, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn stdin_is_forwarded_to_command() {
        let mut p = params(&["cat"]);
        p.stdin = Some(b"piped-input".to_vec());
        let result = start_exec_loopback(&p).await;
        match &result.outcome {
            ExecOutcome::Ok { frames } => {
                let echoed = frames.iter().any(|frame| match frame {
                    ExecFrame::Chunk(chunk) => chunk.data.contains("piped-input"),
                    _ => false,
                });
                assert!(echoed, "cat should echo forwarded stdin");
            }
            other => panic!("expected Ok, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn missing_cwd_maps_to_not_found() {
        let mut p = params(&["true"]);
        p.cwd = Some(PathBuf::from("/this/path/does/not/exist/mx-agent"));
        let result = start_exec_loopback(&p).await;
        match result.outcome {
            ExecOutcome::Error { kind, .. } => assert_eq!(kind, ExecErrorKind::NotFound),
            other => panic!("expected error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn unknown_command_maps_to_not_found() {
        let result = start_exec_loopback(&params(&["definitely-not-a-real-binary-xyz"])).await;
        match result.outcome {
            ExecOutcome::Error { kind, .. } => assert_eq!(kind, ExecErrorKind::NotFound),
            other => panic!("expected error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn empty_command_maps_to_empty_command() {
        let result = start_exec_loopback(&params(&[])).await;
        match result.outcome {
            ExecOutcome::Error { kind, .. } => assert_eq!(kind, ExecErrorKind::EmptyCommand),
            other => panic!("expected error, got {other:?}"),
        }
    }

    #[test]
    fn outcome_serializes_with_status_tag() {
        let err = ExecOutcome::Error {
            kind: ExecErrorKind::NotFound,
            message: "nope".to_string(),
        };
        let value = serde_json::to_value(&err).unwrap();
        assert_eq!(value["status"], "error");
        assert_eq!(value["kind"], "not_found");
    }

    #[test]
    fn timeout_error_kind_serializes() {
        // Issue #314: the requester-side timeout kind the CLI maps to exit 129.
        let err = ExecOutcome::Error {
            kind: ExecErrorKind::Timeout,
            message: "timed out".to_string(),
        };
        let value = serde_json::to_value(&err).unwrap();
        assert_eq!(value["kind"], "timeout");
    }

    #[test]
    fn params_round_trip_with_env_and_timeout() {
        // Issue #314: env/timeout_ms ride ExecStartParams (and default when absent).
        let mut p = params(&["true"]);
        p.env = BTreeMap::from([("FOO".to_string(), "bar".to_string())]);
        p.timeout_ms = Some(45_000);
        let json = serde_json::to_value(&p).unwrap();
        let back: ExecStartParams = serde_json::from_value(json).unwrap();
        assert_eq!(back.env.get("FOO").map(String::as_str), Some("bar"));
        assert_eq!(back.timeout_ms, Some(45_000));

        // Absent fields default (older CLIs / wire forms still parse).
        let minimal: ExecStartParams =
            serde_json::from_value(serde_json::json!({ "command": ["true"] })).unwrap();
        assert!(minimal.env.is_empty());
        assert_eq!(minimal.timeout_ms, None);
    }

    #[test]
    fn frame_serializes_with_kind_tag() {
        let frame = ExecFrame::Finished(ExecFinished {
            invocation_id: "inv_x".to_string(),
            exit_code: Some(0),
            signal: None,
            duration_ms: 0,
            stdout_bytes: 0,
            stderr_bytes: 0,
            truncated: false,
            artifact_mxc: None,
            signature: None,
            extra: Default::default(),
        });
        let value = serde_json::to_value(&frame).unwrap();
        assert_eq!(value["kind"], "finished");
        assert_eq!(value["exit_code"], 0);
    }

    #[tokio::test]
    async fn loopback_control_without_room_is_unsupported() {
        // The Matrix-send helpers guard the no-`--room` case (the dispatch
        // rejects it earlier): a missing room is a usage error, never a live
        // accept (issue #307).
        let stdin = send_exec_stdin_matrix(&ExecStdinParams {
            room: None,
            invocation_id: "inv_1".to_string(),
            data: b"hello".to_vec(),
            eof: true,
        })
        .await;
        assert_eq!(stdin.invocation_id, "inv_1");
        assert!(!stdin.accepted);
        assert_eq!(stdin.message, LOOPBACK_CONTROL_UNSUPPORTED);

        let cancel = send_exec_cancel_matrix(&ExecCancelParams {
            room: None,
            invocation_id: "inv_1".to_string(),
            reason: Some("test".to_string()),
        })
        .await;
        assert_eq!(cancel.invocation_id, "inv_1");
        assert!(!cancel.accepted);
        assert_eq!(cancel.message, LOOPBACK_CONTROL_UNSUPPORTED);
    }

    // --- confinement floor wiring (issue #307) --------------------------------
    //
    // Loopback exec must carry the operator's execution-level confinement floor
    // (sandbox/network/binds/env_allowlist) resolved from
    // Policy::execution_allowance, plus a default timeout and output cap — parity
    // with loopback `call`. These assert the pure loopback_run_spec mapping and
    // the output-cap truncation without depending on a policy file.

    #[test]
    fn loopback_run_spec_carries_allowance_confinement_fields() {
        let policy = Policy::parse(
            r#"
[execution]
default_sandbox = "bubblewrap"
env_allowlist = ["CARGO_HOME"]
network = "deny"
read_only_paths = ["/usr"]
writable_paths = ["/work"]
"#,
        )
        .expect("policy parses");
        let allowance = policy.execution_allowance();
        let spec = loopback_run_spec(&params(&["echo", "hi"]), &allowance);

        assert_eq!(spec.sandbox, mx_agent_sandbox::Backend::Bubblewrap);
        assert_eq!(spec.network, mx_agent_sandbox::Network::Deny);
        assert_eq!(spec.env_allowlist, vec!["CARGO_HOME".to_string()]);
        assert_eq!(spec.read_only_paths, vec![PathBuf::from("/usr")]);
        assert_eq!(spec.writable_paths, vec![PathBuf::from("/work")]);
    }

    #[test]
    fn loopback_run_spec_default_policy_is_fail_closed() {
        // No policy file → Policy::default().execution_allowance(): no sandbox
        // override, network denied (Backend::None ignores it but the spec still
        // records the fail-closed decision), empty env allowlist so daemon
        // secrets stay stripped, and the default timeout bounds the run.
        let allowance = Policy::default().execution_allowance();
        let spec = loopback_run_spec(&params(&["true"]), &allowance);

        assert_eq!(spec.sandbox, mx_agent_sandbox::Backend::None);
        assert_eq!(spec.network, mx_agent_sandbox::Network::Deny);
        assert!(spec.env_allowlist.is_empty());
        assert!(spec.read_only_paths.is_empty());
        assert!(spec.writable_paths.is_empty());
        assert_eq!(
            spec.timeout,
            Some(Duration::from_millis(DEFAULT_LOOPBACK_EXEC_TIMEOUT_MS))
        );
    }

    #[test]
    fn loopback_run_spec_honors_caller_env_and_timeout() {
        // Issue #314: `exec --env K=V --timeout` is consistent on the loopback
        // path too — caller env overrides reach the spec and the caller timeout
        // wins over the default.
        let mut p = params(&["true"]);
        p.env = BTreeMap::from([("FOO".to_string(), "bar".to_string())]);
        p.timeout_ms = Some(12_000);
        let spec = loopback_run_spec(&p, &Allowance::default());
        assert_eq!(spec.env.get("FOO").map(String::as_str), Some("bar"));
        assert_eq!(spec.timeout, Some(Duration::from_millis(12_000)));
    }

    #[test]
    fn loopback_run_spec_honors_policy_runtime_cap_over_default() {
        // When the allowance carries a per-agent runtime cap, the loopback spec
        // uses it instead of the default (the mapping reads the allowance so it
        // stays correct if execution_allowance ever surfaces max_runtime_ms).
        let allowance = Allowance {
            max_runtime_ms: Some(5_000),
            ..Allowance::default()
        };
        let spec = loopback_run_spec(&params(&["true"]), &allowance);
        assert_eq!(spec.timeout, Some(Duration::from_millis(5_000)));
    }

    #[tokio::test]
    async fn loopback_output_cap_reports_truncated() {
        // With a small output cap and output that fits the inline-chunk path
        // (under the 256 KiB artifact threshold) but exceeds the cap, the
        // Finished frame must report truncated: true (issue #268 parity).
        let allowance = Allowance {
            max_output_bytes: Some(64),
            ..Allowance::default()
        };
        // Print ~2 KiB: well under the artifact threshold, well over the cap.
        let p = params(&["sh", "-c", "head -c 2048 /dev/zero | tr '\\0' a"]);
        let outcome = run_loopback_with("inv_cap", &p, &allowance).await;
        let f = finished(&outcome);
        assert!(
            f.truncated,
            "output beyond the cap must be marked truncated"
        );
    }

    #[tokio::test]
    async fn loopback_denied_when_sandbox_required_but_none() {
        // Sandbox floor (issue #349): require_sandbox + a resolved `none` backend
        // must fail closed on the loopback path rather than run unsandboxed. The
        // command (`false`, which would exit 1) must never run — the outcome is an
        // Error, not a Finished frame.
        let allowance = Allowance {
            require_sandbox: true,
            sandbox: None, // resolves to Backend::None
            ..Allowance::default()
        };
        let outcome = run_loopback_with("inv_floor", &params(&["false"]), &allowance).await;
        match outcome {
            ExecOutcome::Error { kind, message } => {
                assert_eq!(kind, ExecErrorKind::Spawn);
                assert!(
                    message.contains("require_sandbox"),
                    "denial message must name the control, got {message:?}"
                );
            }
            other => panic!("expected a fail-closed Error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn loopback_reports_real_duration() {
        // A ~50 ms sleep must surface a real, nonzero duration — not the
        // hardcoded 0 the loopback used to report (issue #307).
        let p = params(&["sh", "-c", "sleep 0.05"]);
        let result = start_exec_loopback(&p).await;
        let f = finished(&result.outcome);
        assert!(
            f.duration_ms >= 40,
            "expected a real duration around 50ms, got {}",
            f.duration_ms
        );
    }

    #[test]
    fn notification_serializes_with_method_tag() {
        let notification = ExecNotification::Frame(ExecFrame::Finished(ExecFinished {
            invocation_id: "inv_1".to_string(),
            exit_code: Some(0),
            signal: None,
            duration_ms: 1,
            stdout_bytes: 0,
            stderr_bytes: 0,
            truncated: false,
            artifact_mxc: None,
            signature: None,
            extra: Default::default(),
        }));
        let value = serde_json::to_value(notification).unwrap();
        assert_eq!(value["method"], "frame");
        assert_eq!(value["params"]["kind"], "finished");
    }

    #[test]
    fn result_round_trips() {
        let result = ExecStartResult {
            invocation_id: "inv_x".to_string(),
            request_id: "req_x".to_string(),
            outcome: ExecOutcome::Ok {
                frames: vec![ExecFrame::Finished(ExecFinished {
                    invocation_id: "inv_x".to_string(),
                    exit_code: Some(2),
                    signal: None,
                    duration_ms: 0,
                    stdout_bytes: 0,
                    stderr_bytes: 0,
                    truncated: false,
                    artifact_mxc: None,
                    signature: None,
                    extra: Default::default(),
                })],
            },
        };
        let json = serde_json::to_value(&result).unwrap();
        let back: ExecStartResult = serde_json::from_value(json).unwrap();
        assert_eq!(back, result);
    }
}
