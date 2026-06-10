//! Approval request queue (architecture §12).
//!
//! When local policy marks a privileged request with `requires_approval`, the
//! target daemon must **not** execute it immediately. Instead it builds a
//! `com.mxagent.approval.request.v1` event, emits it into the room so a human
//! (or supervising agent) can decide, and records the request in a local queue
//! so the pending decision survives a daemon restart and is visible to the
//! operator via `mx-agent approval list`.
//!
//! This module owns three concerns, each independently testable:
//!
//! - [`disposition_for_exec`] honours the policy flag: it turns an authorized
//!   [`ExecRequest`] plus its resolved [`Allowance`] into an [`ExecDisposition`]
//!   that either permits immediate execution or demands approval first.
//! - [`approval_request_for`] is the pure builder that derives the
//!   [`ApprovalRequest`] content (summary, risk, expiry) from a request.
//! - [`ApprovalQueue`] is the local, on-disk queue of pending approvals,
//!   persisted as JSON in the daemon's private data directory with `0600`
//!   permissions (mirroring [`crate::trust::TrustStore`]).
//!
//! Emitting the request event into a room is [`emit_approval_request`]. The
//! receive-side wiring that calls these pieces together lands with the live
//! exec dispatch loop; this module provides the building blocks and enforces
//! the "does not execute immediately" guarantee.

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ed25519_dalek::VerifyingKey;
use matrix_sdk::config::SyncSettings;
use matrix_sdk::room::MessagesOptions;
use matrix_sdk::{Client, Room};
use mx_agent_policy::{Allowance, NetworkPolicy, Sandbox};
use mx_agent_protocol::events::timeline::{APPROVAL_DECISION, APPROVAL_REQUEST};
use mx_agent_protocol::id::generate_request_id;
use mx_agent_protocol::schema::{ApprovalDecision, ApprovalRequest, ExecRequest};
use mx_agent_protocol::signing::{sign_approval_decision, verify_approval_decision};
use serde::{Deserialize, Serialize};

use crate::matrix::restore_client;
use crate::session::{SessionPaths, StoredSession};
use crate::signing::load_or_create_signing_key;
use crate::workspace::{parse_room_or_alias, resolve_room_id, WorkspaceError};

/// Whether an authorized request may run immediately or must wait for approval.
///
/// Produced by [`disposition_for_exec`] from a request and its resolved
/// [`Allowance`]. A [`ExecDisposition::RequiresApproval`] carries the
/// [`ApprovalRequest`] the caller should queue and emit; the wrapped request is
/// **not** to be executed until an approval decision arrives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecDisposition {
    /// The request is authorized and may be executed immediately.
    Execute(ExecRequest),
    /// The request requires approval before running. The caller must queue and
    /// emit the bundled [`ApprovalRequest`] and hold the request until a
    /// decision arrives.
    RequiresApproval {
        /// The request that is being held pending approval.
        request: ExecRequest,
        /// The approval request to queue locally and emit into the room.
        approval: ApprovalRequest,
    },
}

impl ExecDisposition {
    /// Whether this disposition holds the request pending approval.
    pub fn requires_approval(&self) -> bool {
        matches!(self, ExecDisposition::RequiresApproval { .. })
    }

    /// The request that may run now, or `None` when approval is required.
    pub fn executable(&self) -> Option<&ExecRequest> {
        match self {
            ExecDisposition::Execute(request) => Some(request),
            ExecDisposition::RequiresApproval { .. } => None,
        }
    }
}

/// Decide whether an authorized exec request may run now or must be queued for
/// approval, honouring the policy's `requires_approval` flag.
///
/// `allowance` is the resolved [`Allowance`] the policy engine returned for the
/// request (see [`crate::exec::authorize_exec_request_with_allowance`]). When it
/// sets `requires_approval`, the request is wrapped in
/// [`ExecDisposition::RequiresApproval`] alongside the [`ApprovalRequest`] to
/// emit; otherwise it is returned as [`ExecDisposition::Execute`].
pub fn disposition_for_exec(request: ExecRequest, allowance: &Allowance) -> ExecDisposition {
    if allowance.requires_approval {
        let approval = approval_request_for(&request, allowance);
        ExecDisposition::RequiresApproval { request, approval }
    } else {
        ExecDisposition::Execute(request)
    }
}

/// Build the `com.mxagent.approval.request.v1` content for an exec request.
///
/// Pure and deterministic: the identifiers, parties, and expiry are copied from
/// the authorized request, the summary is a human-readable rendering of the
/// command and working directory, and the risk level is derived from how
/// isolated the resolved [`Allowance`] is (see [`risk_for`]).
pub fn approval_request_for(request: &ExecRequest, allowance: &Allowance) -> ApprovalRequest {
    ApprovalRequest {
        request_id: request.request_id.clone(),
        invocation_id: request.invocation_id.clone(),
        requester: request.requesting_agent.clone(),
        target: request.target_agent.clone(),
        summary: summary_for(request),
        risk: risk_for(allowance).to_string(),
        expires_at: request.expires_at.clone(),
        extra: Default::default(),
    }
}

/// Render a one-line, human-readable summary of what an exec request would run.
fn summary_for(request: &ExecRequest) -> String {
    format!("Run {} in {}", request.command.join(" "), request.cwd)
}

/// Classify the risk of permitting an exec request, from its resolved limits.
///
/// A request that is granted network access or runs without a real sandbox is
/// the highest-privilege case (`"high"`); an isolated, network-denied request
/// is `"medium"`. Approval is always interactive, so this is advisory context
/// for the human deciding, not an authorization input.
fn risk_for(allowance: &Allowance) -> &'static str {
    let networked = matches!(allowance.network, Some(NetworkPolicy::Allow));
    let unsandboxed = matches!(allowance.sandbox, None | Some(Sandbox::None));
    if networked || unsandboxed {
        "high"
    } else {
        "medium"
    }
}

/// Emit a `com.mxagent.approval.request.v1` timeline event into `room`.
///
/// Emitting the request never executes the underlying command; it only asks for
/// a decision.
pub async fn emit_approval_request(
    room: &Room,
    request: &ApprovalRequest,
) -> Result<(), WorkspaceError> {
    let content = serde_json::to_value(request)
        .map_err(|e| WorkspaceError::from(matrix_sdk::Error::SerdeJson(e)))?;
    room.send_raw(APPROVAL_REQUEST, content)
        .await
        .map_err(WorkspaceError::from)?;
    Ok(())
}

/// A pending approval recorded in the local queue.
///
/// Wraps the [`ApprovalRequest`] content with the room it belongs to, so the
/// queue can be filtered per workspace and the request re-emitted if needed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingApproval {
    /// Matrix room ID the request was raised in.
    pub room_id: String,
    /// The approval request content awaiting a decision.
    pub request: ApprovalRequest,
}

impl PendingApproval {
    /// The request identifier this pending approval is keyed by.
    pub fn request_id(&self) -> &str {
        &self.request.request_id
    }
}

/// The local, on-disk queue of approval requests awaiting a decision.
///
/// Load with [`ApprovalQueue::load`], mutate with [`ApprovalQueue::enqueue`] /
/// [`ApprovalQueue::remove`], then persist with [`ApprovalQueue::save`]. The
/// queue is keyed by `request_id`: enqueuing a request that is already present
/// replaces it in place rather than duplicating it, so a redelivered request
/// event does not pile up.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalQueue {
    /// Pending approvals, one per `request_id`, in arrival order.
    #[serde(default)]
    pending: Vec<PendingApproval>,
}

/// The path to the persisted approval queue file.
fn approval_queue_file(paths: &SessionPaths) -> PathBuf {
    paths.data_dir.join("approvals.json")
}

impl ApprovalQueue {
    /// Load the queue from disk, returning an empty queue on first run.
    pub fn load(paths: &SessionPaths) -> io::Result<Self> {
        match fs::read(approval_queue_file(paths)) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e),
        }
    }

    /// Persist the queue atomically with `0600` permissions.
    pub fn save(&self, paths: &SessionPaths) -> io::Result<()> {
        paths.ensure_data_dir()?;
        let bytes = serde_json::to_vec_pretty(self)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let file = approval_queue_file(paths);
        let tmp = file.with_extension("json.tmp");
        {
            let mut f = fs::File::create(&tmp)?;
            f.set_permissions(fs::Permissions::from_mode(0o600))?;
            f.write_all(&bytes)?;
            f.flush()?;
        }
        fs::rename(&tmp, &file)?;
        Ok(())
    }

    /// All pending approvals, in arrival order.
    pub fn pending(&self) -> &[PendingApproval] {
        &self.pending
    }

    /// Pending approvals raised in a specific room.
    pub fn pending_in_room<'a>(
        &'a self,
        room_id: &'a str,
    ) -> impl Iterator<Item = &'a PendingApproval> + 'a {
        self.pending.iter().filter(move |p| p.room_id == room_id)
    }

    /// Borrow the pending approval for `request_id`, if one is queued.
    pub fn get(&self, request_id: &str) -> Option<&PendingApproval> {
        self.pending.iter().find(|p| p.request_id() == request_id)
    }

    /// Queue an approval request, replacing any existing entry with the same
    /// `request_id` (so redelivered request events are idempotent).
    pub fn enqueue(&mut self, approval: PendingApproval) {
        if let Some(idx) = self
            .pending
            .iter()
            .position(|p| p.request_id() == approval.request_id())
        {
            self.pending[idx] = approval;
        } else {
            self.pending.push(approval);
        }
    }

    /// Remove and return the pending approval for `request_id`, if present.
    ///
    /// Used once a decision is made to take the request off the queue.
    pub fn remove(&mut self, request_id: &str) -> Option<PendingApproval> {
        let idx = self
            .pending
            .iter()
            .position(|p| p.request_id() == request_id)?;
        Some(self.pending.remove(idx))
    }
}

/// List the locally queued pending approvals, optionally filtered by room.
///
/// Reads the on-disk queue (returning an empty list when none has been written
/// yet) and sorts by `request_id` for stable, deterministic output.
pub fn list_pending_approvals(
    paths: &SessionPaths,
    room: Option<&str>,
) -> io::Result<Vec<PendingApproval>> {
    let queue = ApprovalQueue::load(paths)?;
    let mut pending: Vec<PendingApproval> = match room {
        Some(room_id) => queue.pending_in_room(room_id).cloned().collect(),
        None => queue.pending().to_vec(),
    };
    pending.sort_by(|a, b| a.request_id().cmp(b.request_id()));
    Ok(pending)
}

/// Fetch a single queued approval by request ID.
pub fn get_pending_approval(
    paths: &SessionPaths,
    request_id: &str,
) -> io::Result<Option<PendingApproval>> {
    Ok(ApprovalQueue::load(paths)?.get(request_id).cloned())
}

/// `decision` value approving a request: the held command may now run.
pub const DECISION_APPROVED: &str = "approved";
/// `decision` value denying a request: the held command must never run.
pub const DECISION_DENIED: &str = "denied";

/// Build the `com.mxagent.approval.decision.v1` content for a decision.
///
/// Pure and deterministic: the caller supplies the identity that decided and the
/// timestamp, so the result depends only on its inputs (the wall clock is read by
/// [`decide_approval_for_session`], not here).
pub fn approval_decision_for(
    request_id: &str,
    decision: &str,
    approved_by: &str,
    created_at: &str,
) -> ApprovalDecision {
    ApprovalDecision {
        request_id: request_id.to_string(),
        decision: decision.to_string(),
        approved_by: approved_by.to_string(),
        created_at: created_at.to_string(),
        nonce: None,
        expires_at: None,
        signature: None,
        extra: Default::default(),
    }
}

/// Whether a decision permits the held request to proceed.
///
/// Fail-closed: only an explicit [`DECISION_APPROVED`] lets the request run, so a
/// denial — or any unrecognised decision value — keeps it from ever spawning.
/// This is the gate behind the acceptance criteria "approved request proceeds,
/// denied request never spawns".
pub fn decision_permits_spawn(decision: &ApprovalDecision) -> bool {
    decision.decision == DECISION_APPROVED
}

/// Emit a `com.mxagent.approval.decision.v1` timeline event into `room`.
pub async fn emit_approval_decision(
    room: &Room,
    decision: &ApprovalDecision,
) -> Result<(), WorkspaceError> {
    let content = serde_json::to_value(decision)
        .map_err(|e| WorkspaceError::from(matrix_sdk::Error::SerdeJson(e)))?;
    room.send_raw(APPROVAL_DECISION, content)
        .await
        .map_err(WorkspaceError::from)?;
    Ok(())
}

/// Read recorded `com.mxagent.approval.decision.v1` events from `room`, keyed by
/// `request_id`.
///
/// Scans up to `limit` recent timeline events newest-first and keeps the **first
/// (newest)** decision seen per `request_id`, so a later decision supersedes an
/// earlier one. The live scheduler uses this to resolve a held approval-required
/// task against published decisions (architecture §12): an `approved` decision
/// lets it proceed, any other (or absent) decision keeps it fail-closed.
pub async fn read_approval_decisions(
    room: &Room,
    limit: u32,
) -> Result<HashMap<String, ApprovalDecision>, WorkspaceError> {
    let mut request = MessagesOptions::backward();
    request.limit = matrix_sdk::ruma::UInt::from(limit);
    let messages = room.messages(request).await.map_err(WorkspaceError::from)?;

    let mut decisions: HashMap<String, ApprovalDecision> = HashMap::new();
    for event in messages.chunk {
        let raw = event.raw();
        let is_decision =
            raw.get_field::<String>("type").ok().flatten().as_deref() == Some(APPROVAL_DECISION);
        if !is_decision {
            continue;
        }
        if let Ok(Some(decision)) = raw.get_field::<ApprovalDecision>("content") {
            // Newest-first scan: the first occurrence per request_id wins.
            decisions
                .entry(decision.request_id.clone())
                .or_insert(decision);
        }
    }
    Ok(decisions)
}

/// Read `com.mxagent.approval.decision.v1` events from `room`, keeping only those
/// bound to a verifiable approver identity (issue #264).
///
/// Tightens [`read_approval_decisions`] so a decision can release a held task
/// **only if** every check passes — any failure drops the decision before it is
/// mapped, so a forged or unverifiable `approved` event presents to the gate as
/// "no decision" (still pending) rather than a release:
///
/// 1. **Sender** — the Matrix `sender` (read from the top-level event, not the
///    attacker-controlled `content`) must equal `local_user`, the host daemon's
///    own user id. Room membership alone never satisfies the approval gate.
/// 2. **Signature** — the decision must carry a [`Signature`](mx_agent_protocol::schema::Signature)
///    whose `key_id` resolves in `verifying_keys` and verifies over the
///    decision's canonical bytes. Because the sender check already establishes
///    provenance for a self-issued decision, the daemon's own published key
///    (present in `verifying_keys`) is sufficient; no separate trust-store
///    membership is required for `sender == local_user`.
/// 3. **Replay material** — the decision must carry both a `nonce` and an
///    `expires_at`, which the scheduler consumes through the [`ReplayCache`] on
///    the pass that actually releases the task.
///
/// Rejections are logged with non-sensitive metadata only (sender, request_id,
/// reason) — never the signature, nonce, or content.
///
/// [`ReplayCache`]: crate::replay::ReplayCache
pub async fn read_verified_approval_decisions(
    room: &Room,
    limit: u32,
    local_user: &str,
    verifying_keys: &BTreeMap<String, VerifyingKey>,
) -> Result<HashMap<String, ApprovalDecision>, WorkspaceError> {
    let mut request = MessagesOptions::backward();
    request.limit = matrix_sdk::ruma::UInt::from(limit);
    let messages = room.messages(request).await.map_err(WorkspaceError::from)?;

    let mut decisions: HashMap<String, ApprovalDecision> = HashMap::new();
    for event in messages.chunk {
        let raw = event.raw();
        let is_decision =
            raw.get_field::<String>("type").ok().flatten().as_deref() == Some(APPROVAL_DECISION);
        if !is_decision {
            continue;
        }
        let sender = raw
            .get_field::<String>("sender")
            .ok()
            .flatten()
            .unwrap_or_default();
        let decision = match raw.get_field::<ApprovalDecision>("content") {
            Ok(Some(decision)) => decision,
            _ => continue,
        };

        if let Some(reason) = verification_failure(&decision, &sender, local_user, verifying_keys) {
            tracing::warn!(
                sender = %sender,
                request_id = %decision.request_id,
                reason,
                "rejecting unverified approval decision"
            );
            continue;
        }

        // Newest-first scan: the first *verified* occurrence per request_id wins.
        decisions
            .entry(decision.request_id.clone())
            .or_insert(decision);
    }
    Ok(decisions)
}

/// Return the non-sensitive reason a decision is not eligible to release a held
/// task, or `None` when it passes every sender/signature/replay-material check.
///
/// Pure and fail-closed, so it is unit-testable without a live room.
pub fn verification_failure(
    decision: &ApprovalDecision,
    sender: &str,
    local_user: &str,
    verifying_keys: &BTreeMap<String, VerifyingKey>,
) -> Option<&'static str> {
    if sender.is_empty() || sender != local_user {
        return Some("untrusted_sender");
    }
    let Some(signature) = &decision.signature else {
        return Some("missing_signature");
    };
    let Some(key) = verifying_keys.get(&signature.key_id) else {
        return Some("unresolved_key");
    };
    if verify_approval_decision(key, decision).is_err() {
        return Some("invalid_signature");
    }
    if decision.nonce.is_none() || decision.expires_at.is_none() {
        return Some("missing_replay_material");
    }
    None
}

/// The outcome of deciding a queued approval.
///
/// Returned by [`decide_approval_for_session`] once the decision has been emitted
/// into the room and the request removed from the local queue.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ApprovalDecisionRecord {
    /// The decision event that was emitted.
    pub decision: ApprovalDecision,
    /// Matrix room ID the decision was emitted into.
    pub room_id: String,
}

impl ApprovalDecisionRecord {
    /// Whether the recorded decision approved the request.
    pub fn approved(&self) -> bool {
        decision_permits_spawn(&self.decision)
    }
}

/// Default lifetime stamped onto a queued task approval request.
///
/// Bounds the `expires_at` of an emitted `com.mxagent.approval.request.v1` so a
/// queued approval carries a finite horizon rather than an unbounded one.
pub const APPROVAL_REQUEST_TTL: Duration = Duration::from_secs(3600);

/// Compute the `expires_at` (RFC 3339 UTC) for an approval request raised at
/// `now` with lifetime `ttl`.
///
/// Pure and deterministic given its inputs (the wall clock is read by the
/// caller), so it is unit-testable without mocking time.
pub fn approval_request_expiry(now: SystemTime, ttl: Duration) -> String {
    let secs = now
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
        .saturating_add(ttl.as_secs());
    unix_to_rfc3339(secs)
}

/// Whether an approval request stamped with `expires_at` (RFC 3339 UTC) has
/// closed at or before `now_unix` (Unix seconds).
///
/// Pure and deterministic given its inputs, so the expiry transition is
/// unit-testable without mocking the wall clock (mirrors
/// [`approval_request_expiry`]). The boundary is `<=` to match
/// [`ReplayCache::admit_at`](crate::replay::ReplayCache): a stamp equal to
/// `now_unix` counts as expired.
///
/// A malformed `expires_at` is treated as **not yet expired** (fail-open on the
/// *expiry* axis only): the request stays pending and resolvable by an explicit
/// decision rather than being silently finalized off an unparseable stamp. The
/// same daemon stamps the value with a well-formed formatter, so a malformed
/// stamp signals corruption, not a closed window — and an explicit deny/approve
/// still terminates the request. This never weakens execution safety: a task
/// still requires a verified approval to ever run.
pub fn approval_request_expired(expires_at: &str, now_unix: i64) -> bool {
    match crate::replay::parse_rfc3339_to_unix(expires_at) {
        Some(expiry) => expiry <= now_unix,
        None => false,
    }
}

/// Format the current wall-clock time as an RFC 3339 UTC timestamp.
fn now_rfc3339() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default();
    unix_to_rfc3339(secs)
}

/// Format Unix seconds as an RFC 3339 UTC timestamp (`YYYY-MM-DDTHH:MM:SSZ`).
///
/// Uses Howard Hinnant's civil-from-days algorithm so no date library is
/// required, matching the formatter used elsewhere in the daemon.
fn unix_to_rfc3339(secs: u64) -> String {
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
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { y + 1 } else { y };

    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Sync once, resolve the room, and return its [`Room`] handle.
async fn sync_and_get_room(client: &Client, target: &str) -> Result<Room, WorkspaceError> {
    let id = parse_room_or_alias(target)?;
    client
        .sync_once(SyncSettings::default())
        .await
        .map_err(WorkspaceError::from)?;
    let room_id = resolve_room_id(client, &id).await?;
    client
        .get_room(&room_id)
        .ok_or_else(|| WorkspaceError::RoomNotFound(target.to_string()))
}

/// Decide a queued approval: emit a `com.mxagent.approval.decision.v1` event into
/// the request's room and take it off the local pending queue.
///
/// `decision` is [`DECISION_APPROVED`] or [`DECISION_DENIED`]; `approved_by` is
/// the identity recording the decision (typically the operator's Matrix user ID).
/// The request is looked up in the local queue first — an unknown `request_id` is
/// [`WorkspaceError::ApprovalNotFound`] — so the room the decision belongs to is
/// known without the caller supplying it. The decision is emitted before the
/// queue is updated, so a failure to publish leaves the request pending for a
/// retry rather than silently dropping it.
pub async fn decide_approval_for_session(
    session: &StoredSession,
    paths: &SessionPaths,
    request_id: &str,
    decision: &str,
    approved_by: &str,
) -> Result<ApprovalDecisionRecord, WorkspaceError> {
    let mut queue = ApprovalQueue::load(paths)?;
    let pending = queue
        .get(request_id)
        .cloned()
        .ok_or_else(|| WorkspaceError::ApprovalNotFound(request_id.to_string()))?;

    let client = restore_client(session).await?;
    let room = sync_and_get_room(&client, &pending.room_id).await?;

    // Bind the decision to a verifiable identity (issue #264): stamp a single-use
    // replay nonce and a bounded expiry, then sign with the daemon's own key. The
    // emitting Matrix user is the daemon itself, so a self-issued decision passes
    // the scheduler's sender check; the signature lets it be verified against the
    // daemon's published key before any held task is released.
    let mut content = approval_decision_for(request_id, decision, approved_by, &now_rfc3339());
    content.nonce = Some(generate_request_id());
    content.expires_at = Some(approval_request_expiry(
        SystemTime::now(),
        APPROVAL_REQUEST_TTL,
    ));
    let signing_key = load_or_create_signing_key(paths)
        .map_err(|e| WorkspaceError::Io(io::Error::other(e.to_string())))?;
    sign_approval_decision(
        signing_key.signing_key(),
        signing_key.key_id(),
        &mut content,
    )
    .map_err(|e| WorkspaceError::Io(io::Error::other(e.to_string())))?;
    emit_approval_decision(&room, &content).await?;

    // Only drop the request from the queue once the decision is published.
    queue.remove(request_id);
    queue.save(paths)?;

    Ok(ApprovalDecisionRecord {
        decision: content,
        room_id: pending.room_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use mx_agent_protocol::schema::Signature;
    use mx_agent_protocol::signing::sign_approval_decision;

    fn exec_request() -> ExecRequest {
        ExecRequest {
            invocation_id: "inv_01HZ".to_string(),
            request_id: "req_01HZ".to_string(),
            target_agent: "developer-pi".to_string(),
            requesting_agent: "claude-local".to_string(),
            command: vec!["npm".to_string(), "test".to_string()],
            cwd: "/home/me/code/project".to_string(),
            env: Default::default(),
            stdin: false,
            stream: true,
            pty: false,
            timeout_ms: 600_000,
            task_id: None,
            created_at: "2026-06-02T12:00:00Z".to_string(),
            expires_at: "2026-06-02T12:05:00Z".to_string(),
            nonce: "base64-nonce".to_string(),
            idempotency_key: "exec:inv_01HZ".to_string(),
            signature: Signature {
                alg: "ed25519".to_string(),
                key_id: "mxagent-ed25519:abc".to_string(),
                sig: "c2ln".to_string(),
            },
            extra: Default::default(),
        }
    }

    fn allowance(requires_approval: bool) -> Allowance {
        Allowance {
            requires_approval,
            sandbox: Some(Sandbox::Bubblewrap),
            network: Some(NetworkPolicy::Deny),
            ..Allowance::default()
        }
    }

    fn paths_in(dir: &std::path::Path) -> SessionPaths {
        SessionPaths::for_data_dir(dir.to_path_buf())
    }

    fn tmp_dir(tag: &str) -> PathBuf {
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "mx-agent-approval-test-{tag}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn disposition_holds_request_when_approval_required() {
        // Acceptance: an approval-required request does not execute immediately.
        let disposition = disposition_for_exec(exec_request(), &allowance(true));
        assert!(disposition.requires_approval());
        assert!(
            disposition.executable().is_none(),
            "request must not be runnable while it awaits approval"
        );
        match disposition {
            ExecDisposition::RequiresApproval { approval, request } => {
                assert_eq!(approval.request_id, "req_01HZ");
                assert_eq!(approval.invocation_id, "inv_01HZ");
                assert_eq!(request.invocation_id, "inv_01HZ");
            }
            ExecDisposition::Execute(_) => panic!("expected approval to be required"),
        }
    }

    #[test]
    fn disposition_permits_immediate_run_without_flag() {
        let disposition = disposition_for_exec(exec_request(), &allowance(false));
        assert!(!disposition.requires_approval());
        assert_eq!(disposition.executable().unwrap().invocation_id, "inv_01HZ");
    }

    #[test]
    fn approval_request_summary_and_parties_match_request() {
        let approval = approval_request_for(&exec_request(), &allowance(true));
        assert_eq!(approval.summary, "Run npm test in /home/me/code/project");
        assert_eq!(approval.requester, "claude-local");
        assert_eq!(approval.target, "developer-pi");
        assert_eq!(approval.expires_at, "2026-06-02T12:05:00Z");
    }

    #[test]
    fn risk_reflects_isolation() {
        // Sandboxed and network-denied: the safer, medium case.
        assert_eq!(risk_for(&allowance(true)), "medium");
        // Network access granted raises the risk.
        let mut networked = allowance(true);
        networked.network = Some(NetworkPolicy::Allow);
        assert_eq!(risk_for(&networked), "high");
        // No real sandbox also raises the risk.
        let mut unsandboxed = allowance(true);
        unsandboxed.sandbox = Some(Sandbox::None);
        assert_eq!(risk_for(&unsandboxed), "high");
    }

    #[test]
    fn enqueue_is_idempotent_by_request_id() {
        let mut queue = ApprovalQueue::default();
        let approval = approval_request_for(&exec_request(), &allowance(true));
        let pending = PendingApproval {
            room_id: "!abc:matrix.org".to_string(),
            request: approval.clone(),
        };
        queue.enqueue(pending.clone());
        queue.enqueue(pending);
        assert_eq!(
            queue.pending().len(),
            1,
            "same request_id must not duplicate"
        );
        assert_eq!(queue.get("req_01HZ").unwrap().room_id, "!abc:matrix.org");
    }

    #[test]
    fn remove_takes_request_off_the_queue() {
        let mut queue = ApprovalQueue::default();
        queue.enqueue(PendingApproval {
            room_id: "!abc:matrix.org".to_string(),
            request: approval_request_for(&exec_request(), &allowance(true)),
        });
        let removed = queue.remove("req_01HZ").expect("present");
        assert_eq!(removed.request_id(), "req_01HZ");
        assert!(queue.get("req_01HZ").is_none());
        assert!(
            queue.remove("req_01HZ").is_none(),
            "second remove is a no-op"
        );
    }

    #[test]
    fn queue_survives_save_and_load() {
        // Acceptance: pending approvals are visible locally (and durable).
        let dir = tmp_dir("roundtrip");
        let paths = paths_in(&dir);

        let mut queue = ApprovalQueue::default();
        queue.enqueue(PendingApproval {
            room_id: "!abc:matrix.org".to_string(),
            request: approval_request_for(&exec_request(), &allowance(true)),
        });
        queue.save(&paths).unwrap();

        let reloaded = ApprovalQueue::load(&paths).unwrap();
        assert_eq!(reloaded, queue);
        assert_eq!(reloaded.pending().len(), 1);

        // The queue file must not be world-readable.
        let mode = fs::metadata(approval_queue_file(&paths))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0, "queue file must be 0600");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn list_filters_by_room_and_sorts() {
        let dir = tmp_dir("list");
        let paths = paths_in(&dir);

        let mut queue = ApprovalQueue::default();
        let mut a = exec_request();
        a.request_id = "req_b".to_string();
        let mut b = exec_request();
        b.request_id = "req_a".to_string();
        queue.enqueue(PendingApproval {
            room_id: "!one:matrix.org".to_string(),
            request: approval_request_for(&a, &allowance(true)),
        });
        queue.enqueue(PendingApproval {
            room_id: "!two:matrix.org".to_string(),
            request: approval_request_for(&b, &allowance(true)),
        });
        queue.save(&paths).unwrap();

        // No filter: both, sorted by request_id.
        let all = list_pending_approvals(&paths, None).unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].request_id(), "req_a");
        assert_eq!(all[1].request_id(), "req_b");

        // Room filter narrows to one.
        let one = list_pending_approvals(&paths, Some("!one:matrix.org")).unwrap();
        assert_eq!(one.len(), 1);
        assert_eq!(one[0].request_id(), "req_b");

        assert_eq!(
            get_pending_approval(&paths, "req_a")
                .unwrap()
                .unwrap()
                .room_id,
            "!two:matrix.org"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_is_empty_before_first_write() {
        let dir = tmp_dir("empty");
        let paths = paths_in(&dir);
        assert!(list_pending_approvals(&paths, None).unwrap().is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn decision_content_copies_inputs() {
        let decision = approval_decision_for(
            "req_01HZ",
            DECISION_APPROVED,
            "@alice:matrix.org",
            "2026-06-02T12:01:00Z",
        );
        assert_eq!(decision.request_id, "req_01HZ");
        assert_eq!(decision.decision, "approved");
        assert_eq!(decision.approved_by, "@alice:matrix.org");
        assert_eq!(decision.created_at, "2026-06-02T12:01:00Z");
    }

    #[test]
    fn approved_request_proceeds_denied_never_spawns() {
        // Acceptance: an approved request proceeds; a denied one never spawns.
        let approved = approval_decision_for("req", DECISION_APPROVED, "@a:srv", "t");
        let denied = approval_decision_for("req", DECISION_DENIED, "@a:srv", "t");
        assert!(decision_permits_spawn(&approved));
        assert!(!decision_permits_spawn(&denied));

        // Fail-closed: any unrecognised decision value is treated as a denial.
        let garbled = approval_decision_for("req", "maybe", "@a:srv", "t");
        assert!(
            !decision_permits_spawn(&garbled),
            "only an explicit approval may let a request run"
        );
    }

    #[test]
    fn decision_record_reports_approval() {
        let record = ApprovalDecisionRecord {
            decision: approval_decision_for("req", DECISION_APPROVED, "@a:srv", "t"),
            room_id: "!abc:matrix.org".to_string(),
        };
        assert!(record.approved());
        let denied = ApprovalDecisionRecord {
            decision: approval_decision_for("req", DECISION_DENIED, "@a:srv", "t"),
            room_id: "!abc:matrix.org".to_string(),
        };
        assert!(!denied.approved());
    }

    #[test]
    fn approval_request_expiry_adds_ttl_to_now() {
        // A known instant plus a one-hour TTL yields the expected RFC 3339 stamp.
        let base = UNIX_EPOCH + Duration::from_secs(1_748_865_600); // 2025-06-02T12:00:00Z
        let expiry = approval_request_expiry(base, Duration::from_secs(3600));
        assert_eq!(expiry, "2025-06-02T13:00:00Z");
        // The default TTL is bounded (not unbounded) and well-formed.
        let with_default = approval_request_expiry(base, APPROVAL_REQUEST_TTL);
        assert_eq!(with_default.len(), 20);
        assert!(with_default.ends_with('Z'));
    }

    #[test]
    fn approval_request_expired_is_true_for_past_stamp() {
        // A stamp strictly before `now_unix` is expired.
        let now = 1_748_865_600; // 2025-06-02T12:00:00Z
        assert!(approval_request_expired("2025-06-02T11:00:00Z", now));
    }

    #[test]
    fn approval_request_expired_is_false_for_future_stamp() {
        let now = 1_748_865_600; // 2025-06-02T12:00:00Z
        assert!(!approval_request_expired("2025-06-02T13:00:00Z", now));
        // Boundary: a stamp equal to `now_unix` counts as expired (`<=`).
        assert!(approval_request_expired("2025-06-02T12:00:00Z", now));
    }

    #[test]
    fn approval_request_expired_is_false_for_malformed_stamp() {
        // Fail-open on the expiry axis: an unparseable stamp is never treated as
        // a closed window (it stays decidable by an explicit approve/deny).
        let now = 1_748_865_600;
        assert!(!approval_request_expired("garbage", now));
        assert!(!approval_request_expired("", now));
    }

    #[test]
    fn now_rfc3339_round_trips_a_known_instant() {
        assert_eq!(unix_to_rfc3339(1_748_865_600), "2025-06-02T12:00:00Z");
        // now_rfc3339 reads the wall clock; just assert it is well-formed.
        let now = now_rfc3339();
        assert_eq!(now.len(), 20, "RFC 3339 UTC seconds is 20 chars");
        assert!(now.ends_with('Z'));
    }

    // --- verification_failure tests (issue #264) ----------------------------

    fn vf_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[
            0x3b, 0x6a, 0x27, 0xbc, 0xce, 0xb6, 0xa4, 0x2d, 0x62, 0xa3, 0xa8, 0xd0, 0x2a, 0x6f,
            0x0d, 0x73, 0x65, 0x32, 0x15, 0x77, 0x1d, 0xe2, 0x43, 0xa6, 0x3a, 0xc0, 0x48, 0xa1,
            0x8b, 0x59, 0xda, 0x29,
        ])
    }

    const VF_KEY_ID: &str = "mxagent-ed25519:vf-test";
    const VF_LOCAL_USER: &str = "@daemon:server";

    fn vf_keys() -> BTreeMap<String, VerifyingKey> {
        let mut keys = BTreeMap::new();
        keys.insert(VF_KEY_ID.to_string(), vf_signing_key().verifying_key());
        keys
    }

    fn signed_vf_decision() -> ApprovalDecision {
        let mut d = ApprovalDecision {
            request_id: "approval:task-a".to_string(),
            decision: "approved".to_string(),
            approved_by: VF_LOCAL_USER.to_string(),
            created_at: "2026-06-10T12:00:00Z".to_string(),
            nonce: Some("nonce-vf-test".to_string()),
            expires_at: Some("2026-06-10T13:00:00Z".to_string()),
            signature: None,
            extra: Default::default(),
        };
        sign_approval_decision(&vf_signing_key(), VF_KEY_ID, &mut d).unwrap();
        d
    }

    #[test]
    fn verification_failure_passes_valid_signed_decision() {
        // Positive path: a properly signed decision from the daemon's own user
        // must pass all checks (returns None = no failure).
        assert_eq!(
            verification_failure(
                &signed_vf_decision(),
                VF_LOCAL_USER,
                VF_LOCAL_USER,
                &vf_keys()
            ),
            None,
            "a valid signed decision from the daemon itself must pass all checks"
        );
    }

    #[test]
    fn verification_failure_rejects_empty_sender() {
        assert_eq!(
            verification_failure(&signed_vf_decision(), "", VF_LOCAL_USER, &vf_keys()),
            Some("untrusted_sender")
        );
    }

    #[test]
    fn verification_failure_rejects_wrong_sender_room_member_cannot_approve() {
        // Security regression #264: room membership alone must not satisfy the
        // approval gate. A room member who is not the host daemon cannot release
        // a held task regardless of what they put in the event content.
        assert_eq!(
            verification_failure(
                &signed_vf_decision(),
                "@attacker:server",
                VF_LOCAL_USER,
                &vf_keys()
            ),
            Some("untrusted_sender"),
            "room membership alone must not satisfy the approval gate"
        );
    }

    #[test]
    fn verification_failure_rejects_unsigned_decision() {
        // An event without a signature field must be rejected before it can
        // release a held task, even if it looks otherwise valid.
        let unsigned = ApprovalDecision {
            request_id: "approval:task-a".to_string(),
            decision: "approved".to_string(),
            approved_by: VF_LOCAL_USER.to_string(),
            created_at: "2026-06-10T12:00:00Z".to_string(),
            nonce: Some("nonce-vf-test".to_string()),
            expires_at: Some("2026-06-10T13:00:00Z".to_string()),
            signature: None,
            extra: Default::default(),
        };
        assert_eq!(
            verification_failure(&unsigned, VF_LOCAL_USER, VF_LOCAL_USER, &vf_keys()),
            Some("missing_signature"),
            "an unsigned decision must not release a held task"
        );
    }

    #[test]
    fn verification_failure_rejects_unresolved_key_id() {
        // The signature's key_id must be known locally; an unknown key_id is
        // rejected even if the signature bytes themselves could be valid.
        let mut d = signed_vf_decision();
        d.signature.as_mut().unwrap().key_id = "mxagent-ed25519:unknown".to_string();
        assert_eq!(
            verification_failure(&d, VF_LOCAL_USER, VF_LOCAL_USER, &vf_keys()),
            Some("unresolved_key")
        );
    }

    #[test]
    fn verification_failure_rejects_tampered_decision_field() {
        // Flipping the decision from "approved" to "denied" after signing must
        // invalidate the signature so the event is dropped.
        let mut d = signed_vf_decision();
        d.decision = "denied".to_string();
        assert_eq!(
            verification_failure(&d, VF_LOCAL_USER, VF_LOCAL_USER, &vf_keys()),
            Some("invalid_signature"),
            "a tampered decision field must fail signature verification"
        );
    }

    #[test]
    fn verification_failure_rejects_tampered_request_id() {
        // Changing the request_id after signing must also invalidate the
        // signature, preventing a forged release targeting a different task.
        let mut d = signed_vf_decision();
        d.request_id = "approval:other-task".to_string();
        assert_eq!(
            verification_failure(&d, VF_LOCAL_USER, VF_LOCAL_USER, &vf_keys()),
            Some("invalid_signature")
        );
    }

    #[test]
    fn verification_failure_rejects_missing_nonce() {
        // No nonce means no replay protection: even a validly-signed decision
        // must be rejected if the nonce field is absent.
        let mut d = ApprovalDecision {
            request_id: "approval:task-a".to_string(),
            decision: "approved".to_string(),
            approved_by: VF_LOCAL_USER.to_string(),
            created_at: "2026-06-10T12:00:00Z".to_string(),
            nonce: None,
            expires_at: Some("2026-06-10T13:00:00Z".to_string()),
            signature: None,
            extra: Default::default(),
        };
        sign_approval_decision(&vf_signing_key(), VF_KEY_ID, &mut d).unwrap();
        assert_eq!(
            verification_failure(&d, VF_LOCAL_USER, VF_LOCAL_USER, &vf_keys()),
            Some("missing_replay_material"),
            "a decision without a nonce must not release a held task"
        );
    }

    #[test]
    fn verification_failure_rejects_missing_expires_at() {
        // No expires_at means the replay cache cannot enforce a lifetime bound:
        // reject even a validly-signed decision that lacks this field.
        let mut d = ApprovalDecision {
            request_id: "approval:task-a".to_string(),
            decision: "approved".to_string(),
            approved_by: VF_LOCAL_USER.to_string(),
            created_at: "2026-06-10T12:00:00Z".to_string(),
            nonce: Some("nonce-vf-test".to_string()),
            expires_at: None,
            signature: None,
            extra: Default::default(),
        };
        sign_approval_decision(&vf_signing_key(), VF_KEY_ID, &mut d).unwrap();
        assert_eq!(
            verification_failure(&d, VF_LOCAL_USER, VF_LOCAL_USER, &vf_keys()),
            Some("missing_replay_material"),
            "a decision without expires_at must not release a held task"
        );
    }

    #[test]
    fn verification_failure_rejects_empty_verifying_keys_map() {
        // The host daemon has no record of the signing key: must reject even
        // if the signature is otherwise valid.
        let empty: BTreeMap<String, VerifyingKey> = BTreeMap::new();
        assert_eq!(
            verification_failure(&signed_vf_decision(), VF_LOCAL_USER, VF_LOCAL_USER, &empty),
            Some("unresolved_key"),
            "a decision whose key_id is not locally known must be rejected"
        );
    }
}
