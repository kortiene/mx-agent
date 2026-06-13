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

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ed25519_dalek::VerifyingKey;
use matrix_sdk::config::SyncSettings;
use matrix_sdk::room::MessagesOptions;
use matrix_sdk::{Client, Room};
use mx_agent_policy::{Allowance, NetworkPolicy, Policy, Sandbox};
use mx_agent_protocol::events::timeline::{APPROVAL_DECISION, APPROVAL_REQUEST};
use mx_agent_protocol::id::generate_request_id;
use mx_agent_protocol::schema::{ApprovalDecision, ApprovalRequest, CallRequest, ExecRequest};
use mx_agent_protocol::signing::{sign_approval_decision, verify_approval_decision};
use serde::{Deserialize, Serialize};

use crate::event_router::{EventMeta, EventRouter};
use crate::matrix::restore_client;
use crate::session::{SessionPaths, StoredSession};
use crate::signing::load_or_create_signing_key;
use crate::trust::TrustStore;
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

/// Whether an authorized named `call` may run immediately or must wait for
/// approval.
///
/// The `call` analogue of [`ExecDisposition`]. [`ExecDisposition`] wraps an
/// [`ExecRequest`], so a named call needs its own type wrapping a
/// [`CallRequest`] (the two request shapes differ). A
/// [`CallDisposition::RequiresApproval`] carries the [`ApprovalRequest`] the
/// caller must queue and emit; the wrapped request must **not** be executed
/// until an approval decision arrives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallDisposition {
    /// The call is authorized and may be executed immediately.
    Execute(CallRequest),
    /// The call requires approval before running. The caller must queue and
    /// emit the bundled [`ApprovalRequest`] and hold the call until a decision
    /// arrives.
    RequiresApproval {
        /// The call that is being held pending approval.
        request: CallRequest,
        /// The approval request to queue locally and emit into the room.
        approval: ApprovalRequest,
    },
}

impl CallDisposition {
    /// Whether this disposition holds the call pending approval.
    pub fn requires_approval(&self) -> bool {
        matches!(self, CallDisposition::RequiresApproval { .. })
    }

    /// The call that may run now, or `None` when approval is required.
    pub fn executable(&self) -> Option<&CallRequest> {
        match self {
            CallDisposition::Execute(request) => Some(request),
            CallDisposition::RequiresApproval { .. } => None,
        }
    }
}

/// Decide whether an authorized named `call` may run now or must be queued for
/// approval, honouring the policy's `requires_approval` flag.
///
/// The `call` analogue of [`disposition_for_exec`]. `allowance` is the resolved
/// [`Allowance`] the policy engine returned for the call (see
/// [`crate::call::authorize_call_request_with_allowance`]). When it sets
/// `requires_approval`, the call is wrapped in
/// [`CallDisposition::RequiresApproval`] alongside the [`ApprovalRequest`] to
/// emit; otherwise it is returned as [`CallDisposition::Execute`] and may run
/// immediately, preserving the no-approval behaviour exactly.
pub fn disposition_for_call(request: CallRequest, allowance: &Allowance) -> CallDisposition {
    if allowance.requires_approval {
        let approval = approval_request_for_call(&request, allowance);
        CallDisposition::RequiresApproval { request, approval }
    } else {
        CallDisposition::Execute(request)
    }
}

/// Build the `com.mxagent.approval.request.v1` content for a named call.
///
/// Pure and deterministic: identifiers, parties, and expiry are copied from the
/// authorized request; the summary names only the tool (the call's `args` are
/// never rendered, so nothing sensitive leaks — mirroring the no-leak posture of
/// the audit path); the risk level reuses [`risk_for`].
///
/// `CallRequest::requesting_agent` / `target_agent` are `Option<String>`; the
/// live handler only reaches the disposition once both are present, but this
/// builder stays total via `unwrap_or_default`.
pub fn approval_request_for_call(request: &CallRequest, allowance: &Allowance) -> ApprovalRequest {
    ApprovalRequest {
        request_id: request.request_id.clone(),
        invocation_id: request.invocation_id.clone(),
        requester: request.requesting_agent.clone().unwrap_or_default(),
        target: request.target_agent.clone().unwrap_or_default(),
        summary: format!("Call tool {}", request.tool),
        risk: risk_for(allowance).to_string(),
        expires_at: request.expires_at.clone(),
        extra: Default::default(),
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

/// The original signed live request held pending an approval decision (issue
/// #306).
///
/// Persisted locally alongside a [`PendingApproval`] (in the `0600`
/// `approvals.json`, never re-emitted) so an approving
/// `com.mxagent.approval.decision.v1` can recover the exact request, re-run the
/// full authorize pipeline, and spawn it. `None` for task-backed holds (released
/// by the scheduler via `QueueApprovalGate`) and for holds written by an older
/// daemon, which the live handler cannot auto-resume → the operator re-issues
/// (fail-closed).
///
/// The variant is the daemon's externally-tagged JSON (`{"exec": {…}}` /
/// `{"call": {…}}`); this is daemon-private state, so the representation only
/// needs to round-trip locally, not federate. It carries the full signed
/// request — including `command`/`env`/`args` — so it is `0600`-at-rest only and
/// is **never** logged or copied into the emitted no-leak `ApprovalRequest`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HeldRequest {
    /// A held raw `exec` request.
    Exec(ExecRequest),
    /// A held named `call` request.
    Call(CallRequest),
}

impl HeldRequest {
    /// A copy with the sensitive request payload removed, for the inspection
    /// surface (issue #306).
    ///
    /// The variant and request identity survive — so `list_pending_approvals`
    /// / `get_pending_approval` callers (the CLI `approval list`/`show` views)
    /// can still see that a live-resume hold exists — but the content that must
    /// stay `0600`-at-rest is blanked: an exec's `command`/`env` and a call's
    /// `args`, plus each request's forward-compat `extra` (a `#[serde(flatten)]`
    /// escape hatch that could otherwise carry the same secrets to the top
    /// level). Resume reads the full request from the on-disk queue, never from
    /// this scrubbed copy, so blanking these costs the release path nothing.
    fn redacted_for_inspection(&self) -> HeldRequest {
        match self {
            HeldRequest::Exec(req) => {
                let mut redacted = req.clone();
                redacted.command = Vec::new();
                redacted.env = Default::default();
                redacted.extra = Default::default();
                HeldRequest::Exec(redacted)
            }
            HeldRequest::Call(req) => {
                let mut redacted = req.clone();
                redacted.args = serde_json::Value::Null;
                redacted.extra = Default::default();
                HeldRequest::Call(redacted)
            }
        }
    }
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
    /// The original signed live request to resume on an approving decision
    /// (issue #306); local-only, `0600`-at-rest, never emitted or logged. `None`
    /// for task-backed holds (released by the scheduler) and legacy holds, which
    /// the live decision handler ignores so the task and live release paths never
    /// collide. Additive and `#[serde(default)]`, so older queues load.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub held_request: Option<HeldRequest>,
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
    // `held_request` carries the full signed request (command/env/args) for
    // local resume only; it is `0600`-at-rest and must never reach an inspection
    // surface (this is the CLI `approval list` view). Redact — rather than drop —
    // the held payload so a caller can still see a live-resume hold *exists*
    // (`held_request.is_some()`) without its secrets serializing. The internal
    // release paths read the queue directly via `ApprovalQueue::load`/`get`, so
    // this keeps persistence and resume intact while preventing the arg leak
    // (issue #306).
    for p in &mut pending {
        p.held_request = p
            .held_request
            .as_ref()
            .map(HeldRequest::redacted_for_inspection);
    }
    Ok(pending)
}

/// Fetch a single queued approval by request ID.
pub fn get_pending_approval(
    paths: &SessionPaths,
    request_id: &str,
) -> io::Result<Option<PendingApproval>> {
    // Redact `held_request` on this inspection surface for the same reason as
    // `list_pending_approvals` (issue #306): the CLI `approval show` view keeps
    // the "a live-resume hold exists" signal but never the held command/env/args.
    // Resume reads the queue directly.
    Ok(ApprovalQueue::load(paths)?
        .get(request_id)
        .cloned()
        .map(|mut p| {
            p.held_request = p
                .held_request
                .as_ref()
                .map(HeldRequest::redacted_for_inspection);
            p
        }))
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

/// The anchors an approval decision is verified against before it may release a
/// held `requires_approval` task (issue #309).
///
/// Releasing a held task is a privileged action, so — like the exec/call/task
/// receiver pipeline (`signature verify → trust store → deny-by-default`) — it is
/// anchored in the operator's **local trust store**, never in room-published
/// state alone. All four anchors are checked: an authorized approver identity, an
/// Ed25519 signature from a key that is BOTH room-published and locally
/// [`Trusted`](crate::trust::TrustStatus::Trusted), replay material, and a
/// non-expired deadline.
pub struct DecisionVerification<'a> {
    /// The host daemon's own Matrix user id — always an authorized approver.
    pub local_user: &'a str,
    /// Additional Matrix user ids configured (via `RoomPolicy::approvers`) to
    /// approve in this room. The authorized set is the **union**
    /// `{local_user} ∪ approvers`, so an empty set means daemon-only (the secure
    /// default). Membership is necessary but never sufficient: an approver still
    /// needs an Ed25519 signature from a locally-trusted key.
    pub approvers: &'a BTreeSet<String>,
    /// Verifying keys resolved from room-published agent state, keyed by key_id.
    /// This is the *key material*; the trust store below is the *authority*.
    pub verifying_keys: &'a BTreeMap<String, VerifyingKey>,
    /// The authoritative local trust store (mirrors the exec/call anchor).
    pub trust: &'a TrustStore,
    /// "Now" in Unix seconds for the cache-independent decision-expiry check.
    pub now_unix: i64,
}

/// Read `com.mxagent.approval.decision.v1` events from `room`, keeping only those
/// bound to a verifiable approver identity (issues #264, #309).
///
/// Tightens [`read_approval_decisions`] so a decision can release a held task
/// **only if** every check in [`verification_failure`] passes — any failure drops
/// the decision before it is mapped, so a forged or unverifiable `approved` event
/// presents to the gate as "no decision" (still pending) rather than a release.
/// The decision's signing key must be both room-published *and* locally trusted,
/// the sender must be an authorized approver, and the decision must be unexpired,
/// so room membership / room-state write access (companion #301) can never on its
/// own satisfy the approval gate.
///
/// Rejections are logged with non-sensitive metadata only (sender, request_id,
/// reason) — never the signature, nonce, or content.
pub async fn read_verified_approval_decisions(
    room: &Room,
    limit: u32,
    verification: &DecisionVerification<'_>,
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

        if let Some(reason) = verification_failure(&decision, &sender, verification) {
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
/// task, or `None` when it passes every check.
///
/// Pure and fail-closed, so it is unit-testable without a live room. Checks are
/// applied in this order, each reason a non-sensitive `&'static str` (issue
/// #309):
///
/// 1. `untrusted_sender` — the Matrix `sender` (the top-level event sender, not
///    the attacker-controlled `content`) is empty, or is neither
///    `ctx.local_user` nor a member of the configured `ctx.approvers` allowlist.
/// 2. `missing_signature` — no detached Ed25519 signature.
/// 3. `unresolved_key` — `signature.key_id` is not among the room-published
///    `ctx.verifying_keys`.
/// 4. `untrusted_key` — `signature.key_id` is unknown or revoked in the local
///    trust store. This is the trust-store anchor (mirrors
///    [`authorize_exec_request_with_allowance`](crate::exec::authorize_exec_request_with_allowance)):
///    room-published state is never the sole key anchor.
/// 5. `invalid_signature` — the signature does not verify over the decision's
///    canonical bytes.
/// 6. `missing_replay_material` — `nonce` or `expires_at` is absent.
/// 7. `malformed_expiry` / `decision_expired` — the `expires_at` stamp cannot be
///    parsed (fail **closed**: a daemon-signed decision with an unparseable stamp
///    is corrupt/tampered, unlike the request-side fail-open in
///    [`approval_request_expired`]), or it has passed `ctx.now_unix` (the `<=`
///    boundary matches [`ReplayCache::admit_at`](crate::replay::ReplayCache)).
///    This makes decision expiry hold even when no replay cache is attached.
pub fn verification_failure(
    decision: &ApprovalDecision,
    sender: &str,
    ctx: &DecisionVerification<'_>,
) -> Option<&'static str> {
    // 1. Authorized approver: the daemon's own account is always allowed; a
    //    configured allowlist *adds* approvers (union semantics).
    let authorized =
        !sender.is_empty() && (sender == ctx.local_user || ctx.approvers.contains(sender));
    if !authorized {
        return Some("untrusted_sender");
    }
    let Some(signature) = &decision.signature else {
        return Some("missing_signature");
    };
    let Some(key) = ctx.verifying_keys.get(&signature.key_id) else {
        return Some("unresolved_key");
    };
    // The signing key must be locally trusted — not merely self-consistent in
    // room state. Unknown and revoked keys both return false here.
    if !ctx.trust.is_key_trusted(&signature.key_id) {
        return Some("untrusted_key");
    }
    if verify_approval_decision(key, decision).is_err() {
        return Some("invalid_signature");
    }
    let (Some(_nonce), Some(expires_at)) = (&decision.nonce, &decision.expires_at) else {
        return Some("missing_replay_material");
    };
    // Cache-independent expiry: enforced here at read time so it holds even on a
    // pass with no replay cache attached. Fail closed on a malformed stamp.
    match crate::replay::parse_rfc3339_to_unix(expires_at) {
        None => return Some("malformed_expiry"),
        Some(expiry) if expiry <= ctx.now_unix => return Some("decision_expired"),
        Some(_) => {}
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
/// the request's room and, for task/legacy holds, take it off the local pending
/// queue.
///
/// `decision` is [`DECISION_APPROVED`] or [`DECISION_DENIED`]; `approved_by` is
/// the identity recording the decision (typically the operator's Matrix user ID).
/// The request is looked up in the local queue first — an unknown `request_id` is
/// [`WorkspaceError::ApprovalNotFound`] — so the room the decision belongs to is
/// known without the caller supplying it. The decision is emitted before the
/// queue is updated, so a failure to publish leaves the request pending for a
/// retry rather than silently dropping it.
///
/// A *live* hold (`held_request` set) is intentionally left queued: its original
/// request lives only in the queue entry, so [`handle_live_approval_decision`]
/// must still find it to spawn (approve) or reject (deny) it. Only that handler
/// (or the expiry sweep) removes a live hold.
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

    // Only drop the request from the queue once the decision is published — and
    // only for task/legacy holds (`held_request == None`), which the scheduler
    // releases from the decision event alone. A *live* hold carries its original
    // request solely in this queue entry (`held_request`, never emitted on the
    // wire), so removing it here would leave `handle_live_approval_decision` with
    // nothing to look up: it would return early and an approved exec/call would
    // never spawn while a denied one would never emit its terminal rejection
    // (issue #306). Leave live holds queued for the handler's own
    // remove-then-resume (and the expiry sweep as a backstop).
    if pending.held_request.is_none() {
        queue.remove(request_id);
        queue.save(paths)?;
    }

    Ok(ApprovalDecisionRecord {
        decision: content,
        room_id: pending.room_id,
    })
}

/// Burn an approval **decision** nonce through the sync router's own shared
/// replay cache, returning whether the live release may proceed (issue #306).
///
/// Defense-in-depth on top of the queue-removal exactly-once guarantee: a
/// captured valid decision re-delivered after the first release is dropped here.
/// The burn must go through the **router's single** cache instance (passed down
/// from [`crate::sync::run_matrix_sync`]) — loading a second `ReplayCache` would
/// be silently clobbered the next time the router persists its in-memory copy
/// (whole-file overwrite). When no router is attached (the cache failed to load,
/// so no events were routed at all) the decision handler is never reached, but
/// this still fails open to `true`: queue-removal-before-spawn is the primary
/// exactly-once guard and `verification_failure` already enforced expiry
/// cache-independently.
fn burn_decision_nonce(
    router: Option<&Arc<Mutex<EventRouter>>>,
    decision: &ApprovalDecision,
) -> bool {
    let (Some(nonce), Some(expires_at)) =
        (decision.nonce.as_deref(), decision.expires_at.as_deref())
    else {
        // `verification_failure` already requires both; defensive fail-closed.
        return false;
    };
    match router {
        Some(router) => {
            let mut guard = router.lock().unwrap_or_else(|e| e.into_inner());
            guard.admit_decision_nonce(nonce, expires_at)
        }
        None => true,
    }
}

/// Consume a live `com.mxagent.approval.decision.v1` for a held `exec`/`call`
/// hold and release, deny, or ignore it (issue #306).
///
/// This is the receive-side consumer the live path was missing: the scheduler
/// already releases held *tasks*, but held *live* requests had no handler. It
/// honours a decision only with the same rigor as the scheduler's
/// [`read_verified_approval_decisions`] — sender-verified, Ed25519-signed by a
/// **locally-trusted** key, non-replayed, and unexpired — then, on approval,
/// re-runs the *full* authorize pipeline (signature → trust → deny-by-default
/// policy → verified-device gate) against the recovered original request before
/// spawning. Matrix room membership is never execution permission.
///
/// Fail-closed throughout: a missing/legacy hold, an unavailable room, a load
/// error, a verification failure, a replayed decision, or a re-authorize denial
/// all leave the hold queued or drop it **without running**. Logs carry only
/// non-sensitive metadata (`sender`, `request_id`, `reason`) — never the held
/// request content.
pub(crate) async fn handle_live_approval_decision(
    client: &Client,
    paths: &SessionPaths,
    router: Option<&Arc<Mutex<EventRouter>>>,
    meta: &EventMeta,
    decision: &ApprovalDecision,
) {
    // 1. Match a live hold by request_id. A task/legacy hold (held_request ==
    //    None) is the scheduler's to release — do nothing here so the two paths
    //    never double-fire on one decision.
    let pending = match ApprovalQueue::load(paths) {
        Ok(queue) => queue.get(&decision.request_id).cloned(),
        Err(e) => {
            tracing::warn!(error = %e, request_id = %decision.request_id, "could not load approval queue for live decision");
            return;
        }
    };
    let Some(pending) = pending else {
        return;
    };
    let Some(held) = pending.held_request.clone() else {
        return;
    };

    // 2. Resolve the room the decision arrived in.
    let room_id = match matrix_sdk::ruma::RoomId::parse(&meta.room_id) {
        Ok(id) => id,
        Err(e) => {
            tracing::warn!(error = %e, room = %meta.room_id, "invalid room id in routed approval decision");
            return;
        }
    };
    let Some(room) = client.get_room(&room_id) else {
        tracing::warn!(room = %meta.room_id, "room for routed approval decision is unavailable");
        return;
    };

    // 3. Resolve verification inputs, identical to the scheduler's anchors: the
    //    local user, room-published verifying keys, the local trust store, the
    //    room's approver allowlist, and "now".
    let local_user = client.user_id().map(|u| u.to_string()).unwrap_or_default();
    let agents = match crate::agent::read_all_agent_states(&room).await {
        Ok(agents) => agents,
        Err(e) => {
            tracing::warn!(error = %e, room = %meta.room_id, "could not read agent states for approval decision");
            return;
        }
    };
    let mut verifying_keys: BTreeMap<String, VerifyingKey> = BTreeMap::new();
    for agent in &agents {
        if agent.signing_key_id.is_empty() {
            continue;
        }
        if let Ok(key) = crate::call::verifying_key_from_agent_state(agent) {
            verifying_keys.insert(agent.signing_key_id.clone(), key);
        }
    }
    let trust = TrustStore::load(paths).unwrap_or_default();
    let policy = Policy::default_path()
        .and_then(|path| Policy::load(path).ok())
        .unwrap_or_default();
    let approvers: BTreeSet<String> = policy
        .rooms
        .get(&meta.room_id)
        .map(|r| r.approvers.iter().cloned().collect())
        .unwrap_or_default();
    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default();
    let verification = DecisionVerification {
        local_user: &local_user,
        approvers: &approvers,
        verifying_keys: &verifying_keys,
        trust: &trust,
        now_unix,
    };

    // 4. Verify the decision with scheduler parity. The `sender` is the top-level
    //    event sender (never the attacker-controlled content). Any failure leaves
    //    the hold queued — fail-closed.
    if let Some(reason) = verification_failure(decision, &meta.sender, &verification) {
        tracing::warn!(
            sender = %meta.sender,
            request_id = %decision.request_id,
            reason,
            "rejecting unverified live approval decision"
        );
        return;
    }

    // 5. Burn the decision nonce (defense-in-depth) through the router's shared
    //    cache. A replayed decision is dropped before any release.
    if !burn_decision_nonce(router, decision) {
        tracing::warn!(
            request_id = %decision.request_id,
            "live approval decision nonce already seen; not releasing"
        );
        return;
    }

    // 6. Remove-then-resume so a redelivered decision finds no entry (exactly
    //    once). The hold leaves the queue here for both deny and approve; the
    //    sync loop only advances its batch token after this returns, so a crash
    //    mid-handle re-reads the decision and the still-queued entry releases
    //    exactly once.
    let mut queue = ApprovalQueue::load(paths).unwrap_or_default();
    queue.remove(&decision.request_id);
    if let Err(e) = queue.save(paths) {
        tracing::warn!(error = %e, request_id = %decision.request_id, "could not persist approval queue after live decision");
    }

    // 7. Deny (or any non-"approved"): emit the terminal rejection and audit
    //    denied-while-held; never run.
    if !decision_permits_spawn(decision) {
        match held {
            HeldRequest::Exec(request) => {
                crate::exec::deny_held_exec(&room, paths, &meta.room_id, &request).await
            }
            HeldRequest::Call(request) => {
                crate::call::deny_held_call(&room, paths, &meta.room_id, &request).await
            }
        }
        return;
    }

    // 8. Approved: re-run the full authorize pipeline against the recovered
    //    request and spawn it (or emit a terminal rejection if policy/trust now
    //    deny it). The hold is already removed → fail-closed, never re-held.
    match held {
        HeldRequest::Exec(request) => {
            crate::exec::release_held_exec(client, paths, &room, &meta.room_id, request).await
        }
        HeldRequest::Call(request) => {
            crate::call::release_held_call(paths, &room, &meta.room_id, request).await
        }
    }
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

    // --- call disposition (issue #263) --------------------------------------

    fn call_request() -> CallRequest {
        CallRequest {
            invocation_id: "inv_01HZ".to_string(),
            request_id: "req_01HZ".to_string(),
            tool: "deploy".to_string(),
            // A secret-like arg value to prove it never reaches the emitted
            // ApprovalRequest (the call surface's no-leak posture).
            args: serde_json::json!({ "secret_key": "should_not_appear_in_approval" }),
            created_at: "2026-06-02T12:00:00Z".to_string(),
            expires_at: "2026-06-02T12:05:00Z".to_string(),
            nonce: "base64-nonce".to_string(),
            signature: Signature {
                alg: "ed25519".to_string(),
                key_id: "mxagent-ed25519:abc".to_string(),
                sig: "c2ln".to_string(),
            },
            requesting_agent: Some("claude-local".to_string()),
            target_agent: Some("developer-pi".to_string()),
            extra: Default::default(),
        }
    }

    #[test]
    fn call_disposition_holds_when_approval_required() {
        // Acceptance (issue #263): an approval-required named call must not be
        // runnable immediately — `executable()` is the seam that proves the tool
        // runner is never reached while the call awaits approval.
        let disposition = disposition_for_call(call_request(), &allowance(true));
        assert!(disposition.requires_approval());
        assert!(
            disposition.executable().is_none(),
            "call must not be runnable while it awaits approval"
        );
        match disposition {
            CallDisposition::RequiresApproval { approval, request } => {
                assert_eq!(approval.request_id, "req_01HZ");
                assert_eq!(approval.invocation_id, "inv_01HZ");
                assert_eq!(approval.expires_at, "2026-06-02T12:05:00Z");
                assert_eq!(request.invocation_id, "inv_01HZ");
            }
            CallDisposition::Execute(_) => panic!("expected approval to be required"),
        }
    }

    #[test]
    fn call_disposition_permits_immediate_run_without_flag() {
        // Regression: with requires_approval = false a call still runs immediately
        // (no behaviour change for ordinary named calls).
        let disposition = disposition_for_call(call_request(), &allowance(false));
        assert!(!disposition.requires_approval());
        assert_eq!(disposition.executable().unwrap().invocation_id, "inv_01HZ");
    }

    #[test]
    fn call_approval_request_summary_and_parties_match_request() {
        let approval = approval_request_for_call(&call_request(), &allowance(true));
        assert_eq!(approval.summary, "Call tool deploy");
        assert_eq!(approval.requester, "claude-local");
        assert_eq!(approval.target, "developer-pi");
        assert_eq!(approval.expires_at, "2026-06-02T12:05:00Z");
        // No-leak: the call's args must never appear in the emitted/queued request.
        let json = serde_json::to_string(&approval).unwrap();
        assert!(
            !json.contains("should_not_appear_in_approval"),
            "call args must not leak into the approval request: {json}"
        );
    }

    #[test]
    fn call_approval_request_parties_total_when_unset() {
        // The builder must stay total even though the live handler only reaches
        // it with both parties present.
        let mut request = call_request();
        request.requesting_agent = None;
        request.target_agent = None;
        let approval = approval_request_for_call(&request, &allowance(true));
        assert_eq!(approval.requester, "");
        assert_eq!(approval.target, "");
    }

    #[test]
    fn held_call_approval_survives_save_and_load() {
        // Acceptance (issue #263): a held call's PendingApproval is enqueued,
        // durable, and 0600 — operator-visible exactly like an exec hold.
        let dir = tmp_dir("call-hold");
        let paths = paths_in(&dir);

        let disposition = disposition_for_call(call_request(), &allowance(true));
        let CallDisposition::RequiresApproval { approval, .. } = disposition else {
            panic!("expected approval to be required");
        };
        let mut queue = ApprovalQueue::default();
        queue.enqueue(PendingApproval {
            room_id: "!abc:matrix.org".to_string(),
            request: approval,
            held_request: None,
        });
        queue.save(&paths).unwrap();

        let reloaded = ApprovalQueue::load(&paths).unwrap();
        assert_eq!(reloaded.pending().len(), 1);
        assert_eq!(reloaded.get("req_01HZ").unwrap().room_id, "!abc:matrix.org");

        let mode = fs::metadata(approval_queue_file(&paths))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0, "queue file must be 0600");

        let _ = fs::remove_dir_all(&dir);
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
            held_request: None,
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
            held_request: None,
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
            held_request: None,
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
            held_request: None,
        });
        queue.enqueue(PendingApproval {
            room_id: "!two:matrix.org".to_string(),
            request: approval_request_for(&b, &allowance(true)),
            held_request: None,
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

    // --- held-request persistence/recovery (issue #306) ---------------------

    #[test]
    fn held_request_round_trips_for_both_surfaces() {
        // The original signed request is recoverable from a HeldRequest for both
        // live surfaces, so an approving decision can re-authorize and spawn it.
        let exec = HeldRequest::Exec(exec_request());
        let back: HeldRequest =
            serde_json::from_str(&serde_json::to_string(&exec).unwrap()).unwrap();
        assert_eq!(back, exec);
        match back {
            HeldRequest::Exec(req) => {
                assert_eq!(req.command, vec!["npm".to_string(), "test".to_string()])
            }
            HeldRequest::Call(_) => panic!("expected exec variant"),
        }

        let call = HeldRequest::Call(call_request());
        let back: HeldRequest =
            serde_json::from_str(&serde_json::to_string(&call).unwrap()).unwrap();
        assert_eq!(back, call);
    }

    #[test]
    fn pending_approval_recovers_held_request_from_queue() {
        // Persistence/recovery: a held exec recovers the *exact* original signed
        // request from the on-disk queue (0600), so release re-authorizes the
        // real request rather than the lossy ApprovalRequest summary.
        let dir = tmp_dir("held-recover");
        let paths = paths_in(&dir);
        let original = exec_request();
        let mut queue = ApprovalQueue::default();
        queue.enqueue(PendingApproval {
            room_id: "!abc:matrix.org".to_string(),
            request: approval_request_for(&original, &allowance(true)),
            held_request: Some(HeldRequest::Exec(original.clone())),
        });
        queue.save(&paths).unwrap();

        let reloaded = ApprovalQueue::load(&paths).unwrap();
        let pending = reloaded.get("req_01HZ").expect("queued");
        match &pending.held_request {
            Some(HeldRequest::Exec(req)) => assert_eq!(req, &original),
            other => panic!("expected a held exec, got {other:?}"),
        }
        let mode = fs::metadata(approval_queue_file(&paths))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0, "queue file must be 0600");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn inspection_apis_redact_held_request_while_queue_keeps_it() {
        // The READ surface (issue #306) must satisfy BOTH contracts the live
        // suite pins on `list_pending_approvals`: the hold's secret payload must
        // not serialize (`live_named_call_requires_approval_holds_and_enqueues`),
        // yet `held_request` must remain `Some` so a caller sees a live-resume
        // hold exists (`live_{exec,call}_held_approval_approve_releases_and_runs`).
        // So list/get REDACT — keep the variant, blank the secret — rather than
        // drop. This is the unit-level guard for those live-only tests: the
        // pre-merge gates run `cargo test`, not the #[ignore]d live suite, so
        // either regression (leak, or held_request going None) must be catchable
        // without a homeserver.
        let dir = tmp_dir("held-redact");
        let paths = paths_in(&dir);
        let call = call_request(); // args carry "should_not_appear_in_approval"
        let mut queue = ApprovalQueue::default();
        queue.enqueue(PendingApproval {
            room_id: "!abc:matrix.org".to_string(),
            request: approval_request_for(&exec_request(), &allowance(true)),
            held_request: Some(HeldRequest::Call(call)),
        });
        queue.save(&paths).unwrap();

        // list: held_request still present (resume signal), secret arg gone.
        let listed = list_pending_approvals(&paths, None).unwrap();
        assert_eq!(listed.len(), 1);
        assert!(
            listed[0].held_request.is_some(),
            "list must keep held_request present so the resume signal survives"
        );
        match &listed[0].held_request {
            Some(HeldRequest::Call(req)) => assert_eq!(
                req.args,
                serde_json::Value::Null,
                "the held call's args must be redacted on the inspection surface"
            ),
            other => panic!("expected a redacted held call, got {other:?}"),
        }
        let listed_json = serde_json::to_string(&listed).unwrap();
        assert!(
            !listed_json.contains("should_not_appear_in_approval"),
            "held args leaked through list_pending_approvals: {listed_json}"
        );

        // get: same redaction on the single-fetch surface.
        let got = get_pending_approval(&paths, "req_01HZ")
            .unwrap()
            .expect("queued");
        assert!(
            got.held_request.is_some(),
            "get must keep held_request present"
        );
        let got_json = serde_json::to_string(&got).unwrap();
        assert!(
            !got_json.contains("should_not_appear_in_approval"),
            "held args leaked through get_pending_approval: {got_json}"
        );

        // Resume path is unaffected: the raw queue still recovers the full hold.
        let reloaded = ApprovalQueue::load(&paths).unwrap();
        match &reloaded.get("req_01HZ").expect("queued").held_request {
            Some(HeldRequest::Call(req)) => {
                assert_eq!(req.args["secret_key"], "should_not_appear_in_approval")
            }
            other => panic!("queue must retain the held call for resume, got {other:?}"),
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn pending_approval_loads_legacy_queue_without_held_request() {
        // Forward/backward compatibility: a queue written by an older daemon (no
        // `held_request` field) still loads; the field defaults to None, which
        // the live decision handler ignores (task/legacy holds are not resumed).
        let json = r#"{"pending":[{"room_id":"!abc:matrix.org","request":{
            "request_id":"req_old","invocation_id":"inv_old","requester":"a",
            "target":"b","summary":"s","risk":"medium",
            "expires_at":"2026-06-02T12:05:00Z"}}]}"#;
        let queue: ApprovalQueue = serde_json::from_str(json).unwrap();
        let pending = queue.get("req_old").expect("legacy entry loads");
        assert!(
            pending.held_request.is_none(),
            "a legacy hold carries no live-resume material"
        );
    }

    #[test]
    fn held_request_never_leaks_into_emitted_approval_request() {
        // No-leak: the emitted ApprovalRequest carries no structured
        // command/env (exec) fields and no `held_request`, even though the queue
        // persists the full signed request at rest (0600).
        let approval = approval_request_for(&exec_request(), &allowance(true));
        let json = serde_json::to_string(&approval).unwrap();
        assert!(!json.contains("held_request"), "got {json}");
        assert!(!json.contains("\"command\""), "got {json}");
        assert!(!json.contains("\"env\""), "got {json}");
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

    // --- verification_failure tests (issues #264, #309) ---------------------

    fn vf_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[
            0x3b, 0x6a, 0x27, 0xbc, 0xce, 0xb6, 0xa4, 0x2d, 0x62, 0xa3, 0xa8, 0xd0, 0x2a, 0x6f,
            0x0d, 0x73, 0x65, 0x32, 0x15, 0x77, 0x1d, 0xe2, 0x43, 0xa6, 0x3a, 0xc0, 0x48, 0xa1,
            0x8b, 0x59, 0xda, 0x29,
        ])
    }

    const VF_KEY_ID: &str = "mxagent-ed25519:vf-test";
    const VF_LOCAL_USER: &str = "@daemon:server";
    const VF_EXPIRES_AT: &str = "2026-06-10T13:00:00Z";

    fn vf_keys() -> BTreeMap<String, VerifyingKey> {
        let mut keys = BTreeMap::new();
        keys.insert(VF_KEY_ID.to_string(), vf_signing_key().verifying_key());
        keys
    }

    /// A trust store that trusts `VF_KEY_ID` (the daemon's own key), so the new
    /// trust-store anchor (issue #309) passes by default.
    fn vf_trust() -> TrustStore {
        let mut trust = TrustStore::default();
        trust.approve("vf-agent", VF_KEY_ID, None, None, None);
        trust
    }

    fn signed_vf_decision() -> ApprovalDecision {
        let mut d = ApprovalDecision {
            request_id: "approval:task-a".to_string(),
            decision: "approved".to_string(),
            approved_by: VF_LOCAL_USER.to_string(),
            created_at: "2026-06-10T12:00:00Z".to_string(),
            nonce: Some("nonce-vf-test".to_string()),
            expires_at: Some(VF_EXPIRES_AT.to_string()),
            signature: None,
            extra: Default::default(),
        };
        sign_approval_decision(&vf_signing_key(), VF_KEY_ID, &mut d).unwrap();
        d
    }

    /// Owned holders for a [`DecisionVerification`] context so a test can borrow
    /// a context from them. Defaults trust `VF_KEY_ID`, configure no extra
    /// approvers, and set `now_unix = 0` (long before `VF_EXPIRES_AT`).
    struct VfFixture {
        approvers: BTreeSet<String>,
        keys: BTreeMap<String, VerifyingKey>,
        trust: TrustStore,
        now_unix: i64,
    }

    impl VfFixture {
        fn new() -> Self {
            Self {
                approvers: BTreeSet::new(),
                keys: vf_keys(),
                trust: vf_trust(),
                now_unix: 0,
            }
        }

        fn ctx(&self) -> DecisionVerification<'_> {
            DecisionVerification {
                local_user: VF_LOCAL_USER,
                approvers: &self.approvers,
                verifying_keys: &self.keys,
                trust: &self.trust,
                now_unix: self.now_unix,
            }
        }
    }

    fn vf_expiry_unix() -> i64 {
        crate::replay::parse_rfc3339_to_unix(VF_EXPIRES_AT).expect("VF_EXPIRES_AT parses")
    }

    #[test]
    fn verification_failure_passes_valid_signed_decision() {
        // Positive path: a properly signed decision from the daemon's own user,
        // a trusted key, and a fresh deadline must pass all checks (None).
        let fx = VfFixture::new();
        assert_eq!(
            verification_failure(&signed_vf_decision(), VF_LOCAL_USER, &fx.ctx()),
            None,
            "a valid signed decision from the daemon itself must pass all checks"
        );
    }

    #[test]
    fn verification_failure_rejects_empty_sender() {
        let fx = VfFixture::new();
        assert_eq!(
            verification_failure(&signed_vf_decision(), "", &fx.ctx()),
            Some("untrusted_sender")
        );
    }

    #[test]
    fn verification_failure_rejects_wrong_sender_room_member_cannot_approve() {
        // Security regression #264: room membership alone must not satisfy the
        // approval gate. A room member who is not the host daemon cannot release
        // a held task regardless of what they put in the event content.
        let fx = VfFixture::new();
        assert_eq!(
            verification_failure(&signed_vf_decision(), "@attacker:server", &fx.ctx()),
            Some("untrusted_sender"),
            "room membership alone must not satisfy the approval gate"
        );
    }

    #[test]
    fn verification_failure_allows_configured_approver() {
        // Issue #309: a non-daemon sender in the room's `approvers` allowlist,
        // signing with a trusted key, may release a task.
        let mut fx = VfFixture::new();
        fx.approvers.insert("@approver:server".to_string());
        assert_eq!(
            verification_failure(&signed_vf_decision(), "@approver:server", &fx.ctx()),
            None,
            "a configured approver with a trusted key must be authorized"
        );
    }

    #[test]
    fn verification_failure_rejects_stranger_not_in_approvers() {
        // Issue #309: a sender that is neither the daemon nor in the allowlist is
        // rejected even when the (populated) allowlist exists.
        let mut fx = VfFixture::new();
        fx.approvers.insert("@approver:server".to_string());
        assert_eq!(
            verification_failure(&signed_vf_decision(), "@stranger:server", &fx.ctx()),
            Some("untrusted_sender")
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
            expires_at: Some(VF_EXPIRES_AT.to_string()),
            signature: None,
            extra: Default::default(),
        };
        let fx = VfFixture::new();
        assert_eq!(
            verification_failure(&unsigned, VF_LOCAL_USER, &fx.ctx()),
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
        let fx = VfFixture::new();
        assert_eq!(
            verification_failure(&d, VF_LOCAL_USER, &fx.ctx()),
            Some("unresolved_key")
        );
    }

    #[test]
    fn verification_failure_rejects_untrusted_key() {
        // Issue #309 headline: a key that resolves in the room-published
        // verifying-keys map but is absent from the local trust store can never
        // release a held task, even with a valid signature and the correct
        // sender. This is the room-state-is-not-trust anchor.
        let mut fx = VfFixture::new();
        fx.trust = TrustStore::default(); // key is published but not trusted
        assert_eq!(
            verification_failure(&signed_vf_decision(), VF_LOCAL_USER, &fx.ctx()),
            Some("untrusted_key"),
            "a room-published key that is not locally trusted must be rejected"
        );
    }

    #[test]
    fn verification_failure_rejects_revoked_key() {
        // A key the operator explicitly revoked must also be rejected.
        let mut fx = VfFixture::new();
        fx.trust.revoke("vf-agent", VF_KEY_ID);
        assert_eq!(
            verification_failure(&signed_vf_decision(), VF_LOCAL_USER, &fx.ctx()),
            Some("untrusted_key")
        );
    }

    #[test]
    fn verification_failure_rejects_approver_with_untrusted_key() {
        // "Necessary-not-sufficient" (issue #309): being in the `approvers`
        // allowlist grants identity authorization but never overrides the
        // trust-store anchor. An allowlisted sender whose signing key is absent
        // from the local trust store must still be rejected with `untrusted_key`.
        let mut fx = VfFixture::new();
        fx.approvers.insert("@approver:server".to_string());
        fx.trust = TrustStore::default(); // key published in room state, not locally trusted
        assert_eq!(
            verification_failure(&signed_vf_decision(), "@approver:server", &fx.ctx()),
            Some("untrusted_key"),
            "allowlisted approver with a room-published but locally untrusted key must be rejected"
        );
    }

    #[test]
    fn verification_failure_rejects_tampered_decision_field() {
        // Flipping the decision from "approved" to "denied" after signing must
        // invalidate the signature so the event is dropped.
        let mut d = signed_vf_decision();
        d.decision = "denied".to_string();
        let fx = VfFixture::new();
        assert_eq!(
            verification_failure(&d, VF_LOCAL_USER, &fx.ctx()),
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
        let fx = VfFixture::new();
        assert_eq!(
            verification_failure(&d, VF_LOCAL_USER, &fx.ctx()),
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
            expires_at: Some(VF_EXPIRES_AT.to_string()),
            signature: None,
            extra: Default::default(),
        };
        sign_approval_decision(&vf_signing_key(), VF_KEY_ID, &mut d).unwrap();
        let fx = VfFixture::new();
        assert_eq!(
            verification_failure(&d, VF_LOCAL_USER, &fx.ctx()),
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
        let fx = VfFixture::new();
        assert_eq!(
            verification_failure(&d, VF_LOCAL_USER, &fx.ctx()),
            Some("missing_replay_material"),
            "a decision without expires_at must not release a held task"
        );
    }

    #[test]
    fn verification_failure_rejects_expired_decision() {
        // Issue #309: the cache-less expiry proof. A trusted, validly-signed
        // decision whose `expires_at <= now_unix` is rejected at read time,
        // independent of any replay cache.
        let mut fx = VfFixture::new();
        fx.now_unix = vf_expiry_unix() + 100; // past the deadline
        assert_eq!(
            verification_failure(&signed_vf_decision(), VF_LOCAL_USER, &fx.ctx()),
            Some("decision_expired")
        );

        // Boundary: `expires_at == now_unix` counts as expired (`<=`).
        let mut boundary = VfFixture::new();
        boundary.now_unix = vf_expiry_unix();
        assert_eq!(
            verification_failure(&signed_vf_decision(), VF_LOCAL_USER, &boundary.ctx()),
            Some("decision_expired"),
            "a stamp equal to now_unix is expired"
        );
    }

    #[test]
    fn verification_failure_rejects_malformed_expiry() {
        // Issue #309: a daemon-signed decision with an unparseable `expires_at`
        // is corrupt/tampered, so fail CLOSED (distinct from the request-side
        // fail-open).
        let mut d = ApprovalDecision {
            request_id: "approval:task-a".to_string(),
            decision: "approved".to_string(),
            approved_by: VF_LOCAL_USER.to_string(),
            created_at: "2026-06-10T12:00:00Z".to_string(),
            nonce: Some("nonce-vf-test".to_string()),
            expires_at: Some("garbage".to_string()),
            signature: None,
            extra: Default::default(),
        };
        sign_approval_decision(&vf_signing_key(), VF_KEY_ID, &mut d).unwrap();
        let fx = VfFixture::new();
        assert_eq!(
            verification_failure(&d, VF_LOCAL_USER, &fx.ctx()),
            Some("malformed_expiry")
        );
    }

    #[test]
    fn verification_failure_rejects_empty_verifying_keys_map() {
        // The host daemon has no record of the signing key: must reject even
        // if the signature is otherwise valid.
        let mut fx = VfFixture::new();
        fx.keys = BTreeMap::new();
        assert_eq!(
            verification_failure(&signed_vf_decision(), VF_LOCAL_USER, &fx.ctx()),
            Some("unresolved_key"),
            "a decision whose key_id is not locally known must be rejected"
        );
    }

    #[test]
    fn verification_failure_approved_by_field_does_not_gate_auth() {
        // Issue #309 / --by flag: `approved_by` in the decision content is
        // display-only metadata, not an authentication input. The auth inputs
        // are the Matrix event sender (top-level event header) and the
        // Ed25519 signature from a locally-trusted key. A decision whose
        // `approved_by` field differs from the sender must still pass when the
        // sender is authorized and the signature is valid.
        //
        // Note: because `approved_by` is bound by the signature, changing it
        // *post-signing* would break verification (tested separately in
        // signing.rs's `tampered_approval_decision_fails_verification`). This
        // test proves the field's value does not influence the sender/trust
        // authorization checks — the daemon signs it as a record, not as an
        // auth gate.
        let mut d = ApprovalDecision {
            request_id: "approval:task-a".to_string(),
            decision: "approved".to_string(),
            approved_by: "@custom-display-label:server".to_string(), // != VF_LOCAL_USER
            created_at: "2026-06-10T12:00:00Z".to_string(),
            nonce: Some("nonce-vf-test".to_string()),
            expires_at: Some(VF_EXPIRES_AT.to_string()),
            signature: None,
            extra: Default::default(),
        };
        sign_approval_decision(&vf_signing_key(), VF_KEY_ID, &mut d).unwrap();
        let fx = VfFixture::new();
        assert_eq!(
            verification_failure(&d, VF_LOCAL_USER, &fx.ctx()),
            None,
            "approved_by in content is display-only and must not affect the auth check"
        );
    }

    #[test]
    fn verification_failure_daemon_remains_authorized_when_approvers_configured() {
        // Issue #309 union semantics: the authorized sender set is
        // `{local_user} ∪ approvers`. Adding external approvers must never
        // revoke the daemon's own capability to release a held task — the host
        // daemon is always a member of the authorized set.
        let mut fx = VfFixture::new();
        fx.approvers.insert("@external-approver:server".to_string());
        assert_eq!(
            verification_failure(&signed_vf_decision(), VF_LOCAL_USER, &fx.ctx()),
            None,
            "daemon must remain authorized even when external approvers are configured"
        );
    }

    #[test]
    fn verification_failure_multiple_approvers_any_member_authorized() {
        // Issue #309: with multiple configured approvers, each member of the
        // set independently satisfies the sender check. A sender not in the
        // set (nor the daemon itself) is still rejected.
        //
        // The signed decision uses `VF_KEY_ID` which is trusted; the different
        // senders represent three agents whose Matrix accounts would be found
        // as event senders in the timeline.
        let mut fx = VfFixture::new();
        fx.approvers.insert("@alice:server".to_string());
        fx.approvers.insert("@bob:server".to_string());

        assert_eq!(
            verification_failure(&signed_vf_decision(), "@alice:server", &fx.ctx()),
            None,
            "@alice is a configured approver and must be authorized"
        );
        assert_eq!(
            verification_failure(&signed_vf_decision(), "@bob:server", &fx.ctx()),
            None,
            "@bob is a configured approver and must be authorized"
        );
        // A third party not in the set is rejected even with a non-empty list.
        assert_eq!(
            verification_failure(&signed_vf_decision(), "@charlie:server", &fx.ctx()),
            Some("untrusted_sender"),
            "@charlie is not in the approvers set and must be rejected"
        );
    }

    // --- burn_decision_nonce (issue #306) -----------------------------------

    /// Build a minimal [`ApprovalDecision`] for `burn_decision_nonce` tests.
    /// No signature is needed because `burn_decision_nonce` only reads the
    /// `nonce` and `expires_at` fields; signature verification happens in
    /// `verification_failure` before the caller reaches the burn step.
    fn burn_decision(nonce: Option<&str>, expires_at: Option<&str>) -> ApprovalDecision {
        ApprovalDecision {
            request_id: "req-burn-test".to_string(),
            decision: DECISION_APPROVED.to_string(),
            approved_by: "@daemon:server".to_string(),
            created_at: "2026-06-13T12:00:00Z".to_string(),
            nonce: nonce.map(str::to_string),
            expires_at: expires_at.map(str::to_string),
            signature: None,
            extra: Default::default(),
        }
    }

    /// A future expiry used in burn tests so the cache admission does not
    /// reject the nonce on the grounds of being expired.
    const BURN_FUTURE_EXPIRY: &str = "2099-01-01T00:00:00Z";

    /// Create an `Arc<Mutex<EventRouter>>` backed by a fresh temp data dir for
    /// `burn_decision_nonce` tests. Returns the dir so the caller can clean up.
    fn make_router_for_burn(tag: &str) -> (Arc<Mutex<EventRouter>>, PathBuf) {
        use crate::replay::ReplayCache;
        let dir = tmp_dir(&format!("burn-router-{tag}"));
        let paths = paths_in(&dir);
        let cache = ReplayCache::load(&paths).unwrap();
        (Arc::new(Mutex::new(EventRouter::new(cache))), dir)
    }

    #[test]
    fn burn_decision_nonce_missing_nonce_fails_closed() {
        // A decision without a nonce fails closed regardless of the router.
        // This is a defensive check; `verification_failure` should have already
        // rejected such a decision before `burn_decision_nonce` is called.
        let d = burn_decision(None, Some(BURN_FUTURE_EXPIRY));
        assert!(
            !burn_decision_nonce(None, &d),
            "missing nonce must fail closed without a router"
        );
        let (router, dir) = make_router_for_burn("no-nonce");
        assert!(
            !burn_decision_nonce(Some(&router), &d),
            "missing nonce must fail closed even with a router"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn burn_decision_nonce_missing_expires_at_fails_closed() {
        // A decision without `expires_at` fails closed: the cache cannot
        // enforce a lifetime bound without knowing when the nonce expires.
        let d = burn_decision(Some("nonce-no-expiry"), None);
        assert!(!burn_decision_nonce(None, &d));
        let (router, dir) = make_router_for_burn("no-expiry");
        assert!(!burn_decision_nonce(Some(&router), &d));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn burn_decision_nonce_without_router_fails_open() {
        // When no router is attached (cache failed to load at startup, so no
        // events were routed at all), the burn fails OPEN (returns true). This
        // is safe: queue-removal-before-spawn is the primary exactly-once guard
        // and `verification_failure` already enforced expiry cache-independently.
        let d = burn_decision(Some("nonce-no-router"), Some(BURN_FUTURE_EXPIRY));
        assert!(
            burn_decision_nonce(None, &d),
            "router=None must return true when nonce and expires_at are both present"
        );
    }

    #[test]
    fn burn_decision_nonce_with_router_admits_fresh_nonce() {
        // The first call for a fresh nonce must be admitted (true) so the
        // approval-decision release path proceeds.
        let (router, dir) = make_router_for_burn("admit-fresh");
        let d = burn_decision(Some("nonce-fresh-dec"), Some(BURN_FUTURE_EXPIRY));
        assert!(
            burn_decision_nonce(Some(&router), &d),
            "a fresh decision nonce must be admitted through the router's cache"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn burn_decision_nonce_with_router_rejects_replay() {
        // Defense-in-depth: a captured valid decision re-delivered after the
        // first release is blocked by the nonce cache. Even if the approval
        // queue somehow retained the entry, the replayed nonce prevents a
        // second release.
        let (router, dir) = make_router_for_burn("replay-dec");
        let d = burn_decision(Some("nonce-replay-dec"), Some(BURN_FUTURE_EXPIRY));
        assert!(
            burn_decision_nonce(Some(&router), &d),
            "first burn must succeed"
        );
        assert!(
            !burn_decision_nonce(Some(&router), &d),
            "replayed decision nonce must be rejected"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    // --- held call persistence/recovery (issue #306) -----------------------

    #[test]
    fn pending_approval_recovers_held_call_from_queue() {
        // Mirrors `pending_approval_recovers_held_request_from_queue` for the
        // call surface: a held named call recovers the exact original signed
        // request from the on-disk queue (0600) so an approving decision can
        // re-authorize and spawn it, rather than the lossy `ApprovalRequest`
        // summary (which deliberately omits `args` for the no-leak posture).
        let dir = tmp_dir("held-call-recover");
        let paths = paths_in(&dir);
        let original = call_request();
        let mut queue = ApprovalQueue::default();
        queue.enqueue(PendingApproval {
            room_id: "!abc:matrix.org".to_string(),
            request: approval_request_for_call(&original, &allowance(true)),
            held_request: Some(HeldRequest::Call(original.clone())),
        });
        queue.save(&paths).unwrap();

        let reloaded = ApprovalQueue::load(&paths).unwrap();
        let pending = reloaded.get("req_01HZ").expect("queued");
        match &pending.held_request {
            Some(HeldRequest::Call(req)) => assert_eq!(req, &original),
            other => panic!("expected a held call, got {other:?}"),
        }
        // The queue file must remain 0600 after holding a call.
        let mode = fs::metadata(approval_queue_file(&paths))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0, "queue file must be 0600");
        let _ = fs::remove_dir_all(&dir);
    }

    // --- HeldRequest serde representation (issue #306) ---------------------

    #[test]
    fn held_request_json_tags_use_lowercase_discriminants() {
        // The on-disk representation of `HeldRequest` is `{"exec": {...}}` /
        // `{"call": {...}}` (externally-tagged, lowercase variant name via
        // `rename_all = "lowercase"`). Pinning these tags ensures older daemons
        // can read queues written by newer ones — and vice versa — without a
        // silent deserialization break caused by case or naming drift.
        let exec_json = serde_json::to_string(&HeldRequest::Exec(exec_request())).unwrap();
        assert!(
            exec_json.starts_with(r#"{"exec":"#),
            "exec variant must use {{\"exec\":...}} discriminant tag; got: {exec_json}"
        );
        let call_json = serde_json::to_string(&HeldRequest::Call(call_request())).unwrap();
        assert!(
            call_json.starts_with(r#"{"call":"#),
            "call variant must use {{\"call\":...}} discriminant tag; got: {call_json}"
        );
    }

    // --- issue #306: decision_permits_spawn fail-closed cases ----------------

    #[test]
    fn decision_permits_spawn_is_case_sensitive() {
        // Fail-closed (issue #306): only the exact lowercase "approved" string
        // permits spawn. An uppercase "APPROVED" or an empty decision field must
        // both be treated as a denial — any other byte sequence is a denial.
        let uppercase = approval_decision_for("req", "APPROVED", "@a:srv", "t");
        assert!(
            !decision_permits_spawn(&uppercase),
            "uppercase APPROVED must not permit spawn (case-sensitive)"
        );
        let empty = approval_decision_for("req", "", "@a:srv", "t");
        assert!(
            !decision_permits_spawn(&empty),
            "empty decision string must not permit spawn"
        );
        let mixed = approval_decision_for("req", "Approved", "@a:srv", "t");
        assert!(
            !decision_permits_spawn(&mixed),
            "mixed-case Approved must not permit spawn"
        );
    }

    // --- issue #306: burn_decision_nonce expiry via wall clock ---------------

    #[test]
    fn burn_decision_nonce_rejects_expired_nonce_via_cache() {
        // A decision whose `expires_at` is in the past is rejected by the cache's
        // `admit` (expiry semantics), so `burn_decision_nonce` returns `false`.
        // This is a defense-in-depth layer on top of `verification_failure` which
        // checks expiry cache-independently.
        let (router, dir) = make_router_for_burn("expired-via-cache");
        let d = burn_decision(Some("nonce-expired-cache"), Some("1970-01-01T00:00:01Z"));
        assert!(
            !burn_decision_nonce(Some(&router), &d),
            "a decision with a past expires_at must fail closed through the cache"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    // --- issue #306: held request preserves full content at rest -------------

    #[test]
    fn held_exec_request_preserves_env_vars_at_rest() {
        // The `HeldRequest::Exec` must store the full signed request including
        // environment variables so the release path can re-authorize and spawn the
        // exact same invocation. The env vars live only in the at-rest (0600)
        // queue — they must never appear in the emitted, no-leak `ApprovalRequest`.
        let mut request = exec_request();
        request.env = std::collections::BTreeMap::from([
            ("MY_TOKEN".to_string(), "secret-token-value".to_string()),
            ("PATH".to_string(), "/usr/bin".to_string()),
        ]);
        let held = HeldRequest::Exec(request.clone());
        let held_json = serde_json::to_string(&held).unwrap();

        // At-rest: env vars must be present so re-authorization recovers them.
        assert!(
            held_json.contains("MY_TOKEN"),
            "env key must be preserved in HeldRequest at rest"
        );
        assert!(
            held_json.contains("secret-token-value"),
            "env value must be preserved in HeldRequest at rest"
        );

        // Emitted (no-leak): the lossy ApprovalRequest must never contain them.
        let approval = approval_request_for(&request, &allowance(true));
        let approval_json = serde_json::to_string(&approval).unwrap();
        assert!(
            !approval_json.contains("MY_TOKEN"),
            "env key must not leak into emitted ApprovalRequest: {approval_json}"
        );
        assert!(
            !approval_json.contains("secret-token-value"),
            "env value must not leak into emitted ApprovalRequest: {approval_json}"
        );
    }

    #[test]
    fn held_call_request_preserves_args_at_rest() {
        // The `HeldRequest::Call` must store the full original call request
        // including args so the release path can re-authorize and spawn the exact
        // tool invocation. The args live only in the at-rest (0600) queue — they
        // must never appear in the emitted, no-leak `ApprovalRequest`.
        let request = call_request();
        let held = HeldRequest::Call(request.clone());
        let held_json = serde_json::to_string(&held).unwrap();

        // At-rest: args must be present so re-authorization recovers them.
        assert!(
            held_json.contains("secret_key"),
            "call arg keys must be preserved in HeldRequest at rest"
        );
        assert!(
            held_json.contains("should_not_appear_in_approval"),
            "call arg values must be preserved in HeldRequest at rest"
        );

        // Emitted (no-leak): the lossy ApprovalRequest must never contain them.
        let approval = approval_request_for_call(&request, &allowance(true));
        let approval_json = serde_json::to_string(&approval).unwrap();
        assert!(
            !approval_json.contains("secret_key"),
            "call arg keys must not leak into emitted ApprovalRequest: {approval_json}"
        );
    }

    // --- issue #306: mixed task/live holds co-exist in the same queue --------

    #[test]
    fn queue_holds_task_and_live_entries_without_interference() {
        // A task-backed hold (`held_request == None`) and a live hold
        // (`held_request == Some`) can co-exist in the same queue. The live
        // decision handler uses `held_request.is_none()` as the sentinel to skip
        // task/legacy holds (those are released by the scheduler), so the two
        // release paths never double-fire on a single decision.
        let dir = tmp_dir("mixed-holds");
        let paths = paths_in(&dir);

        let mut task_req = exec_request();
        task_req.request_id = "req_task_hold".to_string();
        let mut live_req = exec_request();
        live_req.request_id = "req_live_hold".to_string();

        let mut queue = ApprovalQueue::default();
        queue.enqueue(PendingApproval {
            room_id: "!room:matrix.org".to_string(),
            request: approval_request_for(&task_req, &allowance(true)),
            held_request: None, // task/legacy sentinel: skip in live handler
        });
        queue.enqueue(PendingApproval {
            room_id: "!room:matrix.org".to_string(),
            request: approval_request_for(&live_req, &allowance(true)),
            held_request: Some(HeldRequest::Exec(live_req.clone())),
        });
        queue.save(&paths).unwrap();

        let reloaded = ApprovalQueue::load(&paths).unwrap();
        assert_eq!(
            reloaded.pending().len(),
            2,
            "both hold types must be in the queue"
        );

        let task_hold = reloaded.get("req_task_hold").expect("task hold present");
        assert!(
            task_hold.held_request.is_none(),
            "task-backed hold must carry no held_request (scheduler releases it)"
        );

        let live_hold = reloaded.get("req_live_hold").expect("live hold present");
        assert!(
            live_hold.held_request.is_some(),
            "live hold must carry the original signed request"
        );
        // Removing one hold must not affect the other.
        let mut reloaded2 = reloaded.clone();
        reloaded2.remove("req_task_hold");
        assert!(reloaded2.get("req_task_hold").is_none());
        assert!(
            reloaded2.get("req_live_hold").is_some(),
            "live hold must survive removal of task hold"
        );

        let _ = fs::remove_dir_all(&dir);
    }
}
