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

use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use matrix_sdk::Room;
use mx_agent_policy::{Allowance, NetworkPolicy, Sandbox};
use mx_agent_protocol::events::timeline::APPROVAL_REQUEST;
use mx_agent_protocol::schema::{ApprovalRequest, ExecRequest};
use serde::{Deserialize, Serialize};

use crate::session::SessionPaths;
use crate::workspace::WorkspaceError;

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

#[cfg(test)]
mod tests {
    use super::*;
    use mx_agent_protocol::schema::Signature;

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
        SessionPaths {
            data_dir: dir.to_path_buf(),
            session_file: dir.join("session.json"),
            sync_token_file: dir.join("sync_token"),
        }
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
}
