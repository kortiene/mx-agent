//! Parameter types for daemon-mediated IPC methods (issue #201).
//!
//! For every Matrix-backed command group **except the `auth`/`trust` carve-out**
//! (architecture §10.3), the stateless CLI does not restore Matrix sessions or
//! build Matrix clients itself: the command is sent to the daemon over the local
//! Unix-socket JSON-RPC channel, and the daemon — which owns the session,
//! signing key, policy, and trust store — performs the operation. The exception
//! is `auth login` (CLI-initiated; it builds a store-backed client and creates
//! the daemon-owned crypto store in-process) plus `auth status`/`logout` and the
//! local `trust list`/`approve`/`revoke`/`fingerprint` commands, which run
//! CLI-local against the data dir; those have no method in this module. This is
//! safe only because the CLI and daemon are the same binary at the same UID. The
//! methods defined here cover the daemon-mediated groups. Most methods reuse the
//! existing option structs
//! (`CreateWorkspaceOptions`, `RegisterAgentOptions`, `ShareContextOptions`, …)
//! as their parameters; the small scalar-argument methods use the param structs
//! defined here. Sharing these types between the CLI and the daemon keeps the
//! two ends of each IPC method in lock-step.

use serde::{Deserialize, Serialize};

use crate::trust::TrustEntry;

/// Parameters for a method scoped to a single room/alias.
///
/// Used by `workspace.join`, `workspace.status`, `workspace.watch`, and
/// `trust.state`. For `workspace.join` the value may be a room alias.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoomParams {
    /// Room ID or alias to target.
    pub room: String,
}

/// Parameters for a method scoped to a room and a named agent.
///
/// Used by `agent.show` and `agent.tools`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoomAgentParams {
    /// Room ID or alias the agent is registered in.
    pub room: String,
    /// Agent identifier (state key).
    pub agent_id: String,
}

/// Parameters for a method scoped to a room and an invocation.
///
/// Used by `invocation.get`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoomInvocationParams {
    /// Room ID or alias the invocation lives in.
    pub room: String,
    /// Invocation identifier (`inv_...`).
    pub invocation_id: String,
}

/// Parameters for `trust.publish`: publish a local trust record into a room.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustPublishParams {
    /// Room ID or alias to publish the trust state into.
    pub room: String,
    /// The local trust record to publish as `com.mxagent.trust.v1` state.
    pub entry: TrustEntry,
}

/// Parameters for `approval.decide`: approve or deny a queued request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalDecideParams {
    /// Request identifier to decide.
    pub request_id: String,
    /// Decision string (`approved` or `denied`).
    pub decision: String,
    /// Decision-maker identity override; when `None` the daemon uses its own
    /// logged-in user ID.
    #[serde(default)]
    pub by: Option<String>,
}

/// Parameters for `invocation.cancel`: request cancellation of a live
/// invocation over Matrix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvocationCancelParams {
    /// Room ID or alias the invocation lives in.
    pub room: String,
    /// Invocation identifier to cancel.
    pub invocation_id: String,
    /// Human-readable cancellation reason.
    #[serde(default)]
    pub reason: Option<String>,
}

/// Parameters for `task.cancel`: cancel a task and drive its linked remote
/// invocation to `cancelled` (issue #239).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskCancelParams {
    /// Room ID or alias the task lives in.
    pub room: String,
    /// Task identifier (state key) to cancel.
    pub task_id: String,
    /// Human-readable cancellation reason.
    #[serde(default)]
    pub reason: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn params_round_trip_through_json() {
        let room = RoomParams {
            room: "!r:server".to_string(),
        };
        let back: RoomParams =
            serde_json::from_value(serde_json::to_value(&room).unwrap()).unwrap();
        assert_eq!(room, back);

        let agent = RoomAgentParams {
            room: "!r:server".to_string(),
            agent_id: "developer-pi".to_string(),
        };
        let back: RoomAgentParams =
            serde_json::from_value(serde_json::to_value(&agent).unwrap()).unwrap();
        assert_eq!(agent, back);

        let cancel = InvocationCancelParams {
            room: "!r:server".to_string(),
            invocation_id: "inv_1".to_string(),
            reason: Some("caller cancelled".to_string()),
        };
        let back: InvocationCancelParams =
            serde_json::from_value(serde_json::to_value(&cancel).unwrap()).unwrap();
        assert_eq!(cancel, back);

        let task_cancel = TaskCancelParams {
            room: "!r:server".to_string(),
            task_id: "task_1".to_string(),
            reason: Some("operator cancelled".to_string()),
        };
        let back: TaskCancelParams =
            serde_json::from_value(serde_json::to_value(&task_cancel).unwrap()).unwrap();
        assert_eq!(task_cancel, back);
    }

    #[test]
    fn task_cancel_reason_defaults_to_none() {
        let parsed: TaskCancelParams =
            serde_json::from_value(serde_json::json!({"room":"!r:server","task_id":"task_1"}))
                .unwrap();
        assert_eq!(parsed.task_id, "task_1");
        assert!(parsed.reason.is_none());
    }

    #[test]
    fn approval_decide_by_defaults_to_none() {
        let parsed: ApprovalDecideParams =
            serde_json::from_value(serde_json::json!({"request_id":"req_1","decision":"approved"}))
                .unwrap();
        assert_eq!(parsed.request_id, "req_1");
        assert_eq!(parsed.decision, "approved");
        assert!(parsed.by.is_none());
    }
}
