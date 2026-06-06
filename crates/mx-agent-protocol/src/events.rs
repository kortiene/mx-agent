//! Matrix event type constants for the mx-agent protocol.
//!
//! These constants mirror the event namespace defined in
//! `docs/architecture.md`, section 7.1. Every event type is fully versioned
//! with an explicit `.v1` suffix (see [`crate::PROTOCOL_VERSION`]).
//!
//! # Compatibility rules
//!
//! - Event type names carry an explicit schema version suffix
//!   (`com.mxagent.<name>.v1`). The semantics of a given version are frozen:
//!   never change the meaning of fields under the same version.
//! - A breaking change to an event's content schema requires a new versioned
//!   type (for example `com.mxagent.exec.request.v2`) added alongside the
//!   existing one, not an in-place edit.
//! - Additive, backward-compatible changes (new optional fields) may be made
//!   within the same version.
//! - Always reference these constants instead of hand-writing event type
//!   strings, so that typos are caught at compile time and the canonical list
//!   stays in one place.

/// Common namespace prefix shared by all mx-agent event types.
pub const NAMESPACE: &str = "com.mxagent";

/// Schema version suffix applied to every event type name.
pub const SCHEMA_VERSION_SUFFIX: &str = "v1";

/// Numeric schema version corresponding to [`SCHEMA_VERSION_SUFFIX`].
pub const SCHEMA_VERSION: u32 = 1;

/// Timeline (message) event types.
///
/// These are sent into a room's timeline as discrete messages.
pub mod timeline {
    /// Request to execute a command on a remote agent.
    pub const EXEC_REQUEST: &str = "com.mxagent.exec.request.v1";
    /// Acceptance of an exec request.
    pub const EXEC_ACCEPTED: &str = "com.mxagent.exec.accepted.v1";
    /// Rejection of an exec request.
    pub const EXEC_REJECTED: &str = "com.mxagent.exec.rejected.v1";
    /// Notification that an exec invocation has finished.
    pub const EXEC_FINISHED: &str = "com.mxagent.exec.finished.v1";
    /// Request to send stdin to a running exec invocation.
    pub const EXEC_STDIN: &str = "com.mxagent.exec.stdin.v1";
    /// Request to cancel a running exec invocation.
    pub const EXEC_CANCEL: &str = "com.mxagent.exec.cancel.v1";
    /// Confirmation that an exec invocation was cancelled.
    pub const EXEC_CANCELLED: &str = "com.mxagent.exec.cancelled.v1";
    /// Request for a named tool/RPC call.
    pub const CALL_REQUEST: &str = "com.mxagent.call.request.v1";
    /// Response to a named tool/RPC call.
    pub const CALL_RESPONSE: &str = "com.mxagent.call.response.v1";
    /// A chunk of streamed stdout/stderr output.
    pub const STREAM_CHUNK: &str = "com.mxagent.stream.chunk.v1";
    /// A streamed or uploaded artifact reference.
    pub const STREAM_ARTIFACT: &str = "com.mxagent.stream.artifact.v1";
    /// Shared execution context between agents.
    pub const CONTEXT_SHARE: &str = "com.mxagent.context.share.v1";
    /// Liveness heartbeat from an agent.
    pub const HEARTBEAT: &str = "com.mxagent.heartbeat.v1";
    /// Request for a human/agent approval decision.
    pub const APPROVAL_REQUEST: &str = "com.mxagent.approval.request.v1";
    /// An approval decision in response to an approval request.
    pub const APPROVAL_DECISION: &str = "com.mxagent.approval.decision.v1";
    /// PTY resize notification for an interactive session.
    pub const PTY_RESIZE: &str = "com.mxagent.pty.resize.v1";

    /// All timeline event types, in declaration order.
    pub const ALL: &[&str] = &[
        EXEC_REQUEST,
        EXEC_ACCEPTED,
        EXEC_REJECTED,
        EXEC_FINISHED,
        EXEC_STDIN,
        EXEC_CANCEL,
        EXEC_CANCELLED,
        CALL_REQUEST,
        CALL_RESPONSE,
        STREAM_CHUNK,
        STREAM_ARTIFACT,
        CONTEXT_SHARE,
        HEARTBEAT,
        APPROVAL_REQUEST,
        APPROVAL_DECISION,
        PTY_RESIZE,
    ];
}

/// State event types.
///
/// These are stored as room state, keyed by a state key.
pub mod state {
    /// Agent persona state.
    pub const AGENT: &str = "com.mxagent.agent.v1";
    /// Durable task (DAG node) state.
    pub const TASK: &str = "com.mxagent.task.v1";
    /// Invocation state for a running or completed remote call.
    pub const INVOCATION: &str = "com.mxagent.invocation.v1";
    /// Named tool definition state.
    pub const TOOL: &str = "com.mxagent.tool.v1";
    /// Workspace metadata state.
    pub const WORKSPACE: &str = "com.mxagent.workspace.v1";
    /// Trust relationship state.
    pub const TRUST: &str = "com.mxagent.trust.v1";

    /// All state event types, in declaration order.
    pub const ALL: &[&str] = &[AGENT, TASK, INVOCATION, TOOL, WORKSPACE, TRUST];
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_version_suffix_matches_numeric() {
        assert_eq!(SCHEMA_VERSION_SUFFIX, format!("v{SCHEMA_VERSION}"));
    }

    #[test]
    fn every_event_type_is_well_formed() {
        for ty in timeline::ALL.iter().chain(state::ALL.iter()) {
            assert!(
                ty.starts_with(&format!("{NAMESPACE}.")),
                "{ty} must start with {NAMESPACE}."
            );
            assert!(
                ty.ends_with(&format!(".{SCHEMA_VERSION_SUFFIX}")),
                "{ty} must end with .{SCHEMA_VERSION_SUFFIX}"
            );
        }
    }

    #[test]
    fn event_types_are_unique() {
        let mut all: Vec<&str> = timeline::ALL
            .iter()
            .chain(state::ALL.iter())
            .copied()
            .collect();
        let total = all.len();
        all.sort_unstable();
        all.dedup();
        assert_eq!(all.len(), total, "duplicate event type detected");
    }

    #[test]
    fn timeline_and_state_do_not_overlap() {
        for t in timeline::ALL {
            assert!(
                !state::ALL.contains(t),
                "{t} appears in both timeline and state"
            );
        }
    }

    #[test]
    fn expected_event_counts() {
        // Guards against accidental additions/removals diverging from
        // docs/architecture.md section 7.1.
        assert_eq!(timeline::ALL.len(), 16);
        assert_eq!(state::ALL.len(), 6);
    }

    #[test]
    fn canonical_values_match_architecture_doc() {
        assert_eq!(timeline::EXEC_REQUEST, "com.mxagent.exec.request.v1");
        assert_eq!(timeline::EXEC_STDIN, "com.mxagent.exec.stdin.v1");
        assert_eq!(timeline::STREAM_CHUNK, "com.mxagent.stream.chunk.v1");
        assert_eq!(timeline::PTY_RESIZE, "com.mxagent.pty.resize.v1");
        assert_eq!(state::AGENT, "com.mxagent.agent.v1");
        assert_eq!(state::TRUST, "com.mxagent.trust.v1");
    }
}
