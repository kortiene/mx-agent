//! The mx-agent daemon.
//!
//! The daemon owns the Matrix sync loop, credentials, crypto state, policy
//! enforcement, and process supervision (see `docs/architecture.md`,
//! section 10). This is a placeholder that wires the supporting crates
//! together so the workspace builds end to end.

pub mod agent;
pub mod approval;
pub mod artifact;
pub mod audit;
pub mod call;
pub mod call_ipc;
pub mod context;
pub mod event_router;
pub mod exec;
pub mod exec_ipc;
pub mod exec_subscribers;
pub mod heartbeat;
pub mod invocation;
pub mod lifecycle;
pub mod matrix;
#[cfg(unix)]
pub mod pty;
pub mod replay;
pub mod runner;
pub mod scheduler;
pub mod scheduler_loop;
pub mod session;
pub mod signing;
pub mod stream;
pub mod sync;
pub mod task;
pub mod task_diagnostics;
pub mod task_dispatch;
pub mod task_graph;
pub mod task_orchestrator;
pub mod tool_exec;
pub mod tools;
pub mod trust;
pub mod trust_state;
pub mod watch;
pub mod workspace;

pub use agent::{
    agent_tools, agent_tools_for_session, list_agents, list_agents_for_session, register_agent,
    register_agent_for_session, show_agent, show_agent_for_session, AgentTools, ListAgentsOptions,
    RegisterAgentOptions, DEFAULT_AGENT_KIND, DEFAULT_MAX_INVOCATIONS,
};
pub use approval::{
    approval_decision_for, approval_request_for, decide_approval_for_session,
    decision_permits_spawn, disposition_for_exec, emit_approval_decision, emit_approval_request,
    get_pending_approval, list_pending_approvals, ApprovalDecisionRecord, ApprovalQueue,
    ExecDisposition, PendingApproval, DECISION_APPROVED, DECISION_DENIED,
};
pub use artifact::{
    list_stream_artifacts, prepare_artifact, retrieve_artifact, retrieve_artifact_for_session,
    upload_artifact, zstd_available, ArtifactConfig, ArtifactError, PreparedArtifact,
    RetrieveArtifactOptions, RetrievedArtifact, DEFAULT_ARTIFACT_SCAN_LIMIT,
    DEFAULT_MAX_TIMELINE_OUTPUT_BYTES, DEFAULT_TAIL_PREVIEW_BYTES,
};
pub use audit::{redact_command, AuditDecision, AuditLog, AuditRecord, AUDIT_FILE_NAME};
pub use call::{
    authorize_call_request, build_signed_call_request, build_signed_call_request_for_target,
    emit_call_response, execute_authorized_call, handle_live_call_request, rejection_response,
    send_call_request, start_call_matrix, success_response, verifying_key_from_agent_state,
    CallRejection, CallTargeting,
};
pub use call_ipc::{
    start_call_loopback, CallErrorKind, CallOutcome, CallStartParams, CallStartResult,
};
pub use context::{
    fetch_context, fetch_context_for_session, list_context_shares, list_context_shares_for_session,
    share_context, share_context_for_session, share_diff, share_diff_for_session, share_env,
    share_env_for_session, FetchContextOptions, FetchedContext, ListSharesOptions,
    ShareContextOptions, ShareDiffOptions, ShareEnvOptions, DEFAULT_ENV_INCLUDE,
    DEFAULT_FETCH_SCAN_LIMIT, DIFF_MIME_TYPE, ENV_MIME_TYPE, MAX_INLINE_BYTES,
};
pub use event_router::{
    classify as classify_event, events_from_sync_response, EventCategory, EventMeta, EventRouter,
    IncomingEvent, RouteOutcome, RoutedEvent,
};
pub use exec::{
    authorize_exec_cancel, authorize_exec_request, authorize_exec_request_with_allowance,
    build_signed_exec_cancel, build_signed_exec_request, build_signed_exec_stdin,
    emit_exec_accepted, emit_exec_cancelled, emit_exec_rejected, handle_live_exec_cancel,
    handle_live_exec_request, handle_live_exec_stdin, invocation_state_for,
    publish_invocation_state, send_exec_cancel, send_exec_request, send_exec_stdin,
    CancelRejection, ExecRejection, ExecRequestOptions,
};
pub use exec_ipc::{
    handle_exec_cancel_loopback, handle_exec_stdin_loopback, send_exec_cancel_matrix,
    send_exec_stdin_matrix, start_exec_loopback, start_exec_matrix, ExecCancelParams,
    ExecControlResult, ExecErrorKind, ExecFrame, ExecNotification, ExecOutcome, ExecStartParams,
    ExecStartResult, ExecStdinParams,
};
pub use exec_subscribers::{
    ExecSubscriberRegistry, ExecSubscription, ExecSubscriptionKey, ForwardStats, ForwardedExecEvent,
};
pub use heartbeat::{
    emit_heartbeat, HeartbeatConfig, Liveness, LivenessConfig, DEFAULT_HEARTBEAT_INTERVAL,
    DEFAULT_OFFLINE_AFTER, DEFAULT_STALE_AFTER, DEFAULT_STATE_REFRESH,
};
pub use invocation::{
    advance_invocation, advance_invocation_for_session, cancel_invocation,
    cancel_invocation_for_session, get_invocation, get_invocation_for_session, invocation_for_task,
    is_terminal, list_invocations, list_invocations_for_session, task_result_from_invocation,
    task_state_for_invocation, terminal_state_for_exit, ListInvocationsOptions,
};
pub use lifecycle::{
    run_foreground, start_background, status, stop, Paths, RunningStatus, StopOutcome,
};
pub use matrix::{
    build_client, login_password, restore_client, ClientError, ConfigError, LoginError,
    MatrixConfig,
};
pub use mx_agent_protocol::schema::{TaskAction, TaskActionAuthorization, TaskResult};
#[cfg(unix)]
pub use pty::{PtySession, PtyWinsize};
pub use replay::{ReplayCache, ReplayError, DEFAULT_CAPACITY};
pub use runner::{
    is_secret_var, kill_process_group, run, sanitize_env, terminate_process_group, RunError,
    RunOutput, RunSpec, CANCEL_SIGNAL, DEFAULT_GRACE_PERIOD,
};
pub use scheduler::{ScheduleDecision, TaskScheduler};
pub use scheduler_loop::{
    run_scheduler_loop, run_scheduler_tick, MatrixTaskStore, RoutingDispatcher,
    DEFAULT_SCHEDULER_INTERVAL,
};
pub use session::{
    auth_status, clear_session, clear_sync_token, load_session, load_sync_token, save_session,
    save_sync_token, AuthStatus, Secret, SessionPaths, StoredSession,
};
pub use signing::{
    decode_verifying_key, encode_verifying_key, key_id_for_verifying_key,
    load_or_create_signing_key, DaemonSigningKey, SigningKeyError, KEY_ALG, KEY_ID_PREFIX,
};
pub use stream::{
    capture_child_output, capture_stream, capture_stream_limited, CaptureLimiter, CaptureSummary,
    OutputCaps, StreamCaptureConfig, DEFAULT_BATCH_FLUSH_INTERVAL,
    DEFAULT_INTERACTIVE_FLUSH_INTERVAL, DEFAULT_MAX_CHUNK_BYTES,
};
pub use sync::{
    run_matrix_sync, run_matrix_sync_with_subscribers, run_sync_loop, Backoff, BackoffConfig,
    StepError, SyncHealth, SyncState,
};
pub use task::{
    can_transition, create_task, create_task_for_session, is_known_state, is_runnable, list_tasks,
    list_tasks_for_session, update_task, update_task_for_session, CreateTaskOptions,
    ListTasksOptions, UpdateTaskOptions, DEFAULT_TASK_STATE, STATE_ASSIGNED, STATE_BLOCKED,
    STATE_CANCELLED, STATE_EXECUTING, STATE_FAILED, STATE_PENDING, STATE_PROPOSED, STATE_SUCCEEDED,
    STATE_SUPERSEDED,
};
pub use task_diagnostics::{diagnose_tasks, Severity, TaskDiagnostic};
pub use task_dispatch::{
    exec_result_from_output, ExecRunRequest, ExecTaskDispatcher, ToolTaskDispatcher,
};
pub use task_graph::{GraphEdge, GraphNode, TaskGraph};
pub use task_orchestrator::{
    action_from_task, sign_task_action, task_approval_request, ApprovalDisposition,
    OrchestrationOutcome, QueueApprovalGate, TaskActionError, TaskApprovalGate, TaskDispatchError,
    TaskDispatcher, TaskExecutionResult, TaskOrchestrator, TaskStore, TaskStoreError,
};
pub use tool_exec::{execute_tool, ToolError, ToolResult, RUN_TESTS};
pub use tools::{builtin_tools, ToolRegistry};
pub use trust::{fingerprint_from_key_id, TrustEntry, TrustStatus, TrustStore};
pub use trust_state::{
    effective_trust, effective_trust_table, list_trust_states, list_trust_states_for_session,
    publish_trust_state, publish_trust_state_for_session, trust_state_from_entry, trust_state_key,
    EffectiveTrust, TrustSource,
};
pub use watch::{
    diff_tasks, watch_tasks_for_session, watch_workspace_status_for_session, TaskChange,
    WatchConfig, WatchUpdate, DEFAULT_WATCH_SYNC_TIMEOUT,
};
pub use workspace::{
    attach_workspace, attach_workspace_for_session, create_workspace, create_workspace_for_session,
    join_workspace, join_workspace_for_session, workspace_status, workspace_status_for_session,
    AttachWorkspaceOptions, CreateWorkspaceOptions, MemberSummary, WorkspaceError, WorkspaceInfo,
    WorkspaceStatus, WorkspaceVisibility,
};

use mx_agent_ipc::default_socket_name;
use mx_agent_policy::{default_decision, Decision};
use mx_agent_protocol::protocol_version;
use mx_agent_sandbox::{default_backend, Backend};

/// A snapshot of the daemon's default runtime configuration.
#[derive(Debug, Clone)]
pub struct DaemonInfo {
    /// Protocol version the daemon speaks.
    pub protocol_version: &'static str,
    /// Default IPC socket file name.
    pub socket_name: &'static str,
    /// Default policy decision (deny-by-default).
    pub default_decision: Decision,
    /// Default sandbox backend.
    pub sandbox_backend: Backend,
}

impl DaemonInfo {
    /// Build the default daemon info from the supporting crates.
    pub fn new() -> Self {
        Self {
            protocol_version: protocol_version(),
            socket_name: default_socket_name(),
            default_decision: default_decision(),
            sandbox_backend: default_backend(),
        }
    }
}

impl DaemonInfo {
    /// Emit a structured startup log describing the daemon configuration.
    ///
    /// The subscriber is installed by the hosting process (the CLI today, a
    /// dedicated daemon binary later); this method only produces the event.
    pub fn log_summary(&self) {
        tracing::info!(
            protocol_version = self.protocol_version,
            socket_name = self.socket_name,
            default_decision = ?self.default_decision,
            sandbox_backend = ?self.sandbox_backend,
            "daemon configuration"
        );
    }
}

impl Default for DaemonInfo {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn info_uses_supporting_crate_defaults() {
        let info = DaemonInfo::new();
        assert_eq!(info.protocol_version, "v1");
        assert_eq!(info.socket_name, "daemon.sock");
        assert_eq!(info.default_decision, Decision::Deny);
        assert_eq!(info.sandbox_backend, Backend::None);
    }

    #[test]
    fn log_summary_emits_a_structured_event() {
        use std::io::Write;
        use std::sync::{Arc, Mutex};
        use tracing_subscriber::fmt::MakeWriter;

        #[derive(Clone, Default)]
        struct Buffer(Arc<Mutex<Vec<u8>>>);
        impl Write for Buffer {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        impl<'a> MakeWriter<'a> for Buffer {
            type Writer = Buffer;
            fn make_writer(&'a self) -> Buffer {
                self.clone()
            }
        }

        let buffer = Buffer::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(buffer.clone())
            .with_max_level(tracing::Level::INFO)
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            DaemonInfo::new().log_summary();
        });

        let output = String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap();
        assert!(output.contains("daemon configuration"), "got: {output}");
        assert!(output.contains("protocol_version"), "got: {output}");
    }
}
