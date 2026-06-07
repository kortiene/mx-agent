//! Matrix-backed task dispatchers (issue #200).
//!
//! These connect the orchestrator's [`TaskDispatcher`] seam to the *live* signed
//! Matrix `call`/`exec` transport (architecture §5, §7), so a task action runs
//! through exactly the same verify → trust → policy → runner pipeline a direct
//! CLI `call`/`exec` uses (#194/#196) rather than a separate in-process path:
//!
//! ```text
//! TaskAction::Tool -> live call.request -> call.response -> task result
//! TaskAction::Exec -> live exec.request -> stream/finished -> task result
//! ```
//!
//! Authorization is unchanged: the orchestrator core authorizes the task action
//! (signature/trust/replay + deny-by-default policy + approval) *before* calling
//! a dispatcher, and the target daemon independently re-verifies the signed
//! request before executing. A dispatcher only translates a task action into a
//! transport request, runs it, and maps the outcome onto a
//! [`TaskExecutionResult`] (exit code, non-sensitive summary, linked artifact)
//! or a [`TaskDispatchError`]. The transport runner is injectable so the mapping
//! is unit-tested without a live homeserver; the live default bridges to
//! [`crate::start_call_matrix`] / [`crate::start_exec_matrix`].

use mx_agent_protocol::schema::{TaskAction, TaskState};

use crate::call_ipc::{CallOutcome, CallStartParams, CallStartResult};
use crate::exec_ipc::{ExecFrame, ExecOutcome, ExecStartParams, ExecStartResult};
use crate::task_orchestrator::{TaskDispatchError, TaskDispatcher, TaskExecutionResult};

/// Map a live `call` outcome onto a task execution result.
///
/// A tool that ran (even with a nonzero exit code) is a successful dispatch; the
/// summary records the remote invocation id for traceability. A failure to
/// invoke or a remote rejection is a [`TaskDispatchError::Failed`] so the task is
/// finalized `failed` without a local spawn.
fn map_call_outcome(result: CallStartResult) -> Result<TaskExecutionResult, TaskDispatchError> {
    match result.outcome {
        CallOutcome::Ok { exit_code, summary } => Ok(TaskExecutionResult {
            exit_code: Some(exit_code),
            summary: format!("{summary} (remote call {})", result.invocation_id),
            artifact_mxc: None,
        }),
        CallOutcome::Error { message, .. } => Err(TaskDispatchError::Failed(format!(
            "remote call failed: {message}"
        ))),
    }
}

/// Map a live `exec` outcome onto a task execution result.
///
/// From the ordered frames this takes the terminal `Finished` frame's exit code
/// (or signal) and links the first output **artifact** (`mxc_uri`) when present.
/// A failure to invoke or a remote rejection is a [`TaskDispatchError::Failed`].
fn map_exec_outcome(result: ExecStartResult) -> Result<TaskExecutionResult, TaskDispatchError> {
    match result.outcome {
        ExecOutcome::Error { message, .. } => Err(TaskDispatchError::Failed(format!(
            "remote exec failed: {message}"
        ))),
        ExecOutcome::Ok { frames } => {
            let mut artifact_mxc: Option<String> = None;
            let mut finished = None;
            for frame in &frames {
                match frame {
                    ExecFrame::Artifact(artifact) if !artifact.mxc_uri.is_empty() => {
                        artifact_mxc.get_or_insert_with(|| artifact.mxc_uri.clone());
                    }
                    ExecFrame::Finished(finished_frame) => finished = Some(finished_frame),
                    _ => {}
                }
            }
            match finished {
                Some(finished) => {
                    let summary = match finished.exit_code {
                        Some(code) => {
                            format!(
                                "remote exec {} exited with code {code}",
                                result.invocation_id
                            )
                        }
                        None => match &finished.signal {
                            Some(signal) => format!(
                                "remote exec {} terminated by signal {signal}",
                                result.invocation_id
                            ),
                            None => format!("remote exec {} finished", result.invocation_id),
                        },
                    };
                    Ok(TaskExecutionResult {
                        exit_code: finished.exit_code,
                        summary,
                        artifact_mxc,
                    })
                }
                None => Err(TaskDispatchError::Failed(format!(
                    "remote exec {} produced no terminal frame",
                    result.invocation_id
                ))),
            }
        }
    }
}

/// Dispatches tool-backed task actions through the live Matrix `call` transport.
///
/// For a [`TaskAction::Tool`] it builds a [`CallStartParams`] targeting the
/// task's assignee, runs the injected call runner, and maps the outcome. Exec
/// actions are rejected so the caller routes them to the exec dispatcher.
pub struct MatrixCallTaskDispatcher<C> {
    room: String,
    run_call: C,
}

impl<C> MatrixCallTaskDispatcher<C>
where
    C: FnMut(CallStartParams) -> CallStartResult,
{
    /// Build a dispatcher bound to `room` that runs calls via `run_call`.
    pub fn new(room: impl Into<String>, run_call: C) -> Self {
        Self {
            room: room.into(),
            run_call,
        }
    }
}

impl<C> TaskDispatcher for MatrixCallTaskDispatcher<C>
where
    C: FnMut(CallStartParams) -> CallStartResult,
{
    fn dispatch(
        &mut self,
        task: &TaskState,
        action: &TaskAction,
        invocation_id: &str,
    ) -> Result<TaskExecutionResult, TaskDispatchError> {
        match action {
            TaskAction::Tool { tool, args, .. } => {
                // Preset the orchestrator's invocation id so the remote call runs
                // under the same id the owning task records (issue #239).
                let params = CallStartParams {
                    room: Some(self.room.clone()),
                    agent: Some(task.assigned_to.clone()),
                    tool: tool.clone(),
                    input: args.clone(),
                    invocation_id: Some(invocation_id.to_string()),
                };
                map_call_outcome((self.run_call)(params))
            }
            TaskAction::Exec { .. } => Err(TaskDispatchError::Failed(
                "exec action cannot run through the Matrix call dispatcher".to_string(),
            )),
        }
    }
}

/// Dispatches exec-backed task actions through the live Matrix `exec` transport.
///
/// For a [`TaskAction::Exec`] it builds an [`ExecStartParams`] targeting the
/// task's assignee, runs the injected exec runner, and maps the outcome
/// (including linking any output artifact). Tool actions are rejected so the
/// caller routes them to the call dispatcher.
pub struct MatrixExecTaskDispatcher<E> {
    room: String,
    run_exec: E,
}

impl<E> MatrixExecTaskDispatcher<E>
where
    E: FnMut(ExecStartParams) -> ExecStartResult,
{
    /// Build a dispatcher bound to `room` that runs execs via `run_exec`.
    pub fn new(room: impl Into<String>, run_exec: E) -> Self {
        Self {
            room: room.into(),
            run_exec,
        }
    }
}

impl<E> TaskDispatcher for MatrixExecTaskDispatcher<E>
where
    E: FnMut(ExecStartParams) -> ExecStartResult,
{
    fn dispatch(
        &mut self,
        task: &TaskState,
        action: &TaskAction,
        invocation_id: &str,
    ) -> Result<TaskExecutionResult, TaskDispatchError> {
        match action {
            TaskAction::Exec {
                command,
                cwd,
                stream,
                ..
            } => {
                // Preset the orchestrator's invocation id so the remote exec —
                // and its `com.mxagent.invocation.v1` state — run under the same
                // id the owning task records (issue #239).
                let params = ExecStartParams {
                    room: Some(self.room.clone()),
                    agent: Some(task.assigned_to.clone()),
                    command: command.clone(),
                    cwd: Some(std::path::PathBuf::from(cwd)),
                    stdin: None,
                    stream: *stream,
                    pty: false,
                    task: Some(task.task_id.clone()),
                    strict_stream: false,
                    invocation_id: Some(invocation_id.to_string()),
                };
                map_exec_outcome((self.run_exec)(params))
            }
            TaskAction::Tool { .. } => Err(TaskDispatchError::Failed(
                "tool action cannot run through the Matrix exec dispatcher".to_string(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::call_ipc::CallErrorKind;
    use crate::exec_ipc::ExecErrorKind;
    use mx_agent_protocol::schema::{ExecFinished, StreamChunk};
    use mx_agent_protocol::schema::{Extra, StreamArtifact, StreamKind};
    use serde_json::json;

    fn tool_task() -> TaskState {
        base_task(Some(TaskAction::Tool {
            tool: "run_tests".to_string(),
            args: json!({ "package": "api" }),
            authorization: None,
        }))
    }

    fn exec_task() -> TaskState {
        base_task(Some(TaskAction::Exec {
            command: vec!["cargo".to_string(), "test".to_string()],
            cwd: "/repo".to_string(),
            env: Default::default(),
            timeout_ms: Some(60_000),
            stream: true,
            authorization: None,
        }))
    }

    fn base_task(action: Option<TaskAction>) -> TaskState {
        TaskState {
            task_id: "task-a".to_string(),
            title: "t".to_string(),
            description: String::new(),
            state: "pending".to_string(),
            assigned_to: "developer-pi".to_string(),
            created_by: "@planner:server".to_string(),
            depends_on: Vec::new(),
            blocks: Vec::new(),
            invocation_id: None,
            created_at: "2026-06-04T18:00:00Z".to_string(),
            updated_at: "2026-06-04T18:00:00Z".to_string(),
            state_rev: 1,
            previous_event_id: None,
            result: None,
            action,
            extra: Extra::default(),
        }
    }

    fn finished_frame(exit_code: Option<i32>, signal: Option<&str>) -> ExecFrame {
        ExecFrame::Finished(ExecFinished {
            invocation_id: "inv_remote".to_string(),
            exit_code,
            signal: signal.map(ToString::to_string),
            duration_ms: 5,
            stdout_bytes: 0,
            stderr_bytes: 0,
            truncated: false,
            artifact_mxc: None,
            extra: Extra::default(),
        })
    }

    fn artifact_frame(mxc: &str) -> ExecFrame {
        ExecFrame::Artifact(StreamArtifact {
            invocation_id: "inv_remote".to_string(),
            stream: StreamKind::Stdout,
            name: "stdout.log".to_string(),
            mime_type: "text/plain".to_string(),
            size_bytes: 10,
            sha256: String::new(),
            mxc_uri: mxc.to_string(),
            tail_preview: String::new(),
            extra: Extra::default(),
        })
    }

    fn chunk_frame() -> ExecFrame {
        ExecFrame::Chunk(StreamChunk {
            invocation_id: "inv_remote".to_string(),
            stream: StreamKind::Stdout,
            seq: 0,
            encoding: "utf-8".to_string(),
            data: "hi".to_string(),
            eof: false,
            compressed: false,
            sha256: None,
            timestamp: "2026-06-04T18:00:00Z".to_string(),
            extra: Extra::default(),
        })
    }

    #[test]
    fn call_dispatcher_targets_assignee_and_maps_success() {
        let mut dispatcher =
            MatrixCallTaskDispatcher::new("!room:server", |params: CallStartParams| {
                // The request targets the task's assignee in the bound room.
                assert_eq!(params.room.as_deref(), Some("!room:server"));
                assert_eq!(params.agent.as_deref(), Some("developer-pi"));
                assert_eq!(params.tool, "run_tests");
                // The orchestrator's invocation id is preset so the remote call
                // runs under the same id the task records (issue #239).
                assert_eq!(params.invocation_id.as_deref(), Some("inv_orch"));
                CallStartResult {
                    invocation_id: "inv_call".to_string(),
                    request_id: "req_call".to_string(),
                    outcome: CallOutcome::Ok {
                        exit_code: 0,
                        summary: "tests passed".to_string(),
                    },
                }
            });
        let task = tool_task();
        let action = task.action.clone().unwrap();
        let result = dispatcher.dispatch(&task, &action, "inv_orch").unwrap();
        assert_eq!(result.exit_code, Some(0));
        assert!(result.summary.contains("tests passed"));
        assert!(result.summary.contains("inv_call"));
        assert!(result.is_success());
    }

    #[test]
    fn call_dispatcher_maps_remote_error_to_failure() {
        let mut dispatcher = MatrixCallTaskDispatcher::new("!room:server", |_p| CallStartResult {
            invocation_id: "inv_call".to_string(),
            request_id: "req_call".to_string(),
            outcome: CallOutcome::Error {
                kind: CallErrorKind::Remote,
                message: "policy denied tool".to_string(),
            },
        });
        let task = tool_task();
        let action = task.action.clone().unwrap();
        let err = dispatcher.dispatch(&task, &action, "inv_orch").unwrap_err();
        assert!(matches!(err, TaskDispatchError::Failed(m) if m.contains("policy denied tool")));
    }

    #[test]
    fn call_dispatcher_rejects_exec_actions() {
        let mut dispatcher = MatrixCallTaskDispatcher::new("!room:server", |_p| {
            panic!("exec action must not reach the call runner")
        });
        let task = exec_task();
        let action = task.action.clone().unwrap();
        assert!(matches!(
            dispatcher.dispatch(&task, &action, "inv_orch"),
            Err(TaskDispatchError::Failed(_))
        ));
    }

    #[test]
    fn exec_dispatcher_maps_exit_code_and_links_artifact() {
        let mut dispatcher =
            MatrixExecTaskDispatcher::new("!room:server", |params: ExecStartParams| {
                assert_eq!(params.agent.as_deref(), Some("developer-pi"));
                assert_eq!(
                    params.command,
                    vec!["cargo".to_string(), "test".to_string()]
                );
                assert_eq!(params.cwd, Some(std::path::PathBuf::from("/repo")));
                // The orchestrator's invocation id is preset so the remote exec —
                // and its invocation state — run under the unified id (issue #239).
                assert_eq!(params.invocation_id.as_deref(), Some("inv_orch"));
                ExecStartResult {
                    invocation_id: "inv_exec".to_string(),
                    request_id: "req_exec".to_string(),
                    outcome: ExecOutcome::Ok {
                        frames: vec![
                            chunk_frame(),
                            artifact_frame("mxc://server/log"),
                            finished_frame(Some(0), None),
                        ],
                    },
                }
            });
        let task = exec_task();
        let action = task.action.clone().unwrap();
        let result = dispatcher.dispatch(&task, &action, "inv_orch").unwrap();
        assert_eq!(result.exit_code, Some(0));
        assert_eq!(result.artifact_mxc.as_deref(), Some("mxc://server/log"));
        assert!(result.summary.contains("inv_exec"));
    }

    #[test]
    fn exec_dispatcher_maps_nonzero_and_signal() {
        let mut nonzero = MatrixExecTaskDispatcher::new("!room:server", |_p| ExecStartResult {
            invocation_id: "inv_exec".to_string(),
            request_id: "req_exec".to_string(),
            outcome: ExecOutcome::Ok {
                frames: vec![finished_frame(Some(2), None)],
            },
        });
        let task = exec_task();
        let action = task.action.clone().unwrap();
        let result = nonzero.dispatch(&task, &action, "inv_orch").unwrap();
        assert_eq!(result.exit_code, Some(2));
        assert!(!result.is_success());

        let mut signalled = MatrixExecTaskDispatcher::new("!room:server", |_p| ExecStartResult {
            invocation_id: "inv_exec".to_string(),
            request_id: "req_exec".to_string(),
            outcome: ExecOutcome::Ok {
                frames: vec![finished_frame(None, Some("SIGKILL"))],
            },
        });
        let result = signalled.dispatch(&task, &action, "inv_orch").unwrap();
        assert_eq!(result.exit_code, None);
        assert!(!result.is_success());
        assert!(result.summary.contains("SIGKILL"));
    }

    #[test]
    fn exec_dispatcher_maps_remote_error_and_rejects_tools() {
        let mut dispatcher = MatrixExecTaskDispatcher::new("!room:server", |_p| ExecStartResult {
            invocation_id: "inv_exec".to_string(),
            request_id: "req_exec".to_string(),
            outcome: ExecOutcome::Error {
                kind: ExecErrorKind::Remote,
                message: "remote rejected".to_string(),
            },
        });
        let task = exec_task();
        let action = task.action.clone().unwrap();
        assert!(matches!(
            dispatcher.dispatch(&task, &action, "inv_orch"),
            Err(TaskDispatchError::Failed(m)) if m.contains("remote rejected")
        ));

        // A tool action is rejected by the exec dispatcher.
        let tool = tool_task();
        let tool_action = tool.action.clone().unwrap();
        assert!(matches!(
            dispatcher.dispatch(&tool, &tool_action, "inv_orch"),
            Err(TaskDispatchError::Failed(_))
        ));
    }
}
