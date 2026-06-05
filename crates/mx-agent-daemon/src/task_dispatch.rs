//! Concrete task dispatchers that connect the orchestrator to execution paths.
//!
//! The orchestrator core ([`crate::task_orchestrator`]) performs all
//! authorization — signature/trust verification, replay protection, and
//! deny-by-default local policy — and only then calls a [`TaskDispatcher`] to
//! actually run an authorized action. This module provides the concrete
//! dispatchers for that final step:
//!
//! - [`ToolTaskDispatcher`] runs tool-backed task actions through the named-tool
//!   execution path (architecture §5.2). Named tools are the preferred,
//!   safer-by-default execution boundary over raw `exec`.
//!
//! Because authorization happens before dispatch, a dispatcher never needs to
//! re-check policy; it only executes the already-authorized action and maps the
//! outcome onto a [`TaskExecutionResult`] (success/exit code/summary) or a
//! [`TaskDispatchError`].

use mx_agent_protocol::schema::{TaskAction, TaskState};
use serde_json::Value;

use crate::task_orchestrator::{TaskDispatchError, TaskDispatcher, TaskExecutionResult};
use crate::tool_exec::{execute_tool, ToolError, ToolResult};

/// A function that runs a named tool with JSON arguments.
type ToolRunner = fn(&str, &Value) -> Result<ToolResult, ToolError>;

/// Dispatches tool-backed task actions by invoking the named tool.
///
/// For a [`TaskAction::Tool`] this runs the named tool and maps its
/// [`ToolResult`] onto a [`TaskExecutionResult`]: a nonzero tool exit code is a
/// *successful run that reports failure* (the task is finalized `failed`),
/// whereas a tool that could not be invoked at all yields a
/// [`TaskDispatchError::Failed`]. Raw `exec` actions are not this dispatcher's
/// responsibility and are rejected so the caller routes them to the exec path.
///
/// The tool runner is injectable for deterministic testing; by default it uses
/// the built-in [`execute_tool`].
pub struct ToolTaskDispatcher<F = ToolRunner> {
    run_tool: F,
}

impl Default for ToolTaskDispatcher<ToolRunner> {
    fn default() -> Self {
        Self {
            run_tool: execute_tool,
        }
    }
}

impl ToolTaskDispatcher<ToolRunner> {
    /// Build a dispatcher that runs the built-in tools via [`execute_tool`].
    pub fn new() -> Self {
        Self::default()
    }
}

impl<F> ToolTaskDispatcher<F>
where
    F: FnMut(&str, &Value) -> Result<ToolResult, ToolError>,
{
    /// Build a dispatcher with a custom tool runner (used by tests and callers
    /// that wire the Matrix-backed `call` path).
    pub fn with_runner(run_tool: F) -> Self {
        Self { run_tool }
    }
}

impl<F> TaskDispatcher for ToolTaskDispatcher<F>
where
    F: FnMut(&str, &Value) -> Result<ToolResult, ToolError>,
{
    fn dispatch(
        &mut self,
        _task: &TaskState,
        action: &TaskAction,
        _invocation_id: &str,
    ) -> Result<TaskExecutionResult, TaskDispatchError> {
        match action {
            TaskAction::Tool { tool, args, .. } => match (self.run_tool)(tool, args) {
                Ok(result) => Ok(TaskExecutionResult {
                    exit_code: Some(result.exit_code),
                    summary: result.summary,
                    artifact_mxc: None,
                }),
                Err(err) => Err(TaskDispatchError::Failed(format!(
                    "tool {tool:?} could not be invoked: {err}"
                ))),
            },
            TaskAction::Exec { .. } => Err(TaskDispatchError::Failed(
                "exec action cannot run through the tool dispatcher".to_string(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::task::{UpdateTaskOptions, STATE_PENDING};
    use crate::task_orchestrator::{
        OrchestrationOutcome, TaskOrchestrator, TaskStore, TaskStoreError,
    };
    use mx_agent_policy::Policy;
    use mx_agent_protocol::schema::{Extra, TaskState};
    use serde_json::json;

    fn tool_task(tool: &str) -> TaskState {
        TaskState {
            task_id: "task-a".to_string(),
            title: "run tests".to_string(),
            description: String::new(),
            state: STATE_PENDING.to_string(),
            assigned_to: "agent-a".to_string(),
            created_by: "@planner:server".to_string(),
            depends_on: Vec::new(),
            blocks: Vec::new(),
            invocation_id: None,
            created_at: "2026-06-02T12:00:00Z".to_string(),
            updated_at: "2026-06-02T12:00:00Z".to_string(),
            state_rev: 1,
            previous_event_id: None,
            result: None,
            action: Some(TaskAction::Tool {
                tool: tool.to_string(),
                args: json!({}),
                authorization: None,
            }),
            extra: Extra::default(),
        }
    }

    #[derive(Default)]
    struct MemoryStore {
        current_rev: u64,
        finalized_state: Option<String>,
        finalized_result: Option<Value>,
    }

    impl TaskStore for MemoryStore {
        fn claim(&mut self, options: UpdateTaskOptions) -> Result<TaskState, TaskStoreError> {
            self.current_rev = options.expected_state_rev.unwrap_or(1) + 1;
            Ok(claimed_state(options, self.current_rev))
        }
        fn finalize(&mut self, options: UpdateTaskOptions) -> Result<TaskState, TaskStoreError> {
            self.current_rev = options.expected_state_rev.unwrap_or(self.current_rev) + 1;
            self.finalized_state = options.state.clone();
            self.finalized_result = options.result.clone();
            Ok(claimed_state(options, self.current_rev))
        }
    }

    fn claimed_state(options: UpdateTaskOptions, rev: u64) -> TaskState {
        TaskState {
            task_id: options.task_id,
            title: String::new(),
            description: String::new(),
            state: options.state.unwrap_or_default(),
            assigned_to: options.assigned_to.unwrap_or_default(),
            created_by: String::new(),
            depends_on: Vec::new(),
            blocks: Vec::new(),
            invocation_id: options.invocation_id,
            created_at: String::new(),
            updated_at: String::new(),
            state_rev: rev,
            previous_event_id: None,
            result: options.result,
            action: None,
            extra: Extra::default(),
        }
    }

    fn policy() -> Policy {
        Policy::parse(
            r#"
[rooms."!room:server"]
trusted = true

[rooms."!room:server".agents."@planner:server"]
allow_tools = ["run_tests"]
"#,
        )
        .expect("policy parses")
    }

    fn run(
        task: &TaskState,
        dispatcher: &mut impl TaskDispatcher,
    ) -> (OrchestrationOutcome, MemoryStore) {
        let mut store = MemoryStore::default();
        let outcome = TaskOrchestrator::new("agent-a")
            .with_room_id("!room:server")
            .with_policy(policy())
            .process_one(task, std::slice::from_ref(task), &mut store, dispatcher);
        (outcome, store)
    }

    #[test]
    fn successful_tool_marks_task_succeeded() {
        let t = tool_task("run_tests");
        let mut dispatcher = ToolTaskDispatcher::with_runner(|name, _args| {
            assert_eq!(name, "run_tests");
            Ok(ToolResult {
                exit_code: 0,
                summary: "tests passed".to_string(),
            })
        });
        let (outcome, store) = run(&t, &mut dispatcher);
        assert!(matches!(
            outcome,
            OrchestrationOutcome::Completed { state, .. } if state == "succeeded"
        ));
        let result = store.finalized_result.unwrap();
        assert_eq!(
            result.get("status").and_then(Value::as_str),
            Some("succeeded")
        );
        assert_eq!(result.get("exit_code").and_then(Value::as_i64), Some(0));
        assert_eq!(
            result.get("summary").and_then(Value::as_str),
            Some("tests passed")
        );
    }

    #[test]
    fn failing_tool_marks_task_failed() {
        let t = tool_task("run_tests");
        let mut dispatcher = ToolTaskDispatcher::with_runner(|_name, _args| {
            Ok(ToolResult {
                exit_code: 1,
                summary: "tests failed".to_string(),
            })
        });
        let (outcome, store) = run(&t, &mut dispatcher);
        assert!(matches!(
            outcome,
            OrchestrationOutcome::Completed { state, .. } if state == "failed"
        ));
        let result = store.finalized_result.unwrap();
        assert_eq!(result.get("status").and_then(Value::as_str), Some("failed"));
        assert_eq!(
            result.get("reason").and_then(Value::as_str),
            Some("process_exit")
        );
    }

    #[test]
    fn uninvokable_tool_fails_the_task() {
        // The tool is policy-allowed, but the runner reports it cannot be
        // invoked at all; that maps to a dispatch failure (task `failed`).
        let t = tool_task("run_tests");
        let mut dispatcher = ToolTaskDispatcher::with_runner(|name, _args| {
            Err(ToolError::UnknownTool(name.to_string()))
        });
        let (outcome, store) = run(&t, &mut dispatcher);
        assert!(matches!(
            outcome,
            OrchestrationOutcome::Completed { state, .. } if state == "failed"
        ));
        let result = store.finalized_result.unwrap();
        assert_eq!(result.get("status").and_then(Value::as_str), Some("failed"));
        assert_eq!(
            result.get("reason").and_then(Value::as_str),
            Some("dispatch_failed")
        );
    }

    #[test]
    fn default_dispatcher_rejects_exec_actions() {
        let mut dispatcher = ToolTaskDispatcher::new();
        let exec = TaskAction::Exec {
            command: vec!["true".to_string()],
            cwd: "/repo".to_string(),
            env: Default::default(),
            timeout_ms: None,
            stream: false,
            authorization: None,
        };
        let task = tool_task("run_tests");
        let err = dispatcher
            .dispatch(&task, &exec, "inv-1")
            .expect_err("exec action is not a tool");
        assert!(matches!(err, TaskDispatchError::Failed(_)));
    }

    #[test]
    fn policy_denied_tool_is_not_dispatched() {
        // The tool is not allowlisted, so the orchestrator denies before dispatch
        // and the runner must never be called.
        let t = tool_task("forbidden_tool");
        let mut dispatcher = ToolTaskDispatcher::with_runner(|_name, _args| {
            panic!("policy-denied tool must not be dispatched")
        });
        let (outcome, store) = run(&t, &mut dispatcher);
        assert!(matches!(outcome, OrchestrationOutcome::Denied { .. }));
        assert_eq!(store.finalized_state.as_deref(), Some("blocked"));
    }
}
