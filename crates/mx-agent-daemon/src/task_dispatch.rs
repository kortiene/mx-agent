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
//! - [`ExecTaskDispatcher`] runs raw `exec` task actions through the process
//!   runner (architecture §7.7, §13.5), mapping the exit status onto the task
//!   result and linking any output artifact.
//!
//! Because authorization happens before dispatch, a dispatcher never needs to
//! re-check policy; it only executes the already-authorized action and maps the
//! outcome onto a [`TaskExecutionResult`] (success/exit code/summary) or a
//! [`TaskDispatchError`].

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use mx_agent_protocol::schema::{TaskAction, TaskState};
use serde_json::Value;

use crate::runner::{RunError, RunOutput, RunSpec, DEFAULT_GRACE_PERIOD};
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
        _allowance: &mx_agent_policy::Allowance,
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

/// A request to run one exec-backed task action, passed to the command runner.
///
/// Carries the policy-resolved isolation settings (sandbox backend, network
/// decision, filesystem binds, env allowlist) so an auto-executed task DAG runs
/// under the same confinement the direct `exec` path applies (architecture
/// §13.5), rather than unsandboxed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecRunRequest {
    /// Command argv: program followed by arguments.
    pub command: Vec<String>,
    /// Working directory for the command.
    pub cwd: PathBuf,
    /// Explicit environment overrides (layered on the sanitized env).
    pub env: BTreeMap<String, String>,
    /// Maximum wall-clock runtime, if any.
    pub timeout: Option<Duration>,
    /// Sandbox backend to launch the command under, resolved from policy
    /// (architecture §13.5). Defaults to [`Backend::None`][mx_agent_sandbox::Backend::None].
    pub sandbox: mx_agent_sandbox::Backend,
    /// Whether the command may reach the network, resolved from policy. Only an
    /// isolating backend enforces this; defaults to
    /// [`Network::Deny`][mx_agent_sandbox::Network::Deny] (fail closed).
    pub network: mx_agent_sandbox::Network,
    /// Paths an isolating backend binds read-only into the sandbox.
    pub read_only_paths: Vec<PathBuf>,
    /// Paths an isolating backend binds writable into the sandbox.
    pub writable_paths: Vec<PathBuf>,
    /// Extra environment variable names the child may inherit beyond the
    /// built-in safe defaults, resolved from the policy's `env_allowlist`.
    pub env_allowlist: Vec<String>,
}

/// A function that runs an exec request and returns the captured outcome.
type CommandRunner = fn(&ExecRunRequest) -> Result<RunOutput, RunError>;

/// Default command runner: bridges to the async process runner.
///
/// Must be called from a blocking (non-async) context, consistent with the
/// synchronous orchestrator core. It builds a [`RunSpec`] from the request's
/// policy-resolved settings (sanitized env, restricted cwd, timeout, sandbox
/// backend, network decision, filesystem binds) and runs the command to
/// completion on a temporary current-thread runtime.
fn default_command_runner(request: &ExecRunRequest) -> Result<RunOutput, RunError> {
    let spec = RunSpec {
        command: request.command.clone(),
        cwd: request.cwd.clone(),
        env: request.env.clone(),
        env_allowlist: request.env_allowlist.clone(),
        stdin: None,
        timeout: request.timeout,
        grace_period: DEFAULT_GRACE_PERIOD,
        sandbox: request.sandbox,
        network: request.network,
        read_only_paths: request.read_only_paths.clone(),
        writable_paths: request.writable_paths.clone(),
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(RunError::Spawn)?;
    runtime.block_on(crate::runner::run(&spec))
}

/// Map a finished [`RunOutput`] onto a [`TaskExecutionResult`].
///
/// Exit code `0` is success; a nonzero code, or a process killed by a signal or
/// a timeout (no exit code), is a failure. `artifact_mxc`, when present, links
/// an uploaded output artifact into the task result. The summary is
/// non-sensitive (it never carries raw process output).
pub fn exec_result_from_output(
    output: &RunOutput,
    artifact_mxc: Option<String>,
) -> TaskExecutionResult {
    let summary = if output.timed_out {
        "exec command timed out".to_string()
    } else if let Some(code) = output.exit_code {
        format!("exec command exited with code {code}")
    } else if let Some(signal) = output.signal {
        format!("exec command terminated by signal {signal}")
    } else {
        "exec command finished".to_string()
    };
    // A process killed by a signal or a timeout has no successful exit code; map
    // it to a conventional failure code (128 + signal where known) so the task
    // is finalized `failed` rather than `succeeded`.
    let exit_code = match output.exit_code {
        Some(code) => Some(code),
        None => Some(128 + output.signal.unwrap_or(0)),
    };
    TaskExecutionResult {
        exit_code,
        summary,
        artifact_mxc,
    }
}

/// Dispatches raw `exec` task actions by running the command through the
/// process runner.
///
/// The exec action is already authorized (policy/trust/signature) before the
/// orchestrator calls this dispatcher, so it only runs the command and maps the
/// outcome: exit `0` finalizes the task `succeeded`, any other termination
/// finalizes it `failed`. A command that could not be run at all yields a
/// [`TaskDispatchError::Failed`]. Explicit cancellation is handled separately
/// through the invocation cancel path (`exec.cancelled`), which finalizes the
/// owning task `cancelled` via the invocation linkage helpers.
///
/// The command runner is injectable for deterministic testing; by default it
/// bridges to the async [`crate::runner::run`].
pub struct ExecTaskDispatcher<F = CommandRunner> {
    run_command: F,
}

impl Default for ExecTaskDispatcher<CommandRunner> {
    fn default() -> Self {
        Self {
            run_command: default_command_runner,
        }
    }
}

impl ExecTaskDispatcher<CommandRunner> {
    /// Build a dispatcher that runs commands via the process runner.
    pub fn new() -> Self {
        Self::default()
    }
}

impl<F> ExecTaskDispatcher<F>
where
    F: FnMut(&ExecRunRequest) -> Result<RunOutput, RunError>,
{
    /// Build a dispatcher with a custom command runner (used by tests).
    pub fn with_runner(run_command: F) -> Self {
        Self { run_command }
    }
}

impl<F> TaskDispatcher for ExecTaskDispatcher<F>
where
    F: FnMut(&ExecRunRequest) -> Result<RunOutput, RunError>,
{
    fn dispatch(
        &mut self,
        _task: &TaskState,
        action: &TaskAction,
        _invocation_id: &str,
        allowance: &mx_agent_policy::Allowance,
    ) -> Result<TaskExecutionResult, TaskDispatchError> {
        match action {
            TaskAction::Exec {
                command,
                cwd,
                env,
                timeout_ms,
                ..
            } => {
                // Honor the policy-resolved isolation for this task action rather
                // than running it unsandboxed (architecture §13.5). The backend
                // and network decision use the same mapping as the direct `exec`
                // path so both stay consistent and fail closed.
                let request = ExecRunRequest {
                    command: command.clone(),
                    cwd: PathBuf::from(cwd),
                    env: env.clone(),
                    timeout: timeout_ms.map(Duration::from_millis),
                    sandbox: crate::exec::sandbox_backend(allowance.sandbox),
                    network: crate::exec::network_for(allowance.network),
                    read_only_paths: allowance.read_only_paths.clone(),
                    writable_paths: allowance.writable_paths.clone(),
                    env_allowlist: allowance.env_allowlist.clone(),
                };
                match (self.run_command)(&request) {
                    Ok(output) => Ok(exec_result_from_output(&output, None)),
                    Err(err) => Err(TaskDispatchError::Failed(format!(
                        "exec command could not be run: {err}"
                    ))),
                }
            }
            TaskAction::Tool { .. } => Err(TaskDispatchError::Failed(
                "tool action cannot run through the exec dispatcher".to_string(),
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
        run_with(task, policy(), dispatcher)
    }

    fn run_with(
        task: &TaskState,
        policy: Policy,
        dispatcher: &mut impl TaskDispatcher,
    ) -> (OrchestrationOutcome, MemoryStore) {
        let mut store = MemoryStore::default();
        let outcome = TaskOrchestrator::new("agent-a")
            .with_room_id("!room:server")
            .with_policy(policy)
            .process_one(task, std::slice::from_ref(task), &mut store, dispatcher);
        (outcome, store)
    }

    fn exec_policy() -> Policy {
        Policy::parse(
            r#"
[rooms."!room:server"]
trusted = true
raw_exec_default = "deny"

[rooms."!room:server".agents."@planner:server"]
allow_exec = true
allow_commands = ["true"]
allow_cwd = ["/repo"]
"#,
        )
        .expect("exec policy parses")
    }

    fn exec_task(program: &str) -> TaskState {
        let mut t = tool_task("unused");
        t.action = Some(TaskAction::Exec {
            command: vec![program.to_string()],
            cwd: "/repo".to_string(),
            env: Default::default(),
            timeout_ms: Some(600_000),
            stream: false,
            authorization: None,
        });
        t
    }

    fn run_output(exit_code: Option<i32>, signal: Option<i32>, timed_out: bool) -> RunOutput {
        RunOutput {
            exit_code,
            signal,
            stdout: Vec::new(),
            stderr: Vec::new(),
            timed_out,
        }
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
            .dispatch(
                &task,
                &exec,
                "inv-1",
                &mx_agent_policy::Allowance::default(),
            )
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

    // --- exec dispatcher (issue #163) ---------------------------------------

    #[test]
    fn exec_zero_exit_marks_task_succeeded() {
        let t = exec_task("true");
        let mut dispatcher = ExecTaskDispatcher::with_runner(|req| {
            assert_eq!(req.command, vec!["true".to_string()]);
            Ok(run_output(Some(0), None, false))
        });
        let (outcome, store) = run_with(&t, exec_policy(), &mut dispatcher);
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
    }

    #[test]
    fn exec_nonzero_exit_marks_task_failed() {
        let t = exec_task("true");
        let mut dispatcher =
            ExecTaskDispatcher::with_runner(|_req| Ok(run_output(Some(2), None, false)));
        let (outcome, store) = run_with(&t, exec_policy(), &mut dispatcher);
        assert!(matches!(
            outcome,
            OrchestrationOutcome::Completed { state, .. } if state == "failed"
        ));
        let result = store.finalized_result.unwrap();
        assert_eq!(result.get("exit_code").and_then(Value::as_i64), Some(2));
        assert_eq!(
            result.get("reason").and_then(Value::as_str),
            Some("process_exit")
        );
    }

    #[test]
    fn exec_signalled_run_marks_task_failed() {
        let t = exec_task("true");
        // Killed by SIGKILL (9): no exit code, mapped to 128 + 9.
        let mut dispatcher =
            ExecTaskDispatcher::with_runner(|_req| Ok(run_output(None, Some(9), false)));
        let (outcome, store) = run_with(&t, exec_policy(), &mut dispatcher);
        assert!(matches!(
            outcome,
            OrchestrationOutcome::Completed { state, .. } if state == "failed"
        ));
        let result = store.finalized_result.unwrap();
        assert_eq!(result.get("exit_code").and_then(Value::as_i64), Some(137));
    }

    #[test]
    fn exec_run_failure_fails_the_task() {
        let t = exec_task("true");
        let mut dispatcher = ExecTaskDispatcher::with_runner(|_req| {
            Err(RunError::MissingCwd(PathBuf::from("/repo")))
        });
        let (outcome, store) = run_with(&t, exec_policy(), &mut dispatcher);
        assert!(matches!(
            outcome,
            OrchestrationOutcome::Completed { state, .. } if state == "failed"
        ));
        let result = store.finalized_result.unwrap();
        assert_eq!(
            result.get("reason").and_then(Value::as_str),
            Some("dispatch_failed")
        );
    }

    #[test]
    fn policy_denied_exec_is_not_dispatched() {
        // `rm` is not in allow_commands, so the orchestrator denies before
        // dispatch and the runner must never be called.
        let t = exec_task("rm");
        let mut dispatcher = ExecTaskDispatcher::with_runner(|_req| {
            panic!("policy-denied exec must not be dispatched")
        });
        let (outcome, store) = run_with(&t, exec_policy(), &mut dispatcher);
        assert!(matches!(outcome, OrchestrationOutcome::Denied { .. }));
        assert_eq!(store.finalized_state.as_deref(), Some("blocked"));
    }

    #[test]
    fn exec_dispatcher_rejects_tool_actions() {
        let mut dispatcher = ExecTaskDispatcher::new();
        let tool = TaskAction::Tool {
            tool: "run_tests".to_string(),
            args: json!({}),
            authorization: None,
        };
        let task = exec_task("true");
        let err = dispatcher
            .dispatch(
                &task,
                &tool,
                "inv-1",
                &mx_agent_policy::Allowance::default(),
            )
            .expect_err("tool action is not exec");
        assert!(matches!(err, TaskDispatchError::Failed(_)));
    }

    #[test]
    fn exec_result_links_artifact_and_maps_timeout() {
        let with_artifact = exec_result_from_output(
            &run_output(Some(0), None, false),
            Some("mxc://matrix.org/log".to_string()),
        );
        assert_eq!(
            with_artifact.artifact_mxc.as_deref(),
            Some("mxc://matrix.org/log")
        );
        assert_eq!(with_artifact.exit_code, Some(0));

        let timed_out = exec_result_from_output(&run_output(None, None, true), None);
        // A timeout has no successful exit code, so the task is finalized failed.
        assert!(timed_out.exit_code != Some(0));
        assert!(timed_out.summary.contains("timed out"));
    }

    // --- allowance wiring tests (issue #248) ---------------------------------
    //
    // These verify that the policy-resolved `Allowance` fields (sandbox backend,
    // network decision, filesystem paths) are correctly threaded into the
    // `ExecRunRequest` passed to the command runner, replacing the prior
    // hardcoded `Backend::None`.

    #[test]
    fn exec_dispatcher_carries_policy_sandbox_network_and_paths_to_runner() {
        // An allowance with Bubblewrap + Allow + paths must produce an
        // ExecRunRequest carrying those values so the runner builds the right bwrap
        // argv (architecture §13.5).
        use std::cell::RefCell;
        use std::rc::Rc;

        let captured: Rc<RefCell<Option<ExecRunRequest>>> = Rc::new(RefCell::new(None));
        let cap = captured.clone();

        let t = exec_task("true");
        let action = t.action.clone().unwrap();

        let allowance = mx_agent_policy::Allowance {
            sandbox: Some(mx_agent_policy::Sandbox::Bubblewrap),
            network: Some(mx_agent_policy::NetworkPolicy::Allow),
            read_only_paths: vec![PathBuf::from("/usr"), PathBuf::from("/lib")],
            writable_paths: vec![PathBuf::from("/work")],
            ..mx_agent_policy::Allowance::default()
        };

        let mut dispatcher = ExecTaskDispatcher::with_runner(move |req| {
            *cap.borrow_mut() = Some(req.clone());
            Ok(run_output(Some(0), None, false))
        });

        let _ = dispatcher.dispatch(&t, &action, "inv-1", &allowance);

        let req = captured.borrow().clone().expect("runner was called");
        assert_eq!(
            req.sandbox,
            mx_agent_sandbox::Backend::Bubblewrap,
            "policy Bubblewrap must reach the runner"
        );
        assert_eq!(
            req.network,
            mx_agent_sandbox::Network::Allow,
            "policy network=allow must reach the runner"
        );
        assert_eq!(
            req.read_only_paths,
            vec![PathBuf::from("/usr"), PathBuf::from("/lib")],
            "read_only_paths must be threaded through"
        );
        assert_eq!(
            req.writable_paths,
            vec![PathBuf::from("/work")],
            "writable_paths must be threaded through"
        );
    }

    #[test]
    fn exec_dispatcher_defaults_to_none_backend_and_deny_with_empty_allowance() {
        // An empty (default) allowance must yield Backend::None and Network::Deny,
        // preserving the pre-fix baseline behavior and failing closed on network.
        use std::cell::RefCell;
        use std::rc::Rc;

        let captured: Rc<RefCell<Option<ExecRunRequest>>> = Rc::new(RefCell::new(None));
        let cap = captured.clone();

        let t = exec_task("true");
        let action = t.action.clone().unwrap();

        let mut dispatcher = ExecTaskDispatcher::with_runner(move |req| {
            *cap.borrow_mut() = Some(req.clone());
            Ok(run_output(Some(0), None, false))
        });

        let _ = dispatcher.dispatch(&t, &action, "inv-1", &mx_agent_policy::Allowance::default());

        let req = captured.borrow().clone().expect("runner was called");
        assert_eq!(
            req.sandbox,
            mx_agent_sandbox::Backend::None,
            "default allowance must yield Backend::None"
        );
        assert_eq!(
            req.network,
            mx_agent_sandbox::Network::Deny,
            "default allowance must fail closed to Network::Deny"
        );
        assert!(
            req.read_only_paths.is_empty(),
            "default allowance must yield empty read_only_paths"
        );
        assert!(
            req.writable_paths.is_empty(),
            "default allowance must yield empty writable_paths"
        );
    }

    #[test]
    fn exec_dispatcher_carries_container_backend_for_docker_policy() {
        // Docker policy sandbox must map to Backend::Container in the request.
        use std::cell::RefCell;
        use std::rc::Rc;

        let captured: Rc<RefCell<Option<ExecRunRequest>>> = Rc::new(RefCell::new(None));
        let cap = captured.clone();

        let t = exec_task("true");
        let action = t.action.clone().unwrap();

        let allowance = mx_agent_policy::Allowance {
            sandbox: Some(mx_agent_policy::Sandbox::Docker),
            network: Some(mx_agent_policy::NetworkPolicy::Deny),
            ..mx_agent_policy::Allowance::default()
        };

        let mut dispatcher = ExecTaskDispatcher::with_runner(move |req| {
            *cap.borrow_mut() = Some(req.clone());
            Ok(run_output(Some(0), None, false))
        });

        let _ = dispatcher.dispatch(&t, &action, "inv-1", &allowance);

        let req = captured.borrow().clone().expect("runner was called");
        assert_eq!(
            req.sandbox,
            mx_agent_sandbox::Backend::Container,
            "Docker policy sandbox must map to Backend::Container"
        );
        assert_eq!(
            req.network,
            mx_agent_sandbox::Network::Deny,
            "policy network=deny must reach the runner"
        );
    }
}
