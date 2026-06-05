//! Daemon-side task orchestration core.
//!
//! This module contains the deterministic scheduler/worker state machine for
//! Matrix-backed tasks. It deliberately separates orchestration decisions from
//! live Matrix I/O: callers provide a [`TaskStore`] implementation that claims
//! and finalizes `com.mxagent.task.v1` state, and a [`TaskDispatcher`] that
//! represents the existing signed, trust-checked, deny-by-default execution
//! path. Keeping this core pure and testable lets the daemon reject malformed,
//! stale, dependency-blocked, or policy-denied work without spawning a process
//! and without exposing Matrix credentials to the CLI/coding agent.

use std::collections::BTreeSet;
use std::time::{SystemTime, UNIX_EPOCH};

use mx_agent_protocol::id::generate_invocation_id;
use mx_agent_protocol::schema::{TaskAction, TaskResult, TaskState};
#[cfg(test)]
use serde_json::json;
use serde_json::Value;

use crate::task::{is_runnable, UpdateTaskOptions, STATE_EXECUTING, STATE_FAILED, STATE_SUCCEEDED};
#[cfg(test)]
use crate::task::{STATE_ASSIGNED, STATE_PENDING};

const ACTION_FIELD: &str = "action";

/// Parse a task action from a task.
///
/// The typed [`TaskState::action`] field is preferred. A fallback to
/// `extra["action"]` preserves already-published tasks created before the field
/// was modeled directly in the protocol schema.
pub fn action_from_task(task: &TaskState) -> Result<TaskAction, TaskActionError> {
    if let Some(action) = &task.action {
        return Ok(action.clone());
    }
    let value = task
        .extra
        .get(ACTION_FIELD)
        .ok_or(TaskActionError::MissingAction)?;
    serde_json::from_value(value.clone()).map_err(|source| TaskActionError::InvalidAction {
        task_id: task.task_id.clone(),
        source,
    })
}

/// Why a task action could not be parsed.
#[derive(Debug)]
pub enum TaskActionError {
    /// The task has no `extra["action"]` payload.
    MissingAction,
    /// The payload exists but does not match a supported action schema.
    InvalidAction {
        /// Task whose action was malformed.
        task_id: String,
        /// Serde validation error.
        source: serde_json::Error,
    },
}

impl std::fmt::Display for TaskActionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingAction => write!(f, "task has no action payload"),
            Self::InvalidAction { task_id, source } => {
                write!(
                    f,
                    "task {task_id:?} has an invalid action payload: {source}"
                )
            }
        }
    }
}

impl std::error::Error for TaskActionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidAction { source, .. } => Some(source),
            Self::MissingAction => None,
        }
    }
}

/// Result returned by a policy-approved dispatcher.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskExecutionResult {
    /// Process or tool exit code, if applicable.
    pub exit_code: Option<i32>,
    /// Non-sensitive human summary.
    pub summary: String,
    /// Optional Matrix artifact link for large output.
    pub artifact_mxc: Option<String>,
}

impl TaskExecutionResult {
    /// Whether the dispatch result should mark the task as successful.
    pub fn is_success(&self) -> bool {
        self.exit_code == Some(0)
    }
}

/// Dispatch failure after a task has been claimed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskDispatchError {
    /// Local trust/policy denied execution. This must not spawn a process.
    PolicyDenied(String),
    /// Execution was authorized but failed before producing a normal result.
    Failed(String),
}

impl std::fmt::Display for TaskDispatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PolicyDenied(reason) => write!(f, "policy denied task action: {reason}"),
            Self::Failed(reason) => write!(f, "task action failed: {reason}"),
        }
    }
}

impl std::error::Error for TaskDispatchError {}

/// Abstraction over the daemon's signed, trust/policy checked execution path.
pub trait TaskDispatcher {
    /// Dispatch `action` for `task` and `invocation_id`.
    ///
    /// Implementations must perform signature/trust/policy authorization before
    /// spawning, and return [`TaskDispatchError::PolicyDenied`] without spawning
    /// when local deny-by-default policy rejects the request.
    fn dispatch(
        &mut self,
        task: &TaskState,
        action: &TaskAction,
        invocation_id: &str,
    ) -> Result<TaskExecutionResult, TaskDispatchError>;
}

/// Storage operations required by the orchestrator.
pub trait TaskStore {
    /// Claim a task at its observed revision, transitioning it to `executing`.
    fn claim(&mut self, options: UpdateTaskOptions) -> Result<TaskState, TaskStoreError>;
    /// Finalize a claimed task with terminal state and structured result.
    fn finalize(&mut self, options: UpdateTaskOptions) -> Result<TaskState, TaskStoreError>;
}

/// Store-level failures surfaced by orchestration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskStoreError {
    /// The task has advanced since the scheduler observed it.
    StaleClaim {
        /// Task ID.
        task_id: String,
        /// Expected state revision.
        expected: u64,
        /// Current state revision.
        current: u64,
    },
    /// The task no longer exists.
    NotFound(String),
    /// Other non-sensitive storage error.
    Other(String),
}

/// Outcome for one scheduler decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OrchestrationOutcome {
    /// Task was ignored because it is not assigned to this daemon's agent.
    NotAssigned {
        /// Task ID.
        task_id: String,
    },
    /// Task is not in a scheduler-owned state.
    NotRunnableState {
        /// Task ID.
        task_id: String,
        /// Observed task state.
        state: String,
    },
    /// Task has dependencies that have not succeeded yet.
    Blocked {
        /// Task ID.
        task_id: String,
        /// Dependency task IDs still blocking execution.
        waiting_on: Vec<String>,
    },
    /// Task action payload was missing or malformed.
    MalformedAction {
        /// Task ID.
        task_id: String,
        /// Non-sensitive parse error.
        reason: String,
    },
    /// Claim lost a race with another writer, so nothing was spawned.
    StaleClaim {
        /// Task ID.
        task_id: String,
    },
    /// Action was denied by local policy/trust and finalized as failed.
    Denied {
        /// Task ID.
        task_id: String,
        /// Invocation ID linked to the denied task.
        invocation_id: String,
    },
    /// Action ran and task was finalized.
    Completed {
        /// Task ID.
        task_id: String,
        /// Invocation ID linked to the task.
        invocation_id: String,
        /// Terminal task state.
        state: String,
    },
    /// Previously executing local work was recovered without respawning.
    RecoveredStale {
        /// Task ID.
        task_id: String,
    },
    /// Store failed in a way the caller must surface.
    StoreError {
        /// Task ID.
        task_id: String,
        /// Non-sensitive store error.
        reason: String,
    },
}

/// Daemon task orchestrator for a single local agent.
pub struct TaskOrchestrator {
    agent_id: String,
}

impl TaskOrchestrator {
    /// Build an orchestrator for `agent_id`.
    pub fn new(agent_id: impl Into<String>) -> Self {
        Self {
            agent_id: agent_id.into(),
        }
    }

    /// Return pending tasks assigned to this agent and not dependency-blocked.
    pub fn runnable_tasks<'a>(&self, tasks: &'a [TaskState]) -> Vec<&'a TaskState> {
        let succeeded = succeeded_ids(tasks);
        tasks
            .iter()
            .filter(|task| self.is_assigned(task))
            .filter(|task| is_runnable(&task.state))
            .filter(|task| unmet_dependencies(task, &succeeded).is_empty())
            .collect()
    }

    /// Evaluate and, when safe, run one task.
    pub fn process_one<S, D>(
        &self,
        task: &TaskState,
        all_tasks: &[TaskState],
        store: &mut S,
        dispatcher: &mut D,
    ) -> OrchestrationOutcome
    where
        S: TaskStore,
        D: TaskDispatcher,
    {
        if !self.is_assigned(task) {
            return OrchestrationOutcome::NotAssigned {
                task_id: task.task_id.clone(),
            };
        }
        if !is_runnable(&task.state) {
            return OrchestrationOutcome::NotRunnableState {
                task_id: task.task_id.clone(),
                state: task.state.clone(),
            };
        }
        let waiting_on = unmet_dependencies(task, &succeeded_ids(all_tasks));
        if !waiting_on.is_empty() {
            return OrchestrationOutcome::Blocked {
                task_id: task.task_id.clone(),
                waiting_on,
            };
        }
        let action = match action_from_task(task) {
            Ok(action) => action,
            Err(err) => {
                return OrchestrationOutcome::MalformedAction {
                    task_id: task.task_id.clone(),
                    reason: err.to_string(),
                }
            }
        };

        let invocation_id = generate_invocation_id();
        let claimed = match store.claim(UpdateTaskOptions {
            room: String::new(),
            task_id: task.task_id.clone(),
            state: Some(STATE_EXECUTING.to_string()),
            invocation_id: Some(invocation_id.clone()),
            expected_state_rev: Some(task.state_rev),
            ..UpdateTaskOptions::default()
        }) {
            Ok(claimed) => claimed,
            Err(TaskStoreError::StaleClaim { .. }) => {
                return OrchestrationOutcome::StaleClaim {
                    task_id: task.task_id.clone(),
                }
            }
            Err(err) => {
                return OrchestrationOutcome::StoreError {
                    task_id: task.task_id.clone(),
                    reason: format_store_error(&err),
                }
            }
        };

        let (terminal, result) = match dispatcher.dispatch(&claimed, &action, &invocation_id) {
            Ok(output) => {
                let state = if output.is_success() {
                    STATE_SUCCEEDED
                } else {
                    STATE_FAILED
                };
                (
                    state,
                    dispatch_result(
                        state,
                        &self.agent_id,
                        &invocation_id,
                        action.kind(),
                        (state == STATE_FAILED).then(|| "process_exit".to_string()),
                        &output,
                    ),
                )
            }
            Err(TaskDispatchError::PolicyDenied(reason)) => (
                STATE_FAILED,
                failure_result(
                    &self.agent_id,
                    Some(&invocation_id),
                    Some(action.kind()),
                    "policy_denied",
                    Some(reason),
                ),
            ),
            Err(TaskDispatchError::Failed(reason)) => (
                STATE_FAILED,
                failure_result(
                    &self.agent_id,
                    Some(&invocation_id),
                    Some(action.kind()),
                    "dispatch_failed",
                    Some(reason),
                ),
            ),
        };

        match store.finalize(UpdateTaskOptions {
            room: String::new(),
            task_id: task.task_id.clone(),
            state: Some(terminal.to_string()),
            result: Some(result),
            expected_state_rev: Some(claimed.state_rev),
            ..UpdateTaskOptions::default()
        }) {
            Ok(finalized) => {
                if terminal == STATE_FAILED
                    && finalized
                        .result
                        .as_ref()
                        .and_then(|v| v.get("reason"))
                        .and_then(Value::as_str)
                        == Some("policy_denied")
                {
                    OrchestrationOutcome::Denied {
                        task_id: finalized.task_id,
                        invocation_id,
                    }
                } else {
                    OrchestrationOutcome::Completed {
                        task_id: finalized.task_id,
                        invocation_id,
                        state: finalized.state,
                    }
                }
            }
            Err(err) => OrchestrationOutcome::StoreError {
                task_id: task.task_id.clone(),
                reason: format_store_error(&err),
            },
        }
    }

    /// Recover an assigned `executing` task whose invocation is no longer live.
    ///
    /// This restart path resolves stale local work safely: it marks the task as
    /// failed with a recovery result instead of double-spawning the action.
    pub fn recover_stale_executing<S>(
        &self,
        task: &TaskState,
        live_invocations: &BTreeSet<String>,
        store: &mut S,
    ) -> OrchestrationOutcome
    where
        S: TaskStore,
    {
        if !self.is_assigned(task) || task.state != STATE_EXECUTING {
            return OrchestrationOutcome::NotRunnableState {
                task_id: task.task_id.clone(),
                state: task.state.clone(),
            };
        }
        if task
            .invocation_id
            .as_ref()
            .is_some_and(|id| live_invocations.contains(id))
        {
            return OrchestrationOutcome::NotRunnableState {
                task_id: task.task_id.clone(),
                state: task.state.clone(),
            };
        }
        let result = failure_result(
            &self.agent_id,
            task.invocation_id.as_deref(),
            None,
            "recovered_stale_invocation",
            Some("daemon restart found executing task without live local invocation".to_string()),
        );
        match store.finalize(UpdateTaskOptions {
            room: String::new(),
            task_id: task.task_id.clone(),
            state: Some(STATE_FAILED.to_string()),
            result: Some(result),
            expected_state_rev: Some(task.state_rev),
            ..UpdateTaskOptions::default()
        }) {
            Ok(finalized) => OrchestrationOutcome::RecoveredStale {
                task_id: finalized.task_id,
            },
            Err(err) => OrchestrationOutcome::StoreError {
                task_id: task.task_id.clone(),
                reason: format_store_error(&err),
            },
        }
    }

    fn is_assigned(&self, task: &TaskState) -> bool {
        task.assigned_to == self.agent_id
    }
}

fn succeeded_ids(tasks: &[TaskState]) -> BTreeSet<String> {
    tasks
        .iter()
        .filter(|task| task.state == STATE_SUCCEEDED)
        .map(|task| task.task_id.clone())
        .collect()
}

fn unmet_dependencies(task: &TaskState, succeeded: &BTreeSet<String>) -> Vec<String> {
    task.depends_on
        .iter()
        .filter(|dep| !succeeded.contains(*dep))
        .cloned()
        .collect()
}

fn dispatch_result(
    status: &str,
    completed_by: &str,
    invocation_id: &str,
    action: &str,
    reason: Option<String>,
    output: &TaskExecutionResult,
) -> Value {
    TaskResult {
        status: status.to_string(),
        completed_by: completed_by.to_string(),
        completed_at: now_rfc3339(),
        invocation_id: Some(invocation_id.to_string()),
        action: Some(action.to_string()),
        reason,
        exit_code: output.exit_code,
        summary: Some(output.summary.clone()),
        artifact_mxc: output.artifact_mxc.clone(),
        extra: Default::default(),
    }
    .into_value()
}

fn failure_result(
    completed_by: &str,
    invocation_id: Option<&str>,
    action: Option<&str>,
    reason: &str,
    summary: Option<String>,
) -> Value {
    TaskResult {
        status: STATE_FAILED.to_string(),
        completed_by: completed_by.to_string(),
        completed_at: now_rfc3339(),
        invocation_id: invocation_id.map(ToString::to_string),
        action: action.map(ToString::to_string),
        reason: Some(reason.to_string()),
        exit_code: None,
        summary,
        artifact_mxc: None,
        extra: Default::default(),
    }
    .into_value()
}

fn now_rfc3339() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default();
    unix_to_rfc3339(secs)
}

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

fn format_store_error(err: &TaskStoreError) -> String {
    match err {
        TaskStoreError::StaleClaim {
            task_id,
            expected,
            current,
        } => format!(
            "task {task_id:?} update is stale: expected state_rev {expected} but current is {current}"
        ),
        TaskStoreError::NotFound(task_id) => format!("task {task_id:?} was not found"),
        TaskStoreError::Other(reason) => reason.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mx_agent_protocol::schema::Extra;

    fn task(id: &str, state: &str, assigned_to: &str) -> TaskState {
        TaskState {
            task_id: id.to_string(),
            title: id.to_string(),
            description: String::new(),
            state: state.to_string(),
            assigned_to: assigned_to.to_string(),
            created_by: "planner".to_string(),
            depends_on: Vec::new(),
            blocks: Vec::new(),
            invocation_id: None,
            created_at: "2026-06-02T12:00:00Z".to_string(),
            updated_at: "2026-06-02T12:00:00Z".to_string(),
            state_rev: 1,
            previous_event_id: None,
            result: None,
            action: None,
            extra: Extra::default(),
        }
    }

    fn with_action(mut task: TaskState, action: Value) -> TaskState {
        task.extra.insert(ACTION_FIELD.to_string(), action);
        task
    }

    #[derive(Default)]
    struct MemoryStore {
        current_rev: u64,
        stale: bool,
        finalized_result: Option<Value>,
    }

    impl TaskStore for MemoryStore {
        fn claim(&mut self, options: UpdateTaskOptions) -> Result<TaskState, TaskStoreError> {
            if self.stale {
                return Err(TaskStoreError::StaleClaim {
                    task_id: options.task_id,
                    expected: options.expected_state_rev.unwrap_or_default(),
                    current: self.current_rev,
                });
            }
            self.current_rev = options.expected_state_rev.unwrap_or(1) + 1;
            Ok(TaskState {
                task_id: options.task_id,
                title: String::new(),
                description: String::new(),
                state: options.state.unwrap(),
                assigned_to: "agent-a".to_string(),
                created_by: String::new(),
                depends_on: Vec::new(),
                blocks: Vec::new(),
                invocation_id: options.invocation_id,
                created_at: String::new(),
                updated_at: String::new(),
                state_rev: self.current_rev,
                previous_event_id: None,
                result: None,
                action: None,
                extra: Extra::default(),
            })
        }

        fn finalize(&mut self, options: UpdateTaskOptions) -> Result<TaskState, TaskStoreError> {
            self.current_rev = options.expected_state_rev.unwrap_or(self.current_rev) + 1;
            self.finalized_result = options.result.clone();
            Ok(TaskState {
                task_id: options.task_id,
                title: String::new(),
                description: String::new(),
                state: options.state.unwrap(),
                assigned_to: "agent-a".to_string(),
                created_by: String::new(),
                depends_on: Vec::new(),
                blocks: Vec::new(),
                invocation_id: options.invocation_id,
                created_at: String::new(),
                updated_at: String::new(),
                state_rev: self.current_rev,
                previous_event_id: None,
                result: options.result,
                action: None,
                extra: Extra::default(),
            })
        }
    }

    struct Dispatcher(Result<TaskExecutionResult, TaskDispatchError>);

    impl TaskDispatcher for Dispatcher {
        fn dispatch(
            &mut self,
            _task: &TaskState,
            _action: &TaskAction,
            _invocation_id: &str,
        ) -> Result<TaskExecutionResult, TaskDispatchError> {
            self.0.clone()
        }
    }

    #[test]
    fn parses_legacy_tool_action_from_extra() {
        let t = with_action(
            task("task-a", STATE_PENDING, "agent-a"),
            json!({"type":"tool", "tool":"run_tests", "args":{"package":"cli"}}),
        );
        assert_eq!(
            action_from_task(&t).unwrap(),
            TaskAction::Tool {
                tool: "run_tests".to_string(),
                args: json!({"package":"cli"})
            }
        );
    }

    #[test]
    fn typed_action_takes_precedence_over_legacy_extra() {
        let mut t = with_action(
            task("task-a", STATE_PENDING, "agent-a"),
            json!({"type":"tool", "tool":"legacy", "args":{}}),
        );
        t.action = Some(TaskAction::Tool {
            tool: "typed".to_string(),
            args: json!({ "package": "cli" }),
        });
        assert_eq!(
            action_from_task(&t).unwrap(),
            TaskAction::Tool {
                tool: "typed".to_string(),
                args: json!({ "package": "cli" })
            }
        );
    }

    #[test]
    fn missing_action_does_not_spawn() {
        let t = task("task-a", STATE_PENDING, "agent-a");
        let mut store = MemoryStore::default();
        let mut dispatcher = Dispatcher(Ok(TaskExecutionResult {
            exit_code: Some(0),
            summary: "ok".to_string(),
            artifact_mxc: None,
        }));
        let outcome = TaskOrchestrator::new("agent-a").process_one(
            &t,
            std::slice::from_ref(&t),
            &mut store,
            &mut dispatcher,
        );
        assert!(matches!(
            outcome,
            OrchestrationOutcome::MalformedAction { .. }
        ));
    }

    #[test]
    fn dependency_blocking_prevents_claim() {
        let mut t = with_action(
            task("task-test", STATE_PENDING, "agent-a"),
            json!({"type":"exec", "command":["cargo", "test"], "cwd":"/repo"}),
        );
        t.depends_on = vec!["task-plan".to_string()];
        let blocked = task("task-plan", STATE_PENDING, "agent-a");
        let mut store = MemoryStore::default();
        let mut dispatcher = Dispatcher(Ok(TaskExecutionResult {
            exit_code: Some(0),
            summary: "ok".to_string(),
            artifact_mxc: None,
        }));
        let outcome = TaskOrchestrator::new("agent-a").process_one(
            &t,
            &[t.clone(), blocked],
            &mut store,
            &mut dispatcher,
        );
        assert_eq!(
            outcome,
            OrchestrationOutcome::Blocked {
                task_id: "task-test".to_string(),
                waiting_on: vec!["task-plan".to_string()]
            }
        );
        assert_eq!(store.current_rev, 0);
    }

    #[test]
    fn runnable_tasks_include_pending_and_assigned_ready_work() {
        let pending = with_action(
            task("task-pending", STATE_PENDING, "agent-a"),
            json!({"type":"tool", "tool":"run_tests", "args":{}}),
        );
        let assigned = with_action(
            task("task-assigned", STATE_ASSIGNED, "agent-a"),
            json!({"type":"tool", "tool":"run_tests", "args":{}}),
        );
        let other_agent = task("task-other", STATE_PENDING, "agent-b");
        let executing = task("task-running", STATE_EXECUTING, "agent-a");
        let succeeded = task("task-done", STATE_SUCCEEDED, "agent-a");
        let failed = task("task-failed", STATE_FAILED, "agent-a");
        let tasks = vec![pending, assigned, other_agent, executing, succeeded, failed];
        let ids: Vec<&str> = TaskOrchestrator::new("agent-a")
            .runnable_tasks(&tasks)
            .into_iter()
            .map(|task| task.task_id.as_str())
            .collect();
        assert_eq!(ids, vec!["task-pending", "task-assigned"]);
    }

    fn finalized_result(store: &MemoryStore) -> &Value {
        store
            .finalized_result
            .as_ref()
            .expect("task should be finalized with a result")
    }

    #[test]
    fn successful_dispatch_claims_and_finalizes_task() {
        let t = with_action(
            task("task-a", STATE_PENDING, "agent-a"),
            json!({"type":"tool", "tool":"run_tests", "args":{}}),
        );
        let mut store = MemoryStore::default();
        let mut dispatcher = Dispatcher(Ok(TaskExecutionResult {
            exit_code: Some(0),
            summary: "tests passed".to_string(),
            artifact_mxc: None,
        }));
        let outcome = TaskOrchestrator::new("agent-a").process_one(
            &t,
            std::slice::from_ref(&t),
            &mut store,
            &mut dispatcher,
        );
        assert!(matches!(
            outcome,
            OrchestrationOutcome::Completed {
                task_id,
                state,
                ..
            } if task_id == "task-a" && state == STATE_SUCCEEDED
        ));
        assert_eq!(store.current_rev, 3);
        let result = finalized_result(&store);
        assert_eq!(
            result.get("status").and_then(Value::as_str),
            Some("succeeded")
        );
        assert_eq!(
            result.get("completed_by").and_then(Value::as_str),
            Some("agent-a")
        );
        assert_eq!(result.get("action").and_then(Value::as_str), Some("tool"));
        assert_eq!(result.get("exit_code").and_then(Value::as_i64), Some(0));
        assert_eq!(
            result.get("summary").and_then(Value::as_str),
            Some("tests passed")
        );
        assert!(result.get("completed_at").and_then(Value::as_str).is_some());
    }

    #[test]
    fn failed_exit_uses_stable_process_exit_result() {
        let t = with_action(
            task("task-a", STATE_PENDING, "agent-a"),
            json!({"type":"exec", "command":["cargo", "test"], "cwd":"/repo"}),
        );
        let mut store = MemoryStore::default();
        let mut dispatcher = Dispatcher(Ok(TaskExecutionResult {
            exit_code: Some(1),
            summary: "tests failed".to_string(),
            artifact_mxc: Some("mxc://matrix.org/log".to_string()),
        }));
        let outcome = TaskOrchestrator::new("agent-a").process_one(
            &t,
            std::slice::from_ref(&t),
            &mut store,
            &mut dispatcher,
        );
        assert!(matches!(
            outcome,
            OrchestrationOutcome::Completed { state, .. } if state == STATE_FAILED
        ));
        let result = finalized_result(&store);
        assert_eq!(result.get("status").and_then(Value::as_str), Some("failed"));
        assert_eq!(
            result.get("reason").and_then(Value::as_str),
            Some("process_exit")
        );
        assert_eq!(result.get("exit_code").and_then(Value::as_i64), Some(1));
        assert_eq!(
            result.get("artifact_mxc").and_then(Value::as_str),
            Some("mxc://matrix.org/log")
        );
    }

    #[test]
    fn policy_denial_finalizes_failed_without_success() {
        let t = with_action(
            task("task-a", STATE_PENDING, "agent-a"),
            json!({"type":"exec", "command":["sh", "-c", "true"], "cwd":"/repo"}),
        );
        let mut store = MemoryStore::default();
        let mut dispatcher = Dispatcher(Err(TaskDispatchError::PolicyDenied(
            "no matching allow rule".to_string(),
        )));
        let outcome = TaskOrchestrator::new("agent-a").process_one(
            &t,
            std::slice::from_ref(&t),
            &mut store,
            &mut dispatcher,
        );
        assert!(matches!(
            outcome,
            OrchestrationOutcome::Denied { task_id, .. } if task_id == "task-a"
        ));
        assert_eq!(store.current_rev, 3);
        let result = finalized_result(&store);
        assert_eq!(result.get("status").and_then(Value::as_str), Some("failed"));
        assert_eq!(
            result.get("reason").and_then(Value::as_str),
            Some("policy_denied")
        );
        assert_eq!(
            result.get("summary").and_then(Value::as_str),
            Some("no matching allow rule")
        );
    }

    #[test]
    fn stale_claim_loses_race_without_dispatch() {
        let t = with_action(
            task("task-a", STATE_PENDING, "agent-a"),
            json!({"type":"tool", "tool":"run_tests", "args":{}}),
        );
        let mut store = MemoryStore {
            current_rev: 2,
            stale: true,
            ..MemoryStore::default()
        };
        let mut dispatcher = Dispatcher(Ok(TaskExecutionResult {
            exit_code: Some(0),
            summary: "should not run".to_string(),
            artifact_mxc: None,
        }));
        let outcome = TaskOrchestrator::new("agent-a").process_one(
            &t,
            std::slice::from_ref(&t),
            &mut store,
            &mut dispatcher,
        );
        assert_eq!(
            outcome,
            OrchestrationOutcome::StaleClaim {
                task_id: "task-a".to_string()
            }
        );
    }

    #[test]
    fn recovery_marks_stale_executing_failed_without_respawn() {
        let mut t = task("task-a", STATE_EXECUTING, "agent-a");
        t.invocation_id = Some("inv-lost".to_string());
        let mut store = MemoryStore::default();
        let live = BTreeSet::new();
        let outcome =
            TaskOrchestrator::new("agent-a").recover_stale_executing(&t, &live, &mut store);
        assert_eq!(
            outcome,
            OrchestrationOutcome::RecoveredStale {
                task_id: "task-a".to_string()
            }
        );
        assert_eq!(store.current_rev, 2);
        let result = finalized_result(&store);
        assert_eq!(result.get("status").and_then(Value::as_str), Some("failed"));
        assert_eq!(
            result.get("reason").and_then(Value::as_str),
            Some("recovered_stale_invocation")
        );
        assert_eq!(
            result.get("invocation_id").and_then(Value::as_str),
            Some("inv-lost")
        );
    }
}
