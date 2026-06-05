//! Daemon task scheduler: deciding which tasks are runnable.
//!
//! The scheduler is the read-side counterpart to the orchestrator's claim/
//! dispatch core ([`crate::task_orchestrator`]). Given a snapshot of a room's
//! tasks (for example from [`crate::watch`] or [`crate::list_tasks`]), it
//! decides which tasks this daemon's agent should attempt to run, applying the
//! full runnable condition from `docs/architecture.md` §9.2:
//!
//! ```text
//! state in [pending, assigned]
//! all depends_on tasks are succeeded
//! assigned_to matches local agent id or auto-claim policy
//! task has an executable action
//! agent has capacity
//! ```
//!
//! The scheduler is deliberately pure and deterministic: it never performs
//! Matrix I/O and never spawns anything. It only computes decisions and emits
//! non-sensitive `tracing` logs, so the claim/dispatch path (and its policy,
//! trust, and signature checks) remains the sole place execution can begin.

use std::collections::BTreeSet;

use mx_agent_protocol::schema::TaskState;

use crate::task::{is_runnable, is_terminal, STATE_SUCCEEDED};
use crate::task_orchestrator::action_from_task;

/// The scheduler's decision for a single task at a point in time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScheduleDecision {
    /// The task is runnable now and should be claimed/dispatched.
    Runnable {
        /// Task ID.
        task_id: String,
    },
    /// The task is not assigned to this agent and auto-claim is disabled.
    NotAssigned {
        /// Task ID.
        task_id: String,
        /// Agent the task is assigned to (may be empty).
        assigned_to: String,
    },
    /// The task is in a terminal state and must never run again.
    TerminalState {
        /// Task ID.
        task_id: String,
        /// Observed terminal state.
        state: String,
    },
    /// The task is in a state the scheduler does not own.
    NotSchedulableState {
        /// Task ID.
        task_id: String,
        /// Observed state.
        state: String,
    },
    /// The task has dependencies that have not succeeded yet.
    DependenciesUnmet {
        /// Task ID.
        task_id: String,
        /// Dependency task IDs still blocking execution.
        waiting_on: Vec<String>,
    },
    /// The task has no executable action (manual/planning or malformed).
    NoExecutableAction {
        /// Task ID.
        task_id: String,
    },
    /// The task is otherwise runnable but the agent has no spare capacity.
    AtCapacity {
        /// Task ID.
        task_id: String,
    },
}

impl ScheduleDecision {
    /// The task ID this decision concerns.
    pub fn task_id(&self) -> &str {
        match self {
            Self::Runnable { task_id }
            | Self::NotAssigned { task_id, .. }
            | Self::TerminalState { task_id, .. }
            | Self::NotSchedulableState { task_id, .. }
            | Self::DependenciesUnmet { task_id, .. }
            | Self::NoExecutableAction { task_id }
            | Self::AtCapacity { task_id } => task_id,
        }
    }

    /// Whether this decision marks the task as runnable now.
    pub fn is_runnable(&self) -> bool {
        matches!(self, Self::Runnable { .. })
    }

    /// A stable, non-sensitive label for logs and metrics.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Runnable { .. } => "runnable",
            Self::NotAssigned { .. } => "not_assigned",
            Self::TerminalState { .. } => "terminal",
            Self::NotSchedulableState { .. } => "not_schedulable_state",
            Self::DependenciesUnmet { .. } => "dependencies_unmet",
            Self::NoExecutableAction { .. } => "no_executable_action",
            Self::AtCapacity { .. } => "at_capacity",
        }
    }
}

/// Decides which tasks this daemon's agent should attempt to run.
#[derive(Debug, Clone)]
pub struct TaskScheduler {
    agent_id: String,
    max_invocations: u32,
    auto_claim: bool,
}

impl TaskScheduler {
    /// Build a scheduler for `agent_id` with a concurrency `max_invocations`.
    ///
    /// Auto-claim is disabled by default: only tasks assigned to `agent_id` are
    /// considered. Enable it with [`TaskScheduler::with_auto_claim`] to also
    /// consider unassigned tasks.
    pub fn new(agent_id: impl Into<String>, max_invocations: u32) -> Self {
        Self {
            agent_id: agent_id.into(),
            max_invocations,
            auto_claim: false,
        }
    }

    /// Enable or disable auto-claiming of unassigned tasks.
    pub fn with_auto_claim(mut self, auto_claim: bool) -> Self {
        self.auto_claim = auto_claim;
        self
    }

    /// Evaluate one task against the runnable condition (excluding capacity).
    ///
    /// Capacity is applied by [`TaskScheduler::schedule`], which knows how many
    /// invocations are already running and how many runnable tasks precede this
    /// one. Use this method to classify a single task's runnability ignoring
    /// load.
    pub fn evaluate(&self, task: &TaskState, all_tasks: &[TaskState]) -> ScheduleDecision {
        if is_terminal(&task.state) {
            return ScheduleDecision::TerminalState {
                task_id: task.task_id.clone(),
                state: task.state.clone(),
            };
        }
        if !is_runnable(&task.state) {
            return ScheduleDecision::NotSchedulableState {
                task_id: task.task_id.clone(),
                state: task.state.clone(),
            };
        }
        if !self.is_claimable(task) {
            return ScheduleDecision::NotAssigned {
                task_id: task.task_id.clone(),
                assigned_to: task.assigned_to.clone(),
            };
        }
        let waiting_on = unmet_dependencies(task, &succeeded_ids(all_tasks));
        if !waiting_on.is_empty() {
            return ScheduleDecision::DependenciesUnmet {
                task_id: task.task_id.clone(),
                waiting_on,
            };
        }
        if action_from_task(task).is_err() {
            return ScheduleDecision::NoExecutableAction {
                task_id: task.task_id.clone(),
            };
        }
        ScheduleDecision::Runnable {
            task_id: task.task_id.clone(),
        }
    }

    /// Decide the scheduling outcome for every task, honoring `running_count`
    /// against the configured capacity.
    ///
    /// Tasks are considered in `task_id` order for a stable, deterministic
    /// result. Each decision is logged at debug level with only non-sensitive
    /// fields. Returns one [`ScheduleDecision`] per input task.
    pub fn decide(&self, tasks: &[TaskState], running_count: u32) -> Vec<ScheduleDecision> {
        let mut ordered: Vec<&TaskState> = tasks.iter().collect();
        ordered.sort_by(|a, b| a.task_id.cmp(&b.task_id));

        let mut remaining = self.max_invocations.saturating_sub(running_count);
        let mut decisions = Vec::with_capacity(ordered.len());
        for task in ordered {
            let mut decision = self.evaluate(task, tasks);
            if decision.is_runnable() {
                if remaining == 0 {
                    decision = ScheduleDecision::AtCapacity {
                        task_id: task.task_id.clone(),
                    };
                } else {
                    remaining -= 1;
                }
            }
            tracing::debug!(
                task_id = %decision.task_id(),
                state = %task.state,
                decision = decision.kind(),
                "scheduler decision"
            );
            decisions.push(decision);
        }
        decisions
    }

    /// Return the tasks the scheduler decided are runnable now.
    pub fn runnable<'a>(&self, tasks: &'a [TaskState], running_count: u32) -> Vec<&'a TaskState> {
        let runnable_ids: BTreeSet<String> = self
            .decide(tasks, running_count)
            .into_iter()
            .filter(ScheduleDecision::is_runnable)
            .map(|d| d.task_id().to_string())
            .collect();
        tasks
            .iter()
            .filter(|task| runnable_ids.contains(&task.task_id))
            .collect()
    }

    /// Whether this agent may claim `task` (assigned to it, or auto-claim on).
    fn is_claimable(&self, task: &TaskState) -> bool {
        self.auto_claim || task.assigned_to == self.agent_id
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

#[cfg(test)]
mod tests {
    use super::*;
    use mx_agent_protocol::schema::{Extra, TaskAction};
    use serde_json::json;

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

    fn with_tool(mut t: TaskState) -> TaskState {
        t.action = Some(TaskAction::Tool {
            tool: "run_tests".to_string(),
            args: json!({}),
            authorization: None,
        });
        t
    }

    #[test]
    fn pending_task_with_action_is_runnable() {
        let t = with_tool(task("task-a", "pending", "agent-a"));
        let scheduler = TaskScheduler::new("agent-a", 4);
        assert_eq!(
            scheduler.evaluate(&t, std::slice::from_ref(&t)),
            ScheduleDecision::Runnable {
                task_id: "task-a".to_string()
            }
        );
    }

    #[test]
    fn terminal_tasks_never_run() {
        for state in ["succeeded", "failed", "cancelled", "superseded"] {
            let t = with_tool(task("task-a", state, "agent-a"));
            let scheduler = TaskScheduler::new("agent-a", 4);
            assert!(matches!(
                scheduler.evaluate(&t, std::slice::from_ref(&t)),
                ScheduleDecision::TerminalState { .. }
            ));
        }
    }

    #[test]
    fn non_schedulable_state_is_ignored() {
        let t = with_tool(task("task-a", "executing", "agent-a"));
        let scheduler = TaskScheduler::new("agent-a", 4);
        assert!(matches!(
            scheduler.evaluate(&t, std::slice::from_ref(&t)),
            ScheduleDecision::NotSchedulableState { .. }
        ));
    }

    #[test]
    fn unassigned_task_excluded_unless_auto_claim() {
        let t = with_tool(task("task-a", "pending", "agent-b"));
        let scheduler = TaskScheduler::new("agent-a", 4);
        assert!(matches!(
            scheduler.evaluate(&t, std::slice::from_ref(&t)),
            ScheduleDecision::NotAssigned { .. }
        ));
        let auto = TaskScheduler::new("agent-a", 4).with_auto_claim(true);
        assert!(auto.evaluate(&t, std::slice::from_ref(&t)).is_runnable());
    }

    #[test]
    fn dependencies_must_be_succeeded() {
        let mut t = with_tool(task("task-test", "pending", "agent-a"));
        t.depends_on = vec!["task-plan".to_string()];
        let scheduler = TaskScheduler::new("agent-a", 4);

        // Pending dependency blocks.
        let pending_dep = task("task-plan", "pending", "agent-a");
        assert!(matches!(
            scheduler.evaluate(&t, &[t.clone(), pending_dep]),
            ScheduleDecision::DependenciesUnmet { .. }
        ));

        // Failed dependency blocks.
        let failed_dep = task("task-plan", "failed", "agent-a");
        assert!(matches!(
            scheduler.evaluate(&t, &[t.clone(), failed_dep]),
            ScheduleDecision::DependenciesUnmet { .. }
        ));

        // Succeeded dependency unblocks.
        let ok_dep = task("task-plan", "succeeded", "agent-a");
        assert!(scheduler.evaluate(&t, &[t.clone(), ok_dep]).is_runnable());
    }

    #[test]
    fn task_without_action_is_not_runnable() {
        let t = task("task-a", "pending", "agent-a");
        let scheduler = TaskScheduler::new("agent-a", 4);
        assert!(matches!(
            scheduler.evaluate(&t, std::slice::from_ref(&t)),
            ScheduleDecision::NoExecutableAction { .. }
        ));
    }

    #[test]
    fn capacity_limits_runnable_tasks() {
        let tasks = vec![
            with_tool(task("task-a", "pending", "agent-a")),
            with_tool(task("task-b", "pending", "agent-a")),
            with_tool(task("task-c", "pending", "agent-a")),
        ];
        // Capacity 2, nothing running -> 2 runnable, 1 at capacity.
        let scheduler = TaskScheduler::new("agent-a", 2);
        let runnable: Vec<&str> = scheduler
            .runnable(&tasks, 0)
            .into_iter()
            .map(|t| t.task_id.as_str())
            .collect();
        assert_eq!(runnable, vec!["task-a", "task-b"]);

        let decisions = scheduler.decide(&tasks, 0);
        assert!(decisions
            .iter()
            .any(|d| matches!(d, ScheduleDecision::AtCapacity { task_id } if task_id == "task-c")));

        // One already running -> only 1 more runnable.
        assert_eq!(scheduler.runnable(&tasks, 1).len(), 1);
        // Fully loaded -> none runnable.
        assert!(scheduler.runnable(&tasks, 2).is_empty());
    }
}
