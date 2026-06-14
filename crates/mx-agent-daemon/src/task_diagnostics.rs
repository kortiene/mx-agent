//! Non-blocking diagnostics for a workspace's task DAG (issue #170).
//!
//! A Matrix room can legitimately hold confusing task state: duplicate titles,
//! dependency cycles, dangling dependency IDs, tasks assigned to agents that do
//! not exist or are no longer active, runnable tasks with no executable action,
//! or tool actions the assigned agent does not offer. None of these are errors —
//! Matrix room state cannot enforce DAG invariants and advanced workflows may be
//! intentional — so this module only *surfaces* them as warnings. It never
//! rejects or mutates task state.
//!
//! [`diagnose_tasks`] is a pure function over the room's tasks and (optionally)
//! its agents. The agent-dependent checks are skipped entirely when no agent
//! state is available, so a missing agent snapshot never produces misleading
//! warnings.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::time::{SystemTime, UNIX_EPOCH};

use mx_agent_protocol::schema::{AgentState, TaskAction, TaskState};
use serde::{Deserialize, Serialize};

use crate::heartbeat::{Liveness, LivenessConfig};
use crate::task::is_runnable;
use crate::task_graph::TaskGraph;
use crate::task_orchestrator::action_from_task;

/// Severity of a [`TaskDiagnostic`]. Diagnostics are advisory; the only severity
/// today is [`Severity::Warning`], but the field keeps the JSON shape stable if
/// stronger severities are added later.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// A non-blocking warning: the workspace is valid but possibly confusing.
    Warning,
}

/// A single non-blocking diagnostic about the task DAG.
///
/// `kind` is a stable, machine-readable identifier (e.g. `"duplicate_title"`)
/// for `--json` consumers; `message` is a human-readable explanation; `task_id`
/// names the task the diagnostic is about, when it concerns a single task.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskDiagnostic {
    /// Diagnostic severity (currently always `warning`).
    pub severity: Severity,
    /// Stable, machine-readable diagnostic kind.
    pub kind: String,
    /// Task this diagnostic concerns, when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_id: Option<String>,
    /// Human-readable explanation.
    pub message: String,
}

impl TaskDiagnostic {
    fn warning(kind: &str, task_id: Option<String>, message: String) -> Self {
        Self {
            severity: Severity::Warning,
            kind: kind.to_string(),
            task_id,
            message,
        }
    }
}

/// Diagnostic kind: two or more tasks share a non-empty title.
pub const KIND_DUPLICATE_TITLE: &str = "duplicate_title";
/// Diagnostic kind: the `depends_on` graph contains a cycle.
pub const KIND_DEPENDENCY_CYCLE: &str = "dependency_cycle";
/// Diagnostic kind: a `depends_on` entry names a task not present in the room.
pub const KIND_MISSING_DEPENDENCY: &str = "missing_dependency";
/// Diagnostic kind: a task is assigned to an agent not present in the room.
pub const KIND_UNKNOWN_AGENT: &str = "assigned_to_unknown_agent";
/// Diagnostic kind: a task is assigned to an agent that is not active.
pub const KIND_INACTIVE_AGENT: &str = "assigned_to_inactive_agent";
/// Diagnostic kind: a schedulable, assigned task has no executable action.
pub const KIND_RUNNABLE_WITHOUT_ACTION: &str = "runnable_without_action";
/// Diagnostic kind: a tool action's tool is not offered by the assigned agent.
pub const KIND_TOOL_UNAVAILABLE: &str = "tool_unavailable";

/// Compute non-blocking diagnostics for a room's `tasks` and `agents`.
///
/// When `agents` is empty the agent-dependent checks (unknown/inactive agent,
/// tool availability) are skipped, so an unavailable agent snapshot never yields
/// misleading warnings. Liveness is evaluated against the current wall clock; use
/// [`diagnose_tasks_at`] for a deterministic time in tests.
///
/// `liveness` supplies a precomputed, heartbeat-enriched verdict per `agent_id`
/// (typically from [`crate::agent::list_agents_with_liveness_for_session`]). The
/// inactive-agent check uses it so a healthy agent that is heartbeating but whose
/// durable `last_seen_ts` has aged past the stale threshold (it is only refreshed
/// every ~300 s) does not produce a false `assigned_to_inactive_agent` warning
/// (issue #312). An agent absent from the map falls back to durable-only
/// [`LivenessConfig::liveness_of`], so callers with no heartbeat data (e.g. an
/// empty map) get the previous durable-only behavior.
pub fn diagnose_tasks(
    tasks: &[TaskState],
    agents: &[AgentState],
    liveness: &HashMap<String, Liveness>,
) -> Vec<TaskDiagnostic> {
    diagnose_tasks_at(tasks, agents, liveness, now_ms())
}

/// Like [`diagnose_tasks`] but evaluates agent liveness as of `now_ms`
/// (milliseconds since the Unix epoch) for deterministic testing.
pub fn diagnose_tasks_at(
    tasks: &[TaskState],
    agents: &[AgentState],
    liveness: &HashMap<String, Liveness>,
    now_ms: u64,
) -> Vec<TaskDiagnostic> {
    let mut out = Vec::new();

    // Duplicate titles.
    let mut by_title: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for task in tasks {
        if !task.title.is_empty() {
            by_title
                .entry(task.title.as_str())
                .or_default()
                .push(task.task_id.as_str());
        }
    }
    for (title, ids) in &by_title {
        if ids.len() > 1 {
            out.push(TaskDiagnostic::warning(
                KIND_DUPLICATE_TITLE,
                None,
                format!(
                    "{} tasks share the title {title:?}: {}",
                    ids.len(),
                    ids.join(", ")
                ),
            ));
        }
    }

    // Dependency cycles (reuse the DAG analysis).
    for cycle in &TaskGraph::from_tasks(tasks).cycles {
        out.push(TaskDiagnostic::warning(
            KIND_DEPENDENCY_CYCLE,
            cycle.first().cloned(),
            format!("dependency cycle: {}", cycle.join(" -> ")),
        ));
    }

    // Missing dependency IDs.
    let present: BTreeSet<&str> = tasks.iter().map(|t| t.task_id.as_str()).collect();
    for task in tasks {
        for dep in &task.depends_on {
            if !present.contains(dep.as_str()) {
                out.push(TaskDiagnostic::warning(
                    KIND_MISSING_DEPENDENCY,
                    Some(task.task_id.clone()),
                    format!("task {:?} depends on missing task {dep:?}", task.task_id),
                ));
            }
        }
    }

    // Agent-dependent checks (only when an agent snapshot is available).
    if !agents.is_empty() {
        let by_id: BTreeMap<&str, &AgentState> =
            agents.iter().map(|a| (a.agent_id.as_str(), a)).collect();
        let cfg = LivenessConfig::default();
        for task in tasks {
            if task.assigned_to.is_empty() {
                continue;
            }
            match by_id.get(task.assigned_to.as_str()) {
                None => out.push(TaskDiagnostic::warning(
                    KIND_UNKNOWN_AGENT,
                    Some(task.task_id.clone()),
                    format!(
                        "task {:?} is assigned to unknown agent {:?}",
                        task.task_id, task.assigned_to
                    ),
                )),
                Some(agent) => {
                    // Prefer the precomputed (heartbeat-enriched) verdict; fall
                    // back to durable-only liveness when the agent has no entry.
                    let verdict = liveness
                        .get(agent.agent_id.as_str())
                        .copied()
                        .unwrap_or_else(|| cfg.liveness_of(agent, now_ms));
                    if verdict != Liveness::Active {
                        out.push(TaskDiagnostic::warning(
                            KIND_INACTIVE_AGENT,
                            Some(task.task_id.clone()),
                            format!(
                                "task {:?} is assigned to inactive agent {:?}",
                                task.task_id, task.assigned_to
                            ),
                        ));
                    }
                    if let Ok(TaskAction::Tool { tool, .. }) = action_from_task(task) {
                        let offered = agent
                            .tools
                            .iter()
                            .any(|q| q.split('@').next() == Some(tool.as_str()));
                        if !offered {
                            out.push(TaskDiagnostic::warning(
                                KIND_TOOL_UNAVAILABLE,
                                Some(task.task_id.clone()),
                                format!(
                                    "task {:?} requires tool {:?}, not offered by agent {:?}",
                                    task.task_id, tool, task.assigned_to
                                ),
                            ));
                        }
                    }
                }
            }
        }
    }

    // Runnable, assigned tasks that have no executable action.
    for task in tasks {
        if is_runnable(&task.state)
            && !task.assigned_to.is_empty()
            && action_from_task(task).is_err()
        {
            out.push(TaskDiagnostic::warning(
                KIND_RUNNABLE_WITHOUT_ACTION,
                Some(task.task_id.clone()),
                format!(
                    "task {:?} is assigned and {} but has no executable action",
                    task.task_id, task.state
                ),
            ));
        }
    }

    out
}

/// Current epoch time in milliseconds.
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use mx_agent_protocol::schema::{AgentLoad, AgentWorkspace, Extra};
    use serde_json::json;

    fn task(id: &str, title: &str, state: &str, assigned_to: &str) -> TaskState {
        TaskState {
            task_id: id.to_string(),
            title: title.to_string(),
            description: String::new(),
            state: state.to_string(),
            assigned_to: assigned_to.to_string(),
            created_by: "@planner:server".to_string(),
            depends_on: Vec::new(),
            blocks: Vec::new(),
            invocation_id: None,
            created_at: "2026-06-04T18:00:00Z".to_string(),
            updated_at: "2026-06-04T18:00:00Z".to_string(),
            state_rev: 1,
            previous_event_id: None,
            result: None,
            action: None,
            extra: Extra::default(),
        }
    }

    fn with_tool(mut t: TaskState, tool: &str) -> TaskState {
        t.action = Some(TaskAction::Tool {
            tool: tool.to_string(),
            args: json!({}),
            authorization: None,
        });
        t
    }

    fn agent(agent_id: &str, last_seen_ts: u64, tools: &[&str]) -> AgentState {
        AgentState {
            agent_id: agent_id.to_string(),
            kind: "pi".to_string(),
            matrix_user_id: format!("@{agent_id}:server"),
            device_id: "DEV".to_string(),
            signing_key_id: "mxagent-ed25519:abc".to_string(),
            signing_public_key: None,
            status: "active".to_string(),
            capabilities: Vec::new(),
            tools: tools.iter().map(|s| s.to_string()).collect(),
            workspace: AgentWorkspace {
                cwd: "/repo".to_string(),
                project_id: String::new(),
                git_commit: String::new(),
            },
            load: AgentLoad {
                running_invocations: 0,
                max_invocations: 4,
            },
            last_seen_ts,
            state_rev: 1,
            extra: Extra::default(),
        }
    }

    fn kinds(diags: &[TaskDiagnostic]) -> Vec<&str> {
        diags.iter().map(|d| d.kind.as_str()).collect()
    }

    /// Diagnose with no precomputed liveness verdicts, so the inactive-agent
    /// check falls back to durable-only liveness (the pre-issue-#312 behavior).
    fn diag_at(tasks: &[TaskState], agents: &[AgentState], now_ms: u64) -> Vec<TaskDiagnostic> {
        diagnose_tasks_at(tasks, agents, &HashMap::new(), now_ms)
    }

    #[test]
    fn detects_duplicate_titles() {
        let tasks = vec![
            with_tool(task("task-a", "Run tests", "pending", ""), "run_tests"),
            with_tool(task("task-b", "Run tests", "pending", ""), "run_tests"),
        ];
        let diags = diag_at(&tasks, &[], 0);
        let dup: Vec<&TaskDiagnostic> = diags
            .iter()
            .filter(|d| d.kind == KIND_DUPLICATE_TITLE)
            .collect();
        assert_eq!(dup.len(), 1);
        assert!(dup[0].message.contains("task-a"));
        assert!(dup[0].message.contains("task-b"));
    }

    #[test]
    fn detects_dependency_cycle() {
        let mut a = with_tool(task("task-a", "A", "pending", ""), "run_tests");
        let mut b = with_tool(task("task-b", "B", "pending", ""), "run_tests");
        a.depends_on = vec!["task-b".to_string()];
        b.depends_on = vec!["task-a".to_string()];
        let diags = diag_at(&[a, b], &[], 0);
        assert!(kinds(&diags).contains(&KIND_DEPENDENCY_CYCLE));
    }

    #[test]
    fn detects_missing_dependency() {
        let mut t = with_tool(task("task-a", "A", "pending", ""), "run_tests");
        t.depends_on = vec!["task-ghost".to_string()];
        let diags = diag_at(std::slice::from_ref(&t), &[], 0);
        let missing: Vec<&TaskDiagnostic> = diags
            .iter()
            .filter(|d| d.kind == KIND_MISSING_DEPENDENCY)
            .collect();
        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0].task_id.as_deref(), Some("task-a"));
        assert!(missing[0].message.contains("task-ghost"));
    }

    #[test]
    fn detects_unknown_and_inactive_agents() {
        let now = 10_000_000u64;
        let assigned_unknown =
            with_tool(task("task-a", "A", "pending", "ghost-agent"), "run_tests");
        let assigned_inactive = with_tool(task("task-b", "B", "pending", "sleepy"), "run_tests");
        // `sleepy` was last seen long ago -> offline/inactive.
        let agents = vec![agent("sleepy", 0, &["run_tests@1.0.0"])];
        let diags = diag_at(&[assigned_unknown, assigned_inactive], &agents, now);
        let ks = kinds(&diags);
        assert!(ks.contains(&KIND_UNKNOWN_AGENT));
        assert!(ks.contains(&KIND_INACTIVE_AGENT));
    }

    #[test]
    fn detects_tool_unavailable() {
        let now = 1_000u64;
        // Active agent that offers `lint`, not `run_tests`.
        let agents = vec![agent("dev", now, &["lint@1.0.0"])];
        let t = with_tool(task("task-a", "A", "pending", "dev"), "run_tests");
        let diags = diag_at(std::slice::from_ref(&t), &agents, now);
        let tool: Vec<&TaskDiagnostic> = diags
            .iter()
            .filter(|d| d.kind == KIND_TOOL_UNAVAILABLE)
            .collect();
        assert_eq!(tool.len(), 1);
        assert!(tool[0].message.contains("run_tests"));
    }

    #[test]
    fn detects_runnable_task_without_action() {
        // Assigned + pending but no action.
        let t = task("task-a", "A", "pending", "dev");
        let diags = diag_at(std::slice::from_ref(&t), &[], 0);
        assert!(kinds(&diags).contains(&KIND_RUNNABLE_WITHOUT_ACTION));

        // An unassigned planning task with no action is fine (no warning).
        let planning = task("task-plan", "Plan", "pending", "");
        let diags = diag_at(std::slice::from_ref(&planning), &[], 0);
        assert!(!kinds(&diags).contains(&KIND_RUNNABLE_WITHOUT_ACTION));
    }

    #[test]
    fn agent_checks_skipped_without_agent_data() {
        // A task assigned to an unknown agent must NOT warn when no agent
        // snapshot is available (avoids misleading diagnostics).
        let t = with_tool(task("task-a", "A", "pending", "ghost"), "run_tests");
        let diags = diag_at(std::slice::from_ref(&t), &[], 0);
        let ks = kinds(&diags);
        assert!(!ks.contains(&KIND_UNKNOWN_AGENT));
        assert!(!ks.contains(&KIND_INACTIVE_AGENT));
        assert!(!ks.contains(&KIND_TOOL_UNAVAILABLE));
    }

    #[test]
    fn active_agent_with_offered_tool_has_no_agent_warnings() {
        let now = 1_000u64;
        let agents = vec![agent("dev", now, &["run_tests@1.0.0"])];
        let t = with_tool(task("task-a", "A", "pending", "dev"), "run_tests");
        let diags = diag_at(std::slice::from_ref(&t), &agents, now);
        assert!(diags.is_empty(), "unexpected diagnostics: {diags:?}");
    }

    #[test]
    fn heartbeat_verdict_suppresses_false_inactive_warning() {
        // The durable state alone is offline (last seen long ago), which without
        // a heartbeat would raise `assigned_to_inactive_agent` (issue #312)...
        let now = 10_000_000u64;
        let agents = vec![agent("dev", 0, &["run_tests@1.0.0"])];
        let t = with_tool(task("task-a", "A", "pending", "dev"), "run_tests");
        assert!(
            kinds(&diag_at(std::slice::from_ref(&t), &agents, now)).contains(&KIND_INACTIVE_AGENT),
            "durable-only liveness should warn for a long-idle agent"
        );
        // ...but a supplied `Active` verdict (a recent heartbeat lifted it) must
        // suppress the warning.
        let liveness: HashMap<String, Liveness> = [("dev".to_string(), Liveness::Active)]
            .into_iter()
            .collect();
        let diags = diagnose_tasks_at(std::slice::from_ref(&t), &agents, &liveness, now);
        assert!(
            !kinds(&diags).contains(&KIND_INACTIVE_AGENT),
            "a heartbeat-lifted Active verdict must not warn: {diags:?}"
        );
    }

    #[test]
    fn stale_heartbeat_still_warns_inactive() {
        // When both signals are stale (durable offline and the supplied verdict
        // is also non-Active), the inactive-agent warning still fires.
        let now = 10_000_000u64;
        let agents = vec![agent("dev", 0, &["run_tests@1.0.0"])];
        let t = with_tool(task("task-a", "A", "pending", "dev"), "run_tests");
        for verdict in [Liveness::Stale, Liveness::Offline] {
            let liveness: HashMap<String, Liveness> =
                [("dev".to_string(), verdict)].into_iter().collect();
            let diags = diagnose_tasks_at(std::slice::from_ref(&t), &agents, &liveness, now);
            assert!(
                kinds(&diags).contains(&KIND_INACTIVE_AGENT),
                "a {verdict} verdict must still warn inactive: {diags:?}"
            );
        }
    }

    #[test]
    fn liveness_map_fallback_is_per_agent_independent() {
        // Agent X is in the liveness map as Active → no inactive warning.
        // Agent Y is NOT in the liveness map → fallback to durable (offline) → warns.
        // The two evaluations must not interfere with each other.
        let now = 10_000_000u64;
        // Both agents have a durable state that is far offline.
        let agent_x = agent("agent-x", 0, &["run_tests@1.0.0"]);
        let agent_y = agent("agent-y", 0, &["run_tests@1.0.0"]);
        let task_x = with_tool(task("task-x", "X", "pending", "agent-x"), "run_tests");
        let task_y = with_tool(task("task-y", "Y", "pending", "agent-y"), "run_tests");

        // X has a precomputed Active verdict (heartbeat lifted it); Y is absent.
        let liveness: HashMap<String, Liveness> = [("agent-x".to_string(), Liveness::Active)]
            .into_iter()
            .collect();
        let agents = vec![agent_x, agent_y];
        let tasks = vec![task_x, task_y];
        let diags = diagnose_tasks_at(&tasks, &agents, &liveness, now);

        // task-x: agent-x is Active in the map → no inactive warning.
        assert!(
            !diags
                .iter()
                .any(|d| d.kind == KIND_INACTIVE_AGENT && d.task_id.as_deref() == Some("task-x")),
            "agent-x has Active verdict in liveness map; task-x must not warn inactive: {diags:?}"
        );
        // task-y: agent-y absent from map → fallback to durable (offline) → warns.
        assert!(
            diags
                .iter()
                .any(|d| d.kind == KIND_INACTIVE_AGENT && d.task_id.as_deref() == Some("task-y")),
            "agent-y absent from liveness map; task-y must warn inactive via durable fallback: {diags:?}"
        );
    }

    #[test]
    fn diagnostics_serialize_with_stable_fields() {
        let diag = TaskDiagnostic::warning(
            KIND_MISSING_DEPENDENCY,
            Some("task-a".to_string()),
            "msg".to_string(),
        );
        let value = serde_json::to_value(&diag).unwrap();
        assert_eq!(value["severity"], json!("warning"));
        assert_eq!(value["kind"], json!("missing_dependency"));
        assert_eq!(value["task_id"], json!("task-a"));
        assert_eq!(value["message"], json!("msg"));
    }
}
