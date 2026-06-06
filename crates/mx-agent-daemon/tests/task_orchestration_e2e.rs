//! End-to-end test for daemon-driven task orchestration (issue #171).
//!
//! This drives the daemon's *real* task-orchestration subsystem end to end —
//! the [`TaskScheduler`] deciding what is runnable, the [`TaskOrchestrator`]
//! authorizing against local deny-by-default policy and claiming with optimistic
//! `state_rev` concurrency, and a concrete [`ExecTaskDispatcher`] running real
//! subprocesses through the process runner — against a faithful in-memory model
//! of `com.mxagent.task.v1` room state. It then asserts the orchestration
//! acceptance criteria:
//!
//! 1. **Automatic task progression.** An assigned, runnable task moves
//!    `pending -> executing -> succeeded` on its own as the scheduler ticks,
//!    and the finalized result carries the invocation link and a non-sensitive
//!    summary.
//! 2. **Dependencies block execution until satisfied.** A task that depends on
//!    another does not run while the dependency is unfinished, and starts only
//!    once the dependency has succeeded.
//! 3. **A denied task action does not execute.** A task whose command is not
//!    allowlisted is blocked by local policy and its process never spawns
//!    (proven by a sentinel file the command would have created).
//! 4. **No secrets appear in captured logs.** The whole run is observed under a
//!    capturing `tracing` subscriber; a planted secret in the daemon's
//!    environment is scrubbed by the runner and never appears in the logs.
//!
//! Like `tests/chaos.rs`, this needs no live homeserver: the only boundary the
//! daemon-driven scheduler has against Matrix is the `TaskStore` (room state
//! read/write), which is modelled here exactly as the real `update_task`
//! optimistic-concurrency contract. That keeps the test deterministic and part
//! of the default `cargo test --all` run. It drives the same
//! [`mx_agent_daemon::run_scheduler_tick`] the live daemon scheduler loop uses
//! (issue #199), so the in-memory store stands in only for real
//! `com.mxagent.task.v1` room state; a true live `/sync`-driven run is covered
//! behind the Docker-gated Matrix integration suite.

use std::collections::{BTreeSet, HashMap};
use std::io::Write;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use mx_agent_daemon::{
    ExecTaskDispatcher, OrchestrationOutcome, TaskDispatcher, TaskOrchestrator, TaskScheduler,
    TaskStore, TaskStoreError, UpdateTaskOptions, STATE_BLOCKED, STATE_EXECUTING, STATE_PENDING,
    STATE_SUCCEEDED,
};
use mx_agent_policy::Policy;
use mx_agent_protocol::schema::{Extra, TaskAction, TaskState};

/// The local daemon agent that owns and runs the workspace's assigned tasks.
const LOCAL_AGENT: &str = "agent-local";
/// The Matrix user id that authored the tasks (the policy's requesting agent).
const PLANNER: &str = "@planner:mx-agent.test";
/// A room the local policy trusts for raw exec.
const ROOM_ID: &str = "!orchestration:mx-agent.test";
/// Planted secret value that must never leak into logs or results.
const PLANTED_SECRET: &str = "super-secret-token-value-do-not-log";

/// A faithful in-memory model of `com.mxagent.task.v1` room state.
///
/// It enforces the same optimistic-concurrency contract as the real
/// `update_task`: a claim/finalize carrying an `expected_state_rev` is applied
/// only when the task is still at that revision, otherwise it is rejected as a
/// stale claim. Each task's observed `state` history is recorded so the test can
/// prove the `pending -> executing -> succeeded` progression.
#[derive(Default)]
struct RoomTaskStore {
    tasks: HashMap<String, TaskState>,
    history: HashMap<String, Vec<String>>,
}

impl RoomTaskStore {
    fn insert(&mut self, task: TaskState) {
        self.history
            .entry(task.task_id.clone())
            .or_default()
            .push(task.state.clone());
        self.tasks.insert(task.task_id.clone(), task);
    }

    fn snapshot(&self) -> Vec<TaskState> {
        let mut tasks: Vec<TaskState> = self.tasks.values().cloned().collect();
        tasks.sort_by(|a, b| a.task_id.cmp(&b.task_id));
        tasks
    }

    fn get(&self, task_id: &str) -> &TaskState {
        self.tasks.get(task_id).expect("task exists")
    }

    fn apply(&mut self, options: &UpdateTaskOptions) -> Result<TaskState, TaskStoreError> {
        let task = self
            .tasks
            .get_mut(&options.task_id)
            .ok_or_else(|| TaskStoreError::NotFound(options.task_id.clone()))?;
        if let Some(expected) = options.expected_state_rev {
            if expected != task.state_rev {
                return Err(TaskStoreError::StaleClaim {
                    task_id: options.task_id.clone(),
                    expected,
                    current: task.state_rev,
                });
            }
        }
        if let Some(state) = &options.state {
            task.state = state.clone();
        }
        if let Some(assigned_to) = &options.assigned_to {
            task.assigned_to = assigned_to.clone();
        }
        if let Some(invocation_id) = &options.invocation_id {
            task.invocation_id = Some(invocation_id.clone());
        }
        if let Some(result) = &options.result {
            task.result = Some(result.clone());
        }
        task.state_rev += 1;
        let snapshot = task.clone();
        self.history
            .entry(snapshot.task_id.clone())
            .or_default()
            .push(snapshot.state.clone());
        Ok(snapshot)
    }
}

impl TaskStore for RoomTaskStore {
    fn claim(&mut self, options: UpdateTaskOptions) -> Result<TaskState, TaskStoreError> {
        self.apply(&options)
    }
    fn finalize(&mut self, options: UpdateTaskOptions) -> Result<TaskState, TaskStoreError> {
        self.apply(&options)
    }
}

/// A capturing `tracing` writer so the test can assert on emitted log text.
#[derive(Clone, Default)]
struct LogBuffer(Arc<Mutex<Vec<u8>>>);

impl LogBuffer {
    fn contents(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
}

impl Write for LogBuffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogBuffer {
    type Writer = LogBuffer;
    fn make_writer(&'a self) -> LogBuffer {
        self.clone()
    }
}

/// Build a base `com.mxagent.task.v1` record for `task_id`.
fn task(task_id: &str, command: &[&str], cwd: &str) -> TaskState {
    TaskState {
        task_id: task_id.to_string(),
        title: task_id.to_string(),
        description: String::new(),
        state: STATE_PENDING.to_string(),
        assigned_to: LOCAL_AGENT.to_string(),
        created_by: PLANNER.to_string(),
        depends_on: Vec::new(),
        blocks: Vec::new(),
        invocation_id: None,
        created_at: "2026-06-04T18:00:00Z".to_string(),
        updated_at: "2026-06-04T18:00:00Z".to_string(),
        state_rev: 1,
        previous_event_id: None,
        result: None,
        action: Some(TaskAction::Exec {
            command: command.iter().map(|s| s.to_string()).collect(),
            cwd: cwd.to_string(),
            env: Default::default(),
            timeout_ms: Some(60_000),
            stream: false,
            authorization: None,
        }),
        extra: Extra::default(),
    }
}

/// A trusted room policy that allows the local planner to run `sh` in `cwd`.
///
/// `touch` is deliberately *not* allowlisted, so a task that tries to run it is
/// denied by policy and never spawns.
fn policy(cwd: &str) -> Policy {
    Policy::parse(&format!(
        r#"
[rooms."{ROOM_ID}"]
trusted = true
raw_exec_default = "deny"

[rooms."{ROOM_ID}".agents."{PLANNER}"]
allow_exec = true
allow_commands = ["sh"]
allow_cwd = ["{cwd}"]
"#
    ))
    .expect("policy parses")
}

/// Run one scheduler tick through the shared library entry point the live
/// daemon scheduler loop uses (recovery over `executing` tasks, then schedule
/// and process runnable tasks).
fn tick(
    scheduler: &TaskScheduler,
    orchestrator: &TaskOrchestrator,
    store: &mut RoomTaskStore,
    dispatcher: &mut impl TaskDispatcher,
) -> Vec<OrchestrationOutcome> {
    let snapshot = store.snapshot();
    // No long-lived local invocations across a synchronous tick, so recovery
    // sees an empty live set (matching the live loop's local-dispatch path).
    let live_invocations = BTreeSet::new();
    // A fresh attempt set per tick: the in-memory store updates synchronously,
    // so there is no stale re-read to dedupe (unlike the live loop).
    let mut attempted = std::collections::HashSet::new();
    mx_agent_daemon::run_scheduler_tick(
        scheduler,
        orchestrator,
        &snapshot,
        &live_invocations,
        store,
        dispatcher,
        &mut attempted,
    )
}

#[test]
fn daemon_drives_tasks_through_policy_dependencies_and_denial() {
    // A throwaway workspace directory the allowed commands run in.
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let workspace = std::env::temp_dir().join(format!(
        "mx-agent-orch-e2e-{}-{}-{}",
        std::process::id(),
        nanos,
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&workspace).expect("create workspace");
    let cwd = workspace.to_string_lossy().into_owned();
    // The sentinel the denied task would create if it ever spawned.
    let sentinel = workspace.join("denied-ran");

    // Plant a secret in the daemon's environment. The runner's allowlist-based
    // env scrubbing must keep it out of the child and out of any logs. This test
    // is the only one in its binary, so the process-global env is not shared.
    std::env::set_var("GITHUB_TOKEN", PLANTED_SECRET);

    let mut store = RoomTaskStore::default();
    // task-plan: a harmless allowed command that echoes the (scrubbed) secret.
    store.insert(task(
        "task-plan",
        &["sh", "-c", "echo \"GH=[$GITHUB_TOKEN]\""],
        &cwd,
    ));
    // task-test: depends on task-plan; must not run until it succeeds.
    let mut test_task = task("task-test", &["sh", "-c", "exit 0"], &cwd);
    test_task.depends_on = vec!["task-plan".to_string()];
    store.insert(test_task);
    // task-denied: a non-allowlisted command that would create the sentinel.
    store.insert(task(
        "task-denied",
        &["touch", sentinel.to_string_lossy().as_ref()],
        &cwd,
    ));

    let scheduler = TaskScheduler::new(LOCAL_AGENT, 4);
    let orchestrator = TaskOrchestrator::new(LOCAL_AGENT)
        .with_room_id(ROOM_ID)
        .with_policy(policy(&cwd));
    let mut dispatcher = ExecTaskDispatcher::new();

    // Observe the whole run under a capturing subscriber so we can assert that
    // no secret leaks into logs. Scoped (not global) so it cannot clash with
    // other tests' subscribers.
    let log = LogBuffer::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(log.clone())
        .with_max_level(tracing::Level::DEBUG)
        .with_ansi(false)
        .finish();

    let (after_tick1, after_tick2) = tracing::subscriber::with_default(subscriber, || {
        // Tick 1: task-plan runs; task-test is dependency-blocked; task-denied is
        // denied by policy.
        let outcomes1 = tick(&scheduler, &orchestrator, &mut store, &mut dispatcher);
        let t1 = (
            store.get("task-plan").state.clone(),
            store.get("task-test").state.clone(),
            store.get("task-denied").state.clone(),
        );
        // Tick 2: with task-plan succeeded, task-test becomes runnable and runs.
        let outcomes2 = tick(&scheduler, &orchestrator, &mut store, &mut dispatcher);
        let t2 = store.get("task-test").state.clone();
        ((outcomes1, t1), (outcomes2, t2))
    });

    let (outcomes1, (plan1, test1, denied1)) = after_tick1;
    let (_outcomes2, test2) = after_tick2;

    // --- 1. Automatic progression: pending -> executing -> succeeded ---------
    assert_eq!(plan1, STATE_SUCCEEDED, "task-plan should auto-progress");
    assert!(
        outcomes1.iter().any(
            |o| matches!(o, OrchestrationOutcome::Completed { task_id, state, .. }
                if task_id == "task-plan" && state == STATE_SUCCEEDED)
        ),
        "expected task-plan completion outcome, got {outcomes1:?}"
    );
    let plan_history = store.history.get("task-plan").unwrap();
    assert!(
        plan_history.iter().any(|s| s == STATE_EXECUTING)
            && plan_history.iter().any(|s| s == STATE_SUCCEEDED),
        "task-plan must pass through executing then succeeded: {plan_history:?}"
    );
    // Result carries the invocation link and a non-sensitive summary.
    let plan_result = store.get("task-plan").result.clone().expect("plan result");
    assert_eq!(
        plan_result.get("status").and_then(|v| v.as_str()),
        Some("succeeded")
    );
    assert!(plan_result
        .get("invocation_id")
        .and_then(|v| v.as_str())
        .is_some_and(|s| !s.is_empty()));
    assert!(plan_result
        .get("summary")
        .and_then(|v| v.as_str())
        .is_some());

    // --- 2. Dependencies block until satisfied -------------------------------
    assert_eq!(
        test1, STATE_PENDING,
        "task-test must stay pending while its dependency is unfinished"
    );
    assert_eq!(
        test2, STATE_SUCCEEDED,
        "task-test must run only after its dependency succeeded"
    );

    // --- 3. Denied task action does not execute ------------------------------
    assert_eq!(
        denied1, STATE_BLOCKED,
        "policy-denied task must be blocked, not executed"
    );
    assert!(
        !sentinel.exists(),
        "denied task's command must never spawn (sentinel must not exist)"
    );
    let denied_result = store
        .get("task-denied")
        .result
        .clone()
        .expect("denied result");
    assert_eq!(
        denied_result.get("reason").and_then(|v| v.as_str()),
        Some("policy_denied")
    );
    assert!(
        denied_result
            .get("exit_code")
            .and_then(|v| v.as_i64())
            .is_none(),
        "a denied task never produced a process exit code"
    );

    // --- 4. No secrets in captured logs --------------------------------------
    let logs = log.contents();
    assert!(
        !logs.contains(PLANTED_SECRET),
        "captured logs must not contain the planted secret"
    );
    // And the secret never reached any task result either.
    let all_results = store
        .snapshot()
        .iter()
        .filter_map(|t| t.result.clone())
        .map(|r| r.to_string())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !all_results.contains(PLANTED_SECRET),
        "task results must not contain the planted secret"
    );

    // Cleanup.
    std::env::remove_var("GITHUB_TOKEN");
    let _ = std::fs::remove_dir_all(&workspace);
}
