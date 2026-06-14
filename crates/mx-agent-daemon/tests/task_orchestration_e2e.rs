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
//! The issue-#262 section at the bottom adds equivalent coverage for the
//! `TaskAction::Tool` / `ToolTaskDispatcher` path, proving that the
//! policy-resolved `Allowance` (sandbox backend, network, paths, env_allowlist)
//! is threaded from policy evaluation all the way through the orchestrator and
//! dispatcher to the built-in tool runner — the gap that #262 closed.
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

use std::cell::RefCell;
use std::collections::{BTreeSet, HashMap};
use std::io::Write;
use std::rc::Rc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use mx_agent_daemon::{
    sanitize_env, ExecTaskDispatcher, OrchestrationOutcome, RoutingDispatcher, TaskDispatcher,
    TaskOrchestrator, TaskScheduler, TaskStore, TaskStoreError, ToolResult, ToolTaskDispatcher,
    UpdateTaskOptions, STATE_BLOCKED, STATE_EXECUTING, STATE_PENDING, STATE_SUCCEEDED,
};
use mx_agent_policy::Policy;
use mx_agent_protocol::schema::{Extra, TaskAction, TaskState};
use serde_json::json;

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
    // No invocations claimed across a synchronous tick to remember, so recovery
    // starts from an empty this-run set (matching the live loop's local-dispatch
    // path on a fresh start).
    let mut claimed_invocations = BTreeSet::new();
    // A fresh attempt set per tick: the in-memory store updates synchronously,
    // so there is no stale re-read to dedupe (unlike the live loop).
    let mut attempted = std::collections::HashSet::new();
    // No invocation snapshot in this in-memory tick: every not-live executing
    // task is treated as a stale orphan (the historical recovery behavior).
    let invocations = std::collections::BTreeMap::new();
    mx_agent_daemon::run_scheduler_tick(
        scheduler,
        orchestrator,
        &snapshot,
        &invocations,
        &mut claimed_invocations,
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

// --- issue #248: sandbox policy settings flow end to end --------------------

/// Whether a minimal `bwrap` invocation works in this environment.
///
/// Returns `false` on any error — absent binary, kernel without user-namespace
/// support, CI sandbox, macOS — so bubblewrap tests skip gracefully. Mirrors
/// the check in `mx-agent-sandbox/src/lib.rs`.
fn bwrap_usable() -> bool {
    use std::process::Command;
    // Mirror the hardened flags `BubblewrapSandbox::prepare` emits (issue #310),
    // so the skip decision matches what the real run actually does.
    match Command::new("bwrap")
        .args([
            "--ro-bind",
            "/",
            "/",
            "--unshare-user",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--tmpfs",
            "/tmp",
            "--new-session",
            "--",
            "true",
        ])
        .output()
    {
        Ok(out) => out.status.success(),
        Err(_) => false,
    }
}

/// Return whether bwrap is usable; when it is not, either skip (default) or — if
/// `MX_AGENT_REQUIRE_BWRAP` is set — panic, so the CI `sandbox-linux` job fails
/// instead of silently skipping the real-bwrap coverage (issue #310).
fn bwrap_available_or_required() -> bool {
    if bwrap_usable() {
        return true;
    }
    if std::env::var_os("MX_AGENT_REQUIRE_BWRAP").is_some() {
        panic!(
            "MX_AGENT_REQUIRE_BWRAP is set but bwrap is not usable here; \
             the real-bwrap orchestration test must run (install bubblewrap / enable user namespaces)"
        );
    }
    false
}

/// System paths that a bubblewrap sandbox needs bound read-only for `sh` and
/// basic utilities to be resolvable inside the container.
fn base_ro_paths_for_bwrap() -> Vec<std::path::PathBuf> {
    ["/usr", "/bin", "/lib", "/lib64", "/etc"]
        .iter()
        .map(std::path::PathBuf::from)
        .filter(|p| p.exists())
        .collect()
}

/// Verify that policy sandbox settings (read_only_paths / writable_paths /
/// network / default_sandbox) flow through the full task orchestration stack
/// and reach the runner end to end (issue #248).
///
/// **Part 1 — Backend::None (always runs):**  A policy with `read_only_paths`,
/// `writable_paths`, and `network = "deny"` but no `default_sandbox` resolves
/// to the `none` backend.  The `none` backend ignores those settings by design,
/// so the command runs normally.  This proves the orchestration chain correctly
/// threads the allowance (carrying paths/network) without breaking backward
/// compatibility when no isolating backend is selected.
///
/// **Part 2 — Backend::Bubblewrap (skips when bwrap is unavailable):**  A
/// policy with `default_sandbox = "bubblewrap"` and correctly configured path
/// binds runs the command inside `bwrap`.  The sentinel file appears in the
/// writable workspace, proving that the configured paths flow all the way from
/// the policy engine through the allowance, the dispatcher, the RunSpec, and
/// into the real `bwrap` argv — and that `bwrap` actually bound the filesystem
/// as configured.
#[test]
fn sandbox_policy_settings_flow_through_task_orchestration() {
    static SANDBOX_COUNTER: AtomicU32 = AtomicU32::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();

    // --- Part 1: Backend::None with path/network settings in policy. ---------
    //
    // The orchestration chain must resolve the allowance (with read_only_paths,
    // writable_paths, and network) and thread it into the dispatcher even when
    // the backend is `none`.  The `none` backend ignores the confinement — the
    // command runs normally.
    let workspace = std::env::temp_dir().join(format!(
        "mx-agent-sandbox-e2e-none-{}-{}-{}",
        std::process::id(),
        nanos,
        SANDBOX_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&workspace).expect("create workspace");
    let cwd = workspace.to_string_lossy().into_owned();
    let sentinel = workspace.join("ran");

    // Policy has path/network settings but no default_sandbox → Backend::None.
    let policy_none = Policy::parse(&format!(
        r#"
[execution]
network = "deny"
read_only_paths = ["{cwd}"]
writable_paths = ["{cwd}"]

[rooms."{ROOM_ID}"]
trusted = true
raw_exec_default = "deny"

[rooms."{ROOM_ID}".agents."{PLANNER}"]
allow_exec = true
allow_commands = ["sh"]
allow_cwd = ["{cwd}"]
"#
    ))
    .expect("none-backend policy parses");

    let cmd_none = format!("touch {}", sentinel.display());
    let mut store = RoomTaskStore::default();
    store.insert(task("task-none", &["sh", "-c", &cmd_none], &cwd));

    let scheduler = TaskScheduler::new(LOCAL_AGENT, 4);
    let orchestrator = TaskOrchestrator::new(LOCAL_AGENT)
        .with_room_id(ROOM_ID)
        .with_policy(policy_none);
    let mut dispatcher = ExecTaskDispatcher::new();
    tick(&scheduler, &orchestrator, &mut store, &mut dispatcher);

    assert_eq!(
        store.get("task-none").state,
        STATE_SUCCEEDED,
        "backend=none must not confine the command; policy path/network settings are ignored"
    );
    assert!(
        sentinel.exists(),
        "command must have run and created the sentinel (backend=none exec)"
    );
    let _ = std::fs::remove_dir_all(&workspace);

    // --- Part 2: Backend::Bubblewrap with real confinement. ------------------
    //
    // Skip gracefully when bwrap is absent or unprivileged user namespaces are
    // blocked (macOS, some CI sandboxes) — unless MX_AGENT_REQUIRE_BWRAP forces it
    // to run (the CI sandbox-linux job).
    if !bwrap_available_or_required() {
        eprintln!(
            "skipping sandbox_policy_settings_flow_through_task_orchestration (bubblewrap part): \
            bwrap not usable in this environment (macOS, absent binary, or no user-namespaces)"
        );
        return;
    }

    let workspace_bwrap = std::env::temp_dir().join(format!(
        "mx-agent-sandbox-e2e-bwrap-{}-{}-{}",
        std::process::id(),
        nanos,
        SANDBOX_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&workspace_bwrap).expect("create bwrap workspace");
    let cwd_bwrap = workspace_bwrap.to_string_lossy().into_owned();
    let sentinel_bwrap = workspace_bwrap.join("ran-bwrap");

    // Build the TOML read_only_paths array from the system paths sh needs.
    let ro_toml = base_ro_paths_for_bwrap()
        .iter()
        .map(|p| format!("\"{}\"", p.display()))
        .collect::<Vec<_>>()
        .join(", ");

    // Policy selects bubblewrap + network=allow + filesystem binds so the
    // command can run inside the sandbox and write to the writable workspace.
    let policy_bwrap = Policy::parse(&format!(
        r#"
[execution]
default_sandbox = "bubblewrap"
network = "allow"
read_only_paths = [{ro_toml}]
writable_paths = ["{cwd_bwrap}"]

[rooms."{ROOM_ID}"]
trusted = true
raw_exec_default = "deny"

[rooms."{ROOM_ID}".agents."{PLANNER}"]
allow_exec = true
allow_commands = ["sh"]
allow_cwd = ["{cwd_bwrap}"]
"#
    ))
    .expect("bubblewrap policy parses");

    let cmd_bwrap = format!("touch {}", sentinel_bwrap.display());
    let mut store_bwrap = RoomTaskStore::default();
    store_bwrap.insert(task("task-bwrap", &["sh", "-c", &cmd_bwrap], &cwd_bwrap));

    let scheduler_bwrap = TaskScheduler::new(LOCAL_AGENT, 4);
    let orchestrator_bwrap = TaskOrchestrator::new(LOCAL_AGENT)
        .with_room_id(ROOM_ID)
        .with_policy(policy_bwrap);
    let mut dispatcher_bwrap = ExecTaskDispatcher::new();
    tick(
        &scheduler_bwrap,
        &orchestrator_bwrap,
        &mut store_bwrap,
        &mut dispatcher_bwrap,
    );

    assert_eq!(
        store_bwrap.get("task-bwrap").state,
        STATE_SUCCEEDED,
        "bubblewrap-sandboxed task must succeed when paths are correctly configured \
        (read_only_paths covers system binaries, writable_paths covers the workspace)"
    );
    assert!(
        sentinel_bwrap.exists(),
        "bwrap must have bound the workspace writable end to end through the policy pipeline"
    );
    let _ = std::fs::remove_dir_all(&workspace_bwrap);
}

// --- issue #262: `TaskAction::Tool` path is confined end-to-end -------------
//
// Before the fix, `ToolTaskDispatcher` received an `_allowance` parameter but
// never forwarded it; the built-in tool runner used `std::process::Command`
// directly with no sandbox, no filesystem binds, and no env scrubbing.  These
// tests prove that the policy-resolved `Allowance` now flows from the policy
// engine through the orchestrator and dispatcher all the way to the tool runner,
// so a named tool is confined at least as strictly as `exec` (architecture
// §13.5).

/// Build a `TaskState` with `TaskAction::Tool` for `tool_name`, assigned to
/// [`LOCAL_AGENT`] and authored by [`PLANNER`].
fn tool_task(task_id: &str, tool_name: &str) -> TaskState {
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
        created_at: "2026-06-10T00:00:00Z".to_string(),
        updated_at: "2026-06-10T00:00:00Z".to_string(),
        state_rev: 1,
        previous_event_id: None,
        result: None,
        action: Some(TaskAction::Tool {
            tool: tool_name.to_string(),
            args: json!({ "package": "api" }),
            authorization: None,
        }),
        extra: Extra::default(),
    }
}

/// Minimal policy that permits the planner to invoke `run_tests` as a named
/// tool from [`ROOM_ID`].
fn tool_policy() -> Policy {
    Policy::parse(&format!(
        r#"
[rooms."{ROOM_ID}"]
trusted = true

[rooms."{ROOM_ID}".agents."{PLANNER}"]
allow_tools = ["run_tests"]
"#
    ))
    .expect("tool policy parses")
}

/// A tool policy that additionally sets `[execution]` confinement fields so we
/// can assert they reach the runner end to end (issue #262).
fn tool_policy_with_confinement() -> Policy {
    Policy::parse(&format!(
        r#"
[execution]
network = "deny"
env_allowlist = ["CARGO_HOME"]
read_only_paths = ["/usr"]

[rooms."{ROOM_ID}"]
trusted = true

[rooms."{ROOM_ID}".agents."{PLANNER}"]
allow_tools = ["run_tests"]
"#
    ))
    .expect("tool confinement policy parses")
}

/// A `TaskAction::Tool` task auto-progresses `pending → executing → succeeded`
/// through the full scheduler → orchestrator → `ToolTaskDispatcher` pipeline,
/// proving the named-tool path is fully wired into the orchestration stack.
#[test]
fn tool_task_auto_progresses_through_full_orchestration_pipeline() {
    let runner_called = Rc::new(RefCell::new(false));
    let runner_called_clone = runner_called.clone();

    let t = tool_task("task-tool-prog", "run_tests");
    let mut store = RoomTaskStore::default();
    store.insert(t);

    let scheduler = TaskScheduler::new(LOCAL_AGENT, 4);
    let orchestrator = TaskOrchestrator::new(LOCAL_AGENT)
        .with_room_id(ROOM_ID)
        .with_policy(tool_policy());

    let mut dispatcher = ToolTaskDispatcher::with_runner(move |name, _args, _al, _cwd| {
        assert_eq!(name, "run_tests");
        *runner_called_clone.borrow_mut() = true;
        Ok(ToolResult {
            exit_code: 0,
            summary: "tests passed".to_string(),
        })
    });

    let outcomes = tick(&scheduler, &orchestrator, &mut store, &mut dispatcher);

    assert!(*runner_called.borrow(), "tool runner must be called");
    assert_eq!(
        store.get("task-tool-prog").state,
        STATE_SUCCEEDED,
        "tool task must auto-progress to succeeded"
    );
    assert!(
        outcomes.iter().any(|o| matches!(
            o,
            OrchestrationOutcome::Completed { task_id, state, .. }
                if task_id == "task-tool-prog" && state == STATE_SUCCEEDED
        )),
        "orchestration must emit Completed outcome for tool task"
    );

    // State history must include the executing → succeeded progression.
    let history = store.history.get("task-tool-prog").unwrap();
    assert!(
        history.iter().any(|s| s == STATE_EXECUTING),
        "tool task must pass through executing: {history:?}"
    );
    assert!(
        history.iter().any(|s| s == STATE_SUCCEEDED),
        "tool task must reach succeeded: {history:?}"
    );

    // Finalized result must carry status, exit_code, and summary.
    let result = store
        .get("task-tool-prog")
        .result
        .clone()
        .expect("finalized result");
    assert_eq!(
        result.get("status").and_then(|v| v.as_str()),
        Some("succeeded")
    );
    assert_eq!(result.get("exit_code").and_then(|v| v.as_i64()), Some(0));
    assert!(result.get("summary").and_then(|v| v.as_str()).is_some());
}

/// A `TaskAction::Tool` task whose tool is not in `allow_tools` is denied by
/// local policy and finalized `blocked`, with the runner never called.
#[test]
fn policy_denied_tool_task_is_blocked_and_runner_not_called() {
    let t = tool_task("task-tool-denied", "forbidden_tool");
    let mut store = RoomTaskStore::default();
    store.insert(t);

    let scheduler = TaskScheduler::new(LOCAL_AGENT, 4);
    let orchestrator = TaskOrchestrator::new(LOCAL_AGENT)
        .with_room_id(ROOM_ID)
        .with_policy(tool_policy()); // only "run_tests" is allowed

    let mut dispatcher = ToolTaskDispatcher::with_runner(|_name, _args, _al, _cwd| {
        panic!("policy-denied tool must never reach the runner")
    });

    let outcomes = tick(&scheduler, &orchestrator, &mut store, &mut dispatcher);

    assert_eq!(
        store.get("task-tool-denied").state,
        STATE_BLOCKED,
        "policy-denied tool task must be finalized blocked"
    );
    assert!(
        outcomes
            .iter()
            .any(|o| matches!(o, OrchestrationOutcome::Denied { task_id, .. } if task_id == "task-tool-denied")),
        "orchestration must emit Denied outcome for disallowed tool"
    );
    let result = store
        .get("task-tool-denied")
        .result
        .clone()
        .expect("denied result");
    assert_eq!(
        result.get("reason").and_then(|v| v.as_str()),
        Some("policy_denied")
    );
    assert!(
        result.get("exit_code").and_then(|v| v.as_i64()).is_none(),
        "denied task must carry no exit code"
    );
}

/// The policy-resolved `Allowance` — carrying `sandbox`, `network`,
/// `read_only_paths`, and `env_allowlist` — is forwarded unchanged from the
/// policy engine through the orchestrator and dispatcher to the tool runner.
///
/// This is the critical fix for issue #262: previously the allowance was computed
/// but then discarded before execution; now it is threaded all the way through.
#[test]
fn tool_task_allowance_is_forwarded_end_to_end_through_orchestration() {
    let captured_allowance: Rc<RefCell<Option<mx_agent_policy::Allowance>>> =
        Rc::new(RefCell::new(None));
    let cap = captured_allowance.clone();

    let t = tool_task("task-tool-allowance", "run_tests");
    let mut store = RoomTaskStore::default();
    store.insert(t);

    let scheduler = TaskScheduler::new(LOCAL_AGENT, 4);
    let orchestrator = TaskOrchestrator::new(LOCAL_AGENT)
        .with_room_id(ROOM_ID)
        .with_policy(tool_policy_with_confinement());

    let mut dispatcher = ToolTaskDispatcher::with_runner(
        move |_name, _args, al: &mx_agent_policy::Allowance, _cwd| {
            *cap.borrow_mut() = Some(al.clone());
            Ok(ToolResult {
                exit_code: 0,
                summary: "ok".to_string(),
            })
        },
    );

    tick(&scheduler, &orchestrator, &mut store, &mut dispatcher);

    assert_eq!(
        store.get("task-tool-allowance").state,
        STATE_SUCCEEDED,
        "tool task with confinement policy must succeed"
    );

    let al = captured_allowance
        .borrow()
        .clone()
        .expect("runner must have been called and captured the allowance");

    // The policy sets network = "deny"; the allowance must carry that.
    assert_eq!(
        al.network,
        Some(mx_agent_policy::NetworkPolicy::Deny),
        "policy network=deny must reach the tool runner"
    );
    // The policy sets env_allowlist = ["CARGO_HOME"].
    assert_eq!(
        al.env_allowlist,
        vec!["CARGO_HOME".to_string()],
        "policy env_allowlist must reach the tool runner"
    );
    // The policy sets read_only_paths = ["/usr"].
    assert!(
        al.read_only_paths.iter().any(|p| p.as_os_str() == "/usr"),
        "policy read_only_paths must reach the tool runner; got {:?}",
        al.read_only_paths
    );
}

/// The `env_allowlist` flowing from policy through the tool runner's allowance
/// correctly drives `sanitize_env` to scrub known-secret variables, mirroring
/// the `exec` path's secret-scrubbing guarantee.
///
/// This test captures the allowance that reaches the tool runner via the full
/// orchestration pipeline and then calls `sanitize_env` with that allowlist to
/// assert a planted secret is dropped — proving the chain:
/// policy engine → allowance.env_allowlist → tool runner → sanitize_env.
#[test]
fn tool_task_env_allowlist_scrubs_secrets_end_to_end() {
    let captured: Rc<RefCell<Option<mx_agent_policy::Allowance>>> = Rc::new(RefCell::new(None));
    let cap = captured.clone();

    let t = tool_task("task-tool-env", "run_tests");
    let mut store = RoomTaskStore::default();
    store.insert(t);

    let scheduler = TaskScheduler::new(LOCAL_AGENT, 4);
    // Policy has env_allowlist = ["CARGO_HOME"] — GITHUB_TOKEN is not listed.
    let orchestrator = TaskOrchestrator::new(LOCAL_AGENT)
        .with_room_id(ROOM_ID)
        .with_policy(tool_policy_with_confinement());

    let mut dispatcher = ToolTaskDispatcher::with_runner(
        move |_name, _args, al: &mx_agent_policy::Allowance, _cwd| {
            *cap.borrow_mut() = Some(al.clone());
            Ok(ToolResult {
                exit_code: 0,
                summary: "ok".to_string(),
            })
        },
    );

    tick(&scheduler, &orchestrator, &mut store, &mut dispatcher);

    let al = captured
        .borrow()
        .clone()
        .expect("runner must have been called");

    // Simulate what the real runner does: sanitize the daemon's inherited env
    // using the policy-resolved allowlist.
    let inherited = vec![
        ("GITHUB_TOKEN".to_string(), "secret-value".to_string()),
        ("CARGO_HOME".to_string(), "/home/user/.cargo".to_string()),
        ("PATH".to_string(), "/usr/bin".to_string()),
    ];
    let sanitized = sanitize_env(inherited, &Default::default(), &al.env_allowlist);

    assert!(
        !sanitized.contains_key("GITHUB_TOKEN"),
        "GITHUB_TOKEN is a known-secret variable and must be scrubbed even if it were allowlisted"
    );
    assert!(
        sanitized.contains_key("PATH"),
        "PATH must survive scrubbing as a built-in safe default"
    );
}

/// The `RoutingDispatcher` correctly routes `TaskAction::Tool` to the tool
/// dispatcher and `TaskAction::Exec` to the exec dispatcher within the same
/// scheduler tick, proving the routing layer works for mixed-action workloads.
#[test]
fn routing_dispatcher_routes_tool_and_exec_tasks_in_same_tick() {
    static ROUTING_COUNTER: AtomicU32 = AtomicU32::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();

    let workspace = std::env::temp_dir().join(format!(
        "mx-agent-routing-e2e-{}-{}-{}",
        std::process::id(),
        nanos,
        ROUTING_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&workspace).expect("create workspace");
    let cwd = workspace.to_string_lossy().into_owned();

    let tool_called = Rc::new(RefCell::new(false));
    let tool_called_clone = tool_called.clone();

    // Mixed policy: allows run_tests (tool) AND sh (exec) from PLANNER.
    let mixed_policy = Policy::parse(&format!(
        r#"
[rooms."{ROOM_ID}"]
trusted = true
raw_exec_default = "deny"

[rooms."{ROOM_ID}".agents."{PLANNER}"]
allow_tools = ["run_tests"]
allow_exec = true
allow_commands = ["sh"]
allow_cwd = ["{cwd}"]
"#
    ))
    .expect("mixed policy parses");

    let mut store = RoomTaskStore::default();
    store.insert(tool_task("task-tool-mixed", "run_tests"));

    // Exec task: a simple `sh -c exit 0` in the workspace.
    let mut exec_t = task("task-exec-mixed", &["sh", "-c", "exit 0"], &cwd);
    exec_t.task_id = "task-exec-mixed".to_string();
    store.insert(exec_t);

    let scheduler = TaskScheduler::new(LOCAL_AGENT, 4);
    let orchestrator = TaskOrchestrator::new(LOCAL_AGENT)
        .with_room_id(ROOM_ID)
        .with_policy(mixed_policy);

    let tool_dispatcher = ToolTaskDispatcher::with_runner(move |_name, _args, _al, _cwd| {
        *tool_called_clone.borrow_mut() = true;
        Ok(ToolResult {
            exit_code: 0,
            summary: "tool ran".to_string(),
        })
    });
    let exec_dispatcher = ExecTaskDispatcher::new();
    let mut routing = RoutingDispatcher::new(tool_dispatcher, exec_dispatcher);

    tick(&scheduler, &orchestrator, &mut store, &mut routing);

    assert!(
        *tool_called.borrow(),
        "tool runner must be called for TaskAction::Tool"
    );
    assert_eq!(
        store.get("task-tool-mixed").state,
        STATE_SUCCEEDED,
        "tool task must succeed through routing dispatcher"
    );
    assert_eq!(
        store.get("task-exec-mixed").state,
        STATE_SUCCEEDED,
        "exec task must succeed through routing dispatcher"
    );

    let _ = std::fs::remove_dir_all(&workspace);
}

// --- issue #305: replay protection wired end-to-end through scheduler/orchestrator ---
//
// These tests cross the signing → trust → replay-cache → scheduler-tick →
// dispatch boundary that the existing tests cover only in isolation. They prove
// that:
//   1. A signed task action admitted through `run_scheduler_tick` (the real
//      scheduler entry point) is replay-blocked when the same nonce is
//      re-presented in a second tick — i.e. the replay cache is correctly
//      threaded from the orchestrator into the scheduler tick.
//   2. A benign optimistic-claim race (`StaleClaim`) un-burns the action's
//      single-use nonce so the next scheduler tick retries cleanly instead of
//      wedging the task blocked (the regression fixed in issue #305).
//
// Neither test requires a live homeserver; they drive `run_scheduler_tick` with
// an in-memory task store, a real tempdir-backed `ReplayCache`, and a
// deterministic Ed25519 signing key.

use ed25519_dalek::SigningKey as Ed25519SigningKey;
use mx_agent_daemon::{
    key_id_for_verifying_key, sign_task_action, ReplayCache, ReplayError, SessionPaths,
};

/// Deterministic signing key for issue #305 e2e tests.
fn key_305() -> Ed25519SigningKey {
    Ed25519SigningKey::from_bytes(&[55u8; 32])
}

/// A trust store that approves `PLANNER`'s key, plus the key ID string.
fn trust_305() -> (mx_agent_daemon::TrustStore, String) {
    let key = key_305();
    let key_id = key_id_for_verifying_key(&key.verifying_key());
    let mut trust = mx_agent_daemon::TrustStore::default();
    trust.approve(PLANNER, &key_id, None, None, None);
    (trust, key_id)
}

/// Build a tool task signed by `key_305` with `nonce` and a far-future expiry.
fn signed_tool_task_305(task_id: &str, nonce: &str) -> TaskState {
    let key = key_305();
    let (_, key_id) = trust_305();
    let base_action = TaskAction::Tool {
        tool: "run_tests".to_string(),
        args: json!({}),
        authorization: None,
    };
    let auth = sign_task_action(
        &key,
        &key_id,
        task_id,
        &base_action,
        PLANNER,
        LOCAL_AGENT,
        "2026-06-12T00:00:00Z",
        "2099-01-01T00:00:00Z",
        nonce,
    )
    .expect("sign task action");
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
        created_at: "2026-06-12T00:00:00Z".to_string(),
        updated_at: "2026-06-12T00:00:00Z".to_string(),
        state_rev: 1,
        previous_event_id: None,
        result: None,
        action: Some(TaskAction::Tool {
            tool: "run_tests".to_string(),
            args: json!({}),
            authorization: Some(auth),
        }),
        extra: Extra::default(),
    }
}

/// Create a tempdir-backed `ReplayCache` for use across multiple scheduler ticks.
fn tempdir_replay_cache(tag: &str) -> (ReplayCache, std::path::PathBuf) {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "mx-agent-replay-e2e-{}-{}-{}",
        tag,
        std::process::id(),
        nanos,
    ));
    std::fs::create_dir_all(&dir).expect("create replay dir");
    let paths = SessionPaths::for_data_dir(dir.clone());
    let cache = ReplayCache::load_with_capacity(&paths, 64).expect("replay cache loads");
    (cache, dir)
}

/// A `TaskStore` whose `claim` always returns `StaleClaim` (another daemon won).
struct StaleClaimStore {
    task: TaskState,
}

impl mx_agent_daemon::TaskStore for StaleClaimStore {
    fn claim(
        &mut self,
        options: mx_agent_daemon::UpdateTaskOptions,
    ) -> Result<TaskState, mx_agent_daemon::TaskStoreError> {
        Err(mx_agent_daemon::TaskStoreError::StaleClaim {
            task_id: options.task_id,
            expected: options.expected_state_rev.unwrap_or(1),
            current: options.expected_state_rev.unwrap_or(1) + 1,
        })
    }
    fn finalize(
        &mut self,
        _options: mx_agent_daemon::UpdateTaskOptions,
    ) -> Result<TaskState, mx_agent_daemon::TaskStoreError> {
        Ok(self.task.clone())
    }
}

/// A signed task action is admitted through `run_scheduler_tick` (the entry
/// point the live daemon loop uses) and the replay cache correctly blocks a
/// re-presentation of the same nonce in a subsequent tick.
///
/// Crosses the signing → trust → policy → replay-cache → scheduler-tick →
/// dispatch boundary. Proves:
/// - The replay cache is correctly threaded from the orchestrator into the
///   scheduler tick (the nonce burned in tick 1 persists to disk and is still
///   known on tick 2).
/// - A replayed nonce produces `STATE_BLOCKED` (not just a policy denial), and
///   the block result carries the "replayed" reason string.
#[test]
fn signed_task_action_is_replay_enforced_end_to_end() {
    let task_id = "task-replay-e2e";
    let nonce = "nonce-replay-e2e-unique";
    let t = signed_tool_task_305(task_id, nonce);

    let (cache, replay_dir) = tempdir_replay_cache("replay-e2e");
    let (trust, key_id) = trust_305();
    let key = key_305();

    let orchestrator = TaskOrchestrator::new(LOCAL_AGENT)
        .with_room_id(ROOM_ID)
        .with_policy(tool_policy())
        .with_trust_store(trust)
        .with_verifying_key(key_id, key.verifying_key())
        .with_replay_cache(cache);

    let scheduler = TaskScheduler::new(LOCAL_AGENT, 4);

    // --- Tick 1: fresh nonce → task runs to succeeded. -----------------------
    let mut store1 = RoomTaskStore::default();
    store1.insert(t.clone());
    let mut dispatcher1 = ToolTaskDispatcher::with_runner(|_name, _args, _al, _cwd| {
        Ok(ToolResult {
            exit_code: 0,
            summary: "signed task ran".to_string(),
        })
    });
    let outcomes1 = tick(&scheduler, &orchestrator, &mut store1, &mut dispatcher1);

    assert_eq!(
        store1.get(task_id).state,
        STATE_SUCCEEDED,
        "signed task must succeed on the first tick: {outcomes1:?}"
    );

    // --- Tick 2: same nonce replayed → task must be blocked (not executed). --
    //
    // Re-insert the task at pending/state_rev=1 to simulate a second delivery
    // of the same signed authorization. The replay cache persists to disk, so
    // the nonce burned in tick 1 is still known after the orchestrator is
    // reused on tick 2.
    let mut store2 = RoomTaskStore::default();
    store2.insert(t.clone());
    let mut panic_dispatcher = ToolTaskDispatcher::with_runner(|_name, _args, _al, _cwd| {
        panic!("replayed task must never reach the runner")
    });
    let outcomes2 = tick(
        &scheduler,
        &orchestrator,
        &mut store2,
        &mut panic_dispatcher,
    );

    assert_eq!(
        store2.get(task_id).state,
        STATE_BLOCKED,
        "a replayed signed nonce must be blocked, not executed: {outcomes2:?}"
    );
    let result = store2
        .get(task_id)
        .result
        .as_ref()
        .expect("blocked task has result");
    assert!(
        result
            .get("summary")
            .and_then(|v| v.as_str())
            .is_some_and(|s| s.contains("replayed")),
        "blocked result summary must mention 'replayed': {result:?}"
    );

    let _ = std::fs::remove_dir_all(&replay_dir);
}

/// A benign optimistic-claim race (`StaleClaim`) must not permanently burn the
/// action's single-use nonce. After the failed claim, the nonce is un-burned so
/// the next scheduler tick can re-authorize and run the task, instead of
/// wedging it blocked as "replayed" forever.
///
/// Two-pass scenario driven via `run_scheduler_tick`:
///   1. A store that always returns `StaleClaim` on `claim()` — the nonce is
///      burned inside `admit_task_action_replay` before the claim attempt, then
///      `ReplayCache::forget` compensates it when the claim fails.
///   2. A normal `RoomTaskStore` — the un-burned nonce is admitted again and
///      the task completes successfully.
///
/// Tests the end-to-end integration of `ReplayCache::forget`, the `StaleClaim`
/// compensation arm in `run_one`, and `run_scheduler_tick`.
#[test]
fn stale_claim_does_not_wedge_signed_task_through_scheduler() {
    let task_id = "task-stale-e2e";
    let nonce = "nonce-stale-e2e-unique";
    let t = signed_tool_task_305(task_id, nonce);

    let (cache, replay_dir) = tempdir_replay_cache("stale-e2e");
    let (trust, key_id) = trust_305();
    let key = key_305();

    let orchestrator = TaskOrchestrator::new(LOCAL_AGENT)
        .with_room_id(ROOM_ID)
        .with_policy(tool_policy())
        .with_trust_store(trust)
        .with_verifying_key(key_id, key.verifying_key())
        .with_replay_cache(cache);

    let scheduler = TaskScheduler::new(LOCAL_AGENT, 4);

    // --- Tick 1: claim fails with StaleClaim → nonce must be un-burned. ------
    let snapshot1 = vec![t.clone()];
    let mut stale_store = StaleClaimStore { task: t.clone() };
    let mut panic_dispatcher = ToolTaskDispatcher::with_runner(|_name, _args, _al, _cwd| {
        panic!("a stale-claim pass must never dispatch to the runner")
    });
    let mut claimed1 = std::collections::BTreeSet::new();
    let mut attempted1 = std::collections::HashSet::new();
    let outcomes1 = mx_agent_daemon::run_scheduler_tick(
        &scheduler,
        &orchestrator,
        &snapshot1,
        &std::collections::BTreeMap::new(),
        &mut claimed1,
        &mut stale_store,
        &mut panic_dispatcher,
        &mut attempted1,
    );
    assert!(
        outcomes1
            .iter()
            .any(|o| matches!(o, OrchestrationOutcome::StaleClaim { .. })),
        "stale-claim store must produce StaleClaim outcome: {outcomes1:?}"
    );

    // --- Tick 2: normal store → un-burned nonce is admitted, task succeeds. --
    let mut store2 = RoomTaskStore::default();
    store2.insert(t.clone());
    let mut dispatcher2 = ToolTaskDispatcher::with_runner(|_name, _args, _al, _cwd| {
        Ok(ToolResult {
            exit_code: 0,
            summary: "task ran after stale-claim retry".to_string(),
        })
    });
    let outcomes2 = tick(&scheduler, &orchestrator, &mut store2, &mut dispatcher2);

    assert_eq!(
        store2.get(task_id).state,
        STATE_SUCCEEDED,
        "task must succeed after a benign stale-claim race (nonce must be un-burned): \
         {outcomes2:?}"
    );

    let _ = std::fs::remove_dir_all(&replay_dir);
}

/// Burned nonces persist to disk and survive a simulated daemon restart.
///
/// Tick 1 runs a signed task to completion (nonce burned, cache file persisted).
/// A second orchestrator is then constructed by loading the replay cache from the
/// same disk path, simulating what happens when the daemon restarts. Tick 2 with
/// the new orchestrator re-presents the same signed authorization → blocked as
/// replayed, proving the persistence-across-reload guarantee that prevents a
/// restarted daemon from reprocessing signed requests it already handled.
///
/// Crosses the Ed25519 signing → orchestrator → scheduler-tick → disk-persistence
/// → orchestrator-reload → replay-check boundary.
#[test]
fn replay_protection_survives_simulated_daemon_restart() {
    let task_id = "task-persist-replay-e2e";
    let nonce = "nonce-persist-restart-unique";
    let t = signed_tool_task_305(task_id, nonce);

    let (cache, replay_dir) = tempdir_replay_cache("persist-restart");
    let (trust, key_id) = trust_305();
    let key = key_305();
    let paths = SessionPaths::for_data_dir(replay_dir.clone());

    let orchestrator_a = TaskOrchestrator::new(LOCAL_AGENT)
        .with_room_id(ROOM_ID)
        .with_policy(tool_policy())
        .with_trust_store(trust.clone())
        .with_verifying_key(key_id.clone(), key.verifying_key())
        .with_replay_cache(cache);

    let scheduler = TaskScheduler::new(LOCAL_AGENT, 4);

    // --- Tick 1 with orchestrator A: task runs to succeeded, nonce burned. ---
    let mut store1 = RoomTaskStore::default();
    store1.insert(t.clone());
    let mut dispatcher1 = ToolTaskDispatcher::with_runner(|_, _, _, _| {
        Ok(ToolResult {
            exit_code: 0,
            summary: "ran on first orchestrator".to_string(),
        })
    });
    let outcomes1 = tick(&scheduler, &orchestrator_a, &mut store1, &mut dispatcher1);
    assert_eq!(
        store1.get(task_id).state,
        STATE_SUCCEEDED,
        "tick 1 must succeed on the first orchestrator: {outcomes1:?}"
    );

    // --- Simulate daemon restart: rebuild the orchestrator from disk. ---------
    let cache_b = ReplayCache::load_with_capacity(&paths, 64)
        .expect("replay cache must reload successfully after tick 1");
    let orchestrator_b = TaskOrchestrator::new(LOCAL_AGENT)
        .with_room_id(ROOM_ID)
        .with_policy(tool_policy())
        .with_trust_store(trust)
        .with_verifying_key(key_id, key.verifying_key())
        .with_replay_cache(cache_b);

    // --- Tick 2 with orchestrator B: same nonce must still be blocked. --------
    let mut store2 = RoomTaskStore::default();
    store2.insert(t.clone());
    let mut panic_dispatcher = ToolTaskDispatcher::with_runner(|_, _, _, _| {
        panic!("replayed task must not reach the runner after a daemon restart")
    });
    let outcomes2 = tick(
        &scheduler,
        &orchestrator_b,
        &mut store2,
        &mut panic_dispatcher,
    );

    assert_eq!(
        store2.get(task_id).state,
        STATE_BLOCKED,
        "nonce burned before restart must still block after reload (disk persistence holds): \
         {outcomes2:?}"
    );
    let result2 = store2
        .get(task_id)
        .result
        .as_ref()
        .expect("blocked task must have a result");
    assert!(
        result2
            .get("summary")
            .and_then(|v| v.as_str())
            .is_some_and(|s| s.contains("replayed")),
        "blocked result must mention 'replayed': {result2:?}"
    );

    let _ = std::fs::remove_dir_all(&replay_dir);
}

/// A corrupt replay cache file fails closed across the full orchestrator lifecycle.
///
/// After a successful scheduler tick (nonce burned, cache file persisted), the
/// cache file is externally corrupted (simulating a partial write or truncation).
/// The next attempt to load the cache via `ReplayCache::load` must:
///
/// 1. Return `Err(ReplayError::Corrupt)` — fail closed, not silently reset.
/// 2. Quarantine the corrupt bytes at `replay_cache.json.corrupt` so an operator
///    can inspect them (architecture §13; issue #305 acceptance criterion).
/// 3. Leave the original path absent — the daemon cannot load an empty cache on
///    top of the corrupt bytes and silently forget every burned nonce.
///
/// After operator recovery (removing the quarantine file) a subsequent load
/// succeeds with a fresh empty cache, making the trade-off explicit: recovery
/// from corruption is possible but only after an operator-visible error.
///
/// Crosses the orchestrator → scheduler-tick → disk-write → file-corruption →
/// `ReplayCache::load` → quarantine boundary.
#[test]
fn corrupt_replay_cache_fails_closed_and_quarantines() {
    let task_id = "task-corrupt-e2e";
    let nonce = "nonce-corrupt-e2e-unique";
    let t = signed_tool_task_305(task_id, nonce);

    let (cache, replay_dir) = tempdir_replay_cache("corrupt-e2e");
    let (trust, key_id) = trust_305();
    let key = key_305();
    let paths = SessionPaths::for_data_dir(replay_dir.clone());
    let cache_file = replay_dir.join("replay_cache.json");
    let quarantine_file = replay_dir.join("replay_cache.json.corrupt");

    let orchestrator = TaskOrchestrator::new(LOCAL_AGENT)
        .with_room_id(ROOM_ID)
        .with_policy(tool_policy())
        .with_trust_store(trust)
        .with_verifying_key(key_id, key.verifying_key())
        .with_replay_cache(cache);

    let scheduler = TaskScheduler::new(LOCAL_AGENT, 4);

    // --- Tick 1: task succeeds, nonce burned, cache file written to disk. ----
    let mut store1 = RoomTaskStore::default();
    store1.insert(t.clone());
    let mut dispatcher1 = ToolTaskDispatcher::with_runner(|_, _, _, _| {
        Ok(ToolResult {
            exit_code: 0,
            summary: "ran before corruption".to_string(),
        })
    });
    tick(&scheduler, &orchestrator, &mut store1, &mut dispatcher1);
    assert_eq!(
        store1.get(task_id).state,
        STATE_SUCCEEDED,
        "tick 1 must succeed before corruption"
    );
    assert!(cache_file.exists(), "cache file must exist after tick 1");

    // --- Corrupt the cache file (simulate partial write or truncation). ------
    std::fs::write(&cache_file, b"{ not valid json at all").expect("corrupt write");

    // --- Reload attempt fails closed (Err(Corrupt)), not silently. -----------
    let load_result = ReplayCache::load_with_capacity(&paths, 64);
    assert!(
        matches!(load_result, Err(ReplayError::Corrupt)),
        "a corrupt cache file must fail closed (Err(Corrupt)); \
         silently resetting to empty would forget every burned nonce: {load_result:?}"
    );

    // The corrupt bytes are quarantined so the operator can inspect them.
    assert!(
        quarantine_file.exists(),
        "corrupt bytes must be quarantined at replay_cache.json.corrupt for operator inspection"
    );
    // The original path is absent — not silently reset to an empty cache.
    assert!(
        !cache_file.exists(),
        "original path must be vacated (moved to quarantine), not silently reset in place"
    );

    // --- Operator recovery: remove the quarantine file. ----------------------
    std::fs::remove_file(&quarantine_file).expect("remove quarantine");

    // After recovery, a fresh load succeeds with an empty cache. The burned
    // nonces are lost — this is the documented risk that the operator-visible
    // error (Err(Corrupt) + quarantine) makes explicit.
    let recovered = ReplayCache::load_with_capacity(&paths, 64).expect(
        "load after operator recovery must succeed (quarantine cleared → NotFound → empty)",
    );
    assert!(
        recovered.is_empty(),
        "recovered cache must be empty (burned nonces lost after corruption — operator-visible)"
    );

    let _ = std::fs::remove_dir_all(&replay_dir);
}
