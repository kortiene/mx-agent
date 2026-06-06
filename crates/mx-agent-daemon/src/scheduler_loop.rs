//! Live task scheduler loop: driving the orchestrator off Matrix `/sync`.
//!
//! The daemon already owns a deterministic, unit-tested orchestration core:
//! [`TaskScheduler`] decides which tasks are runnable, and [`TaskOrchestrator`]
//! authorizes them (signature/trust/replay + deny-by-default policy + approval),
//! optimistically claims them with `state_rev`, dispatches an authorized action,
//! and finalizes the task (architecture §9.2). This module supplies the missing
//! *live wiring* (issue #199):
//!
//! - [`MatrixTaskStore`] — a [`TaskStore`] that maps `claim`/`finalize` onto the
//!   real `com.mxagent.task.v1` optimistic-concurrency contract
//!   ([`crate::task::update_task_in_room`]), translating a stale write into
//!   [`TaskStoreError::StaleClaim`].
//! - [`RoutingDispatcher`] — routes a [`TaskAction::Tool`] to a tool dispatcher
//!   and a [`TaskAction::Exec`] to an exec dispatcher, so one tick can process a
//!   mix of actions.
//! - [`run_scheduler_tick`] — the single, pure tick used by both the live loop
//!   and tests: restart recovery over `executing` tasks, then schedule and
//!   process runnable tasks.
//! - [`run_scheduler_loop`] — the live thread that, for each joined room and
//!   each agent this daemon owns, reads task snapshots and ticks the
//!   orchestrator with policy/trust/replay configured so task state stays
//!   advisory unless signed and trusted, and denied actions never spawn.
//!
//! The Matrix boundary is bridged synchronously: the loop runs on a dedicated
//! thread with its own current-thread runtime and shares the daemon's Matrix
//! client. The loop body is plain synchronous code that enters the runtime only
//! at discrete `block_on` points (reading state, claiming, finalizing), so the
//! synchronous orchestrator core is reused unchanged and there is no second
//! `/sync` loop competing for the session token.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::VerifyingKey;
use mx_agent_policy::Policy;
use mx_agent_protocol::schema::{TaskAction, TaskState};

use crate::scheduler::TaskScheduler;
use crate::session::SessionPaths;
use crate::task::{
    apply_and_publish_task, read_task_state, read_tasks, ListTasksOptions, UpdateTaskOptions,
    STATE_EXECUTING,
};
use crate::task_dispatch::{ExecTaskDispatcher, ToolTaskDispatcher};
use crate::task_dispatch_matrix::{MatrixCallTaskDispatcher, MatrixExecTaskDispatcher};
use crate::task_orchestrator::{
    OrchestrationOutcome, TaskDispatcher, TaskExecutionResult, TaskOrchestrator, TaskStore,
    TaskStoreError,
};
use crate::trust::TrustStore;
use crate::workspace::WorkspaceError;
use crate::{ExecSubscriberRegistry, ReplayCache};

/// Default interval between live scheduler passes.
pub const DEFAULT_SCHEDULER_INTERVAL: Duration = Duration::from_secs(5);

/// How the live scheduler loop dispatches a runnable task's action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskDispatchMode {
    /// Run the action in-process via the local tool/exec dispatchers (the
    /// verified default).
    Local,
    /// Route the action through the signed Matrix-backed `call`/`exec` transport
    /// (issue #200), so it runs through the same verify → trust → policy →
    /// runner pipeline as a direct CLI invocation.
    Matrix,
}

impl TaskDispatchMode {
    /// Resolve the dispatch mode from `MX_AGENT_TASK_DISPATCH`.
    ///
    /// `matrix` selects the Matrix-backed transport; anything else (including
    /// unset) keeps the local default.
    pub fn from_env() -> Self {
        match std::env::var("MX_AGENT_TASK_DISPATCH").ok().as_deref() {
            Some("matrix") => Self::Matrix,
            _ => Self::Local,
        }
    }
}

/// A [`TaskStore`] backed by real `com.mxagent.task.v1` Matrix room state.
///
/// `claim` and `finalize` inject the bound room and delegate to an updater that
/// performs the optimistic-concurrency update (the live loop wires this to
/// [`crate::task::update_task_in_room`]). A `WorkspaceError::StaleTaskUpdate`
/// (another writer advanced the task first) is mapped to
/// [`TaskStoreError::StaleClaim`] so the orchestrator treats a lost claim race
/// as stale and does not spawn. The updater is injectable so the error mapping
/// is unit-tested without a live homeserver.
pub struct MatrixTaskStore<U> {
    room: String,
    update: U,
}

impl<U> MatrixTaskStore<U>
where
    U: FnMut(UpdateTaskOptions) -> Result<TaskState, WorkspaceError>,
{
    /// Build a store bound to `room` that applies updates via `update`.
    pub fn new(room: impl Into<String>, update: U) -> Self {
        Self {
            room: room.into(),
            update,
        }
    }

    fn apply(&mut self, mut options: UpdateTaskOptions) -> Result<TaskState, TaskStoreError> {
        options.room = self.room.clone();
        (self.update)(options).map_err(workspace_to_store_error)
    }
}

impl<U> TaskStore for MatrixTaskStore<U>
where
    U: FnMut(UpdateTaskOptions) -> Result<TaskState, WorkspaceError>,
{
    fn claim(&mut self, options: UpdateTaskOptions) -> Result<TaskState, TaskStoreError> {
        self.apply(options)
    }

    fn finalize(&mut self, options: UpdateTaskOptions) -> Result<TaskState, TaskStoreError> {
        self.apply(options)
    }
}

/// Map a task-store [`WorkspaceError`] onto the orchestrator's
/// [`TaskStoreError`], preserving the stale-claim signal that protects against
/// duplicate execution.
fn workspace_to_store_error(err: WorkspaceError) -> TaskStoreError {
    match err {
        WorkspaceError::StaleTaskUpdate {
            task_id,
            expected,
            current,
        } => TaskStoreError::StaleClaim {
            task_id,
            expected,
            current,
        },
        WorkspaceError::TaskNotFound(task_id) => TaskStoreError::NotFound(task_id),
        other => TaskStoreError::Other(other.to_string()),
    }
}

/// A [`TaskDispatcher`] that routes by action kind.
///
/// `Tool` actions go to the tool dispatcher (the preferred, safer-by-default
/// named-tool path) and `Exec` actions go to the exec dispatcher. This lets a
/// single scheduler tick process a workspace containing both kinds of task.
pub struct RoutingDispatcher<T, E> {
    tool: T,
    exec: E,
}

impl<T, E> RoutingDispatcher<T, E>
where
    T: TaskDispatcher,
    E: TaskDispatcher,
{
    /// Build a router over a tool dispatcher and an exec dispatcher.
    pub fn new(tool: T, exec: E) -> Self {
        Self { tool, exec }
    }
}

impl Default for RoutingDispatcher<ToolTaskDispatcher, ExecTaskDispatcher> {
    fn default() -> Self {
        Self::new(ToolTaskDispatcher::new(), ExecTaskDispatcher::new())
    }
}

impl<T, E> TaskDispatcher for RoutingDispatcher<T, E>
where
    T: TaskDispatcher,
    E: TaskDispatcher,
{
    fn dispatch(
        &mut self,
        task: &TaskState,
        action: &TaskAction,
        invocation_id: &str,
    ) -> Result<TaskExecutionResult, crate::task_orchestrator::TaskDispatchError> {
        match action {
            TaskAction::Tool { .. } => self.tool.dispatch(task, action, invocation_id),
            TaskAction::Exec { .. } => self.exec.dispatch(task, action, invocation_id),
        }
    }
}

/// Run one scheduler tick against a task `snapshot`.
///
/// This is the single tick used by both the live loop and the deterministic
/// tests. It first performs restart recovery over `executing` tasks
/// ([`TaskOrchestrator::recover_executing_tasks`]) — an `executing` task this
/// daemon owns whose invocation is *not* one this run has claimed is finalized
/// `failed` with a recovery result rather than re-run, so a restart never
/// double-runs work. It then computes the scheduler-runnable tasks and processes
/// each through [`TaskOrchestrator::process_one`], which authorizes
/// (signature/trust/replay + deny-by-default policy + approval) before any claim
/// or dispatch. Returns one [`OrchestrationOutcome`] per recovery decision and
/// per processed task.
///
/// `claimed_invocations` accumulates every invocation id this run has claimed,
/// and is the set recovery treats as "still owned by this run". It is essential
/// for the live loop, whose snapshot is read from a local store that lags the
/// homeserver `/sync` echo: a task this daemon claimed and finalized in an
/// earlier pass can still appear `executing` in a later pass's snapshot, and
/// without this set recovery would clobber that real success back to `failed`
/// (issue #221). A genuine orphan from a *previous* daemon run carries an
/// invocation id this run never claimed, so it is absent from the set and still
/// recovered. The in-memory tests start from an empty set, since their store
/// updates synchronously and never lags.
///
/// `attempted` deduplicates work across ticks by observed `(task_id,
/// state_rev)`: a task is processed at most once per revision. This is essential
/// for the live loop, whose task snapshot is read from a local store that lags
/// the homeserver — without it, a just-claimed task that has not yet synced back
/// would be re-read as still `pending`, re-verified, and rejected by replay
/// protection (blocking work the scheduler already ran). The in-memory tests
/// pass a fresh set, since their store updates synchronously.
pub fn run_scheduler_tick<S, D>(
    scheduler: &TaskScheduler,
    orchestrator: &TaskOrchestrator,
    snapshot: &[TaskState],
    claimed_invocations: &mut BTreeSet<String>,
    store: &mut S,
    dispatcher: &mut D,
    attempted: &mut HashSet<(String, u64)>,
) -> Vec<OrchestrationOutcome>
where
    S: TaskStore,
    D: TaskDispatcher,
{
    let mut outcomes = orchestrator.recover_executing_tasks(snapshot, claimed_invocations, store);

    let running = snapshot
        .iter()
        .filter(|task| task.state == STATE_EXECUTING)
        .count() as u32;
    let runnable_ids: Vec<String> = scheduler
        .runnable(snapshot, running)
        .into_iter()
        .map(|task| task.task_id.clone())
        .collect();
    for id in runnable_ids {
        if let Some(task) = snapshot.iter().find(|t| t.task_id == id) {
            // Skip a task already attempted at this exact revision; record it
            // before processing so a stale re-read on the next tick is ignored.
            if !attempted.insert((task.task_id.clone(), task.state_rev)) {
                continue;
            }
            let outcome = orchestrator.process_one(task, snapshot, store, dispatcher);
            // Remember the invocation this pass claimed so a later pass that
            // re-reads the task as `executing` off a stale snapshot does not
            // recover (clobber) it.
            if let Some(invocation_id) = outcome.claimed_invocation_id() {
                claimed_invocations.insert(invocation_id.to_string());
            }
            outcomes.push(outcome);
        }
    }
    outcomes
}

/// Run the live scheduler loop until `running` is cleared.
///
/// On its own dedicated thread (the caller spawns it), this builds a
/// current-thread Tokio runtime, then repeatedly — every `interval` — performs a
/// [`scheduler_pass`] over every joined room. It shares the daemon's Matrix
/// `client` and never runs its own `/sync`, so it reads room state populated by
/// the main sync loop and writes task state events directly; only the main loop
/// owns the session token. All Matrix and store errors are logged and skipped so
/// a transient failure never stops the loop or panics the daemon.
pub fn run_scheduler_loop(
    client: matrix_sdk::Client,
    subscribers: ExecSubscriberRegistry,
    mode: TaskDispatchMode,
    running: Arc<AtomicBool>,
    interval: Duration,
) {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => Arc::new(runtime),
        Err(e) => {
            tracing::error!(error = %e, "failed to build scheduler runtime; scheduler loop not started");
            return;
        }
    };
    let paths = SessionPaths::resolve();
    // Observed `(task_id, state_rev)` pairs already attempted, so a task is never
    // re-processed at the same revision while the local store catches up to the
    // homeserver. Capped to bound memory on a long-lived daemon.
    let mut attempted: HashSet<(String, u64)> = HashSet::new();
    // Invocation ids this run has claimed. Restart recovery treats these as still
    // owned by this run and never recovers them, so a task this daemon claimed and
    // finalized in an earlier pass is not clobbered to `failed` off a stale
    // local-store snapshot that still shows it `executing` (issue #221). Capped to
    // bound memory on a long-lived daemon.
    let mut claimed_invocations: BTreeSet<String> = BTreeSet::new();
    tracing::info!(
        interval_secs = interval.as_secs(),
        dispatch = ?mode,
        "task scheduler loop started"
    );
    while running.load(Ordering::SeqCst) {
        if attempted.len() > MAX_ATTEMPTED_TRACKED {
            attempted.clear();
        }
        if claimed_invocations.len() > MAX_ATTEMPTED_TRACKED {
            claimed_invocations.clear();
        }
        scheduler_pass(
            &runtime,
            &client,
            &subscribers,
            mode,
            &paths,
            &mut attempted,
            &mut claimed_invocations,
        );
        sleep_interruptible(interval, &running);
    }
    tracing::info!("task scheduler loop stopped");
}

/// Upper bound on the tracked `(task_id, state_rev)` attempts and this-run
/// claimed-invocation sets before each is cleared, bounding scheduler memory on a
/// long-running daemon.
const MAX_ATTEMPTED_TRACKED: usize = 50_000;

/// Sleep for `delay`, waking early when `running` is cleared.
fn sleep_interruptible(delay: Duration, running: &AtomicBool) {
    let step = Duration::from_millis(100);
    let mut remaining = delay;
    while remaining > Duration::ZERO && running.load(Ordering::SeqCst) {
        let chunk = remaining.min(step);
        std::thread::sleep(chunk);
        remaining = remaining.saturating_sub(chunk);
    }
}

/// Perform one scheduler pass over every joined room.
///
/// For each room, this reads the published agent states, resolves the verifying
/// keys for signed task-action authorization, and — for each agent whose Matrix
/// user is this daemon — ticks the orchestrator over the room's tasks.
fn scheduler_pass(
    runtime: &Arc<tokio::runtime::Runtime>,
    client: &matrix_sdk::Client,
    subscribers: &ExecSubscriberRegistry,
    mode: TaskDispatchMode,
    paths: &SessionPaths,
    attempted: &mut HashSet<(String, u64)>,
    claimed_invocations: &mut BTreeSet<String>,
) {
    let local_user = client.user_id().map(|u| u.to_string()).unwrap_or_default();
    if local_user.is_empty() {
        return;
    }
    for room in client.joined_rooms() {
        let room_id = room.room_id().to_string();
        let agents = match runtime.block_on(crate::agent::read_all_agent_states(&room)) {
            Ok(agents) => agents,
            Err(e) => {
                tracing::debug!(error = %e, room = %room_id, "scheduler pass could not read agent states");
                continue;
            }
        };
        let owned: Vec<&mx_agent_protocol::schema::AgentState> = agents
            .iter()
            .filter(|agent| agent.matrix_user_id == local_user)
            .collect();
        if owned.is_empty() {
            continue;
        }

        let mut verifying_keys: BTreeMap<String, VerifyingKey> = BTreeMap::new();
        for agent in &agents {
            if agent.signing_key_id.is_empty() {
                continue;
            }
            if let Ok(key) = crate::call::verifying_key_from_agent_state(agent) {
                verifying_keys.insert(agent.signing_key_id.clone(), key);
            }
        }

        let snapshot = match runtime.block_on(read_tasks(
            &room,
            &ListTasksOptions {
                room: room_id.clone(),
                state: None,
                assigned_to: None,
            },
        )) {
            Ok(tasks) => tasks,
            Err(e) => {
                tracing::debug!(error = %e, room = %room_id, "scheduler pass could not read tasks");
                continue;
            }
        };

        for agent in owned {
            scheduler_pass_for_agent(
                runtime,
                &room,
                &room_id,
                agent,
                &snapshot,
                &verifying_keys,
                subscribers,
                mode,
                paths,
                attempted,
                claimed_invocations,
            );
        }
    }
}

/// Tick the orchestrator for a single local `agent` against a room snapshot.
#[allow(clippy::too_many_arguments)]
fn scheduler_pass_for_agent(
    runtime: &Arc<tokio::runtime::Runtime>,
    room: &matrix_sdk::Room,
    room_id: &str,
    agent: &mx_agent_protocol::schema::AgentState,
    snapshot: &[TaskState],
    verifying_keys: &BTreeMap<String, VerifyingKey>,
    subscribers: &ExecSubscriberRegistry,
    mode: TaskDispatchMode,
    paths: &SessionPaths,
    attempted: &mut HashSet<(String, u64)>,
    claimed_invocations: &mut BTreeSet<String>,
) {
    // Deny-by-default: when no policy file is present, the default policy denies
    // every action, so nothing is claimed or dispatched.
    let policy = Policy::default_path()
        .and_then(|path| Policy::load(path).ok())
        .unwrap_or_default();
    let trust = TrustStore::load(paths).unwrap_or_default();

    // Task state is advisory: configuring the trust store (and replay cache when
    // available) makes the orchestrator require a valid signed authorization
    // before any claim/dispatch, so an unsigned/untrusted/expired/replayed task
    // action is blocked rather than executed.
    let mut orchestrator = TaskOrchestrator::new(agent.agent_id.clone())
        .with_room_id(room_id.to_string())
        .with_policy(policy)
        .with_trust_store(trust);
    if let Ok(replay) = ReplayCache::load(paths) {
        orchestrator = orchestrator.with_replay_cache(replay);
    }
    for (key_id, key) in verifying_keys {
        orchestrator = orchestrator.with_verifying_key(key_id.clone(), *key);
    }

    // Only tasks assigned to this agent are claimed (auto-claim disabled): room
    // membership never implies execution.
    let scheduler = TaskScheduler::new(agent.agent_id.clone(), agent.load.max_invocations);

    // A per-pass cache of the state this store just wrote, so a `claim`
    // immediately followed by a `finalize` checks staleness against the claim's
    // revision rather than the local store, which has not yet received the
    // daemon's own echo over `/sync` (otherwise the finalize would be rejected
    // as stale and the task would never reach a terminal state).
    let mut write_cache: BTreeMap<String, (TaskState, Option<String>)> = BTreeMap::new();
    let mut store = MatrixTaskStore::new(room_id.to_string(), |options: UpdateTaskOptions| {
        let (current, event_id) = match write_cache.get(&options.task_id) {
            Some((state, event_id)) => (state.clone(), event_id.clone()),
            None => match runtime.block_on(read_task_state(room, &options.task_id))? {
                Some(found) => found,
                None => return Err(WorkspaceError::TaskNotFound(options.task_id.clone())),
            },
        };
        let updated =
            runtime.block_on(apply_and_publish_task(room, current, event_id, &options))?;
        write_cache.insert(updated.task_id.clone(), (updated.clone(), None));
        Ok(updated)
    });

    // Local dispatch runs the action in-process; Matrix dispatch routes it
    // through the signed Matrix `call`/`exec` transport (issue #200), so the
    // daemon's own /sync loop receives the request and runs it through the full
    // verify → trust → policy → runner pipeline.
    let outcomes = match mode {
        TaskDispatchMode::Local => {
            let mut dispatcher = RoutingDispatcher::default();
            run_scheduler_tick(
                &scheduler,
                &orchestrator,
                snapshot,
                claimed_invocations,
                &mut store,
                &mut dispatcher,
                attempted,
            )
        }
        TaskDispatchMode::Matrix => {
            let call = MatrixCallTaskDispatcher::new(room_id.to_string(), |params| {
                runtime.block_on(crate::start_call_matrix(&params))
            });
            let exec = MatrixExecTaskDispatcher::new(room_id.to_string(), |params| {
                runtime.block_on(crate::start_exec_matrix(&params, subscribers))
            });
            let mut dispatcher = RoutingDispatcher::new(call, exec);
            run_scheduler_tick(
                &scheduler,
                &orchestrator,
                snapshot,
                claimed_invocations,
                &mut store,
                &mut dispatcher,
                attempted,
            )
        }
    };
    for outcome in &outcomes {
        log_outcome(room_id, &agent.agent_id, outcome);
    }
}

/// Log a non-sensitive summary of one orchestration outcome.
fn log_outcome(room_id: &str, agent_id: &str, outcome: &OrchestrationOutcome) {
    match outcome {
        OrchestrationOutcome::Completed { task_id, state, .. } => {
            tracing::info!(room = %room_id, agent = %agent_id, task_id = %task_id, state = %state, "scheduler finalized task")
        }
        OrchestrationOutcome::Denied { task_id, .. } => {
            tracing::info!(room = %room_id, agent = %agent_id, task_id = %task_id, "scheduler blocked task action")
        }
        OrchestrationOutcome::RecoveredStale { task_id } => tracing::warn!(
            room = %room_id, agent = %agent_id, task_id = %task_id, "scheduler recovered stale executing task"
        ),
        OrchestrationOutcome::AwaitingApproval { task_id, .. } => tracing::info!(
            room = %room_id, agent = %agent_id, task_id = %task_id, "scheduler holding task pending approval"
        ),
        OrchestrationOutcome::StoreError { task_id, reason } => tracing::warn!(
            room = %room_id, agent = %agent_id, task_id = %task_id, reason = %reason, "scheduler store error"
        ),
        other => tracing::debug!(
            room = %room_id, agent = %agent_id, task_id = %other.task_id_for_log(), "scheduler skipped task"
        ),
    }
}

impl OrchestrationOutcome {
    /// The invocation id this daemon generated and claimed for a task it
    /// processed this pass, if any.
    ///
    /// Used to record this-run invocations so restart recovery never clobbers a
    /// task this loop already claimed and finalized off a stale snapshot (issue
    /// #221). Both `Completed` (the task was claimed `executing` and finalized to
    /// a terminal state) and `Denied` (claimed then blocked) carry the invocation
    /// this run owns.
    fn claimed_invocation_id(&self) -> Option<&str> {
        match self {
            Self::Completed { invocation_id, .. } | Self::Denied { invocation_id, .. } => {
                Some(invocation_id)
            }
            _ => None,
        }
    }

    /// A non-sensitive task id for logging, regardless of variant.
    fn task_id_for_log(&self) -> &str {
        match self {
            Self::NotAssigned { task_id }
            | Self::NotRunnableState { task_id, .. }
            | Self::Blocked { task_id, .. }
            | Self::MalformedAction { task_id, .. }
            | Self::StaleClaim { task_id }
            | Self::Denied { task_id, .. }
            | Self::Completed { task_id, .. }
            | Self::RecoveredStale { task_id }
            | Self::StaleRemoteExecuting { task_id, .. }
            | Self::AwaitingApproval { task_id, .. }
            | Self::StoreError { task_id, .. } => task_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::task::{STATE_BLOCKED, STATE_FAILED, STATE_PENDING, STATE_SUCCEEDED};
    use crate::task_dispatch::ExecRunRequest;
    use crate::task_orchestrator::TaskDispatchError;
    use crate::tool_exec::{ToolError, ToolResult};
    use mx_agent_protocol::schema::Extra;
    use serde_json::{json, Value};
    use std::collections::HashMap;

    const AGENT: &str = "agent-a";
    const PLANNER: &str = "@planner:server";
    const ROOM: &str = "!room:server";

    /// In-memory model of `com.mxagent.task.v1` room state enforcing the same
    /// optimistic-concurrency contract as `update_task`.
    #[derive(Default)]
    struct RoomTaskStore {
        tasks: HashMap<String, TaskState>,
    }

    impl RoomTaskStore {
        fn insert(&mut self, task: TaskState) {
            self.tasks.insert(task.task_id.clone(), task);
        }
        fn snapshot(&self) -> Vec<TaskState> {
            let mut tasks: Vec<TaskState> = self.tasks.values().cloned().collect();
            tasks.sort_by(|a, b| a.task_id.cmp(&b.task_id));
            tasks
        }
        fn state_of(&self, task_id: &str) -> &str {
            &self.tasks.get(task_id).expect("task exists").state
        }
        fn apply(&mut self, options: UpdateTaskOptions) -> Result<TaskState, WorkspaceError> {
            let task = self
                .tasks
                .get_mut(&options.task_id)
                .ok_or_else(|| WorkspaceError::TaskNotFound(options.task_id.clone()))?;
            if let Some(expected) = options.expected_state_rev {
                if expected != task.state_rev {
                    return Err(WorkspaceError::StaleTaskUpdate {
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
            Ok(task.clone())
        }
    }

    fn policy() -> Policy {
        Policy::parse(&format!(
            r#"
[rooms."{ROOM}"]
trusted = true
raw_exec_default = "deny"

[rooms."{ROOM}".agents."{PLANNER}"]
allow_exec = true
allow_tools = ["run_tests"]
allow_commands = ["true"]
allow_cwd = ["/repo"]
"#
        ))
        .expect("policy parses")
    }

    fn base_task(id: &str, state: &str) -> TaskState {
        TaskState {
            task_id: id.to_string(),
            title: id.to_string(),
            description: String::new(),
            state: state.to_string(),
            assigned_to: AGENT.to_string(),
            created_by: PLANNER.to_string(),
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

    fn tool_task(id: &str, tool: &str) -> TaskState {
        let mut t = base_task(id, STATE_PENDING);
        t.action = Some(TaskAction::Tool {
            tool: tool.to_string(),
            args: json!({}),
            authorization: None,
        });
        t
    }

    fn exec_task(id: &str, program: &str) -> TaskState {
        let mut t = base_task(id, STATE_PENDING);
        t.action = Some(TaskAction::Exec {
            command: vec![program.to_string()],
            cwd: "/repo".to_string(),
            env: Default::default(),
            timeout_ms: Some(60_000),
            stream: false,
            authorization: None,
        });
        t
    }

    fn orchestrator() -> TaskOrchestrator {
        // No trust store configured: this exercises the scheduler/dispatch tick
        // against local policy (signed-authorization enforcement is covered by
        // the orchestrator's own tests).
        TaskOrchestrator::new(AGENT)
            .with_room_id(ROOM)
            .with_policy(policy())
    }

    fn tick_with<D: TaskDispatcher>(
        store: &mut RoomTaskStore,
        dispatcher: &mut D,
    ) -> Vec<OrchestrationOutcome> {
        let snapshot = store.snapshot();
        let scheduler = TaskScheduler::new(AGENT, 4);
        let orchestrator = orchestrator();
        let mut claimed = BTreeSet::new();
        // Bridge the in-memory model through MatrixTaskStore so the store
        // adapter (and its error mapping) is exercised too.
        let store_ref = std::cell::RefCell::new(store);
        let mut matrix_store = MatrixTaskStore::new(ROOM, |options: UpdateTaskOptions| {
            store_ref.borrow_mut().apply(options)
        });
        let mut attempted = HashSet::new();
        run_scheduler_tick(
            &scheduler,
            &orchestrator,
            &snapshot,
            &mut claimed,
            &mut matrix_store,
            dispatcher,
            &mut attempted,
        )
    }

    #[test]
    fn matrix_store_maps_stale_update_to_stale_claim() {
        let err = workspace_to_store_error(WorkspaceError::StaleTaskUpdate {
            task_id: "task-a".to_string(),
            expected: 1,
            current: 3,
        });
        assert!(matches!(
            err,
            TaskStoreError::StaleClaim { expected, current, .. } if expected == 1 && current == 3
        ));
        assert!(matches!(
            workspace_to_store_error(WorkspaceError::TaskNotFound("x".to_string())),
            TaskStoreError::NotFound(id) if id == "x"
        ));
    }

    #[test]
    fn attempted_set_dedupes_a_task_at_the_same_revision() {
        // A stale snapshot re-read of the same `(task_id, state_rev)` must not be
        // re-processed: the live loop relies on this to avoid re-verifying (and
        // replay-blocking) a task it already ran before the claim syncs back.
        let mut store = RoomTaskStore::default();
        store.insert(tool_task("task-a", "run_tests"));
        let snapshot = store.snapshot();
        let scheduler = TaskScheduler::new(AGENT, 4);
        let orchestrator = orchestrator();
        let mut claimed = BTreeSet::new();
        let mut attempted = HashSet::new();
        let mut runs = 0u32;
        let mut dispatcher = RoutingDispatcher::new(
            ToolTaskDispatcher::with_runner(|_n, _a| {
                Ok(ToolResult {
                    exit_code: 0,
                    summary: "ok".to_string(),
                })
            }),
            ExecTaskDispatcher::with_runner(|_r| panic!("no exec")),
        );

        // First tick over the rev-1 snapshot processes the task once.
        let store_ref = std::cell::RefCell::new(&mut store);
        let mut matrix_store = MatrixTaskStore::new(ROOM, |options: UpdateTaskOptions| {
            runs += 1;
            store_ref.borrow_mut().apply(options)
        });
        let first = run_scheduler_tick(
            &scheduler,
            &orchestrator,
            &snapshot,
            &mut claimed,
            &mut matrix_store,
            &mut dispatcher,
            &mut attempted,
        );
        // A second tick over the *same* (stale) rev-1 snapshot is a no-op.
        let second = run_scheduler_tick(
            &scheduler,
            &orchestrator,
            &snapshot,
            &mut claimed,
            &mut matrix_store,
            &mut dispatcher,
            &mut attempted,
        );
        drop(matrix_store);

        assert!(
            first
                .iter()
                .any(|o| matches!(o, OrchestrationOutcome::Completed { .. })),
            "first tick should process the task"
        );
        assert!(
            second.is_empty(),
            "second tick over the same revision must process nothing: {second:?}"
        );
        // claim + finalize ran exactly once (2 store writes), not twice.
        assert_eq!(runs, 2, "task must be claimed/finalized exactly once");
    }

    #[test]
    fn routing_dispatcher_routes_by_action_kind() {
        let mut dispatcher = RoutingDispatcher::new(
            ToolTaskDispatcher::with_runner(|name, _args| {
                assert_eq!(name, "run_tests");
                Ok(ToolResult {
                    exit_code: 0,
                    summary: "tool ran".to_string(),
                })
            }),
            ExecTaskDispatcher::with_runner(|req: &ExecRunRequest| {
                assert_eq!(req.command, vec!["true".to_string()]);
                Ok(crate::runner::RunOutput {
                    exit_code: Some(0),
                    signal: None,
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                    timed_out: false,
                })
            }),
        );
        let tool = TaskAction::Tool {
            tool: "run_tests".to_string(),
            args: json!({}),
            authorization: None,
        };
        let exec = TaskAction::Exec {
            command: vec!["true".to_string()],
            cwd: "/repo".to_string(),
            env: Default::default(),
            timeout_ms: None,
            stream: false,
            authorization: None,
        };
        let task = tool_task("task-a", "run_tests");
        assert!(dispatcher
            .dispatch(&task, &tool, "inv-1")
            .unwrap()
            .is_success());
        assert!(dispatcher
            .dispatch(&task, &exec, "inv-2")
            .unwrap()
            .is_success());
    }

    #[test]
    fn tick_runs_runnable_tool_task_to_success() {
        let mut store = RoomTaskStore::default();
        store.insert(tool_task("task-a", "run_tests"));
        let mut dispatcher = RoutingDispatcher::new(
            ToolTaskDispatcher::with_runner(|_n, _a| {
                Ok(ToolResult {
                    exit_code: 0,
                    summary: "ok".to_string(),
                })
            }),
            ExecTaskDispatcher::with_runner(|_r| panic!("exec must not run for a tool task")),
        );
        let outcomes = tick_with(&mut store, &mut dispatcher);
        assert!(outcomes.iter().any(|o| matches!(
            o,
            OrchestrationOutcome::Completed { state, .. } if state == STATE_SUCCEEDED
        )));
        assert_eq!(store.state_of("task-a"), STATE_SUCCEEDED);
    }

    #[test]
    fn tick_blocks_dependent_task_until_dependency_succeeds() {
        let mut store = RoomTaskStore::default();
        let mut dep = tool_task("task-dep", "run_tests");
        dep.state = STATE_PENDING.to_string();
        store.insert(dep);
        let mut dependent = tool_task("task-main", "run_tests");
        dependent.depends_on = vec!["task-dep".to_string()];
        store.insert(dependent);

        let make_dispatcher = || {
            RoutingDispatcher::new(
                ToolTaskDispatcher::with_runner(|_n, _a| {
                    Ok(ToolResult {
                        exit_code: 0,
                        summary: "ok".to_string(),
                    })
                }),
                ExecTaskDispatcher::with_runner(|_r| panic!("no exec")),
            )
        };

        // Tick 1: the dependency runs; the dependent stays pending (blocked).
        let mut d1 = make_dispatcher();
        tick_with(&mut store, &mut d1);
        assert_eq!(store.state_of("task-dep"), STATE_SUCCEEDED);
        assert_eq!(
            store.state_of("task-main"),
            STATE_PENDING,
            "dependent must not run before its dependency succeeds"
        );

        // Tick 2: with the dependency succeeded, the dependent runs.
        let mut d2 = make_dispatcher();
        tick_with(&mut store, &mut d2);
        assert_eq!(store.state_of("task-main"), STATE_SUCCEEDED);
    }

    #[test]
    fn tick_blocks_policy_denied_task_without_spawning() {
        let mut store = RoomTaskStore::default();
        // `rm` is not allowlisted -> denied by policy before dispatch.
        store.insert(exec_task("task-denied", "rm"));
        let mut dispatcher = RoutingDispatcher::new(
            ToolTaskDispatcher::with_runner(|_n, _a| panic!("no tool")),
            ExecTaskDispatcher::with_runner(|_r| panic!("denied exec must never spawn")),
        );
        let outcomes = tick_with(&mut store, &mut dispatcher);
        assert!(outcomes
            .iter()
            .any(|o| matches!(o, OrchestrationOutcome::Denied { .. })));
        assert_eq!(store.state_of("task-denied"), STATE_BLOCKED);
        let result = store
            .tasks
            .get("task-denied")
            .unwrap()
            .result
            .clone()
            .unwrap();
        assert_eq!(
            result.get("reason").and_then(Value::as_str),
            Some("policy_denied")
        );
    }

    #[test]
    fn tick_recovers_stale_executing_task_without_redispatch() {
        let mut store = RoomTaskStore::default();
        // A task left `executing` by a previous (crashed) run, owned by us, with
        // an invocation that is not live. Recovery must fail it, not re-run it.
        let mut stale = exec_task("task-stale", "true");
        stale.state = STATE_EXECUTING.to_string();
        stale.invocation_id = Some("inv-old".to_string());
        store.insert(stale);

        let mut dispatcher = RoutingDispatcher::new(
            ToolTaskDispatcher::with_runner(|_n, _a| panic!("no tool")),
            ExecTaskDispatcher::with_runner(|_r| {
                panic!("recovered task must not be re-dispatched")
            }),
        );
        let outcomes = tick_with(&mut store, &mut dispatcher);
        assert!(outcomes
            .iter()
            .any(|o| matches!(o, OrchestrationOutcome::RecoveredStale { .. })));
        assert_eq!(store.state_of("task-stale"), STATE_FAILED);
        let result = store
            .tasks
            .get("task-stale")
            .unwrap()
            .result
            .clone()
            .unwrap();
        assert_eq!(
            result.get("reason").and_then(Value::as_str),
            Some("recovered_stale_invocation")
        );
    }

    #[test]
    fn recovery_skips_task_finalized_this_run_off_a_stale_snapshot() {
        // Deterministic reproduction of the #221 flake. A task this loop claimed
        // and finalized `succeeded` in an earlier pass still appears `executing`
        // in a later pass's snapshot, because the local store lags the homeserver
        // `/sync` echo. Restart recovery must NOT clobber that real success back
        // to `failed`: the invocation was claimed this run, so it is excluded
        // from recovery.
        let mut store = RoomTaskStore::default();
        store.insert(tool_task("task-plan", "run_tests"));

        let scheduler = TaskScheduler::new(AGENT, 4);
        let orchestrator = orchestrator();
        let mut attempted = HashSet::new();
        // Persisted across both ticks, exactly as the live loop threads it.
        let mut claimed = BTreeSet::new();
        let mut dispatcher = RoutingDispatcher::new(
            ToolTaskDispatcher::with_runner(|_n, _a| {
                Ok(ToolResult {
                    exit_code: 0,
                    summary: "ok".to_string(),
                })
            }),
            ExecTaskDispatcher::with_runner(|_r| panic!("no exec")),
        );

        // Pass 1: the task runs to success and its invocation is recorded.
        let snapshot1 = store.snapshot();
        {
            let store_ref = std::cell::RefCell::new(&mut store);
            let mut matrix_store = MatrixTaskStore::new(ROOM, |options: UpdateTaskOptions| {
                store_ref.borrow_mut().apply(options)
            });
            let first = run_scheduler_tick(
                &scheduler,
                &orchestrator,
                &snapshot1,
                &mut claimed,
                &mut matrix_store,
                &mut dispatcher,
                &mut attempted,
            );
            assert!(
                first.iter().any(|o| matches!(
                    o,
                    OrchestrationOutcome::Completed { state, .. } if state == STATE_SUCCEEDED
                )),
                "first tick should run the task to success: {first:?}"
            );
        }
        assert_eq!(store.state_of("task-plan"), STATE_SUCCEEDED);
        let invocation = store
            .tasks
            .get("task-plan")
            .unwrap()
            .invocation_id
            .clone()
            .expect("claimed task has an invocation id");
        assert!(
            claimed.contains(&invocation),
            "the claimed invocation must be recorded for this run"
        );

        // Pass 2: a STALE snapshot still shows the task `executing` with that same
        // invocation (the success echo has not synced back into the local store).
        let mut stale = store.tasks.get("task-plan").unwrap().clone();
        stale.state = STATE_EXECUTING.to_string();
        let stale_snapshot = vec![stale];
        {
            let store_ref = std::cell::RefCell::new(&mut store);
            let mut matrix_store = MatrixTaskStore::new(ROOM, |options: UpdateTaskOptions| {
                store_ref.borrow_mut().apply(options)
            });
            let second = run_scheduler_tick(
                &scheduler,
                &orchestrator,
                &stale_snapshot,
                &mut claimed,
                &mut matrix_store,
                &mut dispatcher,
                &mut attempted,
            );
            assert!(
                !second
                    .iter()
                    .any(|o| matches!(o, OrchestrationOutcome::RecoveredStale { .. })),
                "a task finalized this run must not be recovered off a stale snapshot: {second:?}"
            );
        }
        // The real success in the store is untouched.
        assert_eq!(
            store.state_of("task-plan"),
            STATE_SUCCEEDED,
            "recovery must not clobber a task this run already finalized"
        );
    }

    #[test]
    fn unauthorized_dispatcher_error_is_dispatch_failure() {
        // Sanity: a dispatcher reporting policy denial maps to a failed task.
        struct DenyDispatcher;
        impl TaskDispatcher for DenyDispatcher {
            fn dispatch(
                &mut self,
                _task: &TaskState,
                _action: &TaskAction,
                _invocation_id: &str,
            ) -> Result<TaskExecutionResult, TaskDispatchError> {
                Err(TaskDispatchError::Failed("boom".to_string()))
            }
        }
        let mut store = RoomTaskStore::default();
        store.insert(tool_task("task-a", "run_tests"));
        let mut dispatcher = DenyDispatcher;
        let outcomes = tick_with(&mut store, &mut dispatcher);
        assert!(outcomes.iter().any(
            |o| matches!(o, OrchestrationOutcome::Completed { state, .. } if state == STATE_FAILED)
        ));
        // Avoid an unused-import style warning for ToolError in this module.
        let _ = ToolError::UnknownTool("x".to_string());
    }
}
