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

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ed25519_dalek::VerifyingKey;
use mx_agent_policy::{Allowance, Policy};
use mx_agent_protocol::schema::{ApprovalDecision, InvocationState, TaskAction, TaskState};

use crate::approval::{
    approval_request_expiry, read_verified_approval_decisions, ApprovalQueue, DecisionVerification,
    APPROVAL_REQUEST_TTL,
};
use crate::audit::AuditLog;
use crate::scheduler::TaskScheduler;
use crate::session::SessionPaths;
use crate::task::{
    apply_and_publish_task, read_task_state, read_tasks, ListTasksOptions, UpdateTaskOptions,
    STATE_ASSIGNED, STATE_EXECUTING, STATE_PENDING,
};
use crate::task_dispatch::{ExecTaskDispatcher, ToolTaskDispatcher};
use crate::task_dispatch_matrix::{MatrixCallTaskDispatcher, MatrixExecTaskDispatcher};
use crate::task_orchestrator::{
    OrchestrationOutcome, QueueApprovalGate, TaskDispatcher, TaskExecutionResult, TaskOrchestrator,
    TaskStore, TaskStoreError,
};
use crate::trust::TrustStore;
use crate::workspace::WorkspaceError;
use crate::{ExecSubscriberRegistry, ReplayCache};

/// Upper bound on recent timeline events scanned for approval decisions per room
/// per pass. Bounds the cost of resolving held approval-required tasks.
const APPROVAL_DECISIONS_SCAN_LIMIT: u32 = 100;

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
        allowance: &Allowance,
    ) -> Result<TaskExecutionResult, crate::task_orchestrator::TaskDispatchError> {
        match action {
            TaskAction::Tool { .. } => self.tool.dispatch(task, action, invocation_id, allowance),
            TaskAction::Exec { .. } => self.exec.dispatch(task, action, invocation_id, allowance),
        }
    }
}

/// Run one scheduler tick against a task `snapshot`.
///
/// This is the single tick used by both the live loop and the deterministic
/// tests. It first reconciles `executing` tasks against the room's invocation
/// snapshot ([`TaskOrchestrator::reconcile_executing_tasks`]) by the unified id —
/// an `executing` task this daemon owns whose invocation already finished is
/// reconciled to that outcome, one still running is left alone, and a genuine
/// orphan (no invocation, not claimed this run) is finalized `failed` rather than
/// re-run, so a restart never double-runs work (`invocations` may be empty when
/// no snapshot is available, matching the historical fail-the-orphan behavior).
/// It then computes the scheduler-runnable tasks and processes
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
#[allow(clippy::too_many_arguments)]
pub fn run_scheduler_tick<S, D>(
    scheduler: &TaskScheduler,
    orchestrator: &TaskOrchestrator,
    snapshot: &[TaskState],
    invocations: &BTreeMap<String, InvocationState>,
    claimed_invocations: &mut BTreeSet<String>,
    store: &mut S,
    dispatcher: &mut D,
    attempted: &mut HashSet<(String, u64)>,
) -> Vec<OrchestrationOutcome>
where
    S: TaskStore,
    D: TaskDispatcher,
{
    let mut outcomes =
        orchestrator.reconcile_executing_tasks(snapshot, claimed_invocations, invocations, store);

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
            // A task held pending an approval decision stays at this same
            // `state_rev`, so drop it from `attempted` to let a later pass
            // re-evaluate it once a decision is published (otherwise it would be
            // skipped forever at this revision and never resume). It is not yet
            // verified-by-replay, claimed, or finalized, so re-processing is safe.
            if matches!(outcome, OrchestrationOutcome::AwaitingApproval { .. }) {
                attempted.remove(&(task.task_id.clone(), task.state_rev));
            }
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
///
/// Shared by the scheduler and heartbeat loops so both wind down promptly on
/// daemon shutdown rather than blocking a full interval.
pub(crate) fn sleep_interruptible(delay: Duration, running: &AtomicBool) {
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

    // Load policy and the local trust store once per pass (every owned agent
    // reads the same files). Deny-by-default fallbacks: an absent/invalid policy
    // denies every action and an unreadable trust store trusts nothing. The trust
    // store is also the authority anchoring approval-decision verification (issue
    // #309), so it is read here and threaded into both the per-room decision
    // verification and each agent's orchestrator.
    let policy = crate::policy::resolve_policy_for_enforcement("scheduler.pass");
    let trust = TrustStore::load(paths).unwrap_or_default();

    // The on-disk approval queue is daemon-global. Load it once per pass behind a
    // shared handle each gate enqueues/removes through, then persist if it
    // changed. The published `com.mxagent.approval.decision.v1` event is the
    // source of truth for fail-closed safety; the queue is operator-visibility
    // state (so `mx-agent approval list/approve` can see and resolve a request).
    let approval_queue = Rc::new(RefCell::new(ApprovalQueue::load(paths).unwrap_or_default()));
    let approval_queue_before = approval_queue.borrow().clone();
    // A single, finite expiry stamped onto requests raised this pass.
    let approval_expires_at = approval_request_expiry(SystemTime::now(), APPROVAL_REQUEST_TTL);
    // The matching "now" (Unix seconds) used to detect a queued request whose
    // stamped `expires_at` has already passed (issue #265). Captured once per
    // pass so every gate agrees on the present.
    let approval_now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default();

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

        // Resolve held approval-required tasks against published decisions, but
        // only read the timeline when this room has a runnable candidate for an
        // owned agent — a held approval-required task stays `pending` until it is
        // decided, so this keeps resolving it while skipping the round-trip for
        // rooms with no pending/assigned work. (Gating on the queue instead would
        // break the approve flow: the operator's `approval approve` removes the
        // queued entry, so the decision must still be read on the next pass.) The
        // map is keyed by `request_id` and records whether the decision permits a
        // spawn (only an explicit `approved` does; everything else fails closed.)
        let owned_ids: BTreeSet<&str> = owned.iter().map(|a| a.agent_id.as_str()).collect();
        let has_runnable_candidate = snapshot.iter().any(|task| {
            matches!(task.state.as_str(), STATE_PENDING | STATE_ASSIGNED)
                && owned_ids.contains(task.assigned_to.as_str())
        });
        // The extra approvers configured for this room (issue #309). The
        // authorized set is the union `{local_user} ∪ approvers`, applied inside
        // `verification_failure` via the `local_user` field, so this set holds
        // only the additional approvers (empty ⇒ daemon-only, the secure default).
        let approvers: BTreeSet<String> = policy
            .rooms
            .get(&room_id)
            .map(|r| r.approvers.iter().cloned().collect())
            .unwrap_or_default();

        // Only authorized, signature- AND trust-verified, unexpired decisions are
        // admitted (issues #264, #309): a forged or untrusted-key `approved` event
        // — even one published in room state — is dropped here and never reaches
        // the gate, so it cannot release a held task. The signing key must be
        // locally `Trusted`, not merely room-published.
        let verification = DecisionVerification {
            local_user: &local_user,
            approvers: &approvers,
            verifying_keys: &verifying_keys,
            trust: &trust,
            now_unix: approval_now_unix,
        };
        let decisions: HashMap<String, ApprovalDecision> = if has_runnable_candidate {
            match runtime.block_on(read_verified_approval_decisions(
                &room,
                APPROVAL_DECISIONS_SCAN_LIMIT,
                &verification,
            )) {
                Ok(found) => found,
                Err(e) => {
                    tracing::debug!(error = %e, room = %room_id, "scheduler pass could not read approval decisions");
                    HashMap::new()
                }
            }
        } else {
            HashMap::new()
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
                paths,
                &policy,
                &trust,
                attempted,
                claimed_invocations,
                &decisions,
                Rc::clone(&approval_queue),
                &approval_expires_at,
                approval_now_unix,
                mode,
            );
        }

        // Sweep undecided *live* exec/call holds whose approval window has passed
        // (issue #306, mirroring the task expiry sweep of #265/#291): emit the
        // terminal rejection and remove them from the queue so they never run.
        // Cheap and timeline-free — it only compares the persisted `expires_at`
        // stamp to `now` — so it runs every pass, independent of runnable work.
        sweep_expired_live_holds(
            runtime,
            &room,
            &room_id,
            paths,
            &approval_queue,
            approval_now_unix,
        );
    }

    // Persist the approval queue only if a gate enqueued or resolved something
    // this pass, so `mx-agent approval list/approve` sees held requests.
    if *approval_queue.borrow() != approval_queue_before {
        if let Err(e) = approval_queue.borrow().save(paths) {
            tracing::warn!(error = %e, "scheduler pass could not persist approval queue");
        }
    }
}

/// Sweep undecided *live* `exec`/`call` holds in `room_id` whose approval window
/// has expired, removing them from the shared queue fail-closed (issue #306).
///
/// Only holds carrying live-resume material (`held_request.is_some()`) are
/// considered: task-backed holds are the scheduler gate's to expire (#265), and
/// a `None` hold cannot be resumed regardless. For each expired live hold this
/// emits the terminal rejection (`exec.rejected` / `call.response` error with
/// `approval_expired`), audits *expired-while-held*, and removes the entry. The
/// caller persists the (now shared, mutated) queue once if anything changed.
/// Expiry can only ever **block** a hold, never release one, so it strengthens
/// the deny-by-default posture.
fn sweep_expired_live_holds(
    runtime: &Arc<tokio::runtime::Runtime>,
    room: &matrix_sdk::Room,
    room_id: &str,
    paths: &SessionPaths,
    queue: &Rc<RefCell<ApprovalQueue>>,
    now_unix: i64,
) {
    use crate::approval::HeldRequest;

    // Snapshot the expired live holds before mutating, so the immutable borrow is
    // released before any `remove`. The selection is a pure function, so it is
    // unit-tested without a live `Room`.
    let expired = expired_live_holds_in_room(&queue.borrow(), room_id, now_unix);

    for pending in expired {
        match pending.held_request {
            Some(HeldRequest::Exec(request)) => {
                runtime.block_on(crate::exec::expire_held_exec(
                    room, paths, room_id, &request,
                ));
            }
            Some(HeldRequest::Call(request)) => {
                runtime.block_on(crate::call::expire_held_call(
                    room, paths, room_id, &request,
                ));
            }
            // Defensive: the selection above only retains `Some` holds.
            None => continue,
        }
        queue
            .borrow_mut()
            .remove(pending.request.request_id.as_str());
    }
}

/// Select the *live* holds in `room_id` whose approval window has expired at
/// `now_unix` (issue #306).
///
/// Pure and fail-closed, so the sweep's selection is unit-testable without a
/// live `Room`. Only holds carrying live-resume material
/// (`held_request.is_some()`) past their persisted `expires_at` are returned:
/// task-backed and legacy (`None`) holds are left untouched (the scheduler gate
/// owns task expiry), and a fresh (unexpired) hold is left to be decided. A
/// malformed stamp is treated as not-yet-expired (it stays operator-decidable),
/// matching [`approval_request_expired`](crate::approval::approval_request_expired).
fn expired_live_holds_in_room(
    queue: &ApprovalQueue,
    room_id: &str,
    now_unix: i64,
) -> Vec<crate::approval::PendingApproval> {
    queue
        .pending_in_room(room_id)
        .filter(|pending| {
            pending.held_request.is_some()
                && crate::approval::approval_request_expired(&pending.request.expires_at, now_unix)
        })
        .cloned()
        .collect()
}

/// Build the production-configured task orchestrator for `agent_id`: the same
/// policy / trust / replay / verifying-key / audit-log wiring the live scheduler
/// uses, minus the approval gate (which borrows the returned orchestrator's
/// replay-cache handle and so is attached by the caller).
///
/// The audit log is resolved the same way the exec/call path resolves it
/// ([`crate::audit::append_audit`]): the default config-dir path
/// ([`AuditLog::default_path`]) with a data-dir fallback, so task-action policy
/// decisions and direct exec/call decisions land in one audit log. The fallback
/// guarantees a path, so the production orchestrator is always audited.
///
/// The replay cache is **required**, not optional: replay/expiry enforcement is
/// part of the privileged-action verify pipeline, not a best-effort layer.
/// Taking a non-`Option` [`ReplayCache`] makes it impossible to construct the
/// production orchestrator (or its approval gate, which shares the handle)
/// cache-less; the caller obtains the cache via [`load_pass_replay_cache`] and
/// skips the whole pass when it cannot load.
///
/// Extracted from [`scheduler_pass_for_agent`] so the audit-log wiring is
/// unit-testable without a live Matrix `Room`.
pub(crate) fn build_scheduler_orchestrator(
    agent_id: String,
    room_id: &str,
    policy: Policy,
    trust: TrustStore,
    replay: ReplayCache,
    verifying_keys: &BTreeMap<String, VerifyingKey>,
    paths: &SessionPaths,
) -> TaskOrchestrator {
    let audit_log = AuditLog::new(
        AuditLog::default_path()
            .unwrap_or_else(|| paths.data_dir.join(crate::audit::AUDIT_FILE_NAME)),
    );
    let mut orchestrator = TaskOrchestrator::new(agent_id)
        .with_room_id(room_id.to_string())
        .with_policy(policy)
        .with_trust_store(trust)
        .with_audit_log(audit_log)
        .with_replay_cache(replay);
    for (key_id, key) in verifying_keys {
        orchestrator = orchestrator.with_verifying_key(key_id.clone(), *key);
    }
    orchestrator
}

/// Load the replay cache for a scheduler pass, or `None` to skip the pass.
///
/// Replay/expiry enforcement is part of the privileged-action verify pipeline,
/// not an optional layer, so a load error — IO or a corrupt/truncated cache
/// file ([`ReplayError::Corrupt`](crate::replay::ReplayError::Corrupt)) — is
/// logged loudly and **fails closed**: the caller must not claim, dispatch, or
/// release a held approval without replay protection. This mirrors the sync
/// router, which routes nothing when the cache cannot load (`sync.rs`). The
/// `/sync` health loop is separate and keeps running.
fn load_pass_replay_cache(paths: &SessionPaths) -> Option<ReplayCache> {
    match ReplayCache::load(paths) {
        Ok(cache) => Some(cache),
        Err(e) => {
            tracing::error!(
                error = %e,
                "could not load replay cache; skipping scheduler pass \
                 (no claim, dispatch, or approval release this pass)"
            );
            None
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
    paths: &SessionPaths,
    policy: &Policy,
    trust: &TrustStore,
    attempted: &mut HashSet<(String, u64)>,
    claimed_invocations: &mut BTreeSet<String>,
    decisions: &HashMap<String, ApprovalDecision>,
    approval_queue: Rc<RefCell<ApprovalQueue>>,
    approval_expires_at: &str,
    approval_now_unix: i64,
    mode: TaskDispatchMode,
) {
    // Policy and the local trust store are loaded once per pass by the caller
    // ([`scheduler_pass`]) and shared by reference; the orchestrator clones them
    // in via its by-value `with_policy`/`with_trust_store` API. Deny-by-default:
    // an absent/invalid policy denies every action and an unreadable trust store
    // trusts nothing, so nothing is claimed or dispatched.

    // Task state is advisory: configuring the trust store and replay cache makes
    // the orchestrator require a valid signed authorization before any
    // claim/dispatch, so an unsigned/untrusted/expired/replayed task action is
    // blocked rather than executed. The audit log is attached here so every
    // policy decision (allow and deny) leaves a trace, matching the direct
    // exec/call path (issue #266).
    //
    // Replay protection is mandatory: if the cache cannot be loaded (IO error or
    // a corrupt cache file) we fail closed and skip this agent's pass entirely —
    // no claim, dispatch, or approval release — rather than running cache-less
    // (issue #305). Every owned agent loads the same shared cache file, so a
    // persistent load error skips them all, equivalent to skipping the pass,
    // while the separate `/sync` health loop keeps running.
    let Some(replay) = load_pass_replay_cache(paths) else {
        return;
    };
    let mut orchestrator = build_scheduler_orchestrator(
        agent.agent_id.clone(),
        room_id,
        policy.clone(),
        trust.clone(),
        replay,
        verifying_keys,
        paths,
    );

    // Approval gate: a task local policy marks `requires_approval` is held until a
    // verified, published decision approves it. The first undecided encounter
    // enqueues a pending approval into the shared queue (persisted by the caller);
    // a verified `approved` decision lets it proceed, any other decision blocks it.
    // Without this gate the orchestrator fails closed and never runs the action.
    // The gate shares the orchestrator's replay cache so an approving decision's
    // single-use nonce is burned on the releasing pass (issue #264), preventing a
    // stale duplicate from re-releasing the task on a later pass.
    let decisions = decisions.clone();
    let gate = QueueApprovalGate::new(
        room_id.to_string(),
        agent.agent_id.clone(),
        approval_expires_at.to_string(),
        approval_queue,
        move |request_id: &str| decisions.get(request_id).cloned(),
    )
    .with_now_unix(approval_now_unix)
    .with_replay_cache(orchestrator.replay_cache_handle());
    orchestrator = orchestrator.with_approval_gate(Box::new(gate));

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
        // Never clobber a task another writer has already finalized — in
        // particular an operator `task cancel` that finalized it `cancelled` while
        // this daemon was mid-dispatch (issue #239). If the live room state shows
        // the task terminal, refuse the write as stale so the cancelled outcome
        // wins. A lagging non-terminal read is harmless: the write cache below
        // still drives the claim→finalize transition (#230).
        if let Ok(Some((latest, _))) = runtime.block_on(read_task_state(room, &options.task_id)) {
            if crate::task::is_terminal(&latest.state) {
                return Err(WorkspaceError::StaleTaskUpdate {
                    task_id: options.task_id.clone(),
                    expected: options.expected_state_rev.unwrap_or(latest.state_rev),
                    current: latest.state_rev,
                });
            }
        }
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

    // Restart reconciliation matches an `executing` task to its live invocation
    // state by the unified id (issue #239): read the room's invocation snapshot so
    // a task whose remote invocation already finished is reconciled to that real
    // outcome, one still running is left alone, and a genuine orphan is recovered.
    // A read failure yields an empty map (fail the orphan, the historical default).
    let invocations: BTreeMap<String, InvocationState> = match runtime
        .block_on(crate::invocation::read_all_invocation_states(room))
    {
        Ok(states) => states
            .into_iter()
            .map(|inv| (inv.invocation_id.clone(), inv))
            .collect(),
        Err(e) => {
            tracing::debug!(error = %e, room = %room_id, "scheduler pass could not read invocation states");
            BTreeMap::new()
        }
    };

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
                &invocations,
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
                &invocations,
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
        OrchestrationOutcome::ReconciledInvocation { task_id, state } => tracing::info!(
            room = %room_id, agent = %agent_id, task_id = %task_id, state = %state,
            "scheduler reconciled executing task with its terminal invocation"
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
            | Self::ReconciledInvocation { task_id, .. }
            | Self::StillRunningInvocation { task_id }
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

    /// Points [`AuditLog::default_path`] at a private per-test tempdir by setting
    /// `MX_AGENT_CONFIG_DIR`, so the scheduler-orchestrator audit tests resolve
    /// their audit log into the tempdir instead of touching the real
    /// `~/.config/mx-agent/audit.log` (test isolation, issue #266). The crate-level
    /// env lock ([`crate::tests::config_dir_env_lock`]) is held for the lifetime of
    /// the guard so no other test module can observe a half-set value.
    struct ConfigDirGuard {
        dir: std::path::PathBuf,
        _guard: std::sync::MutexGuard<'static, ()>,
    }

    impl ConfigDirGuard {
        fn new(tag: &str) -> Self {
            let guard = crate::tests::config_dir_env_lock();
            let dir =
                std::env::temp_dir().join(format!("mx-agent-sched-{}-{}", tag, std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::env::set_var(mx_agent_policy::ENV_CONFIG_DIR, &dir);
            Self { dir, _guard: guard }
        }
    }

    impl Drop for ConfigDirGuard {
        fn drop(&mut self) {
            std::env::remove_var(mx_agent_policy::ENV_CONFIG_DIR);
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

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
            &BTreeMap::new(),
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
            ToolTaskDispatcher::with_runner(|_n, _a, _al, _cwd| {
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
            &BTreeMap::new(),
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
            &BTreeMap::new(),
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
            ToolTaskDispatcher::with_runner(|name, _args, _al, _cwd| {
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
            .dispatch(&task, &tool, "inv-1", &Allowance::default())
            .unwrap()
            .is_success());
        assert!(dispatcher
            .dispatch(&task, &exec, "inv-2", &Allowance::default())
            .unwrap()
            .is_success());
    }

    #[test]
    fn tick_runs_runnable_tool_task_to_success() {
        let mut store = RoomTaskStore::default();
        store.insert(tool_task("task-a", "run_tests"));
        let mut dispatcher = RoutingDispatcher::new(
            ToolTaskDispatcher::with_runner(|_n, _a, _al, _cwd| {
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
                ToolTaskDispatcher::with_runner(|_n, _a, _al, _cwd| {
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
            ToolTaskDispatcher::with_runner(|_n, _a, _al, _cwd| panic!("no tool")),
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
            ToolTaskDispatcher::with_runner(|_n, _a, _al, _cwd| panic!("no tool")),
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
            ToolTaskDispatcher::with_runner(|_n, _a, _al, _cwd| {
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
                &BTreeMap::new(),
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
                &BTreeMap::new(),
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
                _allowance: &Allowance,
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

    /// Policy that allows the planner's `run_tests` tool but marks it
    /// `requires_approval`, so the approval gate must be consulted before any
    /// claim/dispatch.
    fn approval_policy() -> Policy {
        Policy::parse(&format!(
            r#"
[rooms."{ROOM}"]
trusted = true

[rooms."{ROOM}".agents."{PLANNER}"]
allow_tools = ["run_tests"]
requires_approval = true
"#
        ))
        .expect("approval policy parses")
    }

    /// Build a verified-looking approval decision that permits (or denies) a
    /// spawn. These gate tests attach no replay cache, so `nonce`/`expires_at`
    /// can be absent — the gate releases on the decision value alone.
    fn decision(permits: bool) -> ApprovalDecision {
        ApprovalDecision {
            request_id: "approval:task-a".to_string(),
            decision: if permits { "approved" } else { "denied" }.to_string(),
            approved_by: "@operator:server".to_string(),
            created_at: "2026-06-05T00:00:00Z".to_string(),
            nonce: None,
            expires_at: None,
            signature: None,
            extra: Default::default(),
        }
    }

    /// Run one tick with an approval gate wired exactly as the live loop does:
    /// the gate shares `queue` and resolves decisions from `decisions`
    /// (`request_id -> permits_spawn`). Returns the outcomes; `queue` reflects the
    /// gate's enqueues/removes afterward.
    fn tick_with_approval<D: TaskDispatcher>(
        store: &mut RoomTaskStore,
        dispatcher: &mut D,
        decisions: HashMap<String, bool>,
        queue: Rc<RefCell<ApprovalQueue>>,
    ) -> Vec<OrchestrationOutcome> {
        let snapshot = store.snapshot();
        let scheduler = TaskScheduler::new(AGENT, 4);
        let gate = QueueApprovalGate::new(
            ROOM,
            AGENT,
            "2026-06-05T00:00:00Z",
            Rc::clone(&queue),
            move |request_id: &str| decisions.get(request_id).map(|&permits| decision(permits)),
        );
        let orchestrator = TaskOrchestrator::new(AGENT)
            .with_room_id(ROOM)
            .with_policy(approval_policy())
            .with_approval_gate(Box::new(gate));
        let mut claimed = BTreeSet::new();
        let store_ref = std::cell::RefCell::new(store);
        let mut matrix_store = MatrixTaskStore::new(ROOM, |options: UpdateTaskOptions| {
            store_ref.borrow_mut().apply(options)
        });
        let mut attempted = HashSet::new();
        run_scheduler_tick(
            &scheduler,
            &orchestrator,
            &snapshot,
            &BTreeMap::new(),
            &mut claimed,
            &mut matrix_store,
            dispatcher,
            &mut attempted,
        )
    }

    #[test]
    fn approval_required_task_is_held_and_enqueued_without_a_decision() {
        // With no decision recorded, the gate holds the task (fail closed): it is
        // not spawned, stays re-schedulable, and a pending approval is enqueued
        // into the shared queue (which the live loop persists for the operator).
        let mut store = RoomTaskStore::default();
        store.insert(tool_task("task-a", "run_tests"));
        let mut dispatcher = RoutingDispatcher::new(
            ToolTaskDispatcher::with_runner(|_n, _a, _al, _cwd| panic!("held task must not spawn")),
            ExecTaskDispatcher::with_runner(|_r| panic!("no exec")),
        );
        let queue = Rc::new(RefCell::new(ApprovalQueue::default()));
        let outcomes = tick_with_approval(
            &mut store,
            &mut dispatcher,
            HashMap::new(),
            Rc::clone(&queue),
        );
        assert!(
            outcomes.iter().any(|o| matches!(
                o,
                OrchestrationOutcome::AwaitingApproval { request_id: Some(id), .. }
                    if id == "approval:task-a"
            )),
            "task must be held awaiting approval: {outcomes:?}"
        );
        assert_eq!(store.state_of("task-a"), STATE_PENDING);
        let pending = queue.borrow();
        let queued = pending
            .get("approval:task-a")
            .expect("a pending approval is enqueued for the operator");
        assert_eq!(queued.room_id, ROOM);
        assert_eq!(queued.request.target, AGENT);
    }

    #[test]
    fn approved_decision_lets_task_run_to_success() {
        // A recorded `approved` decision resolves the gate so the task proceeds to
        // claim/dispatch and succeeds, and the approval leaves the queue.
        let mut store = RoomTaskStore::default();
        store.insert(tool_task("task-a", "run_tests"));
        let mut dispatcher = RoutingDispatcher::new(
            ToolTaskDispatcher::with_runner(|_n, _a, _al, _cwd| {
                Ok(ToolResult {
                    exit_code: 0,
                    summary: "ok".to_string(),
                })
            }),
            ExecTaskDispatcher::with_runner(|_r| panic!("no exec")),
        );
        let decisions = HashMap::from([("approval:task-a".to_string(), true)]);
        let queue = Rc::new(RefCell::new(ApprovalQueue::default()));
        let outcomes =
            tick_with_approval(&mut store, &mut dispatcher, decisions, Rc::clone(&queue));
        assert!(
            outcomes.iter().any(|o| matches!(
                o,
                OrchestrationOutcome::Completed { state, .. } if state == STATE_SUCCEEDED
            )),
            "approved task must run to success: {outcomes:?}"
        );
        assert_eq!(store.state_of("task-a"), STATE_SUCCEEDED);
        assert!(
            queue.borrow().get("approval:task-a").is_none(),
            "an approved request is removed from the queue"
        );
    }

    #[test]
    fn held_task_resumes_on_a_later_tick_after_approval() {
        // The `attempted` dedup must not permanently skip a held approval task at
        // its (unchanging) revision: once a decision lands, a later tick over the
        // same `attempted` set re-evaluates and runs it.
        let mut store = RoomTaskStore::default();
        store.insert(tool_task("task-a", "run_tests"));
        let scheduler = TaskScheduler::new(AGENT, 4);
        let mut attempted = HashSet::new();
        let mut claimed = BTreeSet::new();

        // Tick 1: no decision -> held, command never spawns.
        {
            let snapshot = store.snapshot();
            let queue = Rc::new(RefCell::new(ApprovalQueue::default()));
            let gate = QueueApprovalGate::new(
                ROOM,
                AGENT,
                "2026-06-05T00:00:00Z",
                Rc::clone(&queue),
                move |_id: &str| None,
            );
            let orchestrator = TaskOrchestrator::new(AGENT)
                .with_room_id(ROOM)
                .with_policy(approval_policy())
                .with_approval_gate(Box::new(gate));
            let mut dispatcher = RoutingDispatcher::new(
                ToolTaskDispatcher::with_runner(|_n, _a, _al, _cwd| {
                    panic!("held task must not spawn")
                }),
                ExecTaskDispatcher::with_runner(|_r| panic!("no exec")),
            );
            let store_ref = std::cell::RefCell::new(&mut store);
            let mut matrix_store = MatrixTaskStore::new(ROOM, |options: UpdateTaskOptions| {
                store_ref.borrow_mut().apply(options)
            });
            let outcomes = run_scheduler_tick(
                &scheduler,
                &orchestrator,
                &snapshot,
                &BTreeMap::new(),
                &mut claimed,
                &mut matrix_store,
                &mut dispatcher,
                &mut attempted,
            );
            assert!(
                outcomes
                    .iter()
                    .any(|o| matches!(o, OrchestrationOutcome::AwaitingApproval { .. })),
                "tick 1 must hold the task: {outcomes:?}"
            );
        }
        assert_eq!(store.state_of("task-a"), STATE_PENDING);

        // Tick 2: same `attempted` set, now approved -> the held task is
        // re-evaluated and runs to success.
        {
            let snapshot = store.snapshot();
            let queue = Rc::new(RefCell::new(ApprovalQueue::default()));
            let decisions = HashMap::from([("approval:task-a".to_string(), true)]);
            let gate = QueueApprovalGate::new(
                ROOM,
                AGENT,
                "2026-06-05T00:00:00Z",
                Rc::clone(&queue),
                move |id: &str| decisions.get(id).map(|&permits| decision(permits)),
            );
            let orchestrator = TaskOrchestrator::new(AGENT)
                .with_room_id(ROOM)
                .with_policy(approval_policy())
                .with_approval_gate(Box::new(gate));
            let mut dispatcher = RoutingDispatcher::new(
                ToolTaskDispatcher::with_runner(|_n, _a, _al, _cwd| {
                    Ok(ToolResult {
                        exit_code: 0,
                        summary: "ok".to_string(),
                    })
                }),
                ExecTaskDispatcher::with_runner(|_r| panic!("no exec")),
            );
            let store_ref = std::cell::RefCell::new(&mut store);
            let mut matrix_store = MatrixTaskStore::new(ROOM, |options: UpdateTaskOptions| {
                store_ref.borrow_mut().apply(options)
            });
            let outcomes = run_scheduler_tick(
                &scheduler,
                &orchestrator,
                &snapshot,
                &BTreeMap::new(),
                &mut claimed,
                &mut matrix_store,
                &mut dispatcher,
                &mut attempted,
            );
            assert!(
                outcomes.iter().any(|o| matches!(
                    o,
                    OrchestrationOutcome::Completed { state, .. } if state == STATE_SUCCEEDED
                )),
                "tick 2 must run the approved task: {outcomes:?}"
            );
        }
        assert_eq!(store.state_of("task-a"), STATE_SUCCEEDED);
    }

    #[test]
    fn denied_decision_blocks_task_without_spawning() {
        // A recorded `denied` decision blocks the task; the command never spawns.
        let mut store = RoomTaskStore::default();
        store.insert(tool_task("task-a", "run_tests"));
        let mut dispatcher = RoutingDispatcher::new(
            ToolTaskDispatcher::with_runner(|_n, _a, _al, _cwd| {
                panic!("denied task must never spawn")
            }),
            ExecTaskDispatcher::with_runner(|_r| panic!("no exec")),
        );
        let decisions = HashMap::from([("approval:task-a".to_string(), false)]);
        let queue = Rc::new(RefCell::new(ApprovalQueue::default()));
        let outcomes =
            tick_with_approval(&mut store, &mut dispatcher, decisions, Rc::clone(&queue));
        assert!(
            outcomes
                .iter()
                .any(|o| matches!(o, OrchestrationOutcome::Denied { .. })),
            "denied task must be blocked: {outcomes:?}"
        );
        assert_eq!(store.state_of("task-a"), STATE_BLOCKED);
        let result = store.tasks.get("task-a").unwrap().result.clone().unwrap();
        assert_eq!(
            result.get("reason").and_then(Value::as_str),
            Some("approval_denied")
        );
        assert!(
            queue.borrow().get("approval:task-a").is_none(),
            "a denied request is removed from the queue"
        );
    }

    #[test]
    fn load_pass_replay_cache_skips_on_corrupt() {
        // Fail-closed decision (issue #305): a corrupt cache file makes the
        // scheduler pass skip (returns `None`), while an absent/valid file loads.
        let dir = std::env::temp_dir().join(format!(
            "mx-agent-sched-replay-load-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let paths = SessionPaths::for_data_dir(dir.clone());

        // Absent file: a fresh empty cache loads, so the pass proceeds.
        assert!(
            load_pass_replay_cache(&paths).is_some(),
            "an absent cache file must load a fresh cache, not skip the pass"
        );

        // Corrupt file: fail closed — skip the pass.
        std::fs::write(dir.join("replay_cache.json"), b"not valid json").unwrap();
        assert!(
            load_pass_replay_cache(&paths).is_none(),
            "a corrupt replay cache must skip the scheduler pass (fail closed)"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_pass_replay_cache_skips_on_io_error() {
        // Fail-closed decision (issue #305): a genuine (non-NotFound) IO error
        // loading the cache file also makes the scheduler pass skip (returns
        // `None`), not just a corrupt-JSON case. Regression guard: the error
        // arm of `load_pass_replay_cache` must match ALL `Err(_)` variants, not
        // only `ReplayError::Corrupt`.
        let dir = std::env::temp_dir().join(format!(
            "mx-agent-sched-replay-ioerr-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let paths = SessionPaths::for_data_dir(dir.clone());

        // Make `replay_cache.json` a directory so `fs::read` returns a
        // non-NotFound IO error (IsADirectory / EISDIR on Unix).
        std::fs::create_dir(dir.join("replay_cache.json")).unwrap();
        assert!(
            load_pass_replay_cache(&paths).is_none(),
            "an IO error reading the replay cache must skip the scheduler pass (fail closed)"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- build_scheduler_orchestrator audit-log wiring (issue #266) -----------

    /// Build a signed tool action and the trust artifacts needed to validate it,
    /// so tests can exercise the full `build_scheduler_orchestrator` path (which
    /// requires a signed authorization when a trust store is attached).
    ///
    /// Returns `(TrustStore, verifying_keys, TaskState)`.  The signing key is
    /// fixed (`[7u8; 32]`) for reproducibility; the key ID is a recognisable
    /// test constant.
    fn scheduler_signed_tool_task(
        task_id: &str,
        tool: &str,
    ) -> (
        crate::trust::TrustStore,
        BTreeMap<String, ed25519_dalek::VerifyingKey>,
        TaskState,
    ) {
        use ed25519_dalek::SigningKey;

        const TEST_KEY_ID: &str = "mxagent-ed25519:sched-wiring-test-key";

        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let verifying_key = signing_key.verifying_key();

        let mut trust = crate::trust::TrustStore::default();
        trust.approve(
            PLANNER,
            TEST_KEY_ID,
            Some("SHA256:test".to_string()),
            Some(ROOM.to_string()),
            None,
        );

        let mut keys = BTreeMap::new();
        keys.insert(TEST_KEY_ID.to_string(), verifying_key);

        let unsigned_action = TaskAction::Tool {
            tool: tool.to_string(),
            args: serde_json::json!({}),
            authorization: None,
        };
        let auth = crate::task_orchestrator::sign_task_action(
            &signing_key,
            TEST_KEY_ID,
            task_id,
            &unsigned_action,
            PLANNER,
            AGENT,
            "2026-01-01T00:00:00Z",
            "2099-01-01T00:00:00Z",
            "nonce-scheduler-wiring-001",
        )
        .expect("test signing must succeed");

        let mut t = base_task(task_id, STATE_PENDING);
        t.action = Some(TaskAction::Tool {
            tool: tool.to_string(),
            args: serde_json::json!({}),
            authorization: Some(auth),
        });

        (trust, keys, t)
    }

    #[test]
    fn build_scheduler_orchestrator_has_audit_log() {
        // Regression guard for issue #266: build_scheduler_orchestrator must
        // chain with_audit_log so task-action policy decisions leave a trace.
        // audit_log_path() returns None only when with_audit_log was never called.
        let paths = crate::session::SessionPaths::for_data_dir(
            std::env::temp_dir().join(format!("mx-agent-sched-wiring-{}", std::process::id())),
        );
        let orchestrator = build_scheduler_orchestrator(
            AGENT.to_string(),
            ROOM,
            policy(),
            crate::trust::TrustStore::default(),
            ReplayCache::load(&paths).expect("replay cache loads"),
            &BTreeMap::new(),
            &paths,
        );
        assert!(
            orchestrator.audit_log_path().is_some(),
            "build_scheduler_orchestrator must call with_audit_log(); \
             audit_log_path() returns None only when with_audit_log was never called (issue #266)"
        );
    }

    #[test]
    fn build_scheduler_orchestrator_audits_policy_denied_action() {
        // A policy-denied task action through the production scheduler
        // orchestrator must produce an audit record with "decision":"denied"
        // (issue #266: audit was silently skipped before the fix because the
        // production orchestrator never had an audit log attached).
        //
        // MX_AGENT_CONFIG_DIR points AuditLog::default_path() at a private
        // tempdir so this test never touches the real audit.log. We still track
        // the byte offset across process_one to isolate our entry.
        let config_dir = ConfigDirGuard::new("audit-deny");
        let (trust, keys, t) = scheduler_signed_tool_task("task-sched-deny", "delete_everything");
        let paths = crate::session::SessionPaths::for_data_dir(
            std::env::temp_dir().join(format!("mx-agent-sched-audit-deny-{}", std::process::id())),
        );
        let orchestrator = build_scheduler_orchestrator(
            AGENT.to_string(),
            ROOM,
            policy(),
            trust,
            ReplayCache::load(&paths).expect("replay cache loads"),
            &keys,
            &paths,
        );
        let audit_path = orchestrator
            .audit_log_path()
            .expect("production orchestrator must have audit log")
            .to_path_buf();
        assert!(
            audit_path.starts_with(&config_dir.dir),
            "audit log must resolve into the per-test tempdir, not {audit_path:?}"
        );

        // Snapshot the pre-existing byte count so we only inspect the new entry.
        let pre_size = std::fs::metadata(&audit_path).map(|m| m.len()).unwrap_or(0);

        let mut store_inner = RoomTaskStore::default();
        store_inner.insert(t.clone());
        let store_ref = std::cell::RefCell::new(store_inner);
        let mut ms = MatrixTaskStore::new(ROOM, |opts: UpdateTaskOptions| {
            store_ref.borrow_mut().apply(opts)
        });
        let mut dispatcher = RoutingDispatcher::new(
            ToolTaskDispatcher::with_runner(|_n, _a, _al, _cwd| {
                panic!("policy-denied action must never dispatch")
            }),
            ExecTaskDispatcher::with_runner(|_r| panic!("no exec")),
        );
        orchestrator.process_one(&t, std::slice::from_ref(&t), &mut ms, &mut dispatcher);

        let full =
            std::fs::read_to_string(&audit_path).expect("audit log must exist after process_one");
        let new_content = &full[pre_size as usize..];
        assert!(
            new_content.contains("\"decision\":\"denied\""),
            "policy-denied action must be audited as denied: {new_content}"
        );
        assert!(new_content.contains("delete_everything"), "{new_content}");
    }

    #[test]
    fn build_scheduler_orchestrator_audits_policy_allowed_action() {
        // A policy-allowed task action through the production scheduler
        // orchestrator must produce an audit record with "decision":"allowed"
        // (issue #266: auditing was a no-op before the fix because the
        // production orchestrator never had an audit log attached).
        //
        // MX_AGENT_CONFIG_DIR points AuditLog::default_path() at a private
        // tempdir so this test never touches the real audit.log.
        let config_dir = ConfigDirGuard::new("audit-allow");
        let (trust, keys, t) = scheduler_signed_tool_task("task-sched-allow", "run_tests");
        let paths = crate::session::SessionPaths::for_data_dir(
            std::env::temp_dir().join(format!("mx-agent-sched-audit-allow-{}", std::process::id())),
        );
        let orchestrator = build_scheduler_orchestrator(
            AGENT.to_string(),
            ROOM,
            policy(),
            trust,
            ReplayCache::load(&paths).expect("replay cache loads"),
            &keys,
            &paths,
        );
        let audit_path = orchestrator
            .audit_log_path()
            .expect("production orchestrator must have audit log")
            .to_path_buf();
        assert!(
            audit_path.starts_with(&config_dir.dir),
            "audit log must resolve into the per-test tempdir, not {audit_path:?}"
        );

        let pre_size = std::fs::metadata(&audit_path).map(|m| m.len()).unwrap_or(0);

        let mut store_inner = RoomTaskStore::default();
        store_inner.insert(t.clone());
        let store_ref = std::cell::RefCell::new(store_inner);
        let mut ms = MatrixTaskStore::new(ROOM, |opts: UpdateTaskOptions| {
            store_ref.borrow_mut().apply(opts)
        });
        let mut dispatcher = RoutingDispatcher::new(
            ToolTaskDispatcher::with_runner(|_n, _a, _al, _cwd| {
                Ok(ToolResult {
                    exit_code: 0,
                    summary: "ok".to_string(),
                })
            }),
            ExecTaskDispatcher::with_runner(|_r| panic!("no exec")),
        );
        orchestrator.process_one(&t, std::slice::from_ref(&t), &mut ms, &mut dispatcher);

        let full =
            std::fs::read_to_string(&audit_path).expect("audit log must exist after process_one");
        let new_content = &full[pre_size as usize..];
        assert!(
            new_content.contains("\"decision\":\"allowed\""),
            "policy-allowed action must be audited as allowed: {new_content}"
        );
        assert!(new_content.contains("run_tests"), "{new_content}");
    }

    #[test]
    fn build_scheduler_orchestrator_blocks_action_with_untrusted_signing_key() {
        // Issue #309 wiring: the trust store passed to build_scheduler_orchestrator
        // is the final authority. When a task's authorization key is present in
        // `verifying_keys` (room-published state) but absent from the local trust
        // store, the orchestrator must block the task — room state alone is not
        // sufficient. This mirrors the `untrusted_key` anchor in the exec/call path.
        let config_dir = ConfigDirGuard::new("trust-wire");
        // scheduler_signed_tool_task produces a signed task and an populated
        // verifying_keys map. We intentionally withhold the trust store so the key
        // is room-published but not locally trusted.
        let (_trust, keys, t) = scheduler_signed_tool_task("task-trust-wire", "run_tests");
        let paths = crate::session::SessionPaths::for_data_dir(
            std::env::temp_dir().join(format!("mx-agent-sched-trust-wire-{}", std::process::id())),
        );
        let orchestrator = build_scheduler_orchestrator(
            AGENT.to_string(),
            ROOM,
            policy(),
            crate::trust::TrustStore::default(), // empty — key not trusted
            ReplayCache::load(&paths).expect("replay cache loads"),
            &keys,
            &paths,
        );
        let mut store_inner = RoomTaskStore::default();
        store_inner.insert(t.clone());
        let store_ref = std::cell::RefCell::new(store_inner);
        let mut ms = MatrixTaskStore::new(ROOM, |opts: UpdateTaskOptions| {
            store_ref.borrow_mut().apply(opts)
        });
        let mut dispatcher = RoutingDispatcher::new(
            ToolTaskDispatcher::with_runner(|_n, _a, _al, _cwd| {
                panic!("action with untrusted signing key must never dispatch")
            }),
            ExecTaskDispatcher::with_runner(|_r| panic!("no exec")),
        );
        let outcome =
            orchestrator.process_one(&t, std::slice::from_ref(&t), &mut ms, &mut dispatcher);
        assert!(
            matches!(outcome, OrchestrationOutcome::Denied { .. }),
            "task with untrusted signing key must be blocked, not dispatched: {outcome:?}"
        );
        assert_eq!(
            store_ref.borrow().state_of("task-trust-wire"),
            STATE_BLOCKED,
            "task must be finalized blocked when its signing key is absent from the trust store"
        );
        drop(config_dir);
    }

    /// `sleep_interruptible` must wake early when the `running` flag is cleared
    /// by another thread. This covers the shutdown path shared by both the
    /// scheduler loop and the heartbeat loop (issue #250).
    #[test]
    fn sleep_interruptible_exits_early_when_flag_cleared() {
        let running = Arc::new(AtomicBool::new(true));
        let flag = running.clone();
        let handle = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            flag.store(false, Ordering::SeqCst);
        });
        let start = std::time::Instant::now();
        // Would block for 10 full seconds if it ignored the flag.
        sleep_interruptible(Duration::from_secs(10), &running);
        handle.join().unwrap();
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "sleep_interruptible must wake within ~150ms of the flag clear, not after the full 10s"
        );
    }

    // --- live-hold expiry sweep selection (issue #306) ----------------------

    fn pending_exec_hold(
        request_id: &str,
        room: &str,
        expires_at: &str,
        live: bool,
    ) -> crate::approval::PendingApproval {
        use mx_agent_protocol::schema::{ApprovalRequest, ExecRequest, Signature};
        let request = ApprovalRequest {
            request_id: request_id.to_string(),
            invocation_id: format!("inv_{request_id}"),
            requester: "@a:s".to_string(),
            target: "dev-pi".to_string(),
            summary: "held".to_string(),
            risk: "medium".to_string(),
            expires_at: expires_at.to_string(),
            extra: Default::default(),
        };
        let held_request = live.then(|| {
            crate::approval::HeldRequest::Exec(ExecRequest {
                invocation_id: format!("inv_{request_id}"),
                request_id: request_id.to_string(),
                target_agent: "dev-pi".to_string(),
                requesting_agent: "@a:s".to_string(),
                command: vec!["true".to_string()],
                cwd: "/repo".to_string(),
                env: Default::default(),
                stdin: false,
                stream: false,
                pty: false,
                timeout_ms: 1000,
                task_id: None,
                created_at: "2026-06-02T12:00:00Z".to_string(),
                expires_at: expires_at.to_string(),
                nonce: "n".to_string(),
                idempotency_key: format!("exec:inv_{request_id}"),
                signature: Signature {
                    alg: "ed25519".to_string(),
                    key_id: "k".to_string(),
                    sig: "s".to_string(),
                },
                extra: Default::default(),
            })
        });
        crate::approval::PendingApproval {
            room_id: room.to_string(),
            request,
            held_request,
            requester_user: None,
        }
    }

    #[test]
    fn expiry_sweep_selects_only_expired_live_holds() {
        // The sweep selects only live holds (held_request.is_some()) past their
        // stamp, leaving fresh holds and task/legacy (None) holds untouched, and
        // restricts to the room it is sweeping.
        let now = 1_748_865_600; // 2025-06-02T12:00:00Z
        let mut queue = ApprovalQueue::default();
        // Expired + live → selected.
        queue.enqueue(pending_exec_hold(
            "expired-live",
            ROOM,
            "2025-06-02T11:00:00Z",
            true,
        ));
        // Fresh + live → left to be decided.
        queue.enqueue(pending_exec_hold(
            "fresh-live",
            ROOM,
            "2025-06-02T13:00:00Z",
            true,
        ));
        // Expired but task/legacy (None) → the scheduler gate owns task expiry.
        queue.enqueue(pending_exec_hold(
            "expired-task",
            ROOM,
            "2025-06-02T11:00:00Z",
            false,
        ));
        // Expired + live but a different room → not swept by this room's pass.
        queue.enqueue(pending_exec_hold(
            "expired-other-room",
            "!other:server",
            "2025-06-02T11:00:00Z",
            true,
        ));

        let selected = expired_live_holds_in_room(&queue, ROOM, now);
        let ids: Vec<&str> = selected
            .iter()
            .map(|p| p.request.request_id.as_str())
            .collect();
        assert_eq!(ids, vec!["expired-live"], "got {ids:?}");
    }

    #[test]
    fn expiry_sweep_is_a_noop_when_nothing_expired() {
        let now = 1_748_865_600;
        let mut queue = ApprovalQueue::default();
        queue.enqueue(pending_exec_hold(
            "fresh-live",
            ROOM,
            "2025-06-02T13:00:00Z",
            true,
        ));
        assert!(expired_live_holds_in_room(&queue, ROOM, now).is_empty());
    }
}
