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

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::VerifyingKey;
use mx_agent_policy::{Allowance, CallContext, ExecContext, Outcome, Policy};
use mx_agent_protocol::canonical_json;
use mx_agent_protocol::id::generate_invocation_id;
use mx_agent_protocol::schema::{
    ApprovalDecision, ApprovalRequest, InvocationState, Signature, TaskAction,
    TaskActionAuthorization, TaskResult, TaskState,
};
use mx_agent_protocol::signing::{self, SignatureError};

use crate::approval::{
    approval_request_expired, decision_permits_spawn, ApprovalQueue, PendingApproval,
};
use crate::invocation::{
    is_terminal as invocation_is_terminal, task_result_from_invocation, task_state_for_invocation,
};
#[cfg(test)]
use serde_json::json;
use serde_json::Value;

use crate::audit::{AuditLog, AuditRecord};
use crate::replay::{ReplayCache, ReplayError};
use crate::task::{
    is_runnable, UpdateTaskOptions, STATE_BLOCKED, STATE_EXECUTING, STATE_FAILED, STATE_SUCCEEDED,
};
#[cfg(test)]
use crate::task::{STATE_ASSIGNED, STATE_PENDING};
use crate::trust::TrustStore;

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
    ///
    /// `allowance` carries the policy-resolved isolation settings (sandbox
    /// backend, network decision, filesystem binds, env allowlist) the local
    /// exec path must apply so an auto-executed task DAG runs under the same
    /// confinement as a direct `exec` (architecture §13.5). Dispatchers that do
    /// not spawn a local process (the tool path, and the Matrix transport, which
    /// re-resolves policy on the remote daemon) ignore it.
    fn dispatch(
        &mut self,
        task: &TaskState,
        action: &TaskAction,
        invocation_id: &str,
        allowance: &Allowance,
    ) -> Result<TaskExecutionResult, TaskDispatchError>;
}

/// Storage operations required by the orchestrator.
pub trait TaskStore {
    /// Claim a task at its observed revision, transitioning it to `executing`.
    fn claim(&mut self, options: UpdateTaskOptions) -> Result<TaskState, TaskStoreError>;
    /// Finalize a claimed task with terminal state and structured result.
    fn finalize(&mut self, options: UpdateTaskOptions) -> Result<TaskState, TaskStoreError>;
}

/// The disposition of a task action that local policy marked
/// `requires_approval` (architecture §12).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalDisposition {
    /// An approval decision permits the action to run now.
    Approved,
    /// An approval decision denied the action; it must never spawn.
    Denied(String),
    /// No decision yet: the action waits. The string is the request id the
    /// operator can inspect/decide.
    Pending(String),
    /// The approval window closed (`expires_at` passed) before any decision was
    /// made: the action must never spawn and the task is finalized `blocked`
    /// (issue #265). The string is the request id, now removed from the queue.
    Expired(String),
}

/// Gate consulted before running a task action that requires human approval.
///
/// When local policy returns `requires_approval` for an authorized task action,
/// the orchestrator asks the gate whether a decision exists. Implementations
/// must be **idempotent**: the first time an action is seen with no decision
/// they should record/emit exactly one approval request (so the operator can
/// inspect it via `mx-agent approval list`) and return
/// [`ApprovalDisposition::Pending`]; subsequent calls for the same undecided
/// action must not duplicate the request. A gate must never permit a denied or
/// undecided action to run.
pub trait TaskApprovalGate {
    /// Resolve the approval disposition for `task`'s `action`.
    fn evaluate(&mut self, task: &TaskState, action: &TaskAction) -> ApprovalDisposition;

    /// Un-burn the decision nonce consumed by the most recent `Approved`
    /// [`evaluate`](Self::evaluate), compensating a lost optimistic-claim race so
    /// the operator's single-use approval is not permanently spent on an action
    /// that never dispatched. Called only from the `StaleClaim` path, i.e. after
    /// approval released the task but the conditional claim lost its race.
    ///
    /// The default is a no-op, for gates that consume no nonce.
    fn compensate_lost_claim(&mut self) {}
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
    /// On restart, an `executing` task was reconciled with its linked invocation
    /// by the unified id: the invocation had already reached a terminal state, so
    /// the task was finalized to that real outcome rather than blindly failed
    /// (issue #239).
    ReconciledInvocation {
        /// Task ID.
        task_id: String,
        /// Terminal state the task was reconciled to (from the invocation).
        state: String,
    },
    /// On restart, an `executing` task's linked invocation (by the unified id) was
    /// found still running (non-terminal), so the task is left `executing` for the
    /// remote work to finish — not recovered as a stale orphan (issue #239).
    StillRunningInvocation {
        /// Task ID.
        task_id: String,
    },
    /// An `executing` task is owned by another (remote) agent; it is left
    /// unchanged during recovery and surfaced as a stale warning.
    StaleRemoteExecuting {
        /// Task ID.
        task_id: String,
        /// Agent that owns the executing task.
        owner: String,
    },
    /// The action is authorized but local policy requires human approval, which
    /// has not been granted yet; the task is not claimed or dispatched.
    AwaitingApproval {
        /// Task ID.
        task_id: String,
        /// Pending approval request id the operator can inspect, if the gate
        /// produced one.
        request_id: Option<String>,
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
    room_id: Option<String>,
    policy: Option<Policy>,
    audit_log: Option<AuditLog>,
    trust_store: Option<TrustStore>,
    verifying_keys: BTreeMap<String, VerifyingKey>,
    replay_cache: Option<Rc<RefCell<ReplayCache>>>,
    approval_gate: Option<RefCell<Box<dyn TaskApprovalGate>>>,
}

impl TaskOrchestrator {
    /// Build an orchestrator for `agent_id`.
    pub fn new(agent_id: impl Into<String>) -> Self {
        Self {
            agent_id: agent_id.into(),
            room_id: None,
            policy: None,
            audit_log: None,
            trust_store: None,
            verifying_keys: BTreeMap::new(),
            replay_cache: None,
            approval_gate: None,
        }
    }

    /// Attach the Matrix room ID used for local policy evaluation.
    pub fn with_room_id(mut self, room_id: impl Into<String>) -> Self {
        self.room_id = Some(room_id.into());
        self
    }

    /// Attach the local deny-by-default policy used to authorize task actions
    /// before the scheduler claims or dispatches them.
    pub fn with_policy(mut self, policy: Policy) -> Self {
        self.policy = Some(policy);
        self
    }

    /// Attach an audit log that records task action policy decisions.
    pub fn with_audit_log(mut self, audit_log: AuditLog) -> Self {
        self.audit_log = Some(audit_log);
        self
    }

    /// Attach the local trust store used to authorize signed task actions.
    pub fn with_trust_store(mut self, trust_store: TrustStore) -> Self {
        self.trust_store = Some(trust_store);
        self
    }

    /// Add a verifying key resolved for a task action signing key id.
    pub fn with_verifying_key(mut self, key_id: impl Into<String>, key: VerifyingKey) -> Self {
        self.verifying_keys.insert(key_id.into(), key);
        self
    }

    /// Attach replay protection for signed task action authorizations.
    ///
    /// The cache is held behind a shared [`Rc`] so the approval gate can consume
    /// an approval **decision** nonce against the *same* on-disk cache (see
    /// [`replay_cache_handle`](Self::replay_cache_handle)); a second cache over
    /// the same file would race the orchestrator's persists.
    pub fn with_replay_cache(mut self, replay_cache: ReplayCache) -> Self {
        self.replay_cache = Some(Rc::new(RefCell::new(replay_cache)));
        self
    }

    /// A handle to the shared replay cache, if one is configured.
    ///
    /// The approval gate uses this to consume an approval decision's single-use
    /// nonce on the pass that releases a held task, sharing the orchestrator's
    /// cache instance so both task-action and decision nonces persist to one file.
    pub fn replay_cache_handle(&self) -> Option<Rc<RefCell<ReplayCache>>> {
        self.replay_cache.clone()
    }

    /// Path of the audit log this orchestrator records policy decisions to, or
    /// `None` if no audit log is attached.
    ///
    /// Used by the scheduler wiring regression test to assert production
    /// auditing is enabled, so a future refactor that drops
    /// [`with_audit_log`](Self::with_audit_log) cannot silently regress.
    #[cfg(test)]
    pub(crate) fn audit_log_path(&self) -> Option<&std::path::Path> {
        self.audit_log.as_ref().map(AuditLog::path)
    }

    /// Attach the approval gate consulted when local policy requires approval.
    ///
    /// Without a gate, an action that requires approval cannot run: the
    /// orchestrator fails closed and reports [`OrchestrationOutcome::AwaitingApproval`]
    /// without claiming or dispatching.
    pub fn with_approval_gate(mut self, gate: Box<dyn TaskApprovalGate>) -> Self {
        self.approval_gate = Some(RefCell::new(gate));
        self
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
        // Signature/trust first (idempotent), then deny-by-default policy, then
        // approval. The single-use replay/expiry nonce is consumed *after*
        // approval so a task held pending a decision over several passes is not
        // replay-blocked when it resumes; it is burned only on the pass that goes
        // on to claim and dispatch.
        if let Err(outcome) =
            self.verify_task_action_authorization(task, &action, &invocation_id, store)
        {
            return outcome;
        }
        let allowance = match self.authorize_task_action(task, &action, &invocation_id, store) {
            Ok(allowance) => allowance,
            Err(outcome) => return outcome,
        };
        if allowance.requires_approval {
            if let Err(outcome) = self.resolve_approval(task, &action, &invocation_id, store) {
                return outcome;
            }
        }
        if let Err(outcome) = self.admit_task_action_replay(task, &action, &invocation_id, store) {
            return outcome;
        }

        // Optimistic claim: transition pending/assigned -> executing only if the
        // task is still at the observed `state_rev`. The claim also records this
        // agent as the owner via `assigned_to`, so a successful claim publishes
        // both the executing state and ownership atomically. If another daemon
        // claimed first, the conditional update is stale and we must not run.
        let claimed = match store.claim(UpdateTaskOptions {
            room: String::new(),
            task_id: task.task_id.clone(),
            state: Some(STATE_EXECUTING.to_string()),
            assigned_to: Some(self.agent_id.clone()),
            invocation_id: Some(invocation_id.clone()),
            expected_state_rev: Some(task.state_rev),
            ..UpdateTaskOptions::default()
        }) {
            Ok(claimed) => claimed,
            Err(TaskStoreError::StaleClaim { .. }) => {
                // Benign optimistic-concurrency race: the task advanced since we
                // read it (another daemon claimed first, or an operator cancelled
                // it). The single-use nonces this pass already burned *before* the
                // claim — the action nonce here, and the approval decision nonce
                // inside the gate — must be un-burned so the next pass retries
                // cleanly instead of wedging the task (`blocked` for the action
                // nonce, `Pending` forever for the approval nonce). We never
                // dispatched, and the daemon that won the claim burns its own
                // copies in its own cache, so un-burning here cannot enable a
                // replay (see `ReplayCache::forget`).
                if let (Some(cache), Some(auth)) = (&self.replay_cache, action.authorization()) {
                    let _ = cache.borrow_mut().forget(&auth.nonce);
                }
                // Only an approval-gated task burns a decision nonce, and an
                // approval-gated task reaching the claim has just admitted *its
                // own* decision nonce this pass; the guard keeps a later non-gated
                // stale task from un-burning a prior task's already-executed nonce.
                if allowance.requires_approval {
                    if let Some(gate) = &self.approval_gate {
                        gate.borrow_mut().compensate_lost_claim();
                    }
                }
                return OrchestrationOutcome::StaleClaim {
                    task_id: task.task_id.clone(),
                };
            }
            Err(err) => {
                return OrchestrationOutcome::StoreError {
                    task_id: task.task_id.clone(),
                    reason: format_store_error(&err),
                }
            }
        };

        let dispatched = dispatcher.dispatch(&claimed, &action, &invocation_id, &allowance);
        let (terminal, result) = match dispatched {
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

    /// Reconcile every `executing` task against the set of live invocations on
    /// daemon startup/reconnect, returning one outcome per executing task.
    ///
    /// This is the restart-recovery entry point (architecture §11.3). An
    /// invocation is "live" when it is present in `live_invocations`; the live
    /// scheduler loop populates this set with every invocation it has claimed
    /// during the current run (not only ones still executing), so a task this
    /// daemon already claimed and finalized in an earlier pass is never recovered
    /// off a stale local-store snapshot that still shows it `executing` (issue
    /// #221). For each `executing` task:
    ///
    /// - **owned by this agent, with a live invocation** — left unchanged
    ///   ([`OrchestrationOutcome::NotRunnableState`]); the invocation is still
    ///   owned by this run (in flight or already finalized this run), so nothing
    ///   is changed and nothing is re-spawned.
    /// - **owned by this agent, with no live invocation** — recovered: marked
    ///   `failed` with a recovery result via [`Self::recover_stale_executing`]
    ///   so an orphan left by a *previous* daemon run is resolved safely and
    ///   never double-run.
    /// - **owned by another (remote) agent** — left unchanged and surfaced as a
    ///   stale warning ([`OrchestrationOutcome::StaleRemoteExecuting`]); only the
    ///   owning daemon may resolve it.
    ///
    /// Every recovery decision is logged (non-sensitive: task id, owner, and
    /// decision), and a recovered task's durable `result` records why it was
    /// recovered, so the decision is auditable.
    pub fn recover_executing_tasks<S>(
        &self,
        tasks: &[TaskState],
        live_invocations: &BTreeSet<String>,
        store: &mut S,
    ) -> Vec<OrchestrationOutcome>
    where
        S: TaskStore,
    {
        // With no invocation snapshot, every not-live executing task this agent
        // owns is treated as a stale orphan (the historical behavior).
        self.reconcile_executing_tasks(tasks, live_invocations, &BTreeMap::new(), store)
    }

    /// Restart-recovery entry point that reconciles each `executing` task against
    /// the *actual* invocation state by the unified id (issue #239).
    ///
    /// This refines [`Self::recover_executing_tasks`]: instead of blindly failing
    /// every not-live executing task, it looks up the task's `invocation_id` in
    /// `invocations` (the room's `com.mxagent.invocation.v1` snapshot keyed by id)
    /// and reconciles accordingly. Because the id is unified, a task and its remote
    /// invocation are matched reliably across a daemon restart. For each
    /// `executing` task:
    ///
    /// - **owned by another (remote) agent** — left unchanged
    ///   ([`OrchestrationOutcome::StaleRemoteExecuting`]).
    /// - **owned by this agent, live this run** — left unchanged
    ///   ([`OrchestrationOutcome::NotRunnableState`]); the #230 protection, so a
    ///   task this run already claimed/finalized is never clobbered off a stale
    ///   snapshot.
    /// - **owned by this agent, not live, invocation terminal** — reconciled to the
    ///   invocation's real outcome ([`OrchestrationOutcome::ReconciledInvocation`]),
    ///   so a remote invocation that already `succeeded`/`failed`/`cancelled` is
    ///   surfaced onto the task rather than mislabeled `failed`.
    /// - **owned by this agent, not live, invocation still running** — left
    ///   `executing` ([`OrchestrationOutcome::StillRunningInvocation`]); the remote
    ///   work may still complete and finalize.
    /// - **owned by this agent, not live, no invocation state** — a genuine orphan
    ///   from a previous run, recovered `failed`
    ///   ([`Self::recover_stale_executing`]).
    ///
    /// An already-terminal task is never touched (only `executing` tasks are
    /// scanned and the lifecycle guard rejects reopening), so finalized state is
    /// never clobbered. Every decision is logged (non-sensitive).
    pub fn reconcile_executing_tasks<S>(
        &self,
        tasks: &[TaskState],
        live_invocations: &BTreeSet<String>,
        invocations: &BTreeMap<String, InvocationState>,
        store: &mut S,
    ) -> Vec<OrchestrationOutcome>
    where
        S: TaskStore,
    {
        let mut outcomes = Vec::new();
        for task in tasks.iter().filter(|t| t.state == STATE_EXECUTING) {
            if !self.is_assigned(task) {
                tracing::warn!(
                    task_id = %task.task_id,
                    owner = %task.assigned_to,
                    decision = "stale_remote_executing",
                    "restart recovery left a remote-owned executing task unchanged"
                );
                outcomes.push(OrchestrationOutcome::StaleRemoteExecuting {
                    task_id: task.task_id.clone(),
                    owner: task.assigned_to.clone(),
                });
                continue;
            }
            let live = task
                .invocation_id
                .as_ref()
                .is_some_and(|id| live_invocations.contains(id));
            if live {
                tracing::debug!(
                    task_id = %task.task_id,
                    decision = "executing_still_live",
                    "restart recovery left a live local executing task unchanged"
                );
                outcomes.push(OrchestrationOutcome::NotRunnableState {
                    task_id: task.task_id.clone(),
                    state: task.state.clone(),
                });
                continue;
            }
            // Not live this run: reconcile against the real invocation state by the
            // unified id.
            let invocation = task
                .invocation_id
                .as_ref()
                .and_then(|id| invocations.get(id));
            match invocation {
                Some(inv) if invocation_is_terminal(&inv.state) => {
                    outcomes.push(self.reconcile_terminal_invocation(task, inv, store));
                }
                Some(_) => {
                    tracing::debug!(
                        task_id = %task.task_id,
                        invocation_id = task.invocation_id.as_deref().unwrap_or(""),
                        decision = "invocation_still_running",
                        "restart recovery left an executing task whose remote invocation is still running"
                    );
                    outcomes.push(OrchestrationOutcome::StillRunningInvocation {
                        task_id: task.task_id.clone(),
                    });
                }
                None => {
                    let outcome = self.recover_stale_executing(task, live_invocations, store);
                    if let OrchestrationOutcome::RecoveredStale { task_id } = &outcome {
                        tracing::warn!(
                            task_id = %task_id,
                            invocation_id = task.invocation_id.as_deref().unwrap_or(""),
                            decision = "recovered_stale_invocation",
                            "restart recovery marked an orphaned executing task failed"
                        );
                    }
                    outcomes.push(outcome);
                }
            }
        }
        outcomes
    }

    /// Finalize an `executing` task to the terminal outcome of its already-finished
    /// linked invocation, deriving a non-sensitive result from the invocation.
    fn reconcile_terminal_invocation<S>(
        &self,
        task: &TaskState,
        invocation: &InvocationState,
        store: &mut S,
    ) -> OrchestrationOutcome
    where
        S: TaskStore,
    {
        let state = task_state_for_invocation(&invocation.state).unwrap_or(STATE_FAILED);
        let result = task_result_from_invocation(invocation, &self.agent_id, now_rfc3339());
        match store.finalize(UpdateTaskOptions {
            room: String::new(),
            task_id: task.task_id.clone(),
            state: Some(state.to_string()),
            result: Some(result.into_value()),
            expected_state_rev: Some(task.state_rev),
            ..UpdateTaskOptions::default()
        }) {
            Ok(finalized) => {
                tracing::info!(
                    task_id = %finalized.task_id,
                    invocation_id = %invocation.invocation_id,
                    state = %finalized.state,
                    decision = "reconciled_invocation",
                    "restart recovery reconciled an executing task with its terminal invocation"
                );
                OrchestrationOutcome::ReconciledInvocation {
                    task_id: finalized.task_id,
                    state: finalized.state,
                }
            }
            Err(err) => OrchestrationOutcome::StoreError {
                task_id: task.task_id.clone(),
                reason: format_store_error(&err),
            },
        }
    }

    /// Require a trusted, signed authorization (addressed to this agent) before a
    /// task action may execute.
    ///
    /// Task state is advisory: when trust or replay enforcement is configured, an
    /// action must carry a [`TaskActionAuthorization`] from a locally trusted
    /// signing key, addressed to this agent, with a valid signature. Any failure
    /// blocks the task without dispatching. This step is **idempotent** (no cache
    /// side effects) so it can be re-run safely while a task is held for approval;
    /// the single-use replay/expiry nonce is consumed separately, only once the
    /// action is about to execute (see [`admit_task_action_replay`]). When neither
    /// a trust store nor a replay cache is configured, this check is a no-op (the
    /// deterministic scheduler core used in tests and by callers that supply
    /// authorization elsewhere).
    ///
    /// [`admit_task_action_replay`]: Self::admit_task_action_replay
    fn verify_task_action_authorization<S>(
        &self,
        task: &TaskState,
        action: &TaskAction,
        invocation_id: &str,
        store: &mut S,
    ) -> Result<(), OrchestrationOutcome>
    where
        S: TaskStore,
    {
        if self.trust_store.is_none() && self.replay_cache.is_none() {
            return Ok(());
        }

        let Some(auth) = action.authorization() else {
            return self.block_unauthorized(task, action, invocation_id, "unsigned", store);
        };

        // The authorization must be addressed to this agent.
        if auth.target_agent != self.agent_id {
            return self.block_unauthorized(task, action, invocation_id, "wrong_target", store);
        }

        // Trust + signature verification (local trust store is final authority).
        if let Some(trust) = &self.trust_store {
            if !trust.is_key_trusted(&auth.signature.key_id) {
                return self.block_unauthorized(
                    task,
                    action,
                    invocation_id,
                    "untrusted_key",
                    store,
                );
            }
            let Some(verifying_key) = self.verifying_keys.get(&auth.signature.key_id) else {
                return self.block_unauthorized(
                    task,
                    action,
                    invocation_id,
                    "unresolved_key",
                    store,
                );
            };
            match verify_task_action_signature(verifying_key, &task.task_id, action, auth) {
                Ok(()) => {}
                Err(_) => {
                    return self.block_unauthorized(
                        task,
                        action,
                        invocation_id,
                        "invalid_signature",
                        store,
                    );
                }
            }
        }

        Ok(())
    }

    /// Consume the single-use replay/expiry nonce for an authorized task action,
    /// blocking the task if it is expired or already seen.
    ///
    /// This is the **side-effecting** half of authorization: it records the nonce
    /// so the same signed authorization cannot run twice. It is deliberately
    /// invoked only once the action is fully authorized *and* approved (right
    /// before the claim), so a task held for approval over several scheduler
    /// passes is not falsely rejected as a replay when it resumes — the nonce is
    /// burned only on the pass that actually executes. Signature/trust are checked
    /// separately and idempotently in [`verify_task_action_authorization`]. A no-op
    /// when no replay cache is configured.
    ///
    /// [`verify_task_action_authorization`]: Self::verify_task_action_authorization
    fn admit_task_action_replay<S>(
        &self,
        task: &TaskState,
        action: &TaskAction,
        invocation_id: &str,
        store: &mut S,
    ) -> Result<(), OrchestrationOutcome>
    where
        S: TaskStore,
    {
        let Some(cache) = &self.replay_cache else {
            // Test-only path: the pure-core unit tests deliberately run the
            // orchestrator without a cache. Production never reaches here —
            // `build_scheduler_orchestrator` (the only production constructor)
            // takes a non-`Option` `ReplayCache` and attaches it unconditionally,
            // and the scheduler skips the whole pass when the cache cannot load.
            return Ok(());
        };
        // `verify_task_action_authorization` already rejected an unsigned action
        // whenever a replay cache (or trust store) is configured, so an authorized
        // action reaching here carries an authorization; fail closed otherwise.
        let Some(auth) = action.authorization() else {
            return self.block_unauthorized(task, action, invocation_id, "unsigned", store);
        };
        // Denials are side-effect free in the cache.
        let admit = cache.borrow_mut().admit(&auth.nonce, &auth.expires_at);
        if let Err(err) = admit {
            let reason = match err {
                ReplayError::Expired => "expired",
                ReplayError::Replayed => "replayed",
                ReplayError::MalformedTimestamp => "malformed_expiry",
                // Produced only by `ReplayCache::load`, never by `admit`; mapped
                // here so the match stays exhaustive over the error type.
                ReplayError::Corrupt => "replay_cache_corrupt",
                ReplayError::Io(_) => "replay_cache_unavailable",
            };
            return self.block_unauthorized(task, action, invocation_id, reason, store);
        }
        Ok(())
    }

    fn block_unauthorized<S>(
        &self,
        task: &TaskState,
        action: &TaskAction,
        invocation_id: &str,
        reason: &str,
        store: &mut S,
    ) -> Result<(), OrchestrationOutcome>
    where
        S: TaskStore,
    {
        let result = failure_result(
            &self.agent_id,
            Some(invocation_id),
            Some(action.kind()),
            "unauthorized",
            Some(format!("task action authorization rejected: {reason}")),
        );
        match store.finalize(UpdateTaskOptions {
            room: String::new(),
            task_id: task.task_id.clone(),
            state: Some(STATE_BLOCKED.to_string()),
            result: Some(result),
            expected_state_rev: Some(task.state_rev),
            ..UpdateTaskOptions::default()
        }) {
            Ok(finalized) => Err(OrchestrationOutcome::Denied {
                task_id: finalized.task_id,
                invocation_id: invocation_id.to_string(),
            }),
            Err(err) => Err(OrchestrationOutcome::StoreError {
                task_id: task.task_id.clone(),
                reason: format_store_error(&err),
            }),
        }
    }

    /// Authorize the action against local policy. Returns `Ok(allowance)` when
    /// permitted — carrying the policy-resolved limits and isolation settings
    /// (`requires_approval`, sandbox backend, network decision, filesystem
    /// binds, env allowlist) the claim/dispatch step must enforce — or
    /// `Err(outcome)` when denied (the task is finalized blocked).
    ///
    /// When no policy is configured the default [`Allowance`] is returned
    /// (`requires_approval = false`, `Backend::None`, network denied, no binds),
    /// preserving the prior "no policy ⇒ run with no isolation" behavior.
    fn authorize_task_action<S>(
        &self,
        task: &TaskState,
        action: &TaskAction,
        invocation_id: &str,
        store: &mut S,
    ) -> Result<Allowance, OrchestrationOutcome>
    where
        S: TaskStore,
    {
        let Some(policy) = &self.policy else {
            return Ok(Allowance::default());
        };
        let Some(room_id) = &self.room_id else {
            return self
                .block_policy_denied(
                    task,
                    action,
                    invocation_id,
                    "policy_not_configured_for_room".to_string(),
                    store,
                )
                .map(|_| Allowance::default());
        };
        let outcome = evaluate_task_action(policy, room_id, task, action);
        // Auditing is a side effect that must never block dispatch: a failed
        // write is logged and swallowed (matching `append_audit`), so a flaky or
        // unwritable audit file can never flip an allowed task to a `StoreError`
        // or a denied task to anything other than `policy_denied`.
        self.audit_policy_decision(room_id, task, action, invocation_id, &outcome);
        match outcome {
            Outcome::Allow(allowance) => Ok(allowance),
            Outcome::Deny(reason) => self
                .block_policy_denied(task, action, invocation_id, reason.to_string(), store)
                .map(|_| Allowance::default()),
        }
    }

    /// Consult the approval gate for an action local policy marked
    /// `requires_approval`. `Ok(())` proceeds to claim/dispatch; `Err(outcome)`
    /// holds or blocks the task without spawning.
    fn resolve_approval<S>(
        &self,
        task: &TaskState,
        action: &TaskAction,
        invocation_id: &str,
        store: &mut S,
    ) -> Result<(), OrchestrationOutcome>
    where
        S: TaskStore,
    {
        let Some(gate) = &self.approval_gate else {
            // Fail closed: approval is required but no gate can grant it, so the
            // action must not run.
            tracing::info!(
                task_id = %task.task_id,
                decision = "awaiting_approval",
                "task requires approval but no approval gate is configured; not running"
            );
            return Err(OrchestrationOutcome::AwaitingApproval {
                task_id: task.task_id.clone(),
                request_id: None,
            });
        };
        match gate.borrow_mut().evaluate(task, action) {
            ApprovalDisposition::Approved => Ok(()),
            ApprovalDisposition::Denied(reason) => {
                self.block_approval_denied(task, action, invocation_id, reason, store)
            }
            ApprovalDisposition::Pending(request_id) => {
                tracing::info!(
                    task_id = %task.task_id,
                    request_id = %request_id,
                    decision = "awaiting_approval",
                    "task is held pending an approval decision"
                );
                Err(OrchestrationOutcome::AwaitingApproval {
                    task_id: task.task_id.clone(),
                    request_id: Some(request_id),
                })
            }
            ApprovalDisposition::Expired(request_id) => {
                tracing::info!(
                    task_id = %task.task_id,
                    request_id = %request_id,
                    decision = "approval_expired",
                    "task approval window closed without a decision; blocking"
                );
                self.block_approval_expired(task, action, invocation_id, store)
            }
        }
    }

    /// Finalize a task blocked because its approval window closed before any
    /// decision was made (issue #265). Never spawns.
    fn block_approval_expired<S>(
        &self,
        task: &TaskState,
        action: &TaskAction,
        invocation_id: &str,
        store: &mut S,
    ) -> Result<(), OrchestrationOutcome>
    where
        S: TaskStore,
    {
        let result = failure_result(
            &self.agent_id,
            Some(invocation_id),
            Some(action.kind()),
            "approval_expired",
            Some("approval window expired before a decision was made".to_string()),
        );
        match store.finalize(UpdateTaskOptions {
            room: String::new(),
            task_id: task.task_id.clone(),
            state: Some(STATE_BLOCKED.to_string()),
            result: Some(result),
            expected_state_rev: Some(task.state_rev),
            ..UpdateTaskOptions::default()
        }) {
            Ok(finalized) => Err(OrchestrationOutcome::Denied {
                task_id: finalized.task_id,
                invocation_id: invocation_id.to_string(),
            }),
            Err(err) => Err(OrchestrationOutcome::StoreError {
                task_id: task.task_id.clone(),
                reason: format_store_error(&err),
            }),
        }
    }

    /// Finalize a task blocked because its approval was denied. Never spawns.
    fn block_approval_denied<S>(
        &self,
        task: &TaskState,
        action: &TaskAction,
        invocation_id: &str,
        reason: String,
        store: &mut S,
    ) -> Result<(), OrchestrationOutcome>
    where
        S: TaskStore,
    {
        let result = failure_result(
            &self.agent_id,
            Some(invocation_id),
            Some(action.kind()),
            "approval_denied",
            Some(format!("task action approval denied: {reason}")),
        );
        match store.finalize(UpdateTaskOptions {
            room: String::new(),
            task_id: task.task_id.clone(),
            state: Some(STATE_BLOCKED.to_string()),
            result: Some(result),
            expected_state_rev: Some(task.state_rev),
            ..UpdateTaskOptions::default()
        }) {
            Ok(finalized) => Err(OrchestrationOutcome::Denied {
                task_id: finalized.task_id,
                invocation_id: invocation_id.to_string(),
            }),
            Err(err) => Err(OrchestrationOutcome::StoreError {
                task_id: task.task_id.clone(),
                reason: format_store_error(&err),
            }),
        }
    }

    fn block_policy_denied<S>(
        &self,
        task: &TaskState,
        action: &TaskAction,
        invocation_id: &str,
        reason: String,
        store: &mut S,
    ) -> Result<(), OrchestrationOutcome>
    where
        S: TaskStore,
    {
        let result = failure_result(
            &self.agent_id,
            Some(invocation_id),
            Some(action.kind()),
            "policy_denied",
            Some(reason),
        );
        match store.finalize(UpdateTaskOptions {
            room: String::new(),
            task_id: task.task_id.clone(),
            state: Some(STATE_BLOCKED.to_string()),
            result: Some(result),
            expected_state_rev: Some(task.state_rev),
            ..UpdateTaskOptions::default()
        }) {
            Ok(finalized) => Err(OrchestrationOutcome::Denied {
                task_id: finalized.task_id,
                invocation_id: invocation_id.to_string(),
            }),
            Err(err) => Err(OrchestrationOutcome::StoreError {
                task_id: task.task_id.clone(),
                reason: format_store_error(&err),
            }),
        }
    }

    /// Record a task-action policy decision (allow or deny) to the audit log.
    ///
    /// No-ops when no audit log is attached. A failed append is logged and
    /// swallowed — auditing is a side effect that must never block or fail a
    /// dispatch decision (matching [`crate::audit::append_audit`]).
    fn audit_policy_decision(
        &self,
        room_id: &str,
        task: &TaskState,
        action: &TaskAction,
        invocation_id: &str,
        outcome: &Outcome,
    ) {
        let Some(log) = &self.audit_log else {
            return;
        };
        let record = match action {
            TaskAction::Tool { tool, .. } => AuditRecord::for_call(
                room_id,
                &task.created_by,
                &self.agent_id,
                Some(invocation_id),
                tool,
                outcome,
            ),
            TaskAction::Exec { command, .. } => AuditRecord::for_exec(
                room_id,
                &task.created_by,
                &self.agent_id,
                Some(invocation_id),
                command,
                outcome,
            ),
        };
        if let Err(e) = log.append(&record) {
            tracing::warn!(
                error = %e,
                invocation_id = %invocation_id,
                task_id = %task.task_id,
                "failed to append task policy audit record"
            );
        }
    }

    fn is_assigned(&self, task: &TaskState) -> bool {
        task.assigned_to == self.agent_id
    }
}

/// Build the canonical bytes a task-action authorization signs.
///
/// The signature binds the approval to a specific task id and to the action
/// payload with its embedded authorization removed, plus the authorization
/// metadata with its own signature removed. Both sides compute the same
/// canonical JSON so the `signature` field is excluded consistently.
fn task_action_signing_value(
    task_id: &str,
    action: &TaskAction,
    auth: &TaskActionAuthorization,
) -> Value {
    let action_value = serde_json::to_value(action.without_authorization())
        .expect("task action serializes to JSON");
    let auth_meta = serde_json::json!({
        "requesting_agent": auth.requesting_agent,
        "target_agent": auth.target_agent,
        "created_at": auth.created_at,
        "expires_at": auth.expires_at,
        "nonce": auth.nonce,
    });
    serde_json::json!({
        "task_id": task_id,
        "action": action_value,
        "authorization": auth_meta,
    })
}

/// Verify a task-action authorization signature against `verifying_key`.
pub(crate) fn verify_task_action_signature(
    verifying_key: &VerifyingKey,
    task_id: &str,
    action: &TaskAction,
    auth: &TaskActionAuthorization,
) -> Result<(), SignatureError> {
    let value = task_action_signing_value(task_id, action, auth);
    let bytes = canonical_json::to_canonical_bytes(&value).map_err(SignatureError::NonCanonical)?;
    signing::verify_signature(verifying_key, &auth.signature, &bytes)
}

/// Build a detached task-action signature with `signing_key`.
///
/// This is the producer side of [`verify_task_action_signature`]: it signs the
/// canonical bytes binding `task_id`, the action (without authorization), and
/// the authorization metadata (without signature).
#[allow(clippy::too_many_arguments)]
pub fn sign_task_action(
    signing_key: &ed25519_dalek::SigningKey,
    key_id: impl Into<String>,
    task_id: &str,
    action: &TaskAction,
    requesting_agent: impl Into<String>,
    target_agent: impl Into<String>,
    created_at: impl Into<String>,
    expires_at: impl Into<String>,
    nonce: impl Into<String>,
) -> Result<TaskActionAuthorization, SignatureError> {
    let mut auth = TaskActionAuthorization {
        requesting_agent: requesting_agent.into(),
        target_agent: target_agent.into(),
        created_at: created_at.into(),
        expires_at: expires_at.into(),
        nonce: nonce.into(),
        signature: Signature {
            alg: signing::ALG_ED25519.to_string(),
            key_id: key_id.into(),
            sig: String::new(),
        },
        extra: Default::default(),
    };
    let value = task_action_signing_value(task_id, action, &auth);
    let key_id = auth.signature.key_id.clone();
    let signature = signing::sign(signing_key, key_id, &value)?;
    auth.signature = signature;
    Ok(auth)
}

/// Build the `com.mxagent.approval.request.v1` content for a task action that
/// requires approval (architecture §12).
///
/// The request is non-sensitive: it references the task and action kind, not raw
/// command output. Its `request_id` is derived deterministically from the task
/// id, so a redelivered/recomputed request is idempotent in the approval queue.
pub fn task_approval_request(
    task: &TaskState,
    action: &TaskAction,
    target_agent: &str,
    expires_at: &str,
) -> ApprovalRequest {
    ApprovalRequest {
        request_id: format!("approval:{}", task.task_id),
        invocation_id: String::new(),
        requester: task.created_by.clone(),
        target: target_agent.to_string(),
        summary: format!("Run {} action for task {}", action.kind(), task.task_id),
        risk: "medium".to_string(),
        expires_at: expires_at.to_string(),
        extra: Default::default(),
    }
}

/// A [`TaskApprovalGate`] backed by the local [`ApprovalQueue`].
///
/// On the first undecided encounter it enqueues a [`PendingApproval`] (so the
/// operator can inspect it via `mx-agent approval list`) and returns
/// [`ApprovalDisposition::Pending`]. A decision is resolved through the supplied
/// closure, which the daemon wires to recorded approval decisions: `Some(true)`
/// approves, `Some(false)` denies, and `None` keeps the action pending.
///
/// The queue is held behind a shared [`Rc<RefCell<ApprovalQueue>>`] so the caller
/// can observe the gate's enqueues/removes after a run — boxed as a trait object
/// the gate is otherwise unreachable — and persist them so pending approvals
/// survive a restart and are resolvable by `mx-agent approval approve/deny`. The
/// gate is single-threaded by construction (built and used on the scheduler
/// thread), so the non-`Send` `Rc` is sound here.
pub struct QueueApprovalGate<R> {
    room_id: String,
    target_agent: String,
    expires_at: String,
    now_unix: i64,
    queue: Rc<RefCell<ApprovalQueue>>,
    replay_cache: Option<Rc<RefCell<ReplayCache>>>,
    /// Nonce of the decision burned by the most recent successful
    /// [`admit_decision_nonce`](Self::admit_decision_nonce), recorded so a lost
    /// optimistic-claim race can un-burn it (see
    /// [`compensate_lost_claim`](TaskApprovalGate::compensate_lost_claim)).
    last_admitted_decision_nonce: Option<String>,
    resolve_decision: R,
}

impl<R> QueueApprovalGate<R>
where
    R: FnMut(&str) -> Option<ApprovalDecision>,
{
    /// Build a queue-backed approval gate for `room_id`/`target_agent`.
    ///
    /// `expires_at` is stamped onto emitted approval requests; `resolve_decision`
    /// maps a request id to a **verified** [`ApprovalDecision`] (sender- and
    /// signature-checked by the scheduler, see
    /// [`read_verified_approval_decisions`](crate::approval::read_verified_approval_decisions))
    /// or `None` when still undecided. `queue` is the shared queue the gate
    /// enqueues pending approvals into and removes decided ones from; pass it
    /// pre-seeded with any persisted approvals so a restart does not re-emit them,
    /// and read it back via [`queue`](Self::queue) after a run to persist changes.
    ///
    /// The gate is replay-cache-less by default (decisions still release on a
    /// valid signature); attach one with [`with_replay_cache`](Self::with_replay_cache)
    /// to burn the decision's single-use nonce on the releasing pass.
    pub fn new(
        room_id: impl Into<String>,
        target_agent: impl Into<String>,
        expires_at: impl Into<String>,
        queue: Rc<RefCell<ApprovalQueue>>,
        resolve_decision: R,
    ) -> Self {
        Self {
            room_id: room_id.into(),
            target_agent: target_agent.into(),
            expires_at: expires_at.into(),
            now_unix: 0,
            queue,
            replay_cache: None,
            last_admitted_decision_nonce: None,
            resolve_decision,
        }
    }

    /// Set the gate's "now" (Unix seconds) used to compare a queued request's
    /// stamped `expires_at` against the present (issue #265).
    ///
    /// Injectable so the expiry transition is unit-testable without reading the
    /// wall clock. The scheduler captures one value per pass (mirroring the
    /// per-pass `expires_at` horizon) so every gate in a pass agrees on "now".
    /// Defaults to `0` (the Unix epoch) when unset, which never spuriously
    /// expires a request stamped with a real future deadline.
    pub fn with_now_unix(mut self, now_unix: i64) -> Self {
        self.now_unix = now_unix;
        self
    }

    /// Attach the shared replay cache used to consume an approving decision's
    /// single-use nonce on the releasing pass (issue #264).
    ///
    /// Pass the orchestrator's own handle (via
    /// [`TaskOrchestrator::replay_cache_handle`]) so decision and task-action
    /// nonces persist to one file. A held decision (no approval yet) never reaches
    /// the cache, so a legitimately-held task is not falsely replay-blocked; once
    /// an approving decision burns its nonce, a stale duplicate is rejected and
    /// the gate falls back to `Pending` rather than re-releasing.
    pub fn with_replay_cache(mut self, replay_cache: Option<Rc<RefCell<ReplayCache>>>) -> Self {
        self.replay_cache = replay_cache;
        self
    }

    /// A handle to the gate's shared approval queue (for inspection or
    /// persistence after a run).
    pub fn queue(&self) -> Rc<RefCell<ApprovalQueue>> {
        Rc::clone(&self.queue)
    }
}

impl<R> TaskApprovalGate for QueueApprovalGate<R>
where
    R: FnMut(&str) -> Option<ApprovalDecision>,
{
    fn evaluate(&mut self, task: &TaskState, action: &TaskAction) -> ApprovalDisposition {
        let mut request = task_approval_request(task, action, &self.target_agent, &self.expires_at);
        let request_id = request.request_id.clone();
        match (self.resolve_decision)(&request_id) {
            Some(decision) if decision_permits_spawn(&decision) => {
                // Releasing pass: consume the decision's single-use nonce so a
                // stale duplicate in the scan window cannot re-release the task.
                // A replayed/expired/absent nonce fails closed to `Pending`.
                if !self.admit_decision_nonce(&decision) {
                    self.queue.borrow_mut().enqueue(PendingApproval {
                        room_id: self.room_id.clone(),
                        request,
                    });
                    return ApprovalDisposition::Pending(request_id);
                }
                self.queue.borrow_mut().remove(&request_id);
                ApprovalDisposition::Approved
            }
            Some(_) => {
                self.queue.borrow_mut().remove(&request_id);
                ApprovalDisposition::Denied("approval denied by operator".to_string())
            }
            None => {
                // No decision yet. The human-approval deadline is the stamp
                // carried on the *already-queued* entry from the first pass that
                // raised this request — NOT the freshly re-stamped per-pass
                // `self.expires_at` (which would slide forward forever). Fall
                // back to the rebuilt request's stamp only on the first
                // encounter, before anything is queued.
                let deadline = self
                    .queue
                    .borrow()
                    .get(&request_id)
                    .map(|pending| pending.request.expires_at.clone())
                    .unwrap_or_else(|| request.expires_at.clone());
                if approval_request_expired(&deadline, self.now_unix) {
                    // Window closed without a decision: finalize (fail-closed
                    // liveness) by dropping the queue entry and blocking the task
                    // instead of re-enqueuing it forever (issue #265).
                    self.queue.borrow_mut().remove(&request_id);
                    return ApprovalDisposition::Expired(request_id);
                }
                // Anchor the deadline to the first time the request was queued:
                // `enqueue` replaces any existing entry, so re-stamping with the
                // fresh per-pass `self.expires_at` would slide the window forward
                // every pass and never expire. Carry the persisted stamp back in.
                request.expires_at = deadline;
                self.queue.borrow_mut().enqueue(PendingApproval {
                    room_id: self.room_id.clone(),
                    request,
                });
                ApprovalDisposition::Pending(request_id)
            }
        }
    }

    fn compensate_lost_claim(&mut self) {
        if let (Some(cache), Some(nonce)) =
            (&self.replay_cache, self.last_admitted_decision_nonce.take())
        {
            // The releasing pass lost the optimistic claim, so the approved
            // action never dispatched. Un-burn the decision's single-use nonce
            // so the next pass can re-release the task with the same operator
            // approval instead of hanging it `Pending` forever (the same
            // verified decision is still in the scan window). Safe: nothing
            // executed, so this cannot enable a replay (see `ReplayCache::forget`).
            let _ = cache.borrow_mut().forget(&nonce);
        }
    }
}

impl<R> QueueApprovalGate<R> {
    /// Admit the approving decision's nonce into the shared replay cache.
    ///
    /// Returns `true` when the decision may release the task: either no replay
    /// cache is attached (signature alone gates the release) or the nonce is
    /// fresh and within its `expires_at`. Returns `false` — fail-closed — when a
    /// cache is attached but the decision lacks replay material or its nonce is
    /// expired/replayed.
    ///
    /// The cache-less branch is **test-only**: production attaches the
    /// orchestrator's shared cache via
    /// [`with_replay_cache`](Self::with_replay_cache), wired by
    /// `build_scheduler_orchestrator` (which requires a cache). On a successful
    /// admit the burned nonce is recorded so a lost optimistic-claim race can
    /// un-burn it (see
    /// [`compensate_lost_claim`](TaskApprovalGate::compensate_lost_claim)).
    fn admit_decision_nonce(&mut self, decision: &ApprovalDecision) -> bool {
        let Some(cache) = &self.replay_cache else {
            return true;
        };
        let (Some(nonce), Some(expires_at)) =
            (decision.nonce.as_deref(), decision.expires_at.as_deref())
        else {
            return false;
        };
        if cache.borrow_mut().admit(nonce, expires_at).is_ok() {
            self.last_admitted_decision_nonce = Some(nonce.to_string());
            true
        } else {
            false
        }
    }
}

fn evaluate_task_action(
    policy: &Policy,
    room_id: &str,
    task: &TaskState,
    action: &TaskAction,
) -> Outcome {
    match action {
        TaskAction::Tool { tool, .. } => policy.evaluate_call(&CallContext {
            room_id,
            requesting_agent: &task.created_by,
            tool,
        }),
        TaskAction::Exec { command, cwd, .. } => policy.evaluate_exec(&ExecContext {
            room_id,
            requesting_agent: &task.created_by,
            command,
            cwd,
        }),
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
            created_by: "@planner:server".to_string(),
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
        finalized_state: Option<String>,
        claimed_assigned_to: Option<String>,
        claimed_invocation_id: Option<String>,
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
            self.claimed_assigned_to = options.assigned_to.clone();
            self.claimed_invocation_id = options.invocation_id.clone();
            let assigned_to = options.assigned_to.clone().unwrap_or_default();
            Ok(TaskState {
                task_id: options.task_id,
                title: String::new(),
                description: String::new(),
                state: options.state.unwrap(),
                assigned_to,
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
            self.finalized_state = options.state.clone();
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
            _allowance: &Allowance,
        ) -> Result<TaskExecutionResult, TaskDispatchError> {
            self.0.clone()
        }
    }

    struct PanicDispatcher;

    impl TaskDispatcher for PanicDispatcher {
        fn dispatch(
            &mut self,
            _task: &TaskState,
            _action: &TaskAction,
            _invocation_id: &str,
            _allowance: &Allowance,
        ) -> Result<TaskExecutionResult, TaskDispatchError> {
            panic!("policy-denied task must not dispatch")
        }
    }

    fn policy() -> Policy {
        Policy::parse(
            r#"
[rooms."!room:server"]
trusted = true
raw_exec_default = "deny"

[rooms."!room:server".agents."@planner:server"]
allow_exec = true
allow_tools = ["run_tests"]
allow_commands = ["cargo"]
allow_cwd = ["/repo"]
"#,
        )
        .expect("test policy parses")
    }

    fn audit_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "mx-agent-task-policy-{name}-{}-{}.log",
            std::process::id(),
            now_rfc3339().replace([':', '-'], "")
        ))
    }

    /// A policy that allows `run_tests` but requires approval before running.
    fn policy_requires_approval() -> Policy {
        Policy::parse(
            r#"
[rooms."!room:server"]
trusted = true

[rooms."!room:server".agents."@planner:server"]
allow_tools = ["run_tests"]
requires_approval = true
"#,
        )
        .expect("approval policy parses")
    }

    /// A gate returning a fixed disposition (for orchestrator integration).
    struct FixedGate(ApprovalDisposition);
    impl TaskApprovalGate for FixedGate {
        fn evaluate(&mut self, _task: &TaskState, _action: &TaskAction) -> ApprovalDisposition {
            self.0.clone()
        }
    }

    fn approval_tool_task() -> TaskState {
        with_action(
            task("task-a", STATE_PENDING, "agent-a"),
            json!({"type":"tool", "tool":"run_tests", "args":{}}),
        )
    }

    #[test]
    fn approval_required_task_does_not_execute_while_pending() {
        let t = approval_tool_task();
        let mut store = MemoryStore::default();
        let mut dispatcher = PanicDispatcher;
        let outcome = TaskOrchestrator::new("agent-a")
            .with_room_id("!room:server")
            .with_policy(policy_requires_approval())
            .with_approval_gate(Box::new(FixedGate(ApprovalDisposition::Pending(
                "approval:task-a".to_string(),
            ))))
            .process_one(&t, std::slice::from_ref(&t), &mut store, &mut dispatcher);
        assert!(matches!(
            outcome,
            OrchestrationOutcome::AwaitingApproval { task_id, request_id }
                if task_id == "task-a" && request_id.as_deref() == Some("approval:task-a")
        ));
        // The task was neither claimed nor finalized: it stays re-schedulable.
        assert!(store.finalized_state.is_none());
    }

    #[test]
    fn approval_required_task_fails_closed_without_gate() {
        let t = approval_tool_task();
        let mut store = MemoryStore::default();
        let mut dispatcher = PanicDispatcher;
        let outcome = TaskOrchestrator::new("agent-a")
            .with_room_id("!room:server")
            .with_policy(policy_requires_approval())
            .process_one(&t, std::slice::from_ref(&t), &mut store, &mut dispatcher);
        assert!(matches!(
            outcome,
            OrchestrationOutcome::AwaitingApproval {
                request_id: None,
                ..
            }
        ));
        assert!(store.finalized_state.is_none());
    }

    #[test]
    fn denied_approval_blocks_task_without_spawning() {
        let t = approval_tool_task();
        let mut store = MemoryStore::default();
        let mut dispatcher = PanicDispatcher;
        let outcome = TaskOrchestrator::new("agent-a")
            .with_room_id("!room:server")
            .with_policy(policy_requires_approval())
            .with_approval_gate(Box::new(FixedGate(ApprovalDisposition::Denied(
                "operator said no".to_string(),
            ))))
            .process_one(&t, std::slice::from_ref(&t), &mut store, &mut dispatcher);
        assert!(matches!(outcome, OrchestrationOutcome::Denied { .. }));
        assert_eq!(store.finalized_state.as_deref(), Some(STATE_BLOCKED));
        let result = store.finalized_result.as_ref().expect("blocked result");
        assert_eq!(
            result.get("reason").and_then(Value::as_str),
            Some("approval_denied")
        );
    }

    #[test]
    fn expired_approval_blocks_task_with_reason() {
        // Issue #265: an approval whose window closed without a decision must be
        // finalized `blocked` with reason `approval_expired` — not held forever.
        let t = approval_tool_task();
        let mut store = MemoryStore::default();
        let mut dispatcher = PanicDispatcher;
        let outcome = TaskOrchestrator::new("agent-a")
            .with_room_id("!room:server")
            .with_policy(policy_requires_approval())
            .with_approval_gate(Box::new(FixedGate(ApprovalDisposition::Expired(
                "approval:task-a".to_string(),
            ))))
            .process_one(&t, std::slice::from_ref(&t), &mut store, &mut dispatcher);
        // Terminal, not held: the task is finalized blocked rather than left
        // AwaitingApproval (which is what would happen if expiry were ignored).
        assert!(
            matches!(outcome, OrchestrationOutcome::Denied { .. }),
            "expired approval must reach a terminal outcome, got {outcome:?}"
        );
        assert!(
            !matches!(outcome, OrchestrationOutcome::AwaitingApproval { .. }),
            "an expired approval must not be held indefinitely"
        );
        assert_eq!(store.finalized_state.as_deref(), Some(STATE_BLOCKED));
        let result = store.finalized_result.as_ref().expect("blocked result");
        assert_eq!(
            result.get("reason").and_then(Value::as_str),
            Some("approval_expired")
        );
    }

    #[test]
    fn approved_task_runs_through_dispatch() {
        let t = approval_tool_task();
        let mut store = MemoryStore::default();
        let mut dispatcher = Dispatcher(Ok(TaskExecutionResult {
            exit_code: Some(0),
            summary: "tests passed".to_string(),
            artifact_mxc: None,
        }));
        let outcome = TaskOrchestrator::new("agent-a")
            .with_room_id("!room:server")
            .with_policy(policy_requires_approval())
            .with_approval_gate(Box::new(FixedGate(ApprovalDisposition::Approved)))
            .process_one(&t, std::slice::from_ref(&t), &mut store, &mut dispatcher);
        assert!(matches!(
            outcome,
            OrchestrationOutcome::Completed { state, .. } if state == STATE_SUCCEEDED
        ));
    }

    #[test]
    fn queue_gate_enqueues_inspectable_pending_then_resolves() {
        use std::cell::Cell;
        // Decision source: pending first, then approved.
        let approved = Rc::new(Cell::new(false));
        let flag = approved.clone();
        let shared_queue = Rc::new(RefCell::new(ApprovalQueue::default()));
        let gate = QueueApprovalGate::new(
            "!room:server",
            "agent-a",
            "2026-06-05T00:00:00Z",
            Rc::clone(&shared_queue),
            move |request_id: &str| {
                flag.get().then(|| ApprovalDecision {
                    request_id: request_id.to_string(),
                    decision: "approved".to_string(),
                    approved_by: "@operator:server".to_string(),
                    created_at: "2026-06-05T00:00:00Z".to_string(),
                    nonce: Some("nonce-queue-gate".to_string()),
                    expires_at: Some("2026-06-05T01:00:00Z".to_string()),
                    signature: None,
                    extra: Default::default(),
                })
            },
        );
        let gate = RefCell::new(gate);
        let t = approval_tool_task();
        let action = action_from_task(&t).unwrap();

        // First evaluation: undecided -> Pending, and the request is queued and
        // inspectable (as `mx-agent approval list` would read it).
        let first = gate.borrow_mut().evaluate(&t, &action);
        assert_eq!(
            first,
            ApprovalDisposition::Pending("approval:task-a".to_string())
        );
        // The shared queue handle observes the gate's enqueue (this is what the
        // live loop persists so `mx-agent approval approve` can resolve it).
        let queued = gate
            .borrow()
            .queue()
            .borrow()
            .get("approval:task-a")
            .expect("pending approval is inspectable")
            .clone();
        assert_eq!(queued.room_id, "!room:server");
        assert_eq!(queued.request.target, "agent-a");
        assert!(queued.request.summary.contains("task-a"));

        // After the operator approves, the gate resolves to Approved and removes
        // the request from the shared queue.
        approved.set(true);
        assert_eq!(
            gate.borrow_mut().evaluate(&t, &action),
            ApprovalDisposition::Approved
        );
        assert!(
            shared_queue.borrow().get("approval:task-a").is_none(),
            "an approved request is removed from the queue"
        );
    }

    /// Seed a shared queue with a pending approval stamped `expires_at`.
    fn seed_pending(queue: &Rc<RefCell<ApprovalQueue>>, expires_at: &str) {
        let t = approval_tool_task();
        let action = action_from_task(&t).unwrap();
        let request = task_approval_request(&t, &action, "agent-a", expires_at);
        queue.borrow_mut().enqueue(PendingApproval {
            room_id: "!room:server".to_string(),
            request,
        });
    }

    /// A gate whose decision source always returns `None` (undecided).
    fn undecided_gate(
        queue: Rc<RefCell<ApprovalQueue>>,
        self_expires_at: &str,
        now_unix: i64,
    ) -> QueueApprovalGate<impl FnMut(&str) -> Option<ApprovalDecision>> {
        QueueApprovalGate::new(
            "!room:server",
            "agent-a",
            self_expires_at.to_string(),
            queue,
            |_request_id: &str| None,
        )
        .with_now_unix(now_unix)
    }

    #[test]
    fn queue_gate_expires_held_request_past_deadline() {
        // Issue #265: a queued request whose stamped `expires_at` is at/before
        // `now_unix` and that has no decision must transition to `Expired` and be
        // removed from the queue, not re-enqueued forever.
        let queue = Rc::new(RefCell::new(ApprovalQueue::default()));
        seed_pending(&queue, "2020-01-01T00:00:00Z"); // 1_577_836_800
        let mut gate = undecided_gate(Rc::clone(&queue), "2099-01-01T00:00:00Z", 1_577_836_801);
        let t = approval_tool_task();
        let action = action_from_task(&t).unwrap();

        let disposition = gate.evaluate(&t, &action);
        assert_eq!(
            disposition,
            ApprovalDisposition::Expired("approval:task-a".to_string())
        );
        assert!(
            queue.borrow().get("approval:task-a").is_none(),
            "an expired request is removed from the queue"
        );
    }

    #[test]
    fn queue_gate_keeps_valid_request_pending() {
        // A not-yet-expired held request stays `Pending` and remains queued
        // (no regression to the approve/deny path).
        let queue = Rc::new(RefCell::new(ApprovalQueue::default()));
        let mut gate = undecided_gate(Rc::clone(&queue), "2099-01-01T00:00:00Z", 1_577_836_801);
        let t = approval_tool_task();
        let action = action_from_task(&t).unwrap();

        let disposition = gate.evaluate(&t, &action);
        assert_eq!(
            disposition,
            ApprovalDisposition::Pending("approval:task-a".to_string())
        );
        assert!(
            queue.borrow().get("approval:task-a").is_some(),
            "a valid pending request stays queued and resolvable"
        );
    }

    #[test]
    fn queue_gate_approved_decision_wins_over_expiry() {
        // A verified `approved` decision releases the task even when the stamp is
        // in the past: decision precedence is preserved and the entry is removed.
        let queue = Rc::new(RefCell::new(ApprovalQueue::default()));
        seed_pending(&queue, "2020-01-01T00:00:00Z");
        let gate = QueueApprovalGate::new(
            "!room:server",
            "agent-a",
            "2099-01-01T00:00:00Z".to_string(),
            Rc::clone(&queue),
            |request_id: &str| {
                Some(ApprovalDecision {
                    request_id: request_id.to_string(),
                    decision: "approved".to_string(),
                    approved_by: "@operator:server".to_string(),
                    created_at: "2020-01-01T00:00:00Z".to_string(),
                    nonce: None,
                    expires_at: None,
                    signature: None,
                    extra: Default::default(),
                })
            },
        )
        .with_now_unix(1_577_836_801);
        let mut gate = gate;
        let t = approval_tool_task();
        let action = action_from_task(&t).unwrap();

        assert_eq!(gate.evaluate(&t, &action), ApprovalDisposition::Approved);
        assert!(
            queue.borrow().get("approval:task-a").is_none(),
            "an approved request is removed even past the deadline"
        );
    }

    #[test]
    fn queue_gate_deadline_anchored_to_persisted_stamp() {
        // The deadline is the *persisted* queued stamp, not the freshly
        // re-stamped per-pass `self.expires_at`. A gate with a far-future
        // `self.expires_at` must still expire a request whose queued stamp is
        // past — otherwise the window would slide forward every pass forever.
        let queue = Rc::new(RefCell::new(ApprovalQueue::default()));
        seed_pending(&queue, "2020-01-01T00:00:00Z");
        let mut gate = undecided_gate(Rc::clone(&queue), "2099-01-01T00:00:00Z", 1_577_836_801);
        let t = approval_tool_task();
        let action = action_from_task(&t).unwrap();

        assert_eq!(
            gate.evaluate(&t, &action),
            ApprovalDisposition::Expired("approval:task-a".to_string()),
            "deadline must be anchored to the persisted stamp, not self.expires_at"
        );
    }

    #[test]
    fn queue_gate_does_not_slide_persisted_deadline_across_passes() {
        // Re-enqueuing a still-valid request must preserve the original stamp
        // rather than overwriting it with the fresher per-pass `self.expires_at`.
        let queue = Rc::new(RefCell::new(ApprovalQueue::default()));
        seed_pending(&queue, "2099-01-01T00:00:00Z");
        let mut gate = undecided_gate(Rc::clone(&queue), "2100-01-01T00:00:00Z", 1_577_836_801);
        let t = approval_tool_task();
        let action = action_from_task(&t).unwrap();

        assert_eq!(
            gate.evaluate(&t, &action),
            ApprovalDisposition::Pending("approval:task-a".to_string())
        );
        // The persisted stamp is unchanged — the fresh self.expires_at did not
        // overwrite (slide) it.
        assert_eq!(
            queue
                .borrow()
                .get("approval:task-a")
                .expect("still queued")
                .request
                .expires_at,
            "2099-01-01T00:00:00Z"
        );
    }

    #[test]
    fn queue_gate_with_replay_cache_rejects_replayed_nonce() {
        // Security regression #264: a stale `approved` event still present in
        // the APPROVAL_DECISIONS_SCAN_LIMIT window must not re-release the held
        // task on a subsequent pass once the nonce has been burned.
        let expires_at = future_rfc3339();
        let shared_queue = Rc::new(RefCell::new(ApprovalQueue::default()));
        let (cache, dir) = replay_cache("gate-replay");
        let cache_rc = Rc::new(RefCell::new(cache));

        let et = expires_at.clone();
        let gate = QueueApprovalGate::new(
            "!room:server",
            "agent-a",
            "2099-01-01T00:00:00Z",
            Rc::clone(&shared_queue),
            move |request_id: &str| {
                Some(ApprovalDecision {
                    request_id: request_id.to_string(),
                    decision: "approved".to_string(),
                    approved_by: "@daemon:server".to_string(),
                    created_at: "2026-06-10T12:00:00Z".to_string(),
                    nonce: Some("nonce-gate-replay-test".to_string()),
                    expires_at: Some(et.clone()),
                    signature: None,
                    extra: Default::default(),
                })
            },
        )
        .with_replay_cache(Some(Rc::clone(&cache_rc)));
        let gate = RefCell::new(gate);
        let t = approval_tool_task();
        let action = action_from_task(&t).unwrap();

        // First pass: nonce is fresh — the decision is admitted and the task released.
        assert_eq!(
            gate.borrow_mut().evaluate(&t, &action),
            ApprovalDisposition::Approved,
            "first pass with fresh nonce must release the task"
        );

        // Second pass: same nonce is now replayed — gate must fail closed to Pending.
        let second = gate.borrow_mut().evaluate(&t, &action);
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(
            second,
            ApprovalDisposition::Pending("approval:task-a".to_string()),
            "a replayed decision nonce must not re-release the held task"
        );
    }

    #[test]
    fn queue_gate_with_replay_cache_rejects_decision_without_replay_material() {
        // An approving decision that lacks both nonce and expires_at cannot
        // consume a replay-cache slot; the gate must fail closed to Pending.
        let shared_queue = Rc::new(RefCell::new(ApprovalQueue::default()));
        let (cache, dir) = replay_cache("gate-no-nonce");
        let cache_rc = Rc::new(RefCell::new(cache));

        let gate = QueueApprovalGate::new(
            "!room:server",
            "agent-a",
            "2099-01-01T00:00:00Z",
            Rc::clone(&shared_queue),
            |request_id: &str| {
                Some(ApprovalDecision {
                    request_id: request_id.to_string(),
                    decision: "approved".to_string(),
                    approved_by: "@daemon:server".to_string(),
                    created_at: "2026-06-10T12:00:00Z".to_string(),
                    nonce: None,
                    expires_at: None,
                    signature: None,
                    extra: Default::default(),
                })
            },
        )
        .with_replay_cache(Some(Rc::clone(&cache_rc)));
        let gate = RefCell::new(gate);
        let t = approval_tool_task();
        let action = action_from_task(&t).unwrap();

        let result = gate.borrow_mut().evaluate(&t, &action);
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(
            result,
            ApprovalDisposition::Pending("approval:task-a".to_string()),
            "an approving decision with no replay material must not release the task"
        );
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
                args: json!({"package":"cli"}),
                authorization: None,
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
            authorization: None,
        });
        assert_eq!(
            action_from_task(&t).unwrap(),
            TaskAction::Tool {
                tool: "typed".to_string(),
                args: json!({ "package": "cli" }),
                authorization: None,
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
    fn policy_denies_malicious_tool_before_claim_and_audits() {
        let t = with_action(
            task("task-a", STATE_PENDING, "agent-a"),
            json!({"type":"tool", "tool":"delete_everything", "args":{}}),
        );
        let audit_path = audit_path("tool-deny");
        let audit_log = AuditLog::new(audit_path.clone());
        let mut store = MemoryStore::default();
        let mut dispatcher = PanicDispatcher;
        let outcome = TaskOrchestrator::new("agent-a")
            .with_room_id("!room:server")
            .with_policy(policy())
            .with_audit_log(audit_log)
            .process_one(&t, std::slice::from_ref(&t), &mut store, &mut dispatcher);

        assert!(matches!(
            outcome,
            OrchestrationOutcome::Denied { task_id, .. } if task_id == "task-a"
        ));
        // No claim happened; only the denial update advanced the observed rev.
        assert_eq!(store.current_rev, 2);
        assert_eq!(store.finalized_state.as_deref(), Some(STATE_BLOCKED));
        let result = finalized_result(&store);
        assert_eq!(result.get("status").and_then(Value::as_str), Some("failed"));
        assert_eq!(
            result.get("reason").and_then(Value::as_str),
            Some("policy_denied")
        );
        assert!(result
            .get("summary")
            .and_then(Value::as_str)
            .is_some_and(|s| s.contains("not allowlisted")));

        let audit = std::fs::read_to_string(&audit_path).expect("audit log written");
        let _ = std::fs::remove_file(&audit_path);
        assert!(audit.contains("\"decision\":\"denied\""), "{audit}");
        assert!(audit.contains("delete_everything"), "{audit}");
        assert!(
            audit.contains("ToolNotAllowed") || audit.contains("tool"),
            "{audit}"
        );
    }

    #[test]
    fn policy_allows_known_task_action_and_audits() {
        // Mirror of policy_denies_malicious_tool_before_claim_and_audits for the
        // allow path: a permitted tool action must produce an audit record with
        // "decision":"allowed" (issue #266: production auditing was a no-op
        // before the fix because the orchestrator had no audit log attached).
        let t = with_action(
            task("task-a", STATE_PENDING, "agent-a"),
            json!({"type":"tool", "tool":"run_tests", "args":{}}),
        );
        let audit_path = audit_path("tool-allow");
        let audit_log = AuditLog::new(audit_path.clone());
        let mut store = MemoryStore::default();
        let mut dispatcher = Dispatcher(Ok(TaskExecutionResult {
            exit_code: Some(0),
            summary: "tests passed".to_string(),
            artifact_mxc: None,
        }));
        let outcome = TaskOrchestrator::new("agent-a")
            .with_room_id("!room:server")
            .with_policy(policy())
            .with_audit_log(audit_log)
            .process_one(&t, std::slice::from_ref(&t), &mut store, &mut dispatcher);

        assert!(
            matches!(outcome, OrchestrationOutcome::Completed { ref state, .. } if state == STATE_SUCCEEDED),
            "allowed task must complete successfully: {outcome:?}"
        );
        let audit = std::fs::read_to_string(&audit_path).expect("audit log written");
        let _ = std::fs::remove_file(&audit_path);
        assert!(
            audit.contains("\"decision\":\"allowed\""),
            "allowed action must be audited: {audit}"
        );
        assert!(
            audit.contains("run_tests"),
            "audit must record the tool name: {audit}"
        );
    }

    #[test]
    fn audit_write_failure_is_swallowed_and_action_still_authorized() {
        // Spec testing-plan item 4 / issue #266: task-path auditing is a side
        // effect that must never block dispatch. With an unwritable audit path,
        // `audit_policy_decision` logs-and-swallows the append error instead of
        // mapping it to `OrchestrationOutcome::StoreError`, so a policy-allowed
        // action still authorizes and completes. Guards against a regression
        // that re-introduces audit-blocks-dispatch.
        let t = with_action(
            task("task-a", STATE_PENDING, "agent-a"),
            json!({"type":"tool", "tool":"run_tests", "args":{}}),
        );
        // A regular file cannot serve as the log's parent directory, so
        // `AuditLog::append`'s `create_dir_all(parent)` fails — exercising the
        // swallow path without depending on filesystem permissions.
        let blocker = audit_path("audit-unwritable");
        std::fs::write(&blocker, b"not a directory").expect("seed blocker file");
        let unwritable = blocker.join("audit.log");
        let mut store = MemoryStore::default();
        let mut dispatcher = Dispatcher(Ok(TaskExecutionResult {
            exit_code: Some(0),
            summary: "tests passed".to_string(),
            artifact_mxc: None,
        }));
        let outcome = TaskOrchestrator::new("agent-a")
            .with_room_id("!room:server")
            .with_policy(policy())
            .with_audit_log(AuditLog::new(unwritable.clone()))
            .process_one(&t, std::slice::from_ref(&t), &mut store, &mut dispatcher);

        let _ = std::fs::remove_file(&blocker);
        assert!(
            matches!(outcome, OrchestrationOutcome::Completed { ref state, .. } if state == STATE_SUCCEEDED),
            "an unwritable audit log must not block dispatch (swallow contract); got {outcome:?}"
        );
        assert!(
            !unwritable.exists(),
            "the audit append must have failed (no log written), proving the swallow path ran"
        );
    }

    #[test]
    fn policy_denies_disallowed_exec_before_claim() {
        let t = with_action(
            task("task-a", STATE_PENDING, "agent-a"),
            json!({"type":"exec", "command":["sh", "-c", "rm -rf /"], "cwd":"/repo"}),
        );
        let mut store = MemoryStore::default();
        let mut dispatcher = PanicDispatcher;
        let outcome = TaskOrchestrator::new("agent-a")
            .with_room_id("!room:server")
            .with_policy(policy())
            .process_one(&t, std::slice::from_ref(&t), &mut store, &mut dispatcher);

        assert!(matches!(outcome, OrchestrationOutcome::Denied { .. }));
        assert_eq!(store.current_rev, 2);
        assert_eq!(store.finalized_state.as_deref(), Some(STATE_BLOCKED));
        let result = finalized_result(&store);
        assert_eq!(
            result.get("reason").and_then(Value::as_str),
            Some("policy_denied")
        );
        assert!(result
            .get("summary")
            .and_then(Value::as_str)
            .is_some_and(|s| s.contains("not allowlisted")));
    }

    #[test]
    fn policy_allows_known_task_action_to_dispatch() {
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
        let outcome = TaskOrchestrator::new("agent-a")
            .with_room_id("!room:server")
            .with_policy(policy())
            .process_one(&t, std::slice::from_ref(&t), &mut store, &mut dispatcher);

        assert!(matches!(
            outcome,
            OrchestrationOutcome::Completed { state, .. } if state == STATE_SUCCEEDED
        ));
        assert_eq!(store.current_rev, 3);
    }

    #[test]
    fn claim_records_owner_and_invocation() {
        let t = with_action(
            task("task-a", STATE_PENDING, "agent-a"),
            json!({"type":"tool", "tool":"run_tests", "args":{}}),
        );
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
        assert!(matches!(outcome, OrchestrationOutcome::Completed { .. }));
        // The claim recorded this agent as the owner and linked an invocation.
        assert_eq!(store.claimed_assigned_to.as_deref(), Some("agent-a"));
        assert!(store.claimed_invocation_id.is_some());
    }

    #[test]
    fn competing_daemon_cannot_double_claim() {
        // A second daemon observing the same task at the now-stale revision must
        // lose the claim race and must not dispatch anything.
        let t = with_action(
            task("task-a", STATE_PENDING, "agent-a"),
            json!({"type":"tool", "tool":"run_tests", "args":{}}),
        );
        let mut store = MemoryStore {
            current_rev: 2,
            stale: true,
            ..MemoryStore::default()
        };
        let mut dispatcher = PanicDispatcher;
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
        // No claim was recorded and no finalize happened.
        assert!(store.claimed_assigned_to.is_none());
        assert!(store.finalized_state.is_none());
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

    #[test]
    fn recover_executing_tasks_reconciles_local_and_remote() {
        // A live local task (still running), an orphaned local task (process
        // gone), and a remote-owned task. Recovery must resolve only the
        // orphaned local one, leave the live and the remote ones unchanged, and
        // never re-spawn anything.
        let mut live_local = task("task-live", STATE_EXECUTING, "agent-a");
        live_local.invocation_id = Some("inv-live".to_string());
        let mut orphaned_local = task("task-orphan", STATE_EXECUTING, "agent-a");
        orphaned_local.invocation_id = Some("inv-gone".to_string());
        let mut remote = task("task-remote", STATE_EXECUTING, "agent-b");
        remote.invocation_id = Some("inv-remote".to_string());
        let pending = with_action(
            task("task-pending", STATE_PENDING, "agent-a"),
            json!({"type":"tool", "tool":"run_tests", "args":{}}),
        );
        let tasks = vec![live_local, orphaned_local, remote, pending];

        let mut live = BTreeSet::new();
        live.insert("inv-live".to_string());

        let mut store = MemoryStore::default();
        let outcomes =
            TaskOrchestrator::new("agent-a").recover_executing_tasks(&tasks, &live, &mut store);

        // Only the three executing tasks produce outcomes; the pending one is
        // not part of recovery.
        assert_eq!(outcomes.len(), 3);
        assert!(outcomes.iter().any(|o| matches!(
            o,
            OrchestrationOutcome::NotRunnableState { task_id, .. } if task_id == "task-live"
        )));
        assert!(outcomes.iter().any(|o| matches!(
            o,
            OrchestrationOutcome::RecoveredStale { task_id } if task_id == "task-orphan"
        )));
        assert!(outcomes.iter().any(|o| matches!(
            o,
            OrchestrationOutcome::StaleRemoteExecuting { task_id, owner }
                if task_id == "task-remote" && owner == "agent-b"
        )));
        // The only finalize was the orphaned local task being recovered failed;
        // the live and remote tasks were never written, so nothing was
        // double-run.
        assert_eq!(store.finalized_state.as_deref(), Some(STATE_FAILED));
        let result = store.finalized_result.as_ref().expect("recovery result");
        assert_eq!(
            result.get("reason").and_then(Value::as_str),
            Some("recovered_stale_invocation")
        );
    }

    // --- Signed task action authorization (issue #166) -----------------------

    use crate::session::SessionPaths;
    use ed25519_dalek::SigningKey;

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    const TEST_KEY_ID: &str = "mxagent-ed25519:test-task-key";

    fn trust_store_with_key(status_trusted: bool) -> TrustStore {
        let mut store = TrustStore::default();
        store.approve(
            "@planner:server",
            TEST_KEY_ID,
            Some("SHA256:test".to_string()),
            None,
            None,
        );
        if !status_trusted {
            store.revoke("@planner:server", TEST_KEY_ID);
        }
        store
    }

    fn replay_cache(name: &str) -> (ReplayCache, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "mx-agent-task-auth-{name}-{}-{}",
            std::process::id(),
            now_rfc3339().replace([':', '-'], "")
        ));
        std::fs::create_dir_all(&dir).expect("create replay dir");
        let paths = SessionPaths::for_data_dir(dir.clone());
        let cache = ReplayCache::load_with_capacity(&paths, 64).expect("replay cache loads");
        (cache, dir)
    }

    fn future_rfc3339() -> String {
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or_default()
            + 3600;
        unix_to_rfc3339(secs)
    }

    fn signed_tool_action(expires_at: &str, nonce: &str) -> (TaskState, TaskAction) {
        let action = TaskAction::Tool {
            tool: "run_tests".to_string(),
            args: json!({}),
            authorization: None,
        };
        let auth = sign_task_action(
            &signing_key(),
            TEST_KEY_ID,
            "task-a",
            &action,
            "@planner:server",
            "agent-a",
            "2026-06-04T18:00:00Z",
            expires_at,
            nonce,
        )
        .expect("sign task action");
        let signed = TaskAction::Tool {
            tool: "run_tests".to_string(),
            args: json!({}),
            authorization: Some(auth),
        };
        let mut t = task("task-a", STATE_PENDING, "agent-a");
        t.created_by = "@planner:server".to_string();
        t.action = Some(signed.clone());
        (t, signed)
    }

    #[test]
    fn trusted_signed_action_runs_through_policy_and_dispatch() {
        let (t, _action) = signed_tool_action(&future_rfc3339(), "nonce-ok");
        let (cache, dir) = replay_cache("ok");
        let mut store = MemoryStore::default();
        let mut dispatcher = Dispatcher(Ok(TaskExecutionResult {
            exit_code: Some(0),
            summary: "tests passed".to_string(),
            artifact_mxc: None,
        }));
        let outcome = TaskOrchestrator::new("agent-a")
            .with_room_id("!room:server")
            .with_policy(policy())
            .with_trust_store(trust_store_with_key(true))
            .with_verifying_key(TEST_KEY_ID, signing_key().verifying_key())
            .with_replay_cache(cache)
            .process_one(&t, std::slice::from_ref(&t), &mut store, &mut dispatcher);
        let _ = std::fs::remove_dir_all(&dir);
        assert!(matches!(
            outcome,
            OrchestrationOutcome::Completed { state, .. } if state == STATE_SUCCEEDED
        ));
    }

    #[test]
    fn unsigned_action_does_not_execute_when_trust_required() {
        let mut t = task("task-a", STATE_PENDING, "agent-a");
        t.created_by = "@planner:server".to_string();
        t.action = Some(TaskAction::Tool {
            tool: "run_tests".to_string(),
            args: json!({}),
            authorization: None,
        });
        let mut store = MemoryStore::default();
        let mut dispatcher = PanicDispatcher;
        let outcome = TaskOrchestrator::new("agent-a")
            .with_room_id("!room:server")
            .with_policy(policy())
            .with_trust_store(trust_store_with_key(true))
            .with_verifying_key(TEST_KEY_ID, signing_key().verifying_key())
            .process_one(&t, std::slice::from_ref(&t), &mut store, &mut dispatcher);
        assert!(matches!(outcome, OrchestrationOutcome::Denied { .. }));
        assert_eq!(store.finalized_state.as_deref(), Some(STATE_BLOCKED));
        let result = finalized_result(&store);
        assert_eq!(
            result.get("reason").and_then(Value::as_str),
            Some("unauthorized")
        );
    }

    #[test]
    fn untrusted_key_signed_action_does_not_execute() {
        let (t, _action) = signed_tool_action(&future_rfc3339(), "nonce-untrusted");
        let mut store = MemoryStore::default();
        let mut dispatcher = PanicDispatcher;
        let outcome = TaskOrchestrator::new("agent-a")
            .with_room_id("!room:server")
            .with_policy(policy())
            .with_trust_store(TrustStore::default())
            .with_verifying_key(TEST_KEY_ID, signing_key().verifying_key())
            .process_one(&t, std::slice::from_ref(&t), &mut store, &mut dispatcher);
        assert!(matches!(outcome, OrchestrationOutcome::Denied { .. }));
        let result = finalized_result(&store);
        assert!(result
            .get("summary")
            .and_then(Value::as_str)
            .is_some_and(|s| s.contains("untrusted_key")));
    }

    #[test]
    fn revoked_key_signed_action_does_not_execute() {
        let (t, _action) = signed_tool_action(&future_rfc3339(), "nonce-revoked");
        let mut store = MemoryStore::default();
        let mut dispatcher = PanicDispatcher;
        let outcome = TaskOrchestrator::new("agent-a")
            .with_room_id("!room:server")
            .with_policy(policy())
            .with_trust_store(trust_store_with_key(false))
            .with_verifying_key(TEST_KEY_ID, signing_key().verifying_key())
            .process_one(&t, std::slice::from_ref(&t), &mut store, &mut dispatcher);
        assert!(matches!(outcome, OrchestrationOutcome::Denied { .. }));
        let result = finalized_result(&store);
        assert!(result
            .get("summary")
            .and_then(Value::as_str)
            .is_some_and(|s| s.contains("untrusted_key")));
    }

    #[test]
    fn tampered_signed_action_fails_verification() {
        let (mut t, _action) = signed_tool_action(&future_rfc3339(), "nonce-tamper");
        // Tamper with the action after signing: change the tool name.
        if let Some(TaskAction::Tool {
            tool,
            authorization,
            ..
        }) = t.action.clone()
        {
            t.action = Some(TaskAction::Tool {
                tool: format!("{tool}-tampered"),
                args: json!({}),
                authorization,
            });
        }
        let mut store = MemoryStore::default();
        let mut dispatcher = PanicDispatcher;
        let outcome = TaskOrchestrator::new("agent-a")
            .with_room_id("!room:server")
            .with_policy(policy())
            .with_trust_store(trust_store_with_key(true))
            .with_verifying_key(TEST_KEY_ID, signing_key().verifying_key())
            .process_one(&t, std::slice::from_ref(&t), &mut store, &mut dispatcher);
        assert!(matches!(outcome, OrchestrationOutcome::Denied { .. }));
        let result = finalized_result(&store);
        assert!(result
            .get("summary")
            .and_then(Value::as_str)
            .is_some_and(|s| s.contains("invalid_signature")));
    }

    #[test]
    fn expired_signed_action_does_not_execute() {
        let (t, _action) = signed_tool_action("2000-01-01T00:00:00Z", "nonce-expired");
        let (cache, dir) = replay_cache("expired");
        let mut store = MemoryStore::default();
        let mut dispatcher = PanicDispatcher;
        let outcome = TaskOrchestrator::new("agent-a")
            .with_room_id("!room:server")
            .with_policy(policy())
            .with_trust_store(trust_store_with_key(true))
            .with_verifying_key(TEST_KEY_ID, signing_key().verifying_key())
            .with_replay_cache(cache)
            .process_one(&t, std::slice::from_ref(&t), &mut store, &mut dispatcher);
        let _ = std::fs::remove_dir_all(&dir);
        assert!(matches!(outcome, OrchestrationOutcome::Denied { .. }));
        let result = finalized_result(&store);
        assert!(result
            .get("summary")
            .and_then(Value::as_str)
            .is_some_and(|s| s.contains("expired")));
    }

    #[test]
    fn replayed_signed_action_does_not_execute_twice() {
        let expires = future_rfc3339();
        let (cache, dir) = replay_cache("replay");
        let mut store = MemoryStore::default();
        let orchestrator = TaskOrchestrator::new("agent-a")
            .with_room_id("!room:server")
            .with_policy(policy())
            .with_trust_store(trust_store_with_key(true))
            .with_verifying_key(TEST_KEY_ID, signing_key().verifying_key())
            .with_replay_cache(cache);

        let (t, _action) = signed_tool_action(&expires, "nonce-replay");
        let mut dispatcher = Dispatcher(Ok(TaskExecutionResult {
            exit_code: Some(0),
            summary: "tests passed".to_string(),
            artifact_mxc: None,
        }));
        let first =
            orchestrator.process_one(&t, std::slice::from_ref(&t), &mut store, &mut dispatcher);
        assert!(matches!(first, OrchestrationOutcome::Completed { .. }));

        // Re-presenting the same signed authorization (same nonce) must not run.
        let mut replay_store = MemoryStore::default();
        let mut panic_dispatcher = PanicDispatcher;
        let second = orchestrator.process_one(
            &t,
            std::slice::from_ref(&t),
            &mut replay_store,
            &mut panic_dispatcher,
        );
        let _ = std::fs::remove_dir_all(&dir);
        assert!(matches!(second, OrchestrationOutcome::Denied { .. }));
        let result = finalized_result(&replay_store);
        assert!(result
            .get("summary")
            .and_then(Value::as_str)
            .is_some_and(|s| s.contains("replayed")));
    }

    #[test]
    fn approval_held_task_is_not_replay_blocked_when_it_resumes() {
        // Regression for the core of issue #223: an approval-required signed task
        // is held on the first pass (no decision) and must NOT burn its single-use
        // replay nonce while held, so that when it is approved on a later pass the
        // same authorization runs instead of being rejected as a replay.
        use std::cell::Cell;
        struct SwitchGate(Rc<Cell<bool>>);
        impl TaskApprovalGate for SwitchGate {
            fn evaluate(&mut self, _task: &TaskState, _action: &TaskAction) -> ApprovalDisposition {
                if self.0.get() {
                    ApprovalDisposition::Approved
                } else {
                    ApprovalDisposition::Pending("approval:task-a".to_string())
                }
            }
        }

        let approved = Rc::new(Cell::new(false));
        let (t, _action) = signed_tool_action(&future_rfc3339(), "nonce-approval-resume");
        let (cache, dir) = replay_cache("approval-resume");
        let orchestrator = TaskOrchestrator::new("agent-a")
            .with_room_id("!room:server")
            .with_policy(policy_requires_approval())
            .with_trust_store(trust_store_with_key(true))
            .with_verifying_key(TEST_KEY_ID, signing_key().verifying_key())
            .with_replay_cache(cache)
            .with_approval_gate(Box::new(SwitchGate(Rc::clone(&approved))));

        // Pass 1: undecided -> held; the task is neither claimed nor finalized and
        // the replay nonce is not consumed.
        let mut held_store = MemoryStore::default();
        let mut panic_dispatcher = PanicDispatcher;
        let first = orchestrator.process_one(
            &t,
            std::slice::from_ref(&t),
            &mut held_store,
            &mut panic_dispatcher,
        );
        assert!(
            matches!(first, OrchestrationOutcome::AwaitingApproval { .. }),
            "first pass should hold the task: {first:?}"
        );
        assert!(held_store.finalized_state.is_none());

        // Pass 2: approved -> the same authorization now runs to success. Had the
        // nonce been burned while held, this would be blocked as "replayed".
        approved.set(true);
        let mut run_store = MemoryStore::default();
        let mut dispatcher = Dispatcher(Ok(TaskExecutionResult {
            exit_code: Some(0),
            summary: "tests passed".to_string(),
            artifact_mxc: None,
        }));
        let second = orchestrator.process_one(
            &t,
            std::slice::from_ref(&t),
            &mut run_store,
            &mut dispatcher,
        );
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            matches!(&second, OrchestrationOutcome::Completed { state, .. } if state == STATE_SUCCEEDED),
            "an approved held task must run, not be replay-blocked: {second:?}"
        );
    }

    #[test]
    fn stale_claim_does_not_consume_action_nonce() {
        // A benign optimistic-claim race must not permanently burn the action's
        // single-use nonce: the next pass against a non-stale store must run the
        // same authorization to success, not block it as "replayed".
        let (t, _action) = signed_tool_action(&future_rfc3339(), "nonce-stale-action");
        let (cache, dir) = replay_cache("stale-action");
        let orchestrator = TaskOrchestrator::new("agent-a")
            .with_room_id("!room:server")
            .with_policy(policy())
            .with_trust_store(trust_store_with_key(true))
            .with_verifying_key(TEST_KEY_ID, signing_key().verifying_key())
            .with_replay_cache(cache);

        // Pass 1: the store reports a stale claim, so nothing dispatches and the
        // nonce burned before the claim is un-burned.
        let mut stale_store = MemoryStore {
            stale: true,
            ..MemoryStore::default()
        };
        let mut panic_dispatcher = PanicDispatcher;
        let first = orchestrator.process_one(
            &t,
            std::slice::from_ref(&t),
            &mut stale_store,
            &mut panic_dispatcher,
        );
        assert!(
            matches!(first, OrchestrationOutcome::StaleClaim { .. }),
            "a lost claim race must surface as StaleClaim: {first:?}"
        );
        assert!(
            stale_store.finalized_state.is_none(),
            "a stale claim must not finalize the task blocked"
        );

        // Pass 2: a non-stale store now runs the same authorization to success.
        let mut run_store = MemoryStore::default();
        let mut dispatcher = Dispatcher(Ok(TaskExecutionResult {
            exit_code: Some(0),
            summary: "tests passed".to_string(),
            artifact_mxc: None,
        }));
        let second = orchestrator.process_one(
            &t,
            std::slice::from_ref(&t),
            &mut run_store,
            &mut dispatcher,
        );
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            matches!(&second, OrchestrationOutcome::Completed { state, .. } if state == STATE_SUCCEEDED),
            "the action nonce must survive a benign stale-claim race: {second:?}"
        );
    }

    #[test]
    fn stale_claim_does_not_consume_approval_nonce() {
        // A benign optimistic-claim race on an approval-gated task must not
        // consume the operator's single-use approval decision nonce: the next
        // pass must re-release the task with the same decision instead of hanging
        // it pending forever.
        let (t, _action) = signed_tool_action(&future_rfc3339(), "nonce-stale-approval-action");
        let (cache, dir) = replay_cache("stale-approval");
        let decision_expires = future_rfc3339();

        let orchestrator = TaskOrchestrator::new("agent-a")
            .with_room_id("!room:server")
            .with_policy(policy_requires_approval())
            .with_trust_store(trust_store_with_key(true))
            .with_verifying_key(TEST_KEY_ID, signing_key().verifying_key())
            .with_replay_cache(cache);

        let shared_queue = Rc::new(RefCell::new(ApprovalQueue::default()));
        let et = decision_expires.clone();
        let gate = QueueApprovalGate::new(
            "!room:server",
            "agent-a",
            "2099-01-01T00:00:00Z",
            Rc::clone(&shared_queue),
            move |request_id: &str| {
                Some(ApprovalDecision {
                    request_id: request_id.to_string(),
                    decision: "approved".to_string(),
                    approved_by: "@daemon:server".to_string(),
                    created_at: "2026-06-10T12:00:00Z".to_string(),
                    nonce: Some("decision-nonce-stale".to_string()),
                    expires_at: Some(et.clone()),
                    signature: None,
                    extra: Default::default(),
                })
            },
        )
        // Share the orchestrator's cache so decision and action nonces persist to
        // one file, exactly as the scheduler wires it.
        .with_replay_cache(orchestrator.replay_cache_handle());
        let orchestrator = orchestrator.with_approval_gate(Box::new(gate));

        // Pass 1: approved, but the store reports a stale claim. Both the action
        // and decision nonces burned before the claim must be un-burned.
        let mut stale_store = MemoryStore {
            stale: true,
            ..MemoryStore::default()
        };
        let mut panic_dispatcher = PanicDispatcher;
        let first = orchestrator.process_one(
            &t,
            std::slice::from_ref(&t),
            &mut stale_store,
            &mut panic_dispatcher,
        );
        assert!(
            matches!(first, OrchestrationOutcome::StaleClaim { .. }),
            "a lost claim race on an approval-gated task must surface as StaleClaim: {first:?}"
        );

        // Pass 2: the same approving decision (still in the scan window) must
        // re-release the task and run it, because its nonce was un-burned.
        let mut run_store = MemoryStore::default();
        let mut dispatcher = Dispatcher(Ok(TaskExecutionResult {
            exit_code: Some(0),
            summary: "tests passed".to_string(),
            artifact_mxc: None,
        }));
        let second = orchestrator.process_one(
            &t,
            std::slice::from_ref(&t),
            &mut run_store,
            &mut dispatcher,
        );
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            matches!(&second, OrchestrationOutcome::Completed { state, .. } if state == STATE_SUCCEEDED),
            "a benign stale claim must not consume the approval decision nonce: {second:?}"
        );
    }

    // --- restart reconciliation by unified id (issue #239) ------------------

    fn executing_task(id: &str, assigned_to: &str, invocation_id: Option<&str>) -> TaskState {
        let mut t = task(id, STATE_EXECUTING, assigned_to);
        t.invocation_id = invocation_id.map(str::to_string);
        t
    }

    fn invocation(invocation_id: &str, state: &str, exit_code: Option<i32>) -> InvocationState {
        InvocationState {
            invocation_id: invocation_id.to_string(),
            task_id: None,
            requester: "@planner:server".to_string(),
            target: "agent-a".to_string(),
            state: state.to_string(),
            created_at: "2026-06-04T18:00:00Z".to_string(),
            updated_at: "2026-06-04T18:00:00Z".to_string(),
            exit_code,
            state_rev: 1,
            extra: Extra::default(),
        }
    }

    #[test]
    fn reconcile_finalizes_task_from_terminal_invocation() {
        // An owned executing task whose remote invocation already finished is
        // reconciled to that real outcome by the unified id, not blindly failed.
        let t = executing_task("task-a", "agent-a", Some("inv_1"));
        let mut invocations = BTreeMap::new();
        invocations.insert("inv_1".to_string(), invocation("inv_1", "cancelled", None));
        let mut store = MemoryStore::default();
        let outcomes = TaskOrchestrator::new("agent-a").reconcile_executing_tasks(
            std::slice::from_ref(&t),
            &BTreeSet::new(),
            &invocations,
            &mut store,
        );
        assert!(matches!(
            outcomes.as_slice(),
            [OrchestrationOutcome::ReconciledInvocation { state, .. }] if state == "cancelled"
        ));
        assert_eq!(store.finalized_state.as_deref(), Some("cancelled"));
        let result = store
            .finalized_result
            .expect("a reconciled result is recorded");
        assert_eq!(
            result.get("invocation_id").and_then(Value::as_str),
            Some("inv_1")
        );
    }

    #[test]
    fn reconcile_leaves_task_when_invocation_still_running() {
        // A still-running remote invocation must not be killed off on restart.
        let t = executing_task("task-a", "agent-a", Some("inv_1"));
        let mut invocations = BTreeMap::new();
        invocations.insert("inv_1".to_string(), invocation("inv_1", "running", None));
        let mut store = MemoryStore::default();
        let outcomes = TaskOrchestrator::new("agent-a").reconcile_executing_tasks(
            std::slice::from_ref(&t),
            &BTreeSet::new(),
            &invocations,
            &mut store,
        );
        assert!(matches!(
            outcomes.as_slice(),
            [OrchestrationOutcome::StillRunningInvocation { .. }]
        ));
        assert!(
            store.finalized_state.is_none(),
            "the task must be left executing"
        );
    }

    #[test]
    fn reconcile_recovers_orphan_with_no_invocation_state() {
        // No invocation state by the unified id and not claimed this run: a genuine
        // orphan from a previous daemon run, recovered failed.
        let t = executing_task("task-a", "agent-a", Some("inv_gone"));
        let mut store = MemoryStore::default();
        let outcomes = TaskOrchestrator::new("agent-a").reconcile_executing_tasks(
            std::slice::from_ref(&t),
            &BTreeSet::new(),
            &BTreeMap::new(),
            &mut store,
        );
        assert!(matches!(
            outcomes.as_slice(),
            [OrchestrationOutcome::RecoveredStale { .. }]
        ));
        assert_eq!(store.finalized_state.as_deref(), Some("failed"));
        let result = store
            .finalized_result
            .expect("a recovery result is recorded");
        assert_eq!(
            result.get("reason").and_then(Value::as_str),
            Some("recovered_stale_invocation")
        );
    }

    #[test]
    fn reconcile_skips_invocation_claimed_this_run() {
        // #230: a task this run claimed/finalized must never be clobbered, even if
        // a stale snapshot still shows it executing and a terminal invocation
        // exists for it.
        let t = executing_task("task-a", "agent-a", Some("inv_1"));
        let mut invocations = BTreeMap::new();
        invocations.insert(
            "inv_1".to_string(),
            invocation("inv_1", "succeeded", Some(0)),
        );
        let mut live = BTreeSet::new();
        live.insert("inv_1".to_string());
        let mut store = MemoryStore::default();
        let outcomes = TaskOrchestrator::new("agent-a").reconcile_executing_tasks(
            std::slice::from_ref(&t),
            &live,
            &invocations,
            &mut store,
        );
        assert!(matches!(
            outcomes.as_slice(),
            [OrchestrationOutcome::NotRunnableState { .. }]
        ));
        assert!(store.finalized_state.is_none());
    }

    #[test]
    fn reconcile_leaves_remote_owned_task() {
        // Only the owning daemon may resolve a remote-owned executing task.
        let t = executing_task("task-a", "other-agent", Some("inv_1"));
        let mut invocations = BTreeMap::new();
        invocations.insert("inv_1".to_string(), invocation("inv_1", "cancelled", None));
        let mut store = MemoryStore::default();
        let outcomes = TaskOrchestrator::new("agent-a").reconcile_executing_tasks(
            std::slice::from_ref(&t),
            &BTreeSet::new(),
            &invocations,
            &mut store,
        );
        assert!(matches!(
            outcomes.as_slice(),
            [OrchestrationOutcome::StaleRemoteExecuting { owner, .. }] if owner == "other-agent"
        ));
        assert!(store.finalized_state.is_none());
    }

    // ── Verifier security regressions (issue #302) ─────────────────────────────
    // These tests confirm that the executing-side enforcement is unchanged after
    // daemon-side authoring-time signing was introduced. Authoring-side signing
    // only attaches a signature — it does not weaken any of the execution gates.

    #[test]
    fn wrong_target_signed_action_does_not_execute() {
        // An action signed for "wrong-agent" must not run when presented to an
        // orchestrator for "agent-a": the verifier rejects it as `wrong_target`
        // before dispatch is attempted. This guards the case where an authorization
        // was authored for a different executing agent or where the task was
        // reassigned without re-signing.
        let action = TaskAction::Tool {
            tool: "run_tests".to_string(),
            args: json!({}),
            authorization: None,
        };
        let auth = sign_task_action(
            &signing_key(),
            TEST_KEY_ID,
            "task-a",
            &action,
            "@planner:server",
            "wrong-agent", // not "agent-a"
            "2026-06-02T12:00:00Z",
            future_rfc3339(),
            "nonce-wrong-target",
        )
        .expect("sign task action");
        let mut t = task("task-a", STATE_PENDING, "agent-a");
        t.action = Some(TaskAction::Tool {
            tool: "run_tests".to_string(),
            args: json!({}),
            authorization: Some(auth),
        });

        let mut store = MemoryStore::default();
        let mut dispatcher = PanicDispatcher;
        let outcome = TaskOrchestrator::new("agent-a") // agent_id != target_agent
            .with_room_id("!room:server")
            .with_policy(policy())
            .with_trust_store(trust_store_with_key(true))
            .with_verifying_key(TEST_KEY_ID, signing_key().verifying_key())
            .process_one(&t, std::slice::from_ref(&t), &mut store, &mut dispatcher);
        assert!(matches!(outcome, OrchestrationOutcome::Denied { .. }));
        let result = finalized_result(&store);
        assert!(
            result
                .get("summary")
                .and_then(Value::as_str)
                .is_some_and(|s| s.contains("wrong_target")),
            "wrong-target action must be blocked with reason wrong_target; got: {result:?}"
        );
    }

    #[test]
    fn unresolved_key_signed_action_does_not_execute() {
        // An action whose `signature.key_id` is trusted in the trust store but has
        // no registered verifying key must not run: the verifier blocks it as
        // `unresolved_key`. This covers the case where a daemon is listed as trusted
        // in the trust store but its public key bytes have not been loaded (e.g.
        // the key was approved by key_id before the public key was fetched and
        // registered via `.with_verifying_key`).
        //
        // The trust check (is_key_trusted) passes because the key_id is approved,
        // but the verifying-key lookup returns None, producing `unresolved_key`.
        let action = TaskAction::Tool {
            tool: "run_tests".to_string(),
            args: json!({}),
            authorization: None,
        };
        let unknown_key_id = "mxagent-ed25519:trusted-but-unresolved";
        let auth = sign_task_action(
            &signing_key(),
            unknown_key_id,
            "task-a",
            &action,
            "@planner:server",
            "agent-a",
            "2026-06-02T12:00:00Z",
            future_rfc3339(),
            "nonce-unresolved-key",
        )
        .expect("sign task action");
        let mut t = task("task-a", STATE_PENDING, "agent-a");
        t.action = Some(TaskAction::Tool {
            tool: "run_tests".to_string(),
            args: json!({}),
            authorization: Some(auth),
        });

        // Trust store approves the key_id, but no verifying key is registered for it.
        let mut trust = TrustStore::default();
        trust.approve("@planner:server", unknown_key_id, None, None, None);

        let mut store = MemoryStore::default();
        let mut dispatcher = PanicDispatcher;
        let outcome = TaskOrchestrator::new("agent-a")
            .with_room_id("!room:server")
            .with_policy(policy())
            .with_trust_store(trust) // unknown_key_id is trusted...
            // ...but no .with_verifying_key(unknown_key_id, ...) → unresolved_key
            .process_one(&t, std::slice::from_ref(&t), &mut store, &mut dispatcher);
        assert!(matches!(outcome, OrchestrationOutcome::Denied { .. }));
        let result = finalized_result(&store);
        assert!(
            result
                .get("summary")
                .and_then(Value::as_str)
                .is_some_and(|s| s.contains("unresolved_key")),
            "trusted but unresolved key_id must be blocked as unresolved_key; got: {result:?}"
        );
    }
}
