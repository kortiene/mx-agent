//! Task DAG state: publishing and reading `com.mxagent.task.v1` room state.
//!
//! A task is a durable DAG node tracked in a workspace room as a
//! `com.mxagent.task.v1` state event keyed by its `task_id` (see
//! `docs/architecture.md`, section 9.2). Peers read this state to discover what
//! work exists, who it is assigned to, and where it is in its lifecycle.
//!
//! Because Matrix room state is last-write-wins per `(type, state_key)`,
//! updating a task republishes its state key in place. The prior `state_rev` is
//! read first so the counter advances monotonically, and the prior event ID is
//! carried forward as `previous_event_id` so stale overwrites can be detected
//! (architecture §9.4).

use std::io;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use matrix_sdk::config::SyncSettings;
use matrix_sdk::ruma::events::StateEventType;
use matrix_sdk::{Client, Room};
use mx_agent_protocol::events::state::TASK as TASK_STATE_TYPE;
use mx_agent_protocol::id::{generate_request_id, generate_task_id};
use mx_agent_protocol::schema::{InvocationState, TaskAction, TaskResult, TaskState};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::exec_ipc::rfc3339_after;
use crate::invocation::{
    cancel_invocation, task_result_from_invocation, task_state_for_invocation,
};
use crate::matrix::restore_client;
use crate::session::{SessionPaths, StoredSession};
use crate::signing::{load_or_create_signing_key, DaemonSigningKey};
use crate::task_orchestrator::sign_task_action;
use crate::workspace::{
    parse_room_or_alias, resolve_room_id, send_workspace_state, WorkspaceError,
};

/// Lifecycle state for newly proposed work not yet ready to run.
pub const STATE_PROPOSED: &str = "proposed";
/// Lifecycle state for tasks waiting to be assigned or run.
pub const STATE_PENDING: &str = "pending";
/// Lifecycle state for tasks assigned and ready to run once dependencies pass.
pub const STATE_ASSIGNED: &str = "assigned";
/// Lifecycle state for tasks currently owned by a worker.
pub const STATE_EXECUTING: &str = "executing";
/// Lifecycle state for tasks that completed successfully.
pub const STATE_SUCCEEDED: &str = "succeeded";
/// Lifecycle state for tasks that completed unsuccessfully or were denied.
pub const STATE_FAILED: &str = "failed";
/// Lifecycle state for tasks cancelled before successful completion.
pub const STATE_CANCELLED: &str = "cancelled";
/// Lifecycle state for tasks waiting on an external condition.
pub const STATE_BLOCKED: &str = "blocked";
/// Lifecycle state for tasks replaced by newer work.
pub const STATE_SUPERSEDED: &str = "superseded";

/// State assigned to a freshly created task when the caller does not specify
/// one (architecture §9.2, `proposed -> pending -> ...`).
pub const DEFAULT_TASK_STATE: &str = STATE_PENDING;

const KNOWN_STATES: &[&str] = &[
    STATE_PROPOSED,
    STATE_PENDING,
    STATE_ASSIGNED,
    STATE_EXECUTING,
    STATE_SUCCEEDED,
    STATE_FAILED,
    STATE_CANCELLED,
    STATE_BLOCKED,
    STATE_SUPERSEDED,
];

/// Return `true` when `state` is one of the task lifecycle states mx-agent
/// understands.
pub fn is_known_state(state: &str) -> bool {
    KNOWN_STATES.contains(&state)
}

/// Return `true` when `state` is terminal and must never be auto-executed
/// again by the scheduler.
pub fn is_terminal(state: &str) -> bool {
    matches!(
        state,
        STATE_SUCCEEDED | STATE_FAILED | STATE_CANCELLED | STATE_SUPERSEDED
    )
}

/// Return `true` when a task in `state` may be considered by the scheduler.
///
/// This is only a lifecycle check. The scheduler must still require assignment,
/// satisfied dependencies, a valid action, and local policy/trust approval.
pub fn is_runnable(state: &str) -> bool {
    matches!(state, STATE_PENDING | STATE_ASSIGNED)
}

/// Return `true` when a task may move from `from` to `to`.
///
/// Equal states are treated as idempotent republishes. Terminal states do not
/// transition to any different state, which prevents succeeded/failed/cancelled
/// or superseded tasks from being reopened and auto-executed accidentally.
pub fn can_transition(from: &str, to: &str) -> bool {
    if from == to {
        return is_known_state(from);
    }
    match from {
        STATE_PROPOSED => matches!(to, STATE_PENDING | STATE_CANCELLED | STATE_SUPERSEDED),
        // A pending task may be claimed straight to `executing` by the scheduler
        // (architecture §9.2: the daemon "claims the pending task ... sets state =
        // executing"); the intermediate `assigned` state is optional.
        STATE_PENDING => matches!(
            to,
            STATE_ASSIGNED | STATE_EXECUTING | STATE_BLOCKED | STATE_CANCELLED | STATE_SUPERSEDED
        ),
        STATE_ASSIGNED => matches!(
            to,
            STATE_PENDING | STATE_EXECUTING | STATE_BLOCKED | STATE_CANCELLED | STATE_SUPERSEDED
        ),
        STATE_BLOCKED => matches!(
            to,
            STATE_PENDING | STATE_ASSIGNED | STATE_CANCELLED | STATE_SUPERSEDED
        ),
        STATE_EXECUTING => matches!(to, STATE_SUCCEEDED | STATE_FAILED | STATE_CANCELLED),
        STATE_SUCCEEDED | STATE_FAILED | STATE_CANCELLED | STATE_SUPERSEDED => false,
        _ => false,
    }
}

/// Options for [`create_task`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CreateTaskOptions {
    /// Room ID or alias to create the task in.
    pub room: String,
    /// Explicit task identifier and state key. When `None`, a sortable
    /// `task_...` ID is generated.
    pub task_id: Option<String>,
    /// Human-readable title.
    pub title: String,
    /// Longer description.
    pub description: String,
    /// Initial lifecycle state; defaults to [`DEFAULT_TASK_STATE`].
    pub state: Option<String>,
    /// Agent the task is assigned to (may be empty for an unassigned task).
    pub assigned_to: String,
    /// Identity that created the task; defaults to the caller's Matrix user ID.
    pub created_by: Option<String>,
    /// Upstream task IDs this task depends on.
    pub depends_on: Vec<String>,
    /// Downstream task IDs blocked by this one.
    pub blocks: Vec<String>,
    /// Optional structured action. When absent, this is a manual/planning task
    /// and must not be auto-executed by inferring intent from text fields.
    pub action: Option<TaskAction>,
}

/// Options for [`update_task`]. Every mutable field is optional; `None` leaves
/// the existing value unchanged.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UpdateTaskOptions {
    /// Room ID or alias the task lives in.
    pub room: String,
    /// Task identifier (state key) to update.
    pub task_id: String,
    /// New lifecycle state, e.g. `executing` or `succeeded`.
    pub state: Option<String>,
    /// New assignee.
    pub assigned_to: Option<String>,
    /// New title.
    pub title: Option<String>,
    /// New description.
    pub description: Option<String>,
    /// Associated invocation ID.
    pub invocation_id: Option<String>,
    /// Result payload to attach (typically when the task completes).
    pub result: Option<Value>,
    /// Optional structured action to replace the task's current action.
    /// `None` leaves the existing action unchanged.
    pub action: Option<TaskAction>,
    /// `state_rev` the caller last observed for this task. When `Some`, the
    /// update is applied only if the task is still at that revision; otherwise
    /// it is rejected as stale ([`WorkspaceError::StaleTaskUpdate`]) so newer
    /// state is never overwritten silently (architecture §9.4). `None` skips the
    /// check and performs an unconditional last-write-wins update.
    pub expected_state_rev: Option<u64>,
}

/// Options for [`list_tasks`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ListTasksOptions {
    /// Room ID or alias to list tasks in.
    pub room: String,
    /// Only include tasks in this lifecycle state. `None` means "no filter".
    pub state: Option<String>,
    /// Only include tasks assigned to this agent. `None` means "no filter".
    pub assigned_to: Option<String>,
}

/// Format the current wall-clock time as an RFC 3339 UTC timestamp.
fn now_rfc3339() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default();
    unix_to_rfc3339(secs)
}

/// Format Unix seconds as an RFC 3339 UTC timestamp (`YYYY-MM-DDTHH:MM:SSZ`).
///
/// Uses Howard Hinnant's civil-from-days algorithm so no date library is
/// required, matching the formatter used elsewhere in the daemon.
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

/// Default validity window for a daemon-authored task-action authorization.
///
/// Long enough to outlast realistic dependency waits and a pending approval, but
/// bounded so a captured-but-never-executed authorization does not stay valid
/// forever. The single-use nonce (burned by the verifier on the executing pass)
/// already prevents replay within this window; the TTL only bounds how long an
/// unexecuted authorization remains admissible. Overridable via
/// [`ENV_TASK_AUTH_TTL`].
const TASK_AUTH_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// Environment variable overriding [`TASK_AUTH_TTL`], in whole seconds.
const ENV_TASK_AUTH_TTL: &str = "MX_AGENT_TASK_AUTH_TTL";

/// Resolve the validity window for a daemon-authored task-action authorization.
///
/// Reads [`ENV_TASK_AUTH_TTL`] as a positive number of seconds, falling back to
/// [`TASK_AUTH_TTL`] when the variable is unset, unparseable, or zero.
fn task_auth_ttl() -> Duration {
    std::env::var(ENV_TASK_AUTH_TTL)
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .filter(|secs| *secs > 0)
        .map(Duration::from_secs)
        .unwrap_or(TASK_AUTH_TTL)
}

/// Resolve the creator identity for a task, defaulting to the client's Matrix
/// user ID when the caller left `created_by` empty (architecture §9.2).
fn resolve_created_by(options: &CreateTaskOptions, client: &Client) -> String {
    options
        .created_by
        .clone()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| client.user_id().map(|u| u.to_string()).unwrap_or_default())
}

/// Attach a daemon-authored signature to an actionable, unsigned task action.
///
/// This is the single production producer of a [`TaskActionAuthorization`]
/// (issue #302): the CLI submits `Tool`/`Exec` actions with `authorization:
/// None` because — per the architecture §10.3 auth/trust carve-out — it must
/// never hold the daemon's signing key. The daemon signs on behalf of the
/// locally-authenticated IPC caller, after the request crosses the local IPC
/// boundary, so the live scheduler (which always configures a trust store) will
/// admit the action instead of blocking it as `unsigned`.
///
/// Signs with the daemon's own Ed25519 identity, addressed to `target_agent`
/// (the executing agent), binding the final `task_id`, with a fresh single-use
/// nonce and a bounded `expires_at` ([`task_auth_ttl`]). Returns:
///
/// - `Ok(Some(signed_action))` when the daemon signed the action;
/// - `Ok(None)` to leave the caller's action field untouched when the action
///   already carries an authorization (a pre-signed action from a test or a
///   future programmatic caller is honored exactly as supplied — the daemon
///   never overwrites an existing signature), or when `target_agent` is empty
///   (an unassigned actionable task cannot be addressed yet; it stays advisory
///   until an assigning update names a target).
///
/// Signing happens only on the authoring IPC path; the executing agent still
/// runs the full gate (signature verify + local trust store + deny-by-default
/// policy + approval + replay/expiry). Attaching a signature is not a grant:
/// room membership is not execution permission, and an authorization from an
/// untrusted key stays blocked.
fn authored_authorization(
    signing: &DaemonSigningKey,
    task_id: &str,
    action: &TaskAction,
    requesting_agent: &str,
    target_agent: &str,
) -> Result<Option<TaskAction>, WorkspaceError> {
    if action.authorization().is_some() {
        return Ok(None);
    }
    if target_agent.is_empty() {
        return Ok(None);
    }
    // Sign the authorization-stripped action: the signature binds `task_id` plus
    // the action without its authorization, which the verifier re-derives.
    let unsigned = action.without_authorization();
    let auth = sign_task_action(
        signing.signing_key(),
        signing.key_id(),
        task_id,
        &unsigned,
        requesting_agent,
        target_agent,
        rfc3339_after(Duration::ZERO),
        rfc3339_after(task_auth_ttl()),
        generate_request_id(),
    )
    .map_err(|e| WorkspaceError::Io(io::Error::other(e.to_string())))?;
    Ok(Some(unsigned.with_authorization(auth)))
}

/// Load the daemon signing key for daemon-side authoring, mapping a key error to
/// a [`WorkspaceError`] the IPC layer surfaces to the CLI (mirroring the
/// `task.cancel` signing path).
fn load_authoring_key() -> Result<DaemonSigningKey, WorkspaceError> {
    load_or_create_signing_key(&SessionPaths::resolve())
        .map_err(|e| WorkspaceError::Io(io::Error::other(e.to_string())))
}

/// Build the `com.mxagent.task.v1` content for a newly created task.
fn build_new_task(
    options: &CreateTaskOptions,
    task_id: String,
    created_by: String,
    now: String,
) -> TaskState {
    TaskState {
        task_id,
        title: options.title.clone(),
        description: options.description.clone(),
        state: options
            .state
            .clone()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| DEFAULT_TASK_STATE.to_string()),
        assigned_to: options.assigned_to.clone(),
        created_by,
        depends_on: options.depends_on.clone(),
        blocks: options.blocks.clone(),
        invocation_id: None,
        created_at: now.clone(),
        updated_at: now,
        state_rev: 1,
        previous_event_id: None,
        result: None,
        action: options.action.clone(),
        extra: Default::default(),
    }
}

/// Apply an update in place: overwrite only the fields the caller supplied,
/// advance `state_rev`, refresh `updated_at`, and record the prior event ID.
fn apply_update(
    state: &mut TaskState,
    options: &UpdateTaskOptions,
    now: String,
    previous_event_id: Option<String>,
) {
    if let Some(s) = &options.state {
        state.state = s.clone();
    }
    if let Some(a) = &options.assigned_to {
        state.assigned_to = a.clone();
    }
    if let Some(t) = &options.title {
        state.title = t.clone();
    }
    if let Some(d) = &options.description {
        state.description = d.clone();
    }
    if let Some(inv) = &options.invocation_id {
        state.invocation_id = Some(inv.clone());
    }
    if let Some(result) = &options.result {
        state.result = Some(result.clone());
    }
    if let Some(action) = &options.action {
        state.action = Some(action.clone());
    }
    state.state_rev += 1;
    state.updated_at = now;
    state.previous_event_id = previous_event_id;
}

/// Reject an update whose `expected_state_rev` no longer matches the task's
/// current revision.
///
/// This is the client-side stale-update guard (architecture §9.4): because
/// Matrix room state is last-write-wins, a caller working from an outdated view
/// could clobber a newer revision published by a peer. When the caller supplies
/// the revision they last saw and it differs from `current_rev`, the task has
/// moved on and we refuse the write. A `None` expectation opts out of the check.
fn check_not_stale(
    task_id: &str,
    current_rev: u64,
    expected_rev: Option<u64>,
) -> Result<(), WorkspaceError> {
    match expected_rev {
        Some(expected) if expected != current_rev => Err(WorkspaceError::StaleTaskUpdate {
            task_id: task_id.to_string(),
            expected,
            current: current_rev,
        }),
        _ => Ok(()),
    }
}

/// Validate that a task state string is recognized.
fn check_known_state(state: &str) -> Result<(), WorkspaceError> {
    if is_known_state(state) {
        Ok(())
    } else {
        Err(WorkspaceError::InvalidTaskState(state.to_string()))
    }
}

/// Validate a lifecycle transition before publishing it.
fn check_transition(task_id: &str, from: &str, to: &str) -> Result<(), WorkspaceError> {
    check_known_state(to)?;
    if can_transition(from, to) {
        Ok(())
    } else {
        Err(WorkspaceError::InvalidTaskTransition {
            task_id: task_id.to_string(),
            from: from.to_string(),
            to: to.to_string(),
        })
    }
}

/// Return `true` when `task` passes the (optional) state and assignee filters.
fn matches_filters(task: &TaskState, options: &ListTasksOptions) -> bool {
    options.state.as_deref().is_none_or(|s| task.state == s)
        && options
            .assigned_to
            .as_deref()
            .is_none_or(|a| task.assigned_to == a)
}

/// Sync once, resolve the room, and return its [`Room`] handle.
async fn sync_and_get_room(client: &Client, target: &str) -> Result<Room, WorkspaceError> {
    let id = parse_room_or_alias(target)?;
    client
        .sync_once(SyncSettings::default())
        .await
        .map_err(WorkspaceError::from)?;
    let room_id = resolve_room_id(client, &id).await?;
    client
        .get_room(&room_id)
        .ok_or_else(|| WorkspaceError::RoomNotFound(target.to_string()))
}

/// Read the `com.mxagent.task.v1` state event for `task_id`, returning the
/// parsed content together with its Matrix event ID (when available).
///
/// Returns `Ok(None)` when no task with that ID exists in the room.
pub(crate) async fn read_task_state(
    room: &Room,
    task_id: &str,
) -> Result<Option<(TaskState, Option<String>)>, WorkspaceError> {
    use matrix_sdk::deserialized_responses::RawAnySyncOrStrippedState as RawState;

    let raw = room
        .get_state_event(StateEventType::from(TASK_STATE_TYPE), task_id)
        .await
        .map_err(WorkspaceError::from)?;

    let (content, event_id) = match raw {
        Some(RawState::Sync(raw)) => (
            raw.get_field::<TaskState>("content"),
            raw.get_field::<String>("event_id").ok().flatten(),
        ),
        Some(RawState::Stripped(raw)) => (raw.get_field::<TaskState>("content"), None),
        None => return Ok(None),
    };
    let content = content.map_err(|e| WorkspaceError::from(matrix_sdk::Error::SerdeJson(e)))?;
    Ok(content.map(|state| (state, event_id)))
}

/// Read every `com.mxagent.task.v1` state event from a room.
async fn read_all_task_states(room: &Room) -> Result<Vec<TaskState>, WorkspaceError> {
    use matrix_sdk::deserialized_responses::RawAnySyncOrStrippedState as RawState;

    let raws = room
        .get_state_events(StateEventType::from(TASK_STATE_TYPE))
        .await
        .map_err(WorkspaceError::from)?;

    let mut tasks = Vec::with_capacity(raws.len());
    for raw in raws {
        let content = match raw {
            RawState::Sync(raw) => raw.get_field::<TaskState>("content"),
            RawState::Stripped(raw) => raw.get_field::<TaskState>("content"),
        }
        .map_err(|e| WorkspaceError::from(matrix_sdk::Error::SerdeJson(e)))?;
        // A removed task leaves an empty state event behind; skip those.
        if let Some(task) = content {
            tasks.push(task);
        }
    }
    Ok(tasks)
}

/// Publish `state` as a `com.mxagent.task.v1` state event keyed by `task_id`.
///
/// Returns the emitted event's Matrix `event_id` (issue #367), so the IPC entry
/// points can surface it as an audit anchor in the reply.
async fn publish_task_state(
    room: &Room,
    task_id: &str,
    state: &TaskState,
) -> Result<String, WorkspaceError> {
    warn_env_in_encrypted_room_state(room, task_id, state);
    let content = serde_json::to_value(state)
        .map_err(|e| WorkspaceError::from(matrix_sdk::Error::SerdeJson(e)))?;
    send_workspace_state(room, TASK_STATE_TYPE, task_id, content).await
}

/// Warn when a task action carrying a non-empty `env` is published into an
/// **encrypted** room.
///
/// Matrix never Megolm-encrypts state events, so the `com.mxagent.task.v1`
/// action (`command`/`cwd`/`env`) is plaintext readable by the homeserver
/// operator even under `--e2ee on` (issue #308). An operator who created an
/// encrypted workspace might wrongly assume the env is confidential, so the
/// daemon surfaces one advisory warning per publish. To avoid leaking the very
/// secrets it is warning about, the log records only the **count** of env keys —
/// never their names or values. Unencrypted rooms are already documented as
/// cleartext and are not warned about, so they are not spammed.
fn warn_env_in_encrypted_room_state(room: &Room, task_id: &str, state: &TaskState) {
    let Some(TaskAction::Exec { env, .. }) = state.action.as_ref() else {
        return;
    };
    if env.is_empty() || !room.encryption_state().is_encrypted() {
        return;
    }
    tracing::warn!(
        task_id,
        room_id = %room.room_id(),
        env_key_count = env.len(),
        "task action env is published in room state and is readable by the homeserver \
         operator even in an encrypted room; do not place secrets in task env"
    );
}

/// IPC reply for `task.create` / `task.update`: the resulting [`TaskState`] plus
/// the **audit anchor** — the Matrix `event_id` of the emitted
/// `com.mxagent.task.v1` state event — so a caller can correlate the signed task
/// mutation to the event it produced (issue #367).
///
/// The task fields are `#[serde(flatten)]`-ed, so the JSON reply is the prior
/// `TaskState` shape with a single added top-level `event_id` field (backward
/// compatible). `previous_event_id` continues to carry the *prior* revision's
/// event id; `event_id` is the id of *this* emission.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskMutation {
    /// The task state after the create/update.
    #[serde(flatten)]
    pub task: TaskState,
    /// Matrix event id of the `com.mxagent.task.v1` state event this mutation
    /// emitted.
    pub event_id: String,
}

/// Create a task in a workspace room.
///
/// Publishes a `com.mxagent.task.v1` state event keyed by the task ID with
/// `state_rev` 1. Refuses to overwrite an existing task ID
/// ([`WorkspaceError::TaskExists`]); mutating an existing task is the job of
/// [`update_task`].
pub async fn create_task(
    client: &Client,
    options: &CreateTaskOptions,
) -> Result<TaskState, WorkspaceError> {
    create_task_returning_event_id(client, options)
        .await
        .map(|(state, _event_id)| state)
}

/// Like [`create_task`] but also returns the emitted `com.mxagent.task.v1`
/// event id (issue #367). The public [`create_task`] stays a thin wrapper so its
/// many callers are unaffected; only the IPC entry point
/// ([`create_task_for_session`]) needs the audit anchor.
async fn create_task_returning_event_id(
    client: &Client,
    options: &CreateTaskOptions,
) -> Result<(TaskState, String), WorkspaceError> {
    let room = sync_and_get_room(client, &options.room).await?;

    let task_id = options
        .task_id
        .clone()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(generate_task_id);

    if read_task_state(&room, &task_id).await?.is_some() {
        return Err(WorkspaceError::TaskExists(task_id));
    }

    let created_by = resolve_created_by(options, client);

    let state = build_new_task(options, task_id.clone(), created_by, now_rfc3339());
    check_known_state(&state.state)?;
    let event_id = publish_task_state(&room, &task_id, &state).await?;
    Ok((state, event_id))
}

/// Create a task, restoring the authenticated client from `session`.
///
/// This is the production `task.create` IPC entry point. When the caller submits
/// a `Tool`/`Exec` action with no authorization, the daemon signs it on the
/// caller's behalf ([`authored_authorization`]) so the live scheduler admits it
/// instead of blocking it as `unsigned` (issue #302). The CLI never holds the
/// signing key; signing happens here, after the request crosses the local IPC
/// boundary. An unassigned actionable task is left advisory (unsigned) until an
/// assigning [`update_task_for_session`] names a target.
pub async fn create_task_for_session(
    session: &StoredSession,
    options: &CreateTaskOptions,
) -> Result<TaskMutation, WorkspaceError> {
    let client = restore_client(session).await?;
    let mut options = options.clone();

    // Resolve the final task id *before* signing. The signature binds the id, so
    // signing against a placeholder and then minting a different id inside
    // `create_task` would make the verifier reject the action as
    // `invalid_signature`. Pin the resolved id so both signing and publish agree.
    let task_id = options
        .task_id
        .clone()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(generate_task_id);
    options.task_id = Some(task_id.clone());

    if let Some(action) = &options.action {
        let signing = load_authoring_key()?;
        let requester = resolve_created_by(&options, &client);
        if let Some(signed) =
            authored_authorization(&signing, &task_id, action, &requester, &options.assigned_to)?
        {
            options.action = Some(signed);
        }
    }

    let (task, event_id) = create_task_returning_event_id(&client, &options).await?;
    Ok(TaskMutation { task, event_id })
}

/// Update an existing task in a workspace room.
///
/// Reads the current state, applies the supplied fields, advances `state_rev`,
/// refreshes `updated_at`, records the prior event ID as `previous_event_id`,
/// and republishes. Returns [`WorkspaceError::TaskNotFound`] when the task does
/// not exist.
///
/// When `options.expected_state_rev` is set, the update is first checked against
/// the task's current revision and rejected with
/// [`WorkspaceError::StaleTaskUpdate`] if the task has already moved on, so a
/// caller working from a stale view never silently overwrites newer state
/// (architecture §9.4).
pub async fn update_task(
    client: &Client,
    options: &UpdateTaskOptions,
) -> Result<TaskState, WorkspaceError> {
    let room = sync_and_get_room(client, &options.room).await?;
    update_task_in_room(&room, options)
        .await
        .map(|(state, _event_id)| state)
}

/// Update a task against an already-resolved [`Room`], performing no `/sync`.
///
/// This is the body of [`update_task`] without room resolution. The daemon's
/// scheduler loop shares the daemon's Matrix client and must not run a second
/// overlapping `/sync`, so it reads room state populated by the main sync loop
/// and writes task state events directly through the room handle. The same
/// stale-update guard ([`WorkspaceError::StaleTaskUpdate`]) and lifecycle
/// transition validation as [`update_task`] apply (architecture §9.2, §9.4).
pub(crate) async fn update_task_in_room(
    room: &Room,
    options: &UpdateTaskOptions,
) -> Result<(TaskState, String), WorkspaceError> {
    let (state, event_id) = read_task_state(room, &options.task_id)
        .await?
        .ok_or_else(|| WorkspaceError::TaskNotFound(options.task_id.clone()))?;
    apply_and_publish_task(room, state, event_id, options).await
}

/// Apply an update onto an already-known `current` task state and publish it,
/// without re-reading the room.
///
/// This is the body of [`update_task_in_room`] after the read. The daemon's
/// scheduler loop uses it with a per-pass cache of the state it just wrote, so a
/// `claim` immediately followed by a `finalize` checks staleness against the
/// claim's revision rather than the lagging local store (which has not yet
/// received the daemon's own echo over `/sync`). The same stale-update guard and
/// lifecycle-transition validation as [`update_task_in_room`] apply.
pub(crate) async fn apply_and_publish_task(
    room: &Room,
    mut current: TaskState,
    previous_event_id: Option<String>,
    options: &UpdateTaskOptions,
) -> Result<(TaskState, String), WorkspaceError> {
    check_not_stale(
        &current.task_id,
        current.state_rev,
        options.expected_state_rev,
    )?;
    if let Some(to) = &options.state {
        check_transition(&current.task_id, &current.state, to)?;
    }
    apply_update(&mut current, options, now_rfc3339(), previous_event_id);
    let event_id = publish_task_state(room, &options.task_id, &current).await?;
    Ok((current, event_id))
}

/// Update a task, restoring the authenticated client from `session`.
///
/// This is the production `task.update` IPC entry point. Like
/// [`create_task_for_session`], it (re)signs the task action daemon-side when the
/// update changes the action body or the assignee (issue #302), so a CLI-authored
/// action — or a task reassigned to a new executing agent — carries a valid
/// authorization addressed to the right target. State/title/description/result/
/// invocation-only updates leave the action (and its existing signature)
/// untouched. The scheduler's claim/finalize path uses [`update_task`] /
/// [`update_task_in_room`] (no signer) and so never signs.
pub async fn update_task_for_session(
    session: &StoredSession,
    options: &UpdateTaskOptions,
) -> Result<TaskMutation, WorkspaceError> {
    let client = restore_client(session).await?;
    // Only an action change or a reassignment can affect the signature; every
    // other update round-trips the existing action untouched, so skip the key
    // load and the extra read entirely.
    let (task, event_id) = if options.action.is_some() || options.assigned_to.is_some() {
        let signing = load_authoring_key()?;
        update_task_with_signing(&client, options, &signing).await?
    } else {
        // Inline update_task's body so the emitted event id can be captured for
        // the audit anchor (issue #367); the public update_task stays a TaskState
        // wrapper for the scheduler/test callers that do not need the anchor.
        let room = sync_and_get_room(&client, &options.room).await?;
        update_task_in_room(&room, options).await?
    };
    Ok(TaskMutation { task, event_id })
}

/// Update a task on behalf of a local IPC caller, (re)signing the action when the
/// update changes the action body or the assignee.
///
/// Reads the current task once and computes the *effective* action and assignee
/// (the supplied value, falling back to the task's current value), then:
///
/// - a newly-supplied action is signed addressed to the effective assignee
///   (honoring a caller-supplied pre-signed action, which is left untouched);
/// - a reassignment with no new action re-targets the task's existing action to
///   the new assignee by stripping the stale authorization and re-signing,
///   because the signature binds the target (an authorization addressed to the
///   old assignee would be rejected as `wrong_target`);
/// - an empty effective assignee leaves the action advisory (unsigned).
///
/// Publishing is delegated to [`apply_and_publish_task`], so the same
/// `expected_state_rev` stale guard and lifecycle-transition validation apply.
/// Signing lives here (not in [`update_task_in_room`] / [`apply_and_publish_task`])
/// so the scheduler's claim/finalize path — which has no signing key and must not
/// re-sign — is never affected.
async fn update_task_with_signing(
    client: &Client,
    options: &UpdateTaskOptions,
    signing: &DaemonSigningKey,
) -> Result<(TaskState, String), WorkspaceError> {
    let room = sync_and_get_room(client, &options.room).await?;
    let (current, event_id) = read_task_state(&room, &options.task_id)
        .await?
        .ok_or_else(|| WorkspaceError::TaskNotFound(options.task_id.clone()))?;

    let mut options = options.clone();

    let effective_assignee = options
        .assigned_to
        .clone()
        .unwrap_or_else(|| current.assigned_to.clone());
    // The verifier does not semantically enforce `requesting_agent`, but it is
    // bound into the signature; keep it consistent with the task's creator.
    let requester = if current.created_by.is_empty() {
        client.user_id().map(|u| u.to_string()).unwrap_or_default()
    } else {
        current.created_by.clone()
    };

    let signed = if let Some(new_action) = options.action.as_ref() {
        // A newly-supplied action: sign it (honoring a pre-signed one), addressed
        // to the effective assignee.
        authored_authorization(
            signing,
            &current.task_id,
            new_action,
            &requester,
            &effective_assignee,
        )?
    } else if options.assigned_to.is_some() {
        // Reassignment of an existing actionable task with no new action body:
        // re-target the current action to the new assignee. The current action is
        // daemon-signed for the *old* target, so strip its authorization first and
        // re-sign unconditionally (the strip makes `authored_authorization` sign
        // rather than short-circuit on the existing signature).
        match current.action.as_ref() {
            Some(current_action) => authored_authorization(
                signing,
                &current.task_id,
                &current_action.without_authorization(),
                &requester,
                &effective_assignee,
            )?,
            None => None,
        }
    } else {
        None
    };
    if let Some(signed) = signed {
        options.action = Some(signed);
    }

    apply_and_publish_task(&room, current, event_id, &options).await
}

/// Decide the terminal state and structured `result` for a cancelled task,
/// reconciling against its linked invocation by the unified id (issue #239).
///
/// This is the pure, side-effect-free core of [`cancel_task`]:
///
/// - When the linked invocation was read back (always terminal after
///   [`cancel_invocation`] runs — it either cancelled a live invocation or
///   returned an already-finished one unchanged), the task is reconciled to the
///   invocation's *real* terminal outcome: a cancelled invocation finalizes the
///   task `cancelled`, while an invocation that had already `succeeded`/`failed`
///   before the cancel reached it finalizes the task to that outcome instead of a
///   misleading `cancelled`. The result is derived from the invocation
///   ([`task_result_from_invocation`]) so it carries the unified `invocation_id`.
/// - When there is no linked invocation (no id, or the invocation state was never
///   published — e.g. the local-synchronous dispatch path), the task is finalized
///   `cancelled` with a minimal, non-sensitive result.
///
/// The result is always non-sensitive (no raw process output).
fn cancel_finalization(
    invocation: Option<&InvocationState>,
    task: &TaskState,
    completed_by: &str,
    now: String,
) -> (&'static str, Value) {
    match invocation {
        Some(inv) => {
            let state = task_state_for_invocation(&inv.state).unwrap_or(STATE_CANCELLED);
            (
                state,
                task_result_from_invocation(inv, completed_by, now).into_value(),
            )
        }
        None => {
            let result = TaskResult {
                status: STATE_CANCELLED.to_string(),
                completed_by: completed_by.to_string(),
                completed_at: now,
                invocation_id: task.invocation_id.clone(),
                action: None,
                reason: Some("cancelled".to_string()),
                exit_code: None,
                summary: Some("task cancelled".to_string()),
                artifact_mxc: None,
                extra: Default::default(),
            };
            (STATE_CANCELLED, result.into_value())
        }
    }
}

/// Cancel a task and drive its linked remote invocation to `cancelled`,
/// finalizing the owning task accordingly (issue #239).
///
/// Reads the task first: an unknown id is [`WorkspaceError::TaskNotFound`], and an
/// already-terminal task is returned unchanged (cancelling finished work is a
/// no-op and must never reopen a terminal task). Otherwise, when the task records
/// an `invocation_id`, the linked invocation is cancelled through the existing
/// signed cancel path ([`cancel_invocation`]): the daemon signs a
/// `com.mxagent.exec.cancel.v1`, and the target agent verifies the requester's
/// ownership/trust before terminating the process group and confirming with
/// `com.mxagent.exec.cancelled.v1`. A missing invocation state
/// ([`WorkspaceError::InvocationNotFound`]) is treated as benign (e.g. the
/// local-synchronous dispatch path publishes no live invocation state) and the
/// task is still finalized. The owning task is then finalized to the reconciled
/// terminal state with a non-sensitive structured `result` (see
/// [`cancel_finalization`]).
///
/// The cancel is privileged: the caller supplies the daemon's signing key so the
/// target can authorize the requester. The coding agent never sees the key.
pub async fn cancel_task(
    client: &Client,
    signing_key: &SigningKey,
    key_id: &str,
    room: &str,
    task_id: &str,
    reason: &str,
) -> Result<TaskState, WorkspaceError> {
    let resolved = sync_and_get_room(client, room).await?;
    let (task, _event_id) = read_task_state(&resolved, task_id)
        .await?
        .ok_or_else(|| WorkspaceError::TaskNotFound(task_id.to_string()))?;

    // Cancelling an already-finished task is a no-op; never reopen a terminal task.
    if is_terminal(&task.state) {
        return Ok(task);
    }

    // Drive the linked remote invocation to cancelled (signed/trust/ownership
    // checked by the target). A task with no published invocation state is
    // finalized cancelled without a remote cancel.
    let invocation = match &task.invocation_id {
        Some(invocation_id) => {
            match cancel_invocation(client, signing_key, key_id, room, invocation_id, reason).await
            {
                Ok(invocation) => Some(invocation),
                Err(WorkspaceError::InvocationNotFound(_)) => None,
                Err(err) => return Err(err),
            }
        }
        None => None,
    };

    let completed_by = client.user_id().map(|u| u.to_string()).unwrap_or_default();
    let (terminal, result) =
        cancel_finalization(invocation.as_ref(), &task, &completed_by, now_rfc3339());

    let options = UpdateTaskOptions {
        room: room.to_string(),
        task_id: task_id.to_string(),
        state: Some(terminal.to_string()),
        result: Some(result),
        ..UpdateTaskOptions::default()
    };
    update_task(client, &options).await
}

/// Cancel a task, restoring the authenticated client from `session`.
pub async fn cancel_task_for_session(
    session: &StoredSession,
    signing_key: &SigningKey,
    key_id: &str,
    room: &str,
    task_id: &str,
    reason: &str,
) -> Result<TaskState, WorkspaceError> {
    let client = restore_client(session).await?;
    cancel_task(&client, signing_key, key_id, room, task_id, reason).await
}

/// Read the tasks in an already-synced `room`, applying `options`' filters and
/// sorting by `task_id` for a stable, deterministic ordering.
///
/// Unlike [`list_tasks`] this performs no `/sync`; it reads from the room state
/// already in the client's store. The watch loop ([`crate::watch`]) calls it
/// once per sync to take a fresh snapshot without re-establishing the room.
pub(crate) async fn read_tasks(
    room: &Room,
    options: &ListTasksOptions,
) -> Result<Vec<TaskState>, WorkspaceError> {
    let mut tasks = read_all_task_states(room).await?;
    tasks.retain(|task| matches_filters(task, options));
    tasks.sort_by(|a, b| a.task_id.cmp(&b.task_id));
    Ok(tasks)
}

/// List tasks in a workspace room, optionally filtered by state and assignee.
///
/// Reads every `com.mxagent.task.v1` state event in the room, applies the
/// filters, and sorts by `task_id` for a stable, deterministic ordering.
pub async fn list_tasks(
    client: &Client,
    options: &ListTasksOptions,
) -> Result<Vec<TaskState>, WorkspaceError> {
    let room = sync_and_get_room(client, &options.room).await?;
    read_tasks(&room, options).await
}

/// List tasks in a workspace, restoring the authenticated client from
/// `session`.
pub async fn list_tasks_for_session(
    session: &StoredSession,
    options: &ListTasksOptions,
) -> Result<Vec<TaskState>, WorkspaceError> {
    let client = restore_client(session).await?;
    list_tasks(&client, options).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn create_opts() -> CreateTaskOptions {
        CreateTaskOptions {
            room: "!room:server".to_string(),
            task_id: None,
            title: "Run API tests".to_string(),
            description: "Run npm test after applying latest diff".to_string(),
            state: None,
            assigned_to: "developer-pi".to_string(),
            created_by: Some("claude-local".to_string()),
            depends_on: vec!["task-plan".to_string()],
            blocks: vec!["task-review".to_string()],
            action: None,
        }
    }

    // ── Issue #302: daemon-side signing of CLI-authored task actions ────────────

    use crate::task_orchestrator::verify_task_action_signature;
    use mx_agent_protocol::schema::TaskActionAuthorization;

    /// A throwaway data dir holding a fresh daemon signing key, removed on drop.
    struct SigningFixture {
        key: DaemonSigningKey,
        dir: std::path::PathBuf,
    }

    impl Drop for SigningFixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    /// Build a fresh signing key in an isolated data dir without mutating the
    /// process environment (`for_data_dir`), so parallel tests do not race.
    fn signing_fixture(tag: &str) -> SigningFixture {
        let dir = std::env::temp_dir().join(format!(
            "mx-agent-task-sign-{}-{}-{}",
            tag,
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let paths = SessionPaths::for_data_dir(dir.clone());
        paths.ensure_data_dir().unwrap();
        let key = load_or_create_signing_key(&paths).unwrap();
        SigningFixture { key, dir }
    }

    fn exec_action(authorization: Option<TaskActionAuthorization>) -> TaskAction {
        TaskAction::Exec {
            command: vec!["sh".to_string(), "-c".to_string(), "exit 0".to_string()],
            cwd: "/repo".to_string(),
            env: Default::default(),
            timeout_ms: Some(60_000),
            stream: false,
            authorization,
        }
    }

    #[test]
    fn authored_authorization_signs_actionable_assigned_unsigned_action() {
        let fx = signing_fixture("signs");
        let signed = authored_authorization(
            &fx.key,
            "task_T",
            &exec_action(None),
            "@planner:server",
            "developer-pi",
        )
        .expect("signing succeeds")
        .expect("an actionable, assigned, unsigned action is signed");

        let auth = signed.authorization().expect("authorization attached");
        assert_eq!(
            auth.target_agent, "developer-pi",
            "addressed to the assignee"
        );
        assert_eq!(auth.requesting_agent, "@planner:server");
        assert!(!auth.nonce.is_empty(), "a fresh nonce is attached");
        assert!(
            auth.expires_at > auth.created_at,
            "expiry must be after creation: {} !> {}",
            auth.expires_at,
            auth.created_at
        );
        assert_eq!(
            auth.signature.key_id,
            fx.key.key_id(),
            "signed with the daemon key"
        );
        // The daemon-authored signature verifies against the daemon verifying key
        // for this exact task id — the production scheduler will admit it.
        verify_task_action_signature(&fx.key.verifying_key(), "task_T", &signed, auth)
            .expect("daemon-authored signature must verify");
    }

    #[test]
    fn authored_authorization_leaves_presigned_and_unassigned_untouched() {
        let fx = signing_fixture("untouched");
        // A pre-signed action (e.g. a manually-signed test action) is honored
        // exactly as supplied — the daemon never overwrites an existing signature.
        let presigned = authored_authorization(
            &fx.key,
            "task_T",
            &exec_action(None),
            "@planner:server",
            "developer-pi",
        )
        .unwrap()
        .unwrap();
        assert!(
            authored_authorization(
                &fx.key,
                "task_T",
                &presigned,
                "@planner:server",
                "developer-pi"
            )
            .unwrap()
            .is_none(),
            "a pre-signed action is left untouched"
        );

        // An unassigned actionable task cannot be addressed yet; left advisory.
        assert!(
            authored_authorization(&fx.key, "task_T", &exec_action(None), "@planner:server", "")
                .unwrap()
                .is_none(),
            "an unassigned action stays unsigned"
        );
    }

    #[test]
    fn authored_authorization_binds_the_task_id() {
        // Guards the auto-id-resolution trap: a signature minted for one task id
        // must not verify when bound to a different id.
        let fx = signing_fixture("bind");
        let signed =
            authored_authorization(&fx.key, "task_T", &exec_action(None), "@p", "developer-pi")
                .unwrap()
                .unwrap();
        let auth = signed.authorization().unwrap();
        assert!(
            verify_task_action_signature(&fx.key.verifying_key(), "task_OTHER", &signed, auth)
                .is_err(),
            "a signature bound to task_T must not verify for task_OTHER"
        );
    }

    #[test]
    fn task_auth_ttl_reads_env_override_and_falls_back() {
        struct EnvGuard;
        impl Drop for EnvGuard {
            fn drop(&mut self) {
                std::env::remove_var(ENV_TASK_AUTH_TTL);
            }
        }
        let _guard = EnvGuard;

        std::env::set_var(ENV_TASK_AUTH_TTL, "3600");
        assert_eq!(task_auth_ttl(), Duration::from_secs(3600));
        // Unparseable and non-positive values fall back to the bounded default.
        std::env::set_var(ENV_TASK_AUTH_TTL, "not-a-number");
        assert_eq!(task_auth_ttl(), TASK_AUTH_TTL);
        std::env::set_var(ENV_TASK_AUTH_TTL, "0");
        assert_eq!(task_auth_ttl(), TASK_AUTH_TTL);
    }

    #[test]
    fn lifecycle_helpers_classify_states() {
        assert!(is_known_state(STATE_PROPOSED));
        assert!(is_known_state(STATE_PENDING));
        assert!(is_known_state(STATE_ASSIGNED));
        assert!(is_known_state(STATE_EXECUTING));
        assert!(is_known_state(STATE_SUCCEEDED));
        assert!(is_known_state(STATE_FAILED));
        assert!(is_known_state(STATE_CANCELLED));
        assert!(is_known_state(STATE_BLOCKED));
        assert!(is_known_state(STATE_SUPERSEDED));
        assert!(!is_known_state("unknown"));

        assert!(is_runnable(STATE_PENDING));
        assert!(is_runnable(STATE_ASSIGNED));
        assert!(!is_runnable(STATE_EXECUTING));
        assert!(!is_runnable(STATE_SUCCEEDED));

        assert!(!is_terminal(STATE_PROPOSED));
        assert!(!is_terminal(STATE_PENDING));
        assert!(is_terminal(STATE_SUCCEEDED));
        assert!(is_terminal(STATE_FAILED));
        assert!(is_terminal(STATE_CANCELLED));
        assert!(is_terminal(STATE_SUPERSEDED));
    }

    #[test]
    fn lifecycle_transitions_match_architecture_state_machine() {
        assert!(can_transition(STATE_PROPOSED, STATE_PENDING));
        assert!(can_transition(STATE_PENDING, STATE_ASSIGNED));
        assert!(can_transition(STATE_ASSIGNED, STATE_EXECUTING));
        // The scheduler claims a pending task straight to executing.
        assert!(can_transition(STATE_PENDING, STATE_EXECUTING));
        assert!(can_transition(STATE_EXECUTING, STATE_SUCCEEDED));
        assert!(can_transition(STATE_EXECUTING, STATE_FAILED));
        assert!(can_transition(STATE_EXECUTING, STATE_CANCELLED));
        assert!(can_transition(STATE_BLOCKED, STATE_PENDING));
        assert!(can_transition(STATE_PENDING, STATE_PENDING));

        assert!(!can_transition(STATE_PENDING, STATE_SUCCEEDED));
        assert!(!can_transition(STATE_SUCCEEDED, STATE_PENDING));
        assert!(!can_transition(STATE_FAILED, STATE_EXECUTING));
        assert!(!can_transition("unknown", STATE_PENDING));
        assert!(!can_transition(STATE_PENDING, "unknown"));
    }

    #[test]
    fn transition_validation_reports_unknown_and_invalid_states() {
        let unknown =
            check_known_state("unknown").expect_err("unknown lifecycle states should be rejected");
        assert!(matches!(unknown, WorkspaceError::InvalidTaskState(state) if state == "unknown"));

        let invalid = check_transition("task_abc", STATE_SUCCEEDED, STATE_PENDING)
            .expect_err("terminal tasks must not be reopened");
        assert!(matches!(
            invalid,
            WorkspaceError::InvalidTaskTransition { task_id, from, to }
                if task_id == "task_abc" && from == STATE_SUCCEEDED && to == STATE_PENDING
        ));
    }

    #[test]
    fn unix_to_rfc3339_formats_known_instants() {
        assert_eq!(unix_to_rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(unix_to_rfc3339(1_748_865_600), "2025-06-02T12:00:00Z");
    }

    #[test]
    fn new_task_defaults_to_pending_with_rev_one() {
        let opts = create_opts();
        let task = build_new_task(
            &opts,
            "task_abc".to_string(),
            "claude-local".to_string(),
            "2026-06-02T12:00:00Z".to_string(),
        );
        assert_eq!(task.task_id, "task_abc");
        assert_eq!(task.state, DEFAULT_TASK_STATE);
        assert_eq!(task.assigned_to, "developer-pi");
        assert_eq!(task.created_by, "claude-local");
        assert_eq!(task.depends_on, vec!["task-plan".to_string()]);
        assert_eq!(task.state_rev, 1);
        assert_eq!(task.created_at, task.updated_at);
        assert!(task.previous_event_id.is_none());
        assert!(task.result.is_none());
        assert!(task.action.is_none());
    }

    #[test]
    fn new_task_honors_action() {
        let mut opts = create_opts();
        opts.action = Some(TaskAction::Tool {
            tool: "run_tests".to_string(),
            args: json!({ "package": "api" }),
            authorization: None,
        });
        let task = build_new_task(
            &opts,
            "task_abc".to_string(),
            "me".to_string(),
            "t".to_string(),
        );
        assert_eq!(task.action, opts.action);
    }

    #[test]
    fn new_task_honors_explicit_state() {
        let mut opts = create_opts();
        opts.state = Some("proposed".to_string());
        let task = build_new_task(
            &opts,
            "task_abc".to_string(),
            "me".to_string(),
            "t".to_string(),
        );
        assert_eq!(task.state, "proposed");
    }

    #[test]
    fn update_overwrites_only_supplied_fields_and_bumps_rev() {
        let mut task = build_new_task(
            &create_opts(),
            "task_abc".to_string(),
            "claude-local".to_string(),
            "2026-06-02T12:00:00Z".to_string(),
        );
        let update = UpdateTaskOptions {
            room: "!room:server".to_string(),
            task_id: "task_abc".to_string(),
            state: Some("executing".to_string()),
            assigned_to: None,
            title: None,
            description: None,
            invocation_id: Some("inv_01HZ".to_string()),
            result: None,
            action: None,
            expected_state_rev: None,
        };
        apply_update(
            &mut task,
            &update,
            "2026-06-02T12:01:12Z".to_string(),
            Some("$event".to_string()),
        );
        assert_eq!(task.state, "executing");
        // Untouched fields are preserved.
        assert_eq!(task.title, "Run API tests");
        assert_eq!(task.assigned_to, "developer-pi");
        assert_eq!(task.invocation_id.as_deref(), Some("inv_01HZ"));
        assert_eq!(task.state_rev, 2);
        assert_eq!(task.updated_at, "2026-06-02T12:01:12Z");
        assert_eq!(task.previous_event_id.as_deref(), Some("$event"));
    }

    #[test]
    fn update_can_attach_a_result() {
        let mut task = build_new_task(
            &create_opts(),
            "task_abc".to_string(),
            "me".to_string(),
            "t".to_string(),
        );
        let mut update = UpdateTaskOptions {
            task_id: "task_abc".to_string(),
            ..Default::default()
        };
        update.state = Some("succeeded".to_string());
        update.result = Some(json!({ "exit_code": 0 }));
        apply_update(&mut task, &update, "t2".to_string(), None);
        assert_eq!(task.state, "succeeded");
        assert_eq!(task.result, Some(json!({ "exit_code": 0 })));
    }

    #[test]
    fn update_can_replace_action() {
        let mut task = build_new_task(
            &create_opts(),
            "task_abc".to_string(),
            "me".to_string(),
            "t".to_string(),
        );
        let mut update = UpdateTaskOptions {
            task_id: "task_abc".to_string(),
            ..Default::default()
        };
        update.action = Some(TaskAction::Exec {
            command: vec!["cargo".to_string(), "test".to_string()],
            cwd: "/repo".to_string(),
            env: Default::default(),
            timeout_ms: Some(600_000),
            stream: true,
            authorization: None,
        });
        apply_update(&mut task, &update, "t2".to_string(), None);
        assert_eq!(task.action, update.action);
    }

    #[test]
    fn check_not_stale_passes_when_expectation_omitted_or_matches() {
        // No expectation: unconditional update is always allowed.
        assert!(check_not_stale("task_abc", 4, None).is_ok());
        // Matching expectation: the caller's view is current.
        assert!(check_not_stale("task_abc", 4, Some(4)).is_ok());
    }

    #[test]
    fn stale_update_is_detected_and_reports_both_revisions() {
        // Caller read the task at rev 1, but a peer has since advanced it to
        // rev 3. The update must be rejected rather than clobbering rev 3.
        let err = check_not_stale("task_abc", 3, Some(1))
            .expect_err("an update based on an older revision must be rejected");
        match err {
            WorkspaceError::StaleTaskUpdate {
                task_id,
                expected,
                current,
            } => {
                assert_eq!(task_id, "task_abc");
                assert_eq!(expected, 1);
                assert_eq!(current, 3);
            }
            other => panic!("expected StaleTaskUpdate, got {other:?}"),
        }
    }

    #[test]
    fn newer_state_is_not_overwritten_silently() {
        // Two callers both read the task at rev 1. The first update lands,
        // bumping it to rev 2. The second caller still expects rev 1, so its
        // update is refused: the newer state survives untouched.
        let mut task = build_new_task(
            &create_opts(),
            "task_abc".to_string(),
            "claude-local".to_string(),
            "2026-06-02T12:00:00Z".to_string(),
        );
        assert_eq!(task.state_rev, 1);

        // First writer succeeds: rev 1 -> 2.
        check_not_stale(&task.task_id, task.state_rev, Some(1))
            .expect("first update from rev 1 should be accepted");
        let first = UpdateTaskOptions {
            state: Some("executing".to_string()),
            expected_state_rev: Some(1),
            ..Default::default()
        };
        apply_update(&mut task, &first, "2026-06-02T12:01:00Z".to_string(), None);
        assert_eq!(task.state_rev, 2);
        assert_eq!(task.state, "executing");

        // Second writer is working from the now-stale rev 1 and is rejected;
        // the executing state from the first writer is preserved.
        let err = check_not_stale(&task.task_id, task.state_rev, Some(1))
            .expect_err("second update from the stale rev 1 must be rejected");
        assert!(matches!(err, WorkspaceError::StaleTaskUpdate { .. }));
        assert_eq!(task.state, "executing");
        assert_eq!(task.state_rev, 2);
    }

    fn task_with(task_id: &str, state: &str, assigned_to: &str) -> TaskState {
        let mut opts = create_opts();
        opts.state = Some(state.to_string());
        opts.assigned_to = assigned_to.to_string();
        build_new_task(
            &opts,
            task_id.to_string(),
            "me".to_string(),
            "t".to_string(),
        )
    }

    #[test]
    fn task_mutation_reply_flattens_task_and_adds_event_id_anchor() {
        // Issue #367: the task.create/update reply must carry the emitted event
        // id as a top-level audit anchor, alongside (not replacing) the flattened
        // task fields and the existing previous_event_id.
        let mut task = task_with("task_anchor", "pending", "developer-pi");
        task.previous_event_id = Some("$prev:server".to_string());
        let reply = TaskMutation {
            task,
            event_id: "$emitted:server".to_string(),
        };
        let v = serde_json::to_value(&reply).expect("serializes");

        // Task fields are flattened to the top level (no nested "task" object),
        // so the reply is the prior TaskState shape with one added field.
        assert_eq!(v["task_id"], "task_anchor");
        assert_eq!(v["state"], "pending");
        assert_eq!(v["assigned_to"], "developer-pi");
        assert!(
            v.get("task").is_none(),
            "task fields must be flattened, not nested"
        );

        // The new audit anchor is the emitted event id, and it coexists with
        // previous_event_id (the prior revision's id) rather than replacing it.
        assert_eq!(v["event_id"], "$emitted:server");
        assert_eq!(v["previous_event_id"], "$prev:server");

        // The reply still deserializes into a bare TaskState (the extra event_id
        // lands in TaskState's flatten `extra`), so the CLI — which parses the
        // reply as TaskState — keeps working.
        let as_task: TaskState = serde_json::from_value(v).expect("deserializes as TaskState");
        assert_eq!(as_task.task_id, "task_anchor");
    }

    #[test]
    fn filters_match_state_and_assignee() {
        let task = task_with("task_a", "pending", "developer-pi");

        // No filters: always matches.
        assert!(matches_filters(&task, &ListTasksOptions::default()));

        // State filter.
        assert!(matches_filters(
            &task,
            &ListTasksOptions {
                state: Some("pending".to_string()),
                ..Default::default()
            }
        ));
        assert!(!matches_filters(
            &task,
            &ListTasksOptions {
                state: Some("executing".to_string()),
                ..Default::default()
            }
        ));

        // Assignee filter.
        assert!(matches_filters(
            &task,
            &ListTasksOptions {
                assigned_to: Some("developer-pi".to_string()),
                ..Default::default()
            }
        ));
        assert!(!matches_filters(
            &task,
            &ListTasksOptions {
                assigned_to: Some("other".to_string()),
                ..Default::default()
            }
        ));

        // Both filters are AND-combined.
        assert!(matches_filters(
            &task,
            &ListTasksOptions {
                state: Some("pending".to_string()),
                assigned_to: Some("developer-pi".to_string()),
                ..Default::default()
            }
        ));
        assert!(!matches_filters(
            &task,
            &ListTasksOptions {
                state: Some("pending".to_string()),
                assigned_to: Some("other".to_string()),
                ..Default::default()
            }
        ));
    }

    fn invocation(state: &str, exit_code: Option<i32>) -> InvocationState {
        InvocationState {
            invocation_id: "inv_1".to_string(),
            task_id: Some("task_a".to_string()),
            requester: "@planner:server".to_string(),
            target: "developer-pi".to_string(),
            state: state.to_string(),
            created_at: "2026-06-04T18:00:00Z".to_string(),
            updated_at: "2026-06-04T18:00:00Z".to_string(),
            exit_code,
            state_rev: 2,
            extra: Default::default(),
        }
    }

    #[test]
    fn cancel_finalization_uses_cancelled_invocation_outcome() {
        let task = task_with("task_a", STATE_EXECUTING, "developer-pi");
        let inv = invocation(STATE_CANCELLED, None);
        let (state, result) = cancel_finalization(Some(&inv), &task, "developer-pi", "now".into());
        assert_eq!(state, STATE_CANCELLED);
        assert_eq!(
            result.get("status").and_then(Value::as_str),
            Some("cancelled")
        );
        assert_eq!(
            result.get("invocation_id").and_then(Value::as_str),
            Some("inv_1")
        );
        assert_eq!(
            result.get("reason").and_then(Value::as_str),
            Some("cancelled")
        );
    }

    #[test]
    fn cancel_finalization_reconciles_already_finished_invocation() {
        // The invocation already succeeded before the cancel reached it; reconcile
        // the task to the real outcome rather than a misleading `cancelled`.
        let task = task_with("task_a", STATE_EXECUTING, "developer-pi");
        let inv = invocation(STATE_SUCCEEDED, Some(0));
        let (state, result) = cancel_finalization(Some(&inv), &task, "developer-pi", "now".into());
        assert_eq!(state, STATE_SUCCEEDED);
        assert_eq!(
            result.get("status").and_then(Value::as_str),
            Some("succeeded")
        );
        assert_eq!(result.get("exit_code").and_then(Value::as_i64), Some(0));
    }

    #[test]
    fn cancel_finalization_without_invocation_is_minimal_cancelled() {
        let mut task = task_with("task_a", STATE_EXECUTING, "developer-pi");
        task.invocation_id = Some("inv_x".to_string());
        let (state, result) = cancel_finalization(None, &task, "developer-pi", "now".into());
        assert_eq!(state, STATE_CANCELLED);
        assert_eq!(
            result.get("status").and_then(Value::as_str),
            Some("cancelled")
        );
        assert_eq!(
            result.get("invocation_id").and_then(Value::as_str),
            Some("inv_x")
        );
        assert_eq!(
            result.get("reason").and_then(Value::as_str),
            Some("cancelled")
        );
        assert_eq!(
            result.get("summary").and_then(Value::as_str),
            Some("task cancelled")
        );
    }

    // ── Update-path signing rules (issue #302) ─────────────────────────────────
    // These tests exercise the signing decision logic that lives in
    // update_task_with_signing by calling the underlying authored_authorization
    // helper directly — no live Matrix client is required.

    #[test]
    fn authored_authorization_signs_tool_action() {
        // Both TaskAction variants must be signable; the existing tests only cover
        // Exec. Verify Tool actions are signed and verifiable via the daemon key.
        let fx = signing_fixture("tool-action");
        let tool_action = TaskAction::Tool {
            tool: "run_tests".to_string(),
            args: json!({ "suite": "unit" }),
            authorization: None,
        };
        let signed = authored_authorization(
            &fx.key,
            "task_T",
            &tool_action,
            "@planner:server",
            "developer-pi",
        )
        .expect("signing succeeds")
        .expect("a Tool action gets a signed authorization");

        let auth = signed.authorization().expect("authorization attached");
        assert_eq!(auth.target_agent, "developer-pi");
        verify_task_action_signature(&fx.key.verifying_key(), "task_T", &signed, auth)
            .expect("Tool action signature must verify against the daemon key");
    }

    #[test]
    fn update_reassignment_resigns_existing_action_to_new_target() {
        // update_task_with_signing strips the old auth and re-signs when only the
        // assignee changes (no new action body). A signature addressed to "old-agent"
        // would be rejected by the verifier as `wrong_target` if it reached
        // "new-agent". Re-signing after stripping produces a fresh nonce for the
        // new target.
        let fx = signing_fixture("reassign");

        let old_signed = authored_authorization(
            &fx.key,
            "task_T",
            &exec_action(None),
            "@planner:server",
            "old-agent",
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            old_signed.authorization().unwrap().target_agent,
            "old-agent"
        );

        // On reassignment, the existing auth is stripped before re-signing so that
        // authored_authorization signs rather than short-circuiting on the old sig.
        let stripped = old_signed.without_authorization();
        assert!(
            stripped.authorization().is_none(),
            "auth must be stripped before re-signing"
        );

        let resigned =
            authored_authorization(&fx.key, "task_T", &stripped, "@planner:server", "new-agent")
                .expect("re-signing must succeed")
                .expect("reassignment produces a new signed authorization");

        let auth = resigned.authorization().unwrap();
        assert_eq!(
            auth.target_agent, "new-agent",
            "re-signed to the new assignee"
        );
        assert_ne!(
            old_signed.authorization().unwrap().nonce,
            auth.nonce,
            "re-signing mints a fresh nonce"
        );
        verify_task_action_signature(&fx.key.verifying_key(), "task_T", &resigned, auth)
            .expect("re-signed authorization must verify for the new target");
    }

    #[test]
    fn update_new_action_signed_to_effective_assignee() {
        // When an update carries a new action body but no new assigned_to, the
        // effective assignee is the task's existing assignee. The new action must
        // be signed to that agent so the scheduler admits it.
        let fx = signing_fixture("new-action-update");

        let new_action = exec_action(None);
        // effective_assignee = current task's assigned_to (no new assigned_to in opts)
        let effective_assignee = "developer-pi";
        let signed = authored_authorization(
            &fx.key,
            "task_T",
            &new_action,
            "@planner:server",
            effective_assignee,
        )
        .expect("signing the new action succeeds")
        .expect("new action on update is signed to the effective assignee");

        let auth = signed.authorization().unwrap();
        assert_eq!(auth.target_agent, effective_assignee);
        verify_task_action_signature(&fx.key.verifying_key(), "task_T", &signed, auth)
            .expect("new action signed on update must verify");
    }

    #[test]
    fn state_only_update_preserves_existing_action_signature() {
        // A state/title/invocation/result-only update (action = None, assigned_to =
        // None) must leave the action and its signed authorization completely
        // untouched. apply_update only writes the action field when options.action
        // is Some; this test confirms the existing signature round-trips.
        let fx = signing_fixture("state-only");

        let signed_action = authored_authorization(
            &fx.key,
            "task_T",
            &exec_action(None),
            "@planner:server",
            "developer-pi",
        )
        .unwrap()
        .unwrap();
        let original_nonce = signed_action.authorization().unwrap().nonce.clone();

        let mut opts = create_opts();
        opts.action = Some(signed_action);
        let mut task = build_new_task(
            &opts,
            "task_T".to_string(),
            "claude-local".to_string(),
            "t0".to_string(),
        );

        // State-only update: neither action nor assigned_to is set.
        let update = UpdateTaskOptions {
            task_id: "task_T".to_string(),
            state: Some(STATE_EXECUTING.to_string()),
            ..Default::default()
        };
        apply_update(&mut task, &update, "t1".to_string(), None);

        let preserved = task.action.as_ref().unwrap().authorization().unwrap();
        assert_eq!(
            preserved.nonce, original_nonce,
            "a state-only update must not alter the action authorization"
        );
        assert_eq!(preserved.target_agent, "developer-pi");
    }

    #[test]
    fn presigned_action_on_update_path_is_left_unchanged() {
        // When the caller supplies an already-signed action on task.update, the
        // daemon must not overwrite it. authored_authorization returns None for a
        // pre-signed action, so the update path leaves the caller-provided
        // authorization in place. This is the compatibility hinge that keeps
        // signed_exec_task and other manually-signed test helpers green.
        let fx = signing_fixture("presigned-update");

        let presigned = authored_authorization(
            &fx.key,
            "task_T",
            &exec_action(None),
            "@planner:server",
            "developer-pi",
        )
        .unwrap()
        .unwrap();
        let original_nonce = presigned.authorization().unwrap().nonce.clone();

        // Passing the pre-signed action to authored_authorization returns None.
        let result = authored_authorization(
            &fx.key,
            "task_T",
            &presigned,
            "@planner:server",
            "developer-pi",
        )
        .expect("no error for a pre-signed action");
        assert!(
            result.is_none(),
            "a pre-signed action submitted on the update path must not be overwritten"
        );
        // Original authorization is unchanged.
        assert_eq!(presigned.authorization().unwrap().nonce, original_nonce);
    }

    // ── Issue #308: plaintext-in-state exec env tests ─────────────────────────

    #[test]
    fn build_new_task_preserves_exec_action_with_non_empty_env() {
        // The exec action (including env) is published as `com.mxagent.task.v1`
        // state, which is plaintext readable even in an `--e2ee on` workspace
        // (issue #308). The daemon must publish exactly the env the requester
        // supplied — neither dropping keys nor injecting extras.
        let mut env = std::collections::BTreeMap::new();
        env.insert("CI".to_string(), "1".to_string());
        env.insert("NODE_ENV".to_string(), "test".to_string());
        let mut opts = create_opts();
        opts.action = Some(TaskAction::Exec {
            command: vec!["npm".to_string(), "test".to_string()],
            cwd: "/repo".to_string(),
            env: env.clone(),
            timeout_ms: Some(60_000),
            stream: false,
            authorization: None,
        });
        let task = build_new_task(
            &opts,
            "task_env".to_string(),
            "claude-local".to_string(),
            "2026-06-12T10:00:00Z".to_string(),
        );
        let action = task.action.expect("task must carry the exec action");
        if let TaskAction::Exec {
            env: task_env,
            command,
            cwd,
            ..
        } = action
        {
            assert_eq!(
                task_env, env,
                "task action env must be preserved as published"
            );
            assert_eq!(command, vec!["npm", "test"]);
            assert_eq!(cwd, "/repo");
        } else {
            panic!("expected Exec action in built task");
        }
    }

    #[test]
    fn apply_update_replaces_exec_action_preserving_env() {
        // When a task update supplies a new exec action (e.g. to change the
        // cwd or timeout), the replacement action — including its env — must be
        // stored exactly as supplied. The env is later serialized into the
        // plaintext state event (issue #308); dropping or modifying it would
        // cause the scheduler to run with wrong environment variables.
        let mut task = build_new_task(
            &create_opts(),
            "task_update_env".to_string(),
            "me".to_string(),
            "t1".to_string(),
        );
        let mut new_env = std::collections::BTreeMap::new();
        new_env.insert("DEPLOY_ENV".to_string(), "staging".to_string());
        let new_action = TaskAction::Exec {
            command: vec!["./deploy.sh".to_string()],
            cwd: "/opt/app".to_string(),
            env: new_env.clone(),
            timeout_ms: Some(120_000),
            stream: false,
            authorization: None,
        };
        let update = UpdateTaskOptions {
            task_id: "task_update_env".to_string(),
            action: Some(new_action),
            ..Default::default()
        };
        apply_update(&mut task, &update, "t2".to_string(), None);

        let stored = task.action.expect("action must be set after update");
        if let TaskAction::Exec {
            env: stored_env, ..
        } = stored
        {
            assert_eq!(
                stored_env, new_env,
                "exec env must be preserved after action replacement"
            );
        } else {
            panic!("expected Exec action after update");
        }
    }
}
