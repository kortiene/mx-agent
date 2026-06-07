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

use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use matrix_sdk::config::SyncSettings;
use matrix_sdk::ruma::events::StateEventType;
use matrix_sdk::{Client, Room};
use mx_agent_protocol::events::state::TASK as TASK_STATE_TYPE;
use mx_agent_protocol::id::generate_task_id;
use mx_agent_protocol::schema::{InvocationState, TaskAction, TaskResult, TaskState};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::invocation::{
    cancel_invocation, task_result_from_invocation, task_state_for_invocation,
};
use crate::matrix::restore_client;
use crate::session::StoredSession;
use crate::workspace::{parse_room_or_alias, resolve_room_id, WorkspaceError};

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
    options.state.as_deref().map_or(true, |s| task.state == s)
        && options
            .assigned_to
            .as_deref()
            .map_or(true, |a| task.assigned_to == a)
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
async fn publish_task_state(
    room: &Room,
    task_id: &str,
    state: &TaskState,
) -> Result<(), WorkspaceError> {
    let content = serde_json::to_value(state)
        .map_err(|e| WorkspaceError::from(matrix_sdk::Error::SerdeJson(e)))?;
    room.send_state_event_raw(TASK_STATE_TYPE, task_id, content)
        .await
        .map_err(WorkspaceError::from)?;
    Ok(())
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
    let room = sync_and_get_room(client, &options.room).await?;

    let task_id = options
        .task_id
        .clone()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(generate_task_id);

    if read_task_state(&room, &task_id).await?.is_some() {
        return Err(WorkspaceError::TaskExists(task_id));
    }

    let created_by = options
        .created_by
        .clone()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| client.user_id().map(|u| u.to_string()).unwrap_or_default());

    let state = build_new_task(options, task_id.clone(), created_by, now_rfc3339());
    check_known_state(&state.state)?;
    publish_task_state(&room, &task_id, &state).await?;
    Ok(state)
}

/// Create a task, restoring the authenticated client from `session`.
pub async fn create_task_for_session(
    session: &StoredSession,
    options: &CreateTaskOptions,
) -> Result<TaskState, WorkspaceError> {
    let client = restore_client(session).await?;
    create_task(&client, options).await
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
    update_task_in_room(&room, options).await
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
) -> Result<TaskState, WorkspaceError> {
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
) -> Result<TaskState, WorkspaceError> {
    check_not_stale(
        &current.task_id,
        current.state_rev,
        options.expected_state_rev,
    )?;
    if let Some(to) = &options.state {
        check_transition(&current.task_id, &current.state, to)?;
    }
    apply_update(&mut current, options, now_rfc3339(), previous_event_id);
    publish_task_state(room, &options.task_id, &current).await?;
    Ok(current)
}

/// Update a task, restoring the authenticated client from `session`.
pub async fn update_task_for_session(
    session: &StoredSession,
    options: &UpdateTaskOptions,
) -> Result<TaskState, WorkspaceError> {
    let client = restore_client(session).await?;
    update_task(&client, options).await
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
}
