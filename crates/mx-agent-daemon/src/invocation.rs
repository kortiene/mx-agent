//! Invocation state tracking: advancing and reading `com.mxagent.invocation.v1`
//! room state.
//!
//! An invocation is a durable record of one remote call/exec, tracked in a
//! workspace room as a `com.mxagent.invocation.v1` state event keyed by its
//! `invocation_id` (see `docs/architecture.md`, sections 5 and 9). Its `state`
//! field advances through a lifecycle — `accepted -> running ->
//! {succeeded, failed, cancelled}` — and it carries the owning `task_id` so
//! peers can link work back to the task DAG.
//!
//! Publishing the *initial* record lives with the exec protocol
//! ([`crate::exec::invocation_state_for`] + [`crate::exec::publish_invocation_state`]);
//! this module adds the lifecycle transitions and the read/list queries that
//! back `mx-agent invocation list`.
//!
//! Because Matrix room state is last-write-wins per `(type, state_key)`,
//! advancing an invocation republishes its state key in place. The prior
//! `state_rev` is read first so the counter advances monotonically.

use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use matrix_sdk::config::SyncSettings;
use matrix_sdk::ruma::events::StateEventType;
use matrix_sdk::{Client, Room};
use mx_agent_protocol::events::state::INVOCATION as INVOCATION_STATE_TYPE;
use mx_agent_protocol::schema::InvocationState;

use crate::exec::{publish_invocation_state, send_exec_cancel};
use crate::matrix::restore_client;
use crate::session::StoredSession;
use crate::workspace::{parse_room_or_alias, resolve_room_id, WorkspaceError};

/// Lifecycle state of an invocation the target agent has accepted but not yet
/// started running (set by [`crate::exec::invocation_state_for`]).
pub const STATE_ACCEPTED: &str = "accepted";
/// The invocation's process is running.
pub const STATE_RUNNING: &str = "running";
/// The invocation finished successfully (exit code 0).
pub const STATE_SUCCEEDED: &str = "succeeded";
/// The invocation finished with a non-zero exit code or an error.
pub const STATE_FAILED: &str = "failed";
/// The invocation was cancelled before completion.
pub const STATE_CANCELLED: &str = "cancelled";

/// Return `true` when `state` is terminal (admits no further transitions).
pub fn is_terminal(state: &str) -> bool {
    state == STATE_SUCCEEDED || state == STATE_FAILED || state == STATE_CANCELLED
}

/// Map a process exit code to a terminal lifecycle state: `0` is
/// [`STATE_SUCCEEDED`], anything else is [`STATE_FAILED`].
pub fn terminal_state_for_exit(exit_code: i32) -> &'static str {
    if exit_code == 0 {
        STATE_SUCCEEDED
    } else {
        STATE_FAILED
    }
}

/// Options for [`list_invocations`].
#[derive(Debug, Clone, Default)]
pub struct ListInvocationsOptions {
    /// Room ID or alias to list invocations in.
    pub room: String,
    /// Only include invocations in this lifecycle state. `None` means
    /// "no filter".
    pub state: Option<String>,
    /// Only include invocations linked to this task ID. `None` means
    /// "no filter".
    pub task_id: Option<String>,
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

/// Advance an invocation to a new lifecycle `state` in place: overwrite the
/// state, advance `state_rev`, refresh `updated_at`, and record `exit_code`
/// when finishing.
///
/// `exit_code` is recorded only when supplied (typically alongside a terminal
/// state); passing `None` leaves any previous exit code untouched.
fn apply_transition(
    invocation: &mut InvocationState,
    state: &str,
    exit_code: Option<i32>,
    now: String,
) {
    invocation.state = state.to_string();
    if let Some(code) = exit_code {
        invocation.exit_code = Some(code);
    }
    invocation.state_rev += 1;
    invocation.updated_at = now;
}

/// Return `true` when `invocation` passes the (optional) state and task filters.
fn matches_filters(invocation: &InvocationState, options: &ListInvocationsOptions) -> bool {
    options
        .state
        .as_deref()
        .map_or(true, |s| invocation.state == s)
        && options
            .task_id
            .as_deref()
            .map_or(true, |t| invocation.task_id.as_deref() == Some(t))
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

/// Read the `com.mxagent.invocation.v1` state event for `invocation_id`.
///
/// Returns `Ok(None)` when no invocation with that ID exists in the room.
async fn read_invocation_state(
    room: &Room,
    invocation_id: &str,
) -> Result<Option<InvocationState>, WorkspaceError> {
    use matrix_sdk::deserialized_responses::RawAnySyncOrStrippedState as RawState;

    let raw = room
        .get_state_event(StateEventType::from(INVOCATION_STATE_TYPE), invocation_id)
        .await
        .map_err(WorkspaceError::from)?;

    let content = match raw {
        Some(RawState::Sync(raw)) => raw.get_field::<InvocationState>("content"),
        Some(RawState::Stripped(raw)) => raw.get_field::<InvocationState>("content"),
        None => return Ok(None),
    };
    content.map_err(|e| WorkspaceError::from(matrix_sdk::Error::SerdeJson(e)))
}

/// Read every `com.mxagent.invocation.v1` state event from a room.
async fn read_all_invocation_states(room: &Room) -> Result<Vec<InvocationState>, WorkspaceError> {
    use matrix_sdk::deserialized_responses::RawAnySyncOrStrippedState as RawState;

    let raws = room
        .get_state_events(StateEventType::from(INVOCATION_STATE_TYPE))
        .await
        .map_err(WorkspaceError::from)?;

    let mut invocations = Vec::with_capacity(raws.len());
    for raw in raws {
        let content = match raw {
            RawState::Sync(raw) => raw.get_field::<InvocationState>("content"),
            RawState::Stripped(raw) => raw.get_field::<InvocationState>("content"),
        }
        .map_err(|e| WorkspaceError::from(matrix_sdk::Error::SerdeJson(e)))?;
        // A cleared invocation leaves an empty state event behind; skip those.
        if let Some(invocation) = content {
            invocations.push(invocation);
        }
    }
    Ok(invocations)
}

/// Advance an existing invocation to a new lifecycle `state` and republish it.
///
/// Reads the current state, applies the transition (bumping `state_rev` and
/// refreshing `updated_at`), and republishes the `com.mxagent.invocation.v1`
/// state event in place. Returns [`WorkspaceError::InvocationNotFound`] when no
/// invocation with that ID exists in the room.
pub async fn advance_invocation(
    client: &Client,
    room: &str,
    invocation_id: &str,
    state: &str,
    exit_code: Option<i32>,
) -> Result<InvocationState, WorkspaceError> {
    let room = sync_and_get_room(client, room).await?;
    let mut invocation = read_invocation_state(&room, invocation_id)
        .await?
        .ok_or_else(|| WorkspaceError::InvocationNotFound(invocation_id.to_string()))?;

    apply_transition(&mut invocation, state, exit_code, now_rfc3339());
    publish_invocation_state(&room, &invocation).await?;
    Ok(invocation)
}

/// Advance an invocation, restoring the authenticated client from `session`.
pub async fn advance_invocation_for_session(
    session: &StoredSession,
    room: &str,
    invocation_id: &str,
    state: &str,
    exit_code: Option<i32>,
) -> Result<InvocationState, WorkspaceError> {
    let client = restore_client(session).await?;
    advance_invocation(&client, room, invocation_id, state, exit_code).await
}

/// Generate a random, base64-encoded nonce for a signed cancel request.
///
/// A nonce only needs to be unique per request (the signature binds it), so on
/// the astronomically unlikely event the system RNG is unavailable, a
/// high-resolution timestamp is used as a unique fallback rather than failing
/// the cancel.
fn random_nonce() -> String {
    use base64::Engine as _;
    let mut bytes = [0u8; 16];
    if getrandom::getrandom(&mut bytes).is_err() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default();
        bytes.copy_from_slice(&nanos.to_le_bytes());
    }
    base64::engine::general_purpose::STANDARD_NO_PAD.encode(bytes)
}

/// Cancel a running invocation: send a signed `com.mxagent.exec.cancel.v1` into
/// the room and advance the invocation to the `cancelled` state.
///
/// Reads the invocation first: an unknown id is
/// [`WorkspaceError::InvocationNotFound`], and an already-terminal invocation is
/// returned unchanged (cancelling a finished command is a no-op). Otherwise the
/// cancel is signed with the caller's key and sent so it federates to the target
/// agent that runs the command — which verifies ownership
/// ([`crate::exec::authorize_exec_cancel`]), terminates the process group, and
/// confirms with `com.mxagent.exec.cancelled.v1` — and the invocation state is
/// republished as `cancelled`.
pub async fn cancel_invocation(
    client: &Client,
    signing_key: &SigningKey,
    key_id: &str,
    room: &str,
    invocation_id: &str,
    reason: &str,
) -> Result<InvocationState, WorkspaceError> {
    let room = sync_and_get_room(client, room).await?;
    let mut invocation = read_invocation_state(&room, invocation_id)
        .await?
        .ok_or_else(|| WorkspaceError::InvocationNotFound(invocation_id.to_string()))?;

    // Cancelling an already-finished invocation is a no-op.
    if is_terminal(&invocation.state) {
        return Ok(invocation);
    }

    let now = now_rfc3339();
    send_exec_cancel(
        &room,
        signing_key,
        key_id,
        invocation_id,
        reason,
        now.clone(),
        random_nonce(),
    )
    .await?;

    apply_transition(&mut invocation, STATE_CANCELLED, None, now);
    publish_invocation_state(&room, &invocation).await?;
    Ok(invocation)
}

/// Cancel an invocation, restoring the authenticated client from `session`.
pub async fn cancel_invocation_for_session(
    session: &StoredSession,
    signing_key: &SigningKey,
    key_id: &str,
    room: &str,
    invocation_id: &str,
    reason: &str,
) -> Result<InvocationState, WorkspaceError> {
    let client = restore_client(session).await?;
    cancel_invocation(&client, signing_key, key_id, room, invocation_id, reason).await
}

/// List invocations in a workspace room, optionally filtered by state and task.
///
/// Reads every `com.mxagent.invocation.v1` state event in the room, applies the
/// filters, and sorts by `invocation_id` for a stable, deterministic ordering.
pub async fn list_invocations(
    client: &Client,
    options: &ListInvocationsOptions,
) -> Result<Vec<InvocationState>, WorkspaceError> {
    let room = sync_and_get_room(client, &options.room).await?;
    let mut invocations = read_all_invocation_states(&room).await?;
    invocations.retain(|invocation| matches_filters(invocation, options));
    invocations.sort_by(|a, b| a.invocation_id.cmp(&b.invocation_id));
    Ok(invocations)
}

/// List invocations in a workspace, restoring the authenticated client from
/// `session`.
pub async fn list_invocations_for_session(
    session: &StoredSession,
    options: &ListInvocationsOptions,
) -> Result<Vec<InvocationState>, WorkspaceError> {
    let client = restore_client(session).await?;
    list_invocations(&client, options).await
}

/// Fetch a single invocation by ID from a workspace room.
///
/// Returns `Ok(None)` when no invocation with that ID exists.
pub async fn get_invocation(
    client: &Client,
    room: &str,
    invocation_id: &str,
) -> Result<Option<InvocationState>, WorkspaceError> {
    let room = sync_and_get_room(client, room).await?;
    read_invocation_state(&room, invocation_id).await
}

/// Fetch a single invocation, restoring the authenticated client from
/// `session`.
pub async fn get_invocation_for_session(
    session: &StoredSession,
    room: &str,
    invocation_id: &str,
) -> Result<Option<InvocationState>, WorkspaceError> {
    let client = restore_client(session).await?;
    get_invocation(&client, room, invocation_id).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(invocation_id: &str, state: &str, task_id: Option<&str>) -> InvocationState {
        InvocationState {
            invocation_id: invocation_id.to_string(),
            task_id: task_id.map(str::to_string),
            requester: "claude-local".to_string(),
            target: "developer-pi".to_string(),
            state: state.to_string(),
            created_at: "2026-06-02T12:00:00Z".to_string(),
            updated_at: "2026-06-02T12:00:00Z".to_string(),
            exit_code: None,
            state_rev: 0,
            extra: Default::default(),
        }
    }

    #[test]
    fn unix_to_rfc3339_formats_known_instants() {
        assert_eq!(unix_to_rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(unix_to_rfc3339(1_748_865_600), "2025-06-02T12:00:00Z");
    }

    #[test]
    fn random_nonce_is_nonempty_and_distinct() {
        let a = random_nonce();
        let b = random_nonce();
        assert!(!a.is_empty());
        // Base64 of 16 bytes (no padding) is 22 chars.
        assert_eq!(a.len(), 22);
        assert_ne!(a, b, "nonces must differ between requests");
    }

    #[test]
    fn terminal_states_are_recognized() {
        assert!(is_terminal(STATE_SUCCEEDED));
        assert!(is_terminal(STATE_FAILED));
        assert!(is_terminal(STATE_CANCELLED));
        assert!(!is_terminal(STATE_ACCEPTED));
        assert!(!is_terminal(STATE_RUNNING));
    }

    #[test]
    fn exit_code_maps_to_terminal_state() {
        assert_eq!(terminal_state_for_exit(0), STATE_SUCCEEDED);
        assert_eq!(terminal_state_for_exit(1), STATE_FAILED);
        assert_eq!(terminal_state_for_exit(137), STATE_FAILED);
    }

    #[test]
    fn transition_to_running_bumps_rev_and_refreshes_timestamp() {
        let mut inv = sample("inv_01HZ", STATE_ACCEPTED, Some("task_abc"));
        apply_transition(
            &mut inv,
            STATE_RUNNING,
            None,
            "2026-06-02T12:00:05Z".to_string(),
        );
        assert_eq!(inv.state, STATE_RUNNING);
        assert_eq!(inv.state_rev, 1);
        assert_eq!(inv.updated_at, "2026-06-02T12:00:05Z");
        // No exit code on a non-terminal transition.
        assert!(inv.exit_code.is_none());
        // The task link is preserved across transitions.
        assert_eq!(inv.task_id.as_deref(), Some("task_abc"));
    }

    #[test]
    fn transition_to_terminal_records_exit_code() {
        let mut inv = sample("inv_01HZ", STATE_RUNNING, None);
        inv.state_rev = 1;
        apply_transition(
            &mut inv,
            STATE_FAILED,
            Some(1),
            "2026-06-02T12:01:00Z".to_string(),
        );
        assert_eq!(inv.state, STATE_FAILED);
        assert_eq!(inv.exit_code, Some(1));
        assert_eq!(inv.state_rev, 2);
        assert!(is_terminal(&inv.state));
    }

    #[test]
    fn filters_match_state_and_task() {
        let inv = sample("inv_a", STATE_RUNNING, Some("task_abc"));

        // No filters: always matches.
        assert!(matches_filters(&inv, &ListInvocationsOptions::default()));

        // State filter.
        assert!(matches_filters(
            &inv,
            &ListInvocationsOptions {
                state: Some(STATE_RUNNING.to_string()),
                ..Default::default()
            }
        ));
        assert!(!matches_filters(
            &inv,
            &ListInvocationsOptions {
                state: Some(STATE_SUCCEEDED.to_string()),
                ..Default::default()
            }
        ));

        // Task filter.
        assert!(matches_filters(
            &inv,
            &ListInvocationsOptions {
                task_id: Some("task_abc".to_string()),
                ..Default::default()
            }
        ));
        assert!(!matches_filters(
            &inv,
            &ListInvocationsOptions {
                task_id: Some("task_other".to_string()),
                ..Default::default()
            }
        ));

        // Both filters are AND-combined.
        assert!(matches_filters(
            &inv,
            &ListInvocationsOptions {
                state: Some(STATE_RUNNING.to_string()),
                task_id: Some("task_abc".to_string()),
                ..Default::default()
            }
        ));
        assert!(!matches_filters(
            &inv,
            &ListInvocationsOptions {
                state: Some(STATE_RUNNING.to_string()),
                task_id: Some("task_other".to_string()),
                ..Default::default()
            }
        ));
    }

    #[test]
    fn task_filter_excludes_unlinked_invocations() {
        let inv = sample("inv_a", STATE_RUNNING, None);
        assert!(!matches_filters(
            &inv,
            &ListInvocationsOptions {
                task_id: Some("task_abc".to_string()),
                ..Default::default()
            }
        ));
    }
}
