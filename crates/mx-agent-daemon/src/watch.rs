//! Live watch loops over workspace room state (architecture §9, §11.3).
//!
//! The one-shot `task list` and `workspace status` commands read room state
//! once and exit. Watch mode keeps a long-lived Matrix `/sync` running and
//! surfaces state changes as they arrive, so an operator sees task transitions
//! and membership changes without rerunning the command.
//!
//! The loop here mirrors the daemon's own sync loop ([`crate::sync`]): it
//! resumes from the batch token returned by each `/sync`, classifies sync
//! errors as fatal (re-auth required) or transient, and retries transient
//! failures with exponential backoff. A transient failure therefore reads as a
//! brief reconnect rather than a crash, satisfying the "watch mode handles
//! reconnect gracefully" acceptance criterion. Unlike the daemon loop the batch
//! token is held in memory only, so a CLI `watch` never disturbs the daemon's
//! persisted sync token.
//!
//! [`run_watch`] is generic over the snapshot it reads each tick, so the same
//! resilient loop drives both `task watch` (a `Vec<TaskState>` snapshot) and
//! `workspace status --watch` (a [`WorkspaceStatus`] snapshot). A snapshot is
//! forwarded to the caller's callback only when it differs from the previous
//! one, so an idle room produces no output.

use std::collections::BTreeMap;
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime};

use matrix_sdk::config::SyncSettings;
use matrix_sdk::{Client, Room};
use mx_agent_protocol::schema::TaskState;
use serde::Serialize;

use crate::matrix::restore_client;
use crate::session::StoredSession;
use crate::sync::{
    is_fatal_sync_error, rate_limit_retry_after, sleep_interruptible, Backoff, BackoffConfig,
};
use crate::task::ListTasksOptions;
use crate::workspace::{
    build_workspace_status, parse_room_or_alias, resolve_room_id, WorkspaceError, WorkspaceStatus,
};

/// Default long-poll timeout for each `/sync` in a watch loop.
///
/// A long timeout keeps the watch responsive (the homeserver returns as soon as
/// there is activity) without busy-polling an idle room.
pub const DEFAULT_WATCH_SYNC_TIMEOUT: Duration = Duration::from_secs(30);

/// Tunable timing for a watch loop.
#[derive(Debug, Clone, Copy)]
pub struct WatchConfig {
    /// Long-poll timeout applied to each `/sync` request.
    pub sync_timeout: Duration,
    /// Exponential backoff applied to transient sync failures so a flaky
    /// network reads as a graceful reconnect rather than a crash.
    pub backoff: BackoffConfig,
}

impl Default for WatchConfig {
    fn default() -> Self {
        Self {
            sync_timeout: DEFAULT_WATCH_SYNC_TIMEOUT,
            backoff: BackoffConfig::default(),
        }
    }
}

/// An update delivered to a watcher's callback.
///
/// Borrows the snapshot it refers to so the callback can render it without a
/// clone. `Initial` carries the baseline read taken before the loop begins;
/// `Changed` fires only when a snapshot differs from the previous one.
#[derive(Debug)]
pub enum WatchUpdate<'a, T> {
    /// The baseline snapshot, emitted once before the live loop starts.
    Initial(&'a T),
    /// The snapshot changed from the previous one.
    Changed {
        /// The snapshot last rendered.
        previous: &'a T,
        /// The new snapshot.
        current: &'a T,
    },
    /// A transient sync failure occurred; the loop will retry after backing off.
    Reconnecting {
        /// Number of consecutive failures so far (1 on the first failure).
        attempt: u32,
        /// Human-readable description of the failure.
        error: String,
    },
    /// A sync succeeded after one or more transient failures.
    Reconnected,
}

/// Watch the tasks in a workspace room, invoking `callback` on each change.
///
/// Reads a baseline task list (filtered by `options`), then keeps syncing and
/// re-reading the room, emitting a [`WatchUpdate`] whenever the task list
/// changes or the connection drops and recovers. Returns when `running` is
/// cleared (a clean shutdown) or a fatal, re-auth-requiring sync error occurs.
pub async fn watch_tasks_for_session<F>(
    session: &StoredSession,
    options: &ListTasksOptions,
    config: WatchConfig,
    running: &AtomicBool,
    callback: F,
) -> Result<(), WorkspaceError>
where
    F: FnMut(WatchUpdate<'_, Vec<TaskState>>),
{
    let client = restore_client(session).await?;
    let room_target = options.room.clone();
    let options = options.clone();
    run_watch(
        &client,
        &room_target,
        config,
        running,
        move |room| {
            let options = options.clone();
            async move { crate::task::read_tasks(&room, &options).await }
        },
        callback,
    )
    .await
}

/// Watch a workspace room's status, invoking `callback` on each change.
///
/// Reads a baseline [`WorkspaceStatus`], then keeps syncing and re-reading the
/// room, emitting a [`WatchUpdate`] whenever the status changes or the
/// connection drops and recovers. Returns when `running` is cleared (a clean
/// shutdown) or a fatal, re-auth-requiring sync error occurs.
pub async fn watch_workspace_status_for_session<F>(
    session: &StoredSession,
    target: &str,
    config: WatchConfig,
    running: &AtomicBool,
    callback: F,
) -> Result<(), WorkspaceError>
where
    F: FnMut(WatchUpdate<'_, WorkspaceStatus>),
{
    let client = restore_client(session).await?;
    run_watch(
        &client,
        target,
        config,
        running,
        |room| async move { build_workspace_status(&room).await },
        callback,
    )
    .await
}

/// Drive a resilient watch loop over a workspace room.
///
/// Resolves `target` once (an unresolvable room fails fast, matching the
/// one-shot commands), takes a baseline snapshot via `read`, then loops:
/// sync, re-read, and emit a [`WatchUpdate::Changed`] when the snapshot moves.
/// Transient sync errors back off and surface as
/// [`WatchUpdate::Reconnecting`]/[`WatchUpdate::Reconnected`]; a fatal sync
/// error stops the loop and is returned.
async fn run_watch<T, R, Fut, F>(
    client: &Client,
    target: &str,
    config: WatchConfig,
    running: &AtomicBool,
    mut read: R,
    mut callback: F,
) -> Result<(), WorkspaceError>
where
    T: PartialEq,
    R: FnMut(Room) -> Fut,
    Fut: Future<Output = Result<T, WorkspaceError>>,
    F: FnMut(WatchUpdate<'_, T>),
{
    let id = parse_room_or_alias(target)?;

    // An initial one-shot sync populates room state (a freshly restored client
    // has none until it has talked to the homeserver once), exactly as the
    // one-shot commands do. Its batch token seeds the live loop below.
    let mut next_batch = client
        .sync_once(SyncSettings::default())
        .await
        .map_err(WorkspaceError::from)?
        .next_batch;

    let room_id = resolve_room_id(client, &id).await?;
    let room = client
        .get_room(&room_id)
        .ok_or_else(|| WorkspaceError::RoomNotFound(target.to_string()))?;

    let mut last = read(room.clone()).await?;
    callback(WatchUpdate::Initial(&last));

    let mut backoff = Backoff::new(config.backoff);
    let mut failures: u32 = 0;

    while running.load(Ordering::SeqCst) {
        let settings = SyncSettings::default()
            .timeout(config.sync_timeout)
            .token(next_batch.clone());

        match client.sync_once(settings).await {
            Ok(response) => {
                next_batch = response.next_batch;
                if failures > 0 {
                    callback(WatchUpdate::Reconnected);
                    failures = 0;
                    backoff.reset();
                }
                // A read failure is treated as transient: skip this tick and
                // try again on the next sync rather than tearing down the watch.
                let current = match read(room.clone()).await {
                    Ok(current) => current,
                    Err(_) => continue,
                };
                if current != last {
                    callback(WatchUpdate::Changed {
                        previous: &last,
                        current: &current,
                    });
                    last = current;
                }
            }
            Err(error) => {
                if is_fatal_sync_error(&error) {
                    return Err(WorkspaceError::from(error));
                }
                failures = failures.saturating_add(1);
                callback(WatchUpdate::Reconnecting {
                    attempt: failures,
                    error: error.to_string(),
                });
                // Honor a homeserver `Retry-After` on a 429 (clamped to the
                // backoff ceiling) instead of blindly backing off, mirroring the
                // daemon sync loop (issue #351). `rate_limit_retry_after` returns
                // `None` for any non-rate-limit error, so this falls straight
                // through to the exponential floor in the common case.
                let floor = backoff.next_delay();
                let delay = error
                    .client_api_error_kind()
                    .and_then(|kind| {
                        rate_limit_retry_after(
                            kind,
                            SystemTime::now(),
                            config.backoff.rate_limit_ceiling,
                        )
                    })
                    .map_or(floor, |after| after.max(floor));
                sleep_interruptible(delay, running).await;
            }
        }
    }

    Ok(())
}

/// A single change between two task snapshots, reported by [`diff_tasks`].
///
/// Tasks are matched by `task_id`: an id present only in the new snapshot is
/// [`Added`](TaskChange::Added), one present only in the old snapshot is
/// [`Removed`](TaskChange::Removed), and one present in both whose content
/// differs is [`Updated`](TaskChange::Updated).
///
/// The [`TaskState`] payloads are boxed so every variant is the same small size
/// (a state is several hundred bytes).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "change", rename_all = "snake_case")]
pub enum TaskChange {
    /// A task that appeared in the new snapshot.
    Added(Box<TaskState>),
    /// A task that disappeared from the new snapshot.
    Removed(Box<TaskState>),
    /// A task present in both snapshots whose content changed.
    Updated {
        /// The task as it was before the change.
        previous: Box<TaskState>,
        /// The task as it is now.
        current: Box<TaskState>,
    },
}

impl TaskChange {
    /// The `task_id` this change concerns.
    pub fn task_id(&self) -> &str {
        match self {
            TaskChange::Added(task) | TaskChange::Removed(task) => &task.task_id,
            TaskChange::Updated { current, .. } => &current.task_id,
        }
    }
}

/// Compute the per-task changes between two task snapshots.
///
/// Returns one [`TaskChange`] per task that was added, removed, or whose content
/// changed, ordered by `task_id` for stable, deterministic output. Tasks present
/// in both snapshots that are byte-for-byte identical produce no change.
pub fn diff_tasks(previous: &[TaskState], current: &[TaskState]) -> Vec<TaskChange> {
    let prev_by_id: BTreeMap<&str, &TaskState> =
        previous.iter().map(|t| (t.task_id.as_str(), t)).collect();
    let curr_by_id: BTreeMap<&str, &TaskState> =
        current.iter().map(|t| (t.task_id.as_str(), t)).collect();

    let mut changes = Vec::new();

    // Added or updated: walk the current snapshot.
    for (id, curr) in &curr_by_id {
        match prev_by_id.get(id) {
            None => changes.push(TaskChange::Added(Box::new((*curr).clone()))),
            Some(prev) if prev != curr => changes.push(TaskChange::Updated {
                previous: Box::new((*prev).clone()),
                current: Box::new((*curr).clone()),
            }),
            Some(_) => {}
        }
    }

    // Removed: ids present before but gone now.
    for (id, prev) in &prev_by_id {
        if !curr_by_id.contains_key(id) {
            changes.push(TaskChange::Removed(Box::new((*prev).clone())));
        }
    }

    changes.sort_by(|a, b| a.task_id().cmp(b.task_id()));
    changes
}

#[cfg(test)]
mod tests {
    use super::*;

    fn task(task_id: &str, state: &str, rev: u64) -> TaskState {
        TaskState {
            task_id: task_id.to_string(),
            title: format!("title for {task_id}"),
            description: String::new(),
            state: state.to_string(),
            assigned_to: String::new(),
            created_by: "creator".to_string(),
            depends_on: Vec::new(),
            blocks: Vec::new(),
            invocation_id: None,
            created_at: "2026-06-02T12:00:00Z".to_string(),
            updated_at: "2026-06-02T12:00:00Z".to_string(),
            state_rev: rev,
            previous_event_id: None,
            result: None,
            action: None,
            extra: Default::default(),
        }
    }

    #[test]
    fn identical_snapshots_produce_no_changes() {
        let snap = vec![task("task_a", "pending", 1), task("task_b", "executing", 3)];
        assert!(diff_tasks(&snap, &snap).is_empty());
    }

    #[test]
    fn state_transition_is_reported_as_an_update() {
        // The core acceptance case: a task moving pending -> executing surfaces.
        let before = vec![task("task_a", "pending", 1)];
        let after = vec![task("task_a", "executing", 2)];
        let changes = diff_tasks(&before, &after);
        assert_eq!(changes.len(), 1);
        match &changes[0] {
            TaskChange::Updated { previous, current } => {
                assert_eq!(previous.state, "pending");
                assert_eq!(current.state, "executing");
                assert_eq!(current.task_id, "task_a");
            }
            other => panic!("expected an update, got {other:?}"),
        }
    }

    #[test]
    fn added_and_removed_tasks_are_detected() {
        let before = vec![task("task_a", "pending", 1)];
        let after = vec![task("task_b", "pending", 1)];
        let changes = diff_tasks(&before, &after);
        // Sorted by task_id: task_a (removed) precedes task_b (added).
        assert_eq!(changes.len(), 2);
        assert!(matches!(&changes[0], TaskChange::Removed(t) if t.task_id == "task_a"));
        assert!(matches!(&changes[1], TaskChange::Added(t) if t.task_id == "task_b"));
    }

    #[test]
    fn changes_are_ordered_by_task_id() {
        let before = vec![task("task_b", "pending", 1)];
        let after = vec![
            task("task_c", "pending", 1),
            task("task_a", "pending", 1),
            task("task_b", "executing", 2),
        ];
        let changes = diff_tasks(&before, &after);
        let ids: Vec<&str> = changes.iter().map(TaskChange::task_id).collect();
        assert_eq!(ids, vec!["task_a", "task_b", "task_c"]);
    }

    #[test]
    fn task_change_serializes_with_a_tag() {
        let change = TaskChange::Added(Box::new(task("task_a", "pending", 1)));
        let json = serde_json::to_value(&change).unwrap();
        assert_eq!(json["change"], "added");
        assert_eq!(json["task_id"], "task_a");
    }
}
