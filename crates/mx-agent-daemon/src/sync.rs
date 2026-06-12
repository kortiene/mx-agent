//! Long-lived Matrix `/sync` loop, token persistence, and health reporting.
//!
//! The daemon owns the Matrix sync loop (see `docs/architecture.md`, sections
//! 10 and 11.3). This module drives a `/sync` loop that:
//!
//! - resumes from a persisted batch token so a restart continues where it left
//!   off (see [`crate::session::load_sync_token`]);
//! - persists each new token as it arrives;
//! - retries transient failures with exponential backoff so a flaky network
//!   does not stop the daemon; and
//! - exposes a non-sensitive [`SyncHealth`] snapshot for status reporting.
//!
//! The core loop ([`run_sync_loop`]) is generic over a "step" function so it can
//! be tested without a live homeserver. [`run_matrix_sync`] wires the generic
//! loop to a real [`matrix_sdk::Client`].

use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::event_router::{
    events_from_sync_response, EventMeta, EventRouter, RouteOutcome, RoutedEvent,
};
use crate::exec_subscribers::{ExecSubscriberRegistry, ForwardedExecEvent};
use crate::replay::ReplayCache;
use crate::session::{load_sync_token, save_sync_token, SessionPaths};

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Coarse health state of the sync loop, safe to expose in status output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncState {
    /// The loop has started but not yet completed a successful sync.
    Initializing,
    /// The most recent sync attempt succeeded.
    Healthy,
    /// Recent sync attempts are failing and are being retried with backoff.
    Degraded,
    /// The loop has stopped (shutdown requested or a fatal error).
    Stopped,
}

/// A non-sensitive snapshot of sync-loop health, suitable for status output.
///
/// Contains no tokens or credentials, only counters and a coarse state, so it
/// can be serialized into status responses safely.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncHealth {
    /// Coarse health state.
    pub state: SyncState,
    /// Total number of successful syncs since the loop started.
    pub total_syncs: u64,
    /// Number of consecutive failures since the last success.
    pub consecutive_failures: u32,
    /// Unix timestamp (seconds) of the last successful sync, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_success_unix: Option<u64>,
    /// Human-readable description of the most recent error, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    /// Whether the loop resumed from a persisted sync token.
    pub resumed_from_token: bool,
}

impl SyncHealth {
    /// The initial health of a loop that has not yet synced.
    pub fn initializing(resumed_from_token: bool) -> Self {
        Self {
            state: SyncState::Initializing,
            total_syncs: 0,
            consecutive_failures: 0,
            last_success_unix: None,
            last_error: None,
            resumed_from_token,
        }
    }

    /// Record a successful sync at `now` (Unix seconds).
    pub fn record_success(&mut self, now: u64) {
        self.state = SyncState::Healthy;
        self.total_syncs = self.total_syncs.saturating_add(1);
        self.consecutive_failures = 0;
        self.last_success_unix = Some(now);
        self.last_error = None;
    }

    /// Record a transient failure that will be retried.
    pub fn record_failure(&mut self, error: impl Into<String>) {
        self.state = SyncState::Degraded;
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        self.last_error = Some(error.into());
    }

    /// Record a fatal failure that stops the loop.
    pub fn record_fatal(&mut self, error: impl Into<String>) {
        self.state = SyncState::Stopped;
        self.last_error = Some(error.into());
    }

    /// Mark the loop as cleanly stopped (e.g. shutdown requested).
    pub fn record_stopped(&mut self) {
        self.state = SyncState::Stopped;
    }

    /// Render the health as a single-line JSON object.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{\"state\":\"stopped\"}".to_string())
    }
}

/// Configuration for the exponential backoff applied between failed syncs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackoffConfig {
    /// Delay after the first failure.
    pub base: Duration,
    /// Upper bound on the delay.
    pub max: Duration,
    /// Multiplier applied per consecutive failure.
    pub factor: u32,
}

impl Default for BackoffConfig {
    fn default() -> Self {
        Self {
            base: Duration::from_secs(1),
            max: Duration::from_secs(60),
            factor: 2,
        }
    }
}

/// Exponential backoff state machine.
///
/// `next_delay` returns `base * factor^attempt`, capped at `max`, and advances
/// the attempt counter. `reset` returns to the initial delay after a success.
#[derive(Debug, Clone)]
pub struct Backoff {
    config: BackoffConfig,
    attempt: u32,
}

impl Backoff {
    /// Create a new backoff from the given configuration.
    pub fn new(config: BackoffConfig) -> Self {
        Self { config, attempt: 0 }
    }

    /// Return the delay for the current attempt and advance the counter.
    pub fn next_delay(&mut self) -> Duration {
        let base_ms = self.config.base.as_millis() as u64;
        let max_ms = self.config.max.as_millis() as u64;
        let mult = (self.config.factor as u64)
            .checked_pow(self.attempt)
            .unwrap_or(u64::MAX);
        let delay_ms = base_ms.saturating_mul(mult).min(max_ms);
        self.attempt = self.attempt.saturating_add(1);
        Duration::from_millis(delay_ms)
    }

    /// Reset the backoff to its initial delay (after a successful sync).
    pub fn reset(&mut self) {
        self.attempt = 0;
    }
}

/// Outcome of a single sync step.
#[derive(Debug)]
pub enum StepError {
    /// A transient error; the loop should back off and retry.
    Transient(String),
    /// A fatal error (e.g. an invalid token); the loop should stop.
    Fatal(String),
}

/// Run the generic sync loop until `running` is cleared or a fatal error.
///
/// `step` is called with the current sync token (the persisted token on the
/// first iteration) and returns the next token on success. Successful tokens
/// are persisted before the next iteration so a restart resumes from the most
/// recent batch. Transient errors update health and sleep for the backoff
/// delay; fatal errors stop the loop.
pub async fn run_sync_loop<F, Fut>(
    paths: &SessionPaths,
    health: Arc<Mutex<SyncHealth>>,
    backoff_config: BackoffConfig,
    running: Arc<AtomicBool>,
    mut step: F,
) -> std::io::Result<()>
where
    F: FnMut(Option<String>) -> Fut,
    Fut: Future<Output = Result<String, StepError>>,
{
    let mut token = load_sync_token(paths)?;
    {
        let mut h = health.lock().unwrap_or_else(|e| e.into_inner());
        *h = SyncHealth::initializing(token.is_some());
    }
    let mut backoff = Backoff::new(backoff_config);

    while running.load(Ordering::SeqCst) {
        match step(token.clone()).await {
            Ok(next_token) => {
                save_sync_token(paths, &next_token)?;
                token = Some(next_token);
                backoff.reset();
                let mut h = health.lock().unwrap_or_else(|e| e.into_inner());
                h.record_success(now_unix());
            }
            Err(StepError::Transient(msg)) => {
                tracing::warn!(error = %msg, "transient sync failure; backing off");
                {
                    let mut h = health.lock().unwrap_or_else(|e| e.into_inner());
                    h.record_failure(msg);
                }
                let delay = backoff.next_delay();
                sleep_interruptible(delay, &running).await;
            }
            Err(StepError::Fatal(msg)) => {
                tracing::error!(error = %msg, "fatal sync failure; stopping sync loop");
                let mut h = health.lock().unwrap_or_else(|e| e.into_inner());
                h.record_fatal(msg);
                return Ok(());
            }
        }
    }

    let mut h = health.lock().unwrap_or_else(|e| e.into_inner());
    h.record_stopped();
    Ok(())
}

/// Sleep for `delay`, waking early if `running` is cleared.
pub(crate) async fn sleep_interruptible(delay: Duration, running: &AtomicBool) {
    let step = Duration::from_millis(50);
    let mut remaining = delay;
    while remaining > Duration::ZERO && running.load(Ordering::SeqCst) {
        let chunk = remaining.min(step);
        tokio::time::sleep(chunk).await;
        remaining = remaining.saturating_sub(chunk);
    }
}

/// Drive a real Matrix `/sync` loop for `client`, persisting tokens and health.
///
/// Each iteration calls [`matrix_sdk::Client::sync_once`] with the current
/// token. Authentication failures (an unknown or missing token) are treated as
/// fatal; all other errors are transient and retried with backoff so the daemon
/// keeps syncing across network blips.
pub async fn run_matrix_sync(
    client: &matrix_sdk::Client,
    paths: &SessionPaths,
    health: Arc<Mutex<SyncHealth>>,
    backoff_config: BackoffConfig,
    running: Arc<AtomicBool>,
) -> std::io::Result<()> {
    run_matrix_sync_with_subscribers(client, paths, health, backoff_config, running, None).await
}

/// Drive a real Matrix `/sync` loop and forward routed stream/result events to
/// `subscribers` when provided.
pub async fn run_matrix_sync_with_subscribers(
    client: &matrix_sdk::Client,
    paths: &SessionPaths,
    health: Arc<Mutex<SyncHealth>>,
    backoff_config: BackoffConfig,
    running: Arc<AtomicBool>,
    subscribers: Option<ExecSubscriberRegistry>,
) -> std::io::Result<()> {
    use matrix_sdk::config::SyncSettings;

    // Register this client in the process-global map so per-call IPC handlers
    // (exec, approval) reuse the same store-backed client rather than opening
    // a second one that would race the SQLite OlmMachine (issue #240).
    crate::matrix::publish_active_client(client.clone());

    // The event router observes mx-agent events on each sync (architecture
    // §10.1, issue #192). Replay protection for privileged requests is
    // essential, so if the replay cache cannot be loaded we log and route
    // nothing rather than dispatching unchecked requests; syncing still
    // continues so token/health tracking is unaffected.
    let router = match ReplayCache::load(paths) {
        Ok(cache) => Some(Arc::new(Mutex::new(EventRouter::new(cache)))),
        Err(e) => {
            tracing::warn!(
                error = %e,
                "could not load replay cache; mx-agent sync events will not be routed"
            );
            None
        }
    };

    run_sync_loop(paths, health, backoff_config, running, move |token| {
        let router = router.clone();
        let subscribers = subscribers.clone();
        async move {
            let mut settings = SyncSettings::default().timeout(Duration::from_secs(30));
            if let Some(token) = token {
                settings = settings.token(token);
            }
            match client.sync_once(settings).await {
                Ok(response) => {
                    let routed = if let Some(router) = &router {
                        let mut router = router.lock().unwrap_or_else(|e| e.into_inner());
                        route_sync_response(&mut router, &response)
                    } else {
                        Vec::new()
                    };
                    handle_routed_events(client, paths, subscribers.as_ref(), routed).await;
                    Ok(response.next_batch)
                }
                Err(e) => {
                    if is_fatal_sync_error(&e) {
                        Err(StepError::Fatal(e.to_string()))
                    } else {
                        Err(StepError::Transient(e.to_string()))
                    }
                }
            }
        }
    })
    .await
}

/// Route every mx-agent event in a sync response through `router`, logging only
/// non-sensitive metadata (event type, room, sender, category, reason) — never
/// event content (architecture §13.6, issue #192).
///
/// Dispatched events are returned to the async Matrix handler after routing so
/// no handler awaits while holding the router/replay-cache lock.
fn route_sync_response(
    router: &mut EventRouter,
    response: &matrix_sdk::sync::SyncResponse,
) -> Vec<(EventMeta, RoutedEvent)> {
    let mut routed_events = Vec::new();
    for event in events_from_sync_response(response) {
        let mut sink = |meta: &EventMeta, routed: RoutedEvent| {
            tracing::debug!(
                category = routed.category().as_str(),
                event_type = %meta.event_type,
                room = %meta.room_id,
                sender = %meta.sender,
                "dispatched mx-agent event to handler"
            );
            routed_events.push((meta.clone(), routed));
        };
        match router.route(&event, &mut sink) {
            RouteOutcome::Dispatched(_) | RouteOutcome::Ignored => {}
            RouteOutcome::SkippedEncrypted => tracing::debug!(
                event_type = %event.event_type,
                room = %event.room_id,
                "skipped undecryptable encrypted event"
            ),
            RouteOutcome::Malformed(cat) => tracing::warn!(
                category = cat.as_str(),
                event_type = %event.event_type,
                room = %event.room_id,
                sender = %event.sender,
                "rejected malformed mx-agent event"
            ),
            RouteOutcome::ReplayRejected(cat) => tracing::warn!(
                category = cat.as_str(),
                event_type = %event.event_type,
                room = %event.room_id,
                sender = %event.sender,
                "rejected replayed or expired privileged request"
            ),
        }
    }
    routed_events
}

async fn handle_routed_events(
    client: &matrix_sdk::Client,
    paths: &SessionPaths,
    subscribers: Option<&ExecSubscriberRegistry>,
    events: Vec<(EventMeta, RoutedEvent)>,
) {
    for (meta, routed) in events {
        match routed {
            RoutedEvent::ExecRequest(request) => {
                crate::exec::handle_live_exec_request(client, paths, &meta, &request).await;
            }
            RoutedEvent::ExecStdin(event) => {
                if let Ok(room_id) = matrix_sdk::ruma::RoomId::parse(&meta.room_id) {
                    if let Some(room) = client.get_room(&room_id) {
                        if let Ok(content) = serde_json::to_value(&*event) {
                            crate::exec::handle_live_exec_stdin(&room, paths, &content, &event)
                                .await;
                        }
                    }
                }
            }
            RoutedEvent::ExecCancel(event) => {
                if let Ok(room_id) = matrix_sdk::ruma::RoomId::parse(&meta.room_id) {
                    if let Some(room) = client.get_room(&room_id) {
                        if let Ok(content) = serde_json::to_value(&*event) {
                            crate::exec::handle_live_exec_cancel(&room, paths, &content, &event)
                                .await;
                        }
                    }
                }
            }
            RoutedEvent::PtyResize(event) => {
                if let Ok(room_id) = matrix_sdk::ruma::RoomId::parse(&meta.room_id) {
                    if let Some(room) = client.get_room(&room_id) {
                        if let Ok(content) = serde_json::to_value(&*event) {
                            crate::exec::handle_live_pty_resize(&room, paths, &content, &event)
                                .await;
                        }
                    }
                }
            }
            RoutedEvent::CallRequest(request) => {
                crate::call::handle_live_call_request(client, paths, &meta, &request).await;
            }
            RoutedEvent::StreamChunk(event) => {
                publish_forwarded(subscribers, &meta, ForwardedExecEvent::StreamChunk(*event))
            }
            RoutedEvent::StreamArtifact(event) => publish_forwarded(
                subscribers,
                &meta,
                ForwardedExecEvent::StreamArtifact(*event),
            ),
            RoutedEvent::ExecRejected(event) => {
                publish_forwarded(subscribers, &meta, ForwardedExecEvent::ExecRejected(event));
            }
            RoutedEvent::ExecFinished(event) => {
                publish_forwarded(subscribers, &meta, ForwardedExecEvent::ExecFinished(*event))
            }
            RoutedEvent::ExecCancelled(event) => {
                publish_forwarded(
                    subscribers,
                    &meta,
                    ForwardedExecEvent::ExecCancelled(*event),
                );
            }
            RoutedEvent::CallResponse(event) => {
                publish_forwarded(subscribers, &meta, ForwardedExecEvent::CallResponse(*event));
            }
            other => {
                tracing::debug!(
                    category = other.category().as_str(),
                    room = %meta.room_id,
                    sender = %meta.sender,
                    "no live handler for routed mx-agent event"
                );
            }
        }
    }
}

fn publish_forwarded(
    subscribers: Option<&ExecSubscriberRegistry>,
    meta: &EventMeta,
    event: ForwardedExecEvent,
) {
    let Some(subscribers) = subscribers else {
        tracing::debug!(
            event_type = %meta.event_type,
            room = %meta.room_id,
            sender = %meta.sender,
            "no exec subscriber registry configured for routed result event"
        );
        return;
    };
    let key = event.key();
    // Sender-pin the result plane: the registry delivers this event only to
    // subscribers that pinned `meta.sender` as the executing agent, so a forged
    // result/stream event from any other room member is dropped (issue #304).
    let stats = subscribers.publish(event, &meta.sender);
    tracing::debug!(
        event_type = %meta.event_type,
        room = %meta.room_id,
        sender = %meta.sender,
        key = ?key,
        delivered = stats.delivered,
        filtered = stats.filtered,
        pruned = stats.pruned,
        "forwarded routed Matrix result event to exec subscribers"
    );
}

/// Classify a Matrix sync error: an unknown/missing access token is fatal
/// (re-auth required); everything else is treated as transient.
pub(crate) fn is_fatal_sync_error(error: &matrix_sdk::Error) -> bool {
    use matrix_sdk::ruma::api::error::ErrorKind;
    matches!(
        error.client_api_error_kind(),
        Some(ErrorKind::UnknownToken(_)) | Some(ErrorKind::MissingToken)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex as StdMutex, MutexGuard, OnceLock};

    fn env_lock() -> MutexGuard<'static, ()> {
        static LOCK: OnceLock<StdMutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| StdMutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    struct TempData {
        dir: std::path::PathBuf,
        _guard: MutexGuard<'static, ()>,
    }

    impl TempData {
        fn new(tag: &str) -> Self {
            let guard = env_lock();
            let dir = std::env::temp_dir().join(format!(
                "mx-agent-sync-{}-{}-{}",
                tag,
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::env::set_var(crate::session::ENV_DATA_DIR, &dir);
            Self { dir, _guard: guard }
        }
    }

    impl Drop for TempData {
        fn drop(&mut self) {
            std::env::remove_var(crate::session::ENV_DATA_DIR);
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn fast_backoff() -> BackoffConfig {
        BackoffConfig {
            base: Duration::from_millis(1),
            max: Duration::from_millis(4),
            factor: 2,
        }
    }

    #[test]
    fn backoff_grows_exponentially_and_caps() {
        let mut b = Backoff::new(BackoffConfig {
            base: Duration::from_millis(100),
            max: Duration::from_millis(500),
            factor: 2,
        });
        assert_eq!(b.next_delay(), Duration::from_millis(100));
        assert_eq!(b.next_delay(), Duration::from_millis(200));
        assert_eq!(b.next_delay(), Duration::from_millis(400));
        assert_eq!(b.next_delay(), Duration::from_millis(500)); // capped
        assert_eq!(b.next_delay(), Duration::from_millis(500)); // still capped
        b.reset();
        assert_eq!(b.next_delay(), Duration::from_millis(100));
    }

    #[test]
    fn health_transitions_and_redacts_nothing() {
        let mut h = SyncHealth::initializing(false);
        assert_eq!(h.state, SyncState::Initializing);
        h.record_failure("network down");
        assert_eq!(h.state, SyncState::Degraded);
        assert_eq!(h.consecutive_failures, 1);
        h.record_failure("still down");
        assert_eq!(h.consecutive_failures, 2);
        h.record_success(1000);
        assert_eq!(h.state, SyncState::Healthy);
        assert_eq!(h.consecutive_failures, 0);
        assert_eq!(h.total_syncs, 1);
        assert_eq!(h.last_success_unix, Some(1000));
        assert!(h.last_error.is_none());

        let json = h.to_json();
        assert!(json.contains("\"state\":\"healthy\""), "json: {json}");
        assert!(json.contains("\"total_syncs\":1"), "json: {json}");
    }

    // The daemon continues syncing after transient failures.
    #[tokio::test]
    async fn loop_recovers_from_transient_failures() {
        let _data = TempData::new("recover");
        let paths = SessionPaths::resolve();
        let health = Arc::new(Mutex::new(SyncHealth::initializing(false)));
        let running = Arc::new(AtomicBool::new(true));

        let counter = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let counter_step = counter.clone();
        let running_step = running.clone();

        run_sync_loop(
            &paths,
            health.clone(),
            fast_backoff(),
            running.clone(),
            move |_token| {
                let counter = counter_step.clone();
                let running = running_step.clone();
                async move {
                    let n = counter.fetch_add(1, Ordering::SeqCst);
                    // Fail transiently twice, then succeed, then stop the loop.
                    match n {
                        0 | 1 => Err(StepError::Transient(format!("blip {n}"))),
                        2 => Ok("token_after_recovery".to_string()),
                        _ => {
                            running.store(false, Ordering::SeqCst);
                            Ok("token_final".to_string())
                        }
                    }
                }
            },
        )
        .await
        .unwrap();

        // It kept going past the failures and synced successfully.
        let h = health.lock().unwrap();
        assert!(h.total_syncs >= 1, "should have synced after failures");
        // The latest token was persisted (restart would resume from it).
        assert_eq!(
            load_sync_token(&paths).unwrap().as_deref(),
            Some("token_final")
        );
    }

    // Restart resumes from the stored sync token.
    #[tokio::test]
    async fn loop_resumes_from_stored_token() {
        let _data = TempData::new("resume");
        let paths = SessionPaths::resolve();
        // Simulate a prior run having persisted a token.
        save_sync_token(&paths, "prior_token").unwrap();

        let health = Arc::new(Mutex::new(SyncHealth::initializing(false)));
        let running = Arc::new(AtomicBool::new(true));
        let seen = Arc::new(Mutex::new(Vec::<Option<String>>::new()));
        let seen_step = seen.clone();
        let running_step = running.clone();

        run_sync_loop(
            &paths,
            health.clone(),
            fast_backoff(),
            running.clone(),
            move |token| {
                let seen = seen_step.clone();
                let running = running_step.clone();
                async move {
                    seen.lock().unwrap().push(token);
                    running.store(false, Ordering::SeqCst);
                    Ok("next_token".to_string())
                }
            },
        )
        .await
        .unwrap();

        let seen = seen.lock().unwrap();
        assert_eq!(seen.first().unwrap().as_deref(), Some("prior_token"));
        assert!(health.lock().unwrap().resumed_from_token);
    }

    // A fatal error stops the loop and is reflected in health.
    #[tokio::test]
    async fn loop_stops_on_fatal_error() {
        let _data = TempData::new("fatal");
        let paths = SessionPaths::resolve();
        let health = Arc::new(Mutex::new(SyncHealth::initializing(false)));
        let running = Arc::new(AtomicBool::new(true));

        run_sync_loop(
            &paths,
            health.clone(),
            fast_backoff(),
            running.clone(),
            move |_token| async move { Err(StepError::Fatal("token revoked".to_string())) },
        )
        .await
        .unwrap();

        let h = health.lock().unwrap();
        assert_eq!(h.state, SyncState::Stopped);
        assert_eq!(h.last_error.as_deref(), Some("token revoked"));
    }
}
