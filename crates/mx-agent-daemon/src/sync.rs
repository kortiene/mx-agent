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

use matrix_sdk::ruma::api::error::{ErrorKind, RetryAfter};
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
    /// When the most recent failure was a homeserver rate limit (HTTP 429 /
    /// `M_LIMIT_EXCEEDED`), the backoff the loop is honoring, in whole seconds;
    /// `None` otherwise. Lets `daemon status` distinguish a server-directed
    /// rate-limit pause from a generic transient failure (issue #351).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_limited_secs: Option<u64>,
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
            rate_limited_secs: None,
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
        self.rate_limited_secs = None;
    }

    /// Record a transient failure that will be retried.
    pub fn record_failure(&mut self, error: impl Into<String>) {
        self.state = SyncState::Degraded;
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        self.last_error = Some(error.into());
        // A generic transient supersedes any earlier rate-limit pause.
        self.rate_limited_secs = None;
    }

    /// Record a homeserver rate-limit (HTTP 429) that the loop will retry after
    /// honoring a server-directed (or backoff-derived) `delay`.
    ///
    /// Keeps the coarse state [`SyncState::Degraded`] — the loop is alive and
    /// retrying, not stopped — but records the honored wait in
    /// [`SyncHealth::rate_limited_secs`] and a clear `last_error`, so an operator
    /// reading `daemon status` sees *why* sync is paused (issue #351). The
    /// snapshot stays token-free: only the duration and a fixed message are
    /// recorded.
    pub fn record_rate_limited(&mut self, delay: Duration) {
        self.state = SyncState::Degraded;
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        let secs = delay.as_secs();
        self.rate_limited_secs = Some(secs);
        self.last_error = Some(format!("rate limited by homeserver; retrying in {secs}s"));
    }

    /// Record a fatal failure that stops the loop.
    pub fn record_fatal(&mut self, error: impl Into<String>) {
        self.state = SyncState::Stopped;
        self.last_error = Some(error.into());
        self.rate_limited_secs = None;
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
    /// Ceiling on a server-directed `Retry-After` honored after a homeserver
    /// rate limit (HTTP 429). A hostile or misconfigured homeserver cannot wedge
    /// the sync loop offline for an unbounded time with a giant `retry_after_ms`
    /// or a far-future HTTP-date: the honored delay is clamped to this value
    /// (issue #351). This caps a *single* wait, not the total number of retries,
    /// so a long-lived daemon keeps retrying.
    pub rate_limit_ceiling: Duration,
}

impl Default for BackoffConfig {
    fn default() -> Self {
        Self {
            base: Duration::from_secs(1),
            max: Duration::from_secs(60),
            factor: 2,
            rate_limit_ceiling: Duration::from_secs(300),
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
    /// A homeserver rate-limit (HTTP 429 / `M_LIMIT_EXCEEDED`). `retry_after` is
    /// the server-directed wait (already clamped to the configured ceiling) when
    /// one was supplied; `None` falls back to the exponential backoff schedule.
    RateLimited {
        /// The clamped, server-directed retry delay, if the homeserver supplied
        /// one; `None` means fall back to the exponential backoff floor.
        retry_after: Option<Duration>,
    },
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
    // A sync-token persistence error is fatal to the loop: record it on the
    // shared health *before* returning so `daemon.status` reports the dead loop
    // as `Stopped` rather than reporting the last healthy state forever (the
    // bare `?` here previously bypassed health entirely — issue #316).
    let mut token = match load_sync_token(paths) {
        Ok(token) => token,
        Err(e) => {
            health
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .record_fatal(format!("sync token load failed: {e}"));
            return Err(e);
        }
    };
    {
        let mut h = health.lock().unwrap_or_else(|e| e.into_inner());
        *h = SyncHealth::initializing(token.is_some());
    }
    let mut backoff = Backoff::new(backoff_config);

    while running.load(Ordering::SeqCst) {
        match step(token.clone()).await {
            Ok(next_token) => {
                if let Err(e) = save_sync_token(paths, &next_token) {
                    health
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .record_fatal(format!("sync token save failed: {e}"));
                    return Err(e);
                }
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
            Err(StepError::RateLimited { retry_after }) => {
                // Advance the exponential schedule so *repeated* rate limits
                // ratchet up rather than hammering at exactly the server minimum,
                // but never wait less than the homeserver asked for. When the
                // server gave no usable delay, fall back to the backoff floor.
                let floor = backoff.next_delay();
                let delay = retry_after.map_or(floor, |after| after.max(floor));
                tracing::warn!(
                    delay_secs = delay.as_secs(),
                    server_directed = retry_after.is_some(),
                    "rate limited by homeserver; backing off"
                );
                {
                    let mut h = health.lock().unwrap_or_else(|e| e.into_inner());
                    h.record_rate_limited(delay);
                }
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

    // Captured by the step so the 429 classifier clamps the honored
    // `Retry-After` to the same ceiling the loop's backoff uses.
    let rate_limit_ceiling = backoff_config.rate_limit_ceiling;
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
                        let mut guard = router.lock().unwrap_or_else(|e| e.into_inner());
                        route_sync_response(&mut guard, &response)
                    } else {
                        Vec::new()
                    };
                    // Thread the router's shared replay cache into the handler so
                    // the live approval-decision consumer can burn a decision
                    // nonce through the *same* cache the request plane admits
                    // through (issue #306) — never a second, clobber-prone cache.
                    handle_routed_events(
                        client,
                        paths,
                        subscribers.as_ref(),
                        router.as_ref(),
                        routed,
                    )
                    .await;
                    Ok(response.next_batch)
                }
                Err(e) => {
                    // Classify in order: fatal (re-auth) → rate-limited (429,
                    // honor Retry-After) → generic transient (blind backoff).
                    if is_fatal_sync_error(&e) {
                        Err(StepError::Fatal(e.to_string()))
                    } else if is_rate_limit_error(&e) {
                        let retry_after = e.client_api_error_kind().and_then(|kind| {
                            rate_limit_retry_after(kind, SystemTime::now(), rate_limit_ceiling)
                        });
                        Err(StepError::RateLimited { retry_after })
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
    router: Option<&Arc<Mutex<EventRouter>>>,
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
                publish_forwarded(
                    client,
                    paths,
                    subscribers,
                    &meta,
                    ForwardedExecEvent::StreamChunk(*event),
                )
                .await
            }
            RoutedEvent::StreamArtifact(event) => {
                publish_forwarded(
                    client,
                    paths,
                    subscribers,
                    &meta,
                    ForwardedExecEvent::StreamArtifact(*event),
                )
                .await
            }
            RoutedEvent::ExecRejected(event) => {
                publish_forwarded(
                    client,
                    paths,
                    subscribers,
                    &meta,
                    ForwardedExecEvent::ExecRejected(event),
                )
                .await;
            }
            RoutedEvent::ExecFinished(event) => {
                publish_forwarded(
                    client,
                    paths,
                    subscribers,
                    &meta,
                    ForwardedExecEvent::ExecFinished(*event),
                )
                .await
            }
            RoutedEvent::ExecCancelled(event) => {
                publish_forwarded(
                    client,
                    paths,
                    subscribers,
                    &meta,
                    ForwardedExecEvent::ExecCancelled(*event),
                )
                .await;
            }
            RoutedEvent::CallResponse(event) => {
                publish_forwarded(
                    client,
                    paths,
                    subscribers,
                    &meta,
                    ForwardedExecEvent::CallResponse(*event),
                )
                .await;
            }
            RoutedEvent::ApprovalDecision(decision) => {
                // Consume a decision for a held live exec/call (issue #306):
                // verify it with scheduler parity, then release / deny / ignore
                // the hold. Task-backed holds (held_request == None) are the
                // scheduler's and are ignored here.
                crate::approval::handle_live_approval_decision(
                    client, paths, router, &meta, &decision,
                )
                .await;
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

async fn publish_forwarded(
    client: &matrix_sdk::Client,
    paths: &SessionPaths,
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

    // Verify the executor's Ed25519 signature on the result-plane event before
    // delivering it, fail-closed on the Matrix transport — defense-in-depth in
    // *series* with the sender-pin below (issue #348, spec D5). A compromised
    // homeserver that spoofs `sender` and forges a result cannot also forge a
    // signature over the executor's trusted key, so a forged/tampered/unsigned
    // result is dropped here and the caller's waiter times out.
    match verify_forwarded_event(client, paths, meta, &event).await {
        Ok(crate::result_verify::VerifyOutcome::Verified) => {}
        Ok(crate::result_verify::VerifyOutcome::AcceptedUnsigned) => {
            tracing::warn!(
                event_type = %meta.event_type,
                room = %meta.room_id,
                sender = %meta.sender,
                invocation_id = %forwarded_correlation_id(&event),
                "accepting an UNSIGNED result-plane event because MX_AGENT_ALLOW_UNSIGNED_RESULTS is set"
            );
        }
        Err(err) => {
            tracing::warn!(
                event_type = %meta.event_type,
                room = %meta.room_id,
                sender = %meta.sender,
                invocation_id = %forwarded_correlation_id(&event),
                reason = err.reason(),
                "dropping result-plane event with an unverified signature"
            );
            return;
        }
    }

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

/// The invocation/request correlation id for a forwarded result event, for
/// non-sensitive log lines.
fn forwarded_correlation_id(event: &ForwardedExecEvent) -> String {
    match event {
        ForwardedExecEvent::StreamChunk(ev) => ev.invocation_id.clone(),
        ForwardedExecEvent::StreamArtifact(ev) => ev.invocation_id.clone(),
        ForwardedExecEvent::ExecRejected(ev) => ev.invocation_id.clone(),
        ForwardedExecEvent::ExecFinished(ev) => ev.invocation_id.clone(),
        ForwardedExecEvent::ExecCancelled(ev) => ev.invocation_id.clone(),
        ForwardedExecEvent::CallResponse(ev) => ev.request_id.clone(),
    }
}

/// Verify the Ed25519 signature on a forwarded result-plane event against the
/// executing agent's published, locally-trusted key (issue #348).
///
/// Resolves the executor's [`AgentState`](mx_agent_protocol::schema::AgentState)
/// from `meta.sender` (the already-pinned executing Matrix user) in the event's
/// room, then applies the centralized fail-closed policy in
/// [`crate::result_verify::verify_result_signature`] (verify → key-id match →
/// trust re-check, with the `MX_AGENT_ALLOW_UNSIGNED_RESULTS` override applying
/// only to a *missing* signature).
async fn verify_forwarded_event(
    client: &matrix_sdk::Client,
    paths: &SessionPaths,
    meta: &EventMeta,
    event: &ForwardedExecEvent,
) -> Result<crate::result_verify::VerifyOutcome, crate::result_verify::ResultVerifyError> {
    use crate::result_verify::{verify_result_signature, ResultVerifyError};

    // Resolve the executor's AgentState by its Matrix user id (`meta.sender`),
    // the same identity the sender-pin uses. Any failure to resolve a single
    // matching agent state fails closed.
    let room_id = matrix_sdk::ruma::RoomId::parse(&meta.room_id)
        .map_err(|_| ResultVerifyError::UnresolvableKey)?;
    let room = client
        .get_room(&room_id)
        .ok_or(ResultVerifyError::UnresolvableKey)?;
    let agent_state = crate::agent::read_all_agent_states(&room)
        .await
        .map_err(|_| ResultVerifyError::UnresolvableKey)?
        .into_iter()
        .find(|agent| agent.matrix_user_id == meta.sender)
        .ok_or(ResultVerifyError::UnresolvableKey)?;

    let trust = crate::trust::TrustStore::load(paths).unwrap_or_default();

    // Verify the typed inner event (its serialized form carries the embedded
    // `signature`). The policy helper handles the unsigned-results override.
    match event {
        ForwardedExecEvent::StreamChunk(ev) => verify_result_signature(ev, &agent_state, &trust),
        ForwardedExecEvent::StreamArtifact(ev) => verify_result_signature(ev, &agent_state, &trust),
        ForwardedExecEvent::ExecRejected(ev) => verify_result_signature(ev, &agent_state, &trust),
        ForwardedExecEvent::ExecFinished(ev) => verify_result_signature(ev, &agent_state, &trust),
        ForwardedExecEvent::ExecCancelled(ev) => verify_result_signature(ev, &agent_state, &trust),
        ForwardedExecEvent::CallResponse(ev) => verify_result_signature(ev, &agent_state, &trust),
    }
}

/// Classify a Matrix sync error: an unknown/missing access token is fatal
/// (re-auth required); everything else is treated as transient.
pub(crate) fn is_fatal_sync_error(error: &matrix_sdk::Error) -> bool {
    matches!(
        error.client_api_error_kind(),
        Some(ErrorKind::UnknownToken(_)) | Some(ErrorKind::MissingToken)
    )
}

/// Whether a Matrix sync error is a homeserver rate limit (HTTP 429 /
/// `M_LIMIT_EXCEEDED`).
///
/// The step closure branches on this alongside [`is_fatal_sync_error`] so a
/// rate limit becomes a [`StepError::RateLimited`] (honoring `Retry-After`)
/// rather than a blindly-backed-off [`StepError::Transient`] (issue #351).
pub(crate) fn is_rate_limit_error(error: &matrix_sdk::Error) -> bool {
    matches!(
        error.client_api_error_kind(),
        Some(ErrorKind::LimitExceeded(_))
    )
}

/// Extract a server-directed retry delay from a rate-limit [`ErrorKind`],
/// clamped to `[Duration::ZERO, ceiling]`.
///
/// Returns `None` when `kind` is not a rate limit or carries no usable delay, in
/// which case the caller falls back to the exponential backoff schedule. The
/// `now` parameter is passed in (rather than read internally) so the HTTP-date
/// (`DateTime`) form is deterministically testable.
///
/// - [`RetryAfter::Delay`] → `Some(delay.min(ceiling))`.
/// - [`RetryAfter::DateTime`] → `Some((instant - now).min(ceiling))`, with a
///   past instant collapsing to `Duration::ZERO`.
/// - Any other kind, or `retry_after == None` → `None`.
///
/// Clamping to `ceiling` is a DoS guard: a hostile or misconfigured homeserver
/// cannot pin the sync loop offline with a giant `retry_after_ms` or a far-future
/// HTTP-date (issue #351).
pub(crate) fn rate_limit_retry_after(
    kind: &ErrorKind,
    now: SystemTime,
    ceiling: Duration,
) -> Option<Duration> {
    let ErrorKind::LimitExceeded(data) = kind else {
        return None;
    };
    match data.retry_after? {
        RetryAfter::Delay(delay) => Some(delay.min(ceiling)),
        RetryAfter::DateTime(instant) => Some(
            instant
                .duration_since(now)
                .unwrap_or(Duration::ZERO)
                .min(ceiling),
        ),
    }
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
            rate_limit_ceiling: Duration::from_millis(50),
        }
    }

    #[test]
    fn backoff_grows_exponentially_and_caps() {
        let mut b = Backoff::new(BackoffConfig {
            base: Duration::from_millis(100),
            max: Duration::from_millis(500),
            factor: 2,
            rate_limit_ceiling: Duration::from_secs(300),
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

    /// A unique per-call data dir that does not set `MX_AGENT_DATA_DIR` (avoids
    /// the env-var mutex), for tests that can share a `SessionPaths` explicitly.
    fn unique_temp_dir(tag: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "mx-agent-sync-uniq-{}-{}-{}",
            tag,
            std::process::id(),
            n,
        ))
    }

    // A sync-token persistence error is surfaced as a stopped (unhealthy) loop
    // rather than silently bypassing health (issue #316).
    #[tokio::test]
    async fn loop_records_stopped_on_token_load_error() {
        let _data = TempData::new("tokenloaderr");
        let paths = SessionPaths::resolve();
        paths.ensure_data_dir().unwrap();
        // Force a non-NotFound I/O error from `load_sync_token` by making the
        // token path a directory (so `read_to_string` fails).
        std::fs::create_dir_all(&paths.sync_token_file).unwrap();

        let health = Arc::new(Mutex::new(SyncHealth::initializing(false)));
        let running = Arc::new(AtomicBool::new(true));
        let result = run_sync_loop(
            &paths,
            health.clone(),
            fast_backoff(),
            running,
            |_token| async move { Ok::<String, StepError>("unused".to_string()) },
        )
        .await;

        assert!(result.is_err(), "a token load error must propagate");
        let h = health.lock().unwrap();
        assert_eq!(h.state, SyncState::Stopped, "dead loop reports Stopped");
        assert!(
            h.last_error.is_some(),
            "the persistence error is recorded for status"
        );
    }

    // A sync-token SAVE error must also transition health to Stopped so
    // daemon.status reports the dead loop as unhealthy (issue #316 — the
    // load path was already guarded; this closes the save path gap).
    #[tokio::test]
    async fn loop_records_stopped_on_token_save_error() {
        use std::os::unix::fs::PermissionsExt;

        let dir = unique_temp_dir("tokensaveerr");
        let paths = crate::session::SessionPaths::for_data_dir(dir.clone());
        paths.ensure_data_dir().unwrap();

        // Make the data dir read-only so save_sync_token cannot create the tmp
        // file; load_sync_token still succeeds (missing file returns Ok(None)).
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o500)).unwrap();

        let health = Arc::new(Mutex::new(SyncHealth::initializing(false)));
        let running = Arc::new(AtomicBool::new(true));

        let result = run_sync_loop(
            &paths,
            health.clone(),
            fast_backoff(),
            running,
            |_token| async move { Ok::<String, StepError>("next_token".to_string()) },
        )
        .await;

        // Restore write permissions before cleanup so the dir can be removed.
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
        let _ = std::fs::remove_dir_all(&dir);

        assert!(result.is_err(), "a token save error must propagate");
        let h = health.lock().unwrap();
        assert_eq!(
            h.state,
            SyncState::Stopped,
            "dead loop must report Stopped on save error"
        );
        assert!(
            h.last_error.is_some(),
            "the save error must be recorded for status"
        );
    }

    // ---- Rate-limit (HTTP 429 / Retry-After) handling, issue #351 ----

    /// Build an `M_LIMIT_EXCEEDED` error kind with the given `Retry-After`.
    ///
    /// `LimitExceededErrorData` is `#[non_exhaustive]`, so it is built via its
    /// constructor and the public field is then set (a struct literal would not
    /// compile outside ruma).
    fn limit_exceeded(retry_after: Option<RetryAfter>) -> ErrorKind {
        use matrix_sdk::ruma::api::error::LimitExceededErrorData;
        let mut data = LimitExceededErrorData::new();
        data.retry_after = retry_after;
        ErrorKind::LimitExceeded(data)
    }

    #[test]
    fn rate_limit_retry_after_extracts_and_clamps() {
        let ceiling = Duration::from_secs(300);
        let now = SystemTime::now();

        // A `Delay` within the ceiling is honored verbatim.
        let kind = limit_exceeded(Some(RetryAfter::Delay(Duration::from_secs(5))));
        assert_eq!(
            rate_limit_retry_after(&kind, now, ceiling),
            Some(Duration::from_secs(5))
        );

        // A `Delay` above the ceiling is clamped (DoS guard).
        let kind = limit_exceeded(Some(RetryAfter::Delay(Duration::from_secs(10_000))));
        assert_eq!(rate_limit_retry_after(&kind, now, ceiling), Some(ceiling));

        // A future `DateTime` resolves to (instant - now), within the ceiling.
        let kind = limit_exceeded(Some(RetryAfter::DateTime(now + Duration::from_secs(7))));
        assert_eq!(
            rate_limit_retry_after(&kind, now, ceiling),
            Some(Duration::from_secs(7))
        );

        // A far-future `DateTime` is clamped to the ceiling.
        let kind = limit_exceeded(Some(RetryAfter::DateTime(
            now + Duration::from_secs(100_000),
        )));
        assert_eq!(rate_limit_retry_after(&kind, now, ceiling), Some(ceiling));

        // A past `DateTime` collapses to zero (never negative).
        let kind = limit_exceeded(Some(RetryAfter::DateTime(now - Duration::from_secs(10))));
        assert_eq!(
            rate_limit_retry_after(&kind, now, ceiling),
            Some(Duration::ZERO)
        );

        // `LimitExceeded` with no `Retry-After` -> fall back to backoff.
        assert_eq!(
            rate_limit_retry_after(&limit_exceeded(None), now, ceiling),
            None
        );

        // A non-rate-limit kind is never treated as a rate limit.
        assert_eq!(
            rate_limit_retry_after(&ErrorKind::MissingToken, now, ceiling),
            None
        );
    }

    #[test]
    fn record_rate_limited_sets_and_clears() {
        let mut h = SyncHealth::initializing(false);
        h.record_rate_limited(Duration::from_secs(12));
        // Stays Degraded (alive, retrying) but surfaces *why* sync is paused.
        assert_eq!(h.state, SyncState::Degraded);
        assert_eq!(h.rate_limited_secs, Some(12));
        assert_eq!(h.consecutive_failures, 1);
        assert!(h
            .last_error
            .as_deref()
            .is_some_and(|e| e.contains("rate limited")));

        let json = h.to_json();
        assert!(json.contains("\"rate_limited_secs\":12"), "json: {json}");

        // A success clears the rate-limit surface (and omits it from JSON).
        h.record_success(2000);
        assert_eq!(h.rate_limited_secs, None);
        assert!(h.last_error.is_none());
        assert!(
            !h.to_json().contains("rate_limited_secs"),
            "cleared field must be omitted"
        );
    }

    #[test]
    fn backoff_default_has_sane_rate_limit_ceiling() {
        assert_eq!(
            BackoffConfig::default().rate_limit_ceiling,
            Duration::from_secs(300)
        );
    }

    // A subsequent generic transient failure must clear the rate-limit surface
    // so `daemon status` does not continue to show "rate limited" after the
    // homeserver lifts the rate limit and the next failure is unrelated (issue #351).
    #[test]
    fn record_failure_clears_rate_limited_secs() {
        let mut h = SyncHealth::initializing(false);
        h.record_rate_limited(Duration::from_secs(30));
        assert_eq!(h.rate_limited_secs, Some(30), "precondition");
        h.record_failure("network blip");
        assert_eq!(
            h.rate_limited_secs, None,
            "generic transient must supersede an earlier rate-limit pause"
        );
        assert!(
            !h.to_json().contains("rate_limited_secs"),
            "cleared field must be absent from JSON"
        );
    }

    // A fatal failure must also clear the rate-limit surface so a dead loop
    // does not persist a stale "rate limited" annotation.
    #[test]
    fn record_fatal_clears_rate_limited_secs() {
        let mut h = SyncHealth::initializing(false);
        h.record_rate_limited(Duration::from_secs(60));
        assert_eq!(h.rate_limited_secs, Some(60), "precondition");
        h.record_fatal("token revoked");
        assert_eq!(
            h.rate_limited_secs, None,
            "fatal failure must clear a prior rate-limit annotation"
        );
        assert_eq!(h.state, SyncState::Stopped);
        assert!(
            !h.to_json().contains("rate_limited_secs"),
            "cleared field must be absent from JSON after fatal"
        );
    }

    // Edge cases for `rate_limit_retry_after`:
    //   - `Delay(ZERO)` → `Some(ZERO)` (a zero server delay is honored, not filtered)
    //   - `Delay(ceiling)` exactly → `Some(ceiling)` (boundary: min(ceiling, ceiling))
    //   - `DateTime(now)` exactly → `Some(ZERO)` (now - now = zero, same as a past instant)
    #[test]
    fn rate_limit_retry_after_boundary_edges() {
        let ceiling = Duration::from_secs(120);
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);

        // A zero server delay is returned as `Some(ZERO)`, not `None`.
        let kind = limit_exceeded(Some(RetryAfter::Delay(Duration::ZERO)));
        assert_eq!(
            rate_limit_retry_after(&kind, now, ceiling),
            Some(Duration::ZERO),
            "zero delay must be honored as Some(ZERO)"
        );

        // A delay exactly at the ceiling is returned verbatim (min(ceiling, ceiling)).
        let kind = limit_exceeded(Some(RetryAfter::Delay(ceiling)));
        assert_eq!(
            rate_limit_retry_after(&kind, now, ceiling),
            Some(ceiling),
            "delay exactly at ceiling must not be clamped further"
        );

        // A `DateTime` exactly at `now` collapses to zero (not negative, not None).
        let kind = limit_exceeded(Some(RetryAfter::DateTime(now)));
        assert_eq!(
            rate_limit_retry_after(&kind, now, ceiling),
            Some(Duration::ZERO),
            "DateTime(now) must collapse to ZERO"
        );
    }

    // The sync loop advances the exponential floor on each rate-limited step,
    // so repeated 429s ratchet the wait upward rather than hammering at exactly
    // the server minimum (issue #351).  This tests the `Backoff` state machine
    // in isolation using the same `floor = backoff.next_delay(); delay = server.max(floor)`
    // idiom the loop uses.
    #[test]
    fn backoff_floor_ratchets_under_repeated_rate_limits() {
        let mut b = Backoff::new(BackoffConfig {
            base: Duration::from_secs(1),
            max: Duration::from_secs(8),
            factor: 2,
            rate_limit_ceiling: Duration::from_secs(300),
        });
        // Server sends a very short retry delay (100 ms) — the floor should dominate
        // on all four attempts, and the floor should double each time.
        let server = Duration::from_millis(100);

        let floor0 = b.next_delay(); // attempt 0 → 1s
        assert_eq!(floor0, Duration::from_secs(1));
        assert_eq!(server.max(floor0), Duration::from_secs(1));

        let floor1 = b.next_delay(); // attempt 1 → 2s (ratcheted)
        assert_eq!(floor1, Duration::from_secs(2));
        assert_eq!(server.max(floor1), Duration::from_secs(2));

        let floor2 = b.next_delay(); // attempt 2 → 4s
        assert_eq!(floor2, Duration::from_secs(4));
        assert_eq!(server.max(floor2), Duration::from_secs(4));

        let floor3 = b.next_delay(); // attempt 3 → 8s (capped by max)
        assert_eq!(floor3, Duration::from_secs(8));
        assert_eq!(server.max(floor3), Duration::from_secs(8));

        // A large server delay supersedes the floor even at the cap.
        let large_server = Duration::from_secs(50);
        let floor4 = b.next_delay(); // attempt 4 → still 8s (capped)
        assert_eq!(floor4, Duration::from_secs(8));
        assert_eq!(
            large_server.max(floor4),
            Duration::from_secs(50),
            "server delay exceeding the floor must be honored"
        );

        // After a success the floor resets to base.
        b.reset();
        assert_eq!(
            b.next_delay(),
            Duration::from_secs(1),
            "reset must restore base"
        );
    }

    // A rate-limited step is honored (not treated as fatal): the loop records
    // the rate-limited pause and keeps running.
    #[tokio::test]
    async fn loop_honors_rate_limit_and_records_health() {
        let _data = TempData::new("ratelimit");
        let paths = SessionPaths::resolve();
        let health = Arc::new(Mutex::new(SyncHealth::initializing(false)));
        let running = Arc::new(AtomicBool::new(true));
        let running_step = running.clone();

        run_sync_loop(
            &paths,
            health.clone(),
            fast_backoff(),
            running.clone(),
            move |_token| {
                let running = running_step.clone();
                async move {
                    // Stop after this iteration so the loop exits right after
                    // honoring the rate limit (record_stopped does not clear the
                    // rate-limited surface), leaving it observable.
                    running.store(false, Ordering::SeqCst);
                    Err::<String, _>(StepError::RateLimited {
                        retry_after: Some(Duration::from_millis(1)),
                    })
                }
            },
        )
        .await
        .unwrap();

        let h = health.lock().unwrap();
        // It recorded a rate-limit pause (not record_fatal, which clears it).
        assert_eq!(h.rate_limited_secs, Some(0));
        assert_eq!(h.consecutive_failures, 1);
        assert!(h
            .last_error
            .as_deref()
            .is_some_and(|e| e.contains("rate limited")));
    }

    // The loop recovers to Healthy after rate limits, exercising both the
    // server-directed (`Some`) and fall-back-to-backoff (`None`) paths.
    #[tokio::test]
    async fn loop_recovers_after_rate_limit() {
        let _data = TempData::new("ratelimitrecover");
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
                    match n {
                        0 => Err(StepError::RateLimited {
                            retry_after: Some(Duration::from_millis(1)),
                        }),
                        // No server delay -> falls back to the exponential floor.
                        1 => Err(StepError::RateLimited { retry_after: None }),
                        2 => Ok("recovered".to_string()),
                        _ => {
                            running.store(false, Ordering::SeqCst);
                            Ok("final".to_string())
                        }
                    }
                }
            },
        )
        .await
        .unwrap();

        let h = health.lock().unwrap();
        // At least one success happened after the rate limits — they were
        // honored and retried, never treated as fatal. (The loop ends in
        // `Stopped` via the clean shutdown, as the transient-recovery test
        // above also relies on, so state is not asserted here.)
        assert!(h.total_syncs >= 1, "should recover after rate limits");
        assert!(h.rate_limited_secs.is_none(), "cleared on success");
    }
}
