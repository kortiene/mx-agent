//! Heartbeat emission and liveness calculation.
//!
//! Agents advertise themselves with a durable `com.mxagent.agent.v1` state
//! event (see [`crate::agent`]). That state alone cannot tell a peer whether an
//! agent is still running: room state is last-write-wins and does not expire.
//! To answer "is this agent alive right now?", an agent periodically emits a
//! lightweight `com.mxagent.heartbeat.v1` **timeline** event, and peers combine
//! the most recent heartbeat timestamp with the durable state to compute a
//! [`Liveness`] verdict (architecture §9.1, "Liveness should combine").
//!
//! Heartbeats are timeline events rather than state events on purpose: they are
//! frequent and ephemeral, so routing them through the timeline avoids churning
//! room state on every tick. The durable `last_seen_ts`/`status` fields in the
//! agent state are only refreshed when the status changes or after a longer
//! [`HeartbeatConfig::state_refresh`] interval, so steady-state heartbeats do
//! not produce excessive state-event updates.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use matrix_sdk::room::MessagesOptions;
use matrix_sdk::{Client, Room};
use mx_agent_protocol::events::state::AGENT as AGENT_STATE_TYPE;
use mx_agent_protocol::events::timeline::HEARTBEAT as HEARTBEAT_EVENT_TYPE;
use mx_agent_protocol::schema::{AgentLoad, AgentState, Heartbeat};

use crate::agent::{read_agent_state, read_all_agent_states};
use crate::scheduler_loop::sleep_interruptible;
use crate::workspace::{send_workspace_state, WorkspaceError};

/// Default interval between emitted heartbeats.
pub const DEFAULT_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);

/// Default time without a heartbeat after which an agent is considered stale.
///
/// Three missed heartbeats at the default interval.
pub const DEFAULT_STALE_AFTER: Duration = Duration::from_secs(90);

/// Default time without a heartbeat after which an agent is considered offline.
pub const DEFAULT_OFFLINE_AFTER: Duration = Duration::from_secs(300);

/// Default interval at which the durable agent state's `last_seen_ts` is
/// refreshed even when the status has not changed.
pub const DEFAULT_STATE_REFRESH: Duration = Duration::from_secs(300);

/// Per-page limit on recent timeline events scanned when resolving the latest
/// heartbeat per agent. One `/messages` request fetches at most this many
/// events; [`read_latest_heartbeats`] paginates backward up to
/// [`MAX_HEARTBEAT_SCAN_EVENTS`] in total. Consistent with the approval-decision
/// scan limit.
pub const HEARTBEAT_SCAN_LIMIT: u32 = 100;

/// Total upper bound on timeline events scanned (across all pages) by a single
/// [`read_latest_heartbeats`] call.
///
/// Heartbeats share the timeline with exec stream chunks, so on a busy room a
/// heartbeat can sit behind many newer events; a single
/// [`HEARTBEAT_SCAN_LIMIT`]-event page would silently miss it and degrade
/// liveness to durable-only. Paginating backward up to this bound (≈10 pages)
/// recovers the heartbeat while keeping a liveness query's cost bounded — a
/// hostile or pathological timeline cannot make the scan walk unbounded history.
/// The loop also stops early once every queried agent has a heartbeat, so the
/// common (quiet) case still ends after the first page.
pub const MAX_HEARTBEAT_SCAN_EVENTS: u32 = 1_000;

/// Upper bound on the per-agent durable-refresh timestamps tracked by
/// [`run_heartbeat_loop`] before the map is cleared, bounding memory on a
/// long-running daemon (mirrors the scheduler loop's tracking cap).
const MAX_TRACKED_AGENTS: usize = 50_000;

/// Liveness verdict for an agent, derived from heartbeat recency.
///
/// Serializes to/from a stable lowercase string (`"active"`/`"stale"`/
/// `"offline"`) so it can travel over IPC and appear in `--json` output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Liveness {
    /// Seen within the heartbeat window: actively running.
    Active,
    /// Missed several heartbeats but not yet timed out: possibly unhealthy.
    Stale,
    /// No heartbeat for the full offline timeout: presumed stopped/gone.
    Offline,
}

impl Liveness {
    /// Stable lowercase label used in human and JSON output.
    pub fn as_str(self) -> &'static str {
        match self {
            Liveness::Active => "active",
            Liveness::Stale => "stale",
            Liveness::Offline => "offline",
        }
    }
}

impl std::fmt::Display for Liveness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Thresholds used to translate heartbeat recency into a [`Liveness`] verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LivenessConfig {
    /// Elapsed time since the last heartbeat after which an agent is stale.
    pub stale_after: Duration,
    /// Elapsed time since the last heartbeat after which an agent is offline.
    pub offline_after: Duration,
}

impl Default for LivenessConfig {
    fn default() -> Self {
        Self {
            stale_after: DEFAULT_STALE_AFTER,
            offline_after: DEFAULT_OFFLINE_AFTER,
        }
    }
}

impl LivenessConfig {
    /// Compute the [`Liveness`] verdict for an agent last seen at `last_seen_ms`
    /// (ms since the Unix epoch) as of `now_ms`.
    ///
    /// A `last_seen_ms` in the future (clock skew) is clamped to "just seen" and
    /// reported as [`Liveness::Active`].
    pub fn liveness(&self, last_seen_ms: u64, now_ms: u64) -> Liveness {
        let elapsed = now_ms.saturating_sub(last_seen_ms);
        if elapsed >= self.offline_after.as_millis() as u64 {
            Liveness::Offline
        } else if elapsed >= self.stale_after.as_millis() as u64 {
            Liveness::Stale
        } else {
            Liveness::Active
        }
    }

    /// Compute the [`Liveness`] verdict for an [`AgentState`] as of `now_ms`,
    /// using its `last_seen_ts`.
    pub fn liveness_of(&self, state: &AgentState, now_ms: u64) -> Liveness {
        self.liveness(state.last_seen_ts, now_ms)
    }

    /// Compute the [`Liveness`] verdict by combining the durable agent state's
    /// `last_seen_ts` with the most recent heartbeat timeline event (architecture
    /// §9.1, "Liveness should combine … recent heartbeat event").
    ///
    /// The verdict is taken from whichever of the two is newer, so a healthy
    /// agent emitting timeline heartbeats every
    /// [`DEFAULT_HEARTBEAT_INTERVAL`] reads [`Liveness::Active`] between the
    /// rarer durable-state refreshes (the durable `last_seen_ts` is only
    /// rewritten every [`HeartbeatConfig::state_refresh`]). A `None`
    /// `latest_heartbeat_ts` falls back to [`Self::liveness_of`]. Future
    /// timestamps (clock skew) are clamped to "just seen" by [`Self::liveness`].
    pub fn liveness_combined(
        &self,
        state: &AgentState,
        latest_heartbeat_ts: Option<u64>,
        now_ms: u64,
    ) -> Liveness {
        let last_seen = state.last_seen_ts.max(latest_heartbeat_ts.unwrap_or(0));
        self.liveness(last_seen, now_ms)
    }
}

/// Configuration for periodic heartbeat emission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeartbeatConfig {
    /// Interval between emitted heartbeat timeline events.
    pub interval: Duration,
    /// Minimum interval between durable agent-state `last_seen_ts` refreshes,
    /// used to bound state-event churn when the status is unchanged.
    pub state_refresh: Duration,
}

impl Default for HeartbeatConfig {
    fn default() -> Self {
        Self {
            interval: DEFAULT_HEARTBEAT_INTERVAL,
            state_refresh: DEFAULT_STATE_REFRESH,
        }
    }
}

impl HeartbeatConfig {
    /// Decide whether the durable agent state should be refreshed.
    ///
    /// To avoid excessive state-event updates, the durable state is only
    /// rewritten when the reported status changes, or when at least
    /// `state_refresh` has elapsed since the last state write
    /// (`last_state_ms`).
    pub fn should_refresh_state(
        &self,
        status_changed: bool,
        last_state_ms: u64,
        now_ms: u64,
    ) -> bool {
        if status_changed {
            return true;
        }
        now_ms.saturating_sub(last_state_ms) >= self.state_refresh.as_millis() as u64
    }
}

/// Current epoch time in milliseconds.
pub(crate) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or_default()
}

/// Emit a single heartbeat for `agent_id` into `room`.
///
/// Always sends a `com.mxagent.heartbeat.v1` timeline event. Additionally, when
/// [`HeartbeatConfig::should_refresh_state`] indicates it is due (status change
/// or `state_refresh` elapsed), the durable `com.mxagent.agent.v1` state event
/// is rewritten with a fresh `last_seen_ts`/`status` and an advanced
/// `state_rev`. Returns `true` when the durable state was refreshed.
pub async fn emit_heartbeat(
    room: &Room,
    agent_id: &str,
    status: &str,
    config: &HeartbeatConfig,
    last_state_ms: u64,
) -> Result<bool, WorkspaceError> {
    let ts = now_ms();

    let existing = read_agent_state(room, agent_id).await?;
    // Publish the *live* in-flight count (issue #312) rather than carrying the
    // registration-time `0` forward. `max_invocations` is the agent's advertised
    // capacity, so it is preserved from the durable state.
    let load = AgentLoad {
        running_invocations: crate::inflight::running_invocations(agent_id),
        max_invocations: existing
            .as_ref()
            .map(|s| s.load.max_invocations)
            .unwrap_or(0),
    };

    let heartbeat = Heartbeat {
        agent_id: agent_id.to_string(),
        status: status.to_string(),
        load: load.clone(),
        ts,
        extra: Default::default(),
    };
    let content = serde_json::to_value(&heartbeat)
        .map_err(|e| WorkspaceError::from(matrix_sdk::Error::SerdeJson(e)))?;
    room.send_raw(HEARTBEAT_EVENT_TYPE, content)
        .await
        .map_err(WorkspaceError::from)?;

    let status_changed = existing
        .as_ref()
        .map(|s| s.status != status)
        .unwrap_or(true);
    if !config.should_refresh_state(status_changed, last_state_ms, ts) {
        return Ok(false);
    }

    if let Some(mut state) = existing {
        state.status = status.to_string();
        state.last_seen_ts = ts;
        // Reflect the live in-flight count in the durable state too, so
        // `agent show` reports real load between heartbeat ticks (issue #312).
        state.load = load.clone();
        state.state_rev += 1;
        let content = serde_json::to_value(&state)
            .map_err(|e| WorkspaceError::from(matrix_sdk::Error::SerdeJson(e)))?;
        send_workspace_state(room, AGENT_STATE_TYPE, agent_id, content).await?;
        Ok(true)
    } else {
        // No durable state to refresh; the timeline heartbeat still went out.
        Ok(false)
    }
}

/// Decide whether a heartbeat carrying `agent_id`, emitted by Matrix `sender`,
/// should be accepted given the `expected` `agent_id → matrix_user_id` map.
///
/// A heartbeat is accepted only when its `agent_id` is a known registered agent
/// **and** the homeserver-asserted event `sender` equals that agent's registered
/// `matrix_user_id` (issue #312). This pins the display-only heartbeat plane to
/// the registered sender so a room member cannot spoof a `com.mxagent.heartbeat.v1`
/// for another agent's `agent_id` and inflate its verdict. It is a display guard,
/// not an authorization input: dispatch authority remains signature → trust →
/// policy → approval regardless.
fn accept_heartbeat(expected: &HashMap<&str, &str>, agent_id: &str, sender: Option<&str>) -> bool {
    match (expected.get(agent_id), sender) {
        (Some(&registered), Some(sender)) => registered == sender,
        // Unknown agent, or an event with no `sender` field: reject.
        _ => false,
    }
}

/// Read the most recent `com.mxagent.heartbeat.v1` timeline event per agent in
/// `room`, accepting only heartbeats whose sender matches the registered agent.
///
/// Scans the timeline newest-first, keeping the **first (newest)** heartbeat seen
/// per `agent_id`, mirroring [`crate::approval::read_approval_decisions`]. Each
/// heartbeat is sender-pinned via [`accept_heartbeat`]: its `agent_id` must name
/// an agent in `agents` and the event `sender` must equal that agent's
/// `matrix_user_id`, so a spoofed heartbeat from any other member is ignored.
///
/// The scan paginates `/messages` backward, one [`HEARTBEAT_SCAN_LIMIT`]-event
/// page at a time, up to `max_events` total (callers pass
/// [`MAX_HEARTBEAT_SCAN_EVENTS`]). It stops early once every agent in `agents`
/// has a heartbeat — the common quiet case ends after the first page — so exec
/// stream chunks sharing the timeline cannot evict heartbeats from the scan
/// window on a busy room. The bound caps a liveness query's cost.
///
/// The returned timestamps feed [`LivenessConfig::liveness_combined`] so a
/// liveness verdict reflects the 30s timeline heartbeat cadence rather than the
/// slower durable-state refresh.
///
/// No server-side event-type filter is applied: in an encrypted room a heartbeat
/// is an `m.room.encrypted` event on the wire, so a `types` filter on the inner
/// `com.mxagent.heartbeat.v1` type would match nothing and *hide* heartbeats
/// there. Bounded pagination is the load-bearing mechanism and works in both
/// encrypted and unencrypted rooms (`/messages` decrypts what it returns).
pub async fn read_latest_heartbeats(
    room: &Room,
    agents: &[AgentState],
    max_events: u32,
) -> Result<HashMap<String, Heartbeat>, WorkspaceError> {
    // Expected sender per agent for the per-event sender pin.
    let expected: HashMap<&str, &str> = agents
        .iter()
        .map(|a| (a.agent_id.as_str(), a.matrix_user_id.as_str()))
        .collect();
    // With no agents to pin to, every heartbeat would be rejected; skip the scan.
    if expected.is_empty() {
        return Ok(HashMap::new());
    }

    let mut latest: HashMap<String, Heartbeat> = HashMap::new();
    let mut from: Option<String> = None;
    let mut scanned: u32 = 0;

    while scanned < max_events {
        let mut request = MessagesOptions::backward();
        request.limit = matrix_sdk::ruma::UInt::from(HEARTBEAT_SCAN_LIMIT);
        request.from = from.clone();
        let messages = room.messages(request).await.map_err(WorkspaceError::from)?;
        if messages.chunk.is_empty() {
            break;
        }
        for event in &messages.chunk {
            scanned += 1;
            let raw = event.raw();
            let is_heartbeat = raw.get_field::<String>("type").ok().flatten().as_deref()
                == Some(HEARTBEAT_EVENT_TYPE);
            if !is_heartbeat {
                continue;
            }
            let sender = raw.get_field::<String>("sender").ok().flatten();
            if let Ok(Some(heartbeat)) = raw.get_field::<Heartbeat>("content") {
                if !accept_heartbeat(&expected, &heartbeat.agent_id, sender.as_deref()) {
                    // Spoofed (sender mismatch) or unknown agent: ignore.
                    continue;
                }
                // Newest-first scan: the first occurrence per agent_id wins.
                latest
                    .entry(heartbeat.agent_id.clone())
                    .or_insert(heartbeat);
            }
        }
        // Every queried agent now has a heartbeat: nothing older can improve the
        // result, so stop (the common case after the first page).
        if expected.keys().all(|id| latest.contains_key(*id)) {
            break;
        }
        match messages.end {
            Some(end) => from = Some(end),
            // No earlier pagination token: the timeline is exhausted.
            None => break,
        }
    }
    Ok(latest)
}

/// Return the agents in `agents` owned by `local_user` (those whose
/// `matrix_user_id` matches), in input order.
///
/// Room membership never implies ownership: the heartbeat loop only refreshes
/// liveness for agents this daemon's Matrix user published, so it never
/// impersonates another daemon's agent.
fn owned_agents<'a>(agents: &'a [AgentState], local_user: &str) -> Vec<&'a AgentState> {
    agents
        .iter()
        .filter(|agent| agent.matrix_user_id == local_user)
        .collect()
}

/// Return the durable-refresh timestamp the loop should pass to
/// [`emit_heartbeat`] for an agent, seeding a first sighting from the agent's
/// discovered `last_seen_ts`.
///
/// Seeding from `last_seen_ts` (rather than `0`) means a freshly registered
/// agent is not forced into an immediate extra durable-state write on the loop's
/// first pass: [`HeartbeatConfig::should_refresh_state`] only fires once
/// `state_refresh` has elapsed since that stamp.
fn stored_last_state_ms(
    tracked: &mut HashMap<(String, String), u64>,
    key: (String, String),
    discovered_last_seen_ts: u64,
) -> u64 {
    *tracked.entry(key).or_insert(discovered_last_seen_ts)
}

/// Run the live heartbeat loop until `running` is cleared.
///
/// On its own dedicated thread (the caller spawns it), this builds a
/// current-thread Tokio runtime, then repeatedly — every `interval` — emits a
/// heartbeat for every agent this daemon owns in every joined room. It shares
/// the daemon's Matrix `client` and never runs its own `/sync`, so it reads room
/// state populated by the main sync loop and only sends events; only the main
/// loop owns the session token (mirroring [`crate::run_scheduler_loop`]). All
/// Matrix and store errors are logged and skipped so a transient failure never
/// stops the loop or panics the daemon.
pub fn run_heartbeat_loop(
    client: Client,
    running: Arc<AtomicBool>,
    config: HeartbeatConfig,
    interval: Duration,
) {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(e) => {
            tracing::error!(error = %e, "failed to build heartbeat runtime; heartbeat loop not started");
            return;
        }
    };
    // Per-agent last durable state-refresh time, keyed by `(room_id, agent_id)`,
    // so each agent's `state_refresh` cadence is honored across ticks. Capped to
    // bound memory on a long-lived daemon.
    let mut last_state_ms: HashMap<(String, String), u64> = HashMap::new();
    tracing::info!(interval_secs = interval.as_secs(), "heartbeat loop started");
    while running.load(Ordering::SeqCst) {
        if last_state_ms.len() > MAX_TRACKED_AGENTS {
            last_state_ms.clear();
        }
        heartbeat_pass(&runtime, &client, &config, &mut last_state_ms);
        sleep_interruptible(interval, &running);
    }
    tracing::info!("heartbeat loop stopped");
}

/// Perform one heartbeat pass over every joined room.
///
/// For each room, reads the published agent states, filters to agents this
/// daemon owns, and emits a heartbeat for each. A `true` return from
/// [`emit_heartbeat`] (the durable state was refreshed) advances the agent's
/// tracked `last_state_ms` to now so the next refresh is one `state_refresh`
/// away.
fn heartbeat_pass(
    runtime: &tokio::runtime::Runtime,
    client: &Client,
    config: &HeartbeatConfig,
    last_state_ms: &mut HashMap<(String, String), u64>,
) {
    let local_user = client.user_id().map(|u| u.to_string()).unwrap_or_default();
    if local_user.is_empty() {
        return;
    }

    for room in client.joined_rooms() {
        let room_id = room.room_id().to_string();
        let agents = match runtime.block_on(read_all_agent_states(&room)) {
            Ok(agents) => agents,
            Err(e) => {
                tracing::debug!(error = %e, room = %room_id, "heartbeat pass could not read agent states");
                continue;
            }
        };
        for agent in owned_agents(&agents, &local_user) {
            let key = (room_id.clone(), agent.agent_id.clone());
            let stored = stored_last_state_ms(last_state_ms, key.clone(), agent.last_seen_ts);
            match runtime.block_on(emit_heartbeat(
                &room,
                &agent.agent_id,
                &agent.status,
                config,
                stored,
            )) {
                Ok(true) => {
                    last_state_ms.insert(key, now_ms());
                }
                Ok(false) => {}
                Err(e) => {
                    tracing::warn!(error = %e, room = %room_id, agent = %agent.agent_id, "heartbeat emit failed");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agent_state(last_seen_ts: u64, status: &str) -> AgentState {
        AgentState {
            agent_id: "developer-pi".to_string(),
            kind: "pi".to_string(),
            matrix_user_id: "@pi:matrix.org".to_string(),
            device_id: "DEV".to_string(),
            signing_key_id: String::new(),
            signing_public_key: None,
            status: status.to_string(),
            capabilities: vec![],
            tools: vec![],
            workspace: mx_agent_protocol::schema::AgentWorkspace {
                cwd: "/tmp".to_string(),
                project_id: String::new(),
                git_commit: String::new(),
            },
            load: AgentLoad {
                running_invocations: 0,
                max_invocations: 1,
            },
            last_seen_ts,
            state_rev: 1,
            extra: Default::default(),
        }
    }

    #[test]
    fn liveness_labels_are_stable() {
        assert_eq!(Liveness::Active.as_str(), "active");
        assert_eq!(Liveness::Stale.as_str(), "stale");
        assert_eq!(Liveness::Offline.as_str(), "offline");
        assert_eq!(Liveness::Stale.to_string(), "stale");
    }

    #[test]
    fn active_agent_within_window_is_active() {
        let cfg = LivenessConfig::default();
        let now = 1_000_000;
        // A heartbeat one interval ago is still well within the stale window.
        let last = now - DEFAULT_HEARTBEAT_INTERVAL.as_millis() as u64;
        assert_eq!(cfg.liveness(last, now), Liveness::Active);
    }

    #[test]
    fn stopped_agent_becomes_stale_after_timeout() {
        let cfg = LivenessConfig::default();
        let now = 1_000_000;
        // Just past the stale threshold but before offline.
        let last = now - DEFAULT_STALE_AFTER.as_millis() as u64;
        assert_eq!(cfg.liveness(last, now), Liveness::Stale);
        // Well past the offline threshold.
        let gone = now - (DEFAULT_OFFLINE_AFTER.as_millis() as u64 + 1);
        assert_eq!(cfg.liveness(gone, now), Liveness::Offline);
    }

    #[test]
    fn future_last_seen_is_treated_as_active() {
        let cfg = LivenessConfig::default();
        // Clock skew: last seen "in the future" clamps to elapsed 0 -> active.
        assert_eq!(cfg.liveness(2_000_000, 1_000_000), Liveness::Active);
    }

    #[test]
    fn liveness_of_uses_state_last_seen() {
        let cfg = LivenessConfig::default();
        let now = 1_000_000;
        let active = agent_state(now - 1_000, "active");
        let gone = agent_state(now - DEFAULT_OFFLINE_AFTER.as_millis() as u64 - 1, "active");
        assert_eq!(cfg.liveness_of(&active, now), Liveness::Active);
        assert_eq!(cfg.liveness_of(&gone, now), Liveness::Offline);
    }

    #[test]
    fn custom_thresholds_apply() {
        let cfg = LivenessConfig {
            stale_after: Duration::from_secs(10),
            offline_after: Duration::from_secs(20),
        };
        let now = 100_000;
        assert_eq!(cfg.liveness(now - 5_000, now), Liveness::Active);
        assert_eq!(cfg.liveness(now - 15_000, now), Liveness::Stale);
        assert_eq!(cfg.liveness(now - 25_000, now), Liveness::Offline);
    }

    #[test]
    fn state_refresh_skips_unchanged_status_within_interval() {
        let cfg = HeartbeatConfig::default();
        let now = 1_000_000;
        // Status unchanged and last state write was recent: skip the update.
        assert!(!cfg.should_refresh_state(false, now - 1_000, now));
    }

    #[test]
    fn state_refresh_fires_on_status_change() {
        let cfg = HeartbeatConfig::default();
        let now = 1_000_000;
        assert!(cfg.should_refresh_state(true, now - 1_000, now));
    }

    #[test]
    fn state_refresh_fires_after_interval() {
        let cfg = HeartbeatConfig::default();
        let now = 1_000_000;
        let stale_state = now - (DEFAULT_STATE_REFRESH.as_millis() as u64 + 1);
        assert!(cfg.should_refresh_state(false, stale_state, now));
    }

    #[test]
    fn defaults_are_sane() {
        let hb = HeartbeatConfig::default();
        assert_eq!(hb.interval, DEFAULT_HEARTBEAT_INTERVAL);
        let lv = LivenessConfig::default();
        assert!(lv.stale_after < lv.offline_after);
        assert!(DEFAULT_HEARTBEAT_INTERVAL < DEFAULT_STALE_AFTER);
    }

    #[test]
    fn liveness_combined_prefers_recent_heartbeat_over_stale_durable_state() {
        let cfg = LivenessConfig::default();
        let now = 1_000_000;
        // Durable state alone would be offline (well past 300s)...
        let state = agent_state(now - DEFAULT_OFFLINE_AFTER.as_millis() as u64 - 1, "active");
        assert_eq!(cfg.liveness_of(&state, now), Liveness::Offline);
        // ...but a heartbeat one interval ago keeps the agent active.
        let hb_ts = now - DEFAULT_HEARTBEAT_INTERVAL.as_millis() as u64;
        assert_eq!(
            cfg.liveness_combined(&state, Some(hb_ts), now),
            Liveness::Active
        );
    }

    #[test]
    fn liveness_combined_without_heartbeat_falls_back_to_durable_state() {
        let cfg = LivenessConfig::default();
        let now = 1_000_000;
        let gone = agent_state(now - DEFAULT_OFFLINE_AFTER.as_millis() as u64 - 1, "active");
        assert_eq!(
            cfg.liveness_combined(&gone, None, now),
            cfg.liveness_of(&gone, now)
        );
        assert_eq!(cfg.liveness_combined(&gone, None, now), Liveness::Offline);
    }

    #[test]
    fn liveness_combined_offline_when_both_signals_stale() {
        let cfg = LivenessConfig::default();
        let now = 1_000_000;
        let state = agent_state(now - DEFAULT_OFFLINE_AFTER.as_millis() as u64 - 1, "active");
        let hb_ts = now - DEFAULT_OFFLINE_AFTER.as_millis() as u64 - 1;
        assert_eq!(
            cfg.liveness_combined(&state, Some(hb_ts), now),
            Liveness::Offline
        );
    }

    #[test]
    fn liveness_combined_clamps_future_heartbeat_to_active() {
        let cfg = LivenessConfig::default();
        let state = agent_state(0, "active");
        // A heartbeat "in the future" (clock skew) clamps to just-seen -> active.
        assert_eq!(
            cfg.liveness_combined(&state, Some(2_000_000), 1_000_000),
            Liveness::Active
        );
    }

    #[test]
    fn liveness_serde_roundtrips_as_lowercase() {
        for (variant, text) in [
            (Liveness::Active, "\"active\""),
            (Liveness::Stale, "\"stale\""),
            (Liveness::Offline, "\"offline\""),
        ] {
            let encoded = serde_json::to_string(&variant).unwrap();
            assert_eq!(encoded, text);
            let decoded: Liveness = serde_json::from_str(text).unwrap();
            assert_eq!(decoded, variant);
        }
    }

    #[test]
    fn accept_heartbeat_pins_to_registered_sender() {
        // `developer-pi` is registered as `@pi:matrix.org`.
        let expected: HashMap<&str, &str> =
            [("developer-pi", "@pi:matrix.org")].into_iter().collect();

        // Genuine sender for a known agent is accepted.
        assert!(accept_heartbeat(
            &expected,
            "developer-pi",
            Some("@pi:matrix.org")
        ));
        // A different room member spoofing the agent's heartbeat is rejected.
        assert!(!accept_heartbeat(
            &expected,
            "developer-pi",
            Some("@mallory:matrix.org")
        ));
        // An unknown agent_id is rejected even with a plausible sender.
        assert!(!accept_heartbeat(
            &expected,
            "ghost-agent",
            Some("@pi:matrix.org")
        ));
        // A heartbeat with no `sender` field is rejected.
        assert!(!accept_heartbeat(&expected, "developer-pi", None));
    }

    #[test]
    fn owned_agents_returns_only_local_user_agents() {
        let mine = {
            let mut a = agent_state(0, "active");
            a.agent_id = "mine".to_string();
            a.matrix_user_id = "@me:server".to_string();
            a
        };
        let theirs = {
            let mut a = agent_state(0, "active");
            a.agent_id = "theirs".to_string();
            a.matrix_user_id = "@other:server".to_string();
            a
        };
        let agents = vec![mine, theirs];
        let owned: Vec<&str> = owned_agents(&agents, "@me:server")
            .iter()
            .map(|a| a.agent_id.as_str())
            .collect();
        assert_eq!(owned, vec!["mine"]);
        assert!(owned_agents(&agents, "@nobody:server").is_empty());
    }

    #[test]
    fn stored_last_state_ms_seeds_then_advances() {
        let mut tracked: HashMap<(String, String), u64> = HashMap::new();
        let key = ("!room:server".to_string(), "agent-a".to_string());
        // First sight seeds from the discovered last_seen_ts (no forced refresh).
        assert_eq!(
            stored_last_state_ms(&mut tracked, key.clone(), 1_234),
            1_234
        );
        // A `true` emit_heartbeat return advances the stored value to "now".
        tracked.insert(key.clone(), 9_999);
        // The advanced value is now returned, not the original seed.
        assert_eq!(stored_last_state_ms(&mut tracked, key, 1_234), 9_999);
    }

    #[test]
    fn liveness_combined_stale_heartbeat_produces_stale_verdict() {
        let cfg = LivenessConfig::default();
        let now = 1_000_000;
        // Durable state is offline (elapsed >> 300s)...
        let state = agent_state(now - DEFAULT_OFFLINE_AFTER.as_millis() as u64 - 1, "active");
        assert_eq!(cfg.liveness_of(&state, now), Liveness::Offline);
        // ...but a heartbeat within the stale window (past stale threshold, before offline threshold)
        // means the combined verdict is Stale, not Offline.
        let hb_ts = now - (DEFAULT_STALE_AFTER.as_millis() as u64 + 1_000);
        assert!(
            hb_ts > now - DEFAULT_OFFLINE_AFTER.as_millis() as u64,
            "heartbeat is in the stale window"
        );
        assert_eq!(
            cfg.liveness_combined(&state, Some(hb_ts), now),
            Liveness::Stale
        );
    }

    #[test]
    fn liveness_combined_active_heartbeat_overrides_stale_durable_state() {
        // A heartbeat within the active window keeps the verdict Active even when
        // the durable state alone would be Stale (common during normal operation
        // between the slower durable-state refresh cadence).
        let cfg = LivenessConfig::default();
        let now = 1_000_000;
        // Durable state is just past the stale threshold.
        let state = agent_state(now - DEFAULT_STALE_AFTER.as_millis() as u64 - 1, "active");
        assert_eq!(cfg.liveness_of(&state, now), Liveness::Stale);
        // A heartbeat one interval ago (well within the stale window) lifts to Active.
        let hb_ts = now - DEFAULT_HEARTBEAT_INTERVAL.as_millis() as u64;
        assert_eq!(
            cfg.liveness_combined(&state, Some(hb_ts), now),
            Liveness::Active
        );
    }

    #[test]
    fn accept_heartbeat_rejects_all_when_expected_map_is_empty() {
        // When no agents are registered in the expected map (e.g. read_latest_heartbeats
        // was called with an empty agents slice and the early-exit was bypassed, or
        // a test exercises the predicate directly), every heartbeat must be rejected.
        let expected: HashMap<&str, &str> = HashMap::new();
        assert!(!accept_heartbeat(
            &expected,
            "any-agent",
            Some("@any:server")
        ));
        assert!(!accept_heartbeat(&expected, "any-agent", None));
        assert!(!accept_heartbeat(&expected, "", Some("@any:server")));
    }

    #[test]
    fn accept_heartbeat_handles_multiple_agents_independently() {
        // Two agents are registered; each is pinned to its own sender. Cross-sender
        // spoofing (alice heartbeating for agent-b) must be rejected for each agent.
        let expected: HashMap<&str, &str> =
            [("agent-a", "@alice:server"), ("agent-b", "@bob:server")]
                .into_iter()
                .collect();

        // Each agent's genuine sender is accepted.
        assert!(accept_heartbeat(
            &expected,
            "agent-a",
            Some("@alice:server")
        ));
        assert!(accept_heartbeat(&expected, "agent-b", Some("@bob:server")));
        // Cross-sender: alice cannot send a heartbeat for agent-b.
        assert!(!accept_heartbeat(
            &expected,
            "agent-b",
            Some("@alice:server")
        ));
        // Cross-sender: bob cannot send a heartbeat for agent-a.
        assert!(!accept_heartbeat(&expected, "agent-a", Some("@bob:server")));
        // Unknown agent is rejected even when the sender is a registered user.
        assert!(!accept_heartbeat(
            &expected,
            "agent-c",
            Some("@alice:server")
        ));
        // Missing sender for a known agent is rejected.
        assert!(!accept_heartbeat(&expected, "agent-a", None));
    }

    // Compile-time sanity: MAX_HEARTBEAT_SCAN_EVENTS must exceed the per-page
    // HEARTBEAT_SCAN_LIMIT and cover at least two full pages so the pagination
    // loop can actually cross page boundaries on busy timelines (issue #312).
    const _: () = assert!(MAX_HEARTBEAT_SCAN_EVENTS > HEARTBEAT_SCAN_LIMIT);
    const _: () = assert!(MAX_HEARTBEAT_SCAN_EVENTS >= HEARTBEAT_SCAN_LIMIT * 2);
}
