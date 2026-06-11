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

/// Upper bound on recent timeline events scanned per room when resolving the
/// latest heartbeat per agent. Bounds the cost of a liveness query, consistent
/// with the approval-decision scan limit.
pub const HEARTBEAT_SCAN_LIMIT: u32 = 100;

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
    let load = existing
        .as_ref()
        .map(|s| s.load.clone())
        .unwrap_or(AgentLoad {
            running_invocations: 0,
            max_invocations: 0,
        });

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

/// Read the most recent `com.mxagent.heartbeat.v1` timeline event per agent in
/// `room`.
///
/// Scans up to `limit` recent timeline events newest-first and keeps the **first
/// (newest)** heartbeat seen per `agent_id`, mirroring
/// [`crate::approval::read_approval_decisions`]. The returned timestamps feed
/// [`LivenessConfig::liveness_combined`] so a liveness verdict reflects the 30s
/// timeline heartbeat cadence rather than the slower durable-state refresh.
pub async fn read_latest_heartbeats(
    room: &Room,
    limit: u32,
) -> Result<HashMap<String, Heartbeat>, WorkspaceError> {
    let mut request = MessagesOptions::backward();
    request.limit = matrix_sdk::ruma::UInt::from(limit);
    let messages = room.messages(request).await.map_err(WorkspaceError::from)?;

    let mut latest: HashMap<String, Heartbeat> = HashMap::new();
    for event in messages.chunk {
        let raw = event.raw();
        let is_heartbeat =
            raw.get_field::<String>("type").ok().flatten().as_deref() == Some(HEARTBEAT_EVENT_TYPE);
        if !is_heartbeat {
            continue;
        }
        if let Ok(Some(heartbeat)) = raw.get_field::<Heartbeat>("content") {
            // Newest-first scan: the first occurrence per agent_id wins.
            latest
                .entry(heartbeat.agent_id.clone())
                .or_insert(heartbeat);
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
}
