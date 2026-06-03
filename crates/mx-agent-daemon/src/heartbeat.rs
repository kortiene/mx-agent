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

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use matrix_sdk::Room;
use mx_agent_protocol::events::state::AGENT as AGENT_STATE_TYPE;
use mx_agent_protocol::events::timeline::HEARTBEAT as HEARTBEAT_EVENT_TYPE;
use mx_agent_protocol::schema::{AgentLoad, AgentState, Heartbeat};

use crate::agent::read_agent_state;
use crate::workspace::WorkspaceError;

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

/// Liveness verdict for an agent, derived from heartbeat recency.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
fn now_ms() -> u64 {
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
        room.send_state_event_raw(AGENT_STATE_TYPE, agent_id, content)
            .await
            .map_err(WorkspaceError::from)?;
        Ok(true)
    } else {
        // No durable state to refresh; the timeline heartbeat still went out.
        Ok(false)
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
}
