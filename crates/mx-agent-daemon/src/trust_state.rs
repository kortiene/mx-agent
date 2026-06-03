//! Optional Matrix publication of trust state (architecture §13.2).
//!
//! The [`crate::trust`] module owns the daemon's *local* trust store, which is
//! the final authority on whether a signing key authorizes privileged
//! requests. This module adds an *optional* convenience layer on top: a daemon
//! (typically a room admin) may publish trust records to a workspace room as
//! `com.mxagent.trust.v1` state events so peers can discover them, and any
//! daemon may read them back.
//!
//! # Trust precedence
//!
//! Room-published trust is **advisory**. The local trust store always wins:
//!
//! 1. If the local store has a record for an `(agent_id, key_id)` pair, that
//!    record decides — including a local **revocation**, which overrides any
//!    room-published `trusted` state.
//! 2. Only when the local store has *no* record for the pair is the
//!    room-published state consulted, and then only a `trusted`, non-revoked
//!    record grants trust.
//!
//! [`effective_trust`] implements this precedence. Publication and reads never
//! mutate the local store; they only move advisory state in and out of Matrix.

use matrix_sdk::config::SyncSettings;
use matrix_sdk::ruma::events::StateEventType;
use matrix_sdk::{Client, Room};
use mx_agent_protocol::events::state::TRUST as TRUST_STATE_TYPE;
use mx_agent_protocol::schema::TrustState;

use crate::matrix::restore_client;
use crate::session::StoredSession;
use crate::trust::{TrustEntry, TrustStore};
use crate::workspace::{parse_room_or_alias, resolve_room_id, WorkspaceError};

/// Build the Matrix state key for a trust record: `<agent_id>|<key_id>`
/// (architecture §13.2).
pub fn trust_state_key(agent_id: &str, key_id: &str) -> String {
    format!("{agent_id}|{key_id}")
}

/// Format Unix seconds as an RFC 3339 UTC timestamp (`YYYY-MM-DDTHH:MM:SSZ`).
///
/// Uses Howard Hinnant's civil-from-days algorithm so no date library is
/// required. This is the inverse of the parser used for request-expiry checks
/// (see `crate::replay`).
fn unix_to_rfc3339(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let tod = (secs % 86_400) as i64;
    let (hour, minute, second) = (tod / 3600, (tod % 3600) / 60, tod % 60);

    // civil_from_days: days since 1970-01-01 -> (year, month, day).
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let day = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let month = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = if month <= 2 { y + 1 } else { y };

    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Convert a local [`TrustEntry`] into publishable `com.mxagent.trust.v1`
/// content.
///
/// `published_by` is used as the `trusted_by` identity when the entry does not
/// already record one (typically the publishing daemon's Matrix user ID).
pub fn trust_state_from_entry(entry: &TrustEntry, published_by: &str) -> TrustState {
    TrustState {
        agent_id: entry.agent_id.clone(),
        key_id: entry.key_id.clone(),
        fingerprint: entry.fingerprint.clone(),
        status: entry.status.to_string(),
        trusted_by: entry
            .trusted_by
            .clone()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| published_by.to_string()),
        created_at: unix_to_rfc3339(entry.created_at),
        expires_at: None,
        revoked_at: entry.revoked_at.map(unix_to_rfc3339),
        extra: Default::default(),
    }
}

/// Where an effective-trust decision came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustSource {
    /// Decided by the local trust store (final authority).
    Local,
    /// Decided by a room-published trust state event.
    Room,
    /// No record found in either place; trust defaults to denied.
    None,
}

/// The combined trust decision for an `(agent_id, key_id)` pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveTrust {
    /// Agent the key belongs to.
    pub agent_id: String,
    /// Signing key identifier.
    pub key_id: String,
    /// Whether the key is effectively trusted.
    pub trusted: bool,
    /// Which source decided the outcome.
    pub source: TrustSource,
}

/// Whether a room-published trust record currently grants trust.
///
/// Only a `trusted` record with no `revoked_at` counts; a published revocation
/// (or any other status) does not grant trust.
fn room_state_grants_trust(state: &TrustState) -> bool {
    state.status == "trusted" && state.revoked_at.is_none()
}

/// Combine the local trust store with room-published trust state, with the
/// local store as the final authority.
///
/// Precedence (see the module docs):
///
/// 1. A local record decides outright — a local revocation overrides any
///    room-published `trusted` state.
/// 2. Otherwise the room-published state is consulted, and only a `trusted`,
///    non-revoked record grants trust.
pub fn effective_trust(
    local: &TrustStore,
    room_states: &[TrustState],
    agent_id: &str,
    key_id: &str,
) -> EffectiveTrust {
    // 1. Local store is the final authority.
    if let Some(entry) = local.entry(agent_id, key_id) {
        return EffectiveTrust {
            agent_id: agent_id.to_string(),
            key_id: key_id.to_string(),
            trusted: entry.is_trusted(),
            source: TrustSource::Local,
        };
    }

    // 2. Fall back to room-published trust only when the local store is silent.
    let room_trusted = room_states
        .iter()
        .filter(|s| s.agent_id == agent_id && s.key_id == key_id)
        .any(room_state_grants_trust);

    EffectiveTrust {
        agent_id: agent_id.to_string(),
        key_id: key_id.to_string(),
        trusted: room_trusted,
        source: if room_trusted {
            TrustSource::Room
        } else {
            TrustSource::None
        },
    }
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

/// Publish a local trust record to a workspace room as a
/// `com.mxagent.trust.v1` state event keyed by `<agent_id>|<key_id>`.
///
/// Publishing is last-write-wins per `(type, state_key)`, so re-publishing the
/// same pair (for example after a local revocation) overwrites the prior state.
/// The local store is never modified by this call.
pub async fn publish_trust_state(
    client: &Client,
    room: &str,
    entry: &TrustEntry,
) -> Result<TrustState, WorkspaceError> {
    let room_handle = sync_and_get_room(client, room).await?;
    let published_by = client.user_id().map(|u| u.to_string()).unwrap_or_default();
    let state = trust_state_from_entry(entry, &published_by);
    let key = trust_state_key(&entry.agent_id, &entry.key_id);

    let content = serde_json::to_value(&state)
        .map_err(|e| WorkspaceError::from(matrix_sdk::Error::SerdeJson(e)))?;
    room_handle
        .send_state_event_raw(TRUST_STATE_TYPE, &key, content)
        .await
        .map_err(WorkspaceError::from)?;

    Ok(state)
}

/// Publish a trust record, restoring the authenticated client from `session`.
pub async fn publish_trust_state_for_session(
    session: &StoredSession,
    room: &str,
    entry: &TrustEntry,
) -> Result<TrustState, WorkspaceError> {
    let client = restore_client(session).await?;
    publish_trust_state(&client, room, entry).await
}

/// Read every `com.mxagent.trust.v1` state event from a room.
async fn read_all_trust_states(room: &Room) -> Result<Vec<TrustState>, WorkspaceError> {
    use matrix_sdk::deserialized_responses::RawAnySyncOrStrippedState as RawState;

    let raws = room
        .get_state_events(StateEventType::from(TRUST_STATE_TYPE))
        .await
        .map_err(WorkspaceError::from)?;

    let mut states = Vec::with_capacity(raws.len());
    for raw in raws {
        let content = match raw {
            RawState::Sync(raw) => raw.get_field::<TrustState>("content"),
            RawState::Stripped(raw) => raw.get_field::<TrustState>("content"),
        }
        .map_err(|e| WorkspaceError::from(matrix_sdk::Error::SerdeJson(e)))?;
        // A cleared trust record leaves an empty state event behind; skip those.
        if let Some(state) = content {
            states.push(state);
        }
    }
    Ok(states)
}

/// List the trust records published to a workspace room, sorted by
/// `(agent_id, key_id)` for a stable ordering.
pub async fn list_trust_states(
    client: &Client,
    room: &str,
) -> Result<Vec<TrustState>, WorkspaceError> {
    let room_handle = sync_and_get_room(client, room).await?;
    let mut states = read_all_trust_states(&room_handle).await?;
    states.sort_by(|a, b| {
        a.agent_id
            .cmp(&b.agent_id)
            .then_with(|| a.key_id.cmp(&b.key_id))
    });
    Ok(states)
}

/// List room-published trust records, restoring the client from `session`.
pub async fn list_trust_states_for_session(
    session: &StoredSession,
    room: &str,
) -> Result<Vec<TrustState>, WorkspaceError> {
    let client = restore_client(session).await?;
    list_trust_states(&client, room).await
}

/// The effective trust for every `(agent_id, key_id)` pair known to either the
/// local store or the room-published state, with local records taking
/// precedence.
pub fn effective_trust_table(
    local: &TrustStore,
    room_states: &[TrustState],
) -> Vec<EffectiveTrust> {
    let mut pairs: Vec<(String, String)> = Vec::new();
    let push = |agent: &str, key: &str, pairs: &mut Vec<(String, String)>| {
        let p = (agent.to_string(), key.to_string());
        if !pairs.contains(&p) {
            pairs.push(p);
        }
    };
    for e in local.entries() {
        push(&e.agent_id, &e.key_id, &mut pairs);
    }
    for s in room_states {
        push(&s.agent_id, &s.key_id, &mut pairs);
    }
    pairs.sort();
    pairs
        .iter()
        .map(|(agent, key)| effective_trust(local, room_states, agent, key))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trust::TrustStatus;

    const AGENT: &str = "developer-pi";
    const KEY: &str = "mxagent-ed25519:abc123";

    fn room_state(agent: &str, key: &str, status: &str, revoked: bool) -> TrustState {
        TrustState {
            agent_id: agent.to_string(),
            key_id: key.to_string(),
            fingerprint: "SHA256:abc123".to_string(),
            status: status.to_string(),
            trusted_by: "@owner:matrix.org".to_string(),
            created_at: "2026-06-02T12:00:00Z".to_string(),
            expires_at: None,
            revoked_at: if revoked {
                Some("2026-06-03T00:00:00Z".to_string())
            } else {
                None
            },
            extra: Default::default(),
        }
    }

    #[test]
    fn state_key_combines_agent_and_key() {
        assert_eq!(
            trust_state_key(AGENT, KEY),
            "developer-pi|mxagent-ed25519:abc123"
        );
    }

    #[test]
    fn unix_to_rfc3339_formats_known_instants() {
        assert_eq!(unix_to_rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(unix_to_rfc3339(10), "1970-01-01T00:00:10Z");
        assert_eq!(unix_to_rfc3339(946_684_800), "2000-01-01T00:00:00Z");
        assert_eq!(unix_to_rfc3339(1_748_865_600), "2025-06-02T12:00:00Z");
    }

    #[test]
    fn entry_round_trips_into_publishable_state() {
        let mut store = TrustStore::default();
        let entry = store.approve(AGENT, KEY, None, None, None);
        let state = trust_state_from_entry(&entry, "@owner:matrix.org");
        assert_eq!(state.agent_id, AGENT);
        assert_eq!(state.key_id, KEY);
        assert_eq!(state.status, "trusted");
        assert_eq!(state.trusted_by, "@owner:matrix.org");
        assert!(state.revoked_at.is_none());
    }

    #[test]
    fn published_revocation_carries_revoked_at() {
        let mut store = TrustStore::default();
        store.approve(AGENT, KEY, None, None, None);
        let entry = store.revoke(AGENT, KEY).unwrap();
        assert_eq!(entry.status, TrustStatus::Revoked);
        let state = trust_state_from_entry(&entry, "@owner:matrix.org");
        assert_eq!(state.status, "revoked");
        assert!(state.revoked_at.is_some());
    }

    #[test]
    fn local_revocation_overrides_room_published_trust() {
        // Room publishes the key as trusted...
        let room = vec![room_state(AGENT, KEY, "trusted", false)];
        // ...but the local store has revoked it.
        let mut store = TrustStore::default();
        store.approve(AGENT, KEY, None, None, None);
        store.revoke(AGENT, KEY);

        let decision = effective_trust(&store, &room, AGENT, KEY);
        assert!(
            !decision.trusted,
            "local revocation must override room-published trust"
        );
        assert_eq!(decision.source, TrustSource::Local);
    }

    #[test]
    fn local_approval_is_authoritative() {
        // Room publishes a revocation, but the local store trusts the key.
        let room = vec![room_state(AGENT, KEY, "revoked", true)];
        let mut store = TrustStore::default();
        store.approve(AGENT, KEY, None, None, None);

        let decision = effective_trust(&store, &room, AGENT, KEY);
        assert!(decision.trusted);
        assert_eq!(decision.source, TrustSource::Local);
    }

    #[test]
    fn room_trust_applies_only_when_local_is_silent() {
        let room = vec![room_state(AGENT, KEY, "trusted", false)];
        let store = TrustStore::default();

        let decision = effective_trust(&store, &room, AGENT, KEY);
        assert!(decision.trusted);
        assert_eq!(decision.source, TrustSource::Room);
    }

    #[test]
    fn published_revocation_does_not_grant_trust() {
        let room = vec![room_state(AGENT, KEY, "revoked", true)];
        let store = TrustStore::default();

        let decision = effective_trust(&store, &room, AGENT, KEY);
        assert!(!decision.trusted);
        assert_eq!(decision.source, TrustSource::None);
    }

    #[test]
    fn unknown_pair_is_untrusted() {
        let decision = effective_trust(&TrustStore::default(), &[], AGENT, KEY);
        assert!(!decision.trusted);
        assert_eq!(decision.source, TrustSource::None);
    }

    #[test]
    fn effective_table_merges_local_and_room_pairs() {
        let room = vec![
            room_state(AGENT, KEY, "trusted", false),
            room_state("other", "mxagent-ed25519:def", "trusted", false),
        ];
        let mut store = TrustStore::default();
        store.approve(AGENT, KEY, None, None, None);
        store.revoke(AGENT, KEY);

        let table = effective_trust_table(&store, &room);
        assert_eq!(table.len(), 2);
        let dev = table.iter().find(|t| t.agent_id == AGENT).unwrap();
        assert!(!dev.trusted);
        assert_eq!(dev.source, TrustSource::Local);
        let other = table.iter().find(|t| t.agent_id == "other").unwrap();
        assert!(other.trusted);
        assert_eq!(other.source, TrustSource::Room);
    }
}
