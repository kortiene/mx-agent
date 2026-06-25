//! Agent registration: publishing `com.mxagent.agent.v1` room state.
//!
//! An agent advertises itself in a workspace room by publishing a
//! `com.mxagent.agent.v1` state event keyed by its `agent_id` (see
//! `docs/architecture.md`, section 9.1). Peers read this state to discover
//! which agents are present, what kind they are, and what capabilities and
//! tools they offer.
//!
//! Because Matrix room state is last-write-wins per `(type, state_key)`,
//! re-registering the same `agent_id` updates the existing entry in place. The
//! prior `state_rev` is read first so the counter advances monotonically.

use std::collections::HashMap;
use std::future::Future;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use matrix_sdk::config::SyncSettings;
use matrix_sdk::ruma::events::StateEventType;
use matrix_sdk::{Client, Room};
use mx_agent_protocol::events::state::AGENT as AGENT_STATE_TYPE;
use mx_agent_protocol::schema::{AgentLoad, AgentState, AgentWorkspace, Heartbeat, ToolSchema};

use crate::heartbeat::{
    now_ms, read_latest_heartbeats, Liveness, LivenessConfig, MAX_HEARTBEAT_SCAN_EVENTS,
};
use crate::matrix::restore_client;
use crate::session::{SessionPaths, StoredSession};
use crate::signing::load_or_create_signing_key;
use crate::tools::ToolRegistry;
use crate::trust::{TrustStatus, TrustStore};
use crate::workspace::{
    git_output, parse_room_or_alias, resolve_room_id, send_workspace_state, WorkspaceError,
};

/// Default agent kind used when the caller does not specify one.
pub const DEFAULT_AGENT_KIND: &str = "generic";

/// Default maximum number of concurrent invocations advertised by an agent.
pub const DEFAULT_MAX_INVOCATIONS: u32 = 1;

/// Options for [`register_agent`].
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RegisterAgentOptions {
    /// Room ID or alias to register in.
    pub room: String,
    /// Agent identifier; also used as the state key. When `None`, an ID is
    /// derived from the Matrix user localpart and device ID.
    pub agent_id: Option<String>,
    /// Agent kind, e.g. `pi` or `generic`.
    pub kind: String,
    /// Declared capabilities.
    pub capabilities: Vec<String>,
    /// Available named tools.
    pub tools: Vec<String>,
    /// Working directory the agent operates in.
    pub cwd: String,
    /// Project identifier, e.g. `repo:github.com/org/project`.
    pub project_id: String,
    /// Maximum concurrent invocations the agent will accept.
    pub max_invocations: u32,
}

impl Default for RegisterAgentOptions {
    fn default() -> Self {
        Self {
            room: String::new(),
            agent_id: None,
            kind: DEFAULT_AGENT_KIND.to_string(),
            capabilities: Vec::new(),
            tools: Vec::new(),
            cwd: String::new(),
            project_id: String::new(),
            max_invocations: DEFAULT_MAX_INVOCATIONS,
        }
    }
}

/// Derive a stable `agent_id` from a Matrix user ID and device ID.
///
/// Uses the user's localpart (the `alice` in `@alice:server`) joined to the
/// device ID, e.g. `alice-MXAGENTDEVICE01`. Falls back to the full user ID when
/// it has no recognizable localpart.
fn derive_agent_id(matrix_user_id: &str, device_id: &str) -> String {
    let localpart = matrix_user_id
        .strip_prefix('@')
        .and_then(|rest| rest.split(':').next())
        .filter(|s| !s.is_empty())
        .unwrap_or(matrix_user_id);
    format!("{localpart}-{device_id}")
}

/// Register the calling agent in a workspace room.
///
/// Publishes a `com.mxagent.agent.v1` state event keyed by the agent ID,
/// carrying the agent's kind, capabilities, tools, load metrics, working
/// directory, project ID, and the current git commit when `cwd` is a git
/// repository. Re-registering the same agent ID overwrites the existing state
/// (last-write-wins) and advances `state_rev`.
pub async fn register_agent(
    client: &Client,
    options: &RegisterAgentOptions,
) -> Result<AgentState, WorkspaceError> {
    let id = parse_room_or_alias(&options.room)?;

    client
        .sync_once(SyncSettings::default())
        .await
        .map_err(WorkspaceError::from)?;

    let room_id = resolve_room_id(client, &id).await?;
    let room = client
        .get_room(&room_id)
        .ok_or_else(|| WorkspaceError::RoomNotFound(options.room.clone()))?;

    let matrix_user_id = client.user_id().map(|u| u.to_string()).unwrap_or_default();
    let device_id = client
        .device_id()
        .map(|d| d.to_string())
        .unwrap_or_default();
    let agent_id = options
        .agent_id
        .clone()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| derive_agent_id(&matrix_user_id, &device_id));

    let git_commit =
        git_output(Path::new(&options.cwd), &["rev-parse", "HEAD"]).unwrap_or_default();

    let last_seen_ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or_default();

    // Read the prior revision (if any) so we can advance `state_rev` and update
    // the existing state key in place.
    let previous = read_agent_state(&room, &agent_id).await?;
    let state_rev = previous.map(|a| a.state_rev + 1).unwrap_or(1);

    let signing = load_or_create_signing_key(&SessionPaths::resolve())
        .map_err(|e| WorkspaceError::InvalidTarget(format!("could not load signing key: {e}")))?;

    let state = AgentState {
        agent_id: agent_id.clone(),
        kind: options.kind.clone(),
        matrix_user_id,
        device_id,
        signing_key_id: signing.key_id(),
        signing_public_key: Some(signing.public_key_b64()),
        status: "active".to_string(),
        capabilities: options.capabilities.clone(),
        tools: options.tools.clone(),
        workspace: AgentWorkspace {
            cwd: options.cwd.clone(),
            project_id: options.project_id.clone(),
            git_commit,
        },
        load: AgentLoad {
            running_invocations: 0,
            max_invocations: options.max_invocations,
        },
        last_seen_ts,
        state_rev,
        extra: Default::default(),
    };

    let content = serde_json::to_value(&state)
        .map_err(|e| WorkspaceError::from(matrix_sdk::Error::SerdeJson(e)))?;
    send_workspace_state(&room, AGENT_STATE_TYPE, &agent_id, content).await?;

    // Anchor this daemon's own signing key in the local trust store (issue #309).
    // Approval-decision verification is now anchored to the trust store, and the
    // daemon signs its self-issued decisions with this key, so the daemon-only
    // approval default only works if its own key is locally `Trusted`. Seeding it
    // on registration removes a manual `trust approve` bootstrap step. An explicit
    // prior `Revoked` record is honoured (never overwritten), so a deliberate
    // revocation still takes effect.
    let paths = SessionPaths::resolve();
    let mut trust = TrustStore::load(&paths).unwrap_or_default();
    if seed_local_key_trust(
        &mut trust,
        &agent_id,
        &signing.key_id(),
        &signing.fingerprint(),
        room_id.as_str(),
        &state.matrix_user_id,
    ) {
        if let Err(e) = trust.save(&paths) {
            tracing::warn!(error = %e, "could not persist local signing key trust seed (issue #309)");
        }
    }

    Ok(state)
}

/// Seed the daemon's own signing key as [`TrustStatus::Trusted`] in `trust`,
/// unless it carries an explicit prior revocation (issue #309).
///
/// Returns `true` when `trust` was modified (the caller should persist it), and
/// `false` when no change was needed — either the key is already trusted, or the
/// operator explicitly [`Revoked`](TrustStatus::Revoked) it (which is honoured
/// and never silently re-trusted).
///
/// Anchoring approval decisions to the local trust store means the daemon must
/// trust the key it signs its own self-issued decisions with, or the daemon-only
/// approval default would reject them. Seeding the key here keeps trust
/// operator-revocable while making a fresh deployment work without a manual step.
fn seed_local_key_trust(
    trust: &mut TrustStore,
    agent_id: &str,
    key_id: &str,
    fingerprint: &str,
    room: &str,
    trusted_by: &str,
) -> bool {
    if trust
        .entry(agent_id, key_id)
        .is_some_and(|e| e.status == TrustStatus::Revoked)
    {
        return false;
    }
    if trust.is_trusted(agent_id, key_id) {
        return false;
    }
    trust.approve(
        agent_id,
        key_id,
        Some(fingerprint.to_string()),
        Some(room.to_string()),
        Some(trusted_by.to_string()),
    );
    true
}

/// Register an agent, restoring the authenticated client from `session`.
pub async fn register_agent_for_session(
    session: &StoredSession,
    options: &RegisterAgentOptions,
) -> Result<AgentState, WorkspaceError> {
    let client = restore_client(session).await?;
    register_agent(&client, options).await
}

/// Read the `com.mxagent.agent.v1` state event for `agent_id` from a room,
/// returning `None` when the agent has not registered yet.
pub(crate) async fn read_agent_state(
    room: &Room,
    agent_id: &str,
) -> Result<Option<AgentState>, WorkspaceError> {
    use matrix_sdk::deserialized_responses::RawAnySyncOrStrippedState as RawState;

    let raw = room
        .get_state_event(StateEventType::from(AGENT_STATE_TYPE), agent_id)
        .await
        .map_err(WorkspaceError::from)?;

    let content = match raw {
        Some(RawState::Sync(raw)) => raw.get_field::<AgentState>("content"),
        Some(RawState::Stripped(raw)) => raw.get_field::<AgentState>("content"),
        None => return Ok(None),
    }
    .map_err(|e| WorkspaceError::from(matrix_sdk::Error::SerdeJson(e)))?;

    Ok(content)
}

/// Options for [`list_agents`].
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ListAgentsOptions {
    /// Room ID or alias to list agents in.
    pub room: String,
    /// Capability filters. An agent is included only when it declares *every*
    /// capability listed here (logical AND). Empty means "no filter".
    pub capabilities: Vec<String>,
}

/// An agent's durable state plus the daemon-computed liveness verdict.
///
/// Returned by the liveness-enriched `agent list`/`agent show` IPC handlers so
/// the CLI stays stateless: the daemon owns the Matrix client and timeline, and
/// computes the [`Liveness`] verdict, while the CLI only renders the precomputed
/// envelope (architecture §9.1). The verdict combines the durable
/// `com.mxagent.agent.v1` `last_seen_ts` with the latest
/// `com.mxagent.heartbeat.v1` timeline event.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AgentListing {
    /// Durable `com.mxagent.agent.v1` state.
    pub agent: AgentState,
    /// Liveness verdict at the time of the query (`active`/`stale`/`offline`).
    pub liveness: Liveness,
}

/// View of the tools an agent offers, derived from its registered
/// [`AgentState`].
///
/// Reports the tools and capabilities the agent advertised at registration so
/// callers can discover what is on offer. Each advertised `name@version`
/// reference is resolved against the known tool registry into a full
/// [`ToolSchema`] when possible, so `agent tools` can display tool metadata
/// (name, version, description, and input/output schemas) rather than bare
/// references.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AgentTools {
    /// Agent identifier.
    pub agent_id: String,
    /// Agent kind, e.g. `pi`.
    pub kind: String,
    /// Current status, e.g. `active`.
    pub status: String,
    /// Declared capabilities.
    pub capabilities: Vec<String>,
    /// Advertised named tool references, e.g. `run_tests@1.0.0`.
    pub tools: Vec<String>,
    /// Full metadata for advertised tools that resolve against the registry.
    pub schemas: Vec<ToolSchema>,
}

impl AgentTools {
    /// Build a tools view from a registered agent state, resolving advertised
    /// tool references against the built-in [`ToolRegistry`].
    pub fn from_state(state: &AgentState) -> Self {
        Self::from_state_with_registry(state, &ToolRegistry::builtin())
    }

    /// Build a tools view, resolving advertised tool references against a
    /// caller-supplied registry.
    pub fn from_state_with_registry(state: &AgentState, registry: &ToolRegistry) -> Self {
        let schemas = state
            .tools
            .iter()
            .filter_map(|reference| registry.resolve(reference).cloned())
            .collect();
        Self {
            agent_id: state.agent_id.clone(),
            kind: state.kind.clone(),
            status: state.status.clone(),
            capabilities: state.capabilities.clone(),
            tools: state.tools.clone(),
            schemas,
        }
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

/// Read every `com.mxagent.agent.v1` state event from a room.
pub(crate) async fn read_all_agent_states(room: &Room) -> Result<Vec<AgentState>, WorkspaceError> {
    use matrix_sdk::deserialized_responses::RawAnySyncOrStrippedState as RawState;

    let raws = room
        .get_state_events(StateEventType::from(AGENT_STATE_TYPE))
        .await
        .map_err(WorkspaceError::from)?;

    let mut agents = Vec::with_capacity(raws.len());
    for raw in raws {
        let content = match raw {
            RawState::Sync(raw) => raw.get_field::<AgentState>("content"),
            RawState::Stripped(raw) => raw.get_field::<AgentState>("content"),
        }
        .map_err(|e| WorkspaceError::from(matrix_sdk::Error::SerdeJson(e)))?;
        // A removed agent leaves an empty state event behind; skip those.
        if let Some(agent) = content {
            agents.push(agent);
        }
    }
    Ok(agents)
}

/// Return `true` when `agent` declares every capability in `wanted` (logical
/// AND). An empty `wanted` always matches.
fn matches_capabilities(agent: &AgentState, wanted: &[String]) -> bool {
    wanted
        .iter()
        .all(|w| agent.capabilities.iter().any(|have| have == w))
}

/// List agents registered in a workspace room, optionally filtered by declared
/// capabilities.
///
/// Reads every `com.mxagent.agent.v1` state event in the room. When
/// `options.capabilities` is non-empty, only agents declaring *all* of the
/// requested capabilities are returned. Results are sorted by `agent_id` for a
/// stable, deterministic ordering.
pub async fn list_agents(
    client: &Client,
    options: &ListAgentsOptions,
) -> Result<Vec<AgentState>, WorkspaceError> {
    let room = sync_and_get_room(client, &options.room).await?;
    let mut agents = read_all_agent_states(&room).await?;
    agents.retain(|agent| matches_capabilities(agent, &options.capabilities));
    agents.sort_by(|a, b| a.agent_id.cmp(&b.agent_id));
    Ok(agents)
}

/// List agents in a workspace, restoring the authenticated client from
/// `session`.
pub async fn list_agents_for_session(
    session: &StoredSession,
    options: &ListAgentsOptions,
) -> Result<Vec<AgentState>, WorkspaceError> {
    let client = restore_client(session).await?;
    list_agents(&client, options).await
}

/// Show the registered state of a single agent in a workspace room.
///
/// Returns [`WorkspaceError::RoomNotFound`] semantics via `None` only when the
/// room is missing; an unregistered `agent_id` yields `Ok(None)`.
pub async fn show_agent(
    client: &Client,
    room: &str,
    agent_id: &str,
) -> Result<Option<AgentState>, WorkspaceError> {
    let room = sync_and_get_room(client, room).await?;
    read_agent_state(&room, agent_id).await
}

/// Show one agent, restoring the authenticated client from `session`.
pub async fn show_agent_for_session(
    session: &StoredSession,
    room: &str,
    agent_id: &str,
) -> Result<Option<AgentState>, WorkspaceError> {
    let client = restore_client(session).await?;
    show_agent(&client, room, agent_id).await
}

/// Attach a daemon-computed [`Liveness`] verdict to each `agent`, using the
/// latest heartbeat per agent in `room`.
///
/// The room's timeline is scanned (paginating backward up to
/// [`MAX_HEARTBEAT_SCAN_EVENTS`] events) with each heartbeat sender-pinned to the
/// registered agent, and the verdict is computed with
/// [`LivenessConfig::liveness_combined`], so a healthy agent reads `active`
/// between durable-state refreshes. A timeline read failure **or a timeout**
/// (see [`bounded_latest_heartbeats`], issue #368) degrades to durable-only
/// liveness (advisory signal, never hang or fail the query): the verdict falls
/// back to the durable `last_seen_ts`.
/// Wall-clock bound on the heartbeat-timeline read that backs a liveness verdict.
///
/// [`read_latest_heartbeats`] paginates `/messages`, a network round trip that can
/// block against a slow or unresponsive homeserver. The liveness-enriched IPC
/// handlers (`task.graph`, `agent.list`, `agent.show`) await it inline, and a
/// single IPC connection is served serially, so an unbounded read would hang the
/// handler *and* stall every request multiplexed behind it on that connection
/// (issue #368). Bounding it keeps those handlers responsive; on timeout the
/// verdict degrades to durable-only liveness, which is advisory anyway. 5s is the
/// trade-off: long enough for the heartbeat scan to complete against a healthy
/// homeserver (the common case exits after the first `/messages` page), short
/// enough that a stalled read cannot block the handler — or, since one IPC
/// connection is served serially, the requests multiplexed behind it — for long.
/// (Scope note: this bounds only the differential read that made task.graph hang
/// where task.list does not; the shared `sync_once` in `sync_and_get_room` and the
/// `/messages` scans in approval/context/artifact paths remain unbounded — a
/// separate, repo-wide hardening.)
const LIVENESS_ENRICHMENT_TIMEOUT: Duration = Duration::from_secs(5);

/// Run the heartbeat-timeline read under `timeout`, degrading to an empty map
/// (→ durable-only liveness) on either an error **or a timeout**.
///
/// `read_latest_heartbeats` already surfaces a failed read as `Err`, but a slow
/// homeserver makes the future *pend* rather than error, which `unwrap_or_else`
/// cannot catch — that is the indefinite `task.graph` hang in issue #368. Split
/// out so the bound is unit-testable without a live homeserver.
async fn bounded_latest_heartbeats(
    read: impl Future<Output = Result<HashMap<String, Heartbeat>, WorkspaceError>>,
    timeout: Duration,
) -> HashMap<String, Heartbeat> {
    match tokio::time::timeout(timeout, read).await {
        Ok(Ok(latest)) => latest,
        Ok(Err(e)) => {
            tracing::debug!(error = %e, "could not read heartbeats; using durable-only liveness");
            HashMap::new()
        }
        Err(_elapsed) => {
            tracing::warn!(
                timeout_ms = timeout.as_millis() as u64,
                "heartbeat timeline read timed out; using durable-only liveness (issue #368)"
            );
            HashMap::new()
        }
    }
}

async fn enrich_with_liveness(room: &Room, agents: Vec<AgentState>) -> Vec<AgentListing> {
    let latest = bounded_latest_heartbeats(
        read_latest_heartbeats(room, &agents, MAX_HEARTBEAT_SCAN_EVENTS),
        LIVENESS_ENRICHMENT_TIMEOUT,
    )
    .await;
    let cfg = LivenessConfig::default();
    let now = now_ms();
    agents
        .into_iter()
        .map(|agent| {
            let hb_ts = latest.get(&agent.agent_id).map(|h| h.ts);
            let liveness = cfg.liveness_combined(&agent, hb_ts, now);
            AgentListing { agent, liveness }
        })
        .collect()
}

/// List agents with a daemon-computed liveness verdict, restoring the
/// authenticated client from `session`.
///
/// Mirrors [`list_agents`] (same room resolution, capability filtering, and
/// `agent_id` ordering) but resolves the room once and reuses it to scan the
/// heartbeat timeline, returning [`AgentListing`]s rather than bare
/// [`AgentState`]s. The plain `list_agents` is left intact for the scheduler and
/// integration tests.
pub async fn list_agents_with_liveness_for_session(
    session: &StoredSession,
    options: &ListAgentsOptions,
) -> Result<Vec<AgentListing>, WorkspaceError> {
    let client = restore_client(session).await?;
    let room = sync_and_get_room(&client, &options.room).await?;
    let mut agents = read_all_agent_states(&room).await?;
    agents.retain(|agent| matches_capabilities(agent, &options.capabilities));
    agents.sort_by(|a, b| a.agent_id.cmp(&b.agent_id));
    Ok(enrich_with_liveness(&room, agents).await)
}

/// Show one agent with a daemon-computed liveness verdict, restoring the
/// authenticated client from `session`.
///
/// Returns `Ok(None)` when the agent has not registered, mirroring
/// [`show_agent`]; otherwise the room is reused to scan the heartbeat timeline
/// for the verdict.
pub async fn show_agent_with_liveness_for_session(
    session: &StoredSession,
    room: &str,
    agent_id: &str,
) -> Result<Option<AgentListing>, WorkspaceError> {
    let client = restore_client(session).await?;
    let room = sync_and_get_room(&client, room).await?;
    let Some(agent) = read_agent_state(&room, agent_id).await? else {
        return Ok(None);
    };
    Ok(enrich_with_liveness(&room, vec![agent]).await.pop())
}

/// Report the tools a single agent offers, derived from its registered state.
///
/// Placeholder behavior: returns the tools and capabilities advertised at
/// registration. Returns `Ok(None)` when the agent has not registered.
pub async fn agent_tools(
    client: &Client,
    room: &str,
    agent_id: &str,
) -> Result<Option<AgentTools>, WorkspaceError> {
    Ok(show_agent(client, room, agent_id)
        .await?
        .as_ref()
        .map(AgentTools::from_state))
}

/// Report an agent's tools, restoring the authenticated client from `session`.
pub async fn agent_tools_for_session(
    session: &StoredSession,
    room: &str,
    agent_id: &str,
) -> Result<Option<AgentTools>, WorkspaceError> {
    let client = restore_client(session).await?;
    agent_tools(&client, room, agent_id).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_agent_id_uses_localpart_and_device() {
        assert_eq!(
            derive_agent_id("@alice:matrix.org", "MXAGENTDEVICE01"),
            "alice-MXAGENTDEVICE01"
        );
    }

    #[test]
    fn derive_agent_id_falls_back_to_full_user_id() {
        assert_eq!(derive_agent_id("weird-id", "DEV"), "weird-id-DEV");
    }

    // --- liveness-enrichment bound (issue #368) -----------------------------

    fn sample_heartbeat(agent_id: &str) -> Heartbeat {
        Heartbeat {
            agent_id: agent_id.to_string(),
            status: "active".to_string(),
            load: AgentLoad {
                running_invocations: 0,
                max_invocations: 1,
            },
            ts: 1,
            extra: Default::default(),
        }
    }

    #[tokio::test]
    async fn bounded_latest_heartbeats_returns_value_when_ready() {
        let mut map = HashMap::new();
        map.insert("a-1".to_string(), sample_heartbeat("a-1"));
        let out = bounded_latest_heartbeats(async move { Ok(map) }, Duration::from_secs(5)).await;
        assert_eq!(out.len(), 1);
        assert!(out.contains_key("a-1"));
    }

    #[tokio::test]
    async fn bounded_latest_heartbeats_falls_back_on_error() {
        // A failed timeline read degrades to durable-only liveness (empty map),
        // never propagating the error to fail the query.
        let read = async { Err(WorkspaceError::RoomNotFound("nope".to_string())) };
        let out = bounded_latest_heartbeats(read, Duration::from_secs(5)).await;
        assert!(out.is_empty());
    }

    #[tokio::test]
    async fn bounded_latest_heartbeats_falls_back_on_timeout() {
        // Regression for #368: a heartbeat read that never completes must not
        // hang the liveness-enriched IPC handlers (task.graph / agent.list /
        // agent.show). It degrades to durable-only liveness within the bound
        // rather than pending forever — which `unwrap_or_else` could not catch.
        let never = std::future::pending::<Result<HashMap<String, Heartbeat>, WorkspaceError>>();
        let out = bounded_latest_heartbeats(never, Duration::from_millis(20)).await;
        assert!(out.is_empty());
    }

    // --- local signing-key trust seed (issue #309) --------------------------

    const SEED_KEY: &str = "mxagent-ed25519:local-seed";
    const SEED_AGENT: &str = "alice-DEV";

    #[test]
    fn seed_trusts_fresh_local_key() {
        // A fresh deployment: the daemon's own key is seeded Trusted so its
        // self-issued approval decisions survive the trust-store anchor.
        let mut trust = TrustStore::default();
        assert!(!trust.is_key_trusted(SEED_KEY));
        let changed = seed_local_key_trust(
            &mut trust,
            SEED_AGENT,
            SEED_KEY,
            "SHA256:local-seed",
            "!room:server",
            "@alice:server",
        );
        assert!(changed, "first seed must report a change to persist");
        assert!(trust.is_key_trusted(SEED_KEY));
    }

    #[test]
    fn seed_is_idempotent_when_already_trusted() {
        let mut trust = TrustStore::default();
        trust.approve(SEED_AGENT, SEED_KEY, None, None, None);
        let changed =
            seed_local_key_trust(&mut trust, SEED_AGENT, SEED_KEY, "SHA256:x", "!r:s", "@a:s");
        assert!(
            !changed,
            "re-seeding an already-trusted key must be a no-op"
        );
        assert!(trust.is_key_trusted(SEED_KEY));
    }

    #[test]
    fn seed_honours_explicit_revocation() {
        // An operator's deliberate revocation must never be overwritten by the
        // registration seed.
        let mut trust = TrustStore::default();
        trust.approve(SEED_AGENT, SEED_KEY, None, None, None);
        trust.revoke(SEED_AGENT, SEED_KEY);
        let changed =
            seed_local_key_trust(&mut trust, SEED_AGENT, SEED_KEY, "SHA256:x", "!r:s", "@a:s");
        assert!(!changed, "a revoked key must not be re-trusted by the seed");
        assert!(!trust.is_key_trusted(SEED_KEY));
    }

    fn sample_state(agent_id: &str, capabilities: &[&str], tools: &[&str]) -> AgentState {
        AgentState {
            agent_id: agent_id.to_string(),
            kind: "pi".to_string(),
            matrix_user_id: "@a:server".to_string(),
            device_id: "DEV".to_string(),
            signing_key_id: String::new(),
            signing_public_key: None,
            status: "active".to_string(),
            capabilities: capabilities.iter().map(|s| s.to_string()).collect(),
            tools: tools.iter().map(|s| s.to_string()).collect(),
            workspace: AgentWorkspace {
                cwd: "/tmp".to_string(),
                project_id: String::new(),
                git_commit: String::new(),
            },
            load: AgentLoad {
                running_invocations: 0,
                max_invocations: 1,
            },
            last_seen_ts: 0,
            state_rev: 1,
            extra: Default::default(),
        }
    }

    #[test]
    fn capability_filter_requires_all_capabilities() {
        let agent = sample_state("dev-pi", &["shell", "edit", "test"], &[]);
        assert!(matches_capabilities(&agent, &[]));
        assert!(matches_capabilities(&agent, &["shell".to_string()]));
        assert!(matches_capabilities(
            &agent,
            &["shell".to_string(), "test".to_string()]
        ));
        assert!(!matches_capabilities(&agent, &["deploy".to_string()]));
        assert!(!matches_capabilities(
            &agent,
            &["shell".to_string(), "deploy".to_string()]
        ));
    }

    #[test]
    fn agent_tools_view_is_derived_from_state() {
        let agent = sample_state("dev-pi", &["shell"], &["run_tests@1.0.0", "lint@1.0.0"]);
        let tools = AgentTools::from_state(&agent);
        assert_eq!(tools.agent_id, "dev-pi");
        assert_eq!(tools.kind, "pi");
        assert_eq!(tools.status, "active");
        assert_eq!(tools.capabilities, vec!["shell".to_string()]);
        assert_eq!(
            tools.tools,
            vec!["run_tests@1.0.0".to_string(), "lint@1.0.0".to_string()]
        );
        // Both advertised references resolve to built-in tool metadata.
        assert_eq!(tools.schemas.len(), 2);
        let names: Vec<&str> = tools.schemas.iter().map(|s| s.name.as_str()).collect();
        assert!(names.contains(&"run_tests"));
        assert!(names.contains(&"lint"));
    }

    #[test]
    fn agent_tools_view_skips_unknown_tool_references() {
        let agent = sample_state("dev-pi", &[], &["run_tests@1.0.0", "mystery@2.0.0"]);
        let tools = AgentTools::from_state(&agent);
        assert_eq!(tools.tools.len(), 2);
        // Only the known reference resolves to metadata.
        assert_eq!(tools.schemas.len(), 1);
        assert_eq!(tools.schemas[0].name, "run_tests");
    }

    #[test]
    fn default_options_are_generic_and_empty() {
        let opts = RegisterAgentOptions::default();
        assert_eq!(opts.kind, DEFAULT_AGENT_KIND);
        assert_eq!(opts.max_invocations, DEFAULT_MAX_INVOCATIONS);
        assert!(opts.capabilities.is_empty());
        assert!(opts.tools.is_empty());
        assert!(opts.agent_id.is_none());
    }
}
