# Issue #250 — Periodic heartbeat loop + agent liveness surfacing

## Problem Statement

The heartbeat primitive and the liveness math already exist and are unit-tested,
but nothing in a running daemon ever emits a heartbeat, and the CLI never shows
the computed verdict:

- `emit_heartbeat` (`crates/mx-agent-daemon/src/heartbeat.rs:167`) sends a
  `com.mxagent.heartbeat.v1` timeline event and, when due, refreshes the durable
  `com.mxagent.agent.v1` state's `last_seen_ts`/`status`/`state_rev`. It is only
  re-exported (`lib.rs:107`) and called by the live integration test — it has **no
  caller** in `crates/mx-agent-daemon/src` or `crates/mx-agent-cli/src`. No
  heartbeat task is spawned in `spawn_matrix_workers`
  (`crates/mx-agent-daemon/src/lifecycle.rs:300`).
- `LivenessConfig` (defaults: stale 90s, offline 300s; heartbeat interval 30s,
  state-refresh 300s) computes `Active`/`Stale`/`Offline` from a `last_seen_ts`,
  but no command surfaces it. `agent list` / `agent show` print only the raw
  `status` string (`crates/mx-agent-cli/src/cli.rs:1534`, `:1572`).

Consequences:

- An agent's `last_seen_ts` is stamped once at registration and never refreshed,
  so any consumer of liveness would watch even a healthy long-running agent drift
  `Active → Stale → Offline` after 90s/300s.
- Operators cannot see `stale`/`offline` through the documented commands.
- Roadmap Phase 4's "periodic heartbeat event" deliverable is therefore not
  actually delivered.

There is also a latent correctness trap: `DEFAULT_STATE_REFRESH` (300s) equals
`DEFAULT_OFFLINE_AFTER` (300s), and `liveness_of` reads only the **durable**
`last_seen_ts`. If liveness were computed purely from durable state, a perfectly
healthy agent emitting a 30s timeline heartbeat would still be reported `Stale`
at 90s and `Offline` at 300s, because the durable `last_seen_ts` is only rewritten
every 300s. Surfacing a verdict computed that way would surface a *wrong* verdict.
This spec therefore computes liveness from the **most recent heartbeat timeline
event** (falling back to durable `last_seen_ts`), which is exactly the
architecture §9.1 "Liveness should combine … recent heartbeat event" model and
makes the 30s timeline cadence the liveness signal while keeping durable-state
churn at the 300s refresh interval.

## Goals

- A daemon-owned heartbeat task that, for every agent this daemon owns, calls
  `emit_heartbeat` at `DEFAULT_HEARTBEAT_INTERVAL`, so `last_seen_ts` is refreshed
  and a fresh `com.mxagent.heartbeat.v1` timeline event is published every tick.
- The task is spawned alongside the sync and scheduler loops, shares the same
  restored Matrix client (no second `/sync`), stops cleanly on daemon shutdown,
  and never panics or exits on a transient Matrix error.
- `agent list` and `agent show` surface a `Liveness` verdict and a human
  `last_seen` for every agent, in both human-readable and `--json` output, with
  the verdict computed daemon-side from heartbeat recency (so the CLI stays
  stateless and the daemon remains the authority on liveness).
- Liveness combines the durable `agent` state with the latest heartbeat timeline
  event — a partial realization of §9.1 — so a healthy agent reads `active`
  between durable refreshes.
- Documentation (README status table, `docs/architecture.md` §9.1, roadmap Phase
  4) updated to match what now ships, and narrowed where the multi-signal model
  is still only partially implemented.

## Non-Goals

- The remaining §9.1 liveness signals — Matrix presence, room membership, and
  trusted signing/device-key status. Only durable state + heartbeat recency are
  combined here; the rest stay documented as planned.
- Using liveness as an **authorization** input (e.g. refusing to dispatch a task
  to an `offline` agent). Liveness stays *advisory*; execution authority remains
  signature → trust → policy → approval. Scheduler dispatch gating on liveness is
  explicitly out of scope (and noted as a follow-up).
- Auto-claim / heartbeating on behalf of agents this daemon does not own.
- Configurable heartbeat cadence beyond the existing `HeartbeatConfig` defaults
  (an env override is listed as an open question, not built).
- Signing heartbeat events. Heartbeats are non-privileged liveness signals, like
  the existing timeline heartbeat, and are not part of the signed-request path.
- Per-chunk / streaming changes, PTY, sandboxing, or any task-engine behavior.

## Relevant Repository Context

- **Workspace / crates.** Rust Cargo workspace, MSRV 1.74, `unsafe_code =
  "forbid"`, `missing_docs` warns and CI treats warnings as errors. Unix only.
  CLI is stateless; the daemon owns all Matrix state, crypto, policy, supervision
  (README, `docs/architecture.md` §0, §10).
- **Heartbeat module** (`crates/mx-agent-daemon/src/heartbeat.rs`):
  - `DEFAULT_HEARTBEAT_INTERVAL` 30s, `DEFAULT_STALE_AFTER` 90s,
    `DEFAULT_OFFLINE_AFTER` 300s, `DEFAULT_STATE_REFRESH` 300s.
  - `Liveness { Active, Stale, Offline }` with stable `as_str()`/`Display`.
  - `LivenessConfig { stale_after, offline_after }` with `liveness(last_ms,
    now_ms)` and `liveness_of(&AgentState, now_ms)`.
  - `HeartbeatConfig { interval, state_refresh }` with `should_refresh_state(...)`.
  - `emit_heartbeat(room, agent_id, status, &HeartbeatConfig, last_state_ms) ->
    Result<bool, WorkspaceError>`: always sends the timeline heartbeat; rewrites
    durable state (and returns `true`) only when `should_refresh_state` fires.
    Uses non-secret fields only.
- **Daemon worker spawning** (`crates/mx-agent-daemon/src/lifecycle.rs`):
  - `run_foreground` builds the IPC socket, then `spawn_matrix_workers(running,
    exec_subscribers)` returns `(sync_thread, scheduler_thread, health)` and is
    joined/stopped on the `SIGINT`/`SIGTERM` path via a shared
    `Arc<AtomicBool>`.
  - `spawn_matrix_workers` returns `(None, None, None)` before login; otherwise it
    spawns the **sync thread** (owns the session token, publishes the restored
    `Client` into a shared `Arc<Mutex<Option<Client>>>`) and the **scheduler
    thread** (waits for that shared client, then runs `run_scheduler_loop`).
  - `WorkerThreads` is the 2-tuple type alias for the returned join handles.
- **Scheduler loop** (`crates/mx-agent-daemon/src/scheduler_loop.rs`) is the
  pattern to mirror: a dedicated current-thread runtime, `sleep_interruptible`,
  and a per-pass `for room in client.joined_rooms()` walk that reads
  `read_all_agent_states(&room)` and filters `agent.matrix_user_id ==
  client.user_id()` to find agents this daemon owns.
- **Agent reads** (`crates/mx-agent-daemon/src/agent.rs`):
  - `read_all_agent_states(room) -> Vec<AgentState>` (`pub(crate)`),
    `read_agent_state(room, agent_id)`, `list_agents` / `show_agent` (return
    `AgentState` / `Option<AgentState>`), and the `*_for_session` wrappers the IPC
    handlers call.
  - `AgentTools` is the precedent for a daemon-side *view* struct serialized over
    IPC.
- **Timeline scan precedent** (`crates/mx-agent-daemon/src/approval.rs:345`):
  `read_approval_decisions(room, limit)` uses `MessagesOptions::backward()` +
  `room.messages()` and a newest-first scan keeping the first hit per key. The
  heartbeat-recency reader mirrors this exactly.
- **Protocol** (`crates/mx-agent-protocol/src/schema.rs`): `AgentState` (carries
  `last_seen_ts: u64`, `state_rev`, `#[serde(flatten)] extra`), `Heartbeat`
  (`agent_id`, `status`, `load`, `ts`, `extra`). `events::timeline::HEARTBEAT =
  "com.mxagent.heartbeat.v1"`.
- **CLI agent rendering** (`crates/mx-agent-cli/src/cli.rs`): `agent_list`
  deserializes `Vec<AgentState>`; `agent_show` deserializes
  `Option<AgentState>`. Both print human columns/lines and a raw `--json` dump.
  The CLI already depends on `mx-agent-daemon` for option/param types, so
  `mx_agent_daemon::{Liveness, AgentListing}` are usable directly.
- **Existing test** (`crates/mx-agent-daemon/tests/matrix_integration.rs:2236`):
  `two_daemons_discover_each_other_and_compute_liveness` already drives
  `emit_heartbeat` once and asserts the durable refresh + Active→Stale→Offline
  thresholds against an injected clock. `assert_stable_agent_json` pins the
  `AgentState` JSON shape (this asserts the *protocol struct*, not the CLI command
  output).

## Proposed Implementation

### 1. Heartbeat loop (`heartbeat.rs` + `lifecycle.rs`)

Add a live loop next to the emission primitive and wire it into the worker set.

`heartbeat.rs`:

- Add `pub fn run_heartbeat_loop(client: matrix_sdk::Client, running:
  Arc<AtomicBool>, config: HeartbeatConfig, interval: Duration)`:
  - Build a dedicated current-thread Tokio runtime (mirror `run_scheduler_loop`);
    log a start line with the interval, and a stop line on exit.
  - Maintain `last_state_ms: HashMap<(String /*room_id*/, String /*agent_id*/),
    u64>` so each agent's durable-refresh cadence is honored across ticks. Seed an
    agent's entry from its discovered `last_seen_ts` on first sight (so the loop
    does not force an immediate extra state write right after registration); cap
    the map size like the scheduler caps its tracked sets.
  - Each pass, while `running`: for each `client.joined_rooms()`, read
    `read_all_agent_states(&room)`, filter to owned agents (`matrix_user_id ==
    client.user_id()`), and for each owned agent call `emit_heartbeat(&room,
    &agent.agent_id, &agent.status, &config, last_state_ms_for_agent)`. When it
    returns `true`, update the stored `last_state_ms` to "now". All Matrix/store
    errors are logged at `debug`/`warn` and skipped — a transient failure never
    stops the loop.
  - Sleep `interval` between passes using an interruptible sleep (extract the
    scheduler's `sleep_interruptible` into a shared helper, or duplicate the tiny
    100ms-step loop; prefer sharing).
- Keep `emit_heartbeat`, `Liveness`, `LivenessConfig`, `HeartbeatConfig`
  unchanged in signature.

`lifecycle.rs`:

- Extend `spawn_matrix_workers` to spawn a **third** thread: after the sync
  thread publishes the shared client, the heartbeat thread waits for that client
  (same wait-loop as the scheduler thread) and calls
  `run_heartbeat_loop(client, running, HeartbeatConfig::default(),
  DEFAULT_HEARTBEAT_INTERVAL)`.
- Change `WorkerThreads` to a 3-tuple and update the return type
  `(Option<JoinHandle>, Option<JoinHandle>, Option<JoinHandle>, SharedHealth)`
  (or return a small named struct of handles to avoid a 4-tuple); update
  `run_foreground` to join the heartbeat handle on shutdown alongside the others.
  The pre-login `(None, None, None)` early-returns become `(None, None, None,
  None)` accordingly.
- The heartbeat thread shares the client but never advances `/sync`; it only does
  cached-state reads and event sends, exactly like the scheduler thread, so there
  is no token race.

### 2. Heartbeat-recency liveness (`heartbeat.rs`)

- Add `pub async fn read_latest_heartbeats(room: &Room, limit: u32) ->
  Result<HashMap<String /*agent_id*/, Heartbeat>, WorkspaceError>`, mirroring
  `read_approval_decisions`: `MessagesOptions::backward()`, scan newest-first,
  keep the first (newest) `com.mxagent.heartbeat.v1` per `agent_id`. Bound `limit`
  with a module constant (e.g. `HEARTBEAT_SCAN_LIMIT = 100`).
- Add `impl LivenessConfig { pub fn liveness_combined(&self, state: &AgentState,
  latest_heartbeat_ts: Option<u64>, now_ms: u64) -> Liveness }` that evaluates
  `self.liveness(max(state.last_seen_ts, latest_heartbeat_ts.unwrap_or(0)),
  now_ms)`. Future skew clamping already lives in `liveness`. `liveness_of` is
  left intact (still used by the existing integration test and as the
  no-heartbeat fallback).

### 3. CLI surfacing (`agent.rs`, `lifecycle.rs` IPC, `cli.rs`)

Compute liveness daemon-side and return it as an explicit, documented envelope so
the CLI stays stateless and the daemon stays authoritative (and can later fold in
the remaining §9.1 signals without a second CLI change).

`agent.rs` (new daemon-side view + enrichment, leaving `list_agents` /
`show_agent` untouched so the scheduler and integration tests keep their
`AgentState` return types):

```rust
/// An agent's durable state plus the daemon-computed liveness verdict.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AgentListing {
    /// Durable `com.mxagent.agent.v1` state.
    pub agent: AgentState,
    /// Liveness verdict at the time of the query (active/stale/offline),
    /// combining durable `last_seen_ts` with the latest heartbeat timeline event.
    pub liveness: Liveness, // serializes via a stable lowercase string
}
```

- `Liveness` gains `#[derive(Serialize, Deserialize)]` with a lowercase string
  representation (e.g. serde `rename_all = "lowercase"` or an explicit
  `as_str()`-backed impl) so `--json` reads `"active"`/`"stale"`/`"offline"` and
  the CLI can deserialize it.
- Add `list_agents_with_liveness_for_session` and
  `show_agent_with_liveness_for_session` (resolve the room once, call the existing
  `list_agents` / `show_agent`, then `read_latest_heartbeats(&room, …)` once and
  build `AgentListing`s with `LivenessConfig::default().liveness_combined(state,
  latest.get(agent_id).map(|h| h.ts), now_ms())`). Reuse the room resolved by the
  underlying call to avoid an extra `/sync`.

`lifecycle.rs` IPC dispatch: point the `agent.list` / `agent.show` arms at the new
`*_with_liveness_for_session` functions so they return `Vec<AgentListing>` /
`Option<AgentListing>`.

`cli.rs`:

- `agent_list`: deserialize `Vec<AgentListing>`. Human output adds a `liveness`
  column (and keeps the existing `status`/caps columns); add a `last_seen` column
  or a trailing relative-age token (e.g. `42s ago`) computed from
  `agent.last_seen_ts` and the local clock. `--json` prints the
  `Vec<AgentListing>` verbatim.
- `agent_show`: deserialize `Option<AgentListing>`. Human output adds
  `liveness:` and `last_seen:` lines (relative age plus the raw ms is available
  in `--json`). `--json` prints the `AgentListing`.
- Relative age is plain integer arithmetic on epoch-ms (`now - last_seen_ts`
  rendered as `Ns`/`Nm`/`Nh ago`); no new time-formatting dependency.

`lib.rs`: re-export `AgentListing`, `read_latest_heartbeats`, and `run_heartbeat_loop`.

## Affected Files / Crates / Modules

- `crates/mx-agent-daemon/src/heartbeat.rs` — `run_heartbeat_loop`,
  `read_latest_heartbeats`, `LivenessConfig::liveness_combined`, `Liveness`
  serde, scan-limit const, unit tests.
- `crates/mx-agent-daemon/src/lifecycle.rs` — spawn/join the heartbeat thread in
  `spawn_matrix_workers`/`run_foreground`; widen `WorkerThreads`; route
  `agent.list`/`agent.show` IPC to the liveness-enriched functions.
- `crates/mx-agent-daemon/src/agent.rs` — `AgentListing`,
  `list_agents_with_liveness_for_session`,
  `show_agent_with_liveness_for_session`.
- `crates/mx-agent-daemon/src/scheduler_loop.rs` — only if `sleep_interruptible`
  is extracted/shared (optional refactor).
- `crates/mx-agent-daemon/src/lib.rs` — new re-exports.
- `crates/mx-agent-cli/src/cli.rs` — `agent_list` / `agent_show` rendering +
  deserialization; CLI parse/render tests.
- `crates/mx-agent-daemon/tests/matrix_integration.rs` — extend liveness coverage
  (Docker-gated `#[ignore]`).
- Docs: `README.md`, `docs/architecture.md`, `docs/roadmap-rust.md`,
  relevant `wiki/` pages.

## CLI / API Changes

- **CLI behavior:** `agent list` / `agent show` gain a `liveness` verdict and a
  `last_seen` age in human output; no new flags or commands. Existing columns/lines
  remain.
- **CLI `--json` shape change (breaking, intentional, additive content):**
  - `agent list --json`: `[AgentState, …]` → `[{ "agent": AgentState, "liveness":
    "active|stale|offline" }, …]`.
  - `agent show --json`: `AgentState | null` → `{ "agent": AgentState,
    "liveness": … } | null`.
  - Automation that read top-level `AgentState` fields now reads them under
    `.agent` (e.g. `.[].agent.agent_id`, `.[].agent.last_seen_ts`) and gains
    `.[].liveness`. This is called out in Risks; the alternative (additive
    flattened field that preserves the bare-`AgentState` top level) is described
    there.
- **Daemon IPC result types:** `agent.list` now returns `AgentListing[]` and
  `agent.show` returns `AgentListing?` (the request *params* —
  `ListAgentsOptions` / `RoomAgentParams` — are unchanged). The internal
  `list_agents` / `show_agent` library functions keep returning `AgentState`.
- **Public API:** new exported items `AgentListing`, `run_heartbeat_loop`,
  `read_latest_heartbeats`, `LivenessConfig::liveness_combined`; `Liveness` gains
  serde derives. All documented (`missing_docs`).

## Data Model / Protocol Changes

- **No Matrix event schema changes.** `com.mxagent.heartbeat.v1` and
  `com.mxagent.agent.v1` content are emitted exactly as `emit_heartbeat` already
  does. The heartbeat loop only *invokes* the existing emission.
- **No persistence/policy/on-disk format changes.** The per-agent
  `last_state_ms` map is in-memory loop state only.
- `AgentListing` is a new **IPC** (CLI↔daemon) serialization type, not a Matrix
  protocol type. `Liveness` serializes as a stable lowercase string.

## Security Considerations

- **CLI stays stateless; daemon owns liveness.** The heartbeat loop runs only in
  the daemon, which owns the Matrix client, tokens, and keys. The CLI never emits
  heartbeats, never reads timelines, and never restores a Matrix client; it
  receives a precomputed verdict over local IPC. The coding agent never sees
  Matrix tokens or device keys.
- **Heartbeats carry no secrets.** `Heartbeat` content is `agent_id`, `status`,
  `load`, `ts` — all non-secret, matching existing redaction expectations. Loop
  logging is limited to non-sensitive metadata (room id, agent id, verdict,
  counts); never event content or credentials.
- **Liveness is advisory, never an authorization input.** A heartbeat is an
  unsigned timeline event; a hostile room member could publish a
  `com.mxagent.heartbeat.v1` to make a departed agent *look* alive (or stay
  silent to make one look offline). That changes only a displayed verdict — it
  grants nothing. Execution authority remains signature → local trust → policy →
  approval, and room membership still never implies execution. This issue does
  **not** let liveness gate dispatch, preserving deny-by-default. (Mitigation
  note for the reader: `read_latest_heartbeats` could later prefer the agent's own
  `matrix_user_id` sender, but that is not required for an advisory signal.)
- **Owned-agent scoping.** The loop only heartbeats agents whose
  `matrix_user_id == client.user_id()`, so it never impersonates another daemon's
  agent.
- **Unix-only, no `unsafe`.** Uses safe `matrix_sdk` and `std` APIs; no new
  platform assumptions, no `unsafe`, MSRV 1.74 respected (no APIs newer than
  1.74).
- **No token race across threads.** Like the scheduler thread, the heartbeat
  thread shares the restored client but never runs a second `/sync`; it performs
  cached-state reads, `/messages` pagination, and event sends only.

## Testing Plan

Default `cargo test --all` (no homeserver):

- **`heartbeat.rs` unit tests** (extend the existing module):
  - `liveness_combined`: heartbeat newer than durable `last_seen_ts` ⇒ `Active`
    when the durable stamp alone would be `Stale`/`Offline`; `None` heartbeat
    falls back to `liveness_of`; both stale ⇒ `Offline`; future heartbeat ts
    clamps to `Active`.
  - `Liveness` serde round-trips to/from `"active"`/`"stale"/"offline"`.
  - `last_state_ms` cadence: factor the per-tick "should I refresh / what is this
    agent's stored `last_state_ms`" decision into a pure helper and test that the
    first sight seeds from `last_seen_ts` (no immediate forced refresh) and that a
    `true` return advances the stored value. (`should_refresh_state` itself is
    already covered.)
  - Owned-agent filtering: a pure helper over `(&[AgentState], local_user)`
    returns exactly the owned `agent_id`s (none when the local user owns nothing).
- **`AgentListing`** serialization test pins the `{ "agent": …, "liveness": …}`
  envelope and the lowercase verdict string.
- **CLI tests** (`cli.rs`): existing `agent list` / `agent show` arg-parse tests
  stay green; add a test that the new result types deserialize and that human
  rendering includes a liveness token (string-contains assertion on a captured
  render helper if one is introduced; otherwise a deserialization test).

Docker-gated `#[ignore]` integration (`matrix_integration.rs`, run via
`scripts/matrix_integration_test.sh`):

- Extend `two_daemons_discover_each_other_and_compute_liveness` (or add a focused
  test): after B emits a heartbeat, assert `read_latest_heartbeats(&room)`
  returns B's heartbeat with the expected `ts`, and that
  `LivenessConfig::default().liveness_combined(&b_state, Some(hb_ts), hb_ts +
  1_000)` is `Active` even when the durable `last_seen_ts` alone would be stale
  under injected thresholds.
- Optionally, a test that drives `run_heartbeat_loop` for a couple of intervals
  against the live room (bounded, injected short interval) and asserts a peer
  observes an advanced `last_seen_ts`/`state_rev` and a fresh heartbeat event.
  Keep it out of the default suite.

CI gates: `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D
warnings`, `cargo test --all`, `cargo build --all`.

## Documentation Updates

- **`README.md` "Project status" table:** add/adjust a row so the periodic
  heartbeat + liveness surfacing reads ✅ Implemented (the heartbeat loop emits on
  an interval; `agent list`/`show` show `active`/`stale`/`offline` and
  `last_seen`). Keep claims scoped to what ships — liveness combines durable state
  + heartbeat recency; presence/membership/key-status remain planned.
- **`docs/architecture.md`:**
  - §9.1 "Liveness should combine …": note that the implementation currently
    combines durable `agent` state + recent `heartbeat` event, and that Matrix
    presence, room membership, and key status are not yet folded in.
  - §4 agent command example output may show a liveness column for accuracy.
- **`docs/roadmap-rust.md`:** mark Phase 4's "periodic heartbeat event"
  deliverable as delivered.
- **`wiki/`** (Core-Concepts / AI-Agent-Orchestration where liveness/discovery is
  described): mention that agents heartbeat periodically and that liveness is
  visible via `agent list`/`show`. Keep edits minimal and in `wiki/` (mirrored on
  merge to `main`).
- **Help text:** no new flags; the `agent list`/`show` long help can mention the
  liveness column. Do not imply the unimplemented §9.1 signals exist.

## Risks and Open Questions

- **`--json` shape change (decision needed).** Recommended: the `AgentListing`
  envelope (`{agent, liveness}`), which is clean, keeps the daemon authoritative,
  and extends naturally to more signals. Trade-off: it relocates `AgentState`
  fields under `.agent`, breaking automation that read them at the top level.
  *Alternative for strict backward compatibility:* add `liveness` as an additive
  field on a flattened view of `AgentState` (top-level fields preserved). This is
  serde-fragile because `AgentState` itself has a `#[serde(flatten)] extra`
  catch-all map, and nesting a flattened struct over a catch-all can mis-route the
  added field on deserialization — so if exact backward compatibility is required,
  prefer computing/printing liveness only in human output and exposing it in
  `--json` via the envelope on `show` only, or pin the encoding with explicit
  tests. **Confirm which shape to ship.**
- **`state_refresh == offline_after`.** Resolved by heartbeat-recency liveness, so
  no constant change is required and durable-state churn stays at 300s. Open
  question: should `DEFAULT_STATE_REFRESH` still be lowered (e.g. < 90s) as
  belt-and-suspenders for any consumer that uses durable-only `liveness_of`? Not
  recommended (it reintroduces churn), but worth a decision.
- **Timeline read cost per `agent list`/`show`.** Each query now scans up to
  `HEARTBEAT_SCAN_LIMIT` recent timeline events via `/messages`. Bounded and
  consistent with `read_approval_decisions`, but it adds a round-trip; a future
  cache is out of scope.
- **Heartbeat cadence config.** Defaults only for now; an env override
  (`MX_AGENT_HEARTBEAT_INTERVAL` à la `MX_AGENT_TASK_DISPATCH`) is a possible
  follow-up — confirm whether it is wanted in this issue.
- **Spoofed/absent heartbeats.** Advisory-only; explicitly not an auth input here
  (see Security). Folding sender identity into `read_latest_heartbeats` is a
  possible hardening follow-up.
- **Three threads sharing one client.** Same mitigation as the existing scheduler
  thread (no second `/sync`); the new thread only reads cached state, paginates
  `/messages`, and sends events.
- **Power levels.** Emitting a heartbeat *timeline* event needs only
  `events_default` (0); the durable state refresh needs the agent-state power
  level the agent already holds from registration. A daemon lacking state power
  still emits timeline heartbeats (durable refresh silently skips) — acceptable.

## Implementation Checklist

- [ ] `heartbeat.rs`: add `read_latest_heartbeats(room, limit)` (+ scan-limit
      const) mirroring `read_approval_decisions`.
- [ ] `heartbeat.rs`: add `LivenessConfig::liveness_combined(state, hb_ts,
      now_ms)`; derive serde for `Liveness` as a lowercase string.
- [ ] `heartbeat.rs`: add `run_heartbeat_loop(client, running, config, interval)`
      with per-agent `last_state_ms` tracking, owned-agent filtering,
      interruptible sleep, error-skip logging, start/stop logs.
- [ ] `lifecycle.rs`: spawn the heartbeat thread in `spawn_matrix_workers`
      (waiting on the shared client), widen `WorkerThreads`, and join it in
      `run_foreground` shutdown.
- [ ] `agent.rs`: add `AgentListing` and the
      `list_agents_with_liveness_for_session` /
      `show_agent_with_liveness_for_session` enrichment (single timeline scan per
      query; reuse the resolved room).
- [ ] `lifecycle.rs`: route `agent.list` / `agent.show` IPC to the
      liveness-enriched functions.
- [ ] `cli.rs`: deserialize `AgentListing`; render `liveness` + `last_seen`
      (human) and the envelope (`--json`) for `agent list` and `agent show`.
- [ ] `lib.rs`: re-export `AgentListing`, `run_heartbeat_loop`,
      `read_latest_heartbeats`.
- [ ] Unit tests: `liveness_combined`, `Liveness` serde, `last_state_ms`/seed
      helper, owned-agent filter, `AgentListing` shape, CLI deserialization/render.
- [ ] Integration (`#[ignore]`): extend liveness test for heartbeat-recency
      (`read_latest_heartbeats` + `liveness_combined`); optional bounded
      `run_heartbeat_loop` live check.
- [ ] Docs: README status table, `docs/architecture.md` §9.1 (+ §4 example),
      `docs/roadmap-rust.md` Phase 4, relevant `wiki/` pages.
- [ ] Green: `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D
      warnings`, `cargo test --all`, `cargo build --all`.
```
