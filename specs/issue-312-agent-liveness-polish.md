# Agent Liveness Polish: Sender-Pinned Heartbeats, Real Load, Combined `task.graph` Liveness, Robust Scan

GitHub issue: #312 — *Agent liveness gaps: unpinned heartbeat sender, placeholder load, durable-only `task.graph`, unpaginated scan*
Labels: `type:bug` `area:daemon` `area:matrix` `priority:p2`

## Problem Statement

The heartbeat/liveness subsystem (#88, spec #250, shipped in #255 / `351b852`) works end-to-end
but has four operator-facing polish gaps. None are authorization-relevant — liveness is advisory
and heartbeats route as non-privileged timeline events — but each degrades signal quality:

1. **Unpinned heartbeat sender.** `read_latest_heartbeats`
   (`crates/mx-agent-daemon/src/heartbeat.rs:268-292`) matches only the raw event `type` and
   `content`; it never compares the Matrix event `sender` to the registered agent's
   `matrix_user_id`. Any room member can therefore emit a `com.mxagent.heartbeat.v1` carrying
   another agent's `agent_id` and inflate that agent's *displayed* liveness verdict.

2. **Placeholder load.** `AgentLoad.running_invocations` is hardcoded to `0` at registration
   (`crates/mx-agent-daemon/src/agent.rs:156-159`) and carried forward verbatim by
   `emit_heartbeat` (`heartbeat.rs:216-223`). No code path increments it, yet `agent show` and
   `agent register` print it as live load (`crates/mx-agent-cli/src/cli.rs:2435-2438`, `:2556-2559`),
   so it always reads `0/N`.

3. **Durable-only `task.graph` liveness.** The `task.graph` IPC handler fetches bare
   `AgentState`s via `list_agents_for_session` with no heartbeat scan
   (`crates/mx-agent-daemon/src/lifecycle.rs:591-610`), and `diagnose_tasks` evaluates liveness
   with `liveness_of` (durable `last_seen_ts` only) at `task_diagnostics.rs:166`. Because the
   durable state is refreshed at most every 300 s but heartbeats tick every 30 s, a healthy
   heartbeating agent reads `Stale`/`Offline` for ~210 s of every 300 s window, producing false
   `assigned_to_inactive_agent` warnings. `agent list`/`agent show` already avoid this by using
   `enrich_with_liveness` (combined liveness); `task.graph` does not.

4. **Unpaginated, unfiltered scan.** The heartbeat scan is a single backward `/messages` page
   capped at `HEARTBEAT_SCAN_LIMIT = 100` (`heartbeat.rs:51`, `:272-276`) with no event-type
   filter and no pagination. On busy timelines (exec stream chunks share the timeline), heartbeats
   are silently evicted from the 100-event window and liveness silently degrades to durable-only.
   A live-test comment (`crates/mx-agent-daemon/tests/matrix_integration.rs`, the
   `read_latest_heartbeats` "paginates `/messages` backward" claim near the scan assertion) is
   misleading: the function issues a single page.

This spec specifies fixes for all four, plus an optional clean-shutdown convergence improvement.

## Goals

- **Pin heartbeat acceptance to the registered sender.** Accept a heartbeat for an `agent_id`
  only when the timeline event's Matrix `sender` equals the registered
  `AgentState.matrix_user_id` for that agent. A spoofed heartbeat from any other member is ignored.
- **Track and publish a real `running_invocations`.** Maintain a daemon-local per-agent in-flight
  counter (increment when an invocation/exec/call starts, decrement when it finishes, is cancelled,
  or is rejected) and publish it in `emit_heartbeat` and durable-state refreshes instead of the
  registration-time `0`.
- **Use combined liveness in `task.graph`.** Compute `diagnose_tasks` agent liveness with the
  heartbeat-enriched verdict (`liveness_combined`) so a recently heartbeating agent never yields a
  false `assigned_to_inactive_agent` warning between durable refreshes; still warn when both the
  durable state and the latest heartbeat are stale.
- **Make the scan robust on busy timelines.** Paginate `/messages` backward beyond
  `HEARTBEAT_SCAN_LIMIT` up to a bounded total, with early termination once a heartbeat has been
  located for every relevant agent, so exec stream chunks cannot evict heartbeats from the scan
  window.
- **Keep documentation honest.** Remove the "heartbeat sender is not yet pinned" caveat from
  `docs/architecture.md` once pinning lands, correct the scan description, and fix the misleading
  live-test comment.

## Non-Goals

- **No change to dispatch authority.** Liveness stays advisory and is never an authorization input.
  Dispatch authority remains signature → Ed25519 local trust store → deny-by-default policy →
  approval. Sender pinning here hardens a display signal; it grants nothing.
- **No new liveness signals.** Room membership, Matrix presence, and key status remain out of
  scope (still "Planned" in the architecture doc).
- **No protocol/schema change.** `com.mxagent.heartbeat.v1` and `com.mxagent.agent.v1` keep their
  current shapes; `AgentLoad.running_invocations` already exists and is simply populated.
- **No persistence of the in-flight counter.** A daemon restart kills every live invocation, so an
  in-memory counter that resets to `0` on restart is correct (mirrors `LIVE_EXEC_CONTROLS`).
- **No CLI surface change.** The CLI already prints `running_invocations`; only the value it
  receives changes.

## Relevant Repository Context

**Crate layout.** Daemon-only work lives in `crates/mx-agent-daemon`. The CLI
(`crates/mx-agent-cli`) is stateless and reaches the daemon over local IPC; it never owns Matrix
credentials, keys, or liveness logic. The protocol crate (`crates/mx-agent-protocol`) owns the
wire schema (`schema.rs`, `events`).

**Heartbeat module (`crates/mx-agent-daemon/src/heartbeat.rs`).**
- `Liveness` (`active`/`stale`/`offline`) and `LivenessConfig` with `liveness`, `liveness_of`
  (durable-only), and `liveness_combined(state, latest_heartbeat_ts, now_ms)` (newer of durable
  `last_seen_ts` and latest heartbeat).
- `emit_heartbeat(room, agent_id, status, config, last_state_ms)` sends a
  `com.mxagent.heartbeat.v1` timeline event every tick and rewrites the durable
  `com.mxagent.agent.v1` state at most every `state_refresh` (default 300 s). It currently reads
  `existing.load` and carries `running_invocations` forward unchanged.
- `read_latest_heartbeats(room, limit)` issues one backward `/messages` page (`MessagesOptions`),
  keeps the newest heartbeat per `agent_id`, and matches only `type`/`content`.
- `run_heartbeat_loop` / `heartbeat_pass` iterate joined rooms, filter to `owned_agents` (those
  whose `matrix_user_id == client.user_id()`), and emit per owned agent. The loop already never
  impersonates a peer.

**Agent module (`crates/mx-agent-daemon/src/agent.rs`).**
- `register_agent` writes the initial `AgentState` with `load.running_invocations = 0`.
- `AgentListing { agent: AgentState, liveness: Liveness }` is the IPC envelope returned to the CLI.
- `enrich_with_liveness(room, agents)` calls `read_latest_heartbeats(room, HEARTBEAT_SCAN_LIMIT)`,
  computes each verdict with `liveness_combined`, and returns `AgentListing`s. It degrades to
  durable-only on a timeline read failure.
- `list_agents_with_liveness_for_session` / `show_agent_with_liveness_for_session` are the
  IPC-facing enriched paths used by `agent list` / `agent show`.
- `list_agents_for_session` returns bare `AgentState`s (used by the scheduler, integration tests,
  and currently `task.graph`).

**Task diagnostics (`crates/mx-agent-daemon/src/task_diagnostics.rs`).**
- `diagnose_tasks(tasks, agents)` / `diagnose_tasks_at(tasks, agents, now_ms)` are pure functions.
  The agent-dependent block (`!agents.is_empty()`) emits `KIND_UNKNOWN_AGENT`,
  `KIND_INACTIVE_AGENT` (via `LivenessConfig::liveness_of`), and `KIND_TOOL_UNAVAILABLE`.

**`task.graph` IPC handler (`crates/mx-agent-daemon/src/lifecycle.rs:591-610`).** Restores the
session, lists tasks, best-effort lists *bare* agents, calls `diagnose_tasks`, and wraps the result
in `TaskGraph::from_tasks(&tasks).with_diagnostics(warnings)`.

**Exec / call invocation lifecycle.**
- `crates/mx-agent-daemon/src/exec.rs`: `spawn_authorized_live_exec(client, room, request,
  allowance)` is the single start point for a remote exec. It emits `exec.accepted`, publishes
  running invocation state, registers a `LiveExecControl` via `insert_live_exec_control`, then
  spawns the run task (PTY path via `run_pty_exec_task`, non-PTY via `run_controlled_exec`). The
  run task removes the control via `remove_live_exec_control` on every terminal path
  (finished / cancelled / rejected / error). The executing (local) agent is `request.target_agent`.
- `crates/mx-agent-daemon/src/call.rs`: `handle_live_call_request` authorizes a `call.request`,
  then runs the tool via `execute_tool_async` and emits a `call.response`. The executing (local)
  agent is `request.target_agent` (an `Option<String>`).
- Existing in-memory daemon registries use the pattern
  `static X: OnceLock<Mutex<HashMap<..>>>` with `get_or_init` (see `LIVE_EXEC_CONTROLS` in
  `exec.rs:85-111`, `ACTIVE_CLIENTS` in `matrix.rs`). The in-flight counter should follow this
  same pattern: in-memory, reset on restart, lock-poisoning-tolerant
  (`.lock().unwrap_or_else(|e| e.into_inner())`).

**Matrix SDK 0.18 specifics (verified in the vendored source).**
- `MessagesOptions` (`matrix-sdk-0.18.0/src/room/messages.rs`) exposes public `from: Option<String>`,
  `limit: UInt`, and `filter: RoomEventFilter`. `Messages` returns `end: Option<String>` (the
  backward pagination token) and `chunk: Vec<TimelineEvent>`. Pagination: pass the previous
  response's `end` as the next request's `from`; stop when `end` is `None`.
- `ruma::api::client::filter::RoomEventFilter` has a `types: Option<Vec<String>>` field for a
  server-side event-type filter.
- **Encryption caveat (critical for the scan fix):** in an `--e2ee on` room, `Room::send_raw`
  encrypts custom timeline events, so on the wire a heartbeat is an `m.room.encrypted` event; the
  homeserver cannot see the inner `com.mxagent.heartbeat.v1` type. A server-side `types` filter on
  the custom type therefore returns nothing in encrypted rooms (`/messages` still decrypts what it
  returns, but the server filters on the *outer* type). **Pagination, not the type filter, is the
  load-bearing fix.** The type filter is at best an unencrypted-room optimization and must not be
  the sole mechanism.

**Security model context (`docs/architecture.md`).** §1.2 documents that the result/stream/
artifact/share plane is sender-pinned to the executing/producing agent using the homeserver-asserted
`sender` (issue #304). The heartbeat sender pin specified here extends the same homeserver-asserted-
`sender` hardening to the display-only heartbeat plane. The current "heartbeat sender is not yet
pinned" caveat is at `docs/architecture.md` (the "Planned." block, ~lines 997-1005), and the scan
description is ~lines 989-995.

## Proposed Implementation

### 1. Pin heartbeat acceptance to the registered sender

Change `read_latest_heartbeats` so the caller supplies the expected sender per agent, and accept a
heartbeat only when the event `sender` matches.

- New signature (recommended):
  ```rust
  pub async fn read_latest_heartbeats(
      room: &Room,
      agents: &[AgentState],
      max_events: u32,
  ) -> Result<HashMap<String, Heartbeat>, WorkspaceError>
  ```
  Build a lookup `expected: HashMap<&str /*agent_id*/, &str /*matrix_user_id*/>` from `agents`.
  (Passing `&[AgentState]` rather than a prebuilt map keeps the call sites — which already hold the
  agent states — simple and lets the function early-terminate pagination once every known agent has
  a heartbeat.)
- In the scan loop, extract the event sender from the raw timeline event
  (`raw.get_field::<String>("sender")`, mirroring the existing `type`/`content` extraction style)
  and accept the deserialized `Heartbeat` only when:
  - the `agent_id` is present in `expected`, **and**
  - `sender == expected[agent_id]`.
  Drop (continue past) any heartbeat whose `agent_id` is unknown or whose sender does not match.
  Keep the newest-first "first occurrence wins" behavior per `agent_id`.
- The router already classifies `Heartbeat` as non-privileged; this change adds no authorization,
  only display-signal hardening.

### 2. Track a real `running_invocations`

Add a small daemon-local in-flight registry keyed by the executing agent id, following the existing
`OnceLock<Mutex<HashMap<..>>>` pattern. Recommended new module
`crates/mx-agent-daemon/src/inflight.rs` (or a private section of `heartbeat.rs`):

```rust
static INFLIGHT: OnceLock<Mutex<HashMap<String, u32>>> = OnceLock::new();

/// Number of invocations currently running for `agent_id` on this daemon.
pub(crate) fn running_invocations(agent_id: &str) -> u32 { /* read, default 0 */ }

/// RAII guard: increments the in-flight count for `agent_id` on construction and
/// decrements it on drop. The Drop-based decrement guarantees the count is
/// released on every terminal path (finish, cancel, reject, error, panic).
#[must_use]
pub(crate) struct InflightGuard { agent_id: String }
impl InflightGuard { pub(crate) fn enter(agent_id: &str) -> Self { /* saturating_add */ } }
impl Drop for InflightGuard { fn drop(&mut self) { /* saturating_sub, remove at 0 */ } }
```

- Use saturating arithmetic; remove the map entry when it hits `0` to bound memory.
- Lock-poisoning-tolerant (`.lock().unwrap_or_else(|e| e.into_inner())`).
- **Wire the guard at invocation start so it lives for the invocation duration:**
  - **Exec** (`exec.rs::spawn_authorized_live_exec`): create
    `InflightGuard::enter(&request.target_agent)` and **move it into the spawned run task** (both
    the PTY `tokio::spawn` and the non-PTY `tokio::spawn`). When that task ends — finished,
    cancelled, rejected, or errored — the guard drops and the count decrements. This covers all the
    early-`return` terminal paths without per-path bookkeeping. (Do not place the guard before the
    spawn on the synchronous path, or it would drop immediately.)
  - **Call** (`call.rs::handle_live_call_request`): hold an
    `InflightGuard::enter(target_agent)` across the `execute_tool_async` + `emit_call_response`
    section, where `target_agent` is the resolved local executing agent. The guard drops when the
    handler returns.
- **Publish the live count** instead of carrying the registration value forward:
  - In `emit_heartbeat` (`heartbeat.rs:216-223`), set
    `load.running_invocations = inflight::running_invocations(agent_id)` while preserving
    `max_invocations` from the existing durable state. Apply the same live value when rewriting the
    durable `AgentState` during a state refresh (so `agent show` reflects it between heartbeats).
  - `register_agent` may keep `running_invocations: 0` at registration time (the counter is `0`
    then); the heartbeat loop will publish the live value on its next tick.

### 3. Use combined liveness in `task.graph`

Make `diagnose_tasks` evaluate agent liveness from a precomputed per-agent verdict so the handler
can supply heartbeat-enriched verdicts.

- Change the diagnostics signature to accept precomputed verdicts:
  ```rust
  pub fn diagnose_tasks(
      tasks: &[TaskState],
      agents: &[AgentState],
      liveness: &HashMap<String, Liveness>, // agent_id -> combined verdict
  ) -> Vec<TaskDiagnostic>
  pub fn diagnose_tasks_at(
      tasks: &[TaskState],
      agents: &[AgentState],
      liveness: &HashMap<String, Liveness>,
      now_ms: u64,
  ) -> Vec<TaskDiagnostic>
  ```
  In the inactive-agent check, use the supplied verdict when present and fall back to durable-only
  `LivenessConfig::liveness_of(agent, now_ms)` when an agent is absent from the map (preserves the
  current behavior for callers that have no heartbeat data):
  ```rust
  let verdict = liveness.get(agent.agent_id.as_str()).copied()
      .unwrap_or_else(|| cfg.liveness_of(agent, now_ms));
  if verdict != Liveness::Active { /* push KIND_INACTIVE_AGENT */ }
  ```
  *(Alternative equally acceptable to the issue: pass a `HashMap<String, u64>` of latest heartbeat
  timestamps and call `liveness_combined` inside `diagnose_tasks`. The verdict-map form is preferred
  because it reuses `enrich_with_liveness` as the single source of liveness truth and needs no new
  daemon plumbing.)*
- Update the **`task.graph` IPC handler** (`lifecycle.rs:591-610`) to obtain heartbeat-enriched
  agents instead of bare ones: call the existing `list_agents_with_liveness_for_session` (returns
  `Vec<AgentListing>`), then build `agents: Vec<AgentState>` and
  `liveness: HashMap<String, Liveness>` from the listings and pass both to `diagnose_tasks`. Keep
  the best-effort semantics: on error, fall back to empty agents / empty verdict map so agent
  checks are skipped rather than failing the graph query.

### 4. Make the scan robust on busy timelines

Replace the single-page scan in `read_latest_heartbeats` with a bounded backward pagination loop:

- Introduce constants in `heartbeat.rs`:
  - keep `HEARTBEAT_SCAN_LIMIT = 100` as the **per-page** limit, and
  - add a bounded total, e.g. `MAX_HEARTBEAT_SCAN_EVENTS: u32 = 1000` (≈10 pages) and/or
    `MAX_HEARTBEAT_SCAN_PAGES: u32 = 10`. Document the bound and that it caps liveness-query cost.
- Pagination loop:
  1. `let mut opts = MessagesOptions::backward(); opts.limit = UInt::from(HEARTBEAT_SCAN_LIMIT);`
  2. *(Optional unencrypted-room optimization)* set
     `opts.filter.types = Some(vec![HEARTBEAT_EVENT_TYPE.to_owned()])`. Note in code that this only
     helps unencrypted rooms (encrypted heartbeats appear as `m.room.encrypted` on the wire and are
     not matched by the inner-type filter), so it is an optimization, not the correctness mechanism.
  3. Scan the page (sender-pinned per item per §1), accumulating newest-per-agent.
  4. **Early-terminate** once every agent in `expected` has a heartbeat (the common case ends after
     the first page).
  5. Otherwise set `opts.from = messages.end` and repeat while `end.is_some()`, the per-page chunk
     is non-empty, and the running total scanned `< MAX_HEARTBEAT_SCAN_EVENTS`.
- Preserve the existing failure semantics in `enrich_with_liveness`: a `/messages` error still
  degrades to durable-only liveness (advisory), never failing the query.

### 5. Optional: faster convergence on clean shutdown

In the foreground shutdown path (`lifecycle.rs:265-287`), after the loops stop and before dropping
the client, best-effort rewrite each owned agent's durable `com.mxagent.agent.v1` state to a
stopped/`offline`-leaning status (e.g. `status = "stopped"` with a fresh `last_seen_ts`) so peers
converge faster than the 300 s heartbeat decay. Constraints:
- Bound the total time spent (e.g. a small overall timeout); failures must be logged and **must not
  block shutdown**.
- This is the only optional item; ship it only if it does not complicate the shutdown sequence.

## Affected Files / Crates / Modules

Likely to **modify**:
- `crates/mx-agent-daemon/src/heartbeat.rs` — `read_latest_heartbeats` signature, sender pinning,
  pagination loop + new bound constant(s); `emit_heartbeat` publishing the live load.
- `crates/mx-agent-daemon/src/agent.rs` — update `enrich_with_liveness` call to
  `read_latest_heartbeats` (pass agent states); confirm `register_agent` load handling.
- `crates/mx-agent-daemon/src/task_diagnostics.rs` — `diagnose_tasks` / `diagnose_tasks_at`
  signature + combined-liveness evaluation; update existing unit tests to pass the new arg.
- `crates/mx-agent-daemon/src/lifecycle.rs` — `task.graph` handler to use enriched agents + verdict
  map; optional clean-shutdown convergence.
- `crates/mx-agent-daemon/src/exec.rs` — `InflightGuard` wiring in `spawn_authorized_live_exec`
  (PTY and non-PTY tasks).
- `crates/mx-agent-daemon/src/call.rs` — `InflightGuard` wiring in `handle_live_call_request`.
- `crates/mx-agent-daemon/src/inflight.rs` — **new** in-flight counter + RAII guard (or a private
  section of `heartbeat.rs`); export via `lib.rs` only if needed by other modules/tests.
- `crates/mx-agent-daemon/src/lib.rs` — re-export changes if the new module is referenced by tests.
- `crates/mx-agent-daemon/tests/matrix_integration.rs` — fix the misleading "paginates" comment;
  add/extend live tests (see Testing Plan); update the direct `read_latest_heartbeats` caller to the
  new signature.
- `crates/mx-agent-cli/src/cli.rs` — only if its test module imports/calls `read_latest_heartbeats`
  or `diagnose_tasks` directly (update call sites to new signatures). No runtime CLI change.
- `docs/architecture.md` — remove the heartbeat "not yet pinned" caveat; correct the scan
  description; note the real `running_invocations`.

Likely to **read** (no change expected):
- `crates/mx-agent-protocol/src/schema.rs` (`AgentLoad`, `Heartbeat`, `AgentState`).
- `crates/mx-agent-daemon/src/event_router.rs` (`Heartbeat` stays non-privileged).

## CLI / API Changes

- **CLI surface:** none. `agent show` / `agent register` already print `running_invocations`; only
  the value changes (now nonzero during in-flight work).
- **IPC surface:** none. `agent.list` / `agent.show` keep returning `AgentListing`; `task.graph`
  keeps returning `TaskGraph` with diagnostics. The fix changes how the daemon computes the
  diagnostics, not the wire shape.
- **Daemon-internal Rust API (not a public/stable surface):** `read_latest_heartbeats` gains an
  `agents: &[AgentState]` parameter; `diagnose_tasks` / `diagnose_tasks_at` gain a precomputed
  liveness map; a new `inflight` module is added. Document the new/changed functions with rustdoc.

## Data Model / Protocol Changes

None. No event schema, persistence format, policy, or serialization change. `AgentLoad`,
`Heartbeat`, and `AgentState` keep their current shapes; `running_invocations` is an existing field
that is now populated with a real value. The in-flight counter is in-memory only and is never
serialized or persisted.

## Security Considerations

- **Liveness stays advisory.** Sender pinning hardens a *display* signal only; it grants no
  execution authority. Dispatch authority remains signature → Ed25519 local trust store →
  deny-by-default policy → approval. Confirm via the existing router assertion that `Heartbeat`
  remains non-privileged.
- **Homeserver-asserted sender.** The pin uses the homeserver-asserted Matrix `sender`, consistent
  with the result/stream/artifact/share plane pin (§1.2, issue #304). It is a cheap display guard,
  not an authenticity proof; the security narrative must not overstate it.
- **Daemon owns liveness and load.** Verdicts and load counts stay daemon-computed and travel to the
  stateless CLI over local IPC only. The CLI never owns Matrix credentials, keys, or liveness logic.
- **Room membership ≠ execution permission.** Unchanged and must remain so.
- **No secrets in logs or output.** The in-flight counter and liveness logic log only non-sensitive
  identifiers (agent_id, room, counts). Do not log command content, env, or tokens. Reuse existing
  redaction/`Secret` patterns where any sensitive value is in scope.
- **Unix-only; no `unsafe`; MSRV 1.74.** No new dependencies that raise MSRV. `RoomEventFilter` and
  `MessagesOptions::{from,filter}` are already available via the pinned matrix-sdk 0.18 / ruma 0.19.
- **DoS bound on the scan.** The pagination loop must enforce `MAX_HEARTBEAT_SCAN_EVENTS` /
  `MAX_HEARTBEAT_SCAN_PAGES` so a hostile or pathological timeline cannot make a liveness query scan
  unbounded history.

## Testing Plan

**Unit tests (daemon, no live homeserver):**
- `heartbeat.rs`:
  - A heartbeat whose `sender` does not match the registered `matrix_user_id` is ignored; a
    matching-sender heartbeat is accepted. (Exercise the sender-pin predicate directly; if
    `read_latest_heartbeats` is hard to unit-test without a `Room`, factor the per-event
    accept/reject decision into a pure helper, e.g. `accept_heartbeat(expected, sender, agent_id)`,
    and unit-test that.)
  - Pagination bound: a pure helper deciding "continue paginating?" honors
    `MAX_HEARTBEAT_SCAN_EVENTS` / page-count and early-terminates when all expected agents are found.
- `inflight.rs`: increment on `enter`, decrement on drop; count is correct across
  start→finish, start→cancel, start→reject, and concurrent overlapping guards for the same
  `agent_id`; entry removed (count back to 0) after all guards drop.
- `task_diagnostics.rs`:
  - No `assigned_to_inactive_agent` warning when the durable state alone is stale/offline but the
    supplied verdict is `Active` (heartbeat lift).
  - Still warns `assigned_to_inactive_agent` when both signals are stale (verdict `Stale`/`Offline`).
  - Existing tests updated to pass the new precomputed-liveness argument (empty map preserves
    durable-only behavior).

**Live Tuwunel integration tests (`crates/mx-agent-daemon/tests/matrix_integration.rs`):**
- **Spoof rejection:** a heartbeat emitted by a *second* user carrying another agent's `agent_id`
  does not change that agent's verdict (the spoofed heartbeat is ignored; verdict reflects only the
  genuine sender).
- **Deep-scan find:** a genuine heartbeat older than 100+ newer timeline noise events is still found
  by the paginating `read_latest_heartbeats`.
- **`task.graph` no false warning:** `task.graph` over IPC emits no `assigned_to_inactive_agent` for
  a task assigned to a currently-heartbeating agent whose durable state has aged past the stale
  threshold.
- **Nonzero load:** `agent show` reflects a nonzero `running_invocations` during an in-flight exec,
  returning to `0` after it finishes.
- **Comment fix:** correct the existing comment that claims `read_latest_heartbeats` "paginates
  `/messages` backward" (now accurate after the pagination change) and update the direct caller to
  the new signature.

**Full gate:** `cargo fmt --check`, `cargo clippy -D warnings`, build, and the full test suite stay
green. No new dependency raises MSRV above 1.74.

## Documentation Updates

- `docs/architecture.md`:
  - Remove the "The **heartbeat** sender is not yet pinned …" caveat from the "Planned." block
    (~lines 997-1005); state that the heartbeat plane is now sender-pinned to the registered
    `matrix_user_id`, consistent with the result/stream/artifact/share plane (§1.2).
  - Update the scan description (~lines 989-995): replace "scan the most recent 100 timeline events"
    with the bounded backward-pagination behavior and the per-agent sender pin; keep the
    encrypted-room note that the scan decrypts heartbeats and that the server-side type filter is an
    unencrypted-room optimization only.
  - Note that `running_invocations` now reflects real in-flight invocations (no longer a placeholder).
- Rustdoc on the changed/added functions (`read_latest_heartbeats`, `diagnose_tasks*`, the new
  `inflight` module, `emit_heartbeat`'s load population).
- If a status table / README mentions heartbeat liveness caveats, reconcile it with the pinned
  behavior. Do not imply unimplemented alpha behavior exists.

## Risks and Open Questions

- **Encrypted-room scan cost.** Because the server-side type filter cannot match encrypted
  heartbeats, busy encrypted rooms rely entirely on bounded pagination. If `MAX_HEARTBEAT_SCAN_EVENTS`
  is too small, a very busy encrypted room could still miss heartbeats and degrade to durable-only
  (advisory, not a failure). Choose the bound to comfortably exceed the expected exec-stream burst
  between heartbeat ticks; document the chosen value. *Open question:* confirm `1000` events / `10`
  pages is an acceptable upper bound for liveness-query latency.
- **`diagnose_tasks` signature churn.** Several existing unit tests call `diagnose_tasks_at(tasks,
  agents, now)`; all must be updated to pass the new liveness map. Mechanical but broad.
- **Guard placement on the exec path.** The `InflightGuard` must be *moved into* the spawned run
  task (not held on the synchronous path), or it would drop immediately and never reflect the live
  invocation. Verify both the PTY and non-PTY spawns own a guard, and that the early-`return`
  terminal branches still drop it.
- **Counter vs. published value timing.** `running_invocations` is only republished on the next
  heartbeat tick / state refresh, so `agent show` may lag a fast exec by up to one heartbeat
  interval (30 s) for the durable view; the heartbeat timeline value updates each tick. This is
  acceptable for an advisory signal — call it out in docs rather than forcing an immediate state
  write per invocation (which would churn room state).
- **Call-path executing-agent resolution.** Confirm `request.target_agent` (Option) is the correct
  local executing agent to key the counter on in `handle_live_call_request`; skip counting when it
  is absent/unresolved rather than keying on an empty string.
- **Clean-shutdown convergence (optional).** Writing a final durable state on shutdown adds a
  network round-trip to the shutdown path; keep it strictly best-effort and time-bounded, and drop
  the item if it risks delaying shutdown.

## Implementation Checklist

1. **In-flight counter (`inflight.rs`).** Add the `OnceLock<Mutex<HashMap<String,u32>>>` registry,
   `running_invocations(agent_id)`, and the `InflightGuard` RAII type (saturating inc/dec, remove at
   0, poison-tolerant). Unit-test inc/dec/overlap/removal.
2. **Wire the guard at exec start.** In `spawn_authorized_live_exec`, create
   `InflightGuard::enter(&request.target_agent)` and move it into the spawned PTY and non-PTY run
   tasks so it drops on every terminal path.
3. **Wire the guard at call start.** In `handle_live_call_request`, hold an `InflightGuard` for the
   resolved local `target_agent` across tool execution + response; skip when unresolved.
4. **Publish the real load.** In `emit_heartbeat`, set `load.running_invocations` from
   `inflight::running_invocations(agent_id)` (preserving `max_invocations`) for both the timeline
   heartbeat and the durable-state refresh.
5. **Sender-pin the scan.** Change `read_latest_heartbeats` to take `agents: &[AgentState]`, build
   the expected `agent_id → matrix_user_id` map, extract each event's `sender`, and accept only
   matching-sender heartbeats for known agents. Factor a pure `accept_heartbeat(...)` helper for
   unit testing.
6. **Paginate the scan.** Replace the single page with a bounded backward pagination loop
   (per-page `HEARTBEAT_SCAN_LIMIT`, total `MAX_HEARTBEAT_SCAN_EVENTS` / `MAX_HEARTBEAT_SCAN_PAGES`,
   early-terminate when all expected agents are found, follow `messages.end` via `opts.from`).
   Optionally set `opts.filter.types` and comment that it is an unencrypted-room optimization only.
7. **Update `enrich_with_liveness`** (and any other caller) to pass the agent states to
   `read_latest_heartbeats`; preserve the durable-only degradation on read failure.
8. **Combined liveness in diagnostics.** Change `diagnose_tasks` / `diagnose_tasks_at` to accept a
   precomputed `HashMap<String, Liveness>` and evaluate the inactive-agent check against it (falling
   back to `liveness_of` when absent). Update all existing unit-test call sites.
9. **`task.graph` handler.** Switch `lifecycle.rs:591-610` to `list_agents_with_liveness_for_session`,
   build the `Vec<AgentState>` + `HashMap<String, Liveness>` from the `AgentListing`s, and pass both
   to `diagnose_tasks`; keep best-effort fallback to empty data.
10. **(Optional) Clean-shutdown convergence.** Best-effort, time-bounded durable state rewrite to a
    stopped/offline status for owned agents in the shutdown path; never block shutdown on failure.
11. **Tests.** Add the unit tests (steps 1, 5, 8) and the live integration tests (spoof rejection,
    deep-scan find, `task.graph` no-false-warning, nonzero `running_invocations`). Fix the misleading
    live-test comment and update the direct `read_latest_heartbeats` caller signature.
12. **Docs.** Remove the heartbeat "not yet pinned" caveat, correct the scan description, and note
    the real `running_invocations` in `docs/architecture.md`; add rustdoc to changed/added APIs.
13. **Gate.** Run `cargo fmt --check`, `cargo clippy -D warnings`, build, and the full test suite;
    confirm green and no MSRV bump.
