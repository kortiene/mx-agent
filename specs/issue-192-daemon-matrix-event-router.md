# Daemon Matrix Event Router for `/sync`

## Problem Statement

`run_matrix_sync()` drives the long-lived Matrix `/sync` loop, persisting batch
tokens and reporting health, but it discards every event in each sync response
except `next_batch`. Nothing in the daemon observes mx-agent Matrix events
(`com.mxagent.*`) as they arrive, so live orchestration (remote `exec`/`call`,
task/invocation updates, approvals, heartbeats) cannot be driven by `/sync`.

This issue adds a daemon **event-router layer** that receives Matrix sync
timeline events and dispatches supported mx-agent event types to handlers, while
safely ignoring unknown events, rejecting malformed ones, never routing
undecryptable encrypted events, and replay-checking privileged requests before
any handler can act.

## Goals

- Add a routing layer that classifies and dispatches the mx-agent event types
  listed in the issue to handlers (stub handlers for this issue).
- Ignore unknown event types without error.
- Reject malformed events (content that does not match the declared type)
  without panicking and without dispatching.
- Never route opaque/undecryptable encrypted (`m.room.encrypted`) events to a
  handler.
- Replay/expiry-check privileged execution requests (`exec.request`) before
  dispatch, using the existing `ReplayCache`.
- Wire the router into the live `/sync` loop so the daemon observes mx-agent
  events during sync, dispatching to a non-sensitive logging stub.
- Prove with tests that malformed/encrypted/replayed privileged events do not
  reach a handler.

## Non-Goals

- No execution of routed events: handlers are stubs in this issue. Actual
  authorization (signature + trust + policy + approval) and dispatch remain the
  responsibility of the existing orchestrator/exec/call paths and are wired to
  real handlers in follow-up work (#191 epic).
- No change to the signed Matrix transport for remote `exec`/`call` (#155).
- No reconciliation of pre-timeline room **state** snapshots: the router
  consumes timeline events (which include state events that land in the
  timeline window). Durable state snapshots are still read via the existing
  `get_state_event(s)` helpers.
- No new Matrix event schema or protocol-type changes.

## Relevant Repository Context

- `mx-agent-daemon::sync` owns `run_matrix_sync()` / `run_sync_loop()` and the
  `Backoff`/`SyncHealth` machinery.
- `mx-agent-daemon::replay::ReplayCache` provides nonce replay + expiry checks
  for privileged requests (`admit(nonce, expires_at)`), persisted `0600`.
- `mx-agent-protocol::events` defines the `timeline`/`state` type constants.
- `mx-agent-protocol::schema` defines the serde content structs (`ExecRequest`,
  `CallRequest`, `TaskState`, …), all tolerant of unknown fields via `extra`.
- Existing event extraction pattern (e.g. `context.rs`, `agent.rs`) uses
  `Raw::get_field::<String>("type")` / `Raw::get_field::<T>("content")`.
- `matrix_sdk::sync::SyncResponse` → `rooms.joined: BTreeMap<RoomId,
  JoinedRoomUpdate>` → `timeline.events: Vec<TimelineEvent>`; a `TimelineEvent`
  exposes `.raw()` (the encrypted event for UTDs, type `m.room.encrypted`) and
  `.event_id()`.

## Proposed Implementation

Add `crates/mx-agent-daemon/src/event_router.rs`:

1. **Transport-agnostic input** `IncomingEvent { event_type, room_id, sender,
   event_id, state_key, encrypted, content: serde_json::Value }`. This decouples
   the pure routing logic from `matrix_sdk` so it is fully unit-testable.
2. **Classification** `classify(event_type) -> Option<EventCategory>` mapping the
   mx-agent type constants to a stable `EventCategory` enum, plus
   `EventCategory::is_privileged()`.
3. **Routed payloads** `RoutedEvent` enum carrying the parsed protocol struct for
   each supported category (boxed where large).
4. **Outcome** `RouteOutcome` enum: `Dispatched(category)`, `Ignored`,
   `SkippedEncrypted`, `Malformed(category)`, `ReplayRejected(category)`.
5. **Router** `EventRouter` owning a `ReplayCache`. `route(ev, &mut sink)`:
   - if `ev.encrypted` → `SkippedEncrypted` (never parse/dispatch);
   - `classify` → `None` ⇒ `Ignored`;
   - parse `content` into the typed `RoutedEvent` → failure ⇒ `Malformed`;
   - for `exec.request`, `replay.admit(nonce, expires_at)` → failure ⇒
     `ReplayRejected`;
   - otherwise build `EventMeta` and call the sink, returning `Dispatched`.
6. **Matrix adapter** `events_from_sync_response(&SyncResponse) ->
   Vec<IncomingEvent>` extracting timeline events from joined rooms via the
   `Raw::get_field` pattern; `m.room.encrypted` ⇒ `encrypted = true`.
7. **Sync wiring**: `run_matrix_sync()` constructs an `EventRouter` (loading the
   replay cache from `paths`) and, after each successful `sync_once`, routes the
   response through it with a non-sensitive logging sink before returning the
   next batch token.

## Affected Files / Crates / Modules

- `crates/mx-agent-daemon/src/event_router.rs` (new)
- `crates/mx-agent-daemon/src/sync.rs` (wire router into `run_matrix_sync`)
- `crates/mx-agent-daemon/src/lib.rs` (module + re-exports)
- `docs/architecture.md` (implementation note: `event_router`)

## CLI / API Changes

- New public daemon API: `EventRouter`, `IncomingEvent`, `RoutedEvent`,
  `EventCategory`, `RouteOutcome`, `EventMeta`, `classify`,
  `events_from_sync_response`.
- No CLI surface or `--json`/human-output changes.

## Data Model / Protocol Changes

None. The router reuses existing `mx-agent-protocol` content structs and event
type constants.

## Security Considerations

- **No execution at the router layer.** The router only classifies, parses,
  replay-checks, and hands off to a handler; it performs no side effects.
  Privileged handlers must still verify signature + local trust + policy +
  approval before any execution (architecture §9.2, §13).
- **Encrypted/undecryptable events never route.** `m.room.encrypted` events are
  skipped before classification, so they cannot reach authorization/execution.
- **Malformed events never dispatch.** Content that fails to deserialize into its
  declared type yields `Malformed` with no handler call and no panic.
- **Replay protection.** Privileged `exec.request` events are admitted through
  the persistent `ReplayCache` (expiry + replay) before dispatch.
- **No secret/payload logging.** The logging sink records only event type, room,
  sender, event id, and the outcome — never full event content.

## Testing Plan

Focused unit tests in `event_router.rs`:

- `classify` maps every supported type and rejects unknown types.
- Known events dispatch to the sink with the right `RoutedEvent` variant.
- Unknown event types are `Ignored` and never reach the sink.
- Malformed privileged (`exec.request`, `call.request`) content is `Malformed`
  and never dispatched (acceptance: malformed privileged events do not execute).
- Encrypted (`m.room.encrypted`) privileged events are `SkippedEncrypted` and
  never dispatched (acceptance: E2EE undecryptable does not route).
- Replayed/expired `exec.request` is `ReplayRejected` and dispatched at most once.
- The logging sink/outcome contains no event content (redaction regression).

## E2E Decision

No new e2e/Docker test. The router is decoupled from `matrix_sdk` via
`IncomingEvent`, and the matrix adapter is a thin field-extraction shim; the
security-critical behavior (dispatch, malformed/encrypted/replay rejection) is
fully covered by deterministic unit tests without a live homeserver. Adding a
Docker/Matrix integration test would not increase confidence in the routing
invariants and would make `cargo test --all` depend on external services, which
is against project convention. (`E2E decision: not added because lower-level
tests fully cover the routing invariants and the matrix adapter is a thin shim.`)

## Risks / Open Questions

- The matrix adapter depends on `matrix_sdk::sync::SyncResponse` shape; verified
  against matrix-sdk 0.18 (`rooms.joined` → `timeline.events`).
- Timeline-only extraction means a state event that changed strictly before the
  timeline window (e.g. on the very first sync) is observed via the existing
  state-read helpers rather than the router. This is acceptable for live
  observation and documented as a non-goal.

## Implementation Checklist

- [ ] `event_router.rs` with pure router + matrix adapter and docs.
- [ ] Wire router into `run_matrix_sync` with a non-sensitive logging sink.
- [ ] Re-export new public API from `lib.rs`.
- [ ] Unit tests covering dispatch, ignore, malformed, encrypted, replay.
- [ ] Architecture doc note.
- [ ] `cargo fmt --check`, `clippy -D warnings`, `test --all`, `build --all`.
