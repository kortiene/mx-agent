# Issue #199 — Wire live task scheduler loop into daemon sync

## Problem statement

The daemon already contains a complete, unit-tested task-orchestration core:
`TaskScheduler` (decides runnable tasks), `TaskOrchestrator` (authorizes via
signature/trust/replay + deny-by-default policy + approval, optimistically
claims with `state_rev`, dispatches, finalizes), the `ToolTaskDispatcher` /
`ExecTaskDispatcher`, and `recover_executing_tasks` for restart recovery. What
is missing is the *live wiring*: a running daemon does not auto-drive tasks from
real `com.mxagent.task.v1` Matrix room state. The orchestrator only operates
against an in-memory `TaskStore`; there is no Matrix-backed `TaskStore`, and
nothing reads task snapshots from `/sync` and ticks the scheduler.

`tests/task_orchestration_e2e.rs` already proves the orchestration acceptance
criteria against an in-memory model and notes: *"Wiring the same scheduler loop
onto a live `/sync` task feed is tracked separately."* That is this issue.

## Goals

- A Matrix-backed `TaskStore` that maps `claim`/`finalize` onto the existing
  `update_task` optimistic-concurrency contract (`expected_state_rev`), mapping
  a stale write to `TaskStoreError::StaleClaim`.
- A single reusable scheduler-tick function in the daemon library
  (`run_scheduler_tick`) so the live loop and tests share one implementation:
  restart recovery over `executing` tasks, then schedule + process runnable
  tasks, routing tool vs exec actions to the right dispatcher.
- A live scheduler loop wired into the daemon, driven off the daemon's Matrix
  session, that for each joined room and each agent this daemon owns:
  reads tasks, performs recovery, and ticks the orchestrator with
  policy/trust/replay/approval gates configured (so task state is advisory
  unless signed/trusted and denied actions never spawn).
- Restart recovery avoids double-running an `executing` task.

## Non-goals

- Live Matrix-backed *remote* call/exec task dispatch — that is issue #200,
  which swaps the local dispatchers used here for signed Matrix-backed ones.
  This issue uses the existing local `ToolTaskDispatcher`/`ExecTaskDispatcher`.
- E2EE in production, PTY, large artifacts, auto-claim of unassigned tasks
  (the loop only claims tasks assigned to one of this daemon's agents).

## Repository context

- `crates/mx-agent-daemon/src/scheduler.rs` — `TaskScheduler`.
- `crates/mx-agent-daemon/src/task_orchestrator.rs` — `TaskOrchestrator`,
  `TaskStore`, `TaskDispatcher`, `recover_executing_tasks`.
- `crates/mx-agent-daemon/src/task_dispatch.rs` — local dispatchers.
- `crates/mx-agent-daemon/src/task.rs` — `update_task`, `read_tasks`,
  `UpdateTaskOptions`, lifecycle helpers.
- `crates/mx-agent-daemon/src/sync.rs` / `lifecycle.rs` — `/sync` loop and the
  daemon thread that owns the Matrix session.
- `crates/mx-agent-daemon/src/agent.rs` — `read_all_agent_states`,
  `read_agent_state`, `AgentState` (signing key, `max_invocations`).
- `crates/mx-agent-daemon/src/{trust,replay,call}.rs` — trust store, replay
  cache, `verifying_key_from_agent_state`.

## Affected crates/modules

- `mx-agent-daemon` only. New module `scheduler_loop.rs`. Small additive helper
  in `task.rs` (`update_task_in_room`, a no-`/sync` update used by the
  Matrix-backed store and the loop). Wiring in `lifecycle.rs`. Re-exports in
  `lib.rs`. Docs in README + architecture.

## Implementation approach

1. **`task.rs`:** factor the body of `update_task` into a
   `update_task_in_room(room, options)` that operates on an already-resolved
   `Room` (no internal `/sync`), keeping `update_task` as a thin wrapper. The
   scheduler loop shares the daemon's Matrix client and must not run a second
   overlapping `/sync`.

2. **`scheduler_loop.rs`:**
   - `RoutingDispatcher<T, E>`: a `TaskDispatcher` that routes
     `TaskAction::Tool` to a tool dispatcher and `TaskAction::Exec` to an exec
     dispatcher, so one tick can process mixed actions.
   - `MatrixTaskStore`: a `TaskStore` bound to a `Room` plus a Tokio runtime
     handle; `claim`/`finalize` inject the room and `block_on`
     `update_task_in_room`, mapping `WorkspaceError::StaleTaskUpdate` →
     `TaskStoreError::StaleClaim`, `TaskNotFound` → `NotFound`, else `Other`.
     The Matrix-backed default is wrapped behind an injectable updater so the
     error mapping is unit-tested without a homeserver.
   - `run_scheduler_tick(scheduler, orchestrator, store, dispatcher, snapshot,
     live_invocations) -> SchedulerTickReport`: runs `recover_executing_tasks`
     then processes scheduler-runnable tasks via `process_one`. Pure/sync and
     fully unit-testable. Returns the per-task outcomes.
   - `run_scheduler_loop` (live): a dedicated thread with its own current-thread
     runtime sharing the daemon's restored `Client`; periodically, for each
     joined room and each agent owned by this daemon (agent state
     `matrix_user_id == client.user_id()`), build the policy/trust/replay/
     verifying-key-configured orchestrator and a `MatrixTaskStore`, and tick.
     Local synchronous dispatch means an `executing` task observed at the start
     of a fresh tick is stale, so recovery uses an empty live-invocation set.

3. **`lifecycle.rs`:** `spawn_scheduler_loop(running, ...)` analogous to
   `spawn_sync_loop`, started in `run_foreground` and stopped on shutdown.

## Security considerations

- Task state is advisory: the loop configures the orchestrator with trust store,
  replay cache, and resolved verifying keys, so an unsigned/untrusted/expired/
  replayed task action is blocked before any claim/dispatch.
- Deny-by-default policy is evaluated before claim; a denied action is finalized
  `blocked` and never spawns (already enforced by the orchestrator core).
- Approval gate: when configured policy requires approval the loop fails closed
  (no gate ⇒ `AwaitingApproval`, no spawn). (Wiring a live approval gate beyond
  fail-closed is follow-up.)
- The loop only claims tasks assigned to one of this daemon's own agents
  (`auto_claim = false`); Matrix room membership never implies execution.
- No secrets logged; only non-sensitive task ids/states/decisions, consistent
  with the orchestrator's existing logging.

## Testing plan

- Unit: `MatrixTaskStore` error mapping (stale/not-found/other) via injected
  updater; `RoutingDispatcher` routes tool vs exec and rejects the wrong kind;
  `run_scheduler_tick` covers all acceptance criteria with an in-memory store +
  fake dispatchers: dependency blocks until succeeded, success → terminal,
  denied → blocked without spawn, recovery of a stale `executing` task does not
  re-dispatch.
- Reuse: update `tests/task_orchestration_e2e.rs` to drive the shared
  `run_scheduler_tick` so the library function is exercised end-to-end against
  the in-memory room model (keeps it in the default `cargo test --all`).

## E2E decision

A live-homeserver E2E (create a tool/exec task, assert the running daemon
auto-executes it) requires Docker/Tuwunel and is **not** added to the default
`cargo test --all`. The deterministic in-memory orchestration E2E already covers
the behavioral criteria; the Matrix-backed store/loop is exercised by the shared
tick. A Docker-gated live test is noted as follow-up to avoid making the default
suite depend on external services (matching existing `matrix_integration.rs`
conventions).

## Risks / open questions

- Sharing the daemon `Client` across the sync thread and the scheduler thread:
  mitigated by the scheduler thread never running its own `/sync` (reads come
  from the store the main loop populates; writes are independent state-event
  PUTs).
- Loop cadence is a fixed interval; a future change can make it event-driven
  off the router. Acceptable for alpha.

## Implementation checklist

- [ ] `update_task_in_room` factored in `task.rs` (+ test).
- [ ] `scheduler_loop.rs`: `RoutingDispatcher`, `MatrixTaskStore`,
      `run_scheduler_tick`, `run_scheduler_loop` (+ unit tests).
- [ ] `lifecycle.rs`: spawn/stop the scheduler loop.
- [ ] `lib.rs` re-exports.
- [ ] `tests/task_orchestration_e2e.rs` uses the shared tick.
- [ ] README status table + `docs/architecture.md` note updated.
- [ ] `cargo fmt --check`, `clippy -D warnings`, `test --all`, `build --all`.
