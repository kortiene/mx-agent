# Daemon Task Scheduler: Runnable Task Detection

## Problem Statement

Tasks stay `pending` because nothing in the daemon decides which tasks are runnable. The orchestrator can claim/dispatch a single task (`process_one`) and expose `runnable_tasks`, but there is no scheduler that evaluates the full runnable condition (assignment/auto-claim, dependencies, executable action, capacity) and logs non-sensitive decisions.

## Goals

- Detect pending/assigned tasks whose dependencies are satisfied.
- Ignore terminal tasks and tasks blocked by failed/pending dependencies.
- Require an executable action before a task is considered runnable.
- Respect a per-agent capacity (load) limit.
- Support assignment to the local agent or an explicit auto-claim policy.
- Emit non-sensitive structured scheduler decisions via `tracing`.
- Provide deterministic unit tests for the dependency/runnability logic.

## Non-Goals

- Do not implement the live Matrix `/sync` watch wiring in this issue (existing `crate::watch` provides snapshots; the scheduler consumes task snapshots).
- Do not change claiming semantics (issue #161) or execution (issues #162/#163).
- Do not change policy/trust/signature enforcement (already in the orchestrator).

## Relevant Repository Context

- `mx-agent-daemon::task_orchestrator` exposes `runnable_tasks`, `action_from_task`, and lifecycle constants.
- `mx-agent-daemon::task` exposes lifecycle helpers `is_runnable`/`is_terminal`.
- `AgentLoad`/heartbeat give a model for running vs. max invocations (capacity).

## Proposed Implementation

1. Add a `scheduler` module with:
   - `ScheduleDecision` enum (Runnable, NotAssigned, TerminalState, NotSchedulableState, DependenciesUnmet, NoExecutableAction, AtCapacity).
   - `TaskScheduler` configured with `agent_id`, `max_invocations` (capacity), and an `auto_claim` flag.
   - `evaluate(task, all_tasks, remaining_capacity)` -> `ScheduleDecision`.
   - `schedule(tasks, running_count)` -> runnable tasks (respecting capacity), logging a non-sensitive decision per task.
2. Determine "dependencies satisfied" by checking that every `depends_on` id is in the set of `succeeded` tasks.
3. Determine "executable action" via `action_from_task(task).is_ok()`.
4. Log each decision at debug level with only `task_id`, `state`, and decision kind.

## Affected Files / Crates / Modules

- `crates/mx-agent-daemon/src/scheduler.rs` (new)
- `crates/mx-agent-daemon/src/lib.rs`
- `docs/architecture.md` (scheduler note)

## CLI / API Changes

- New public daemon API: `TaskScheduler`, `ScheduleDecision`.
- No CLI changes.

## Data Model / Protocol Changes

None.

## Security Considerations

- Scheduler decisions log only non-sensitive identifiers and states.
- Detection does not execute anything; execution remains gated by policy/trust in the orchestrator.

## Testing Plan

- Unit tests: dependency satisfaction/blocking, terminal exclusion, unassigned exclusion (and auto-claim inclusion), missing executable action exclusion, capacity limiting.

## Documentation Updates

- Note the scheduler decision step in architecture task orchestration text.

## Implementation Checklist

- [ ] Add `scheduler` module with decisions + scheduler.
- [ ] Export public types.
- [ ] Add unit tests.
- [ ] Update docs.
- [ ] Run required checks.
