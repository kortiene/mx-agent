# Task Lifecycle Transition Validation

## Problem Statement

Task state updates currently accept arbitrary lifecycle strings, which can let daemon-originated claims/finalization or manual CLI updates move tasks through invalid transitions. The architecture defines a lifecycle and scheduler safety requires terminal tasks to never be auto-executed again.

## Goals

- Add documented lifecycle helpers: `can_transition(from, to)`, `is_terminal(state)`, and `is_runnable(state)`.
- Cover `proposed` plus at minimum `pending`, `assigned`, `executing`, `succeeded`, `failed`, `cancelled`, `blocked`, and `superseded`.
- Reject invalid daemon task updates before publishing new Matrix state.
- Make CLI manual `--state` updates reject unknown states and warn/reject invalid obvious transitions when it has enough local information.
- Ensure terminal states are not auto-executed again.

## Non-Goals

- Do not implement a rich conflict resolution UI.
- Do not change protocol event type names or Matrix schemas beyond adding helper APIs.
- Do not alter signing, policy, trust, or dispatcher authorization semantics.
- Do not add Docker/Matrix/live-service e2e tests.

## Relevant Repository Context

- `mx-agent-daemon::task` builds and updates `TaskState` and has stale update guards.
- `mx-agent-daemon::task_orchestrator` currently has string constants for common lifecycle states and only schedules `pending`/`assigned` tasks.
- `mx-agent-cli` sends `task.update` over stateless IPC and can reject bad state strings before contacting the daemon.
- `WorkspaceError` is the shared daemon error surface for task update failures.

## Proposed Implementation

1. Add lifecycle helpers in the daemon task layer (or protocol-adjacent module if useful) with public documentation:
   - state constants for all required lifecycle states
   - `is_known_state(state) -> bool`
   - `is_terminal(state) -> bool`
   - `is_runnable(state) -> bool`
   - `can_transition(from, to) -> bool`
2. Transition rules:
   - self-transitions are allowed as idempotent republishes
   - `proposed -> pending|superseded|cancelled`
   - `pending -> assigned|blocked|superseded|cancelled`
   - `assigned -> pending|executing|blocked|superseded|cancelled`
   - `blocked -> pending|assigned|superseded|cancelled`
   - `executing -> succeeded|failed|cancelled`
   - terminal states (`succeeded`, `failed`, `cancelled`, `superseded`) do not transition to non-terminal states
3. Validate `CreateTaskOptions.state` is known when creating a task.
4. Validate `UpdateTaskOptions.state` against the current state before applying an update.
5. Add `WorkspaceError` variants for unknown and invalid lifecycle states.
6. Update orchestrator to use `is_runnable`/`is_terminal` helpers instead of ad-hoc string matching.
7. Add CLI state validation for `task create --state` and `task update --state`. Because the stateless CLI does not know the prior state during manual update, it should reject unknown states locally; the daemon rejects invalid transitions after reading current task state.

## Affected Files / Crates / Modules

- `crates/mx-agent-daemon/src/task.rs`
- `crates/mx-agent-daemon/src/task_orchestrator.rs`
- `crates/mx-agent-daemon/src/workspace.rs`
- `crates/mx-agent-daemon/src/lib.rs`
- `crates/mx-agent-cli/src/cli.rs`
- `docs/architecture.md` if transition wording needs alignment

## CLI / API Changes

- New public daemon helper APIs for task lifecycle validation.
- CLI rejects unknown lifecycle state strings for task create/update.
- Daemon rejects invalid transitions with a structured `WorkspaceError`.

## Data Model / Protocol Changes

None. This validates existing `TaskState.state` values and transitions; no event type or serialized field changes are required.

## Security Considerations

- Invalid transitions must not permit terminal tasks to be scheduled or re-spawned.
- Scheduler and dispatcher still use signed/trust/policy-controlled execution paths.
- CLI remains stateless and does not read credentials or Matrix state.
- Error messages must be non-sensitive.

## Testing Plan

- Unit tests for all lifecycle helpers and representative valid/invalid transitions.
- Daemon task tests for invalid create state and invalid update transition.
- Orchestrator tests confirming terminal tasks are not runnable.
- CLI tests for rejecting unknown states.

## Documentation Updates

- Keep architecture lifecycle table aligned if helper rules refine it.

## Risks and Open Questions

- Existing callers may rely on arbitrary custom states. The issue requires validation for the architecture states, so unknown state rejection is intentional.
- Some manual override workflows may want to reopen terminal tasks; this remains out of scope and can be added later with explicit force semantics.

## Implementation Checklist

- [ ] Add lifecycle constants/helpers and docs.
- [ ] Add `WorkspaceError` variants/display messages.
- [ ] Validate create/update states in daemon.
- [ ] Update orchestrator scheduling checks.
- [ ] Add CLI state validation.
- [ ] Add focused tests.
- [ ] Run required checks.
