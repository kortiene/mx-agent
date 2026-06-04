# Daemon Task Orchestration Lifecycle

## Problem Statement

`mx-agent task` can publish and mutate durable Matrix task state, but no daemon-owned scheduler claims runnable work, enforces dependency and policy gates, dispatches tool/exec actions, records invocation links, or recovers stale local work. This leaves task DAGs as passive state instead of daemon-driven orchestration.

## Goals

- Add a daemon-side orchestration core that detects runnable assigned tasks.
- Block tasks until all dependencies are terminal-success.
- Claim tasks with the task's observed `state_rev` so stale claims do not overwrite newer Matrix state.
- Support structured task actions for named tools and exec-backed work without exposing credentials to the CLI/coding agent.
- Dispatch only after a local policy/trust gate approves the action.
- Advance task state through `executing` and terminal states, attach invocation IDs, and store structured results.
- Provide restart/recovery behavior for stale local `executing` work.
- Add focused deterministic tests for success, dependency blocking, policy denial, stale-claim, and recovery decisions.

## Non-Goals

- No new Matrix credentials or device-key exposure to CLI commands.
- No change to Matrix room membership semantics; membership does not grant execution permission.
- No Windows support.
- No default test dependency on Docker, external homeservers, or live services.
- No broad rewrite of the existing Matrix sync loop.

## Relevant Repository Context

- `crates/mx-agent-daemon/src/task.rs` publishes and updates `com.mxagent.task.v1` state with optimistic `state_rev` checks.
- `TaskState` in `mx-agent-protocol` has a forward-compatible `extra` map. Structured task action payloads can be stored under `extra["action"]` without breaking older readers.
- `crates/mx-agent-daemon/src/exec.rs`, `call.rs`, `runner.rs`, and `tool_exec.rs` contain existing request, invocation, and execution primitives.
- `crates/mx-agent-daemon/src/invocation.rs` already models invocation lifecycle and terminal state names.
- Security constraints require daemon-owned credentials, signed privileged requests, deny-by-default local policy, and redacted logs.

## Proposed Implementation

Implement a new `task_orchestrator` module with a testable core independent of live Matrix I/O:

1. Parse `TaskState.extra["action"]` into a `TaskAction` enum:
   - `{"type":"tool","tool":"run_tests","args":{...}}`
   - `{"type":"exec","command":[...],"cwd":"...","env":{...},"timeout_ms":...}`
2. Select runnable tasks whose state is `pending`, assigned to the local agent, and whose dependencies are all `succeeded`.
3. Return dependency-blocking, malformed-action, unassigned, already-terminal, and stale-local-work decisions explicitly.
4. Claim by calling an abstract store with `expected_state_rev = observed state_rev`, transition to `executing`, and attach a generated invocation ID.
5. Dispatch through an abstract `TaskDispatcher` that represents the existing policy/trust/exec/tool path. The dispatcher returns success, failure, or policy denial.
6. Finalize the task with `succeeded`/`failed` and structured result payload including invocation ID, action kind, exit code, and policy-denial reason when applicable.
7. Recover stale local work by marking assigned `executing` tasks without a live invocation as failed with a recovery result rather than double-spawning.

## Affected Files / Crates / Modules

- `crates/mx-agent-daemon/src/task_orchestrator.rs` (new)
- `crates/mx-agent-daemon/src/lib.rs` (exports)
- `docs/architecture.md` (status/behavior note)
- Possibly `docs/user-guide.md` if user-visible status claims change

## CLI / API Changes

No new CLI commands. New public daemon APIs/types are documented and exported for daemon integration.

## Data Model / Protocol Changes

No required schema fields. Task actions are forward-compatible content in `TaskState.extra["action"]`.

## Security Considerations

- The orchestrator is daemon-side only; the CLI remains stateless.
- The dispatcher abstraction must represent signed, trust-checked, deny-by-default policy authorization before execution.
- Dependency satisfaction never implies execution permission.
- Malformed, stale, unassigned, policy-denied, or replayed work must not spawn.
- Result payloads must avoid secrets and use structured, non-sensitive summaries.

## Testing Plan

- Unit tests for action parsing and malformed payload rejection.
- Scheduler tests for runnable selection, dependency blocking, stale claim rejection, and assigned-agent filtering.
- Orchestration tests for success and policy denial paths.
- Recovery tests for stale `executing` tasks without live invocations.
- Full workspace checks: build, test, fmt, clippy.

## Documentation Updates

- Update architecture task section with daemon orchestration core and action payload convention.
- Do not claim full live Matrix e2e coverage unless added.

## Risks and Open Questions

- Full live Matrix scheduler integration is broad; this implementation keeps the core deterministic and ready to wire into the sync loop without adding flaky network tests.
- The exact public task action schema may evolve; using `extra["action"]` preserves compatibility.

## Implementation Checklist

- [ ] Add `task_orchestrator` module and exports.
- [ ] Define `TaskAction`, `TaskExecutionResult`, `TaskDispatchError`, `TaskDispatcher`, and store abstractions.
- [ ] Implement runnable/dependency/stale recovery decisions.
- [ ] Implement claim-dispatch-finalize orchestration.
- [ ] Add focused tests.
- [ ] Update architecture docs.
- [ ] Run required checks.
