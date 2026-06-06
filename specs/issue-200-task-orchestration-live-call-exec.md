# Issue #200 — Integrate task orchestration with live call and exec

## Problem statement

After #199 the daemon auto-drives tasks, but its scheduler loop dispatches task
actions through the **local** in-process dispatchers (`ToolTaskDispatcher`,
`ExecTaskDispatcher`). Fully distributed orchestration should be able to route a
task action through the **same signed Matrix-backed `call`/`exec` transport** a
direct CLI invocation uses (#194/#196):

```text
TaskAction::Tool -> live call.request -> call.response -> task result
TaskAction::Exec -> live exec.request -> stream/finished -> task result
```

## Goals

- `TaskDispatcher` implementations that run a task action through the live
  transport: `MatrixCallTaskDispatcher` (tool) and `MatrixExecTaskDispatcher`
  (exec), composable with the existing `RoutingDispatcher` (named-tool preferred).
- Faithful task-result mapping from the transport outcome: exit code, a
  non-sensitive summary that carries the remote invocation id, and the linked
  stream **artifact** ref (`mxc_uri`) when the exec produced one.
- A denied/failed remote action maps to a failed task and never spawns locally
  (the orchestrator's own deny-by-default policy still gates before dispatch).
- Make the scheduler loop able to select Matrix-backed dispatch, keeping the
  verified-safe local dispatch as the default.

## Non-goals

- Changing the default scheduler dispatch (stays local from #199).
- Tight bidirectional task↔invocation id unification (the transport entry points
  mint their own invocation id; the task result records the orchestrator's
  invocation id and the remote one in its summary — full id unification is
  follow-up). Forwarding task exec `env`/`timeout_ms` through `start_exec_matrix`
  is likewise follow-up (that entry point fixes them today).

## Repository context

- `crates/mx-agent-daemon/src/call.rs` — `start_call_matrix` (self-contained:
  signs, sends `call.request`, awaits `call.response`).
- `crates/mx-agent-daemon/src/exec_ipc.rs` — `start_exec_matrix(params,
  subscribers)` (signs, sends `exec.request`, awaits stream/finished forwarded
  into the daemon's shared `ExecSubscriberRegistry`).
- `crates/mx-agent-daemon/src/scheduler_loop.rs` (#199) — the live loop and
  `RoutingDispatcher`; `MatrixTaskStore`; `run_scheduler_tick`.
- `crates/mx-agent-daemon/src/task_orchestrator.rs` — `TaskDispatcher`,
  `TaskExecutionResult`, `TaskDispatchError`.

Self-dispatch is consistent with shipped behavior: a task assigned to one of
this daemon's agents is dispatched with `target_agent = assignee`; the daemon's
main `/sync` loop routes the request to its own
`handle_live_call_request`/`handle_live_exec_request`, which verify signature →
trust → policy and execute — exactly the path an IPC-initiated `call`/`exec`
to a self-owned agent already takes today.

## Affected crates/modules

- `mx-agent-daemon` only. New module `task_dispatch_matrix.rs`. Wiring in
  `scheduler_loop.rs` (a `TaskDispatchMode`) and `lifecycle.rs` (env-selected
  mode + share the exec subscriber registry). Re-exports in `lib.rs`. Docs.

## Implementation approach

1. **`task_dispatch_matrix.rs`:**
   - `map_call_outcome(CallStartResult) -> Result<TaskExecutionResult,
     TaskDispatchError>`: `Ok{exit_code,summary}` → success result (summary notes
     the remote invocation id); `Error{..}` → `TaskDispatchError::Failed`.
   - `map_exec_outcome(ExecStartResult) -> Result<...>`: from the `Ok{frames}`
     extract the terminal `Finished` frame's exit code/signal and the first
     `Artifact` frame's `mxc_uri`; `Error{..}` → `Failed`.
   - `MatrixCallTaskDispatcher<C>` / `MatrixExecTaskDispatcher<E>`: build
     `CallStartParams`/`ExecStartParams` from the task action with
     `agent = task.assigned_to`, run an injected runner, and map the outcome.
     Reject the wrong action kind. The runner is injectable so the mapping is
     unit-tested without a homeserver; the live default `block_on`s
     `start_call_matrix`/`start_exec_matrix`.
2. **`scheduler_loop.rs`:** add `TaskDispatchMode { Local, Matrix }`; the live
   loop/pass takes the mode and the shared `ExecSubscriberRegistry` and, per
   agent, builds either the local `RoutingDispatcher::default()` or a
   Matrix-backed routing dispatcher.
3. **`lifecycle.rs`:** select the mode from `MX_AGENT_TASK_DISPATCH`
   (`local` default, `matrix` opt-in) and pass the daemon's exec subscriber
   registry to the scheduler loop.

## Security considerations

- Same trust/policy/approval path as direct `call`/`exec`: the orchestrator
  authorizes (signature/trust/replay + deny-by-default policy + approval) before
  any claim or dispatch, and the **target** daemon independently re-verifies the
  signed request before executing. A revoked signing key cannot trigger
  execution on either side.
- A remote rejection/denial maps to a failed task; no local process is spawned.
- No secrets in summaries/logs (only ids, exit codes, non-sensitive text).
- Default behavior is unchanged (local dispatch); the Matrix path is opt-in.

## Testing plan

- Unit: `map_call_outcome`/`map_exec_outcome` (success, nonzero exit, signal,
  artifact linkage, error→failed); dispatchers route by action kind, target the
  assignee, and reject the wrong kind, driven by injected fake runners.
- Reuse the orchestrator/tick to prove a denied action never reaches the runner.

## E2E decision

A live-homeserver E2E (a tool/exec task executed over Matrix by a target daemon)
needs Docker/Tuwunel and is **not** added to the default `cargo test --all`. The
underlying transport is already covered by the #194/#196 live integration tests;
this issue adds the task→transport mapping, covered deterministically by unit
tests. A Docker-gated task-over-Matrix E2E is noted as follow-up.

## Risks / open questions

- Loose task↔remote-invocation id linkage and unforwarded exec `env`/`timeout`
  (follow-up; documented as non-goals).
- The Matrix dispatch path is opt-in and not Docker-verified here; the default
  stays the verified local path.

## Implementation checklist

- [ ] `task_dispatch_matrix.rs`: mapping + dispatchers (+ unit tests).
- [ ] `scheduler_loop.rs`: `TaskDispatchMode` + Matrix dispatcher wiring.
- [ ] `lifecycle.rs`: env-selected mode + shared subscriber registry.
- [ ] `lib.rs` re-exports; README/architecture docs.
- [ ] `cargo fmt --check`, `clippy -D warnings`, `test --all`, `build --all`.
