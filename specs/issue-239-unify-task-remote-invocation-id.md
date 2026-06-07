# Unify task↔remote-invocation id (task cancel drives remote invocation)

Implements GitHub issue #239. Split out from epic #191; roadmap-adjacent (phases
10/12). Builds on the restart-recovery clobber-protection landed in #230.

## Problem Statement

A claimed task records an `invocation_id` and the daemon publishes
`com.mxagent.invocation.v1` lifecycle state, so a task and its invocation are
*nominally* linked. Invocation-level cancel works over IPC
(`invocation.cancel`), signs a `com.mxagent.exec.cancel.v1`, and the target
terminates the process group and emits `com.mxagent.exec.cancelled.v1`.

Two gaps remain:

1. **The ids are not actually unified for Matrix-dispatched tasks.** The
   orchestrator (`task_orchestrator::process_one`) generates an `invocation_id`
   via `generate_invocation_id()`, claims the task with it, and passes it to the
   `TaskDispatcher`. But every dispatcher ignores it (`_invocation_id`), and the
   live Matrix transport (`start_exec_matrix` / `start_call_matrix`) **mints its
   own fresh id**. So the id stored on the task is *not* the id of the
   `com.mxagent.invocation.v1` state event that actually runs the action. Cancel
   and recovery cannot reliably find the real invocation from the task.

2. **There is no task-side cancel.** Only `invocation.cancel` exists. Nothing
   lets an operator cancel a *task* such that its linked remote invocation is
   driven to `cancelled` and the owning task is finalized `cancelled`. The README
   lists "tight task↔remote-invocation id unification" as planned.

## Goals

1. Define and enforce the canonical id relationship for local-synchronous vs
   `MX_AGENT_TASK_DISPATCH=matrix` task dispatch: **the `invocation_id` a task
   records is the id of the invocation that actually runs the action.** For
   Matrix dispatch this is the remote `com.mxagent.invocation.v1` state event's
   id; the orchestrator-minted id flows through into the signed request so they
   are one id.
2. Add `task.cancel` (IPC + daemon function + CLI): read the task → cancel the
   linked invocation (signed/trust/policy/ownership-checked, exactly as
   `invocation.cancel`) → finalize the task `cancelled`, surfacing the remote
   `exec.cancelled` / `call` outcome onto the task `result`.
3. Make restart recovery reconcile an `executing` task against the *actual*
   invocation state by the unified id: a remote invocation that already finished
   reconciles the task to the matching terminal state (rather than blindly
   marking it `failed`); a still-running remote invocation leaves the task
   `executing`; only a genuinely missing invocation is recovered `failed`. Never
   clobber a task finalized this run (#230) or any already-terminal task.
4. Tests: unification mapping; task cancel → linked-invocation cancel → task
   `cancelled`; recovery reconciliation by unified id; a live e2e test that task
   cancel propagates to a live remote invocation.

## Non-Goals

- Interactive PTY cancel semantics (separate planned item).
- Cancelling an in-flight **local-synchronous** dispatch mid-run. Local dispatch
  runs in-process and blocks the scheduler thread from claim→finalize, so there
  is no externally-cancellable live invocation; task cancel of such a task is a
  best-effort finalize and is documented as such.
- Changing the signing/trust/policy model. Cancel reuses the existing signed exec
  cancel authorization path unchanged.
- New invocation lifecycle states or task lifecycle states.

## Relevant Repository Context

- `crates/mx-agent-daemon/src/task_orchestrator.rs` — pure orchestration core:
  `process_one` mints `invocation_id`, authorizes, claims, dispatches, finalizes;
  `recover_executing_tasks` / `recover_stale_executing` restart recovery;
  `OrchestrationOutcome`; `TaskDispatcher` / `TaskStore` traits.
- `crates/mx-agent-daemon/src/invocation.rs` — `cancel_invocation[_for_session]`,
  `task_state_for_invocation`, `task_result_from_invocation`, `is_terminal`,
  `get_invocation`, `read_invocation_state` (private), `advance_invocation`.
- `crates/mx-agent-daemon/src/task.rs` — task lifecycle states, `can_transition`
  (`executing|pending|assigned → cancelled` allowed; terminal → none),
  `UpdateTaskOptions`, `update_task[_for_session]`, `read_task_state`.
- `crates/mx-agent-daemon/src/task_dispatch.rs` — local `ToolTaskDispatcher` /
  `ExecTaskDispatcher` (ignore `_invocation_id`).
- `crates/mx-agent-daemon/src/task_dispatch_matrix.rs` — `MatrixCallTaskDispatcher`
  / `MatrixExecTaskDispatcher` (ignore `_invocation_id`; build `CallStartParams` /
  `ExecStartParams`).
- `crates/mx-agent-daemon/src/exec_ipc.rs` — `ExecStartParams`, `start_exec_matrix`
  (mints id), `start_exec_loopback`.
- `crates/mx-agent-daemon/src/call_ipc.rs` — `CallStartParams`, `start_call_matrix`
  (mints id), `start_call_loopback`.
- `crates/mx-agent-daemon/src/scheduler_loop.rs` — `run_scheduler_tick`,
  `scheduler_pass_for_agent` wires local vs Matrix dispatchers; `claimed_invocations`
  (#230 protection); `MatrixTaskStore`.
- `crates/mx-agent-daemon/src/lifecycle.rs` — IPC dispatch table (`invocation.cancel`
  handler at ~684 loads the signing key and calls `cancel_invocation_for_session`).
- `crates/mx-agent-daemon/src/ipc.rs` — IPC param structs (`InvocationCancelParams`).
- `crates/mx-agent-cli/src/cli.rs` — `TaskCommand`, `InvocationCommand::Cancel`,
  `invocation_cancel`, `task_update`, `daemon_ipc_call`, `command_path`.
- Tests: `crates/mx-agent-daemon/tests/matrix_integration.rs` (`#[ignore]`d live
  suite, `signed_exec_task`, scheduler-loop drive), `task_orchestration_e2e.rs`,
  in-module tests in the files above.

Constraints (must preserve): CLI stateless; daemon owns Matrix state/keys/policy;
coding agent never sees tokens/device keys; room membership ≠ execution; privileged
cancel stays Ed25519-signed + trust + deny-by-default policy + ownership-checked
(authorized by requester agent id, #218); Unix-only; no `unsafe`; MSRV 1.74;
document public APIs; never log secrets; human output by default + `--json`.

## Proposed Implementation

### Part A — Unify the invocation id through the dispatch transport

Add an optional preset id to the transport params and honor it:

- `exec_ipc::ExecStartParams`: add `#[serde(default)] pub invocation_id: Option<String>`.
  In `start_exec_matrix` (and `start_exec_loopback`), use
  `params.invocation_id.clone().unwrap_or_else(generate_invocation_id)` instead of
  always minting. The CLI exec path leaves it `None` (mints fresh = today's
  behavior); the Matrix task dispatcher sets it.
- `call_ipc::CallStartParams`: add the same field; honor it in `start_call_matrix`
  (and `start_call_loopback`).
- `task_dispatch_matrix.rs`: `MatrixCallTaskDispatcher` / `MatrixExecTaskDispatcher`
  set `invocation_id: Some(invocation_id.to_string())` from the `invocation_id`
  arg they already receive, so the published `exec.request` / `call.request`, the
  resulting `com.mxagent.invocation.v1` state event, and the task's recorded
  `invocation_id` are **one id**. Their `map_*_outcome` summaries already include
  the invocation id; with unification, `result.invocation_id` now equals the task's.

This is backward compatible: all existing CLI call sites build params without the
new field (serde default `None`), so direct `mx-agent exec` / `call` still mint a
fresh id. Only task dispatch presets it.

Local-synchronous dispatch (`ToolTaskDispatcher` / `ExecTaskDispatcher`) keeps the
same id contract definitionally: the task's `invocation_id` is the id of the
in-process invocation, which has no separately-published live state event (it runs
and finalizes within the claim→finalize window). Documented in module/struct docs.

### Part B — `task.cancel`

- `ipc.rs`: add `TaskCancelParams { room: String, task_id: String, reason: Option<String> }`
  (mirrors `InvocationCancelParams`), with a round-trip test.
- New daemon function (place in `task.rs` or a small `task_cancel.rs`; prefer
  `invocation.rs` adjacency is wrong — put it in `task.rs` near update helpers, or
  a new `task_cancel` module). Signature:
  `cancel_task(client, signing_key, key_id, room, task_id, reason) -> Result<TaskState, WorkspaceError>`
  and `cancel_task_for_session(session, signing_key, key_id, room, task_id, reason)`.
  Logic:
  1. `read_task_state(room, task_id)`; `None` → `WorkspaceError::TaskNotFound`.
  2. If the task state is terminal (`task::is_terminal`) → return it unchanged
     (cancelling a finished task is a no-op; do not reopen — respects
     `can_transition` terminal guard and "without clobbering finalized state").
  3. If `task.invocation_id` is `Some(inv)`: call `cancel_invocation(client,
     signing_key, key_id, room, inv, reason)`. This signs `exec.cancel`; the target
     verifies ownership/trust and terminates the process group, emitting
     `exec.cancelled`; the invocation state republishes as `cancelled`. Treat
     `WorkspaceError::InvocationNotFound` as benign (e.g. local dispatch published
     no live invocation state) — proceed to finalize. Keep the returned
     `InvocationState` (when present) to derive the task result.
  4. Build the task `result`: when an invocation was read, use
     `invocation::task_result_from_invocation(&inv_cancelled, completed_by, now)`
     (status `cancelled`, reason `cancelled`, carries the unified `invocation_id`);
     otherwise a minimal cancelled `TaskResult` with `reason = "cancelled"` and the
     task's `invocation_id` (if any). `completed_by` = the daemon's logged-in user
     id / agent.
  5. Finalize: `update_task` with `state = Some("cancelled")`, `result = Some(..)`,
     `invocation_id` preserved, no `expected_state_rev` (operator-initiated,
     last-write-wins is acceptable; the terminal-state read in step 2 already
     guards against reopening a finished task). `can_transition` permits
     `executing|pending|assigned → cancelled`.
  - Factor the result-shaping decision into a small pure helper
    (`cancelled_task_result(invocation: Option<&InvocationState>, task: &TaskState,
    completed_by, now) -> Value`) so it is unit-testable without a live client.
- `lifecycle.rs`: add `"task.cancel"` to the dispatch table, mirroring
  `"invocation.cancel"`: parse `TaskCancelParams`, load the signing key via
  `load_or_create_signing_key`, default the reason to `"cancelled by operator"`,
  call `cancel_task_for_session`. Add `task.cancel` to the method-coverage lists in
  the lifecycle tests (around lines 1170/1216).
- `lib.rs`: export `TaskCancelParams`, `cancel_task`, `cancel_task_for_session`.

### Part C — CLI `task cancel`

- `cli.rs`: add `TaskCommand::Cancel(TaskCancelArgs)` with
  `--room`, positional `task_id`, `--reason` (default `"cancelled by operator"`),
  honoring global `--json`. Add `task_cancel(global, args)` mirroring
  `invocation_cancel`: build `mx_agent_daemon::TaskCancelParams`, call
  `daemon_ipc_call::<_, TaskState>(global, "task.cancel", &params)`, print human
  output (`mx-agent: cancelled task <id>` + `print_task`, or "already <state>;
  nothing to cancel" when not cancelled) or JSON. Wire into the `TaskCommand`
  match and the `command_path` mapping. Add CLI parse tests.

### Part D — Restart recovery reconciliation by unified id

Extend the pure orchestrator core so recovery consults the actual invocation
state by the unified id:

- New `OrchestrationOutcome` variant
  `ReconciledInvocation { task_id: String, state: String }` (task finalized to the
  invocation's real terminal state) and treat a still-running invocation as a new
  `StillRunningInvocation { task_id }` (left `executing`). Update
  `claimed_invocation_id`, `task_id_for_log`, and `log_outcome` for the new
  variants.
- Add `reconcile_executing_tasks(tasks, live_invocations,
  invocations: &BTreeMap<String, InvocationState>, store) -> Vec<OrchestrationOutcome>`
  that supersedes `recover_executing_tasks` in the live path. Per `executing` task:
  - **remote-owned** → `StaleRemoteExecuting` (unchanged).
  - **owned + live this run** → `NotRunnableState` (unchanged; #230 protection).
  - **owned + not live**, look up `invocations[task.invocation_id]`:
    - terminal → finalize task to `task_state_for_invocation(inv.state)` with
      `task_result_from_invocation`; emit `ReconciledInvocation`.
    - present but non-terminal (`accepted`/`running`) → leave `executing`; emit
      `StillRunningInvocation` (the remote work may still complete).
    - missing → existing `recover_stale_executing` (`failed`,
      `recovered_stale_invocation`).
  - Keep `recover_executing_tasks` for existing call sites/tests, implemented as
    `reconcile_executing_tasks` with an empty invocation map (so "no invocation
    info" == today's behavior). Or have `run_scheduler_tick` call the new method.
- `scheduler_loop.rs`: `run_scheduler_tick` gains an `invocations: &BTreeMap<String,
  InvocationState>` parameter and calls `reconcile_executing_tasks`.
  `scheduler_pass_for_agent` reads the room's invocation states once per pass
  (`read_all_invocation_states` — expose a crate-visible reader) and passes the map
  in. In-module scheduler tests pass an empty map (current behavior preserved).

This guarantees: a finished remote invocation reconciles its task to the true
outcome (not a misleading `failed`); a live remote invocation is not killed off on
restart; a missing one is still recovered; and a task finalized this run or already
terminal is never touched.

## Affected Files / Crates / Modules

- `crates/mx-agent-daemon/src/exec_ipc.rs` — `ExecStartParams.invocation_id`; honor in `start_exec_matrix`/`_loopback`.
- `crates/mx-agent-daemon/src/call_ipc.rs` — `CallStartParams.invocation_id`; honor in `start_call_matrix`/`_loopback`.
- `crates/mx-agent-daemon/src/task_dispatch_matrix.rs` — set preset `invocation_id`.
- `crates/mx-agent-daemon/src/ipc.rs` — `TaskCancelParams`.
- `crates/mx-agent-daemon/src/task.rs` (+ maybe a `task_cancel` helper) — `cancel_task[_for_session]`, `cancelled_task_result`.
- `crates/mx-agent-daemon/src/invocation.rs` — expose `read_all_invocation_states` (crate-visible) if needed; reuse helpers.
- `crates/mx-agent-daemon/src/task_orchestrator.rs` — `reconcile_executing_tasks`, new outcomes.
- `crates/mx-agent-daemon/src/scheduler_loop.rs` — thread invocation map through tick + pass; outcome logging.
- `crates/mx-agent-daemon/src/lifecycle.rs` — `task.cancel` handler + method-list tests.
- `crates/mx-agent-daemon/src/lib.rs` — exports.
- `crates/mx-agent-cli/src/cli.rs` — `task cancel` command, handler, routing, tests.
- `README.md`, `docs/architecture.md` — status table + §9.2 wording.
- `crates/mx-agent-daemon/tests/matrix_integration.rs` — live e2e cancel test (`#[ignore]`).

## CLI / API Changes

- New CLI: `mx-agent task cancel --room <ROOM> <TASK_ID> [--reason <REASON>] [--json]`.
- New IPC method: `task.cancel` (params `TaskCancelParams`, result `TaskState`).
- New public daemon API: `TaskCancelParams`, `cancel_task`, `cancel_task_for_session`.
- Additive field `invocation_id: Option<String>` on `ExecStartParams` /
  `CallStartParams` (serde default; backward compatible).

## Data Model / Protocol Changes

- No new Matrix event types or state schemas. `exec.request`/`call.request` now
  carry the task-supplied `invocation_id` when dispatched from a task (the field
  already exists in the signed content); the signature binds it as before.
- No change to `com.mxagent.task.v1` / `com.mxagent.invocation.v1` schemas.

## Security Considerations

- `task.cancel` is privileged and reuses the **exact** signed exec-cancel path:
  the daemon signs `com.mxagent.exec.cancel.v1` with its own key; the target
  re-verifies the signature, trust, and **ownership** (requester == invocation
  requester) before terminating — deny-by-default, room membership ≠ execution.
- The signing key is loaded inside the daemon IPC handler (as for
  `invocation.cancel`); the CLI never sees it.
- Unifying the id does not weaken signing: the id is set *before* signing and is
  part of the signed content.
- No secrets logged; reuse non-sensitive `tracing` fields (task id, invocation id,
  decision). Task results stay non-sensitive (`task_result_from_invocation`).
- Recovery reconciliation only *reads* invocation state and finalizes the owning
  task; it never re-dispatches and never resolves another agent's task.

## Testing Plan

Non-e2e (`/tests`):
- `task_dispatch_matrix.rs`: assert the dispatchers set `params.invocation_id =
  Some(orchestrator_id)` for both call and exec.
- `exec_ipc.rs` / `call_ipc.rs`: `start_*_loopback` honors a preset
  `invocation_id` and still mints when `None`.
- `ipc.rs`: `TaskCancelParams` JSON round-trip.
- `task.rs`: `cancelled_task_result` — with a cancelled invocation (status
  `cancelled`, reason `cancelled`, carries unified id) and without one (minimal
  cancelled result); terminal task → no-op shaping.
- `task_orchestrator.rs`: `reconcile_executing_tasks` —
  (a) terminal invocation reconciles task to matching state (`ReconciledInvocation`);
  (b) running invocation leaves task `executing` (`StillRunningInvocation`);
  (c) missing invocation recovers `failed`;
  (d) live-this-run invocation untouched (#230);
  (e) remote-owned untouched.
- `cli.rs`: `task cancel` parses room + id + default/explicit reason; `command_path`.
- `lifecycle.rs`: `task.cancel` present in method coverage; unknown-method still errors.

E2E (`/e2e_tests`, `#[ignore]`d, Tuwunel): see decision below.

## Documentation Updates

- `README.md` status table: move "tight task↔remote-invocation id unification"
  from 🔮 Planned to ✅ Implemented (keep PTY as planned), and mention `task cancel`.
- `docs/architecture.md` §9.2: state that a task's `invocation_id` is the id of the
  invocation that runs the action (unified across local and Matrix dispatch), and
  that `task cancel` drives the linked invocation to `cancelled` and finalizes the
  task `cancelled`; note restart reconciliation by the unified id. Update the §10.3
  IPC method table with `task.cancel`. Keep the existing §9.2 note about
  `exec.cancelled` finalizing the owning task accurate.

## E2E decision

Add one `#[ignore]`d live test in `matrix_integration.rs`: two daemons (Bob
creates a signed long-running exec task assigned to Alice; Alice runs `/sync` +
`run_scheduler_loop` in `MX_AGENT_TASK_DISPATCH=matrix`). Once the task is
`executing` with a live remote invocation, Bob issues `cancel_task` and the test
asserts the linked invocation reaches `cancelled` and the task is finalized
`cancelled` by the unified id. This is the only layer that exercises the real
signed cancel propagation across daemons; lower layers cannot. Gated behind the
existing Docker/Tuwunel harness so default `cargo test --all` is unaffected.

## Risks and Open Questions

- **Scheduler thread blocks during Matrix dispatch.** `process_one` calls the
  dispatcher synchronously, so while a task's remote exec runs, the scheduler
  thread is inside the dispatch awaiting frames. Cancel arrives via the *IPC*
  thread (separate), signs `exec.cancel`, the target terminates and emits
  `exec.cancelled`; the blocked dispatch then observes the terminal frame and the
  orchestrator would try to finalize. Mitigation: `cancel_task` finalizes to
  `cancelled` first; the orchestrator's later `finalize` (executing→succeeded/
  failed) will be rejected by the terminal-transition guard (`can_transition`
  cancelled→X = false) / stale-rev check, so the cancelled outcome wins. Verify
  this ordering holds and the rejected finalize is logged, not panicked.
- **Local-synchronous cancel is best-effort** (documented non-goal): a fast local
  task may already be finalized; cancel then returns it unchanged.
- Reconciliation reads all invocation states once per pass — bounded by room size;
  acceptable and consistent with existing per-pass reads.

## Implementation Checklist

1. Add `invocation_id: Option<String>` to `ExecStartParams` and `CallStartParams`;
   honor it in `start_exec_matrix`/`_loopback` and `start_call_matrix`/`_loopback`.
2. Set the preset id in `MatrixCallTaskDispatcher` / `MatrixExecTaskDispatcher`.
3. Add `TaskCancelParams` to `ipc.rs` (+ round-trip test).
4. Implement `cancel_task[_for_session]` + pure `cancelled_task_result` in `task.rs`.
5. Add the `task.cancel` IPC handler in `lifecycle.rs`; update method-list tests.
6. Export new symbols from `lib.rs`.
7. Add `task cancel` CLI command, handler, routing, `command_path`, and tests.
8. Add `reconcile_executing_tasks` + new outcomes in `task_orchestrator.rs`; keep
   `recover_executing_tasks` behavior via empty-map delegation.
9. Thread the invocation-state map through `run_scheduler_tick` /
   `scheduler_pass_for_agent`; expose `read_all_invocation_states` crate-visibly;
   update outcome logging.
10. Add the non-e2e tests listed above.
11. Add the `#[ignore]`d live cancel e2e test.
12. Update `README.md` and `docs/architecture.md`.
13. `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`,
    `cargo test --all`, `cargo build --all`.
