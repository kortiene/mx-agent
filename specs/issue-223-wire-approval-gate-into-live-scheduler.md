# Wire the Approval Gate into the Live Scheduler Loop (+ approve→execute E2E)

## Problem Statement

The daemon's orchestration core already implements approval handling
(`QueueApprovalGate`, fail-closed without a gate, `denied → blocked`,
`approved → runs`) and it is unit-tested in
`crates/mx-agent-daemon/src/task_orchestrator.rs`. But the **live** scheduler
loop (`scheduler_pass_for_agent` in `crates/mx-agent-daemon/src/scheduler_loop.rs`)
never attaches an approval gate. As a result, a task whose local policy sets
`requires_approval = true` stays `pending` indefinitely under the live scheduler
even after an operator publishes an approval decision. The approve→execute path
is never exercised live or in CI.

## Goals

1. Attach a `QueueApprovalGate` to the live orchestrator in
   `scheduler_pass_for_agent` so that, for a task local policy marks
   `requires_approval`:
   - the first undecided encounter enqueues a pending approval into the local,
     on-disk approval queue (so it is visible to `mx-agent approval list/show`
     and resolvable by `mx-agent approval approve/deny` over IPC), and the task
     is held (not claimed/dispatched);
   - the gate resolves against published `com.mxagent.approval.decision.v1`
     events in the room: an `approved` decision lets the task proceed to
     claim+dispatch; a `denied` (or any non-`approved`) decision finalizes the
     task `blocked` and never spawns.
2. Add a live two-daemon E2E: an approval-required task is held; an operator
   `approval approve` over IPC drives it to `succeeded`; a separate
   `approval deny` path drives a task to `blocked` and its command never spawns.
3. Bound queued approval requests with a finite `expires_at` (addresses the
   "currently unbounded" note minimally; full auto-expiry-to-`blocked` is called
   out as a follow-up to avoid a misleading blocked reason).

## Non-Goals

- Changing the orchestrator's approval *core* (already implemented/tested).
- Changing the approval CLI/IPC surface (`approval list/show/approve/deny`,
  `approval.decide`) — these already exist and work.
- Auto-expiring an undecided approval to `blocked` after a TTL. The emitted
  request carries a bounded `expires_at`, but converting an *expired* pending
  approval into a terminal `blocked` task (with a distinct
  `reason = "approval_expired"`) is deferred: it needs a dedicated denial reason
  the current `FnMut(&str) -> Option<bool>` resolver does not carry, and is out
  of scope for the must-hold acceptance criteria.
- Any Windows support, `unsafe`, or new external dependencies.

## Relevant Repository Context

- `scheduler_loop.rs` — the live wiring. `scheduler_pass` iterates joined rooms,
  reads agent + task state, and calls `scheduler_pass_for_agent` per owned agent,
  which builds a `TaskOrchestrator` (policy + trust + replay + verifying keys),
  a `MatrixTaskStore`, and a dispatcher, then calls `run_scheduler_tick`.
- `task_orchestrator.rs` — `QueueApprovalGate<R>` enqueues a `PendingApproval`
  into an `ApprovalQueue` on the first undecided encounter and resolves a
  decision via a `resolve_decision: FnMut(&str) -> Option<bool>` closure
  (`Some(true)` approve, `Some(false)` deny, `None` pending). `task_approval_request`
  derives a deterministic `request_id = "approval:{task_id}"`.
- `approval.rs` — `ApprovalQueue` (on-disk `approvals.json`, `0600`,
  load/enqueue/remove/save), `decide_approval_for_session` (looks the request up
  in the local queue, emits a `com.mxagent.approval.decision.v1`, removes it),
  `decision_permits_spawn` (fail-closed: only `approved` permits). Timeline
  reading pattern is established by `context.rs::list_context_shares`
  (`room.messages(MessagesOptions::backward())` + `raw.get_field`).
- `lifecycle.rs` — `approval.decide` IPC handler → `decide_approval_for_session`.
- `tests/matrix_integration.rs::live_scheduler_executes_signed_task_dag_and_denies`
  — the existing `#[ignore]` two-daemon live scheduler E2E that currently asserts
  the gate-less fail-closed behavior for `task-approval`.

Constraints preserved: CLI stateless / daemon owns state; the coding agent never
sees Matrix tokens or device keys; room membership ≠ execution permission;
privileged task actions remain Ed25519-signed + trust + deny-by-default policy
checked *before* approval; Unix-only; no `unsafe`; MSRV 1.74; never log secrets;
human output + `--json` preserved.

## Proposed Implementation

### 1. Read published approval decisions (`approval.rs`)

Add `read_approval_decisions(room: &Room, limit: u32) -> Result<HashMap<String, ApprovalDecision>, WorkspaceError>`:
scan up to `limit` recent timeline events backward (newest first) and keep the
**first** (newest) `com.mxagent.approval.decision.v1` per `request_id`. Mirrors
`list_context_shares`. Expose a small pure time helper to stamp a bounded
`expires_at` (reuse the existing `unix_to_rfc3339`): add
`pub fn approval_request_expiry(now: SystemTime, ttl: Duration) -> String` (pure,
deterministic given inputs) and a `pub const APPROVAL_REQUEST_TTL: Duration`.

### 2. Share the queue out of the gate (`task_orchestrator.rs`)

`QueueApprovalGate` currently owns `ApprovalQueue` by value, which is
unreachable once the gate is boxed into the orchestrator. Change its internal
storage to `Rc<RefCell<ApprovalQueue>>` so the live loop can hold a clone, run a
tick (the gate enqueues/removes through the shared handle), then persist:
- `new(... , queue: Rc<RefCell<ApprovalQueue>>, resolve_decision: R)`;
- `queue(&self) -> Rc<RefCell<ApprovalQueue>>` (clone of the handle);
- `evaluate` uses `self.queue.borrow_mut().enqueue/remove`.

`Rc` is sound here: the gate is built and used entirely on the scheduler thread
and never crosses a thread boundary (`TaskApprovalGate`/`TaskOrchestrator` carry
no `Send` bound). Update the one unit test accordingly.

### 3. Wire the gate into the live loop (`scheduler_loop.rs`)

- In `scheduler_pass`: load the `ApprovalQueue` once per pass. For each room,
  read the room's decisions **only when** that room has pending approvals queued
  (avoids a timeline round-trip for rooms with nothing pending). Build a
  `'static` `HashMap<String, bool>` mapping `request_id → decision_permits_spawn`
  and pass it (cloned per owned agent) plus a shared `Rc<RefCell<ApprovalQueue>>`
  down to `scheduler_pass_for_agent`. After all rooms/agents are processed,
  `save` the queue if it changed.
- In `scheduler_pass_for_agent`: build a `QueueApprovalGate` with `room_id`,
  `target_agent = agent.agent_id`, a bounded `expires_at`, the shared queue
  handle, and a `move` closure `|rid| decisions.get(rid).copied()`. Attach it
  via `orchestrator.with_approval_gate(Box::new(gate))`.

Result: an approval-required task is enqueued + held on the first pass (no
decision yet → `Pending`/persisted); after an operator decides, a later pass
reads the decision and the gate returns `Approved` (claim+dispatch → `succeeded`)
or `Denied` (finalize `blocked`, never spawns).

### 4. Update the live E2E (`tests/matrix_integration.rs`)

Extend `live_scheduler_executes_signed_task_dag_and_denies` (it already wires two
daemons + an approval-required task) to:
- assert the approval-required task is **held** (not `succeeded`) and its command
  has not spawned before any decision (preserves the fail-closed assertion, now
  against a *wired* gate);
- read the pending approval from the local queue, call
  `decide_approval_for_session(..., DECISION_APPROVED, ...)` over the target's
  session, then poll until the task reaches `succeeded` and its sentinel exists;
- add a second approval-required task, `decide(..., DECISION_DENIED, ...)`, and
  assert it reaches `blocked` with its command never spawned.

## Affected Files / Crates / Modules

- `crates/mx-agent-daemon/src/approval.rs` — decisions reader + expiry helper (+ unit tests).
- `crates/mx-agent-daemon/src/task_orchestrator.rs` — `QueueApprovalGate` shared queue (+ test update).
- `crates/mx-agent-daemon/src/scheduler_loop.rs` — live gate wiring (+ unit tests for resolve/persist).
- `crates/mx-agent-daemon/src/lib.rs` — export the new public items if needed.
- `crates/mx-agent-daemon/tests/matrix_integration.rs` — extended live E2E.
- `docs/architecture.md` — confirm wording still accurate (already describes the wired behavior).

## CLI / API Changes

None to the CLI. New daemon-internal public functions: `read_approval_decisions`,
`approval_request_expiry`, `APPROVAL_REQUEST_TTL`. `QueueApprovalGate::new`/`queue`
signatures change (newly-added internal gate, single in-crate caller + test).

## Data Model / Protocol Changes

None. Uses existing `com.mxagent.approval.request.v1` /
`com.mxagent.approval.decision.v1` events and the existing `approvals.json` queue.

## Security Considerations

- **Fail-closed:** only an explicit `approved` decision permits a spawn
  (`decision_permits_spawn`); denied/garbled/absent → held or blocked. No gate →
  still `AwaitingApproval` (unchanged).
- Approval is consulted **after** signature + trust + replay + deny-by-default
  policy already permitted the action; approval cannot widen authorization.
- Room membership never implies execution; only tasks assigned to the local agent
  are processed (auto-claim disabled).
- No secrets: approval requests/decisions reference task/action kind and ids, not
  command output; queue file stays `0600`; nothing new is logged.
- Unix-only; no `unsafe`; MSRV 1.74; no new dependencies.

## Testing Plan

- `approval.rs` unit tests: `read_approval_decisions` keeps the newest decision
  per `request_id` and ignores non-decision events; `approval_request_expiry`
  formats a known instant + TTL.
- `task_orchestrator.rs`: update the queue-gate test for the shared handle;
  assert enqueue-then-resolve still works and the persisted queue reflects it.
- `scheduler_loop.rs` unit tests (deterministic, in-memory, no homeserver):
  - approval-required task with no decision → held (`AwaitingApproval`), not
    spawned, and a pending approval is enqueued into the shared queue;
  - same task with an `approved` decision in the map → runs to `succeeded`;
  - with a `denied` decision → `blocked`, dispatcher never called.
- Live E2E (`#[ignore]`, gated by `scripts/matrix_integration_test.sh`): the
  approve→execute and deny→blocked flows above.

## Documentation Updates

- `docs/architecture.md` §9.2/§12 already describe the wired behavior; verify
  wording and adjust only if it implies the live loop was already wired.
- No README status-table change required (approval workflow already listed);
  adjust only if a status cell currently implies this was complete.

## Risks and Open Questions

- **Timeline read cost:** decisions are read per pass only for rooms with pending
  approvals, bounding round-trips. `limit` is capped (e.g. 100).
- **Eventual consistency with `approval.decide`:** the IPC path and the scheduler
  both touch `approvals.json`. The room decision event is the source of truth for
  fail-closed safety; the queue is operator-visibility state and converges
  (gate removes a decided entry; a transient re-save self-heals next pass).
- **Expiry:** only metadata is bounded now; auto-`blocked`-on-expiry is a noted
  follow-up.

## Implementation Checklist

1. [ ] `approval.rs`: add `read_approval_decisions` + `approval_request_expiry` +
   `APPROVAL_REQUEST_TTL`, with unit tests.
2. [ ] `task_orchestrator.rs`: switch `QueueApprovalGate` to a shared
   `Rc<RefCell<ApprovalQueue>>`; update its doc + the one unit test.
3. [ ] `scheduler_loop.rs`: load queue per pass, read room decisions when
   pending, build + attach `QueueApprovalGate`, persist on change; add unit tests.
4. [ ] `lib.rs`: export new public items as needed.
5. [ ] `tests/matrix_integration.rs`: extend the live E2E (approve→succeeded,
   deny→blocked, never spawned).
6. [ ] Verify wording in `docs/architecture.md`.
7. [ ] `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`,
   `cargo test --all`, `cargo build --all`.
