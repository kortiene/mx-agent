# Enforce Approval `expires_at`: Block Held Tasks Whose Approval Window Has Closed

## Problem Statement

The daemon stamps an `expires_at` on every task approval request
(`APPROVAL_REQUEST_TTL` = 1 h) and threads it through the task approval gate, but
no code path ever enforces it. `QueueApprovalGate::evaluate` only reacts to an
explicit approve/deny decision; an approval-required task that is simply never
decided returns `ApprovalDisposition::Pending` on every scheduler pass and is
held in the on-disk `ApprovalQueue` (and surfaced by `mx-agent approval list`)
**forever**. The stamped horizon is cosmetic.

This is a fail-closed-but-unbounded liveness/safety gap: a held task never
reaches a terminal state, never produces an operator signal that the window has
closed, and silently occupies the queue. It leaves the acceptance criterion
"fail/block on denial **or expiry**" from #169 unmet and #223's "expiry/timeout
for queued approvals (currently unbounded)" unaddressed.

This is **distinct from** the signed task-action authorization nonce
(`auth.expires_at`), which *is* enforced (`admit_task_action_replay` →
`ReplayError::Expired` → block, reason `"expired"`). That mechanism guards
task-authorization freshness; it does not guard the human-approval deadline, so
this gap is not covered by it.

## Goals

- The approval gate transitions a held approval-required task whose `expires_at`
  is in the past to a terminal `blocked` state with a structured, machine-readable
  reason `"approval_expired"`, finalizing the task instead of re-enqueuing it
  `Pending`.
- The comparison uses a single, injectable/testable time source (mirroring the
  pure `approval_request_expiry` style), so the transition is unit-testable
  without mocking the wall clock.
- The expired entry is removed from the on-disk `ApprovalQueue` so
  `mx-agent approval list` no longer shows it as actionable.
- A non-expired pending approval still returns `Pending` and remains resolvable
  by a later approve/deny — no regression to the approve→execute path.
- An expired-but-then-decided case is not mishandled: an `approved` or `denied`
  *verified* decision that exists for the request continues to take priority over
  expiry (decision wins; the gate already removes the queue entry in that path).

## Non-Goals

- Do **not** introduce a new Matrix event type, and do not emit a new timeline
  event for expiry — expiry is resolved locally from the already-stamped
  `expires_at` and finalized onto the existing `com.mxagent.task.v1` state.
- Do **not** change the signed task-action authorization nonce/expiry mechanism
  (`admit_task_action_replay`, `ReplayCache`) — that is a separate, already-enforced
  concept.
- Do **not** change the approval-decision verification path (sender/signature/replay,
  issue #264) — expiry is orthogonal to whether a decision is genuine.
- Do **not** add live Matrix e2e tests; use deterministic unit tests with an
  injected time source.
- Do **not** alter the `APPROVAL_REQUEST_TTL` value or the
  `com.mxagent.approval.request.v1` content schema.
- Do **not** add a CLI surface for expiry; the behavior is internal to the
  scheduler/gate.

## Relevant Repository Context

`mx-agent` splits a stateless CLI from a long-lived daemon. This change is
entirely inside `mx-agent-daemon`; no CLI, IPC, or protocol surface changes.

Key pieces:

- **`crates/mx-agent-daemon/src/approval.rs`**
  - `APPROVAL_REQUEST_TTL: Duration = 3600s` (`:500`).
  - `approval_request_expiry(now: SystemTime, ttl: Duration) -> String` (`:507`)
    — the pure, deterministic builder of the RFC 3339 UTC stamp; the model for a
    pure, testable expiry helper.
  - `unix_to_rfc3339` (`:529`) — civil-from-days formatter (no date library).
  - `ApprovalQueue` (`:184`) with `enqueue` / `remove` / `get` and `0600`
    atomic `save` — the on-disk queue `mx-agent approval list` reads.
  - `decision_permits_spawn` (`:327`) and `read_verified_approval_decisions`
    (`:403`) resolve only explicit decisions; neither consults `expires_at`.
- **`crates/mx-agent-daemon/src/replay.rs`**
  - `parse_rfc3339_to_unix(s: &str) -> Option<i64>` (`:242`) — a **private**
    RFC 3339 → Unix-seconds parser already used by `ReplayCache::admit_at`
    (supports `Z`, fractional seconds, and numeric offsets; returns `None` on
    malformed input). This is the natural parser for comparing `expires_at`
    against "now"; it currently is not `pub`.
- **`crates/mx-agent-daemon/src/task_orchestrator.rs`**
  - `QueueApprovalGate<R>` (`:1307`): fields `room_id`, `target_agent`,
    `expires_at`, `queue: Rc<RefCell<ApprovalQueue>>`,
    `replay_cache: Option<Rc<RefCell<ReplayCache>>>`, `resolve_decision: R`.
  - `QueueApprovalGate::evaluate` (`:1376`): matches the resolved decision; the
    `None` branch (`:1398`) always re-enqueues `Pending` and never compares
    `self.expires_at` to the current time. **This is the core gap.**
  - `task_approval_request(task, action, target_agent, expires_at)` (`:1275`)
    stamps the request `expires_at`; the same `expires_at` is the gate field.
  - `ApprovalDisposition` enum (`:174`): `Approved` / `Denied(String)` /
    `Pending(String)`.
  - `resolve_approval` (`:1038`) maps the gate disposition to an
    `OrchestrationOutcome`: `Approved → Ok(())`, `Denied(reason) →
    block_approval_denied`, `Pending(id) → AwaitingApproval`.
  - `block_approval_denied` (`:1082`) finalizes the task `STATE_BLOCKED` with a
    `failure_result(..., "approval_denied", ...)` and returns
    `OrchestrationOutcome::Denied`. This is the existing template for finalizing a
    held task to `blocked` with a structured reason.
  - For contrast (already enforced, different concept): `admit_task_action_replay`
    (`:916`) → `ReplayError::Expired` → block reason `"expired"`, tested at
    `:2487-2505`.
- **`crates/mx-agent-daemon/src/scheduler_loop.rs`**
  - `scheduler_pass` (`:380`) computes one finite `approval_expires_at =
    approval_request_expiry(SystemTime::now(), APPROVAL_REQUEST_TTL)` per pass
    (`:402`) and threads it into each `QueueApprovalGate` (`:559-566`). Note this
    is the **freshly-recomputed** TTL horizon for *new* requests, **not** the
    `expires_at` already stamped on a previously-queued request — see Risks.
  - `QueueApprovalGate::new(... expires_at ...)` is built at `:559`; the gate is
    where expiry must be enforced because it is the only place with access to both
    the queued request (with its persisted `expires_at`) and the queue handle.

Conventions to follow: no `unsafe`; MSRV 1.74; `missing_docs` is `-D warnings`
in CI so every new public item needs a doc comment; pure helpers take their time
input as a parameter (see `approval_request_expiry`, `ReplayCache::admit_at`) so
they are testable without the wall clock; only non-sensitive metadata is logged.

## Proposed Implementation

The fix lives in the **approval gate** (`QueueApprovalGate::evaluate`), because
that is the single point that (a) holds the queued `PendingApproval` whose
persisted `expires_at` is the human-approval deadline, (b) owns the queue handle
to remove the expired entry, and (c) already produces the `ApprovalDisposition`
the orchestrator finalizes from. Resolving it there keeps
`scheduler_pass`/orchestrator wiring unchanged except for surfacing the new
disposition.

### 1. A pure, testable expiry predicate (in `approval.rs`)

Add a pure helper next to `approval_request_expiry`, deriving "is this stamp in
the past relative to `now`?" without reading the wall clock itself:

```rust
/// Whether an approval request stamped with `expires_at` (RFC 3339 UTC) has
/// closed at or before `now_unix` (Unix seconds).
///
/// Pure and deterministic given its inputs, so the expiry transition is
/// unit-testable without mocking the wall clock (mirrors
/// [`approval_request_expiry`]). A malformed `expires_at` is treated as
/// **not yet expired** (fail-open on the *expiry* axis only): the request stays
/// `Pending` and resolvable by an explicit decision rather than being silently
/// finalized off an unparseable stamp — explicit deny/approve still terminates it.
pub fn approval_request_expired(expires_at: &str, now_unix: i64) -> bool {
    match /* RFC 3339 -> Unix seconds */ {
        Some(expiry) => expiry <= now_unix,
        None => false,
    }
}
```

To parse, **promote `parse_rfc3339_to_unix` in `replay.rs` to `pub(crate)`** (it
already exists, is tested, and handles `Z`/fractional/offset forms) and call it
from `approval.rs`, rather than duplicating a second parser. (Alternative if
cross-module coupling is undesirable: move `parse_rfc3339_to_unix` to a small
shared time module, e.g. `crate::time`, and have both `replay.rs` and
`approval.rs` use it. Prefer the minimal `pub(crate)` promotion.)

Rationale for the malformed-stamp policy: a malformed `expires_at` must not cause
a silent terminal `blocked`, because the same daemon stamps the value with a
well-formed formatter — a malformed stamp signals corruption, not a closed
window. Fail-open on *expiry* keeps the task decidable; it does **not** weaken
execution safety (the task still requires a verified approval to ever run).

### 2. Give the gate an injectable "now" and enforce expiry in `evaluate`

`QueueApprovalGate` currently has no time source. Add one as an injectable
closure/field so the gate is unit-testable without the wall clock, defaulting to
`SystemTime::now()` in production:

- Add a field `now_unix: i64` **or** a `now_fn: Box<dyn Fn() -> i64>` to
  `QueueApprovalGate`. Prefer a simple stamped `now_unix: i64` captured once per
  scheduler pass (the gate is rebuilt every pass), set from
  `SystemTime::now().duration_since(UNIX_EPOCH)` in `scheduler_pass_for_agent`.
  This mirrors how `approval_expires_at` is already computed once per pass and
  passed in, and keeps the gate `now` aligned with the request stamp's clock.
  - Add a builder method, e.g. `QueueApprovalGate::with_now_unix(self, now_unix:
    i64) -> Self`, defaulting to a value captured at `new()` if not set, so
    existing call sites that do not set it still compile and behave correctly.

In `evaluate`, the `None` (undecided) branch becomes:

```rust
None => {
    // No decision yet. If the human-approval window has closed, finalize
    // (fail-closed liveness): drop the queue entry and block the task with a
    // structured reason instead of re-enqueuing it forever (issue #265).
    let request_expiry = &request.expires_at; // the *queued* request's stamp
    if approval_request_expired(request_expiry, self.now_unix) {
        self.queue.borrow_mut().remove(&request_id);
        return ApprovalDisposition::Expired(request_id);
    }
    self.queue.borrow_mut().enqueue(PendingApproval {
        room_id: self.room_id.clone(),
        request,
    });
    ApprovalDisposition::Pending(request_id)
}
```

**Important — which `expires_at` is compared.** Compare against the
`expires_at` carried on the **request being evaluated**
(`task_approval_request(...)` returns one stamped with `self.expires_at`, but the
*persisted* queued entry from a prior pass is what defines the real deadline).
Because `task_approval_request` re-stamps `self.expires_at` (the fresh per-pass
TTL horizon) on every pass, the naively-rebuilt `request.expires_at` would never
appear expired. The gate must therefore compare against the **already-queued**
entry's `expires_at` when one exists:

```rust
None => {
    let existing = self.queue.borrow().get(&request_id).map(|p| p.request.expires_at.clone());
    let deadline = existing.unwrap_or_else(|| request.expires_at.clone());
    if approval_request_expired(&deadline, self.now_unix) {
        self.queue.borrow_mut().remove(&request_id);
        return ApprovalDisposition::Expired(request_id);
    }
    // first encounter (or still valid): enqueue/keep pending with the request's stamp
    self.queue.borrow_mut().enqueue(PendingApproval { room_id: self.room_id.clone(), request });
    ApprovalDisposition::Pending(request_id)
}
```

This guarantees the deadline is anchored to the **first** time the request was
queued (its persisted stamp), so the window genuinely closes 1 h after the
approval was first requested rather than sliding forward every pass. The first
encounter enqueues with the current stamp; subsequent passes read the persisted
stamp back and enforce it.

### 3. Add an `Expired` disposition + outcome and finalize the task

- Add `ApprovalDisposition::Expired(String)` (the request id) to the enum
  (`:174`), documented.
- In `resolve_approval` (`:1061`), handle the new arm by finalizing the task to
  `STATE_BLOCKED` with reason `"approval_expired"`, reusing the
  `block_approval_denied` pattern. Add a sibling
  `block_approval_expired(task, action, invocation_id, store)` (or parameterize
  the existing helper with the reason string) that builds
  `failure_result(&self.agent_id, Some(invocation_id), Some(action.kind()),
  "approval_expired", Some("approval window expired before a decision was made"))`
  and finalizes `STATE_BLOCKED` with `expected_state_rev: Some(task.state_rev)`.
- It should return a terminal outcome. Reuse `OrchestrationOutcome::Denied`
  (task is finalized blocked, no spawn) **or** add a dedicated
  `OrchestrationOutcome::ApprovalExpired { task_id, invocation_id }` variant for
  clearer logging/telemetry. **Recommended:** reuse `Denied` to minimize surface,
  but distinguish via the structured `reason` in the task `result`
  (`"approval_expired"` vs `"approval_denied"`); add a one-line log in
  `log_outcome`/`resolve_approval` noting `decision = "approval_expired"`. If a
  dedicated outcome variant is added, update `log_outcome`
  (`scheduler_loop.rs:670`) and any exhaustive matches (e.g. the
  `task_id`-extracting match around `scheduler_loop.rs:729`,
  `:1365`, `:1461`).

### 4. Wire the per-pass `now` into the gate

In `scheduler_pass` (`scheduler_loop.rs:402`), alongside `approval_expires_at`,
capture `let approval_now_unix = SystemTime::now().duration_since(UNIX_EPOCH)
.map(|d| d.as_secs() as i64).unwrap_or_default();` and thread it into
`scheduler_pass_for_agent` → `QueueApprovalGate::new(...).with_now_unix(approval_now_unix)`.
Using one timestamp per pass keeps every gate in the pass consistent.

### 5. Persist the queue change

The existing `scheduler_pass` already persists the queue when it differs from
`approval_queue_before` (`:503`). Because expiry calls `queue.remove(...)`, the
removal is captured by that existing diff-and-save, so the expired entry
disappears from `approvals.json` (and thus `mx-agent approval list`) with no
extra wiring.

## Affected Files / Crates / Modules

- `crates/mx-agent-daemon/src/approval.rs` — add `approval_request_expired`
  (pure helper); doc comment; unit tests.
- `crates/mx-agent-daemon/src/replay.rs` — promote `parse_rfc3339_to_unix` to
  `pub(crate)` (or extract to a shared `crate::time` module).
- `crates/mx-agent-daemon/src/task_orchestrator.rs`:
  - `ApprovalDisposition` — add `Expired(String)`.
  - `QueueApprovalGate` — add injectable `now_unix` field + `with_now_unix`
    builder; enforce expiry in `evaluate`'s `None` arm using the queued entry's
    persisted `expires_at`.
  - `resolve_approval` — handle `Expired`; add/parameterize
    `block_approval_expired`.
  - (Optional) `OrchestrationOutcome::ApprovalExpired` variant.
- `crates/mx-agent-daemon/src/scheduler_loop.rs` — capture per-pass `now_unix`,
  thread to the gate; update `log_outcome` and exhaustive `OrchestrationOutcome`
  matches if a new variant is added.
- Read-only context: `docs/architecture.md` §12 (Approval Workflow).

## CLI / API Changes

None to the CLI command surface or IPC method table. `mx-agent approval
list/show/approve/deny` are unchanged; an expired request simply stops appearing
in `approval list` once a scheduler pass finalizes it. New **public Rust** items
(`approval_request_expired`, `ApprovalDisposition::Expired`,
`QueueApprovalGate::with_now_unix`, and any new `OrchestrationOutcome` variant)
must carry doc comments (CI `missing_docs`/`-D warnings`).

## Data Model / Protocol Changes

None to the wire protocol. No new event types, no change to
`com.mxagent.approval.request.v1` / `.decision.v1` content. The
`com.mxagent.task.v1` `result` object gains a new **value** for its existing
`reason` field — `"approval_expired"` — alongside the already-defined
`approval_denied` / `policy_denied` / `process_exit` / `dispatch_failed` /
`recovered_stale_invocation`. The on-disk `approvals.json` schema is unchanged;
only the lifecycle (entries are now removed on expiry) changes.

## Security Considerations

- **Fail-closed liveness, not a new grant.** Expiry can only ever *block* a task;
  it never causes execution. This strengthens the deny-by-default posture by
  giving an undecided privileged action a terminal, auditable outcome instead of
  an unbounded hold.
- **Daemon/CLI separation preserved.** All logic stays in the daemon; the CLI is
  untouched and never gains access to approval internals, tokens, or keys.
- **Room membership still grants nothing.** This change is orthogonal to the
  #264 sender/signature/replay verification of decisions — an expired request is
  blocked regardless of who is or is not in the room.
- **No secret logging.** Log only non-sensitive metadata (task id, request id,
  `reason = "approval_expired"`); never the approval content.
- **Malformed-stamp policy is fail-open on expiry only** (stays `Pending`,
  decidable) and fail-closed on execution (still needs a verified approval to
  run), so a corrupt stamp can neither silently kill nor silently release a task.
- **Clock source.** Uses the same wall clock and RFC 3339 parser as the already-
  enforced authorization expiry; no new trust assumptions. The deadline is
  anchored to the request's persisted stamp so it cannot be slid forward
  indefinitely by repeated passes.
- Unix-only assumptions unchanged; no new platform code.

## Testing Plan

Unit tests (deterministic, no wall-clock mocking — pass `now_unix` explicitly):

In `approval.rs`:
- `approval_request_expired_is_true_for_past_stamp` — a stamp strictly before
  `now_unix` returns `true`.
- `approval_request_expired_is_false_for_future_stamp` — a stamp after `now_unix`
  returns `false` (boundary: `expiry == now_unix` counts as expired, matching
  `ReplayCache::admit_at`'s `<=`; assert the chosen boundary explicitly).
- `approval_request_expired_is_false_for_malformed_stamp` — garbage/empty stamp
  returns `false` (fail-open on expiry).

In `task_orchestrator.rs` (gate-level, the issue's required pair):
- `expired_pending_approval_is_finalized_blocked_with_reason` — build a
  `QueueApprovalGate` with `resolve_decision` returning `None`, seed the shared
  queue with a `PendingApproval` whose `expires_at` is in the past, set
  `now_unix` after that stamp, call `evaluate`, and assert the disposition is
  `Expired(request_id)`, the queue no longer contains the entry, and — driving it
  through `resolve_approval`/a stub `TaskStore` — the task is finalized
  `STATE_BLOCKED` with `result.reason == "approval_expired"`. **Explicitly assert
  it is not held indefinitely** (i.e. not `Pending`).
- `valid_pending_approval_remains_pending` — same gate with `now_unix` *before*
  the queued `expires_at` and no decision: disposition is `Pending`, the entry
  stays queued, no finalize occurs (no regression to the approve/deny path).
- `approved_decision_wins_over_expiry` — a verified `approved` decision present
  for the request still releases (`Approved`) even when the stamp is past, and
  the queue entry is removed (decision precedence preserved).
- `expiry_deadline_anchored_to_persisted_stamp` — simulate two passes: first
  pass enqueues with a near-past stamp via the persisted entry; assert the second
  pass compares against the **queued** stamp (expires) rather than a freshly
  re-stamped future `self.expires_at` (does not slide).

Regression coverage:
- Keep existing `disposition_holds_request_when_approval_required`,
  `approved_request_proceeds_denied_never_spawns`, and the scheduler
  `AwaitingApproval` tests green (a still-valid held task remains
  `AwaitingApproval`).
- `replay.rs`: existing `parse_rfc3339_to_unix` tests remain; add none unless the
  visibility change requires a compile-time touch.

No live Matrix / e2e tests (per Non-Goals); the gate and helper are exercised
purely in-process.

## Documentation Updates

- `docs/architecture.md` §12 (Approval Workflow): add a sentence that a held
  `requires_approval` task whose stamped `expires_at` passes without a verified
  decision is finalized `blocked` with reason `"approval_expired"` and removed
  from the local approval queue — so the stamped TTL is now enforced, not
  cosmetic. Cross-reference the existing `result` `reason` list in §9.2.
- `docs/architecture.md` §9.2 task `result` reasons: add `approval_expired` to
  the enumerated machine-readable reasons.
- `README.md`: no change required (the approval row in Project status remains
  accurate); optionally note expiry enforcement if the approval area is described
  in detail elsewhere.
- No wiki/help-text changes (no CLI surface change).

## Risks and Open Questions

- **Which `expires_at` is authoritative (resolved above, but verify in code).**
  `task_approval_request` re-stamps `self.expires_at` every pass with the *fresh*
  per-pass TTL horizon, so comparing the rebuilt request's stamp would never
  expire. The implementation **must** compare against the persisted queued
  entry's `expires_at`. Confirm the queue actually retains the original stamp
  across passes (it does: `enqueue` is idempotent by `request_id` and only
  replaces on a new `evaluate`, and the persisted entry is read back via
  `queue.get`). Double-check the `enqueue` on the still-valid branch does not
  overwrite the original stamp with a fresher one on every pass — if it does,
  the deadline would slide; the implementation should preserve the existing
  entry's `expires_at` when re-enqueuing (e.g. enqueue only on first encounter,
  or keep the earlier stamp). **This is the single most important correctness
  detail.**
- **Boundary semantics (`<=` vs `<`).** Decide and document whether `expiry ==
  now` is expired. Recommended `<=` to match `ReplayCache::admit_at`.
- **Reuse vs. new `OrchestrationOutcome` variant.** Reusing `Denied` keeps the
  diff small but conflates denial and expiry in outcome-level matching (they are
  still distinguishable by `result.reason`). A dedicated `ApprovalExpired`
  variant is cleaner for telemetry but touches more exhaustive matches. Pick one;
  the spec recommends reuse with a distinct `reason`.
- **`parse_rfc3339_to_unix` visibility.** Promoting to `pub(crate)` is the
  minimal change; a shared `crate::time` module is tidier but larger. Either is
  acceptable; avoid duplicating the parser.
- **Interaction with restart recovery.** An expired-and-blocked task is terminal
  (`STATE_BLOCKED`), so restart reconciliation (which only touches `executing`
  tasks) will not reopen it. Confirm no recovery path re-enqueues a blocked
  approval.
- **No emitted expiry event.** The issue does not ask for one; operators observe
  the closed window via the task's terminal `blocked`/`approval_expired` result
  and its disappearance from `approval list`. If a future requirement wants an
  emitted `com.mxagent.approval.decision.v1`-style "expired" signal, that is
  out of scope here.

## Implementation Checklist

1. In `replay.rs`, change `fn parse_rfc3339_to_unix` to `pub(crate) fn`
   (or extract to `crate::time` and re-point `ReplayCache`).
2. In `approval.rs`, add `pub fn approval_request_expired(expires_at: &str,
   now_unix: i64) -> bool` with a doc comment; malformed stamp → `false`
   (fail-open on expiry). Add unit tests (past/future/boundary/malformed).
3. In `task_orchestrator.rs`, add `ApprovalDisposition::Expired(String)` with a
   doc comment.
4. Add an injectable `now_unix: i64` field to `QueueApprovalGate` and a
   `with_now_unix(self, now_unix: i64) -> Self` builder (doc-commented); default
   to a value captured at construction.
5. In `QueueApprovalGate::evaluate`'s `None` arm, read the **persisted** queued
   entry's `expires_at` (fallback to the rebuilt request's stamp only on first
   encounter), and if `approval_request_expired(deadline, self.now_unix)`:
   `queue.remove(&request_id)` and return `Expired(request_id)`; otherwise enqueue
   (preserving the original stamp) and return `Pending`.
6. In `resolve_approval`, handle `ApprovalDisposition::Expired` by finalizing the
   task `STATE_BLOCKED` with `reason = "approval_expired"` via a new/parameterized
   `block_approval_expired` (mirror `block_approval_denied`); return the chosen
   terminal `OrchestrationOutcome` (reuse `Denied` recommended). Log
   `decision = "approval_expired"` (non-sensitive metadata only).
7. If a new `OrchestrationOutcome` variant is added, update `log_outcome` and all
   exhaustive matches in `scheduler_loop.rs` (`:670`, `:729`, `:1365`, `:1461`).
8. In `scheduler_pass`, capture `approval_now_unix` (Unix seconds) once per pass;
   thread it through `scheduler_pass_for_agent` into
   `QueueApprovalGate::new(...).with_now_unix(approval_now_unix)`.
9. Add gate-level unit tests: expired→`Expired`+removed+finalized-blocked-with-
   reason (assert *not* indefinitely held); valid→`Pending`; approved-wins-over-
   expiry; deadline-anchored-to-persisted-stamp.
10. Update `docs/architecture.md` §9.2 (add `approval_expired` reason) and §12
    (expiry enforcement note).
11. Run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D
    warnings`, and `cargo test --all`; ensure no `unsafe`, MSRV 1.74 compatible,
    and all new public items documented.
