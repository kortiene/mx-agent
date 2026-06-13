# Release Held Live `exec`/`call` Approvals: Wire the Live `ApprovalDecision` Handler

GitHub issue: #306 — *Held approval-required live exec/call is never released: no
ApprovalDecision live handler, queue cannot resume*
Labels: `type:feature` `area:daemon` `area:security` `priority:p1`

## Problem Statement

When local policy resolves a privileged live request with
`Allowance::requires_approval`, the target daemon correctly **holds** it: it
enqueues a `PendingApproval`, emits a `com.mxagent.approval.request.v1`, and
returns without spawning (fail-closed). The operator can then run
`mx-agent approval approve` / `deny`, which emits a single-use-nonce'd,
Ed25519-signed `com.mxagent.approval.decision.v1` and dequeues the request.

The gap: **nothing on the live path ever consumes that decision.**
`handle_routed_events` (`crates/mx-agent-daemon/src/sync.rs:381-459`) has no
`RoutedEvent::ApprovalDecision` arm, so the decision lands in the catch-all
`"no live handler for routed mx-agent event"` branch (`sync.rs:449-456`).
Decision-driven release exists **only for task-backed actions** via the
scheduler (`crates/mx-agent-daemon/src/scheduler_loop.rs:454-516`,
`QueueApprovalGate`). Consequently:

- An approved held live `exec` or `call` **never executes** — `requires_approval`
  is a dead end on both live surfaces.
- The queue cannot resume even if a handler existed: `PendingApproval` persists
  only `room_id` + the lossy `ApprovalRequest` fields. The original signed
  request needed to re-authorize and spawn is **not stored** (call args are
  deliberately never rendered for no-leak; the exec summary is a display string).
- A naive re-route of the re-fetched original request would be `ReplayRejected`:
  the route-level replay cache already consumed its nonce at first admission
  (`crates/mx-agent-daemon/src/event_router.rs:344-360`).
- The audit log cannot distinguish *allow-and-ran* from *allow-and-held*:
  `audit_*_decision(Outcome::Allow)` runs **before** the hold, and
  `AuditDecision` has only `Allowed`/`Denied` (`audit.rs:30-48`).
- Held live requests have **no expiry sweep** (tasks gained one in #291); an
  undecided live hold lingers forever.

The hold is fail-closed (no active vulnerability), but the feature is
non-functional end-to-end. This spec wires the release/deny/expiry path while
preserving every existing security invariant.

## Goals

- Approving a held live `exec` or `call` via `mx-agent approval approve` causes
  **exactly-once** execution under a **re-resolved** allowance, emitting the
  normal accepted/running/finished (exec) or `call.response` (call) lifecycle.
- Denial emits the rejection/response and drops the hold; the request never runs.
- An undecided hold past its `expires_at` is swept fail-closed: removed from the
  queue, never run, and audited.
- Release re-runs the **full** authorize pipeline (signature → trust store →
  deny-by-default policy → optional verified-device gate) against the recovered
  original request before spawning — room membership is never execution permission.
- The decision itself is honored only when sender-verified, Ed25519-signed by a
  **locally-trusted** key, non-replayed, and unexpired — identical rigor to the
  scheduler's `read_verified_approval_decisions` / `verification_failure`
  (`approval.rs:502-610`).
- The audit log distinguishes *allow-and-held* / *released* / *denied-while-held*
  / *expired-while-held* from *allow-and-ran*.
- A forged, unsigned, expired, or nonce-replayed decision never releases a hold,
  covered by unit + integration + live tests.
- `cargo fmt --check`, `cargo clippy -D warnings`, build, and the full suite stay
  green. Unix-only, no `unsafe`, MSRV 1.74.

## Non-Goals

- Changing the **task** approval/release path (`QueueApprovalGate`,
  `scheduler_loop.rs`). It already works; this spec mirrors its verification but
  does not alter it.
- Changing the emitted `approval.request` content. It stays lossy / no-leak
  (`approval.rs:109-120`, `:211-222`): no command, no cwd-leak beyond the
  existing summary, no call args.
- Changing the CLI surface of `mx-agent approval approve/deny/list/show`. The
  decision is already emitted with nonce + expiry + signature
  (`approval.rs:729-774`); this spec only adds the **receive-side** consumer.
- Extending the human-approval window. The held approval's `expires_at` is copied
  from the request today (`approval_request_for*`); whether to stamp a longer TTL
  at hold time is called out as an Open Question, not implemented here.
- New sandbox/policy semantics; protocol version bumps; cross-signing/E2EE changes.

## Relevant Repository Context

Owning crate: **`mx-agent-daemon`** (receive-side live handlers, approval queue,
audit, scheduler). Supporting: **`mx-agent-protocol`** (`PendingApproval` lives in
the daemon; `ApprovalRequest`/`ApprovalDecision`/`ExecRequest`/`CallRequest`
schemas live in protocol — `schema.rs:400-458`). No CLI change.

Key existing pieces this builds on:

- **Hold (exec):** `handle_live_exec_request` authorizes, audits `Allow`, then
  `disposition_for_exec` → on `RequiresApproval` enqueues `PendingApproval`, emits
  the request, and returns without spawning
  (`crates/mx-agent-daemon/src/exec.rs:561-618`). The spawn/lifecycle code that a
  release must re-use is inline at `exec.rs:620-757` (accepted → running →
  `run_controlled_exec` / `run_pty_exec_task` → finished/cancelled + invocation
  state).
- **Hold (call):** `handle_live_call_request` authorizes, audits `Allow`, then
  `disposition_for_call` → `hold_call_for_approval` (`call.rs:659-715`,
  `:746-762`). The execute path is `execute_authorized_call` + `emit_call_response`
  (`call.rs:692`, `:712-714`).
- **Authorize pipelines (pure, no spawn, no replay-admit):**
  `authorize_live_exec` (`exec.rs:916-...`) → `authorize_exec_request_with_allowance`
  (`exec.rs:396`); `authorize_live_call` (`call.rs:764-809`) →
  `authorize_call_request_with_allowance`. Both run signature → routing → trust →
  policy and return `(Request, Allowance)`. **Neither admits the replay nonce** —
  that is exclusively the router's step 4 (`event_router.rs:344-360`). This is the
  hook the resume path uses to stay exempt from a second admission (see below).
- **Decision verification (reuse verbatim):** `DecisionVerification`,
  `verification_failure`, `read_verified_approval_decisions`
  (`approval.rs:470-610`). Anchors: authorized approver (`{local_user} ∪
  RoomPolicy::approvers`), Ed25519 signature, room-published **and** locally-trusted
  key, single-use nonce, cache-independent expiry. `decision_permits_spawn`
  (`approval.rs:409-411`) is the approve-vs-deny gate (only `"approved"` passes).
- **Scheduler precedent (mirror, don't modify):** `scheduler_pass` builds
  `DecisionVerification` from policy `approvers`, room-published `verifying_keys`,
  the local `TrustStore`, and `approval_now_unix` (`scheduler_loop.rs:441-516`);
  `QueueApprovalGate::admit_decision_nonce` burns the decision nonce in the shared
  replay cache as defense-in-depth (`task_orchestrator.rs:1605-1620`).
- **Replay cache:** `ReplayCache::admit` **persists atomically on every admit**
  (`replay.rs:186-233`). The sync router holds one in-memory `EventRouter` over an
  `Arc<Mutex<…>>` loaded once at sync start (`sync.rs:290-317`). **Pitfall:**
  loading a *second* `ReplayCache` in the decision handler and admitting through it
  would be silently clobbered the next time the router persists its in-memory copy
  (whole-file overwrite). The decision-nonce burn must go through the **router's
  own** cache instance — see Proposed Implementation.
- **Audit:** `AuditRecord` + `AuditDecision{Allowed,Denied}`, `append_audit`,
  `redact_command` (`audit.rs:29-216`, `:290-299`, `:353-376`). Builders:
  `for_exec` / `for_call` / `for_exec_denied` / `for_call_denied`.
- **Architecture §12** (`docs/architecture.md:1633-1762`) documents the workflow
  and explicitly discloses the gap: *"Inline resume of a live held request from a
  decision event is not wired on either surface today"* (`:1640-1642`).

Conventions: stateless CLI / stateful daemon; the coding agent never sees Matrix
tokens or device keys; all daemon-private state is `0600`/`0700`; logs carry only
non-sensitive metadata (sender, request_id, reason); fail-closed everywhere.

## Proposed Implementation

Five coordinated changes, each independently testable. The decision handler is
**event-driven** (the new `RoutedEvent::ApprovalDecision` arm, per the issue); the
expiry sweep is **timer-driven** (a scheduler-pass sweep, mirroring #291).

### 1. Persist the original signed request alongside the hold

Extend `PendingApproval` (`approval.rs:244-250`) with a local-only, optional field
holding the original signed request so release can re-authorize and spawn. **This
is the recommended option over re-fetching by `event_id`** (deterministic, no
dependency on timeline retention or a second decrypt, no extra round-trip).

```rust
/// The original signed live request held pending approval, persisted locally
/// (0600, never re-emitted) so an approving decision can re-authorize and spawn
/// it. `None` for task-backed holds (released by the scheduler) and for holds
/// written by an older daemon (which the live handler cannot auto-resume → the
/// operator re-issues; fail-closed).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum HeldRequest {
    Exec(ExecRequest),
    Call(CallRequest),
}

pub struct PendingApproval {
    pub room_id: String,
    pub request: ApprovalRequest,
    /// Original signed request to resume on approval; local-only, never emitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub held_request: Option<HeldRequest>,
}
```

- Populate it at hold time: `exec.rs:604-608` sets
  `held_request: Some(HeldRequest::Exec(request.clone()))`;
  `enqueue_call_approval` / `hold_call_for_approval` (`call.rs:729-762`) set
  `HeldRequest::Call(...)`. (The held `request` here is the already-authorized
  original.)
- Stays out of the emitted event: `emit_approval_request` serializes the
  `ApprovalRequest`, not `PendingApproval` — no leak. The approvals queue file is
  already `0600` (`approval.rs:289-304`); the full request (incl. `command`/`env`/
  `args`) at rest matches the daemon's existing posture for `session.json` and the
  replay cache. **Never log `held_request`** — logs keep `request_id` only.
- Backward/forward compatible: `#[serde(default)]` lets older queues load;
  task holds and legacy holds carry `None`, which the live handler ignores (it
  only auto-resumes entries with a `HeldRequest`), so task and live release paths
  never collide.

### 2. Wire the live `RoutedEvent::ApprovalDecision` handler

Add an arm to `handle_routed_events` (`sync.rs:387-457`) dispatching to a new
`crate::approval::handle_live_approval_decision(client, paths, router_replay, &meta, &decision)`.

The handler (new code in `approval.rs`, exec/call spawn helpers in their modules):

1. **Match a live hold.** Load `ApprovalQueue`; look up `decision.request_id`.
   If absent, or the entry has `held_request == None` (task/legacy), **return** —
   nothing to do (task holds are the scheduler's; legacy holds cannot resume).
2. **Resolve verification inputs** (exactly as the scheduler does):
   - `local_user = client.user_id()`;
   - the room via `client.get_room(parse(meta.room_id))` (skip if unavailable);
   - `verifying_keys` from room-published agent state
     (`call::verifying_key_from_agent_state` over `agent::read_*`, as
     `scheduler_loop.rs:441-449`);
   - `trust = TrustStore::load(paths)`;
   - `approvers` from `Policy::load(...).rooms.get(room_id).approvers`
     (same loader the live exec/call path uses, `exec.rs:936` / `call.rs:413-415`);
   - `now_unix` from the wall clock.
3. **Verify the decision.** Build `DecisionVerification` and call
   `verification_failure(&decision, &meta.sender, &ctx)`. **Any `Some(reason)` →
   log non-sensitively and return** (the hold stays queued; fail-closed). This is
   the same function the scheduler uses — no parallel verifier. Crucially the
   `sender` is `meta.sender` (top-level event sender, not content).
4. **Burn the decision nonce (defense-in-depth).** Through the **router's own
   shared replay cache** (passed into `handle_routed_events`; see §5 of this
   section), `admit(nonce, expires_at)`. On `Err` (replayed) → return. *Do not load
   a second cache* (see Pitfall). Primary idempotency is queue-removal (step 6);
   this prevents a captured valid decision from re-releasing across redelivery.
5. **Branch on the decision value** (`decision_permits_spawn`):
   - **Denied (or any non-`"approved"`):** audit *denied-while-held* (§4),
     remove the hold from the queue + save, emit the terminal rejection:
     `emit_exec_rejected(reason = "approval_denied")` for exec, or
     `emit_call_response(error)` via a new `CallRejection::ApprovalDenied` for
     call. Return.
   - **Approved:** continue.
6. **Remove-then-resume (exactly-once).** Remove the `PendingApproval` from the
   queue and **persist before spawning**, so a duplicate/redelivered decision
   finds no entry and is a no-op. (The sync loop only advances its `next_batch`
   token after `handle_routed_events` returns — `sync.rs:317-318` — so a crash
   mid-handle re-reads the decision on restart and the still-queued entry releases
   exactly once.)
7. **Re-run the full authorize pipeline** against the recovered request:
   `authorize_live_exec` / `authorize_live_call` (re-derives the `Allowance` from
   *current* policy + trust + signature + verified-device gate). This is the
   security crux: room membership / a stale hold never bypasses policy.
   - **On `Ok((request, allowance))`:** audit *released* (§4) and spawn via the
     extracted lifecycle helper (§3). A re-resolved `requires_approval` is **not**
     re-held (it was just approved) — release runs it.
   - **On `Err(rejection)`** (policy changed to deny, key revoked, etc.): audit
     the denial via the existing `audit_*_rejection` path and emit the rejection.
     The hold is already removed → fail-closed, never runs. (Transient room-read
     failures while resolving the verifying key are the one edge where this drops a
     legitimately-approved hold; see Risks. Default: fail-closed, operator
     re-issues.)

The handler must **not** re-inject the original request into the `EventRouter`:
calling `authorize_live_*` directly is precisely the "daemon-internal exemption
from the route-level replay cache" the issue requires — the authorize pipeline
performs no nonce admission, so the already-consumed request nonce is never
re-checked.

### 3. Extract the exec/call spawn-and-lifecycle into reusable helpers

Today the exec spawn/lifecycle is inline in `handle_live_exec_request`
(`exec.rs:620-757`). Extract it into a `pub(crate)` helper, e.g.:

```rust
pub(crate) async fn spawn_authorized_live_exec(
    client: &Client, room: &Room,
    request: ExecRequest, allowance: Allowance,
) { /* emit accepted → running, register LiveExecControl, pty vs controlled run,
       emit output/finished/cancelled, publish invocation state */ }
```

Have both `handle_live_exec_request` (the `Execute` branch) and the release path
call it, so live release produces byte-for-byte the same lifecycle as a direct
exec. Do the analogous extraction on the call side around
`execute_authorized_call` + `emit_call_response` (`call.rs:692`, `:712-714`) into
a helper the release path reuses. Keep the extractions behavior-preserving (no
change to the non-approval path).

### 4. Audit variants for the held lifecycle

Distinguish the four new states from *allow-and-ran*. Extend the audit model and
**move the allow audit to the right place**:

- Add states. Either extend `AuditDecision` with `Held`, `Released`, `Expired`
  (keep `Allowed`/`Denied`), or add purpose-built `AuditRecord` constructors
  (`for_exec_held` / `for_exec_released` / `for_exec_expired` and the `for_call_*`
  counterparts) that set a stable `decision` + `policy_rule`. Prefer dedicated
  constructors mirroring `for_exec_denied` (`audit.rs:152-208`) so the existing
  `Allowed`/`Denied` JSON stays stable for current consumers; gate the new
  `decision` values behind the same `#[serde(rename_all = "lowercase")]`.
- **Re-point the existing allow audit.** Currently `audit_exec_decision(Allow)`
  fires before the disposition (`exec.rs:595-600`), and `audit_call_decision(Allow)`
  before it (`call.rs:670-677`). Change so:
  - `Execute` branch → audit *allowed* (allow-and-ran) as today;
  - `RequiresApproval` branch → audit *held* instead of *allowed*;
  - release → audit *released*; deny-while-held → *denied*; expiry → *expired*.
- All new records redact identically: exec via `redact_command(&request.command)`,
  call via tool-name-only (no `args`), reusing `redact_command` / the `for_call*`
  no-argv shape. Audit the release/deny/expiry events themselves (not just the
  original hold).

### 5. Fail-closed expiry sweep for live holds (mirror #291)

Add a sweep that removes undecided live holds past `expires_at`. **Home: the
scheduler pass** (`scheduler_loop.rs`), which already loads/persists the shared
`ApprovalQueue`, computes `approval_now_unix`, and visits exactly the rooms where
this daemon owns the target agent (a live hold only exists where `is_local_target`
held). Implement as a small function run once per pass:

- For each `PendingApproval` with `held_request.is_some()` and
  `approval_request_expired(&p.request.expires_at, now_unix)`
  (`approval.rs:667-672`, already `<=`-boundary and fail-open on a malformed
  stamp): audit *expired-while-held* (§4), best-effort emit the terminal
  rejection (`emit_exec_rejected(reason = "approval_expired")` /
  `CallRejection::ApprovalExpired` → `call.response` error), remove from queue.
- Persist the queue once if anything changed (the pass already gates its save on a
  queue delta, `scheduler_loop.rs:541-547`).

Expiry can only ever **block** a hold, never release one, strengthening
deny-by-default. The sweep needs no timeline read (it compares the persisted
stamp to `now`), so it is cheap and independent of `has_runnable_candidate`.

### 6. New rejection reasons

Add `ApprovalDenied` and `ApprovalExpired` to `ExecRejection` (`exec.rs:138-177`)
with `reason()` → `"approval_denied"` / `"approval_expired"`, and to
`CallRejection` (`call.rs:52-...`) feeding `rejection_response` (`call.rs:372-381`).
These are terminal, post-policy outcomes surfaced to the requester so a held
invocation does not hang silently on deny/expire.

## Affected Files / Crates / Modules

- `crates/mx-agent-protocol/src/schema.rs` — no change required (existing
  `ExecRequest`/`CallRequest`/`ApprovalDecision` reused). `HeldRequest` is a daemon
  type, defined in `approval.rs`.
- `crates/mx-agent-daemon/src/approval.rs` — `HeldRequest`, `PendingApproval`
  field, `handle_live_approval_decision`, reuse of `verification_failure` /
  `read_verified_approval_decisions` machinery, expiry-sweep helper.
- `crates/mx-agent-daemon/src/sync.rs` — new `RoutedEvent::ApprovalDecision` arm
  in `handle_routed_events`; thread the router's `Arc<Mutex<ReplayCache>>` (or an
  `EventRouter` admit method) into the handler (`sync.rs:290-330`, `:381-459`).
- `crates/mx-agent-daemon/src/exec.rs` — set `held_request` at hold; extract
  `spawn_authorized_live_exec`; add `ApprovalDenied`/`ApprovalExpired`
  `ExecRejection` variants; re-point the allow audit.
- `crates/mx-agent-daemon/src/call.rs` — set `held_request` at hold; extract a
  call execute/respond helper; add `CallRejection` variants; re-point the allow
  audit.
- `crates/mx-agent-daemon/src/audit.rs` — held/released/expired audit
  states/constructors.
- `crates/mx-agent-daemon/src/scheduler_loop.rs` — live-hold expiry sweep per pass.
- `crates/mx-agent-daemon/src/event_router.rs` — optionally a thin
  `admit_decision_nonce` accessor so the decision handler burns through the shared
  cache (no change to routing/step-4 behavior).
- `docs/architecture.md` §12 — update the disclosure (see Documentation Updates).
- Tests: `approval.rs`/`exec.rs`/`call.rs`/`audit.rs` unit modules;
  `crates/mx-agent-daemon/tests/matrix_integration.rs` (live E2E).

## CLI / API Changes

**None** to the CLI surface. `mx-agent approval approve/deny/list/show` are
unchanged; the decision event they emit already carries nonce + expiry +
signature. All new behavior is receive-side daemon logic. New `pub(crate)`
helpers (`handle_live_approval_decision`, `spawn_authorized_live_exec`, the call
execute helper) get doc comments (`missing_docs` is `-D warnings`); no new public
crate API is exported.

## Data Model / Protocol Changes

- **No wire/protocol change.** `com.mxagent.approval.request.v1`,
  `.decision.v1`, `exec.*`, `call.*` schemas are unchanged; no event-type or
  version bump. The emitted `approval.request` stays lossy/no-leak.
- **Local persistence (daemon-private):** `PendingApproval` gains an optional
  `held_request: Option<HeldRequest>` in `approvals.json` (`0600`). Additive and
  `#[serde(default)]` → forward/backward compatible; older queues load, newer
  queues are ignored by older daemons' unknown-field handling.
- **Audit schema:** new `decision` values (`held`/`released`/`expired`) and/or
  new records in `audit.log`. Append-only, additive; existing `allowed`/`denied`
  lines unchanged. Document in architecture §13.6 if that section enumerates
  values.

## Security Considerations

- **Re-authorize before spawn.** Release re-runs `authorize_live_exec` /
  `authorize_live_call` (signature → local trust store → deny-by-default policy →
  verified-device gate). A stale hold, a since-revoked key, or a since-tightened
  policy is denied at release. Matrix room membership is never execution
  permission.
- **Decision authenticity = scheduler parity.** Release honors a decision only via
  the shared `verification_failure`: authorized approver (`{local_user} ∪
  approvers`, read from `meta.sender`, never content), detached Ed25519 signature,
  key both room-published **and** locally `Trusted`, single-use nonce, and
  cache-independent unexpired `expires_at`. A forged/unsigned/expired/replayed or
  wrong-sender decision presents as "still pending" and never releases.
- **Replay-cache exemption is strictly scoped.** The exemption is *not* a router
  bypass: the resume path calls the pure authorize pipeline directly (which never
  admits a nonce), so the request nonce consumed at first admission is never
  re-checked — and no room-originated event is re-`admit`ed. The decision nonce is
  separately burned through the router's **single** shared cache (avoid the
  second-cache clobber pitfall). Exactly-once primarily rests on atomic
  queue-removal-before-spawn.
- **Fail closed.** Undecided, denied, expired, or re-authorize-denied holds never
  execute. Verification failure, missing `held_request`, unavailable room, or a
  load error all leave the hold queued or drop it without running.
- **No secret leakage.** `held_request` (with `command`/`env`/`args`) is
  `0600`-at-rest only, never re-emitted and never logged (logs carry `request_id`,
  `sender`, `reason` only). The emitted `approval.request` keeps its no-leak
  summary. Audit records redact via `redact_command` (exec) / tool-name-only
  (call).
- **Unix-only, no `unsafe`, MSRV 1.74.** All new code is portable safe Rust over
  existing `0600`/`0700` file helpers; no new platform assumptions.

## Testing Plan

Unit (no homeserver; `cargo test --all`):

- `approval.rs`:
  - `PendingApproval` round-trips with/without `held_request` (back-compat),
    file stays `0600`, `held_request` absent from the emitted `ApprovalRequest`
    (no-leak assertion like `call_approval_request_summary_*`).
  - Disposition/recovery: a held exec/call recovers the exact original signed
    request from the queue.
  - Decision disposition reuse: a valid signed `approved` decision passes
    `verification_failure` and yields *release*; `denied`/garbled →
    no-release; forged sender / unsigned / untrusted key / expired / missing
    nonce each map to the right `Some(reason)` and **no release** (extend the
    existing `verification_failure_*` battery).
  - Exactly-once: a second identical decision after release finds no queue entry
    → no-op.
- `exec.rs` / `call.rs`: new `ExecRejection`/`CallRejection` variants'
  `reason()`/`rejection_response` strings (`approval_denied`, `approval_expired`);
  the extracted spawn/execute helpers preserve the non-approval lifecycle
  (regression).
- `audit.rs`: held/released/expired records serialize with stable
  `decision`/`policy_rule`, redact command/omit args, single-line JSON, `0600`.
- `scheduler_loop.rs` (or a pure helper): the live-hold expiry sweep removes only
  `held_request.is_some()` entries past `expires_at`, leaves fresh and
  task/legacy holds, and is a no-op when nothing expired.

Integration (routed-event handler, no live homeserver where possible): drive
`handle_live_approval_decision` against a temp `SessionPaths` + in-memory queue +
a stub verification context to assert release/deny/expiry dispositions and queue
mutation without a real `Room`, mirroring how `verification_failure` and the audit
helpers are already unit-tested.

Live E2E (`#[ignore]`d, Tuwunel; `scripts/matrix_integration_test.sh`), added to
`crates/mx-agent-daemon/tests/matrix_integration.rs` alongside the existing
approval-required cases:

- **approve → held exec executes:** policy `requires_approval`; remote `exec`
  is held (accepted/finished not emitted); `mx-agent approval approve` →
  invocation runs exactly once and emits accepted → running → finished; audit
  shows *held* then *released* (not *allowed*).
- **approve → held call executes:** analogous; `call.response` ok is emitted only
  after approval.
- **deny → never runs:** held exec/call denied → terminal `exec.rejected`
  (`approval_denied`) / `call.response` error; no process; audit *denied*.
- **expire → never runs:** held request past `expires_at` is swept; terminal
  `approval_expired`; queue entry gone; audit *expired*.
- **forged/unsigned/expired/replayed decision → no release:** a decision from a
  non-approver room member, unsigned, or with a replayed nonce leaves the hold
  pending and never executes.

## Documentation Updates

- `docs/architecture.md` §12 — replace the disclosure
  *"Inline resume of a live held request from a decision event is not wired on
  either surface today; held-action resume exists for task-backed actions via the
  scheduler."* (`:1640-1642`) with a description of the live release path:
  event-driven `ApprovalDecision` handling, re-authorize-before-spawn, the
  decision-nonce/queue-removal exactly-once posture, and the fail-closed live-hold
  expiry sweep. Note the replay-cache exemption is the pure-authorize call, not a
  router bypass.
- `docs/architecture.md` §13.6 — add the new audit `decision` values
  (held/released/expired) if that section enumerates them.
- `README.md` Project-status row for approval / `requires_approval` and the
  `CONTRIBUTING.md`/integration-suite description — note live held `exec`/`call`
  now resume on an approved decision (only if behavior actually ships).
- Wiki (`wiki/` source of truth) Security/Approval pages — reflect that live holds
  now release/deny/expire, keeping the no-leak and re-authorize guarantees.
- Doc comments on every new `pub(crate)` item (`missing_docs` is `-D warnings`).

## Risks and Open Questions

- **Transient failure at release.** Resolving the verifying key reads
  room-published agent state; a transient read failure during re-authorize would,
  with remove-then-resume, drop a legitimately-approved hold (the decision was
  consumed and won't be redelivered). *Recommended default:* fail-closed (drop;
  operator re-issues). *Alternative to weigh:* re-authorize **before**
  queue-removal and, on a transient (non-policy) error, leave the hold queued and
  do not burn the nonce so a restart re-sync can retry — at the cost of a more
  complex error taxonomy. Confirm which.
- **Human-approval window.** `approval_request_for*` copies the request's
  `expires_at` (often ~5 min) into the held approval, so the expiry sweep may
  reclaim a hold before an operator can approve. The task path stamps
  `APPROVAL_REQUEST_TTL` (1 h) instead. Decide whether to (a) keep current
  behavior (in-scope, minimal) or (b) stamp a longer TTL at live-hold time —
  (b) changes the emitted `approval.request.expires_at` and the
  `approval_request_summary_*` unit tests, so it is a deliberate, separately-tested
  behavior change. *Recommended:* keep (a) for #306; file a follow-up for (b).
- **Where the decision-nonce cache lives.** Threading the router's
  `Arc<Mutex<ReplayCache>>` into `handle_routed_events` is the correct fix but
  touches the sync wiring. If that proves invasive, the fallback is queue-removal
  idempotency alone (acceptable: `verification_failure` already enforces expiry
  cache-independently and the nonce is signature-bound to one `request_id`), with
  the nonce burn deferred — but document the reduced defense-in-depth. *Recommended:*
  thread the handle.
- **Spawn-helper extraction surface.** `exec.rs:620-757` mixes invocation-state
  publishing, `LiveExecControl` registration, PTY vs controlled paths, and output
  emission. The extraction must be behavior-preserving; guard with the regression
  tests above before relying on it from the release path.
- **Task vs live disambiguation.** Relies on `held_request.is_some()` to route a
  decision to the live handler vs leaving it to the scheduler. Confirm task holds
  never set `held_request` (they go through `QueueApprovalGate`, not the live
  exec/call hold paths) so the two release paths never double-fire on one decision.

## Implementation Checklist

1. **Schema/persistence:** add `HeldRequest` enum and
   `PendingApproval::held_request: Option<HeldRequest>` (`approval.rs`), with
   doc comments, `#[serde(default, skip_serializing_if)]`, and a no-leak unit
   test. Keep `enqueue` idempotent-by-`request_id` carrying the new field.
2. **Populate at hold:** set `held_request` in the exec hold (`exec.rs:604-608`)
   and the call hold (`call.rs:729-762`).
3. **Rejection reasons:** add `ApprovalDenied`/`ApprovalExpired` to `ExecRejection`
   (`exec.rs`) and `CallRejection` (`call.rs`) + `reason()`/`Display`/
   `rejection_response` wiring; unit-test the strings.
4. **Extract spawn/execute helpers:** `spawn_authorized_live_exec` (exec) and a
   call execute/respond helper; re-point the existing `Execute`/`Allow` paths to
   them; add regression tests.
5. **Audit states:** add held/released/expired constructors/values (`audit.rs`),
   redacting like `for_*_denied`; re-point the allow audit so `Execute` →
   *allowed*, `RequiresApproval` → *held*; unit-test serialization + redaction.
6. **Decision handler:** implement `handle_live_approval_decision` (`approval.rs`)
   — match live hold by `request_id` + `held_request`, build
   `DecisionVerification` (local_user / room keys / trust / approvers / now),
   call `verification_failure`, burn the decision nonce via the router cache,
   branch deny vs approve, remove-then-resume, re-authorize, spawn; non-sensitive
   logging only.
7. **Sync wiring:** add the `RoutedEvent::ApprovalDecision` arm to
   `handle_routed_events` and thread the router's shared replay cache into it
   (`sync.rs`); optional `EventRouter::admit_decision_nonce` accessor.
8. **Expiry sweep:** add the per-pass live-hold sweep to `scheduler_loop.rs`
   (audit + terminal emit + queue removal, gated save), with a pure unit test.
9. **Integration test** of the routed handler disposition (release/deny/expiry,
   queue mutation) without a live `Room`.
10. **Live E2E** cases in `matrix_integration.rs`: approve→exec runs,
    approve→call runs, deny→never runs, expire→never runs, forged/unsigned/
    replayed→no release.
11. **Docs:** update architecture §12 (drop the "not wired" disclosure) and
    §13.6, README/CONTRIBUTING status, and the wiki approval/security pages.
12. **Green gate:** `cargo fmt --check`, `cargo clippy --all-targets
    --all-features -- -D warnings`, `cargo build --all`, `cargo test --all`, and
    the live suite.
