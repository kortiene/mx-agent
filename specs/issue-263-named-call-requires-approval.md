# Enforce `requires_approval` on the named-`call` path (issue #263)

## Problem Statement

A policy that marks a tool with `requires_approval = true` is silently bypassed
for **named tool calls** (`com.mxagent.call.request.v1`). The raw `exec` surface
honours the flag: after authorization it consults
[`disposition_for_exec`](../crates/mx-agent-daemon/src/approval.rs) and, when the
resolved `Allowance` demands approval, it enqueues a `PendingApproval`, emits a
`com.mxagent.approval.request.v1` into the room, and **returns without spawning
the process** (`exec.rs:575-591`).

The `call` surface has no equivalent gate. In
`handle_live_call_request` (`crates/mx-agent-daemon/src/call.rs`) the flow is:

```text
authorize_live_call → (CallRequest, Allowance)
  → audit_call_decision(Outcome::Allow)
  → execute_authorized_call(&authorized, &allowance)   // runs the tool immediately
```

The resolved `Allowance` *is* now threaded through to the executor (that
plumbing landed with #284/#257 — see "Current state" below), and it is consulted
for `require_verified_device`, but its `requires_approval` flag is never checked.
An approval-required `call` therefore executes **before — in fact, without — any
operator decision**. This fails *open* on a security control, unlike the `call`
audit gap (#257) which merely lost a record. Any operator relying on
`requires_approval` to gate a sensitive tool over the `call` surface has a false
sense of safety.

This is an explicit human-in-the-loop requirement carried over from the
live-call work (#194) and the scheduler approval gate (#223), and is documented
in architecture §12.

## Goals

- Honour `Allowance.requires_approval` on the live named-`call` path so an
  approval-required call **does not invoke the tool** until an operator decides
  — fail closed, mirroring `exec.rs:575-591` exactly.
- When approval is required, **enqueue a `PendingApproval`** into the on-disk
  approval queue (so it is visible to `mx-agent approval list` / `show` and
  survives a daemon restart) and **emit a `com.mxagent.approval.request.v1`**
  into the room.
- Preserve the existing behaviour when `requires_approval = false`: the call
  still executes immediately with no observable change.
- Reuse the existing approval machinery (`ApprovalQueue`, `PendingApproval`,
  `emit_approval_request`, `approval_request_*`) rather than introducing a
  parallel queue or event type.
- Add unit coverage proving the hold gate: an approval-required call holds (tool
  not reached, a `PendingApproval` is produced) and a non-approval call runs
  immediately.

## Non-Goals

- **Inline resume of a held *live* call request.** The reference `exec` surface
  has **no** inline resume either: a held live `exec` request is enqueued, the
  approval request is emitted, and the handler returns — `RoutedEvent::ApprovalDecision`
  falls into the `other` arm of the sync dispatch (`sync.rs:449`) with no live
  handler. Resume of a *held action* exists today only for **task-backed**
  actions, through the scheduler loop + `QueueApprovalGate` in
  `task_orchestrator.rs`, and tool-backed task actions already flow through the
  named-tool execution path there. Building an inline ApprovalDecision→execute
  resume for live requests would be net-new behaviour on *both* surfaces and is
  out of scope here (see Risks/Open Questions; a follow-up issue should track it
  if wanted). This spec brings `call` to **parity with `exec`**: fail closed and
  make the pending request visible/durable.
- Changing the policy schema, the `requires_approval` semantics, or the
  `Allowance` shape (the flag already exists — `engine.rs` `allowance_for`).
- The local CLI loopback call path (`start_call_loopback`), which uses the
  operator's own execution-level defaults and is not a remote, signed request.
- Re-deriving the verified-decision / replay / expiry machinery — that is owned
  by #264/#265 and the scheduler and is unchanged here.
- Any new IPC method, CLI command, or protocol event type.

## Relevant Repository Context

**Crate layout.** The fix is confined to `crates/mx-agent-daemon`:

- `src/call.rs` — the named-`call` request/response flow. `handle_live_call_request`
  is the live receive-side handler; `authorize_live_call` runs signature → trust
  → policy and returns `(CallRequest, Allowance)`; `execute_authorized_call`
  bridges to the built-in tool runner.
- `src/approval.rs` — the approval queue and the `exec`-typed disposition
  (`disposition_for_exec`, `ExecDisposition`, `approval_request_for`,
  `ApprovalQueue`, `PendingApproval`, `emit_approval_request`). This is where the
  shared/parallel disposition logic belongs.
- `src/exec.rs:575-591` — the working reference for the hold behaviour.
- `src/sync.rs:386-459` — the live dispatch `match` that routes
  `RoutedEvent::CallRequest` to `handle_live_call_request` and (today) drops
  `ApprovalDecision` into the catch-all arm.
- `src/lib.rs:58-78` — public re-exports for `approval::*` and `call::*`.

**Current state (important — the issue's "Where" snapshot predates #284/#257).**
The `Allowance` is **already plumbed through** to the executor on `main`:
`authorize_live_call` returns `Result<(CallRequest, Allowance), CallRejection>`,
`handle_live_call_request` audits with the allowance and calls
`execute_authorized_call(&authorized, &allowance)`, and `execute_authorized_call`
takes `&Allowance` and confines the tool through `tool_exec::execute_tool_async`
(§13.5 sandbox/network/env confinement, #262/#284). **The only missing piece is
the disposition/approval gate** between `audit_call_decision(...Allow...)` and
`execute_authorized_call(...)`. The implementation is therefore narrower than the
issue text implies: no signature changes to `authorize_live_call` or
`execute_authorized_call` are required.

**Conventions.** Unix-only; no `unsafe`; Rust MSRV 1.74; deny-by-default policy;
privileged requests are Ed25519-signed and trust-checked before policy; audit
records and logs carry only non-sensitive metadata (never args/secrets — see the
existing `call_request_for_audit` test asserting args never leak); human-readable
output by default with `--json` for automation; new public items get doc
comments.

## Proposed Implementation

### 1. Add a `call`-typed disposition in `approval.rs`

Mirror the `exec` disposition. `ExecDisposition` wraps an `ExecRequest`, so a
`call` needs its own type wrapping a `CallRequest` (the two request shapes differ
and a generic over both adds more complexity than it saves):

```rust
/// Whether an authorized named call may run immediately or must wait for approval.
///
/// The `call` analogue of [`ExecDisposition`]. A [`CallDisposition::RequiresApproval`]
/// carries the [`ApprovalRequest`] the caller must queue and emit; the wrapped
/// request must **not** be executed until an approval decision arrives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallDisposition {
    Execute(CallRequest),
    RequiresApproval { request: CallRequest, approval: ApprovalRequest },
}

impl CallDisposition {
    pub fn requires_approval(&self) -> bool { matches!(self, Self::RequiresApproval { .. }) }
    pub fn executable(&self) -> Option<&CallRequest> {
        match self { Self::Execute(r) => Some(r), Self::RequiresApproval { .. } => None }
    }
}

/// Decide whether an authorized `call` may run now or must be queued for approval,
/// honouring the policy's `requires_approval` flag (mirrors [`disposition_for_exec`]).
pub fn disposition_for_call(request: CallRequest, allowance: &Allowance) -> CallDisposition {
    if allowance.requires_approval {
        let approval = approval_request_for_call(&request, allowance);
        CallDisposition::RequiresApproval { request, approval }
    } else {
        CallDisposition::Execute(request)
    }
}

/// Build the `com.mxagent.approval.request.v1` content for a named call.
///
/// Pure and deterministic. Identifiers, parties, and expiry are copied from the
/// authorized request; the summary names the tool (no args, so nothing sensitive
/// is rendered); the risk level reuses [`risk_for`].
pub fn approval_request_for_call(request: &CallRequest, allowance: &Allowance) -> ApprovalRequest {
    ApprovalRequest {
        request_id: request.request_id.clone(),
        invocation_id: request.invocation_id.clone(),
        requester: request.requesting_agent.clone().unwrap_or_default(),
        target: request.target_agent.clone().unwrap_or_default(),
        summary: format!("Call tool {}", request.tool),
        risk: risk_for(allowance).to_string(),
        expires_at: request.expires_at.clone(),
        extra: Default::default(),
    }
}
```

Notes:
- `CallRequest.requesting_agent` / `target_agent` are `Option<String>`; the live
  handler only reaches the disposition once both are known to be present
  (`handle_live_call_request` returns early otherwise), but the builder must
  still be total — use `.clone().unwrap_or_default()`.
- The summary must **not** include `request.args` (args can carry secrets; the
  existing audit tests enforce no-leak). Naming only the tool keeps parity with
  the deny-by-default redaction posture.
- `risk_for` is currently private to `approval.rs`; `approval_request_for_call`
  lives in the same module so it stays private. Good.
- Re-export `CallDisposition`, `disposition_for_call`, and
  `approval_request_for_call` from `lib.rs` alongside the existing `approval::*`
  exports.

### 2. Insert the hold gate in `handle_live_call_request`

In `call.rs`, between the allowed-audit and execution (currently the
`Ok((authorized, allowance)) => { audit_call_decision(...); execute_authorized_call(...).await }`
arm), branch on the disposition exactly as `exec.rs:575-591` does:

```rust
Ok((authorized, allowance)) => {
    audit_call_decision(paths, &meta.room_id, &authorized, requesting_agent, target_agent,
                        &Outcome::Allow(allowance.clone()));
    match crate::approval::disposition_for_call(authorized.clone(), &allowance) {
        crate::approval::CallDisposition::RequiresApproval { approval, .. } => {
            let mut queue = crate::approval::ApprovalQueue::load(paths).unwrap_or_default();
            queue.enqueue(crate::approval::PendingApproval {
                room_id: meta.room_id.clone(),
                request: approval.clone(),
            });
            if let Err(e) = queue.save(paths) {
                tracing::warn!(error = %e, request_id = %approval.request_id,
                               "failed to persist call approval request");
            }
            if let Err(e) = crate::approval::emit_approval_request(&room, &approval).await {
                tracing::warn!(error = %e, request_id = %approval.request_id,
                               "failed to emit call approval request");
            }
            return; // held, fail closed — do not execute, mirroring exec
        }
        crate::approval::CallDisposition::Execute(_) => {}
    }
    execute_authorized_call(&authorized, &allowance).await
}
```

The held branch **returns before the function's trailing `emit_call_response`**,
so no `call.response` is emitted for a held request — parity with `exec`, which
emits neither `exec.accepted` nor a result while holding. (See Open Questions on
whether to instead emit a non-terminal "pending approval" response; the
recommended behaviour is parity = no response.)

Because the handler returns early in the held branch, the existing structure
that computes a `response` and emits it at the end is only reached on the
`Execute` and rejection paths — confirm the early `return` is inside the match
arm and does not skip required cleanup (there is none on this path).

### 3. Sync dispatch

No change required for the recommended (parity) scope: `RoutedEvent::ApprovalDecision`
continues to fall into the catch-all arm (no inline resume — see Non-Goals).
If a follow-up adds inline resume, that is where a new handler would be wired.

## Affected Files / Crates / Modules

- `crates/mx-agent-daemon/src/approval.rs` — add `CallDisposition`,
  `disposition_for_call`, `approval_request_for_call`; unit tests.
- `crates/mx-agent-daemon/src/call.rs` — insert the hold gate in
  `handle_live_call_request`; unit tests for the disposition seam.
- `crates/mx-agent-daemon/src/lib.rs` — re-export the new public items.
- `docs/architecture.md` — §5.2 / §12 note that named `call` honours
  `requires_approval` (see Documentation Updates).
- (Read-only reference) `crates/mx-agent-daemon/src/exec.rs:575-591`,
  `crates/mx-agent-policy/src/engine.rs` (`allowance_for`).

## CLI / API Changes

None to the CLI. New **public Rust API** items (documented): `CallDisposition`,
`disposition_for_call`, and (module-private but newly added)
`approval_request_for_call`. No new IPC method and no protocol surface change —
the `com.mxagent.approval.request.v1` event and `ApprovalQueue` already exist and
are reused unchanged.

## Data Model / Protocol Changes

None. The emitted `com.mxagent.approval.request.v1` content reuses the existing
`ApprovalRequest` schema; the on-disk `approvals.json` queue format
(`PendingApproval`) is unchanged. A `call`-originated pending approval is
indistinguishable in shape from an `exec`-originated one (same fields), which is
intentional — `mx-agent approval list/show/approve/deny` already handle it.

## Security Considerations

- **Fail closed.** The whole point: an approval-required `call` must never reach
  `execute_authorized_call` before a decision. The gate sits *after* the
  authoritative signature → trust → policy gate and the verified-device gate, so
  it can only *add* a hold, never grant — consistent with §1.2 layering.
- **No secret leakage.** The approval summary names only the tool, never
  `request.args`. Mirror the existing `call_request_for_audit` assertions: add a
  test that the emitted/queued `ApprovalRequest` does not contain a secret-like
  arg value. Logs on the held path carry only `request_id` (non-sensitive).
- **Daemon/CLI separation preserved.** All work stays in the daemon; the CLI
  remains stateless and never sees tokens or keys.
- **Room membership is not execution permission.** Unchanged — authority still
  comes from signing + trust + policy; this only inserts the optional human gate.
- **Durability.** Persisting the `PendingApproval` (0600, atomic write via the
  existing `ApprovalQueue::save`) means a held call survives a daemon restart and
  is operator-visible, matching exec.
- **Unix-only**; no `unsafe`; no new dependencies.

## Testing Plan

Unit tests (in `approval.rs` and `call.rs`, `#[cfg(test)]`, no live Matrix
client required — mirror the existing `disposition_*` and `enforce_verified_device_call`
tests):

1. **`disposition_for_call` holds when approval required** — build a `CallRequest`
   and an `Allowance { requires_approval: true, .. }`; assert
   `disposition.requires_approval()` and `disposition.executable().is_none()`
   (the seam that proves the tool runner is not reached — the direct analogue of
   exec's `disposition_holds_request_when_approval_required`). Assert the bundled
   `ApprovalRequest` carries the request's `request_id` / `invocation_id` /
   `expires_at`.
2. **`disposition_for_call` permits immediate run without the flag** — with
   `requires_approval: false`, assert `!requires_approval()` and
   `executable()` is `Some` with the right `invocation_id` (regression: no
   behaviour change for ordinary calls).
3. **`approval_request_for_call` summary/parties** — assert the summary is
   `"Call tool <tool>"`, requester/target map from the request, expiry copied,
   and that a secret-like arg value does **not** appear anywhere in the produced
   `ApprovalRequest` (serialize to JSON and assert absence), matching the
   no-leak posture.
4. **Queue integration** — using a temp `SessionPaths` (as in the existing
   `queue_survives_save_and_load` test), enqueue the `approval` from a
   `RequiresApproval` disposition, save, reload, and assert the pending approval
   is present and the file is `0600`.
5. **Optional handler-seam test** — if the enqueue+emit step is factored into a
   small pure helper (e.g. `hold_call_for_approval(paths, room_id, &approval)`
   that does queue load/enqueue/save and returns the `PendingApproval`), unit-test
   that helper against a temp dir so the "PendingApproval is enqueued" criterion
   is covered without a live room. Emitting into a room (`emit_approval_request`)
   stays exercised by the existing exec/e2e coverage.

Run `cargo test -p mx-agent-daemon` and `cargo clippy --all-targets -- -D warnings`.

## Documentation Updates

- `docs/architecture.md` §5.2 (Named Tool Calls): add a sentence that named
  `call` requests honour `requires_approval` identically to `exec` — an
  approval-required call is held (not executed), enqueued to the local approval
  queue, and emitted as `com.mxagent.approval.request.v1`.
- `docs/architecture.md` §12 (Approval Workflow): note that the approval queue
  and `mx-agent approval list/show/approve/deny` cover both `exec`- and
  `call`-originated pending approvals. **Do not** claim inline live-call resume
  exists (it does not — see Non-Goals); only state the hold/visibility guarantee.
- No README or help-text change (no new command/flag).

## Risks and Open Questions

1. **Resume of a held *live* call (primary open question).** The issue's
   acceptance criteria mention a resume path
   (`approval_decision_for` / `decision_permits_spawn`, reject on deny/expiry).
   But the `exec` reference has **no** inline resume for live held requests, and
   `ApprovalDecision` events are not handled in the live dispatch
   (`sync.rs:449`). Recommended decision: **mirror exec exactly** — hold +
   enqueue + emit, no inline resume — because (a) it fully delivers the
   fail-closed security guarantee the p1 is about, (b) it matches the surface the
   issue tells us to mirror, and (c) adding live resume would be net-new
   behaviour on both surfaces and risks implying alpha behaviour that does not
   exist. If inline resume for live held requests is genuinely wanted, it should
   be a **separate tracked issue covering both `exec` and `call`** (a shared
   `RoutedEvent::ApprovalDecision` handler that re-drives held requests against
   `read_verified_approval_decisions` + replay/expiry). Confirm this scoping with
   the maintainer.
2. **Held-call response behaviour.** Should the daemon emit a non-terminal
   `call.response` (e.g. `ok: false`, `error: "pending_approval"`) so the
   requester's `wait_for_call_response` (60 s) does not simply time out?
   Recommended: **no** — emit nothing, matching exec (which emits neither accept
   nor result while holding). A "pending" response risks being read as a terminal
   failure. Flagged for confirmation.
3. **Generalize vs. duplicate the disposition.** This spec recommends a separate
   `CallDisposition` rather than generalizing `ExecDisposition` over a request
   trait, because the request types and summary rendering differ and duplication
   is small. If the maintainer prefers a single shared abstraction, the builder
   (`summary_for` vs tool naming) is the only real divergence.
4. **Task-backed tool actions** already honour approval through the scheduler's
   `QueueApprovalGate`; this change must not double-gate them. The live `call`
   handler and the task path are distinct entry points, so there is no overlap —
   but verify no task-dispatch code routes through `handle_live_call_request`.

## Implementation Checklist

1. In `approval.rs`, add `CallDisposition`, `disposition_for_call`, and
   `approval_request_for_call` (doc-commented), reusing `risk_for`,
   `ApprovalRequest`, and importing `CallRequest` from
   `mx_agent_protocol::schema`.
2. (Optional) Factor an enqueue+save helper `hold_call_for_approval(paths,
   room_id, &approval) -> PendingApproval` to make the hold step unit-testable;
   otherwise inline it in the handler.
3. In `call.rs` `handle_live_call_request`, insert the disposition branch between
   `audit_call_decision(...Allow...)` and `execute_authorized_call(...)`; on
   `RequiresApproval`, enqueue + save + `emit_approval_request`, then `return`
   without executing or emitting a `call.response`.
4. Re-export `CallDisposition`, `disposition_for_call` (and the helper if added)
   from `lib.rs`.
5. Add the unit tests from the Testing Plan to `approval.rs` / `call.rs`,
   including the no-secret-leak assertion on the emitted `ApprovalRequest`.
6. Update `docs/architecture.md` §5.2 and §12 (hold/visibility only; no resume
   claim).
7. Run `cargo test -p mx-agent-daemon` and `cargo clippy --all-targets -- -D
   warnings`; ensure no `unsafe`, MSRV-compatible.
8. Confirm the two open scoping questions (inline resume; held-call response)
   with the maintainer before extending beyond exec parity.
```