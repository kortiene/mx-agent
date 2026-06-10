# Audit Named `call` Decisions (Allow and Deny)

## Problem Statement

The daemon keeps a local, append-only **audit log** (`docs/architecture.md` §13.6,
`docs/security-hardening.md`) — the operator's tamper-evident trail of "who asked
for what, and whether it was allowed or denied." For the raw `exec` path this is
complete: `handle_live_exec_request` audits every allowed invocation
(`audit_exec_decision` → `AuditRecord::for_exec`), every policy denial, and — since
#256 — the post-policy `require_verified_device` denial (`audit_exec_rejection` →
`AuditRecord::for_exec_denied`).

The named-`call` path audits **nothing**. `handle_live_call_request`
(`crates/mx-agent-daemon/src/call.rs`) matches `Ok(authorized)` /
`Err(rejection)` and emits a `com.mxagent.call.response.v1`, but never constructs
or appends an `AuditRecord`. As a result every privileged named-tool invocation —
and every denial of one — leaves no entry in the local audit log. A reviewer
reading the log sees `exec` decisions but is blind to all `call` decisions.

This gap was surfaced during the #240 review (PR #256), which fixed the
equivalent exec-side hole but left the call path untouched. The audit record
helper for calls already exists (`AuditRecord::for_call`) and is unit-tested, but
no production code calls it.

## Goals

- Audit **allowed** named calls via `AuditRecord::for_call(...)`, recording the
  room, requester, target, invocation id, tool name, decision (`allowed`), the
  `allow_tools` policy-rule family, and the selected sandbox backend.
- Audit **`CallRejection::PolicyDenied`** with its `DenyReason`, producing a
  `denied` record whose `policy_rule` is the stable `deny:<reason>` string (e.g.
  `deny:tool_not_allowed`) and which omits the `sandbox` field.
- Audit **`CallRejection::UnverifiedDevice`** as `deny:unverified_device`,
  mirroring the exec post-policy gate denial.
- Leave **pre-policy authentication failures** (`Malformed`, `Unsigned`,
  `InvalidSignature`, `UntrustedKey`) **unaudited**, exactly as exec does — these
  are not attributable to a trusted requester.
- Add unit tests covering the call audit records (allow + both audited denials),
  including the no-secret / single-line invariants the audit module already
  upholds.

## Non-Goals

- No change to the authoritative authorization pipeline (signature → trust →
  policy) or to the verified-device gate behaviour. This is purely additive
  logging around decisions already being made.
- No new audit fields, no schema/format change to `AuditRecord`, and no change to
  the audit file location, permissions, or rotation behaviour.
- Auditing pre-policy auth failures (unsigned/bad-signature/untrusted/malformed):
  intentionally excluded to match exec and avoid logging un-attributable noise.
- Loopback / IPC-local calls (`start_call_loopback`) are out of scope; this issue
  concerns the **receive-side** live Matrix handler `handle_live_call_request`.
- No CLI surface to read/print the audit log (none exists today for exec either).

## Relevant Repository Context

**Crate:** `mx-agent-daemon` (the daemon owns long-lived Matrix state, crypto,
policy enforcement, and the audit log; the CLI never sees tokens or keys).

**Key modules:**

- `crates/mx-agent-daemon/src/call.rs`
  - `handle_live_call_request(client, paths, meta, request)` — receive-side
    handler. Resolves the target agent, reserializes the request, calls
    `authorize_live_call`, then `execute_authorized_call` (on `Ok`) or
    `rejection_response` (on `Err`), and emits a `call.response`. **No audit
    call today.**
  - `authorize_live_call(room, paths, content, request, requesting_agent,
    room_id) -> Result<CallRequest, CallRejection>` — wraps
    `authorize_call_request_with_allowance` (which already returns the
    `Allowance`) and then applies the additive verified-device gate via
    `enforce_verified_device_call`. **It currently discards the `Allowance`** and
    returns only the `CallRequest`.
  - `CallRejection` enum: `Malformed`, `Unsigned`, `InvalidSignature`,
    `UntrustedKey { key_id }`, `PolicyDenied(DenyReason)`, `UnverifiedDevice`.
    `CallRejection::reason()` yields stable strings (e.g. `"policy_denied"`,
    `"unverified_device"`).

- `crates/mx-agent-daemon/src/exec.rs` — the pattern to mirror:
  - `handle_live_exec_request` matches the rejection and selectively audits:
    `ExecRejection::PolicyDenied(reason)` → `audit_exec_decision(..,
    &Outcome::Deny(reason.clone()))`; `ExecRejection::UnverifiedDevice` →
    `audit_exec_rejection(..)`; all other (pre-policy) variants → `{}` (no audit).
    On success it calls `audit_exec_decision(.., &Outcome::Allow(allowance))`.
  - `authorize_live_exec` returns `Result<(ExecRequest, Allowance),
    ExecRejection>` — the shape the call path should adopt.
  - Private helpers `audit_exec_decision`, `audit_exec_rejection`, and
    `append_exec_audit` (the latter resolves the path via
    `AuditLog::default_path()` with a `paths.data_dir` fallback, then appends,
    warning on I/O error).

- `crates/mx-agent-daemon/src/audit.rs` — the audit log model:
  - `AuditRecord::for_call(room, requester, target, invocation_id, tool,
    outcome)` — **already exists and is unit-tested** (`call_record_uses_tool_field`),
    sets `request: "call"`, `tool: Some(...)`, `policy_rule` via
    `rule_for(outcome, "allow_tools")`, and `sandbox` via `sandbox_for_outcome`.
  - `AuditRecord::for_exec_denied(.., command, deny_reason: &str)` — the
    post-policy-gate denial constructor. **There is no `for_call_denied`
    equivalent yet**, so one must be added for the `UnverifiedDevice` case (a call
    has no command argv, so `for_exec_denied` cannot be reused).
  - `AuditLog::append` enforces `0700` dir / `0600` file modes and writes
    newline-delimited JSON; `redact_command` masks secret-bearing argv (not used
    by calls, which carry no command).

**Conventions:** deny-by-default policy; Ed25519-signed privileged requests;
Unix-only; no `unsafe`; MSRV 1.74; document new public APIs; never log secrets.
The audit record for a call carries a *tool name and structured args metadata by
reference only* — the `args` JSON is **not** written to the audit log (only the
tool name), so no redaction is required for calls.

## Proposed Implementation

Mirror the exec path with three small, additive changes.

### 1. Return the `Allowance` from `authorize_live_call`

Change the signature from:

```rust
async fn authorize_live_call(..) -> Result<CallRequest, CallRejection>
```

to:

```rust
async fn authorize_live_call(..) -> Result<(CallRequest, mx_agent_policy::Allowance), CallRejection>
```

The body already binds `(request, allowance)` from
`authorize_call_request_with_allowance`; today it returns only `request`. Return
`Ok((request, allowance))` instead (the verified-device gate logic in between is
unchanged). This gives the audit site the sandbox/allow-rule, exactly as exec's
`authorize_live_exec` does.

### 2. Add `AuditRecord::for_call_denied` to `audit.rs`

The `UnverifiedDevice` denial is a post-policy gate denial with no
policy `Outcome` and no command argv, so neither `for_call` nor `for_exec_denied`
fits. Add a sibling to `for_exec_denied`:

```rust
/// Build an audit record for a named `call` request denied by a gate that
/// runs *after* the policy engine — currently the verified-device gate
/// (issue #240/#257). Mirrors [`AuditRecord::for_exec_denied`] but records the
/// `tool` field instead of a command argv. The decision is always `Denied`, no
/// sandbox is selected (nothing runs), and `policy_rule` is `deny:<deny_reason>`.
pub fn for_call_denied(
    room: &str,
    requester: &str,
    target: &str,
    invocation_id: Option<&str>,
    tool: &str,
    deny_reason: &str,
) -> Self {
    Self {
        ts: now_rfc3339(),
        room: room.to_string(),
        requester: requester.to_string(),
        target: target.to_string(),
        invocation_id: invocation_id.map(str::to_string),
        request: "call",
        command: None,
        tool: Some(tool.to_string()),
        decision: AuditDecision::Denied,
        policy_rule: format!("deny:{deny_reason}"),
        sandbox: None,
    }
}
```

### 3. Audit decisions in `handle_live_call_request`

Add private helpers in `call.rs` mirroring exec's `audit_exec_decision` /
`audit_exec_rejection` / `append_exec_audit`. To avoid duplicating
`append_exec_audit`, **prefer making the existing exec audit-append helper
reusable** rather than copy-pasting:

- Option A (recommended): expose a crate-private `append_audit(paths,
  invocation_id, record)` in `audit.rs` (or reuse `exec::append_exec_audit` by
  making it `pub(crate)` and renaming to `append_audit`) so both paths share the
  one path-resolution + warn-on-error routine. Then add `call`-specific
  `audit_call_decision` / `audit_call_rejection` thin wrappers in `call.rs`.
- Option B: replicate a small `append_call_audit` in `call.rs`. Acceptable but
  duplicates the path-resolution logic; only choose if sharing proves awkward.

The handler's match becomes (target/requester already in scope as `&str`):

```rust
let response = match authorize_live_call(
    &room, paths, &content, request, requesting_agent, &meta.room_id,
).await {
    Ok((authorized, allowance)) => {
        audit_call_decision(
            paths, &meta.room_id, &authorized,
            requesting_agent, target_agent,
            &Outcome::Allow(allowance),
        );
        execute_authorized_call(&authorized)
    }
    Err(rejection) => {
        match &rejection {
            // Policy denials keep their detailed DenyReason.
            CallRejection::PolicyDenied(reason) => audit_call_decision_denied(
                paths, &meta.room_id, request,
                requesting_agent, target_agent,
                &Outcome::Deny(reason.clone()),
            ),
            // Post-policy verified-device gate denial (issue #240).
            CallRejection::UnverifiedDevice => audit_call_rejection(
                paths, &meta.room_id, request,
                requesting_agent, target_agent, &rejection,
            ),
            // Pre-policy auth failures are not attributable to a trusted
            // requester and are intentionally not audited (mirrors exec).
            _ => {}
        }
        rejection_response(request.request_id.clone(), &rejection)
    }
};
```

Notes:

- `target_agent` and `requesting_agent` are already bound as `&str` at the top of
  `handle_live_call_request` (the handler returns early if either is missing), so
  the audit calls do not need the `Option` fields off `CallRequest`.
- Use `request.invocation_id` for the audit `invocation_id` (calls carry one,
  just like exec).
- The allow-path helper takes the **authorized** request (returned from
  `authorize_live_call`); the deny-path helpers take the original `request` (the
  rejection path never produces an authorized request), matching exec.
- Bring `mx_agent_policy::{Outcome}` and `crate::audit::{AuditLog, AuditRecord}`
  into scope in `call.rs` (exec already imports these).

Wrapper helper signatures (in `call.rs`):

```rust
fn audit_call_decision(paths, room_id, request: &CallRequest,
    requester: &str, target: &str, outcome: &Outcome) {
    let record = AuditRecord::for_call(
        room_id, requester, target,
        Some(&request.invocation_id), &request.tool, outcome);
    append_audit(paths, &request.invocation_id, record);
}

fn audit_call_rejection(paths, room_id, request: &CallRequest,
    requester: &str, target: &str, rejection: &CallRejection) {
    let record = AuditRecord::for_call_denied(
        room_id, requester, target,
        Some(&request.invocation_id), &request.tool, &rejection.reason());
    append_audit(paths, &request.invocation_id, record);
}
```

(The `PolicyDenied` case can route through `audit_call_decision` with
`Outcome::Deny(reason)` exactly like exec, so a single allow/deny helper plus the
`for_call_denied` wrapper covers all three audited cases.)

## Affected Files / Crates / Modules

- `crates/mx-agent-daemon/src/call.rs` — change `authorize_live_call` return type;
  add audit calls in `handle_live_call_request`; add `audit_call_*` helpers; add
  imports (`Outcome`, `AuditRecord`, audit-append helper). **(primary)**
- `crates/mx-agent-daemon/src/audit.rs` — add `AuditRecord::for_call_denied`;
  optionally expose a shared `append_audit`. **(primary)**
- `crates/mx-agent-daemon/src/exec.rs` — only if the append helper is shared
  (rename/`pub(crate)` `append_exec_audit` → `append_audit`, update its call
  sites). **(optional, refactor-only)**
- Read-only context: `docs/architecture.md` §13.5/§13.6, `docs/security-hardening.md`.

## CLI / API Changes

None to the CLI. The only public-API change is the **new public method**
`AuditRecord::for_call_denied` on the existing `mx-agent-daemon` `audit` module
(documented with a doc-comment, consistent with `for_exec_denied`). The change to
`authorize_live_call` is to a private (`async fn`, non-`pub`) helper, so it is not
a public-API change. No IPC or wire-protocol surface changes.

## Data Model / Protocol Changes

None. No new `AuditRecord` fields, no change to the JSON line format, the audit
file path, file modes, or any Matrix event schema. The emitted
`com.mxagent.call.response.v1` is unchanged. New audit lines for calls use the
already-defined fields (`request: "call"`, `tool`, `policy_rule`, `sandbox`).

## Security Considerations

- **No secret leakage.** Call audit records carry only the tool *name*, never the
  `args` JSON (which may contain sensitive values). `AuditRecord::for_call` /
  `for_call_denied` do not serialize `args`, so no redaction is needed; confirm in
  a test that args content cannot reach the log.
- **Daemon-only.** All audit logic lives in `mx-agent-daemon`; the CLI and the
  coding agent never see it, consistent with credential isolation.
- **Decision faithfulness.** Audit the decision actually taken: allowed calls
  record the resolved `Allowance`'s sandbox; the `UnverifiedDevice` denial is
  recorded only on the deny branch (the additive gate can only deny). Do not audit
  pre-policy auth failures — they are not attributable to a trusted requester, and
  auditing them would let an unauthenticated sender spam the operator's log.
- **No authority change.** Logging is strictly additive; it must not alter whether
  a call runs. The audit append happens after the decision and its failure is only
  `warn!`-logged (never blocks the response), matching exec.
- **File posture.** Reuse `AuditLog::append`'s existing `0700`/`0600` enforcement;
  do not introduce a second writer with different permissions.
- **Unix-only**, no `unsafe`, MSRV 1.74 — all satisfied by reusing existing code.

## Testing Plan

Unit tests (in `crates/mx-agent-daemon/src/audit.rs` `#[cfg(test)]` and/or
`call.rs`):

- `for_call` allow record: `decision == Allowed`, `request == "call"`,
  `tool` set, `policy_rule == "allow_tools"`, `sandbox == Some("none")` by default
  (and `Some("bubblewrap")` when the allowance selects it). (Extends the existing
  `call_record_uses_tool_field` coverage to the allow side.)
- `for_call` policy-deny record: `decision == Denied`, `policy_rule ==
  "deny:tool_not_allowed"` (and at least one other `DenyReason`), `sandbox` omitted,
  `command` field absent.
- `for_call_denied` (new): `decision == Denied`, `request == "call"`,
  `policy_rule == "deny:unverified_device"`, `tool` set, `sandbox` omitted,
  single-line JSON, and the `args`/secret content never appears.
- Append round-trip: write an allowed call + a denied call via `AuditLog::append`,
  assert one JSON line each, all valid JSON, and no secret/args substring leaks
  (extend the existing `append_writes_one_line_per_record_and_no_secrets`).

Handler-level coverage:

- A pure unit test asserting the **routing** of `CallRejection` variants to audit
  vs no-audit is preferable to a full live-Matrix test. If `handle_live_call_request`
  is hard to unit-test directly (it needs a `Client`/`Room`), factor the
  decision→audit mapping so the *selection* (which variant audits which record) is
  testable without Matrix, mirroring how exec keeps the audit helpers pure over
  `(room_id, request, outcome/rejection)`.
- Confirm pre-policy variants (`Unsigned`, `InvalidSignature`, `UntrustedKey`,
  `Malformed`) produce **no** audit record.

Existing E2E (`crates/mx-agent-daemon/tests/` live call flow, if present) should
continue to pass unchanged; optionally extend a live test to assert an audit line
appears after a successful remote call, but this is not required for acceptance.

Run `cargo test -p mx-agent-daemon` and `cargo clippy -p mx-agent-daemon -- -D warnings`.

## Documentation Updates

- `docs/architecture.md` §13.6: the example shows an `exec` record; add (or note)
  a `call`-shaped example line (`"request": "call"`, `"tool": "run_tests"`,
  `"policy_rule": "allow_tools"`) so the documented schema reflects that calls are
  now audited. Keep it minimal and accurate — do not imply unimplemented behaviour.
- `docs/security-hardening.md`: if it states that the audit log covers privileged
  decisions, ensure it does not still imply calls are unaudited; update the wording
  to include named `call` decisions.
- No README or help-text changes (no CLI surface).

## Risks and Open Questions

- **Shared vs duplicated append helper.** Reusing `exec`'s `append_exec_audit`
  (renamed `append_audit`, made `pub(crate)`) avoids duplication but touches
  `exec.rs`. Duplicating a small `append_call_audit` keeps the change local. Either
  is acceptable; recommend the shared helper for DRYness. **Decision needed at
  implementation time** (low risk).
- **`PolicyDenied` via `for_call` vs a denied helper.** The policy-deny case can
  reuse `AuditRecord::for_call` with `Outcome::Deny(reason)` (exactly as exec
  reuses `for_exec`), so `for_call_denied` is needed *only* for the
  `UnverifiedDevice` (non-`Outcome`) case. Confirm this split rather than adding a
  redundant denied constructor for policy denials.
- **Target field semantics.** For exec, audit `target` is `request.target_agent`
  (the local agent name). For call, use the already-resolved `target_agent` `&str`.
  Confirm this is the agent id the operator expects to see (consistent with exec).
- **No invocation-state record for calls.** Unlike exec, calls do not publish an
  `invocation.v1` state event; the audit `invocation_id` comes straight from
  `request.invocation_id`. Confirm that id is always populated for live calls (it
  is set by `start_call_matrix`/`build_signed_call_request`).
- Testability of `handle_live_call_request` without a live `Client`: may require a
  light refactor to keep the audit-selection logic pure (see Testing Plan).

## Implementation Checklist

1. In `audit.rs`, add `pub fn for_call_denied(room, requester, target,
   invocation_id, tool, deny_reason) -> AuditRecord` mirroring `for_exec_denied`
   (sets `request: "call"`, `command: None`, `tool: Some(...)`, `decision:
   Denied`, `policy_rule: format!("deny:{deny_reason}")`, `sandbox: None`), with a
   doc-comment.
2. (Recommended) Make the audit-append helper shared: rename
   `exec::append_exec_audit` → `append_audit`, make it `pub(crate)` (or move it to
   `audit.rs`), and update exec's call sites. Otherwise add a local
   `append_call_audit` in `call.rs`.
3. In `call.rs`, import `mx_agent_policy::Outcome`, `crate::audit::AuditRecord`,
   and the append helper.
4. Change `authorize_live_call` to return `Result<(CallRequest,
   mx_agent_policy::Allowance), CallRejection>`; return `Ok((request, allowance))`
   (verified-device gate logic unchanged).
5. Add `audit_call_decision(paths, room_id, request, requester, target, outcome)`
   → `AuditRecord::for_call(...)` and `audit_call_rejection(paths, room_id,
   request, requester, target, rejection)` → `AuditRecord::for_call_denied(...)`
   wrappers in `call.rs`.
6. In `handle_live_call_request`, destructure `Ok((authorized, allowance))`; audit
   the allow with `Outcome::Allow(allowance)` before `execute_authorized_call`.
7. On `Err(rejection)`, match: `PolicyDenied(reason)` →
   `audit_call_decision(.., &Outcome::Deny(reason.clone()))`; `UnverifiedDevice` →
   `audit_call_rejection(..)`; all other variants → no audit (`_ => {}`). Then
   build `rejection_response` as before.
8. Add unit tests for `for_call` (allow, with default and explicit sandbox),
   `for_call` policy-deny, and `for_call_denied`, plus an append round-trip with
   no-secret/single-line assertions.
9. Add/extend a test (or pure helper) verifying the rejection→audit routing:
   pre-policy variants produce no record; `PolicyDenied` and `UnverifiedDevice` do.
10. Update `docs/architecture.md` §13.6 (and `docs/security-hardening.md` if
    needed) to show/state that `call` decisions are audited.
11. Run `cargo test -p mx-agent-daemon` and `cargo clippy -p mx-agent-daemon -- -D
    warnings`; ensure no `unsafe`, MSRV-compatible, no secrets logged.
