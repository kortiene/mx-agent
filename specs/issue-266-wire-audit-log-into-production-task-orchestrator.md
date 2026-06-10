# Wire `with_audit_log` into the production task orchestrator so scheduler policy decisions are audited

## Problem Statement

The running daemon never attaches an audit log to the task orchestrator, so
auto-executed task-DAG policy decisions are silently unaudited.
`scheduler_pass_for_agent` builds the only production `TaskOrchestrator` and
chains room_id / policy / trust / replay / keys / approval-gate, but never calls
`.with_audit_log(...)`. Because `audit_policy_decision` returns early when
`audit_log` is `None`
(`crates/mx-agent-daemon/src/task_orchestrator.rs:1217` — `let Some(log) = &self.audit_log else { return Ok(()) };`),
both `Outcome::Allow` and `Outcome::Deny` task-action decisions produce **no**
audit record in production. The `with_audit_log` capability and its unit test
exist, but the builder is dead code on the live path (its only caller is the
unit test at `task_orchestrator.rs:2488`).

This violates the security guarantee from #165 ("policy denial emits audit
log") on the task path, and creates an asymmetry: the direct exec path audits
every privileged decision (allow, policy-deny, and verified-device deny via
`exec.rs:541-573`), while the auto-executed task-DAG path audits nothing. An
operator reviewing the audit log cannot reconstruct what the scheduler
authorized or blocked. The gap is invisible — the code compiles, the unit test
passes, and `audit_policy_decision` silently no-ops.

## Goals

- The production scheduler attaches an audit log to every `TaskOrchestrator` it
  builds, resolving the **same** path the exec/call path uses, so task-action
  decisions and direct exec decisions land in one audit log.
- A policy-allowed task action produces an audit record with
  `"decision":"allowed"`; a policy-denied task action produces a record with
  `"decision":"denied"` — both written from the running daemon, not only from a
  hand-built test orchestrator.
- The wiring is guarded by a regression test that asserts the
  production-configured orchestrator has an audit log attached, so it cannot
  silently regress.
- An audit-write failure on the task path is **logged and swallowed** (matching
  `append_audit`'s contract), never converted into a dispatch-blocking error.

## Non-Goals

- No change to the audit record schema, fields, or `AuditRecord` constructors
  (`for_call`, `for_exec`, `for_exec_denied`).
- No change to audit path-resolution precedence
  (`MX_AGENT_CONFIG_DIR` → `$XDG_CONFIG_HOME/mx-agent` → `$HOME/.config/mx-agent`,
  data-dir fallback).
- No change to policy evaluation, trust verification, replay protection, or the
  approval gate.
- No new CLI commands, flags, or audit-query/inspection tooling.
- No audit coverage for non-policy task outcomes (claim contention, store
  errors, approval-pending) beyond what `audit_policy_decision` already emits for
  Allow/Deny. (Approval-denied/-expired auditing on the task path is out of
  scope; track separately if desired.)

## Relevant Repository Context

- **Crate:** `mx-agent-daemon` owns long-lived Matrix state, policy enforcement,
  crypto, supervision, and all auditing. The CLI is stateless and never sees
  tokens or device keys — no CLI involvement here.
- **`scheduler_loop.rs`** runs the periodic scheduler. `scheduler_pass_for_agent`
  (`crates/mx-agent-daemon/src/scheduler_loop.rs:520-577`) is the only place a
  production `TaskOrchestrator` is constructed and configured. It already
  imports `SessionPaths` (`paths: &SessionPaths`) and has `crate::audit`
  reachable. It builds the orchestrator at lines 548-557 (room_id, policy,
  trust, replay, verifying keys) and the approval gate at 568-577.
- **`task_orchestrator.rs`**:
  - `TaskOrchestrator` struct with `audit_log: Option<AuditLog>` field
    (`:326`), defaulting to `None` (`:340`).
  - `with_audit_log` builder (`:362-365`).
  - `authorize_task_action` (`:1001-1039`) evaluates policy and calls
    `audit_policy_decision` for both Allow and Deny. **Today an audit error is
    turned into `OrchestrationOutcome::StoreError` (`:1026-1032`), which blocks
    dispatch** — this contradicts the "auditing never blocks" contract and must
    change.
  - `audit_policy_decision` (`:1209-1239`) short-circuits on `None`, then builds
    `AuditRecord::for_call` (tool) or `for_exec` (exec) and appends.
  - `replay_cache_handle()` (`:395`) is the existing precedent for a
    `pub`/accessor on the orchestrator usable from another module.
- **`audit.rs`**:
  - `pub const AUDIT_FILE_NAME: &str = "audit.log"` (`:27`).
  - `AuditLog::default_path()` (`:239-250`) and `AuditLog::new(path)` (`:230`).
  - `pub(crate) fn append_audit(paths, invocation_id, record)` (`:290-299`) —
    the canonical "resolve default path, fall back to data dir, log-and-swallow
    on failure" helper, shared by the exec and call receive-side handlers. This
    is the contract the task path must match.
- **`exec.rs`** is the reference implementation of the desired behavior:
  `audit_exec_decision` (`:1575-1590`) audits allow and policy-deny;
  `audit_exec_rejection` (`:1601-1616`) audits the post-policy verified-device
  deny; both delegate to `append_audit`, which logged-and-swallows.
- **Convention:** the daemon audit log file is `0600` in a `0700` parent
  (`audit.rs:257-283`); Unix-only; no `unsafe`; MSRV 1.74.

## Proposed Implementation

Three coordinated changes, all inside `mx-agent-daemon`.

### 1. Attach the audit log in the production builder

In `scheduler_pass_for_agent` (`scheduler_loop.rs`), chain `.with_audit_log(...)`
onto the orchestrator using the same path resolution the exec/call path uses:

```rust
let audit_log = AuditLog::new(
    AuditLog::default_path()
        .unwrap_or_else(|| paths.data_dir.join(crate::audit::AUDIT_FILE_NAME)),
);
let mut orchestrator = TaskOrchestrator::new(agent.agent_id.clone())
    .with_room_id(room_id.to_string())
    .with_policy(policy)
    .with_trust_store(trust)
    .with_audit_log(audit_log);
```

`AuditLog::default_path()` returns `None` only when none of `MX_AGENT_CONFIG_DIR`
/ `XDG_CONFIG_HOME` / `HOME` are set; the data-dir fallback guarantees a path,
so the orchestrator is always audited in production. Add `AuditLog` to the
`use crate::audit::...` import in `scheduler_loop.rs` (or reference it
fully-qualified, mirroring `crate::audit::AUDIT_FILE_NAME`).

To make this testable without a `matrix_sdk::Room`, **extract the orchestrator
construction into a small `pub(crate)` helper** that takes the already-resolved
inputs and returns the configured `TaskOrchestrator`. The approval gate borrows
`orchestrator.replay_cache_handle()`, so the cleanest split is to extract a
builder that produces the orchestrator *with* policy/trust/replay/keys/audit
(everything that does not need the `Room`), then have `scheduler_pass_for_agent`
attach the approval gate and build the `Room`-backed store as it does today. For
example:

```rust
/// Build the production-configured task orchestrator for `agent_id`: the same
/// policy / trust / replay / verifying-key / audit-log wiring the live
/// scheduler uses. Extracted so the audit-log wiring is unit-testable without a
/// live Matrix `Room`. The caller attaches the approval gate (which borrows the
/// returned orchestrator's replay-cache handle).
pub(crate) fn build_scheduler_orchestrator(
    agent_id: String,
    room_id: &str,
    policy: Policy,
    trust: TrustStore,
    replay: Option<ReplayCache>,
    verifying_keys: &BTreeMap<String, VerifyingKey>,
    paths: &SessionPaths,
) -> TaskOrchestrator { /* ... chains the builders incl. with_audit_log ... */ }
```

The production audit-path resolution lives inside this helper so the regression
test exercises the real path logic.

### 2. Add a `pub(crate)` accessor so the wiring is assertable

`audit_log` is a private field and the scheduler test module lives in a
different module than `TaskOrchestrator`. Add a small accessor (documented),
mirroring `replay_cache_handle`:

```rust
/// Path of the audit log this orchestrator records policy decisions to, or
/// `None` if no audit log is attached. Used by the scheduler wiring regression
/// test to assert production auditing is enabled.
pub(crate) fn audit_log_path(&self) -> Option<&std::path::Path> {
    self.audit_log.as_ref().map(AuditLog::path)
}
```

(`AuditLog::path` already exists at `audit.rs:253`.) A simpler
`has_audit_log() -> bool` is acceptable, but returning the path lets the test
also assert it resolved to the expected location.

### 3. Make task-path auditing non-blocking (logged-and-swallowed)

Today `authorize_task_action` (`:1026-1032`) maps an audit error to
`OrchestrationOutcome::StoreError`, turning an audit-write failure into a
dispatch-blocking decision error. Change the task path to match
`append_audit`'s "logged and swallowed" contract:

- Change `audit_policy_decision` to swallow its own write error: keep the
  `None` short-circuit, build the record as today, and on `log.append(&record)`
  failure emit `tracing::warn!(error = %e, invocation_id, task_id, "failed to append task policy audit record")` and return. Return type becomes `()` (or keep `io::Result` but have the caller ignore it — prefer `()` for clarity and to remove the dead error branch).
- Update the call site in `authorize_task_action` to just call
  `self.audit_policy_decision(...)` (no `if let Err(...) { return StoreError }`),
  then proceed to the `match outcome` exactly as today.

This preserves: (a) both Allow and Deny are audited; (b) the policy decision
itself still drives claim/dispatch/block; (c) a flaky/full/permission-denied
audit file can never silently flip an allowed task to a `StoreError` or a denied
task to anything other than `policy_denied`.

> Note: the existing unit test `policy_denies_malicious_tool_before_claim_and_audits`
> (`:2475-2517`) still passes — it asserts the denied record is written, which
> remains true. No existing assertion depends on audit failure becoming a
> `StoreError`.

## Affected Files / Crates / Modules

- `crates/mx-agent-daemon/src/scheduler_loop.rs` — wire `.with_audit_log(...)`
  into `scheduler_pass_for_agent`; add/extract `build_scheduler_orchestrator`
  helper; add `AuditLog` import; new tests in the existing `#[cfg(test)] mod tests`.
- `crates/mx-agent-daemon/src/task_orchestrator.rs` — add `audit_log_path`
  accessor; change `audit_policy_decision` to log-and-swallow; simplify the
  `authorize_task_action` call site; optionally a new behavioral test.
- `crates/mx-agent-daemon/src/audit.rs` — read-only reference
  (`AUDIT_FILE_NAME`, `default_path`, `AuditLog::path`, `append_audit`); no
  change expected.
- `crates/mx-agent-daemon/src/exec.rs` — read-only reference for the contract;
  no change expected.

## CLI / API Changes

None. No command-line, public crate-API, IPC, or Matrix-protocol surface
changes. `build_scheduler_orchestrator` and `audit_log_path` are `pub(crate)`
internal helpers.

## Data Model / Protocol Changes

None. Audit records reuse the existing `AuditRecord::for_call` / `for_exec`
shapes and the existing `audit.log` file format and location. No event-schema,
policy-schema, or serialization changes.

## Security Considerations

- **Closes a security gap (#165 on the task path):** every auto-executed
  task-action policy decision (allow and deny) now leaves an audit trail,
  matching the exec path. This restores the "policy denial emits audit log"
  guarantee for the scheduler.
- **Single audit log:** resolving the path identically to `append_audit` ensures
  task-path and exec-path decisions interleave in one file an operator can
  review; no second, divergent log.
- **File posture preserved:** `AuditLog::append` already enforces `0600`/`0700`
  and re-asserts permissions per append. No new file is introduced and no
  permission logic changes.
- **Auditing must never block dispatch:** the log-and-swallow change guarantees
  an audit-write failure cannot escalate into a `StoreError` that changes the
  authorization outcome. The decision is driven solely by policy; auditing is a
  side effect.
- **No secrets logged:** audit records and the swallow-path `tracing::warn`
  carry only non-sensitive identifiers (room id, agent ids, invocation id, tool
  name / command, decision, deny reason) already emitted elsewhere. No tokens,
  device keys, or `Secret` material. The coding agent path is unaffected.
- **Unix-only:** path resolution and file modes remain Unix-only; no Windows
  assumptions introduced.
- No `unsafe`; MSRV 1.74 respected.

## Testing Plan

All tests in `mx-agent-daemon`; no homeserver or e2e harness required.

1. **Wiring regression test** (`scheduler_loop.rs` tests): call
   `build_scheduler_orchestrator(...)` with representative inputs (an agent id, a
   room id, a loaded policy, default trust, no replay, empty keys, a tempdir
   `SessionPaths`) and assert `orchestrator.audit_log_path().is_some()`.
   Optionally assert the path ends in `audit.log`. This is the guard that fails
   if a future refactor drops `.with_audit_log(...)`.
2. **Behavioral allow test** (driven through the production builder): build the
   orchestrator via `build_scheduler_orchestrator` with a policy that **allows** a
   tool/exec action, point the audit path at a tempdir (set
   `MX_AGENT_CONFIG_DIR` for the test, or assert against the data-dir fallback in
   `SessionPaths`), run `process_one` with a `MemoryStore`, and assert the audit
   file contains `"decision":"allowed"` and the tool/command name.
3. **Behavioral deny test**: same setup with a denying policy (mirror
   `policy_denies_malicious_tool_before_claim_and_audits`), assert the audit file
   contains `"decision":"denied"` and the deny reason — but built from
   `build_scheduler_orchestrator` rather than a hand-rolled `TaskOrchestrator::new(...)`,
   so the test proves the *production* configuration audits.
4. **Non-blocking audit-failure test**: point the audit log at a path that
   cannot be written (e.g. a path whose parent is a file, or a read-only dir),
   evaluate a policy-**allowed** action via `process_one`, and assert the action
   is still authorized/claimed (outcome is not `StoreError`) — proving the
   audit-write failure was swallowed. Use a tempdir so test isolation holds.
5. **Existing tests stay green:** `policy_denies_malicious_tool_before_claim_and_audits`
   and the other `task_orchestrator.rs` policy tests must continue to pass
   unchanged.

Run: `cargo test -p mx-agent-daemon` and `cargo clippy -p mx-agent-daemon --all-targets`.

Test-isolation note: tests that exercise `AuditLog::default_path()` read process
env (`MX_AGENT_CONFIG_DIR` / `XDG_CONFIG_HOME` / `HOME`); set the config-dir env
to a per-test tempdir to avoid touching the developer's real `~/.config/mx-agent`
and to avoid cross-test interference. Prefer asserting via an explicit
tempdir-based path where possible.

## Documentation Updates

- `docs/architecture.md`: in the auditing / task-scheduler section, state that
  the scheduler now audits task-action policy decisions to the same audit log as
  the exec/call path (closing the #165 gap on the task path). Update any wording
  that implies only the direct exec path is audited.
- Doc comments on the new `audit_log_path` accessor and the
  `build_scheduler_orchestrator` helper (rustdoc) per the "document new public
  APIs" rule.
- No README or `--help` changes (no user-facing surface).
- If a v0.2.0 status/feature-completeness table tracks this deviation, mark it
  resolved.

## Risks and Open Questions

- **Refactor shape:** extracting `build_scheduler_orchestrator` is recommended
  for testability, but if the approval-gate / replay-handle coupling makes a
  clean extraction awkward, an acceptable fallback is to keep construction inline
  and write the behavioral tests against a `TaskOrchestrator` configured by a
  shared private helper that performs *only* the audit-path resolution +
  `.with_audit_log(...)`. The hard requirement is that the audit-path logic under
  test is the same code the daemon runs, not a test reimplementation.
- **Return-type change of `audit_policy_decision`:** changing it from
  `io::Result<()>` to `()` is internal-only; confirm no other caller exists
  (currently only `authorize_task_action`).
- **Default-path env coupling in tests:** `AuditLog::default_path()` reads
  process-wide env, which can make parallel tests flaky if they mutate env.
  Prefer constructing the audit log from an explicit tempdir path in behavioral
  tests, reserving `default_path` exercise for a single, env-guarded test.
- **Open question:** should approval-denied / approval-expired task outcomes also
  be audited for full symmetry with "every privileged decision"? This issue
  scopes auditing to policy Allow/Deny (the #165 guarantee). Recommend deferring
  approval-outcome auditing to a follow-up unless reviewers want it included.

## Implementation Checklist

1. In `task_orchestrator.rs`, change `audit_policy_decision` to log-and-swallow
   its append error (`tracing::warn!` with `error`, `invocation_id`, `task_id`)
   and return `()`; keep the `None` short-circuit and both record-builder arms.
2. Simplify the call site in `authorize_task_action`: call
   `self.audit_policy_decision(...)` and drop the `Err(...) => StoreError` branch;
   then `match outcome` as before.
3. Add `pub(crate) fn audit_log_path(&self) -> Option<&std::path::Path>` (rustdoc
   documented) to `TaskOrchestrator`, using `AuditLog::path`.
4. In `scheduler_loop.rs`, add `AuditLog` to the `use crate::audit::...` import.
5. Extract `pub(crate) fn build_scheduler_orchestrator(...)` (rustdoc documented)
   that builds the orchestrator with policy / trust / replay / verifying keys /
   `.with_audit_log(AuditLog::new(AuditLog::default_path().unwrap_or_else(|| paths.data_dir.join(crate::audit::AUDIT_FILE_NAME))))`.
6. Rewrite `scheduler_pass_for_agent` to call `build_scheduler_orchestrator`,
   then attach the approval gate (borrowing `replay_cache_handle()`) and build the
   `Room`-backed store exactly as today.
7. Add the wiring regression test (assert `audit_log_path().is_some()`).
8. Add behavioral allow + deny tests driven through `build_scheduler_orchestrator`
   + `process_one` + `MemoryStore`, asserting `"decision":"allowed"` /
   `"decision":"denied"` in the audit file.
9. Add the non-blocking audit-failure test (unwritable audit path ⇒ allowed
   action still authorized, not `StoreError`).
10. Update `docs/architecture.md` auditing/scheduler section.
11. Run `cargo test -p mx-agent-daemon` and
    `cargo clippy -p mx-agent-daemon --all-targets`; ensure green.
