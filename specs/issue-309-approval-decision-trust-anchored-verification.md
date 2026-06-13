# Approval decisions verify against the local trust store, with an explicit approver allowlist and cache-independent expiry

> GitHub issue #309 — `type:security area:daemon area:security priority:p1`
> Follow-up to epic #274; companions: #301 (workspace room power levels), #305 (replay cache fail-open).

## Problem Statement

Approval decisions are already signed and sender-verified (#264/#285) and the
approval *request* window already fails closed (#265/#291). But the verification
**anchors** are wrong or missing, so the privileged act of releasing a held
`requires_approval` task is not anchored where the rest of the daemon anchors
execution authority (Ed25519 → **local trust store** → deny-by-default policy):

1. **Key anchor is room state, not the trust store.** The scheduler builds
   `verifying_keys` from *every* agent's room-published `com.mxagent.agent.v1`
   state (`scheduler_loop.rs:429-437`) and `verifying_key_from_agent_state` only
   checks that a published key hashes to its own `key_id`
   (`call.rs:400-411`) — pure self-consistency, no trust opinion. The
   `TrustStore` loaded at `scheduler_loop.rs:611` is handed to the task-action
   orchestrator but **never** to decision verification. Combined with writable
   `com.mxagent.*` room state (companion #301), the signature gate degrades to
   "trust whatever key the room published", i.e. room-state trust rather than the
   operator's trust anchor.

2. **No approver identity model.** The only identity allowed to decide is the
   daemon's own Matrix account: `sender.is_empty() || sender != local_user →
   untrusted_sender` (`approval.rs:540-542`). There is no approver
   allowlist/role in `Policy` (`mx-agent-policy/src/file.rs`) or `TrustStore`
   (`trust.rs`), and the CLI `--by` flag is unauthenticated display data flowing
   straight into `approved_by` (`cli.rs:866-873`, `lifecycle.rs:710-723`).

3. **Decision expiry disappears on the cache-less path.** `verification_failure`
   checks `nonce`/`expires_at` for *presence only* (`approval.rs:552-554`). The
   actual clock comparison lives only in `ReplayCache::admit_at`
   (`replay.rs:202-208`), reached via `QueueApprovalGate::admit_decision_nonce`,
   which returns `true` **unconditionally** when no cache is attached
   (`task_orchestrator.rs:1597-1600`). The scheduler attaches
   `ReplayCache::load(paths).ok()`-equivalent (`load_pass_replay_cache`,
   `scheduler_loop.rs:573-585`), so a decision's expiry is only enforced when a
   cache is present. The cache-load fail-closed is companion #305; this issue
   must make decision-expiry hold **even on a cache-less path**, independently of
   #305 landing.

4. **Docs drift.** `docs/architecture.md:1656` shows `mx-agent approval deny
   req_01HZ... --reason 'unsafe command'`, but no `--reason` flag exists
   (`cli.rs:866-873`) so the documented command fails to parse.
   `docs/cli-reference.md` (approve §2387-2392, deny §2443-2448) documents the
   decision JSON as `request_id`/`decision`/`approved_by`/`created_at` only,
   omitting the `nonce`/`expires_at`/`signature` fields decisions have carried
   since #285.

## Goals

- Anchor approval-decision **key** verification to the local `TrustStore`: a key
  that is unknown or revoked locally can never release a held task, even when it
  is published in `com.mxagent.agent.v1` room state. Mirror the exec/call
  receiver pipeline (`signature verify → trust.is_key_trusted → deny-by-default`).
- Introduce an explicit **approver allowlist** consulted by decision
  verification instead of the implicit `sender == local_user` rule, while keeping
  the daemon's own account as the secure default when none is configured.
- Resolve the unauthenticated `--by` flag by **documenting `approved_by` as
  display-only metadata** (verification never reads it) — the approver identity is
  established daemon-side from the Matrix `sender` + Ed25519 signature + trust.
- Add a **cache-independent decision-expiry** check so an expired decision is
  rejected with a distinct, non-sensitive reason even when no replay cache is
  attached, without depending on companion #305.
- Add unit + live Tuwunel coverage for all of the above, including the
  `pending → blocked(approval_expired)` request-window transition (today
  unit-only).
- Fix the documented `approval deny` example and document the decision
  replay/signature fields.

## Non-Goals

- The replay-cache fail-open on load error / corrupt cache, and exec control-frame
  replay checking, are **companion issue #305** — out of scope here. The
  cache-independent expiry check added here must not assume #305 has landed.
- Writable-room-state power-level hardening is **companion issue #301** — out of
  scope. This issue makes the daemon robust *regardless* of who can write room
  state.
- No change to the inline-resume-from-decision behavior for live `exec`/`call`
  holds (still scheduler/task-backed only, per architecture §12).
- No new transport/E2EE behavior; no changes to how decisions are *signed* or
  *emitted* (only how they are *verified* on receipt, plus the `approvers` policy
  field and docs).
- No revocation/trust-publication redesign; reuse the existing `TrustStore`.

## Relevant Repository Context

**Workspace** — Rust Cargo workspace, Unix-only, MSRV 1.74, `unsafe_code =
"forbid"`, `missing_docs = "warn"` (CI `-D warnings`). Crates of interest:
`mx-agent-daemon` (Matrix sync, crypto, policy, scheduler, approval), and
`mx-agent-policy` (the authorization policy engine).

**Approval verification today** (`crates/mx-agent-daemon/src/approval.rs`):

- `read_verified_approval_decisions(room, limit, local_user, verifying_keys)`
  (lines 484-528) scans the timeline newest-first, reads the top-level `sender`
  and the `content` decision, and drops any decision for which
  `verification_failure(...)` returns a reason. Surviving decisions are mapped by
  `request_id` (first/newest verified wins).
- `verification_failure(decision, sender, local_user, verifying_keys)` (lines
  534-556) is the pure, unit-testable gate. Current checks, in order:
  `untrusted_sender` (empty or `!= local_user`) → `missing_signature` →
  `unresolved_key` (key_id not in `verifying_keys`) → `invalid_signature` →
  `missing_replay_material` (nonce/expires_at absence). **No trust-store check,
  no approver allowlist, no clock comparison.**
- `approval_request_expired(expires_at, now_unix)` (lines 613-618) parses RFC 3339
  and compares `<= now_unix`, **failing open on a malformed stamp** (returns
  `false`). `crate::replay::parse_rfc3339_to_unix` is the shared parser.
- `decide_approval_for_session(...)` (lines 675-720) is the emit side: it builds
  the decision, stamps a fresh `nonce` and a `now + APPROVAL_REQUEST_TTL`
  (`3600 s`) `expires_at`, signs with the daemon's own key
  (`load_or_create_signing_key`), emits, and dequeues. `approved_by` is whatever
  the IPC caller passed.

**Scheduler wiring** (`crates/mx-agent-daemon/src/scheduler_loop.rs`):

- `scheduler_pass` (line 381) computes `local_user` (390), loads the approval
  queue (400), computes `approval_expires_at` (403) and `approval_now_unix`
  (407-410) once per pass. Per joined room it reads agent states, builds
  `verifying_keys` from **all** agents (429-437), reads tasks, computes
  `has_runnable_candidate`, and calls `read_verified_approval_decisions`
  (472-478). It then loops owned agents into `scheduler_pass_for_agent`.
- `scheduler_pass_for_agent` (line 589) loads `Policy` (608) and `TrustStore`
  (611) **per agent**, builds the orchestrator via `build_scheduler_orchestrator`
  (539-562, which takes `Policy` + `TrustStore` + `verifying_keys` by value), and
  attaches a `QueueApprovalGate` with `with_now_unix(approval_now_unix)` and the
  shared replay cache.

**The exec/call anchor to mirror** (`crates/mx-agent-daemon/src/exec.rs:396-440`):
`authorize_exec_request_with_allowance` does (1) signature present + valid, (2)
addressed to this agent, (3) **`trust.is_key_trusted(&signature.key_id)` →
`UntrustedKey`**, (4) `policy.evaluate_exec(...)`. `call.rs` and live-control
authorization (`exec.rs:894-916`) use the same `trust.is_key_trusted(key_id)`
anchor. Task-action authorization in the orchestrator already requires
`trust.is_key_trusted(&auth.signature.key_id)` (`task_orchestrator.rs:915-925`,
reason `untrusted_key`) — so **the daemon's own signing key must already be
trusted locally for the live scheduler to run any signed task action**. That is
why anchoring decisions to the trust store *preserves* the daemon-only default:
the same key that signs the daemon's own task actions (and which the operator has
already approved) also signs its self-issued decisions.

**TrustStore** (`crates/mx-agent-daemon/src/trust.rs`): keyed by `(agent_id,
key_id)`. `is_key_trusted(key_id)` returns true iff some entry with that key_id
is `Trusted`; `is_trusted(agent_id, key_id)` is the pair-scoped variant. Unknown
and revoked keys return `false`. This is the same store the exec/call pipeline
consults.

**Policy** (`crates/mx-agent-policy/src/file.rs`): `RoomPolicy` (lines 203-224)
has `trusted`, `raw_exec_default`, `require_verified_device`, and `agents`. Both
`Policy` and `RoomPolicy` use `#[serde(deny_unknown_fields)]` with `#[serde(default)]`
fields, so adding a new `#[serde(default)]` field keeps older policy files
parsing while allowing the new key. `Policy::validate` (line 277) enforces room
ids start with `!` and agent ids start with `@`.

**CLI / IPC** (`cli.rs:866-873`, `cli.rs:3493-3527`, `lifecycle.rs:710-723`):
`approval approve/deny <REQUEST_ID> [--by <IDENTITY>]` → IPC `approval.decide`
with `{request_id, decision, by}` → daemon resolves `approved_by =
by.unwrap_or(session.user_id)` and calls `decide_approval_for_session`. The CLI
is stateless; the daemon owns the Matrix session and signing key.

**Protocol** (`crates/mx-agent-protocol/src/schema.rs:433-458`):
`ApprovalDecision { request_id, decision, approved_by, created_at,
nonce: Option, expires_at: Option, signature: Option<Signature>, extra }`. No
schema change is required — all fields already exist.

**Existing live pattern** (`crates/mx-agent-daemon/tests/matrix_integration.rs`):
`live_scheduler_rejects_forged_approval_decisions` (line 4653) is the template —
it stands up Alice (daemon) + Bob (room member), registers agents, writes a
`requires_approval` policy, trusts the daemon key, creates a held task, waits for
the pending-approval queue entry, publishes a forged decision and asserts the
task stays held + sentinel absent, then approves legitimately via
`decide_approval_for_session` and asserts `succeeded` + sentinel present.

## Proposed Implementation

### 1. Thread a verification context with the trust store, approver set, and `now`

Add a small context struct in `approval.rs` to avoid a long argument list and
keep `verification_failure` pure/unit-testable:

```rust
/// Inputs an approval decision is verified against before it may release a held
/// task (issue #309). All four anchors are checked: an authorized approver
/// identity, an Ed25519 signature from a key that is BOTH room-published and
/// locally trusted, replay material, and a non-expired deadline.
pub struct DecisionVerification<'a> {
    /// The host daemon's own Matrix user id — always an authorized approver.
    pub local_user: &'a str,
    /// Additional Matrix user ids configured to approve in this room. Empty =>
    /// daemon-only (the secure default).
    pub approvers: &'a BTreeSet<String>,
    /// Verifying keys resolved from room-published agent state, keyed by key_id.
    pub verifying_keys: &'a BTreeMap<String, VerifyingKey>,
    /// The authoritative local trust store (mirrors the exec/call anchor).
    pub trust: &'a TrustStore,
    /// "Now" in Unix seconds for the cache-independent expiry check.
    pub now_unix: i64,
}
```

Rewrite `verification_failure` to take `(&ApprovalDecision, sender, &DecisionVerification)`
and apply checks in this fail-closed order (every reason a non-sensitive
`&'static str`):

1. **Authorized approver** — `let ok = !sender.is_empty() && (sender ==
   ctx.local_user || ctx.approvers.contains(sender)); if !ok { return
   Some("untrusted_sender") }`. (Daemon's own account is always allowed; the
   allowlist *adds* approvers. See "Approver-set semantics" below.)
2. `missing_signature` — signature absent.
3. `unresolved_key` — `signature.key_id` not in `verifying_keys`.
4. **`untrusted_key`** *(NEW)* — `!ctx.trust.is_key_trusted(&signature.key_id)`.
   This is the trust-store anchor, mirroring `exec.rs:424`. Place it after
   `unresolved_key` and before signature verification so "not trusted" is a
   distinct, testable reason rather than collapsing into `unresolved_key`.
5. `invalid_signature` — `verify_approval_decision(key, decision).is_err()`.
6. `missing_replay_material` — `nonce` or `expires_at` absent.
7. **expiry** *(NEW)* — parse `expires_at` with
   `crate::replay::parse_rfc3339_to_unix`; `None → Some("malformed_expiry")`
   (fail **closed** — a daemon-signed decision with an unparseable stamp is
   corrupt/tampered, unlike the request-side fail-open in
   `approval_request_expired`); `Some(expiry)` and `expiry <= ctx.now_unix →
   Some("decision_expired")`. The `<=` boundary matches `ReplayCache::admit_at`
   (`replay.rs:206`).

This places the expiry comparison **inside `verification_failure`**, so it runs
on every pass that reads decisions — independent of whether a replay cache is
attached. The cache-backed `admit_decision_nonce` remains as defense-in-depth
(burns the single-use nonce on the releasing pass) but is no longer the sole
expiry enforcer. Do **not** alter the `admit_decision_nonce` cache-less `return
true` branch — it is still correct because expiry is now enforced upstream at
read time; note in its doc comment that decision expiry is enforced by
`verification_failure`.

Update `read_verified_approval_decisions` to accept `&DecisionVerification`
instead of `(local_user, verifying_keys)` and pass it through to
`verification_failure`. Keep its newest-verified-wins mapping unchanged.

### 2. Approver allowlist in policy

Add to `RoomPolicy` (`mx-agent-policy/src/file.rs`):

```rust
/// Matrix user ids authorized to decide approvals in this room, in addition to
/// the daemon's own account (issue #309).
///
/// Empty (the default) preserves the daemon-only behavior: only the host
/// daemon's own Matrix account may release a held `requires_approval` task. A
/// configured approver still must publish a decision Ed25519-signed by a key
/// present in the local trust store; membership here is necessary but never
/// sufficient.
#[serde(default)]
pub approvers: Vec<String>,
```

Validate in `Policy::validate` (per room): each approver is non-empty and starts
with `@` (a Matrix user id), with a precise dotted path
(`rooms.<id>.approvers[<n>]`), mirroring the existing agent-id check.

**Approver-set semantics (recommended): union.** The authorized set for a room
is `{local_user} ∪ room.approvers`. Rationale: the daemon issuing its own
self-signed decision is the secure foundation that must never be removed, and an
operator adding a human approver should not lose the daemon's ability to approve.
This satisfies the acceptance criteria in both directions (a configured approver
can release; an unconfigured sender cannot; no config ⇒ daemon-only). See Open
Questions for the "replace" alternative.

### 3. Wire trust + approvers + now into the scheduler

In `scheduler_pass` (`scheduler_loop.rs`):

- Load `Policy` and `TrustStore` **once per pass** near the top (they are the
  same files every agent reads today at `scheduler_pass_for_agent:608/611`); pass
  them down to `scheduler_pass_for_agent` to remove the per-agent re-reads (purely
  a refactor — same files, same deny-by-default fallbacks
  `Policy::default()`/`TrustStore::default()`).
- Per room, compute the approver set: `let mut approvers: BTreeSet<String> =
  policy.rooms.get(&room_id).map(|r| r.approvers.iter().cloned().collect())
  .unwrap_or_default();` (the union with `local_user` is applied inside
  `verification_failure` via the `local_user` field, so the set holds only the
  *extra* approvers).
- Build `DecisionVerification { local_user: &local_user, approvers: &approvers,
  verifying_keys: &verifying_keys, trust: &trust, now_unix: approval_now_unix }`
  and pass it to `read_verified_approval_decisions`.

`build_scheduler_orchestrator` and the per-agent gate wiring are unchanged except
for receiving the already-loaded `policy`/`trust` by reference and cloning into
the orchestrator (matching its existing by-value `with_policy`/`with_trust_store`
API).

> Note: `verifying_keys` is still built from agent state (it is the *key
> material*, resolved by `verifying_key_from_agent_state`); the trust check in
> `verification_failure` is the *authority*. Optionally, as belt-and-suspenders,
> the build loop at `scheduler_loop.rs:429-437` may additionally skip keys that
> are not `trust.is_key_trusted(...)`, but the authoritative gate is the
> `untrusted_key` check so the distinct reason survives for tests — do not rely on
> map-filtering alone.

### 4. `--by` / `approved_by` → documented display-only

No verification code reads `approved_by` (verification uses the Matrix `sender` +
signature + trust). Resolve the unauthenticated-`--by` concern by **documentation
only**: state in `docs/cli-reference.md` and `docs/architecture.md` that
`approved_by` (and the `--by` flag) is **display-only metadata** recorded in the
event for human/audit context and is **not** an authentication input — the
authoritative approver identity is the Matrix `sender` whose decision is
Ed25519-signed by a locally-trusted key and matched against the room's approver
set. No CLI/IPC behavior change. (See Open Questions for the optional hardening of
binding `approved_by` to the verified sender.)

### 5. Documentation fixes

- `docs/architecture.md:1656`: change `mx-agent approval deny req_01HZ...
  --reason 'unsafe command'` to `mx-agent approval deny req_01HZ...` (drop the
  non-existent flag).
- `docs/architecture.md` §12 (Approval Workflow): add a short paragraph that
  decision verification anchors to the local trust store + approver allowlist +
  unexpired deadline (cache-independent), and that `approved_by` is display-only.
- `docs/cli-reference.md` approve (§2387-2392) and deny (§2443-2448): add
  `nonce`, `expires_at`, and `signature` to the JSON field lists; add the
  display-only note for `--by`/`approved_by`; document the new
  `[rooms."!id".approvers]` policy field (here and/or in the policy/security
  sections).

## Affected Files / Crates / Modules

**Modify:**

- `crates/mx-agent-daemon/src/approval.rs` — add `DecisionVerification`; rewrite
  `verification_failure` (new `untrusted_key`, `decision_expired`,
  `malformed_expiry` reasons; approver-set sender check); update
  `read_verified_approval_decisions` signature; update/extend `#[cfg(test)]`.
- `crates/mx-agent-daemon/src/scheduler_loop.rs` — load policy/trust once per
  pass; compute per-room approver set; build `DecisionVerification`; pass it to
  `read_verified_approval_decisions`; thread policy/trust into
  `scheduler_pass_for_agent`.
- `crates/mx-agent-policy/src/file.rs` — add `RoomPolicy::approvers`; validate;
  unit tests.
- `crates/mx-agent-daemon/src/task_orchestrator.rs` — doc-comment touch on
  `admit_decision_nonce` (expiry now enforced in `verification_failure`); confirm
  existing `approval_expired` transition tests still hold; optionally a unit test
  proving an expired/untrusted decision never reaches the gate.
- `crates/mx-agent-daemon/tests/matrix_integration.rs` — new live tests (below).
- `docs/architecture.md`, `docs/cli-reference.md` — doc fixes.

**Read for reference (not necessarily modified):**

- `crates/mx-agent-daemon/src/exec.rs` (anchor pattern), `src/call.rs`
  (`verifying_key_from_agent_state`), `src/trust.rs`, `src/replay.rs`
  (`parse_rfc3339_to_unix`, `admit_at`), `crates/mx-agent-protocol/src/schema.rs`
  (`ApprovalDecision`), `crates/mx-agent-cli/src/cli.rs` /
  `src/lifecycle.rs` (`approval.decide`).

## CLI / API Changes

- **No new CLI flags.** `approval approve/deny` keep `<REQUEST_ID> [--by]`. `--by`
  is documented as display-only.
- **Public Rust API (within `mx-agent-daemon`):** new `DecisionVerification<'a>`
  struct (documented, `missing_docs` clean); changed signatures of the `pub`
  `verification_failure` and `read_verified_approval_decisions` (both internal to
  the daemon crate / its tests — update all callers). All new public items need
  doc comments.

## Data Model / Protocol Changes

- **Policy:** new optional `RoomPolicy.approvers: Vec<String>` (TOML
  `[rooms."!id"].approvers = ["@alice:server"]`). Backward compatible: defaults to
  empty, old policy files parse unchanged (still `deny_unknown_fields`-safe
  because the field now exists with `#[serde(default)]`).
- **Event schema:** none. `ApprovalDecision` already carries
  `nonce`/`expires_at`/`signature` (since #285); this issue only documents them.
- **Persistence:** none (trust store, approval queue, replay cache formats
  unchanged).

## Security Considerations

- **Trust anchor (primary fix):** releasing a held task now requires the
  decision's signing key to be `Trusted` in the **local** `TrustStore`, not merely
  self-consistent in room state. Room membership / room-state write access (cf.
  #301) can no longer satisfy the approval gate. This matches the exec/call/task
  receiver invariant exactly.
- **Daemon-only default preserved:** with no `approvers` configured, only
  `sender == local_user` is authorized, and the daemon's own key must be trusted
  locally — it is the key that signs the daemon's own task actions and its
  self-issued decisions (`load_or_create_signing_key`). No new default-open
  surface. **Caveat (see Open Questions #8):** a deployment that only trusted
  *remote planner* keys (and never the local daemon key) would have its
  self-issued decisions rejected with the new `untrusted_key` reason; the
  implementation must guarantee the local key is trusted before this lands.
- **Approver allowlist is necessary-not-sufficient:** an allowlisted sender still
  must present an Ed25519 signature from a locally-trusted key; the allowlist
  cannot grant execution by itself.
- **Expiry fails closed without a cache:** the clock check moves into
  `verification_failure`, so it holds on the cache-less path and does not depend
  on companion #305. Malformed decision expiry stamps fail **closed**.
- **CLI never owns credentials:** approver identity is established daemon-side
  from the Matrix `sender` + signature + trust; `approved_by`/`--by` is non-authoritative
  display metadata. No tokens or device keys cross the IPC boundary.
- **No secrets in logs:** rejection logging keeps the existing posture — only
  `sender`, `request_id`, and the non-sensitive reason are logged; never the
  signature, nonce, key bytes, or content. The new reasons
  (`untrusted_key`, `decision_expired`, `malformed_expiry`) are `&'static str`.
- **Unix-only; no `unsafe`; MSRV 1.74.** `BTreeSet`/`BTreeMap` and existing
  helpers only; no new deps.

## Testing Plan

**Unit — `approval.rs` `verification_failure` (update existing + add):**

- Migrate the ~10 existing tests (lines 1142-1329) to the `DecisionVerification`
  context (supply a trust store that trusts `VF_KEY_ID`, an empty `approvers`
  set, and a `now_unix` before the test's `expires_at`).
- **Positive:** valid signed decision from `local_user`, trusted key, fresh
  deadline ⇒ `None`.
- **`untrusted_key`:** key present in `verifying_keys` but absent from / revoked
  in the trust store ⇒ `Some("untrusted_key")` — even with a valid signature and
  correct sender. (Directly covers the headline acceptance criterion.)
- **Approver allowlist — positive:** `sender = "@approver:server"` (≠
  local_user) in `approvers`, trusted key, valid signature ⇒ `None`.
- **Approver allowlist — negative:** `sender = "@stranger:server"` not in
  `approvers` and ≠ local_user ⇒ `Some("untrusted_sender")`.
- **Default preserved:** empty `approvers`, `sender == local_user` ⇒ passes;
  `sender != local_user` ⇒ `untrusted_sender`.
- **`decision_expired`:** valid+trusted+signed decision whose `expires_at <=
  now_unix` ⇒ `Some("decision_expired")` (this is the cache-less expiry proof).
- **`malformed_expiry`:** `expires_at = "garbage"` ⇒ `Some("malformed_expiry")`
  (fail closed).
- Boundary: `expires_at == now_unix` ⇒ expired.

**Unit — `mx-agent-policy/src/file.rs`:**

- Parse `[rooms."!r:s"].approvers = ["@a:s", "@b:s"]` ⇒ field populated.
- Default empty when omitted; old files unchanged.
- `validate()` rejects an approver not starting with `@` with the dotted path.

**Unit — `task_orchestrator.rs`:**

- Confirm existing `approval_required_*` and `Expired ⇒ blocked(approval_expired)`
  tests (lines 1920-1958, 1984-2009) still pass unchanged.
- (Optional) a gate-level test showing that when `read_verified_approval_decisions`
  has already dropped an expired/untrusted decision, the gate resolves `None`
  (Pending), never `Approved`.

**Live Tuwunel — `matrix_integration.rs` (model on
`live_scheduler_rejects_forged_approval_decisions`):**

1. **Untrusted key never releases (acceptance):** hold a `requires_approval`
   task; publish a decision from the daemon's own `sender` but signed by a second
   Ed25519 key that is published in some agent's `com.mxagent.agent.v1` state (so
   it resolves in `verifying_keys`) yet is **absent from the local trust store** ⇒
   task stays held, sentinel absent. Then issue a legitimately signed decision
   (daemon's trusted key) ⇒ released, sentinel present.
2. **Configured approver, both directions (acceptance):** add `approvers =
   ["@bob:server"]` to `policy.toml`; trust Bob's signing key; Bob (a separate
   account/daemon) publishes a decision signed by his trusted key ⇒ released.
   Control: a non-allowlisted, non-daemon sender's decision (even validly signed)
   ⇒ not released.
3. **Expired decision never releases (acceptance):** publish a decision signed by
   the daemon's trusted key with `expires_at` in the past (and a fresh nonce) ⇒
   task stays held (`decision_expired`); a subsequent in-window decision releases
   it.
4. **Request window lapses to `blocked` (acceptance):** pre-seed `approvals.json`
   with a `PendingApproval` for `approval:<task_id>` whose `request.expires_at` is
   in the past (the gate reads the *persisted* deadline at
   `task_orchestrator.rs:1539-1544`), start the scheduler over a held
   `requires_approval` task ⇒ task transitions to `blocked` with result reason
   `approval_expired`, sentinel never created. (No production env knob needed.)

**Gate checks:** `cargo fmt --check`, `cargo clippy --all-targets --all-features
-- -D warnings`, `cargo build --all`, `cargo test --all`, and the
`#[ignore]`d live suite via `scripts/matrix_integration_test.sh`.

## Documentation Updates

- `docs/architecture.md`: fix the `approval deny --reason` example (§12); add the
  trust-anchor + approver-allowlist + cache-independent-expiry note and the
  `approved_by` display-only note to §12; ensure the decision-event example
  (already showing nonce/expires_at/signature at lines 1676-1689) stays consistent.
- `docs/cli-reference.md`: add `nonce`/`expires_at`/`signature` to the approve and
  deny JSON field lists; add the `--by`/`approved_by` display-only note; document
  the `approvers` room-policy field (policy/security section).
- `docs/security-hardening.md`: a sentence on configuring `approvers` and the
  "necessary-not-sufficient + trusted key required" rule, if the threat-model
  section warrants it.
- README/CONTRIBUTING status table: not strictly required (this hardens an
  already-"Implemented" capability); optionally tighten the security-posture
  bullet to mention approval decisions verify against the local trust store. Do
  **not** imply unimplemented behavior.
- No new public CLI surface ⇒ no `clap` help/man regeneration beyond doc text.

## Risks and Open Questions

1. **Approver-set semantics — union vs replace.** Recommended: **union**
   (`{local_user} ∪ approvers`) so the daemon can always self-approve. The issue
   text ("instead of the implicit `sender == local_user` rule") could be read as
   *replace*. Replace would let an operator configure an approver set that
   excludes the daemon — more flexible but riskier and a behavior change for the
   daemon's own flow. **Confirm union.**
2. **Where the allowlist lives.** Recommended: `RoomPolicy.approvers` (approval is
   a room-scoped privileged action; the scheduler already loads policy per room).
   Alternative: a `TrustStore`/trust-config role. **Confirm policy placement.**
3. **`--by` resolution.** Recommended: document `approved_by` as display-only (no
   code change; verification already ignores it). Optional hardening: have the
   emitting daemon force `approved_by = session.user_id` and treat `--by` as a
   separate free-text annotation, or deprecate `--by`. **Confirm doc-only is
   acceptable.**
4. **Reason naming.** New reasons `untrusted_key` (matches exec/call),
   `decision_expired` (distinct from the request-side `approval_expired`), and
   `malformed_expiry`. **Confirm names** — they appear in logs/tests.
5. **Malformed decision expiry fails closed**, diverging from
   `approval_request_expired`'s fail-open (which is about the *request* staying
   operator-decidable). A daemon-signed decision with an unparseable stamp is
   corrupt/tampered, so closed is correct here. **Confirm.**
6. **Key trust by key_id vs (agent_id, key_id).** Use `is_key_trusted(key_id)` to
   mirror the exec/call/task receiver anchor (the verifier has no reliable
   `agent_id` for the decision signer). Acceptable given the existing pipeline
   uses the same.
7. **Live-test account topology.** Test 2 needs a second trusted daemon/account
   (Bob) signing with a key trusted by Alice's store — reuse the requester-key
   trust the forged-decision test already sets up. Confirm the Tuwunel two-user
   harness supports publishing Bob's agent state with his signing key so it lands
   in `verifying_keys`.
8. **Local daemon key must be trusted (load-bearing for the daemon-only
   default).** The claim that "the daemon's own key is already trusted because it
   signs task actions" holds only when the daemon *authored* the held action.
   In a cross-daemon topology (planner Daemon B signs the action with key `K_B`,
   running Daemon A holds + approves it), A's store trusts `K_B` to run the
   action, but A signs the *decision* with its own `K_A`
   (`decide_approval_for_session` → `load_or_create_signing_key`), which A's store
   need not contain. There is **no runtime self-trust today** — every
   `trust.approve(...)` in the daemon is test-only (grep confirms; `trust.rs`
   exposes `approve` but nothing calls it at runtime for the local key). So once
   the `untrusted_key` anchor lands, a self-issued decision is rejected unless
   `K_A` is `Trusted` locally. **Decision required, pick one:**
   (a) document a required bootstrap — the operator runs `mx-agent trust approve`
   on the local fingerprint as part of daemon setup (lowest code change; verify
   the existing `trust approve` CLI/IPC can target the local key), or
   (b) self-seed the local signing key as `Trusted` on agent registration /
   daemon startup, honoring an explicit prior `Revoked` record (so revocation
   still takes effect and the seed is not re-applied over a revocation). Option
   (b) is more robust for fresh deployments; option (a) keeps trust fully
   operator-driven. The live tests must trust the local key explicitly regardless
   (the forged-decision template already does via `trust.approve(REQUESTER_AGENT,
   &key_id, …)`), so this gap is invisible to the suite — it is a *production
   bootstrap* concern that must be resolved in docs and/or code, not only tests.

## Implementation Checklist

1. **Policy crate:** add `RoomPolicy.approvers: Vec<String>` (`#[serde(default)]`,
   documented); validate each entry starts with `@` in `Policy::validate` with a
   dotted path; add parse + validation unit tests.
2. **approval.rs:** add the documented `DecisionVerification<'a>` struct.
3. **approval.rs:** rewrite `verification_failure` to take
   `(&ApprovalDecision, &str, &DecisionVerification)` and apply the 7 ordered
   checks, adding `untrusted_key`, `decision_expired`, and `malformed_expiry`
   (parse via `crate::replay::parse_rfc3339_to_unix`, `<=` boundary, fail closed
   on malformed). Update the doc comment.
4. **approval.rs:** update `read_verified_approval_decisions` to take and forward
   `&DecisionVerification`; keep newest-verified-wins mapping and the
   non-sensitive rejection logging.
5. **scheduler_loop.rs:** load `Policy` + `TrustStore` once per pass; per room
   compute the extra-approver `BTreeSet`; construct `DecisionVerification` (with
   `approval_now_unix`) and pass it to `read_verified_approval_decisions`; thread
   the shared policy/trust into `scheduler_pass_for_agent` (drop the per-agent
   re-reads).
6. **Local-key trust bootstrap (resolve Open Questions #8 before shipping):**
   guarantee the daemon's own signing key is `Trusted` locally so self-issued
   decisions survive the new `untrusted_key` anchor — either (a) document the
   `mx-agent trust approve <local fingerprint>` setup step, or (b) self-seed the
   local key as trusted on registration/startup (honoring an explicit prior
   `Revoked` record). Add a regression test for whichever path is chosen.
7. **task_orchestrator.rs:** update the `admit_decision_nonce` doc comment to note
   expiry is enforced in `verification_failure`; leave the cache-less `return
   true` branch intact; (optional) add the gate-sees-`None`-for-dropped-decision
   test.
8. **Unit tests:** migrate + extend the `verification_failure` suite (positive,
   `untrusted_key`, approver positive/negative, default preserved,
   `decision_expired`, `malformed_expiry`, boundary).
9. **Live tests:** add the four `#[ignore]`d Tuwunel tests (untrusted-key,
   configured-approver both directions, expired-decision, request-window-lapse via
   pre-seeded queue).
10. **Docs:** fix `architecture.md` `--reason` example; add the §12 trust/approver/
    expiry + `approved_by` notes; add `nonce`/`expires_at`/`signature` and the
    display-only note to `cli-reference.md` approve/deny; document the `approvers`
    policy field.
11. **Gates:** `cargo fmt --check`; `cargo clippy --all-targets --all-features --
    -D warnings`; `cargo build --all`; `cargo test --all`; run the live suite via
    `scripts/matrix_integration_test.sh` and confirm green.
