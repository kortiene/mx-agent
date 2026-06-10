# Sign and Sender-Verify Approval Decisions (issue #264)

## Problem Statement

The approval-release step accepts `com.mxagent.approval.decision.v1` events with
**no sender verification, no signature, and no replay protection**. The live
scheduler's `read_approval_decisions` (`crates/mx-agent-daemon/src/approval.rs:345`)
parses only the event `type` and `content` and keys decisions by `request_id`;
`decision_permits_spawn` (`approval.rs:320`) returns `true` for any
`decision == "approved"`. The scheduler maps those into
`HashMap<request_id, bool>` (`scheduler_loop.rs:461`) and the
`QueueApprovalGate` releases the held task on `Some(true)`
(`task_orchestrator.rs:1343`).

Because the `request_id` is derived deterministically as `approval:<task_id>`
(`task_orchestrator.rs:1268`) and is visible to every room member, **any room
member** — including a compromised or newly-joined member — can publish an
`approved` decision for a held `requires_approval` task and cause the host
daemon's scheduler to claim and dispatch it.

This violates the project's core invariant that **room membership is NOT
execution permission** (architecture §1.2, §13). The human-in-the-loop approval
gate — the last line of defense for high-risk (networked / unsandboxed) execs —
can be satisfied by a non-approver.

Scoped honestly: the underlying action is still re-verified (signature → trust →
replay → deny-by-default policy) at claim/dispatch time, so an *unauthorized*
action cannot be smuggled through this path. The defect is specifically the loss
of the human-in-the-loop control over an **already-authorized-but-deliberately-held**
action, which `priority:p1` reflects.

There is also no replay protection: a single stale `approved` event living within
the `APPROVAL_DECISIONS_SCAN_LIMIT` (100-event) window re-approves the request on
every scheduler pass.

## Goals

- Bind every honored approval decision to a **verifiable approver identity** so a
  decision from an untrusted/unexpected sender (or one without a valid signature)
  can never release a held task.
- Verify the decision event's Matrix `sender` against the host daemon's own user
  id (`local_user`, already in scope at `scheduler_loop.rs:390`) and/or a
  configured trusted-approver set, **before** the decision is mapped into the
  release set.
- Add an Ed25519 `Signature` to `ApprovalDecision`, sign decisions when they are
  emitted, and verify the signature against a locally-trusted signing key before
  `decision_permits_spawn` is honored — mirroring the existing signed task-action
  / exec-request pattern.
- Add a `nonce` to `ApprovalDecision` and replay-protect it (mirror the existing
  `ReplayCache` usage in the task path) so a stale `approved` event in the scan
  window cannot re-release a task.
- Preserve the existing approve→execute end-to-end behavior from #223: a decision
  from the legitimate approver (correct sender / valid signature) still releases
  the held task.
- Keep the change **additive and fail-closed**: rejection only ever *denies* a
  release; it never grants one. Default behaviour for a correctly-emitted decision
  is unchanged.

## Non-Goals

- Changing the *policy* decision of whether a task `requires_approval` (that is
  unchanged — this is about who may satisfy the gate, not when it is raised).
- Re-architecting the approval **queue** persistence or the operator CLI surface
  (`mx-agent approval list/show/approve/deny`); their behaviour is preserved.
- Multi-approver quorum / m-of-n approvals, approval delegation, or threshold
  signatures. A single trusted approver remains sufficient.
- Encrypting approval decisions or making them E2EE-only (transport confidentiality
  is governed separately, architecture §1.2).
- Re-verifying the underlying exec/tool action here — that stays the
  responsibility of the claim/dispatch pipeline (signature → trust → replay →
  policy), which is already enforced.
- Windows support (Unix only) and any change to MSRV/`unsafe` posture.

## Relevant Repository Context

**Crates touched.** `mx-agent-protocol` (event schema + signing helpers) and
`mx-agent-daemon` (decision emit/read, scheduler wiring, orchestrator gate).

**The approval flow today.**

1. The orchestrator marks a `requires_approval` task held; `QueueApprovalGate`
   (`task_orchestrator.rs:1293`) enqueues a `PendingApproval` and returns
   `ApprovalDisposition::Pending`.
2. The operator runs `mx-agent approval approve <req>` → IPC `approval.decide`
   (`lifecycle.rs:704`) → `decide_approval_for_session` (`approval.rs:465`) builds
   an `ApprovalDecision` via `approval_decision_for` (`approval.rs:299`), emits it
   with `emit_approval_decision` (`approval.rs:325`), and removes the queue entry.
   The decider identity (`approved_by`) defaults to the daemon's own
   `session.user_id`.
3. Each scheduler pass, `scheduler_pass` (`scheduler_loop.rs:381`) calls
   `read_approval_decisions` (only when a runnable candidate exists), maps each
   `ApprovalDecision` through `decision_permits_spawn` into
   `HashMap<request_id, bool>`, and wires it into the gate via
   `move |request_id| decisions.get(request_id).copied()` (`scheduler_loop.rs:559`).
4. On `Some(true)` the gate releases the task; the orchestrator then *separately*
   verifies the signed `TaskActionAuthorization` (`verify_task_action_authorization`,
   `task_orchestrator.rs:829`) and consumes the task-action replay nonce
   (`admit_task_action_replay`, `task_orchestrator.rs:902`) before claiming.

**Existing patterns to mirror.**

- **Detached Ed25519 signatures over canonical JSON.** `mx-agent-protocol::signing`
  (`signing.rs`): `sign`, `sign_into`, `verify`, `verify_signature`, `signing_bytes`
  (excludes the top-level `signature` field), `ALG_ED25519`. Privileged events
  (`ExecRequest`, `CallRequest`) carry a `Signature` in content and are verified
  against a resolved `VerifyingKey`.
- **Task-action signing value.** `task_action_signing_value` /
  `verify_task_action_signature` / `sign_task_action`
  (`task_orchestrator.rs:1185-1253`) sign a synthesized JSON object binding the
  semantic fields (not the raw struct), and verify with
  `signing::verify_signature` over `canonical_json::to_canonical_bytes`.
- **Replay/expiry.** `ReplayCache::admit(nonce, expires_at)` /
  `admit_at(.., now)` (`replay.rs:143`), `ReplayError` variants
  (`Expired`/`Replayed`/`MalformedTimestamp`/`Io`). The task path admits the nonce
  only on the pass that actually executes (so a held-for-approval task is not
  falsely replay-rejected when it resumes — see
  `approval_held_task_is_not_replay_blocked_when_it_resumes`).
- **Verifying-key resolution.** The scheduler already builds
  `verifying_keys: BTreeMap<key_id, VerifyingKey>` from published agent states
  (`scheduler_loop.rs:422-430`, via `call::verifying_key_from_agent_state`) and
  loads the per-agent `TrustStore` (`scheduler_loop.rs:531`). `local_user` (the
  daemon's own Matrix user id) is at `scheduler_loop.rs:390`.
- **Daemon signing identity.** `load_or_create_signing_key(&paths)`
  (`crate::signing`, used in `call.rs:517`, `exec_ipc.rs:342`, etc.) returns the
  daemon's `DaemonSigningKey`; `.signing_key()` yields the `ed25519_dalek::SigningKey`
  and the key id is `mxagent-ed25519:<sha256-b64>`.
- **Sender access in `read_approval_decisions`.** The loop already holds
  `event.raw()` and reads top-level fields via
  `raw.get_field::<String>("type")`. The Matrix event's top-level `sender` is
  reachable the same way (`raw.get_field::<String>("sender")`), independent of
  the (attacker-controlled) `content`.

**Conventions.** Unix-only; `unsafe_code = forbid`; MSRV 1.74; `missing_docs`
warns (so every new public item needs a doc comment); human-readable output by
default with `--json` for automation; never log secrets — log only non-sensitive
metadata (event type, room, sender, request_id, reason). Forward-compatible
structs keep `#[serde(flatten)] pub extra: Extra`.

## Proposed Implementation

Apply **both** binding mechanisms the issue suggests — they are complementary and
match the project's defense-in-depth ethos:

1. **Mandatory sender check** (cheap, no key material needed): a decision is only
   eligible if its Matrix `sender` equals the host daemon's `local_user` or is in
   a configured trusted-approver set.
2. **Signature + nonce binding** (cryptographic + replay): the decision carries an
   Ed25519 signature from a locally-trusted signing key and a single-use nonce.

Both are *additive denials*: a decision that fails either check is dropped before
it can release a task. A correctly self-emitted decision (the daemon signs with
its own key and is its own sender) passes both, preserving #223.

### 1. Protocol: extend `ApprovalDecision` (`mx-agent-protocol/src/schema.rs:422`)

Add two **optional** fields so existing/older events still deserialize
(forward-compatible) while the verifier enforces presence:

```rust
pub struct ApprovalDecision {
    pub request_id: String,
    pub decision: String,
    pub approved_by: String,
    pub created_at: String,
    /// Single-use nonce binding this decision for replay protection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    /// Detached Ed25519 signature over the decision's canonical bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<Signature>,
    #[serde(flatten)]
    pub extra: Extra,
}
```

Notes:
- `Option<_>` keeps the field *deserializable* for any event (so a hostile or
  legacy event never fails to parse and silently bypasses logging) but the
  scheduler treats `None` as **not verifiable → rejected** when enforcement is on.
- Add an `expires_at: Option<String>` only if a bounded decision lifetime is
  wanted for the replay-cache `admit` call. Recommended: reuse the approval
  *request* expiry semantics by stamping `expires_at` on the decision (the
  operator decides within the request's lifetime). If omitted, `ReplayCache`
  needs a non-expiring admit path — see Risks. **Recommendation: add
  `expires_at`** so the existing `admit(nonce, expires_at)` API is reused verbatim.

### 2. Protocol: signing value for a decision (`mx-agent-protocol/src/signing.rs` or a new helper in `approval.rs`)

Mirror `task_action_signing_value`: sign a synthesized object over the *semantic*
fields, excluding the `signature` field. Simplest and consistent with
`ExecRequest`/`CallRequest`: sign the canonical JSON of the decision content with
the top-level `signature` field removed (exactly what `signing::sign`/`verify`
already do for content objects). Implement:

```rust
/// Sign an `ApprovalDecision` in place with the daemon's key.
pub fn sign_approval_decision(
    signing_key: &SigningKey,
    key_id: impl Into<String>,
    decision: &mut ApprovalDecision,
) -> Result<(), SignatureError>;

/// Verify an `ApprovalDecision`'s embedded signature against a verifying key.
pub fn verify_approval_decision(
    verifying_key: &VerifyingKey,
    decision: &ApprovalDecision,
) -> Result<(), SignatureError>;
```

Implementation: serialize the decision to `serde_json::Value`, route through the
existing `signing::sign_into` / `signing::verify` (which already strip the
`signature` field via `signing_bytes`). This reuses the audited path and the
known-answer-test discipline. The `nonce` and `expires_at` are part of the signed
bytes, so they cannot be swapped.

### 3. Daemon: sign decisions on emit (`approval.rs`)

- `approval_decision_for` (`approval.rs:299`): generate a fresh random `nonce`
  (use the same RNG source the exec/call/task signers use for nonces) and stamp
  `expires_at`. Keep it pure where possible by passing `nonce`/`expires_at` in
  from the caller (the wall clock and RNG are read by
  `decide_approval_for_session`, matching how `created_at` is already injected).
- `decide_approval_for_session` (`approval.rs:465`): after building the decision,
  load the daemon signing key (`load_or_create_signing_key(paths)`) and call
  `sign_approval_decision` before `emit_approval_decision`. The decider remains
  `approved_by = session.user_id` and the **emitting Matrix user is the daemon's
  own user**, so the sender check passes for self-issued decisions.

### 4. Daemon: verify on read (`approval.rs` + `scheduler_loop.rs`)

Tighten `read_approval_decisions` (or add a `read_verified_approval_decisions`
variant that the scheduler uses) so a decision is admitted into the returned map
**only if**:

1. **Sender check** — `raw.get_field::<String>("sender")` equals `local_user`
   (passed in) or is contained in an optional configured trusted-approver set.
   Reject otherwise (log non-sensitive `reason = "untrusted_sender"`).
2. **Signature check** — `decision.signature` is `Some`, its `key_id` is trusted
   in the `TrustStore`, the verifying key resolves (the daemon's own key is in
   `verifying_keys` from its published agent state — ensure the operator trusts
   their own signing key; see Risks), and `verify_approval_decision` succeeds.
   Reject otherwise (`reason = "missing_signature"` / `"untrusted_key"` /
   `"unresolved_key"` / `"invalid_signature"`).

Pass `local_user`, the `verifying_keys` map, and the `TrustStore` into the read
helper (they already exist in `scheduler_pass`). Keep logging to non-sensitive
metadata only.

**Replay protection.** Consume the decision `nonce` through the per-pass
`ReplayCache` **at the moment the gate transitions a held task to released**, not
when the decision is merely read. Re-use the existing late-consumption discipline:
the scheduler already consumes the task-action replay nonce right before the claim
(`admit_task_action_replay`). Add the decision-nonce admit alongside it (or as a
new `admit_approval_decision_replay` step gated on an approving disposition), so:
- a legitimately-held task whose `approved` decision is read on several passes is
  not falsely replay-rejected — the nonce burns only on the pass that actually
  releases+claims;
- once consumed, a stale duplicate-nonce `approved` event in the scan window is
  rejected (`ReplayError::Replayed`) and cannot re-release the task on a later
  pass.

Because `decision_permits_spawn` is the boolean the gate sees, keep the
read/verify layer responsible for *eligibility* and let the existing
`decision_permits_spawn` continue to enforce *fail-closed `approved`-only*
semantics on the surviving, verified decisions.

### 5. Gate wiring (`scheduler_loop.rs:553-560`, `task_orchestrator.rs:1340`)

No semantic change to `QueueApprovalGate::evaluate` is required: it already maps
`Some(true) → Approved`, `Some(false) → Denied`, `None → Pending`. The map it
reads is now built only from **verified** decisions, so an unverified `approved`
decision presents as `None` (still pending) rather than `Some(true)`. This keeps
the gate fail-closed and the held task `pending` for an unverified/forged
approval — exactly the required negative-test behaviour. Ensure the
replay-rejected case also resolves to `None` (pending) rather than a hard error.

### Ordering / fail-closed summary

For a held `requires_approval` task to release, **all** must hold:
sender ∈ {local_user, trusted approvers} → decision carries a valid signature
from a locally-trusted key → nonce is fresh (not expired/replayed) →
`decision == "approved"`. Any failure leaves the task `pending` (or `Denied` for
an explicit, verified `denied`). None of these can *grant* a release that the
operator did not actually sign.

## Affected Files / Crates / Modules

Read:
- `crates/mx-agent-daemon/src/approval.rs` — emit/read/decide, `decision_permits_spawn`.
- `crates/mx-agent-daemon/src/scheduler_loop.rs` — `scheduler_pass`,
  `scheduler_pass_for_agent`, `local_user`, `verifying_keys`, gate wiring,
  `APPROVAL_DECISIONS_SCAN_LIMIT`.
- `crates/mx-agent-daemon/src/task_orchestrator.rs` — `QueueApprovalGate`,
  `task_approval_request`, `verify_task_action_authorization`,
  `admit_task_action_replay`, `task_action_signing_value`,
  `verify_task_action_signature`.
- `crates/mx-agent-protocol/src/schema.rs` — `ApprovalDecision`, `Signature`.
- `crates/mx-agent-protocol/src/signing.rs` — `sign`/`verify`/`signing_bytes`.
- `crates/mx-agent-daemon/src/replay.rs` — `ReplayCache`, `ReplayError`.
- `crates/mx-agent-daemon/src/signing.rs` — `load_or_create_signing_key`.
- `crates/mx-agent-daemon/src/lifecycle.rs:704` — `approval.decide` handler.

Modify (likely):
- `crates/mx-agent-protocol/src/schema.rs` — add `nonce`, `signature`
  (`Option`), optional `expires_at` to `ApprovalDecision`.
- `crates/mx-agent-protocol/src/signing.rs` (or `approval.rs`) — add
  `sign_approval_decision` / `verify_approval_decision`.
- `crates/mx-agent-daemon/src/approval.rs` — generate nonce/expiry + sign in
  `approval_decision_for` / `decide_approval_for_session`; verify sender +
  signature in `read_approval_decisions` (or a new verified variant).
- `crates/mx-agent-daemon/src/scheduler_loop.rs` — pass `local_user`,
  `verifying_keys`, `TrustStore`, and the replay cache into the verified read;
  consume decision nonce on the releasing pass.
- `crates/mx-agent-daemon/src/lib.rs` — re-export any new public helpers.
- Possibly `crates/mx-agent-policy` / config — optional `trusted_approvers` set
  (see Open Questions; can default to "self only" with no config surface).

## CLI / API Changes

- **CLI:** none. `mx-agent approval approve/deny/list/show` keep their flags and
  human / `--json` output. The decision the daemon emits simply now carries
  `signature`/`nonce` fields internally.
- **IPC:** `approval.decide` params (`ApprovalDecideParams`) and the
  `ApprovalDecisionRecord` result shape are unchanged. The `ApprovalDecision`
  embedded in the record gains optional fields (additive; existing JSON clients
  ignore unknown/optional fields).

## Data Model / Protocol Changes

- `com.mxagent.approval.decision.v1` content gains:
  - `nonce` (`Option<String>`) — single-use replay nonce.
  - `signature` (`Option<Signature>`) — detached Ed25519 signature over the
    decision's canonical bytes (signature field excluded), matching
    `ExecRequest`/`CallRequest`.
  - `expires_at` (`Option<String>`, recommended) — RFC 3339 UTC bound for the
    replay-cache admit.
- Fields are additive and optional at the serde layer (older events still
  deserialize) but **required by the verifier** before a decision can release a
  task. Document the new fields in the schema doc comments (`missing_docs`).
- Replay-cache persistence: decision nonces are admitted into the existing
  on-disk `ReplayCache` (no new store).

## Security Considerations

- **Closes the privilege-escalation path.** After this change a decision from any
  sender other than the trusted approver, or without a valid signature from a
  locally-trusted signing key, cannot release a held task — restoring "room
  membership ≠ execution permission" for the approval gate (architecture §1.2).
- **Two independent gates, both additive denials.** Sender-equality is a cheap
  transport-level signal; the Ed25519 signature + local trust store is the
  authoritative execution-level binding (consistent with §1.2's transport-vs-
  execution split). Neither can *grant* a release; they only deny forged ones.
- **Replay.** Late nonce consumption (only on the releasing pass) preserves the
  approve-then-resume flow while preventing a stale `approved` event in the
  100-event scan window from re-releasing a task. Mirrors the audited task-action
  replay discipline.
- **Fail-closed everywhere.** Missing/`None` signature, unparseable signature,
  untrusted/unresolved key, wrong sender, expired/replayed nonce, and any
  non-`approved` value all leave the task `pending` (or explicitly `Denied`).
- **No secret exposure.** Signing uses the daemon-owned key via
  `load_or_create_signing_key`; the coding agent never sees it. Logs carry only
  non-sensitive metadata (event type, room, sender, request_id, reason) — never
  signatures, nonces, or content.
- **Self-trust requirement.** The daemon must be able to resolve and trust *its
  own* signing key to verify self-issued decisions. Confirm the operator's own
  signing key is present in the room's agent state (it is, for an owned agent) and
  trusted in the local `TrustStore`; if self-trust is not implicit, either
  special-case `sender == local_user` to bypass the trust-store lookup (sender
  check already proves provenance) or document that the operator must
  `trust approve` their own key. **Recommendation:** treat a valid signature whose
  `sender == local_user` as sufficient even if the key is not explicitly in the
  trust store, since the sender check already establishes provenance; require
  trust-store membership only for *other* configured approvers.
- **Unix-only**; no `unsafe`; MSRV 1.74 preserved.

## Testing Plan

Daemon unit tests (`approval.rs`, `task_orchestrator.rs`, `scheduler_loop.rs`):

- **Negative (forged sender):** a `decision: "approved"` whose Matrix `sender` is
  a non-approver room member is dropped by the verified read; the gate sees `None`
  and the held task stays `pending` / `ApprovalDisposition::Pending`.
- **Negative (missing signature):** an `approved` decision from the correct sender
  but with `signature: None` is rejected (`missing_signature`); task stays held.
- **Negative (invalid signature / untrusted key):** an `approved` decision signed
  by a non-trusted key, or whose signature fails verification, is rejected;
  task stays held.
- **Negative (replay):** a verified `approved` decision releases the task once;
  a duplicate-nonce `approved` event re-seen on a subsequent pass is rejected
  (`ReplayError::Replayed`) and does not re-release.
- **Positive (legitimate approver):** a decision emitted by the daemon (correct
  sender, signed with its own key, fresh nonce) releases the held task →
  `ApprovalDisposition::Approved` → claim/dispatch, preserving #223.
- **Held-task-not-falsely-replayed:** an `approved` decision read across several
  passes while the task is still held does not burn the nonce until the releasing
  pass (mirror `approval_held_task_is_not_replay_blocked_when_it_resumes`).
- **Explicit deny still denies:** a verified `denied` decision yields
  `ApprovalDisposition::Denied` (reason `approval_denied`).

Protocol unit tests (`schema.rs`, `signing.rs`):

- `sign_approval_decision` → `verify_approval_decision` round-trips; a tampered
  field (`decision`, `request_id`, `nonce`, `expires_at`) fails verification.
- A known-answer test vector for a fixed key + decision (guards the canonical
  form), following the existing `known_answer_test_vector` style.
- `ApprovalDecision` with no `signature`/`nonce` still deserializes
  (forward-compat) but `verify_approval_decision` reports `MissingSignature`.

E2E / integration (extend the #223 approve→execute scenario):

- The existing live approve→execute path stays green (daemon-emitted, signed
  decision releases and runs the task).
- A decision published by a *second* room member (different Matrix user) does not
  release the held task; the task remains `pending` and no invocation is spawned.

Run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`,
`cargo test --all`.

## Documentation Updates

- `docs/architecture.md` §12 (Approval Workflow): update the decision event JSON
  to include `nonce` and `signature`, and state that decisions are
  sender-verified against the host daemon's user / trusted approvers and
  signature-verified against the local trust store, with replay protection — i.e.
  room membership does not let a non-approver release a held task.
- `docs/architecture.md` §7.1 / §9.2: note the decision event now carries a
  signature + nonce like other privileged events; the approval gate's release is
  authority-checked.
- README "Security posture" / status table: optionally note that approval
  decisions are signed and sender-verified (only if it does not overstate beyond
  what ships).
- Wiki Security-and-Sandboxing / approval docs: mirror the §12 change.
- Help text: unchanged (no CLI surface change).

## Risks and Open Questions

- **Self-trust of the daemon's own signing key.** Verifying a self-issued
  decision requires resolving/trusting the daemon's own key. Decision:
  treat `sender == local_user` + valid signature as sufficient (sender proves
  provenance), and require trust-store membership only for additional configured
  approvers. Confirm with maintainers.
- **`expires_at` on the decision vs. non-expiring replay admit.** Reusing
  `ReplayCache::admit(nonce, expires_at)` is cleanest if the decision carries an
  `expires_at`. Alternative: a non-expiring admit variant. Recommendation: add
  `expires_at` (stamped within the approval request's lifetime).
- **Trusted-approver configuration surface.** MVP can hardcode "self only"
  (`sender == local_user`) with no config. A configurable
  `trusted_approvers` set (policy or config) is a natural extension; decide
  whether to ship it now or defer. Defaulting to self-only is safe and unblocks
  the fix.
- **Backward compatibility with in-flight unsigned decisions.** Any decision
  emitted before this change is unsigned and will be rejected after upgrade. This
  is the intended fail-closed behaviour; a held task simply needs to be
  re-approved. Note in release docs.
- **Nonce-consumption point.** Consuming the decision nonce too early (at read)
  would break the legitimate multi-pass hold; it must burn only on the releasing
  pass, alongside the task-action nonce. Verify the ordering matches
  `admit_task_action_replay`'s late-consumption guarantee.
- **`read_approval_decisions` signature change.** Adding `local_user` /
  `verifying_keys` / trust / replay parameters changes the function signature;
  prefer a new `read_verified_approval_decisions` to keep the pure reader testable
  and avoid churn in unrelated callers.

## Implementation Checklist

1. **Schema:** add `nonce: Option<String>`, `signature: Option<Signature>`, and
   `expires_at: Option<String>` to `ApprovalDecision` (`schema.rs:422`) with serde
   defaults + doc comments.
2. **Signing helpers:** add `sign_approval_decision` / `verify_approval_decision`
   (route through `signing::sign_into` / `signing::verify`), with unit tests and a
   known-answer vector.
3. **Emit side:** in `approval_decision_for` accept a `nonce`/`expires_at`; in
   `decide_approval_for_session` generate a fresh nonce + expiry, load the daemon
   signing key, sign the decision, then emit.
4. **Read/verify side:** add `read_verified_approval_decisions(room, limit,
   local_user, verifying_keys, trust)` that drops any decision failing the sender
   check or signature check, logging only non-sensitive metadata.
5. **Scheduler wiring:** call the verified reader from `scheduler_pass`, passing
   `local_user`, `verifying_keys`, and the `TrustStore`; keep the map as
   `HashMap<request_id, bool>` of `decision_permits_spawn` over surviving
   decisions.
6. **Replay:** consume the decision nonce in the orchestrator on the releasing
   pass (alongside `admit_task_action_replay`), resolving a replayed/expired nonce
   to `None`/pending (fail-closed), not a hard error.
7. **Re-exports:** surface new public items from `lib.rs` as needed.
8. **Docs:** update architecture §12 (and §7.1/§9.2), README/wiki as listed.
9. **Tests:** add the negative (forged sender / missing-sig / invalid-sig /
   replay) and positive (legitimate approver) daemon tests, the protocol
   round-trip/tamper/KAT tests, and extend the #223 E2E with a second-member
   negative case.
10. **Gates:** run `cargo fmt --check`,
    `cargo clippy --all-targets --all-features -- -D warnings`, `cargo test --all`.
