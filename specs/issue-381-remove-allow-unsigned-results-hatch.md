# Remove the `MX_AGENT_ALLOW_UNSIGNED_RESULTS` fail-open escape hatch

> Spec for GitHub issue #381 — `security: remove or feature-gate
> MX_AGENT_ALLOW_UNSIGNED_RESULTS before first stable release`.
> Labels: `type:security` `area:protocol` `area:security` `priority:p2`.
> Follow-up to #348 (signed result plane, shipped) and #304 (sender-pin, shipped).

## Problem Statement

The result-plane signature verification shipped in #348 carries a documented,
default-off escape hatch: the `MX_AGENT_ALLOW_UNSIGNED_RESULTS` environment
variable. When set to `1`, a **missing** Ed25519 signature on a result-plane
event (`exec.finished` / `exec.rejected` / `exec.cancelled` / `stream.chunk` /
`stream.artifact` / `call.response`) is downgraded from a fail-closed drop to a
logged-accept. It was introduced solely to ease a mixed-fleet upgrade window —
when some executors had not yet been upgraded to sign their results — and its own
doc comment (`crates/mx-agent-daemon/src/result_verify.rs:28-31`) and the
architecture note (`docs/architecture.md:124`) both slate it for removal at the
first stable release.

The hatch is not a critical hole (it is off by default, downgrades **only** a
missing signature, never an invalid/wrong-key/untrusted/key-id-mismatched one,
and runs in series with the sender-pin from #304, and every downgrade is logged
one-per-event at `warn`). The concern is leaving a fail-open knob in a stable
release: an operator can set it "temporarily" for a rollout and never unset it,
silently weakening the result-plane defense long after the mixed-fleet window has
closed. A compromised/hostile homeserver (or any room member who can already pass
the sender-pin) could then deliver unsigned `exec.finished` / `call.response` /
`stream.*` output and have the caller accept it.

This issue asks to retire the temporary rollout knob before the first stable
release — nothing more. The verification itself is already shipped and correct;
this is **not** a re-implementation of #348.

## Goals

- A stable build cannot downgrade a missing result-plane signature to a
  logged-accept via environment alone. A missing signature on a Matrix-delivered
  result is **always** fail-closed (dropped + logged).
- Remove the `MX_AGENT_ALLOW_UNSIGNED_RESULTS` environment override surface
  entirely (the preferred path in the issue), along with the dead code it leaves
  behind: the `ALLOW_UNSIGNED_RESULTS_ENV` constant, the `allow_unsigned_results()`
  env reader, the `VerifyOutcome::AcceptedUnsigned` variant, and the two
  per-event "accepting an UNSIGNED …" downgrade log branches.
- Preserve every other shipped behavior of the #348 result-plane verifier exactly:
  invalid / wrong-key / untrusted-key / key-id-mismatch signatures are still
  always rejected; the trust and key-id re-checks still apply on the verified
  path; the sender-pin from #304 still runs in series.
- Keep the existing fail-closed unit tests passing
  (`missing_signature_rejected_by_default`, the tampered/other-key/untrusted/
  key-id-mismatch rejections), and remove the now-meaningless downgrade test.
- Update the docs that describe the hatch (`docs/architecture.md`,
  `docs/cli-reference.md`) so they no longer advertise an environment override
  that does not exist.

## Non-Goals

- Re-implementing or changing the #348 signing/verification policy itself
  (canonical JSON, detached `signature`, key-id cross-check, trust re-check,
  sender-pin series). Those are correct and stay as-is.
- Changing the loopback / local-IPC result path (unsigned by design — no
  untrusted hop, no separate identity to verify).
- Introducing the workspace's first Cargo feature flag. Option 2 in the issue
  (gate behind a non-default `allow-unsigned-results` Cargo feature) is recorded
  below as a documented alternative, but it is **not** the recommended path
  because the workspace currently has zero Cargo features and the mixed-fleet
  window the hatch served has closed — keeping any compile-time path to a
  fail-open knob still ships a fail-open knob. Full removal is cleaner and
  matches the issue's stated preference.
- Touching unrelated env-var plumbing (the #375 remote-env-override allowlist,
  the `SECRET_VARS` child-exec denylist). `MX_AGENT_ALLOW_UNSIGNED_RESULTS` is a
  daemon-read knob and appears in none of those lists (verified by repo-wide
  grep), so nothing there needs editing.

## Relevant Repository Context

**Crate ownership.** All affected code lives in `crates/mx-agent-daemon` (the
long-lived daemon that owns Matrix state, crypto, policy, and supervision). The
stateless CLI is not involved; it never sees Matrix tokens or device keys, and
this change does not alter the daemon/CLI boundary.

**The verifier (`crates/mx-agent-daemon/src/result_verify.rs`).** Centralizes the
result-plane verification policy so both result-plane consumers apply the
identical rule:

- `ALLOW_UNSIGNED_RESULTS_ENV` (line 32) — the env-var name constant.
- `allow_unsigned_results()` (lines 69-73) — reads the env (`v == "1"`, defaults
  `false` when unset/other).
- `VerifyOutcome` (lines 76-84) — two variants: `Verified` and `AcceptedUnsigned`.
- `verify_result_signature<T>()` (lines 106-112) — public entry; delegates to
  `verify_result_signature_with_policy(..., allow_unsigned_results())`.
- `verify_result_signature_with_policy<T>(..., allow_unsigned: bool)`
  (lines 118-166) — the deterministic policy: resolve key → verify signature →
  key-id cross-check → trust re-check. The downgrade is taken **only** for
  `SignatureError::MissingSignature` **and only** when `allow_unsigned`
  (lines 132-137); `Err(_) => return Err(ResultVerifyError::Invalid)` (line 138)
  rejects every invalid/wrong-key/non-canonical signature regardless of the flag.
- `ResultVerifyError` (lines 38-66) — stable, non-sensitive reason labels;
  `Unsigned` (`"unsigned"`) is the missing-signature rejection reason and is
  **retained** (a missing signature is still a rejection, just now unconditional).
- Tests (lines 179-351) — `verified_when_signed_keyid_matches_and_trusted`,
  `missing_signature_rejected_by_default`,
  `missing_signature_downgraded_only_when_override_on`,
  `tampered_result_rejected_even_with_override`, `signed_by_other_key_rejected`,
  `untrusted_key_rejected`, `keyid_mismatch_rejected`. All call
  `verify_result_signature_with_policy(..., <bool>)` directly.

**The two consumers.**

- Exec/stream path — `crate::sync::publish_forwarded`
  (`crates/mx-agent-daemon/src/sync.rs:611-673`). Calls
  `verify_forwarded_event` (lines 697-732, returns
  `Result<VerifyOutcome, ResultVerifyError>`) and matches three arms:
  `Ok(Verified) => {}`, `Ok(AcceptedUnsigned) => warn!` (the downgrade log,
  lines 636-644), `Err(err) => warn!("dropping …"); return` (lines 645-655).
- `call.response` path — `crate::call::verify_call_response_signature`
  (`crates/mx-agent-daemon/src/call.rs:697-734`). Matches `Ok(Verified) => Ok(())`,
  `Ok(AcceptedUnsigned) => warn!; Ok(())` (the second downgrade log, lines
  724-731), `Err(err) => Err(err.reason())`.

`VerifyOutcome` is referenced only in these three files (confirmed by grep); no
other module pattern-matches it.

**Convention reference.** The issue cites the `MX_AGENT_REQUIRE_BWRAP` /
`execution.require_sandbox` "explicit-gate" convention. Note that
`require_sandbox` is a **policy/config** gate (a `policy.toml` field), and
`MX_AGENT_REQUIRE_BWRAP` is a **test-only** env var read in
`crates/mx-agent-sandbox/src/lib.rs:949`; neither is a Cargo build feature. The
workspace has **no** `[features]` tables anywhere (confirmed by grep over all
`Cargo.toml`), so the issue's option 2 would introduce the first one — another
reason to prefer full removal.

**Docs that mention the hatch** (grep-confirmed, only two):

- `docs/architecture.md:122-126` — §1 result-plane description: "The lone escape
  hatch `MX_AGENT_ALLOW_UNSIGNED_RESULTS=1` (default off) downgrades only a
  *missing* signature … the hatch is removable at the first stable release."
- `docs/cli-reference.md:3081` — the `MX_AGENT_ALLOW_UNSIGNED_RESULTS` bullet in
  the "User-facing (affect behavior)" environment-variable list.

`docs/security-hardening.md`, the wiki, `README.md`, and the `doc_drift.rs` test
do **not** reference this env var (grep-confirmed), so they need no edits.

**Integration test that touches the constant.**
`crates/mx-agent-daemon/tests/matrix_integration.rs` —
`live_result_plane_unsigned_or_misigned_is_rejected` (`#[ignore]`d, live
homeserver) clears the env at line 8329 via
`std::env::remove_var(mx_agent_daemon::result_verify::ALLOW_UNSIGNED_RESULTS_ENV)`
and references the override in its doc comments (lines 8286-8287, 8307-8309,
8536). The `remove_var` call references the about-to-be-removed `pub const` and
**will not compile** once the constant is deleted.

**Historical spec.** `specs/issue-348-sign-result-plane.md` documents the hatch
as the record of what shipped in #348. It is a historical artifact and should be
left as-is (do not retro-edit shipped specs); the new behavior is captured by this
spec instead.

## Proposed Implementation

Recommended path: **Option 1 — remove the hatch entirely** (the issue's preferred
option). Collapse the verifier to a single, always-fail-closed entry point.

### 1. `crates/mx-agent-daemon/src/result_verify.rs`

1. **Delete** the `ALLOW_UNSIGNED_RESULTS_ENV` constant and its doc comment
   (lines 28-32) and the `allow_unsigned_results()` function (lines 68-73).
2. **Delete** the `VerifyOutcome` enum (lines 75-84) entirely. With the downgrade
   gone there is exactly one success state, so the function's success type becomes
   `()`.
3. **Collapse** `verify_result_signature` and `verify_result_signature_with_policy`
   into one public function:

   ```rust
   pub fn verify_result_signature<T: serde::Serialize>(
       event: &T,
       agent_state: &AgentState,
       trust: &TrustStore,
   ) -> Result<(), ResultVerifyError> {
       let verifying_key = verifying_key_from_agent_state(agent_state)
           .map_err(|_| ResultVerifyError::UnresolvableKey)?;

       match signing::verify_signed(&verifying_key, event) {
           Ok(()) => {}
           Err(SignatureError::MissingSignature) => return Err(ResultVerifyError::Unsigned),
           Err(_) => return Err(ResultVerifyError::Invalid),
       }

       let key_id = embedded_key_id(event).ok_or(ResultVerifyError::Invalid)?;
       if key_id != agent_state.signing_key_id {
           return Err(ResultVerifyError::KeyIdMismatch);
       }
       if !trust.is_key_trusted(&key_id) {
           return Err(ResultVerifyError::UntrustedKey);
       }
       Ok(())
   }
   ```

   Keep the existing detailed doc comment (steps 1–4), but **remove** the
   paragraph describing the `ALLOW_UNSIGNED_RESULTS_ENV` downgrade; replace it
   with a sentence stating a missing signature is now always rejected
   (`ResultVerifyError::Unsigned`). The `Err(_) => Invalid` line and the trust /
   key-id re-checks are unchanged.
4. **Update** the module-level doc comment (lines 11-19): drop the
   "single removable escape hatch … downgrades only a *missing* signature"
   sentence; keep the "fails closed on the Matrix transport" framing.
5. **Keep** `ResultVerifyError` unchanged — including the `Unsigned` variant and
   its `"unsigned"` reason label (a missing signature is still a rejection).
6. **Tests** (`mod tests`):
   - `verified_when_signed_keyid_matches_and_trusted`: change the call to
     `verify_result_signature(&signed_finished(&k), &agent_state(&k), &trusted_store(&k))`
     and expect `Ok(())`.
   - `missing_signature_rejected_by_default`: change the call to drop the `false`
     arg; still expect `Err(ResultVerifyError::Unsigned)`.
   - `missing_signature_downgraded_only_when_override_on`: **delete** (the
     downgrade no longer exists).
   - `tampered_result_rejected_even_with_override`: **rename** to
     `tampered_result_rejected`, drop the `true` arg and the "override never
     downgrades" comment; still expect `Err(ResultVerifyError::Invalid)`. (See
     Risks: the issue's acceptance lists the old name under "still pass" — the
     behavior is preserved; only the now-vacuous "even with override" framing and
     argument are dropped.)
   - `signed_by_other_key_rejected`, `untrusted_key_rejected`,
     `keyid_mismatch_rejected`: drop the trailing `false` arg from each call;
     expectations unchanged.

### 2. `crates/mx-agent-daemon/src/sync.rs`

1. `verify_forwarded_event` (lines 697-732): change the return type from
   `Result<crate::result_verify::VerifyOutcome, ResultVerifyError>` to
   `Result<(), ResultVerifyError>`. The match body already returns
   `verify_result_signature(...)` directly, which now yields `Result<(), _>` — no
   body change needed. Update its doc comment (lines 688-696) to drop the
   "with the `MX_AGENT_ALLOW_UNSIGNED_RESULTS` override applying only to a missing
   signature" clause.
2. `publish_forwarded` (lines 634-656): collapse the three-arm match to two:

   ```rust
   match verify_forwarded_event(client, paths, meta, &event).await {
       Ok(()) => {}
       Err(err) => {
           tracing::warn!(
               event_type = %meta.event_type,
               room = %meta.room_id,
               sender = %meta.sender,
               invocation_id = %forwarded_correlation_id(&event),
               reason = err.reason(),
               "dropping result-plane event with an unverified signature"
           );
           return;
       }
   }
   ```

   Delete the `Ok(VerifyOutcome::AcceptedUnsigned) => warn!(…)` arm (lines
   636-644) and remove the now-unused `crate::result_verify::VerifyOutcome` path.

### 3. `crates/mx-agent-daemon/src/call.rs`

1. `verify_call_response_signature` (lines 697-734): drop `VerifyOutcome` from the
   `use` on line 702 and collapse the match (lines 722-733) to:

   ```rust
   verify_result_signature(&response, &agent_state, &trust).map_err(|err| err.reason())
   ```

   Delete the `Ok(VerifyOutcome::AcceptedUnsigned) => { warn!(…); Ok(()) }` branch
   (lines 724-731). Update the doc comment (lines 687-696) to drop the
   "the `MX_AGENT_ALLOW_UNSIGNED_RESULTS` override applies only to a *missing*
   signature" clause.

### 4. `crates/mx-agent-daemon/tests/matrix_integration.rs`

1. Delete the `std::env::remove_var(... ALLOW_UNSIGNED_RESULTS_ENV)` call (line
   8329) and its two-line preceding comment (lines 8327-8328) — the override no
   longer exists, so the test's missing-signature forge is now rejected
   unconditionally.
2. Update the doc comments that reference the override (lines 8286-8287,
   8307-8309, 8536) to state the missing-signature forge is **always** rejected
   (`Unsigned`), with no env override in play. The test's three cases (positive /
   unsigned-forge-dropped / wrong-key-forge-dropped) and their assertions are
   otherwise unchanged.

### 5. Documentation

1. `docs/architecture.md:122-126`: rewrite the result-plane paragraph to end at
   the fail-closed guarantee. Replace the two "lone escape hatch …" sentences with
   a single sentence such as: "A missing, invalid, wrong-key, or untrusted-key
   signature is always dropped and the consumer's wait times out (no environment
   override; #381 retired the mixed-fleet rollout hatch)." Keep the loopback/local
   note that follows.
2. `docs/cli-reference.md:3081`: delete the `MX_AGENT_ALLOW_UNSIGNED_RESULTS`
   bullet from the "User-facing (affect behavior)" list. Leave the surrounding
   bullets intact.

### Alternative (Option 2, not recommended) — Cargo feature gate

If the maintainers prefer to keep a compile-time path for an unusual rollout, add
a non-default `allow-unsigned-results` feature to
`crates/mx-agent-daemon/Cargo.toml` and wrap `allow_unsigned_results()` /
`VerifyOutcome::AcceptedUnsigned` / both downgrade log branches in
`#[cfg(feature = "allow-unsigned-results")]`, with the env read returning `false`
(or being absent) when the feature is off. This requires adding a CI build that
exercises the feature, keeps `VerifyOutcome` and the env constant alive, and
introduces the workspace's first Cargo feature. Because stable release artifacts
build without the feature, the env var still cannot weaken them — but the
maintenance surface is larger and a fail-open path still exists in the codebase.
**Prefer Option 1** unless a concrete future-rollout requirement is identified.

## Affected Files / Crates / Modules

| File | Change |
| --- | --- |
| `crates/mx-agent-daemon/src/result_verify.rs` | Remove env const, env reader, `VerifyOutcome` enum, the downgrade branch; collapse two fns into one `verify_result_signature` returning `Result<(), ResultVerifyError>`; update module + fn docs; adjust/delete tests. |
| `crates/mx-agent-daemon/src/sync.rs` | `verify_forwarded_event` return type → `Result<(), …>`; collapse `publish_forwarded` match to two arms; drop `AcceptedUnsigned` log; update docs. |
| `crates/mx-agent-daemon/src/call.rs` | `verify_call_response_signature`: drop `VerifyOutcome` import + `AcceptedUnsigned` log branch; collapse to `.map_err(|e| e.reason())`; update docs. |
| `crates/mx-agent-daemon/tests/matrix_integration.rs` | Remove the `remove_var(ALLOW_UNSIGNED_RESULTS_ENV)` call + comment; update doc comments. |
| `docs/architecture.md` | §1 result-plane paragraph: drop the escape-hatch sentences. |
| `docs/cli-reference.md` | Remove the `MX_AGENT_ALLOW_UNSIGNED_RESULTS` env-var bullet. |

Read-only context (no change expected): `crates/mx-agent-protocol/src/signing.rs`
(provides `verify_signed` / `SignatureError::MissingSignature`),
`crates/mx-agent-daemon/src/trust.rs` (`TrustStore::is_key_trusted`),
`crates/mx-agent-cli/tests/doc_drift.rs` (does not reference this env var),
`specs/issue-348-sign-result-plane.md` (historical, leave as-is).

## CLI / API Changes

- **Environment surface:** `MX_AGENT_ALLOW_UNSIGNED_RESULTS` is removed. Setting
  it has no effect after this change (a missing result-plane signature is always
  rejected). This is the intended, documented removal.
- **Public Rust API (`mx-agent-daemon` crate):** `pub const
  ALLOW_UNSIGNED_RESULTS_ENV` and `pub enum VerifyOutcome` are deleted;
  `pub fn verify_result_signature` changes its return type from
  `Result<VerifyOutcome, ResultVerifyError>` to `Result<(), ResultVerifyError>`.
  These are internal-to-workspace items (the daemon crate is not a published
  library API); the only in-repo consumers are `sync.rs`, `call.rs`, and the
  integration test, all updated here. Document the surviving `verify_result_signature`
  with its new always-fail-closed contract (the `missing_docs = "warn"` workspace
  lint requires doc comments on public items).
- **CLI commands / IPC / protocol wire format:** none. The result-plane event
  schema, signing, and IPC methods are unchanged.

## Data Model / Protocol Changes

None. No event schema, persistence, policy, or serialization change. The detached
`signature` field on result-plane events and its canonical-JSON signing/verify
contract from #348 are untouched; only the receive-side acceptance of a *missing*
signature changes (from "accept if override set" to "always reject").

## Security Considerations

- **Net effect is a security hardening (fail-closed by default → fail-closed
  always).** Removing the knob eliminates the one configuration in which a
  missing result-plane signature was accepted, closing the "set temporarily,
  never unset" risk the issue describes.
- **No regression to the verified path.** Invalid / wrong-key / non-canonical
  signatures were already always rejected (`Err(_) => Invalid`), and the key-id
  cross-check + trust re-check + sender-pin (#304, in series) are all preserved.
  This change only makes the *missing*-signature case unconditional.
- **No secrets in logs.** The surviving drop log uses the stable, non-sensitive
  `ResultVerifyError::reason()` label and correlation ids only — no key bytes,
  no payloads. The two deleted `warn!` branches logged only `event_type` / `room`
  / `sender` / `invocation_id` / `request_id`, so nothing sensitive is lost or
  added. Existing redaction/`Secret` patterns are unaffected.
- **Daemon/CLI separation intact.** All edits are within the daemon crate; the
  stateless CLI and the coding agent never see Matrix tokens or device keys, and
  this change does not move any state across that boundary.
- **Unix-only, no `unsafe`, MSRV.** No new platform assumptions, no `unsafe`, no
  new dependencies; the change only deletes code and simplifies a return type, so
  the workspace MSRV (1.93, per root `Cargo.toml`) is unaffected.
- **Matrix membership still does not imply execution permission**, and privileged
  requests remain Ed25519-signed against deny-by-default policy — unchanged.

## Testing Plan

**Unit (`result_verify.rs`):**
- Keep and adapt (drop the `bool` arg): `missing_signature_rejected_by_default`
  (`Err(Unsigned)`), `verified_when_signed_keyid_matches_and_trusted` (now
  `Ok(())`), `signed_by_other_key_rejected` (`Err(Invalid)`),
  `untrusted_key_rejected` (`Err(UntrustedKey)`), `keyid_mismatch_rejected`
  (`Err(KeyIdMismatch)`).
- Rename `tampered_result_rejected_even_with_override` → `tampered_result_rejected`
  (still `Err(Invalid)`).
- Delete `missing_signature_downgraded_only_when_override_on`.
- These run in the default `cargo test -p mx-agent-daemon` (no homeserver needed)
  and must stay green.

**Integration (`matrix_integration.rs`, `#[ignore]`d / live homeserver):**
- `live_result_plane_unsigned_or_misigned_is_rejected` must still compile and
  pass after removing the `remove_var(ALLOW_UNSIGNED_RESULTS_ENV)` line; its
  unsigned-forge case now relies on the unconditional reject. Run via
  `scripts/matrix_integration_test.sh` where a homeserver is available; otherwise
  rely on `cargo build --tests -p mx-agent-daemon` to confirm it compiles.

**Build / lint gates:**
- `cargo build -p mx-agent-daemon` and `cargo build --tests` must succeed (the
  integration test referencing the deleted const is the compile tripwire).
- `cargo clippy --workspace --all-targets` clean (watch for an unused-import
  warning on `VerifyOutcome` in `call.rs`/`sync.rs` and an unused `paths`/`trust`
  only if a match arm was the sole user — none here).
- `cargo fmt --all --check` (the ADW finalize gate runs this cwd-independently).
- `cargo test -p mx-agent-cli --test doc_drift` — confirm no doc-drift assertion
  regresses after the doc edits (the test does not currently key on this env var,
  so it should stay green; re-run to be sure).

**No new test is strictly required** (this is a removal), but optionally add a
one-line unit assertion documenting that the public `verify_result_signature`
rejects a missing signature with `ResultVerifyError::Unsigned` — already covered
by `missing_signature_rejected_by_default`.

## Documentation Updates

- `docs/architecture.md` §1 — remove the `MX_AGENT_ALLOW_UNSIGNED_RESULTS` escape-
  hatch sentences (lines 122-125); keep the fail-closed description.
- `docs/cli-reference.md` — delete the `MX_AGENT_ALLOW_UNSIGNED_RESULTS` bullet
  from the "User-facing" environment-variable list (line 3081).
- Rust doc comments on `result_verify.rs` (module + `verify_result_signature`),
  `sync.rs::verify_forwarded_event`, and `call.rs::verify_call_response_signature`
  — drop every mention of the override and reflect the always-fail-closed contract.
- No README, wiki, status-table, security-hardening, or `--help`/man-page change
  is needed (grep-confirmed none reference this env var). Do **not** retro-edit
  `specs/issue-348-sign-result-plane.md` (historical record).

## Risks and Open Questions

- **Acceptance-list wording vs. test rename.** The issue's acceptance lists
  `tampered_result_rejected_even_with_override` among the tests that "still pass."
  Removing the `allow_unsigned` parameter (a prerequisite of deleting
  `VerifyOutcome::AcceptedUnsigned`, which option 1 explicitly requires) means that
  test can no longer pass `true`. Resolution: rename it to `tampered_result_rejected`
  and keep its assertion (tampered → `Err(Invalid)`). The behavior the acceptance
  cares about is preserved; only the now-vacuous "even with override" framing is
  dropped. Flagging so a reviewer does not read the rename as a dropped test.
- **You cannot both keep the `_with_policy(allow_unsigned)` seam *and* delete
  `AcceptedUnsigned`.** The issue offers "keep the seam for unit tests only, or
  drop the `true` test cases." If the seam is kept with a working
  `allow_unsigned == true` branch, that branch must still return some
  "accepted-unsigned" outcome, which keeps `VerifyOutcome::AcceptedUnsigned` alive
  — contradicting option 1's "delete the variant." This spec chooses full removal
  (drop the seam + the `true` cases) for a clean fail-closed end state. If a
  reviewer instead wants the seam retained, that is the Option-2-flavored path and
  should be decided before implementation.
- **Option 1 vs. Option 2 decision.** This spec recommends Option 1 (full
  removal). If the maintainers have a concrete future mixed-fleet rollout in mind
  and want a compile-time fallback, switch to the Option 2 sketch (Cargo feature)
  — but that introduces the workspace's first feature flag and a CI build to
  exercise it. Confirm the choice before coding.
- **Live integration test coverage.** `live_result_plane_unsigned_or_misigned_is_rejected`
  is `#[ignore]`d and only runs against a real homeserver (not in default CI), so
  the unsigned-reject behavior change is exercised by the in-tree unit tests in CI
  and by the live script when run manually. No additional default-CI gap is
  introduced (the unit test `missing_signature_rejected_by_default` already covers
  the core invariant).
- **No external/back-compat consumers.** `mx-agent-daemon` is not a published
  library; the changed public items are workspace-internal, so the signature
  change is safe within the repo.

## Implementation Checklist

1. `result_verify.rs`: delete `ALLOW_UNSIGNED_RESULTS_ENV` (+ its doc) and
   `allow_unsigned_results()`.
2. `result_verify.rs`: delete the `VerifyOutcome` enum.
3. `result_verify.rs`: merge `verify_result_signature` +
   `verify_result_signature_with_policy` into a single public
   `verify_result_signature(event, agent_state, trust) -> Result<(),
   ResultVerifyError>` that returns `Err(Unsigned)` on a missing signature;
   keep the key-id and trust re-checks and `Err(_) => Invalid`.
4. `result_verify.rs`: update the module doc + fn doc to drop the override and
   state always-fail-closed; keep `ResultVerifyError` (incl. `Unsigned`).
5. `result_verify.rs` tests: drop the trailing `bool` arg from the surviving
   tests; delete `missing_signature_downgraded_only_when_override_on`; rename
   `tampered_result_rejected_even_with_override` → `tampered_result_rejected`;
   adjust the positive test's expectation to `Ok(())`.
6. `sync.rs`: change `verify_forwarded_event` return type to `Result<(),
   ResultVerifyError>`; update its doc.
7. `sync.rs`: collapse the `publish_forwarded` match to `Ok(()) => {}` /
   `Err(err) => { warn!("dropping …", reason = err.reason()); return }`; delete
   the `AcceptedUnsigned` warn arm.
8. `call.rs`: in `verify_call_response_signature`, drop `VerifyOutcome` from the
   `use`, delete the `AcceptedUnsigned` warn branch, and collapse to
   `verify_result_signature(&response, &agent_state, &trust).map_err(|e|
   e.reason())`; update its doc.
9. `matrix_integration.rs`: delete the `remove_var(ALLOW_UNSIGNED_RESULTS_ENV)`
   call + its comment; update the test's doc comments to "always rejected, no
   override."
10. `docs/architecture.md`: remove the escape-hatch sentences in §1.
11. `docs/cli-reference.md`: remove the `MX_AGENT_ALLOW_UNSIGNED_RESULTS` env
    bullet.
12. Verify: `cargo fmt --all --check`, `cargo clippy --workspace --all-targets`,
    `cargo build --tests -p mx-agent-daemon`, `cargo test -p mx-agent-daemon`
    (unit), `cargo test -p mx-agent-cli --test doc_drift`. Grep the tree for any
    surviving `ALLOW_UNSIGNED` / `VerifyOutcome` / `AcceptedUnsigned` reference
    and confirm only `specs/` historical records remain.
