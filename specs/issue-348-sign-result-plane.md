# Spec — issue #348: Ed25519-sign the result plane

> `type:security` `area:protocol` `area:security` `priority:p1`. Branch
> `feat/348-security-ed25519-sign-the-result-plane-e`.

## Problem statement

The **result plane is sender-pinned but not Ed25519-signed.** `ExecAccepted`,
`ExecRejected`, `ExecFinished`, `ExecCancelled`, `StreamChunk`, `StreamArtifact`,
and `CallResponse` (`crates/mx-agent-protocol/src/schema.rs`) carry no
`signature`, unlike the request plane (`ExecRequest`/`ExecStdin`/`ExecCancel`/
`PtyResize`/`CallRequest`).

Delivery is gated only by matching the homeserver-asserted Matrix `sender`
against the target agent's registered `matrix_user_id` (sender-pin, added by
#304). That defeats other *room members*, but a **compromised or malicious
homeserver** can spoof `sender` and forge results, exit codes, or streamed
output back to the caller. We close this by signing every result-plane event
with the executor's daemon Ed25519 key and verifying it on the caller side
against the executor's published, locally-trusted key — defense-in-depth *in
series* with the existing sender-pin.

## Goals

- Add a detached Ed25519 `signature` to the seven result-plane events above,
  reusing the existing canonical-JSON signing path (`signing::sign_into` /
  `verify`, field-exclusion already implemented).
- Verify the result-plane signature on receipt (caller side), against the
  executor's trusted verifying key resolved from its `AgentState`, **in addition
  to** the existing sender-pin, and **fail closed** on the Matrix transport.
- Sign per-chunk for inline `StreamChunk` and sign the `StreamArtifact` event so
  large (offloaded) output is also authenticated.
- A live test proving a homeserver-spoofed/forged/tampered result is rejected.

## Non-goals

- Loopback / local-IPC results (`ExecFrame`, in-process `ExecOutcome`) are **not**
  signed — there is no untrusted hop and no separate identity to verify.
- No replay cache or `expires_at` for results (see Decision D4).
- No change to the request plane, trust model, or key management.
- Encrypting result payloads (separate concern; E2EE already covers timeline
  confidentiality where enabled).

## Repository context

- Signing API — `crates/mx-agent-protocol/src/signing.rs`: `signing_bytes`
  (drops top-level `signature`, canonical-JSON encodes the rest), `sign`,
  `sign_into` (sign + embed), `verify` (read embedded sig, recompute, check),
  `verify_signature`. `SignatureError::{NotAnObject, MissingSignature,
  UnsupportedAlg, MalformedSignature, Invalid, NonCanonical}`. The
  `sign_approval_decision`/`verify_approval_decision` pair shows the typed-struct
  round-trip (`to_value` → sign/verify).
- Schema — `crates/mx-agent-protocol/src/schema.rs`: `Signature {alg, key_id,
  sig}` (`:24-33`); result structs `ExecAccepted` `:93`, `ExecRejected` `:103`,
  `ExecFinished` `:115`, `ExecCancelled` `:177`, `StreamChunk` `:193`,
  `StreamArtifact` `:219`, `CallResponse` `:408`; **`ApprovalDecision` `:446-482`
  is the precedent** — `signature: Option<Signature>` + `#[serde(default,
  skip_serializing_if = "Option::is_none")]`, doc-commented fail-closed rationale.
- Daemon key — `crates/mx-agent-daemon/src/signing.rs`: `DaemonSigningKey`
  (`.signing_key()`, `.verifying_key()`, `.key_id()`), `load_or_create_signing_key`,
  `key_id_for_verifying_key`, `decode_verifying_key`.
- Send sites (executor, Matrix `room.send_raw`) — `exec.rs` `emit_exec_accepted`
  (~690), `emit_exec_rejected` (~711), `ExecFinished` non-pty (~1015) + pty
  (~1632), `StreamChunk` pty (~1874); `stream.rs:618` buffered chunk (egress in
  exec.rs); `emit_exec_cancelled` (~2499); `artifact.rs` `StreamArtifact` emit;
  `call.rs` `emit_call_response` (~400).
- Verify sites (caller) — `sync.rs` `publish_forwarded` (~502-531) for exec /
  stream results; `call.rs` `wait_for_call_response` (~583-622) for `CallResponse`.
- Key resolution — `verifying_key_from_agent_state` (`call.rs:414-425`) reads
  `AgentState.signing_public_key`, decodes, and asserts
  `key_id_for_verifying_key(&key) == AgentState.signing_key_id`;
  `agent::read_agent_state` (`agent.rs:244-263`). Trust: `TrustStore::is_trusted(agent_id, key_id)`
  (`trust.rs:231`), `is_key_trusted(key_id)` (`trust.rs:239`).
- Sender-pin precedent — `exec_subscribers.rs:159-187`, `call.rs:~606`.

## Decisions (latitude delegated by the issue / disambiguated by the security intent)

- **D1 — Field shape: mirror `ApprovalDecision`.** Add
  `#[serde(default, skip_serializing_if = "Option::is_none")] pub signature:
  Option<Signature>` immediately before the trailing `#[serde(flatten)] pub
  extra: Extra` on each of the seven structs. `Option` so legacy/unsigned events
  still *deserialize* (and can be logged + rejected with a reason rather than
  failing to parse); the verifier fails closed on `None`.
- **D2 — Chunk granularity: per-chunk signatures, plus signed `StreamArtifact`.**
  Inline streaming is rate-bounded (16 KiB/chunk, token bucket), so per-chunk
  Ed25519 (~tens of µs, dominated by the existing per-chunk SHA-256 + Matrix
  send) is cheap and authenticates output *as it is consumed* (a terminal
  digest-on-`ExecFinished` would leave consumed chunks unauthenticated and emit
  nothing if the stream never finishes). High-volume output switches to artifact
  mode → one signed `StreamArtifact` (signature binds `mxc_uri`+`sha256`+`size_bytes`),
  so the "per-chunk is expensive at scale" case never arises.
- **D3 — Scope: include `StreamArtifact`.** The issue enumerates six types and
  omits it, but it is part of the same result plane, a `ForwardedExecEvent`
  variant, and the large-output substitute for `StreamChunk`; leaving it unsigned
  is a signing hole that defeats D2 on big outputs.
- **D4 — No `nonce`/`expires_at`/replay cache for results.** Results are
  correlated to a single in-flight waiter (`invocation_id`/`request_id`) and
  consumed once; the open IPC subscription / `wait_for_call_response` 60s
  deadline is the freshness bound, and `StreamChunk.seq` orders/dedupes chunks. A
  replayed *validly-signed* result is either identical to the genuine one
  (harmless) or carries a non-matching signed `invocation_id` (no waiter →
  dropped). A nonce with no replay cache would be signed-but-unchecked surface,
  so it is omitted. (Replay-cache parity with `ApprovalDecision` is a possible
  follow-up, not needed here.)
- **D5 — Fail-closed on the Matrix transport, with a removable escape hatch.**
  Missing / invalid / wrong-key / untrusted-key result-plane signature on a
  Matrix-delivered result → **drop + log a warning with the reason and
  correlation id**; the caller's waiter then times out (the existing #304
  forge-rejection behavior). Fail-open would provide zero new security (an
  attacker simply omits the signature). For mixed-fleet rollout, a single
  `MX_AGENT_ALLOW_UNSIGNED_RESULTS=1` env override (default off, mirrors the
  `MX_AGENT_REQUIRE_BWRAP` explicit-gate convention) downgrades a *missing*
  signature to a logged-accept; invalid/wrong-key/untrusted signatures are
  **always** rejected regardless. Documented as removable at first stable release.

## Implementation approach

### 1. Protocol crate (`mx-agent-protocol`)

- `schema.rs`: add the `signature: Option<Signature>` field (D1) to
  `ExecAccepted`, `ExecRejected`, `ExecFinished`, `ExecCancelled`, `StreamChunk`,
  `StreamArtifact`, `CallResponse`, each before `extra`, with a doc comment
  mirroring `ApprovalDecision`'s.
- `signing.rs`: add a generic `verify_signed<T: Serialize>(verifying_key, msg:
  &T) -> Result<(), SignatureError>` (= `verify(key, &to_value(msg)?)`) for the
  typed-struct caller path, and unit tests (round-trip per type, tamper →
  `Invalid`, unsigned → `MissingSignature`, wrong-key → `Invalid`, plus a KAT
  vector for `ExecFinished` to guard canonical-form drift). Signing at emit sites
  reuses `sign_into` on the already-built `Value`.

### 2. Daemon send side (sign before `room.send_raw`)

Thread the daemon `SigningKey` + `key_id` (from `DaemonSigningKey`, obtained via
`load_or_create_signing_key(paths)` already in scope at the exec/call entry
points) to each emit site; after `let mut content = serde_json::to_value(&msg)?`
and before `room.send_raw(EVENT_TYPE, content)`, call
`signing::sign_into(signing_key, &key_id, &mut content)?`. Sign at the single
Matrix egress per type (e.g. sign the buffered `StreamChunk` in `exec.rs`, not in
`stream.rs`, to keep one signing locus per transport boundary). If signing a
`CallResponse` fails `NonCanonical` (non-canonicalizable tool `result`), emit a
signed error `CallResponse` instead of an unsigned success (fail closed,
consistent with `CallRequest.args`).

### 3. Daemon verify side (caller, fail-closed)

- `publish_forwarded` (`sync.rs`): for `ExecAccepted/Rejected/Finished/Cancelled`,
  `StreamChunk`, `StreamArtifact`, resolve the executor `AgentState` (already
  read for sender-pin) → `verifying_key_from_agent_state` → re-serialize the
  typed struct → `signing::verify_signed`; cross-check `signature.key_id ==
  AgentState.signing_key_id`; `TrustStore::is_trusted(agent_id, key_id)`. On any
  failure, drop (do not `subscribers.publish`) and log. Apply the
  `MX_AGENT_ALLOW_UNSIGNED_RESULTS` downgrade only to the missing-signature case.
- `wait_for_call_response` (`call.rs`): after the sender-pin and before the
  `request_id` match, run the same verify against the resolved key.

### 4. Docs

Update `docs/architecture.md` result-plane prose (currently documents the
sender-pin-vs-sign gap as deferred) to state the result plane is now signed +
verified, and the `MX_AGENT_ALLOW_UNSIGNED_RESULTS` escape hatch. Update
`docs/security-hardening.md` if it references the gap.

## Security considerations

- Signature binds every serialized field except `signature` (canonical JSON),
  so exit codes, stream bytes+seq, and call results cannot be swapped.
- Verify-against-published-key + trust re-check means a key revoked between
  request and response causes the result to be dropped (value-add over sender-pin).
- Fail-closed default; the escape hatch never accepts an *invalid* signature.
- No secrets logged: log only reason + correlation id + sender, never key bytes
  or payloads.

## Testing plan

- **Unit** (`mx-agent-protocol`): per-type round-trip sign→verify; tampered field
  → `Invalid`; unsigned → `MissingSignature`; wrong key → `Invalid`; `ExecFinished`
  KAT. Reuse `test_key()`.
- **Daemon unit**: verify helper resolves key from `AgentState` and enforces
  `key_id` match; `MX_AGENT_ALLOW_UNSIGNED_RESULTS` gating.
- **Live** (`tests/matrix_integration.rs`, `#[ignore]`, run via
  `scripts/matrix_integration_test.sh`): extend the #304 model with
  `live_result_plane_unsigned_or_misigned_is_rejected`: (1) unsigned forge
  dropped; (2) sender-spoof + self-signed dropped (key_id ≠ executor); (3)
  tampered genuine result dropped; (4) revoked-key result dropped; (5) genuine
  signed `ExecFinished` + `StreamChunk`s delivered and resolve correctly.

## E2E decision

E2E **added** (the live spoof-rejection test) — this is a cross-boundary
Matrix-transport security invariant that lower-level tests cannot prove. It is
`#[ignore]`d and script-gated, so default `cargo test --all` stays Docker-free.

## Risks / open questions

- `CallResponse.result` non-canonicalizable (float) → signing fails; handled by
  emitting a signed error response (fail closed). Confirm `canonical_json`
  behavior during impl.
- Verify re-serializes the parsed struct (router already deserialized); safe
  because all result fields are scalars/strings/`Option`/flatten-`extra` and
  round-trip losslessly through `serde_json`.
- Threading the signing key touches several `exec.rs` signatures; keep the
  signing locus at the Matrix egress to bound churn.

## Implementation checklist

- [ ] `schema.rs`: `signature: Option<Signature>` on the 7 result structs.
- [ ] `signing.rs`: `verify_signed` helper + unit tests.
- [ ] Sign at all Matrix result emit sites (exec/stream/artifact/call).
- [ ] Verify + trust re-check at `publish_forwarded` and `wait_for_call_response`,
      fail-closed, with `MX_AGENT_ALLOW_UNSIGNED_RESULTS` gate.
- [ ] Live spoof-rejection test + daemon/protocol unit tests.
- [ ] Docs (`architecture.md`, `security-hardening.md`).
- [ ] `cargo build --all`, `test --all`, `fmt --check`, `clippy -D warnings`,
      `shellcheck`, `test_release_yml.sh` (unaffected) all green.
