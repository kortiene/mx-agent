# Replay/Expiry Protection for `call.request`

Issue: [#222](https://github.com/kortiene/mx-agent/issues/222) — *call.request has no
replay/expiry protection (signed tool calls are replayable)* (type:security,
area:daemon, area:protocol, area:security, area:tools, priority:p0)

## Problem Statement

`com.mxagent.call.request.v1` (named tool calls) is **not replay- or
expiry-protected**, unlike `com.mxagent.exec.request.v1`. A captured,
validly-signed `call.request` event can be re-sent into the room and the target
daemon will re-authorize and re-execute the named tool. This violates the stated
security model:

- `CallRequest` (`crates/mx-agent-protocol/src/schema.rs`) carries only a
  detached `signature` — no `nonce`, `created_at`, or `expires_at`. `ExecRequest`
  carries all three.
- The event router (`crates/mx-agent-daemon/src/event_router.rs`) replay/expiry
  checks **only** `ExecRequest` before dispatch. The router comment claims
  `call.request` is "dispatched to handlers that enforce their own
  signature/nonce checks", but the call authorization path
  (`authorize_call_request` / `authorize_live_call` in `call.rs`) performs
  signature → trust → policy and **never** calls `replay.admit`. There is no
  nonce to check.

This is a latent RCE-boundary defect. Practical impact is currently low (the only
built-in tool is `run_tests`, bounded by deny-by-default policy), but it must be
closed before the tool surface grows.

## Goals

1. Add `created_at`, `expires_at`, and `nonce` to `CallRequest`, mirroring
   `ExecRequest`, and include them in the signed canonical content.
2. Replay/expiry-check `CallRequest` in `EventRouter::route` exactly like
   `ExecRequest`, using the same persistent `ReplayCache`.
3. Populate `nonce`/`created_at`/`expires_at` in every call-request builder path
   (loopback is excluded — see Non-Goals — and the Matrix send path).
4. Remove/correct the misleading router comment and update the router module
   docs and architecture docs.
5. Add a regression test paralleling
   `valid_exec_request_dispatches_once_then_replay_is_rejected` for
   `call.request`, plus an expiry test.

## Non-Goals

- Changing the loopback call path (`start_call_loopback` /
  `call_ipc::start_call_loopback`): loopback executes a built-in tool directly on
  the local daemon in response to a local IPC request. It never builds or sends a
  federated `call.request` Matrix event, so it is not a replay vector and needs
  no nonce/expiry.
- Adding replay/expiry to `call.response` (responses are not privileged
  execution requests).
- Changing the call authorization order (signature → trust → policy) or adding a
  redundant per-handler replay check; replay/expiry is enforced at the router
  layer, identical to `exec.request`.
- Backwards compatibility with pre-fix `call.request` events that lack the new
  fields. Making the fields required means such events now fail to deserialize
  (rejected as `Malformed`), which is the desired security posture for the alpha.

## Relevant Repository Context

- **`mx-agent-protocol`** owns event content structs (`schema.rs`) and signing
  (`signing.rs`). `signing::sign_into` signs the canonical JSON of the content
  with the `signature` field excluded, so any field added to `CallRequest` is
  automatically covered by the signature.
- **`mx-agent-daemon`**:
  - `event_router.rs` — the `/sync` gate. Replay-checks `ExecRequest` via
    `ReplayCache::admit(nonce, expires_at)` at `route` step 4 before dispatch.
  - `replay.rs` — `ReplayCache::admit` parses `expires_at` (RFC 3339), rejects
    expired and replayed nonces side-effect-free, and persists `0600`.
  - `call.rs` — builders (`build_signed_call_request`,
    `build_signed_call_request_for_target`, `send_call_request`), the live Matrix
    send path (`start_call_matrix_inner`), and the receive-side authorization
    (`authorize_call_request`, `authorize_live_call`, `handle_live_call_request`).
  - `exec_ipc.rs` — the exec analog. `rfc3339_after(offset)` produces an RFC 3339
    UTC timestamp `now + offset`; exec uses `rfc3339_after(Duration::ZERO)` for
    `created_at`, `rfc3339_after(Duration::from_secs(300))` for `expires_at`, and
    `generate_request_id()` as the nonce.
- **Constraints**: no `unsafe`; MSRV 1.74; document public APIs; never log
  secrets; CLI stateless, daemon owns Matrix state/keys; Unix only.

## Proposed Implementation

### 1. Protocol schema (`mx-agent-protocol/src/schema.rs`)

Add three required `String` fields to `CallRequest`, mirroring `ExecRequest`:

```rust
/// Creation timestamp (RFC 3339).
pub created_at: String,
/// Expiry timestamp (RFC 3339).
pub expires_at: String,
/// Random nonce (base64), unique per request, used for replay protection.
pub nonce: String,
```

These are required (not `Option`) so a pre-fix request missing them fails to
deserialize and is rejected as `Malformed` at the router. Update the round-trip
test JSON for `CallRequest` (`schema.rs` tests) to include the new fields.

### 2. Builders (`mx-agent-daemon/src/call.rs`)

- `build_signed_call_request_for_target`: add explicit `nonce`, `created_at`,
  `expires_at` parameters (deterministic, testable; mirrors
  `build_signed_exec_request`). Set them on the `CallRequest` before signing so
  they are covered by the signature.
- `build_signed_call_request`: keep its public 6-arg signature stable; stamp a
  fresh nonce (`generate_request_id()`) and `created_at = now`,
  `expires_at = now + CALL_REQUEST_TTL` internally, then delegate to
  `_for_target`. Document the stamping behavior.
- `send_call_request`: unchanged surface — it already delegates to
  `build_signed_call_request`, which now stamps the fields.
- `start_call_matrix_inner`: compute `created_at`/`expires_at`/`nonce` the same
  way exec does and pass them to `_for_target`.
- Reuse the timestamp helper by making `exec_ipc::rfc3339_after` `pub(crate)`
  (single source of truth), and define `CALL_REQUEST_TTL: Duration =
  Duration::from_secs(300)` to match exec's 5-minute window.

### 3. Router (`mx-agent-daemon/src/event_router.rs`)

Extend the replay check at `route` step 4 to cover `CallRequest`:

```rust
let replay = match &routed {
    RoutedEvent::ExecRequest(req) => Some((req.nonce.as_str(), req.expires_at.as_str())),
    RoutedEvent::CallRequest(req) => Some((req.nonce.as_str(), req.expires_at.as_str())),
    _ => None,
};
if let Some((nonce, expires_at)) = replay {
    if self.replay.admit(nonce, expires_at).is_err() {
        return RouteOutcome::ReplayRejected(category);
    }
}
```

Update the inline comment and the module-doc bullet to state that both
`exec.request` and `call.request` are replay/expiry-checked.

### 4. Docs

- `event_router.rs` module docs: privileged-requests bullet names both
  `exec.request` and `call.request`.
- `docs/architecture.md` §10.1 event-router description: correct the claim that
  `call.request` enforces nonce checks only in its handler.

## Affected Files / Crates / Modules

- `crates/mx-agent-protocol/src/schema.rs` — `CallRequest` struct + round-trip test.
- `crates/mx-agent-daemon/src/call.rs` — builders, live send path, doc comments,
  new tests.
- `crates/mx-agent-daemon/src/event_router.rs` — router replay check, comment,
  module docs, new regression tests.
- `crates/mx-agent-daemon/src/exec_ipc.rs` — `rfc3339_after` visibility.
- `crates/mx-agent-daemon/tests/matrix_integration.rs` — any `CallRequest`
  builder call sites (verify they still compile / parse).
- `docs/architecture.md` — §10.1 router description.

## CLI / API Changes

No CLI surface change. Public Rust API change: `CallRequest` gains three required
fields, and `build_signed_call_request_for_target` gains three parameters. These
are alpha-internal crates; the change is documented.

## Data Model / Protocol Changes

`com.mxagent.call.request.v1` content gains `created_at`, `expires_at`, `nonce`
(all RFC 3339 / base64 strings), now part of the signed canonical content.
Pre-fix events without these fields are rejected (no backward compatibility, by
design — this is the security fix).

## Security Considerations

- The new fields are covered by the existing Ed25519 signature (`sign_into`
  excludes only `signature`), so an attacker cannot alter the nonce/expiry
  without invalidating the signature.
- Replay/expiry enforcement lives at the router, the first gate, before any
  handler — matching `exec.request`. A replayed or expired `call.request` is
  rejected before signature/trust/policy run, and never executes a tool.
- Room membership still grants nothing; signature → trust → policy → replay all
  hold.
- No secrets are introduced or logged; the nonce is non-secret random data and
  only `RouteOutcome` categories are logged.
- Unix-only, no `unsafe`, MSRV 1.74 preserved.

## Testing Plan

- **Protocol**: `CallRequest` round-trips with the new fields; deserialization of
  a `CallRequest` missing `nonce`/`expires_at` fails (covered implicitly by
  required-field semantics and the router `Malformed` test).
- **Router unit tests** (parallel to exec):
  - `valid_call_request_dispatches_once_then_replay_is_rejected`
  - `expired_call_request_is_rejected`
  - Confirm the existing `malformed_privileged_event_is_not_dispatched` still
    holds (a `call.request` missing fields is `Malformed`).
- **call.rs unit tests**: a built request carries non-empty
  `nonce`/`created_at`/`expires_at`, and these fields are covered by the
  signature (tampering with `nonce` fails `authorize_call_request`).
- Run `cargo test --all`, `cargo fmt --check`, `cargo clippy --all-targets
  --all-features -- -D warnings`, `cargo build --all`.

## Documentation Updates

- `event_router.rs` module docs + inline comment.
- `docs/architecture.md` §10.1.
- (README security posture already states "signature, nonce, and expiry" — no
  change needed.)

## Risks and Open Questions

- **Compatibility**: pre-fix `call.request` events become undeserializable. This
  is intentional and acceptable for the alpha; documented as a Non-Goal.
- **Nonce source**: reuse `generate_request_id()` (ULID) as the nonce, identical
  to exec, rather than introducing a new RNG dependency.
- No open questions; the issue's proposed fix is precise and matches the existing
  exec pattern.

## Implementation Checklist

1. [ ] Add `created_at`, `expires_at`, `nonce` to `CallRequest` and update the
   schema round-trip test.
2. [ ] Make `exec_ipc::rfc3339_after` `pub(crate)`.
3. [ ] Add explicit `nonce`/`created_at`/`expires_at` params to
   `build_signed_call_request_for_target`; stamp them internally in
   `build_signed_call_request`; define `CALL_REQUEST_TTL`.
4. [ ] Populate the fields in `start_call_matrix_inner` (mirror exec).
5. [ ] Extend the router replay check to cover `CallRequest`; fix the comment and
   module docs.
6. [ ] Update `docs/architecture.md` §10.1.
7. [ ] Add router replay + expiry regression tests for `call.request`; add a
   call.rs test asserting nonce/expiry are signed.
8. [ ] Run fmt, clippy, test, build; fix any failures.
