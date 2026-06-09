# Align the device-verify IPC surface with the in-band SAS flow (issue #259)

## Problem Statement

The daemon registers two IPC dispatch methods, `device.verify.confirm` and
`device.verify.cancel` (`crates/mx-agent-daemon/src/lifecycle.rs:844`/`853`),
that act on the process-global interactive-verification (SAS) registry by
`flow_id`. But the only way to *start* an interactive verification is the
streaming `device.verify.start`, whose handler reads the operator's
confirm/cancel decision **in-band on the same held-open connection**:
`dispatch_device_verify` (`lifecycle.rs:1191`) passes a `wait_decision` closure
that calls `read_verify_decision` (`device_ipc.rs:315`), which only treats a
bare `control.method == "confirm"` control frame *on that connection* as a
confirmation.

A standalone `device.verify.confirm` / `.cancel` request sent over a *separate*
connection cannot advance that in-band wait. Worse, now that the IPC server is
per-connection threaded (issue #258, resolved in #280), such a request would run
*concurrently* and call `confirm_sas`/`cancel_sas` directly on the live SAS — a
side effect the parked `device.verify.start` handler neither expects nor
observes. The start handler keeps blocking in `read_verify_decision` until its
own deadline elapses and then fail-safes to `Cancel`, racing against the
out-of-band action.

So these two registered methods are **dead code for the flow as implemented**:
the CLI never calls them (it only sends `device.verify.start` and then bare
`confirm`/`cancel` control frames in-band — `cli.rs:1262`), they cannot drive
the documented streaming flow, and as a live-but-unreachable surface they
quietly bypass the single deliberate confirmation point that issue #258
established. The IPC surface (and `docs/architecture.md:1343`) advertises a
contract the implementation does not honor.

Surfaced during the #240 review (PR #256), severity "skippable."

## Goals

- Make the device-verify IPC surface **match the implemented in-band SAS flow**:
  no registered method should be unreachable, misleading, or able to mutate a
  live verification outside the operator's in-band decision.
- **Preserve the single fail-safe confirmation point** from issue #258:
  `read_verify_decision` on the held-open `device.verify.start` connection stays
  the *only* path that can confirm an interactive SAS. Removing the out-of-band
  methods strengthens this invariant rather than weakening it.
- Keep the working, bounded, de-serialized in-band flow (`started → emoji-ready →
  confirmed/cancelled`) and the CLI behavior unchanged.
- Update documentation (`docs/architecture.md` IPC table, the `device_ipc.rs`
  module doc) so the surface is described accurately.
- Leave the codebase free of dead pub API: either every exported verify symbol is
  reachable, or it is removed.

## Non-Goals

- **The out-of-band redesign** (making `device.verify.confirm` / `.cancel`
  reachable by having `device.verify.start` stream `emoji-ready` and then await a
  registry-backed decision delivered over a *second* connection). This is a
  larger feature, not a surface-alignment bug fix, and its original motivation
  (unblocking the single-threaded IPC freeze, #258) is already resolved by #280.
  It is captured as a future option in *Risks and Open Questions*, not built
  here.
- Changing the SAS/emoji protocol, the `DeviceVerifyFrame` schema, the
  `VERIFY_DEADLINE` bound, or the `read_verify_decision` fail-safe semantics.
- Touching the out-of-band fingerprint path `device.verify.manual`, which already
  serves headless/scripted verification.
- Promoting device verification to an execution-authorization input. It remains
  an advisory transport-identity signal (architecture §1.2, §13.2).
- Any Windows / named-pipe support (Unix-only project).

## Relevant Repository Context

- **Crates.** `mx-agent-daemon` owns long-lived Matrix state, crypto, the SAS
  flow registry, and IPC dispatch; `mx-agent-ipc` owns the Unix-socket transport
  and now serves each accepted connection on its own detached worker thread after
  the `SO_PEERCRED` gate (`mx-agent-ipc/src/server.rs:84`). `mx-agent-cli` is the
  stateless client.
- **Interactive verify, as built.** `device.verify.start` is a *streaming*
  method routed through `dispatch_streaming` →`dispatch_device_verify`
  (`lifecycle.rs:1279`/`1191`), not the unary `dispatch` match. It calls
  `run_device_verify` (`device_ipc.rs:350`), which:
  1. `start_sas` → registers a `SasFlow::Requested` under a freshly generated
     `flow_id`, emits `DeviceVerifyFrame::Started`.
  2. Drives `/sync` (`drive_until`) until the SAS can be presented, emits
     `EmojiReady`.
  3. Calls `wait_decision()` — i.e. `read_verify_decision` on the *same* socket —
     bounded by `VERIFY_DEADLINE` (300 s); anything but an explicit `confirm`
     frame (cancel, unknown method, malformed, EOF, error, timeout) fail-safes to
     `Cancel`.
  4. Applies the decision via `confirm_sas`/`cancel_sas`, drives `/sync` to
     completion, emits `Confirmed`/`Cancelled`, and `forget_sas`.
- **The SAS registry** (`verification.rs:391`–`570`) is a process-global
  `Mutex<HashMap<String, SasFlow>>`. `confirm_sas`, `cancel_sas`, `advance_sas`,
  and `forget_sas` are all keyed by `flow_id` and are the shared primitives both
  the in-band handler and the (unreachable) out-of-band dispatch methods call.
  These registry primitives stay — they are used by `run_device_verify`. Only the
  *out-of-band IPC wrappers* are unreachable.
- **The dead surface.** `lifecycle.rs:844`–`861` dispatches
  `device.verify.confirm`/`.cancel` to `confirm_verify`/`cancel_verify`
  (`device_ipc.rs:229`/`242`), which return `VerificationActionResult`. These
  wrappers, `VerifyFlowParams`, and `VerificationActionResult` exist *only* for
  these two methods (confirmed by repo-wide grep): no CLI subcommand, no other
  caller.
- **CLI.** `device_verify_interactive` (`cli.rs:1179`) opens one connection,
  sends `device.verify.start`, reads frames, and on `EmojiReady` sends a bare
  `confirm`/`cancel` control frame back on the same connection. There is no
  `mx-agent device verify confirm/cancel` subcommand.
- **Prior art / decision already recorded.** The issue-258 spec
  (`specs/issue-258-device-verify-decision-deadline.md:54`) explicitly scoped the
  in-band confirm/cancel redesign *out* and deferred it to #259, while keeping
  "the decision still multiplexed on the same connection" as the contract. That
  contract is the in-band design this spec finalizes.
- **Conventions.** No `unsafe`; MSRV 1.74; no secrets in logs; human output by
  default with `--json`; document public APIs; deny-by-default policy for
  privileged Matrix requests (orthogonal here — verification is not policy-gated
  execution).

## Proposed Implementation

**Recommended option: in-band only — remove the unreachable surface and document
the flow as in-band.** This is the minimal, honest fix that makes the IPC
surface match the implementation and *tightens* the #258 fail-safe (no second
code path can confirm a live SAS). Rationale over the out-of-band redesign:

- The redesign's stated motivation — unblocking the single-threaded IPC freeze —
  is already solved by #280; per-connection threading means the in-band wait no
  longer starves other methods.
- Interactive emoji/SAS is inherently *attended*: the operator is present at the
  terminal comparing emoji, so multiplexing the decision on the open connection
  is the natural UX. The headless/scripted need is already met by
  `device.verify.manual`.
- A reachable out-of-band `confirm` would re-introduce a second, un-bounded path
  to confirm a live verification, undercutting the deliberate single-point
  fail-safe.

### Changes

1. **Remove the two dispatch arms** in `lifecycle.rs` (the
   `"device.verify.confirm"` and `"device.verify.cancel"` match arms, ~844–861).
   They fall through to the existing `unknown method` arm, so callers receive a
   clean `METHOD_NOT_FOUND`.
2. **Remove the now-unused handlers and types** in `device_ipc.rs`:
   `confirm_verify`, `cancel_verify`, `VerifyFlowParams`, and
   `VerificationActionResult`, plus their unit tests
   (`verify_flow_params_roundtrip`-style serde tests and the
   `confirm`-control-frame-disambiguation test that references the
   `device.verify.confirm` *string* should be re-checked: keep the tests that
   assert `read_verify_decision` rejects a `device.verify.confirm` method as
   `Cancel`, since that fail-safe behavior is still meaningful; only drop tests
   tied to the removed types).
3. **Remove the corresponding re-exports** from `lib.rs:89`/`93`
   (`cancel_verify`, `confirm_verify`, `VerificationActionResult`,
   `VerifyFlowParams`). Keep `run_device_verify`, `read_verify_decision`,
   `VerifyDecision`, `DeviceVerifyFrame`, `DeviceVerifyStartParams`,
   `VERIFY_DEADLINE` — all reachable.
4. **Keep the registry primitives** `confirm_sas`/`cancel_sas`/`advance_sas`/
   `forget_sas`/`start_sas` (`verification.rs`) untouched — they back the in-band
   `run_device_verify`.
5. **Update the module doc** at the top of `device_ipc.rs` (lines 8–14): drop
   `device.verify.confirm`, `device.verify.cancel` from the "single-response
   methods" list and state explicitly that the interactive decision is delivered
   in-band as a `confirm`/`cancel` control frame on the held-open
   `device.verify.start` connection.
6. **Update `docs/architecture.md`**: delete the `device.verify.confirm /
   device.verify.cancel` row (line 1343) and extend the `device.verify.start`
   row's note to say the confirm/cancel decision is sent in-band on the same
   connection (no separate method).

### Compile-time guard

After removal, `cargo build` and `cargo clippy --all-targets` must be clean — a
leftover reference would fail to compile, which is the desired safety net.
`#[deny(dead_code)]` is not relied on (the types were `pub`); the removal of both
the methods and the exports is what guarantees no dead surface.

## Affected Files / Crates / Modules

- `crates/mx-agent-daemon/src/lifecycle.rs` — remove the two dispatch arms (~844–861).
- `crates/mx-agent-daemon/src/device_ipc.rs` — remove `confirm_verify`,
  `cancel_verify`, `VerifyFlowParams`, `VerificationActionResult`; update module
  doc; prune the serde round-trip tests for the removed types.
- `crates/mx-agent-daemon/src/lib.rs` — remove the four re-exports.
- `crates/mx-agent-daemon/src/verification.rs` — read only; registry primitives stay.
- `crates/mx-agent-cli/src/cli.rs` — read only; confirms no CLI subcommand
  depends on the removed methods (no change expected).
- `docs/architecture.md` — IPC method table update.
- `specs/issue-240-production-e2ee-hardening.md` (lines 217, 355) and
  `specs/issue-258-device-verify-decision-deadline.md` (line 54) — historical
  specs; update only if a coherence note is wanted (optional, see Docs).

## CLI / API Changes

- **IPC surface:** removal of two methods — `device.verify.confirm` and
  `device.verify.cancel`. They become `METHOD_NOT_FOUND`. Since no shipped CLI
  path or documented client invokes them (the CLI uses in-band control frames),
  this is a surface *correction*, not a behavior regression. Pre-1.0 alpha, no
  deprecation window required.
- **Public Rust API (daemon crate):** removal of the re-exported `confirm_verify`,
  `cancel_verify`, `VerifyFlowParams`, `VerificationActionResult`. These have no
  external consumers in-repo.
- **CLI commands:** none. `mx-agent device verify` is unchanged.

## Data Model / Protocol Changes

- No event-schema, persistence, policy, or canonical-JSON serialization changes.
- The `DeviceVerifyFrame` streaming schema is unchanged.
- The only protocol-surface change is the deletion of two JSON-RPC method names
  and their request/response structs (`VerifyFlowParams` /
  `VerificationActionResult`), which were unreachable.

## Security Considerations

- **Strengthens the #258 fail-safe.** With the out-of-band methods gone,
  `read_verify_decision` on the held-open connection is the *sole* path that can
  confirm an interactive SAS. No concurrent same-UID connection can call
  `confirm_sas(flow_id)` on a live flow out of band, so an interactive
  verification can only be completed by a deliberate in-band `confirm`.
- **No key material crosses IPC.** Unchanged: the CLI sees only flow frames
  (emoji/decimal SAS, status), never device keys or tokens. The daemon owns the
  SAS object for the flow's lifetime.
- **Daemon/CLI separation preserved.** CLI stays stateless; daemon owns crypto
  and the flow registry.
- **Peer-cred gate unaffected.** `SO_PEERCRED` UID matching still gates every
  connection on the accept thread.
- **Membership ≠ execution permission** and **Ed25519-signed deny-by-default
  policy** are orthogonal to this change (verification is an advisory transport
  signal, not policy-gated execution) and are not touched.
- **No secrets logged.** No new logging; existing redaction patterns untouched.
- **Unix-only**; no platform assumptions added.

## Testing Plan

- **Daemon unit (dispatch):** add/adjust a test asserting that a unary
  `device.verify.confirm` / `device.verify.cancel` request now returns a
  `METHOD_NOT_FOUND` error response (the `unknown method` arm), confirming the
  surface was removed cleanly.
- **`read_verify_decision` fail-safe tests:** keep the existing tests
  (`device_ipc.rs:720`+) that verify `confirm` → `Confirm` and that a
  `device.verify.confirm` *method string*, unknown method, malformed JSON, EOF,
  and timeout all → `Cancel`. These remain the contract for the in-band decision
  and must still pass.
- **Remove** the serde round-trip tests for `VerifyFlowParams` /
  `VerificationActionResult` (the types no longer exist).
- **Registry primitives:** the existing `confirm_sas`/`cancel_sas`/`advance_sas`
  unknown-flow tests (`verification.rs:774`+) stay green unchanged (primitives
  retained).
- **Build/lint gate:** `cargo build`, `cargo test -p mx-agent-daemon`, and
  `cargo clippy --all-targets -- -D warnings` must pass with no dead-code or
  unused-import warnings.
- **E2EE smoke (manual / existing e2e):** if there is a live `device.verify.start`
  end-to-end test, confirm it still completes `started → emoji-ready →
  confirmed`; no new e2e is required since behavior is unchanged.

## Documentation Updates

- `docs/architecture.md` — remove the `device.verify.confirm / .cancel` table
  row (line 1343); note the decision is in-band on the `device.verify.start`
  connection.
- `crates/mx-agent-daemon/src/device_ipc.rs` module doc — drop the two methods
  from the single-response list; describe the in-band decision frame.
- Optional coherence note in `specs/issue-258-device-verify-decision-deadline.md`
  / `specs/issue-240-production-e2ee-hardening.md` recording that #259 was
  resolved by removing the unreachable methods (the in-band design is final), so
  future readers of those specs are not misled.
- No README or `--help` text changes (no CLI surface change).
- Do not document any out-of-band confirm/cancel capability — it does not exist
  after this change.

## Risks and Open Questions

- **Decision: in-band-only vs. out-of-band redesign.** This spec recommends
  in-band-only. If the maintainers instead want a scriptable/headless interactive
  SAS (operator confirms from a different process), the out-of-band redesign is
  the alternative: `device.verify.start` would emit `emoji-ready` and then
  *await a registry-backed decision* (e.g. a per-flow `Condvar`/`tokio::Notify`
  or a polled decision slot) set by a separate `device.verify.confirm
  {flow_id}` connection, now safe because IPC is per-connection threaded (#280).
  That path requires: a decision-signaling channel in the registry, reworking
  `run_device_verify` phase 2, new CLI `verify confirm/cancel` subcommands, and
  careful fail-safe re-derivation (the deadline still default-cancels). It is
  strictly more work and re-opens the "second path can confirm" surface, so it is
  deferred. **Confirm this choice before implementation.**
- **External clients.** Assumes no out-of-tree consumer calls
  `device.verify.confirm`/`.cancel`. Given pre-1.0 alpha and that no shipped CLI
  uses them, this is low risk, but worth a one-line changelog note.
- **Test references to the method string.** `read_verify_decision` tests
  intentionally use the literal `"device.verify.confirm"` to prove it is *not*
  the bare `confirm` control frame; keep these (they document the fail-safe), but
  ensure they no longer imply a live method exists.

## Implementation Checklist

1. Read `lifecycle.rs:823`–`896`, `device_ipc.rs:1`–`14`, `:80`–`252`,
   `:700`–end, `lib.rs:88`–`95`, and `docs/architecture.md:1340`–`1360` to
   confirm the current state.
2. Remove the `"device.verify.confirm"` and `"device.verify.cancel"` match arms
   from `dispatch` in `lifecycle.rs`.
3. Delete `confirm_verify`, `cancel_verify`, `VerifyFlowParams`, and
   `VerificationActionResult` from `device_ipc.rs`.
4. Remove `cancel_verify`, `confirm_verify`, `VerificationActionResult`,
   `VerifyFlowParams` from the `device_ipc` re-export block in `lib.rs`.
5. Update the `device_ipc.rs` module doc to drop the two methods and describe the
   in-band confirm/cancel control frame.
6. Prune the serde round-trip tests for the removed types in `device_ipc.rs`;
   keep the `read_verify_decision` fail-safe tests.
7. Add a daemon dispatch test asserting `device.verify.confirm` /
   `device.verify.cancel` now return `METHOD_NOT_FOUND`.
8. Update `docs/architecture.md`: delete the confirm/cancel IPC row and amend the
   `device.verify.start` note.
9. (Optional) Add a coherence note to the #258/#240 specs that #259 is resolved
   in-band.
10. Run `cargo build`, `cargo test -p mx-agent-daemon`,
    `cargo clippy --all-targets -- -D warnings`, and `cargo fmt --check`; fix any
    fallout.
11. Verify no remaining repo references to the removed symbols/methods via
    grep (`device.verify.confirm`, `device.verify.cancel`, `confirm_verify`,
    `cancel_verify`, `VerifyFlowParams`, `VerificationActionResult`) outside
    historical spec prose and the intentional `read_verify_decision` test string.
