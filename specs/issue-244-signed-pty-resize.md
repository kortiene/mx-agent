# Make `com.mxagent.pty.resize.v1` a signed control event (issue #244)

## Problem Statement

PR #243 (issue #238) shipped interactive PTY exec over IPC and the signed Matrix
transport. As a deliberate deviation from the #238 spec (section "A. Protocol:
make `PtyResize` a signed control event"), the merged implementation treats
`com.mxagent.pty.resize.v1` as an **unsigned, sender-authorized window-size
hint** instead of an Ed25519-signed control event.

Resize is therefore the lone live PTY control that is *not* verified against a
locally trusted signing key: `exec.stdin` and `exec.cancel` both go through the
`authorize_live_control` (signature → trust → ownership) gate, while resize is
authorized only by the homeserver-asserted Matrix `sender`. This is a
consistency footgun and a small defense-in-depth gap (a spoofed/compromised
sender could jam a victim invocation's window size). This issue closes that gap.

## Goals

1. `PtyResize` carries `created_at`, `nonce`, and `signature`, mirroring
   `ExecStdin` / `ExecCancel`.
2. The requester side signs every `com.mxagent.pty.resize.v1` it emits.
3. The target side authorizes resize via the **same** `authorize_live_control`
   gate (signature → trust → ownership) used for stdin/cancel.
4. The router classifies resize as a privileged control, consistent with
   stdin/cancel; the replay-handling decision is documented.
5. Tests prove a signed resize is verifiable and that unsigned / untrusted /
   wrong-owner resizes are rejected; end-to-end resize propagation still works.
6. `docs/architecture.md` §7 describes resize as a signed control event.

## Non-Goals

- Changing the PTY-over-IPC sub-protocol (`pty_ipc.rs` IPC frames are unchanged;
  only the *Matrix* `pty.resize` event gains a signature).
- Adding nonce/replay caching for resize in the router (stdin/cancel are not
  router-replay-checked either; resize follows that model — see decision below).
- Any change to non-PTY exec, stdin, or cancel behavior.

## Relevant Repository Context

- `crates/mx-agent-protocol/src/schema.rs`: `PtyResize` content struct and its
  serde round-trip tests; `ExecStdin` / `ExecCancel` are the signed-control
  templates to mirror.
- `crates/mx-agent-daemon/src/exec.rs`:
  - `build_signed_exec_stdin` / `build_signed_exec_cancel` — build+sign helpers
    to mirror with a new `build_signed_pty_resize`.
  - `send_pty_resize` — currently emits an unsigned resize; must sign.
  - `handle_live_pty_resize` — currently sender-authorized; must use
    `authorize_live_control`.
  - `LiveExecControl.requester_user` — added in #243 only for sender-auth resize;
    becomes dead once resize uses `requester_agent`, so it is removed.
- `crates/mx-agent-daemon/src/event_router.rs`: `EventCategory::is_privileged`,
  `classify`, replay/expiry gate.
- `crates/mx-agent-daemon/src/sync.rs`: dispatches `RoutedEvent::PtyResize`.
- `crates/mx-agent-daemon/src/pty_ipc.rs`: two `send_pty_resize` call sites
  (initial size + forwarded resize frames) — both already hold the signing key.
- `crates/mx-agent-daemon/tests/matrix_integration.rs`: ignored two-daemon PTY
  e2e calls `send_pty_resize`.

## Proposed Implementation

1. **Protocol** (`schema.rs`): add `created_at: String`, `nonce: String`,
   `signature: Signature` to `PtyResize` (after the pixel fields, before
   `extra`). Update the struct doc comment to describe a signed control event.
   Update `pty_resize_round_trips` and `pty_resize_defaults_pixels_when_absent`
   to include the new required fields.
2. **Daemon** (`exec.rs`):
   - Add `build_signed_pty_resize(signing_key, key_id, invocation_id, size,
     created_at, nonce) -> Result<Value, SignatureError>` mirroring
     `build_signed_exec_stdin`.
   - Change `send_pty_resize` to take `signing_key` + `key_id`, build via
     `build_signed_pty_resize` with `rfc3339_now()` + `random_control_nonce()`.
   - Change `handle_live_pty_resize` to `(room, paths, content, resize)` and
     authorize via `authorize_live_control(room, paths, content,
     &resize.signature.key_id, &control.requester_agent)`.
   - Remove `LiveExecControl.requester_user` and the `read_agent_state` lookup
     that populated it.
3. **Router** (`event_router.rs`): add `PtyResize` to `is_privileged`; update the
   doc comment; document that resize, like stdin/cancel, is signed + ownership-
   checked in the handler and not router-replay-checked (idempotent, executes
   nothing).
4. **sync.rs**: pass `room`, `paths`, and the serialized `content` to
   `handle_live_pty_resize` (same shape as the `ExecCancel` arm).
5. **pty_ipc.rs**: update both `send_pty_resize` call sites to pass the signing
   key/key id already in scope.
6. **lib.rs**: re-export `build_signed_pty_resize`.
7. **Tests** (`exec.rs`): `build_signed_pty_resize` produces a content value that
   `authorize_control_from_states` accepts for the owner with a trusted key, and
   rejects when unsigned, untrusted, or from a non-owner. Add a schema-level
   round-trip in `schema.rs`.
8. **Docs**: `docs/architecture.md` §7 — add a "Terminal Resize" subsection
   documenting the signed `com.mxagent.pty.resize.v1` event.

### Replay/expiry decision

`exec.stdin` and `exec.cancel` are **not** nonce-replay-checked in the router
(only `exec.request` / `call.request`, which carry `expires_at`, are). Resize
follows the same model: it is signed and ownership-checked in the handler, and is
idempotent (it only sets the current window size of an already-authorized,
running invocation, executing nothing). A replayed resize at most re-applies the
same dimensions. Therefore no router replay-check is added; the decision is
documented in `is_privileged`'s doc comment.

## Affected Files / Crates / Modules

- `crates/mx-agent-protocol/src/schema.rs`
- `crates/mx-agent-daemon/src/exec.rs`
- `crates/mx-agent-daemon/src/event_router.rs`
- `crates/mx-agent-daemon/src/sync.rs`
- `crates/mx-agent-daemon/src/pty_ipc.rs`
- `crates/mx-agent-daemon/src/lib.rs`
- `crates/mx-agent-daemon/tests/matrix_integration.rs`
- `docs/architecture.md`

## CLI / API Changes

No CLI surface change. Public daemon API: `send_pty_resize` signature gains
`signing_key` + `key_id`; new public `build_signed_pty_resize`.

## Data Model / Protocol Changes

`com.mxagent.pty.resize.v1` gains required `created_at`, `nonce`, `signature`
fields. Additive within `v1` (field set only grows; `extra` flatten preserves
forward-compat), consistent with `ExecStdin` / `ExecCancel`.

## Security Considerations

- Resize joins the signature → trust → ownership authorization model. Room
  membership / Matrix sender identity alone no longer authorizes a resize.
- No secrets logged (resize carries only IDs and dimensions).
- Unix-only; no `unsafe`; MSRV 1.74; public APIs documented.

## Testing Plan

- Unit (`schema.rs`): `PtyResize` round-trip with signature; pixel defaults with
  signature present.
- Unit (`exec.rs`): `build_signed_pty_resize` verifiable; unsigned / untrusted /
  wrong-owner rejected via `authorize_control_from_states`.
- E2E: extend the ignored two-daemon PTY integration test's resize call to the
  signed signature (no new scenario required).

## Documentation Updates

`docs/architecture.md` §7 — add a signed-resize subsection.

## Risks and Open Questions

- Backward compatibility: a pre-#244 unsigned resize will now fail to
  deserialize as `PtyResize`. Acceptable in alpha and consistent with how
  `ExecStdin`/`ExecCancel` are modeled; both daemons in a session run the same
  build.

## Implementation Checklist

1. schema.rs: add fields + doc + update round-trip tests.
2. exec.rs: `build_signed_pty_resize`; sign in `send_pty_resize`; authorize in
   `handle_live_pty_resize`; drop `requester_user`.
3. event_router.rs: `is_privileged` += `PtyResize`; document replay decision.
4. sync.rs: pass room/paths/content to handler.
5. pty_ipc.rs: update both call sites.
6. lib.rs: export `build_signed_pty_resize`.
7. matrix_integration.rs: update resize call.
8. exec.rs tests: signed resize accept/reject cases.
9. docs/architecture.md §7.
10. `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D
    warnings`, `cargo test --all`, `cargo build --all`.
