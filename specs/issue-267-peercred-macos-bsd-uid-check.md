# SO_PEERCRED Peer-UID Check on macOS/BSD (issue #267)

## Problem Statement

The local-IPC peer-credential check that enforces the daemon's same-UID
invariant is implemented **only on Linux/Android**. On macOS — a first-class
supported target (release binaries are built for `x86_64-apple-darwin` and
`aarch64-apple-darwin`) — `verify_peer_against` resolves to
`PeerCredCheck::Unsupported`, which `is_allowed()` permits and `serve_streaming`
proceeds past after one warning. The net effect: on macOS the daemon's
defence-in-depth UID authentication **silently does not hold**, leaving only the
`0600` socket mode under a `0700` runtime directory as access control.

Compounding the gap, the README advertises the `SO_PEERCRED` peer check as
universally "Implemented" with no platform caveat, presenting a stronger
security posture than ships on macOS. (The deeper docs — `docs/architecture.md`
§10.2 and `docs/security-hardening.md` §"CLI ⇄ daemon isolation" — are already
honest and scope the check to Linux/Android.)

The fix is to close the implementation gap on macOS/BSD using the safe
`nix::sys::socket::sockopt::LocalPeerCred` (`LOCAL_PEERCRED`) wrapper, so the
same-UID invariant holds on macOS without any `unsafe` (the workspace forbids
it), and to align documentation with reality.

## Goals

- Implement a peer-UID check on macOS/iOS and the BSDs that retrieves the peer
  UID via the safe `nix` `LocalPeerCred` sockopt and compares it against the
  daemon's effective UID, returning `Allowed`/`Denied` exactly as the Linux arm
  does, so `serve_streaming` rejects cross-UID clients on macOS.
- Keep the implementation `unsafe`-free, MSRV 1.74-compatible, and within the
  already-enabled `nix` `socket` feature (add a feature only if `LocalPeerCred`
  requires one).
- Add unit tests mirroring the existing Linux-gated tests: a same-UID
  `UnixStream::pair()` peer yields `Allowed`, and a forced UID mismatch yields
  `Denied`, gated to the macOS/BSD `cfg`.
- Exercise the macOS path in CI by adding a macOS job (or matrix entry) that runs
  at least the `mx-agent-ipc` test suite, since every current `ci.yml` job runs
  on `ubuntu-latest` and never compiles or tests the macOS arm.
- Correct the README so the `SO_PEERCRED` claims accurately describe what ships:
  either drop the platform caveat (now that macOS is covered) by generalizing the
  wording to "peer-UID check," or, if a residual `Unsupported` fallback remains
  for unsupported platforms, qualify it precisely.
- Update `docs/security-hardening.md` line 56 / line 88-89 to match the new
  platform coverage.

## Non-Goals

- No change to the JSON-RPC protocol, IPC framing, or any CLI surface.
- No change to the Linux/Android `SO_PEERCRED` arm's behavior.
- No Windows support or Windows-specific code paths (project is Unix-only).
- Not solving the deeper unsupported-platform philosophy question (whether
  `Unsupported` should ever be permitted): platforms genuinely lacking a peer
  credential mechanism keep the current `0600`-fallback behavior. The scope here
  is to make macOS/BSD `Allowed`/`Denied` rather than `Unsupported`.
- Not addressing #258 (IPC availability/accept-loop concurrency) beyond noting
  the peer check stays on the accept thread before any worker is spawned, which
  the macOS arm must preserve.

## Relevant Repository Context

- **Owning crate:** `crates/mx-agent-ipc` — the local IPC transport between CLI
  and daemon.
- **`crates/mx-agent-ipc/src/peercred.rs`** — the peer-credential logic:
  - `PeerCredCheck` enum (`Allowed { uid }`, `Denied { peer_uid, daemon_uid }`,
    `Unsupported`).
  - `is_allowed()` (lines 46-48): returns `true` for everything except `Denied`,
    so `Unsupported` is permitted (filesystem-perms fallback).
  - `verify_peer` (lines 56-59): reads `geteuid()` and delegates to
    `verify_peer_against`.
  - `verify_peer_against` Linux/Android arm (lines 61-82): `getsockopt(fd,
    PeerCredentials)` → compare `cred.uid()` to `daemon_uid`. On `getsockopt`
    error, returns `Unsupported` (defined, observable fallback).
  - `verify_peer_against` non-Linux arm (lines 84-87): unconditionally
    `Unsupported`. **This is the arm to split for macOS/BSD.**
  - Test module (lines 89-141): `allows_same_uid_peer_on_linux`,
    `denied_is_not_allowed`, `unsupported_is_allowed_fallback`,
    `wrong_uid_is_denied` — all gated with `#[cfg(any(target_os = "linux",
    target_os = "android"))]` for the platform-specific assertions.
- **`crates/mx-agent-ipc/src/server.rs`** — `serve_streaming` (lines 84-135):
  calls `verify_peer` on the accept thread (line 93), then matches:
  `Allowed` → proceed; `Denied` → `tracing::warn!` UIDs + `drop(stream)` +
  `continue`; `Unsupported` → warn once (latched via `warned_unsupported`) and
  proceed. Connections are served on detached worker threads; the peer check
  stays on the accept thread (issue #258). No change needed to the match arms —
  on macOS the result simply becomes `Allowed`/`Denied` instead of
  `Unsupported`, which the existing arms already handle. The once-only
  `Unsupported` warning will simply stop firing on macOS.
- **`crates/mx-agent-ipc/Cargo.toml`** (line 12): `nix = { workspace = true,
  features = ["socket"] }` — the `socket` feature is already enabled.
- **Root `Cargo.toml`**: `nix = "0.31"` (workspace dep, line 39);
  `unsafe_code = "forbid"` and `missing_docs = "warn"` (lines 49-51); MSRV
  `rust-version = "1.74"` (line 16).
- **`.github/workflows/ci.yml`**: jobs `docs`, `shell`, `adw`, `rust`,
  `cargo-deny`, `matrix-integration` — **all `runs-on: ubuntu-latest`.** The
  `rust` job runs `cargo fmt --check`, `cargo clippy --all-targets --all-features
  -- -D warnings`, `cargo build --all`, `cargo test --all`. No macOS runner
  exists, so the macOS `cfg` arm is never compiled or tested today.
- **`docs/architecture.md` §10.2** (around lines 1265-1279): already documents
  the Linux/Android scope and the `Unsupported` fallback honestly — use as the
  source of truth for wording.
- **README claims to correct:** line 42 (status table), line 120
  (security-properties bullet), lines 206-208 (daemon-lifecycle prose).
- **`docs/security-hardening.md` to correct:** line 56 (secrets table: "IPC
  socket | `0600`, peer-UID checked") and lines 87-89 ("On Linux the daemon
  additionally checks the peer credentials (`SO_PEERCRED`)…").

### `nix` API note (verify before coding)

The recommended call is `nix::sys::socket::sockopt::LocalPeerCred`
(`LOCAL_PEERCRED`), a safe `GetSockOpt` wrapper available on
macOS/iOS/FreeBSD. On those platforms it yields a credentials struct (commonly
`nix::sys::socket::XuCred`) exposing `.uid()`. The coding agent must confirm,
against the actual `nix` 0.31 source in the build environment:

1. The exact sockopt type name and which `cfg(target_os = ...)` set it is gated
   to in `nix` 0.31 (typically `macos`, `ios`, `freebsd`; **NetBSD/OpenBSD may
   not be covered** — `LOCAL_PEERCRED` is not universal across the BSDs).
2. The returned struct's UID accessor (`.uid()` returning a `uid_t`/`u32`).
3. Whether any additional `nix` feature beyond `socket` is required (it should
   not be).

The macOS/BSD `cfg` set in `verify_peer_against` must exactly match the platform
set `nix` actually gates `LocalPeerCred` to — do not list `target_os` values
`nix` does not support, or the build will fail on those targets. Any Unix target
not covered by the new arm continues to fall through to the existing
`Unsupported` arm.

## Proposed Implementation

This is the suggested-fix **(A)** path (implement the macOS arm), which also
makes the README claims true and avoids needing the **(B)** caveat-only path.

1. **Split the non-Linux arm in `peercred.rs`.** Replace the single
   `#[cfg(not(any(target_os = "linux", target_os = "android")))]` arm with two:
   - A new `#[cfg(any(target_os = "macos", target_os = "ios", target_os =
     "freebsd"))]` (final set to match `nix`'s actual support) arm that:
     - imports `getsockopt`, `sockopt::LocalPeerCred`, and `std::os::unix::io::AsFd`;
     - calls `getsockopt(&stream.as_fd(), LocalPeerCred)`;
     - on `Ok(cred)`, reads `cred.uid()` into `peer_uid` and returns
       `Allowed { uid: peer_uid }` if `peer_uid == daemon_uid` else
       `Denied { peer_uid, daemon_uid }` — structurally identical to the Linux
       arm;
     - on `Err(_)`, returns `PeerCredCheck::Unsupported` (same defensive
       fallback as the Linux arm's `getsockopt` error path).
   - A final `#[cfg(not(any(... linux, android, macos, ios, freebsd ...)))]`
     fallback arm that keeps returning `Unsupported` for any remaining Unix
     target.
2. **Optionally factor shared logic.** The Linux and macOS arms differ only in
   the sockopt type and the credential struct's accessor. A small private helper
   that takes `peer_uid: u32` and `daemon_uid: u32` and returns the
   `Allowed`/`Denied` decision can de-duplicate the comparison, keeping each
   `cfg` arm to just the `getsockopt` call + uid extraction. Keep it simple;
   mirroring the existing arm verbatim is acceptable if a helper adds noise.
3. **Update module/doc comments.** Adjust the module doc (lines 1-13) and
   `verify_peer` / `verify_peer_against` doc comments so they no longer imply
   "Linux only" — describe Linux/Android via `SO_PEERCRED` and macOS/BSD via
   `LOCAL_PEERCRED`, with `Unsupported` reserved for platforms with no mechanism.
   `missing_docs = "warn"` requires any new public item to be documented (the new
   arm is a private fn body, so no new public surface is expected).
4. **No change to `server.rs` logic.** The existing `Allowed`/`Denied`/`Unsupported`
   match arms already handle every case; on macOS the result now becomes
   `Allowed`/`Denied`. Confirm the `warned_unsupported` latch still compiles and
   behaves (it simply won't fire on macOS).
5. **Tests** (see Testing Plan): generalize the Linux-gated tests so the
   same-UID-allows / wrong-UID-denies assertions also run under the macOS/BSD
   `cfg`, and adjust `wrong_uid_is_denied`'s `#[cfg(not(...))]` branch so it only
   expects `Unsupported` on platforms genuinely without a mechanism.
6. **CI** (see below): add a macOS job running the IPC tests so the new arm is
   compiled, linted, and tested.

## Affected Files / Crates / Modules

- `crates/mx-agent-ipc/src/peercred.rs` — add macOS/BSD `verify_peer_against`
  arm; adjust the fallback `cfg`; update doc comments; extend/adjust tests.
- `crates/mx-agent-ipc/Cargo.toml` — only if `LocalPeerCred` needs a `nix`
  feature beyond `socket` (likely not).
- `crates/mx-agent-ipc/src/server.rs` — read-only; confirm no change needed
  (document in PR that the match already handles the new outcomes).
- `.github/workflows/ci.yml` — add a macOS job/matrix entry running at least
  `cargo test -p mx-agent-ipc` (plus `cargo clippy` for the IPC crate) on
  `macos-latest`.
- `README.md` — lines 42, 120, 206-208: correct the `SO_PEERCRED` claims.
- `docs/security-hardening.md` — line 56 and lines 87-89: reflect macOS/BSD
  coverage.
- `docs/architecture.md` §10.2 (lines ~1265-1279) — update to state macOS/BSD is
  now covered via `LOCAL_PEERCRED` (it currently says only Linux/Android, with
  macOS falling back to `Unsupported`).

## CLI / API Changes

None. No command-line flags, subcommands, or help text change. `PeerCredCheck`
and `verify_peer` remain the same public API with the same variants; only the
platform behavior of the private `verify_peer_against` changes.

## Data Model / Protocol Changes

None. No event schema, persistence, policy, serialization, or JSON-RPC wire
changes. The peer check is a transport-admission gate that runs before any frame
is read.

## Security Considerations

- **Strengthens the same-UID invariant on macOS**, closing a real
  defence-in-depth gap: cross-UID clients connecting to the socket are now
  rejected on macOS as they already are on Linux, rather than admitted under the
  `0600`-only fallback.
- **No `unsafe`.** `LocalPeerCred` is a safe `nix` wrapper; the workspace's
  `unsafe_code = "forbid"` is respected. Do not hand-roll `getsockopt` via
  `libc`/raw FFI.
- **Logging/redaction unchanged.** The `Denied` audit log records only
  `peer_uid` and `daemon_uid` (no payloads, no secrets), matching the existing
  Linux path. The macOS arm must not log anything additional, and must not read
  any request bytes before the admission decision.
- **Accept-thread placement preserved.** The check must stay on the accept
  thread before the worker thread is spawned (issue #258), so concurrency never
  weakens the UID gate.
- **Fallback semantics.** `Err(_)` from `getsockopt` continues to map to
  `Unsupported` (permitted, filesystem-perms fallback) rather than `Denied`, to
  avoid bricking the daemon on a kernel that unexpectedly refuses the sockopt —
  matching the Linux arm's existing posture. Note in the PR that this `Err`
  fallback is a deliberate availability choice, not a silent bypass (it is logged
  once by `serve_streaming`).
- **Daemon/CLI separation, signing, policy, replay** — all unaffected; this
  change is purely at the IPC admission layer and does not touch tokens, device
  keys, Ed25519 signing, trust, or policy enforcement.
- **Honest docs.** Correcting the README removes a security over-claim; ensure
  the new wording does not over-claim coverage on BSDs that `nix` does *not*
  support (e.g. if NetBSD/OpenBSD remain `Unsupported`, do not imply otherwise).

## Testing Plan

- **Unit tests in `peercred.rs`:**
  - Generalize `allows_same_uid_peer_on_linux` (rename to e.g.
    `allows_same_uid_peer`) so its `Allowed { uid: me }` assertion is gated to
    `#[cfg(any(linux, android, macos, ios, freebsd))]` — every platform with a
    real mechanism. A same-process `UnixStream::pair()` peer must yield
    `Allowed`.
  - Generalize `wrong_uid_is_denied`: under the mechanism-supported `cfg` assert
    `Denied { peer_uid: me, daemon_uid: bogus }`; under the no-mechanism `cfg`
    assert `Unsupported`. Update the `cfg` sets accordingly.
  - Keep `denied_is_not_allowed` and `unsupported_is_allowed_fallback` as-is
    (platform-independent enum behavior).
  - Optionally add an explicit `verify_peer_against` test on macOS confirming the
    `LocalPeerCred` path returns `Allowed` for a same-UID pair (covered by the
    generalized test, but an explicit macOS-gated assertion documents intent).
- **CI:**
  - Add `.github/workflows/ci.yml` macOS coverage: a job on `macos-latest`
    running `cargo test -p mx-agent-ipc` and `cargo clippy -p mx-agent-ipc
    --all-targets -- -D warnings` (scope to the IPC crate to keep the job fast
    and avoid pulling the full Matrix/daemon toolchain on macOS, unless a broader
    macOS build is desired). This is the only way the macOS `cfg` arm gets
    compiled, linted, and run.
  - Confirm `cargo fmt --check`, `clippy -D warnings`, and `cargo build --all`
    still pass on Linux (existing `rust` job) with the new `cfg` arms — clippy
    must not flag dead code or unused imports on Linux (the macOS imports live
    inside the macOS-gated fn body).
- **Manual/local verification (if a macOS dev machine is available):** start the
  daemon and confirm a same-UID CLI connects, and that the once-only
  `Unsupported` warning no longer appears in `daemon.log` on macOS.

## Documentation Updates

- **README.md:**
  - Line 42 (status table): change "`0600` perms + `SO_PEERCRED` peer check" to
    wording covering both mechanisms, e.g. "`0600` perms + peer-UID check
    (`SO_PEERCRED` on Linux, `LOCAL_PEERCRED` on macOS/BSD)".
  - Line 120 (security-properties bullet): generalize "enforces a `SO_PEERCRED`
    UID check" to "enforces a peer-UID check" (mechanism per platform).
  - Lines 206-208 (daemon-lifecycle prose): "verifies the peer UID via
    `SO_PEERCRED`" → "verifies the peer UID (`SO_PEERCRED` on Linux,
    `LOCAL_PEERCRED` on macOS/BSD)".
- **docs/security-hardening.md:**
  - Line 56 (secrets table): keep "peer-UID checked" (already platform-neutral);
    optionally footnote the mechanism.
  - Lines 87-89: change "On Linux the daemon additionally checks the peer
    credentials (`SO_PEERCRED`)…" to also cover macOS/BSD via `LOCAL_PEERCRED`,
    and note that any platform without a mechanism falls back to `0600` + `0700`.
- **docs/architecture.md §10.2 (lines ~1265-1279):** update the bullet list so
  macOS/BSD is described as covered (peer UID via `LOCAL_PEERCRED`), and reserve
  the `Unsupported`/filesystem-fallback bullet for platforms with no mechanism.
- **Regression guard:** if `scripts/check-doc-claims.sh` is extended for this
  area, ensure it does not flag the corrected (accurate) wording. (Not strictly
  required; mentioned for awareness since `ci.yml` runs that lint.)

## Risks and Open Questions

- **`nix` 0.31 API surface (must verify before coding):** confirm the exact
  sockopt name (`LocalPeerCred`), the returned struct and its `.uid()` accessor,
  and the precise `cfg(target_os)` set `nix` gates it to. `LOCAL_PEERCRED` is
  **not** available on all BSDs — NetBSD/OpenBSD likely remain `Unsupported`. The
  `cfg` in `verify_peer_against` must match `nix`'s support set exactly or the
  build breaks on those targets.
- **macOS `XuCred` quirk:** historically `getsockopt(LOCAL_PEERCRED)` on macOS
  can report a stale/struct-version-tagged credential for `socketpair()`-created
  pairs in some OS versions. The unit test uses `UnixStream::pair()`; verify on a
  real `macos-latest` runner that `cred.uid()` equals the current euid for a
  same-process pair. If a pair does not reliably report the UID on macOS, the
  test may need to use a real `UnixListener`/`UnixStream::connect` pair instead
  of `pair()`. **This is the single most likely source of a flaky/failing test —
  validate early on the macOS runner.**
- **CI cost/time:** adding a `macos-latest` job consumes macOS runner minutes
  (more expensive than Linux). Scoping it to `-p mx-agent-ipc` keeps it minimal;
  decide whether a broader macOS build is wanted.
- **Caveat-only fallback (option B):** if, after investigation, implementing the
  macOS arm is deferred, the minimum acceptable outcome is correcting README
  lines 42/120/206-208 and `docs/security-hardening.md` to state the check is
  Linux/Android only and macOS relies on `0600` + `0700`. The spec recommends
  **not** settling for B given `nix` already ships `LocalPeerCred` safely.
- **Relation to #258:** the peer check must remain on the accept thread before
  worker spawn; the macOS arm does not change threading but the implementer
  should not accidentally move the check.

## Implementation Checklist

1. In the build environment, inspect `nix` 0.31 `src/sys/socket/sockopt.rs` to
   confirm `LocalPeerCred`, its returned credential type, the `.uid()` accessor,
   the gating `cfg(target_os)` set, and any required feature.
2. In `crates/mx-agent-ipc/src/peercred.rs`, replace the single non-Linux
   `verify_peer_against` arm with:
   a. a macOS/BSD arm (`cfg` matching `nix`'s `LocalPeerCred` support) that does
      `getsockopt(&stream.as_fd(), LocalPeerCred)`, extracts `peer_uid` via
      `.uid()`, and returns `Allowed`/`Denied` vs `daemon_uid`, with `Err(_) =>
      Unsupported`;
   b. a final `cfg(not(any(linux, android, <macos/bsd set>)))` arm that returns
      `Unsupported`.
3. Optionally extract a tiny `decide(peer_uid, daemon_uid) -> PeerCredCheck`
   helper shared by both mechanism arms.
4. Update the module doc comment and `verify_peer` / `verify_peer_against` doc
   comments to describe Linux/Android (`SO_PEERCRED`) and macOS/BSD
   (`LOCAL_PEERCRED`), reserving `Unsupported` for platforms with no mechanism.
5. Generalize the `cfg` gates on the `allows_same_uid_peer*` and
   `wrong_uid_is_denied` tests so the `Allowed`/`Denied` assertions run on every
   mechanism-supported platform, and the `Unsupported` expectation only applies
   to no-mechanism platforms.
6. Confirm `crates/mx-agent-ipc/src/server.rs` needs no change (existing match
   handles all outcomes); do not move the `verify_peer` call off the accept
   thread.
7. Add `nix` feature to `crates/mx-agent-ipc/Cargo.toml` only if step 1 shows
   `LocalPeerCred` requires one.
8. Add a `macos-latest` job (or matrix entry) to `.github/workflows/ci.yml`
   running `cargo test -p mx-agent-ipc` and `cargo clippy -p mx-agent-ipc
   --all-targets -- -D warnings`.
9. Validate on the macOS runner that the same-UID `UnixStream::pair()` test
   passes; if `pair()` does not reliably report the UID via `LOCAL_PEERCRED`,
   switch the test to a real `connect()`-based pair.
10. Run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D
    warnings`, `cargo build --all`, and `cargo test --all` on Linux; confirm no
    unused-import/dead-code warnings from the new `cfg` arms.
11. Correct README lines 42, 120, 206-208 and `docs/security-hardening.md` lines
    56, 87-89; update `docs/architecture.md` §10.2 to state macOS/BSD coverage.
12. Re-read the changed docs against `scripts/check-doc-claims.sh` expectations
    so the doc-claims CI lint still passes.
