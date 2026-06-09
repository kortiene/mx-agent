# Production E2EE Hardening: Device Verification, Cross-Signing, Key Backup

> Issue: #240 — Production E2EE hardening (device verification UX, cross-signing,
> key backup/recovery). Split out from epic #191. Roadmap phase 16 ("Hardening and
> Release"). Labels: `type:feature` `area:daemon` `area:matrix` `area:security`
> `priority:p2`.

## Problem Statement

The daemon already decrypts privileged end-to-end-encrypted (E2EE) events and runs
them through the normal verify → trust → policy → runner pipeline, and it fails
safe by skipping any `m.room.encrypted` event it cannot decrypt before that event
reaches a handler (`crates/mx-agent-daemon/src/event_router.rs:322-325`,
`RouteOutcome::SkippedEncrypted`). That covers *confidentiality on receipt* and the
fail-closed invariant, and it is exercised by the `#[ignore]`d
`daemon_e2ee_privileged_event_coverage` integration test in the
`matrix-integration` CI job.

What is missing is the *production hardening* around that core:

1. **No device verification.** Encrypted sessions are established TOFU (trust on
   first use): the daemon will happily share Megolm keys with, and accept
   decrypted traffic from, any device in the room. Operators have no way to verify
   a peer device (emoji/SAS or out-of-band fingerprint), so a malicious or spoofed
   device that joins an encrypted workspace can read or inject encrypted traffic
   without anyone noticing.

2. **No cross-signing.** Device trust is not anchored to a user identity, so trust
   does not transit across a peer's devices and there is no published identity to
   pin against.

3. **No persistent crypto store and no key backup.** The daemon builds its Matrix
   client with `Client::builder().homeserver_url(...).build()`
   (`crates/mx-agent-daemon/src/matrix.rs:166-179`, `262-291`) and **never
   configures a crypto store**. Worse, in production builds the `e2e-encryption`
   feature is not even compiled in — it is enabled only under `[dev-dependencies]`
   for the test binary (`crates/mx-agent-daemon/Cargo.toml:40-46`). A daemon
   restart or re-provision therefore regenerates device/session state and silently
   loses the ability to decrypt history; there is no server-side key backup or
   documented recovery path.

4. **Trust-model ambiguity.** The relationship between *Matrix device trust* (the
   E2EE identity) and the *mx-agent Ed25519 signing trust* (the local trust store
   that authorizes privileged actions) is asserted in `docs/architecture.md` §1.2
   but not specified operationally. We must state, and enforce, that the two are
   distinct and that execution authority never derives from device verification.

This spec plans the work to close those gaps while preserving every existing
security invariant.

## Goals

- **Compile and persist E2EE in production.** Ship the daemon with the matrix-sdk
  crypto stack enabled and a persistent, daemon-owned crypto store at
  `~/.local/share/mx-agent/crypto-store/` (`0700`), so identity and Megolm
  sessions survive a restart.
- **Device verification UX.** Give operators a daemon-mediated, stateless-CLI way
  to (a) list peer devices with their verification status and fingerprints, (b)
  run an interactive emoji/SAS verification, and (c) verify a device out-of-band
  by comparing/entering its fingerprint. All crypto state stays in the daemon.
- **Cross-signing.** Bootstrap the daemon's own cross-signing identity, publish it,
  and observe peers' cross-signing identities so that verifying a user's identity
  marks their cross-signed devices verified. Local mx-agent trust remains the
  authoritative gate on execution.
- **Key backup / recovery.** Enable secure server-side key backup (Secure Secret
  Storage + key backup via the matrix-sdk `Recovery` API) behind an operator
  command, surface a recovery key once for the operator to store, and document the
  restore-after-restart / re-provision procedure. A restart must not silently lose
  decryptability.
- **Specify the two-trust-layer interaction.** Document, and where chosen enforce,
  that Matrix device verification governs *transport confidentiality/integrity*
  while mx-agent Ed25519 signing + local trust + local policy govern *execution* —
  both must hold for a privileged action, and device presence/membership/
  verification alone never authorizes execution.
- **Tests.** Add integration coverage for the verified-device happy path, the
  unverified-device handling path, and key-backup restore across a daemon restart,
  wired into the existing `matrix-integration` `#[ignore]`d suite.
- **No regressions.** Keep the fail-safe (undecryptable events never execute),
  keep the CLI stateless, keep all secrets out of logs, and keep
  signing+trust+policy as the execution gate.

## Non-Goals

- **Room-level E2EE on `workspace create`** (the `--e2ee` flag). That is the
  sibling concern tracked under #249 and `docs/architecture.md:118-121`; this spec
  assumes encrypted rooms exist and hardens the daemon's behavior inside them. The
  two should land compatibly but are separate PRs.
- **Replacing the mx-agent Ed25519 signing/trust model with Matrix device trust.**
  The local signing-key trust store stays the authoritative execution gate.
- **Automatic, unattended cross-user trust.** No silent TOFU promotion to
  "verified". Verification is an explicit operator action (or an explicit policy
  opt-in for cross-signed transit).
- **Full key-rotation/revocation automation** (deferred per architecture §17 "Defer
  until after MVP").
- **Windows / cross-platform key storage** (Keychain/DPAPI). Unix-only; the crypto
  store and recovery metadata live in the daemon's `0700`/`0600` data dir.
- **New `com.mxagent.*` timeline event types.** Device verification, cross-signing,
  and key backup ride standard Matrix endpoints (to-device SAS, cross-signing key
  upload, server-side key backup) handled by matrix-sdk; no new mx-agent protocol
  event is required (see Data Model section).

## Relevant Repository Context

**Architecture.** The daemon owns all long-lived Matrix state, including "E2EE
sessions and device verification" and the crypto store (`docs/architecture.md`
§10.1, §13.1). The CLI is stateless and reaches the daemon only over the
`0600`/`SO_PEERCRED` Unix-socket JSON-RPC channel; it never restores a Matrix
client or sees tokens/device keys (§10.3, README "Project status"). §1.2 already
names the three independent identities (Matrix user, Matrix device/E2EE identity,
mx-agent Ed25519 signing identity) and says privileged operations should verify all
applicable layers. §13.1 already reserves `~/.local/share/mx-agent/crypto-store/`
(`0700`) — but nothing writes it yet. §13.2 documents the trust modes table where
"Matrix device verified" trust is listed as **Planned (not yet implemented)**.

**Owning crate: `mx-agent-daemon`.** Relevant modules:

- `src/matrix.rs` — `build_client` / `restore_client` / `login_password`. This is
  where the crypto store and `e2e-encryption` must be wired (today: no store
  config; in-memory crypto only under the test feature).
- `src/session.rs` — `SessionPaths` (resolves the `0700` data dir), `StoredSession`,
  the `Secret` redaction type. New crypto-store path and recovery metadata resolve
  here.
- `src/sync.rs` — `run_matrix_sync` / `run_matrix_sync_with_subscribers` drive
  `client.sync_once`, which is what uploads device keys and decrypts. To-device
  verification events flow through sync; this is where verification-flow handling
  is observed.
- `src/event_router.rs` — `EventRouter::route` enforces the fail-safe
  (`SkippedEncrypted` at lines 322-325). Must remain unchanged in its guarantees;
  any "require verified device" gate is layered *after* decryption, inside the
  privileged handlers, not here.
- `src/exec.rs` / `src/call.rs` — `authorize_exec_request*` / `call` authorization.
  The execution gate (signature → `TrustStore::is_key_trusted` → policy) lives
  here; an optional `require_verified_device` policy check is layered here, never
  replacing the existing gate.
- `src/trust.rs` / `src/trust_state.rs` — the authoritative local trust store
  (`trust.json`, `0600`) and the advisory room-published `com.mxagent.trust.v1`
  state. The Ed25519 signing-trust model that must stay authoritative.
- `src/signing.rs` — Ed25519 signing key (`signing_key.ed25519`, `0600`), key id
  `mxagent-ed25519:<sha256-b64>`. Distinct from Matrix device keys.
- `src/lifecycle.rs` — restores the client and launches the sync thread
  (`restore_client` → `run_matrix_sync_with_subscribers`). Cross-signing bootstrap
  / backup enablement at startup hooks here.
- `src/ipc.rs`, `src/*_ipc.rs` — IPC method dispatch pattern (e.g. `call_ipc.rs`,
  `exec_ipc.rs`, `pty_ipc.rs`). New `device.*` / `recovery.*` / `cross_signing.*`
  methods follow this pattern; the interactive verification flow follows the
  multi-frame streaming pattern already used by `task.watch`.

**CLI: `mx-agent-cli`.** Command groups are defined in `src/cli.rs` (`AuthCommand`
≈ lines 120-138, `TrustCommand` ≈ lines 715-787) and dispatched to daemon IPC.
There is **no** `device`, `verify`, or `recovery` surface today.

**matrix-sdk.** Workspace pins `matrix-sdk = "0.18"` with `default-features =
false` (`Cargo.toml:31`). The crypto features needed are `e2e-encryption` (already
used in dev) plus a persistent store backend (`matrix-sdk-sqlite` via the
`sqlite`/`bundled-sqlite` feature, or `matrix-sdk`'s `sqlite` feature). matrix-sdk
0.18 exposes `client.encryption()` with verification (`request_verification`,
`SasVerification`, emoji/decimal), cross-signing
(`Encryption::bootstrap_cross_signing`), and recovery/backup (`Encryption::recovery()`,
`Recovery::enable`, `Recovery::recover`, Secure Secret Storage). The implementer
must confirm the exact 0.18 API surface and feature flags (see Open Questions).

**CI.** `.github/workflows/ci.yml` runs a `matrix-integration` job that executes
`scripts/matrix_integration_test.sh --teardown`, which boots a throwaway Tuwunel
homeserver and runs the `#[ignore]`d daemon integration tests (including
`daemon_e2ee_privileged_event_coverage` in
`crates/mx-agent-daemon/tests/matrix_integration.rs`). New E2EE tests extend this
suite, not the default `cargo test --all`.

## Proposed Implementation

Implement in four layered stages; each stage is independently shippable and keeps
all existing invariants.

### Stage 1 — Persistent crypto store in production (foundation)

1. **Enable the crypto stack in production builds.** Move `e2e-encryption` (and the
   chosen persistent store feature) from `[dev-dependencies]` to the daemon's
   regular `matrix-sdk` dependency in `crates/mx-agent-daemon/Cargo.toml`. Keep the
   workspace pin and `default-features = false`; enable features per-crate. Verify
   the production binary still builds on MSRV 1.74 and that `cargo build --all`
   (no dev-deps) now links the crypto stack.
2. **Resolve a crypto-store path.** Add `crypto_store_dir` to `SessionPaths`
   (`src/session.rs`), resolving to `<data_dir>/crypto-store`, created `0700` via
   the existing `ensure_data_dir` pattern. Document it as daemon-owned, never
   agent-readable.
3. **Configure the store on build/restore.** In `src/matrix.rs`, set a
   SQLite-backed crypto/state store via `Client::builder().sqlite_store(path,
   passphrase)` (or the 0.18 equivalent `StoreConfig`) in `build_client`,
   `restore_client`, and `login_password`. The store passphrase is a daemon secret:
   generate it once, wrap it in `Secret`, persist it `0600` in the data dir (e.g.
   `crypto-store-key`), and never log it. Restore must reuse the same device id and
   the same store so the daemon resumes as the same E2EE device after a restart.
4. **Verify decryptability persists.** Add a test (Stage-4 suite) proving the
   daemon can decrypt a message after a simulated restart using only the persisted
   store. No behavior change to the event router or fail-safe.

### Stage 2 — Device verification UX

1. **Daemon-side verification manager.** Add `src/verification.rs` (and
   `src/device_ipc.rs`) owning the interactive verification state. It exposes:
   - **list devices** for a given user (default: peers in a room, or all of the
     daemon's own user's devices): device id, display name, the Matrix device
     fingerprint (Ed25519 *device* key, distinct from the mx-agent signing key),
     and verification status (`verified` / `unverified` / `blacklisted`).
   - **start SAS** with a target user+device: returns the emoji (and decimal)
     short-authentication string for the operator to compare out-of-band.
   - **confirm / cancel** the in-flight SAS once the operator has compared.
   - **manual verify**: mark a device verified after the operator confirms a
     fingerprint match supplied out-of-band (no SAS round-trip).
2. **Drive verification through sync.** SAS verification rides to-device events;
   `run_matrix_sync` already drives `sync_once`. Register the matrix-sdk
   verification handlers so incoming verification requests are observable and the
   manager can advance the flow. The router's `SkippedEncrypted` fail-safe is
   unaffected (to-device verification events are not `m.room.encrypted` privileged
   requests).
3. **IPC + CLI.** Add IPC methods `device.list`, `device.show`,
   `device.verify.start`, `device.verify.confirm`, `device.verify.cancel`,
   `device.verify.manual`. Because SAS is interactive, model `device.verify.start`
   like `task.watch`: keep the socket open and stream flow updates
   (`emoji-ready`, `confirmed`, `cancelled`, `done`) so the CLI can show the emoji,
   prompt the operator, and send `confirm`/`cancel`. Add a stateless CLI group
   `mx-agent device { list | show | verify }` with human-readable output by default
   and `--json` for automation. The CLI receives only fingerprints, emoji/decimal
   SAS, and status — **never key material**.
4. **No execution-path change by default.** Verification status is informational by
   default; see Stage 4 for the optional `require_verified_device` policy gate.

### Stage 3 — Cross-signing + key backup / recovery

1. **Cross-signing.** On first authenticated start (or via an explicit
   `mx-agent auth cross-signing bootstrap` command), call
   `client.encryption().bootstrap_cross_signing(...)` to create and publish the
   daemon's master/self-signing/user-signing keys. Bootstrapping touches Secure
   Secret Storage, so coordinate it with Stage-3 recovery (one passphrase/recovery
   key). Observe peers' cross-signing identities during sync so that verifying a
   user's identity (via SAS to one of their devices) marks their other
   cross-signed devices verified. Surface cross-signing status in `device list`
   and a new `auth cross-signing status`.
2. **Key backup / recovery.** Behind an explicit operator command
   `mx-agent recovery enable`, call `client.encryption().recovery().enable()` (or
   the 0.18 equivalent) to provision Secure Secret Storage + server-side key
   backup. Return the generated **recovery key once** over IPC for the operator to
   record; treat it as a `Secret` end-to-end (never logged, never persisted in
   clear, surfaced to the human exactly once). Add `recovery status` (enabled?
   backup version? keys backed up count) and `recovery recover` (re-import keys
   from server-side backup using an operator-supplied recovery key/passphrase),
   used after a re-provision onto a fresh host.
3. **Restart vs re-provision.** Document the distinction: a *restart* on the same
   host recovers transparently from the persistent crypto store (Stage 1); a
   *re-provision* onto a fresh host or a wiped store recovers history via
   `recovery recover` + the recovery key (Stage 3). Both paths must end with the
   daemon able to decrypt prior privileged events.

### Stage 4 — Two-trust-layer specification + optional enforcement

1. **Document the interaction (authoritative).** In `docs/architecture.md` §1.2 and
   §13.2 and `docs/security-hardening.md`, specify precisely:
   - *Matrix device verification* establishes **who you share Megolm keys with and
     who can read/inject encrypted transport** — it protects confidentiality and
     integrity of the channel.
   - *mx-agent Ed25519 signing + local trust store + local policy* establish **who
     may cause a privileged action to execute**.
   - For a privileged action delivered over E2EE, **both must hold**: the event
     must decrypt (transport), *and* it must carry a valid Ed25519 signature from a
     locally-trusted signing key that policy permits (execution). Neither room
     membership, device presence, nor device verification ever substitutes for
     signing+trust+policy. Update the §13.2 trust-modes table to reflect that
     "Matrix device verified" trust is now an *advisory transport signal*, not an
     execution grant.
2. **Optional enforcement knob.** Add an opt-in policy field
   `require_verified_device` (per-room / per-agent, default `false`). When `true`,
   the privileged handlers in `exec.rs`/`call.rs`, *after* the existing
   signature → trust → policy gate passes, additionally require that the sending
   Matrix device is verified (cross-signed or directly verified); otherwise the
   request is denied with a non-sensitive reason (`unverified_device`) and audited.
   This is strictly additive — it can only *deny*, never *grant*. Default behavior
   is unchanged (signing+trust+policy remain the gate).
3. **Unverified-device handling (default).** With the knob off, a request from an
   unverified-but-trusted signing key still executes (TOFU on device, but
   authority comes from the signing key); the daemon logs a non-sensitive advisory
   that the originating device is unverified. This is the documented default
   behavior the tests assert.

## Affected Files / Crates / Modules

**Read / understand:**

- `docs/architecture.md` (§1.2, §10.1, §10.3, §13.1, §13.2), `docs/security-hardening.md`,
  `docs/roadmap-rust.md` (Phase 16), README "Project status" / "Security posture".
- `crates/mx-agent-daemon/src/event_router.rs` (fail-safe invariant, lines 296-369).
- `crates/mx-agent-daemon/src/exec.rs`, `src/call.rs` (authorization gates).
- `crates/mx-agent-daemon/tests/matrix_integration.rs`
  (`daemon_e2ee_privileged_event_coverage`), `scripts/matrix_integration_test.sh`,
  `.github/workflows/ci.yml`.

**Modify:**

- `crates/mx-agent-daemon/Cargo.toml` — move `e2e-encryption` + add the persistent
  store feature to the production `matrix-sdk` dependency.
- `crates/mx-agent-daemon/src/matrix.rs` — crypto-store wiring in `build_client` /
  `restore_client` / `login_password`.
- `crates/mx-agent-daemon/src/session.rs` — `crypto_store_dir` path + store-key /
  recovery-metadata persistence (`Secret`, `0600`/`0700`).
- `crates/mx-agent-daemon/src/sync.rs` — register verification handlers; observe
  cross-signing on sync.
- `crates/mx-agent-daemon/src/lifecycle.rs` — optional cross-signing bootstrap at
  startup; ensure restore reuses the persistent store/device.
- `crates/mx-agent-daemon/src/exec.rs` / `src/call.rs` — optional
  `require_verified_device` post-gate (additive deny only).
- `crates/mx-agent-policy/*` — add the `require_verified_device` policy field
  (parse + default `false`).
- `crates/mx-agent-cli/src/cli.rs` — new `device` and `recovery` command groups;
  `auth cross-signing` subcommands; dispatch to daemon IPC.
- `crates/mx-agent-ipc/*` (if a shared method registry exists) and the daemon IPC
  dispatcher — register the new methods.

**Add:**

- `crates/mx-agent-daemon/src/verification.rs` — device verification + cross-signing
  manager.
- `crates/mx-agent-daemon/src/device_ipc.rs`, `src/recovery_ipc.rs` — IPC handlers
  following the `call_ipc.rs` / `pty_ipc.rs` pattern.
- Integration tests in `crates/mx-agent-daemon/tests/` (or extend
  `matrix_integration.rs`).

## CLI / API Changes

New stateless CLI surface (all daemon-IPC-mediated; human output by default,
`--json` for automation):

```bash
# Device verification
mx-agent device list   --room '!abc:matrix.org' [--user @peer:hs]   # devices + verify status + fingerprint
mx-agent device show   --user @peer:hs --device DEVICEID
mx-agent device verify --user @peer:hs --device DEVICEID            # interactive SAS (emoji compare)
mx-agent device verify --user @peer:hs --device DEVICEID --manual --fingerprint 'SHA256:...'  # out-of-band

# Cross-signing
mx-agent auth cross-signing bootstrap    # create + publish cross-signing identity (idempotent)
mx-agent auth cross-signing status

# Key backup / recovery
mx-agent recovery enable    # provision SSSS + server-side key backup; prints recovery key ONCE
mx-agent recovery status
mx-agent recovery recover   # re-import keys from backup (prompts for recovery key)
```

New daemon IPC methods (framed JSON-RPC 2.0 over the existing Unix socket):

| Method | Params | Result |
|---|---|---|
| `device.list` | `{ room?, user? }` | `DeviceInfo[]` |
| `device.show` | `{ user, device }` | `DeviceInfo?` |
| `device.verify.start` | `{ user, device }` | streamed flow frames (`emoji-ready` → `done`/`cancelled`) |
| `device.verify.confirm` / `.cancel` | `{ flow_id }` | `VerificationState` |
| `device.verify.manual` | `{ user, device, fingerprint }` | `DeviceInfo` |
| `cross_signing.bootstrap` / `.status` | `{}` | `CrossSigningStatus` |
| `recovery.enable` | `{}` | `{ recovery_key: Secret }` (surfaced once) |
| `recovery.status` | `{}` | `RecoveryStatus` |
| `recovery.recover` | `{ recovery_key }` | `RecoveryStatus` |

`DeviceInfo` carries non-secret fields only: `user_id`, `device_id`,
`display_name?`, `ed25519_fingerprint` (the Matrix device key fingerprint),
`verified: bool`, `cross_signed: bool`, `blacklisted: bool`. No private key
material crosses IPC. The interactive `device.verify.start` follows the existing
`task.watch` streaming convention (one response frame per flow update, same request
id). Document every new public IPC type and CLI command (`missing_docs` is denied in
CI). Exit codes follow existing conventions; verification failure/cancel surfaces a
clear non-zero exit.

## Data Model / Protocol Changes

- **No new `com.mxagent.*` event types.** Device verification (to-device SAS),
  cross-signing key upload, and server-side key backup use standard Matrix
  Client-Server endpoints handled by matrix-sdk.
- **Persistence (new, daemon-owned):**
  - `<data_dir>/crypto-store/` — SQLite crypto/state store, `0700`.
  - `<data_dir>/crypto-store-key` — `Secret`-wrapped store passphrase, `0600`.
  - Recovery metadata (backup version / enabled flag) as needed, `0600`; the
    recovery key itself is **not** persisted in clear — it is surfaced to the
    operator once.
- **Policy (additive, backward-compatible):** new optional
  `require_verified_device` boolean (per-room and per-agent), default `false`. Older
  policy files without it parse unchanged.
- **Config (additive):** optional `[matrix] enable_e2ee` / crypto-store toggles if
  the implementer chooses to gate the stack behind config (default on); confirm
  during implementation.
- **Agent state (optional, advisory only):** may surface a peer's device
  verification status for display, but it must never be an authorization input. No
  required schema change.

## Security Considerations

- **The coding agent never sees device keys or tokens.** All crypto, the crypto
  store, the store passphrase, and the recovery key stay inside the daemon. IPC
  returns only fingerprints, SAS emoji/decimal, verification status, and the
  one-time recovery key (which is the operator's secret to record, surfaced once and
  never logged). CLI stays stateless.
- **Fail-safe preserved.** The event-router `SkippedEncrypted` guarantee
  (`event_router.rs:322-325`) is unchanged: undecryptable encrypted events never
  reach a handler and never execute. Persisting the crypto store *reduces* spurious
  undecryptable events but must not weaken the skip.
- **Execution gate unchanged and authoritative.** Signature → local trust store
  (`TrustStore::is_key_trusted`) → local deny-by-default policy → optional approval
  remains the only path to execution. Device verification is layered *after* that
  gate and can only add a deny (`require_verified_device`), never a grant. Room
  membership / device presence / device verification never authorize execution.
- **Two distinct trust roots.** The Matrix device Ed25519 key (transport) and the
  mx-agent Ed25519 signing key (execution authority) are different keys with
  different fingerprints; the docs and CLI output must label them unambiguously to
  avoid operator confusion.
- **No secrets in logs.** Wrap the store passphrase and recovery key in
  `mx_agent_telemetry::Secret` / `crate::session::Secret`; log only non-sensitive
  metadata (user id, device id, verification status, backup version). Never log SAS
  bytes, store keys, or recovery keys.
- **File permissions / Unix-only.** Crypto store `0700`, store-key/recovery-metadata
  `0600`, under the already-`0700` data dir. No Windows paths or Keychain/DPAPI.
- **No `unsafe`; MSRV 1.74.** The crypto stack and any new code must build with
  `unsafe_code = "forbid"` and Rust 1.74 (verify matrix-sdk 0.18 + sqlite feature
  compiles on 1.74 — see Open Questions).
- **Recovery-key handling.** Surfaced exactly once on `recovery enable`; if the
  operator loses it, history backed up under it is unrecoverable — document this
  plainly rather than silently storing it.

## Testing Plan

Unit / non-network (run under default `cargo test --all`):

- `SessionPaths` resolves `crypto_store_dir`; the store-key file is created `0600`
  and the store dir `0700`.
- Policy parsing: `require_verified_device` defaults to `false`; present value
  parses; absence is backward-compatible.
- `DeviceInfo` / verification IPC types serialize without leaking key material;
  `Secret`-wrapped store key and recovery key redact in `Debug`/`Display`.
- Authorization unit tests: with `require_verified_device = true`, a trusted-but-
  unverified device is denied with reason `unverified_device`; with the knob off,
  it is allowed (authority from the signing key). The existing signature/trust/policy
  denials are unchanged.

Integration (`#[ignore]`d, in `matrix_integration.rs`, run by
`scripts/matrix_integration_test.sh` / the `matrix-integration` CI job):

- **Verified-device happy path:** two daemons in an encrypted room complete SAS
  verification; `device list` reports the peer `verified = true`; a signed
  privileged exec from the verified device decrypts and executes through the normal
  pipeline.
- **Unverified-device handling:** default behavior — a trusted-signing-key request
  from an unverified device still executes, with the advisory surfaced; and, with
  `require_verified_device = true`, the same request is denied `unverified_device`
  while signing+trust+policy are otherwise satisfied.
- **Key-backup restore across daemon restart:** enable recovery, back up keys,
  simulate a restart from the persistent crypto store and decrypt prior history;
  and a re-provision path that wipes the store and re-imports via `recovery recover`
  + recovery key, then decrypts prior history.
- Keep `daemon_e2ee_privileged_event_coverage` green (regression guard for the
  fail-safe and the decrypt→authorize path).

## Documentation Updates

- **`docs/architecture.md`** — §1.2 (spell out the two-trust-layer interaction and
  "both must hold"); §13.2 trust-modes table (reframe "Matrix device verified" as an
  advisory transport signal, not an execution grant; document `require_verified_device`);
  §13.1 (note the crypto store / store-key / recovery files are now actually
  created); update the §10.1 daemon-responsibilities note from aspirational to
  implemented where appropriate.
- **`docs/security-hardening.md`** — device verification UX, cross-signing,
  key-backup/recovery procedure, recovery-key handling, restart vs re-provision,
  and the `require_verified_device` knob.
- **`docs/roadmap-rust.md`** — mark the Phase 16 E2EE hardening items delivered as
  they land.
- **`README.md`** — "Project status" table: update the "E2EE privileged-event
  handling" row from "production hardening … remains planned" to reflect what
  actually ships (device verification, cross-signing, key backup). Do **not** claim
  capabilities not yet implemented; tag partial vs done precisely.
- **`wiki/`** — Getting Started / Security-and-Sandboxing pages: how to verify a
  peer device, bootstrap cross-signing, enable recovery, and store the recovery key.
- **CLI help text** for the new `device` / `recovery` / `auth cross-signing`
  commands (doubles as `missing_docs` coverage).
- **`CONTRIBUTING.md`** — note the new `#[ignore]`d E2EE integration tests in the
  Matrix integration section if the run instructions change.

## Risks and Open Questions

1. **matrix-sdk 0.18 API + features.** Confirm exact 0.18 names/features for the
   persistent crypto store (`sqlite_store` / `StoreConfig` / `bundled-sqlite`),
   SAS (`SasVerification`, emoji/decimal), `bootstrap_cross_signing`, and the
   `Recovery`/Secure-Secret-Storage API. If 0.18 lacks a needed surface, decide
   whether to bump matrix-sdk (workspace-wide, with care) — a blocker to resolve
   first.
2. **MSRV 1.74 vs the crypto stack.** The crypto store backend (rusqlite/libsqlite,
   vodozemac) and its transitive deps must build on Rust 1.74; verify before
   committing, and prefer a vendored/`bundled` SQLite to avoid system-lib drift.
3. **Production binary cost.** Compiling the crypto stack into the production daemon
   increases build time and binary size; acceptable for the security gain, but note
   it. Decide whether to gate behind a Cargo feature (e.g. `e2ee` on by default) so a
   minimal build is still possible.
4. **Bootstrap UX / Secure Secret Storage coupling.** Cross-signing bootstrap and
   recovery both touch SSSS; sequence them so the operator deals with one recovery
   key/passphrase, not two. Decide auto-bootstrap-on-first-login vs explicit command.
5. **`require_verified_device` default and semantics.** Confirm default `false`
   (so existing deployments are unaffected) and that it is purely additive deny.
   Decide whether "verified" means directly-verified-only or includes cross-signed
   transit.
6. **Headless / multi-agent verification.** SAS is interactive; document how an
   unattended/headless daemon handles verification (manual out-of-band fingerprint
   path; or pre-seeded cross-signing). Ensure the interactive IPC flow degrades
   cleanly when no operator is attached.
7. **Interaction with #249 (room E2EE on create).** Coordinate so enabling E2EE at
   room-create time and this hardening compose without double-implementing config.
8. **Recovery-key loss.** Accept and document that a lost recovery key means lost
   backed-up history; no silent escrow.

## Implementation Checklist

- [ ] **Stage 1 — persistent crypto store**
  - [ ] Move `e2e-encryption` + add the persistent store feature to the production
        `matrix-sdk` dep in `crates/mx-agent-daemon/Cargo.toml`; confirm `cargo
        build --all` links the crypto stack and still builds on MSRV 1.74.
  - [ ] Add `crypto_store_dir` to `SessionPaths` (`0700`); add `Secret`-wrapped
        store-key persistence (`0600`).
  - [ ] Wire the SQLite crypto store + passphrase into `build_client`,
        `restore_client`, `login_password` (`src/matrix.rs`); ensure restart reuses
        the same device/store.
  - [ ] Test: decrypt after simulated restart from the persistent store.
- [ ] **Stage 2 — device verification UX**
  - [ ] Add `src/verification.rs` (list/SAS/manual) + register verification handlers
        in `src/sync.rs`.
  - [ ] Add `device.*` IPC (`src/device_ipc.rs`), streaming `device.verify.start`
        like `task.watch`.
  - [ ] Add stateless CLI `mx-agent device { list | show | verify }` with `--json`;
        return only fingerprints/SAS/status over IPC.
  - [ ] Tests: verified-device happy path; `device list` reflects status.
- [ ] **Stage 3 — cross-signing + key backup/recovery**
  - [ ] Cross-signing bootstrap (startup hook in `src/lifecycle.rs` and/or
        `auth cross-signing bootstrap`); observe peers' cross-signing on sync.
  - [ ] `recovery enable` / `status` / `recover` IPC + CLI; surface the recovery key
        once as a `Secret`; persist only non-secret backup metadata `0600`.
  - [ ] Tests: key-backup restore across restart and across re-provision
        (`recovery recover`).
- [ ] **Stage 4 — two-trust-layer spec + optional enforcement**
  - [ ] Add `require_verified_device` policy field (`mx-agent-policy`, default
        `false`); layer the additive post-gate deny in `exec.rs`/`call.rs`
        (reason `unverified_device`), audited, never a grant.
  - [ ] Document the Matrix-device-trust vs Ed25519-signing-trust interaction in
        `docs/architecture.md` §1.2/§13.2 and `docs/security-hardening.md`.
  - [ ] Tests: trusted-but-unverified device allowed by default; denied with the
        knob on.
- [ ] **Cross-cutting**
  - [ ] Confirm no secrets in logs (store key, recovery key, SAS bytes); `Secret`
        redaction tests.
  - [ ] Keep `daemon_e2ee_privileged_event_coverage` green; add new `#[ignore]`d
        tests to `scripts/matrix_integration_test.sh` / the `matrix-integration` job.
  - [ ] Update README status table, `docs/`, `wiki/`, CLI help; document all new
        public APIs (`missing_docs`).
  - [ ] `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D
        warnings`, `cargo test --all`, `cargo build --all` all pass.
