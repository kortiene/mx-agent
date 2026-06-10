# Issue #260 — E2EE integration tests: decrypt-after-restart, key-backup restore, two-daemon SAS

## Problem Statement

PR #256 (closing parts of issue #240) added live Matrix-integration coverage for
the E2EE production-hardening surface: manual device verify + `sender_verified`,
`recovery.enable`/`status`, cross-signing bootstrap/status, and the
`require_verified_device` exec gate. Those tests live in the `#[ignore]`d suite
`crates/mx-agent-daemon/tests/matrix_integration.rs` and run via
`scripts/matrix_integration_test.sh`.

Three acceptance criteria from the issue #240 *Testing Plan* are still **not
exercised live**:

1. **Decrypt-after-restart from the persistent crypto store** (issue #240 "Stage
   1"): a daemon that resumes as the *same* E2EE device must still decrypt a
   message that was encrypted while it was down. Today no test drops and rebuilds
   a client from the persisted device-keyed crypto store and then decrypts.
2. **Key-backup restore across a restart / re-provision** (issue #240 criterion
   #5): `recovery.enable`/`status` is covered, but the *restore* path — proving
   that a re-provisioned device (empty local store) regains decryptability of
   previously-encrypted history via server-side key backup — is not. The existing
   `live_recovery_enable_and_status` test explicitly documents this round-trip as
   "left for a follow-up".
3. **Full two-daemon interactive SAS happy path**: only `manual_verify`
   (out-of-band fingerprint) is exercised live by
   `live_device_manual_verify_and_sender_verified`. The emoji/SAS request →
   accept → present → confirm flow *between two daemons*, ending with both sides
   marking the other verified, is not.

The gap was surfaced during the issue #240 review (PR #256). Closing it hardens
confidence in the three highest-value E2EE durability/verification properties
against a real homeserver.

## Goals

- Add a live integration test proving **decrypt-after-restart from the persistent
  store**: log in (device A), persist the crypto store, drive sync, drop the
  client, rebuild from the *same* device-id store via `restore_client`, and
  decrypt an event that was encrypted to device A while the client was down.
- Add a live integration test proving **key-backup restore across a
  re-provision**: enable key backup on device A, re-provision onto a fresh device
  B (empty crypto store) that cannot decrypt the history, call `recover` with the
  one-time recovery key, and confirm the previously-encrypted event is decryptable
  again.
- Add a live **two-daemon SAS** test that drives the interactive emoji/SAS flow
  between two independent daemons to a mutual `confirmed`, and asserts
  `sender_verified(...) == Some(true)` on **both** sides.
- Keep all three tests `#[ignore]`d, wired into `scripts/matrix_integration_test.sh`,
  and consistent with the existing suite's helpers, isolation, and timeout
  conventions so the default offline `cargo test --all` stays green.
- Provision any additional throwaway homeserver users the new tests need from the
  harness (mirroring the existing per-run recovery user), and document them.

## Non-Goals

- **No production/library behavior change.** This is test-only coverage. In
  particular, do **not** add a new responder-side SAS *helper* to the daemon to
  make the two-daemon test convenient (the responder is driven through the
  `matrix_sdk` verification API inside the test). If a first-class responder/
  "accept incoming verification" daemon helper is later wanted, it is a separate
  feature (see Open Questions), not part of #260.
- No CLI, IPC method, protocol event, or policy surface changes.
- No room-level E2EE-on-create (`workspace create --e2ee`) work — that remains
  tracked under #240/#249.
- No change to the trust/execution model: these tests validate the **transport**
  verification + key-durability layer only. Device verification stays advisory;
  signing + local trust + policy remain the execution gate (architecture §1.2).
- No Windows support, no `unsafe`, no MSRV bump.

## Relevant Repository Context

### Crate ownership

- **`mx-agent-daemon`** owns all Matrix state, crypto, device verification,
  recovery, and the live test suite. All three new tests land in
  `crates/mx-agent-daemon/tests/matrix_integration.rs`.
- **`scripts/matrix_integration_test.sh`** boots a throwaway Tuwunel homeserver,
  registers test users, and runs the `#[ignore]`d suite single-threaded
  (`--test-threads=1 --ignored --nocapture`).

### Existing test conventions (reuse, do not reinvent)

`crates/mx-agent-daemon/tests/matrix_integration.rs` already provides the
building blocks the new tests should reuse:

- `required_env(name)` — read a harness-provided env var or panic with guidance.
- `throwaway_data_dir()` — a unique temp data dir per run.
- `paths_in(dir)` / `SessionPaths::for_data_dir(dir)` — isolate persisted state
  (sync token, signing key, **crypto store**) without mutating the process-global
  `MX_AGENT_DATA_DIR`. The crypto store lives under `data_dir/<device_id>/`
  (see below), so isolating the data dir isolates the crypto store too.
- `create_encrypted_room(client, name)` — create a public room, enable
  `m.room.encryption`, and wait for the encryption state to land. Requires the
  caller to already be running a sync loop.
- `wait_for_joined_member(room, user)` — block until a user is observed joined,
  so a subsequent encrypted send shares the Megolm room key with that user's
  device.
- `decrypted_content(room, event_id)` — poll `room.event(...)` until the daemon's
  client can decrypt it (asserts `encryption_info().is_some()`), returning the
  decrypted `content`. This is the exact mechanism the restart and backup tests
  use to assert "decryptable".
- Sync-loop pattern: `run_matrix_sync(&client, &paths, health, BackoffConfig::default(), running)`
  spawned on a task, with `running: Arc<AtomicBool>` to stop it and join cleanly.

### Persistent crypto store (the mechanism under test #1)

From `session.rs` / `matrix.rs`:

- `SessionPaths` carries `crypto_store_dir` (`data_dir/crypto-store`, legacy flat
  layout) and `crypto_store_key_file` (`0600` passphrase that encrypts the SQLite
  store at rest).
- `build_client_with_store(config, paths)` builds a client with
  `.sqlite_store(&paths.crypto_store_dir, Some(passphrase))` — a **persistent**
  store holding the device identity + Megolm sessions.
- `login_password(config, user, pass)` **mints a new Matrix device each call**
  and relocates the store into a per-device subdirectory
  `data_dir/<device_id>/`. So *two `login_password` calls = two devices = two
  empty stores* (this is exactly what test #2 exploits for re-provision).
- `restore_client(&session)` rebuilds a client backed by **the same persistent
  store keyed by `session.device_id`** (`data_dir/<device_id>/`, with a legacy
  `crypto-store/` fallback). It resumes as the same E2EE device and keeps its
  Megolm sessions — *this is the property test #1 asserts*.
- Caveat: `restore_client` first checks an in-process `active_client_for(session)`
  registry and reuses a client **only if one was published via
  `publish_active_client`**. The live tests do not publish, so a `drop()` of the
  first client followed by a second `restore_client(&same_session)` faithfully
  models a process restart that rebuilds from disk. **The restart test must not
  call `publish_active_client`.**

The chaos suite (`tests/chaos.rs`) already models a *non-crypto* restart
(signing identity, trust, sync token, replay cache survive a drop+reload) but
needs no homeserver; #260's restart test is the crypto/E2EE analogue that does.

### SAS verification API (the surface under test #3)

From `verification.rs` + `device_ipc.rs` (re-exported from `lib.rs`):

- Requester side helpers exist: `start_sas(client, user, device) -> flow_id`
  (request-based, uses `VerificationRequest::request_verification()`),
  `advance_sas(flow_id) -> SasAdvance`, `confirm_sas(flow_id)`,
  `cancel_sas(flow_id)`, `forget_sas(flow_id)`.
- `SasAdvance` variants: `Pending`, `Negotiating`, `Ready { emoji, decimals }`,
  `Done`, `Cancelled`. `advance_for_sas` maps `is_done()`/`is_cancelled()`/
  `can_be_presented()`.
- `run_device_verify` drives the **requester** through all phases plus the
  operator decision over IPC; `device_verify_ipc_e2e.rs` tests the IPC framing
  with a **mock** SAS (no live homeserver).
- **There is no responder-side daemon helper.** The internal flow id used by
  `start_sas` is a self-generated ULID (the SDK transaction id "is not exposed on
  `SasVerification`"), so the *peer* cannot look the flow up by the requester's
  flow id. The two-daemon test must therefore drive the **responder** via the raw
  `matrix_sdk` verification API (capture the incoming `m.key.verification.request`
  to learn the SDK flow id, accept it, observe its `SasVerification`, confirm).
- `sender_verified(client, user_id) -> Option<bool>` returns `Some(true)` iff the
  user has known devices and **all** are verified; `Some(false)` if any known
  device is unverified; `None` if indeterminate. This is the both-sides assertion
  target for test #3.

### Recovery API (the surface under test #2)

From `verification.rs` + `recovery_ipc.rs`:

- `bootstrap_cross_signing(client) -> CrossSigningStatusInfo` — requires a
  **pristine** cross-signing identity (no-ops once the server already advertises
  one). This is why the existing recovery test uses a freshly-registered per-run
  user.
- `enable_recovery(client) -> RecoveryEnableResult { recovery_key: Secret, status }`.
  `Secret::expose()` is public, so a test can read the actual key without adding
  any API. `Debug` redacts to `***redacted***`.
- `recover(client, recovery_key: &str) -> RecoveryStatusInfo` — re-imports keys
  from server-side backup (the re-provision path).
- `recovery_status(client) -> RecoveryStatusInfo { state, backup_enabled, ... }`.
- The existing `live_recovery_enable_and_status` test documents the unimplemented
  restore round-trip and the reason it was deferred ("requires either a second
  login (a different device, so the backup has keys to restore) or exposing the
  key out of `Secret`"). #260's backup test resolves both: a second `login_password`
  yields device B, and `Secret::expose()` yields the key.

### Harness user provisioning

`scripts/matrix_integration_test.sh` registers `USER1`/`USER2` (shared) and a
**fresh per-run** `USER_REC` (unique name, pristine cross-signing) exported as
`MX_AGENT_TEST_RECOVERY_USER`/`_PASSWORD`. New tests that need pristine
cross-signing, a clean backup version, or a peer with exactly one device should
follow this fresh-per-run pattern.

## Proposed Implementation

Add three `#[ignore]`d `#[tokio::test(flavor = "multi_thread", worker_threads = 4)]`
functions to `crates/mx-agent-daemon/tests/matrix_integration.rs`, plus the
supporting harness users in `scripts/matrix_integration_test.sh`. Reuse the
existing helpers throughout.

### Test 1 — `live_decrypt_after_restart_from_persistent_store`

Proves issue #240 Stage 1: a daemon resumes as the same E2EE device and decrypts
a message sent while it was down.

1. Isolate state in a `throwaway_data_dir()`; set `ENV_DATA_DIR` (or use
   `paths_in(...)` to avoid mutating the process global — match the local
   convention, preferring the non-global `paths_in` style used by
   `daemon_e2ee_privileged_event_coverage`).
2. `login_password` Alice (device A) and Bob; `restore_client` both. Capture
   `alice_session` (the `StoredSession` — same `device_id`/token reused on
   restart). **Do not** call `publish_active_client`.
3. Spawn Alice's `run_matrix_sync` loop (uploads device/one-time keys, decrypts);
   spawn Bob's sync (`bob.sync(...)`).
4. Bob `create_encrypted_room`; Alice `join_room_by_id`; `wait_for_joined_member`
   for Alice so the Megolm key is shared with device A.
5. **Establish the inbound session in Alice's persistent store while she is up:**
   Bob sends message #1; assert Alice decrypts it via `decrypted_content` (this
   persists the inbound Megolm session to device A's SQLite store).
6. **Restart:** set `running=false`, join Alice's sync task, and `drop` Alice's
   client so no in-memory crypto state remains. (Optionally assert the on-disk
   `data_dir/<device_id>/` crypto store exists.)
7. **While Alice is down:** Bob sends message #2 over the *same* Megolm session
   (send promptly / few messages so the SDK does not rotate the session — default
   rotation is 100 msgs / 1 week, so two sends share a session).
8. **Rebuild:** `restore_client(&alice_session)` again (same device-id store),
   spawn a fresh sync loop.
9. Assert Alice decrypts message #2 via `decrypted_content(&alice_room, &msg2_id)`
   — proving the resumed device identity + persisted Megolm session decrypt an
   event encrypted to device A while it was down.
10. Stop loops, join, clean up env vars.

Primary assertion: message #2 decrypts after restart. Because the inbound session
was already persisted at step 5, this is a pure persistent-store decrypt; even if
the SDK additionally re-shares the key to the resumed device on sync, the assertion
("same device decrypts a message sent while down") holds either way.

### Test 2 — `live_key_backup_restore_across_reprovision`

Proves issue #240 criterion #5: key backup restores decryptability after a
re-provision.

1. Use a **fresh per-run user** (`MX_AGENT_TEST_BACKUP_USER`/`_PASSWORD`, added to
   the harness) for a pristine cross-signing identity and a clean backup version.
   Fall back to the shared user when the env var is unset (mirrors the recovery
   test) so a bare `cargo test` still runs, with the cross-run caveat documented.
2. `login_password` device A; `restore_client`; spawn sync; wait for `Healthy`.
3. `bootstrap_cross_signing(&deviceA)` (assert `has_master`/`complete`), then
   `enable_recovery(&deviceA)`; assert `status.state == "enabled"` and
   `backup_enabled`. **Capture the key via `result.recovery_key.expose()`** into a
   local `String` (do not log it).
4. Establish backed-up history: Bob (`MX_AGENT_TEST_USER2`) `create_encrypted_room`,
   device A joins, `wait_for_joined_member`, Bob sends a message, device A decrypts
   it (`decrypted_content`) so device A holds the room key. Wait for the SDK to
   upload that room key to server-side backup (poll `recovery_status`/backup state,
   or allow a bounded grace period with retries — see Risks for the Tuwunel
   round-trip caveat). Record the history `event_id`.
5. **Re-provision:** `login_password` again as the same user → **device B** with an
   empty crypto store; `restore_client(&deviceB_session)`; spawn sync. Device B is
   the same Matrix user, hence already a room member; it can fetch but **not**
   decrypt the history event. Assert undecryptable first (poll `room.event(...)`;
   `encryption_info().is_none()` / still `m.room.encrypted`), to prove the restore
   is what fixes it.
6. **Restore:** `recover(&deviceB, &recovery_key)`; assert the returned status is
   `enabled` with `backup_enabled`.
7. Assert device B can now decrypt the history event via `decrypted_content` —
   proving previously-encrypted history is decryptable again after restore.
8. Stop loops, join, clean up.

### Test 3 — `live_two_daemon_sas_confirms_and_verifies`

Proves the full interactive SAS happy path between two daemons.

1. Use **fresh per-run users** for both sides
   (`MX_AGENT_TEST_SAS_USER`/`_PASSWORD` and `MX_AGENT_TEST_SAS_USER2`/`_PASSWORD2`,
   added to the harness) so each peer has exactly **one** device and the
   all-devices `sender_verified == Some(true)` assertion is not defeated by stale
   devices accumulated by other tests' `login_password` calls in the same run.
   Fall back to the shared users when unset, with the caveat documented.
2. `login_password` + `restore_client` Alice and Bob; spawn both sync loops (both
   need live crypto for to-device verification traffic). Put both in a shared
   encrypted room (or rely on device-key download via `list_devices`) so each
   sees the other's device, as `live_device_manual_verify_and_sender_verified`
   does.
3. Pre-assert: `sender_verified(&alice, bob_user) != Some(true)` and the converse.
4. **Requester (Alice):** `start_sas(&alice, bob_user, bob_device_id) -> flow_id_A`.
5. **Responder (Bob), via the SDK:** register a to-device handler (or poll) to
   capture the incoming `m.key.verification.request` and its SDK transaction id,
   then `bob.encryption().get_verification_request(alice_user, sdk_flow).accept()`.
   Drive Bob's SAS: obtain the `SasVerification` (from the accepted request /
   `get_verification`), drive `/sync` until `can_be_presented()`, then `confirm()`.
6. **Requester (Alice):** loop `advance_sas(flow_id_A)` over `/sync` until
   `SasAdvance::Ready`, then `confirm_sas(flow_id_A)`; continue advancing until
   `Done`. In the test there is no human, so both sides confirm unconditionally
   (the emoji are assumed to match — both daemons compute the same SAS).
7. Drive both sides to completion (`is_done()` / `SasAdvance::Done`).
8. **Both-sides assertion:** poll until
   `sender_verified(&alice, bob_user) == Some(true)` **and**
   `sender_verified(&bob, alice_user) == Some(true)`. As belt-and-suspenders, also
   assert via `list_devices` that the specific peer device shows `verified == true`
   on each side.
9. Stop loops, join, `forget_sas(flow_id_A)`, clean up.

Because the responder side is driven through `matrix_sdk` directly, no daemon API
changes are required. Keep the responder logic in a small private helper inside
the test module (e.g. `drive_sas_responder(&bob, alice_user) -> ()`), mirroring
how the existing tests factor `create_encrypted_room`, `decrypted_content`, etc.

### Harness changes (`scripts/matrix_integration_test.sh`)

- Add fresh per-run users mirroring `USER_REC`:
  - `USER_BACKUP="mxagent_it_backup_$$_${RANDOM}"` → `MX_AGENT_TEST_BACKUP_USER`/`_PASSWORD`.
  - `USER_SAS1`/`USER_SAS2` (fresh) → `MX_AGENT_TEST_SAS_USER`/`_PASSWORD` and
    `MX_AGENT_TEST_SAS_USER2`/`_PASSWORD2`.
- `ensure_user` each new user before the `cargo test` invocation and export the
  env vars alongside the existing block. Keep the single-threaded `--ignored`
  invocation unchanged.
- Update the script's header comment to mention the new E2EE durability/SAS
  coverage and why these users are provisioned fresh per run.

## Affected Files / Crates / Modules

| Path | Change |
|---|---|
| `crates/mx-agent-daemon/tests/matrix_integration.rs` | **Add** the three `#[ignore]`d tests + a small private SAS-responder helper; extend the module doc comment. |
| `scripts/matrix_integration_test.sh` | **Add** fresh per-run backup + SAS users; export `MX_AGENT_TEST_BACKUP_USER`/`_PASSWORD`, `MX_AGENT_TEST_SAS_USER`/`_PASSWORD`, `MX_AGENT_TEST_SAS_USER2`/`_PASSWORD2`; update header comment. |
| `crates/mx-agent-daemon/src/verification.rs` | **Read only** — confirm `start_sas`/`advance_sas`/`confirm_sas`/`cancel_sas`/`forget_sas`/`sender_verified`/`enable_recovery`/`recover`/`recovery_status`/`bootstrap_cross_signing` signatures. |
| `crates/mx-agent-daemon/src/matrix.rs` | **Read only** — confirm `login_password` device-minting + `restore_client` device-keyed store reuse + `active_client_for`/`publish_active_client`. |
| `crates/mx-agent-daemon/src/session.rs` | **Read only** — confirm `SessionPaths` crypto-store layout, `Secret::expose()`, `StoredSession`. |
| `crates/mx-agent-daemon/src/device_ipc.rs` | **Read only** — confirm `DeviceVerifyFrame`/`run_device_verify` shapes (reference only; responder is driven via SDK). |
| `CONTRIBUTING.md`, `README.md`/status table, `docs/security-hardening.md` (optional) | **Doc touch-ups** describing the new live coverage (see Documentation Updates). |

No new source files. No `Cargo.toml` changes expected (the integration test
already depends on `matrix-sdk`, `tokio`, `base64`, `serde_json`, and the daemon
crate).

## CLI / API Changes

None. No new CLI commands, IPC methods, or public daemon APIs. The tests consume
existing public re-exports from `mx_agent_daemon` (`start_sas`, `advance_sas`,
`confirm_sas`, `cancel_sas`, `forget_sas`, `sender_verified`, `list_devices`,
`enable_recovery`, `recover`, `recovery_status`, `bootstrap_cross_signing`,
`restore_client`, `login_password`, `save_session`, `StoredSession`, `Secret`,
`SessionPaths`, `RecoveryEnableResult`, `SasAdvance`) plus the `matrix_sdk`
verification API for the SAS responder.

If a follow-up decides to expose a first-class responder helper (e.g.
`accept_sas` / an "accept incoming verification" daemon function), that would be a
documented public API addition handled in its own issue — out of scope here.

## Data Model / Protocol Changes

None. No event-schema, persistence-format, policy, or serialization changes. The
tests exercise existing persisted artifacts (the device-keyed SQLite crypto store,
the server-side key backup, SAS to-device events) without altering their shapes.

## Security Considerations

- **No secrets reach any coding agent.** These are daemon-side tests; tokens and
  device keys never leave the test process. Consistent with the architecture
  invariant that the coding agent never sees Matrix tokens or device keys.
- **Recovery key handling.** The backup test reads the one-time recovery key only
  via `Secret::expose()` into a local variable used to call `recover`. It must
  **never** be logged or printed; assert (as the existing recovery test does) that
  `Debug` still redacts to `***redacted***`. Do not add a `Display`/log of the
  exposed value.
- **Transport vs. execution separation preserved.** The SAS test asserts only the
  *transport* signal (`sender_verified`, device verification). It must not imply
  that verification grants execution authority — signing + trust + policy remain
  the gate (architecture §1.2). Keep assertions scoped to verification status.
- **Isolation / no cross-run state bleed.** Each test uses a `throwaway_data_dir()`
  so crypto stores never collide. Tests that depend on pristine cross-signing or a
  clean backup version (backup, SAS) use fresh per-run homeserver users, mirroring
  the recovery user, so they are hermetic across re-runs against a persistent
  homeserver. Document this so a future change does not collapse them back onto the
  shared users (which would reintroduce cross-run flakes, exactly like the recovery
  test's documented hazard).
- **Unix-only, no `unsafe`.** Tests use the existing Unix/`tokio`/`matrix-sdk`
  surface; no platform-specific or `unsafe` additions.
- **Offline default stays green.** All three remain `#[ignore]`d so
  `cargo test --all` (no homeserver, no Docker) is unaffected and never leaks live
  credentials into CI logs.

## Testing Plan

The deliverables *are* tests; this section enumerates exactly what is added/run.

- **New live integration tests** (in `matrix_integration.rs`, `#[ignore]`d, run via
  `scripts/matrix_integration_test.sh`):
  1. `live_decrypt_after_restart_from_persistent_store` — restart + decrypt of a
     while-down message from the persisted device store.
  2. `live_key_backup_restore_across_reprovision` — enable backup, re-provision to
     a fresh device, `recover`, decrypt previously-encrypted history.
  3. `live_two_daemon_sas_confirms_and_verifies` — two-daemon SAS to mutual
     `confirmed`, `sender_verified == Some(true)` on both sides.
- **Negative sub-assertions inside the tests** (not separate tests): pre-restart /
  pre-recover undecryptability and pre-verify `sender_verified != Some(true)`, so
  each test proves the operation under test is what changes the outcome.
- **Harness run:** `scripts/matrix_integration_test.sh` (optionally `--teardown`)
  must pass with the three new users provisioned. Confirm the suite still runs
  single-threaded and the new tests honor bounded timeouts (~30–60 s) like the
  existing ones.
- **Offline CI unchanged:** `cargo test --all`, `cargo fmt --check`,
  `cargo clippy --all-targets --all-features -- -D warnings`, `cargo build --all`
  must all stay green (the new tests are `#[ignore]`d and compile under the
  default feature set). No new `missing_docs` warnings (test items and any new
  private helpers need no public docs; if any new *public* item is added, document
  it — none is expected).

## Documentation Updates

- **Test module doc comment** (`matrix_integration.rs` top-of-file): extend the
  summary to list the three new behaviors (decrypt-after-restart, key-backup
  restore, two-daemon SAS) and the env vars they read.
- **`scripts/matrix_integration_test.sh` header**: note the new fresh-per-run
  users and why (pristine cross-signing / clean backup version / single-device
  peers).
- **`CONTRIBUTING.md` → "Running the integration tests"**: append the new coverage
  to the suite description (it currently enumerates login/sync, signed call/exec,
  E2EE privileged-event handling, scheduler) so contributors know the suite now
  also covers E2EE restart durability, key-backup restore, and interactive SAS.
- **`README.md` status table** *(optional, only if a status row should reflect it)*:
  the "E2EE production hardening" row already says device verification +
  recovery enable/status are implemented. If desired, note that
  decrypt-after-restart, key-backup restore, and two-daemon SAS now have live
  coverage. **Do not** claim any new runtime capability — these are tests of
  existing behavior, so avoid implying new alpha features exist.
- **`docs/security-hardening.md`** *(optional)*: if it references the E2EE test
  coverage, add the three scenarios. Skip if it does not.
- Update the existing `live_recovery_enable_and_status` doc comment (which says the
  restore round-trip is "left for a follow-up") to cross-reference the new
  `live_key_backup_restore_across_reprovision` test now that the follow-up exists.

## Risks and Open Questions

- **Tuwunel server-side key-backup round-trip.** `enable_recovery`/`recovery_status`
  already pass on Tuwunel, but the full `recover` *restore* (room-key upload to
  `/room_keys` then re-import on a fresh device) may not be fully supported by the
  Conduit-family homeserver. **Mitigation/decision needed:** if `recover` cannot
  round-trip on Tuwunel, either (a) gate test #2 to log a clear skip and pass when
  the backup endpoints are unsupported, or (b) keep it failing-loud and document a
  homeserver requirement. Validate early; this is the single biggest unknown.
- **Megolm session rotation in the restart test.** Messages #1 and #2 must share a
  Megolm session for the "pure persistent-store decrypt" framing. Defaults
  (100 msgs / 1 week) make this safe, but membership changes or an explicit
  rotation would break it — send both promptly and avoid membership churn between
  them.
- **`restore_client` active-client cache.** The restart test must not
  `publish_active_client` (else the second `restore_client` reuses the in-memory
  client and does not exercise a real reload). Keep the test free of any publish
  call and rely on `drop` + re-`restore_client`.
- **SAS responder flow-id discovery.** The requester's `start_sas` flow id is an
  internal ULID, not the SDK transaction id, so the responder cannot look the flow
  up through the daemon helpers. The test must learn the SDK flow id from the
  incoming `m.key.verification.request` to-device event (handler or poll) and use
  `matrix_sdk` APIs to accept/confirm. **Open question:** is it worth adding a
  first-class responder ("accept incoming verification") daemon helper for
  symmetry/operator use? Recommend tracking separately; #260 stays test-only.
- **`sender_verified` and accumulated devices.** `sender_verified == Some(true)`
  requires *all* of the peer's known devices to be verified. Repeated
  `login_password` calls across the suite accumulate devices on the *shared*
  users, which would defeat the both-sides assertion. The recommendation (fresh
  per-run SAS users with one device each) avoids this; confirm that is acceptable
  versus the alternative of scoping the assertion to the specific verified device
  only. **Decision needed:** add the fresh SAS user pair to the harness (preferred,
  matches criterion wording) vs. weaken the assertion.
- **Does `sender_verified` need cross-signing?** Direct device SAS should mark the
  peer device locally verified (`is_verified()` true) without cross-signing, but
  some SDK configurations factor cross-signing into the verdict. If the both-sides
  assertion is flaky, bootstrap cross-signing on each SAS user first. Validate
  against Tuwunel.
- **Wall-clock budget.** Three more live, sync-driven, single-threaded tests add
  noticeable runtime. Keep per-step timeouts tight (reuse the 30–60 s bounds the
  suite already uses) and avoid unbounded polling.
- **Harness fallback semantics.** When the new env vars are unset (bare
  `cargo test ... --ignored` without the script), tests should fall back to shared
  users (like the recovery test) and document that this is only hermetic against a
  freshly-reset homeserver.

## Implementation Checklist

1. Read `verification.rs`, `device_ipc.rs`, `matrix.rs`, `session.rs` to confirm
   the exact signatures of `start_sas`/`advance_sas`/`confirm_sas`/`cancel_sas`/
   `forget_sas`, `sender_verified`, `list_devices`, `enable_recovery`/`recover`/
   `recovery_status`, `bootstrap_cross_signing`, `login_password`/`restore_client`,
   `Secret::expose`, and `StoredSession` re-exports.
2. In `scripts/matrix_integration_test.sh`, add fresh per-run users
   `USER_BACKUP`, `USER_SAS1`, `USER_SAS2`; `ensure_user` each; export
   `MX_AGENT_TEST_BACKUP_USER`/`_PASSWORD`, `MX_AGENT_TEST_SAS_USER`/`_PASSWORD`,
   `MX_AGENT_TEST_SAS_USER2`/`_PASSWORD2`; update the header comment.
3. Add `live_decrypt_after_restart_from_persistent_store`:
   - login A (capture `StoredSession`) + Bob, restore both, spawn syncs, encrypted
     room, Alice joins + `wait_for_joined_member`.
   - Bob msg#1 → Alice decrypts (`decrypted_content`) to persist the inbound
     session.
   - Stop+join Alice sync, `drop` Alice client (no `publish_active_client`);
     optionally assert the device store dir exists.
   - Bob msg#2 (same session, sent promptly).
   - `restore_client(&alice_session)`, new sync; assert msg#2 decrypts.
   - Cleanup.
4. Add `live_key_backup_restore_across_reprovision`:
   - fresh backup user (fallback to shared), login A, sync to `Healthy`.
   - `bootstrap_cross_signing` (assert master/complete), `enable_recovery`
     (assert enabled + `backup_enabled`), `expose()` the key into a `String`;
     assert `Debug` redaction.
   - encrypted room with Bob, A decrypts a message (room key in A's store), wait
     for backup upload; record history `event_id`.
   - `login_password` again → device B (empty store), restore, sync; assert the
     history event is **not** decryptable yet.
   - `recover(&deviceB, &key)`; assert status enabled/backup_enabled.
   - assert device B now decrypts the history event.
   - Cleanup; never log the key.
5. Add `live_two_daemon_sas_confirms_and_verifies`:
   - fresh SAS user pair (fallback to shared), login + restore both, spawn syncs,
     shared encrypted room so devices are mutually visible.
   - pre-assert `sender_verified != Some(true)` both ways.
   - Alice `start_sas` → `flow_id_A`; implement a private `drive_sas_responder`
     that captures the incoming verification request on Bob (to-device handler /
     poll), accepts, drives sync to presentable, and confirms.
   - Alice loops `advance_sas` to `Ready`, `confirm_sas`, advances to `Done`.
   - poll until `sender_verified == Some(true)` both ways; also assert the
     specific peer device shows `verified` via `list_devices`.
   - `forget_sas`, stop loops, cleanup.
6. Run `cargo fmt`, `cargo clippy --all-targets --all-features -- -D warnings`,
   and `cargo test --all` (offline; the three stay `#[ignore]`d and must compile).
7. Run `scripts/matrix_integration_test.sh` locally; iterate on timeouts/flakes;
   if the Tuwunel key-backup restore is unsupported, apply the agreed skip/guard
   for test #2 and log it clearly.
8. Update docs: module doc comment, script header, `CONTRIBUTING.md` suite
   description, the existing recovery-test doc cross-reference, and (optionally)
   the README status note — without overclaiming new runtime behavior.
```
