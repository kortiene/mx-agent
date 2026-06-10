# Enable E2EE on `workspace create` via an opt-in `--e2ee` flag

> Issue: #249 — Workspace create never enables E2EE; `--e2ee` flag absent; docs
> showed `--e2ee on` / `encrypted: true`. Labels: `type:bug` `area:daemon`
> `area:matrix` `area:security` `priority:p2`. Found during the v0.2.0
> feature-completeness assessment. Couples with #240 (production E2EE hardening).

## Problem Statement

`mx-agent workspace create` always produces an **unencrypted** Matrix room. There
is no `--e2ee` flag, and `create_workspace` sets only the room name/topic/alias
and a visibility-derived preset — it never adds an `m.room.encryption` initial
state event and never calls `enable_encryption`
(`crates/mx-agent-daemon/src/workspace.rs:389-413`). `WorkspaceInfo.encrypted` is
only ever read back from `room.encryption_state().is_encrypted()`
(`workspace.rs:112,511`), so a real create always reports `encrypted: false`.

Because privileged `exec`/`call`/`task` events flow through workspace rooms, an
unencrypted workspace exposes their contents (commands, diffs, env snapshots,
streamed output) to the homeserver operator — at odds with the project's
confidentiality model (architecture §0, §14, "Matrix Client-Server API + E2EE").

The documentation originally advertised a `--e2ee on` flag and showed
`encrypted: true`. Those docs have since been corrected to describe the current
unencrypted behavior with a "no `--e2ee` flag yet" note
(`docs/architecture.md:144-148`, `docs/user-guide.md` create section), so the
immediate docs-overstatement is already addressed as an interim. What remains is
the *implement* arm of the issue: now that the E2EE receive path is in place, add
real encryption-on-create.

This work is unblocked by #240, which has since landed: the daemon now builds its
Matrix client with a persistent SQLite crypto store
(`build_client_with_store`, `crates/mx-agent-daemon/src/matrix.rs:196-213`; used
by `restore_client`, `matrix.rs:396-431`), ships `e2e-encryption` in production
(`crates/mx-agent-daemon/Cargo.toml:31`), decrypts privileged events, and **fails
safe** by skipping any undecryptable `m.room.encrypted` event before
authorization (`event_router.rs:322-325`). The decrypt path the issue named as a
prerequisite is therefore ready.

## Goals

- Add an opt-in `--e2ee <on|off>` flag to `mx-agent workspace create`, matching
  the originally-documented `--e2ee on` syntax. Default **off** (preserves
  today's behavior).
- When `--e2ee on`, create the workspace **born encrypted**: include an
  `m.room.encryption` (Megolm v1) event in the room's `initial_state` so the room
  is encrypted from its first event, with no unencrypted window.
- Surface the real encryption state through `WorkspaceInfo.encrypted` so a `create
  --e2ee on` reports `encrypted: true` in both human and `--json` output, and a
  default create still reports `encrypted: false`.
- Thread the new option through the existing stateless-CLI → IPC → daemon path
  (`workspace.create`) without the CLI touching Matrix state.
- Keep the change additive and backward compatible: an older CLI that omits the
  new IPC field, and older tasks/sessions, continue to work (default off).
- Update the docs and CLI help to describe the real flag instead of the interim
  "not implemented" note.

## Non-Goals

- **Turning E2EE on by default** for all new workspaces. That is a separate
  rollout decision (interop, key-backup/device-verification UX prerequisites) and
  is captured as an open question, not delivered here.
- Encrypting **existing** rooms created before this change (no migration/backfill;
  `enable_encryption` on an existing room is out of scope here).
- Device verification, cross-signing, key backup/recovery, or the
  `require_verified_device` policy gate — all delivered under #240/#260 and only
  cross-referenced here.
- Changing the execution authorization model. Encryption is a transport property;
  signing + trust + policy + approval remain the sole execution gate (§1.2).
- Per-room encryption tuning beyond Megolm recommended defaults (custom rotation
  periods, algorithm negotiation).

## Relevant Repository Context

- **Crate split.** The CLI (`mx-agent-cli`) is stateless and never builds a Matrix
  client; the daemon (`mx-agent-daemon`) owns the Matrix session, crypto store,
  and all room operations. `workspace create` flows
  CLI → IPC `workspace.create` → daemon `create_workspace_for_session` →
  `create_workspace`.
- **CLI surface.** `WorkspaceCreateArgs` (`crates/mx-agent-cli/src/cli.rs:277-291`)
  exposes `--alias/--name/--topic/--visibility` only. `workspace_create`
  (`cli.rs:1928-1947`) maps these into `mx_agent_daemon::CreateWorkspaceOptions`
  and issues `daemon_ipc_call::<_, WorkspaceInfo>(global, "workspace.create", …)`.
  `report_workspace_info` (`cli.rs:1911-1926`) prints `encrypted: {…}`.
- **Daemon dispatch.** `lifecycle.rs:636-641` parses `CreateWorkspaceOptions` and
  calls `create_workspace_for_session`, which restores an authenticated client via
  `restore_client` (crypto-store-backed) and calls `create_workspace`
  (`workspace.rs:389-425`).
- **Room creation today.** `create_workspace` builds a
  `create_room::v3::Request`, sets `name`/`topic`/`room_alias_name`, and maps
  visibility to `Visibility` + `RoomPreset` (`workspace.rs:393-406`). It then
  `client.create_room(request)` and returns `WorkspaceInfo::from_room`
  (`workspace.rs:106-115`), which reads `room.encryption_state().is_encrypted()`.
- **Options + info types.** `CreateWorkspaceOptions` (`workspace.rs:60-82`) and
  `WorkspaceInfo` (`workspace.rs:84-121`) are `Serde` types re-exported from
  `mx_agent_daemon` (`lib.rs:217-218`) and used both as IPC params/results and in
  the CLI.
- **Crypto stack is present.** `matrix-sdk = { features = ["e2e-encryption",
  "bundled-sqlite"] }` (`crates/mx-agent-daemon/Cargo.toml:31`); ruma 0.34 /
  ruma-client-api 0.24 are pinned (`Cargo.lock`). The daemon's restored client has
  a persistent crypto store, so it can transparently encrypt outgoing events in an
  encrypted room.
- **Receive path is fail-safe.** The event router skips undecryptable
  `m.room.encrypted` events before classification (`event_router.rs:18-19,
  322-325`, `RouteOutcome::SkippedEncrypted`), so turning on room encryption never
  routes an opaque privileged event.
- **Encryption helper precedent.** The integration tests already enable room
  encryption via `room.enable_encryption()` (the two-step approach) in
  `create_encrypted_room` (`crates/mx-agent-daemon/tests/matrix_integration.rs:334-366`),
  and `daemon_e2ee_privileged_event_coverage` proves a signed privileged event in
  an encrypted room decrypts and routes.
- **Conventions.** Human output by default, `--json` for automation; `#![forbid(unsafe_code)]`
  workspace-wide; MSRV 1.74; Unix-only; `missing_docs` is denied in CI, so new
  public items need doc comments. Specs follow `specs/issue-<n>-<slug>.md`.

## Proposed Implementation

Recommended arm: **implement `--e2ee on`** (born-encrypted via `initial_state`),
default **off**.

### 1. CLI flag (`crates/mx-agent-cli/src/cli.rs`)

- Add a `ValueEnum` to match the documented `on|off` syntax, e.g.:
  ```rust
  /// Whether to enable end-to-end encryption on `workspace create`.
  #[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
  enum E2ee { On, Off }
  ```
- Add the field to `WorkspaceCreateArgs`:
  ```rust
  /// Enable end-to-end encryption for the new workspace (default: off).
  #[arg(long, value_enum, default_value_t = E2ee::Off)]
  e2ee: E2ee,
  ```
- In `workspace_create` (`cli.rs:1928`), map `E2ee::On => true` / `E2ee::Off =>
  false` into a new `CreateWorkspaceOptions.e2ee: bool` field.
- Decision: use a value-enum `--e2ee on|off` rather than a bare boolean `--e2ee`,
  because the original docs (and operator muscle memory) used `--e2ee on`, and an
  explicit `off` reads clearly. (A bare `--e2ee` boolean is an acceptable
  alternative if the team prefers; pick one and keep docs consistent.)

### 2. Options type + room build (`crates/mx-agent-daemon/src/workspace.rs`)

- Extend `CreateWorkspaceOptions` with an additive, default-false field so older
  IPC callers still deserialize:
  ```rust
  /// Enable end-to-end encryption on the created room (default: false).
  #[serde(default)]
  pub e2ee: bool,
  ```
  Update `Default for CreateWorkspaceOptions` to set `e2ee: false`.
- In `create_workspace`, when `options.e2ee` is set, push an `m.room.encryption`
  event into `request.initial_state` before `client.create_room`. Build the
  content with ruma's recommended Megolm defaults and serialize to a
  `Raw<AnyInitialStateEvent>`. Sketch (confirm exact paths against the pinned
  ruma 0.34 API):
  ```rust
  use matrix_sdk::ruma::events::{room::encryption::RoomEncryptionEventContent, InitialStateEvent};
  // EventEncryptionAlgorithm::MegolmV1AesSha2 via RoomEncryptionEventContent::new(...)
  // or RoomEncryptionEventContent::with_recommended_defaults() in ruma 0.34.
  if options.e2ee {
      let content = RoomEncryptionEventContent::with_recommended_defaults();
      let raw = InitialStateEvent::new(content).to_raw_any();
      request.initial_state = vec![raw];
  }
  ```
  Prefer `initial_state` over a post-create `room.enable_encryption()` so the room
  is encrypted from event zero (no unencrypted window) and the operation stays a
  single round-trip. Keep `enable_encryption()` only as a documented fallback if
  the `initial_state` API proves awkward against the pinned SDK.

### 3. Accurate `encrypted` read-back (`WorkspaceInfo`)

`WorkspaceInfo::from_room` reads `room.encryption_state().is_encrypted()`. Right
after `create_room` returns, the local store may not yet reflect the
`initial_state` encryption event (it can lag the create response / first sync), so
the freshly-built `WorkspaceInfo` could report `encrypted: false` even for an
encrypted create. Resolve by OR-ing the requested setting with the room state so
the reported flag never *under*-reports:
- Add a constructor variant, e.g.
  `WorkspaceInfo::from_room_with_e2ee(room: &Room, requested_e2ee: bool)`, that
  sets `encrypted = requested_e2ee || room.encryption_state().is_encrypted()`, and
  have `create_workspace` use it. `join`/`status` keep reading live state via the
  existing `from_room`. (Document the rationale in the doc comment.)
- This keeps the invariant: `create --e2ee on` always reports `encrypted: true`;
  default create reports the room's true state (`false`).

### 4. Pass-through (`lifecycle.rs`)

No logic change is needed in `workspace.create` dispatch — it already parses
`CreateWorkspaceOptions` and forwards it. The `#[serde(default)]` on the new field
preserves compatibility with an older CLI that omits `e2ee`. Add a regression test
asserting `workspace.create` params without `e2ee` still deserialize.

### 5. Testable seam

Room-request construction is currently inline and only exercisable against a live
homeserver. Extract a small pure helper, e.g.
`fn build_create_room_request(options: &CreateWorkspaceOptions) ->
create_room::v3::Request`, so a unit test can assert that `e2ee: true` yields an
`initial_state` containing one `m.room.encryption` (Megolm v1) event and `e2ee:
false` yields an empty `initial_state` — no homeserver required.

## Affected Files / Crates / Modules

- `crates/mx-agent-cli/src/cli.rs` — `E2ee` value enum, `WorkspaceCreateArgs.e2ee`
  field, `workspace_create` mapping, CLI parse tests (extend
  `workspace_create_defaults_to_private` / `workspace_create_accepts_flags`).
- `crates/mx-agent-daemon/src/workspace.rs` — `CreateWorkspaceOptions.e2ee`,
  `Default`, `create_workspace` initial_state, `build_create_room_request` helper,
  `WorkspaceInfo::from_room_with_e2ee`, unit tests.
- `crates/mx-agent-daemon/src/lifecycle.rs` — no behavior change; add a
  back-compat deserialization test for `workspace.create` params.
- `crates/mx-agent-daemon/src/lib.rs` — re-exports already cover the changed types;
  verify nothing else needs export.
- `crates/mx-agent-daemon/tests/matrix_integration.rs` — new `#[ignore]`d live test
  for encrypted-on-create (reuse the `create_encrypted_room`/decrypt helpers).
- `docs/architecture.md`, `docs/user-guide.md`, `README.md` — documentation
  updates (below).

## CLI / API Changes

- **CLI:** `mx-agent workspace create` gains `--e2ee <on|off>` (default `off`).
  Help text: "Enable end-to-end encryption for the new workspace (default: off)."
- **Public API (daemon):** `CreateWorkspaceOptions` gains a public `e2ee: bool`
  field (documented). `WorkspaceInfo` gains a `from_room_with_e2ee` constructor
  (documented); the existing `from_room` is unchanged. A
  `build_create_room_request` helper may be `pub(crate)`.
- **IPC:** `workspace.create` params (`CreateWorkspaceOptions`) carry the new
  optional `e2ee` field. Additive and `#[serde(default)]`, so the method signature
  in architecture §10.3 is unchanged and older callers remain compatible. No new
  IPC method.

## Data Model / Protocol Changes

- **Matrix room state:** an encrypted-on-create room carries a standard
  `m.room.encryption` state event (`algorithm: m.megolm.v1.aes-sha2`) set at
  creation via `initial_state`. This is standard Matrix, not an mx-agent custom
  event; no `com.mxagent.*` schema changes.
- **IPC param schema:** `CreateWorkspaceOptions` gains `e2ee: bool`
  (`#[serde(default)]`, default `false`). Backward compatible.
- **`WorkspaceInfo.encrypted`** semantics are unchanged (still "is the room
  encrypted"); it can now legitimately be `true` for a fresh create.
- No persistence/migration changes; no changes to signing, policy, or trust
  schemas.

## Security Considerations

- **Encryption ≠ authorization.** Reiterate the §1.2 invariant explicitly in code
  comments and docs: an encrypted workspace changes only *channel confidentiality*
  (who the homeserver can read), not who may cause execution. Room membership,
  device presence/verification, and now room encryption never substitute for
  Ed25519 signature + local trust + deny-by-default policy + optional approval. Do
  not let `encrypted: true` be read anywhere as a trust signal.
- **Fail-safe receive path is required and present.** With encryption on,
  undecryptable privileged events are skipped before authorization
  (`event_router.rs:322-325`). Confirm this path is unaffected; never weaken it to
  "best-effort decrypt then run."
- **Megolm key sharing exposure.** In an encrypted room the daemon shares room
  keys with member devices. A malicious/unverified device that is a room member
  can still receive keys under TOFU. Document that operators relying on
  confidentiality should pair `--e2ee on` with device verification and the
  optional `require_verified_device` policy gate (#240), and enable key backup
  (`recovery enable`) so history survives restart.
- **CLI stays secret-free.** The CLI only passes a boolean; all crypto, tokens,
  and device keys remain in the daemon. No token or key material crosses IPC. No
  new logging of secrets; log only non-sensitive metadata (room id, `e2ee` bool)
  consistent with existing redaction/`Secret` patterns.
- **Default off is the safe default.** Shipping default-on would silently change
  interop (peers without E2EE-capable daemons could not read the room) and would
  imply confidentiality before device-verification/key-backup UX is routinely
  used. Opt-in keeps the deny-by-default posture and avoids over-claiming.
- **Unix-only assumptions** are unchanged; no platform-specific paths added.

## Testing Plan

- **CLI unit (`cli.rs`):**
  - `workspace create` defaults to `e2ee: off` (extend
    `workspace_create_defaults_to_private`).
  - `--e2ee on` and `--e2ee off` parse to the expected enum; `--e2ee on` maps to
    `CreateWorkspaceOptions.e2ee == true` in `workspace_create`.
  - `command_path` for `workspace create` unchanged.
- **Daemon unit (`workspace.rs`):**
  - `build_create_room_request` with `e2ee: true` produces exactly one
    `m.room.encryption` Megolm-v1 `initial_state` event; with `e2ee: false`
    produces an empty `initial_state`. (No homeserver.)
  - `CreateWorkspaceOptions` serde round-trips with and without `e2ee`; a JSON
    object lacking `e2ee` deserializes to `false` (back-compat).
  - `WorkspaceInfo::from_room_with_e2ee` reports `encrypted: true` when requested
    even if room state has not yet propagated; `--json` round-trips
    `"encrypted":true`.
- **Daemon back-compat (`lifecycle.rs`):** `workspace.create` params JSON without
  `e2ee` deserialize successfully (older CLI compatibility).
- **Live integration (`matrix_integration.rs`, `#[ignore]`, real homeserver):**
  - Create a workspace through `create_workspace` with `e2ee: true`; assert the
    returned `WorkspaceInfo.encrypted == true` and, after a sync,
    `room.encryption_state().is_encrypted() == true`.
  - Create a default workspace; assert `encrypted == false`.
  - End-to-end: in the encrypted-on-create room, publish a signed privileged
    event and assert it decrypts and routes through verify → trust → policy
    (reuse the `daemon_e2ee_privileged_event_coverage` machinery), proving
    encryption-on-create composes with the existing decrypt path.
  - Run via the documented harness (`scripts/matrix_integration_test.sh`).
- **Docs/CLI snapshot:** ensure `mx-agent workspace create --help` lists `--e2ee`
  and that no doc shows behavior the build does not provide.

## Documentation Updates

- `docs/architecture.md` §3 (Workspace Commands): replace the interim "Note
  (current behavior): no `--e2ee` flag yet" note (around `:144-148`) with the real
  flag — show `mx-agent workspace create … --e2ee on` and that it reports
  `encrypted: true`; keep a line stating default is unencrypted (opt-in) for the
  alpha and cross-reference device verification + key backup (#240) as
  recommended companions.
- `docs/user-guide.md` (Create a workspace): update the example and the note —
  default create still prints `encrypted: false`; `--e2ee on` prints `encrypted:
  true`. Remove the "no `--e2ee` flag yet" wording.
- `README.md` status table: update the "E2EE privileged-event handling" /
  "E2EE production hardening" rows (or add a note) to record that
  encryption-on-create is available via `workspace create --e2ee on` (opt-in).
- CLI help text for `--e2ee` (auto-rendered into generated man pages/completions
  via the hidden `generate` command).
- Doc comments on the new public `CreateWorkspaceOptions.e2ee` field,
  `WorkspaceInfo::from_room_with_e2ee`, and the `E2ee` enum (CI denies
  `missing_docs`).
- Optionally add a short memory/changelog note that the docs no longer overstate
  (this issue closes the gap the v0.2.0 assessment flagged).

## Risks and Open Questions

- **Default on vs off?** Recommended **off** (opt-in) for this change. Flipping the
  default to on is a separate decision requiring: peers run E2EE-capable daemons;
  device-verification + key-backup are part of the normal setup; and interop
  expectations are documented. Track the flip as a follow-up under the #240 epic.
  *Needs confirmation.*
- **`--e2ee on|off` enum vs bare boolean `--e2ee`.** Recommended enum to match the
  originally-documented `--e2ee on`. *Needs confirmation* if the team prefers a
  bare flag.
- **Read-back timing.** `room.encryption_state()` may lag immediately after
  create; the `requested || live` OR resolves it. Confirm the chosen ruma 0.34 API
  (`with_recommended_defaults` vs explicit `MegolmV1AesSha2`) and that
  `client.create_room` surfaces the `initial_state` encryption into the returned
  `Room` consistently.
- **Interop / lock-out.** An encrypted room is unreadable to non-E2EE-capable or
  unprovisioned members; document this so operators do not create encrypted
  workspaces for peers that cannot decrypt. Existing unencrypted rooms are
  unaffected (no migration).
- **Send path in encrypted rooms.** Outgoing mx-agent privileged events are
  encrypted transparently by matrix-sdk once the room is encrypted and the crypto
  store is present (it is). #240/#260 already exercise privileged events in
  encrypted rooms, but the live integration test should confirm the
  encrypted-on-create variant end-to-end.
- **Ruma API surface.** The exact `RoomEncryptionEventContent` / `InitialStateEvent`
  / `to_raw_any` names should be confirmed against the pinned ruma 0.34 /
  matrix-sdk 0.18; the `enable_encryption()` two-step is the documented fallback.

## Implementation Checklist

1. `crates/mx-agent-daemon/src/workspace.rs`: add `#[serde(default)] pub e2ee:
   bool` to `CreateWorkspaceOptions`; set it `false` in `Default`.
2. Extract `build_create_room_request(options)` and, when `options.e2ee`, push one
   `m.room.encryption` (Megolm v1, recommended defaults) event into
   `request.initial_state`; route `create_workspace` through the helper.
3. Add `WorkspaceInfo::from_room_with_e2ee(room, requested_e2ee)` that sets
   `encrypted = requested_e2ee || room.encryption_state().is_encrypted()`; use it
   in `create_workspace`. Document both with doc comments.
4. `crates/mx-agent-cli/src/cli.rs`: add the `E2ee { On, Off }` value enum and the
   `--e2ee` field (default `Off`) to `WorkspaceCreateArgs`; map it into
   `CreateWorkspaceOptions.e2ee` in `workspace_create`.
5. Unit tests: CLI parse (`--e2ee on/off`/default + mapping); daemon
   `build_create_room_request` initial_state assertions; `CreateWorkspaceOptions`
   serde back-compat; `WorkspaceInfo` encrypted read-back/JSON.
6. `crates/mx-agent-daemon/src/lifecycle.rs`: add the back-compat deserialization
   test for `workspace.create` params lacking `e2ee`.
7. Add the `#[ignore]`d live integration test in `matrix_integration.rs`
   (encrypted-on-create reports `encrypted: true`; default create reports
   `false`; signed privileged event decrypts and routes).
8. Update `docs/architecture.md`, `docs/user-guide.md`, and `README.md` to
   document the real `--e2ee on` flag (opt-in, default unencrypted) and remove the
   interim "not implemented" notes; cross-reference #240 device verification + key
   backup.
9. Run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D
   warnings`, and `cargo test --all`; run the `#[ignore]`d live test via
   `scripts/matrix_integration_test.sh` where a homeserver is available.
10. Confirm the open questions (default off, `on|off` enum) with a maintainer
    before flipping any default.
