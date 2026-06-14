# Encrypt Media Offload and Close State-Event Confidentiality Gaps in E2EE Workspaces (issue #308)

## Problem Statement

`workspace create --e2ee on` (issue #249, shipped) makes a Matrix workspace room
born encrypted, so **timeline** events — exec/call requests, results, stream
chunks, the `com.mxagent.stream.artifact.v1` / `com.mxagent.context.share.v1`
*referencing* events, heartbeats — are Megolm-encrypted on the wire and opaque to
the homeserver operator. Two confidentiality channels, however, bypass Megolm
entirely and stay readable by the homeserver operator even in an encrypted room:

1. **Media offload is always plaintext.** When exec output exceeds the 256 KiB
   timeline budget (`DEFAULT_MAX_TIMELINE_OUTPUT_BYTES`), the full log is uploaded
   as a Matrix media object via `client.media().upload` and referenced by a plain
   `mxc://` URI; large context shares (`share` over 256 KiB) upload the same way.
   The *referencing event* is encrypted in an `--e2ee on` room, but the **media
   blob it points at is uploaded and downloaded as cleartext** (`MediaSource::Plain`).
   There are zero uses of `EncryptedFile` / `upload_encrypted_file` anywhere under
   `crates/`. So the most sensitive payload — the *full* command output, or a full
   shared file/diff/env snapshot — sits unencrypted on the homeserver.

2. **Privileged room state events are plaintext by Matrix spec.** Megolm only
   covers timeline events; `m.room.encrypted` is never applied to state events.
   The daemon publishes privileged data through state events that therefore leak
   even in an encrypted room:
   - `com.mxagent.task.v1` (`TaskState`) carries the full
     `TaskAction::Exec { command, cwd, env }` and the `result` payload.
   - `com.mxagent.invocation.v1` (`InvocationState`) carries requester/target and
     lifecycle.
   - `com.mxagent.agent.v1` (`AgentState`) carries capabilities, `cwd`,
     `project_id`, and the git commit, refreshed by the heartbeat loop.
   - `com.mxagent.workspace.v1` (`WorkspaceState`) carries project id, local path,
     and repo metadata.

On top of the behavior gaps, the documentation and its drift guard are stale:

- `docs/cli-reference.md` (the exec **Confidentiality** note) over-claims that in an
  encrypted workspace "traffic is opaque to the homeserver", which is false for
  the media blob and for all state events. The `share` notes imply `--e2ee on`
  covers shares, but media-offloaded share payloads stay plaintext.
- `scripts/check-doc-claims.sh` still says "RELAX WHEN #249 … LANDS" and errors
  with "workspace rooms are unencrypted; see #249" even though #249 shipped. It
  scans only 3 of 9 docs files and its denylist has no "opaque to the homeserver"
  pattern, so it cannot catch the current over-claim.
- The live suite has no encrypted **full round trip**: every daemon-executed
  handler round-trip test uses `create_public_room`; the two encrypted-room tests
  stop at decrypt + `authorize_*_request` and never assert that daemon-emitted
  result/stream events arrive encrypted and decrypt at the requester, nor that a
  >256 KiB artifact's media content round-trips encrypted.

This issue closes the media gap (the concrete, testable deliverable), commits to
and documents a confidentiality model for the plaintext state events, corrects the
docs, un-stales the drift guard, and adds an encrypted full-round-trip live test.

## Goals

- In an `--e2ee on` workspace, **encrypt media offload end to end**: exec output
  >256 KiB and every media-backed share upload as ciphertext using the Matrix
  `EncryptedFile` attachment scheme, and download + decrypt reproduces the original
  bytes and SHA-256 digest. Plaintext upload remains the behavior in unencrypted
  rooms.
- Carry the `EncryptedFile` key material on the referencing events
  (`StreamArtifact`, `ContextShare`) in a **backward-compatible** way; old
  plaintext `mxc://` references (pre-change events) still download.
- **Commit to and document a confidentiality model** for the plaintext state
  events (`task.v1` `command`/`env`/`result`, `invocation.v1`, `agent.v1`,
  `workspace.v1`): each plaintext state event type carries an explicit caveat, and
  the daemon surfaces an advisory warning when sensitive task `env` is published
  into an encrypted room (so operators do not assume confidentiality that does not
  exist for state).
- **Correct the docs**: scope "opaque to the homeserver" to timeline events only,
  state that media is encrypted under `--e2ee on` once this lands, and extend the
  existing plaintext-state caveat to the task/invocation/agent state sections.
- **Un-stale `scripts/check-doc-claims.sh`**: drop the #249 framing, widen the
  scanned file set to `README.md` + all `docs/*.md`, and add an "opaque to the
  homeserver"-class denylist pattern.
- Add a **live Tuwunel test** asserting the encrypted full round trip (exec / call
  / share handler dispatch, not just authorize), that daemon→requester
  result/stream events are `m.room.encrypted` on the wire, and that a >256 KiB
  artifact's media content round-trips as ciphertext and decrypts at the requester.

## Non-Goals

- **Encrypting Matrix state events themselves.** State events cannot be
  Megolm-encrypted (Matrix spec). Moving `command`/`env`/`result` *out* of state
  into encrypted timeline events that the scheduler resolves is a substantial
  task-engine redesign (it touches `state_rev` optimistic claiming, restart
  recovery, and the approval path — all of which this issue must not weaken). It is
  explicitly deferred to a follow-up; see Risks & Open Questions.
- **Redacting/hashing `env` in published task state.** The scheduler reads the
  action (`command`/`cwd`/`env`) directly from `task.v1` state to execute it;
  redacting those in state would break execution. Confidentiality for executable
  task actions requires the deferred encrypted-timeline-offload redesign, not
  redaction. Within this issue, the env exposure is documented and an advisory
  warning is emitted, not silently mutated.
- **Changing the execution gate.** Room encryption changes *who can read*, never
  *who may execute*. Ed25519 signature + local trust + deny-by-default policy +
  approval remain the only execution authority; nothing here touches them.
- **Encrypting loopback large output.** A loopback `exec` has no homeserver to
  upload to; it already delivers large output inline with an empty `mxc_uri`. That
  path is unchanged.
- **Turning E2EE on by default** (issue #240 rollout) — out of scope.
- **Inline (small) context-share or tail-preview confidentiality** — those ride
  the encrypted *timeline* event already, so they are not part of this gap.

## Relevant Repository Context

**Architecture.** The CLI is stateless; the long-running **daemon** owns all
Matrix state, credentials, the crypto store, policy, and supervision. Media
encrypt/decrypt happens daemon-side; the CLI never sees Matrix tokens, device
keys, or `EncryptedFile` material. Workspace layout: `mx-agent-protocol` (event
schemas, dependency-free — no `ruma`/`matrix-sdk`), `mx-agent-daemon` (Matrix +
crypto + media), plus `mx-agent-cli`, `mx-agent-ipc`, `mx-agent-policy`,
`mx-agent-sandbox`, `mx-agent-telemetry`. Unix-only; `unsafe_code = "forbid"`;
MSRV 1.74; `missing_docs` is a CI error.

**matrix-sdk 0.18 surface (already a dependency).** The daemon enables
`matrix-sdk = { features = ["e2e-encryption", "bundled-sqlite"] }`
(`crates/mx-agent-daemon/Cargo.toml:35`). That gives:
- `Client::upload_encrypted_file(&mut reader) -> Result<EncryptedFile>`
  (`matrix-sdk` `encryption/mod.rs`): encrypts the bytes client-side with
  `AttachmentEncryptor` (AES-CTR), uploads the ciphertext via `media().upload`, and
  returns a ruma `EncryptedFile { url, key (JWK), iv, hashes, v }`. The `hashes`
  carry a SHA-256 of the **ciphertext** that the SDK verifies on download.
- `Media::get_media_content(&MediaRequestParameters { source, format }, use_cache)`
  already decrypts when `source` is `MediaSource::Encrypted(Box<EncryptedFile>)`
  and the `e2e-encryption` feature is on; the plain path stays
  `MediaSource::Plain(OwnedMxcUri)`.
- `EncryptedFile` / `MediaSource` are at `matrix_sdk::ruma::events::room::{…}`.
- Room encryption is detected with `room.encryption_state().is_encrypted()`
  (already used in `WorkspaceInfo::from_room`, `workspace.rs:163`).

**Timeline vs. state classification** (`mx-agent-protocol/src/events.rs`):
- `STREAM_ARTIFACT` (`:55`) and `CONTEXT_SHARE` (`:57`) are **timeline** events
  (`timeline::ALL`), sent via `room.send_raw(...)` → Megolm-encrypted under
  `--e2ee on`. So the referencing events, tail preview, and inline share data are
  *already* protected; only the referenced **media blob** leaks.
- `AGENT`, `TASK`, `INVOCATION`, `TOOL`, `WORKSPACE`, `TRUST` are **state** events
  (`state::ALL`) → plaintext by spec regardless of room encryption.

**Media upload/download today.**
- Artifacts: `upload_artifact(client, prepared)` →
  `client.media().upload(&mime, bytes, None)` (`artifact.rs:204-218`), called from
  `emit_output_events(client, room, …)` in `exec.rs` (the `should_switch(total)`
  branch, ~`exec.rs:1112-1130`). Download via `MediaSource::Plain`
  (`artifact.rs:478-487`). `StreamArtifact::sha256` covers the *uploaded*
  (possibly zstd-compressed) bytes; `verify_and_decompress` checks the digest
  before decompressing.
- Shares: `upload_media_share(client, …)` →
  `client.media().upload(&mime, data, None)` (`context.rs:231-254`), reached from
  `share_context` when `data.len() > MAX_INLINE_BYTES` (`context.rs:442-450`).
  Download via `MediaSource::Plain` (`context.rs:269-279`). `ContextShare::sha256`
  covers the raw (decoded) bytes; `verify_digest` checks after download/decode.
  Small payloads are inlined in the (already-encrypted) timeline event.

**Sender-pin (issue #304).** Artifact and share retrieval pin the producing
agent's Matrix identity and reject shadows; the new encrypted path must preserve
this — the `encrypted_file` lives in event *content* (attacker-controllable for a
forged event), so the existing sender-pin on the raw event `sender` is still the
authority for *which* event to trust. No change to selection logic.

**State publishing call sites.** `TaskState` via `publish_task_state`
(`task.rs:517`, used by create/update/finalize); `InvocationState` via
`publish_invocation_state` (`exec.rs`); `AgentState` via `send_workspace_state`
(`agent.rs:166`) and refreshed in `heartbeat.rs:248`; `WorkspaceState` on attach.
The plaintext-state caveat is documented for the workspace-attach event only
(`docs/cli-reference.md:694`: "The state event is unencrypted so all workspace
members can read project metadata.").

**Drift guard.** `scripts/check-doc-claims.sh` denylists confidentiality
over-claims in docs; comment + error text reference #249 as unshipped; `files=()`
lists only `docs/cli-reference.md`, `README.md`, `docs/user-guide.md`.

## Proposed Implementation

### 1. Schema: backward-compatible `EncryptedFile` reference (mx-agent-protocol)

Add one optional field to each referencing struct in
`crates/mx-agent-protocol/src/schema.rs`, holding the ruma `EncryptedFile`
serialization as an **opaque `serde_json::Value`** (keeps the protocol crate free
of a `ruma`/`matrix-sdk` dependency and forward-compatible with ruma's JWK shape):

```rust
/// `EncryptedFile` key material (ruma `m.encrypted` file scheme) for a media
/// payload uploaded to an end-to-end-encrypted room. Present only when the media
/// blob is ciphertext; absent for a plaintext `mxc_uri` upload (the default and
/// the only form produced before this field existed). Carried as an opaque JSON
/// object so the protocol crate stays free of a ruma dependency. The bytes are
/// the AES-CTR key, IV, and ciphertext SHA-256 hashes; never log them.
#[serde(default, skip_serializing_if = "Option::is_none")]
pub encrypted_file: Option<serde_json::Value>,
```

- Add to `StreamArtifact` (`schema.rs:221`) and `ContextShare` (`schema.rs:292`).
- `#[serde(default)]` + `skip_serializing_if = "Option::is_none"` gives full
  backward compatibility: old events (no field) deserialize to `None`; new
  plaintext events do not serialize it.
- For both types keep `mxc_uri` populated with the **ciphertext** `EncryptedFile.url`
  on the encrypted path (so display, scanning, and the
  `StreamArtifact.mxc_uri.is_empty()` guard stay correct). The presence of
  `encrypted_file` — not the URI — selects the decrypt path on download.
- `sha256` semantics are unchanged: it still covers the bytes handed to the
  uploader (compressed-or-raw plaintext). The SDK independently verifies the
  ciphertext via `EncryptedFile.hashes`, giving defense-in-depth; our existing
  `verify_and_decompress` / `verify_digest` still run on the
  decrypted(-and-decompressed) bytes and pass unchanged.

### 2. Encrypt artifact upload when the room is encrypted (daemon)

In `crates/mx-agent-daemon/src/artifact.rs`:
- Change `upload_artifact` to take the room's encryption state, e.g.
  `pub async fn upload_artifact(client: &Client, prepared: PreparedArtifact, encrypted: bool)`.
  When `encrypted`:
  ```rust
  let mut reader = std::io::Cursor::new(prepared.upload_bytes().to_vec());
  let file = client.upload_encrypted_file(&mut reader).await
      .map_err(|e| ArtifactError::Upload(Box::new(e)))?;
  let mxc = file.url.to_string();
  let encrypted_file = serde_json::to_value(&file).ok();
  Ok(prepared.into_event_encrypted(mxc, encrypted_file))
  ```
  When `!encrypted`, keep the existing `media().upload` plain path.
- Add a `PreparedArtifact::into_event_encrypted(mxc_uri, encrypted_file)` (or
  extend `into_event` with an optional `encrypted_file`) that populates the new
  field.
- In `download_media` (`artifact.rs:477`), select the source from the artifact:
  `MediaSource::Encrypted(Box::new(serde_json::from_value::<EncryptedFile>(v)?))`
  when `artifact.encrypted_file` is `Some`, else the existing
  `MediaSource::Plain(parse_mxc(...))`. `get_media_content` decrypts the former.
  `verify_and_decompress` is then applied to the returned (decrypted) bytes
  exactly as today.

In `crates/mx-agent-daemon/src/exec.rs` (`emit_output_events`, which already holds
`room`):
- Compute `let encrypted = room.encryption_state().is_encrypted();` and pass it to
  `upload_artifact(client, prepared, encrypted)`.

### 3. Encrypt media-backed shares when the room is encrypted (daemon)

In `crates/mx-agent-daemon/src/context.rs`:
- Thread the room's encryption state into `upload_media_share` (it is reached from
  `share_context`, which already resolves the `Room` via `sync_and_get_room`). Add
  an `encrypted: bool` parameter computed from `room.encryption_state().is_encrypted()`.
- When `encrypted`, upload with `client.upload_encrypted_file`, then build the
  share with both `mxc_uri = Some(file.url)` and
  `encrypted_file = Some(serde_json::to_value(&file)?)`. Add a
  `build_encrypted_media_share(...)` mirroring `build_media_share`.
- In `download_media` (`context.rs:269`), branch on `share.encrypted_file`:
  `MediaSource::Encrypted(...)` vs the existing `MediaSource::Plain(...)`.
  `fetch_context` (`context.rs:619-622`) keeps its `Some(mxc_uri) => download_media`
  / `None => decode_inline` shape; only `download_media` changes internally.

### 4. State-event confidentiality model (the committed decision)

Because state events cannot be Megolm-encrypted and executable task actions must
keep their real `command`/`cwd`/`env` in state for the scheduler, the model for
this issue is **transparency + advisory**, not silent mutation:

- **Document the leak loudly per event type** (see Documentation Updates) — in
  `docs/cli-reference.md` for the task/invocation/agent state sections and in the
  schema doc-comments for `TaskAction::Exec`, `TaskResult` / `TaskState::result`,
  `InvocationState`, `AgentState`, and `WorkspaceState`.
- **Daemon advisory warning.** When a task action carrying a non-empty `env` is
  published into an **encrypted** room (where an operator might wrongly assume the
  env is confidential), emit one `tracing::warn!` per publish naming the room and
  the *count* of env keys — **never the keys or values** — e.g. "task action env
  (N keys) is published in room-state and is readable by the homeserver operator
  even in an encrypted room; do not place secrets in task env". Wire it at the
  task-action publish site (`task.rs` create/update path) and/or the scheduler
  dispatch path, guarded by `room.encryption_state().is_encrypted()` so unencrypted
  rooms (already documented as cleartext) are not spammed.
- The truly-confidential redesign (offload action/result into encrypted timeline
  events referenced by an opaque id, scheduler resolves on dispatch) is recorded as
  deferred follow-up in Risks & Open Questions; do **not** attempt it here.

### 5. Docs corrections

- `docs/cli-reference.md` exec **Confidentiality** note (the "opaque to the
  homeserver" line): reword to scope confidentiality to **timeline events**, state
  that under `--e2ee on` media offload is also encrypted (once this lands), and add
  that **Matrix state events** (`task`/`invocation`/`agent`/`workspace`) remain
  plaintext readable by the operator. Avoid the bare phrase "opaque to the
  homeserver" (the new drift-guard pattern) — use precise wording such as
  "timeline events and media offload are Megolm-encrypted and not readable by the
  homeserver operator; room **state** events remain plaintext".
- `share` notes: clarify that inline (small) shares ride the encrypted timeline
  event, and media-offloaded (large) shares are encrypted under `--e2ee on` once
  this lands; correct any implication that the prior plaintext media path was
  confidential.
- Extend the `:694`-style plaintext-state caveat to the `task` / `invocation` /
  `agent` state sections.

### 6. Refresh `scripts/check-doc-claims.sh`

- Drop the stale #249 framing: rewrite the header comment (lines ~7-17) and the
  error text (lines ~63-66) to state that media offload and timeline traffic are
  encrypted under `--e2ee on`, while **state events stay plaintext**, so docs must
  not claim whole-workspace confidentiality.
- Widen the scanned set to `README.md` plus **all** `docs/*.md` (glob, replacing
  the hand-listed 3), so `architecture.md` and `security-hardening.md` are covered.
- Add an "opaque to the homeserver"-class denylist pattern (e.g.
  `opaque to the homeserver`) that trips on the unscoped over-claim. Ensure the
  corrected docs do not contain the bare phrase, so the lint passes in CI.
- Keep the existing patterns; the script remains exit-0 clean / exit-1 on a hit.

### 7. Live encrypted full-round-trip test (daemon integration)

Add an `#[ignore]` test in
`crates/mx-agent-daemon/tests/matrix_integration.rs` (model it on
`daemon_e2ee_privileged_event_coverage` + the public-room handler round-trips),
using the existing `create_encrypted_room` helper and the two-user
(alice requester / bob executor) harness with megolm key sharing:

- Drive **handler dispatch** (not just `authorize_*_request`) for exec, call, and
  share inside the encrypted room.
- Assert daemon→requester **result and stream events are `m.room.encrypted` on the
  wire**: inspect the raw timeline event `type` (as `scan_stream_artifacts` reads
  `raw.get_field::<String>("type")`) and confirm the envelope type is
  `m.room.encrypted` for the result-direction events before decryption.
- Exec a command whose combined output **exceeds 256 KiB** so it offloads to an
  artifact; assert the published `StreamArtifact` carries `encrypted_file`, that the
  raw media downloaded via `MediaSource::Plain` is **not** the plaintext, and that
  retrieval (`retrieve_artifact`, which uses `MediaSource::Encrypted`) reproduces
  the original bytes and SHA-256 digest.
- Share a >256 KiB payload; assert the `ContextShare` carries `encrypted_file` and
  `fetch_context` round-trips the exact bytes.
- Keep the existing #295 live E2EE tests and the public-room round-trips green
  (the plain path must still produce plaintext `mxc://` with no `encrypted_file`).

## Affected Files / Crates / Modules

**Read / modify:**
- `crates/mx-agent-protocol/src/schema.rs` — add `encrypted_file: Option<Value>`
  to `StreamArtifact` (`:221`) and `ContextShare` (`:292`); update doc-comments on
  `TaskAction::Exec` (`:619`), `TaskResult` / `TaskState::result` (`:727`, `:794`),
  `InvocationState` (`:806`), `AgentState` (`:517`), `WorkspaceState` (`:478`) with
  the plaintext-state caveat.
- `crates/mx-agent-daemon/src/artifact.rs` — `upload_artifact` signature +
  encrypted upload; `PreparedArtifact::into_event{,_encrypted}`; `download_media`
  encrypted/plain branch; new unit tests.
- `crates/mx-agent-daemon/src/context.rs` — `upload_media_share` /
  `build_*_media_share` encrypted variant; `download_media` branch; thread
  `encrypted` from `share_context`; new unit tests.
- `crates/mx-agent-daemon/src/exec.rs` — pass `room.encryption_state().is_encrypted()`
  into `upload_artifact` in `emit_output_events` (~`:1112-1130`).
- `crates/mx-agent-daemon/src/task.rs` (and/or scheduler dispatch) — advisory
  env-in-encrypted-room warning at the task-action publish site.
- `scripts/check-doc-claims.sh` — un-stale, widen files, add pattern.
- `docs/cli-reference.md` — exec confidentiality note, share notes, task/invocation/
  agent plaintext-state caveats.
- `crates/mx-agent-daemon/tests/matrix_integration.rs` — new encrypted
  full-round-trip test (reuse `create_encrypted_room`, two-daemon harness).

**Read for context:** `crates/mx-agent-daemon/src/workspace.rs` (encryption-state
detection, `WorkspaceInfo`), `crates/mx-agent-protocol/src/events.rs` (timeline vs
state), `crates/mx-agent-daemon/Cargo.toml` (`e2e-encryption` feature),
`docs/architecture.md` (§6 context, §8.3/§8.4 artifacts, §9 state), README status
table.

## CLI / API Changes

- **No new CLI flags or commands.** `workspace create --e2ee on`, `exec`, and
  `share` keep their existing surface; behavior changes only in *how* media is
  stored (ciphertext vs plaintext) inside an already-encrypted room.
- **Public Rust API (daemon-internal crate):** `upload_artifact` gains an
  `encrypted: bool` parameter; `upload_media_share` gains an `encrypted` parameter;
  `PreparedArtifact` gains an encrypted-event constructor. New/changed public items
  must carry doc-comments (`missing_docs` is a CI error). These are
  `mx-agent-daemon` internals, not a stable external API.
- Human-readable default output and `--json` are preserved for `exec`/`share`;
  no output-shape change (the `mxc://` reference still appears; `encrypted_file` is
  an internal event field, not surfaced as user output).

## Data Model / Protocol Changes

- **`StreamArtifact` and `ContextShare`** gain
  `encrypted_file: Option<serde_json::Value>` (opaque ruma `EncryptedFile` JSON),
  `#[serde(default, skip_serializing_if = "Option::is_none")]`. Backward compatible:
  - Old events without the field deserialize to `None` → plaintext `MediaSource::Plain`
    download (unchanged).
  - New plaintext uploads omit the field.
  - New encrypted uploads set it alongside a ciphertext `mxc_uri`.
- **No state-event schema change.** `TaskState` / `TaskAction::Exec` /
  `InvocationState` / `AgentState` / `WorkspaceState` are unchanged on the wire
  (the env redesign is deferred); only their doc-comments gain caveats.
- **No persistence/policy format change.** No new policy keys; the crypto store and
  `e2e-encryption` feature already exist.
- `sha256` field semantics on both events are unchanged (cover pre-encryption
  bytes).

## Security Considerations

- **Secret handling / logging.** `EncryptedFile` key material (AES key, IV) and all
  decrypted payloads must never be logged. The advisory env warning logs only a
  *count* of env keys, never names or values. Use the existing
  `mx_agent_telemetry::Secret` / `redact` patterns where any value could surface.
- **Daemon/CLI separation.** All encrypt/decrypt happens daemon-side; the CLI never
  receives Matrix tokens, device keys, or `EncryptedFile` material. The
  `upload_encrypted_file` / `get_media_content` calls run inside the daemon's
  authenticated client only.
- **Execution gate unchanged.** Room encryption changes confidentiality (who can
  read), never authority. Ed25519 signature + local trust store + deny-by-default
  policy + optional verified-device + approval remain the sole execution gate
  (`workspace.rs:80-87` contract). No code path here grants execution based on
  membership or encryption.
- **Approval path untouched.** Approval-gated actions still require an
  authenticated, unexpired, signed decision before running; the media-encryption
  change is downstream of execution (it encrypts *output*), so it cannot bypass or
  weaken approval.
- **Integrity / sender-pin.** The producing agent's Matrix identity stays the
  authority for selecting which artifact/share event to trust (issue #304). The
  `encrypted_file` lives in attacker-controllable event content, so the existing
  sender-pin on the raw `sender` is retained; additionally the SDK verifies the
  ciphertext SHA-256 (`EncryptedFile.hashes`) and we re-verify the plaintext
  `sha256` after decrypt — a tampered blob fails closed with the existing
  `ArtifactIntegrity` / `ContextIntegrity` errors.
- **State-event leak is now explicit.** The committed model does not hide
  `command`/`env`/`result` in state (Matrix cannot); it documents the exposure and
  warns operators. This must be stated plainly so no over-claim is reintroduced
  (the drift guard enforces this).
- **Unix-only; no `unsafe`; MSRV 1.74.** No new platform assumptions;
  `upload_encrypted_file` / `EncryptedFile` are available in matrix-sdk 0.18 with
  the already-enabled `e2e-encryption` feature; no MSRV bump.

## Testing Plan

**Unit — `mx-agent-protocol`:**
- `StreamArtifact` / `ContextShare` JSON round-trip with `encrypted_file = Some(obj)`
  and with `None`.
- Deserialize legacy JSON (no `encrypted_file` field) → `None` (backward compat).
- Serialization omits `encrypted_file` when `None` (no wire bloat for plaintext).

**Unit — `mx-agent-daemon` (`artifact.rs`, `context.rs`):**
- Encrypted-vs-plain upload selection driven by the `encrypted` flag (mock/avoid
  network where possible; assert the produced event carries / omits
  `encrypted_file` and a ciphertext `mxc_uri`).
- Download path picks `MediaSource::Encrypted` when `encrypted_file` is present and
  `MediaSource::Plain` otherwise.
- `verify_and_decompress` / `verify_digest` still pass on decrypted+decompressed
  bytes; a tampered (corrupt) decrypted blob fails with the existing integrity
  error.
- Loopback empty-`mxc_uri` path is unchanged (no `encrypted_file`).

**Integration — live Tuwunel (`matrix_integration.rs`, `#[ignore]`):**
- New encrypted full-round-trip test (exec / call / share handler dispatch):
  - daemon→requester result/stream events are `m.room.encrypted` on the wire;
  - >256 KiB exec output offloads to an encrypted artifact; raw `MediaSource::Plain`
    download is ciphertext; `retrieve_artifact` reproduces original bytes + digest;
  - >256 KiB share round-trips encrypted via `fetch_context`.
- Regression: a public-room (`create_public_room`) artifact/share still uploads
  plaintext with no `encrypted_file` and round-trips.
- Existing #295 live E2EE tests
  (`daemon_e2ee_privileged_event_coverage`,
  `workspace_create_with_e2ee_enables_encryption_and_routes_privileged_events`,
  decrypt-after-restart, key-backup restore, two-daemon SAS) stay green.

**Documentation / CI:**
- `scripts/check-doc-claims.sh` runs clean against the widened file set with the
  new pattern; add/keep its CI invocation green.
- `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`,
  `cargo test --all`, `cargo build --all` stay green.

## Documentation Updates

- `docs/cli-reference.md`:
  - exec **Confidentiality** note — scope "opaque to the homeserver" to timeline
    events + media offload; state that room **state** events remain plaintext;
    avoid the bare "opaque to the homeserver" phrase.
  - `share` notes — inline shares ride the encrypted timeline event; media-offloaded
    shares are encrypted under `--e2ee on`; remove any plaintext-media confidentiality
    implication.
  - Add plaintext-state caveats to the `task` / `invocation` / `agent` sections
    (mirroring the existing workspace-attach note at `:694`).
- `README.md` status table — refine the "Large-output artifact mode" and/or
  E2EE rows to note media offload is encrypted in `--e2ee on` rooms while state
  events remain plaintext (avoid over-claiming).
- `docs/security-hardening.md` — document the state-event plaintext exposure and
  the "no secrets in task env" guidance; note media is encrypted under `--e2ee on`.
- `docs/architecture.md` — update §6 (context shares) and §8.3/§8.4 (artifacts) to
  describe the `EncryptedFile`-backed media path in encrypted rooms, and note the
  plaintext-state property for §9 state events.
- `scripts/check-doc-claims.sh` header/error text — rewritten as above.
- Wiki (`wiki/`) security/protocol pages, if they repeat the confidentiality
  claim, get the same scoping correction.

## Risks and Open Questions

- **State-event confidentiality model (decision recorded, confirm before merge).**
  This spec commits to *document-loudly + advisory-warning* for `task`/`invocation`/
  `agent`/`workspace` state, because Matrix state events cannot be Megolm-encrypted
  and the scheduler needs the real `command`/`env` in state. The stronger model —
  move action/result into encrypted **timeline** events referenced by an opaque id
  in state, with the scheduler resolving them on dispatch — is deferred as a
  follow-up because it touches `state_rev` optimistic claiming, restart recovery,
  and the approval path (which must not be weakened). Confirm this scoping is
  acceptable; if the stronger model is required now, scope expands substantially.
- **Drift-guard pattern vs. corrected docs.** The new "opaque to the homeserver"
  denylist pattern must not trip on the corrected, scoped phrasing. Mitigation:
  reword the docs to avoid the bare phrase (use "not readable by the homeserver
  operator" scoped to timeline + media). Verify the lint passes after the doc edits.
- **`encrypted_file` as opaque `Value` vs. typed struct.** Storing the ruma
  `EncryptedFile` as `serde_json::Value` keeps `mx-agent-protocol` dependency-free
  and forward-compatible, at the cost of a `from_value::<EncryptedFile>` parse on
  the daemon side (which fails closed to a retrieval error if malformed). Confirm
  this trade-off vs. mirroring the fields in a protocol-native struct.
- **`mxc_uri` redundancy on the encrypted path.** Populating both `mxc_uri`
  (ciphertext url) and `encrypted_file` is intentional (preserves display, scan,
  and the non-empty guard) but stores the url twice. Decoupling (empty `mxc_uri`,
  reference solely via `encrypted_file`) would require touching the
  `mxc_uri.is_empty()` guard and is not recommended.
- **Live-test cost.** The encrypted full-round-trip test needs megolm key sharing
  between two daemons and a >256 KiB upload; it is `#[ignore]`d and runs only in the
  Tuwunel suite. Watch for flakiness vs. the existing E2EE tests' sync timing
  (reuse their wait helpers).
- **Pre-existing plaintext media on the homeserver.** Media uploaded before this
  change stays plaintext on the server; this is download-compatible (old `mxc://`
  references still resolve) but those blobs are not retroactively encrypted —
  expected and acceptable.

## Implementation Checklist

1. **Schema (protocol).** Add `encrypted_file: Option<serde_json::Value>`
   (`#[serde(default, skip_serializing_if = "Option::is_none")]`, doc-commented) to
   `StreamArtifact` and `ContextShare` in `schema.rs`. Add protocol unit tests:
   round-trip with/without the field and legacy-JSON deserialize.
2. **Artifact upload (daemon).** Change `upload_artifact` to take `encrypted: bool`;
   on `true`, `client.upload_encrypted_file(&mut Cursor::new(bytes))`, build the
   event with ciphertext `mxc_uri` + `encrypted_file`; on `false`, keep the plain
   path. Add `PreparedArtifact::into_event_encrypted` (or extend `into_event`).
3. **Artifact download (daemon).** Branch `download_media` on `encrypted_file`:
   `MediaSource::Encrypted(Box::new(from_value::<EncryptedFile>))` vs `Plain`. Keep
   `verify_and_decompress` after download. Unit-test both branches + integrity.
4. **Exec wiring.** In `emit_output_events`, pass
   `room.encryption_state().is_encrypted()` into `upload_artifact`.
5. **Share upload/download (daemon).** Add `encrypted` to `upload_media_share` and
   a `build_encrypted_media_share`; thread `encrypted` from `share_context`; branch
   `context.rs` `download_media` on `encrypted_file`. Unit-test both branches.
6. **State-event documentation + advisory.** Add plaintext-state caveats to the
   schema doc-comments (`TaskAction::Exec`, `TaskResult`/`TaskState::result`,
   `InvocationState`, `AgentState`, `WorkspaceState`). Add the daemon advisory
   `tracing::warn!` (env key *count* only, never values) when a task action with
   non-empty `env` is published into an encrypted room.
7. **Docs.** Correct `docs/cli-reference.md` exec confidentiality + share notes;
   add task/invocation/agent plaintext-state caveats. Update README status row,
   `security-hardening.md`, and `architecture.md` §6/§8/§9. Avoid the bare "opaque
   to the homeserver" phrase.
8. **Drift guard.** Rewrite `scripts/check-doc-claims.sh` header/error text (drop
   #249 framing), widen `files` to `README.md` + `docs/*.md`, add the
   "opaque to the homeserver"-class pattern. Run it; ensure clean.
9. **Live test.** Add the encrypted full-round-trip `#[ignore]` test in
   `matrix_integration.rs` (exec/call/share dispatch, `m.room.encrypted`
   result-direction assertion, >256 KiB encrypted artifact + share round-trip).
   Confirm public-room and existing E2EE tests stay green.
10. **Green checks.** `cargo fmt --check`, `cargo clippy --all-targets
    --all-features -- -D warnings`, `cargo test --all`, `cargo build --all`, and
    `scripts/check-doc-claims.sh` all pass.
