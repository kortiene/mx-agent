# Sender-Pin and Sign the Result Plane (issue #304)

## Problem Statement

mx-agent authenticates the **request** plane but not the **result** plane.
`com.mxagent.exec.request.v1` and `com.mxagent.call.request.v1` carry an Ed25519
`signature` + `nonce` and are routed as privileged, verified against the
requester's published signing key + the local trust store + deny-by-default
policy (`event_router.rs:168-177`, `call.rs:726-771`). The results those requests
produce are neither signed nor sender-pinned:

- `CallResponse` has **no** `signature`/`nonce` field, unlike `CallRequest`
  (`crates/mx-agent-protocol/src/schema.rs:386-398` vs `:356-382`).
  `emit_call_response` publishes it raw via `room.send_raw(CALL_RESPONSE, …)`
  (`crates/mx-agent-daemon/src/call.rs:385-396`).
- `wait_for_call_response` returns the **first** timeline `call.response` whose
  `request_id` matches, with **no sender check**
  (`crates/mx-agent-daemon/src/call.rs:544-570`) — contrast the request path,
  which checks signature/trust and `verification::sender_verified(…)`
  (`call.rs:760`).
- The sync loop forwards `StreamChunk` / `StreamArtifact` / `ExecRejected` /
  `ExecFinished` / `ExecCancelled` / `CallResponse` to waiting IPC subscribers
  keyed **only** on `invocation_id` / `request_id`
  (`crates/mx-agent-daemon/src/sync.rs:425-448` → `publish_forwarded`
  `sync.rs:461-486` → `exec_subscribers.rs:52-63`, `:127-149`); `meta.sender` is
  logged but never enforced.
- These categories are classified **non-privileged**, so no signature/replay gate
  applies: `is_privileged()` matches only
  `ExecRequest|ExecStdin|ExecCancel|CallRequest|PtyResize`
  (`crates/mx-agent-daemon/src/event_router.rs:168-177`).
- Per-chunk `sha256` is `None` from **both** real producers — the buffered stream
  encoder (`crates/mx-agent-daemon/src/stream.rs:617-629`) and the PTY emitter
  (`crates/mx-agent-daemon/src/exec.rs:1427-1447`) — so the CLI strict digest
  check (`crates/mx-agent-cli/src/stream.rs:385-396`) is **vacuous**; only
  sequence gaps trip `EXIT_STREAM_INTEGRITY` (`132`, `stream.rs:53`).
- Artifact/share retrieval scans recent timeline events and selects with **no
  sender check**: `select_artifact` takes the newest `invocation_id`+`stream`
  match (`crates/mx-agent-daemon/src/artifact.rs:394-402`), `list_stream_artifacts`
  parses any `stream.artifact` event (`artifact.rs:475-497`), and
  `list_context_shares` parses any `context.share` event
  (`crates/mx-agent-daemon/src/context.rs:495-516`).

**Impact.** Both `request_id` and `invocation_id` travel in cleartext over the
same room timeline. Any member of a workspace room who observes an in-flight id
can forge a `call.response`, fake an `exec.finished` exit status, inject
stdout/stderr chunks, or shadow a legitimate artifact with a self-consistent
digest — and the daemon/CLI will accept it. This breaks the project's core
invariant that **room membership is NOT execution permission** (architecture
§1.2, §13) for everything *downstream* of a dispatch: a faked exit `0` can mark a
task succeeded and unblock the DAG; a forged `call.response` feeds a malicious
result to the caller; a shadowed artifact serves attacker-controlled bytes whose
digest verifies. Found by the 2026-06-11 feature-completeness re-assessment
(HEAD `a7680e8`, follow-up to epic #274); `priority:p1`.

## Goals

- Establish and **document** a single result-plane trust model so that accepting
  any result/stream/artifact/share event traces to a verifiable producer
  identity, never to mere room presence.
- Pin `call.response` consumption: a `call.response` whose Matrix sender is not
  the resolved executing/targeted agent can never satisfy
  `wait_for_call_response`.
- Pin forwarded result/stream events: a forged `StreamChunk` / `ExecFinished` /
  `ExecCancelled` / `ExecRejected` / `StreamArtifact` from a non-executing member
  is dropped before it reaches a waiting IPC subscriber.
- Make the per-chunk integrity guard real: both producers populate `sha256`, and
  a chunk whose digest does not match its bytes fails the CLI strict check
  (`EXIT_STREAM_INTEGRITY`).
- Pin artifact/share selection to the requester-known producer so a room member
  cannot shadow a legitimate artifact or context share with a same-id event.
- For the authoritative, low-volume result events, root acceptance in **Ed25519 +
  the local trust store** (model (b) below), mirroring the request plane and the
  `ApprovalDecision` precedent (#264), so authority does not rest on the
  homeserver-asserted `sender`.
- Keep every change **additive and fail-closed**: a check only ever *rejects* a
  forged/unverifiable result; it never accepts one. A legitimate executor's
  result still resolves end-to-end (loopback and remote).

## Non-Goals

- **Heartbeat sender pinning** (`read_latest_heartbeats`,
  `heartbeat.rs:270-294`). Display-only, lower stakes, already a documented caveat
  (`docs/architecture.md:905-909`) and tracked under the companion liveness issue
  #312. Out of scope here.
- Re-architecting the request plane, the policy engine, the approval queue, or the
  task scheduler. This issue concerns only what happens to *results*.
- Encrypting result events or changing E2EE/transport confidentiality (governed
  separately, architecture §1.2). Sender-pinning/signing is orthogonal to whether
  the room is encrypted.
- Per-**chunk** Ed25519 signatures. High-volume `stream.chunk` stays on
  sender-pinning + per-chunk `sha256`; the authoritative byte totals / exit status
  that bound the stream live on the (signed) `exec.finished`.
- Giving the CLI any Matrix credentials, signing key, or device key. All
  pinning/verification stays daemon-side.
- Windows support (Unix only); any change to the `unsafe`-forbid posture or MSRV
  (1.74).

## Relevant Repository Context

**Crates touched.** `mx-agent-protocol` (result event schemas + signing helpers),
`mx-agent-daemon` (emit, forward, wait, retrieve, verify), and `mx-agent-cli`
(strict digest check is already present; only behaviour-via-populated-`sha256`
changes, plus optional retrieval flags).

**The result/stream flow today.**

1. A remote dispatch resolves the target agent and subscribes for results:
   - exec: `exec_ipc.rs` `start_exec_matrix` resolves the room and `target_agent`,
     signs the request, then `subscribers.subscribe(ExecSubscriptionKey::Invocation(
     invocation_id))` and `room.send_raw(EXEC_REQUEST, …)` (`exec_ipc.rs:420-491`).
   - call: `call.rs` `start_call_matrix_inner` resolves the room and `target_agent`,
     signs the request, sends it, then `wait_for_call_response(client, request_id,
     60s)` (`call.rs:482-542`). This path uses its **own** `client.sync_once`
     loop, **not** the subscriber registry.
2. The shared daemon `/sync` loop routes inbound events. Result/stream categories
   land in `handle_routed_events` and are handed to `publish_forwarded`
   (`sync.rs:425-448`), which calls `ExecSubscriberRegistry::publish` keyed by id
   (`sync.rs:461-486`, `exec_subscribers.rs:127-149`). `meta.sender` is logged but
   not enforced.
3. The waiting consumer reads `ForwardedExecEvent`s off its subscription
   (`exec_ipc.rs:505-529`) and renders them (CLI strict/best-effort:
   `mx-agent-cli/src/stream.rs`).

**Where the executing agent's Matrix identity is known.** The dispatcher always
knows `target_agent` (the agent it dispatched to) and the room, and
`AgentState.matrix_user_id` is the agent's Matrix user id
(`schema.rs:518-524`). The daemon already resolves agent state in-room:
`agent::read_agent_state(room, agent_id)` (`agent.rs:182`) and
`read_all_agent_states(room)` (`agent.rs:294`, already used at
`exec_ipc.rs:447-453` and `call.rs:509-515`). So the **expected sender** =
`read_agent_state(room, target_agent)?.matrix_user_id`. For loopback (no `--room`)
the target is the local agent, whose `matrix_user_id` equals the daemon's own
Matrix user — so the sender-pin is `sender == self` and holds.

For artifacts, the executing agent of an invocation is recorded as
`InvocationState.target` (`schema.rs:807-829`), resolvable from room state at
retrieval time and then mapped to `matrix_user_id` the same way.

**The Matrix `sender` is reachable independent of (attacker-controlled)
`content`.** Routed events carry it on `IncomingEvent.sender` /`EventMeta.sender`
(`event_router.rs:64`, `:85`); timeline scans can read it via
`raw.get_field::<String>("sender")` (the same mechanism already used for `"type"`
and `"content"` in `artifact.rs:488-491` and `context.rs:507-510`).

**Existing patterns to mirror (model (b) signing).**

- **Detached Ed25519 over canonical JSON.** `mx-agent-protocol::signing`
  (`signing.rs`): `sign` / `sign_into` / `verify` / `verify_signature` /
  `signing_bytes` (excludes the top-level `signature` field), `ALG_ED25519`.
  `ExecRequest` / `CallRequest` carry a `Signature` in content; handlers verify
  against a resolved `VerifyingKey`.
- **The `ApprovalDecision` precedent (#264).** `schema.rs:432-458` added
  `nonce` / `expires_at` / `signature` as **optional** (`#[serde(default,
  skip_serializing_if = "Option::is_none")]`) so legacy/hostile events still
  deserialize (and can be logged + rejected, not silently bypass parsing), while
  the verifier treats a missing nonce/signature as **not verifiable → rejected**.
  `sign_approval_decision` / `verify_approval_decision` route through
  `signing::sign_into` / `signing::verify`. This is the exact template for signed
  result events.
- **Verifying-key resolution + trust.** `call::verifying_key_from_agent_state`
  (`call.rs:400-411`) decodes an agent's published `signing_public_key`, checks
  its digest matches `signing_key_id`, and yields the `VerifyingKey`;
  `TrustStore::load(paths)` then decides whether that key id is authorized.
- **Daemon signing identity.** `load_or_create_signing_key(&paths)`
  (`crate::signing`) returns the daemon's key (`.signing_key()`,
  `.key_id() = mxagent-ed25519:<sha256-b64>`), used at `call.rs:517`,
  `exec_ipc.rs:455`.

**Transport vs. execution (architecture §1.2, lines 76-98).** The Matrix
device/E2EE identity and the homeserver-asserted `sender` are *transport*
signals; mx-agent Ed25519 signing + the local trust store + local policy are the
*execution* authority. The codebase is consistent about **never** trusting the
homeserver-asserted sender for an authorization-relevant decision: see the signed
control events `ExecStdin` / `ExecCancel` / `PtyResize`
(`schema.rs:251-256`, doc §7.5/§7.7) and `ApprovalDecision` (§12). The result
plane is the one remaining place that violates this; the heartbeat caveat at
`docs/architecture.md:905-909` already names the gap.

**Conventions.** Unix-only; `unsafe_code = forbid`; MSRV 1.74; `missing_docs`
warns (every new public item needs a doc comment); human output by default with
`--json` for automation; never log secrets — log only non-sensitive metadata
(event type, room, sender, id, reason). Forward-compatible structs keep
`#[serde(flatten)] pub extra: Extra`.

## Proposed Implementation

### Trust-model decision (recommended)

Adopt a **hybrid** that the issue's two options are not mutually exclusive about:

- **(a) Sender-pin every result/stream/artifact/share event** to the resolved
  executing/producing agent's `matrix_user_id`. This is the cheap, uniform,
  always-on deny-by-default backbone — it covers the high-volume `stream.chunk`
  path at zero crypto cost and closes the "any room member" hole for all six
  categories. Sender-pinning defends against other room members; it does **not**
  defend against a malicious homeserver that can spoof `sender`, which is why (b)
  follows.
- **(b) Additionally sign the authoritative, low-volume result events** —
  `call.response` and `exec.finished` (and, recommended, `stream.artifact`,
  `context.share`, `exec.rejected`, `exec.cancelled`) — with Ed25519 + `nonce`,
  verified against the **producing agent's published signing key + the local trust
  store**, mirroring `ApprovalDecision`. This roots the highest-stakes results
  (exit status, call result, artifact digest) in Ed25519, satisfying the security
  constraint "result acceptance must trace to Ed25519 … never to mere room
  presence."
- **`sha256` on `stream.chunk`**: populate it in both producers so chunk *integrity*
  is verifiable; chunks remain authenticated by the (a) sender-pin (not by
  per-chunk signatures), and the signed `exec.finished` carries the authoritative
  `stdout_bytes`/`stderr_bytes`/`exit_code` that bound the whole stream.

Rationale for the split: signing every `stream.chunk` is impractical (thousands
per invocation); sender-pin + `sha256` is the right tool there. Signing one
`exec.finished` / `call.response` per invocation is negligible cost for the
events whose forgery is most damaging. Pure (a) literally satisfies the issue's
acceptance criteria, but only (b) on the authoritative events honors the stated
Ed25519-tracing constraint; the recommendation lands both. See **Risks and Open
Questions** for the "how far to take (b)" decision and the mixed-fleet rollout
stance — both warrant maintainer confirmation.

### 1. Sender-pin the subscriber registry (`exec_subscribers.rs`, `sync.rs`)

Carry the expected sender on each subscription and enforce it at publish:

- `ExecSubscriberRegistry::subscribe(key, expected_sender: String)` stores
  `expected_sender` on `Subscriber` (`exec_subscribers.rs:76-79`, `:105-121`).
- `ExecSubscriberRegistry::publish(event, sender: &str)` delivers only to
  subscribers whose `expected_sender == sender`; others are skipped (counted as a
  new `ForwardStats::filtered`, not `delivered`/`pruned`) (`:127-149`).
- `publish_forwarded` passes `meta.sender` (`sync.rs:461-486`); the routing arms at
  `sync.rs:425-448` are unchanged except for threading `meta.sender` through.
- Dispatch site (`exec_ipc.rs:447-488`): before `subscribe`, resolve
  `expected_sender = read_agent_state(&room, &target_agent)?.matrix_user_id`
  (fail closed if the target agent is not registered) and pass it in.

This places the deny-by-default drop where the expected-sender knowledge lives and
gives the precise unit-test surface the acceptance criteria name
(`exec_subscribers.rs`).

### 2. Sender-pin `call.response` (`call.rs`)

- `wait_for_call_response(client, request_id, expected_sender, timeout)` gains
  `expected_sender: &str`. In the scan loop (`call.rs:560-568`), require
  `event.sender == expected_sender` **before** matching `request_id`; a mismatch
  is skipped (and logged with non-sensitive `reason = "untrusted_sender"`).
- Caller `start_call_matrix_inner` (`call.rs:482-542`) already has `room` and
  `target_agent`; resolve `expected_sender = read_agent_state(&room,
  &target_agent)?.matrix_user_id` and pass it in.

### 3. Populate per-chunk `sha256` (`stream.rs`, `exec.rs`)

- `send_chunk` (`stream.rs:609-632`): set `sha256: Some(base64(Sha256::digest(
  decoded_bytes)))` over the **decoded** bytes (`data` is the encoded form; digest
  the bytes that the CLI will reconstruct — i.e. the raw `data: &[u8]` slice passed
  in, matching what `chunk_integrity_error` recomputes after decoding).
- `emit_pty_chunk` (`exec.rs:1427-1447`): same, over the raw `data: &[u8]` before
  base64 encoding.
- Verify against the CLI check (`mx-agent-cli/src/stream.rs:368-396`): for
  `encoding == "base64"` it decodes then digests; for `utf-8` it digests
  `data.as_bytes()`. The producers must digest the **same** bytes the CLI will
  digest, so:
  - base64 chunk → digest the original raw bytes (CLI decodes base64 back to those
    bytes, then digests). ✓
  - utf-8 chunk → digest the UTF-8 `data` bytes (which equal the original raw
    bytes, since `encode_chunk` only chooses utf-8 when the bytes are valid UTF-8).
    ✓
  Add a daemon-side unit test asserting `chunk_integrity_error` returns `None` for
  a producer-built chunk and `Some(...)` for a tampered one, to lock the
  convention.

### 4. Pin artifact selection (`artifact.rs`)

- Thread the event sender through the scan: `list_stream_artifacts` reads
  `raw.get_field::<String>("sender")` alongside `content` and returns the producer
  with each artifact (e.g. `Vec<(StreamArtifact, String)>`, or a small
  `ScannedArtifact { artifact, sender }`) (`artifact.rs:475-497`).
- `select_artifact` (`artifact.rs:394-402`) gains an `expected_sender: &str` and
  matches `invocation_id` + `stream` **and** `sender == expected_sender`, so a
  same-id artifact from another member cannot shadow the legitimate one.
- `retrieve_artifact` (`artifact.rs:507-530`) resolves the expected producer:
  read the `com.mxagent.invocation.v1` state for `options.invocation_id` →
  `InvocationState.target` → `read_agent_state(room, target)?.matrix_user_id`.
  Fail closed (`WorkspaceError::ArtifactNotFound` / a new
  `ProducerUnresolved`) when the invocation state or target agent cannot be
  resolved, rather than accepting an unverified producer. Optionally accept an
  explicit override via `RetrieveArtifactOptions.expected_sender:
  Option<String>` (see CLI/API).

### 5. Pin share selection (`context.rs`)

Shares are **not** invocation-linked, so the producer must be requester-supplied:

- Thread the sender through `list_context_shares` (`context.rs:495-516`) and
  surface it on the listing result so a caller can see who produced each share.
- For `fetch_context` (by `context_id`), require the selected share's sender to
  match a caller-supplied expected producer (`FetchContextOptions.expected_sender`/
  `--from <agent>`); when multiple events carry the same `context_id`, never let a
  later/foreign sender shadow the expected one. If no expected producer is given,
  the safe default is to accept only shares whose sender resolves to a
  **registered + trusted** agent in the room and to reject ambiguous same-id
  collisions. (Confirm the share-producer default with maintainers — see Open
  Questions.)

### 6. (Model (b)) Sign the authoritative result events

For each signed result content type — start with `CallResponse` and `ExecFinished`,
then `StreamArtifact`, `ContextShare`, `ExecRejected`, `ExecCancelled`:

- **Schema** (`schema.rs`): add optional `nonce: Option<String>` and
  `signature: Option<Signature>` (and `created_at`/`expires_at: Option<String>` if
  a bounded replay window is wanted), each `#[serde(default,
  skip_serializing_if = "Option::is_none")]`, with doc comments mirroring
  `ApprovalDecision` (`schema.rs:432-458`). Forward-compatible: older events still
  deserialize; the verifier treats missing fields as not verifiable → rejected.
- **Sign on emit**: load the daemon signing key
  (`load_or_create_signing_key(paths)`) and sign via the existing
  `signing::sign_into` (which strips the top-level `signature` via `signing_bytes`)
  in `emit_call_response` (`call.rs:385-396`), in the `exec.finished` emit path,
  and in the artifact/share emitters. Bind the event to its `invocation_id` /
  `request_id` / `context_id` (already in content) so a signature cannot be
  replayed across ids.
- **Verify on consume**: at the pin points above, when the signed content type is
  involved, additionally resolve the producing agent's `VerifyingKey`
  (`verifying_key_from_agent_state`), confirm its `key_id` is trusted in the
  `TrustStore`, and `verify` the signature; reject on missing/invalid signature,
  untrusted/unresolved key (non-sensitive `reason`). For `exec.finished` /
  `call.response` this is the authoritative gate; the sender-pin from (1)/(2)
  remains as a cheap pre-filter.
- Add a `verify_*` helper per type (or one generic `verify_signed_result`) routed
  through `signing::verify`, with protocol round-trip / tamper / known-answer
  tests, following the `verify_approval_decision` discipline.

### Fail-closed summary

A result is accepted only when its Matrix sender equals the resolved
executing/producing agent's `matrix_user_id` (always) **and**, for the
authoritative signed events, it carries a valid Ed25519 signature from a
trust-store-authorized key bound to the right id. Any failure — wrong sender,
missing/invalid signature, untrusted/unresolved key, mismatched chunk `sha256` in
strict mode — drops the event; none of these can *accept* a forged result. A
legitimate executor (loopback: `sender == self`; remote: the dispatched-to agent)
still resolves end-to-end.

## Affected Files / Crates / Modules

Read:
- `crates/mx-agent-protocol/src/schema.rs` — `CallResponse` (`:386`),
  `ExecFinished` (`:117`), `ExecRejected` (`:105`), `ExecCancelled` (`:179`),
  `StreamChunk` (`:195`, `sha256` `:211`), `StreamArtifact` (`:221`),
  `ContextShare` (`:292`), `InvocationState` (`:807`), `AgentState` (`:518`),
  `Signature` (`:26`), `ApprovalDecision` (`:432`, the pattern).
- `crates/mx-agent-protocol/src/signing.rs` — `sign`/`sign_into`/`verify`/
  `verify_signature`/`signing_bytes`/`ALG_ED25519`.
- `crates/mx-agent-daemon/src/exec_subscribers.rs` — `Subscriber`, `subscribe`,
  `publish`, `ForwardStats`, `ForwardedExecEvent::key`.
- `crates/mx-agent-daemon/src/sync.rs` — `handle_routed_events` (`:388-457`),
  `publish_forwarded` (`:461-486`).
- `crates/mx-agent-daemon/src/call.rs` — `emit_call_response` (`:385`),
  `wait_for_call_response` (`:544`), `start_call_matrix_inner` (`:482`),
  `verifying_key_from_agent_state` (`:400`), `authorize_live_call` (`:726`).
- `crates/mx-agent-daemon/src/exec_ipc.rs` — `start_exec_matrix` (`:420-491`).
- `crates/mx-agent-daemon/src/exec.rs` — `emit_pty_chunk` (`:1427`), the
  `exec.finished` emit path.
- `crates/mx-agent-daemon/src/stream.rs` — `send_chunk` (`:609`),
  `encode_chunk` (`:635`).
- `crates/mx-agent-daemon/src/artifact.rs` — `select_artifact` (`:394`),
  `list_stream_artifacts` (`:475`), `retrieve_artifact` (`:507`),
  `RetrieveArtifactOptions` (`:317`).
- `crates/mx-agent-daemon/src/context.rs` — `list_context_shares` (`:495`),
  `fetch_context` (`:526`), the share emitter.
- `crates/mx-agent-daemon/src/agent.rs` — `read_agent_state` (`:182`),
  `read_all_agent_states` (`:294`).
- `crates/mx-agent-daemon/src/event_router.rs` — `EventMeta`/`IncomingEvent`
  `sender`, `is_privileged` (`:168`), `EventCategory`.
- `crates/mx-agent-cli/src/stream.rs` — `chunk_integrity_error` (`:368`),
  `EXIT_STREAM_INTEGRITY` (`:53`).
- `crates/mx-agent-daemon/src/signing.rs` — `load_or_create_signing_key`.
- `crates/mx-agent-daemon/src/trust.rs` — `TrustStore`.

Modify (likely):
- `exec_subscribers.rs` — `expected_sender` on subscribe/publish; `ForwardStats`.
- `sync.rs` — thread `meta.sender` into `publish_forwarded`/`publish`.
- `exec_ipc.rs` — resolve expected sender before `subscribe`.
- `call.rs` — `expected_sender` on `wait_for_call_response`; sign in
  `emit_call_response` (model (b)).
- `stream.rs`, `exec.rs` — populate `sha256`; sign `exec.finished` (model (b)).
- `artifact.rs`, `context.rs` — sender-pin selection; resolve/accept expected
  producer; (model (b)) verify signed artifact/share.
- `schema.rs` — optional `nonce`/`signature` on signed result types (model (b)).
- `signing.rs` (protocol) and/or per-type helpers — `verify_signed_result`.
- `crates/mx-agent-daemon/src/lib.rs` — re-export any new public helpers.

## CLI / API Changes

- **CLI:** primarily none. `mx-agent call` / `exec` / artifact + share retrieval
  keep their existing flags and human / `--json` output. Optional additions:
  - artifact/share `--json` listings gain a non-secret `producer` (sender) field.
  - `share fetch` (and optionally `invocation`/artifact retrieve) may gain an
    optional `--from <agent>` to pin the expected producer explicitly. Document in
    help text only if added.
- **IPC (daemon-internal, CLI↔daemon):**
  - `RetrieveArtifactOptions` may gain `expected_sender: Option<String>`
    (additive; defaults to invocation-state resolution).
  - `FetchContextOptions` / the shares-listing options may gain
    `expected_sender: Option<String>` and the listing result a `producer` field
    (additive; existing JSON clients ignore unknown fields).
  - `ExecSubscriberRegistry::subscribe`/`publish` signatures change
    (`expected_sender`/`sender`) — purely intra-daemon, no IPC wire change.
- **No new CLI ownership of Matrix state.** All resolution/verification stays in
  the daemon.

## Data Model / Protocol Changes

- `com.mxagent.stream.chunk.v1`: **no schema change** — `sha256` already exists
  (`schema.rs:211`); producers begin populating it. Update the doc example
  (`docs/architecture.md:567`) to note it is now populated by mx-agent producers.
- (Model (b)) The authoritative result contents gain **optional, additive**
  fields, `#[serde(default, skip_serializing_if = "Option::is_none")]`:
  - `com.mxagent.call.response.v1` (`CallResponse`): `nonce`, `signature`
    (+ `created_at`/`expires_at` if bounded replay is adopted).
  - `com.mxagent.exec.finished.v1` (`ExecFinished`): `nonce`, `signature`.
  - Recommended next: `com.mxagent.stream.artifact.v1`,
    `com.mxagent.context.share.v1`, `com.mxagent.exec.rejected.v1`,
    `com.mxagent.exec.cancelled.v1`.
  - Older events still deserialize; the verifier treats missing nonce/signature
    as not verifiable → rejected (matching `ApprovalDecision`). Signed bytes
    exclude the top-level `signature` (`signing::signing_bytes`) and include the
    event's binding id (`invocation_id`/`request_id`/`context_id`).
- No new persistence beyond reusing the existing `ReplayCache` if/where a result
  nonce is replay-checked.

## Security Considerations

- **Closes the result-plane forgery path.** After this change a `call.response`,
  `exec.finished`, `exec.cancelled`, `exec.rejected`, `StreamChunk`,
  `StreamArtifact`, or `context.share` from any sender other than the resolved
  executing/producing agent is dropped; for the signed authoritative events,
  acceptance additionally requires a valid Ed25519 signature from a
  trust-store-authorized key. Restores "room membership ≠ execution permission"
  (architecture §1.2) downstream of dispatch.
- **Transport vs. execution.** Sender-pinning uses the homeserver-asserted
  `sender` — a cheap *transport-level* additive denial that defeats other room
  members but not a hostile homeserver. The Ed25519 signature + local trust store
  is the *execution-level* authority for the high-stakes events, consistent with
  §1.2's split. Neither check can *grant* acceptance; both only deny forgeries.
- **Chunk integrity vs. authenticity.** Per-chunk `sha256` proves a chunk's bytes
  were not corrupted relative to its declared digest; it does **not** by itself
  authenticate the producer (an attacker can compute a self-consistent digest).
  Authenticity of chunks comes from the sender-pin; the signed `exec.finished`
  carries the authoritative byte totals/exit status. The spec does not overstate
  `sha256` as authentication.
- **Daemon/CLI separation preserved.** The CLI never gains Matrix credentials,
  signing keys, or device keys; all resolution/verification is daemon-side. The
  daemon signs with `load_or_create_signing_key`; the coding agent never sees it.
- **No secrets in logs or diagnostics.** Rejection diagnostics log only
  non-sensitive metadata (event type, room, sender, id, `reason`) — never content,
  signatures, nonces, or digests. Use existing `tracing` + redaction discipline.
- **Fail-closed everywhere.** Wrong sender, missing/invalid signature,
  untrusted/unresolved key, unresolved producer, and a mismatched chunk digest in
  strict mode all drop the event. Loopback (`sender == self`) and a legitimate
  remote executor still resolve.
- **Mixed-fleet rollout (see Open Questions).** Result events come from a *remote*
  executor that may run an older build. Sender-pinning is always safe (the sender
  is always present). Enforcing signatures on results can break interop with a
  pre-upgrade executor — needs an explicit migration stance.
- **Unix-only; no `unsafe`; MSRV 1.74** preserved.

## Testing Plan

Daemon/protocol unit tests:

- **`exec_subscribers.rs`** — a subscription with `expected_sender = "@exec:hs"`
  receives a `StreamChunk`/`ExecFinished` published with `sender = "@exec:hs"` but
  **not** one published with `sender = "@member:hs"` (delivered vs filtered
  counts). Extend the existing `publish_only_delivers_to_matching_invocation`
  style.
- **`call.rs`** — `wait_for_call_response` returns a `call.response` from the
  expected executing sender and **ignores** a same-`request_id` response from a
  foreign sender (drive via a stubbed event scan; keep the assertion on the
  sender-pin decision, not on real `/sync`). For model (b): a valid-signature
  response from a trusted key is accepted; a missing/invalid-signature one is
  rejected.
- **`stream.rs` / `exec.rs`** — `send_chunk` and `emit_pty_chunk` produce a chunk
  whose `sha256` is `Some(...)` and for which `chunk_integrity_error` returns
  `None`; a byte-tampered copy returns `Some(...)`.
- **`mx-agent-cli/src/stream.rs`** — in strict mode, a chunk with a mismatched
  `sha256` marks the outcome an integrity failure (maps to
  `EXIT_STREAM_INTEGRITY`); best-effort mode tolerates it. (Extend existing strict
  tests.)
- **`artifact.rs`** — `select_artifact` rejects a same-`invocation_id`+`stream`
  artifact whose sender ≠ expected producer; accepts the legitimate one.
  `retrieve_artifact` fails closed when the producer cannot be resolved.
- **`context.rs`** — `fetch_context` rejects a same-`context_id` share from an
  unexpected sender; accepts the expected producer's share.
- **Protocol (`schema.rs`/`signing.rs`)** (model (b)) — sign→verify round-trips
  for each signed result type; a tampered field (`request_id`/`invocation_id`/
  `exit_code`/`result`/`nonce`) fails verification; a content with no
  `signature`/`nonce` still deserializes but verification reports the
  missing-signature error; a known-answer vector for a fixed key locks the
  canonical form.

Integration / live Tuwunel suite (extend the #202 two-agent E2E):

- A **second room member** cannot: forge a `call.response`, fake an
  `exec.finished` exit status, inject stdout/stderr chunks, or shadow a
  `stream.artifact` / `context.share` for an in-flight invocation — each forged
  event is dropped and does not reach the requester.
- The **legitimate executor's** result still resolves end-to-end: remote signed
  `call`/`exec` (streamed output, exit status, artifact retrieval) and loopback
  both succeed unchanged.

Gates: `cargo fmt --check`,
`cargo clippy --all-targets --all-features -- -D warnings`, `cargo test --all`,
`cargo build --all` stay green.

## Documentation Updates

- **`docs/architecture.md`** — document the result-plane trust model next to the
  request-signing material. The issue references "the §11 request-signing notes";
  in the current doc the request-signing material lives in **§1.2** (transport vs.
  execution, lines 76-98), **§7.3/§7.4** (stream/finished event mapping), and
  **§13.2/§13.3** (trust/policy) — place the result-plane note there and reconcile
  the §-number reference (flag if §11 is stale). State explicitly: result/stream/
  artifact/share events are sender-pinned to the resolved executing/producing
  agent's `matrix_user_id`, the authoritative events (`call.response`,
  `exec.finished`, …) are Ed25519-signed + trust-verified, `stream.chunk` carries a
  populated `sha256` integrity digest, and room membership does not let a member
  forge a result.
- Update the §7.3 stream-chunk example note (`docs/architecture.md:567`) — `sha256`
  is now populated by mx-agent producers and strict mode verifies it.
- Update the §9.1 heartbeat caveat (`docs/architecture.md:905-909`) to scope it to
  heartbeats only, noting the result/stream/artifact/share plane is now
  sender-pinned (and signed for authoritative events) — i.e. the caveat no longer
  applies beyond liveness.
- **README** "Security posture" / status table and the **wiki** protocol/security
  pages — note result events are sender-pinned (and authoritative ones signed),
  **only** to the extent the change actually ships (do not overstate alpha
  behaviour).
- Help text — only if the optional `--from`/producer flag is added.

## Risks and Open Questions

- **How far to take model (b).** The recommendation signs `call.response` +
  `exec.finished` (and ideally `stream.artifact`/`context.share`/`exec.rejected`/
  `exec.cancelled`). Pure (a) sender-pinning + `sha256` literally satisfies the
  acceptance criteria; signing the authoritative events is what satisfies the
  "trace to Ed25519" constraint. Confirm the target set with maintainers and
  whether to land it all in one PR or land (a)+`sha256` first with (b) as a tracked
  fast-follow.
- **Mixed-fleet / backward compatibility.** Unlike self-issued approval decisions,
  result events arrive from a *remote* executor. Enforcing signatures on results
  would reject results from a pre-upgrade executor. Options: (i) sender-pin always,
  enforce signatures only when present (log-and-allow for one release, then
  hard-cutover) — weaker but interop-safe; (ii) hard-cutover now (alpha, p1
  security) and document that both ends must upgrade. **Recommendation:** make
  sender-pinning unconditional immediately (no interop break), and decide the
  signature-enforcement cutover explicitly. Capture in release notes.
- **Share producer resolution.** `context.share` has no invocation linkage, so the
  "requester-known producer" must come from the caller (`--from`) or a
  default-to-registered-and-trusted-agents policy. Confirm the default behaviour
  for `share fetch`/`list` with no explicit producer (reject ambiguous same-id
  collisions either way).
- **InvocationState availability at artifact retrieval.** Resolving the expected
  producer from `InvocationState.target` assumes the invocation state event is
  present in the room at retrieval time. Confirm it always is for remote execs; if
  not, require an explicit `expected_sender`/`--from` and fail closed otherwise.
- **`send_chunk`/`emit_pty_chunk` digest domain.** The producer must digest the
  exact bytes the CLI reconstructs and digests (raw bytes for base64 chunks; the
  UTF-8 `data` bytes for utf-8 chunks). The added daemon test must pin this so the
  two sides cannot drift.
- **`subscribe`/`publish` signature churn.** Adding `expected_sender`/`sender`
  changes the registry API and every call site/test. Prefer updating them together
  in one change; the existing `exec_subscribers.rs` tests already construct events
  and can pass an expected sender.
- **Replay stakes for results.** A result event does not cause execution on
  receipt, so replay stakes are lower than for requests. Binding the signature to
  the event's id + a `nonce` is sufficient; a full `ReplayCache` admit is optional.
  Decide whether to reuse `ReplayCache` or rely on id-binding + first-valid-wins.

## Implementation Checklist

1. **Subscriber registry pin:** add `expected_sender` to `subscribe`/`Subscriber`
   and `sender` to `publish` in `exec_subscribers.rs`; add `ForwardStats.filtered`;
   thread `meta.sender` through `publish_forwarded` (`sync.rs`); resolve the
   expected sender before `subscribe` in `exec_ipc.rs:start_exec_matrix`.
2. **`call.response` pin:** add `expected_sender` to `wait_for_call_response`,
   enforce `event.sender == expected_sender` before the `request_id` match, and
   resolve it in `start_call_matrix_inner`.
3. **Populate `sha256`:** set the digest in `send_chunk` (`stream.rs`) and
   `emit_pty_chunk` (`exec.rs`); add a daemon test that the producer chunk passes
   `chunk_integrity_error` and a tampered one fails. Confirm the CLI strict path
   trips `EXIT_STREAM_INTEGRITY` on a mismatch.
4. **Artifact pin:** thread sender through `list_stream_artifacts`, add
   `expected_sender` to `select_artifact`, resolve the producer from
   `InvocationState.target` → `matrix_user_id` in `retrieve_artifact`, fail closed
   when unresolved; optional `RetrieveArtifactOptions.expected_sender` override.
5. **Share pin:** thread sender through `list_context_shares`, surface `producer`
   on listings, and pin `fetch_context` to a caller-supplied/registered-trusted
   producer (reject same-`context_id` shadowing).
6. **(Model (b)) Schema:** add optional `nonce`/`signature` (+ optional
   `created_at`/`expires_at`) to `CallResponse` and `ExecFinished` (then
   `StreamArtifact`/`ContextShare`/`ExecRejected`/`ExecCancelled`) with serde
   defaults + doc comments.
7. **(Model (b)) Sign on emit:** sign in `emit_call_response`, the `exec.finished`
   emitter, and the artifact/share emitters via `signing::sign_into` with the
   daemon key; bind to the event id.
8. **(Model (b)) Verify on consume:** add `verify_signed_result` helper(s); verify
   the signature + trust-store authorization at the pin points; fail closed with
   non-sensitive `reason`.
9. **Re-exports:** surface new public items from `lib.rs`.
10. **Docs:** update `docs/architecture.md` (result-plane trust model near
    §1.2/§7.3-§7.4/§13, reconcile the §11 reference), the §7.3 `sha256` note, the
    §9.1 heartbeat caveat scoping, README/wiki — only to what ships.
11. **Tests:** add the negative (forged sender / forged exit / injected chunk /
    shadowed artifact-share / mismatched digest) and positive (legitimate
    executor, loopback) unit tests, the protocol round-trip/tamper/KAT tests
    (model (b)), and extend the live two-agent E2E with a second-member forge
    scenario.
12. **Gates:** `cargo fmt --check`,
    `cargo clippy --all-targets --all-features -- -D warnings`, `cargo test --all`,
    `cargo build --all`.
