# Stream & Protocol Spec

A reference for protocol contributors and core developers. It documents the on-Matrix wire format, the stream transport semantics, and the transport-layer trade-offs. The canonical event-type constants live in `crates/mx-agent-protocol/src/events.rs`; this page mirrors them.

> All event types are **explicitly versioned** with a `.v1` suffix. Semantics never change under a fixed version — a breaking change means a new `.v2` type.

---

## Event Namespace

**Timeline events** (immutable activity / streams):

```text
com.mxagent.exec.request.v1      com.mxagent.call.request.v1
com.mxagent.exec.accepted.v1     com.mxagent.call.response.v1
com.mxagent.exec.rejected.v1     com.mxagent.stream.chunk.v1
com.mxagent.exec.finished.v1     com.mxagent.stream.artifact.v1
com.mxagent.exec.stdin.v1        com.mxagent.context.share.v1
com.mxagent.exec.cancel.v1       com.mxagent.heartbeat.v1
com.mxagent.exec.cancelled.v1    com.mxagent.approval.request.v1
com.mxagent.pty.resize.v1        com.mxagent.approval.decision.v1
```

**State events** (durable, queryable snapshots):

```text
com.mxagent.agent.v1        com.mxagent.tool.v1
com.mxagent.task.v1         com.mxagent.workspace.v1
com.mxagent.invocation.v1   com.mxagent.trust.v1
```

---

## Stream Decoupling

The single most important design rule for protocol implementers: **standard I/O is decoupled from durable task/invocation state.**

Durable state (`task.v1`, `invocation.v1`) answers *"what is the status of the work?"* It mutates rarely and is read often. Stream data (`stdout`/`stderr`/`stdin`/`pty`) is high-frequency, high-volume, and write-once. If you folded streams into state you would get **state bloat**: every line of test output would rewrite a state event, blow past homeserver event-size limits, and make the durable snapshot enormous and slow to read.

So they ride on different rails:

| Concern | Stream data | Durable state |
|---|---|---|
| Carrier | `stream.chunk.v1` timeline events (or media artifacts) | `*.v1` **state** events |
| Cardinality | thousands per invocation | a handful per invocation |
| Mutability | append-only, never rewritten | last-write-wins, versioned via `state_rev` |
| Keyed by | `(invocation_id, stream, seq)` | `(type, state_key)` |
| Lifetime | live tail; large output spills to artifacts | the canonical record |

### Chunking defaults (architecture §8.1)

```text
max_chunk_bytes     : 16 KiB
max_flush_interval  : 50 ms  (interactive) / 250 ms (batch)
max_events_per_second : internal cap (no policy key; unset / None in production)
max_output_bytes    : policy-controlled
compression         : zstd, optional, for non-interactive streams
```

A chunk is flushed when **any** condition is met: the buffer hits `max_chunk_bytes`, a newline is seen in interactive mode, the flush interval expires, or the stream reaches EOF.

### Ordering, reassembly, and strict mode (architecture §8.2)

Chunks are totally ordered within a stream by `(invocation_id, stream, seq)`. Receivers:

- de-duplicate exact repeated `(invocation_id, stream, seq)` chunks;
- buffer out-of-order chunks for a bounded window;
- mark the stream **degraded** if a gap persists past timeout;
- mark **integrity failure** if a chunk cannot be decoded (bad base64) or carries a `sha256` digest that does not match — but mx-agent producers do not populate the per-chunk `sha256` today (`sha256: null`), so a missing digest is tolerated (a passing check) in both best-effort and strict mode, and the digest-mismatch branch is unreachable until producers emit digests;
- otherwise render best-effort.

**Strict mode** turns "best-effort" into "fail loudly":

```bash
mx-agent exec --room "$ROOM" --agent developer-pi --strict-stream -- npm test
```

In strict mode, a missing chunk or one that fails validation aborts the local CLI with exit code **132** (stream integrity failure) rather than showing partial output.

### Backpressure & artifact fallback (architecture §8.3–8.4)

The daemon protects both Matrix and the local child: it applies per-invocation output caps, pauses child reads only when safe, and **switches to artifact mode** when output exceeds the timeline budget or the homeserver's rate limits. In artifact mode, bulk output is uploaded to Matrix media and referenced by `mxc://` URI + `sha256`, while the timeline carries only a summary and a tail preview (see `stream.artifact.v1` below). Truncation is always surfaced explicitly, never silent.

---

## Transport Layer: to-device vs. timeline

mx-agent has two qualitatively different transport needs, and the protocol matches each to the right Matrix mechanism.

| Need | Mechanism | Why |
|---|---|---|
| **Low-latency, ultra-secure 1:1 signaling** (a single privileged request/ack between two specific daemons) | **Olm ephemeral to-device messages** — 🔮 *future / not implemented* | A to-device transport would address a single device, stay out of room history, and use Olm 1:1 sessions (minimal residue, forward secrecy). **mx-agent does not use to-device messaging today — there is zero to-device usage in the tree.** Privileged signaling (`exec.request`, `exec.cancel`, `call.request`, and the signed stdin/resize/cancel controls) rides **signed Matrix timeline events** instead; do **not** implement a to-device handshake to interoperate. |
| **High-throughput, multi-party stream data** (continuous `stdout`/`stderr`, fan-out to observers, durable replay) | **Matrix room timeline events** (Megolm-encrypted), with **media artifacts** for bulk | Timeline events are ordered, durable, replayable after reconnect, and naturally fan out to every room member. Megolm group encryption amortizes crypto across many recipients. Large payloads escape to media so the timeline stays light. **This is the transport mx-agent uses today for every privileged event as well as stream data.** |

> **Implementation status.** E2EE (Olm/Megolm) is provided by `matrix-sdk` 0.18 behind the `e2e-encryption` feature. The daemon decrypts privileged E2EE events and fails safe on undecryptable events today, and **production E2EE hardening shipped** — device verification UX, cross-signing, and server-side key backup/recovery (#256/#260). Privileged signaling currently rides **signed Matrix timeline events**, not to-device messages (the to-device row above is a future option, not a current transport). The wire schemas below are stable regardless of whether a given deployment has E2EE enabled. "Matrix RTC"–style real-time channels are a 🔮 future option for the highest-throughput interactive PTY streams; today, interactive output uses chunked timeline events with a 50 ms flush.

### Signature envelope

Every **privileged** timeline event (`exec.request`, `exec.cancel`, `call.request`) carries an Ed25519 signature over the **canonical JSON** of its content (the `signature` field itself excluded from the signed bytes):

```json
"signature": {
  "alg": "ed25519",
  "key_id": "mxagent-ed25519:abc123",
  "sig": "base64-of-ed25519-signature-over-canonical-content"
}
```

The verifying daemon recomputes canonical JSON, checks the signature against the trusted `key_id` (see [[Security & Sandboxing|Security-and-Sandboxing]]), then validates `nonce`/`expires_at` before any routing or policy decision for request types whose schema carries those fields.

**Canonical JSON contract.** The canonical JSON encoder follows the Matrix spec exactly: object keys sorted lexicographically, no insignificant whitespace, standard JSON string escaping, arrays in insertion order. **Floating-point numbers are rejected** — the encoder returns `CanonicalJsonError::NonIntegerNumber` rather than producing bytes a strict Matrix peer would compute differently. All fields appearing in signed events must be integers, strings, booleans, nulls, arrays, or objects; a payload containing a float cannot be signed or verified and will fail at the signing step. Integer encoding is unchanged (plain decimal string, no coercion), so existing signatures remain valid.

---

## Concrete Wire Specs

These are complete, valid payloads — no truncation.

### 1. Execution request — `com.mxagent.exec.request.v1`

```json
{
  "type": "com.mxagent.exec.request.v1",
  "content": {
    "invocation_id": "inv_01HZ8QK3M9V0X2YJ4N6P7R5T8W",
    "request_id": "req_01HZ8QK3M9V0X2YJ4N6P7R5T8X",
    "target_agent": "developer-pi",
    "requesting_agent": "claude-local",
    "command": ["npm", "test"],
    "cwd": "/home/me/code/project",
    "env": {},
    "stdin": true,
    "stream": true,
    "pty": false,
    "timeout_ms": 600000,
    "task_id": "task-test-api",
    "created_at": "2026-06-02T12:00:00Z",
    "expires_at": "2026-06-02T12:05:00Z",
    "nonce": "8f3kQ2pLwR1vNc7Bz0aYxs9TgUo4eHd",
    "idempotency_key": "exec:inv_01HZ8QK3M9V0X2YJ4N6P7R5T8W",
    "signature": {
      "alg": "ed25519",
      "key_id": "mxagent-ed25519:abc123",
      "sig": "Qm9ndXNTaWduYXR1cmVCYXNlNjRFbmNvZGVkRWQyNTUxOVZhbHVlAAAAAAAA"
    }
  }
}
```

### 2. Stream chunk — `com.mxagent.stream.chunk.v1`

Text (UTF-8) chunk:

```json
{
  "type": "com.mxagent.stream.chunk.v1",
  "content": {
    "invocation_id": "inv_01HZ8QK3M9V0X2YJ4N6P7R5T8W",
    "stream": "stdout",
    "seq": 42,
    "encoding": "utf-8",
    "data": "PASS src/foo.test.ts\n",
    "eof": false,
    "compressed": false,
    "sha256": null,
    "timestamp": "2026-06-02T12:00:01.123Z"
  }
}
```

Binary chunk (non-UTF-8 bytes are base64-encoded):

```json
{
  "type": "com.mxagent.stream.chunk.v1",
  "content": {
    "invocation_id": "inv_01HZ8QK3M9V0X2YJ4N6P7R5T8W",
    "stream": "stdout",
    "seq": 43,
    "encoding": "base64",
    "data": "AAECAwQ=",
    "eof": false,
    "compressed": false,
    "sha256": null,
    "timestamp": "2026-06-02T12:00:01.187Z"
  }
}
```

Valid `stream` values: `stdin`, `stdout`, `stderr`, `pty`, `control`.

### 3. Finished / exit-code packet — `com.mxagent.exec.finished.v1`

Process exited normally with a non-zero code:

```json
{
  "type": "com.mxagent.exec.finished.v1",
  "content": {
    "invocation_id": "inv_01HZ8QK3M9V0X2YJ4N6P7R5T8W",
    "exit_code": 1,
    "signal": null,
    "duration_ms": 18231,
    "stdout_bytes": 50231,
    "stderr_bytes": 1409,
    "truncated": false,
    "artifact_mxc": null
  }
}
```

Process killed by a signal (the `signal` field is the signal *name* — `Option<String>`, e.g. `"SIGKILL"` — not an integer); the local CLI maps it to `128 + signum` per the exit-code table below:

```json
{
  "type": "com.mxagent.exec.finished.v1",
  "content": {
    "invocation_id": "inv_01HZ8QK3M9V0X2YJ4N6P7R5T8W",
    "exit_code": null,
    "signal": "SIGKILL",
    "duration_ms": 5004,
    "stdout_bytes": 1048576,
    "stderr_bytes": 0,
    "truncated": true,
    "artifact_mxc": null
  }
}
```

### 4. Large-output artifact — `com.mxagent.stream.artifact.v1`

```json
{
  "type": "com.mxagent.stream.artifact.v1",
  "content": {
    "invocation_id": "inv_01HZ8QK3M9V0X2YJ4N6P7R5T8W",
    "stream": "stdout",
    "name": "stdout.log.zst",
    "mime_type": "text/plain+zstd",
    "size_bytes": 10485760,
    "sha256": "OnvT4jYKPSnupDb8+35ExzXRF8QtHBg1Qgtrm9JdTxs=",
    "mxc_uri": "mxc://matrix.org/abcdef0123456789",
    "tail_preview": "… 4 KiB of trailing output for quick inspection …"
  }
}
```

Retrieve and verify it:

```bash
mx-agent invocation artifact --room "$ROOM" --stream stdout inv_01HZ8QK3M9V0X2YJ4N6P7R5T8W
```

The daemon downloads from media, **recomputes SHA-256 over the raw bytes** and rejects a mismatch as tamper/corruption, then decompresses zstd so you get the original output.

### Result-plane sender-pinning

`exec.finished`, `stream.chunk`, `stream.artifact`, `exec.rejected`, `exec.cancelled`, and `call.response` are **sender-pinned** to the executing/producing agent's Matrix user id (resolved from its `com.mxagent.agent.v1` room state). The daemon drops any of these events whose Matrix `sender` is not the dispatched-to agent before it reaches a waiting consumer — so a room member who learns an in-flight `invocation_id` cannot forge an exit status, inject output chunks, or shadow a legitimate artifact. `stream.chunk` defines an optional `sha256` digest field (base64 SHA-256 of the decoded bytes) for strict-mode verification (exit `132`), but mx-agent producers do not populate it today (`sha256: null`); strict mode therefore fails only on a missing/lost chunk or one that cannot be decoded, not on a digest mismatch. See [[Security & Sandboxing|Security-and-Sandboxing]] and the architecture §1.2/§7.3–§7.4 for the full trust model.

---

## Exit-Code Contract (architecture §5.3)

The local CLI exits with the remote process's exit code when possible; reserved codes carry protocol meaning:

| Code | Meaning |
|---:|---|
| 0 | Remote command succeeded |
| 1–125 | Remote command's own exit code |
| 3 | Could not reach the daemon, or the daemon rejected the local request |
| 64 | Invalid CLI usage (empty command / bad arguments) |
| 127 | Agent / tool / command not found |
| 128 | Protocol / network failure; today also covers local policy denial and remote rejection (dedicated codes for those are planned follow-up) |
| 129 | Timeout — the requester abandoned a remote exec past its deadline and sent a signed `exec.cancel` (issue #314) |
| 132 | **Stream integrity failure** (strict mode) |

A remote process killed by signal `N` is reported as `128 + N` (e.g. a Ctrl-C'd PTY command exits `130`). This table mirrors the canonical exit-code contract in `docs/architecture.md §5.3`.

---

## See also

- The state model these events feed: [[Core Concepts|Core-Concepts]]
- Signing keys, trust, and policy gates: [[Security & Sandboxing|Security-and-Sandboxing]]
