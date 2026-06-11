# Live exec `truncated` flag + PTY-stream output caps (issue #268)

## Problem Statement

Two output-cap defects exist on the live (Matrix) and loopback streaming exec
paths in `mx-agent-daemon`:

1. **The live exec `truncated` flag is hardcoded `false`.** Both the non-PTY and
   PTY live exec paths emit `com.mxagent.exec.finished.v1` with
   `truncated: false` regardless of whether output was actually capped. For the
   non-PTY path the real value *is* computed — `emit_output_events` builds an
   `OutputCaps { max_output_bytes: allowance.max_output_bytes, .. }`
   (`exec.rs:952-955`) and `capture_child_output` returns a
   `CaptureSummary { truncated }` — but the summary is discarded at `exec.rs:974`
   (`let _ = capture.await;`) and `truncated: false` is hardcoded at
   `exec.rs:708`. The PTY live path hardcodes the same at `exec.rs:1190`. A remote
   caller whose output was capped to `max_output_bytes` is told `truncated:
   false` and cannot distinguish partial output from complete output.

2. **The PTY stream paths enforce no output cap at all.** The live PTY chunker
   forwards every byte of merged terminal output with no `max_output_bytes`
   reference (`exec.rs:1305-1314`, emitting via `emit_pty_chunk` at
   `exec.rs:1384`), and the loopback PTY pump streams raw 8 KiB master reads
   uncapped (`pty_ipc.rs:573-590`, driven by `run_pty_loopback` at
   `pty_ipc.rs:182`). A runaway interactive program (`yes`, a verbose build) can
   therefore flood the encrypted Matrix timeline / homeserver rate limits (live)
   or the local IPC socket (loopback) unbounded — exactly the resource-exhaustion
   surface `max_output_bytes` exists to prevent. The non-PTY path is already
   protected by the `CaptureLimiter` byte budget in `stream.rs`.

The correct, structurally-analogous reference is the loopback non-PTY path,
which threads `summary.truncated` from `capture_child_output` straight into its
`ExecFinished` (`exec_ipc.rs:652-664`).

## Goals

- The non-PTY **live** exec path reports the real `truncated` value in
  `exec.finished` (true when output exceeded `allowance.max_output_bytes`).
- The **live PTY** chunker honors `allowance.max_output_bytes`: it stops
  forwarding `stream:"pty"` chunks once the per-invocation byte budget is
  exhausted, and reports `truncated: true` in the PTY `exec.finished`.
- The **loopback PTY** pump honors a byte cap: it stops forwarding `output`
  frames once the budget is exhausted and reports `truncated: true` to the CLI.
- The **remote PTY** CLI bridge surfaces the target's `exec.finished.truncated`
  to the local CLI over the IPC `PtyServerFrame::Finished`.
- Truncation always still terminates the stream cleanly (the EOF chunk / the
  terminal `Finished` frame is still delivered), and the capped child process is
  still allowed to run to completion (or timeout/cancel) — capping drops
  *forwarded output*, it never deadlocks the reader or kills the child.
- New behavior is covered by tests for the live non-PTY, live PTY, and loopback
  PTY paths.

## Non-Goals

- Adding a per-chunk `sha256` digest, strict-mode integrity, or artifact-mode
  switchover to the PTY paths (PTY remains a live merged stream; large-output
  artifact offload stays a non-PTY feature).
- Adding an event-rate limit (`max_events_per_second`) to the exec paths. The
  `OutputCaps` type and `CaptureLimiter` already support it, but no policy field
  feeds it for exec today (the non-PTY live path passes
  `max_events_per_second: None`). PTY parity stays byte-cap-only; wiring a policy
  rate-limit field is out of scope and noted as follow-up.
- Capping or reporting `truncated` on the **cancelled** paths. `exec.cancelled`
  has no `truncated` field; only `exec.finished` carries it. The cancelled
  branches (`exec.rs:650-680`, `exec.rs:1163-1179`) are unchanged except that
  `emit_output_events`' now-returned summary is explicitly ignored there.
- Changing `stdout_bytes` / `stderr_bytes` semantics (they continue to report
  total bytes *produced*, not bytes *forwarded*).
- Wiring a CLI flag to set the PTY cap; the loopback cap is resolved internally
  (see Open Questions for the optional `ExecPtyParams` seam).

## Relevant Repository Context

- **Crate:** `mx-agent-daemon` owns all live/loopback exec execution; this change
  is contained to it plus a one-field additive change to the daemon-local
  `PtyServerFrame` IPC type. No change to `mx-agent-protocol`,
  `mx-agent-policy`, `mx-agent-ipc`, `mx-agent-sandbox`, or the CLI is required.
- **Streaming + caps (`src/stream.rs`):** `OutputCaps { max_output_bytes,
  max_events_per_second }` (`stream.rs:82-90`), the per-invocation
  `CaptureLimiter` (`stream.rs:209-307`) with a private
  `reserve(len) -> usize` that atomically grants bytes and flags `truncated`, and
  `CaptureSummary { truncated, output_bytes }` (`stream.rs:310-316`).
  `capture_child_output` returns a `CaptureSummary` (`stream.rs:331-367`). The
  EOF marker always bypasses the cap so the stream is always terminated.
- **Non-PTY live exec (`src/exec.rs`):** `handle_live_exec_request` spawns
  `run_controlled_exec`, then on the Finished branch calls `emit_output_events`
  (`exec.rs:690-698`, currently `-> ()`) and builds `ExecFinished` with
  `truncated: false` (`exec.rs:701-711`). `emit_output_events` (`exec.rs:917-975`)
  has an artifact-mode early return (`exec.rs:927-946`) and a streaming branch
  that spawns `capture_child_output` with `allowance.max_output_bytes` caps but
  drops the summary at `exec.rs:974`.
- **PTY live exec (`src/exec.rs`):** `run_pty_exec_task` (`exec.rs:1139-1207`)
  drives `run_controlled_pty_exec` (`exec.rs:1216-1347`) and builds the PTY
  `ExecFinished` with `truncated: false` (`exec.rs:1181-1193`). The chunker
  (`exec.rs:1305-1314`) sums `total` and forwards every chunk via `emit_pty_chunk`
  (`exec.rs:1384-1404`). `PtyExecOutcome` (`exec.rs:1123-1130`) carries
  `output_bytes` but no `truncated`.
- **Loopback + remote PTY (`src/pty_ipc.rs`):** `PtyServerFrame::Finished {
  exit_code, signal }` (`pty_ipc.rs:111-117`). `run_pty_loopback`
  (`pty_ipc.rs:182-237`) spawns `pump_master_to_client` (`pty_ipc.rs:573-591`,
  uncapped, `-> ()` joined and discarded at `pty_ipc.rs:220`) and emits the
  terminal `Finished` frame at `pty_ipc.rs:226-230`. `run_pty_remote` /
  `drain_remote_pty` (`pty_ipc.rs:430-504`) render the forwarded
  `ForwardedExecEvent::ExecFinished` into `PtyServerFrame::Finished`
  (`pty_ipc.rs:467-477`), currently dropping `finished.truncated`.
- **Reference (correct):** loopback non-PTY `run_loopback` threads
  `summary.truncated` into `ExecFinished` (`exec_ipc.rs:633-666`).
- **Allowance (`mx-agent-policy::engine::Allowance`):** carries
  `max_output_bytes: Option<u64>` (`engine.rs:60`); `None` means unlimited. There
  is **no** `max_events_per_second` field. The live PTY path already receives the
  resolved `Allowance` (`run_pty_exec_task` / `run_controlled_pty_exec` take
  `&Allowance`). The **loopback** PTY path resolves no policy/allowance today.
- **Conventions:** Unix-only; `unsafe_code = "forbid"`; MSRV 1.74; `missing_docs`
  is `-D warnings` so every new public item needs a doc comment; PTY bytes are
  never logged; preserve `tracing::warn!`-only non-sensitive logging.
- **Schema:** `ExecFinished.truncated: bool` already exists
  (`mx-agent-protocol/src/schema.rs:130-131`); no protocol change.

## Proposed Implementation

### A. Thread the real `truncated` into the non-PTY live `exec.finished`

1. Change `emit_output_events` (`exec.rs:917`) to return `CaptureSummary` (import
   already in scope via `crate::stream`). Update its doc comment.
   - Artifact-mode early-return branch (`exec.rs:927-946`): return
     `CaptureSummary { truncated: false, output_bytes: total as u64 }` — the full
     log is preserved in the artifact, so nothing was truncated (mirrors
     `exec_ipc.rs:632`).
   - Streaming branch: replace `let _ = capture.await;` (`exec.rs:974`) with
     `capture.await.unwrap_or_default()` and return it.
2. At the Finished call site (`exec.rs:690-711`): capture the returned summary
   (`let summary = emit_output_events(...).await;`) and set
   `truncated: summary.truncated` in the `ExecFinished` literal (`exec.rs:708`).
3. At the Cancelled call site (`exec.rs:654-662`): explicitly discard the now
   non-`()` return (`let _ = emit_output_events(...).await;`) — the cancelled
   branch emits `exec.cancelled`, which has no `truncated` field.

### B. Cap the live PTY merged stream and report `truncated`

1. Add `truncated: bool` to `PtyExecOutcome` (`exec.rs:1123-1130`), documented.
2. In `run_controlled_pty_exec` (`exec.rs:1216`), build a per-invocation
   single-stream byte budget from the allowance before the chunker:
   ```rust
   let limiter = CaptureLimiter::new(OutputCaps {
       max_output_bytes: allowance.max_output_bytes,
       max_events_per_second: None,
   });
   ```
   Move the `limiter` clone into the chunker task. In the chunker loop
   (`exec.rs:1305-1314`), reserve budget per chunk and forward only the granted
   prefix:
   ```rust
   while let Some(bytes) = out_rx.recv().await {
       total += bytes.len() as u64;
       let allowed = limiter.reserve(bytes.len());
       if allowed > 0 {
           emit_pty_chunk(&chunk_room, &chunk_invocation, &bytes[..allowed], false, &mut seq).await;
       }
       // Once the budget is exhausted, `allowed` is 0: stop forwarding but keep
       // draining `out_rx` so the blocking reader thread never blocks on a full
       // channel (which would stall the master read and the child).
   }
   emit_pty_chunk(&chunk_room, &chunk_invocation, &[], true, &mut seq).await; // EOF always sent
   (total, limiter.truncated())
   ```
   Change the chunker's join type from `u64` to `(u64, bool)`.
3. Read both from the chunker join: `let (output_bytes, truncated) =
   chunker.await.unwrap_or((0, false));` and set `truncated` in the returned
   `PtyExecOutcome` (`exec.rs:1340-1346`). `output_bytes` stays the total
   produced (not the forwarded subset).
4. In `run_pty_exec_task` (`exec.rs:1181-1193`), set
   `truncated: outcome.truncated`.
5. **Reuse vs. reimplement:** make `CaptureLimiter::reserve` `pub` (it is
   currently a private `fn`) with a clear doc comment, so the single-stream PTY
   chunker shares the exact truncation semantics of the non-PTY capture stage.
   `reserve` is synchronous, so it is usable from both the async live chunker and
   the sync loopback pump (below). `acquire_event` (the async rate-limit) is not
   called because no event-rate cap is configured. (Alternative: a small standalone
   `ByteBudget` helper; reusing `CaptureLimiter` is preferred to keep one source
   of truth for `truncated`.)

### C. Cap the loopback PTY pump and report `truncated`

1. Add `truncated: bool` to `PtyServerFrame::Finished` (`pty_ipc.rs:111-117`)
   with `#[serde(default)]` so older/newer peers stay compatible; document the
   field. Update the three constructors that build a `Finished` frame
   (`run_pty_loopback`'s terminal frame `pty_ipc.rs:226-230`; `drain_remote_pty`'s
   finished `pty_ipc.rs:467-477` and cancelled `pty_ipc.rs:488-498` mappings).
2. Change `pump_master_to_client` (`pty_ipc.rs:573`) to take a cap and return
   whether it truncated:
   ```rust
   fn pump_master_to_client(
       mut reader: std::fs::File,
       mut out: UnixStream,
       request_id: Value,
       max_output_bytes: Option<u64>,
   ) -> bool {
       let limiter = CaptureLimiter::new(OutputCaps { max_output_bytes, max_events_per_second: None });
       let mut buf = [0u8; 8192];
       loop {
           match reader.read(&mut buf) {
               Ok(0) => break,
               Ok(n) => {
                   let allowed = limiter.reserve(n);
                   if allowed > 0 {
                       let frame = PtyServerFrame::Output {
                           data: base64::engine::general_purpose::STANDARD.encode(&buf[..allowed]),
                       };
                       if write_server_frame(&mut out, &request_id, &frame).is_err() { break; }
                   }
                   // Budget exhausted: keep reading (drain) so the child can finish,
                   // but stop forwarding frames to the client.
               }
               Err(_) => break, // EIO once the slave is gone
           }
       }
       limiter.truncated()
   }
   ```
   (`CaptureLimiter`/`OutputCaps` are in `crate::stream`; add the `use`.)
3. In `run_pty_loopback` (`pty_ipc.rs:182`), resolve the loopback cap and thread
   it + the truncated result through:
   - Resolve `let cap = params.max_output_bytes.or(Some(DEFAULT_PTY_OUTPUT_CAP_BYTES));`
     (see Open Questions for the cap-source decision; default-constant is the
     recommended baseline).
   - `let output = std::thread::spawn(move || pump_master_to_client(reader, out_stream, request_id_out, cap));`
   - Replace `let _ = output.join();` (`pty_ipc.rs:220`) with
     `let truncated = output.join().unwrap_or(false);`
   - Set `truncated` in the terminal `PtyServerFrame::Finished`
     (`pty_ipc.rs:226-230`).
4. Add a documented `pub const DEFAULT_PTY_OUTPUT_CAP_BYTES: u64` (in `pty_ipc.rs`
   or `stream.rs`) — a generous default (e.g. 64 MiB; an interactive terminal
   producing 64 MiB is already pathological). Document that loopback PTY is now
   bounded by default where it was previously unbounded.

### D. Surface remote-PTY `truncated` to the CLI

In `drain_remote_pty` (`pty_ipc.rs:467-477`), populate
`PtyServerFrame::Finished { truncated: finished.truncated, .. }` from the
forwarded `ExecFinished` (which now carries the real value from change B). The
cancelled mapping (`pty_ipc.rs:488-498`) sets `truncated: false`.

### Backpressure / correctness notes (encode in code comments)

- **Live PTY:** the reader thread uses a bounded `mpsc` (capacity 64) and
  `blocking_send`. The chunker must keep calling `out_rx.recv().await` even after
  the budget is exhausted, otherwise the channel fills, the reader thread blocks,
  the master is not drained, and the child can stall on write. So: stop emitting,
  keep draining. The child is still bounded by the exec timeout
  (`spec.timeout`).
- **Loopback PTY:** there is no timeout, so after the cap is hit the pump keeps
  draining the master to EOF and the child runs to its natural exit (or until the
  user sends Ctrl-D / Ctrl-C through stdin). Capping prevents the IPC-socket
  flood; it does not kill the process. Document this explicitly since loopback
  has no wall-clock bound.

## Affected Files / Crates / Modules

- `crates/mx-agent-daemon/src/exec.rs` — non-PTY live `truncated` (A);
  `emit_output_events` return type (A); live PTY chunker cap + `PtyExecOutcome`
  + PTY `exec.finished` (B).
- `crates/mx-agent-daemon/src/stream.rs` — make `CaptureLimiter::reserve` public
  (+ doc); optionally home `DEFAULT_PTY_OUTPUT_CAP_BYTES` here.
- `crates/mx-agent-daemon/src/pty_ipc.rs` — `PtyServerFrame::Finished.truncated`
  (C/D); `pump_master_to_client` cap + return (C); `run_pty_loopback` plumbing
  (C); `drain_remote_pty` finished mapping (D); optional `ExecPtyParams`
  cap field (Open Questions).
- `crates/mx-agent-daemon/src/exec_ipc.rs` — read-only reference (loopback
  non-PTY already correct); no change expected.
- Tests: `crates/mx-agent-daemon/tests/pty_ipc_loopback.rs` (loopback PTY cap);
  `crates/mx-agent-daemon/tests/matrix_integration.rs` (live non-PTY + live PTY
  truncation); unit tests co-located in `exec.rs` / `stream.rs` / `pty_ipc.rs`.

## CLI / API Changes

- **No `mx-agent` command-line surface change.** Human-default and `--json`
  output are unaffected; `truncated` already exists on `exec.finished` and on the
  CLI's invocation/exec result rendering.
- **Internal daemon API:** `CaptureLimiter::reserve` becomes `pub`;
  `emit_output_events` return type changes (`()` → `CaptureSummary`) — both are
  crate-internal. If the optional `ExecPtyParams.max_output_bytes` seam is taken
  (Open Questions), it is an additive `#[serde(default)] Option<u64>` field on a
  daemon-local IPC param that the CLI does not currently set.

## Data Model / Protocol Changes

- **Matrix event schema:** none. `com.mxagent.exec.finished.v1` already defines
  `truncated: bool`; this change only makes the live/PTY producers populate it
  truthfully.
- **Local IPC frame:** `PtyServerFrame::Finished` gains a `truncated: bool`
  field, `#[serde(default)]` for forward/backward compatibility within the
  same-binary CLI↔daemon contract. (Optional) `ExecPtyParams` gains an additive
  `#[serde(default)] max_output_bytes: Option<u64>`.
- **Policy:** none. The live paths consume the existing
  `Allowance.max_output_bytes`; no new policy keys.

## Security Considerations

- **Resource exhaustion / DoS (the core fix):** PTY streams currently have no
  byte budget, so a remote interactive PTY (issue #238 surface) or a local
  loopback PTY can flood the encrypted Matrix timeline / homeserver rate limits /
  IPC socket without bound. Applying `allowance.max_output_bytes` (live) and a
  default cap (loopback) closes the gap that `max_output_bytes` already closes
  for non-PTY exec.
- **No new authority:** capping never grants execution and never changes the
  signature → trust → policy → approval gate. The live PTY path already runs
  behind that gate and already receives the resolved `Allowance`; this only
  enforces a limit the allowance already expresses.
- **Observability/integrity of the result:** reporting the real `truncated`
  prevents a capped remote caller from mistaking partial output for complete
  output — an integrity-of-results property, not just cosmetics.
- **No secret logging:** PTY bytes (keystrokes/output) remain unlogged; capping
  drops bytes silently from the stream and never logs payloads. Keep
  `tracing` to non-sensitive metadata only (e.g. an optional `debug!` noting a
  truncation event by invocation id, no payload).
- **Unix-only:** unchanged; no Windows paths introduced. No `unsafe`. The
  `CaptureLimiter` reuse keeps the atomic byte accounting in one audited place.

## Testing Plan

**Unit (co-located):**

- `stream.rs`: a focused test that `CaptureLimiter::reserve` (now public) grants
  the full length under no cap, grants the remaining budget and flags `truncated`
  when the cap is crossed, and grants 0 once exhausted. (Existing
  `output_byte_cap_*` tests already cover the capture-stage behavior.)
- `exec.rs`: a unit test for the live PTY chunker logic if it can be factored to
  take an injectable `mpsc` receiver + `CaptureLimiter` without a real PTY:
  assert that bytes past the budget are not forwarded, the EOF chunk is still
  emitted, and the returned `(total, truncated)` is `(produced, true)`.
- `pty_ipc.rs`: `PtyServerFrame::Finished` round-trips with and without
  `truncated` (serde default → `false`).

**Integration / daemon:**

- `pty_ipc_loopback.rs` (gated by the existing `pty_available()` skip): a new
  test that runs a high-output command (e.g. `sh -c "yes x | head -c 100000"` or
  a tight `printf` loop) under `run_pty_loopback` with a **small** cap, asserts
  the accumulated forwarded `output` bytes are `<= cap`, and asserts the terminal
  `PtyServerFrame::Finished { truncated: true, .. }`. (Requires the cap to be
  injectable — via the optional `ExecPtyParams.max_output_bytes` field or a
  test-only entry point; see Open Questions.) Add a companion assertion that a
  small-output command reports `truncated: false`.
- `matrix_integration.rs`, non-PTY live (alongside
  `live_matrix_backed_remote_exec_round_trips_and_denies`, ~line 670): a test
  whose target agent policy sets a small `max_output_bytes`, runs a command that
  exceeds it, and asserts the forwarded `ExecFinished.truncated == true`
  (and a within-cap command asserts `false`).
- `matrix_integration.rs`, live PTY (alongside
  `live_matrix_backed_remote_pty_streams_and_resizes`, ~line 957): with a small
  per-agent `max_output_bytes`, run a high-output PTY command and assert the
  forwarded PTY `ExecFinished.truncated == true` and that forwarded `pty` chunk
  bytes stop at the budget.

All Matrix integration tests must keep the homeserver-availability / `pty_available()`
skips so headless CI still passes. Run `cargo test --all`, `cargo fmt --check`,
and `cargo clippy --all-targets --all-features -- -D warnings`.

## Documentation Updates

- `docs/architecture.md` §8.3 (Backpressure) / §7.3 (Stream Chunk): note that
  the PTY merged stream is now byte-capped like non-PTY output and that the cap
  is surfaced via `exec.finished.truncated`. §5.x / status table: the
  interactive-PTY row currently says "baseline controls only" — add that output
  is now byte-capped.
- `README.md` Project-status table: the "Interactive PTY over IPC/remote" and
  `call`/`exec` rows can note that PTY output is now byte-capped and reports
  truncation (avoid implying any cap behavior the implementation does not add —
  i.e. do not claim a rate-limit or artifact mode for PTY).
- Doc comments on every new/changed public item (`CaptureLimiter::reserve`,
  `PtyServerFrame::Finished.truncated`, `DEFAULT_PTY_OUTPUT_CAP_BYTES`, any new
  `ExecPtyParams` field) — `missing_docs` is `-D warnings`.
- No wiki source (`wiki/`) change required unless the PTY/streaming page
  enumerates caps; check `wiki/` for a streaming/security page and update if it
  asserts "PTY is uncapped".

## Risks and Open Questions

1. **Loopback cap source (decision needed).** The loopback PTY resolves no
   policy/allowance today (and the loopback **non-PTY** path is itself uncapped).
   Options:
   - **(Recommended)** A documented module constant `DEFAULT_PTY_OUTPUT_CAP_BYTES`
     (generous, e.g. 64 MiB), with an additive `#[serde(default)]
     max_output_bytes: Option<u64>` on `ExecPtyParams` so tests (and any future
     CLI flag) can override it. Simplest, testable, no policy-resolution in the
     sync loopback path.
   - Resolve the operator's execution-default `max_output_bytes` from policy in
     `run_pty_loopback`. More "consistent" with the architecture's "loopback uses
     the operator's execution-level defaults," but `max_output_bytes` is a
     *per-agent* policy field today (no execution-level default exists), so there
     is no clean operator-default to read; this would be a larger policy change.
   Recommendation: take the constant + optional-param approach; leave
   policy-resolution for loopback as a separate follow-up that should also cover
   the loopback non-PTY path for symmetry.
2. **Default-cap behavior change.** Loopback PTY becomes bounded by default where
   it was unbounded. With a generous default this should be invisible in practice,
   but it is a behavior change worth a changelog note.
3. **`stdout_bytes`/`output_bytes` semantics.** These keep reporting *produced*
   bytes, while `truncated` reflects that *forwarded* bytes were capped. This
   matches the existing non-PTY contract; confirm no consumer treats
   `stdout_bytes <= max_output_bytes` as an invariant.
4. **Live PTY draining under cap.** The chunker must keep draining `out_rx` after
   the cap to avoid stalling the reader thread / child (documented above). A
   naive `break` would deadlock the blocking reader on a full channel — call this
   out in review.
5. **Event-rate limiting deferred.** The issue mentions "optionally
   `max_events_per_second`." No exec policy field feeds it (the non-PTY live path
   passes `None`), so PTY parity is byte-cap-only. If a rate-limit is later
   wanted, add a policy field and thread it through both paths uniformly.
6. **Test environment.** PTY tests must retain the `pty_available()` skip
   (`openpt`/`ENOTTY` on some sandboxed macOS hosts) and Matrix tests their
   homeserver-availability skip, per existing conventions.

## Implementation Checklist

1. **stream.rs:** make `CaptureLimiter::reserve` `pub` with a doc comment;
   (optionally) add `pub const DEFAULT_PTY_OUTPUT_CAP_BYTES: u64`.
2. **exec.rs (non-PTY live, A):** change `emit_output_events` to return
   `CaptureSummary`; return `{ truncated: false, output_bytes: total }` from the
   artifact branch and `capture.await.unwrap_or_default()` from the streaming
   branch; set `truncated: summary.truncated` at the Finished site
   (`exec.rs:708`); `let _ = emit_output_events(...)` at the Cancelled site.
3. **exec.rs (live PTY, B):** add `truncated` to `PtyExecOutcome`; build a
   `CaptureLimiter` from `allowance.max_output_bytes`; reserve-per-chunk and stop
   forwarding (keep draining) in the chunker; return `(total, truncated)`; read
   both from the join; set `truncated` in `PtyExecOutcome` and in the PTY
   `ExecFinished` (`exec.rs:1190`).
4. **pty_ipc.rs (loopback, C):** add `#[serde(default)] truncated: bool` to
   `PtyServerFrame::Finished`; cap `pump_master_to_client` and return `truncated`;
   resolve the cap (constant + optional `ExecPtyParams` field) and thread the
   truncated result into the terminal `Finished` frame in `run_pty_loopback`.
5. **pty_ipc.rs (remote, D):** set `truncated: finished.truncated` in
   `drain_remote_pty`'s finished mapping; `false` in the cancelled mapping.
6. **Docs:** update `docs/architecture.md` §7.3/§8.3 and the PTY status rows;
   update `README.md` status table; doc-comment all new public items; sweep
   `wiki/` for any "PTY is uncapped" claim.
7. **Tests:** add the live non-PTY truncation test, the live PTY truncation test
   (both in `matrix_integration.rs`, with small policy caps and the existing
   skips), the loopback PTY cap test in `pty_ipc_loopback.rs`, and unit tests for
   `reserve`/`PtyServerFrame` round-trip.
8. **Gates:** `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`,
   `cargo test --all` all green.
