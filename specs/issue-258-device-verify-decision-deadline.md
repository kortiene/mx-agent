# Bound the interactive `device.verify.start` decision wait and stop it from freezing daemon IPC

> GitHub issue #258 — `type:security area:daemon area:ipc priority:p1`
> Related: #259 (in-band confirm/cancel design behind the same flow), #240 (E2EE hardening that introduced the flow).

## Problem Statement

The `device.verify.start` streaming handler (`dispatch_device_verify` in
`crates/mx-agent-daemon/src/lifecycle.rs`) drives an interactive emoji/SAS device
verification over a single held-open IPC connection. After it presents the
short-authentication string (the `emoji-ready` frame), it blocks on the
operator's confirm/cancel decision via a `wait_decision` closure that performs an
**unbounded blocking read** (`mx_agent_ipc::read_frame`) on the Unix-socket
stream.

Two facts make this a self-DoS:

1. **No deadline on phase 2.** The two `/sync`-driven phases around it (phase 1:
   wait for the SAS to become presentable; phase 3: wait for completion) are
   bounded by `VERIFY_DEADLINE` (300 s) inside `drive_until`. The phase-2
   decision wait has *no* timeout — `read_frame` calls `Read::read`/`read_exact`
   on a `UnixStream` that has no read timeout set, so it blocks forever.
2. **The IPC server is single-threaded.** `mx_agent_ipc::serve_streaming` accepts
   and serves connections **serially** in one `for stream in listener.incoming()`
   loop on one background thread. While `dispatch_device_verify` is parked in the
   blocking read, the accept loop never advances, so **every** other IPC method —
   `daemon.status`, `exec`, `call`, `approval.*`, `task.*`, heartbeat reads, etc.
   — is frozen until the operator answers or the connection drops.

So one stalled operator (or a hung/abandoned `mx-agent device verify` client)
takes the whole daemon's local control plane offline indefinitely.

This was surfaced during the #240 review (PR #256).

## Goals

- **Bound the phase-2 decision wait** with a deadline (reuse the ~300 s
  `VERIFY_DEADLINE` budget the other phases use), and **fail safe to cancel** on
  timeout. The handler already treats EOF and any read error as a cancel, so a
  timeout must funnel into the same `VerifyDecision::Cancel` path — never an
  unintended `Confirm`.
- **Stop a held-open interactive connection from starving unrelated IPC** so a
  pending verification cannot block `status`, `exec`, `approval`, `task`,
  heartbeat, or any other method. A concurrent IPC request must be served
  promptly while a `device.verify.start` is still awaiting its decision.
- Make the timeout behaviour **deterministically testable** without a 300 s
  wall-clock wait and without a live Matrix homeserver.
- Preserve the existing fail-safe semantics and the CLI/daemon contract: no key
  material crosses IPC, the decision is still multiplexed on the same connection,
  and the human/`--json` CLI output is unchanged.

## Non-Goals

- The **in-band confirm/cancel redesign** tracked in #259 (making the standalone
  `device.verify.confirm` / `device.verify.cancel` methods reachable, or moving
  the decision onto a second connection/event). This spec keeps the current
  single-connection multiplexed design and only bounds it and de-serializes it.
- Changing the SAS/emoji verification protocol, the `DeviceVerifyFrame` schema,
  or the `device.verify.manual` (out-of-band) path.
- Reworking phases 1 and 3, which are already deadline-bounded.
- Promoting device verification to an execution-authorization input. It remains
  an advisory transport signal (architecture §1.2, §13.2); this change is purely
  about availability.
- Any Windows/named-pipe support (Unix-only project).

## Relevant Repository Context

- **Crates.** `mx-agent-daemon` owns long-lived Matrix state, crypto, policy, and
  the IPC dispatch; `mx-agent-ipc` owns the Unix-socket transport
  (framing + server loop + peer-cred check). The CLI is stateless and only
  speaks framed JSON-RPC 2.0 over `$XDG_RUNTIME_DIR/mx-agent/daemon.sock`.
- **The handler.** `crates/mx-agent-daemon/src/lifecycle.rs`
  - `dispatch_device_verify` (~line 1191) parses params, loads the daemon
    session, builds a current-thread Tokio runtime, and defines two closures over
    a `RefCell<&mut UnixStream>`:
    - `frame` — serializes a `DeviceVerifyFrame` and writes it as a JSON-RPC
      result frame (the streaming responses to the CLI).
    - `wait_decision` (~line 1237) — `read_frame` on the same stream; a control
      frame whose `method == "confirm"` ⇒ `VerifyDecision::Confirm`, **anything
      else (other method, parse error, `Ok(None)` EOF, or `Err`) ⇒
      `VerifyDecision::Cancel`**.
  - It then `runtime.block_on(crate::run_device_verify(... frame, wait_decision))`.
- **The flow driver.** `crates/mx-agent-daemon/src/device_ipc.rs`
  - `const VERIFY_DEADLINE: Duration = Duration::from_secs(300);`
  - `enum VerifyDecision { Confirm, Cancel }`
  - `pub async fn run_device_verify<F, D>(...)` — phase 1 `drive_until` →
    `EmojiReady` frame → **phase 2 `wait_decision()`** → confirm/cancel → phase 3
    `drive_until` → terminal frame. `drive_until` (~line 427) enforces
    `VERIFY_DEADLINE` and a `running` `AtomicBool`; the phase-2 wait does not.
- **The server.** `crates/mx-agent-ipc/src/server.rs`
  - `serve_streaming<F>(listener, handler)` where
    `F: Fn(&Request, &mut UnixStream) -> io::Result<()>` — **serial** accept loop,
    one connection at a time, per-connection `verify_peer` (`SO_PEERCRED`) check,
    then `serve_streaming_connection` loops `read_frame`→`handler` on that
    connection until EOF.
  - `serve` is a thin wrapper over `serve_streaming` for the one-response methods.
- **Framing.** `crates/mx-agent-ipc/src/frame.rs` — `read_frame`/`write_frame`,
  4-byte BE length prefix, `MAX_FRAME_LEN` 16 MiB. `read_frame` blocks in
  `fill`/`read_exact`; it has no notion of a timeout.
- **Client reuse.** `crates/mx-agent-daemon/src/matrix.rs` caches restored Matrix
  clients in a process-global `static ACTIVE_CLIENTS: OnceLock<RwLock<HashMap<(String,String), Client>>>`;
  `restore_client` returns a clone of the cached `matrix_sdk::Client` (which is
  itself `Arc`-backed and designed for concurrent use, with its own internal
  synchronization over the SQLite crypto/state store). This materially de-risks
  serving connections concurrently (see Security Considerations).
- **Other long-lived streaming methods** that share the same starvation exposure
  today: `task.watch` (`dispatch_task_watch`), `workspace.watch`, and
  `exec.pty` (`dispatch_exec_pty`). A general server-level fix benefits all of
  them; the deadline fix is specific to `device.verify.start`.
- **CLI side.** `crates/mx-agent-cli/src/cli.rs` (~line 1177) sends
  `device.verify.start`, renders frames, prompts the operator, and on the
  `emoji-ready` frame writes a control request whose `method` is `"confirm"` or
  `"cancel"` back on the same connection (~line 1262).
- **Conventions.** No `unsafe` (forbidden workspace-wide); MSRV 1.74; document
  new public items (`missing_docs` = warn, `-D warnings` in CI); structured
  `tracing` to stderr; never log secrets; human-readable by default with `--json`.

## Proposed Implementation

Two complementary changes. Change A is the security-critical fail-safe required
by the issue; Change B is the structural fix the "does not block a concurrent IPC
request" acceptance test depends on. Implement both.

### Change A — Bound the phase-2 decision wait (fail safe to cancel)

The mechanism that composes cleanly with the existing `wait_decision` design is a
**socket read timeout**: a `UnixStream` with `set_read_timeout(Some(d))` makes a
blocking `read` that receives no data return an `Err` (`WouldBlock`/`TimedOut`)
after `d`. The current `wait_decision` already maps any read `Err` to
`VerifyDecision::Cancel`, so a timeout naturally fails safe.

1. **Factor the decision wait into a deadline-aware, unit-testable helper** in
   `device_ipc.rs` (next to `VERIFY_DEADLINE` and `VerifyDecision`), e.g.:

   ```rust
   /// Read the operator's confirm/cancel control frame from `stream`, waiting at
   /// most `timeout`. A `confirm` control frame ⇒ `Confirm`; a `cancel`, any other
   /// method, a malformed frame, EOF, a read error, **or the timeout elapsing** ⇒
   /// `Cancel`. Fails safe: the only path to `Confirm` is an explicit, well-formed
   /// `confirm` frame received before the deadline.
   pub fn read_verify_decision(
       stream: &mut std::os::unix::net::UnixStream,
       timeout: Duration,
   ) -> VerifyDecision
   ```

   Implementation: save the stream's prior read timeout, `set_read_timeout(Some(timeout))`,
   `mx_agent_ipc::read_frame`, classify the result exactly as today, then restore
   the prior timeout (best-effort) before returning. Restoring matters because the
   same stream is reused for the phase-3 result frame and connection teardown.

2. **Use the helper from `dispatch_device_verify`.** Replace the inline
   `wait_decision` closure body with a call to `read_verify_decision(&mut **guard,
   VERIFY_DEADLINE)` (re-export or reference the constant). Keep the closure shape
   (`FnMut() -> VerifyDecision`) so `run_device_verify`'s signature is unchanged.

3. **Keep the fail-safe classification centralized.** Confirm there is exactly one
   place that can yield `Confirm` (an explicit `confirm` frame), and that timeout,
   EOF, parse failure, and unknown method all yield `Cancel`. Add a short comment
   re-stating the security property.

Notes / edge cases:
- A partial/torn frame (length prefix arrives, body stalls) is covered:
  `read_frame` returns `Err(UnexpectedEof)`/timeout ⇒ `Cancel`.
- Fresh 300 s budget for phase 2 (rather than a remaining-budget split) is
  acceptable and matches the issue's "same ~300 s budget as the other phases".
- After a phase-2 timeout the handler should emit a `Cancelled` frame (it already
  does on `VerifyDecision::Cancel`) and call `verification::cancel_sas` /
  `forget_sas` so the SAS object is not leaked.

### Change B — De-serialize long-held connections so one verify can't starve IPC

Make `serve_streaming` handle each accepted connection **concurrently** instead of
serially, so a connection parked in a 300 s verify decision wait cannot block the
accept loop or other connections.

Recommended approach — **thread-per-connection** in `mx-agent-ipc/src/server.rs`:

1. Tighten the handler bound to `F: Fn(&Request, &mut UnixStream) -> io::Result<()> + Send + Sync + 'static`
   and wrap it in an `Arc<F>`. The daemon's handler closure (lifecycle.rs ~246)
   already captures only `Send + Sync + 'static`-friendly state (`String`, `u32`,
   `SharedHealth`/`Arc`, the clonable `ExecSubscriberRegistry`), so this is a
   compatible tightening.
2. In the accept loop, after a successful `verify_peer`, `std::thread::spawn` a
   worker that runs `serve_streaming_connection(&mut stream, &handler_clone)` and
   logs (`tracing::debug!`) on error, mirroring today's logging. The accept loop
   immediately returns to `listener.incoming()`.
3. Keep `verify_peer` (the `SO_PEERCRED` check) **on the accept thread, before
   spawning**, so the security gate is unchanged and a rejected peer never spawns
   a worker.
4. `serve` (the one-response wrapper) is unaffected beyond inheriting the new
   bound.

This is intentionally minimal and uniform: it fixes the starvation for
`device.verify.start`, `task.watch`, `workspace.watch`, and `exec.pty` alike,
rather than special-casing one method. Spawned worker threads are detached and
exit when their connection closes.

Alternative considered (and rejected as the primary fix): keep the serial accept
loop but move only `device.verify.start` onto its own thread inside
`dispatch_streaming`. This special-cases one method, still serializes the *other*
long-lived streamers, and complicates lifetime/ownership of the `&mut UnixStream`
handed to the dispatcher. Thread-per-connection at the server boundary is simpler
and more general. (A bounded worker pool / async accept loop is a heavier
refactor not justified for an alpha daemon with a single local user.)

### Sequencing

Change A alone fixes the unbounded freeze (worst case becomes a bounded 300 s).
Change B removes the blocking of *unrelated* IPC entirely. The acceptance test's
second clause ("does not block a concurrent IPC request") is satisfied by B; A
guarantees the verify itself terminates. Land them together.

## Affected Files / Crates / Modules

| File | Change |
|---|---|
| `crates/mx-agent-daemon/src/device_ipc.rs` | Add `read_verify_decision(stream, timeout) -> VerifyDecision` (deadline-aware, fail-safe); document it; unit tests via `UnixStream::pair()`. |
| `crates/mx-agent-daemon/src/lifecycle.rs` | `dispatch_device_verify`: replace the inline unbounded `wait_decision` body with a call to the new helper using `VERIFY_DEADLINE`. |
| `crates/mx-agent-ipc/src/server.rs` | `serve_streaming`: tighten handler bound to `Send + Sync + 'static`, wrap in `Arc`, spawn a thread per accepted connection (after `verify_peer`); concurrency unit test. |
| `crates/mx-agent-daemon/src/lib.rs` | Re-export the new helper / `VERIFY_DEADLINE` if needed for the dispatch site (only if not already reachable). |
| `crates/mx-agent-ipc/tests/rpc_over_socket.rs` (or a new test) | Integration test: a slow/blocking handler on one connection does not delay a `ping` on a second connection. |
| `docs/architecture.md` | §10.1/§10.3 note that streaming IPC connections are served concurrently and that the interactive verify decision is deadline-bounded and fails safe to cancel. |
| Files to read for context (not necessarily modify): `crates/mx-agent-ipc/src/frame.rs`, `crates/mx-agent-cli/src/cli.rs` (verify command), `crates/mx-agent-daemon/src/matrix.rs` (client reuse). |

## CLI / API Changes

**None to the external surface.** `mx-agent device verify` behaves the same from
the operator's perspective. The only observable difference: if the operator never
answers, the daemon now cancels the verification after ~300 s and emits the
existing `Cancelled` frame (the CLI already renders cancellation), instead of
hanging forever and blocking other commands.

Internal Rust API additions: a new public, documented helper
(`read_verify_decision`) in `mx-agent-daemon`, and a tightened generic bound on
`mx_agent_ipc::serve_streaming` (`Send + Sync + 'static`). These are
crate-internal/transport-level and carry no protocol/wire change.

## Data Model / Protocol Changes

**None.** No new event types, no `DeviceVerifyFrame` variant, no JSON-RPC method
or params change, no persistence/policy/serialization change. The `confirm`/`cancel`
control frame contract on the verify connection is unchanged. The Matrix
event/state schema is untouched.

## Security Considerations

- **Availability (the fix itself).** Removing the unbounded blocking read and the
  serial-accept starvation closes a self-DoS where one stalled interactive
  verification freezes the entire local control plane. This is the P1 driver.
- **Fail-safe direction preserved.** The timeout must resolve to
  `VerifyDecision::Cancel`. There must remain exactly one path to `Confirm`: a
  well-formed `confirm` control frame received before the deadline. Cover with an
  explicit test that a timeout never confirms.
- **No secrets cross IPC.** Unchanged: only `DeviceVerifyFrame`s (flow id, emoji
  symbols/descriptions, decimals) and a `confirm`/`cancel` control frame traverse
  the socket. No key material is read, logged, or forwarded. New `tracing` lines
  (e.g. a `debug!` on decision timeout) must log only non-sensitive metadata
  (flow id, reason).
- **Peer-credential gate unchanged.** `verify_peer` (`SO_PEERCRED`) stays on the
  accept thread *before* a worker is spawned, so concurrency does not weaken the
  UID check; the socket remains `0600` in a user-owned runtime dir.
- **Concurrency safety of thread-per-connection.** Restored clients are shared
  clones of cached `matrix_sdk::Client`s (`ACTIVE_CLIENTS` in `matrix.rs`);
  `matrix_sdk::Client` is `Clone`/`Arc`-backed and internally synchronizes access
  to its crypto/state store, so concurrent handlers are expected to be safe.
  Validate during implementation that running an `exec`/`status` concurrently with
  an in-flight verification does not corrupt or deadlock the SQLite crypto store;
  if a specific operation proves non-reentrant, serialize only that critical
  section behind an existing mutex rather than reverting to a serial accept loop.
- **Execution authority unchanged.** Device verification remains advisory
  transport (architecture §1.2/§13.2). This change touches only the IPC
  availability path; signing + local trust + policy remain the sole execution
  gate.
- **Unix-only.** Uses `std::os::unix::net::UnixStream::set_read_timeout` and
  `std::thread`; no Windows assumptions introduced. No `unsafe`.

## Testing Plan

Unit (no homeserver, fast):
- **`read_verify_decision` timeout ⇒ cancel** (`device_ipc.rs`): create a
  `UnixStream::pair()`, write nothing on the peer, call the helper with a short
  timeout (e.g. 150–250 ms), assert it returns `VerifyDecision::Cancel` and that
  elapsed ≥ the timeout (bounded). Confirms fail-safe-on-timeout without a 300 s
  wait.
- **`read_verify_decision` confirm frame ⇒ confirm**: peer writes a framed
  JSON-RPC request with `method == "confirm"` before the deadline; assert
  `Confirm`.
- **`read_verify_decision` other inputs ⇒ cancel**: a `cancel` method, an unknown
  method, a malformed frame, and a clean EOF each yield `Cancel`.
- **Read timeout is restored** after the helper returns (assert the stream's
  `read_timeout()` matches its prior value), so phase-3 framing/teardown is
  unaffected.

IPC server concurrency (`mx-agent-ipc`):
- **A blocking connection does not starve a second connection**: start
  `serve_streaming` on a temp socket with a test handler where method `"block"`
  parks (e.g. reads a never-arriving frame / sleeps on a channel) and `"ping"`
  responds immediately. Open connection A and send `block`; then open connection B
  and send `ping`; assert B's response arrives promptly (well under any
  block timeout) while A is still parked. This directly encodes "does not block a
  concurrent IPC request". Tear down by closing A.
- Re-confirm `verify_peer` still rejects a mismatched UID before any worker would
  spawn (existing peercred test coverage; extend if needed).

Daemon-level (optional, behind the live/`#[ignore]` suite if a homeserver is
required): a `device.verify.start` whose operator never answers ends in a
`Cancelled` frame after the (test-shortened) deadline, while a concurrent
`daemon.status` over a second connection returns promptly.

Regression: `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D
warnings`, `cargo test --all` all green; no new `missing_docs` warnings for the
added public helper.

## Documentation Updates

- `docs/architecture.md` §10.1/§10.3: note that (a) streaming IPC connections are
  now served concurrently (one worker per connection) so a long-lived
  `task.watch` / `exec.pty` / `device.verify.start` cannot starve other methods,
  and (b) the interactive verify decision wait is deadline-bounded (~300 s) and
  fails safe to cancel. Keep the existing "decision multiplexed on the same
  single connection" description accurate.
- No README status-table change is strictly required (device verification is
  already listed as implemented); optionally add a one-line note that interactive
  verification is bounded/non-blocking. Do **not** imply any new alpha capability.
- Update the `device.verify.start` row context in any IPC method reference if it
  states or implies an unbounded wait.

## Risks and Open Questions

- **Concurrent crypto-store access.** Thread-per-connection lets a verification
  `/sync` loop run alongside other Matrix-touching handlers against the shared
  cached client + SQLite store. Expected safe (matrix-sdk synchronizes
  internally), but must be validated; fallback is to serialize only the proven
  non-reentrant section, not the whole accept loop. **Decision needed if a
  conflict is found.**
- **Scope of Change B.** Is full thread-per-connection acceptable for the alpha
  (simplest, fixes all streamers), or should only `device.verify.start` be moved
  off the accept thread? Recommendation: thread-per-connection — uniform and the
  shared-client model already supports it. Confirm with maintainers if they want
  to keep the single-threaded IPC invariant for now (in which case ship Change A
  plus a narrower carve-out and accept that a pending verify still delays others
  for up to the deadline).
- **Test-time deadline.** The 300 s constant is too long for an end-to-end daemon
  test. The unit test path (testing `read_verify_decision` with an injected short
  timeout) avoids needing to make `VERIFY_DEADLINE` env-configurable. Only
  introduce an env override (e.g. `MX_AGENT_VERIFY_DECISION_TIMEOUT_MS`) if a
  full-daemon timeout test is deemed necessary — and document it if added.
- **Relationship to #259.** The in-band confirm/cancel redesign may later move the
  decision off this connection entirely; the helper and the server-concurrency fix
  remain valid regardless and should not conflict.

## Implementation Checklist

1. Read `device_ipc.rs` (`VERIFY_DEADLINE`, `VerifyDecision`, `run_device_verify`,
   `drive_until`), `lifecycle.rs` (`dispatch_device_verify`, the IPC server spawn
   ~line 245), `mx-agent-ipc/src/server.rs`, and `frame.rs`.
2. **Change A:** add `pub fn read_verify_decision(stream: &mut UnixStream, timeout:
   Duration) -> VerifyDecision` in `device_ipc.rs` — save prior read timeout, set
   `Some(timeout)`, `read_frame`, classify (only an explicit `confirm` ⇒ `Confirm`;
   everything else incl. timeout/EOF/parse-error ⇒ `Cancel`), restore prior
   timeout. Document it (fail-safe property).
3. Update `dispatch_device_verify` to call the helper with `VERIFY_DEADLINE`
   (re-export the constant if needed); keep the `FnMut() -> VerifyDecision` closure
   shape so `run_device_verify` is unchanged. On cancel/timeout the existing path
   already emits `Cancelled` and calls `cancel_sas`/`forget_sas` — verify it does.
4. Add unit tests for the helper (timeout⇒cancel + bounded, confirm⇒confirm,
   cancel/unknown/malformed/EOF⇒cancel, timeout restored) using `UnixStream::pair()`.
5. **Change B:** in `serve_streaming`, tighten the bound to `Fn(...) + Send + Sync
   + 'static`, wrap the handler in `Arc`, and after `verify_peer` succeeds spawn a
   detached thread running `serve_streaming_connection` (clone the `Arc`); keep the
   error `tracing::debug!`. Leave `verify_peer` on the accept thread.
6. Confirm the daemon's IPC handler closure in `lifecycle.rs` satisfies the new
   bound (capture only `Send + Sync + 'static` state); adjust captures/clones if
   the compiler objects.
7. Add an `mx-agent-ipc` integration test: a blocking handler on connection A does
   not delay a `ping` on connection B; re-confirm peercred rejection still precedes
   any worker spawn.
8. Update `docs/architecture.md` §10.1/§10.3 (concurrent streaming connections;
   deadline-bounded fail-safe verify decision).
9. Run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D
   warnings`, `cargo test --all`; fix any `missing_docs`/lint fallout.
10. (If maintainers require a full-daemon timeout test) add and document
    `MX_AGENT_VERIFY_DECISION_TIMEOUT_MS`; otherwise rely on the helper unit tests.
