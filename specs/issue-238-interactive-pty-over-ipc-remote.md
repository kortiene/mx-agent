# Interactive PTY exec over IPC and the signed Matrix transport (issue #238)

## Problem Statement

Interactive PTY `exec` (`mx-agent exec --pty -- bash`) runs **local-only** today:
the CLI links `mx_agent_daemon::PtySession` directly and spawns the child process
**inside the stateless CLI** (`crates/mx-agent-cli/src/cli.rs::cmd_exec_pty`).
This violates the CLI/daemon split (the daemon must own process supervision) and
means PTY exec is the one `exec` mode not carried over daemon IPC or the signed
Matrix transport. The loopback `exec.start` IPC path explicitly *accepts but
ignores* `pty` (`crates/mx-agent-daemon/src/exec_ipc.rs`), and the live Matrix
exec handler (`crates/mx-agent-daemon/src/exec.rs::run_controlled_exec`) ignores
`request.pty` entirely. There is no routing or handler for
`com.mxagent.pty.resize.v1`.

## Goals

1. Carry interactive PTY exec over the daemon IPC channel (loopback first): the
   daemon allocates the PTY, streams the merged PTY byte stream to the CLI, and
   the CLI forwards local stdin and terminal-resize events to the daemon. The CLI
   no longer spawns the process itself.
2. Extend PTY exec to the signed Matrix transport for remote `--room`/`--agent`
   targets, reusing the existing exec authorization pipeline (signature → routing
   → trust → replay/expiry → policy) and the signed `exec.stdin`/`exec.cancel`
   control events. The target daemon allocates the PTY and streams
   `com.mxagent.stream.chunk.v1` events with `stream: "pty"`.
3. Propagate terminal window-resize over both transports
   (`com.mxagent.pty.resize.v1`), and keep the documented Ctrl-C / signal
   semantics (local raw mode → control bytes forwarded to the remote PTY).
4. Tests: a loopback PTY-over-IPC round-trip (default `cargo test`), resize
   propagation, and an `#[ignore]`d live two-daemon remote PTY matrix-integration
   test.

## Non-Goals

- Changing the protocol schema. `StreamKind::Pty` and `PtyResize` already exist.
- Multiplexing several interactive PTY sessions concurrently on one daemon. Like
  `task.watch`, an interactive PTY session holds the IPC connection open and the
  blocking IPC server serves it exclusively for the session's lifetime.
- Artifact-mode / large-output handling for PTY (a PTY is an interactive live
  stream, not a captured batch).
- Windows support (Unix-only, unchanged).

## Relevant Repository Context

- IPC transport (`mx-agent-ipc`): length-delimited (4-byte BE) JSON-RPC 2.0
  frames over a Unix socket. The server (`serve_streaming`) serves connections
  **sequentially**; a streaming handler receives `(&Request, &mut UnixStream)`
  and may write many response frames on the same connection (the `task.watch`
  precedent). `read_frame`/`write_frame`/`Request`/`Response` are public.
- Daemon dispatch (`crates/mx-agent-daemon/src/lifecycle.rs`):
  `dispatch_streaming` routes `task.watch`/`workspace.watch` to streaming
  handlers and everything else to the single-response `dispatch`. Streaming
  handlers build a current-thread tokio runtime and `block_on`.
- PTY (`crates/mx-agent-daemon/src/pty.rs`): `PtySession::spawn(spec, winsize)`,
  `resize`, `try_clone_reader`/`try_clone_writer` (independent master fds),
  `wait`. Safe `rustix`, no `unsafe`.
- Live Matrix exec (`crates/mx-agent-daemon/src/exec.rs`):
  `handle_live_exec_request` authorizes then spawns `run_controlled_exec` (piped,
  non-PTY); `LiveExecControl { requester_agent, stdin, cancel }` in a global table
  drives signed `exec.stdin`/`exec.cancel`. Output is emitted via
  `emit_output_events` (buffered then chunked). Requester side
  (`exec_ipc.rs::start_exec_matrix`) subscribes through `ExecSubscriberRegistry`
  and collects frames.
- Event router (`event_router.rs`) + `sync.rs::handle_routed_events`: classify →
  parse → (replay-check) → dispatch. `pty.resize` is **not** classified today.
- CLI PTY path (`cli.rs::cmd_exec_pty`, `terminal.rs`): raw-mode guard with
  signal-safe terminal restore; SIGWINCH → resize; documented Ctrl-C semantics.

## Proposed Implementation

### New IPC sub-protocol (one streaming connection, full-duplex)

A new streaming IPC method `exec.pty`. Because the blocking server can only read
the next client frame after the handler returns, the daemon-side handler does
full duplex on the **one** connection by `try_clone`-ing the `UnixStream` and
using OS threads:

- **daemon → CLI**: JSON-RPC `Response` frames (echoing the request id) carrying
  a `PtyServerFrame`: `{event:"output",data:<base64>}`,
  `{event:"finished",exit_code,signal}`, or `{event:"error",message}`.
- **CLI → daemon** (mid-stream, same connection): JSON-RPC `Request` frames with
  method `pty.stdin` (`{data:<base64>}`) or `pty.resize`
  (`{rows,cols,pixel_width,pixel_height}`).

Types live in a new daemon module `pty_ipc.rs` (`ExecPtyParams`,
`PtyServerFrame`, `PtyClientFrame`) and are re-exported from the daemon crate so
the CLI reuses them.

### Loopback PTY over IPC

`dispatch_exec_pty` (registered in `dispatch_streaming`): when `room`/`agent` are
absent, spawn `PtySession`, then:
- thread A pumps the master reader → `PtyServerFrame::Output` frames;
- the input reader applies `pty.stdin` (write to a cloned master fd) and
  `pty.resize` (`tcsetwinsize` on the master fd);
- `session.wait()`, drain output, send `PtyServerFrame::Finished`, shut down the
  connection so the input reader unblocks.

CLI `cmd_exec_pty` rewrite: connect the socket, send `exec.pty`, enter raw mode,
then read output frames → stdout (thread), forward local stdin → `pty.stdin`
frames (thread), forward SIGWINCH → `pty.resize` frames (thread); exit with the
finished frame's code (`128+signum` on signal death). The CLI no longer links
`PtySession`/`RunSpec`.

### Remote PTY over the signed Matrix transport

Target side: `handle_live_exec_request` branches on `request.pty`. A new
`run_controlled_pty_exec` allocates `PtySession`, **live-streams** the merged
master output as `com.mxagent.stream.chunk.v1` with `stream:"pty"` (monotonic
seq), writes signed-stdin bytes to the master, applies resize, and kills the
process group on cancel/timeout. `LiveExecControl` gains a `resize` channel and
records the requester's Matrix user id for resize authorization.

`com.mxagent.pty.resize.v1` is added to `classify`/`RoutedEvent`/
`handle_routed_events`; `handle_live_pty_resize` authorizes by **Matrix sender ==
requester's `matrix_user_id`** (resize is an unsigned, non-executing window hint —
it cannot run anything, and the sender is homeserver-authenticated) and forwards
the new size to the live control's resize channel. `StreamKind::Pty` chunks are
forwarded to subscribers (already wired for `StreamChunk`).

Requester side: `dispatch_exec_pty` with `room`+`agent` bridges the IPC duplex to
Matrix — send a signed `exec.request{pty:true}`, send an initial `pty.resize`,
subscribe to the invocation, forward `StreamChunk(pty)` → IPC `output`,
`exec.finished` → IPC `finished`, `exec.rejected`/`cancelled` → IPC
`error`/`finished`; and translate inbound `pty.stdin`/`pty.resize` IPC frames to
signed `exec.stdin` / `pty.resize` Matrix events. New helpers `build_signed_*`
not needed for resize (unsigned) — add `send_pty_resize`.

## Affected Files / Crates / Modules

- `crates/mx-agent-daemon/src/pty_ipc.rs` (new): IPC sub-protocol types + loopback
  + remote duplex handlers.
- `crates/mx-agent-daemon/src/pty.rs`: small helpers if needed (resize on a bare
  master fd).
- `crates/mx-agent-daemon/src/exec.rs`: `run_controlled_pty_exec`,
  `LiveExecControl` resize + requester user, `handle_live_pty_resize`,
  `send_pty_resize`, PTY branch in `handle_live_exec_request`, live pty streaming.
- `crates/mx-agent-daemon/src/event_router.rs`: classify + `RoutedEvent::PtyResize`.
- `crates/mx-agent-daemon/src/sync.rs`: dispatch `PtyResize` to the handler.
- `crates/mx-agent-daemon/src/lifecycle.rs`: register `exec.pty` in
  `dispatch_streaming`.
- `crates/mx-agent-daemon/src/lib.rs`: module + re-exports.
- `crates/mx-agent-cli/src/cli.rs`: rewrite `cmd_exec_pty` over IPC; drop direct
  `PtySession` use.
- `crates/mx-agent-daemon/tests/`: loopback round-trip + resize tests;
  `tests/matrix_integration.rs`: `#[ignore]`d two-daemon remote PTY.
- Docs: `README.md` status table, `docs/architecture.md` (§7.3/§7.6 already cover
  PTY/Ctrl-C; update status note), `CONTRIBUTING.md` integration-test note.

## CLI / API Changes

- New IPC method `exec.pty` (streaming) and mid-stream client methods
  `pty.stdin` / `pty.resize`. No change to the `mx-agent exec --pty` command
  surface (same flags, same behavior, now daemon-mediated and remote-capable).
- New public daemon types: `ExecPtyParams`, `PtyServerFrame`, `PtyClientFrame`,
  `send_pty_resize`.

## Data Model / Protocol Changes

None to the Matrix schema. Reuses existing `StreamKind::Pty`, `PtyResize`,
`PTY_RESIZE`, `exec.stdin`/`exec.cancel`. New `RoutedEvent::PtyResize` and
`EventCategory::PtyResize` (internal routing only).

## Security Considerations

- PTY remote exec passes the **same** signed/trust/replay/policy pipeline as
  non-PTY exec (`request.pty` does not bypass any gate). Stdin/cancel stay
  Ed25519-signed and requester-owned.
- `pty.resize` is unsigned in the schema; it changes only the window size of an
  already-authorized, running invocation and can execute nothing. The target
  authorizes it by **Matrix sender == invocation requester's `matrix_user_id`**
  (homeserver-authenticated identity), so room membership alone cannot resize
  another agent's session. This is documented in the handler.
- CLI stays stateless: the daemon owns the PTY/process. No Matrix tokens/keys
  reach the CLI. No secrets logged (PTY bytes are never logged; only IDs/metadata).
- Unix-only; no `unsafe` (PTY stays on `rustix`).

## Testing Plan

- Unit: `PtyServerFrame`/`PtyClientFrame`/`ExecPtyParams` serde round-trips;
  `classify(PTY_RESIZE)`; resize authorization helper (sender match / mismatch).
- Loopback integration (`mx-agent-daemon` test, no Docker): start a daemon socket,
  run `exec.pty` for a small interactive program, assert merged output round-trips,
  stdin is delivered, and a `pty.resize` reaches the child (`stty size`).
- Resize propagation unit/integration via the master-fd path.
- `#[ignore]`d matrix-integration: two daemons, signed remote `exec --pty`,
  assert PTY output + a resize round-trip; documented to run via
  `scripts/matrix_integration_test.sh`.

## Documentation Updates

- README status table row: Interactive PTY over IPC/remote → ✅ Implemented.
- README/`docs/architecture.md` status prose to reflect PTY now daemon-mediated
  and remote-capable.
- `CONTRIBUTING.md`: mention the remote PTY e2e in the integration suite.

## Risks and Open Questions

- The blocking IPC server serves one connection at a time, so an interactive PTY
  session monopolizes the daemon for its lifetime (same as `task.watch`).
  Acceptable for alpha; documented.
- Live PTY streaming over Matrix has homeserver rate limits; interactive chunks
  are small and flushed promptly. Backpressure/rate tuning is out of scope.
- The Docker-backed two-daemon e2e cannot run in every environment; it is
  `#[ignore]`d per project convention and validated via the integration script.

## Implementation Checklist

1. Add `pty_ipc.rs` with `ExecPtyParams`, `PtyServerFrame`, `PtyClientFrame` + serde tests.
2. Implement loopback `dispatch_exec_pty` full-duplex handler; register `exec.pty`.
3. Rewrite CLI `cmd_exec_pty` over IPC; drop direct `PtySession`/`RunSpec` use.
4. Add live PTY streaming + `run_controlled_pty_exec` + resize channel on target.
5. Route `pty.resize`; add `handle_live_pty_resize` (sender-authorized) + `send_pty_resize`.
6. Bridge remote PTY in `dispatch_exec_pty` (room+agent) via the subscriber registry.
7. Tests: loopback round-trip + resize (CI); `#[ignore]`d two-daemon remote PTY.
8. Docs: README status, architecture prose, CONTRIBUTING.
9. `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`,
   `cargo test --all`, `cargo build --all`.
</content>
</invoke>
