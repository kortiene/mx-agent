# Complete Matrix-backed daemon-mediated `mx-agent exec` (Phase 1–2: IPC migration)

Tracking issue: [#155](https://github.com/kortiene/mx-agent/issues/155)

## Problem Statement

`mx-agent exec` currently runs the requested command **inside the stateless CLI
process**: `cmd_exec` calls `mx_agent_daemon::run()` / `capture_child_output()` /
`prepare_artifact()` and (for `--pty`) `PtySession` directly. This violates the
mx-agent daemon/CLI separation described in `docs/architecture.md` §10.1: the CLI
is supposed to be a thin, stateless stdio bridge while the daemon owns process
supervision, the Matrix client, signing keys, policy, and trust.

The just-landed `call` migration (#193, `call_ipc.rs`) moved `mx-agent call`
behind a daemon `call.start` IPC method backed by a local-loopback executor.
`exec` should follow the same pattern as the first concrete step of #155.

## Goals

- Define an `exec.start` daemon IPC method and a serializable result that
  carries the exec output frames (chunks/artifact/finished) plus a stable
  invoke-failure shape.
- Add a daemon-side **local-loopback** executor (`start_exec_loopback`) that runs
  the command through the existing runner/stream/artifact stages and returns the
  frames — the same behavior `cmd_exec` produces today, but inside the daemon.
- Refactor CLI `cmd_exec` (non-PTY path) so it no longer imports daemon runner
  internals; it connects to the daemon over IPC, receives frames, and renders
  them with the existing `crate::stream` renderer, preserving stdout/stderr
  output, artifact previews, `--strict-stream`, and exit-code propagation.
- Make non-PTY `mx-agent exec` require a running daemon (exit 3 when absent),
  matching `call`.

## Non-Goals

This PR delivers **Phases 1–2 only** (the incremental milestone the issue
explicitly blesses). The following remain follow-up work and are **not** in
scope here:

- Phase 3–6: publishing signed `com.mxagent.exec.request.v1` to a room and
  driving a real remote exec end-to-end over Matrix `/sync` (target-side
  authorize/run/respond + requester-side live event forwarding). This depends on
  a live `/sync`-driven exec execution loop that does not exist yet (README
  lists "remote Matrix-backed exec" as Planned; `event_router` dispatches to a
  logging stub today).
- Phase 7: stdin streaming as Matrix stdin chunks and signed cancellation.
- Phase 8: remote PTY over IPC/Matrix. `--pty` keeps its current local path in
  this PR; moving it behind streaming IPC is tracked as follow-up.

Live streaming of partial output over IPC is also out of scope: today's loopback
already runs the command to completion before rendering, so a single batched
`exec.start` response is behavior-preserving. The streaming/notification IPC
machinery (Phase 1's "notifications") is deferred until the remote path needs it.

## Relevant Repository Context

- `crates/mx-agent-cli/src/cli.rs`: `cmd_exec` (non-PTY) + `collect_exec_frames`
  call `mx_agent_daemon::run/RunSpec/capture_child_output/prepare_artifact/
  ArtifactConfig`. `cmd_call` already uses `daemon_ipc_call(global, "call.start",
  ...)`. `daemon_ipc_call` is the shared single-response IPC helper.
- `crates/mx-agent-cli/src/stream.rs`: `StreamFrame` (Chunk/Artifact/Finished),
  `render_stream`/`render_stream_with`, exit-code constants.
- `crates/mx-agent-daemon/src/call_ipc.rs`: the established IPC-contract +
  loopback pattern to mirror.
- `crates/mx-agent-daemon/src/lifecycle.rs`: `dispatch` wires IPC methods;
  `call.start` is a synchronous arm; task methods build a current-thread runtime
  via `block_on_task_response`.
- `crates/mx-agent-protocol/src/schema.rs`: `StreamChunk`, `StreamArtifact`,
  `ExecFinished` are all `Serialize`/`Deserialize`.
- `crates/mx-agent-cli/tests/daemon_lifecycle.rs`: `call_uses_daemon_ipc_path`
  is the integration-test template (exit 3 with no daemon; full round-trip with
  a daemon).

## Proposed Implementation

New daemon module `crates/mx-agent-daemon/src/exec_ipc.rs`:

```rust
pub struct ExecStartParams {
    pub room: Option<String>,
    pub agent: Option<String>,
    pub command: Vec<String>,
    pub cwd: Option<PathBuf>,
    pub stdin: Option<Vec<u8>>,   // buffered piped stdin, forwarded to the child
    pub stream: bool,
    pub pty: bool,                 // accepted for forward-compat; loopback ignores
    pub task: Option<String>,
    pub strict_stream: bool,
}

#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ExecFrame {
    Chunk(StreamChunk),
    Artifact(StreamArtifact),
    Finished(ExecFinished),
}

#[serde(rename_all = "snake_case")]
pub enum ExecErrorKind { NotFound, EmptyCommand, Spawn }

#[serde(tag = "status", rename_all = "snake_case")]
pub enum ExecOutcome {
    Ok { frames: Vec<ExecFrame> },
    Error { kind: ExecErrorKind, message: String },
}

pub struct ExecStartResult {
    pub invocation_id: String,
    pub request_id: String,
    pub outcome: ExecOutcome,
}

pub async fn start_exec_loopback(params: &ExecStartParams) -> ExecStartResult { ... }
```

`start_exec_loopback` reproduces today's `collect_exec_frames` logic inside the
daemon: mint `invocation_id`/`request_id`, build a `RunSpec`, run it, switch to
artifact mode for high-output commands, otherwise capture chunks, and append a
terminal `ExecFinished`. Runner errors map to `ExecErrorKind`
(MissingCwd / spawn-NotFound → `NotFound`; `EmptyCommand` → `EmptyCommand`;
other spawn → `Spawn`).

`lifecycle::dispatch` gets an `"exec.start"` arm that builds a current-thread
runtime, `block_on`s `start_exec_loopback`, and returns the serialized result —
no Matrix session required (loopback), like `call.start`.

CLI `cmd_exec` (non-PTY): read piped stdin (unchanged), build `ExecStartParams`,
call `daemon_ipc_call::<_, ExecStartResult>(global, "exec.start", &params)`, then:
- `Error` → map `kind` to exit codes (NotFound → 127, EmptyCommand → 64,
  Spawn → `EXIT_PROTOCOL_FAILURE` 128);
- `Ok { frames }` → convert each `ExecFrame` to `StreamFrame` and render with the
  existing renderer (strict vs best-effort), preserving today's exit-code and
  integrity handling.

`collect_exec_frames` and the now-unused daemon-internal imports are removed from
the CLI. `--pty` continues to call `cmd_exec_pty` (local) unchanged.

## Affected Files / Crates / Modules

- `crates/mx-agent-daemon/src/exec_ipc.rs` (new)
- `crates/mx-agent-daemon/src/lib.rs` (module + re-exports)
- `crates/mx-agent-daemon/src/lifecycle.rs` (`exec.start` dispatch arm + test)
- `crates/mx-agent-cli/src/cli.rs` (`cmd_exec` non-PTY refactor; drop
  `collect_exec_frames`)
- `crates/mx-agent-cli/tests/daemon_lifecycle.rs` (exec-over-IPC test)
- `README.md` status table; `docs/user-guide.md` exec note (no overclaiming)

## CLI / API Changes

- New daemon IPC method `exec.start` (params/result above). New public daemon
  types `ExecStartParams`, `ExecStartResult`, `ExecOutcome`, `ExecFrame`,
  `ExecErrorKind`, `start_exec_loopback`.
- CLI behavior change: non-PTY `mx-agent exec` now requires a running daemon
  (exit 3 otherwise). Output/exit-code/`--json`-free rendering is unchanged.

## Data Model / Protocol Changes

No Matrix event-schema changes. The IPC result reuses the existing
`StreamChunk`/`StreamArtifact`/`ExecFinished` schema types. No persistence
changes.

## Security Considerations

- Restores daemon/CLI separation for the non-PTY exec path: the CLI no longer
  links the process runner. The daemon owns execution.
- Loopback runs the literal command (raw exec) exactly as today — this is not a
  new capability and not a remote path; no Matrix tokens, device keys, or signing
  keys are exposed to the CLI.
- The exec command/cwd/stdin can contain sensitive data and are never logged by
  the new code.
- No `unsafe`; Unix-only; MSRV 1.74. New public items are documented.
- The full signed/trust/policy-gated remote path remains future work; this PR
  must not imply remote exec is implemented.

## Testing Plan

- Daemon unit tests in `exec_ipc.rs`: well-formed minted IDs; successful run
  yields a `Finished` frame with the child's exit code; missing cwd / unknown
  command map to `ExecErrorKind::NotFound`; empty command → `EmptyCommand`;
  result/outcome round-trip and serde tag shapes.
- Daemon lifecycle test: `exec.start` validates params and is reachable through
  `dispatch`.
- CLI integration test mirroring `call_uses_daemon_ipc_path`: exit 3 with no
  daemon; with a daemon, `exec -- echo hi` (or a not-found command for exit 127)
  round-trips through IPC.
- No Docker/Matrix dependency added to default `cargo test --all`.

## Documentation Updates

- README status table: note exec is daemon-IPC-mediated (loopback) like call;
  do not claim remote Matrix exec.
- `docs/user-guide.md`: adjust exec wording to "through the daemon" without
  implying remote execution.

## Risks and Open Questions

- `--pty` still runs locally in the CLI this PR; the headline DoD bullet ("no
  longer directly runs local commands from the CLI process") is satisfied for
  the non-PTY path only. Documented as Phase 8 follow-up.
- Buffered stdin is carried as `Option<Vec<u8>>` over JSON (array of bytes);
  acceptable for local IPC and small piped inputs, matching today's buffered
  loopback.

## Implementation Checklist

1. Add `crates/mx-agent-daemon/src/exec_ipc.rs` with types + `start_exec_loopback`
   and unit tests.
2. Register the module and re-export the public types in daemon `lib.rs`.
3. Add the `exec.start` dispatch arm (current-thread runtime, no session) + a
   lifecycle test.
4. Refactor CLI `cmd_exec` non-PTY to use `daemon_ipc_call`; delete
   `collect_exec_frames` and now-unused daemon imports; add an `ExecFrame` →
   `StreamFrame` conversion.
5. Add the CLI integration test.
6. Update README status table and `docs/user-guide.md` (no overclaiming).
7. Run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D
   warnings`, `cargo test --all`, `cargo build --all`.
