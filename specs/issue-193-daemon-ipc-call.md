# Daemon IPC API for `call`

## Problem Statement

`mx-agent call` executes named tools **in the CLI process** by calling
`mx_agent_daemon::execute_tool()` directly. That violates the CLI/daemon split:
the daemon should own tool execution (and, later, the Matrix client, signing
key, policy, and trust context), and the stateless CLI should only talk to it
over the local IPC socket. This issue moves `call` onto the IPC path with a
local-loopback execution fallback, so the live Matrix-backed flow (#194) can
later replace the loopback without changing the CLI.

## Goals

- Add a `call.start` IPC method handled by the daemon.
- Have the daemon execute the tool (local loopback for now) and return an
  `invocation_id`, `request_id`, and the structured outcome.
- Rewire `cmd_call` to use IPC; the CLI no longer calls `execute_tool()`.
- Fail clearly (exit 3) when the daemon is unavailable, matching other IPC
  commands.
- Preserve the existing human and `--json` output and exit-code behavior.

## Non-Goals

- No live Matrix call transport, signing, trust, or policy enforcement — that is
  #194. Loopback simply runs the built-in tool locally.
- No `call.cancel` (calls are synchronous today).
- No change to the tool registry or `execute_tool` semantics.

## Relevant Repository Context

- CLI `cmd_call` (`crates/mx-agent-cli/src/cli.rs`) currently builds tool input
  and calls `mx_agent_daemon::execute_tool`, mapping `ToolError` to exit codes
  127/64/128 (architecture §5.3).
- `daemon_ipc_call` (renamed from `task_ipc_call`) is the generic CLI→daemon
  JSON-RPC helper used by the `task.*` commands; it returns exit 3 when the
  daemon cannot be contacted.
- Daemon IPC dispatch lives in `lifecycle.rs::dispatch` (single-response) and
  `dispatch_streaming` (for `task.watch`).
- `tool_exec::{execute_tool, ToolResult, ToolError}` runs built-in tools.
- `id::{generate_invocation_id, generate_request_id}` mint `inv_`/`req_` IDs.

## Proposed Implementation

New `crates/mx-agent-daemon/src/call_ipc.rs`:

- `CallStartParams { room: Option<String>, agent: Option<String>, tool: String,
  input: Value }` — `call.start` params. `room`/`agent` are accepted for
  forward compatibility with #194 and unused by loopback.
- `CallErrorKind { UnknownTool, InvalidArgs, NotFound, Spawn }` — stable,
  machine-readable invoke-failure kind.
- `CallOutcome { Ok { exit_code, summary } | Error { kind, message } }`
  (internally tagged by `status`).
- `CallStartResult { invocation_id, request_id, outcome: CallOutcome }`.
- `start_call_loopback(&CallStartParams) -> CallStartResult` — mint IDs, run
  `execute_tool`, map `ToolError` to `CallErrorKind`. Never logs raw `input`.

Daemon dispatch: add `"call.start"` to `lifecycle.rs::dispatch`, parsing
`CallStartParams` and returning `start_call_loopback(...)`.

CLI: rename `task_ipc_call` → `daemon_ipc_call`; rewrite `cmd_call` to send
`call.start` and render `CallOutcome`:
- `Ok` → human `mx-agent: <summary>` / `--json` `{"exit_code","summary"}`; exit
  = `exit_code`.
- `Error` → human `mx-agent: <message>` (stderr) / `--json`
  `{"ok":false,"error":<message>}`; exit per `CallErrorKind`
  (`UnknownTool`/`NotFound` → 127, `InvalidArgs` → 64, `Spawn` → 128).

## Affected Files / Crates / Modules

- `crates/mx-agent-daemon/src/call_ipc.rs` (new)
- `crates/mx-agent-daemon/src/lib.rs` (module + re-exports)
- `crates/mx-agent-daemon/src/lifecycle.rs` (`call.start` dispatch)
- `crates/mx-agent-cli/src/cli.rs` (`cmd_call`, rename helper)
- `README.md` / `docs/user-guide.md` (call needs a running daemon)

## CLI / API Changes

- `mx-agent call` now requires a running daemon; without one it exits 3 with a
  clear message (`run `mx-agent daemon start``). User-facing stdout/stderr shape
  and exit codes are otherwise unchanged.
- New public daemon API: `CallStartParams`, `CallStartResult`, `CallOutcome`,
  `CallErrorKind`, `start_call_loopback`.

## Data Model / Protocol Changes

None to the Matrix protocol. New local IPC method `call.start`.

## Security Considerations

- The CLI never executes tools and never reads Matrix/session/signing state; the
  daemon owns execution. IPC keeps the existing `0600` + `SO_PEERCRED` checks.
- Raw tool `input` is never logged (it can carry secret-looking args).
- Loopback runs only built-in, schema-validated tools — no arbitrary shell.

## Testing Plan

- Daemon unit tests for `start_call_loopback`: success result shape +
  invocation/request IDs; unknown tool → `CallErrorKind::UnknownTool`; bad args
  → `InvalidArgs`.
- CLI unit tests: `CallArgs` parsing (already present) and `CallErrorKind` →
  exit-code mapping.
- IPC integration test (`tests/`): start a daemon, call `call.start`, assert the
  response shape — verifying the CLI path uses IPC.

## E2E Decision

Add a lightweight IPC integration test that drives a real daemon socket (no
Docker/Matrix needed), consistent with existing daemon IPC tests. No
Docker/Matrix e2e — loopback does not touch Matrix. (`E2E decision: IPC
integration test added; no Docker/Matrix e2e because loopback is local.`)

## Risks / Open Questions

- Behavior change: `call` now needs the daemon. Documented in README/user guide.

## Implementation Checklist

- [ ] `call_ipc.rs` with IPC types + loopback executor and docs.
- [ ] `call.start` dispatch in the daemon.
- [ ] CLI `cmd_call` on the IPC path; rename helper to `daemon_ipc_call`.
- [ ] Unit + IPC integration tests.
- [ ] README/user-guide note that `call` needs a daemon.
- [ ] `cargo fmt --check`, `clippy -D warnings`, `test --all`, `build --all`.
