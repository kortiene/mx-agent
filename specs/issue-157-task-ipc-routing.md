# Route Task Commands Through Daemon IPC

## Problem Statement

Task CLI commands currently call `*_for_session` helpers after reading the persisted Matrix session directly from the CLI process. That violates mx-agent's daemon/CLI split: Matrix credentials and long-lived Matrix state must stay inside the daemon. Issue #157 requires the task command group to use local daemon IPC instead.

## Goals

- Route `mx-agent task create`, `update`, `list`, `graph`, and `watch` through daemon IPC.
- Add daemon IPC methods `task.create`, `task.update`, `task.list`, `task.graph`, and `task.watch`.
- Preserve existing human-readable and `--json` task output.
- Ensure the CLI task path does not read Matrix session files or tokens.
- Stream `task watch` updates over the local IPC connection.
- Add tests that task commands fail cleanly when the daemon socket is unavailable.

## Non-Goals

- Do not change Matrix task event schema.
- Do not implement new task scheduler behavior beyond routing commands.
- Do not add Windows support.
- Do not make default tests require Docker or a live Matrix homeserver.

## Relevant Repository Context

- `crates/mx-agent-cli/src/cli.rs` owns command parsing and currently calls `load_session_or_exit()` for task commands.
- `crates/mx-agent-daemon/src/lifecycle.rs` runs the IPC server and currently handles `daemon.ping` and `daemon.status`.
- `crates/mx-agent-ipc` provides length-delimited JSON-RPC frames over Unix sockets.
- `crates/mx-agent-daemon/src/task.rs` and `watch.rs` already provide Matrix task create/update/list/watch helpers that restore a daemon-owned session.
- `mx-agent-daemon::TaskGraph` can render graph state after `task.list` returns tasks.

## Proposed Implementation

1. Add CLI helpers to connect to the daemon socket from `mx_agent_daemon::Paths::resolve().socket_path`, call a JSON-RPC method, validate errors, and deserialize result payloads.
2. Replace task create/update/list/graph code paths so they build existing option structs and call IPC methods instead of `load_session_or_exit()` / `*_for_session`.
3. For `task.graph`, add a daemon `task.graph` method returning a serialized `TaskGraph`; the CLI renders it exactly as before.
4. Add streaming support in `mx-agent-ipc` server for `task.watch`: the daemon sends one JSON-RPC response frame per watch event on the same connection. Each response's result is an envelope carrying `event = initial|changed|reconnecting|reconnected` and the same data the CLI already renders.
5. Keep `daemon.status` and other non-streaming methods as single-response calls.
6. In daemon handlers, load the stored session and call existing task/watch functions internally. Missing sessions return JSON-RPC errors; no session material is serialized to the CLI.
7. Add focused tests for task command daemon-unavailable errors and daemon IPC dispatch behavior.

## Affected Files / Crates / Modules

- `crates/mx-agent-cli/src/cli.rs`
- `crates/mx-agent-daemon/src/lifecycle.rs`
- `crates/mx-agent-ipc/src/server.rs`
- Possibly `docs/architecture.md`
- `specs/issue-157-task-ipc-routing.md`

## CLI / API Changes

No CLI flag changes. New JSON-RPC methods:

- `task.create` params: `CreateTaskOptions`; result: `TaskState`
- `task.update` params: `UpdateTaskOptions`; result: `TaskState`
- `task.list` params: `ListTasksOptions`; result: `TaskState[]`
- `task.graph` params: `ListTasksOptions`; result: `TaskGraph`
- `task.watch` params: `ListTasksOptions`; result stream: watch event envelopes

## Data Model / Protocol Changes

No Matrix protocol changes. Local IPC gains task method names and a task-watch event envelope.

## Security Considerations

- The CLI no longer reads Matrix session files for task commands.
- Matrix tokens/device keys remain daemon-owned and are never serialized over IPC.
- IPC stays Unix-socket-only with existing same-UID checks and `0600` socket protections.
- Room membership still does not grant execution permission; this issue only routes task state commands.
- Watch errors must not include secrets; use existing error messages without token material.

## Testing Plan

- Unit tests for daemon task IPC method parameter validation where practical.
- CLI tests that task subcommands return a clean daemon-unavailable error when no socket exists.
- Existing task rendering tests and full suite should continue to pass.
- No Docker/live Matrix e2e in default tests.

## Documentation Updates

- Update architecture IPC method list / task command notes to state task commands are daemon-mediated.

## Risks and Open Questions

- `task.watch` streaming over JSON-RPC requires extending the IPC server without breaking existing single-response clients.
- Live Matrix behavior remains covered by existing ignored/script-gated integration tests, not default unit tests.

## Implementation Checklist

- [ ] Add serializable task option support if missing.
- [ ] Add IPC client helper for task commands.
- [ ] Add daemon handlers for task methods.
- [ ] Add streaming server support for `task.watch`.
- [ ] Refactor task CLI functions to use IPC only.
- [ ] Add unavailable daemon CLI tests.
- [ ] Update docs.
- [ ] Run required checks.
