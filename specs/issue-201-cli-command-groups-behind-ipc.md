# Issue #201 — Move remaining Matrix CLI command groups behind daemon IPC

## Problem statement

Several CLI command groups still restore Matrix sessions **in the CLI process**:
each handler calls `load_session_or_exit()` and then a daemon-crate
`*_for_session(&session, …)` function directly, so the stateless CLI reads the
Matrix session file and builds Matrix clients itself — violating the daemon's
ownership of credentials/crypto (architecture §10, §13). The `task.*` and
`call`/`exec` groups already go through daemon IPC; the rest do not.

Affected groups (21 `load_session_or_exit()` call sites): `workspace`
(create/join/attach/status/watch), `agent` (register/list/show/tools), `trust`
(publish/state), `approval` (decide), `share` (file/diff/env/list/get), and
`invocation` (list/get/cancel/artifact).

## Goals

- Add daemon IPC methods for each Matrix-backed command above; the daemon owns
  the session and calls the existing `*_for_session` functions internally.
- Rewire every affected CLI handler to call the daemon over the local IPC socket
  (reusing the established `daemon_ipc_call` / streaming-watch patterns) and
  remove `load_session_or_exit()`.
- Preserve human-readable and `--json` output for every command.
- A daemon that cannot be contacted maps to the existing exit code 3.

## Non-goals

- **Auth login stays CLI-initiated** (decision below); `auth status`/`logout`
  read only local session *metadata* and do not restore a Matrix client, so they
  are left unchanged. No new password-over-socket surface is introduced.
- No change to the Matrix wire protocol, signing, trust, or policy semantics —
  only *where* the session is restored (daemon, not CLI).
- Large-artifact streaming over IPC is unchanged; `share get` / `invocation
  artifact` return their already-bounded, verified bytes in the IPC result.

### Auth login decision

`auth login` necessarily receives a password and performs the Matrix login. It
remains **CLI-initiated** (option 1 in the issue): the CLI performs the login and
writes the `StoredSession` into the daemon-owned data dir; the daemon restores it
for every subsequent operation. The password is read interactively / from the
existing flag path and never placed on argv by this change, and is never logged
(`mx_agent_telemetry::Secret`). Adding an `auth.login` IPC that ships the
password over the socket is deliberately deferred to avoid a new credential
surface; this is documented, not implied as done.

## Repository context

- `crates/mx-agent-cli/src/cli.rs` — command handlers; `daemon_ipc_call`,
  `daemon_socket_path`, the `task_watch` streaming pattern, `load_session_or_exit`.
- `crates/mx-agent-daemon/src/lifecycle.rs` — IPC `dispatch` / `dispatch_streaming`,
  `block_on_task_response`, `parse_params`, `load_daemon_session_response`.
- `*_for_session` functions in `workspace.rs`, `agent.rs`, `trust_state.rs`,
  `approval.rs`, `context.rs`, `invocation.rs`, `artifact.rs`, `watch.rs` — all
  return `Result<T, WorkspaceError>`.

## Affected crates/modules

- `mx-agent-daemon`: `Serialize`/`Deserialize` derives on the option structs and
  return types that lack them (`CreateWorkspaceOptions`, `AttachWorkspaceOptions`,
  `RegisterAgentOptions`, `ListAgentsOptions`, `Share*Options`, `ListSharesOptions`,
  `FetchContextOptions`, `RetrieveArtifactOptions`, `ListInvocationsOptions`, and
  `EffectiveTrust`/`ApprovalDecisionRecord`/`RetrievedArtifact`/`FetchedContext`),
  small IPC param structs for scalar-arg methods, new `dispatch` arms, and a
  streaming `workspace.watch` arm.
- `mx-agent-cli`: rewire handlers to `daemon_ipc_call` / streaming watch; remove
  `load_session_or_exit`.

## Implementation approach

1. **Daemon types:** add serde derives to the listed option/return structs (and
   their enum fields). `RetrievedArtifact`/`FetchedContext` carry `Vec<u8>`
   payloads (serde-default array encoding); they are already bounded/verified.
2. **Daemon IPC:** add request/response `dispatch` arms reusing
   `block_on_task_response` (all `*_for_session` share `WorkspaceError`):
   `workspace.create/join/attach/status`, `agent.register/list/show/tools`,
   `trust.publish/state`, `approval.decide`, `share.file/diff/env/list/get`,
   `invocation.list/get/cancel/artifact`. Methods needing the daemon signing key
   (`approval.decide`, `invocation.cancel`) load it from `SessionPaths` inside the
   handler. Add a streaming `workspace.watch` arm modeled on `task.watch`. Scalar
   args use small `#[derive(Serialize, Deserialize)]` param structs.
3. **CLI:** replace each `load_session_or_exit()` + `*_for_session` block with a
   `daemon_ipc_call::<_, Ret>(global, "method", &params)` call, preserving exit
   codes and human/`--json` rendering; wire `workspace watch` to the streaming
   client like `task watch`. Remove `load_session_or_exit` once unused.

## Security considerations

- The CLI no longer reads the session file or builds Matrix clients for these
  operations; the daemon (user-owned, `0600`) owns all Matrix/crypto state.
- The IPC socket keeps its `0600` perms + `SO_PEERCRED` UID check (unchanged).
- No secrets cross the socket for these methods (no tokens/keys in params or
  results); login keeps the password off argv and out of logs.
- Deny-by-default policy / signing / trust are unchanged — they already run in
  the daemon-side `*_for_session` paths.

## Testing plan

- Daemon: for each new method, a unit test that invalid params are rejected with
  `INVALID_PARAMS` before any session load, and that a missing daemon session is
  reported (`not logged in`) — mirroring the existing `task.*` dispatch tests.
- Param/result round-trip serialization tests for the new param structs and the
  newly-serializable option/return types.
- CLI: a test that a Matrix-backed command exits 3 when the daemon socket is
  absent (daemon-unavailable behavior), and that no handler references
  `load_session_or_exit` (grep-style guard in review).

## E2E decision

No new Docker E2E in the default suite: these are CLI↔daemon IPC rewirings whose
Matrix behavior is unchanged (same `*_for_session` functions). The
daemon-unavailable and param-validation tests run in `cargo test --all`; live
flows remain covered by the existing `matrix_integration.rs` suite. A
CLI-over-IPC live E2E is folded into issue #202.

## Risks / open questions

- Large surface (21 methods): mitigated by the uniform `WorkspaceError` return,
  reuse of `block_on_task_response`, and per-method param-validation tests.
- Byte payloads (`share get`, `invocation artifact`) use serde-default encoding
  over the framed socket; fine for alpha-bounded payloads, consistent with the
  deferred large-artifact work.

## Implementation checklist

- [ ] serde derives on option/return structs + enums.
- [ ] daemon IPC param structs + request/response dispatch arms + `workspace.watch`.
- [ ] CLI handlers rewired; `load_session_or_exit` removed.
- [ ] daemon param-validation/missing-session tests; CLI daemon-unavailable test.
- [ ] README/user-guide note that all listed groups are daemon-mediated IPC.
- [ ] `cargo fmt --check`, `clippy -D warnings`, `test --all`, `build --all`.
