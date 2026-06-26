# Real-socket + CLI e2e for the `task.*` / `agent.*` IPC dispatch seam (issue #373)

> Status: planning spec. Implements **tests** (plus one small CLI behavior fix) — it adds
> no Matrix protocol features. Do not implement product behavior beyond the documented
> `event_id` CLI surfacing decision in §"CLI / API Changes".

## Problem Statement

Three confirmed fail-CLOSED bugs (`#366`, `#367`, `#368`) all reached a green `main`
inside a single audit because **nothing exercises the transport-composed dispatch seam end
to end**. There is coverage on either side of the seam but nothing *through* it:

- The real Unix-socket transport is tested, but only with a **stub** handler
  (`crates/mx-agent-ipc/tests/rpc_over_socket.rs:33-39`, `:156-159`) — it proves
  `serve`/`serve_streaming`, not the daemon's real `dispatch`.
- The daemon's real `dispatch()` is tested **in-process** for param-validation and the
  "not logged in" path (`crates/mx-agent-daemon/src/lifecycle.rs:1739` `task_ipc_methods_validate_params_before_loading_session`,
  `:1764` `task_ipc_methods_report_missing_daemon_session`, `:1788`
  `matrix_ipc_methods_validate_params_before_loading_session`, `:1835`
  `matrix_ipc_methods_report_missing_daemon_session`). These call `dispatch(...)` directly;
  they never cross a socket and never go through `dispatch_streaming`'s composition
  (`lifecycle.rs:1511-1539`) or `write_ipc_response`.
- The orchestrator internals are tested against an in-memory `TaskStore`
  (`crates/mx-agent-daemon/tests/task_orchestration_e2e.rs`), never crossing the socket or
  touching `dispatch`.
- The only real CLI↔daemon-over-socket suite
  (`crates/mx-agent-cli/tests/daemon_lifecycle.rs`) covers `daemon start/status/stop`,
  `call`, `exec`, and CLI-local auth/trust — but **no `task.*` / `agent.*`** at all.

So the daemon-side `dispatch` routes for `task.*`/`agent.*` and the CLI-side
`daemon_ipc_call` call sites for those methods have **zero coverage that composes transport
+ real handler + CLI client**. Each of `#366` (denial propagation), `#367` (response shape),
and `#368` (handler liveness / connection poisoning) is a different failure mode behind that
same untested boundary.

The gap is **still live today**: `task_create`/`task_update` deserialize the daemon reply as
`mx_agent_protocol::schema::TaskState` (`crates/mx-agent-cli/src/cli.rs:2809`, `:2865`) even
though the daemon returns `mx_agent_daemon::TaskMutation` (`crates/mx-agent-daemon/src/task.rs:567-575`,
returned at `task.rs:658`). Because `TaskMutation` `#[serde(flatten)]`s `TaskState`, the parse
succeeds and the `#367` `event_id` audit anchor is silently dropped — so `mx-agent task create
--json` never surfaces it. That silent drop is itself proof the seam is untested.

## Goals

1. **Tier 1 — daemon real-dispatch over a real socket (no homeserver, default `cargo test`).**
   One persistent socket connection drives the **real** `dispatch_streaming`/`dispatch`
   (not a stub) for `task.create`, `task.update`, `task.graph`, `task.list`,
   `agent.register`, `agent.list`, `agent.show`, asserting:
   - (a) every method **routes** (never `METHOD_NOT_FOUND`);
   - (b) malformed params surface as a structured `INVALID_PARAMS` IPC error **across the socket**;
   - (c) the "not logged in" denial surfaces as a structured `INTERNAL_ERROR` **across the socket**;
   - (d) an error/empty response on one call **does not poison the next call** on the same
     connection (the multiplexing regression class behind `#368`/`#258`).
2. **Tier 1 — CLI `task.*`/`agent.*` over the socket against a live daemon.** Extend
   `crates/mx-agent-cli/tests/daemon_lifecycle.rs` to drive `mx-agent task
   create|update|graph|list` and `mx-agent agent register|list|show` against a real daemon,
   asserting **clean exit codes and structured stderr** (these `daemon_ipc_call` call sites
   have no coverage today).
3. **Tier 2 — session-backed success-path shapes (Docker-gated).** Drive `task.create →
   task.update → task.graph` and `agent.register → agent.list/show` to success against a live
   homeserver and assert response **shapes**, including:
   - the `#367` `event_id` anchor on `task.create`/`task.update` replies (`TaskMutation`);
   - `task.graph` returns enriched diagnostics **and returns bounded — without hanging** (`#368`);
   - a policy/signing denial (`#366`) propagates as a structured IPC error.
4. **Resolve the `event_id` drop (`#367`)**: surface the anchor at the CLI (`task create
   --json` / `task update --json`) by deserializing the reply as `TaskMutation`, and assert it
   — at the CLI in Tier-2 (or, if Tier-2 stays at the IPC layer, assert the anchor at the IPC
   layer and the CLI surfacing in a focused unit test).

## Non-Goals

- **Re-testing already-covered paths.** Param-validation and "not logged in" are covered
  in-process (`lifecycle.rs:1739-1853`); orchestrator internals by
  `task_orchestration_e2e.rs`; the raw transport by `rpc_over_socket.rs`. This issue is
  about *composing* them, not duplicating them.
- **New Matrix protocol features, event schema, or policy semantics.** No new
  `com.mxagent.*` event types, no new IPC methods, no policy-engine changes.
- **Changing daemon dispatch behavior.** `dispatch`/`dispatch_streaming` are exercised
  as-is; the only product change is the CLI deserialization/output of the *already shipped*
  `TaskMutation.event_id`.
- **Windows support** and any non-Unix path assumptions.
- **A required production seam refactor.** An "inject `StoredSession` + in-memory room-state
  backend" refactor is described as an *optional* alternative to the Docker-gated Tier-2; the
  recommended path needs no production refactor.
- **`#371` follow-up.** The unbounded `/messages`+`/sync` hardening is its own merged work
  (`block_on_task_response`'s `IPC_REQUEST_BUDGET`); this spec only *relies* on it for the
  Tier-2 bounded-graph assertion.

## Relevant Repository Context

**Architecture split** (`docs/architecture.md` §0, §10): the CLI is stateless; the daemon
owns the Matrix session, crypto, policy, signing key, and supervision. The CLI never restores
a Matrix client for `task.*`/`agent.*` — it calls the daemon over a `0600`, peer-UID-checked
Unix socket using length-delimited (4-byte BE) JSON-RPC 2.0 frames.

**Transport (crate `mx-agent-ipc`).**
- `serve_streaming(listener, handler)` (`crates/mx-agent-ipc/src/server.rs:120`) accepts
  connections, runs `verify_peer` on the accept thread, then serves each connection on a
  detached worker via `serve_streaming_connection` (`server.rs:38`), which **loops reading
  frames on one connection** and calls `handler(&request, stream)` per frame. A malformed
  frame yields a controlled `PARSE_ERROR` and the loop continues.
- `serve(...)` is the one-response convenience wrapper over `serve_streaming` (`server.rs:61`).
- `Client::connect` + `Client::call(method, params)` is the CLI-side client. The
  `mx_agent_ipc::rpc` codes used here: `INVALID_PARAMS`, `INTERNAL_ERROR`, `METHOD_NOT_FOUND`,
  `PARSE_ERROR`.

**Daemon dispatch (crate `mx-agent-daemon`, `src/lifecycle.rs`).**
- `dispatch_streaming(req, stream, pid, started_at, socket_path, supervisor, exec_subscribers)`
  (`:1511`) routes streaming methods (`task.watch`, `workspace.watch`, `exec.pty`,
  `device.verify.start`) to their long-lived handlers, and **everything else** to
  `dispatch(...)` followed by `write_ipc_response` (`:1528-1538`). This is the composition
  the daemon's real serve loop installs (`lifecycle.rs:282-297`).
- `dispatch(...)` (`:778`) matches the method and routes `task.create`→
  `create_task_for_session` (`:838`), `task.update` (`:844`), `task.list` (`:850`),
  `task.graph` (`:856`, with `#368`/`#312` liveness enrichment bounded by `#371`),
  `task.cancel` (`:889`), `agent.register` (`:945`), `agent.list` (`:951`), `agent.show`
  (`:957`), `agent.tools` (`:968`).
- The **session gate**: every `task.*`/`agent.*` route runs under `block_on_task_response`
  (`:745`), which calls `load_daemon_session_response` (`:637`) **first**. With no stored
  session it returns `INTERNAL_ERROR` "not logged in; run `mx-agent auth login` first" (`:643`)
  *before* any handler future is built. Issue `#371`'s `run_bounded`/`bounded_response`
  (`:698`, `:713`) then bound a *session-backed* handler's homeserver work to
  `IPC_REQUEST_BUDGET` (60s; 180s for recovery) so a stalled read can't poison the connection.

**Existing real-socket precedent to mirror.** `lifecycle.rs:2372`
`stalled_handler_times_out_over_socket_without_poisoning_connection` (issue #371) already
binds a real `UnixListener`, spawns `serve_streaming` on a thread, connects a `UnixStream`,
and issues multiple frames on one connection asserting bounded-error + no-poisoning. It uses a
*stand-in* handler; the Tier-1a test reuses this skeleton but installs the **real**
`dispatch_streaming`. The dispatch unit tests (`task_ipc_methods_*`) live in the same
`#[cfg(test)] mod tests` and already have `TempRuntime` (`:1669`, sets
`MX_AGENT_RUNTIME_DIR` + `ENV_DATA_DIR` under a global env lock) and `test_supervisor()`
(`:1665`, an idle `WorkerSupervisor`). Both are reusable for the new in-crate socket test.

**CLI call sites (crate `mx-agent-cli`, `src/cli.rs`).**
- `daemon_ipc_call::<T, R>(global, method, params)` (`:2742`) connects, calls, and: on a
  transport failure prints `could not contact daemon … run mx-agent daemon start` and exits
  `3` (`:2757`); on a daemon error response prints `mx-agent: daemon rejected {method}: {msg}`
  and exits `FAILURE` (1) (`:2763-2766`); otherwise deserializes `R`.
- `task_create` (`:2774`) and `task_update` (`:2830`) deserialize as
  `mx_agent_protocol::schema::TaskState` → **drops `event_id`**. `task_cancel` (`:2886`),
  `task_list` (`:2921`, `Vec<TaskState>`), `task_graph` (`:2952`, `mx_agent_daemon::TaskGraph`).
- `agent_register` (`:2623`, `mx_agent_protocol::schema::AgentState`), `agent_list` (`:2457`,
  `Vec<mx_agent_daemon::AgentListing>`), `agent_show` (`:2497`,
  `Option<mx_agent_daemon::AgentListing>`).

**The `#367` reply type** is public: `mx_agent_daemon::TaskMutation { #[serde(flatten)] task:
TaskState, event_id: String }` (`crates/mx-agent-daemon/src/lib.rs:186-189`,
`src/task.rs:567-575`). It is a strict superset of the `TaskState` JSON (one added top-level
`event_id`), so switching the CLI to it is backward-compatible for existing `--json`
consumers and additive for new ones.

**Test conventions.**
- `crates/mx-agent-cli/tests/daemon_lifecycle.rs` drives the compiled binary
  (`env!("CARGO_BIN_EXE_mx-agent")`), isolates state with a per-test
  `MX_AGENT_RUNTIME_DIR` (monotonic counter, not just a timestamp — `unique_runtime_dir()`),
  sets `MX_AGENT_LOG=off`, polls `daemon status --json` until ready, and stops the daemon at
  the end. No homeserver is needed for `start`/`call`/`exec` loopback.
- The Docker-gated live suite lives in `crates/mx-agent-daemon/tests/matrix_integration.rs`,
  every test `#[ignore = "requires a local Matrix homeserver; run via
  scripts/matrix_integration_test.sh"]`, reading `MX_AGENT_TEST_HOMESERVER`,
  `MX_AGENT_TEST_USER`/`_PASSWORD`, `MX_AGENT_TEST_USER2`/`_PASSWORD2` via `required_env`.
- `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`,
  `cargo test --all` must pass. `unsafe_code = forbid`; `missing_docs = warn` (CI `-D
  warnings`). MSRV is **1.93** (raised from 1.74 by issue #315; the issue template's "1.74"
  is stale — honor the declared 1.93 and use only std + existing deps so MSRV is a non-issue).

## Proposed Implementation

Three test additions plus one CLI fix. Work in this order so each tier's value is independent.

### Tier 1a — real `dispatch` over a real socket (in-crate, `mx-agent-daemon`)

Because `dispatch`/`dispatch_streaming`, `WorkerSupervisor`, `ExecSubscriberRegistry`, and
`now_unix()` are **private** to `mx-agent-daemon`, this test must be an **in-crate unit test**
in `lifecycle.rs`'s `#[cfg(test)] mod tests` (a `tests/` integration test can only see the
public API and would force widening it). Add `serve_streaming_real_dispatch_*` mirroring the
existing `stalled_handler_times_out_over_socket_without_poisoning_connection` (`:2372`):

1. `let _rt = TempRuntime::new("dispatch-socket");` — fresh runtime/data dir, **no
   `session.json`**, so the session gate resolves to "not logged in". Holding `_rt` keeps the
   global env lock for the whole socket interaction (the detached worker thread reads the same
   process env).
2. Bind a real `UnixListener` in the temp runtime dir (or a unique temp path with a monotonic
   counter, as the #371 test does). Clone `socket_path: String`, `supervisor =
   test_supervisor()` (it is `Clone`), and `exec_subscribers = ExecSubscriberRegistry::new()`
   (`Clone`); `pid`/`started_at` are `Copy`.
3. Spawn the server on a thread, installing the **real** handler — the exact closure the
   production serve loop uses (`lifecycle.rs:283-293`):
   ```rust
   serve_streaming(&listener, move |req, stream| {
       dispatch_streaming(req, stream, pid, started_at, &socket_path,
                          &supervisor, &exec_subscribers)
   })
   ```
4. Connect **one** `mx_agent_ipc::Client` (or raw `UnixStream` + `read_frame`/`write_frame`)
   and, over that single connection, issue the seam methods and assert:
   - **(a) routes / never `METHOD_NOT_FOUND`.** For each of `task.create`, `task.update`,
     `task.graph`, `task.list`, `agent.register`, `agent.list`, `agent.show`: send a
     **well-formed** params object; assert the response is an error whose code is
     `INTERNAL_ERROR` with message containing `not logged in` — i.e. it reached the session
     gate, proving the route exists and is not `METHOD_NOT_FOUND`. (Asserting `code !=
     METHOD_NOT_FOUND` is the load-bearing check; the "not logged in" message is the positive
     signal that it routed into `block_on_task_response`.)
   - **(b) `INVALID_PARAMS` across the socket.** For at least `task.create` and
     `agent.register` (struct-shaped params), send `Value::Null`; assert the framed response
     is an error with code `INVALID_PARAMS` and a message containing `invalid params` and the
     method name. This proves `parse_params`' error crosses the socket as a structured frame.
   - **(c) `INTERNAL_ERROR` "not logged in" across the socket.** Covered by (a)'s well-formed
     calls; assert the code is `INTERNAL_ERROR` and the message is the gate's wording.
   - **(d) no connection poisoning.** On the **same** connection, interleave a malformed call
     (`task.graph` with null params → `INVALID_PARAMS`) immediately followed by a well-formed
     call (`task.list` valid params → `INTERNAL_ERROR`); assert both produce distinct framed
     responses whose `id`s match their requests and that the second call is served (the
     connection survived the first error). This structurally exercises the multiplexing /
     one-bad-response-doesn't-break-the-next regression class behind `#368`/`#258`. (The
     *liveness-hang* form of `#368` is session-gated and belongs to Tier 2.)
5. Drop the client, then `_rt`, then best-effort `remove_*` the socket/dir, matching the
   cleanup style of the surrounding tests.

Notes:
- Route everything through `dispatch_streaming` (not `dispatch` directly) so the test
  exercises the real composition branch (`:1528-1538`) plus `write_ipc_response`.
- Do not log or assert anything secret; the no-session path produces none.
- Keep all client calls synchronous within the test body and complete them before dropping
  `_rt`, so the worker thread never reads env after the runtime is torn down.

### Tier 1b — CLI `task.*`/`agent.*` over the socket (`mx-agent-cli` `daemon_lifecycle.rs`)

Add tests mirroring `call_uses_daemon_ipc_path` / `exec_uses_daemon_ipc_path`. Reuse
`unique_runtime_dir()` and `run(runtime_dir, args)`. The daemon starts with **no Matrix
session** (loopback start needs none), so `task.*`/`agent.*` reach IPC and are denied "not
logged in" — which is exactly the `daemon_ipc_call` error path under test.

- `task_and_agent_commands_round_trip_daemon_ipc` (one test, several sub-assertions):
  1. **No daemon** → at least one `task list --room '!x:test'` and one `agent list --room
     '!x:test'` exit `3` with stderr mentioning `daemon` (mirrors the existing no-daemon
     assertions).
  2. Start the daemon; poll `daemon status --json` until ready.
  3. For each of `task create --room '!x:test' --title t`, `task update --room '!x:test'
     --task-id t1 --state pending`, `task graph --room '!x:test'`, `task list --room
     '!x:test'`, `agent register --room '!x:test' --agent-id a1 --kind pi`, `agent list --room
     '!x:test'`, `agent show --room '!x:test' --agent-id a1`: assert the process exits with a
     **clean, structured** failure — exit code `1` (`ExitCode::FAILURE` from
     `daemon_ipc_call`'s daemon-rejected arm), **not** a panic/timeout/crash — and stderr
     contains `daemon rejected` and `not logged in`. Assert stdout is empty (no partial JSON
     printed before the error).
  4. Stop the daemon; clean up the runtime dir.
- **Choose args that pass local CLI validation first** so the IPC round-trip is actually
  exercised (e.g. a valid `--state` value, since `validate_task_state_arg` runs before IPC and
  would otherwise exit `64`; a `task create` with no `--tool`/`--exec` yields a `None` action,
  which is a valid manual task and reaches IPC). Document each chosen arg set inline.

The assertion boundary is intentionally the **structured-failure** contract (clean exit +
structured stderr + no stdout leak), not success — success requires a session and belongs to
Tier 2. This proves every `daemon_ipc_call` `task.*`/`agent.*` call site round-trips a real
socket frame and surfaces a daemon error cleanly.

### Tier 2 — session-backed success-path shapes (Docker-gated, recommended)

Add `#[ignore]`d tests to `crates/mx-agent-daemon/tests/matrix_integration.rs` using the
existing `required_env` harness (`MX_AGENT_TEST_HOMESERVER`, `MX_AGENT_TEST_USER`/`_PASSWORD`).
Log in, create a workspace room, then drive the **IPC entry points** the dispatch routes call,
asserting:

- `task_create_update_reply_carries_event_id_anchor` (#367): call `create_task_for_session`
  then `update_task_for_session`; assert each returns a `TaskMutation` whose `event_id` is
  non-empty and well-formed (a Matrix `$…` event id) and whose flattened task fields match the
  request. This asserts the anchor at the IPC layer regardless of the CLI surfacing decision.
- `task_graph_returns_enriched_diagnostics_without_hanging` (#368): build a small DAG (a
  dependency edge and/or an agent-assigned task), call the `task.graph` enrichment
  (`list_tasks_for_session` + `list_agents_with_liveness_for_session` + `diagnose_tasks` +
  `TaskGraph::from_tasks(...).with_diagnostics(...)`, mirroring `dispatch`'s `task.graph` arm
  at `lifecycle.rs:856-887`); assert it returns **within a bounded wall-clock** (well under
  `IPC_REQUEST_BUDGET`) and that diagnostics are populated (e.g. a dependency or
  liveness warning).
- `agent_register_then_list_show_shapes`: `register_agent_for_session`, then
  `list_agents_with_liveness_for_session` (assert the `AgentListing { agent, liveness }`
  envelope) and `show_agent_with_liveness_for_session` (assert `Some(listing)` with the
  registered `agent_id` and a computed `liveness`).
- `policy_or_signing_denial_propagates_as_ipc_error` (#366): drive a task action / remote
  call that local deny-by-default policy (or an untrusted/missing signature) must reject;
  assert it surfaces as a `WorkspaceError` → `INTERNAL_ERROR` structured failure, not a
  success or a silent drop.

**Optional stronger variant (full transport composition at Tier 2).** Additionally drive the
real `mx-agent` CLI binary (`task create --json`) against a started daemon whose data dir
holds a real session, and assert the `--json` stdout contains the `event_id` anchor. This
exercises socket + CLI + session together but requires wiring a logged-in session into the
daemon data dir (via the harness); keep it as an extension, not the baseline.

**Alternative to Docker-gating (optional seam refactor).** If a maintainer prefers the
success-path assertions to run under plain `cargo test`, refactor the handlers so `dispatch`
can take an injected `StoredSession` + an in-memory room-state backend (the
`task_orchestration_e2e.rs:66` in-memory `RoomTaskStore` is a ready building block). This is a
larger production change and is **not** required by this spec; the Docker-gated route is the
recommended default.

### CLI fix — surface the `#367` `event_id` anchor

In `crates/mx-agent-cli/src/cli.rs`, change `task_create` (`:2809`) and `task_update`
(`:2865`) to deserialize the reply as `mx_agent_daemon::TaskMutation` instead of
`mx_agent_protocol::schema::TaskState`:

- **Human output (default): unchanged.** Use `mutation.task` for `println!("mx-agent: created
  task {}", …)` + `print_task(&mutation.task)`.
- **`--json` output: emit the full `TaskMutation`** (flattened `TaskState` plus the top-level
  `event_id`). This is additive/backward-compatible — existing consumers that read `TaskState`
  fields keep working; automation that wants the audit anchor can now read `event_id`.
- Leave `task_cancel` (`TaskState`), `task_list` (`Vec<TaskState>`), and `task_graph`
  (`TaskGraph`) unchanged — only create/update carry `TaskMutation`.

This is the recommended resolution because the daemon already pays to produce the anchor and
an anchor no caller can read is a dead feature. Document the new `--json` field (see
Documentation Updates) and assert it.

**Homeserver-free regression guard for the fix (default tier, recommended).** The fix can be
proven without Docker by standing up a *fake daemon* at the CLI's resolved socket path. The IPC
client (`crates/mx-agent-ipc/src/client.rs:27-47`) writes one request frame and reads the
**next** response frame with no strict `id` matching, so a test can: bind a `UnixListener` at
`<runtime_dir>/daemon.sock` (the path `daemon_socket_path` resolves from `MX_AGENT_RUNTIME_DIR`),
spawn a one-shot thread that `read_frame`s the request and `write_frame`s a canned
`Response::result(id, <TaskMutation JSON with a sentinel event_id>)`, then run `mx-agent task
create --room '!x:test' --title t --json` against it and assert stdout parses to JSON containing
the sentinel `event_id`. A companion negative assertion (the *pre-fix* deserialize-as-`TaskState`
behavior would drop it) makes the guard meaningful. This belongs in
`crates/mx-agent-cli/tests/daemon_lifecycle.rs` alongside Tier-1b and needs no homeserver —
prefer it over deferring the fix's assertion to the Docker-gated Tier 2.

## Affected Files / Crates / Modules

**Read (context):**
- `crates/mx-agent-daemon/src/lifecycle.rs` — `dispatch` (`:778`), `dispatch_streaming`
  (`:1511`), `block_on_task_response`/`load_daemon_session_response` (`:637-775`), the serve
  loop wiring (`:282-297`), the existing socket test (`:2372`), and `mod tests` helpers
  (`TempRuntime` `:1669`, `test_supervisor` `:1665`).
- `crates/mx-agent-ipc/src/server.rs` (`serve_streaming` `:120`), `crates/mx-agent-ipc/src/rpc.rs`
  (error codes), `crates/mx-agent-ipc/tests/rpc_over_socket.rs` (transport-only precedent).
- `crates/mx-agent-daemon/src/task.rs` (`TaskMutation` `:567`, `create_task_for_session`
  `:629`), `crates/mx-agent-daemon/src/lib.rs:186-189` (public exports).
- `crates/mx-agent-cli/src/cli.rs` (`daemon_ipc_call` `:2742`, `task_*`/`agent_*` call sites).
- `crates/mx-agent-daemon/tests/task_orchestration_e2e.rs` (in-memory `RoomTaskStore`),
  `crates/mx-agent-daemon/tests/matrix_integration.rs` (Docker-gated harness pattern).

**Modify / add:**
- `crates/mx-agent-daemon/src/lifecycle.rs` — **add** in-crate Tier-1a socket test(s) in
  `#[cfg(test)] mod tests` (no production code change).
- `crates/mx-agent-cli/tests/daemon_lifecycle.rs` — **add** Tier-1b CLI `task.*`/`agent.*`
  test(s).
- `crates/mx-agent-daemon/tests/matrix_integration.rs` — **add** `#[ignore]`d Tier-2 tests.
- `crates/mx-agent-cli/src/cli.rs` — **modify** `task_create`/`task_update` to use
  `TaskMutation` and surface `event_id` in `--json` (the only production change).
- Docs (see Documentation Updates).

## CLI / API Changes

- **`mx-agent task create --json` / `mx-agent task update --json`**: the JSON object gains a
  top-level `event_id` string (the `com.mxagent.task.v1` audit anchor, `#367`). All prior
  `TaskState` fields remain present and unchanged — additive/backward-compatible. Human
  (non-`--json`) output is unchanged.
- No new IPC methods, no new CLI subcommands or flags, no changes to `task cancel`/`list`/
  `graph` or `agent` output shapes.

## Data Model / Protocol Changes

None. No new Matrix event types, no state-schema changes, no policy changes, no signing/trust
changes. `TaskMutation` and its `event_id` already exist on the wire (`#367`); this work only
stops the CLI from discarding it and adds tests around the existing dispatch seam.

## Security Considerations

- **CLI/daemon separation preserved.** Tests drive the daemon only over the existing
  peer-UID-checked `0600` Unix socket (Tier-1b/2) or through the real private `dispatch`
  (Tier-1a). No test grants the CLI/coding-agent access to Matrix tokens or device keys; the
  Tier-1a/1b paths run with **no session at all**.
- **No secret logging / no token leakage.** The no-session tiers produce no secrets. The
  Tier-2 login path must use the existing harness and `MX_AGENT_LOG` posture; any CLI-output
  assertion must additionally assert the access token never appears in stdout/stderr (mirror
  `auth_status_reports_session_without_leaking_tokens` in `daemon_lifecycle.rs:267`). The new
  `event_id` is non-secret public event-id material.
- **Authorization unchanged & still fail-closed.** The Tier-2 `#366` assertion confirms
  policy/signing denial *propagates* as an IPC error — room membership still never implies
  execution, and privileged actions remain Ed25519-signed + trust + policy gated. No test
  weakens or bypasses any gate.
- **Unix-only.** Tests use Unix-domain sockets and Unix process semantics already present in
  the suite; no Windows paths or assumptions are added.
- **No `unsafe`; MSRV-safe.** Test code uses only `std` + existing workspace deps; the CLI fix
  is a type swap and a `serde_json::to_string` of a different (already-derived `Serialize`)
  struct. Nothing requires `unsafe` or APIs newer than the declared MSRV (1.93).

## Testing Plan

- **Tier 1a (daemon, default `cargo test`):** in-crate `lifecycle.rs` socket test(s)
  asserting (a) routes/never `METHOD_NOT_FOUND`, (b) `INVALID_PARAMS` over the socket, (c)
  `INTERNAL_ERROR` "not logged in" over the socket, (d) no connection poisoning across an
  error-then-valid pair on one connection — for `task.create/update/graph/list` and
  `agent.register/list/show` through the **real** `dispatch_streaming`.
- **Tier 1b (CLI, default `cargo test`):** `daemon_lifecycle.rs` test(s) driving `mx-agent
  task create|update|graph|list` and `mx-agent agent register|list|show` against a live
  no-session daemon, asserting clean exit (`3` no-daemon, `1` daemon-rejected), structured
  stderr (`daemon rejected` + `not logged in`), and no stdout leak.
- **Tier 2 (Docker-gated `#[ignore]`d, `scripts/matrix_integration_test.sh`):** session-backed
  `task.create→update→graph` and `agent.register→list/show` success shapes, the `#367`
  `event_id` anchor, the `#368` bounded-graph (no hang), and the `#366` denial propagation;
  optional CLI-binary `--json` extension asserting `event_id` reaches `task create --json`.
- **CLI fix coverage (default `cargo test`, recommended):** a homeserver-free `daemon_lifecycle.rs`
  test that binds a fake daemon at the CLI socket path, returns a canned `TaskMutation` frame
  (the `Client` reads the next frame without `id` matching — `client.rs:27-47`), and asserts
  `task create --json` / `task update --json` stdout carries the sentinel `event_id`. The
  Docker-gated Tier-2 CLI extension can additionally assert it end-to-end against a real session.
- **Gates:** `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`,
  `cargo test --all` (default tiers), and the integration script for Tier 2. Confirm
  `crates/mx-agent-cli/tests/doc_drift.rs` still passes after the CLI/docs change.

## Documentation Updates

- **`docs/architecture.md` §9.2** (task state / `TaskMutation`, around the `#367` reply note):
  state that `mx-agent task create/update --json` now surfaces the `event_id` audit anchor.
- **CLI reference / wiki** (`wiki/` task examples, and any `docs/user-guide.md` task snippet):
  show the `event_id` field in a `task create --json` example. Keep `wiki/**` edits in the
  source files (mirrored on merge to `main`).
- **README status table** (`task create/update/list/graph` row): no status change required,
  but if a one-line note about the surfaced audit anchor is desired, add it without implying
  new behavior. Do **not** imply any unimplemented capability.
- No new public Rust API is introduced (test-only code + an existing-type swap), so no new
  `missing_docs` items — but keep the new CLI `--json` field documented in help/reference text
  if the command help enumerates JSON fields.

## Risks and Open Questions

1. **Surface `event_id` vs keep internal-only (decision).** Recommended: **surface** it in
   `--json` (the anchor is otherwise unreachable). It is an additive `--json` change, so it
   should be documented and `doc_drift`-checked. If a maintainer instead deems it internal,
   the fallback is to document "internal-only" and assert the anchor only at the IPC layer
   (Tier-2) — but then the daemon keeps paying to produce a field no caller can use. This is
   the one behavior decision in the spec.
2. **Tier-1a must be in-crate.** `dispatch_streaming` is private; the faithful test cannot be
   a `tests/` integration test without widening the public surface. The spec chooses the
   in-crate `mod tests` placement (matching the existing `#371` socket test) over adding a
   `pub` shim. If a maintainer prefers a `tests/` file, a minimal `#[doc(hidden)] pub`
   test-only entry point would be needed — avoid unless required.
3. **Env-lock / parallelism in Tier-1a.** `TempRuntime` serializes env-dependent tests via a
   global lock; the detached `serve_streaming` worker reads process env. The test must finish
   all client calls before dropping `TempRuntime`. Low risk, but the implementer must keep the
   interaction synchronous and the runtime alive throughout.
4. **Tier-1b arg validation.** Some CLI args are validated locally before IPC (e.g.
   `validate_task_state_arg` → exit `64`; an empty command → exit `64`). The test must pick
   arg sets that pass local validation so the IPC round-trip is actually reached; otherwise it
   would assert the wrong exit code and never touch the socket.
5. **`#368` liveness-hang is session-gated.** Tier-1a can only prove the *poisoning/multiplex*
   regression class structurally (one bad frame doesn't break the next); the actual
   timeline-read hang reproduction requires a session and lives in Tier-2 (and relies on the
   merged `#371` `IPC_REQUEST_BUDGET` bound to *not* hang). Make this scoping explicit in test
   comments so a future reader doesn't think Tier-1a reproduces the hang.
6. **Tier-2 Docker dependency.** Tier-2 only runs under `scripts/matrix_integration_test.sh`;
   it will not run in plain `cargo test --all` or on macOS without Docker. The default-tier
   value (1a/1b) must stand on its own. The optional seam refactor (in-memory room-state
   backend) is the escape hatch if maintainers want success-path shapes without Docker, at the
   cost of a production change.
7. **MSRV note mismatch.** The issue template says "MSRV 1.74"; the repo's real MSRV is 1.93
   (issue #315). Honor 1.93; the added code uses only std + existing deps, so this is a
   non-issue in practice.

## Implementation Checklist

1. **Tier 1a (daemon in-crate socket test).**
   - [ ] In `crates/mx-agent-daemon/src/lifecycle.rs` `#[cfg(test)] mod tests`, add a test
     that binds a real `UnixListener`, sets up `TempRuntime` (no session), and spawns
     `serve_streaming` with the real `dispatch_streaming` closure (clone `supervisor`,
     `exec_subscribers`, `socket_path`; `pid`/`started_at` `Copy`).
   - [ ] Over one connection, assert (a) routes/never `METHOD_NOT_FOUND`, (b) `INVALID_PARAMS`
     for null params (≥ `task.create`, `agent.register`), (c) `INTERNAL_ERROR` "not logged in"
     for well-formed params across all seven methods, (d) error-then-valid on the same
     connection both return distinct framed responses with matching ids.
   - [ ] Comment that Tier-1a proves the multiplex/poisoning class, not the session-gated
     `#368` hang.
   - [ ] Clean up client → runtime → socket/dir; keep calls synchronous before teardown.
2. **Tier 1b (CLI over socket).**
   - [ ] In `crates/mx-agent-cli/tests/daemon_lifecycle.rs`, add a test using
     `unique_runtime_dir()`/`run(...)`: no-daemon `task list`/`agent list` → exit `3` +
     stderr `daemon`; start daemon; poll ready.
   - [ ] Drive `task create|update|graph|list` and `agent register|list|show` with
     locally-valid args; assert exit `1`, stderr contains `daemon rejected` + `not logged in`,
     stdout empty.
   - [ ] Stop daemon; remove runtime dir.
3. **CLI fix — surface `event_id`.**
   - [ ] Change `task_create`/`task_update` in `crates/mx-agent-cli/src/cli.rs` to
     deserialize `mx_agent_daemon::TaskMutation`; human output uses `mutation.task`; `--json`
     emits the full `TaskMutation` (with `event_id`).
   - [ ] Leave `task_cancel`/`task_list`/`task_graph` unchanged.
   - [ ] Add a homeserver-free `daemon_lifecycle.rs` test: fake daemon at the CLI socket path
     returns a canned `TaskMutation` frame; assert `task create --json` stdout carries the
     sentinel `event_id` (default-tier regression guard for the fix).
4. **Tier 2 (Docker-gated).**
   - [ ] In `crates/mx-agent-daemon/tests/matrix_integration.rs`, add `#[ignore]`d tests using
     `required_env`: login + room, then assert `TaskMutation.event_id` (#367); bounded
     `task.graph` enrichment with diagnostics (#368); `agent.register→list/show` shapes;
     policy/signing denial propagation (#366).
   - [ ] (Optional) Add a CLI-binary `--json` extension asserting `event_id` reaches `task
     create --json`, with a no-token-leak assertion.
5. **Docs.**
   - [ ] Update `docs/architecture.md` §9.2 and the CLI/wiki task examples to show the
     surfaced `event_id` in `task create/update --json`.
   - [ ] Verify `crates/mx-agent-cli/tests/doc_drift.rs` still passes.
6. **Gates.**
   - [ ] `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`,
     `cargo test --all` green.
   - [ ] `scripts/matrix_integration_test.sh` green for the new Tier-2 tests (where Docker is
     available).
