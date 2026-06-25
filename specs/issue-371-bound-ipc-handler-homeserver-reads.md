# Bound IPC request/response handlers against a stalled-homeserver hang (issue #371)

## Problem Statement

Issue #368 fixed one symptom — `task.graph` hanging on an unbounded `/messages`
pagination in the liveness-enrichment read — by wrapping that single read in a
5 s `tokio::time::timeout` (`agent.rs::bounded_latest_heartbeats`). The
adversarial verification of that fix found the same unbounded-read pattern is
repo-wide: many daemon IPC handlers `await` `client.sync_once(...)` and/or
`room.messages(...)` with no wall-clock bound. matrix-sdk's `RequestConfig`
caps each *single* request at ≈30 s (per-attempt timeout) × a 30 s
`max_retry_time` budget, but a handler that does `sync_once` **plus** an
unbounded `/messages` pagination loop accumulates those bounded reads into an
effectively unbounded total. Because each IPC connection is served as a serial
request/response loop (`mx-agent-ipc::server::serve_streaming_connection`), a
handler stuck on a stalled homeserver read holds its worker and never returns —
the exact failure mode (`task.graph` poisoning subsequent calls) that let #368
escape to a green `main`.

The CLI IPC client (`mx-agent-ipc::client::Client::recv`) has no read timeout,
so the daemon side is the only place that can bound this.

## Goals

- No request/response IPC handler (`task.*`, `agent.*`, `approval.*`,
  `share.*`/artifact, `workspace.*`, `invocation.*`, `trust.*`,
  `device.list/show/verify.manual`, `cross_signing.*`, `recovery.*`) can hang
  indefinitely on a stalled homeserver read. Each returns a bounded JSON-RPC
  error instead.
- A stalled handler must not poison its multiplexed connection: the bounded
  error returns, and a subsequent request on the same connection is still
  served (the #368/#258 regression class).
- A real-socket regression test covering the timeout-bounded round-trip for a
  representative handler.
- The bound must not break legitimately long-running / streaming handlers.

## Non-Goals

- Bounding the **streaming / interactive** handlers (`task.watch`,
  `workspace.watch`, `exec.start`/`exec.pty`, `call.start`,
  `device.verify.start` SAS). These are intentionally long-lived, do **not** go
  through `block_on_task_response`, and already run on their own detached worker
  threads (#258) so they cannot starve other connections. Their internal initial
  `sync_once` (e.g. `watch.rs:184`) is left unbounded by design.
- Per-read individual timeouts at all ~25 `sync_once` / 5 `room.messages` call
  sites. A single wall-clock bound on the handler's **total** homeserver work is
  strictly stronger (it also bounds multi-page pagination loops) and is
  future-proof (covers handlers not yet written) — see Proposed Implementation.
- Changing the CLI, the wire protocol, error codes, or adding configuration.
- Refactoring `block_on_task_response` to inject a session for testing (tracked
  separately in #373).

## Relevant Repository Context

- `crates/mx-agent-daemon/src/lifecycle.rs`
  - `dispatch()` (`:686`) routes every IPC method. All session-backed
    request/response methods funnel through `block_on_task_response()`
    (`:653`), which: loads the daemon session
    (`load_daemon_session_response`, `:637`), builds a per-request
    current-thread tokio runtime with `.enable_all()` (`:663`, so the timer
    driver is available), and `runtime.block_on(f(session))` (`:676`).
  - The streaming methods are split off earlier: `dispatch_streaming()`
    (`:1419`) routes `task.watch` / `workspace.watch` / `exec.pty` /
    `device.verify.start` to dedicated handlers; everything else falls through
    to `dispatch()`.
  - `serve_streaming` is invoked at `:294`; the existing tests module is at
    `:1556` (`use super::*`).
- `crates/mx-agent-daemon/src/agent.rs` — the #368 precedent:
  `LIVENESS_ENRICHMENT_TIMEOUT` (`:468`) + `bounded_latest_heartbeats` (`:477`)
  wrap a single read in `tokio::time::timeout` and degrade gracefully.
- `crates/mx-agent-daemon/src/matrix.rs:31` — `SDK_MAX_RETRY_TIME = 30s` bounds
  matrix-sdk's internal retry, so a single request is ≈30 s worst case; the
  IPC budget must sit comfortably above that to avoid false-tripping a slow but
  working single read.
- `crates/mx-agent-ipc/src/server.rs` — `serve_streaming(listener, handler)`
  (handler: `Fn(&Request, &mut UnixStream) -> io::Result<()>`); the
  `serve_streaming_concurrent_connections_do_not_block` test (`:236`, #258) is
  the harness to mirror. `read_frame`/`write_frame`/`Request`/`Response` are
  public re-exports.
- Error codes (`crates/mx-agent-ipc/src/rpc.rs`): `INTERNAL_ERROR = -32603`
  (reused for the timeout; no new code, no protocol change).

## Proposed Implementation

A single backstop in `block_on_task_response`, factored into small testable
pieces, in `crates/mx-agent-daemon/src/lifecycle.rs`:

1. Budgets (named constants, doc-commented):
   - `IPC_REQUEST_BUDGET: Duration = Duration::from_secs(60)` — default ceiling
     for a request/response handler's homeserver work. ~2× the SDK's single
     request envelope (#matrix.rs SDK_MAX_RETRY_TIME 30 s), so a slow-but-working
     single read is not false-tripped, while a stalled read / unbounded
     pagination is bounded.
   - `IPC_RECOVERY_BUDGET: Duration = Duration::from_secs(180)` — key-backup
     restore (`recovery.enable`/`recovery.recover`) legitimately takes longer
     (server-side backup + room-key download).
   - `fn request_budget(method: &str) -> Duration` → recovery budget for
     `recovery.enable`/`recovery.recover`, default otherwise. (The per-method
     hook the issue suggests; easy to extend.)

2. A small generic, runtime-agnostic core:
   - `enum BoundedOutcome<T> { Completed(Result<T, WorkspaceError>), TimedOut }`
   - `async fn run_bounded<T>(budget: Duration, fut) -> BoundedOutcome<T>` —
     `tokio::time::timeout(budget, fut)`; `Ok(res) => Completed(res)`,
     `Err(_elapsed) => TimedOut`. On timeout the inner future is dropped, which
     cancels the in-flight matrix-sdk request (cancel-safe; no half-committed
     local state).
   - `fn bounded_response<T: Serialize>(req: &Request, budget, outcome) -> Response`
     — `Completed(Ok)` → serialize to result; `Completed(Err)` → `INTERNAL_ERROR`
     with the error string; `TimedOut` → `INTERNAL_ERROR` with a distinctive,
     greppable message naming the method + budget + issue #371, and a
     `tracing::warn!` (method + budget only, no secrets) for operator visibility.

3. Rewire `block_on_task_response`:
   ```rust
   let budget = request_budget(&req.method);
   let outcome = runtime.block_on(run_bounded(budget, f(session)));
   bounded_response(req, budget, outcome)
   ```
   Session load and runtime build are unchanged (so the existing "not logged in"
   and "invalid params" paths are untouched).

Why the dispatch-wrapper bound (not per-read): it bounds the handler's *total*
homeserver time in one place, so it also bounds multi-page pagination loops and
any future handler, and it cannot break the streaming handlers because those do
not use `block_on_task_response`.

## Affected Files / Crates / Modules

- `crates/mx-agent-daemon/src/lifecycle.rs` — add budgets/helpers; rewire
  `block_on_task_response`; add unit + real-socket tests in the existing tests
  module.
- Docs: `README.md` status table and/or `docs/architecture.md` IPC section —
  note that request/response IPC handlers are wall-clock-bounded against a
  stalled homeserver (only if an existing claim needs reconciling; keep minimal).
- No changes to `mx-agent-ipc`, `mx-agent-protocol`, the CLI, or any read-site
  module.

## CLI / API Changes

None. Same methods, same success payloads. A stalled handler now returns a
JSON-RPC `INTERNAL_ERROR` (-32603) with a timeout message instead of hanging —
the CLI already renders IPC errors.

## Data Model / Protocol Changes

None. No new error code, no schema change, no persistence change.

## Security Considerations

- Availability hardening: removes a stalled-/malicious-homeserver denial-of-service
  vector on the serial IPC connection (a hung handler poisoning multiplexed
  requests). Strengthens, does not weaken, the model.
- No change to signing / trust / policy / approval — the bound is orthogonal to
  the authorization pipeline and applies after the existing session gate.
- No secrets in logs: the timeout `warn!` and error message carry only the
  method name and the budget seconds.
- Unix-only, no `unsafe`, MSRV unchanged. Dropping the timed-out future is
  ordinary async cancellation (cancel-safe matrix-sdk reads).

## Testing Plan

Unit (deterministic, no homeserver), in `lifecycle.rs` tests:
- `run_bounded` times out a never-completing future within a tiny budget →
  `TimedOut`.
- `run_bounded` passes a ready future through → `Completed(Ok)`.
- `run_bounded` propagates a handler `Err` → `Completed(Err)`.
- `request_budget` maps `recovery.*` to the recovery budget and everything else
  to the default.
- `bounded_response`: `TimedOut` → error response whose message names the method
  + budget + #371; `Completed(Ok)` → result; `Completed(Err)` → error.

Real-socket regression (acceptance #2), in `lifecycle.rs` tests, mirroring the
`serve_streaming_concurrent_connections_do_not_block` (#258) harness:
- Bind a real Unix socket; `serve_streaming` with a handler that, for a "stalls"
  method, runs the production `run_bounded(short_budget, pending-future)` and
  writes `bounded_response`; for "ping" returns a result.
- One client connection: send "stalls" → assert a bounded timeout **error**
  comes back within a few seconds; then send "ping" on the **same** connection →
  assert it still succeeds (no connection poisoning — the #368 class).

## Documentation Updates

- Add a one-line note (architecture IPC section or README status row) that
  request/response IPC handlers are wall-clock-bounded against a stalled
  homeserver. Keep it factual to what ships here; do not imply per-read bounds.
- Reference #371 in the code doc comments (as #368/#258/#351 are referenced).

## Risks and Open Questions

- Budget tuning: 60 s default / 180 s recovery are generous backstops, not tight
  SLAs. They convert "potentially unbounded" into "bounded"; a pathologically
  slow-but-working pagination on a degraded homeserver may hit the bound and
  error — acceptable and preferable to hanging.
- Cancellation safety: dropping a timed-out matrix-sdk read aborts the HTTP
  request; matrix-sdk reads are cancel-safe (crypto-store writes are
  transactional and follow successful responses). No local state corruption.
- Streaming handlers' internal reads remain unbounded by design (own worker
  thread per #258); documented as a non-goal.

## Implementation Checklist

1. Add `IPC_REQUEST_BUDGET`, `IPC_RECOVERY_BUDGET`, `request_budget()` to
   `lifecycle.rs`.
2. Add `BoundedOutcome<T>`, `run_bounded()`, `bounded_response()`.
3. Rewire `block_on_task_response` to use them; keep session/runtime setup.
4. Add the unit tests (run_bounded / request_budget / bounded_response).
5. Add the real-socket regression test (timeout + no-poison).
6. `cargo fmt`, `cargo clippy --all-targets --all-features -- -D warnings`,
   `cargo test -p mx-agent-daemon`, then `cargo test --all` + `cargo build --all`.
7. Reconcile any docs claim; keep the change minimal.
8. Commit `closes #371`, push, open PR, watch CI, self-review, merge.
