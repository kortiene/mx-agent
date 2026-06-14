# Session Lifecycle: Lock trust.json/logout, Fix Stale Sync Token, Surface Sync-Loop Death, Reap Orphaned Children, Consume idempotency_key

GitHub issue: #316 — `type:bug area:daemon area:matrix priority:p2`

## Problem Statement

The `#269`/`#297` data-dir advisory flock (`with_data_dir_write_lock`) guards only three writers (signing-key generation, crypto-store-key generation, and `save_session`). Several other mutators of the same daemon-owned data dir run **outside** that lock, and several session-lifecycle transitions are incomplete. Concretely, the daemon today has these defects, all verified at HEAD:

1. **Lost trust revocations.** `TrustStore::save` is atomic but unlocked, and the CLI `trust approve`/`trust revoke` paths do unlocked load → modify → save round trips. Two concurrent invocations can lost-update `trust.json`, silently dropping a revocation — the exact failure mode the local trust store exists to prevent.
2. **Orphaned crypto store on logout.** `clear_session` is unlocked; a logout racing a login can interleave with `save_session` and strand a per-device crypto store (Megolm keys + device identity) on disk after a "successful" logout.
3. **Stale sync token across sessions.** `clear_session` removes `session.json`, the device crypto store, and the store key — but not the sync token, and login never clears it. Because every re-login mints a brand-new Matrix device, `run_sync_loop` resumes from the previous session's batch token, skipping the initial full sync (incomplete room state, missed invites). The token even carries across a different account on the same data dir. `clear_sync_token` exists, is unit-tested, and is exported — but is never called from production code.
4. **Logout is local-only.** No `matrix_auth().logout()` call exists anywhere, so an exfiltrated `session.json` stays usable server-side indefinitely after a local logout.
5. **Stranded device stores accumulate.** Each re-login without logout permanently strands the previous device's crypto store (`clear_session` removes only the device named by the *current* session).
6. **Silent sync-loop death.** `load_sync_token`/`save_sync_token` I/O errors propagate out of `run_sync_loop` without recording fatal/stopped health; the sync thread only logs a warning, so `daemon.status` keeps reporting the last healthy state forever. After a fatal auth error the sync loop exits but the scheduler and heartbeat loops keep running on the (now dead-token) client.
7. **Post-start login needs a restart.** `spawn_matrix_workers` runs once at startup and returns early when no session exists. A post-start `auth login` therefore never starts the sync/scheduler/heartbeat loops; a daemon restart is required. `docs/cli-reference.md` says the daemon "idles waiting for `auth login`", which is misleading.
8. **Orphaned exec children on stop.** `daemon stop` SIGTERMs, then after a fixed grace SIGKILLs only the daemon pid. In-flight exec children run in their own process groups with `kill_on_drop`, which never fires on SIGKILL, so they orphan. Restart recovery reconciles only task-linked invocations; bare (task-less) invocation state has no janitor.
9. **Dead `idempotency_key`.** `idempotency_key` is constructed and carried on the wire but consumed nowhere, despite `docs/architecture.md` promising "De-duplicate by idempotency key."

This spec covers fixing all nine as a single coherent session-lifecycle hardening pass.

## Goals

- Serialize `trust.json` writes under the existing data-dir advisory lock so concurrent `trust approve`/`trust revoke` can never lost-update (no dropped revocation), holding the lock across the whole load-modify-save round trip.
- Serialize `clear_session` under the same lock so a logout cannot interleave with `save_session` and strand a crypto store.
- Clear the sync token on logout and whenever the stored session identity (`user_id`/`device_id`) changes on login, so a re-login (including across accounts on one data dir) always performs an initial full sync.
- Make `auth logout` best-effort invalidate the access token server-side via `/logout`, degrading cleanly to local-only on network failure, never logging or printing the token.
- Detect and clean up (or visibly warn about) stranded per-device crypto stores on login, without clobbering a concurrent multi-user store.
- Surface sync-loop death in `daemon.status`: record fatal/stopped health on the persistence-error exit path, and stop or visibly degrade the scheduler/heartbeat loops when sync hits a fatal auth error.
- Add a `session.reload` IPC method (plus auto-invocation from `auth login` and a `daemon reload` CLI subcommand) so a post-start `auth login` brings up sync/scheduler/heartbeat without a daemon restart; fix the docs.
- Terminate in-flight exec child process groups on shutdown, and reconcile/clean up bare (task-less) invocation state plus any orphaned process groups on restart.
- Either consume `idempotency_key` (de-duplicate replayed exec requests) or remove the field and correct `docs/architecture.md`. Recommendation: consume it.
- Keep `cargo fmt --check`, `cargo clippy -D warnings`, build, and the full test suite green.

## Non-Goals

- Changing trust **semantics** (deny-by-default, Ed25519 + local trust store as the execution-permission anchor). The lock changes serialization only; a lost revocation is the bug being fixed, never tolerated.
- Widening the `#269` CLI-local auth/trust carve-out. The CLI may continue to write `session.json` and `trust.json` locally (the documented carve-out); it must not gain ownership of any *new* credential surface.
- Device-keying the sync token as a storage-layout change (kept as a considered alternative; the recommended fix is clear-on-change, no migration).
- Re-architecting the IPC server's per-connection detached-thread model or adding a connection drain (noted as optional hardening; not required by the acceptance criteria, which scope orphan teardown to exec children).
- Adding any Windows code paths; the daemon is Unix-only.
- Cross-signing / key-backup behavior beyond what logout already removes.

## Relevant Repository Context

**Crates.** The owning crate is `mx-agent-daemon` (long-lived Matrix state, crypto, policy, supervision). `mx-agent-cli` is the thin stateless front end that talks to the daemon over IPC and holds the documented auth/trust CLI-local carve-out. `mx-agent-protocol` owns the wire schema. `mx-agent-ipc` owns the Unix-domain-socket transport.

**Data-dir lock (`#269`/`#297`).** `crates/mx-agent-daemon/src/session.rs:289-312` — `with_data_dir_write_lock(paths, f)` is `pub(crate)`, generic over the closure error `E: From<io::Error>`, takes `flock(LOCK_EX)` on `<data_dir>/.write.lock` (`0600`), runs `f`, and releases on return. It currently guards `generate_crypto_store_key` (`session.rs:240-269`), `save_session` (`session.rs:320-334`), and signing-key generation (`signing.rs`). Callers must not nest acquisitions, and `save`-style writers called *inside* it must not re-acquire it.

**Session/token persistence.** `session.rs`: `clear_session` (`:359-373`) removes the current device's crypto store, the legacy flat store + key, and `session.json`, but not the sync token; `clear_sync_token` (`:438-444`) and `save_sync_token`/`load_sync_token` (`:411-435`) exist and are exported (`lib.rs:162-163`) but `clear_sync_token` is never called in production. `SessionPaths` resolves `sync_token` at the data-dir root (`:174`), shared across devices/accounts. `is_plain_path_component` (`:397-404`) is the path-traversal guard already used to safely `join`/remove device dirs.

**Trust store.** `crates/mx-agent-daemon/src/trust.rs`: `TrustStore::load` (`:117-124`), `TrustStore::save` (`:127-141`, atomic temp+rename, `0600`, but unlocked), `approve`/`revoke` mutate the in-memory `Vec<TrustEntry>`. CLI `trust_approve`/`trust_revoke` (`crates/mx-agent-cli/src/cli.rs:~1814-1860`) do unlocked `load → mutate → save`.

**Login / crypto-store layout.** `crates/mx-agent-daemon/src/matrix.rs`: `login_password` (`:280-331`) creates a temp crypto store, logs in (new device each time), then renames the temp dir to `<data_dir>/<device_id>`. It supports multiple users in one process (Alice+Bob integration tests) — each user gets its own device-id subdir — so any login-time cleanup must **not** delete a different user's store. `restore_client` (`:396-450`) reuses a published active client when present, else builds a store-backed client under the device subdir (with a legacy flat-layout fallback). `build_client` (`:174-181`) is store-less. The active-client registry (`ACTIVE_CLIENTS`, `:341-379`) is keyed by `(user_id, device_id)`.

**Sync loop + health.** `crates/mx-agent-daemon/src/sync.rs`: `run_sync_loop` (`:191-239`) loads the token (`:202`, `?`), persists each new token (`:212`, `?`), records success/failure/fatal/stopped on a shared `SyncHealth`, and on `StepError::Fatal` calls `record_fatal` and returns `Ok(())`. The two token-I/O `?` sites bypass health entirely. `run_matrix_sync_with_subscribers` (`:270-342`) wires the real client; `is_fatal_sync_error` (`:516-522`) classifies `UnknownToken`/`MissingToken` as fatal. `SyncHealth` (`:56-118`) already has `record_fatal`/`record_stopped` and serializes safely (no secrets).

**Worker supervision.** `crates/mx-agent-daemon/src/lifecycle.rs`: `run_foreground` (`:209-288`) binds IPC, calls `spawn_matrix_workers` once (`:237-238`), serves IPC on a background thread, then on signal signals `sync_running=false` and joins the three handles. `spawn_matrix_workers` (`:311-455`) returns `((None,None,None), None)` when no session exists (`:316-328`); otherwise spawns sync (`:342-383`), scheduler (`:398-421`), and heartbeat (`:427-447`) threads sharing one restored client and the `running` flag. The sync thread's error branch only `tracing::warn!`s (`:380`). `daemon.status` (`dispatch`, `:540-556`) reads health from a `SharedHealth` captured at startup. Per-request handlers reload the session via `load_daemon_session_response` (`:481-495`), but there is no `session.reload` method in the dispatch table (`:538-857`).

**Stop / process groups.** `lifecycle.rs` `stop(grace)` (`:1334-1361`) SIGTERMs the daemon pid, waits `grace`, then SIGKILLs the daemon pid only. `crates/mx-agent-daemon/src/runner.rs`: children are placed in their own process group (`process_group(0)`, `:418`, pgid == pid) with `kill_on_drop(true)` (`:412`); `signal_process_group` (`:539-554`) / `terminate_process_group` (`:572-574`) / `kill_process_group` (`:582-584`) use `killpg`. The live-exec path (`exec.rs` `run_controlled_exec`, `:1194-1325`) spawns the child, captures `pid = child.id()`, and already kills the group on timeout/cancel. The in-flight registry `LIVE_EXEC_CONTROLS` (`exec.rs:85-111`) is keyed by `invocation_id`; `InflightGuard` (`inflight.rs`) counts running invocations in memory only.

**Restart recovery.** `crates/mx-agent-daemon/src/task_orchestrator.rs`: `reconcile_executing_tasks` (`:756…`) and `recover_executing_tasks` (`:711-724`) reconcile only **task-linked** `executing` tasks against invocation state (driven from `scheduler_loop.rs:255-256`). Bare (task-less) invocation state has no janitor.

**idempotency_key.** Constructed as `format!("exec:{invocation_id}")` in `build_signed_exec_request` (`exec.rs:296,316`) and `scheduler_loop.rs:2173`; declared required in `mx-agent-protocol/src/schema.rs:85`; promised in `docs/architecture.md:1654-1663` ("De-duplicate by idempotency key"); consumed nowhere.

**Conventions.** Secrets are wrapped in `Secret` (redacting `Debug`/`Display`); private files are `0600`, dirs `0700`, created atomically via `OpenOptionsExt::mode`. Health/status structs carry no secrets. No `unsafe`; MSRV 1.74; Unix-only `nix`/`rustix`. Human output by default, `--json` for automation. Tests use a per-test temp data dir and an env lock when mutating `MX_AGENT_DATA_DIR`.

## Proposed Implementation

Implement as nine focused, independently-testable changes. Order them so the lock/token/health primitives land first (1–3, 6), then the higher-level flows (4, 5, 7, 8), then 9.

### 1. Lock `trust.json` writes (no lost revocation)

Add a public, lock-holding mutation helper in `mx-agent-daemon` so the load-modify-save round trip happens under one lock acquisition, and expose it to the CLI without widening the carve-out or leaking the low-level lock primitive.

- In `trust.rs`, add:
  ```rust
  /// Load the trust store, apply `f`, and persist the result atomically — the
  /// whole round trip under the data-dir advisory write lock so concurrent
  /// `trust approve`/`trust revoke` invocations cannot lost-update (issue #316).
  pub fn update_trust_store<R>(
      paths: &SessionPaths,
      f: impl FnOnce(&mut TrustStore) -> R,
  ) -> io::Result<R>
  ```
  Implement it via `crate::session::with_data_dir_write_lock(paths, || { let mut store = TrustStore::load(paths)?; let r = f(&mut store); store.save(paths)?; Ok(r) })`. `TrustStore::save` must stay lock-free (it is) so there is no nested acquisition.
- Export `update_trust_store` from `lib.rs`.
- Rewrite CLI `trust_approve`/`trust_revoke` (`cli.rs`) to call `update_trust_store`, returning the resulting `TrustEntry` (or `None` for `revoke` of an unknown key) from the closure, instead of the current unlocked `load`/`save`. Daemon-side trust IPC paths that mutate the store should use the same helper.
- Keep `TrustStore::load` lock-free (reads tolerate a concurrent atomic rename).

### 2. Lock `clear_session` and clear the sync token on logout

- Wrap the body of `clear_session` (`session.rs:359-373`) in `with_data_dir_write_lock(paths, || { … })` so it serializes against `save_session` and `generate_crypto_store_key`. The closure error type is `io::Error`, matching the helper's `E: From<io::Error>`.
- Inside the locked body, after removing the device store / legacy store / session file, call `clear_sync_token(paths)` so logout also drops the persisted batch token. Keep idempotency (missing files are not errors).
- Update the existing `clear_session_*` unit tests to assert the sync token is gone after `clear_session`, and add a concurrency test (logout racing `save_session`) asserting a consistent end state (either fully logged out, or a complete session — never a torn/orphaned mix), mirroring `concurrent_save_session_never_tears`.

### 3. Clear the sync token on login identity change

- Add a daemon helper that the CLI calls instead of bare `save_session` after a successful login:
  ```rust
  /// Persist a freshly-minted login session, clearing the stale sync token when
  /// the session identity (user_id/device_id) differs from the previously stored
  /// one, so a new device performs an initial full sync (issue #316).
  pub fn persist_login_session(paths: &SessionPaths, session: &StoredSession) -> io::Result<()>
  ```
  Implement under the lock: load the prior session (if any); if absent or `(user_id, device_id)` differs, `clear_sync_token(paths)`; then `save_session`-equivalent write. Since every login mints a new `device_id`, this clears the token on essentially every real login while still being correct if the same identity is re-saved.
- Have CLI `auth_login` call `persist_login_session` (replacing the current `save_session` call at `cli.rs:~1681`).
- Keep the token at the data-dir root (no layout change). Note device-keying as an alternative in Open Questions.

### 4. Best-effort server-side logout

- Add a daemon helper:
  ```rust
  /// Best-effort server-side `/logout`, then clear all local session state.
  /// Returns whether the server-side call succeeded; a network/HTTP failure
  /// degrades to local-only logout (issue #316). Never logs or returns the token.
  pub async fn logout_session(paths: &SessionPaths) -> io::Result<LogoutOutcome>
  ```
  Where `LogoutOutcome { server_side: bool, .. }` carries only non-sensitive fields. Implementation: load the stored session; build a **store-less** client (`build_client`) and `restore_session` the tokens onto it (avoids racing a running daemon's SQLite OlmMachine — we only need an authenticated HTTP client for `/logout`); call `client.matrix_auth().logout()`; record success/failure (failure is logged non-sensitively, never with the token). **Regardless** of the result, call `clear_session(paths)` (which now also clears the sync token). If there is no stored session, treat as already-logged-out.
- Rewrite CLI `auth_logout` to run this on a current-thread Tokio runtime, print `mx-agent: logged out` (human) / `{"logged_in":false}` (`--json`), and additionally signal whether the server-side call succeeded (e.g. a one-line note in human mode and a `"server_side":true|false` field in JSON), without ever surfacing the token.
- Note: if a daemon is running, server-side logout makes its sync loop hit `UnknownToken` → fatal (now surfaced by item 6); document that re-login + `session.reload` is required to resume.

### 5. Clean up / warn about stranded per-device crypto stores on login

The hard constraint is the multi-user layout: device-id subdirs may belong to *different users* in one data dir (integration tests). A blanket "remove every dir that is not the new device" would delete a concurrent user's store. Therefore:

- In `persist_login_session` (item 3), after determining the prior stored session: if a prior session existed for the **same `user_id`** with a **different `device_id`**, remove that specific superseded device store (`<data_dir>/<old_device_id>`), guarded by `is_plain_path_component`. This precisely reclaims the superseded device of the same account without touching other users.
- Additionally, scan the data dir for device-store directories (a plain-component dir containing a `crypto-store/`) that match neither the new session's device nor any active session, and **warn** (non-sensitive: count and device-id stems) rather than auto-deleting, so an operator can reclaim them deliberately. Do not warn about `.login-*` temp dirs, the legacy flat `crypto-store/`, the lock file, or `trust.json`.
- Document the precise-removal vs warn-only split and the multi-user rationale in the function doc comment.

### 6. Surface sync-loop death in `daemon.status`; stop/degrade scheduler + heartbeat

Two sub-fixes plus a supervision change shared with item 7.

- **Persistence-error health.** In `run_sync_loop` (`sync.rs`), replace the bare `?` on `load_sync_token`/`save_sync_token` with handling that records fatal health before returning the error:
  ```rust
  let mut token = match load_sync_token(paths) {
      Ok(t) => t,
      Err(e) => { health.lock()…record_fatal(format!("sync token load failed: {e}")); return Err(e); }
  };
  // …and likewise around save_sync_token in the loop body.
  ```
  This makes the persistence-error exit visible as `SyncState::Stopped` and is directly unit-testable (force a token-file I/O error and assert `state == Stopped`).
- **Fatal-stop wind-down.** Make the sync thread, on **any** non-shutdown exit (fatal auth error or persistence error), flip a shared per-generation `running` flag false so the scheduler and heartbeat loops (which already watch that flag) wind down with it, leaving the daemon idle but alive (still serving IPC, ready for re-login + `session.reload`). Concretely: when `run_matrix_sync_with_subscribers` returns `Err`, or after a fatal exit, the sync thread clears the generation flag and ensures `record_fatal` is recorded.
- **Status surfacing.** `daemon.status` already serializes `SyncHealth`; once health reflects `Stopped`/`Degraded`, the CLI `daemon status` output (`cli.rs:3695-3704`) shows it. Add an explicit "unhealthy" signal: when `sync.state` is `Stopped` with a `last_error`, the CLI should render it prominently (and consider a non-zero exit for `--json` consumers — confirm in Open Questions whether to change the exit code).

### 7. `session.reload` IPC method + worker supervisor refactor

To let a post-start `auth login` start the workers and to support the fatal-stop/restart-generation model from item 6, lift worker state into a shared supervisor.

- Introduce a `WorkerSupervisor` owned by `run_foreground` and shared (`Arc`) with both the shutdown path and the IPC handler. It holds, behind a `Mutex`, the current generation's `running: Arc<AtomicBool>`, `health: SharedHealth`, and the three `JoinHandle`s, with methods:
  - `ensure_started()` — if no workers run and a session exists, spawn them (reuse `spawn_matrix_workers`), storing handles + health; no-op if already running or no session.
  - `reload()` — wind down the current generation (clear its flag, join handles, `clear_active_client`), then `ensure_started()` with a fresh generation/flag. Used by `session.reload` and on a fatal-stop recovery.
  - `health()` — current generation's `SharedHealth` for `daemon.status`.
- Change `dispatch`/`dispatch_streaming` to take the supervisor (reading `health()` live) instead of a fixed `SharedHealth` captured at startup, so status reflects a sync loop that started *after* daemon start.
- Add a `session.reload` arm to the dispatch table that calls `supervisor.reload()` and returns a small non-sensitive result (`{ "started": bool, "logged_in": bool }`).
- CLI: add `DaemonCommand::Reload` → `daemon reload` that sends `session.reload` over IPC; and have `auth_login`, after a successful `persist_login_session`, best-effort send `session.reload` to a running daemon (silently skip if no daemon is up — the next `daemon start` will pick up the session).
- On shutdown, `run_foreground` asks the supervisor to wind down whatever generation is current (replacing the hand-rolled join trio).

### 8. Reap in-flight exec child process groups on stop and restart

Children are in their own pgids and `kill_on_drop` does not fire on SIGKILL, so two mechanisms are needed:

- **Live pgid registry (in-memory).** Maintain a process-wide set of live exec child pgids (pgid == child pid). Register a child's pgid when `run_controlled_exec` (and the PTY path) spawns it; deregister on terminal exit (RAII guard, mirroring `InflightGuard`). On **graceful** SIGTERM shutdown (`run_foreground` after the signal, before/after winding down workers), `killpg(SIGTERM)` then `killpg(SIGKILL)` after a short grace over every registered pgid via the existing `terminate_process_group`/`kill_process_group`, so the common stop path leaves no orphans.
- **Persisted pgid records (for the SIGKILL escalation + restart).** When a live child starts, record its pgid in the invocation state (or a sidecar `live-pgids` file under the data dir, `0600`), and clear it on terminal exit. Then:
  - In `stop()` (`lifecycle.rs`), when the grace expires and the daemon must be SIGKILLed, after killing the daemon pid also read the persisted live pgids and `killpg(SIGKILL)` them (the daemon is being force-killed in the same breath, so the pgid-reuse window is negligible).
  - Add a **restart janitor**: on daemon startup, before/with the existing task reconcile, read any persisted live pgids left by a previous run, best-effort `killpg` any still-alive groups, mark the corresponding **bare (task-less)** invocation state as interrupted/failed (so it is not left dangling), and clear the records. Task-linked invocations continue to flow through `reconcile_executing_tasks`.
- Call out the **pgid-reuse caveat** (a pgid could be reused by an unrelated process after the original child dies and before the janitor runs) in Risks/Open Questions; mitigate by recording alongside the pgid a cheap liveness discriminator (e.g. the child's start time) and only killing when the discriminator still matches, or by preferring the graceful in-process teardown for the common case and treating the restart janitor as best-effort reconcile-first, kill-second.
- (Optional, non-blocking) the IPC server's detached per-connection threads (`ipc/server.rs:134-142`) have no drain; this does not orphan child processes and is out of scope for the acceptance criteria, but can be noted.

### 9. Consume `idempotency_key` (recommended) or remove it

Recommended: **consume** it as a de-dup index so the architecture's promise holds, since removing a required wire field (`schema.rs:85`) is a breaking protocol change.

- Validate on receipt that `idempotency_key == format!("exec:{invocation_id}")` (it is fully derived); treat a mismatch as a malformed request (rejection reason `malformed_request`), so the field cannot smuggle an out-of-band key.
- Before spawning a live exec (`handle_live_exec_request`/`spawn_authorized_live_exec`), de-duplicate: if an invocation with this key/`invocation_id` is already live in `LIVE_EXEC_CONTROLS`, or already has a terminal record in invocation state, do **not** spawn a second child — re-emit the existing `exec.accepted` (or surface the existing terminal result) instead. This delivers "De-duplicate by idempotency key" and "persist invocation state before starting the local child process; on restart, reconcile" without double-running a retried request.
- Add unit tests for the de-dup (a replayed exec request with the same key does not spawn twice) and the malformed-key rejection.
- If the owner instead chooses removal: drop `idempotency_key` from `schema.rs`, its construction sites, and fixtures, and correct `docs/architecture.md:1654-1663`. (Lower-preferred; documented as the alternative.)

## Affected Files / Crates / Modules

- `crates/mx-agent-daemon/src/trust.rs` — `update_trust_store`; trust-store tests.
- `crates/mx-agent-daemon/src/session.rs` — lock `clear_session`, clear sync token on logout, `persist_login_session`, stranded-store helper; tests.
- `crates/mx-agent-daemon/src/matrix.rs` — `logout_session`, store-less logout client; login-time stranded-store cleanup hook.
- `crates/mx-agent-daemon/src/sync.rs` — token-I/O health recording; fatal-stop wind-down.
- `crates/mx-agent-daemon/src/lifecycle.rs` — `WorkerSupervisor`, `session.reload` dispatch arm, status from live health, graceful-stop child teardown, `stop()` persisted-pgid reap, restart janitor wiring.
- `crates/mx-agent-daemon/src/runner.rs` — reuse `terminate_process_group`/`kill_process_group`; possibly a small helper for batch-killing a set of pgids.
- `crates/mx-agent-daemon/src/exec.rs` — live pgid registry + RAII guard; idempotency de-dup; pgid persistence on spawn/terminal.
- `crates/mx-agent-daemon/src/inflight.rs` — pattern reference for the pgid RAII guard.
- `crates/mx-agent-daemon/src/task_orchestrator.rs` / `scheduler_loop.rs` — bare-invocation janitor entry point on restart.
- `crates/mx-agent-daemon/src/lib.rs` — export `update_trust_store`, `persist_login_session`, `logout_session`, `LogoutOutcome`, any new reload helper.
- `crates/mx-agent-protocol/src/schema.rs` — only if removal is chosen for `idempotency_key` (otherwise unchanged).
- `crates/mx-agent-cli/src/cli.rs` — `trust_approve`/`trust_revoke` (locked), `auth_login` (`persist_login_session` + best-effort `session.reload`), `auth_logout` (server-side logout), `DaemonCommand::Reload`, status rendering of unhealthy sync.
- `docs/cli-reference.md` — `auth logout` behavior (`:425`), daemon-idle note (`:176`), new `daemon reload`.
- `docs/architecture.md` — `idempotency_key` section (`:1654-1663`) reconciled with the chosen behavior.
- Tests: `crates/mx-agent-daemon/tests/` (matrix-integration / live Tuwunel suites) for re-login full sync, server-side logout invalidation, post-start reload, orphan-free stop, dead-sync status.

## CLI / API Changes

- **New CLI subcommand:** `mx-agent daemon reload` — sends `session.reload`; human + `--json` output of `{ started, logged_in }`.
- **`mx-agent auth login`** — after persisting the session, best-effort sends `session.reload` to a running daemon so workers come up without a restart (silent no-op if no daemon).
- **`mx-agent auth logout`** — now attempts a best-effort server-side `/logout` before clearing local state; output gains a non-sensitive indication of whether the server-side call succeeded (`"server_side": bool` in `--json`). Never prints the token.
- **`mx-agent daemon status`** — renders a stopped/degraded sync loop prominently (and possibly a non-zero `--json` exit; see Open Questions).
- **New public daemon APIs** (documented): `update_trust_store`, `persist_login_session`, `logout_session` + `LogoutOutcome`, and any `WorkerSupervisor`/reload helper surfaced from `lib.rs`.
- **New IPC method:** `session.reload` (non-streaming), returning `{ "started": bool, "logged_in": bool }`.

## Data Model / Protocol Changes

- **No event-schema change** if `idempotency_key` is **consumed** (recommended). If removed instead, `ExecRequest.idempotency_key` is dropped from `mx-agent-protocol/src/schema.rs` and all fixtures — a breaking wire change requiring `docs/architecture.md` correction.
- **New IPC method** `session.reload` (additive; method-not-found on older daemons, which is acceptable for a local same-version socket).
- **Persistence additions** (no wire surface): the persisted live-pgid records (in invocation state or a `0600` sidecar `live-pgids` file under the data dir). The sync token continues to live at the data-dir root (no layout change); logout/identity-change now clear it.
- Trust-store JSON format is unchanged; only its write path gains the lock.

## Security Considerations

- **CLI/daemon separation & carve-out.** The trust lock must use the existing `with_data_dir_write_lock` via the new `update_trust_store` helper; do **not** export the raw lock primitive or let the CLI own any new credential surface. The CLI keeps only the documented auth/trust CLI-local writes. Server-side logout reads the stored token within that same auth carve-out.
- **No secrets in logs/output.** `logout_session` must never log or print the access/refresh token; build the logout client from `Secret`-wrapped tokens and surface only success/failure. Stranded-store warnings log device-id stems and counts only — no keys, no token. The persisted pgid sidecar contains only integers (pgids/timestamps), no secrets, and is `0600`.
- **Trust semantics unchanged.** Locking only serializes writers; deny-by-default, Ed25519 + local trust store as the authorization anchor, and "room membership is not execution permission" are untouched. A lost revocation is the bug being fixed.
- **Process-group killing.** `killpg` on a persisted pgid risks a pgid-reuse race; mitigate with a liveness discriminator and prefer reconcile-first on restart (see Open Questions). Never escalate to broader kills.
- **Crypto-store removal safety.** All device-dir removals stay guarded by `is_plain_path_component` so a server-assigned/garbage device id can never escape the data dir; login-time removal is scoped to the superseded device of the *same user* to avoid clobbering a concurrent user's store.
- **Unix-only, no `unsafe`, MSRV 1.74.** All new code uses `nix`/`rustix`/std as already in the crate; no Windows paths.
- **Status confidentiality.** `SyncHealth`/reload results carry no secrets; keep it that way.

## Testing Plan

**Unit tests (`#[cfg(test)]`, temp data dir):**
- `trust.rs`: two threads each running `update_trust_store` (one approve, one revoke of the same key) converge to a store where **both** updates are reflected — the revocation is never lost (mirror `concurrent_save_session_never_tears`). A single-thread round-trip test that `update_trust_store` persists.
- `session.rs`: `clear_session` removes the sync token; a logout-racing-`save_session` concurrency test ends in a consistent state (fully cleared or a complete session, never a torn/orphaned mix); `persist_login_session` clears the token when `(user_id, device_id)` changes and preserves it when identical; same-user prior-device store is removed, other-user store is preserved.
- `sync.rs`: forcing a `load_sync_token`/`save_sync_token` I/O error makes `run_sync_loop` record `SyncState::Stopped` (extend `loop_stops_on_fatal_error` style). A fatal exit clears the shared generation flag (assert the scheduler/heartbeat wind-down signal).
- `exec.rs`: a duplicate exec request with the same `idempotency_key`/`invocation_id` does not spawn a second child; a request whose `idempotency_key` ≠ `exec:{invocation_id}` is rejected `malformed_request`. Live-pgid RAII guard registers on spawn and deregisters on every terminal path.

**Integration tests (matrix-integration / daemon):**
- Re-login after logout performs an **initial full sync** — no stale batch token reuse — including a second login as a *different account* on the same data dir.
- `daemon stop` leaves **no orphaned exec children** (start a long-running live exec, stop the daemon, assert the child pgid is gone).
- `daemon.status` reports a **dead** sync loop (forced persistence error / revoked token) as `Stopped`/unhealthy rather than stale-healthy.
- Restart janitor: a bare (task-less) invocation left `running` by a killed daemon is reconciled (not left dangling) and any orphaned pgid is reaped.

**Live Tuwunel suite:**
- Server-side `logout_session` invalidates the old access token (a subsequent request with the old token is rejected by the homeserver).
- Post-start `auth login` + `session.reload` (or auto-reload) brings up sync/scheduler/heartbeat **without** a daemon restart; `daemon status` shows a healthy sync loop afterward.

**Gates:** `cargo fmt --check`, `cargo clippy -D warnings`, `cargo build`, and the full `cargo test` workspace suite stay green.

## Documentation Updates

- `docs/cli-reference.md:425` (`auth logout`) — describe best-effort server-side `/logout`, the local-only degrade on network failure, that the local `session.json`/sync token/crypto store are cleared, and that a running daemon's sync will go fatal until re-login + reload.
- `docs/cli-reference.md:176` — correct the "idles waiting for `auth login`" note: a post-start `auth login` now brings up sync/scheduler/heartbeat via `session.reload` (auto-invoked by `auth login`, or `daemon reload`) without a restart.
- `docs/cli-reference.md` — add a `daemon reload` entry.
- `docs/architecture.md:1654-1663` — reconcile the "De-duplicate by idempotency key" promise with the implemented behavior (de-dup index on receipt) — or, if removal is chosen, delete the `idempotency_key` line and field references.
- Doc-comment the new public APIs (`update_trust_store`, `persist_login_session`, `logout_session`, reload helper) and the multi-user rationale on the stranded-store cleanup.
- README/status-table: if any status table claims post-login auto-start or server-side logout, update it to match the implemented behavior (do not claim behavior not actually shipped).

## Risks and Open Questions

- **pgid reuse on the SIGKILL/restart path.** Killing a persisted pgid could hit an unrelated process if the pgid was reused. Mitigation options: store a liveness discriminator (child start time) and only kill on a match; or make the restart janitor reconcile-first (mark invocation interrupted) and kill best-effort. **Decision needed:** is the in-process graceful SIGTERM teardown sufficient for the acceptance criterion, with the SIGKILL-path reap treated as best-effort? (Recommend: yes — graceful path is authoritative; restart janitor is best-effort with a discriminator.)
- **Worker-supervisor refactor scope.** Lifting `SharedHealth` into a `WorkerSupervisor` touches `dispatch`/`dispatch_streaming` signatures and `run_foreground`. This is the largest change; confirm it is acceptable versus the lighter "lazy-start on first authenticated request" alternative (less explicit, racier — not recommended).
- **Stopping vs degrading scheduler/heartbeat on fatal sync.** The spec recommends winding them down (daemon idles, still serves IPC, recovers via reload). Confirm this is preferred over leaving them running in a "degraded" state. (Recommend: wind down — sends on a dead token fail anyway.)
- **idempotency_key consume vs remove.** Recommend consume (avoids a breaking wire change and fulfills the documented promise). Confirm the owner agrees, or choose removal + doc correction.
- **`daemon status` exit code.** Should `--json daemon status` exit non-zero when sync is `Stopped`/unhealthy? This changes automation contracts; confirm before adding.
- **Sync token: clear-on-change vs device-keying.** Recommend clear-on-change (no migration). Device-keying is more robust against future layouts but invasive; left as an alternative.
- **Server-side logout while daemon is running.** The store-less logout client avoids the SQLite race, but the running daemon's token dies immediately; documented as expected, recovered via re-login + reload.
- **Stranded-store auto-removal breadth.** Auto-removal is scoped to the superseded same-user device to protect multi-user test layouts; broader cleanup is warn-only. Confirm this is the desired safety/automation balance.

## Implementation Checklist

1. **Trust lock:** add `update_trust_store(paths, f)` in `trust.rs` (loads/saves under `with_data_dir_write_lock`); export from `lib.rs`; rewrite CLI `trust_approve`/`trust_revoke` and any daemon trust-mutation path to use it. Add the concurrent approve/revoke "no lost revocation" test.
2. **Lock + token on logout:** wrap `clear_session` in the data-dir lock and call `clear_sync_token` inside it; update/add tests (token cleared, logout-vs-save race consistent).
3. **Login token clearing:** add `persist_login_session` (clear sync token on identity change, under the lock); switch CLI `auth_login` to it; add tests.
4. **Server-side logout:** add `logout_session` + `LogoutOutcome` (store-less client, best-effort `/logout`, then `clear_session`, no token in logs); rewrite CLI `auth_logout`; export from `lib.rs`.
5. **Stranded stores:** in `persist_login_session`, remove the superseded same-user device store (guarded by `is_plain_path_component`) and warn (non-sensitively) about other stranded device dirs; document the multi-user rationale; add tests.
6. **Sync health on persistence error:** record `record_fatal` before the token-I/O early returns in `run_sync_loop`; add a forced-I/O-error unit test asserting `Stopped`.
7. **Fatal-stop wind-down:** on non-shutdown sync exit, clear the shared generation flag so scheduler/heartbeat wind down; ensure `record_fatal` is recorded.
8. **Worker supervisor + reload:** introduce `WorkerSupervisor` (running flag + health + handles, `ensure_started`/`reload`/`health`); route `daemon.status` through live `health()`; add the `session.reload` dispatch arm; add `DaemonCommand::Reload` and best-effort auto-reload from `auth_login`; wire shutdown through the supervisor.
9. **Live pgid registry + graceful teardown:** register/deregister child pgids (RAII guard) in the live exec/PTY spawn paths; on graceful SIGTERM shutdown, SIGTERM-then-SIGKILL all registered pgids via `terminate_process_group`/`kill_process_group`.
10. **Persisted pgid reap + restart janitor:** persist live pgids (`0600` sidecar or invocation state) on spawn, clear on terminal exit; reap them in `stop()`'s SIGKILL escalation; add a restart janitor that reaps stale pgids and reconciles bare (task-less) invocation state; add the pgid-reuse discriminator.
11. **idempotency_key:** validate `== exec:{invocation_id}` (else `malformed_request`) and de-duplicate before spawning a live exec (re-emit existing accepted/result rather than double-running); add tests. (Or, if removing: drop the field + fixtures and fix `docs/architecture.md`.)
12. **Docs:** update `docs/cli-reference.md` (`:176`, `:425`, new `daemon reload`), `docs/architecture.md:1654-1663`, README/status table; doc-comment all new public APIs.
13. **Integration + live tests:** re-login full sync (incl. across accounts), orphan-free `daemon stop`, dead-sync `daemon.status`, server-side logout invalidation, post-start reload without restart.
14. **Gates:** `cargo fmt --check`, `cargo clippy -D warnings`, `cargo build`, full `cargo test` all green.
