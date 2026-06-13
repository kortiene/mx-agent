# Replay Protection Fails Closed; Exec Control Frames Replay-Checked (issue #305)

## Problem Statement

`ReplayCache` is the only component that both enforces nonce single-use **and**
checks `expires_at` against the wall clock
(`crates/mx-agent-daemon/src/replay.rs:159-190`). It is solid in isolation
(side-effect-free denials, expiry prune on load, atomic `0600` persistence), but
the surrounding wiring lets privileged actions through when the cache is
unavailable, and never replay-checks live exec control frames. Five concrete gaps
(found by the 2026-06-11 feature-completeness re-assessment at HEAD `a7680e8`,
follow-up to epic #274; `priority:p1`):

1. **Cache-less scheduler pass admits everything.** The live scheduler attaches
   the cache best-effort: `ReplayCache::load(paths).ok()`
   (`scheduler_loop.rs:591`). On any IO load error the pass runs cache-less, and
   both consumers treat "no cache" as *admit*:
   `admit_task_action_replay` returns `Ok(())` with no cache
   (`task_orchestrator.rs:943-945`) and `QueueApprovalGate::admit_decision_nonce`
   returns `true` with no cache ("signature alone gates the release",
   `task_orchestrator.rs:1530-1533`). Task-action replay checking becomes a no-op
   and an approving decision releases a held task with no nonce burn and no expiry
   check. The sync-loop router already does the right thing here — on cache-load
   failure it logs and routes nothing (`sync.rs:290-299`) — so the scheduler
   `.ok()` is an inconsistency, not a design. **Amplifier:** approval request ids
   are deterministic (`format!("approval:{}", task.task_id)`,
   `task_orchestrator.rs:1356`) and decisions are matched by `request_id` within a
   100-event scan window (`scheduler_loop.rs:65`,
   `APPROVAL_DECISIONS_SCAN_LIMIT`), so on the cache-less path an old
   validly-signed approved decision re-releases any *future* hold for the same
   task. The only clock comparison on decisions lives in `ReplayCache::admit_at`;
   `decision_permits_spawn` checks only the decision string (`approval.rs:408-410`)
   and `verification_failure` checks field presence only (`approval.rs:534-556`).

2. **Corrupt cache silently resets.** `load_with_capacity` deserializes a
   corrupt/truncated file to an **empty** cache with no log:
   `serde_json::from_slice(...).unwrap_or_else(|_| empty)` (`replay.rs:99-105`).
   `load()` returns `Ok` with every previously burned nonce forgotten and no
   operator-visible signal. This affects *every* caller — including the
   otherwise-fail-closed sync router — and the next `persist()` overwrites the
   corrupt bytes, destroying forensic evidence.

3. **Exec control frames are never replay-checked.** `ExecStdin` / `ExecCancel` /
   `PtyResize` carry a signed `nonce`
   (`crates/mx-agent-protocol/src/schema.rs:151`, `:169`, `:273`) but the router's
   replay step extracts replay material only for `ExecRequest` / `CallRequest` —
   the explicit `_ => None` excludes everything else
   (`event_router.rs:344-353`). `LiveExecControl` holds no seen-nonce set or
   sequence counter (`exec.rs:67-75`). Bounded impact: an actor with room access
   can re-deliver already-authorized bytes into a **still-live** session
   (duplicate stdin line, premature EOF, resize flapping). Once the session ends
   the control entry is removed (`remove_live_exec_control`,
   `exec.rs:90-95`) and a later replay is dropped at the `live_exec_control() =>
   None` guard, so the replay window is the session lifetime only.

4. **Burn-before-claim wedges on a benign race.** The action nonce is admitted at
   `task_orchestrator.rs:491` **before** the optimistic claim at `:500`. A benign
   `StaleClaim` (`:510-514`, the store saw a newer `state_rev`) never un-burns it,
   so the *next* pass hits `Replayed` in `admit_task_action_replay` and finalizes
   the task `blocked` (`block_unauthorized`, `:966-1001`). For approval-gated
   tasks the gate burns the decision nonce even earlier (resolve at `:487` →
   `admit_decision_nonce` at `:1473`/`:1530`), so the same race consumes the
   operator's single-use approval and the task hangs `Pending` forever (the next
   pass re-burns → `Replayed` → fail-closed to `Pending`,
   `task_orchestrator.rs:1473-1479`).

## Goals

- The scheduler **fails closed** on a replay-cache load error: skip
  claim/dispatch/approval-release for the pass with a loud, non-sensitive log,
  matching the sync router (`sync.rs:290-299`). Sync/health tracking is
  unaffected.
- A corrupt/truncated `replay_cache.json` **never** silently yields an empty
  cache; forgetting burned nonces requires an operator-visible error, and the
  corrupt bytes are preserved (not overwritten) for inspection.
- No production code path admits a privileged task action or releases a held
  approval **without** a replay cache: the cache-less `admit` branches become
  reachable only from the pure-core unit tests.
- A re-delivered `exec.stdin` / `exec.cancel` / `pty.resize` frame carrying a
  previously seen nonce is **dropped, observably**, for the duration of the live
  session.
- A benign `StaleClaim` race leaves the task **runnable** on the next pass and
  does **not** consume the action nonce or the approval decision's nonce.
- Unit tests cover all four failure modes; the live Tuwunel suite stays green;
  `cargo fmt --check`, `cargo clippy -D warnings`, build, and tests stay green.

## Non-Goals

- Signing or sender-pinning the *result* plane — that is issue #304 (already
  landed: §1.2, `sync.rs:461-489`). This spec only authenticates replay/expiry on
  the request and control planes.
- Pinning the heartbeat sender (issue #312) or any other liveness signal.
- Changing the replay cache's on-disk format, capacity policy, or eviction
  strategy (`replay.rs:172-190`); the format stays backward-compatible.
- Adding an `expires_at` field to the control-frame schemas, or any other
  protocol/Matrix event-type change. The fix uses the `nonce` already present.
- Re-deriving distinct CLI exit codes for replay/expiry denials (the existing
  `128`/blocked-state surfacing is retained).
- Persisting control-frame replay state across daemon restarts — a restart kills
  every live session (`LIVE_EXEC_CONTROLS` is in-memory), so a post-restart
  control replay is already dropped at the no-live-control guard.

## Relevant Repository Context

- **Workspace / crates.** Rust Cargo workspace, MSRV 1.74, `unsafe_code =
  "forbid"`, `missing_docs = "warn"` (warnings are errors in CI). Owning crate for
  all changes here is **`mx-agent-daemon`**; the control-frame nonces already
  exist in **`mx-agent-protocol`** so no protocol crate change is required.
- **Replay cache** (`crates/mx-agent-daemon/src/replay.rs`). `ReplayCache::admit`
  / `admit_at` are side-effect-free on denial, prune expired entries, evict
  soonest-to-expire when full, and persist atomically with `0600`. `ReplayError`
  has `Expired | Replayed | MalformedTimestamp | Io(io::ErrorKind)`. `load` ->
  `load_with_capacity` is the only place a corrupt file is tolerated
  (`:99-105`). `parse_rfc3339_to_unix` is `pub(crate)` and is the single shared
  RFC 3339 parser.
- **Event router** (`crates/mx-agent-daemon/src/event_router.rs`). The first gate
  for every synced event: classify → parse → (privileged) replay-check →
  dispatch, **no side effects** beyond the replay cache. `EventCategory::is_privileged()`
  already returns `true` for `ExecStdin`/`ExecCancel`/`PtyResize`
  (`:168-176`), but the replay-material extraction (`:344-348`) only covers
  `ExecRequest`/`CallRequest`. The router holds **one** `ReplayCache`
  (`EventRouter { replay }`, `:301-310`).
- **Live exec controls** (`crates/mx-agent-daemon/src/exec.rs`).
  `LiveExecControl { requester_agent, stdin, cancel, resize }` is stored in a
  process-global `Mutex<HashMap<String, LiveExecControl>>` keyed by
  `invocation_id`; handler lookups return a **clone** (`live_exec_control`,
  `:97-103`). `authorize_live_control` → `authorize_control_from_states`
  (`:819-865`) verifies signature → key-match → trust → requester ownership for
  every control frame. The three handlers are `handle_live_exec_stdin`
  (`:732-772`), `handle_live_exec_cancel` (`:775-802`), and
  `handle_live_pty_resize` (`exec.rs`, dispatched from `sync.rs:412-421`).
- **Scheduler loop** (`crates/mx-agent-daemon/src/scheduler_loop.rs`).
  `scheduler_pass_for_agent` (`:560-…`) loads policy/trust/replay per owned agent
  per pass, builds the orchestrator via `build_scheduler_orchestrator`
  (`:532-557`, `pub(crate)`, takes `replay: Option<ReplayCache>`), then attaches a
  `QueueApprovalGate` sharing the orchestrator's replay handle
  (`replay_cache_handle()`, `:619`). This is the **only production constructor**
  of a replay-configured orchestrator; tests build `TaskOrchestrator` directly.
- **Task orchestrator** (`crates/mx-agent-daemon/src/task_orchestrator.rs`).
  `run_one` order: `verify_task_action_authorization` (idempotent, no side
  effects) → `authorize_task_action` (policy → `Allowance`) → `resolve_approval`
  (only when `requires_approval`; the gate burns the decision nonce on an
  approving pass) → `admit_task_action_replay` (burns the action nonce) → `claim`
  → dispatch → finalize. `replay_cache: Option<Rc<RefCell<ReplayCache>>>`,
  `approval_gate: Option<RefCell<Box<dyn TaskApprovalGate>>>`. `TaskApprovalGate`
  is a one-method trait (`evaluate`). `ApprovalDisposition` =
  `Approved | Denied | Pending | Expired`.
- **Conventions.** Deny-by-default everywhere; room membership never implies
  execution (architecture §1.2). Log only non-sensitive metadata — **never**
  nonces or signed payloads (architecture §13.6; `sync.rs:369-375` is the model
  for a replay-rejection log). Unix-only; no `unsafe`. Document new public items.

## Proposed Implementation

### A. Replay cache: corrupt-file fail-closed + an un-burn primitive (`replay.rs`)

1. **New error variant.** Add `ReplayError::Corrupt` and render it in `Display`
   (e.g. `"replay cache file is corrupt"`). It is produced **only** by `load`.

2. **Fail closed on parse corruption.** In `load_with_capacity`, replace the
   `serde_json::from_slice(...).unwrap_or_else(|_| empty)` fallback (`:101-105`)
   with an explicit error:
   ```rust
   Ok(bytes) => {
       let stored: StoredCache = match serde_json::from_slice(&bytes) {
           Ok(stored) => stored,
           Err(_) => {
               // Do NOT silently reset to an empty cache: that would forget
               // every burned nonce with no operator-visible signal. Preserve
               // the corrupt bytes for inspection and fail closed; callers
               // (router, scheduler) then skip routing/dispatch for this pass.
               quarantine_corrupt(&path); // best-effort rename; never panics
               tracing::error!(
                   path = %path.display(),
                   "replay cache file is corrupt; refusing to admit (fail closed). \
                    Move the quarantined file aside to reset replay protection."
               );
               return Err(ReplayError::Corrupt);
           }
       };
       Self { path, capacity: stored.capacity.max(1), nonces: stored.nonces }
   }
   ```
   - `quarantine_corrupt` renames `replay_cache.json` to a sibling
     `replay_cache.json.corrupt` (best-effort; log at `debug` on failure, never
     panic, never log file contents). Renaming — rather than the previous
     silent overwrite-on-next-persist — preserves the corrupt bytes and means a
     subsequent load finds `NotFound` only after an operator/the rename has moved
     the bad file aside. **Do not auto-continue with an empty cache after
     quarantine**: that would reintroduce a (one-log-line) silent reset. The
     daemon stays fail-closed until the operator clears the file. (See Risks for
     the rejected auto-reset alternative.)
   - Log **no** nonce material — only the path.

3. **Un-burn primitive for claim compensation.** Add:
   ```rust
   /// Remove a previously admitted nonce, persisting the change. A no-op (still
   /// `Ok`) when the nonce is absent. Used to compensate a lost optimistic-claim
   /// race so a single-use nonce is not permanently consumed for an action that
   /// never executed.
   pub fn forget(&mut self, nonce: &str) -> Result<(), ReplayError> {
       if self.nonces.remove(nonce).is_some() {
           self.persist()?;
       }
       Ok(())
   }
   ```
   Document the safety invariant: `forget` is only ever called on a nonce whose
   action **did not execute** (claim failed before dispatch), so it cannot enable
   a real replay.

### B. Scheduler: fail closed on load error; require a cache by construction (`scheduler_loop.rs`)

1. **Load-or-skip helper (testable seam).** Extract the per-pass load into a
   small free function so the fail-closed decision is unit-testable without a
   live `matrix_sdk::Room`:
   ```rust
   /// Load the replay cache for a scheduler pass, or `None` to skip the pass.
   /// A load error (IO or corruption) is logged loudly and fails closed: the
   /// caller must not claim/dispatch/release without replay protection.
   fn load_pass_replay_cache(paths: &SessionPaths) -> Option<ReplayCache> {
       match ReplayCache::load(paths) {
           Ok(cache) => Some(cache),
           Err(e) => {
               tracing::error!(
                   error = %e,
                   "could not load replay cache; skipping scheduler pass \
                    (no claim, dispatch, or approval release this pass)"
               );
               None
           }
       }
   }
   ```

2. **Honor it in `scheduler_pass_for_agent`.** Replace `let replay =
   ReplayCache::load(paths).ok();` (`:591`) with an early return:
   ```rust
   let Some(replay) = load_pass_replay_cache(paths) else { return; };
   ```
   Because every owned agent in the pass loads the same shared cache file, a
   persistent load error skips them all — equivalent to skipping the whole pass —
   while the `/sync` health loop (separate, `sync.rs`) keeps running.

3. **Require a cache by construction.** Change `build_scheduler_orchestrator`'s
   parameter from `replay: Option<ReplayCache>` to `replay: ReplayCache` and call
   `orchestrator.with_replay_cache(replay)` unconditionally (drop the
   `if let Some(replay)` at `:550-552`). The approval gate continues to take
   `orchestrator.replay_cache_handle()` (`:619`), which is now always `Some`. This
   makes it impossible to construct the production orchestrator/gate cache-less.

### C. Keep the cache-less admit branches test-only (`task_orchestrator.rs`)

With **B**, production never reaches the `None` branches in
`admit_task_action_replay` (`:943-945`) and `admit_decision_nonce` (`:1530-1533`).
Keep both branches for the pure-core unit tests (which deliberately run the
orchestrator without a cache), but tighten their docs to state they are
*test-only; production constructs via `build_scheduler_orchestrator`, which
requires a cache*. No behavioral change here beyond the doc clarification — the
guarantee is enforced upstream by the non-`Option` builder signature. Add the new
`ReplayError::Corrupt => "replay_cache_corrupt"` arm to the reason mapping in
`admit_task_action_replay` (`:955-960`) so the match stays exhaustive (it cannot
actually fire from `admit`, but the type now has the variant).

### D. Replay-check live control frames (per-session seen-nonce set) (`exec.rs`)

Use **per-session** dedup rather than the router's persistent cache. Rationale:
an interactive PTY emits a control frame per keystroke; burning each into the
single bounded (8192-entry, soonest-expiry-evicted) request-plane cache would
thrash the persisted file and **evict legitimate `exec.request`/`call.request`
nonces**, weakening request-plane protection. A per-session set scopes dedup to
the live invocation, needs no `expires_at`, and is freed when the session ends.

1. **Add a shared seen-set to `LiveExecControl`** (`exec.rs:67-75`). Because
   handlers operate on a **clone** of the control, the set must be shared:
   ```rust
   struct LiveExecControl {
       requester_agent: String,
       stdin: tokio::sync::mpsc::Sender<StdinFrame>,
       cancel: tokio::sync::watch::Sender<Option<String>>,
       resize: Option<tokio::sync::mpsc::Sender<PtyWinsize>>,
       /// Nonces of control frames already applied to this live session. Shared
       /// across clones so a re-delivered (replayed) frame is dropped.
       seen_control_nonces: Arc<Mutex<HashSet<String>>>,
   }
   ```
   Initialize it (`Arc::new(Mutex::new(HashSet::new()))`) wherever
   `LiveExecControl` is constructed and inserted (`insert_live_exec_control`
   call sites). `Arc`/`Mutex` are already in scope via `std::sync`.

2. **Check-and-record after authorization, side-effect-free on denial.** Add a
   helper and call it in all three handlers *after*
   `authorize_live_control(...).is_ok()` and before applying the frame:
   ```rust
   /// Returns `true` if `nonce` is fresh for this live session (and records it);
   /// `false` if it was already seen (a replay). Only authorized frames reach
   /// here, so an attacker cannot pre-seed the set.
   fn admit_control_nonce(control: &LiveExecControl, nonce: &str) -> bool {
       control
           .seen_control_nonces
           .lock()
           .unwrap_or_else(|e| e.into_inner())
           .insert(nonce.to_string())
   }
   ```
   In each handler:
   ```rust
   if !admit_control_nonce(&control, &stdin.nonce) {   // / &cancel.nonce / &resize.nonce
       tracing::warn!(
           invocation_id = %stdin.invocation_id,
           "dropped replayed exec control frame (nonce already seen this session)"
       );
       return;
   }
   ```
   Record **only** authorized frames (authorize first, then admit-nonce) so a
   denied frame leaves the set unchanged — mirroring the replay cache's
   side-effect-free denials. The frame is applied (write stdin / signal cancel /
   resize) only on a fresh nonce.

3. **No router change strictly required**, but leave a one-line comment at
   `event_router.rs:344-348` noting that control-frame replay is enforced
   per-session in the live handlers (so a future reader doesn't "fix" the
   `_ => None` by routing control nonces into the shared cache).

### E. Compensate the lost claim race so nonces aren't wedged (`task_orchestrator.rs`)

Recommended approach: **un-burn on `StaleClaim`** (symmetric for both nonces;
preserves the "approval is consulted only when about to run" ordering; avoids the
post-claim `state_rev` complications of a claim-first reorder — see Risks).

1. **Gate compensation hook.** Extend the trait with a default no-op so existing
   gates/tests are unaffected:
   ```rust
   pub trait TaskApprovalGate {
       fn evaluate(&mut self, task: &TaskState, action: &TaskAction) -> ApprovalDisposition;
       /// Un-burn the decision nonce consumed by the most recent `Approved`
       /// evaluation, compensating a lost optimistic-claim race. Default: no-op.
       fn compensate_lost_claim(&mut self) {}
   }
   ```

2. **`QueueApprovalGate` records and un-burns its last-admitted nonce.** Add a
   field `last_admitted_decision_nonce: Option<String>`. In `admit_decision_nonce`
   record the nonce on a successful admit; implement `compensate_lost_claim` to
   `forget` it from the shared replay cache and clear the record:
   ```rust
   fn compensate_lost_claim(&mut self) {
       if let (Some(cache), Some(nonce)) =
           (&self.replay_cache, self.last_admitted_decision_nonce.take())
       {
           let _ = cache.borrow_mut().forget(&nonce);
       }
   }
   ```

3. **`run_one` un-burns on the `StaleClaim` arm** (`:510-514`):
   ```rust
   Err(TaskStoreError::StaleClaim { .. }) => {
       // Benign optimistic-concurrency race: the task advanced since we read
       // it. Un-burn the single-use nonces this pass consumed *before* the
       // claim so the next pass retries cleanly instead of wedging (the action
       // finalized `blocked`, or an approval-gated task hung `Pending`). The
       // winning daemon burns its own copies in its own cache, so single-use
       // is preserved; we never executed, so un-burning cannot enable a replay.
       if let (Some(cache), Some(auth)) = (&self.replay_cache, action.authorization()) {
           let _ = cache.borrow_mut().forget(&auth.nonce);
       }
       if let Some(gate) = &self.approval_gate {
           gate.borrow_mut().compensate_lost_claim();
       }
       return OrchestrationOutcome::StaleClaim { task_id: task.task_id.clone() };
   }
   ```
   `compensate_lost_claim` is a no-op when the gate burned nothing (non-approval
   task, or the gate returned `Pending`/`Denied`/`Expired`), so it is always safe
   to call here.

## Affected Files / Crates / Modules

- `crates/mx-agent-daemon/src/replay.rs` — `ReplayError::Corrupt`,
  `Display` arm, fail-closed corrupt-file handling + `quarantine_corrupt`,
  `forget`, tests.
- `crates/mx-agent-daemon/src/scheduler_loop.rs` — `load_pass_replay_cache`
  helper, early-return at `:591`, `build_scheduler_orchestrator` signature
  (`Option<ReplayCache>` → `ReplayCache`) and call site.
- `crates/mx-agent-daemon/src/task_orchestrator.rs` — `TaskApprovalGate`
  compensation hook, `QueueApprovalGate` last-nonce field +
  `compensate_lost_claim`, `run_one` `StaleClaim` arm, exhaustive `ReplayError`
  match + doc tightening on the cache-less branches, tests.
- `crates/mx-agent-daemon/src/exec.rs` — `LiveExecControl.seen_control_nonces`,
  `admit_control_nonce`, calls in `handle_live_exec_stdin` /
  `handle_live_exec_cancel` / `handle_live_pty_resize`, construction sites, tests.
- `crates/mx-agent-daemon/src/event_router.rs` — clarifying comment only
  (`:344-348`).
- **Read for context (no change expected):** `sync.rs` (the fail-closed router
  pattern + control-frame dispatch `:381-458`), `approval.rs`
  (`read_verified_approval_decisions`, `decision_permits_spawn`),
  `crates/mx-agent-protocol/src/schema.rs` (`ExecStdin`/`ExecCancel`/`PtyResize`
  carry `nonce`).
- **Docs:** `docs/architecture.md` §7.7 (resize replay), §9.2 (replay
  fail-closed), §10.1 (router note); `README.md` security-posture bullet if
  re-worded.

## CLI / API Changes

None to the CLI surface. New **public Rust items** in `mx-agent-daemon`
(documented per `missing_docs`): `ReplayError::Corrupt`, `ReplayCache::forget`,
and the `TaskApprovalGate::compensate_lost_claim` trait method. No IPC method,
JSON-RPC param, or exit-code change.

## Data Model / Protocol Changes

None to the Matrix event schema — `ExecStdin`/`ExecCancel`/`PtyResize` already
carry the `nonce` used for per-session dedup. The replay cache's on-disk
`StoredCache` format (`{capacity, nonces}`) is unchanged and remains
backward-compatible; a corrupt file is now renamed to
`replay_cache.json.corrupt` instead of being silently overwritten. The
per-session seen-nonce set is in-memory only (not persisted, not synced).

## Security Considerations

- **Deny-by-default / fail-closed.** Every changed path moves from fail-open to
  fail-closed: a missing/corrupt cache skips the scheduler pass; an unauthorized
  or replayed control frame is dropped; a lost claim retries without consuming
  single-use material. Room membership still never implies execution
  (architecture §1.2).
- **Approval integrity across restart and corruption.** Item B closes the
  amplifier where an old validly-signed approved decision (deterministic
  `approval:<task_id>` request id, 100-event scan window) could re-release a
  future hold on the cache-less path. After this change a release always burns
  the decision nonce against a live cache or is skipped.
- **Un-burn cannot enable a replay.** `forget` is reached only from the
  `StaleClaim` arm, i.e. for an action that **did not dispatch**. The winning
  daemon burns its own nonces in its own per-daemon cache; single-use is a
  per-execution property, so un-burning a non-executed action is correct.
- **Control-frame dedup is authorization-gated.** Nonces are recorded only for
  frames that already pass signature → trust → ownership
  (`authorize_control_from_states`), so an attacker cannot pre-seed the
  seen-set to block a legitimate requester's future (random) nonce.
- **No secrets in logs.** Corrupt-cache, skipped-pass, dropped-frame, and
  un-burn logs carry only paths/ids/reasons — never nonces, signatures, or signed
  payloads (architecture §13.6). `quarantine_corrupt` logs a path, never file
  contents.
- **Unix-only, no `unsafe`.** `forget`/`quarantine_corrupt` use the same
  `std::fs` + `0600`/`0700` patterns already in `replay.rs`; the seen-set uses
  `std::sync` only. MSRV 1.74 preserved (no APIs newer than 1.74).
- **Bounded memory.** The per-session seen-set grows only with distinct
  control frames in one live invocation and is dropped at
  `remove_live_exec_control`. (If a pathologically long interactive session is a
  concern, an optional cap is noted under Open Questions.)

## Testing Plan

Add focused `#[cfg(test)]` unit tests (no homeserver) covering each failure mode;
reuse the existing `replay.rs` `TempData` harness and the `task_orchestrator.rs`
mock-store / `replay_cache(name)` helpers.

- **`replay.rs`**
  - `corrupt_file_fails_closed`: write non-JSON / truncated bytes to
    `replay_cache.json`; assert `ReplayCache::load` returns `Err(Corrupt)`.
  - `corrupt_file_is_quarantined_not_overwritten`: after the failed load, assert
    the original bytes survive at `replay_cache.json.corrupt` and the daemon did
    not write an empty cache over them.
  - `load_io_error_surfaces_err`: trigger the non-`NotFound` IO branch (e.g. make
    `data_dir/replay_cache.json` a directory) and assert `Err(Io(..))`.
  - `forget_removes_and_persists`: admit a nonce, `forget` it, reload, assert it
    is admissible again; `forget` of an absent nonce is `Ok` and a no-op.
- **`scheduler_loop.rs`**
  - `load_pass_replay_cache_skips_on_corrupt`: corrupt file → `None`; good/absent
    file → `Some`. (Directly exercises the fail-closed "skip the pass" decision.)
  - Confirm `build_scheduler_orchestrator` requires a `ReplayCache` (compile-time;
    update existing callers/tests to pass a real cache).
- **`exec.rs`**
  - `replayed_control_nonce_is_dropped`: build a `LiveExecControl`, call
    `admit_control_nonce` with the same nonce twice → `true` then `false`;
    distinct nonces → both `true`. (Pure seam; no `Room` needed.)
  - If feasible without a live `Room`, a focused test that
    `handle_live_exec_stdin` applies the first frame and drops a re-delivered one;
    otherwise cover via the seam above + the live suite.
- **`task_orchestrator.rs`**
  - `stale_claim_does_not_consume_action_nonce`: orchestrator with a replay cache
    + a mock store whose `claim` returns `StaleClaim`; assert the action nonce is
    still admissible afterward and a second `run_one` against a non-stale store
    succeeds (task reaches a terminal/executing state, not `blocked`).
  - `stale_claim_does_not_consume_approval_nonce`: same with a `QueueApprovalGate`
    (or a fake gate that records `compensate_lost_claim`) approving the action;
    assert the decision nonce is un-burned and the next pass releases the task.
- **Live Tuwunel suite (`scripts/matrix_integration_test.sh`).** Keep green; if a
  scheduler/approval scenario already runs there, extend it to assert a held
  approval still releases after a benign re-read, but no new live test is strictly
  required by the acceptance criteria.

## Documentation Updates

- **`docs/architecture.md` §7.7 (Terminal Resize).** Currently states resize "is
  not router replay/expiry-checked; a replayed resize at most re-applies the same
  dimensions." Update to: resize (like `exec.stdin`/`exec.cancel`) is
  **per-session replay-checked** — a re-delivered frame with a seen nonce is
  dropped.
- **`docs/architecture.md` §9.2 / §10.1.** Note that the scheduler and router
  both **fail closed** on replay-cache load/parse errors (skip the pass / route
  nothing), and that live exec control frames are replay-checked per session.
- **`README.md`.** The security-posture bullet ("request types that carry
  nonce/expiry fields are also replay/expiry checked") may be extended to mention
  live control frames are replay-checked per session and that replay protection
  fails closed. Keep claims accurate — do not imply persisted/cross-restart
  control-frame replay state (there is none).
- **Rustdoc** on `ReplayCache::forget`, `ReplayError::Corrupt`,
  `TaskApprovalGate::compensate_lost_claim`, and `admit_control_nonce` (required
  by `missing_docs`).

## Risks and Open Questions

- **Corrupt-cache wedge vs. self-heal.** The recommended design keeps the daemon
  fail-closed until an operator moves the corrupt file aside. The rejected
  alternative — quarantine then continue with a fresh empty cache — trades the
  wedge for a one-time loud reset but reintroduces a (logged) "forget all burned
  nonces" event an attacker could trigger by corrupting the file. Confirm
  fail-closed-until-operator is the desired posture (the acceptance criterion
  "forgetting burned nonces requires an operator-visible error" is satisfied
  either way; the wedge is strictly safer).
- **Claim-first vs. un-burn for item E.** A claim-first reorder (burn *after* a
  successful claim) avoids un-burn for the action nonce, but (a) a post-claim
  `admit` failure would need to finalize with the **claimed** `state_rev` (not the
  pre-claim `task.state_rev` that `block_unauthorized` uses today, `:989`),
  complicating that path, and (b) the decision nonce is burned inside the gate
  *before* the claim, so it would still need either a gate refactor or
  compensation. The un-burn approach is uniform for both nonces with less churn;
  this spec recommends it. Flag if a reorder is preferred for clarity.
- **Per-session set growth.** Unbounded per long interactive session (one entry
  per distinct control nonce). Freed at session end. Optional hardening: cap the
  set (e.g. last N nonces) or add a `created_at + TTL` staleness reject using the
  existing `parse_rfc3339_to_unix`; deferred unless a concrete DoS concern is
  raised.
- **`build_scheduler_orchestrator` callers.** Changing the signature to a
  non-`Option` cache touches existing tests/call sites in `scheduler_loop.rs` —
  update them to pass a real (temp-dir-backed) cache.
- **Shared cache file, multiple owned agents.** Each owned agent loads its own
  in-memory cache from the same file within a single-threaded pass and persists
  after each admit; this is existing behavior and unchanged. A corrupt file makes
  every agent's load fail (whole pass skipped), which is the intended fail-closed
  outcome.

## Implementation Checklist

1. `replay.rs`: add `ReplayError::Corrupt` + `Display` arm.
2. `replay.rs`: rewrite the corrupt-file branch in `load_with_capacity` to
   `quarantine_corrupt` (best-effort rename to `*.corrupt`), `tracing::error!`
   (path only), and `return Err(ReplayError::Corrupt)`.
3. `replay.rs`: add `pub fn forget(&mut self, nonce: &str) -> Result<(),
   ReplayError>` (remove + persist; `Ok` no-op when absent) with safety rustdoc.
4. `scheduler_loop.rs`: add `load_pass_replay_cache(paths) -> Option<ReplayCache>`
   (loud fail-closed log on `Err`).
5. `scheduler_loop.rs`: replace `ReplayCache::load(paths).ok()` (`:591`) with
   `let Some(replay) = load_pass_replay_cache(paths) else { return; };`.
6. `scheduler_loop.rs`: change `build_scheduler_orchestrator` to take
   `replay: ReplayCache` and call `with_replay_cache(replay)` unconditionally;
   update call site and any test callers.
7. `task_orchestrator.rs`: add the `ReplayError::Corrupt => "replay_cache_corrupt"`
   reason arm; tighten docs on the cache-less `admit_task_action_replay` /
   `admit_decision_nonce` branches to "test-only".
8. `task_orchestrator.rs`: add `TaskApprovalGate::compensate_lost_claim` (default
   no-op); add `QueueApprovalGate.last_admitted_decision_nonce`, record it on a
   successful `admit_decision_nonce`, and implement `compensate_lost_claim` via
   `ReplayCache::forget`.
9. `task_orchestrator.rs`: in `run_one`'s `StaleClaim` arm, `forget` the action
   nonce and call `gate.compensate_lost_claim()` before returning.
10. `exec.rs`: add `seen_control_nonces: Arc<Mutex<HashSet<String>>>` to
    `LiveExecControl`, initialize at every construction site, add
    `admit_control_nonce`, and gate `handle_live_exec_stdin` /
    `handle_live_exec_cancel` / `handle_live_pty_resize` on a fresh nonce (after
    authorization) with an observable drop log.
11. `event_router.rs`: add the clarifying comment at the replay-material `match`
    (`:344-348`).
12. Add the unit tests enumerated in the Testing Plan.
13. Update `docs/architecture.md` (§7.7, §9.2, §10.1) and the `README.md`
    security bullet; add rustdoc on all new public items.
14. Run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D
    warnings`, `cargo build --all`, `cargo test --all`; then the live suite
    (`scripts/matrix_integration_test.sh`) to confirm green.
