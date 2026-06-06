# Issue #221 — Scheduler restart-recovery clobbers a succeeded task off a stale snapshot

## Problem statement

The live scheduler loop runs restart-recovery on **every pass**, finalizing any
`executing` task this daemon owns whose `invocation_id` is not in a `live_invocations`
set to `failed` with reason `recovered_stale_invocation`. The live loop passes a
**permanently empty** `live_invocations` set, on the assumption that "dispatch is
synchronous within a pass, so any task seen `executing` at the start of a pass is a
leftover from a previous daemon run."

That assumption is wrong because the task snapshot is read from a local store that
**lags the homeserver `/sync` echo**. Sequence that triggers the flake
(`live_scheduler_executes_signed_task_dag_and_denies`):

1. Pass N: `task-plan` `pending` → claim → `executing` (invocation `inv-X`) → local
   dispatch (synchronous) → finalize `succeeded`.
2. Its dependent `task-test` becomes runnable and succeeds.
3. Pass N+k: the snapshot for this pass **still shows `task-plan` as `executing`**
   (the `succeeded` echo has not synced back into the local store yet). With
   `live_invocations` empty, recovery treats `inv-X` as a stale orphan and finalizes
   the task `failed`, clobbering a real success.

This is a real product race in the daemon, not just a test artifact (same shape as
the exec-stdin race fixed in #218).

## Goals

- The live scheduler loop never finalizes a task to `failed` via restart-recovery
  when that task's invocation was **claimed by this daemon during the current run**.
- Genuine restart recovery — a task left `executing` by a *previous* daemon run,
  whose invocation this run never claimed — is preserved unchanged.
- A deterministic unit test reproduces the "completed-this-run must not be recovered"
  case, alongside the existing genuine-orphan coverage.

## Non-goals

- No change to the optimistic-concurrency `claim`/`finalize` contract.
- No change to the orchestrator's authorization (signature/trust/replay/policy/approval).
- No new Docker/Matrix/live-service requirement on the default `cargo test --all`.

## Repository context

- `crates/mx-agent-daemon/src/scheduler_loop.rs`
  - `run_scheduler_tick` — the single pure tick used by the live loop and tests:
    recovery first, then schedule + process runnable tasks. Already threads an
    `attempted: HashSet<(task_id, state_rev)>` across ticks to dedupe stale re-reads.
  - `run_scheduler_loop` / `scheduler_pass` / `scheduler_pass_for_agent` — the live
    wiring; `scheduler_pass_for_agent` constructs `live_invocations = BTreeSet::new()`
    (the empty set that causes the bug).
- `crates/mx-agent-daemon/src/task_orchestrator.rs`
  - `recover_executing_tasks` / `recover_stale_executing` — finalize an owned
    `executing` task whose `invocation_id` is not in the live set to `failed`.

## Affected crates / modules

- `mx-agent-daemon`: `scheduler_loop.rs` (primary), doc comments in
  `task_orchestrator.rs`, architecture note in `docs/architecture.md`.

## Implementation approach (issue option 2: track this-run invocations)

Thread a persistent `claimed_invocations: BTreeSet<String>` through the live loop,
mirroring the existing `attempted` set:

1. `run_scheduler_tick` takes `claimed_invocations: &mut BTreeSet<String>` in place of
   the immutable `live_invocations: &BTreeSet<String>`. It passes this set to
   `recover_executing_tasks` as the "still owned by this run" set, and after each
   processed task records the invocation id it claimed (from the `Completed` /
   `Denied` outcome) into the set.
2. `scheduler_pass_for_agent` uses the loop-owned `claimed_invocations` instead of a
   fresh empty set, so an invocation claimed in pass N is remembered in pass N+k.
3. `run_scheduler_loop` owns `claimed_invocations` next to `attempted` and bounds its
   memory the same way (clear past `MAX_ATTEMPTED_TRACKED`).

Why this is correct: invocation ids are unique per claim. A task this daemon claimed
and finalized this run has its `invocation_id` recorded, so when a later stale
snapshot shows it `executing`, recovery sees the invocation as "owned this run" and
leaves it for the next, fresh snapshot. A genuine orphan from a *previous* daemon run
has an invocation id this run never generated, so it is not in the set and is still
recovered. On a fresh process start `claimed_invocations` is empty, so true
restart-recovery at startup is unchanged.

## Security considerations

- No change to authorization, signing, trust, replay, or policy. Recovery only ever
  *fails* a task; this change makes it strictly more conservative (it fails fewer
  tasks), so it cannot cause unauthorized execution.
- No secrets logged; invocation ids are non-sensitive and already logged.
- No `unsafe`; MSRV 1.74.

## Testing plan

- Unit (`scheduler_loop.rs`): new deterministic test that (a) runs a tick taking a
  pending task to `succeeded`, recording its invocation, then (b) runs a second tick
  over a *stale* snapshot that still shows the task `executing` with that same
  invocation and asserts no `RecoveredStale` outcome and the store is not clobbered to
  `failed`.
- Unit (existing, preserved): `tick_recovers_stale_executing_task_without_redispatch`
  and `recover_executing_tasks_reconciles_local_and_remote` continue to recover a
  genuine orphan (invocation not in the this-run set).
- Update the two existing direct `run_scheduler_tick` callers in tests and the
  `task_orchestration_e2e.rs` `tick` helper for the new `&mut` parameter.

## E2E decision

No new e2e test. The flaky e2e
(`live_scheduler_executes_signed_task_dag_and_denies`, `#[ignore]`, Docker-gated) is
the existing coverage and remains. The fix is verified deterministically at the unit
layer, which is the smallest layer that reproduces the race. Adding more Docker-gated
coverage would not increase confidence over the deterministic reproduction.

## Risks / open questions

- Memory growth of `claimed_invocations` on a long-lived daemon: bounded by clearing
  past `MAX_ATTEMPTED_TRACKED`, identical to `attempted`. Clearing can only re-expose
  the original race if 50k tasks complete within a single `/sync` lag window, which is
  not realistic.

## Implementation checklist

- [ ] `run_scheduler_tick` records claimed invocations and excludes them from recovery.
- [ ] `scheduler_pass_for_agent` / `scheduler_pass` / `run_scheduler_loop` thread the
      persistent `claimed_invocations` set and bound its memory.
- [ ] Doc comments updated (`run_scheduler_tick`, recovery methods, module docs).
- [ ] New deterministic unit test for "completed-this-run must not be recovered".
- [ ] Existing direct-tick test callers updated for the new signature.
- [ ] `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`,
      `cargo test --all`, `cargo build --all` pass.
</content>
</invoke>
