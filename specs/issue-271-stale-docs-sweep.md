# Stale-Docs Sweep: roadmap §10 status, user-guide agent-list demo, alpha-checklist E2EE status, architecture §11.3 recovery

## Problem Statement

Four residual documentation passages in the `docs/` tree still describe
pre-v0.2.0 behavior. Each contradicts the current shipped code — and in two
cases also contradicts other documentation that has already been corrected.
These drifts erode trust in otherwise-accurate v0.2.0 docs:

1. **Roadmap Phase 10 status block** (`docs/roadmap-rust.md:383-385`) lists the
   live `/sync` scheduler loop and the signed Matrix `exec` transport as
   "Remaining work … (tracked by #155)". Both are implemented, wired, and
   e2e-tested; the cited tracker #155 (and #199/#200/#196) are closed. This
   makes a fully-wired feature look unfinished.
2. **User-guide two-agent demo** (`docs/user-guide.md:421-423`) prints a stale
   4-column `agent list` sample with status `online`. The real renderer emits
   6 columns and the registration status is `active`. The CLI no longer
   produces this output, and the canonical example earlier in the same file
   (lines 170-173) is already correct.
3. **Alpha-release-checklist** (`docs/alpha-release-checklist.md:142-148`) lists
   "production E2EE hardening" (device verification UX, cross-signing, key
   backup) as "still landing". It shipped via #240 / #256 and contradicts both
   `README.md:53` and `docs/roadmap-rust.md:582-589`, which report it delivered.
4. **Architecture §11.3** (`docs/architecture.md:1437,1439`) describes restart
   recovery as loading active invocations from a local store and reconciling a
   local OS process table. Recovery is actually room-state-based: the daemon
   reconciles `executing` tasks from `com.mxagent.task.v1` room state against the
   `com.mxagent.invocation.v1` snapshot and the live-invocation id set. No OS
   process table is consulted.

This is a focused, docs-only sweep to bring these four passages in line with the
code. No behavior changes.

## Goals

- Roadmap Phase 10 status block reflects that the live scheduler loop and the
  signed Matrix `exec` transport ship (no longer "remaining work"). If a tracker
  reference is kept, cite the closed #199/#200/#196/#155 as delivered.
- User-guide two-agent demo sample matches the real 6-column renderer with
  status `active` and a liveness verdict, consistent with the canonical example
  at `docs/user-guide.md:170-173`.
- Alpha-release-checklist no longer lists production E2EE hardening as "still
  landing"; wording is reconciled with `README.md:53` and
  `docs/roadmap-rust.md:582-589`. Only the genuinely-remaining very-large-output
  artifact tuning stays in the "still landing" framing.
- Architecture §11.3 steps describe recovery as room-state reconciliation, with
  the "local process table" language removed.
- Verifiable end state: no remaining occurrence in the four files of `online`
  as an `agent list` status, of `#155` framed as open/remaining work, or of
  "process table" recovery.

## Non-Goals

- No code changes to any crate. This is documentation only.
- No rewrite of the surrounding sections beyond the cited passages; keep edits
  surgical and preserve existing voice/structure.
- No new docs, diagrams, or restructuring of the roadmap/architecture/checklist.
- Not re-auditing other docs for drift beyond the four passages named here (the
  broader feature-completeness assessment that surfaced these is out of scope).
- Do not change the already-correct canonical `agent list` example at
  `docs/user-guide.md:170-173` — it is the template, not a target.

## Relevant Repository Context

This repo is `mx-agent`, a Rust workspace. The CLI is stateless; the daemon owns
long-lived Matrix state, credentials, crypto, policy, and process supervision.
The four passages below describe daemon/CLI behavior that has since shipped.

**1. Live scheduler loop + signed Matrix exec transport (roadmap §10).**
- `run_scheduler_loop` lives at
  `crates/mx-agent-daemon/src/scheduler_loop.rs:303` and is exported from
  `crates/mx-agent-daemon/src/lib.rs:156`.
- It is driven by the live daemon at
  `crates/mx-agent-daemon/src/lifecycle.rs:398-414`.
- The Matrix dispatch path (`MX_AGENT_TASK_DISPATCH=matrix`) is functional at
  `crates/mx-agent-daemon/src/scheduler_loop.rs:83-88`.
- Live e2e coverage: `crates/mx-agent-daemon/tests/matrix_integration.rs:1387`.
- Trackers #155, #199, #200, #196 are closed. Existing specs confirm the
  delivered work: `specs/issue-199-live-task-scheduler-loop.md`,
  `specs/issue-200-task-orchestration-live-call-exec.md`,
  `specs/issue-196-live-matrix-remote-exec.md`,
  `specs/issue-155-daemon-mediated-exec-ipc.md`.

**2. `agent list` renderer (user-guide demo).**
- The renderer emits 6 columns — `agent_id, kind, status, liveness, last_seen,
  caps` — at `crates/mx-agent-cli/src/cli.rs:2148-2156`.
- Registration sets status `active` at
  `crates/mx-agent-daemon/src/exec.rs:2143`.
- The already-correct canonical sample is `docs/user-guide.md:170-173`:
  ```text
  mx-agent: 1 agent(s) in #demo:localhost
    alice-agent              generic  active   active   12s ago    shell,test
  ```
  Columns there are `agent_id  kind  status  liveness  last_seen  caps`.

**3. E2EE production hardening (alpha checklist).**
- Delivered via #240 / #256. `README.md:53` marks it 🟡 Implemented and
  enumerates: persistent daemon-owned crypto store; device verification
  (`device list`/`show`/`verify`); cross-signing (`auth cross-signing`);
  server-side key backup/recovery (`recovery enable`/`status`/`recover`);
  optional `require_verified_device` policy gate.
- `docs/roadmap-rust.md:582-589` reports the same as "delivered".
- The only genuinely-remaining item in the checklist bullet is very-large-output
  artifact tuning (artifact mode itself already ships).

**4. Restart recovery (architecture §11.3).**
- Entry point: `recover_executing_tasks` / `reconcile_executing_tasks` at
  `crates/mx-agent-daemon/src/task_orchestrator.rs:624-665`, documented in-code
  as "the restart-recovery entry point (architecture §11.3)".
- It reconciles `executing` tasks from `com.mxagent.task.v1` room state against
  the `com.mxagent.invocation.v1` snapshot and live-invocation ids; no OS
  process table is consulted (`crates/mx-agent-daemon/src/scheduler_loop.rs:95`).
- Related spec: `specs/issue-221-scheduler-restart-recovery-stale-snapshot.md`.

Convention note: docs in this repo cite code paths and closed issue numbers
sparingly and report status with explicit markers (✅/🟡, "implemented",
"delivered"). Match that style. Architecture §11.2 (`docs/architecture.md:1429`)
also mentions "reconcile running child processes" — that line is **outside** the
issue scope (§11.3 only); leave it unless trivially consistent to align, and if
touched, mirror the room-state framing rather than process-table framing.

## Proposed Implementation

Make four surgical edits.

### Edit 1 — `docs/roadmap-rust.md` Phase 10 status block (lines 383-385)

Replace the trailing "Remaining work … (tracked by #155)." sentence so the block
reads that the live scheduler loop and signed Matrix `exec` transport ship.
Suggested replacement for the final sentence(s):

> The engine is wired into a live `/sync` scheduler loop, so a running daemon
> auto-executes ready tasks (`run_scheduler_loop`), and the signed Matrix
> transport for remote `exec` is delivered (#199/#200/#196/#155, all closed).

Keep the preceding sentences (CRUD/graph/watch, orchestration engine list)
intact. Do not introduce new claims beyond "wired and delivered".

### Edit 2 — `docs/user-guide.md` two-agent demo sample (lines 421-423)

Update the commented sample output to the 6-column renderer with status `active`
and a liveness verdict, matching `docs/user-guide.md:170-173`. Both agents
appear. Suggested replacement (preserve the leading `#   ` comment prefix used
in this fenced block):

```text
#   mx-agent: 2 agent(s) in #demo:localhost
#     alice-agent              generic  active   active   8s ago     shell,test
#     bob-agent                generic  active   active   3s ago     shell
```

Column order: `agent_id  kind  status  liveness  last_seen  caps`. Use plausible
relative `last_seen` ages. Keep the surrounding step comments (Step 4 prose at
line 432) unchanged; that prose still reads correctly.

### Edit 3 — `docs/alpha-release-checklist.md` bullet (lines 142-148)

Narrow the "still landing" bullet to only the genuinely-remaining
very-large-output artifact tuning, and state that production E2EE hardening
shipped. Suggested rewrite of the bullet:

> - **Very-large-output tuning is still landing.** Large-output artifact mode
>   already ships: streams that exceed the timeline budget can be uploaded as
>   Matrix media with SHA-256 integrity, optional zstd compression, and a tail
>   preview; remaining artifact work is tuning for very large outputs. E2EE
>   privileged-event decryption and fail-safe handling for undecryptable events
>   ship today, and **production E2EE hardening shipped** (#240/#256): device
>   verification UX, cross-signing, and server-side key backup/recovery — see
>   `README.md` and roadmap Phase 12.

Reconcile wording with `README.md:53` and `docs/roadmap-rust.md:582-589`; do not
re-list the full feature enumeration (link to those instead) to avoid creating a
fourth copy that can drift.

### Edit 4 — `docs/architecture.md` §11.3 steps 2 and 4 (lines 1437, 1439)

Rephrase the recovery steps as room-state reconciliation; remove the "local
process table" language and the "local store" framing for active invocations.
Suggested replacement for steps 2 and 4:

- Step 2: `Load the executing-task snapshot from com.mxagent.task.v1 room state.`
- Step 4: `Reconcile executing tasks against the com.mxagent.invocation.v1
  snapshot and the live-invocation id set (no OS process table is consulted).`

Keep steps 1, 3, 5, 6 as-is (step 3 already fetches room-state snapshots, which
is consistent). Ensure the resulting list reads coherently end-to-end.

### Verification pass

After the edits, grep the four files to confirm the acceptance criteria:
- no `online` as an `agent list` status,
- no `#155` framed as open/remaining work,
- no "process table" recovery language.

## Affected Files / Crates / Modules

Docs only — no crates modified.

- `docs/roadmap-rust.md` (Phase 10 status block, ~lines 377-385).
- `docs/user-guide.md` (two-agent demo sample, ~lines 421-423).
- `docs/alpha-release-checklist.md` (E2EE/large-output bullet, ~lines 142-148).
- `docs/architecture.md` (§11.3 steps 2 and 4, lines 1437/1439).

Read-only references used to ground the edits (do not modify):
- `crates/mx-agent-daemon/src/scheduler_loop.rs` (`:83-88`, `:95`, `:303`)
- `crates/mx-agent-daemon/src/lib.rs:156`
- `crates/mx-agent-daemon/src/lifecycle.rs:398-414`
- `crates/mx-agent-cli/src/cli.rs:2148-2156`
- `crates/mx-agent-daemon/src/exec.rs:2143`
- `crates/mx-agent-daemon/src/task_orchestrator.rs:624-665`
- `crates/mx-agent-daemon/tests/matrix_integration.rs:1387`
- `README.md:53`, `docs/user-guide.md:170-173`, `docs/roadmap-rust.md:582-589`

## CLI / API Changes

None. No command-line, public API, IPC, or protocol surface changes.

## Data Model / Protocol Changes

None. No event schema, persistence, policy, or serialization changes. The event
type names referenced in the architecture edit (`com.mxagent.task.v1`,
`com.mxagent.invocation.v1`) already exist; the doc is being corrected to match
them, not changing them.

## Security Considerations

- These are user-trust-sensitive corrections. Items 3 and 4 must end **more**
  accurate, not differently-wrong: the checklist currently *understates* shipped
  security work, and the architecture doc describes a recovery mechanism the
  daemon does not implement.
- Do not overclaim. Production E2EE hardening is 🟡 (Implemented with caveats),
  not ✅; preserve the README's framing that Matrix device verification is an
  advisory transport signal and that signing + trust + policy remain the
  execution gate. Do not imply the SAS flow is unattended or that device
  verification replaces Ed25519 signing/policy.
- Preserve the invariant in surrounding docs: Matrix room membership does not
  imply execution permission; privileged requests remain Ed25519-signed and
  deny-by-default policy-checked. None of these edits should weaken that framing.
- No secrets, tokens, or device keys appear in any of these passages; none
  should be introduced. Unix-only assumptions unaffected.

## Testing Plan

Docs-only change; no unit/integration code tests apply. Verification is by
content checks:

- Run the repo's documentation drift guard if one exists (the CLI reference has
  a drift guard per commit `aefbd6f`; confirm whether a broader docs check or
  link-checker runs in CI and that these files still pass).
- Grep assertions (manual or as a one-off check) over the four files:
  - `grep -n "online" docs/user-guide.md` → no `agent list` status row uses
    `online`.
  - `grep -n "#155" docs/roadmap-rust.md` → #155 not framed as open/remaining.
  - `grep -niE "process table" docs/architecture.md` → no matches.
  - `grep -ni "still landing" docs/alpha-release-checklist.md` → only
    very-large-output tuning remains.
- Visual review that the `agent list` sample columns match
  `crates/mx-agent-cli/src/cli.rs:2148-2156` and the canonical example at
  `docs/user-guide.md:170-173`.

## Documentation Updates

This task *is* the documentation update. Files touched:
`docs/roadmap-rust.md`, `docs/user-guide.md`, `docs/alpha-release-checklist.md`,
`docs/architecture.md`. No README, help-text, or status-table change is
required (those are already correct and serve as the reconciliation source). Do
not edit `docs/user-guide.md:170-173`, `README.md:53`, or
`docs/roadmap-rust.md:582-589` except to keep cross-references valid.

## Risks and Open Questions

- **Roadmap reference style:** the acceptance criteria allow either dropping the
  "remaining work" sentence or marking it delivered. Recommendation: mark
  delivered and cite the closed issues, to preserve the audit trail. Low risk.
- **Checklist de-duplication:** the full E2EE feature list already lives in
  `README.md:53` and roadmap §12. Recommendation: link rather than re-enumerate
  in the checklist, to prevent a future fourth drift. Confirm reviewers prefer a
  link over an inline list.
- **Architecture §11.2 line 1429-1430** ("reconcile running child processes")
  also leans process-centric but is outside the named scope (§11.3). Open
  question: align it too for consistency, or leave strictly to scope?
  Recommendation: leave out of scope unless a reviewer requests it; if touched,
  mirror room-state framing.
- **`last_seen` values in the demo sample** are illustrative; any plausible
  relative age is acceptable since the demo is not a golden-output test.

## Implementation Checklist

1. Re-read the four target passages and their already-correct counterparts
   (`docs/user-guide.md:170-173`, `README.md:53`,
   `docs/roadmap-rust.md:582-589`) to match voice and claims.
2. Edit `docs/roadmap-rust.md` Phase 10 status block: replace the "Remaining
   work … (tracked by #155)." sentence with delivered/wired wording citing the
   closed #199/#200/#196/#155.
3. Edit `docs/user-guide.md:421-423`: replace the 4-column `online` sample with
   the 6-column `active` sample (both agents), matching lines 170-173.
4. Edit `docs/alpha-release-checklist.md:142-148`: narrow the "still landing"
   bullet to very-large-output tuning; state production E2EE hardening shipped
   (#240/#256) and link to README / roadmap §12 instead of re-enumerating.
5. Edit `docs/architecture.md` §11.3 steps 2 and 4: rephrase as room-state
   reconciliation (`com.mxagent.task.v1` vs `com.mxagent.invocation.v1` snapshot
   and live-invocation ids); remove "local process table" / "local store".
6. Run the grep verification pass (online / #155-as-remaining / "process table")
   over the four files and confirm zero offending matches.
7. Sanity-check that no cross-reference (line ranges cited elsewhere, the
   canonical example) was disturbed and the four files render correctly.
