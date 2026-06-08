# Python-Orchestrated Phased ADW Delivery Pipeline

## Problem Statement

mx-agent's `adw/issue.py` delivers a GitHub issue by rendering **one** monolithic
`.pi/prompts/issue.md` template and making **one** coding-agent call (`pi -p` / `claude -p`)
that does everything inline — read context, plan, implement, test, self-review, commit,
open a PR, watch CI, and squash-merge — after which Python only verifies the issue ended up
`CLOSED`. Control flow lives entirely inside the model's single session; Python is a
launcher + final verifier.

This monolithic design has structural limits (established in the prior `adw/` evaluation and
the tac-6 ADW comparison):

- **No per-phase observability or retry.** If tests come out weak or review misses a
  blocker, there is no isolated phase to inspect, re-run, or repair — only the whole run.
- **The token and the merge gate live with the agent.** The single agent needs `GH_TOKEN`
  to push/PR/merge, which contradicts mx-agent's "the coding agent must never see Matrix
  tokens or device keys" posture (the same env that holds a GitHub token can hold others),
  and the irreversible squash-merge happens at the agent's discretion rather than in
  auditable code.
- **No durable run identity.** A failed run leaves nothing to resume from or correlate logs
  with; "resume" means re-running and relying on the already-`CLOSED` skip.
- **No self-healing loop.** Test/CI repair is delegated wholesale to the agent's judgment in
  one pass; there is no bounded `run → parse → resolve → rerun` loop owned by code.

This spec replaces the monolith-by-default with a **Python-orchestrated phased pipeline**:
Python drives a sequence of discrete, single-purpose agent calls (each reusing an existing
or new `.pi/prompts` template), threads a persistent run state between them, owns all
git/GitHub mechanics (branch, commit, push, PR, CI-watch, merge) deterministically in code,
and withholds `GH_TOKEN` from the agent. It keeps the previous one-shot behavior available
behind `--one-shot`. The design ports the high-value concepts from the tac-6 ADW system
(`/Users/sekou/TAC/tac-6/adws`) while honoring mx-agent's constraints: stdlib-only Python,
`.pi/prompts` as source of truth, deliberate confirmation + `CLOSED`/merge verification, no
secrets to agents, Unix-only.

### Locked design decisions (from review)

1. **Phased execution becomes the new default** for `adw/issue.py`; the monolithic
   `issue.md` single-call path is preserved behind `--one-shot`.
2. **Git ownership = "Python executes, agent authors text" (Option A).** Python executes
   `git`/`gh` (branch, commit, push, PR open, CI watch, squash-merge); the agent **authors**
   the commit message and PR body, returning them as structured phase output that Python
   then executes. `GH_TOKEN` is **withheld from the agent's environment in phased mode**. The
   squash-merge gate lives in Python.
3. **Granularity = Fine.** Default phase chain:
   `classify → plan → implement → tests → resolve* → [e2e?] → review → patch* → [document?]`,
   then Python-owned `finalize → ci-fix* → merge → report`. The phase list is configurable via
   `--phases`; **per-phase model routing is in-scope** (cheap model for `classify`); 4 new
   prompt templates are added (`classify`, `resolve_failed_test`, `patch`, `document`).

## Goals

- **Phased orchestrator (new default).** Python runs the issue through discrete agent phases,
  each a single runner invocation rendering one phase template, with results parsed as
  structured JSON so Python can branch, loop, and resume.
- **Run identity + state + workspace (Tier A1).** An 8-char `adw_id`, an
  `agents/{adw_id}/` workspace, and a `state.json` recording run identifiers and **completed
  phases**, enabling `--resume`. Implemented with `dataclasses` + `json` only.
- **Python-owned git/GitHub (decision A).** A stdlib `gh`/`git` layer performs branch,
  commit (with agent-authored message), push, PR open (with agent-authored body), CI watch,
  and squash-merge; the merge gate and confirmation are in Python.
- **Secret-withholding runner env (Tier A2).** `safe_subprocess_env()` builds an explicit
  allowlist for the agent; in phased mode it **excludes `GH_TOKEN`** and all Matrix/secret
  vars. (In `--one-shot` mode the agent still needs `GH_TOKEN`; that mode is documented as
  less isolated.)
- **Self-healing loops (Tier B1, now first-class phases).** Bounded `resolve*` (failing
  tests/gates) and `ci-fix*` (red CI) loops: run gate → parse failures → invoke a resolve/
  fix phase → rerun, stopping on green / no-progress / max attempts.
- **Per-phase model routing.** A `{phase: model}` map (cheap for `classify`, capable for
  `implement`/`review`/`patch`), with a global `--model` override.
- **Conditional documentation phase.** A `document` phase that updates the repo's existing
  documentation surface (README status tables, `docs/*`, `wiki/*`, help text) when the change
  is user-visible / public-API- / behavior-affecting; skipped with a recorded reason
  otherwise. Distinct from the inline doc edits `implement` already makes (see boundary in
  Proposed Implementation).
- **Tagged progress + transcripts (Tier A3).** `[MX-ADW]`-tagged progress comments per phase
  (opt-out), and per-phase transcripts/prompts under `agents/{adw_id}/{phase}/`.
- **Preserve safety semantics.** Keep deliberate confirmation before merge and the final
  `CLOSED` verification; fix the non-tty confirmation bypass now that the merge gate is in
  Python.
- **Enforcement.** Add the missing CI job running the `adw/` unittest suite; cover the
  previously-untested `_exec.py` helpers and all new modules.
- **No new third-party dependencies.**

## Non-Goals

- **No pydantic** — use `dataclasses` + `parse_json` validation.
- **No `uv` / PEP-723 inline-dependency script headers** — invoked as `python adw/…`.
- **No Cloudflare R2 / screenshots / UI review artifacts** — mx-agent is a CLI/daemon.
- **No hardcoded `--dangerously-skip-permissions`** — it stays an explicit `--` passthrough.
- **No GitHub webhook / FastAPI server and no cron auto-trigger.** Event-driven triggering is
  future work and should be Matrix-native (mx-agent is a Matrix daemon), not a GitHub
  webhook. See Risks/Open Questions.
- **No daemon/Rust changes.** This is Python developer-tooling only; the daemon, IPC,
  signing, policy, and Matrix code are untouched.
- **Not changing the `issues.py` batch model** beyond inheriting the new default and logging
  per-run `adw_id`s; it remains serial and lock-guarded.

## Relevant Repository Context

`adw/` is stdlib-only Python with two deliberately separated tiers (`adw/README.md`):

- **Render-only tier** — `adw/common.py` + thin wrappers (`prime.py`, `plan.py`,
  `implement.py`, `tests.py`, `e2e_tests.py`, `review.py`). Each loads a `.pi/prompts/*.md`
  template, strips frontmatter, applies Pi-style `$1 / $@ / ${@:N:L}` substitution, prints.
  `common.py` holds `render_prompt_file`, `expand_issue_selectors`, `split_notes`, `AdwError`.
- **Executable tier** — `adw/_exec.py` (subprocess/`gh`/runner-resolution/console helpers),
  `adw/work_issue.py` (bootstrap one issue: branch/assign/board), `adw/issue.py` (the
  `/issue` executor), `adw/issues.py` (serial batch driver, `fcntl`-locked).

Key existing pieces this spec builds on / changes:

- `adw/issue.py`: `default_template(runner)`, `build_runner_command(...)`,
  `wrap_timeout(...)`, `run_runner(cmd, log_dir, issue)`, `split_passthru()`, `_run()`.
  Currently renders one template and runs one runner process inheriting the full env; then
  re-checks `issue_state == CLOSED`. The confirmation prompt is skipped when stdin is not a
  TTY (non-tty bypass — see Risks).
- `adw/_exec.py`: `note/die/assume_yes/confirm`, `capture/run/gh_json`,
  `_resolve_bin/resolve_runner_bin/resolve_gh_bin`, `issue_state/detect_repo/working_tree_dirty`.
  `capture()` does not guard `OSError`. **No unit tests exist for this module.**
- `adw/work_issue.py`: `branch_prefix(labels)` (maps `type:*` labels → `feat/fix/docs/ci/test`),
  `slugify_title`, `extract_scope`, `set_status` (project board), branch create/checkout from
  `origin/<base>`, assign `@me`. These are reusable as the Python **setup** phase.
- `.pi/prompts/`: source-of-truth templates, mirrored to `.claude/commands/` (the
  `$ARGUMENTS` dialect for `claude`). Existing phase templates already present and directly
  reusable as discrete phases: `plan.md`, `implement.md`, `tests.md`, `e2e_tests.md`,
  `review.md`. The monolithic `issue.md` references these as inline "phase contracts" today.
  **No `classify.md`, `resolve_failed_test.md`, or `patch.md` exist yet** (new).
- CI: `.github/workflows/ci.yml` has `docs`, `shell`, `rust`, `cargo-deny`,
  `matrix-integration`. **No Python job runs the `adw/` suite.**
- Tests: `adw/test_common.py`, `test_issue.py`, `test_issues.py`, `test_work_issue.py`
  (42 tests, run via `python -m unittest discover -s adw -p 'test_*.py'`); they never invoke
  `pi`/`claude`/`gh`/`cargo` (mocks + `--dry-run`/`--print-prompt`).
- Docs: `docs/github-management.md` and `adw/README.md` document current usage and safety.

tac-6 reference (read-only models; do not vendor verbatim / no pydantic/uv):
`adw_modules/state.py`, `adw_modules/utils.py` (`make_adw_id`, `parse_json`,
`get_safe_subprocess_env`), `adw_modules/workflow_ops.py` (`format_issue_message`,
`classify_issue`, `build_plan`, `create_or_find_branch`, `create_and_implement_patch`),
`adw_modules/git_ops.py` (push/PR/finalize), `adw_modules/github.py` (`ADW_BOT_IDENTIFIER`),
`adw_test.py` (`run_tests_with_resolution`), `adw_review.py` (severity grading +
`resolve_review_issues`), `adw_sdlc.py` (phase orchestration), `adw/agent.py`
(`SLASH_COMMAND_MODEL_MAP` model routing).

mx-agent constraints that bound the implementation:
- CLI is stateless; the daemon owns long-lived Matrix state, credentials, crypto, policy.
  `agents/{adw_id}/` holds **ephemeral developer-workflow artifacts**, not daemon/app state —
  compatible.
- The coding agent must never see Matrix tokens or device keys; do not log secrets.
- Matrix room membership ≠ execution permission; privileged requests stay Ed25519-signed and
  policy-checked (untouched here).
- Unix-only; no `unsafe`; MSRV 1.74 (no Rust changes here).
- Human-readable output by default; `--json` for automation.

## Proposed Implementation

### Execution model overview

```
issue.py 15                       # PHASED (new default)
issue.py 15 --one-shot            # legacy monolithic issue.md single call
issue.py 15 --phases plan,implement,tests,review   # custom subset
issue.py 15 --adw-id a1b2c3d4 --resume             # resume a prior run

Default phased chain (Fine granularity):
  [Python] setup          fetch issue, branch from origin/main, assign, board -> In Progress
  [agent ] classify       cheap model; -> {issue_class, reason}        (NEW template)
  [agent ] plan           plan.md; writes specs/ when warranted -> {plan_file, spec_created}
  [agent ] implement      implement.md (capable model) -> {summary, files_changed}
  [agent ] tests          tests.md -> {tests_added, summary}
  [Python] gate           run cargo test (+ named gates); parse failures
  [agent ] resolve*       resolve_failed_test.md loop (bounded) until green/no-progress (NEW)
  [agent ] e2e?           e2e_tests.md ONLY if change touches cross-boundary flows (conditional)
  [agent ] review         review.md -> {findings[severity], commit_message, pr_body}
  [agent ] patch*         patch.md loop over blocker findings (bounded)            (NEW)
  [agent ] document?      document.md; ONLY if user-visible/API/docs surface changed (NEW, conditional)
  [Python] finalize       cargo build/test/fmt/clippy gates; commit(agent msg, incl. docs); push; open PR(agent body)
  [Python] ci-fix*        watch CI; on red, re-invoke implement/patch with failure logs (bounded)
  [Python] merge          CONFIRM (Python gate) -> squash-merge --delete-branch; pull --rebase
  [Python] report         verify issue CLOSED; post final summary; persist state
```

The orchestrator is the single source of control flow. Each agent phase is one runner
invocation; Python parses its structured output, updates `AdwState`, saves, and posts
progress before advancing.

### Module layout

New executable-tier modules (stdlib only):
- `adw/_state.py` — `make_adw_id()`, `AdwState` dataclass, `REPO_ROOT`/`AGENTS_DIR`.
- `adw/_git.py` — Python `git`/`gh` operations (branch/commit/push/PR/CI-watch/merge).
- `adw/_phases.py` — phase registry, per-phase dataclasses + loaders, model-routing map,
  the single-phase runner helper, conditional-e2e and conditional-document gates.
- `adw/_orchestrator.py` — the phased driver: sequences phases, threads state, runs the
  bounded `resolve*`/`patch*`/`ci-fix*` loops, owns confirmation + verification.

`adw/issue.py` becomes a thin front-end: parse args → if `--one-shot`, run the legacy single
call (today's `_run`, factored out); else call `_orchestrator.run(...)`.

Add `parse_json` to `adw/common.py` (render-tier-safe, pure).

### Tier A1 — `adw/_state.py`

```python
@dataclass
class AdwState:
    adw_id: str
    issue_number: str | None = None
    issue_class: str | None = None          # feat/fix/docs/chore/...
    branch_name: str | None = None
    base: str = "main"
    plan_file: str | None = None
    pr_number: int | None = None
    pr_url: str | None = None
    commit_message: str | None = None       # agent-authored, executed by Python
    pr_body: str | None = None              # agent-authored, executed by Python
    completed_phases: list[str] = field(default_factory=list)
    # save()/load()/workspace()/phase_dir(phase)/mark_done(phase)
```

- `make_adw_id()` → `uuid.uuid4().hex[:8]`; validate `^[0-9a-f]{8}$` before any path use
  (path-injection guard, mirrors `common.prompt_path`).
- `save()` writes `agents/{adw_id}/state.json` via `json.dump(asdict(self))`; `load()` filters
  to declared fields (forward-compat) and returns `None` on missing/corrupt. State writes are
  best-effort and never abort a run.
- `agents/` added to `.gitignore`. Centralize `REPO_ROOT` here; import where `_exec.py` /
  `issue.py` currently each recompute it.

### Tier A2 — `safe_subprocess_env()` (mode-dependent)

In `adw/_exec.py`:

```python
def safe_subprocess_env(*, allow_gh_token: bool, extra_allow: Sequence[str] = ()) -> dict[str, str]:
    """Allowlist env for the coding-agent runner. Never copies os.environ wholesale."""
```

- Base allowlist (Unix): `HOME, USER, PATH, SHELL, TERM, LANG, LC_ALL, TMPDIR`,
  `ANTHROPIC_API_KEY`, runner discovery/config (`PI_BIN, CLAUDE_BIN, CLAUDE_CODE_PATH,
  PI_MODEL, PI_THINKING`), `PYTHONUNBUFFERED=1`, plus `extra_allow`.
- **`GH_TOKEN`/`GH_BIN` are included only when `allow_gh_token=True`.** Phased mode calls with
  `allow_gh_token=False` (the agent never touches `gh`; Python does). `--one-shot` calls with
  `allow_gh_token=True` (the agent must push/PR/merge) and is documented as **less isolated**.
- **Explicitly excluded always:** `MATRIX_*`, any access-token/device-key vars, `MX_AGENT_*`
  internal flags, and anything not in the allowlist.
- `--inherit-env` debug escape hatch restores full inheritance (documented as reducing
  isolation). Wire `env=safe_subprocess_env(...)` into the single-phase runner helper.

### Python git/GitHub layer — `adw/_git.py` (decision A)

Stdlib `subprocess` wrappers modeled on tac-6 `git_ops.py`, but Python executes everything
and the agent supplies only text:

- `current_branch()`, `create_or_checkout_branch(name, base)` (fetch `origin`, branch from
  `origin/<base>` or checkout existing — reuse `work_issue.py` logic),
- `commit_all(message)` (stage `-A`, commit; no-op if clean),
- `push(branch)`, `pr_for_branch(branch) -> url|None`,
- `create_pr(branch, title, body, base) -> (number, url)`,
- `ci_status(pr) -> {state, failing_jobs:[{name, log_excerpt}]}` (poll `gh pr checks <pr>`;
  bounded wait with interval; truncate/redact logs),
- `squash_merge(pr)` (`gh pr merge <pr> --squash --delete-branch`), `pull_rebase()`.

All run with Python's own env (it legitimately holds `GH_TOKEN`); none of these are exposed
to the agent. Commit message/PR body come from agent phase output (review phase), executed
here. Provide `--dry-run` rendering for each (print the command, never execute).

### Phases and structured outputs — `adw/_phases.py`

Each agent phase = render a template (existing or new) with phase args, invoke the runner
once via the shared helper (factored from `issue.py`'s `run_runner` + `build_runner_command`),
capture the transcript under `agents/{adw_id}/{phase}/`, and parse a **final fenced JSON
block** into a per-phase dataclass via `parse_json`.

Phase template + output contract (contracts documented in each template):

| Phase | Template | Model (default) | Structured output (dataclass) |
|---|---|---|---|
| classify | `classify.md` (NEW) | cheap | `{issue_class, reason}` |
| plan | `plan.md` (existing) | capable | `{plan_file, spec_created, summary}` |
| implement | `implement.md` (existing) | capable | `{summary, files_changed}` |
| tests | `tests.md` (existing) | mid | `{tests_added, summary}` |
| resolve | `resolve_failed_test.md` (NEW) | mid | `{resolved, remaining, summary}` |
| e2e | `e2e_tests.md` (existing) | mid | `{e2e_added, summary}` |
| review | `review.md` (existing) | capable | `{findings:[{severity,description,location}], commit_message, pr_body}` |
| patch | `patch.md` (NEW) | capable | `{resolved, remaining, summary}` |
| document | `document.md` (NEW, conditional) | mid | `{docs_updated, files, summary, commit_message, pr_body}` |

- **Output discipline:** each template instructs the agent to end its reply with a single
  fenced ```json block of the specified shape. `parse_json` is fence/prose tolerant. If
  parsing fails, retry the phase once with a "respond with the required JSON only" nudge;
  on second failure, fail the phase with a clear `AdwError`.
- **Model routing:** `PHASE_MODEL = {classify: cheap, implement: capable, review: capable,
  patch: capable, tests: mid, resolve: mid, e2e: mid, plan: capable}`. Map is **runner-aware**
  (pi vs claude model strings differ). `--model` overrides all; `MX_AGENT_MODEL_<PHASE>` env
  overrides one phase. The "cheap/mid/capable" tiers resolve to concrete model strings per
  runner (documented; pick sensible defaults, e.g. claude haiku/sonnet/opus).
- **Conditional e2e gate:** run `e2e` only when the diff (or plan/classify signal) touches
  cross-boundary flows (CLI↔daemon IPC, Matrix login/sync, signing/trust/policy, sandbox/
  process exec, streaming/PTY/artifacts) — mirror the gate the current `issue.md` step 7
  describes. Otherwise record `E2E decision: skipped because …`.
- **Conditional document gate:** run `document` only when the change is user-visible / alters
  a public API / CLI / help text / Matrix-or-IPC protocol surface, or invalidates a README
  status row, `docs/*`, or `wiki/*` page. Skip with a recorded `Docs decision: skipped
  because …` for internal-only refactors or test-only changes.
- **`document` vs `implement` boundary:** `implement` makes the *tight, code-local* doc edits
  that must ship with the code (doc-comments on new public APIs, `--help`/usage text, a single
  README status-table row toggled by the change). `document` is the *standalone* pass that runs
  after the implementation is final and reviewed: prose updates to `docs/architecture.md`,
  `docs/user-guide.md`, other `docs/*`, and `wiki/*` pages, plus any cross-references. It does
  **not** create a tac-6-style `app_docs/features/` tree. Templates state this split so the two
  phases do not duplicate or fight over the same lines.
- **Commit/PR text source:** the orchestrator takes `commit_message`/`pr_body` from the **last
  agent phase that emits them** — `document` when it runs, otherwise `review` — so the text
  reflects all committed changes (code, tests, and docs). The `finalize` commit includes any
  `document` changes.
- **classify vs labels:** `work_issue.branch_prefix` already derives a type from `type:*`
  labels. The `classify` phase **defers to an explicit `type:*` label when present** and only
  calls the agent when absent/ambiguous (saves a call, avoids conflict). Its result feeds
  branch prefix, commit type, and model routing.

### Orchestrator — `adw/_orchestrator.py`

Responsibilities:
1. Resolve/mint `adw_id`; load state if `--resume`; record `issue_number`; `save()`.
2. Pre-flight (reuse existing): resolve `gh`, detect repo, `issue_state` (skip `CLOSED` unless
   `--force`; fail fast on `UNKNOWN`), dirty-tree check (`--allow-dirty`).
3. Run the configured phase list in order, **skipping phases already in
   `state.completed_phases`** (resume). For each agent phase: render → run (with
   `safe_subprocess_env(allow_gh_token=False)`) → parse → update+save state → post progress →
   `mark_done`.
4. **Bounded loops** (`MAX_RESOLVE=3`, `MAX_PATCH=2`, `MAX_CI_FIX=3`, all overridable):
   - `resolve*`: Python runs `cargo test --all` (+ any gates named in the issue/spec);
     `resolve_failed_test.md` over the failure output; rerun; stop on green / no-progress
     (remaining not decreasing) / max.
   - `patch*`: over review `findings` with `severity == "blocker"` only (tech_debt/skippable
     are reported, not fixed — tac-6 grading); stop when none remain / no-progress / max.
   - `ci-fix*`: after PR open, `_git.ci_status` poll; on red, re-invoke `implement`/`patch`
     with failing-job logs; push; re-watch; stop on green / max.
5. **Finalize/merge gate (Python):** run `cargo build/test/fmt/clippy` as deterministic gates
   before merge; **confirmation prompt immediately before `squash_merge`** — and, fixing the
   prior bug, **abort when stdin is not a TTY and neither `--yes` nor `MX_AGENT_YES=1` is
   set** (no silent unattended merge). Then merge, `pull --rebase`.
6. **Verify + report:** re-check `issue_state == CLOSED`; post final `[MX-ADW]` summary;
   `save()`. Exit non-zero if not `CLOSED` (unless `--no-verify`).

`--one-shot` bypasses all of the above and runs today's single `issue.md` call (factored
into `adw/issue.py:run_one_shot`), with `safe_subprocess_env(allow_gh_token=True)` and the
same confirmation/verify wrapper (also fixing the non-tty bypass there).

### Tier A3 — progress comments + transcripts

- `MX_ADW_BOT_TAG = "[MX-ADW]"`; `format_progress(adw_id, phase, msg)` →
  `"[MX-ADW] {adw_id}_{phase}: {msg}"`; `post_progress(...)` best-effort `gh issue comment`
  (never raises). The bot tag is the loop-prevention marker any future trigger must filter on.
- **On by default in phased mode** (it's the run's primary visibility), with `--no-progress`
  to silence. Messages are built from fixed strings + ids/phase/branch/PR only — never
  runner output, env, or tokens. Truncate/redact any failure text placed in a comment.
- Transcripts: each phase writes `agents/{adw_id}/{phase}/transcript.log` and `prompt.txt`;
  `--log-dir` remains an explicit override.

### `parse_json` in `adw/common.py`

Port the ~30-line fence/prose-tolerant parser (strip ```json fences or locate the first
balanced `{`/`[`); raise `AdwError` on failure; optional `expect=(dict|list)` type check. No
pydantic.

### `issues.py` interaction

Unchanged batch semantics (serial, `fcntl`-locked, stop-on-failure/`--keep-going`,
`--start`, summary). It now drives the phased default. It logs each run's `adw_id` in the
per-issue and summary output so a specific failed run can be resumed with
`issue.py --adw-id <id> --resume`. Flag forwarding (`--model`, `--runner`, `--phases`,
`--log-dir`, tail after `--`) extended as needed.

## Affected Files / Crates / Modules

New:
- `adw/_state.py`, `adw/_git.py`, `adw/_phases.py`, `adw/_orchestrator.py`
- `.pi/prompts/classify.md`, `.pi/prompts/resolve_failed_test.md`, `.pi/prompts/patch.md`,
  `.pi/prompts/document.md` (+ `.claude/commands/` mirrors of each)
- `adw/test_state.py`, `adw/test_git.py`, `adw/test_phases.py`, `adw/test_orchestrator.py`,
  `adw/test_exec.py`
- `.gitignore` entry: `agents/`

Modified:
- `adw/issue.py` — thin front-end: `--one-shot` (legacy), default → orchestrator; new flags
  (below); factor `run_one_shot()`; share the single-phase runner helper; fix non-tty bypass.
- `adw/_exec.py` — `safe_subprocess_env(allow_gh_token=...)`, `MX_ADW_BOT_TAG`,
  `format_progress`, `post_progress`; guard `capture()` against `OSError`; import shared
  `REPO_ROOT`.
- `adw/common.py` — add `parse_json`; (optional) consolidate the three `--` argv splitters.
- `adw/work_issue.py` — expose setup logic (branch/assign/board, scope extraction) as
  importable functions reused by the orchestrator's `setup` phase (keep the CLI intact).
- `adw/issues.py` — log per-run `adw_id`; forward new flags.
- `adw/README.md`, `docs/github-management.md` — document the phased default, `--one-shot`,
  `--phases`, state/resume, git ownership, model routing, progress comments.
- `.github/workflows/ci.yml` — add a `python` unittest job.

Read for context (no change): `.pi/prompts/{issue,plan,implement,tests,e2e_tests,review}.md`.

No Rust crates change.

## CLI / API Changes

`adw/issue.py` new flags (phased is default):
- `--one-shot` — run the legacy monolithic `issue.md` single call (old default behavior).
- `--phases <csv>` — explicit phase subset/order (default: full Fine chain). Validated
  against the known phase set.
- `--adw-id <id>` / `--resume` — reuse/resume a run by id (skip completed phases).
- `--no-progress` — suppress `[MX-ADW]` issue comments (on by default in phased mode).
- `--inherit-env` — debug escape hatch; full env inheritance (reduces isolation).
- `--max-resolve N` / `--max-patch N` / `--max-ci-fix N` — loop bounds.
- `--test-cmd "<cmd>"` (env `MX_AGENT_TEST_CMD`) — gate command for `resolve*`
  (default `cargo test --all`).
- Existing flags (`--runner/--model/--thinking/--repo/--log-dir/--timeout/--no-verify/
  --force/--allow-dirty/-y/--yes/--print-prompt/--dry-run`) retained; `--model` now overrides
  all phases.

**Behavior change (intended):** `python adw/issue.py 15` now runs the phased pipeline instead
of one monolithic call. `--one-shot` restores the prior behavior. This is the agreed new
default. `issues.py` inherits it. Documented prominently as a migration note.

No Rust CLI, IPC, or protocol surface changes.

## Data Model / Protocol Changes

- New on-disk developer-tooling artifact `agents/{adw_id}/state.json` (not a daemon protocol;
  git-ignored). Schema = `AdwState` fields; forward-compatible reader (ignores unknown keys).
- New per-phase artifacts: `agents/{adw_id}/{phase}/{transcript.log,prompt.txt}`.
- New agent↔Python output contracts (documented in each phase template) parsed by
  `parse_json` into dataclasses (classify/plan/implement/tests/resolve/e2e/review/patch/
  document). The `review` contract additionally carries `commit_message` and `pr_body`
  (decision A); the conditional `document` contract re-emits them so the text reflects doc
  changes when that phase runs.
- No Matrix event schema, IPC, policy, signing, or persistence changes.

## Security Considerations

- **Token withholding is the central hardening.** In phased mode the runner env is built by
  `safe_subprocess_env(allow_gh_token=False)`, so `GH_TOKEN`, `MATRIX_*`, device keys, and
  unrelated secrets are not handed to the agent; Python alone holds `GH_TOKEN` and performs
  all `gh` operations. `--one-shot` and `--inherit-env` are documented as **less isolated**
  (the agent receives `GH_TOKEN` because it must push/merge there).
- **Merge gate in auditable code.** The irreversible squash-merge is executed by Python
  behind an explicit confirmation; the prior **non-tty confirmation bypass is fixed**
  (abort, don't silently proceed, when stdin is not a TTY and `--yes`/`MX_AGENT_YES` is
  absent) in both phased and one-shot paths.
- **No secrets in logs/comments/transcripts.** Progress comments and transcripts are built
  from fixed strings + ids/branch/PR; agent output, env, and tokens are never interpolated
  into comments; failing test/CI logs placed into resolve/ci-fix prompts or comments are
  truncated and scrubbed of obvious secret patterns. Add a test asserting comment/PR/commit
  text construction excludes env values.
- **Path-injection guard:** `adw_id` validated `^[0-9a-f]{8}$` before filesystem use.
- **CLI statelessness preserved:** `agents/{adw_id}/` is ephemeral run artifacts only; no
  daemon/app state, credentials, crypto, or policy move into the tooling. Daemon, IPC,
  signing, deny-by-default policy, and Matrix paths are untouched.
- **Unix-only**; no `unsafe`; no Rust/MSRV impact.

## Testing Plan

All tests use stdlib `unittest` and **never invoke `pi`/`claude`/`gh`/`git`/`cargo`**;
external effects are mocked or exercised via `--dry-run`/`--print-prompt`. Use a temp
`AGENTS_DIR` so tests never write into the repo.

- `adw/test_state.py`: `make_adw_id` shape/uniqueness; save/load round-trip; missing →
  `None`; corrupt → `None`; unknown keys ignored; `adw_id` rejects `../`/slashes/non-hex;
  `completed_phases`/`mark_done` semantics.
- `adw/test_exec.py` (also covers currently-untested helpers):
  `safe_subprocess_env` includes allowlist, drops `None`, **excludes `GH_TOKEN` when
  `allow_gh_token=False` and includes it when True**, excludes injected `MATRIX_ACCESS_TOKEN`/
  `MX_AGENT_*`; `_resolve_bin` precedence (env → `which` → fallback); `resolve_runner_bin`/
  `resolve_gh_bin` happy + missing; `issue_state`/`detect_repo` parse mocked `gh` JSON /
  non-zero / `OSError`; `format_progress` shape includes `[MX-ADW]`.
- `adw/test_git.py`: command construction + output parsing for branch/commit/push/PR/
  `ci_status`/`squash_merge` via mocked `capture`; `--dry-run` prints, never executes.
- `adw/test_phases.py`: per-phase template renders and substitutes args; structured-output
  loaders parse valid JSON, fenced JSON, prose-wrapped JSON; reparse-nudge then `AdwError` on
  repeated bad output; `PHASE_MODEL` routing + `--model` override + per-phase env override;
  conditional-e2e and conditional-document gates true/false; commit/PR text sourced from
  `document` when present, else `review`.
- `adw/test_orchestrator.py` (mock the single-phase runner + `_git` + `gh`):
  phases run in order; `--phases` subsetting; `--resume` skips `completed_phases`; `resolve*`/
  `patch*`/`ci-fix*` stop on green / no-progress / max; blockers patched but tech_debt/
  skippable only reported; **merge confirmation aborts on non-tty without `--yes`**; `CLOSED`
  verification success/failure; `--one-shot` takes the legacy path; default run wires
  `allow_gh_token=False`.
- `adw/test_common.py`: `parse_json` cases (raw/fenced/prose/garbage, `expect` type-check).
- `adw/test_issue.py` (extend): `--print-prompt`/`--dry-run` still exit 0; `--one-shot`
  produces today's single command; default produces a phased plan (dry-run).
- CI: add a `python` job to `.github/workflows/ci.yml` running
  `python -m unittest discover -s adw -p 'test_*.py'` on `ubuntu-latest` (stock Python 3.x),
  gating PRs. Closes the "adw tests never run in CI" gap.
- Manual/local (documented, not automated): `issue.py 15 --dry-run` shows the phase plan and
  that no secrets/`GH_TOKEN` appear in any rendered agent env.

## Documentation Updates

- `adw/README.md`: rewrite the executable-tier section for the phased default — phase chain,
  `--one-shot`, `--phases`, run id / `agents/{adw_id}/` workspace / `state.json` / resume,
  Python-owned git (decision A) and the `GH_TOKEN`-withheld posture, per-phase model routing,
  `[MX-ADW]` progress comments. Update "Safety expectations" (env allowlist, merge gate).
- `docs/github-management.md`: update `issue.py`/`issues.py` usage and examples for the new
  default; migration note that `--one-shot` restores prior behavior; document `agents/` is
  git-ignored and how to resume.
- New templates document their JSON output contracts inline.
- Parser help/epilogs for the new flags.
- Note in `adw/README.md` that the suite now runs in CI.
- Do not imply any unimplemented daemon/alpha behavior; this is developer tooling only.

## Risks and Open Questions

- **Default-behavior change blast radius.** Phased becomes default; anything scripting
  `issue.py` expecting the monolith must add `--one-shot`. Mitigation: prominent migration
  note; keep `--one-shot` a permanent first-class mode. Confirm acceptable.
- **Structured-output reliability.** Phases depend on the agent emitting clean trailing JSON.
  Mitigation: explicit contract in templates, fence-tolerant `parse_json`, one reparse nudge,
  then fail. Risk that capable models still occasionally wander — bounded by the nudge/fail.
- **`.pi` ↔ `.claude` mirror drift.** Fine granularity adds 3 new template pairs to a mirror
  that is already a known drift hazard. Mitigation: a small `check_prompt_mirror` test or a
  generator that derives `.claude` from `.pi`; decide which.
- **CI-fix loop cost/latency.** Watching CI and re-invoking the agent on red can be slow/
  expensive. Mitigation: bounded `--max-ci-fix`, `--timeout`, and a clear "left red after N"
  report. Confirm default bound (proposed 3).
- **Default gate command.** `cargo test --all` matches CI but is slow; consider a faster
  default or require `--test-cmd`. Confirm.
- **classify vs labels overlap.** Proposed: defer to `type:*` label when present, else call
  the agent. Confirm this precedence.
- **`document` phase boundaries and commit shape.** Proposed: `document` is conditional (gated
  on user-visible/API/protocol/docs-surface change), runs after `patch`, edits existing
  `docs/*`/`wiki/*`/README/help only (no `app_docs/` tree), and its changes are folded into the
  single `finalize` commit. Confirm vs (a) always-on, (b) a separate `docs: …` commit, and
  confirm the `implement`-vs-`document` line split so the two phases don't churn the same docs.
- **Commit/PR authoring placement.** Proposed: emitted by the `review` phase output. Confirm
  vs a dedicated cheap `commit`/`pr_text` call (more calls, cleaner separation).
- **`--one-shot` token exposure.** One-shot necessarily gives the agent `GH_TOKEN`. Accept as
  the documented less-isolated mode, or also move git out of one-shot (defeats its purpose)?
  Proposed: accept and document.
- **Per-phase fresh context vs session continuity.** Each phase is a fresh agent invocation
  (re-reads repo context) — simpler and cheaper to reason about, but more context re-reads
  than a single session. Accept for now; note session-reuse as future optimization.
- **macOS `--timeout` no-op (adjacent prior-eval item).** `wrap_timeout` relies on GNU
  `timeout`, absent on macOS, so per-phase timeouts silently no-op there. Out of core scope;
  recommend a native Python timeout + process-group kill as a follow-up.
- **Matrix-native triggering (future work).** Event-driven runs should arrive over Matrix,
  not a GitHub webhook; the `[MX-ADW]` tag and `make_adw_id` are laid down now to support it.

## Implementation Checklist

- [ ] Add `agents/` to `.gitignore`.
- [ ] `adw/common.py`: add `parse_json` (fence/prose tolerant, raises `AdwError`, optional
      `expect`); (optional) consolidate `--` splitters; export `REPO_ROOT`.
- [ ] `adw/_state.py`: `make_adw_id`, `AdwState` (+ save/load/workspace/phase_dir/mark_done),
      `adw_id` validation, `AGENTS_DIR`.
- [ ] `adw/_exec.py`: `safe_subprocess_env(allow_gh_token=...)` (exclude `GH_TOKEN` unless
      allowed; exclude `MATRIX_*`/`MX_AGENT_*`), `MX_ADW_BOT_TAG`, `format_progress`,
      `post_progress`; guard `capture()` against `OSError`.
- [ ] `adw/_git.py`: branch/commit/push/PR/`ci_status`/`squash_merge`/`pull_rebase`, each with
      `--dry-run` rendering; run with Python's own env.
- [ ] Factor the single-phase runner helper out of `issue.py` (`build_runner_command` +
      `run_runner` + `wrap_timeout`), wiring `env=safe_subprocess_env(...)` and per-phase
      transcript/prompt capture.
- [ ] `adw/_phases.py`: phase registry, per-phase dataclasses + `parse_json` loaders +
      reparse-nudge fallback, `PHASE_MODEL` routing (runner-aware) with `--model`/env
      overrides, conditional-e2e and conditional-document gates, classify-vs-label
      precedence, commit/PR text sourced from `document`-else-`review`.
- [ ] New templates `.pi/prompts/{classify,resolve_failed_test,patch,document}.md` +
      `.claude/commands` mirrors, each documenting its JSON output contract; `document.md`
      states the `document`-vs-`implement` boundary and targets `docs/*`/`wiki/*`/README, not
      an `app_docs/` tree.
- [ ] `adw/_orchestrator.py`: mint/load state + `--resume`; pre-flight (CLOSED/UNKNOWN/dirty);
      run phases skipping completed (`e2e`/`document` conditional); bounded
      `resolve*`/`patch*`/`ci-fix*`; cargo gates;
      Python merge gate with confirmation (abort on non-tty without `--yes`); CLOSED verify;
      final report; progress posting.
- [ ] `adw/issue.py`: thin front-end; `run_one_shot()` (legacy, `allow_gh_token=True`,
      non-tty fix); new flags (`--one-shot/--phases/--adw-id/--resume/--no-progress/
      --inherit-env/--max-*/--test-cmd`); default → orchestrator.
- [ ] `adw/work_issue.py`: expose setup functions for the orchestrator `setup` phase.
- [ ] `adw/issues.py`: log per-run `adw_id`; forward new flags.
- [ ] Tests: `test_state.py`, `test_exec.py`, `test_git.py`, `test_phases.py`,
      `test_orchestrator.py`; extend `test_common.py`, `test_issue.py`. Temp `AGENTS_DIR`; no
      real `pi`/`claude`/`gh`/`git`/`cargo`.
- [ ] `.github/workflows/ci.yml`: add the `python` unittest job.
- [ ] `adw/README.md` + `docs/github-management.md`: phased default, `--one-shot`, `--phases`,
      state/resume, decision-A git ownership, model routing, progress, migration note.
- [ ] Resolve Open Questions (default-change acceptance; mirror drift mitigation; ci-fix/
      resolve bounds; default gate command; classify-vs-label; commit/PR authoring placement;
      one-shot token exposure) at/before review.
- [ ] Run `python -m unittest discover -s adw -p 'test_*.py'` locally; confirm green and that
      `--one-shot` reproduces today's single runner command.
- [ ] Commit, PR, and merge per the `/issue` workflow.
