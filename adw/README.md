# Agent Development Workflow scripts

`adw/` holds the project's Agent Development Workflow (ADW) tooling — everything
used to take a GitHub issue or spec from idea to merged change. It is all Python
(standard library only) and comes in two tiers:

1. **Render-only wrappers** for the slash-command prompt templates in
   `.pi/prompts/`. The prompt templates remain the source of truth; each wrapper
   loads the matching Markdown file, strips frontmatter, applies Pi-style
   argument substitution, and prints the rendered workflow. These wrappers are
   intentionally conservative: they **do not execute** GitHub, Cargo, merge, or
   destructive steps. Use the rendered workflow with an agent or operator that
   performs the steps under review.
2. **Executable delivery drivers** (`issue.py`, `issues.py`, `work_issue.py`)
   that run the headless delivery loop end to end — branch, code, test, open a
   PR, watch CI, and merge. Unlike the render-only wrappers, these **do** perform
   GitHub/Cargo/merge actions, so they gate on an explicit confirmation
   (`--yes` / `MX_AGENT_YES=1` to skip), support `--dry-run` / `--print-prompt`
   previews, and verify each issue ends up CLOSED on GitHub before counting it
   done.

## Render-only wrappers

| Slash command | Script | Purpose |
|---|---|---|
| `/prime` | `python adw/prime.py [task/context]` | Render repository priming instructions. |
| `/plan` | `python adw/plan.py "<prompt>"` | Render a workflow to create a detailed spec in `specs/`. |
| `/implement` | `python adw/implement.py <spec-file>` | Render a workflow to implement a spec end-to-end. |
| `/tests` | `python adw/tests.py [spec-file\|pr\|notes]` | Render a focused non-e2e test coverage workflow. |
| `/e2e_tests` | `python adw/e2e_tests.py [spec-file\|pr\|notes]` | Render an end-to-end test coverage workflow. |
| `/review` | `python adw/review.py <pr-url-or-number> [spec-file]` | Render a PR review workflow. |

```bash
python adw/plan.py "add workspace export command"
python adw/implement.py specs/workspace-export.md
python adw/tests.py specs/workspace-export.md
python adw/e2e_tests.py 123
python adw/review.py 123 specs/workspace-export.md
```

> `issue.py` and `issues.py` are **executable delivery drivers** (below), not
> render-only wrappers. Pass `--print-prompt` to either for render-only output
> (e.g. `python adw/issues.py 12 13-15 --print-prompt -- shared notes`).

## Executable delivery drivers

These run the actual delivery loop. They perform GitHub/Cargo/merge actions and
must be run deliberately: each gates on a confirmation prompt (`--yes` /
`MX_AGENT_YES=1` to skip) and supports `--dry-run` / `--print-prompt` previews.

| Script | Purpose |
|---|---|
| `python adw/work_issue.py <n>` | Bootstrap one issue: fetch it, derive a branch, switch to it from an up-to-date base, assign it, and move its board card to In Progress. The `/issue` workflow runs `--print` for context, then this to set up. Needs `gh` + `git`. |
| `python adw/issue.py <n> [notes]` | **The `/issue` executor.** Runs the **phased pipeline** by default (see below): Python drives discrete agent phases and owns all git/GitHub work, then verifies the issue is CLOSED. `--one-shot` runs the legacy single monolithic agent call instead. |
| `python adw/issues.py <spec...>` | Deliver several issues in order via `issue.py`, one fully completing (CI + merge) before the next starts. Accepts single IDs and `N-M` / `N..M` ranges; resumable, serialized by a lock file. |

```bash
python adw/work_issue.py 15 --print                # show issue context, change nothing
python adw/issue.py 15                             # phased pipeline (new default)
python adw/issue.py 15 --dry-run                   # preview the phase plan
python adw/issue.py 15 --phases plan,implement,tests,review   # custom phase subset
python adw/issue.py 15 --one-shot                  # legacy single monolithic agent call
python adw/issue.py 15 --adw-id a1b2c3d4 --resume  # resume a prior run, skipping done phases
python adw/issue.py 15 --print-prompt              # render the one-shot template only (no run)
python adw/issues.py 15-22 --keep-going            # a range, continue past failures
python adw/issues.py 15 16 18-20 --dry-run         # preview the batch plan
```

## Phased pipeline (default)

`python adw/issue.py <n>` now runs a **Python-orchestrated phased pipeline**. Instead
of one monolithic agent call, Python drives a sequence of discrete, single-purpose
agent phases and performs all git/GitHub mechanics itself:

```
[Python] setup     fetch issue, branch from origin/main, assign, board → In Progress
[agent ] classify  cheap model → issue type
[agent ] plan      create a spec in specs/ when warranted
[agent ] implement make the change
[agent ] tests     add focused coverage
[Python] resolve*  run the test gate; on failure ask the agent to fix; rerun (bounded)
[agent ] e2e?      only if the change crosses CLI/daemon/Matrix/signing/sandbox flows
[agent ] review    self-review → findings (blocker/tech_debt/skippable) + commit/PR text
[agent ] patch*    fix blocker findings only (bounded)
[agent ] document? only if user-visible/API/docs surface changed
[Python] finalize  run gates; commit (agent-authored msg); push; open PR (agent-authored body)
[Python] ci-fix*   watch CI; on red, re-invoke the agent to fix (bounded)
[Python] merge     confirm, then squash-merge --delete-branch; verify issue CLOSED
```

Key properties:

- **Run identity + resume.** Each run gets an 8-char `adw_id` and a workspace at
  `agents/{adw_id}/` (git-ignored) holding `state.json` and per-phase transcripts.
  Re-run with `--adw-id <id> --resume` to skip already-completed phases. The
  `state.json` contract is codified in [`state.schema.json`](state.schema.json)
  (versioned via `schema_version`; unknown keys are tolerated and dropped).
- **Python owns git; the agent never sees `GH_TOKEN`.** All branch/commit/push/PR/
  CI-watch/merge work runs in Python. The agent only *authors* the commit message and
  PR body; the runner is launched with an env allowlist that withholds `GH_TOKEN`,
  Matrix tokens, and other secrets. The squash-merge is gated in Python behind an
  explicit confirmation (a non-interactive run must pass `--yes`/`MX_AGENT_YES=1`).
- **Per-phase model routing.** Cheap model for `classify`, capable for
  `implement`/`review`/`patch`. Override with `--model` (all phases) or
  `MX_AGENT_MODEL_<PHASE>` (one phase). An exported `PI_MODEL` does *not* override
  routing (it would defeat the point); pass `--model` to do so explicitly.
- **`--phases <csv>`** runs a custom subset/order; `--max-resolve` / `--max-patch` /
  `--max-ci-fix` bound the self-healing loops; `--test-cmd` overrides only the *test*
  gate (default `cargo test --all`) — `cargo fmt --check`, clippy, and build still run
  before merge; `--no-progress` silences the `[MX-ADW]` issue comments. Resume
  (`--adw-id <id> --resume`) tolerates the prior run's uncommitted edits and skips the
  clean-tree precondition.
- **Prompt composition.** The reused phase templates
  (`plan`/`implement`/`tests`/`e2e_tests`) are wrapped at render time with a shared preamble
  (Python owns git/gh; the agent has no GitHub access this phase) and a per-phase JSON output
  contract, so those interactive templates stay unedited and serve all three consumers
  (render-only wrappers, one-shot `issue.md`, and the orchestrator). The `review` phase uses a
  dedicated working-tree template, `review_phase.md` (the PR-oriented `review.md` stays for
  interactive/`--one-shot` use). The contract lives in
  `adw/_phases.py` (one source of truth, kept in sync with the result parsers); a mock-free
  self-test (`adw/test_phase_contracts.py`) asserts every composed phase prompt carries it.
  Free-form text (the commit message and PR body) is authored to
  `agents/{adw_id}/commit_message.txt` and `pr_body.md` and read back by Python — kept out of
  the parsed JSON so multiline prose can't break parsing.

`--one-shot` restores the previous behavior: render the monolithic `.pi/prompts/issue.md`
template and hand the whole pipeline to a single agent call. That mode necessarily gives
the agent `GH_TOKEN` (it pushes/merges itself), so it is **less isolated**; prefer the
phased default unless you specifically need the old flow.

## `/issues` selectors

`adw/issues.py` expands issue selectors the same way in both execute and
`--print-prompt` modes:

- `12` selects issue 12.
- `12-15` selects issues 12, 13, 14, and 15.
- `12..15` also selects issues 12, 13, 14, and 15.
- Repeated IDs are deduplicated while preserving first occurrence.
- Descending ranges are rejected to avoid accidental reverse-order batch work.
- With `--print-prompt`, arguments after `--` become shared notes; when
  executing, they are forwarded to the runner (e.g. `-- --dangerously-skip-permissions`).

```bash
python adw/issues.py 10 12-14 13 20 --print-prompt -- fix in priority order
```

renders the workflow with the normalized issue list:

```text
10 12 13 14 20 -- fix in priority order
```

## Template substitutions

The wrappers support the Pi substitutions used by this repository's templates:

- `$1`, `$2`, ... positional arguments
- `$@` and `$ARGUMENTS` for all arguments joined by spaces
- `${@:N}` for arguments from position `N`
- `${@:N:L}` for `L` arguments starting at position `N`

## Safety expectations

Neither tier bypasses repository safety constraints. The render-only wrappers
never execute anything; the executable delivery drivers (`issue.py`, `issues.py`,
`work_issue.py`) act only after an explicit confirmation (`--yes` /
`MX_AGENT_YES=1` to skip in unattended runs) and support `--dry-run` /
`--print-prompt` previews. In phased mode the coding-agent runner is launched
with an environment allowlist (`adw/_exec.py:safe_subprocess_env`) that withholds
`GH_TOKEN`, Matrix tokens, device keys, and other secrets — Python performs all
`gh`/`git` work itself — and the irreversible squash-merge is gated in Python
(an unattended run without `--yes`/`MX_AGENT_YES=1` is refused, not silently
merged). The rendered workflows they drive continue to require:

- stateless CLI / daemon-owned long-lived state
- no Matrix tokens or device keys exposed to coding agents
- deny-by-default local policy and signed privileged requests
- Unix-only assumptions
- no `unsafe` Rust
- Rust MSRV 1.74
- documented public APIs
- no secrets in logs, fixtures, output, or PR comments
- human-readable output by default and `--json` for automation where applicable

## Tests

Helper tests use the Python standard library and never invoke pi, claude, gh,
git, or cargo (execution paths are covered only through `--dry-run` /
`--print-prompt` and by mocking the runner, git, and gh layers; phase workspaces
are written under a temporary `AGENTS_DIR`). They run in CI via the `adw` job in
`.github/workflows/ci.yml`:

```bash
python -m unittest discover -s adw -p 'test_*.py'
```
