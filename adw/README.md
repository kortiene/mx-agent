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
| `python adw/issue.py <n> [notes]` | **The `/issue` executor.** Expand the template and drive a coding-agent runner (`pi` default, or `claude`) end to end, then verify the issue is CLOSED on GitHub. Renders the `.claude/commands` variant for `--runner claude`. |
| `python adw/issues.py <spec...>` | Deliver several issues in order via `issue.py`, one fully completing (CI + merge) before the next starts. Accepts single IDs and `N-M` / `N..M` ranges; resumable, serialized by a lock file. |

```bash
python adw/work_issue.py 15 --print                # show issue context, change nothing
python adw/issue.py 15                             # implement issue #15 end-to-end
python adw/issue.py 15 --print-prompt              # render the workflow only (no run)
python adw/issue.py 15 --runner claude -- --permission-mode acceptEdits
python adw/issues.py 15-22 --keep-going            # a range, continue past failures
python adw/issues.py 15 16 18-20 --dry-run         # preview the batch plan
```

## `/issues` selectors

`adw/issues.py` expands issue selectors the same way in both execute and
`--print-prompt` modes:

- `12` selects issue 12.
- `12-15` selects issues 12, 13, 14, and 15.
- `12..15` also selects issues 12, 13, 14, and 15.
- Repeated IDs are deduplicated while preserving first occurrence.
- Descending ranges are rejected to avoid accidental reverse-order batch work.
- With `--print-prompt`, arguments after `--` become shared notes; when
  executing, they are forwarded verbatim to each `issue.py` run.

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
`--print-prompt` previews. The rendered workflows they drive continue to
require:

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

Helper tests use the Python standard library and never invoke pi, claude, or gh
(execution paths are covered only through `--dry-run` / `--print-prompt` and by
mocking the runner):

```bash
python -m unittest discover -s adw -p 'test_*.py'
```
