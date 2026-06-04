# Agent Development Workflow scripts

`adw/` contains Python wrappers for the project slash-command prompt templates in
`.pi/prompts/`. The prompt templates remain the source of truth; each script
loads the matching Markdown file, strips frontmatter, applies Pi-style argument
substitution, and prints the rendered workflow.

The scripts are intentionally conservative: they **do not execute** GitHub,
Cargo, merge, or destructive workflow steps. Use the rendered workflow with an
agent or operator that can perform the steps with review and confirmation.

## Commands

| Slash command | Script | Purpose |
|---|---|---|
| `/prime` | `python adw/prime.py [task/context]` | Render repository priming instructions. |
| `/plan` | `python adw/plan.py "<prompt>"` | Render a workflow to create a detailed spec in `specs/`. |
| `/implement` | `python adw/implement.py <spec-file>` | Render a workflow to implement a spec end-to-end. |
| `/tests` | `python adw/tests.py [spec-file\|pr\|notes]` | Render a focused non-e2e test coverage workflow. |
| `/e2e_tests` | `python adw/e2e_tests.py [spec-file\|pr\|notes]` | Render an end-to-end test coverage workflow. |
| `/review` | `python adw/review.py <pr-url-or-number> [spec-file]` | Render a PR review workflow. |
| `/issue` | `python adw/issue.py <issue-number> [notes]` | Render a single-issue delivery workflow. |
| `/issues` | `python adw/issues.py <issue-id-or-range> [...] [-- notes]` | Render a sequential multi-issue delivery workflow. |

## Examples

```bash
python adw/plan.py "add workspace export command"
python adw/implement.py specs/workspace-export.md
python adw/tests.py specs/workspace-export.md
python adw/e2e_tests.py 123
python adw/review.py 123 specs/workspace-export.md
python adw/issue.py 123 "keep the change minimal"
python adw/issues.py 12 13-15 20 -- shared context for all issues
```

## `/issues` selectors

`adw/issues.py` normalizes issue selectors before rendering the prompt:

- `12` selects issue 12.
- `12-15` selects issues 12, 13, 14, and 15.
- `12..15` also selects issues 12, 13, 14, and 15.
- Repeated IDs are deduplicated while preserving first occurrence.
- Descending ranges are rejected to avoid accidental reverse-order batch work.
- Arguments after `--` are treated as shared notes.

Example:

```bash
python adw/issues.py 10 12-14 13 20 -- fix in priority order
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

These scripts do not bypass repository safety constraints. The rendered workflows
continue to require:

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

Helper tests use the Python standard library:

```bash
python -m unittest adw.test_common
```
