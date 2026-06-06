# GitHub Project Management

This repository uses GitHub Issues, Milestones, Projects, Actions, and Releases to manage the Rust implementation of `mx-agent`.

See also:

- [Architecture](architecture.md)
- [Rust implementation roadmap](roadmap-rust.md)
- [Issue backlog](github-issue-backlog.md)

---

## Milestones

Create these milestones in GitHub:

| Milestone | Roadmap Phases | Goal |
|---|---:|---|
| 1. Local Daemon Foundation | 0–2 | Rust workspace, CLI/daemon skeleton, IPC, protocol types |
| 2. Matrix Workspace MVP | 3–4 | Matrix login, sync, rooms, agent registration/discovery |
| 3. Secure Tool Calls | 5–7 | signing, trust, named tools, policy engine |
| 4. Remote Exec MVP | 8–9 | remote process execution, streaming, backpressure |
| 5. Orchestration Layer | 10–12 | task DAG, context sharing, cancellation, approvals |
| 6. Production Hardening | 13–16 | sandboxing, artifacts, PTY, tests, releases |

---

## Labels

Recommended labels:

```text
type:feature
type:bug
type:docs
type:security
type:testing
type:ci
area:cli
area:daemon
area:ipc
area:matrix
area:protocol
area:policy
area:security
area:sandbox
area:streaming
area:tasks
area:tools
area:docs
priority:p0
priority:p1
priority:p2
status:blocked
good-first-issue
```

---

## Project Board

Create a GitHub Project with these statuses:

```text
Backlog
Ready
In Progress
In Review
Blocked
Done
```

Suggested custom fields:

- Milestone
- Priority
- Area
- Risk
- Estimate
- Target Release

Useful views:

- Roadmap: grouped by milestone
- Engineering: grouped by status
- Security: filtered by `area:security` or `type:security`
- MVP: filtered to milestones 1–4

---

## Branch and PR Workflow

Use short-lived branches:

```bash
git checkout -b feat/ipc-json-rpc
git checkout -b feat/matrix-login
git checkout -b fix/socket-permissions
git checkout -b docs/github-backlog
```

Every PR should:

- link an issue
- describe security considerations
- update docs when behavior changes
- pass CI
- avoid exposing secrets in logs/output

Protect `main`:

- require PRs before merge
- require CI passing
- require at least one review when collaborators exist
- disallow force pushes
- optionally require linear history and signed commits

---

## Automation

This repo includes:

- issue templates under `.github/ISSUE_TEMPLATE/`
- PR template at `.github/pull_request_template.md`
- CI workflow at `.github/workflows/ci.yml`
- Dependabot config at `.github/dependabot.yml`
- security policy at `SECURITY.md`

The CI workflow is safe before Rust code exists: Rust checks run only when `Cargo.toml` exists.

---

## Automated Population

`docs/github-issue-backlog.md` is the source of truth for the roadmap. It is parsed by `scripts/populate_github.py`, which creates/updates:

- all labels in the label set
- the six roadmap milestones
- one GitHub issue per backlog entry (66 total)

The script is idempotent by exact issue title, so reruns update labels/milestones instead of creating duplicates.

### How it runs

The workflow `.github/workflows/populate-github.yml` runs:

- automatically on push to `main` when the backlog, script, or workflow changes
- manually via the Actions tab using `workflow_dispatch`

It uses the built-in `GITHUB_TOKEN` with `issues: write` permission, so no extra secret is required.

### Local validation

Validate parsing without touching GitHub:

```bash
python scripts/populate_github.py --dry-run
```

## Project Board Wiring

Issues are organized on a GitHub Projects v2 board titled `mx-agent roadmap`.

Projects v2 are owned by a user/org, not a repository, so the default Actions `GITHUB_TOKEN` cannot manage them. A personal access token (PAT) with `project` scope is required for board automation.

### One-time setup

1. Authenticate with project scope and create/backfill the board:

   ```bash
   gh auth login --scopes "repo,project"
   scripts/wire_project.sh
   ```

   This creates (or reuses) the `mx-agent roadmap` board and adds every issue labeled `roadmap:auto` to it. It prints the board's `PROJECT_URL`.

2. Store the project URL as a repo variable so new issues auto-add:

   ```bash
   gh variable set PROJECT_URL --body "<printed project url>"
   ```

3. Store a PAT with `project` scope as a secret for the sync workflow:

   ```bash
   gh secret set PROJECT_TOKEN --body "<pat>"
   ```

### Ongoing automation

The workflow `.github/workflows/project-sync.yml` runs `actions/add-to-project` whenever an issue or PR is opened, reopened, or labeled, and adds it to `PROJECT_URL`. It is a no-op until `PROJECT_URL` is set.

## Starting Work on an Issue

`adw/work_issue.sh` takes a GitHub issue number and bootstraps everything needed to start implementing it:

```bash
adw/work_issue.sh 3
```

It will:

1. Fetch the issue (title, body, labels, milestone, state).
2. Derive a branch name from the issue's type label and title, e.g. `ci/3-add-rust-formatting-linting-and-baseline`.
3. Create/check out that branch from an up-to-date `origin/main`.
4. Assign the issue to the current user.
5. Move the issue's project board card to `In Progress` (best effort).
6. Print the scope and acceptance criteria.

Useful flags:

```bash
adw/work_issue.sh 3 --print      # only show issue context, change nothing
adw/work_issue.sh 3 --dry-run    # show all actions without performing them
adw/work_issue.sh 3 --base main --status "In Progress"
adw/work_issue.sh 3 --no-status  # skip board update (no project scope needed)
```

Requirements: `gh` (authenticated; `project` scope needed for board updates), `jq`, and `git`.

## Automated Issue Processing

For unattended runs, two tools drive a [pi](https://github.com/earendil-works/pi-mono) or Claude Code coding agent headlessly through the same `/issue` workflow used interactively (defined in `.pi/prompts/issue.md`).

### Single issue: `python adw/issue.py`

The CLI equivalent of typing `/issue <number> [notes]` in the agent's editor. It expands the `issue.md` template (substituting `$1` and `${@:2}` exactly as pi does), then runs it via the selected runner in print mode — `pi -p` by default, or `claude -p` with `--runner claude` — so the agent implements the issue end-to-end: branch, code, test, open a PR, watch CI, and squash-merge.

```bash
python adw/issue.py 15                            # implement issue #15 end-to-end
python adw/issue.py 15 "do not continue on unmet deps"   # notes fill the ${@:2} slot
python adw/issue.py 15 --json --model sonnet:high # JSON event stream, pick a model
python adw/issue.py 15 --print-prompt             # expand the template only; do not run
python adw/issue.py 15 --dry-run                  # show the exact pi invocation
python adw/issue.py 15 -- --thinking high -nc     # pass extra flags verbatim to pi
```

```bash
python adw/issue.py 15 --log-dir ./logs            # tee the transcript to a per-issue log
python adw/issue.py 15 --timeout 3600              # abort the run after an hour
python adw/issue.py 15 --yes                        # skip the confirmation prompt
python adw/issue.py 15 --no-verify                 # skip the post-run CLOSED check
python adw/issue.py 15 --force                      # run even if already CLOSED
```

By default the script refuses to start on a dirty working tree (`--allow-dirty` to override) and, when run interactively, asks for confirmation before implementing and merging (`--yes`/`MX_AGENT_YES=1` to skip; auto-skipped when stdin is not a terminal). `--timeout` aborts a stuck run.

Notes:

- Slash-command/template expansion only happens in the agent's interactive editor, so `issue.py` performs the substitution itself before calling the runner.
- **Outcome is verified against GitHub.** pi's print-mode exit code only reflects whether the model responded, not whether the issue shipped, so after the run the script checks that the issue is `CLOSED` and fails otherwise. Already-closed issues are skipped and unknown numbers fail fast (before spending tokens). Disable with `--no-verify`; re-run anyway with `--force`.
- Headless mode cannot ask interactive questions, so the template's "ask whether to continue" step becomes "state the assumption and proceed"; pass a note to steer it.
- Each run is fully autonomous (edits, pushes, opens a PR, and merges unattended). `pi` is resolved from `PATH`, then `~/.local/share/pi-node/current/bin/pi`, or `PI_BIN`; `claude` from `PATH`, then `~/.claude/local/claude` or `~/.local/bin/claude`, or `CLAUDE_BIN`; `gh` from `PATH` then `~/.local/bin/gh` or `GH_BIN`. `PI_MODEL`, `PI_THINKING`, and `MX_AGENT_LOG_DIR` set defaults for the matching flags.

### Many issues in order: `adw/issues.sh`

Processes several issues sequentially via `python adw/issue.py`, one fully completing (including its CI and merge) before the next begins — important because later backlog issues usually depend on earlier ones being merged to `main`.

```bash
adw/issues.sh 15 16 17                      # explicit list, stop on first failure
adw/issues.sh 15-22                          # inclusive range (also N..M)
adw/issues.sh 15..30 --keep-going -- --json --model sonnet:high
adw/issues.sh 15-30 --start 21               # resume from #21
adw/issues.sh 15 16 18-20 --dry-run          # preview the plan
```

It stops at the first failure by default (`--keep-going` to continue), preserves the given order, supports number/range specs, forwards flags after `--` to `issue.py`, and prints a completed/failed summary (also on Ctrl-C). It confirms once for the whole batch (`--yes` to skip), holds a lock so only one batch runs at a time, and resumes at a given issue with `--start <n>` (index-based). Because each run verifies closure and already-closed issues are skipped, a batch is also **resumable just by re-running it**; `--log-dir <dir>` is forwarded to each run. It deliberately does not parallelize, since concurrent merges to `main` would conflict.

Requirements: `pi` on `PATH` (or `PI_BIN`), plus the same `gh`/`git`/`cargo` access the interactive workflow uses.

### Manual alternative with gh

```bash
gh issue create \
  --title "Phase issue 7: Implement framed JSON-RPC IPC transport" \
  --label "type:feature,area:ipc,priority:p0" \
  --milestone "1. Local Daemon Foundation" \
  --body-file /tmp/issue.md
```
