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

## Creating Issues

`docs/github-issue-backlog.md` contains a complete phase-by-phase issue backlog. Create issues manually from that file or use `gh` once authenticated.

Example:

```bash
gh issue create \
  --title "Phase 1: implement Unix socket JSON-RPC IPC" \
  --label "type:feature,area:ipc,priority:p0" \
  --milestone "1. Local Daemon Foundation" \
  --body-file /tmp/issue.md
```
