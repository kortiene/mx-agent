---
description: Implement a GitHub issue end-to-end using plan/implement/tests/e2e/review phases
argument-hint: "<issue-number> [notes]"
---
Implement GitHub issue #$1 for this repository, end to end.

Extra context/notes from me (everything after the issue number; may be empty). Full invocation for reference: $ARGUMENTS

`/issue` is the full delivery pipeline. It should reuse the project command templates below as phase contracts, but it must not stop after any individual phase unless there is a real blocker:

- `.claude/commands/plan.md` for spec creation when warranted
- `.claude/commands/implement.md` for disciplined implementation
- `.claude/commands/tests.md` for focused non-e2e test coverage
- `.claude/commands/e2e_tests.md` for conditional end-to-end coverage
- `.claude/commands/review.md` for local self-review before shipping

Read those prompt files before starting the work. Apply their workflows inline as phases of this `/issue` run; do not merely tell the user to run them separately.

Follow this exact workflow and do not stop until the issue is shipped or you hit a genuine blocker.

1. Validate input and start the issue
   - If `$1` is missing, stop and ask for an issue number.
   - Run `python adw/work_issue.py $1 --print` first to read the title, labels, milestone, scope, and acceptance criteria. Treat the acceptance criteria as the definition of done.
   - If the issue is CLOSED, stop and tell me.
   - If the issue has unmet dependencies (a "Depends on" line referencing another open issue), warn me and ask whether to continue.
   - Stop for real blockers such as acceptance criteria that conflict with repository security constraints, require real secrets/credentials, or require broad architecture decisions with insufficient detail.
   - Then run `python adw/work_issue.py $1` to create the branch, assign the issue, and move its board card to In Progress.
   - Use `~/.local/bin/gh` if `gh` is not on PATH and `. "$HOME/.cargo/env"` before any cargo command when needed.

2. Read repository context
   - Read and internalize:
     - `README.md`
     - `CONTRIBUTING.md`
     - `docs/architecture.md`
     - root `Cargo.toml`
     - relevant crate `Cargo.toml` files and source files for the issue
     - existing tests and docs around the affected behavior
   - Preserve mx-agent constraints:
     - CLI is stateless; daemon owns long-lived Matrix state, credentials, crypto, policy, and supervision.
     - The coding agent must never see Matrix tokens or device keys.
     - Matrix room membership does not imply execution permission.
     - Privileged requests must remain Ed25519-signed and checked against local deny-by-default policy.
     - Unix only; do not add Windows paths or assumptions.
     - No `unsafe`; respect Rust MSRV 1.74.
     - Document new public APIs.
     - Never log secrets; use existing redaction/`Secret` patterns.
     - Preserve human-readable output by default and `--json` for automation.
     - Do not imply unimplemented alpha behavior exists unless this issue actually implements it.

3. Decide whether a `/plan`-style spec is needed
   - Create a spec when the issue is non-trivial, spans multiple crates, changes user-visible behavior, affects CLI/daemon/protocol/policy/security boundaries, changes Matrix event schemas, IPC, signing, trust, sandboxing, persistence, or has ambiguous acceptance criteria.
   - For specs, create `specs/` if needed and write `specs/issue-$1-<descriptive-slug>.md` using the structure and quality bar from `.claude/commands/plan.md`.
   - The spec must include problem statement, goals/non-goals, repository context, affected crates/modules, implementation approach, security considerations, testing plan, e2e decision, risks/open questions, and implementation checklist.
   - For trivial issues, skip the spec and state: `Spec decision: no separate spec needed because ...`.
   - If a spec is created, treat it as the source of truth together with the issue acceptance criteria.

4. Summarize and plan briefly
   - Summarize the requested implementation in a few bullets.
   - Identify the owning crate(s), modules, existing patterns, docs, and tests involved.
   - List the concrete implementation steps.
   - Then proceed; do not stop after planning.

5. Implement using `/implement` semantics
   - Make the smallest correct change that satisfies the issue and any created spec.
   - Keep changes focused, idiomatic, and testable.
   - Do not pull in unrelated work or broad rewrites.
   - Update docs, help text, README status tables, or architecture docs when behavior changes.
   - Maintain daemon/CLI separation and security boundaries.
   - Never expose Matrix tokens, device keys, signing keys, or other secrets through logs, stdout/stderr, command arguments, fixtures, or PR text.

6. Strengthen focused tests using `/tests` semantics
   - Inspect existing coverage for the changed behavior.
   - Add or update focused unit tests, deterministic integration tests, CLI tests, policy/protocol/schema tests, and negative/security regression tests as appropriate.
   - Prefer the smallest test layer that gives confidence.
   - Do not weaken assertions or delete meaningful tests to make the suite pass.
   - Do not add Docker/Matrix/live-service requirements in this phase.

7. Evaluate e2e coverage using `/e2e_tests` semantics
   - Consider e2e coverage when the issue affects CLI↔daemon IPC, daemon lifecycle, Matrix login/sync/session behavior, signing/trust/policy authorization, sandbox/process execution, streaming/PTY/artifacts, or other cross-boundary user-visible flows.
   - Add e2e tests only when lower-level tests are insufficient and use existing infrastructure such as `scripts/matrix_dev.sh`, `dev/matrix/README.md`, ignored tests, or script-gated tests.
   - Do not make default `cargo test --all` depend on Docker, external networks, or live services unless that is already the project convention.
   - If e2e tests are not added, explicitly report: `E2E decision: not added because ...`.

8. Self-review using `/review` semantics before committing
   - Review the changed files against the issue and any spec.
   - Check for scope creep, correctness bugs, missing error handling, weak tests, misleading docs, secret exposure, policy/signing/trust bypasses, daemon/CLI separation violations, missing public docs, MSRV risks, and formatting/clippy/doc-warning risks.
   - Fix issues found during self-review before opening a PR.
   - Do not post PR comments during this local self-review phase because the PR does not exist yet.

9. Verify locally before opening a PR
   - If Rust changed, run all required checks:
     - `cargo build --all`
     - `cargo test --all`
     - `cargo fmt --check`
     - `cargo clippy --all-targets --all-features -- -D warnings`
   - Run any explicit commands named in the issue acceptance criteria or created spec.
   - Run any relevant narrow tests first when useful, but the required checks above must pass before opening a PR unless there is a genuine environment blocker.
   - If a check fails, fix it and rerun the relevant check.

10. Commit and open the PR
   - Inspect `git status` and ensure only relevant files are included.
   - Commit with a clear message ending in `closes #$1`.
   - Push the branch.
   - Open a PR with `gh pr create`, base `main`, and a complete body that includes:
     - Summary
     - Related issue: `Closes #$1`
     - Spec path, if one was created
     - Changes made
     - Tests/checks run and results
     - E2E decision and commands, if applicable
     - Security considerations
     - Any assumptions or limitations
     - Checklist from the repository PR template, if present

11. Monitor CI, fix failures, and review the PR
   - Wait for CI with `gh pr checks <pr> --watch` or equivalent polling.
   - If any check fails, inspect logs, fix the failure, commit, push, and wait again until green.
   - Perform a final `/review`-style PR review using the opened PR and the spec if one exists.
   - If the final review finds required fixes, fix them before merging.

12. Merge and clean up
   - When CI is green and the final review is acceptable, merge with `gh pr merge <pr> --squash --delete-branch`.
   - Switch back to `main` and run `git pull --rebase origin main`.

13. Final report
   - Confirm issue #$1 is CLOSED.
   - Report the PR number and CI result.
   - Report the spec path if one was created, or the reason a spec was skipped.
   - Summarize files changed and behavior implemented.
   - Summarize tests and e2e coverage decisions.
   - Note assumptions, risks, limitations, or follow-up work.

If anything is ambiguous, state the assumption you are making and proceed when safe. Only stop for genuine blockers.
