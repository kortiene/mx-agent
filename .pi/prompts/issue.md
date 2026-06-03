---
description: Implement a GitHub issue end-to-end (branch, code, test, PR, merge)
argument-hint: "<issue-number> [notes]"
---
Implement GitHub issue #$1 for this repository, end to end.

Extra context/notes from me (may be empty): ${@:2}

Follow this exact workflow and do not stop until the issue is shipped or you hit a real blocker:

1. Start the issue
   - Run `scripts/work_issue.sh $1 --print` first to read the title, labels, milestone, scope, and acceptance criteria. Treat the acceptance criteria as the definition of done.
   - If the issue is CLOSED, stop and tell me.
   - If the issue has unmet dependencies (a "Depends on" line referencing another open issue), warn me and ask whether to continue.
   - Then run `scripts/work_issue.sh $1` to create the branch, assign the issue, and move its board card to In Progress. Use `~/.local/bin/gh` if `gh` is not on PATH and `. "$HOME/.cargo/env"` before any cargo command.

2. Implement
   - Make the smallest correct change that satisfies the scope and acceptance criteria. Do not pull in work from other issues.
   - Match existing code style and crate layout. Keep changes focused.

3. Verify locally (must all pass before opening a PR)
   - If Rust changed: `cargo build --all`, `cargo test --all`, `cargo fmt --check`, and `cargo clippy --all-targets --all-features -- -D warnings`.
   - Run any explicit commands named in the acceptance criteria and confirm each one passes.
   - Never log or commit secrets or tokens.

4. Ship
   - Commit with a clear message ending in `closes #$1`.
   - Push the branch and open a PR with `gh pr create`, base `main`, body filling out the repo PR template (summary, related issue `Closes #$1`, changes, tests, security considerations, checklist).
   - Wait for CI with `gh pr checks <pr> --watch` (or poll). If any check fails, fix it and push again until green.
   - When all checks pass, merge with `gh pr merge <pr> --squash --delete-branch`.
   - Switch back to `main` and `git pull --rebase origin main`.

5. Report
   - Confirm issue #$1 is CLOSED and summarize what changed, the PR number, and the CI result.

If anything is ambiguous, state the assumption you are making and proceed; only stop for genuine blockers.
