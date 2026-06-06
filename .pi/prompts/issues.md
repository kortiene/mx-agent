---
description: Implement multiple GitHub issues sequentially using /issue semantics
argument-hint: "<issue-id-or-range> [issue-id-or-range ...] [-- notes]"
---
Implement multiple GitHub issues sequentially for this repository, end to end, using `/issue` semantics for each issue.

Issue selectors and shared notes:

$ARGUMENTS

`/issues` is a batch orchestrator. It must process issues one at a time, in normalized order, and must return to a clean, updated `main` between issues. Do not parallelize. Do not combine multiple issues into one branch or PR unless the user explicitly asks and the issues genuinely require a shared implementation.

Read `.pi/prompts/issue.md` before starting. Treat it as the phase contract for each individual issue. Apply its workflow inline for every issue; do not merely tell the user to run `/issue` separately.

Workflow:

1. Parse and normalize issue selectors
   - Accept single numeric issue IDs, e.g. `12`.
   - Accept inclusive hyphen ranges, e.g. `12-14` expands to `12, 13, 14`.
   - Accept inclusive dot ranges, e.g. `12..14` expands to `12, 13, 14`.
   - Preserve the order written by the user.
   - Expand ranges in place.
   - Deduplicate repeated IDs while preserving the first occurrence.
   - Treat everything after `--` as shared notes/context to pass into each issue workflow.
   - If no issue selector is provided, stop and ask for one or more issue IDs/ranges.
   - If any selector is invalid, stop and report the invalid selector.
   - Print the expanded issue list before starting.
   - If more than 5 issues are selected, ask for confirmation before proceeding.

2. Preflight all selected issues before implementing any of them
   - For each normalized issue ID, run `python adw/work_issue.py <id> --print` to inspect the title, labels, milestone, status, scope, dependencies, and acceptance criteria.
   - Use `~/.local/bin/gh` if `gh` is not on PATH.
   - Use `. "$HOME/.cargo/env"` before cargo commands when needed.
   - If an issue is already CLOSED, mark it as skipped and continue.
   - If an issue is missing or inaccessible, stop and report it.
   - Detect obvious dependency lines such as `Depends on #<id>`.
   - If an issue depends on another selected issue that appears later in the normalized list, recommend reordering and ask whether to continue in the given order.
   - If an issue depends on an open issue that is not selected, ask whether to skip that issue, stop the batch, or continue anyway.
   - Stop for real blockers such as acceptance criteria that conflict with repository security constraints, require real secrets/credentials, or require broad architecture decisions with insufficient detail.

3. Establish batch processing rules
   - Default branch/PR strategy: one issue → one branch → one PR → one merge.
   - Preserve user-provided order after range expansion unless dependency preflight leads to an explicit user-approved reorder.
   - Continue automatically after successfully shipped issues.
   - Skip already-closed issues.
   - If an issue hits a genuine blocker, stop the entire batch unless the user explicitly instructs you to skip blocked issues.
   - If CI fails for an issue, fix it as `/issue` would; do not move on while that PR is red.
   - If the repository is dirty unexpectedly between issues, stop and report the dirty state.

4. Process each issue sequentially using `/issue` semantics
   For each issue ID that was not skipped:
   - Confirm the repository is on `main`, updated from origin, and has a clean working tree before starting.
   - Run the equivalent of `/issue <id> <shared notes>` inline, following `.pi/prompts/issue.md` completely:
     - start the issue with `python adw/work_issue.py <id> --print` and `python adw/work_issue.py <id>`
     - read repository context
     - decide whether a `/plan`-style spec is needed
     - implement using `/implement` semantics
     - strengthen focused tests using `/tests` semantics
     - evaluate e2e coverage using `/e2e_tests` semantics
     - self-review using `/review` semantics
     - run required checks
     - commit with a message ending in `closes #<id>`
     - push and open a PR
     - wait for CI and fix failures until green
     - perform final PR review
     - merge with squash and delete the branch
     - return to `main` and `git pull --rebase origin main`
   - Confirm the issue is closed after merge.
   - Record the result, PR number, spec path or spec-skip reason, tests added, e2e decision, checks, assumptions, and any follow-up notes.
   - Only then continue to the next issue.

5. Preserve mx-agent constraints for every issue
   - Keep the CLI stateless; daemon owns long-lived Matrix state, credentials, crypto, policy, and supervision.
   - The coding agent must never see Matrix tokens or device keys.
   - Matrix room membership does not imply execution permission.
   - Privileged requests must remain Ed25519-signed and checked against local deny-by-default policy.
   - Unix only; do not add Windows paths or assumptions.
   - Do not use `unsafe`; the workspace forbids unsafe Rust.
   - Respect Rust MSRV 1.74.
   - Document new public APIs.
   - Never log secrets; use existing redaction/`Secret` patterns.
   - Preserve CLI UX: human-readable output by default, `--json` for automation.
   - Do not imply unimplemented alpha behavior exists unless a given issue actually implements it.

6. Final batch report
   At the end, produce a concise table with one row per normalized issue:

   | Issue | Result | PR | Spec | Tests | E2E | Notes |
   |---|---|---|---|---|---|---|

   Include:
   - Total selected
   - Total shipped
   - Total skipped
   - Total blocked
   - Final branch
   - Final working tree status
   - Any issue order/dependency decisions
   - Any assumptions, risks, limitations, or follow-up work

Important: `/issues` is intentionally sequential and conservative. Each issue should be fully shipped or explicitly skipped/blocked before moving to the next one.
