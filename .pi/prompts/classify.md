---
description: Classify a GitHub issue into a change type for the phased ADW pipeline
argument-hint: "<issue-number> <issue-context>"
---
Classify GitHub issue #$1 into a single change type for branch naming and commit prefixing.

Issue context (title, body, labels):

$ARGUMENTS

## Instructions

- Choose exactly one `issue_class` from: `feat`, `fix`, `docs`, `chore`, `ci`, `test`, `refactor`.
  - `feat` — new user-visible feature or capability.
  - `fix` — bug fix or correctness change.
  - `docs` — documentation-only change.
  - `chore` — maintenance, deps, tooling with no user-visible behavior change.
  - `ci` — CI/build/workflow change.
  - `test` — test-only change.
  - `refactor` — internal restructuring with no behavior change.
- Prefer the issue's `type:*` label when one is present; otherwise infer from the title and body.
- Do not examine the codebase. Decide only from the context above.
