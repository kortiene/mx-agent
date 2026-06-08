---
description: Resolve blocking review findings in the phased ADW pipeline
argument-hint: "<blocker-findings-and-context>"
---
A self-review found blocking issues in the current implementation. Resolve them.

Blocking findings and context:

$ARGUMENTS

## Instructions

- Address every blocking finding above with the smallest correct change.
- Only fix the listed blockers; do not act on tech-debt or skippable items, and do not start
  unrelated work or broad rewrites.
- Keep tests meaningful — fix the cause, do not weaken assertions.
- Preserve mx-agent constraints: no `unsafe` Rust, MSRV 1.74, daemon/CLI separation, signed
  privileged requests and deny-by-default policy unchanged unless the change requires it, no
  secrets in code/logs/output, Unix-only.
- Report how many blocking findings you fixed (`resolved`) and how many remain (`remaining`).
