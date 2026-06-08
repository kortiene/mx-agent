---
description: Review the working-tree implementation in the phased ADW pipeline
argument-hint: "<spec-file-or-empty> <issue-and-change-context>"
---
Review the implementation currently in the working tree for this change. There is no pull
request yet — review the staged and uncommitted changes against the issue and, if one was
created, the spec.

Spec file, if any: $1

Issue and change context:

${@:2}

## What to do

1. Understand the change.
   - Inspect the working-tree diff against the base branch and read the changed files in
     context, not just the diff.
   - Read the issue/acceptance criteria and the spec (`$1`) when provided; treat them as the
     definition of done.

2. Review for quality and correctness.
   - Correctness bugs, missing error handling, weak or missing tests, untested edge cases.
   - Scope control: the change should not exceed what the issue/spec asked for.
   - Docs/status tables updated when behavior changes; new public APIs documented.

3. Check mx-agent constraints.
   - Daemon/CLI separation: the CLI stays stateless; the daemon owns long-lived Matrix state,
     credentials, crypto, policy, and supervision.
   - The coding agent must never see Matrix tokens or device keys; no secrets in logs/output.
   - Matrix room membership is not execution permission; privileged requests stay
     Ed25519-signed and checked against local deny-by-default policy.
   - Unix-only; no `unsafe` Rust; Rust MSRV 1.74; no misleading alpha claims.

4. Grade every finding by severity:
   - `blocker` — must be fixed before merge. A later `patch` phase auto-resolves these.
   - `tech_debt` — should be addressed but is not blocking. Reported, not auto-fixed.
   - `skippable` — minor or nit. Reported only.

5. Author the release text.
   - This is the final authoring phase for most runs, so write a high-quality commit message
     and PR body (see the output instructions below) describing the change, the tests/checks
     run, and any security considerations.

Do not modify code in this phase — only report findings; the `patch` phase fixes blockers.
