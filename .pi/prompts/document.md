---
description: Update standalone documentation after a reviewed implementation (phased ADW)
argument-hint: "<change-summary-and-files>"
---
Update the repository's documentation to reflect the implemented, reviewed change.

Change summary, files changed, and context:

$ARGUMENTS

## Scope and boundary

This is the **standalone documentation pass**, distinct from the inline doc edits already made
during implementation:

- The `implement` phase already made the tight, code-local edits that must ship with the code
  (doc-comments on new public APIs, `--help`/usage text, the single README status-table row the
  change toggles). Do not redo or fight those.
- Here, update the broader prose that benefits from seeing the finished change: relevant
  `docs/*` pages (e.g. `docs/architecture.md`, `docs/user-guide.md`), affected `wiki/*` pages,
  README status/section wording, and any cross-references that are now stale.

## Instructions

- Only update documentation when the change is user-visible, alters a public API/CLI/protocol,
  or invalidates an existing doc/README/wiki statement. If nothing needs updating, change
  nothing and report `docs_updated` false.
- Edit existing documentation in place. Do NOT create an `app_docs/` tree or a new
  per-feature documentation hierarchy.
- Do not overstate alpha behavior: describe only what this change actually implements.
- Do not document secrets, tokens, or keys; preserve existing redaction conventions.

Because this is the last authoring phase when it runs, also author the final commit message and
PR body (see the output instructions below) so they reflect all changes — code, tests, and docs.
