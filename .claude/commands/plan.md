---
description: Create a detailed implementation spec in specs/ without implementing it
argument-hint: "<prompt>"
---
Create a detailed implementation specification for this request:

$ARGUMENTS

Do not implement the requested feature. Only create a planning/spec document.

Workflow:
1. Read enough repository context to make the plan accurate:
   - `README.md`
   - `CONTRIBUTING.md`
   - `docs/architecture.md`
   - root `Cargo.toml`
   - relevant crate `Cargo.toml` files and source files for the request
2. Think through the request carefully and identify the owning crate(s), existing patterns, security constraints, and likely edge cases.
3. Create the `specs/` directory if it does not already exist.
4. Write a new Markdown spec file in `specs/`.
   - Derive a short, descriptive, kebab-case filename from the prompt when possible.
   - Prefer a stable name like `specs/<descriptive-slug>.md`.
   - If a file with that name already exists, choose a non-conflicting variant.
5. After writing the spec, report the spec path and a short summary. Do not make code changes beyond the spec file.

The spec must include these sections:

# <Descriptive Title>

## Problem Statement
Explain the user need and current gap.

## Goals
List concrete outcomes this implementation should achieve.

## Non-Goals
List related work that should remain out of scope.

## Relevant Repository Context
Summarize the relevant architecture, crates, modules, current status, and conventions.

## Proposed Implementation
Describe the recommended implementation approach in enough detail for a coding agent to execute later.

## Affected Files / Crates / Modules
List likely files and modules to read or modify.

## CLI / API Changes
Describe any command-line, public API, IPC, or protocol surface changes. State “none” if none are expected.

## Data Model / Protocol Changes
Describe event schema, persistence, policy, or serialization changes. State “none” if none are expected.

## Security Considerations
Call out secret handling, daemon/CLI separation, policy enforcement, signing/trust implications, Unix-only assumptions, and logging/redaction concerns as applicable.

## Testing Plan
List unit, integration, CLI, daemon, policy, protocol, or documentation tests that should be added or updated.

## Documentation Updates
List README, docs, wiki, status-table, or help-text updates needed.

## Risks and Open Questions
Identify ambiguities, blockers, compatibility concerns, and decisions needing confirmation.

## Implementation Checklist
Provide a step-by-step checklist suitable for a coding agent to follow later.

Important constraints to preserve:
- Keep the CLI stateless; daemon owns long-lived Matrix state, credentials, crypto, policy, and supervision.
- The coding agent must never see Matrix tokens or device keys.
- Matrix room membership does not imply execution permission.
- Privileged requests must remain Ed25519-signed and checked against local deny-by-default policy.
- Unix only; do not add Windows paths or assumptions.
- No `unsafe`; respect Rust MSRV 1.74.
- Document new public APIs.
- Do not log secrets; use existing redaction/`Secret` patterns.
- Preserve human-readable output by default and `--json` for automation.
- Do not imply unimplemented alpha behavior exists unless the later implementation actually adds it.
