---
description: Implement a spec file end-to-end
argument-hint: "<spec-file>"
---
Implement the specification in this file end-to-end:

$1

Extra context/notes from me (may be empty): ${@:2}

Do not stop after planning unless the spec is genuinely ambiguous, unsafe, impossible, or blocked by missing information. Read the spec, implement it, test it, and report the result.

Workflow:

1. Read and understand the spec
   - Read the spec file at `$1` completely.
   - Treat the spec as the source of truth for scope and acceptance criteria.
   - If the file does not exist, stop and report the missing path.
   - If the spec is ambiguous, state the ambiguity, make a reasonable assumption when safe, and proceed. Stop only for real blockers.

2. Read repository context before editing
   - `README.md`
   - `CONTRIBUTING.md`
   - `docs/architecture.md`
   - root `Cargo.toml`
   - relevant crate `Cargo.toml` files and source files for the spec
   - existing tests and docs around the affected behavior

3. Summarize and plan briefly
   - Summarize the requested implementation in a few bullets.
   - Identify the owning crate(s), modules, and existing patterns.
   - List the concrete implementation steps.
   - Then proceed with implementation.

4. Implement the spec completely
   - Make the smallest correct change that satisfies the spec.
   - Keep changes focused, idiomatic, and testable.
   - Preserve existing repository conventions and alpha-status boundaries.
   - Do not introduce broad rewrites unless the spec explicitly requires them.
   - Update docs/status tables when behavior changes.
   - Add or update tests that cover the new behavior.

5. Preserve mx-agent constraints
   - Keep the CLI stateless; daemon owns long-lived Matrix state, credentials, crypto, policy, and supervision.
   - The coding agent must never see Matrix tokens or device keys.
   - Matrix room membership does not imply execution permission.
   - Privileged requests must remain Ed25519-signed and checked against local deny-by-default policy.
   - Unix only; do not add Windows paths or assumptions.
   - Do not use `unsafe`; the workspace forbids unsafe Rust.
   - Respect Rust MSRV 1.74.
   - Document new public APIs because missing docs can fail CI.
   - Do not log secrets; use existing redaction/`Secret` patterns.
   - Preserve CLI UX: human-readable output by default, `--json` for automation.
   - Do not imply unimplemented alpha behavior exists unless this implementation actually adds it.

6. Verify before finishing
   - If Rust code changed, run:
     - `cargo fmt --check`
     - `cargo clippy --all-targets --all-features -- -D warnings`
     - `cargo test --all`
     - `cargo build --all`
   - Run any additional checks named in the spec.
   - If a check fails, fix the issue and rerun the relevant check when practical.
   - If a check cannot be run, explain why and recommend the exact command.

7. Final report
   - Spec implemented: `$1`
   - Files changed
   - Behavior implemented
   - Tests/checks run and results
   - Any assumptions made
   - Any remaining risks, limitations, or follow-up work

Important: do not merely create another plan. Implement the provided spec end-to-end.
