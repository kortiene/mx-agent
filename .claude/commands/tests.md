---
description: Add or improve focused non-e2e tests for a spec, PR, or working tree
argument-hint: "[spec-file|pr-url-or-number|notes]"
---
Add or improve focused non-e2e test coverage for this target:

$ARGUMENTS

This command is for unit tests, deterministic integration tests that do not require external services, CLI argument/output tests, policy/protocol/schema tests, and negative/security regression tests. Do not add Docker/Matrix/live-service e2e tests here; use `/e2e_tests` for those.

Workflow:

1. Understand the testing target
   - If the argument is a spec file path, read it completely and identify the behavior that should be covered by tests.
   - If the argument is a PR URL or number, inspect PR metadata, changed files, commits, checks, and diff using `gh` (or `~/.local/bin/gh` if needed).
   - If the argument is notes/free text, treat it as testing goals for the current working tree.
   - If no argument is provided, inspect the current working tree and ask for clarification only if the target is genuinely unclear.

2. Read repository context before editing
   - `README.md`
   - `CONTRIBUTING.md`
   - `docs/architecture.md`
   - root `Cargo.toml`
   - relevant crate `Cargo.toml` files
   - relevant source files and existing tests around the target behavior

3. Identify coverage gaps
   - Summarize the behavior under test.
   - Identify existing tests that already cover it.
   - Identify missing edge cases, negative cases, error handling, CLI JSON/human output, policy/security checks, protocol/schema compatibility, and regression risks.
   - Prefer the smallest test layer that gives confidence: unit tests before integration tests, integration tests before e2e tests.

4. Add or improve tests
   - Add focused, deterministic tests that cover the gaps.
   - Do not implement new product behavior except minimal testability hooks when absolutely necessary.
   - Do not weaken assertions or delete meaningful coverage to make tests pass.
   - Do not introduce flaky sleeps, timing-sensitive assertions, network dependencies, or external service requirements.
   - Do not use real secrets, Matrix credentials, tokens, or private keys in fixtures.
   - Keep tests compatible with Rust MSRV 1.74.
   - Document public test helpers if they are public APIs; prefer private helpers when possible.

5. Preserve mx-agent constraints
   - Keep the CLI stateless; daemon owns long-lived Matrix state, credentials, crypto, policy, and supervision.
   - The coding agent must never see Matrix tokens or device keys.
   - Matrix room membership does not imply execution permission.
   - Privileged behavior must remain signed and checked against local deny-by-default policy.
   - Unix only; do not add Windows paths or assumptions.
   - Do not use `unsafe`; the workspace forbids unsafe Rust.
   - Do not log secrets; use existing redaction/`Secret` patterns.
   - Preserve CLI UX: human-readable output by default, `--json` for automation.
   - Do not imply unimplemented alpha behavior exists unless it is actually implemented.

6. Verify before finishing
   - Run the most relevant test command first, for example `cargo test -p <crate> <test-name>` when practical.
   - Then run, when Rust changed:
     - `cargo fmt --check`
     - `cargo test --all`
     - `cargo clippy --all-targets --all-features -- -D warnings`
     - `cargo build --all`
   - If a check fails, fix the issue and rerun the relevant check when practical.
   - If a check cannot be run, explain why and recommend the exact command.

7. Final report
   - Testing target
   - Files changed
   - Tests added or updated
   - Coverage gaps closed
   - Bugs discovered, if any
   - Checks run and results
   - Remaining coverage gaps or follow-up recommendations

Important: focus on tests. Do not broaden the implementation scope or add e2e infrastructure unless explicitly asked.
