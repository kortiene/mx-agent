---
description: Add or improve end-to-end tests for daemon/IPC/Matrix/process flows
argument-hint: "[spec-file|pr-url-or-number|notes]"
---
Add or improve end-to-end test coverage for this target:

$ARGUMENTS

This command is for heavier end-to-end scenarios, especially behavior crossing CLI, daemon, IPC, Matrix sync, session state, policy, signing, sandbox/process execution, or dev homeserver boundaries. Prefer `/tests` for unit tests and deterministic non-e2e integration tests.

Workflow:

1. Understand the e2e target
   - If the argument is a spec file path, read it completely and identify the end-to-end behavior that needs coverage.
   - If the argument is a PR URL or number, inspect PR metadata, changed files, commits, checks, and diff using `gh` (or `~/.local/bin/gh` if needed).
   - If the argument is notes/free text, treat it as e2e testing goals for the current working tree.
   - If no argument is provided, inspect the current working tree and ask for clarification only if the target is genuinely unclear.

2. Read repository and test infrastructure context before editing
   - `README.md`
   - `CONTRIBUTING.md`
   - `docs/architecture.md`
   - `docs/user-guide.md` if relevant to user-facing flows
   - `dev/matrix/README.md` if Matrix/dev homeserver behavior is relevant
   - root `Cargo.toml`
   - relevant crate `Cargo.toml` files
   - relevant source files, existing tests, ignored integration tests, and scripts
   - `scripts/matrix_dev.sh` and any dedicated Matrix/e2e test scripts when relevant

3. Decide whether e2e coverage is warranted
   - Summarize the behavior under test.
   - Identify what lower-level tests already cover.
   - Add e2e tests only when unit or non-e2e integration tests are insufficient.
   - Prefer a small number of high-value scenarios over broad, slow, flaky coverage.
   - Clearly separate Docker/Matrix/live-service tests from default tests if the project convention requires gating.

4. Add or improve e2e tests
   - Use existing project infrastructure and patterns.
   - For Matrix/dev homeserver scenarios, use `scripts/matrix_dev.sh` and `dev/matrix/README.md` guidance.
   - Do not require real homeserver credentials, real Matrix tokens, or production services.
   - Avoid making default `cargo test --all` depend on Docker, external networks, or live services unless that is already the project convention.
   - Prefer `#[ignore]`, script-gated tests, or clearly documented external prerequisites for Docker/Matrix-dependent tests.
   - Keep tests reproducible, deterministic where possible, and safe to run repeatedly.
   - Avoid arbitrary sleeps; prefer readiness checks, bounded retries, or existing synchronization helpers.
   - Ensure test logs and fixtures do not expose secrets.

5. Preserve mx-agent constraints
   - Keep the CLI stateless; daemon owns long-lived Matrix state, credentials, crypto, policy, and supervision.
   - The coding agent must never see Matrix tokens or device keys.
   - Matrix room membership does not imply execution permission.
   - Privileged requests must remain Ed25519-signed and checked against local deny-by-default policy.
   - E2E tests must not create trust/policy bypasses just to pass.
   - Unix only; do not add Windows paths or assumptions.
   - Do not use `unsafe`; the workspace forbids unsafe Rust.
   - Respect Rust MSRV 1.74.
   - Do not log secrets; use existing redaction/`Secret` patterns.
   - Preserve CLI UX: human-readable output by default, `--json` for automation.
   - Do not imply unimplemented alpha behavior exists unless it is actually implemented.

6. Document how to run the e2e tests
   - Update nearby docs, test comments, or scripts when needed.
   - Clearly list external requirements such as Docker or a dev Matrix homeserver.
   - Include exact commands for setup, execution, and cleanup.

7. Verify before finishing
   - Run the narrowest relevant e2e test first when practical.
   - For normal Rust changes, run:
     - `cargo fmt --check`
     - `cargo clippy --all-targets --all-features -- -D warnings`
     - `cargo test --all`
     - `cargo build --all`
   - For Matrix/dev homeserver e2e tests, when practical, run the project’s script or a documented sequence such as:
     - `scripts/matrix_dev.sh up`
     - `cargo test --all -- --ignored`
     - `scripts/matrix_dev.sh reset`
   - If a check cannot be run, explain why and recommend the exact command.

8. Final report
   - E2E target and scenario covered
   - Test infrastructure used
   - Files changed
   - Tests added or updated
   - Commands run and results
   - External requirements, if any
   - Bugs discovered, if any
   - Remaining gaps, flakes, risks, or follow-up recommendations

Important: focus on end-to-end coverage. Do not broaden product behavior beyond what is necessary to make the e2e scenario testable and safe.
