---
description: Review a PR produced by /implement and comment when useful
argument-hint: "<pr-url-or-number> [spec-file]"
---
Review this pull request, which may have been produced by `/implement`:

PR: $1
Spec file, if provided: $2
Extra context/notes from me (may be empty): ${@:3}

Do not modify code unless explicitly asked. Focus on review quality, correctness, security, scope control, and actionable feedback. If the PR has actionable issues, comment on the PR when useful.

Workflow:

1. Validate inputs
   - If `$1` is missing, stop and ask for a PR URL or number.
   - If `$2` is provided, read the spec file completely and review the PR against it.
   - If `$2` is provided but missing, report that clearly and continue reviewing against repository context if possible.

2. Read repository context before reviewing
   - `README.md`
   - `CONTRIBUTING.md`
   - `docs/architecture.md`
   - root `Cargo.toml`
   - affected crate `Cargo.toml` files
   - changed source files, tests, and docs from the PR

3. Inspect the PR
   - Use `gh` (or `~/.local/bin/gh` if needed) to inspect PR metadata, commits, changed files, checks, and diff.
   - Determine the base branch and compare the PR against the correct base.
   - Read enough of the changed files in context to understand the implementation, not just the diff.

4. Review against the spec and repository constraints
   - Verify whether the PR satisfies the provided spec and acceptance criteria.
   - Check that the implementation does not exceed the requested scope.
   - Confirm docs/status tables are updated when behavior changes.
   - Confirm tests cover the new behavior and important edge cases.

5. Check mx-agent-specific requirements
   - Preserve daemon/CLI separation: CLI stays stateless; daemon owns long-lived Matrix state, credentials, crypto, policy, and supervision.
   - Ensure the coding agent never sees Matrix tokens or device keys.
   - Ensure Matrix room membership is not treated as execution permission.
   - Ensure privileged requests remain Ed25519-signed and checked against local deny-by-default policy.
   - Verify Unix-only assumptions are preserved; do not add Windows paths or behavior.
   - Verify no `unsafe` Rust is introduced.
   - Check Rust MSRV 1.74 compatibility.
   - Check public APIs have documentation.
   - Verify secrets are never logged or posted; use existing redaction/`Secret` patterns.
   - Preserve CLI UX: human-readable output by default, `--json` for automation.
   - Do not accept misleading alpha-status claims or docs implying unimplemented behavior exists.

6. Look for general review issues
   - Correctness bugs or incomplete behavior
   - Missing error handling or poor error messages
   - Race conditions, restart/retry issues, or persistence gaps
   - Security regressions or trust/policy bypasses
   - Protocol/schema compatibility issues
   - Weak tests or missing negative tests
   - Overly broad rewrites or unrelated changes
   - Formatting, clippy, or docs-warning risks

7. Verify checks when practical
   - Inspect existing PR/CI check status with `gh`.
   - When practical and appropriate locally, run relevant checks:
     - `cargo fmt --check`
     - `cargo clippy --all-targets --all-features -- -D warnings`
     - `cargo test --all`
     - `cargo build --all`
   - If checks cannot be run, explain why and recommend exact commands.

8. Comment on the PR when needed
   - If the PR has actionable issues, post a clear PR review comment or review summary using `gh`.
   - Prefer one consolidated review comment over many noisy comments unless line-specific feedback is important.
   - Comment only when feedback is useful, actionable, and relevant to the PR.
   - Do not post a PR comment for purely local observations unless they affect the PR.
   - If the PR looks good, either approve if appropriate or leave a concise positive summary, depending on available permissions.
   - Never post secrets, tokens, credentials, private paths that matter, or sensitive data in PR comments.
   - In the local final report, state exactly what PR comments or reviews were posted, if any.

9. Produce a structured local review report
   - Summary
   - Spec compliance assessment
   - Security assessment
   - Correctness issues
   - Testing/docs gaps
   - Required fixes
   - Optional improvements
   - Checks reviewed or run, with results
   - PR comments posted, if any
   - Final recommendation: approve / request changes / needs more info

Important: do not implement fixes during review unless explicitly asked. Review first; comment on the PR only when it improves the PR outcome.
