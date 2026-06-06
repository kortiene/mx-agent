---
description: Assess mx-agent feature completeness against docs, roadmap, code, and GitHub issues
argument-hint: "[focus area or release target]"
---
Think hard and perform a thorough repository assessment of `mx-agent`.

Optional focus area or release target from me: $ARGUMENTS

Read all files needed to accurately evaluate how close the project is to being fully feature-complete relative to its README, architecture document, roadmap, and GitHub issue state.

Start by reviewing at minimum:

- `README.md`
- `CONTRIBUTING.md`
- `docs/architecture.md`
- `docs/roadmap-rust.md`
- `docs/user-guide.md`
- `docs/alpha-release-checklist.md`
- root `Cargo.toml`
- all crate `Cargo.toml` files
- relevant source modules across all workspace crates:
  - `mx-agent-cli`
  - `mx-agent-daemon`
  - `mx-agent-protocol`
  - `mx-agent-ipc`
  - `mx-agent-policy`
  - `mx-agent-sandbox`
  - `mx-agent-telemetry`

Also inspect GitHub issue state with `gh issue list` / `gh issue view` as needed, including recently completed work and remaining open issues.

Evaluate feature completeness across these areas:

1. CLI/daemon separation
2. Matrix login/session/sync
3. Workspace create/join/attach/status
4. Agent registration/discovery/liveness
5. Trust/signing model
6. Policy enforcement
7. IPC transport/security
8. Exec lifecycle
9. Tool/call lifecycle
10. Task orchestration lifecycle
11. Invocation tracking/cancellation
12. Context sharing/artifacts
13. Streaming/stdin/stdout/stderr/PTY
14. Approval workflow
15. Sandbox backends
16. Telemetry/logging/secret redaction
17. E2EE support
18. Restart/recovery behavior
19. Integration/E2E testing
20. Documentation accuracy

For each area, report:

- status: complete / partial / missing
- evidence from files or issues
- gaps or risks
- security implications
- recommended next work
- whether docs accurately reflect implementation

Important constraints:

- Do not assume behavior exists just because docs describe it.
- Distinguish implemented behavior from placeholders.
- Preserve the mx-agent security model:
  - CLI must not own Matrix credentials.
  - Daemon owns long-lived state.
  - Room membership is not execution permission.
  - Privileged requests require signing/trust/policy checks.
  - No secrets in logs.
- Respect Unix-only scope and no `unsafe`.
- Do not make code changes unless explicitly asked.

End with:

- overall feature-completeness estimate
- top blockers to feature complete
- recommended GitHub issues to file or update
- recommended validation commands:
  - `cargo fmt --check`
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all`
  - `cargo build --all`
  - relevant Matrix/Tuwunel E2E scripts
