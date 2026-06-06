---
description: Prime the agent with mx-agent repository architecture and contribution rules
argument-hint: "[task/context]"
---
Prime yourself for working in the `mx-agent` repository before taking action.

Optional task/context from me: $ARGUMENTS

First, read and internalize the repository context:
- `README.md`
- `CONTRIBUTING.md`
- `docs/architecture.md`
- root `Cargo.toml`
- the relevant crate `Cargo.toml` and source files for the requested task

Project summary:
`mx-agent` is a Unix-only Rust workspace implementing a Matrix-backed CLI + daemon for decentralized orchestration between autonomous coding agents. It turns Matrix rooms into federated workspaces where agents can discover peers, share context, invoke tools, stream I/O, and coordinate tasks without inbound ports or a central orchestration server.

Workspace/crate map:
- `mx-agent-cli`: stateless CLI binary named `mx-agent`
- `mx-agent-daemon`: long-running daemon for Matrix sync, credentials, crypto, policy, and supervision
- `mx-agent-protocol`: protocol/event schemas, IDs, signing-related protocol types, and versioning
- `mx-agent-ipc`: local Unix-socket JSON-RPC IPC between CLI and daemon
- `mx-agent-policy`: deny-by-default local authorization policy engine
- `mx-agent-sandbox`: sandbox backends for process execution
- `mx-agent-telemetry`: logging, tracing, and secret-redaction helpers

Architecture and security constraints:
- The coding agent must never see Matrix tokens or device keys.
- Matrix room membership does not imply execution permission.
- Privileged requests are Ed25519-signed and checked against local policy.
- The CLI is stateless; the daemon owns long-lived state.
- Unix only. Do not add Windows assumptions or support paths unless explicitly requested.
- No `unsafe`; the workspace forbids unsafe Rust.
- Respect Rust MSRV 1.74.
- Public APIs should be documented because missing docs can become CI warnings.
- Do not log secrets. Use existing redaction/`Secret` patterns.

Current status to preserve:
This is public alpha v0.1.0. Daemon lifecycle, IPC, logging, protocol schema, signing, policy parser, and the `none` sandbox are implemented. Many higher-level CLI subcommands intentionally parse arguments but report “not implemented yet”. Do not imply unimplemented behavior exists unless you implement it.

Working rules:
- Identify the owning crate and existing patterns before editing.
- Keep changes focused, idiomatic, and testable.
- Preserve CLI UX conventions: human-readable by default, `--json` for automation.
- Preserve daemon/CLI separation.
- Use safe abstractions such as `nix`/`rustix` for Unix operations.
- Avoid broad rewrites unless explicitly requested.
- Update docs/status tables when behavior changes.

Before finalizing code changes, run or clearly recommend:
- `cargo fmt --check`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo test --all`
- `cargo build --all`

After reading the relevant files, summarize the repository context in a few bullets, identify the likely crate(s) involved in the task/context above, and propose a short plan before making code changes.
