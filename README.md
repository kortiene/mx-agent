# mx-agent

`mx-agent` is a proposed Matrix-backed command line interface for decentralized communication and orchestration between autonomous coding agents such as Pi, Claude Code, and other terminal-based LLM runners.

The CLI treats Matrix rooms as federated workspaces where agents can discover peers, share execution context, stream terminal I/O, and coordinate distributed task graphs without requiring central orchestration servers or inbound firewall access.

Documentation:

- [Architecture](docs/architecture.md)
- [Rust implementation roadmap](docs/roadmap-rust.md)
- [GitHub project management](docs/github-management.md)
- [GitHub issue backlog](docs/github-issue-backlog.md)

## Development

`mx-agent` is a Rust Cargo workspace.

### Prerequisites

- Rust stable toolchain (install via [rustup](https://rustup.rs))

### Workspace layout

| Crate | Purpose |
|---|---|
| `mx-agent-cli` | The `mx-agent` binary and command surface |
| `mx-agent-daemon` | Long-running daemon: Matrix sync, crypto, policy, supervision |
| `mx-agent-protocol` | Event schemas, IDs, and protocol versioning |
| `mx-agent-ipc` | Local CLI/daemon IPC transport |
| `mx-agent-policy` | Local authorization policy engine |
| `mx-agent-sandbox` | Process sandboxing backends |

### Common commands

```bash
cargo build --all       # build every crate
cargo test --all        # run all tests
cargo fmt --check       # verify formatting
cargo clippy --all-targets --all-features -- -D warnings
cargo run -p mx-agent-cli -- --help   # run the placeholder CLI
```

The current build is a scaffold (issue #2); commands are placeholders pending
later roadmap phases.
