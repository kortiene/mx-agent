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

The same checks run in CI (`.github/workflows/ci.yml`) and must pass on every PR.

### Lint and format configuration

- Formatting is pinned by `rustfmt.toml` (stable options only); run `cargo fmt`
  to apply.
- Clippy honors the MSRV in `clippy.toml`.
- Shared lints are declared once in `[workspace.lints]` in the root `Cargo.toml`
  and inherited by each crate via `[lints] workspace = true`. Notably,
  `unsafe_code` is forbidden and `missing_docs` is a warning (treated as an
  error in CI via `-D warnings`).
- Minimum supported Rust version (MSRV): 1.74.

### Logging

All mx-agent processes emit structured logs via `tracing` (to stderr, so `--json`
command output on stdout is never corrupted). Configure logging with:

| Variable | Values | Default | Purpose |
|---|---|---|---|
| `MX_AGENT_LOG` | `RUST_LOG`-style directive | unset | Log filter (preferred) |
| `RUST_LOG` | `RUST_LOG`-style directive | unset | Log filter fallback |
| `MX_AGENT_LOG_FORMAT` | `human` \| `json` | `human` | Output format |

The CLI `-v`/`-vv`/`-vvv` flags raise the default level (`warn` → `info` →
`debug` → `trace`) when no filter env var is set.

```bash
MX_AGENT_LOG_FORMAT=json mx-agent -vv agent list   # JSON logs on stderr
MX_AGENT_LOG=mx_agent_daemon=debug,info mx-agent daemon status
```

Credentials are wrapped in `mx_agent_telemetry::Secret`, which renders as
`***redacted***` in `Debug`/`Display`, and `mx_agent_telemetry::redact` blanks
values for secret-looking keys. Never log raw tokens or keys.

### Daemon lifecycle

The background daemon is managed through the CLI:

```bash
mx-agent daemon start              # start detached in the background
mx-agent daemon start --foreground # run in the current terminal (Ctrl-C to stop)
mx-agent daemon status             # human-readable status (exit 3 if not running)
mx-agent daemon status --json      # pid, uptime, socket path, version as JSON
mx-agent daemon stop               # graceful shutdown (SIGTERM, then SIGKILL)
```

Runtime state lives under `$XDG_RUNTIME_DIR/mx-agent/` (override with
`MX_AGENT_RUNTIME_DIR`): a `daemon.json` status file, the intended
`daemon.sock` path, and a `daemon.log` for background output.

Most other commands are still placeholders pending later roadmap phases.
