# mx-agent

**Matrix-backed CLI + daemon for decentralized orchestration between autonomous coding agents** — Pi, Claude Code, and other terminal-based LLM runners.

[![CI](https://github.com/kortiene/mx-agent/actions/workflows/ci.yml/badge.svg)](https://github.com/kortiene/mx-agent/actions/workflows/ci.yml)
[![Status: public alpha](https://img.shields.io/badge/status-public%20alpha-orange)](#project-status)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)](#license)
[![MSRV: 1.74](https://img.shields.io/badge/rustc-1.74%2B-93450a)](#prerequisites)
[![Platform: Unix](https://img.shields.io/badge/platform-Linux%20%7C%20macOS-555)](#project-status)

mx-agent turns Matrix rooms into **federated workspaces** where agents discover peers, share execution context (diffs, plans, env snapshots), invoke named tools, stream terminal I/O, and coordinate a distributed task graph — **without a central orchestration server and without any inbound firewall port**.

📖 **[Wiki](https://github.com/kortiene/mx-agent/wiki)** · [Getting Started](https://github.com/kortiene/mx-agent/wiki/Getting-Started) · [AI Agent Orchestration](https://github.com/kortiene/mx-agent/wiki/AI-Agent-Orchestration) · [Architecture](docs/architecture.md)

---

## Why mx-agent?

Traditional remote-execution tooling assumes a box you can reach inbound — an SSH port, an RPC listener, a VPN or bastion. That breaks the moment your agents live behind NAT, corporate firewalls, or a home router, and it tends to hand long-lived secrets to the very LLM you'd rather not trust with them.

mx-agent inverts that:

| Traditional remote execution | mx-agent |
|---|---|
| Needs an **inbound port** (SSH/RPC/agent listener) | **Outbound-only** — daemons connect *out* to a homeserver; nothing listens inbound |
| NAT/firewall traversal needs a **VPN/bastion/tunnel** | Works anywhere an HTTPS connection to a homeserver works |
| A **central coordinator** is a single point of failure | **Federated** — state lives in Matrix room history; no central mx-agent server |
| "Can reach the box" ≈ "**can run anything**" | **Room membership ≠ execution rights** — every privileged request is Ed25519-signed and checked against deny-by-default local policy |
| Long-lived secrets **handed to the agent** | The coding agent **never sees** Matrix tokens or device keys |

If a box can sync with a homeserver, it can participate — even one that accepts no inbound connections at all.

---

## Project status

**Public alpha (v0.2.0).** The architecture, protocol schema, IPC layer, policy engine, Ed25519 signing, and sandbox abstraction are in place, and the command groups run against a real Matrix homeserver through the daemon. Matrix-backed remote `call` and `exec` (batch and interactive `--pty`) are implemented behind daemon IPC, including signed Matrix stdin/resize/cancel controls for live remote exec. A **live daemon scheduler loop** now auto-drives assigned, signed, policy-allowed tasks from real `com.mxagent.task.v1` room state (claiming with `state_rev`, dispatching, finalizing, and recovering stale work on restart) using local tool/exec dispatch by default, and can instead route that task dispatch through the signed Matrix-backed `call`/`exec` transport (`MX_AGENT_TASK_DISPATCH=matrix`) so a task action runs through the same verify → trust → policy → runner pipeline as a direct CLI invocation. Interactive `exec --pty` is now daemon-mediated too: the daemon allocates the pseudo-terminal and streams it over local IPC, and over the signed Matrix transport for remote `--room`/`--agent` targets (with live stdin, terminal resize, and cancel). A **periodic heartbeat loop** (roadmap Phase 4) now emits `com.mxagent.heartbeat.v1` timeline events every 30 seconds per owned agent; `agent list` and `agent show` surface the computed liveness verdict (`active`/`stale`/`offline`) and a relative `last_seen` age in human and `--json` output. Each capability below is tagged so you always know what runs today.

| Area | Status |
|---|---|
| Daemon lifecycle (`start` / `status` / `stop`), background + foreground | ✅ Implemented |
| Local IPC: Unix-socket JSON-RPC 2.0 with `0600` perms + peer-UID check (`SO_PEERCRED` on Linux, `LOCAL_PEERCRED` on macOS/BSD) | ✅ Implemented |
| Structured logging, secret redaction, dev Matrix homeserver (Tuwunel) | ✅ Implemented |
| Protocol event schema, Ed25519 signing, policy parser, sandbox selection | ✅ Implemented |
| `auth`, `workspace`, `agent`, `trust`, `approval`, `share`, `invocation` commands fully daemon-IPC-mediated (CLI never restores a Matrix session/client) | ✅ Implemented |
| Task state: `task create` / `update` / `list` / `graph` / `watch` (daemon-IPC, over Matrix) | ✅ Implemented |
| Structured task actions (`tool` / `exec`), lifecycle-transition validation, stable task result schema | ✅ Implemented |
| Daemon task-orchestration engine: scheduler, optimistic `state_rev` claiming, tool/exec dispatch, policy + trust/signature + approval enforcement, restart recovery, DAG diagnostics | ✅ Implemented (engine + tests) |
| Live daemon scheduler loop: auto-claims assigned, signed, policy-allowed tasks from room state and runs them, with restart recovery | ✅ Implemented (local tool/exec dispatch by default; signed Matrix-backed `call`/`exec` task dispatch is opt-in via `MX_AGENT_TASK_DISPATCH=matrix`) |
| `call` / `exec` runners | 🟡 `call` and `exec` (batch and interactive `--pty`) support signed Matrix-backed remote daemon dispatch when `--room`/`--agent` are provided; live remote exec supports signed stdin/cancel controls and PTY resize |
| Sandbox backends | ✅ Implemented (`none` fallback by default; `bubblewrap` and Docker/Podman container backends are policy-selectable; `read_only_paths`/`writable_paths` bind-mount confinement and `network` policy enforced end-to-end for batch exec; interactive `--pty` has baseline controls only; no seccomp/rlimit/UID-GID remap) |
| E2EE privileged-event handling | ✅ Implemented (decrypts privileged events; fails safe on undecryptable events) |
| Encryption-on-create | ✅ Implemented (opt-in): `workspace create --e2ee on` makes the room born encrypted (Megolm v1 via `initial_state`) and reports `encrypted: true`; default remains unencrypted (`--e2ee off`). Encryption is a transport property only — signing+trust+policy+approval remain the execution gate. Turning E2EE on by default is a separate rollout (issue #240) |
| E2EE production hardening | 🟡 Implemented: persistent daemon-owned crypto store (device identity + Megolm sessions survive restart); device verification (`device list`/`show`/`verify` — out-of-band fingerprint and interactive emoji/SAS); cross-signing bootstrap/observe (`auth cross-signing`); server-side key backup/recovery (`recovery enable`/`status`/`recover`); and an optional, additive `require_verified_device` policy gate. Matrix device verification is an advisory **transport** signal — signing+trust+policy remain the execution gate. Interactive SAS is operator-attended; see the [security hardening guide](docs/security-hardening.md). Live coverage (issue #260) exercises decrypt-after-restart from the persistent crypto store, key-backup restore across a re-provision, and the two-daemon SAS flow |
| Large-output artifact mode | ✅ Implemented (Matrix media offload, SHA-256 integrity, optional zstd compression, tail preview); very-large-output tuning remains planned |
| Unified task↔remote-invocation id: a task records the id of the invocation that runs it, and `task cancel` drives that linked invocation to `cancelled` (signed/ownership-checked) and finalizes the task | ✅ Implemented |
| Interactive PTY over IPC/remote | ✅ Implemented (daemon-allocated PTY streamed over IPC; remote `--room`/`--agent` PTY over the signed Matrix transport with stdin/resize/cancel) |
| Periodic heartbeat loop; agent liveness (`active`/`stale`/`offline`) in `agent list` / `agent show` | ✅ Implemented (daemon emits `com.mxagent.heartbeat.v1` every 30s per owned agent; verdict combines durable `last_seen_ts` + latest heartbeat event; CLI renders liveness + relative `last_seen` age in human and `--json` output; roadmap Phase 4 delivered) |

**Platform: Unix only** (Linux and macOS). Windows was intentionally dropped — the project relies on Unix-domain-socket IPC and Unix process semantics.

---

## Quickstart

Everything here runs today. (For the full conceptual walkthrough, see the [Getting Started](https://github.com/kortiene/mx-agent/wiki/Getting-Started) wiki page.)

### Prerequisites

- A Unix host (Linux or macOS)
- Rust stable toolchain, **1.74+** (install via [rustup](https://rustup.rs))

### Build

```bash
git clone https://github.com/kortiene/mx-agent.git
cd mx-agent
cargo build --all --release
```

### Explore the command surface

```bash
cargo run -p mx-agent-cli -- --help        # or ./target/release/mx-agent --help
```

### Run the daemon

```bash
mx-agent daemon start                 # start detached in the background
mx-agent daemon status                # human-readable status (exit 3 if not running)
mx-agent daemon status --json         # pid, uptime, socket path, version as JSON
mx-agent daemon stop                  # graceful shutdown (SIGTERM, then SIGKILL)
```

The daemon owns all long-lived state (Matrix session, keys, policy). The CLI is stateless and talks to it over `$XDG_RUNTIME_DIR/mx-agent/daemon.sock`. The `auth` / `workspace` / `agent` / `trust` / `approval` / `share` / `invocation` and `task` command groups run against a real Matrix homeserver entirely through the daemon over local IPC today — the stateless CLI never reads the Matrix session file or builds a Matrix client itself (`auth login` stays CLI-initiated to receive the password and hand the session to the daemon). `call` and `exec` — including interactive `exec --pty` — are daemon-mediated local loopback by default and become signed Matrix-backed remote operations when `--room` and `--agent` target a registered, trusted, policy-allowed remote agent. Live remote exec stdin/cancel controls are signed and policy/ownership checked by the target daemon; an interactive PTY's window-resize is likewise a signed control event the target verifies by signature, trust, and requester ownership before applying. See [Project status](#project-status) for the full breakdown.

---

## How it works

```text
 coding agent / shell  ──spawns──▶  mx-agent (CLI, stateless)
                                          │  JSON-RPC over Unix socket (0600, SO_PEERCRED)
                                          ▼
                                   mx-agent daemon  ──signs──▶  com.mxagent.exec.request.v1 (Ed25519)
                                          │  Matrix Client-Server API (+ E2EE)
                                          ▼
                          Matrix homeserver + federation  ◀──▶  remote daemon ──▶ verify → policy → process
```

A *local* exec follows the **same path** as a remote one: the daemon signs an event, publishes it, and its own `/sync` loop receives it back through the full verify → policy → runner pipeline. See [Core Concepts](https://github.com/kortiene/mx-agent/wiki/Core-Concepts) and [Architecture](docs/architecture.md).

## Security posture

mx-agent is **zero-trust and deny-by-default**: room membership grants nothing on its own.

- Every privileged request is **Ed25519-signed** and checked against **local policy** before running anything; request types that carry nonce/expiry fields are also replay/expiry checked.
- The coding agent **never sees** Matrix tokens or device keys — they stay inside the daemon (`0600`, user-owned).
- Child processes start from an **environment allowlist** with secret scrubbing (`GITHUB_TOKEN`, `OPENAI_API_KEY`, `AWS_*`, …).
- The local IPC socket enforces a **peer-UID check** (`SO_PEERCRED` on Linux, `LOCAL_PEERCRED` on macOS/BSD) and refuses cross-user or world-accessible runtime dirs.
- The workspace **forbids `unsafe` Rust** (`unsafe_code = "forbid"`).

Full details and a complete `policy.toml`: [Security & Sandboxing](https://github.com/kortiene/mx-agent/wiki/Security-and-Sandboxing) · [Security hardening guide](docs/security-hardening.md).

---

## Documentation

| Doc | What it covers |
|---|---|
| **[Wiki](https://github.com/kortiene/mx-agent/wiki)** | Conceptual guides: getting started, core concepts, protocol spec, security, AI-agent orchestration |
| [Alpha user guide](docs/user-guide.md) | Install, log in, create a workspace, register agents, run the two-agent demo |
| [Architecture](docs/architecture.md) | Full system design, protocol, state model, security boundaries |
| [Security hardening guide](docs/security-hardening.md) | Safe defaults and unsafe options for tokens, trust, policy, sandboxing, audit |
| [Alpha release checklist](docs/alpha-release-checklist.md) | The alpha gate, known limitations, rollback/revocation guidance |
| [Rust implementation roadmap](docs/roadmap-rust.md) | Implementation phases |
| [GitHub management](docs/github-management.md) · [Issue backlog](docs/github-issue-backlog.md) | Project process |

---

## Development

`mx-agent` is a Rust Cargo workspace.

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
cargo run -p mx-agent-cli -- --help   # explore the CLI command surface
```

The same checks run in CI (`.github/workflows/ci.yml`) and must pass on every PR.

### Lint and format configuration

- Formatting is pinned by `rustfmt.toml` (stable options only); run `cargo fmt` to apply.
- Clippy honors the MSRV in `clippy.toml`.
- Shared lints are declared once in `[workspace.lints]` in the root `Cargo.toml` and
  inherited by each crate via `[lints] workspace = true`. Notably, `unsafe_code` is
  forbidden and `missing_docs` is a warning (treated as an error in CI via `-D warnings`).
- Minimum supported Rust version (MSRV): 1.74.

### Logging

All mx-agent processes emit structured logs via `tracing` (to stderr, so `--json`
command output on stdout is never corrupted). Configure logging with:

| Variable | Values | Default | Purpose |
|---|---|---|---|
| `MX_AGENT_LOG` | `RUST_LOG`-style directive | unset | Log filter (preferred) |
| `RUST_LOG` | `RUST_LOG`-style directive | unset | Log filter fallback |
| `MX_AGENT_LOG_FORMAT` | `human` \| `json` | `human` | Output format |

The CLI `-v`/`-vv`/`-vvv` flags raise the default level (`warn` → `info` → `debug` →
`trace`) when no filter env var is set.

```bash
MX_AGENT_LOG_FORMAT=json mx-agent -vv agent list   # JSON logs on stderr
MX_AGENT_LOG=mx_agent_daemon=debug,info mx-agent daemon status
```

Credentials are wrapped in `mx_agent_telemetry::Secret`, which renders as
`***redacted***` in `Debug`/`Display`, and `mx_agent_telemetry::redact` blanks values
for secret-looking keys. Never log raw tokens or keys.

### Daemon lifecycle

Runtime state lives under `$XDG_RUNTIME_DIR/mx-agent/` (override with
`MX_AGENT_RUNTIME_DIR`): a `daemon.json` status file, the `daemon.sock` IPC socket, and
a `daemon.log` for background output.

The IPC socket is created with mode `0600`; the daemon refuses to run if its runtime
directory is group- or world-accessible or owned by another user, and verifies the peer
UID (`SO_PEERCRED` on Linux, `LOCAL_PEERCRED` on macOS/BSD). Stale sockets from a previous run are cleaned up automatically
when no daemon is listening. The CLI and daemon communicate over this socket using
length-delimited (4-byte big-endian prefix) JSON-RPC 2.0 frames; malformed input yields
a controlled JSON-RPC error rather than a dropped connection.

### Local Matrix homeserver (dev / e2e)

A throwaway [Tuwunel](https://github.com/matrix-construct/tuwunel) homeserver in Docker
is provided for development and the integration/e2e tests:

```bash
scripts/matrix_dev.sh up             # start (loopback-only); auto-creates dev/matrix/.env
scripts/matrix_dev.sh register alice # register a test user, print an access token
scripts/matrix_dev.sh reset          # wipe all homeserver data
```

Then point the daemon at it (`homeserver_url = "http://127.0.0.1:8008"`). See
[`dev/matrix/README.md`](dev/matrix/README.md) for details.

### Wiki sync

The `wiki/` folder is the source of truth for the GitHub wiki. A GitHub Action
([`.github/workflows/wiki-sync.yml`](.github/workflows/wiki-sync.yml)) mirrors it
to the wiki automatically whenever `wiki/**` changes land on `main` — no local
setup is required. To force a re-sync, run the **wiki-sync** workflow manually
from the Actions tab.

---

## Contributing

Issues and pull requests are welcome. See **[CONTRIBUTING.md](CONTRIBUTING.md)** for
setup, the required checks (`cargo fmt --check`, `cargo clippy --all-targets
--all-features -- -D warnings`, `cargo test --all`), and PR guidelines. The
[issue backlog](docs/github-issue-backlog.md) tracks where help is needed.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
