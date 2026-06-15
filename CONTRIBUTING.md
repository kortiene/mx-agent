# Contributing to mx-agent

Thanks for your interest in mx-agent — a Matrix-backed CLI + daemon for
decentralized orchestration between autonomous coding agents. This guide covers
how to get set up, the checks your change must pass, and how we handle issues and
pull requests.

> **Project status: public alpha (v0.2.1).** All command groups run against a
> real Matrix homeserver through the daemon, including signed Matrix-backed remote
> `call` and `exec` (batch and interactive `--pty`) and a live task scheduler. See
> the [README](README.md#project-status) for what works today and the
> [issue backlog](docs/github-issue-backlog.md) for where help is most useful.

## Code of conduct

Be respectful and constructive. Assume good faith, keep discussion technical, and
help newcomers. Maintainers may moderate comments, commits, and contributions that
are abusive or off-topic.

## Prerequisites

- A **Unix host** (Linux or macOS). Windows is not supported — mx-agent relies on
  Unix-domain-socket IPC and Unix process semantics.
- **Rust stable toolchain, 1.93+** (the project MSRV), installed via
  [rustup](https://rustup.rs). The MSRV was raised from 1.74 to 1.93 for
  `matrix-sdk 0.18`; the `msrv` CI job builds the workspace on it (issue #315).
- Optional, for integration/e2e tests: **Docker** (for the throwaway
  [Tuwunel](https://github.com/matrix-construct/tuwunel) homeserver).

## Getting started

```bash
git clone https://github.com/kortiene/mx-agent.git
cd mx-agent
cargo build --all
cargo run -p mx-agent-cli -- --help
```

Wiki pages live in `wiki/` and are the source of truth. A GitHub Action mirrors
them to the GitHub wiki automatically when changes to `wiki/**` land on `main` —
edit the files in `wiki/`, not the wiki UI.

## Workspace layout

| Crate | Purpose |
|---|---|
| `mx-agent-cli` | The `mx-agent` binary and command surface |
| `mx-agent-daemon` | Long-running daemon: Matrix sync, crypto, policy, supervision |
| `mx-agent-protocol` | Event schemas, IDs, and protocol versioning |
| `mx-agent-ipc` | Local CLI/daemon IPC transport |
| `mx-agent-policy` | Local authorization policy engine |
| `mx-agent-sandbox` | Process sandboxing backends |

The full design lives in [docs/architecture.md](docs/architecture.md).

## Required checks

Every pull request must pass the same checks CI runs
(`.github/workflows/ci.yml`). Run them locally before pushing:

```bash
cargo fmt --check                                            # formatting (rustfmt.toml)
cargo clippy --all-targets --all-features -- -D warnings     # lints, warnings = errors
cargo test --all                                             # all tests
cargo build --all                                            # everything builds
```

Notes:

- **`unsafe` is forbidden** workspace-wide (`unsafe_code = "forbid"`). Use safe
  abstractions (e.g. `rustix`/`nix`) for syscalls.
- **`missing_docs` is a warning** and CI treats warnings as errors — document new
  public items.
- Formatting is pinned to stable rustfmt options; just run `cargo fmt`.
- Clippy honors the MSRV declared in `clippy.toml`; don't use APIs newer than
  Rust 1.93 without bumping it deliberately (and update `Cargo.toml`
  `rust-version` + the `msrv` CI job's `toolchain:` in lockstep).

## Running the integration tests

The default `cargo test --all` needs no homeserver. The live Matrix
integration/E2E tests are `#[ignore]`d and run against a throwaway Tuwunel
homeserver via Docker. The one-command harness boots the homeserver, registers
the per-run test users (two stable accounts plus a fresh account per recovery,
key-backup, SAS, and log-redaction test), and runs the whole `#[ignore]`d suite:

```bash
scripts/matrix_integration_test.sh              # run the live E2E suite
scripts/matrix_integration_test.sh --teardown   # ...and stop the homeserver after
```

That suite covers the live daemon paths end to end (issue #202): login/`/sync`,
signed remote `call` and `exec` (streaming, stdin, policy denial, and interactive
`--pty` with terminal resize), E2EE
privileged-event handling, and the live scheduler loop auto-executing a signed,
assigned task DAG over real room state while refusing policy-denied and
approval-required actions. It also covers the E2EE durability/verification
surface (issue #260): decrypt-after-restart from the persistent crypto store,
key-backup restore across a re-provision, and the interactive two-daemon SAS
verification flow. To drive the homeserver manually instead:

```bash
scripts/matrix_dev.sh up              # start a loopback-only Tuwunel homeserver
scripts/matrix_dev.sh register alice  # register a test user, print an access token
scripts/matrix_dev.sh reset           # wipe homeserver data when done
```

See [dev/matrix/README.md](dev/matrix/README.md) for details.

## Commit and pull request guidelines

- **Branch from `main`** (or the active release branch when a release is in
  progress); never commit directly to `main`.
- **Keep PRs focused** — one logical change per PR. Split unrelated changes.
- **Write clear commit messages**: a concise imperative subject line (e.g.
  `daemon: persist sync token across restarts`), then a body explaining the *why*
  when it isn't obvious.
- **Reference issues** the PR addresses (e.g. `Closes #123`).
- **Update docs** alongside behavior changes — the README status table,
  `docs/`, and the `wiki/` pages where relevant. The `wiki/` folder is mirrored to
  the GitHub wiki on pushes to `main`.
- **Don't introduce secrets** into code, tests, logs, or fixtures. Credentials are
  wrapped in `mx_agent_telemetry::Secret` and must never be logged raw.

## Reporting bugs and requesting features

- Search [existing issues](https://github.com/kortiene/mx-agent/issues) first.
- For bugs, include: what you ran, what you expected, what happened, and relevant
  logs (set `MX_AGENT_LOG=debug` and redact any tokens — though mx-agent already
  redacts known secret keys).
- For security-sensitive reports, prefer a private channel over a public issue
  until a fix is available. See the
  [security hardening guide](docs/security-hardening.md) for the threat model.

## License

By contributing, you agree that your contributions will be licensed under the
[Apache License, Version 2.0](LICENSE), consistent with the rest of the project.
Unless you state otherwise, any contribution you intentionally submit for
inclusion is provided under those terms (per Section 5 of the License).
