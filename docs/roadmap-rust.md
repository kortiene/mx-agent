# Rust Implementation Roadmap

This roadmap describes a phased Rust implementation plan for `mx-agent`, a Matrix-backed CLI and daemon for decentralized orchestration between autonomous coding agents.

See also: [architecture.md](architecture.md).

---

## Recommended Rust Stack

Core libraries:

- CLI: `clap`
- async runtime: `tokio`
- Matrix client: `matrix-sdk`
- serialization: `serde`, `serde_json`
- errors: `thiserror`, `anyhow`
- logging/tracing: `tracing`, `tracing-subscriber`
- config: `toml`, `directories`
- signing: `ed25519-dalek`
- Unix IPC: `tokio::net::UnixListener`
- process supervision: `tokio::process`
- PTY later: `portable-pty` or `nix`
- storage: `sqlite`, `redb`, or `sled`

Suggested workspace layout:

```text
crates/
  mx-agent-cli/
  mx-agent-daemon/
  mx-agent-protocol/
  mx-agent-ipc/
  mx-agent-policy/
  mx-agent-sandbox/
```

---

## Phase 0 — Project Foundation

Goal: establish the Rust workspace, build tooling, and module boundaries.

Deliverables:

- Cargo workspace.
- crate boundaries for CLI, daemon, protocol, IPC, policy, and sandboxing.
- `cargo fmt`, `cargo clippy`, and CI checks.
- baseline `tracing` setup.
- shared error conventions.

Acceptance criteria:

- `cargo test` passes.
- `cargo fmt --check` passes.
- `cargo clippy` passes with project-defined lint level.
- Workspace can build a placeholder `mx-agent` binary.

---

## Phase 1 — CLI and Daemon Skeleton

Goal: implement local control plane behavior without Matrix functionality.

Commands:

```bash
mx-agent daemon start
mx-agent daemon status
mx-agent daemon stop
mx-agent daemon status --json
```

Deliverables:

- daemon process lifecycle.
- Unix socket at `$XDG_RUNTIME_DIR/mx-agent/daemon.sock`.
- socket permissions set to `0600`.
- pid/status file.
- framed JSON-RPC over Unix socket.
- daemon status response.

Acceptance criteria:

- CLI can start, query, and stop the daemon.
- daemon rejects wrong-UID clients where supported.
- daemon logs are structured and useful.

---

## Phase 2 — Protocol Crate

Goal: define stable Rust types for Matrix event schemas and IPC messages.

Deliverables:

- `AgentState`
- `TaskState`
- `InvocationState`
- `ExecRequest`
- `ExecAccepted`
- `ExecRejected`
- `ExecFinished`
- `StreamChunk`
- `ContextShare`
- `ApprovalRequest`
- `TrustState`
- event type constants.
- schema version constants.
- ID generation helpers for `agent_id`, `task_id`, `request_id`, `invocation_id`, and `context_id`.

Acceptance criteria:

- serde round-trip tests pass.
- protocol structs serialize to documented JSON shapes.
- tests cover tolerant parsing for forward-compatible fields.

---

## Phase 3 — Matrix Login and Workspace Basics

Goal: authenticate with Matrix and manage workspace rooms.

Commands:

```bash
mx-agent auth login
mx-agent auth status
mx-agent workspace create
mx-agent workspace join
mx-agent workspace status
```

Daemon responsibilities:

- store Matrix session securely.
- initialize `matrix-sdk` client.
- maintain `/sync` loop.
- persist sync token.
- maintain basic room state cache.

Acceptance criteria:

- login persists across daemon restarts.
- daemon can create and join rooms.
- workspace status reads Matrix room membership/state.

---

## Phase 4 — Agent Registration and Discovery ✅ Delivered

Goal: agents can advertise themselves and discover peers.

Commands:

```bash
mx-agent agent register
mx-agent agent list
mx-agent agent show
```

Matrix events:

```text
com.mxagent.agent.v1
com.mxagent.heartbeat.v1
```

Deliverables:

- durable agent state event. ✅
- periodic heartbeat event — daemon emits `com.mxagent.heartbeat.v1` every
  30 s per owned agent; durable state refreshed at most every 300 s. ✅
- liveness calculation — `active`/`stale`/`offline` verdict from durable
  `last_seen_ts` + latest heartbeat event; surfaced in `agent list` /
  `agent show` (human + `--json`) as `AgentListing { agent, liveness }`. ✅
- capability and tool advertisement. ✅

Acceptance criteria:

- two daemons in the same room can discover each other. ✅
- inactive agents become stale after timeout. ✅
- `--json` output is stable and agent-friendly. ✅

---

## Phase 5 — Trust and Signing

Goal: privileged messages are signed and verifiable.

Commands:

```bash
mx-agent trust fingerprint
mx-agent trust list
mx-agent trust approve
mx-agent trust revoke
```

Deliverables:

- daemon-owned Ed25519 signing key.
- canonical JSON signing.
- signature verification.
- nonce replay cache.
- request expiry checks.
- local trusted key store.

Acceptance criteria:

- unsigned privileged requests are rejected.
- expired requests are rejected.
- replayed nonces are rejected.
- trusted keys survive daemon restart.

---

## Phase 6 — Named Tool Calls MVP

Goal: implement safer remote execution through named tools before raw shell execution.

Commands:

```bash
mx-agent call --tool run_tests
mx-agent agent tools
```

Matrix events:

```text
com.mxagent.call.request.v1
com.mxagent.call.response.v1
```

Deliverables:

- signed tool request/response flow.
- built-in `run_tests` tool.
- JSON input/output support.
- tool schema discovery.

Acceptance criteria:

- remote daemon receives signed tool request.
- policy allows or denies the tool call.
- structured JSON response returns to caller.
- local CLI exits nonzero on tool failure.

---

## Phase 7 — Policy Engine

Goal: enforce local authorization controls for remote actions.

Policy file:

```text
~/.config/mx-agent/policy.toml
```

Example:

```toml
[rooms."!abc:matrix.org"]
trusted = true
raw_exec_default = "deny"

[rooms."!abc:matrix.org".agents."@claude:matrix.org"]
allow_tools = ["run_tests", "lint"]
allow_commands = ["npm", "cargo"]
allow_cwd = ["/home/me/code/project"]
max_runtime_ms = 900000
max_output_bytes = 5000000
requires_approval = false
```

Deliverables:

- room-level trust.
- requester-level permissions.
- allowed tools.
- allowed commands.
- allowed cwd prefixes.
- runtime/output limits.
- approval-required flag.
- audit log for decisions.

Acceptance criteria:

- denied requests never spawn processes.
- policy decisions are recorded in audit log.
- config reload works without daemon restart if feasible.

---

## Phase 8 — Remote Exec MVP

Goal: run non-interactive remote commands with stdout/stderr streaming.

Command:

```bash
mx-agent exec --room '!abc:matrix.org' --agent developer-pi -- npm test
```

Matrix events:

```text
com.mxagent.exec.request.v1
com.mxagent.exec.accepted.v1
com.mxagent.exec.rejected.v1
com.mxagent.exec.finished.v1
com.mxagent.stream.chunk.v1
```

Deliverables:

- process spawning through `tokio::process`.
- stdout/stderr async readers.
- stream chunks sent over Matrix.
- local CLI rendering.
- timeout handling.
- remote exit-code propagation.

Initial limitations:

- no PTY.
- no artifact mode.
- strict output caps.
- no interactive stdin beyond piped input.

Acceptance criteria:

- `npm test` can run remotely.
- stdout and stderr render locally in near-real time.
- local exit code matches remote exit code.
- timeout kills the remote process group.

---

## Phase 9 — Stream Reliability and Backpressure

Goal: make Matrix stream transport safe under real-world conditions.

Deliverables:

- per-stream sequence numbers.
- duplicate suppression.
- out-of-order buffering.
- missing chunk timeout.
- optional chunk checksums.
- configurable chunk sizes.
- output cap enforcement.
- degraded stream markers.
- strict stream mode.

Command option:

```bash
mx-agent exec --strict-stream --agent developer-pi -- npm test
```

Acceptance criteria:

- duplicate chunks do not duplicate terminal output.
- missing chunks are detected.
- excessive output is truncated or summarized.
- daemon does not overwhelm homeserver rate limits.

---

## Phase 10 — Task DAG State

Goal: implement distributed workflow tracking.

> **Status: implemented.** Task state CRUD/graph/watch run over Matrix through
> the daemon (`task create`/`update`/`list`/`graph`/`watch`), with structured
> task actions, lifecycle-transition validation, a stable task result schema,
> invocation/task linkage, `state_rev` revisions, and stale-update detection. A
> daemon **task-orchestration engine** (scheduler, optimistic claiming, tool/exec
> dispatch, policy + trust/signature + approval enforcement, restart recovery,
> and DAG diagnostics) is implemented and tested. Remaining work: wiring that
> engine into a live `/sync` scheduler loop so a running daemon auto-executes
> tasks, plus the signed Matrix transport for remote `exec` (tracked by #155).

Commands:

```bash
mx-agent task create
mx-agent task update
mx-agent task list
mx-agent task graph
mx-agent invocation list
```

Matrix events:

```text
com.mxagent.task.v1
com.mxagent.invocation.v1
```

Deliverables:

- task lifecycle.
- dependency graph calculation.
- invocation/task linkage.
- state revisions.
- stale update detection.

Acceptance criteria:

- agents can query pending, running, failed, and completed tasks.
- DAG graph renders correctly.
- `exec` can attach to a task ID.

---

## Phase 11 — Context Sharing

Goal: agents can share diffs, environment metadata, plans, logs, and arbitrary context.

Commands:

```bash
mx-agent share diff
mx-agent share env
mx-agent share --type application/json --name plan.json
```

Matrix event:

```text
com.mxagent.context.share.v1
```

Deliverables:

- stdin upload.
- small payload timeline events.
- Matrix media upload for large payloads.
- `mxc://` references.
- sha256 integrity metadata.

Acceptance criteria:

- remote agents can list and retrieve shared context.
- large files use Matrix media references.
- integrity metadata is validated on retrieval.

---

## Phase 12 — Cancellation and Approval

Goal: allow safe control over pending and running work.

Commands:

```bash
mx-agent invocation cancel --invocation inv_...
mx-agent approval list
mx-agent approval approve req_...
mx-agent approval deny req_...
```

Matrix events:

```text
com.mxagent.exec.cancel.v1
com.mxagent.exec.cancelled.v1
com.mxagent.approval.request.v1
com.mxagent.approval.decision.v1
```

Deliverables:

- cancellation request flow.
- process group termination.
- approval queue.
- approval request/decision events.
- policy integration with `requires_approval`.

Acceptance criteria:

- cancellation reliably terminates the remote process group.
- approval-required policy blocks execution until approved.
- denied approvals never spawn processes.

---

## Phase 13 — Sandboxing

Goal: reduce remote code execution blast radius.

Baseline sandbox:

- restricted cwd.
- sanitized environment.
- timeout.
- output cap.
- process group kill on timeout/cancel.

Advanced backends:

- bubblewrap.
- Docker or Podman.
- network deny-by-default.
- read-only root paths.
- writable workspace/temp only.

Example config:

```toml
[execution]
default_sandbox = "bubblewrap"
network = "deny"
```

Acceptance criteria:

- secrets are absent from child environment.
- denied paths cannot be used as cwd.
- sandbox failures are reported clearly.

---

## Phase 14 — Artifact Output Mode

Goal: handle large logs without flooding Matrix timeline.

Deliverables:

- switch to Matrix media upload after threshold.
- compressed logs, e.g. zstd.
- `com.mxagent.stream.artifact.v1` event.
- tail preview.
- artifact integrity hash.

Acceptance criteria:

- large test logs do not exceed event rate limits.
- full logs are retrievable via `mxc://`.
- terminal still shows useful live summary or tail.

---

## Phase 15 — PTY Mode

Goal: support interactive remote terminal sessions.

Command:

```bash
mx-agent exec --pty -- bash
```

Deliverables:

- raw local terminal mode.
- remote PTY allocation.
- resize events.
- merged PTY stream.
- control character handling.

Acceptance criteria:

- basic remote shell works.
- terminal resizing propagates.
- Ctrl-C behavior is sane and documented.

---

## Phase 16 — Hardening and Release

Goal: prepare a public alpha release.

Deliverables:

- integration test harness with local Matrix server.
- E2EE test coverage.
- **E2EE production hardening (issue #240) — delivered:** persistent
  daemon-owned crypto store (device identity + Megolm sessions survive restart),
  device verification UX (`device list`/`show`/`verify`, out-of-band fingerprint
  and interactive emoji/SAS), cross-signing bootstrap/observe (`auth
  cross-signing`), server-side key backup/recovery (`recovery
  enable`/`status`/`recover`), and the optional additive `require_verified_device`
  policy gate. The Matrix-device-trust vs. Ed25519-signing-trust interaction is
  documented (architecture §1.2/§13.2, security hardening guide).
- reconnect and rate-limit tests.
- security review checklist.
- packaging.
- install script.
- release artifacts.

Recommended checks:

```bash
cargo test
cargo fmt --check
cargo clippy
cargo deny check
```

Suggested release targets:

```text
x86_64-unknown-linux-musl
aarch64-unknown-linux-musl
x86_64-apple-darwin
aarch64-apple-darwin
x86_64-pc-windows-msvc
```

---

## Suggested Milestones

| Milestone | Scope |
|---|---|
| 1. Local Daemon Foundation | Phases 0–2 |
| 2. Matrix Workspace MVP | Phases 3–4 |
| 3. Secure Tool Calls | Phases 5–7 |
| 4. Remote Exec MVP | Phases 8–9 |
| 5. Orchestration Layer | Phases 10–12 |
| 6. Production Hardening | Phases 13–16 |

---

## Recommended MVP

The first usable MVP should include:

1. daemon with Matrix login, sync, room join/create.
2. Unix socket JSON-RPC IPC.
3. agent registration and listing.
4. signed `call` requests for named tools.
5. one built-in tool: `run_tests`.
6. basic `exec` behind explicit local policy.
7. stdout/stderr chunk streaming with output cap.
8. task state create/list/update.
9. local credential isolation and audit log.

Defer until after MVP:

- PTY mode.
- large artifact mode.
- rich approval UX.
- advanced sandboxing presets.
- cross-platform named pipes.
- full key rotation/revocation automation.
