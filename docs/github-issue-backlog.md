# GitHub Issue Backlog

This backlog breaks the Rust implementation roadmap into GitHub-sized issues. Each issue should be copied into GitHub, assigned to the listed milestone, and labeled accordingly.

Format:

```text
Title
Milestone
Labels
Depends on
Scope
Acceptance criteria
```

---

## Milestone 1 — Local Daemon Foundation

Covers roadmap phases 0–2.

### 1. Bootstrap Cargo workspace

Milestone: 1. Local Daemon Foundation  
Labels: `type:feature`, `area:cli`, `area:daemon`, `priority:p0`

Scope:

- Create Cargo workspace.
- Add crates: `mx-agent-cli`, `mx-agent-daemon`, `mx-agent-protocol`, `mx-agent-ipc`, `mx-agent-policy`, `mx-agent-sandbox`.
- Add placeholder `mx-agent` binary.
- Add baseline `README` development instructions.

Acceptance criteria:

- `cargo build --all` succeeds.
- `cargo test --all` succeeds.
- `mx-agent --help` prints placeholder CLI help.

### 2. Add Rust formatting, linting, and baseline CI support

Milestone: 1. Local Daemon Foundation  
Labels: `type:ci`, `area:ci`, `priority:p0`

Depends on: issue 1

Scope:

- Configure `cargo fmt` expectations.
- Configure `cargo clippy` expectations.
- Ensure GitHub Actions runs Rust checks once `Cargo.toml` exists.
- Document local check commands.

Acceptance criteria:

- `cargo fmt --check` passes.
- `cargo clippy --all-targets --all-features -- -D warnings` passes.
- CI passes on a PR.

### 3. Implement top-level CLI command skeleton

Milestone: 1. Local Daemon Foundation  
Labels: `type:feature`, `area:cli`, `priority:p0`

Depends on: issue 1

Scope:

- Use `clap` for command parsing.
- Add command groups: `daemon`, `auth`, `workspace`, `agent`, `call`, `exec`, `share`, `task`, `invocation`, `approval`, `trust`.
- Add global flags: `--json`, `--config`, `--socket`, `--verbose`.

Acceptance criteria:

- `mx-agent --help` lists all command groups.
- Each command group has placeholder subcommands matching the architecture.
- Invalid command usage returns a nonzero exit code.

### 4. Add structured tracing and logging foundation

Milestone: 1. Local Daemon Foundation  
Labels: `type:feature`, `area:daemon`, `priority:p1`

Scope:

- Add `tracing` and `tracing-subscriber`.
- Support human and JSON log formats.
- Add redaction helper for secrets.
- Document logging env vars.

Acceptance criteria:

- CLI and daemon emit structured logs.
- JSON log mode works.
- obvious secret-looking fields are redacted in debug output.

### 5. Implement daemon process lifecycle commands

Milestone: 1. Local Daemon Foundation  
Labels: `type:feature`, `area:daemon`, `priority:p0`

Depends on: issues 3, 4

Scope:

- Implement `mx-agent daemon start`.
- Implement `mx-agent daemon status`.
- Implement `mx-agent daemon stop`.
- Manage pid/status file.

Acceptance criteria:

- daemon starts in foreground and background modes.
- `daemon status --json` reports pid, uptime, socket path, and version.
- `daemon stop` shuts down gracefully.

### 6. Implement Unix socket creation and permissions

Milestone: 1. Local Daemon Foundation  
Labels: `type:feature`, `area:ipc`, `area:security`, `priority:p0`

Depends on: issue 5

Scope:

- Create socket at `$XDG_RUNTIME_DIR/mx-agent/daemon.sock` by default.
- Ensure parent directory has safe permissions.
- Ensure socket is accessible only to the current user.
- Clean up stale sockets safely.

Acceptance criteria:

- socket path follows XDG runtime conventions.
- socket mode is restrictive.
- daemon refuses to use unsafe socket directory permissions.

### 7. Implement framed JSON-RPC IPC transport

Milestone: 1. Local Daemon Foundation  
Labels: `type:feature`, `area:ipc`, `priority:p0`

Depends on: issue 6

Scope:

- Define length-delimited JSON-RPC frames.
- Implement IPC client in CLI.
- Implement IPC server in daemon.
- Add request/response IDs and error responses.

Acceptance criteria:

- CLI can send `daemon.status` over IPC.
- malformed frames return controlled errors.
- IPC unit tests cover partial frames and multiple frames.

### 8. Verify local IPC peer credentials where supported

Milestone: 1. Local Daemon Foundation  
Labels: `type:security`, `area:ipc`, `area:security`, `priority:p0`

Depends on: issue 7

Scope:

- Use `SO_PEERCRED` on Linux where available.
- Reject clients not owned by daemon UID.
- Provide a clear unsupported-platform behavior.

Acceptance criteria:

- Linux wrong-UID clients are rejected.
- rejection is audited/logged without leaking sensitive data.
- behavior is documented.

### 9. Define protocol event constants and versioning

Milestone: 1. Local Daemon Foundation  
Labels: `type:feature`, `area:protocol`, `priority:p0`

Scope:

- Add event type constants for all `.v1` Matrix event types.
- Add schema version constants.
- Add protocol crate docs explaining compatibility rules.

Acceptance criteria:

- protocol constants match `docs/architecture.md`.
- tests prevent accidental event type typos.

### 10. Implement protocol structs and serde round-trip tests

Milestone: 1. Local Daemon Foundation  
Labels: `type:feature`, `area:protocol`, `priority:p0`

Depends on: issue 9

Scope:

- Implement structs for agent, task, invocation, exec, call, stream, context, approval, trust.
- Derive serde serialization/deserialization.
- Allow forward-compatible unknown fields where appropriate.

Acceptance criteria:

- documented JSON examples round-trip in tests.
- missing required fields fail deserialization.
- unknown future fields do not break tolerant readers.

### 11. Implement ID generation helpers

Milestone: 1. Local Daemon Foundation  
Labels: `type:feature`, `area:protocol`, `priority:p1`

Scope:

- Generate IDs for `agent`, `task`, `request`, `invocation`, and `context`.
- Prefer sortable IDs, e.g. ULID.
- Validate ID prefixes.

Acceptance criteria:

- generated IDs are unique in tests.
- IDs include expected prefixes, e.g. `inv_`.
- invalid IDs are rejected by protocol validators.

---

## Milestone 2 — Matrix Workspace MVP

Covers roadmap phases 3–4.

### 12. Add Matrix SDK client initialization

Milestone: 2. Matrix Workspace MVP  
Labels: `type:feature`, `area:matrix`, `priority:p0`

Depends on: milestone 1

Scope:

- Integrate `matrix-sdk`.
- Create daemon Matrix client from config/session.
- Add basic homeserver URL configuration.

Acceptance criteria:

- daemon initializes Matrix client without login.
- configuration errors are actionable.

### 13. Implement Matrix login and session persistence

Milestone: 2. Matrix Workspace MVP  
Labels: `type:feature`, `area:matrix`, `area:security`, `priority:p0`

Depends on: issue 12

Scope:

- Implement `mx-agent auth login`.
- Persist session in daemon-owned storage.
- Implement `mx-agent auth status`.
- Ensure tokens are never printed.

Acceptance criteria:

- login survives daemon restart.
- `auth status --json` reports user/device without token.
- debug logs redact tokens.

### 14. Implement daemon Matrix sync loop

Milestone: 2. Matrix Workspace MVP  
Labels: `type:feature`, `area:matrix`, `area:daemon`, `priority:p0`

Depends on: issue 13

Scope:

- Run long-lived `/sync` loop.
- Persist sync token.
- Implement retry/backoff.
- Emit health status.

Acceptance criteria:

- daemon continues syncing after transient failures.
- restart resumes from stored sync token.
- status reports sync health.

### 15. Implement workspace create/join/status

Milestone: 2. Matrix Workspace MVP  
Labels: `type:feature`, `area:matrix`, `area:cli`, `priority:p0`

Depends on: issue 14

Scope:

- `workspace create` with alias/name/privacy flags.
- `workspace join` by alias or room ID.
- `workspace status` with membership summary.

Acceptance criteria:

- CLI can create private room.
- CLI can join existing room.
- status works in human and JSON output.

### 16. Implement workspace state event

Milestone: 2. Matrix Workspace MVP  
Labels: `type:feature`, `area:matrix`, `area:protocol`, `priority:p1`

Depends on: issue 15

Scope:

- Send/read `com.mxagent.workspace.v1` state.
- Store project ID, attached path metadata, and repo info.
- Implement `workspace attach`.

Acceptance criteria:

- attached workspace metadata appears in `workspace status`.
- state event content matches protocol docs.

### 17. Implement agent registration state event

Milestone: 2. Matrix Workspace MVP  
Labels: `type:feature`, `area:matrix`, `area:daemon`, `priority:p0`

Depends on: issue 15

Scope:

- Implement `agent register`.
- Publish `com.mxagent.agent.v1` state.
- Include kind, capabilities, tools, load, cwd, and git commit when available.

Acceptance criteria:

- registered agent appears in room state.
- repeated registration updates existing state key.

### 18. Implement heartbeat and liveness calculation

Milestone: 2. Matrix Workspace MVP  
Labels: `type:feature`, `area:daemon`, `area:matrix`, `priority:p0`

Depends on: issue 17

Scope:

- Emit `com.mxagent.heartbeat.v1` periodically.
- Calculate active/stale/offline status.
- Avoid excessive state-event updates.

Acceptance criteria:

- active agents appear active within heartbeat window.
- stopped agents become stale after configured timeout.

### 19. Implement agent list/show/tools commands

Milestone: 2. Matrix Workspace MVP  
Labels: `type:feature`, `area:cli`, `area:tools`, `priority:p0`

Depends on: issues 17, 18

Scope:

- `agent list` with capability filters.
- `agent show` for one agent.
- `agent tools` placeholder based on agent state.

Acceptance criteria:

- two daemons in one room can discover each other.
- JSON output is stable.

---

## Milestone 3 — Secure Tool Calls

Covers roadmap phases 5–7.

### 20. Implement daemon signing key storage

Milestone: 3. Secure Tool Calls  
Labels: `type:security`, `area:security`, `priority:p0`

Depends on: milestone 2

Scope:

- Generate Ed25519 keypair on first run.
- Store under daemon-owned permissions.
- Expose public fingerprint through `trust fingerprint`.

Acceptance criteria:

- private key is not world-readable.
- fingerprint remains stable across restarts.

### 21. Implement canonical JSON signing and verification

Milestone: 3. Secure Tool Calls  
Labels: `type:security`, `area:protocol`, `priority:p0`

Depends on: issue 20

Scope:

- Define canonical JSON representation.
- Sign privileged request payloads.
- Verify signatures.
- Add test vectors.

Acceptance criteria:

- valid signatures verify.
- modified payloads fail verification.
- signature field is excluded from signed bytes consistently.

### 22. Implement nonce replay cache and request expiry checks

Milestone: 3. Secure Tool Calls  
Labels: `type:security`, `area:daemon`, `priority:p0`

Depends on: issue 21

Scope:

- Persist bounded nonce cache.
- Reject replayed nonces.
- Reject expired privileged requests.

Acceptance criteria:

- replayed request is denied.
- expired request is denied without side effects.

### 23. Implement trust list/approve/revoke commands

Milestone: 3. Secure Tool Calls  
Labels: `type:security`, `area:cli`, `priority:p0`

Depends on: issue 21

Scope:

- `trust list`.
- `trust approve`.
- `trust revoke`.
- local trust store.

Acceptance criteria:

- approved keys can be used for privileged requests.
- revoked keys are rejected.
- trust state survives daemon restart.

### 24. Implement optional Matrix trust state publication

Milestone: 3. Secure Tool Calls  
Labels: `type:security`, `area:matrix`, `priority:p1`

Depends on: issue 23

Scope:

- Publish/read `com.mxagent.trust.v1` state.
- Respect local policy as final authority.
- Document trust precedence.

Acceptance criteria:

- trust state can be inspected in room state.
- local revocation overrides room-published trust.

### 25. Implement policy file parsing

Milestone: 3. Secure Tool Calls  
Labels: `type:feature`, `area:policy`, `priority:p0`

Scope:

- Parse `~/.config/mx-agent/policy.toml`.
- Validate room, agent, tool, command, cwd, runtime, and output rules.
- Provide useful errors.

Acceptance criteria:

- valid sample policy parses.
- invalid policy reports precise error path.

### 26. Implement policy decision engine

Milestone: 3. Secure Tool Calls  
Labels: `type:feature`, `area:policy`, `area:security`, `priority:p0`

Depends on: issue 25

Scope:

- Evaluate room trust.
- Evaluate requester permissions.
- Enforce allowed tools/commands/cwd.
- Enforce runtime/output caps.

Acceptance criteria:

- denied requests never spawn processes.
- unit tests cover allow/deny cases.

### 27. Implement audit log for privileged decisions

Milestone: 3. Secure Tool Calls  
Labels: `type:security`, `area:daemon`, `priority:p0`

Depends on: issue 26

Scope:

- Append local audit records.
- Redact secrets.
- Include request, requester, target, decision, and policy rule.

Acceptance criteria:

- every allow/deny decision is logged.
- audit log contains no tokens or private keys.

### 28. Implement tool registry and tool schema model

Milestone: 3. Secure Tool Calls  
Labels: `type:feature`, `area:tools`, `area:protocol`, `priority:p0`

Scope:

- Define tool metadata model.
- Define input/output schema fields.
- Register built-in tools.
- Expose tool list in agent state.

Acceptance criteria:

- `agent tools` displays tool metadata.
- schema JSON serializes correctly.

### 29. Implement signed call request/response flow

Milestone: 3. Secure Tool Calls  
Labels: `type:feature`, `area:tools`, `area:matrix`, `priority:p0`

Depends on: issues 21, 26, 28

Scope:

- Send `com.mxagent.call.request.v1`.
- Route request to target agent.
- Verify signature/trust/policy.
- Emit `com.mxagent.call.response.v1`.

Acceptance criteria:

- remote call succeeds between two daemons.
- unsigned or untrusted calls are rejected.

### 30. Implement built-in run_tests tool

Milestone: 3. Secure Tool Calls  
Labels: `type:feature`, `area:tools`, `priority:p0`

Depends on: issue 29

Scope:

- Implement `run_tests` tool with JSON input.
- Support package/name args.
- Return structured result with exit code and summary.

Acceptance criteria:

- `mx-agent call --tool run_tests` works locally/remotely.
- local CLI exits nonzero on tool failure.

---

## Milestone 4 — Remote Exec MVP

Covers roadmap phases 8–9.

### 31. Implement exec request routing

Milestone: 4. Remote Exec MVP  
Labels: `type:feature`, `area:daemon`, `area:matrix`, `priority:p0`

Depends on: milestone 3

Scope:

- Send signed `com.mxagent.exec.request.v1`.
- Route to target agent.
- Emit accepted/rejected events.
- Create invocation state.

Acceptance criteria:

- target daemon accepts allowed exec requests.
- disallowed requests emit rejection without spawning.

### 32. Implement process runner for non-interactive commands

Milestone: 4. Remote Exec MVP  
Labels: `type:feature`, `area:daemon`, `priority:p0`

Depends on: issue 31

Scope:

- Spawn command with `tokio::process`.
- Set cwd.
- Sanitize environment.
- Track process group where supported.

Acceptance criteria:

- command runs in requested allowed cwd.
- child env excludes known secret variables.
- exit status is captured.

### 33. Implement stdout/stderr async capture

Milestone: 4. Remote Exec MVP  
Labels: `type:feature`, `area:streaming`, `priority:p0`

Depends on: issue 32

Scope:

- Read stdout and stderr concurrently.
- Chunk by size/time/newline.
- Emit stream chunks.

Acceptance criteria:

- stdout and stderr are captured separately.
- chunk size/flush interval are configurable.

### 34. Implement CLI stream rendering and exit-code propagation

Milestone: 4. Remote Exec MVP  
Labels: `type:feature`, `area:cli`, `area:streaming`, `priority:p0`

Depends on: issue 33

Scope:

- Forward daemon stream frames to local stdout/stderr.
- Wait for `exec.finished`.
- Exit with remote exit code when possible.

Acceptance criteria:

- remote `npm test` output appears locally.
- local exit code matches remote command.

### 35. Implement piped stdin support for exec

Milestone: 4. Remote Exec MVP  
Labels: `type:feature`, `area:streaming`, `priority:p1`

Depends on: issue 34

Scope:

- Detect piped stdin.
- Send stdin chunks.
- Close remote stdin on EOF.

Acceptance criteria:

- `echo hi | mx-agent exec ... -- cat` returns `hi`.
- stdin EOF is propagated exactly once.

### 36. Implement timeout and process-group termination

Milestone: 4. Remote Exec MVP  
Labels: `type:feature`, `area:daemon`, `area:security`, `priority:p0`

Depends on: issue 32

Scope:

- Enforce max runtime.
- Send SIGTERM, then SIGKILL after grace period.
- Emit timeout/finished state.

Acceptance criteria:

- timed-out commands are terminated.
- child process groups do not remain orphaned.

### 37. Implement stream sequencing and duplicate suppression

Milestone: 4. Remote Exec MVP  
Labels: `type:feature`, `area:streaming`, `priority:p0`

Depends on: issue 33

Scope:

- Add per-stream sequence numbers.
- De-duplicate repeated chunks.
- Add tests for duplicate/out-of-order input.

Acceptance criteria:

- duplicate chunks do not duplicate terminal output.
- sequence state is tracked per stream.

### 38. Implement missing chunk detection and degraded stream mode

Milestone: 4. Remote Exec MVP  
Labels: `type:feature`, `area:streaming`, `priority:p1`

Depends on: issue 37

Scope:

- Buffer out-of-order chunks.
- Detect missing chunks after timeout.
- Mark stream degraded.

Acceptance criteria:

- missing chunks are surfaced to CLI/user.
- best-effort output continues by default.

### 39. Implement strict stream mode

Milestone: 4. Remote Exec MVP  
Labels: `type:feature`, `area:streaming`, `priority:p2`

Depends on: issue 38

Scope:

- Add `--strict-stream`.
- Fail invocation rendering on missing/invalid chunks.
- Return exit code `132` for stream integrity failure.

Acceptance criteria:

- strict mode fails on simulated missing chunk.
- default mode remains best-effort.

### 40. Implement rate limiting and output caps

Milestone: 4. Remote Exec MVP  
Labels: `type:feature`, `area:streaming`, `area:policy`, `priority:p0`

Depends on: issue 33

Scope:

- Enforce max output bytes.
- Limit event rate per invocation.
- Truncate/summarize excessive output.

Acceptance criteria:

- high-output command does not flood Matrix.
- truncation is explicit in finished event.

---

## Milestone 5 — Orchestration Layer

Covers roadmap phases 10–12.

### 41. Implement task create/update/list commands

Milestone: 5. Orchestration Layer  
Labels: `type:feature`, `area:tasks`, `priority:p0`

Depends on: milestone 4

Scope:

- `task create`.
- `task update`.
- `task list`.
- Matrix `com.mxagent.task.v1` state events.

Acceptance criteria:

- tasks can be created and updated in room state.
- filtering by state/assignee works.

### 42. Implement task DAG graph rendering

Milestone: 5. Orchestration Layer  
Labels: `type:feature`, `area:tasks`, `priority:p1`

Depends on: issue 41

Scope:

- Parse `depends_on` edges.
- Detect cycles.
- Render text graph.
- Output JSON graph.

Acceptance criteria:

- graph output matches documented example.
- cycles are reported clearly.

### 43. Implement invocation state tracking

Milestone: 5. Orchestration Layer  
Labels: `type:feature`, `area:tasks`, `area:protocol`, `priority:p0`

Depends on: issue 31

Scope:

- Publish `com.mxagent.invocation.v1` state.
- Update lifecycle states.
- Link invocation to task ID.

Acceptance criteria:

- `invocation list --state running` works.
- task shows linked invocation.

### 44. Implement state revision and stale update detection

Milestone: 5. Orchestration Layer  
Labels: `type:feature`, `area:tasks`, `area:protocol`, `priority:p1`

Depends on: issue 41

Scope:

- Add `state_rev` handling.
- Track previous event IDs.
- Warn/reject stale updates client-side.

Acceptance criteria:

- stale task update is detected in tests.
- newer state is not overwritten silently.

### 45. Implement context share for small payloads

Milestone: 5. Orchestration Layer  
Labels: `type:feature`, `area:matrix`, `priority:p1`

Scope:

- `share --type --name < stdin`.
- `share diff`.
- `share env`.
- Send `com.mxagent.context.share.v1` timeline event.

Acceptance criteria:

- JSON/text context can be shared and listed.
- diff command captures current git diff.

### 46. Implement Matrix media upload/download for shared context

Milestone: 5. Orchestration Layer  
Labels: `type:feature`, `area:matrix`, `priority:p1`

Depends on: issue 45

Scope:

- Upload large shared context to Matrix media.
- Include `mxc://`, size, mime, sha256.
- Retrieve and verify context artifacts.

Acceptance criteria:

- large context uses media instead of timeline body.
- sha256 mismatch is detected.

### 47. Implement invocation cancellation protocol

Milestone: 5. Orchestration Layer  
Labels: `type:feature`, `area:daemon`, `priority:p0`

Depends on: issue 36

Scope:

- Send `com.mxagent.exec.cancel.v1`.
- Verify requester authorization.
- Terminate process group.
- Emit `com.mxagent.exec.cancelled.v1`.

Acceptance criteria:

- `invocation cancel` terminates running remote command.
- unauthorized cancellation is rejected.

### 48. Implement approval request queue

Milestone: 5. Orchestration Layer  
Labels: `type:feature`, `area:policy`, `area:security`, `priority:p1`

Depends on: issue 26

Scope:

- Honor `requires_approval` policy.
- Queue pending requests.
- Emit approval request event.

Acceptance criteria:

- approval-required request does not execute immediately.
- pending approvals are visible locally.

### 49. Implement approval CLI decisions

Milestone: 5. Orchestration Layer  
Labels: `type:feature`, `area:cli`, `area:security`, `priority:p1`

Depends on: issue 48

Scope:

- `approval list`.
- `approval show`.
- `approval approve`.
- `approval deny`.
- Emit decision events.

Acceptance criteria:

- approved request proceeds.
- denied request never spawns.

### 50. Implement workspace/task watch mode

Milestone: 5. Orchestration Layer  
Labels: `type:feature`, `area:cli`, `area:tasks`, `priority:p2`

Depends on: issues 41, 43

Scope:

- `task watch`.
- `workspace status --watch`.
- Render state changes live.

Acceptance criteria:

- task transitions appear without rerunning command.
- watch mode handles reconnect gracefully.

---

## Milestone 6 — Production Hardening

Covers roadmap phases 13–16.

### 51. Implement environment allowlist and secret scrubbing

Milestone: 6. Production Hardening  
Labels: `type:security`, `area:sandbox`, `priority:p0`

Depends on: issue 32

Scope:

- Default child env to allowlist.
- Explicitly scrub common token variables.
- Add tests for secret removal.

Acceptance criteria:

- child env excludes Matrix/API/cloud tokens by default.
- policy can explicitly allow safe vars.

### 52. Implement baseline sandbox abstraction

Milestone: 6. Production Hardening  
Labels: `type:feature`, `area:sandbox`, `priority:p0`

Depends on: issue 32

Scope:

- Define sandbox trait/interface.
- Implement `none` backend with restrictions.
- Centralize cwd/env/timeout/output controls.

Acceptance criteria:

- process runner uses sandbox abstraction.
- sandbox selection appears in audit log.

### 53. Implement bubblewrap sandbox backend

Milestone: 6. Production Hardening  
Labels: `type:feature`, `area:sandbox`, `area:security`, `priority:p1`

Depends on: issue 52

Scope:

- Add bubblewrap runner.
- Support network deny.
- Configure read-only and writable paths.

Acceptance criteria:

- command runs inside bubblewrap when configured.
- denied network/path behavior is validated where possible.

### 54. Implement Docker/Podman sandbox backend

Milestone: 6. Production Hardening  
Labels: `type:feature`, `area:sandbox`, `priority:p2`

Depends on: issue 52

Scope:

- Add container runner backend.
- Mount workspace safely.
- Pass sanitized env only.

Acceptance criteria:

- command runs in configured image.
- workspace is mounted according to policy.

### 55. Implement stream artifact output mode

Milestone: 6. Production Hardening  
Labels: `type:feature`, `area:streaming`, `area:matrix`, `priority:p1`

Depends on: issue 40

Scope:

- Switch large output to Matrix media.
- Compress logs with zstd where available.
- Emit `com.mxagent.stream.artifact.v1`.
- Include tail preview and hash.

Acceptance criteria:

- high-output commands upload full log as artifact.
- terminal shows useful preview.

### 56. Implement artifact retrieval command

Milestone: 6. Production Hardening  
Labels: `type:feature`, `area:cli`, `area:streaming`, `priority:p2`

Depends on: issue 55

Scope:

- Add command to fetch invocation artifacts.
- Verify hash.
- Decompress if needed.

Acceptance criteria:

- user can retrieve stdout/stderr artifact by invocation ID.
- corrupt artifact fails verification.

### 57. Implement PTY mode

Milestone: 6. Production Hardening  
Labels: `type:feature`, `area:streaming`, `priority:p2`

Depends on: milestone 4

Scope:

- Local raw terminal mode.
- Remote PTY allocation.
- Merged PTY stream.
- Resize events.

Acceptance criteria:

- `mx-agent exec --pty -- bash` works between two agents.
- terminal resize propagates.

### 58. Implement Ctrl-C and terminal signal semantics

Milestone: 6. Production Hardening  
Labels: `type:feature`, `area:streaming`, `priority:p2`

Depends on: issue 57

Scope:

- Define local interrupt behavior.
- Forward control characters/signals as appropriate.
- Restore terminal state on exit.

Acceptance criteria:

- Ctrl-C behavior is documented and tested manually.
- local terminal is restored after failure.

### 59. Build local Matrix integration test harness

Milestone: 6. Production Hardening  
Labels: `type:testing`, `area:matrix`, `priority:p1`

Depends on: milestone 4

Scope:

- Run local Synapse/Dendrite container in tests or scripts.
- Create test users/rooms.
- Exercise daemon sync and events.

Acceptance criteria:

- integration test can run locally from documented command.
- CI path is planned or implemented.

### 60. Add E2EE integration coverage

Milestone: 6. Production Hardening  
Labels: `type:testing`, `area:matrix`, `area:security`, `priority:p1`

Depends on: issue 59

Scope:

- Enable E2EE test room.
- Verify encrypted event send/receive.
- Test undecryptable event behavior.

Acceptance criteria:

- encrypted exec/call metadata works in test harness.
- undecryptable privileged events are not executed.

### 61. Add reconnect, replay, and rate-limit chaos tests

Milestone: 6. Production Hardening  
Labels: `type:testing`, `area:daemon`, `area:streaming`, `priority:p1`

Depends on: issues 14, 22, 40

Scope:

- Simulate daemon restart.
- Simulate duplicate/replayed events.
- Simulate stream gaps and rate limits.

Acceptance criteria:

- daemon recovers expected state after restart.
- replayed privileged requests remain denied.

### 62. Add cargo-deny and dependency policy

Milestone: 6. Production Hardening  
Labels: `type:security`, `type:ci`, `priority:p1`

Depends on: issue 1

Scope:

- Add `cargo-deny` config.
- Define license/advisory policy.
- Add CI check.

Acceptance criteria:

- `cargo deny check` passes.
- denied licenses/advisories fail CI.

### 63. Add release packaging workflow

Milestone: 6. Production Hardening  
Labels: `type:ci`, `priority:p2`

Depends on: milestone 4

Scope:

- Build release binaries for Linux/macOS/Windows targets.
- Generate checksums.
- Attach artifacts to GitHub Releases.

Acceptance criteria:

- tagged release builds artifacts.
- checksums are published.

### 64. Write alpha user guide

Milestone: 6. Production Hardening  
Labels: `type:docs`, `area:docs`, `priority:p1`

Depends on: milestones 2, 3, 4

Scope:

- Install instructions.
- Login/setup.
- Create workspace.
- Register agents.
- Run tool call and exec.
- Security warnings.

Acceptance criteria:

- new user can run a two-agent demo from docs.

### 65. Write security hardening guide

Milestone: 6. Production Hardening  
Labels: `type:docs`, `type:security`, `area:docs`, `priority:p1`

Depends on: issues 26, 51, 52

Scope:

- Policy examples.
- Token isolation model.
- Trust bootstrap.
- Sandbox configuration.
- Audit logging.

Acceptance criteria:

- guide explains safe defaults and unsafe options clearly.

### 66. Prepare public alpha release checklist

Milestone: 6. Production Hardening  
Labels: `type:docs`, `type:ci`, `priority:p2`

Depends on: issues 59, 62, 63, 64, 65

Scope:

- Define alpha gate checklist.
- Include known limitations.
- Include rollback and revocation guidance.

Acceptance criteria:

- maintainers can decide whether a commit is alpha-release ready.
