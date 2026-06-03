# mx-agent Architecture

## Purpose

`mx-agent` is a specialized CLI and local daemon for decentralized orchestration between autonomous coding agents. It uses the Matrix protocol as a federated event backplane, allowing agents running on different machines to discover each other, exchange context, invoke tools, stream terminal input/output, and coordinate multi-step workflows.

The core design is:

```text
agent / shell / LLM runner
        |
        | mx-agent CLI
        v
local mx-agent daemon
        |
        | Matrix Client-Server API
        v
Matrix homeserver federation
```

The ephemeral CLI provides a Unix-native interface. The daemon owns Matrix sync, credentials, encryption state, policy enforcement, process supervision, and stream routing.

---

## 1. Command Surface and Agent UX

### Design Principles

- Stateless CLI invocations from the agent perspective.
- Pipe-friendly stdin/stdout/stderr behavior.
- JSON output for automation.
- Human-readable output by default.
- Long-lived Matrix sync hidden behind a local daemon.
- Every operation addressable by workspace, agent, task, and invocation ID.

### Core Concepts

| Concept | Matrix Mapping |
|---|---|
| Workspace | Matrix room |
| Agent | Matrix user/device/session plus agent state event |
| Remote execution | Request/response timeline events |
| Task | Room state event keyed by task ID |
| Stream | Chunked Matrix timeline events |
| Shared context | Timeline or state events with typed payloads |
| Capability | Agent state event |

### Command Groups

```bash
mx-agent workspace ...
mx-agent agent ...
mx-agent exec ...
mx-agent call ...
mx-agent share ...
mx-agent task ...
mx-agent daemon ...
mx-agent auth ...
```

---

### Workspace Commands

Create a workspace:

```bash
mx-agent workspace create \
  --alias my-project \
  --name "my-project orchestration" \
  --visibility private
```

Join a workspace:

```bash
mx-agent workspace join '#my-project:matrix.org'
mx-agent workspace join '!abc123:matrix.org'
```

Attach the current directory to a workspace:

```bash
mx-agent workspace attach \
  --room '!abc123:matrix.org' \
  --path "$PWD" \
  --project-id 'repo:github.com/org/project'
```

Show workspace status:

```bash
mx-agent workspace status --room '!abc123:matrix.org'
mx-agent workspace status --room '!abc123:matrix.org' --json
```

---

### Agent Commands

Register the current agent session:

```bash
mx-agent agent register \
  --name claude-local \
  --kind claude-code \
  --capability plan \
  --capability review \
  --capability shell:limited
```

Register a Pi runner:

```bash
mx-agent agent register \
  --name developer-pi \
  --kind pi \
  --capability shell \
  --capability edit \
  --capability test \
  --capability repo:node
```

List available agents:

```bash
mx-agent agent list --room '!abc123:matrix.org'
mx-agent agent list --room '!abc123:matrix.org' --json
```

---

### Remote Execution Commands

Run a command on a remote agent:

```bash
mx-agent exec \
  --room '!abc123:matrix.org' \
  --agent developer-pi \
  --cwd /home/me/code/project \
  --stream \
  -- npm test
```

Invoke a named remote tool:

```bash
mx-agent call \
  --room '!abc123:matrix.org' \
  --agent developer-pi \
  --tool run_tests \
  --arg package=api \
  --arg coverage=true
```

Pipe stdin to a remote command:

```bash
git diff | mx-agent exec \
  --room '!abc123:matrix.org' \
  --agent developer-pi \
  --stdin \
  -- bash -lc 'cat > /tmp/patch.diff && npm test'
```

Remote command exit codes should propagate to the local process:

```bash
mx-agent exec --agent developer-pi -- npm test
echo $?
```

Recommended reserved local/protocol exit codes:

| Code | Meaning |
|---:|---|
| 0 | Remote command succeeded |
| 1-125 | Remote command exit code |
| 126 | Local policy denied |
| 127 | Agent or command not found |
| 128 | Protocol or network failure |
| 129 | Timeout |
| 130 | Interrupted |

---

### Context Sharing Commands

Share a git diff:

```bash
mx-agent share diff \
  --room '!abc123:matrix.org' \
  --base main \
  --format unified
```

Share arbitrary typed context:

```bash
mx-agent share \
  --room '!abc123:matrix.org' \
  --type application/json \
  --name plan.json \
  < plan.json
```

Share environment metadata:

```bash
mx-agent share env \
  --room '!abc123:matrix.org' \
  --include node,npm,os,git
```

---

### Task Commands

Create a task:

```bash
mx-agent task create \
  --room '!abc123:matrix.org' \
  --title 'Run API tests' \
  --depends-on task-plan \
  --assign developer-pi
```

Update a task:

```bash
mx-agent task update \
  --room '!abc123:matrix.org' \
  --task task-test-api \
  --state executing
```

List or watch tasks:

```bash
mx-agent task list --room '!abc123:matrix.org'
mx-agent task watch --room '!abc123:matrix.org'
mx-agent task graph --room '!abc123:matrix.org'
```

---

### Claude Code to Pi Example

Claude Code asks a remote Pi agent to run tests:

```bash
mx-agent workspace join '#project-orchestration:matrix.org'

mx-agent share diff \
  --room '#project-orchestration:matrix.org' \
  --base main

mx-agent exec \
  --room '#project-orchestration:matrix.org' \
  --agent developer-pi \
  --cwd /home/me/code/project \
  --stream \
  -- npm test
```

Structured task-backed version:

```bash
TASK_ID=$(mx-agent task create \
  --room '#project-orchestration:matrix.org' \
  --title 'Run npm test on latest diff' \
  --assign developer-pi \
  --json | jq -r .task_id)

mx-agent exec \
  --room '#project-orchestration:matrix.org' \
  --agent developer-pi \
  --task "$TASK_ID" \
  --cwd /home/me/code/project \
  --stream \
  -- npm test
```

---

## 2. POSIX Stream Mapping to Matrix

Matrix events are discrete JSON objects, while terminal I/O is byte-oriented. `mx-agent` maps process streams to chunked Matrix timeline events.

```text
local stdin  -> Matrix stream chunks -> remote child stdin
local stdout <- Matrix stream chunks <- remote child stdout
local stderr <- Matrix stream chunks <- remote child stderr
exit status  <- Matrix finished event  <- remote child exit
```

### Invocation Request

When a user runs:

```bash
mx-agent exec --room '!abc:matrix.org' --agent developer-pi -- npm test
```

The local daemon emits:

```json
{
  "type": "com.mxagent.exec.request",
  "content": {
    "schema": "com.mxagent.exec.request.v1",
    "invocation_id": "inv_01HZ...",
    "target_agent": "developer-pi",
    "requesting_agent": "claude-local",
    "command": ["npm", "test"],
    "cwd": "/home/me/code/project",
    "env": {},
    "stdin": true,
    "stream": true,
    "pty": false,
    "timeout_ms": 600000,
    "task_id": "task-test-api"
  }
}
```

The remote daemon verifies identity and policy, then responds with either accepted or rejected.

Accepted:

```json
{
  "type": "com.mxagent.exec.accepted",
  "content": {
    "invocation_id": "inv_01HZ...",
    "agent": "developer-pi",
    "pid": 18422,
    "started_at": "2026-06-02T12:00:00Z"
  }
}
```

Rejected:

```json
{
  "type": "com.mxagent.exec.rejected",
  "content": {
    "invocation_id": "inv_01HZ...",
    "reason": "policy_denied"
  }
}
```

### Stream Chunk Event

```json
{
  "type": "com.mxagent.stream.chunk",
  "content": {
    "invocation_id": "inv_01HZ...",
    "stream": "stdout",
    "seq": 42,
    "encoding": "utf-8",
    "data": "PASS src/foo.test.ts\n",
    "eof": false,
    "timestamp": "2026-06-02T12:00:01.123Z"
  }
}
```

For binary data:

```json
{
  "type": "com.mxagent.stream.chunk",
  "content": {
    "invocation_id": "inv_01HZ...",
    "stream": "stdout",
    "seq": 43,
    "encoding": "base64",
    "data": "AAECAwQ=",
    "eof": false
  }
}
```

End of stdin:

```json
{
  "type": "com.mxagent.stream.chunk",
  "content": {
    "invocation_id": "inv_01HZ...",
    "stream": "stdin",
    "seq": 12,
    "encoding": "utf-8",
    "data": "",
    "eof": true
  }
}
```

Finished event:

```json
{
  "type": "com.mxagent.exec.finished",
  "content": {
    "invocation_id": "inv_01HZ...",
    "exit_code": 1,
    "signal": null,
    "duration_ms": 18231,
    "stdout_bytes": 50231,
    "stderr_bytes": 1409
  }
}
```

### Chunking Defaults

Recommended defaults:

```text
max_chunk_bytes: 16 KiB
max_flush_interval: 50 ms
max_events_per_second: configurable
compression: optional for large non-interactive payloads
```

Stream sequencing is per invocation and per stream:

```text
(invocation_id, stream, seq)
```

The receiver buffers out-of-order chunks until missing sequence numbers arrive or a timeout expires.

### PTY Mode

Interactive commands can request PTY mode:

```bash
mx-agent exec --agent developer-pi --pty -- bash
```

PTY mode:

- Merges stdout and stderr.
- Preserves ANSI escape sequences.
- Uses raw local terminal input.
- Propagates terminal size changes.

Resize event:

```json
{
  "type": "com.mxagent.pty.resize",
  "content": {
    "invocation_id": "inv_01HZ...",
    "cols": 120,
    "rows": 40
  }
}
```

---

## 3. Orchestration State Machine and DAG Tracking

Use Matrix room state events for durable workflow state and timeline events for logs and streaming output.

### Agent State

State event:

```text
type: com.mxagent.agent.v1
state_key: <agent_id>
```

Content:

```json
{
  "agent_id": "developer-pi",
  "kind": "pi",
  "device_id": "MXAGENTDEVICE01",
  "status": "active",
  "capabilities": [
    "shell",
    "edit",
    "test",
    "repo:node",
    "sandbox:docker"
  ],
  "policy": {
    "requires_approval": false,
    "allowed_commands": ["npm", "pnpm", "pytest", "go", "cargo"],
    "max_runtime_ms": 900000
  },
  "workspace": {
    "cwd": "/home/me/code/project",
    "project_id": "repo:github.com/org/project",
    "git_commit": "abc123"
  },
  "load": {
    "running_invocations": 1,
    "max_invocations": 4
  },
  "last_seen_ts": 1780392000000
}
```

Agents should update durable state periodically and optionally emit lower-cost heartbeat events for liveness.

### Task State

State event:

```text
type: com.mxagent.task.v1
state_key: <task_id>
```

Content:

```json
{
  "task_id": "task-test-api",
  "title": "Run API tests",
  "description": "Run npm test after applying latest diff",
  "state": "executing",
  "assigned_to": "developer-pi",
  "created_by": "claude-local",
  "depends_on": ["task-plan"],
  "blocks": ["task-review"],
  "invocation_id": "inv_01HZ...",
  "created_at": "2026-06-02T12:00:00Z",
  "updated_at": "2026-06-02T12:01:12Z",
  "result": null
}
```

Allowed task states:

```text
proposed
pending
assigned
executing
blocked
succeeded
failed
cancelled
superseded
```

A task is runnable when:

```text
state is pending or assigned
all depends_on tasks are succeeded
assigned agent is active
local policy permits execution
```

### Invocation State

State event:

```text
type: com.mxagent.invocation.v1
state_key: <invocation_id>
```

Content:

```json
{
  "invocation_id": "inv_01HZ...",
  "task_id": "task-test-api",
  "requester": "claude-local",
  "target": "developer-pi",
  "command": ["npm", "test"],
  "state": "running",
  "started_at": "2026-06-02T12:00:00Z",
  "updated_at": "2026-06-02T12:00:05Z"
}
```

Invocation transitions:

```text
requested -> accepted -> running -> succeeded
                              -> failed
                              -> cancelled
                              -> timed_out
                              -> rejected
```

### Querying State

List active agents:

```bash
mx-agent agent list --room '!abc:matrix.org' --json
```

Implementation:

1. Fetch room state.
2. Filter `com.mxagent.agent.v1` events.
3. Check Matrix membership and latest heartbeat.
4. Verify device or signing key trust where required.

List tasks:

```bash
mx-agent task list --room '!abc:matrix.org'
mx-agent task list --room '!abc:matrix.org' --state pending
mx-agent task list --room '!abc:matrix.org' --assigned developer-pi
mx-agent task graph --room '!abc:matrix.org'
```

Example graph output:

```text
task-plan       succeeded
  └─ task-code  succeeded
      └─ task-test  failed
          └─ task-review blocked
```

---

## 4. Daemon and IPC Architecture

### Why a Daemon Exists

Matrix clients need long-lived state:

- `/sync` loop.
- End-to-end encryption sessions.
- Device verification.
- Event retries and backoff.
- Room state cache.
- Stream reassembly.
- Incoming exec handling.
- Policy enforcement.

Ephemeral CLI commands should not each perform a full Matrix login/sync lifecycle.

### Component Split

The CLI owns:

- Argument parsing.
- Local stdin/stdout/stderr bridging.
- Output formatting.
- Exit code propagation.
- Short-lived user interaction.

The daemon owns:

- Matrix access token.
- Device and E2EE keys.
- Matrix sync loop.
- Event send/receive routing.
- Room state cache.
- Agent registration and heartbeat.
- Local authorization policy.
- Process spawning for local executions.
- Stream chunking and reassembly.
- Retry queues.
- Rate limiting.
- Audit logging.

### IPC Transport

Preferred POSIX transport:

```text
$XDG_RUNTIME_DIR/mx-agent/daemon.sock
```

Properties:

- Unix domain socket.
- Mode `0600`.
- Owned by the current user.
- Supports peer credential checks with `SO_PEERCRED` on Linux.

Windows equivalent:

```text
\\.\pipe\mx-agent-daemon
```

### IPC Protocol

Initial recommendation: JSON-RPC over a framed Unix socket.

Example request:

```json
{
  "jsonrpc": "2.0",
  "id": "req-123",
  "method": "exec.start",
  "params": {
    "room": "!abc:matrix.org",
    "agent": "developer-pi",
    "command": ["npm", "test"],
    "cwd": "/home/me/code/project",
    "stdin": true,
    "stream": true,
    "pty": false
  }
}
```

Response:

```json
{
  "jsonrpc": "2.0",
  "id": "req-123",
  "result": {
    "invocation_id": "inv_01HZ..."
  }
}
```

Streaming frame from daemon to CLI:

```json
{
  "method": "stream.stdout",
  "params": {
    "invocation_id": "inv_01HZ...",
    "data": "PASS src/foo.test.ts\n"
  }
}
```

Streaming frame from CLI to daemon:

```json
{
  "method": "stream.stdin",
  "params": {
    "invocation_id": "inv_01HZ...",
    "data": "...",
    "eof": false
  }
}
```

---

## 5. Security Boundary and Token Isolation

`mx-agent` can trigger remote code execution, so room membership must never imply execution permission.

### Security Goals

1. Matrix access tokens are never exposed to coding agents.
2. Device keys are never readable by child processes.
3. Remote execution requires explicit local policy.
4. Privileged requests are signed and auditable.
5. E2EE is used where possible.
6. Agents run commands in restricted environments by default.

### Credential Storage

The daemon owns all credentials.

Recommended Linux paths:

```text
~/.local/share/mx-agent/session.db
~/.local/share/mx-agent/crypto-store/
~/.config/mx-agent/config.toml
~/.config/mx-agent/policy.toml
$XDG_RUNTIME_DIR/mx-agent/daemon.sock
```

Permissions:

```bash
chmod 0700 ~/.local/share/mx-agent
chmod 0600 ~/.local/share/mx-agent/session.db
chmod 0700 ~/.local/share/mx-agent/crypto-store
chmod 0600 ~/.config/mx-agent/policy.toml
```

macOS should use Keychain for tokens. Windows should use Credential Manager or DPAPI.

Never expose Matrix tokens through:

- Environment variables.
- Command arguments.
- Logs.
- Shell history.
- stdout/stderr.
- Matrix messages.
- Agent-readable config files.

### Daemon Socket Protection

The daemon should reject IPC clients that do not match the current UID. On Linux, verify peer credentials via `SO_PEERCRED`.

Socket path:

```text
$XDG_RUNTIME_DIR/mx-agent/daemon.sock
```

Permissions:

```text
0600
```

### Execution Policy

Example policy:

```toml
[rooms."!abc:matrix.org"]
trusted = true

[rooms."!abc:matrix.org".agents."@claude:matrix.org"]
allow_exec = true
allow_tools = ["run_tests", "lint", "read_file"]
allow_commands = ["npm", "pnpm", "pytest", "go", "cargo"]
allow_cwd = ["/home/me/code/project"]
deny_args_regex = [
  "curl\\s+.*\\|\\s*sh",
  "rm\\s+-rf\\s+/",
  "ssh",
  "scp"
]
max_runtime_ms = 900000
max_output_bytes = 5000000
requires_approval = false
```

Prefer named tools over arbitrary shell commands:

```bash
mx-agent call --tool run_tests
```

Raw shell execution should be disabled in high-security environments.

### Signed Requests

Each daemon manages an Ed25519 signing key. Privileged requests include a signature over canonical JSON.

```json
{
  "type": "com.mxagent.exec.request",
  "content": {
    "invocation_id": "inv_01HZ...",
    "requester_agent": "claude-local",
    "target_agent": "developer-pi",
    "command": ["npm", "test"],
    "nonce": "random",
    "created_at": "2026-06-02T12:00:00Z",
    "expires_at": "2026-06-02T12:05:00Z",
    "signature": {
      "alg": "ed25519",
      "key_id": "mxagent-ed25519:abc123",
      "sig": "base64..."
    }
  }
}
```

The receiver verifies:

- Signature validity.
- Trusted key for the room.
- Matrix sender and device match expected identity.
- Nonce has not been replayed.
- Request has not expired.
- Local policy allows the operation.

### Environment Scrubbing

Remote child processes should receive a sanitized environment. Default behavior should be allowlist-based.

Sensitive values to exclude unless explicitly allowed:

```text
MATRIX_ACCESS_TOKEN
MX_AGENT_TOKEN
SSH_AUTH_SOCK
GITHUB_TOKEN
OPENAI_API_KEY
ANTHROPIC_API_KEY
AWS_*
GOOGLE_*
AZURE_*
NPM_TOKEN
```

### Sandboxing

Minimum controls:

- Restricted cwd.
- Sanitized env.
- Timeout.
- Output cap.
- Kill process group on timeout.

Stronger controls:

- Docker or Podman.
- bubblewrap or firejail.
- chroot.
- user namespace.
- seccomp.
- Read-only filesystem except workspace.
- Network disabled by default.

Example sandbox config:

```toml
[execution]
default_sandbox = "bubblewrap"
network = "deny"
read_only_paths = ["/usr", "/bin", "/lib"]
writable_paths = ["/home/me/code/project", "/tmp/mx-agent"]
```

### Room Security Recommendations

- Private rooms.
- Invite-only membership.
- E2EE enabled.
- History visibility set to joined members only.
- Power levels restrict state events.
- Only trusted agents can send task or exec events.
- Separate rooms per workspace/repository.
- Optional per-task rooms for sensitive workflows.

### Audit Logging

Every privileged operation should produce a local audit record without secrets.

```json
{
  "ts": "2026-06-02T12:00:00Z",
  "room": "!abc:matrix.org",
  "requester": "@claude:matrix.org",
  "target": "developer-pi",
  "invocation_id": "inv_01HZ",
  "command": ["npm", "test"],
  "decision": "allowed",
  "policy_rule": "rooms.!abc.agents.@claude.allow_commands"
}
```

---

## Event Namespace

Recommended custom event types:

```text
com.mxagent.agent.v1
com.mxagent.task.v1
com.mxagent.invocation.v1
com.mxagent.exec.request
com.mxagent.exec.accepted
com.mxagent.exec.rejected
com.mxagent.exec.finished
com.mxagent.stream.chunk
com.mxagent.context.share
com.mxagent.pty.resize
```

---

## Suggested Implementation Structure

Rust and Go are both strong candidates.

Rust advantages:

- Strong async ecosystem.
- Matrix support via `matrix-rust-sdk`.
- Memory safety.
- Good Unix socket and PTY support.

Go advantages:

- Simple static binaries.
- Excellent process, CLI, and networking support.
- Operational simplicity.

Suggested source layout:

```text
mx-agent/
  cmd/
    root
    workspace
    agent
    exec
    call
    share
    task
    daemon
    auth
  daemon/
    matrix_sync
    event_router
    ipc_server
    process_runner
    policy_engine
    crypto_store
  protocol/
    events
    canonical_json
    signing
    stream_chunking
  sandbox/
    docker
    bubblewrap
    none
```

---

## End-to-End Flow

1. Claude Code runs `mx-agent exec --agent developer-pi -- npm test`.
2. The CLI sends `exec.start` to the local daemon over Unix socket.
3. The local daemon signs and emits `com.mxagent.exec.request` to the Matrix room.
4. The remote Pi daemon receives the request via Matrix sync.
5. The remote daemon verifies identity, signature, replay nonce, expiry, and local policy.
6. The remote daemon starts the command in a restricted environment.
7. stdout/stderr are chunked into `com.mxagent.stream.chunk` events.
8. The local daemon receives chunks and forwards them over IPC.
9. The local CLI writes data to stdout/stderr.
10. The remote daemon emits `com.mxagent.exec.finished`.
11. The local CLI exits with the remote process exit code.

The fundamental split remains:

```text
CLI = stateless Unix UX
Daemon = Matrix session, crypto, policy, process orchestration
Matrix = federated event log and distributed state machine
```
