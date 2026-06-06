# mx-agent Architecture

`mx-agent` is a Matrix-backed CLI and daemon for decentralized orchestration between autonomous coding agents such as Pi, Claude Code, and terminal-based LLM runners.

It turns Matrix rooms into federated workspaces where agents can discover peers, share context, invoke tools, stream terminal I/O, and coordinate distributed task DAGs without central orchestration servers or inbound firewall access.

---

## 0. Executive Summary

```text
agent / shell / LLM runner
        |
        | ephemeral mx-agent CLI
        v
local mx-agent daemon
        |
        | Matrix Client-Server API + E2EE
        v
Matrix homeserver federation
```

Core split:

```text
CLI     = stateless Unix UX, stdio bridge, output formatting, exit-code propagation
Daemon  = Matrix sync, credentials, crypto, policy, process supervision, stream routing
Matrix  = federated event log, room state store, workspace membership, distributed DAG state
```

Primary design constraints:

- The coding agent must never see Matrix access tokens or device keys.
- Matrix room membership must not imply remote execution permission.
- Streaming terminal data over Matrix must be rate-limited, chunked, resumable, and fall back to artifact upload for large outputs.
- Task and invocation state must be durable enough to survive daemon restarts and Matrix reconnects.
- Raw shell execution should be optional; named tools should be the safer default.

---

## 1. System Model

### 1.1 Core Entities

| Entity | Description | Matrix Mapping |
|---|---|---|
| Workspace | Shared project coordination context | Matrix room |
| Agent | Local daemon persona representing a coding agent/runtime | Matrix user/device plus `com.mxagent.agent.v1` state |
| Capability | Advertised function or constraint | Agent state content |
| Tool | Named, policy-controlled operation | `call` request/response events |
| Exec | Raw or shell-like remote process invocation | `exec` request/response events |
| Invocation | One running or completed remote call/exec | `com.mxagent.invocation.v1` state |
| Task | Durable DAG node | `com.mxagent.task.v1` state |
| Stream | stdin/stdout/stderr/pty data | chunked timeline events or media artifacts |
| Context | Diffs, env snapshots, plans, summaries | timeline event or Matrix media object |

### 1.2 Trust Model

There are three independent identities:

1. **Matrix user ID**: e.g. `@alice:matrix.org`.
2. **Matrix device ID / E2EE identity**: homeserver/client cryptographic device identity.
3. **mx-agent signing identity**: daemon-managed Ed25519 key used to sign privileged agent requests.

All privileged operations should verify all applicable layers:

```text
room membership
+ Matrix event sender
+ Matrix device trust, if E2EE is enabled
+ mx-agent request signature
+ local policy
+ optional human approval
```

---

## 2. CLI Command Surface

### 2.1 Design Principles

- Stateless invocations from the agent's perspective.
- POSIX pipe friendly.
- Human-readable by default, `--json` for automation.
- `--` separates CLI options from remote command arguments.
- Every operation can be scoped by `--room`, `--agent`, `--task`, and `--invocation`.
- Long-lived Matrix session state lives only in the daemon.

### 2.2 Command Groups

```bash
mx-agent workspace ...
mx-agent agent ...
mx-agent exec ...
mx-agent call ...
mx-agent share ...
mx-agent task ...
mx-agent invocation ...
mx-agent approval ...
mx-agent daemon ...
mx-agent auth ...
mx-agent trust ...
```

---

## 3. Workspace Commands

Create a Matrix-backed workspace:

```bash
mx-agent workspace create \
  --alias my-project \
  --name "my-project orchestration" \
  --visibility private \
  --e2ee on
```

Join an existing workspace:

```bash
mx-agent workspace join '#my-project:matrix.org'
mx-agent workspace join '!abc123:matrix.org'
```

Attach the current repository/path:

```bash
mx-agent workspace attach \
  --room '!abc123:matrix.org' \
  --path "$PWD" \
  --project-id 'repo:github.com/org/project'
```

Inspect status:

```bash
mx-agent workspace status --room '!abc123:matrix.org'
mx-agent workspace status --room '!abc123:matrix.org' --json
```

Example output:

```text
Workspace: !abc123:matrix.org
Project: repo:github.com/org/project
Agents:
  claude-local    active  plan,review
  developer-pi    active  shell,test,edit,repo:node
Tasks:
  task-plan       succeeded
  task-test       executing  developer-pi
```

---

## 4. Agent Commands

Register a Claude Code agent session:

```bash
mx-agent agent register \
  --room '!abc123:matrix.org' \
  --name claude-local \
  --kind claude-code \
  --capability plan \
  --capability review
```

Register a Pi runner:

```bash
mx-agent agent register \
  --room '!abc123:matrix.org' \
  --name developer-pi \
  --kind pi \
  --capability shell \
  --capability edit \
  --capability test \
  --capability repo:node \
  --capability sandbox:docker
```

List agents:

```bash
mx-agent agent list --room '!abc123:matrix.org'
mx-agent agent list --room '!abc123:matrix.org' --capability test --json
```

Show one agent:

```bash
mx-agent agent show --room '!abc123:matrix.org' developer-pi --json
```

---

## 5. Exec and Tool Invocation

### 5.1 Raw Remote Exec

```bash
mx-agent exec \
  --room '!abc123:matrix.org' \
  --agent developer-pi \
  --cwd /home/me/code/project \
  --stream \
  -- npm test
```

Pipe stdin:

```bash
git diff | mx-agent exec \
  --room '!abc123:matrix.org' \
  --agent developer-pi \
  --stdin \
  -- bash -lc 'cat > /tmp/patch.diff && npm test'
```

Interactive PTY:

```bash
mx-agent exec --room '!abc123:matrix.org' --agent developer-pi --pty -- bash
```

Cancel an invocation:

```bash
mx-agent invocation cancel \
  --room '!abc123:matrix.org' \
  --invocation inv_01HZ...
```

### 5.2 Named Tool Calls

Named tools are the preferred security boundary. They avoid arbitrary shell injection and allow strict input/output schemas.

```bash
mx-agent call \
  --room '!abc123:matrix.org' \
  --agent developer-pi \
  --tool run_tests \
  --arg package=api \
  --arg coverage=true
```

JSON input:

```bash
mx-agent call \
  --room '!abc123:matrix.org' \
  --agent developer-pi \
  --tool run_tests \
  --input-json tests.request.json \
  --json
```

Discover tools:

```bash
mx-agent agent tools --room '!abc123:matrix.org' --agent developer-pi
mx-agent agent tools --room '!abc123:matrix.org' --agent developer-pi --json
```

Tool metadata should include:

```json
{
  "name": "run_tests",
  "version": "1.0.0",
  "description": "Run project test suites",
  "input_schema": {
    "type": "object",
    "properties": {
      "package": { "type": "string" },
      "coverage": { "type": "boolean" }
    },
    "required": ["package"]
  },
  "output_schema": {
    "type": "object",
    "properties": {
      "exit_code": { "type": "integer" },
      "summary": { "type": "string" },
      "log_mxc": { "type": "string" }
    }
  }
}
```

### 5.3 Exit Codes

The local CLI should exit with the remote process exit code when possible.

| Code | Meaning |
|---:|---|
| 0 | Remote command succeeded |
| 1-125 | Remote command exit code |
| 126 | Local policy denied |
| 127 | Agent/tool/command not found |
| 128 | Protocol/network failure |
| 129 | Timeout |
| 130 | Interrupted/cancelled locally |
| 131 | Remote rejected request |
| 132 | Stream integrity failure |

---

## 6. Context Sharing

Share a diff:

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

List recently shared context in a room:

```bash
mx-agent share list \
  --room '!abc123:matrix.org' \
  --limit 50
```

Retrieve and verify a shared artifact by ID (writes the raw bytes to stdout, or
to `--output`):

```bash
mx-agent share get \
  --room '!abc123:matrix.org' \
  --context-id ctx_01HZ... \
  --output full-test-log.txt
```

Small context objects (up to 256 KiB) are inlined directly in the event,
avoiding a media round-trip. Text payloads are stored verbatim (`encoding:
"utf-8"`); binary payloads are base64-encoded (`encoding: "base64"`). The
`sha256` digest always covers the raw bytes:

```json
{
  "type": "com.mxagent.context.share",
  "content": {
    "context_id": "ctx_01HZ...",
    "name": "plan.json",
    "mime_type": "application/json",
    "size_bytes": 27,
    "sha256": "base64...",
    "data": "{\"step\":\"run tests\"}",
    "encoding": "utf-8"
  }
}
```

Large context objects (over 256 KiB) are uploaded as Matrix media and
referenced by URI instead of inlining the bytes in the timeline:

```json
{
  "type": "com.mxagent.context.share",
  "content": {
    "context_id": "ctx_01HZ...",
    "name": "full-test-log.txt",
    "mime_type": "text/plain",
    "size_bytes": 2500000,
    "sha256": "base64...",
    "mxc_uri": "mxc://matrix.org/abcdef"
  }
}
```

On retrieval (`share get`), the artifact is fetched from media (or decoded from
the inline payload) and its SHA-256 is recomputed over the raw bytes and checked
against `sha256`; a mismatch is rejected as an integrity failure rather than
returned to the caller.

---

## 7. Matrix Protocol Mapping

### 7.1 Event Namespace

Timeline events:

```text
com.mxagent.exec.request.v1
com.mxagent.exec.accepted.v1
com.mxagent.exec.rejected.v1
com.mxagent.exec.finished.v1
com.mxagent.exec.stdin.v1
com.mxagent.exec.cancel.v1
com.mxagent.exec.cancelled.v1
com.mxagent.call.request.v1
com.mxagent.call.response.v1
com.mxagent.stream.chunk.v1
com.mxagent.stream.artifact.v1
com.mxagent.context.share.v1
com.mxagent.heartbeat.v1
com.mxagent.approval.request.v1
com.mxagent.approval.decision.v1
com.mxagent.pty.resize.v1
```

State events:

```text
com.mxagent.agent.v1
com.mxagent.task.v1
com.mxagent.invocation.v1
com.mxagent.tool.v1
com.mxagent.workspace.v1
com.mxagent.trust.v1
```

Use explicit `.v1` versions in Matrix event type names. Avoid changing semantics under the same version.

### 7.2 Exec Request

```json
{
  "type": "com.mxagent.exec.request.v1",
  "content": {
    "invocation_id": "inv_01HZ...",
    "request_id": "req_01HZ...",
    "target_agent": "developer-pi",
    "requesting_agent": "claude-local",
    "command": ["npm", "test"],
    "cwd": "/home/me/code/project",
    "env": {},
    "stdin": true,
    "stream": true,
    "pty": false,
    "timeout_ms": 600000,
    "task_id": "task-test-api",
    "created_at": "2026-06-02T12:00:00Z",
    "expires_at": "2026-06-02T12:05:00Z",
    "nonce": "base64-random",
    "idempotency_key": "exec:inv_01HZ...",
    "signature": {
      "alg": "ed25519",
      "key_id": "mxagent-ed25519:abc123",
      "sig": "base64..."
    }
  }
}
```

### 7.3 Stream Chunk

```json
{
  "type": "com.mxagent.stream.chunk.v1",
  "content": {
    "invocation_id": "inv_01HZ...",
    "stream": "stdout",
    "seq": 42,
    "encoding": "utf-8",
    "data": "PASS src/foo.test.ts\n",
    "eof": false,
    "compressed": false,
    "sha256": "optional-base64-chunk-digest",
    "timestamp": "2026-06-02T12:00:01.123Z"
  }
}
```

Supported streams:

```text
stdin
stdout
stderr
pty
control
```

For non-UTF-8 data, use base64:

```json
{
  "encoding": "base64",
  "data": "AAECAwQ="
}
```

### 7.4 Finished Event

```json
{
  "type": "com.mxagent.exec.finished.v1",
  "content": {
    "invocation_id": "inv_01HZ...",
    "exit_code": 1,
    "signal": null,
    "duration_ms": 18231,
    "stdout_bytes": 50231,
    "stderr_bytes": 1409,
    "truncated": false,
    "artifact_mxc": null
  }
}
```

### 7.5 Stdin and Cancellation

Requester may stream stdin to a live invocation with signed control events:

```json
{
  "type": "com.mxagent.exec.stdin.v1",
  "content": {
    "invocation_id": "inv_01HZ...",
    "data": "aGVsbG8K",
    "eof": true,
    "created_at": "2026-06-02T12:00:02Z",
    "nonce": "base64-random",
    "signature": { "alg": "ed25519", "key_id": "mxagent-ed25519:abc123", "sig": "base64..." }
  }
}
```

`data` is base64-encoded raw stdin bytes. `eof=true` closes stdin after any
bytes in the frame are written. The target accepts stdin only when the signature
verifies against a trusted agent key and that agent is the invocation requester.

Requester sends cancellation:

```json
{
  "type": "com.mxagent.exec.cancel.v1",
  "content": {
    "invocation_id": "inv_01HZ...",
    "reason": "caller_cancelled",
    "created_at": "2026-06-02T12:01:00Z",
    "nonce": "base64-random",
    "signature": { "alg": "ed25519", "key_id": "mxagent-ed25519:abc123", "sig": "base64..." }
  }
}
```

Target acknowledges:

```json
{
  "type": "com.mxagent.exec.cancelled.v1",
  "content": {
    "invocation_id": "inv_01HZ...",
    "signal_sent": "SIGTERM",
    "killed_process_group": true,
    "finished_at": "2026-06-02T12:01:01Z"
  }
}
```

Cancellation policy:

1. Send SIGTERM to process group.
2. Wait grace period, e.g. 5 seconds.
3. Send SIGKILL to process group.
4. Emit `exec.cancelled` and final invocation state.

### 7.6 Terminal Signals and Ctrl-C

Interactive `exec --pty` makes the local terminal transparent to the remote
program: the requester puts its local terminal into **raw mode** (clearing
`ISIG`, `ICANON`, and `ECHO`) so keystrokes — including control characters — are
forwarded byte-for-byte rather than interpreted locally.

- **Ctrl-C (and Ctrl-\\, Ctrl-Z, …)** are sent as their literal bytes (`0x03`,
  …) over `StreamKind::Stdin` to the remote PTY, whose line discipline raises
  the corresponding signal (`SIGINT`, `SIGQUIT`, `SIGTSTP`) in the remote
  foreground process group. The local `mx-agent` is **not** interrupted; Ctrl-C
  acts on the remote program exactly as it would at a local terminal.
- A remote process killed by a signal reports `128 + signum` per §5.3, so a
  Ctrl-C'd remote command exits `130`.
- The non-interactive `exec` path leaves the terminal in cooked mode, so Ctrl-C
  raises `SIGINT` locally and terminates `mx-agent` itself with exit code `130`.

**Terminal restoration.** The raw-mode settings are restored on normal exit, on
error, and on panic. Because a signal can terminate the process without running
that cleanup, the requester also installs a handler so that a `SIGINT`,
`SIGTERM`, `SIGHUP`, or `SIGQUIT` first restores the terminal (and then exits
`128 + signum`). The local terminal is therefore never left stranded in raw mode
after a failure.

---

## 8. Stream Transport Semantics

### 8.1 Chunking Defaults

```text
max_chunk_bytes: 16 KiB
max_flush_interval: 50 ms interactive / 250 ms batch
max_events_per_second: policy-controlled
max_output_bytes: policy-controlled
compression: zstd optional for non-interactive streams
```

Flush when any condition is met:

- buffer reaches `max_chunk_bytes`
- newline observed in interactive mode
- flush interval expires
- stream EOF

### 8.2 Ordering and Reassembly

Chunks are ordered by:

```text
(invocation_id, stream, seq)
```

Receiver behavior:

- De-duplicate exact repeated `(invocation_id, stream, seq)` chunks.
- Buffer out-of-order chunks for a bounded window.
- If a gap persists past timeout, mark stream degraded.
- If chunk hashes are present and invalid, mark integrity failure.
- Continue rendering best-effort output unless strict mode is enabled.

Strict mode:

```bash
mx-agent exec --strict-stream --agent developer-pi -- npm test
```

In strict mode, missing or invalid chunks cause local exit code `132`.

### 8.3 Backpressure

The daemon must protect both Matrix and local processes:

- Apply per-invocation output caps.
- Pause local child reads only when safe.
- Drop or summarize excessive output according to policy.
- Switch to artifact mode when output exceeds timeline budget.
- Surface truncation explicitly.

### 8.4 Large Output Artifact Mode

For high-output commands, Matrix timeline events should carry summaries and references, not every byte.

Trigger conditions:

```text
output_bytes > max_timeline_output_bytes
or events_per_second exceeds homeserver rate limits
or receiver explicitly requested --artifact-output
```

Artifact event:

```json
{
  "type": "com.mxagent.stream.artifact.v1",
  "content": {
    "invocation_id": "inv_01HZ...",
    "stream": "stdout",
    "name": "stdout.log.zst",
    "mime_type": "text/plain+zstd",
    "size_bytes": 10485760,
    "sha256": "base64...",
    "mxc_uri": "mxc://matrix.org/abcdef",
    "tail_preview": "last 4KB of output..."
  }
}
```

Retrieve the full artifact by invocation ID:

```bash
mx-agent invocation artifact \
  --room '!abc:matrix.org' \
  --stream stdout \
  inv_01HZ...
```

The bytes are downloaded from media, verified against `sha256` (a mismatch is
rejected as a corrupt/tampered artifact), and decompressed when the artifact is
zstd-encoded — so the command emits the original output. `--stream` selects
`stdout` (default), `stderr`, or `pty`; `--output PATH` writes to a file instead
of stdout.

---

## 9. Distributed State Machine and DAG Tracking

Matrix room state is used for durable state. Timeline events are used for activity and stream logs.

### 9.1 Agent State

State event:

```text
type: com.mxagent.agent.v1
state_key: <agent_id>
```

```json
{
  "agent_id": "developer-pi",
  "kind": "pi",
  "matrix_user_id": "@pi:matrix.org",
  "device_id": "MXAGENTDEVICE01",
  "signing_key_id": "mxagent-ed25519:abc123",
  "signing_public_key": "base64-no-pad-ed25519-public-key",
  "status": "active",
  "capabilities": ["shell", "edit", "test", "repo:node", "sandbox:docker"],
  "tools": ["run_tests@1.0.0", "lint@1.0.0"],
  "workspace": {
    "cwd": "/home/me/code/project",
    "project_id": "repo:github.com/org/project",
    "git_commit": "abc123"
  },
  "load": {
    "running_invocations": 1,
    "max_invocations": 4
  },
  "last_seen_ts": 1780392000000,
  "state_rev": 7
}
```

`signing_public_key` is non-secret public key material. Remote privileged
handlers decode it, verify that its SHA-256 digest matches `signing_key_id`, and
then use the resulting Ed25519 verifying key for request signatures; the local
trust store still decides whether the key id is authorized.

Liveness should combine:

- latest durable `agent` state
- recent `heartbeat` event
- room membership
- optional Matrix presence
- trusted signing/device key status

### 9.2 Task State

State event:

```text
type: com.mxagent.task.v1
state_key: <task_id>
```

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
  "state_rev": 4,
  "previous_event_id": "$eventid",
  "result": null,
  "action": null
}
```

Task states and common forward transitions:

```text
proposed -> pending -> assigned -> executing -> succeeded
    |           |          |              |--> failed
    |           |          |              |--> cancelled
    |           |          |--> blocked -> pending/assigned
    |           |--> blocked
    |--> cancelled
    |--> superseded
```

Terminal states (`succeeded`, `failed`, `cancelled`, `superseded`) are not
reopened by default; invalid daemon-originated state transitions are rejected
rather than published.

A task is runnable when:

```text
state in [pending, assigned]
all depends_on tasks are succeeded
assigned agent is active
local policy permits the operation
no conflicting newer state_rev exists
```

Daemon orchestration treats the optional `action` field as structured work. A
missing or `null` action means the task is manual/planning-only and must not be
auto-executed by inferring intent from the title or description. The field is
additive, so older tasks without it remain valid:

```json
{
  "action": {
    "type": "tool",
    "tool": "run_tests",
    "args": { "package": "mx-agent-cli" }
  }
}
```

or:

```json
{
  "action": {
    "type": "exec",
    "command": ["cargo", "test", "--all"],
    "cwd": "/home/me/code/project",
    "env": {},
    "timeout_ms": 600000,
    "stream": true
  }
}
```

A daemon task scheduler watches a room's task snapshots and decides which tasks
this agent should attempt to run. A task is *runnable* only when it is in a
schedulable state (`pending`/`assigned`), is not terminal, has every `depends_on`
task succeeded, is assigned to this agent (or auto-claim is enabled), carries an
executable action, and the agent has spare capacity. The scheduler is pure: it
only computes decisions and logs non-sensitive outcomes; it never executes
anything itself.

Task state is **advisory**: room membership does not grant execution. A task
action only becomes executable when it carries a signed `authorization` from a
locally trusted mx-agent signing key, addressed to the executing agent, within
its expiry, and with a fresh nonce. The daemon verifies the Ed25519 signature
(binding the task id and action), checks the local trust store (the final
authority; revoked keys are rejected), and applies replay/expiry protection
*before* any policy or dispatch step. An unsigned, untrusted, revoked, expired,
or replayed task action is blocked and never executes.

After authorization, the daemon scheduler parses the task action and checks
local deny-by-default policy against the task creator and requested tool/exec
before claiming or dispatching. When local policy marks the action
`requires_approval`, the task does **not** execute immediately: the daemon
consults an approval gate that records a `com.mxagent.approval.request.v1` in the
local approval queue (inspectable via `mx-agent approval list`) and holds the
task. An approved decision lets the task proceed to claim/dispatch; a denied
decision blocks the task (`reason = "approval_denied"`) and never spawns; an
undecided action keeps waiting. With no approval gate configured the daemon
fails closed and does not run the action. The claim is an optimistic, conditional update
guarded by the observed `state_rev`: it transitions `pending`/`assigned` ->
`executing`, records this agent as the owner (`assigned_to`), and attaches a
generated `invocation_id` atomically. If another daemon claimed first, the
conditional update is stale and this daemon does not execute. A policy denial is audited locally, does not spawn, and
moves the task to a safe non-runnable state with `reason = "policy_denied"`.
When policy permits execution, the daemon claims the pending task with the
observed `state_rev`, sets `state = "executing"`, and attaches a generated
`invocation_id`. A lost claim race is treated as a stale update and must not
spawn. After the signed, trust-checked dispatcher returns, the daemon finalizes
the task as `succeeded` or `failed` with a stable, non-sensitive structured
`result`.

Successful result example:

```json
{
  "status": "succeeded",
  "completed_by": "pi-builder",
  "completed_at": "2026-06-04T18:00:00Z",
  "invocation_id": "inv_01HZ...",
  "action": "tool",
  "exit_code": 0,
  "summary": "tests passed",
  "artifact_mxc": null
}
```

Failure, denial, and recovery results use the same object shape with
`status = "failed"` and a machine-readable `reason`, e.g. `process_exit`,
`policy_denied`, `dispatch_failed`, or `recovered_stale_invocation`:

```json
{
  "status": "failed",
  "completed_by": "pi-builder",
  "completed_at": "2026-06-04T18:00:00Z",
  "invocation_id": "inv_01HZ...",
  "action": "exec",
  "reason": "process_exit",
  "exit_code": 1,
  "summary": "tests failed"
}
```

On restart, the daemon reconciles every `executing` task against its live local
invocations (architecture §11.3): a task it owns whose invocation is still live
is left running; a task it owns whose local invocation is gone is marked failed
with a recovery result instead of being spawned a second time; and a task owned
by another (remote) agent is left unchanged and surfaced as a non-sensitive
stale warning, since only the owning daemon may resolve it. Recovery decisions
are logged and the recovered task's durable `result` records why it was
recovered, so the outcome is auditable. The live scheduler loop also treats
every invocation it has *claimed during the current run* as live, so a task it
already claimed and finalized in an earlier pass is never recovered off a stale
local-store snapshot that still shows it `executing` before the homeserver
`/sync` echo catches up; only a genuine orphan from a previous daemon run, whose
invocation this run never claimed, is recovered.

Tool-backed task actions (`{"type":"tool", ...}`) run through the named-tool
execution path once authorized: the daemon links an invocation, runs the named
tool, and finalizes the task `succeeded` (tool exit 0) or `failed` (nonzero or
un-invokable) with the tool summary recorded in the task `result`. A
policy-denied tool action never runs and the task becomes `blocked`.

Exec-backed task actions (`{"type":"exec", ...}`) run through the process runner
once authorized (and only behind strict policy/trust checks): a denied exec
never spawns, exit code `0` finalizes the task `succeeded`, and any other
termination (nonzero exit, signal, or timeout) finalizes it `failed`; output
artifacts are linked in the task `result` when present. Explicit cancellation is
handled through the invocation cancel path (`exec.cancelled`), which finalizes
the owning task `cancelled` via the task↔invocation linkage.

### 9.3 Workspace State

State event:

```text
type: com.mxagent.workspace.v1
state_key: "" (one workspace metadata per room)
```

```json
{
  "project_id": "repo:github.com/org/project",
  "path": "/home/me/code/project",
  "repo": {
    "remote_url": "git@github.com:org/project.git",
    "branch": "main",
    "commit": "abc123"
  },
  "attached_by": "@alice:matrix.org",
  "attached_at": 1780392000000,
  "state_rev": 1
}
```

The `attached_at` timestamp is milliseconds since the Unix epoch (matching
`agent` state's `last_seen_ts`). The `repo` object is omitted (or `null`) when the attached path is not a git
repository; each of its fields is `null` when the corresponding git metadata is
unavailable. `path` is the local filesystem path attached on the agent that
published the state.

### 9.4 Conflict Handling

Matrix room state is last-write-wins per `(type, state_key)`. To reduce accidental overwrites:

- Include `state_rev` on mutable state events.
- Include `previous_event_id` when updating known state.
- Treat lower or repeated `state_rev` as stale in clients.
- Restrict task mutation by Matrix power levels and mx-agent policy.
- For contentious workflows, append timeline decision events and let a coordinator agent resolve state.

### 9.5 Query Commands

```bash
mx-agent task list --room '!abc:matrix.org'
mx-agent task list --room '!abc:matrix.org' --state pending
mx-agent task list --room '!abc:matrix.org' --assigned developer-pi
mx-agent task graph --room '!abc:matrix.org'
mx-agent invocation list --room '!abc:matrix.org' --state running
```

Graph output:

```text
task-plan  succeeded
  └─ task-code  succeeded
      └─ task-test  failed
          └─ task-review  blocked
```

Roots (tasks that depend on nothing present) are drawn at the left margin and
each dependent is nested beneath the task it depends on, indented four columns
deeper per level. `mx-agent task graph --json` emits the same graph as a JSON
object with `nodes`, `edges`, `roots`, `cycles`, and `warnings`. Any dependency
cycle is reported on its own `cycle detected: a -> b -> a` line rather than
expanded.

`task graph` also surfaces non-blocking **diagnostics** about the DAG (issue
#170): duplicate task titles, dependency cycles, missing dependency IDs, tasks
assigned to unknown or inactive agents, schedulable-but-actionless tasks, and
tool actions the assigned agent does not offer. These are warnings only — they
never reject or mutate task state, so advanced workflows are never blocked. Each
warning has a stable machine-readable `kind` plus a human message; the
human-readable graph prints a `warnings (...)` section and `--json` includes a
`warnings` array. Agent-dependent checks are skipped when no agent snapshot is
available, so a missing agent list never produces misleading warnings.

---

## 10. Daemon and IPC Architecture

### 10.1 Why the Daemon Exists

The daemon owns long-lived Matrix state:

- `/sync` loop
- E2EE sessions and device verification
- Matrix access token
- room state cache
- event send queues and retry backoff
- incoming request routing
- local policy enforcement
- process supervision
- stream chunking/reassembly
- audit logging

#### Event router (`mx-agent-daemon::event_router`)

The `/sync` loop feeds each sync response through an `EventRouter` that turns
raw Matrix timeline events into typed mx-agent events and dispatches the
supported types (`exec.*`, `call.*`, `stream.*`, `task`/`invocation`,
`approval.*`, `heartbeat`) to handlers. The router is the first gate a remote
event passes, so it is deliberately conservative:

- it performs **no side effects** — it classifies, parses, replay-checks, and
  hands off; privileged handlers must still verify signature, local trust,
  policy, and approval before executing (room membership never implies
  execution rights);
- **undecryptable encrypted** (`m.room.encrypted`) events are skipped before
  classification, so an opaque payload can never reach authorization;
- **unknown** event types are ignored and **malformed** content is rejected
  without panicking and without dispatch;
- privileged `exec.request` events are **replay/expiry-checked** through the
  persistent replay cache before dispatch;
- only non-sensitive metadata is logged (event type, room, sender, IDs,
  category, reason) — never event content.

The routing logic is decoupled from `matrix_sdk` via a transport-agnostic
`IncomingEvent`, with `events_from_sync_response` adapting a real sync
response. `call.request` events now have a live handler: the target daemon
confirms the request is addressed to one of its registered agents, resolves the
requester's published signing key, verifies signature/trust/policy, executes the
named built-in tool, and emits `call.response`. `exec.request` events also have
a live non-PTY handler: the target daemon verifies signature/trust/replay/policy,
emits `exec.accepted`/`exec.rejected`, publishes invocation state, spawns a
supervised live task, emits stream/result events, and never spawns denied or
approval-pending requests. While running, signed `exec.stdin` and `exec.cancel`
controls are accepted only from the trusted invocation requester. Result-side
stream events (`stream.chunk`, `stream.artifact`, `exec.finished`,
`exec.rejected`, `exec.cancelled`, and `call.response`) are forwarded into an
in-memory subscriber registry keyed by invocation id or request id so IPC
clients can wait without accessing Matrix state.

### 10.2 IPC Transport

POSIX:

```text
$XDG_RUNTIME_DIR/mx-agent/daemon.sock
```

Windows:

```text
\\.\pipe\mx-agent-daemon
```

Security:

- socket mode `0600`
- owned by current user
- verify peer credentials where supported, e.g. `SO_PEERCRED`
- optional local IPC auth token stored outside agent-visible env

Peer credential verification works as follows (implemented in
`mx-agent-ipc`, module `peercred`):

- On Linux/Android the daemon reads the connecting peer's UID via
  `SO_PEERCRED` and rejects any client whose UID does not match the daemon's
  effective UID. Rejections are audited via a `tracing::warn!` log that records
  only the peer and daemon UIDs — no request payloads or other peer data are
  read before rejection.
- On platforms without a supported peer credential mechanism the check returns
  `Unsupported`: the daemon logs a single warning and falls back to the
  socket's `0600` filesystem permissions and user-owned parent directory as the
  sole access control. This keeps behavior well defined and observable rather
  than silently allowing or failing.

### 10.3 IPC Protocol

Start with framed JSON-RPC over Unix socket. The framing should support streaming messages and cancellation.

Request:

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
  "result": { "invocation_id": "inv_01HZ..." }
}
```

Every Matrix-backed command group is daemon-mediated over the same local IPC
channel so the CLI never reads Matrix session files, tokens, or device keys and
never restores a Matrix client: the daemon owns Matrix restoration and calls the
existing helpers internally (issue #201). `auth login` stays CLI-initiated (it
receives the password and writes the session into the daemon-owned data dir);
`auth status`/`logout` read only local session metadata.

| Method | Params | Result |
|---|---|---|
| `task.create` | `CreateTaskOptions` | `TaskState` |
| `task.update` | `UpdateTaskOptions` | `TaskState` |
| `task.list` | `ListTasksOptions` | `TaskState[]` |
| `task.graph` | `ListTasksOptions` | `TaskGraph` |
| `task.watch` | `ListTasksOptions` | stream of watch event envelopes |
| `workspace.create` / `.attach` | `CreateWorkspaceOptions` / `AttachWorkspaceOptions` | `WorkspaceInfo` / `WorkspaceState` |
| `workspace.join` / `.status` | `RoomParams` | `WorkspaceInfo` / `WorkspaceStatus` |
| `workspace.watch` | `RoomParams` | stream of watch event envelopes |
| `agent.register` / `.list` | `RegisterAgentOptions` / `ListAgentsOptions` | `AgentState` / `AgentState[]` |
| `agent.show` / `.tools` | `RoomAgentParams` | `AgentState?` / `AgentTools?` |
| `trust.publish` / `.state` | `TrustPublishParams` / `RoomParams` | `TrustState` / `TrustState[]` |
| `approval.decide` | `ApprovalDecideParams` | `ApprovalDecisionRecord` |
| `share.file` / `.diff` / `.env` | `ShareContextOptions` / `ShareDiffOptions` / `ShareEnvOptions` | `ContextShare` |
| `share.list` / `.get` | `ListSharesOptions` / `FetchContextOptions` | `ContextShare[]` / `FetchedContext` |
| `invocation.list` / `.get` | `ListInvocationsOptions` / `RoomInvocationParams` | `InvocationState[]` / `InvocationState?` |
| `invocation.cancel` / `.artifact` | `InvocationCancelParams` / `RetrieveArtifactOptions` | `InvocationState` / `RetrievedArtifact` |

`task.watch` keeps the Unix-socket connection open and sends one JSON-RPC
response frame per event using the original request id. Event envelopes carry
`event = "initial"`, `"changed"`, `"reconnecting"`, or `"reconnected"` plus
the task snapshots/diff metadata needed by the CLI to preserve human and
`--json` output compatibility.

Stream from daemon to CLI:

```json
{
  "method": "stream.stdout",
  "params": {
    "invocation_id": "inv_01HZ...",
    "data": "PASS src/foo.test.ts\n"
  }
}
```

Stream from CLI to daemon:

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

Cancel:

```json
{
  "jsonrpc": "2.0",
  "id": "req-124",
  "method": "invocation.cancel",
  "params": {
    "room": "!abc:matrix.org",
    "invocation_id": "inv_01HZ...",
    "reason": "caller_cancelled"
  }
}
```

---

## 11. Reliability Model

### 11.1 Delivery Assumptions

Matrix provides durable event history, but clients must still handle:

- duplicate events
- delayed events
- out-of-order stream chunks
- homeserver rate limits
- federation delay
- daemon restarts
- E2EE decryption delays
- partial media upload failures

### 11.2 Idempotency

Privileged request events should include:

```text
request_id
invocation_id
idempotency_key
nonce
expires_at
```

Daemon behavior:

- Ignore expired requests.
- Reject replayed nonces.
- De-duplicate by idempotency key.
- Persist invocation state before starting local child process.
- On restart, reconcile running child processes and Matrix invocation state.

### 11.3 Reconnect and Recovery

On daemon startup or reconnect:

1. Resume Matrix sync from stored sync token.
2. Load active invocations from local store.
3. Fetch room state for agent/task/invocation snapshots.
4. Reconcile local process table with invocation state.
5. Emit recovery updates for orphaned, failed, or completed invocations.
6. Rebuild stream cursors per `(invocation_id, stream)`.

### 11.4 Failure Modes

| Failure | Expected behavior |
|---|---|
| Target agent offline | request remains pending until timeout or is rejected by caller policy |
| Homeserver rate limit | daemon backs off, chunks less frequently, may switch to artifact mode |
| Missing stream chunk | receiver buffers then marks degraded or fails in strict mode |
| Daemon crashes while child runs | supervisor kills or recovers child according to policy |
| Request arrives after expiry | target rejects without execution |
| E2EE decryption fails | event ignored or marked undecryptable; no execution |
| Policy changes during run | new requests use new policy; running invocations follow configured behavior |

---

## 12. Approval Workflow

Policy can require approval before executing privileged requests.

Policy flag:

```toml
requires_approval = true
```

Commands:

```bash
mx-agent approval list --room '!abc:matrix.org'
mx-agent approval show req_01HZ...
mx-agent approval approve req_01HZ...
mx-agent approval deny req_01HZ... --reason 'unsafe command'
```

Approval request event:

```json
{
  "type": "com.mxagent.approval.request.v1",
  "content": {
    "request_id": "req_01HZ...",
    "invocation_id": "inv_01HZ...",
    "requester": "claude-local",
    "target": "developer-pi",
    "summary": "Run npm test in /home/me/code/project",
    "risk": "medium",
    "expires_at": "2026-06-02T12:05:00Z"
  }
}
```

Approval decision event:

```json
{
  "type": "com.mxagent.approval.decision.v1",
  "content": {
    "request_id": "req_01HZ...",
    "decision": "approved",
    "approved_by": "local-user",
    "created_at": "2026-06-02T12:00:30Z"
  }
}
```

---

## 13. Security Boundary and Token Isolation

### 13.1 Credential Storage

Daemon-owned paths on Linux:

```text
~/.local/share/mx-agent/session.db
~/.local/share/mx-agent/crypto-store/
~/.local/share/mx-agent/signing-keys/
~/.config/mx-agent/config.toml
~/.config/mx-agent/policy.toml
$XDG_RUNTIME_DIR/mx-agent/daemon.sock
```

Permissions:

```bash
chmod 0700 ~/.local/share/mx-agent
chmod 0600 ~/.local/share/mx-agent/session.db
chmod 0700 ~/.local/share/mx-agent/crypto-store
chmod 0700 ~/.local/share/mx-agent/signing-keys
chmod 0600 ~/.config/mx-agent/policy.toml
```

macOS should use Keychain for tokens. Windows should use Credential Manager or DPAPI.

Never expose tokens through:

- environment variables
- command arguments
- logs
- shell history
- stdout/stderr
- Matrix messages
- agent-readable config files

### 13.2 Trust Bootstrap

Supported trust modes:

| Mode | Description | Security |
|---|---|---|
| manual | user verifies signing key fingerprint | strongest operational default |
| Matrix device verified | trust follows verified Matrix device | strong if Matrix verification is used correctly |
| room-admin grant | trusted admin publishes trust state | convenient for teams |
| TOFU | first key seen is trusted | convenient but vulnerable on first contact |

Trust commands:

```bash
mx-agent trust list --room '!abc:matrix.org'
mx-agent trust fingerprint --agent developer-pi
mx-agent trust approve --room '!abc:matrix.org' --agent developer-pi --key mxagent-ed25519:abc123
mx-agent trust revoke --room '!abc:matrix.org' --agent developer-pi --key mxagent-ed25519:abc123
```

Trust state event:

```text
type: com.mxagent.trust.v1
state_key: <agent_id>|<key_id>
```

```json
{
  "agent_id": "developer-pi",
  "key_id": "mxagent-ed25519:abc123",
  "fingerprint": "SHA256:...",
  "status": "trusted",
  "trusted_by": "@owner:matrix.org",
  "created_at": "2026-06-02T12:00:00Z",
  "expires_at": null,
  "revoked_at": null
}
```

Publishing trust state is **optional** and is offered as a convenience for
team bootstrapping (the "room-admin grant" mode above):

```bash
# Publish a local trust record into a room as com.mxagent.trust.v1 state.
mx-agent trust publish --room '!abc:matrix.org' --agent developer-pi --key mxagent-ed25519:abc123
# Inspect published trust state in a room, reconciled with the local store.
mx-agent trust state --room '!abc:matrix.org'
```

#### Trust precedence

The **local trust store is always the final authority**. Room-published
`com.mxagent.trust.v1` state is purely advisory; it never overrides a local
decision. When resolving whether an `(agent_id, key_id)` pair is trusted:

1. If the local store has a record for the pair, that record decides. In
   particular, a **local revocation always overrides** any room-published
   `trusted` state — revocation cannot be undone by a room admin.
2. Only when the local store has *no* record for the pair is the
   room-published state consulted, and then only a `trusted`, non-revoked
   record grants trust. A published revocation (or any other status) never
   grants trust.

Publishing and reading trust state never mutate the local store; approval and
revocation happen only through `mx-agent trust approve` / `trust revoke`.

### 13.3 Execution Policy

Example:

```toml
[rooms."!abc:matrix.org"]
trusted = true
raw_exec_default = "deny"

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
sandbox = "bubblewrap"
network = "deny"
```

Policy recommendations:

- Prefer `call` tools over raw `exec`.
- Disable raw shell execution by default.
- Use allowlists for commands, cwd, tools, and environment variables.
- Apply network deny-by-default for remote execution.
- Enforce output and runtime caps.

### 13.4 Environment Scrubbing

Child process environment should be allowlist-based.

Exclude unless explicitly allowed:

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

### 13.5 Sandboxing

Minimum controls:

- restricted cwd
- sanitized env
- timeout
- output cap
- kill process group on timeout/cancel

Stronger controls:

- Docker or Podman
- bubblewrap or firejail
- chroot
- user namespace
- seccomp
- read-only root filesystem
- writable workspace and temp only
- network disabled by default

Example:

```toml
[execution]
default_sandbox = "bubblewrap"
network = "deny"
read_only_paths = ["/usr", "/bin", "/lib"]
writable_paths = ["/home/me/code/project", "/tmp/mx-agent"]
```

### 13.6 Audit Logging

Every privileged decision should be logged locally without secrets:

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

## 14. Matrix Room Security

Recommended room settings:

- private invite-only rooms
- E2EE enabled
- history visibility: joined members only
- power levels restrict state-event mutation
- only trusted agents can send `task`, `exec`, `call`, and `trust` events
- one workspace room per repository/project
- optional per-task rooms for highly sensitive workflows

---

## 15. Implementation Layout

Suggested Rust/Go layout:

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
    invocation
    approval
    daemon
    auth
    trust
  daemon/
    matrix_sync
    event_router
    ipc_server
    process_runner
    policy_engine
    crypto_store
    approval_queue
    audit_log
  protocol/
    events
    canonical_json
    signing
    stream_chunking
    artifact_upload
    dag
  sandbox/
    docker
    bubblewrap
    none
```

Rust advantages:

- strong async ecosystem
- `matrix-rust-sdk`
- memory safety
- good Unix socket and PTY support

Go advantages:

- simple static binaries
- excellent process/networking support
- operational simplicity

---

## 16. End-to-End Example

Claude Code asks a remote Pi agent to run tests:

```bash
mx-agent workspace join '#project-orchestration:matrix.org'

mx-agent share diff \
  --room '#project-orchestration:matrix.org' \
  --base main

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

Flow:

1. CLI sends `exec.start` to the local daemon over Unix socket.
2. Local daemon creates signed `com.mxagent.exec.request.v1`.
3. Matrix federates the event to the workspace room.
4. Remote Pi daemon receives the event through `/sync`.
5. Remote daemon verifies Matrix sender, device trust, mx-agent signature, nonce, expiry, and local policy.
6. If required, approval is requested and awaited.
7. Remote daemon starts `npm test` in the configured sandbox.
8. stdout/stderr are streamed as `com.mxagent.stream.chunk.v1` or uploaded as artifacts if large.
9. Local daemon receives chunks and forwards them over IPC.
10. Local CLI writes stdout/stderr to the terminal.
11. Remote daemon emits `com.mxagent.exec.finished.v1`.
12. Local CLI exits with the remote exit code.

---

## 17. MVP Scope

Recommended MVP:

1. Daemon with Matrix login, sync, room join/create.
2. Unix socket JSON-RPC IPC.
3. Agent registration and listing.
4. Signed `call` requests for named tools.
5. One built-in tool: `run_tests`.
6. Basic `exec` behind explicit local policy.
7. stdout/stderr chunk streaming with output cap.
8. Task state create/list/update.
9. Local credential isolation and audit log.

Defer until after MVP:

- PTY mode.
- Large artifact mode.
- Multi-writer conflict resolution UI.
- Rich approval UX.
- Advanced sandboxing presets.
- Cross-platform named pipes.
- Full key rotation/revocation automation.
