# AI Agent Orchestration

This is the flagship use case: mx-agent as the **secure substrate for multi-agent AI coding workflows**. If you are running LLM coding agents — Claude Code, Pi, terminal-based runners — across laptops, CI boxes, and remote machines, this page shows how they coordinate through mx-agent without exposing ports or sharing secrets.

> **Implementation status.** The orchestration model is fully implemented and CI-stable. All command groups run through the daemon over local IPC; `call` and non-PTY `exec` support signed Matrix-backed remote dispatch (including stdin/cancel controls) when `--room`/`--agent` target a registered, trusted, policy-allowed agent. The **live daemon scheduler loop** auto-claims assigned tasks from `com.mxagent.task.v1` room state, dispatches them (local tool/exec by default; opt into signed Matrix-backed remote dispatch via `MX_AGENT_TASK_DISPATCH=matrix`), and recovers stale work on restart. Remaining gaps: interactive PTY is not yet remote-capable over IPC; production E2EE and `bubblewrap`/container sandboxes are planned. Commands below are tagged where behavior is not yet live.

---

## Why AI agents need this

Autonomous coding agents are increasingly *distributed*: a planner runs on your laptop, tests run on a beefy CI box, a reviewer runs somewhere with the production schema. Wiring them together the traditional way is painful and unsafe:

- **Networking pain.** Agents sit behind NAT, corporate firewalls, and home routers. Opening inbound ports or standing up a VPN per agent doesn't scale and widens your attack surface.
- **Secret sprawl.** "Let agent A drive agent B" usually devolves into handing long-lived SSH keys or API tokens to an LLM — exactly the thing you don't want an autonomous, prompt-injectable process holding.
- **No shared, auditable state.** Ad-hoc orchestration scripts have no durable record of who asked whom to do what, or why.
- **No safety rail.** An LLM that can "run commands on the build box" can, by construction, run *any* command on the build box.

mx-agent replaces all of that with a **federated, end-to-end-encryptable, policy-gated bus**: agents connect *outbound* to a Matrix homeserver, every privileged request is **Ed25519-signed**, and the machine that would execute checks it against **deny-by-default local policy** — with optional human approval. The agent never touches a Matrix token or device key.

---

## The mental model

Map AI-orchestration concepts onto mx-agent primitives (full definitions in [[Core Concepts|Core-Concepts]]):

| You want… | mx-agent primitive | On Matrix |
|---|---|---|
| Each AI agent to be a known participant with declared skills | **Agent** | `com.mxagent.agent.v1` state (capabilities, tools) |
| To break a feature into coordinated steps with dependencies | **Task DAG** | `com.mxagent.task.v1` state (`depends_on` / `blocks`) |
| Agent A to run a *named, schema'd* operation on agent B | **Tool call** | signed `com.mxagent.call.request.v1` |
| Agent A to run an arbitrary command on agent B | **Exec** | signed `com.mxagent.exec.request.v1` |
| Live output from a running step | **Stream** | `com.mxagent.stream.chunk.v1` |
| A human to gate risky actions | **Approval** | `com.mxagent.approval.request.v1` / `.decision.v1` |

Two rules make this safe for *autonomous* agents specifically:

1. **Named tools are the preferred boundary** — a `call` to `run_tests` with a typed schema is far safer than raw `exec`, because the agent can't inject arbitrary shell. Disable raw exec by default; allow specific tools.
2. **The requesting agent's identity is cryptographic, not conversational** — a prompt-injected agent still cannot forge another agent's Ed25519 signature, and still can't exceed the *target's* local policy.

---

## Worked scenario: a three-agent feature pipeline

**Goal:** A planner agent decomposes "add rate limiting to the API," dispatches test and review work to remote agents, and a human approves the one risky step. Three agents, three machines, one workspace room:

- `@claude-planner` — Claude Code on a laptop (capabilities: `plan`, `review`).
- `@pi-builder` — a Pi runner on a remote build box (capabilities: `shell`, `edit`, `test`).
- `@claude-reviewer` — a reviewer agent near the staging DB (capabilities: `review`).

```text
            workspace room  !aBcDeF123:matrix.org  (private, E2EE)

  @claude-planner ──plan──┐
                          ▼
                 task-plan (succeeded)
                          │ blocks
                          ▼
                 task-code  ──assigned──▶ @pi-builder ──edit/exec──▶ build box
                          │ blocks
              ┌───────────┴───────────┐
              ▼                       ▼
        task-test               task-review
        (@pi-builder)           (@claude-reviewer)
              │ exec: npm test        │ call: review_diff
              ▼                       ▼
        stream.chunk ──▶ planner    approval.request ──▶ human ──▶ approval.decision
```

### 1. Stand up the workspace and register agents 🟡

```bash
export ROOM='!aBcDeF123:matrix.org'

# Each agent's daemon registers itself once it has joined the room.
mx-agent agent register --room "$ROOM" --agent-id claude-planner \
  --kind claude-code --capability plan --capability review

mx-agent agent register --room "$ROOM" --agent-id pi-builder \
  --kind pi --capability shell --capability edit --capability test \
  --tool run_tests --max-invocations 4

mx-agent agent register --room "$ROOM" --agent-id claude-reviewer \
  --kind claude-code --capability review --tool review_diff
```

### 2. The planner decomposes the work into a task DAG 🟡

```bash
PLAN=$(mx-agent task create --room "$ROOM" \
  --title "Plan: add rate limiting to API" --assign claude-planner --json | jq -r .task_id)

CODE=$(mx-agent task create --room "$ROOM" \
  --title "Implement rate limiter" --assign pi-builder \
  --depends-on "$PLAN" --json | jq -r .task_id)

TEST=$(mx-agent task create --room "$ROOM" \
  --title "Run API test suite" --assign pi-builder \
  --depends-on "$CODE" --json | jq -r .task_id)

REVIEW=$(mx-agent task create --room "$ROOM" \
  --title "Review the diff" --assign claude-reviewer \
  --depends-on "$CODE" --json | jq -r .task_id)
```

`task-test` and `task-review` both `depends_on` `task-code` — a **fork**: they run in parallel on different agents once the code lands, and nothing downstream proceeds until their dependencies are `succeeded` (see [[Core Concepts|Core-Concepts]]).

### 3. The planner shares context, then dispatches a test run 🟡

```bash
# Share the proposed diff so the builder and reviewer see the same bytes.
mx-agent share diff --room "$ROOM" --base main --format unified

# Ask the builder to run the test suite, streaming output back live.
mx-agent exec --room "$ROOM" --agent pi-builder --task "$TEST" \
  --cwd /home/me/code/project --stream -- npm test
```

Streamed back to the planner's terminal:

```text
→ exec inv_01HZ8QK3M9V0X2YJ4N6P7R5T8W  (agent: pi-builder, task: task-test)
  policy: allowed (rooms.!aBcDeF123.agents.@pi-builder.allow_tools/exec)
PASS  src/ratelimit.test.ts
PASS  src/api.test.ts
FAIL  src/api.burst.test.ts
  ● rejects bursts over the limit
    expected 429, received 200
✔ finished  exit=1  duration=18.2s  stdout=50KB  stderr=1KB
```

The planner agent reads `exit=1`, sees the failing assertion in the stream, and loops back to `task-code` — all without a human, and without ever holding a credential for the build box.

### 4. A risky step requires human approval 🟡

Suppose `task-review` needs to run a migration against staging. The reviewer's policy sets `requires_approval = true`, so the privileged request pauses for a human:

```bash
mx-agent approval list --room "$ROOM"
```

```text
REQUEST-ID     REQUESTER         TARGET            RISK    SUMMARY
req_01HZ…XQ    claude-reviewer   claude-reviewer   medium  apply migration to staging DB
```

```bash
mx-agent approval show req_01HZ…XQ
mx-agent approval approve req_01HZ…XQ
# or: mx-agent approval deny req_01HZ…XQ --reason 'run against a clone first'
```

The agent only proceeds after a `com.mxagent.approval.decision.v1` with `decision: "approved"` — a human stays in the loop precisely at the dangerous boundary, and the decision is recorded in room history.

---

## Guardrails for autonomous agents

Because the actor here is an LLM that may be prompt-injected, the safety model assumes the *requesting* agent can be adversarial. The defenses (detailed in [[Security & Sandboxing|Security-and-Sandboxing]]):

- **Deny-by-default policy.** An agent can do *nothing* on a target until that target's `policy.toml` explicitly allows it — per room, per agent.
- **Prefer named tools over raw exec.** A `call` to `run_tests` with an input schema can't be turned into `rm -rf /`; raw `exec` is opt-in and command-allowlisted.
- **Command/arg allowlists.** `allow_commands`, `allow_cwd`, and `deny_args_regex` bound even permitted exec — no `ssh`, no `curl | sh`, no escaping the project tree.
- **Environment scrubbing.** The child starts from an allowlist; `GITHUB_TOKEN`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `AWS_*`, etc. are stripped — a compromised agent cannot read your secrets out of the environment.
- **`network = "deny"`.** No exfiltration, no SSRF, no callbacks to cloud metadata endpoints.
- **Runtime & output caps.** `max_runtime_ms` and `max_output_bytes` bound runaway agents and log-flood DoS.
- **Mandatory approval gates.** `requires_approval = true` forces a human decision for privileged actions.
- **Cryptographic identity.** Every privileged request is Ed25519-signed; a prompt-injected agent cannot impersonate another agent or exceed the target's policy.

The net effect: you can let AI agents coordinate work across machines while holding them to a **least-privilege, auditable, human-gated** contract that the agents themselves cannot talk their way out of.

---

## See also

- [[Getting Started|Getting-Started]] — set up your first agent and room
- [[Core Concepts|Core-Concepts]] — the task DAG and invocation model
- [[Security & Sandboxing|Security-and-Sandboxing]] — the full `policy.toml` reference
- [[Stream & Protocol Spec|Stream-and-Protocol-Spec]] — the events these commands emit
