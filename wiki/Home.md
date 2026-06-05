# mx-agent

> A Matrix-backed CLI and daemon for **decentralized orchestration between autonomous coding agents** — Pi, Claude Code, and other terminal-based LLM runners.

mx-agent turns Matrix rooms into **federated workspaces**. Inside a room, agents discover one another, share execution context (diffs, plans, environment snapshots), invoke named tools, stream terminal I/O, and coordinate a distributed task graph — all **without a central orchestration server and without any inbound firewall port**.

---

## What is mx-agent?

mx-agent is two cooperating processes plus a transport you already trust:

- **A stateless CLI** (`mx-agent …`) that your coding agent or shell drives. It speaks only to a local socket, formats output, and propagates exit codes. It never touches Matrix credentials.
- **A long-lived local daemon** that owns the Matrix session, end-to-end-encryption (E2EE) keys, the signing identity, the local authorization policy, and process supervision.
- **The Matrix protocol** as the wire between daemons — a federated, end-to-end-encryptable event log that any homeserver (matrix.org, a self-hosted Synapse/Conduit, or the loopback **Tuwunel** server used in development) can carry.

The result: one coding agent can ask another — on a different machine, network, or continent — to run a command, and watch its output stream back, with every privileged request cryptographically signed and checked against local policy on the machine that would execute it.

> **Project status (v0.1.0, public alpha).** The architecture, protocol schema, IPC layer (with peer-credential checks), policy engine, Ed25519 signing, and the `none` sandbox backend are implemented, and most command groups now run against a real Matrix homeserver through the daemon: `auth` / `workspace` / `agent` / `trust` / `approval` / `share` and the `task` state commands (create/update/list/graph/watch) plus DAG diagnostics. The daemon task-orchestration engine (scheduler, claiming, tool/exec dispatch, policy + trust/signature + approval enforcement, restart recovery) is implemented and tested but **not yet auto-driven by a live `/sync` loop**, and `call` / `exec` still run **local-loopback** (remote Matrix transport is landing, #155). Throughout this wiki, each feature is tagged **✅ Implemented**, **🟡 Designed / in progress**, or **🔮 Planned** so you always know what runs today.

---

## The Core Problem

Traditional remote-agent and remote-execution tooling assumes a server you can reach:

| Traditional remote execution | mx-agent |
|---|---|
| Requires an **inbound port** (SSH 22, an RPC port, an agent listener) | **Outbound-only.** Daemons connect *out* to a homeserver; nothing listens for inbound connections. |
| Punching through NAT/firewalls needs a **VPN, bastion, or tunnel** | Works anywhere an HTTPS connection to a homeserver works — coffee shop, CI runner, Raspberry Pi behind a home router. |
| A **central coordinator** is a single point of failure and trust | **Federated.** State lives in Matrix room history; any homeserver can carry it; there is no central mx-agent server. |
| Transport security is **bolted on** (TLS to a trusted box) | **End-to-end encryptable** between daemons via Matrix Olm/Megolm; the homeserver sees ciphertext. |
| "Can reach the box" usually means "**can run anything**" | **Room membership ≠ execution permission.** Every privileged request is Ed25519-signed and must pass *local* deny-by-default policy on the target. |
| Long-lived secrets are **handed to the agent** | The coding agent **never sees** Matrix tokens or device keys; they stay inside the daemon. |

In short: a firewalled box that can only make outbound connections — the hardest case for SSH or a webhook — is the *easy* case for mx-agent. If it can sync with a homeserver, it can participate.

---

## Architecture Layout

The exact data flow for a single remote command, from your keyboard to a remote process and back:

```text
   LOCAL MACHINE (requester)                                      REMOTE MACHINE (target)
 ┌───────────────────────────────┐                            ┌───────────────────────────────┐
 │  Coding agent / shell / LLM   │                            │       Process / sandbox       │
 │            runner             │                            │      (npm test, etc.)         │
 └───────────────┬───────────────┘                            └───────────────▲───────────────┘
                 │ spawns ephemeral                                            │ spawn + supervise
                 ▼                                                            │ (process group)
 ┌───────────────────────────────┐                            ┌───────────────┴───────────────┐
 │        mx-agent  (CLI)        │                            │      mx-agent daemon          │
 │  stateless · stdio bridge ·   │                            │  sync · crypto · policy ·     │
 │  exit-code propagation        │                            │  signature verify · runner    │
 └───────────────┬───────────────┘                            └───────────────▲───────────────┘
                 │  framed JSON-RPC 2.0                                        │  Matrix /sync
                 │  over Unix domain socket                                    │  receives the event
                 │  $XDG_RUNTIME_DIR/mx-agent/daemon.sock                      │
                 │  (mode 0600 · SO_PEERCRED UID check)                        │
                 ▼                                                            │
 ┌───────────────────────────────┐                            ┌──────────────┴────────────────┐
 │      mx-agent daemon          │   signed, E2EE event       │   verify pipeline:            │
 │  builds & signs               │   com.mxagent.exec.        │   sender → device trust →     │
 │  com.mxagent.exec.request.v1  │───request.v1───────────┐   │   Ed25519 sig → nonce/expiry  │
 │  (Ed25519)                    │                        │   │   → local policy → approval   │
 └───────────────┬───────────────┘                        │   └───────────────────────────────┘
                 │ Matrix Client-Server API + E2EE         │
                 ▼                                         ▼
        ┌─────────────────────────────────────────────────────────────┐
        │              Matrix homeserver  +  federation                │
        │   (Synapse / Conduit / Tuwunel) — federated encrypted log    │
        │   timeline events: exec.request, stream.chunk, exec.finished │
        │   state events:    agent, task, invocation, workspace, trust │
        └─────────────────────────────────────────────────────────────┘
                 ▲                                         ▲
                 │  stream.chunk.v1 (stdout/stderr)        │
                 │  exec.finished.v1 (exit code)           │
                 └─────────────── flows back the same path ┘
```

**The local-loopback detail that surprises people:** there is no separate "runner" daemon. A *local* exec follows the **exact same path** as a remote one — the daemon signs an event, publishes it to the room, and then **its own `/sync` loop receives that event back** and runs it through the identical verify→policy→runner pipeline. Local and remote execution share one code path, so anything you can prove about a remote call also holds for a local one. (See [[Core Concepts|Core-Concepts]].)

---

## Where to go next

- **New here?** Start with [[Getting Started|Getting-Started]] — a beginner-friendly walkthrough from install to "Hello World".
- **Building multi-agent AI workflows?** Read [[AI Agent Orchestration|AI-Agent-Orchestration]] — the flagship use case.
- **Want the model?** [[Core Concepts|Core-Concepts]] explains workspaces, tasks, invocations, and the event-sourced timeline.
- **Implementing the protocol?** [[Stream & Protocol Spec|Stream-and-Protocol-Spec]] has the wire format.
- **Deploying securely?** [[Security & Sandboxing|Security-and-Sandboxing]] covers zero-trust, socket isolation, and a complete `policy.toml`.
