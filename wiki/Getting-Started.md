# Getting Started

This guide takes you from nothing to your first remote-style command with mx-agent. **No prior Matrix, Rust, or distributed-systems knowledge is assumed.** If you can use a terminal, you can follow along.

We define every new term the first time it appears, explain *why* each step exists before giving the command, and end with a "Common errors & fixes" table.

> **What's real in v0.1.0?** mx-agent is a public alpha. The daemon's lifecycle (`start` / `status` / `stop`) and the local IPC are functional. **Most other subcommands currently parse your arguments and print "not implemented yet."** Steps below are tagged ✅ (works today), 🟡 (designed, wiring in progress), or 🔮 (planned). You can run every command to see its shape, but expect the 🟡/🔮 ones to be stubs for now.

---

## Vocabulary (read this once)

| Term | Plain-English meaning |
|---|---|
| **Daemon** | A program that runs quietly in the background. mx-agent's daemon holds your login and keys so the short-lived `mx-agent` commands don't have to. |
| **Homeserver** | A Matrix server (like an email provider, but for Matrix). You log into one — e.g. `matrix.org` — and it relays your messages. mx-agent uses Matrix purely as a secure pipe. |
| **Room** | A Matrix chat room. In mx-agent, a room **is** a shared workspace where agents coordinate. |
| **Room ID vs. alias** | An ID looks like `!aBcDeF:matrix.org` (permanent, ugly). An alias looks like `#my-project:matrix.org` (human-friendly, points at an ID). Either works. |
| **Agent** | A registered participant in a room — your Claude Code session, a Pi runner, a remote build box. Each has an `agent-id`. |
| **E2EE** | End-to-end encryption. Only the two daemons can read message contents; the homeserver sees ciphertext. |
| **Socket** | A local "phone line" (a special file) the CLI uses to talk to the daemon on the same machine. |

---

## Step 0 — Install ✅

**Why:** You need the `mx-agent` binary. mx-agent is a Rust project, so you build it with Cargo (Rust's build tool).

Install the Rust toolchain (one time) from [rustup.rs](https://rustup.rs), then build:

```bash
git clone https://github.com/<org>/mx-agent.git
cd mx-agent
cargo build --all --release
```

Put the binary on your `PATH` (or call it directly):

```bash
sudo install -m 0755 target/release/mx-agent /usr/local/bin/mx-agent
mx-agent --help
```

Expected output (abridged):

```text
Matrix-backed CLI for decentralized agent orchestration

Usage: mx-agent [OPTIONS] <COMMAND>

Commands:
  daemon      Daemon lifecycle (start, status, stop)
  auth        Matrix authentication (login, status, logout)
  workspace   Create/join Matrix-backed workspaces
  agent       Register and discover agents
  exec        Run a command on an agent
  call        Invoke a named tool on an agent
  task        Manage the distributed task graph
  ...
Options:
      --json            Machine-readable JSON output
      --socket <PATH>   Override the IPC socket path
  -v, -vv, -vvv         Increase log verbosity
  -h, --help            Print help
```

**What just happened?** You built the CLI. It's just a front-end; the real work happens in the daemon, which you'll start next.

---

## Step 1 — Start the daemon ✅

**Why:** The daemon is the long-lived process that will hold your Matrix session and keys. The CLI is stateless and talks to it over a local socket — so secrets never live in your shell history or environment.

```bash
mx-agent daemon start
```

Expected output:

```text
✔ daemon started (pid 48213)
  socket: /run/user/1000/mx-agent/daemon.sock
  logs:   ~/.local/share/mx-agent/daemon.log
```

Check it's alive:

```bash
mx-agent daemon status
```

```text
daemon: running (pid 48213)
  uptime: 4s
  socket: /run/user/1000/mx-agent/daemon.sock  (mode 0600)
  matrix: not logged in
```

**What just happened?** A background process is now listening on a private socket file at `$XDG_RUNTIME_DIR/mx-agent/daemon.sock`. That file is mode `0600` (only you can read/write it), and on Linux the daemon also checks the **UID** of anything that connects (via `SO_PEERCRED`) and refuses connections from other users. See [[Security & Sandboxing|Security-and-Sandboxing]].

> Run `mx-agent daemon start --foreground` to keep it attached to your terminal (handy for watching logs while learning).

---

## Step 2 — Log in to Matrix 🟡

**Why:** mx-agent doesn't run its own servers. It rides on Matrix, so it needs a Matrix account to send and receive events. This is the *only* place your token is entered — and it goes straight into the daemon, never to your coding agent.

```bash
mx-agent auth login \
  --homeserver https://matrix.org \
  --user my-agent-bot
```

```text
Password for @my-agent-bot:matrix.org: ********
✔ logged in as @my-agent-bot:matrix.org
  device: MXAGENTDEVICE01
  E2EE:   enabled
```

Confirm:

```bash
mx-agent auth status
```

```text
matrix: logged in
  user:   @my-agent-bot:matrix.org
  device: MXAGENTDEVICE01
  homeserver: https://matrix.org
```

**What just happened?** The daemon now has a Matrix session. The token is stored in `~/.local/share/mx-agent/session.db` (mode `0600`), owned by the daemon. Your shell and any agent you later connect see *none* of it.

> **Just experimenting?** You don't need a public account. The repo ships a loopback homeserver called **Tuwunel** (`dev/matrix/`) that runs on `127.0.0.1:8008` and auto-registers test users — perfect for trying mx-agent entirely on one machine.

---

## Step 3 — Create or join a workspace room 🟡

**Why:** A room is the shared space where agents find each other and coordinate. Create one for your project (or join an existing one a teammate created).

Create:

```bash
mx-agent workspace create \
  --alias my-project \
  --name "my-project orchestration" \
  --visibility private
```

```text
✔ workspace created
  room:  !aBcDeF123:matrix.org
  alias: #my-project:matrix.org
  e2ee:  on
```

Join (if someone already made it):

```bash
mx-agent workspace join '#my-project:matrix.org'
```

**What just happened?** You now have a private, encrypted Matrix room. Think of its ID (`!aBcDeF123:matrix.org`) as your workspace's address — you'll pass it as `--room` to almost every command. (Tip: `export ROOM='!aBcDeF123:matrix.org'` to save typing.)

---

## Step 4 — Register an agent 🟡

**Why:** Other participants need to know who is in the room and what they can do. Registration publishes an agent "business card" — its ID, kind, and capabilities — as room state.

```bash
mx-agent agent register \
  --room "$ROOM" \
  --agent-id claude-local \
  --kind claude-code \
  --capability plan \
  --capability review
```

```text
✔ registered agent 'claude-local' (kind: claude-code)
  capabilities: plan, review
  room: !aBcDeF123:matrix.org
```

List who's present:

```bash
mx-agent agent list --room "$ROOM"
```

```text
AGENT-ID       KIND          STATUS   CAPABILITIES
claude-local   claude-code   active   plan, review
```

**What just happened?** Your agent is now discoverable in the room as a `com.mxagent.agent.v1` state event. Real flags: `--agent-id` (not `--name`), repeatable `--capability`, optional `--tool`, `--project-id`, and `--max-invocations`.

---

## Step 5 — "Hello World" exec 🟡

**Why:** This is the payoff — asking an agent to run a command and streaming its output back. Because mx-agent uses a **local loopback** model, you can do this with a single machine: the daemon sends the request to itself through Matrix and runs it through the full signature + policy pipeline, exactly as a remote box would.

```bash
mx-agent exec \
  --room "$ROOM" \
  --agent claude-local \
  --stream \
  -- echo 'Hello World'
```

Everything after `--` is the remote command. Expected streamed output:

```text
→ exec inv_01HZABCDEFGHJKMNPQRSTVWXYZ  (agent: claude-local)
  policy: allowed (rooms.!aBcDeF123.agents.claude-local.allow_commands)
Hello World
✔ finished  exit=0  duration=12ms  stdout=12B  stderr=0B
```

The CLI exits with the **remote command's exit code** (here, `0`). Try a failing command to see it propagate:

```bash
mx-agent exec --room "$ROOM" --agent claude-local -- sh -c 'exit 7'; echo "local exit: $?"
```

```text
✔ finished  exit=7  duration=9ms
local exit: 7
```

**What just happened?** The CLI sent `exec.start` over the socket → the daemon built and **signed** a `com.mxagent.exec.request.v1` event → published it to the room → its own `/sync` received it → it verified the signature, nonce, expiry, and **local policy** → ran `echo` in a supervised process → streamed stdout back as `com.mxagent.stream.chunk.v1` and the result as `com.mxagent.exec.finished.v1`. See [[Stream & Protocol Spec|Stream-and-Protocol-Spec]] for the wire format.

---

## Common errors & fixes

| Symptom | Cause | Fix |
|---|---|---|
| `error: could not connect to daemon socket` | Daemon isn't running | `mx-agent daemon start`, then retry |
| `error: peer credential mismatch (peer uid 1001 != daemon uid 1000)` | You're running the CLI as a different user than the daemon | Run both as the **same** OS user; mx-agent deliberately refuses cross-user sockets |
| `error: not logged in to Matrix` | Skipped Step 2, or session expired | `mx-agent auth login --homeserver <URL> --user <USER>` |
| `error: unknown room '!…'` | Wrong room ID, or you haven't joined | `mx-agent workspace join '#alias:server'`; double-check the `$ROOM` value |
| `exit 126` from an exec | **Local policy denied** the command | Allow it in `~/.config/mx-agent/policy.toml` (see [[Security & Sandboxing|Security-and-Sandboxing]]); deny-by-default is intentional |
| `exit 127` | Agent / tool / command not found | Check `mx-agent agent list --room "$ROOM"` and that the binary exists on the target |
| `not implemented yet` printed | You hit a 🟡/🔮 alpha stub | Expected in v0.1.0; the command's shape is final, behavior is landing |
| `--socket` ignored / wrong path | Custom `$XDG_RUNTIME_DIR` | Pass `--socket <path>` explicitly or set `MX_AGENT_RUNTIME_DIR` |

---

## Next steps

- Coordinate multiple AI agents: [[AI Agent Orchestration|AI-Agent-Orchestration]]
- Understand the model: [[Core Concepts|Core-Concepts]]
- Lock it down for production: [[Security & Sandboxing|Security-and-Sandboxing]]
