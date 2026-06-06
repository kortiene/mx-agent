# mx-agent alpha user guide

This guide walks a new user from a fresh checkout to a working **two-agent
demo**: two agents registered in a shared Matrix workspace, discovering each
other, then running a tool call and a remote-style `exec`.

> **Alpha status.** `mx-agent` is pre-release software. The workspace,
> authentication, agent-registry, task, trust, and context-sharing commands run
> against a real Matrix homeserver. `call` is daemon-mediated local loopback by
> default and uses signed Matrix-backed remote dispatch when `--room`/`--agent`
> target a registered, trusted, policy-allowed agent. `exec` is still
> daemon-mediated local loopback. Treat execution commands carefully and read
> [Security warnings](#security-warnings) before pointing mx-agent at anything
> you do not control.

## Contents

- [Install](#install)
- [Start a Matrix homeserver](#start-a-matrix-homeserver)
- [Log in and set up](#log-in-and-set-up)
- [Create a workspace](#create-a-workspace)
- [Register agents](#register-agents)
- [Run a tool call](#run-a-tool-call)
- [Run exec](#run-exec)
- [Track work with tasks](#track-work-with-tasks)
- [Two-agent demo (end to end)](#two-agent-demo-end-to-end)
- [Security warnings](#security-warnings)

## Install

### Prerequisites

- A Rust stable toolchain (install via [rustup](https://rustup.rs); MSRV 1.74).
- [Docker](https://docs.docker.com/get-docker/) with Compose v2, plus `curl`
  and `jq` — only needed for the local homeserver used by this guide.

### Build from source

```bash
git clone https://github.com/kortiene/mx-agent
cd mx-agent
cargo build --release
```

The binary is then at `target/release/mx-agent`. For convenience, either put it
on your `PATH`:

```bash
install -m 0755 target/release/mx-agent ~/.local/bin/mx-agent   # if ~/.local/bin is on PATH
mx-agent --help
```

…or run it in place via Cargo, which is what the rest of this guide assumes you
can do interchangeably:

```bash
cargo run -p mx-agent-cli -- --help
```

Throughout this guide, `mx-agent <args>` means "the binary you built" — use
whichever of the two forms above you prefer.

## Start a Matrix homeserver

`mx-agent` needs a Matrix homeserver to host workspaces. For local use the repo
ships a throwaway [Tuwunel](https://github.com/matrix-construct/tuwunel)
homeserver in Docker that binds to loopback only and has federation disabled.

```bash
scripts/matrix_dev.sh up                 # start it (auto-creates dev/matrix/.env)
scripts/matrix_dev.sh register alice     # create user @alice:localhost (password: alice-pass)
scripts/matrix_dev.sh register bob       # create user @bob:localhost   (password: bob-pass)
```

`register <user>` defaults the password to `<user>-pass`. The homeserver base
URL is `http://127.0.0.1:8008` and user IDs are `@<name>:localhost`. See
[`dev/matrix/README.md`](../dev/matrix/README.md) for `status`, `logs`,
`down`, and `reset`.

To use your own homeserver instead, substitute its base URL (e.g.
`https://matrix.org`) and your own credentials everywhere below.

## Log in and set up

Log in with the password flow. To keep the password out of your shell history
and the process table, pass it in `MX_AGENT_PASSWORD`; if that variable is
unset, `mx-agent` prompts for it on the terminal instead.

```bash
MX_AGENT_PASSWORD=alice-pass \
  mx-agent auth login --homeserver http://127.0.0.1:8008 --user alice
```

```text
mx-agent: logged in as @alice:localhost
  device: MXAGENTDEV
```

Confirm the saved session and log out when you are done:

```bash
mx-agent auth status        # prints the logged-in user, device, homeserver
mx-agent auth logout        # clears the local session
```

`auth status` exits `3` when no session is stored, so it is safe to use in
scripts.

## Create a workspace

A workspace is a Matrix room that agents share. Create one as the logged-in
user:

```bash
mx-agent workspace create --alias demo --name "Demo workspace"
```

```text
mx-agent: created workspace !aBcD...:localhost
  alias:     #demo:localhost
  encrypted: true
  members:   1
```

Note the room alias (`#demo:localhost`) — every later command takes it via
`--room`. Other members join with `mx-agent workspace join '#demo:localhost'`.

Optionally bind the room to a local checkout so shares and registrations carry
repo metadata:

```bash
mx-agent workspace attach --room '#demo:localhost' --project-id repo:github.com/kortiene/mx-agent
mx-agent workspace status --room '#demo:localhost'
```

## Register agents

Registering publishes an agent's presence, capabilities, and tool list into the
workspace as room state so peers can discover it. Each session corresponds to
one agent; the `--agent-id` is the state key and defaults to `<user>-<device>`.

```bash
mx-agent agent register \
  --room '#demo:localhost' \
  --agent-id alice-agent \
  --kind generic \
  --capability shell --capability test \
  --tool 'run_tests@1.0.0'
```

List and inspect agents in the room:

```bash
mx-agent agent list  --room '#demo:localhost'
mx-agent agent show  --room '#demo:localhost' --agent-id alice-agent
mx-agent agent tools --room '#demo:localhost' --agent-id alice-agent
```

The default `--kind` is `generic` and the default `--max-invocations` is `1`.

## Run a tool call

`mx-agent call` invokes a named tool and exits with the tool's own exit code, so
failures propagate to your shell. Tool execution happens in the **daemon**, not
the CLI, so a daemon must be running (`mx-agent daemon start`); without one,
`call` exits `3` with a clear message. The built-in `run_tests` tool shells out
to `cargo test`:

```bash
mx-agent call --tool run_tests --arg package=mx-agent-protocol
```

Pass structured input as repeated `--arg key=value` pairs, or as a JSON object
with `--input-json <file>` (`-` reads stdin):

```bash
echo '{"package":"mx-agent-protocol","name":"canonical"}' \
  | mx-agent call --tool run_tests --input-json -
```

Unknown tools exit `127` and invalid arguments exit `64`.

To target a remote daemon, register both agents in the room, approve the
requester's signing key in the target daemon's trust store, allow the tool in
local policy, then pass both targeting flags:

```bash
mx-agent call --room '!room:server' --agent developer-pi \
  --tool run_tests --arg package=mx-agent-protocol
```

The target daemon verifies the signed request, local trust, and local policy
before executing the tool and sending a Matrix response.

## Run exec

`mx-agent exec` runs a command and renders its output, exiting with the
command's exit code. Put the command after `--`:

```bash
mx-agent exec -- echo "hello from mx-agent"
mx-agent exec --stream -- sh -c 'echo out; echo err 1>&2; exit 3'   # exits 3
```

Useful flags: `--stream` (live stdout/stderr), `--strict-stream` (treat a
missing or corrupt chunk as a hard error), `--pty` (allocate a pseudo-terminal),
`--stdin` (forward local stdin), and `--cwd <dir>`.

> In this alpha, `exec` is mediated by the daemon over local IPC, so a daemon
> must be running (`mx-agent daemon start`); otherwise `exec` exits `3`. The
> daemon — not the CLI — runs the command, but it still runs on your **local**
> machine as a loopback. The `--room`/`--agent` targeting flags are accepted for
> forward compatibility but do not yet dispatch to a remote agent over Matrix.
> `--pty` still runs in the CLI for now; moving it onto the IPC path is
> follow-up work.

## Track work with tasks

Tasks are durable DAG nodes stored as `com.mxagent.task.v1` room state. The
`task` commands are mediated by the daemon over local IPC, so start it first and
keep it running:

```bash
mx-agent daemon start
mx-agent daemon status
```

The CLI stays stateless; the daemon owns the Matrix session and signing key and
reads/writes task state on the homeserver.

### Create tasks

A planning/manual task (no action) just records intent:

```bash
mx-agent task create --room '#demo:localhost' --title "Plan the release"
```

A **tool-backed** task carries a structured action naming a tool and its
arguments:

```bash
mx-agent task create --room '#demo:localhost' \
  --title "Run protocol tests" --assign alice-agent \
  --tool run_tests --arg package=mx-agent-protocol
```

An **exec-backed** task carries a command (after `--`):

```bash
mx-agent task create --room '#demo:localhost' \
  --title "Build the workspace" --assign alice-agent \
  --exec --cwd "$PWD" --timeout-ms 600000 \
  -- cargo build --all
```

Express dependencies with `--depends-on` (repeatable). A dependent task is not
runnable until every dependency has succeeded:

```bash
PLAN=$(mx-agent task create --room '#demo:localhost' --title Plan --json | jq -r .task_id)
mx-agent task create --room '#demo:localhost' --title Test \
  --assign alice-agent --tool run_tests --arg package=mx-agent-protocol \
  --depends-on "$PLAN"
```

### Inspect tasks

`task list` shows tasks (human by default, `--json` for automation):

```bash
mx-agent task list --room '#demo:localhost'
mx-agent task list --room '#demo:localhost' --state pending --json
```

`task graph` renders the dependency tree and surfaces non-blocking
**diagnostics** — duplicate titles, dependency cycles, dangling dependency IDs,
unknown/inactive assignees, schedulable tasks with no action, and tool actions
the assigned agent does not offer:

```bash
mx-agent task graph --room '#demo:localhost'
```

```text
task-plan  pending
  └─ task-test  pending

warnings (1):
  ! [missing_dependency] task-test: task "task-test" depends on missing task "task-deploy"
```

`mx-agent task graph --room '#demo:localhost' --json` emits the same graph as a
JSON object with `nodes`, `edges`, `roots`, `cycles`, and a machine-readable
`warnings` array. Diagnostics never reject or change task state, so valid
advanced workflows are never blocked.

`task watch` streams live task changes until you press Ctrl-C:

```bash
mx-agent task watch --room '#demo:localhost'
```

### Update task state

Transition a task or attach an action/result. Lifecycle transitions are
validated, so terminal states are not reopened and unknown states are rejected.
Use `--expected-state-rev` for safe optimistic updates that refuse to clobber a
newer revision:

```bash
mx-agent task update --room '#demo:localhost' task_01H... --state assigned --assign alice-agent
mx-agent task update --room '#demo:localhost' task_01H... --state cancelled
```

### What the daemon enforces (orchestration engine)

mx-agent ships a daemon **task-orchestration engine** that decides what is
runnable, claims a task with optimistic `state_rev` concurrency, runs its
action, and writes a stable result. It enforces the security model *before*
anything runs:

- **Room membership is not execution permission.** A task action runs only when
  it is authorized: local deny-by-default **policy** must allow the requested
  tool/command for the task's creator, and a privileged action must additionally
  carry a valid **Ed25519 signature** from a key your **local trust store**
  trusts (the local store is the final authority; a revoked key never runs).
  Unsigned, untrusted, expired, replayed, malformed, or policy-denied actions
  never spawn — they are blocked with a recorded, non-sensitive reason.
- **Approvals** hold a task whose policy sets `requires_approval`; it does not
  run until you approve it (`mx-agent approval list` / `approve` / `deny`), and a
  denied approval never spawns.
- **Lifecycle:** a claimed task moves `pending`/`assigned` → `executing` →
  `succeeded`/`failed`; the result records the linked `invocation_id`, exit code,
  and a non-sensitive summary. Exit `0` succeeds; anything else fails.
- **Restart recovery:** on restart the daemon reconciles `executing` tasks
  against its live invocations — an orphaned local task is marked failed (never
  double-run), and a remote-owned task is left unchanged with a stale warning.

> **Alpha limitation.** This orchestration engine is implemented and covered by
> unit and integration tests, but it is **not yet auto-driven by a live `/sync`
> loop**: a running daemon does not yet poll the room and execute tasks on its
> own. Today you create, inspect, transition, and graph task state over Matrix;
> automatic end-to-end scheduling/execution — and the signed Matrix transport
> that carries an action to a *remote* agent's daemon (#155) — are still landing.

## Two-agent demo (end to end)

This is the demo the rest of the guide builds toward: two agents in one
workspace, discovered over Matrix, with a tool call and an exec run against the
shared project. Run it from a clean checkout.

```bash
# 0. Build and start a local homeserver with two users.
cargo build --release
export PATH="$PWD/target/release:$PATH"
scripts/matrix_dev.sh up
scripts/matrix_dev.sh register alice    # @alice:localhost / alice-pass
scripts/matrix_dev.sh register bob      # @bob:localhost   / bob-pass

# 1. Alice logs in and creates the shared workspace.
MX_AGENT_PASSWORD=alice-pass \
  mx-agent auth login --homeserver http://127.0.0.1:8008 --user alice
mx-agent workspace create --alias demo --name "Two-agent demo"

# 2. Alice registers her agent.
mx-agent agent register --room '#demo:localhost' \
  --agent-id alice-agent --capability shell --capability test \
  --tool 'run_tests@1.0.0'

# 3. Bob logs in, joins the same room, and registers the second agent.
MX_AGENT_PASSWORD=bob-pass \
  mx-agent auth login --homeserver http://127.0.0.1:8008 --user bob
mx-agent workspace join '#demo:localhost'
mx-agent agent register --room '#demo:localhost' \
  --agent-id bob-agent --capability shell --tool 'run_tests@1.0.0'

# 4. Both agents are now discoverable in the workspace.
mx-agent agent list --room '#demo:localhost'
#   mx-agent: 2 agent(s) in #demo:localhost
#     alice-agent  generic  online  shell,test
#     bob-agent    generic  online  shell

# 5. Run a tool call and an exec. Both are daemon-mediated over local IPC, so a
#    daemon must be running (start it once; it stays up in the background).
mx-agent daemon start
mx-agent call --tool run_tests --arg package=mx-agent-protocol
mx-agent exec -- echo "hello from the demo"
```

Step 4 showing both `alice-agent` and `bob-agent` is the demo working: two
independent sessions registered into one Matrix workspace and discovering each
other. Steps 1–3 each authenticate to the homeserver under a different user, so
re-run `mx-agent auth login` whenever you switch identities (a single machine
holds one active session at a time).

When finished, tear the homeserver down:

```bash
scripts/matrix_dev.sh reset   # stop and wipe all homeserver data
```

## Security warnings

- **Remote execution is dangerous by design.** `call` and `exec` run commands
  and the `run_tests` tool literally shells out to `cargo test`. Only target
  workspaces and agents you trust, and never run a command or tool you have not
  read. In this alpha both runners execute on your local machine.
- **The bundled homeserver is for local testing only.** It binds to
  `127.0.0.1`, disables federation, and its registration token lives in a
  gitignored `dev/matrix/.env`. Do not expose it, point it at production data,
  or treat `@alice:localhost`-style accounts as secure identities.
- **Protect your session and signing key.** A successful login stores a Matrix
  access token, and the daemon keeps an Ed25519 signing key, under your
  XDG state directory. Anyone who can read those files can act as you. Run
  `mx-agent trust fingerprint` to view your key fingerprint and verify it
  out-of-band with peers.
- **Verify trust before acting on peers.** Use `mx-agent trust approve` /
  `revoke` / `state` to manage which agent signing keys you accept. The local
  trust store is the final authority — a local revocation overrides any
  room-published trust.
- **Never paste secrets onto the command line.** Pass the login password via
  `MX_AGENT_PASSWORD` (or the interactive prompt) rather than a flag, so it
  stays out of shell history and `ps`. mx-agent redacts secret-looking values in
  its logs, but tokens and keys should never be committed or shared.
- **Approvals gate privileged work.** When a request requires human sign-off it
  is held until you decide it. Review the queue with `mx-agent approval list`
  and resolve entries with `mx-agent approval approve` / `deny`.
</content>
</invoke>
