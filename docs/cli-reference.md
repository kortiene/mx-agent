# mx-agent CLI Reference

<!-- markdownlint-disable MD013 MD036 MD060 -->

> Complete command reference for the `mx-agent` binary (workspace **v0.2.0**, public alpha).
> Verified against source at commit `e616908`. Platform: **Unix only** (Linux and macOS).

`mx-agent` is a Matrix-backed CLI for decentralized orchestration between coding agents. The
CLI is **stateless**: it holds no Matrix session, keys, or policy of its own. Every command is
mediated by a local background **daemon** over a Unix-domain-socket JSON-RPC 2.0 channel
(socket mode `0600`, peer-checked with `SO_PEERCRED`). The daemon owns all long-lived state;
the CLI just formats requests and renders responses.

## Status & scope

This reference documents every command group, subcommand, option, and exit code in the shipped CLI. Capabilities are tagged where behavior is local-only, opt-in, or partial in this alpha. For conceptual walkthroughs see [`docs/user-guide.md`](user-guide.md), the [Architecture](architecture.md), and the [security hardening guide](security-hardening.md).

## Table of contents

- [Quick start](#quick-start)
- [Global options](#global-options)
- [Architecture & the request pipeline](#architecture--the-request-pipeline)
- [Conventions](#conventions)
- **Commands**
  - [`daemon` — Manage the local background daemon](#daemon--manage-the-local-background-daemon)
  - [`auth` — Manage Matrix authentication](#auth--manage-matrix-authentication)
  - [`workspace` — Create, join, and inspect Matrix workspaces](#workspace--create-join-and-inspect-matrix-workspaces)
  - [`agent` — Register and discover agents](#agent--register-and-discover-agents)
  - [`call` — Invoke a named tool on a remote agent](#call--invoke-a-named-tool-on-a-remote-agent)
  - [`exec` — Run a command on a remote agent](#exec--run-a-command-on-a-remote-agent)
  - [`share` — Broadcast context (diffs, environment, files)](#share--broadcast-context-diffs-environment-files)
  - [`task` — Manage the distributed task DAG](#task--manage-the-distributed-task-dag)
  - [`invocation` — Inspect and cancel running invocations](#invocation--inspect-and-cancel-running-invocations)
  - [`approval` — Review and decide pending approval requests](#approval--review-and-decide-pending-approval-requests)
  - [`trust` — Manage local and published trust for remote agents](#trust--manage-local-and-published-trust-for-remote-agents)
  - [`device` — Inspect and verify peer Matrix devices (E2EE transport identity)](#device--inspect-and-verify-peer-matrix-devices-e2ee-transport-identity)
  - [`recovery` — Manage server-side key backup and recovery](#recovery--manage-server-side-key-backup-and-recovery)
- [Files and directories](#files-and-directories)
- [Environment variables](#environment-variables)
- [Exit codes](#exit-codes)
- [Defaults and limits](#defaults-and-limits)
- [Configuration: policy.toml](#configuration-policytoml)
- [Trust store format](#trust-store-format)
- [Audit log format](#audit-log-format)
- [JSON output](#json-output)
- [Shell completions and man pages](#shell-completions-and-man-pages)
- [See also](#see-also)

## Quick start

A minimal end-to-end flow. Each line is a separate command.

```bash
# 1. Start the local daemon (owns the Matrix session, keys, and policy).
mx-agent daemon start

# 2. Log in to a homeserver. The password comes from MX_AGENT_PASSWORD or a prompt;
#    the CLI hands the session to the daemon and never stores it itself.
mx-agent auth login --homeserver https://matrix.example.org --user @me:example.org

# 3. Create a workspace room and bind the current repo to it.
mx-agent workspace create --name "My project" --alias my-project --visibility private
mx-agent workspace attach --room '#my-project:example.org' \
    --project-id repo:github.com/org/project

# 4. Register this machine as an agent in the room.
mx-agent agent register --room '#my-project:example.org' \
    --capability shell --capability test --tool run_tests@1.0.0

# 5. Run a command locally (daemon-mediated loopback)...
mx-agent exec -- cargo test

# 6. ...or on a trusted remote agent (Ed25519-signed over Matrix; alpha rooms are unencrypted).
mx-agent exec --room '#my-project:example.org' --agent '@peer:example.org' -- uname -a
```

Add `--json` to any command for machine-readable output, and `-v`/`-vv` for more logs.

## Global options

Clap `global=true` — accepted before OR after the subcommand:

- `--json` — machine-readable JSON instead of human text
- `--config <PATH>` — path to the configuration file
- `--socket <PATH>` — daemon IPC socket path override
- `-v, --verbose` — repeatable log verbosity: 0=warn, 1=info, 2=debug, 3+=trace (overridden by MX_AGENT_LOG)
- `--version` — print version (propagated to all subcommands via `propagate_version = true`)
- `--help`

Running `mx-agent` with NO subcommand prints help (`arg_required_else_help`).

## Architecture & the request pipeline

The CLI is STATELESS. Every command group is mediated by the daemon over a local Unix-domain-socket JSON-RPC 2.0 channel (socket mode 0600, peer checked with SO_PEERCRED). The CLI never reads the Matrix session file and never builds a Matrix client itself.

EXCEPTIONS/nuance:

- `mx-agent daemon start/status/stop` manage the daemon process itself (not over IPC for start).
- `auth login` is CLI-initiated only to receive the password and hand the new session to the daemon.
- `call` and `exec` run daemon-mediated LOCAL loopback execution by DEFAULT; they become signed, Matrix-backed REMOTE operations when BOTH `--room` and `--agent` target a registered remote agent (Ed25519-signed; the workspace room is unencrypted in this alpha, so traffic is readable by the homeserver — see #249).
- Privileged remote requests run the receiver-side pipeline: verify(Ed25519 signature) → local trust store → deny-by-default policy.toml → optional require_verified_device gate → optional approval gate → sandbox runner. Room membership alone grants NOTHING.

## Conventions

- **Human vs JSON output.** Commands print human-readable text by default; `--json` emits a
  single JSON value (object or array) per command, suitable for piping to `jq`. Each subcommand's
  **Behavior** note names the key JSON fields it returns.

- **Room identifiers.** Anywhere a `<ROOM>` is accepted you may pass a room alias
  (`#name:server`) or a raw room ID (`!id:server`). Quote aliases in shells (`'#room:server'`).

- **Repeatable options.** Flags marked *(repeatable)* may be given multiple times to build a list
  (e.g. `--capability shell --capability test`).

- **The `--` separator.** `exec` and `task --exec` take the remote command after a literal `--`,
  so its own flags are not parsed by `mx-agent` (e.g. `exec -- ls -la`).

- **Local vs remote.** `call` and `exec` run locally through the daemon by default; supplying
  **both** `--room` and `--agent` turns them into signed remote operations (Ed25519-signed and
  authorized by the target daemon; not end-to-end encrypted in this alpha) that the target daemon
  authorizes independently.

Commands are grouped below. Each group lists its subcommands, then documents every option, behavior, exit codes, and examples.

## `daemon` — Manage the local background daemon

The daemon is the runtime process that the CLI communicates with over a Unix-domain socket. It maintains the Matrix session, handles E2EE crypto state, manages the task scheduler, and processes incoming invocation requests. A daemon must be running before any workspace/agent/call/exec commands will work.

| Subcommand | Purpose |
|---|---|
| `start` | Start the daemon in the background (or foreground with `--foreground`). Returns success if already running. |
| `status` | Check if the daemon is running and report its PID, uptime, socket path, version, and (if authenticated) Matrix sync health. |
| `stop` | Stop the daemon gracefully via SIGTERM, then SIGKILL if needed. |

### `mx-agent daemon start`

Start the daemon in the background, or foreground if `--foreground` is set.

**Synopsis**

```text
mx-agent [GLOBAL] daemon start [--foreground]
```

**Options**

| Option | Value | Required | Default | Description |
|---|---|---|---|---|
| `--foreground` | — | no | false | Run in foreground and block until shutdown (SIGINT/SIGTERM). Useful for debugging or systemd Type=simple services. |

**Behavior**
When invoked without `--foreground`, checks if a daemon is already running. If it is, prints a message and exits 0. If not, spawns a background process, writes a status file to the runtime directory, and prints the PID. In foreground mode, the daemon runs until interrupted and exits when the process receives SIGINT or SIGTERM.

In human mode, prints `"mx-agent daemon already running (pid <PID>)"` or `"mx-agent daemon started (pid <PID>)"`. With `--json`, emits a single-line JSON object with fields `running` (true), `pid`, `uptime_seconds`, `socket_path`, and `version`.

**Exit codes**

- 0: daemon started or already running
- 1: failed to start (e.g., socket binding failed, permission error, or status check error)

**Examples**

```bash
# Start daemon in background
mx-agent daemon start

# Start daemon in foreground (for debugging or Docker)
mx-agent daemon start --foreground

# Start daemon and capture its status as JSON
mx-agent --json daemon start
```

**Notes**
On startup, the daemon binds the Unix-domain socket with mode 0600 (readable/writable by owner only) and validates that the runtime directory is private to the current user. If a Matrix session exists, the daemon spawns a sync loop and a live task scheduler; otherwise, it idles waiting for `auth login`. The status file is written to `$MX_AGENT_RUNTIME_DIR/daemon.json` (defaults to `$XDG_RUNTIME_DIR/mx-agent`). The socket is unlinked on shutdown.

---

### `mx-agent daemon status`

Report the daemon's status (PID, uptime, socket path, version, and sync health if authenticated).

**Synopsis**

```text
mx-agent [GLOBAL] daemon status
```

**Options**

| Option | Value | Required | Default | Description |
|---|---|---|---|---|
| (none) | — | — | — | |

**Behavior**
Checks if a daemon is running by reading the status file and verifying the process is alive. If running, attempts to query live status from the daemon over IPC; falls back to the status file if the socket cannot be reached. If authenticated (a Matrix session exists), the live daemon's sync loop health is included.

In human mode, prints:

```text
mx-agent daemon: running
  pid:     <PID>
  uptime:  <SECONDS>s
  socket:  <PATH>
  version: <VERSION>
  sync:    <STATE>
    syncs:    <COUNT>
    failures: <COUNT>  (only if > 0)
    last err: <ERROR>  (only if set)
```

If not running, prints `"mx-agent daemon: not running"`.

With `--json`, emits `{"running":true,"pid":<PID>,"uptime_seconds":<SECONDS>,"socket_path":"<PATH>","version":"<VERSION>"}` when running, or `{"running":false}` when not. The `sync` field is included only if available:

```json
{
  "running": true,
  "pid": <PID>,
  "uptime_seconds": <SECONDS>,
  "socket_path": "<PATH>",
  "version": "<VERSION>",
  "sync": {
    "state": "initializing",
    "total_syncs": 42,
    "consecutive_failures": 0,
    "last_success_unix": 1234567890,
    "last_error": null,
    "resumed_from_token": true
  }
}
```

**Exit codes**

- 0: daemon is running
- 1: status check failed (e.g., permission error reading status file)
- 3: daemon is not running

**Examples**

```bash
# Check daemon status
mx-agent daemon status

# Get machine-readable status
mx-agent --json daemon status

# Check exit code (0=running, 3=not running, 1=error)
mx-agent daemon status; echo $?
```

**Notes**
A stale status file (referencing a dead PID) is automatically removed and treated as "not running". The sync field's `state` in JSON is one of `initializing`, `healthy`, `degraded`, or `stopped` (snake_case). In human-readable output, the state is printed with the PascalCase variant name (e.g., `Initializing`, `Healthy`, `Degraded`, `Stopped`). Scripts can use exit code 3 to distinguish "daemon not running" from "status check error" (exit code 1).

---

### `mx-agent daemon stop`

Stop the daemon gracefully (SIGTERM, then SIGKILL if needed).

**Synopsis**

```text
mx-agent [GLOBAL] daemon stop
```

**Options**

| Option | Value | Required | Default | Description |
|---|---|---|---|---|
| (none) | — | — | — | |

**Behavior**
Attempts to stop a running daemon by sending SIGTERM and waiting up to 5 seconds. If the daemon does not exit, sends SIGKILL. If no daemon is running, reports success with no action taken.

In human mode, prints `"mx-agent daemon stopped (pid <PID>)"`, `"mx-agent daemon force-killed (pid <PID>)"`, or `"mx-agent daemon: not running"`.

With `--json`, emits:

- `{"stopped":true,"pid":<PID>}` if stopped via SIGTERM
- `{"stopped":true,"killed":true,"pid":<PID>}` if force-killed
- `{"stopped":false,"running":false}` if not running

**Exit codes**

- 0: daemon stopped (or was not running)
- 1: failed to stop (e.g., permission denied, status check error)

**Examples**

```bash
# Stop daemon
mx-agent daemon stop

# Stop daemon and get JSON confirmation
mx-agent --json daemon stop

# Stop and check that it's gone
mx-agent daemon stop
mx-agent daemon status  # exit 3
```

**Notes**
The graceful shutdown gives the daemon 5 seconds to exit cleanly (e.g., flush logs, close Matrix sockets) before forcibly killing it. Any running invocations are cancelled with SIGTERM followed by SIGKILL per the standard cancel grace policy. The status file is removed on shutdown. Under the hood, stop reads the PID from the status file and signals it directly; it does not use IPC.

## `auth` — Manage Matrix authentication

Authenticate against a Matrix homeserver and manage E2EE device/cross-signing identity. All operations except login and logout are daemon-mediated via IPC and require the daemon to be running.

| Subcommand | Purpose |
|---|---|
| `login` | Authenticate against a Matrix homeserver with username and password |
| `status` | Report authentication status (logged in / not logged in) |
| `logout` | Clear the local session |
| `cross-signing bootstrap` | Create and publish the daemon's cross-signing identity (idempotent) |
| `cross-signing status` | Show cross-signing key status |

### `mx-agent auth login`

Authenticate against a Matrix homeserver and persist the session locally.

**Synopsis**

```text
mx-agent [GLOBAL] auth login --homeserver <URL> --user <USER>
```

**Options**

| Option | Value | Required | Default | Description |
|---|---|---|---|---|
| `--homeserver` | `<URL>` | yes | — | Homeserver base URL, e.g. `https://matrix.org` |
| `--user` | `<USER>` | yes | — | Matrix user localpart or full user ID |

**Behavior**
Checks the `MX_AGENT_PASSWORD` environment variable for a password; if not set, prompts on stderr with `Matrix password:` (echo suppressed on TTY stdin via an RAII guard; transparent for non-TTY input such as pipes or CI harnesses). Performs interactive password authentication against the homeserver, obtains a session token, and persists it in the data directory (not readable by agents). Session includes device ID and access token (wrapped as `Secret` so never logged). The daemon automatically re-syncs and E2EE-registers the device on first restart. In human mode, prints `mx-agent: logged in as {user_id}` followed by indented `device: {device_id}`; in `--json`, outputs an `AuthStatus` object with keys `logged_in`, `user_id`, `device_id`, `homeserver`.

**Exit codes**

| Code | Meaning |
|---|---|
| 0 | Successfully logged in and session persisted |
| 1 | Login failed: invalid credentials, network error, homeserver validation error, or session save error |

**Examples**

```bash
# Interactive password prompt
mx-agent auth login --homeserver https://matrix.org --user alice

# Non-interactive (CI/automation)
MX_AGENT_PASSWORD="secret123" mx-agent auth login --homeserver https://matrix.org --user alice

# Machine-readable output
mx-agent --json auth login --homeserver https://matrix.org --user alice
```

**Notes**

- The password is never echoed, logged, or passed as a command-line argument (safe for shell history). When stdin is a TTY, an RAII guard clears terminal echo (`ECHO`/`ECHONL`) for the duration of the interactive read and restores it unconditionally on return, early error, or panic unwind — typed characters do not appear on screen or land in terminal scrollback. Non-TTY stdin (pipe, here-doc, CI harness) is handled transparently without echo manipulation.
- The `MX_AGENT_PASSWORD` env var must be set or the CLI prompts on stderr.
- The daemon does not require a running instance to login; it runs standalone. Session is read by the daemon on next start.
- The session token is never exposed to the CLI or agents; only the daemon accesses it.

### `mx-agent auth status`

Report whether a session is persisted and show login details.

**Synopsis**

```text
mx-agent [GLOBAL] auth status
```

**Options**
None.

**Behavior**
Reads the persisted session file (if it exists) and reports logged-in state. Does not contact the homeserver or the daemon. In human mode, prints:

- `mx-agent: logged in` with indented fields (`user`, `device`, `homeserver`), or
- `mx-agent: not logged in`

In `--json`, outputs an `AuthStatus` object: `{"logged_in": true/false, "user_id": "...", "device_id": "...", "homeserver": "..."}` (fields omitted if not logged in).

**Exit codes**

| Code | Meaning |
|---|---|
| 0 | Logged in |
| 1 | Error reading session (file I/O error) |
| 3 | Not logged in |

**Examples**

```bash
# Check login status
mx-agent auth status

# Machine-readable check
mx-agent --json auth status
```

**Notes**

- Exit code 3 (not 1) when not logged in, allowing scripts to branch on authentication state.
- This command does not require the daemon to be running.

### `mx-agent auth logout`

Clear the local session file, logging out.

**Synopsis**

```text
mx-agent [GLOBAL] auth logout
```

**Options**
None.

**Behavior**
Removes the persisted session file. The daemon is unaffected (does not unregister the device or revoke the token server-side); restarting the daemon later will fail to sync until you `auth login` again. In human mode, prints `mx-agent: logged out`; in `--json`, outputs `{"logged_in":false}`.

**Exit codes**

| Code | Meaning |
|---|---|
| 0 | Successfully cleared session |
| 1 | Error deleting session file (e.g., permission denied) |

**Examples**

```bash
mx-agent auth logout
```

**Notes**

- Does not contact the homeserver or require the daemon to run.
- The daemon's in-memory session reference will be stale until it is restarted.

### `mx-agent auth cross-signing bootstrap`

Create and publish the daemon's cross-signing identity to the homeserver (idempotent).

**Synopsis**

```text
mx-agent [GLOBAL] auth cross-signing bootstrap
```

**Options**
None.

**Behavior**
Daemon-mediated operation: contacts the homeserver, generates or retrieves the daemon's master key, self-signing key, and user-signing key, and publishes them as cross-signing identity state on the server. Safe to re-run; the daemon reuses existing keys if already present. In human mode, prints:

```text
mx-agent: cross-signing bootstrap
  complete:     true/false
  master:       true/false
  self-signing: true/false
  user-signing: true/false
```

In `--json`, outputs a `CrossSigningStatusInfo` object with fields `complete`, `has_master`, `has_self_signing`, `has_user_signing`.

**Exit codes**

| Code | Meaning |
|---|---|
| 0 | Cross-signing keys created or already present |
| 1 | Daemon error or network failure |
| 3 | Not authenticated (daemon could not contact homeserver) |

**Examples**

```bash
mx-agent auth cross-signing bootstrap

# Check if idempotent
mx-agent auth cross-signing bootstrap
```

**Notes**

- Requires an authenticated session (must `auth login` first).
- Requires the daemon to be running.
- E2EE device verification flows (SAS, QR code) can verify device identity across the cross-signing hierarchy once bootstrap completes.

### `mx-agent auth cross-signing status`

Show the daemon's cross-signing key status.

**Synopsis**

```text
mx-agent [GLOBAL] auth cross-signing status
```

**Options**
None.

**Behavior**
Daemon-mediated operation: queries the local crypto store and reports whether each of the three cross-signing keys (master, self-signing, user-signing) is available. The `complete` field is true only if all three are present. In human mode, prints:

```text
mx-agent: cross-signing status
  complete:     true/false
  master:       true/false
  self-signing: true/false
  user-signing: true/false
```

In `--json`, outputs a `CrossSigningStatusInfo` object.

**Exit codes**

| Code | Meaning |
|---|---|
| 0 | Status retrieved |
| 1 | Daemon error |
| 3 | Not authenticated |

**Examples**

```bash
mx-agent auth cross-signing status

# Check in JSON
mx-agent --json auth cross-signing status
```

**Notes**

- Requires the daemon to be running and authenticated.
- Does not publish to the homeserver; use `bootstrap` to do so.

## `workspace` — Create, join, and inspect Matrix workspaces

A workspace is a Matrix room that agents use to discover peers, exchange context, and coordinate tasks. All workspace operations are mediated by the daemon over the local Unix-socket IPC channel; the CLI never reads or restores the Matrix session itself. Authentication via `auth login` is required before any workspace operation.

| Subcommand | Purpose |
|---|---|
| `create` | Create a new private or public workspace room with optional alias, name, and topic |
| `join` | Join an existing workspace room by alias or room ID |
| `attach` | Attach the current directory (or a specified path) to a workspace as a project context |
| `status` | Display workspace membership and attached project metadata, with optional live streaming |

### `mx-agent workspace create`

Create a new workspace room.

**Synopsis**

```text
mx-agent [GLOBAL] workspace create [OPTIONS]
```

**Options**

| Option | Value | Required | Default | Description |
|---|---|---|---|---|
| `--alias` | `<ALIAS>` | no | unset | Room alias localpart (e.g. `my-project` for `#my-project:server`); must be unique on the homeserver |
| `--name` | `<NAME>` | no | unset | Human-readable room name |
| `--topic` | `<TOPIC>` | no | unset | Room topic (description) |
| `--visibility` | `private\|public` | no | `private` | Room visibility: `private` (invite-only, hidden from directory) or `public` (joinable, listed in directory) |

**Behavior**

Creates a new Matrix room with the provided options. Private workspaces are invite-only; public workspaces are openly joinable and listed in the homeserver's public room directory. The room is created with E2EE encryption disabled (workspace state events must be readable to all members). Returns [`WorkspaceInfo`](https://spec.matrix.org) containing the room ID, canonical alias (if provided), name, topic, encryption state, and joined member count.

In human mode, prints the room details in a block; `--json` outputs a single-line JSON object with keys: `room_id`, `canonical_alias` (optional), `name` (optional), `topic` (optional), `encrypted`, `joined_members`.

Requires daemon running (`mx-agent daemon start`) and authentication (`auth login`).

**Examples**

```bash
# Create a private workspace for a coding project
mx-agent workspace create --alias my-project --name "My Project" --visibility private

# Create a public workspace visible in the room directory
mx-agent workspace create --alias shared-space --visibility public

# Output as JSON for scripting
mx-agent workspace create --alias test-room --json
```

**Notes**

- The alias must be globally unique on the homeserver; creation fails if the alias is already taken.
- Private workspaces start with no members except the creator; invite others with Matrix client tooling.
- Public workspaces are joinable by anyone on the homeserver but still require explicit membership to exchange exec/call/share operations.

---

### `mx-agent workspace join`

Join an existing workspace room.

**Synopsis**

```text
mx-agent [GLOBAL] workspace join <ROOM>
```

**Options**

| Option | Value | Required | Default | Description |
|---|---|---|---|---|
| `<ROOM>` | room alias or ID | yes | — | Room to join: alias `#name:server` or room ID `!id:server` |

**Behavior**

Joins an existing workspace room. Accepts either a room alias (`#name:server`) or room ID (`!id:server`). The daemon syncs once to fetch room metadata, joins the room, and returns a [`WorkspaceInfo`](https://spec.matrix.org) summary. If the room is already joined, this is a no-op. Returns the room ID, alias (if any), name, topic, encryption state, and member count.

Requires daemon running and authentication. Fails with exit code 1 if the room does not exist, the user is not invited (for private rooms), or the Matrix request fails.

**Examples**

```bash
# Join a public workspace by alias
mx-agent workspace join '#my-project:matrix.org'

# Join by explicit room ID
mx-agent workspace join '!abc123:matrix.org'

# JSON output
mx-agent workspace join '#test:server' --json
```

**Notes**

- The room must be joinable (public or the user invited) for the join to succeed.
- After joining, use `agent register` to advertise yourself and your capabilities in the workspace.

---

### `mx-agent workspace attach`

Attach the current directory to a workspace as a project context.

**Synopsis**

```text
mx-agent [GLOBAL] workspace attach --room <ROOM> --project-id <PROJECT_ID> [OPTIONS]
```

**Options**

| Option | Value | Required | Default | Description |
|---|---|---|---|---|
| `--room` | `<ROOM>` | yes | — | Room alias (`#name:server`) or room ID (`!id:server`) to attach to |
| `--project-id` | `<PROJECT_ID>` | yes | — | Project identifier, e.g. `repo:github.com/org/project` |
| `--path` | `<PATH>` | no | current directory | Local filesystem path to attach; must exist and be a directory |

**Behavior**

Publishes a `com.mxagent.workspace.v1` state event (empty state key) to the specified room, recording the project ID, attached path, and detected git repository metadata (remote URL, branch, commit if inside a git work tree). The state event is broadcast to all room members, allowing agents to discover and navigate the workspace's attached project context.

Returns a [`WorkspaceState`](https://spec.matrix.org) object with keys: `project_id`, `path`, `repo` (optional; git metadata), `attached_by` (user ID), `attached_at` (epoch ms), `state_rev` (incremented per attach), `extra`.

Overwrites any previously attached metadata for the room (last-write-wins); `state_rev` increments each time. Requires the path to exist and be a directory (not a file).

In human mode, prints the attached metadata; `--json` outputs the `WorkspaceState`.

Requires daemon running and authentication, and the user must be a member of the room.

**Examples**

```bash
# Attach the current directory to a workspace
mx-agent workspace attach --room '#my-project:server' --project-id 'repo:github.com/myorg/myproject'

# Attach a specific directory
mx-agent workspace attach --room '!abc:server' --project-id 'docs:internal' --path /var/docs/specs

# JSON output showing git metadata
mx-agent workspace attach --room '#test:server' --project-id 'repo:github' --json
```

**Notes**

- Git metadata is auto-detected; if the path is not in a git work tree, `repo` is omitted.
- Multiple agents can attach the same or different paths; the last attach wins.
- The state event is unencrypted so all workspace members can read project metadata.

---

### `mx-agent workspace status`

Display workspace membership and attached project metadata.

**Synopsis**

```text
mx-agent [GLOBAL] workspace status --room <ROOM> [OPTIONS]
```

**Options**

| Option | Value | Required | Default | Description |
|---|---|---|---|---|
| `--room` | `<ROOM>` | yes | — | Room alias (`#name:server`) or room ID (`!id:server`) to inspect |
| `--watch` | flag | no | unset | Keep running and stream updates as the room changes (Ctrl-C to stop) |

**Behavior**

Fetches the current membership and state of a workspace room, including joined and invited members (with display names), room metadata (ID, alias, name, encryption state), and attached project context if `workspace attach` has been run.

Returns a [`WorkspaceStatus`](https://spec.matrix.org) object with keys: `room_id`, `canonical_alias` (optional), `name` (optional), `encrypted`, `joined_members`, `invited_members`, `members` (list of user IDs and display names, sorted), `workspace` (optional; attached metadata from state event).

In human mode, prints the room info, member count, and a table of joined/invited members; `--json` outputs a single-line JSON object.

When `--watch` is set, establishes a daemon-mediated streaming watch over the room's state. The daemon syncs continuously and emits updates whenever membership or workspace state changes. The CLI receives frames:

- `initial`: first snapshot
- `changed`: membership or metadata changed
- `reconnecting`: transient sync error (with attempt count and error message)
- `reconnected`: recovered after transient error

The watch loop handles network transients with exponential backoff and runs until the user presses Ctrl-C or a fatal error occurs.

Requires daemon running and authentication, and the user must be a member of the room. One-shot `status` performs a single sync; `--watch` establishes a persistent stream.

**Examples**

```bash
# Check workspace membership
mx-agent workspace status --room '#my-project:server'

# JSON output
mx-agent workspace status --room '!abc:server' --json

# Live watch (Ctrl-C to stop)
mx-agent workspace status --room '#my-project:server' --watch

# Watch with JSON streaming
mx-agent workspace status --room '#my-project:server' --watch --json
```

**Notes**

- Members are sorted by user ID for deterministic output.
- The `workspace` field contains the most recent attach metadata; if no attach has occurred, it is omitted.
- `--watch` is daemon-mediated; the CLI does not restore the Matrix session or maintain sync state itself.
- Transient network errors are surfaced as `reconnecting` frames; the watch resumes automatically.
- Press Ctrl-C to cleanly exit the watch loop.

---

**Global Flags** (apply to all subcommands)

| Flag | Description |
|---|---|
| `--json` | Output machine-readable JSON instead of human text |
| `--config <PATH>` | Path to configuration file (overrides `$MX_AGENT_CONFIG_DIR` or `~/.config/mx-agent`) |
| `--socket <PATH>` | Daemon IPC socket path override (overrides `$MX_AGENT_RUNTIME_DIR` or `$XDG_RUNTIME_DIR/mx-agent`) |
| `-v, --verbose` | Repeatable log verbosity (0=warn, 1=info, 2=debug, 3+=trace; overridden by `$MX_AGENT_LOG`) |

**Exit Codes**

- `0`: success
- `1`: invalid input, daemon IPC error, authentication required, or room not found
- `3`: daemon not running (from `daemon status` exit code reuse; catch this if you check daemon before workspace operations)

## `agent` — Register and discover agents

Manage agent registration and discovery in a workspace. Agents advertise themselves via room state events with their capabilities, tools, working directory, and status. Requires the daemon to be running and authenticated to a Matrix homeserver with a joined workspace room.

| Subcommand | Purpose |
|---|---|
| `register` | Register the current agent session |
| `list` | List agents in a workspace |
| `show` | Show details for one agent |
| `tools` | List tools offered by an agent |

### `mx-agent agent register`

Register the current agent session in a workspace room.

**Synopsis**

```text
mx-agent [GLOBAL] agent register --room <ROOM> [--agent-id <ID>] [--kind <KIND>] [--capability <CAP>...] [--tool <TOOL>...] [--cwd <PATH>] [--project-id <ID>] [--max-invocations <N>]
```

**Options**

| Option | Value | Required | Default | Description |
|---|---|---|---|---|
| `--room` | `<ROOM>` | Yes | — | Workspace room alias (`#name:server`) or room ID (`!id:server`) |
| `--agent-id` | `<AGENT_ID>` | No | `<user>-<device>` | Agent identifier (state key); derived from Matrix user and device ID when omitted |
| `--kind` | `<KIND>` | No | `generic` | Agent kind, e.g. `pi`, `generic` |
| `--capability` | `<CAPABILITY>` | No | (empty) | Declared capability, repeatable (e.g. `shell`, `edit`, `test`) |
| `--tool` | `<TOOL>` | No | (empty) | Available named tool, repeatable (e.g. `run_tests@1.0.0`) |
| `--cwd` | `<PATH>` | No | current directory | Working directory the agent operates in |
| `--project-id` | `<PROJECT_ID>` | No | (empty) | Project identifier (e.g. `repo:github.com/org/project`) |
| `--max-invocations` | `<N>` | No | `1` | Maximum concurrent invocations the agent will accept |

**Behavior**

Publishes a `com.mxagent.agent.v1` room state event keyed by the agent ID. Captures the agent's kind, declared capabilities, available tools, working directory, project identifier, and current git commit (if `cwd` is a git repository). Re-registering the same agent ID overwrites the existing state (last-write-wins) and increments the `state_rev` counter. The agent is marked with status `active` and emits heartbeats periodically (every 30s by default) so peers can assess liveness.

Human output prints the registered agent's ID, kind, user ID, device ID, cwd, project, git commit (if present), capabilities, tools, concurrent invocation load, and state revision number.

With `--json`, returns the `AgentState` object containing:

- `agent_id`, `kind`, `matrix_user_id`, `device_id`, `signing_key_id`
- `signing_public_key` (optional, base64-no-pad Ed25519 verifying key)
- `status`
- `capabilities` (array of strings)
- `tools` (array of tool references)
- `workspace` object: `cwd`, `project_id`, `git_commit`
- `load` object: `running_invocations` (0 initially), `max_invocations`
- `last_seen_ts` (milliseconds since epoch)
- `state_rev` (starting at 1, incremented on re-registration)

**Prerequisites**

- Daemon must be running (`mx-agent daemon start`)
- CLI must be authenticated (`mx-agent auth status` shows success)
- Caller must be a member of the workspace room
- Room must exist and be joinable

**Exit codes**

0 on success; 1 on authentication failure, invalid room, or IPC error.

**Examples**

```bash
# Register as a generic agent with default settings
mx-agent agent register --room '#my-workspace:matrix.org'

# Register with explicit agent ID, project ID, and capabilities
mx-agent agent register --room '#project:matrix.org' \
  --agent-id my-agent-1 --project-id repo:github.com/org/repo \
  --capability shell --capability test --max-invocations 4

# Register with advertised tools
mx-agent agent register --room '#workspace:matrix.org' \
  --tool run_tests@1.0.0 --tool build@2.0.0 --cwd /home/user/project
```

**Notes**

- The agent ID must be unique within the room; re-registering the same ID updates the existing entry.
- Re-registering advances `state_rev` monotonically, allowing peers to detect stale states.
- If `--agent-id` is not provided, it is automatically derived as `<user-localpart>-<device-id>`.
- The `--capability` and `--tool` flags are repeatable and concatenated into the agent state; they are used by callers to filter or discover agents.
- Git commit is captured at registration time; it does not update with subsequent git changes.
- Agent status is always set to `active` at registration and managed by the daemon's heartbeat loop thereafter.

---

### `mx-agent agent list`

List agents in a workspace.

**Synopsis**

```text
mx-agent [GLOBAL] agent list --room <ROOM> [--capability <CAP>...]
```

**Options**

| Option | Value | Required | Default | Description |
|---|---|---|---|---|
| `--room` | `<ROOM>` | Yes | — | Workspace room alias (`#name:server`) or room ID (`!id:server`) |
| `--capability` | `<CAPABILITY>` | No | (none) | Filter agents by capability; repeatable and AND-combined |

**Behavior**

Queries all `com.mxagent.agent.v1` room state events in the workspace and computes liveness for each agent by combining the state's `last_seen_ts` with recent heartbeats scanned from the room timeline (up to 100 events). Returns agents matching all specified capabilities (if any).

Human output prints a summary table with columns:

- Agent ID (left-aligned, 24 chars)
- Kind (8 chars)
- Status (8 chars, e.g. `active`)
- Liveness (8 chars: `active`, `stale`, or `offline`)
- Last seen (relative age, 10 chars, e.g. `42s ago`, `3m ago`, `2h ago`, or `never`)
- Capabilities (comma-separated or `-` if none)

With `--json`, returns an array of `AgentListing` objects, each containing:

- `agent` object (the full `AgentState` as in `agent register --json`)
- `liveness` string (`"active"`, `"stale"`, or `"offline"`)

**Prerequisites**

- Daemon must be running
- CLI must be authenticated
- Caller must be a member of the workspace room

**Exit codes**

0 on success; 1 on authentication failure, invalid room, daemon-side error, or IPC error.

**Examples**

```bash
# List all agents in a workspace
mx-agent agent list --room '#my-workspace:matrix.org'

# List only agents with shell capability
mx-agent agent list --room '#project:matrix.org' --capability shell

# List agents with both shell and test capabilities (AND filter)
mx-agent agent list --room '#workspace:matrix.org' \
  --capability shell --capability test

# Get JSON output for scripting
mx-agent agent list --room '#workspace:matrix.org' --json
```

**Notes**

- Liveness verdicts are computed at query time and reflect the most recent heartbeat plus the durable `last_seen_ts` field. Liveness transitions happen after:
  - `active`: heartbeat seen within 90 seconds
  - `stale`: no heartbeat for 90–300 seconds (agent may be unhealthy)
  - `offline`: no heartbeat for 300+ seconds (agent presumed stopped)
- The timeline is scanned backward up to 100 events; very old agents may not have recent heartbeats in the scan window.
- Capability filtering is AND-combined: `--capability a --capability b` returns only agents declaring both capabilities.
- Empty capability list (when no `--capability` flags are given) returns all agents.

---

### `mx-agent agent show`

Show details for one agent.

**Synopsis**

```text
mx-agent [GLOBAL] agent show --room <ROOM> --agent-id <ID>
```

**Options**

| Option | Value | Required | Default | Description |
|---|---|---|---|---|
| `--room` | `<ROOM>` | Yes | — | Workspace room alias (`#name:server`) or room ID (`!id:server`) |
| `--agent-id` | `<AGENT_ID>` | Yes | — | Agent identifier to show |

**Behavior**

Retrieves the `com.mxagent.agent.v1` state for a specific agent and computes its liveness. Returns the agent's full profile including ID, kind, status, capabilities, tools, workspace metadata, load, and liveness.

Human output prints a detailed block with fields:

- `kind`: agent kind
- `status`: current status
- `liveness`: `active`/`stale`/`offline`
- `last_seen`: relative age and exact timestamp (ms since epoch)
- `user`: Matrix user ID
- `device`: Matrix device ID
- `cwd`: working directory
- `project`: project identifier (if set)
- `git commit`: git commit hash (if available)
- `capabilities`: comma-separated list
- `tools`: comma-separated tool references
- `load`: running and max invocations
- `state_rev`: state revision counter

With `--json`, returns an `AgentListing` object containing:

- `agent` object (full `AgentState`)
- `liveness` string

**Prerequisites**

- Daemon must be running
- CLI must be authenticated
- Caller must be a member of the workspace room

**Exit codes**

0 on success; 1 on authentication failure, invalid room, or IPC error; 3 if the agent is not found.

**Examples**

```bash
# Show details for a specific agent
mx-agent agent show --room '#my-workspace:matrix.org' --agent-id alice-DEVICE01

# Get JSON output
mx-agent agent show --room '#project:matrix.org' --agent-id my-agent-1 --json
```

**Notes**

- If the agent does not exist, exit code 3 is returned and the output (in human mode) is sent to stderr.
- Liveness is computed at query time using the same heuristics as `agent list`.
- The `state_rev` field can be used to detect concurrent updates and implement optimistic concurrency control (e.g. in `task update --expected-state-rev`).

---

### `mx-agent agent tools`

List tools offered by an agent.

**Synopsis**

```text
mx-agent [GLOBAL] agent tools --room <ROOM> --agent-id <ID>
```

**Options**

| Option | Value | Required | Default | Description |
|---|---|---|---|---|
| `--room` | `<ROOM>` | Yes | — | Workspace room alias (`#name:server`) or room ID (`!id:server`) |
| `--agent-id` | `<AGENT_ID>` | Yes | — | Agent identifier whose tools to list |

**Behavior**

Retrieves the tools advertised by an agent and resolves them against the built-in tool registry to extract metadata (description, input/output schemas). Displays each tool's full reference, description, and JSON schemas.

Human output prints a header naming the agent, then for each tool:

- Tool name, version, and description (e.g. `run_tests@1.0.0 (Executes test suite)`)
- `input:` line with the tool's input schema (JSON)
- `output:` line with the tool's output schema (JSON)

If no tools are advertised, prints `(no tools advertised)`.

With `--json`, returns an `AgentTools` object containing:

- `agent_id`, `kind`, `status`
- `capabilities` (array)
- `tools` (array of tool references, e.g. `["run_tests@1.0.0"]`)
- `schemas` (array of `ToolSchema` objects, each with `name`, `version`, `description`, `input_schema`, `output_schema`, and `qualified_ref()` method)

**Prerequisites**

- Daemon must be running
- CLI must be authenticated
- Caller must be a member of the workspace room

**Exit codes**

0 on success; 1 on authentication failure, invalid room, or IPC error; 3 if the agent is not found.

**Examples**

```bash
# List tools for an agent
mx-agent agent tools --room '#my-workspace:matrix.org' --agent-id alice-DEVICE01

# Get JSON output for tooling integration
mx-agent agent tools --room '#project:matrix.org' --agent-id my-agent --json
```

**Notes**

- Tool references are resolved against the built-in tool registry; if a tool is not found in the registry, it is listed in the `tools` array but not in `schemas`.
- Schemas are displayed as raw JSON; callers must parse them to extract validation rules or parameter documentation.
- The `--json` output includes both the advertised references and the resolved schemas, allowing callers to handle missing tools gracefully.
- Tool registration is part of `agent register`; tools are not separately installable at runtime in the current alpha.

## `call` — Invoke a named tool on a remote agent

Synchronously invoke a named tool on a local or remote agent and wait for the result. Local daemon-mediated by default (loopback execution on the local daemon); becomes signed Matrix-backed remote when both `--room` and `--agent` target a registered remote agent. Receiver enforces verify -> trust -> policy(allow_tools) -> approval gates before execution.

| Subcommand | Purpose |
|---|---|
| (direct invocation) | Call a named tool with key=value arguments or JSON input |

### `mx-agent call`

Invoke a named tool on a local or remote agent and wait for completion.

**Synopsis**

```text
mx-agent [GLOBAL] call [OPTIONS]
```

**Options**

| Option | Value | Required | Default | Description |
|---|---|---|---|---|
| `--room` | `<ROOM>` | No | — | Workspace room alias (`#name:server`) or room ID (`!id:server`). Required for remote agent targeting; omit for local loopback. |
| `--agent` | `<AGENT>` | No | — | Target agent identifier. Required for remote agent targeting; omit for local loopback. |
| `--tool` | `<TOOL>` | Yes | — | Named tool to invoke, e.g. `run_tests`. |
| `--arg` | `<KEY=VALUE>` | No | — | Tool argument as a `key=value` pair (repeatable). Mutually exclusive with `--input-json`. |
| `--input-json` | `<FILE>` | No | — | Read the tool input as a JSON object from this file; `-` reads from stdin. Mutually exclusive with `--arg`. |

**Behavior**

Invokes the named tool with the supplied input and waits for completion. When `--room` and `--agent` are both omitted, the daemon executes the tool locally (loopback mode via the built-in tool executor). When both are provided, the daemon sends a signed call request to the remote agent over the Matrix transport; the receiver verifies the signature, checks the local trust store, applies policy, optionally prompts for approval, and executes if all gates pass.

Tool input is built from either `--arg` key=value pairs (combined into a JSON object) or from `--input-json` (a file containing a JSON object). An empty input is `{}`. The tool runs in the daemon's execution context (local) or the remote agent's execution context (remote).

The tool may exit with any code 0-255; a tool that runs and exits nonzero is a successful invocation (exit code is propagated). Only a failure to invoke the tool (unknown tool, invalid schema, spawn failure, or remote rejection) yields an `Error` outcome.

**Output**

Human mode (success): `mx-agent: <summary>` to stdout.

Human mode (error): `mx-agent: <error message>` to stderr.

`--json` output (on success):

```json
{"exit_code": <i32>, "summary": "<string>"}
```

`--json` output (on error):

```json
{"ok": false, "error": "<message>"}
```

**Exit codes**

| Code | Meaning |
|---:|---|
| 0 | Tool succeeded (exit code 0) |
| 1-255 | Tool exited with that code |
| 64 | Invalid input: `--tool` missing, `--input-json` and `--arg` both provided, or tool input schema violation |
| 127 | Tool not found or program executable not found on the daemon/agent host |
| 128 | Protocol/spawn/remote failure (e.g. invocation spawn failed, remote rejected, policy denied, approval denied) |

**Examples**

Local loopback execution (built-in tool):

```bash
mx-agent call --tool run_tests --arg package=api --arg coverage=true
```

Remote agent execution with key=value arguments:

```bash
mx-agent call \
  --room '!abc123:matrix.org' \
  --agent developer-pi \
  --tool run_tests \
  --arg package=api \
  --arg coverage=true
```

Remote agent execution with JSON input file and machine-readable output:

```bash
mx-agent call \
  --room '!abc123:matrix.org' \
  --agent developer-pi \
  --tool run_tests \
  --input-json tests.request.json \
  --json
```

JSON input from stdin:

```bash
echo '{"package":"api","coverage":true}' | mx-agent call \
  --room '!abc123:matrix.org' \
  --agent developer-pi \
  --tool run_tests \
  --input-json -
```

**Notes**

- The CLI is stateless; the daemon owns the Matrix client, signing key, policy, and trust context. Only the daemon can execute tools or send signed remote requests.
- Tools are the safer default compared to raw shell execution (`exec`); they enforce input schemas and avoid shell injection.
- Local loopback execution runs built-in tools immediately; remote execution over Matrix is asynchronous and may be held pending approval.
- For signed Matrix-backed remote calls, the receiver verifies the Ed25519 request signature and checks the local trust store and policy before executing; room membership alone grants no execution rights.
- Large artifacts (> 256 KiB) landing in future releases will be uploaded to Matrix media and referenced via `mxc://` URIs.
- If the tool consumes stdin (e.g. for a prompt), stdin is not forwarded; use `exec --stdin` for bidirectional I/O.

## `exec` — Run a command on a remote agent

Executes a command on a local or remote agent, capturing its output as a structured stream of stdout/stderr chunks ending with a terminal frame carrying the exit status. Local execution is the default; with `--room` and `--agent`, the command becomes a signed, Matrix-backed remote operation routed through the trust and approval pipeline. The daemon (not the CLI) owns process supervision, policy enforcement, and the Matrix client.

| Subcommand | Purpose |
|---|---|
| `mx-agent exec` | Run a command locally or remotely |

### `mx-agent exec`

Run a command on a local or remote agent.

**Synopsis**

```text
mx-agent [GLOBAL] exec [OPTIONS] -- <COMMAND>...
```

**Options**

| Option | Value | Required | Default | Description |
|---|---|---|---|---|
| `--room` | `<ROOM>` | No | None | Workspace room alias (`#name:server`) or room ID (`!id:server`) to target for a remote execution. If omitted, exec runs locally. |
| `--agent` | `<AGENT>` | No | None | Target agent name. Required if `--room` is specified. |
| `--cwd` | `<PATH>` | No | Current directory | Working directory for the command. |
| `--task` | `<TASK_ID>` | No | None | Associate the execution with a task ID for tracking in the distributed task DAG. |
| `--stream` | — | No | false | Request streamed stdout/stderr capture. The flag is forwarded to the daemon (it influences chunk flushing on the daemon/remote streaming paths). Note: the direct CLI `exec` path buffers the output frames and renders them after the command finishes — its loopback frame source runs the command in one shot — so for live interactive I/O use `--pty`. |
| `--strict-stream` | — | No | false | Hard-fail (exit 132) if the output stream has missing or corrupt chunks instead of continuing best-effort. A missing chunk (one that fails integrity validation or cannot be decoded) becomes fatal. |
| `--pty` | — | No | false | Allocate a pseudo-terminal (Unix only). The CLI puts the local terminal into raw mode and forwards keystrokes and window-resize signals live to the remote PTY. Interactive only; incompatible with piped stdin for non-PTY mode. |
| `--stdin` | — | No | false | (Loopback) Forward piped stdin to the command if detected. In PTY mode, stdin is always forwarded. Note: stdin is auto-detected; this flag is reserved for future use. |
| `<COMMAND>` | Command argv after `--` | Yes | — | The command to run and its arguments, provided after the `--` separator. |

**Behavior**

When `--room` and `--agent` are omitted, the command runs in the daemon's local process supervisor (loopback). The daemon sends all stdout/stderr as a sequence of `StreamChunk` frames (utf-8 or base64 encoded) followed by an `ExecFinished` frame carrying the exit status. The CLI renders these frames to its own stdout/stderr in real time.

When `--room` and `--agent` are specified, the command becomes a signed, Matrix-backed remote execution. The CLI sends the request through the daemon, which verifies the signature, checks the trust store (deny-by-default), optionally gates on verified device status, and optionally routes through the approval pipeline before spawning. The receiver-side daemon runs the command and streams frames back.

**Output (human mode):**

- Stdout and stderr are rendered directly to the terminal.
- If output is large (> 256 KiB), it is uploaded as a SHA-256 artifact and referenced by a `mxc://` URI with a 4 KiB tail preview.
- A degraded stream (missing chunks in best-effort mode) triggers a warning: `mx-agent: warning: output was degraded (N chunk(s) missing)`.
- In strict mode, a missing or invalid chunk prints `mx-agent: error: stream integrity check failed (strict mode)` and exits 132.

**Exit codes**

| Code | Meaning |
|---|---|
| 0 | Command succeeded (exit 0). |
| 1–127 | Remote command's exit code (passed through). |
| 127 | Command or working directory not found (`ExecErrorKind::NotFound`). |
| 128 | Stream protocol failure: stream ended without an `exec.finished` frame. |
| 128+*n* | Remote process was killed by signal *n* (e.g., 130 = SIGINT = 2, 143 = SIGTERM = 15). |
| 132 | Stream integrity violation in strict mode (`--strict-stream`): a chunk was missing or failed validation (bad encoding or sha256 mismatch). |
| 64 | Input validation error: empty command, bad `--cwd` path, or daemon IPC failure. |
| 3 | Daemon not running (when `--pty` fails to connect to the daemon socket). |

**Examples**

```bash
# Run a local command
mx-agent exec -- ls -la /home
```

```bash
# Run a command on a remote agent in a workspace room with live output
mx-agent exec --room '#workspace:example.com' --agent alice -- cargo build --release
```

```bash
# Run with strict output validation and a task association
mx-agent exec --room '#workspace:example.com' --agent alice --strict-stream --task task_abc123 -- ./deploy.sh
```

```bash
# Interactive PTY session on a remote agent
mx-agent exec --room '#workspace:example.com' --agent bob --pty -- bash
```

```bash
# Pipe input and capture output
mx-agent exec --cwd /tmp -- python3 -c "import sys; print(sys.stdin.read())" < input.txt
```

**Notes**

- **Streaming vs batch:** the direct CLI `exec` renders captured frames after the command completes (its loopback frame source runs the command in one shot); `--stream` is forwarded to the daemon and shapes daemon/remote-side chunk flushing. Use `--pty` for live interactive I/O.
- **PTY semantics:** `--pty` is Unix-only. The CLI forwards Ctrl-C and other signals as if connected directly; the remote PTY behaves like a local terminal.
- **Large output:** Exec output larger than 256 KiB is automatically uploaded to a Matrix media artifact; the CLI receives a reference URI and a 4 KiB tail for preview.
- **Strict mode:** `--strict-stream` is useful for audit trails (e.g., build logs); degraded output (default) is suitable for interactive use.
- **Task integration:** `--task` links the invocation to a scheduled task's DAG; the daemon records the invocation ID on the task state and can thus trace execution lineage.
- **Confidentiality:** Remote exec is **Ed25519-signed** for integrity and authenticity, and the receiver authorizes it (verify → trust store → deny-by-default policy → optional verified-device and approval gates). It is **not** end-to-end encrypted in this alpha: the workspace room is created with encryption disabled (see [`workspace create`](#mx-agent-workspace-create) above), so the command line, stdin, and captured output transit as cleartext Matrix timeline events **readable by the homeserver operator**. Confidentiality from the homeserver is not provided until workspace E2EE lands (#249; see [`docs/architecture.md`](architecture.md)).
- **Restart durability:** a command held for approval survives a daemon restart — the approval queue is persisted (`approvals.json`). In-flight output of a running command is not guaranteed to survive a restart.
- **Policy enforcement:** Remote exec checks `policy.toml` (`allow_commands` glob and `deny_args_regex`), optional verified-device gates, and optional approval before spawning.
- **Stdin detection:** In non-PTY mode, stdin is auto-detected from `IsTerminal`; piped input is buffered and forwarded automatically. The `--stdin` flag is reserved for future use.

## `share` — Broadcast context (diffs, environment, files)

Share files, diffs, and environment metadata with a workspace room. The daemon broadcasts the payload as a Matrix timeline event (or media for large payloads). Requires authentication and a joined workspace room. All share operations are daemon-mediated over IPC.

| Subcommand | Purpose |
|---|---|
| `file` | Share a typed payload (JSON, binary, text, etc.) read from stdin. |
| `diff` | Capture and share the current git diff (unified or stat format). |
| `env` | Collect and share environment metadata (Node.js, npm, OS, git versions). |
| `list` | List recently shared context artifacts in a workspace room. |
| `get` | Retrieve and verify a shared context artifact by its context ID. |

### `mx-agent share file`

Share a typed payload read from stdin.

**Synopsis**

```text
mx-agent [GLOBAL] share file --room <ROOM> [--type <MIME>] --name <NAME>
```

**Options**

| Option | Value | Required | Default | Description |
|---|---|---|---|---|
| `--room` | `<ROOM>` | Yes | — | Workspace room alias (`#name:server`) or room ID (`!id:server`). |
| `--type` | `<MIME>` | No | `application/octet-stream` | MIME type of the payload (e.g. `application/json`, `text/plain`). |
| `--name` | `<NAME>` | Yes | — | Object name to record with the share (e.g. `plan.json`, `output.txt`). |

**Behavior**
Reads the payload from stdin (pipe or redirect). If stdin is a terminal and not redirected, exits with code 64 ("no input"). The daemon uploads the payload to the room as either inline state (small payloads) or Matrix media (large payloads > 256 KiB). On success, prints the context share in human-readable format (name, context_id, MIME type, size, SHA-256 digest) or as a JSON `ContextShare` object under `--json`.

**Exit codes**

| Code | Meaning |
|---|---|
| 0 | Success. |
| 1 | Daemon IPC error, authentication failure, or room membership error. |
| 3 | Daemon not running. |
| 64 | Input error: stdin is a terminal (no piped input). |

**Examples**

```bash
# Share a JSON plan file
cat plan.json | mx-agent share file --room '#project:matrix.org' --type application/json --name plan.json

# Share raw binary data
tar czf - . | mx-agent share file --room '!roomid:server' --type application/gzip --name archive.tar.gz

# Share as JSON with metadata
echo '{"status":"complete"}' | mx-agent share file --room '#work:example.com' --type application/json --name status.json --json
```

**Notes**

- Payloads over 256 KiB are automatically offloaded to Matrix media (mxc://) to avoid bloating room state.
- Shares transit an **unencrypted** workspace room in this alpha and are readable by the homeserver operator; room-wide E2EE is tracked by #249 (see [`docs/architecture.md`](architecture.md)). Payloads are integrity-checked via their recorded SHA-256 digest.
- The context_id is sortable (ulid format, e.g. `ctx_01HZ...`) and can be used with `share get` to retrieve the artifact later.

---

### `mx-agent share diff`

Capture and share the current git diff.

**Synopsis**

```text
mx-agent [GLOBAL] share diff --room <ROOM> [--base <REV>] [--format <FORMAT>]
```

**Options**

| Option | Value | Required | Default | Description |
|---|---|---|---|---|
| `--room` | `<ROOM>` | Yes | — | Workspace room alias (`#name:server`) or room ID (`!id:server`). |
| `--base` | `<REV>` | No | unstaged working-tree diff | Git revision to diff against (e.g. `main`, `HEAD`, `origin/main`). |
| `--format` | `unified\|stat` | No | `unified` | Diff output format: `unified` (full diff) or `stat` (summary of changed files). |

**Behavior**
Runs `git diff` (unstaged changes) or `git diff <REV>` (against a base revision). Captures the output and uploads it as a shared context artifact. On success, prints the context share metadata or as JSON under `--json`.

**Exit codes**

| Code | Meaning |
|---|---|
| 0 | Success. |
| 1 | Daemon IPC error, git execution error, or room membership error. |
| 3 | Daemon not running. |

**Examples**

```bash
# Share unstaged working-tree diff (git diff)
mx-agent share diff --room '#project:matrix.org'

# Share diff against main branch
mx-agent share diff --room '#project:matrix.org' --base main

# Share diff as stat summary
mx-agent share diff --room '#project:matrix.org' --base HEAD --format stat

# Get diff as JSON output
mx-agent share diff --room '#project:matrix.org' --json
```

**Notes**

- Requires a git repository in the current working directory or a parent.
- If no `--base` is provided, shows unstaged changes only (equivalent to `git diff`).
- Large diffs (> 256 KiB) are stored as media; the room state includes a 4 KiB tail preview.

---

### `mx-agent share env`

Collect and share environment metadata.

**Synopsis**

```text
mx-agent [GLOBAL] share env --room <ROOM> [--include <FACTS>]
```

**Options**

| Option | Value | Required | Default | Description |
|---|---|---|---|---|
| `--room` | `<ROOM>` | Yes | — | Workspace room alias (`#name:server`) or room ID (`!id:server`). |
| `--include` | `<FACTS>` | No | `node,npm,os,git` | Comma-separated facts to include (e.g. `node,npm,os,git,python,rust`). |

**Behavior**
Gathers environment information (Node.js version, npm version, OS info, git version, etc. as specified by `--include`), formats it as JSON, and uploads it as a shared context. Useful for agents to broadcast runtime capabilities and toolchain versions. On success, prints the context share metadata.

**Exit codes**

| Code | Meaning |
|---|---|
| 0 | Success. |
| 1 | Daemon IPC error, environment collection error, or room membership error. |
| 3 | Daemon not running. |

**Examples**

```bash
# Share default environment facts (node, npm, os, git)
mx-agent share env --room '#project:matrix.org'

# Share only Node.js and npm versions
mx-agent share env --room '#project:matrix.org' --include node,npm

# Share extended toolchain info
mx-agent share env --room '#project:matrix.org' --include node,npm,python,rust,os,git

# Get environment as JSON
mx-agent share env --room '#project:matrix.org' --json
```

**Notes**

- The default fact set is: `node`, `npm`, `os`, `git`.
- Fact names are case-sensitive and tool-defined; unknown facts are ignored or skipped.
- Environment info is useful for cross-agent discovery and compatibility checks.

---

### `mx-agent share list`

List recently shared context in a room.

**Synopsis**

```text
mx-agent [GLOBAL] share list --room <ROOM> [--limit <N>]
```

**Options**

| Option | Value | Required | Default | Description |
|---|---|---|---|---|
| `--room` | `<ROOM>` | Yes | — | Workspace room alias (`#name:server`) or room ID (`!id:server`). |
| `--limit` | `<N>` | No | `50` | Maximum number of recent timeline events to scan (higher = older shares included). |

**Behavior**
Scans the room timeline (up to `--limit` events) for shared context artifacts and prints a summary. Each share shows its context_id, name, size (bytes), MIME type, and SHA-256 digest. Under `--json`, returns an array of `ContextShare` objects.

**Exit codes**

| Code | Meaning |
|---|---|
| 0 | Success. |
| 1 | Daemon IPC error or room membership error. |
| 3 | Daemon not running. |

**Examples**

```bash
# List recent shares (up to 50 events)
mx-agent share list --room '#project:matrix.org'

# List more context (scan up to 200 events)
mx-agent share list --room '#project:matrix.org' --limit 200

# Get shares as JSON array
mx-agent share list --room '#project:matrix.org' --json
```

**Notes**

- The limit controls how far back in the room timeline to scan; higher limits may take longer for large rooms.
- Shares are listed in reverse chronological order (most recent first, by room timeline insertion order).
- This is a read-only operation and does not verify artifact integrity.

---

### `mx-agent share get`

Retrieve and verify a shared context artifact by ID.

**Synopsis**

```text
mx-agent [GLOBAL] share get --room <ROOM> --context-id <CONTEXT_ID> [--output <PATH>] [--limit <N>]
```

**Options**

| Option | Value | Required | Default | Description |
|---|---|---|---|---|
| `--room` | `<ROOM>` | Yes | — | Workspace room alias (`#name:server`) or room ID (`!id:server`). |
| `--context-id` | `<CONTEXT_ID>` | Yes | — | Context ID of the share to retrieve (e.g. `ctx_01HZ...`). |
| `--output` | `<PATH>` | No | — | Write the verified artifact to this file; if omitted, output to stdout. |
| `--limit` | `<N>` | No | `100` | Maximum number of recent timeline events to scan when locating the share. |

**Behavior**
Scans the room timeline for the specified `context_id`, downloads and verifies the artifact against its SHA-256 digest, and either writes it to `--output` or stdout. The artifact payload is emitted raw (binary-safe). When writing to a file, share metadata is printed to stderr (or stdout as JSON under `--json`) to avoid corrupting the payload. When writing to stdout, metadata goes to stderr.

**Exit codes**

| Code | Meaning |
|---|---|
| 0 | Success (artifact verified and retrieved). |
| 1 | Daemon IPC error, artifact not found, verification failure, or room membership error. |
| 3 | Daemon not running. |

**Examples**

```bash
# Retrieve and print artifact to stdout
mx-agent share get --room '#project:matrix.org' --context-id ctx_01HZ6QN2A7K

# Retrieve and save to a file
mx-agent share get --room '#project:matrix.org' --context-id ctx_01HZ6QN2A7K --output /tmp/artifact.json

# Retrieve with extended timeline scan
mx-agent share get --room '#project:matrix.org' --context-id ctx_01HZ6QN2A7K --limit 500

# Get as JSON (with metadata on stdout)
mx-agent share get --room '#project:matrix.org' --context-id ctx_01HZ6QN2A7K --json 2>/dev/null
```

**Notes**

- SHA-256 verification is mandatory; a corrupted or tampered artifact will cause the command to fail.
- Large artifacts (> 256 KiB) are stored as Matrix media; the daemon fetches them from the homeserver's media repository.
- The `--limit` controls the timeline scan depth; if the context_id is not found within this range, the command fails with exit code 1.
- Artifact data is always binary-safe; text encoding is preserved but not validated.

## `task` — Manage the distributed task DAG

Tasks are durable, Matrix-backed DAG nodes in a workspace room. Each task carries an optional structured action (tool invocation or exec command) and state lifecycle. The daemon mediates all task operations via IPC, requiring authentication and workspace room membership. Tasks can depend on and block each other; the scheduler respects dependencies before auto-execution.

| Subcommand | Purpose |
|---|---|
| `create` | Create a new task in a workspace room |
| `update` | Update task metadata, state, action, or link an invocation |
| `list` | List tasks in a workspace, optionally filtered by state or assignment |
| `graph` | Render the task dependency DAG and report diagnostics (cycles, conflicts) |
| `watch` | Stream live task state changes (Ctrl-C to stop) |
| `cancel` | Cancel a task and its linked invocation |

### `mx-agent task create`

Create a new task in a workspace room.

**Synopsis**

```text
mx-agent [GLOBAL] task create --room <ROOM> --title <TITLE>
  [--id <TASK_ID>]
  [--description <DESCRIPTION>]
  [--state <STATE>]
  [--assign <AGENT>]
  [--depends-on <TASK_ID>...]
  [--blocks <TASK_ID>...]
  [--tool <TOOL> [--arg KEY=VALUE...] [--input-json <FILE>]]
  [--exec [--cwd <PATH>] [--timeout-ms <MS>] [--stream] -- <COMMAND>...]
```

**Options**

| Option | Value | Required | Default | Description |
|---|---|---|---|---|
| `<ROOM>` | `--room <ROOM>` | yes | — | Workspace room alias (`#name:server`) or room ID (`!id:server`) |
| `<TITLE>` | `--title <TITLE>` | yes | — | Human-readable task title |
| `--id` | `<TASK_ID>` | no | generated `task_...` | Explicit task ID (state key); if omitted, a sortable ID is generated |
| `--description` | `<DESCRIPTION>` | no | empty string | Longer task description |
| `--state` | `<STATE>` | no | `pending` | Initial lifecycle state (`proposed`, `pending`, `assigned`, `executing`, `succeeded`, `failed`, `cancelled`, `blocked`, `superseded`) |
| `--assign` | `<AGENT>` | no | empty (unassigned) | Agent ID to assign the task to |
| `--depends-on` | `<TASK_ID>` | no | none | Upstream task this depends on (repeatable); scheduler will not run this until dependencies succeed |
| `--blocks` | `<TASK_ID>` | no | none | Downstream task blocked by this one (repeatable) |
| `--tool` | `<TOOL>` | no | none | Named tool to invoke (e.g., `run_tests`, `format_code`); mutually exclusive with `--exec` |
| `--arg` | `KEY=VALUE` | no | none | Tool argument as `key=value` pair (repeatable); requires `--tool` |
| `--input-json` | `<FILE>` | no | none | Read tool input as a JSON object from this file or `-` for stdin; mutually exclusive with `--arg` |
| `--exec` | — | no | false | Attach an exec-style command action; mutually exclusive with `--tool` |
| `--cwd` | `<PATH>` | no | `.` (exec only) | Working directory for the exec command; requires `--exec` |
| `--timeout-ms` | `<MS>` | no | none (exec only) | Timeout in milliseconds for exec; requires `--exec` |
| `--stream` | — | no | false (exec only) | Request streamed output for exec; requires `--exec` |
| `<COMMAND>` | command after `--` | no | none (if `--exec` given) | Exec command and arguments; must come after `--` and requires `--exec` |

**Behavior**

Creates a new task in the specified workspace room with a unique task ID (auto-generated unless `--id` is provided). The task is published as a `com.mxagent.task.v1` state event keyed by task ID. All task operations require daemon IPC connectivity and prior Matrix authentication.

A task action is either optional (manual/planning task) or one of:

- **Tool action**: invokes a named, policy-controlled tool via the daemon with arguments supplied as `--arg KEY=VALUE` pairs or as a JSON object via `--input-json`
- **Exec action**: runs a shell command with optional timeout and streaming; only local execution is supported at create time

The task begins in the specified `--state` (default `pending`). If `--assign` is provided, the task starts assigned; otherwise it is unassigned. Dependencies and blocking relationships are recorded but not validated at creation time.

Human output prints `created task <ID>` followed by a compact summary (ID, state, title, assignment, dependencies, action, revision). JSON output returns the full `TaskState` object with all fields.

**Exit codes**

| Code | Reason |
|---|---|
| 0 | Task created successfully |
| 1 | General failure (IPC error, daemon-side error, invalid action) |
| 3 | Daemon not running or unreachable |
| 64 | Bad arguments (invalid state, conflicting action flags, malformed JSON, invalid command) |

**Examples**

```bash
# Create a simple pending task
mx-agent task create --room '#project:server' --title 'Fix logging'

# Create and assign a task with a tool action
mx-agent task create --room '#project:server' \
  --title 'Run tests' \
  --assign alice-dev \
  --tool run_tests --arg suite=unit

# Create a task with an exec action and dependency
mx-agent task create --room '#project:server' \
  --title 'Build distribution' \
  --depends-on task_001 \
  --exec --timeout-ms 60000 --stream -- npm run build

# Create with JSON tool input
mx-agent task create --room '#project:server' \
  --title 'Custom analysis' \
  --tool analyze --input-json params.json
```

**Notes**

- Task IDs must be unique within a room; `--id` should follow URI-friendly conventions (alphanumeric, `-`, `_`).
- A task without an action (no `--tool` or `--exec`) is a manual/planning task and will never be auto-executed by the scheduler.
- Tool and exec actions are advisory; the daemon's policy and trust store determine whether they are actually executable.
- Output larger than 256 KiB is offloaded to a SHA-256 mxc:// artifact with a 4 KiB tail preview.
- Tasks are durable across daemon restarts (persisted in the Matrix room).

---

### `mx-agent task update`

Update task metadata, state, action, or link an invocation.

**Synopsis**

```text
mx-agent [GLOBAL] task update --room <ROOM> <TASK_ID>
  [--state <STATE>]
  [--assign <AGENT>]
  [--title <TITLE>]
  [--description <DESCRIPTION>]
  [--invocation <INVOCATION_ID>]
  [--expected-state-rev <REV>]
  [--tool <TOOL> [--arg KEY=VALUE...] [--input-json <FILE>]]
  [--exec [--cwd <PATH>] [--timeout-ms <MS>] [--stream] -- <COMMAND>...]
```

**Options**

| Option | Value | Required | Default | Description |
|---|---|---|---|---|
| `--room` | `<ROOM>` | yes | — | Workspace room alias (`#name:server`) or room ID (`!id:server`) |
| `<TASK_ID>` | task ID (positional) | yes | — | Task ID (state key) to update |
| `--state` | `<STATE>` | no | none (unchanged) | New lifecycle state; must be a valid transition from current state |
| `--assign` | `<AGENT>` | no | none (unchanged) | Reassign the task to a different agent |
| `--title` | `<TITLE>` | no | none (unchanged) | New title |
| `--description` | `<DESCRIPTION>` | no | none (unchanged) | New description |
| `--invocation` | `<INVOCATION_ID>` | no | none (unchanged) | Associate this task with a running invocation ID |
| `--expected-state-rev` | `<REV>` | no | none (optimistic concurrency disabled) | Only apply the update if the task's `state_rev` matches this value; reject if stale to prevent race conditions |
| `--tool` | `<TOOL>` | no | none (unchanged) | Replace the task action with a new tool action; mutually exclusive with `--exec` |
| `--arg` | `KEY=VALUE` | no | none | Tool argument (repeatable); requires `--tool` |
| `--input-json` | `<FILE>` | no | none | Read tool input as JSON from file or `-` (stdin); requires `--tool` |
| `--exec` | — | no | false | Replace the task action with an exec action; mutually exclusive with `--tool` |
| `--cwd` | `<PATH>` | no | `.` (exec only) | Working directory for exec; requires `--exec` |
| `--timeout-ms` | `<MS>` | no | none (exec only) | Timeout in milliseconds; requires `--exec` |
| `--stream` | — | no | false (exec only) | Request streamed output; requires `--exec` |
| `<COMMAND>` | command after `--` | no | none (if `--exec` given) | Exec command and arguments; must come after `--` and requires `--exec` |

**Behavior**

Updates an existing task identified by `<TASK_ID>`. Only the specified fields are modified; omitted options leave the task unchanged. State transitions are validated against the task lifecycle rules (e.g., executing tasks cannot move to pending, and terminal states cannot transition to any other state).

If `--expected-state-rev` is provided, the update is applied only if the task's current `state_rev` matches; this provides optimistic concurrency control. A mismatch rejects the update as stale (exit 1) to prevent race conditions in distributed workflows.

Task actions can be replaced independently: providing `--tool` (with arguments) or `--exec` (with command) replaces the entire action payload. The daemon validates state transitions and action compatibility before publishing the update to the room.

Human output prints `updated task <ID>` followed by the updated task summary. JSON output returns the full `TaskState` object.

**Exit codes**

| Code | Reason |
|---|---|
| 0 | Task updated successfully |
| 1 | General failure (invalid transition, state mismatch, stale `--expected-state-rev`, IPC error) |
| 3 | Daemon not running or unreachable |
| 64 | Bad arguments (invalid state, conflicting action flags, malformed JSON) |

**Examples**

```bash
# Transition a task to executing
mx-agent task update --room '#project:server' task_001 --state executing

# Reassign and update the title
mx-agent task update --room '#project:server' task_001 \
  --assign bob-agent \
  --title 'Refactored logging implementation'

# Update state with optimistic concurrency check
mx-agent task update --room '#project:server' task_001 \
  --state succeeded \
  --expected-state-rev 2

# Replace the action with a new tool invocation
mx-agent task update --room '#project:server' task_001 \
  --tool lint --arg style=prettier

# Replace the action with an exec command
mx-agent task update --room '#project:server' task_001 \
  --exec --timeout-ms 120000 -- make test
```

**Notes**

- Task state transitions are subject to the lifecycle rules defined in the architecture; not all transitions are allowed (e.g., terminal states never transition).
- The `--expected-state-rev` field prevents "lost updates" in concurrent scenarios; if omitted, the update is applied unconditionally.
- Updating a task action does not automatically cancel any linked invocation; use `task cancel` to terminate a running invocation.

---

### `mx-agent task list`

List tasks in a workspace, optionally filtered by state or assignment.

**Synopsis**

```text
mx-agent [GLOBAL] task list --room <ROOM>
  [--state <STATE>]
  [--assigned <AGENT>]
```

**Options**

| Option | Value | Required | Default | Description |
|---|---|---|---|---|
| `--room` | `<ROOM>` | yes | — | Workspace room alias (`#name:server`) or room ID (`!id:server`) |
| `--state` | `<STATE>` | no | none (all states) | Filter to tasks in this lifecycle state only |
| `--assigned` | `<AGENT>` | no | none (all assignments) | Filter to tasks assigned to this agent only |

**Behavior**

Queries all tasks in the specified room and returns them in creation order. Optional filters narrow the result set:

- `--state` returns only tasks in that state (e.g., `pending`, `executing`, `succeeded`)
- `--assigned` returns only tasks assigned to a specific agent

Human output prints a count and a compact per-task summary (ID, state, title, optional assignment, dependencies, invocation, action details, and state revision). JSON output returns an array of `TaskState` objects with all fields.

**Exit codes**

| Code | Reason |
|---|---|
| 0 | Successfully listed tasks (may be empty) |
| 1 | General failure (IPC error, daemon-side error) |
| 3 | Daemon not running or unreachable |

**Examples**

```bash
# List all tasks in a room
mx-agent task list --room '#project:server'

# List only pending tasks
mx-agent task list --room '#project:server' --state pending

# List tasks assigned to a specific agent
mx-agent task list --room '#project:server' --assigned alice-dev

# Combine filters
mx-agent task list --room '#project:server' \
  --state executing --assigned bob-agent

# Retrieve as JSON for programmatic processing
mx-agent task list --room '#project:server' --json | jq '.[] | .task_id'
```

**Notes**

- The room must exist and the user must be a member; membership is validated by the daemon.
- Empty results return a count message (0 tasks) with no further output.
- Large task lists (>100) may be slow to retrieve due to Matrix timeline scanning; consider using filters to narrow scope.

---

### `mx-agent task graph`

Render the task dependency DAG and report diagnostics (cycles, conflicts).

**Synopsis**

```text
mx-agent [GLOBAL] task graph --room <ROOM>
```

**Options**

| Option | Value | Required | Default | Description |
|---|---|---|---|---|
| `--room` | `<ROOM>` | yes | — | Workspace room alias (`#name:server`) or room ID (`!id:server`) |

**Behavior**

Fetches all tasks in the room and renders their dependency DAG as human-readable ASCII art or structured JSON. Analyzes the graph for diagnostic warnings:

- **Cycles**: circular dependencies that would deadlock the scheduler
- **Dangling references**: tasks that depend on or block non-existent tasks
- **Invalid actions**: tasks with conflicting or incomplete action payloads

Human output renders a stylized graph visualization with node and edge labels, followed by a warnings section listing each detected issue with task ID, warning kind, and detailed message. JSON output returns a structured `TaskGraph` object with `nodes`, `edges`, and `warnings` arrays.

**Exit codes**

| Code | Reason |
|---|---|
| 0 | Graph rendered successfully (warnings, if any, are informational) |
| 1 | General failure (IPC error, daemon-side error) |
| 3 | Daemon not running or unreachable |

**Examples**

```bash
# Render the task DAG
mx-agent task graph --room '#project:server'

# Retrieve as JSON for analysis
mx-agent task graph --room '#project:server' --json | jq '.warnings'
```

**Notes**

- The graph is a snapshot of current room state; it reflects the latest committed task mutations visible to the daemon.
- Warnings do not block task execution; they are diagnostic hints for the operator. Use them to debug workflow issues.
- Large graphs (>50 nodes) may render slowly due to layout computation.

---

### `mx-agent task watch`

Stream live task state changes (Ctrl-C to stop).

**Synopsis**

```text
mx-agent [GLOBAL] task watch --room <ROOM>
  [--state <STATE>]
  [--assigned <AGENT>]
```

**Options**

| Option | Value | Required | Default | Description |
|---|---|---|---|---|
| `--room` | `<ROOM>` | yes | — | Workspace room alias (`#name:server`) or room ID (`!id:server`) |
| `--state` | `<STATE>` | no | none (all states) | Watch only tasks in this lifecycle state |
| `--assigned` | `<AGENT>` | no | none (all assignments) | Watch only tasks assigned to this agent |

**Behavior**

Opens a persistent IPC connection to the daemon and streams live task state updates. The command renders an initial snapshot of matching tasks, then emits change notifications as tasks are created, updated, or removed. Filters narrow the task set:

- `--state` watches only tasks in that state
- `--assigned` watches only tasks assigned to a specific agent

Filters are evaluated on the initial snapshot; subsequent updates that match the criterion are streamed. If a task state changes to exclude it from the filter, it is reported as removed.

Human output renders the initial task list followed by incremental change lines prefixed with `+` (added), `-` (removed), or `~` (updated). State transitions are highlighted (e.g., `executing -> succeeded`). JSON output emits two event types:

- `"initial"`: includes the initial task list
- `"changed"`: includes an array of change objects with `task_id`, `kind` (`Added`/`Removed`/`Updated`), and field-level details

The command runs until interrupted (Ctrl-C), at which point it exits cleanly.

**Exit codes**

| Code | Reason |
|---|---|
| 0 | Watch stopped cleanly (Ctrl-C) |
| 1 | General failure (IPC error, daemon-side error, stream corruption) |
| 3 | Daemon not running or unreachable |

**Examples**

```bash
# Watch all task changes
mx-agent task watch --room '#project:server'

# Watch only pending tasks
mx-agent task watch --room '#project:server' --state pending

# Watch tasks assigned to an agent
mx-agent task watch --room '#project:server' --assigned alice-dev

# Stream to a file (Ctrl-C to stop)
mx-agent task watch --room '#project:server' > task_log.txt &

# Watch in JSON mode for downstream processing
mx-agent task watch --room '#project:server' --json | jq '.changes'
```

**Notes**

- Watch uses a streaming IPC connection; the daemon maintains the subscription state.
- Network interruptions or daemon crashes cause watch to exit with exit code 1.
- The command reconnects automatically up to a configurable limit; reconnection attempts are logged to stderr.
- Large, frequently-mutated task lists may produce high I/O volume; consider using filters to reduce noise.

---

### `mx-agent task cancel`

Cancel a task and its linked invocation.

**Synopsis**

```text
mx-agent [GLOBAL] task cancel --room <ROOM> <TASK_ID>
  [--reason <REASON>]
```

**Options**

| Option | Value | Required | Default | Description |
|---|---|---|---|---|
| `--room` | `<ROOM>` | yes | — | Workspace room alias (`#name:server`) or room ID (`!id:server`) |
| `<TASK_ID>` | task ID (positional) | yes | — | Task ID (state key) to cancel |
| `--reason` | `<REASON>` | no | `cancelled by operator` | Human-readable reason for cancellation |

**Behavior**

Cancels a task and drives the lifecycle transition to `cancelled`. If the task has a linked invocation (via `--invocation`), the daemon signs a cancellation request and sends it to the target agent, which then terminates the running command. The reason is recorded in the cancellation event and may be audited.

If the task is already in a terminal state (succeeded, failed, cancelled, superseded), the operation succeeds but reports that there was nothing to cancel; the task state is unchanged.

Human output prints either `cancelled task <ID>` (if a cancellation occurred) or a note that the task was already finished. JSON output returns the final `TaskState` object regardless.

**Exit codes**

| Code | Reason |
|---|---|
| 0 | Task cancelled or already terminal |
| 1 | General failure (IPC error, daemon-side error) |
| 3 | Daemon not running or unreachable |

**Examples**

```bash
# Cancel a task with a default reason
mx-agent task cancel --room '#project:server' task_001

# Cancel with a custom reason
mx-agent task cancel --room '#project:server' task_001 \
  --reason 'User requested cancellation due to resource constraints'

# Cancel in JSON mode
mx-agent task cancel --room '#project:server' task_001 --json
```

**Notes**

- Cancellation drives both the task state and any linked invocation to `cancelled`; the daemon uses its signing key to authenticate the cancellation to the target agent.
- If a task has no linked invocation, only the task state is updated; no agent communication occurs.
- Terminal tasks cannot transition to any other state; calling cancel on a succeeded task is a no-op.
- Cancellation reasons are logged and auditable; use them to record intent.

## `invocation` — Inspect and cancel running invocations

Invocations are remote agent executions initiated by `call` or `exec` commands. The `invocation` group allows operators to list, inspect, cancel, and retrieve output artifacts from running or finished invocations in a workspace room. All commands require daemon IPC contact and a valid room identity. Output artifacts (stdout, stderr, pty) are transparently decompressed and SHA-256 verified before delivery.

| Subcommand | Purpose |
|---|---|
| `list` | List invocations in a room, optionally filtered by state or task ID |
| `show` | Display a single invocation's full state |
| `cancel` | Terminate a running invocation with an operator reason |
| `artifact` | Retrieve, verify, and decompress an invocation's captured output stream |

### `mx-agent invocation list`

List invocations in a workspace room, optionally filtered by lifecycle state or task association.

**Synopsis**

```text
mx-agent [GLOBAL] invocation list --room <ROOM> [--state <STATE>] [--task <TASK_ID>]
```

**Options**

| Option | Value | Required | Default | Description |
|---|---|---|---|---|
| `--room` | `<ROOM>` | yes | — | Workspace room alias (`#name:server`) or room ID (`!id:server`) |
| `--state` | `<STATE>` | no | — | Only list invocations in this lifecycle state (e.g., `running`, `succeeded`, `failed`, `cancelled`) |
| `--task` | `<TASK_ID>` | no | — | Only list invocations linked to this task ID |

**Behavior**

Queries the daemon for invocations in the specified room, applying optional filters. In human mode, prints a count and a summary line per invocation showing ID, state, requester agent, and target agent; optional task ID and exit code follow. In `--json` mode, outputs an array of `InvocationState` objects with fields: `invocation_id`, `task_id` (optional), `requester`, `target`, `state`, `created_at`, `updated_at`, `exit_code` (optional), `state_rev`, and forward-compatible extra fields.

**Exit codes**

- `0` — Success
- `1` — IPC request failed or daemon rejected request
- `3` — Daemon not running or unreachable

**Examples**

```bash
# List all invocations in a room
mx-agent invocation list --room '#workspace:example.com'

# List only running invocations
mx-agent invocation list --room '#workspace:example.com' --state running

# List invocations linked to a task
mx-agent invocation list --room '#workspace:example.com' --task task_12345

# Machine-readable output
mx-agent invocation list --room '!abc:example.com' --json
```

**Notes**

Filters are applied cumulatively; specifying both `--state` and `--task` lists invocations matching both conditions. Empty results print a user-facing message in human mode and an empty array in JSON mode.

### `mx-agent invocation show`

Display the full state of a single invocation.

**Synopsis**

```text
mx-agent [GLOBAL] invocation show --room <ROOM> <INVOCATION_ID>
```

**Options**

| Option | Value | Required | Default | Description |
|---|---|---|---|---|
| `--room` | `<ROOM>` | yes | — | Workspace room alias (`#name:server`) or room ID (`!id:server`) |
| `<INVOCATION_ID>` | — | yes | — | Invocation ID (state key) to show |

**Behavior**

Retrieves and displays a single invocation's state from the room timeline. In human mode, prints the invocation summary (ID, state, requester, target) followed by optional fields (task ID, exit code, state revision). In `--json` mode, outputs the `InvocationState` object with all fields. If the invocation is not found, an error message is printed and exit code 1 is returned.

**Exit codes**

- `0` — Success; invocation found and displayed
- `1` — Invocation not found, IPC request failed, or daemon rejected request
- `3` — Daemon not running or unreachable

**Examples**

```bash
# Show a specific invocation
mx-agent invocation show --room '#workspace:example.com' inv_01HZ

# JSON output for scripting
mx-agent invocation show --room '!abc:example.com' inv_01HZ --json
```

**Notes**

The invocation state includes the `state_rev` counter, which increments on each update. This can be useful for polling-based workflows to detect state changes.

### `mx-agent invocation cancel`

Terminate a running invocation with an operator-provided reason.

**Synopsis**

```text
mx-agent [GLOBAL] invocation cancel --room <ROOM> [--reason <REASON>] <INVOCATION_ID>
```

**Options**

| Option | Value | Required | Default | Description |
|---|---|---|---|---|
| `--room` | `<ROOM>` | yes | — | Workspace room alias (`#name:server`) or room ID (`!id:server`) |
| `--reason` | `<REASON>` | no | `cancelled by operator` | Human-readable reason recorded with the cancellation |
| `<INVOCATION_ID>` | — | yes | — | Invocation ID (state key) to cancel |

**Behavior**

Sends a cancellation request to the daemon, which signs it (using the local signing key) and broadcasts it to the target agent over the room timeline. The target agent verifies the signature and applies the cancellation policy (verify sender → local trust store → deny-by-default policy.toml → optional approval gate → terminate process). In human mode, if cancellation succeeds, prints a confirmation and the updated invocation state; if the invocation had already finished, prints a message indicating its final state. In `--json` mode, outputs the updated `InvocationState` object. A successful cancellation sets the invocation state to `cancelled`.

**Exit codes**

- `0` — Success; cancellation request sent and processed
- `1` — IPC request failed, daemon rejected request, or invocation not found
- `3` — Daemon not running or unreachable

**Examples**

```bash
# Cancel an invocation with default reason
mx-agent invocation cancel --room '#workspace:example.com' inv_01HZ

# Cancel with a custom reason
mx-agent invocation cancel --room '#workspace:example.com' --reason 'User request; manual timeout' inv_01HZ

# JSON output
mx-agent invocation cancel --room '!abc:example.com' inv_01HZ --json
```

**Notes**

The cancellation is signed by the daemon and verified by the target agent. Room membership alone does not grant cancellation authority; the target agent's policy may require approval or device verification. Once sent, the cancellation reason is recorded in the invocation state for audit purposes. If the invocation has already finished (succeeded, failed, or cancelled), the cancellation is a no-op and the existing state is returned.

### `mx-agent invocation artifact`

Retrieve, verify, and decompress an invocation's captured output stream.

**Synopsis**

```text
mx-agent [GLOBAL] invocation artifact --room <ROOM> [--stream <STREAM>] [--output <PATH>] [--limit <N>] <INVOCATION_ID>
```

**Options**

| Option | Value | Required | Default | Description |
|---|---|---|---|---|
| `--room` | `<ROOM>` | yes | — | Workspace room alias (`#name:server`) or room ID (`!id:server`) |
| `--stream` | `stdout \| stderr \| pty` | no | `stdout` | Which captured stream to retrieve |
| `--output` | `<PATH>` | no | — | Write the verified artifact to this file instead of stdout |
| `--limit` | `<N>` | no | `100` | Maximum number of recent timeline events to scan when locating the artifact |
| `<INVOCATION_ID>` | — | yes | — | Invocation ID whose output artifact to retrieve |

**Behavior**

Retrieves a stream artifact from the room timeline. If the output was small enough to stream as timeline chunks, the artifact is reconstructed from those chunks; if it exceeded the per-stream budget (256 KiB by default), it was uploaded as a Matrix media object and a single `com.mxagent.stream.artifact.v1` event references it. The daemon downloads (if needed), decompresses (zstd or uncompressed), and SHA-256 verifies the artifact before delivery.

Raw artifact bytes are written to the output file (if `--output` is specified) or stdout. Metadata is handled as follows: when `--output` is specified, metadata goes to stdout in JSON mode and stderr in human mode; when artifact is written to stdout (no `--output`), metadata always goes to stderr, even in JSON mode, to avoid corrupting binary output when piped.

If `--stream pty` is specified and the invocation used interactive PTY mode, the captured PTY output (including terminal control sequences) is retrieved. If no artifact is found after scanning the specified number of timeline events, an error is returned with exit code 1.

**Exit codes**

- `0` — Success; artifact retrieved, verified, and written
- `1` — Artifact not found, verification failed, IPC request failed, or write error
- `3` — Daemon not running or unreachable

**Examples**

```bash
# Retrieve stdout artifact and print to stdout
mx-agent invocation artifact --room '#workspace:example.com' inv_01HZ

# Save stderr to a file
mx-agent invocation artifact --room '#workspace:example.com' --stream stderr --output logs/error.log inv_01HZ

# Retrieve PTY output
mx-agent invocation artifact --room '#workspace:example.com' --stream pty inv_01HZ

# Increase timeline scan depth
mx-agent invocation artifact --room '#workspace:example.com' --limit 200 inv_01HZ

# Get metadata in JSON (artifact to stdout)
mx-agent invocation artifact --room '#workspace:example.com' inv_01HZ --json
```

**Notes**

Artifacts may be compressed with zstd (if available on the hosting agent) to reduce media storage. The daemon transparently decompresses and verifies the SHA-256 digest before returning. The `--limit` parameter controls how far back in the timeline to search; increase it if artifacts are old or the room is very active. Artifact metadata includes a tail preview (last 4 KiB of uncompressed output by default), shown in timeline events for quick inspection without downloading the full log. Large artifacts are automatically offloaded to media (mxc://) if output exceeds 256 KiB per stream.

The artifact metadata object contains the following fields: `invocation_id`, `stream`, `name`, `mime_type`, `size_bytes`, `sha256`, `mxc_uri`, `tail_preview`.

## `approval` — Review and decide pending approval requests

The `approval` command group manages requests queued for interactive human (or agent) decision when a policy rule marks a privileged operation with `requires_approval`. All operations read from the durable local queue (`approvals.json` in the daemon's data directory, persisted with `0600` permissions). Only the `approve` and `deny` subcommands require the daemon running and authentication; `list` and `show` work entirely from the local queue.

| Subcommand | Purpose |
|---|---|
| `list` | List all pending approval requests, optionally filtered by workspace room |
| `show` | Display a single approval request by ID |
| `approve` | Approve a held request so the underlying command may proceed |
| `deny` | Deny a held request so the command never executes |

### `mx-agent approval list`

List pending approval requests from the local queue, optionally scoped to a single workspace room.

**Synopsis**

```text
mx-agent [GLOBAL] approval list [--room <ROOM>]
```

**Options**

| Option | Value | Required | Default | Description |
|---|---|---|---|---|
| `--room` | `<ROOM>` | No | (all rooms) | Filter to approvals queued for this workspace room (room ID or alias) |

**Behavior**

Reads the durable local approval queue and displays pending requests in human-readable format (default) or as a JSON array (`--json`). The queue is stored at `$MX_AGENT_DATA_DIR/approvals.json` and survives daemon restarts. Output is sorted by `request_id` for deterministic results.

Human output shows:

- Count of pending approvals (or "no pending approvals" message)
- For each request: `request_id`, `risk` level, `requester` and `target` agents, invocation ID, room, human-readable command summary, and expiry timestamp

JSON output is an array of `PendingApproval` objects, each with:

- `room_id`: Matrix room ID the request was raised in
- `request`: the `ApprovalRequest` content (request_id, invocation_id, requester, target, summary, risk, expires_at)

**Exit codes**

0 on success (includes the "no pending approvals" case); 1 on file read errors.

**Examples**

```bash
# List all pending approvals across all rooms
mx-agent approval list

# Show only approvals for a specific workspace room
mx-agent approval list --room '!abc:example.org'

# Output as JSON for integration
mx-agent approval list --json
```

**Notes**

This command does not require the daemon to be running or the user to be authenticated; it reads only the local queue file. Useful for offline approval auditing or integration with external approval systems.

---

### `mx-agent approval show`

Display the full details of a single pending approval request.

**Synopsis**

```text
mx-agent [GLOBAL] approval show <REQUEST_ID>
```

**Options**

| Option | Value | Required | Default | Description |
|---|---|---|---|---|
| `<REQUEST_ID>` | string | Yes | — | Unique identifier of the approval request to retrieve |

**Behavior**

Looks up a single pending approval by `request_id` in the local queue and prints its details. Human output is the same format as individual entries from `approval list`. JSON output is a single `PendingApproval` object.

Returns exit code 1 and an error message if the request is not found in the queue.

**Exit codes**

0 on success; 1 if the request_id is not found or the queue file cannot be read.

**Examples**

```bash
# Show a specific approval request
mx-agent approval show req_01HZ5V

# Output as JSON
mx-agent approval show req_01HZ5V --json
```

**Notes**

Like `approval list`, this does not require the daemon or authentication and reads only the local queue.

---

### `mx-agent approval approve`

Approve a held request so the underlying operation may proceed.

**Synopsis**

```text
mx-agent [GLOBAL] approval approve <REQUEST_ID> [--by <IDENTITY>]
```

**Options**

| Option | Value | Required | Default | Description |
|---|---|---|---|---|
| `<REQUEST_ID>` | string | Yes | — | Unique identifier of the approval request to approve |
| `--by` | `<IDENTITY>` | No | logged-in user | Matrix user ID (e.g., `@alice:example.org`) to record as the decision-maker; daemon uses its own user ID if omitted |

**Behavior**

Emits a `com.mxagent.approval.decision.v1` event into the room where the request was raised, recording the approval decision and decision-maker identity. The request is then removed from the local queue. The operation is mediated over the daemon IPC channel (JSON-RPC 2.0) and requires the daemon to be running and authenticated.

Human output: "mx-agent: approved approval request {request_id} in {room_id}"

JSON output is the `ApprovalDecision` object that was emitted, with fields:

- `request_id`: the approved request
- `decision`: the string `"approved"`
- `approved_by`: the identity that made the decision
- `created_at`: RFC 3339 UTC timestamp

**Exit codes**

0 on success; 1 if the daemon cannot be reached, the request is not found in the queue, or the decision event fails to emit; 3 if the daemon is not running (IPC connection error).

**Examples**

```bash
# Approve a request as the logged-in user (daemon resolves the identity)
mx-agent approval approve req_01HZ5V

# Approve and explicitly record a different user as the decision-maker
mx-agent approval approve req_01HZ5V --by '@supervisor:example.org'

# Output the decision event as JSON
mx-agent approval approve req_01HZ5V --json
```

**Notes**

- **Daemon required:** The daemon must be running (`mx-agent daemon start`) and the user must be authenticated (`mx-agent auth login`).
- **Idempotent queue:** If the same request is approved twice, the second approval is still emitted but removes the request from the queue only once; further attempts fail with "request not found".
- **Matrix publication:** The decision is published into the workspace room so other agents and observers can see it. The decision survives daemon restarts (it is part of the Matrix timeline) but is not duplicated in the local queue.
- **Fail-closed scheduling:** Only an explicit `approved` decision lets a held task proceed; any other decision (or absence of a decision) keeps it indefinitely held.

---

### `mx-agent approval deny`

Deny a held request so the underlying operation never executes.

**Synopsis**

```text
mx-agent [GLOBAL] approval deny <REQUEST_ID> [--by <IDENTITY>]
```

**Options**

| Option | Value | Required | Default | Description |
|---|---|---|---|---|
| `<REQUEST_ID>` | string | Yes | — | Unique identifier of the approval request to deny |
| `--by` | `<IDENTITY>` | No | logged-in user | Matrix user ID (e.g., `@alice:example.org`) to record as the decision-maker; daemon uses its own user ID if omitted |

**Behavior**

Emits a `com.mxagent.approval.decision.v1` event into the request's room, recording a denial decision. The request is removed from the local queue. Like `approve`, this is mediated over the daemon IPC channel and requires the daemon to be running and authenticated.

Human output: "mx-agent: denied approval request {request_id} in {room_id}"

JSON output is the `ApprovalDecision` object with:

- `request_id`: the denied request
- `decision`: the string `"denied"` (or any non-`"approved"` value)
- `approved_by`: the identity that made the decision
- `created_at`: RFC 3339 UTC timestamp

**Exit codes**

0 on success; 1 if the daemon cannot be reached, the request is not found, or the decision event fails to emit; 3 if the daemon is not running.

**Examples**

```bash
# Deny a request as the logged-in user
mx-agent approval deny req_01HZ5V

# Deny and explicitly record a supervisor's rejection
mx-agent approval deny req_01HZ5V --by '@supervisor:example.org'

# Output the decision event as JSON
mx-agent approval deny req_01HZ5V --json
```

**Notes**

- **Daemon required:** Like `approve`, this requires the daemon to be running and the user authenticated.
- **Permanent rejection:** A denied request may not be re-approved. If needed, the underlying command must be re-submitted as a new request with a new `request_id`.
- **Fail-closed gate:** Only `decision == "approved"` permits the held operation to proceed; a denial (or any other value, including an unrecognized string) causes the scheduler to reject the task permanently without spawning it.

## `trust` — Manage local and published trust for remote agents

The trust system manages cryptographic signing keys for remote agents. Local trust decisions (approve/revoke) control whether a key can authorize privileged Matrix-backed operations in any room. The CLI operates on the local trust store directly (no daemon required) for list/fingerprint/approve/revoke; `publish` and `state` operations are daemon-mediated and require authentication and a workspace room.

| Subcommand | Purpose |
|---|---|
| `list` | List approved and revoked keys from the local trust store |
| `fingerprint` | Print the local daemon's signing key fingerprint |
| `approve` | Approve an agent signing key in the local trust store |
| `revoke` | Revoke an approved agent signing key |
| `publish` | Publish a local trust record to a workspace room as room state |
| `state` | Inspect trust records published in a room, merged with local store |

### `mx-agent trust list`

List trusted keys from the local trust store with optional agent and room filters.

**Synopsis**

```text
mx-agent [GLOBAL] trust list [--agent <AGENT>] [--room <ROOM>]
```

**Options**

| Option | Value | Required | Default | Description |
|---|---|---|---|---|
| `--agent` | `<AGENT>` | No | — | Filter to this agent identifier |
| `--room` | `<ROOM>` | No | — | Filter to keys scoped to this workspace room |

**Behavior**
Reads the local trust store and lists all entries matching optional filters. In human mode, prints count and formatted details (status, key ID, agent, fingerprint, room, trusted_by, timestamps). With `--json`, outputs an array of TrustEntry objects. Exits 0 even if no keys are found.

**Examples**

```sh
mx-agent trust list
mx-agent trust list --agent alice
mx-agent trust list --room '!abc:example.com' --json
```

**Notes**
No daemon or authentication required. Operates on local store only. Entries can be `trusted` or `revoked`.

---

### `mx-agent trust fingerprint`

Print this daemon's local signing key fingerprint.

**Synopsis**

```text
mx-agent [GLOBAL] trust fingerprint
```

**Options**
None.

**Behavior**
Loads or creates the daemon's Ed25519 signing key on first run. In human mode, prints the fingerprint (`SHA256:<base64>`). With `--json`, outputs an object with `alg` (algorithm), `key_id` (`mxagent-ed25519:<base64>`), and `fingerprint` fields.

**Examples**

```sh
mx-agent trust fingerprint
mx-agent trust fingerprint --json
```

**Notes**
No daemon or authentication required. The fingerprint is stable across daemon restarts. Used to identify the local daemon in trust conversations with other agents.

---

### `mx-agent trust approve`

Approve an agent signing key in the local trust store.

**Synopsis**

```text
mx-agent [GLOBAL] trust approve --agent <AGENT> --key <KEY> [--room <ROOM>] [--fingerprint <FINGERPRINT>]
```

**Options**

| Option | Value | Required | Default | Description |
|---|---|---|---|---|
| `--agent` | `<AGENT>` | Yes | — | Agent identifier the key belongs to |
| `--key` | `<KEY>` | Yes | — | Signing key identifier (`mxagent-ed25519:<base64>`) |
| `--room` | `<ROOM>` | No | — | Scope the trust to this workspace room |
| `--fingerprint` | `<FINGERPRINT>` | No | Derived from key ID | Key fingerprint (`SHA256:<base64>`) |

**Behavior**
Adds or updates a trust entry in the local store, marking the key as `trusted`. If `--fingerprint` is omitted, it is derived from the key ID. In human mode, prints "approved key for agent X" and the formatted entry details. With `--json`, outputs the TrustEntry object. Creates the store if it does not exist.

**Examples**

```sh
mx-agent trust approve --agent alice --key 'mxagent-ed25519:wJ0w...' --room '!abc:example.com'
mx-agent trust approve --agent bob --key 'mxagent-ed25519:xK1v...' --fingerprint 'SHA256:+bCd...'
mx-agent trust approve --agent carol --key 'mxagent-ed25519:yZ2m...' --json
```

**Notes**
No daemon or authentication required. Operates on local store only. Does not validate the key format; provide a valid base64-encoded Ed25519 key to avoid unexpected behavior.

---

### `mx-agent trust revoke`

Revoke an approved agent signing key.

**Synopsis**

```text
mx-agent [GLOBAL] trust revoke --agent <AGENT> --key <KEY>
```

**Options**

| Option | Value | Required | Default | Description |
|---|---|---|---|---|
| `--agent` | `<AGENT>` | Yes | — | Agent identifier the key belongs to |
| `--key` | `<KEY>` | Yes | — | Signing key identifier (`mxagent-ed25519:<base64>`) |

**Behavior**
Revokes a previously approved key in the local store, marking it as `revoked`. If no record exists for the agent-key pair, prints an error and exits 3. In human mode, prints "revoked key for agent X" and the formatted entry. With `--json`, outputs the TrustEntry object (or `null` if not found).

**Exit codes**

- 3: No trust record exists for the given agent and key.

**Examples**

```sh
mx-agent trust revoke --agent alice --key 'mxagent-ed25519:wJ0w...'
mx-agent trust revoke --agent bob --key 'mxagent-ed25519:xK1v...' --json
```

**Notes**
No daemon or authentication required. Operates on local store only. Revocation is permanent but non-destructive (the entry is retained with a `revoked_at` timestamp).

---

### `mx-agent trust publish`

Publish a local trust record to a workspace room as room state.

**Synopsis**

```text
mx-agent [GLOBAL] trust publish --room <ROOM> --agent <AGENT> --key <KEY>
```

**Options**

| Option | Value | Required | Default | Description |
|---|---|---|---|---|
| `--room` | `<ROOM>` | Yes | — | Workspace room ID to publish to |
| `--agent` | `<AGENT>` | Yes | — | Agent identifier the key belongs to |
| `--key` | `<KEY>` | Yes | — | Signing key identifier (`mxagent-ed25519:<base64>`) |

**Behavior**
Publishes the local trust record as a Matrix room state event (`com.mxagent.trust.v1`). The record must already exist in the local store; publication is purely advisory and never changes local trust decisions. Requires daemon to be running and user to be authenticated and joined to the room. In human mode, prints confirmation and the published TrustState details. With `--json`, outputs the TrustState object.

**Prerequisites**

- Daemon running.
- User authenticated (`auth status` shows a session).
- User joined to the target workspace room.

**Exit codes**

- 3: No local trust record exists for the given agent and key, or daemon is not running.
- 1: Daemon rejected the request (authentication failed, room membership issue, etc.).

**Examples**

```sh
mx-agent trust publish --room '!abc:example.com' --agent alice --key 'mxagent-ed25519:wJ0w...'
mx-agent trust publish --room '!xyz:example.com' --agent bob --key 'mxagent-ed25519:xK1v...' --json
```

**Notes**
Published trust is not enforced locally; the local store is always the final authority. Remote agents in the room can see the published record to build their own trust decision. E2E encrypted state is not yet supported in the Matrix spec; published trust may be visible to room moderators.

---

### `mx-agent trust state`

Inspect trust records published in a workspace room.

**Synopsis**

```text
mx-agent [GLOBAL] trust state --room <ROOM> [--agent <AGENT>]
```

**Options**

| Option | Value | Required | Default | Description |
|---|---|---|---|---|
| `--room` | `<ROOM>` | Yes | — | Workspace room ID to read published trust from |
| `--agent` | `<AGENT>` | No | — | Filter to this agent identifier |

**Behavior**
Fetches published trust records from the room and reconciles them with the local store. Outputs both the published records and an "effective trust" table that combines room state with local store decisions (local always wins; a local revocation overrides any room-published trust). In human mode, prints the published records, then the effective trust table. With `--json`, outputs an object with `published` (array of TrustState) and `effective` (array with `agent_id`, `key_id`, `trusted`, `source` fields).

**Prerequisites**

- Daemon running.
- User authenticated.
- User joined to the target workspace room.

**Exit codes**

- 3: Daemon is not running.
- 1: Daemon rejected the request (authentication failed, room membership issue, etc.).

**Examples**

```sh
mx-agent trust state --room '!abc:example.com'
mx-agent trust state --room '!abc:example.com' --agent alice --json
```

**Notes**
Local revocations override published trust; a key revoked locally will show as `untrusted` in the effective table even if published as trusted. The `source` field in `--json` output indicates whether the effective decision came from `local` store or `published` room state. E2EE constraints apply as above.

## `device` — Inspect and verify peer Matrix devices (E2EE transport identity)

The `device` group manages Matrix device verification and inspection. These commands are daemon-mediated; the daemon owns the Matrix session and E2EE state, and the CLI receives only non-secret fingerprints and verification status over IPC. Requires the daemon to be running and the operator to be authenticated.

| Subcommand | Purpose |
|---|---|
| `list` | List Matrix devices with verification status and fingerprints |
| `show` | Display details for a single peer device |
| `verify` | Verify a peer device using interactive emoji/SAS or out-of-band fingerprint comparison |

### `mx-agent device list`

List Matrix devices with verification status and fingerprints.

**Synopsis**

```text
mx-agent [GLOBAL] device list [--room <ROOM>] [--user <USER>]
```

**Options**

| Option | Value | Required | Default | Description |
|---|---|---|---|---|
| `--room` | `<ROOM>` | No | — | Workspace room alias or ID; lists devices of all joined members |
| `--user` | `<USER>` | No | daemon's own user | Specific Matrix user ID to list devices for |

**Behavior**

Lists all known Matrix devices for the target user(s). When `--room` is given, retrieves device information for all members currently joined to that room. When `--user` is given, lists only that user's devices. If neither is supplied, defaults to the daemon's own user's devices.

Human output prints one device per line with verification status (`unverified`, `verified`, `verified (cross-signed)`, or `blacklisted`), followed by optional display name and fingerprint lines.

With `--json`, returns an array of device objects. Each object contains `user_id`, `device_id`, optional `display_name`, optional `ed25519_fingerprint` (public device key as `ed25519:<base64>`), `verified` (boolean), `cross_signed` (boolean), `blacklisted` (boolean), and `locally_trusted` (boolean).

**Exit codes**

- 0: success
- 1: daemon unavailable, IPC error, authentication failed, or room/user not found
- 3: daemon not running

**Examples**

```bash
# List the daemon's own devices
mx-agent device list

# List devices of all members in a workspace
mx-agent device list --room '#project:example.com'

# List devices of a specific peer
mx-agent device list --user '@alice:example.com'

# Get device list as JSON for automation
mx-agent --json device list --user '@bob:example.com'
```

**Notes**

- Device verification status is an **advisory E2EE transport signal**; it does not authorize execution on its own. Signed agent requests remain gated by local trust store + policy.toml.
- The `ed25519_fingerprint` is the device's **public Matrix E2EE key**, distinct from the mx-agent Ed25519 signing-key fingerprint (`SHA256:…`).

### `mx-agent device show`

Display details for a single peer device.

**Synopsis**

```text
mx-agent [GLOBAL] device show --user <USER> --device <DEVICE>
```

**Options**

| Option | Value | Required | Default | Description |
|---|---|---|---|---|
| `--user` | `<USER>` | Yes | — | Owning Matrix user ID |
| `--device` | `<DEVICE>` | Yes | — | Matrix device ID |

**Behavior**

Retrieves detailed information for one specific device owned by the given user. The daemon syncs with the homeserver to fetch the latest device state.

Human output prints the device's user ID, device ID, and verification status on the first line, followed by optional display name and fingerprint lines.

With `--json`, returns a single device object with fields: `user_id`, `device_id`, optional `display_name`, optional `ed25519_fingerprint`, `verified`, `cross_signed`, `blacklisted`, and `locally_trusted`.

**Exit codes**

- 0: success
- 1: daemon unavailable, IPC error, or authentication failed
- 3: daemon not running or device not found

**Examples**

```bash
# Show details of a specific device
mx-agent device show --user '@alice:example.com' --device 'ABCDEFGHIJ'

# Get device details as JSON
mx-agent --json device show --user '@peer:example.com' --device 'GHIJKLMNOP'
```

**Notes**

- Exit code 3 signals device not found or daemon unavailable.

### `mx-agent device verify`

Verify a peer device using interactive emoji/SAS or out-of-band fingerprint comparison.

**Synopsis**

```text
mx-agent [GLOBAL] device verify --user <USER> --device <DEVICE> [--manual] [--fingerprint <FINGERPRINT>]
```

**Options**

| Option | Value | Required | Default | Description |
|---|---|---|---|---|
| `--user` | `<USER>` | Yes | — | Peer Matrix user ID to verify with |
| `--device` | `<DEVICE>` | Yes | — | Peer Matrix device ID to verify |
| `--manual` | — | No | false | Verify out-of-band by fingerprint instead of interactive SAS |
| `--fingerprint` | `<FINGERPRINT>` | No | — | Expected `ed25519:<base64>` device fingerprint (optional with `--manual`) |

**Behavior**

Verifies a peer's device using one of two flows:

**Interactive emoji/SAS (default):** Initiates a real-time verification flow with the peer device. The daemon and peer exchange a short-authentication string as emoji symbols and decimal fallback. The operator compares these out-of-band with the peer and confirms or cancels on stdin (prompted `Do these match on the peer device? [y/N]:` on stderr). Frames are streamed over a held-open IPC connection; human mode prints status messages and the SAS to stderr, `--json` mode emits `DeviceVerifyFrame` events (one per line).

**Out-of-band fingerprint (with `--manual`):** Verifies the device using a pre-shared or externally-verified fingerprint. When `--fingerprint` is provided, the daemon confirms the device's public key matches before marking it verified. When omitted, the operator asserts they have confirmed the fingerprint themselves.

On success, the device is marked verified locally; this status is persisted in the daemon's crypto store and survives restarts.

With `--json`, interactive mode emits a stream of frame objects with `event` field: `started` (flow initiated), `emoji-ready` (SAS ready; contains `emoji` array of `{symbol, description}` and/or `decimals` tuple), `confirmed` (verification succeeded), `cancelled` (cancelled by either side), or `error` (flow failed with a non-secret message).

**Exit codes**

- 0: verification succeeded
- 1: daemon unavailable, IPC error, authentication failed, or verification failed
- 3: daemon not running

**Examples**

```bash
# Interactive emoji/SAS verification
mx-agent device verify --user '@alice:example.com' --device 'ABCDEFGHIJ'
# Prompts: "Do these match on the peer device? [y/N]:"

# Out-of-band fingerprint verification (fingerprint confirmed externally)
mx-agent device verify --user '@alice:example.com' --device 'ABCDEFGHIJ' --manual

# Out-of-band with explicit fingerprint check
mx-agent device verify --user '@alice:example.com' --device 'ABCDEFGHIJ' --manual \
  --fingerprint 'ed25519:AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOp'

# Stream verification frames as JSON for UI integration
mx-agent --json device verify --user '@bob:example.com' --device 'GHIJKLMNOP'
```

**Notes**

- Device verification is an **advisory E2EE transport signal** only; it does not authorize privileged execution. Signed agent requests remain gated by local trust store + policy.
- The daemon owns all Matrix E2EE state; the CLI never sees private key material.
- Interactive verification requires the peer to be online and accept the verification request.
- Verified devices persist in the daemon's crypto store (`$MX_AGENT_DATA_DIR`); the status survives daemon restarts.
- The `ed25519_fingerprint` is the device's **public Matrix E2EE key**, not the mx-agent signing key.

## `recovery` — Manage server-side key backup and recovery

Provisions Secure Secret Storage and server-side key backup on the Matrix homeserver, enabling recovery of cryptographic keys after a device wipe or re-provision. Requires the daemon running and authentication (`mx-agent auth login` first).

| Subcommand | Purpose |
|---|---|
| `enable` | Provision Secure Secret Storage + key backup; generate and print the recovery key once |
| `status` | Show recovery state, backup enablement, and server-side backup status |
| `recover` | Re-import keys from server-side backup using a previously recorded recovery key |

### `mx-agent recovery enable`

Provision Secure Secret Storage and server-side key backup, generating a one-time recovery key.

**Synopsis**

```text
mx-agent [GLOBAL] recovery enable
```

**Options**
None.

**Behavior** — Provisions the Matrix homeserver with Secure Secret Storage (creating the `m.secret_storage.key.ssss_key` account data) and enables automatic key backup. Generates a unique recovery key and prints it to stdout exactly once in human-readable form. The recovery key is the operator's sole secret to record; it is wrapped in a confidential type and never logged. In `--json` mode, outputs a JSON object with `recovery_key` (the generated key string) and `status` fields. Requires the daemon running and the user authenticated; returns error if not logged in.

**Exit codes** — Beyond standard 0/1:

- `1` if not authenticated, daemon unreachable, or Secure Secret Storage provisioning fails.

**Examples**

```bash
# Enable key backup and capture the recovery key
mx-agent recovery enable

# Non-interactive JSON output for automated workflows
mx-agent --json recovery enable | jq -r '.recovery_key' > /secure/location/recovery.key
```

**Notes** — The recovery key is the only mechanism to restore cryptographic keys on a fresh device or after a crypto store wipe. Record it in a secure location (e.g., a password manager, offline storage, or printed). The key is never printed again; if lost, history backed up under it becomes unrecoverable. This is a permanent operation; Secure Secret Storage, once enabled, remains active until manually disabled on the homeserver.

### `mx-agent recovery status`

Show the current recovery and key-backup state.

**Synopsis**

```text
mx-agent [GLOBAL] recovery status
```

**Options**
None.

**Behavior** — Queries the daemon's Matrix session to report the recovery/backup state. In human mode, prints three fields: `state` (one of `unknown`, `enabled`, `disabled`, `incomplete`), `backup_enabled` (whether the daemon is uploading room keys), and `backup_exists_on_server` (whether a key backup version exists on the homeserver). In `--json` mode, outputs those same fields as a JSON object. Requires the daemon running and authentication.

**Exit codes** — Beyond standard 0/1:

- `1` if not authenticated or daemon unreachable.

**Examples**

```bash
# Check recovery status in human format
mx-agent recovery status

# Parse status as JSON
mx-agent --json recovery status | jq '.state'
```

**Notes** — `state: incomplete` typically means Secure Secret Storage was provisioned but key backup has not yet synced to the server; re-run `recovery enable` or wait for the next backup cycle.

### `mx-agent recovery recover`

Re-import cryptographic keys from server-side backup using a recovery key.

**Synopsis**

```text
mx-agent [GLOBAL] recovery recover [--recovery-key <KEY>]
```

**Options**

| Option | Value | Required | Default | Description |
|---|---|---|---|---|
| `--recovery-key` | `<KEY>` | No | — | The recovery key recorded when `recovery enable` was run. If omitted, read from `MX_AGENT_RECOVERY_KEY` environment variable or prompted on stdin. |

**Behavior** — Re-imports cryptographic keys (Megolm session keys and device identity) from the Matrix homeserver's server-side backup, using the operator-supplied recovery key to decrypt them. This is the primary recovery path after a device wipe, crypto store loss, or fresh provision on a new machine. The recovery key can be supplied via flag, environment variable, or interactively via stdin prompt. In human mode, prints "mx-agent: keys re-imported from server-side backup" followed by the recovery status; in `--json` mode, outputs only the status object with `state`, `backup_enabled`, and `backup_exists_on_server` fields. Requires the daemon running and authentication.

**Exit codes** — Beyond standard 0/1:

- `1` if the recovery key is invalid, not provided, or if recovery fails (e.g., no backup exists, network error).

**Examples**

```bash
# Interactive prompt for the recovery key
mx-agent recovery recover

# Provide the recovery key via flag
mx-agent recovery recover --recovery-key "EsTL 1234 5678 ..."

# Non-interactive via environment variable
MX_AGENT_RECOVERY_KEY="EsTL 1234 5678 ..." mx-agent recovery recover

# Recover and verify the status afterward
mx-agent recovery recover --recovery-key "$(cat /secure/recovery.key)" && mx-agent recovery status
```

**Notes** — If the key is incorrect, recovery fails with an error; there is no brute-force protection beyond the homeserver's rate limits. Recovery does not re-authenticate the device; the daemon must already be logged in and the crypto store must be cleared (or empty) for keys to be re-imported. After successful recovery, the daemon may need a brief moment to process the re-imported keys before they are usable in new E2EE rooms.

## Files and directories

### Runtime (socket)

- **Directory**: `$MX_AGENT_RUNTIME_DIR` (env), else `$XDG_RUNTIME_DIR/mx-agent`, else `$TMPDIR/mx-agent`
- **Files**:
  - `daemon.sock` — IPC socket (mode 0600)
  - `daemon.json` — daemon status file (JSON, internally managed)
  - `daemon.log` — background daemon log file

### Config

- **Directory**: `$MX_AGENT_CONFIG_DIR` (env), else `$XDG_CONFIG_HOME/mx-agent`, else `$HOME/.config/mx-agent`
- **Files**:
  - `policy.toml` — deny-by-default policy (required for privileged requests)
  - `audit.log` — append-only JSON audit log (mode 0600, records privileged policy decisions)

### Data

- **Directory**: `$MX_AGENT_DATA_DIR` (env), else `$XDG_DATA_HOME/mx-agent`, else `$HOME/.local/share/mx-agent`, else `$TMPDIR/mx-agent`
- **Files**:
  - `session.json` — Matrix session (mode 0600: user ID, device ID, access/refresh tokens as `Secret`)
  - `sync_token` — latest Matrix `/sync` batch token (plain text)
  - `approvals.json` — durable approval queue (mode 0600, survives restart)
  - `crypto-store/` — persistent, daemon-owned matrix-sdk crypto/state directory (mode 0700). Contains device keys and Megolm sessions; never agent-readable (architecture §13.1, issue #240).
  - `crypto-store-key` — secret passphrase encrypting the crypto store at rest (mode 0600). Generated once on first use and reused across restarts so the daemon resumes as the same E2EE device.

## Environment variables

### User-facing (affect behavior)

- `MX_AGENT_PASSWORD` — non-interactive password for `auth login` (read via stdin if not set)
- `MX_AGENT_RECOVERY_KEY` — fallback recovery key for `recovery recover` (else stdin prompt)
- `MX_AGENT_TASK_DISPATCH` — `local` (default) | `matrix` — route live scheduler task dispatch through the signed Matrix call/exec transport instead of local dispatch
- `MX_AGENT_LOG` — tracing/EnvFilter directive (e.g. `debug`, `mx_agent=trace`); overrides `-v` flag
- `MX_AGENT_LOG_FORMAT` — log output format: `human` (default) | `json`
- `MX_AGENT_CONFIG_DIR` — directory override for config (policy.toml, audit.log)
- `MX_AGENT_DATA_DIR` — directory override for data (session, crypto store, approvals)
- `MX_AGENT_RUNTIME_DIR` — directory override for runtime socket

### Internal (secret, scrubbed from child processes)

- `MX_AGENT_TOKEN` — listed in SECRET_VARS denylist; filtered from exec child environment

## Exit codes

Per crates/mx-agent-cli/src/cli.rs, stream.rs, terminal.rs:

- **0** — success
- **1** — general failure (clap `ExitCode::FAILURE`: daemon-side error, IPC error)
- **3** — negative-status sentinel:
  - `daemon status` when the daemon is not running
  - `auth status` when not authenticated
  - "not found" lookups (device/invocation/etc.)
- **64** — input validation: empty `exec`/`call` command, an unusable `--cwd`, malformed arguments, or an IPC setup failure (`EmptyCommand` / `InvalidArgs`)
- **127** — command, tool, or working directory not found on the target (`ExecErrorKind::NotFound` / `CallErrorKind::NotFound`)
- **128** — `EXIT_PROTOCOL_FAILURE` — an `exec` stream ended without an `exec.finished` frame
- **132** — `EXIT_STREAM_INTEGRITY` — `--strict-stream` and a chunk was missing/corrupt (bad encoding or sha256 mismatch)
- **128 + signum** — `exec` passes the target process's own exit status through (0–255); a process killed by a signal maps to 128+signum per shell convention (e.g. SIGTERM=15 → 143, SIGINT=2 → 130)

> The exact code per command is given in each command's **Exit codes** note above. `exec` is the
> richest case (64/127/128/132 all apply); most other commands return only `0`/`1`, with `3` for the
> status/lookup sentinels noted above.

## Defaults and limits

- `agent --kind=generic` — default agent kind
- `agent --max-invocations=1` — default max concurrent invocations
- Cancel grace period: SIGTERM then 5s then SIGKILL
- Heartbeat emitted every 30s per owned agent
- Exec output larger than 256 KiB is offloaded to a SHA-256 mxc:// artifact with a 4 KiB tail preview
- Default timeline scan limit for retrieval: 100 events (for `invocation artifact`, `share get`)

---

## Configuration: policy.toml

The policy file defines deny-by-default authorization rules for privileged requests. Located at `~/.config/mx-agent/policy.toml` (configurable via `MX_AGENT_CONFIG_DIR`), it is parsed and validated in two stages: TOML deserialization with `deny_unknown_fields`, then semantic validation with precise error paths.

### Example Structure

```toml
[execution]
# Workspace-wide defaults applied when agents do not specify overrides
default_sandbox = "bubblewrap"       # none | bubblewrap | firejail | docker | podman | chroot
network = "deny"                      # allow | deny
read_only_paths = ["/usr", "/bin"]   # Absolute paths; mounted read-only in sandbox
writable_paths = ["/home/me/project"] # Absolute paths; child process may write to these
env_allowlist = ["CARGO_HOME"]        # Additional safe env vars to pass to child (allowlist-based)

[rooms."!abc:matrix.org"]
trusted = true                        # Enable privileged request evaluation in this room
raw_exec_default = "deny"             # allow | deny — default for raw exec when no agent rule matches
require_verified_device = false       # Additive: when true, every agent in room requires device verification

[rooms."!abc:matrix.org".agents."@claude:matrix.org"]
allow_exec = true                     # Permit raw exec for this agent
allow_tools = ["run_tests", "lint"]   # Allowlisted call tool names
allow_commands = ["npm", "pytest"]    # Allowlisted command basenames (raw exec only)
allow_cwd = ["/home/me/project"]      # Absolute paths where commands may run
deny_args_regex = ["rm\\s+-rf", "ssh"] # Deny if any pattern matches argv
max_runtime_ms = 900000               # Wall-clock timeout in milliseconds (must be > 0)
max_output_bytes = 5000000            # Captured output limit in bytes (must be > 0)
requires_approval = false             # Require interactive approval gate
sandbox = "bubblewrap"                # Backend override for this agent
network = "deny"                      # Network policy override for this agent
require_verified_device = false       # When true, Matrix device must be verified to proceed
```

### Field Reference

| Field | Level | Type | Notes |
|-------|-------|------|-------|
| `execution.default_sandbox` | workspace | enum | `none` `bubblewrap` `firejail` `docker` `podman` `chroot` |
| `execution.network` | workspace | enum | `allow` or `deny` |
| `execution.read_only_paths` | workspace | list | Absolute paths; validated |
| `execution.writable_paths` | workspace | list | Absolute paths; validated |
| `execution.env_allowlist` | workspace | list | Env var names; non-empty validated |
| `rooms."ROOM_ID".trusted` | room | bool | Must have Matrix room ID starting with `!` |
| `rooms."ROOM_ID".raw_exec_default` | room | enum | `allow` or `deny`; default when no agent rule applies |
| `rooms."ROOM_ID".require_verified_device` | room | bool | Room-level override for device verification gate |
| `rooms."ROOM_ID".agents."AGENT_ID".allow_exec` | agent | bool | Permit raw `exec` for this agent |
| `rooms."ROOM_ID".agents."AGENT_ID".allow_tools` | agent | list | Tool names; non-empty validated |
| `rooms."ROOM_ID".agents."AGENT_ID".allow_commands` | agent | list | Command basenames; non-empty validated |
| `rooms."ROOM_ID".agents."AGENT_ID".allow_cwd` | agent | list | Absolute paths; validated |
| `rooms."ROOM_ID".agents."AGENT_ID".deny_args_regex` | agent | list | Regex patterns; validated for syntax |
| `rooms."ROOM_ID".agents."AGENT_ID".max_runtime_ms` | agent | u64 | Must be > 0 if set |
| `rooms."ROOM_ID".agents."AGENT_ID".max_output_bytes` | agent | u64 | Must be > 0 if set |
| `rooms."ROOM_ID".agents."AGENT_ID".requires_approval` | agent | bool | Additive gate |
| `rooms."ROOM_ID".agents."AGENT_ID".sandbox` | agent | enum | Overrides `execution.default_sandbox` |
| `rooms."ROOM_ID".agents."AGENT_ID".network` | agent | enum | Overrides `execution.network` |
| `rooms."ROOM_ID".agents."AGENT_ID".require_verified_device` | agent | bool | Additive gate (issue #240) |

> **Implemented backends vs. accepted values.** `policy.toml` *parses* all six `sandbox` /
> `default_sandbox` values, but only `bubblewrap` (Linux) and `docker`/`podman` (the container
> backend) are implemented runners in v0.2.0; `none` is the default fallback and applies no
> isolation. `firejail` and `chroot` are accepted by the parser but are **not** implemented
> backends today. Path/network confinement is enforced end-to-end for **batch** `exec`; interactive
> `--pty` has baseline controls only. (See the sandbox row in the README status matrix.)

### Validation Rules

- Room IDs must start with `!`; agent IDs must start with `@` (Matrix format)
- All absolute paths must be canonically absolute
- `deny_args_regex` values must be valid Rust regex patterns
- `allow_tools` and `allow_commands` must contain non-empty strings
- `max_runtime_ms` and `max_output_bytes` must be > 0 if specified
- Unknown top-level, room, or agent fields are rejected with precise dotted paths (e.g., `rooms."!abc:matrix.org".agents."@a:matrix.org".deny_args_regex[1]`)

---

## Trust Store Format

The trust store (`~/.config/mx-agent/trust.json` in the data directory) is a JSON array of `TrustEntry` objects, persisted with `0600` permissions. Each entry records a single `(agent_id, key_id)` pair, its trust status, and audit metadata.

```json
{
  "entries": [
    {
      "agent_id": "@claude:matrix.org",
      "key_id": "mxagent-ed25519:abc123def456...",
      "fingerprint": "SHA256:abc123def456...",
      "status": "trusted",
      "room": "!abc:matrix.org",
      "trusted_by": "@owner:matrix.org",
      "created_at": 1700000000,
      "revoked_at": null
    }
  ]
}
```

**Key fields:**

- `agent_id`: Matrix user ID of the signer
- `key_id`: Stable identifier `mxagent-ed25519:<base64>`
- `fingerprint`: `SHA256:<base64>` (derived from key_id; optional on load)
- `status`: `"trusted"` or `"revoked"` (revoked keys never authorize requests)
- `room`: Room the key was approved in (optional scope)
- `trusted_by`: Matrix user who approved the key (optional)
- `created_at`: Unix timestamp of approval
- `revoked_at`: Unix timestamp of revocation (null if not revoked)

Unknown and revoked keys return `false` on `is_trusted()` checks. Only keys with `status: "trusted"` authorize privileged requests.

---

## Audit Log Format

The audit log (`~/.config/mx-agent/audit.log`) is newline-delimited JSON, one record per privileged request decision. The file is created with `0600` permissions and appended atomically; logs left loose are re-tightened to `0600` on next write.

```jsonl
{"ts":"2023-11-14T22:13:20Z","room":"!abc:matrix.org","requester":"@claude:matrix.org","target":"developer-pi","invocation_id":"inv_01HZ","request":"exec","command":["cargo","test"],"decision":"allowed","policy_rule":"allow_commands","sandbox":"bubblewrap"}
{"ts":"2023-11-14T22:14:05Z","room":"!abc:matrix.org","requester":"@attacker:matrix.org","target":"developer-pi","request":"exec","command":["rm","-rf","/"],"decision":"denied","policy_rule":"deny:denied_arguments"}
{"ts":"2023-11-14T22:15:00Z","room":"!abc:matrix.org","requester":"@claude:matrix.org","target":"developer-pi","invocation_id":"inv_02HZ","request":"call","tool":"run_tests","decision":"allowed","policy_rule":"allow_tools","sandbox":"none"}
{"ts":"2023-11-14T22:15:30Z","room":"!abc:matrix.org","requester":"@claude:matrix.org","target":"developer-pi","invocation_id":"inv_03HZ","request":"call","tool":"deploy","decision":"denied","policy_rule":"deny:tool_not_allowed"}
```

**Standard fields (all records):**

- `ts`: RFC 3339 UTC timestamp (`YYYY-MM-DDTHH:MM:SSZ`)
- `room`: Matrix room ID request arrived in
- `requester`: Matrix user ID of requesting agent
- `target`: Local target name (agent or session name)
- `request`: `"exec"` or `"call"`
- `decision`: `"allowed"` or `"denied"`
- `policy_rule`: For allowed: `allow_commands`/`allow_tools`; for denied: `deny:REASON` (e.g., `deny:command_not_allowed`, `deny:unverified_device`)

**Conditional fields (omitted when absent):**

- `invocation_id`: Tracking ID if part of an invocation
- `command`: Redacted command argv (exec only; omitted for call)
- `tool`: Tool name (call only; omitted for exec)
- `sandbox`: Backend selected for allowed request (e.g., `"bubblewrap"`, `"none"`); omitted for denied

**Redaction:** Command arguments are redacted before logging using shared sensitive-key rules: inline `KEY=value` and `--key=value` pairs have the value replaced with `REDACTED`, and sensitive flag arguments (e.g., `--token VALUE`) have the value replaced. Secrets in arguments never reach the log.

**Post-policy denials:** Requests denied by gates *after* policy evaluation (e.g., verified-device gate, issue #240) are recorded as denied with `policy_rule: "deny:GATE_NAME"` and `sandbox: null`, identical to policy denials.

**Deny reason codes:** `deny:unknown_room`, `deny:untrusted_room`, `deny:unknown_agent`, `deny:empty_command`, `deny:exec_not_allowed`, `deny:command_not_allowed`, `deny:cwd_not_allowed`, `deny:denied_arguments`, `deny:tool_not_allowed`, `deny:unverified_device` (and other post-policy gates).

## JSON output

Every command accepts the global `--json` flag and emits a single JSON value on stdout:

- **Read commands** (`*list`, `*show`, `*status`, `agent tools`, `task graph`, `trust state`)
  return an object or array describing the queried state.

- **Mutating commands** (`*create`, `*update`, `*approve`, `trust approve`, etc.) return an
  object describing the resulting record (IDs, lifecycle state, `state_rev`).

- **`exec`/`call`** stream rendered output to stdout/stderr as usual; `--json` reports the
  structured result envelope (exit status, captured-output/artifact references).

The exact field set per command is given in that command's **Behavior** note above. The JSON
shape tracks the protocol schema (`com.mxagent.*`) and should be treated as **alpha-stable**:
prefer addressing fields by name and tolerate additions.

## Shell completions and man pages

`mx-agent` can emit shell completion scripts and `roff` man pages from its own command tree
(generated by `clap_complete`/`clap_mangen`, so they never drift from the binary). These are
produced by a hidden `generate` command — tooling for packagers, not part of the day-to-day
surface, so it does not appear in `--help`.

```bash
# Shell completions (bash | zsh | fish | elvish | powershell) to stdout:
mx-agent generate completions bash  > /usr/share/bash-completion/completions/mx-agent
mx-agent generate completions zsh   > "${fpath[1]}/_mx-agent"
mx-agent generate completions fish  > ~/.config/fish/completions/mx-agent.fish

# Man pages (one per command + subcommand) into a directory:
mx-agent generate man --dir ./dist/man   # writes mx-agent.1, mx-agent-exec.1, ...
```

Release archives ship pre-generated completions (`completions/`) and man pages (`man/`); see
[`scripts/gen-cli-artifacts.sh`](../scripts/gen-cli-artifacts.sh) to produce them locally. A
CI test (`cli_reference_matches_command_surface`) asserts this reference documents every command
and flag in the binary, so the docs cannot silently drift either.

## See also

- [`README.md`](../README.md) — project overview and the authoritative status matrix
- [`docs/user-guide.md`](user-guide.md) — task-oriented walkthroughs
- [`docs/architecture.md`](architecture.md) — daemon/IPC/protocol internals
- [`docs/security-hardening.md`](security-hardening.md) — trust, signing, E2EE, sandbox, policy
- [`docs/roadmap-rust.md`](roadmap-rust.md) — what is planned vs shipped
