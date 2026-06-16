# Security hardening guide

`mx-agent` brokers remote command execution between autonomous agents over
Matrix. That makes its configuration security-critical: a permissive policy or a
misplaced token can turn a workspace peer into remote code execution on your
machine. This guide explains how the safety controls fit together and, for each
one, **what the safe default is and which options weaken it**.

> **Alpha status.** As noted in the [user guide](user-guide.md), `call` and
> `exec` (batch and interactive `--pty`) run a daemon-mediated local execution by
> default and become signed Matrix-backed remote operations when `--room`/`--agent`
> target a registered, trusted, policy-allowed remote agent, with signed
> stdin/resize/cancel controls for live remote exec. The trust, signing, policy, audit, and
> sandbox machinery described here is real. A **remote** `exec`/`call` (`--room`/`--agent`)
> runs the full receiver-side gate — signature → trust → deny-by-default policy engine →
> sandbox. A **local loopback** `exec`/`call`/`--pty` (no `--room`/`--agent`) is
> operator-initiated over the peer-UID-checked socket, so it skips the signature/trust
> **authorization gate** but still runs under the operator's execution **confinement
> floor** — the configured sandbox backend, network decision, filesystem binds, env
> allowlist, plus a default timeout and output cap (parity with `call`; issue #307).
> Both batch and interactive `exec --pty` route the command through the selected sandbox
> backend. The output
> cap for live remote PTY is the agent's `max_output_bytes` from policy (same as batch
> exec); a loopback PTY (no `--room`/`--agent`) falls back to a 64 MiB hard cap when
> `max_output_bytes` is unset. When the cap is reached the daemon stops forwarding
> terminal output (the child keeps running), terminates the stream cleanly, and reports
> `truncated: true` in `exec.finished`. Replay/expiry checks are enforced for
> request types whose schema carries nonce/expiry fields.

## Contents

- [Threat model in one paragraph](#threat-model-in-one-paragraph)
- [Safe defaults at a glance](#safe-defaults-at-a-glance)
- [Workspace power levels (state-write integrity)](#workspace-power-levels-state-write-integrity)
- [Token isolation model](#token-isolation-model)
- [Trust bootstrap](#trust-bootstrap)
- [Policy examples](#policy-examples)
- [Sandbox configuration](#sandbox-configuration)
- [Audit logging](#audit-logging)
- [Hardening checklist](#hardening-checklist)

## Threat model in one paragraph

A request to run something on your machine has to clear independent gates before
a single byte executes: it must carry a **valid Ed25519 signature**, the signing
key must be in your **local trust store**, the **policy engine** must explicitly
allow the room + agent + command + working directory, and — if the request schema
carries freshness fields — it must be **fresh** (not expired, not a replayed
nonce). If policy requires human approval, that approval — a decision from an **authorized approver**, **Ed25519-signed by a key in your local trust store**, and **unexpired** — must also be present (room membership alone cannot release a held task). By default the only authorized approver is the daemon's own account; add others per room with `approvers = ["@alice:server"]` in `policy.toml`. Membership in `approvers` is **necessary but not sufficient**: an approver still needs a signature from a locally-trusted key, so a room member you have not also trusted cannot release a held task (issue #309).
Every gate is deny-by-default. Removing any one of them (trusting a key you did
not verify, marking a room `trusted` with a wide `allow_commands` list, running
with `sandbox = "none"`) widens your exposure; the rest of this guide is about
doing that deliberately rather than by accident.

## Safe defaults at a glance

| Control | Safe default (shipped) | Unsafe / permissive option |
|---|---|---|
| Policy decision | **Deny** (no policy file ⇒ nothing runs) | Adding broad `allow_*` lists |
| Room trust | `trusted = false` | `trusted = true` |
| Raw `exec` | `allow_exec = false` | `allow_exec = true`, or `raw_exec_default = "allow"` |
| Tool / command allowlists | empty (`[]`) ⇒ allow nothing | wide lists, or matching `allow_cwd = ["/"]` |
| Sandbox backend | operator must choose; choose `bubblewrap`/`docker`/`podman` | `none` (zero isolation) |
| Network in sandbox | `Network::Deny` | `network = "allow"` |
| Environment | allowlist of 13 benign vars; secrets always scrubbed | large `env_allowlist` |
| Token / key files | `0600`, dirs `0700` | loosening file modes |
| IPC socket | `0600`, peer-UID checked | exposing the socket directory |
| Workspace power levels | per-event-type PL 50, `state_default` 100, joiners PL 0 | lowering `state_default`, or a wide `events_default` |

The single most important fact: **with no `policy.toml`, the engine denies every
*remote* `exec` and `call`.** You opt into remote-execution risk explicitly, never
by omission. A *local loopback* `exec`/`call` (no `--room`/`--agent`) does not pass
through the engine's allow/deny gate — it is operator-initiated on the operator's
own host — but with no `policy.toml` it still runs under the fail-closed
confinement floor: no sandbox override, network denied, only the 13 benign env
vars (secrets scrubbed), and a default timeout/output cap (issue #307).

A *missing* policy is the intended deny-all default; a **malformed** one is not.
A `policy.toml` that is present but unreadable, unparseable, or fails validation
no longer silently degrades to deny-all — that was indistinguishable from "policy
applied and everything denied." The daemon now **refuses to start** with a
non-zero exit and a precise diagnostic (file path, the parse/validation failure,
and the dotted field path), `mx-agent daemon status` reports a prominent
`policy: MALFORMED — authorizing nothing (deny-all) until fixed` block (with the
file and error; the `--json` output carries a `policy` object), and a file broken
*after* startup logs an `error` at each authorization. Authorization stays
fail-closed throughout (a malformed policy still permits nothing); only the
signal is added. There is deliberately no env-var opt-out to "start anyway" — that
would re-create the silent footgun (issue #350).

## Workspace power levels (state-write integrity)

A workspace room is born with an explicit Matrix `m.room.power_levels`:

- Each `com.mxagent.*` **state** type (`agent` / `task` / `invocation` / `trust`
  / `workspace` / `tool`) requires **power level 50** to write.
- `state_default` is **100**, so changing *native* room state (name, topic,
  encryption, the power levels themselves) is creator-only.
- `users_default` / `events_default` are **0**: any member may send signed
  *timeline* events (`heartbeat`, `exec.request`, `call.request`, …), which are
  verified independently of power levels.

This yields three tiers — **creator** (PL 100), **granted agent** (PL 50, set via
`mx-agent workspace grant`), and **member** (PL 0, refused on every
`com.mxagent.*` state write). A plain member therefore cannot grief the room by
overwriting another agent's `agent.v1` / `task.v1` / `invocation.v1` / `trust.v1`
state.

**Do not lower `state_default` or widen `events_default` as a shortcut.** A wide
loosening lets any member overwrite any agent's state (an integrity/DoS hazard);
the per-event-type grant model exists precisely so that is never necessary. Grant
each participating daemon explicitly instead.

**Power levels never gate execution.** They are a Matrix transport/integrity
property: even a power-level-100 member cannot cause a command to run. Execution
stays gated by the Ed25519 signature + local trust store (`key_id =
SHA256(pubkey)`) + deny-by-default policy + sender-verified approval. Loosening
power levels is a state-integrity decision only, never an authorization one.

## Token isolation model

The daemon owns all long-lived secrets **at rest**, and for the daemon-mediated
command groups (`workspace`/`agent`/`approval`/`share`/`invocation`/`task`, and
`trust publish`/`state`) the CLI never builds a Matrix client or touches them. The
`auth`/`trust` carve-out is the exception: for `auth login` (and `trust
fingerprint`/the local `trust` commands) the **same-binary CLI process** reads
the password, builds a store-backed Matrix client, performs the network login,
and creates/reads the crypto-store passphrase and Ed25519 signing key
in-process. Because the CLI and daemon are the same binary at the same UID this
is an **accepted same-UID exception, not a separate privilege boundary** (see
[architecture §10.3](architecture.md#103-ipc-protocol) and issue #201). A
cross-process advisory `flock` on `<data_dir>/.write.lock` serializes those
in-process writes against a running daemon so they cannot lost-update the shared
session/key files; the lock is advisory and coordinates only mx-agent's own
writers. (It does **not** refresh a running daemon's in-memory client after a
CLI-local re-login — that staleness is resolved only by restarting the daemon.)

**What is stored, and where** (defaults; override the data dir with
`MX_AGENT_DATA_DIR`, the config dir with `MX_AGENT_CONFIG_DIR`):

| Secret | Path | Mode |
|---|---|---|
| Matrix access / refresh token | `~/.local/share/mx-agent/session.json` | `0600` |
| Daemon Ed25519 signing key | `~/.local/share/mx-agent/signing_key.ed25519` | `0600` |
| Local trust store | `~/.local/share/mx-agent/trust.json` | `0600` |
| Replay nonce cache | `~/.local/share/mx-agent/replay_cache.json` | `0600` |
| Pending approvals | data dir, `0600` | `0600` |

The data directory itself is created `0700`. Files are written with the
write-to-temp-then-rename pattern so the mode is correct before the data is
visible.

**Replay cache fail-closed behavior (issue #305).** The daemon enforces
replay/expiry checks on all privileged requests; this check is **mandatory, not
best-effort**:

- A genuine IO error reading `replay_cache.json` (not `NotFound`) causes the
  scheduler to skip the pass entirely (no claim, dispatch, or approval release)
  and the sync router to route nothing — the daemon waits for the next sync cycle
  rather than running unchecked.
- A corrupt or truncated `replay_cache.json` is **quarantined** by renaming it
  to a sibling `replay_cache.json.corrupt` so the bytes survive for inspection.
  The daemon keeps failing closed on every subsequent load while the quarantine
  file exists — a missing `replay_cache.json` alone does *not* silently yield a
  fresh empty cache when the quarantine sentinel is present.
- On first run, `NotFound` is normal and produces a fresh empty cache.

To recover from a corrupt cache incident: inspect `replay_cache.json.corrupt`,
then remove it. The next load will start from a fresh empty cache. Nonces burned
before the corruption are lost, but the quarantine makes this an explicit
operator decision rather than a silent reset.

Live control frames (`exec.stdin`, `exec.cancel`, `pty.resize`) are not burned
into the shared bounded request-plane cache. They are replay-checked **per live
session** in their handlers using an in-memory seen-nonce set scoped to the
invocation lifetime (architecture §7.5–§7.7).

**Tokens never leak into output.** Access and refresh tokens are wrapped in a
`Secret` type whose `Debug` and `Display` render `***redacted***`. As a backstop
for accidental `tracing` field leaks, the telemetry subscriber independently
redacts the value of any structured field whose key looks sensitive (`token`,
`secret`, `password`, `api_key`, `private_key`, `credential`, `authorization`,
…), substituting `***redacted***` in both the human and JSON output formats. The
redaction is a safety net, not a licence to log secrets: the `Secret` wrappers
and the "never log raw tokens/keys" discipline still apply.

**CLI ⇄ daemon isolation.** The CLI talks to the daemon over a Unix domain
socket created with mode `0600` in a directory that must not have group/world
bits set. The daemon additionally checks the peer credentials — `SO_PEERCRED`
on Linux/Android, `LOCAL_PEERCRED` on macOS/iOS and the FreeBSD-family BSDs —
and rejects any connection whose UID does not match its own. Platforms without
a supported peer-credential mechanism (e.g. NetBSD/OpenBSD) fall back to the
socket's `0600` mode under its `0700` parent directory as the sole access
control. Credentials are never passed over IPC or through the environment — the
daemon reads them from its own `0600` files.

**Child-process environment is an allowlist, not a blocklist.** When a sandboxed
command runs, its environment is built from scratch:

- Only these 13 variables pass through by default: `PATH`, `HOME`, `USER`,
  `LOGNAME`, `SHELL`, `LANG`, `LANGUAGE`, `LC_ALL`, `LC_CTYPE`, `TZ`, `TERM`,
  `TMPDIR`, `PWD`.
- You may add names via `execution.env_allowlist` in `policy.toml`.
- **Defence in depth:** even an allowlisted name is dropped if it matches a
  secret pattern — exact names `MATRIX_ACCESS_TOKEN`, `MX_AGENT_TOKEN`,
  `MX_AGENT_PASSWORD`, `MX_AGENT_RECOVERY_KEY`, `SSH_AUTH_SOCK`,
  `GITHUB_TOKEN`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `NPM_TOKEN`, or
  prefixes `AWS_*`, `GOOGLE_*`, `AZURE_*`. As a final catch-all,
  `mx_agent_telemetry::is_sensitive_key` scrubs any name containing `token`,
  `secret`, `password`, `api_key`, etc., so future mx-agent credential
  variables are covered automatically.

> **Safe vs unsafe:** keep `env_allowlist` minimal. Every name you add is a
> variable the remote agent's command can read. Adding a credential-bearing var
> here does *not* expose it (the secret scrub still fires), but adding broad
> application config can still leak internal details.

**Operational rules.** Anyone who can read `session.json` or
`signing_key.ed25519` can act as you. Never copy them off-box, never commit
them, and never pass a password as a flag — use the `MX_AGENT_PASSWORD`
environment variable or the interactive prompt so it stays out of shell history
and `ps`. The interactive `Matrix password:` prompt suppresses terminal echo
(`ECHO`/`ECHONL`) for the duration of the read, restored unconditionally on
return or error — typed characters do not appear on screen or persist in
scrollback.

## Trust bootstrap

Every privileged request is signed; the daemon decides whether to honour a
signature by consulting its **local trust store**, which is always
authoritative.

**Identity.** On first run the daemon generates an Ed25519 key
(`signing_key.ed25519`, `0600`). Two stable identifiers derive from the public
key:

- **Key id** — `mxagent-ed25519:<base64>`
- **Fingerprint** — `SHA256:<base64>`

View yours and read it out-of-band to peers:

```bash
mx-agent trust fingerprint
```

**Approving a peer.** Trust is opt-in and per-key. After verifying a peer's
fingerprint over a channel you trust (voice, in person, an existing secure
chat), approve their key:

```bash
mx-agent trust approve \
  --agent @claude:matrix.org \
  --key   mxagent-ed25519:BASE64... \
  --room  '!workspace:matrix.org' \
  --fingerprint SHA256:BASE64...      # optional; derived from the key id if omitted
```

Inspect and revoke:

```bash
mx-agent trust list --room '!workspace:matrix.org'
mx-agent trust revoke --agent @claude:matrix.org --key mxagent-ed25519:BASE64...
```

A revoked key keeps its record (for auditability) but is rejected for
authorization.

**Room-published trust is advisory only.** A room may carry
`com.mxagent.trust.v1` state events so members can discover each other's keys
(`mx-agent trust publish` / `mx-agent trust state`). This is a convenience, not
an authority: **the local store always wins**, and a local revocation overrides
any room-published "trusted".

> **Safe vs unsafe:** the only safe way to bootstrap trust is to verify the
> fingerprint out-of-band before `trust approve`. Approving a key you read out
> of a room state event, unverified, defeats the entire model — anyone able to
> write that state could impersonate a peer.

**Where signatures sit in the pipeline.** For a raw `exec` the daemon checks, in
order: signature valid → request routed to this agent → key trusted → replay/
freshness → policy. A tool `call` is the same minus the routing check. The
replay/freshness check is **fail-closed**: a cache load error or corrupt file
causes the daemon to skip the work entirely rather than run unchecked (see
[Replay cache fail-closed behavior](#token-isolation-model) above). Any failure
denies the request, and the denial is recorded in the audit log.

## Device verification, cross-signing, and key backup (E2EE)

There are **two distinct trust roots**, and conflating them is a mistake:

- The **mx-agent signing key** (`mxagent-ed25519:…`, fingerprint `SHA256:…`)
  authorizes *execution* — see [Trust bootstrap](#trust-bootstrap) above.
- The **Matrix device key** (`ed25519:<base64>`) is a *transport* identity: it
  decides who you share Megolm keys with and who can read or inject encrypted
  traffic. It is a **different key with a different fingerprint** and **never**
  authorizes execution on its own.

The daemon owns all crypto state in a persistent, encrypted SQLite store
(`~/.local/share/mx-agent/crypto-store/`, `0700`); the coding agent and the
stateless CLI never see device keys. The CLI receives only fingerprints, the SAS
emoji/decimal, and verification status.

**Listing and verifying peer devices.**

```bash
mx-agent device list   --room '!workspace:matrix.org'          # devices + status + fingerprints
mx-agent device show   --user @peer:hs --device DEVICEID

# Out-of-band: confirm the device fingerprint over a channel you trust, then:
mx-agent device verify --user @peer:hs --device DEVICEID \
  --manual --fingerprint 'ed25519:BASE64...'

# Interactive emoji/SAS (operator-attended): compare the emoji with the peer,
# then answer the prompt. The confirm/cancel travels over the same connection.
# The entire flow — including the decision wait — is bounded by a ~300 s
# deadline. An unanswered prompt cancels automatically (fails safe to cancel).
mx-agent device verify --user @peer:hs --device DEVICEID
```

A headless/unattended daemon should use the out-of-band `--manual --fingerprint`
path (or pre-seeded cross-signing); the interactive SAS expects an operator. An
in-progress interactive verification does not block other daemon IPC commands
(exec, approval, task, heartbeat) — each connection is served on its own worker
thread (issue #258).

**Cross-signing.** Bootstrap the daemon's own cross-signing identity so verifying
a user's identity marks their cross-signed devices verified:

```bash
mx-agent auth cross-signing bootstrap    # idempotent
mx-agent auth cross-signing status
```

**Key backup / recovery.** Enable secure server-side key backup so a restart or
re-provision does not silently lose the ability to decrypt history:

```bash
mx-agent recovery enable     # provisions SSSS + key backup; prints the recovery key ONCE
mx-agent recovery status
mx-agent recovery recover    # after a re-provision: re-import keys (prompts for the recovery key)
```

> **Recovery-key handling.** `recovery enable` surfaces the recovery key exactly
> once. Store it somewhere safe immediately. It is never logged and never
> persisted in clear; **if you lose it, history backed up under it is
> unrecoverable** — there is no escrow.
>
> When feeding the key back to `recovery recover`, prefer the
> `MX_AGENT_RECOVERY_KEY` environment variable or the interactive `Recovery key:`
> prompt (which suppresses terminal echo, exactly like the password prompt) over
> the `--recovery-key` flag. Passing it as a flag exposes it in shell history and
> `ps`; the CLI prints a warning to stderr if you do.

**Restart vs. re-provision.**

- A **restart on the same host** recovers transparently from the persistent
  crypto store — no recovery key needed.
- A **re-provision onto a fresh host** (or a wiped store) recovers history via
  `mx-agent recovery recover` plus the recovery key.

Both paths end with the daemon able to decrypt prior privileged events.

**Optionally requiring verified devices.** By default, device verification is
*advisory*: a request from a trusted signing key whose sending device is
unverified still executes (authority comes from the signing key), and the daemon
logs a non-sensitive advisory. To additionally require a verified sending device,
set `require_verified_device` in policy (per-room or per-agent). It is **strictly
additive**: after the signature → trust → policy gate passes, an unverified
device is denied with reason `unverified_device`. It can only *deny*, never grant
— so it cannot be used to widen access, only to tighten it.

```toml
[rooms."!workspace:matrix.org"]
trusted = true
require_verified_device = true     # every agent in this room must send from a verified device
```

**What `--e2ee on` does and does not protect (issue #308).** Room encryption is
a *confidentiality* property (who can read), never an *authority* property (who
may execute). Under `workspace create --e2ee on`:

- **Encrypted, unreadable by the homeserver operator:** workspace **timeline**
  events — exec/call requests, results, stream chunks, the artifact/share
  *referencing* events, heartbeats — are Megolm-encrypted. The **media offload**
  (exec output over 256 KiB and large `share` payloads) is uploaded as
  ciphertext via the Matrix `EncryptedFile` scheme and decrypted on retrieval, so
  the full log / shared blob is not readable by the operator.
- **Plaintext, readable by the homeserver operator even under `--e2ee on`:**
  Matrix **state** events are never Megolm-encrypted. That includes the
  `com.mxagent.task.v1` action (`command`/`cwd`/`env`) and result, and the
  `com.mxagent.invocation.v1` / `com.mxagent.agent.v1` / `com.mxagent.workspace.v1`
  state (requester/target identities, capabilities, `cwd`, `project_id`, git
  commit, local path). The scheduler reads the real action from state to execute
  it, so it cannot be redacted or moved into encrypted timeline events without a
  deferred task-engine redesign.

> **Do not place secrets in a task action's `env`.** It is published in plaintext
> room state and is readable by the homeserver operator regardless of encryption.
> The daemon emits one advisory warning (logging only the *count* of env keys,
> never their names or values) when a task action with a non-empty `env` is
> published into an encrypted room. Exec request `env` rides the encrypted
> timeline event, but operational env secrets are scrubbed by the daemon's
> redactor regardless — prefer the daemon's `env_allowlist` and the host
> environment over carrying secrets through Matrix at all.

## Policy examples

Policy lives in `policy.toml`, resolved in this order:

1. `${MX_AGENT_CONFIG_DIR}/policy.toml`
2. `${XDG_CONFIG_HOME}/mx-agent/policy.toml`
3. `~/.config/mx-agent/policy.toml`

If that file is **absent**, the deny-all default applies silently. If it is
**present but malformed** (unreadable, bad TOML, or failing validation), the
daemon refuses to start and `daemon status` flags it — it never silently
deny-alls without a signal (issue #350; see "the single most important fact"
above).

The engine is a pure deny-by-default function. Every field defaults to
empty / `false` / `None`, and an **empty allowlist permits nothing** (it is not
a wildcard). For a raw `exec` to run, *all* of these must hold: the room is
known and `trusted`, the agent is known, `allow_exec = true` (or the room's
`raw_exec_default = "allow"`), the command basename is in `allow_commands`, the
working directory is under an `allow_cwd` entry, and no `deny_args_regex` matches.

### A safe, restrictive policy

```toml
# Workspace-wide execution defaults.
[execution]
default_sandbox = "bubblewrap"   # isolate every command by default
network         = "deny"         # no outbound network unless overridden
read_only_paths = ["/usr", "/bin", "/lib"]
writable_paths  = ["/home/me/code/project", "/tmp/mx-agent"]
env_allowlist   = ["CARGO_HOME", "RUSTUP_HOME"]  # keep this list short

# Per-room rules. A room is untrusted until you say otherwise.
[rooms."!abc:matrix.org"]
trusted          = true
raw_exec_default = "deny"        # deny raw exec unless an agent rule allows it
# approvers = ["@supervisor:matrix.org"]  # extra approvers beyond the daemon itself (issue #309);
#                                         # each listed user still needs a locally-trusted signing key

# Per-agent rules, keyed by Matrix user id.
[rooms."!abc:matrix.org".agents."@claude:matrix.org"]
allow_exec      = true
allow_tools     = ["run_tests", "lint", "read_file"]
allow_commands  = ["npm", "pnpm", "pytest", "go", "cargo"]   # basenames or full paths
allow_cwd       = ["/home/me/code/project"]                  # absolute paths only
deny_args_regex = [
  "curl\\s+.*\\|\\s*sh",   # block "curl … | sh"
  "rm\\s+-rf\\s+/",        # block "rm -rf /"
  "ssh",
  "scp",
]
max_runtime_ms  = 900000        # 15 min wall-clock cap
max_output_bytes = 5000000      # 5 MB captured output cap
requires_approval = false       # set true to hold every request for sign-off
sandbox = "bubblewrap"          # overrides execution.default_sandbox for this agent
network = "deny"
```

### Field reference

`[execution]` (workspace defaults):

| Field | Default | Notes |
|---|---|---|
| `default_sandbox` | none set | Backend used when an agent rule doesn't override. `firejail`/`chroot` are rejected. |
| `network` | none set | `allow` or `deny`. |
| `read_only_paths` | `[]` | Bound read-only into the sandbox. |
| `writable_paths` | `[]` | Bound writable — **keep minimal**. |
| `env_allowlist` | `[]` | Extra env names (still subject to the secret scrub). |
| `container_image` | `debian:stable-slim` | Image the `docker`/`podman` backend runs in. The runtime follows the `sandbox` value. |
| `max_processes` | none | Process-count cap (`RLIMIT_NPROC` on host paths, `--pids-limit` on containers). Unset ⇒ uncapped. Recommended starting point: `256`. |
| `max_memory_bytes` | none | Address-space cap in bytes (`RLIMIT_AS` / `--memory`). Unset ⇒ uncapped. Recommended: `2147483648` (2 GiB). |
| `max_cpu_seconds` | none | Total CPU-seconds cap (`RLIMIT_CPU` / `--ulimit cpu`). Distinct from wall-clock `max_runtime_ms`. Unset ⇒ uncapped. Recommended: `120`. |
| `seccomp` | `"off"` | Syscall-filtering mode: `"off"` (default) or `"default"` (opt-in curated default-deny profile, Linux-only; BPF profile installation is a documented follow-up — selecting `"default"` today logs a loud enforcement-pending warning rather than silently leaving the command unfiltered). |
| `require_sandbox` | `false` | Deny any execution that resolves to the `none` backend, fail-closed (`deny:sandbox_required`). Set `true` in environments where falling back to zero isolation is unacceptable. |

`[rooms."<room>"]`:

| Field | Default | Notes |
|---|---|---|
| `trusted` | `false` | Raw `exec` is only ever evaluated for trusted rooms. |
| `raw_exec_default` | none | `allow` / `deny` room-wide default for raw exec. |
| `require_verified_device` | `false` | Room-wide default for the additive verified-device gate (deny-only; see [Device verification](#device-verification-cross-signing-and-key-backup-e2ee)). |
| `approvers` | `[]` | Matrix user ids (start with `@`) allowed to decide approvals, in addition to the daemon's own account. Empty ⇒ daemon-only. Necessary-not-sufficient: an approver still needs an Ed25519 signature from a locally-trusted key (issue #309). |

`[rooms."<room>".agents."<agent>"]`:

| Field | Default | Notes |
|---|---|---|
| `allow_exec` | `false` | Master switch for raw exec for this agent. |
| `allow_tools` | `[]` | Allowlisted `call` tool names. |
| `allow_commands` | `[]` | Allowlisted command basenames/paths for raw exec. |
| `allow_cwd` | `[]` | Allowlisted absolute working directories (subdirs included). |
| `deny_args_regex` | `[]` | Deny if any pattern matches the argv. |
| `max_runtime_ms` | none | Wall-clock cap; unset ⇒ unbounded. |
| `max_output_bytes` | none | Captured-output cap; unset ⇒ unbounded for batch exec/call. For live remote `--pty` sessions the same value is applied; a loopback `--pty` falls back to a 64 MiB default when unset. |
| `requires_approval` | `false` | Hold the request for human sign-off. |
| `sandbox` / `network` | none | Per-agent overrides. |
| `max_processes` | none | Overrides `execution.max_processes` for this agent. |
| `max_memory_bytes` | none | Overrides `execution.max_memory_bytes` for this agent. |
| `max_cpu_seconds` | none | Overrides `execution.max_cpu_seconds` for this agent. |
| `seccomp` | inherits | Overrides `execution.seccomp` for this agent (`"off"` or `"default"`). |
| `require_verified_device` | `false` | Per-agent verified-device gate (deny-only; OR-ed with the room default). |

### Unsafe options to use deliberately, if ever

- **`raw_exec_default = "allow"`** flips a room to allow raw exec unless an agent
  rule denies it — the opposite of deny-by-default. Prefer per-agent
  `allow_exec = true`.
- **`allow_cwd = ["/"]`** (or any broad root) lets a command run anywhere the
  daemon user can reach. Scope it to a single project tree.
- **A long `allow_commands` list**, or shells (`bash`, `sh`) in it, effectively
  grants arbitrary execution — a shell can run anything. Allow specific tools,
  not interpreters.
- **Unset `max_runtime_ms` / `max_output_bytes`** allow unbounded runtime and
  output (resource exhaustion). Always set caps for untrusted peers. For interactive
  `--pty`, an unset `max_output_bytes` still applies the 64 MiB loopback default, but
  remote PTY sessions run without any cap — set it explicitly for remote agents.
- **`requires_approval = false` with a wide allowlist** removes the human in the
  loop. Set `requires_approval = true` for anything you have not fully
  constrained.

## Sandbox configuration

The sandbox decides *how* an allowed command is isolated. Backends:

| Backend (`sandbox = …`) | Isolation |
|---|---|
| `none` | **No isolation.** Only the centralized controls (cwd, env scrub, timeout, output cap) apply. |
| `bubblewrap` | PID/UTS/IPC/**user** namespaces, `--die-with-parent`, `--cap-drop ALL`, private `/proc` + minimal `/dev` + tmpfs `/tmp`, bind-mounted filesystem, network namespace dropped when `network = "deny"`, and `--new-session` on the batch path (omitted for an interactive `--pty` so Ctrl-C still works). |
| `docker` / `podman` | Read-only root (`--read-only`), `--security-opt no-new-privileges`, `--network none` when denied, explicit `--volume` mounts, env passed **by name** (`--env KEY`, values never in argv), `--rm` cleanup. The runtime follows the `sandbox` value (`podman` runs `podman run …`); the image is `execution.container_image` (default `debian:stable-slim`). Runs as the daemon's own identity (`--user <uid>:<gid>` on docker, `--userns=keep-id` on rootless podman) so it owns operator-owned `writable_paths`, and with that mapping drops **all** capabilities (`--cap-drop ALL`) — bubblewrap parity (issue #349). Resource caps map to `--pids-limit` / `--memory` / `--ulimit cpu`. |
| `firejail` / `chroot` | **Not implemented — rejected at policy load.** Naming either in `execution.default_sandbox` or an agent `sandbox` fails validation with a dotted-path error (no silent unsandboxed fallthrough). |

**Default backend.** The library's built-in fallback is `Backend::None` (zero
isolation). This is *not* the configuration you should run: always set
`execution.default_sandbox` (and, for untrusted agents, a per-agent `sandbox`)
to `bubblewrap`, `docker`, or `podman`. Treat `none` as a debugging-only choice
for code you fully trust.

**Network.** Inside the sandbox the default is `Network::Deny` — a fresh empty
network namespace (bubblewrap) or `--network none` (containers). Set
`network = "allow"` only when a command genuinely needs the network, and prefer
scoping it per-agent rather than workspace-wide.

**Filesystem.** Only `read_only_paths` and `writable_paths` are visible inside
the sandbox; everything else is hidden. Read-only mounts are applied before
writable ones, so a nested `writable_paths` entry can carve a writable hole in a
read-only tree. Keep `writable_paths` as small as the task allows — typically
the project directory and a scratch dir under `/tmp`. Filesystem-bind confinement
applies to batch exec, named tool calls (`call`), **and** the interactive
`exec --pty` path — all three route the command through the selected sandbox
backend; the output byte cap (`max_output_bytes`) is also enforced on the PTY
stream.

**A backend selected but missing fails closed.** If `bwrap`/`docker`/`podman` is
not on the daemon's `PATH`, the run fails with an actionable diagnostic naming the
backend and the missing launcher — it never silently falls back to no isolation.

**Resource limits (issue #349).** A confinement floor bounds host resource
consumption by an authorized-but-misbehaving command (fork bomb, memory/CPU
exhaustion). Three policy keys resolve through the engine (agent override, else
the `execution` default):

| Key | Host paths (`none`/`bubblewrap`) | Container backend |
|---|---|---|
| `max_processes` | `RLIMIT_NPROC` (best-effort under the user namespace) | `--pids-limit` (exact, cgroup) |
| `max_memory_bytes` | `RLIMIT_AS` (address space) | `--memory` (cgroup) |
| `max_cpu_seconds` | `RLIMIT_CPU` (CPU-seconds, not wall clock) | `--ulimit cpu` |

On the `none`/`bubblewrap` paths the caps are applied by a hidden self-re-exec
launcher (`mx-agent __sandbox-exec …`) that calls `setrlimit` (a safe API — the
workspace forbids the `unsafe` `pre_exec`) before `exec`. Recommended starting
points: `max_processes = 256`, `max_memory_bytes = 2 GiB`, `max_cpu_seconds = 120`.
For exact process capping prefer a container backend (`--pids-limit` is cgroup-
enforced); on macOS `RLIMIT_NPROC` is skipped.

**Syscall filtering (seccomp, issue #349).** `execution.seccomp` selects `"off"`
(default) or a curated default-deny `"default"` profile (Linux-only, agent
override available). It ships **off by default** so deployments do not suddenly
`EPERM` syscalls their commands rely on. The mode threads end to end through the
launcher; installing the default-deny BPF profile (in-process for `none`, via
`bwrap --seccomp` / container `--security-opt seccomp=`) is a documented follow-up
(the allowlist breadth and the `bwrap --seccomp` byte format are open questions
pending a real-Linux acceptance test), so selecting `"default"` today logs a loud
"enforcement pending" notice rather than silently leaving the command unfiltered.

**Require a sandbox (issue #349).** When an authorized execution resolves to the
`none` backend the daemon emits a prominent warning naming the room / requester /
target (no secrets). Set `execution.require_sandbox = true` to turn that warning
into a hard, fail-closed denial (`deny:sandbox_required`).

**What the sandbox does *not* do.** Bubblewrap runs the command in a user
namespace (`--unshare-user`, so it is not the daemon's privileged identity) and
drops all capabilities; containers block privilege escalation
(`no-new-privileges`), run as the daemon's identity, and `--cap-drop ALL`.
Resource caps mitigate host exhaustion but do not defend against a kernel
vulnerability, and the default-deny seccomp profile installation is still pending
(see above). For the strongest isolation, prefer a container backend, set the
resource caps, and consider `require_sandbox = true`.

> **Safe vs unsafe:** `sandbox = "bubblewrap"` (or a container) + `network =
> "deny"` + tight `writable_paths` is the safe baseline. `sandbox = "none"`,
> `network = "allow"`, or a `writable_paths` that includes `$HOME` each remove a
> layer — combine all three and an allowed command is effectively unconfined.

## Audit logging

Every authorization decision — allow or deny — is appended to an audit log.

- **Location:** `~/.config/mx-agent/audit.log` (honours `MX_AGENT_CONFIG_DIR` /
  `XDG_CONFIG_HOME`). Created `0600` inside a `0700` directory — the same
  private-state posture as `session.json`, `signing_key.ed25519`, `trust.json`,
  and the replay cache — so decision metadata is not world-readable under a
  loose umask.
- **Format:** newline-delimited JSON, one decision per line, opened in append
  mode so external log rotation works.

Each record carries: RFC 3339 UTC `ts`, `room`, `requester` (Matrix user id),
`target`, optional `invocation_id`, `request` (`"exec"` or `"call"`), the
redacted `command` argv or `tool` name, the `decision` (`Allowed` / `Denied`),
a stable `policy_rule`, and (for allowed requests) the selected `sandbox`
backend.

**Denials are machine-readable.** The `policy_rule` field uses stable
identifiers so you can alert on them:

```
deny:unknown_room        deny:untrusted_room      deny:unknown_agent
deny:empty_command       deny:exec_not_allowed    deny:command_not_allowed
deny:cwd_not_allowed     deny:denied_arguments    deny:tool_not_allowed
deny:unverified_device
```

The policy-engine reasons above are joined by `deny:unverified_device`, recorded
when the optional `require_verified_device` gate rejects an `exec` or a named
`call` from an unverified Matrix device (issues #240 and #257). That gate runs
*after* the policy decision, so its denial is audited in addition to — not
instead of — the policy outcome. Pre-policy authentication failures (unsigned,
bad signature, untrusted key, malformed) are deliberately *not* audited for
either path, since they are not attributable to a trusted requester.

**Auto-executed task-DAG decisions are covered too.** The scheduler attaches an
audit log to every task orchestrator it builds, resolving the same path as the
exec/call path (`~/.config/mx-agent/audit.log` with a data-dir fallback), so a
task-action policy decision — whether the underlying action is a named tool
(`"call"` record) or a shell command (`"exec"` record) — lands in the same file
with the same record shape as a direct exec/call decision (#266). Audit-write
failures on the task path are logged and swallowed — they never convert to a
dispatch error — so a flaky or unwritable audit file cannot change an
authorization outcome.

**Secrets are redacted in the log.** Command arguments pass through a redactor
that masks `KEY=value` pairs and `--flag value` pairs whose key looks sensitive,
so the audit trail records *that* a command ran without recording its secrets.

**Operational logs** are separate from the audit log and go to stderr. Control
them with `MX_AGENT_LOG` (filter directives, falls back to `RUST_LOG`) and
`MX_AGENT_LOG_FORMAT` (`human` or `json`). The same secret-key redaction applies
to structured fields here, in both formats. When the daemon runs in the
background its stdout/stderr are captured to `daemon.log` in the runtime
directory; that file is created `0600` (owner-only) regardless of the umask, like
the rest of the daemon's private state.

> **Safe vs unsafe:** the audit log is append-only and lives `0600` under your
> config dir — ship it to a tamper-evident store if you need non-repudiation,
> and never disable redaction. Treat a burst of
> `deny:untrusted_room` / `deny:command_not_allowed` entries as a signal worth
> investigating.

## Hardening checklist

- [ ] No `policy.toml` until you intend to allow execution (default = deny all).
- [ ] After editing `policy.toml`, verify it is valid before starting the daemon: `mx-agent daemon start` (or `daemon status` if already running) will report `policy: MALFORMED …` and exit non-zero if the file is present but broken; a parse error includes the TOML line/column, a validation error includes the dotted field path (issue #350).
- [ ] Each room left `trusted = false` unless you actively use it.
- [ ] `allow_commands` lists specific tools, never shells/interpreters.
- [ ] `allow_cwd` scoped to a project tree, never `/` or `$HOME`.
- [ ] `max_runtime_ms` and `max_output_bytes` set for every privileged agent.
- [ ] `max_processes`, `max_memory_bytes`, and `max_cpu_seconds` set where fork-bomb / memory / CPU exhaustion is a concern. Prefer the container backend for exact process capping (`--pids-limit` is cgroup-enforced); on macOS `RLIMIT_NPROC` is skipped.
- [ ] `requires_approval = true` for anything not fully constrained.
- [ ] Non-daemon approvers added to `approvers` in `policy.toml` **only after** running `trust approve` for each; `approvers` is necessary-not-sufficient — an approver still needs a locally-trusted signing key (issue #309).
- [ ] `default_sandbox` set to `bubblewrap`/`docker`/`podman`; `none` avoided.
- [ ] `execution.require_sandbox = true` in environments where resolving to `none` is unacceptable.
- [ ] `network = "deny"` except where a command genuinely needs it.
- [ ] `writable_paths` minimal; secrets kept out of `read_only_paths` too.
- [ ] `env_allowlist` short; rely on the built-in secret scrub.
- [ ] Peer fingerprints verified out-of-band before `trust approve`.
- [ ] `session.json` / `signing_key.ed25519` kept `0600`, never copied or
      committed; passwords passed via `MX_AGENT_PASSWORD` or the interactive
      prompt, never as flags; the interactive prompt suppresses terminal echo.
- [ ] `crypto-store/` (`0700`) and `crypto-store-key` (`0600`) left daemon-owned; never copied off-box.
- [ ] `recovery enable` run once per daemon identity; recovery key stored safely offline (shown once, never logged or persisted in clear).
- [ ] After a re-provision onto a new host, `recovery recover` run before accepting privileged events so history remains decryptable; feed the key via `MX_AGENT_RECOVERY_KEY` or the interactive `Recovery key:` prompt (both suppress terminal echo, exactly like the password prompt) — avoid `--recovery-key` (argv is visible in shell history and `ps`; the CLI prints a warning if you do).
- [ ] If peer device verification is required, `require_verified_device = true` set *after* verifying peer devices via `mx-agent device verify`; the flag is additive-deny only and does not relax execution policy.
- [ ] Interactive SAS (`mx-agent device verify`) treated as operator-attended; headless daemons use `--manual --fingerprint` or pre-seeded cross-signing instead. An unanswered prompt cancels automatically after ~300 s (fails safe to cancel); other daemon IPC commands remain unaffected while the flow is in progress.
- [ ] Audit log monitored and shipped off-box if you need non-repudiation.

See also: [`SECURITY.md`](../SECURITY.md) for reporting vulnerabilities, and the
[user guide](user-guide.md) for the end-to-end setup these controls protect.
