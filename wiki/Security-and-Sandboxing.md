# Security & Sandboxing

A hardening guide for deploying mx-agent in environments where remote agents can run commands on your machines. mx-agent's security posture is **zero-trust and deny-by-default**: room membership grants nothing; every privileged action must independently pass cryptographic and policy checks on the machine that would execute it.

> **Implementation status.** The IPC peer-credential check, the deny-by-default policy engine (parser + validator), Ed25519 signing/verification, allowlist-based environment scrubbing, audit-log structure, and `none`/`bubblewrap`/container sandbox backends are **✅ implemented**. Policy `read_only_paths` / `writable_paths` filesystem-bind confinement and `network` enforcement are wired end-to-end from the policy engine through `Allowance` into the runner's `Restrictions` — including for auto-executed task DAGs (previously hardcoded to `Backend::None`). The sandbox backend applies to **batch exec only**; interactive `exec --pty` does not route through the sandbox backend (only the baseline controls — env scrub, cwd, timeout, output cap — apply to the PTY path). `none` is the built-in fallback and provides zero isolation; `bubblewrap` and Docker/Podman container backends are policy-selectable but are not a standalone security boundary (no seccomp, rlimit caps, or UID/GID remap). E2EE production hardening (issue #240) is **✅ implemented**: persistent daemon-owned crypto store, device verification UX (`device list`/`show`/`verify`), cross-signing bootstrap (`auth cross-signing`), server-side key backup/recovery (`recovery enable`/`status`/`recover`), and the optional additive `require_verified_device` policy gate. No canonical `policy.toml` ships in-repo yet; the schema below is the one the engine parses. The whole workspace **forbids `unsafe` Rust** (`unsafe_code = "forbid"`) and uses `rustix`/`nix` for syscalls.

---

## Zero-Trust Architecture

There is no ambient authority. A request is honored only if it clears **every** applicable layer (architecture §1.2):

```text
room membership
+ Matrix event sender identity
+ Matrix device trust            (when E2EE is enabled)
+ mx-agent Ed25519 request signature
+ local policy (deny-by-default)
+ optional human approval
```

### Three independent identities

A single agent is pinned by three separate cryptographic facts, so compromising one does not grant execution:

1. **Matrix user ID** — `@alice:matrix.org` (who, socially).
2. **Matrix device / E2EE identity** — the homeserver-issued device key (which client).
3. **mx-agent signing identity** — a daemon-managed **Ed25519** key that signs privileged requests (`exec`, `call`, `cancel`). This is the one that actually authorizes execution.

### End-to-end encryption over Matrix

When E2EE is enabled, message *contents* are encrypted between daemons (Olm for 1:1 to-device signaling, Megolm for room streams); the homeserver relays ciphertext only. E2EE protects confidentiality and binds the device identity — but note it is **orthogonal to authorization**: a correctly decrypted request from a trusted device is *still* rejected if its Ed25519 signature, local policy, or any schema-provided nonce/expiry check fails. Encryption answers "did this really come from that device, privately?"; policy answers "is that device allowed to do this here?".

### Two distinct trust roots — transport vs. execution

**Matrix device verification** and **mx-agent Ed25519 signing** are separate trust roots for separate purposes. Conflating them is a security mistake:

- The **Matrix device key** (`ed25519:<base64>`) is the E2EE *transport* identity. Verifying it establishes who you share Megolm keys with and protects confidentiality. It is shown by `mx-agent device list`.
- The **mx-agent signing key** (`mxagent-ed25519:…`, fingerprint `SHA256:…`) authorizes *execution*. This is what `trust approve` records and what the daemon checks before running any privileged action.

For a privileged action delivered over E2EE, **both must hold**: the event must decrypt (transport) *and* carry a valid Ed25519 signature from a locally-trusted signing key that policy permits (execution). Device verification is layered *after* the execution gate via the optional `require_verified_device` policy knob (additive deny only; default `false`). See the [security hardening guide](../docs/security-hardening.md) for details.

### Trust bootstrap modes (architecture §13.2)

| Mode | How a key becomes trusted | Posture | Status |
|---|---|---|---|
| **manual** | Verify the Ed25519 fingerprint out-of-band and `trust approve` it | Strongest — the recommended default | ✅ Implemented |
| **Matrix device verified** | Transport advisory signal; optionally adds a denial via `require_verified_device` | Additive-deny only; never a grant | ✅ Implemented |
| **room-admin grant** | An admin publishes `com.mxagent.trust.v1` state | Advisory only; never overrides local store | ✅ Partial |
| **TOFU** | First key seen is trusted | Convenient, but vulnerable on first contact | Planned |

**Trust precedence — the local store is final authority.** Room-published trust state is purely advisory and is consulted *only* when the local store has no record for an `(agent_id, key_id)` pair. A **local revocation always wins** and can never be undone by a room admin:

```bash
mx-agent trust fingerprint --agent developer-pi
mx-agent trust approve --room "$ROOM" --agent developer-pi --key mxagent-ed25519:abc123
mx-agent trust revoke  --room "$ROOM" --agent developer-pi --key mxagent-ed25519:abc123
```

---

## Daemon Socket Isolation

The CLI↔daemon channel is a Unix domain socket — a local trust boundary that must not be crossable by other users on a shared host.

```text
$XDG_RUNTIME_DIR/mx-agent/daemon.sock      # mode 0600, user-owned parent dir
```

Two enforcement layers (implemented in `mx-agent-ipc`, module `peercred`):

1. **Filesystem permissions.** The socket is `0600` and its parent directory is user-owned, so the OS already bars other users at the file layer.
2. **`SO_PEERCRED` UID check (Linux/Android).** Before reading *any* request bytes, the daemon reads the connecting peer's UID via the `SO_PEERCRED` socket option and **rejects any client whose UID ≠ the daemon's effective UID**. Rejections are audited with a `tracing::warn!` that records *only* the two UIDs — no payload is read before rejection, so a hostile peer cannot smuggle data through the rejection path.

```text
WARN ipc::peercred: rejecting peer: uid mismatch (peer_uid=1001, daemon_uid=1000)
```

On platforms without a supported peer-credential mechanism, the check returns `Unsupported`: the daemon logs a single warning and falls back to the `0600` permissions and user-owned directory as the sole access control — defined and observable, never silently permissive. (An optional local IPC auth token, stored outside any agent-visible environment, is a 🔮 future second factor.)

---

## Environment Scrubbing (architecture §13.4)

Child processes start from an **allowlist**, not your shell environment. The runner builds the child env from a small default allowlist plus policy-permitted variables, then applies a **secret denylist that strips matching variables even if they were allowlisted**:

```text
# Always stripped (exact names):
MATRIX_ACCESS_TOKEN   MX_AGENT_TOKEN   SSH_AUTH_SOCK
GITHUB_TOKEN          OPENAI_API_KEY   ANTHROPIC_API_KEY   NPM_TOKEN
# Always stripped (prefixes):
AWS_*    GOOGLE_*    AZURE_*
```

This means a remote agent cannot exfiltrate your cloud or model-provider credentials by reading the child's environment, even if a policy rule is overly broad.

---

## Hardened Production Configuration

A complete, fully-commented `policy.toml`. Place it at `~/.config/mx-agent/policy.toml` (override the config dir with `MX_CONFIG_DIR`) and set it to mode `0600`. The engine is **deny-by-default**: anything not explicitly allowed is denied (local exit code `126`).

```toml
# ~/.config/mx-agent/policy.toml
#
# mx-agent local authorization policy.
# DENY-BY-DEFAULT: a request is rejected unless a matching rule allows it.
# Scope is per-room, then per-agent within that room.

# ─────────────────────────────────────────────────────────────────────────────
# Global execution defaults. These bound EVERY invocation and are the floor that
# OS-level sandbox backends build on. They are enforced even by the `none`
# backend (zero isolation) and by the `bubblewrap`/container backends.
# ─────────────────────────────────────────────────────────────────────────────
[execution]
default_sandbox = "bubblewrap"      # Select the implemented bubblewrap backend.
                                    # Use "none" only to be explicit about zero
                                    # isolation.
network         = "deny"            # Deny child network access by default.
                                    # Blocks data exfiltration and SSRF: a
                                    # compromised command cannot phone home or
                                    # pivot to internal services (169.254.169.254,
                                    # localhost admin ports, etc.).

# Read-only vs. read-write filesystem boundaries.
# read_only_paths are bind-mounted read-only; writable_paths are the ONLY places
# a child may write. Everything else is inaccessible under an isolating backend.
read_only_paths = ["/usr", "/bin", "/lib", "/lib64", "/etc"]
writable_paths  = ["/home/me/code/project", "/tmp/mx-agent"]

# ─────────────────────────────────────────────────────────────────────────────
# Per-room rules. The room ID is the table key.
# ─────────────────────────────────────────────────────────────────────────────
[rooms."!aBcDeF123:matrix.org"]
trusted          = true             # This workspace is operationally trusted...
raw_exec_default = "deny"           # ...but raw shell exec is STILL denied unless
                                    # an agent rule below opts in. Prefer named
                                    # `call` tools over raw `exec`.

# Per-agent rules within the room. The agent's Matrix user ID is the table key.
[rooms."!aBcDeF123:matrix.org".agents."@claude:matrix.org"]
allow_exec      = true              # Permit raw exec for THIS agent only.
allow_tools     = ["run_tests", "lint", "read_file"]   # Named-tool allowlist.
allow_commands  = ["npm", "pnpm", "pytest", "go", "cargo"]  # argv[0] allowlist.
allow_cwd       = ["/home/me/code/project"]            # Working-dir allowlist.

# Argument denylist (regex, AND-checked against the full command line). Defense
# in depth against obvious foot-guns even within allowed commands.
deny_args_regex = [
  "curl\\s+.*\\|\\s*sh",            # piping a download straight into a shell
  "rm\\s+-rf\\s+/",                 # catastrophic recursive delete
  "ssh",                           # no lateral movement
  "scp",                           # no off-box copy
]

max_runtime_ms   = 900000          # 15 min hard wall-clock cap (then SIGTERM,
                                   # 5 s grace, SIGKILL on the process group).
max_output_bytes = 5000000         # 5 MB output cap; beyond this, switch to
                                   # artifact mode and mark truncated.
requires_approval = false          # Set true to require a human `approval`
                                   # decision before this agent's privileged
                                   # requests execute.

# Tighter rule for a less-trusted remote runner: tools only, no raw exec,
# mandatory approval, no network, short caps.
[rooms."!aBcDeF123:matrix.org".agents."@ci-runner:matrix.org"]
allow_exec        = false
allow_tools       = ["run_tests"]
max_runtime_ms    = 300000
max_output_bytes  = 2000000
requires_approval = true
```

### Defense-in-depth summary

| Control | What it stops | Where |
|---|---|---|
| `network = "deny"` | Exfiltration, SSRF, callbacks to metadata endpoints | `[execution]` and per-agent |
| `read_only_paths` / `writable_paths` | Tampering outside the workspace | `[execution]` |
| `allow_commands` / `deny_args_regex` | Arbitrary binaries and dangerous argument patterns | per-agent |
| `allow_cwd` | Running outside the intended project tree | per-agent |
| `max_runtime_ms` / `max_output_bytes` | Runaway processes, log-flood DoS | per-agent / `[execution]` |
| `requires_approval` | Unattended privileged actions | per-agent |
| Environment scrubbing | Credential theft via env | runner (always on) |

---

## Credential Storage & Permissions (architecture §13.1)

The daemon owns all secrets; the coding agent sees none of them. On Linux:

```bash
chmod 0700 ~/.local/share/mx-agent
chmod 0600 ~/.local/share/mx-agent/session.json      # Matrix access/refresh token
chmod 0700 ~/.local/share/mx-agent/crypto-store      # E2EE device keys and Megolm sessions (SQLite)
chmod 0600 ~/.local/share/mx-agent/crypto-store-key  # Daemon-generated store passphrase (Secret-wrapped)
chmod 0600 ~/.local/share/mx-agent/signing_key.ed25519  # mx-agent Ed25519 signing identity
chmod 0600 ~/.local/share/mx-agent/trust.json        # Local trusted-key store
chmod 0600 ~/.config/mx-agent/policy.toml
```

The crypto store and its passphrase are created once on first authenticated startup and reused across restarts — the daemon resumes as the same E2EE device with its Megolm sessions without generating a new identity. The recovery key for server-side key backup (`mx-agent recovery enable`) is surfaced to the operator exactly once and is never persisted in clear or logged.

Tokens must **never** appear in environment variables, command arguments, logs, shell history, stdout/stderr, Matrix messages, or agent-readable config. (macOS should back tokens with Keychain; the project targets Unix — there is no Windows path.)

### E2EE device verification and key backup

```bash
# List peer devices with fingerprints and verification status
mx-agent device list --room '!workspace:matrix.org'

# Verify a peer device out-of-band (confirm fingerprint first)
mx-agent device verify --user @peer:hs --device DEVICEID \
  --manual --fingerprint 'ed25519:BASE64...'

# Interactive emoji/SAS (operator-attended)
mx-agent device verify --user @peer:hs --device DEVICEID

# Bootstrap cross-signing identity (idempotent)
mx-agent auth cross-signing bootstrap

# Enable server-side key backup — prints the recovery key ONCE; store it safely
mx-agent recovery enable
mx-agent recovery status

# After a re-provision: re-import keys
mx-agent recovery recover --recovery-key 'EsTL ...'
```

Device verification is advisory by default. To additionally require a verified sending device for execution, set `require_verified_device = true` in policy (per-room or per-agent). This can only *deny*, never grant — the signature → trust → policy gate remains the sole execution authority.

---

## Audit Logging (architecture §13.6)

Every privileged decision is logged locally, without secrets, to `~/.local/share/mx-agent/audit.log`:

```json
{
  "ts": "2026-06-02T12:00:00Z",
  "room": "!aBcDeF123:matrix.org",
  "requester": "@claude:matrix.org",
  "target": "developer-pi",
  "invocation_id": "inv_01HZ8QK3M9V0X2YJ4N6P7R5T8W",
  "command": ["npm", "test"],
  "decision": "allowed",
  "policy_rule": "rooms.!aBcDeF123.agents.@claude.allow_commands"
}
```

---

## Matrix Room Security (architecture §14)

- Private, invite-only rooms; E2EE enabled.
- History visibility: joined members only.
- Use Matrix **power levels** so only trusted agents can send `task`, `exec`, `call`, and `trust` events.
- One workspace room per repository/project; optional per-task rooms for highly sensitive work.

---

## See also

- How signatures and nonces ride on the wire: [[Stream & Protocol Spec|Stream-and-Protocol-Spec]]
- Why state is signed and versioned rather than flag-based: [[Core Concepts|Core-Concepts]]
- Guardrails specifically for autonomous AI agents: [[AI Agent Orchestration|AI-Agent-Orchestration]]
