# Fail Loudly on a Malformed `policy.toml` (distinct from absent → deny-all)

GitHub issue: #350 — `type:feature area:policy priority:p2`

## Problem Statement

A **malformed** `policy.toml` silently degrades to the empty deny-all default
instead of producing a hard signal. Every daemon enforcement point resolves the
operator policy as:

```rust
let policy = Policy::default_path()
    .and_then(|path| Policy::load(path).ok())   // <-- .ok() swallows the error
    .unwrap_or_default();                         // <-- empty Policy == deny-all
```

`Policy::load` returns `Err(PolicyError)` for three distinct situations:

- the file **does not exist** (`PolicyError::Io` wrapping `ErrorKind::NotFound`),
- the file exists but **cannot be read** (other I/O error, e.g. permission denied),
- the file exists but is **unparseable / fails validation** (`PolicyError::Parse`
  or `PolicyError::Validation`).

`.ok()` collapses all three into "use the deny-all default." For *authorization*
this is the correct fail-closed posture in every case (nothing is permitted). But
an operator who fat-fingers a policy key, breaks the TOML, or writes an invalid
room id gets **total denial with no hard signal** — outwardly indistinguishable
from "policy applied and everything happens to be denied." There is currently no
`tracing` error, no refusal to start, and nothing in `daemon status` to tell the
operator their policy never loaded.

The **absent-file** case (no `policy.toml` → deny-all default) is correct and
intentional (the daemon must run before login and before any policy exists). It
must stay. Only the **present-but-unusable** case needs to fail loudly.

## Goals

- Distinguish, at the policy layer, "absent" (→ deny-all default, silent, fine)
  from "present but unreadable/unparseable/invalid" (→ a loud, operator-visible
  error). The new state must not change the *authorization* outcome — a malformed
  policy still authorizes nothing (deny-all, fail-closed).
- Refuse to start the daemon when the policy file is present but unusable, with a
  precise diagnostic naming the file path, the failure, and (for validation
  errors) the dotted field path the policy crate already produces. The operator
  who runs `daemon start` sees the precise reason immediately and with a non-zero
  exit code.
- For the case where the file is corrupted *after* the daemon is already running
  (policy is re-read lazily on every authorization), surface a **prominent,
  persistent warning through `daemon status`** and emit an `error`-level log at
  each lazy load, so the degradation is never silent at runtime either.
- Centralize the six copies of the silent `Policy::load(path).ok()` idiom behind
  one daemon helper, so the absent-vs-malformed distinction is enforced uniformly
  and cannot drift back to the silent form at one call site.
- Add tests covering: absent → deny-all silent default, malformed → daemon refuses
  to start, malformed → `daemon status` reports the warning, and the policy-crate
  absent-vs-malformed distinction.

## Non-Goals

- Changing the deny-by-default authorization semantics. A malformed (or absent)
  policy still permits nothing; this issue is about the *signal*, not the decision.
- Hot-reloading / watching `policy.toml` for changes. Policy stays lazily re-read
  per request/pass as today.
- Adding a standalone `mx-agent policy check` / `policy validate` CLI subcommand.
  It would be a natural follow-up (the policy crate already produces precise
  errors), but the issue does not ask for it; note it as future work only.
- Any change to the policy *schema* or to what counts as valid (the existing
  `Policy::validate` rules are unchanged).
- Windows support or any non-Unix path handling.

## Relevant Repository Context

mx-agent is a Rust Cargo workspace (MSRV 1.93, `unsafe_code = "forbid"`,
`missing_docs = "warn"` treated as error in CI). The CLI is stateless; the daemon
owns long-lived Matrix state, credentials, crypto, **policy**, and supervision.
Privileged requests are Ed25519-signed and checked against a local deny-by-default
policy; room membership never implies execution. Human-readable output is the
default with `--json` for automation. Unix only.

### Policy crate (`crates/mx-agent-policy`)

- `src/file.rs` defines `Policy`, the nested `ExecutionPolicy`/`RoomPolicy`/
  `AgentPolicy` structs (all `#[serde(deny_unknown_fields)]`), and the error type
  `PolicyError { Io { path, source }, Parse(String), Validation { path, message } }`.
- `Policy::default_path() -> Option<PathBuf>` resolves
  `MX_AGENT_CONFIG_DIR` → `$XDG_CONFIG_HOME/mx-agent` → `$HOME/.config/mx-agent`,
  joined with `policy.toml`; returns `None` if no config dir can be determined.
- `Policy::load(path) -> Result<Self, PolicyError>` does
  `read_to_string` → `Policy::parse` (which is `toml::from_str` → `validate`).
  Note: `load` maps **any** read error (including `NotFound`) into
  `PolicyError::Io { source: e.to_string() }`, discarding the `io::ErrorKind`, so
  today the absent case is not separable from other I/O errors at the type level.
- `Policy::default()` is the empty policy: no `rooms`, default `execution`. An
  empty policy authorizes nothing → deny-all. (`crates/mx-agent-policy/src/lib.rs`
  documents deny-by-default and `default_decision() == Decision::Deny`.)
- Tests are inline in `src/file.rs` under `#[cfg(test)] mod tests` and already
  cover parse/validation errors with precise dotted paths.

### The six silent call sites (`crates/mx-agent-daemon`)

All use the identical `Policy::default_path().and_then(|p| Policy::load(p).ok()).unwrap_or_default()` idiom:

- `src/exec.rs:1461` — `authorize_live_exec` (signed remote exec authorization).
- `src/exec_ipc.rs:672` — loopback / IPC exec confinement floor.
- `src/call.rs:477` — signed remote `call` authorization.
- `src/call_ipc.rs:134` — loopback / IPC `call` confinement floor.
- `src/scheduler_loop.rs:403` — per-pass policy load in the live scheduler. Its
  comment already states the intended behavior: *"an absent/invalid policy denies
  every action"* — confirming the deny-all-on-malformed authorization outcome is
  intentional; only the loud signal is missing.
- `src/approval.rs:992` — approval-decision handling (also reads
  `room.approvers`).

### Daemon lifecycle & status surface (`crates/mx-agent-daemon/src/lifecycle.rs`)

- The daemon does **not** load policy at startup today — it is resolved lazily at
  each of the six sites above. There is therefore a single clean place to add a
  startup gate (`run_foreground`) but no existing startup policy read to piggyback
  on.
- `run_foreground()` binds the IPC socket, writes the `daemon.json` status file
  (which is the readiness signal `start_background` polls for), reaps orphaned exec
  children, starts the `WorkerSupervisor`, then serves IPC.
- `start_background()` spawns `daemon start --foreground` detached (stdout/stderr →
  `daemon.log`) and polls up to 5s for the status file; on timeout it returns a
  generic `"daemon did not become ready within timeout"` error (a poor diagnostic
  if the child refused to start).
- `RunningStatus { running, pid, uptime_seconds, socket_path, version, sync:
  Option<SyncHealth> }` is the status payload, re-exported from the crate root
  along with `run_foreground`, `start_background`, `status`, `SyncHealth`,
  `SyncState`.
- The `daemon.status` IPC handler (in `dispatch`) builds `RunningStatus`, pulling
  `sync` health from the supervisor. **Precedent to follow:** the CLI's
  `daemon_status` (`crates/mx-agent-cli/src/cli.rs:3753`) already renders a
  degraded/stopped sync loop *prominently* (`sync: STOPPED (unhealthy …)`). The
  malformed-policy warning should reuse exactly this rendering pattern.
- `SharedHealth = Option<Arc<Mutex<SyncHealth>>>` is the existing model for a
  mutable health value surfaced through status; it is **not** needed here because
  `daemon.status` can re-resolve the policy on demand (see Proposed Implementation).

## Proposed Implementation

The recommended approach is a **hybrid that covers both lifecycles** — boot-time
and runtime — using one centralized resolver:

### 1. Policy crate: a clean absent-vs-present API

Add a non-breaking constructor that separates "absent" from "present but bad",
preserving `load`/`parse` as-is.

```rust
// crates/mx-agent-policy/src/file.rs
use std::io;

impl Policy {
    /// Load a policy only if the file exists.
    ///
    /// Returns `Ok(None)` when the file is **absent** (the deny-all default
    /// applies — this is the correct, silent fallback), `Ok(Some(policy))` when
    /// the file is present and valid, and `Err(PolicyError)` when the file is
    /// present but cannot be read, parsed, or validated. This lets callers fail
    /// loudly on a malformed policy while still treating a missing file as the
    /// intended deny-all default (issue #350).
    pub fn load_optional(path: impl AsRef<Path>) -> Result<Option<Self>, PolicyError> {
        let path = path.as_ref();
        match std::fs::read_to_string(path) {
            Ok(input) => Self::parse(&input).map(Some),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(PolicyError::Io {
                path: path.to_path_buf(),
                source: e.to_string(),
            }),
        }
    }
}
```

A file that exists but is unreadable (e.g. permission denied) is **not** "absent"
— it is an unusable, present file, so it returns `Err` and is treated as malformed
(fail loud). Only a genuine `NotFound` returns `Ok(None)`.

### 2. Daemon: one centralized resolver (new `policy` module)

Add `crates/mx-agent-daemon/src/policy.rs` (declared `pub mod policy;` and
re-exported from `lib.rs`) with a small resolution type and helpers:

```rust
use mx_agent_policy::{Policy, PolicyError};

/// Outcome of resolving the operator policy file.
pub enum PolicyResolution {
    /// No policy file present — the deny-all default applies (correct, silent).
    Absent,
    /// Policy file present, parsed, and validated.
    Loaded(Policy),
    /// Policy file present but unreadable / unparseable / invalid. Authorization
    /// still uses the deny-all default (fail-closed), but this is an error state
    /// that callers must surface loudly (issue #350).
    Malformed { path: PathBuf, display: String },
}

impl PolicyResolution {
    /// The policy to authorize against: the loaded policy, or the deny-all
    /// default for both the absent and malformed cases (fail-closed).
    pub fn into_policy(self) -> Policy { /* Loaded(p) => p, else Policy::default() */ }

    /// `Some(human message)` when the policy is malformed, else `None`.
    pub fn malformed_message(&self) -> Option<String> { /* ... */ }
}

/// Resolve the operator policy from its default path without side effects.
pub fn resolve_policy() -> PolicyResolution {
    match Policy::default_path() {
        None => PolicyResolution::Absent, // no config dir → nothing to be malformed
        Some(path) => match Policy::load_optional(&path) {
            Ok(None) => PolicyResolution::Absent,
            Ok(Some(p)) => PolicyResolution::Loaded(p),
            Err(e) => PolicyResolution::Malformed { path, display: e.to_string() },
        },
    }
}

/// Resolve the policy for an enforcement pass: like `resolve_policy`, but emits a
/// single `error`-level log when the policy is malformed so a runtime breakage is
/// never silent in the daemon log. Returns the policy to authorize against.
pub fn resolve_policy_for_enforcement(context: &str) -> Policy {
    let resolution = resolve_policy();
    if let Some(msg) = resolution.malformed_message() {
        tracing::error!(context, %msg,
            "policy file is present but unusable; authorizing nothing (deny-all) until it is fixed");
    }
    resolution.into_policy()
}
```

`PolicyError`'s `Display` already produces operator-friendly messages including
the dotted field path for validation errors (e.g.
`invalid policy at rooms."!abc".agents."@a".deny_args_regex[1]: invalid regular
expression: …`) and the TOML line/column for parse errors — so `display`/`%msg`
need no extra formatting. No secrets are involved (policy is non-sensitive
config), so logging the full message is safe.

### 3. Replace the six silent call sites

At each of the six sites, replace:

```rust
let policy = Policy::default_path()
    .and_then(|path| Policy::load(path).ok())
    .unwrap_or_default();
```

with:

```rust
let policy = crate::policy::resolve_policy_for_enforcement("exec.authorize");
```

(using a distinct `context` string per site, e.g. `"exec.authorize"`,
`"exec_ipc.floor"`, `"call.authorize"`, `"call_ipc.floor"`, `"scheduler.pass"`,
`"approval.decision"`). The authorization outcome is unchanged (still deny-all on
absent or malformed); the only behavioral change is the loud `error` log on
malformed. `approval.rs` keeps reading `policy.rooms.get(..).approvers` from the
returned `Policy` exactly as before.

### 4. Startup gate: refuse to start on a malformed policy (the loud signal)

In `run_foreground()` (`lifecycle.rs`), **before** writing the status file /
announcing readiness, resolve the policy once and refuse to start if it is
malformed:

```rust
if let PolicyResolution::Malformed { path, display } = crate::policy::resolve_policy() {
    tracing::error!(path = %path.display(), error = %display,
        "refusing to start: policy file is present but unusable; fix or remove it");
    return Err(io::Error::new(
        io::ErrorKind::InvalidData,
        format!("malformed policy {}: {display}", path.display()),
    ));
}
```

An **absent** policy (`Absent`) still starts normally (deny-all). Because policy
is independent of the Matrix session, this gate runs unconditionally (the daemon
that starts before login would otherwise deny-all silently the moment a request
arrives).

To give the operator a precise, immediate error (instead of the generic 5s
"did not become ready" timeout from the detached child), **also** pre-check in
`start_background()` before spawning the child, returning the same
`InvalidData` error early:

```rust
// in start_background(), right after ensure_safe_parent_dir(...)
if let PolicyResolution::Malformed { path, display } = crate::policy::resolve_policy() {
    return Err(io::Error::new(io::ErrorKind::InvalidData,
        format!("malformed policy {}: {display}", path.display())));
}
```

The CLI `daemon_start` already prints the `io::Error` from `start_background`, so
no CLI change is needed for the message to reach the operator; confirm the
non-zero exit path. The foreground gate remains the authoritative check (covers a
direct `daemon start --foreground` and defends against a TOCTOU edit between
pre-check and spawn).

### 5. Persistent runtime warning via `daemon status`

For a policy broken *after* the daemon is already up, extend the status surface.
`daemon.status` is operator-initiated and low-frequency, so it can re-resolve the
policy fresh (no shared mutable handle needed):

- Add a field to `RunningStatus`:
  ```rust
  /// Operator-policy health. Present only when the policy file is unusable.
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub policy: Option<PolicyStatus>,
  ```
  with a small serializable `PolicyStatus { state: "malformed", path: String,
  error: String }` (a single `malformed` state is enough; `absent`/`ok` are simply
  represented by `policy: None`, keeping the JSON unchanged for healthy daemons and
  backward-compatible).
- In the `daemon.status` dispatch handler, call `crate::policy::resolve_policy()`
  and populate `policy` only on `Malformed`.
- `lifecycle::status()` (the on-disk-status-file path used when the socket is
  unreachable) sets `policy: None` (it has no live view); the live IPC path is the
  authoritative one and the CLI already prefers it.
- In the CLI `daemon_status` renderer, surface the warning prominently right after
  `version`, mirroring the existing `sync: STOPPED` treatment, e.g.:
  ```text
    policy:  MALFORMED — authorizing nothing (deny-all) until fixed
      file:  /home/me/.config/mx-agent/policy.toml
      error: failed to parse policy: … at line 4 column 1
  ```
  `--json` carries the structured `policy` object unchanged.

This gives three independent loud signals: refuse-to-start at boot, an `error`
log at each lazy enforcement load, and a persistent `daemon status` warning.

## Affected Files / Crates / Modules

Read:
- `crates/mx-agent-policy/src/file.rs`, `src/lib.rs` — policy load/parse/validate,
  `PolicyError`, exports.
- `crates/mx-agent-daemon/src/lib.rs` — module list and re-exports.
- `crates/mx-agent-daemon/src/lifecycle.rs` — `run_foreground`, `start_background`,
  `RunningStatus`, `daemon.status` dispatch, `status()`.
- `crates/mx-agent-cli/src/cli.rs` — `daemon_status`, `daemon_start`,
  `query_status_over_ipc`.
- The six call sites (`exec.rs`, `exec_ipc.rs`, `call.rs`, `call_ipc.rs`,
  `scheduler_loop.rs`, `approval.rs`).

Modify:
- `crates/mx-agent-policy/src/file.rs` — add `Policy::load_optional` (+ tests).
- `crates/mx-agent-daemon/src/policy.rs` — **new** module: `PolicyResolution`,
  `PolicyStatus`, `resolve_policy`, `resolve_policy_for_enforcement`.
- `crates/mx-agent-daemon/src/lib.rs` — `pub mod policy;` + re-exports.
- `crates/mx-agent-daemon/src/lifecycle.rs` — startup gate in `run_foreground`,
  pre-check in `start_background`, `policy` field on `RunningStatus`, populate it
  in the `daemon.status` handler, `None` in `status()`.
- `crates/mx-agent-daemon/src/exec.rs`, `exec_ipc.rs`, `call.rs`, `call_ipc.rs`,
  `scheduler_loop.rs`, `approval.rs` — swap the silent idiom for the resolver.
- `crates/mx-agent-cli/src/cli.rs` — render the malformed-policy warning in
  `daemon_status`.

## CLI / API Changes

- **New public API (documented):** `Policy::load_optional` in `mx-agent-policy`;
  `PolicyResolution`, `PolicyStatus`, `resolve_policy`,
  `resolve_policy_for_enforcement` in `mx-agent-daemon` (re-exported from the crate
  root). All require `///` docs (CI treats `missing_docs` as an error).
- **`mx-agent daemon start`:** now exits non-zero with a precise diagnostic when
  `policy.toml` is present but unusable (previously it started and silently
  denied everything). No new flags.
- **`mx-agent daemon status`:** new optional `policy` block in `--json` output
  (omitted entirely when the policy is healthy/absent — backward compatible) and a
  prominent `policy: MALFORMED …` section in human output when malformed.
- No new commands. (A `mx-agent policy check` subcommand is explicitly out of
  scope; see Non-Goals.)

## Data Model / Protocol Changes

- No Matrix event-schema, signing, trust, or wire-protocol changes.
- IPC: the `daemon.status` response gains an **additive, optional** `policy`
  object (`{ state, path, error }`). Absent/healthy daemons omit it, so existing
  consumers and older CLIs are unaffected.
- Persisted `daemon.json` status file is unchanged (it never carried `sync` or
  `policy`; both are live-only over IPC).
- No change to `policy.toml`'s schema or validation rules.

## Security Considerations

- **Fail-closed is preserved end to end.** A malformed (or absent) policy still
  authorizes nothing — `into_policy()` returns the empty deny-all `Policy::default()`
  in both cases. This change only adds signal; it never widens authorization. The
  refuse-to-start gate is strictly *more* conservative (a broken-policy daemon
  cannot run at all).
- **No secrets in policy or logs.** `policy.toml` is non-sensitive operator config;
  `PolicyError`'s `Display` (file path, TOML location, dotted field path,
  validation message) contains no credentials, so logging it and returning it in
  `daemon status` is safe. Do not log file *contents* — only the structured error
  message the policy crate already produces.
- **CLI/daemon separation intact.** The CLI remains stateless: it does not read or
  parse `policy.toml`; the daemon owns policy resolution and merely reports a
  health string to the CLI over IPC.
- **No new escape hatch.** Do not add an env var to "ignore a malformed policy and
  start anyway" — that would reintroduce the exact silent footgun this issue
  closes. (Flag as an open question if a maintainer wants a narrow, logged opt-out
  later, but default to none.)
- Unix-only; no Windows assumptions. No `unsafe`. MSRV 1.93.

## Testing Plan

Policy crate (`crates/mx-agent-policy/src/file.rs`, inline `#[cfg(test)]`):
- `load_optional` on a non-existent path returns `Ok(None)` (absent → default).
- `load_optional` on a valid policy file returns `Ok(Some(_))` with expected
  fields.
- `load_optional` on a syntactically broken TOML returns `Err(PolicyError::Parse)`.
- `load_optional` on a file that parses but fails validation (e.g. a bad room id)
  returns `Err(PolicyError::Validation { path, .. })` with the precise dotted path.
- (Optional) a present-but-unreadable file returns `Err`, not `Ok(None)` — only
  `NotFound` is "absent". May be hard to assert portably; document the intent in a
  comment if skipped.

Daemon resolver (`crates/mx-agent-daemon/src/policy.rs`, inline tests using
`MX_AGENT_CONFIG_DIR` pointed at a temp dir):
- absent file → `PolicyResolution::Absent`, `into_policy()` deny-all,
  `malformed_message() == None`.
- valid file → `Loaded`, `into_policy()` round-trips the parsed rooms.
- malformed file → `Malformed`, `malformed_message()` is `Some(_)`, `into_policy()`
  is still the deny-all default.
  (Guard `MX_AGENT_CONFIG_DIR` mutation with a serial test mutex as the lifecycle
  tests already do; restore the env var after.)

Daemon lifecycle (`crates/mx-agent-daemon/src/lifecycle.rs` tests and/or a small
integration test):
- `start_background()` (or the `run_foreground` gate helper) returns
  `Err(InvalidData)` whose message contains the policy path and error when
  `MX_AGENT_CONFIG_DIR` holds a malformed `policy.toml`; starts normally when the
  file is absent or valid.
- `daemon.status` dispatch with a malformed policy populates
  `RunningStatus.policy = Some(PolicyStatus { state: "malformed", .. })`; with an
  absent/valid policy `policy` is `None` (and serializes away).

CLI:
- `daemon_status` rendering test (or a CLI smoke test) showing the `policy:
  MALFORMED …` human block and the `policy` object in `--json` when the daemon
  reports it; absent when healthy.

Regression:
- Confirm existing exec/call/scheduler/approval tests still pass — the deny-all
  authorization outcome on absent/malformed policy is unchanged.

## Documentation Updates

- `README.md` "Security posture" / status table: note that a malformed policy now
  **fails loudly** (daemon refuses to start; `daemon status` flags it), while an
  absent policy remains the intended deny-all default. Keep claims accurate — only
  describe behavior this change actually ships.
- `docs/architecture.md`: in the policy/§13 area and the `daemon.status` /
  lifecycle description, document the absent-vs-malformed distinction, the
  refuse-to-start gate, and the new optional `policy` field in the status payload.
- `docs/security-hardening.md`: under the policy section, state that a broken
  policy will not silently deny-all without signal — the daemon refuses to start
  and surfaces it in `daemon status`.
- `wiki/Security-and-Sandboxing.md` (source of truth for the wiki): mirror the
  README note if it covers policy loading.
- Help text / CLI reference: mention the new `policy` block in `daemon status`
  output if a reference doc enumerates fields.

## Risks and Open Questions

- **Behavior change at startup (intended).** A deployment whose `policy.toml` is
  currently malformed gets deny-all-while-running today; after this change the
  daemon **refuses to start**. This is the issue's explicitly preferred behavior
  and is strictly safer, but it is a visible change — call it out in the PR/release
  notes. There is no valid operating state in which a malformed policy should be
  ignored, so no opt-out is provided by default.
- **Opt-out env var?** Should there be a narrow, logged
  `MX_AGENT_ALLOW_MALFORMED_POLICY=1` that downgrades refuse-to-start to
  warn-and-deny-all (matching the project's pattern of narrow hatches like
  `MX_AGENT_ALLOW_UNSIGNED_RESULTS`)? Recommendation: **no** — it re-creates the
  silent footgun. Flag for maintainer confirmation.
- **Unreadable-but-present file** (permission denied, etc.) is treated as malformed
  (fail loud), not absent. Confirm this is desired (recommended: yes — a present
  file the daemon cannot read is a misconfiguration, not "no policy").
- **`daemon.status` re-reads the file** rather than caching the last lazy-load
  outcome. This is simpler and catches runtime corruption, but the reported state
  reflects the file *at status-query time*, which may differ from what the most
  recent authorization used. Acceptable for an advisory operator signal; note it.
- **TOCTOU between `start_background` pre-check and the foreground gate.** Mitigated
  by keeping the `run_foreground` gate authoritative; the pre-check is only a UX
  nicety for a precise immediate error.

## Implementation Checklist

1. Add `Policy::load_optional(path) -> Result<Option<Policy>, PolicyError>` to
   `crates/mx-agent-policy/src/file.rs` (NotFound → `Ok(None)`; other I/O →
   `Err(Io)`; parse/validation → `Err`). Document it. Add inline tests for absent,
   valid, parse-broken, and validation-broken inputs.
2. Create `crates/mx-agent-daemon/src/policy.rs` with `PolicyResolution`,
   `PolicyStatus`, `resolve_policy()`, and `resolve_policy_for_enforcement(context)`
   (logs `error!` once on malformed, returns deny-all default). Document all public
   items. Add inline tests (temp `MX_AGENT_CONFIG_DIR`, serial-guarded).
3. Declare `pub mod policy;` and re-export the new types from
   `crates/mx-agent-daemon/src/lib.rs`.
4. Replace the silent `Policy::default_path().and_then(|p| Policy::load(p).ok()).unwrap_or_default()`
   idiom at all six sites (`exec.rs:1461`, `exec_ipc.rs:672`, `call.rs:477`,
   `call_ipc.rs:134`, `scheduler_loop.rs:403`, `approval.rs:992`) with
   `crate::policy::resolve_policy_for_enforcement("<context>")`, one distinct
   context label each. Verify `approval.rs` still reads `approvers` from the result.
5. Add the startup gate to `run_foreground()` (refuse to start with
   `io::Error::InvalidData` + `error!` log on `Malformed`; `Absent`/`Loaded`
   proceed), before writing the status file.
6. Add the same pre-spawn `Malformed` check to `start_background()` so the operator
   gets the precise error immediately instead of the 5s readiness timeout.
7. Add `policy: Option<PolicyStatus>` to `RunningStatus` (`#[serde(default,
   skip_serializing_if = "Option::is_none")]`); populate it via
   `resolve_policy()` in the `daemon.status` dispatch handler; set `None` in
   `lifecycle::status()`.
8. Update the CLI `daemon_status` renderer to print a prominent `policy:
   MALFORMED …` block (file + error) in human mode, mirroring the `sync: STOPPED`
   treatment; `--json` passes the object through unchanged.
9. Add lifecycle/IPC tests: refuse-to-start on malformed, start on absent/valid,
   `daemon.status` reports the warning on malformed and omits it otherwise. Add a
   CLI rendering test for the human + `--json` surfaces.
10. Update docs: `README.md` status/security note, `docs/architecture.md`
    (policy + `daemon.status`), `docs/security-hardening.md`, and the
    `wiki/Security-and-Sandboxing.md` mirror if applicable.
11. Run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D
    warnings`, `cargo test --all`, `cargo build --all`. Ensure no `missing_docs`
    warnings on the new public items.
