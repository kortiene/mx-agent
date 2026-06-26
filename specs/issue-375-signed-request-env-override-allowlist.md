# Constrain signed-request `env` overrides on the remote exec path (issue #375)

## Problem Statement

The child-environment allowlist (`sanitize_env`, architecture §13.4) only filters
the **inherited** daemon environment. The caller-supplied `env` overrides carried
by a signed `com.mxagent.exec.request.v1` are layered in **unconditionally** — they
win over both the inherited-env allowlist and the secret denylist.

On the remote exec path those overrides come verbatim from the signed
`ExecRequest.env` map. The `env` field is covered by the request's Ed25519
signature (the `signature` field is excluded from the signed bytes — see
`build_signed_exec_request`, `crates/mx-agent-daemon/src/exec.rs:515-545`), so it
is fully attacker-chosen by whoever holds the signing key. The result: a
trusted-but-malicious peer, or a holder of a compromised signing key that is
already policy-authorized to `exec`, can set arbitrary environment variables on
the spawned child — including loader-control variables (`LD_PRELOAD`,
`LD_LIBRARY_PATH`, `LD_AUDIT`, `DYLD_*` on macOS) and `PATH` — none of which is in
the env allowlist.

Because the sanitized map is fed to `Command::env_clear().envs(env)`
(`runner.rs:495-496`), the injected key becomes part of the child's **complete**
environment (replace, not merge). This turns an authorized `exec` into arbitrary
code execution outside the requested argv, can defeat sandbox path assumptions,
and re-introduces secret-shaped variables that the inherited-env scrubber exists
to strip.

This is **hardening**, not an open RCE: the `env` map is part of the
Ed25519-signed, sender-bound, policy-gated request, so an anonymous room member
cannot reach it (cf. #348 result-plane signing, #366 sender-bound exec
authorization). It complements #366 — #366 fixed *who* may request remote
`call`/`exec`; this constrains *what* environment an already-authorized requester
may inject. Tracked as p2 in a public issue per repo convention.

### Current behavior (evidence)

- `crates/mx-agent-daemon/src/runner.rs:143-146` — `sanitize_env` filters the
  inherited env to `is_allowed_var(name) && !is_secret_var(name)`.
- `crates/mx-agent-daemon/src/runner.rs:147-149` — it then `env.insert(name,
  value)` for every override **unconditionally** (no allowlist or secret check on
  override keys). The doc comment (`runner.rs:127-130`) states this is intentional:
  overrides are "applied unconditionally … because the caller has made a
  deliberate, per-request choice." That rationale holds for a local operator, not
  for a remote requester.
- `crates/mx-agent-daemon/src/runner.rs:811-820` — the existing test
  `sanitize_env_honours_explicit_secret_override` asserts that an override of
  `GITHUB_TOKEN` wins "even over the denylist", confirming overrides are unfiltered
  by design.
- `crates/mx-agent-daemon/src/runner.rs:468` + `:495-496` — the sanitized map is
  fed to `Command::env_clear().envs(env)`, i.e. it becomes the child's **complete**
  environment (replace, not merge), so an injected key is the only value the child
  sees.
- `crates/mx-agent-daemon/src/exec.rs:1775-1779` (`run_controlled_exec`) and
  `crates/mx-agent-daemon/src/exec.rs:2047-2051` (`run_controlled_pty_exec`) — both
  remote live paths build `RunSpec { env: request.env.clone(), env_allowlist:
  allowance.env_allowlist.clone(), .. }`. `env_allowlist` comes from policy, but
  `env` (the overrides) comes straight from the request and is never intersected
  with it.
- `crates/mx-agent-protocol/src/schema.rs:66-67` — `env: BTreeMap<String, String>`
  is a signed field of `ExecRequest`.

There is no env-key denylist applied to overrides anywhere between the wire and
the child; `SECRET_VARS` / `is_secret_var` only gate inherited vars
(`runner.rs:67-114`). `CallRequest` (`mx-agent-protocol/src/schema.rs`) carries
**no** `env` field, so the named-`call` path is not affected — the
override-injection wire surface is exclusively `ExecRequest.env`.

## Goals

- A remote, signed `exec.request` can **no longer** inject loader-control
  (`LD_*`, `DYLD_*`), `PATH`, or secret-named environment variables into the
  spawned child, regardless of who signed it.
- Caller-supplied `env` override **keys** on the remote path are constrained to a
  policy-controlled set; un-permitted keys are rejected fail-closed.
- The failure mode is an explicit, signed `com.mxagent.exec.rejected.v1` with a
  stable, machine-readable reason — not a silent drop — so a misconfigured
  requester gets a clear error.
- The constraint is enforced at the single live-exec authorization choke point
  (`authorize_live_exec`), so it covers the direct batch path, the direct
  interactive PTY path, and the approval-release path uniformly.
- The local-operator escape hatch (in-process loopback `exec --env K=V`) is
  preserved: the unconditional-override semantics may stay for the local path.
- New env-screening logic is a pure, unit-testable function; behavior is covered
  by unit tests and a live regression mirroring the seam #366/#367/#368 escaped
  through.

## Non-Goals

- Changing the **inherited**-env allowlist/secret-scrub behavior of `sanitize_env`
  (already correct; `runner.rs:143-146`).
- Constraining the **local loopback** override path (`exec_ipc.rs` loopback
  `RunSpec` assembly, `pty_ipc.rs` loopback PTY assembly) — the operator's
  deliberate per-request choice stays (issue #314). Only the remote signed path is
  tightened.
- Changing the named-`call` path — `CallRequest` carries no caller `env` overrides
  (tool env comes from the tool descriptor + policy).
- The default **local** task-dispatch runner (`task_dispatch.rs`
  `default_command_runner`) — it runs locally-authored, locally-signed task actions
  in-process, analogous to the loopback escape hatch. (The
  `MX_AGENT_TASK_DISPATCH=matrix` path is automatically covered: it builds and
  sends a signed `ExecRequest` that the *target* daemon authorizes through the same
  live-exec gate fixed here.) See Risks/Open Questions for whether to extend the
  screen to the local task action `env` in a follow-up.
- Encryption/transport changes; this is an authorization gate, not a confidentiality
  change.
- Windows support (Unix only).

## Relevant Repository Context

- **Crates** (`Cargo.toml`): `mx-agent-daemon` owns the runner and exec
  authorization; `mx-agent-protocol` owns `ExecRequest`; `mx-agent-policy` owns
  `Allowance`; `mx-agent-telemetry` owns `is_sensitive_key`. The fix lands almost
  entirely in `mx-agent-daemon` (runner + exec), with doc updates.
- **Security posture** (README "Security posture", architecture §13): zero-trust,
  deny-by-default. Room membership grants nothing; every privileged request is
  Ed25519-signed and checked against local policy. Child processes start from an
  **environment allowlist** with secret scrubbing. This change extends that
  allowlist philosophy to caller-supplied overrides on the remote path.
- **Inherited-env scrub** (`runner.rs:62-157`): `DEFAULT_ALLOWED_VARS` (13 benign
  names incl. `PATH`, `HOME`, `TERM`, `LANG`, `TMPDIR`, `PWD`), `SECRET_VARS`,
  `SECRET_PREFIXES` (`AWS_`/`GOOGLE_`/`AZURE_`), `is_secret_var`, `sanitize_env`,
  `is_allowed_var`. Note the established defense-in-depth pattern: an allowlisted
  inherited name is still dropped if it is a secret (`runner.rs:145`). The new
  override screen mirrors this carve-out idea.
- **Live-exec authorization choke point** (`exec.rs`): `authorize_live_exec`
  (`exec.rs:1481-1556`) returns `Result<(ExecRequest, Allowance), ExecRejection>`
  and is the single place the post-policy gates run (`enforce_verified_device`
  at `:1534`, `enforce_sandbox_floor` at `:1548`). It is called by
  `handle_live_exec_request` for direct requests **and** by the approval-release
  path (`exec.rs:1233-1245`). Both `run_controlled_exec` and
  `run_controlled_pty_exec` are reached only after `authorize_live_exec` succeeds
  (via `spawn_authorized_live_exec` → batch or `run_pty_exec_task`). This is the
  natural location for the new gate.
- **Rejection model** (`exec.rs:338-431`): `ExecRejection` enum + stable
  `reason()` strings, `Display`, `emit_exec_rejected`, and `audit_exec_rejection`.
  Post-policy gates (`UnverifiedDevice`, `SandboxRequired`) are audited in the
  rejection match arms at `exec.rs:909` and `exec.rs:1252`.
  `enforce_sandbox_floor` / `check_sandbox_floor` (`exec.rs:1605-1658`) is the
  template "post-policy gate that can only deny" to copy.
- **Policy `Allowance`** (`mx-agent-policy/src/engine.rs`): `env_allowlist:
  Vec<String>` resolved from `execution.env_allowlist`, empty by default
  (deny-by-default). Documented as "names the child may inherit from the daemon
  beyond the built-in safe defaults".
- **Conventions**: `unsafe` forbidden workspace-wide (`Cargo.toml`
  `unsafe_code = "forbid"`); `missing_docs` is a warning treated as error in CI —
  document new public items. MSRV is **1.93** (`Cargo.toml` `rust-version = "1.93"`;
  the historically declared 1.74 was never actually built — matrix-sdk 0.18 floors
  it at 1.93). Pure functions for env rules so they're unit-testable without
  spawning (the established `sanitize_env` / `restrictions_for` style).
  Human-readable + `--json` output preserved; never log secrets — log variable
  **names** only, never values.

## Proposed Implementation

Add a deny-by-default screen on remote override **keys** at the live-exec
authorization choke point, rejecting the whole request with a new, stable
rejection reason when any override key is not permitted. Keep `sanitize_env`
unchanged so the local escape hatch is preserved.

### 1. Pure screening predicate (`crates/mx-agent-daemon/src/runner.rs`)

Co-locate the new rules with the existing env logic so all env policy lives in one
module and is unit-testable without spawning.

- Add a loader-control predicate:

  ```rust
  /// Environment variable names that control the dynamic loader / binary
  /// resolution and must never be set by a *remote* requester, because they can
  /// redirect code execution outside the requested argv or defeat sandbox path
  /// assumptions: the glibc loader (`LD_*`, e.g. `LD_PRELOAD`, `LD_LIBRARY_PATH`,
  /// `LD_AUDIT`), the macOS dyld loader (`DYLD_*`, e.g. `DYLD_INSERT_LIBRARIES`),
  /// and `PATH` (which changes which binary argv[0] resolves to). Prefix matching
  /// on `LD_`/`DYLD_` is used so future loader knobs are covered automatically
  /// (fail-safe: it can only widen what is denied).
  pub fn is_loader_control_var(name: &str) -> bool {
      name == "PATH" || name.starts_with("LD_") || name.starts_with("DYLD_")
  }
  ```

- Add the screen returning the first offending key (so the caller can name it in
  the log / rejection), deny-by-default:

  ```rust
  /// Screen caller-supplied `env` override **keys** from a *remote* (signed)
  /// request against what policy permits, returning the first key that must not
  /// be honored (or `None` when all keys are permitted).
  ///
  /// A remote override key is permitted only when ALL hold:
  /// 1. it is not a known secret (`is_secret_var`) — secrets are never
  ///    re-introducible, mirroring the inherited-env scrub;
  /// 2. it is not a loader-control variable (`is_loader_control_var`) — these are
  ///    denied even if allowlisted, because a remote requester has no legitimate
  ///    need to replace the loader/`PATH` the daemon already provides; and
  /// 3. its name is in the policy `env_allowlist` OR a built-in safe default
  ///    (`DEFAULT_ALLOWED_VARS`) — so benign `TERM`/`LANG`/`TMPDIR`/operator-
  ///    allowlisted overrides still work, but anything unlisted is denied.
  ///
  /// Deny-by-default: with an empty `env_allowlist`, only the (non-loader,
  /// non-secret) built-in safe names may be overridden. Local-operator overrides
  /// do not flow through here — only the remote assembly sites call it.
  pub fn first_disallowed_remote_override<'a>(
      env: &'a BTreeMap<String, String>,
      extra_allowed: &[String],
  ) -> Option<&'a str> {
      let extra: BTreeSet<&str> = extra_allowed.iter().map(String::as_str).collect();
      env.keys()
          .map(String::as_str)
          .find(|name| {
              is_secret_var(name)
                  || is_loader_control_var(name)
                  || !(DEFAULT_ALLOWED_VARS.contains(name) || extra.contains(name))
          })
  }
  ```

  Notes:
  - `PATH` is in `DEFAULT_ALLOWED_VARS` (rule 3 would admit it) but the
    loader-control check (rule 2) denies it — the carve-out is intentional and is
    the issue's "PATH-sensitivity" concern. The daemon's inherited `PATH` already
    reaches the child via `sanitize_env`, so denying the override does not break
    normal resolution.
  - Iterate keys deterministically (`BTreeMap` is ordered) so the named offending
    key is stable across runs (matters for the test and the log line).

### 2. New rejection reason (`crates/mx-agent-daemon/src/exec.rs`)

Add to the `ExecRejection` enum (`exec.rs:343-381`):

```rust
/// A signed `exec.request` carried an `env` override key that policy does not
/// permit a remote requester to set (a secret, a loader-control variable such
/// as `LD_PRELOAD`/`DYLD_*`/`PATH`, or a name absent from the env allowlist).
/// A post-policy gate applied once the allowance is known; like the
/// verified-device and require-sandbox gates it can only deny (issue #375).
EnvOverrideNotAllowed {
    /// The offending variable **name** (never its value — values may be
    /// secret-shaped). Carried for the daemon log / `Display` only; the emitted
    /// machine-readable `reason()` stays generic.
    var: String,
},
```

- `reason()` (`exec.rs:385-398`): return the stable string
  `"env_override_not_allowed"` (no variable name — keep the emitted reason
  generic and value-free, matching `untrusted_key` / `wrong_target`).
- `Display` (`exec.rs:401-428`): `write!(f, "exec request env override {var:?} is
  not permitted for a remote requester")` — the name only, never the value.

### 3. Wire the gate into `authorize_live_exec` (`crates/mx-agent-daemon/src/exec.rs:1515-1555`)

Immediately after the allowance is resolved by
`authorize_exec_request_with_allowance` (`:1515-1523`) and alongside the other
post-policy gates (after `enforce_verified_device` at `:1534`, near
`enforce_sandbox_floor` at `:1548`), add:

```rust
// Post-policy env-override screen (issue #375): a signed remote request may not
// inject loader-control (`LD_*`/`DYLD_*`/`PATH`), secret-named, or un-allowlisted
// `env` override keys into the child, even from a trusted signer. The
// authoritative inherited-env scrub (`sanitize_env`) does not gate override keys
// — the local operator's deliberate `--env` choice stays unconditional — so the
// remote path is screened here, fail-closed, before the request can spawn.
if let Some(var) = crate::runner::first_disallowed_remote_override(
    &request.env,
    &allowance.env_allowlist,
) {
    tracing::warn!(
        invocation_id = %request.invocation_id,
        requesting_agent = %request.requesting_agent,
        target_agent = %request.target_agent,
        var = %var,
        "rejecting exec: env override key is not permitted for a remote requester"
    );
    return Err(ExecRejection::EnvOverrideNotAllowed { var: var.to_string() });
}
```

Note that `request.env` is borrowed before the `var.to_string()` allocation, so
ownership across the early-return is clean (the returned `&str` borrows `request`,
which is owned locally by this point). Because both `run_controlled_exec` and
`run_controlled_pty_exec` are reached only through `authorize_live_exec` (direct
dispatch *and* approval-release re-auth), this single gate covers all remote spawn
paths. No change is needed at the `RunSpec` assembly sites (`exec.rs:1775`/
`exec.rs:2047`) — they only execute after the gate passes.

### 4. Audit the new rejection

In both rejection match arms that audit post-policy denials
(`handle_live_exec_request` at `exec.rs:909` and the approval-release path at
`exec.rs:1252`), add `ExecRejection::EnvOverrideNotAllowed { .. }` to the
`UnverifiedDevice | SandboxRequired` arm so the denial is audited via
`audit_exec_rejection` like the other post-policy gates. The non-sensitive
`tracing::warn!` lives at the gate (step 3) and logs the room/requester/target/
invocation ids and the offending variable **name** (never the value), consistent
with the established non-sensitive log posture.

### Approach trade-off (recorded)

The issue offered two mechanisms: (a) a denylist on override keys, or (b)
intersecting `request.env` keys with the policy allowlist. The recommendation
above is the **hybrid**: allowlist-intersection (fail-closed, complete, matches
the deny-by-default ethos) *plus* a loader/secret denylist carve-out (so `PATH`
and loader knobs are denied even when present in `DEFAULT_ALLOWED_VARS` or
explicitly allowlisted). Placing it at the assembly choke point (not inside
`sanitize_env`) is what preserves the local escape hatch, because only the remote
path knows it is remote.

## Affected Files / Crates / Modules

- `crates/mx-agent-daemon/src/runner.rs` — add `is_loader_control_var` and
  `first_disallowed_remote_override` (public, documented) + unit tests. Leave
  `sanitize_env` unchanged.
- `crates/mx-agent-daemon/src/exec.rs` — add `ExecRejection::EnvOverrideNotAllowed`
  variant, its `reason()`/`Display`, the gate call in `authorize_live_exec`, and
  the two audit match-arm additions; unit tests.
- `docs/architecture.md` — §13.4: document that remote-request `env` overrides are
  allowlist-constrained and that loader-control/secret keys are always denied on
  the remote path.
- `docs/security-hardening.md` — extend the "Child-process environment is an
  allowlist" section to cover remote override screening; note the reject-with-reason
  behavior.
- `wiki/Security-and-Sandboxing.md` — mirror the doc note (wiki source of truth;
  synced on merge to `main`).
- `README.md` — one-line addition under "Security posture" (the env-allowlist
  bullet) noting remote override keys are constrained.
- `crates/mx-agent-daemon/tests/matrix_integration.rs` — live regression (a signed
  remote `exec.request` carrying `LD_PRELOAD` is rejected and never spawns).
- Reference only (no change expected): `mx-agent-policy/src/engine.rs`
  (`Allowance.env_allowlist`), `mx-agent-protocol/src/schema.rs` (`ExecRequest.env`),
  `exec_ipc.rs` / `pty_ipc.rs` loopback specs (escape hatch unchanged).

## CLI / API Changes

- **CLI**: none. No new flags or output fields. (Behavioral note: a remote
  `exec --env KEY=VALUE` whose `KEY` is not permitted now returns a rejection
  reason `env_override_not_allowed` instead of silently running — surfaced through
  the existing exec error/rejection rendering, human and `--json`.)
- **Public Rust API (within `mx-agent-daemon`)**: two new public, documented
  functions in `runner.rs` (`is_loader_control_var`, `first_disallowed_remote_override`)
  and one new `ExecRejection` variant (`EnvOverrideNotAllowed`). `ExecRejection`
  is a public enum, so the new variant is an additive API change; existing match
  arms on it in this crate must be updated (the two audit arms above; the
  `reason()` and `Display` matches are exhaustive and updated in step 2).
- **IPC protocol**: none — the same `com.mxagent.exec.rejected.v1` event carries
  the new `reason` string value; no schema field is added.

## Data Model / Protocol Changes

- **Event schema**: none. `ExecRequest` and `ExecRejected` structs are unchanged;
  only a new value (`"env_override_not_allowed"`) for the existing
  `ExecRejected.reason` string.
- **Policy**: no new field is required — the existing `execution.env_allowlist`
  doubles as the permitted set for remote overrides. (A dedicated
  `execution.request_env_allowlist` is an Open Question; default recommendation is
  to reuse `env_allowlist`.)
- **Persistence**: none.

## Security Considerations

- **Trust boundary**: the fix lives at the daemon-side live-exec authorization
  gate, after signature → trust → policy and alongside the existing post-policy
  gates. It can only *deny*, never grant — consistent with `enforce_verified_device`
  / `enforce_sandbox_floor`.
- **Fail-closed**: deny-by-default. With an empty `env_allowlist`, only non-loader,
  non-secret built-in safe names may be overridden by a remote requester; anything
  else is rejected. Loader-control (`LD_*`/`DYLD_*`/`PATH`) and secret names are
  denied even if allowlisted (defense-in-depth carve-out, mirroring the inherited
  secret-scrub).
- **No secret logging**: the rejection event's machine `reason()` is generic
  (`env_override_not_allowed`); the offending variable **name** appears only in the
  daemon's stderr `tracing` log and `Display`; the variable **value** is never
  logged or emitted. This avoids leaking a secret-shaped override value.
- **Daemon/CLI separation preserved**: the CLI remains stateless and never sees
  tokens/keys; the gate is daemon-only.
- **Signing/trust unchanged**: still requires a valid signature from a trusted,
  sender-bound, policy-authorized requester to even reach the gate. This narrows
  the blast radius of a trusted-but-malicious peer / compromised key; it is not a
  fix for key compromise itself.
- **Sandbox interaction**: denying remote `PATH`/`LD_*`/`DYLD_*` overrides closes
  a path to defeating sandbox binary/path assumptions and loader injection.
- **Local escape hatch intentionally retained**: loopback `exec --env` and the
  local task runner stay unconditional. Documented so the asymmetry is explicit.
- **Unix-only**: no Windows assumptions added.

## Testing Plan

Unit tests (pure, no spawning, no homeserver) — `crates/mx-agent-daemon/src/runner.rs`:

- `is_loader_control_var` recognizes `LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_AUDIT`,
  `DYLD_INSERT_LIBRARIES`, `DYLD_LIBRARY_PATH`, `PATH`; and does **not** match
  benign names (`CARGO_HOME`, `TERM`, `LANG`, `HOME`).
- `first_disallowed_remote_override` returns the offending key for each of:
  `{LD_PRELOAD}`, `{DYLD_INSERT_LIBRARIES}`, `{PATH}` (even though `PATH` is a
  built-in default), `{GITHUB_TOKEN}` (secret), `{MY_UNLISTED_VAR}` (not
  allowlisted).
- `first_disallowed_remote_override` returns `None` for permitted sets:
  `{TERM, LANG}` (built-in safe), `{CARGO_HOME}` when `env_allowlist =
  ["CARGO_HOME"]`, and an empty override map.
- A `CARGO_HOME` override is permitted only when allowlisted (deny-by-default):
  returns the key with empty allowlist, `None` once allowlisted.
- Loader/secret carve-out beats the allowlist: `{LD_PRELOAD}` / `{GITHUB_TOKEN}`
  are still rejected even when those names appear in `env_allowlist`.

Unit tests — `crates/mx-agent-daemon/src/exec.rs`:

- `ExecRejection::EnvOverrideNotAllowed { .. }.reason() == "env_override_not_allowed"`
  (stability test, mirroring the existing `reason()` stability tests).
- `Display` for the variant contains the variable name and never the value.
- A focused test that an `ExecRequest` built via the existing test helpers
  (`test_key`/`options`/`signed_request`) with `env: {"LD_PRELOAD": "/tmp/evil.so"}`
  and an allowance (`env_allowlist = []`) is rejected by the screen, and that the
  same request with only a benign/allowlisted override passes the screen.
  (Exercise the pure predicate directly when `authorize_live_exec` is not unit-
  reachable without a `Room`; the live test below covers the end-to-end gate.)
- Belt-and-suspenders: confirm the **local** semantics are unchanged — the
  existing `sanitize_env_honours_explicit_secret_override` (`runner.rs:811`) and
  `sanitize_env_applies_overrides` (`runner.rs:799`) tests still pass (the screen is
  not in `sanitize_env`).

Live integration test (`#[ignore]`d, `crates/mx-agent-daemon/tests/matrix_integration.rs`):

- Mirroring the seam #366/#367/#368 escaped through (CLI→socket→dispatch→Matrix
  exec): a signed remote `exec.request` whose `env` contains `LD_PRELOAD` (and a
  variant with `PATH`, and one with a secret-named key) is **rejected** with a
  `com.mxagent.exec.rejected.v1` carrying `reason == "env_override_not_allowed"`,
  and **no child runs** (no `exec.accepted`/`exec.finished`, env never observed).
  Add alongside the existing remote-exec policy-denial assertions in this suite.
- Positive case: a remote `exec.request` with a `TERM`/operator-allowlisted
  override runs normally and the override reaches the child env.

Run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`,
`cargo test --all`; live suite via `scripts/matrix_integration_test.sh`.

## Documentation Updates

- `docs/architecture.md` §13.4 (Environment Scrubbing): add that on the remote
  signed-request path, caller-supplied `env` override **keys** are constrained to
  `execution.env_allowlist ∪ DEFAULT_ALLOWED_VARS`, with loader-control
  (`LD_*`/`DYLD_*`/`PATH`) and secret names always denied; an un-permitted key
  rejects the request (`exec.rejected`, `reason: env_override_not_allowed`). State
  the local loopback override path is unchanged.
- `docs/security-hardening.md`: extend the "Child-process environment is an
  allowlist" section with the remote-override rule and the reject-with-reason
  failure mode; add a "safe vs unsafe" note that allowlisting a name now also lets
  a remote requester *override* it.
- `wiki/Security-and-Sandboxing.md`: mirror the architecture/hardening note (wiki
  source of truth; synced on merge to `main`).
- `README.md` "Security posture": amend the environment-allowlist bullet to note
  remote override keys are constrained (one clause; do not over-claim).
- Document the two new public `runner.rs` functions and the new `ExecRejection`
  variant (CI treats `missing_docs` as an error).

## Risks and Open Questions

- **Behavior change for remote `--env` (compatibility)**: today a trusted remote
  requester can set any `env` override; after this, only allowlisted/built-in-safe
  (non-loader, non-secret) keys are honored, else the request is rejected. This is
  the intended hardening but is a breaking change for any deployment relying on
  arbitrary remote `--env`. Mitigation: operators add the needed names to
  `execution.env_allowlist`; documented in the hardening guide and architecture.
  *Decision to confirm:* accept the reject-on-violation default (recommended) vs.
  silently drop offending keys (issue prefers reject; this spec recommends reject).
- **Reuse `env_allowlist` vs. a dedicated policy field**: the spec reuses
  `execution.env_allowlist` as the permitted override set, overloading "may inherit"
  with "may be overridden by a remote requester." Cleaner alternative is a new
  `execution.request_env_allowlist` (separates the two semantics) at the cost of
  added policy surface + migration. Recommendation: reuse; flag for confirmation.
- **`PATH` and `DEFAULT_ALLOWED_VARS` carve-out**: the spec denies remote `PATH`
  override even though `PATH` is a built-in default (loader-control carve-out).
  Confirm this is acceptable (it should be — inherited `PATH` still reaches the
  child). Secondary question: should `HOME`/`PWD` (config-redirect potential) also
  be carved out of remote-overridable defaults, or is denying loader/`PATH`/secrets
  sufficient? Recommendation: start with loader/`PATH`/secrets; revisit `HOME` if
  warranted (note it in the doc).
- **Local task-action `env` (out of scope here)**: `task_dispatch.rs`
  `default_command_runner` passes a task action's `env` unconditionally. The
  `matrix` dispatch path is covered (it re-enters the live-exec gate on the
  target); the default local path runs locally-authored signed actions in-process.
  Evaluate in a follow-up whether task-action `env` from room state warrants the
  same screen (depends on the PL50 + signature + policy gating already on task
  state writes).
- **`authorize_live_exec` unit-testability**: it requires a `Room` (reads agent
  state), so the gate's end-to-end rejection is covered by the live suite; the
  pure predicate carries the unit coverage. Acceptable given the established
  testing split in this module.

## Implementation Checklist

1. `runner.rs`: add documented `pub fn is_loader_control_var(name: &str) -> bool`
   (`PATH`, `LD_*`, `DYLD_*`).
2. `runner.rs`: add documented `pub fn first_disallowed_remote_override(env,
   extra_allowed) -> Option<&str>` implementing the deny-by-default screen
   (secret OR loader-control OR not-in-(`DEFAULT_ALLOWED_VARS` ∪ `env_allowlist`)).
3. `runner.rs`: add unit tests for both functions (offending-key and permitted
   cases, loader/secret-beats-allowlist carve-out, deny-by-default).
4. `exec.rs`: add `ExecRejection::EnvOverrideNotAllowed { var: String }`; map
   `reason()` → `"env_override_not_allowed"`; add `Display` (name only, no value).
5. `exec.rs`: in `authorize_live_exec`, after the allowance is resolved and the
   verified-device/sandbox-floor gates, call `first_disallowed_remote_override`
   and return `EnvOverrideNotAllowed` on the first offending key, with a
   non-sensitive `tracing::warn!` (ids + variable name only).
6. `exec.rs`: add `EnvOverrideNotAllowed { .. }` to the post-policy audit match
   arms in `handle_live_exec_request` (`:909`) and the approval-release path
   (`:1252`) so the denial is audited.
7. `exec.rs`: add unit tests — `reason()` stability, `Display` no-value, and the
   focused screen test using existing `test_key`/`options`/`signed_request` helpers.
8. `matrix_integration.rs`: add the live regression — signed remote `exec.request`
   with `LD_PRELOAD` / `PATH` / secret-named override is rejected
   (`reason: env_override_not_allowed`) and never spawns; positive case for a
   permitted override.
9. Docs: update `docs/architecture.md` §13.4, `docs/security-hardening.md`,
   `wiki/Security-and-Sandboxing.md`, and the README security-posture bullet.
10. Run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D
    warnings`, `cargo test --all`; run the live suite via
    `scripts/matrix_integration_test.sh`. Confirm no `unsafe`, docs present, MSRV
    1.93 clean.
</content>
</invoke>
