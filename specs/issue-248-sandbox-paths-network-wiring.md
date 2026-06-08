# Wire sandbox filesystem-bind and network controls from policy into the runner, and honor the policy-selected backend on the task-dispatch path

## Problem Statement

mx-agent's sandbox backends are selectable by policy and recorded in the audit
log, and the process runner enforces the *baseline* controls (allowlist env
scrub, restricted cwd, wall-clock timeout, output cap, kill-process-group). But
the policy's **filesystem-bind** (`read_only_paths` / `writable_paths`) and
**network** controls are parsed and validated yet **never reach the runner**.
Two distinct gaps cause this:

1. **Policy → `Allowance` drop.** The policy file parses and validates
   `execution.read_only_paths` / `execution.writable_paths`
   (`crates/mx-agent-policy/src/file.rs:134-139,257-258`), but the resolved
   [`Allowance`](crates/mx-agent-policy/src/engine.rs:54-71) has **no fields for
   those paths**, so they can never be threaded to the runner.

2. **`Allowance` → `Restrictions` stub.** The runner builds
   [`Restrictions`](crates/mx-agent-sandbox/src/lib.rs:113-139) leaving
   `network` and the path lists at their `..Default::default()` values, with an
   explicit *"threading them from policy into the runner is a later step"*
   comment (`crates/mx-agent-daemon/src/runner.rs:292-302`). `allowance.network`
   is read **nowhere** in `exec.rs` / `runner.rs` / `task_dispatch.rs`.

The result: selecting `sandbox = "bubblewrap"` (or a container backend) produces
a wrapper that **confines nothing it was configured to confine** — it is built
with no `--ro-bind`/`--bind`/`--volume` for the configured paths and *always*
network-isolates (`--unshare-net` / `--network none`) regardless of
`network = "allow"`. Because an isolating backend binds *only* the configured
paths (plus `--chdir`/`--workdir` into the cwd), an empty path set means the cwd
and the program's own binary/libraries are not mounted, so the command also
**likely fails to run at all**.

Separately, the orchestrator/scheduler exec path **hardcodes the backend to
`Backend::None`** (`crates/mx-agent-daemon/src/task_dispatch.rs:135`), so signed,
policy-allowed auto-executed task DAGs run **unsandboxed** even when policy
selects a backend.

This is a config-vs-behavior mismatch: an operator who configures path/network
confinement gets neither the intended isolation nor (for an isolating backend) a
working command, with no error indicating the settings were ignored. The argv
builders themselves are real and correct
(`crates/mx-agent-sandbox/src/lib.rs:229-409`); **the gap is purely the wiring
from policy → `Allowance` → `Restrictions`, plus the task-dispatch backend
selection.**

## Goals

- Carry `read_only_paths` / `writable_paths` on the resolved `Allowance`,
  populated from `execution.read_only_paths` / `execution.writable_paths`.
- Thread `allowance.network` and the path lists into `Restrictions` in the
  runner so isolating backends bind the configured paths and honor
  `network = "allow"` (no `--unshare-net` / `--network none`) while remaining
  **fail-closed** (deny network when policy does not say otherwise).
- Make the **local task-dispatch exec path** honor the policy-selected backend,
  network, and paths instead of hardcoding `Backend::None`.
- Prove the wiring with tests that assert a `bubblewrap`/container policy
  actually produces the expected `--ro-bind`/`--bind`/`--volume`/network argv,
  and that `network = "allow"` is respected.
- Keep the change backward-compatible and fail-closed: existing call sites and
  the `none` backend behave exactly as before (network defaults to deny, no
  binds), and a missing/unset policy yields the current defaults.

## Non-Goals

- No new sandbox backend, and no changes to the `bwrap`/container **argv
  builders** themselves — they already emit the correct flags.
- No seccomp filtering, rlimit capping, or UID/GID remapping (still out of scope
  per the alpha known-limitations; the "sandbox is not a standalone security
  boundary" caveat stays true).
- No mapping of the currently-unimplemented `firejail` / `chroot` policy
  backends to a real backend (they continue to fall back to `Backend::None` via
  `sandbox_backend`); that is pre-existing behavior and a separate issue.
- No change to the **non-policy local loopback** exec/PTY IPC paths
  (`start_exec_loopback` in `exec_ipc.rs`, `pty_ipc.rs`) beyond what falls out of
  adding fields with safe defaults — those paths do not consult policy and are
  out of scope (see Risks/Open Questions).
- No auto-injection of the cwd into `writable_paths` (operators remain
  responsible for binding a working filesystem; see Risks/Open Questions).
- No change to large-output artifact handling, approval flow, or the signing /
  trust pipeline.

## Relevant Repository Context

- **Crates** (root `Cargo.toml`, workspace; MSRV 1.74; `unsafe_code = "forbid"`):
  - `mx-agent-policy` — pure deny-by-default policy engine. `Policy` parses/validates
    the TOML (`file.rs`); `evaluate_exec` / `evaluate_call` return
    `Outcome::Allow(Allowance)` / `Outcome::Deny(reason)` (`engine.rs`).
    `allowance_for(agent)` resolves the effective limits, already folding
    `execution` defaults with agent overrides for `sandbox` and `network`.
  - `mx-agent-sandbox` — backend abstraction. `Restrictions` is the centralized
    control set (`cwd`, `env`, `timeout`, `max_output_bytes`, `network`,
    `read_only_paths`, `writable_paths`). `Network` is `Allow`/`Deny`
    (`Default == Deny`, fail-closed). `Backend` is `None`/`Bubblewrap`/`Container`.
    `BubblewrapSandbox`/`ContainerSandbox`/`NoneSandbox` implement `Sandbox::prepare`,
    which already consume `Restrictions::network`/`read_only_paths`/`writable_paths`
    and have unit + (skip-gracefully) integration tests
    (`lib.rs:445-962`). `NoneSandbox` ignores network/paths by design.
  - `mx-agent-daemon` — owns the runner and dispatch:
    - `runner.rs`: `RunSpec` (what to run) → `build_command` builds a
      `tokio::process::Command` via `sandbox_for(spec.sandbox).prepare(argv,
      restrictions)`. **This is gap #2** — `Restrictions` is built with
      `..Default::default()` for network/paths.
    - `exec.rs`: the policy-mediated exec path. `authorize_exec_request_with_allowance`
      returns `(ExecRequest, Allowance)`. `run_controlled_exec` (batch + live)
      and `run_controlled_pty_exec` (interactive) build a `RunSpec` and already
      set `sandbox: sandbox_backend(allowance.sandbox)` and
      `env_allowlist: allowance.env_allowlist.clone()` — but **not** network/paths.
      Helper `sandbox_backend(Option<Sandbox>) -> Backend` lives here
      (`exec.rs:1458-1464`); there is **no** network-mapping helper yet.
    - `task_dispatch.rs`: `ExecTaskDispatcher` runs already-authorized exec task
      actions through the runner via an injectable `CommandRunner`.
      `default_command_runner` builds a `RunSpec` and **hardcodes
      `sandbox: Backend::None`** and empty env-allowlist/paths (**gap #3**).
      `ExecRunRequest` is the input to the injectable runner and carries only
      `command`/`cwd`/`env`/`timeout`.
    - `task_orchestrator.rs`: `process_one` authorizes (signature/trust →
      deny-by-default policy → approval → replay) then `claim`s and calls
      `dispatcher.dispatch(&claimed, &action, &invocation_id)`.
      `authorize_task_action` already calls the policy and currently extracts
      only `allowance.requires_approval` (returns `Ok(bool)`); the full
      `Allowance` is in scope there but discarded. The `TaskDispatcher::dispatch`
      trait signature does **not** carry the allowance.
    - `scheduler_loop.rs`: `RoutingDispatcher` fans `Tool`/`Exec` actions to
      `ToolTaskDispatcher`/`ExecTaskDispatcher` (or the Matrix-backed variants
      when `MX_AGENT_TASK_DISPATCH=matrix`).
    - `task_dispatch_matrix.rs`: `MatrixExecTaskDispatcher` routes the exec
      action over the **signed Matrix transport** to a remote daemon, which runs
      it through *its own* `exec.rs` pipeline — so the Matrix path's isolation is
      fixed by the `exec.rs` + `runner.rs` changes on the remote side; it builds
      no local `RunSpec` and needs no backend-selection change itself.
- **Docs**: architecture §13.5 shows the `[execution]` `read_only_paths` /
  `writable_paths` / `network` block as effective; `docs/security-hardening.md`
  and `wiki/Security-and-Sandboxing.md` document those keys as enforced
  (security-hardening.md:14 even asserts the machinery is "real and already
  enforced"). The alpha known-limitations
  (`docs/alpha-release-checklist.md:149-155`) correctly limits its claim to "no
  seccomp/rlimit/UID-remap"; it does **not** claim paths/network are unenforced.
- **Conventions**: `runner.rs` depends on `mx-agent-sandbox` (not
  `mx-agent-policy`), so the runner's `RunSpec` should carry sandbox-layer types
  (`mx_agent_sandbox::Network`, `PathBuf`), with the policy→sandbox mapping done
  at the `exec.rs` / `task_dispatch.rs` call sites that already depend on
  `mx-agent-policy`. Document all new public items (`missing_docs` is denied in
  CI). Pure helpers are unit-tested without spawning.

## Proposed Implementation

### 1. `Allowance` carries the path lists (`mx-agent-policy`)

In `crates/mx-agent-policy/src/engine.rs`:

- Add two fields to `Allowance` (which derives `Debug, Clone, PartialEq, Eq,
  Default`; `Vec<PathBuf>` is compatible):
  ```rust
  /// Filesystem paths an isolating sandbox binds read-only (architecture §13.5).
  /// Resolved from `execution.read_only_paths`. Ignored by the `none` backend.
  pub read_only_paths: Vec<std::path::PathBuf>,
  /// Filesystem paths an isolating sandbox binds writable (architecture §13.5).
  /// Resolved from `execution.writable_paths`. Ignored by the `none` backend.
  pub writable_paths: Vec<std::path::PathBuf>,
  ```
- Populate them in `allowance_for`:
  ```rust
  read_only_paths: self.execution.read_only_paths.clone(),
  writable_paths: self.execution.writable_paths.clone(),
  ```
  These are workspace-wide execution defaults (there is no per-agent override
  field for them in `AgentPolicy`, consistent with the existing schema), so they
  come straight from `self.execution`.
- Update the `Allowance` doc comment so it lists path confinement among the
  controls the runner must enforce.

### 2. Thread network + paths into `Restrictions` (`mx-agent-daemon/runner.rs`)

- Extend `RunSpec` with sandbox-layer fields (keep `RunSpec` policy-agnostic):
  ```rust
  /// Whether the command may reach the network. Only an isolating backend
  /// enforces this; the `none` backend ignores it (architecture §13.5).
  /// Defaults to [`Network::Deny`] (fail closed).
  pub network: mx_agent_sandbox::Network,
  /// Paths an isolating backend binds read-only into the sandbox.
  pub read_only_paths: Vec<PathBuf>,
  /// Paths an isolating backend binds writable into the sandbox.
  pub writable_paths: Vec<PathBuf>,
  ```
- In `impl Default for RunSpec`, default `network` to `Network::default()`
  (`Deny`) and the path vecs to empty. This **preserves today's behavior**: the
  pre-change `Restrictions { ..Default::default() }` already meant
  `network = Deny`, empty binds.
- Replace the "later step" block in `build_command` so the `Restrictions` are
  built from the spec:
  ```rust
  let restrictions = Restrictions {
      cwd: spec.cwd.clone(),
      env,
      timeout: spec.timeout,
      max_output_bytes: None, // enforced by the capture stage
      network: spec.network,
      read_only_paths: spec.read_only_paths.clone(),
      writable_paths: spec.writable_paths.clone(),
  };
  ```
  Remove the stale comment about threading being "a later step."
- **Testability seam:** extract the `Restrictions` construction into a small
  pure `pub(crate) fn restrictions_for(spec: &RunSpec, env: BTreeMap<String,
  String>) -> Restrictions` (or `fn restrictions_for(spec) -> Restrictions` that
  re-derives env via `sanitize_env`). This lets tests call
  `sandbox_for(spec.sandbox).prepare(spec.command.clone(),
  restrictions_for(spec))` and assert the resulting argv contains the expected
  flags without spawning. (`build_command` then calls this helper.)

### 3. Map policy network → sandbox network and thread at the exec call sites (`exec.rs`)

- Add a helper mirroring `sandbox_backend`:
  ```rust
  /// Map the policy network decision to the sandbox-layer setting, failing
  /// closed: an unset policy network denies (architecture §13.5).
  fn network_for(network: Option<NetworkPolicy>) -> mx_agent_sandbox::Network {
      match network {
          Some(NetworkPolicy::Allow) => mx_agent_sandbox::Network::Allow,
          Some(NetworkPolicy::Deny) | None => mx_agent_sandbox::Network::Deny,
      }
  }
  ```
- At both `RunSpec` build sites (`run_controlled_exec` ~`exec.rs:938` and
  `run_controlled_pty_exec` ~`exec.rs:1161`), add:
  ```rust
  network: network_for(allowance.network),
  read_only_paths: allowance.read_only_paths.clone(),
  writable_paths: allowance.writable_paths.clone(),
  ```
  (Both already set `sandbox` and `env_allowlist` from the allowance, so this
  completes the set.) Keep the trailing `..Default::default()`.

### 4. Honor the policy-selected backend on the task-dispatch path

Thread the resolved `Allowance` from the orchestrator into the dispatcher so the
local exec dispatcher can build a faithful `RunSpec`.

**`task_orchestrator.rs`:**
- Change `authorize_task_action` to return the resolved `Allowance` rather than
  just the `requires_approval` bool: `Result<Allowance, OrchestrationOutcome>`.
  - On `Outcome::Allow(allowance)` return `Ok(allowance)`.
  - When no policy is configured (`self.policy` is `None`) or no room is set,
    return `Ok(Allowance::default())` (preserves today's "no policy ⇒
    requires_approval = false, `Backend::None`, deny network, no binds").
  - On `Outcome::Deny` keep the existing block-and-error behavior.
- In `process_one`, read `requires_approval` from `allowance.requires_approval`
  and pass `&allowance` to dispatch.
- Extend the `TaskDispatcher::dispatch` trait to accept the allowance:
  ```rust
  fn dispatch(
      &mut self,
      task: &TaskState,
      action: &TaskAction,
      invocation_id: &str,
      allowance: &mx_agent_policy::Allowance,
  ) -> Result<TaskExecutionResult, TaskDispatchError>;
  ```

**`task_dispatch.rs`:**
- Add resolved sandbox fields to `ExecRunRequest` (it derives `Debug, Clone,
  PartialEq, Eq`; `Backend`/`Network`/`Vec<PathBuf>` are compatible):
  ```rust
  pub sandbox: mx_agent_sandbox::Backend,
  pub network: mx_agent_sandbox::Network,
  pub read_only_paths: Vec<PathBuf>,
  pub writable_paths: Vec<PathBuf>,
  pub env_allowlist: Vec<String>,
  ```
- In `ExecTaskDispatcher::dispatch`, populate them from the `allowance`
  (reusing the same `sandbox_backend` / `network_for` mapping — extract these
  into a shared location, e.g. a small `pub(crate)` module or re-export from
  `exec.rs`, to avoid duplication).
- In `default_command_runner`, build the `RunSpec` from the request instead of
  hardcoding `Backend::None`:
  ```rust
  sandbox: request.sandbox,
  network: request.network,
  read_only_paths: request.read_only_paths.clone(),
  writable_paths: request.writable_paths.clone(),
  env_allowlist: request.env_allowlist.clone(),
  ```
- `ToolTaskDispatcher::dispatch` accepts the new `allowance` param and ignores
  it (tools do not spawn a sandboxed process here).

**`scheduler_loop.rs`:** `RoutingDispatcher::dispatch` forwards the new
`allowance` argument to the inner tool/exec dispatchers unchanged.

**`task_dispatch_matrix.rs`:** `MatrixCallTaskDispatcher` /
`MatrixExecTaskDispatcher` accept the `allowance` param; the exec variant does
not need it locally (the remote daemon re-resolves policy and applies isolation
via its own `exec.rs`/`runner.rs`), so it ignores it. Confirm no behavior change
there.

**Optional consistency fixes (recommended, same class of bug):** the task exec
path currently also drops `allowance.env_allowlist` (uses `Vec::new()`) and does
not clamp the action timeout against `allowance.max_runtime_ms`. Threading the
allowance lets `default_command_runner` set `env_allowlist` from the allowance
(parity with `exec.rs`) and, if desired, clamp the timeout like `exec.rs` does
(`allowance.max_runtime_ms.unwrap_or(request.timeout)`). Keep these clearly
scoped; the path/network/backend wiring is the primary fix.

### Behavioral result

- `sandbox = "bubblewrap"` + `read_only_paths`/`writable_paths` → the wrapper is
  built with `--ro-bind <p> <p>` / `--bind <p> <p>` for each configured path and
  `--chdir <cwd>`.
- `sandbox = "docker"`/`"podman"` → `--volume <p>:<p>:ro` / `--volume <p>:<p>`
  and `--workdir <cwd>`, read-only root.
- `network = "allow"` → **no** `--unshare-net` (bwrap) / **no** `--network none`
  (container); unset or `network = "deny"` → network isolated (fail closed).
- `sandbox = "none"` (the built-in fallback) → unchanged (paths/network ignored).
- Auto-executed task DAGs now run under the policy-selected backend, not
  `Backend::None`.

## Affected Files / Crates / Modules

- `crates/mx-agent-policy/src/engine.rs` — `Allowance` fields + `allowance_for`;
  unit test.
- `crates/mx-agent-sandbox/src/lib.rs` — **no production change** (argv builders
  already correct); possibly an added wiring-level test is unnecessary here since
  builders are tested. Read for reference.
- `crates/mx-agent-daemon/src/runner.rs` — `RunSpec` fields + `Default` +
  `build_command`/`restrictions_for`; unit tests.
- `crates/mx-agent-daemon/src/exec.rs` — `network_for` helper; thread
  network/paths into the two `RunSpec` build sites.
- `crates/mx-agent-daemon/src/task_dispatch.rs` — `ExecRunRequest` fields,
  `ExecTaskDispatcher::dispatch`, `default_command_runner`, `ToolTaskDispatcher`
  signature; tests.
- `crates/mx-agent-daemon/src/task_orchestrator.rs` — `authorize_task_action`
  return type, `process_one` wiring, `TaskDispatcher` trait, test mocks
  (~lines 1574, 1587).
- `crates/mx-agent-daemon/src/scheduler_loop.rs` — `RoutingDispatcher::dispatch`
  + test mock (~line 1239) forward the allowance.
- `crates/mx-agent-daemon/src/task_dispatch_matrix.rs` — two `dispatch` impls
  accept the allowance param.
- Docs: `docs/architecture.md` (§13.5 — confirm now accurate),
  `docs/security-hardening.md`, `wiki/Security-and-Sandboxing.md`,
  `docs/alpha-release-checklist.md`, `README.md` status row (see Documentation
  Updates).

## CLI / API Changes

- **CLI surface: none.** No new flags, commands, or output formats. Human
  output and `--json` are unaffected.
- **Internal Rust API (within `mx-agent-daemon`, and `Allowance` in
  `mx-agent-policy`):**
  - `mx_agent_policy::Allowance` gains `read_only_paths` / `writable_paths`
    public fields (additive; constructed by the engine, consumed by the daemon).
  - `mx_agent_daemon::runner::RunSpec` gains `network` / `read_only_paths` /
    `writable_paths` fields (additive; defaults preserve behavior).
  - `mx_agent_daemon::task_dispatch::ExecRunRequest` gains sandbox-resolution
    fields.
  - `TaskDispatcher::dispatch` gains an `allowance: &Allowance` parameter
    (signature change across all impls/mocks — internal trait, not a stable
    public protocol).
  All new public items must carry doc comments (CI denies `missing_docs`).

## Data Model / Protocol Changes

- **None.** No Matrix event schema, IPC JSON-RPC, signing, or persistence
  changes. The policy **file format is unchanged** — `read_only_paths` /
  `writable_paths` / `network` already parse and validate today; this work only
  makes them take effect. The audit-log record (already including the selected
  `sandbox`) is unchanged.

## Security Considerations

- **Fail-closed network default.** `network_for(None)` and `RunSpec::default()`
  must resolve to `Network::Deny`. An unset or `deny` policy must never widen to
  network access; only an explicit `network = "allow"` removes isolation. This
  matches `Network::default() == Deny` in the sandbox crate.
- **No secret leakage.** Secret scrubbing is unchanged — `sanitize_env` /
  `is_secret_var` still run, and the container backend forwards only the
  already-sanitized env via `--env`. Path lists and the network flag carry no
  credentials; do not log raw env. Keep `Secret`/redaction patterns intact.
- **Daemon owns enforcement.** The CLI stays stateless; all policy resolution
  and isolation happen in the daemon. The coding agent never sees Matrix tokens
  or device keys; this change does not move any credential toward the CLI/agent.
- **Room membership ≠ execution.** Unchanged: signature/trust → deny-by-default
  policy → approval → replay all run *before* dispatch; this work only affects
  *how* an already-authorized command is isolated.
- **Auto-executed DAGs were previously unsandboxed.** Switching task-dispatch
  off `Backend::None` is a security *improvement*, but it changes runtime
  behavior for operators relying (knowingly or not) on no isolation — call this
  out in docs/changelog.
- **Operator footgun, not a regression.** With an isolating backend, a command
  fails if its cwd / program / libraries are not covered by the configured
  paths. This is by design (deny-by-default filesystem) and already true for the
  direct `exec` path; the runner does **not** silently inject paths. Document
  that `writable_paths`/`read_only_paths` must cover the working set, and surface
  the backend's spawn/exit error rather than masking it.
- **Unix only.** No Windows assumptions; bind/namespace semantics are Linux/Unix
  (`bwrap` is Linux; containers via Docker/Podman). No `unsafe`.

## Testing Plan

Unit tests (no spawning required for the wiring assertions):

- **policy/`engine.rs`**: extend an `allowance_for` test (or add one) asserting a
  policy with `execution.read_only_paths`/`writable_paths` yields an `Allowance`
  whose path vectors match; a policy without them yields empty vectors. Confirm
  `network` continues to resolve via agent-override-then-execution-default.
- **runner/`runner.rs`**: with the `restrictions_for` seam, assert
  `RunSpec { sandbox: Backend::Bubblewrap, network: Network::Deny,
  read_only_paths: [/usr,/lib], writable_paths: [/work], cwd: /work, .. }`
  prepares an argv containing `--ro-bind /usr /usr`, `--ro-bind /lib /lib`,
  `--bind /work /work`, `--chdir /work`, and `--unshare-net`; and that
  `network: Network::Allow` produces an argv **without** `--unshare-net`. Repeat
  for `Backend::Container` asserting `--volume …:ro`, `--volume /work:/work`,
  `--workdir /work`, `--read-only`, `--network none` (deny) / no `--network`
  (allow). Add a `Backend::None` case asserting paths/network are ignored (argv
  unchanged). (This satisfies proposed-work item #4.)
- **exec/`exec.rs`**: unit test `network_for` (`Allow→Allow`, `Deny→Deny`,
  `None→Deny`). If practical, extract a small `run_spec_for(request, allowance)`
  helper from the two async build sites so a test can assert the `RunSpec` built
  from an `Allowance` carries the sandbox/network/paths (otherwise assert via the
  runner-level test above plus the dispatcher test below).
- **task_dispatch/`task_dispatch.rs`**: with `ExecTaskDispatcher::with_runner`
  capturing the `ExecRunRequest`, assert that an exec action dispatched with an
  `Allowance { sandbox: Some(Bubblewrap), network: Some(Allow),
  read_only_paths, writable_paths, .. }` yields an `ExecRunRequest` carrying
  `Backend::Bubblewrap`, `Network::Allow`, and the path lists — proving the
  hardcoded `Backend::None` is gone. Add a case with a default/empty allowance
  asserting `Backend::None` + deny + empty paths (backward-compat).
- **task_orchestrator.rs / scheduler_loop.rs**: update the mock dispatchers to
  the new signature; add/extend a test asserting `process_one` passes the
  policy-resolved allowance to `dispatch` (e.g. a mock that records the received
  `allowance.sandbox`).

Integration tests (kept green where tooling is absent):

- The existing `mx-agent-sandbox` integration tests already exercise real
  `bwrap`/container behavior and skip gracefully; no new ones required, but
  optionally add a daemon-level test that runs a trivial command end-to-end
  under `Backend::Bubblewrap` with the cwd in `writable_paths` and the system
  paths in `read_only_paths`, skipping when `bwrap` is unusable (mirror
  `bwrap_usable()` in `lib.rs`).

Required checks must pass: `cargo fmt --check`,
`cargo clippy --all-targets --all-features -- -D warnings`, `cargo test --all`,
`cargo build --all`.

## Documentation Updates

- **`docs/architecture.md` §13.5** — verify the `[execution]` example now
  matches real behavior; no correction needed if it already presented the block
  as effective (it did). Optionally add a one-line note that paths/network are
  enforced only by isolating backends (`none` ignores them).
- **`docs/security-hardening.md`** — its claim that the sandbox machinery is
  "real and already enforced" (line ~14) and the `read_only_paths`/
  `writable_paths`/network tables become accurate; confirm wording and add a
  caution that the configured paths must cover the cwd/program for an isolating
  backend, else the command fails.
- **`wiki/Security-and-Sandboxing.md`** — confirm the implementation-status note
  and the `read_only_paths`/`writable_paths` rows reflect that these now take
  effect.
- **`docs/alpha-release-checklist.md` Known limitations** — the "Sandbox is not a
  security boundary on its own" item stays (no seccomp/rlimit/UID-remap). Do
  **not** add a "paths/network not yet enforced" limitation (the stopgap the
  issue proposed *if not implemented* is moot once this lands); if any such
  wording already exists elsewhere, remove it.
- **`README.md`** — the "Sandbox backends" status row already notes the backends
  are policy-selectable and not a standalone boundary; review for accuracy. No
  new capability claims beyond what this change delivers.
- Reference issue #248 in the PR (`Closes #248`).

## Risks and Open Questions

- **Trait signature blast radius.** Adding `&Allowance` to
  `TaskDispatcher::dispatch` touches every impl and test mock
  (`task_dispatch.rs`×2, `task_dispatch_matrix.rs`×2,
  `scheduler_loop.rs` RoutingDispatcher + test mock, `task_orchestrator.rs` test
  mocks). Mechanical but must be complete or it won't compile. *Alternative:*
  pass only the three resolved values (backend/network/paths) instead of the
  whole `Allowance` — narrower, but `Allowance` is the natural unit and also
  unlocks the env-allowlist/timeout parity fixes; recommend passing `&Allowance`.
- **Operator footgun (cwd not bound).** An isolating backend with a
  `writable_paths`/`read_only_paths` set that doesn't cover the cwd or the
  program will fail to run the command (this is the "likely fails to run real
  commands" symptom the issue calls out). **Decision needed:** keep strict
  (operator must list the cwd; recommended, least surprising security-wise) vs.
  auto-add the cwd to `writable_paths`. Recommendation: strict + clear docs;
  revisit auto-binding separately if it proves too sharp.
- **Behavior change for existing task DAGs.** Operators who selected an
  isolating backend in policy but relied on tasks running unsandboxed (because
  task-dispatch hardcoded `none`) will now get real isolation, which can break
  commands that need network or paths not listed. This is the intended fix;
  flag it in the PR description / changelog.
- **Non-policy loopback paths.** `start_exec_loopback` (`exec_ipc.rs`) and the
  PTY IPC path build `RunSpec` without an `Allowance` and do not consult policy.
  Adding `RunSpec` fields with safe defaults leaves them unchanged
  (`Backend::None`, deny, no binds). Confirm this is acceptable and out of scope;
  if those local loopback paths should also be policy-mediated, that is a
  separate issue.
- **`firejail` / `chroot` policy values.** These map to `Backend::None` via
  `sandbox_backend` today, so selecting them silently yields no isolation —
  unchanged by this work, but worth a follow-up issue/doc note so operators
  aren't surprised.
- **`Network` import location.** Keep `runner.rs` depending only on
  `mx-agent-sandbox` (`Network`, `PathBuf`); do the `NetworkPolicy → Network`
  and `Sandbox → Backend` mapping in `exec.rs`/`task_dispatch.rs` (which already
  depend on `mx-agent-policy`). Share `sandbox_backend`/`network_for` rather than
  duplicating.

## Implementation Checklist

1. `mx-agent-policy/src/engine.rs`: add `read_only_paths` / `writable_paths` to
   `Allowance`; populate from `self.execution` in `allowance_for`; update the
   `Allowance` doc comment; add/extend the `allowance_for` unit test.
2. `mx-agent-daemon/src/runner.rs`: add `network` / `read_only_paths` /
   `writable_paths` to `RunSpec`; update `impl Default` (network = `Deny`, empty
   vecs); extract `restrictions_for` and have `build_command` use it (remove the
   "later step" comment); add unit tests asserting the prepared argv for
   `Bubblewrap`, `Container`, and `None` under deny/allow.
3. `mx-agent-daemon/src/exec.rs`: add `network_for(Option<NetworkPolicy>) ->
   Network`; set `network` / `read_only_paths` / `writable_paths` from the
   allowance at both `RunSpec` build sites (`run_controlled_exec`,
   `run_controlled_pty_exec`); unit-test `network_for`.
4. `mx-agent-daemon/src/task_orchestrator.rs`: change `authorize_task_action` to
   return `Result<Allowance, OrchestrationOutcome>` (default `Allowance` when no
   policy/room); in `process_one` read `requires_approval` from the allowance and
   pass `&allowance` to `dispatch`; extend the `TaskDispatcher::dispatch` trait
   with `allowance: &Allowance`; update the in-file test mocks.
5. `mx-agent-daemon/src/task_dispatch.rs`: add sandbox-resolution fields to
   `ExecRunRequest`; update `ToolTaskDispatcher`/`ExecTaskDispatcher::dispatch`
   to the new signature; populate `ExecRunRequest` from the allowance in
   `ExecTaskDispatcher::dispatch` (shared `sandbox_backend`/`network_for`); make
   `default_command_runner` build the `RunSpec` from the request (no more
   hardcoded `Backend::None`); optionally thread `env_allowlist` (and timeout
   clamp) for parity; add/extend tests capturing the `ExecRunRequest`.
6. `mx-agent-daemon/src/scheduler_loop.rs`: forward the `allowance` through
   `RoutingDispatcher::dispatch`; update the test mock.
7. `mx-agent-daemon/src/task_dispatch_matrix.rs`: accept the `allowance` param in
   both `dispatch` impls (exec ignores it locally; remote daemon enforces).
8. Run `cargo fmt`, `cargo clippy --all-targets --all-features -- -D warnings`,
   `cargo test --all`, `cargo build --all`; fix all warnings (CI denies them).
9. Update docs: confirm architecture §13.5 / security-hardening /
   wiki accuracy; ensure no "paths/network not yet enforced" wording remains; add
   the "configured paths must cover the cwd/program" caution.
10. Open the PR referencing `Closes #248`; in the description call out the
    behavior change (auto-executed task DAGs now sandboxed; `network = "allow"`
    now honored) and the operator footgun (paths must cover the working set).
