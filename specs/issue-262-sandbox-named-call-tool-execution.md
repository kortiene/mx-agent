# Confine Named-`call` / Built-in-Tool Execution Under the Resolved `Allowance`

## Problem Statement

The named-`call` / built-in-tool execution path applies **none** of the
confinement that the raw `exec` path applies. Built-in tools (`run_tests`,
`lint`) spawn child processes through `std::process::Command` directly
(`crates/mx-agent-daemon/src/tool_exec.rs:170-173`, `:226-229`), with:

- no sandbox backend (`bubblewrap` / container) — the process runs on the bare
  host;
- no filesystem confinement (`read_only_paths` / `writable_paths` are ignored);
- no network policy (`network = "deny"` is silently inert);
- **no environment scrubbing** — the child inherits the daemon's full
  environment, including exactly the secrets (`MATRIX_ACCESS_TOKEN`,
  `GITHUB_TOKEN`, `ANTHROPIC_API_KEY`, `AWS_*`, …) that `sanitize_env` exists to
  strip (architecture §13.4).

The resolved [`Allowance`](../crates/mx-agent-policy/src/engine.rs) — which
already carries `sandbox`, `network`, `env_allowlist`, `read_only_paths`, and
`writable_paths` — is computed during authorization and then **discarded**
before execution:

- `authorize_live_call` resolves and returns `(CallRequest, Allowance)`, but
  `handle_live_call_request` passes only the request to
  `execute_authorized_call`, which calls `execute_tool(&tool, &args)` with no
  allowance (`call.rs:348-359`, `:630`).
- `ToolTaskDispatcher::dispatch` receives `_allowance` and ignores it, running
  the tool with only `(tool, args)` (`task_dispatch.rs:80-102`).
- The local loopback path `start_call_loopback` runs `execute_tool` with no
  confinement at all (`call_ipc.rs:116-145`).

Net effect: an agent restricted to "safe" named tools gets **less** confinement
than one using raw `exec`, inverting the project's own framing of named tools as
the preferred/safer boundary (`docs/architecture.md:37`, `:302`;
`tool_exec.rs:10-11`). `cargo test` / `cargo clippy` execute arbitrary
`build.rs`, proc-macros, and test binaries, so "no arbitrary shell" does **not**
mean "no arbitrary code"; that code runs unsandboxed with un-scrubbed env. The
exposure is bounded today (two fixed tools) but **unbounded relative to the
policy the operator configured** — the sandbox/network/path/env knobs are
silently inert, which is the more dangerous failure mode because operators
believe they are in effect.

The contrast already exists in-tree: `TaskAction::Exec` was wired to the
allowance in #254 (`task_dispatch.rs:266-276`), and the direct `exec` path runs
through `RunSpec` → `build_command` → `sandbox_for(...).prepare(...)`
(`exec.rs:1000-1015`, `:1226-1239`; `runner.rs:319-365`). The tool path was
never given the same treatment.

## Goals

- Thread the resolved `Allowance` into every built-in-tool execution entry point
  instead of discarding it.
- Run built-in tools through the **same** `RunSpec` → `build_command` →
  `sandbox_for(...).prepare(...)` pipeline that `exec` uses, so they inherit:
  - `sandbox_backend(allowance.sandbox)`,
  - `network_for(allowance.network)` (fail-closed `deny` default),
  - `allowance.read_only_paths` / `allowance.writable_paths`,
  - a **sanitized** environment driven by `allowance.env_allowlist` (secrets
    stripped unless explicitly allowlisted).
- Wire the allowance through `ToolTaskDispatcher::dispatch` so `TaskAction::Tool`
  is confined identically to `TaskAction::Exec` (no underscore-ignored
  `_allowance`).
- Confine the local loopback tool path (`start_call_loopback`) under the
  operator's `execution` defaults so all three tool entry points are consistent
  — at minimum env-scrubbed.
- Reuse `crate::exec::sandbox_backend` / `crate::exec::network_for` rather than
  re-deriving the policy→backend mapping, mirroring the `TaskAction::Exec` arm.
- Update the `tool_exec.rs:10-11` doc comment and `docs/architecture.md:302`
  claim **only once** tools are actually confined at least as strictly as
  `exec`.

## Non-Goals

- Adding new built-in tools or changing the `run_tests` / `lint` argument
  schemas or their `(program, argv)` construction. The command they build is
  unchanged; only *how* it is spawned changes.
- Output streaming / chunking / artifact upload for tool calls. Tools keep their
  current contract (capture exit code → `ToolResult { exit_code, summary }`); no
  `stream.chunk` / `stream.artifact` is added here.
- Changing the policy schema, the `Allowance` struct fields, or
  `evaluate_call`. The allowance already carries everything required.
- The audit-log gap and the `(CallRequest, Allowance)` return-shape change for
  `authorize_live_call` — those overlap #257 and are already implemented in tree
  (`authorize_live_call` already returns the tuple; named `call` decisions are
  already audited per #283). This spec only consumes the allowance that is
  already resolved.
- New sandbox backends (`firejail`, `chroot` remain unimplemented and fall back
  to `Backend::None`, unchanged).
- Windows / non-Unix support.

## Relevant Repository Context

- **Crate:** `mx-agent-daemon` (owns tool execution, the live `call` path, and
  task dispatch). Supporting crates: `mx-agent-policy` (the `Allowance`),
  `mx-agent-sandbox` (`Backend`, `Network`, `Restrictions`).
- **Tool execution today** (`tool_exec.rs`):
  - `execute_tool(name, &Value) -> Result<ToolResult, ToolError>` dispatches to
    `run_tests` / `lint`.
  - `run_tests_command(args)` / `lint_command(args)` are pure builders returning
    `(program, argv)` — already unit-tested and **kept as-is**.
  - `run_tests` / `lint` then do `Command::new(program).args(argv).status()`
    (raw `std::process::Command`, `.status()` inherits the daemon's stdio and
    env, captures only the exit code).
  - `summarize(label, Option<i32>) -> (i32, String)` maps an exit code to a
    summary; reused unchanged.
- **The confinement pipeline to reuse** (`runner.rs`):
  - `RunSpec { command, cwd, env, env_allowlist, stdin, timeout, grace_period,
    sandbox, network, read_only_paths, writable_paths }` (`runner.rs:150-223`).
  - `sanitize_env(vars, &overrides, &allowlist)` — allowlist-based env scrub that
    always drops known token variables even if allowlisted (`runner.rs:119`,
    tested by `sanitize_env_drops_secrets` at `:560`).
  - `build_command(spec) -> Result<Command, RunError>` — validates argv + cwd,
    applies `sanitize_env`, runs through `sandbox_for(spec.sandbox).prepare(...)`
    via `restrictions_for(spec, env)`, sets cwd, `env_clear().envs(env)`, new
    process group (`runner.rs:319-365`).
  - `run(spec) -> Result<RunOutput, RunError>` — async; spawns `build_command`,
    waits, captures stdout/stderr + exit/signal/timeout (`runner.rs:381`).
  - `RunOutput { exit_code, signal, stdout, stderr, timed_out }`.
- **Policy → backend mapping** (`exec.rs`):
  - `pub(crate) fn sandbox_backend(Option<Sandbox>) -> mx_agent_sandbox::Backend`
    (`exec.rs:1534`).
  - `pub(crate) fn network_for(Option<NetworkPolicy>) -> mx_agent_sandbox::Network`
    (fail-closed; `exec.rs:1549`).
- **The `TaskAction::Exec` precedent** (`task_dispatch.rs:247-289`): builds an
  `ExecRunRequest` from `allowance.{sandbox→sandbox_backend, network→network_for,
  read_only_paths, writable_paths, env_allowlist}`, then runs via
  `default_command_runner`, which builds a `RunSpec` and `block_on`s
  `crate::runner::run` on a temporary current-thread runtime
  (`task_dispatch.rs:147-166`). This spec mirrors that shape for tools.
- **Allowance resolution** (`engine.rs:228-271`): `evaluate_call` returns
  `Outcome::Allow(allowance)`; `allowance_for` fills `sandbox`
  (`agent.sandbox.or(execution.default_sandbox)`), `network`, `env_allowlist`,
  `read_only_paths`, `writable_paths` from the `execution` config.
- **Execution context for the sync/async split:**
  - The live `call` handler `handle_live_call_request` is **async**; it currently
    calls the **sync** `execute_authorized_call` (no spawn). It must not nest a
    `block_on` (tokio panics on nested runtimes), so the call path should
    `.await` the async runner directly.
  - The task orchestrator (`process_one` → `dispatch`) runs **synchronously**,
    *not* inside a `block_on` (the scheduler `block_on`s individual async ops
    around it; `scheduler_loop.rs:28`, `:273`). The existing `ExecTaskDispatcher`
    already builds its own temporary current-thread runtime inside `dispatch`, so
    the tool dispatcher may do the same safely.
  - `start_call_loopback` is **sync** and called outside any runtime
    (`lifecycle.rs:871`), so it may also build a temporary runtime.
- **Conventions:** Unix only, no `unsafe`, deny-by-default, fail-closed network,
  audit without secrets, MSRV 1.74. Tools/specs live under `specs/issue-NNN-*`.

## Proposed Implementation

The heart of the fix is a single pure, testable seam in `tool_exec.rs` that
turns a tool name + args + allowance + cwd into a `RunSpec`, plus rewiring the
three callers (live `call`, task dispatch, loopback) to supply the allowance and
run that spec through the shared pipeline.

### 1. `tool_exec.rs` — build a confined `RunSpec` and run it through the runner

Add a pure builder that mirrors the `(program, argv)` construction but produces a
fully-populated `RunSpec`:

```rust
/// Build the confined `RunSpec` for a built-in tool invocation.
///
/// Validates `args` via the tool's existing command builder, then wraps the
/// resulting `(program, argv)` in a `RunSpec` carrying the policy-resolved
/// confinement (sandbox backend, network decision, filesystem binds, and the
/// env allowlist that drives `sanitize_env`). The runner spawns this exactly
/// like a raw `exec`, so a named tool is confined at least as strictly as
/// `exec` (architecture §13.5). Pure + side-effect-free so tests can assert the
/// spec without spawning.
fn tool_run_spec(
    name: &str,
    args: &Value,
    allowance: &mx_agent_policy::Allowance,
    cwd: PathBuf,
) -> Result<RunSpec, ToolError> {
    let (program, argv) = match name {
        RUN_TESTS => run_tests_command(args)?,
        LINT => lint_command(args)?,
        other => return Err(ToolError::UnknownTool(other.to_string())),
    };
    let mut command = vec![program];
    command.extend(argv);
    Ok(RunSpec {
        command,
        cwd,
        env: Default::default(),
        env_allowlist: allowance.env_allowlist.clone(),
        stdin: None,
        timeout: allowance.max_runtime_ms.map(Duration::from_millis),
        grace_period: DEFAULT_GRACE_PERIOD,
        sandbox: crate::exec::sandbox_backend(allowance.sandbox),
        network: crate::exec::network_for(allowance.network),
        read_only_paths: allowance.read_only_paths.clone(),
        writable_paths: allowance.writable_paths.clone(),
    })
}
```

Notes / decisions:

- **`cwd`:** tools currently inherit the daemon's working directory (raw
  `Command` with no `current_dir`). `build_command` requires an existing
  directory (`RunError::MissingCwd`), so the cwd must be explicit. Resolve it
  once at the call sites as the daemon's current working directory
  (`std::env::current_dir()`), falling back to `.` on error, and pass it in.
  Keep the resolution at the callers (not inside the pure builder) so the builder
  stays side-effect-free and testable. Document that, under an isolating sandbox,
  this cwd must be inside the configured `writable_paths` for the tool to do
  anything useful (operator configuration concern, not a code concern).
- **`label` for `summarize`:** keep the existing labels (`"cargo test"`,
  `"cargo clippy"`). Map `RunOutput` → `ToolResult` by feeding
  `output.exit_code` (which is `None` when signalled/timed-out) into the existing
  `summarize`, so a signalled/timed-out tool reports a nonzero failure exactly as
  today.
- Unknown-tool / invalid-args validation happens **before** any spec is built or
  runtime is spun up, so those errors return synchronously with no runner cost
  (preserves `execute_tool_rejects_unknown_tool`, `execute_tool_dispatches_lint`,
  and the `execute_authorized_call_reports_invoke_failure` test's fast path).

Provide two run entry points over the builder so both the async call path and the
sync dispatch/loopback paths are served without nesting runtimes:

```rust
/// Async: run a built-in tool confined by `allowance`, mapping the captured
/// outcome onto a `ToolResult`. Used by the live `call` handler, which is
/// already async and must not nest a runtime.
pub async fn execute_tool_async(
    name: &str,
    args: &Value,
    allowance: &mx_agent_policy::Allowance,
    cwd: PathBuf,
) -> Result<ToolResult, ToolError> {
    let spec = tool_run_spec(name, args, allowance, cwd)?;
    let output = crate::runner::run(&spec).await.map_err(map_run_error)?;
    let (exit_code, summary) = summarize(tool_label(name), output.exit_code);
    Ok(ToolResult { exit_code, summary })
}

/// Sync: run a built-in tool confined by `allowance` on a temporary
/// current-thread runtime. Used by the synchronous task orchestrator dispatch
/// and the loopback path, neither of which runs inside a tokio runtime
/// (mirrors `task_dispatch::default_command_runner`).
pub fn execute_tool(
    name: &str,
    args: &Value,
    allowance: &mx_agent_policy::Allowance,
    cwd: PathBuf,
) -> Result<ToolResult, ToolError> {
    // Validate synchronously first so unknown-tool / bad-args never spin a runtime.
    let spec = tool_run_spec(name, args, allowance, cwd)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(ToolError::Spawn)?;
    let output = runtime.block_on(crate::runner::run(&spec)).map_err(map_run_error)?;
    let (exit_code, summary) = summarize(tool_label(name), output.exit_code);
    Ok(ToolResult { exit_code, summary })
}
```

- `map_run_error(RunError) -> ToolError`: map `RunError::Spawn(io)` →
  `ToolError::Spawn(io)`; map `RunError::EmptyCommand` / `RunError::MissingCwd`
  → `ToolError::Spawn(io::Error)` (or a small new `ToolError` variant if a
  cleaner message is wanted — prefer reusing `Spawn` to avoid widening the public
  enum). Keep `ToolError`'s existing variants and `Display`/`source` semantics.
- `tool_label(name)` returns `"cargo test"` / `"cargo clippy"` so summaries are
  unchanged.
- Drop the `use std::process::Command;` import; tool spawning now goes through
  the runner. Update the test-only `run_tests_via` / `lint_via` helpers (which
  currently use raw `Command`) to exercise the new spec/runner path, or replace
  them with `tool_run_spec`-based assertions.

### 2. `call.rs` — thread the allowance into the live call path

- `authorize_live_call` already returns `(CallRequest, Allowance)` — no change.
- Make `execute_authorized_call` **async** and take the allowance + cwd:

  ```rust
  pub async fn execute_authorized_call(
      request: &CallRequest,
      allowance: &mx_agent_policy::Allowance,
  ) -> CallResponse {
      let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
      match crate::tool_exec::execute_tool_async(&request.tool, &request.args, allowance, cwd).await {
          Ok(result) => success_response(request.request_id.clone(), result.to_value()),
          Err(err) => CallResponse { ok: false, error: Some(err.to_string()), .. },
      }
  }
  ```

- At `call.rs:630`, change `execute_authorized_call(&authorized)` to
  `execute_authorized_call(&authorized, &allowance).await`. The `allowance` is
  already bound in the `Ok((authorized, allowance))` arm and is also passed to
  `audit_call_decision`; reuse it (clone if the borrow checker requires it, since
  it is moved into `Outcome::Allow(allowance)` for the audit call — reorder so
  the audit uses a borrow/clone and execution uses the value, or clone once).

### 3. `task_dispatch.rs` — confine `TaskAction::Tool`

Mirror the `TaskAction::Exec` arm. Change the injected runner signature to carry
the allowance + cwd, and stop ignoring `_allowance`:

```rust
type ToolRunner = fn(&str, &Value, &mx_agent_policy::Allowance, PathBuf)
    -> Result<ToolResult, ToolError>;

impl Default for ToolTaskDispatcher<ToolRunner> {
    fn default() -> Self { Self { run_tool: execute_tool } } // the new sync execute_tool
}

impl<F> TaskDispatcher for ToolTaskDispatcher<F>
where F: FnMut(&str, &Value, &mx_agent_policy::Allowance, PathBuf) -> Result<ToolResult, ToolError>
{
    fn dispatch(&mut self, _task, action, _invocation_id, allowance) -> ... {
        match action {
            TaskAction::Tool { tool, args, .. } => {
                let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
                match (self.run_tool)(tool, args, allowance, cwd) {
                    Ok(result) => Ok(TaskExecutionResult { exit_code: Some(result.exit_code), summary: result.summary, artifact_mxc: None }),
                    Err(err) => Err(TaskDispatchError::Failed(format!("tool {tool:?} could not be invoked: {err}"))),
                }
            }
            TaskAction::Exec { .. } => Err(..),
        }
    }
}
```

- Update `ToolTaskDispatcher::with_runner` callers and the existing
  `with_runner(|name, _args| ...)` test closures to the new 4-arg signature
  (`|name, _args, _allowance, _cwd| ...`).
- The default tool runner is now the new sync `execute_tool`, which itself
  applies the confinement — so the dispatcher does not need to build a `RunSpec`
  inline (unlike `ExecTaskDispatcher`, where command building lives in the
  dispatcher). This keeps tool-specific command construction inside
  `tool_exec.rs`.

### 4. `call_ipc.rs` — confine the loopback path

`start_call_loopback` runs locally without remote authorization, so there is no
per-agent allowance. Apply the operator's **execution-level defaults** so the
loopback is at least env-scrubbed and honors `default_sandbox` / `network` /
paths:

- Add a small helper to resolve an execution-defaults allowance from the local
  policy, e.g. in `mx-agent-policy`:

  ```rust
  impl Policy {
      /// Allowance carrying only the execution-level defaults (sandbox, network,
      /// env allowlist, filesystem binds), with no per-agent gate. For local,
      /// already-trusted paths (e.g. CLI loopback) that still must apply the
      /// operator's configured confinement and env scrubbing.
      pub fn execution_allowance(&self) -> Allowance { /* fill from self.execution */ }
  }
  ```

- In `start_call_loopback`, load the local policy (`Policy::default_path()` →
  `Policy::load` → `unwrap_or_default`, mirroring `policy_for_live_call`), build
  the execution-defaults allowance, resolve `cwd`, and call the new sync
  `execute_tool(&params.tool, &params.input, &allowance, cwd)`. Map errors to
  `CallErrorKind` exactly as today.
- If a lighter touch is preferred to avoid a policy load on every loopback call,
  the minimum acceptable behavior is a `Allowance::default()` (which still yields
  `sanitize_env` scrubbing and fail-closed `Network::Deny`); prefer the
  execution-defaults variant so operator config is honored. Flag this as an open
  question below.

### 5. `lib.rs` — public surface

`pub use tool_exec::{execute_tool, ...}` changes signature (new params) and a new
`execute_tool_async` is added. Update the re-export. `execute_authorized_call`
becomes async (re-export unchanged in name). Document the new/changed public
functions.

### 6. Docs — flip the claim only after the behavior is true

Once tools run through the confined pipeline, update:
- `tool_exec.rs:10-11` to state tools are confined at least as strictly as
  `exec` (sandbox + network + path binds + sanitized env), not merely
  "no arbitrary shell".
- `docs/architecture.md:302` (and §5.2 / §13.5 as needed) to note named tools
  inherit the same sandbox/network/path/env confinement as `exec`.

## Affected Files / Crates / Modules

- `crates/mx-agent-daemon/src/tool_exec.rs` — new `tool_run_spec`,
  `execute_tool_async`, rewritten `execute_tool` (new signature), `map_run_error`,
  `tool_label`; drop raw `Command`; update tests/helpers.
- `crates/mx-agent-daemon/src/call.rs` — `execute_authorized_call` async + takes
  allowance; update the call site at `:630` and the unit test at `:1156`.
- `crates/mx-agent-daemon/src/task_dispatch.rs` — `ToolRunner` signature,
  `ToolTaskDispatcher::dispatch` uses `allowance`; update `with_runner` test
  closures.
- `crates/mx-agent-daemon/src/call_ipc.rs` — `start_call_loopback` resolves an
  execution-defaults allowance + cwd and calls the new `execute_tool`.
- `crates/mx-agent-daemon/src/lib.rs` — re-export updates / docs.
- `crates/mx-agent-policy/src/engine.rs` (or `file.rs`) — new
  `Policy::execution_allowance()` helper (optional but recommended).
- `crates/mx-agent-daemon/src/exec.rs` — no change beyond confirming
  `sandbox_backend` / `network_for` visibility (already `pub(crate)`).
- `docs/architecture.md` — §5.2 / §13.5 wording (after behavior is true).
- Read-only references: `crates/mx-agent-daemon/src/runner.rs` (RunSpec /
  build_command / sanitize_env / run), `crates/mx-agent-daemon/src/scheduler_loop.rs`
  (dispatch context), `crates/mx-agent-sandbox` (Backend / Network).

## CLI / API Changes

- **Rust public API (within the daemon crate):**
  - `execute_tool` gains parameters: `(name, args, &Allowance, cwd)` and runs
    confined.
  - New `execute_tool_async(name, args, &Allowance, cwd) -> ...`.
  - `execute_authorized_call` becomes `async` and takes `(&CallRequest,
    &Allowance)`.
  - `ToolTaskDispatcher`'s injected runner type changes signature.
  - New `Policy::execution_allowance()` (if adopted).
  All are internal/daemon-facing; no end-user CLI command, flag, or output
  changes. Human-readable + `--json` behavior of `mx-agent call` is unchanged.
- **No IPC/protocol surface change.** `call.request` / `call.response` event
  shapes, `CallStartParams` / `CallStartResult`, and exit-code mapping are
  unchanged.

## Data Model / Protocol Changes

None. No event schema, persistence, policy file schema, or serialization
changes. The `Allowance` struct and `evaluate_call` are unchanged; this work only
*consumes* the already-resolved allowance.

## Security Considerations

- **This is the core security fix:** it removes the inversion where named tools
  were *less* confined than raw `exec`. After it lands, a `run_tests` / `lint`
  call honors the operator's `default_sandbox`, `network`, `read_only_paths`,
  `writable_paths`, and `env_allowlist`.
- **Env scrubbing is the highest-value change.** Routing through
  `build_command` → `sanitize_env` strips `MATRIX_ACCESS_TOKEN`, `MX_AGENT_TOKEN`,
  `GITHUB_TOKEN`, `ANTHROPIC_API_KEY`, `AWS_*`, etc. from the child — including
  from arbitrary `build.rs`/proc-macro/test-binary code that `cargo test` /
  `cargo clippy` execute. `sanitize_env` always drops known token variables even
  if explicitly allowlisted (`sanitize_env_scrubs_secret_even_when_allowlisted`),
  so confidence is high.
- **Fail-closed network.** `network_for(None)` → `Network::Deny`; the default
  (no policy) confines network for isolating backends rather than leaving it
  open.
- **No new secrets in logs.** The audit record continues to log only the tool
  name (never `args`); summaries never carry raw process output. No change to the
  redaction posture.
- **Daemon/CLI separation preserved.** The CLI remains stateless; the daemon
  still owns policy, signing, and execution. The coding agent never sees tokens —
  reinforced, since secrets are now scrubbed from tool children too.
- **Authority order unchanged.** Signature → trust → policy → (additive)
  verified-device gating all still run before any tool executes; this change only
  governs *how* the already-authorized tool is spawned. Room membership still
  never implies execution.
- **Loopback path.** Local loopback is operator-initiated on the operator's own
  host, but should still scrub env (the daemon's environment may hold the Matrix
  token) and honor execution defaults; the spec applies the execution-defaults
  allowance there. This is a defense-in-depth improvement, not an authorization
  change (loopback is not a remote-authorized path).
- **Unix only.** Process-group, `sanitize_env`, and sandbox backends are the
  existing Unix-only mechanisms; no Windows assumptions added. No `unsafe`.
- **Sandbox availability caveat:** `firejail`/`chroot` remain unimplemented and
  fall back to `Backend::None` (pre-existing); `bubblewrap`/container require the
  host tool to be present. Behavior is unchanged from the `exec` path.

## Testing Plan

Unit tests (mirroring `exec` / `runner` coverage):

- **`tool_run_spec` carries policy confinement** (`tool_exec.rs`):
  - For `run_tests` and `lint`, with an allowance of
    `{ sandbox: Some(Bubblewrap), network: Some(Allow), read_only_paths,
    writable_paths, env_allowlist }`, assert the resulting `RunSpec` carries
    `Backend::Bubblewrap`, `Network::Allow`, and the exact paths/allowlist —
    parallel to `exec_dispatcher_carries_policy_sandbox_network_and_paths_to_runner`.
  - With `Allowance::default()`, assert `Backend::None` and **`Network::Deny`**
    (fail closed) and empty paths — parallel to
    `exec_dispatcher_defaults_to_none_backend_and_deny_with_empty_allowance`.
  - Docker policy → `Backend::Container`.
  - Unknown tool / invalid args return `ToolError` without building a spec or
    spinning a runtime (preserve existing fast-path tests).
- **Env is sanitized** (`tool_exec.rs`): build the spec, then assert
  `sanitize_env(vars_including_GITHUB_TOKEN, &spec.env, &spec.env_allowlist)`
  drops `GITHUB_TOKEN` (and other secrets) unless explicitly allowlisted —
  mirroring `sanitize_env_drops_secrets` / `sanitize_env_scrubs_secret_even_when_allowlisted`.
- **Tool still spawns + reports exit code** (`tool_exec.rs`): keep the
  `true`/`false`-program exercise of the spawn + `summarize` path, adapted to the
  new spec/runner entry (a default `Allowance` + a temp dir cwd), asserting exit
  `0` vs nonzero and that a signalled/`None` exit maps to a nonzero summary.
- **Task dispatch applies confinement** (`task_dispatch.rs`): with a
  `with_runner` closure capturing `(name, args, allowance, cwd)`, assert the
  dispatcher forwards a non-default allowance (e.g. Bubblewrap + paths) to the
  tool runner for a `TaskAction::Tool` — the tool analogue of the existing exec
  allowance-wiring tests. Update the existing tool-dispatch tests to the 4-arg
  closure signature.
- **Live call path** (`call.rs`): keep
  `execute_authorized_call_reports_invoke_failure` (now `async`, unknown tool →
  `ok: false` fast path with a default allowance). Optionally add a test that an
  allowed `run_tests` against a `true`-substitute under a non-None sandbox spec is
  invoked confined (may require an injectable seam or live-runner test; if
  awkward, rely on the `tool_run_spec` unit tests for the confinement assertion
  and keep the call-path test focused on wiring).
- **Loopback path** (`call_ipc.rs`): keep the existing loopback tests passing
  under the new signature; add one asserting the resolved execution-defaults
  allowance is used (e.g. via a policy fixture with `env_allowlist` and a
  capturing seam, or by asserting `Network::Deny` default behavior).

Integration / e2e:

- Extend or add a daemon test (alongside `tests/task_orchestration_e2e.rs`)
  asserting a `TaskAction::Tool` dispatch under a non-`None` policy sandbox runs
  through the confined path (e.g. by configuring a policy with a writable-path
  bind and a sentinel secret env var, then asserting the secret does not reach the
  child — analogous to the exec confinement coverage).

Docs/build:

- `cargo test -p mx-agent-daemon -p mx-agent-policy`, `cargo clippy --all-targets
  -- -D warnings`, `cargo fmt --check`.

## Documentation Updates

- `crates/mx-agent-daemon/src/tool_exec.rs:10-11` — replace the "no arbitrary
  shell" framing with the accurate claim that tools run through the same
  sandbox/network/path/env confinement as `exec`.
- `docs/architecture.md` §5.2 (`:302`) and §13.5 — note that named tools inherit
  the resolved `Allowance`'s sandbox backend, network policy, filesystem binds,
  and sanitized env, identical to `exec`.
- Rustdoc on the new/changed public functions (`execute_tool`,
  `execute_tool_async`, `execute_authorized_call`, `Policy::execution_allowance`,
  `ToolTaskDispatcher`).
- No README or status-table change expected (no user-visible CLI surface change);
  if a v0.2.0 status note tracks this deviation, mark it resolved.

## Risks and Open Questions

- **Sync vs async duplication.** The spec provides both `execute_tool` (sync,
  temp runtime) and `execute_tool_async` (for the already-async call path) to
  avoid nesting tokio runtimes. Confirm the call path uses the async variant and
  the orchestrator/loopback use the sync variant. Alternative: make every caller
  async — rejected because the orchestrator core is synchronous by design.
- **cwd semantics.** Tools historically inherited the daemon's cwd implicitly.
  Making it explicit (`std::env::current_dir()`) is behavior-preserving for the
  `none` backend, but under `bubblewrap`/container the cwd must be inside
  `writable_paths` or the tool cannot write. This is operator configuration, but
  should be documented. Open question: should the tool cwd instead come from the
  attached workspace path (`com.mxagent.workspace.v1`)? Out of scope here;
  current behavior (daemon cwd) is preserved.
- **Loopback confinement scope.** Recommended: apply execution-level defaults via
  `Policy::execution_allowance()`. Decision needed: is loading local policy on
  every loopback call acceptable, or should loopback use `Allowance::default()`
  (still scrubs env, still `Network::Deny`)? Either closes the secret-leak; the
  former additionally honors `default_sandbox`/paths.
- **`ToolError` surface.** Mapping `RunError::{EmptyCommand,MissingCwd}` onto
  `ToolError::Spawn` reuses the existing enum; if clearer messages are wanted, a
  new `ToolError` variant could be added (a minor public-API widening). Prefer
  reuse unless a reviewer wants the distinction.
- **Output capture difference.** Switching from `.status()` (inherited stdio) to
  the runner (piped capture) means tool stdout/stderr is no longer printed to the
  daemon's terminal; only the exit-code summary is surfaced (already the tool
  contract). Confirm no operator workflow relies on the daemon-side console
  output of `cargo test`/`clippy`.
- **Backend availability at runtime.** If policy selects `bubblewrap`/container
  but the host lacks it, the spawn fails — same failure mode as the `exec` path;
  surfaced as `ok: false` / task `failed`. No new handling required.

## Implementation Checklist

1. In `tool_exec.rs`, add the pure `tool_run_spec(name, args, &Allowance, cwd)
   -> Result<RunSpec, ToolError>` builder reusing `run_tests_command` /
   `lint_command`, `crate::exec::sandbox_backend`, `crate::exec::network_for`,
   and the allowance's paths/env_allowlist/max_runtime_ms.
2. Add `map_run_error` and `tool_label`; add async `execute_tool_async` and
   rewrite sync `execute_tool` to validate-then-run via the runner (temp
   current-thread runtime for the sync variant). Remove `use std::process::Command`.
3. Update `tool_exec.rs` tests/helpers (`run_tests_via`/`lint_via`) to the new
   path; add `tool_run_spec` confinement + sanitized-env assertions.
4. In `call.rs`, make `execute_authorized_call` async and take `&Allowance`;
   resolve cwd; call `execute_tool_async`. Update the call site at `:630` to pass
   the bound `allowance` and `.await`, reconciling the move into the audit
   `Outcome::Allow(allowance)` (clone/borrow as needed).
5. Update the `execute_authorized_call_reports_invoke_failure` test to async with
   a default allowance.
6. In `task_dispatch.rs`, change `ToolRunner` to
   `fn(&str, &Value, &Allowance, PathBuf) -> Result<ToolResult, ToolError>`,
   default to the new sync `execute_tool`, and make `dispatch` resolve cwd and
   pass `allowance` (drop `_allowance`). Update `with_runner` test closures and
   add a tool allowance-wiring test mirroring the exec one.
7. (Recommended) Add `Policy::execution_allowance()` in `mx-agent-policy`.
8. In `call_ipc.rs`, load local policy, build the execution-defaults allowance,
   resolve cwd, and run `start_call_loopback` through the new `execute_tool`;
   keep error→`CallErrorKind` mapping; update tests.
9. Update `lib.rs` re-exports and rustdoc for the changed/added public functions.
10. Once behavior is confirmed, update `tool_exec.rs:10-11` and
    `docs/architecture.md` §5.2/§13.5 to state tools are confined as strictly as
    `exec`.
11. Run `cargo fmt`, `cargo clippy --all-targets -- -D warnings`, and
    `cargo test -p mx-agent-daemon -p mx-agent-policy`; add/adjust the
    `TaskAction::Tool` confinement e2e coverage.
```