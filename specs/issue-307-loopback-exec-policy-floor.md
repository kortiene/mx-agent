# Issue #307 — Loopback exec/PTY policy confinement floor

## Problem

A loopback `exec` (no `--room`/`--agent`) and loopback `exec --pty` run with **no
policy evaluation, no sandbox, no timeout, and (batch) no output cap** — the only
protection is the runner's env scrub. Loopback `call` already applies the
operator's `Policy::execution_allowance()` floor, so a built-in tool is confined
while a raw loopback command is not. Loopback `exec.cancel`/`exec.stdin` are
permanently `accepted: false` stubs, so a runaway loopback command cannot be
stopped through the exec IPC API. `README.md` and `docs/security-hardening.md`
claim policy/pipeline coverage the loopback path does not have.

## Goals

- Loopback batch exec and loopback PTY carry the operator's confinement floor
  (`sandbox` / `network` / `read_only_paths` / `writable_paths` / `env_allowlist`)
  resolved from `Policy::execution_allowance()`, matching loopback `call`.
- Loopback batch exec enforces a default timeout and a default output cap;
  exceeding the cap reports `truncated: true` in `exec.finished`.
- Loopback `exec.finished` reports a real `duration_ms`.
- `exec.cancel`/`exec.stdin` no longer exist as permanently-dead `accepted: false`
  loopback API surface; the no-`--room` dispatch returns an honest error.
- Docs (`README.md`, `docs/security-hardening.md`, `docs/cli-reference.md`) describe
  the loopback path accurately; a `doc_drift.rs` test pins the corrected wording.

## Non-goals

- Implementing async loopback supervision / a live invocation table so that
  synchronous batch loopback could be cancelled mid-run. Loopback batch exec runs
  to completion in a single IPC request; there is no concurrent control channel.
  The default timeout (added here) bounds runaways instead. Cancellable execution
  remains the remote (`--room`/`--agent`) path; interactive local sessions use
  `--pty`.
- Changing loopback artifact mode to upload to a homeserver (loopback has none).
  The empty `mxc_uri` behavior is documented, not changed.

## Affected code

- `crates/mx-agent-daemon/src/exec_ipc.rs` — `run_loopback`; new pure
  `loopback_run_spec`, injectable `run_loopback_with`, default timeout/cap consts;
  remove `handle_exec_stdin_loopback` / `handle_exec_cancel_loopback`.
- `crates/mx-agent-daemon/src/pty_ipc.rs` — `run_pty_loopback`; new pure
  `pty_loopback_run_spec`; resolve allowance; keep 64 MiB cap fallback.
- `crates/mx-agent-daemon/src/lifecycle.rs` — `dispatch_exec_stdin` /
  `dispatch_exec_cancel` return a JSON-RPC `INVALID_PARAMS` error for no-`--room`;
  update the `exec_control_methods_*` test.
- `crates/mx-agent-daemon/src/lib.rs` — drop the two removed re-exports.
- `crates/mx-agent-daemon/src/exec.rs` — `sandbox_backend` / `network_for` are
  already `pub(crate)`; reuse from exec_ipc/pty_ipc.
- Docs: `README.md`, `docs/security-hardening.md`, `docs/cli-reference.md`.
- Test: `crates/mx-agent-cli/tests/doc_drift.rs` — new guard.

## Approach

The confinement floor for both loopback paths is resolved exactly as
`start_call_loopback` does:

```
let allowance = Policy::default_path()
    .and_then(|p| Policy::load(p).ok())
    .unwrap_or_default()
    .execution_allowance();
```

`execution_allowance()` carries `sandbox` / `network` / `env_allowlist` /
`read_only_paths` / `writable_paths` from the workspace execution defaults but
leaves the per-agent `max_runtime_ms` / `max_output_bytes` at `None`. So loopback
uses defaults for those: `DEFAULT_LOOPBACK_EXEC_TIMEOUT_MS = 600_000` (mirrors the
remote request default) and `DEFAULT_PTY_OUTPUT_CAP_BYTES = 64 MiB` (already the
loopback PTY fallback). A policy that *does* set them (impossible via
`execution_allowance` today, but the mapping reads the allowance so it stays
correct if that changes) is honored via `unwrap_or(default)`.

Pure `loopback_run_spec(params, allowance)` and `pty_loopback_run_spec(params,
allowance)` map the allowance onto a `RunSpec` (mirroring `run_controlled_exec`
at `exec.rs:1190` and the PTY spawn). They are unit-tested directly without
spawning. `run_loopback_with` takes an injectable allowance so an output-cap
truncation test can pass a small `max_output_bytes`.

`duration_ms` is measured with `std::time::Instant::now()` around `run()`,
matching `exec.rs:709`.

## Security

- Parity with loopback `call`, not a new remote gate. Loopback stays
  operator-initiated over the peer-UID-checked socket; the floor is
  defense-in-depth (env scrub + sandbox/network/binds + a runtime/output bound).
- With no policy file the safe defaults apply (no sandbox override, network deny,
  empty env allowlist → daemon secrets stay stripped).
- No secrets logged; `sanitize_env` and the policy `env_allowlist` remain enforced
  on both the batch and PTY paths.

## Testing

- Unit: `loopback_run_spec` / `pty_loopback_run_spec` carry the allowance fields
  (sandbox/network/binds/env_allowlist) and the default/overridden timeout.
- Unit: default-policy loopback spec is fail-closed (no sandbox, network deny,
  empty allowlist) — mirrors the `call_ipc` floor test.
- Integration: `run_loopback_with` with a small `max_output_bytes` and output
  between the cap and the 256 KiB artifact threshold reports `truncated: true`;
  default timeout terminates a runaway command.
- Unit: no-`--room` `exec.stdin`/`exec.cancel` dispatch returns a JSON-RPC error
  (replaces the structured `accepted:false` assertion).
- `doc_drift.rs`: README/security-hardening no longer claim loopback policy/pipeline
  coverage; the corrected wording is present.

## E2E decision

No new Docker/live-service e2e needed: the loopback path is fully exercisable in
the in-crate test harness (no Matrix, no homeserver). The existing live Tuwunel
suite must stay green (loopback exec runs `true`/`echo`/`cat`, all within the new
bounds).
