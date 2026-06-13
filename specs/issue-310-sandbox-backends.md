# Issue #310 — Sandbox backends: fail-closed firejail/chroot, real podman, bwrap/container hardening

## Problem

- `sandbox = "firejail"` / `"chroot"` parse and validate cleanly, then run with
  **zero isolation** (`sandbox_backend` maps them to `Backend::None`).
- `sandbox = "podman"` silently runs through **Docker** with a hardcoded
  `debian:stable-slim` image; no policy key for image/runtime.
- bubblewrap mounts no `/dev`, `/proc`, or tmpfs and skips `--unshare-user` /
  `--new-session`; the crate's own probe needs `--dev-bind` for even `true`.
- Container env is forwarded as `--env KEY=VALUE` on argv — values visible in `ps`.
- No backend-availability preflight; a missing `bwrap`/`docker` is a bare spawn
  `NotFound`. CI never exercises real bwrap.

## Goals (acceptance criteria)

- firejail/chroot can no longer run unsandboxed silently: `Policy::validate`
  rejects them with a precise dotted-path error (covers `execution.default_sandbox`
  and per-agent `sandbox`); the pinned `sandbox_backend` mapping test is updated.
- `sandbox = "podman"` produces a `podman run …` argv; a policy-configured
  `execution.container_image` reaches the argv in place of `debian:stable-slim`.
- bwrap argv includes `/dev`, `/proc`, tmpfs, `--unshare-user`, `--new-session`
  (batch); real-bwrap integration tests pass under the new flags.
- A missing backend binary yields an actionable diagnostic (PATH-controlled unit
  test) instead of a bare spawn `NotFound`.
- No `KEY=VALUE` pairs appear in the prepared container argv.
- New CI job (Linux, `apt-get install bubblewrap`) runs the real-bwrap tests
  un-skipped and fails if they skip.
- Docs corrected; fmt/clippy/build/test green; live Tuwunel suite unaffected.

## Non-goals / deferred

- `--pids-limit` / `--memory` container limits and their policy keys: deferred
  (not in acceptance criteria; would expand the policy schema). Documented as
  follow-up. Container still gains `--cap-drop ALL` + `--security-opt
  no-new-privileges` (no new policy keys).
- Implementing real firejail/chroot backends (rejected, not built).

## Design

### firejail/chroot → fail closed at validate
`Policy::validate` rejects `Sandbox::Firejail` / `Sandbox::Chroot` wherever they
appear (`execution.default_sandbox`, `rooms.<id>.agents.<id>.sandbox`) with a
dotted-path `Validation` error: "sandbox backend `firejail` is not implemented;
use `bubblewrap`, `docker`, or `podman`". `Policy::parse`/`load` therefore reject
such files; the daemon's `Policy::load(...).ok().unwrap_or_default()` then falls
back to the deny-by-default `Policy::default()` (fail closed). The `Sandbox` enum
keeps the variants so the error message is precise (vs. a serde unknown-variant).

### podman runtime + container image
- `ExecutionPolicy` gains `container_image: Option<String>`; `Allowance` gains
  `container_image: Option<String>` (set in `execution_allowance` + `allowance_for`).
- The runtime is implied by the `Sandbox` value (`podman` → `Runtime::Podman`,
  else `Docker`) via a new `container_runtime_for(Option<Sandbox>)`.
- `RunSpec` gains `container_runtime: Runtime` and `container_image: Option<String>`.
- New `mx_agent_sandbox::sandbox_for_container(runtime, image)`; the runner/pty
  resolve `Backend::Container` through it (default image when unset), other
  backends through `sandbox_for`.

### bwrap hardening (`BubblewrapSandbox::prepare`)
Order: namespaces → `--cap-drop ALL` → `--proc /proc` `--dev /dev` `--tmpfs /tmp`
(before binds, so an explicit writable `/tmp` bind re-mounts over the tmpfs) →
ro/rw binds → `--chdir` → `--`. Add `--unshare-user`. Add `--new-session` **only
for the non-interactive (batch) path** — it `setsid`s away from the controlling
terminal, which would break Ctrl-C on an interactive `--pty` session, so it is
omitted when `restrictions.interactive`.

### container hardening + env (`ContainerSandbox::prepare`)
Add `--cap-drop ALL` and `--security-opt no-new-privileges`. Replace the
`--env KEY=VALUE` loop with the **passthrough form `--env KEY`** (name only):
Docker/Podman read the value from the `docker run` process environment, which the
runner already sets to the sanitized env (`env_clear().envs(sanitized)`). This
keeps `prepare` pure, keeps values out of `ps`/argv, and is behavior-equivalent.

### backend preflight
Pure `find_in_path(program, path)` + `preflight_backend(backend, runtime)` in the
sandbox crate return `Ok(())` or an actionable `Err(String)`. The runner
(`build_command`) and `PtySession::spawn` call it before spawning a non-`None`
backend, surfacing the diagnostic via `RunError::Spawn(NotFound, msg)`.

### CI + tests
- `bwrap_usable()` probe updated to mirror the hardened flags; a
  `bwrap_available_or_required()` helper panics (instead of skipping) when
  `MX_AGENT_REQUIRE_BWRAP` is set, so the new CI job (Linux, `apt-get install -y
  bubblewrap`, `MX_AGENT_REQUIRE_BWRAP=1`) fails if the real tests skip. The same
  gate is applied to `task_orchestration_e2e.rs`.

## Affected code

- `crates/mx-agent-sandbox/src/lib.rs` — bwrap/container prepare, env passthrough,
  `sandbox_for_container`, preflight, probe + require-gate, tests.
- `crates/mx-agent-policy/src/file.rs` — `container_image` field; validate rejects
  firejail/chroot.
- `crates/mx-agent-policy/src/engine.rs` — `Allowance.container_image`.
- `crates/mx-agent-daemon/src/runner.rs` — `RunSpec` fields, `resolve_sandbox`,
  preflight wiring.
- `crates/mx-agent-daemon/src/exec.rs` — `container_runtime_for`, RunSpec fields,
  updated `sandbox_backend` test.
- `crates/mx-agent-daemon/src/pty.rs` — resolve + preflight.
- `crates/mx-agent-daemon/src/{exec_ipc,pty_ipc,task_dispatch}.rs` — RunSpec fields.
- `crates/mx-agent-daemon/tests/task_orchestration_e2e.rs` — require-gate.
- `.github/workflows/ci.yml` — `sandbox-linux` job.
- Docs: `docs/security-hardening.md`, `README.md`; `doc_drift.rs` guard.

## Security

- Backend resolution fails closed: an unimplemented backend never silently widens
  or narrows isolation; firejail/chroot are rejected at load.
- No secrets in argv/logs: container env moves off argv; preflight diagnostics
  never echo env values.
- Unix-only; no `unsafe`; MSRV 1.74.

## Testing

- Unit (policy): validate rejects firejail/chroot at execution + agent scope with
  the dotted path; valid backends still parse.
- Unit (sandbox prepare): podman argv; configured image in argv; bwrap
  `/dev`/`/proc`/tmpfs/`--unshare-user`/`--new-session` (batch) and no
  `--new-session` (interactive); container `--cap-drop`/`no-new-privileges`; no
  `KEY=VALUE` in argv; `--env KEY` passthrough.
- Unit (preflight): PATH-controlled found/not-found + diagnostic.
- Integration (real bwrap): existing tests pass under new flags; require-gate.
- E2E decision: the new CI job is the e2e for real-bwrap; no Docker added to
  default `cargo test --all` (container tests still skip without a runtime).
