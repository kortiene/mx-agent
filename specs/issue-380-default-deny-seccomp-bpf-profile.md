# Issue #380 — Ship the default-deny seccomp BPF profile (follow-up to #349)

## Problem Statement

Issue #349 shipped seccomp as **opt-in machinery only**. The policy parses and
threads `seccomp = "default"` end to end — `mx-agent-policy` parses it at both
scopes and rejects unknown variants, `engine.rs` resolves it onto the
`Allowance`, the daemon maps it `Seccomp` → `SeccompMode` (`exec.rs::seccomp_for`)
and threads it into every exec path, and `SeccompMode::is_on()` returns `true`
for `Default` — but **no BPF filter is ever installed on any backend**:

- **`none` path** — `launcher::run_launcher` (`crates/mx-agent-sandbox/src/launcher.rs:186-197`)
  only emits a `tracing::warn!` "…installation is not yet active (issue #349
  follow-up)…" and proceeds to `exec` unfiltered.
- **`bubblewrap` path** — `BubblewrapSandbox::prepare` emits namespace + `--cap-drop ALL`
  flags but no `--seccomp <fd>`. Worse, `LauncherArgs::is_needed`
  (`launcher.rs:78-84`) only engages the launcher for seccomp on the `none`
  backend, so the bwrap path never even reaches the warn — the request is dropped
  **silently**.
- **`container` path** — `ContainerSandbox::prepare` emits `--security-opt no-new-privileges`
  but never `--security-opt seccomp=`; `restrictions.seccomp` is carried into
  `Prepared` and never read for the argv. The omission is *asserted* by the test
  `container_seccomp_field_not_emitted_by_prepare` (`lib.rs:1874-1896`), again
  silently.

So `SeccompMode::is_on() == true` means "**requested**", not "**syscall-filtered**".
An operator who sets `seccomp = "default"` gets **zero syscall filtering** on any
backend and may believe otherwise; the kernel attack surface is exactly as wide as
with seccomp off, and the "not yet active" signal is uneven (it fires only on the
`none`-path launcher).

This issue ships the actual curated default-deny BPF profile, installs it on all
three backends, makes `is_on()` truthfully mean "syscall-filtered", and adds a
real-Linux acceptance test. It is post-authorization confinement only — it never
changes the signature → trust → policy → approval gate.

**Bound (why p2, not critical).** seccomp ships **off by default**
(`SeccompMode::Off`), so only operators who explicitly opt in are affected, and
it is defence-in-depth on top of the primary isolation that *is* enforced
(bubblewrap user namespace + `--cap-drop ALL` + pid/uts/ipc/net unshare; container
`--read-only` + `no-new-privileges` + `--cap-drop ALL` + `--network none`). A
command requesting `"default"` is still sandboxed — just not syscall-filtered.

## Goals

- **One curated default-deny allowlist profile.** A single canonical source of
  truth (a syscall allowlist) with default action `ERRNO(EPERM)` — matching the
  `SeccompMode::Default` contract (`lib.rs:99-102`) — broad enough to run the real
  build/test command corpus (`sh`, `cargo`, `rustc`, `make`, `git`, `cc`, …) but
  narrow enough to confine. Modeled on the proven Docker/Podman default profile.
- **Install it on the `none` path.** Replace the warn in `run_launcher` with an
  in-process `seccompiler::apply_filter` (a *safe* call) applied **after**
  `setrlimit` and **immediately before** `exec`.
- **Install it on the `bubblewrap` path.** Compile the program, write it to a
  surviving (non-`CLOEXEC`) fd, and pass `--seccomp <fd>` to `bwrap` so bwrap
  installs it *after* its own namespace setup and before exec of the target.
- **Install it on the `container` path.** Write the equivalent OCI-JSON seccomp
  profile to a file and emit `--security-opt seccomp=<path>`, replacing the
  deliberate omission.
- **Make `is_on()` truthful.** Update the doc contract at `lib.rs:80-118` and the
  launcher module doc at `launcher.rs:23-34` so `is_on()` means "syscall-filtered
  where the platform supports it (Linux)", and so neither doc claims an
  aspirational install that does not exist.
- **No silent drops.** Until the install lands on a given path, that path must
  still emit the "not yet active" warning (not silently read `"default"` as
  enforcing). The end state (all three installed) removes the warn on Linux and
  keeps a documented macOS no-op note.
- **Real-Linux acceptance test.** A CI `sandbox-linux` test asserts a
  representative *denied* syscall returns `EPERM` under `seccomp = "default"`
  while a normal build/test command still succeeds — settling the profile-breadth
  and `bwrap --seccomp` byte-format open questions named in `launcher.rs:23-34`.
- **No `unsafe`, Unix-only, MSRV-clean.** All seccomp code is `cfg(target_os = "linux")`,
  uses only safe APIs (`seccompiler::apply_filter`, bwrap `--seccomp`, container
  `--security-opt`), builds on MSRV 1.93, and degrades to a documented no-op on
  macOS.

## Non-Goals

- **Re-doing the already-shipped #349 plumbing.** Policy parse/reject, engine
  resolution, `seccomp_for` threading, the `SeccompMode`/`Seccomp` types, the
  launcher trampoline, and the existing none-path warn / container-no-emit tests
  are done. Only the BPF install (and the honest cross-path warning) is missing.
- **Flipping the default to `seccomp = "default"`.** It stays `off` by default for
  this release; turning it on once the profile is validated against the real
  command corpus is a separate, later rollout (mirrors the cautious E2EE-on
  deferral).
- **A per-syscall policy DSL / user-editable profiles.** Exactly two modes ship:
  `off` and the built-in `default`. Custom profiles remain future work.
- **A `KILL`-action profile.** The default action is `ERRNO(EPERM)` so a too-strict
  profile degrades to a recoverable command failure, not an opaque `SIGSYS` death.
  A `KILL` default is possible future hardening once the allowlist is proven.
- **macOS / Seatbelt parity.** seccomp does not exist on macOS; the launcher's
  seccomp step is a documented no-op there, and bwrap/containers do not run there.
- **`firejail`/`chroot` backends, network egress filtering, cgroup-v2 host
  delegation.** Out of scope (unchanged from #349).
- **Changing signing, trust, approval, or any Matrix event/IPC schema.** This is
  daemon-local, post-authorization confinement only.

## Relevant Repository Context

**Workspace.** Rust Cargo workspace, MSRV 1.93, `unsafe_code = "forbid"` in
`[workspace.lints]` (root `Cargo.toml`); `missing_docs = "warn"` (→ `-D warnings`
in CI, so every new public item needs a doc). `cargo-deny` enforces the license
allowlist (Apache-2.0 included) and restricts sources to crates.io.

**`mx-agent-sandbox` (owning crate).**
- `lib.rs` defines the pure backend abstraction: `Sandbox::prepare(argv,
  Restrictions) -> Prepared { backend, argv, restrictions }`. `prepare` **only
  computes an argv** — this purity is load-bearing; nearly every backend test
  asserts argv shape without spawning. `NoneSandbox`/`BubblewrapSandbox`/
  `ContainerSandbox`.
- `Restrictions` (`lib.rs:200-253`) is the one struct every backend consumes. It
  already carries impure-but-data values set by the runner (`cwd`, `env`,
  `run_uid`, `run_gid`) plus `seccomp: SeccompMode` (`:243`). The runner-supplied
  `run_uid`/`run_gid` → container `--user`/`--cap-drop` pattern (`lib.rs:541-565`)
  is the established template for "runner resolves an impure value, `prepare`
  emits a flag from it purely".
- `SeccompMode` (`lib.rs:94-118`): `Off`/`Default`; `is_on()` (true for `Default`),
  `name()` ("off"/"default"). Its doc (`:89-93`) already *claims* an in-process
  install "via `seccompiler::apply_filter`" — aspirational; no such call exists.
- `launcher.rs`: the self-re-exec trampoline. `LauncherArgs { resources, seccomp,
  command }` with pure `to_args`/`parse` round-trip; `is_needed(resources,
  seccomp, is_none_backend)` decides whether the runner prepends the launcher;
  `run_launcher(args)` applies `setrlimit` (safe `nix::sys::resource::setrlimit`),
  then warns about seccomp, then `exec`s. The whole module is `cfg(unix)`-aware
  and macOS-degrading.
- `Cargo.toml`: depends on `tracing`; under `cfg(unix)`, `nix` with
  `features = ["resource"]`. **`seccompiler` is not yet a dependency.**

**`mx-agent-daemon` (the runner that drives the backends).**
- `runner.rs`: `RunSpec` carries `seccomp: SeccompMode` (`:289`). `launcher_wrap(spec,
  prepared_argv)` (`:456-491`) prepends `[current_exe, __sandbox-exec, …flags, --, argv]`
  for `none`/`bubblewrap` when `LauncherArgs::is_needed`; for bubblewrap it forces
  `seccomp = Off` into the launcher (`:475-479`) because the launcher must not
  filter `bwrap`'s own setup. `build_command(spec)` (`:503+`) calls
  `preflight_backend`, `restrictions_for`, `resolve_sandbox(spec).prepare(...)`,
  then `launcher_wrap`, then spawns via `tokio::process::Command` with
  `env_clear().envs(env)` (**no `pre_exec` — it is `unsafe`**). The interactive
  path mirrors this (`pty_ipc.rs`, `:226` sets `seccomp`).
- `exec.rs::seccomp_for(Seccomp) -> SeccompMode` (`:2645-2650`) is the policy→sandbox
  map; the `RunSpec` is assembled with it at `exec.rs:1950`, `:2221`,
  `tool_exec.rs:282`, `pty_ipc.rs:226`, `task_dispatch.rs:331`, `exec_ipc.rs:715`.
- `restrictions_for(spec, env)` copies `RunSpec` fields onto `Restrictions`.

**`mx-agent-policy`.** `file.rs` `Seccomp` enum (`:131-149`, off/default, serde
`rename_all = "lowercase"`, rejects unknown variants), `execution.seccomp` /
agent override; `engine.rs` resolves it onto `Allowance` (`:107-109`, `:293`,
`:329`). **No change needed here** — the vocabulary is complete.

**`mx-agent-cli`.** Same binary as the daemon; hidden `__sandbox-exec` subcommand
(`cli.rs:127`) dispatches to `run_launcher` via `LauncherArgs::parse`
(`cli.rs:1085-1104`). The daemon already re-execs `current_exe()` for the
launcher and for background start, so a self-re-exec that installs seccomp is an
established pattern.

**CI.** `.github/workflows/ci.yml` `sandbox-linux` job (`:193-229`) installs
`bubblewrap`, lifts the AppArmor userns restriction, sets `MX_AGENT_REQUIRE_BWRAP=1`
(so real-sandbox tests panic instead of skipping), and runs
`cargo test -p mx-agent-sandbox` + a daemon real-bwrap e2e. This is the only
place seccomp can be validated on real Linux (macOS dev hosts cannot).

**Docs that describe the current "deferred" state and must be updated.**
`docs/architecture.md:2186-2196` (Seccomp paragraph), `docs/security-hardening.md:503`,
`:531`, `:606-626`, `docs/alpha-release-checklist.md:163`,
`docs/cli-reference.md:3141`, `:3176`, `:3195`, `:3219`, the README sandbox status
row (`README.md:51`), and the doc-drift guards in
`crates/mx-agent-cli/tests/doc_drift.rs:594-664`.

## Proposed Implementation

The feature decomposes into a shared profile module plus three install slices, in
recommended landing order: **(1) profile module** (single source of truth, fully
unit-tested, no behaviour change) → **(2) `none` path** (lowest risk, in-process,
unit + acceptance) → **(3) `container` path** (JSON file + argv flag, pure-ish) →
**(4) `bubblewrap` path** (fd plumbing, highest risk) → **(5) docs + CI + truthful
`is_on()`**. Each slice can be its own PR; **after each slice, the not-yet-installed
paths must still emit the "not yet active" warning** so `"default"` is never read
silently as enforcing.

### Slice 1 — the curated default-deny profile module (single source of truth)

Add `crates/mx-agent-sandbox/src/seccomp.rs` (new module), `cfg(target_os = "linux")`:

- A canonical **allowlist** expressed once as a table of syscalls. Because
  `seccompiler` rules are keyed by syscall *number* (`i64`) while the OCI JSON
  profile is keyed by *name*, keep them in sync with a single
  `&[(&str /* name */, libc::c_long /* number */)]` table built from
  `libc::SYS_*` constants — `libc::SYS_*` resolves per target arch automatically,
  so x86_64 and aarch64 stay correct. Model the set on the Docker/Podman default
  allowlist (the proven baseline). The list **must** include the process-startup
  and exec set the kernel/libc/loader need after the filter is active: at minimum
  `execve`, `execveat`, `mmap`, `mprotect`, `munmap`, `brk`, `arch_prctl` (x86_64),
  `openat`, `read`, `write`, `close`, `rt_sigaction`, `rt_sigprocmask`,
  `set_tid_address`, `set_robust_list`, `futex`, `clone`/`clone3` (for spawning
  subprocesses in build/test), `wait4`, `exit`, `exit_group`, plus the broad
  filesystem/stat/poll/epoll/socket set ordinary tooling uses.
- `pub fn default_bpf_program() -> Result<seccompiler::BpfProgram, SeccompError>`:
  builds a `seccompiler::SeccompFilter` from the table with
  `default_action = SeccompAction::Errno(libc::EPERM as u32)` and
  `match_action = SeccompAction::Allow` for each listed syscall, for the current
  `seccompiler::TargetArch` (derive from `cfg(target_arch)`), then `compile`s it
  to a `BpfProgram`.
- `pub fn default_profile_json() -> &'static str` **or** `fn write_default_profile(dir)
  -> io::Result<PathBuf>`: the equivalent OCI-JSON seccomp profile string
  (`defaultAction: SCMP_ACT_ERRNO`, one `SCMP_ACT_ALLOW` block listing the same
  names, `architectures: [SCMP_ARCH_X86_64, SCMP_ARCH_AARCH64, …]`). Emit from the
  *same* table so it cannot drift from the BPF program. A unit test asserts the
  JSON name set and the BPF table cover identical syscalls.
- A small `SeccompError` (documented) wrapping `seccompiler` build/compile errors.
- On non-Linux, the module is absent; callers `cfg`-gate to a no-op.

Add the dependency to `crates/mx-agent-sandbox/Cargo.toml` under the existing
`[target.'cfg(unix)'.dependencies]` (or a narrower `cfg(target_os = "linux")`
block): `seccompiler = "…"` and `libc = "…"` (libc is already in the tree via
`nix`; reference the same version). Confirm `seccompiler`'s MSRV ≤ 1.93 and that
it is Apache-2.0 / crates.io (passes `cargo-deny`).

### Slice 2 — `none` path: install in `run_launcher`

In `launcher.rs::run_launcher`, replace the seccomp warn block (`:186-197`) with:
after `apply_resource_limits`, when `args.seccomp.is_on()`:

```rust
#[cfg(target_os = "linux")]
{
    match crate::seccomp::default_bpf_program() {
        Ok(program) => {
            if let Err(e) = seccompiler::apply_filter(&program) {
                // fail-closed: do NOT exec unfiltered when a filter was requested
                return std::io::Error::new(std::io::ErrorKind::Other,
                    format!("failed to install seccomp filter: {e}"));
            }
        }
        Err(e) => return std::io::Error::new(/* … */),
    }
}
#[cfg(not(target_os = "linux"))]
{
    tracing::debug!("seccomp requested but unavailable on this platform; running unfiltered");
}
```

- The filter is applied **after** `setrlimit` and **immediately before**
  `exec_command`; the allowlist includes `execve`/`execveat` so the subsequent
  `exec` and the target's startup succeed. seccomp filters survive `execve`, so
  the target command runs filtered.
- **Fail-closed:** if the program cannot be built or applied, `run_launcher`
  returns an error and the command is *not* exec'd (mirrors the fail-closed
  `setrlimit` handling at `:177`). This is the same posture as the rest of the
  sandbox.
- `apply_filter` is a safe call (the `unsafe` syscall lives inside `seccompiler`),
  so the workspace `forbid(unsafe)` is preserved.

### Slice 3 — `container` path: JSON profile + `--security-opt seccomp=<path>`

- Thread a runner-resolved profile path through `Restrictions`: add
  `pub seccomp_profile_path: Option<PathBuf>` (documented; default `None`, so
  unit tests and the other backends are unaffected). This mirrors `run_uid`:
  an impure value the runner resolves, that `prepare` reads purely.
- In `ContainerSandbox::prepare`, when `restrictions.seccomp.is_on()` **and**
  `seccomp_profile_path` is `Some(path)`, push `--security-opt` /
  `format!("seccomp={path}")` into the `run` flags (alongside the existing
  `no-new-privileges`). When the path is `None` (e.g. not yet written, or macOS),
  emit nothing — never reference a non-existent file (that would break the launch).
- In the daemon runner, for the container backend only: write the OCI-JSON profile
  to a stable, daemon-owned file (e.g. `$MX_AGENT_RUNTIME_DIR/seccomp-default.json`
  or under the daemon data dir) once, world-unwritable, readable by the runtime
  process (rootless podman runs as the invoking uid, so file perms must let that
  uid read it — `0644` owner-only-write is fine). Set `restrictions.seccomp_profile_path`
  to that path. Do this where `run_uid`/`run_gid` are already resolved for the
  container backend (`exec.rs`), keeping `prepare` pure.
- **Replace** the test `container_seccomp_field_not_emitted_by_prepare`
  (`lib.rs:1874-1896`) with its inverse: with `seccomp = Default` **and** a
  `seccomp_profile_path` set, the argv contains `--security-opt seccomp=<path>`;
  with `seccomp = Default` but `seccomp_profile_path = None`, no seccomp flag is
  emitted (so an un-provisioned path cannot break the launch).
- Note: Docker/Podman already apply a built-in default seccomp profile unless
  `--privileged`; shipping mx-agent's explicit profile makes the filter
  independent of the host runtime's default and consistent with the `none`/bwrap
  paths.

### Slice 4 — `bubblewrap` path: `--seccomp <fd>`

`bwrap --seccomp N` reads a raw BPF program (a `struct sock_filter[]`) from fd `N`
and installs it *after* its own namespace setup, immediately before exec of the
target — which is exactly why the launcher must **not** filter bwrap (it would
block `unshare`/`mount`/`pivot_root`). Keep `prepare` pure; the fd is created and
injected by the **runner**:

- Add a pure helper in `mx-agent-sandbox` to inject the flag, unit-testable with a
  fake fd number, e.g. `pub fn bubblewrap_with_seccomp_fd(argv: Vec<String>, fd:
  RawFd) -> Vec<String>` that inserts `["--seccomp", fd.to_string()]` into the
  bwrap flags (after `bwrap`, before the `--` separator). Unit-test that the flag
  lands before `--` and the command after `--` is untouched.
- In the daemon runner (`build_command`, and the PTY spawn path), for
  `Backend::Bubblewrap` with `seccomp.is_on()` on Linux:
  1. Build the `BpfProgram` via `seccomp::default_bpf_program()`.
  2. Serialize it to the raw `struct sock_filter` byte layout and write it to a
     **non-`CLOEXEC`** fd — a `memfd_create` (via `nix`, *without* `MFD_CLOEXEC`)
     or a temp file `dup`'d without `CLOEXEC`. Rewind to offset 0.
  3. Inject `--seccomp <fd>` into the prepared bwrap argv (before `launcher_wrap`
     runs, so it is part of the command the resource-limit launcher carries
     verbatim).
  4. Hold the `OwnedFd` alive until **after** `Command::spawn()` returns (the
     child inherits a copy at fork); then it may be dropped.
- **fd-survival caveat:** the fd must survive (a) the daemon→`__sandbox-exec`
  launcher spawn (when resource caps are also set) and (b) the launcher→`bwrap`
  `exec`. `exec` preserves the fd table; a non-`CLOEXEC` fd survives. Tokio
  inherits non-`CLOEXEC` fds into the child. The real-bwrap acceptance test
  (Slice 5) is what confirms the byte format and fd inheritance end to end.
- Update `LauncherArgs::is_needed` doc (`launcher.rs:73-84`): seccomp on the bwrap
  path is now installed by `bwrap --seccomp` (runner-injected), not the launcher,
  so `is_needed` still only adds the launcher for *resource caps* on bwrap (and
  for caps-or-seccomp on `none`). The `is_needed` behaviour itself does not need
  to change; the doc should explain that bwrap seccomp is handled out-of-band.

### Slice 5 — truthful `is_on()`, docs, CI acceptance test

- Update `SeccompMode` doc (`lib.rs:80-118`) and `launcher.rs` module doc
  (`:23-34`): `is_on()` means "syscall filtering is installed on Linux (a
  documented no-op on macOS)", and remove the "installation is a documented
  follow-up / not yet active" language. Keep the method body (`matches!(self,
  Default)`).
- Replace the interim warn text everywhere it remains; on Linux there is no warn
  for `"default"` once installed; on macOS log a one-time `debug`/`warn` that
  seccomp is unavailable.
- Add the **real-Linux acceptance test** (in `mx-agent-sandbox` tests, gated by
  `bwrap_available_or_required()` / `MX_AGENT_REQUIRE_BWRAP` for the bwrap case,
  and runnable directly for the `none`/launcher case):
  - A *denied* syscall returns `EPERM`. Pick a syscall **not** in the allowlist
    that is easy to trigger and observe — e.g. running `/usr/bin/unshare --user
    true` (calls `unshare(2)`) or a tiny probe; under `seccomp = "default"` the
    syscall returns `EPERM` and the probe exits non-zero. (Choose a probe that is
    independent of bwrap's own setup, since the filter is active only for the
    *target*.)
  - A *normal* build/test command (e.g. `sh -c 'echo ok'`, or a small `cargo`/`cc`
    invocation if available) still **succeeds** under `seccomp = "default"` —
    proving the allowlist is broad enough.
  - Cover both the `none` launcher path (`mx-agent __sandbox-exec --seccomp default
    -- <probe>`) and the bwrap `--seccomp <fd>` path.
- Extend the `sandbox-linux` CI job to run these un-skipped (it already sets
  `MX_AGENT_REQUIRE_BWRAP=1`).

## Affected Files / Crates / Modules

**`crates/mx-agent-sandbox/`**
- `src/seccomp.rs` *(new, Linux-only)* — canonical allowlist table, `default_bpf_program()`,
  `default_profile_json()`/`write_default_profile()`, `SeccompError`.
- `src/lib.rs` — `mod seccomp` (cfg-gated) + re-exports; `Restrictions`
  `seccomp_profile_path: Option<PathBuf>`; `ContainerSandbox::prepare` emits
  `--security-opt seccomp=<path>`; `bubblewrap_with_seccomp_fd` helper; update
  `SeccompMode` docs; **replace** `container_seccomp_field_not_emitted_by_prepare`;
  add container/bwrap-injection argv tests; keep the none/bwrap purity guard.
- `src/launcher.rs` — `run_launcher` installs the filter (Linux) / no-ops (macOS),
  fail-closed; module + `is_needed` doc updates.
- `Cargo.toml` — add Linux-target-gated `seccompiler` (+ `libc`).

**`crates/mx-agent-daemon/`**
- `src/runner.rs` — `build_command`/`launcher_wrap`/PTY spawn: create + inject the
  bwrap `--seccomp` fd; hold the fd until after spawn; doc the bwrap seccomp path.
- `src/exec.rs` — for the container backend, write the JSON profile and set
  `restrictions.seccomp_profile_path` where `run_uid`/`run_gid` are resolved.
- `src/pty_ipc.rs`, `src/tool_exec.rs`, `src/task_dispatch.rs`, `src/exec_ipc.rs`
  — only if a new `RunSpec`/`Restrictions` field needs populating at those sites
  (the seccomp *mode* is already threaded; the profile path/fd are resolved in the
  runner/exec, so most sites are untouched).

**`crates/mx-agent-cli/`**
- `tests/doc_drift.rs` — refresh the issue-#349 seccomp guards (`:594-664`) so they
  assert the now-installed state and don't re-pin "not yet active".
- `tests/sandbox_exec.rs` — extend with a `--seccomp default` launcher case if a
  no-spawn / EPERM assertion fits there.

**Docs:** `docs/architecture.md` (§ seccomp `:2186-2196`), `docs/security-hardening.md`
(`:503`, `:531`, `:606-626`), `docs/alpha-release-checklist.md` (`:163`),
`docs/cli-reference.md` (`:3141`, `:3176`, `:3195`, `:3219`), `README.md` (sandbox
status row `:51`), and the wiki Security-and-Sandboxing page (auto-synced from
`wiki/**`).

**CI:** `.github/workflows/ci.yml` `sandbox-linux` job (`:193-229`).

## CLI / API Changes

- **New public items in `mx-agent-sandbox`** (must be documented — `missing_docs`):
  the `seccomp` module's `default_bpf_program`/`default_profile_json`/`SeccompError`,
  the `bubblewrap_with_seccomp_fd` helper, and the new
  `Restrictions::seccomp_profile_path` field.
- **No new or changed user-facing command, flag, or output.** The hidden
  `__sandbox-exec` subcommand keeps its surface (it already accepts `--seccomp
  off|default`); its *behaviour* changes from warn-and-run to install-and-run.
  Human-readable default and `--json` output of every existing command is
  untouched.
- **No IPC method or wire-protocol change.**

## Data Model / Protocol Changes

- **None to the policy schema, Matrix events, IPC, or audit fields.** `seccomp =
  "off" | "default"` already exists and parses; this issue only makes `"default"`
  actually filter. No new policy key, no new `DenyReason`, no serialization
  change. (The profile JSON file written for the container backend is a local
  artifact, not a persisted/synced data model.)

## Security Considerations

- **Confinement only, never authority.** seccomp runs *after* signature → trust →
  policy → approval. It can only narrow what an already-authorized command may do;
  it never grants execution and is unreachable by an unauthenticated sender.
- **No `unsafe`.** `seccompiler::apply_filter` is a safe API (the `unsafe` syscall
  is inside the crate); bwrap and the container runtime install via flags/fd; the
  in-process install happens in a *fresh launcher process before `exec`*, never via
  `pre_exec`. A reviewer should confirm no `pre_exec`/`unsafe` crept in — the
  workspace `forbid` fails the build otherwise.
- **Fail-closed.** If the BPF program cannot be built or `apply_filter` fails, the
  `none`-path launcher returns an error and does **not** `exec` (no unfiltered
  fallback). The container/bwrap paths surface a spawn/build error rather than
  silently running unfiltered. This matches the existing fail-closed `setrlimit`.
- **`ERRNO(EPERM)`, not `KILL`.** A too-strict profile degrades to a recoverable
  command failure, not an opaque `SIGSYS` — important while the allowlist is being
  tuned (it ships opt-in).
- **No silent enforcement gaps.** During phased rollout, any path without the
  install must still warn so `"default"` is never read as enforcing — the current
  bug is precisely the silent bwrap/container drops.
- **No secrets in argv, logs, or the profile.** The seccomp flag carries only an
  fd number or a profile path; the JSON profile contains only syscall names. The
  profile file is daemon-owned and world-unwritable. The `none`/bwrap warnings (if
  any remain during phasing) log no command args or env (established redaction
  posture).
- **Env scrubbing preserved.** The launcher inherits the daemon's
  `env_clear().envs(sanitized)` environment and passes it through `exec` unchanged;
  installing seccomp adds no variables and re-reads no `std::env`.
- **Unix/Linux-only.** seccomp is `cfg(target_os = "linux")`; macOS is a documented
  no-op (bwrap/containers do not run there anyway). No Windows paths.
- **DoS framing.** Reduces — but does not eliminate — the kernel attack surface an
  authorized-but-misbehaving command can reach; it is defence-in-depth atop the
  enforced namespace/filesystem/cap-drop isolation, not a substitute for it.

## Testing Plan

**Unit — `mx-agent-sandbox` (`seccomp.rs`, Linux-gated, pure):**
- `default_bpf_program()` builds and compiles without error on the supported
  arches; the allowlist includes the mandatory exec/startup syscalls
  (`execve`/`execveat`/`mmap`/`mprotect`/`clone`/…).
- The BPF table and the JSON name set cover **identical** syscalls (drift guard
  over the single source of truth).
- `default_profile_json()` parses as valid JSON with `defaultAction:
  SCMP_ACT_ERRNO` and an `SCMP_ACT_ALLOW` block.

**Unit — `mx-agent-sandbox` (`lib.rs`, pure argv):**
- Container: `seccomp = Default` + `seccomp_profile_path = Some(p)` →
  `--security-opt seccomp=<p>` present; `seccomp_profile_path = None` → no seccomp
  flag (replaces `container_seccomp_field_not_emitted_by_prepare`).
- `bubblewrap_with_seccomp_fd(argv, fd)` inserts `--seccomp <fd>` before `--` and
  leaves the post-`--` command verbatim.
- Regression guard preserved: `none`/`bwrap` `prepare` argv is **unchanged** by
  `seccomp` (the fd is injected by the runner, not `prepare`).
- `SeccompMode::is_on()`/`name()` unchanged (existing `seccomp_mode_methods` test).

**Unit — `mx-agent-daemon` (`runner.rs`):**
- For `Backend::Bubblewrap` + `seccomp.is_on()`, `build_command` produces a bwrap
  argv containing `--seccomp <fd>` and the fd is kept open until spawn (can be
  asserted by inspecting the argv / a seam that returns the prepared argv).
- For the container backend, the resolved `Restrictions::seccomp_profile_path` is
  set and points at a readable file.
- `none`/`bwrap` specs with `seccomp = Off` produce no seccomp flag (no behaviour
  change).

**Integration — real Linux (`sandbox-linux`, `MX_AGENT_REQUIRE_BWRAP`):**
- `none` launcher: `mx-agent __sandbox-exec --seccomp default -- <denied-probe>`
  → the denied syscall returns `EPERM` (probe exits non-zero); `--seccomp default
  -- sh -c 'echo ok'` succeeds.
- bwrap `--seccomp <fd>`: a command inside the sandbox hitting a denied syscall
  gets `EPERM`; a normal build/test command succeeds — confirms the byte format
  and fd inheritance.
- (Where a runtime is available) container `--security-opt seccomp=<path>`:
  denied syscall `EPERM`, normal command succeeds; skips gracefully when no
  runtime, like the existing container integration tests.

**Docs:** `doc_drift.rs` updated so the §13.5 seccomp claim reflects the installed
state and cannot silently drift back to "not yet active".

## Documentation Updates

- **`docs/architecture.md`** (§ seccomp, `:2186-2196`) — rewrite to: `"default"`
  installs a curated default-deny (`ERRNO(EPERM)`) BPF profile in-process on the
  `none` path, via `bwrap --seccomp` on bubblewrap, and via `--security-opt
  seccomp=` on containers; Linux-only (macOS no-op); still **off by default** with
  the on-by-default flip a later rollout. Drop the "open question / not yet active"
  language.
- **`docs/security-hardening.md`** (`:503`, `:531`, `:606-626`) — update the
  `seccomp` policy-table rows and the "Syscall filtering" subsection: selecting
  `"default"` now filters syscalls; remove "BPF profile installation is a
  documented follow-up / pending". Keep the opt-in + `EPERM` + Linux-only notes.
- **`docs/alpha-release-checklist.md`** (`:163`) — replace "opt-in machinery; the
  curated default-deny BPF profile [pending]" with "curated default-deny profile
  ships, opt-in (`off` default)".
- **`docs/cli-reference.md`** (`:3141`, `:3176`, `:3195`, `:3219`) — update the
  `execution.seccomp` / agent-override descriptions to "installs a default-deny
  profile (Linux)".
- **`README.md`** (sandbox status row `:51`) — change "seccomp is opt-in machinery
  (default off, default-deny profile install a follow-up)" to "seccomp ships a
  default-deny profile, opt-in (default off, Linux)".
- **Wiki** Security-and-Sandboxing page — mirror the above (auto-synced from
  `wiki/**`).

## Risks and Open Questions

1. **Profile breadth (highest risk).** A default-deny allowlist that is too strict
   breaks arbitrary build/test commands; too loose adds little. Mitigated by
   shipping `off` by default and `ERRNO` (not `KILL`). *Decision:* base the
   allowlist on the Docker/Podman default profile and validate against the real
   command corpus (`sh`, `cargo`, `rustc`, `make`, `git`, `cc`, `ld`, package
   managers) in the acceptance test; expand the list if a common tool trips.
2. **`bwrap --seccomp` byte format + fd inheritance.** Confirm `seccompiler`'s
   serialized `BpfProgram` is byte-identical to the `struct sock_filter[]` bwrap
   expects, and that a non-`CLOEXEC` fd survives the daemon→launcher→bwrap exec
   chain. The real-bwrap acceptance test is the settling mechanism. *Fallback:* if
   the byte format mismatches, drop bwrap seccomp to a documented gap and keep
   none + container, or write via `--seccomp` only when no resource-launcher is
   interposed.
3. **Choice of denied probe syscall for the test.** Must be reliably denied,
   independent of bwrap's own setup (the filter is active only for the target),
   and observable as `EPERM`. Candidate: `unshare(2)` via `/usr/bin/unshare`
   (kept out of the allowlist for the target), or a tiny in-repo probe binary.
4. **`seccompiler` MSRV / supply chain.** Confirm `seccompiler` builds on MSRV
   1.93, is Apache-2.0, and passes `cargo-deny` (advisories/licenses/sources). It
   adds a Linux-only dep to a security-critical crate. *Fallback:* hand-roll the
   BPF or use `libseccomp` (C dep — less attractive) if `seccompiler` does not fit.
5. **`TargetArch` coverage.** seccompiler builds per-arch; ensure x86_64 and
   aarch64 (CI runners + common dev) are handled and any unsupported arch fails
   loudly rather than installing a wrong-arch filter.
6. **Container profile file location/perms.** The JSON must be readable by the
   runtime process (rootless podman = invoking uid). Decide a stable daemon-owned
   path (runtime dir vs data dir), `0644`, written once or per-run; ensure it is
   recreated if missing and never world-writable.
7. **`is_on()` on macOS.** Under the new "syscall-filtered" contract, `is_on()`
   returning `true` on macOS is technically not "filtered" (no seccomp). Document
   it as "filtering requested; installed on Linux, no-op on macOS" rather than
   changing the method to lie per-platform.
8. **Interaction with the resource-limit launcher on bwrap.** When both caps and
   seccomp are set on bwrap, the argv becomes
   `[current_exe, __sandbox-exec, --as N, --, bwrap, --seccomp FD, …, --, cmd]`.
   Verify the launcher's first-`--` split and the fd both survive — covered by a
   runner unit test plus the acceptance test.

## Implementation Checklist

1. **Profile module (no behaviour change).**
   - [ ] Add `crates/mx-agent-sandbox/src/seccomp.rs` (Linux-gated): canonical
         `(name, libc::SYS_*)` allowlist, `default_bpf_program()` (`ERRNO(EPERM)`
         default action), `default_profile_json()`/`write_default_profile()`,
         `SeccompError`; all documented.
   - [ ] Add Linux-target-gated `seccompiler` (+ `libc`) to
         `crates/mx-agent-sandbox/Cargo.toml`; verify MSRV 1.93 + `cargo-deny`.
   - [ ] Unit tests: program builds/compiles; BPF table ↔ JSON names identical;
         JSON valid with `SCMP_ACT_ERRNO` default.

2. **`none` path install.**
   - [ ] In `run_launcher`, replace the warn with `apply_filter` (Linux,
         fail-closed) after `setrlimit`, before `exec`; macOS debug no-op.
   - [ ] Acceptance test (launcher): denied syscall → `EPERM`; normal command
         succeeds.

3. **`container` path install.**
   - [ ] Add `Restrictions::seccomp_profile_path: Option<PathBuf>` (documented).
   - [ ] `ContainerSandbox::prepare`: emit `--security-opt seccomp=<path>` when
         `seccomp.is_on()` && path set; nothing when path `None`.
   - [ ] Runner/`exec.rs`: write the JSON profile to a daemon-owned file and set
         the path for the container backend (where `run_uid`/`run_gid` resolve).
   - [ ] Replace `container_seccomp_field_not_emitted_by_prepare` with the
         inverse (flag present when path set; absent when `None`).

4. **`bubblewrap` path install.**
   - [ ] Add pure `bubblewrap_with_seccomp_fd(argv, fd)` helper + unit test.
   - [ ] Runner: build BPF → serialize → non-`CLOEXEC` fd (memfd/temp) → inject
         `--seccomp <fd>` into the bwrap argv before `launcher_wrap`; hold the fd
         until after spawn.
   - [ ] Mirror on the interactive PTY spawn path.
   - [ ] Update `LauncherArgs::is_needed` doc (bwrap seccomp is out-of-band now).
   - [ ] Acceptance test (real bwrap): denied syscall → `EPERM`; normal command
         succeeds (confirms byte format + fd inheritance).

5. **Truthful `is_on()` + docs + CI.**
   - [ ] Update `SeccompMode` doc (`lib.rs:80-118`) and `launcher.rs` module doc
         (`:23-34`); remove "not yet active / follow-up" language; document macOS
         no-op.
   - [ ] Ensure no path silently reads `"default"` as enforcing during phasing
         (warn until each path's install lands).
   - [ ] Update `docs/architecture.md`, `docs/security-hardening.md`,
         `docs/alpha-release-checklist.md`, `docs/cli-reference.md`, `README.md`,
         wiki; refresh `doc_drift.rs` guards.
   - [ ] Extend `sandbox-linux` CI to run the seccomp acceptance tests un-skipped.
   - [ ] `cargo fmt --check`, `cargo clippy --all-targets --all-features -D
         warnings`, `cargo test --all` green; live Tuwunel suite unaffected.
