# Issue #349 — Sandbox depth: seccomp-bpf, rlimit/cgroup resource caps, container `--cap-drop ALL` via `--user`

## Problem Statement

The mx-agent sandbox backends (`crates/mx-agent-sandbox/`, wired through
`crates/mx-agent-daemon/src/runner.rs` and `pty.rs`) already confine an allowed
command's cwd, environment, network, and filesystem binds. Bubblewrap adds a
user namespace, `--cap-drop ALL`, private `/proc`/`/dev`/tmpfs, and
`--new-session`; containers add `--read-only` and `--security-opt
no-new-privileges`. Two depth gaps remain — documented today as known
limitations in `docs/architecture.md` §13.5, `docs/security-hardening.md`, and
`docs/alpha-release-checklist.md`:

1. **No syscall filtering and no resource caps.** There is no seccomp-bpf filter
   and no `setrlimit`/cgroup capping on any host path. An allowed command can
   fork-bomb, exhaust memory, or spin CPU on the host. Only `max_runtime_ms`
   (wall clock) and `max_output_bytes` bound it.
2. **The container backend deliberately does *not* `--cap-drop ALL`.** It runs as
   root-in-container, and dropping `CAP_DAC_OVERRIDE` would block writes to a
   host-owned `writable_paths` mount. Full cap-drop was deferred pending a
   `--user` uid-mapping. The container backend is therefore weaker than bwrap.
3. **The built-in fallback backend is `none`** (zero isolation) when policy does
   not select one. An execution permitted with `sandbox = none` runs with no
   isolation and only an advisory doc note, no runtime signal.

This issue closes those gaps: add a seccomp + resource-limit *confinement floor*
that layers under the existing namespace/filesystem backends, make container
`--cap-drop ALL` viable via `--user` uid-mapping, and make `sandbox = none`
loud (and optionally gated).

## Goals

- **Resource caps from policy.** New policy keys cap a sandboxed process's
  process count (`RLIMIT_NPROC` / container `--pids-limit`), address space /
  memory (`RLIMIT_AS` or `RLIMIT_DATA` / container `--memory`), and CPU time
  (`RLIMIT_CPU` seconds / container `--ulimit cpu`). They resolve through the
  policy engine onto the `Allowance`, then `RunSpec` → `Restrictions`, and are
  enforced for batch `exec`, named `call`, auto-executed task DAGs, the
  interactive `--pty` path, and the loopback floor — exactly the surfaces the
  existing sandbox controls already cover.
- **Default-deny seccomp-bpf.** A curated allowlist ("default") seccomp profile
  applies to the `bubblewrap` and `none` execution paths (Linux), and to the
  container backend via `--security-opt seccomp=<profile>`. It is policy-selectable
  and, for the first release, **opt-in** (default `off`) to avoid breaking the
  open-ended set of commands operators run today; flipping the default to on is a
  documented follow-up.
- **Container `--cap-drop ALL` via `--user`.** The container backend runs as the
  daemon's own uid:gid (`--user <uid>:<gid>`) so writes to host-owned
  `writable_paths` succeed without `CAP_DAC_OVERRIDE`, and then drops all
  capabilities (`--cap-drop ALL`). This brings the container backend up to bwrap
  parity.
- **Loud (optionally gated) `sandbox = none`.** When an execution is permitted
  and its resolved backend is `Backend::None`, the daemon emits a prominent,
  non-sensitive warning. A new opt-in workspace knob `execution.require_sandbox`
  (default `false`, fail-closed when `true`) lets an operator turn that warning
  into a hard denial.
- **No `unsafe`, Unix-only, MSRV-clean.** The whole feature is implemented
  without `unsafe` Rust (the workspace forbids it), without Windows assumptions,
  and builds on MSRV 1.93. Linux-only mechanisms (seccomp, cgroup) are
  `cfg`-gated and degrade to documented no-ops on macOS.
- **Docs and CI updated.** The §13.5 backend list, the security-hardening backend
  table, the alpha-checklist limitation, the cli-reference policy table, and the
  doc-drift guard reflect what actually ships. The `sandbox-linux` CI job
  exercises the new controls under real bwrap / a real container runtime.

## Non-Goals

- **Implementing `firejail` / `chroot` backends.** They remain rejected at policy
  load (issue #310). Unchanged.
- **General cgroup-v2 delegation for the host (`none`/`bwrap`) paths.** True
  cgroup accounting for a non-container host process needs a delegated cgroup
  (e.g. `systemd-run --user --scope`) or root, which is environment-specific.
  This issue uses **`setrlimit`** for host paths and **cgroup-backed runtime
  flags** (`--memory`/`--pids-limit`/`--cpus`) only for the container backend.
  `systemd-run`-based host cgroups are explicitly deferred and called out as a
  future enhancement.
- **A user-facing seccomp profile editor / per-syscall policy DSL.** Exactly two
  modes ship: `off` and a built-in curated `default` profile. Custom profiles are
  future work.
- **Network egress filtering beyond the existing namespace deny.** Out of scope;
  `network = "deny"` already drops the network namespace.
- **Changing the request/result-plane signing, trust, or approval gates.** This
  is post-authorization confinement only; it never grants execution and never
  substitutes for signature → trust → policy → approval.
- **macOS sandbox parity.** seccomp/cgroup do not exist on macOS; only
  `setrlimit` applies there. No `sandbox_init`/Seatbelt work.

## Relevant Repository Context

**Workspace.** Rust Cargo workspace, MSRV 1.93, `unsafe_code = "forbid"` in
`[workspace.lints]` (root `Cargo.toml`). Crates relevant here:

- `mx-agent-sandbox` — pure, no-spawn backend abstraction. `Sandbox::prepare(argv,
  Restrictions) -> Prepared { backend, argv, restrictions }`. Backends:
  `NoneSandbox`, `BubblewrapSandbox`, `ContainerSandbox`. `Restrictions` is the
  one struct every backend consumes (cwd, env, timeout, max_output_bytes,
  network, read_only_paths, writable_paths, interactive). `prepare` only *computes
  an argv*; this purity is load-bearing — almost all backend tests assert argv
  shape without spawning. `sandbox_for` / `sandbox_for_container` /
  `preflight_backend` / `backend_program` / `find_in_path` round it out.
- `mx-agent-policy` — `file.rs` defines the TOML schema (`ExecutionPolicy`,
  `AgentPolicy`, `RoomPolicy`, `Sandbox`, `NetworkPolicy`) and `Policy::validate`
  (dotted-path errors, `deny_unknown_fields`). `engine.rs` defines `Allowance`
  and the deny-by-default `evaluate_exec` / `evaluate_call` /
  `execution_allowance` / `allowance_for`. `load_optional` distinguishes
  absent (Ok(None), deny-all) from malformed (Err) — issue #350.
- `mx-agent-daemon` —
  - `runner.rs`: `RunSpec` (the non-protocol view of an authorized exec) +
    `restrictions_for(spec, env) -> Restrictions` (pure) + `resolve_sandbox(spec)
    -> Box<dyn Sandbox>` + `build_command` (spawns through `tokio::process`,
    `env_clear().envs(env)`, `process_group(0)`, `preflight_backend`). Output cap
    is enforced by the capture stage, timeout by `run`. **The child is spawned
    directly via `tokio::process::Command`; there is no `pre_exec` hook (it is
    `unsafe`, which the workspace forbids).**
  - `pty.rs`: `PtySession::spawn(spec, size)` mirrors `runner` for the
    interactive path; it calls `restrictions_for`, sets `restrictions.interactive
    = true`, then `resolve_sandbox(spec).prepare(...)`.
  - `exec.rs`: `sandbox_backend(Option<Sandbox>) -> Backend`,
    `container_runtime_for(...) -> Runtime`, `network_for(...) -> Network` map
    policy → sandbox-layer values; the `RunSpec` is assembled here (lines ~1600
    and ~1870) and in `task_dispatch.rs` / `tool_exec.rs` / loopback.
- `nix` dependency: workspace declares `features = ["signal", "process",
  "user"]`; the daemon enables `["fs"]`. `setrlimit` needs the **`resource`**
  feature; `Uid::current()`/`Gid::current()` need **`user`** (already on).
- The CLI (`mx-agent-cli`) is the same binary as the daemon and already has a
  hidden subcommand pattern (`#[command(subcommand, hide = true)]`,
  `cli.rs:117`), and the daemon already re-execs `current_exe()` for background
  start (`lifecycle.rs`) — so a hidden self-re-exec launcher subcommand is an
  established, idiomatic pattern here.

**The critical constraint — no `pre_exec`.** The textbook way to set rlimits and
install a seccomp filter is `std::os::unix::process::CommandExt::pre_exec`, which
is an `unsafe fn`. The workspace `forbid`s unsafe (a `forbid` cannot be locally
`allow`-overridden), so `pre_exec` is unavailable anywhere. The design below
works *around* this with safe APIs only:

- `nix::sys::resource::setrlimit` is **safe**.
- `std::os::unix::process::CommandExt::exec` (replace the current process image)
  is **safe** (only `pre_exec` is unsafe).
- A pure-Rust seccomp compiler (`seccompiler`) exposes a **safe**
  `apply_filter(&BpfProgram)` (the `unsafe` syscall lives inside that crate, not
  our workspace).
- bubblewrap installs a seccomp filter for us via its native `--seccomp <fd>`
  flag (no in-process syscall at all).
- docker/podman enforce limits and seccomp via run flags
  (`--ulimit`/`--memory`/`--pids-limit`/`--security-opt seccomp=`).

So the only place we *install* seccomp/rlimits in-process is inside a **fresh
launcher process** that does its work and then `exec()`s the target — never via
`pre_exec` on the daemon's spawn.

## Proposed Implementation

The feature decomposes into four independent slices. Recommended landing order:
**(C) container `--user`/`--cap-drop`** and **(D) `none` warning/gate** first
(lowest risk, no new deps, no new process), then **(A) resource limits**, then
**(B) seccomp** (highest risk — profile tuning + new dependency + the launcher).
Each can be its own PR under #349.

### Shared: extend `Restrictions`, `Allowance`, `RunSpec`, policy schema

Thread a small resource-limit struct and a seccomp mode through the existing
pure pipeline so backends can emit the right flags and the runner can drive the
launcher.

```rust
// mx-agent-sandbox
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ResourceLimits {
    pub max_processes: Option<u64>,     // RLIMIT_NPROC / --pids-limit / --ulimit nproc
    pub max_memory_bytes: Option<u64>,  // RLIMIT_AS (or DATA) / --memory / --ulimit as
    pub max_cpu_seconds: Option<u64>,   // RLIMIT_CPU / --ulimit cpu
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SeccompMode {
    #[default] Off,
    Default,   // built-in curated allowlist profile
}

// added to Restrictions:
pub resources: ResourceLimits,
pub seccomp: SeccompMode,
pub run_uid: Option<u32>,   // container --user; daemon's own uid
pub run_gid: Option<u32>,
```

Policy (`ExecutionPolicy` and `AgentPolicy`, `#[serde(default)]` so old files
parse unchanged):

```toml
[execution]
default_sandbox = "bubblewrap"
max_processes   = 256          # RLIMIT_NPROC
max_memory_bytes = 2147483648  # 2 GiB, RLIMIT_AS
max_cpu_seconds = 120          # RLIMIT_CPU (CPU-seconds, distinct from wall clock)
seccomp = "default"            # "off" (default) | "default"
require_sandbox = true         # deny execution that resolves to Backend::None
```

`Allowance` gains `resources: ResourceLimits` and `seccomp: SeccompMode`
(`execution.*` defaults, with per-agent override the same way `sandbox`/`network`
resolve in `allowance_for`). `require_sandbox` lives only at
`execution`-scope. `Policy::validate` rejects zero values for the three caps
with a dotted-path error (mirroring the existing `max_runtime_ms == Some(0)`
check). `RunSpec` gains the same `resources` / `seccomp` fields plus
`run_uid`/`run_gid`; `restrictions_for` copies them onto `Restrictions`.

`exec.rs` resolves them where it builds the `RunSpec` (both call sites, plus
`task_dispatch.rs`, `tool_exec.rs`, and the loopback floor) from the
`Allowance`. `run_uid`/`run_gid` come from `nix::unistd::Uid::current()` /
`Gid::current()` (safe), populated only for the container backend.

### (A) Resource limits — `setrlimit` on host paths, cgroup flags in containers

**Container backend (`ContainerSandbox::prepare`, pure).** Emit native flags
from `Restrictions::resources`:

- `max_processes` → `--pids-limit <n>` (cgroup-enforced; superior to NPROC for
  fork-bomb prevention).
- `max_memory_bytes` → `--memory <n>` (cgroup memory cap).
- `max_cpu_seconds` → `--ulimit cpu=<n>:<n>` (RLIMIT_CPU inside the container;
  `--cpus` is a *rate*, not a total, so it is not the right primitive for a
  cap — keep CPU-seconds as the cross-backend meaning).

All three are omitted when `None`. Unit-tested by argv assertion like the
existing container tests.

**`none` and `bubblewrap` backends — the launcher.** Because these have no
runtime to enforce limits and we cannot `pre_exec`, introduce a hidden
self-re-exec launcher:

- New `mx_agent_sandbox::launcher` module: a public `run_launcher(args:
  LauncherArgs) -> std::io::Error` that (1) calls `nix::sys::resource::setrlimit`
  for each `Some` cap, (2) when `seccomp == Default` on Linux applies the
  compiled BPF program via `seccompiler::apply_filter`, then (3)
  `Command::new(target[0]).args(target[1..]).exec()`. It returns only on failure
  (exec replaces the image). Pure parsing of `LauncherArgs` is unit-testable; the
  setrlimit/exec behaviour is integration-tested.
- New hidden CLI subcommand (e.g. `mx-agent __sandbox-exec --nproc N --as M
  --cpu S [--seccomp default] -- <argv>`) in `mx-agent-cli` that calls
  `run_launcher`. Hidden from help (`hide = true`), and rejected for any
  non-self caller is unnecessary (it confers no privilege — it only *narrows*).
- The **runner** (not `prepare`, to keep `prepare` pure and free of
  `current_exe`) prepends the launcher prefix to the prepared argv for the
  `none`/`bubblewrap` backends when any cap is set or seccomp is on:
  `[current_exe, "__sandbox-exec", …flags, "--", <prepared.argv>]`. The launcher
  inherits the already-`env_clear().envs(sanitized)` environment from
  `build_command` and passes it through `exec`, so env scrubbing is unchanged.

**`bubblewrap` ordering caveat.** rlimits set by the launcher on the `bwrap`
process are inherited by the final command — fine. seccomp, however, must **not**
be applied by the launcher around `bwrap` (it would filter bwrap's own
`unshare`/`mount`/`pivot_root` setup syscalls and break it). For bubblewrap,
seccomp is installed by bwrap itself (see (B)); the launcher only does rlimits
for the bwrap path.

**`RLIMIT_NPROC` under a user namespace is best-effort.** NPROC is counted per
real UID; inside bubblewrap's `--unshare-user` the mapping makes the cap
imprecise. For containers, `--pids-limit` (cgroup) is exact. Document NPROC on
the bwrap/none path as a best-effort fork-bomb dampener, not a hard guarantee,
and recommend the container backend where exact pid capping matters.

### (B) seccomp-bpf default-deny profile

**Profile.** Ship a curated **allowlist** ("default-deny everything not listed")
profile modeled on the Docker/Podman default seccomp profile — allow the broad
set of syscalls ordinary build/test tooling needs, default-action `ERRNO(EPERM)`
(not `KILL`, so a blocked syscall surfaces as a normal failure rather than an
opaque SIGSYS). Generate it with `seccompiler`:

- Build a `seccompiler::SeccompFilter` for the default profile, compile to a
  `BpfProgram` (`Vec<sock_filter>`).
- **`none` path:** the launcher calls `seccompiler::apply_filter(&program)`
  (safe) just before `exec`.
- **`bubblewrap` path:** the runner serializes the `BpfProgram` to the raw
  `struct sock_filter` byte layout bwrap expects, writes it to a `memfd`/temp fd,
  and passes `--seccomp <fd>` to bwrap; bwrap installs it after namespace setup,
  immediately before exec. The runner must keep that fd un-`CLOEXEC` so it
  survives into bwrap (open with `OFlag` minus cloexec, or `fcntl` clear). **Open
  question:** confirm bwrap's `--seccomp` byte format matches seccompiler's
  serialized output (both target `struct sock_filter`); add a real-bwrap
  acceptance test that a blocked syscall fails.
- **`container` path:** write the equivalent JSON seccomp profile (or rely on the
  runtime default and only *narrow* via a shipped JSON) and pass `--security-opt
  seccomp=<path>`. Docker/Podman already apply a default seccomp profile unless
  `--privileged`; the explicit profile makes mx-agent's filter independent of the
  host runtime's default.

**Default off for v1.** `seccomp` defaults to `Off` so existing deployments do
not suddenly start `EPERM`-ing syscalls their commands rely on. The `default`
profile is opt-in. Document a follow-up to validate the profile against the real
command corpus and then flip the default on (mirroring the cautious E2EE-on-by-
default deferral pattern). `Off` produces no launcher seccomp step, no bwrap
`--seccomp`, and no container `--security-opt seccomp`.

**Linux-only.** seccomp is gated behind `cfg(target_os = "linux")`. On macOS the
launcher's seccomp step is a documented no-op (with a one-time warning if a
policy requests `seccomp = "default"` there), and bwrap/containers do not run on
macOS anyway. Add `seccompiler` as a Linux-only (target-gated) dependency of
`mx-agent-sandbox`; confirm its MSRV ≤ 1.93.

### (C) Container `--user` uid-mapping → `--cap-drop ALL`

In `ContainerSandbox::prepare`:

- Add `--user <uid>:<gid>` from `Restrictions::run_uid`/`run_gid` when present.
  The runner sets these to the daemon's own uid/gid, so the container process
  owns the same identity that owns the host `writable_paths` mounts — writes
  succeed *without* `CAP_DAC_OVERRIDE`.
- Add `--cap-drop ALL` (keep `--security-opt no-new-privileges`). Update the
  existing test `container_includes_privilege_hardening` (which currently asserts
  `--cap-drop` is *absent*) to assert it is *present*, and update
  `container_non_interactive_omits_tty_flags`'s full-argv expectation.
- Update the `ContainerSandbox` doc comment and §13.5 to drop the "deferred"
  language.

**Rootless-podman nuance (open question).** Under rootless podman the container
"root" is already mapped to the invoking host uid via `/etc/subuid`, so
`--user <hostuid>` inside that user namespace does **not** mean the host uid and
can break writes. Options: (a) for `podman`, prefer `--userns=keep-id` and omit
`--user`, or (b) detect rootless and skip `--user`. Recommend gating the
`--user` mapping to `Runtime::Docker` initially, documenting podman as
`--userns=keep-id`, and covering the real behaviour in the container integration
test on CI. Decide before landing.

### (D) Loud / gated `sandbox = none`

- In the daemon enforcement path (where `RunSpec.sandbox` is resolved — `exec.rs`
  and the shared task/loopback assembly), when the resolved backend is
  `Backend::None` **and** the request is permitted, emit a single `warn!`
  naming the room/requester/target (no secrets) that the command will run
  **unsandboxed**. This is advisory and always on.
- Add `execution.require_sandbox: bool` (default `false`). When `true`, an
  otherwise-allowed request whose resolved backend is `Backend::None` is **denied
  fail-closed** with a new `DenyReason::SandboxRequired` (audited as
  `deny:sandbox_required`, no `sandbox` field per the existing denied-record
  convention). The check lives in the daemon disposition step (it needs the
  resolved backend), not in the pure policy engine, OR is surfaced from the
  engine as a new deny reason if the engine already knows the resolved sandbox —
  prefer wherever `sandbox_backend(allowance.sandbox)` is computed today.
- Default `false` preserves backward compatibility; the warning still fires.

## Affected Files / Crates / Modules

**`crates/mx-agent-sandbox/src/lib.rs`**
- New `ResourceLimits`, `SeccompMode`; new `Restrictions` fields (`resources`,
  `seccomp`, `run_uid`, `run_gid`).
- `ContainerSandbox::prepare`: `--user`, `--cap-drop ALL`, `--pids-limit`,
  `--memory`, `--ulimit cpu`, `--security-opt seccomp=`.
- New `launcher` module (`run_launcher`, `LauncherArgs`); seccomp profile builder
  (Linux-only); BPF→`sock_filter` serialization for bwrap.
- Update tests: container cap-drop now present, new argv assertions, launcher
  arg-parse tests.
- **`crates/mx-agent-sandbox/Cargo.toml`**: target-gated `seccompiler` (Linux);
  add `nix` with `resource` (+ `user`) features if the crate applies rlimits
  itself.

**`crates/mx-agent-policy/src/file.rs`**
- `ExecutionPolicy` + `AgentPolicy`: `max_processes`, `max_memory_bytes`,
  `max_cpu_seconds`, `seccomp`; `ExecutionPolicy::require_sandbox`. New `Seccomp`
  enum (`off`/`default`). Validation: reject zero caps; (no validation needed for
  the enum — serde rejects unknown variants).

**`crates/mx-agent-policy/src/engine.rs`**
- `Allowance`: `resources`, `seccomp` (+ resolve in `allowance_for` and
  `execution_allowance`). Optional new `DenyReason::SandboxRequired`.

**`crates/mx-agent-daemon/src/runner.rs`**
- `RunSpec`: `resources`, `seccomp`, `run_uid`, `run_gid`; `restrictions_for`
  threads them; `build_command` prepends the launcher prefix for `none`/`bwrap`
  and wires the bwrap `--seccomp` fd.

**`crates/mx-agent-daemon/src/pty.rs`**
- `PtySession::spawn`: same launcher/fd wiring on the interactive path.

**`crates/mx-agent-daemon/src/exec.rs`**
- Populate the new `RunSpec` fields from the `Allowance` at both assembly sites;
  resolve `run_uid`/`run_gid` for the container backend; emit the `none` warning;
  enforce `require_sandbox`. Update `sandbox_backend` doc if needed.

**`crates/mx-agent-daemon/src/{task_dispatch.rs, tool_exec.rs}`** and any other
`RunSpec` constructor — populate the new fields.

**`crates/mx-agent-cli/src/cli.rs`** — hidden `__sandbox-exec` subcommand →
`run_launcher`.

**Docs**: `docs/architecture.md` §13.3 (new policy keys) + §13.5 (rewrite the
"no seccomp/rlimit" + "container deferred cap-drop" paragraphs);
`docs/security-hardening.md` (backend table + "What the sandbox does not do");
`docs/alpha-release-checklist.md` (limitation bullet); `docs/cli-reference.md`
(policy table rows + sandbox note); `crates/mx-agent-cli/tests/doc_drift.rs`
(any pinned §13.5 strings).

**CI**: `.github/workflows/ci.yml` `sandbox-linux` job — exercise seccomp/rlimit
under real bwrap and (where a runtime is available) `--cap-drop ALL` writes.

## CLI / API Changes

- **New public types in `mx-agent-sandbox`** (must be documented — `missing_docs`
  is a CI-warned lint): `ResourceLimits`, `SeccompMode`, `LauncherArgs`,
  `run_launcher`, new `Restrictions` fields.
- **New hidden CLI subcommand** `mx-agent __sandbox-exec` — internal re-exec
  trampoline, hidden from `--help`, not part of the stable user surface. No
  change to any existing command's flags or output. Human-readable default and
  `--json` behaviour of every existing command is untouched.
- No IPC method or wire-protocol change.

## Data Model / Protocol Changes

- **Policy schema (additive, backward-compatible):** `execution.max_processes`,
  `execution.max_memory_bytes`, `execution.max_cpu_seconds`,
  `execution.seccomp`, `execution.require_sandbox`, and the per-agent overrides
  for the three caps + `seccomp`. All `#[serde(default)]`, so existing
  `policy.toml` files parse unchanged and resolve to "no extra cap / seccomp off
  / sandbox not required" (current behaviour).
- **Audit log:** a `require_sandbox` denial records `decision = "denied"`,
  `policy_rule = "deny:sandbox_required"`, no `sandbox` field — consistent with
  the existing denied-record shape (§13.6). No new audit field.
- **No Matrix event schema change.** This is post-authorization, daemon-local
  confinement; nothing new is signed, published, or synced.

## Security Considerations

- **Confinement only, never authority.** seccomp, rlimits, `--cap-drop`, and the
  `none` gate run *after* signature → trust → policy → approval. They can only
  narrow what an already-authorized command may do (or, for `require_sandbox`,
  add a denial). They never grant execution and must not be reachable by an
  unauthenticated sender.
- **No `unsafe`.** Enforced by the launcher design (safe `setrlimit`, safe
  `apply_filter`, safe `exec`, bwrap `--seccomp`, container flags). A reviewer
  should confirm no `pre_exec` or other `unsafe` crept in; the workspace `forbid`
  will fail the build if it did.
- **Env scrubbing preserved.** The launcher inherits the daemon's
  already-`env_clear().envs(sanitized)` environment and passes it through `exec`
  unchanged — it adds no variables and must not re-read `std::env`. The container
  `--user`/`--cap-drop`/limit flags carry no secrets (only numbers and uid/gid).
- **No secrets in argv or logs.** Resource caps and uid/gid are non-sensitive.
  The `none` warning and the `sandbox_required` denial log room/requester/target
  ids only (the established redaction posture), never command args or env.
- **Seccomp fail-mode.** Default action `ERRNO(EPERM)` rather than `KILL` so a
  too-strict profile degrades to a recoverable command failure, not an opaque
  process death — important while the profile is still being tuned. A `KILL`
  default could be a future hardening once the allowlist is proven.
- **`--cap-drop ALL` correctness.** Dropping all caps is only safe because
  `--user` makes the container process the mount-owning uid; landing them
  together (slice C) is mandatory — never `--cap-drop ALL` without the matching
  `--user` mapping, or writes to `writable_paths` break.
- **Unix-only.** seccomp/cgroup are Linux; `setrlimit` is Linux+macOS; the
  launcher and `--user` are Unix. All new code is `cfg(unix)` / `cfg(target_os =
  "linux")` as appropriate, with no Windows paths.
- **DoS framing.** This directly mitigates host resource-exhaustion (fork bomb,
  memory/CPU exhaustion) by an *authorized but misbehaving* command — the exact
  threat called out in the issue. It does not defend against a kernel
  vulnerability; seccomp reduces but does not eliminate kernel attack surface.

## Testing Plan

**Unit — policy (`file.rs` / `engine.rs`):**
- New keys parse at execution and agent scope; omitting them keeps current
  defaults (caps `None`, `seccomp = Off`, `require_sandbox = false`).
- Zero-value caps rejected with the precise dotted path (mirror
  `zero_runtime_reports_precise_path`).
- `seccomp` accepts `"off"`/`"default"`, rejects unknown variants (serde).
- `allowance_for` / `execution_allowance` carry `resources` + `seccomp`; agent
  override beats execution default (mirror the network-override test).

**Unit — sandbox (`lib.rs`, pure argv):**
- Container argv: `--pids-limit`, `--memory`, `--ulimit cpu=…` appear when caps
  set and are absent when `None`.
- Container argv: `--user <uid>:<gid>` and `--cap-drop ALL` present (update the
  two existing tests that assert their absence / pin the full batch argv).
- `SeccompMode::Default` container argv adds `--security-opt seccomp=…`; `Off`
  does not.
- `none`/`bwrap` `prepare` argv is **unchanged** by `resources`/`seccomp` (the
  launcher is applied by the runner, not `prepare`) — a regression guard that
  purity is preserved.
- Launcher `LauncherArgs` parse round-trip (flags → struct).

**Unit — runner (`runner.rs`):**
- `restrictions_for` threads `resources`/`seccomp`/uid/gid.
- `build_command` prepends the launcher prefix for `none`/`bwrap` when a cap or
  seccomp is set, and omits it when all are unset/`Off` (no behaviour change for
  existing specs).

**Integration — real bwrap (Linux CI `sandbox-linux`, `MX_AGENT_REQUIRE_BWRAP`):**
- RLIMIT enforced: a command that forks past `max_processes` / allocates past
  `max_memory_bytes` fails rather than exhausting the host (skips gracefully off
  Linux, like existing real-bwrap tests).
- seccomp: with `seccomp = "default"`, an allowed-but-blocked syscall returns
  `EPERM`; a normal command still succeeds. Confirms the bwrap `--seccomp` fd
  format matches the serialized BPF.

**Integration — real container runtime (skips when none available):**
- `--user`/`--cap-drop ALL`: a write to a host-owned `writable_paths` mount
  *succeeds* (proving `--user` makes cap-drop viable), while a privileged
  operation is blocked.
- `--pids-limit`/`--memory` cap a fork/allocation.

**Daemon / behavioural:**
- `require_sandbox = true` + resolved `Backend::None` → request denied
  (`deny:sandbox_required`), audited; with `require_sandbox = false` it runs and
  emits the warning (assert via a tracing capture).
- The launcher runs identically on the loopback floor and the `--pty` path
  (resource caps apply to interactive sessions too).

**Docs:** `doc_drift.rs` updated/added assertions so the §13.5 backend list and
the "no seccomp/rlimit" claim cannot silently drift back.

## Documentation Updates

- **`docs/architecture.md`** — §13.3: document the four new policy keys with the
  example block. §13.5: rewrite the "no seccomp filtering and no rlimit/cgroup
  resource capping yet" paragraph and the container "deliberately does not
  `--cap-drop ALL` … deferred pending a `--user` mapping" paragraph to describe
  what now ships (seccomp opt-in, rlimit/cgroup caps, container `--user` +
  `--cap-drop ALL`). Note macOS limitations and the seccomp default-off rollout.
- **`docs/security-hardening.md`** — update the backend table rows for
  `bubblewrap` and `docker`/`podman`; rewrite "What the sandbox does *not* do" to
  reflect the new floor; add a short "Resource limits" + "Syscall filtering"
  subsection with the recommended caps.
- **`docs/alpha-release-checklist.md`** — update the "Sandbox is not a security
  boundary on its own" bullet (remove "no seccomp filtering and no rlimit/cgroup
  resource capping"; note the container cap-drop and the `require_sandbox` knob).
- **`docs/cli-reference.md`** — add the new policy keys to the policy table
  (~line 3160) and update the "Implemented backends vs. accepted values" note.
- **README status matrix** — refresh the "Sandbox backends" row (drop "still no
  seccomp/rlimit/cgroup caps"; note seccomp opt-in + resource caps + container
  cap-drop).
- **Wiki Security-and-Sandboxing page** — mirror the doc changes (wiki sync is
  automatic from `wiki/**`).

## Risks and Open Questions

1. **seccomp profile breadth (highest risk).** A default-deny allowlist that is
   too strict breaks arbitrary build/test commands; too loose adds little. The
   Docker default profile is a proven starting point but must be validated
   against mx-agent's real command corpus. Mitigated by shipping `seccomp` **off
   by default** with `ERRNO` (not `KILL`) action. *Decision needed:* exact
   allowlist source and whether v1 ships the profile at all or only the
   machinery.
2. **bwrap `--seccomp` byte format.** Need to confirm `seccompiler`'s serialized
   `BpfProgram` is byte-identical to what `bwrap --seccomp <fd>` expects, and
   that the fd survives (non-CLOEXEC) into bwrap. Backed by a real-bwrap
   acceptance test.
3. **`--user` under rootless podman.** `--user <hostuid>` means different things
   under docker (real uid) vs rootless podman (in-userns uid). Recommend gating
   `--user` to docker and using `--userns=keep-id` for podman; finalize against a
   real podman run on CI.
4. **`RLIMIT_NPROC` under `--unshare-user`.** Best-effort only on the bwrap/none
   path; exact pid capping needs the container `--pids-limit`. Documented, not a
   bug.
5. **`RLIMIT_AS` vs `RLIMIT_DATA`.** `RLIMIT_AS` (address space) can be
   surprisingly tight for runtimes that mmap large arenas (JVM, some allocators);
   `RLIMIT_DATA` is narrower. *Decision needed:* which to map `max_memory_bytes`
   to (recommend `RLIMIT_AS` with a generous default and clear docs). macOS
   honours `RLIMIT_AS` inconsistently — document.
6. **Launcher and `current_exe()`.** The runner must resolve its own binary to
   build the launcher prefix; `current_exe()` is already used in `lifecycle.rs`,
   but edge cases (binary moved/renamed at runtime) should fail with an
   actionable diagnostic like `preflight_backend` does, not a bare error.
7. **New dependency (`seccompiler`).** Adds a Linux-only dep to a security-
   critical crate; confirm MSRV 1.93 compatibility and that it passes the CI
   supply-chain checks (issue #315). If it does not fit, fall back to bwrap-only
   seccomp (drop seccomp on the `none` path) and document the gap.
8. **Default-off seccomp leaves `none` mostly unchanged.** With seccomp off, the
   `none` backend gains only rlimits (via the launcher) — still no namespace/fs
   isolation. The `require_sandbox` gate and the warning are the real mitigations
   for `none`; the issue's "seccomp on the none path" is delivered as opt-in
   machinery, not as a default-on behaviour. Confirm this satisfies the intent.

## Implementation Checklist

1. **Schema + plumbing (no behaviour yet).**
   - [ ] Add `ResourceLimits`, `SeccompMode` and the new `Restrictions` fields
         (`resources`, `seccomp`, `run_uid`, `run_gid`) to `mx-agent-sandbox`,
         all documented; keep `prepare` pure.
   - [ ] Add policy keys (`max_processes`, `max_memory_bytes`, `max_cpu_seconds`,
         `seccomp`, `require_sandbox`) to `ExecutionPolicy`/`AgentPolicy`; add the
         `Seccomp` enum; validate non-zero caps with dotted paths.
   - [ ] Carry `resources`/`seccomp` on `Allowance` (resolve in `allowance_for` +
         `execution_allowance`); add `DenyReason::SandboxRequired` if engine-side.
   - [ ] Add the same fields to `RunSpec`; thread through `restrictions_for`; set
         them at every `RunSpec` construction site (`exec.rs` ×2,
         `task_dispatch.rs`, `tool_exec.rs`, loopback).
   - [ ] Unit-test parse/validate/resolve + purity regression guard.

2. **(C) Container `--user` + `--cap-drop ALL`.**
   - [ ] Emit `--user <uid>:<gid>` (docker; `--userns=keep-id` for podman) and
         `--cap-drop ALL` in `ContainerSandbox::prepare`; resolve uid/gid via
         `nix::unistd` in the runner.
   - [ ] Update `container_includes_privilege_hardening` and the full-argv batch
         test; add a real-container write test.

3. **(D) `none` warning + `require_sandbox` gate.**
   - [ ] `warn!` on permitted `Backend::None`; deny fail-closed when
         `require_sandbox`; audit `deny:sandbox_required`.
   - [ ] Behavioural tests for both branches.

4. **(A) Resource limits.**
   - [ ] Container: `--pids-limit`/`--memory`/`--ulimit cpu` from `resources`
         (pure argv tests).
   - [ ] `launcher` module + `run_launcher` (safe `setrlimit` → `exec`); hidden
         `__sandbox-exec` CLI subcommand.
   - [ ] Runner/pty: prepend the launcher prefix for `none`/`bwrap` when a cap
         (or seccomp) is set; preserve env scrubbing.
   - [ ] Real-bwrap rlimit enforcement test (require-gated on CI).

5. **(B) seccomp.**
   - [ ] Add target-gated `seccompiler`; build the curated default profile
         (`ERRNO(EPERM)` default action) on Linux.
   - [ ] `none` path: `apply_filter` in the launcher; macOS no-op + warning.
   - [ ] `bwrap` path: serialize BPF → non-CLOEXEC fd → `--seccomp <fd>`.
   - [ ] `container` path: write JSON profile → `--security-opt seccomp=`.
   - [ ] Real-bwrap/container seccomp acceptance tests (blocked syscall → EPERM,
         normal command succeeds).

6. **Docs + CI.**
   - [ ] Update architecture §13.3/§13.5, security-hardening, alpha-checklist,
         cli-reference, README status row, wiki page.
   - [ ] Update `doc_drift.rs` pinned strings.
   - [ ] Extend `sandbox-linux` CI to exercise rlimit/seccomp/cap-drop
         un-skipped; keep container tests skipping gracefully when no runtime.
   - [ ] `cargo fmt --check`, `cargo clippy --all-targets --all-features -D
         warnings`, `cargo test --all` green; live Tuwunel suite unaffected.
```
