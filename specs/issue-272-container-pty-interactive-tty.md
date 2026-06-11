# Container sandbox backend + PTY: allocate an interactive TTY (`-i -t`)

> Implements GitHub issue #272 (`type:bug`, `area:sandbox`, `priority:p2`).
> Related: #248 (sandbox paths/network wiring through `--pty`), #254 (PTY TTY
> setup), #268 (live-exec PTY output cap).

## Problem Statement

The interactive `exec --pty` path routes every sandbox backend through
`Sandbox::prepare` in `PtySession::spawn`
(`crates/mx-agent-daemon/src/pty.rs:167`), including `Backend::Container`. But
`ContainerSandbox::prepare` builds `<runtime> run --rm --read-only … <image>
<argv>` with **no `-i`/`-t` flags** (`crates/mx-agent-sandbox/src/lib.rs:356-410`).

Without interactive/TTY allocation, `docker run` / `podman run` does **not**
give the command a controlling terminal *inside* the container, even though the
host correctly wires the PTY slave fds as the child's stdin/stdout/stderr. The
container runtime reads/writes those host fds but the in-container process is
handed pipes, not a terminal. The result is a degraded, non-interactive session
for `--pty` + container: `isatty` is false inside the container, so job control,
line editing, and full-screen TUIs (`vim`, `top`, a login shell) misbehave or
hang.

The combination is **untested**: the only PTY-through-sandbox test
(`pty.rs:397-451`, `pty_command_runs_inside_selected_sandbox_backend`) hardcodes
`Backend::Bubblewrap`, and all container integration tests are non-PTY — so the
breakage is invisible to CI. `bubblewrap` works under `--pty` without any extra
flags because `bwrap` simply inherits the parent's stdio (the PTY slave) and the
child therefore already has a real terminal; the container runtime is the only
backend that needs an explicit signal to allocate an in-container TTY.

This is a **functional/usability bug, not a security bypass**: the argv still
applies `--read-only`, `--network none`, the volume mounts, and the sanitized
`--env` allowlist, so isolation holds and the session fails safe — only
interactivity is lost.

## Goals

- Make a container-backed `exec --pty` session **genuinely interactive**:
  `isatty` is true inside the container, line editing and full-screen TUIs work,
  matching the behavior already delivered for the `none` and `bubblewrap`
  backends.
- Thread an explicit **interactive** signal from the PTY entry point
  (`PtySession::spawn`) to the sandbox layer so `ContainerSandbox::prepare`
  emits `-i -t` (interactive + TTY) **only** when the command runs under a PTY.
- Keep the **non-interactive** container argv byte-for-byte unchanged (no `-i`,
  no `-t`) so batch `exec`, named-`call` tool execution, and auto-executed task
  DAGs are unaffected.
- Keep the sandbox `prepare` implementations **pure** (argv computation only) so
  the wrapping rule is unit-testable without a real runtime.
- Add unit coverage asserting the interactive vs non-interactive container argv,
  and a behavioral test exercising container + PTY that skips gracefully when no
  runtime is available.
- Document the chosen behavior alongside the architecture §13.5 sandbox notes and
  the sandbox-crate module docs.

## Non-Goals

- No change to the `none` or `bubblewrap` backends: they already behave
  correctly under `--pty` and must ignore the new interactive signal.
- No `-i`/stdin handling for the **non-interactive** container path. Batch
  `exec` stdin forwarding (`RunSpec::stdin`) is out of scope; the interactive
  signal is driven purely by the PTY path.
- No new policy keys, CLI flags, or protocol/event-schema changes. The `--pty`
  flag and the exec/PTY IPC surface already exist.
- No `--privileged`, `--init`, `--cap-add`, UID/GID remap, seccomp, or any flag
  that would change the isolation posture. Only `-i -t` (TTY allocation) is
  added.
- No attempt to support Windows; PTYs and this module are Unix-only.

## Relevant Repository Context

- **Workspace**: Rust Cargo workspace, MSRV 1.74, `unsafe_code = "forbid"`
  workspace-wide, `missing_docs = "warn"` treated as an error in CI (`-D
  warnings`). Unix only (Linux + macOS).
- **`mx-agent-sandbox`** (`crates/mx-agent-sandbox/src/lib.rs`) defines the
  `Sandbox` trait, the centralized `Restrictions` control set, and the three
  backends:
  - `Restrictions` (`lib.rs:113-139`) is the single vocabulary every backend
    consumes: `cwd`, `env`, `timeout`, `max_output_bytes`, `network`,
    `read_only_paths`, `writable_paths`. It derives
    `Debug, Clone, Default, PartialEq, Eq`.
  - `Sandbox::prepare(argv, restrictions) -> Prepared` (`lib.rs:163-168`) is
    pure; `Prepared` carries `backend`, `argv`, `restrictions`.
  - `NoneSandbox` returns the argv unchanged (`lib.rs:180-192`).
  - `BubblewrapSandbox::prepare` (`lib.rs:224-273`) prepends `bwrap …`; it
    inherits the parent's stdio so a PTY slave already makes the child's stdin a
    TTY — no extra flag needed.
  - `ContainerSandbox::prepare` (`lib.rs:351-410`) builds `<runtime> run --rm
    --read-only [--network none] [--env K=V…] [--volume …] --workdir <cwd>
    <image> <argv>`. The flag literal is at `lib.rs:357-365`. This is the
    function to change.
  - `sandbox_for(backend)` (`lib.rs:417-423`) maps a `Backend` to a boxed
    backend; `ContainerSandbox::default()` uses Docker + `debian:stable-slim`.
- **`mx-agent-daemon`**:
  - `runner.rs` owns `RunSpec` (`runner.rs:150-205`), `RunError`
    (`runner.rs:252-281`), `sanitize_env` (`runner.rs:119-136`), and the pure
    `restrictions_for(spec, env) -> Restrictions` (`runner.rs:296-307`) used by
    **both** the non-interactive runner (`build_command`, `runner.rs:336`) and
    the PTY path. `RunSpec` carries `sandbox`, `network`, `read_only_paths`,
    `writable_paths` but **no `interactive` field** — `PtySession::spawn` is
    itself the interactive entry point.
  - `pty.rs` owns `PtySession::spawn` (`pty.rs:129-191`): it allocates the PTY
    via safe `rustix` wrappers, calls `restrictions_for` + `sandbox_for(…)
    .prepare(…)` (`pty.rs:165-167`), and wires the slave fds as the child's
    stdin/stdout/stderr (`pty.rs:178-180`). Every interactive caller funnels
    through this one function:
    - `exec.rs:1261` (`run_controlled_pty_exec`, live remote `--pty`),
    - `pty_ipc.rs:207` (local IPC loopback PTY),
    - the loopback integration test (`tests/pty_ipc_loopback.rs:36`).
    Because all PTY callers go through `PtySession::spawn`, setting the
    interactive signal there fixes every path with no caller changes.
  - The existing sandbox-through-PTY test
    `pty_command_runs_inside_selected_sandbox_backend` (`pty.rs:397-451`) only
    exercises `Backend::Bubblewrap` and probes `/sys/class/net` (Linux-only).
- **Architecture doc**: §13.5 "Sandboxing" (`docs/architecture.md:1812-1847`)
  lists the container backend ("Docker or Podman", "read-only root filesystem",
  "network disabled by default") and the minimum/stronger controls. The README
  status table (`README.md:51`) notes container backends are policy-selectable
  and that interactive `--pty` "has baseline controls plus a per-invocation
  output byte cap".
- **Conventions**: sandbox `prepare` methods are pure and unit-tested by
  asserting argv slices (`container_flags` / `container_command` helpers at
  `lib.rs:726-739`). Integration tests probe a real runtime via a
  `usable_container()` helper (`lib.rs:868-883`) and skip gracefully when none is
  available. Daemon PTY tests drain the master on a thread, then `wait`
  (`pty.rs:253-265`).

## Proposed Implementation

**Chosen option: Option A — make the container + PTY session interactive.** The
daemon already wires the PTY slave fds correctly; the only missing piece is the
in-container TTY allocation. Making it work matches the capability already
delivered for `none`/`bubblewrap` and avoids regressing a usable path. Option B
(reject/degrade `Backend::Container` under `--pty`) is documented under *Risks
and Open Questions* as the fallback if a maintainer prefers it.

### 1. Add an `interactive` control to `Restrictions` (`mx-agent-sandbox`)

Add a documented boolean field to `Restrictions`:

```rust
/// Whether the command runs under an interactive pseudo-terminal (an
/// `exec --pty` session). Only a backend that launches the command through a
/// separate runtime needs this: the container backend allocates an
/// in-container TTY (`-i -t`) when set, so `isatty` is true inside the
/// container and full-screen/interactive programs work. The `none` and
/// `bubblewrap` backends inherit the parent's PTY slave directly and ignore
/// this flag. Defaults to `false` (the non-interactive batch path).
pub interactive: bool,
```

- It derives `Default` to `false`, so every `..Restrictions::default()` call
  site and the existing `assert_eq!(prepared.restrictions, …)` tests keep
  compiling and passing unchanged.
- Place the field after `writable_paths` to keep the struct grouped
  (filesystem controls together, then the interactive flag) — order is
  immaterial to `Default`/`PartialEq`.

### 2. Emit `-i -t` in `ContainerSandbox::prepare` when interactive

In the `run` flag vec (`lib.rs:357-365`), after the existing `--rm` /
`--read-only` flags (and independent of the network branch), add:

```rust
// Interactive PTY session: allocate a TTY inside the container so the command
// gets a controlling terminal (`isatty` true), enabling job control, line
// editing, and full-screen TUIs. The host already wires the PTY slave fds as
// this process's stdin/stdout/stderr; `-i` keeps stdin attached and `-t`
// allocates the in-container pty (architecture §13.5). Omitted for
// non-interactive batch runs so their argv is unchanged.
if restrictions.interactive {
    wrapped.push("-i".to_string());
    wrapped.push("-t".to_string());
}
```

- Use the short forms `-i` / `-t` as two separate argv tokens (not the combined
  `-it`) for clarity; both Docker and Podman accept them. The test should accept
  either the short or the long (`--interactive` / `--tty`) spelling so a future
  refactor is not brittle.
- Placement is before the image (anywhere in the `run` flag region works); keep
  it adjacent to the other `run` flags for readability.
- Leave the other backends untouched: `NoneSandbox` and `BubblewrapSandbox`
  ignore `restrictions.interactive` entirely.

### 3. Set the interactive signal at the PTY entry point (`mx-agent-daemon`)

`restrictions_for` (`runner.rs:296-307`) is shared by the non-interactive runner
and the PTY path, and the interactive property is a function of the *execution
path*, not of policy. So keep `restrictions_for` producing
`interactive: false` and flip it in `PtySession::spawn` only:

- In `restrictions_for`, add `interactive: false` to the struct literal (the
  literal is exhaustive — no `..default()` — so the new field must be named).
- In `PtySession::spawn` (`pty.rs:165-167`), change:

  ```rust
  let restrictions = restrictions_for(spec, env);
  ```

  to:

  ```rust
  let mut restrictions = restrictions_for(spec, env);
  // This is the interactive `--pty` path: signal the sandbox layer so a
  // backend that launches through a separate runtime (the container backend)
  // allocates an in-container TTY. `none`/`bubblewrap` ignore it.
  restrictions.interactive = true;
  ```

This fixes **all** PTY callers (`exec.rs`, `pty_ipc.rs`, the loopback test) with
no changes to them, because every interactive session funnels through
`PtySession::spawn`. `build_command` in the non-interactive runner keeps
`interactive: false` and its container argv is unchanged.

> Alternative threading (mention only): add an `interactive: bool` parameter to
> `restrictions_for` and pass `true`/`false` at the two call sites. This is
> marginally more explicit but churns the five `restrictions_for(&spec,
> BTreeMap::new())` unit-test call sites in `runner.rs`. The mutate-in-`spawn`
> approach above is preferred for minimal blast radius; pick one and be
> consistent.

### Why this preserves isolation

`-i -t` only governs stdin attachment and TTY allocation. The same argv still
carries `--read-only`, `--network none` (under `Network::Deny`), the
`--volume …` binds, `--workdir`, and the explicit `--env K=V` allowlist
(secret-scrubbed by the caller, §13.4). No filesystem, network, capability, or
privilege boundary is widened. The daemon-side merged-PTY output byte cap (issue
#268) is enforced above the sandbox layer and is unaffected.

## Affected Files / Crates / Modules

| File | Change |
|---|---|
| `crates/mx-agent-sandbox/src/lib.rs` | Add `Restrictions::interactive` (documented); emit `-i -t` in `ContainerSandbox::prepare` when set; update the `ContainerSandbox` doc comment; add pure unit tests. |
| `crates/mx-agent-daemon/src/runner.rs` | Add `interactive: false` to the `restrictions_for` struct literal. (No behavior change to `build_command`.) |
| `crates/mx-agent-daemon/src/pty.rs` | Set `restrictions.interactive = true` in `PtySession::spawn`; add a container + PTY behavioral test that skips when no runtime is available; update the `spawn` doc comment to note interactive TTY allocation for containers. |
| `docs/architecture.md` | Add a §13.5 note that a container-backed `--pty` session allocates an interactive in-container TTY (`-i -t`); batch runs do not. |
| `README.md` | Update the sandbox-backends status row to note interactive container `--pty` allocates an in-container TTY. |

Files to **read** for context (not necessarily modify): `crates/mx-agent-daemon/src/exec.rs`
(`run_controlled_pty_exec`), `crates/mx-agent-daemon/src/pty_ipc.rs`,
`crates/mx-agent-daemon/tests/pty_ipc_loopback.rs`.

## CLI / API Changes

- **New public field**: `mx_agent_sandbox::Restrictions::interactive: bool`
  (additive; defaults to `false`). It must carry a doc comment (`missing_docs`
  is enforced). This is the only public-API surface change.
- **No command-line changes**: the `--pty` flag and the exec/PTY command surface
  already exist; behavior of `exec --pty` with the container backend changes from
  degraded to interactive, but no flag is added or renamed.
- **No IPC/JSON-RPC method or parameter changes.**

## Data Model / Protocol Changes

None. `Restrictions::interactive` is an internal control consumed inside the
daemon/sandbox process boundary; it is **not** serialized into any Matrix event,
IPC frame, policy file, or audit record. No event schema, persistence, policy
vocabulary, or canonical-JSON change.

## Security Considerations

- **Not a privilege change.** `-i -t` allocates a TTY and keeps stdin attached;
  it grants no filesystem, network, or capability access. `--read-only`,
  `--network none`, the volume binds, `--workdir`, and the `--env` allowlist are
  all still emitted, so the isolation posture is identical to the non-interactive
  container path. The fix removes a usability gap, not a control.
- **Fail-safe preserved.** `Network` still defaults to `Deny`; `interactive`
  defaults to `false`. An unset/old code path that forgets to set `interactive`
  degrades to non-interactive (the current behavior), never to a less-isolated
  one.
- **Secret handling unchanged.** The forwarded env is still the sanitized
  allowlist (`sanitize_env`, §13.4); `TERM` is already in
  `DEFAULT_ALLOWED_VARS`, so an interactive program inside the container gets a
  sane terminal type without leaking anything. No secret reaches the argv or the
  logs; existing `Secret`/redaction patterns are untouched.
- **Daemon/CLI separation intact.** The change lives entirely inside the daemon
  and sandbox crate. The stateless CLI is unchanged; the coding agent never sees
  Matrix tokens or device keys. Room membership still does not imply execution
  rights; signing/trust/policy/approval gating happens in `exec.rs` *before*
  `PtySession::spawn` and is not touched.
- **Output cap unchanged.** The merged-PTY byte cap (#268) is enforced
  daemon-side, above the runtime, and still bounds a runaway interactive session.
- **Unix-only.** No Windows paths or assumptions; the module is already
  `cfg`-free Unix. No `unsafe`; the change is pure argv/string construction plus
  one boolean assignment.
- **Note on `-t` and host fd.** `docker run -t` requires the attached stdin fd to
  be a TTY; on the PTY path the slave *is* a TTY, so this is always satisfied.
  The flag is never set on the non-interactive path, where stdin is `/dev/null`
  or a pipe.

## Testing Plan

All new tests must keep CI green where Docker/Podman is absent (skip gracefully)
and where `bwrap` is absent (already handled).

**Pure unit tests (`mx-agent-sandbox`, no runtime required):**

1. `container_interactive_adds_tty_flags`: prepare with `Restrictions {
   interactive: true, .. }` and assert the `run` flags (before the image, via
   `container_flags`) contain both an interactive flag (`-i` or `--interactive`)
   and a TTY flag (`-t` or `--tty`), and that they precede the image.
2. `container_non_interactive_omits_tty_flags`: prepare with the default
   `Restrictions` (`interactive: false`) and assert the flags contain **neither**
   `-i`/`--interactive` nor `-t`/`--tty`, and that the rest of the argv is
   unchanged (still `docker run --rm --read-only …`). Guards against accidental
   regression of the batch path.
3. `bubblewrap_ignores_interactive_flag` (and/or extend a `none` test): prepare
   the bubblewrap backend with `interactive: true` vs `false` and assert the argv
   is identical — only the container backend reacts to the flag.

**Behavioral test (`mx-agent-daemon`, `pty.rs`):**

4. `pty_container_session_is_interactive`, mirroring
   `pty_command_runs_inside_selected_sandbox_backend` but with
   `Backend::Container`:
   - Probe for a usable runtime/image (reuse the `usable_container()`-style
     helper from the sandbox crate's tests, or a local equivalent: try
     `docker`/`podman run --rm <image> true` with `busybox`/`alpine`/the default
     image). If none works, `eprintln!("skipping …")` and return — never fail.
   - Build a `RunSpec` with `sandbox = Backend::Container`, `cwd = "/"` (exists on
     host and in the image, so no writable mount is needed), and run `sh -c 'if
     test -t 0; then echo PTY-CONTAINER-TTY; else echo PTY-CONTAINER-NOTTY; fi'`
     (equivalently `tty`).
   - Spawn via `PtySession::spawn`, drain with the existing `run_and_collect`
     helper, assert the output contains `PTY-CONTAINER-TTY` and not
     `PTY-CONTAINER-NOTTY`. Without the fix this asserts the bug (NOTTY); with it,
     TTY.
   - Note: the default `ContainerSandbox` image is `debian:stable-slim`; the test
     should construct the spec so the probed image is used (e.g. by selecting an
     image the probe confirmed runnable). If the daemon path can only use the
     default backend image, prefer the probe that confirms the default image runs,
     or document that the behavioral test uses whatever `sandbox_for(Container)`
     resolves.

**Regression guard / existing tests:**

5. Confirm the existing container unit tests
   (`container_wraps_command_in_configured_image`,
   `container_root_filesystem_is_read_only`, `container_*`) still pass unchanged —
   they assert the non-interactive argv, which must stay byte-for-byte identical.
6. Confirm `restrictions_for_*` runner unit tests still pass (only an added
   `interactive: false` literal field; no behavioral change).

**Checks:** `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D
warnings`, `cargo test --all`, `cargo build --all`.

## Documentation Updates

- **`docs/architecture.md` §13.5**: add a sentence noting that an interactive
  `exec --pty` session under the container backend allocates an in-container TTY
  (`-i -t`) so `isatty` is true and full-screen programs work, while batch
  `exec` keeps the non-interactive argv; isolation flags are identical in both
  cases.
- **`crates/mx-agent-sandbox/src/lib.rs`**: update the `ContainerSandbox` /
  `prepare` doc comment (and the crate-level module doc if appropriate) to
  describe the `interactive` → `-i -t` rule; document the new
  `Restrictions::interactive` field (required by `missing_docs`).
- **`crates/mx-agent-daemon/src/pty.rs`**: update the `PtySession::spawn` doc
  comment to state that the container backend is launched interactively under a
  PTY.
- **`README.md`**: tweak the sandbox-backends status row to mention that
  interactive container `--pty` now allocates an in-container TTY (avoid
  over-claiming — keep the existing "no seccomp/rlimit/UID-GID remap" caveat).
- No wiki page is the source of truth for this detail; if the
  Security-and-Sandboxing wiki page enumerates container flags, mirror the note
  there.

## Risks and Open Questions

- **Option A vs Option B (decision to confirm).** This spec recommends Option A
  (make it interactive). If a maintainer instead prefers Option B (reject or
  degrade container + PTY), the implementation becomes: in `PtySession::spawn`,
  detect `spec.sandbox == Backend::Container` and either return a new
  `RunError` variant (e.g. `InteractiveUnsupported(Backend)` with message
  "container backend does not support interactive `--pty`") **or** log a warning
  and proceed degraded; then the behavioral test asserts the rejection/degrade
  instead of the TTY, and the docs state the limitation. Adding a `RunError`
  variant is a small public-API change in the daemon crate. **Recommendation:
  Option A.**
- **Short vs long flag spelling.** Recommend `-i -t`; tests should accept either
  spelling to stay robust. Confirm no downstream tooling greps for an exact
  spelling.
- **Double cooked/raw handling.** With `-t`, the container runtime sets the host
  side (our PTY slave) to raw mode and proxies to an in-container pty, producing
  a nested-PTY arrangement. The requester's terminal already manages cooked/raw
  at its end; this is the same nesting users see with `ssh -t` + `docker run -t`
  and is expected. Worth a one-line note but not a blocker.
- **`--init` / PID-1 signal handling (out of scope).** Without `--init`, the
  command runs as the container's PID 1, which can change SIGTERM/zombie-reaping
  semantics on timeout/cancel. The host kill-process-group still signals the
  runtime client, which forwards termination to the container. Adding `--init`
  is a possible future hardening but is intentionally out of scope here; flag if
  cancel/timeout behavior for interactive containers needs follow-up.
- **CI coverage gap.** The behavioral container + PTY test is skip-on-absence, so
  on runners without Docker/Podman it provides no signal — exactly like the
  existing container integration tests. The pure unit tests (which require no
  runtime) are the load-bearing regression guard and run everywhere.
- **Image must contain a shell/TTY-aware program.** The behavioral test relies on
  `sh`/`test`/`tty` existing in the probed image (busybox/alpine/debian all
  qualify); if only an image without a shell is available the test should skip.

## Implementation Checklist

1. `mx-agent-sandbox/src/lib.rs`: add the documented `pub interactive: bool`
   field to `Restrictions` (after `writable_paths`).
2. `mx-agent-sandbox/src/lib.rs`: in `ContainerSandbox::prepare`, push `-i` and
   `-t` into the `run` flags when `restrictions.interactive` is true; update the
   `ContainerSandbox`/`prepare` doc comment to describe the rule.
3. `mx-agent-sandbox/src/lib.rs`: add unit tests
   `container_interactive_adds_tty_flags`,
   `container_non_interactive_omits_tty_flags`, and
   `bubblewrap_ignores_interactive_flag`.
4. `mx-agent-daemon/src/runner.rs`: add `interactive: false` to the
   `restrictions_for` struct literal (keeps the non-interactive runner unchanged).
5. `mx-agent-daemon/src/pty.rs`: change `let restrictions = …` to `let mut
   restrictions = …` and set `restrictions.interactive = true` before `prepare`;
   update the `PtySession::spawn` doc comment.
6. `mx-agent-daemon/src/pty.rs`: add the `pty_container_session_is_interactive`
   behavioral test with a graceful skip when no runtime/image is usable.
7. `docs/architecture.md` §13.5: add the interactive-container-PTY note.
8. `README.md`: update the sandbox-backends status row (avoid over-claiming).
9. Run `cargo fmt`, `cargo clippy --all-targets --all-features -- -D warnings`,
   `cargo test --all`, `cargo build --all`; confirm existing container and
   `restrictions_for_*` tests still pass.
