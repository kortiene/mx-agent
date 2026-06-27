# Close the `..`/non-canonical traversal gap in the `cwd_allowed` policy check (issue #374)

## Problem Statement

The engine's working-directory allowlist (`agent.allow_cwd`) is matched with
`Path::starts_with` against the **raw, non-canonicalized** requested cwd.
`Path::starts_with` is component-wise, so a requested cwd that begins with an
allowed prefix but then contains `..` (parent-dir) components satisfies the
prefix check even though the OS later resolves it to a directory **outside** the
allowlist.

Concretely, with `allow_cwd = ["/srv/project"]`, a requested
`cwd = "/srv/project/../../etc"` passes `cwd_allowed()` because its first two
components (`srv`, `project`) match the allowed prefix — yet when the command is
spawned with `Command::current_dir(...)` the kernel resolves `..` and runs in
`/etc`.

For the isolating backends (`bubblewrap`, `container`) the bind-mounts constrain
the real filesystem, so a textually-escaping cwd cannot reach anything that was
not mounted in. For `Backend::None` (no sandbox configured / unset) there is no
such containment: the same raw string is handed to `Command::current_dir`, so
the allowlist is bypassable. Because `firejail`/`chroot` are rejected at policy
load (`file.rs` `validate_sandbox`, issue #310), **`Backend::None` is the only
reachable affected backend** — but it is the default whenever no sandbox is
configured.

The gap is reachable only by a requester that has **already** cleared the
privileged-exec gates (trusted room, valid Ed25519 signature, locally-trusted
key, allowlisted command basename). It controls only the *working directory* of
an already-allowlisted program, so it is a privilege-tightening defect (p2), not
an unauthenticated RCE. Operators who set `execution.require_sandbox` are
unaffected (the `none` backend is denied outright). Still, on `Backend::None`
it defeats the purpose of `allow_cwd`: a permitted `npm`/`git`/`cargo` invocation
can read/write relative paths against `/etc`, `$HOME`, or another project,
pick up config/credentials from an unintended cwd, or write artifacts outside
the confined tree.

This spec closes the `..`/non-canonical gap in `cwd_allowed` as
defense-in-depth for the `none` backend. It is a local policy-evaluation
tightening only — no protocol or wire change.

## Goals

- A request with `cwd = "/srv/project/../../etc"` against
  `allow_cwd = ["/srv/project"]` evaluates to
  `Outcome::Deny(DenyReason::CwdNotAllowed { .. })`.
- A request with a clean in-bounds cwd (the exact allowed dir, e.g.
  `/srv/project`, or a clean subdirectory, e.g. `/srv/project/sub`) **still
  allows** — no regression to the existing accepted cases.
- Any requested cwd containing a `..` (`Component::ParentDir`) component is
  denied, regardless of where in the path it appears (leading-after-prefix,
  mixed, or trailing).
- Any requested cwd containing a `.` (`Component::CurDir`) component is denied
  (over-rejection is acceptable for a deny-by-default gate; a well-formed caller
  sends a clean absolute path).
- The `cwd_allowed` check remains a **pure function** — no filesystem access, no
  `canonicalize`, deterministic — preserving the engine's documented invariant
  that it "never touches the filesystem, network, or spawns processes"
  (`engine.rs` module doc, architecture §13.3).
- New unit tests assert the `..`-escape and a mixed/leading-`..` case are denied,
  and that clean in-bounds paths still allow.

## Non-Goals

- **No canonicalization in the engine.** `Path::canonicalize` would touch the
  filesystem (resolving symlinks, requiring the path to exist), violating the
  engine's purity invariant, introducing a TOCTOU window between policy
  evaluation and spawn, and making the deny/allow decision depend on filesystem
  state. The lexical reject is preferred per the issue and per the engine's
  design contract.
- **No symlink-resolution guarantee.** This fix closes the *textual* `..`/`.`
  traversal gap only. A pre-existing symlink *inside* an allowed directory that
  points outside it (e.g. `/srv/project/link -> /etc`) is a strictly narrower,
  separate concern; it is not introduced or worsened here, is contained by the
  isolating backends, and is out of scope. Do not claim the fix closes all cwd
  escapes — only the `..`/`.` lexical one.
- **No change to the loopback / `execution_allowance()` path.** That path does
  not consult `cwd_allowed` at all (`engine.rs` `execution_allowance` builds
  only the execution-scope floor with no per-agent gate); it is explicitly out
  of scope per the issue.
- **No change to the runner / spawn layer** (`runner.rs` `build_command`,
  `daemon` `exec.rs` `RunSpec.cwd`). The fix lives entirely in the policy
  evaluation; no normalization is added between the policy check and the spawn.
- **No protocol, IPC, wire, or CLI surface change.**
- **No sibling-prefix work.** `Path::starts_with` is already component-wise, so
  `allow_cwd = ["/srv/project"]` does **not** match `/srv/project-evil`; there is
  no sibling-prefix bug to fix.
- **No change to `Backend::None` reachability or the sandbox-floor warn/deny
  gate** (issue #349); those already exist and are unchanged.

## Relevant Repository Context

- **Workspace** (Rust Cargo workspace, Unix-only, MSRV 1.93, `unsafe_code =
  "forbid"`). Crates relevant here:
  - `mx-agent-policy` — the local authorization policy engine. Owns the fix.
  - `mx-agent-daemon` — builds the `ExecContext` from the raw requester-supplied
    `ExecRequest.cwd` and later spawns with that same string. Read-only context
    for this change; no edits expected.
- **`crates/mx-agent-policy/src/engine.rs`**
  - Module doc (`:1-11`): the engine is "deny-by-default and purely a pure
    function over its inputs: it never touches the filesystem, network, or spawns
    processes." This is the contract the fix must preserve — it rules out
    `canonicalize`.
  - `evaluate_exec()` (`:204-249`): the raw-exec authorization path. The cwd gate
    is at `:237-241` — `if !cwd_allowed(ctx.cwd, &agent.allow_cwd) { return
    Outcome::Deny(DenyReason::CwdNotAllowed { cwd: ctx.cwd.to_string() }) }`.
  - `cwd_allowed()` (`:353-363`): the helper to change. Currently:
    ```rust
    fn cwd_allowed(cwd: &str, allow_cwd: &[std::path::PathBuf]) -> bool {
        let cwd_path = Path::new(cwd);
        if !cwd_path.is_absolute() {
            return false;
        }
        allow_cwd
            .iter()
            .any(|allowed| cwd_path.starts_with(allowed))
    }
    ```
  - `execution_allowance()` (`:282-297`): the loopback floor — does **not**
    consult `cwd_allowed`. Out of scope.
  - `DenyReason::CwdNotAllowed { cwd: String }` (`:135-139`) and its `Display`
    (`:163-165`): the existing deny reason carries the rejected cwd verbatim;
    reused unchanged.
  - Test module (`#[cfg(test)] mod tests`, from `:~390`): helpers `policy()`
    (`:401-422`, fixture has `allow_cwd = ["/home/me/code/project"]`),
    `exec(command, cwd)` (`:424-431`), `argv(parts)` (`:433-435`). Existing
    relevant tests: `exec_allows_command_in_subdirectory_of_allowed_cwd`
    (`:521-527`), `exec_denied_cwd_not_allowlisted` (`:584-595`),
    `exec_denied_relative_cwd` (`:597-606`). New tests mirror these.
- **`crates/mx-agent-policy/src/file.rs`**
  - `validate_paths()` (`:551-561`): enforces `is_absolute` on `allow_cwd`
    *entries* only; never validates the *requested* cwd. Optional secondary
    hardening can extend this to also reject `..`/`.` in allowlist entries at
    load time.
  - `validate_sandbox()` (`:459-470`): rejects `firejail`/`chroot` at load
    (issue #310) — the reason `Backend::None` is the only reachable affected
    backend.
  - `relative_cwd_reports_precise_path` test (`:847-862`): the pattern to mirror
    if adding a load-time allowlist-entry test.
- **`crates/mx-agent-daemon/src/exec.rs`** (context only, no edits)
  - `ExecRequest.cwd` field (`~:481`): the raw requester-supplied string.
  - Authorization gate (`~:663-668`): builds `ExecContext { cwd: &request.cwd, .. }`.
  - `RunSpec.cwd = PathBuf::from(&request.cwd)` at `~:1777` (batch) and `~:2049`
    (pty): the *same* string checked by policy is used verbatim to spawn — no
    normalization in between, which is why the lexical check at the policy layer
    is the right place to close the gap.
  - `check_sandbox_floor` (`~:1605-1633`, issue #349): on `Backend::None` emits a
    prominent `warn!` and, when `execution.require_sandbox` is set, denies
    outright. Unchanged.
- **`docs/architecture.md` §13.3 Execution Policy** (`:2036-2086`): documents the
  `allow_cwd` allowlist and the deny-by-default posture; the place to add a
  one-line note that the requested cwd must be a clean absolute path.
- **Conventions:** deny-by-default; precise dotted-path errors at policy load;
  pure engine; tests live in the same file's `#[cfg(test)] mod tests`; document
  public items (`missing_docs` is a CI-enforced warning). `std::path::Component`
  / `Path::components()` are stable since Rust 1.0 — comfortably within MSRV 1.93,
  no toolchain concern.

## Proposed Implementation

**Primary change (required) — lexical reject in `cwd_allowed`,
`crates/mx-agent-policy/src/engine.rs`:**

After the existing `is_absolute()` guard and before the `starts_with` match,
reject any requested cwd that contains a `Component::ParentDir` (`..`) or
`Component::CurDir` (`.`) component. A well-formed absolute Unix path that is
genuinely inside an allowed directory contains only `RootDir` + `Normal`
components; any `ParentDir`/`CurDir` component means the textual path is either
escaping (`..`) or non-canonical (`.`), so it is denied fail-closed.

```rust
/// Whether `cwd` is within one of the allowed directories.
///
/// Deny-by-default: an empty allowlist permits nothing. The requested cwd must
/// be an **absolute, canonical** path — any `..` (`ParentDir`) or `.` (`CurDir`)
/// component is rejected before the prefix match, because `Path::starts_with`
/// is component-wise and would otherwise accept a path like
/// `/srv/project/../../etc` that the OS later resolves *outside* the allowlist
/// when the command is spawned with `current_dir(...)`. This is a pure,
/// filesystem-free check (no `canonicalize`): it is defense-in-depth for the
/// `none` sandbox backend, where nothing else constrains the real cwd (issue
/// #374). Note: it closes the textual traversal gap only; it does not resolve
/// symlinks.
fn cwd_allowed(cwd: &str, allow_cwd: &[std::path::PathBuf]) -> bool {
    use std::path::Component;

    let cwd_path = Path::new(cwd);
    // Only absolute working directories can be safely matched against the
    // absolute allowlist entries.
    if !cwd_path.is_absolute() {
        return false;
    }
    // Reject non-canonical components: `..` can escape the allowlisted prefix
    // under the component-wise `starts_with`, and `.` indicates a non-canonical
    // path. A genuinely in-bounds absolute cwd has only RootDir + Normal
    // components.
    if cwd_path
        .components()
        .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return false;
    }
    allow_cwd
        .iter()
        .any(|allowed| cwd_path.starts_with(allowed))
}
```

Notes:
- The `use std::path::Component;` can live at function scope (as above) or be
  added to the existing top-of-file `use std::path::{Path, PathBuf};`
  (`engine.rs:13`) as `use std::path::{Component, Path, PathBuf};`. Either is
  fine; prefer the module-level import for consistency with the existing style.
- Behavior on the documented cases:
  - `/srv/project/../../etc` → has `ParentDir` → denied. ✅
  - `/srv/project/..` → has `ParentDir` → denied (escapes to `/srv`). ✅
  - `/srv/./project` or `/srv/project/./sub` → has `CurDir` → denied
    (over-rejection of a benign-but-non-canonical path; acceptable, fail-closed).
  - `/srv/project` and `/srv/project/sub` → only Normal components → fall through
    to `starts_with` → allowed if matching an entry. ✅
  - `relative/dir` → not absolute → denied (unchanged). ✅
- The deny reason at the call site (`engine.rs:237-241`) is unchanged: a rejected
  cwd still surfaces as `DenyReason::CwdNotAllowed { cwd }`, carrying the
  requester-supplied string verbatim (consistent with the existing
  not-allowlisted and relative-cwd denials, which share this reason).

**Optional secondary hardening (recommended, low value) — reject `..`/`.` in
`allow_cwd` entries at load, `crates/mx-agent-policy/src/file.rs`:**

Extend `validate_paths` (`:551-561`) so a configured `allow_cwd` entry that is
itself non-canonical fails policy load with a precise dotted-path error,
guaranteeing the allowlist prefix the engine compares against is canonical:

```rust
fn validate_paths(prefix: &str, paths: &[PathBuf]) -> Result<(), PolicyError> {
    for (idx, path) in paths.iter().enumerate() {
        if !path.is_absolute() {
            return Err(PolicyError::Validation {
                path: format!("{prefix}[{idx}]"),
                message: format!("path {} must be absolute", path.display()),
            });
        }
        if path
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
        {
            return Err(PolicyError::Validation {
                path: format!("{prefix}[{idx}]"),
                message: format!(
                    "path {} must be canonical (no \"..\" or \".\" components)",
                    path.display()
                ),
            });
        }
    }
    Ok(())
}
```

This is operator-controlled (trusted) config, so it is lower priority than the
requested-cwd reject; include it for completeness but treat the primary change as
the acceptance gate. If included, add the matching `use std::path::Component;` to
`file.rs`. (`validate_paths` is invoked for `agent.allow_cwd` via `validate_agent`
at `file.rs:473`.)

## Affected Files / Crates / Modules

- **`crates/mx-agent-policy/src/engine.rs`** (required): tighten `cwd_allowed`
  (`:353-363`); add unit tests in the `#[cfg(test)] mod tests` module; update the
  `cwd_allowed` doc comment.
- **`crates/mx-agent-policy/src/file.rs`** (optional secondary hardening):
  extend `validate_paths` (`:551-561`); add a load-time validation test mirroring
  `relative_cwd_reports_precise_path` (`:847-862`).
- **`docs/architecture.md`** (docs): one-line note in §13.3 that the requested
  cwd must be a clean absolute path (no `..`/`.`) or it is denied.
- **Read-only context (no edits expected):**
  `crates/mx-agent-daemon/src/exec.rs` (`ExecRequest.cwd`, the auth gate, the
  `RunSpec.cwd` spawn sites), `crates/mx-agent-daemon/src/runner.rs`
  (`build_command`).

## CLI / API Changes

None. `cwd_allowed` is a private function; `evaluate_exec`'s signature,
`ExecContext`, `Outcome`, and `DenyReason` are unchanged. No CLI flags, no IPC
methods, no help text. If the optional `validate_paths` hardening is included,
`Policy::parse` may now reject a previously-accepted (non-canonical) `allow_cwd`
entry at load — a stricter-validation change, not a surface change (see Risks).

## Data Model / Protocol Changes

None. No event schema, persistence, serialization, or wire change. The policy
TOML format is unchanged. (The optional hardening only tightens *validation* of
the existing `allow_cwd` field; it adds no new field.)

## Security Considerations

- **Defense-in-depth, fail-closed.** The change only ever turns a previous
  *allow* into a *deny*; it can never widen authorization. It tightens the
  `Backend::None` path where nothing else constrains the real cwd; the isolating
  backends (`bubblewrap`/`container`) already contain the escape via bind-mounts,
  and `require_sandbox` operators already deny `none` outright (issue #349).
- **Engine purity preserved.** The fix is a lexical component scan — no
  `canonicalize`, no filesystem access, no TOCTOU window, deterministic. This
  upholds the engine's documented contract ("never touches the filesystem") and
  keeps a `Deny` outcome a hard guarantee that no process starts.
- **Does not bypass any other gate.** The cwd check is consulted only *after* the
  trusted-room, signature/trust, `allow_exec`, and command-basename gates
  (`engine.rs:205-234`); this change does not alter their ordering or semantics.
  It controls only the working directory, never which program runs.
- **Residual symlink risk is unchanged and out of scope.** A pre-existing symlink
  *inside* an allowed directory that points outside it is not resolved by a
  lexical check; it is contained by the isolating backends and is a separate,
  narrower concern. The spec must not overclaim that all cwd escapes are closed —
  only the `..`/`.` textual gap.
- **No secret/redaction impact.** The rejected cwd is a requester-supplied
  filesystem path (not a credential) and is already embedded in
  `DenyReason::CwdNotAllowed { cwd }` and its `Display`; no new value is logged
  and no `Secret` handling changes. The optional load-time error logs only the
  configured path and its dotted field location, consistent with existing
  validation errors.
- **Unix-only.** `Component::ParentDir`/`CurDir` are the correct, portable
  primitives; no Windows path assumptions are introduced.
- **No `unsafe`, MSRV-safe.** Uses only `Path::components()` /
  `std::path::Component` (stable since Rust 1.0; well within MSRV 1.93).

## Testing Plan

All tests live in `crates/mx-agent-policy/src/engine.rs`'s `#[cfg(test)] mod
tests` (reuse `policy()`, whose fixture allowlist is `["/home/me/code/project"]`,
plus `exec()` and `argv()`):

1. **`exec_denied_cwd_parentdir_escape`** (acceptance core): argv
   `["cargo", "test"]`, cwd `"/home/me/code/project/../../etc"` →
   `Outcome::Deny(DenyReason::CwdNotAllowed { .. })`. Assert via
   `matches!(...)` (the embedded `cwd` is the raw string, so prefer the
   wildcard form as in `exec_denied_relative_cwd`).
2. **`exec_denied_cwd_trailing_parentdir`** (leading/mixed `..` case): cwd
   `"/home/me/code/project/.."` (escapes to `/home/me/code`) → `Deny`.
3. **`exec_denied_cwd_curdir_component`**: cwd `"/home/me/code/project/./sub"`
   → `Deny` (documents the deliberate over-rejection of `.`).
4. **`exec_still_allows_exact_allowed_cwd`**: cwd `"/home/me/code/project"` →
   `is_allowed()`. (Guards the no-regression goal for the exact dir.)
5. **No-regression for clean subdir**: the existing
   `exec_allows_command_in_subdirectory_of_allowed_cwd` (cwd
   `"/home/me/code/project/crates/foo"`) must continue to pass unchanged — verify,
   do not duplicate.
6. **Optional direct-helper unit tests** on the private `cwd_allowed` fn (callable
   from the same-file test module) for tighter coverage:
   `cwd_allowed("/home/me/code/project/../../etc", &allow)` → `false`;
   `cwd_allowed("/home/me/code/project/sub", &allow)` → `true`;
   `cwd_allowed("/home/me/code/project/./x", &allow)` → `false`; where `allow =
   vec![PathBuf::from("/home/me/code/project")]`.

If the optional `file.rs` hardening is implemented, add to `file.rs`'s test
module (mirroring `relative_cwd_reports_precise_path`):

7. **`noncanonical_cwd_entry_reports_precise_path`**: a policy with
   `allow_cwd = ["/abs", "/abs/../etc"]` → `Policy::parse` returns
   `PolicyError::Validation` whose `path` ends in `allow_cwd[1]` and whose
   `message` mentions canonical / `..`.

Run `cargo test -p mx-agent-policy`, plus the workspace gates
(`cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`,
`cargo test --all`). No live Matrix homeserver is needed — this is a pure policy
unit change.

## Documentation Updates

- **`docs/architecture.md` §13.3 Execution Policy** (`:2036-2086`): add one
  sentence that the *requested* cwd is matched against `allow_cwd` only when it is
  a clean absolute path — any `..` or `.` component is denied
  (`CwdNotAllowed`) — to prevent component-wise prefix escapes on the `none`
  backend.
- **`cwd_allowed` doc comment** in `engine.rs`: updated as shown in Proposed
  Implementation (this is also the `missing_docs`-style in-code documentation for
  the behavior).
- **Wiki `Security-and-Sandboxing`** (source in `wiki/`, if it enumerates
  `allow_cwd` semantics): optionally note the canonical-cwd requirement. Mirror
  any architecture wording; keep it to one line.
- **No README status-table change**: this is a bug-fix/tightening of an existing
  ✅ capability, not a new feature. Do not add a row or imply new behavior.

## Risks and Open Questions

- **Over-rejection of `.` (CurDir):** rejecting `/srv/project/./sub` (which is
  textually in-bounds) is deliberate and fail-closed; a well-formed caller sends a
  clean path. *Decision (recommended):* reject both `..` and `.` per the issue.
  Flag if any real caller is known to emit `.`-containing cwds (none expected;
  the daemon passes through a requester-supplied absolute path).
- **Optional `validate_paths` hardening is a stricter load-time check:** a policy
  whose `allow_cwd` entry contains `..`/`.` would newly fail to load. This is the
  intended hardening, but it is a (small) backward-incompatibility for an
  operator with a non-canonical entry. *Decision:* include it (cheap,
  operator-controlled, fail-loud with a precise path) but treat it as optional —
  the primary requested-cwd reject is the acceptance gate. Confirm with the
  maintainer whether to ship both in one PR or defer the load-time check.
- **Symlink escapes remain possible** on `Backend::None` via a pre-existing
  symlink inside an allowed dir. This is explicitly out of scope (a lexical check
  cannot resolve it without filesystem access, which the engine forbids); the
  spec/PR must not claim otherwise. If full symlink containment is ever wanted, it
  belongs in the runner/sandbox layer, not the pure policy engine — a separate
  issue.
- **Trailing-slash / double-slash inputs** (`/srv/project/`, `/srv//project`):
  `Path::components()` already collapses these to `RootDir + Normal*`, so they are
  unaffected (still matched normally). No special handling needed; a test is
  optional.

## Implementation Checklist

1. In `crates/mx-agent-policy/src/engine.rs`, modify `cwd_allowed` (`:353-363`):
   after the `is_absolute()` guard, return `false` if any
   `cwd_path.components()` element is `Component::ParentDir` or
   `Component::CurDir`; keep the existing `starts_with` match as the final step.
   Add `Component` to the imports (function-scope `use` or the top-of-file
   `use std::path::{...}`).
2. Update the `cwd_allowed` doc comment to explain the canonical-cwd requirement,
   the component-wise `starts_with` escape it prevents, that it is a pure
   (no-`canonicalize`) check for the `none` backend (issue #374), and that it does
   not resolve symlinks.
3. Add unit tests to the `engine.rs` test module:
   - `exec_denied_cwd_parentdir_escape` (cwd `/home/me/code/project/../../etc`).
   - `exec_denied_cwd_trailing_parentdir` (cwd `/home/me/code/project/..`).
   - `exec_denied_cwd_curdir_component` (cwd `/home/me/code/project/./sub`).
   - `exec_still_allows_exact_allowed_cwd` (cwd `/home/me/code/project`).
   - (optional) direct `cwd_allowed(...)` helper assertions for escape vs.
     clean-subdir vs. `.`-component.
4. Verify the existing `exec_allows_command_in_subdirectory_of_allowed_cwd`,
   `exec_denied_cwd_not_allowlisted`, and `exec_denied_relative_cwd` tests still
   pass unchanged (no regression).
5. (Optional, recommended) In `crates/mx-agent-policy/src/file.rs`, extend
   `validate_paths` (`:551-561`) to also reject `allow_cwd` entries containing
   `..`/`.` with a precise dotted-path `PolicyError::Validation`; add a
   `noncanonical_cwd_entry_reports_precise_path` test mirroring
   `relative_cwd_reports_precise_path`; add the `Component` import to `file.rs`.
6. Update `docs/architecture.md` §13.3 with the one-line canonical-cwd note; if
   the wiki `Security-and-Sandboxing` page enumerates `allow_cwd`, mirror the note
   there.
7. Run `cargo fmt`, then `cargo fmt --check`,
   `cargo clippy --all-targets --all-features -- -D warnings`, and
   `cargo test -p mx-agent-policy` / `cargo test --all`; ensure all green.
8. Keep the change a single focused PR referencing issue #374
   (`Closes #374`); do not touch the daemon spawn path, the loopback floor, or any
   protocol/CLI surface.
