# Issue #379 — Restart janitor must verify process-group identity (`started_unix`) before SIGKILL, and prove the reap path against a real orphan

## Problem Statement

The restart janitor `reap_orphaned_live_exec_children`
(`crates/mx-agent-daemon/src/exec.rs:312-336`, shipped under issue #316) signals
any recorded pgid whose **group leader is merely alive**, without consulting the
`started_unix` discriminator the `LivePgid` sidecar records for exactly this
purpose. The reap loop (`exec.rs:329-333`) gates solely on
`process_group_alive(rec.pgid)` and then calls `kill_process_group(rec.pgid)`;
`rec.started_unix` is never read. `process_group_alive` (`exec.rs:256-265`) is a
bare `kill(pgid, None)` existence probe (`Ok(()) | Err(EPERM)`) — it proves a
leader *exists* with that pgid, not that the leader is *our* child.

Between a daemon crash / force-kill and the next daemon start there is an
unbounded window in which the OS can recycle a recorded pgid onto an unrelated
process owned by the **same uid**. On the next boot
(`crates/mx-agent-daemon/src/lifecycle.rs:262-265`, invoked unconditionally) the
janitor will deliver an ungraceful `SIGKILL` (no SIGTERM grace) to that innocent
process group. The function's own doc concedes the gap (`exec.rs:315-318`:
"accepting the documented pgid-reuse caveat").

The `LivePgid` struct already records `started_unix` precisely so a reaper has a
"discriminator against the pgid-reuse race" (`exec.rs:133-145`, doc at
`:136-138`, field at `:143-144`, set to `now_unix()` on register at `:232`) —
but **no reaper consults it**.

Separately, the restart-janitor reap path has **no** process-level test. The only
proof against a real process group is
`kill_persisted_live_exec_children_kills_real_process_group`
(`exec.rs:4287-4360`), which covers the **`daemon stop` SIGKILL-escalation path**
(`kill_persisted_live_exec_children`), *not* the restart janitor. The janitor is
exercised only as a no-op against a missing sidecar
(`kill_persisted_and_reap_orphaned_children_with_no_sidecar_are_noops`,
`exec.rs:4266-4277`), so it has never been shown to reap a real surviving orphan
across a restart.

### Severity bound (why p2, not p0)

The daemon runs as an unprivileged uid, so `kill_process_group` (→ `killpg`,
`runner.rs:679-691`) can only reach process groups owned by that same uid — no
cross-user or privilege-escalation blast radius, no remote trigger, and the
`0600` sidecar carries only integers (pgids + timestamps, no secrets). The window
is already closed on the two non-crash paths: the graceful in-process teardown
clears the sidecar (`terminate_live_exec_children`, `exec.rs:296`) and the
`daemon stop` path force-kills "in the same breath" (`kill_persisted_…`,
`exec.rs:299-310`). The residual risk is the crash/force-kill-then-restart path,
where an arbitrary delay can elapse before boot: a local, self-inflicted DoS
(ungraceful `SIGKILL`) on an innocent same-uid process group, contingent on pid
reuse hitting the exact recorded value — low probability but non-zero on
long-lived hosts or after heavy spawn churn.

## Goals

1. **Identity-gate the janitor.** Before signaling in
   `reap_orphaned_live_exec_children`, confirm the live group leader is actually
   the recorded child — compare the leader's OS-reported start time against
   `rec.started_unix` within a small tolerance. Only kill on a match.
2. **Fail closed.** If the leader's identity cannot be established (start time
   undeterminable, helper unavailable, output unparseable), **skip the kill**
   rather than signal blindly. A surviving orphan is acceptable; killing an
   innocent process is not.
3. **Preserve the asymmetry with `kill_persisted_live_exec_children`.** That path
   keeps its no-identity-check behavior — the daemon is being force-killed in the
   same breath, so its reuse window is negligible. Only the restart janitor gains
   the check.
4. **Prove the reap path against a real process.** Add a process-level test that
   spawns a real `sleep` in its own group, records it with a *truthful*
   `started_unix`, and asserts the janitor kills it and clears the sidecar —
   plus a negative case where a recorded pgid resolves to a live process with a
   *mismatched* start time and is left untouched.
5. **No new dependencies, no `unsafe`, Unix-only, portable across Linux and
   macOS** (the daemon's only two platforms).

## Non-Goals

- **No schema or migration change.** `started_unix` is already in the sidecar
  (`exec.rs:143-144`, written at `:232`); closing this gap reads an existing
  field. Do not change the `LivePgid` shape or the sidecar file format.
- **No change to the graceful path or the `daemon stop` SIGKILL-escalation
  path.** `terminate_live_exec_children` and `kill_persisted_live_exec_children`
  are out of scope except where shared helpers are introduced.
- **No new "per-group marker" channel.** The issue offers a marker file as an
  *alternative*; this spec chooses the start-time comparison because the exec
  child is an arbitrary user command (`sleep`, `cargo`, …) that runs no mx-agent
  code and cannot be made to write a marker. The sidecar's `started_unix` already
  *is* the daemon-recorded marker; the OS start time is the independent witness we
  compare it against.
- **No attempt to fix the pre-existing "leader exited, group members still
  alive" limitation.** `process_group_alive` gates on the *leader* pid; if the
  leader is gone but children survive, the group is skipped today and stays
  skipped. That is the existing accepted behavior of both reap paths and is
  orthogonal to the reuse race.
- **No CLI, IPC, protocol, or policy surface changes.**
- **No Windows paths or assumptions.**

## Relevant Repository Context

- **Crate / module.** Everything lives in `mx-agent-daemon`, module
  `crates/mx-agent-daemon/src/exec.rs`. Process-group signaling primitives live
  in `crates/mx-agent-daemon/src/runner.rs`.
- **The live-pgid mechanism (issue #316).**
  - `LivePgid { pgid: u32, started_unix: u64 }` (`exec.rs:139-145`). The pgid
    equals the child pid (children spawn in their own group via
    `runner::build_command`).
  - `LIVE_PGIDS` in-memory registry + `0600` JSON sidecar
    (`live-pgids.json` under `paths.data_dir`), persisted atomically
    temp+rename (`persist_live_pgids`, `exec.rs:173-194`), loaded by
    `load_live_pgids` (`exec.rs:198-205`), removed by `clear_live_pgids_file`
    (`exec.rs:208-210`).
  - RAII `LivePgidGuard::register` stamps `started_unix: now_unix()` at spawn
    (`exec.rs:224-241`).
  - Three reapers consume the sidecar:
    `terminate_live_exec_children` (graceful, in-process, clears sidecar —
    `exec.rs:275-297`); `kill_persisted_live_exec_children` (`daemon stop`
    SIGKILL escalation, different process — `exec.rs:305-310`);
    `reap_orphaned_live_exec_children` (restart janitor — `exec.rs:320-336`).
  - `now_unix()` returns wall-clock Unix **seconds**
    (`exec.rs:2678-2684`), so `started_unix` is wall-clock seconds — any OS
    start-time comparison must produce wall-clock seconds too.
- **Signaling primitives.** `kill_process_group` / `terminate_process_group`
  (`runner.rs:712-724`) wrap `signal_process_group` → `nix::sys::signal::killpg`
  (`runner.rs:678-691`). All `#[cfg(unix)]` with `#[cfg(not(unix))]` no-op
  stubs; ignore `ESRCH`.
- **Dependencies available.** `nix` (workspace features `signal`, `process`,
  `user`; daemon adds `fs`) is the only OS-facing crate. There is **no**
  `procfs`, `sysinfo`, `libc`, or date-parsing crate, and `unsafe_code` is
  `forbid` workspace-wide (`Cargo.toml:54`) — so reading `/proc/<pid>/stat`'s
  `CLK_TCK`/`btime` conversion (needs `sysconf`) or macOS `sysctl KERN_PROC`
  (needs FFI) is **not** available without `unsafe` or a new dependency.
- **Platform reality (re-verified live on the target macOS / Darwin 25.5.0
  host during this plan run).** `ps -o etimes=` (raw elapsed seconds) is a
  **Linux-only** procps keyword — macOS `ps` rejects it with `ps: etimes:
  keyword not found` (and prints its valid-keyword list, which includes
  `etime`). The portable keyword present on **both** Linux and macOS is `etime`,
  formatted `[[DD-]HH:]MM:SS` (observed `00:00` for a just-spawned pid). A query
  for a non-existent pid exits **non-zero** (`ps -o etime= -p <gone>` → exit 1),
  so `process_start_unix`'s `status.success()` guard fails closed for a reaped
  leader exactly as designed. `lstart` (absolute datetime) is also portable but
  requires month-name + timezone parsing (and thus a date crate) and is rejected
  here in favor of `etime`.
- **Test conventions.** Tests live in the `#[cfg(test)] mod tests` block at the
  bottom of `exec.rs`. `unique_temp_dir(tag)` (`exec.rs:3041-3051`) gives a
  per-call data dir; `SessionPaths::for_data_dir(dir)` +
  `paths.ensure_data_dir()` build a private `0700` data dir without touching the
  process environment. The existing real-process pattern to mirror is
  `kill_persisted_live_exec_children_kills_real_process_group` (`exec.rs:4287`):
  spawn `Command::new("sleep").arg("300").process_group(0).spawn()`,
  `pgid == child.id()`, register in the sidecar, signal, `child.wait()` +
  `waitpid` (tolerating `ECHILD`), assert `!process_group_alive(pgid)`.
- **Architecture docs.** §11.2 (`docs/architecture.md:1697-1701`) and the §11.4
  failure table (`:1727`) describe the live-pgid sidecar + restart-janitor reap;
  neither yet mentions the identity check.
- **MSRV.** The workspace MSRV is **1.93** (`Cargo.toml:20`, README badge),
  enforced by the `msrv` CI job — not the 1.74 quoted in some legacy text.
  `u64::abs_diff` (stable since 1.60) is available.

## Proposed Implementation

All changes are confined to `crates/mx-agent-daemon/src/exec.rs`. Strategy:
derive each live group leader's wall-clock start time from `ps -o etime=` and
compare it to `rec.started_unix` within a small tolerance; only `SIGKILL` on a
match; fail closed otherwise. A single `ps`-based code path serves both Linux
and macOS (no `/proc` vs `sysctl` fork), adds no dependency, and uses no
`unsafe`. The janitor runs once at boot over a handful of records, so spawning
`ps` per live record is negligible.

### 1. A pure, unit-testable `etime` parser

Add a free function that converts a `ps -o etime=` string into elapsed seconds:

```rust
/// Parse a `ps -o etime=` elapsed-time string (`[[DD-]HH:]MM:SS`) into whole
/// seconds. Returns `None` on any shape `ps` would not produce.
///
/// `ps` renders process age as `MM:SS`, `HH:MM:SS`, or `DD-HH:MM:SS`; the field
/// is portable across Linux (procps) and macOS (BSD ps), unlike the Linux-only
/// `etimes` raw-seconds keyword.
fn parse_etime_seconds(raw: &str) -> Option<u64> {
    let raw = raw.trim();
    let (days, hms) = match raw.split_once('-') {
        Some((d, rest)) => (d.parse::<u64>().ok()?, rest),
        None => (0, raw),
    };
    let mut it = hms.split(':').rev(); // ss, mm, [hh]
    let secs = it.next()?.parse::<u64>().ok()?;
    let mins = it.next()?.parse::<u64>().ok()?;
    let hours = match it.next() {
        Some(h) => h.parse::<u64>().ok()?,
        None => 0,
    };
    if it.next().is_some() {
        return None; // more than 3 colon-separated fields → not an etime
    }
    if secs >= 60 || mins >= 60 {
        return None; // reject malformed components
    }
    Some(days * 86_400 + hours * 3_600 + mins * 60 + secs)
}
```

### 2. OS-reported start time of a pid (fail-closed)

```rust
/// The OS-reported start time of `pid` in wall-clock Unix seconds, or `None`
/// when it cannot be determined (process gone, `ps` unavailable/failed, or
/// unparseable output). Derived as `now - elapsed` from `ps -o etime=`.
///
/// Comparable to [`LivePgid::started_unix`] (also wall-clock seconds). Used by
/// the restart janitor to defend against the pgid-reuse race: a recycled pgid
/// belongs to a *recently* started process, whose derived start time will be far
/// from the recorded child's.
#[cfg(unix)]
fn process_start_unix(pid: u32) -> Option<u64> {
    let out = std::process::Command::new("ps")
        .args(["-o", "etime=", "-p", &pid.to_string()])
        .output()
        .ok()?;
    if !out.status.success() {
        return None; // pid gone, or ps refused
    }
    let elapsed = parse_etime_seconds(std::str::from_utf8(&out.stdout).ok()?)?;
    Some(now_unix().saturating_sub(elapsed))
}
```

Notes:
- `now - elapsed` is robust to slow boots/tests: `elapsed` grows with wall time,
  so the derived start stays ≈ the true start regardless of how long the daemon
  was down or how long the janitor takes.
- `saturating_sub` guards the (impossible-in-practice) case where the system
  clock moved backward.

### 3. Identity check + tolerance constant

```rust
/// Wall-clock-second slack allowed between a recorded child's `started_unix` and
/// the OS-reported start time of its pgid leader.
///
/// Absorbs measurement skew only: `started_unix` is stamped on the parent side
/// just *after* fork, while `ps` reports `etime` truncated to whole seconds, so
/// the two can differ by ~1–2s. It need not (and must not) absorb the orphan's
/// *age*: we compare start *times*, not ages, so a long-lived orphan still
/// matches. A recycled pgid's leader started long after the crash, far outside
/// this window, so it is rejected.
const PGID_START_TOLERANCE_SECS: u64 = 5;

/// Whether the live group leader `rec.pgid` is the child we recorded — i.e. its
/// OS start time matches `rec.started_unix` within [`PGID_START_TOLERANCE_SECS`].
/// Fails closed (`false`) when the start time cannot be established.
#[cfg(unix)]
fn pgid_leader_matches_record(rec: &LivePgid) -> bool {
    match process_start_unix(rec.pgid) {
        Some(started) => started.abs_diff(rec.started_unix) <= PGID_START_TOLERANCE_SECS,
        None => false, // fail closed: cannot confirm identity → do not signal
    }
}
```

### 4. Gate the janitor

Update the reap loop (`exec.rs:329-333`) so the cheap liveness probe remains the
first filter (avoids spawning `ps` for already-dead groups, the common boot
case) and the identity check is the second, kill-authorizing gate:

```rust
for rec in &records {
    #[cfg(unix)]
    {
        if !process_group_alive(rec.pgid) {
            continue; // leader already gone; nothing to reap
        }
        if pgid_leader_matches_record(rec) {
            kill_process_group(rec.pgid);
        } else {
            tracing::warn!(
                pgid = rec.pgid,
                started_unix = rec.started_unix,
                "skipping reap of live pgid: leader identity does not match the \
                 recorded child (possible pgid reuse); failing closed"
            );
        }
    }
}
clear_live_pgids_file(paths);
```

Keep clearing the sidecar unconditionally at the end (matching today): the
sidecar is a snapshot of the *previous* run's in-flight children; once the
janitor has decided what to reap, those records are spent. (A skipped impostor
record is intentionally dropped — re-attempting it on a later boot would only
re-risk the same innocent kill.)

### 5. Update the function and `LivePgid` docs

- Rewrite the `reap_orphaned_live_exec_children` doc (`exec.rs:312-319`) to
  state it now verifies leader identity via OS start time before signaling and
  fails closed on mismatch — removing the "accepting the documented pgid-reuse
  caveat" concession.
- Tighten the `LivePgid::started_unix` doc (`exec.rs:136-138`) from "a reaper
  has a discriminator" to note the restart janitor *consults* it.
- Leave `kill_persisted_live_exec_children`'s doc as-is (it deliberately does
  not check identity; the window is negligible).

### `#[cfg(unix)]` discipline

`process_start_unix` and `pgid_leader_matches_record` are `#[cfg(unix)]` like
`process_group_alive`. The whole project is Unix-only, but keep the gating
consistent with the existing functions so a non-Unix build (if ever attempted)
still compiles the no-op surface. `parse_etime_seconds` is pure and needs no cfg.

## Affected Files / Crates / Modules

- **`crates/mx-agent-daemon/src/exec.rs`** (only production change):
  - Add `parse_etime_seconds`, `process_start_unix`, `pgid_leader_matches_record`,
    `PGID_START_TOLERANCE_SECS`.
  - Modify `reap_orphaned_live_exec_children` (`:320-336`) reap loop.
  - Update docs on `reap_orphaned_live_exec_children` (`:312-319`) and
    `LivePgid::started_unix` (`:136-138`).
  - Add tests in `#[cfg(test)] mod tests`.
- **`docs/architecture.md`** — §11.2 (`:1697-1701`) and §11.4 table row
  (`:1727`): note the janitor verifies leader start-time identity before
  `SIGKILL` and fails closed on mismatch.
- **Read-only references** (no change): `crates/mx-agent-daemon/src/runner.rs`
  (`kill_process_group`, `signal_process_group`),
  `crates/mx-agent-daemon/src/lifecycle.rs:262-265` (janitor call site),
  `crates/mx-agent-daemon/src/session.rs` (`SessionPaths`).

## CLI / API Changes

None. The janitor and all new helpers are private (`fn`, not `pub fn`); the
boot-time call site in `lifecycle.rs` is unchanged. No command, flag, IPC method,
or `--json` shape changes.

## Data Model / Protocol Changes

None. The `LivePgid` struct, the `live-pgids.json` sidecar format, its `0600`
permissions, and its atomic temp+rename persistence are unchanged. The fix reads
the existing `started_unix` field — no schema, migration, or serialization
change, so an old sidecar left by a pre-upgrade daemon still deserializes and is
handled correctly (its `started_unix` is real, so a genuine orphan still
matches).

## Security Considerations

- **Tightens, never loosens, authorization.** The change can only *suppress* a
  `SIGKILL` (when identity is unconfirmed or mismatched); it never causes a kill
  that the old code would not have performed. The execution-authorization gate
  (signing → trust → policy → approval) is untouched and unrelated.
- **Fail-closed direction is "do not signal."** Unlike the daemon's
  authorization paths (where fail-closed = deny execution), here the safe failure
  is *not killing*: protecting an innocent same-uid process outweighs guaranteeing
  an orphan is reaped. This is explicitly the issue's instruction and is logged at
  `warn` so an un-reaped orphan is observable.
- **No secrets.** The sidecar remains integers only (pgids + timestamps,
  `0600`). The new `warn!` log records `pgid` and `started_unix` (non-sensitive
  integers) and never a command, env, or token — consistent with the
  redaction/`Secret` conventions. No new field flows through
  `is_sensitive_key`.
- **Subprocess surface.** `ps` is invoked with a fixed argv
  (`-o etime= -p <integer>`) and no shell, so there is no argument-injection
  surface; `pid` is a `u32` rendered via `to_string()`. `ps` is resolved from
  `PATH`; if it is absent or replaced the helper returns `None` and the janitor
  fails closed (skips the kill) — the safe direction. This runs only in the
  daemon's own boot path, never under the sandbox or on behalf of a remote
  request.
- **Unix-only.** New OS-facing helpers are `#[cfg(unix)]`, mirroring
  `process_group_alive`. No Windows paths introduced.
- **No `unsafe`, no new dependency.** Honors `unsafe_code = "forbid"` and adds no
  crate; uses `std::process::Command` + `nix` already in the tree.

## Testing Plan

All tests in `crates/mx-agent-daemon/src/exec.rs` `#[cfg(test)] mod tests`.

### Unit — `parse_etime_seconds`
- `MM:SS`: `"00:00"` → `0`, `"05:42"` → `342`, `"00:59"` → `59`.
- `HH:MM:SS`: `"01:02:03"` → `3723`.
- `DD-HH:MM:SS`: `"23-14:41:54"` → `23*86400 + 14*3600 + 41*60 + 54`
  (the value observed on the target host).
- Whitespace tolerance: leading/trailing spaces (ps right-pads) parse the same.
- Malformed → `None`: `""`, `"abc"`, `"1:2:3:4"` (too many fields), `"99:99"`
  (out-of-range minutes), `"00:99"` (out-of-range seconds), `"x-01:02:03"`.

### Unit — `process_start_unix` (`#[cfg(unix)]`)
- For `std::process::id()` (the test process), returns `Some(t)` with
  `t <= now_unix()` and `now_unix() - t` within a sane bound (this process is
  young in a test binary; assert `t` is within, say, the last hour to avoid
  flakiness).
- For a pid that does not exist (e.g. spawn `true`, `wait` it, then query its
  reaped pid) returns `None` (ps exits non-zero) — i.e. fails closed.

### Unit — `pgid_leader_matches_record` (`#[cfg(unix)]`)
- Spawn a real `sleep` in its own group; build `LivePgid { pgid, started_unix:
  now_unix() }`; assert `true`. Then build a record with `started_unix:
  now_unix() - 3600`; assert `false`. Clean up the child.

### Process-level — janitor reaps a real orphan (mirror `exec.rs:4287`)
`reap_orphaned_live_exec_children_kills_matching_real_process_group`:
1. `unique_temp_dir` + `SessionPaths::for_data_dir` + `ensure_data_dir`.
2. Spawn `sleep 300` with `.process_group(0)`; `pgid = child.id()`.
3. Persist a sidecar with `LivePgid { pgid, started_unix: now_unix() }`
   (**truthful** timestamp).
4. Assert the child is alive (`process_group_alive(pgid)`).
5. Call `reap_orphaned_live_exec_children(&paths)`.
6. `child.wait()` + `waitpid` tolerating `ECHILD`; assert
   `!process_group_alive(pgid)`.
7. Assert the sidecar was cleared (`load_live_pgids(&paths).is_empty()`).
8. `remove_dir_all`.

### Process-level — janitor does NOT kill a start-time impostor
`reap_orphaned_live_exec_children_spares_pgid_with_mismatched_start_time`:
1. Spawn a real `sleep 300` in its own group; `pgid = child.id()` (OS start ≈
   now). This stands in for a recycled pgid now owned by an innocent process.
2. Persist a sidecar with `LivePgid { pgid, started_unix: now_unix() - 3600 }`
   (a stale recorded time, simulating the dead original child).
3. Call `reap_orphaned_live_exec_children(&paths)`.
4. Assert the process is **still alive** (`process_group_alive(pgid)` /
   `kill(pid, None).is_ok()`) — the identity gate spared it.
5. Assert the sidecar was cleared anyway (spent record dropped).
6. **Explicitly** `kill_process_group(pgid)` + `child.wait()` to clean up; assert
   gone.

### Regression — keep the existing tests green
- `kill_persisted_and_reap_orphaned_children_with_no_sidecar_are_noops`
  (`exec.rs:4266`) and `live_pgids_sidecar_round_trips` (`exec.rs:4217`) must
  still pass unchanged.
- `kill_persisted_live_exec_children_kills_real_process_group`
  (`exec.rs:4287`) must still pass — it uses `started_unix: 0` and must continue
  to kill, proving the `kill_persisted` path keeps its no-identity-check behavior
  (only the janitor changed).

### CI gates
`cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`,
`cargo test --all`, and the `msrv` (1.93) build. The process-level tests use only
`sleep`/`ps`, both present on Linux and macOS CI runners; no homeserver, Docker,
or `#[ignore]` needed.

## Documentation Updates

- **`docs/architecture.md`**: §11.2 (`:1697-1701`) — add that the restart janitor
  verifies each live group leader's OS-reported start time against the recorded
  `started_unix` before `SIGKILL`, and skips (fails closed) on mismatch or when
  the start time cannot be determined. §11.4 table row (`:1727`) — append the
  identity check to the "Daemon crashes while child runs" cell.
- **In-code docs** (counted as required `missing_docs`-clean documentation):
  doc-comment every new `fn`/`const`; update the `reap_orphaned_live_exec_children`
  and `LivePgid::started_unix` docs as in §5 above.
- **README**: no change required — the status table and security posture bullets
  do not enumerate the janitor's reuse defense, and per the alpha-honesty rule we
  should not advertise behavior beyond what ships. (Optional: a one-line note in
  the "E2EE production hardening"/security area is *not* recommended to avoid
  scope creep.)
- **`docs/security-hardening.md`**: only touch if it currently describes the
  janitor's pgid-reuse caveat; otherwise leave it (grep for `live-pgid` / `reap`
  before editing). Do not introduce a new claim it does not already make.

## Risks and Open Questions

- **`etime` granularity / tolerance sizing.** `etime` is whole seconds and
  `started_unix` is stamped just after fork, so a small positive skew is normal.
  `PGID_START_TOLERANCE_SECS = 5` comfortably covers it while still rejecting a
  recycled pgid (whose leader started after the crash+downtime, far outside 5s).
  Open question: confirm 5s is acceptable; it can be lowered to 2–3s with no loss
  of safety, but 5s is the conservative default. The tolerance must **not** scale
  with orphan age — we compare start *times*, not ages.
- **System clock adjustments.** `etime` is kernel-derived elapsed time; deriving
  start via `now_unix() - etime` assumes the wall clock did not jump materially
  between the child's spawn and the janitor run. A backward jump is handled by
  `saturating_sub`; a large forward jump could in principle push a genuine
  orphan's derived start outside tolerance and cause a *skip* (fail-closed, safe:
  an un-reaped orphan, never an innocent kill). Acceptable given the safe failure
  direction. `lstart` (absolute) would avoid this but needs a date parser/crate —
  rejected as out of scope.
- **`ps` availability/format.** `ps -o etime=` is POSIX-portable across the two
  supported platforms (verified `etime` on macOS; procps on Linux). If a minimal
  container lacks `ps`, the helper returns `None` → janitor fails closed (skips),
  which is safe. No new dependency is incurred to avoid this.
- **Subprocess at boot.** One `ps` per *alive* recorded pgid. The `process_group_alive`
  pre-filter means dead records (the common case) cost no subprocess, and the
  record count is bounded by concurrent in-flight execs of the prior run — so the
  overhead is negligible.
- **Confirm no other consumer** of `process_group_alive` expects the new
  semantics — it is unchanged; only the janitor composes it with the new identity
  check. (Verify via grep that `process_group_alive` callers are limited to the
  reap paths/tests before finalizing.)
- **MSRV note.** Implement against MSRV 1.93 (`u64::abs_diff`, `str::split_once`
  both well below 1.93). Ignore the stale "1.74" figure in legacy task text.

## Implementation Checklist

1. In `crates/mx-agent-daemon/src/exec.rs`, add `parse_etime_seconds(raw: &str)
   -> Option<u64>` (pure; handles `MM:SS`, `HH:MM:SS`, `DD-HH:MM:SS`; rejects
   out-of-range and over-long inputs).
2. Add `#[cfg(unix)] fn process_start_unix(pid: u32) -> Option<u64>` running
   `ps -o etime= -p <pid>` and returning `now_unix().saturating_sub(elapsed)`;
   `None` on non-zero exit / spawn error / parse failure.
3. Add `const PGID_START_TOLERANCE_SECS: u64 = 5;` and
   `#[cfg(unix)] fn pgid_leader_matches_record(rec: &LivePgid) -> bool` using
   `abs_diff <= PGID_START_TOLERANCE_SECS`, failing closed on `None`.
4. Rewrite the reap loop in `reap_orphaned_live_exec_children` (`exec.rs:329-333`)
   to: skip dead leaders, `kill_process_group` only when
   `pgid_leader_matches_record`, and `warn!` (pgid + started_unix) on a skipped
   live mismatch. Keep the unconditional `clear_live_pgids_file` at the end.
5. Update the doc comments on `reap_orphaned_live_exec_children` (`:312-319`) and
   `LivePgid::started_unix` (`:136-138`); add doc comments to all new items.
6. Add unit tests for `parse_etime_seconds` (valid + malformed cases).
7. Add `#[cfg(unix)]` unit tests for `process_start_unix` (self pid → `Some`,
   reaped pid → `None`) and `pgid_leader_matches_record` (truthful → true,
   stale-by-3600s → false).
8. Add `reap_orphaned_live_exec_children_kills_matching_real_process_group`
   (positive, truthful `started_unix`) mirroring `exec.rs:4287`.
9. Add `reap_orphaned_live_exec_children_spares_pgid_with_mismatched_start_time`
   (negative, stale `started_unix`; assert process survives, then clean up).
10. Update `docs/architecture.md` §11.2 (`:1697-1701`) and §11.4 row (`:1727`).
11. Run `cargo fmt`, `cargo clippy --all-targets --all-features -- -D warnings`,
    `cargo test -p mx-agent-daemon` (and `cargo test --all`); confirm the MSRV
    (1.93) build still compiles.
12. Grep for other `process_group_alive` / `reap_orphaned_live_exec_children`
    callers to confirm no behavior expectations were broken.
