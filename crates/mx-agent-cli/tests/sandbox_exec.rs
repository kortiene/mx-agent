//! End-to-end tests for the hidden `__sandbox-exec` launcher trampoline
//! (issue #349).
//!
//! These tests drive the real `mx-agent` binary to validate the full chain:
//! CLI subcommand → `LauncherArgs::parse` → `apply_resource_limits` (setrlimit)
//! → `exec` (process-image replacement). Unit tests in `mx-agent-sandbox` and
//! `mx-agent-daemon` cover the pure parts (argv shape, parse round-trip,
//! `launcher_wrap` logic); these tests cover what only a real binary can verify:
//!
//! - The hidden subcommand is wired in the CLI (`cmd_sandbox_exec` calls
//!   `run_launcher`) and accepts the documented flag set.
//! - A command actually runs and its stdout/exit code pass through the `exec`.
//! - Resource caps are enforced by the kernel (not just serialised into argv):
//!   a CPU-limited busy loop is killed rather than running forever.
//!
//! The CPU-cap tests are Unix-only (RLIMIT_CPU is a Unix concept) but work on
//! both Linux and macOS, since the kernel delivers SIGXCPU at the soft limit
//! (1 CPU-second here) and SIGKILL at the hard limit.

const BIN: &str = env!("CARGO_BIN_EXE_mx-agent");

fn sandbox_exec(args: &[&str]) -> std::process::Output {
    std::process::Command::new(BIN)
        .arg(mx_agent_sandbox::LAUNCHER_SUBCOMMAND)
        .args(args)
        .env("MX_AGENT_LOG", "off")
        .output()
        .expect("failed to spawn mx-agent __sandbox-exec")
}

// --- Basic pass-through and exit-code forwarding ----------------------------

#[test]
fn sandbox_exec_runs_command_and_forwards_stdout() {
    // A command under a generous CPU cap must run normally and forward its
    // stdout through the exec. The daemon always provides at least one flag
    // before `--` (the `is_needed` guard prevents the launcher from being
    // invoked with zero flags), so we mirror that here.
    let out = sandbox_exec(&["--cpu", "3600", "--", "/bin/echo", "sandbox-ok"]);
    assert!(
        out.status.success(),
        "exit code: {:?}, stderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "sandbox-ok");
}

#[test]
fn sandbox_exec_forwards_nonzero_exit_code() {
    // A command that exits nonzero must produce a non-success status through
    // the launcher; the launcher itself does not add an extra exit code.
    let out = sandbox_exec(&["--cpu", "3600", "--", "/bin/sh", "-c", "exit 42"]);
    assert_eq!(
        out.status.code(),
        Some(42),
        "expected exit 42, got: {:?}",
        out.status.code()
    );
}

#[test]
fn sandbox_exec_cpu_and_seccomp_flags_run_command() {
    // CPU cap and seccomp=off with generous limits must run the command
    // normally. This exercises the multi-flag parse path and verifies
    // that seccomp=off is accepted as a valid value without error.
    // Note: RLIMIT_AS is intentionally omitted here because on macOS
    // the process address space may already exceed conservative test values,
    // causing EINVAL from setrlimit; the cpu cap path exercises the limit-apply
    // codepath sufficiently.
    let out = sandbox_exec(&[
        "--cpu",
        "3600",
        "--seccomp",
        "off",
        "--",
        "/bin/echo",
        "multi-flags-ok",
    ]);
    assert!(
        out.status.success(),
        "exit code: {:?}, stderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "multi-flags-ok"
    );
}

// --- Error handling ---------------------------------------------------------

#[test]
fn sandbox_exec_rejects_missing_separator() {
    // Without `--` the launcher cannot find the command boundary and must exit
    // nonzero. The diagnostic ("missing `--`…") may appear on stderr or stdout.
    let out = sandbox_exec(&["--nproc", "16"]);
    assert!(
        !out.status.success(),
        "missing `--` must cause a nonzero exit"
    );
}

#[test]
fn sandbox_exec_rejects_unknown_flag() {
    // An unrecognized flag must cause a nonzero exit.
    let out = sandbox_exec(&["--bogus-flag", "--", "true"]);
    assert!(
        !out.status.success(),
        "unknown flag must cause a nonzero exit"
    );
}

#[test]
fn sandbox_exec_rejects_bad_cap_value() {
    // A non-numeric value for a numeric cap flag must cause a nonzero exit.
    let out = sandbox_exec(&["--cpu", "not-a-number", "--", "true"]);
    assert!(
        !out.status.success(),
        "non-numeric cap value must cause a nonzero exit"
    );
}

// --- Sandbox visibility (issue #349) ----------------------------------------

#[test]
fn sandbox_exec_subcommand_is_hidden_from_help() {
    // The `__sandbox-exec` subcommand must not appear in the human-readable
    // --help output: it is an internal re-exec trampoline, not a user command.
    let out = std::process::Command::new(BIN)
        .arg("--help")
        .env("MX_AGENT_LOG", "off")
        .output()
        .expect("mx-agent --help failed");
    let help = String::from_utf8_lossy(&out.stdout);
    assert!(
        !help.contains(mx_agent_sandbox::LAUNCHER_SUBCOMMAND),
        "hidden launcher subcommand must not appear in --help: {help}"
    );
}

// --- Seccomp filter installation (issue #380) --------------------------------
//
// These tests verify that `--seccomp default` actually installs the curated
// default-deny BPF profile — not just that it is declared in the allowance.
// They span two levels:
//
//  - Cross-platform: the flag is accepted and the command runs (on macOS the
//    seccomp step is a documented no-op; on Linux it is the real filter).
//  - Linux-only: the filter survives `execve` and is active in the child
//    (SECCOMP_MODE_FILTER = 2), verified via `/proc/self/status`; and the
//    allowlist is broad enough that real shell pipelines complete without
//    triggering the default-deny action.
//
// The CI `sandbox-linux` job (ubuntu + sysctl userns) is the authoritative gate
// for the Linux-only tests; the cross-platform test also runs on macOS CI.

#[test]
fn sandbox_exec_seccomp_default_runs_command() {
    // Acceptance (issue #380): `--seccomp default` must not prevent a simple
    // command from running. On Linux the curated BPF filter is installed and
    // the allowlist must include `execve`/`read`/`write`/`exit_group`; on macOS
    // the step is a documented no-op. Either way the launcher must not fail on
    // this flag and the command must succeed.
    //
    // No resource cap is set alongside seccomp, exercising the path where the
    // launcher is engaged *only* for the seccomp filter (none path, Linux) or
    // is a pure no-op (macOS).
    let out = sandbox_exec(&[
        "--seccomp",
        "default",
        "--",
        "/bin/echo",
        "seccomp-default-ok",
    ]);
    assert!(
        out.status.success(),
        "echo must succeed with --seccomp default: exit={:?} stderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "seccomp-default-ok",
        "stdout must pass through the exec unchanged"
    );
}

// The following two tests are Linux-only: seccomp BPF does not exist on macOS
// (the step is a no-op there), so SECCOMP_MODE_FILTER cannot be observed and
// the tests are compiled out.

#[cfg(target_os = "linux")]
#[test]
fn sandbox_exec_seccomp_filter_mode_active_after_exec() {
    // Acceptance (issue #380): after the launcher installs the BPF filter and
    // replaces its own image with the target via `exec`, the target process must
    // run under SECCOMP_MODE_FILTER (mode 2). Reading `/proc/self/status` from
    // *within* the filtered child confirms:
    //   (a) the filter survived `execve` (seccomp filters are inherited across exec),
    //   (b) the filter is active in the child, not just declared by the launcher.
    //
    // `/proc/self/status` field values:
    //   Seccomp: 0  = SECCOMP_MODE_DISABLED
    //   Seccomp: 1  = SECCOMP_MODE_STRICT
    //   Seccomp: 2  = SECCOMP_MODE_FILTER  ← expected when the BPF profile is installed
    //
    // `awk` is used instead of `grep -P` for portability (no Perl-regex dep).
    let out = sandbox_exec(&[
        "--seccomp",
        "default",
        "--",
        "/bin/sh",
        "-c",
        "awk '/^Seccomp:/ { exit($2 == 2 ? 0 : 1) }' /proc/self/status",
    ]);
    assert!(
        out.status.success(),
        "awk must find Seccomp mode 2 (FILTER) in /proc/self/status of the \
         filtered child, confirming the BPF profile survived execve: \
         exit={:?} stderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[cfg(target_os = "linux")]
#[test]
fn sandbox_exec_seccomp_default_allowlist_permits_shell_pipeline() {
    // Acceptance (issue #380): the curated allowlist must be broad enough that
    // a realistic shell pipeline completes without triggering the default-deny
    // action. A simple `echo hi | cat` exercises `clone`/`clone3` (fork),
    // `pipe2`, `dup3`/`dup`, `execve`, `read`, `write`, and `exit_group` —
    // all of which must be present in the allowlist for the pipeline to work.
    //
    // The default-deny action is ERRNO(EPERM) (not KILL), so a too-strict
    // allowlist causes a recoverable command failure rather than a silent hang.
    let out = sandbox_exec(&[
        "--seccomp",
        "default",
        "--",
        "/bin/sh",
        "-c",
        "echo 'pipeline-ok' | cat",
    ]);
    assert!(
        out.status.success(),
        "shell pipeline must complete under the default seccomp filter: \
         exit={:?} stderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "pipeline-ok",
        "pipeline output must reach stdout"
    );
}

// --- Resource-cap enforcement (Unix, issue #349) ----------------------------
//
// These tests verify that the kernel actually enforces the resource caps the
// launcher configures via setrlimit, not just that the caps are serialised
// into the launcher argv (that is covered by the unit tests). They are
// Unix-only because RLIMIT_CPU is a Unix concept. The CPU-kill test is expected
// to complete within a few wall-clock seconds on any CI machine: the kernel
// delivers SIGXCPU when the process consumes 1 CPU-second, and SIGKILL at the
// hard limit. A tight shell busy-loop consumes 1 CPU-second quickly.

#[cfg(unix)]
#[test]
fn sandbox_exec_cpu_cap_terminates_busy_loop() {
    // A CPU-intensive loop under a 1-CPU-second cap must be killed by the
    // kernel via RLIMIT_CPU. The launcher sets both the soft and hard limit to
    // 1; on soft-limit delivery (SIGXCPU) a plain shell exits nonzero by
    // default. Either way the exit must not be success.
    let out = sandbox_exec(&[
        "--cpu",
        "1",
        "--",
        "/bin/sh",
        "-c",
        "while true; do :; done",
    ]);
    assert!(
        !out.status.success(),
        "CPU-limited busy loop must be terminated by RLIMIT_CPU, not succeed: \
         exit={:?} stderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[cfg(unix)]
#[test]
fn sandbox_exec_cpu_cap_allows_fast_command() {
    // A command that completes well within the CPU-second cap must NOT be
    // killed: the cap is a ceiling, not a guaranteed execution time.
    let out = sandbox_exec(&["--cpu", "30", "--", "/bin/echo", "cpu-ok"]);
    assert!(
        out.status.success(),
        "a fast command must not be killed by a generous CPU cap: {:?}",
        out.status
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "cpu-ok");
}
