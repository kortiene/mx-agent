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
