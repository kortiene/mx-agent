//! End-to-end lifecycle test driving the real `mx-agent` binary.

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_mx-agent");

fn unique_runtime_dir() -> PathBuf {
    // Use a monotonic counter (not just a timestamp) so parallel tests in the
    // same process always get distinct directories regardless of clock resolution.
    // Parallel tests share the same PID, and system clocks can have coarser-than-
    // nanosecond resolution on some hosts, making timestamp-only paths collide.
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("mx-agent-it-{}-{}", std::process::id(), n))
}

fn run(runtime_dir: &PathBuf, args: &[&str]) -> std::process::Output {
    Command::new(BIN)
        .args(args)
        .env("MX_AGENT_RUNTIME_DIR", runtime_dir)
        .env("MX_AGENT_LOG", "off")
        .output()
        .expect("failed to run mx-agent")
}

#[test]
fn daemon_start_status_stop_cycle() {
    let runtime_dir = unique_runtime_dir();

    // Initially not running -> status exits 3.
    let out = run(&runtime_dir, &["daemon", "status", "--json"]);
    assert_eq!(
        out.status.code(),
        Some(3),
        "expected not-running status code"
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("\"running\":false"));

    // Start in the background.
    let out = run(&runtime_dir, &["daemon", "start"]);
    assert!(out.status.success(), "start should succeed: {out:?}");

    // Poll until running.
    let deadline = Instant::now() + Duration::from_secs(5);
    let running_json = loop {
        let out = run(&runtime_dir, &["daemon", "status", "--json"]);
        if out.status.success() {
            break String::from_utf8_lossy(&out.stdout).into_owned();
        }
        assert!(Instant::now() < deadline, "daemon never became ready");
        std::thread::sleep(Duration::from_millis(50));
    };

    // status --json reports pid, uptime, socket path, and version.
    assert!(running_json.contains("\"running\":true"));
    assert!(running_json.contains("\"pid\":"));
    assert!(running_json.contains("\"uptime_seconds\":"));
    assert!(running_json.contains("\"socket_path\":"));
    assert!(running_json.contains("\"version\":"));

    // Starting again is a no-op success.
    let out = run(&runtime_dir, &["daemon", "start"]);
    assert!(out.status.success());

    // Stop gracefully.
    let out = run(&runtime_dir, &["daemon", "stop"]);
    assert!(out.status.success(), "stop should succeed: {out:?}");

    // Poll until stopped.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let out = run(&runtime_dir, &["daemon", "status", "--json"]);
        if out.status.code() == Some(3) {
            break;
        }
        assert!(Instant::now() < deadline, "daemon never stopped");
        std::thread::sleep(Duration::from_millis(50));
    }

    // Stopping again is idempotent.
    let out = run(&runtime_dir, &["daemon", "stop"]);
    assert!(out.status.success());

    let _ = std::fs::remove_dir_all(&runtime_dir);
}

/// `mx-agent call` runs through the daemon IPC path (issue #193): it fails
/// clearly when no daemon is running, and otherwise the daemon — not the CLI —
/// executes the tool and returns a structured outcome.
#[test]
fn call_uses_daemon_ipc_path() {
    let runtime_dir = unique_runtime_dir();

    // No daemon yet: `call` fails clearly with exit code 3.
    let out = run(
        &runtime_dir,
        &["call", "--tool", "run_tests", "--arg", "package=x"],
    );
    assert_eq!(
        out.status.code(),
        Some(3),
        "call without a daemon should exit 3: {out:?}"
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("daemon"),
        "error should mention the daemon: {out:?}"
    );

    // Start the daemon (no Matrix session needed for loopback).
    let out = run(&runtime_dir, &["daemon", "start"]);
    assert!(out.status.success(), "start should succeed: {out:?}");
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let out = run(&runtime_dir, &["daemon", "status", "--json"]);
        if out.status.success() {
            break;
        }
        assert!(Instant::now() < deadline, "daemon never became ready");
        std::thread::sleep(Duration::from_millis(50));
    }

    // An unknown tool exercises the full IPC round-trip without spawning a
    // heavy build: the daemon executes loopback, returns a structured error,
    // and the CLI maps it to exit 127 with the preserved `--json` error shape.
    let out = run(
        &runtime_dir,
        &["call", "--tool", "definitely_not_a_tool", "--json"],
    );
    assert_eq!(
        out.status.code(),
        Some(127),
        "unknown tool should exit 127: {out:?}"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("\"ok\":false"),
        "expected JSON error envelope, got: {stdout}"
    );

    let out = run(&runtime_dir, &["daemon", "stop"]);
    assert!(out.status.success(), "stop should succeed: {out:?}");

    let _ = std::fs::remove_dir_all(&runtime_dir);
}

/// `mx-agent auth login` reads the password from `MX_AGENT_PASSWORD` rather
/// than hanging on an interactive TTY prompt (issue #273). When the env var is
/// set the binary must attempt the login (failing at the network level for an
/// unreachable homeserver) rather than printing "no password provided".
///
/// Using `127.0.0.1:1` as the homeserver guarantees an immediate connection
/// failure with no external dependency. The assertion boundary is: the env-var
/// read path works in the compiled binary, not that login itself succeeds.
#[test]
fn auth_login_reads_password_from_env_not_stdin() {
    let runtime_dir = unique_runtime_dir();
    let out = Command::new(BIN)
        .args([
            "auth",
            "login",
            "--homeserver",
            "https://127.0.0.1:1",
            "--user",
            "@test:localhost",
        ])
        .env("MX_AGENT_RUNTIME_DIR", &runtime_dir)
        .env("MX_AGENT_LOG", "off")
        .env("MX_AGENT_PASSWORD", "hunter2")
        .output()
        .expect("failed to run mx-agent");

    assert!(!out.status.success(), "login to port 1 must fail");
    let stderr = String::from_utf8_lossy(&out.stderr);
    // The env-var path was taken: we must NOT see the "no password provided"
    // message that would appear when the password is empty or unset.
    assert!(
        !stderr.contains("no password provided"),
        "env-var password must bypass the 'no password' guard: {stderr}"
    );
    // The failure must be a network / login error, not a password-reading error.
    // Any of the expected phrases confirm the login was attempted.
    let attempted = stderr.contains("login failed")
        || stderr.contains("could not")
        || stderr.contains("error")
        || stderr.contains("failed");
    assert!(
        attempted,
        "expected a login/network error in stderr: {stderr}"
    );
}

/// `mx-agent exec` runs through the daemon IPC path (issue #155): it fails
/// clearly when no daemon is running, and otherwise the daemon — not the CLI —
/// runs the command and returns the output frames the CLI renders.
#[test]
fn exec_uses_daemon_ipc_path() {
    let runtime_dir = unique_runtime_dir();

    // No daemon yet: `exec` fails clearly with exit code 3.
    let out = run(&runtime_dir, &["exec", "--", "echo", "hi"]);
    assert_eq!(
        out.status.code(),
        Some(3),
        "exec without a daemon should exit 3: {out:?}"
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("daemon"),
        "error should mention the daemon: {out:?}"
    );

    // Start the daemon (no Matrix session needed for loopback).
    let out = run(&runtime_dir, &["daemon", "start"]);
    assert!(out.status.success(), "start should succeed: {out:?}");
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let out = run(&runtime_dir, &["daemon", "status", "--json"]);
        if out.status.success() {
            break;
        }
        assert!(Instant::now() < deadline, "daemon never became ready");
        std::thread::sleep(Duration::from_millis(50));
    }

    // A successful command round-trips through IPC: the daemon runs it and the
    // CLI renders stdout and exits with the remote exit code (0 here).
    let out = run(&runtime_dir, &["exec", "--", "echo", "hi"]);
    assert!(out.status.success(), "echo should exit 0: {out:?}");
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("hi"),
        "stdout should carry the command output: {out:?}"
    );

    // A nonzero exit is propagated as the CLI's exit code.
    let out = run(&runtime_dir, &["exec", "--", "false"]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "false should exit 1 through IPC: {out:?}"
    );

    // A command that cannot be invoked maps to "not found" (exit 127).
    let out = run(
        &runtime_dir,
        &["exec", "--", "definitely-not-a-real-binary-xyz"],
    );
    assert_eq!(
        out.status.code(),
        Some(127),
        "unknown command should exit 127: {out:?}"
    );

    let out = run(&runtime_dir, &["daemon", "stop"]);
    assert!(out.status.success(), "stop should succeed: {out:?}");

    let _ = std::fs::remove_dir_all(&runtime_dir);
}
