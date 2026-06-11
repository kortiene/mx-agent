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

// ── Issue #269: auth login / trust CLI-local carve-out e2e tests ──────────────
//
// `auth status`, `auth logout`, and `trust fingerprint` are the CLI-local
// commands that form the auth/trust carve-out (architecture §10.3). They touch
// the daemon-owned data directory directly without going over IPC, and the
// session/key writes are serialised by an advisory `flock` on `.write.lock`
// (issue #269). The tests below drive the compiled binary and verify:
//   • auth status exit codes and JSON output (no token leakage)
//   • auth logout removes the session file and reverts status to logged-out
//   • trust fingerprint creates the signing key with 0600 permissions and
//     emits a stable SHA256: fingerprint
//   • two concurrent trust-fingerprint processes converge on one key
//     (cross-process advisory-lock regression test for issue #269)

/// Extract `SHA256:<base64>` from a `trust fingerprint --json` JSON response.
/// Used by the concurrency test to compare fingerprints without a JSON parser.
fn extract_sha256_fingerprint(json: &str) -> String {
    let start = json.find("SHA256:").expect("SHA256: not found in output");
    let after = &json[start..];
    let end = after
        .find('"')
        .expect("closing quote after SHA256: fingerprint");
    after[..end].to_string()
}

/// `mx-agent auth status --json` on a fresh data directory must exit 3 (not
/// logged in) and emit `{"logged_in":false}`. This exercises the CLI-local
/// `auth status` path (issue #269 carve-out) without a daemon or homeserver.
#[test]
fn auth_status_not_logged_in_exits_3_with_json() {
    let data_dir = unique_runtime_dir();

    let out = Command::new(BIN)
        .args(["auth", "status", "--json"])
        .env("MX_AGENT_DATA_DIR", &data_dir)
        .env("MX_AGENT_RUNTIME_DIR", &data_dir)
        .env("MX_AGENT_LOG", "off")
        .output()
        .expect("failed to run mx-agent auth status");

    assert_eq!(
        out.status.code(),
        Some(3),
        "auth status with no session must exit 3: {out:?}"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("\"logged_in\":false"),
        "auth status --json must report logged_in:false: {stdout}"
    );

    let _ = std::fs::remove_dir_all(&data_dir);
}

/// `mx-agent auth status --json` when a session file exists must exit 0,
/// report `logged_in:true` with the user/device/homeserver fields, and must
/// NOT include the access token in the output (issue #269: CLI-local auth path
/// must not leak credentials).
#[test]
fn auth_status_reports_session_without_leaking_tokens() {
    use std::os::unix::fs::PermissionsExt;

    let data_dir = unique_runtime_dir();
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::set_permissions(&data_dir, std::fs::Permissions::from_mode(0o700)).unwrap();

    // Write a synthetic session.json — no homeserver required.
    let session_json = concat!(
        "{\"homeserver\":\"https://example.matrix.org/\",",
        "\"user_id\":\"@testuser:example.matrix.org\",",
        "\"device_id\":\"TESTDEVICE01\",",
        "\"access_token\":\"syt_very_secret_test_token_xyz\"}"
    );
    let session_path = data_dir.join("session.json");
    std::fs::write(&session_path, session_json).unwrap();
    std::fs::set_permissions(&session_path, std::fs::Permissions::from_mode(0o600)).unwrap();

    let out = Command::new(BIN)
        .args(["auth", "status", "--json"])
        .env("MX_AGENT_DATA_DIR", &data_dir)
        .env("MX_AGENT_RUNTIME_DIR", &data_dir)
        .env("MX_AGENT_LOG", "off")
        .output()
        .expect("failed to run mx-agent auth status");

    assert!(
        out.status.success(),
        "auth status with a valid session must exit 0: {out:?}"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);

    assert!(
        stdout.contains("\"logged_in\":true"),
        "auth status --json must report logged_in:true: {stdout}"
    );
    assert!(
        stdout.contains("@testuser:example.matrix.org"),
        "auth status must include user_id: {stdout}"
    );
    assert!(
        stdout.contains("TESTDEVICE01"),
        "auth status must include device_id: {stdout}"
    );
    assert!(
        stdout.contains("example.matrix.org"),
        "auth status must include homeserver: {stdout}"
    );
    // The access token must never appear in the status output.
    assert!(
        !stdout.contains("syt_very_secret_test_token_xyz"),
        "auth status must not leak the access token: {stdout}"
    );
    assert!(
        !stdout.contains("access_token"),
        "auth status --json must not include the access_token field: {stdout}"
    );

    let _ = std::fs::remove_dir_all(&data_dir);
}

/// `mx-agent auth logout` removes the session file; a subsequent `auth status`
/// reports not-logged-in. Exercises the full CLI-local logout → status
/// round-trip (issue #269 carve-out: auth commands touch the data dir
/// directly without IPC).
#[test]
fn auth_logout_clears_session_and_status_reverts_to_logged_out() {
    use std::os::unix::fs::PermissionsExt;

    let data_dir = unique_runtime_dir();
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::set_permissions(&data_dir, std::fs::Permissions::from_mode(0o700)).unwrap();

    let session_json = concat!(
        "{\"homeserver\":\"https://example.matrix.org/\",",
        "\"user_id\":\"@logout_test:example.matrix.org\",",
        "\"device_id\":\"LOGOUTDEV01\",",
        "\"access_token\":\"syt_logout_test_token\"}"
    );
    let session_path = data_dir.join("session.json");
    std::fs::write(&session_path, session_json).unwrap();
    std::fs::set_permissions(&session_path, std::fs::Permissions::from_mode(0o600)).unwrap();

    // Confirm the session is visible before logging out.
    let pre = Command::new(BIN)
        .args(["auth", "status", "--json"])
        .env("MX_AGENT_DATA_DIR", &data_dir)
        .env("MX_AGENT_RUNTIME_DIR", &data_dir)
        .env("MX_AGENT_LOG", "off")
        .output()
        .expect("failed to run mx-agent auth status");
    assert!(
        pre.status.success(),
        "auth status must succeed with session: {pre:?}"
    );

    // Logout.
    let logout = Command::new(BIN)
        .args(["auth", "logout"])
        .env("MX_AGENT_DATA_DIR", &data_dir)
        .env("MX_AGENT_RUNTIME_DIR", &data_dir)
        .env("MX_AGENT_LOG", "off")
        .output()
        .expect("failed to run mx-agent auth logout");
    assert!(
        logout.status.success(),
        "auth logout must succeed: {logout:?}"
    );
    assert!(
        !session_path.exists(),
        "session.json must be removed after auth logout"
    );

    // Auth status after logout must report not-logged-in (exit 3).
    let post = Command::new(BIN)
        .args(["auth", "status", "--json"])
        .env("MX_AGENT_DATA_DIR", &data_dir)
        .env("MX_AGENT_RUNTIME_DIR", &data_dir)
        .env("MX_AGENT_LOG", "off")
        .output()
        .expect("failed to run mx-agent auth status after logout");
    assert_eq!(
        post.status.code(),
        Some(3),
        "auth status must exit 3 after logout: {post:?}"
    );
    let post_stdout = String::from_utf8_lossy(&post.stdout);
    assert!(
        post_stdout.contains("\"logged_in\":false"),
        "auth status after logout must report logged_in:false: {post_stdout}"
    );

    let _ = std::fs::remove_dir_all(&data_dir);
}

/// `mx-agent trust fingerprint --json` creates the daemon signing key in the
/// CLI process (issue #269 carve-out: CLI-local), emits a `SHA256:` fingerprint
/// and a `mxagent-ed25519:` key ID, creates the key file with `0600`
/// permissions, and returns the same fingerprint on subsequent invocations
/// (key stability across restarts).
#[test]
fn trust_fingerprint_creates_signing_key_cli_locally_and_is_stable() {
    use std::os::unix::fs::PermissionsExt;

    let data_dir = unique_runtime_dir();

    let run_fp = || {
        Command::new(BIN)
            .args(["trust", "fingerprint", "--json"])
            .env("MX_AGENT_DATA_DIR", &data_dir)
            .env("MX_AGENT_RUNTIME_DIR", &data_dir)
            .env("MX_AGENT_LOG", "off")
            .output()
            .expect("failed to run mx-agent trust fingerprint")
    };

    // First invocation creates the key.
    let first = run_fp();
    assert!(
        first.status.success(),
        "trust fingerprint must succeed: {first:?}"
    );
    let first_out = String::from_utf8_lossy(&first.stdout);

    assert!(
        first_out.contains("\"alg\":\"ed25519\""),
        "trust fingerprint JSON must contain alg:ed25519: {first_out}"
    );
    assert!(
        first_out.contains("SHA256:"),
        "trust fingerprint JSON must contain SHA256: fingerprint: {first_out}"
    );
    assert!(
        first_out.contains("mxagent-ed25519:"),
        "trust fingerprint JSON must contain mxagent-ed25519: key_id: {first_out}"
    );

    // The signing key file must exist and be private (0600).
    let key_file = data_dir.join("signing_key.ed25519");
    assert!(
        key_file.exists(),
        "signing key file must be created by trust fingerprint"
    );
    let mode = std::fs::metadata(&key_file).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "signing key file must be private (0600)");

    // Second invocation must return the same fingerprint (key stability).
    let second = run_fp();
    assert!(
        second.status.success(),
        "second trust fingerprint must succeed: {second:?}"
    );
    let second_out = String::from_utf8_lossy(&second.stdout);

    let fp1 = extract_sha256_fingerprint(&first_out);
    let fp2 = extract_sha256_fingerprint(&second_out);
    assert_eq!(
        fp1, fp2,
        "trust fingerprint must be stable across invocations (same key on disk)"
    );

    let _ = std::fs::remove_dir_all(&data_dir);
}

/// Two concurrent `mx-agent trust fingerprint` invocations on the same data
/// directory must converge on one signing key — the advisory `flock` on
/// `.write.lock` must prevent a lost update between the two processes
/// (issue #269: cross-process key-creation race).
#[test]
fn concurrent_trust_fingerprint_converges_on_one_key() {
    let data_dir = unique_runtime_dir();

    // Spawn both CLI processes simultaneously before waiting for either.
    // Pipe stdout so wait_with_output() can collect it.
    let child_a = Command::new(BIN)
        .args(["trust", "fingerprint", "--json"])
        .env("MX_AGENT_DATA_DIR", &data_dir)
        .env("MX_AGENT_RUNTIME_DIR", &data_dir)
        .env("MX_AGENT_LOG", "off")
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("failed to spawn mx-agent trust fingerprint (a)");
    let child_b = Command::new(BIN)
        .args(["trust", "fingerprint", "--json"])
        .env("MX_AGENT_DATA_DIR", &data_dir)
        .env("MX_AGENT_RUNTIME_DIR", &data_dir)
        .env("MX_AGENT_LOG", "off")
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("failed to spawn mx-agent trust fingerprint (b)");

    let out_a = child_a
        .wait_with_output()
        .expect("failed to collect output from trust fingerprint (a)");
    let out_b = child_b
        .wait_with_output()
        .expect("failed to collect output from trust fingerprint (b)");

    assert!(
        out_a.status.success(),
        "trust fingerprint (a) must succeed: {out_a:?}"
    );
    assert!(
        out_b.status.success(),
        "trust fingerprint (b) must succeed: {out_b:?}"
    );

    let fp_a = extract_sha256_fingerprint(&String::from_utf8_lossy(&out_a.stdout));
    let fp_b = extract_sha256_fingerprint(&String::from_utf8_lossy(&out_b.stdout));
    assert_eq!(
        fp_a, fp_b,
        "concurrent trust fingerprint invocations must converge on one key \
         (advisory flock must prevent lost update — issue #269)"
    );

    // A third invocation after both complete must also return the same
    // fingerprint: the on-disk key was not corrupted.
    let steady = Command::new(BIN)
        .args(["trust", "fingerprint", "--json"])
        .env("MX_AGENT_DATA_DIR", &data_dir)
        .env("MX_AGENT_RUNTIME_DIR", &data_dir)
        .env("MX_AGENT_LOG", "off")
        .output()
        .expect("failed to run steady-state trust fingerprint");
    assert!(
        steady.status.success(),
        "steady-state fingerprint must succeed: {steady:?}"
    );
    let fp_steady = extract_sha256_fingerprint(&String::from_utf8_lossy(&steady.stdout));
    assert_eq!(
        fp_a, fp_steady,
        "steady-state fingerprint must match the converged key"
    );

    let _ = std::fs::remove_dir_all(&data_dir);
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
