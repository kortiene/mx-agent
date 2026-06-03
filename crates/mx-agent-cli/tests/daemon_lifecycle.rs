//! End-to-end lifecycle test driving the real `mx-agent` binary.

use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_mx-agent");

fn unique_runtime_dir() -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("mx-agent-it-{}-{}", std::process::id(), nanos))
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
