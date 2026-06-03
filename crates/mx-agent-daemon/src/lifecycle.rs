//! Daemon process lifecycle: start (foreground/background), status, and stop.
//!
//! State is tracked with a small JSON status file under the runtime directory
//! (see `docs/architecture.md`, section 10). The Unix socket itself is created
//! in a later phase; this module only records its intended path.

use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use serde::{Deserialize, Serialize};
use signal_hook::consts::{SIGINT, SIGTERM};
use signal_hook::iterator::Signals;

use crate::DaemonInfo;

/// Version reported by the daemon, taken from the crate version.
pub const DAEMON_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Environment variable overriding the runtime directory (useful for tests).
pub const ENV_RUNTIME_DIR: &str = "MX_AGENT_RUNTIME_DIR";

/// Resolved filesystem locations used by the daemon.
#[derive(Debug, Clone)]
pub struct Paths {
    /// Directory holding the daemon's runtime state.
    pub runtime_dir: PathBuf,
    /// JSON status file describing the running daemon.
    pub status_file: PathBuf,
    /// Intended Unix domain socket path.
    pub socket_path: PathBuf,
    /// Log file used when the daemon runs in the background.
    pub log_file: PathBuf,
}

impl Paths {
    /// Resolve runtime paths from the environment.
    ///
    /// Precedence: `MX_AGENT_RUNTIME_DIR`, then `$XDG_RUNTIME_DIR/mx-agent`,
    /// then a temp-directory fallback.
    pub fn resolve() -> Self {
        let runtime_dir = if let Ok(dir) = std::env::var(ENV_RUNTIME_DIR) {
            PathBuf::from(dir)
        } else if let Ok(xdg) = std::env::var("XDG_RUNTIME_DIR") {
            PathBuf::from(xdg).join("mx-agent")
        } else {
            std::env::temp_dir().join("mx-agent")
        };
        Self {
            status_file: runtime_dir.join("daemon.json"),
            socket_path: runtime_dir.join("daemon.sock"),
            log_file: runtime_dir.join("daemon.log"),
            runtime_dir,
        }
    }

    /// Ensure the runtime directory exists, creating it with `0700` permissions.
    ///
    /// An existing directory is left untouched so that unsafe permissions are
    /// surfaced (and refused) at socket-bind time rather than silently widened
    /// or narrowed.
    pub fn ensure_runtime_dir(&self) -> io::Result<()> {
        if !self.runtime_dir.exists() {
            fs::create_dir_all(&self.runtime_dir)?;
            fs::set_permissions(&self.runtime_dir, fs::Permissions::from_mode(0o700))?;
        }
        Ok(())
    }
}

/// Persisted contents of the daemon status file.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StatusFile {
    pid: u32,
    started_at_unix: u64,
    socket_path: String,
    version: String,
}

/// A snapshot of a running daemon, suitable for display.
#[derive(Debug, Clone, Serialize)]
pub struct RunningStatus {
    /// Always `true`; present so JSON output is self-describing.
    pub running: bool,
    /// Process ID of the daemon.
    pub pid: u32,
    /// Seconds elapsed since the daemon started.
    pub uptime_seconds: u64,
    /// Intended Unix socket path.
    pub socket_path: String,
    /// Daemon version.
    pub version: String,
}

impl RunningStatus {
    /// Render the status as a single-line JSON object.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{\"running\":true}".to_string())
    }
}

/// Outcome of a [`stop`] request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopOutcome {
    /// No daemon was running.
    NotRunning,
    /// The daemon exited after `SIGTERM`.
    Stopped(u32),
    /// The daemon had to be force-killed with `SIGKILL`.
    Killed(u32),
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Returns true if a process with `pid` currently exists.
fn is_alive(pid: u32) -> bool {
    // Ok means the process exists; EPERM means it exists but we may not signal
    // it; anything else (notably ESRCH) means it is gone.
    matches!(
        kill(Pid::from_raw(pid as i32), None),
        Ok(()) | Err(nix::errno::Errno::EPERM)
    )
}

fn read_status_file(paths: &Paths) -> io::Result<Option<StatusFile>> {
    match fs::read(&paths.status_file) {
        Ok(bytes) => match serde_json::from_slice::<StatusFile>(&bytes) {
            Ok(status) => Ok(Some(status)),
            Err(_) => Ok(None),
        },
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

fn write_status_file(paths: &Paths, status: &StatusFile) -> io::Result<()> {
    paths.ensure_runtime_dir()?;
    let tmp = paths.status_file.with_extension("json.tmp");
    let bytes = serde_json::to_vec_pretty(status)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    {
        let mut f = fs::File::create(&tmp)?;
        f.set_permissions(fs::Permissions::from_mode(0o600))?;
        f.write_all(&bytes)?;
        f.flush()?;
    }
    fs::rename(&tmp, &paths.status_file)?;
    Ok(())
}

fn remove_status_file(paths: &Paths) {
    let _ = fs::remove_file(&paths.status_file);
}

/// Return the status of the running daemon, if any.
///
/// A stale status file (referencing a dead process) is removed and treated as
/// "not running".
pub fn status() -> io::Result<Option<RunningStatus>> {
    let paths = Paths::resolve();
    let Some(sf) = read_status_file(&paths)? else {
        return Ok(None);
    };
    if !is_alive(sf.pid) {
        remove_status_file(&paths);
        return Ok(None);
    }
    let uptime = now_unix().saturating_sub(sf.started_at_unix);
    Ok(Some(RunningStatus {
        running: true,
        pid: sf.pid,
        uptime_seconds: uptime,
        socket_path: sf.socket_path,
        version: sf.version,
    }))
}

/// Run the daemon in the foreground until `SIGINT`/`SIGTERM`.
///
/// Writes the status file on startup and removes it on shutdown.
pub fn run_foreground() -> io::Result<()> {
    let paths = Paths::resolve();
    paths.ensure_runtime_dir()?;
    let mut signals = Signals::new([SIGINT, SIGTERM])?;

    // Bind the IPC socket before announcing readiness. The guard unlinks the
    // socket on shutdown. Binding validates that the runtime directory is
    // private to the current user.
    let _socket = mx_agent_ipc::bind(&paths.socket_path)?;

    let pid = std::process::id();
    let status = StatusFile {
        pid,
        started_at_unix: now_unix(),
        socket_path: paths.socket_path.to_string_lossy().into_owned(),
        version: DAEMON_VERSION.to_string(),
    };
    write_status_file(&paths, &status)?;

    DaemonInfo::new().log_summary();
    tracing::info!(pid, socket = %status.socket_path, "daemon started (foreground)");

    if let Some(signal) = signals.forever().next() {
        tracing::info!(signal, "received shutdown signal");
    }

    remove_status_file(&paths);
    tracing::info!(pid, "daemon stopped");
    Ok(())
}

/// Spawn the daemon as a detached background process and wait for it to report
/// readiness via the status file.
pub fn start_background() -> io::Result<RunningStatus> {
    let paths = Paths::resolve();
    paths.ensure_runtime_dir()?;

    // Fail fast (before spawning) if the runtime directory is unsafe.
    mx_agent_ipc::ensure_safe_parent_dir(&paths.runtime_dir)?;

    let exe = std::env::current_exe()?;
    let log = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&paths.log_file)?;
    let log_err = log.try_clone()?;

    Command::new(exe)
        .args(["daemon", "start", "--foreground"])
        .stdin(Stdio::null())
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(log_err))
        .spawn()?;

    // Poll for the child to write its status file.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(running) = status()? {
            return Ok(running);
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "daemon did not become ready within timeout",
            ));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Stop the running daemon: `SIGTERM`, then `SIGKILL` after `grace`.
pub fn stop(grace: Duration) -> io::Result<StopOutcome> {
    let paths = Paths::resolve();
    let Some(sf) = read_status_file(&paths)? else {
        return Ok(StopOutcome::NotRunning);
    };
    let pid = sf.pid;
    if !is_alive(pid) {
        remove_status_file(&paths);
        return Ok(StopOutcome::NotRunning);
    }

    let target = Pid::from_raw(pid as i32);
    let _ = kill(target, Signal::SIGTERM);

    let deadline = Instant::now() + grace;
    while Instant::now() < deadline {
        if !is_alive(pid) {
            remove_status_file(&paths);
            return Ok(StopOutcome::Stopped(pid));
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    let _ = kill(target, Signal::SIGKILL);
    std::thread::sleep(Duration::from_millis(100));
    remove_status_file(&paths);
    Ok(StopOutcome::Killed(pid))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::{Mutex, MutexGuard, OnceLock};

    fn env_lock() -> MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    struct TempRuntime {
        dir: PathBuf,
        _guard: MutexGuard<'static, ()>,
    }

    impl TempRuntime {
        fn new(tag: &str) -> Self {
            let guard = env_lock();
            let dir = std::env::temp_dir().join(format!(
                "mx-agent-test-{}-{}-{}",
                tag,
                std::process::id(),
                now_unix()
            ));
            std::env::set_var(ENV_RUNTIME_DIR, &dir);
            Self { dir, _guard: guard }
        }
    }

    impl Drop for TempRuntime {
        fn drop(&mut self) {
            std::env::remove_var(ENV_RUNTIME_DIR);
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    #[test]
    fn status_is_none_when_no_status_file() {
        let _rt = TempRuntime::new("none");
        assert!(status().unwrap().is_none());
    }

    #[test]
    fn stale_status_file_is_cleaned_up() {
        let _rt = TempRuntime::new("stale");
        let paths = Paths::resolve();
        // PID 0x7FFFFFFE is extremely unlikely to be alive.
        let sf = StatusFile {
            pid: 0x7FFF_FFFE,
            started_at_unix: now_unix(),
            socket_path: paths.socket_path.to_string_lossy().into_owned(),
            version: DAEMON_VERSION.to_string(),
        };
        write_status_file(&paths, &sf).unwrap();
        assert!(paths.status_file.exists());
        assert!(status().unwrap().is_none());
        assert!(!paths.status_file.exists(), "stale file should be removed");
    }

    #[test]
    fn status_reports_self_as_running() {
        let _rt = TempRuntime::new("selfpid");
        let paths = Paths::resolve();
        let sf = StatusFile {
            pid: std::process::id(),
            started_at_unix: now_unix().saturating_sub(2),
            socket_path: paths.socket_path.to_string_lossy().into_owned(),
            version: DAEMON_VERSION.to_string(),
        };
        write_status_file(&paths, &sf).unwrap();
        let running = status().unwrap().expect("should be running");
        assert_eq!(running.pid, std::process::id());
        assert!(running.uptime_seconds >= 2);
        assert_eq!(running.version, DAEMON_VERSION);
        assert!(running.to_json().contains("\"running\":true"));
    }

    #[test]
    fn stop_when_not_running_is_idempotent() {
        let _rt = TempRuntime::new("stop");
        assert_eq!(
            stop(Duration::from_millis(200)).unwrap(),
            StopOutcome::NotRunning
        );
    }
}
