//! Process runner for non-interactive `exec` commands (architecture §7.7, §13).
//!
//! Once an [`ExecRequest`][crate::exec] has been authorized, the daemon needs
//! to actually run the requested command. This module is that runner: it spawns
//! a child process with [`tokio::process`], runs it in the requested working
//! directory, hands it a *sanitized* environment, captures its output, and
//! reports the exit status.
//!
//! The runner deliberately implements only the *non-interactive* path: it
//! launches a command, waits for it to finish, and collects everything it wrote
//! to stdout/stderr. Streaming, PTY allocation, and stdin forwarding are
//! handled elsewhere.
//!
//! ## Environment scrubbing
//!
//! Per architecture §13.4, the child must not inherit the daemon's secrets. The
//! runner builds the child environment from the current process environment
//! with all known secret variables removed (see [`is_secret_var`]), then layers
//! the request's explicit `env` overrides on top. This is the security boundary
//! that keeps credentials such as `MATRIX_ACCESS_TOKEN`, `GITHUB_TOKEN`, or any
//! `AWS_*` variable out of remotely-triggered commands.
//!
//! ## Process groups
//!
//! Where the platform supports it (Unix), the child is placed in its own
//! process group so that a later timeout or cancellation can signal the whole
//! group rather than just the immediate child (architecture §7.4). On other
//! platforms this is a no-op and the child runs in the daemon's group.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use tokio::process::Command;

/// Default grace period between the SIGTERM and the SIGKILL escalation when a
/// command exceeds its timeout (architecture §7.4: "wait grace period, e.g. 5
/// seconds").
pub const DEFAULT_GRACE_PERIOD: Duration = Duration::from_secs(5);

/// Known secret environment variable names that must never be passed to a
/// child process unless explicitly provided as an override.
///
/// Mirrors the denylist in architecture §13.4.
const SECRET_VARS: &[&str] = &[
    "MATRIX_ACCESS_TOKEN",
    "MX_AGENT_TOKEN",
    "SSH_AUTH_SOCK",
    "GITHUB_TOKEN",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "NPM_TOKEN",
];

/// Known secret environment variable *prefixes*. Any variable whose name starts
/// with one of these is treated as a secret (e.g. `AWS_SECRET_ACCESS_KEY`).
const SECRET_PREFIXES: &[&str] = &["AWS_", "GOOGLE_", "AZURE_"];

/// Whether `name` names a known secret environment variable.
///
/// A name is considered secret if it matches one of [`SECRET_VARS`] exactly or
/// begins with one of [`SECRET_PREFIXES`]. This is the predicate used to scrub
/// the inherited environment before spawning a child.
pub fn is_secret_var(name: &str) -> bool {
    SECRET_VARS.contains(&name) || SECRET_PREFIXES.iter().any(|p| name.starts_with(p))
}

/// Build the sanitized environment for a child process.
///
/// Starts from `inherited` (typically the daemon's own environment), drops every
/// variable for which [`is_secret_var`] returns true, then applies `overrides`
/// on top. Overrides are applied unconditionally: an explicitly-provided value
/// is honoured even if its name would otherwise be scrubbed, because the caller
/// has made a deliberate choice to pass it.
///
/// Kept as a pure function so the scrubbing rules are unit-testable without
/// spawning anything.
pub fn sanitize_env<I>(
    inherited: I,
    overrides: &BTreeMap<String, String>,
) -> BTreeMap<String, String>
where
    I: IntoIterator<Item = (String, String)>,
{
    let mut env: BTreeMap<String, String> = inherited
        .into_iter()
        .filter(|(name, _)| !is_secret_var(name))
        .collect();
    for (name, value) in overrides {
        env.insert(name.clone(), value.clone());
    }
    env
}

/// What to run and how (the non-protocol view of an authorized exec request).
///
/// This is intentionally small: the runner only needs the argv, the working
/// directory, and any explicit environment overrides. Protocol bookkeeping
/// (invocation ids, signatures, timeouts) lives with the request itself.
#[derive(Debug, Clone)]
pub struct RunSpec {
    /// Command argv: program followed by its arguments.
    pub command: Vec<String>,
    /// Working directory the command must run in (an allowed cwd).
    pub cwd: PathBuf,
    /// Explicit environment overrides layered on top of the sanitized env.
    pub env: BTreeMap<String, String>,
    /// Bytes to feed to the child's standard input, if any.
    ///
    /// `None` runs the command with stdin connected to `/dev/null` (the
    /// non-interactive default). `Some(bytes)` writes `bytes` to the child's
    /// stdin and then closes it, propagating end-of-file exactly once
    /// (architecture §7.7). An empty `Some(Vec::new())` still opens and closes
    /// the pipe, so the child observes an immediate EOF.
    pub stdin: Option<Vec<u8>>,
    /// Maximum wall-clock runtime for the command.
    ///
    /// `None` runs the command with no enforced limit. `Some(dur)` enforces a
    /// max runtime (architecture §7.4): once `dur` elapses the runner signals
    /// the child's process group and reports the result with
    /// [`RunOutput::timed_out`] set.
    pub timeout: Option<Duration>,
    /// Grace period to wait after SIGTERM before escalating to SIGKILL when a
    /// timed-out command is being terminated. Defaults to
    /// [`DEFAULT_GRACE_PERIOD`].
    pub grace_period: Duration,
}

impl Default for RunSpec {
    fn default() -> Self {
        Self {
            command: Vec::new(),
            cwd: PathBuf::new(),
            env: BTreeMap::new(),
            stdin: None,
            timeout: None,
            grace_period: DEFAULT_GRACE_PERIOD,
        }
    }
}

/// The captured result of a finished, non-interactive command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunOutput {
    /// The process exit code, or `None` if it was terminated by a signal.
    pub exit_code: Option<i32>,
    /// The terminating signal number on Unix, if the process was signalled.
    pub signal: Option<i32>,
    /// Everything the process wrote to stdout.
    pub stdout: Vec<u8>,
    /// Everything the process wrote to stderr.
    pub stderr: Vec<u8>,
    /// Whether the command was terminated because it exceeded its timeout.
    ///
    /// When `true` the runner enforced [`RunSpec::timeout`] by signalling the
    /// child's process group; `exit_code`/`signal` then reflect how the child
    /// (or its group) actually died.
    pub timed_out: bool,
}

impl RunOutput {
    /// Whether the process exited successfully (exit code 0).
    pub fn is_success(&self) -> bool {
        self.exit_code == Some(0)
    }
}

/// Why a command could not be run.
#[derive(Debug)]
pub enum RunError {
    /// The spec carried an empty argv, so there is no program to run.
    EmptyCommand,
    /// The requested working directory does not exist or is not a directory.
    MissingCwd(PathBuf),
    /// The child process could not be spawned or its output collected.
    Spawn(std::io::Error),
}

impl std::fmt::Display for RunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyCommand => write!(f, "command argv is empty"),
            Self::MissingCwd(path) => {
                write!(f, "working directory {path:?} does not exist")
            }
            Self::Spawn(err) => write!(f, "could not run command: {err}"),
        }
    }
}

impl std::error::Error for RunError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Spawn(err) => Some(err),
            _ => None,
        }
    }
}

/// Build a configured [`Command`] from a [`RunSpec`].
///
/// Validates the argv and cwd, applies the sanitized environment, sets the
/// working directory, and (on Unix) places the child in its own process group.
/// Stdout and stderr are piped so they can be captured. Stdin is piped when the
/// spec carries input bytes (so they can be written and the pipe closed),
/// otherwise it is connected to `/dev/null` for the non-interactive path.
///
/// Kept separate from [`run`] so the command construction is testable without
/// actually waiting on a child.
fn build_command(spec: &RunSpec) -> Result<Command, RunError> {
    let (program, args) = spec.command.split_first().ok_or(RunError::EmptyCommand)?;

    if !is_existing_dir(&spec.cwd) {
        return Err(RunError::MissingCwd(spec.cwd.clone()));
    }

    let env = sanitize_env(std::env::vars(), &spec.env);

    let stdin = if spec.stdin.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    };

    let mut command = Command::new(program);
    command
        .args(args)
        .current_dir(&spec.cwd)
        .env_clear()
        .envs(env)
        .stdin(stdin)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // Reap the child if the runner is dropped before it finishes.
        .kill_on_drop(true);

    // Track the process group where supported so a later timeout/cancel can
    // signal the whole group (architecture §7.4). `0` asks for a new group
    // whose id equals the child's pid.
    #[cfg(unix)]
    command.process_group(0);

    Ok(command)
}

/// Whether `path` exists and is a directory.
fn is_existing_dir(path: &Path) -> bool {
    std::fs::metadata(path).map(|m| m.is_dir()).unwrap_or(false)
}

/// Run a non-interactive command to completion and capture its output.
///
/// Spawns the command described by `spec` with [`tokio::process`], runs it in
/// the requested working directory with a sanitized environment, waits for it
/// to exit, and returns the captured stdout/stderr plus the exit status.
///
/// Returns a [`RunError`] only when the command could not be *run* (empty argv,
/// missing cwd, or a spawn failure); a command that runs and exits nonzero is a
/// successful [`RunOutput`] with a nonzero `exit_code`.
pub async fn run(spec: &RunSpec) -> Result<RunOutput, RunError> {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let mut command = build_command(spec)?;
    let mut child = command.spawn().map_err(RunError::Spawn)?;
    // Capture the pid up front: once the child exits we still want it to signal
    // the (now possibly-orphaned) process group, and after `wait` the handle no
    // longer reports an id.
    let pid = child.id();

    // Feed piped stdin (if any) to the child, then drop the handle so the child
    // sees end-of-file exactly once. The handle is moved out of the child and
    // explicitly dropped here, before we wait, so even an empty input still
    // closes the pipe and unblocks a reader like `cat`.
    if let Some(input) = &spec.stdin {
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(input).await.map_err(RunError::Spawn)?;
            stdin.flush().await.map_err(RunError::Spawn)?;
            drop(stdin);
        }
    }

    // Drain stdout/stderr concurrently with the wait so the child never blocks
    // on a full pipe (which would otherwise deadlock against our timeout).
    let stdout_pipe = child.stdout.take();
    let stderr_pipe = child.stderr.take();
    let stdout_task = tokio::spawn(async move {
        let mut buf = Vec::new();
        if let Some(mut pipe) = stdout_pipe {
            let _ = pipe.read_to_end(&mut buf).await;
        }
        buf
    });
    let stderr_task = tokio::spawn(async move {
        let mut buf = Vec::new();
        if let Some(mut pipe) = stderr_pipe {
            let _ = pipe.read_to_end(&mut buf).await;
        }
        buf
    });

    // Wait for the child, enforcing the max runtime if one was requested. On
    // timeout we terminate the whole process group (SIGTERM, then SIGKILL after
    // the grace period) so no descendant is left orphaned.
    let mut timed_out = false;
    let status = match spec.timeout {
        Some(limit) => match tokio::time::timeout(limit, child.wait()).await {
            Ok(result) => result.map_err(RunError::Spawn)?,
            Err(_elapsed) => {
                timed_out = true;
                signal_process_group(pid, TermSignal::Term);
                match tokio::time::timeout(spec.grace_period, child.wait()).await {
                    Ok(result) => result.map_err(RunError::Spawn)?,
                    Err(_elapsed) => {
                        signal_process_group(pid, TermSignal::Kill);
                        child.wait().await.map_err(RunError::Spawn)?
                    }
                }
            }
        },
        None => child.wait().await.map_err(RunError::Spawn)?,
    };

    // The reader tasks complete once the pipes hit EOF, which happens when the
    // child (and anything holding its stdout/stderr) is gone.
    let stdout = stdout_task.await.unwrap_or_default();
    let stderr = stderr_task.await.unwrap_or_default();

    #[cfg(unix)]
    let signal = {
        use std::os::unix::process::ExitStatusExt as _;
        status.signal()
    };
    #[cfg(not(unix))]
    let signal = None;

    Ok(RunOutput {
        exit_code: status.code(),
        signal,
        stdout,
        stderr,
        timed_out,
    })
}

/// Which terminating signal to deliver to a process group.
#[derive(Debug, Clone, Copy)]
enum TermSignal {
    /// Polite request to terminate (SIGTERM).
    Term,
    /// Forceful, uncatchable kill (SIGKILL).
    Kill,
}

/// Signal the entire process group led by `pid`.
///
/// The child is placed in its own process group (see [`build_command`]), whose
/// id equals the child's pid. Signalling the group (rather than just the child)
/// ensures grandchildren spawned by the command are torn down too, so nothing
/// is left orphaned after a timeout (architecture §7.4). On platforms without
/// process groups this is a best-effort no-op.
#[cfg(unix)]
fn signal_process_group(pid: Option<u32>, signal: TermSignal) {
    use nix::sys::signal::{killpg, Signal};
    use nix::unistd::Pid;

    let Some(pid) = pid else { return };
    let signal = match signal {
        TermSignal::Term => Signal::SIGTERM,
        TermSignal::Kill => Signal::SIGKILL,
    };
    // ESRCH (group already gone) and other errors are ignored: the goal is
    // best-effort teardown, and a vanished group needs no further signalling.
    let _ = killpg(Pid::from_raw(pid as i32), signal);
}

#[cfg(not(unix))]
fn signal_process_group(_pid: Option<u32>, _signal: TermSignal) {}

/// The signal a cancellation delivers to a running command's process group.
///
/// Reported as `signal_sent` in the emitted `com.mxagent.exec.cancelled.v1`
/// (see [`crate::exec::emit_exec_cancelled`]).
pub const CANCEL_SIGNAL: &str = "SIGTERM";

/// Terminate the process group led by `pid` when cancelling a running command
/// (architecture §7.5).
///
/// Sends [`SIGTERM`][CANCEL_SIGNAL] to the whole process group — whose id equals
/// the command's pid (see [`build_command`]) — so the command and every
/// descendant it spawned are torn down together, leaving nothing orphaned. A
/// caller that must guarantee teardown of a process ignoring `SIGTERM` can
/// escalate with [`kill_process_group`] after a grace period, mirroring the
/// timeout path in [`run`]. On platforms without process groups this is a
/// best-effort no-op.
pub fn terminate_process_group(pid: u32) {
    signal_process_group(Some(pid), TermSignal::Term);
}

/// Forcefully kill the process group led by `pid` with `SIGKILL`.
///
/// The uncatchable escalation after [`terminate_process_group`] for a command
/// that ignores `SIGTERM`. Like its sibling, it signals the whole group so no
/// descendant is left orphaned, and is a best-effort no-op on platforms without
/// process groups.
pub fn kill_process_group(pid: u32) {
    signal_process_group(Some(pid), TermSignal::Kill);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn overrides(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn secret_vars_are_recognised() {
        assert!(is_secret_var("MATRIX_ACCESS_TOKEN"));
        assert!(is_secret_var("GITHUB_TOKEN"));
        assert!(is_secret_var("OPENAI_API_KEY"));
        assert!(is_secret_var("AWS_SECRET_ACCESS_KEY"));
        assert!(is_secret_var("GOOGLE_APPLICATION_CREDENTIALS"));
        assert!(is_secret_var("AZURE_CLIENT_SECRET"));
    }

    #[test]
    fn non_secret_vars_are_kept() {
        assert!(!is_secret_var("PATH"));
        assert!(!is_secret_var("HOME"));
        assert!(!is_secret_var("LANG"));
        assert!(!is_secret_var("CARGO_HOME"));
    }

    #[test]
    fn sanitize_env_drops_secrets() {
        let inherited = vec![
            ("PATH".to_string(), "/usr/bin".to_string()),
            ("GITHUB_TOKEN".to_string(), "ghp_secret".to_string()),
            ("AWS_SECRET_ACCESS_KEY".to_string(), "aws".to_string()),
            ("HOME".to_string(), "/home/me".to_string()),
        ];
        let env = sanitize_env(inherited, &BTreeMap::new());
        assert_eq!(env.get("PATH").map(String::as_str), Some("/usr/bin"));
        assert_eq!(env.get("HOME").map(String::as_str), Some("/home/me"));
        assert!(!env.contains_key("GITHUB_TOKEN"));
        assert!(!env.contains_key("AWS_SECRET_ACCESS_KEY"));
    }

    #[test]
    fn sanitize_env_applies_overrides() {
        let inherited = vec![("PATH".to_string(), "/usr/bin".to_string())];
        let env = sanitize_env(
            inherited,
            &overrides(&[("MY_FLAG", "1"), ("PATH", "/custom")]),
        );
        assert_eq!(env.get("MY_FLAG").map(String::as_str), Some("1"));
        assert_eq!(env.get("PATH").map(String::as_str), Some("/custom"));
    }

    #[test]
    fn sanitize_env_honours_explicit_secret_override() {
        // An override wins even over the denylist: the caller chose to pass it.
        let inherited: Vec<(String, String)> = vec![];
        let env = sanitize_env(inherited, &overrides(&[("GITHUB_TOKEN", "explicit")]));
        assert_eq!(
            env.get("GITHUB_TOKEN").map(String::as_str),
            Some("explicit")
        );
    }

    #[test]
    fn build_command_rejects_empty_argv() {
        let spec = RunSpec {
            command: vec![],
            cwd: std::env::temp_dir(),
            env: BTreeMap::new(),
            stdin: None,
            ..RunSpec::default()
        };
        assert!(matches!(build_command(&spec), Err(RunError::EmptyCommand)));
    }

    #[test]
    fn build_command_rejects_missing_cwd() {
        let spec = RunSpec {
            command: vec!["true".to_string()],
            cwd: PathBuf::from("/this/path/should/not/exist/mx-agent"),
            env: BTreeMap::new(),
            stdin: None,
            ..RunSpec::default()
        };
        assert!(matches!(build_command(&spec), Err(RunError::MissingCwd(_))));
    }

    #[tokio::test]
    async fn runs_command_and_captures_exit_status() {
        let spec = RunSpec {
            command: vec!["true".to_string()],
            cwd: std::env::temp_dir(),
            env: BTreeMap::new(),
            stdin: None,
            ..RunSpec::default()
        };
        let out = run(&spec).await.expect("runs");
        assert_eq!(out.exit_code, Some(0));
        assert!(out.is_success());

        let spec = RunSpec {
            command: vec!["false".to_string()],
            cwd: std::env::temp_dir(),
            env: BTreeMap::new(),
            stdin: None,
            ..RunSpec::default()
        };
        let out = run(&spec).await.expect("runs");
        assert_eq!(out.exit_code, Some(1));
        assert!(!out.is_success());
    }

    #[tokio::test]
    async fn runs_command_in_requested_cwd() {
        // Acceptance: command runs in the requested allowed cwd.
        let dir = std::env::temp_dir();
        let spec = RunSpec {
            command: vec!["pwd".to_string()],
            cwd: dir.clone(),
            env: BTreeMap::new(),
            stdin: None,
            ..RunSpec::default()
        };
        let out = run(&spec).await.expect("runs");
        let printed = String::from_utf8(out.stdout).unwrap();
        let printed = printed.trim_end();
        // Resolve symlinks (e.g. macOS /tmp -> /private/tmp) before comparing.
        let expected = std::fs::canonicalize(&dir).unwrap();
        let actual = std::fs::canonicalize(printed).unwrap();
        assert_eq!(actual, expected);
    }

    #[tokio::test]
    async fn child_env_excludes_known_secrets() {
        // Acceptance: child env excludes known secret variables.
        std::env::set_var("GITHUB_TOKEN", "ghp_should_not_leak");
        std::env::set_var("AWS_SECRET_ACCESS_KEY", "should_not_leak");
        let spec = RunSpec {
            command: vec!["env".to_string()],
            cwd: std::env::temp_dir(),
            env: BTreeMap::new(),
            stdin: None,
            ..RunSpec::default()
        };
        let out = run(&spec).await.expect("runs");
        let env_dump = String::from_utf8(out.stdout).unwrap();
        assert!(!env_dump.contains("GITHUB_TOKEN"), "got: {env_dump}");
        assert!(
            !env_dump.contains("AWS_SECRET_ACCESS_KEY"),
            "got: {env_dump}"
        );
        std::env::remove_var("GITHUB_TOKEN");
        std::env::remove_var("AWS_SECRET_ACCESS_KEY");
    }

    #[tokio::test]
    async fn child_env_includes_overrides() {
        let spec = RunSpec {
            command: vec!["env".to_string()],
            cwd: std::env::temp_dir(),
            env: overrides(&[("MX_AGENT_RUN_MARKER", "present")]),
            stdin: None,
            ..RunSpec::default()
        };
        let out = run(&spec).await.expect("runs");
        let env_dump = String::from_utf8(out.stdout).unwrap();
        assert!(
            env_dump.contains("MX_AGENT_RUN_MARKER=present"),
            "got: {env_dump}"
        );
    }

    #[tokio::test]
    async fn piped_stdin_is_forwarded_to_child() {
        // Acceptance: `echo hi | ... -- cat` returns `hi`. The bytes written to
        // the child's stdin must come back out of `cat` unchanged.
        let spec = RunSpec {
            command: vec!["cat".to_string()],
            cwd: std::env::temp_dir(),
            env: BTreeMap::new(),
            stdin: Some(b"hi\n".to_vec()),
            ..RunSpec::default()
        };
        let out = run(&spec).await.expect("runs");
        assert_eq!(out.exit_code, Some(0));
        assert_eq!(out.stdout, b"hi\n");
    }

    #[tokio::test]
    async fn empty_piped_stdin_closes_with_eof() {
        // An empty input still opens and closes the pipe, so a reader like
        // `cat` observes an immediate EOF and exits cleanly with no output.
        let spec = RunSpec {
            command: vec!["cat".to_string()],
            cwd: std::env::temp_dir(),
            env: BTreeMap::new(),
            stdin: Some(Vec::new()),
            ..RunSpec::default()
        };
        let out = run(&spec).await.expect("runs");
        assert_eq!(out.exit_code, Some(0));
        assert!(out.stdout.is_empty());
    }

    #[tokio::test]
    async fn timed_out_command_is_terminated() {
        // Acceptance: timed-out commands are terminated. `sleep 60` cannot
        // finish within the 100ms limit, so it must be signalled and reported
        // as timed out rather than running to completion.
        let spec = RunSpec {
            command: vec!["sleep".to_string(), "60".to_string()],
            cwd: std::env::temp_dir(),
            timeout: Some(Duration::from_millis(100)),
            grace_period: Duration::from_millis(100),
            ..RunSpec::default()
        };
        let start = std::time::Instant::now();
        let out = run(&spec).await.expect("runs");
        assert!(out.timed_out, "command should be marked timed out");
        // It must not have run anywhere near the full 60s.
        assert!(start.elapsed() < Duration::from_secs(5));
        // Terminated by a signal, so there is no clean exit code.
        assert!(out.exit_code.is_none());
        #[cfg(unix)]
        assert!(out.signal.is_some(), "expected a terminating signal");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn timeout_kills_whole_process_group() {
        // Acceptance: child process groups do not remain orphaned. The command
        // spawns a long-lived grandchild and prints its pid, then sleeps. On
        // timeout the whole group must be signalled, so the grandchild dies
        // too rather than being left orphaned.
        let spec = RunSpec {
            command: vec![
                "sh".to_string(),
                "-c".to_string(),
                "sleep 60 & echo $! ; wait".to_string(),
            ],
            cwd: std::env::temp_dir(),
            timeout: Some(Duration::from_millis(200)),
            grace_period: Duration::from_millis(100),
            ..RunSpec::default()
        };
        let out = run(&spec).await.expect("runs");
        assert!(out.timed_out);
        let printed = String::from_utf8(out.stdout).unwrap();
        let grandchild: i32 = printed.trim().parse().expect("grandchild pid");

        // Give the kernel a moment to reap the signalled group.
        tokio::time::sleep(Duration::from_millis(300)).await;

        use nix::sys::signal::kill;
        use nix::unistd::Pid;
        // ESRCH means the process is gone; anything else means it survived.
        let alive = matches!(
            kill(Pid::from_raw(grandchild), None),
            Ok(()) | Err(nix::errno::Errno::EPERM)
        );
        assert!(!alive, "grandchild {grandchild} was left orphaned");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn terminate_process_group_tears_down_running_command() {
        // Acceptance (#48): cancelling a running command terminates it. The
        // command spawns a long-lived grandchild and prints its pid, then
        // sleeps. Signalling the whole group must tear the grandchild down too
        // rather than leave it orphaned.
        let mut child = build_command(&RunSpec {
            command: vec![
                "sh".to_string(),
                "-c".to_string(),
                "sleep 60 & echo $! ; wait".to_string(),
            ],
            cwd: std::env::temp_dir(),
            ..RunSpec::default()
        })
        .expect("builds")
        .spawn()
        .expect("spawns");

        // The child leads its own process group (id == its pid).
        let pid = child.id().expect("running child has a pid");

        // Read the grandchild pid the command prints before it blocks on sleep.
        use tokio::io::AsyncReadExt as _;
        let mut stdout = child.stdout.take().expect("piped stdout");
        let mut buf = Vec::new();
        // The first line carries the grandchild pid; reading to EOF would block
        // until the group dies, so read just enough to see the newline.
        loop {
            let mut byte = [0u8; 1];
            if stdout.read(&mut byte).await.unwrap_or(0) == 0 || byte[0] == b'\n' {
                break;
            }
            buf.push(byte[0]);
        }
        let grandchild: i32 = String::from_utf8(buf)
            .unwrap()
            .trim()
            .parse()
            .expect("grandchild pid");

        // Cancel: signal the whole group.
        terminate_process_group(pid);
        let _ = child.wait().await;

        // Give the kernel a moment to reap the signalled group.
        tokio::time::sleep(Duration::from_millis(300)).await;

        use nix::sys::signal::kill;
        use nix::unistd::Pid;
        // ESRCH means the process is gone; anything else means it survived.
        let alive = matches!(
            kill(Pid::from_raw(grandchild), None),
            Ok(()) | Err(nix::errno::Errno::EPERM)
        );
        assert!(
            !alive,
            "grandchild {grandchild} was left orphaned after cancel"
        );
    }

    #[tokio::test]
    async fn command_within_timeout_is_not_marked_timed_out() {
        let spec = RunSpec {
            command: vec!["true".to_string()],
            cwd: std::env::temp_dir(),
            timeout: Some(Duration::from_secs(30)),
            ..RunSpec::default()
        };
        let out = run(&spec).await.expect("runs");
        assert!(!out.timed_out);
        assert_eq!(out.exit_code, Some(0));
    }

    #[tokio::test]
    async fn null_stdin_yields_immediate_eof() {
        // The non-interactive default (no stdin) connects /dev/null, so a
        // reader sees EOF right away rather than blocking.
        let spec = RunSpec {
            command: vec!["cat".to_string()],
            cwd: std::env::temp_dir(),
            env: BTreeMap::new(),
            stdin: None,
            ..RunSpec::default()
        };
        let out = run(&spec).await.expect("runs");
        assert_eq!(out.exit_code, Some(0));
        assert!(out.stdout.is_empty());
    }
}
