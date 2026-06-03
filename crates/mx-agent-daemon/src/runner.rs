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

use tokio::process::Command;

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
/// Stdout and stderr are piped so they can be captured; stdin is null because
/// this is the non-interactive path.
///
/// Kept separate from [`run`] so the command construction is testable without
/// actually waiting on a child.
fn build_command(spec: &RunSpec) -> Result<Command, RunError> {
    let (program, args) = spec.command.split_first().ok_or(RunError::EmptyCommand)?;

    if !is_existing_dir(&spec.cwd) {
        return Err(RunError::MissingCwd(spec.cwd.clone()));
    }

    let env = sanitize_env(std::env::vars(), &spec.env);

    let mut command = Command::new(program);
    command
        .args(args)
        .current_dir(&spec.cwd)
        .env_clear()
        .envs(env)
        .stdin(Stdio::null())
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
    let mut command = build_command(spec)?;
    let output = command.output().await.map_err(RunError::Spawn)?;

    #[cfg(unix)]
    let signal = {
        use std::os::unix::process::ExitStatusExt as _;
        output.status.signal()
    };
    #[cfg(not(unix))]
    let signal = None;

    Ok(RunOutput {
        exit_code: output.status.code(),
        signal,
        stdout: output.stdout,
        stderr: output.stderr,
    })
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
        };
        assert!(matches!(build_command(&spec), Err(RunError::EmptyCommand)));
    }

    #[test]
    fn build_command_rejects_missing_cwd() {
        let spec = RunSpec {
            command: vec!["true".to_string()],
            cwd: PathBuf::from("/this/path/should/not/exist/mx-agent"),
            env: BTreeMap::new(),
        };
        assert!(matches!(build_command(&spec), Err(RunError::MissingCwd(_))));
    }

    #[tokio::test]
    async fn runs_command_and_captures_exit_status() {
        let spec = RunSpec {
            command: vec!["true".to_string()],
            cwd: std::env::temp_dir(),
            env: BTreeMap::new(),
        };
        let out = run(&spec).await.expect("runs");
        assert_eq!(out.exit_code, Some(0));
        assert!(out.is_success());

        let spec = RunSpec {
            command: vec!["false".to_string()],
            cwd: std::env::temp_dir(),
            env: BTreeMap::new(),
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
        };
        let out = run(&spec).await.expect("runs");
        let env_dump = String::from_utf8(out.stdout).unwrap();
        assert!(
            env_dump.contains("MX_AGENT_RUN_MARKER=present"),
            "got: {env_dump}"
        );
    }
}
