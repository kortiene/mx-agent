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
//! Per architecture §13.4, the child environment is *allowlist-based*: the
//! child must not inherit the daemon's secrets, so it starts from nothing and
//! only the variables that are known to be safe are passed through. The runner
//! builds the child environment from the current process environment by keeping
//! only the built-in safe defaults ([`DEFAULT_ALLOWED_VARS`]) plus any names the
//! policy explicitly allows ([`RunSpec::env_allowlist`]), then layers the
//! request's explicit `env` overrides on top. As defence in depth, any inherited
//! variable matching a known token name (see [`is_secret_var`]) is scrubbed even
//! if it was allowlisted, so the allowlist can never reintroduce a credential.
//! This is the security boundary that keeps credentials such as
//! `MATRIX_ACCESS_TOKEN`, `GITHUB_TOKEN`, or any `AWS_*` variable out of
//! remotely-triggered commands.
//!
//! ## Process groups
//!
//! Where the platform supports it (Unix), the child is placed in its own
//! process group so that a later timeout or cancellation can signal the whole
//! group rather than just the immediate child (architecture §7.4). On other
//! platforms this is a no-op and the child runs in the daemon's group.
//!
//! ## Sandbox abstraction
//!
//! The command is launched through the [`mx_agent_sandbox`] abstraction
//! (architecture §13.5). The runner resolves the selected [`Backend`]
//! ([`RunSpec::sandbox`]) into a backend implementation and asks it to
//! [`prepare`][mx_agent_sandbox::Sandbox::prepare] the argv and the centralized
//! [`Restrictions`] (restricted cwd, sanitized env, timeout, output cap). The
//! baseline `none` backend returns the argv unchanged and leaves the runner to
//! enforce those controls; stronger backends rewrite the argv to launch inside
//! their wrapper. This keeps the control set in one place regardless of backend.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use mx_agent_sandbox::{
    preflight_backend, sandbox_for, sandbox_for_container, Backend, Network, Restrictions, Runtime,
    Sandbox,
};
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
    // mx-agent's own credential inputs: an operator must never be able to leak
    // these to a spawned child, even by explicitly allowlisting them. Both are
    // now also caught by `is_sensitive_key` (the `password`/`recovery` needles,
    // issue #376); the explicit entries are retained as a stable,
    // telemetry-independent guarantee that does not depend on needle-list tuning.
    "MX_AGENT_PASSWORD",
    "MX_AGENT_RECOVERY_KEY",
    "SSH_AUTH_SOCK",
    "GITHUB_TOKEN",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "NPM_TOKEN",
];

/// Known secret environment variable *prefixes*. Any variable whose name starts
/// with one of these is treated as a secret (e.g. `AWS_SECRET_ACCESS_KEY`).
const SECRET_PREFIXES: &[&str] = &["AWS_", "GOOGLE_", "AZURE_"];

/// Environment variables that are always safe to pass through to a child
/// process.
///
/// These carry no credentials yet are needed for most commands to behave
/// normally — locating binaries, the home and working directories, locale, and
/// the terminal. The child environment is allowlist-based (architecture §13.4):
/// any inherited variable *not* in this set, and not in the policy's explicit
/// [`RunSpec::env_allowlist`], is dropped so the child inherits a minimal, known
/// environment by default.
pub const DEFAULT_ALLOWED_VARS: &[&str] = &[
    "PATH", "HOME", "USER", "LOGNAME", "SHELL", "LANG", "LANGUAGE", "LC_ALL", "LC_CTYPE", "TZ",
    "TERM", "TMPDIR", "PWD",
];

/// Whether `name` names a known secret environment variable.
///
/// A name is considered secret if it matches one of [`SECRET_VARS`] exactly
/// (including mx-agent's own `MX_AGENT_PASSWORD` / `MX_AGENT_RECOVERY_KEY`),
/// begins with one of [`SECRET_PREFIXES`], or has a key that looks sensitive per
/// [`mx_agent_telemetry::is_sensitive_key`] (e.g. a future `MX_AGENT_*_TOKEN`,
/// `*_SECRET`, `*_RECOVERY_*`, or a name ending in `_KEY`). The `is_sensitive_key`
/// fallback is substring/case-insensitive (with a token-bounded bare-`key` rule),
/// so it can only ever *widen* what is scrubbed (fail-safe). This is the
/// predicate used to scrub the inherited environment before spawning a child.
pub fn is_secret_var(name: &str) -> bool {
    SECRET_VARS.contains(&name)
        || SECRET_PREFIXES.iter().any(|p| name.starts_with(p))
        || mx_agent_telemetry::is_sensitive_key(name)
}

/// Build the sanitized environment for a child process.
///
/// The child environment is *allowlist-based* (architecture §13.4). Starting
/// from `inherited` (typically the daemon's own environment), a variable is
/// passed through only when both:
///
/// 1. its name is in [`DEFAULT_ALLOWED_VARS`] or in `extra_allowed` (the
///    policy's explicit allowlist of further safe variables), and
/// 2. its name is *not* a known secret per [`is_secret_var`].
///
/// The secret check is applied even to allowlisted names as defence in depth, so
/// an operator who mistakenly allows a token variable still does not leak it.
/// Finally `overrides` are applied unconditionally: an explicitly-provided value
/// is honoured even if its name would otherwise be dropped, because the caller
/// has made a deliberate, per-request choice to pass it.
///
/// Kept as a pure function so the rules are unit-testable without spawning
/// anything.
pub fn sanitize_env<I>(
    inherited: I,
    overrides: &BTreeMap<String, String>,
    extra_allowed: &[String],
) -> BTreeMap<String, String>
where
    I: IntoIterator<Item = (String, String)>,
{
    let extra: BTreeSet<&str> = extra_allowed.iter().map(String::as_str).collect();
    let mut env: BTreeMap<String, String> = inherited
        .into_iter()
        .filter(|(name, _)| is_allowed_var(name, &extra) && !is_secret_var(name))
        .collect();
    for (name, value) in overrides {
        env.insert(name.clone(), value.clone());
    }
    env
}

/// Whether `name` is permitted to be inherited by a child process: it is one of
/// the built-in [`DEFAULT_ALLOWED_VARS`] or in the policy's `extra_allowed` set.
fn is_allowed_var(name: &str, extra_allowed: &BTreeSet<&str>) -> bool {
    DEFAULT_ALLOWED_VARS.contains(&name) || extra_allowed.contains(name)
}

/// Whether `name` controls the dynamic loader or binary resolution and must
/// never be set by a *remote* requester (issue #375).
///
/// These variables can redirect code execution outside the requested argv or
/// defeat sandbox path assumptions: the glibc loader (`LD_*`, e.g. `LD_PRELOAD`,
/// `LD_LIBRARY_PATH`, `LD_AUDIT`), the macOS dyld loader (`DYLD_*`, e.g.
/// `DYLD_INSERT_LIBRARIES`), and `PATH` (which changes which binary `argv[0]`
/// resolves to). Prefix matching on `LD_`/`DYLD_` is used so future loader knobs
/// are covered automatically (fail-safe: it can only widen what is denied).
pub fn is_loader_control_var(name: &str) -> bool {
    name == "PATH" || name.starts_with("LD_") || name.starts_with("DYLD_")
}

/// Screen caller-supplied `env` override **keys** from a *remote* (signed)
/// request against what policy permits, returning the first key that must not be
/// honored (or `None` when all keys are permitted) (issue #375).
///
/// Unlike [`sanitize_env`] — which applies overrides unconditionally so the
/// local operator's deliberate per-request `--env` choice always wins — a remote
/// override key is permitted only when ALL of the following hold:
///
/// 1. it is not a known secret ([`is_secret_var`]) — secrets are never
///    re-introducible, mirroring the inherited-env scrub;
/// 2. it is not a loader-control variable ([`is_loader_control_var`]) — these are
///    denied even if allowlisted, because a remote requester has no legitimate
///    need to replace the loader / `PATH` the daemon already provides; and
/// 3. its name is in the policy `extra_allowed` set (`execution.env_allowlist`)
///    OR a built-in safe default ([`DEFAULT_ALLOWED_VARS`]) — so benign
///    `TERM`/`LANG`/`TMPDIR`/operator-allowlisted overrides still work, but
///    anything unlisted is denied.
///
/// Deny-by-default: with an empty `extra_allowed`, only the (non-loader,
/// non-secret) built-in safe names may be overridden by a remote requester.
/// Keys are iterated in [`BTreeMap`] order, so the returned offending key is
/// stable across runs (it names the variable in the daemon log / rejection).
/// Local-operator overrides do not flow through here — only the remote assembly
/// sites call it.
pub fn first_disallowed_remote_override<'a>(
    env: &'a BTreeMap<String, String>,
    extra_allowed: &[String],
) -> Option<&'a str> {
    let extra: BTreeSet<&str> = extra_allowed.iter().map(String::as_str).collect();
    env.keys().map(String::as_str).find(|name| {
        is_secret_var(name)
            || is_loader_control_var(name)
            || !(DEFAULT_ALLOWED_VARS.contains(name) || extra.contains(name))
    })
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
    /// Additional environment variable names this execution may inherit from the
    /// daemon, on top of the built-in [`DEFAULT_ALLOWED_VARS`] safe set.
    ///
    /// Resolved from the policy's `execution.env_allowlist`
    /// ([`Allowance::env_allowlist`][mx_agent_policy::Allowance::env_allowlist]).
    /// Names matching a known secret are still scrubbed, so this can widen the
    /// inherited environment with safe variables but never reintroduce a token.
    pub env_allowlist: Vec<String>,
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
    /// Sandbox backend to launch the command under (architecture §13.5).
    ///
    /// The baseline [`Backend::None`] adds no isolation beyond the centralized
    /// cwd/env/timeout/output controls the runner already enforces. Resolved
    /// from policy (`execution.default_sandbox` / the agent override); defaults
    /// to [`Backend::None`].
    pub sandbox: Backend,
    /// Whether the command may reach the network (architecture §13.5).
    ///
    /// Only an isolating backend enforces this; the [`Backend::None`] backend
    /// ignores it. Resolved from the policy network decision and defaults to
    /// [`Network::Deny`] (fail closed) so an unset policy never widens access.
    pub network: Network,
    /// Filesystem paths an isolating backend binds read-only into the sandbox
    /// (architecture §13.5). Ignored by [`Backend::None`]. Resolved from the
    /// policy's `execution.read_only_paths`; defaults to empty.
    pub read_only_paths: Vec<PathBuf>,
    /// Filesystem paths an isolating backend binds writable into the sandbox
    /// (architecture §13.5). Ignored by [`Backend::None`]. Resolved from the
    /// policy's `execution.writable_paths`; defaults to empty.
    pub writable_paths: Vec<PathBuf>,
    /// Container runtime to launch through when [`sandbox`](RunSpec::sandbox) is
    /// [`Backend::Container`] (architecture §13.5). Derived from the policy
    /// `sandbox` value (`docker` → [`Runtime::Docker`], `podman` →
    /// [`Runtime::Podman`]); ignored by the other backends. Defaults to
    /// [`Runtime::Docker`].
    pub container_runtime: Runtime,
    /// Container image to run the command in when [`sandbox`](RunSpec::sandbox) is
    /// [`Backend::Container`]. Resolved from `execution.container_image`; `None`
    /// uses the backend's built-in default image. Ignored by the other backends.
    pub container_image: Option<String>,
    /// Post-authorization resource caps (process count, memory, CPU-seconds) the
    /// command runs under (architecture §13.5, issue #349). The container backend
    /// emits the matching `run` flags; the `none`/`bubblewrap` backends are wrapped
    /// in the [`launcher`][mx_agent_sandbox::launcher] trampoline by
    /// [`build_command`]. Resolved from policy; defaults to no caps.
    pub resources: mx_agent_sandbox::ResourceLimits,
    /// The seccomp-bpf syscall-filtering mode (issue #349). Resolved from policy;
    /// defaults to [`SeccompMode::Off`][mx_agent_sandbox::SeccompMode::Off].
    pub seccomp: mx_agent_sandbox::SeccompMode,
    /// The uid the [`Backend::Container`] backend runs the command as so it owns
    /// the host `writable_paths` mounts and `--cap-drop ALL` is viable (issue
    /// #349). Set by the assembly sites to the daemon's own uid for the container
    /// backend; `None` for the others.
    pub run_uid: Option<u32>,
    /// The gid paired with [`run_uid`](RunSpec::run_uid) for the container
    /// `--user <uid>:<gid>` mapping.
    pub run_gid: Option<u32>,
}

impl Default for RunSpec {
    fn default() -> Self {
        Self {
            command: Vec::new(),
            cwd: PathBuf::new(),
            env: BTreeMap::new(),
            env_allowlist: Vec::new(),
            stdin: None,
            timeout: None,
            grace_period: DEFAULT_GRACE_PERIOD,
            sandbox: Backend::None,
            network: Network::default(),
            read_only_paths: Vec::new(),
            writable_paths: Vec::new(),
            container_runtime: Runtime::Docker,
            container_image: None,
            resources: mx_agent_sandbox::ResourceLimits::default(),
            seccomp: mx_agent_sandbox::SeccompMode::Off,
            run_uid: None,
            run_gid: None,
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

/// Build the centralized [`Restrictions`] for a [`RunSpec`] and its already
/// sanitized environment.
///
/// This is the single place that maps a [`RunSpec`]'s sandbox-layer settings
/// (network decision and the read-only / writable bind paths) onto the
/// [`Restrictions`] every backend consumes, so an isolating backend confines
/// exactly what policy configured (architecture §13.5). Output capping is
/// enforced by the capture stage rather than the spawn, so `max_output_bytes`
/// is left `None` here.
///
/// Kept as a pure function so tests can assert the prepared argv for a given
/// spec — `sandbox_for(spec.sandbox).prepare(spec.command.clone(),
/// restrictions_for(spec, env))` — without spawning anything.
pub(crate) fn restrictions_for(spec: &RunSpec, env: BTreeMap<String, String>) -> Restrictions {
    Restrictions {
        cwd: spec.cwd.clone(),
        env,
        timeout: spec.timeout,
        // Output capping is enforced by the capture stage, not the spawn.
        max_output_bytes: None,
        network: spec.network,
        read_only_paths: spec.read_only_paths.clone(),
        writable_paths: spec.writable_paths.clone(),
        // The non-interactive runner path: the interactive PTY signal is set by
        // `PtySession::spawn` only (the container backend then allocates an
        // in-container TTY). Batch `exec`/`call` keep the non-interactive argv.
        interactive: false,
        // Confinement floor (issue #349): the container backend emits these as
        // `run` flags; for `none`/`bubblewrap` the launcher prefix added in
        // `build_command` enforces the resource caps. `run_uid`/`run_gid` are only
        // consumed by the container backend.
        resources: spec.resources,
        seccomp: spec.seccomp,
        run_uid: spec.run_uid,
        run_gid: spec.run_gid,
    }
}

/// Construct the sandbox backend for `spec`, threading the container runtime and
/// image for [`Backend::Container`] (issue #310).
///
/// The other backends ignore the container fields, so they resolve through
/// [`sandbox_for`]; the container backend resolves through
/// [`sandbox_for_container`] so `sandbox = "podman"` runs `podman run …` and a
/// policy-configured `execution.container_image` reaches the argv. Shared by the
/// batch runner ([`build_command`]) and the interactive PTY spawn so both honour
/// the configured runtime/image.
pub(crate) fn resolve_sandbox(spec: &RunSpec) -> Box<dyn Sandbox> {
    match spec.sandbox {
        Backend::Container => {
            sandbox_for_container(spec.container_runtime, spec.container_image.clone())
        }
        other => sandbox_for(other),
    }
}

/// Wrap the prepared argv in the self-re-exec [`launcher`][mx_agent_sandbox::launcher]
/// trampoline for the `none`/`bubblewrap` paths when a resource cap (or, on the
/// `none` path, seccomp) must be enforced (issue #349).
///
/// The container backend enforces caps with its own `run` flags, so it is never
/// wrapped (returned unchanged). When nothing needs enforcing the argv is also
/// returned unchanged, so existing specs spawn exactly as before. The launcher
/// runs the daemon's own binary ([`std::env::current_exe`], as `lifecycle.rs`
/// already does) as a hidden subcommand; a binary that cannot be resolved fails
/// with an actionable diagnostic rather than a bare error, mirroring
/// [`preflight_backend`].
///
/// On the bubblewrap path seccomp is **not** carried by the launcher: it would
/// filter `bwrap`'s own namespace-setup syscalls and break it (bwrap installs the
/// filter itself). The launcher only applies the resource caps there.
///
/// Shared with the interactive PTY spawn so resource caps confine interactive
/// sessions too.
pub(crate) fn launcher_wrap(
    spec: &RunSpec,
    prepared_argv: Vec<String>,
) -> Result<Vec<String>, RunError> {
    let is_none = match spec.sandbox {
        Backend::None => true,
        Backend::Bubblewrap => false,
        // The container backend enforces caps/seccomp via its own run flags.
        Backend::Container => return Ok(prepared_argv),
    };
    if !mx_agent_sandbox::LauncherArgs::is_needed(spec.resources, spec.seccomp, is_none) {
        return Ok(prepared_argv);
    }
    let launcher_exe = std::env::current_exe().map_err(|e| {
        RunError::Spawn(std::io::Error::new(
            e.kind(),
            format!("could not resolve the daemon binary to apply sandbox resource limits: {e}"),
        ))
    })?;
    let seccomp = if is_none {
        spec.seccomp
    } else {
        mx_agent_sandbox::SeccompMode::Off
    };
    let args = mx_agent_sandbox::LauncherArgs {
        resources: spec.resources,
        seccomp,
        command: prepared_argv,
    };
    let mut argv = vec![
        launcher_exe.to_string_lossy().into_owned(),
        mx_agent_sandbox::LAUNCHER_SUBCOMMAND.to_string(),
    ];
    argv.extend(args.to_args());
    Ok(argv)
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
pub(crate) fn build_command(spec: &RunSpec) -> Result<Command, RunError> {
    if spec.command.is_empty() {
        return Err(RunError::EmptyCommand);
    }

    if !is_existing_dir(&spec.cwd) {
        return Err(RunError::MissingCwd(spec.cwd.clone()));
    }

    // Fail with an actionable diagnostic if the selected backend's launcher is
    // missing, instead of a bare spawn `NotFound` once the wrapped argv runs
    // (issue #310). The baseline `None` backend has no launcher and always passes.
    preflight_backend(spec.sandbox, spec.container_runtime).map_err(|message| {
        RunError::Spawn(std::io::Error::new(std::io::ErrorKind::NotFound, message))
    })?;

    let env = sanitize_env(std::env::vars(), &spec.env, &spec.env_allowlist);

    // Launch through the selected sandbox backend (architecture §13.5). The
    // backend receives the requested argv and the centralized [`Restrictions`]
    // and returns the argv to actually spawn plus the controls to enforce. The
    // baseline `none` backend returns both unchanged; stronger backends rewrite
    // the argv to launch the command inside their wrapper.
    let restrictions = restrictions_for(spec, env);
    let prepared = resolve_sandbox(spec).prepare(spec.command.clone(), restrictions);
    // For the `none`/`bubblewrap` paths, wrap the prepared argv in the self-re-exec
    // launcher when a resource cap (or, on the `none` path, seccomp) must be
    // enforced — there is no runtime to do it for them and `pre_exec` is `unsafe`
    // (issue #349). The container backend enforces caps via its own `run` flags.
    let argv = launcher_wrap(spec, prepared.argv)?;
    let (program, args) = argv.split_first().ok_or(RunError::EmptyCommand)?;
    let Restrictions { cwd, env, .. } = prepared.restrictions;

    let stdin = if spec.stdin.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    };

    let mut command = Command::new(program);
    command
        .args(args)
        .current_dir(&cwd)
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
        // mx-agent's own credential inputs (issue #311).
        assert!(is_secret_var("MX_AGENT_PASSWORD"));
        assert!(is_secret_var("MX_AGENT_RECOVERY_KEY"));
        // `is_sensitive_key` fallback catches future names by shape.
        assert!(is_secret_var("MX_AGENT_SOMETHING_TOKEN"));
        assert!(is_secret_var("SOME_PASSWORD"));
        // Issue #376: widened needles now catch recovery/passphrase/bare-key shapes.
        assert!(is_secret_var("MY_RECOVERY_KEY"));
        assert!(is_secret_var("APP_PASSPHRASE"));
        assert!(is_secret_var("SIGNING_KEY"));
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
        let env = sanitize_env(inherited, &BTreeMap::new(), &[]);
        assert_eq!(env.get("PATH").map(String::as_str), Some("/usr/bin"));
        assert_eq!(env.get("HOME").map(String::as_str), Some("/home/me"));
        assert!(!env.contains_key("GITHUB_TOKEN"));
        assert!(!env.contains_key("AWS_SECRET_ACCESS_KEY"));
    }

    #[test]
    fn sanitize_env_is_allowlist_based_by_default() {
        // A perfectly innocuous variable is still dropped unless it is in the
        // built-in safe set or the policy allowlist: the child gets a minimal,
        // known environment rather than everything-minus-secrets.
        let inherited = vec![
            ("PATH".to_string(), "/usr/bin".to_string()),
            ("CARGO_HOME".to_string(), "/home/me/.cargo".to_string()),
            ("MY_RANDOM_VAR".to_string(), "value".to_string()),
        ];
        let env = sanitize_env(inherited, &BTreeMap::new(), &[]);
        assert!(env.contains_key("PATH"));
        assert!(!env.contains_key("CARGO_HOME"));
        assert!(!env.contains_key("MY_RANDOM_VAR"));
    }

    #[test]
    fn sanitize_env_passes_policy_allowed_vars() {
        // The policy can explicitly allow further safe variables through.
        let inherited = vec![
            ("PATH".to_string(), "/usr/bin".to_string()),
            ("CARGO_HOME".to_string(), "/home/me/.cargo".to_string()),
            ("RUSTUP_HOME".to_string(), "/home/me/.rustup".to_string()),
        ];
        let allow = vec!["CARGO_HOME".to_string(), "RUSTUP_HOME".to_string()];
        let env = sanitize_env(inherited, &BTreeMap::new(), &allow);
        assert_eq!(
            env.get("CARGO_HOME").map(String::as_str),
            Some("/home/me/.cargo")
        );
        assert_eq!(
            env.get("RUSTUP_HOME").map(String::as_str),
            Some("/home/me/.rustup")
        );
    }

    #[test]
    fn sanitize_env_scrubs_secret_even_when_allowlisted() {
        // Defence in depth: allowlisting a token name does not leak it. Only a
        // deliberate per-request override (next test) can pass such a value.
        let inherited = vec![("GITHUB_TOKEN".to_string(), "ghp_secret".to_string())];
        let allow = vec!["GITHUB_TOKEN".to_string()];
        let env = sanitize_env(inherited, &BTreeMap::new(), &allow);
        assert!(!env.contains_key("GITHUB_TOKEN"));
    }

    #[test]
    fn sanitize_env_drops_mx_agent_secrets_even_when_allowlisted() {
        // Issue #311: an operator who allowlists mx-agent's own credential inputs
        // must still not leak them to a spawned child.
        let inherited = vec![
            ("MX_AGENT_PASSWORD".to_string(), "hunter2".to_string()),
            (
                "MX_AGENT_RECOVERY_KEY".to_string(),
                "EsTL secret key".to_string(),
            ),
            ("PATH".to_string(), "/usr/bin".to_string()),
        ];
        let allow = vec![
            "MX_AGENT_PASSWORD".to_string(),
            "MX_AGENT_RECOVERY_KEY".to_string(),
        ];
        let env = sanitize_env(inherited, &BTreeMap::new(), &allow);
        assert!(
            !env.contains_key("MX_AGENT_PASSWORD"),
            "password must be dropped"
        );
        assert!(
            !env.contains_key("MX_AGENT_RECOVERY_KEY"),
            "recovery key must be dropped"
        );
        assert_eq!(env.get("PATH").map(String::as_str), Some("/usr/bin"));
    }

    #[test]
    fn sanitize_env_applies_overrides() {
        let inherited = vec![("PATH".to_string(), "/usr/bin".to_string())];
        let env = sanitize_env(
            inherited,
            &overrides(&[("MY_FLAG", "1"), ("PATH", "/custom")]),
            &[],
        );
        assert_eq!(env.get("MY_FLAG").map(String::as_str), Some("1"));
        assert_eq!(env.get("PATH").map(String::as_str), Some("/custom"));
    }

    #[test]
    fn sanitize_env_honours_explicit_secret_override() {
        // An override wins even over the denylist: the caller chose to pass it.
        let inherited: Vec<(String, String)> = vec![];
        let env = sanitize_env(inherited, &overrides(&[("GITHUB_TOKEN", "explicit")]), &[]);
        assert_eq!(
            env.get("GITHUB_TOKEN").map(String::as_str),
            Some("explicit")
        );
    }

    // --- remote override screen (issue #375) -------------------------------
    //
    // `first_disallowed_remote_override` gates the *remote* signed-request `env`
    // override keys. It does NOT touch `sanitize_env`, so the local escape hatch
    // (the two tests above) is unchanged.

    #[test]
    fn loader_control_vars_are_recognised() {
        for name in [
            "PATH",
            "LD_PRELOAD",
            "LD_LIBRARY_PATH",
            "LD_AUDIT",
            "DYLD_INSERT_LIBRARIES",
            "DYLD_LIBRARY_PATH",
        ] {
            assert!(is_loader_control_var(name), "{name} must be loader-control");
        }
        // Benign names that merely live near the loader knobs must not match.
        for name in ["CARGO_HOME", "TERM", "LANG", "HOME", "LANGUAGE", "PWD"] {
            assert!(
                !is_loader_control_var(name),
                "{name} must not be loader-control"
            );
        }
    }

    #[test]
    fn remote_override_screen_rejects_loader_secret_and_unlisted_keys() {
        // Each of these override maps must surface its sole offending key.
        for name in [
            "LD_PRELOAD",            // loader-control
            "DYLD_INSERT_LIBRARIES", // loader-control (macOS)
            "PATH",                  // loader-control even though a built-in default
            "GITHUB_TOKEN",          // secret
            "MY_UNLISTED_VAR",       // not allowlisted, not a default
        ] {
            let env = overrides(&[(name, "value")]);
            assert_eq!(
                first_disallowed_remote_override(&env, &[]),
                Some(name),
                "{name} must be rejected for a remote requester"
            );
        }
    }

    #[test]
    fn remote_override_screen_permits_safe_and_allowlisted_keys() {
        // Built-in safe names (non-loader) are overridable with no allowlist.
        assert_eq!(
            first_disallowed_remote_override(&overrides(&[("TERM", "xterm"), ("LANG", "C")]), &[]),
            None
        );
        // An empty override map trivially passes.
        assert_eq!(
            first_disallowed_remote_override(&BTreeMap::new(), &[]),
            None
        );
        // A name is overridable only once the operator allowlists it
        // (deny-by-default): rejected with an empty allowlist, permitted once
        // present.
        let cargo = overrides(&[("CARGO_HOME", "/home/me/.cargo")]);
        assert_eq!(
            first_disallowed_remote_override(&cargo, &[]),
            Some("CARGO_HOME")
        );
        assert_eq!(
            first_disallowed_remote_override(&cargo, &["CARGO_HOME".to_string()]),
            None
        );
    }

    #[test]
    fn remote_override_screen_loader_and_secret_beat_the_allowlist() {
        // Loader-control and secret names are denied even when the operator
        // explicitly allowlists them — the carve-out mirrors the inherited-env
        // secret scrub.
        let loader = overrides(&[("LD_PRELOAD", "/tmp/evil.so")]);
        assert_eq!(
            first_disallowed_remote_override(&loader, &["LD_PRELOAD".to_string()]),
            Some("LD_PRELOAD")
        );
        let secret = overrides(&[("GITHUB_TOKEN", "ghp_x")]);
        assert_eq!(
            first_disallowed_remote_override(&secret, &["GITHUB_TOKEN".to_string()]),
            Some("GITHUB_TOKEN")
        );
        // `PATH` is a built-in default yet still denied (loader-control carve-out).
        let path = overrides(&[("PATH", "/tmp/bin")]);
        assert_eq!(
            first_disallowed_remote_override(&path, &["PATH".to_string()]),
            Some("PATH")
        );
    }

    #[test]
    fn sanitize_env_local_path_still_passes_loader_control_vars() {
        // The local operator override path (sanitize_env) is intentionally
        // unrestricted: a deliberate per-request choice wins even for loader-control
        // names. Only the remote signed-request path runs first_disallowed_remote_override.
        // This test is the regression anchor: if sanitize_env ever starts calling
        // first_disallowed_remote_override, LD_PRELOAD would disappear from the
        // local operator's child env — which would be a regression.
        let env = sanitize_env(
            vec![("PATH".to_string(), "/usr/bin".to_string())],
            &overrides(&[("LD_PRELOAD", "/dev/null"), ("PATH", "/sbin")]),
            &[],
        );
        assert_eq!(
            env.get("LD_PRELOAD").map(String::as_str),
            Some("/dev/null"),
            "local override: LD_PRELOAD must still reach the child"
        );
        assert_eq!(
            env.get("PATH").map(String::as_str),
            Some("/sbin"),
            "local override: PATH must still reach the child"
        );
        // The same keys are denied on the remote path — the two paths diverge here.
        let remote = overrides(&[("LD_PRELOAD", "/dev/null"), ("PATH", "/sbin")]);
        assert_eq!(
            first_disallowed_remote_override(&remote, &[]),
            Some("LD_PRELOAD"),
            "remote path: LD_PRELOAD must be rejected"
        );
    }

    #[test]
    fn remote_override_screen_rejects_secret_prefix_vars() {
        // Secret-prefix variables (AWS_, GOOGLE_, AZURE_) are caught by is_secret_var
        // and must not be injected via a remote override, regardless of allowlist.
        for name in [
            "AWS_SECRET_ACCESS_KEY",
            "AWS_ACCESS_KEY_ID",
            "GOOGLE_APPLICATION_CREDENTIALS",
            "AZURE_CLIENT_SECRET",
        ] {
            let env = overrides(&[(name, "value")]);
            assert_eq!(
                first_disallowed_remote_override(&env, &[]),
                Some(name),
                "{name} (secret-prefix) must be rejected for a remote requester"
            );
            // allowlisting must not help either
            assert_eq!(
                first_disallowed_remote_override(&env, &[name.to_string()]),
                Some(name),
                "{name} must be rejected even when operator-allowlisted"
            );
        }
    }

    #[test]
    fn remote_override_screen_rejects_mx_agent_credentials() {
        // The daemon's own credential inputs (issue #311) are in SECRET_VARS and
        // must not be injected into a spawned child via a remote override.
        for name in ["MX_AGENT_PASSWORD", "MX_AGENT_RECOVERY_KEY"] {
            let env = overrides(&[(name, "value")]);
            assert_eq!(
                first_disallowed_remote_override(&env, &[]),
                Some(name),
                "{name} must be rejected for a remote requester"
            );
        }
    }

    #[test]
    fn remote_override_screen_rejects_sensitive_key_shape_vars() {
        // Variables caught only by `is_sensitive_key` (not in SECRET_VARS or
        // SECRET_PREFIXES) are also denied on the remote path — issue #375.
        // This exercises the third branch of `is_secret_var`: a future variable
        // whose name contains a sensitive needle ("secret", "api_key", "password",
        // "token", "private_key") is denied without needing an explicit registry
        // entry, making the denylist fail-safe against new credential shapes.
        for name in [
            "MY_DEPLOY_SECRET",  // contains "secret"
            "VENDOR_API_KEY",    // contains "api_key"
            "DATABASE_PASSWORD", // contains "password"
            "THIRD_PARTY_TOKEN", // contains "token"
            "APP_PRIVATE_KEY",   // contains "private_key"
        ] {
            let env = overrides(&[(name, "value")]);
            assert_eq!(
                first_disallowed_remote_override(&env, &[]),
                Some(name),
                "{name} (is_sensitive_key shape) must be rejected for a remote requester"
            );
            // Allowlisting must not help — secret-shaped keys are denied regardless.
            assert_eq!(
                first_disallowed_remote_override(&env, &[name.to_string()]),
                Some(name),
                "{name} must be rejected even when operator-allowlisted"
            );
        }
    }

    #[test]
    fn remote_override_screen_rejects_novel_loader_prefix_vars() {
        // The `LD_`/`DYLD_` denylist is prefix-based so future loader knobs are
        // covered automatically (fail-safe). Verify names that are real (but not
        // in the explicit test-name list) and hypothetical future knobs are all
        // caught by the prefix match, not an explicit registry entry.
        for name in [
            "LD_BIND_NOW",               // real glibc knob — lazy binding
            "LD_DEBUG",                  // real glibc knob — verbose linker trace
            "LD_SOMETHING_FUTURE",       // hypothetical future LD_ knob
            "DYLD_FORCE_FLAT_NAMESPACE", // real macOS dyld knob
            "DYLD_SOMETHING_FUTURE",     // hypothetical future DYLD_ knob
        ] {
            let env = overrides(&[(name, "value")]);
            assert_eq!(
                first_disallowed_remote_override(&env, &[]),
                Some(name),
                "{name} (novel LD_/DYLD_ prefix) must be rejected for a remote requester"
            );
            // Allowlisting must not help — loader-control beats the allowlist.
            assert_eq!(
                first_disallowed_remote_override(&env, &[name.to_string()]),
                Some(name),
                "{name} must be rejected even when operator-allowlisted"
            );
        }
    }

    #[test]
    fn remote_override_screen_mixed_map_returns_first_bad_key_in_sorted_order() {
        // When a map contains both permitted and denied keys, the predicate returns
        // the first denied key encountered in BTreeMap (alphabetical) order.
        //
        // Key order: "CARGO_HOME" (C) < "LANG" (L) < "LD_PRELOAD" (L-D)
        let env = overrides(&[
            ("CARGO_HOME", "/home/.cargo"),
            ("LANG", "en_US.UTF-8"),
            ("LD_PRELOAD", "/tmp/evil.so"),
        ]);
        // Without CARGO_HOME in the allowlist: CARGO_HOME is the first key
        // alphabetically, and it fails (not a default, not allowlisted).
        assert_eq!(
            first_disallowed_remote_override(&env, &[]),
            Some("CARGO_HOME"),
            "without allowlist CARGO_HOME is the first bad key"
        );
        // With CARGO_HOME allowlisted: CARGO_HOME passes, LANG passes (built-in
        // default), LD_PRELOAD fails (loader-control beats even the allowlist).
        assert_eq!(
            first_disallowed_remote_override(&env, &["CARGO_HOME".to_string()]),
            Some("LD_PRELOAD"),
            "with CARGO_HOME allowlisted, LD_PRELOAD is the first bad key"
        );
        // With LD_PRELOAD removed: all remaining keys are permitted.
        let safe = overrides(&[("CARGO_HOME", "/home/.cargo"), ("LANG", "en_US.UTF-8")]);
        assert_eq!(
            first_disallowed_remote_override(&safe, &["CARGO_HOME".to_string()]),
            None,
            "all permitted keys return None"
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
    async fn child_env_excludes_unlisted_vars() {
        // Acceptance: the child env is allowlist-based, so a non-secret var that
        // is neither a built-in default nor policy-allowed is not inherited.
        std::env::set_var("MX_AGENT_UNLISTED_VAR", "should_not_leak");
        let spec = RunSpec {
            command: vec!["env".to_string()],
            cwd: std::env::temp_dir(),
            env: BTreeMap::new(),
            stdin: None,
            ..RunSpec::default()
        };
        let out = run(&spec).await.expect("runs");
        let env_dump = String::from_utf8(out.stdout).unwrap();
        assert!(
            !env_dump.contains("MX_AGENT_UNLISTED_VAR"),
            "got: {env_dump}"
        );
        std::env::remove_var("MX_AGENT_UNLISTED_VAR");
    }

    #[tokio::test]
    async fn child_env_includes_policy_allowed_vars() {
        // Acceptance: policy can explicitly allow safe vars, which then reach
        // the child even though they are not built-in defaults.
        std::env::set_var("MX_AGENT_ALLOWED_VAR", "present");
        let spec = RunSpec {
            command: vec!["env".to_string()],
            cwd: std::env::temp_dir(),
            env: BTreeMap::new(),
            env_allowlist: vec!["MX_AGENT_ALLOWED_VAR".to_string()],
            stdin: None,
            ..RunSpec::default()
        };
        let out = run(&spec).await.expect("runs");
        let env_dump = String::from_utf8(out.stdout).unwrap();
        assert!(
            env_dump.contains("MX_AGENT_ALLOWED_VAR=present"),
            "got: {env_dump}"
        );
        std::env::remove_var("MX_AGENT_ALLOWED_VAR");
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
    async fn runs_under_none_sandbox_backend() {
        // Acceptance (#53): the process runner launches through the sandbox
        // abstraction. The baseline `none` backend adds no isolation, so the
        // command still runs normally in the requested cwd.
        let spec = RunSpec {
            command: vec!["true".to_string()],
            cwd: std::env::temp_dir(),
            sandbox: Backend::None,
            ..RunSpec::default()
        };
        let out = run(&spec).await.expect("runs");
        assert!(out.is_success());
    }

    // --- restrictions_for / sandbox wiring tests (issue #248) ----------------
    //
    // These tests verify the pure `restrictions_for` → `sandbox.prepare` wiring
    // without spawning anything: a `RunSpec` with network/path settings must
    // produce the expected argv for each backend.

    #[test]
    fn restrictions_for_threads_network_deny_and_paths_to_bubblewrap_argv() {
        // A bubblewrap spec with network=Deny and ro/rw paths must produce a
        // bwrap argv containing --unshare-net, --ro-bind, and --bind entries.
        let spec = RunSpec {
            command: vec!["echo".to_string(), "hi".to_string()],
            cwd: PathBuf::from("/work"),
            sandbox: Backend::Bubblewrap,
            network: Network::Deny,
            read_only_paths: vec![PathBuf::from("/usr"), PathBuf::from("/lib")],
            writable_paths: vec![PathBuf::from("/work")],
            ..RunSpec::default()
        };
        let restrictions = restrictions_for(&spec, BTreeMap::new());
        let prepared = sandbox_for(Backend::Bubblewrap).prepare(spec.command.clone(), restrictions);
        let argv = prepared.argv.join(" ");
        assert!(
            argv.contains("--ro-bind /usr /usr"),
            "expected --ro-bind /usr /usr in: {argv}"
        );
        assert!(
            argv.contains("--ro-bind /lib /lib"),
            "expected --ro-bind /lib /lib in: {argv}"
        );
        assert!(
            argv.contains("--bind /work /work"),
            "expected --bind /work /work in: {argv}"
        );
        assert!(
            argv.contains("--unshare-net"),
            "expected --unshare-net (network=Deny) in: {argv}"
        );
        assert!(
            argv.contains("--chdir /work"),
            "expected --chdir /work in: {argv}"
        );
    }

    #[test]
    fn restrictions_for_network_allow_omits_unshare_net_from_bubblewrap_argv() {
        // network=Allow must produce no --unshare-net flag so the sandbox keeps
        // the daemon's network access (architecture §13.5).
        let spec = RunSpec {
            command: vec!["true".to_string()],
            cwd: PathBuf::from("/work"),
            sandbox: Backend::Bubblewrap,
            network: Network::Allow,
            ..RunSpec::default()
        };
        let restrictions = restrictions_for(&spec, BTreeMap::new());
        let prepared = sandbox_for(Backend::Bubblewrap).prepare(spec.command.clone(), restrictions);
        let argv = prepared.argv.join(" ");
        assert!(
            !argv.contains("--unshare-net"),
            "expected no --unshare-net (network=Allow) in: {argv}"
        );
    }

    #[test]
    fn resolve_sandbox_threads_container_runtime_and_image() {
        // A container spec carrying the Podman runtime and a configured image
        // must resolve to a `podman run … <image>` launcher (issue #310).
        let spec = RunSpec {
            command: vec!["true".to_string()],
            cwd: std::env::temp_dir(),
            sandbox: Backend::Container,
            container_runtime: Runtime::Podman,
            container_image: Some("ghcr.io/acme/ci:1".to_string()),
            ..RunSpec::default()
        };
        let prepared =
            resolve_sandbox(&spec).prepare(spec.command.clone(), Restrictions::default());
        assert_eq!(prepared.argv.first().map(String::as_str), Some("podman"));
        assert!(
            prepared.argv.iter().any(|a| a == "ghcr.io/acme/ci:1"),
            "configured image must reach the argv: {:?}",
            prepared.argv
        );
    }

    #[test]
    fn resolve_sandbox_non_container_ignores_container_fields() {
        // Bubblewrap and None ignore the container runtime/image.
        for backend in [Backend::None, Backend::Bubblewrap] {
            let spec = RunSpec {
                command: vec!["true".to_string()],
                cwd: std::env::temp_dir(),
                sandbox: backend,
                container_runtime: Runtime::Podman,
                container_image: Some("unused:tag".to_string()),
                ..RunSpec::default()
            };
            let prepared =
                resolve_sandbox(&spec).prepare(spec.command.clone(), Restrictions::default());
            assert_eq!(prepared.backend, backend);
            assert!(!prepared.argv.iter().any(|a| a == "unused:tag"));
        }
    }

    #[test]
    fn restrictions_for_none_backend_ignores_paths_and_network() {
        // The `none` backend must not modify the argv regardless of network/path
        // settings — it adds no isolation and passes the argv through unchanged.
        let spec = RunSpec {
            command: vec!["echo".to_string(), "hi".to_string()],
            cwd: std::env::temp_dir(),
            sandbox: Backend::None,
            network: Network::Deny,
            read_only_paths: vec![PathBuf::from("/usr")],
            writable_paths: vec![PathBuf::from("/work")],
            ..RunSpec::default()
        };
        let restrictions = restrictions_for(&spec, BTreeMap::new());
        let prepared = sandbox_for(Backend::None).prepare(spec.command.clone(), restrictions);
        assert_eq!(
            prepared.argv,
            vec!["echo", "hi"],
            "none backend must not wrap the argv"
        );
    }

    #[test]
    fn restrictions_for_container_backend_deny_includes_network_none_and_volumes() {
        // Container backend + network=Deny must add --network none and volume
        // mounts for the configured paths (architecture §13.5).
        let spec = RunSpec {
            command: vec!["echo".to_string()],
            cwd: PathBuf::from("/work"),
            sandbox: Backend::Container,
            network: Network::Deny,
            read_only_paths: vec![PathBuf::from("/usr")],
            writable_paths: vec![PathBuf::from("/work")],
            ..RunSpec::default()
        };
        let restrictions = restrictions_for(&spec, BTreeMap::new());
        let prepared = sandbox_for(Backend::Container).prepare(spec.command.clone(), restrictions);
        let argv = prepared.argv.join(" ");
        assert!(
            argv.contains("--network none"),
            "expected --network none (deny) in: {argv}"
        );
        assert!(
            argv.contains("/usr:/usr:ro"),
            "expected ro volume for /usr in: {argv}"
        );
        assert!(
            argv.contains("/work:/work"),
            "expected rw volume for /work in: {argv}"
        );
    }

    #[test]
    fn restrictions_for_container_backend_allow_omits_network_none() {
        // Container backend + network=Allow must not add --network none.
        let spec = RunSpec {
            command: vec!["echo".to_string()],
            cwd: PathBuf::from("/work"),
            sandbox: Backend::Container,
            network: Network::Allow,
            ..RunSpec::default()
        };
        let restrictions = restrictions_for(&spec, BTreeMap::new());
        let prepared = sandbox_for(Backend::Container).prepare(spec.command.clone(), restrictions);
        let argv = prepared.argv.join(" ");
        assert!(
            !argv.contains("--network none"),
            "expected no --network none (allow) in: {argv}"
        );
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

    // --- interactive flag threading (issue #272) ------------------------------
    //
    // The non-interactive batch path (run / build_command) must never set
    // interactive=true on the Restrictions it builds. Only PtySession::spawn
    // is the interactive entry point; it sets the flag itself after calling
    // restrictions_for. If restrictions_for ever changed this invariant, the
    // container backend would emit -i/-t for all batch runs.

    // --- launcher prefix wiring (issue #349) ----------------------------------

    #[test]
    fn launcher_wrap_is_noop_without_caps_or_seccomp() {
        // A default spec (no caps, seccomp off) must spawn exactly the prepared
        // argv on every host backend — existing behaviour is unchanged.
        for sandbox in [Backend::None, Backend::Bubblewrap, Backend::Container] {
            let spec = RunSpec {
                command: vec!["echo".to_string(), "hi".to_string()],
                cwd: std::env::temp_dir(),
                sandbox,
                ..RunSpec::default()
            };
            let prepared = vec!["echo".to_string(), "hi".to_string()];
            let wrapped = launcher_wrap(&spec, prepared.clone()).expect("wrap");
            assert_eq!(wrapped, prepared, "backend {sandbox:?} must be unchanged");
        }
    }

    #[test]
    fn launcher_wrap_prepends_prefix_for_host_backends_with_caps() {
        // A resource cap on the `none`/`bubblewrap` path prepends the hidden
        // `__sandbox-exec` launcher; the container path is never wrapped (it uses
        // its own run flags).
        let resources = mx_agent_sandbox::ResourceLimits {
            max_processes: Some(256),
            ..Default::default()
        };
        for (sandbox, wraps) in [
            (Backend::None, true),
            (Backend::Bubblewrap, true),
            (Backend::Container, false),
        ] {
            let spec = RunSpec {
                command: vec!["echo".to_string()],
                cwd: std::env::temp_dir(),
                sandbox,
                resources,
                ..RunSpec::default()
            };
            let prepared = vec!["echo".to_string()];
            let wrapped = launcher_wrap(&spec, prepared.clone()).expect("wrap");
            if wraps {
                assert_eq!(
                    wrapped.get(1).map(String::as_str),
                    Some(mx_agent_sandbox::LAUNCHER_SUBCOMMAND),
                    "backend {sandbox:?} must prepend the launcher: {wrapped:?}"
                );
                assert!(
                    wrapped.windows(2).any(|w| w == ["--nproc", "256"]),
                    "launcher must carry the nproc cap: {wrapped:?}"
                );
                // The original command survives after the launcher's `--`.
                assert_eq!(wrapped.last().map(String::as_str), Some("echo"));
            } else {
                assert_eq!(wrapped, prepared, "container must not be wrapped");
            }
        }
    }

    #[test]
    fn launcher_wrap_drops_seccomp_on_bubblewrap_path() {
        // seccomp must NOT be carried by the launcher around bwrap (it would filter
        // bwrap's own setup). With seccomp on but no caps, the bwrap path is left
        // unwrapped; the `none` path is wrapped (carrying the seccomp flag).
        let spec_bwrap = RunSpec {
            command: vec!["echo".to_string()],
            cwd: std::env::temp_dir(),
            sandbox: Backend::Bubblewrap,
            seccomp: mx_agent_sandbox::SeccompMode::Default,
            ..RunSpec::default()
        };
        assert_eq!(
            launcher_wrap(&spec_bwrap, vec!["echo".to_string()]).unwrap(),
            vec!["echo".to_string()],
            "bwrap + seccomp-only must not be wrapped by the launcher"
        );

        let spec_none = RunSpec {
            sandbox: Backend::None,
            ..spec_bwrap.clone()
        };
        let wrapped = launcher_wrap(&spec_none, vec!["echo".to_string()]).unwrap();
        assert!(
            wrapped.windows(2).any(|w| w == ["--seccomp", "default"]),
            "none + seccomp must carry the seccomp flag: {wrapped:?}"
        );
    }

    #[test]
    fn restrictions_for_threads_resources_seccomp_and_uid() {
        // restrictions_for must copy the new confinement-floor fields onto the
        // Restrictions every backend consumes (issue #349).
        let spec = RunSpec {
            command: vec!["true".to_string()],
            cwd: std::env::temp_dir(),
            resources: mx_agent_sandbox::ResourceLimits {
                max_processes: Some(8),
                max_memory_bytes: Some(1024),
                max_cpu_seconds: Some(5),
            },
            seccomp: mx_agent_sandbox::SeccompMode::Default,
            run_uid: Some(1000),
            run_gid: Some(1000),
            ..RunSpec::default()
        };
        let r = restrictions_for(&spec, BTreeMap::new());
        assert_eq!(r.resources, spec.resources);
        assert_eq!(r.seccomp, mx_agent_sandbox::SeccompMode::Default);
        assert_eq!(r.run_uid, Some(1000));
        assert_eq!(r.run_gid, Some(1000));
    }

    #[test]
    fn restrictions_for_always_returns_interactive_false() {
        // Regression guard: restrictions_for must return interactive=false for
        // every backend on the non-interactive batch path.
        for sandbox in [Backend::None, Backend::Bubblewrap, Backend::Container] {
            let spec = RunSpec {
                command: vec!["true".to_string()],
                cwd: std::env::temp_dir(),
                sandbox,
                ..RunSpec::default()
            };
            let restrictions = restrictions_for(&spec, BTreeMap::new());
            assert!(
                !restrictions.interactive,
                "restrictions_for must return interactive=false for the batch path \
                 (backend: {sandbox:?})"
            );
        }
    }

    #[test]
    fn container_batch_argv_never_has_tty_flags_via_restrictions_for() {
        // Regression guard: the full prepared container argv produced via
        // restrictions_for (the non-interactive batch path) must contain no
        // -i/--interactive or -t/--tty flags. Only PtySession::spawn sets
        // interactive=true before calling prepare.
        let spec = RunSpec {
            command: vec!["echo".to_string()],
            cwd: PathBuf::from("/work"),
            sandbox: Backend::Container,
            network: Network::Deny,
            ..RunSpec::default()
        };
        let restrictions = restrictions_for(&spec, BTreeMap::new());
        let prepared = sandbox_for(Backend::Container).prepare(spec.command.clone(), restrictions);
        assert!(
            !prepared
                .argv
                .iter()
                .any(|a| a == "-i" || a == "--interactive"),
            "batch container argv must not contain -i/--interactive: {:?}",
            prepared.argv
        );
        assert!(
            !prepared.argv.iter().any(|a| a == "-t" || a == "--tty"),
            "batch container argv must not contain -t/--tty: {:?}",
            prepared.argv
        );
    }

    // --- resource-cap launcher flag coverage (issue #349) ----------------------

    #[test]
    fn launcher_wrap_carries_memory_and_cpu_cap_flags() {
        // max_memory_bytes produces --as and max_cpu_seconds produces --cpu in
        // the launcher argv. Combined with the existing nproc test this gives
        // complete coverage of all three cap flags.
        let spec_mem = RunSpec {
            command: vec!["echo".to_string()],
            cwd: std::env::temp_dir(),
            sandbox: Backend::None,
            resources: mx_agent_sandbox::ResourceLimits {
                max_memory_bytes: Some(1_073_741_824),
                ..Default::default()
            },
            ..RunSpec::default()
        };
        let wrapped = launcher_wrap(&spec_mem, vec!["echo".to_string()]).expect("wrap");
        assert!(
            wrapped.windows(2).any(|w| w == ["--as", "1073741824"]),
            "--as must appear in launcher argv for max_memory_bytes: {wrapped:?}"
        );

        let spec_cpu = RunSpec {
            command: vec!["echo".to_string()],
            cwd: std::env::temp_dir(),
            sandbox: Backend::None,
            resources: mx_agent_sandbox::ResourceLimits {
                max_cpu_seconds: Some(60),
                ..Default::default()
            },
            ..RunSpec::default()
        };
        let wrapped_cpu = launcher_wrap(&spec_cpu, vec!["echo".to_string()]).expect("wrap");
        assert!(
            wrapped_cpu.windows(2).any(|w| w == ["--cpu", "60"]),
            "--cpu must appear in launcher argv for max_cpu_seconds: {wrapped_cpu:?}"
        );
    }

    #[test]
    fn restrictions_for_run_gid_none_passes_through_as_none() {
        // When run_gid is absent from the RunSpec, restrictions_for must carry
        // None so the container backend's gid-fallback logic (`run_gid.unwrap_or(uid)`)
        // is evaluated there rather than being short-circuited here.
        let spec = RunSpec {
            command: vec!["true".to_string()],
            cwd: std::env::temp_dir(),
            run_uid: Some(500),
            run_gid: None,
            ..RunSpec::default()
        };
        let r = restrictions_for(&spec, BTreeMap::new());
        assert_eq!(r.run_uid, Some(500), "run_uid must thread through");
        assert_eq!(r.run_gid, None, "run_gid must pass through as None");
    }
}
