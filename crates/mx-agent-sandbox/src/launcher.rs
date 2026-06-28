//! Self-re-exec launcher trampoline for the `none`/`bubblewrap` paths (issue
//! #349).
//!
//! The host execution paths (`none` and `bubblewrap`) have no container runtime
//! to enforce resource caps for them, and the workspace `forbid`s `unsafe`, so
//! the textbook [`pre_exec`](std::os::unix::process::CommandExt::pre_exec) hook
//! (an `unsafe fn`) is unavailable. This module works around that with safe APIs
//! only: the runner re-execs the daemon's own binary as a hidden
//! [`LAUNCHER_SUBCOMMAND`] trampoline, the trampoline applies the caps to *itself*
//! with the safe [`nix::sys::resource::setrlimit`], and then replaces its image
//! with the target command via the safe
//! [`exec`](std::os::unix::process::CommandExt::exec) (only `pre_exec` is
//! `unsafe`). The applied rlimits are inherited across the `exec`, so the target
//! command — and, on the bubblewrap path, the `bwrap` process and the command it
//! ultimately launches — run under them.
//!
//! The trampoline inherits the already-sanitized environment the runner set with
//! `env_clear().envs(...)`, and passes it through `exec` unchanged: it reads no
//! `std::env`, adds no variables, and so leaves the §13.4 secret scrubbing
//! untouched. It confers no privilege — it only ever *narrows* — so it does not
//! need to authenticate its caller.
//!
//! ## Seccomp
//!
//! On the `none` path the launcher installs the curated default-deny BPF profile
//! (see [`crate::seccomp`]) in-process when [`SeccompMode::Default`] is requested:
//! after `setrlimit` and immediately before `exec`, it compiles the allowlist and
//! applies it with the safe `seccompiler::apply_filter` (issue #380). seccomp
//! filters survive `execve`, so the target command — and anything it spawns — runs
//! syscall-filtered. The install is **fail-closed**: if the program cannot be
//! built or applied, the launcher returns an error and does *not* `exec` the
//! command unfiltered, mirroring the fail-closed `setrlimit` handling.
//!
//! The launcher deliberately does **not** carry seccomp on the bubblewrap path:
//! `bwrap` installs the filter itself via `--seccomp <fd>` (wired by the runner)
//! *after* its own namespace setup, so the launcher filtering `bwrap`'s
//! `unshare`/`mount`/`pivot_root` calls would break the sandbox. The container
//! backend installs the equivalent OCI profile with `--security-opt seccomp=`.
//!
//! seccomp does not exist on macOS; there the launcher's seccomp step is a
//! documented no-op (and `bwrap`/containers do not run there anyway).

use crate::{ResourceLimits, SeccompMode};

/// Hidden CLI subcommand name the daemon re-execs itself as to become the
/// launcher trampoline (e.g. `mx-agent __sandbox-exec --nproc 256 -- <argv>`).
///
/// Hidden from `--help`: it is an internal re-exec trampoline, not part of the
/// stable user surface.
pub const LAUNCHER_SUBCOMMAND: &str = "__sandbox-exec";

/// Flag carrying the `RLIMIT_NPROC` cap to the launcher.
const FLAG_NPROC: &str = "--nproc";
/// Flag carrying the `RLIMIT_AS` (address-space, bytes) cap to the launcher.
const FLAG_AS: &str = "--as";
/// Flag carrying the `RLIMIT_CPU` (CPU-seconds) cap to the launcher.
const FLAG_CPU: &str = "--cpu";
/// Flag carrying the seccomp mode to the launcher.
const FLAG_SECCOMP: &str = "--seccomp";

/// The parsed arguments of a [`LAUNCHER_SUBCOMMAND`] invocation: the resource
/// caps and seccomp mode to apply, plus the target command to `exec`.
///
/// Built by the runner from a request's resolved [`ResourceLimits`]/[`SeccompMode`]
/// and serialized with [`to_args`](LauncherArgs::to_args); parsed back with
/// [`parse`](LauncherArgs::parse). The (flags → struct) round-trip is pure and
/// unit-tested.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LauncherArgs {
    /// Resource caps to apply with `setrlimit` before `exec`.
    pub resources: ResourceLimits,
    /// Seccomp mode to apply (see the module note on the deferred installation).
    pub seccomp: SeccompMode,
    /// The target argv to replace this process image with (program + arguments).
    pub command: Vec<String>,
}

impl LauncherArgs {
    /// Whether wrapping a command in the launcher would actually do anything for
    /// the given `backend` — i.e. whether the runner should prepend the prefix.
    ///
    /// A resource cap is enforced on every host path; seccomp only engages the
    /// launcher on the `none` path, where the filter is installed in-process by
    /// [`run_launcher`]. On the bubblewrap path seccomp is handled **out of band**:
    /// the runner injects `bwrap --seccomp <fd>` (see
    /// [`bubblewrap_with_seccomp_fd`][crate::bubblewrap_with_seccomp_fd]) so `bwrap`
    /// installs the filter itself after its own namespace setup — the launcher must
    /// not, or it would filter `bwrap`'s `unshare`/`mount`/`pivot_root` calls. So
    /// the bwrap path only needs the launcher for *resource caps*, never for
    /// seccomp.
    pub fn is_needed(
        resources: ResourceLimits,
        seccomp: SeccompMode,
        is_none_backend: bool,
    ) -> bool {
        !resources.is_unset() || (is_none_backend && seccomp.is_on())
    }

    /// Serialize the caps/seccomp/command into the argv that follows
    /// [`LAUNCHER_SUBCOMMAND`]: `[<flags>, "--", <command>...]`.
    ///
    /// The runner prepends `[<launcher-exe>, LAUNCHER_SUBCOMMAND]` to this. The
    /// `--` separates the launcher's own flags from the target command (which may
    /// itself contain `--`, e.g. `bwrap … -- cmd`); [`parse`](Self::parse) splits
    /// on the *first* `--` only, so a nested separator is preserved verbatim.
    pub fn to_args(&self) -> Vec<String> {
        let mut args = Vec::new();
        if let Some(n) = self.resources.max_processes {
            args.push(FLAG_NPROC.to_string());
            args.push(n.to_string());
        }
        if let Some(bytes) = self.resources.max_memory_bytes {
            args.push(FLAG_AS.to_string());
            args.push(bytes.to_string());
        }
        if let Some(secs) = self.resources.max_cpu_seconds {
            args.push(FLAG_CPU.to_string());
            args.push(secs.to_string());
        }
        if self.seccomp.is_on() {
            args.push(FLAG_SECCOMP.to_string());
            args.push(self.seccomp.name().to_string());
        }
        args.push("--".to_string());
        args.extend(self.command.iter().cloned());
        args
    }

    /// Parse the argv that follows [`LAUNCHER_SUBCOMMAND`] back into a
    /// [`LauncherArgs`], the inverse of [`to_args`](Self::to_args).
    ///
    /// Everything after the first `--` is the target command, taken verbatim.
    /// Returns a human-readable error for a malformed flag or a missing command.
    pub fn parse(args: &[String]) -> Result<Self, String> {
        let mut resources = ResourceLimits::default();
        let mut seccomp = SeccompMode::Off;
        let mut iter = args.iter();
        let mut command: Option<Vec<String>> = None;
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--" => {
                    command = Some(iter.map(|s| s.to_string()).collect());
                    break;
                }
                FLAG_NPROC => resources.max_processes = Some(parse_u64(FLAG_NPROC, iter.next())?),
                FLAG_AS => resources.max_memory_bytes = Some(parse_u64(FLAG_AS, iter.next())?),
                FLAG_CPU => resources.max_cpu_seconds = Some(parse_u64(FLAG_CPU, iter.next())?),
                FLAG_SECCOMP => {
                    seccomp = match iter.next().map(String::as_str) {
                        Some("off") => SeccompMode::Off,
                        Some("default") => SeccompMode::Default,
                        other => {
                            return Err(format!(
                                "{FLAG_SECCOMP} expects \"off\" or \"default\", got {other:?}"
                            ))
                        }
                    };
                }
                other => return Err(format!("unknown launcher flag {other:?}")),
            }
        }
        let command =
            command.ok_or_else(|| "missing `--` before the launcher command".to_string())?;
        if command.is_empty() {
            return Err("launcher command argv is empty".to_string());
        }
        Ok(Self {
            resources,
            seccomp,
            command,
        })
    }
}

/// Parse a non-negative `u64` flag value, naming the flag on error.
fn parse_u64(flag: &str, value: Option<&String>) -> Result<u64, String> {
    let value = value.ok_or_else(|| format!("{flag} expects a value"))?;
    value
        .parse::<u64>()
        .map_err(|_| format!("{flag} expects a non-negative integer, got {value:?}"))
}

/// Apply the resource caps and the seccomp filter, then `exec` the target
/// command, replacing this process image.
///
/// Returns only on failure (a successful `exec` never returns): the returned
/// [`std::io::Error`] describes why the caps or filter could not be applied or the
/// command could not be executed, so the caller can surface a diagnostic and exit
/// non-zero. Both are applied **fail-closed**: if a `setrlimit` or the seccomp
/// install fails, the command is *not* run rather than running unconfined.
///
/// On Linux, when [`SeccompMode::Default`] is requested, the curated default-deny
/// BPF profile (see [`crate::seccomp`]) is installed in-process here — after the
/// resource caps and immediately before `exec` — with the safe
/// `seccompiler::apply_filter`; the allowlist includes `execve`/`execveat` so
/// the subsequent `exec` and the target's own startup succeed, and the filter
/// survives `execve` so the target runs syscall-filtered. On macOS seccomp does
/// not exist, so the step is a logged no-op.
///
/// All work uses safe APIs: [`nix::sys::resource::setrlimit`],
/// `seccompiler::apply_filter` (the `unsafe` syscall lives inside that crate),
/// and [`std::os::unix::process::CommandExt::exec`] (only `pre_exec` is `unsafe`).
pub fn run_launcher(args: LauncherArgs) -> std::io::Error {
    if let Err(e) = apply_resource_limits(args.resources) {
        return e;
    }

    if args.seccomp.is_on() {
        if let Err(e) = apply_seccomp_filter() {
            return e;
        }
    }

    let (program, rest) = match args.command.split_first() {
        Some(split) => split,
        None => {
            return std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "launcher command argv is empty",
            )
        }
    };
    exec_command(program, rest)
}

/// Replace the current process image with `program rest…`.
#[cfg(unix)]
fn exec_command(program: &str, rest: &[String]) -> std::io::Error {
    use std::os::unix::process::CommandExt as _;
    // `exec` only returns on failure; the returned error is the spawn failure.
    std::process::Command::new(program).args(rest).exec()
}

#[cfg(not(unix))]
fn exec_command(_program: &str, _rest: &[String]) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "the sandbox launcher is only supported on Unix",
    )
}

/// Apply each configured resource cap with `setrlimit`, lowering both the soft
/// and hard limits to the cap value. Returns the first failure (fail-closed).
#[cfg(unix)]
fn apply_resource_limits(resources: ResourceLimits) -> Result<(), std::io::Error> {
    use nix::sys::resource::{setrlimit, Resource};

    let to_io = |e: nix::errno::Errno| std::io::Error::from_raw_os_error(e as i32);

    if let Some(n) = resources.max_processes {
        // RLIMIT_NPROC is counted per real uid; under bubblewrap's user namespace
        // the cap is imprecise (a best-effort fork-bomb dampener). The container
        // backend's `--pids-limit` is the exact control. nix exposes
        // `RLIMIT_NPROC` on Linux (the primary sandbox target); on other Unix
        // (e.g. macOS) it is skipped — documented as a platform limitation, since
        // bubblewrap/containers do not run there anyway.
        #[cfg(target_os = "linux")]
        setrlimit(Resource::RLIMIT_NPROC, n, n).map_err(to_io)?;
        #[cfg(not(target_os = "linux"))]
        let _ = n;
    }
    if let Some(bytes) = resources.max_memory_bytes {
        setrlimit(Resource::RLIMIT_AS, bytes, bytes).map_err(to_io)?;
    }
    if let Some(secs) = resources.max_cpu_seconds {
        setrlimit(Resource::RLIMIT_CPU, secs, secs).map_err(to_io)?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn apply_resource_limits(_resources: ResourceLimits) -> Result<(), std::io::Error> {
    Ok(())
}

/// Install the curated default-deny seccomp filter in-process (the `none` path),
/// fail-closed.
///
/// On Linux this compiles [`crate::seccomp::default_bpf_program`] and applies it
/// with the safe [`seccompiler::apply_filter`]. It runs after the resource caps
/// and immediately before `exec`; the filter survives `execve`, so the target
/// command runs syscall-filtered. A build or apply failure is returned (the caller
/// then refuses to `exec`) rather than silently leaving the command unfiltered.
///
/// On non-Linux targets seccomp does not exist, so this is a logged no-op.
#[cfg(target_os = "linux")]
fn apply_seccomp_filter() -> Result<(), std::io::Error> {
    let program = crate::seccomp::default_bpf_program().map_err(|e| {
        std::io::Error::other(format!(
            "could not build the seccomp filter before exec: {e}"
        ))
    })?;
    seccompiler::apply_filter(&program).map_err(|e| {
        std::io::Error::other(format!(
            "could not install the seccomp filter before exec: {e}"
        ))
    })?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn apply_seccomp_filter() -> Result<(), std::io::Error> {
    tracing::debug!(
        "seccomp = \"default\" was requested but seccomp is unavailable on this platform; \
         the command runs without a syscall filter"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn to_args_and_parse_round_trip() {
        let original = LauncherArgs {
            resources: ResourceLimits {
                max_processes: Some(256),
                max_memory_bytes: Some(2_147_483_648),
                max_cpu_seconds: Some(120),
            },
            seccomp: SeccompMode::Default,
            command: argv(&["bwrap", "--unshare-net", "--", "echo", "hi"]),
        };
        let parsed = LauncherArgs::parse(&original.to_args()).expect("round-trips");
        assert_eq!(parsed, original);
    }

    #[test]
    fn parse_minimal_command_only() {
        // No caps, seccomp off: just a command after `--`.
        let parsed = LauncherArgs::parse(&argv(&["--", "echo", "hi"])).expect("parses");
        assert!(parsed.resources.is_unset());
        assert_eq!(parsed.seccomp, SeccompMode::Off);
        assert_eq!(parsed.command, argv(&["echo", "hi"]));
    }

    #[test]
    fn parse_preserves_nested_separator_in_command() {
        // The command itself may contain `--` (e.g. `bwrap … -- cmd`); only the
        // first `--` is the launcher boundary.
        let parsed = LauncherArgs::parse(&argv(&["--nproc", "8", "--", "bwrap", "--", "sh"]))
            .expect("parses");
        assert_eq!(parsed.resources.max_processes, Some(8));
        assert_eq!(parsed.command, argv(&["bwrap", "--", "sh"]));
    }

    #[test]
    fn parse_rejects_missing_separator() {
        let err = LauncherArgs::parse(&argv(&["--nproc", "8"])).unwrap_err();
        assert!(err.contains("missing `--`"), "err: {err}");
    }

    #[test]
    fn parse_rejects_bad_value_and_unknown_flag() {
        assert!(LauncherArgs::parse(&argv(&["--nproc", "x", "--", "true"])).is_err());
        assert!(LauncherArgs::parse(&argv(&["--bogus", "--", "true"])).is_err());
        assert!(LauncherArgs::parse(&argv(&["--seccomp", "loose", "--", "true"])).is_err());
        assert!(LauncherArgs::parse(&argv(&["--", ""])).is_ok());
        assert!(LauncherArgs::parse(&argv(&["--"])).is_err());
    }

    #[test]
    fn is_needed_tracks_caps_and_seccomp_path() {
        let none = ResourceLimits::default();
        let some = ResourceLimits {
            max_processes: Some(1),
            ..Default::default()
        };
        // A cap is always enforced (any host backend).
        assert!(LauncherArgs::is_needed(some, SeccompMode::Off, false));
        assert!(LauncherArgs::is_needed(some, SeccompMode::Off, true));
        // Seccomp only adds the launcher on the `none` path.
        assert!(LauncherArgs::is_needed(none, SeccompMode::Default, true));
        assert!(!LauncherArgs::is_needed(none, SeccompMode::Default, false));
        // Nothing to do ⇒ no launcher.
        assert!(!LauncherArgs::is_needed(none, SeccompMode::Off, true));
    }

    #[test]
    fn seccomp_to_args_omitted_when_off() {
        let args = LauncherArgs {
            command: argv(&["true"]),
            ..Default::default()
        };
        assert_eq!(args.to_args(), argv(&["--", "true"]));
    }

    // --- individual cap coverage (issue #349) -----------------------------------

    #[test]
    fn to_args_memory_cap_only() {
        // max_memory_bytes alone must produce only --as (not --nproc or --cpu).
        let args = LauncherArgs {
            resources: ResourceLimits {
                max_memory_bytes: Some(1_073_741_824),
                ..Default::default()
            },
            command: argv(&["true"]),
            ..Default::default()
        };
        let serialized = args.to_args();
        assert!(
            serialized.windows(2).any(|w| w == ["--as", "1073741824"]),
            "--as must be emitted for max_memory_bytes: {serialized:?}"
        );
        assert!(
            !serialized.contains(&"--nproc".to_string()),
            "--nproc must not appear when max_processes is unset: {serialized:?}"
        );
        assert!(
            !serialized.contains(&"--cpu".to_string()),
            "--cpu must not appear when max_cpu_seconds is unset: {serialized:?}"
        );
    }

    #[test]
    fn to_args_cpu_cap_only() {
        // max_cpu_seconds alone must produce only --cpu.
        let args = LauncherArgs {
            resources: ResourceLimits {
                max_cpu_seconds: Some(120),
                ..Default::default()
            },
            command: argv(&["bash"]),
            ..Default::default()
        };
        let serialized = args.to_args();
        assert!(
            serialized.windows(2).any(|w| w == ["--cpu", "120"]),
            "--cpu must be emitted for max_cpu_seconds: {serialized:?}"
        );
        assert!(
            !serialized.contains(&"--as".to_string()),
            "--as must not appear when max_memory_bytes is unset: {serialized:?}"
        );
    }

    #[test]
    fn parse_individual_memory_cap() {
        // --as alone must parse into max_memory_bytes with no other caps set.
        let parsed =
            LauncherArgs::parse(&argv(&["--as", "2048", "--", "echo", "hi"])).expect("parses --as");
        assert_eq!(parsed.resources.max_memory_bytes, Some(2048));
        assert_eq!(parsed.resources.max_processes, None);
        assert_eq!(parsed.resources.max_cpu_seconds, None);
        assert_eq!(parsed.command, argv(&["echo", "hi"]));
    }

    #[test]
    fn parse_individual_cpu_cap() {
        // --cpu alone must parse into max_cpu_seconds with no other caps set.
        let parsed =
            LauncherArgs::parse(&argv(&["--cpu", "30", "--", "true"])).expect("parses --cpu");
        assert_eq!(parsed.resources.max_cpu_seconds, Some(30));
        assert_eq!(parsed.resources.max_processes, None);
        assert_eq!(parsed.resources.max_memory_bytes, None);
    }

    #[test]
    fn parse_seccomp_off_explicitly() {
        // `--seccomp off` must round-trip back to SeccompMode::Off — i.e. the
        // serialisation and parse are consistent even when the mode is the default.
        // This covers the branch in parse() that sets SeccompMode::Off explicitly,
        // which the to_args_and_parse_round_trip test never exercises (off is
        // omitted by to_args when the mode is default/off).
        let parsed =
            LauncherArgs::parse(&argv(&["--seccomp", "off", "--", "true"])).expect("parses off");
        assert_eq!(parsed.seccomp, SeccompMode::Off);
        assert_eq!(parsed.command, argv(&["true"]));
    }
}
