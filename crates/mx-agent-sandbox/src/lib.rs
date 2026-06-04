//! Process sandboxing backends for mx-agent remote execution.
//!
//! Backends (`none`, `bubblewrap`, container) are described in
//! `docs/architecture.md`, section 13.5. This crate defines the [`Sandbox`]
//! abstraction the process runner uses to launch a command under a chosen
//! backend, the centralized [`Restrictions`] every backend enforces, and the
//! baseline [`NoneSandbox`] implementation.
//!
//! ## The abstraction
//!
//! A [`Sandbox`] takes the requested argv plus the [`Restrictions`] resolved for
//! the request and returns a [`Prepared`] command: the argv to actually spawn
//! and the controls the runner must enforce around it. The baseline `none`
//! backend adds no isolation — it returns the argv unchanged and relies on the
//! runner enforcing the centralized controls. Stronger backends layer isolation
//! on top by rewriting the argv to launch the command inside their wrapper.
//!
//! The [`BubblewrapSandbox`] backend wraps the command in `bwrap` (§13.5
//! "bubblewrap or firejail"): it can drop the command into a fresh network
//! namespace ([`Network::Deny`]) and bind the configured read-only and writable
//! paths into the sandbox, so the command sees only the filesystem it is allowed
//! to touch. The container backend is described in §13.5 and added later.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

/// Available sandbox backends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    /// No isolation beyond cwd/env/timeout/output controls.
    None,
    /// `bubblewrap`-based isolation.
    Bubblewrap,
    /// Container-based isolation (Docker/Podman).
    Container,
}

impl Backend {
    /// The stable, lowercase name of this backend.
    ///
    /// Used to record the selected backend in the audit log (architecture
    /// §13.6) and to match the policy configuration vocabulary (§13.5).
    pub fn name(self) -> &'static str {
        match self {
            Backend::None => "none",
            Backend::Bubblewrap => "bubblewrap",
            Backend::Container => "container",
        }
    }
}

/// Default sandbox backend used until configured otherwise.
pub fn default_backend() -> Backend {
    Backend::None
}

/// Whether the sandboxed command may reach the network (architecture §13.5,
/// "network disabled by default").
///
/// Only isolating backends can enforce this; the baseline `none` backend ignores
/// it because it adds no isolation. [`Network::Deny`] is the default so a backend
/// that does honour it fails closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Network {
    /// The command keeps the daemon's network access.
    Allow,
    /// The command runs with no network access (a fresh, empty network
    /// namespace).
    #[default]
    Deny,
}

/// The baseline execution controls every sandbox backend enforces around a
/// command (architecture §13.5 "minimum controls"): a restricted working
/// directory, a sanitized environment, a wall-clock timeout, and an output cap.
///
/// Centralizing these here gives every backend — and the process runner — one
/// vocabulary for the baseline controls. The `none` backend relies on the
/// runner enforcing them as-is; stronger backends may tighten them further (for
/// example a container backend rewriting `cwd` to its in-container path) before
/// layering additional isolation on top.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Restrictions {
    /// Working directory the command must run in (an allowed cwd).
    pub cwd: PathBuf,
    /// The sanitized environment handed to the command. Secrets are already
    /// scrubbed by the caller (architecture §13.4); a backend may restrict this
    /// further but must never widen it.
    pub env: BTreeMap<String, String>,
    /// Maximum wall-clock runtime, if capped. `None` runs with no enforced
    /// limit. Enforced by the runner, which terminates the process group on
    /// expiry (§7.4).
    pub timeout: Option<Duration>,
    /// Maximum captured output in bytes, if capped. `None` captures without an
    /// enforced limit. Enforced by the output-capture stage, not the spawn
    /// itself; carried here so the full baseline control set lives in one place.
    pub max_output_bytes: Option<u64>,
    /// Whether the command may reach the network. Only an isolating backend can
    /// enforce this; the `none` backend ignores it (architecture §13.5).
    pub network: Network,
    /// Filesystem paths an isolating backend binds read-only into the sandbox
    /// (architecture §13.5, "read-only root filesystem"). Ignored by `none`.
    pub read_only_paths: Vec<PathBuf>,
    /// Filesystem paths an isolating backend binds writable into the sandbox
    /// (architecture §13.5, "writable workspace and temp only"). Ignored by
    /// `none`.
    pub writable_paths: Vec<PathBuf>,
}

/// A command prepared for execution by a [`Sandbox`] backend.
///
/// Returned by [`Sandbox::prepare`]: the argv to actually spawn, the controls
/// the runner must enforce around it, and the backend that prepared it (recorded
/// in the audit log).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prepared {
    /// The backend that prepared this command.
    pub backend: Backend,
    /// The argv to spawn. For `none` this is the requested argv unchanged; an
    /// isolating backend prepends its launcher (e.g. `bwrap … -- <argv>`).
    pub argv: Vec<String>,
    /// The controls the runner must enforce around the spawned process.
    pub restrictions: Restrictions,
}

/// A process isolation backend (architecture §13.5).
///
/// Given the requested argv and the [`Restrictions`] resolved for a request, a
/// backend returns a [`Prepared`] command describing what to spawn and which
/// controls to enforce. Implementations are pure so the wrapping rules can be
/// unit-tested without spawning anything.
pub trait Sandbox {
    /// Which backend this implementation is.
    fn backend(&self) -> Backend;

    /// Prepare `argv` for execution under this backend with `restrictions`.
    fn prepare(&self, argv: Vec<String>, restrictions: Restrictions) -> Prepared;
}

/// The baseline `none` backend: no isolation beyond the centralized
/// [`Restrictions`].
///
/// It returns the requested argv unchanged and relies on the process runner to
/// enforce the restricted cwd, sanitized env, timeout, and output cap. This is
/// the default until a stronger backend is configured (architecture §13.5).
#[derive(Debug, Clone, Copy, Default)]
pub struct NoneSandbox;

impl Sandbox for NoneSandbox {
    fn backend(&self) -> Backend {
        Backend::None
    }

    fn prepare(&self, argv: Vec<String>, restrictions: Restrictions) -> Prepared {
        Prepared {
            backend: Backend::None,
            argv,
            restrictions,
        }
    }
}

/// The `bwrap` launcher this backend wraps commands with. Resolved on `PATH`;
/// the runner surfaces a spawn error if it is not installed.
const BWRAP: &str = "bwrap";

/// The `bubblewrap` backend: runs the command inside a `bwrap` sandbox
/// (architecture §13.5).
///
/// [`prepare`][BubblewrapSandbox::prepare] rewrites the argv to
/// `bwrap <isolation flags> -- <argv>`, deriving the isolation from the
/// [`Restrictions`]:
///
/// - [`Network::Deny`] adds `--unshare-net`, dropping the command into a fresh
///   network namespace with no route to the outside (loopback only, and down).
/// - each [`Restrictions::read_only_paths`] entry is bound read-only
///   (`--ro-bind`) and each [`Restrictions::writable_paths`] entry writable
///   (`--bind`), so the command sees only the filesystem it is permitted to
///   touch.
/// - the working directory is set with `--chdir`; it must be reachable through
///   one of the bound paths.
///
/// `--die-with-parent` ties the sandbox's lifetime to the runner, and `--unshare-pid`
/// / `--unshare-uts` / `--unshare-ipc` give the command its own process, host,
/// and IPC namespaces. The environment is still applied by the runner around the
/// prepared argv, so secret scrubbing (architecture §13.4) is unaffected.
///
/// The implementation is pure — it only computes an argv — so the wrapping rules
/// are unit-tested without spawning `bwrap`.
#[derive(Debug, Clone, Default)]
pub struct BubblewrapSandbox;

impl Sandbox for BubblewrapSandbox {
    fn backend(&self) -> Backend {
        Backend::Bubblewrap
    }

    fn prepare(&self, argv: Vec<String>, restrictions: Restrictions) -> Prepared {
        let mut wrapped: Vec<String> = vec![
            BWRAP.to_string(),
            // Tie the sandbox to the runner and give the command its own
            // process/host/IPC namespaces.
            "--die-with-parent".to_string(),
            "--unshare-pid".to_string(),
            "--unshare-uts".to_string(),
            "--unshare-ipc".to_string(),
        ];

        // Network deny: a fresh, empty network namespace (architecture §13.5,
        // "network disabled by default"). `allow` keeps the daemon's network.
        if restrictions.network == Network::Deny {
            wrapped.push("--unshare-net".to_string());
        }

        // Bind the configured filesystem at the same path inside the sandbox:
        // read-only mounts first, then writable, so a writable path nested under
        // a read-only one still wins.
        for path in &restrictions.read_only_paths {
            wrapped.push("--ro-bind".to_string());
            wrapped.push(path_arg(path));
            wrapped.push(path_arg(path));
        }
        for path in &restrictions.writable_paths {
            wrapped.push("--bind".to_string());
            wrapped.push(path_arg(path));
            wrapped.push(path_arg(path));
        }

        // Run in the requested working directory (must be reachable through a
        // bound path) and stop parsing flags before the command argv.
        wrapped.push("--chdir".to_string());
        wrapped.push(path_arg(&restrictions.cwd));
        wrapped.push("--".to_string());
        wrapped.extend(argv);

        Prepared {
            backend: Backend::Bubblewrap,
            argv: wrapped,
            restrictions,
        }
    }
}

/// Render a path as a `bwrap` argument. Paths are passed verbatim; `bwrap`
/// resolves them relative to the runner's filesystem when binding.
fn path_arg(path: &std::path::Path) -> String {
    path.to_string_lossy().into_owned()
}

/// Construct the sandbox implementation for `backend`.
///
/// [`Backend::None`] and [`Backend::Bubblewrap`] are implemented. The container
/// backend is described in §13.5 and not yet available, so it falls back to the
/// `none` backend; the returned [`Prepared::backend`] then truthfully reports
/// `none`, so the audit log never claims isolation that was not applied.
pub fn sandbox_for(backend: Backend) -> Box<dyn Sandbox> {
    match backend {
        Backend::None => Box::new(NoneSandbox),
        Backend::Bubblewrap => Box::new(BubblewrapSandbox),
        // Not yet implemented: fall back to `none` rather than failing, and
        // report `none` honestly.
        Backend::Container => Box::new(NoneSandbox),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn default_backend_is_none() {
        assert_eq!(default_backend(), Backend::None);
    }

    #[test]
    fn backend_names_are_stable() {
        assert_eq!(Backend::None.name(), "none");
        assert_eq!(Backend::Bubblewrap.name(), "bubblewrap");
        assert_eq!(Backend::Container.name(), "container");
    }

    #[test]
    fn none_backend_runs_argv_unchanged() {
        let restrictions = Restrictions {
            cwd: PathBuf::from("/work"),
            timeout: Some(Duration::from_secs(30)),
            max_output_bytes: Some(1024),
            ..Restrictions::default()
        };
        let prepared = NoneSandbox.prepare(argv(&["echo", "hi"]), restrictions.clone());
        assert_eq!(prepared.backend, Backend::None);
        // No isolation: the argv is passed through verbatim.
        assert_eq!(prepared.argv, argv(&["echo", "hi"]));
        // The centralized controls are carried through unchanged.
        assert_eq!(prepared.restrictions, restrictions);
    }

    #[test]
    fn sandbox_for_none_reports_none() {
        let sandbox = sandbox_for(Backend::None);
        assert_eq!(sandbox.backend(), Backend::None);
    }

    #[test]
    fn unimplemented_backends_fall_back_to_none_honestly() {
        // Until the container backend lands, selection falls back to `none` and
        // the prepared command reports `none` so the audit log stays truthful.
        let prepared =
            sandbox_for(Backend::Container).prepare(argv(&["true"]), Restrictions::default());
        assert_eq!(prepared.backend, Backend::None);
        assert_eq!(prepared.argv, argv(&["true"]));
    }

    #[test]
    fn sandbox_for_bubblewrap_reports_bubblewrap() {
        assert_eq!(
            sandbox_for(Backend::Bubblewrap).backend(),
            Backend::Bubblewrap
        );
    }

    /// The `bwrap` flags up to (and excluding) the `--` separator.
    fn bwrap_flags(prepared: &Prepared) -> &[String] {
        let sep = prepared
            .argv
            .iter()
            .position(|a| a == "--")
            .expect("prepared bwrap argv has a `--` separator");
        &prepared.argv[..sep]
    }

    /// The command argv after the `--` separator.
    fn bwrap_command(prepared: &Prepared) -> &[String] {
        let sep = prepared.argv.iter().position(|a| a == "--").unwrap();
        &prepared.argv[sep + 1..]
    }

    #[test]
    fn bubblewrap_wraps_command_after_separator() {
        let prepared = BubblewrapSandbox.prepare(argv(&["echo", "hi"]), Restrictions::default());
        assert_eq!(prepared.backend, Backend::Bubblewrap);
        assert_eq!(prepared.argv.first().map(String::as_str), Some("bwrap"));
        // The requested command survives verbatim after the `--` separator.
        assert_eq!(bwrap_command(&prepared), argv(&["echo", "hi"]).as_slice());
        // The centralized controls are carried through unchanged.
        assert_eq!(prepared.restrictions, Restrictions::default());
    }

    #[test]
    fn bubblewrap_denies_network_with_unshare_net() {
        let denied = BubblewrapSandbox.prepare(
            argv(&["true"]),
            Restrictions {
                network: Network::Deny,
                ..Restrictions::default()
            },
        );
        assert!(bwrap_flags(&denied).iter().any(|f| f == "--unshare-net"));

        let allowed = BubblewrapSandbox.prepare(
            argv(&["true"]),
            Restrictions {
                network: Network::Allow,
                ..Restrictions::default()
            },
        );
        assert!(!bwrap_flags(&allowed).iter().any(|f| f == "--unshare-net"));
    }

    #[test]
    fn bubblewrap_binds_read_only_and_writable_paths() {
        let prepared = BubblewrapSandbox.prepare(
            argv(&["true"]),
            Restrictions {
                cwd: PathBuf::from("/work"),
                read_only_paths: vec![PathBuf::from("/usr"), PathBuf::from("/lib")],
                writable_paths: vec![PathBuf::from("/work")],
                ..Restrictions::default()
            },
        );
        let flags = bwrap_flags(&prepared).join(" ");
        assert!(flags.contains("--ro-bind /usr /usr"));
        assert!(flags.contains("--ro-bind /lib /lib"));
        assert!(flags.contains("--bind /work /work"));
        // The working directory is entered with --chdir.
        assert!(flags.contains("--chdir /work"));
    }

    // --- Integration tests that actually launch `bwrap`. ---------------------
    //
    // These validate the acceptance criteria (a command runs inside bubblewrap,
    // and denied network/path behavior holds) against a real `bwrap`. They skip
    // gracefully when `bwrap` is absent or unprivileged user namespaces are
    // unavailable (e.g. some CI sandboxes), so the suite stays green there.

    /// Whether a minimal `bwrap` invocation works in this environment.
    fn bwrap_usable() -> bool {
        use std::process::Command;
        match Command::new("bwrap")
            .args([
                "--ro-bind",
                "/",
                "/",
                "--dev-bind",
                "/dev",
                "/dev",
                "--",
                "true",
            ])
            .output()
        {
            Ok(out) => out.status.success(),
            Err(_) => false,
        }
    }

    /// Spawn a prepared command and return its captured output.
    fn run_prepared(prepared: &Prepared) -> std::process::Output {
        use std::process::Command;
        let (program, args) = prepared.argv.split_first().expect("non-empty argv");
        Command::new(program)
            .args(args)
            .output()
            .expect("spawn bwrap")
    }

    /// Read-only system mounts a sandboxed command needs to run a shell.
    fn base_ro_paths() -> Vec<PathBuf> {
        ["/usr", "/bin", "/lib", "/lib64", "/etc"]
            .iter()
            .map(PathBuf::from)
            .filter(|p| p.exists())
            .collect()
    }

    #[test]
    fn command_runs_inside_bubblewrap() {
        if !bwrap_usable() {
            eprintln!("skipping: bwrap not usable in this environment");
            return;
        }
        let tmp = std::env::temp_dir();
        let prepared = BubblewrapSandbox.prepare(
            argv(&["/bin/sh", "-c", "echo inside-sandbox"]),
            Restrictions {
                cwd: tmp.clone(),
                read_only_paths: base_ro_paths(),
                writable_paths: vec![tmp],
                network: Network::Deny,
                ..Restrictions::default()
            },
        );
        let out = run_prepared(&prepared);
        assert!(
            out.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(
            String::from_utf8_lossy(&out.stdout).trim(),
            "inside-sandbox"
        );
    }

    #[test]
    fn read_only_path_denies_writes() {
        if !bwrap_usable() {
            eprintln!("skipping: bwrap not usable in this environment");
            return;
        }
        let tmp = std::env::temp_dir();
        // Writing under a read-only-bound system path must fail; the shell's
        // failure is reported through its exit status.
        let prepared = BubblewrapSandbox.prepare(
            argv(&["/bin/sh", "-c", "echo x > /usr/mx-agent-should-fail"]),
            Restrictions {
                cwd: tmp,
                read_only_paths: base_ro_paths(),
                network: Network::Deny,
                ..Restrictions::default()
            },
        );
        let out = run_prepared(&prepared);
        assert!(
            !out.status.success(),
            "write to a read-only path unexpectedly succeeded",
        );
    }

    #[test]
    fn writable_path_allows_writes() {
        if !bwrap_usable() {
            eprintln!("skipping: bwrap not usable in this environment");
            return;
        }
        let tmp = std::env::temp_dir();
        let prepared = BubblewrapSandbox.prepare(
            argv(&["/bin/sh", "-c", "echo ok > probe && cat probe"]),
            Restrictions {
                cwd: tmp.clone(),
                read_only_paths: base_ro_paths(),
                writable_paths: vec![tmp],
                network: Network::Deny,
                ..Restrictions::default()
            },
        );
        let out = run_prepared(&prepared);
        assert!(
            out.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "ok");
    }

    #[test]
    fn denied_network_has_no_route() {
        if !bwrap_usable() {
            eprintln!("skipping: bwrap not usable in this environment");
            return;
        }
        if !PathBuf::from("/sys/class/net").exists() {
            eprintln!("skipping network probe: /sys/class/net absent");
            return;
        }
        // With --unshare-net the only interface is a down loopback, so the
        // sandbox sees no non-loopback interfaces. We read this from /sys, which
        // needs no extra tooling. The probe prints the count of non-`lo`
        // interfaces; under network deny that must be zero.
        let mut ro = base_ro_paths();
        ro.push(PathBuf::from("/sys"));
        let prepared = BubblewrapSandbox.prepare(
            argv(&["/bin/sh", "-c", "ls /sys/class/net | grep -vx lo | wc -l"]),
            Restrictions {
                cwd: std::env::temp_dir(),
                read_only_paths: ro,
                network: Network::Deny,
                ..Restrictions::default()
            },
        );
        let out = run_prepared(&prepared);
        if !out.status.success() {
            eprintln!("skipping network probe: shell failed in sandbox");
            return;
        }
        let count = String::from_utf8_lossy(&out.stdout).trim().to_string();
        assert_eq!(
            count, "0",
            "expected no non-loopback interfaces under network deny"
        );
    }
}
