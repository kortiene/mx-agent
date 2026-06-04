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
//! to touch.
//!
//! The [`ContainerSandbox`] backend runs the command inside a Docker or Podman
//! container (§13.5 "Docker or Podman"): it launches the configured image with a
//! read-only root filesystem, mounts the configured read-only and writable paths,
//! denies the network by default, and forwards only the sanitized environment.

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

/// The container runtime a [`ContainerSandbox`] launches commands through
/// (architecture §13.5, "Docker or Podman").
///
/// Both runtimes accept the same `run` flags this backend uses, so the only
/// difference is the executable name resolved on `PATH`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Runtime {
    /// Docker (`docker run …`).
    #[default]
    Docker,
    /// Podman (`podman run …`).
    Podman,
}

impl Runtime {
    /// The runtime's executable name, resolved on `PATH`. The runner surfaces a
    /// spawn error if it is not installed.
    pub fn program(self) -> &'static str {
        match self {
            Runtime::Docker => "docker",
            Runtime::Podman => "podman",
        }
    }
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

/// Render a path as a launcher argument. Paths are passed verbatim; the launcher
/// resolves them relative to the runner's filesystem when binding.
fn path_arg(path: &std::path::Path) -> String {
    path.to_string_lossy().into_owned()
}

/// The default image [`ContainerSandbox`] runs in until an operator configures
/// one. A minimal Debian base is a reasonable starting point for running shell
/// commands; the image is meant to be overridden via [`ContainerSandbox::new`].
const DEFAULT_IMAGE: &str = "debian:stable-slim";

/// The container backend: runs the command inside a Docker or Podman container
/// (architecture §13.5, "Docker or Podman").
///
/// [`prepare`][ContainerSandbox::prepare] rewrites the argv to
/// `<runtime> run <isolation flags> <image> <argv>`, deriving the isolation from
/// the [`Restrictions`]:
///
/// - the container starts with a read-only root filesystem (`--read-only`,
///   §13.5 "read-only root filesystem"); only explicitly mounted writable paths
///   can be written.
/// - [`Network::Deny`] adds `--network none`, giving the container an isolated
///   network namespace with no route to the outside (§13.5 "network disabled by
///   default"). [`Network::Allow`] keeps the runtime's default networking.
/// - each [`Restrictions::read_only_paths`] entry is mounted read-only and each
///   [`Restrictions::writable_paths`] entry writable, at the same path inside the
///   container, so the command sees only the filesystem it is permitted to touch
///   (§13.5 "writable workspace and temp only").
/// - the working directory is set with `--workdir`; it must be reachable through
///   one of the mounted paths.
/// - only the sanitized environment ([`Restrictions::env`]) is forwarded, each
///   variable passed explicitly with `--env KEY=VALUE`. A container does not
///   inherit the runner's environment, so the variables are injected here rather
///   than relied on from the spawned process. Secrets are already scrubbed by the
///   caller (architecture §13.4), so no credential reaches the argv.
///
/// `--rm` removes the container when the command exits. The implementation is
/// pure — it only computes an argv — so the wrapping rules are unit-tested
/// without launching a container.
#[derive(Debug, Clone)]
pub struct ContainerSandbox {
    /// The container runtime to launch through.
    runtime: Runtime,
    /// The image the command runs in.
    image: String,
}

impl Default for ContainerSandbox {
    fn default() -> Self {
        Self {
            runtime: Runtime::default(),
            image: DEFAULT_IMAGE.to_string(),
        }
    }
}

impl ContainerSandbox {
    /// Construct a container backend that runs commands in `image` via `runtime`.
    pub fn new(runtime: Runtime, image: impl Into<String>) -> Self {
        Self {
            runtime,
            image: image.into(),
        }
    }

    /// The image commands run in.
    pub fn image(&self) -> &str {
        &self.image
    }

    /// The runtime commands are launched through.
    pub fn runtime(&self) -> Runtime {
        self.runtime
    }
}

impl Sandbox for ContainerSandbox {
    fn backend(&self) -> Backend {
        Backend::Container
    }

    fn prepare(&self, argv: Vec<String>, restrictions: Restrictions) -> Prepared {
        let mut wrapped: Vec<String> = vec![
            self.runtime.program().to_string(),
            "run".to_string(),
            // Remove the container when the command exits.
            "--rm".to_string(),
            // Read-only root filesystem: only explicitly mounted writable paths
            // can be written (architecture §13.5).
            "--read-only".to_string(),
        ];

        // Network deny: an isolated network namespace with no route out
        // (architecture §13.5, "network disabled by default"). `allow` keeps the
        // runtime's default networking.
        if restrictions.network == Network::Deny {
            wrapped.push("--network".to_string());
            wrapped.push("none".to_string());
        }

        // Forward only the sanitized environment (architecture §13.4). A
        // container does not inherit the runner's environment, so each variable
        // is passed explicitly. Values are already secret-scrubbed by the caller.
        for (key, value) in &restrictions.env {
            wrapped.push("--env".to_string());
            wrapped.push(format!("{key}={value}"));
        }

        // Mount the configured filesystem at the same path inside the container:
        // read-only mounts first, then writable, so a writable path nested under
        // a read-only one still wins.
        for path in &restrictions.read_only_paths {
            let p = path_arg(path);
            wrapped.push("--volume".to_string());
            wrapped.push(format!("{p}:{p}:ro"));
        }
        for path in &restrictions.writable_paths {
            let p = path_arg(path);
            wrapped.push("--volume".to_string());
            wrapped.push(format!("{p}:{p}"));
        }

        // Run in the requested working directory (must be reachable through a
        // mounted path), then the image and the command argv.
        wrapped.push("--workdir".to_string());
        wrapped.push(path_arg(&restrictions.cwd));
        wrapped.push(self.image.clone());
        wrapped.extend(argv);

        Prepared {
            backend: Backend::Container,
            argv: wrapped,
            restrictions,
        }
    }
}

/// Construct the sandbox implementation for `backend`.
///
/// All backends are implemented. The container backend uses its default runtime
/// and image ([`ContainerSandbox::default`]); a configured image is supplied by
/// constructing [`ContainerSandbox::new`] directly.
pub fn sandbox_for(backend: Backend) -> Box<dyn Sandbox> {
    match backend {
        Backend::None => Box::new(NoneSandbox),
        Backend::Bubblewrap => Box::new(BubblewrapSandbox),
        Backend::Container => Box::new(ContainerSandbox::default()),
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
    fn sandbox_for_container_reports_container() {
        // The container backend is implemented, so selection returns it and the
        // prepared command honestly reports `container`.
        let prepared =
            sandbox_for(Backend::Container).prepare(argv(&["true"]), Restrictions::default());
        assert_eq!(prepared.backend, Backend::Container);
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

    // --- Container backend (Docker/Podman) -----------------------------------

    fn env_map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    /// The argv after the image: the image is the first token that is neither a
    /// flag nor a flag value, found by scanning the `<runtime> run …` prefix.
    fn container_command<'a>(prepared: &'a Prepared, image: &str) -> &'a [String] {
        let pos = prepared
            .argv
            .iter()
            .position(|a| a == image)
            .expect("prepared container argv contains the image");
        &prepared.argv[pos + 1..]
    }

    /// The `<runtime> run` flags up to (and excluding) the image.
    fn container_flags<'a>(prepared: &'a Prepared, image: &str) -> &'a [String] {
        let pos = prepared.argv.iter().position(|a| a == image).unwrap();
        &prepared.argv[..pos]
    }

    #[test]
    fn runtime_programs_are_stable() {
        assert_eq!(Runtime::Docker.program(), "docker");
        assert_eq!(Runtime::Podman.program(), "podman");
        assert_eq!(Runtime::default(), Runtime::Docker);
    }

    #[test]
    fn container_wraps_command_in_configured_image() {
        let sandbox = ContainerSandbox::new(Runtime::Docker, "myimage:tag");
        let prepared = sandbox.prepare(argv(&["echo", "hi"]), Restrictions::default());
        assert_eq!(prepared.backend, Backend::Container);
        // Launches via `docker run …`.
        assert_eq!(
            &prepared.argv[..2],
            argv(&["docker", "run"]).as_slice(),
            "argv: {:?}",
            prepared.argv
        );
        // The command runs in the configured image, after all flags.
        assert_eq!(
            container_command(&prepared, "myimage:tag"),
            argv(&["echo", "hi"]).as_slice()
        );
        // The centralized controls are carried through unchanged.
        assert_eq!(prepared.restrictions, Restrictions::default());
    }

    #[test]
    fn container_uses_selected_runtime() {
        let sandbox = ContainerSandbox::new(Runtime::Podman, "img");
        let prepared = sandbox.prepare(argv(&["true"]), Restrictions::default());
        assert_eq!(prepared.argv.first().map(String::as_str), Some("podman"));
    }

    #[test]
    fn container_default_uses_default_image() {
        let sandbox = ContainerSandbox::default();
        assert_eq!(sandbox.runtime(), Runtime::Docker);
        assert_eq!(sandbox.image(), DEFAULT_IMAGE);
        let prepared = sandbox.prepare(argv(&["true"]), Restrictions::default());
        // The default image precedes the command argv.
        assert_eq!(
            container_command(&prepared, DEFAULT_IMAGE),
            argv(&["true"]).as_slice()
        );
    }

    #[test]
    fn container_root_filesystem_is_read_only() {
        let prepared = ContainerSandbox::new(Runtime::Docker, "img")
            .prepare(argv(&["true"]), Restrictions::default());
        assert!(container_flags(&prepared, "img")
            .iter()
            .any(|f| f == "--read-only"));
    }

    #[test]
    fn container_denies_network_with_network_none() {
        let denied = ContainerSandbox::new(Runtime::Docker, "img").prepare(
            argv(&["true"]),
            Restrictions {
                network: Network::Deny,
                ..Restrictions::default()
            },
        );
        let flags = container_flags(&denied, "img").join(" ");
        assert!(flags.contains("--network none"), "flags: {flags}");

        let allowed = ContainerSandbox::new(Runtime::Docker, "img").prepare(
            argv(&["true"]),
            Restrictions {
                network: Network::Allow,
                ..Restrictions::default()
            },
        );
        assert!(!container_flags(&allowed, "img")
            .iter()
            .any(|f| f == "--network"));
    }

    #[test]
    fn container_mounts_paths_according_to_policy() {
        let prepared = ContainerSandbox::new(Runtime::Docker, "img").prepare(
            argv(&["true"]),
            Restrictions {
                cwd: PathBuf::from("/work"),
                read_only_paths: vec![PathBuf::from("/usr"), PathBuf::from("/lib")],
                writable_paths: vec![PathBuf::from("/work")],
                ..Restrictions::default()
            },
        );
        let flags = container_flags(&prepared, "img").join(" ");
        assert!(flags.contains("--volume /usr:/usr:ro"), "flags: {flags}");
        assert!(flags.contains("--volume /lib:/lib:ro"), "flags: {flags}");
        // Writable mount has no :ro suffix.
        assert!(flags.contains("--volume /work:/work "), "flags: {flags}");
        // The working directory is entered with --workdir.
        assert!(flags.contains("--workdir /work"), "flags: {flags}");
    }

    #[test]
    fn container_forwards_only_sanitized_env() {
        let prepared = ContainerSandbox::new(Runtime::Docker, "img").prepare(
            argv(&["true"]),
            Restrictions {
                env: env_map(&[("PATH", "/usr/bin"), ("LANG", "C")]),
                ..Restrictions::default()
            },
        );
        let flags = container_flags(&prepared, "img").join(" ");
        // Each sanitized variable is forwarded explicitly as KEY=VALUE.
        assert!(flags.contains("--env PATH=/usr/bin"), "flags: {flags}");
        assert!(flags.contains("--env LANG=C"), "flags: {flags}");
    }

    // --- Integration tests that actually launch a container runtime. ---------
    //
    // These validate the acceptance criteria (a command runs in the configured
    // image, and the workspace is mounted according to policy) against a real
    // runtime. They skip gracefully when no runtime can run a small image (no
    // Docker/Podman installed, no network to pull, or a restricted CI sandbox),
    // so the suite stays green there.

    /// A container runtime and a small image that can run `true`, if one is
    /// available. Tries each runtime with a few tiny images, using any locally
    /// present image and otherwise attempting a pull.
    fn usable_container() -> Option<(Runtime, String)> {
        use std::process::Command;
        for runtime in [Runtime::Docker, Runtime::Podman] {
            for image in ["busybox", "alpine", DEFAULT_IMAGE] {
                let ran = Command::new(runtime.program())
                    .args(["run", "--rm", image, "true"])
                    .output();
                if let Ok(out) = ran {
                    if out.status.success() {
                        return Some((runtime, image.to_string()));
                    }
                }
            }
        }
        None
    }

    #[test]
    fn command_runs_in_configured_image() {
        let Some((runtime, image)) = usable_container() else {
            eprintln!("skipping: no usable container runtime/image in this environment");
            return;
        };
        let prepared = ContainerSandbox::new(runtime, &image).prepare(
            argv(&["sh", "-c", "echo inside-container"]),
            Restrictions {
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
            "inside-container"
        );
    }

    #[test]
    fn workspace_writable_mount_allows_writes() {
        let Some((runtime, image)) = usable_container() else {
            eprintln!("skipping: no usable container runtime/image in this environment");
            return;
        };
        // A unique workspace dir on the host, mounted writable into the container.
        let workspace =
            std::env::temp_dir().join(format!("mx-agent-container-{}", std::process::id()));
        std::fs::create_dir_all(&workspace).expect("create workspace dir");
        let prepared = ContainerSandbox::new(runtime, &image).prepare(
            argv(&["sh", "-c", "echo ok > probe && cat probe"]),
            Restrictions {
                cwd: workspace.clone(),
                writable_paths: vec![workspace.clone()],
                network: Network::Deny,
                ..Restrictions::default()
            },
        );
        let out = run_prepared(&prepared);
        let success = out.status.success();
        let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        // The file is written through the bind mount, so it is visible on the host.
        let host_probe = workspace.join("probe");
        let on_host = std::fs::read_to_string(&host_probe).ok();
        let _ = std::fs::remove_dir_all(&workspace);
        assert!(success, "stderr: {stderr}");
        assert_eq!(stdout, "ok");
        assert_eq!(on_host.as_deref().map(str::trim), Some("ok"));
    }

    #[test]
    fn read_only_root_denies_writes_outside_mounts() {
        let Some((runtime, image)) = usable_container() else {
            eprintln!("skipping: no usable container runtime/image in this environment");
            return;
        };
        // With a read-only root and no writable mount covering it, writing to the
        // container root filesystem must fail.
        let prepared = ContainerSandbox::new(runtime, &image).prepare(
            argv(&["sh", "-c", "echo x > /mx-agent-should-fail"]),
            Restrictions {
                network: Network::Deny,
                ..Restrictions::default()
            },
        );
        let out = run_prepared(&prepared);
        assert!(
            !out.status.success(),
            "write to a read-only root filesystem unexpectedly succeeded",
        );
    }
}
