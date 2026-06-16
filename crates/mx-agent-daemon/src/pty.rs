//! Pseudo-terminal (PTY) allocation for interactive `exec --pty` sessions.
//!
//! Where [`crate::runner::run`] captures a non-interactive command's
//! stdout/stderr as separate pipes, an interactive session needs a *pseudo
//! terminal*: a kernel device pair whose slave end becomes the child's
//! stdin/stdout/stderr so the program believes it is talking to a real terminal
//! (`isatty` is true, line editing and full-screen redraws work). The master
//! end is what the requesting side reads from and writes to.
//!
//! A PTY is inherently a **single merged stream** (architecture §7.3,
//! `StreamKind::Pty`): the child's stdout and stderr are interleaved on the one
//! terminal exactly as a user at a console would see them, so there is no
//! separate stderr channel to reorder. The session also carries the terminal's
//! **window size**, which the requesting side updates with [`PtySession::resize`]
//! whenever its local terminal changes (carried over the wire as a
//! [`PtyResize`](mx_agent_protocol::schema::PtyResize) event) so the remote
//! program re-renders at the new dimensions.
//!
//! This module is deliberately Unix-only: PTYs are a Unix concept and the rest
//! of the runner's interactive machinery (process groups, terminal ioctls)
//! follows suit. All terminal syscalls go through [`rustix`], which wraps them
//! in safe APIs so the crate keeps its `unsafe_code = "forbid"` guarantee.

use std::ffi::OsStr;
use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::process::CommandExt as _;
use std::process::{Child, Command, ExitStatus, Stdio};

use mx_agent_sandbox::{preflight_backend, Restrictions};
use rustix::pty::{grantpt, openpt, ptsname, unlockpt, OpenptFlags};
use rustix::termios::{tcgetwinsize, tcsetwinsize, Winsize};

use crate::runner::{
    launcher_wrap, resolve_sandbox, restrictions_for, sanitize_env, RunError, RunSpec,
};

/// A terminal window size: character grid plus optional pixel dimensions.
///
/// The pixel dimensions are advisory and default to `0`; most programs only
/// consult `rows`/`cols`. Maps directly to the kernel `winsize` struct.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PtyWinsize {
    /// Height in character rows.
    pub rows: u16,
    /// Width in character columns.
    pub cols: u16,
    /// Width in pixels, or `0` when unknown.
    pub pixel_width: u16,
    /// Height in pixels, or `0` when unknown.
    pub pixel_height: u16,
}

impl PtyWinsize {
    /// Rows used when the local terminal size is unknown (the VT100 default).
    pub const DEFAULT_ROWS: u16 = 24;
    /// Columns used when the local terminal size is unknown (the VT100 default).
    pub const DEFAULT_COLS: u16 = 80;

    /// A window size of `rows` by `cols` with unknown pixel dimensions.
    pub fn new(rows: u16, cols: u16) -> Self {
        Self {
            rows,
            cols,
            pixel_width: 0,
            pixel_height: 0,
        }
    }
}

impl Default for PtyWinsize {
    /// The conventional 24×80 fallback when no terminal size is available.
    fn default() -> Self {
        Self::new(Self::DEFAULT_ROWS, Self::DEFAULT_COLS)
    }
}

impl From<PtyWinsize> for Winsize {
    fn from(size: PtyWinsize) -> Self {
        Winsize {
            ws_row: size.rows,
            ws_col: size.cols,
            ws_xpixel: size.pixel_width,
            ws_ypixel: size.pixel_height,
        }
    }
}

impl From<Winsize> for PtyWinsize {
    fn from(ws: Winsize) -> Self {
        Self {
            rows: ws.ws_row,
            cols: ws.ws_col,
            pixel_width: ws.ws_xpixel,
            pixel_height: ws.ws_ypixel,
        }
    }
}

/// An interactive command running under a freshly allocated pseudo-terminal.
///
/// Holds the master end of the PTY and the child handle. The master is the
/// merged byte stream: read it for the program's terminal output, write to it
/// to deliver keystrokes. [`resize`](Self::resize) propagates a new window size
/// to the running program.
#[derive(Debug)]
pub struct PtySession {
    /// Master end of the PTY: read for output, write for input.
    master: File,
    /// The running child attached to the slave end.
    child: Child,
}

impl PtySession {
    /// Allocate a PTY and spawn `spec`'s command attached to its slave end at
    /// the given window `size`.
    ///
    /// The command is launched through the selected sandbox backend
    /// ([`RunSpec::sandbox`]) exactly as [`crate::runner::run`] does, so the
    /// configured network policy and read-only/writable binds confine the
    /// interactive session too (architecture §13.5); the baseline `none` backend
    /// adds no isolation. Because this is the interactive entry point, the
    /// resolved [`Restrictions`] are marked `interactive`, so the container
    /// backend additionally allocates an in-container TTY (`-i -t`) — `isatty` is
    /// true inside the container and full-screen programs work; the
    /// `none`/`bubblewrap` backends inherit the parent's PTY slave directly and
    /// ignore the signal. The child runs in `spec.cwd` with the same
    /// allowlist-sanitized environment (secrets are never inherited) and is
    /// placed in its own process group so a later cancel/timeout can signal the
    /// whole group. Its stdin, stdout, and stderr are all wired to the PTY slave,
    /// producing the single merged terminal stream.
    ///
    /// Returns a [`RunError`] when the command is empty, the working directory
    /// is missing, or the PTY/child could not be set up.
    pub fn spawn(spec: &RunSpec, size: PtyWinsize) -> Result<PtySession, RunError> {
        if spec.command.is_empty() {
            return Err(RunError::EmptyCommand);
        }
        if !is_existing_dir(&spec.cwd) {
            return Err(RunError::MissingCwd(spec.cwd.clone()));
        }

        // Open the master, authorize and unlock its slave, then resolve the
        // slave's device path. All four calls are safe rustix wrappers.
        let master = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY)
            .map_err(|e| RunError::Spawn(e.into()))?;
        grantpt(&master).map_err(|e| RunError::Spawn(e.into()))?;
        unlockpt(&master).map_err(|e| RunError::Spawn(e.into()))?;
        let slave_name = ptsname(&master, Vec::new()).map_err(|e| RunError::Spawn(e.into()))?;
        let master = File::from(master);

        let slave_path = OsStr::from_bytes(slave_name.as_bytes());
        let slave = OpenOptions::new()
            .read(true)
            .write(true)
            .open(slave_path)
            .map_err(RunError::Spawn)?;

        // Set the initial window size on the slave side. On macOS, TIOCSWINSZ
        // on the master returns ENOTTY until the slave is open; the slave form
        // is portable across Linux and macOS. The kernel PTY structure is
        // shared, so tcgetwinsize on the master afterwards reflects this size.
        tcsetwinsize(&slave, size.into()).map_err(|e| RunError::Spawn(e.into()))?;

        // Fail with an actionable diagnostic if the selected backend's launcher
        // is missing, mirroring the batch runner (issue #310).
        preflight_backend(spec.sandbox, spec.container_runtime).map_err(|message| {
            RunError::Spawn(std::io::Error::new(std::io::ErrorKind::NotFound, message))
        })?;

        // Launch through the selected sandbox backend (architecture §13.5),
        // mirroring the non-interactive runner: the backend rewrites the argv to
        // launch inside its wrapper (e.g. `bwrap …`) and so enforces the network
        // policy and the read-only/writable binds. The baseline `none` backend
        // returns the argv unchanged. Without this the sandbox/network/path
        // fields on the spec would have no effect on the interactive path.
        let env = sanitize_env(std::env::vars(), &spec.env, &spec.env_allowlist);
        let mut restrictions = restrictions_for(spec, env);
        // This is the interactive `--pty` path: signal the sandbox layer so a
        // backend that launches through a separate runtime (the container
        // backend) allocates an in-container TTY (`-i -t`), making `isatty` true
        // inside the container. The `none`/`bubblewrap` backends inherit the
        // parent's PTY slave directly and ignore this flag.
        restrictions.interactive = true;
        let prepared = resolve_sandbox(spec).prepare(spec.command.clone(), restrictions);
        // Resource caps confine the interactive session too: wrap the prepared
        // argv in the launcher trampoline for the `none`/`bubblewrap` paths when a
        // cap (or seccomp, on the `none` path) is set (issue #349).
        let argv = launcher_wrap(spec, prepared.argv)?;
        let (program, args) = argv.split_first().ok_or(RunError::EmptyCommand)?;
        let Restrictions { cwd, env, .. } = prepared.restrictions;
        let mut command = Command::new(program);
        command
            .args(args)
            .current_dir(&cwd)
            .env_clear()
            .envs(env)
            // All three standard streams share the one terminal, so stdout and
            // stderr interleave into the single merged PTY stream.
            .stdin(Stdio::from(slave.try_clone().map_err(RunError::Spawn)?))
            .stdout(Stdio::from(slave.try_clone().map_err(RunError::Spawn)?))
            .stderr(Stdio::from(slave.try_clone().map_err(RunError::Spawn)?));
        // Own process group: a later cancel/timeout signals the whole group so
        // nothing the command spawns is left orphaned (architecture §7.4/§7.5).
        command.process_group(0);

        let child = command.spawn().map_err(RunError::Spawn)?;
        // The parent keeps only the master end. Closing our slave handles means
        // the master observes EOF once the child (the last slave holder) exits.
        drop(slave);

        Ok(PtySession { master, child })
    }

    /// Propagate a new terminal window `size` to the running program.
    ///
    /// The kernel delivers `SIGWINCH` to the foreground process group, so
    /// full-screen programs re-query the size and redraw at the new dimensions.
    pub fn resize(&self, size: PtyWinsize) -> io::Result<()> {
        tcsetwinsize(&self.master, size.into())?;
        Ok(())
    }

    /// The PTY's current window size, as last set on the master.
    pub fn winsize(&self) -> io::Result<PtyWinsize> {
        Ok(tcgetwinsize(&self.master)?.into())
    }

    /// A new handle on the master end for reading the merged terminal output.
    ///
    /// Returns an independent file descriptor (via `dup`) so a reader can run on
    /// its own thread while another handle is used for writing input.
    pub fn try_clone_reader(&self) -> io::Result<File> {
        self.master.try_clone()
    }

    /// A new handle on the master end for writing input (keystrokes) to the
    /// program. See [`try_clone_reader`](Self::try_clone_reader).
    pub fn try_clone_writer(&self) -> io::Result<File> {
        self.master.try_clone()
    }

    /// The child's process id, for signalling its process group.
    pub fn id(&self) -> u32 {
        self.child.id()
    }

    /// Block until the child exits and return its status.
    pub fn wait(&mut self) -> io::Result<ExitStatus> {
        self.child.wait()
    }
}

/// Whether `path` exists and is a directory (mirrors the runner's cwd check).
fn is_existing_dir(path: &std::path::Path) -> bool {
    std::fs::metadata(path).map(|m| m.is_dir()).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read as _;
    use std::path::PathBuf;

    fn spec(command: &[&str]) -> RunSpec {
        RunSpec {
            command: command.iter().map(|s| s.to_string()).collect(),
            cwd: PathBuf::from("/"),
            ..Default::default()
        }
    }

    /// Drain the merged terminal output on a thread (so the child never blocks
    /// on a full PTY buffer), wait for exit, and return what was read.
    fn run_and_collect(mut session: PtySession) -> (ExitStatus, String) {
        let mut reader = session.try_clone_reader().expect("clone reader");
        let handle = std::thread::spawn(move || {
            let mut buf = Vec::new();
            // A PTY master reports EIO (not EOF) on Linux once the slave is gone;
            // treat any read error as end-of-stream.
            let _ = reader.read_to_end(&mut buf);
            buf
        });
        let status = session.wait().expect("wait for child");
        let bytes = handle.join().expect("reader thread");
        (status, String::from_utf8_lossy(&bytes).into_owned())
    }

    #[test]
    fn pty_merges_stdout_and_stderr_into_one_stream() {
        // Acceptance: an interactive command's output reaches the requester.
        // stdout and stderr share the one terminal, so both appear merged.
        let session = PtySession::spawn(
            &spec(&["sh", "-c", "echo to-stdout; echo to-stderr 1>&2"]),
            PtyWinsize::default(),
        )
        .expect("spawn pty session");
        let (status, output) = run_and_collect(session);
        assert!(status.success(), "expected success, got {status:?}");
        assert!(output.contains("to-stdout"), "missing stdout: {output:?}");
        assert!(output.contains("to-stderr"), "missing stderr: {output:?}");
    }

    #[test]
    fn child_runs_under_a_real_tty() {
        // The slave is a real terminal, so `test -t 0` (isatty on stdin) passes
        // — this is what makes interactive programs like `bash` behave.
        let session = PtySession::spawn(
            &spec(&["sh", "-c", "test -t 0 && echo is-a-tty"]),
            PtyWinsize::default(),
        )
        .expect("spawn pty session");
        let (status, output) = run_and_collect(session);
        assert!(status.success());
        assert!(
            output.contains("is-a-tty"),
            "stdin was not a tty: {output:?}"
        );
    }

    #[test]
    fn initial_winsize_is_visible_to_child() {
        // The window size set at allocation is what the child sees: `stty size`
        // prints "<rows> <cols>" read from its controlling stream (the PTY).
        let session = PtySession::spawn(&spec(&["stty", "size"]), PtyWinsize::new(24, 80))
            .expect("spawn pty session");
        let (status, output) = run_and_collect(session);
        assert!(status.success());
        assert!(output.contains("24 80"), "unexpected winsize: {output:?}");
    }

    #[test]
    fn resize_propagates_to_child() {
        // Acceptance: terminal resize propagates. Start at 24×80, resize to
        // 50×132, and a (briefly delayed) `stty size` reports the new size.
        let session = PtySession::spawn(
            &spec(&["sh", "-c", "sleep 0.3; stty size"]),
            PtyWinsize::new(24, 80),
        )
        .expect("spawn pty session");
        session
            .resize(PtyWinsize::new(50, 132))
            .expect("resize the pty");
        assert_eq!(session.winsize().expect("read winsize").rows, 50);
        let (status, output) = run_and_collect(session);
        assert!(status.success());
        assert!(
            output.contains("50 132"),
            "resize did not propagate: {output:?}"
        );
    }

    #[test]
    fn empty_command_is_rejected() {
        assert!(matches!(
            PtySession::spawn(&spec(&[]), PtyWinsize::default()),
            Err(RunError::EmptyCommand)
        ));
    }

    #[test]
    fn missing_cwd_is_rejected() {
        let mut s = spec(&["true"]);
        s.cwd = PathBuf::from("/nonexistent/path/for/pty/test");
        assert!(matches!(
            PtySession::spawn(&s, PtyWinsize::default()),
            Err(RunError::MissingCwd(_))
        ));
    }

    #[test]
    fn winsize_round_trips_through_kernel_struct() {
        let size = PtyWinsize {
            rows: 40,
            cols: 120,
            pixel_width: 960,
            pixel_height: 640,
        };
        let ws: Winsize = size.into();
        assert_eq!(PtyWinsize::from(ws), size);
    }

    // --- Sandbox routing through the interactive PTY path (issue #248) --------
    //
    // The interactive `--pty` path must launch through the selected sandbox
    // backend, just like the non-interactive runner, so the configured network
    // policy and bind paths actually confine the session. A real backend only
    // exists on Linux (bubblewrap), so this is a behavioral integration test
    // that skips gracefully when `bwrap` (or `/sys/class/net`) is unavailable.

    /// Whether a minimal `bwrap` invocation works in this environment (mirrors
    /// the probe in the sandbox crate's own integration tests).
    fn bwrap_usable() -> bool {
        Command::new("bwrap")
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
            .map(|out| out.status.success())
            .unwrap_or(false)
    }

    /// Read-only system mounts a sandboxed shell needs to run.
    fn base_ro_paths() -> Vec<PathBuf> {
        ["/usr", "/bin", "/lib", "/lib64", "/etc"]
            .iter()
            .map(PathBuf::from)
            .filter(|p| p.exists())
            .collect()
    }

    #[test]
    fn pty_command_runs_inside_selected_sandbox_backend() {
        use mx_agent_sandbox::{Backend, Network};

        if !bwrap_usable() {
            eprintln!("skipping: bwrap not usable in this environment");
            return;
        }
        if !PathBuf::from("/sys/class/net").exists() {
            eprintln!("skipping: /sys/class/net absent");
            return;
        }

        // A writable workspace bound into the sandbox so --chdir resolves.
        let workspace =
            std::env::temp_dir().join(format!("mx-agent-pty-sandbox-{}", std::process::id()));
        std::fs::create_dir_all(&workspace).expect("create workspace dir");

        let mut ro = base_ro_paths();
        ro.push(PathBuf::from("/sys"));

        // Probe the network from inside the session: under `network=Deny` the
        // sandbox has only a down loopback, so there are no non-`lo` interfaces.
        // If the PTY path failed to route through the backend (the #248 bug), the
        // command would run raw on the host and see real interfaces instead.
        let mut s = spec(&[
            "/bin/sh",
            "-c",
            "n=$(ls /sys/class/net | grep -vx lo | wc -l); \
             if [ \"$n\" -eq 0 ]; then echo PTY-SANDBOX-NET-DENIED; \
             else echo PTY-SANDBOX-NET-OPEN; fi",
        ]);
        s.cwd = workspace.clone();
        s.sandbox = Backend::Bubblewrap;
        s.network = Network::Deny;
        s.read_only_paths = ro;
        s.writable_paths = vec![workspace.clone()];

        let session = PtySession::spawn(&s, PtyWinsize::default()).expect("spawn pty session");
        let (status, output) = run_and_collect(session);
        let _ = std::fs::remove_dir_all(&workspace);

        if !status.success() {
            eprintln!("skipping: shell failed inside sandbox: {output:?}");
            return;
        }
        assert!(
            output.contains("PTY-SANDBOX-NET-DENIED"),
            "interactive PTY exec did not run under the network-denied sandbox: {output:?}"
        );
        assert!(
            !output.contains("PTY-SANDBOX-NET-OPEN"),
            "interactive PTY exec saw the host network — not sandboxed: {output:?}"
        );
    }

    // --- Container backend under the interactive PTY path (issue #272) --------
    //
    // A container-backed `--pty` session must be genuinely interactive: the
    // container backend allocates an in-container TTY (`-i -t`) so `isatty` is
    // true inside the container. This is a behavioral integration test that
    // skips gracefully when no container runtime/image is usable (no
    // Docker/Podman, no network to pull, or a restricted CI sandbox).

    /// A container runtime that can run `true` in a small image, if one is
    /// available (mirrors the probe in the sandbox crate's integration tests).
    /// `-t` requires the attached stdin to be a TTY, which it always is on the
    /// PTY path, so the probe itself runs non-interactively.
    fn usable_container_runtime() -> bool {
        for runtime in ["docker", "podman"] {
            for image in ["busybox", "alpine", "debian:stable-slim"] {
                let ran = Command::new(runtime)
                    .args(["run", "--rm", image, "true"])
                    .output();
                if let Ok(out) = ran {
                    if out.status.success() {
                        return true;
                    }
                }
            }
        }
        false
    }

    #[test]
    fn pty_container_session_is_interactive() {
        use mx_agent_sandbox::Backend;

        if !usable_container_runtime() {
            eprintln!("skipping: no usable container runtime/image in this environment");
            return;
        }

        // `sandbox_for(Backend::Container)` resolves the default runtime/image
        // (`debian:stable-slim`), so run `cwd = /` (present on host and in the
        // image, needing no writable mount). Without the `-i -t` fix the command
        // inside the container sees pipes, not a terminal, so `test -t 0` fails
        // and prints NOTTY; with it, the in-container stdin is a real TTY.
        let mut s = spec(&[
            "sh",
            "-c",
            "if test -t 0; then echo PTY-CONTAINER-TTY; else echo PTY-CONTAINER-NOTTY; fi",
        ]);
        s.cwd = PathBuf::from("/");
        s.sandbox = Backend::Container;

        let session = match PtySession::spawn(&s, PtyWinsize::default()) {
            Ok(session) => session,
            Err(e) => {
                // The default image may not be locally runnable even though the
                // probe found a different one; never fail on environment gaps.
                eprintln!("skipping: could not spawn container PTY session: {e}");
                return;
            }
        };
        let (status, output) = run_and_collect(session);

        if !status.success() {
            eprintln!("skipping: container session did not run cleanly: {output:?}");
            return;
        }
        assert!(
            output.contains("PTY-CONTAINER-TTY"),
            "container PTY session was not interactive (no in-container TTY): {output:?}"
        );
        assert!(
            !output.contains("PTY-CONTAINER-NOTTY"),
            "container PTY session ran without a TTY inside the container: {output:?}"
        );
    }
}
