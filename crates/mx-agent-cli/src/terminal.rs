//! Local terminal state for interactive `exec --pty`, and the Ctrl-C / signal
//! semantics that come with it.
//!
//! Interactive PTY exec puts the local terminal into **raw mode** so that every
//! keystroke — ordinary characters and control characters alike — is delivered
//! to the remote PTY byte-for-byte instead of being interpreted locally. This
//! module owns that mode change and, crucially, guarantees the terminal is put
//! back the way it was found.
//!
//! ## Ctrl-C and control-character semantics
//!
//! Raw mode clears the terminal's `ISIG` flag (among others; see
//! [`rustix::termios::Termios::make_raw`]). With `ISIG` off the local line
//! discipline no longer turns Ctrl-C into a local `SIGINT`: instead the literal
//! byte `0x03` is forwarded over stdin to the **remote** PTY, whose own line
//! discipline raises `SIGINT` in the remote foreground process group. The same
//! is true of Ctrl-\ (`SIGQUIT`, `0x1c`), Ctrl-Z (`SIGTSTP`, `0x1a`), and the
//! other control characters: they act on the *remote* program, exactly as if
//! the user were sitting at the remote terminal. The local `mx-agent` process
//! is deliberately **not** interrupted by Ctrl-C while a PTY session is live.
//!
//! When the remote program dies from such a signal, its exit is reported as the
//! conventional `128 + signum` (architecture §5.3): a remote process killed by
//! Ctrl-C therefore yields local exit code `130`.
//!
//! Outside `--pty` (the non-interactive `exec` path) the local terminal stays
//! in its normal cooked mode, so Ctrl-C raises `SIGINT` locally and terminates
//! `mx-agent` itself with exit code `130`.
//!
//! ## Restoring the terminal after failure
//!
//! Leaving the terminal in raw mode after exit is a classic footgun: the user's
//! shell comes back with no echo and no line editing. [`RawModeGuard`] restores
//! the saved settings on `Drop`, which covers a normal return, an early error
//! return, and a panic unwind. The remaining hole is **signal-triggered
//! death**: a `SIGTERM`/`SIGHUP` (e.g. the controlling terminal closing) kills
//! the process without running any `Drop`, which would strand the terminal in
//! raw mode. To close it, activating raw mode also installs a one-shot
//! background thread that, on receiving a terminating signal, restores the
//! terminal and then exits with the conventional `128 + signum` code. The saved
//! settings are cleared on clean drop so the handler never touches a terminal we
//! have already restored.
//!
//! ## Manual test (acceptance: Ctrl-C documented and tested manually)
//!
//! 1. `cargo run -p mx-agent-cli -- exec --pty -- bash`
//! 2. Run a foreground program, e.g. `sleep 100`, and press **Ctrl-C**. The
//!    `sleep` is interrupted but the `bash` session (and `mx-agent`) keep
//!    running — proof that Ctrl-C reached the remote, not the local CLI.
//! 3. Run `cat` (no args) and press **Ctrl-C**: `cat` exits; `bash` survives.
//! 4. Exit the shell (`exit` or Ctrl-D). Confirm your prompt has working echo
//!    and line editing — the terminal was restored.
//! 5. Repeat, but this time kill the CLI from another shell with
//!    `kill -TERM <pid>` while the PTY is live. Confirm the terminal is *still*
//!    restored (echo/line editing work) — the signal-restore path ran.

#[cfg(unix)]
pub use imp::{signal_exit_code, RawModeGuard};

#[cfg(unix)]
mod imp {
    use std::io;
    use std::sync::{Mutex, OnceLock};

    use rustix::termios::{isatty, tcgetattr, tcsetattr, OptionalActions, Termios};

    /// Process-global copy of the pre-raw terminal settings. Holds a value only
    /// while raw mode is engaged; the signal-restore thread consults it to put
    /// the terminal back before the process dies. Cleared on clean drop.
    fn saved() -> &'static Mutex<Option<Termios>> {
        static SAVED: OnceLock<Mutex<Option<Termios>>> = OnceLock::new();
        SAVED.get_or_init(|| Mutex::new(None))
    }

    /// Record (or clear) the settings the signal handler should restore.
    fn store_saved(termios: Option<Termios>) {
        // A poisoned lock is harmless here: the only data is the saved settings,
        // and restoring stale-but-valid settings is still correct.
        *saved().lock().unwrap_or_else(|e| e.into_inner()) = termios;
    }

    /// Restore the saved settings to stdin, if any. Idempotent: safe to call
    /// from the signal thread and from `Drop`, in any order.
    fn restore_saved() {
        let guard = saved().lock().unwrap_or_else(|e| e.into_inner());
        if let Some(termios) = guard.as_ref() {
            let _ = tcsetattr(io::stdin(), OptionalActions::Flush, termios);
        }
    }

    /// The conventional shell exit code for death by `signum`: `128 + signum`
    /// (architecture §5.3).
    pub fn signal_exit_code(signum: i32) -> i32 {
        128 + signum
    }

    /// Install, at most once per process, a background thread that restores the
    /// terminal and exits with `128 + signum` when a terminating signal arrives.
    ///
    /// Without this a `SIGTERM`/`SIGHUP` (or `SIGINT`/`SIGQUIT` should raw mode
    /// have failed to engage) would kill the CLI without running
    /// [`RawModeGuard::drop`], leaving the user's shell echo-less and uncooked.
    fn install_signal_restore() {
        static INSTALLED: OnceLock<()> = OnceLock::new();
        INSTALLED.get_or_init(|| {
            use signal_hook::consts::{SIGHUP, SIGINT, SIGQUIT, SIGTERM};
            use signal_hook::iterator::Signals;

            if let Ok(mut signals) = Signals::new([SIGINT, SIGTERM, SIGHUP, SIGQUIT]) {
                std::thread::spawn(move || {
                    if let Some(signum) = signals.forever().next() {
                        restore_saved();
                        std::process::exit(signal_exit_code(signum));
                    }
                });
            }
        });
    }

    /// Puts the local terminal into raw mode and guarantees its original
    /// settings are restored — on normal drop, on panic unwind, and (via the
    /// installed signal handler) on signal-triggered termination.
    pub struct RawModeGuard {
        original: Termios,
    }

    impl RawModeGuard {
        /// Put the local terminal (stdin) into raw mode, returning a guard that
        /// restores it on drop. Returns `None` when stdin is not a terminal or
        /// the mode could not be changed, in which case input is left as-is and
        /// no signal handler is installed (there is nothing to restore).
        pub fn activate() -> Option<RawModeGuard> {
            let stdin = io::stdin();
            if !isatty(&stdin) {
                return None;
            }
            let original = tcgetattr(&stdin).ok()?;
            let mut raw = original.clone();
            raw.make_raw();
            tcsetattr(&stdin, OptionalActions::Flush, &raw).ok()?;
            // Publish the pre-raw settings before arming the signal handler so a
            // signal that lands immediately still has something to restore.
            store_saved(Some(original.clone()));
            install_signal_restore();
            Some(RawModeGuard { original })
        }
    }

    impl Drop for RawModeGuard {
        fn drop(&mut self) {
            let _ = tcsetattr(io::stdin(), OptionalActions::Flush, &self.original);
            // Disarm the signal handler's restore: we have already put the
            // terminal back and may no longer own it.
            store_saved(None);
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use rustix::termios::LocalModes;
        use std::fs::File;

        #[test]
        fn signal_exit_code_follows_shell_convention() {
            // Architecture §5.3: death by signal reports 128 + signum, so a
            // Ctrl-C'd (SIGINT, 2) remote process maps to 130.
            assert_eq!(signal_exit_code(2), 130);
            assert_eq!(signal_exit_code(15), 143); // SIGTERM
            assert_eq!(signal_exit_code(9), 137); // SIGKILL
        }

        #[test]
        fn store_and_clear_saved_settings_round_trip() {
            // The saved-settings slot is what the signal handler restores from:
            // it must hold a value while armed and be clearable on teardown.
            // Requires a real terminal to obtain a Termios; skipped otherwise
            // (e.g. CI with no controlling tty).
            let Ok(tty) = File::open("/dev/tty") else {
                return;
            };
            if !isatty(&tty) {
                return;
            }
            let Ok(termios) = tcgetattr(&tty) else {
                return;
            };
            store_saved(Some(termios));
            assert!(saved().lock().unwrap().is_some());
            store_saved(None);
            assert!(saved().lock().unwrap().is_none());
        }

        #[test]
        fn raw_mode_disables_local_signal_generation() {
            // The heart of the Ctrl-C semantics: raw mode clears ISIG (and the
            // canonical/echo flags) so control characters are forwarded to the
            // remote instead of being interpreted locally. Needs a real tty for
            // a baseline Termios; skipped where none is available.
            let Ok(tty) = File::open("/dev/tty") else {
                return;
            };
            if !isatty(&tty) {
                return;
            }
            let Ok(original) = tcgetattr(&tty) else {
                return;
            };
            let mut raw = original.clone();
            raw.make_raw();
            assert!(
                !raw.local_modes.contains(LocalModes::ISIG),
                "raw mode must clear ISIG so Ctrl-C is forwarded, not interpreted"
            );
            assert!(!raw.local_modes.contains(LocalModes::ICANON));
            assert!(!raw.local_modes.contains(LocalModes::ECHO));
        }
    }
}
