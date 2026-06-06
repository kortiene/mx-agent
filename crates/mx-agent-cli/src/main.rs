//! The `mx-agent` command-line interface.
//!
//! The command surface is defined in [`cli`]. The CLI is stateless: every
//! Matrix-backed command is sent to the long-running daemon over the local
//! Unix-socket IPC channel, so the CLI never reads the Matrix session or builds
//! a Matrix client itself. A few advanced flows (interactive PTY `exec`, large
//! artifacts) are still landing — see the project status in `README.md`.

mod cli;
mod stream;
mod terminal;

use std::process::ExitCode;

fn main() -> ExitCode {
    cli::run()
}
