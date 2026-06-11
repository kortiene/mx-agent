//! The `mx-agent` command-line interface.
//!
//! The command surface is defined in [`cli`]. The CLI is stateless: the
//! daemon-mediated command groups are sent to the long-running daemon over the
//! local Unix-socket IPC channel, so for those the CLI never reads the Matrix
//! session or builds a Matrix client itself. The `auth`/`trust` carve-out is the
//! exception — `auth login` builds a store-backed client and creates the
//! daemon-owned crypto store in-process, and the local `auth`/`trust` commands
//! touch the data dir directly (same-binary, same-UID; see `docs/architecture.md`
//! §10.3). A few advanced flows (interactive PTY `exec`, large artifacts) are
//! still landing — see the project status in `README.md`.

mod cli;
mod stream;
mod terminal;

use std::process::ExitCode;

fn main() -> ExitCode {
    cli::run()
}
