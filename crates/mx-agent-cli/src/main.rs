//! The `mx-agent` command-line interface.
//!
//! The command surface is defined in [`cli`]. At this stage (issue #4) the
//! subcommands are placeholders that parse arguments and report that the
//! operation is not implemented yet; behavior arrives in later roadmap phases.

mod cli;
mod stream;

use std::process::ExitCode;

fn main() -> ExitCode {
    cli::run()
}
