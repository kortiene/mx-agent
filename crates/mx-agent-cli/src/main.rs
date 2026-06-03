//! The `mx-agent` command-line interface.
//!
//! This is a placeholder entry point established by the workspace bootstrap
//! (issue #2). The full `clap`-based command surface is implemented in a later
//! phase (issue #3). For now it prints placeholder help and version output so
//! the binary and its `--help` behavior exist end to end.

use std::process::ExitCode;

const NAME: &str = env!("CARGO_PKG_NAME");
const VERSION: &str = env!("CARGO_PKG_VERSION");

const HELP_BODY: &str = "\
mx-agent is a Matrix-backed CLI for decentralized orchestration between
autonomous coding agents. This is a placeholder build; commands are not yet
implemented.

USAGE:
    mx-agent <COMMAND> [OPTIONS]

PLANNED COMMANDS:
    workspace     Create, join, and inspect Matrix workspaces
    agent         Register and discover agents
    exec          Run a command on a remote agent
    call          Invoke a named tool on a remote agent
    share         Broadcast context (diffs, env, files)
    task          Manage the distributed task DAG
    invocation    Inspect and cancel running invocations
    approval      Review and decide pending approval requests
    trust         Manage trusted agent signing keys
    daemon        Manage the local background daemon
    auth          Manage Matrix authentication

OPTIONS:
    -h, --help       Print this help
    -V, --version    Print version

See https://github.com/kortiene/mx-agent for documentation.
";

fn print_help() {
    println!(
        "mx-agent {VERSION} (protocol {proto})\n",
        proto = mx_agent_protocol::protocol_version(),
    );
    print!("{HELP_BODY}");
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();

    match args.first().map(String::as_str) {
        None | Some("-h") | Some("--help") | Some("help") => {
            print_help();
            ExitCode::SUCCESS
        }
        Some("-V") | Some("--version") | Some("version") => {
            println!("{NAME} {VERSION}");
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("mx-agent: command '{other}' is not implemented yet.\n");
            print_help();
            ExitCode::from(2)
        }
    }
}
