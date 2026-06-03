//! Command-line surface for `mx-agent`.
//!
//! This module defines the full command tree with `clap`. Subcommands are
//! placeholders at this stage (issue #4): they parse arguments and report that
//! the operation is not implemented yet. Behavior is filled in by later roadmap
//! phases.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{ArgAction, Args, Parser, Subcommand};

/// Top-level parser for the `mx-agent` binary.
#[derive(Debug, Parser)]
#[command(
    name = "mx-agent",
    version,
    about = "Matrix-backed CLI for decentralized orchestration between coding agents",
    arg_required_else_help = true,
    propagate_version = true
)]
struct Cli {
    #[command(flatten)]
    global: GlobalArgs,

    #[command(subcommand)]
    command: Command,
}

/// Global options accepted alongside any subcommand.
#[derive(Debug, Args)]
struct GlobalArgs {
    /// Emit machine-readable JSON instead of human-readable text.
    #[arg(long, global = true)]
    json: bool,

    /// Path to the configuration file.
    #[arg(long, global = true, value_name = "PATH")]
    config: Option<PathBuf>,

    /// Path to the daemon IPC socket.
    #[arg(long, global = true, value_name = "PATH")]
    socket: Option<PathBuf>,

    /// Increase logging verbosity (repeatable).
    #[arg(short, long, global = true, action = ArgAction::Count)]
    verbose: u8,
}

/// Top-level command groups.
#[derive(Debug, Subcommand)]
enum Command {
    /// Manage the local background daemon.
    #[command(subcommand)]
    Daemon(DaemonCommand),

    /// Manage Matrix authentication.
    #[command(subcommand)]
    Auth(AuthCommand),

    /// Create, join, and inspect Matrix workspaces.
    #[command(subcommand)]
    Workspace(WorkspaceCommand),

    /// Register and discover agents.
    #[command(subcommand)]
    Agent(AgentCommand),

    /// Invoke a named tool on a remote agent.
    Call(CallArgs),

    /// Run a command on a remote agent.
    Exec(ExecArgs),

    /// Broadcast context (diffs, environment, files).
    #[command(subcommand)]
    Share(ShareCommand),

    /// Manage the distributed task DAG.
    #[command(subcommand)]
    Task(TaskCommand),

    /// Inspect and cancel running invocations.
    #[command(subcommand)]
    Invocation(InvocationCommand),

    /// Review and decide pending approval requests.
    #[command(subcommand)]
    Approval(ApprovalCommand),

    /// Manage trusted agent signing keys.
    #[command(subcommand)]
    Trust(TrustCommand),
}

#[derive(Debug, Subcommand)]
enum DaemonCommand {
    /// Start the background daemon.
    Start,
    /// Report daemon status.
    Status,
    /// Stop the background daemon.
    Stop,
}

#[derive(Debug, Subcommand)]
enum AuthCommand {
    /// Log in to a Matrix homeserver.
    Login,
    /// Show authentication status.
    Status,
    /// Log out and clear the local session.
    Logout,
}

#[derive(Debug, Subcommand)]
enum WorkspaceCommand {
    /// Create a new workspace room.
    Create,
    /// Join an existing workspace room.
    Join,
    /// Attach the current directory to a workspace.
    Attach,
    /// Show workspace status.
    Status,
}

#[derive(Debug, Subcommand)]
enum AgentCommand {
    /// Register the current agent session.
    Register,
    /// List agents in a workspace.
    List,
    /// Show details for one agent.
    Show,
    /// List tools offered by an agent.
    Tools,
}

#[derive(Debug, Args)]
struct CallArgs {
    /// Workspace room to target.
    #[arg(long)]
    room: Option<String>,
    /// Target agent name.
    #[arg(long)]
    agent: Option<String>,
    /// Named tool to invoke.
    #[arg(long)]
    tool: Option<String>,
    /// Tool argument as `key=value` (repeatable).
    #[arg(long = "arg", value_name = "KEY=VALUE")]
    args: Vec<String>,
}

#[derive(Debug, Args)]
struct ExecArgs {
    /// Workspace room to target.
    #[arg(long)]
    room: Option<String>,
    /// Target agent name.
    #[arg(long)]
    agent: Option<String>,
    /// Working directory on the remote agent.
    #[arg(long)]
    cwd: Option<PathBuf>,
    /// Associate this execution with a task ID.
    #[arg(long)]
    task: Option<String>,
    /// Stream stdout/stderr live.
    #[arg(long)]
    stream: bool,
    /// Allocate a pseudo-terminal.
    #[arg(long)]
    pty: bool,
    /// Forward local stdin to the remote command.
    #[arg(long)]
    stdin: bool,
    /// Command and arguments to run (after `--`).
    #[arg(trailing_var_arg = true, value_name = "COMMAND")]
    command: Vec<String>,
}

#[derive(Debug, Subcommand)]
enum ShareCommand {
    /// Share a git diff.
    Diff,
    /// Share environment metadata.
    Env,
    /// Share a file or piped content.
    File,
}

#[derive(Debug, Subcommand)]
enum TaskCommand {
    /// Create a task.
    Create,
    /// Update a task.
    Update,
    /// List tasks.
    List,
    /// Render the task dependency graph.
    Graph,
    /// Watch task state changes.
    Watch,
}

#[derive(Debug, Subcommand)]
enum InvocationCommand {
    /// List invocations.
    List,
    /// Show one invocation.
    Show,
    /// Cancel a running invocation.
    Cancel,
}

#[derive(Debug, Subcommand)]
enum ApprovalCommand {
    /// List pending approval requests.
    List,
    /// Show one approval request.
    Show,
    /// Approve a request.
    Approve,
    /// Deny a request.
    Deny,
}

#[derive(Debug, Subcommand)]
enum TrustCommand {
    /// List trusted keys.
    List,
    /// Show the local signing key fingerprint.
    Fingerprint,
    /// Approve an agent signing key.
    Approve,
    /// Revoke an agent signing key.
    Revoke,
}

/// Parse arguments and dispatch. Returns the process exit code.
pub fn run() -> ExitCode {
    let cli = Cli::parse();
    let g = &cli.global;

    if g.verbose > 0 {
        eprintln!(
            "mx-agent: verbose={} json={} config={:?} socket={:?}",
            g.verbose, g.json, g.config, g.socket
        );
    }

    let path = command_path(&cli.command);
    unimplemented(g, &path)
}

/// Build a dotted path string identifying the invoked command.
fn command_path(command: &Command) -> String {
    match command {
        Command::Daemon(c) => format!(
            "daemon {}",
            match c {
                DaemonCommand::Start => "start",
                DaemonCommand::Status => "status",
                DaemonCommand::Stop => "stop",
            }
        ),
        Command::Auth(c) => format!(
            "auth {}",
            match c {
                AuthCommand::Login => "login",
                AuthCommand::Status => "status",
                AuthCommand::Logout => "logout",
            }
        ),
        Command::Workspace(c) => format!(
            "workspace {}",
            match c {
                WorkspaceCommand::Create => "create",
                WorkspaceCommand::Join => "join",
                WorkspaceCommand::Attach => "attach",
                WorkspaceCommand::Status => "status",
            }
        ),
        Command::Agent(c) => format!(
            "agent {}",
            match c {
                AgentCommand::Register => "register",
                AgentCommand::List => "list",
                AgentCommand::Show => "show",
                AgentCommand::Tools => "tools",
            }
        ),
        Command::Call(_) => "call".to_string(),
        Command::Exec(_) => "exec".to_string(),
        Command::Share(c) => format!(
            "share {}",
            match c {
                ShareCommand::Diff => "diff",
                ShareCommand::Env => "env",
                ShareCommand::File => "file",
            }
        ),
        Command::Task(c) => format!(
            "task {}",
            match c {
                TaskCommand::Create => "create",
                TaskCommand::Update => "update",
                TaskCommand::List => "list",
                TaskCommand::Graph => "graph",
                TaskCommand::Watch => "watch",
            }
        ),
        Command::Invocation(c) => format!(
            "invocation {}",
            match c {
                InvocationCommand::List => "list",
                InvocationCommand::Show => "show",
                InvocationCommand::Cancel => "cancel",
            }
        ),
        Command::Approval(c) => format!(
            "approval {}",
            match c {
                ApprovalCommand::List => "list",
                ApprovalCommand::Show => "show",
                ApprovalCommand::Approve => "approve",
                ApprovalCommand::Deny => "deny",
            }
        ),
        Command::Trust(c) => format!(
            "trust {}",
            match c {
                TrustCommand::List => "list",
                TrustCommand::Fingerprint => "fingerprint",
                TrustCommand::Approve => "approve",
                TrustCommand::Revoke => "revoke",
            }
        ),
    }
}

/// Report that a recognized command is not implemented yet.
fn unimplemented(global: &GlobalArgs, path: &str) -> ExitCode {
    if global.json {
        println!("{{\"status\":\"unimplemented\",\"command\":\"{path}\"}}");
    } else {
        eprintln!("mx-agent: '{path}' is recognized but not implemented yet");
    }
    // Exit code 64 (EX_USAGE-adjacent) signals "recognized but unavailable"
    // without colliding with clap's usage-error code (2).
    ExitCode::from(64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        // Panics if the derived command tree is malformed.
        Cli::command().debug_assert();
    }

    #[test]
    fn all_top_level_groups_are_present() {
        let cmd = Cli::command();
        let names: Vec<_> = cmd.get_subcommands().map(|c| c.get_name()).collect();
        for expected in [
            "daemon",
            "auth",
            "workspace",
            "agent",
            "call",
            "exec",
            "share",
            "task",
            "invocation",
            "approval",
            "trust",
        ] {
            assert!(
                names.contains(&expected),
                "missing command group: {expected}"
            );
        }
    }

    #[test]
    fn command_path_renders_subcommands() {
        let cli = Cli::try_parse_from(["mx-agent", "daemon", "status"]).unwrap();
        assert_eq!(command_path(&cli.command), "daemon status");

        let cli = Cli::try_parse_from(["mx-agent", "exec", "--agent", "pi", "--", "npm", "test"])
            .unwrap();
        assert_eq!(command_path(&cli.command), "exec");
    }

    #[test]
    fn global_flags_parse_after_subcommand() {
        let cli = Cli::try_parse_from(["mx-agent", "agent", "list", "--json", "-vv"]).unwrap();
        assert!(cli.global.json);
        assert_eq!(cli.global.verbose, 2);
    }

    #[test]
    fn unknown_command_is_rejected() {
        let err = Cli::try_parse_from(["mx-agent", "definitely-not-a-command"]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::InvalidSubcommand);
    }
}
