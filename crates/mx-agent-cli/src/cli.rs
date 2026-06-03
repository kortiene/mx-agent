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
    /// Start the daemon.
    Start(DaemonStartArgs),
    /// Report daemon status.
    Status,
    /// Stop the daemon.
    Stop,
}

#[derive(Debug, Args)]
struct DaemonStartArgs {
    /// Run in the foreground instead of detaching into the background.
    #[arg(long)]
    foreground: bool,
}

#[derive(Debug, Subcommand)]
enum AuthCommand {
    /// Log in to a Matrix homeserver.
    Login(AuthLoginArgs),
    /// Show authentication status.
    Status,
    /// Log out and clear the local session.
    Logout,
}

#[derive(Debug, Args)]
struct AuthLoginArgs {
    /// Homeserver base URL, e.g. `https://matrix.org`.
    #[arg(long, value_name = "URL")]
    homeserver: String,
    /// Matrix user localpart or full user ID.
    #[arg(long, value_name = "USER")]
    user: String,
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

/// Map repeated `-v` flags to a default log filter directive.
fn verbosity_directive(verbose: u8) -> &'static str {
    match verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    }
}

/// Parse arguments and dispatch. Returns the process exit code.
pub fn run() -> ExitCode {
    let cli = Cli::parse();
    let g = &cli.global;

    // Best-effort: logging is a diagnostic aid, never fatal to set up.
    let _ = mx_agent_telemetry::init(verbosity_directive(g.verbose));

    let path = command_path(&cli.command);
    tracing::debug!(
        command = %path,
        json = g.json,
        verbose = g.verbose,
        config = ?g.config,
        socket = ?g.socket,
        "dispatching command"
    );

    match &cli.command {
        Command::Daemon(cmd) => handle_daemon(g, cmd),
        Command::Auth(cmd) => handle_auth(g, cmd),
        _ => unimplemented(g, &path),
    }
}

/// Environment variable used to pass the login password without exposing it on
/// the command line (where it could be captured in shell history or `ps`).
const ENV_PASSWORD: &str = "MX_AGENT_PASSWORD";

/// Handle the `auth` command group.
fn handle_auth(global: &GlobalArgs, cmd: &AuthCommand) -> ExitCode {
    match cmd {
        AuthCommand::Login(args) => auth_login(global, args),
        AuthCommand::Status => auth_status(global),
        AuthCommand::Logout => auth_logout(global),
    }
}

/// Read the login password from `MX_AGENT_PASSWORD`, or prompt on stdin.
///
/// The password is never echoed back, logged, or passed as an argument.
fn read_password() -> std::io::Result<String> {
    if let Ok(pw) = std::env::var(ENV_PASSWORD) {
        if !pw.is_empty() {
            return Ok(pw);
        }
    }
    eprint!("Matrix password: ");
    use std::io::Write;
    std::io::stderr().flush()?;
    let mut pw = String::new();
    std::io::stdin().read_line(&mut pw)?;
    Ok(pw.trim_end_matches(['\n', '\r']).to_string())
}

fn auth_login(global: &GlobalArgs, args: &AuthLoginArgs) -> ExitCode {
    let config = mx_agent_daemon::MatrixConfig {
        homeserver_url: args.homeserver.clone(),
    };
    if let Err(e) = config.validate() {
        eprintln!("mx-agent: {e}");
        return ExitCode::FAILURE;
    }

    let password = match read_password() {
        Ok(pw) if !pw.is_empty() => pw,
        Ok(_) => {
            eprintln!(
                "mx-agent: no password provided; set {ENV_PASSWORD} or enter it when prompted"
            );
            return ExitCode::FAILURE;
        }
        Err(e) => {
            eprintln!("mx-agent: could not read password: {e}");
            return ExitCode::FAILURE;
        }
    };

    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("mx-agent: could not start async runtime: {e}");
            return ExitCode::FAILURE;
        }
    };

    let result = runtime.block_on(mx_agent_daemon::login_password(
        &config, &args.user, &password,
    ));
    // Drop the password as soon as login finishes.
    drop(password);

    match result {
        Ok(session) => {
            let paths = mx_agent_daemon::SessionPaths::resolve();
            if let Err(e) = mx_agent_daemon::save_session(&paths, &session) {
                eprintln!("mx-agent: login succeeded but saving the session failed: {e}");
                return ExitCode::FAILURE;
            }
            let status = mx_agent_daemon::AuthStatus::from_session(&session);
            if global.json {
                println!("{}", status.to_json());
            } else {
                println!("mx-agent: logged in as {}", session.user_id);
                println!("  device: {}", session.device_id);
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("mx-agent: login failed: {e}");
            ExitCode::FAILURE
        }
    }
}

fn auth_status(global: &GlobalArgs) -> ExitCode {
    let paths = mx_agent_daemon::SessionPaths::resolve();
    match mx_agent_daemon::auth_status(&paths) {
        Ok(status) => {
            if global.json {
                println!("{}", status.to_json());
            } else if status.logged_in {
                println!("mx-agent: logged in");
                if let Some(user) = &status.user_id {
                    println!("  user:       {user}");
                }
                if let Some(device) = &status.device_id {
                    println!("  device:     {device}");
                }
                if let Some(hs) = &status.homeserver {
                    println!("  homeserver: {hs}");
                }
            } else {
                println!("mx-agent: not logged in");
            }
            if status.logged_in {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(3)
            }
        }
        Err(e) => {
            eprintln!("mx-agent: could not read auth status: {e}");
            ExitCode::FAILURE
        }
    }
}

fn auth_logout(global: &GlobalArgs) -> ExitCode {
    let paths = mx_agent_daemon::SessionPaths::resolve();
    match mx_agent_daemon::clear_session(&paths) {
        Ok(()) => {
            if global.json {
                println!("{{\"logged_in\":false}}");
            } else {
                println!("mx-agent: logged out");
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("mx-agent: could not clear session: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Handle the `daemon` command group.
fn handle_daemon(global: &GlobalArgs, cmd: &DaemonCommand) -> ExitCode {
    match cmd {
        DaemonCommand::Start(args) => daemon_start(global, args.foreground),
        DaemonCommand::Status => daemon_status(global),
        DaemonCommand::Stop => daemon_stop(global),
    }
}

fn daemon_start(global: &GlobalArgs, foreground: bool) -> ExitCode {
    if foreground {
        return match mx_agent_daemon::run_foreground() {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("mx-agent: daemon failed: {e}");
                ExitCode::FAILURE
            }
        };
    }

    match mx_agent_daemon::status() {
        Ok(Some(running)) => {
            if global.json {
                println!("{}", running.to_json());
            } else {
                println!("mx-agent daemon already running (pid {})", running.pid);
            }
            ExitCode::SUCCESS
        }
        Ok(None) => match mx_agent_daemon::start_background() {
            Ok(running) => {
                if global.json {
                    println!("{}", running.to_json());
                } else {
                    println!("mx-agent daemon started (pid {})", running.pid);
                }
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("mx-agent: could not start daemon: {e}");
                ExitCode::FAILURE
            }
        },
        Err(e) => {
            eprintln!("mx-agent: could not read daemon status: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Query the live status of a running daemon over IPC, falling back to `None`
/// if the daemon cannot be reached.
fn query_status_over_ipc(socket_path: &str) -> Option<mx_agent_daemon::RunningStatus> {
    let mut client = mx_agent_ipc::Client::connect(socket_path).ok()?;
    let response = client.call("daemon.status", serde_json::Value::Null).ok()?;
    let result = response.result?;
    serde_json::from_value(result).ok()
}

fn daemon_status(global: &GlobalArgs) -> ExitCode {
    match mx_agent_daemon::status() {
        Ok(Some(file_status)) => {
            // Prefer the daemon's live status over IPC; fall back to the status
            // file if the socket cannot be reached.
            let running = query_status_over_ipc(&file_status.socket_path).unwrap_or(file_status);
            if global.json {
                println!("{}", running.to_json());
            } else {
                println!("mx-agent daemon: running");
                println!("  pid:     {}", running.pid);
                println!("  uptime:  {}s", running.uptime_seconds);
                println!("  socket:  {}", running.socket_path);
                println!("  version: {}", running.version);
                if let Some(sync) = &running.sync {
                    println!("  sync:    {:?}", sync.state);
                    println!("    syncs:    {}", sync.total_syncs);
                    if sync.consecutive_failures > 0 {
                        println!("    failures: {}", sync.consecutive_failures);
                    }
                    if let Some(err) = &sync.last_error {
                        println!("    last err: {err}");
                    }
                }
            }
            ExitCode::SUCCESS
        }
        Ok(None) => {
            if global.json {
                println!("{{\"running\":false}}");
            } else {
                println!("mx-agent daemon: not running");
            }
            // Distinct nonzero code so scripts can detect a stopped daemon.
            ExitCode::from(3)
        }
        Err(e) => {
            eprintln!("mx-agent: could not read daemon status: {e}");
            ExitCode::FAILURE
        }
    }
}

fn daemon_stop(global: &GlobalArgs) -> ExitCode {
    use mx_agent_daemon::StopOutcome;
    match mx_agent_daemon::stop(std::time::Duration::from_secs(5)) {
        Ok(outcome) => {
            let (msg, json) = match outcome {
                StopOutcome::NotRunning => (
                    "mx-agent daemon: not running".to_string(),
                    "{\"stopped\":false,\"running\":false}".to_string(),
                ),
                StopOutcome::Stopped(pid) => (
                    format!("mx-agent daemon stopped (pid {pid})"),
                    format!("{{\"stopped\":true,\"pid\":{pid}}}"),
                ),
                StopOutcome::Killed(pid) => (
                    format!("mx-agent daemon force-killed (pid {pid})"),
                    format!("{{\"stopped\":true,\"killed\":true,\"pid\":{pid}}}"),
                ),
            };
            if global.json {
                println!("{json}");
            } else {
                println!("{msg}");
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("mx-agent: could not stop daemon: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Build a dotted path string identifying the invoked command.
fn command_path(command: &Command) -> String {
    match command {
        Command::Daemon(c) => format!(
            "daemon {}",
            match c {
                DaemonCommand::Start(_) => "start",
                DaemonCommand::Status => "status",
                DaemonCommand::Stop => "stop",
            }
        ),
        Command::Auth(c) => format!(
            "auth {}",
            match c {
                AuthCommand::Login(_) => "login",
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
    fn auth_login_requires_homeserver_and_user() {
        // Both flags are required.
        assert!(Cli::try_parse_from(["mx-agent", "auth", "login"]).is_err());
        let cli = Cli::try_parse_from([
            "mx-agent",
            "auth",
            "login",
            "--homeserver",
            "https://matrix.org",
            "--user",
            "alice",
        ])
        .unwrap();
        assert_eq!(command_path(&cli.command), "auth login");
    }

    #[test]
    fn unknown_command_is_rejected() {
        let err = Cli::try_parse_from(["mx-agent", "definitely-not-a-command"]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::InvalidSubcommand);
    }
}
