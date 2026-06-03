//! Command-line surface for `mx-agent`.
//!
//! This module defines the full command tree with `clap`. Subcommands are
//! placeholders at this stage (issue #4): they parse arguments and report that
//! the operation is not implemented yet. Behavior is filled in by later roadmap
//! phases.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{ArgAction, Args, Parser, Subcommand, ValueEnum};

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
    Create(WorkspaceCreateArgs),
    /// Join an existing workspace room.
    Join(WorkspaceJoinArgs),
    /// Attach the current directory to a workspace.
    Attach(WorkspaceAttachArgs),
    /// Show workspace status.
    Status(WorkspaceStatusArgs),
}

/// Room privacy for `workspace create`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Visibility {
    /// Invite-only; hidden from the public room directory.
    Private,
    /// Publicly joinable and listed in the room directory.
    Public,
}

#[derive(Debug, Args)]
struct WorkspaceCreateArgs {
    /// Room alias localpart, e.g. `my-project` for `#my-project:server`.
    #[arg(long, value_name = "ALIAS")]
    alias: Option<String>,
    /// Human-readable room name.
    #[arg(long, value_name = "NAME")]
    name: Option<String>,
    /// Room topic.
    #[arg(long, value_name = "TOPIC")]
    topic: Option<String>,
    /// Room visibility (privacy).
    #[arg(long, value_enum, default_value_t = Visibility::Private)]
    visibility: Visibility,
}

#[derive(Debug, Args)]
struct WorkspaceJoinArgs {
    /// Room alias (`#name:server`) or room ID (`!id:server`) to join.
    #[arg(value_name = "ROOM")]
    room: String,
}

#[derive(Debug, Args)]
struct WorkspaceAttachArgs {
    /// Room alias (`#name:server`) or room ID (`!id:server`) to attach to.
    #[arg(long, value_name = "ROOM")]
    room: String,
    /// Local path to attach (defaults to the current directory).
    #[arg(long, value_name = "PATH")]
    path: Option<PathBuf>,
    /// Project identifier, e.g. `repo:github.com/org/project`.
    #[arg(long = "project-id", value_name = "PROJECT_ID")]
    project_id: String,
}

#[derive(Debug, Args)]
struct WorkspaceStatusArgs {
    /// Room alias (`#name:server`) or room ID (`!id:server`) to inspect.
    #[arg(long, value_name = "ROOM")]
    room: String,
}

#[derive(Debug, Subcommand)]
enum AgentCommand {
    /// Register the current agent session.
    Register(AgentRegisterArgs),
    /// List agents in a workspace.
    List(AgentListArgs),
    /// Show details for one agent.
    Show(AgentShowArgs),
    /// List tools offered by an agent.
    Tools(AgentToolsArgs),
}

#[derive(Debug, Args)]
struct AgentListArgs {
    /// Workspace room alias (`#name:server`) or room ID (`!id:server`).
    #[arg(long, value_name = "ROOM")]
    room: String,
    /// Only list agents declaring this capability (repeatable; AND-combined).
    #[arg(long = "capability", value_name = "CAPABILITY")]
    capabilities: Vec<String>,
}

#[derive(Debug, Args)]
struct AgentShowArgs {
    /// Workspace room alias (`#name:server`) or room ID (`!id:server`).
    #[arg(long, value_name = "ROOM")]
    room: String,
    /// Agent identifier to show.
    #[arg(long = "agent-id", value_name = "AGENT_ID")]
    agent_id: String,
}

#[derive(Debug, Args)]
struct AgentToolsArgs {
    /// Workspace room alias (`#name:server`) or room ID (`!id:server`).
    #[arg(long, value_name = "ROOM")]
    room: String,
    /// Agent identifier whose tools to list.
    #[arg(long = "agent-id", value_name = "AGENT_ID")]
    agent_id: String,
}

#[derive(Debug, Args)]
struct AgentRegisterArgs {
    /// Workspace room alias (`#name:server`) or room ID (`!id:server`).
    #[arg(long, value_name = "ROOM")]
    room: String,
    /// Agent identifier (also the state key). Defaults to `<user>-<device>`.
    #[arg(long = "agent-id", value_name = "AGENT_ID")]
    agent_id: Option<String>,
    /// Agent kind, e.g. `pi` or `generic`.
    #[arg(long, value_name = "KIND", default_value = mx_agent_daemon::DEFAULT_AGENT_KIND)]
    kind: String,
    /// Declared capability (repeatable), e.g. `shell`, `edit`, `test`.
    #[arg(long = "capability", value_name = "CAPABILITY")]
    capabilities: Vec<String>,
    /// Available named tool (repeatable), e.g. `run_tests@1.0.0`.
    #[arg(long = "tool", value_name = "TOOL")]
    tools: Vec<String>,
    /// Working directory the agent operates in (defaults to the current dir).
    #[arg(long, value_name = "PATH")]
    cwd: Option<PathBuf>,
    /// Project identifier, e.g. `repo:github.com/org/project`.
    #[arg(long = "project-id", value_name = "PROJECT_ID", default_value = "")]
    project_id: String,
    /// Maximum concurrent invocations the agent will accept.
    #[arg(long = "max-invocations", value_name = "N", default_value_t = mx_agent_daemon::DEFAULT_MAX_INVOCATIONS)]
    max_invocations: u32,
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
        Command::Workspace(cmd) => handle_workspace(g, cmd),
        Command::Agent(cmd) => handle_agent(g, cmd),
        Command::Trust(cmd) => handle_trust(g, cmd),
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

/// Handle the `trust` command group.
fn handle_trust(global: &GlobalArgs, cmd: &TrustCommand) -> ExitCode {
    match cmd {
        TrustCommand::Fingerprint => trust_fingerprint(global),
        _ => unimplemented(global, &format!("trust {}", trust_subcommand_name(cmd))),
    }
}

/// Short name for a trust subcommand, used in diagnostics.
fn trust_subcommand_name(cmd: &TrustCommand) -> &'static str {
    match cmd {
        TrustCommand::List => "list",
        TrustCommand::Fingerprint => "fingerprint",
        TrustCommand::Approve => "approve",
        TrustCommand::Revoke => "revoke",
    }
}

/// Show the local daemon signing key fingerprint, generating the key on first
/// run. The fingerprint is stable across restarts.
fn trust_fingerprint(global: &GlobalArgs) -> ExitCode {
    let paths = mx_agent_daemon::SessionPaths::resolve();
    match mx_agent_daemon::load_or_create_signing_key(&paths) {
        Ok(key) => {
            let fingerprint = key.fingerprint();
            let key_id = key.key_id();
            if global.json {
                let obj = serde_json::json!({
                    "alg": mx_agent_daemon::KEY_ALG,
                    "key_id": key_id,
                    "fingerprint": fingerprint,
                });
                println!("{obj}");
            } else {
                println!("{fingerprint}");
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("mx-agent: could not load signing key: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Handle the `workspace` command group.
fn handle_workspace(global: &GlobalArgs, cmd: &WorkspaceCommand) -> ExitCode {
    match cmd {
        WorkspaceCommand::Create(args) => workspace_create(global, args),
        WorkspaceCommand::Join(args) => workspace_join(global, args),
        WorkspaceCommand::Status(args) => workspace_status(global, args),
        WorkspaceCommand::Attach(args) => workspace_attach(global, args),
    }
}

/// Build a single-threaded async runtime, reporting a clear error on failure.
fn build_runtime() -> Result<tokio::runtime::Runtime, ExitCode> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| {
            eprintln!("mx-agent: could not start async runtime: {e}");
            ExitCode::FAILURE
        })
}

/// Load the persisted Matrix session, reporting a clear error if absent.
fn load_session_or_exit() -> Result<mx_agent_daemon::StoredSession, ExitCode> {
    let paths = mx_agent_daemon::SessionPaths::resolve();
    match mx_agent_daemon::load_session(&paths) {
        Ok(Some(session)) => Ok(session),
        Ok(None) => {
            eprintln!("mx-agent: not logged in; run `mx-agent auth login` first");
            Err(ExitCode::from(3))
        }
        Err(e) => {
            eprintln!("mx-agent: could not read session: {e}");
            Err(ExitCode::FAILURE)
        }
    }
}

/// Print a [`WorkspaceInfo`] and return success.
fn report_workspace_info(global: &GlobalArgs, info: &mx_agent_daemon::WorkspaceInfo, verb: &str) {
    if global.json {
        println!("{}", info.to_json());
    } else {
        println!("mx-agent: {verb} workspace {}", info.room_id);
        if let Some(alias) = &info.canonical_alias {
            println!("  alias:     {alias}");
        }
        if let Some(name) = &info.name {
            println!("  name:      {name}");
        }
        println!("  encrypted: {}", info.encrypted);
        println!("  members:   {}", info.joined_members);
    }
}

fn workspace_create(global: &GlobalArgs, args: &WorkspaceCreateArgs) -> ExitCode {
    let runtime = match build_runtime() {
        Ok(rt) => rt,
        Err(code) => return code,
    };
    let visibility = match args.visibility {
        Visibility::Private => mx_agent_daemon::WorkspaceVisibility::Private,
        Visibility::Public => mx_agent_daemon::WorkspaceVisibility::Public,
    };
    let options = mx_agent_daemon::CreateWorkspaceOptions {
        alias: args.alias.clone(),
        name: args.name.clone(),
        topic: args.topic.clone(),
        visibility,
    };
    let session = match load_session_or_exit() {
        Ok(s) => s,
        Err(code) => return code,
    };

    runtime.block_on(async {
        match mx_agent_daemon::create_workspace_for_session(&session, &options).await {
            Ok(info) => {
                report_workspace_info(global, &info, "created");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("mx-agent: could not create workspace: {e}");
                ExitCode::FAILURE
            }
        }
    })
}

fn workspace_join(global: &GlobalArgs, args: &WorkspaceJoinArgs) -> ExitCode {
    let runtime = match build_runtime() {
        Ok(rt) => rt,
        Err(code) => return code,
    };
    let session = match load_session_or_exit() {
        Ok(s) => s,
        Err(code) => return code,
    };
    runtime.block_on(async {
        match mx_agent_daemon::join_workspace_for_session(&session, &args.room).await {
            Ok(info) => {
                report_workspace_info(global, &info, "joined");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("mx-agent: could not join workspace: {e}");
                ExitCode::FAILURE
            }
        }
    })
}

fn workspace_attach(global: &GlobalArgs, args: &WorkspaceAttachArgs) -> ExitCode {
    let runtime = match build_runtime() {
        Ok(rt) => rt,
        Err(code) => return code,
    };
    let path = match &args.path {
        Some(p) => p.clone(),
        None => match std::env::current_dir() {
            Ok(p) => p,
            Err(e) => {
                eprintln!("mx-agent: could not resolve current directory: {e}");
                return ExitCode::FAILURE;
            }
        },
    };
    let options = mx_agent_daemon::AttachWorkspaceOptions {
        room: args.room.clone(),
        path: path.to_string_lossy().into_owned(),
        project_id: args.project_id.clone(),
    };
    let session = match load_session_or_exit() {
        Ok(s) => s,
        Err(code) => return code,
    };
    runtime.block_on(async {
        match mx_agent_daemon::attach_workspace_for_session(&session, &options).await {
            Ok(state) => {
                if global.json {
                    println!(
                        "{}",
                        serde_json::to_string(&state).unwrap_or_else(|_| "{}".to_string())
                    );
                } else {
                    println!("mx-agent: attached workspace to {}", args.room);
                    println!("  project:   {}", state.project_id);
                    println!("  path:      {}", state.path);
                    if let Some(repo) = &state.repo {
                        if let Some(url) = &repo.remote_url {
                            println!("  remote:    {url}");
                        }
                        if let Some(branch) = &repo.branch {
                            println!("  branch:    {branch}");
                        }
                        if let Some(commit) = &repo.commit {
                            println!("  commit:    {commit}");
                        }
                    }
                }
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("mx-agent: could not attach workspace: {e}");
                ExitCode::FAILURE
            }
        }
    })
}

fn workspace_status(global: &GlobalArgs, args: &WorkspaceStatusArgs) -> ExitCode {
    let runtime = match build_runtime() {
        Ok(rt) => rt,
        Err(code) => return code,
    };
    let session = match load_session_or_exit() {
        Ok(s) => s,
        Err(code) => return code,
    };
    runtime.block_on(async {
        match mx_agent_daemon::workspace_status_for_session(&session, &args.room).await {
            Ok(status) => {
                if global.json {
                    println!("{}", status.to_json());
                } else {
                    println!("Workspace: {}", status.room_id);
                    if let Some(alias) = &status.canonical_alias {
                        println!("  alias:     {alias}");
                    }
                    if let Some(name) = &status.name {
                        println!("  name:      {name}");
                    }
                    if let Some(ws) = &status.workspace {
                        println!("  project:   {}", ws.project_id);
                        println!("  path:      {}", ws.path);
                        if let Some(repo) = &ws.repo {
                            if let Some(url) = &repo.remote_url {
                                println!("  remote:    {url}");
                            }
                            if let Some(branch) = &repo.branch {
                                println!("  branch:    {branch}");
                            }
                            if let Some(commit) = &repo.commit {
                                println!("  commit:    {commit}");
                            }
                        }
                    }
                    println!("  encrypted: {}", status.encrypted);
                    println!(
                        "  members:   {} joined, {} invited",
                        status.joined_members, status.invited_members
                    );
                    for member in &status.members {
                        let label = member.display_name.as_deref().unwrap_or(&member.user_id);
                        println!(
                            "    {:<20} {:<8} {}",
                            label, member.membership, member.user_id
                        );
                    }
                }
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("mx-agent: could not read workspace status: {e}");
                ExitCode::FAILURE
            }
        }
    })
}

/// Handle the `daemon` command group.
fn handle_agent(global: &GlobalArgs, cmd: &AgentCommand) -> ExitCode {
    match cmd {
        AgentCommand::Register(args) => agent_register(global, args),
        AgentCommand::List(args) => agent_list(global, args),
        AgentCommand::Show(args) => agent_show(global, args),
        AgentCommand::Tools(args) => agent_tools(global, args),
    }
}

fn agent_list(global: &GlobalArgs, args: &AgentListArgs) -> ExitCode {
    let runtime = match build_runtime() {
        Ok(rt) => rt,
        Err(code) => return code,
    };
    let options = mx_agent_daemon::ListAgentsOptions {
        room: args.room.clone(),
        capabilities: args.capabilities.clone(),
    };
    let session = match load_session_or_exit() {
        Ok(s) => s,
        Err(code) => return code,
    };
    runtime.block_on(async {
        match mx_agent_daemon::list_agents_for_session(&session, &options).await {
            Ok(agents) => {
                if global.json {
                    println!(
                        "{}",
                        serde_json::to_string(&agents).unwrap_or_else(|_| "[]".to_string())
                    );
                } else if agents.is_empty() {
                    println!("mx-agent: no agents registered in {}", args.room);
                } else {
                    println!("mx-agent: {} agent(s) in {}", agents.len(), args.room);
                    for agent in &agents {
                        let caps = if agent.capabilities.is_empty() {
                            "-".to_string()
                        } else {
                            agent.capabilities.join(",")
                        };
                        println!(
                            "  {:<24} {:<8} {:<8} {}",
                            agent.agent_id, agent.kind, agent.status, caps
                        );
                    }
                }
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("mx-agent: could not list agents: {e}");
                ExitCode::FAILURE
            }
        }
    })
}

fn agent_show(global: &GlobalArgs, args: &AgentShowArgs) -> ExitCode {
    let runtime = match build_runtime() {
        Ok(rt) => rt,
        Err(code) => return code,
    };
    let session = match load_session_or_exit() {
        Ok(s) => s,
        Err(code) => return code,
    };
    runtime.block_on(async {
        match mx_agent_daemon::show_agent_for_session(&session, &args.room, &args.agent_id).await {
            Ok(Some(state)) => {
                if global.json {
                    println!(
                        "{}",
                        serde_json::to_string(&state).unwrap_or_else(|_| "{}".to_string())
                    );
                } else {
                    println!("mx-agent: agent {}", state.agent_id);
                    println!("  kind:         {}", state.kind);
                    println!("  status:       {}", state.status);
                    println!("  user:         {}", state.matrix_user_id);
                    println!("  device:       {}", state.device_id);
                    println!("  cwd:          {}", state.workspace.cwd);
                    if !state.workspace.project_id.is_empty() {
                        println!("  project:      {}", state.workspace.project_id);
                    }
                    if !state.workspace.git_commit.is_empty() {
                        println!("  git commit:   {}", state.workspace.git_commit);
                    }
                    if !state.capabilities.is_empty() {
                        println!("  capabilities: {}", state.capabilities.join(", "));
                    }
                    if !state.tools.is_empty() {
                        println!("  tools:        {}", state.tools.join(", "));
                    }
                    println!(
                        "  load:         {}/{} invocations",
                        state.load.running_invocations, state.load.max_invocations
                    );
                    println!("  state_rev:    {}", state.state_rev);
                }
                ExitCode::SUCCESS
            }
            Ok(None) => {
                if global.json {
                    println!("null");
                } else {
                    eprintln!(
                        "mx-agent: agent {} not found in {}",
                        args.agent_id, args.room
                    );
                }
                ExitCode::from(3)
            }
            Err(e) => {
                eprintln!("mx-agent: could not show agent: {e}");
                ExitCode::FAILURE
            }
        }
    })
}

fn agent_tools(global: &GlobalArgs, args: &AgentToolsArgs) -> ExitCode {
    let runtime = match build_runtime() {
        Ok(rt) => rt,
        Err(code) => return code,
    };
    let session = match load_session_or_exit() {
        Ok(s) => s,
        Err(code) => return code,
    };
    runtime.block_on(async {
        match mx_agent_daemon::agent_tools_for_session(&session, &args.room, &args.agent_id).await {
            Ok(Some(tools)) => {
                if global.json {
                    println!(
                        "{}",
                        serde_json::to_string(&tools).unwrap_or_else(|_| "{}".to_string())
                    );
                } else {
                    println!("mx-agent: tools for agent {}", tools.agent_id);
                    if tools.tools.is_empty() {
                        println!("  (no tools advertised)");
                    } else {
                        for tool in &tools.tools {
                            println!("  {tool}");
                        }
                    }
                }
                ExitCode::SUCCESS
            }
            Ok(None) => {
                if global.json {
                    println!("null");
                } else {
                    eprintln!(
                        "mx-agent: agent {} not found in {}",
                        args.agent_id, args.room
                    );
                }
                ExitCode::from(3)
            }
            Err(e) => {
                eprintln!("mx-agent: could not list agent tools: {e}");
                ExitCode::FAILURE
            }
        }
    })
}

fn agent_register(global: &GlobalArgs, args: &AgentRegisterArgs) -> ExitCode {
    let runtime = match build_runtime() {
        Ok(rt) => rt,
        Err(code) => return code,
    };
    let cwd = match &args.cwd {
        Some(p) => p.clone(),
        None => match std::env::current_dir() {
            Ok(p) => p,
            Err(e) => {
                eprintln!("mx-agent: could not resolve current directory: {e}");
                return ExitCode::FAILURE;
            }
        },
    };
    let options = mx_agent_daemon::RegisterAgentOptions {
        room: args.room.clone(),
        agent_id: args.agent_id.clone(),
        kind: args.kind.clone(),
        capabilities: args.capabilities.clone(),
        tools: args.tools.clone(),
        cwd: cwd.to_string_lossy().into_owned(),
        project_id: args.project_id.clone(),
        max_invocations: args.max_invocations,
    };
    let session = match load_session_or_exit() {
        Ok(s) => s,
        Err(code) => return code,
    };
    runtime.block_on(async {
        match mx_agent_daemon::register_agent_for_session(&session, &options).await {
            Ok(state) => {
                if global.json {
                    println!(
                        "{}",
                        serde_json::to_string(&state).unwrap_or_else(|_| "{}".to_string())
                    );
                } else {
                    println!("mx-agent: registered agent {}", state.agent_id);
                    println!("  kind:         {}", state.kind);
                    println!("  user:         {}", state.matrix_user_id);
                    println!("  device:       {}", state.device_id);
                    println!("  cwd:          {}", state.workspace.cwd);
                    if !state.workspace.project_id.is_empty() {
                        println!("  project:      {}", state.workspace.project_id);
                    }
                    if !state.workspace.git_commit.is_empty() {
                        println!("  git commit:   {}", state.workspace.git_commit);
                    }
                    if !state.capabilities.is_empty() {
                        println!("  capabilities: {}", state.capabilities.join(", "));
                    }
                    if !state.tools.is_empty() {
                        println!("  tools:        {}", state.tools.join(", "));
                    }
                    println!(
                        "  load:         {}/{} invocations",
                        state.load.running_invocations, state.load.max_invocations
                    );
                    println!("  state_rev:    {}", state.state_rev);
                }
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("mx-agent: could not register agent: {e}");
                ExitCode::FAILURE
            }
        }
    })
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
                WorkspaceCommand::Create(_) => "create",
                WorkspaceCommand::Join(_) => "join",
                WorkspaceCommand::Attach(_) => "attach",
                WorkspaceCommand::Status(_) => "status",
            }
        ),
        Command::Agent(c) => format!(
            "agent {}",
            match c {
                AgentCommand::Register(_) => "register",
                AgentCommand::List(_) => "list",
                AgentCommand::Show(_) => "show",
                AgentCommand::Tools(_) => "tools",
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
        let cli = Cli::try_parse_from([
            "mx-agent",
            "agent",
            "list",
            "--room",
            "!abc:matrix.org",
            "--json",
            "-vv",
        ])
        .unwrap();
        assert!(cli.global.json);
        assert_eq!(cli.global.verbose, 2);
    }

    #[test]
    fn agent_list_requires_room_and_collects_capabilities() {
        assert!(Cli::try_parse_from(["mx-agent", "agent", "list"]).is_err());
        let cli = Cli::try_parse_from([
            "mx-agent",
            "agent",
            "list",
            "--room",
            "!abc:matrix.org",
            "--capability",
            "shell",
            "--capability",
            "test",
        ])
        .unwrap();
        match &cli.command {
            Command::Agent(AgentCommand::List(args)) => {
                assert_eq!(args.room, "!abc:matrix.org");
                assert_eq!(args.capabilities, vec!["shell", "test"]);
            }
            other => panic!("expected agent list, got {other:?}"),
        }
        assert_eq!(command_path(&cli.command), "agent list");
    }

    #[test]
    fn agent_show_requires_room_and_agent_id() {
        assert!(
            Cli::try_parse_from(["mx-agent", "agent", "show", "--room", "!abc:matrix.org"])
                .is_err()
        );
        let cli = Cli::try_parse_from([
            "mx-agent",
            "agent",
            "show",
            "--room",
            "!abc:matrix.org",
            "--agent-id",
            "dev-pi",
        ])
        .unwrap();
        match &cli.command {
            Command::Agent(AgentCommand::Show(args)) => {
                assert_eq!(args.room, "!abc:matrix.org");
                assert_eq!(args.agent_id, "dev-pi");
            }
            other => panic!("expected agent show, got {other:?}"),
        }
        assert_eq!(command_path(&cli.command), "agent show");
    }

    #[test]
    fn agent_tools_requires_room_and_agent_id() {
        assert!(Cli::try_parse_from(["mx-agent", "agent", "tools"]).is_err());
        let cli = Cli::try_parse_from([
            "mx-agent",
            "agent",
            "tools",
            "--room",
            "!abc:matrix.org",
            "--agent-id",
            "dev-pi",
        ])
        .unwrap();
        match &cli.command {
            Command::Agent(AgentCommand::Tools(args)) => {
                assert_eq!(args.room, "!abc:matrix.org");
                assert_eq!(args.agent_id, "dev-pi");
            }
            other => panic!("expected agent tools, got {other:?}"),
        }
        assert_eq!(command_path(&cli.command), "agent tools");
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
    fn workspace_create_defaults_to_private() {
        let cli = Cli::try_parse_from(["mx-agent", "workspace", "create"]).unwrap();
        match &cli.command {
            Command::Workspace(WorkspaceCommand::Create(args)) => {
                assert_eq!(args.visibility, Visibility::Private);
                assert!(args.alias.is_none());
            }
            other => panic!("expected workspace create, got {other:?}"),
        }
    }

    #[test]
    fn workspace_create_accepts_flags() {
        let cli = Cli::try_parse_from([
            "mx-agent",
            "workspace",
            "create",
            "--alias",
            "my-project",
            "--name",
            "My Project",
            "--visibility",
            "public",
        ])
        .unwrap();
        match &cli.command {
            Command::Workspace(WorkspaceCommand::Create(args)) => {
                assert_eq!(args.alias.as_deref(), Some("my-project"));
                assert_eq!(args.name.as_deref(), Some("My Project"));
                assert_eq!(args.visibility, Visibility::Public);
            }
            other => panic!("expected workspace create, got {other:?}"),
        }
        assert_eq!(command_path(&cli.command), "workspace create");
    }

    #[test]
    fn workspace_join_requires_room_argument() {
        assert!(Cli::try_parse_from(["mx-agent", "workspace", "join"]).is_err());
        let cli =
            Cli::try_parse_from(["mx-agent", "workspace", "join", "#proj:matrix.org"]).unwrap();
        match &cli.command {
            Command::Workspace(WorkspaceCommand::Join(args)) => {
                assert_eq!(args.room, "#proj:matrix.org");
            }
            other => panic!("expected workspace join, got {other:?}"),
        }
    }

    #[test]
    fn workspace_status_requires_room_flag() {
        assert!(Cli::try_parse_from(["mx-agent", "workspace", "status"]).is_err());
        let cli = Cli::try_parse_from([
            "mx-agent",
            "workspace",
            "status",
            "--room",
            "!abc:matrix.org",
        ])
        .unwrap();
        match &cli.command {
            Command::Workspace(WorkspaceCommand::Status(args)) => {
                assert_eq!(args.room, "!abc:matrix.org");
            }
            other => panic!("expected workspace status, got {other:?}"),
        }
    }

    #[test]
    fn unknown_command_is_rejected() {
        let err = Cli::try_parse_from(["mx-agent", "definitely-not-a-command"]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::InvalidSubcommand);
    }
}
