//! Command-line surface for `mx-agent`.
//!
//! This module defines the full command tree with `clap`. Subcommands are
//! placeholders at this stage (issue #4): they parse arguments and report that
//! the operation is not implemented yet. Behavior is filled in by later roadmap
//! phases.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use clap::{ArgAction, Args, Parser, Subcommand, ValueEnum};
use serde_json::Value;

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
    /// Keep running and re-render the status as it changes (Ctrl-C to stop).
    #[arg(long)]
    watch: bool,
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
    /// Read the tool input as a JSON object from this file (`-` for stdin).
    #[arg(long = "input-json", value_name = "FILE")]
    input_json: Option<PathBuf>,
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
    /// Fail (exit 132) if the output stream is incomplete or corrupt instead of
    /// rendering best-effort. A missing chunk or one that fails validation
    /// (bad encoding or sha256 mismatch) becomes a hard error.
    #[arg(long = "strict-stream")]
    strict_stream: bool,
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
    /// Share a typed payload read from stdin.
    File(ShareFileArgs),
    /// Capture and share the current git diff.
    Diff(ShareDiffArgs),
    /// Collect and share environment metadata.
    Env(ShareEnvArgs),
    /// List recently shared context in a room.
    List(ShareListArgs),
    /// Retrieve and verify a shared context artifact by ID.
    Get(ShareGetArgs),
}

/// Diff output format for `share diff`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum DiffFormat {
    /// Full unified diff (git's default).
    Unified,
    /// `--stat` summary of changed files.
    Stat,
}

#[derive(Debug, Args)]
struct ShareFileArgs {
    /// Workspace room alias (`#name:server`) or room ID (`!id:server`).
    #[arg(long, value_name = "ROOM")]
    room: String,
    /// MIME type of the payload, e.g. `application/json`.
    #[arg(
        long = "type",
        value_name = "MIME",
        default_value = "application/octet-stream"
    )]
    mime_type: String,
    /// Object name to record on the share, e.g. `plan.json`.
    #[arg(long, value_name = "NAME")]
    name: String,
}

#[derive(Debug, Args)]
struct ShareDiffArgs {
    /// Workspace room alias (`#name:server`) or room ID (`!id:server`).
    #[arg(long, value_name = "ROOM")]
    room: String,
    /// Base revision to diff against (e.g. `main`). Defaults to the unstaged
    /// working-tree diff.
    #[arg(long, value_name = "REV")]
    base: Option<String>,
    /// Diff output format.
    #[arg(long, value_enum, default_value_t = DiffFormat::Unified)]
    format: DiffFormat,
}

#[derive(Debug, Args)]
struct ShareEnvArgs {
    /// Workspace room alias (`#name:server`) or room ID (`!id:server`).
    #[arg(long, value_name = "ROOM")]
    room: String,
    /// Comma-separated facts to include (defaults to `node,npm,os,git`).
    #[arg(long, value_name = "FACTS", value_delimiter = ',')]
    include: Vec<String>,
}

#[derive(Debug, Args)]
struct ShareListArgs {
    /// Workspace room alias (`#name:server`) or room ID (`!id:server`).
    #[arg(long, value_name = "ROOM")]
    room: String,
    /// Maximum number of recent timeline events to scan.
    #[arg(long, value_name = "N", default_value_t = 50)]
    limit: u32,
}

#[derive(Debug, Args)]
struct ShareGetArgs {
    /// Workspace room alias (`#name:server`) or room ID (`!id:server`).
    #[arg(long, value_name = "ROOM")]
    room: String,
    /// Context ID of the share to retrieve, e.g. `ctx_01HZ...`.
    #[arg(long = "context-id", value_name = "CONTEXT_ID")]
    context_id: String,
    /// Write the verified artifact to this file instead of stdout.
    #[arg(long, value_name = "PATH")]
    output: Option<PathBuf>,
    /// Maximum number of recent timeline events to scan when locating the share.
    #[arg(long, value_name = "N", default_value_t = 100)]
    limit: u32,
}

#[derive(Debug, Subcommand)]
enum TaskCommand {
    /// Create a task.
    Create(TaskCreateArgs),
    /// Update a task.
    Update(TaskUpdateArgs),
    /// List tasks.
    List(TaskListArgs),
    /// Render the task dependency graph.
    Graph(TaskGraphArgs),
    /// Watch task state changes live (Ctrl-C to stop).
    Watch(TaskWatchArgs),
}

#[derive(Debug, Args)]
struct TaskCreateArgs {
    /// Workspace room alias (`#name:server`) or room ID (`!id:server`).
    #[arg(long, value_name = "ROOM")]
    room: String,
    /// Explicit task ID (also the state key). A sortable `task_...` ID is
    /// generated when omitted.
    #[arg(long, value_name = "TASK_ID")]
    id: Option<String>,
    /// Human-readable task title.
    #[arg(long, value_name = "TITLE")]
    title: String,
    /// Longer task description.
    #[arg(long, value_name = "DESCRIPTION", default_value = "")]
    description: String,
    /// Initial lifecycle state (defaults to `pending`).
    #[arg(long, value_name = "STATE")]
    state: Option<String>,
    /// Agent to assign the task to.
    #[arg(long = "assign", value_name = "AGENT", default_value = "")]
    assign: String,
    /// Upstream task this one depends on (repeatable).
    #[arg(long = "depends-on", value_name = "TASK_ID")]
    depends_on: Vec<String>,
    /// Downstream task blocked by this one (repeatable).
    #[arg(long = "blocks", value_name = "TASK_ID")]
    blocks: Vec<String>,
    /// Attach a tool action to the task.
    #[arg(long = "tool", value_name = "TOOL")]
    tool: Option<String>,
    /// Tool argument as `key=value` (repeatable). Used with `--tool`.
    #[arg(long = "arg", value_name = "KEY=VALUE")]
    args: Vec<String>,
    /// JSON object file for tool input, or `-` for stdin. Used with `--tool`.
    #[arg(long = "input-json", value_name = "FILE")]
    input_json: Option<PathBuf>,
    /// Attach an exec action to the task.
    #[arg(long = "exec")]
    exec: bool,
    /// Working directory for an exec action.
    #[arg(long = "cwd", value_name = "PATH")]
    cwd: Option<PathBuf>,
    /// Timeout in milliseconds for an exec action.
    #[arg(long = "timeout-ms", value_name = "MS")]
    timeout_ms: Option<u64>,
    /// Request streamed output for an exec action.
    #[arg(long = "stream")]
    stream: bool,
    /// Exec command and arguments (after `--`).
    #[arg(trailing_var_arg = true, value_name = "COMMAND")]
    command: Vec<String>,
}

#[derive(Debug, Args)]
struct TaskUpdateArgs {
    /// Workspace room alias (`#name:server`) or room ID (`!id:server`).
    #[arg(long, value_name = "ROOM")]
    room: String,
    /// Task ID (state key) to update.
    #[arg(value_name = "TASK_ID")]
    task_id: String,
    /// New lifecycle state, e.g. `executing`, `succeeded`, `failed`.
    #[arg(long, value_name = "STATE")]
    state: Option<String>,
    /// Reassign the task to this agent.
    #[arg(long = "assign", value_name = "AGENT")]
    assign: Option<String>,
    /// New title.
    #[arg(long, value_name = "TITLE")]
    title: Option<String>,
    /// New description.
    #[arg(long, value_name = "DESCRIPTION")]
    description: Option<String>,
    /// Associate this task with an invocation ID.
    #[arg(long = "invocation", value_name = "INVOCATION_ID")]
    invocation: Option<String>,
    /// Only apply the update if the task is still at this `state_rev`; otherwise
    /// reject it as stale rather than overwriting newer state.
    #[arg(long = "expected-state-rev", value_name = "REV")]
    expected_state_rev: Option<u64>,
    /// Replace the task action with a tool action.
    #[arg(long = "tool", value_name = "TOOL")]
    tool: Option<String>,
    /// Tool argument as `key=value` (repeatable). Used with `--tool`.
    #[arg(long = "arg", value_name = "KEY=VALUE")]
    args: Vec<String>,
    /// JSON object file for tool input, or `-` for stdin. Used with `--tool`.
    #[arg(long = "input-json", value_name = "FILE")]
    input_json: Option<PathBuf>,
    /// Replace the task action with an exec action.
    #[arg(long = "exec")]
    exec: bool,
    /// Working directory for an exec action.
    #[arg(long = "cwd", value_name = "PATH")]
    cwd: Option<PathBuf>,
    /// Timeout in milliseconds for an exec action.
    #[arg(long = "timeout-ms", value_name = "MS")]
    timeout_ms: Option<u64>,
    /// Request streamed output for an exec action.
    #[arg(long = "stream")]
    stream: bool,
    /// Exec command and arguments (after `--`).
    #[arg(trailing_var_arg = true, value_name = "COMMAND")]
    command: Vec<String>,
}

#[derive(Debug, Args)]
struct TaskGraphArgs {
    /// Workspace room alias (`#name:server`) or room ID (`!id:server`).
    #[arg(long, value_name = "ROOM")]
    room: String,
}

#[derive(Debug, Args)]
struct TaskListArgs {
    /// Workspace room alias (`#name:server`) or room ID (`!id:server`).
    #[arg(long, value_name = "ROOM")]
    room: String,
    /// Only list tasks in this lifecycle state.
    #[arg(long, value_name = "STATE")]
    state: Option<String>,
    /// Only list tasks assigned to this agent.
    #[arg(long = "assigned", value_name = "AGENT")]
    assigned: Option<String>,
}

#[derive(Debug, Args)]
struct TaskWatchArgs {
    /// Workspace room alias (`#name:server`) or room ID (`!id:server`).
    #[arg(long, value_name = "ROOM")]
    room: String,
    /// Only watch tasks in this lifecycle state.
    #[arg(long, value_name = "STATE")]
    state: Option<String>,
    /// Only watch tasks assigned to this agent.
    #[arg(long = "assigned", value_name = "AGENT")]
    assigned: Option<String>,
}

#[derive(Debug, Subcommand)]
enum InvocationCommand {
    /// List invocations.
    List(InvocationListArgs),
    /// Show one invocation.
    Show(InvocationShowArgs),
    /// Cancel a running invocation.
    Cancel(InvocationCancelArgs),
    /// Retrieve and verify an invocation's output artifact.
    Artifact(InvocationArtifactArgs),
}

/// Captured output stream selected by `invocation artifact`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum StreamChannel {
    /// Standard output.
    Stdout,
    /// Standard error.
    Stderr,
    /// Pseudo-terminal output.
    Pty,
}

impl StreamChannel {
    /// Map to the protocol [`StreamKind`](mx_agent_protocol::schema::StreamKind).
    fn to_stream_kind(self) -> mx_agent_protocol::schema::StreamKind {
        use mx_agent_protocol::schema::StreamKind;
        match self {
            StreamChannel::Stdout => StreamKind::Stdout,
            StreamChannel::Stderr => StreamKind::Stderr,
            StreamChannel::Pty => StreamKind::Pty,
        }
    }
}

#[derive(Debug, Args)]
struct InvocationListArgs {
    /// Workspace room alias (`#name:server`) or room ID (`!id:server`).
    #[arg(long, value_name = "ROOM")]
    room: String,
    /// Only list invocations in this lifecycle state, e.g. `running`.
    #[arg(long, value_name = "STATE")]
    state: Option<String>,
    /// Only list invocations linked to this task ID.
    #[arg(long = "task", value_name = "TASK_ID")]
    task: Option<String>,
}

#[derive(Debug, Args)]
struct InvocationShowArgs {
    /// Workspace room alias (`#name:server`) or room ID (`!id:server`).
    #[arg(long, value_name = "ROOM")]
    room: String,
    /// Invocation ID (state key) to show.
    #[arg(value_name = "INVOCATION_ID")]
    invocation_id: String,
}

#[derive(Debug, Args)]
struct InvocationCancelArgs {
    /// Workspace room alias (`#name:server`) or room ID (`!id:server`).
    #[arg(long, value_name = "ROOM")]
    room: String,
    /// Invocation ID (state key) to cancel.
    #[arg(value_name = "INVOCATION_ID")]
    invocation_id: String,
    /// Human-readable reason recorded with the cancellation.
    #[arg(long, value_name = "REASON", default_value = "cancelled by operator")]
    reason: String,
}

#[derive(Debug, Args)]
struct InvocationArtifactArgs {
    /// Workspace room alias (`#name:server`) or room ID (`!id:server`).
    #[arg(long, value_name = "ROOM")]
    room: String,
    /// Invocation ID whose output artifact to retrieve.
    #[arg(value_name = "INVOCATION_ID")]
    invocation_id: String,
    /// Which captured stream to retrieve.
    #[arg(long, value_enum, default_value_t = StreamChannel::Stdout)]
    stream: StreamChannel,
    /// Write the verified artifact to this file instead of stdout.
    #[arg(long, value_name = "PATH")]
    output: Option<PathBuf>,
    /// Maximum number of recent timeline events to scan when locating the
    /// artifact.
    #[arg(long, value_name = "N", default_value_t = 100)]
    limit: u32,
}

#[derive(Debug, Subcommand)]
enum ApprovalCommand {
    /// List pending approval requests.
    List(ApprovalListArgs),
    /// Show one approval request.
    Show(ApprovalShowArgs),
    /// Approve a request so the held command may run.
    Approve(ApprovalDecideArgs),
    /// Deny a request so the held command never runs.
    Deny(ApprovalDecideArgs),
}

#[derive(Debug, Args)]
struct ApprovalListArgs {
    /// Only list approvals queued for this workspace room.
    #[arg(long, value_name = "ROOM")]
    room: Option<String>,
}

#[derive(Debug, Args)]
struct ApprovalShowArgs {
    /// Approval request ID to show.
    #[arg(value_name = "REQUEST_ID")]
    request_id: String,
}

#[derive(Debug, Args)]
struct ApprovalDecideArgs {
    /// Approval request ID to decide.
    #[arg(value_name = "REQUEST_ID")]
    request_id: String,
    /// Identity to record as the decision-maker (defaults to the logged-in user).
    #[arg(long = "by", value_name = "IDENTITY")]
    by: Option<String>,
}

#[derive(Debug, Subcommand)]
enum TrustCommand {
    /// List trusted keys.
    List(TrustListArgs),
    /// Show the local signing key fingerprint.
    Fingerprint,
    /// Approve an agent signing key.
    Approve(TrustApproveArgs),
    /// Revoke an agent signing key.
    Revoke(TrustRevokeArgs),
    /// Publish a local trust record to a workspace room as room state.
    Publish(TrustPublishArgs),
    /// Inspect trust state published in a workspace room (local store wins).
    State(TrustStateArgs),
}

#[derive(Debug, Args)]
struct TrustListArgs {
    /// Only list keys scoped to this workspace room.
    #[arg(long, value_name = "ROOM")]
    room: Option<String>,
    /// Only list keys for this agent.
    #[arg(long = "agent", value_name = "AGENT")]
    agent: Option<String>,
}

#[derive(Debug, Args)]
struct TrustApproveArgs {
    /// Agent identifier the key belongs to.
    #[arg(long = "agent", value_name = "AGENT")]
    agent: String,
    /// Signing key identifier (`mxagent-ed25519:<base64>`).
    #[arg(long, value_name = "KEY")]
    key: String,
    /// Workspace room to scope the trust to.
    #[arg(long, value_name = "ROOM")]
    room: Option<String>,
    /// Key fingerprint (`SHA256:<base64>`); derived from the key id if omitted.
    #[arg(long, value_name = "FINGERPRINT")]
    fingerprint: Option<String>,
}

#[derive(Debug, Args)]
struct TrustRevokeArgs {
    /// Agent identifier the key belongs to.
    #[arg(long = "agent", value_name = "AGENT")]
    agent: String,
    /// Signing key identifier (`mxagent-ed25519:<base64>`).
    #[arg(long, value_name = "KEY")]
    key: String,
}

#[derive(Debug, Args)]
struct TrustPublishArgs {
    /// Workspace room to publish the trust state into.
    #[arg(long, value_name = "ROOM")]
    room: String,
    /// Agent identifier the key belongs to.
    #[arg(long = "agent", value_name = "AGENT")]
    agent: String,
    /// Signing key identifier (`mxagent-ed25519:<base64>`).
    #[arg(long, value_name = "KEY")]
    key: String,
}

#[derive(Debug, Args)]
struct TrustStateArgs {
    /// Workspace room to read published trust state from.
    #[arg(long, value_name = "ROOM")]
    room: String,
    /// Only show records for this agent.
    #[arg(long = "agent", value_name = "AGENT")]
    agent: Option<String>,
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
        Command::Task(cmd) => handle_task(g, cmd),
        Command::Invocation(cmd) => handle_invocation(g, cmd),
        Command::Approval(cmd) => handle_approval(g, cmd),
        Command::Share(cmd) => handle_share(g, cmd),
        Command::Call(args) => cmd_call(g, args),
        Command::Exec(args) => cmd_exec(g, args),
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
        TrustCommand::List(args) => trust_list(global, args),
        TrustCommand::Approve(args) => trust_approve(global, args),
        TrustCommand::Revoke(args) => trust_revoke(global, args),
        TrustCommand::Publish(args) => trust_publish(global, args),
        TrustCommand::State(args) => trust_state(global, args),
    }
}

/// Render a single trust entry as a human-readable block.
fn print_trust_entry(entry: &mx_agent_daemon::TrustEntry) {
    println!("  {} {}", entry.status, entry.key_id);
    println!("    agent:       {}", entry.agent_id);
    println!("    fingerprint: {}", entry.fingerprint);
    if let Some(room) = &entry.room {
        println!("    room:        {room}");
    }
    if let Some(by) = &entry.trusted_by {
        println!("    trusted_by:  {by}");
    }
}

/// List trusted keys from the local trust store, with optional filters.
fn trust_list(global: &GlobalArgs, args: &TrustListArgs) -> ExitCode {
    let paths = mx_agent_daemon::SessionPaths::resolve();
    let store = match mx_agent_daemon::TrustStore::load(&paths) {
        Ok(store) => store,
        Err(e) => {
            eprintln!("mx-agent: could not read trust store: {e}");
            return ExitCode::FAILURE;
        }
    };
    let entries: Vec<&mx_agent_daemon::TrustEntry> = store
        .entries()
        .iter()
        .filter(|e| args.agent.as_deref().map_or(true, |a| e.agent_id == a))
        .filter(|e| {
            args.room
                .as_deref()
                .map_or(true, |r| e.room.as_deref() == Some(r))
        })
        .collect();
    if global.json {
        println!(
            "{}",
            serde_json::to_string(&entries).unwrap_or_else(|_| "[]".to_string())
        );
    } else if entries.is_empty() {
        println!("mx-agent: no trusted keys");
    } else {
        println!("mx-agent: {} trust record(s)", entries.len());
        for entry in &entries {
            print_trust_entry(entry);
        }
    }
    ExitCode::SUCCESS
}

/// Approve an agent signing key in the local trust store.
fn trust_approve(global: &GlobalArgs, args: &TrustApproveArgs) -> ExitCode {
    let paths = mx_agent_daemon::SessionPaths::resolve();
    let mut store = match mx_agent_daemon::TrustStore::load(&paths) {
        Ok(store) => store,
        Err(e) => {
            eprintln!("mx-agent: could not read trust store: {e}");
            return ExitCode::FAILURE;
        }
    };
    let entry = store.approve(
        args.agent.clone(),
        args.key.clone(),
        args.fingerprint.clone(),
        args.room.clone(),
        None,
    );
    if let Err(e) = store.save(&paths) {
        eprintln!("mx-agent: could not save trust store: {e}");
        return ExitCode::FAILURE;
    }
    if global.json {
        println!(
            "{}",
            serde_json::to_string(&entry).unwrap_or_else(|_| "{}".to_string())
        );
    } else {
        println!("mx-agent: approved key for agent {}", entry.agent_id);
        print_trust_entry(&entry);
    }
    ExitCode::SUCCESS
}

/// Revoke an agent signing key in the local trust store.
fn trust_revoke(global: &GlobalArgs, args: &TrustRevokeArgs) -> ExitCode {
    let paths = mx_agent_daemon::SessionPaths::resolve();
    let mut store = match mx_agent_daemon::TrustStore::load(&paths) {
        Ok(store) => store,
        Err(e) => {
            eprintln!("mx-agent: could not read trust store: {e}");
            return ExitCode::FAILURE;
        }
    };
    match store.revoke(&args.agent, &args.key) {
        Some(entry) => {
            if let Err(e) = store.save(&paths) {
                eprintln!("mx-agent: could not save trust store: {e}");
                return ExitCode::FAILURE;
            }
            if global.json {
                println!(
                    "{}",
                    serde_json::to_string(&entry).unwrap_or_else(|_| "{}".to_string())
                );
            } else {
                println!("mx-agent: revoked key for agent {}", entry.agent_id);
                print_trust_entry(&entry);
            }
            ExitCode::SUCCESS
        }
        None => {
            if global.json {
                println!("null");
            } else {
                eprintln!(
                    "mx-agent: no trust record for agent {} key {}",
                    args.agent, args.key
                );
            }
            ExitCode::from(3)
        }
    }
}

/// Publish a local trust record to a workspace room as `com.mxagent.trust.v1`
/// state. The record must already exist in the local store; publication is
/// purely advisory and never changes local trust.
fn trust_publish(global: &GlobalArgs, args: &TrustPublishArgs) -> ExitCode {
    let paths = mx_agent_daemon::SessionPaths::resolve();
    let store = match mx_agent_daemon::TrustStore::load(&paths) {
        Ok(store) => store,
        Err(e) => {
            eprintln!("mx-agent: could not read trust store: {e}");
            return ExitCode::FAILURE;
        }
    };
    let entry = match store.entry(&args.agent, &args.key) {
        Some(entry) => entry.clone(),
        None => {
            eprintln!(
                "mx-agent: no local trust record for agent {} key {}; \
                 approve it first with `mx-agent trust approve`",
                args.agent, args.key
            );
            return ExitCode::from(3);
        }
    };
    let runtime = match build_runtime() {
        Ok(rt) => rt,
        Err(code) => return code,
    };
    let session = match load_session_or_exit() {
        Ok(s) => s,
        Err(code) => return code,
    };
    runtime.block_on(async {
        match mx_agent_daemon::publish_trust_state_for_session(&session, &args.room, &entry).await {
            Ok(state) => {
                if global.json {
                    println!(
                        "{}",
                        serde_json::to_string(&state).unwrap_or_else(|_| "{}".to_string())
                    );
                } else {
                    println!(
                        "mx-agent: published {} trust for agent {} to {}",
                        state.status, state.agent_id, args.room
                    );
                    println!("  key:         {}", state.key_id);
                    println!("  fingerprint: {}", state.fingerprint);
                    println!("  trusted_by:  {}", state.trusted_by);
                }
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("mx-agent: could not publish trust state: {e}");
                ExitCode::FAILURE
            }
        }
    })
}

/// Inspect trust state published in a workspace room, combined with the local
/// store. The local store is the final authority: a local revocation overrides
/// any room-published trust.
fn trust_state(global: &GlobalArgs, args: &TrustStateArgs) -> ExitCode {
    let paths = mx_agent_daemon::SessionPaths::resolve();
    let local = match mx_agent_daemon::TrustStore::load(&paths) {
        Ok(store) => store,
        Err(e) => {
            eprintln!("mx-agent: could not read trust store: {e}");
            return ExitCode::FAILURE;
        }
    };
    let runtime = match build_runtime() {
        Ok(rt) => rt,
        Err(code) => return code,
    };
    let session = match load_session_or_exit() {
        Ok(s) => s,
        Err(code) => return code,
    };
    runtime.block_on(async {
        match mx_agent_daemon::list_trust_states_for_session(&session, &args.room).await {
            Ok(states) => {
                let states: Vec<_> = states
                    .into_iter()
                    .filter(|s| args.agent.as_deref().map_or(true, |a| s.agent_id == a))
                    .collect();
                let effective = mx_agent_daemon::effective_trust_table(&local, &states);
                let effective: Vec<_> = effective
                    .into_iter()
                    .filter(|t| args.agent.as_deref().map_or(true, |a| t.agent_id == a))
                    .collect();
                if global.json {
                    let obj = serde_json::json!({
                        "published": states,
                        "effective": effective.iter().map(|t| serde_json::json!({
                            "agent_id": t.agent_id,
                            "key_id": t.key_id,
                            "trusted": t.trusted,
                            "source": format!("{:?}", t.source).to_lowercase(),
                        })).collect::<Vec<_>>(),
                    });
                    println!("{obj}");
                } else if states.is_empty() {
                    println!("mx-agent: no trust state published in {}", args.room);
                } else {
                    println!(
                        "mx-agent: {} published trust record(s) in {}",
                        states.len(),
                        args.room
                    );
                    for s in &states {
                        println!("  {} {}", s.status, s.key_id);
                        println!("    agent:       {}", s.agent_id);
                        println!("    fingerprint: {}", s.fingerprint);
                        println!("    trusted_by:  {}", s.trusted_by);
                    }
                    println!("mx-agent: effective trust (local store wins):");
                    for t in &effective {
                        let label = if t.trusted { "trusted" } else { "untrusted" };
                        let source = format!("{:?}", t.source).to_lowercase();
                        println!("  {label} {} {} (via {source})", t.agent_id, t.key_id);
                    }
                }
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("mx-agent: could not read trust state: {e}");
                ExitCode::FAILURE
            }
        }
    })
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

/// Render a [`WorkspaceStatus`] as a human-readable block.
fn print_workspace_status(status: &mx_agent_daemon::WorkspaceStatus) {
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

fn workspace_status(global: &GlobalArgs, args: &WorkspaceStatusArgs) -> ExitCode {
    if args.watch {
        return workspace_status_watch(global, args);
    }
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
                    print_workspace_status(&status);
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

/// Render a single workspace-status watch update to the terminal.
fn render_status_update(
    json: bool,
    update: mx_agent_daemon::WatchUpdate<'_, mx_agent_daemon::WorkspaceStatus>,
) {
    use mx_agent_daemon::WatchUpdate;
    match update {
        WatchUpdate::Initial(status)
        | WatchUpdate::Changed {
            current: status, ..
        } => {
            if json {
                println!("{}", status.to_json());
            } else {
                print_workspace_status(status);
            }
        }
        WatchUpdate::Reconnecting { attempt, error } => {
            eprintln!("mx-agent: reconnecting (attempt {attempt}): {error}");
        }
        WatchUpdate::Reconnected => {
            eprintln!("mx-agent: reconnected");
        }
    }
}

fn workspace_status_watch(global: &GlobalArgs, args: &WorkspaceStatusArgs) -> ExitCode {
    let runtime = match build_runtime() {
        Ok(rt) => rt,
        Err(code) => return code,
    };
    let session = match load_session_or_exit() {
        Ok(s) => s,
        Err(code) => return code,
    };
    let running = Arc::new(AtomicBool::new(true));
    let json = global.json;
    let callback =
        move |update: mx_agent_daemon::WatchUpdate<'_, mx_agent_daemon::WorkspaceStatus>| {
            render_status_update(json, update);
        };
    runtime.block_on(async {
        let watch = mx_agent_daemon::watch_workspace_status_for_session(
            &session,
            &args.room,
            mx_agent_daemon::WatchConfig::default(),
            &running,
            callback,
        );
        tokio::select! {
            result = watch => match result {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("mx-agent: could not watch workspace status: {e}");
                    ExitCode::FAILURE
                }
            },
            _ = tokio::signal::ctrl_c() => {
                running.store(false, Ordering::SeqCst);
                eprintln!("mx-agent: watch stopped");
                ExitCode::SUCCESS
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
                        for reference in &tools.tools {
                            let name = reference.split('@').next().unwrap_or(reference);
                            match tools.schemas.iter().find(|s| s.name == name) {
                                Some(schema) => {
                                    println!(
                                        "  {} ({})",
                                        schema.qualified_ref(),
                                        schema.description
                                    );
                                    println!("    input:  {}", schema.input_schema);
                                    println!("    output: {}", schema.output_schema);
                                }
                                None => println!("  {reference}"),
                            }
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

/// Handle the `task` command group.
fn handle_task(global: &GlobalArgs, cmd: &TaskCommand) -> ExitCode {
    match cmd {
        TaskCommand::Create(args) => task_create(global, args),
        TaskCommand::Update(args) => task_update(global, args),
        TaskCommand::List(args) => task_list(global, args),
        TaskCommand::Graph(args) => task_graph(global, args),
        TaskCommand::Watch(args) => task_watch(global, args),
    }
}

/// Render a single task as a human-readable block.
fn print_task(task: &mx_agent_protocol::schema::TaskState) {
    println!("  {:<28} {:<10} {}", task.task_id, task.state, task.title);
    if !task.assigned_to.is_empty() {
        println!("    assigned_to:  {}", task.assigned_to);
    }
    if !task.depends_on.is_empty() {
        println!("    depends_on:   {}", task.depends_on.join(", "));
    }
    if !task.blocks.is_empty() {
        println!("    blocks:       {}", task.blocks.join(", "));
    }
    if let Some(invocation_id) = &task.invocation_id {
        println!("    invocation:   {invocation_id}");
    }
    if let Some(action) = &task.action {
        match action {
            mx_agent_protocol::schema::TaskAction::Tool { tool, .. } => {
                println!("    action:       tool {tool}");
            }
            mx_agent_protocol::schema::TaskAction::Exec { command, cwd, .. } => {
                println!("    action:       exec {} (cwd {cwd})", command.join(" "));
            }
        }
    } else {
        println!("    action:       manual/planning");
    }
    if let Some(result) = &task.result {
        println!("    result:       {}", task_result_summary(result));
    }
    println!("    state_rev:    {}", task.state_rev);
}

fn task_result_summary(result: &Value) -> String {
    let status = result
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let mut parts = vec![status.to_string()];
    if let Some(reason) = result.get("reason").and_then(Value::as_str) {
        parts.push(format!("reason={reason}"));
    }
    if let Some(exit_code) = result.get("exit_code").and_then(Value::as_i64) {
        parts.push(format!("exit_code={exit_code}"));
    }
    if let Some(summary) = result.get("summary").and_then(Value::as_str) {
        if !summary.is_empty() {
            parts.push(summary.to_string());
        }
    }
    parts.join("; ")
}

fn daemon_socket_path(global: &GlobalArgs) -> PathBuf {
    global
        .socket
        .clone()
        .unwrap_or_else(|| mx_agent_daemon::Paths::resolve().socket_path)
}

/// Make a single-response JSON-RPC call to the running daemon over the local
/// IPC socket, returning the typed result or an [`ExitCode`].
///
/// Used by the daemon-mediated commands (`task.*`, `call.start`, …) so the
/// stateless CLI never reads Matrix session, signing, or policy state itself.
/// A daemon that cannot be contacted maps to exit code 3.
fn daemon_ipc_call<T, R>(global: &GlobalArgs, method: &str, params: &T) -> Result<R, ExitCode>
where
    T: serde::Serialize,
    R: serde::de::DeserializeOwned,
{
    let params = serde_json::to_value(params).map_err(|e| {
        eprintln!("mx-agent: could not encode {method} request: {e}");
        ExitCode::FAILURE
    })?;
    let socket = daemon_socket_path(global);
    let mut client = mx_agent_ipc::Client::connect(&socket).map_err(|e| {
        eprintln!(
            "mx-agent: could not contact daemon at {}: {e}; run `mx-agent daemon start`",
            socket.display()
        );
        ExitCode::from(3)
    })?;
    let response = client.call(method, params).map_err(|e| {
        eprintln!("mx-agent: daemon IPC request {method} failed: {e}");
        ExitCode::FAILURE
    })?;
    if let Some(error) = response.error {
        eprintln!("mx-agent: daemon rejected {method}: {}", error.message);
        return Err(ExitCode::FAILURE);
    }
    let result = response.result.unwrap_or(Value::Null);
    serde_json::from_value(result).map_err(|e| {
        eprintln!("mx-agent: daemon returned invalid {method} response: {e}");
        ExitCode::FAILURE
    })
}

fn task_create(global: &GlobalArgs, args: &TaskCreateArgs) -> ExitCode {
    if let Some(state) = &args.state {
        if let Err(e) = validate_task_state_arg(state) {
            eprintln!("mx-agent: {e}");
            return ExitCode::from(64);
        }
    }
    let action = match build_task_action(TaskActionInput {
        tool: args.tool.as_deref(),
        args: &args.args,
        input_json: args.input_json.as_ref(),
        exec: args.exec,
        cwd: args.cwd.as_ref(),
        timeout_ms: args.timeout_ms,
        stream: args.stream,
        command: &args.command,
    }) {
        Ok(action) => action,
        Err(e) => {
            eprintln!("mx-agent: {e}");
            return ExitCode::from(64);
        }
    };
    let options = mx_agent_daemon::CreateTaskOptions {
        room: args.room.clone(),
        task_id: args.id.clone(),
        title: args.title.clone(),
        description: args.description.clone(),
        state: args.state.clone(),
        assigned_to: args.assign.clone(),
        created_by: None,
        depends_on: args.depends_on.clone(),
        blocks: args.blocks.clone(),
        action,
    };
    match daemon_ipc_call::<_, mx_agent_protocol::schema::TaskState>(
        global,
        "task.create",
        &options,
    ) {
        Ok(task) => {
            if global.json {
                println!(
                    "{}",
                    serde_json::to_string(&task).unwrap_or_else(|_| "{}".to_string())
                );
            } else {
                println!("mx-agent: created task {}", task.task_id);
                print_task(&task);
            }
            ExitCode::SUCCESS
        }
        Err(code) => code,
    }
}

fn task_update(global: &GlobalArgs, args: &TaskUpdateArgs) -> ExitCode {
    if let Some(state) = &args.state {
        if let Err(e) = validate_task_state_arg(state) {
            eprintln!("mx-agent: {e}");
            return ExitCode::from(64);
        }
    }
    let action = match build_task_action(TaskActionInput {
        tool: args.tool.as_deref(),
        args: &args.args,
        input_json: args.input_json.as_ref(),
        exec: args.exec,
        cwd: args.cwd.as_ref(),
        timeout_ms: args.timeout_ms,
        stream: args.stream,
        command: &args.command,
    }) {
        Ok(action) => action,
        Err(e) => {
            eprintln!("mx-agent: {e}");
            return ExitCode::from(64);
        }
    };
    let options = mx_agent_daemon::UpdateTaskOptions {
        room: args.room.clone(),
        task_id: args.task_id.clone(),
        state: args.state.clone(),
        assigned_to: args.assign.clone(),
        title: args.title.clone(),
        description: args.description.clone(),
        invocation_id: args.invocation.clone(),
        result: None,
        action,
        expected_state_rev: args.expected_state_rev,
    };
    match daemon_ipc_call::<_, mx_agent_protocol::schema::TaskState>(
        global,
        "task.update",
        &options,
    ) {
        Ok(task) => {
            if global.json {
                println!(
                    "{}",
                    serde_json::to_string(&task).unwrap_or_else(|_| "{}".to_string())
                );
            } else {
                println!("mx-agent: updated task {}", task.task_id);
                print_task(&task);
            }
            ExitCode::SUCCESS
        }
        Err(code) => code,
    }
}

fn task_list(global: &GlobalArgs, args: &TaskListArgs) -> ExitCode {
    let options = mx_agent_daemon::ListTasksOptions {
        room: args.room.clone(),
        state: args.state.clone(),
        assigned_to: args.assigned.clone(),
    };
    match daemon_ipc_call::<_, Vec<mx_agent_protocol::schema::TaskState>>(
        global,
        "task.list",
        &options,
    ) {
        Ok(tasks) => {
            if global.json {
                println!(
                    "{}",
                    serde_json::to_string(&tasks).unwrap_or_else(|_| "[]".to_string())
                );
            } else if tasks.is_empty() {
                println!("mx-agent: no tasks in {}", args.room);
            } else {
                println!("mx-agent: {} task(s) in {}", tasks.len(), args.room);
                for task in &tasks {
                    print_task(task);
                }
            }
            ExitCode::SUCCESS
        }
        Err(code) => code,
    }
}

fn task_graph(global: &GlobalArgs, args: &TaskGraphArgs) -> ExitCode {
    let options = mx_agent_daemon::ListTasksOptions {
        room: args.room.clone(),
        state: None,
        assigned_to: None,
    };
    match daemon_ipc_call::<_, mx_agent_daemon::TaskGraph>(global, "task.graph", &options) {
        Ok(graph) => {
            if global.json {
                println!(
                    "{}",
                    serde_json::to_string(&graph).unwrap_or_else(|_| "{}".to_string())
                );
            } else if graph.nodes.is_empty() {
                println!("mx-agent: no tasks in {}", args.room);
            } else {
                print!("{}", graph.render_text());
                if !graph.warnings.is_empty() {
                    println!("\nwarnings ({}):", graph.warnings.len());
                    for warning in &graph.warnings {
                        match &warning.task_id {
                            Some(task_id) => {
                                println!("  ! [{}] {}: {}", warning.kind, task_id, warning.message)
                            }
                            None => println!("  ! [{}] {}", warning.kind, warning.message),
                        }
                    }
                }
            }
            ExitCode::SUCCESS
        }
        Err(code) => code,
    }
}

/// Render a single task change (added/removed/updated) as a one-line entry.
fn print_task_change(change: &mx_agent_daemon::TaskChange) {
    use mx_agent_daemon::TaskChange;
    let none_if_empty = |s: &str| {
        if s.is_empty() {
            "(none)".to_string()
        } else {
            s.to_string()
        }
    };
    match change {
        TaskChange::Added(task) => {
            println!("  + {:<26} {:<10} {}", task.task_id, task.state, task.title);
        }
        TaskChange::Removed(task) => {
            println!("  - {:<26} {:<10} {}", task.task_id, task.state, task.title);
        }
        TaskChange::Updated { previous, current } => {
            if previous.state != current.state {
                // The headline acceptance case: a live state transition.
                println!(
                    "  ~ {:<26} {} -> {}",
                    current.task_id, previous.state, current.state
                );
            } else {
                println!(
                    "  ~ {:<26} {:<10} {}",
                    current.task_id, current.state, current.title
                );
            }
            if previous.assigned_to != current.assigned_to {
                println!(
                    "      assigned_to: {} -> {}",
                    none_if_empty(&previous.assigned_to),
                    none_if_empty(&current.assigned_to)
                );
            }
        }
    }
}

/// Render a single task watch update to the terminal.
fn render_task_update(
    json: bool,
    room: &str,
    update: mx_agent_daemon::WatchUpdate<'_, Vec<mx_agent_protocol::schema::TaskState>>,
) {
    use mx_agent_daemon::WatchUpdate;
    match update {
        WatchUpdate::Initial(tasks) => {
            if json {
                println!(
                    "{}",
                    serde_json::json!({ "event": "initial", "tasks": tasks })
                );
            } else {
                println!(
                    "mx-agent: watching {} task(s) in {room} (Ctrl-C to stop)",
                    tasks.len()
                );
                for task in tasks {
                    print_task(task);
                }
            }
        }
        WatchUpdate::Changed { previous, current } => {
            let changes = mx_agent_daemon::diff_tasks(previous, current);
            if json {
                println!(
                    "{}",
                    serde_json::json!({ "event": "changed", "changes": changes })
                );
            } else {
                for change in &changes {
                    print_task_change(change);
                }
            }
        }
        WatchUpdate::Reconnecting { attempt, error } => {
            eprintln!("mx-agent: reconnecting (attempt {attempt}): {error}");
        }
        WatchUpdate::Reconnected => {
            eprintln!("mx-agent: reconnected");
        }
    }
}

fn render_task_watch_ipc_payload(json: bool, room: &str, payload: Value) -> Result<(), String> {
    let event = payload
        .get("event")
        .and_then(Value::as_str)
        .ok_or_else(|| "missing watch event kind".to_string())?;
    match event {
        "initial" => {
            let tasks: Vec<mx_agent_protocol::schema::TaskState> =
                serde_json::from_value(payload.get("tasks").cloned().unwrap_or(Value::Null))
                    .map_err(|e| format!("invalid initial task payload: {e}"))?;
            render_task_update(json, room, mx_agent_daemon::WatchUpdate::Initial(&tasks));
        }
        "changed" => {
            if json {
                let changes = payload.get("changes").cloned().unwrap_or(Value::Null);
                println!(
                    "{}",
                    serde_json::json!({ "event": "changed", "changes": changes })
                );
            } else {
                let previous: Vec<mx_agent_protocol::schema::TaskState> =
                    serde_json::from_value(payload.get("previous").cloned().unwrap_or(Value::Null))
                        .map_err(|e| format!("invalid previous task payload: {e}"))?;
                let current: Vec<mx_agent_protocol::schema::TaskState> =
                    serde_json::from_value(payload.get("current").cloned().unwrap_or(Value::Null))
                        .map_err(|e| format!("invalid current task payload: {e}"))?;
                render_task_update(
                    json,
                    room,
                    mx_agent_daemon::WatchUpdate::Changed {
                        previous: &previous,
                        current: &current,
                    },
                );
            }
        }
        "reconnecting" => {
            let attempt = payload.get("attempt").and_then(Value::as_u64).unwrap_or(0);
            let error = payload
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("unknown error");
            eprintln!("mx-agent: reconnecting (attempt {attempt}): {error}");
        }
        "reconnected" => eprintln!("mx-agent: reconnected"),
        other => return Err(format!("unknown watch event kind {other:?}")),
    }
    Ok(())
}

fn task_watch(global: &GlobalArgs, args: &TaskWatchArgs) -> ExitCode {
    let options = mx_agent_daemon::ListTasksOptions {
        room: args.room.clone(),
        state: args.state.clone(),
        assigned_to: args.assigned.clone(),
    };
    let params = match serde_json::to_value(&options) {
        Ok(params) => params,
        Err(e) => {
            eprintln!("mx-agent: could not encode task.watch request: {e}");
            return ExitCode::FAILURE;
        }
    };
    let socket = daemon_socket_path(global);
    let mut client = match mx_agent_ipc::Client::connect(&socket) {
        Ok(client) => client,
        Err(e) => {
            eprintln!(
                "mx-agent: could not contact daemon at {}: {e}; run `mx-agent daemon start`",
                socket.display()
            );
            return ExitCode::from(3);
        }
    };
    let request = mx_agent_ipc::Request::new(Value::from(1_u64), "task.watch", params);
    if let Err(e) = client.send(&request) {
        eprintln!("mx-agent: daemon IPC request task.watch failed: {e}");
        return ExitCode::FAILURE;
    }
    loop {
        let response = match client.recv() {
            Ok(response) => response,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("mx-agent: daemon IPC request task.watch failed: {e}");
                return ExitCode::FAILURE;
            }
        };
        if let Some(error) = response.error {
            eprintln!("mx-agent: daemon rejected task.watch: {}", error.message);
            return ExitCode::FAILURE;
        }
        let payload = response.result.unwrap_or(Value::Null);
        if let Err(e) = render_task_watch_ipc_payload(global.json, &args.room, payload) {
            eprintln!("mx-agent: daemon returned invalid task.watch response: {e}");
            return ExitCode::FAILURE;
        }
    }
}

/// Handle the `share` command group.
fn handle_share(global: &GlobalArgs, cmd: &ShareCommand) -> ExitCode {
    match cmd {
        ShareCommand::File(args) => share_file(global, args),
        ShareCommand::Diff(args) => share_diff(global, args),
        ShareCommand::Env(args) => share_env(global, args),
        ShareCommand::List(args) => share_list(global, args),
        ShareCommand::Get(args) => share_get(global, args),
    }
}

/// Render a single context share as a human-readable block.
fn print_context_share(share: &mx_agent_protocol::schema::ContextShare) {
    println!(
        "  {:<28} {:<24} {} bytes",
        share.context_id, share.name, share.size_bytes
    );
    println!("    mime_type:    {}", share.mime_type);
    if let Some(encoding) = &share.encoding {
        println!("    encoding:     {encoding}");
    }
    if let Some(mxc_uri) = &share.mxc_uri {
        println!("    mxc_uri:      {mxc_uri}");
    }
    println!("    sha256:       {}", share.sha256);
}

/// Emit a shared [`ContextShare`](mx_agent_protocol::schema::ContextShare) as
/// JSON or a human-readable block.
fn report_share(global: &GlobalArgs, share: &mx_agent_protocol::schema::ContextShare) {
    if global.json {
        println!(
            "{}",
            serde_json::to_string(share).unwrap_or_else(|_| "{}".to_string())
        );
    } else {
        println!("mx-agent: shared {} ({})", share.name, share.context_id);
        print_context_share(share);
    }
}

fn share_file(global: &GlobalArgs, args: &ShareFileArgs) -> ExitCode {
    let data = match read_piped_stdin() {
        Ok(Some(buf)) => buf,
        Ok(None) => {
            eprintln!("mx-agent: share file reads the payload from stdin; pipe or redirect input");
            return ExitCode::from(64);
        }
        Err(e) => {
            eprintln!("mx-agent: could not read stdin: {e}");
            return ExitCode::FAILURE;
        }
    };
    let runtime = match build_runtime() {
        Ok(rt) => rt,
        Err(code) => return code,
    };
    let options = mx_agent_daemon::ShareContextOptions {
        room: args.room.clone(),
        name: args.name.clone(),
        mime_type: args.mime_type.clone(),
        data,
    };
    let session = match load_session_or_exit() {
        Ok(s) => s,
        Err(code) => return code,
    };
    runtime.block_on(async {
        match mx_agent_daemon::share_context_for_session(&session, &options).await {
            Ok(share) => {
                report_share(global, &share);
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("mx-agent: could not share context: {e}");
                ExitCode::FAILURE
            }
        }
    })
}

fn share_diff(global: &GlobalArgs, args: &ShareDiffArgs) -> ExitCode {
    let runtime = match build_runtime() {
        Ok(rt) => rt,
        Err(code) => return code,
    };
    let options = mx_agent_daemon::ShareDiffOptions {
        room: args.room.clone(),
        base: args.base.clone(),
        stat: args.format == DiffFormat::Stat,
    };
    let session = match load_session_or_exit() {
        Ok(s) => s,
        Err(code) => return code,
    };
    runtime.block_on(async {
        match mx_agent_daemon::share_diff_for_session(&session, &options).await {
            Ok(share) => {
                report_share(global, &share);
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("mx-agent: could not share diff: {e}");
                ExitCode::FAILURE
            }
        }
    })
}

fn share_env(global: &GlobalArgs, args: &ShareEnvArgs) -> ExitCode {
    let runtime = match build_runtime() {
        Ok(rt) => rt,
        Err(code) => return code,
    };
    // An empty `--include` falls back to the documented default fact set.
    let include = if args.include.is_empty() {
        mx_agent_daemon::DEFAULT_ENV_INCLUDE
            .iter()
            .map(|s| s.to_string())
            .collect()
    } else {
        args.include.clone()
    };
    let options = mx_agent_daemon::ShareEnvOptions {
        room: args.room.clone(),
        include,
    };
    let session = match load_session_or_exit() {
        Ok(s) => s,
        Err(code) => return code,
    };
    runtime.block_on(async {
        match mx_agent_daemon::share_env_for_session(&session, &options).await {
            Ok(share) => {
                report_share(global, &share);
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("mx-agent: could not share environment: {e}");
                ExitCode::FAILURE
            }
        }
    })
}

fn share_list(global: &GlobalArgs, args: &ShareListArgs) -> ExitCode {
    let runtime = match build_runtime() {
        Ok(rt) => rt,
        Err(code) => return code,
    };
    let options = mx_agent_daemon::ListSharesOptions {
        room: args.room.clone(),
        limit: args.limit,
    };
    let session = match load_session_or_exit() {
        Ok(s) => s,
        Err(code) => return code,
    };
    runtime.block_on(async {
        match mx_agent_daemon::list_context_shares_for_session(&session, &options).await {
            Ok(shares) => {
                if global.json {
                    println!(
                        "{}",
                        serde_json::to_string(&shares).unwrap_or_else(|_| "[]".to_string())
                    );
                } else if shares.is_empty() {
                    println!("mx-agent: no shared context in {}", args.room);
                } else {
                    println!("mx-agent: {} share(s) in {}", shares.len(), args.room);
                    for share in &shares {
                        print_context_share(share);
                    }
                }
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("mx-agent: could not list shared context: {e}");
                ExitCode::FAILURE
            }
        }
    })
}

/// Write a verified artifact to `--output` or stdout.
///
/// The artifact is emitted raw (binary-safe); the share's metadata goes to
/// stderr (or stdout as JSON under `--json`) so it never corrupts the payload
/// stream when piped.
fn emit_fetched_context(
    global: &GlobalArgs,
    fetched: &mx_agent_daemon::FetchedContext,
    output: Option<&PathBuf>,
) -> ExitCode {
    use std::io::Write as _;
    match output {
        Some(path) => {
            if let Err(e) = std::fs::write(path, &fetched.data) {
                eprintln!("mx-agent: could not write {}: {e}", path.display());
                return ExitCode::FAILURE;
            }
            if global.json {
                println!(
                    "{}",
                    serde_json::to_string(&fetched.share).unwrap_or_else(|_| "{}".to_string())
                );
            } else {
                eprintln!(
                    "mx-agent: verified {} ({} bytes) -> {}",
                    fetched.share.context_id,
                    fetched.data.len(),
                    path.display()
                );
            }
        }
        None => {
            let stdout = std::io::stdout();
            let mut handle = stdout.lock();
            if let Err(e) = handle.write_all(&fetched.data) {
                eprintln!("mx-agent: could not write artifact to stdout: {e}");
                return ExitCode::FAILURE;
            }
            if global.json {
                eprintln!(
                    "{}",
                    serde_json::to_string(&fetched.share).unwrap_or_else(|_| "{}".to_string())
                );
            } else {
                eprintln!(
                    "mx-agent: verified {} ({} bytes)",
                    fetched.share.context_id,
                    fetched.data.len()
                );
            }
        }
    }
    ExitCode::SUCCESS
}

fn share_get(global: &GlobalArgs, args: &ShareGetArgs) -> ExitCode {
    let runtime = match build_runtime() {
        Ok(rt) => rt,
        Err(code) => return code,
    };
    let options = mx_agent_daemon::FetchContextOptions {
        room: args.room.clone(),
        context_id: args.context_id.clone(),
        limit: args.limit,
    };
    let session = match load_session_or_exit() {
        Ok(s) => s,
        Err(code) => return code,
    };
    runtime.block_on(async {
        match mx_agent_daemon::fetch_context_for_session(&session, &options).await {
            Ok(fetched) => emit_fetched_context(global, &fetched, args.output.as_ref()),
            Err(e) => {
                eprintln!("mx-agent: could not get shared context: {e}");
                ExitCode::FAILURE
            }
        }
    })
}

/// Handle the `invocation` command group.
fn handle_invocation(global: &GlobalArgs, cmd: &InvocationCommand) -> ExitCode {
    match cmd {
        InvocationCommand::List(args) => invocation_list(global, args),
        InvocationCommand::Show(args) => invocation_show(global, args),
        InvocationCommand::Cancel(args) => invocation_cancel(global, args),
        InvocationCommand::Artifact(args) => invocation_artifact(global, args),
    }
}

/// Write a verified artifact to `--output` or stdout.
///
/// Mirrors [`emit_fetched_context`]: the artifact bytes are emitted raw
/// (binary-safe) while metadata goes to stderr (or stdout as JSON under
/// `--json`) so it never corrupts the payload stream when piped.
fn emit_retrieved_artifact(
    global: &GlobalArgs,
    retrieved: &mx_agent_daemon::RetrievedArtifact,
    output: Option<&PathBuf>,
) -> ExitCode {
    use std::io::Write as _;
    match output {
        Some(path) => {
            if let Err(e) = std::fs::write(path, &retrieved.data) {
                eprintln!("mx-agent: could not write {}: {e}", path.display());
                return ExitCode::FAILURE;
            }
            if global.json {
                println!(
                    "{}",
                    serde_json::to_string(&retrieved.artifact).unwrap_or_else(|_| "{}".to_string())
                );
            } else {
                eprintln!(
                    "mx-agent: verified {} ({} bytes) -> {}",
                    retrieved.artifact.invocation_id,
                    retrieved.data.len(),
                    path.display()
                );
            }
        }
        None => {
            let stdout = std::io::stdout();
            let mut handle = stdout.lock();
            if let Err(e) = handle.write_all(&retrieved.data) {
                eprintln!("mx-agent: could not write artifact to stdout: {e}");
                return ExitCode::FAILURE;
            }
            if global.json {
                eprintln!(
                    "{}",
                    serde_json::to_string(&retrieved.artifact).unwrap_or_else(|_| "{}".to_string())
                );
            } else {
                eprintln!(
                    "mx-agent: verified {} ({} bytes)",
                    retrieved.artifact.invocation_id,
                    retrieved.data.len()
                );
            }
        }
    }
    ExitCode::SUCCESS
}

fn invocation_artifact(global: &GlobalArgs, args: &InvocationArtifactArgs) -> ExitCode {
    let runtime = match build_runtime() {
        Ok(rt) => rt,
        Err(code) => return code,
    };
    let options = mx_agent_daemon::RetrieveArtifactOptions {
        room: args.room.clone(),
        invocation_id: args.invocation_id.clone(),
        stream: args.stream.to_stream_kind(),
        limit: args.limit,
    };
    let session = match load_session_or_exit() {
        Ok(s) => s,
        Err(code) => return code,
    };
    runtime.block_on(async {
        match mx_agent_daemon::retrieve_artifact_for_session(&session, &options).await {
            Ok(retrieved) => emit_retrieved_artifact(global, &retrieved, args.output.as_ref()),
            Err(e) => {
                eprintln!("mx-agent: could not retrieve artifact: {e}");
                ExitCode::FAILURE
            }
        }
    })
}

/// Render a single invocation as a human-readable block.
fn print_invocation(invocation: &mx_agent_protocol::schema::InvocationState) {
    println!(
        "  {:<28} {:<10} {} -> {}",
        invocation.invocation_id, invocation.state, invocation.requester, invocation.target
    );
    if let Some(task_id) = &invocation.task_id {
        println!("    task:         {task_id}");
    }
    if let Some(exit_code) = invocation.exit_code {
        println!("    exit_code:    {exit_code}");
    }
    println!("    state_rev:    {}", invocation.state_rev);
}

fn invocation_list(global: &GlobalArgs, args: &InvocationListArgs) -> ExitCode {
    let runtime = match build_runtime() {
        Ok(rt) => rt,
        Err(code) => return code,
    };
    let options = mx_agent_daemon::ListInvocationsOptions {
        room: args.room.clone(),
        state: args.state.clone(),
        task_id: args.task.clone(),
    };
    let session = match load_session_or_exit() {
        Ok(s) => s,
        Err(code) => return code,
    };
    runtime.block_on(async {
        match mx_agent_daemon::list_invocations_for_session(&session, &options).await {
            Ok(invocations) => {
                if global.json {
                    println!(
                        "{}",
                        serde_json::to_string(&invocations).unwrap_or_else(|_| "[]".to_string())
                    );
                } else if invocations.is_empty() {
                    println!("mx-agent: no invocations in {}", args.room);
                } else {
                    println!(
                        "mx-agent: {} invocation(s) in {}",
                        invocations.len(),
                        args.room
                    );
                    for invocation in &invocations {
                        print_invocation(invocation);
                    }
                }
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("mx-agent: could not list invocations: {e}");
                ExitCode::FAILURE
            }
        }
    })
}

fn invocation_show(global: &GlobalArgs, args: &InvocationShowArgs) -> ExitCode {
    let runtime = match build_runtime() {
        Ok(rt) => rt,
        Err(code) => return code,
    };
    let session = match load_session_or_exit() {
        Ok(s) => s,
        Err(code) => return code,
    };
    runtime.block_on(async {
        match mx_agent_daemon::get_invocation_for_session(&session, &args.room, &args.invocation_id)
            .await
        {
            Ok(Some(invocation)) => {
                if global.json {
                    println!(
                        "{}",
                        serde_json::to_string(&invocation).unwrap_or_else(|_| "{}".to_string())
                    );
                } else {
                    print_invocation(&invocation);
                }
                ExitCode::SUCCESS
            }
            Ok(None) => {
                eprintln!(
                    "mx-agent: invocation {:?} was not found in {}",
                    args.invocation_id, args.room
                );
                ExitCode::FAILURE
            }
            Err(e) => {
                eprintln!("mx-agent: could not show invocation: {e}");
                ExitCode::FAILURE
            }
        }
    })
}

fn invocation_cancel(global: &GlobalArgs, args: &InvocationCancelArgs) -> ExitCode {
    let runtime = match build_runtime() {
        Ok(rt) => rt,
        Err(code) => return code,
    };
    let session = match load_session_or_exit() {
        Ok(s) => s,
        Err(code) => return code,
    };
    // The cancel is signed with the daemon's own key so the target agent can
    // verify the requester before terminating the command.
    let paths = mx_agent_daemon::SessionPaths::resolve();
    let key = match mx_agent_daemon::load_or_create_signing_key(&paths) {
        Ok(key) => key,
        Err(e) => {
            eprintln!("mx-agent: could not load signing key: {e}");
            return ExitCode::FAILURE;
        }
    };
    let key_id = key.key_id();
    runtime.block_on(async {
        match mx_agent_daemon::cancel_invocation_for_session(
            &session,
            key.signing_key(),
            &key_id,
            &args.room,
            &args.invocation_id,
            &args.reason,
        )
        .await
        {
            Ok(invocation) => {
                if global.json {
                    println!(
                        "{}",
                        serde_json::to_string(&invocation).unwrap_or_else(|_| "{}".to_string())
                    );
                } else if invocation.state == "cancelled" {
                    println!(
                        "mx-agent: cancelled invocation {}",
                        invocation.invocation_id
                    );
                    print_invocation(&invocation);
                } else {
                    // The invocation had already finished before we could cancel.
                    println!(
                        "mx-agent: invocation {} already {}; nothing to cancel",
                        invocation.invocation_id, invocation.state
                    );
                }
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("mx-agent: could not cancel invocation: {e}");
                ExitCode::FAILURE
            }
        }
    })
}

/// Handle the `approval` command group.
fn handle_approval(global: &GlobalArgs, cmd: &ApprovalCommand) -> ExitCode {
    match cmd {
        ApprovalCommand::List(args) => approval_list(global, args),
        ApprovalCommand::Show(args) => approval_show(global, args),
        ApprovalCommand::Approve(args) => {
            approval_decide(global, args, mx_agent_daemon::DECISION_APPROVED)
        }
        ApprovalCommand::Deny(args) => {
            approval_decide(global, args, mx_agent_daemon::DECISION_DENIED)
        }
    }
}

/// Render a single pending approval as a human-readable block.
fn print_approval(pending: &mx_agent_daemon::PendingApproval) {
    let req = &pending.request;
    println!(
        "  {:<28} {:<6} {} -> {}",
        req.request_id, req.risk, req.requester, req.target
    );
    println!("    invocation:   {}", req.invocation_id);
    println!("    room:         {}", pending.room_id);
    println!("    summary:      {}", req.summary);
    println!("    expires_at:   {}", req.expires_at);
}

fn approval_list(global: &GlobalArgs, args: &ApprovalListArgs) -> ExitCode {
    let paths = mx_agent_daemon::SessionPaths::resolve();
    match mx_agent_daemon::list_pending_approvals(&paths, args.room.as_deref()) {
        Ok(pending) => {
            if global.json {
                println!(
                    "{}",
                    serde_json::to_string(&pending).unwrap_or_else(|_| "[]".to_string())
                );
            } else if pending.is_empty() {
                match &args.room {
                    Some(room) => println!("mx-agent: no pending approvals in {room}"),
                    None => println!("mx-agent: no pending approvals"),
                }
            } else {
                println!("mx-agent: {} pending approval(s)", pending.len());
                for approval in &pending {
                    print_approval(approval);
                }
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("mx-agent: could not read pending approvals: {e}");
            ExitCode::FAILURE
        }
    }
}

fn approval_show(global: &GlobalArgs, args: &ApprovalShowArgs) -> ExitCode {
    let paths = mx_agent_daemon::SessionPaths::resolve();
    match mx_agent_daemon::get_pending_approval(&paths, &args.request_id) {
        Ok(Some(pending)) => {
            if global.json {
                println!(
                    "{}",
                    serde_json::to_string(&pending).unwrap_or_else(|_| "{}".to_string())
                );
            } else {
                print_approval(&pending);
            }
            ExitCode::SUCCESS
        }
        Ok(None) => {
            eprintln!(
                "mx-agent: approval request {:?} was not found in the local queue",
                args.request_id
            );
            ExitCode::FAILURE
        }
        Err(e) => {
            eprintln!("mx-agent: could not read pending approval: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Approve or deny a queued request: emit the decision event and dequeue it.
///
/// `decision` is [`mx_agent_daemon::DECISION_APPROVED`] or
/// [`mx_agent_daemon::DECISION_DENIED`]. The decision-maker identity defaults to
/// the logged-in user unless `--by` overrides it.
fn approval_decide(global: &GlobalArgs, args: &ApprovalDecideArgs, decision: &str) -> ExitCode {
    let runtime = match build_runtime() {
        Ok(rt) => rt,
        Err(code) => return code,
    };
    let session = match load_session_or_exit() {
        Ok(s) => s,
        Err(code) => return code,
    };
    let approved_by = args.by.clone().unwrap_or_else(|| session.user_id.clone());
    let paths = mx_agent_daemon::SessionPaths::resolve();
    runtime.block_on(async {
        match mx_agent_daemon::decide_approval_for_session(
            &session,
            &paths,
            &args.request_id,
            decision,
            &approved_by,
        )
        .await
        {
            Ok(record) => {
                if global.json {
                    println!(
                        "{}",
                        serde_json::to_string(&record.decision)
                            .unwrap_or_else(|_| "{}".to_string())
                    );
                } else {
                    let verb = if record.approved() {
                        "approved"
                    } else {
                        "denied"
                    };
                    println!(
                        "mx-agent: {verb} approval request {} in {}",
                        record.decision.request_id, record.room_id
                    );
                }
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("mx-agent: could not decide approval: {e}");
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
                ShareCommand::File(_) => "file",
                ShareCommand::Diff(_) => "diff",
                ShareCommand::Env(_) => "env",
                ShareCommand::List(_) => "list",
                ShareCommand::Get(_) => "get",
            }
        ),
        Command::Task(c) => format!(
            "task {}",
            match c {
                TaskCommand::Create(_) => "create",
                TaskCommand::Update(_) => "update",
                TaskCommand::List(_) => "list",
                TaskCommand::Graph(_) => "graph",
                TaskCommand::Watch(_) => "watch",
            }
        ),
        Command::Invocation(c) => format!(
            "invocation {}",
            match c {
                InvocationCommand::List(_) => "list",
                InvocationCommand::Show(_) => "show",
                InvocationCommand::Cancel(_) => "cancel",
                InvocationCommand::Artifact(_) => "artifact",
            }
        ),
        Command::Approval(c) => format!(
            "approval {}",
            match c {
                ApprovalCommand::List(_) => "list",
                ApprovalCommand::Show(_) => "show",
                ApprovalCommand::Approve(_) => "approve",
                ApprovalCommand::Deny(_) => "deny",
            }
        ),
        Command::Trust(c) => format!(
            "trust {}",
            match c {
                TrustCommand::List(_) => "list",
                TrustCommand::Fingerprint => "fingerprint",
                TrustCommand::Approve(_) => "approve",
                TrustCommand::Revoke(_) => "revoke",
                TrustCommand::Publish(_) => "publish",
                TrustCommand::State(_) => "state",
            }
        ),
    }
}

/// Parse repeated `--arg key=value` pairs into a JSON object.
///
/// Values are coerced with the lightest touch that matches operator intent:
/// `true`/`false` become booleans and bare integers become numbers; everything
/// else stays a string. This mirrors the examples in `docs/architecture.md`
/// §5.2 (`--arg package=api --arg coverage=true`).
fn parse_tool_args(pairs: &[String]) -> Result<serde_json::Value, String> {
    let mut map = serde_json::Map::new();
    for pair in pairs {
        let (key, value) = pair
            .split_once('=')
            .ok_or_else(|| format!("argument {pair:?} is not in key=value form"))?;
        if key.is_empty() {
            return Err(format!("argument {pair:?} has an empty key"));
        }
        let json = match value {
            "true" => serde_json::Value::Bool(true),
            "false" => serde_json::Value::Bool(false),
            other => match other.parse::<i64>() {
                Ok(n) => serde_json::Value::from(n),
                Err(_) => serde_json::Value::String(other.to_string()),
            },
        };
        map.insert(key.to_string(), json);
    }
    Ok(serde_json::Value::Object(map))
}

/// Read a JSON object from `path`, or stdin when `path` is `-`.
fn read_json_object(path: &std::path::Path) -> Result<serde_json::Value, String> {
    let raw = if path.as_os_str() == "-" {
        use std::io::Read;
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .map_err(|e| format!("could not read stdin: {e}"))?;
        buf
    } else {
        std::fs::read_to_string(path)
            .map_err(|e| format!("could not read {}: {e}", path.display()))?
    };
    match serde_json::from_str::<serde_json::Value>(&raw) {
        Ok(v) if v.is_object() => Ok(v),
        Ok(_) => Err("--input-json must contain a JSON object".to_string()),
        Err(e) => Err(format!("invalid --input-json: {e}")),
    }
}

/// Validate a task lifecycle state supplied on the CLI.
fn validate_task_state_arg(state: &str) -> Result<(), String> {
    if mx_agent_daemon::is_known_state(state) {
        Ok(())
    } else {
        Err(format!("task state {state:?} is not recognized"))
    }
}

/// Borrowed task action flags used to build a structured task action.
struct TaskActionInput<'a> {
    /// Optional tool name.
    tool: Option<&'a str>,
    /// Repeated `--arg key=value` pairs.
    args: &'a [String],
    /// Optional `--input-json` path.
    input_json: Option<&'a PathBuf>,
    /// Whether `--exec` was set.
    exec: bool,
    /// Optional exec working directory.
    cwd: Option<&'a PathBuf>,
    /// Optional exec timeout.
    timeout_ms: Option<u64>,
    /// Whether streaming was requested for exec.
    stream: bool,
    /// Exec argv after `--`.
    command: &'a [String],
}

/// Build an optional structured task action from task create/update flags.
fn build_task_action(
    input: TaskActionInput<'_>,
) -> Result<Option<mx_agent_protocol::schema::TaskAction>, String> {
    use mx_agent_protocol::schema::TaskAction;

    if input.tool.is_some() && input.exec {
        return Err("--tool and --exec are mutually exclusive".to_string());
    }
    if input.input_json.is_some() && !input.args.is_empty() {
        return Err("--input-json and --arg are mutually exclusive".to_string());
    }
    if input.tool.is_none() && !input.args.is_empty() {
        return Err("--arg requires --tool".to_string());
    }
    if input.tool.is_none() && input.input_json.is_some() {
        return Err("--input-json requires --tool".to_string());
    }
    if !input.exec
        && (!input.command.is_empty()
            || input.cwd.is_some()
            || input.timeout_ms.is_some()
            || input.stream)
    {
        return Err("exec action flags require --exec".to_string());
    }

    if let Some(tool) = input.tool {
        let args = match input.input_json {
            Some(path) => read_json_object(path)?,
            None => parse_tool_args(input.args)?,
        };
        return Ok(Some(TaskAction::Tool {
            tool: tool.to_string(),
            args,
            authorization: None,
        }));
    }

    if input.exec {
        if input.command.is_empty() {
            return Err("--exec requires a command after --".to_string());
        }
        let cwd = input
            .cwd
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|| ".".to_string());
        return Ok(Some(TaskAction::Exec {
            command: input.command.to_vec(),
            cwd,
            env: Default::default(),
            timeout_ms: input.timeout_ms,
            stream: input.stream,
            authorization: None,
        }));
    }

    Ok(None)
}

/// Handle `mx-agent call`: invoke a named built-in tool.
///
/// The CLI runs the tool locally and exits with the tool's own exit code, so
/// `mx-agent call --tool run_tests ...` propagates test failures to the shell
/// (architecture §5.3). The same signed request/response flow is used for
/// remote agents (see `mx_agent_daemon::call`).
fn cmd_call(global: &GlobalArgs, args: &CallArgs) -> ExitCode {
    let tool = match &args.tool {
        Some(t) => t.clone(),
        None => {
            eprintln!("mx-agent: --tool is required");
            return ExitCode::from(64);
        }
    };

    // Build the tool input: a JSON object from --input-json, otherwise from
    // the repeated --arg key=value pairs.
    if args.input_json.is_some() && !args.args.is_empty() {
        eprintln!("mx-agent: --input-json and --arg are mutually exclusive");
        return ExitCode::from(64);
    }
    let input = match &args.input_json {
        Some(path) => match read_json_object(path) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("mx-agent: {e}");
                return ExitCode::from(64);
            }
        },
        None => match parse_tool_args(&args.args) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("mx-agent: {e}");
                return ExitCode::from(64);
            }
        },
    };

    // Tool execution happens in the daemon, never in the CLI: the daemon owns
    // the Matrix client, signing key, policy, and trust context (architecture
    // §10.1, issue #193). The CLI only renders the structured outcome.
    let params = mx_agent_daemon::CallStartParams {
        room: args.room.clone(),
        agent: args.agent.clone(),
        tool,
        input,
    };
    let result: mx_agent_daemon::CallStartResult =
        match daemon_ipc_call(global, "call.start", &params) {
            Ok(result) => result,
            Err(code) => return code,
        };

    match result.outcome {
        mx_agent_daemon::CallOutcome::Ok { exit_code, summary } => {
            if global.json {
                let body = serde_json::json!({ "exit_code": exit_code, "summary": summary });
                println!("{body}");
            } else {
                println!("mx-agent: {summary}");
            }
            // Propagate the tool's exit code so the shell sees failures.
            let code = u8::try_from(exit_code).unwrap_or(1);
            ExitCode::from(code)
        }
        mx_agent_daemon::CallOutcome::Error { kind, message } => {
            if global.json {
                let body = serde_json::json!({ "ok": false, "error": message });
                println!("{body}");
            } else {
                eprintln!("mx-agent: {message}");
            }
            // Map invocation failures to the exit codes in architecture §5.3.
            match kind {
                mx_agent_daemon::CallErrorKind::UnknownTool
                | mx_agent_daemon::CallErrorKind::NotFound => ExitCode::from(127),
                mx_agent_daemon::CallErrorKind::InvalidArgs => ExitCode::from(64),
                mx_agent_daemon::CallErrorKind::Spawn => ExitCode::from(128),
            }
        }
    }
}

/// Convert the daemon's serializable [`mx_agent_daemon::ExecFrame`]s (received
/// over IPC) into the CLI renderer's [`crate::stream::StreamFrame`]s.
///
/// The two carry the same protocol schema payloads; this only re-tags them for
/// the renderer, which consumes frames the same way regardless of whether they
/// came from the daemon's local loopback or (later) a remote agent over Matrix.
fn stream_frames_from_exec(
    frames: Vec<mx_agent_daemon::ExecFrame>,
) -> Vec<crate::stream::StreamFrame> {
    use crate::stream::StreamFrame;
    use mx_agent_daemon::ExecFrame;

    frames
        .into_iter()
        .map(|frame| match frame {
            ExecFrame::Chunk(chunk) => StreamFrame::Chunk(chunk),
            ExecFrame::Artifact(artifact) => StreamFrame::Artifact(artifact),
            ExecFrame::Finished(finished) => StreamFrame::Finished(finished),
        })
        .collect()
}

/// Run a command and render its forwarded output stream locally, exiting with
/// the remote command's exit code (architecture §5.3, §7.3).
fn read_piped_stdin() -> std::io::Result<Option<Vec<u8>>> {
    use std::io::{IsTerminal as _, Read as _};

    let mut stdin = std::io::stdin();
    if stdin.is_terminal() {
        // An interactive terminal is left as the non-interactive `/dev/null`
        // default; interactive PTY exec is handled separately.
        return Ok(None);
    }
    // Stdin has been redirected (a pipe, file, or here-string): buffer it so it
    // can be forwarded to the remote command and the remote stdin closed on EOF
    // (architecture §7.7). The whole input is buffered because the present CLI
    // frame source is a local loopback that runs the command in one shot.
    let mut buf = Vec::new();
    stdin.read_to_end(&mut buf)?;
    Ok(Some(buf))
}

fn cmd_exec(global: &GlobalArgs, args: &ExecArgs) -> ExitCode {
    if args.command.is_empty() {
        eprintln!("mx-agent: exec requires a command after `--`");
        return ExitCode::from(64);
    }
    let cwd = match &args.cwd {
        Some(p) => p.clone(),
        None => match std::env::current_dir() {
            Ok(p) => p,
            Err(e) => {
                eprintln!("mx-agent: cannot determine working directory: {e}");
                return ExitCode::from(64);
            }
        },
    };

    // Interactive PTY mode takes a dedicated, synchronous path: it allocates a
    // pseudo-terminal on the (loopback) remote, mirrors the local terminal's raw
    // mode and window size, and forwards keystrokes and resize events live
    // (architecture §7.3, §8.3). The chunk/finished framing used by the
    // non-interactive path does not apply: a PTY is a single live byte stream.
    // PTY does not yet run over IPC; that is tracked as follow-up to #155.
    if args.pty {
        return cmd_exec_pty(&args.command, cwd);
    }

    // Detect piped stdin: when our standard input is not a terminal it has been
    // redirected (a pipe, file, or here-string), so forward those bytes to the
    // remote command and close on EOF. An interactive terminal is left as the
    // non-interactive `/dev/null` default (interactive PTY exec is separate).
    let stdin = match read_piped_stdin() {
        Ok(stdin) => stdin,
        Err(e) => {
            eprintln!("mx-agent: failed reading stdin: {e}");
            return ExitCode::from(64);
        }
    };

    // Execution happens in the daemon, never in the CLI: the daemon owns process
    // supervision and (for the live flow) the Matrix client, signing key, policy,
    // and trust context (architecture §10.1, issue #155). The CLI only forwards
    // the request and renders the structured frame stream it gets back.
    let params = mx_agent_daemon::ExecStartParams {
        room: args.room.clone(),
        agent: args.agent.clone(),
        command: args.command.clone(),
        cwd: Some(cwd),
        stdin,
        stream: args.stream,
        pty: false,
        task: args.task.clone(),
        strict_stream: args.strict_stream,
    };
    let result: mx_agent_daemon::ExecStartResult =
        match daemon_ipc_call(global, "exec.start", &params) {
            Ok(result) => result,
            Err(code) => return code,
        };

    let frames = match result.outcome {
        mx_agent_daemon::ExecOutcome::Ok { frames } => stream_frames_from_exec(frames),
        mx_agent_daemon::ExecOutcome::Error { kind, message } => {
            eprintln!("mx-agent: exec failed: {message}");
            // Map invocation failures to the exit codes in architecture §5.3.
            return match kind {
                mx_agent_daemon::ExecErrorKind::NotFound => ExitCode::from(127),
                mx_agent_daemon::ExecErrorKind::EmptyCommand => ExitCode::from(64),
                mx_agent_daemon::ExecErrorKind::Spawn => {
                    ExitCode::from(crate::stream::EXIT_PROTOCOL_FAILURE)
                }
            };
        }
    };

    let stdout = std::io::stdout();
    let stderr = std::io::stderr();
    let mut out = stdout.lock();
    let mut err = stderr.lock();
    let render = if args.strict_stream {
        let config = crate::stream::RenderConfig {
            strict: true,
            ..Default::default()
        };
        crate::stream::render_stream_with(frames, config, &mut out, &mut err)
    } else {
        crate::stream::render_stream(frames, &mut out, &mut err)
    };
    match render {
        // In strict mode any integrity violation (a missing or invalid chunk)
        // is fatal: exit 132 regardless of the remote command's own status.
        Ok(outcome) if outcome.integrity_failure => {
            eprintln!("mx-agent: error: stream integrity check failed (strict mode)");
            ExitCode::from(crate::stream::EXIT_STREAM_INTEGRITY)
        }
        // Missing chunks (degraded mode) are surfaced to the user by the
        // renderer as they are detected; best-effort output continues here.
        Ok(outcome) => match outcome.exit_code {
            Some(code) if outcome.degraded() => {
                eprintln!(
                    "mx-agent: warning: output was degraded ({} chunk(s) missing)",
                    outcome.missing.len()
                );
                ExitCode::from(code)
            }
            Some(code) => ExitCode::from(code),
            None => {
                eprintln!("mx-agent: stream ended without exec.finished");
                ExitCode::from(crate::stream::EXIT_PROTOCOL_FAILURE)
            }
        },
        Err(e) => {
            eprintln!("mx-agent: failed writing output: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Run a command on the (loopback) remote agent under an interactive
/// pseudo-terminal, wiring it to the local terminal.
///
/// Allocates a remote PTY for the command, puts the local terminal into raw mode
/// so keystrokes pass straight through, forwards the program's merged output
/// back to the local terminal, and propagates `SIGWINCH` window-size changes to
/// the remote PTY. Returns the command's exit code (architecture §5.3, §7.3).
#[cfg(unix)]
fn cmd_exec_pty(command: &[String], cwd: PathBuf) -> ExitCode {
    use mx_agent_daemon::{PtySession, RunError, RunSpec};

    let spec = RunSpec {
        command: command.to_vec(),
        cwd,
        ..Default::default()
    };

    // Match the remote PTY to the local terminal up front; fall back to the
    // conventional 24×80 when there is no local terminal (e.g. piped stdin).
    let initial = local_winsize().unwrap_or_default();

    let mut session = match PtySession::spawn(&spec, initial) {
        Ok(session) => session,
        Err(e) => {
            eprintln!("mx-agent: exec --pty failed: {e}");
            return match e {
                RunError::MissingCwd(_) => ExitCode::from(127),
                RunError::Spawn(ref io) if io.kind() == std::io::ErrorKind::NotFound => {
                    ExitCode::from(127)
                }
                RunError::EmptyCommand => ExitCode::from(64),
                RunError::Spawn(_) => ExitCode::from(crate::stream::EXIT_PROTOCOL_FAILURE),
            };
        }
    };

    // Raw mode for the session: input bytes (arrow keys, control characters,
    // Ctrl-C) reach the remote PTY unmodified rather than being interpreted
    // locally (see [`crate::terminal`] for the Ctrl-C/signal semantics). A no-op
    // when stdin is not a terminal; restored on drop and on signal-triggered
    // death so the local terminal is never stranded in raw mode.
    let raw = crate::terminal::RawModeGuard::activate();

    // Pump the merged PTY output to the local terminal on a dedicated thread so
    // the child never blocks on a full PTY buffer.
    let output = match session.try_clone_reader() {
        Ok(reader) => Some(std::thread::spawn(move || pump_pty_output(reader))),
        Err(e) => {
            eprintln!("mx-agent: could not read pty output: {e}");
            None
        }
    };

    // Forward local stdin to the PTY on a detached thread. It blocks reading the
    // terminal; when the command exits we stop waiting on it and process
    // teardown reclaims it (a blocking tty read has no clean interruption).
    if let Ok(writer) = session.try_clone_writer() {
        std::thread::spawn(move || pump_stdin(writer));
    }

    // Propagate window-size changes: on each SIGWINCH resize the remote PTY to
    // the new local size. Detached for the session's lifetime.
    if let Ok(resize_fd) = session.try_clone_writer() {
        std::thread::spawn(move || forward_resizes(resize_fd));
    }

    let status = session.wait();

    // Drain remaining output before restoring the terminal.
    if let Some(output) = output {
        let _ = output.join();
    }
    drop(raw);

    match status {
        Ok(status) => ExitCode::from(exit_code_from_status(&status)),
        Err(e) => {
            eprintln!("mx-agent: exec --pty failed waiting for command: {e}");
            ExitCode::from(crate::stream::EXIT_PROTOCOL_FAILURE)
        }
    }
}

/// `--pty` is a Unix-only feature; report cleanly elsewhere.
#[cfg(not(unix))]
fn cmd_exec_pty(_command: &[String], _cwd: PathBuf) -> ExitCode {
    eprintln!("mx-agent: --pty is only supported on Unix platforms");
    ExitCode::from(64)
}

/// Copy the PTY's merged output to the local stdout until end-of-stream.
#[cfg(unix)]
fn pump_pty_output(mut reader: std::fs::File) {
    use std::io::{Read as _, Write as _};

    let mut buf = [0u8; 8192];
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    loop {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if out.write_all(&buf[..n]).is_err() || out.flush().is_err() {
                    break;
                }
            }
            // A PTY master reports EIO (not EOF) once the slave is gone; treat
            // any read error as end-of-stream.
            Err(_) => break,
        }
    }
}

/// Copy local stdin to the PTY until end-of-input.
#[cfg(unix)]
fn pump_stdin(mut writer: std::fs::File) {
    use std::io::{Read as _, Write as _};

    let mut buf = [0u8; 8192];
    let stdin = std::io::stdin();
    let mut input = stdin.lock();
    loop {
        match input.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if writer.write_all(&buf[..n]).is_err() || writer.flush().is_err() {
                    break;
                }
            }
            Err(_) => break,
        }
    }
}

/// Resize the remote PTY whenever the local terminal's window size changes.
#[cfg(unix)]
fn forward_resizes(resize_fd: std::fs::File) {
    use signal_hook::consts::SIGWINCH;
    use signal_hook::iterator::Signals;

    let mut signals = match Signals::new([SIGWINCH]) {
        Ok(signals) => signals,
        Err(_) => return,
    };
    for _ in signals.forever() {
        if let Some(size) = local_winsize() {
            let _ = rustix::termios::tcsetwinsize(&resize_fd, size.into());
        }
    }
}

/// The local terminal's current window size, if stdin or stdout is a terminal.
#[cfg(unix)]
fn local_winsize() -> Option<mx_agent_daemon::PtyWinsize> {
    use rustix::termios::{isatty, tcgetwinsize};

    let stdin = std::io::stdin();
    if isatty(&stdin) {
        if let Ok(ws) = tcgetwinsize(&stdin) {
            return Some(ws.into());
        }
    }
    let stdout = std::io::stdout();
    if isatty(&stdout) {
        if let Ok(ws) = tcgetwinsize(&stdout) {
            return Some(ws.into());
        }
    }
    None
}

/// Map a finished command's [`ExitStatus`] to a local exit code, reporting
/// signal death as `128 + signum` (architecture §5.3).
#[cfg(unix)]
fn exit_code_from_status(status: &std::process::ExitStatus) -> u8 {
    use std::os::unix::process::ExitStatusExt as _;

    if let Some(code) = status.code() {
        return u8::try_from(code).unwrap_or(1);
    }
    if let Some(sig) = status.signal() {
        return u8::try_from(crate::terminal::signal_exit_code(sig))
            .unwrap_or(crate::stream::EXIT_PROTOCOL_FAILURE);
    }
    crate::stream::EXIT_PROTOCOL_FAILURE
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
    fn parse_tool_args_coerces_types() {
        let value = parse_tool_args(&[
            "package=api".to_string(),
            "coverage=true".to_string(),
            "retries=3".to_string(),
        ])
        .unwrap();
        assert_eq!(value["package"], serde_json::json!("api"));
        assert_eq!(value["coverage"], serde_json::json!(true));
        assert_eq!(value["retries"], serde_json::json!(3));
    }

    #[test]
    fn parse_tool_args_rejects_malformed() {
        assert!(parse_tool_args(&["nokey".to_string()]).is_err());
        assert!(parse_tool_args(&["=value".to_string()]).is_err());
    }

    #[test]
    fn call_parses_tool_and_args() {
        let cli = Cli::try_parse_from([
            "mx-agent",
            "call",
            "--tool",
            "run_tests",
            "--arg",
            "package=api",
        ])
        .unwrap();
        match cli.command {
            Command::Call(args) => {
                assert_eq!(args.tool.as_deref(), Some("run_tests"));
                assert_eq!(args.args, vec!["package=api".to_string()]);
            }
            other => panic!("expected call, got {other:?}"),
        }
    }

    #[test]
    fn exec_parses_pty_and_command() {
        let cli =
            Cli::try_parse_from(["mx-agent", "exec", "--pty", "--", "bash"]).expect("parse exec");
        match cli.command {
            Command::Exec(args) => {
                assert!(args.pty, "expected --pty to set the pty flag");
                assert_eq!(args.command, vec!["bash".to_string()]);
            }
            other => panic!("expected exec, got {other:?}"),
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
    fn trust_approve_and_revoke_require_agent_and_key() {
        // agent and key are required for approve/revoke.
        assert!(Cli::try_parse_from(["mx-agent", "trust", "approve"]).is_err());
        assert!(
            Cli::try_parse_from(["mx-agent", "trust", "approve", "--agent", "dev-pi"]).is_err()
        );
        assert!(Cli::try_parse_from(["mx-agent", "trust", "revoke", "--key", "k"]).is_err());

        let cli = Cli::try_parse_from([
            "mx-agent",
            "trust",
            "approve",
            "--agent",
            "dev-pi",
            "--key",
            "mxagent-ed25519:abc123",
            "--room",
            "!abc:matrix.org",
        ])
        .unwrap();
        match &cli.command {
            Command::Trust(TrustCommand::Approve(args)) => {
                assert_eq!(args.agent, "dev-pi");
                assert_eq!(args.key, "mxagent-ed25519:abc123");
                assert_eq!(args.room.as_deref(), Some("!abc:matrix.org"));
            }
            other => panic!("expected trust approve, got {other:?}"),
        }
        assert_eq!(command_path(&cli.command), "trust approve");

        let cli = Cli::try_parse_from([
            "mx-agent",
            "trust",
            "revoke",
            "--agent",
            "dev-pi",
            "--key",
            "mxagent-ed25519:abc123",
        ])
        .unwrap();
        assert_eq!(command_path(&cli.command), "trust revoke");
    }

    #[test]
    fn trust_list_accepts_optional_filters() {
        let cli = Cli::try_parse_from(["mx-agent", "trust", "list"]).unwrap();
        assert_eq!(command_path(&cli.command), "trust list");
        let cli = Cli::try_parse_from([
            "mx-agent",
            "trust",
            "list",
            "--agent",
            "dev-pi",
            "--room",
            "!abc:matrix.org",
        ])
        .unwrap();
        match &cli.command {
            Command::Trust(TrustCommand::List(args)) => {
                assert_eq!(args.agent.as_deref(), Some("dev-pi"));
                assert_eq!(args.room.as_deref(), Some("!abc:matrix.org"));
            }
            other => panic!("expected trust list, got {other:?}"),
        }
    }

    #[test]
    fn trust_publish_requires_room_agent_and_key() {
        assert!(Cli::try_parse_from(["mx-agent", "trust", "publish"]).is_err());
        assert!(Cli::try_parse_from([
            "mx-agent", "trust", "publish", "--agent", "dev-pi", "--key", "k",
        ])
        .is_err());

        let cli = Cli::try_parse_from([
            "mx-agent",
            "trust",
            "publish",
            "--room",
            "!abc:matrix.org",
            "--agent",
            "dev-pi",
            "--key",
            "mxagent-ed25519:abc123",
        ])
        .unwrap();
        match &cli.command {
            Command::Trust(TrustCommand::Publish(args)) => {
                assert_eq!(args.room, "!abc:matrix.org");
                assert_eq!(args.agent, "dev-pi");
                assert_eq!(args.key, "mxagent-ed25519:abc123");
            }
            other => panic!("expected trust publish, got {other:?}"),
        }
        assert_eq!(command_path(&cli.command), "trust publish");
    }

    #[test]
    fn trust_state_requires_room_and_accepts_agent_filter() {
        assert!(Cli::try_parse_from(["mx-agent", "trust", "state"]).is_err());

        let cli = Cli::try_parse_from([
            "mx-agent",
            "trust",
            "state",
            "--room",
            "!abc:matrix.org",
            "--agent",
            "dev-pi",
        ])
        .unwrap();
        match &cli.command {
            Command::Trust(TrustCommand::State(args)) => {
                assert_eq!(args.room, "!abc:matrix.org");
                assert_eq!(args.agent.as_deref(), Some("dev-pi"));
            }
            other => panic!("expected trust state, got {other:?}"),
        }
        assert_eq!(command_path(&cli.command), "trust state");
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
    fn task_create_requires_room_and_title() {
        assert!(Cli::try_parse_from(["mx-agent", "task", "create"]).is_err());
        assert!(
            Cli::try_parse_from(["mx-agent", "task", "create", "--room", "!abc:matrix.org"])
                .is_err()
        );
        let cli = Cli::try_parse_from([
            "mx-agent",
            "task",
            "create",
            "--room",
            "!abc:matrix.org",
            "--title",
            "Run tests",
            "--assign",
            "developer-pi",
            "--depends-on",
            "task_plan",
            "--blocks",
            "task_review",
        ])
        .unwrap();
        match &cli.command {
            Command::Task(TaskCommand::Create(args)) => {
                assert_eq!(args.room, "!abc:matrix.org");
                assert_eq!(args.title, "Run tests");
                assert_eq!(args.assign, "developer-pi");
                assert_eq!(args.depends_on, vec!["task_plan"]);
                assert_eq!(args.blocks, vec!["task_review"]);
                assert!(args.id.is_none());
                assert!(args.tool.is_none());
                assert!(!args.exec);
            }
            other => panic!("expected task create, got {other:?}"),
        }
        assert_eq!(command_path(&cli.command), "task create");
    }

    #[test]
    fn task_create_accepts_tool_action_flags() {
        let cli = Cli::try_parse_from([
            "mx-agent",
            "task",
            "create",
            "--room",
            "!abc:matrix.org",
            "--title",
            "Run tests",
            "--tool",
            "run_tests",
            "--arg",
            "package=api",
        ])
        .unwrap();
        match &cli.command {
            Command::Task(TaskCommand::Create(args)) => {
                assert_eq!(args.tool.as_deref(), Some("run_tests"));
                assert_eq!(args.args, vec!["package=api".to_string()]);
                assert!(!args.exec);
            }
            other => panic!("expected task create, got {other:?}"),
        }
    }

    #[test]
    fn task_create_accepts_exec_action_after_separator() {
        let cli = Cli::try_parse_from([
            "mx-agent",
            "task",
            "create",
            "--room",
            "!abc:matrix.org",
            "--title",
            "Run tests",
            "--exec",
            "--cwd",
            "/repo",
            "--timeout-ms",
            "600000",
            "--stream",
            "--",
            "cargo",
            "test",
        ])
        .unwrap();
        match &cli.command {
            Command::Task(TaskCommand::Create(args)) => {
                assert!(args.exec);
                assert_eq!(args.cwd.as_deref(), Some(std::path::Path::new("/repo")));
                assert_eq!(args.timeout_ms, Some(600_000));
                assert!(args.stream);
                assert_eq!(args.command, vec!["cargo".to_string(), "test".to_string()]);
            }
            other => panic!("expected task create, got {other:?}"),
        }
    }

    #[test]
    fn task_result_summary_uses_stable_fields() {
        let result = serde_json::json!({
            "status": "failed",
            "reason": "process_exit",
            "exit_code": 1,
            "summary": "tests failed"
        });
        assert_eq!(
            task_result_summary(&result),
            "failed; reason=process_exit; exit_code=1; tests failed"
        );
    }

    #[test]
    fn task_state_arg_validation_rejects_unknown_states() {
        assert!(validate_task_state_arg("pending").is_ok());
        assert!(validate_task_state_arg("succeeded").is_ok());
        assert!(validate_task_state_arg("proposed").is_ok());
        assert!(validate_task_state_arg("unknown").is_err());
    }

    #[test]
    fn build_task_action_rejects_conflicts_and_builds_actions() {
        use mx_agent_protocol::schema::TaskAction;
        let arg_pairs = vec!["package=api".to_string()];
        assert!(build_task_action(TaskActionInput {
            tool: Some("run_tests"),
            args: &[],
            input_json: None,
            exec: true,
            cwd: None,
            timeout_ms: None,
            stream: false,
            command: &[],
        })
        .is_err());
        assert!(build_task_action(TaskActionInput {
            tool: None,
            args: &arg_pairs,
            input_json: None,
            exec: false,
            cwd: None,
            timeout_ms: None,
            stream: false,
            command: &[],
        })
        .is_err());

        let tool = build_task_action(TaskActionInput {
            tool: Some("run_tests"),
            args: &arg_pairs,
            input_json: None,
            exec: false,
            cwd: None,
            timeout_ms: None,
            stream: false,
            command: &[],
        })
        .unwrap();
        assert_eq!(
            tool,
            Some(TaskAction::Tool {
                tool: "run_tests".to_string(),
                args: serde_json::json!({ "package": "api" }),
                authorization: None,
            })
        );

        let cwd = PathBuf::from("/repo");
        let command = vec!["cargo".to_string(), "test".to_string()];
        let exec = build_task_action(TaskActionInput {
            tool: None,
            args: &[],
            input_json: None,
            exec: true,
            cwd: Some(&cwd),
            timeout_ms: Some(1000),
            stream: true,
            command: &command,
        })
        .unwrap();
        assert_eq!(
            exec,
            Some(TaskAction::Exec {
                command: vec!["cargo".to_string(), "test".to_string()],
                cwd: "/repo".to_string(),
                env: Default::default(),
                timeout_ms: Some(1000),
                stream: true,
                authorization: None,
            })
        );
    }

    #[test]
    fn task_update_requires_room_and_task_id() {
        assert!(
            Cli::try_parse_from(["mx-agent", "task", "update", "--room", "!abc:matrix.org"])
                .is_err()
        );
        let cli = Cli::try_parse_from([
            "mx-agent",
            "task",
            "update",
            "--room",
            "!abc:matrix.org",
            "task_abc",
            "--state",
            "executing",
            "--assign",
            "developer-pi",
        ])
        .unwrap();
        match &cli.command {
            Command::Task(TaskCommand::Update(args)) => {
                assert_eq!(args.room, "!abc:matrix.org");
                assert_eq!(args.task_id, "task_abc");
                assert_eq!(args.state.as_deref(), Some("executing"));
                assert_eq!(args.assign.as_deref(), Some("developer-pi"));
                assert!(args.tool.is_none());
                assert!(!args.exec);
            }
            other => panic!("expected task update, got {other:?}"),
        }
        assert_eq!(command_path(&cli.command), "task update");
    }

    #[test]
    fn task_list_requires_room_and_accepts_filters() {
        assert!(Cli::try_parse_from(["mx-agent", "task", "list"]).is_err());
        let cli = Cli::try_parse_from([
            "mx-agent",
            "task",
            "list",
            "--room",
            "!abc:matrix.org",
            "--state",
            "pending",
            "--assigned",
            "developer-pi",
        ])
        .unwrap();
        match &cli.command {
            Command::Task(TaskCommand::List(args)) => {
                assert_eq!(args.room, "!abc:matrix.org");
                assert_eq!(args.state.as_deref(), Some("pending"));
                assert_eq!(args.assigned.as_deref(), Some("developer-pi"));
            }
            other => panic!("expected task list, got {other:?}"),
        }
        assert_eq!(command_path(&cli.command), "task list");
    }

    #[test]
    fn task_graph_requires_room() {
        assert!(Cli::try_parse_from(["mx-agent", "task", "graph"]).is_err());
        let cli = Cli::try_parse_from(["mx-agent", "task", "graph", "--room", "!abc:matrix.org"])
            .unwrap();
        match &cli.command {
            Command::Task(TaskCommand::Graph(args)) => {
                assert_eq!(args.room, "!abc:matrix.org");
            }
            other => panic!("expected task graph, got {other:?}"),
        }
        assert_eq!(command_path(&cli.command), "task graph");
    }

    #[test]
    fn task_commands_fail_cleanly_when_daemon_unavailable() {
        let socket = std::env::temp_dir().join(format!(
            "mx-agent-missing-task-ipc-{}-{}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let socket = socket.to_string_lossy().into_owned();
        let commands: &[&[&str]] = &[
            &[
                "mx-agent",
                "--socket",
                &socket,
                "task",
                "create",
                "--room",
                "!abc:matrix.org",
                "--title",
                "Run tests",
            ],
            &[
                "mx-agent",
                "--socket",
                &socket,
                "task",
                "update",
                "--room",
                "!abc:matrix.org",
                "task_abc",
                "--state",
                "succeeded",
            ],
            &[
                "mx-agent",
                "--socket",
                &socket,
                "task",
                "list",
                "--room",
                "!abc:matrix.org",
            ],
            &[
                "mx-agent",
                "--socket",
                &socket,
                "task",
                "graph",
                "--room",
                "!abc:matrix.org",
            ],
            &[
                "mx-agent",
                "--socket",
                &socket,
                "task",
                "watch",
                "--room",
                "!abc:matrix.org",
            ],
        ];

        for argv in commands {
            let cli = Cli::try_parse_from(*argv).unwrap();
            match &cli.command {
                Command::Task(cmd) => {
                    assert_eq!(handle_task(&cli.global, cmd), ExitCode::from(3));
                }
                other => panic!("expected task command, got {other:?}"),
            }
        }
    }

    #[test]
    fn invocation_list_requires_room_and_accepts_filters() {
        assert!(Cli::try_parse_from(["mx-agent", "invocation", "list"]).is_err());
        let cli = Cli::try_parse_from([
            "mx-agent",
            "invocation",
            "list",
            "--room",
            "!abc:matrix.org",
            "--state",
            "running",
            "--task",
            "task_abc",
        ])
        .unwrap();
        match &cli.command {
            Command::Invocation(InvocationCommand::List(args)) => {
                assert_eq!(args.room, "!abc:matrix.org");
                assert_eq!(args.state.as_deref(), Some("running"));
                assert_eq!(args.task.as_deref(), Some("task_abc"));
            }
            other => panic!("expected invocation list, got {other:?}"),
        }
        assert_eq!(command_path(&cli.command), "invocation list");
    }

    #[test]
    fn invocation_show_requires_room_and_id() {
        assert!(Cli::try_parse_from([
            "mx-agent",
            "invocation",
            "show",
            "--room",
            "!abc:matrix.org"
        ])
        .is_err());
        let cli = Cli::try_parse_from([
            "mx-agent",
            "invocation",
            "show",
            "--room",
            "!abc:matrix.org",
            "inv_01HZ",
        ])
        .unwrap();
        match &cli.command {
            Command::Invocation(InvocationCommand::Show(args)) => {
                assert_eq!(args.room, "!abc:matrix.org");
                assert_eq!(args.invocation_id, "inv_01HZ");
            }
            other => panic!("expected invocation show, got {other:?}"),
        }
        assert_eq!(command_path(&cli.command), "invocation show");
    }

    #[test]
    fn invocation_cancel_requires_room_and_id_with_default_reason() {
        // The room flag and the positional invocation id are both required.
        assert!(Cli::try_parse_from([
            "mx-agent",
            "invocation",
            "cancel",
            "--room",
            "!abc:matrix.org"
        ])
        .is_err());
        let cli = Cli::try_parse_from([
            "mx-agent",
            "invocation",
            "cancel",
            "--room",
            "!abc:matrix.org",
            "inv_01HZ",
        ])
        .unwrap();
        match &cli.command {
            Command::Invocation(InvocationCommand::Cancel(args)) => {
                assert_eq!(args.room, "!abc:matrix.org");
                assert_eq!(args.invocation_id, "inv_01HZ");
                // A reason is recorded even when the operator does not supply one.
                assert_eq!(args.reason, "cancelled by operator");
            }
            other => panic!("expected invocation cancel, got {other:?}"),
        }
        assert_eq!(command_path(&cli.command), "invocation cancel");
    }

    #[test]
    fn invocation_cancel_accepts_explicit_reason() {
        let cli = Cli::try_parse_from([
            "mx-agent",
            "invocation",
            "cancel",
            "--room",
            "!abc:matrix.org",
            "--reason",
            "superseded",
            "inv_01HZ",
        ])
        .unwrap();
        match &cli.command {
            Command::Invocation(InvocationCommand::Cancel(args)) => {
                assert_eq!(args.reason, "superseded");
            }
            other => panic!("expected invocation cancel, got {other:?}"),
        }
    }

    #[test]
    fn invocation_artifact_requires_room_and_id_with_stream_default() {
        // The room flag and the positional invocation id are both required.
        assert!(Cli::try_parse_from([
            "mx-agent",
            "invocation",
            "artifact",
            "--room",
            "!abc:matrix.org"
        ])
        .is_err());
        let cli = Cli::try_parse_from([
            "mx-agent",
            "invocation",
            "artifact",
            "--room",
            "!abc:matrix.org",
            "inv_01HZ",
        ])
        .unwrap();
        match &cli.command {
            Command::Invocation(InvocationCommand::Artifact(args)) => {
                assert_eq!(args.room, "!abc:matrix.org");
                assert_eq!(args.invocation_id, "inv_01HZ");
                // The stream defaults to stdout, the common retrieval case.
                assert_eq!(args.stream, StreamChannel::Stdout);
                assert!(args.output.is_none());
                assert_eq!(args.limit, 100);
            }
            other => panic!("expected invocation artifact, got {other:?}"),
        }
        assert_eq!(command_path(&cli.command), "invocation artifact");
    }

    #[test]
    fn invocation_artifact_accepts_stream_and_output() {
        let cli = Cli::try_parse_from([
            "mx-agent",
            "invocation",
            "artifact",
            "--room",
            "!abc:matrix.org",
            "--stream",
            "stderr",
            "--output",
            "/tmp/err.log",
            "inv_01HZ",
        ])
        .unwrap();
        match &cli.command {
            Command::Invocation(InvocationCommand::Artifact(args)) => {
                assert_eq!(args.stream, StreamChannel::Stderr);
                assert_eq!(
                    args.stream.to_stream_kind(),
                    mx_agent_protocol::schema::StreamKind::Stderr
                );
                assert_eq!(
                    args.output.as_deref(),
                    Some(std::path::Path::new("/tmp/err.log"))
                );
            }
            other => panic!("expected invocation artifact, got {other:?}"),
        }
    }

    #[test]
    fn approval_approve_requires_request_id() {
        // The positional request id is required.
        assert!(Cli::try_parse_from(["mx-agent", "approval", "approve"]).is_err());
        let cli = Cli::try_parse_from(["mx-agent", "approval", "approve", "req_01HZ"]).unwrap();
        match &cli.command {
            Command::Approval(ApprovalCommand::Approve(args)) => {
                assert_eq!(args.request_id, "req_01HZ");
                assert!(args.by.is_none(), "decision-maker defaults to the user");
            }
            other => panic!("expected approval approve, got {other:?}"),
        }
        assert_eq!(command_path(&cli.command), "approval approve");
    }

    #[test]
    fn approval_deny_requires_request_id_and_accepts_by() {
        assert!(Cli::try_parse_from(["mx-agent", "approval", "deny"]).is_err());
        let cli = Cli::try_parse_from([
            "mx-agent",
            "approval",
            "deny",
            "--by",
            "@alice:matrix.org",
            "req_01HZ",
        ])
        .unwrap();
        match &cli.command {
            Command::Approval(ApprovalCommand::Deny(args)) => {
                assert_eq!(args.request_id, "req_01HZ");
                assert_eq!(args.by.as_deref(), Some("@alice:matrix.org"));
            }
            other => panic!("expected approval deny, got {other:?}"),
        }
        assert_eq!(command_path(&cli.command), "approval deny");
    }

    #[test]
    fn unknown_command_is_rejected() {
        let err = Cli::try_parse_from(["mx-agent", "definitely-not-a-command"]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::InvalidSubcommand);
    }
}
