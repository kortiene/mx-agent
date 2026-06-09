//! Command-line surface for `mx-agent`.
//!
//! This module defines the full command tree with `clap` and dispatches each
//! command. The CLI is stateless: `auth`, `workspace`, `agent`, `trust`,
//! `approval`, `share`, `invocation`, and `task` are mediated by the daemon over
//! the local Unix-socket IPC channel, and `call`/`exec` run a daemon-mediated
//! local execution by default or a signed Matrix-backed remote operation when
//! `--room`/`--agent` target a remote agent. The CLI never reads the Matrix
//! session or builds a Matrix client itself. Interactive `exec --pty` is also
//! daemon-mediated: the daemon allocates the pseudo-terminal and the CLI streams
//! it over a single IPC connection (issue #238). Large artifacts are still
//! landing — see the project status in `README.md`.

use std::path::PathBuf;
use std::process::ExitCode;

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

    /// Inspect and verify peer Matrix devices (E2EE transport identity).
    #[command(subcommand)]
    Device(DeviceCommand),

    /// Manage server-side key backup and recovery.
    #[command(subcommand)]
    Recovery(RecoveryCommand),
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
    /// Manage the daemon's cross-signing identity.
    #[command(subcommand, name = "cross-signing")]
    CrossSigning(CrossSigningCommand),
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

/// `auth cross-signing` subcommands.
#[derive(Debug, Subcommand)]
enum CrossSigningCommand {
    /// Create and publish the daemon's cross-signing identity (idempotent).
    Bootstrap,
    /// Show cross-signing identity status.
    Status,
}

/// `device` subcommands (Matrix E2EE device verification).
#[derive(Debug, Subcommand)]
enum DeviceCommand {
    /// List devices with verification status and fingerprints.
    List(DeviceListArgs),
    /// Show one device's details.
    Show(DeviceShowArgs),
    /// Verify a peer device (interactive emoji/SAS, or out-of-band fingerprint).
    Verify(DeviceVerifyArgs),
}

#[derive(Debug, Args)]
struct DeviceListArgs {
    /// Workspace room whose joined members' devices to list.
    #[arg(long, value_name = "ROOM")]
    room: Option<String>,
    /// Specific user whose devices to list (defaults to the daemon's own user).
    #[arg(long, value_name = "USER")]
    user: Option<String>,
}

#[derive(Debug, Args)]
struct DeviceShowArgs {
    /// Owning Matrix user id.
    #[arg(long, value_name = "USER")]
    user: String,
    /// Matrix device id.
    #[arg(long, value_name = "DEVICE")]
    device: String,
}

#[derive(Debug, Args)]
struct DeviceVerifyArgs {
    /// Peer Matrix user id to verify with.
    #[arg(long, value_name = "USER")]
    user: String,
    /// Peer Matrix device id to verify.
    #[arg(long, value_name = "DEVICE")]
    device: String,
    /// Verify out-of-band by fingerprint instead of an interactive SAS.
    #[arg(long)]
    manual: bool,
    /// Expected `ed25519:<base64>` device fingerprint (with `--manual`).
    #[arg(long, value_name = "FINGERPRINT")]
    fingerprint: Option<String>,
}

/// `recovery` subcommands (server-side key backup).
#[derive(Debug, Subcommand)]
enum RecoveryCommand {
    /// Provision Secure Secret Storage + key backup; prints the recovery key ONCE.
    Enable,
    /// Show recovery/key-backup status.
    Status,
    /// Re-import keys from server-side backup using a recovery key.
    Recover(RecoveryRecoverArgs),
}

#[derive(Debug, Args)]
struct RecoveryRecoverArgs {
    /// Recovery key recorded when recovery was enabled. If omitted, it is read
    /// from `MX_AGENT_RECOVERY_KEY` or prompted on stdin.
    #[arg(long = "recovery-key", value_name = "KEY")]
    recovery_key: Option<String>,
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
    /// Cancel a task and its linked remote invocation.
    Cancel(TaskCancelArgs),
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

#[derive(Debug, Args)]
struct TaskCancelArgs {
    /// Workspace room alias (`#name:server`) or room ID (`!id:server`).
    #[arg(long, value_name = "ROOM")]
    room: String,
    /// Task ID (state key) to cancel.
    #[arg(value_name = "TASK_ID")]
    task_id: String,
    /// Human-readable reason recorded with the cancellation.
    #[arg(long, value_name = "REASON", default_value = "cancelled by operator")]
    reason: String,
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
        Command::Device(cmd) => handle_device(g, cmd),
        Command::Recovery(cmd) => handle_recovery(g, cmd),
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
        AuthCommand::CrossSigning(cmd) => handle_cross_signing(global, cmd),
    }
}

/// Environment variable used to pass a recovery key without exposing it on the
/// command line.
const ENV_RECOVERY_KEY: &str = "MX_AGENT_RECOVERY_KEY";

/// Handle the `auth cross-signing` subgroup (issue #240).
fn handle_cross_signing(global: &GlobalArgs, cmd: &CrossSigningCommand) -> ExitCode {
    let (method, label) = match cmd {
        CrossSigningCommand::Bootstrap => ("cross_signing.bootstrap", "bootstrap"),
        CrossSigningCommand::Status => ("cross_signing.status", "status"),
    };
    match daemon_ipc_call::<_, mx_agent_daemon::CrossSigningStatusInfo>(
        global,
        method,
        &serde_json::json!({}),
    ) {
        Ok(status) => {
            if global.json {
                println!(
                    "{}",
                    serde_json::to_string(&status).unwrap_or_else(|_| "{}".to_string())
                );
            } else {
                println!("mx-agent: cross-signing {label}");
                println!("  complete:     {}", status.complete);
                println!("  master:       {}", status.has_master);
                println!("  self-signing: {}", status.has_self_signing);
                println!("  user-signing: {}", status.has_user_signing);
            }
            ExitCode::SUCCESS
        }
        Err(code) => code,
    }
}

/// Handle the `device` command group (issue #240).
fn handle_device(global: &GlobalArgs, cmd: &DeviceCommand) -> ExitCode {
    match cmd {
        DeviceCommand::List(args) => device_list(global, args),
        DeviceCommand::Show(args) => device_show(global, args),
        DeviceCommand::Verify(args) => device_verify(global, args),
    }
}

/// Render one device's non-secret status line(s).
fn print_device(device: &mx_agent_daemon::DeviceInfo) {
    let status = if device.blacklisted {
        "blacklisted"
    } else if device.cross_signed {
        "verified (cross-signed)"
    } else if device.verified {
        "verified"
    } else {
        "unverified"
    };
    println!("{} {}  [{status}]", device.user_id, device.device_id);
    if let Some(name) = &device.display_name {
        println!("  name:        {name}");
    }
    if let Some(fingerprint) = &device.ed25519_fingerprint {
        println!("  fingerprint: {fingerprint}");
    }
}

fn device_list(global: &GlobalArgs, args: &DeviceListArgs) -> ExitCode {
    let params = mx_agent_daemon::DeviceListParams {
        room: args.room.clone(),
        user: args.user.clone(),
    };
    match daemon_ipc_call::<_, Vec<mx_agent_daemon::DeviceInfo>>(global, "device.list", &params) {
        Ok(devices) => {
            if global.json {
                println!(
                    "{}",
                    serde_json::to_string(&devices).unwrap_or_else(|_| "[]".to_string())
                );
            } else if devices.is_empty() {
                println!("mx-agent: no devices found");
            } else {
                for device in &devices {
                    print_device(device);
                }
            }
            ExitCode::SUCCESS
        }
        Err(code) => code,
    }
}

fn device_show(global: &GlobalArgs, args: &DeviceShowArgs) -> ExitCode {
    let params = mx_agent_daemon::DeviceShowParams {
        user: args.user.clone(),
        device: args.device.clone(),
    };
    match daemon_ipc_call::<_, Option<mx_agent_daemon::DeviceInfo>>(global, "device.show", &params)
    {
        Ok(Some(device)) => {
            if global.json {
                println!(
                    "{}",
                    serde_json::to_string(&device).unwrap_or_else(|_| "{}".to_string())
                );
            } else {
                print_device(&device);
            }
            ExitCode::SUCCESS
        }
        Ok(None) => {
            if global.json {
                println!("null");
            } else {
                eprintln!(
                    "mx-agent: device {} for {} not found",
                    args.device, args.user
                );
            }
            ExitCode::from(3)
        }
        Err(code) => code,
    }
}

fn device_verify(global: &GlobalArgs, args: &DeviceVerifyArgs) -> ExitCode {
    if args.manual {
        let params = mx_agent_daemon::DeviceVerifyManualParams {
            user: args.user.clone(),
            device: args.device.clone(),
            fingerprint: args.fingerprint.clone(),
        };
        return match daemon_ipc_call::<_, mx_agent_daemon::DeviceInfo>(
            global,
            "device.verify.manual",
            &params,
        ) {
            Ok(device) => {
                if global.json {
                    println!(
                        "{}",
                        serde_json::to_string(&device).unwrap_or_else(|_| "{}".to_string())
                    );
                } else {
                    println!("mx-agent: device verified");
                    print_device(&device);
                }
                ExitCode::SUCCESS
            }
            Err(code) => code,
        };
    }
    device_verify_interactive(global, args)
}

/// Print a SAS short-authentication string for out-of-band comparison.
fn print_sas(emoji: &Option<Vec<mx_agent_daemon::EmojiPair>>, decimals: &Option<(u16, u16, u16)>) {
    eprintln!("mx-agent: compare this short authentication string with the peer device:");
    if let Some(emoji) = emoji {
        let rendered: Vec<String> = emoji
            .iter()
            .map(|e| format!("{} ({})", e.symbol, e.description))
            .collect();
        eprintln!("  emoji:   {}", rendered.join("  "));
    }
    if let Some((a, b, c)) = decimals {
        eprintln!("  decimal: {a}-{b}-{c}");
    }
}

/// Prompt the operator for a yes/no answer on stderr (default no).
fn prompt_yes_no(question: &str) -> bool {
    use std::io::Write as _;
    eprint!("{question} [y/N]: ");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    if std::io::stdin().read_line(&mut line).is_err() {
        return false;
    }
    matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

/// Drive an interactive emoji/SAS device verification, streaming flow frames
/// over a single held-open IPC connection (the operator's confirm/cancel is sent
/// back on the same connection).
fn device_verify_interactive(global: &GlobalArgs, args: &DeviceVerifyArgs) -> ExitCode {
    use mx_agent_daemon::DeviceVerifyFrame as Frame;

    let params = mx_agent_daemon::DeviceVerifyStartParams {
        user: args.user.clone(),
        device: args.device.clone(),
    };
    let payload = match serde_json::to_value(&params) {
        Ok(payload) => payload,
        Err(e) => {
            eprintln!("mx-agent: could not encode device.verify.start request: {e}");
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
    let request = mx_agent_ipc::Request::new(
        Value::from(1_u64),
        mx_agent_daemon::METHOD_DEVICE_VERIFY_START,
        payload,
    );
    if let Err(e) = client.send(&request) {
        eprintln!("mx-agent: daemon IPC request device.verify.start failed: {e}");
        return ExitCode::FAILURE;
    }
    loop {
        let response = match client.recv() {
            Ok(response) => response,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                eprintln!("mx-agent: verification connection closed before completing");
                return ExitCode::FAILURE;
            }
            Err(e) => {
                eprintln!("mx-agent: daemon IPC request device.verify.start failed: {e}");
                return ExitCode::FAILURE;
            }
        };
        if let Some(error) = response.error {
            eprintln!(
                "mx-agent: daemon rejected device.verify.start: {}",
                error.message
            );
            return ExitCode::FAILURE;
        }
        let payload = response.result.unwrap_or(Value::Null);
        let frame: Frame = match serde_json::from_value(payload) {
            Ok(frame) => frame,
            Err(e) => {
                eprintln!("mx-agent: daemon returned invalid device.verify.start response: {e}");
                return ExitCode::FAILURE;
            }
        };
        if global.json {
            println!(
                "{}",
                serde_json::to_string(&frame).unwrap_or_else(|_| "{}".to_string())
            );
        }
        match frame {
            Frame::Started { flow_id } => {
                if !global.json {
                    eprintln!(
                        "mx-agent: verification requested (flow {flow_id}); \
                         waiting for the peer to accept…"
                    );
                }
            }
            Frame::EmojiReady {
                emoji, decimals, ..
            } => {
                if !global.json {
                    print_sas(&emoji, &decimals);
                }
                let confirm = prompt_yes_no("Do these match on the peer device?");
                let method = if confirm { "confirm" } else { "cancel" };
                // Send the decision back on the same connection.
                if let Err(e) = client.send(&mx_agent_ipc::Request::new(
                    Value::from(2_u64),
                    method,
                    Value::Null,
                )) {
                    eprintln!("mx-agent: could not send verification decision: {e}");
                    return ExitCode::FAILURE;
                }
            }
            Frame::Confirmed { .. } => {
                if !global.json {
                    println!("mx-agent: device verified");
                }
                return ExitCode::SUCCESS;
            }
            Frame::Cancelled { .. } => {
                if !global.json {
                    eprintln!("mx-agent: verification cancelled");
                }
                return ExitCode::FAILURE;
            }
            Frame::Error { message } => {
                eprintln!("mx-agent: verification failed: {message}");
                return ExitCode::FAILURE;
            }
        }
    }
}

/// Handle the `recovery` command group (issue #240).
fn handle_recovery(global: &GlobalArgs, cmd: &RecoveryCommand) -> ExitCode {
    match cmd {
        RecoveryCommand::Enable => recovery_enable(global),
        RecoveryCommand::Status => recovery_status(global),
        RecoveryCommand::Recover(args) => recovery_recover(global, args),
    }
}

/// Print recovery/key-backup status.
fn print_recovery_status(global: &GlobalArgs, status: &mx_agent_daemon::RecoveryStatusInfo) {
    if global.json {
        println!(
            "{}",
            serde_json::to_string(status).unwrap_or_else(|_| "{}".to_string())
        );
    } else {
        println!("mx-agent: recovery status");
        println!("  state:                  {}", status.state);
        println!("  backup enabled:         {}", status.backup_enabled);
        println!(
            "  backup exists on server: {}",
            status.backup_exists_on_server
        );
    }
}

fn recovery_enable(global: &GlobalArgs) -> ExitCode {
    match daemon_ipc_call::<_, mx_agent_daemon::RecoveryEnableResult>(
        global,
        "recovery.enable",
        &serde_json::json!({}),
    ) {
        Ok(result) => {
            if global.json {
                // The recovery key is surfaced once for the operator to capture;
                // it is never logged. `--json` includes it for automation.
                println!(
                    "{}",
                    serde_json::to_string(&result).unwrap_or_else(|_| "{}".to_string())
                );
            } else {
                println!("mx-agent: server-side key backup enabled.");
                println!();
                println!("  RECOVERY KEY — store this now; it is shown only once:");
                println!("    {}", result.recovery_key.expose());
                println!();
                println!("  If you lose it, history backed up under it is unrecoverable.");
                println!("  state: {}", result.status.state);
            }
            ExitCode::SUCCESS
        }
        Err(code) => code,
    }
}

fn recovery_status(global: &GlobalArgs) -> ExitCode {
    match daemon_ipc_call::<_, mx_agent_daemon::RecoveryStatusInfo>(
        global,
        "recovery.status",
        &serde_json::json!({}),
    ) {
        Ok(status) => {
            print_recovery_status(global, &status);
            ExitCode::SUCCESS
        }
        Err(code) => code,
    }
}

/// Resolve the recovery key from `--recovery-key`, the environment, or a prompt.
fn resolve_recovery_key(args: &RecoveryRecoverArgs) -> Result<String, ExitCode> {
    if let Some(key) = &args.recovery_key {
        if !key.is_empty() {
            return Ok(key.clone());
        }
    }
    if let Ok(key) = std::env::var(ENV_RECOVERY_KEY) {
        if !key.is_empty() {
            return Ok(key);
        }
    }
    use std::io::Write as _;
    eprint!("Recovery key: ");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    if std::io::stdin().read_line(&mut line).is_err() {
        eprintln!("mx-agent: could not read recovery key");
        return Err(ExitCode::FAILURE);
    }
    let key = line.trim().to_string();
    if key.is_empty() {
        eprintln!(
            "mx-agent: no recovery key provided; set {ENV_RECOVERY_KEY} or enter it when prompted"
        );
        return Err(ExitCode::FAILURE);
    }
    Ok(key)
}

fn recovery_recover(global: &GlobalArgs, args: &RecoveryRecoverArgs) -> ExitCode {
    let recovery_key = match resolve_recovery_key(args) {
        Ok(key) => key,
        Err(code) => return code,
    };
    let params = mx_agent_daemon::RecoverParams { recovery_key };
    match daemon_ipc_call::<_, mx_agent_daemon::RecoveryStatusInfo>(
        global,
        "recovery.recover",
        &params,
    ) {
        Ok(status) => {
            if !global.json {
                println!("mx-agent: keys re-imported from server-side backup");
            }
            print_recovery_status(global, &status);
            ExitCode::SUCCESS
        }
        Err(code) => code,
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
    // Publishing the resolved local record is daemon-mediated: the daemon owns
    // the Matrix session (issue #201).
    let params = mx_agent_daemon::TrustPublishParams {
        room: args.room.clone(),
        entry,
    };
    match daemon_ipc_call::<_, mx_agent_protocol::schema::TrustState>(
        global,
        "trust.publish",
        &params,
    ) {
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
        Err(code) => code,
    }
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
    // Reading published trust state is daemon-mediated; the local store
    // reconciliation below stays CLI-side (local-only, issue #201).
    let params = mx_agent_daemon::RoomParams {
        room: args.room.clone(),
    };
    match daemon_ipc_call::<_, Vec<mx_agent_protocol::schema::TrustState>>(
        global,
        "trust.state",
        &params,
    ) {
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
        Err(code) => code,
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
    match daemon_ipc_call::<_, mx_agent_daemon::WorkspaceInfo>(global, "workspace.create", &options)
    {
        Ok(info) => {
            report_workspace_info(global, &info, "created");
            ExitCode::SUCCESS
        }
        Err(code) => code,
    }
}

fn workspace_join(global: &GlobalArgs, args: &WorkspaceJoinArgs) -> ExitCode {
    let params = mx_agent_daemon::RoomParams {
        room: args.room.clone(),
    };
    match daemon_ipc_call::<_, mx_agent_daemon::WorkspaceInfo>(global, "workspace.join", &params) {
        Ok(info) => {
            report_workspace_info(global, &info, "joined");
            ExitCode::SUCCESS
        }
        Err(code) => code,
    }
}

fn workspace_attach(global: &GlobalArgs, args: &WorkspaceAttachArgs) -> ExitCode {
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
    match daemon_ipc_call::<_, mx_agent_protocol::schema::WorkspaceState>(
        global,
        "workspace.attach",
        &options,
    ) {
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
        Err(code) => code,
    }
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
    let params = mx_agent_daemon::RoomParams {
        room: args.room.clone(),
    };
    match daemon_ipc_call::<_, mx_agent_daemon::WorkspaceStatus>(
        global,
        "workspace.status",
        &params,
    ) {
        Ok(status) => {
            if global.json {
                println!("{}", status.to_json());
            } else {
                print_workspace_status(&status);
            }
            ExitCode::SUCCESS
        }
        Err(code) => code,
    }
}

/// Render one streamed `workspace.watch` IPC payload to the terminal.
fn render_workspace_watch_ipc_payload(json: bool, payload: Value) -> Result<(), String> {
    let event = payload
        .get("event")
        .and_then(Value::as_str)
        .ok_or("watch payload missing event")?;
    match event {
        "initial" | "changed" => {
            let key = if event == "initial" {
                "status"
            } else {
                "current"
            };
            let value = payload.get(key).cloned().unwrap_or(Value::Null);
            let status: mx_agent_daemon::WorkspaceStatus = serde_json::from_value(value)
                .map_err(|e| format!("invalid workspace status payload: {e}"))?;
            if json {
                println!("{}", status.to_json());
            } else {
                print_workspace_status(&status);
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

fn workspace_status_watch(global: &GlobalArgs, args: &WorkspaceStatusArgs) -> ExitCode {
    // Daemon-mediated streaming watch: the daemon owns the Matrix session and
    // streams status snapshots over the open IPC connection (issue #201).
    let params = mx_agent_daemon::RoomParams {
        room: args.room.clone(),
    };
    let params = match serde_json::to_value(&params) {
        Ok(params) => params,
        Err(e) => {
            eprintln!("mx-agent: could not encode workspace.watch request: {e}");
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
    let request = mx_agent_ipc::Request::new(Value::from(1_u64), "workspace.watch", params);
    if let Err(e) = client.send(&request) {
        eprintln!("mx-agent: daemon IPC request workspace.watch failed: {e}");
        return ExitCode::FAILURE;
    }
    loop {
        let response = match client.recv() {
            Ok(response) => response,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("mx-agent: daemon IPC request workspace.watch failed: {e}");
                return ExitCode::FAILURE;
            }
        };
        if let Some(error) = response.error {
            eprintln!(
                "mx-agent: daemon rejected workspace.watch: {}",
                error.message
            );
            return ExitCode::FAILURE;
        }
        let payload = response.result.unwrap_or(Value::Null);
        if let Err(e) = render_workspace_watch_ipc_payload(global.json, payload) {
            eprintln!("mx-agent: daemon returned invalid workspace.watch response: {e}");
            return ExitCode::FAILURE;
        }
    }
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

/// Render `last_seen_ts` (epoch ms) as a short relative age token, e.g.
/// `42s ago`, `3m ago`, `2h ago`. A zero stamp (never seen) reads `never`.
/// Plain integer arithmetic on epoch-ms — no time-formatting dependency.
fn format_last_seen(last_seen_ts: u64) -> String {
    if last_seen_ts == 0 {
        return "never".to_string();
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let secs = now.saturating_sub(last_seen_ts) / 1000;
    if secs < 60 {
        format!("{secs}s ago")
    } else if secs < 3600 {
        format!("{}m ago", secs / 60)
    } else {
        format!("{}h ago", secs / 3600)
    }
}

fn agent_list(global: &GlobalArgs, args: &AgentListArgs) -> ExitCode {
    let options = mx_agent_daemon::ListAgentsOptions {
        room: args.room.clone(),
        capabilities: args.capabilities.clone(),
    };
    match daemon_ipc_call::<_, Vec<mx_agent_daemon::AgentListing>>(global, "agent.list", &options) {
        Ok(listings) => {
            if global.json {
                println!(
                    "{}",
                    serde_json::to_string(&listings).unwrap_or_else(|_| "[]".to_string())
                );
            } else if listings.is_empty() {
                println!("mx-agent: no agents registered in {}", args.room);
            } else {
                println!("mx-agent: {} agent(s) in {}", listings.len(), args.room);
                for listing in &listings {
                    let agent = &listing.agent;
                    let caps = if agent.capabilities.is_empty() {
                        "-".to_string()
                    } else {
                        agent.capabilities.join(",")
                    };
                    println!(
                        "  {:<24} {:<8} {:<8} {:<8} {:<10} {}",
                        agent.agent_id,
                        agent.kind,
                        agent.status,
                        listing.liveness,
                        format_last_seen(agent.last_seen_ts),
                        caps
                    );
                }
            }
            ExitCode::SUCCESS
        }
        Err(code) => code,
    }
}

fn agent_show(global: &GlobalArgs, args: &AgentShowArgs) -> ExitCode {
    let params = mx_agent_daemon::RoomAgentParams {
        room: args.room.clone(),
        agent_id: args.agent_id.clone(),
    };
    match daemon_ipc_call::<_, Option<mx_agent_daemon::AgentListing>>(global, "agent.show", &params)
    {
        Ok(Some(listing)) => {
            if global.json {
                println!(
                    "{}",
                    serde_json::to_string(&listing).unwrap_or_else(|_| "{}".to_string())
                );
            } else {
                let state = &listing.agent;
                println!("mx-agent: agent {}", state.agent_id);
                println!("  kind:         {}", state.kind);
                println!("  status:       {}", state.status);
                println!("  liveness:     {}", listing.liveness);
                println!(
                    "  last_seen:    {} ({} ms)",
                    format_last_seen(state.last_seen_ts),
                    state.last_seen_ts
                );
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
        Err(code) => code,
    }
}

fn agent_tools(global: &GlobalArgs, args: &AgentToolsArgs) -> ExitCode {
    let params = mx_agent_daemon::RoomAgentParams {
        room: args.room.clone(),
        agent_id: args.agent_id.clone(),
    };
    match daemon_ipc_call::<_, Option<mx_agent_daemon::AgentTools>>(global, "agent.tools", &params)
    {
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
                                println!("  {} ({})", schema.qualified_ref(), schema.description);
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
        Err(code) => code,
    }
}

fn agent_register(global: &GlobalArgs, args: &AgentRegisterArgs) -> ExitCode {
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
    match daemon_ipc_call::<_, mx_agent_protocol::schema::AgentState>(
        global,
        "agent.register",
        &options,
    ) {
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
        Err(code) => code,
    }
}

/// Handle the `task` command group.
fn handle_task(global: &GlobalArgs, cmd: &TaskCommand) -> ExitCode {
    match cmd {
        TaskCommand::Create(args) => task_create(global, args),
        TaskCommand::Update(args) => task_update(global, args),
        TaskCommand::List(args) => task_list(global, args),
        TaskCommand::Graph(args) => task_graph(global, args),
        TaskCommand::Watch(args) => task_watch(global, args),
        TaskCommand::Cancel(args) => task_cancel(global, args),
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

fn task_cancel(global: &GlobalArgs, args: &TaskCancelArgs) -> ExitCode {
    // The daemon owns the signing key and signs the linked invocation's cancel so
    // the target agent can verify the requester before terminating the command,
    // then finalizes the owning task `cancelled` via the unified id (issue #239).
    let params = mx_agent_daemon::TaskCancelParams {
        room: args.room.clone(),
        task_id: args.task_id.clone(),
        reason: Some(args.reason.clone()),
    };
    match daemon_ipc_call::<_, mx_agent_protocol::schema::TaskState>(global, "task.cancel", &params)
    {
        Ok(task) => {
            if global.json {
                println!(
                    "{}",
                    serde_json::to_string(&task).unwrap_or_else(|_| "{}".to_string())
                );
            } else if task.state == "cancelled" {
                println!("mx-agent: cancelled task {}", task.task_id);
                print_task(&task);
            } else {
                // The task had already finished before we could cancel; its
                // linked invocation outcome is reflected in the task state.
                println!(
                    "mx-agent: task {} already {}; nothing to cancel",
                    task.task_id, task.state
                );
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
    let options = mx_agent_daemon::ShareContextOptions {
        room: args.room.clone(),
        name: args.name.clone(),
        mime_type: args.mime_type.clone(),
        data,
    };
    match daemon_ipc_call::<_, mx_agent_protocol::schema::ContextShare>(
        global,
        "share.file",
        &options,
    ) {
        Ok(share) => {
            report_share(global, &share);
            ExitCode::SUCCESS
        }
        Err(code) => code,
    }
}

fn share_diff(global: &GlobalArgs, args: &ShareDiffArgs) -> ExitCode {
    let options = mx_agent_daemon::ShareDiffOptions {
        room: args.room.clone(),
        base: args.base.clone(),
        stat: args.format == DiffFormat::Stat,
    };
    match daemon_ipc_call::<_, mx_agent_protocol::schema::ContextShare>(
        global,
        "share.diff",
        &options,
    ) {
        Ok(share) => {
            report_share(global, &share);
            ExitCode::SUCCESS
        }
        Err(code) => code,
    }
}

fn share_env(global: &GlobalArgs, args: &ShareEnvArgs) -> ExitCode {
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
    match daemon_ipc_call::<_, mx_agent_protocol::schema::ContextShare>(
        global,
        "share.env",
        &options,
    ) {
        Ok(share) => {
            report_share(global, &share);
            ExitCode::SUCCESS
        }
        Err(code) => code,
    }
}

fn share_list(global: &GlobalArgs, args: &ShareListArgs) -> ExitCode {
    let options = mx_agent_daemon::ListSharesOptions {
        room: args.room.clone(),
        limit: args.limit,
    };
    match daemon_ipc_call::<_, Vec<mx_agent_protocol::schema::ContextShare>>(
        global,
        "share.list",
        &options,
    ) {
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
        Err(code) => code,
    }
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
    let options = mx_agent_daemon::FetchContextOptions {
        room: args.room.clone(),
        context_id: args.context_id.clone(),
        limit: args.limit,
    };
    match daemon_ipc_call::<_, mx_agent_daemon::FetchedContext>(global, "share.get", &options) {
        Ok(fetched) => emit_fetched_context(global, &fetched, args.output.as_ref()),
        Err(code) => code,
    }
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
    let options = mx_agent_daemon::RetrieveArtifactOptions {
        room: args.room.clone(),
        invocation_id: args.invocation_id.clone(),
        stream: args.stream.to_stream_kind(),
        limit: args.limit,
    };
    match daemon_ipc_call::<_, mx_agent_daemon::RetrievedArtifact>(
        global,
        "invocation.artifact",
        &options,
    ) {
        Ok(retrieved) => emit_retrieved_artifact(global, &retrieved, args.output.as_ref()),
        Err(code) => code,
    }
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
    let options = mx_agent_daemon::ListInvocationsOptions {
        room: args.room.clone(),
        state: args.state.clone(),
        task_id: args.task.clone(),
    };
    match daemon_ipc_call::<_, Vec<mx_agent_protocol::schema::InvocationState>>(
        global,
        "invocation.list",
        &options,
    ) {
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
        Err(code) => code,
    }
}

fn invocation_show(global: &GlobalArgs, args: &InvocationShowArgs) -> ExitCode {
    let params = mx_agent_daemon::RoomInvocationParams {
        room: args.room.clone(),
        invocation_id: args.invocation_id.clone(),
    };
    match daemon_ipc_call::<_, Option<mx_agent_protocol::schema::InvocationState>>(
        global,
        "invocation.get",
        &params,
    ) {
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
        Err(code) => code,
    }
}

fn invocation_cancel(global: &GlobalArgs, args: &InvocationCancelArgs) -> ExitCode {
    // The daemon owns the signing key and signs the cancel so the target agent
    // can verify the requester before terminating the command (issue #201).
    let params = mx_agent_daemon::InvocationCancelParams {
        room: args.room.clone(),
        invocation_id: args.invocation_id.clone(),
        reason: Some(args.reason.clone()),
    };
    match daemon_ipc_call::<_, mx_agent_protocol::schema::InvocationState>(
        global,
        "invocation.cancel",
        &params,
    ) {
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
        Err(code) => code,
    }
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
    // The daemon owns the Matrix session and signing key; it resolves the
    // decision-maker default to its own user ID when `--by` is omitted (#201).
    let params = mx_agent_daemon::ApprovalDecideParams {
        request_id: args.request_id.clone(),
        decision: decision.to_string(),
        by: args.by.clone(),
    };
    match daemon_ipc_call::<_, mx_agent_daemon::ApprovalDecisionRecord>(
        global,
        "approval.decide",
        &params,
    ) {
        Ok(record) => {
            if global.json {
                println!(
                    "{}",
                    serde_json::to_string(&record.decision).unwrap_or_else(|_| "{}".to_string())
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
        Err(code) => code,
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
                AuthCommand::CrossSigning(c) => match c {
                    CrossSigningCommand::Bootstrap => "cross-signing bootstrap",
                    CrossSigningCommand::Status => "cross-signing status",
                },
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
                TaskCommand::Cancel(_) => "cancel",
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
        Command::Device(c) => format!(
            "device {}",
            match c {
                DeviceCommand::List(_) => "list",
                DeviceCommand::Show(_) => "show",
                DeviceCommand::Verify(_) => "verify",
            }
        ),
        Command::Recovery(c) => format!(
            "recovery {}",
            match c {
                RecoveryCommand::Enable => "enable",
                RecoveryCommand::Status => "status",
                RecoveryCommand::Recover(_) => "recover",
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
        // Direct CLI `call` mints a fresh invocation id in the daemon.
        invocation_id: None,
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
                mx_agent_daemon::CallErrorKind::Spawn | mx_agent_daemon::CallErrorKind::Remote => {
                    ExitCode::from(128)
                }
            }
        }
    }
}

/// Convert the daemon's serializable [`mx_agent_daemon::ExecFrame`]s (received
/// over IPC) into the CLI renderer's [`crate::stream::StreamFrame`]s.
///
/// The two carry the same protocol schema payloads; this only re-tags them for
/// the renderer, which consumes frames the same way regardless of whether they
/// came from a daemon-mediated local execution or a remote agent over Matrix.
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

    // Interactive PTY mode takes a dedicated streaming IPC path: the daemon
    // allocates the pseudo-terminal (locally, or on a remote agent over the
    // signed Matrix transport when `--room`/`--agent` are set) and the CLI
    // mirrors the local terminal's raw mode and window size, forwarding
    // keystrokes and resize events live over the one connection (architecture
    // §7.3, §7.6; issue #238). The chunk/finished framing of the non-interactive
    // path does not apply: a PTY is a single live byte stream.
    if args.pty {
        return cmd_exec_pty(global, args, cwd);
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
        // Direct CLI `exec` mints a fresh invocation id in the daemon.
        invocation_id: None,
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
                mx_agent_daemon::ExecErrorKind::Spawn | mx_agent_daemon::ExecErrorKind::Remote => {
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

/// Run a command under an interactive pseudo-terminal allocated by the daemon,
/// wiring it to the local terminal over a streaming IPC connection (issue #238).
///
/// Opens one `exec.pty` connection to the daemon (which allocates the PTY locally
/// or, for `--room`/`--agent`, on a remote agent over the signed Matrix
/// transport), puts the local terminal into raw mode so keystrokes pass straight
/// through, renders the program's merged output, and forwards keystrokes and
/// `SIGWINCH` resize events live on the same connection. Returns the command's
/// exit code (architecture §5.3, §7.3, §7.6).
#[cfg(unix)]
fn cmd_exec_pty(global: &GlobalArgs, args: &ExecArgs, cwd: PathBuf) -> ExitCode {
    use std::os::unix::net::UnixStream;
    use std::sync::{Arc, Mutex};

    let socket = daemon_socket_path(global);
    let stream = match UnixStream::connect(&socket) {
        Ok(stream) => stream,
        Err(e) => {
            eprintln!(
                "mx-agent: could not contact daemon at {}: {e}; run `mx-agent daemon start`",
                socket.display()
            );
            return ExitCode::from(3);
        }
    };

    // Match the PTY to the local terminal up front; fall back to the conventional
    // 24×80 when there is no local terminal (e.g. piped stdin).
    let initial = local_winsize().unwrap_or_default();
    let params = mx_agent_daemon::ExecPtyParams {
        room: args.room.clone(),
        agent: args.agent.clone(),
        command: args.command.clone(),
        cwd: Some(cwd),
        rows: initial.rows,
        cols: initial.cols,
        task: args.task.clone(),
    };
    let params_value = match serde_json::to_value(&params) {
        Ok(value) => value,
        Err(e) => {
            eprintln!("mx-agent: could not encode exec.pty request: {e}");
            return ExitCode::FAILURE;
        }
    };

    let read_stream = match stream.try_clone() {
        Ok(stream) => stream,
        Err(e) => {
            eprintln!("mx-agent: exec --pty failed: {e}");
            return ExitCode::from(crate::stream::EXIT_PROTOCOL_FAILURE);
        }
    };
    let write_stream = Arc::new(Mutex::new(stream));

    // Start the session before entering raw mode so a failure prints cleanly.
    {
        let request = mx_agent_ipc::Request::new(
            Value::from(1_u64),
            mx_agent_daemon::METHOD_EXEC_PTY,
            params_value,
        );
        let mut guard = write_stream.lock().unwrap_or_else(|e| e.into_inner());
        if let Err(e) = write_ipc_request(&mut guard, &request) {
            eprintln!("mx-agent: daemon IPC request exec.pty failed: {e}");
            return ExitCode::FAILURE;
        }
    }

    // Raw mode for the session: input bytes (arrow keys, control characters,
    // Ctrl-C) reach the remote PTY unmodified rather than being interpreted
    // locally (see [`crate::terminal`] for the Ctrl-C/signal semantics). A no-op
    // when stdin is not a terminal; restored on drop and on signal-triggered
    // death so the local terminal is never stranded in raw mode.
    let raw = crate::terminal::RawModeGuard::activate();

    // Render merged PTY output (and learn the exit code) on a dedicated thread.
    let (code_tx, code_rx) = std::sync::mpsc::channel::<u8>();
    let reader = std::thread::spawn(move || pty_render_loop(read_stream, code_tx));

    // Forward local stdin as `pty.stdin` frames. Detached: a blocking tty read
    // has no clean interruption, so teardown reclaims it when the session ends.
    let stdin_stream = write_stream.clone();
    std::thread::spawn(move || pty_forward_stdin(stdin_stream));

    // Forward `SIGWINCH` window-size changes as `pty.resize` frames.
    let resize_stream = write_stream.clone();
    std::thread::spawn(move || pty_forward_resizes(resize_stream));

    let code = code_rx
        .recv()
        .unwrap_or(crate::stream::EXIT_PROTOCOL_FAILURE);
    let _ = reader.join();
    drop(raw);
    ExitCode::from(code)
}

/// `--pty` is a Unix-only feature; report cleanly elsewhere.
#[cfg(not(unix))]
fn cmd_exec_pty(_global: &GlobalArgs, _args: &ExecArgs, _cwd: PathBuf) -> ExitCode {
    eprintln!("mx-agent: --pty is only supported on Unix platforms");
    ExitCode::from(64)
}

/// Write a JSON-RPC request as a length-delimited IPC frame.
#[cfg(unix)]
fn write_ipc_request(
    stream: &mut std::os::unix::net::UnixStream,
    request: &mx_agent_ipc::Request,
) -> std::io::Result<()> {
    let bytes = serde_json::to_vec(request)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    mx_agent_ipc::write_frame(stream, &bytes)
}

/// Render the daemon's [`PtyServerFrame`](mx_agent_daemon::PtyServerFrame) stream
/// to the local terminal, sending the final exit code on `code_tx` when the
/// session finishes (architecture §5.3).
#[cfg(unix)]
fn pty_render_loop(
    mut stream: std::os::unix::net::UnixStream,
    code_tx: std::sync::mpsc::Sender<u8>,
) {
    use base64::Engine as _;
    use std::io::Write as _;

    let stdout = std::io::stdout();
    loop {
        match mx_agent_ipc::read_frame(&mut stream) {
            Ok(Some(bytes)) => {
                let Ok(response) = serde_json::from_slice::<mx_agent_ipc::Response>(&bytes) else {
                    continue;
                };
                if let Some(error) = response.error {
                    eprintln!("mx-agent: exec --pty failed: {}", error.message);
                    let _ = code_tx.send(crate::stream::EXIT_PROTOCOL_FAILURE);
                    return;
                }
                let Some(result) = response.result else {
                    continue;
                };
                let Ok(frame) = serde_json::from_value::<mx_agent_daemon::PtyServerFrame>(result)
                else {
                    continue;
                };
                match frame {
                    mx_agent_daemon::PtyServerFrame::Output { data } => {
                        if let Ok(bytes) =
                            base64::engine::general_purpose::STANDARD.decode(data.as_bytes())
                        {
                            let mut out = stdout.lock();
                            if out.write_all(&bytes).is_err() || out.flush().is_err() {
                                let _ = code_tx.send(crate::stream::EXIT_PROTOCOL_FAILURE);
                                return;
                            }
                        }
                    }
                    mx_agent_daemon::PtyServerFrame::Finished { exit_code, signal } => {
                        let _ = code_tx.send(pty_exit_code(exit_code, signal));
                        return;
                    }
                    mx_agent_daemon::PtyServerFrame::Error { message } => {
                        eprintln!("mx-agent: exec --pty failed: {message}");
                        let _ = code_tx.send(crate::stream::EXIT_PROTOCOL_FAILURE);
                        return;
                    }
                }
            }
            Ok(None) | Err(_) => {
                let _ = code_tx.send(crate::stream::EXIT_PROTOCOL_FAILURE);
                return;
            }
        }
    }
}

/// Map a finished PTY session's status to a local exit code, reporting signal
/// death as `128 + signum` (architecture §5.3).
#[cfg(unix)]
fn pty_exit_code(exit_code: Option<i32>, signal: Option<i32>) -> u8 {
    if let Some(code) = exit_code {
        return u8::try_from(code).unwrap_or(1);
    }
    if let Some(sig) = signal {
        return u8::try_from(crate::terminal::signal_exit_code(sig))
            .unwrap_or(crate::stream::EXIT_PROTOCOL_FAILURE);
    }
    crate::stream::EXIT_PROTOCOL_FAILURE
}

/// Copy local stdin to the daemon as base64 `pty.stdin` frames until end-of-input.
#[cfg(unix)]
fn pty_forward_stdin(stream: std::sync::Arc<std::sync::Mutex<std::os::unix::net::UnixStream>>) {
    use base64::Engine as _;
    use std::io::Read as _;

    let mut buf = [0u8; 8192];
    let stdin = std::io::stdin();
    let mut input = stdin.lock();
    loop {
        match input.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                let frame = mx_agent_daemon::PtyStdinFrame {
                    data: base64::engine::general_purpose::STANDARD.encode(&buf[..n]),
                };
                let Ok(params) = serde_json::to_value(&frame) else {
                    continue;
                };
                let request = mx_agent_ipc::Request::new(
                    Value::Null,
                    mx_agent_daemon::METHOD_PTY_STDIN,
                    params,
                );
                let mut guard = stream.lock().unwrap_or_else(|e| e.into_inner());
                if write_ipc_request(&mut guard, &request).is_err() {
                    break;
                }
            }
            Err(_) => break,
        }
    }
}

/// Forward each `SIGWINCH` window-size change as a `pty.resize` frame.
#[cfg(unix)]
fn pty_forward_resizes(stream: std::sync::Arc<std::sync::Mutex<std::os::unix::net::UnixStream>>) {
    use signal_hook::consts::SIGWINCH;
    use signal_hook::iterator::Signals;

    let mut signals = match Signals::new([SIGWINCH]) {
        Ok(signals) => signals,
        Err(_) => return,
    };
    for _ in signals.forever() {
        let Some(size) = local_winsize() else {
            continue;
        };
        let frame = mx_agent_daemon::PtyResizeFrame {
            rows: size.rows,
            cols: size.cols,
            pixel_width: size.pixel_width,
            pixel_height: size.pixel_height,
        };
        let Ok(params) = serde_json::to_value(frame) else {
            continue;
        };
        let request =
            mx_agent_ipc::Request::new(Value::Null, mx_agent_daemon::METHOD_PTY_RESIZE, params);
        let mut guard = stream.lock().unwrap_or_else(|e| e.into_inner());
        if write_ipc_request(&mut guard, &request).is_err() {
            break;
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
    fn task_cancel_requires_room_and_id_with_default_reason() {
        // The room flag and the positional task id are both required.
        assert!(
            Cli::try_parse_from(["mx-agent", "task", "cancel", "--room", "!abc:matrix.org"])
                .is_err()
        );
        let cli = Cli::try_parse_from([
            "mx-agent",
            "task",
            "cancel",
            "--room",
            "!abc:matrix.org",
            "task_01HZ",
        ])
        .unwrap();
        match &cli.command {
            Command::Task(TaskCommand::Cancel(args)) => {
                assert_eq!(args.room, "!abc:matrix.org");
                assert_eq!(args.task_id, "task_01HZ");
                assert_eq!(args.reason, "cancelled by operator");
            }
            other => panic!("expected task cancel, got {other:?}"),
        }
        assert_eq!(command_path(&cli.command), "task cancel");
    }

    #[test]
    fn task_cancel_accepts_explicit_reason() {
        let cli = Cli::try_parse_from([
            "mx-agent",
            "task",
            "cancel",
            "--room",
            "!abc:matrix.org",
            "--reason",
            "superseded",
            "task_01HZ",
        ])
        .unwrap();
        match &cli.command {
            Command::Task(TaskCommand::Cancel(args)) => {
                assert_eq!(args.reason, "superseded");
            }
            other => panic!("expected task cancel, got {other:?}"),
        }
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

    // --- format_last_seen tests (issue #250) ---

    #[test]
    fn format_last_seen_zero_returns_never() {
        assert_eq!(format_last_seen(0), "never");
    }

    #[test]
    fn format_last_seen_relative_age_units() {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        // Under 60s → "Xs ago".
        assert!(
            format_last_seen(now_ms - 30_000).ends_with("s ago"),
            "30s ago should render as seconds"
        );
        // 60s–3599s → "Xm ago".
        assert!(
            format_last_seen(now_ms - 300_000).ends_with("m ago"),
            "5m ago should render as minutes"
        );
        // ≥ 3600s → "Xh ago".
        assert!(
            format_last_seen(now_ms - 7_200_000).ends_with("h ago"),
            "2h ago should render as hours"
        );
        // A near-epoch timestamp (1ms) is at least 50 years old — always hours.
        assert!(
            format_last_seen(1).ends_with("h ago"),
            "epoch-ms 1 should render as hours ago"
        );
    }

    /// Verifies the `AgentListing` IPC envelope shape: `{"agent": {...},
    /// "liveness": "active"|"stale"|"offline"}`. The `liveness` field must be a
    /// lowercase string and agent fields must be nested under `"agent"`, not at
    /// the top level (issue #250).
    #[test]
    fn agent_listing_json_shape_has_envelope_and_lowercase_liveness() {
        use mx_agent_protocol::schema::{AgentLoad, AgentState, AgentWorkspace};
        let state = AgentState {
            agent_id: "dev-pi".to_string(),
            kind: "pi".to_string(),
            matrix_user_id: "@pi:matrix.org".to_string(),
            device_id: "DEV".to_string(),
            signing_key_id: String::new(),
            signing_public_key: None,
            status: "active".to_string(),
            capabilities: vec![],
            tools: vec![],
            workspace: AgentWorkspace {
                cwd: "/tmp".to_string(),
                project_id: String::new(),
                git_commit: String::new(),
            },
            load: AgentLoad {
                running_invocations: 0,
                max_invocations: 1,
            },
            last_seen_ts: 1_700_000_000_000,
            state_rev: 1,
            extra: Default::default(),
        };
        for (verdict, expected) in [
            (mx_agent_daemon::Liveness::Active, "active"),
            (mx_agent_daemon::Liveness::Stale, "stale"),
            (mx_agent_daemon::Liveness::Offline, "offline"),
        ] {
            let listing = mx_agent_daemon::AgentListing {
                agent: state.clone(),
                liveness: verdict,
            };
            let json = serde_json::to_value(&listing).unwrap();
            assert_eq!(
                json["liveness"].as_str(),
                Some(expected),
                "liveness must serialize as lowercase \"{expected}\""
            );
            assert!(
                json["agent"].is_object(),
                "agent state must be nested under the 'agent' key"
            );
            assert_eq!(
                json["agent"]["agent_id"].as_str(),
                Some("dev-pi"),
                "agent fields must be accessible under 'agent'"
            );
            assert!(
                json.get("agent_id").is_none(),
                "agent_id must not appear at the envelope top level"
            );
        }
    }
}
