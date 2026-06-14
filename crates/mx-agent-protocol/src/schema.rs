//! Serde-serializable content structs for mx-agent protocol events.
//!
//! Each struct models the `content` payload of a Matrix event from
//! `docs/architecture.md` (sections 7, 8, 9, and 13). The event `type` is not
//! part of these structs; use the constants in [`crate::events`] when wrapping
//! a payload in a Matrix event.
//!
//! # Forward compatibility
//!
//! Every content struct carries a flattened `extra` map that captures any
//! unknown fields. This makes readers tolerant of newer producers: unknown
//! future fields are preserved on round-trip instead of being dropped or
//! causing a deserialization error. Required fields, by contrast, must be
//! present or deserialization fails.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Map of unknown/forward-compatible fields captured via `#[serde(flatten)]`.
pub type Extra = BTreeMap<String, Value>;

/// Detached signature carried by signed timeline events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature {
    /// Signature algorithm, e.g. `ed25519`.
    pub alg: String,
    /// Identifier of the signing key, e.g. `mxagent-ed25519:abc123`.
    pub key_id: String,
    /// Base64-encoded signature bytes.
    pub sig: String,
}

/// Stream channel for [`StreamChunk`] / [`StreamArtifact`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StreamKind {
    /// Standard input.
    Stdin,
    /// Standard output.
    Stdout,
    /// Standard error.
    Stderr,
    /// Pseudo-terminal data.
    Pty,
    /// Out-of-band control channel.
    Control,
}

/// `com.mxagent.exec.request.v1` content (architecture §7.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecRequest {
    /// Invocation identifier.
    pub invocation_id: String,
    /// Request identifier.
    pub request_id: String,
    /// Agent expected to run the command.
    pub target_agent: String,
    /// Agent issuing the request.
    pub requesting_agent: String,
    /// Command argv.
    pub command: Vec<String>,
    /// Working directory.
    pub cwd: String,
    /// Environment overrides.
    pub env: BTreeMap<String, String>,
    /// Whether stdin will be streamed.
    pub stdin: bool,
    /// Whether output should be streamed.
    pub stream: bool,
    /// Whether to allocate a PTY.
    pub pty: bool,
    /// Timeout in milliseconds.
    pub timeout_ms: u64,
    /// Owning task identifier, if any.
    pub task_id: Option<String>,
    /// Creation timestamp (RFC 3339).
    pub created_at: String,
    /// Expiry timestamp (RFC 3339).
    pub expires_at: String,
    /// Random nonce (base64).
    pub nonce: String,
    /// Idempotency key.
    pub idempotency_key: String,
    /// Detached signature.
    pub signature: Signature,
    /// Forward-compatible unknown fields.
    #[serde(flatten)]
    pub extra: Extra,
}

/// `com.mxagent.exec.accepted.v1` content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecAccepted {
    /// Invocation identifier.
    pub invocation_id: String,
    /// Forward-compatible unknown fields.
    #[serde(flatten)]
    pub extra: Extra,
}

/// `com.mxagent.exec.rejected.v1` content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecRejected {
    /// Invocation identifier.
    pub invocation_id: String,
    /// Machine-readable rejection reason.
    pub reason: String,
    /// Forward-compatible unknown fields.
    #[serde(flatten)]
    pub extra: Extra,
}

/// `com.mxagent.exec.finished.v1` content (architecture §7.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecFinished {
    /// Invocation identifier.
    pub invocation_id: String,
    /// Process exit code, if it exited normally.
    pub exit_code: Option<i32>,
    /// Terminating signal name, if killed by a signal.
    pub signal: Option<String>,
    /// Wall-clock duration in milliseconds.
    pub duration_ms: u64,
    /// Total stdout bytes produced.
    pub stdout_bytes: u64,
    /// Total stderr bytes produced.
    pub stderr_bytes: u64,
    /// Whether output was truncated.
    pub truncated: bool,
    /// MXC URI of an output artifact, if any.
    pub artifact_mxc: Option<String>,
    /// Forward-compatible unknown fields.
    #[serde(flatten)]
    pub extra: Extra,
}

/// `com.mxagent.exec.stdin.v1` content (architecture §7.5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecStdin {
    /// Invocation identifier.
    pub invocation_id: String,
    /// Base64-encoded stdin bytes. Empty when this event only closes stdin.
    pub data: String,
    /// Whether this chunk closes stdin after any data is written.
    pub eof: bool,
    /// Creation timestamp (RFC 3339).
    pub created_at: String,
    /// Random nonce (base64).
    pub nonce: String,
    /// Detached signature.
    pub signature: Signature,
    /// Forward-compatible unknown fields.
    #[serde(flatten)]
    pub extra: Extra,
}

/// `com.mxagent.exec.cancel.v1` content (architecture §7.5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecCancel {
    /// Invocation identifier.
    pub invocation_id: String,
    /// Cancellation reason.
    pub reason: String,
    /// Creation timestamp (RFC 3339).
    pub created_at: String,
    /// Random nonce (base64).
    pub nonce: String,
    /// Detached signature.
    pub signature: Signature,
    /// Forward-compatible unknown fields.
    #[serde(flatten)]
    pub extra: Extra,
}

/// `com.mxagent.exec.cancelled.v1` content (architecture §7.5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecCancelled {
    /// Invocation identifier.
    pub invocation_id: String,
    /// Signal sent to the process group.
    pub signal_sent: String,
    /// Whether the whole process group was killed.
    pub killed_process_group: bool,
    /// Finish timestamp (RFC 3339).
    pub finished_at: String,
    /// Forward-compatible unknown fields.
    #[serde(flatten)]
    pub extra: Extra,
}

/// `com.mxagent.stream.chunk.v1` content (architecture §7.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamChunk {
    /// Invocation identifier.
    pub invocation_id: String,
    /// Originating stream.
    pub stream: StreamKind,
    /// Monotonic sequence number within the stream.
    pub seq: u64,
    /// Data encoding, e.g. `utf-8` or `base64`.
    pub encoding: String,
    /// Chunk payload (text or base64).
    pub data: String,
    /// Whether this chunk is the stream's EOF marker.
    pub eof: bool,
    /// Whether `data` is compressed.
    pub compressed: bool,
    /// Optional base64 digest of the chunk.
    pub sha256: Option<String>,
    /// Chunk timestamp (RFC 3339).
    pub timestamp: String,
    /// Forward-compatible unknown fields.
    #[serde(flatten)]
    pub extra: Extra,
}

/// `com.mxagent.stream.artifact.v1` content (architecture §8.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamArtifact {
    /// Invocation identifier.
    pub invocation_id: String,
    /// Originating stream.
    pub stream: StreamKind,
    /// Artifact file name.
    pub name: String,
    /// MIME type.
    pub mime_type: String,
    /// Size in bytes.
    pub size_bytes: u64,
    /// Base64 digest of the artifact.
    pub sha256: String,
    /// MXC URI of the uploaded artifact. On the encrypted path this is the
    /// ciphertext URL (`EncryptedFile.url`); the presence of
    /// [`encrypted_file`](Self::encrypted_file) — not this URI — selects the
    /// decrypt path on download.
    pub mxc_uri: String,
    /// Tail preview of the output.
    pub tail_preview: String,
    /// `EncryptedFile` key material (ruma `m.encrypted` file scheme) for a media
    /// payload uploaded to an end-to-end-encrypted room. Present only when the
    /// media blob is ciphertext; absent for a plaintext `mxc_uri` upload (the
    /// default and the only form produced before this field existed). Carried as
    /// an opaque JSON object so the protocol crate stays free of a ruma
    /// dependency. The bytes are the AES-CTR key, IV, and ciphertext SHA-256
    /// hashes; never log them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_file: Option<Value>,
    /// Forward-compatible unknown fields.
    #[serde(flatten)]
    pub extra: Extra,
}

/// `com.mxagent.pty.resize.v1` content (architecture §7.7).
///
/// Sent from the requesting side to the executing agent whenever the local
/// terminal's window size changes, so the remote PTY is resized to match and
/// full-screen programs (editors, pagers) re-render at the new dimensions. The
/// pixel dimensions are advisory: they are `0` when the local terminal does not
/// report them, and most consumers only need `rows`/`cols`.
///
/// Resize is a **signed control event**, like [`ExecStdin`] and [`ExecCancel`]:
/// it carries `created_at`, `nonce`, and a detached [`signature`](Self::signature)
/// so the target authorizes it against a locally trusted signing key owned by the
/// invocation's requester (signature → trust → ownership), rather than trusting
/// the homeserver-asserted Matrix sender. Room membership alone never resizes
/// another agent's session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PtyResize {
    /// Invocation identifier the resize applies to.
    pub invocation_id: String,
    /// New height in character rows.
    pub rows: u16,
    /// New width in character columns.
    pub cols: u16,
    /// New width in pixels, or `0` when unknown.
    #[serde(default)]
    pub pixel_width: u16,
    /// New height in pixels, or `0` when unknown.
    #[serde(default)]
    pub pixel_height: u16,
    /// Creation timestamp (RFC 3339).
    pub created_at: String,
    /// Random nonce (base64).
    pub nonce: String,
    /// Detached signature.
    pub signature: Signature,
    /// Forward-compatible unknown fields.
    #[serde(flatten)]
    pub extra: Extra,
}

/// `com.mxagent.context.share.v1` content (architecture §6/7.1).
///
/// A context object is carried in one of two ways. **Small payloads** are
/// inlined directly in the event via [`data`](Self::data) (encoded per
/// [`encoding`](Self::encoding)), avoiding a media round-trip. **Large objects**
/// are uploaded as Matrix media and referenced by [`mxc_uri`](Self::mxc_uri).
/// Exactly one of the two is populated for a given share; the other is `None`.
/// In both cases [`sha256`](Self::sha256) digests the raw bytes so a receiver
/// can verify integrity regardless of transport encoding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextShare {
    /// Context identifier.
    pub context_id: String,
    /// Object name.
    pub name: String,
    /// MIME type.
    pub mime_type: String,
    /// Size in bytes of the raw (decoded) payload.
    pub size_bytes: u64,
    /// Base64 digest of the raw (decoded) payload.
    pub sha256: String,
    /// Inline payload for a small context, encoded per
    /// [`encoding`](Self::encoding). `None` when the object is stored as Matrix
    /// media and referenced by [`mxc_uri`](Self::mxc_uri) instead.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
    /// Encoding of [`data`](Self::data): `utf-8` for text or `base64` for
    /// binary. `None` when there is no inline payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encoding: Option<String>,
    /// MXC URI of the uploaded object for a large context. `None` for an inline
    /// (small-payload) share. On the encrypted path this is the ciphertext URL
    /// (`EncryptedFile.url`); the presence of
    /// [`encrypted_file`](Self::encrypted_file) — not this URI — selects the
    /// decrypt path on download.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mxc_uri: Option<String>,
    /// `EncryptedFile` key material (ruma `m.encrypted` file scheme) for a
    /// media-backed share uploaded to an end-to-end-encrypted room. Present only
    /// when the media blob is ciphertext; absent for an inline payload or a
    /// plaintext `mxc_uri` upload (the default and the only form produced before
    /// this field existed). Carried as an opaque JSON object so the protocol
    /// crate stays free of a ruma dependency. The bytes are the AES-CTR key, IV,
    /// and ciphertext SHA-256 hashes; never log them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_file: Option<Value>,
    /// Forward-compatible unknown fields.
    #[serde(flatten)]
    pub extra: Extra,
}

/// `com.mxagent.tool.v1` state content (architecture §5.2, §7.1).
///
/// Describes a single named tool an agent offers. Tools are the preferred
/// security boundary over raw `exec`: they declare strict input/output JSON
/// schemas so callers know exactly what arguments are accepted and what shape
/// the result takes. The `input_schema` and `output_schema` fields hold JSON
/// Schema documents as opaque [`Value`]s so the model does not constrain which
/// subset of JSON Schema a tool uses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolSchema {
    /// Tool name, e.g. `run_tests`.
    pub name: String,
    /// Tool version, e.g. `1.0.0`.
    pub version: String,
    /// Human-readable description of what the tool does.
    pub description: String,
    /// JSON Schema document describing accepted input arguments.
    pub input_schema: Value,
    /// JSON Schema document describing the result payload.
    pub output_schema: Value,
    /// Forward-compatible unknown fields.
    #[serde(flatten)]
    pub extra: Extra,
}

impl ToolSchema {
    /// Return the qualified tool reference (`name@version`) used to advertise
    /// this tool in [`AgentState::tools`].
    pub fn qualified_ref(&self) -> String {
        format!("{}@{}", self.name, self.version)
    }
}

/// `com.mxagent.call.request.v1` content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallRequest {
    /// Invocation identifier.
    pub invocation_id: String,
    /// Request identifier.
    pub request_id: String,
    /// Named tool being invoked.
    pub tool: String,
    /// Tool arguments.
    pub args: Value,
    /// Creation timestamp (RFC 3339).
    pub created_at: String,
    /// Expiry timestamp (RFC 3339); the target rejects the request after this.
    pub expires_at: String,
    /// Random nonce, unique per request, used for replay protection.
    pub nonce: String,
    /// Detached signature.
    pub signature: Signature,
    /// Agent identifier that issued the request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requesting_agent: Option<String>,
    /// Agent identifier expected to execute the request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_agent: Option<String>,
    /// Forward-compatible unknown fields.
    #[serde(flatten)]
    pub extra: Extra,
}

/// `com.mxagent.call.response.v1` content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallResponse {
    /// Request identifier this responds to.
    pub request_id: String,
    /// Whether the call succeeded.
    pub ok: bool,
    /// Result payload on success.
    pub result: Option<Value>,
    /// Error message on failure.
    pub error: Option<String>,
    /// Forward-compatible unknown fields.
    #[serde(flatten)]
    pub extra: Extra,
}

/// `com.mxagent.approval.request.v1` content (architecture §11).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalRequest {
    /// Request identifier.
    pub request_id: String,
    /// Associated invocation.
    pub invocation_id: String,
    /// Requesting agent.
    pub requester: String,
    /// Target agent.
    pub target: String,
    /// Human-readable summary.
    pub summary: String,
    /// Risk level, e.g. `low`/`medium`/`high`.
    pub risk: String,
    /// Expiry timestamp (RFC 3339).
    pub expires_at: String,
    /// Forward-compatible unknown fields.
    #[serde(flatten)]
    pub extra: Extra,
}

/// `com.mxagent.approval.decision.v1` content (architecture §11, §12).
///
/// A decision releases (or denies) a held `requires_approval` action. To prevent
/// any room member from forging a release, an honored decision must carry a
/// single-use [`nonce`](Self::nonce) and a detached [`signature`](Self::signature)
/// from a locally-trusted signing key, bounded by [`expires_at`](Self::expires_at)
/// — mirroring [`ExecRequest`]/[`CallRequest`]. The fields are optional at the
/// serde layer so older/hostile events still deserialize (and can be logged and
/// rejected rather than failing to parse), but the verifier treats a missing
/// nonce or signature as **not verifiable → rejected**.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalDecision {
    /// Request identifier this decides.
    pub request_id: String,
    /// Decision, e.g. `approved`/`denied`.
    pub decision: String,
    /// Identity that made the decision.
    pub approved_by: String,
    /// Decision timestamp (RFC 3339).
    pub created_at: String,
    /// Single-use nonce binding this decision for replay protection. Absent on
    /// legacy/unsigned events, which the verifier rejects.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    /// Expiry (RFC 3339 UTC) bounding the decision's replay-cache lifetime.
    /// Absent on legacy/unsigned events, which the verifier rejects.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    /// Detached Ed25519 signature over the decision's canonical bytes (the
    /// `signature` field excluded). Absent on legacy/unsigned events, which the
    /// verifier rejects.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<Signature>,
    /// Forward-compatible unknown fields.
    #[serde(flatten)]
    pub extra: Extra,
}

/// Git repository metadata for a [`WorkspaceState`] (architecture §9.3).
///
/// Each field is `None` when the corresponding git metadata cannot be
/// determined (for example, a repository with no remote or no commits yet).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepoInfo {
    /// Remote URL of the `origin` remote, if any.
    pub remote_url: Option<String>,
    /// Currently checked-out branch, if on a branch.
    pub branch: Option<String>,
    /// Currently checked-out commit hash, if any.
    pub commit: Option<String>,
}

/// `com.mxagent.workspace.v1` state content (architecture §9.3).
///
/// Published with an empty state key: one workspace metadata record per room.
///
/// # Confidentiality
///
/// This is a Matrix **state** event: its `project_id`, local `path`, and repo
/// metadata are plaintext readable by the homeserver operator and all room
/// members even in an `--e2ee on` workspace (state events are not
/// Megolm-encrypted). Do not attach a path or project identifier you consider
/// secret (issue #308).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceState {
    /// Project identifier, e.g. `repo:github.com/org/project`.
    pub project_id: String,
    /// Local filesystem path attached on the publishing agent.
    pub path: String,
    /// Git repository metadata, or `None` when `path` is not a git repository.
    pub repo: Option<RepoInfo>,
    /// Matrix user ID that published this workspace state.
    pub attached_by: String,
    /// Attachment timestamp (ms since epoch).
    pub attached_at: u64,
    /// State revision counter.
    pub state_rev: u64,
    /// Forward-compatible unknown fields.
    #[serde(flatten)]
    pub extra: Extra,
}

/// Workspace metadata embedded in [`AgentState`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentWorkspace {
    /// Current working directory.
    pub cwd: String,
    /// Project identifier.
    pub project_id: String,
    /// Git commit hash.
    pub git_commit: String,
}

/// Load metrics embedded in [`AgentState`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentLoad {
    /// Number of running invocations.
    pub running_invocations: u32,
    /// Maximum concurrent invocations.
    pub max_invocations: u32,
}

/// `com.mxagent.agent.v1` state content (architecture §9.1).
///
/// # Confidentiality
///
/// This is a Matrix **state** event, refreshed by the heartbeat loop. Its
/// declared `capabilities`, `tools`, and embedded [`AgentWorkspace`] (`cwd`,
/// `project_id`, git commit) are plaintext readable by the homeserver operator
/// even in an `--e2ee on` workspace (state events are not Megolm-encrypted)
/// (issue #308).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentState {
    /// Agent identifier.
    pub agent_id: String,
    /// Agent kind, e.g. `pi`.
    pub kind: String,
    /// Matrix user ID.
    pub matrix_user_id: String,
    /// Matrix device ID.
    pub device_id: String,
    /// Signing key identifier.
    pub signing_key_id: String,
    /// Base64-no-pad Ed25519 verifying key bytes for `signing_key_id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_public_key: Option<String>,
    /// Status, e.g. `active`.
    pub status: String,
    /// Declared capabilities.
    pub capabilities: Vec<String>,
    /// Available named tools.
    pub tools: Vec<String>,
    /// Workspace metadata.
    pub workspace: AgentWorkspace,
    /// Load metrics.
    pub load: AgentLoad,
    /// Last-seen timestamp (ms since epoch).
    pub last_seen_ts: u64,
    /// State revision counter.
    pub state_rev: u64,
    /// Forward-compatible unknown fields.
    #[serde(flatten)]
    pub extra: Extra,
}

/// `com.mxagent.heartbeat.v1` timeline content (architecture §7.1, §9.1).
///
/// A heartbeat is a lightweight liveness signal an agent emits periodically
/// into a workspace room's timeline. Peers combine the most recent heartbeat
/// timestamp with the durable [`AgentState`] to compute whether an agent is
/// active, stale, or offline (see architecture §9.1, "Liveness should
/// combine"). Heartbeats are timeline events rather than state events so that
/// frequent liveness updates do not churn room state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Heartbeat {
    /// Agent identifier the heartbeat is for.
    pub agent_id: String,
    /// Self-reported status, e.g. `active`.
    pub status: String,
    /// Load metrics at the time of the heartbeat.
    pub load: AgentLoad,
    /// Heartbeat timestamp (ms since epoch).
    pub ts: u64,
    /// Forward-compatible unknown fields.
    #[serde(flatten)]
    pub extra: Extra,
}

/// Signed authorization attached to a privileged task action.
///
/// The signature is produced by the requesting agent's mx-agent signing key and
/// authorizes one specific task action until `expires_at`. Daemons still verify
/// local trust, replay protection, and policy before executing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskActionAuthorization {
    /// Agent requesting the action.
    pub requesting_agent: String,
    /// Agent expected to execute the action.
    pub target_agent: String,
    /// Creation timestamp (RFC 3339).
    pub created_at: String,
    /// Expiry timestamp (RFC 3339).
    pub expires_at: String,
    /// Random nonce for replay protection.
    pub nonce: String,
    /// Detached signature over the task id, action, and authorization metadata.
    pub signature: Signature,
    /// Forward-compatible unknown fields.
    #[serde(flatten)]
    pub extra: Extra,
}

/// Structured work attached to a [`TaskState`] (architecture §9.2).
///
/// A task without an action is a manual/planning task: it can be listed,
/// assigned, and transitioned by users, but the daemon must not infer executable
/// work from its title or description. An action describes the requested work;
/// it is not an authorization grant. Daemons still route execution through the
/// signed, trust-checked, deny-by-default policy path before spawning anything.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TaskAction {
    /// Invoke a named, policy-controlled tool.
    Tool {
        /// Tool name, e.g. `run_tests`.
        tool: String,
        /// Tool arguments as a JSON object or value understood by the tool.
        #[serde(default)]
        args: Value,
        /// Signed authorization making this advisory action executable.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        authorization: Option<TaskActionAuthorization>,
    },
    /// Invoke an exec-style command through the daemon's execution path.
    ///
    /// # Confidentiality
    ///
    /// This action is carried in the `com.mxagent.task.v1` **state** event, which
    /// Matrix never Megolm-encrypts — even in an `--e2ee on` workspace, state
    /// events are plaintext readable by the homeserver operator. The scheduler
    /// reads `command`/`cwd`/`env` from state to execute the task, so they cannot
    /// be redacted or moved into encrypted timeline events without the deferred
    /// task-engine redesign (issue #308). **Do not place secrets in `env`**; the
    /// daemon emits an advisory warning when a non-empty `env` is published into
    /// an encrypted room.
    Exec {
        /// Command argv: program followed by arguments. Published in plaintext
        /// room state; readable by the homeserver operator even under `--e2ee on`.
        command: Vec<String>,
        /// Working directory for the command. Published in plaintext room state.
        cwd: String,
        /// Explicit environment overrides. Published in plaintext room state and
        /// readable by the homeserver operator even under `--e2ee on`; never
        /// place secrets here.
        #[serde(default)]
        env: BTreeMap<String, String>,
        /// Optional timeout in milliseconds.
        #[serde(default)]
        timeout_ms: Option<u64>,
        /// Whether output should be streamed.
        #[serde(default)]
        stream: bool,
        /// Signed authorization making this advisory action executable.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        authorization: Option<TaskActionAuthorization>,
    },
}

impl TaskAction {
    /// Return the stable action kind used in task results and diagnostics.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Tool { .. } => "tool",
            Self::Exec { .. } => "exec",
        }
    }

    /// Borrow the signed authorization attached to this action, if any.
    pub fn authorization(&self) -> Option<&TaskActionAuthorization> {
        match self {
            Self::Tool { authorization, .. } | Self::Exec { authorization, .. } => {
                authorization.as_ref()
            }
        }
    }

    /// Return a clone of this action with any embedded authorization removed.
    ///
    /// This is the action representation covered by a task-action signature.
    pub fn without_authorization(&self) -> Self {
        match self {
            Self::Tool { tool, args, .. } => Self::Tool {
                tool: tool.clone(),
                args: args.clone(),
                authorization: None,
            },
            Self::Exec {
                command,
                cwd,
                env,
                timeout_ms,
                stream,
                ..
            } => Self::Exec {
                command: command.clone(),
                cwd: cwd.clone(),
                env: env.clone(),
                timeout_ms: *timeout_ms,
                stream: *stream,
                authorization: None,
            },
        }
    }

    /// Consume this action and return it carrying `authorization`, replacing any
    /// authorization already attached.
    ///
    /// Symmetric to [`TaskAction::without_authorization`]: the daemon signs the
    /// authorization-stripped action, then re-attaches the freshly signed
    /// [`TaskActionAuthorization`] via this helper before publishing the action
    /// to room state. The signed (`task_id` + stripped-action) binding is what a
    /// verifier checks, so attaching the authorization here does not change the
    /// bytes that were signed.
    pub fn with_authorization(self, authorization: TaskActionAuthorization) -> Self {
        match self {
            Self::Tool { tool, args, .. } => Self::Tool {
                tool,
                args,
                authorization: Some(authorization),
            },
            Self::Exec {
                command,
                cwd,
                env,
                timeout_ms,
                stream,
                ..
            } => Self::Exec {
                command,
                cwd,
                env,
                timeout_ms,
                stream,
                authorization: Some(authorization),
            },
        }
    }
}

/// Stable result object stored in [`TaskState::result`] (architecture §9.2).
///
/// `TaskState::result` remains an optional JSON value for wire compatibility,
/// but daemon-written results use this documented shape so automation can rely
/// on stable fields. The summary should be non-sensitive: large or secret-prone
/// output belongs in stream/artifact events, not in the task result.
///
/// # Confidentiality
///
/// This result is stored in the `com.mxagent.task.v1` **state** event, which is
/// plaintext readable by the homeserver operator even in an `--e2ee on`
/// workspace (Matrix does not Megolm-encrypt state events). Keep the
/// [`summary`](Self::summary) non-sensitive and point full output at an
/// encrypted media artifact via [`artifact_mxc`](Self::artifact_mxc) rather than
/// embedding it here (issue #308).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskResult {
    /// Terminal status, normally `succeeded` or `failed`.
    pub status: String,
    /// Agent that completed/finalized the task.
    pub completed_by: String,
    /// Completion timestamp (RFC 3339).
    pub completed_at: String,
    /// Invocation associated with the result, if any.
    pub invocation_id: Option<String>,
    /// Action kind, e.g. `tool` or `exec`, when known.
    #[serde(default)]
    pub action: Option<String>,
    /// Machine-readable failure/recovery reason, if any.
    #[serde(default)]
    pub reason: Option<String>,
    /// Process/tool exit code, if applicable.
    pub exit_code: Option<i32>,
    /// Non-sensitive human summary, if available.
    #[serde(default)]
    pub summary: Option<String>,
    /// Optional Matrix artifact link for full output.
    #[serde(default)]
    pub artifact_mxc: Option<String>,
    /// Forward-compatible unknown fields.
    #[serde(flatten)]
    pub extra: Extra,
}

impl TaskResult {
    /// Convert this stable result into the JSON value stored in
    /// [`TaskState::result`].
    pub fn into_value(self) -> Value {
        serde_json::to_value(self).unwrap_or(Value::Null)
    }
}

/// `com.mxagent.task.v1` state content (architecture §9.2).
///
/// # Confidentiality
///
/// This is a Matrix **state** event. Matrix never Megolm-encrypts state events,
/// so even in an `--e2ee on` workspace the homeserver operator can read every
/// field — including the [`action`](Self::action) (an [`TaskAction::Exec`]'s
/// `command`/`cwd`/`env`) and the [`result`](Self::result) payload. The
/// scheduler needs the real action in state to execute it, so these are
/// documented-and-warned, not hidden, until the deferred encrypted-timeline
/// offload redesign lands (issue #308). Do not place secrets in a task action's
/// `env`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskState {
    /// Task identifier.
    pub task_id: String,
    /// Title.
    pub title: String,
    /// Description.
    pub description: String,
    /// Task state, e.g. `executing`.
    pub state: String,
    /// Agent the task is assigned to.
    pub assigned_to: String,
    /// Agent that created the task.
    pub created_by: String,
    /// Upstream dependencies.
    pub depends_on: Vec<String>,
    /// Downstream tasks blocked by this one.
    pub blocks: Vec<String>,
    /// Associated invocation, if any.
    pub invocation_id: Option<String>,
    /// Creation timestamp (RFC 3339).
    pub created_at: String,
    /// Update timestamp (RFC 3339).
    pub updated_at: String,
    /// State revision counter.
    pub state_rev: u64,
    /// Previous state event ID, if updating.
    pub previous_event_id: Option<String>,
    /// Result payload, if completed.
    pub result: Option<Value>,
    /// Optional structured action payload. `None` means this is a manual or
    /// planning task and must not be auto-executed by inferring intent from
    /// human-readable fields.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<TaskAction>,
    /// Forward-compatible unknown fields.
    #[serde(flatten)]
    pub extra: Extra,
}

/// `com.mxagent.invocation.v1` state content (architecture §9, table row).
///
/// # Confidentiality
///
/// This is a Matrix **state** event: the `requester`/`target` identities and
/// lifecycle (`state`, `exit_code`) are plaintext readable by the homeserver
/// operator even in an `--e2ee on` workspace (state events are not
/// Megolm-encrypted) (issue #308).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvocationState {
    /// Invocation identifier.
    pub invocation_id: String,
    /// Owning task, if any.
    pub task_id: Option<String>,
    /// Requesting agent.
    pub requester: String,
    /// Target agent.
    pub target: String,
    /// Invocation state, e.g. `running`/`succeeded`/`failed`.
    pub state: String,
    /// Creation timestamp (RFC 3339).
    pub created_at: String,
    /// Update timestamp (RFC 3339).
    pub updated_at: String,
    /// Exit code if finished.
    pub exit_code: Option<i32>,
    /// State revision counter.
    pub state_rev: u64,
    /// Forward-compatible unknown fields.
    #[serde(flatten)]
    pub extra: Extra,
}

/// `com.mxagent.trust.v1` state content (architecture §13.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustState {
    /// Agent identifier.
    pub agent_id: String,
    /// Trusted key identifier.
    pub key_id: String,
    /// Key fingerprint.
    pub fingerprint: String,
    /// Trust status, e.g. `trusted`/`revoked`.
    pub status: String,
    /// Identity that established trust.
    pub trusted_by: String,
    /// Creation timestamp (RFC 3339).
    pub created_at: String,
    /// Expiry timestamp, if any.
    pub expires_at: Option<String>,
    /// Revocation timestamp, if any.
    pub revoked_at: Option<String>,
    /// Forward-compatible unknown fields.
    #[serde(flatten)]
    pub extra: Extra,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Assert that `json` deserializes into `T` and re-serializes to an
    /// equivalent JSON value (documented example round-trip).
    fn assert_round_trip<T>(value: Value)
    where
        T: Serialize + for<'de> Deserialize<'de>,
    {
        let parsed: T = serde_json::from_value(value.clone())
            .unwrap_or_else(|e| panic!("deserialization failed: {e}"));
        let reserialized = serde_json::to_value(&parsed).expect("serialization failed");
        assert_eq!(reserialized, value, "round-trip mismatch");
    }

    #[test]
    fn exec_request_round_trips() {
        assert_round_trip::<ExecRequest>(json!({
            "invocation_id": "inv_01HZ",
            "request_id": "req_01HZ",
            "target_agent": "developer-pi",
            "requesting_agent": "claude-local",
            "command": ["npm", "test"],
            "cwd": "/home/me/code/project",
            "env": {},
            "stdin": true,
            "stream": true,
            "pty": false,
            "timeout_ms": 600000,
            "task_id": "task-test-api",
            "created_at": "2026-06-02T12:00:00Z",
            "expires_at": "2026-06-02T12:05:00Z",
            "nonce": "base64-random",
            "idempotency_key": "exec:inv_01HZ",
            "signature": {
                "alg": "ed25519",
                "key_id": "mxagent-ed25519:abc123",
                "sig": "base64"
            }
        }));
    }

    #[test]
    fn stream_chunk_round_trips() {
        assert_round_trip::<StreamChunk>(json!({
            "invocation_id": "inv_01HZ",
            "stream": "stdout",
            "seq": 42,
            "encoding": "utf-8",
            "data": "PASS src/foo.test.ts\n",
            "eof": false,
            "compressed": false,
            "sha256": "optional-base64-chunk-digest",
            "timestamp": "2026-06-02T12:00:01.123Z"
        }));
    }

    #[test]
    fn exec_finished_round_trips() {
        assert_round_trip::<ExecFinished>(json!({
            "invocation_id": "inv_01HZ",
            "exit_code": 1,
            "signal": null,
            "duration_ms": 18231,
            "stdout_bytes": 50231,
            "stderr_bytes": 1409,
            "truncated": false,
            "artifact_mxc": null
        }));
    }

    #[test]
    fn pty_resize_round_trips() {
        assert_round_trip::<PtyResize>(json!({
            "invocation_id": "inv_01HZ",
            "rows": 40,
            "cols": 120,
            "pixel_width": 960,
            "pixel_height": 640,
            "created_at": "2026-06-02T12:01:00Z",
            "nonce": "base64-random",
            "signature": { "alg": "ed25519", "key_id": "mxagent-ed25519:abc123", "sig": "base64" }
        }));
    }

    #[test]
    fn pty_resize_defaults_pixels_when_absent() {
        // A minimal producer may omit the advisory pixel dimensions; they
        // default to zero rather than failing to deserialize. The signed
        // control fields remain required.
        let parsed: PtyResize = serde_json::from_value(json!({
            "invocation_id": "inv_01HZ",
            "rows": 24,
            "cols": 80,
            "created_at": "2026-06-02T12:01:00Z",
            "nonce": "base64-random",
            "signature": { "alg": "ed25519", "key_id": "mxagent-ed25519:abc123", "sig": "base64" }
        }))
        .expect("deserialization failed");
        assert_eq!(parsed.rows, 24);
        assert_eq!(parsed.cols, 80);
        assert_eq!(parsed.pixel_width, 0);
        assert_eq!(parsed.pixel_height, 0);
    }

    #[test]
    fn exec_stdin_round_trips() {
        assert_round_trip::<ExecStdin>(json!({
            "invocation_id": "inv_01HZ",
            "data": "aGVsbG8K",
            "eof": true,
            "created_at": "2026-06-02T12:01:00Z",
            "nonce": "base64-random",
            "signature": { "alg": "ed25519", "key_id": "mxagent-ed25519:abc123", "sig": "base64" }
        }));
    }

    #[test]
    fn exec_cancel_round_trips() {
        assert_round_trip::<ExecCancel>(json!({
            "invocation_id": "inv_01HZ",
            "reason": "caller_cancelled",
            "created_at": "2026-06-02T12:01:00Z",
            "nonce": "base64-random",
            "signature": { "alg": "ed25519", "key_id": "mxagent-ed25519:abc123", "sig": "base64" }
        }));
    }

    #[test]
    fn exec_cancelled_round_trips() {
        assert_round_trip::<ExecCancelled>(json!({
            "invocation_id": "inv_01HZ",
            "signal_sent": "SIGTERM",
            "killed_process_group": true,
            "finished_at": "2026-06-02T12:01:01Z"
        }));
    }

    #[test]
    fn stream_artifact_round_trips() {
        assert_round_trip::<StreamArtifact>(json!({
            "invocation_id": "inv_01HZ",
            "stream": "stdout",
            "name": "stdout.log.zst",
            "mime_type": "text/plain+zstd",
            "size_bytes": 10485760u64,
            "sha256": "base64",
            "mxc_uri": "mxc://matrix.org/abcdef",
            "tail_preview": "last 4KB of output..."
        }));
    }

    #[test]
    fn stream_artifact_with_encrypted_file_round_trips() {
        // An artifact uploaded to an encrypted room carries the opaque
        // `EncryptedFile` key material alongside a ciphertext `mxc_uri`.
        assert_round_trip::<StreamArtifact>(json!({
            "invocation_id": "inv_01HZ",
            "stream": "stdout",
            "name": "stdout.log.zst",
            "mime_type": "text/plain+zstd",
            "size_bytes": 10485760u64,
            "sha256": "base64",
            "mxc_uri": "mxc://matrix.org/ciphertext",
            "tail_preview": "last 4KB of output...",
            "encrypted_file": {
                "url": "mxc://matrix.org/ciphertext",
                "key": { "kty": "oct", "alg": "A256CTR", "k": "base64url", "ext": true, "key_ops": ["encrypt", "decrypt"] },
                "iv": "base64",
                "hashes": { "sha256": "base64" },
                "v": "v2"
            }
        }));
    }

    #[test]
    fn stream_artifact_legacy_json_has_no_encrypted_file() {
        // A pre-change (plaintext) artifact has no `encrypted_file`; it must
        // deserialize to `None` and re-serialize without the field.
        let parsed: StreamArtifact = serde_json::from_value(json!({
            "invocation_id": "inv_01HZ",
            "stream": "stdout",
            "name": "stdout.log",
            "mime_type": "text/plain",
            "size_bytes": 1024u64,
            "sha256": "base64",
            "mxc_uri": "mxc://matrix.org/plain",
            "tail_preview": "tail"
        }))
        .expect("legacy artifact without encrypted_file must deserialize");
        assert!(parsed.encrypted_file.is_none());
        let value = serde_json::to_value(&parsed).expect("serialize artifact");
        assert!(
            value.get("encrypted_file").is_none(),
            "a plaintext artifact must not serialize encrypted_file"
        );
    }

    #[test]
    fn context_share_large_object_round_trips() {
        // A large object referenced by Matrix media: no inline payload.
        assert_round_trip::<ContextShare>(json!({
            "context_id": "ctx_01HZ",
            "name": "full-test-log.txt",
            "mime_type": "text/plain",
            "size_bytes": 2500000u64,
            "sha256": "base64",
            "mxc_uri": "mxc://matrix.org/abcdef"
        }));
    }

    #[test]
    fn context_share_encrypted_media_round_trips() {
        // A large share uploaded to an encrypted room carries `encrypted_file`
        // alongside a ciphertext `mxc_uri` and no inline payload.
        assert_round_trip::<ContextShare>(json!({
            "context_id": "ctx_01HZ",
            "name": "full-test-log.txt",
            "mime_type": "text/plain",
            "size_bytes": 2500000u64,
            "sha256": "base64",
            "mxc_uri": "mxc://matrix.org/ciphertext",
            "encrypted_file": {
                "url": "mxc://matrix.org/ciphertext",
                "key": { "kty": "oct", "alg": "A256CTR", "k": "base64url", "ext": true, "key_ops": ["encrypt", "decrypt"] },
                "iv": "base64",
                "hashes": { "sha256": "base64" },
                "v": "v2"
            }
        }));
    }

    #[test]
    fn context_share_legacy_media_has_no_encrypted_file() {
        // A pre-change (plaintext) media share has no `encrypted_file`; it must
        // deserialize to `None` and re-serialize without the field.
        let parsed: ContextShare = serde_json::from_value(json!({
            "context_id": "ctx_01HZ",
            "name": "full-test-log.txt",
            "mime_type": "text/plain",
            "size_bytes": 2500000u64,
            "sha256": "base64",
            "mxc_uri": "mxc://matrix.org/plain"
        }))
        .expect("legacy media share without encrypted_file must deserialize");
        assert!(parsed.encrypted_file.is_none());
        let value = serde_json::to_value(&parsed).expect("serialize share");
        assert!(
            value.get("encrypted_file").is_none(),
            "a plaintext share must not serialize encrypted_file"
        );
    }

    #[test]
    fn context_share_inline_small_payload_round_trips() {
        // A small payload inlined directly in the event: no `mxc_uri`.
        assert_round_trip::<ContextShare>(json!({
            "context_id": "ctx_01HZ",
            "name": "plan.json",
            "mime_type": "application/json",
            "size_bytes": 27u64,
            "sha256": "base64",
            "data": "{\"step\":\"run tests\"}",
            "encoding": "utf-8"
        }));
    }

    #[test]
    fn approval_request_round_trips() {
        assert_round_trip::<ApprovalRequest>(json!({
            "request_id": "req_01HZ",
            "invocation_id": "inv_01HZ",
            "requester": "claude-local",
            "target": "developer-pi",
            "summary": "Run npm test in /home/me/code/project",
            "risk": "medium",
            "expires_at": "2026-06-02T12:05:00Z"
        }));
    }

    #[test]
    fn approval_decision_round_trips() {
        assert_round_trip::<ApprovalDecision>(json!({
            "request_id": "req_01HZ",
            "decision": "approved",
            "approved_by": "local-user",
            "created_at": "2026-06-02T12:00:30Z"
        }));
    }

    #[test]
    fn tool_schema_round_trips() {
        // Matches the documented tool metadata example in architecture.md §5.2.
        assert_round_trip::<ToolSchema>(json!({
            "name": "run_tests",
            "version": "1.0.0",
            "description": "Run project test suites",
            "input_schema": {
                "type": "object",
                "properties": {
                    "package": { "type": "string" },
                    "coverage": { "type": "boolean" }
                },
                "required": ["package"]
            },
            "output_schema": {
                "type": "object",
                "properties": {
                    "exit_code": { "type": "integer" },
                    "summary": { "type": "string" },
                    "log_mxc": { "type": "string" }
                }
            }
        }));
    }

    #[test]
    fn tool_schema_qualified_ref_is_name_at_version() {
        let tool = ToolSchema {
            name: "lint".to_string(),
            version: "1.0.0".to_string(),
            description: "Lint the project".to_string(),
            input_schema: json!({ "type": "object" }),
            output_schema: json!({ "type": "object" }),
            extra: Default::default(),
        };
        assert_eq!(tool.qualified_ref(), "lint@1.0.0");
    }

    #[test]
    fn agent_state_round_trips() {
        assert_round_trip::<AgentState>(json!({
            "agent_id": "developer-pi",
            "kind": "pi",
            "matrix_user_id": "@pi:matrix.org",
            "device_id": "MXAGENTDEVICE01",
            "signing_key_id": "mxagent-ed25519:abc123",
            "status": "active",
            "capabilities": ["shell", "edit", "test", "repo:node", "sandbox:docker"],
            "tools": ["run_tests@1.0.0", "lint@1.0.0"],
            "workspace": {
                "cwd": "/home/me/code/project",
                "project_id": "repo:github.com/org/project",
                "git_commit": "abc123"
            },
            "load": { "running_invocations": 1, "max_invocations": 4 },
            "last_seen_ts": 1780392000000u64,
            "state_rev": 7
        }));
    }

    #[test]
    fn workspace_state_round_trips() {
        // Matches the documented example in architecture.md §9.3.
        assert_round_trip::<WorkspaceState>(json!({
            "project_id": "repo:github.com/org/project",
            "path": "/home/me/code/project",
            "repo": {
                "remote_url": "git@github.com:org/project.git",
                "branch": "main",
                "commit": "abc123"
            },
            "attached_by": "@alice:matrix.org",
            "attached_at": 1780392000000u64,
            "state_rev": 1
        }));
    }

    #[test]
    fn workspace_state_without_repo_round_trips() {
        assert_round_trip::<WorkspaceState>(json!({
            "project_id": "repo:github.com/org/project",
            "path": "/home/me/code/project",
            "repo": null,
            "attached_by": "@alice:matrix.org",
            "attached_at": 1780392000000u64,
            "state_rev": 1
        }));
    }

    #[test]
    fn heartbeat_round_trips() {
        assert_round_trip::<Heartbeat>(json!({
            "agent_id": "developer-pi",
            "status": "active",
            "load": { "running_invocations": 1, "max_invocations": 4 },
            "ts": 1780392000000u64
        }));
    }

    #[test]
    fn task_state_round_trips() {
        assert_round_trip::<TaskState>(json!({
            "task_id": "task-test-api",
            "title": "Run API tests",
            "description": "Run npm test after applying latest diff",
            "state": "executing",
            "assigned_to": "developer-pi",
            "created_by": "claude-local",
            "depends_on": ["task-plan"],
            "blocks": ["task-review"],
            "invocation_id": "inv_01HZ",
            "created_at": "2026-06-02T12:00:00Z",
            "updated_at": "2026-06-02T12:01:12Z",
            "state_rev": 4,
            "previous_event_id": "$eventid",
            "result": null
        }));
    }

    #[test]
    fn task_result_round_trips_success_and_failure_examples() {
        assert_round_trip::<TaskResult>(json!({
            "status": "succeeded",
            "completed_by": "pi-builder",
            "completed_at": "2026-06-04T18:00:00Z",
            "invocation_id": "inv_01HZ",
            "action": "tool",
            "reason": null,
            "exit_code": 0,
            "summary": "tests passed",
            "artifact_mxc": "mxc://matrix.org/log"
        }));
        assert_round_trip::<TaskResult>(json!({
            "status": "failed",
            "completed_by": "pi-builder",
            "completed_at": "2026-06-04T18:00:00Z",
            "invocation_id": "inv_01HZ",
            "action": "exec",
            "reason": "process_exit",
            "exit_code": 1,
            "summary": "tests failed",
            "artifact_mxc": null
        }));
    }

    #[test]
    fn task_state_with_tool_action_round_trips() {
        assert_round_trip::<TaskState>(json!({
            "task_id": "task-test-api",
            "title": "Run API tests",
            "description": "Run npm test after applying latest diff",
            "state": "assigned",
            "assigned_to": "developer-pi",
            "created_by": "claude-local",
            "depends_on": [],
            "blocks": [],
            "invocation_id": null,
            "created_at": "2026-06-02T12:00:00Z",
            "updated_at": "2026-06-02T12:01:12Z",
            "state_rev": 2,
            "previous_event_id": "$eventid",
            "result": null,
            "action": {
                "type": "tool",
                "tool": "run_tests",
                "args": { "package": "api" }
            }
        }));
    }

    #[test]
    fn task_state_with_exec_action_round_trips() {
        assert_round_trip::<TaskState>(json!({
            "task_id": "task-test-api",
            "title": "Run API tests",
            "description": "Run npm test after applying latest diff",
            "state": "assigned",
            "assigned_to": "developer-pi",
            "created_by": "claude-local",
            "depends_on": [],
            "blocks": [],
            "invocation_id": null,
            "created_at": "2026-06-02T12:00:00Z",
            "updated_at": "2026-06-02T12:01:12Z",
            "state_rev": 2,
            "previous_event_id": "$eventid",
            "result": null,
            "action": {
                "type": "exec",
                "command": ["cargo", "test", "--all"],
                "cwd": "/home/me/code/project",
                "env": {},
                "timeout_ms": 600000,
                "stream": true
            }
        }));
    }

    #[test]
    fn task_action_with_authorization_round_trips() {
        assert_round_trip::<TaskState>(json!({
            "task_id": "task-test-api",
            "title": "Run API tests",
            "description": "",
            "state": "assigned",
            "assigned_to": "developer-pi",
            "created_by": "@planner:server",
            "depends_on": [],
            "blocks": [],
            "invocation_id": null,
            "created_at": "2026-06-02T12:00:00Z",
            "updated_at": "2026-06-02T12:00:00Z",
            "state_rev": 2,
            "previous_event_id": null,
            "result": null,
            "action": {
                "type": "tool",
                "tool": "run_tests",
                "args": {},
                "authorization": {
                    "requesting_agent": "@planner:server",
                    "target_agent": "developer-pi",
                    "created_at": "2026-06-02T12:00:00Z",
                    "expires_at": "2026-06-02T12:05:00Z",
                    "nonce": "base64-random",
                    "signature": {
                        "alg": "ed25519",
                        "key_id": "mxagent-ed25519:abc123",
                        "sig": "base64"
                    }
                }
            }
        }));
    }

    #[test]
    fn with_authorization_attaches_and_replaces_signature() {
        let auth = TaskActionAuthorization {
            requesting_agent: "@planner:server".to_string(),
            target_agent: "developer-pi".to_string(),
            created_at: "2026-06-02T12:00:00Z".to_string(),
            expires_at: "2026-06-03T12:00:00Z".to_string(),
            nonce: "req_abc".to_string(),
            signature: Signature {
                alg: "ed25519".to_string(),
                key_id: "mxagent-ed25519:abc123".to_string(),
                sig: "base64".to_string(),
            },
            extra: Default::default(),
        };
        // Attaching to an unsigned action yields the same action carrying `auth`.
        let unsigned = TaskAction::Exec {
            command: vec!["sh".to_string(), "-c".to_string(), "exit 0".to_string()],
            cwd: "/repo".to_string(),
            env: Default::default(),
            timeout_ms: Some(60_000),
            stream: false,
            authorization: None,
        };
        let signed = unsigned.clone().with_authorization(auth.clone());
        assert_eq!(signed.authorization(), Some(&auth));
        // The signature binds only the authorization-stripped action, so
        // `with_authorization` must be the exact inverse of `without_authorization`.
        assert_eq!(signed.without_authorization(), unsigned);

        // Re-attaching replaces any existing authorization rather than nesting.
        let mut replacement = auth.clone();
        replacement.nonce = "req_def".to_string();
        let resigned = signed.with_authorization(replacement.clone());
        assert_eq!(resigned.authorization(), Some(&replacement));
    }

    #[test]
    fn task_state_without_action_deserializes_as_manual_task() {
        let parsed: TaskState = serde_json::from_value(json!({
            "task_id": "task-plan",
            "title": "Plan work",
            "description": "Manual planning task",
            "state": "pending",
            "assigned_to": "",
            "created_by": "claude-local",
            "depends_on": [],
            "blocks": [],
            "invocation_id": null,
            "created_at": "2026-06-02T12:00:00Z",
            "updated_at": "2026-06-02T12:00:00Z",
            "state_rev": 1,
            "previous_event_id": null,
            "result": null
        }))
        .expect("old task without action must deserialize");
        assert!(parsed.action.is_none());
        let value = serde_json::to_value(&parsed).expect("serialize task");
        assert!(value.get("action").is_none(), "absent actions stay omitted");
    }

    #[test]
    fn trust_state_round_trips() {
        assert_round_trip::<TrustState>(json!({
            "agent_id": "developer-pi",
            "key_id": "mxagent-ed25519:abc123",
            "fingerprint": "SHA256:...",
            "status": "trusted",
            "trusted_by": "@owner:matrix.org",
            "created_at": "2026-06-02T12:00:00Z",
            "expires_at": null,
            "revoked_at": null
        }));
    }

    #[test]
    fn invocation_and_call_structs_round_trip() {
        // These event types have no full JSON example in the docs; verify the
        // structs round-trip through serde without loss.
        assert_round_trip::<InvocationState>(json!({
            "invocation_id": "inv_01HZ",
            "task_id": null,
            "requester": "claude-local",
            "target": "developer-pi",
            "state": "running",
            "created_at": "2026-06-02T12:00:00Z",
            "updated_at": "2026-06-02T12:00:05Z",
            "exit_code": null,
            "state_rev": 1
        }));
        // A task-linked invocation that has finished records both its owning
        // task and a terminal exit code.
        assert_round_trip::<InvocationState>(json!({
            "invocation_id": "inv_01HZ",
            "task_id": "task_abc",
            "requester": "claude-local",
            "target": "developer-pi",
            "state": "succeeded",
            "created_at": "2026-06-02T12:00:00Z",
            "updated_at": "2026-06-02T12:01:00Z",
            "exit_code": 0,
            "state_rev": 3
        }));
        assert_round_trip::<CallRequest>(json!({
            "invocation_id": "inv_01HZ",
            "request_id": "req_01HZ",
            "tool": "run_tests",
            "args": { "suite": "api" },
            "created_at": "2026-06-02T12:00:00Z",
            "expires_at": "2026-06-02T12:05:00Z",
            "nonce": "base64-random",
            "signature": { "alg": "ed25519", "key_id": "mxagent-ed25519:abc123", "sig": "base64" }
        }));
        assert_round_trip::<CallResponse>(json!({
            "request_id": "req_01HZ",
            "ok": true,
            "result": { "passed": 12 },
            "error": null
        }));
        assert_round_trip::<ExecAccepted>(json!({ "invocation_id": "inv_01HZ" }));
        assert_round_trip::<ExecRejected>(json!({
            "invocation_id": "inv_01HZ",
            "reason": "policy_denied"
        }));
    }

    #[test]
    fn missing_required_field_fails_deserialization() {
        // `invocation_id` is required; omitting it must fail.
        let err = serde_json::from_value::<ExecFinished>(json!({
            "exit_code": 0,
            "signal": null,
            "duration_ms": 10,
            "stdout_bytes": 0,
            "stderr_bytes": 0,
            "truncated": false,
            "artifact_mxc": null
        }));
        assert!(err.is_err(), "missing invocation_id should fail");
    }

    #[test]
    fn unknown_fields_are_tolerated_and_preserved() {
        // A newer producer adds an unknown field; tolerant readers must not
        // break, and the field is preserved on round-trip via `extra`.
        let value = json!({
            "invocation_id": "inv_01HZ",
            "exit_code": 0,
            "signal": null,
            "duration_ms": 10,
            "stdout_bytes": 0,
            "stderr_bytes": 0,
            "truncated": false,
            "artifact_mxc": null,
            "future_field": { "nested": [1, 2, 3] }
        });
        let parsed: ExecFinished = serde_json::from_value(value.clone()).expect("must deserialize");
        assert_eq!(
            parsed.extra.get("future_field"),
            Some(&json!({ "nested": [1, 2, 3] }))
        );
        let reserialized = serde_json::to_value(&parsed).unwrap();
        assert_eq!(reserialized, value, "unknown field must round-trip");
    }

    // ── Issue #308: E2EE confidentiality schema tests ─────────────────────────

    #[test]
    fn task_action_exec_env_survives_json_round_trip() {
        // `TaskAction::Exec` env is published in `com.mxagent.task.v1` state
        // events, which are plaintext readable by the homeserver operator even
        // under `--e2ee on` (issue #308). The env must survive a JSON
        // round-trip without loss so the scheduler reads the same values the
        // requester published.
        let mut env = BTreeMap::new();
        env.insert("CI".to_string(), "1".to_string());
        env.insert("NODE_ENV".to_string(), "test".to_string());
        let action = TaskAction::Exec {
            command: vec!["cargo".to_string(), "test".to_string()],
            cwd: "/repo".to_string(),
            env: env.clone(),
            timeout_ms: Some(60_000),
            stream: true,
            authorization: None,
        };
        let serialized = serde_json::to_value(&action).expect("serialize TaskAction");
        let restored: TaskAction =
            serde_json::from_value(serialized).expect("deserialize TaskAction");
        if let TaskAction::Exec {
            env: restored_env, ..
        } = restored
        {
            assert_eq!(
                restored_env, env,
                "exec action env must survive the JSON round-trip"
            );
        } else {
            panic!("expected Exec after round-trip");
        }
    }

    #[test]
    fn task_action_kind_returns_correct_strings() {
        // `kind()` drives the `action` field recorded in `TaskResult`, so the
        // wrong string would make task results uninterpretable by automation.
        let tool = TaskAction::Tool {
            tool: "run_tests".to_string(),
            args: Value::Null,
            authorization: None,
        };
        assert_eq!(tool.kind(), "tool");

        let exec = TaskAction::Exec {
            command: vec!["sh".to_string()],
            cwd: "/".to_string(),
            env: Default::default(),
            timeout_ms: None,
            stream: false,
            authorization: None,
        };
        assert_eq!(exec.kind(), "exec");
    }

    #[test]
    fn without_authorization_preserves_exec_env_when_non_empty() {
        // The signing helper calls `without_authorization` to derive the byte
        // string it signs, then re-attaches the signature. The env must be
        // preserved — if it were dropped, the signature would bind a different
        // action than what the scheduler actually executes (issue #308).
        let mut env = BTreeMap::new();
        env.insert("DEPLOY_ENV".to_string(), "staging".to_string());
        env.insert("PORT".to_string(), "8080".to_string());
        let exec = TaskAction::Exec {
            command: vec!["deploy.sh".to_string()],
            cwd: "/opt/app".to_string(),
            env: env.clone(),
            timeout_ms: Some(120_000),
            stream: false,
            authorization: None,
        };
        let stripped = exec.without_authorization();
        if let TaskAction::Exec {
            command,
            cwd,
            env: stripped_env,
            timeout_ms,
            stream,
            authorization,
        } = stripped
        {
            assert_eq!(command, vec!["deploy.sh"]);
            assert_eq!(cwd, "/opt/app");
            assert_eq!(stripped_env, env, "env must survive without_authorization");
            assert_eq!(timeout_ms, Some(120_000));
            assert!(!stream);
            assert!(authorization.is_none(), "authorization must be stripped");
        } else {
            panic!("expected Exec after without_authorization");
        }
    }

    #[test]
    fn task_result_without_artifact_mxc_backward_compat() {
        // A result published before `artifact_mxc` existed must deserialize to
        // `None` — the field has `#[serde(default)]` so an absent field is
        // silently treated as `None` (backward compat, issue #308).
        let parsed: TaskResult = serde_json::from_value(json!({
            "status": "succeeded",
            "completed_by": "developer-pi",
            "completed_at": "2026-06-12T10:00:00Z",
            "invocation_id": "inv_legacy",
            "exit_code": 0
        }))
        .expect("legacy result without artifact_mxc must deserialize");
        assert!(
            parsed.artifact_mxc.is_none(),
            "missing artifact_mxc in legacy JSON must be None"
        );
    }

    #[test]
    fn task_state_exec_action_with_non_empty_env_round_trips() {
        // The full `com.mxagent.task.v1` state event — including an exec
        // action with a non-empty `env` — must round-trip losslessly. An env
        // key dropped during round-trip would cause the scheduler to run with
        // fewer environment variables than the requester intended (issue #308).
        assert_round_trip::<TaskState>(json!({
            "task_id": "task-deploy",
            "title": "Deploy staging",
            "description": "",
            "state": "assigned",
            "assigned_to": "developer-pi",
            "created_by": "@planner:server",
            "depends_on": [],
            "blocks": [],
            "invocation_id": null,
            "created_at": "2026-06-12T10:00:00Z",
            "updated_at": "2026-06-12T10:00:00Z",
            "state_rev": 1,
            "previous_event_id": null,
            "result": null,
            "action": {
                "type": "exec",
                "command": ["./deploy.sh"],
                "cwd": "/opt/app",
                "env": {
                    "DEPLOY_ENV": "staging",
                    "PORT": "8080"
                },
                "timeout_ms": 120000,
                "stream": false
            }
        }));
    }
}
