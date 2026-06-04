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
    /// MXC URI of the uploaded artifact.
    pub mxc_uri: String,
    /// Tail preview of the output.
    pub tail_preview: String,
    /// Forward-compatible unknown fields.
    #[serde(flatten)]
    pub extra: Extra,
}

/// `com.mxagent.pty.resize.v1` content (architecture §7.1, §8.3).
///
/// Sent from the requesting side to the executing agent whenever the local
/// terminal's window size changes, so the remote PTY is resized to match and
/// full-screen programs (editors, pagers) re-render at the new dimensions. The
/// pixel dimensions are advisory: they are `0` when the local terminal does not
/// report them, and most consumers only need `rows`/`cols`.
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
    /// (small-payload) share.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mxc_uri: Option<String>,
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
    /// Detached signature.
    pub signature: Signature,
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

/// `com.mxagent.approval.decision.v1` content (architecture §11).
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

/// `com.mxagent.task.v1` state content (architecture §9.2).
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
    /// Forward-compatible unknown fields.
    #[serde(flatten)]
    pub extra: Extra,
}

/// `com.mxagent.invocation.v1` state content (architecture §9, table row).
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
            "pixel_height": 640
        }));
    }

    #[test]
    fn pty_resize_defaults_pixels_when_absent() {
        // A minimal producer may omit the advisory pixel dimensions; they
        // default to zero rather than failing to deserialize.
        let parsed: PtyResize = serde_json::from_value(json!({
            "invocation_id": "inv_01HZ",
            "rows": 24,
            "cols": 80
        }))
        .expect("deserialization failed");
        assert_eq!(parsed.rows, 24);
        assert_eq!(parsed.cols, 80);
        assert_eq!(parsed.pixel_width, 0);
        assert_eq!(parsed.pixel_height, 0);
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
}
