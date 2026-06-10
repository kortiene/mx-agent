//! Matrix-backed workspace operations: create, join, and status.
//!
//! A workspace is a Matrix room that agents share to discover peers, exchange
//! context, and coordinate tasks (see `docs/architecture.md`, section 3). This
//! module turns the daemon's authenticated [`Client`] into the small set of
//! room operations the CLI needs:
//!
//! * [`create_workspace`] creates a room with an optional alias/name and a
//!   privacy (visibility) setting.
//! * [`join_workspace`] joins an existing room by alias (`#name:server`) or
//!   room ID (`!id:server`).
//! * [`workspace_status`] summarizes a room's membership.
//!
//! All of these require an authenticated client; build one with
//! [`crate::restore_client`] from a persisted session.

use std::fmt;
use std::path::Path;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use matrix_sdk::config::SyncSettings;
use matrix_sdk::ruma::api::client::room::{create_room, Visibility};
use matrix_sdk::ruma::events::room::encryption::RoomEncryptionEventContent;
use matrix_sdk::ruma::events::{InitialStateEvent, StateEventType};
use matrix_sdk::ruma::{OwnedRoomId, RoomOrAliasId};
use matrix_sdk::{Client, Room, RoomMemberships};
use mx_agent_protocol::events::state::WORKSPACE as WORKSPACE_STATE_TYPE;
use mx_agent_protocol::schema::{RepoInfo, WorkspaceState};
use serde::{Deserialize, Serialize};

use crate::matrix::{restore_client, LoginError};
use crate::session::StoredSession;

/// Visibility (privacy) of a workspace room.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WorkspaceVisibility {
    /// Invite-only; hidden from the public room directory.
    Private,
    /// Publicly joinable and listed in the room directory.
    Public,
}

impl WorkspaceVisibility {
    /// The lowercase label used in human and JSON output.
    pub fn as_str(self) -> &'static str {
        match self {
            WorkspaceVisibility::Private => "private",
            WorkspaceVisibility::Public => "public",
        }
    }
}

impl fmt::Display for WorkspaceVisibility {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Options for [`create_workspace`].
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CreateWorkspaceOptions {
    /// Optional room alias localpart (the `my-project` in `#my-project:server`).
    pub alias: Option<String>,
    /// Optional human-readable room name.
    pub name: Option<String>,
    /// Optional room topic.
    pub topic: Option<String>,
    /// Room visibility (defaults to private for workspaces).
    pub visibility: WorkspaceVisibility,
    /// Enable end-to-end encryption on the created room (default: `false`).
    ///
    /// When `true`, the room is born encrypted: an `m.room.encryption` (Megolm
    /// v1) state event is included in the room's `initial_state` so the room is
    /// encrypted from its first event, with no unencrypted window.
    ///
    /// Marked `#[serde(default)]` so an older CLI that omits the field over IPC
    /// still deserializes (defaulting to off, preserving prior behavior).
    ///
    /// Encryption is a transport/confidentiality property only: it changes who
    /// the homeserver operator can read, never who may cause execution. Room
    /// membership, device presence, and room encryption never substitute for the
    /// Ed25519 signature + local trust + deny-by-default policy + optional
    /// approval that gate privileged requests (architecture §1.2).
    #[serde(default)]
    pub e2ee: bool,
}

impl Default for CreateWorkspaceOptions {
    fn default() -> Self {
        Self {
            alias: None,
            name: None,
            topic: None,
            visibility: WorkspaceVisibility::Private,
            e2ee: false,
        }
    }
}

/// A non-sensitive summary of a workspace room.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceInfo {
    /// Canonical room ID, e.g. `!abc123:matrix.org`.
    pub room_id: String,
    /// Canonical alias, if the room has one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub canonical_alias: Option<String>,
    /// Human-readable room name, if set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Room topic, if set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub topic: Option<String>,
    /// Whether the room has end-to-end encryption enabled.
    pub encrypted: bool,
    /// Number of joined members known to the client.
    pub joined_members: u64,
}

impl WorkspaceInfo {
    /// Build a summary from a [`Room`] handle.
    pub fn from_room(room: &Room) -> Self {
        Self {
            room_id: room.room_id().to_string(),
            canonical_alias: room.canonical_alias().map(|a| a.to_string()),
            name: room.name(),
            topic: room.topic(),
            encrypted: room.encryption_state().is_encrypted(),
            joined_members: room.joined_members_count(),
        }
    }

    /// Build a summary from a freshly-created [`Room`], OR-ing in the encryption
    /// state that was *requested* at creation time.
    ///
    /// Immediately after `create_room` returns, the local store may not yet
    /// reflect an `m.room.encryption` event supplied via `initial_state` (it can
    /// lag the create response / first sync), so
    /// [`from_room`](Self::from_room) could under-report `encrypted: false` for a
    /// room that was in fact born encrypted. OR-ing `requested_e2ee` with the
    /// live room state keeps the invariant that a `create --e2ee on` always
    /// reports `encrypted: true`, while a default create still reports the room's
    /// true state (`false`).
    pub fn from_room_with_e2ee(room: &Room, requested_e2ee: bool) -> Self {
        let mut info = Self::from_room(room);
        info.encrypted = requested_e2ee || info.encrypted;
        info
    }

    /// Render as a single-line JSON object.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{}".to_string())
    }
}

/// A single member entry in a [`WorkspaceStatus`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberSummary {
    /// Full Matrix user ID.
    pub user_id: String,
    /// Display name, if the member set one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// Membership state (`join`, `invite`, ...).
    pub membership: String,
}

/// Membership summary for a workspace room.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceStatus {
    /// Canonical room ID.
    pub room_id: String,
    /// Canonical alias, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub canonical_alias: Option<String>,
    /// Human-readable room name, if set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Whether the room is end-to-end encrypted.
    pub encrypted: bool,
    /// Number of joined members.
    pub joined_members: u64,
    /// Number of invited (not-yet-joined) members.
    pub invited_members: u64,
    /// Active (joined + invited) members, sorted by user ID.
    pub members: Vec<MemberSummary>,
    /// Attached workspace metadata, if a `com.mxagent.workspace.v1` state event
    /// is present in the room.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspace: Option<WorkspaceState>,
}

/// Options for [`attach_workspace`].
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AttachWorkspaceOptions {
    /// Room ID or alias to attach to.
    pub room: String,
    /// Local filesystem path to attach.
    pub path: String,
    /// Project identifier, e.g. `repo:github.com/org/project`.
    pub project_id: String,
}

impl WorkspaceStatus {
    /// Render as a single-line JSON object.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{}".to_string())
    }
}

/// Errors produced by workspace operations.
#[derive(Debug)]
pub enum WorkspaceError {
    /// The provided room alias/ID could not be parsed.
    InvalidTarget(String),
    /// The room was not found in the client's state after syncing.
    RoomNotFound(String),
    /// The attach path does not exist or is not a directory.
    InvalidPath(String),
    /// A task with the requested ID already exists (refusing to clobber on
    /// create; use update instead).
    TaskExists(String),
    /// No task with the requested ID exists in the room.
    TaskNotFound(String),
    /// A task lifecycle state is not one of the states mx-agent understands.
    InvalidTaskState(String),
    /// A task update attempted a lifecycle transition that is not permitted.
    InvalidTaskTransition {
        /// Task ID (state key) the update targeted.
        task_id: String,
        /// Current lifecycle state.
        from: String,
        /// Requested lifecycle state.
        to: String,
    },
    /// The update was rejected because the task has already advanced past the
    /// revision the caller last observed; applying it would silently overwrite
    /// newer state (architecture §9.4).
    StaleTaskUpdate {
        /// Task ID (state key) the update targeted.
        task_id: String,
        /// Revision the caller expected the task to still be at.
        expected: u64,
        /// Revision the task is actually at in the room right now.
        current: u64,
    },
    /// No invocation with the requested ID exists in the room.
    InvocationNotFound(String),
    /// No approval request with the requested ID exists in the local queue.
    ApprovalNotFound(String),
    /// No context share with the requested ID exists in the room.
    ContextNotFound(String),
    /// A retrieved context artifact did not match the digest recorded on its
    /// share, so the bytes are corrupt or tampered with (architecture §6).
    ContextIntegrity {
        /// Context ID of the artifact that failed verification.
        context_id: String,
        /// Base64 SHA-256 digest the share claimed.
        expected: String,
        /// Base64 SHA-256 digest actually computed over the retrieved bytes.
        actual: String,
    },
    /// A context share could not be decoded back into its raw bytes (malformed
    /// inline payload, unknown encoding, or invalid `mxc://` URI).
    ContextRetrievalFailed(String),
    /// Capturing local context (a git diff or environment metadata) failed.
    ContextCaptureFailed(String),
    /// No stream artifact for the requested invocation (and stream) was found in
    /// the room timeline.
    ArtifactNotFound(String),
    /// A retrieved stream artifact did not match the digest recorded on its
    /// timeline event, so the bytes are corrupt or tampered with (architecture
    /// §8.4).
    ArtifactIntegrity {
        /// Invocation the artifact belongs to.
        invocation_id: String,
        /// Stream the artifact captured (e.g. `stdout`).
        stream: String,
        /// Base64 SHA-256 digest the artifact event claimed.
        expected: String,
        /// Base64 SHA-256 digest actually computed over the retrieved bytes.
        actual: String,
    },
    /// A stream artifact could not be retrieved or decompressed (invalid
    /// `mxc://` URI, or zstd decompression failed/unavailable).
    ArtifactRetrievalFailed(String),
    /// Restoring the authenticated Matrix client from the session failed.
    Restore(Box<LoginError>),
    /// An underlying Matrix request failed.
    Matrix(Box<matrix_sdk::Error>),
    /// A local file operation (e.g. reading or writing the approval queue)
    /// failed.
    Io(std::io::Error),
}

impl fmt::Display for WorkspaceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WorkspaceError::InvalidTarget(value) => write!(
                f,
                "{value:?} is not a valid room ID or alias; \
                 use a room ID like \"!abc:server\" or an alias like \"#name:server\""
            ),
            WorkspaceError::RoomNotFound(value) => {
                write!(f, "room {value:?} was not found; are you a member of it?")
            }
            WorkspaceError::InvalidPath(value) => {
                write!(f, "path {value:?} does not exist or is not a directory")
            }
            WorkspaceError::TaskExists(value) => {
                write!(
                    f,
                    "task {value:?} already exists; use `task update` to change it"
                )
            }
            WorkspaceError::TaskNotFound(value) => {
                write!(f, "task {value:?} was not found in the room")
            }
            WorkspaceError::InvalidTaskState(value) => {
                write!(
                    f,
                    "task state {value:?} is not a recognized lifecycle state"
                )
            }
            WorkspaceError::InvalidTaskTransition { task_id, from, to } => write!(
                f,
                "task {task_id:?} cannot transition from {from:?} to {to:?}"
            ),
            WorkspaceError::StaleTaskUpdate {
                task_id,
                expected,
                current,
            } => write!(
                f,
                "task {task_id:?} update is stale: expected state_rev {expected} \
                 but the task is now at {current}; re-read the task and retry"
            ),
            WorkspaceError::InvocationNotFound(value) => {
                write!(f, "invocation {value:?} was not found in the room")
            }
            WorkspaceError::ApprovalNotFound(value) => {
                write!(
                    f,
                    "approval request {value:?} was not found in the local queue"
                )
            }
            WorkspaceError::ContextNotFound(value) => {
                write!(f, "context share {value:?} was not found in the room")
            }
            WorkspaceError::ContextIntegrity {
                context_id,
                expected,
                actual,
            } => write!(
                f,
                "context {context_id:?} failed integrity check: expected sha256 \
                 {expected} but retrieved bytes hash to {actual}"
            ),
            WorkspaceError::ContextRetrievalFailed(value) => {
                write!(f, "could not retrieve context: {value}")
            }
            WorkspaceError::ContextCaptureFailed(value) => {
                write!(f, "could not capture context: {value}")
            }
            WorkspaceError::ArtifactNotFound(value) => {
                write!(f, "no stream artifact for {value:?} was found in the room")
            }
            WorkspaceError::ArtifactIntegrity {
                invocation_id,
                stream,
                expected,
                actual,
            } => write!(
                f,
                "artifact for invocation {invocation_id:?} ({stream}) failed integrity check: \
                 expected sha256 {expected} but retrieved bytes hash to {actual}"
            ),
            WorkspaceError::ArtifactRetrievalFailed(value) => {
                write!(f, "could not retrieve artifact: {value}")
            }
            WorkspaceError::Restore(e) => write!(f, "{e}"),
            WorkspaceError::Matrix(e) => write!(f, "Matrix request failed: {e}"),
            WorkspaceError::Io(e) => write!(f, "local file operation failed: {e}"),
        }
    }
}

impl std::error::Error for WorkspaceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            WorkspaceError::Restore(e) => Some(e),
            WorkspaceError::Matrix(e) => Some(e),
            WorkspaceError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<LoginError> for WorkspaceError {
    fn from(e: LoginError) -> Self {
        WorkspaceError::Restore(Box::new(e))
    }
}

impl From<matrix_sdk::Error> for WorkspaceError {
    fn from(e: matrix_sdk::Error) -> Self {
        WorkspaceError::Matrix(Box::new(e))
    }
}

impl From<std::io::Error> for WorkspaceError {
    fn from(e: std::io::Error) -> Self {
        WorkspaceError::Io(e)
    }
}

/// Build the `create_room` request for the given workspace options.
///
/// Extracted as a pure helper (no homeserver round-trip) so the room-request
/// construction — in particular the `m.room.encryption` `initial_state` for an
/// encrypted-on-create workspace — is unit-testable without a live Matrix
/// server.
///
/// When `options.e2ee` is set, a single `m.room.encryption` (Megolm v1,
/// recommended defaults) event is pushed into `initial_state` so the room is
/// encrypted from event zero, with no unencrypted window — preferred over a
/// post-create `room.enable_encryption()` (one round-trip, no unencrypted gap).
pub(crate) fn build_create_room_request(
    options: &CreateWorkspaceOptions,
) -> create_room::v3::Request {
    let mut request = create_room::v3::Request::new();
    request.name = options.name.clone();
    request.topic = options.topic.clone();
    request.room_alias_name = options.alias.clone();
    match options.visibility {
        WorkspaceVisibility::Private => {
            request.visibility = Visibility::Private;
            request.preset = Some(create_room::v3::RoomPreset::PrivateChat);
        }
        WorkspaceVisibility::Public => {
            request.visibility = Visibility::Public;
            request.preset = Some(create_room::v3::RoomPreset::PublicChat);
        }
    }

    if options.e2ee {
        let content = RoomEncryptionEventContent::with_recommended_defaults();
        request.initial_state = vec![InitialStateEvent::with_empty_state_key(content).to_raw_any()];
    }

    request
}

/// Create a new workspace room with the given options.
///
/// The room's visibility maps to a Matrix preset: a private workspace is
/// invite-only (`private_chat`), and a public workspace is openly joinable
/// (`public_chat`). With `options.e2ee` set, the room is created born encrypted
/// (see [`build_create_room_request`]).
pub async fn create_workspace(
    client: &Client,
    options: &CreateWorkspaceOptions,
) -> Result<WorkspaceInfo, WorkspaceError> {
    let request = build_create_room_request(options);

    let room = client
        .create_room(request)
        .await
        .map_err(WorkspaceError::from)?;
    Ok(WorkspaceInfo::from_room_with_e2ee(&room, options.e2ee))
}

/// Create a workspace, restoring the authenticated client from `session`.
///
/// Convenience wrapper around [`restore_client`] + [`create_workspace`] so the
/// CLI does not need to depend on `matrix-sdk` directly.
pub async fn create_workspace_for_session(
    session: &StoredSession,
    options: &CreateWorkspaceOptions,
) -> Result<WorkspaceInfo, WorkspaceError> {
    let client = restore_client(session).await?;
    create_workspace(&client, options).await
}

/// Join a workspace, restoring the authenticated client from `session`.
pub async fn join_workspace_for_session(
    session: &StoredSession,
    target: &str,
) -> Result<WorkspaceInfo, WorkspaceError> {
    let client = restore_client(session).await?;
    join_workspace(&client, target).await
}

/// Summarize workspace status, restoring the client from `session`.
pub async fn workspace_status_for_session(
    session: &StoredSession,
    target: &str,
) -> Result<WorkspaceStatus, WorkspaceError> {
    let client = restore_client(session).await?;
    workspace_status(&client, target).await
}

/// Join an existing workspace room by alias (`#name:server`) or room ID
/// (`!id:server`).
pub async fn join_workspace(
    client: &Client,
    target: &str,
) -> Result<WorkspaceInfo, WorkspaceError> {
    let id = parse_room_or_alias(target)?;
    let room = client
        .join_room_by_id_or_alias(&id, &[])
        .await
        .map_err(WorkspaceError::from)?;
    Ok(WorkspaceInfo::from_room(&room))
}

/// Summarize the membership of a workspace room.
///
/// `target` may be a room ID or an alias. The client performs a single sync to
/// populate room state before the lookup, so this works without a running
/// daemon.
pub async fn workspace_status(
    client: &Client,
    target: &str,
) -> Result<WorkspaceStatus, WorkspaceError> {
    let id = parse_room_or_alias(target)?;

    // Populate room state with a one-shot sync; a freshly restored client has
    // no local state until it has talked to the homeserver once.
    client
        .sync_once(SyncSettings::default())
        .await
        .map_err(WorkspaceError::from)?;

    let room_id = resolve_room_id(client, &id).await?;
    let room = client
        .get_room(&room_id)
        .ok_or_else(|| WorkspaceError::RoomNotFound(target.to_string()))?;

    build_workspace_status(&room).await
}

/// Summarize an already-synced `room` into a [`WorkspaceStatus`].
///
/// Unlike [`workspace_status`] this performs no `/sync`; it reads from the room
/// state already in the client's store. The watch loop ([`crate::watch`]) calls
/// it once per sync to take a fresh snapshot without re-establishing the room.
pub(crate) async fn build_workspace_status(room: &Room) -> Result<WorkspaceStatus, WorkspaceError> {
    let mut members = Vec::new();
    for member in room
        .members(RoomMemberships::ACTIVE)
        .await
        .map_err(WorkspaceError::from)?
    {
        members.push(MemberSummary {
            user_id: member.user_id().to_string(),
            display_name: member.display_name().map(str::to_string),
            membership: membership_label(member.membership()),
        });
    }
    members.sort_by(|a, b| a.user_id.cmp(&b.user_id));

    let workspace = read_workspace_state(room).await?;

    Ok(WorkspaceStatus {
        room_id: room.room_id().to_string(),
        canonical_alias: room.canonical_alias().map(|a| a.to_string()),
        name: room.name(),
        encrypted: room.encryption_state().is_encrypted(),
        joined_members: room.joined_members_count(),
        invited_members: room.invited_members_count(),
        members,
        workspace,
    })
}

/// Read the `com.mxagent.workspace.v1` state event (empty state key) from a
/// room, returning `None` when no workspace metadata has been attached.
async fn read_workspace_state(room: &Room) -> Result<Option<WorkspaceState>, WorkspaceError> {
    use matrix_sdk::deserialized_responses::RawAnySyncOrStrippedState as RawState;

    let raw = room
        .get_state_event(StateEventType::from(WORKSPACE_STATE_TYPE), "")
        .await
        .map_err(WorkspaceError::from)?;

    let content = match raw {
        Some(RawState::Sync(raw)) => raw.get_field::<WorkspaceState>("content"),
        Some(RawState::Stripped(raw)) => raw.get_field::<WorkspaceState>("content"),
        None => return Ok(None),
    }
    .map_err(|e| WorkspaceError::from(matrix_sdk::Error::SerdeJson(e)))?;

    Ok(content)
}

/// Attach a local path/project to a workspace room.
///
/// Publishes a `com.mxagent.workspace.v1` state event (empty state key) holding
/// the project ID, attached path, and detected git repository metadata. The
/// state event overwrites any previously attached metadata for the room
/// (last-write-wins per `(type, state_key)`).
pub async fn attach_workspace(
    client: &Client,
    options: &AttachWorkspaceOptions,
) -> Result<WorkspaceState, WorkspaceError> {
    let path = Path::new(&options.path);
    if !path.is_dir() {
        return Err(WorkspaceError::InvalidPath(options.path.clone()));
    }

    let id = parse_room_or_alias(&options.room)?;

    client
        .sync_once(SyncSettings::default())
        .await
        .map_err(WorkspaceError::from)?;

    let room_id = resolve_room_id(client, &id).await?;
    let room = client
        .get_room(&room_id)
        .ok_or_else(|| WorkspaceError::RoomNotFound(options.room.clone()))?;

    let attached_by = client.user_id().map(|u| u.to_string()).unwrap_or_default();
    let attached_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or_default();

    // Read the prior revision (if any) so we can advance `state_rev`.
    let previous = read_workspace_state(&room).await?;
    let state_rev = previous.map(|w| w.state_rev + 1).unwrap_or(1);

    let state = WorkspaceState {
        project_id: options.project_id.clone(),
        path: options.path.clone(),
        repo: detect_repo_info(path),
        attached_by,
        attached_at,
        state_rev,
        extra: Default::default(),
    };

    let content = serde_json::to_value(&state)
        .map_err(|e| WorkspaceError::from(matrix_sdk::Error::SerdeJson(e)))?;
    room.send_state_event_raw(WORKSPACE_STATE_TYPE, "", content)
        .await
        .map_err(WorkspaceError::from)?;

    Ok(state)
}

/// Attach a workspace, restoring the authenticated client from `session`.
pub async fn attach_workspace_for_session(
    session: &StoredSession,
    options: &AttachWorkspaceOptions,
) -> Result<WorkspaceState, WorkspaceError> {
    let client = restore_client(session).await?;
    attach_workspace(&client, options).await
}

/// Detect git repository metadata for `path`, returning `None` when `path` is
/// not inside a git work tree.
pub(crate) fn detect_repo_info(path: &Path) -> Option<RepoInfo> {
    // A non-zero exit (or missing git) means this is not a git repository.
    let inside = git_output(path, &["rev-parse", "--is-inside-work-tree"]);
    if inside.as_deref() != Some("true") {
        return None;
    }
    Some(RepoInfo {
        remote_url: git_output(path, &["remote", "get-url", "origin"]),
        branch: git_output(path, &["rev-parse", "--abbrev-ref", "HEAD"]),
        commit: git_output(path, &["rev-parse", "HEAD"]),
    })
}

/// Run `git -C <path> <args...>`, returning trimmed stdout on success.
///
/// Returns `None` when git is unavailable, exits non-zero, or produces empty
/// output, so callers can treat missing metadata uniformly.
pub(crate) fn git_output(path: &Path, args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(path)
        .args(args)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8(output.stdout).ok()?.trim().to_string();
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

/// Parse a user-supplied room ID or alias into an owned identifier.
pub(crate) fn parse_room_or_alias(
    target: &str,
) -> Result<matrix_sdk::ruma::OwnedRoomOrAliasId, WorkspaceError> {
    RoomOrAliasId::parse(target)
        .map(|id| id.to_owned())
        .map_err(|_| WorkspaceError::InvalidTarget(target.to_string()))
}

/// Resolve an alias to a concrete room ID, or pass through an existing ID.
pub(crate) async fn resolve_room_id(
    client: &Client,
    id: &RoomOrAliasId,
) -> Result<OwnedRoomId, WorkspaceError> {
    match <&matrix_sdk::ruma::RoomId>::try_from(id) {
        Ok(room_id) => Ok(room_id.to_owned()),
        Err(_) => {
            let alias = <&matrix_sdk::ruma::RoomAliasId>::try_from(id)
                .map_err(|_| WorkspaceError::InvalidTarget(id.to_string()))?;
            let response = client
                .resolve_room_alias(alias)
                .await
                .map_err(|e| WorkspaceError::from(matrix_sdk::Error::from(e)))?;
            Ok(response.room_id)
        }
    }
}

/// Render a [`MembershipState`](matrix_sdk::ruma::events::room::member::MembershipState)
/// as a stable lowercase label for output.
fn membership_label(state: &matrix_sdk::ruma::events::room::member::MembershipState) -> String {
    use matrix_sdk::ruma::events::room::member::MembershipState;
    match state {
        MembershipState::Ban => "ban",
        MembershipState::Invite => "invite",
        MembershipState::Join => "join",
        MembershipState::Knock => "knock",
        MembershipState::Leave => "leave",
        other => return other.as_str().to_string(),
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn visibility_labels_are_lowercase() {
        assert_eq!(WorkspaceVisibility::Private.as_str(), "private");
        assert_eq!(WorkspaceVisibility::Public.as_str(), "public");
        assert_eq!(WorkspaceVisibility::Private.to_string(), "private");
    }

    #[test]
    fn default_options_are_private_and_empty() {
        let opts = CreateWorkspaceOptions::default();
        assert_eq!(opts.visibility, WorkspaceVisibility::Private);
        assert!(opts.alias.is_none());
        assert!(opts.name.is_none());
        assert!(opts.topic.is_none());
    }

    #[test]
    fn default_options_e2ee_is_false() {
        // Regression for issue #249: workspace create must default to
        // unencrypted and never silently enable E2EE without --e2ee on.
        let opts = CreateWorkspaceOptions::default();
        assert!(!opts.e2ee, "e2ee must default to false");
    }

    #[test]
    fn create_workspace_options_ipc_compat_missing_e2ee_field() {
        // An older CLI that doesn't send the `e2ee` field must not cause an
        // IPC deserialization error, and the field must default to false.
        let json = r#"{"alias":null,"name":null,"topic":null,"visibility":"private"}"#;
        let opts: CreateWorkspaceOptions =
            serde_json::from_str(json).expect("older IPC payload without e2ee must deserialize");
        assert!(!opts.e2ee, "missing e2ee field must default to false");
    }

    // --- build_create_room_request unit tests --------------------------------

    #[test]
    fn build_create_room_request_no_e2ee_has_empty_initial_state() {
        let opts = CreateWorkspaceOptions {
            e2ee: false,
            ..Default::default()
        };
        let req = build_create_room_request(&opts);
        assert!(
            req.initial_state.is_empty(),
            "default (no e2ee) must not inject any initial_state events"
        );
    }

    #[test]
    fn build_create_room_request_e2ee_on_has_encryption_event() {
        let opts = CreateWorkspaceOptions {
            e2ee: true,
            ..Default::default()
        };
        let req = build_create_room_request(&opts);
        assert_eq!(
            req.initial_state.len(),
            1,
            "e2ee=true must inject exactly one initial_state event"
        );
        let event_type = req.initial_state[0]
            .get_field::<String>("type")
            .expect("get_field must not err")
            .expect("type field must be present");
        assert_eq!(
            event_type, "m.room.encryption",
            "initial_state event must be m.room.encryption"
        );
    }

    #[test]
    fn build_create_room_request_private_sets_private_preset() {
        let opts = CreateWorkspaceOptions {
            visibility: WorkspaceVisibility::Private,
            ..Default::default()
        };
        let req = build_create_room_request(&opts);
        assert_eq!(req.visibility, Visibility::Private);
        assert_eq!(req.preset, Some(create_room::v3::RoomPreset::PrivateChat));
    }

    #[test]
    fn build_create_room_request_public_sets_public_preset() {
        let opts = CreateWorkspaceOptions {
            visibility: WorkspaceVisibility::Public,
            ..Default::default()
        };
        let req = build_create_room_request(&opts);
        assert_eq!(req.visibility, Visibility::Public);
        assert_eq!(req.preset, Some(create_room::v3::RoomPreset::PublicChat));
    }

    #[test]
    fn build_create_room_request_metadata_passthrough() {
        let opts = CreateWorkspaceOptions {
            alias: Some("my-project".to_string()),
            name: Some("My Project".to_string()),
            topic: Some("Build stuff".to_string()),
            visibility: WorkspaceVisibility::Private,
            e2ee: false,
        };
        let req = build_create_room_request(&opts);
        assert_eq!(req.room_alias_name.as_deref(), Some("my-project"));
        assert_eq!(req.name.as_deref(), Some("My Project"));
        assert_eq!(req.topic.as_deref(), Some("Build stuff"));
    }

    #[test]
    fn build_create_room_request_e2ee_and_public_combined() {
        // Combining e2ee + public visibility must produce both a PublicChat
        // preset and the encryption initial_state event.
        let opts = CreateWorkspaceOptions {
            visibility: WorkspaceVisibility::Public,
            e2ee: true,
            ..Default::default()
        };
        let req = build_create_room_request(&opts);
        assert_eq!(req.preset, Some(create_room::v3::RoomPreset::PublicChat));
        assert_eq!(req.initial_state.len(), 1);
        let event_type = req.initial_state[0]
            .get_field::<String>("type")
            .unwrap()
            .unwrap();
        assert_eq!(event_type, "m.room.encryption");
    }

    #[test]
    fn workspace_info_encrypted_false_serializes() {
        // Regression for issue #249: a default (unencrypted) workspace create
        // must report `encrypted: false` in both human and JSON output, not true.
        let info = WorkspaceInfo {
            room_id: "!abc:matrix.org".to_string(),
            canonical_alias: None,
            name: None,
            topic: None,
            encrypted: false,
            joined_members: 1,
        };
        let json = info.to_json();
        assert!(json.contains("\"encrypted\":false"), "{json}");
        let back: WorkspaceInfo = serde_json::from_str(&json).unwrap();
        assert!(!back.encrypted);
    }

    #[test]
    fn workspace_info_json_round_trips_and_omits_empty() {
        let info = WorkspaceInfo {
            room_id: "!abc:matrix.org".to_string(),
            canonical_alias: None,
            name: Some("demo".to_string()),
            topic: None,
            encrypted: true,
            joined_members: 2,
        };
        let json = info.to_json();
        assert!(json.contains("\"room_id\":\"!abc:matrix.org\""), "{json}");
        assert!(json.contains("\"encrypted\":true"), "{json}");
        assert!(
            !json.contains("canonical_alias"),
            "empty field leaked: {json}"
        );
        let back: WorkspaceInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(back, info);
    }

    #[test]
    fn status_json_includes_members() {
        let status = WorkspaceStatus {
            room_id: "!abc:matrix.org".to_string(),
            canonical_alias: Some("#demo:matrix.org".to_string()),
            name: Some("demo".to_string()),
            encrypted: false,
            joined_members: 1,
            invited_members: 0,
            members: vec![MemberSummary {
                user_id: "@alice:matrix.org".to_string(),
                display_name: Some("Alice".to_string()),
                membership: "join".to_string(),
            }],
            workspace: None,
        };
        let json = status.to_json();
        assert!(json.contains("@alice:matrix.org"), "{json}");
        assert!(json.contains("\"membership\":\"join\""), "{json}");
        assert!(
            !json.contains("workspace"),
            "empty workspace leaked: {json}"
        );
        let back: WorkspaceStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(back, status);
    }

    #[test]
    fn status_json_includes_attached_workspace() {
        let status = WorkspaceStatus {
            room_id: "!abc:matrix.org".to_string(),
            canonical_alias: None,
            name: None,
            encrypted: false,
            joined_members: 1,
            invited_members: 0,
            members: vec![],
            workspace: Some(WorkspaceState {
                project_id: "repo:github.com/org/project".to_string(),
                path: "/home/me/code/project".to_string(),
                repo: Some(RepoInfo {
                    remote_url: Some("git@github.com:org/project.git".to_string()),
                    branch: Some("main".to_string()),
                    commit: Some("abc123".to_string()),
                }),
                attached_by: "@alice:matrix.org".to_string(),
                attached_at: 1_780_392_000_000,
                state_rev: 1,
                extra: Default::default(),
            }),
        };
        let json = status.to_json();
        assert!(json.contains("repo:github.com/org/project"), "{json}");
        assert!(json.contains("/home/me/code/project"), "{json}");
        let back: WorkspaceStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(back, status);
    }

    #[test]
    fn git_output_returns_none_outside_repo() {
        let tmp = std::env::temp_dir();
        // A `git rev-parse --is-inside-work-tree` in a non-repo (or with a
        // bogus subcommand) must not panic and should yield no metadata.
        let info = detect_repo_info(&tmp);
        // Either None (not a repo) or Some when temp dir happens to be tracked;
        // both are valid, but the call must not panic.
        let _ = info;
    }

    #[test]
    fn parse_room_or_alias_accepts_id_and_alias() {
        assert!(parse_room_or_alias("!abc:matrix.org").is_ok());
        assert!(parse_room_or_alias("#demo:matrix.org").is_ok());
    }

    #[test]
    fn parse_room_or_alias_rejects_garbage() {
        let err = parse_room_or_alias("not-a-room").unwrap_err();
        assert!(matches!(err, WorkspaceError::InvalidTarget(_)));
        assert!(err.to_string().contains("valid room ID or alias"));
    }

    #[test]
    fn membership_labels_are_stable() {
        use matrix_sdk::ruma::events::room::member::MembershipState;
        assert_eq!(membership_label(&MembershipState::Join), "join");
        assert_eq!(membership_label(&MembershipState::Invite), "invite");
        assert_eq!(membership_label(&MembershipState::Leave), "leave");
    }
}
