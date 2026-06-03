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

use matrix_sdk::config::SyncSettings;
use matrix_sdk::ruma::api::client::room::{create_room, Visibility};
use matrix_sdk::ruma::{OwnedRoomId, RoomOrAliasId};
use matrix_sdk::{Client, Room, RoomMemberships};
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
#[derive(Debug, Clone)]
pub struct CreateWorkspaceOptions {
    /// Optional room alias localpart (the `my-project` in `#my-project:server`).
    pub alias: Option<String>,
    /// Optional human-readable room name.
    pub name: Option<String>,
    /// Optional room topic.
    pub topic: Option<String>,
    /// Room visibility (defaults to private for workspaces).
    pub visibility: WorkspaceVisibility,
}

impl Default for CreateWorkspaceOptions {
    fn default() -> Self {
        Self {
            alias: None,
            name: None,
            topic: None,
            visibility: WorkspaceVisibility::Private,
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
    /// Restoring the authenticated Matrix client from the session failed.
    Restore(Box<LoginError>),
    /// An underlying Matrix request failed.
    Matrix(Box<matrix_sdk::Error>),
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
            WorkspaceError::Restore(e) => write!(f, "{e}"),
            WorkspaceError::Matrix(e) => write!(f, "Matrix request failed: {e}"),
        }
    }
}

impl std::error::Error for WorkspaceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            WorkspaceError::Restore(e) => Some(e),
            WorkspaceError::Matrix(e) => Some(e),
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

/// Create a new workspace room with the given options.
///
/// The room's visibility maps to a Matrix preset: a private workspace is
/// invite-only (`private_chat`), and a public workspace is openly joinable
/// (`public_chat`).
pub async fn create_workspace(
    client: &Client,
    options: &CreateWorkspaceOptions,
) -> Result<WorkspaceInfo, WorkspaceError> {
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

    let room = client
        .create_room(request)
        .await
        .map_err(WorkspaceError::from)?;
    Ok(WorkspaceInfo::from_room(&room))
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

    Ok(WorkspaceStatus {
        room_id: room.room_id().to_string(),
        canonical_alias: room.canonical_alias().map(|a| a.to_string()),
        name: room.name(),
        encrypted: room.encryption_state().is_encrypted(),
        joined_members: room.joined_members_count(),
        invited_members: room.invited_members_count(),
        members,
    })
}

/// Parse a user-supplied room ID or alias into an owned identifier.
fn parse_room_or_alias(
    target: &str,
) -> Result<matrix_sdk::ruma::OwnedRoomOrAliasId, WorkspaceError> {
    RoomOrAliasId::parse(target)
        .map(|id| id.to_owned())
        .map_err(|_| WorkspaceError::InvalidTarget(target.to_string()))
}

/// Resolve an alias to a concrete room ID, or pass through an existing ID.
async fn resolve_room_id(
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
        };
        let json = status.to_json();
        assert!(json.contains("@alice:matrix.org"), "{json}");
        assert!(json.contains("\"membership\":\"join\""), "{json}");
        let back: WorkspaceStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(back, status);
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
