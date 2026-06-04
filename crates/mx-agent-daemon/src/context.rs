//! Context sharing for small payloads: `com.mxagent.context.share.v1`.
//!
//! Agents broadcast working context — a git diff, environment metadata, or an
//! arbitrary typed blob piped on stdin — into a workspace room so peers can pick
//! it up (see `docs/architecture.md`, section 6). This module implements the
//! **small-payload** path: the bytes are inlined directly in the timeline event
//! rather than uploaded as Matrix media, which keeps a single round-trip for the
//! common case of diffs, plans, and config snippets.
//!
//! Inlining is bounded by [`MAX_INLINE_BYTES`]; anything larger is rejected with
//! [`WorkspaceError::PayloadTooLarge`] and belongs on the media path (a separate
//! roadmap phase). Text payloads are stored verbatim as UTF-8; binary payloads
//! are base64-encoded. In both cases the [`ContextShare::sha256`] digest covers
//! the raw bytes so a receiver can verify integrity independent of encoding.

use std::process::Command;

use base64::Engine as _;
use matrix_sdk::config::SyncSettings;
use matrix_sdk::room::MessagesOptions;
use matrix_sdk::{Client, Room};
use sha2::{Digest, Sha256};

use mx_agent_protocol::events::timeline::CONTEXT_SHARE;
use mx_agent_protocol::id::generate_context_id;
use mx_agent_protocol::schema::ContextShare;

use crate::matrix::restore_client;
use crate::session::StoredSession;
use crate::workspace::{parse_room_or_alias, resolve_room_id, WorkspaceError};

/// Maximum size of an inline context-share payload (256 KiB).
///
/// Larger objects should be uploaded as Matrix media and referenced by
/// `mxc_uri` instead (architecture §6); inlining them would bloat the room
/// timeline and the homeserver's event store.
pub const MAX_INLINE_BYTES: usize = 256 * 1024;

/// MIME type assigned to a shared git diff.
pub const DIFF_MIME_TYPE: &str = "text/x-diff";

/// MIME type assigned to shared environment metadata.
pub const ENV_MIME_TYPE: &str = "application/json";

/// Default set of environment facts collected by [`ShareEnvOptions`].
pub const DEFAULT_ENV_INCLUDE: &[&str] = &["node", "npm", "os", "git"];

/// Options for [`share_context`]: share an arbitrary typed payload.
#[derive(Debug, Clone, Default)]
pub struct ShareContextOptions {
    /// Room ID or alias to share into.
    pub room: String,
    /// Object name, e.g. `plan.json`.
    pub name: String,
    /// MIME type of the payload, e.g. `application/json`.
    pub mime_type: String,
    /// Raw payload bytes (typically read from stdin).
    pub data: Vec<u8>,
}

/// Options for [`share_diff`]: capture and share the current git diff.
#[derive(Debug, Clone, Default)]
pub struct ShareDiffOptions {
    /// Room ID or alias to share into.
    pub room: String,
    /// Base revision to diff against (e.g. `main`). When `None`, the unstaged
    /// working-tree diff is captured.
    pub base: Option<String>,
    /// Emit a `--stat` summary instead of a full unified diff.
    pub stat: bool,
}

/// Options for [`share_env`]: collect and share environment metadata.
#[derive(Debug, Clone)]
pub struct ShareEnvOptions {
    /// Room ID or alias to share into.
    pub room: String,
    /// Facts to include, e.g. `["node", "npm", "os", "git"]`.
    pub include: Vec<String>,
}

impl Default for ShareEnvOptions {
    fn default() -> Self {
        Self {
            room: String::new(),
            include: DEFAULT_ENV_INCLUDE.iter().map(|s| s.to_string()).collect(),
        }
    }
}

/// Options for [`list_context_shares`].
#[derive(Debug, Clone)]
pub struct ListSharesOptions {
    /// Room ID or alias to list shares from.
    pub room: String,
    /// Maximum number of recent timeline events to scan.
    pub limit: u32,
}

/// Encode payload bytes as UTF-8 text when valid, otherwise base64.
///
/// Returns the encoding label (`utf-8` or `base64`) and the encoded string.
fn encode_payload(data: &[u8]) -> (&'static str, String) {
    match std::str::from_utf8(data) {
        Ok(text) => ("utf-8", text.to_string()),
        Err(_) => (
            "base64",
            base64::engine::general_purpose::STANDARD.encode(data),
        ),
    }
}

/// Build the `com.mxagent.context.share.v1` content for an inlined payload.
///
/// The SHA-256 digest is computed over the raw `data`, independent of the
/// transport encoding chosen by [`encode_payload`].
fn build_inline_share(
    context_id: String,
    name: String,
    mime_type: String,
    data: &[u8],
) -> ContextShare {
    let sha256 = base64::engine::general_purpose::STANDARD.encode(Sha256::digest(data));
    let (encoding, payload) = encode_payload(data);
    ContextShare {
        context_id,
        name,
        mime_type,
        size_bytes: data.len() as u64,
        sha256,
        data: Some(payload),
        encoding: Some(encoding.to_string()),
        mxc_uri: None,
        extra: Default::default(),
    }
}

/// Reject a payload that is too large to inline (architecture §6).
fn check_inline_size(len: usize) -> Result<(), WorkspaceError> {
    if len > MAX_INLINE_BYTES {
        Err(WorkspaceError::PayloadTooLarge {
            size: len,
            max: MAX_INLINE_BYTES,
        })
    } else {
        Ok(())
    }
}

/// Build the argv for capturing a git diff with the given base and format.
fn git_diff_args(base: Option<&str>, stat: bool) -> Vec<String> {
    let mut args = vec!["diff".to_string()];
    if stat {
        args.push("--stat".to_string());
    }
    if let Some(base) = base.filter(|b| !b.is_empty()) {
        args.push(base.to_string());
    }
    args
}

/// Run `git diff` in the current directory and return its output as text.
///
/// Returns [`WorkspaceError::ContextCaptureFailed`] when git cannot be launched
/// or exits non-zero (for example, outside a repository).
fn capture_git_diff(base: Option<&str>, stat: bool) -> Result<String, WorkspaceError> {
    let args = git_diff_args(base, stat);
    let output = Command::new("git")
        .args(&args)
        .output()
        .map_err(|e| WorkspaceError::ContextCaptureFailed(format!("could not run git: {e}")))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(WorkspaceError::ContextCaptureFailed(format!(
            "git {} failed: {}",
            args.join(" "),
            stderr.trim()
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Probe a tool's version by running `<cmd> --version`, trimming the output.
///
/// Returns `None` when the tool is absent or exits non-zero.
fn tool_version(cmd: &str) -> Option<String> {
    let output = Command::new(cmd).arg("--version").output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let line = text.lines().next().unwrap_or("").trim();
    (!line.is_empty()).then(|| line.to_string())
}

/// Assemble an environment-metadata object from `(key, value)` pairs.
///
/// A `None` value is recorded as JSON `null` so a missing tool is reported
/// explicitly rather than silently dropped.
fn assemble_env(entries: Vec<(String, Option<String>)>) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    for (key, value) in entries {
        map.insert(
            key,
            value.map_or(serde_json::Value::Null, serde_json::Value::String),
        );
    }
    serde_json::Value::Object(map)
}

/// Collect the requested environment facts into a JSON object.
///
/// `os` is resolved from compile-time platform constants; every other key is
/// treated as a command whose `--version` output is probed.
fn collect_env(include: &[String]) -> serde_json::Value {
    let entries = include
        .iter()
        .map(|key| {
            let value = match key.as_str() {
                "os" => Some(format!(
                    "{} {}",
                    std::env::consts::OS,
                    std::env::consts::ARCH
                )),
                other => tool_version(other),
            };
            (key.clone(), value)
        })
        .collect();
    assemble_env(entries)
}

/// Sync once, resolve the room, and return its [`Room`] handle.
async fn sync_and_get_room(client: &Client, target: &str) -> Result<Room, WorkspaceError> {
    let id = parse_room_or_alias(target)?;
    client
        .sync_once(SyncSettings::default())
        .await
        .map_err(WorkspaceError::from)?;
    let room_id = resolve_room_id(client, &id).await?;
    client
        .get_room(&room_id)
        .ok_or_else(|| WorkspaceError::RoomNotFound(target.to_string()))
}

/// Send `content` as a `com.mxagent.context.share.v1` timeline event.
async fn publish_context_share(room: &Room, content: &ContextShare) -> Result<(), WorkspaceError> {
    let value = serde_json::to_value(content)
        .map_err(|e| WorkspaceError::from(matrix_sdk::Error::SerdeJson(e)))?;
    room.send_raw(CONTEXT_SHARE, value)
        .await
        .map_err(WorkspaceError::from)?;
    Ok(())
}

/// Share an arbitrary typed payload into a workspace room.
///
/// The payload is inlined in the event; payloads larger than
/// [`MAX_INLINE_BYTES`] are rejected with [`WorkspaceError::PayloadTooLarge`].
/// Returns the published [`ContextShare`] (including its generated
/// `context_id`).
pub async fn share_context(
    client: &Client,
    options: &ShareContextOptions,
) -> Result<ContextShare, WorkspaceError> {
    check_inline_size(options.data.len())?;
    let room = sync_and_get_room(client, &options.room).await?;
    let content = build_inline_share(
        generate_context_id(),
        options.name.clone(),
        options.mime_type.clone(),
        &options.data,
    );
    publish_context_share(&room, &content).await?;
    Ok(content)
}

/// Capture the current git diff and share it into a workspace room.
pub async fn share_diff(
    client: &Client,
    options: &ShareDiffOptions,
) -> Result<ContextShare, WorkspaceError> {
    let diff = capture_git_diff(options.base.as_deref(), options.stat)?;
    let name = if options.stat {
        "diff.stat"
    } else {
        "diff.patch"
    };
    let ctx = ShareContextOptions {
        room: options.room.clone(),
        name: name.to_string(),
        mime_type: DIFF_MIME_TYPE.to_string(),
        data: diff.into_bytes(),
    };
    share_context(client, &ctx).await
}

/// Collect environment metadata and share it into a workspace room.
pub async fn share_env(
    client: &Client,
    options: &ShareEnvOptions,
) -> Result<ContextShare, WorkspaceError> {
    let env = collect_env(&options.include);
    // Pretty-printing an in-memory `Value` cannot fail.
    let json = serde_json::to_string_pretty(&env).unwrap_or_else(|_| "{}".to_string());
    let ctx = ShareContextOptions {
        room: options.room.clone(),
        name: "env.json".to_string(),
        mime_type: ENV_MIME_TYPE.to_string(),
        data: json.into_bytes(),
    };
    share_context(client, &ctx).await
}

/// List recent context shares in a workspace room, newest first.
///
/// Scans up to `options.limit` recent timeline events and returns the parsed
/// content of every `com.mxagent.context.share.v1` event among them.
pub async fn list_context_shares(
    client: &Client,
    options: &ListSharesOptions,
) -> Result<Vec<ContextShare>, WorkspaceError> {
    let room = sync_and_get_room(client, &options.room).await?;
    let mut request = MessagesOptions::backward();
    request.limit = matrix_sdk::ruma::UInt::from(options.limit);
    let messages = room.messages(request).await.map_err(WorkspaceError::from)?;

    let mut shares = Vec::new();
    for event in messages.chunk {
        let raw = event.raw();
        let is_share =
            raw.get_field::<String>("type").ok().flatten().as_deref() == Some(CONTEXT_SHARE);
        if is_share {
            if let Ok(Some(content)) = raw.get_field::<ContextShare>("content") {
                shares.push(content);
            }
        }
    }
    Ok(shares)
}

/// Share a typed payload, restoring the authenticated client from `session`.
pub async fn share_context_for_session(
    session: &StoredSession,
    options: &ShareContextOptions,
) -> Result<ContextShare, WorkspaceError> {
    let client = restore_client(session).await?;
    share_context(&client, options).await
}

/// Share the current git diff, restoring the authenticated client from
/// `session`.
pub async fn share_diff_for_session(
    session: &StoredSession,
    options: &ShareDiffOptions,
) -> Result<ContextShare, WorkspaceError> {
    let client = restore_client(session).await?;
    share_diff(&client, options).await
}

/// Share environment metadata, restoring the authenticated client from
/// `session`.
pub async fn share_env_for_session(
    session: &StoredSession,
    options: &ShareEnvOptions,
) -> Result<ContextShare, WorkspaceError> {
    let client = restore_client(session).await?;
    share_env(&client, options).await
}

/// List context shares, restoring the authenticated client from `session`.
pub async fn list_context_shares_for_session(
    session: &StoredSession,
    options: &ListSharesOptions,
) -> Result<Vec<ContextShare>, WorkspaceError> {
    let client = restore_client(session).await?;
    list_context_shares(&client, options).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    #[test]
    fn text_payload_is_inlined_as_utf8() {
        let (encoding, payload) = encode_payload(b"{\"step\":\"run tests\"}");
        assert_eq!(encoding, "utf-8");
        assert_eq!(payload, "{\"step\":\"run tests\"}");
    }

    #[test]
    fn binary_payload_is_base64_encoded() {
        let data = [0xff, 0xfe, 0x00, 0x01];
        let (encoding, payload) = encode_payload(&data);
        assert_eq!(encoding, "base64");
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(payload)
            .expect("payload is valid base64");
        assert_eq!(decoded, data);
    }

    #[test]
    fn inline_share_records_size_digest_and_encoding() {
        let data = b"hello context";
        let share = build_inline_share(
            "ctx_test".to_string(),
            "note.txt".to_string(),
            "text/plain".to_string(),
            data,
        );
        assert_eq!(share.context_id, "ctx_test");
        assert_eq!(share.name, "note.txt");
        assert_eq!(share.mime_type, "text/plain");
        assert_eq!(share.size_bytes, data.len() as u64);
        assert_eq!(share.encoding.as_deref(), Some("utf-8"));
        assert_eq!(share.data.as_deref(), Some("hello context"));
        // Inline shares never carry an mxc reference.
        assert!(share.mxc_uri.is_none());
        // The digest is the base64 of SHA-256 over the raw bytes.
        let expected = base64::engine::general_purpose::STANDARD.encode(Sha256::digest(data));
        assert_eq!(share.sha256, expected);
    }

    #[test]
    fn oversize_payload_is_rejected() {
        // Exactly at the limit is allowed; one byte over is not.
        assert!(check_inline_size(MAX_INLINE_BYTES).is_ok());
        let err = check_inline_size(MAX_INLINE_BYTES + 1)
            .expect_err("a payload over the limit must be rejected");
        match err {
            WorkspaceError::PayloadTooLarge { size, max } => {
                assert_eq!(size, MAX_INLINE_BYTES + 1);
                assert_eq!(max, MAX_INLINE_BYTES);
            }
            other => panic!("expected PayloadTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn git_diff_args_encode_base_and_format() {
        assert_eq!(git_diff_args(None, false), vec!["diff"]);
        assert_eq!(git_diff_args(Some("main"), false), vec!["diff", "main"]);
        assert_eq!(git_diff_args(None, true), vec!["diff", "--stat"]);
        assert_eq!(
            git_diff_args(Some("HEAD~1"), true),
            vec!["diff", "--stat", "HEAD~1"]
        );
        // An empty base string is ignored rather than passed to git.
        assert_eq!(git_diff_args(Some(""), false), vec!["diff"]);
    }

    #[test]
    fn assemble_env_records_present_and_missing_facts() {
        let env = assemble_env(vec![
            ("node".to_string(), Some("v20.11.0".to_string())),
            ("npm".to_string(), None),
        ]);
        assert_eq!(
            env,
            json!({
                "node": "v20.11.0",
                "npm": Value::Null
            })
        );
    }

    #[test]
    fn collect_env_resolves_os_from_platform_constants() {
        let env = collect_env(&["os".to_string()]);
        let os = env
            .get("os")
            .and_then(Value::as_str)
            .expect("os is a string");
        assert!(os.contains(std::env::consts::OS));
        assert!(os.contains(std::env::consts::ARCH));
    }
}
