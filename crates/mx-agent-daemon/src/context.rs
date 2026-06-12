//! Context sharing: `com.mxagent.context.share.v1`.
//!
//! Agents broadcast working context — a git diff, environment metadata, or an
//! arbitrary typed blob piped on stdin — into a workspace room so peers can pick
//! it up (see `docs/architecture.md`, section 6). A share travels by one of two
//! transports, chosen by size:
//!
//! - **Small payloads** (up to [`MAX_INLINE_BYTES`]) are inlined directly in the
//!   timeline event via [`ContextShare::data`], keeping a single round-trip for
//!   the common case of diffs, plans, and config snippets. Text is stored
//!   verbatim as UTF-8; binary is base64-encoded.
//! - **Large payloads** are uploaded as Matrix media and referenced by
//!   [`ContextShare::mxc_uri`], keeping the room timeline and the homeserver's
//!   event store small.
//!
//! In both cases the [`ContextShare::sha256`] digest covers the raw bytes, so a
//! receiver can verify integrity independent of transport and encoding.
//! [`fetch_context`] retrieves a share's artifact — downloading the media or
//! decoding the inline payload — and rejects any byte stream whose digest does
//! not match with [`WorkspaceError::ContextIntegrity`].

use std::process::Command;

use base64::Engine as _;
use matrix_sdk::config::SyncSettings;
use matrix_sdk::media::{MediaFormat, MediaRequestParameters};
use matrix_sdk::room::MessagesOptions;
use matrix_sdk::ruma::events::room::MediaSource;
use matrix_sdk::ruma::OwnedMxcUri;
use matrix_sdk::{Client, Room};
use mime::Mime;
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
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
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
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
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
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
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
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ListSharesOptions {
    /// Room ID or alias to list shares from.
    pub room: String,
    /// Maximum number of recent timeline events to scan.
    pub limit: u32,
}

/// Default number of recent timeline events [`fetch_context`] scans when
/// locating a share by `context_id`.
pub const DEFAULT_FETCH_SCAN_LIMIT: u32 = 100;

/// Options for [`fetch_context`].
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FetchContextOptions {
    /// Room ID or alias to fetch the share from.
    pub room: String,
    /// Context ID of the share to retrieve.
    pub context_id: String,
    /// Maximum number of recent timeline events to scan when locating the
    /// share.
    pub limit: u32,
    /// Matrix user id of the agent expected to have produced the share. Shares
    /// are not invocation-linked, so when this is `None` (the default)
    /// [`fetch_context`] accepts a share only if every event carrying the
    /// `context_id` comes from the *same* sender; two senders for one
    /// `context_id` is an ambiguous shadowing attempt and is rejected. Set it to
    /// pin the producer explicitly and resolve such collisions (issue #304).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_sender: Option<String>,
}

impl Default for FetchContextOptions {
    fn default() -> Self {
        Self {
            room: String::new(),
            context_id: String::new(),
            limit: DEFAULT_FETCH_SCAN_LIMIT,
            expected_sender: None,
        }
    }
}

/// A context artifact retrieved and verified by [`fetch_context`].
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FetchedContext {
    /// The share metadata as published in the room.
    pub share: ContextShare,
    /// The raw artifact bytes, verified against [`ContextShare::sha256`].
    pub data: Vec<u8>,
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

/// Base64-encode the SHA-256 digest of `data`.
///
/// This is the canonical form stored in [`ContextShare::sha256`]: it always
/// covers the raw (decoded) bytes, independent of the transport encoding.
fn sha256_b64(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(Sha256::digest(data))
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
    let (encoding, payload) = encode_payload(data);
    ContextShare {
        context_id,
        name,
        mime_type,
        size_bytes: data.len() as u64,
        sha256: sha256_b64(data),
        data: Some(payload),
        encoding: Some(encoding.to_string()),
        mxc_uri: None,
        extra: Default::default(),
    }
}

/// Build the `com.mxagent.context.share.v1` content for a media-backed payload.
///
/// The raw bytes live in Matrix media at `mxc_uri`; the event carries only the
/// reference plus the size and digest, with no inline `data`/`encoding`.
fn build_media_share(
    context_id: String,
    name: String,
    mime_type: String,
    size_bytes: u64,
    sha256: String,
    mxc_uri: String,
) -> ContextShare {
    ContextShare {
        context_id,
        name,
        mime_type,
        size_bytes,
        sha256,
        data: None,
        encoding: None,
        mxc_uri: Some(mxc_uri),
        extra: Default::default(),
    }
}

/// Parse `mime_type`, falling back to `application/octet-stream` when it is not
/// a valid MIME string so a share never fails purely on a malformed label.
fn parse_mime(mime_type: &str) -> Mime {
    mime_type.parse().unwrap_or(mime::APPLICATION_OCTET_STREAM)
}

/// Upload `data` as Matrix media and build a media-backed [`ContextShare`].
async fn upload_media_share(
    client: &Client,
    context_id: String,
    name: String,
    mime_type: String,
    data: &[u8],
) -> Result<ContextShare, WorkspaceError> {
    let sha256 = sha256_b64(data);
    let size_bytes = data.len() as u64;
    let mime = parse_mime(&mime_type);
    let response = client
        .media()
        .upload(&mime, data.to_vec(), None)
        .await
        .map_err(WorkspaceError::from)?;
    Ok(build_media_share(
        context_id,
        name,
        mime_type,
        size_bytes,
        sha256,
        response.content_uri.to_string(),
    ))
}

/// Parse and validate an `mxc://` URI recorded on a share.
fn parse_mxc(uri: &str) -> Result<OwnedMxcUri, WorkspaceError> {
    let parsed = OwnedMxcUri::from(uri);
    if parsed.is_valid() {
        Ok(parsed)
    } else {
        Err(WorkspaceError::ContextRetrievalFailed(format!(
            "{uri:?} is not a valid mxc:// URI"
        )))
    }
}

/// Download the raw bytes of a media-backed share from `mxc_uri`.
async fn download_media(client: &Client, mxc_uri: &str) -> Result<Vec<u8>, WorkspaceError> {
    let request = MediaRequestParameters {
        source: MediaSource::Plain(parse_mxc(mxc_uri)?),
        format: MediaFormat::File,
    };
    client
        .media()
        .get_media_content(&request, false)
        .await
        .map_err(WorkspaceError::from)
}

/// Decode an inline share's [`data`](ContextShare::data) back into raw bytes,
/// reversing the [`encoding`](ContextShare::encoding) chosen by
/// [`encode_payload`].
fn decode_inline(share: &ContextShare) -> Result<Vec<u8>, WorkspaceError> {
    let data = share.data.as_deref().ok_or_else(|| {
        WorkspaceError::ContextRetrievalFailed(format!(
            "share {:?} has neither inline data nor an mxc:// reference",
            share.context_id
        ))
    })?;
    match share.encoding.as_deref() {
        Some("base64") => base64::engine::general_purpose::STANDARD
            .decode(data)
            .map_err(|e| {
                WorkspaceError::ContextRetrievalFailed(format!("invalid base64 payload: {e}"))
            }),
        // Text payloads are stored verbatim; a missing encoding is treated as
        // UTF-8 for forward compatibility.
        Some("utf-8") | None => Ok(data.as_bytes().to_vec()),
        Some(other) => Err(WorkspaceError::ContextRetrievalFailed(format!(
            "unknown payload encoding {other:?}"
        ))),
    }
}

/// Verify that `data` hashes to the digest recorded on `share`.
///
/// Returns [`WorkspaceError::ContextIntegrity`] on any mismatch so a corrupt or
/// tampered artifact is rejected rather than silently accepted (architecture
/// §6).
fn verify_digest(share: &ContextShare, data: &[u8]) -> Result<(), WorkspaceError> {
    let actual = sha256_b64(data);
    if actual == share.sha256 {
        Ok(())
    } else {
        Err(WorkspaceError::ContextIntegrity {
            context_id: share.context_id.clone(),
            expected: share.sha256.clone(),
            actual,
        })
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
/// Payloads up to [`MAX_INLINE_BYTES`] are inlined directly in the event; larger
/// payloads are uploaded as Matrix media and referenced by `mxc_uri` instead of
/// bloating the timeline (architecture §6). Returns the published
/// [`ContextShare`] (including its generated `context_id`).
pub async fn share_context(
    client: &Client,
    options: &ShareContextOptions,
) -> Result<ContextShare, WorkspaceError> {
    let room = sync_and_get_room(client, &options.room).await?;
    let context_id = generate_context_id();
    let content = if options.data.len() > MAX_INLINE_BYTES {
        upload_media_share(
            client,
            context_id,
            options.name.clone(),
            options.mime_type.clone(),
            &options.data,
        )
        .await?
    } else {
        build_inline_share(
            context_id,
            options.name.clone(),
            options.mime_type.clone(),
            &options.data,
        )
    };
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

/// A context share scanned from the room timeline, paired with the Matrix user
/// id (`sender`) that published it. The producer travels independently of the
/// (attacker-controllable) event content, so it is the value the sender-pin is
/// checked against (issue #304).
struct ScannedShare {
    /// The parsed share content.
    share: ContextShare,
    /// Matrix user id of the event sender.
    producer: String,
}

/// Scan up to `limit` recent timeline events in `room` for context shares,
/// pairing each with the Matrix `sender` that published it (newest first).
///
/// The `sender` is read from the raw event (not from its content). A share
/// missing a `sender` is skipped — a share whose producer cannot be established
/// is never returned.
async fn scan_context_shares(room: &Room, limit: u32) -> Result<Vec<ScannedShare>, WorkspaceError> {
    let mut request = MessagesOptions::backward();
    request.limit = matrix_sdk::ruma::UInt::from(limit);
    let messages = room.messages(request).await.map_err(WorkspaceError::from)?;

    let mut shares = Vec::new();
    for event in messages.chunk {
        let raw = event.raw();
        let is_share =
            raw.get_field::<String>("type").ok().flatten().as_deref() == Some(CONTEXT_SHARE);
        if !is_share {
            continue;
        }
        let producer = raw.get_field::<String>("sender").ok().flatten();
        if let (Ok(Some(share)), Some(producer)) =
            (raw.get_field::<ContextShare>("content"), producer)
        {
            shares.push(ScannedShare { share, producer });
        }
    }
    Ok(shares)
}

/// Pin the producer of the share with `context_id` among `shares`.
///
/// With an explicit `expected_sender`, only a share from that producer is
/// accepted. Without one, the share is accepted only when every event carrying
/// `context_id` has the *same* sender; two distinct senders is an ambiguous
/// shadowing attempt and is rejected so a room member cannot shadow a legitimate
/// share (issue #304). A missing `context_id` is
/// [`WorkspaceError::ContextNotFound`].
fn select_share(
    shares: Vec<ScannedShare>,
    context_id: &str,
    expected_sender: Option<&str>,
) -> Result<ContextShare, WorkspaceError> {
    let matches: Vec<ScannedShare> = shares
        .into_iter()
        .filter(|s| s.share.context_id == context_id)
        .collect();
    if matches.is_empty() {
        return Err(WorkspaceError::ContextNotFound(context_id.to_string()));
    }
    if let Some(expected) = expected_sender.filter(|s| !s.is_empty()) {
        return matches
            .into_iter()
            .find(|s| s.producer == expected)
            .map(|s| s.share)
            .ok_or_else(|| WorkspaceError::ContextNotFound(context_id.to_string()));
    }
    // No explicit producer: accept only when every matching share is from one
    // sender. Distinct senders for a single context_id is a shadow attempt.
    let first = &matches[0].producer;
    if matches.iter().all(|s| &s.producer == first) {
        Ok(matches.into_iter().next().expect("non-empty").share)
    } else {
        Err(WorkspaceError::ContextRetrievalFailed(format!(
            "multiple shares with context_id {context_id:?} from different senders; \
             pin the expected producer to disambiguate"
        )))
    }
}

/// List recent context shares in a workspace room, newest first.
///
/// Scans up to `options.limit` recent timeline events and returns the parsed
/// content of every `com.mxagent.context.share.v1` event among them. This is a
/// display lister; [`fetch_context`] applies the sender-pin when actually
/// retrieving a share's bytes.
pub async fn list_context_shares(
    client: &Client,
    options: &ListSharesOptions,
) -> Result<Vec<ContextShare>, WorkspaceError> {
    let room = sync_and_get_room(client, &options.room).await?;
    Ok(scan_context_shares(&room, options.limit)
        .await?
        .into_iter()
        .map(|s| s.share)
        .collect())
}

/// Retrieve and verify a single context artifact from a workspace room.
///
/// Locates the share with `options.context_id` among the recent timeline events,
/// pinned to its producer (issue #304), retrieves its bytes — downloading the
/// Matrix media for a large share or decoding the inline payload for a small one
/// — and verifies them against the share's [`sha256`](ContextShare::sha256). A
/// digest mismatch is reported as [`WorkspaceError::ContextIntegrity`]; an
/// unknown ID (or one only published by an unexpected sender) as
/// [`WorkspaceError::ContextNotFound`].
pub async fn fetch_context(
    client: &Client,
    options: &FetchContextOptions,
) -> Result<FetchedContext, WorkspaceError> {
    let room = sync_and_get_room(client, &options.room).await?;
    let shares = scan_context_shares(&room, options.limit).await?;
    let share = select_share(
        shares,
        &options.context_id,
        options.expected_sender.as_deref(),
    )?;

    let data = match &share.mxc_uri {
        Some(mxc_uri) => download_media(client, mxc_uri).await?,
        None => decode_inline(&share)?,
    };
    verify_digest(&share, &data)?;
    Ok(FetchedContext { share, data })
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

/// Fetch and verify a context artifact, restoring the authenticated client from
/// `session`.
pub async fn fetch_context_for_session(
    session: &StoredSession,
    options: &FetchContextOptions,
) -> Result<FetchedContext, WorkspaceError> {
    let client = restore_client(session).await?;
    fetch_context(&client, options).await
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
    fn media_share_records_reference_size_and_digest() {
        let data = vec![0u8; MAX_INLINE_BYTES + 1];
        let share = build_media_share(
            "ctx_big".to_string(),
            "full-log.txt".to_string(),
            "text/plain".to_string(),
            data.len() as u64,
            sha256_b64(&data),
            "mxc://matrix.org/abcdef".to_string(),
        );
        assert_eq!(share.context_id, "ctx_big");
        assert_eq!(share.name, "full-log.txt");
        assert_eq!(share.size_bytes, data.len() as u64);
        assert_eq!(share.mxc_uri.as_deref(), Some("mxc://matrix.org/abcdef"));
        // Media-backed shares carry no inline payload.
        assert!(share.data.is_none());
        assert!(share.encoding.is_none());
        assert_eq!(share.sha256, sha256_b64(&data));
    }

    #[test]
    fn parse_mime_falls_back_on_garbage() {
        assert_eq!(parse_mime("text/plain"), mime::TEXT_PLAIN);
        assert_eq!(parse_mime("not a mime"), mime::APPLICATION_OCTET_STREAM);
    }

    #[test]
    fn parse_mxc_validates_uri() {
        assert!(parse_mxc("mxc://matrix.org/abcdef").is_ok());
        let err =
            parse_mxc("https://example.org/not-mxc").expect_err("a non-mxc URI must be rejected");
        assert!(matches!(err, WorkspaceError::ContextRetrievalFailed(_)));
    }

    #[test]
    fn decode_inline_reverses_both_encodings() {
        let utf8 = build_inline_share(
            "c".to_string(),
            "n".to_string(),
            "text/plain".to_string(),
            b"hello",
        );
        assert_eq!(decode_inline(&utf8).expect("utf-8 decodes"), b"hello");

        let binary = build_inline_share(
            "c".to_string(),
            "n".to_string(),
            "application/octet-stream".to_string(),
            &[0xff, 0x00, 0x10],
        );
        assert_eq!(
            decode_inline(&binary).expect("base64 decodes"),
            vec![0xff, 0x00, 0x10]
        );
    }

    #[test]
    fn decode_inline_rejects_unknown_encoding() {
        let mut share = build_inline_share(
            "c".to_string(),
            "n".to_string(),
            "text/plain".to_string(),
            b"hello",
        );
        share.encoding = Some("rot13".to_string());
        assert!(matches!(
            decode_inline(&share),
            Err(WorkspaceError::ContextRetrievalFailed(_))
        ));
    }

    fn scanned_share(context_id: &str, producer: &str) -> ScannedShare {
        ScannedShare {
            share: build_inline_share(
                context_id.to_string(),
                "note.txt".to_string(),
                "text/plain".to_string(),
                b"hello",
            ),
            producer: producer.to_string(),
        }
    }

    #[test]
    fn select_share_accepts_a_single_producer() {
        let shares = vec![scanned_share("ctx_1", "@exec:hs")];
        let share = select_share(shares, "ctx_1", None).expect("a single-producer share is picked");
        assert_eq!(share.context_id, "ctx_1");
    }

    #[test]
    fn select_share_rejects_an_unexpected_producer_when_pinned() {
        // With an explicit expected producer, a same-context_id share from any
        // other sender must not be returned (issue #304).
        let shares = vec![scanned_share("ctx_1", "@member:hs")];
        let err = select_share(shares, "ctx_1", Some("@exec:hs"))
            .expect_err("a share from an unexpected sender must be rejected");
        assert!(matches!(err, WorkspaceError::ContextNotFound(_)));
    }

    #[test]
    fn select_share_pins_to_the_expected_producer_amid_a_shadow() {
        // The legitimate producer's share is selected even when a foreign member
        // republished the same context_id first (newest-first ordering).
        let shares = vec![
            scanned_share("ctx_1", "@member:hs"),
            scanned_share("ctx_1", "@exec:hs"),
        ];
        let share = select_share(shares, "ctx_1", Some("@exec:hs"))
            .expect("the expected producer's share is selected past the shadow");
        assert_eq!(share.context_id, "ctx_1");
    }

    #[test]
    fn select_share_rejects_ambiguous_same_id_collisions() {
        // Without an explicit producer, two distinct senders sharing one
        // context_id is a shadow attempt and is rejected — fail closed.
        let shares = vec![
            scanned_share("ctx_1", "@member:hs"),
            scanned_share("ctx_1", "@exec:hs"),
        ];
        let err = select_share(shares, "ctx_1", None)
            .expect_err("ambiguous same-id shares must be rejected");
        assert!(matches!(err, WorkspaceError::ContextRetrievalFailed(_)));
    }

    #[test]
    fn select_share_reports_unknown_context_id() {
        let shares = vec![scanned_share("ctx_1", "@exec:hs")];
        let err =
            select_share(shares, "ctx_missing", None).expect_err("an unknown context id is absent");
        assert!(matches!(err, WorkspaceError::ContextNotFound(_)));
    }

    #[test]
    fn verify_digest_accepts_matching_bytes() {
        let data = b"verify me";
        let share = build_media_share(
            "ctx".to_string(),
            "n".to_string(),
            "text/plain".to_string(),
            data.len() as u64,
            sha256_b64(data),
            "mxc://matrix.org/id".to_string(),
        );
        verify_digest(&share, data).expect("matching digest must pass");
    }

    #[test]
    fn verify_digest_detects_sha256_mismatch() {
        // A share that advertises the digest of one payload but is handed a
        // different (corrupt/tampered) byte stream must be rejected.
        let share = build_media_share(
            "ctx_tampered".to_string(),
            "n".to_string(),
            "text/plain".to_string(),
            9,
            sha256_b64(b"the original"),
            "mxc://matrix.org/id".to_string(),
        );
        let err =
            verify_digest(&share, b"tampered!").expect_err("a digest mismatch must be detected");
        match err {
            WorkspaceError::ContextIntegrity {
                context_id,
                expected,
                actual,
            } => {
                assert_eq!(context_id, "ctx_tampered");
                assert_eq!(expected, sha256_b64(b"the original"));
                assert_eq!(actual, sha256_b64(b"tampered!"));
                assert_ne!(expected, actual);
            }
            other => panic!("expected ContextIntegrity, got {other:?}"),
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

    #[test]
    fn select_share_empty_expected_sender_falls_back_to_ambiguity_detection() {
        // An empty string for `expected_sender` must be treated as unpinned (same
        // as `None`), so the ambiguity-detection path applies when two senders
        // publish the same context_id. This exercises the `filter(|s|
        // !s.is_empty())` guard in `select_share` (issue #304).
        let shares = vec![
            scanned_share("ctx_1", "@member:hs"),
            scanned_share("ctx_1", "@exec:hs"),
        ];
        // An explicit empty string is treated as if no pin was supplied, so
        // two distinct senders for the same context_id must be rejected.
        let err = select_share(shares, "ctx_1", Some(""))
            .expect_err("empty expected_sender must fall back to ambiguity detection");
        assert!(
            matches!(err, WorkspaceError::ContextRetrievalFailed(_)),
            "two distinct senders without a pin must produce ContextRetrievalFailed"
        );
    }

    #[test]
    fn select_share_empty_expected_sender_accepts_single_producer() {
        // When expected_sender is the empty string and only one sender published
        // the context_id, it is accepted (the single-producer path of the
        // ambiguity check) (issue #304).
        let shares = vec![scanned_share("ctx_1", "@exec:hs")];
        let share = select_share(shares, "ctx_1", Some(""))
            .expect("empty expected_sender with a single producer should succeed");
        assert_eq!(share.context_id, "ctx_1");
    }

    #[test]
    fn select_share_accepts_duplicate_events_from_same_producer() {
        // When the executing agent republishes the same context_id (e.g., a
        // retransmission), both events have the same sender, so the ambiguity
        // check passes and the first (newest-first) event is returned.  A room
        // member's shadow attempt would add a *different* sender, which is what
        // the ambiguity check actually blocks (issue #304).
        let shares = vec![
            scanned_share("ctx_1", "@exec:hs"),
            scanned_share("ctx_1", "@exec:hs"),
        ];
        let share =
            select_share(shares, "ctx_1", None).expect("two copies from the same producer are OK");
        assert_eq!(share.context_id, "ctx_1");
    }

    #[test]
    fn select_share_pinned_picks_first_match_among_duplicates() {
        // With an explicit producer pin, duplicate events from that producer
        // return the first match (newest-first) without ambiguity error.
        let shares = vec![
            scanned_share("ctx_1", "@exec:hs"),
            scanned_share("ctx_1", "@exec:hs"),
        ];
        let share = select_share(shares, "ctx_1", Some("@exec:hs"))
            .expect("pinned producer with duplicates should return the first match");
        assert_eq!(share.context_id, "ctx_1");
    }
}
