//! Large-output artifact mode (architecture §8.3, §8.4).
//!
//! Streaming every byte of a noisy command over the Matrix timeline is wasteful
//! and quickly trips the homeserver's rate limits. Once a stream's output
//! exceeds the timeline budget, the daemon switches that stream to **artifact
//! mode**: the *full* log is uploaded once as a Matrix media object and the
//! timeline carries a single `com.mxagent.stream.artifact.v1` event that
//! references it (architecture §8.4). The event also carries a short **tail
//! preview** so a terminal can show the end of the output — usually the most
//! relevant part — without downloading the whole artifact.
//!
//! ## Compression
//!
//! Logs are highly compressible, so the artifact is compressed with **zstd
//! where available** (architecture §8.1: "compression: zstd optional for
//! non-interactive streams"). Compression shells out to the `zstd` binary; if
//! it is not installed the log is uploaded uncompressed and the artifact's
//! `name`/`mime_type` reflect that. This keeps the daemon free of a native zstd
//! dependency while still benefiting from compression on hosts that have it.
//!
//! ## Integrity
//!
//! As with context shares (see [`crate::context`]), the [`StreamArtifact::sha256`]
//! digest and [`StreamArtifact::size_bytes`] describe the *uploaded* bytes (the
//! possibly-compressed media), so a downloader can verify the artifact against
//! the timeline event before trusting it.

use std::fmt;
use std::process::Stdio;

use base64::Engine as _;
use matrix_sdk::config::SyncSettings;
use matrix_sdk::media::{MediaFormat, MediaRequestParameters};
use matrix_sdk::room::MessagesOptions;
use matrix_sdk::ruma::events::room::{EncryptedFile, MediaSource};
use matrix_sdk::ruma::OwnedMxcUri;
use matrix_sdk::{Client, Room};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use mx_agent_protocol::events::timeline::STREAM_ARTIFACT;
use mx_agent_protocol::schema::{StreamArtifact, StreamKind};

use crate::matrix::restore_client;
use crate::session::StoredSession;
use crate::workspace::{parse_room_or_alias, resolve_room_id, WorkspaceError};

/// Default per-stream timeline output budget (architecture §8.4). Output beyond
/// this is uploaded as an artifact instead of streamed as timeline chunks. Set
/// to match the context-share inline threshold (256 KiB).
pub const DEFAULT_MAX_TIMELINE_OUTPUT_BYTES: usize = 256 * 1024;

/// Default tail-preview size (architecture §8.4: "last 4KB of output").
pub const DEFAULT_TAIL_PREVIEW_BYTES: usize = 4 * 1024;

/// zstd compression level for non-interactive log artifacts. Level 3 (zstd's
/// own default) is a good speed/ratio trade-off for text logs.
const ZSTD_LEVEL: &str = "-3";

/// Tuning for when and how output switches to artifact mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArtifactConfig {
    /// Switch a stream to artifact mode once its output exceeds this many bytes.
    pub max_timeline_output_bytes: usize,
    /// How many trailing bytes of the output to include as a tail preview.
    pub tail_preview_bytes: usize,
    /// Attempt zstd compression (used where the `zstd` binary is available).
    pub compress: bool,
}

impl ArtifactConfig {
    /// Default configuration: 256 KiB budget, 4 KiB tail preview, compression on.
    pub const fn new() -> Self {
        Self {
            max_timeline_output_bytes: DEFAULT_MAX_TIMELINE_OUTPUT_BYTES,
            tail_preview_bytes: DEFAULT_TAIL_PREVIEW_BYTES,
            compress: true,
        }
    }

    /// Whether output of `output_len` bytes should switch to artifact mode.
    pub const fn should_switch(&self, output_len: usize) -> bool {
        output_len > self.max_timeline_output_bytes
    }
}

impl Default for ArtifactConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// An artifact assembled from captured output, ready to be uploaded.
///
/// Carries the (possibly-compressed) bytes to upload plus every field of the
/// eventual [`StreamArtifact`] except its `mxc_uri`, which is only known after
/// the upload. Build one with [`prepare_artifact`], then either
/// [`upload_artifact`] it or, when no Matrix client is available, turn it into
/// an event directly with [`PreparedArtifact::into_event`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedArtifact {
    /// Invocation the output belongs to.
    pub invocation_id: String,
    /// Originating stream.
    pub stream: StreamKind,
    /// Artifact file name (e.g. `stdout.log` or `stdout.log.zst`).
    pub name: String,
    /// Logical MIME type of the artifact.
    pub mime_type: String,
    /// Size in bytes of the uploaded (possibly-compressed) media.
    pub size_bytes: u64,
    /// Base64 SHA-256 digest of the uploaded media.
    pub sha256: String,
    /// Tail preview of the original (uncompressed) output.
    pub tail_preview: String,
    /// Whether [`bytes`](Self::upload_bytes) are zstd-compressed.
    pub compressed: bool,
    /// The bytes to upload as Matrix media.
    bytes: Vec<u8>,
}

impl PreparedArtifact {
    /// The bytes to upload as Matrix media.
    pub fn upload_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Finalize into a plaintext [`StreamArtifact`] event referencing `mxc_uri`.
    ///
    /// Pass an empty `mxc_uri` when no upload was performed (e.g. the local
    /// `exec` loopback, which has no homeserver); consumers render the tail
    /// preview regardless. The produced event carries no `encrypted_file`, so it
    /// downloads via the plain [`MediaSource::Plain`] path. For an
    /// end-to-end-encrypted upload use [`into_event_encrypted`](Self::into_event_encrypted).
    pub fn into_event(self, mxc_uri: impl Into<String>) -> StreamArtifact {
        self.into_event_with(mxc_uri, None)
    }

    /// Finalize into an encrypted [`StreamArtifact`] event referencing the
    /// ciphertext `mxc_uri` and carrying the opaque ruma `EncryptedFile` key
    /// material in [`StreamArtifact::encrypted_file`].
    ///
    /// `mxc_uri` is the `EncryptedFile.url` (the ciphertext blob's MXC URI); the
    /// presence of `encrypted_file` selects the decrypt path on download. Never
    /// log `encrypted_file` — it holds the AES-CTR key and IV.
    pub fn into_event_encrypted(
        self,
        mxc_uri: impl Into<String>,
        encrypted_file: serde_json::Value,
    ) -> StreamArtifact {
        self.into_event_with(mxc_uri, Some(encrypted_file))
    }

    /// Shared finalizer for [`into_event`](Self::into_event) /
    /// [`into_event_encrypted`](Self::into_event_encrypted).
    fn into_event_with(
        self,
        mxc_uri: impl Into<String>,
        encrypted_file: Option<serde_json::Value>,
    ) -> StreamArtifact {
        StreamArtifact {
            invocation_id: self.invocation_id,
            stream: self.stream,
            name: self.name,
            mime_type: self.mime_type,
            size_bytes: self.size_bytes,
            sha256: self.sha256,
            mxc_uri: mxc_uri.into(),
            tail_preview: self.tail_preview,
            encrypted_file,
            signature: None,
            extra: Default::default(),
        }
    }
}

/// Assemble an artifact from a stream's full `data`.
///
/// Captures a tail preview of the original output, compresses the bytes with
/// zstd when [`ArtifactConfig::compress`] is set and the `zstd` binary is
/// available (falling back to uncompressed otherwise), and digests the
/// uploadable bytes. The result still needs an `mxc_uri`: upload it with
/// [`upload_artifact`] or finalize locally with [`PreparedArtifact::into_event`].
pub async fn prepare_artifact(
    invocation_id: impl Into<String>,
    stream: StreamKind,
    data: &[u8],
    config: &ArtifactConfig,
) -> PreparedArtifact {
    let invocation_id = invocation_id.into();
    let tail_preview = tail_preview(data, config.tail_preview_bytes);
    let stem = stream_stem(stream);

    let (bytes, name, mime_type, compressed) = match config.compress {
        true => match compress_zstd(data).await {
            Some(compressed) => (
                compressed,
                format!("{stem}.log.zst"),
                "text/plain+zstd".to_string(),
                true,
            ),
            None => (
                data.to_vec(),
                format!("{stem}.log"),
                "text/plain".to_string(),
                false,
            ),
        },
        false => (
            data.to_vec(),
            format!("{stem}.log"),
            "text/plain".to_string(),
            false,
        ),
    };

    PreparedArtifact {
        invocation_id,
        stream,
        name,
        mime_type,
        size_bytes: bytes.len() as u64,
        sha256: sha256_b64(&bytes),
        tail_preview,
        compressed,
        bytes,
    }
}

/// Upload a [`PreparedArtifact`] as Matrix media and return the referencing
/// [`StreamArtifact`] event.
///
/// When `encrypted` is `true` (the destination room has E2EE enabled) the bytes
/// are encrypted client-side and uploaded as ciphertext via
/// [`Client::upload_encrypted_file`]; the returned event carries the ruma
/// `EncryptedFile` key material in [`StreamArtifact::encrypted_file`] and a
/// ciphertext `mxc_uri`. When `false` the existing plaintext `media().upload`
/// path is used and no `encrypted_file` is recorded. The `EncryptedFile` key
/// material is never logged.
pub async fn upload_artifact(
    client: &Client,
    prepared: PreparedArtifact,
    encrypted: bool,
) -> Result<StreamArtifact, ArtifactError> {
    if encrypted {
        let mut reader = std::io::Cursor::new(prepared.bytes.clone());
        let file = client
            .upload_encrypted_file(&mut reader)
            .await
            .map_err(|e| ArtifactError::Upload(Box::new(e)))?;
        let mxc = file.url.to_string();
        let encrypted_file = serde_json::to_value(&file)
            .map_err(|e| ArtifactError::Upload(Box::new(matrix_sdk::Error::SerdeJson(e))))?;
        return Ok(prepared.into_event_encrypted(mxc, encrypted_file));
    }
    let mime = prepared
        .mime_type
        .parse()
        .unwrap_or(mime::APPLICATION_OCTET_STREAM);
    let response = client
        .media()
        .upload(&mime, prepared.bytes.clone(), None)
        .await
        .map_err(|e| ArtifactError::Upload(Box::new(e)))?;
    Ok(prepared.into_event(response.content_uri.to_string()))
}

/// An error raised while producing or uploading an output artifact.
#[derive(Debug)]
pub enum ArtifactError {
    /// Uploading the artifact to Matrix media failed.
    Upload(Box<matrix_sdk::Error>),
}

impl fmt::Display for ArtifactError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ArtifactError::Upload(e) => write!(f, "could not upload output artifact: {e}"),
        }
    }
}

impl std::error::Error for ArtifactError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ArtifactError::Upload(e) => Some(e),
        }
    }
}

/// Whether the `zstd` binary is available on this host.
pub async fn zstd_available() -> bool {
    Command::new("zstd")
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .map(|status| status.success())
        .unwrap_or(false)
}

/// Compress `data` with the `zstd` binary, returning `None` if zstd is not
/// available or compression fails (the caller then uploads `data` uncompressed).
async fn compress_zstd(data: &[u8]) -> Option<Vec<u8>> {
    let mut child = Command::new("zstd")
        .arg("-q")
        .arg(ZSTD_LEVEL)
        .arg("-c")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;

    // Feed stdin from a separate task while we drain stdout concurrently: a
    // large log would otherwise fill zstd's stdout pipe and deadlock a
    // write-everything-then-read approach.
    let mut stdin = child.stdin.take()?;
    let input = data.to_vec();
    let writer = tokio::spawn(async move {
        let _ = stdin.write_all(&input).await;
        let _ = stdin.shutdown().await;
    });

    let output = child.wait_with_output().await.ok();
    let _ = writer.await;

    let output = output?;
    output.status.success().then_some(output.stdout)
}

/// Take the last `max_bytes` of `data` as a lossy-UTF-8 tail preview. Leading
/// bytes that fall mid-character are replaced rather than dropping the preview.
fn tail_preview(data: &[u8], max_bytes: usize) -> String {
    let start = data.len().saturating_sub(max_bytes);
    String::from_utf8_lossy(&data[start..]).into_owned()
}

/// The file-name stem used for a stream's artifact.
fn stream_stem(stream: StreamKind) -> &'static str {
    match stream {
        StreamKind::Stdin => "stdin",
        StreamKind::Stdout => "stdout",
        StreamKind::Stderr => "stderr",
        StreamKind::Pty => "pty",
        StreamKind::Control => "control",
    }
}

/// Base64 SHA-256 of `data` (matching the digest convention used elsewhere).
fn sha256_b64(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    base64::engine::general_purpose::STANDARD.encode(digest)
}

/// Default number of recent timeline events [`retrieve_artifact`] scans when
/// locating a stream artifact by invocation ID. Matches the context-share scan
/// budget ([`crate::context::DEFAULT_FETCH_SCAN_LIMIT`]).
pub const DEFAULT_ARTIFACT_SCAN_LIMIT: u32 = 100;

/// Options for [`retrieve_artifact`].
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RetrieveArtifactOptions {
    /// Room ID or alias to retrieve the artifact from.
    pub room: String,
    /// Invocation whose output artifact to retrieve.
    pub invocation_id: String,
    /// Which captured stream to retrieve (defaults to `stdout`).
    pub stream: StreamKind,
    /// Maximum number of recent timeline events to scan when locating the
    /// artifact.
    pub limit: u32,
    /// Matrix user id of the agent expected to have produced the artifact. When
    /// `None` (the default), [`retrieve_artifact`] resolves the producer from the
    /// invocation's `com.mxagent.invocation.v1` state (`target` → its
    /// `matrix_user_id`) and fails closed if it cannot. Set it to pin the
    /// producer explicitly; either way an artifact from any other sender is
    /// rejected so a room member cannot shadow a legitimate one (issue #304).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_sender: Option<String>,
}

impl Default for RetrieveArtifactOptions {
    fn default() -> Self {
        Self {
            room: String::new(),
            invocation_id: String::new(),
            stream: StreamKind::Stdout,
            limit: DEFAULT_ARTIFACT_SCAN_LIMIT,
            expected_sender: None,
        }
    }
}

/// A stream artifact retrieved, verified, and decompressed by
/// [`retrieve_artifact`].
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RetrievedArtifact {
    /// The artifact metadata as published in the room.
    pub artifact: StreamArtifact,
    /// The original (decompressed) output bytes, verified against
    /// [`StreamArtifact::sha256`].
    pub data: Vec<u8>,
}

/// Whether an artifact's uploaded media is zstd-compressed.
///
/// [`prepare_artifact`] records compression by suffixing the artifact `name`
/// with `.zst` and tagging its `mime_type` with `+zstd`; either marker is
/// sufficient to recognise a compressed artifact on the way back in.
fn is_compressed(artifact: &StreamArtifact) -> bool {
    artifact.name.ends_with(".zst") || artifact.mime_type.ends_with("+zstd")
}

/// Verify `media` against the artifact's recorded digest, then decompress it if
/// the artifact is compressed, returning the original output bytes.
///
/// The [`StreamArtifact::sha256`] digest covers the *uploaded* (possibly
/// compressed) media, so verification happens before decompression: a corrupt
/// download is rejected with [`WorkspaceError::ArtifactIntegrity`] rather than
/// fed to the decompressor.
async fn verify_and_decompress(
    artifact: &StreamArtifact,
    media: Vec<u8>,
) -> Result<Vec<u8>, WorkspaceError> {
    let actual = sha256_b64(&media);
    if actual != artifact.sha256 {
        return Err(WorkspaceError::ArtifactIntegrity {
            invocation_id: artifact.invocation_id.clone(),
            stream: stream_stem(artifact.stream).to_string(),
            expected: artifact.sha256.clone(),
            actual,
        });
    }
    if is_compressed(artifact) {
        decompress_zstd(&media).await.ok_or_else(|| {
            WorkspaceError::ArtifactRetrievalFailed(format!(
                "could not decompress zstd artifact {:?}; is the `zstd` binary installed?",
                artifact.name
            ))
        })
    } else {
        Ok(media)
    }
}

/// A stream artifact scanned from the room timeline, paired with the Matrix user
/// id (`sender`) that published it. The producer travels independently of the
/// (attacker-controllable) event content, so it is the value the sender-pin is
/// checked against (issue #304).
struct ScannedArtifact {
    /// The parsed artifact content.
    artifact: StreamArtifact,
    /// Matrix user id of the event sender.
    producer: String,
}

/// Select the newest artifact matching `invocation_id`, `stream`, **and**
/// `expected_sender` from a timeline scan (artifacts arrive newest-first, so the
/// first match wins).
///
/// Pinning the producer means a same-`invocation_id`+`stream` artifact published
/// by any other room member cannot shadow the legitimate one: it never matches
/// and is skipped (issue #304).
fn select_artifact(
    artifacts: Vec<ScannedArtifact>,
    invocation_id: &str,
    stream: StreamKind,
    expected_sender: &str,
) -> Option<StreamArtifact> {
    artifacts
        .into_iter()
        .find(|s| {
            s.artifact.invocation_id == invocation_id
                && s.artifact.stream == stream
                && s.producer == expected_sender
        })
        .map(|s| s.artifact)
}

/// Decompress zstd `data` with the `zstd` binary, returning `None` if zstd is
/// not available or decompression fails. Inverse of [`compress_zstd`].
async fn decompress_zstd(data: &[u8]) -> Option<Vec<u8>> {
    let mut child = Command::new("zstd")
        .arg("-q")
        .arg("-d")
        .arg("-c")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;

    // Feed stdin from a separate task while draining stdout concurrently to
    // avoid a pipe-buffer deadlock on large artifacts (see `compress_zstd`).
    let mut stdin = child.stdin.take()?;
    let input = data.to_vec();
    let writer = tokio::spawn(async move {
        let _ = stdin.write_all(&input).await;
        let _ = stdin.shutdown().await;
    });

    let output = child.wait_with_output().await.ok();
    let _ = writer.await;

    let output = output?;
    output.status.success().then_some(output.stdout)
}

/// Parse and validate an `mxc://` URI recorded on an artifact.
fn parse_mxc(uri: &str) -> Result<OwnedMxcUri, WorkspaceError> {
    let parsed = OwnedMxcUri::from(uri);
    if parsed.is_valid() {
        Ok(parsed)
    } else {
        Err(WorkspaceError::ArtifactRetrievalFailed(format!(
            "{uri:?} is not a valid mxc:// URI"
        )))
    }
}

/// Resolve the [`MediaSource`] for an artifact's uploaded media.
///
/// When the artifact carries [`StreamArtifact::encrypted_file`] (an upload into
/// an encrypted room) the source is [`MediaSource::Encrypted`], so
/// `get_media_content` decrypts the ciphertext blob and verifies its
/// `EncryptedFile.hashes`. Otherwise it is the plaintext
/// [`MediaSource::Plain`] reference. A malformed `encrypted_file` fails closed
/// with [`WorkspaceError::ArtifactRetrievalFailed`].
fn media_source(artifact: &StreamArtifact) -> Result<MediaSource, WorkspaceError> {
    match &artifact.encrypted_file {
        Some(value) => {
            let file: EncryptedFile = serde_json::from_value(value.clone()).map_err(|e| {
                WorkspaceError::ArtifactRetrievalFailed(format!(
                    "artifact for {:?} has malformed encrypted_file key material: {e}",
                    artifact.invocation_id
                ))
            })?;
            Ok(MediaSource::Encrypted(Box::new(file)))
        }
        None => Ok(MediaSource::Plain(parse_mxc(&artifact.mxc_uri)?)),
    }
}

/// Download the raw bytes of an artifact's uploaded media, decrypting when the
/// artifact references encrypted media (see [`media_source`]).
async fn download_media(
    client: &Client,
    artifact: &StreamArtifact,
) -> Result<Vec<u8>, WorkspaceError> {
    let request = MediaRequestParameters {
        source: media_source(artifact)?,
        format: MediaFormat::File,
    };
    client
        .media()
        .get_media_content(&request, false)
        .await
        .map_err(WorkspaceError::from)
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

/// Scan up to `limit` recent timeline events in `room` for stream artifacts,
/// pairing each with the Matrix `sender` that published it (newest first).
///
/// The `sender` is read from the raw event (not from its content), so it is the
/// homeserver-asserted producer used for the sender-pin (issue #304). An event
/// missing a `sender` is skipped — an artifact whose producer cannot be
/// established is never returned.
async fn scan_stream_artifacts(
    room: &Room,
    limit: u32,
) -> Result<Vec<ScannedArtifact>, WorkspaceError> {
    let mut request = MessagesOptions::backward();
    request.limit = matrix_sdk::ruma::UInt::from(limit);
    let messages = room.messages(request).await.map_err(WorkspaceError::from)?;

    let mut artifacts = Vec::new();
    for event in messages.chunk {
        let raw = event.raw();
        let is_artifact =
            raw.get_field::<String>("type").ok().flatten().as_deref() == Some(STREAM_ARTIFACT);
        if !is_artifact {
            continue;
        }
        let producer = raw.get_field::<String>("sender").ok().flatten();
        if let (Ok(Some(artifact)), Some(producer)) =
            (raw.get_field::<StreamArtifact>("content"), producer)
        {
            artifacts.push(ScannedArtifact { artifact, producer });
        }
    }
    Ok(artifacts)
}

/// List recent stream artifacts in a workspace room, newest first.
///
/// Scans up to `limit` recent timeline events and returns the parsed content of
/// every `com.mxagent.stream.artifact.v1` event among them. This is a display
/// lister; [`retrieve_artifact`] applies the sender-pin when actually fetching
/// bytes.
pub async fn list_stream_artifacts(
    client: &Client,
    room: &str,
    limit: u32,
) -> Result<Vec<StreamArtifact>, WorkspaceError> {
    let room = sync_and_get_room(client, room).await?;
    Ok(scan_stream_artifacts(&room, limit)
        .await?
        .into_iter()
        .map(|s| s.artifact)
        .collect())
}

/// Resolve the Matrix user id of the agent expected to have produced the
/// artifact for `options.invocation_id`.
///
/// An explicit [`RetrieveArtifactOptions::expected_sender`] override wins.
/// Otherwise the producer is the invocation's executing agent: read the
/// `com.mxagent.invocation.v1` state, take its `target`, and map that to the
/// agent's `matrix_user_id`. Fails closed (no unverified producer is accepted)
/// when the invocation state or its target agent cannot be resolved (issue #304).
async fn resolve_artifact_producer(
    room: &Room,
    options: &RetrieveArtifactOptions,
) -> Result<String, WorkspaceError> {
    if let Some(sender) = options.expected_sender.as_deref().filter(|s| !s.is_empty()) {
        return Ok(sender.to_string());
    }
    let invocation = crate::invocation::read_invocation_state(room, &options.invocation_id)
        .await?
        .ok_or_else(|| {
            WorkspaceError::ArtifactNotFound(format!(
                "{} (no invocation state to resolve its producer)",
                options.invocation_id
            ))
        })?;
    let agent = crate::agent::read_agent_state(room, &invocation.target)
        .await?
        .ok_or_else(|| {
            WorkspaceError::ArtifactRetrievalFailed(format!(
                "could not resolve the executing agent {:?} for invocation {:?}",
                invocation.target, options.invocation_id
            ))
        })?;
    Ok(agent.matrix_user_id)
}

/// Retrieve, verify, and decompress a single invocation output artifact.
///
/// Locates the artifact for `options.invocation_id` and `options.stream` among
/// the recent timeline events — accepting only one published by the invocation's
/// executing agent (sender-pinned, issue #304) — downloads its uploaded media,
/// verifies the bytes against the artifact's [`sha256`](StreamArtifact::sha256),
/// and decompresses them when the artifact is zstd-compressed. A digest mismatch
/// is reported as [`WorkspaceError::ArtifactIntegrity`]; an unknown
/// invocation/stream, or one only published by an unexpected sender, as
/// [`WorkspaceError::ArtifactNotFound`].
pub async fn retrieve_artifact(
    client: &Client,
    options: &RetrieveArtifactOptions,
) -> Result<RetrievedArtifact, WorkspaceError> {
    let room = sync_and_get_room(client, &options.room).await?;
    let expected_sender = resolve_artifact_producer(&room, options).await?;
    let artifacts = scan_stream_artifacts(&room, options.limit).await?;
    let artifact = select_artifact(
        artifacts,
        &options.invocation_id,
        options.stream,
        &expected_sender,
    )
    .ok_or_else(|| {
        WorkspaceError::ArtifactNotFound(format!(
            "{} ({})",
            options.invocation_id,
            stream_stem(options.stream)
        ))
    })?;

    if artifact.mxc_uri.is_empty() {
        return Err(WorkspaceError::ArtifactRetrievalFailed(format!(
            "artifact for {:?} has no mxc:// reference to download",
            options.invocation_id
        )));
    }
    let media = download_media(client, &artifact).await?;
    let data = verify_and_decompress(&artifact, media).await?;
    Ok(RetrievedArtifact { artifact, data })
}

/// Retrieve and verify an invocation artifact, restoring the authenticated
/// client from `session`.
pub async fn retrieve_artifact_for_session(
    session: &StoredSession,
    options: &RetrieveArtifactOptions,
) -> Result<RetrievedArtifact, WorkspaceError> {
    let client = restore_client(session).await?;
    retrieve_artifact(&client, options).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn switches_only_above_the_budget() {
        let config = ArtifactConfig {
            max_timeline_output_bytes: 100,
            ..ArtifactConfig::new()
        };
        assert!(!config.should_switch(100));
        assert!(config.should_switch(101));
    }

    #[tokio::test]
    async fn prepared_artifact_uploads_the_full_log() {
        // Acceptance: a high-output command uploads the *full* log as an
        // artifact. Without compression the uploaded bytes are the whole log.
        let data = vec![b'x'; 64 * 1024];
        let config = ArtifactConfig {
            compress: false,
            ..ArtifactConfig::new()
        };
        let prepared = prepare_artifact("inv_1", StreamKind::Stdout, &data, &config).await;
        assert_eq!(prepared.upload_bytes(), &data[..]);
        assert_eq!(prepared.size_bytes, data.len() as u64);
        assert_eq!(prepared.sha256, sha256_b64(&data));
        assert_eq!(prepared.name, "stdout.log");
        assert_eq!(prepared.mime_type, "text/plain");
        assert!(!prepared.compressed);
    }

    #[tokio::test]
    async fn tail_preview_shows_the_end_of_the_output() {
        // Acceptance: the terminal shows a useful preview — the *tail* of the
        // output, bounded to the configured size.
        let mut data = b"START".to_vec();
        data.extend(std::iter::repeat_n(b'.', 10_000));
        data.extend_from_slice(b"THE-END");
        let config = ArtifactConfig {
            compress: false,
            tail_preview_bytes: 16,
            ..ArtifactConfig::new()
        };
        let prepared = prepare_artifact("inv_1", StreamKind::Stdout, &data, &config).await;
        assert!(prepared.tail_preview.len() <= 16);
        assert!(prepared.tail_preview.ends_with("THE-END"));
        assert!(!prepared.tail_preview.contains("START"));
    }

    #[tokio::test]
    async fn tail_preview_handles_short_output() {
        let data = b"tiny".to_vec();
        let config = ArtifactConfig {
            compress: false,
            tail_preview_bytes: 4096,
            ..ArtifactConfig::new()
        };
        let prepared = prepare_artifact("inv_1", StreamKind::Stderr, &data, &config).await;
        assert_eq!(prepared.tail_preview, "tiny");
        assert_eq!(prepared.name, "stderr.log");
    }

    #[tokio::test]
    async fn into_event_carries_metadata_and_reference() {
        let data = b"log body".to_vec();
        let config = ArtifactConfig {
            compress: false,
            ..ArtifactConfig::new()
        };
        let prepared = prepare_artifact("inv_42", StreamKind::Stdout, &data, &config).await;
        let event = prepared.into_event("mxc://server/abc");
        assert_eq!(event.invocation_id, "inv_42");
        assert_eq!(event.stream, StreamKind::Stdout);
        assert_eq!(event.mxc_uri, "mxc://server/abc");
        assert_eq!(event.size_bytes, data.len() as u64);
        assert_eq!(event.sha256, sha256_b64(&data));
        assert_eq!(event.tail_preview, "log body");
    }

    #[tokio::test]
    async fn into_event_encrypted_carries_key_material_and_ciphertext_uri() {
        // The encrypted finalizer records the ciphertext mxc_uri and the opaque
        // EncryptedFile key material; the plain finalizer records neither.
        let data = b"log body".to_vec();
        let config = ArtifactConfig {
            compress: false,
            ..ArtifactConfig::new()
        };
        let prepared = prepare_artifact("inv_enc", StreamKind::Stdout, &data, &config).await;
        let key_material = serde_json::json!({ "url": "mxc://s/cipher", "iv": "base64" });
        let event = prepared.into_event_encrypted("mxc://s/cipher", key_material.clone());
        assert_eq!(event.mxc_uri, "mxc://s/cipher");
        assert_eq!(event.encrypted_file.as_ref(), Some(&key_material));

        let plain = prepare_artifact("inv_plain", StreamKind::Stdout, &data, &config).await;
        let plain_event = plain.into_event("mxc://s/plain");
        assert!(plain_event.encrypted_file.is_none());
    }

    /// A valid ruma `EncryptedFile` serialized to JSON, as `upload_encrypted_file`
    /// would produce it (the protocol crate stores this opaquely).
    fn sample_encrypted_file_value(url: &str) -> serde_json::Value {
        use matrix_sdk::ruma::events::room::{
            EncryptedFile, EncryptedFileHashes, EncryptedFileInfo, V2EncryptedFileInfo,
        };
        use matrix_sdk::ruma::OwnedMxcUri;
        let file = EncryptedFile::new(
            OwnedMxcUri::from(url),
            EncryptedFileInfo::V2(V2EncryptedFileInfo::encode([7u8; 32], [3u8; 16])),
            EncryptedFileHashes::with_sha256([9u8; 32]),
        );
        serde_json::to_value(&file).expect("EncryptedFile serializes to a JSON object")
    }

    #[test]
    fn media_source_selects_encrypted_vs_plain() {
        // A plaintext artifact downloads via MediaSource::Plain.
        let plain = StreamArtifact {
            invocation_id: "inv".into(),
            stream: StreamKind::Stdout,
            name: "stdout.log".into(),
            mime_type: "text/plain".into(),
            size_bytes: 0,
            sha256: String::new(),
            mxc_uri: "mxc://s/plain".into(),
            tail_preview: String::new(),
            encrypted_file: None,
            signature: None,
            extra: Default::default(),
        };
        assert!(matches!(
            media_source(&plain).expect("plain source"),
            MediaSource::Plain(_)
        ));

        // A well-formed EncryptedFile selects MediaSource::Encrypted.
        let encrypted = StreamArtifact {
            mxc_uri: "mxc://example.org/ciphertext".into(),
            encrypted_file: Some(sample_encrypted_file_value("mxc://example.org/ciphertext")),
            ..plain.clone()
        };
        assert!(matches!(
            media_source(&encrypted).expect("encrypted source"),
            MediaSource::Encrypted(_)
        ));

        // Malformed key material fails closed rather than silently downloading
        // the (ciphertext) blob as plaintext.
        let malformed = StreamArtifact {
            encrypted_file: Some(serde_json::json!({ "not": "an EncryptedFile" })),
            ..plain
        };
        assert!(matches!(
            media_source(&malformed),
            Err(WorkspaceError::ArtifactRetrievalFailed(_))
        ));
    }

    #[tokio::test]
    async fn compression_reflects_zstd_availability() {
        // "Compress logs with zstd where available." When zstd is present the
        // artifact is compressed and named accordingly; otherwise it falls back
        // to an uncompressed upload. Either way the tail preview is intact.
        let data = vec![b'a'; 32 * 1024];
        let prepared =
            prepare_artifact("inv_1", StreamKind::Stdout, &data, &ArtifactConfig::new()).await;

        if zstd_available().await {
            assert!(
                prepared.compressed,
                "zstd present: artifact should compress"
            );
            assert_eq!(prepared.name, "stdout.log.zst");
            assert_eq!(prepared.mime_type, "text/plain+zstd");
            // Highly compressible input must shrink.
            assert!(prepared.size_bytes < data.len() as u64);
        } else {
            assert!(!prepared.compressed, "no zstd: artifact stays uncompressed");
            assert_eq!(prepared.name, "stdout.log");
            assert_eq!(prepared.mime_type, "text/plain");
            assert_eq!(prepared.size_bytes, data.len() as u64);
        }
        // The digest always covers the uploaded bytes.
        assert_eq!(prepared.sha256, sha256_b64(prepared.upload_bytes()));
    }

    /// Build the artifact event a prepared upload would produce, pairing it with
    /// the uploaded (possibly-compressed) media for retrieval-side tests.
    async fn prepared_event_and_media(
        data: &[u8],
        config: &ArtifactConfig,
    ) -> (StreamArtifact, Vec<u8>) {
        let prepared = prepare_artifact("inv_ret", StreamKind::Stdout, data, config).await;
        let media = prepared.upload_bytes().to_vec();
        (prepared.into_event("mxc://server/artifact"), media)
    }

    #[test]
    fn is_compressed_recognises_zstd_markers() {
        let prepared = StreamArtifact {
            invocation_id: "inv".into(),
            stream: StreamKind::Stdout,
            name: "stdout.log.zst".into(),
            mime_type: "text/plain+zstd".into(),
            size_bytes: 0,
            sha256: String::new(),
            mxc_uri: "mxc://s/a".into(),
            tail_preview: String::new(),
            encrypted_file: None,
            signature: None,
            extra: Default::default(),
        };
        assert!(is_compressed(&prepared));

        let plain = StreamArtifact {
            name: "stdout.log".into(),
            mime_type: "text/plain".into(),
            ..prepared.clone()
        };
        assert!(!is_compressed(&plain));
    }

    const PRODUCER: &str = "@exec:hs";

    fn scanned(inv: &str, stream: StreamKind, producer: &str) -> ScannedArtifact {
        ScannedArtifact {
            artifact: StreamArtifact {
                invocation_id: inv.into(),
                stream,
                name: "x.log".into(),
                mime_type: "text/plain".into(),
                size_bytes: 0,
                sha256: String::new(),
                mxc_uri: "mxc://s/a".into(),
                tail_preview: String::new(),
                encrypted_file: None,
                signature: None,
                extra: Default::default(),
            },
            producer: producer.into(),
        }
    }

    #[test]
    fn select_artifact_matches_invocation_stream_and_sender() {
        let artifacts = || {
            vec![
                scanned("inv_1", StreamKind::Stdout, PRODUCER),
                scanned("inv_1", StreamKind::Stderr, PRODUCER),
                scanned("inv_2", StreamKind::Stdout, PRODUCER),
            ]
        };
        // stdout/stderr of the same invocation are told apart by stream.
        let stderr = select_artifact(artifacts(), "inv_1", StreamKind::Stderr, PRODUCER)
            .expect("inv_1 stderr exists");
        assert_eq!(stderr.invocation_id, "inv_1");
        assert_eq!(stderr.stream, StreamKind::Stderr);

        assert!(select_artifact(artifacts(), "inv_1", StreamKind::Pty, PRODUCER).is_none());
    }

    #[test]
    fn select_artifact_rejects_a_shadow_from_an_unexpected_sender() {
        // A room member republishing the same invocation+stream artifact (with a
        // self-consistent digest) must not be able to shadow the legitimate one:
        // pinning the producer means only the executing agent's artifact matches
        // (issue #304).
        let artifacts = vec![
            // The forged artifact arrives first (newest), but from a foreign sender.
            scanned("inv_1", StreamKind::Stdout, "@member:hs"),
            scanned("inv_1", StreamKind::Stdout, PRODUCER),
        ];
        let picked = select_artifact(artifacts, "inv_1", StreamKind::Stdout, PRODUCER)
            .expect("the legitimate producer's artifact is selected");
        // The pinned producer's artifact is chosen, not the foreign shadow.
        let only_foreign = vec![scanned("inv_1", StreamKind::Stdout, "@member:hs")];
        assert!(
            select_artifact(only_foreign, "inv_1", StreamKind::Stdout, PRODUCER).is_none(),
            "an artifact only published by an unexpected sender must be rejected"
        );
        assert_eq!(picked.invocation_id, "inv_1");
    }

    #[tokio::test]
    async fn retrieve_round_trips_uncompressed_output() {
        // Acceptance: a user can retrieve the stdout artifact and get back the
        // exact original bytes.
        let data = vec![b'o'; 8 * 1024];
        let config = ArtifactConfig {
            compress: false,
            ..ArtifactConfig::new()
        };
        let (artifact, media) = prepared_event_and_media(&data, &config).await;
        let out = verify_and_decompress(&artifact, media)
            .await
            .expect("verification succeeds for untampered media");
        assert_eq!(out, data);
    }

    #[tokio::test]
    async fn retrieve_round_trips_compressed_output() {
        // Acceptance: compression is transparent — a compressed artifact comes
        // back decompressed and byte-identical to the original output.
        let data = vec![b'z'; 64 * 1024];
        let (artifact, media) = prepared_event_and_media(&data, &ArtifactConfig::new()).await;
        if !is_compressed(&artifact) {
            // No zstd binary on this host: prepare_artifact fell back to an
            // uncompressed upload, already covered by the uncompressed test.
            return;
        }
        let out = verify_and_decompress(&artifact, media)
            .await
            .expect("compressed artifact decompresses after verification");
        assert_eq!(out, data);
    }

    #[tokio::test]
    async fn corrupt_artifact_fails_verification() {
        // Acceptance: a corrupt/tampered artifact must fail verification rather
        // than be returned (or fed to the decompressor).
        let data = b"the original output".to_vec();
        let config = ArtifactConfig {
            compress: false,
            ..ArtifactConfig::new()
        };
        let (artifact, mut media) = prepared_event_and_media(&data, &config).await;
        media[0] ^= 0xff; // flip a byte: the download is now corrupt

        let err = verify_and_decompress(&artifact, media)
            .await
            .expect_err("a digest mismatch must be detected");
        match err {
            WorkspaceError::ArtifactIntegrity {
                invocation_id,
                stream,
                expected,
                actual,
            } => {
                assert_eq!(invocation_id, "inv_ret");
                assert_eq!(stream, "stdout");
                assert_eq!(expected, artifact.sha256);
                assert_ne!(expected, actual);
            }
            other => panic!("expected ArtifactIntegrity, got {other:?}"),
        }
    }

    // ── Issue #308: E2EE media confidentiality tests ───────────────────────────

    #[test]
    fn artifact_config_default_matches_new() {
        // `Default::default()` and `ArtifactConfig::new()` must produce
        // identical tuning so callers using either API get the same switching
        // threshold, tail size, and compression setting.
        let d = ArtifactConfig::default();
        let n = ArtifactConfig::new();
        assert_eq!(d.max_timeline_output_bytes, n.max_timeline_output_bytes);
        assert_eq!(d.tail_preview_bytes, n.tail_preview_bytes);
        assert_eq!(d.compress, n.compress);
    }

    #[test]
    fn stream_stems_are_correct_for_all_kinds() {
        // The stem determines the file name uploaded to Matrix media. A wrong
        // stem makes an artifact indistinguishable from the wrong stream (e.g.
        // `stdin.log` for stdout output).
        assert_eq!(stream_stem(StreamKind::Stdin), "stdin");
        assert_eq!(stream_stem(StreamKind::Stdout), "stdout");
        assert_eq!(stream_stem(StreamKind::Stderr), "stderr");
        assert_eq!(stream_stem(StreamKind::Pty), "pty");
        assert_eq!(stream_stem(StreamKind::Control), "control");
    }

    #[test]
    fn into_event_plaintext_path_leaves_encrypted_file_absent() {
        // `into_event` (plaintext path) must never set `encrypted_file`.
        // Presence of that field is the signal that triggers the decrypt path
        // on download (issue #308); a spurious field would break retrieval.
        let data = b"log output".to_vec();
        let prepared = PreparedArtifact {
            invocation_id: "inv_plain".into(),
            stream: StreamKind::Stdout,
            name: "stdout.log".into(),
            mime_type: "text/plain".into(),
            size_bytes: data.len() as u64,
            sha256: sha256_b64(&data),
            tail_preview: "log output".into(),
            compressed: false,
            bytes: data,
        };
        let event = prepared.into_event("mxc://s/plain");
        assert!(
            event.encrypted_file.is_none(),
            "into_event (plaintext path) must not set encrypted_file"
        );
    }

    #[test]
    fn parse_mxc_fails_for_non_mxc_uri_on_plain_artifact() {
        // `media_source` calls `parse_mxc` on the `mxc_uri` of a plain artifact.
        // A non-mxc URI must fail closed rather than silently constructing an
        // unusable `MediaSource::Plain` that downloads ciphertext as if plain
        // (issue #308).
        let bad_uri = StreamArtifact {
            invocation_id: "inv_1".into(),
            stream: StreamKind::Stdout,
            name: "stdout.log".into(),
            mime_type: "text/plain".into(),
            size_bytes: 0,
            sha256: String::new(),
            mxc_uri: "https://example.org/not-mxc".into(),
            tail_preview: String::new(),
            encrypted_file: None,
            signature: None,
            extra: Default::default(),
        };
        assert!(
            matches!(
                media_source(&bad_uri),
                Err(WorkspaceError::ArtifactRetrievalFailed(_))
            ),
            "a non-mxc URI on a plain artifact must fail closed"
        );
    }

    #[test]
    fn encrypted_artifact_event_carries_distinct_fields() {
        // An artifact from an encrypted room carries both the ciphertext
        // `mxc_uri` AND the opaque `EncryptedFile` key material. The download
        // path selects decryption based on the presence of `encrypted_file`,
        // not on the URI itself, so both fields must be correctly set.
        let data = b"big log".to_vec();
        let prepared = PreparedArtifact {
            invocation_id: "inv_enc".into(),
            stream: StreamKind::Stdout,
            name: "stdout.log".into(),
            mime_type: "text/plain".into(),
            size_bytes: data.len() as u64,
            sha256: sha256_b64(&data),
            tail_preview: "big log".into(),
            compressed: false,
            bytes: data,
        };
        // Use a well-formed EncryptedFile value (real key/IV lengths so ruma
        // validation passes on the retrieval path).
        let key_material = sample_encrypted_file_value("mxc://s/ciphertext");
        let event = prepared.into_event_encrypted("mxc://s/ciphertext", key_material.clone());
        // The ciphertext MXC URI is carried for retrieval.
        assert_eq!(event.mxc_uri, "mxc://s/ciphertext");
        // The key material must be present so the downloader decrypts it.
        assert_eq!(
            event.encrypted_file.as_ref(),
            Some(&key_material),
            "encrypted artifact must carry EncryptedFile key material"
        );
        // The media_source resolves to the Encrypted variant, confirming the
        // key material is parseable and of the correct length.
        assert!(matches!(
            media_source(&event).expect("valid encrypted_file source"),
            MediaSource::Encrypted(_)
        ));
    }
}
