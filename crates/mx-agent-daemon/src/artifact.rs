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
use matrix_sdk::Client;
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use mx_agent_protocol::schema::{StreamArtifact, StreamKind};

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

    /// Finalize into a [`StreamArtifact`] event referencing `mxc_uri`.
    ///
    /// Pass an empty `mxc_uri` when no upload was performed (e.g. the local
    /// `exec` loopback, which has no homeserver); consumers render the tail
    /// preview regardless.
    pub fn into_event(self, mxc_uri: impl Into<String>) -> StreamArtifact {
        StreamArtifact {
            invocation_id: self.invocation_id,
            stream: self.stream,
            name: self.name,
            mime_type: self.mime_type,
            size_bytes: self.size_bytes,
            sha256: self.sha256,
            mxc_uri: mxc_uri.into(),
            tail_preview: self.tail_preview,
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
pub async fn upload_artifact(
    client: &Client,
    prepared: PreparedArtifact,
) -> Result<StreamArtifact, ArtifactError> {
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
        data.extend(std::iter::repeat(b'.').take(10_000));
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
}
