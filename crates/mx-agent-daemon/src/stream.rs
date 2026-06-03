//! Asynchronous stdout/stderr capture and chunking (architecture §7.3, §8.1).
//!
//! Once an [`ExecRequest`][crate::exec] is authorized and the process runner
//! has spawned a child (see [`crate::runner`]), the daemon must turn the
//! child's output into a stream of `com.mxagent.stream.chunk.v1` events that
//! can be federated over Matrix. This module is that capture stage.
//!
//! The two output streams are read **concurrently** so that a process which is
//! noisy on one channel cannot starve the other: [`capture_child_output`]
//! drives one reader for stdout and one for stderr at the same time, each
//! tagging its chunks with the appropriate [`StreamKind`] and keeping its own
//! monotonic sequence counter. Both readers feed a single sink, so a consumer
//! sees an interleaved-but-per-stream-ordered sequence of chunks.
//!
//! ## Chunking
//!
//! Per architecture §8.1, a buffer is flushed into a chunk whenever any of
//! these conditions is met:
//!
//! - the buffer reaches [`StreamCaptureConfig::max_chunk_bytes`];
//! - a newline is observed and [`StreamCaptureConfig::flush_on_newline`] is set
//!   (interactive mode);
//! - the [`StreamCaptureConfig::flush_interval`] elapses with buffered data;
//! - the stream reaches EOF.
//!
//! Both the chunk size and the flush interval are configurable, with batch and
//! interactive presets ([`StreamCaptureConfig::batch`] and
//! [`StreamCaptureConfig::interactive`]).
//!
//! ## Encoding
//!
//! Each chunk is emitted as UTF-8 when its bytes form valid UTF-8, and as
//! base64 otherwise (architecture §7.3). The capture stage never blocks on the
//! sink failing: if the consumer has gone away, capture stops early.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::sync::mpsc;
use tokio::time::timeout;

use mx_agent_protocol::schema::{StreamChunk, StreamKind};

/// Default maximum chunk size in bytes (architecture §8.1: 16 KiB).
pub const DEFAULT_MAX_CHUNK_BYTES: usize = 16 * 1024;

/// Default flush interval for non-interactive (batch) streams (§8.1: 250 ms).
pub const DEFAULT_BATCH_FLUSH_INTERVAL: Duration = Duration::from_millis(250);

/// Default flush interval for interactive streams (§8.1: 50 ms).
pub const DEFAULT_INTERACTIVE_FLUSH_INTERVAL: Duration = Duration::from_millis(50);

/// How output is chunked into [`StreamChunk`] events.
///
/// Both the chunk size and the flush interval are configurable so callers can
/// trade latency for event volume. Use [`StreamCaptureConfig::batch`] for
/// non-interactive commands and [`StreamCaptureConfig::interactive`] for
/// commands whose output should appear with low latency, line by line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamCaptureConfig {
    /// Flush the buffer once it reaches this many bytes.
    pub max_chunk_bytes: usize,
    /// Flush any buffered data once this much time elapses without a flush.
    pub flush_interval: Duration,
    /// Flush at newline boundaries (interactive mode).
    pub flush_on_newline: bool,
}

impl StreamCaptureConfig {
    /// Non-interactive defaults: 16 KiB chunks, 250 ms flush, no newline flush.
    pub const fn batch() -> Self {
        Self {
            max_chunk_bytes: DEFAULT_MAX_CHUNK_BYTES,
            flush_interval: DEFAULT_BATCH_FLUSH_INTERVAL,
            flush_on_newline: false,
        }
    }

    /// Interactive defaults: 16 KiB chunks, 50 ms flush, flush on newline.
    pub const fn interactive() -> Self {
        Self {
            max_chunk_bytes: DEFAULT_MAX_CHUNK_BYTES,
            flush_interval: DEFAULT_INTERACTIVE_FLUSH_INTERVAL,
            flush_on_newline: true,
        }
    }
}

impl Default for StreamCaptureConfig {
    fn default() -> Self {
        Self::batch()
    }
}

/// Capture a child's stdout and stderr **concurrently** into `sink`.
///
/// Spawns a reader for each stream so neither can starve the other, tags each
/// chunk with [`StreamKind::Stdout`] or [`StreamKind::Stderr`], and keeps an
/// independent per-stream sequence counter. Both readers feed the same `sink`,
/// so a consumer observes chunks interleaved across streams but strictly
/// ordered within each stream. Each stream is terminated by a final EOF chunk.
///
/// Returns once both streams have reached EOF (or the sink was dropped).
pub async fn capture_child_output<O, E>(
    stdout: O,
    stderr: E,
    invocation_id: impl Into<String>,
    config: StreamCaptureConfig,
    sink: mpsc::Sender<StreamChunk>,
) where
    O: AsyncRead + Unpin + Send,
    E: AsyncRead + Unpin + Send,
{
    let invocation_id = invocation_id.into();
    let out = capture_stream(
        stdout,
        invocation_id.clone(),
        StreamKind::Stdout,
        config,
        sink.clone(),
    );
    let err = capture_stream(stderr, invocation_id, StreamKind::Stderr, config, sink);
    // Read both concurrently on the current task; `join` polls both futures.
    tokio::join!(out, err);
}

/// Capture a single stream, chunking it into [`StreamChunk`] events.
///
/// Reads from `reader` until EOF, flushing the buffer into `sink` whenever a
/// flush condition in [`StreamCaptureConfig`] is met, then sends a final EOF
/// chunk. Stops early (without error) if the sink is closed by the consumer.
pub async fn capture_stream<R>(
    reader: R,
    invocation_id: impl Into<String>,
    stream: StreamKind,
    config: StreamCaptureConfig,
    sink: mpsc::Sender<StreamChunk>,
) where
    R: AsyncRead + Unpin,
{
    let invocation_id = invocation_id.into();
    let mut reader = reader;
    let mut buf: Vec<u8> = Vec::with_capacity(config.max_chunk_bytes.min(8192));
    let mut read_buf = [0u8; 8192];
    let mut seq: u64 = 0;

    loop {
        match timeout(config.flush_interval, reader.read(&mut read_buf)).await {
            // Flush interval elapsed: flush whatever is buffered.
            Err(_elapsed) => {
                if !buf.is_empty()
                    && !emit_chunk(&sink, &invocation_id, stream, &mut seq, &buf, false).await
                {
                    return;
                }
                buf.clear();
            }
            // EOF: flush any remainder, then send the EOF marker.
            Ok(Ok(0)) => {
                if !buf.is_empty()
                    && !emit_chunk(&sink, &invocation_id, stream, &mut seq, &buf, false).await
                {
                    return;
                }
                let _ = emit_chunk(&sink, &invocation_id, stream, &mut seq, &[], true).await;
                return;
            }
            // Data: append and flush on size / newline as configured.
            Ok(Ok(n)) => {
                buf.extend_from_slice(&read_buf[..n]);

                // Flush whole chunks while the buffer is at or over the cap.
                while buf.len() >= config.max_chunk_bytes {
                    let chunk: Vec<u8> = buf.drain(..config.max_chunk_bytes).collect();
                    if !emit_chunk(&sink, &invocation_id, stream, &mut seq, &chunk, false).await {
                        return;
                    }
                }

                // In interactive mode, flush complete lines as they arrive.
                if config.flush_on_newline {
                    if let Some(last_nl) = buf.iter().rposition(|&b| b == b'\n') {
                        let line: Vec<u8> = buf.drain(..=last_nl).collect();
                        if !emit_chunk(&sink, &invocation_id, stream, &mut seq, &line, false).await
                        {
                            return;
                        }
                    }
                }
            }
            Ok(Err(_io_err)) => {
                // Treat a read error as end-of-stream: flush and mark EOF.
                if !buf.is_empty() {
                    let _ = emit_chunk(&sink, &invocation_id, stream, &mut seq, &buf, false).await;
                }
                let _ = emit_chunk(&sink, &invocation_id, stream, &mut seq, &[], true).await;
                return;
            }
        }
    }
}

/// Build a [`StreamChunk`] for `data` and send it on `sink`.
///
/// Returns `true` if the chunk was delivered and `false` if the sink is closed
/// (the consumer went away), letting the caller stop early. `seq` is advanced
/// on every emitted chunk so sequence numbers stay monotonic per stream.
async fn emit_chunk(
    sink: &mpsc::Sender<StreamChunk>,
    invocation_id: &str,
    stream: StreamKind,
    seq: &mut u64,
    data: &[u8],
    eof: bool,
) -> bool {
    let (encoding, payload) = encode_chunk(data);
    let chunk = StreamChunk {
        invocation_id: invocation_id.to_string(),
        stream,
        seq: *seq,
        encoding: encoding.to_string(),
        data: payload,
        eof,
        compressed: false,
        sha256: None,
        timestamp: now_rfc3339_millis(),
        extra: Default::default(),
    };
    *seq += 1;
    sink.send(chunk).await.is_ok()
}

/// Encode chunk bytes as UTF-8 text when valid, otherwise base64.
fn encode_chunk(data: &[u8]) -> (&'static str, String) {
    match std::str::from_utf8(data) {
        Ok(text) => ("utf-8", text.to_string()),
        Err(_) => {
            use base64::Engine as _;
            (
                "base64",
                base64::engine::general_purpose::STANDARD.encode(data),
            )
        }
    }
}

/// Format the current time as an RFC 3339 UTC timestamp with millisecond
/// precision (`YYYY-MM-DDTHH:MM:SS.mmmZ`), matching the stream chunk schema.
fn now_rfc3339_millis() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    let millis = now.subsec_millis();

    let days = (secs / 86_400) as i64;
    let tod = (secs % 86_400) as i64;
    let (hour, minute, second) = (tod / 3600, (tod % 3600) / 60, tod % 60);

    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { y + 1 } else { y };

    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Drain every chunk from a capture into a Vec.
    async fn collect(mut rx: mpsc::Receiver<StreamChunk>) -> Vec<StreamChunk> {
        let mut chunks = Vec::new();
        while let Some(chunk) = rx.recv().await {
            chunks.push(chunk);
        }
        chunks
    }

    #[tokio::test]
    async fn small_output_yields_one_chunk_plus_eof() {
        let (tx, rx) = mpsc::channel(64);
        let data = b"hello world\n".to_vec();
        capture_stream(
            &data[..],
            "inv_1",
            StreamKind::Stdout,
            StreamCaptureConfig::batch(),
            tx,
        )
        .await;
        let chunks = collect(rx).await;
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].seq, 0);
        assert_eq!(chunks[0].encoding, "utf-8");
        assert_eq!(chunks[0].data, "hello world\n");
        assert!(!chunks[0].eof);
        // EOF marker last.
        assert!(chunks[1].eof);
        assert_eq!(chunks[1].seq, 1);
        assert_eq!(chunks[1].data, "");
    }

    #[tokio::test]
    async fn empty_stream_yields_only_eof() {
        let (tx, rx) = mpsc::channel(64);
        let data: Vec<u8> = Vec::new();
        capture_stream(
            &data[..],
            "inv_1",
            StreamKind::Stderr,
            StreamCaptureConfig::batch(),
            tx,
        )
        .await;
        let chunks = collect(rx).await;
        assert_eq!(chunks.len(), 1);
        assert!(chunks[0].eof);
        assert_eq!(chunks[0].stream, StreamKind::Stderr);
    }

    #[tokio::test]
    async fn output_is_chunked_by_size() {
        // Acceptance: chunk size is configurable.
        let (tx, rx) = mpsc::channel(64);
        let data = [b'x'; 10];
        let config = StreamCaptureConfig {
            max_chunk_bytes: 4,
            ..StreamCaptureConfig::batch()
        };
        capture_stream(&data[..], "inv_1", StreamKind::Stdout, config, tx).await;
        let chunks = collect(rx).await;
        // 10 bytes / 4 => 4, 4, 2, then EOF.
        let lens: Vec<usize> = chunks.iter().map(|c| c.data.len()).collect();
        assert_eq!(lens, vec![4, 4, 2, 0]);
        let seqs: Vec<u64> = chunks.iter().map(|c| c.seq).collect();
        assert_eq!(seqs, vec![0, 1, 2, 3]);
        assert!(chunks.last().unwrap().eof);
    }

    #[tokio::test]
    async fn non_utf8_data_is_base64_encoded() {
        let (tx, rx) = mpsc::channel(64);
        let data = vec![0xff, 0xfe, 0x00, 0x01];
        capture_stream(
            &data[..],
            "inv_1",
            StreamKind::Stdout,
            StreamCaptureConfig::batch(),
            tx,
        )
        .await;
        let chunks = collect(rx).await;
        assert_eq!(chunks[0].encoding, "base64");
        use base64::Engine as _;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&chunks[0].data)
            .unwrap();
        assert_eq!(decoded, data);
    }

    #[tokio::test]
    async fn stdout_and_stderr_are_captured_separately() {
        // Acceptance: stdout and stderr are captured separately.
        let (tx, rx) = mpsc::channel(64);
        let out = b"on stdout\n".to_vec();
        let err = b"on stderr\n".to_vec();
        capture_child_output(
            &out[..],
            &err[..],
            "inv_1",
            StreamCaptureConfig::batch(),
            tx,
        )
        .await;
        let chunks = collect(rx).await;

        let stdout: Vec<&StreamChunk> = chunks
            .iter()
            .filter(|c| c.stream == StreamKind::Stdout)
            .collect();
        let stderr: Vec<&StreamChunk> = chunks
            .iter()
            .filter(|c| c.stream == StreamKind::Stderr)
            .collect();

        // Each stream: one data chunk + one EOF marker, with its own seq space.
        assert_eq!(stdout.len(), 2);
        assert_eq!(stderr.len(), 2);
        assert_eq!(stdout[0].data, "on stdout\n");
        assert_eq!(stderr[0].data, "on stderr\n");
        assert_eq!(stdout[0].seq, 0);
        assert_eq!(stderr[0].seq, 0);
        assert!(stdout[1].eof);
        assert!(stderr[1].eof);
    }

    #[tokio::test]
    async fn interactive_mode_flushes_on_newline() {
        let (tx, rx) = mpsc::channel(64);
        let data = b"line one\nline two\npartial".to_vec();
        capture_stream(
            &data[..],
            "inv_1",
            StreamKind::Stdout,
            StreamCaptureConfig::interactive(),
            tx,
        )
        .await;
        let chunks = collect(rx).await;
        // First flush covers both complete lines (last newline boundary), then
        // the trailing partial line on EOF, then the EOF marker.
        assert_eq!(chunks[0].data, "line one\nline two\n");
        assert_eq!(chunks[1].data, "partial");
        assert!(chunks[2].eof);
    }

    #[test]
    fn presets_differ_in_interval_and_newline_behaviour() {
        // Acceptance: chunk size / flush interval are configurable.
        let batch = StreamCaptureConfig::batch();
        let interactive = StreamCaptureConfig::interactive();
        assert_eq!(batch.flush_interval, DEFAULT_BATCH_FLUSH_INTERVAL);
        assert!(!batch.flush_on_newline);
        assert_eq!(
            interactive.flush_interval,
            DEFAULT_INTERACTIVE_FLUSH_INTERVAL
        );
        assert!(interactive.flush_on_newline);
        assert_eq!(batch.max_chunk_bytes, DEFAULT_MAX_CHUNK_BYTES);
    }

    #[test]
    fn timestamp_has_millisecond_precision() {
        let ts = now_rfc3339_millis();
        // ...T..:..:...mmmZ
        assert!(ts.ends_with('Z'), "got: {ts}");
        assert_eq!(ts.len(), "2026-06-02T12:00:01.123Z".len(), "got: {ts}");
        assert!(ts.contains('.'), "got: {ts}");
    }
}
