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
//!
//! ## Rate limiting and output caps
//!
//! Per architecture §8.1 and §8.3 the daemon must protect both Matrix and the
//! local process from a command that produces enormous or rapid output. Two
//! per-invocation limits, configured through [`OutputCaps`], are enforced here:
//!
//! - `max_output_bytes` bounds the *total* number of output bytes forwarded
//!   across all of an invocation's streams. Once the budget is exhausted the
//!   remaining output is dropped and the invocation is flagged as **truncated**
//!   so the terminal `exec.finished` event can say so explicitly.
//! - `max_events_per_second` bounds how fast chunk events are emitted, using a
//!   token bucket shared across the invocation's streams. This keeps a noisy
//!   command from flooding the Matrix timeline (and the homeserver's own rate
//!   limits).
//!
//! Both limits are shared across stdout and stderr through a [`CaptureLimiter`]
//! so the cap applies per invocation, not per stream. The EOF marker for each
//! stream is always delivered (it carries no payload and terminates the
//! stream), so truncation never leaves a consumer waiting for an end-of-stream
//! that never arrives.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::sync::{mpsc, Mutex};
use tokio::time::{timeout, Instant};

use mx_agent_protocol::schema::{StreamChunk, StreamKind};

/// Default maximum chunk size in bytes (architecture §8.1: 16 KiB).
pub const DEFAULT_MAX_CHUNK_BYTES: usize = 16 * 1024;

/// Default flush interval for non-interactive (batch) streams (§8.1: 250 ms).
pub const DEFAULT_BATCH_FLUSH_INTERVAL: Duration = Duration::from_millis(250);

/// Default flush interval for interactive streams (§8.1: 50 ms).
pub const DEFAULT_INTERACTIVE_FLUSH_INTERVAL: Duration = Duration::from_millis(50);

/// Per-invocation output caps (architecture §8.1, §8.3).
///
/// These limits are shared across all of an invocation's streams and enforced
/// by a [`CaptureLimiter`]. Both fields default to `None` (unlimited); a daemon
/// fills them in from policy before capturing a command's output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct OutputCaps {
    /// Maximum total output bytes forwarded across all streams. Output beyond
    /// this is dropped and the invocation flagged truncated. `None` is
    /// unlimited.
    pub max_output_bytes: Option<u64>,
    /// Maximum chunk events emitted per second across all streams, smoothed by
    /// a token bucket. `None` is unlimited.
    pub max_events_per_second: Option<u32>,
}

impl OutputCaps {
    /// No caps: unlimited output bytes and event rate.
    pub const fn unlimited() -> Self {
        Self {
            max_output_bytes: None,
            max_events_per_second: None,
        }
    }
}

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
    /// Per-invocation output byte cap and event-rate limit.
    pub caps: OutputCaps,
}

impl StreamCaptureConfig {
    /// Non-interactive defaults: 16 KiB chunks, 250 ms flush, no newline flush.
    pub const fn batch() -> Self {
        Self {
            max_chunk_bytes: DEFAULT_MAX_CHUNK_BYTES,
            flush_interval: DEFAULT_BATCH_FLUSH_INTERVAL,
            flush_on_newline: false,
            caps: OutputCaps::unlimited(),
        }
    }

    /// Interactive defaults: 16 KiB chunks, 50 ms flush, flush on newline.
    pub const fn interactive() -> Self {
        Self {
            max_chunk_bytes: DEFAULT_MAX_CHUNK_BYTES,
            flush_interval: DEFAULT_INTERACTIVE_FLUSH_INTERVAL,
            flush_on_newline: true,
            caps: OutputCaps::unlimited(),
        }
    }

    /// Return a copy with the given per-invocation output `caps` applied.
    pub const fn with_caps(mut self, caps: OutputCaps) -> Self {
        self.caps = caps;
        self
    }
}

impl Default for StreamCaptureConfig {
    fn default() -> Self {
        Self::batch()
    }
}

/// A token bucket that smooths event emission to a sustained rate.
///
/// Tokens refill continuously at `refill_per_sec`, capped at `capacity` (one
/// second's worth of events, allowing a small initial burst). Each event costs
/// one token; when none are available the caller waits just long enough for the
/// next token to accrue.
#[derive(Debug)]
struct TokenBucket {
    capacity: f64,
    tokens: f64,
    refill_per_sec: f64,
    last: Instant,
}

impl TokenBucket {
    fn new(events_per_second: u32) -> Self {
        let rate = f64::from(events_per_second.max(1));
        Self {
            capacity: rate,
            tokens: rate,
            refill_per_sec: rate,
            last: Instant::now(),
        }
    }

    /// Refill tokens for the time elapsed since the last update.
    fn refill(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        if elapsed > 0.0 {
            self.tokens = (self.tokens + elapsed * self.refill_per_sec).min(self.capacity);
            self.last = now;
        }
    }

    /// Try to spend one token, returning `None` on success or `Some(wait)` with
    /// how long to wait for the next token if the bucket is empty.
    fn try_take(&mut self, now: Instant) -> Option<Duration> {
        self.refill(now);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            None
        } else {
            let deficit = 1.0 - self.tokens;
            Some(Duration::from_secs_f64(deficit / self.refill_per_sec))
        }
    }
}

/// Shared, per-invocation enforcement of an output byte cap and an event-rate
/// limit across all of an invocation's streams.
///
/// Cloning a [`CaptureLimiter`] shares the same underlying budget and token
/// bucket, so stdout and stderr draw from one pool. Construct one with
/// [`CaptureLimiter::new`] (or [`CaptureLimiter::unlimited`]) and hand clones to
/// each [`capture_stream`].
#[derive(Clone)]
pub struct CaptureLimiter {
    inner: Arc<LimiterInner>,
}

struct LimiterInner {
    max_output_bytes: Option<u64>,
    emitted: AtomicU64,
    truncated: AtomicBool,
    rate: Option<Mutex<TokenBucket>>,
}

impl Default for CaptureLimiter {
    fn default() -> Self {
        Self::unlimited()
    }
}

impl CaptureLimiter {
    /// A limiter that enforces nothing: unlimited bytes and event rate.
    pub fn unlimited() -> Self {
        Self::new(OutputCaps::unlimited())
    }

    /// Build a limiter enforcing `caps` across the invocation.
    pub fn new(caps: OutputCaps) -> Self {
        Self {
            inner: Arc::new(LimiterInner {
                max_output_bytes: caps.max_output_bytes,
                emitted: AtomicU64::new(0),
                truncated: AtomicBool::new(false),
                rate: caps
                    .max_events_per_second
                    .map(|eps| Mutex::new(TokenBucket::new(eps))),
            }),
        }
    }

    /// Reserve up to `len` bytes of the shared output budget, returning how many
    /// bytes may actually be forwarded.
    ///
    /// When the budget cannot satisfy the full request the invocation is flagged
    /// as truncated. With no byte cap, the full `len` is always granted.
    fn reserve(&self, len: usize) -> usize {
        let Some(max) = self.inner.max_output_bytes else {
            return len;
        };
        let want = len as u64;
        let mut current = self.inner.emitted.load(Ordering::Relaxed);
        loop {
            let remaining = max.saturating_sub(current);
            let grant = want.min(remaining);
            match self.inner.emitted.compare_exchange_weak(
                current,
                current + grant,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    if grant < want {
                        self.inner.truncated.store(true, Ordering::Relaxed);
                    }
                    return grant as usize;
                }
                Err(actual) => current = actual,
            }
        }
    }

    /// Wait for permission to emit one chunk event under the rate limit.
    ///
    /// A no-op when no event-rate cap is configured; otherwise blocks until the
    /// shared token bucket has a token available.
    async fn acquire_event(&self) {
        let Some(rate) = &self.inner.rate else {
            return;
        };
        loop {
            let wait = {
                let mut bucket = rate.lock().await;
                bucket.try_take(Instant::now())
            };
            match wait {
                None => return,
                Some(delay) => tokio::time::sleep(delay).await,
            }
        }
    }

    /// Whether output has been truncated because the byte budget was exhausted.
    pub fn truncated(&self) -> bool {
        self.inner.truncated.load(Ordering::Relaxed)
    }

    /// Total output bytes forwarded so far across all streams.
    pub fn emitted_bytes(&self) -> u64 {
        self.inner.emitted.load(Ordering::Relaxed)
    }
}

/// Summary of a finished capture, used to populate the `exec.finished` event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CaptureSummary {
    /// Whether output was truncated to honour the per-invocation byte cap.
    pub truncated: bool,
    /// Total output bytes forwarded across all streams.
    pub output_bytes: u64,
}

/// Capture a child's stdout and stderr **concurrently** into `sink`.
///
/// Spawns a reader for each stream so neither can starve the other, tags each
/// chunk with [`StreamKind::Stdout`] or [`StreamKind::Stderr`], and keeps an
/// independent per-stream sequence counter. Both readers feed the same `sink`,
/// so a consumer observes chunks interleaved across streams but strictly
/// ordered within each stream. Each stream is terminated by a final EOF chunk.
///
/// Returns a [`CaptureSummary`] describing whether output was truncated to
/// honour the per-invocation byte cap and how many bytes were forwarded, so the
/// caller can populate the terminal `exec.finished` event.
///
/// Returns once both streams have reached EOF (or the sink was dropped).
pub async fn capture_child_output<O, E>(
    stdout: O,
    stderr: E,
    invocation_id: impl Into<String>,
    config: StreamCaptureConfig,
    sink: mpsc::Sender<StreamChunk>,
) -> CaptureSummary
where
    O: AsyncRead + Unpin + Send,
    E: AsyncRead + Unpin + Send,
{
    let invocation_id = invocation_id.into();
    // One limiter shared across both streams so the caps apply per invocation.
    let limiter = CaptureLimiter::new(config.caps);
    let out = capture_stream_limited(
        stdout,
        invocation_id.clone(),
        StreamKind::Stdout,
        config,
        sink.clone(),
        limiter.clone(),
    );
    let err = capture_stream_limited(
        stderr,
        invocation_id,
        StreamKind::Stderr,
        config,
        sink,
        limiter.clone(),
    );
    // Read both concurrently on the current task; `join` polls both futures.
    tokio::join!(out, err);
    CaptureSummary {
        truncated: limiter.truncated(),
        output_bytes: limiter.emitted_bytes(),
    }
}

/// Capture a single stream, chunking it into [`StreamChunk`] events.
///
/// Reads from `reader` until EOF, flushing the buffer into `sink` whenever a
/// flush condition in [`StreamCaptureConfig`] is met, then sends a final EOF
/// chunk. Stops early (without error) if the sink is closed by the consumer.
///
/// This convenience wrapper enforces no per-invocation caps; use
/// [`capture_child_output`] (or [`capture_stream_limited`]) to apply an output
/// byte cap or event-rate limit.
pub async fn capture_stream<R>(
    reader: R,
    invocation_id: impl Into<String>,
    stream: StreamKind,
    config: StreamCaptureConfig,
    sink: mpsc::Sender<StreamChunk>,
) where
    R: AsyncRead + Unpin,
{
    capture_stream_limited(
        reader,
        invocation_id,
        stream,
        config,
        sink,
        CaptureLimiter::unlimited(),
    )
    .await;
}

/// Capture a single stream like [`capture_stream`], enforcing the shared
/// per-invocation `limiter` (output byte cap and event-rate limit).
///
/// Once the shared byte budget is exhausted the remaining payload is dropped and
/// the limiter is flagged truncated; the stream's EOF marker is still sent so a
/// consumer never waits for an end-of-stream that never arrives.
pub async fn capture_stream_limited<R>(
    reader: R,
    invocation_id: impl Into<String>,
    stream: StreamKind,
    config: StreamCaptureConfig,
    sink: mpsc::Sender<StreamChunk>,
    limiter: CaptureLimiter,
) where
    R: AsyncRead + Unpin,
{
    let invocation_id = invocation_id.into();
    let mut reader = reader;
    let mut buf: Vec<u8> = Vec::with_capacity(config.max_chunk_bytes.min(8192));
    let mut read_buf = [0u8; 8192];
    let mut seq: u64 = 0;

    // Send the EOF marker and return; used on every exit path so the stream is
    // always terminated for the consumer.
    macro_rules! finish {
        () => {{
            let _ = emit_chunk(&sink, &invocation_id, stream, &mut seq, &[], true, &limiter).await;
            return;
        }};
    }

    loop {
        match timeout(config.flush_interval, reader.read(&mut read_buf)).await {
            // Flush interval elapsed: flush whatever is buffered.
            Err(_elapsed) => {
                if !buf.is_empty() {
                    match emit_chunk(
                        &sink,
                        &invocation_id,
                        stream,
                        &mut seq,
                        &buf,
                        false,
                        &limiter,
                    )
                    .await
                    {
                        Emit::Sent => {}
                        Emit::Closed => return,
                        Emit::BudgetExhausted => finish!(),
                    }
                }
                buf.clear();
            }
            // EOF: flush any remainder, then send the EOF marker.
            Ok(Ok(0)) => {
                if !buf.is_empty() {
                    match emit_chunk(
                        &sink,
                        &invocation_id,
                        stream,
                        &mut seq,
                        &buf,
                        false,
                        &limiter,
                    )
                    .await
                    {
                        Emit::Sent | Emit::BudgetExhausted => {}
                        Emit::Closed => return,
                    }
                }
                finish!();
            }
            // Data: append and flush on size / newline as configured.
            Ok(Ok(n)) => {
                buf.extend_from_slice(&read_buf[..n]);

                // Flush whole chunks while the buffer is at or over the cap.
                while buf.len() >= config.max_chunk_bytes {
                    let chunk: Vec<u8> = buf.drain(..config.max_chunk_bytes).collect();
                    match emit_chunk(
                        &sink,
                        &invocation_id,
                        stream,
                        &mut seq,
                        &chunk,
                        false,
                        &limiter,
                    )
                    .await
                    {
                        Emit::Sent => {}
                        Emit::Closed => return,
                        Emit::BudgetExhausted => finish!(),
                    }
                }

                // In interactive mode, flush complete lines as they arrive.
                if config.flush_on_newline {
                    if let Some(last_nl) = buf.iter().rposition(|&b| b == b'\n') {
                        let line: Vec<u8> = buf.drain(..=last_nl).collect();
                        match emit_chunk(
                            &sink,
                            &invocation_id,
                            stream,
                            &mut seq,
                            &line,
                            false,
                            &limiter,
                        )
                        .await
                        {
                            Emit::Sent => {}
                            Emit::Closed => return,
                            Emit::BudgetExhausted => finish!(),
                        }
                    }
                }
            }
            Ok(Err(_io_err)) => {
                // Treat a read error as end-of-stream: flush and mark EOF.
                if !buf.is_empty() {
                    let _ = emit_chunk(
                        &sink,
                        &invocation_id,
                        stream,
                        &mut seq,
                        &buf,
                        false,
                        &limiter,
                    )
                    .await;
                }
                finish!();
            }
        }
    }
}

/// Outcome of attempting to emit one chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Emit {
    /// The chunk (or as much of it as the budget allowed) was delivered.
    Sent,
    /// The sink is closed (consumer went away); the caller should stop.
    Closed,
    /// The shared output byte budget is exhausted; stop forwarding payload.
    BudgetExhausted,
}

/// Build a [`StreamChunk`] for `data` and send it on `sink`, enforcing the
/// shared per-invocation `limiter`.
///
/// The EOF marker (`eof == true`) bypasses both caps: it carries no payload and
/// must always terminate the stream. For data chunks the byte budget is
/// reserved first (truncating the payload when exhausted) and the event-rate
/// limit is awaited before sending. `seq` is advanced only when a chunk is
/// actually emitted so sequence numbers stay monotonic per stream.
///
/// Returns [`Emit::Closed`] when the sink is closed, [`Emit::BudgetExhausted`]
/// when the byte budget could not cover the chunk (the caller should stop
/// forwarding payload), and [`Emit::Sent`] otherwise.
async fn emit_chunk(
    sink: &mpsc::Sender<StreamChunk>,
    invocation_id: &str,
    stream: StreamKind,
    seq: &mut u64,
    data: &[u8],
    eof: bool,
    limiter: &CaptureLimiter,
) -> Emit {
    if eof {
        return match send_chunk(sink, invocation_id, stream, seq, &[], true).await {
            true => Emit::Sent,
            false => Emit::Closed,
        };
    }

    let allowed = limiter.reserve(data.len());
    let exhausted = allowed < data.len();
    if allowed > 0 {
        limiter.acquire_event().await;
        if !send_chunk(sink, invocation_id, stream, seq, &data[..allowed], false).await {
            return Emit::Closed;
        }
    }
    if exhausted {
        Emit::BudgetExhausted
    } else {
        Emit::Sent
    }
}

/// Build and send a single [`StreamChunk`], advancing `seq`. Returns `false`
/// when the sink is closed.
async fn send_chunk(
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

    #[tokio::test]
    async fn output_byte_cap_truncates_and_flags_summary() {
        // Acceptance: a high-output command does not flood Matrix and truncation
        // is explicit. A 1 KiB cap stops the stream well short of the input.
        let (tx, rx) = mpsc::channel(256);
        let data = vec![b'x'; 64 * 1024];
        let config = StreamCaptureConfig::batch().with_caps(OutputCaps {
            max_output_bytes: Some(1024),
            max_events_per_second: None,
        });
        let summary = capture_child_output(&data[..], &[][..], "inv_cap", config, tx).await;
        let chunks = collect(rx).await;
        let payload: usize = chunks.iter().map(|c| c.data.len()).sum();
        assert!(payload <= 1024, "forwarded {payload} bytes, cap was 1024");
        assert!(summary.truncated, "summary should report truncation");
        assert_eq!(summary.output_bytes, 1024);
        // The stream must still be terminated for the consumer.
        assert!(chunks.iter().any(|c| c.eof));
    }

    #[tokio::test]
    async fn output_byte_cap_is_shared_across_streams() {
        // The cap is per invocation, not per stream: stdout + stderr together
        // cannot exceed the budget.
        let (tx, rx) = mpsc::channel(256);
        let out = vec![b'o'; 8 * 1024];
        let err = vec![b'e'; 8 * 1024];
        let config = StreamCaptureConfig::batch().with_caps(OutputCaps {
            max_output_bytes: Some(4096),
            max_events_per_second: None,
        });
        let summary = capture_child_output(&out[..], &err[..], "inv_cap", config, tx).await;
        let chunks = collect(rx).await;
        let payload: usize = chunks.iter().map(|c| c.data.len()).sum();
        assert!(payload <= 4096, "forwarded {payload} bytes, cap was 4096");
        assert!(summary.truncated);
        assert_eq!(summary.output_bytes, 4096);
    }

    #[tokio::test]
    async fn output_within_cap_is_not_truncated() {
        let (tx, rx) = mpsc::channel(256);
        let data = b"small output\n".to_vec();
        let config = StreamCaptureConfig::batch().with_caps(OutputCaps {
            max_output_bytes: Some(1_000_000),
            max_events_per_second: None,
        });
        let summary = capture_child_output(&data[..], &[][..], "inv_ok", config, tx).await;
        let chunks = collect(rx).await;
        assert!(!summary.truncated);
        assert_eq!(summary.output_bytes, data.len() as u64);
        let payload: Vec<u8> = chunks
            .iter()
            .filter(|c| !c.eof)
            .flat_map(|c| c.data.clone().into_bytes())
            .collect();
        assert_eq!(payload, data);
    }

    #[tokio::test(start_paused = true)]
    async fn event_rate_limit_throttles_chunk_emission() {
        // Acceptance: limit event rate per invocation. With a 2 events/sec cap
        // and tiny one-byte chunks, the fourth chunk cannot be emitted until
        // virtual time advances past the initial burst.
        let (tx, mut rx) = mpsc::channel(256);
        let data = [b'a'; 6];
        let config = StreamCaptureConfig {
            max_chunk_bytes: 1,
            ..StreamCaptureConfig::batch()
        }
        .with_caps(OutputCaps {
            max_output_bytes: None,
            max_events_per_second: Some(2),
        });
        let handle = tokio::spawn(async move {
            capture_child_output(&data[..], &[][..], "inv_rate", config, tx).await
        });
        // The token bucket starts full (capacity == rate == 2), so the first two
        // data chunks emit immediately; the third must wait for a refill.
        tokio::time::sleep(Duration::from_millis(10)).await;
        let mut received = Vec::new();
        while let Ok(chunk) = rx.try_recv() {
            received.push(chunk);
        }
        let data_chunks = received.iter().filter(|c| !c.eof).count();
        assert!(
            data_chunks <= 2,
            "rate limit should hold emission to the initial burst, got {data_chunks}"
        );
        // Advance virtual time enough to refill the bucket and drain the rest.
        tokio::time::advance(Duration::from_secs(5)).await;
        while (rx.recv().await).is_some() {}
        let summary = handle.await.unwrap();
        assert!(!summary.truncated);
    }

    #[test]
    fn token_bucket_refills_over_time() {
        let start = Instant::now();
        let mut bucket = TokenBucket::new(4);
        bucket.last = start;
        bucket.tokens = 0.0;
        // Empty bucket: must wait for the next token (1/4 s at 4 eps).
        let wait = bucket.try_take(start).expect("empty bucket waits");
        assert!(wait > Duration::ZERO);
        // After a full second, the bucket has refilled to capacity.
        let later = start + Duration::from_secs(1);
        assert!(bucket.try_take(later).is_none());
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
