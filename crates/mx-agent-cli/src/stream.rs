//! Render remote `exec` stream frames locally and resolve the exit code.
//!
//! The daemon forwards a remote invocation's output as a sequence of
//! `com.mxagent.stream.chunk.v1` frames followed by a
//! `com.mxagent.exec.finished.v1` frame (architecture §7.3, §7.4, §8.2). This
//! module is the CLI consumer of that sequence: it writes each chunk's bytes to
//! the local stdout/stderr (decoding UTF-8 or base64), waits for the finished
//! frame, and maps the remote exit status to a local process exit code per the
//! table in architecture §5.3.
//!
//! The renderer is deliberately **transport-agnostic**: it operates on an
//! iterator of [`StreamFrame`] values, so the same logic serves whatever
//! delivers the frames (a live daemon IPC stream, or the local runner loopback
//! used by the `exec` command today).
//!
//! ## Reordering and missing chunks (degraded mode)
//!
//! Federated, at-least-once delivery means the CLI can see a chunk more than
//! once, see chunks out of order, or never see a chunk at all. To keep terminal
//! output faithful the renderer **buffers** chunks that arrive ahead of the
//! next contiguous sequence number and releases them in order once the gap
//! fills. A missing chunk would otherwise stall all later output, so each
//! stream tolerates only a bounded reorder window
//! ([`RenderConfig::reorder_window`]); once that many chunks are buffered ahead
//! of a gap, the lowest missing sequence number(s) are declared lost. When a
//! chunk is declared lost the stream is marked **degraded**: a warning is
//! surfaced to the user and best-effort output continues by default.
//!
//! ## Strict stream mode
//!
//! Best-effort rendering is the right default for interactive use, but some
//! callers need a guarantee that what they saw is exactly what the remote
//! produced (e.g. capturing a build log for an audit). [`RenderConfig::strict`]
//! turns any stream-integrity problem into a hard failure: a missing chunk
//! (declared lost as above) or an *invalid* chunk (one whose payload cannot be
//! decoded, or whose `sha256` digest does not match its bytes) marks the
//! outcome as an integrity failure. The CLI maps that to exit code
//! [`EXIT_STREAM_INTEGRITY`] (`132`). Output is still rendered best-effort so
//! the user can see what was received, but the non-zero exit makes the
//! corruption impossible to ignore.

use std::collections::{BTreeMap, HashMap};
use std::io::{self, Write};

use mx_agent_protocol::schema::{ExecFinished, StreamChunk, StreamKind};

/// Local exit code used when the stream ends without an `exec.finished` frame
/// (architecture §5.3: protocol/network failure).
pub const EXIT_PROTOCOL_FAILURE: u8 = 128;

/// Local exit code returned in strict mode when stream integrity is violated:
/// a chunk is missing or fails validation (architecture §5.3).
pub const EXIT_STREAM_INTEGRITY: u8 = 132;

/// Default reorder window: how many chunks may be buffered ahead of a gap on a
/// single stream before the missing sequence number is declared lost. Bounds
/// the head-of-line blocking introduced by waiting for an out-of-order chunk.
pub const DEFAULT_REORDER_WINDOW: usize = 64;

/// One frame in the forwarded exec stream.
#[derive(Debug, Clone)]
pub enum StreamFrame {
    /// A chunk of stdout/stderr output.
    Chunk(StreamChunk),
    /// The terminal frame carrying the remote exit status.
    Finished(ExecFinished),
}

/// Tuning for [`render_stream_with`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RenderConfig {
    /// Maximum number of chunks buffered ahead of a gap, per stream, before the
    /// missing sequence number is declared lost and the stream marked degraded.
    pub reorder_window: usize,
    /// Treat any stream-integrity problem (a missing or invalid chunk) as a
    /// hard failure rather than continuing best-effort. See the module-level
    /// "Strict stream mode" section.
    pub strict: bool,
}

impl Default for RenderConfig {
    fn default() -> Self {
        Self {
            reorder_window: DEFAULT_REORDER_WINDOW,
            strict: false,
        }
    }
}

/// A sequence number that was never delivered and has been declared lost.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MissingChunk {
    /// The stream the gap was detected on.
    pub stream: StreamKind,
    /// The missing sequence number.
    pub seq: u64,
}

/// Outcome of rendering a forwarded exec stream.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct StreamOutcome {
    /// Resolved local exit code, or `None` if the stream ended without an
    /// `exec.finished` frame (treat as [`EXIT_PROTOCOL_FAILURE`]).
    pub exit_code: Option<u8>,
    /// Sequence numbers that were declared lost, in detection order.
    pub missing: Vec<MissingChunk>,
    /// `true` if strict mode detected a stream-integrity violation (a missing
    /// or invalid chunk). Always `false` in best-effort (default) mode.
    pub integrity_failure: bool,
}

impl StreamOutcome {
    /// `true` if any chunk was declared lost, i.e. the stream ran degraded.
    pub fn degraded(&self) -> bool {
        !self.missing.is_empty()
    }
}

/// Per-stream reorder state: chunks arriving ahead of the contiguous boundary
/// are buffered until the gap fills (or the window forces them out).
#[derive(Debug, Default)]
struct StreamReorder {
    /// Lowest sequence number not yet released contiguously.
    next_expected: u64,
    /// Accepted chunks at or above `next_expected`, keyed by sequence number.
    ahead: BTreeMap<u64, StreamChunk>,
}

impl StreamReorder {
    /// Accept `chunk`, returning the chunks now ready to render in sequence
    /// order. Sequence numbers declared lost (because the reorder `window` was
    /// exceeded) are appended to `missing`.
    fn push(
        &mut self,
        chunk: StreamChunk,
        window: usize,
        missing: &mut Vec<u64>,
    ) -> Vec<StreamChunk> {
        let seq = chunk.seq;
        if seq < self.next_expected || self.ahead.contains_key(&seq) {
            // Already released below the boundary, or already buffered: a
            // duplicate/replay. Drop it so output is not duplicated.
            return Vec::new();
        }

        let mut ready = Vec::new();
        if seq == self.next_expected {
            // Fills the boundary: release it plus any contiguous run buffered
            // ahead of it.
            ready.push(chunk);
            self.next_expected += 1;
            self.drain_contiguous(&mut ready);
        } else {
            // Arrived ahead of the boundary: buffer until the gap fills.
            self.ahead.insert(seq, chunk);
        }

        // Bound head-of-line blocking: if too many chunks are buffered ahead of
        // the gap, give up on the missing sequence number(s) and release what
        // we have so best-effort output keeps flowing.
        while self.ahead.len() > window {
            let first = *self.ahead.keys().next().expect("non-empty when len > 0");
            while self.next_expected < first {
                missing.push(self.next_expected);
                self.next_expected += 1;
            }
            self.drain_contiguous(&mut ready);
        }
        ready
    }

    /// Release all buffered chunks, declaring every remaining gap lost.
    fn flush(&mut self, missing: &mut Vec<u64>) -> Vec<StreamChunk> {
        let mut ready = Vec::new();
        while let Some(&first) = self.ahead.keys().next() {
            while self.next_expected < first {
                missing.push(self.next_expected);
                self.next_expected += 1;
            }
            self.drain_contiguous(&mut ready);
        }
        ready
    }

    /// Pop the contiguous run starting at `next_expected` into `ready`.
    fn drain_contiguous(&mut self, ready: &mut Vec<StreamChunk>) {
        while let Some(chunk) = self.ahead.remove(&self.next_expected) {
            ready.push(chunk);
            self.next_expected += 1;
        }
    }
}

/// Reorder buffer that delivers chunks in per-stream sequence order, suppresses
/// duplicates, and detects missing sequence numbers.
///
/// State is kept independently per [`StreamKind`] so stdout and stderr each have
/// their own monotonic sequence space, matching the producer.
#[derive(Debug)]
pub struct ReorderBuffer {
    streams: HashMap<StreamKind, StreamReorder>,
    window: usize,
}

impl ReorderBuffer {
    /// Create an empty buffer with the given per-stream reorder `window`.
    pub fn new(window: usize) -> Self {
        Self {
            streams: HashMap::new(),
            // A zero window would declare any out-of-order chunk lost
            // immediately, defeating reordering; keep at least one slot.
            window: window.max(1),
        }
    }

    /// Accept `chunk`, returning the chunks now ready to render in order.
    /// Sequence numbers declared lost are appended to `missing`.
    pub fn accept(
        &mut self,
        chunk: StreamChunk,
        missing: &mut Vec<MissingChunk>,
    ) -> Vec<StreamChunk> {
        let stream = chunk.stream;
        let window = self.window;
        let state = self.streams.entry(stream).or_default();
        let mut lost = Vec::new();
        let ready = state.push(chunk, window, &mut lost);
        missing.extend(lost.into_iter().map(|seq| MissingChunk { stream, seq }));
        ready
    }

    /// Release every buffered chunk, declaring remaining gaps lost.
    pub fn flush(&mut self, missing: &mut Vec<MissingChunk>) -> Vec<StreamChunk> {
        let mut ready = Vec::new();
        for (stream, state) in self.streams.iter_mut() {
            let mut lost = Vec::new();
            ready.append(&mut state.flush(&mut lost));
            missing.extend(lost.into_iter().map(|seq| MissingChunk {
                stream: *stream,
                seq,
            }));
        }
        ready
    }
}

/// Map a signal name (e.g. `SIGTERM`) to its number, for the shell convention
/// of reporting signal death as `128 + signum`.
fn signal_number(name: &str) -> Option<i32> {
    Some(match name {
        "SIGHUP" => 1,
        "SIGINT" => 2,
        "SIGQUIT" => 3,
        "SIGILL" => 4,
        "SIGABRT" | "SIGIOT" => 6,
        "SIGFPE" => 8,
        "SIGKILL" => 9,
        "SIGSEGV" => 11,
        "SIGPIPE" => 13,
        "SIGALRM" => 14,
        "SIGTERM" => 15,
        _ => return None,
    })
}

/// Resolve the local exit code from a remote [`ExecFinished`].
///
/// Follows architecture §5.3: a normal exit propagates the remote `exit_code`;
/// a signal death reports `128 + signum` (or `128` for an unknown signal); and
/// a finished frame carrying neither maps to `128` (protocol failure).
pub fn resolve_exit_code(finished: &ExecFinished) -> u8 {
    if let Some(code) = finished.exit_code {
        // Process exit codes are a byte on Unix; clamp anything out of range.
        return u8::try_from(code).unwrap_or(1);
    }
    if let Some(signal) = &finished.signal {
        return signal_number(signal)
            .and_then(|n| u8::try_from(128 + n).ok())
            .unwrap_or(EXIT_PROTOCOL_FAILURE);
    }
    EXIT_PROTOCOL_FAILURE
}

/// Decode a chunk's payload bytes from its declared encoding.
///
/// `utf-8` payloads are returned as their bytes; `base64` payloads are decoded;
/// any other encoding is treated as raw bytes so output is never silently lost.
fn decode_chunk(chunk: &StreamChunk) -> Vec<u8> {
    match chunk.encoding.as_str() {
        "base64" => {
            use base64::Engine as _;
            base64::engine::general_purpose::STANDARD
                .decode(chunk.data.as_bytes())
                .unwrap_or_else(|_| chunk.data.clone().into_bytes())
        }
        _ => chunk.data.clone().into_bytes(),
    }
}

/// Write one chunk's bytes to the appropriate local writer.
///
/// `stdout`/`pty` chunks go to `out`, `stderr` to `err`; `stdin`/`control`
/// chunks and empty (EOF marker) chunks produce no output.
pub fn render_chunk<O, E>(chunk: &StreamChunk, out: &mut O, err: &mut E) -> io::Result<()>
where
    O: Write,
    E: Write,
{
    if chunk.data.is_empty() {
        return Ok(());
    }
    let bytes = decode_chunk(chunk);
    match chunk.stream {
        StreamKind::Stdout | StreamKind::Pty => out.write_all(&bytes),
        StreamKind::Stderr => err.write_all(&bytes),
        StreamKind::Stdin | StreamKind::Control => Ok(()),
    }
}

/// Validate a chunk's payload integrity, returning a human-readable reason if
/// the chunk is invalid.
///
/// A chunk is invalid when its declared encoding cannot decode its payload
/// (e.g. malformed base64), or when it carries a `sha256` digest that does not
/// match its decoded bytes. Used only in strict mode; best-effort rendering
/// tolerates such chunks by falling back to raw bytes.
fn chunk_integrity_error(chunk: &StreamChunk) -> Option<String> {
    use base64::Engine as _;
    let engine = base64::engine::general_purpose::STANDARD;
    let bytes = if chunk.encoding.as_str() == "base64" {
        match engine.decode(chunk.data.as_bytes()) {
            Ok(bytes) => bytes,
            Err(e) => {
                return Some(format!(
                    "{} chunk {}: invalid base64 payload: {e}",
                    stream_label(chunk.stream),
                    chunk.seq
                ))
            }
        }
    } else {
        chunk.data.clone().into_bytes()
    };
    if let Some(expected) = &chunk.sha256 {
        use sha2::{Digest as _, Sha256};
        let got = engine.encode(Sha256::digest(&bytes));
        if &got != expected {
            return Some(format!(
                "{} chunk {}: sha256 digest mismatch",
                stream_label(chunk.stream),
                chunk.seq
            ));
        }
    }
    None
}

/// Human-readable label for a stream, used in degraded-mode warnings.
fn stream_label(stream: StreamKind) -> &'static str {
    match stream {
        StreamKind::Stdout => "stdout",
        StreamKind::Stderr => "stderr",
        StreamKind::Pty => "pty",
        StreamKind::Stdin => "stdin",
        StreamKind::Control => "control",
    }
}

/// Surface freshly detected missing chunks to the user (on `err`) and record
/// them on `outcome`. Best-effort output continues; this is purely advisory.
fn surface_missing<E>(
    detected: &[MissingChunk],
    outcome: &mut StreamOutcome,
    strict: bool,
    err: &mut E,
) -> io::Result<()>
where
    E: Write,
{
    for m in detected {
        if strict {
            writeln!(
                err,
                "mx-agent: error: {} stream integrity failure: missing chunk {}",
                stream_label(m.stream),
                m.seq
            )?;
            outcome.integrity_failure = true;
        } else {
            writeln!(
                err,
                "mx-agent: warning: {} stream degraded: missing chunk {} (best-effort output continues)",
                stream_label(m.stream),
                m.seq
            )?;
        }
        outcome.missing.push(*m);
    }
    Ok(())
}

/// In strict mode, validate `chunk` and, if it fails, surface the reason on
/// `err` and mark the outcome as an integrity failure. Output still proceeds
/// best-effort so the user can see what was received. A no-op when not strict.
fn check_chunk_integrity<E>(
    chunk: &StreamChunk,
    outcome: &mut StreamOutcome,
    strict: bool,
    err: &mut E,
) -> io::Result<()>
where
    E: Write,
{
    if !strict {
        return Ok(());
    }
    if let Some(reason) = chunk_integrity_error(chunk) {
        writeln!(err, "mx-agent: error: stream integrity failure: {reason}")?;
        outcome.integrity_failure = true;
    }
    Ok(())
}

/// Render a forwarded exec stream with the default [`RenderConfig`].
///
/// See [`render_stream_with`]. Returns a [`StreamOutcome`] carrying the resolved
/// exit code and any chunks declared lost.
pub fn render_stream<I, O, E>(frames: I, out: &mut O, err: &mut E) -> io::Result<StreamOutcome>
where
    I: IntoIterator<Item = StreamFrame>,
    O: Write,
    E: Write,
{
    render_stream_with(frames, RenderConfig::default(), out, err)
}

/// Render a forwarded exec stream, returning the resolved exit code and any
/// degraded-mode detail.
///
/// Buffers out-of-order chunks and releases them in sequence order, suppresses
/// duplicates, and declares chunks lost once the reorder window is exceeded or
/// the stream ends with gaps still outstanding. Lost chunks are surfaced to the
/// user on `err` and recorded on the returned [`StreamOutcome`]; output
/// continues best-effort. [`StreamOutcome::exit_code`] is `None` if the stream
/// ends without a finished frame (treat as [`EXIT_PROTOCOL_FAILURE`]).
pub fn render_stream_with<I, O, E>(
    frames: I,
    config: RenderConfig,
    out: &mut O,
    err: &mut E,
) -> io::Result<StreamOutcome>
where
    I: IntoIterator<Item = StreamFrame>,
    O: Write,
    E: Write,
{
    let mut outcome = StreamOutcome::default();
    let mut buf = ReorderBuffer::new(config.reorder_window);
    let mut detected = Vec::new();
    let mut finished_seen = false;

    for frame in frames {
        match frame {
            StreamFrame::Chunk(chunk) => {
                detected.clear();
                for ready in buf.accept(chunk, &mut detected) {
                    check_chunk_integrity(&ready, &mut outcome, config.strict, err)?;
                    render_chunk(&ready, out, err)?;
                }
                surface_missing(&detected, &mut outcome, config.strict, err)?;
            }
            StreamFrame::Finished(finished) => {
                // Flush anything still buffered before reporting the exit code;
                // remaining gaps are declared lost.
                detected.clear();
                for ready in buf.flush(&mut detected) {
                    check_chunk_integrity(&ready, &mut outcome, config.strict, err)?;
                    render_chunk(&ready, out, err)?;
                }
                surface_missing(&detected, &mut outcome, config.strict, err)?;
                outcome.exit_code = Some(resolve_exit_code(&finished));
                finished_seen = true;
                break;
            }
        }
    }

    if !finished_seen {
        // Stream ended without a finished frame: still flush buffered output
        // best-effort, then leave the exit code unset (protocol failure).
        detected.clear();
        for ready in buf.flush(&mut detected) {
            check_chunk_integrity(&ready, &mut outcome, config.strict, err)?;
            render_chunk(&ready, out, err)?;
        }
        surface_missing(&detected, &mut outcome, config.strict, err)?;
    }

    out.flush()?;
    err.flush()?;
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chunk(stream: StreamKind, encoding: &str, data: &str, eof: bool) -> StreamChunk {
        chunk_seq(stream, 0, encoding, data, eof)
    }

    fn chunk_seq(
        stream: StreamKind,
        seq: u64,
        encoding: &str,
        data: &str,
        eof: bool,
    ) -> StreamChunk {
        StreamChunk {
            invocation_id: "inv_1".to_string(),
            stream,
            seq,
            encoding: encoding.to_string(),
            data: data.to_string(),
            eof,
            compressed: false,
            sha256: None,
            timestamp: "2026-06-02T12:00:00.000Z".to_string(),
            extra: Default::default(),
        }
    }

    fn finished(exit_code: Option<i32>, signal: Option<&str>) -> ExecFinished {
        ExecFinished {
            invocation_id: "inv_1".to_string(),
            exit_code,
            signal: signal.map(|s| s.to_string()),
            duration_ms: 0,
            stdout_bytes: 0,
            stderr_bytes: 0,
            truncated: false,
            artifact_mxc: None,
            extra: Default::default(),
        }
    }

    #[test]
    fn remote_output_appears_locally_on_correct_streams() {
        // Acceptance: remote `npm test` output appears locally.
        let frames = vec![
            StreamFrame::Chunk(chunk_seq(
                StreamKind::Stdout,
                0,
                "utf-8",
                "PASS src/foo.test.ts\n",
                false,
            )),
            StreamFrame::Chunk(chunk_seq(
                StreamKind::Stderr,
                0,
                "utf-8",
                "warning: deprecated\n",
                false,
            )),
            StreamFrame::Chunk(chunk_seq(
                StreamKind::Stdout,
                1,
                "utf-8",
                "1 passing\n",
                false,
            )),
            StreamFrame::Chunk(chunk_seq(StreamKind::Stdout, 2, "utf-8", "", true)), // EOF marker
            StreamFrame::Finished(finished(Some(0), None)),
        ];
        let mut out = Vec::new();
        let mut err = Vec::new();
        let outcome = render_stream(frames, &mut out, &mut err).unwrap();
        assert_eq!(outcome.exit_code, Some(0));
        assert!(!outcome.degraded());
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "PASS src/foo.test.ts\n1 passing\n"
        );
        assert_eq!(String::from_utf8(err).unwrap(), "warning: deprecated\n");
    }

    #[test]
    fn local_exit_code_matches_remote_command() {
        // Acceptance: local exit code matches the remote command's exit code.
        let frames = vec![
            StreamFrame::Chunk(chunk(StreamKind::Stderr, "utf-8", "1 failing\n", false)),
            StreamFrame::Finished(finished(Some(1), None)),
        ];
        let mut out = Vec::new();
        let mut err = Vec::new();
        let outcome = render_stream(frames, &mut out, &mut err).unwrap();
        assert_eq!(outcome.exit_code, Some(1));
        assert_eq!(String::from_utf8(err).unwrap(), "1 failing\n");
        assert!(out.is_empty());
    }

    #[test]
    fn base64_chunks_are_decoded() {
        use base64::Engine as _;
        let raw = [0xff, 0xfe, 0x00, 0x01];
        let encoded = base64::engine::general_purpose::STANDARD.encode(raw);
        let frames = vec![
            StreamFrame::Chunk(chunk(StreamKind::Stdout, "base64", &encoded, false)),
            StreamFrame::Finished(finished(Some(0), None)),
        ];
        let mut out = Vec::new();
        let mut err = Vec::new();
        render_stream(frames, &mut out, &mut err).unwrap();
        assert_eq!(out, raw);
    }

    #[test]
    fn resolve_exit_code_handles_signal_and_missing() {
        assert_eq!(resolve_exit_code(&finished(Some(0), None)), 0);
        assert_eq!(resolve_exit_code(&finished(Some(42), None)), 42);
        // Signal death reports 128 + signum.
        assert_eq!(resolve_exit_code(&finished(None, Some("SIGTERM"))), 143);
        assert_eq!(resolve_exit_code(&finished(None, Some("SIGKILL"))), 137);
        // Unknown signal and no status both fall back to protocol failure.
        assert_eq!(resolve_exit_code(&finished(None, Some("SIGWEIRD"))), 128);
        assert_eq!(resolve_exit_code(&finished(None, None)), 128);
    }

    #[test]
    fn missing_finished_frame_returns_none() {
        let frames = vec![StreamFrame::Chunk(chunk(
            StreamKind::Stdout,
            "utf-8",
            "partial output\n",
            false,
        ))];
        let mut out = Vec::new();
        let mut err = Vec::new();
        let outcome = render_stream(frames, &mut out, &mut err).unwrap();
        assert_eq!(outcome.exit_code, None);
        assert_eq!(String::from_utf8(out).unwrap(), "partial output\n");
    }

    #[test]
    fn frames_after_finished_are_ignored() {
        let frames = vec![
            StreamFrame::Chunk(chunk_seq(StreamKind::Stdout, 0, "utf-8", "before\n", false)),
            StreamFrame::Finished(finished(Some(7), None)),
            StreamFrame::Chunk(chunk_seq(StreamKind::Stdout, 1, "utf-8", "after\n", false)),
        ];
        let mut out = Vec::new();
        let mut err = Vec::new();
        let outcome = render_stream(frames, &mut out, &mut err).unwrap();
        assert_eq!(outcome.exit_code, Some(7));
        assert_eq!(String::from_utf8(out).unwrap(), "before\n");
    }

    #[test]
    fn duplicate_chunks_do_not_duplicate_terminal_output() {
        // Acceptance: duplicate chunks do not duplicate terminal output.
        // At-least-once delivery replays seq 0 and seq 1 on stdout.
        let frames = vec![
            StreamFrame::Chunk(chunk_seq(
                StreamKind::Stdout,
                0,
                "utf-8",
                "line one\n",
                false,
            )),
            StreamFrame::Chunk(chunk_seq(
                StreamKind::Stdout,
                0,
                "utf-8",
                "line one\n",
                false,
            )),
            StreamFrame::Chunk(chunk_seq(
                StreamKind::Stdout,
                1,
                "utf-8",
                "line two\n",
                false,
            )),
            StreamFrame::Chunk(chunk_seq(
                StreamKind::Stdout,
                1,
                "utf-8",
                "line two\n",
                false,
            )),
            StreamFrame::Chunk(chunk_seq(
                StreamKind::Stdout,
                0,
                "utf-8",
                "line one\n",
                false,
            )),
            StreamFrame::Finished(finished(Some(0), None)),
        ];
        let mut out = Vec::new();
        let mut err = Vec::new();
        let outcome = render_stream(frames, &mut out, &mut err).unwrap();
        assert_eq!(outcome.exit_code, Some(0));
        assert!(!outcome.degraded());
        assert_eq!(String::from_utf8(out).unwrap(), "line one\nline two\n");
    }

    #[test]
    fn out_of_order_chunks_are_buffered_and_rendered_in_order() {
        // Out-of-order arrivals are buffered and released in sequence order, so
        // the gap (seq 0) is rendered before the chunk that arrived first.
        let frames = vec![
            StreamFrame::Chunk(chunk_seq(StreamKind::Stdout, 1, "utf-8", "second\n", false)),
            StreamFrame::Chunk(chunk_seq(StreamKind::Stdout, 0, "utf-8", "first\n", false)),
            // Replays, now below/at the contiguous boundary, are suppressed.
            StreamFrame::Chunk(chunk_seq(StreamKind::Stdout, 1, "utf-8", "second\n", false)),
            StreamFrame::Chunk(chunk_seq(StreamKind::Stdout, 0, "utf-8", "first\n", false)),
            StreamFrame::Chunk(chunk_seq(StreamKind::Stdout, 2, "utf-8", "third\n", false)),
            StreamFrame::Finished(finished(Some(0), None)),
        ];
        let mut out = Vec::new();
        let mut err = Vec::new();
        let outcome = render_stream(frames, &mut out, &mut err).unwrap();
        assert!(!outcome.degraded());
        assert_eq!(String::from_utf8(out).unwrap(), "first\nsecond\nthird\n");
    }

    #[test]
    fn sequence_state_is_tracked_per_stream() {
        // Acceptance: sequence state is tracked per stream. The same seq number
        // on stdout and stderr are independent and both render.
        let frames = vec![
            StreamFrame::Chunk(chunk_seq(StreamKind::Stdout, 0, "utf-8", "out0\n", false)),
            StreamFrame::Chunk(chunk_seq(StreamKind::Stderr, 0, "utf-8", "err0\n", false)),
            // Replays on each stream are suppressed independently.
            StreamFrame::Chunk(chunk_seq(StreamKind::Stdout, 0, "utf-8", "out0\n", false)),
            StreamFrame::Chunk(chunk_seq(StreamKind::Stderr, 0, "utf-8", "err0\n", false)),
            StreamFrame::Finished(finished(Some(0), None)),
        ];
        let mut out = Vec::new();
        let mut err = Vec::new();
        render_stream(frames, &mut out, &mut err).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "out0\n");
        assert_eq!(String::from_utf8(err).unwrap(), "err0\n");
    }

    #[test]
    fn missing_chunk_is_detected_when_window_exceeded() {
        // A small reorder window means a never-delivered seq 0 is declared lost
        // once enough later chunks pile up, and best-effort output continues.
        let config = RenderConfig {
            reorder_window: 2,
            strict: false,
        };
        let frames = vec![
            StreamFrame::Chunk(chunk_seq(StreamKind::Stdout, 1, "utf-8", "b\n", false)),
            StreamFrame::Chunk(chunk_seq(StreamKind::Stdout, 2, "utf-8", "c\n", false)),
            // Buffering seq 3 puts three chunks ahead of the gap at seq 0,
            // exceeding the window of 2 -> seq 0 is declared lost.
            StreamFrame::Chunk(chunk_seq(StreamKind::Stdout, 3, "utf-8", "d\n", false)),
            StreamFrame::Finished(finished(Some(0), None)),
        ];
        let mut out = Vec::new();
        let mut err = Vec::new();
        let outcome = render_stream_with(frames, config, &mut out, &mut err).unwrap();
        assert_eq!(outcome.exit_code, Some(0));
        assert!(outcome.degraded());
        assert_eq!(
            outcome.missing,
            vec![MissingChunk {
                stream: StreamKind::Stdout,
                seq: 0,
            }]
        );
        // Best-effort: the chunks we did receive are still rendered in order.
        assert_eq!(String::from_utf8(out).unwrap(), "b\nc\nd\n");
        // The loss is surfaced to the user on stderr.
        let stderr = String::from_utf8(err).unwrap();
        assert!(stderr.contains("stdout stream degraded"), "got: {stderr}");
        assert!(stderr.contains("missing chunk 0"), "got: {stderr}");
        assert!(
            stderr.contains("best-effort output continues"),
            "got: {stderr}"
        );
    }

    #[test]
    fn trailing_gap_is_declared_missing_on_finish() {
        // A gap that never fills before the stream finishes is declared lost
        // when the buffer is flushed, and surfaced to the user.
        let frames = vec![
            StreamFrame::Chunk(chunk_seq(StreamKind::Stdout, 0, "utf-8", "a\n", false)),
            // seq 1 never arrives; seq 2 is buffered ahead of the gap.
            StreamFrame::Chunk(chunk_seq(StreamKind::Stdout, 2, "utf-8", "c\n", false)),
            StreamFrame::Finished(finished(Some(0), None)),
        ];
        let mut out = Vec::new();
        let mut err = Vec::new();
        let outcome = render_stream(frames, &mut out, &mut err).unwrap();
        assert!(outcome.degraded());
        assert_eq!(
            outcome.missing,
            vec![MissingChunk {
                stream: StreamKind::Stdout,
                seq: 1,
            }]
        );
        assert_eq!(String::from_utf8(out).unwrap(), "a\nc\n");
        assert!(String::from_utf8(err).unwrap().contains("missing chunk 1"));
    }

    #[test]
    fn strict_mode_fails_on_simulated_missing_chunk() {
        // Acceptance: strict mode fails on a simulated missing chunk. seq 1
        // never arrives; the trailing gap is declared lost on finish and, in
        // strict mode, that is an integrity failure (CLI maps it to exit 132).
        let config = RenderConfig {
            strict: true,
            ..Default::default()
        };
        let frames = vec![
            StreamFrame::Chunk(chunk_seq(StreamKind::Stdout, 0, "utf-8", "a\n", false)),
            StreamFrame::Chunk(chunk_seq(StreamKind::Stdout, 2, "utf-8", "c\n", false)),
            StreamFrame::Finished(finished(Some(0), None)),
        ];
        let mut out = Vec::new();
        let mut err = Vec::new();
        let outcome = render_stream_with(frames, config, &mut out, &mut err).unwrap();
        assert!(outcome.integrity_failure);
        assert!(outcome.degraded());
        // Output is still rendered best-effort so the user sees what arrived.
        assert_eq!(String::from_utf8(out).unwrap(), "a\nc\n");
        let stderr = String::from_utf8(err).unwrap();
        assert!(
            stderr.contains("stream integrity failure: missing chunk 1"),
            "got: {stderr}"
        );
    }

    #[test]
    fn default_mode_remains_best_effort_on_missing_chunk() {
        // Acceptance: default mode remains best-effort. The same missing chunk
        // is degraded but never an integrity failure.
        let frames = vec![
            StreamFrame::Chunk(chunk_seq(StreamKind::Stdout, 0, "utf-8", "a\n", false)),
            StreamFrame::Chunk(chunk_seq(StreamKind::Stdout, 2, "utf-8", "c\n", false)),
            StreamFrame::Finished(finished(Some(0), None)),
        ];
        let mut out = Vec::new();
        let mut err = Vec::new();
        let outcome = render_stream(frames, &mut out, &mut err).unwrap();
        assert!(outcome.degraded());
        assert!(!outcome.integrity_failure);
        assert_eq!(outcome.exit_code, Some(0));
        assert_eq!(String::from_utf8(out).unwrap(), "a\nc\n");
    }

    #[test]
    fn strict_mode_fails_on_window_exceeded_missing_chunk() {
        // A never-delivered seq 0 declared lost mid-stream (window exceeded) is
        // also an integrity failure in strict mode.
        let config = RenderConfig {
            strict: true,
            reorder_window: 2,
        };
        let frames = vec![
            StreamFrame::Chunk(chunk_seq(StreamKind::Stdout, 1, "utf-8", "b\n", false)),
            StreamFrame::Chunk(chunk_seq(StreamKind::Stdout, 2, "utf-8", "c\n", false)),
            StreamFrame::Chunk(chunk_seq(StreamKind::Stdout, 3, "utf-8", "d\n", false)),
            StreamFrame::Finished(finished(Some(0), None)),
        ];
        let mut out = Vec::new();
        let mut err = Vec::new();
        let outcome = render_stream_with(frames, config, &mut out, &mut err).unwrap();
        assert!(outcome.integrity_failure);
        assert_eq!(
            outcome.missing,
            vec![MissingChunk {
                stream: StreamKind::Stdout,
                seq: 0,
            }]
        );
    }

    #[test]
    fn strict_mode_fails_on_invalid_base64_chunk() {
        // An undecodable base64 payload is an invalid chunk: fatal in strict
        // mode, tolerated (rendered raw) by default.
        let config = RenderConfig {
            strict: true,
            ..Default::default()
        };
        let frames = vec![
            StreamFrame::Chunk(chunk_seq(
                StreamKind::Stdout,
                0,
                "base64",
                "not valid base64 !!!",
                false,
            )),
            StreamFrame::Finished(finished(Some(0), None)),
        ];
        let mut out = Vec::new();
        let mut err = Vec::new();
        let outcome = render_stream_with(frames, config, &mut out, &mut err).unwrap();
        assert!(outcome.integrity_failure);
        let stderr = String::from_utf8(err).unwrap();
        assert!(stderr.contains("invalid base64 payload"), "got: {stderr}");
    }

    #[test]
    fn strict_mode_fails_on_sha256_mismatch() {
        // A chunk whose declared sha256 does not match its bytes is invalid.
        let config = RenderConfig {
            strict: true,
            ..Default::default()
        };
        let mut bad = chunk_seq(StreamKind::Stdout, 0, "utf-8", "hello\n", false);
        bad.sha256 = Some("AAAA".to_string());
        let frames = vec![
            StreamFrame::Chunk(bad),
            StreamFrame::Finished(finished(Some(0), None)),
        ];
        let mut out = Vec::new();
        let mut err = Vec::new();
        let outcome = render_stream_with(frames, config, &mut out, &mut err).unwrap();
        assert!(outcome.integrity_failure);
        assert!(String::from_utf8(err)
            .unwrap()
            .contains("sha256 digest mismatch"));
    }

    #[test]
    fn strict_mode_accepts_matching_sha256() {
        // A correct sha256 digest passes strict validation.
        use base64::Engine as _;
        use sha2::{Digest as _, Sha256};
        let data = "hello\n";
        let digest =
            base64::engine::general_purpose::STANDARD.encode(Sha256::digest(data.as_bytes()));
        let config = RenderConfig {
            strict: true,
            ..Default::default()
        };
        let mut good = chunk_seq(StreamKind::Stdout, 0, "utf-8", data, false);
        good.sha256 = Some(digest);
        let frames = vec![
            StreamFrame::Chunk(good),
            StreamFrame::Finished(finished(Some(0), None)),
        ];
        let mut out = Vec::new();
        let mut err = Vec::new();
        let outcome = render_stream_with(frames, config, &mut out, &mut err).unwrap();
        assert!(!outcome.integrity_failure);
        assert_eq!(String::from_utf8(out).unwrap(), data);
    }

    #[test]
    fn reorder_buffer_orders_and_reports_missing() {
        let mut buf = ReorderBuffer::new(2);
        let mut missing = Vec::new();

        // seq 1 buffered ahead; nothing ready yet.
        let ready = buf.accept(
            chunk_seq(StreamKind::Stdout, 1, "utf-8", "b\n", false),
            &mut missing,
        );
        assert!(ready.is_empty());
        assert!(missing.is_empty());

        // seq 0 fills the gap and releases both, in order.
        let ready = buf.accept(
            chunk_seq(StreamKind::Stdout, 0, "utf-8", "a\n", false),
            &mut missing,
        );
        let datas: Vec<String> = ready.iter().map(|c| c.data.clone()).collect();
        assert_eq!(datas, vec!["a\n", "b\n"]);
        assert!(missing.is_empty());

        // Replay of seq 0 is suppressed.
        let ready = buf.accept(
            chunk_seq(StreamKind::Stdout, 0, "utf-8", "a\n", false),
            &mut missing,
        );
        assert!(ready.is_empty());

        // A different stream has independent sequence state.
        let ready = buf.accept(
            chunk_seq(StreamKind::Stderr, 0, "utf-8", "e\n", false),
            &mut missing,
        );
        assert_eq!(ready.len(), 1);
        assert!(missing.is_empty());
    }
}
