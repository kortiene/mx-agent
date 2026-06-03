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

use std::collections::{HashMap, HashSet};
use std::io::{self, Write};

use mx_agent_protocol::schema::{ExecFinished, StreamChunk, StreamKind};

/// Local exit code used when the stream ends without an `exec.finished` frame
/// (architecture §5.3: protocol/network failure).
pub const EXIT_PROTOCOL_FAILURE: u8 = 128;

/// One frame in the forwarded exec stream.
#[derive(Debug, Clone)]
pub enum StreamFrame {
    /// A chunk of stdout/stderr output.
    Chunk(StreamChunk),
    /// The terminal frame carrying the remote exit status.
    Finished(ExecFinished),
}

/// Per-stream sequence state used to suppress duplicate or replayed chunks.
///
/// The daemon tags every chunk with a monotonic, per-stream sequence number
/// (see the daemon `stream` module). At-least-once federated delivery means the
/// CLI can observe a chunk more than once, or observe chunks out of order. To
/// keep terminal output faithful, the renderer must render each `(stream, seq)`
/// pair **exactly once**.
///
/// State is kept independently per [`StreamKind`] so stdout and stderr each have
/// their own monotonic sequence space, matching the producer. For each stream
/// we track the next contiguous sequence number expected plus a small set of
/// already-accepted sequence numbers that arrived ahead of that boundary; the
/// set stays empty under in-order delivery and bounded by the reorder window
/// otherwise.
#[derive(Debug, Default)]
pub struct SequenceTracker {
    streams: HashMap<StreamKind, StreamSeqState>,
}

#[derive(Debug, Default)]
struct StreamSeqState {
    /// Lowest sequence number not yet accepted contiguously.
    next_expected: u64,
    /// Accepted sequence numbers at or above `next_expected` (gaps ahead).
    ahead: HashSet<u64>,
}

impl SequenceTracker {
    /// Create an empty tracker with no per-stream state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record `seq` for `stream`, returning `true` if it is the first time this
    /// `(stream, seq)` pair has been seen and `false` if it is a duplicate.
    ///
    /// A `false` return means the caller should drop the chunk so it does not
    /// produce duplicate terminal output. Out-of-order arrivals are accepted
    /// (returning `true`) the first time and suppressed on any replay.
    pub fn accept(&mut self, stream: StreamKind, seq: u64) -> bool {
        let state = self.streams.entry(stream).or_default();
        if seq < state.next_expected || state.ahead.contains(&seq) {
            // Already delivered: either below the contiguous boundary or
            // recorded as an out-of-order arrival.
            return false;
        }
        if seq == state.next_expected {
            // Advance the boundary, draining any contiguous run buffered ahead.
            state.next_expected += 1;
            while state.ahead.remove(&state.next_expected) {
                state.next_expected += 1;
            }
        } else {
            // Arrived ahead of the boundary; remember it to suppress replays.
            state.ahead.insert(seq);
        }
        true
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

/// Render a forwarded exec stream, returning the resolved exit code.
///
/// Writes each chunk to `out`/`err`, stops at the first [`StreamFrame::Finished`]
/// and returns its resolved exit code. Returns `None` if the stream ends
/// without a finished frame, which the caller should treat as
/// [`EXIT_PROTOCOL_FAILURE`].
pub fn render_stream<I, O, E>(frames: I, out: &mut O, err: &mut E) -> io::Result<Option<u8>>
where
    I: IntoIterator<Item = StreamFrame>,
    O: Write,
    E: Write,
{
    let mut code = None;
    let mut tracker = SequenceTracker::new();
    for frame in frames {
        match frame {
            StreamFrame::Chunk(chunk) => {
                // Suppress duplicate/replayed chunks so terminal output is not
                // duplicated; sequence state is tracked per stream.
                if tracker.accept(chunk.stream, chunk.seq) {
                    render_chunk(&chunk, out, err)?;
                }
            }
            StreamFrame::Finished(finished) => {
                code = Some(resolve_exit_code(&finished));
                break;
            }
        }
    }
    out.flush()?;
    err.flush()?;
    Ok(code)
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
        let code = render_stream(frames, &mut out, &mut err).unwrap();
        assert_eq!(code, Some(0));
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
        let code = render_stream(frames, &mut out, &mut err).unwrap();
        assert_eq!(code, Some(1));
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
        let code = render_stream(frames, &mut out, &mut err).unwrap();
        assert_eq!(code, None);
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
        let code = render_stream(frames, &mut out, &mut err).unwrap();
        assert_eq!(code, Some(7));
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
        let code = render_stream(frames, &mut out, &mut err).unwrap();
        assert_eq!(code, Some(0));
        assert_eq!(String::from_utf8(out).unwrap(), "line one\nline two\n");
    }

    #[test]
    fn out_of_order_chunks_are_each_rendered_once() {
        // Acceptance: sequence state is tracked per stream; out-of-order input
        // is accepted once and replays are suppressed.
        let frames = vec![
            StreamFrame::Chunk(chunk_seq(StreamKind::Stdout, 1, "utf-8", "second\n", false)),
            StreamFrame::Chunk(chunk_seq(StreamKind::Stdout, 0, "utf-8", "first\n", false)),
            // Replays of both, now below/at the contiguous boundary.
            StreamFrame::Chunk(chunk_seq(StreamKind::Stdout, 1, "utf-8", "second\n", false)),
            StreamFrame::Chunk(chunk_seq(StreamKind::Stdout, 0, "utf-8", "first\n", false)),
            StreamFrame::Chunk(chunk_seq(StreamKind::Stdout, 2, "utf-8", "third\n", false)),
            StreamFrame::Finished(finished(Some(0), None)),
        ];
        let mut out = Vec::new();
        let mut err = Vec::new();
        render_stream(frames, &mut out, &mut err).unwrap();
        // Rendered in arrival order, but each (stream, seq) exactly once.
        assert_eq!(String::from_utf8(out).unwrap(), "second\nfirst\nthird\n");
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
    fn tracker_reports_first_sight_and_duplicates() {
        let mut tracker = SequenceTracker::new();
        assert!(tracker.accept(StreamKind::Stdout, 0));
        assert!(!tracker.accept(StreamKind::Stdout, 0));
        // Out-of-order: seq 2 accepted, then the gap (seq 1) accepted.
        assert!(tracker.accept(StreamKind::Stdout, 2));
        assert!(!tracker.accept(StreamKind::Stdout, 2));
        assert!(tracker.accept(StreamKind::Stdout, 1));
        assert!(!tracker.accept(StreamKind::Stdout, 1));
        // Contiguous boundary advanced past 2, so its replay is suppressed.
        assert!(!tracker.accept(StreamKind::Stdout, 2));
        // A different stream has independent state.
        assert!(tracker.accept(StreamKind::Stderr, 0));
    }
}
