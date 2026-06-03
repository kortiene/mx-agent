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
    for frame in frames {
        match frame {
            StreamFrame::Chunk(chunk) => render_chunk(&chunk, out, err)?,
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
        StreamChunk {
            invocation_id: "inv_1".to_string(),
            stream,
            seq: 0,
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
            StreamFrame::Chunk(chunk(
                StreamKind::Stdout,
                "utf-8",
                "PASS src/foo.test.ts\n",
                false,
            )),
            StreamFrame::Chunk(chunk(
                StreamKind::Stderr,
                "utf-8",
                "warning: deprecated\n",
                false,
            )),
            StreamFrame::Chunk(chunk(StreamKind::Stdout, "utf-8", "1 passing\n", false)),
            StreamFrame::Chunk(chunk(StreamKind::Stdout, "utf-8", "", true)), // EOF marker
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
            StreamFrame::Chunk(chunk(StreamKind::Stdout, "utf-8", "before\n", false)),
            StreamFrame::Finished(finished(Some(7), None)),
            StreamFrame::Chunk(chunk(StreamKind::Stdout, "utf-8", "after\n", false)),
        ];
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = render_stream(frames, &mut out, &mut err).unwrap();
        assert_eq!(code, Some(7));
        assert_eq!(String::from_utf8(out).unwrap(), "before\n");
    }
}
