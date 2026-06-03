//! Length-delimited framing for IPC messages.
//!
//! Each frame is a 4-byte big-endian length prefix followed by exactly that
//! many payload bytes. This lets multiple JSON-RPC messages share one stream
//! and bounds the work done before a full message is available.

use std::io::{self, Read, Write};

/// Maximum allowed frame payload size (16 MiB).
pub const MAX_FRAME_LEN: usize = 16 * 1024 * 1024;

fn invalid_data(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.to_string())
}

/// Write a single length-delimited frame.
///
/// Returns [`io::ErrorKind::InvalidData`] if `payload` exceeds
/// [`MAX_FRAME_LEN`].
pub fn write_frame<W: Write>(writer: &mut W, payload: &[u8]) -> io::Result<()> {
    if payload.len() > MAX_FRAME_LEN {
        return Err(invalid_data("frame exceeds maximum length"));
    }
    let len = u32::try_from(payload.len()).map_err(|_| invalid_data("frame too large"))?;
    writer.write_all(&len.to_be_bytes())?;
    writer.write_all(payload)?;
    writer.flush()
}

/// Read up to `buf.len()` bytes, returning how many were read before EOF.
fn fill(reader: &mut impl Read, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..])? {
            0 => break,
            n => filled += n,
        }
    }
    Ok(filled)
}

/// Read a single length-delimited frame.
///
/// Returns:
/// - `Ok(Some(payload))` for a complete frame,
/// - `Ok(None)` on a clean end of stream before any bytes of a new frame,
/// - `Err(..)` for a truncated length prefix, a truncated body, or a frame
///   larger than [`MAX_FRAME_LEN`].
pub fn read_frame<R: Read>(reader: &mut R) -> io::Result<Option<Vec<u8>>> {
    let mut len_buf = [0u8; 4];
    match fill(reader, &mut len_buf)? {
        0 => return Ok(None),
        4 => {}
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated frame length prefix",
            ))
        }
    }

    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME_LEN {
        return Err(invalid_data("frame exceeds maximum length"));
    }

    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload).map_err(|e| {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            io::Error::new(io::ErrorKind::UnexpectedEof, "truncated frame body")
        } else {
            e
        }
    })?;
    Ok(Some(payload))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn round_trips_multiple_frames() {
        let mut buf = Vec::new();
        write_frame(&mut buf, b"first").unwrap();
        write_frame(&mut buf, b"second").unwrap();

        let mut cursor = Cursor::new(buf);
        assert_eq!(
            read_frame(&mut cursor).unwrap().as_deref(),
            Some(&b"first"[..])
        );
        assert_eq!(
            read_frame(&mut cursor).unwrap().as_deref(),
            Some(&b"second"[..])
        );
        assert_eq!(read_frame(&mut cursor).unwrap(), None);
    }

    #[test]
    fn clean_eof_returns_none() {
        let mut cursor = Cursor::new(Vec::new());
        assert_eq!(read_frame(&mut cursor).unwrap(), None);
    }

    #[test]
    fn truncated_length_prefix_errors() {
        let mut cursor = Cursor::new(vec![0u8, 0u8]);
        let err = read_frame(&mut cursor).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn truncated_body_errors() {
        // Claims 5 bytes but only 3 follow.
        let mut cursor = Cursor::new(vec![0, 0, 0, 5, 1, 2, 3]);
        let err = read_frame(&mut cursor).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn oversize_frame_is_rejected_without_allocating() {
        // Length prefix 0xFFFFFFFF (~4 GiB) must be rejected up front.
        let mut cursor = Cursor::new(vec![0xFF, 0xFF, 0xFF, 0xFF]);
        let err = read_frame(&mut cursor).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn empty_payload_round_trips() {
        let mut buf = Vec::new();
        write_frame(&mut buf, b"").unwrap();
        let mut cursor = Cursor::new(buf);
        assert_eq!(read_frame(&mut cursor).unwrap().as_deref(), Some(&b""[..]));
    }
}
