//! Blocking JSON-RPC client over a Unix domain socket.

use std::io;
use std::os::unix::net::UnixStream;
use std::path::Path;

use serde_json::Value;

use crate::frame::{read_frame, write_frame};
use crate::rpc::{Request, Response};

/// A connected IPC client.
#[derive(Debug)]
pub struct Client {
    stream: UnixStream,
    next_id: u64,
}

impl Client {
    /// Connect to a daemon socket.
    pub fn connect(path: impl AsRef<Path>) -> io::Result<Self> {
        let stream = UnixStream::connect(path)?;
        Ok(Self { stream, next_id: 1 })
    }

    /// Send a request and wait for the matching response.
    pub fn call(&mut self, method: &str, params: Value) -> io::Result<Response> {
        let id = self.next_id;
        self.next_id += 1;
        let request = Request::new(Value::from(id), method, params);
        self.send(&request)?;
        self.recv()
    }

    /// Send a raw request frame.
    pub fn send(&mut self, request: &Request) -> io::Result<()> {
        let bytes = serde_json::to_vec(request)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        write_frame(&mut self.stream, &bytes)
    }

    /// Receive one response frame.
    pub fn recv(&mut self) -> io::Result<Response> {
        let bytes = read_frame(&mut self.stream)?
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "connection closed"))?;
        serde_json::from_slice(&bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }
}
