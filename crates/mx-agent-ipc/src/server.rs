//! Blocking JSON-RPC server over a Unix domain socket.

use std::io;
use std::os::unix::net::{UnixListener, UnixStream};

use serde_json::Value;

use crate::frame::{read_frame, write_frame};
use crate::peercred::{verify_peer, PeerCredCheck};
use crate::rpc::{Request, Response, PARSE_ERROR};

/// Parse one frame's bytes into a [`Request`], dispatch it, and return the
/// [`Response`].
///
/// Malformed JSON yields a controlled `PARSE_ERROR` response (with a null id)
/// rather than an error or panic.
pub fn handle_message<F>(bytes: &[u8], handler: &F) -> Response
where
    F: Fn(&Request) -> Response,
{
    match serde_json::from_slice::<Request>(bytes) {
        Ok(request) => handler(&request),
        Err(e) => Response::error(Value::Null, PARSE_ERROR, format!("invalid request: {e}")),
    }
}

/// Serve a single connection until the peer closes it.
fn serve_connection<F>(mut stream: UnixStream, handler: &F) -> io::Result<()>
where
    F: Fn(&Request) -> Response,
{
    loop {
        let Some(bytes) = read_frame(&mut stream)? else {
            return Ok(());
        };
        let response = handle_message(&bytes, handler);
        let encoded = serde_json::to_vec(&response).unwrap_or_else(|_| {
            br#"{"jsonrpc":"2.0","id":null,"error":{"code":-32603,"message":"encode failure"}}"#
                .to_vec()
        });
        write_frame(&mut stream, &encoded)?;
    }
}

/// Accept connections on `listener` and dispatch each request through `handler`.
///
/// Connections are served sequentially. A failure on one connection is logged
/// and does not stop the server.
pub fn serve<F>(listener: &UnixListener, handler: F) -> io::Result<()>
where
    F: Fn(&Request) -> Response,
{
    let mut warned_unsupported = false;
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                match verify_peer(&stream) {
                    PeerCredCheck::Allowed { .. } => {}
                    PeerCredCheck::Denied {
                        peer_uid,
                        daemon_uid,
                    } => {
                        // Audit the rejection. Only UIDs are logged; no request
                        // contents or other peer data are read or recorded.
                        tracing::warn!(
                            peer_uid,
                            daemon_uid,
                            "rejecting ipc client: peer uid does not match daemon uid"
                        );
                        drop(stream);
                        continue;
                    }
                    PeerCredCheck::Unsupported => {
                        if !warned_unsupported {
                            warned_unsupported = true;
                            tracing::warn!(
                                "peer credential verification is unsupported on this platform; \
                                 relying on socket filesystem permissions (mode 0600)"
                            );
                        }
                    }
                }
                if let Err(e) = serve_connection(stream, &handler) {
                    tracing::debug!(error = %e, "ipc connection ended with error");
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "ipc accept failed");
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn handler(req: &Request) -> Response {
        match req.method.as_str() {
            "ping" => Response::result(req.id.clone(), json!({"pong": true})),
            _ => Response::error(req.id.clone(), crate::rpc::METHOD_NOT_FOUND, "unknown"),
        }
    }

    #[test]
    fn handles_valid_request() {
        let bytes = serde_json::to_vec(&Request::new(json!(7), "ping", Value::Null)).unwrap();
        let resp = handle_message(&bytes, &handler);
        assert_eq!(resp.id, json!(7));
        assert_eq!(resp.result, Some(json!({"pong": true})));
    }

    #[test]
    fn malformed_json_yields_parse_error() {
        let resp = handle_message(b"{not json", &handler);
        assert!(resp.is_error());
        assert_eq!(resp.error.unwrap().code, PARSE_ERROR);
        assert_eq!(resp.id, Value::Null);
    }

    #[test]
    fn unknown_method_yields_method_not_found() {
        let bytes = serde_json::to_vec(&Request::new(json!(1), "nope", Value::Null)).unwrap();
        let resp = handle_message(&bytes, &handler);
        assert_eq!(resp.error.unwrap().code, crate::rpc::METHOD_NOT_FOUND);
    }
}
