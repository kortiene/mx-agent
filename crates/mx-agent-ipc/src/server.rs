//! Blocking JSON-RPC server over a Unix domain socket.

use std::io;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;

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

fn write_response(stream: &mut UnixStream, response: &Response) -> io::Result<()> {
    let encoded = serde_json::to_vec(response).unwrap_or_else(|_| {
        br#"{"jsonrpc":"2.0","id":null,"error":{"code":-32603,"message":"encode failure"}}"#
            .to_vec()
    });
    write_frame(stream, &encoded)
}

/// Serve a single connection with a handler that may write one or more response
/// frames for each request.
fn serve_streaming_connection<F>(stream: &mut UnixStream, handler: &F) -> io::Result<()>
where
    F: Fn(&Request, &mut UnixStream) -> io::Result<()>,
{
    loop {
        let Some(bytes) = read_frame(stream)? else {
            return Ok(());
        };
        match serde_json::from_slice::<Request>(&bytes) {
            Ok(request) => handler(&request, stream)?,
            Err(e) => {
                let response =
                    Response::error(Value::Null, PARSE_ERROR, format!("invalid request: {e}"));
                write_response(stream, &response)?;
            }
        }
    }
}

/// Accept connections on `listener` and dispatch each request through `handler`.
///
/// Connections are served sequentially. A failure on one connection is logged
/// and does not stop the server.
pub fn serve<F>(listener: &UnixListener, handler: F) -> io::Result<()>
where
    F: Fn(&Request) -> Response + Send + Sync + 'static,
{
    serve_streaming(listener, move |request, stream| {
        let response = handler(request);
        write_response(stream, &response)
    })
}

/// Decide whether an incoming connection should be accepted, logging once for
/// each noteworthy case.
///
/// Returns `true` when the connection may proceed, `false` when it must be
/// closed. The `warned_unsupported` flag is latched on the first
/// [`PeerCredCheck::Unsupported`] result so the "no peer-credential support"
/// warning is emitted exactly once per listener lifetime.
fn gate_peer_check(check: &PeerCredCheck, warned_unsupported: &mut bool) -> bool {
    match check {
        PeerCredCheck::Allowed { .. } => true,
        PeerCredCheck::Denied {
            peer_uid,
            daemon_uid,
        } => {
            // Audit the rejection. Only UIDs are logged; no request contents
            // or other peer data are read or recorded before this gate.
            tracing::warn!(
                peer_uid,
                daemon_uid,
                "rejecting ipc client: peer uid does not match daemon uid"
            );
            false
        }
        PeerCredCheck::Unsupported => {
            if !*warned_unsupported {
                *warned_unsupported = true;
                tracing::warn!(
                    "peer credential verification is unsupported on this platform; \
                     relying on socket filesystem permissions (mode 0600)"
                );
            }
            true
        }
    }
}

/// Accept connections on `listener` and dispatch each request through a handler
/// that may write multiple JSON-RPC response frames.
///
/// This preserves the normal request/one-response behavior for most methods and
/// allows long-lived streaming methods such as `task.watch` to send an initial
/// response followed by change responses on the same Unix-socket connection.
///
/// Each accepted connection is served on its own detached worker thread, so a
/// long-lived or parked connection (e.g. an interactive `device.verify.start`
/// awaiting an operator decision, or a `task.watch`/`exec.pty` stream) cannot
/// starve unrelated IPC methods on other connections (issue #258). The
/// peer-credential gate ([`verify_peer`]) stays on the accept thread, before any
/// worker is spawned, so concurrency does not weaken the UID check.
pub fn serve_streaming<F>(listener: &UnixListener, handler: F) -> io::Result<()>
where
    F: Fn(&Request, &mut UnixStream) -> io::Result<()> + Send + Sync + 'static,
{
    let handler = Arc::new(handler);
    let mut warned_unsupported = false;
    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                let check = verify_peer(&stream);
                if !gate_peer_check(&check, &mut warned_unsupported) {
                    drop(stream);
                    continue;
                }
                // Serve this connection on a detached worker so a long-held or
                // parked connection cannot block the accept loop or starve other
                // connections.
                let handler = Arc::clone(&handler);
                std::thread::spawn(move || {
                    if let Err(e) = serve_streaming_connection(&mut stream, &*handler) {
                        tracing::debug!(error = %e, "ipc connection ended with error");
                    }
                });
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

    // ── gate_peer_check unit tests ────────────────────────────────────────────

    #[test]
    fn gate_allows_allowed_peer_without_warning() {
        let check = PeerCredCheck::Allowed { uid: 1000 };
        let mut warned = false;
        assert!(gate_peer_check(&check, &mut warned));
        // Allowed connections must not set the unsupported-platform latch.
        assert!(!warned);
    }

    #[test]
    fn gate_rejects_denied_peer() {
        let check = PeerCredCheck::Denied {
            peer_uid: 999,
            daemon_uid: 1000,
        };
        let mut warned = false;
        assert!(!gate_peer_check(&check, &mut warned));
        // Denied does not touch the unsupported-platform latch.
        assert!(!warned);
    }

    #[test]
    fn gate_allows_unsupported_peer_and_latches_warn_once() {
        let mut warned = false;
        // First call: allowed, latch set to true.
        assert!(gate_peer_check(&PeerCredCheck::Unsupported, &mut warned));
        assert!(
            warned,
            "warned_unsupported must be latched after first Unsupported"
        );
        // Second call: still allowed, latch unchanged (warn fires only once).
        assert!(gate_peer_check(&PeerCredCheck::Unsupported, &mut warned));
        assert!(warned);
    }

    #[test]
    fn gate_allowed_after_unsupported_does_not_clear_latch() {
        let mut warned = false;
        gate_peer_check(&PeerCredCheck::Unsupported, &mut warned);
        assert!(warned);
        // An Allowed result must not reset the latch.
        gate_peer_check(&PeerCredCheck::Allowed { uid: 0 }, &mut warned);
        assert!(warned);
    }

    // ── serve_streaming integration tests ─────────────────────────────────────

    #[test]
    fn serve_streaming_concurrent_connections_do_not_block() {
        // Regression test for issue #258: a parked connection on one worker thread
        // must not prevent a second connection from being served.
        use crate::frame::{read_frame, write_frame};
        use std::os::unix::net::{UnixListener, UnixStream};
        use std::sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering},
            Arc,
        };
        use std::time::Duration;

        static CTR: AtomicUsize = AtomicUsize::new(0);
        let n = CTR.fetch_add(1, Ordering::Relaxed);
        let socket_path =
            std::env::temp_dir().join(format!("mx_ipc_conc_{}_{}.sock", std::process::id(), n));
        if socket_path.exists() {
            std::fs::remove_file(&socket_path).ok();
        }
        let listener = UnixListener::bind(&socket_path).unwrap();
        let server_listener = listener.try_clone().unwrap();

        let handler_started = Arc::new(AtomicBool::new(false));
        let handler_released = Arc::new(AtomicBool::new(false));
        let started = Arc::clone(&handler_started);
        let released = Arc::clone(&handler_released);

        std::thread::spawn(move || {
            serve_streaming(&server_listener, move |req, stream| {
                if req.method == "slow" {
                    started.store(true, Ordering::SeqCst);
                    while !released.load(Ordering::SeqCst) {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                }
                let resp = Response::result(req.id.clone(), Value::Null);
                let bytes = serde_json::to_vec(&resp).unwrap();
                write_frame(stream, &bytes)?;
                Ok(())
            })
            .ok();
        });

        // Connection 1: parks its worker thread with a "slow" request.
        let mut conn1 = UnixStream::connect(&socket_path).unwrap();
        let req1 = Request::new(json!(1), "slow", Value::Null);
        write_frame(&mut conn1, &serde_json::to_vec(&req1).unwrap()).unwrap();

        // Wait until connection 1's handler has actually started.
        while !handler_started.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(1));
        }

        // Connection 2: must be served while connection 1 is still parked.
        let mut conn2 = UnixStream::connect(&socket_path).unwrap();
        let req2 = Request::new(json!(2), "fast", Value::Null);
        write_frame(&mut conn2, &serde_json::to_vec(&req2).unwrap()).unwrap();
        conn2
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let frame2 = read_frame(&mut conn2)
            .expect("read error on connection 2")
            .expect(
                "connection 2 got EOF — concurrent connections must not be blocked (issue #258)",
            );
        let resp2: Response = serde_json::from_slice(&frame2).unwrap();
        assert!(
            !resp2.is_error(),
            "connection 2 response must not be an error"
        );

        // Release connection 1 and confirm it also completes.
        handler_released.store(true, Ordering::SeqCst);
        conn1
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let frame1 = read_frame(&mut conn1)
            .expect("read error on connection 1")
            .expect("connection 1 must complete after release");
        let resp1: Response = serde_json::from_slice(&frame1).unwrap();
        assert!(
            !resp1.is_error(),
            "connection 1 response must not be an error"
        );

        std::fs::remove_file(&socket_path).ok();
    }
}
