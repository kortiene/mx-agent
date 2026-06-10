//! End-to-end IPC test: a server thread on a real Unix socket, a client, and a
//! raw malformed-frame probe.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use mx_agent_ipc::frame::{read_frame, write_frame};
use mx_agent_ipc::rpc::{Request, Response, METHOD_NOT_FOUND, PARSE_ERROR};
use mx_agent_ipc::{bind, serve, serve_streaming, verify_peer, Client, PeerCredCheck};
use serde_json::{json, Value};

fn temp_socket_dir() -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir =
        std::env::temp_dir().join(format!("mx-agent-ipc-it-{}-{}", std::process::id(), nanos));
    fs::create_dir_all(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

fn handler(req: &Request) -> Response {
    match req.method.as_str() {
        "ping" => Response::result(req.id.clone(), json!({"pong": true})),
        "echo" => Response::result(req.id.clone(), req.params.clone()),
        _ => Response::error(req.id.clone(), METHOD_NOT_FOUND, "unknown method"),
    }
}

#[test]
fn client_server_round_trip_and_malformed_frame() {
    let dir = temp_socket_dir();
    let path = dir.join("daemon.sock");

    let guard = bind(&path).expect("bind socket");
    let listener = guard.listener().try_clone().unwrap();
    let server = thread::spawn(move || {
        let _ = serve(&listener, handler);
    });

    // Two calls on one connection exercise multiple frames per stream.
    let mut client = Client::connect(&path).unwrap();

    let resp = client.call("ping", Value::Null).unwrap();
    assert_eq!(resp.result, Some(json!({"pong": true})));

    let resp = client.call("echo", json!({"hello": "world"})).unwrap();
    assert_eq!(resp.result, Some(json!({"hello": "world"})));

    let resp = client.call("nope", Value::Null).unwrap();
    assert!(resp.is_error());
    assert_eq!(resp.error.unwrap().code, METHOD_NOT_FOUND);

    drop(client);

    // A malformed frame must produce a controlled PARSE_ERROR response, not a
    // dropped connection or crash.
    let mut raw = UnixStream::connect(&path).unwrap();
    write_frame(&mut raw, b"{this is not json").unwrap();
    let bytes = read_frame(&mut raw).unwrap().expect("a response frame");
    let resp: Response = serde_json::from_slice(&bytes).unwrap();
    assert!(resp.is_error());
    assert_eq!(resp.error.unwrap().code, PARSE_ERROR);
    drop(raw);

    // Closing the socket ends the server loop when the process exits; for the
    // test we simply detach the server thread.
    drop(guard);
    let _ = server;
    let _ = fs::remove_dir_all(&dir);
}

/// Verify `verify_peer` on a real accepted socket (not a `socketpair()`).
///
/// On macOS `LOCAL_PEERCRED` can report stale credentials for `socketpair()`
/// pairs on some OS versions (issue #267). Using a real `bind`/`connect` pair
/// confirms the macOS (`LOCAL_PEERCRED`) and Linux (`SO_PEERCRED`) arms both
/// work in the accept path that `serve_streaming` uses.
#[test]
fn verify_peer_allowed_for_real_accepted_socket() {
    let dir = temp_socket_dir();
    let path = dir.join("p.sock");

    let listener = UnixListener::bind(&path).unwrap();
    let (tx, rx) = mpsc::channel();

    thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        tx.send(stream).unwrap();
    });

    let _client = UnixStream::connect(&path).unwrap();
    let server_stream = rx.recv_timeout(Duration::from_secs(5)).unwrap();

    // verify_peer is called on the accepted (server-side) stream — the same
    // call site as serve_streaming's accept loop.
    let check = verify_peer(&server_stream);

    // On platforms with SO_PEERCRED (Linux/Android) or LOCAL_PEERCRED
    // (macOS/iOS/FreeBSD/Dragonfly) the result must be Allowed with our own
    // UID, since the client is in the same process.
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "visionos",
        target_os = "freebsd",
        target_os = "dragonfly"
    ))]
    assert!(
        matches!(check, PeerCredCheck::Allowed { .. }),
        "expected Allowed on mechanism platform, got {check:?}"
    );

    // On all platforms the connection must be permitted.
    assert!(
        check.is_allowed(),
        "same-UID peer must be allowed, got {check:?}"
    );

    drop(_client);
    let _ = fs::remove_dir_all(&dir);
}

/// Verify that the full `serve_streaming` accept loop admits a same-UID client
/// end-to-end: peer check → gate → handler dispatch → response.
///
/// This exercises the platform-specific peer-credential path
/// (`SO_PEERCRED` on Linux, `LOCAL_PEERCRED` on macOS/BSD — issue #267)
/// through the real socket accept path, confirming the macOS arm is wired
/// into the server correctly and that a same-UID client reaches the handler.
#[test]
fn serve_streaming_peer_check_admits_same_uid_client() {
    let dir = temp_socket_dir();
    let path = dir.join("s.sock");

    let guard = bind(&path).expect("bind socket");
    let listener = guard.listener().try_clone().unwrap();

    thread::spawn(move || {
        let _ = serve_streaming(&listener, |req, stream| {
            let resp = match req.method.as_str() {
                "ping" => Response::result(req.id.clone(), json!({"pong": true})),
                _ => Response::error(req.id.clone(), METHOD_NOT_FOUND, "unknown"),
            };
            write_frame(stream, &serde_json::to_vec(&resp).unwrap())
        });
    });

    // Connect as the same UID; the peer check must return Allowed (or
    // Unsupported on no-mechanism platforms) so the handler is reached.
    let mut client = Client::connect(&path).unwrap();
    let resp = client
        .call("ping", Value::Null)
        .expect("request must succeed: peer check must have allowed the connection");
    assert_eq!(
        resp.result,
        Some(json!({"pong": true})),
        "handler must be reached past the peer check gate"
    );

    drop(client);
    drop(guard);
    let _ = fs::remove_dir_all(&dir);
}
