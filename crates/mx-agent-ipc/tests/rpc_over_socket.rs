//! End-to-end IPC test: a server thread on a real Unix socket, a client, and a
//! raw malformed-frame probe.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::thread;

use mx_agent_ipc::frame::{read_frame, write_frame};
use mx_agent_ipc::rpc::{Request, Response, METHOD_NOT_FOUND, PARSE_ERROR};
use mx_agent_ipc::{bind, serve, Client};
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
