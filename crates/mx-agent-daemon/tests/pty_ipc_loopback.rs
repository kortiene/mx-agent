//! Loopback PTY-over-IPC round-trip tests (issue #238).
//!
//! These exercise [`mx_agent_daemon::run_pty_loopback`] end to end over a real
//! Unix-socket connection: the daemon allocates the pseudo-terminal, streams its
//! merged output as base64 `output` frames, and applies inbound `pty.stdin` /
//! `pty.resize` control frames — exactly the wire contract the CLI speaks.
//!
//! They allocate a real PTY (`openpt`). Some sandboxed/headless environments
//! cannot allocate one (`openpt` fails with `ENOTTY`, "Inappropriate ioctl for
//! device"); the tests probe for that and **skip** rather than fail there, while
//! running fully on Linux CI.

use std::io;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use base64::Engine as _;
use serde_json::{json, Value};

use mx_agent_daemon::{
    run_pty_loopback, ExecPtyParams, PtyResizeFrame, PtyServerFrame, PtySession, PtyStdinFrame,
    PtyWinsize, RunSpec, METHOD_PTY_RESIZE, METHOD_PTY_STDIN,
};
use mx_agent_ipc::{read_frame, write_frame, Request, Response};

/// Whether a PTY can be allocated in this environment. Headless/sandboxed hosts
/// (e.g. CI without a controlling tty on macOS) cannot, so PTY tests skip.
fn pty_available() -> bool {
    let spec = RunSpec {
        command: vec!["true".to_string()],
        cwd: PathBuf::from("/"),
        ..Default::default()
    };
    PtySession::spawn(&spec, PtyWinsize::default()).is_ok()
}

/// A unique throwaway socket path.
///
/// Uses `/tmp` directly rather than `std::env::temp_dir()` because on macOS
/// the latter resolves to `/var/folders/…/T/` (~48 chars), and the full path
/// would exceed the 103-char Unix socket limit (`SUN_LEN = 104` including the
/// null terminator).  `/tmp` is always short and available on every supported
/// Unix target.
fn socket_path(tag: &str) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    std::path::PathBuf::from("/tmp").join(format!(
        "mx-{}-{}-{}.sock",
        tag,
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed),
    ))
}

/// Spawn a one-shot loopback PTY server on `path`: accept one connection, read
/// the initial `exec.pty` request, and hand it to [`run_pty_loopback`].
fn spawn_server(path: PathBuf, params: ExecPtyParams) -> std::thread::JoinHandle<()> {
    let listener = UnixListener::bind(&path).expect("bind test socket");
    std::thread::spawn(move || {
        let (mut conn, _) = listener.accept().expect("accept connection");
        // The first frame is the `exec.pty` start request the client sent.
        let bytes = read_frame(&mut conn)
            .expect("read start frame")
            .expect("start frame present");
        let request: Request = serde_json::from_slice(&bytes).expect("parse start request");
        // The server side ignores the start params here (the test passes them in
        // directly) but echoes the request id, exactly as dispatch does.
        let _ = request;
        run_pty_loopback(&params, &mut conn, &Value::from(1_u64)).expect("run loopback pty");
    })
}

/// Send a JSON-RPC request frame to the daemon.
fn send_request(stream: &mut UnixStream, method: &str, params: Value) -> io::Result<()> {
    let request = Request::new(Value::Null, method, params);
    let bytes = serde_json::to_vec(&request).unwrap();
    write_frame(stream, &bytes)
}

/// Send a base64 `pty.stdin` frame carrying `data`.
fn send_stdin(stream: &mut UnixStream, data: &[u8]) -> io::Result<()> {
    let frame = PtyStdinFrame {
        data: base64::engine::general_purpose::STANDARD.encode(data),
    };
    send_request(
        stream,
        METHOD_PTY_STDIN,
        serde_json::to_value(frame).unwrap(),
    )
}

/// Read server frames until the terminal `finished`/`error` frame, returning the
/// accumulated merged output and the finished status.
fn collect(stream: &mut UnixStream) -> (Vec<u8>, PtyServerFrame) {
    let mut output = Vec::new();
    loop {
        let bytes = read_frame(stream)
            .expect("read server frame")
            .expect("server frame present before close");
        let response: Response = serde_json::from_slice(&bytes).expect("parse response");
        let result = response.result.expect("server frame carries a result");
        let frame: PtyServerFrame = serde_json::from_value(result).expect("parse pty frame");
        match frame {
            PtyServerFrame::Output { data } => {
                output.extend(
                    base64::engine::general_purpose::STANDARD
                        .decode(&data)
                        .unwrap(),
                );
            }
            terminal => return (output, terminal),
        }
    }
}

fn params(command: &[&str], rows: u16, cols: u16) -> ExecPtyParams {
    ExecPtyParams {
        room: None,
        agent: None,
        command: command.iter().map(|s| s.to_string()).collect(),
        cwd: Some(PathBuf::from("/")),
        rows,
        cols,
        task: None,
    }
}

#[test]
fn loopback_pty_round_trips_stdin_and_output() {
    if !pty_available() {
        eprintln!("skipping: no PTY available in this environment");
        return;
    }
    // `cat` echoes its input back over the merged PTY stream; an EOT byte at the
    // start of a line closes its stdin so it exits 0.
    let path = socket_path("roundtrip");
    let server = spawn_server(path.clone(), params(&["cat"], 24, 80));

    let mut client = UnixStream::connect(&path).expect("connect to test socket");
    send_request(&mut client, "exec.pty", json!({ "command": ["cat"] })).expect("send start");
    send_stdin(&mut client, b"ping\n").expect("send stdin");
    send_stdin(&mut client, b"\x04").expect("send eof");

    let (output, terminal) = collect(&mut client);
    let _ = std::fs::remove_file(&path);
    let _ = server.join();

    let text = String::from_utf8_lossy(&output);
    assert!(
        text.contains("ping"),
        "merged PTY output should echo stdin: {text:?}"
    );
    match terminal {
        PtyServerFrame::Finished { exit_code, .. } => {
            assert_eq!(exit_code, Some(0), "cat should exit 0 on EOF");
        }
        other => panic!("expected finished frame, got {other:?}"),
    }
}

#[test]
fn loopback_pty_propagates_resize() {
    if !pty_available() {
        eprintln!("skipping: no PTY available in this environment");
        return;
    }
    // Start at 24x80, resize to 50x132, then `stty size` (after a short delay so
    // the resize lands) prints the live dimensions over the PTY.
    let path = socket_path("resize");
    let server = spawn_server(
        path.clone(),
        params(&["sh", "-c", "sleep 0.3; stty size"], 24, 80),
    );

    let mut client = UnixStream::connect(&path).expect("connect to test socket");
    send_request(
        &mut client,
        "exec.pty",
        json!({ "command": ["sh", "-c", "sleep 0.3; stty size"], "rows": 24, "cols": 80 }),
    )
    .expect("send start");
    let resize = PtyResizeFrame {
        rows: 50,
        cols: 132,
        pixel_width: 0,
        pixel_height: 0,
    };
    send_request(
        &mut client,
        METHOD_PTY_RESIZE,
        serde_json::to_value(resize).unwrap(),
    )
    .expect("send resize");

    let (output, terminal) = collect(&mut client);
    let _ = std::fs::remove_file(&path);
    let _ = server.join();

    let text = String::from_utf8_lossy(&output);
    assert!(
        text.contains("50 132"),
        "resize should reach the child's terminal: {text:?}"
    );
    assert!(matches!(terminal, PtyServerFrame::Finished { .. }));
}
