//! End-to-end IPC tests for the `device.verify.start` in-band decision flow
//! (issue #259) and the timeout / concurrency fix (issue #258).
//!
//! These tests exercise the critical-path behavior at the IPC + dispatch level,
//! **without requiring a live Matrix homeserver**. They simulate the
//! `dispatch_device_verify` handler's phase-2 behavior: the handler streams
//! `Started` and `EmojiReady` frames, then calls [`read_verify_decision`] with
//! a bounded timeout and writes a terminal frame.
//!
//! Four scenarios are covered:
//!
//! 1. **Decision timeout → `Cancelled` frame.** A client connects, sends
//!    `device.verify.start`, and never sends a confirm/cancel decision.
//!    `read_verify_decision` fires its deadline and returns `Cancel`; the
//!    handler must write a `Cancelled` frame back to the client. This confirms
//!    the fail-safe property: a stalled operator can never be mistaken for an
//!    approval, and the connection is released once the deadline passes.
//!
//! 2. **Decision-wait phase does not block concurrent IPC requests.** While
//!    one connection is parked in `read_verify_decision` (simulating a 30 s
//!    operator timeout), a second connection must be served promptly. This
//!    directly encodes the acceptance criterion from issue #258: "does not
//!    block a concurrent IPC request". It validates the thread-per-connection
//!    fix in [`mx_agent_ipc::serve_streaming`].
//!
//! 3. **In-band `confirm` → `Confirmed` frame (issue #259 happy path).** A
//!    client sends `device.verify.start`, receives `Started` and `EmojiReady`,
//!    then sends a bare `confirm` control frame **on the same connection**. The
//!    handler must respond with a `Confirmed` terminal frame. This validates the
//!    in-band-only decision design: the standalone `device.verify.confirm` IPC
//!    method was removed in issue #259; the operator must use the held-open
//!    connection instead.
//!
//! 4. **In-band `cancel` → `Cancelled` frame promptly (issue #259 cancel path).**
//!    An explicit `cancel` control frame on the held-open connection must
//!    produce a `Cancelled` terminal frame without waiting for the full decision
//!    timeout. This guards the UX contract: an operator who decides to cancel
//!    early should not be forced to sit out the 300 s deadline.
//!
//! None of these tests require Docker, a Matrix homeserver, or any external
//! service. All run as part of the default `cargo test --all`.

use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use mx_agent_daemon::{read_verify_decision, DeviceVerifyFrame, VerifyDecision};
use mx_agent_ipc::{read_frame, serve_streaming, write_frame, Request, Response};

/// Short decision deadline used in tests so we don't have to wait 300 s.
const TEST_DECISION_TIMEOUT_MS: u64 = 120;

/// Upper bound on how long each test may run in total.
const TEST_WALL_LIMIT: Duration = Duration::from_secs(10);

static SOCKET_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Return a unique throwaway socket path under `/tmp`.
///
/// Uses `/tmp` directly rather than `std::env::temp_dir()` because on macOS
/// the latter expands to `/var/folders/…/T/` (~48 chars), and the full path
/// would exceed the 103-char Unix socket limit.
fn tmp_socket(tag: &str) -> std::path::PathBuf {
    std::path::PathBuf::from("/tmp").join(format!(
        "mx-dv258-{}-{}-{}.sock",
        tag,
        std::process::id(),
        SOCKET_COUNTER.fetch_add(1, Ordering::Relaxed),
    ))
}

/// Write a `DeviceVerifyFrame` as a JSON-RPC result frame on `stream`.
fn write_verify_frame(
    stream: &mut UnixStream,
    req_id: &Value,
    frame: &DeviceVerifyFrame,
) -> std::io::Result<()> {
    let payload = serde_json::to_value(frame).expect("serialize DeviceVerifyFrame");
    let response = Response::result(req_id.clone(), payload);
    let bytes = serde_json::to_vec(&response).expect("serialize Response");
    write_frame(stream, &bytes)
}

/// Simulate the phase-2 decision-wait portion of `dispatch_device_verify`:
///
/// 1. Emit a `Started` frame.
/// 2. Emit an `EmojiReady` frame (decimals only, no emoji — keeps the mock
///    simple and doesn't require any Matrix SAS material).
/// 3. Call [`read_verify_decision`] with `timeout`.
/// 4. Emit the appropriate terminal frame (`Cancelled` or `Confirmed`).
///
/// This mirrors what the real handler does after `run_device_verify` drives
/// phases 1–2 through the Matrix SDK.
fn run_mock_verify_handler(
    stream: &mut UnixStream,
    req_id: &Value,
    timeout: Duration,
) -> std::io::Result<()> {
    write_verify_frame(
        stream,
        req_id,
        &DeviceVerifyFrame::Started {
            flow_id: "mock-flow-1".to_string(),
        },
    )?;
    write_verify_frame(
        stream,
        req_id,
        &DeviceVerifyFrame::EmojiReady {
            flow_id: "mock-flow-1".to_string(),
            emoji: None,
            decimals: Some((111, 222, 333)),
        },
    )?;

    // Phase-2 decision wait — the core of the issue #258 fix.
    let decision = read_verify_decision(stream, timeout);
    match decision {
        VerifyDecision::Cancel => write_verify_frame(
            stream,
            req_id,
            &DeviceVerifyFrame::Cancelled {
                flow_id: "mock-flow-1".to_string(),
            },
        ),
        VerifyDecision::Confirm => write_verify_frame(
            stream,
            req_id,
            &DeviceVerifyFrame::Confirmed {
                flow_id: "mock-flow-1".to_string(),
            },
        ),
    }
}

// ---------------------------------------------------------------------------
// Test 1 — timeout fires Cancel and the client receives a Cancelled frame
// ---------------------------------------------------------------------------

/// A `device.verify.start` whose operator never sends a decision must receive a
/// `Cancelled` terminal frame after the deadline.
///
/// Acceptance criterion from issue #258:
/// > a `device.verify.start` that never receives a decision cancels after the
/// > deadline
///
/// The test uses a `TEST_DECISION_TIMEOUT_MS`-millisecond deadline instead of
/// the production 300 s so it completes in well under a second.
#[test]
fn verify_decision_timeout_emits_cancelled_frame() {
    let path = tmp_socket("timeout");
    let listener = UnixListener::bind(&path).expect("bind test socket");
    let socket_path = path.clone();
    let timeout = Duration::from_millis(TEST_DECISION_TIMEOUT_MS);

    // Spawn a one-shot server: accept one connection, run the mock verify handler.
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let bytes = read_frame(&mut stream)
            .expect("read request frame")
            .expect("request frame present");
        let req: Request = serde_json::from_slice(&bytes).expect("parse request");
        run_mock_verify_handler(&mut stream, &req.id, timeout).expect("mock verify handler");
    });

    let mut client = UnixStream::connect(&path).expect("connect to test socket");
    client
        .set_read_timeout(Some(TEST_WALL_LIMIT))
        .expect("set client read timeout");

    // Send a device.verify.start request.
    let request = Request::new(
        json!(1),
        "device.verify.start",
        json!({"user": "@peer:test.local", "device": "PEERDEV"}),
    );
    write_frame(
        &mut client,
        &serde_json::to_vec(&request).expect("serialize request"),
    )
    .expect("send request frame");

    // Collect all frames until we reach a terminal one.
    let started_at = Instant::now();
    let mut frames: Vec<DeviceVerifyFrame> = Vec::new();
    loop {
        let raw = read_frame(&mut client)
            .expect("read response frame")
            .expect("frame present (server must not close before sending Cancelled)");
        let resp: Response = serde_json::from_slice(&raw).expect("parse Response");
        let frame: DeviceVerifyFrame = serde_json::from_value(
            resp.result
                .expect("response must carry a result, not an error"),
        )
        .expect("parse DeviceVerifyFrame");
        let is_terminal = matches!(
            frame,
            DeviceVerifyFrame::Cancelled { .. }
                | DeviceVerifyFrame::Confirmed { .. }
                | DeviceVerifyFrame::Error { .. }
        );
        frames.push(frame);
        if is_terminal {
            break;
        }
        assert!(
            started_at.elapsed() < TEST_WALL_LIMIT,
            "test wall-clock limit reached while waiting for terminal frame"
        );
    }

    // The handler must have waited at least the deadline before responding.
    let elapsed = started_at.elapsed();
    assert!(
        elapsed >= timeout,
        "handler returned in {elapsed:?}, less than the {timeout:?} deadline — \
         timeout must actually fire before returning Cancel",
    );

    // Frame sequence: Started → EmojiReady → Cancelled (fail-safe on timeout).
    assert!(
        frames.len() >= 3,
        "expected at least 3 frames (Started, EmojiReady, Cancelled), got {}: {frames:?}",
        frames.len(),
    );
    assert!(
        matches!(frames[0], DeviceVerifyFrame::Started { .. }),
        "first frame must be Started, got {:?}",
        frames[0],
    );
    assert!(
        matches!(frames[1], DeviceVerifyFrame::EmojiReady { .. }),
        "second frame must be EmojiReady, got {:?}",
        frames[1],
    );
    assert!(
        matches!(frames.last().unwrap(), DeviceVerifyFrame::Cancelled { .. }),
        "terminal frame must be Cancelled (timeout must fail safe to cancel, not confirm), \
         got {:?}",
        frames.last().unwrap(),
    );

    std::fs::remove_file(&socket_path).ok();
}

// ---------------------------------------------------------------------------
// Test 2 — concurrent IPC is not blocked while one verify connection waits
// ---------------------------------------------------------------------------

/// A connection parked in the `device.verify.start` decision-wait phase must
/// not starve concurrent IPC requests on other connections.
///
/// Acceptance criterion from issue #258:
/// > a `device.verify.start` … does not block a concurrent IPC request
///
/// This test uses the real [`mx_agent_ipc::serve_streaming`] function (the
/// same one the production daemon uses) and validates that the thread-per-
/// connection model introduced by the fix allows a second connection to be
/// served while the first is parked in `read_verify_decision`.
#[test]
fn verify_decision_wait_does_not_block_concurrent_ipc() {
    let path = tmp_socket("concurrent");
    let listener = UnixListener::bind(&path).expect("bind test socket");
    let socket_path = path.clone();

    // Long decision timeout — the connection should stay parked for up to 30 s;
    // the test drives it to EOF/Cancel before that by closing the client socket.
    let long_timeout = Duration::from_secs(30);

    // Spawn the serve_streaming server in a background thread.
    std::thread::spawn(move || {
        serve_streaming(&listener, move |req, stream| {
            if req.method == "device.verify.start" {
                // Simulate the decision-wait phase: write two streaming frames,
                // then block until the decision arrives or the deadline fires.
                let req_id = req.id.clone();
                write_verify_frame(
                    stream,
                    &req_id,
                    &DeviceVerifyFrame::Started {
                        flow_id: "mock-flow-2".to_string(),
                    },
                )?;
                write_verify_frame(
                    stream,
                    &req_id,
                    &DeviceVerifyFrame::EmojiReady {
                        flow_id: "mock-flow-2".to_string(),
                        emoji: None,
                        decimals: Some((100, 200, 300)),
                    },
                )?;
                // Block here for up to 30 s.  The client will drop the connection
                // (triggering an EOF → Cancel) shortly after.
                let decision = read_verify_decision(stream, long_timeout);
                let terminal = match decision {
                    VerifyDecision::Cancel => DeviceVerifyFrame::Cancelled {
                        flow_id: "mock-flow-2".to_string(),
                    },
                    VerifyDecision::Confirm => DeviceVerifyFrame::Confirmed {
                        flow_id: "mock-flow-2".to_string(),
                    },
                };
                // Best-effort write — the client may have already closed.
                let _ = write_verify_frame(stream, &req_id, &terminal);
                Ok(())
            } else {
                // All other methods: respond immediately.
                let resp = Response::result(req.id.clone(), json!({"ok": true}));
                let bytes = serde_json::to_vec(&resp).expect("serialize response");
                write_frame(stream, &bytes)
            }
        })
        .ok();
    });

    // --- Connection 1: device.verify.start (parks in decision-wait) ---
    let mut conn1 = UnixStream::connect(&path).expect("connect conn1");
    conn1
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set conn1 read timeout");

    let req1 = Request::new(
        json!(10),
        "device.verify.start",
        json!({"user": "@peer:test.local", "device": "DEV1"}),
    );
    write_frame(
        &mut conn1,
        &serde_json::to_vec(&req1).expect("serialize req1"),
    )
    .expect("write req1");

    // Drain frames until we reach EmojiReady — at that point the server-side
    // worker is blocked in read_verify_decision.
    let mut saw_emoji_ready = false;
    for _ in 0..10 {
        let raw = read_frame(&mut conn1)
            .expect("read conn1 frame")
            .expect("conn1 frame present");
        let resp: Response = serde_json::from_slice(&raw).expect("parse conn1 response");
        if let Some(payload) = resp.result {
            if let Ok(frame) = serde_json::from_value::<DeviceVerifyFrame>(payload) {
                if matches!(frame, DeviceVerifyFrame::EmojiReady { .. }) {
                    saw_emoji_ready = true;
                    break;
                }
            }
        }
    }
    assert!(
        saw_emoji_ready,
        "connection 1 must receive an EmojiReady frame before the concurrent test"
    );

    // --- Connection 2: any other method, must be served promptly ---
    // Connection 1's worker is now parked in read_verify_decision.  Open a new
    // connection and send a generic request; it must be answered before
    // connection 1's 30 s timeout fires.
    let mut conn2 = UnixStream::connect(&path).expect("connect conn2");
    conn2
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set conn2 read timeout");

    let req2 = Request::new(json!(20), "daemon.status", Value::Null);
    write_frame(
        &mut conn2,
        &serde_json::to_vec(&req2).expect("serialize req2"),
    )
    .expect("write req2");

    let before = Instant::now();
    let raw2 = read_frame(&mut conn2).expect("read conn2 frame").expect(
        "connection 2 must be served even while connection 1 is in the \
             device.verify.start decision-wait phase (issue #258 regression)",
    );
    let latency = before.elapsed();

    let resp2: Response = serde_json::from_slice(&raw2).expect("parse conn2 response");
    assert!(
        !resp2.is_error(),
        "connection 2 response must not be an error; got: {:?}",
        resp2.error,
    );
    assert!(
        latency < Duration::from_secs(3),
        "connection 2 must be served promptly (< 3 s) while connection 1 is parked; \
         took {latency:?} — if this fails, the thread-per-connection fix in \
         serve_streaming may have regressed (issue #258)",
    );

    // Drop both connections — conn1's worker will see EOF and return.
    drop(conn1);
    drop(conn2);

    std::fs::remove_file(&socket_path).ok();
}

// ---------------------------------------------------------------------------
// Test 3 — in-band `confirm` produces a `Confirmed` terminal frame
// ---------------------------------------------------------------------------

/// A bare `confirm` control frame sent **on the same held-open connection** as
/// `device.verify.start` must produce a `Confirmed` terminal frame.
///
/// This is the in-band happy path for issue #259: after the standalone
/// `device.verify.confirm` IPC method was removed, the operator's only way to
/// confirm a SAS flow is to send a bare `confirm` frame on the streaming
/// connection itself. This test ensures that path works end-to-end.
#[test]
fn verify_inband_confirm_emits_confirmed_frame() {
    let path = tmp_socket("inband-confirm");
    let listener = UnixListener::bind(&path).expect("bind test socket");
    let socket_path = path.clone();

    // Use a long timeout so the test cannot accidentally hit it.
    let long_timeout = Duration::from_secs(30);

    // Spawn a one-shot server: accept one connection, run the mock verify handler.
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let bytes = read_frame(&mut stream)
            .expect("read request frame")
            .expect("request frame present");
        let req: Request = serde_json::from_slice(&bytes).expect("parse request");
        run_mock_verify_handler(&mut stream, &req.id, long_timeout).expect("mock verify handler");
    });

    let mut client = UnixStream::connect(&path).expect("connect to test socket");
    client
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("set client read timeout");

    // Send device.verify.start.
    let request = Request::new(
        json!(42),
        "device.verify.start",
        json!({"user": "@peer:test.local", "device": "PEERDEV"}),
    );
    write_frame(
        &mut client,
        &serde_json::to_vec(&request).expect("serialize request"),
    )
    .expect("send request frame");

    // Drain frames until EmojiReady — at that point the server is blocked in
    // read_verify_decision and is waiting for the in-band decision.
    let mut saw_emoji_ready = false;
    for _ in 0..10 {
        let raw = read_frame(&mut client)
            .expect("read frame")
            .expect("frame present");
        let resp: Response = serde_json::from_slice(&raw).expect("parse Response");
        if let Some(payload) = resp.result {
            if let Ok(frame) = serde_json::from_value::<DeviceVerifyFrame>(payload) {
                if matches!(frame, DeviceVerifyFrame::EmojiReady { .. }) {
                    saw_emoji_ready = true;
                    break;
                }
            }
        }
    }
    assert!(
        saw_emoji_ready,
        "client must receive EmojiReady before sending the in-band confirm"
    );

    // Send the bare `confirm` control frame in-band on the same connection.
    let confirm_req = Request::new(json!(43), "confirm", Value::Null);
    write_frame(
        &mut client,
        &serde_json::to_vec(&confirm_req).expect("serialize confirm"),
    )
    .expect("send confirm frame");

    // The next frame from the server must be Confirmed.
    let raw = read_frame(&mut client)
        .expect("read terminal frame")
        .expect("terminal frame must be present after in-band confirm");
    let resp: Response = serde_json::from_slice(&raw).expect("parse terminal Response");
    let frame: DeviceVerifyFrame = serde_json::from_value(
        resp.result
            .expect("terminal response must carry a result, not an error"),
    )
    .expect("parse terminal DeviceVerifyFrame");

    assert!(
        matches!(frame, DeviceVerifyFrame::Confirmed { .. }),
        "in-band confirm must produce Confirmed terminal frame (issue #259 happy path); \
         got {frame:?}",
    );

    std::fs::remove_file(&socket_path).ok();
}

// ---------------------------------------------------------------------------
// Test 4 — in-band `cancel` produces a `Cancelled` frame promptly
// ---------------------------------------------------------------------------

/// An explicit `cancel` control frame on the held-open connection must produce
/// a `Cancelled` terminal frame **without waiting for the full decision timeout**.
///
/// This tests the cancel branch of the in-band flow (issue #259): an operator
/// who decides to abort early sends a bare `cancel` frame on the same
/// connection; the daemon must respond immediately rather than holding the
/// connection open until the 300 s deadline fires.
#[test]
fn verify_inband_cancel_emits_cancelled_frame_promptly() {
    let path = tmp_socket("inband-cancel");
    let listener = UnixListener::bind(&path).expect("bind test socket");
    let socket_path = path.clone();

    // Use a long timeout so we can verify the cancel resolves well before it.
    let long_timeout = Duration::from_secs(30);
    // The test must complete much faster than the decision timeout.
    let prompt_threshold = Duration::from_secs(5);

    // Spawn a one-shot server.
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let bytes = read_frame(&mut stream)
            .expect("read request frame")
            .expect("request frame present");
        let req: Request = serde_json::from_slice(&bytes).expect("parse request");
        run_mock_verify_handler(&mut stream, &req.id, long_timeout).expect("mock verify handler");
    });

    let mut client = UnixStream::connect(&path).expect("connect to test socket");
    client
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("set client read timeout");

    // Send device.verify.start.
    let request = Request::new(
        json!(50),
        "device.verify.start",
        json!({"user": "@peer:test.local", "device": "PEERDEV2"}),
    );
    write_frame(
        &mut client,
        &serde_json::to_vec(&request).expect("serialize request"),
    )
    .expect("send request frame");

    // Drain until EmojiReady.
    let mut saw_emoji_ready = false;
    for _ in 0..10 {
        let raw = read_frame(&mut client)
            .expect("read frame")
            .expect("frame present");
        let resp: Response = serde_json::from_slice(&raw).expect("parse Response");
        if let Some(payload) = resp.result {
            if let Ok(frame) = serde_json::from_value::<DeviceVerifyFrame>(payload) {
                if matches!(frame, DeviceVerifyFrame::EmojiReady { .. }) {
                    saw_emoji_ready = true;
                    break;
                }
            }
        }
    }
    assert!(
        saw_emoji_ready,
        "client must receive EmojiReady before sending the in-band cancel"
    );

    // Send the bare `cancel` control frame and start timing.
    let before = Instant::now();
    let cancel_req = Request::new(json!(51), "cancel", Value::Null);
    write_frame(
        &mut client,
        &serde_json::to_vec(&cancel_req).expect("serialize cancel"),
    )
    .expect("send cancel frame");

    // The next frame must be Cancelled, and it must arrive well before the
    // 30 s decision timeout — i.e. the cancel is handled immediately.
    let raw = read_frame(&mut client)
        .expect("read terminal frame")
        .expect("terminal frame must be present after in-band cancel");
    let elapsed = before.elapsed();
    let resp: Response = serde_json::from_slice(&raw).expect("parse terminal Response");
    let frame: DeviceVerifyFrame = serde_json::from_value(
        resp.result
            .expect("terminal response must carry a result, not an error"),
    )
    .expect("parse terminal DeviceVerifyFrame");

    assert!(
        matches!(frame, DeviceVerifyFrame::Cancelled { .. }),
        "in-band cancel must produce Cancelled terminal frame (issue #259 cancel path); \
         got {frame:?}",
    );
    assert!(
        elapsed < prompt_threshold,
        "in-band cancel must resolve promptly (< {prompt_threshold:?}), not wait for the \
         full {long_timeout:?} decision timeout; took {elapsed:?}",
    );

    std::fs::remove_file(&socket_path).ok();
}
