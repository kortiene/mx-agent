//! Interactive PTY `exec` carried over the daemon IPC channel and, for
//! `--room`/`--agent` targets, the signed Matrix transport (issue #238).
//!
//! Non-PTY `exec` runs to completion and returns its captured output in one
//! [`ExecStartResult`](crate::ExecStartResult). An interactive PTY is different:
//! it is a *live, bidirectional, single merged byte stream*. The requesting side
//! must forward keystrokes (including control characters such as Ctrl-C) and
//! terminal resize events to the program while it runs, and render the program's
//! merged terminal output as it is produced.
//!
//! # Wire protocol
//!
//! A PTY session uses **one** streaming IPC connection (the blocking IPC server
//! serves connections sequentially, so a session holds the connection open for
//! its lifetime, exactly as `task.watch` does). The connection is full-duplex:
//!
//! - **daemon → CLI**: JSON-RPC `Response` frames (echoing the `exec.pty`
//!   request id) whose `result` is a [`PtyServerFrame`] — `output` (a base64
//!   chunk of merged terminal bytes), `finished` (the terminal exit status), or
//!   `error` (the session could not start or failed).
//! - **CLI → daemon** (interleaved on the same connection): JSON-RPC `Request`
//!   frames with method [`METHOD_PTY_STDIN`] ([`PtyStdinFrame`], base64
//!   keystrokes) or [`METHOD_PTY_RESIZE`] ([`PtyResizeFrame`], the new window
//!   size).
//!
//! Because the daemon handler must read client frames *while* it streams output,
//! it clones the Unix-socket connection and runs the two directions on dedicated
//! threads (PTY master I/O is blocking).
//!
//! # Security
//!
//! - The loopback path runs the command on the local host inside the daemon (so
//!   the CLI stays stateless); it is not a new capability.
//! - The remote path reuses the full signed exec pipeline (signature → routing →
//!   trust → replay/expiry → policy) and the signed `exec.stdin`/`exec.cancel`
//!   controls; `pty` never bypasses a gate.
//! - PTY bytes (keystrokes and output) can carry sensitive data and are never
//!   logged.

use std::io::{self, Read as _, Write as _};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use mx_agent_ipc::{read_frame, write_frame, Request, Response};

use crate::pty::{PtySession, PtyWinsize};
use crate::runner::RunSpec;

/// Streaming IPC method that starts an interactive PTY `exec` session.
pub const METHOD_EXEC_PTY: &str = "exec.pty";
/// Client→daemon method carrying base64 keystrokes for a live PTY session.
pub const METHOD_PTY_STDIN: &str = "pty.stdin";
/// Client→daemon method carrying a new terminal window size for a live session.
pub const METHOD_PTY_RESIZE: &str = "pty.resize";

/// Parameters for the [`METHOD_EXEC_PTY`] streaming IPC method.
///
/// `room`/`agent` select a remote target (the signed Matrix transport); when
/// both are absent the daemon runs the PTY locally (loopback). `rows`/`cols` are
/// the requester's initial terminal size so the program's first render matches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecPtyParams {
    /// Workspace room to target, if any.
    #[serde(default)]
    pub room: Option<String>,
    /// Target agent name, if any.
    #[serde(default)]
    pub agent: Option<String>,
    /// Command argv: program followed by its arguments.
    pub command: Vec<String>,
    /// Working directory to run the command in.
    #[serde(default)]
    pub cwd: Option<PathBuf>,
    /// Initial terminal height in character rows.
    #[serde(default = "default_rows")]
    pub rows: u16,
    /// Initial terminal width in character columns.
    #[serde(default = "default_cols")]
    pub cols: u16,
    /// Associated task id, if any.
    #[serde(default)]
    pub task: Option<String>,
}

fn default_rows() -> u16 {
    PtyWinsize::DEFAULT_ROWS
}

fn default_cols() -> u16 {
    PtyWinsize::DEFAULT_COLS
}

/// A daemon→CLI frame on a live PTY connection (carried as a JSON-RPC result).
///
/// Internally tagged by `event` so the wire form is `{"event":"output",...}` /
/// `{"event":"finished",...}` / `{"event":"error",...}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum PtyServerFrame {
    /// A chunk of merged terminal output, base64-encoded.
    Output {
        /// Base64-encoded raw terminal bytes.
        data: String,
    },
    /// The PTY session ended; carries the terminal status.
    Finished {
        /// Process exit code, when it exited normally.
        exit_code: Option<i32>,
        /// Terminating signal number, when killed by a signal.
        signal: Option<i32>,
    },
    /// The session could not be started or failed before/while running.
    Error {
        /// Human-readable, non-sensitive message.
        message: String,
    },
}

/// A CLI→daemon keystroke frame ([`METHOD_PTY_STDIN`] params).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PtyStdinFrame {
    /// Base64-encoded raw stdin bytes (keystrokes / control characters).
    pub data: String,
}

/// A CLI→daemon resize frame ([`METHOD_PTY_RESIZE`] params).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PtyResizeFrame {
    /// New height in character rows.
    pub rows: u16,
    /// New width in character columns.
    pub cols: u16,
    /// New width in pixels, or `0` when unknown.
    #[serde(default)]
    pub pixel_width: u16,
    /// New height in pixels, or `0` when unknown.
    #[serde(default)]
    pub pixel_height: u16,
}

impl From<PtyResizeFrame> for PtyWinsize {
    fn from(f: PtyResizeFrame) -> Self {
        PtyWinsize {
            rows: f.rows,
            cols: f.cols,
            pixel_width: f.pixel_width,
            pixel_height: f.pixel_height,
        }
    }
}

/// Encode a [`PtyServerFrame`] and write it to `stream` as a JSON-RPC `Response`
/// frame echoing `request_id`.
pub(crate) fn write_server_frame(
    stream: &mut UnixStream,
    request_id: &Value,
    frame: &PtyServerFrame,
) -> io::Result<()> {
    let payload =
        serde_json::to_value(frame).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let response = Response::result(request_id.clone(), payload);
    let bytes =
        serde_json::to_vec(&response).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    write_frame(stream, &bytes)
}

/// Run an interactive PTY `exec` locally (loopback), bridging it to the open IPC
/// `stream`.
///
/// Allocates a pseudo-terminal in the daemon, spawns the command on its slave
/// end, and runs full duplex over the single connection: one thread pumps the
/// merged master output to the CLI as [`PtyServerFrame::Output`] frames; another
/// applies inbound [`METHOD_PTY_STDIN`]/[`METHOD_PTY_RESIZE`] frames to the
/// master. On child exit it sends a terminal [`PtyServerFrame::Finished`] and
/// closes the connection.
pub fn run_pty_loopback(
    params: &ExecPtyParams,
    stream: &mut UnixStream,
    request_id: &Value,
) -> io::Result<()> {
    let cwd = params.cwd.clone().unwrap_or_else(|| PathBuf::from("."));
    let spec = RunSpec {
        command: params.command.clone(),
        cwd,
        ..Default::default()
    };
    let winsize = PtyWinsize::new(params.rows, params.cols);
    let mut session = match PtySession::spawn(&spec, winsize) {
        Ok(session) => session,
        Err(e) => {
            let frame = PtyServerFrame::Error {
                message: format!("exec --pty failed: {e}"),
            };
            return write_server_frame(stream, request_id, &frame);
        }
    };

    // Independent master handles: one for reading output, one for writing
    // keystrokes and applying resizes. Independent socket handles: one to push
    // output frames, one to read client frames concurrently.
    let reader = session.try_clone_reader()?;
    let master_io = session.try_clone_writer()?;
    let out_stream = stream.try_clone()?;
    let in_stream = stream.try_clone()?;

    let request_id_out = request_id.clone();
    let output =
        std::thread::spawn(move || pump_master_to_client(reader, out_stream, request_id_out));
    let input = std::thread::spawn(move || pump_client_to_master(in_stream, master_io));

    let status = session.wait();
    // The child has exited; the master reader sees EOF, so the output thread
    // drains and ends.
    let _ = output.join();

    let (exit_code, signal) = match status {
        Ok(status) => (status.code(), status_signal(&status)),
        Err(_) => (None, None),
    };
    let _ = write_server_frame(
        stream,
        request_id,
        &PtyServerFrame::Finished { exit_code, signal },
    );

    // Unblock the input reader (it is parked in a blocking read of the client)
    // and end the connection so the server's outer loop does not race it.
    let _ = stream.shutdown(Shutdown::Both);
    let _ = input.join();
    Ok(())
}

/// Terminating signal number of `status`, when it was killed by a signal.
fn status_signal(status: &std::process::ExitStatus) -> Option<i32> {
    use std::os::unix::process::ExitStatusExt as _;
    status.signal()
}

/// Everything the remote PTY duplex bridge needs after Matrix setup succeeds.
struct RemotePtyContext {
    room: matrix_sdk::Room,
    signing_key: ed25519_dalek::SigningKey,
    key_id: String,
    invocation_id: String,
    subscription: crate::ExecSubscription,
}

/// Bridge an interactive PTY `exec` session to a remote agent over the signed
/// Matrix transport (issue #238).
///
/// Sends a signed `com.mxagent.exec.request.v1` with `pty: true` (so the target
/// daemon allocates the PTY and live-streams `stream:"pty"` chunks), then runs
/// full duplex over the IPC connection: inbound IPC keystroke/resize frames are
/// translated to signed `exec.stdin` and `pty.resize` Matrix events, and the
/// forwarded `stream.chunk`/`exec.finished` events are rendered back as
/// [`PtyServerFrame`]s. Authorization is the target's job and is unchanged from
/// non-PTY exec.
pub fn run_pty_remote(
    params: &ExecPtyParams,
    stream: &mut UnixStream,
    request_id: &Value,
    subscribers: &crate::ExecSubscriberRegistry,
) -> io::Result<()> {
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(e) => {
            return write_server_frame(
                stream,
                request_id,
                &PtyServerFrame::Error {
                    message: format!("could not start async runtime: {e}"),
                },
            );
        }
    };

    let ctx = match runtime.block_on(setup_remote_pty(params, subscribers)) {
        Ok(ctx) => ctx,
        Err(message) => {
            return write_server_frame(stream, request_id, &PtyServerFrame::Error { message });
        }
    };

    // Translate inbound IPC keystroke/resize frames to signed Matrix events on a
    // dedicated thread that drives the shared runtime; the main thread drains the
    // forwarded result stream and writes IPC frames.
    let in_stream = stream.try_clone()?;
    let handle = runtime.handle().clone();
    let input_room = ctx.room.clone();
    let input_key = ctx.signing_key.clone();
    let input_key_id = ctx.key_id.clone();
    let input_invocation = ctx.invocation_id.clone();
    let input = std::thread::spawn(move || {
        forward_client_frames_to_matrix(
            in_stream,
            handle,
            input_room,
            input_key,
            input_key_id,
            input_invocation,
        )
    });

    let mut out_stream = stream.try_clone()?;
    let request_id_out = request_id.clone();
    let mut subscription = ctx.subscription;
    runtime.block_on(async move {
        drain_remote_pty(&mut subscription, &mut out_stream, &request_id_out).await;
    });

    // End the connection so the input thread unparks, then reap it.
    let _ = stream.shutdown(Shutdown::Both);
    let _ = input.join();
    Ok(())
}

/// Establish the Matrix client, resolve the room and requester, sign and send the
/// `exec.request{pty:true}` (plus an initial resize), and subscribe to the
/// invocation's forwarded events.
async fn setup_remote_pty(
    params: &ExecPtyParams,
    subscribers: &crate::ExecSubscriberRegistry,
) -> Result<RemotePtyContext, String> {
    use matrix_sdk::config::SyncSettings;
    use mx_agent_protocol::events::timeline::EXEC_REQUEST;
    use mx_agent_protocol::id::{generate_invocation_id, generate_request_id};

    let room_target = params.room.as_deref().ok_or("remote PTY requires --room")?;
    let target_agent = params.agent.clone().ok_or("remote PTY requires --agent")?;

    let paths = crate::SessionPaths::resolve();
    let session = crate::load_session(&paths)
        .map_err(|e| format!("could not read daemon session: {e}"))?
        .ok_or("not logged in; run `mx-agent auth login` first")?;
    let client = crate::matrix::restore_client(&session)
        .await
        .map_err(|e| e.to_string())?;
    client
        .sync_once(SyncSettings::default())
        .await
        .map_err(|e| e.to_string())?;
    let id = crate::workspace::parse_room_or_alias(room_target).map_err(|e| e.to_string())?;
    let room_id = crate::workspace::resolve_room_id(&client, &id)
        .await
        .map_err(|e| e.to_string())?;
    let room = client
        .get_room(&room_id)
        .ok_or_else(|| format!("room not found: {room_target}"))?;

    let local_user = client.user_id().map(|u| u.to_string()).unwrap_or_default();
    let requester = crate::agent::read_all_agent_states(&room)
        .await
        .map_err(|e| e.to_string())?
        .into_iter()
        .filter(|agent| agent.matrix_user_id == local_user)
        .min_by(|a, b| a.agent_id.cmp(&b.agent_id))
        .ok_or("local agent is not registered in the target room")?;

    let signing = crate::load_or_create_signing_key(&paths).map_err(|e| e.to_string())?;
    let invocation_id = generate_invocation_id();
    let request_id = generate_request_id();
    let created_at = crate::exec_ipc::rfc3339_after(Duration::ZERO);
    let expires_at = crate::exec_ipc::rfc3339_after(Duration::from_secs(300));
    let cwd = params
        .cwd
        .as_ref()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    let options = crate::ExecRequestOptions {
        target_agent,
        requesting_agent: requester.agent_id,
        command: params.command.clone(),
        cwd,
        env: Default::default(),
        stdin: true,
        stream: true,
        pty: true,
        timeout_ms: 600_000,
        task_id: params.task.clone(),
    };
    let content = crate::build_signed_exec_request(
        signing.signing_key(),
        signing.key_id(),
        &invocation_id,
        &request_id,
        generate_request_id(),
        created_at,
        expires_at,
        &options,
    )
    .map_err(|e| e.to_string())?;

    // Subscribe *before* sending so no early stream/result event is missed.
    let subscription = subscribers.subscribe(crate::ExecSubscriptionKey::Invocation(
        invocation_id.clone(),
    ));
    room.send_raw(EXEC_REQUEST, content)
        .await
        .map_err(|e| e.to_string())?;
    // Tell the target the real initial window size right away.
    let _ = crate::exec::send_pty_resize(
        &room,
        &invocation_id,
        PtyWinsize::new(params.rows, params.cols),
    )
    .await;

    Ok(RemotePtyContext {
        room,
        signing_key: signing.signing_key().clone(),
        key_id: signing.key_id().to_string(),
        invocation_id,
        subscription,
    })
}

/// Drain forwarded result events for a remote PTY invocation, writing IPC frames
/// to the CLI until a terminal event arrives.
async fn drain_remote_pty(
    subscription: &mut crate::ExecSubscription,
    out: &mut UnixStream,
    request_id: &Value,
) {
    use mx_agent_protocol::schema::StreamKind;

    loop {
        let Some(event) = subscription.recv().await else {
            let _ = write_server_frame(
                out,
                request_id,
                &PtyServerFrame::Error {
                    message: "remote PTY subscriber closed".to_string(),
                },
            );
            return;
        };
        match event {
            crate::ForwardedExecEvent::StreamChunk(chunk) => {
                if chunk.stream != StreamKind::Pty {
                    continue;
                }
                let raw = if chunk.encoding == "base64" {
                    base64::engine::general_purpose::STANDARD
                        .decode(chunk.data.as_bytes())
                        .unwrap_or_default()
                } else {
                    chunk.data.into_bytes()
                };
                let frame = PtyServerFrame::Output {
                    data: base64::engine::general_purpose::STANDARD.encode(raw),
                };
                if write_server_frame(out, request_id, &frame).is_err() {
                    return;
                }
            }
            crate::ForwardedExecEvent::ExecFinished(finished) => {
                let _ = write_server_frame(
                    out,
                    request_id,
                    &PtyServerFrame::Finished {
                        exit_code: finished.exit_code,
                        signal: finished.signal.as_deref().and_then(signal_number),
                    },
                );
                return;
            }
            crate::ForwardedExecEvent::ExecRejected(rejected) => {
                let _ = write_server_frame(
                    out,
                    request_id,
                    &PtyServerFrame::Error {
                        message: rejected.reason,
                    },
                );
                return;
            }
            crate::ForwardedExecEvent::ExecCancelled(cancelled) => {
                let _ = write_server_frame(
                    out,
                    request_id,
                    &PtyServerFrame::Finished {
                        exit_code: None,
                        signal: signal_number(&cancelled.signal_sent),
                    },
                );
                return;
            }
            // Artifacts and call responses are not part of an interactive PTY.
            crate::ForwardedExecEvent::StreamArtifact(_)
            | crate::ForwardedExecEvent::CallResponse(_) => {}
        }
    }
}

/// Read inbound IPC keystroke/resize frames and forward them as signed
/// `exec.stdin` / `pty.resize` Matrix events until the connection closes.
fn forward_client_frames_to_matrix(
    mut stream: UnixStream,
    handle: tokio::runtime::Handle,
    room: matrix_sdk::Room,
    signing_key: ed25519_dalek::SigningKey,
    key_id: String,
    invocation_id: String,
) {
    while let Ok(Some(bytes)) = read_frame(&mut stream) {
        let Ok(request) = serde_json::from_slice::<Request>(&bytes) else {
            continue;
        };
        match request.method.as_str() {
            METHOD_PTY_STDIN => {
                if let Ok(frame) = serde_json::from_value::<PtyStdinFrame>(request.params.clone()) {
                    if let Ok(data) = base64::engine::general_purpose::STANDARD.decode(&frame.data)
                    {
                        let _ = handle.block_on(crate::exec::send_exec_stdin(
                            &room,
                            &signing_key,
                            key_id.clone(),
                            invocation_id.clone(),
                            &data,
                            false,
                        ));
                    }
                }
            }
            METHOD_PTY_RESIZE => {
                if let Ok(frame) = serde_json::from_value::<PtyResizeFrame>(request.params.clone())
                {
                    let _ = handle.block_on(crate::exec::send_pty_resize(
                        &room,
                        &invocation_id,
                        frame.into(),
                    ));
                }
            }
            _ => {}
        }
    }
}

/// Map a Unix signal name (e.g. `"SIGINT"`) to its number, the inverse of the
/// `signal_name` mapping used when emitting `exec.finished`.
fn signal_number(name: &str) -> Option<i32> {
    Some(match name {
        "SIGHUP" => 1,
        "SIGINT" => 2,
        "SIGQUIT" => 3,
        "SIGABRT" => 6,
        "SIGFPE" => 8,
        "SIGKILL" => 9,
        "SIGSEGV" => 11,
        "SIGPIPE" => 13,
        "SIGALRM" => 14,
        "SIGTERM" => 15,
        _ => return None,
    })
}

/// Copy the PTY's merged output to the client as base64 [`PtyServerFrame::Output`]
/// frames until end-of-stream.
fn pump_master_to_client(mut reader: std::fs::File, mut out: UnixStream, request_id: Value) {
    let mut buf = [0u8; 8192];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                let frame = PtyServerFrame::Output {
                    data: base64::engine::general_purpose::STANDARD.encode(&buf[..n]),
                };
                if write_server_frame(&mut out, &request_id, &frame).is_err() {
                    break;
                }
            }
            // A PTY master reports EIO (not EOF) once the slave is gone; treat
            // any read error as end-of-stream.
            Err(_) => break,
        }
    }
}

/// Apply inbound client frames (keystrokes and resizes) to the PTY master until
/// the connection closes.
fn pump_client_to_master(mut stream: UnixStream, mut master: std::fs::File) {
    // Exits on a closed/broken connection (`Ok(None)`/`Err`); a failed master
    // write breaks early via `apply_client_frame`.
    while let Ok(Some(bytes)) = read_frame(&mut stream) {
        let Ok(request) = serde_json::from_slice::<Request>(&bytes) else {
            continue;
        };
        if !apply_client_frame(&request, &mut master) {
            break;
        }
    }
}

/// Apply a single client frame to the master. Returns `false` when the master
/// write failed (the session is over).
fn apply_client_frame(request: &Request, master: &mut std::fs::File) -> bool {
    match request.method.as_str() {
        METHOD_PTY_STDIN => {
            if let Ok(frame) = serde_json::from_value::<PtyStdinFrame>(request.params.clone()) {
                if let Ok(data) = base64::engine::general_purpose::STANDARD.decode(&frame.data) {
                    if master.write_all(&data).is_err() {
                        return false;
                    }
                    let _ = master.flush();
                }
            }
            true
        }
        METHOD_PTY_RESIZE => {
            if let Ok(frame) = serde_json::from_value::<PtyResizeFrame>(request.params.clone()) {
                let size: PtyWinsize = frame.into();
                let _ = rustix::termios::tcsetwinsize(&*master, size.into());
            }
            true
        }
        // Unknown control frames are ignored; the session stays alive.
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn exec_pty_params_defaults_winsize() {
        let params: ExecPtyParams = serde_json::from_value(json!({
            "command": ["bash"],
        }))
        .expect("minimal params parse");
        assert_eq!(params.rows, PtyWinsize::DEFAULT_ROWS);
        assert_eq!(params.cols, PtyWinsize::DEFAULT_COLS);
        assert!(params.room.is_none());
        assert!(params.agent.is_none());
    }

    #[test]
    fn server_frame_tags_by_event() {
        let output = PtyServerFrame::Output {
            data: "aGk=".to_string(),
        };
        let value = serde_json::to_value(&output).unwrap();
        assert_eq!(value["event"], "output");
        assert_eq!(value["data"], "aGk=");

        let finished = PtyServerFrame::Finished {
            exit_code: Some(0),
            signal: None,
        };
        let value = serde_json::to_value(&finished).unwrap();
        assert_eq!(value["event"], "finished");
        assert_eq!(value["exit_code"], 0);

        let error = PtyServerFrame::Error {
            message: "boom".to_string(),
        };
        let value = serde_json::to_value(&error).unwrap();
        assert_eq!(value["event"], "error");
    }

    #[test]
    fn server_frame_round_trips() {
        for frame in [
            PtyServerFrame::Output {
                data: "AAEC".to_string(),
            },
            PtyServerFrame::Finished {
                exit_code: None,
                signal: Some(2),
            },
            PtyServerFrame::Error {
                message: "nope".to_string(),
            },
        ] {
            let value = serde_json::to_value(&frame).unwrap();
            let back: PtyServerFrame = serde_json::from_value(value).unwrap();
            assert_eq!(back, frame);
        }
    }

    #[test]
    fn resize_frame_maps_to_winsize() {
        let frame = PtyResizeFrame {
            rows: 50,
            cols: 132,
            pixel_width: 0,
            pixel_height: 0,
        };
        let size: PtyWinsize = frame.into();
        assert_eq!(size.rows, 50);
        assert_eq!(size.cols, 132);
    }

    #[test]
    fn resize_frame_pixels_default_to_zero() {
        let frame: PtyResizeFrame = serde_json::from_value(json!({
            "rows": 24,
            "cols": 80,
        }))
        .expect("resize frame parses without pixels");
        assert_eq!(frame.pixel_width, 0);
        assert_eq!(frame.pixel_height, 0);
    }

    #[test]
    fn stdin_frame_round_trips() {
        let frame = PtyStdinFrame {
            data: "bHM=".to_string(),
        };
        let value = serde_json::to_value(&frame).unwrap();
        let back: PtyStdinFrame = serde_json::from_value(value).unwrap();
        assert_eq!(back, frame);
    }

    #[test]
    fn unknown_client_frame_keeps_session_alive() {
        // A control frame the daemon does not recognize must not tear down the
        // session; only a failed master write does.
        let request = Request::new(json!(1), "pty.unknown", json!({}));
        let mut sink = tempfile_master();
        assert!(apply_client_frame(&request, &mut sink));
    }

    /// A throwaway writable file standing in for the PTY master in unit tests
    /// that only exercise the non-PTY branches of [`apply_client_frame`].
    fn tempfile_master() -> std::fs::File {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "mx-agent-pty-ipc-test-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed),
        ));
        std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&path)
            .expect("open temp master stand-in")
    }
}
