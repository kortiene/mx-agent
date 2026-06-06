//! Local IPC contract and loopback execution for `mx-agent exec` (issue #155).
//!
//! The stateless CLI must not run processes itself: the daemon owns process
//! supervision (and, for the live flow, the Matrix client, signing key, policy,
//! and trust context — see [`crate::exec`]). This module defines the
//! `exec.start` IPC method's parameters and result, plus a **local-loopback**
//! executor that runs the command in-process inside the daemon and returns the
//! captured output as a sequence of [`ExecFrame`]s.
//!
//! Loopback is a stepping stone: it moves `exec` onto the IPC path now — so the
//! CLI no longer links the process runner — before the signed Matrix transport
//! to a *remote* daemon (the rest of #155) is wired in. When the live flow lands
//! it replaces [`start_exec_loopback`] behind the same `exec.start` method, so
//! the CLI does not change again.
//!
//! Today's loopback runs the command to completion and returns every frame in
//! one response, exactly matching the previous CLI behavior (which also ran to
//! completion before rendering). Live partial-output streaming is deferred to
//! the remote path.
//!
//! # Security
//!
//! - This is *not* a new capability and *not* a remote path: it runs the literal
//!   command on the local host exactly as the CLI did before, but now inside the
//!   daemon so the CLI stays stateless.
//! - The command, cwd, and stdin can carry sensitive data and are never logged
//!   here.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use mx_agent_protocol::id::{generate_invocation_id, generate_request_id};
use mx_agent_protocol::schema::{
    ExecAccepted, ExecCancelled, ExecFinished, ExecRejected, StreamArtifact, StreamChunk,
    StreamKind,
};

use crate::artifact::{prepare_artifact, ArtifactConfig};
use crate::runner::{run, RunError, RunSpec};
use crate::stream::{capture_child_output, StreamCaptureConfig};

/// Parameters for the `exec.start` IPC method.
///
/// `room`, `agent`, and `task` identify the remote target for the live Matrix
/// flow; the local-loopback executor accepts them for forward compatibility but
/// does not use them. `pty` is likewise accepted but ignored by the loopback
/// (interactive PTY exec takes a dedicated path).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecStartParams {
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
    /// Buffered stdin bytes to feed the command, if any. `None` connects stdin
    /// to `/dev/null`; `Some(bytes)` writes the bytes and closes the pipe.
    #[serde(default)]
    pub stdin: Option<Vec<u8>>,
    /// Whether the caller requested live streaming. The loopback always runs to
    /// completion, so this is accepted for forward compatibility.
    #[serde(default)]
    pub stream: bool,
    /// Whether the caller requested an interactive PTY (ignored by loopback).
    #[serde(default)]
    pub pty: bool,
    /// Associated task ID, if any.
    #[serde(default)]
    pub task: Option<String>,
    /// Whether the caller requested strict stream integrity. Rendering happens
    /// in the CLI; carried for forward compatibility.
    #[serde(default)]
    pub strict_stream: bool,
}

/// One frame in the forwarded exec output stream.
///
/// Internally tagged by `kind` so the wire form is `{"kind":"chunk",...}` /
/// `{"kind":"artifact",...}` / `{"kind":"finished",...}`. Mirrors the CLI's
/// renderer input so the CLI can convert each frame and render it unchanged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ExecFrame {
    /// A chunk of stdout/stderr output.
    Chunk(StreamChunk),
    /// A reference to a large output stream uploaded as an artifact
    /// (architecture §8.4). In loopback there is no homeserver, so the
    /// `mxc_uri` is empty.
    Artifact(StreamArtifact),
    /// The terminal frame carrying the exit status.
    Finished(ExecFinished),
}

/// Stable, machine-readable kind of an exec invocation failure.
///
/// These distinguish failures to *invoke* the command from a command that ran
/// and exited nonzero (which is a successful [`ExecOutcome::Ok`] with a
/// `Finished` frame). The CLI maps each kind to an exit code per architecture
/// §5.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecErrorKind {
    /// The command program or working directory was not found.
    NotFound,
    /// The argv was empty, so there was no program to run.
    EmptyCommand,
    /// The child process could not be spawned for another reason.
    Spawn,
}

/// The outcome of an `exec.start` invocation.
///
/// Internally tagged by `status` so the wire form is `{"status":"ok",...}` /
/// `{"status":"error",...}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ExecOutcome {
    /// The command ran (possibly exiting nonzero); the frames carry its output
    /// and a terminal `Finished` frame with the exit status.
    Ok {
        /// Output frames in order, ending with exactly one `Finished` frame.
        frames: Vec<ExecFrame>,
    },
    /// The command could not be invoked at all.
    Error {
        /// Machine-readable failure kind.
        kind: ExecErrorKind,
        /// Human-readable failure message (no secrets).
        message: String,
    },
}

/// The result of the `exec.start` IPC method.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecStartResult {
    /// Generated invocation identifier (`inv_...`).
    pub invocation_id: String,
    /// Generated request identifier (`req_...`).
    pub request_id: String,
    /// The execution outcome.
    pub outcome: ExecOutcome,
}

/// Parameters for the `exec.stdin` IPC method.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecStdinParams {
    /// Invocation receiving stdin.
    pub invocation_id: String,
    /// Raw stdin bytes for this frame.
    #[serde(default)]
    pub data: Vec<u8>,
    /// Whether this frame closes stdin.
    #[serde(default)]
    pub eof: bool,
}

/// Parameters for the `exec.cancel` IPC method.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecCancelParams {
    /// Invocation to cancel.
    pub invocation_id: String,
    /// Human-readable cancellation reason.
    #[serde(default)]
    pub reason: Option<String>,
}

/// Result for fire-and-forget exec control methods (`exec.stdin`, `exec.cancel`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecControlResult {
    /// Invocation the control request addressed.
    pub invocation_id: String,
    /// Whether a live invocation accepted the control request.
    pub accepted: bool,
    /// Non-sensitive status message.
    pub message: String,
}

/// Daemon-to-CLI exec notification payloads for streaming transports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "method", content = "params", rename_all = "snake_case")]
pub enum ExecNotification {
    /// The daemon accepted an exec request.
    ExecAccepted(ExecAccepted),
    /// The daemon rejected an exec request before spawning.
    ExecRejected(ExecRejected),
    /// A stdout/stderr/artifact/finished frame.
    Frame(ExecFrame),
    /// The daemon cancelled an invocation.
    ExecCancelled(ExecCancelled),
}

/// Loopback `exec.stdin` response.
///
/// The current loopback `exec.start` runs to completion in one request, so there
/// is no live stdin pipe to address. The method exists now so clients and future
/// remote/streaming handlers share a stable API.
pub fn handle_exec_stdin_loopback(params: &ExecStdinParams) -> ExecControlResult {
    ExecControlResult {
        invocation_id: params.invocation_id.clone(),
        accepted: false,
        message: "exec.stdin is only available for live streaming exec invocations".to_string(),
    }
}

/// Loopback `exec.cancel` response.
///
/// The current loopback `exec.start` is synchronous and returns only after the
/// child has finished, so there is no daemon-side live invocation table to
/// cancel yet. The method is part of the IPC API for later streaming/remote exec.
pub fn handle_exec_cancel_loopback(params: &ExecCancelParams) -> ExecControlResult {
    ExecControlResult {
        invocation_id: params.invocation_id.clone(),
        accepted: false,
        message: "exec.cancel is only available for live streaming exec invocations".to_string(),
    }
}

/// Map a Unix signal number to its name, for reporting signal death.
fn signal_name(n: i32) -> Option<String> {
    Some(
        match n {
            1 => "SIGHUP",
            2 => "SIGINT",
            3 => "SIGQUIT",
            6 => "SIGABRT",
            8 => "SIGFPE",
            9 => "SIGKILL",
            11 => "SIGSEGV",
            13 => "SIGPIPE",
            14 => "SIGALRM",
            15 => "SIGTERM",
            _ => return None,
        }
        .to_string(),
    )
}

fn error_kind_for(err: &RunError) -> ExecErrorKind {
    match err {
        RunError::EmptyCommand => ExecErrorKind::EmptyCommand,
        RunError::MissingCwd(_) => ExecErrorKind::NotFound,
        RunError::Spawn(io) if io.kind() == std::io::ErrorKind::NotFound => ExecErrorKind::NotFound,
        RunError::Spawn(_) => ExecErrorKind::Spawn,
    }
}

/// Execute an `exec.start` request locally (loopback), without Matrix.
///
/// Mints fresh `invocation_id`/`request_id`, runs the command through the
/// daemon's process runner, and packages the captured output as ordered
/// [`ExecFrame`]s ending in a single `Finished` frame. High-output commands
/// switch to artifact mode (architecture §8.4); the loopback has no homeserver,
/// so the artifact is finalized with an empty `mxc_uri`. A command that runs and
/// exits nonzero still yields [`ExecOutcome::Ok`]; only a failure to *invoke*
/// yields [`ExecOutcome::Error`].
pub async fn start_exec_loopback(params: &ExecStartParams) -> ExecStartResult {
    let invocation_id = generate_invocation_id();
    let request_id = generate_request_id();
    let outcome = run_loopback(&invocation_id, params).await;
    ExecStartResult {
        invocation_id,
        request_id,
        outcome,
    }
}

async fn run_loopback(invocation_id: &str, params: &ExecStartParams) -> ExecOutcome {
    let cwd = match &params.cwd {
        Some(cwd) => cwd.clone(),
        None => PathBuf::new(),
    };
    let spec = RunSpec {
        command: params.command.clone(),
        cwd,
        stdin: params.stdin.clone(),
        ..Default::default()
    };
    let output = match run(&spec).await {
        Ok(output) => output,
        Err(err) => {
            return ExecOutcome::Error {
                kind: error_kind_for(&err),
                message: err.to_string(),
            };
        }
    };

    let artifact_config = ArtifactConfig::default();
    let total_output = output.stdout.len() + output.stderr.len();

    let mut frames = Vec::new();
    let (truncated, artifact_mxc) = if artifact_config.should_switch(total_output) {
        // High-output commands package the full log as an artifact and show a
        // tail preview rather than streaming every byte (architecture §8.4).
        let mut artifact_mxc = None;
        for (stream, data) in [
            (StreamKind::Stdout, &output.stdout),
            (StreamKind::Stderr, &output.stderr),
        ] {
            if data.is_empty() {
                continue;
            }
            let prepared = prepare_artifact(invocation_id, stream, data, &artifact_config).await;
            let event = prepared.into_event(String::new());
            if stream == StreamKind::Stdout {
                artifact_mxc = Some(event.mxc_uri.clone());
            }
            frames.push(ExecFrame::Artifact(event));
        }
        // The full log is preserved in the artifact, so nothing was truncated.
        (false, artifact_mxc)
    } else {
        let (tx, mut rx) = tokio::sync::mpsc::channel(256);
        let stdout_bytes = output.stdout.clone();
        let stderr_bytes = output.stderr.clone();
        let invocation = invocation_id.to_string();
        // Capture concurrently so a full channel never deadlocks the drain.
        let capture = tokio::spawn(async move {
            capture_child_output(
                &stdout_bytes[..],
                &stderr_bytes[..],
                &invocation,
                StreamCaptureConfig::batch(),
                tx,
            )
            .await
        });
        while let Some(chunk) = rx.recv().await {
            frames.push(ExecFrame::Chunk(chunk));
        }
        let summary = capture.await.unwrap_or_default();
        (summary.truncated, None)
    };

    frames.push(ExecFrame::Finished(ExecFinished {
        invocation_id: invocation_id.to_string(),
        exit_code: output.exit_code,
        signal: output.signal.and_then(signal_name),
        duration_ms: 0,
        stdout_bytes: output.stdout.len() as u64,
        stderr_bytes: output.stderr.len() as u64,
        truncated,
        artifact_mxc,
        extra: Default::default(),
    }));

    ExecOutcome::Ok { frames }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mx_agent_protocol::id::{validate, IdKind};

    fn params(command: &[&str]) -> ExecStartParams {
        ExecStartParams {
            room: Some("!room:server".to_string()),
            agent: Some("developer-pi".to_string()),
            command: command.iter().map(|s| s.to_string()).collect(),
            cwd: Some(std::env::temp_dir()),
            stdin: None,
            stream: true,
            pty: false,
            task: None,
            strict_stream: false,
        }
    }

    fn finished(outcome: &ExecOutcome) -> &ExecFinished {
        match outcome {
            ExecOutcome::Ok { frames } => match frames.last() {
                Some(ExecFrame::Finished(f)) => f,
                other => panic!("expected trailing Finished frame, got {other:?}"),
            },
            other => panic!("expected Ok outcome, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn loopback_mints_well_formed_ids() {
        let result = start_exec_loopback(&params(&["true"])).await;
        assert!(validate(IdKind::Invocation, &result.invocation_id).is_ok());
        assert!(validate(IdKind::Request, &result.request_id).is_ok());
    }

    #[tokio::test]
    async fn successful_command_finishes_zero() {
        let result = start_exec_loopback(&params(&["true"])).await;
        let f = finished(&result.outcome);
        assert_eq!(f.exit_code, Some(0));
        assert_eq!(f.invocation_id, result.invocation_id);
    }

    #[tokio::test]
    async fn nonzero_exit_is_ok_outcome() {
        let result = start_exec_loopback(&params(&["false"])).await;
        let f = finished(&result.outcome);
        assert_eq!(f.exit_code, Some(1));
    }

    #[tokio::test]
    async fn stdout_is_captured_as_chunks() {
        let result = start_exec_loopback(&params(&["echo", "hello"])).await;
        match &result.outcome {
            ExecOutcome::Ok { frames } => {
                let has_stdout = frames.iter().any(|frame| match frame {
                    ExecFrame::Chunk(chunk) => {
                        chunk.stream == StreamKind::Stdout && chunk.data.contains("hello")
                    }
                    _ => false,
                });
                assert!(has_stdout, "expected a stdout chunk containing 'hello'");
            }
            other => panic!("expected Ok, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn stdin_is_forwarded_to_command() {
        let mut p = params(&["cat"]);
        p.stdin = Some(b"piped-input".to_vec());
        let result = start_exec_loopback(&p).await;
        match &result.outcome {
            ExecOutcome::Ok { frames } => {
                let echoed = frames.iter().any(|frame| match frame {
                    ExecFrame::Chunk(chunk) => chunk.data.contains("piped-input"),
                    _ => false,
                });
                assert!(echoed, "cat should echo forwarded stdin");
            }
            other => panic!("expected Ok, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn missing_cwd_maps_to_not_found() {
        let mut p = params(&["true"]);
        p.cwd = Some(PathBuf::from("/this/path/does/not/exist/mx-agent"));
        let result = start_exec_loopback(&p).await;
        match result.outcome {
            ExecOutcome::Error { kind, .. } => assert_eq!(kind, ExecErrorKind::NotFound),
            other => panic!("expected error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn unknown_command_maps_to_not_found() {
        let result = start_exec_loopback(&params(&["definitely-not-a-real-binary-xyz"])).await;
        match result.outcome {
            ExecOutcome::Error { kind, .. } => assert_eq!(kind, ExecErrorKind::NotFound),
            other => panic!("expected error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn empty_command_maps_to_empty_command() {
        let result = start_exec_loopback(&params(&[])).await;
        match result.outcome {
            ExecOutcome::Error { kind, .. } => assert_eq!(kind, ExecErrorKind::EmptyCommand),
            other => panic!("expected error, got {other:?}"),
        }
    }

    #[test]
    fn outcome_serializes_with_status_tag() {
        let err = ExecOutcome::Error {
            kind: ExecErrorKind::NotFound,
            message: "nope".to_string(),
        };
        let value = serde_json::to_value(&err).unwrap();
        assert_eq!(value["status"], "error");
        assert_eq!(value["kind"], "not_found");
    }

    #[test]
    fn frame_serializes_with_kind_tag() {
        let frame = ExecFrame::Finished(ExecFinished {
            invocation_id: "inv_x".to_string(),
            exit_code: Some(0),
            signal: None,
            duration_ms: 0,
            stdout_bytes: 0,
            stderr_bytes: 0,
            truncated: false,
            artifact_mxc: None,
            extra: Default::default(),
        });
        let value = serde_json::to_value(&frame).unwrap();
        assert_eq!(value["kind"], "finished");
        assert_eq!(value["exit_code"], 0);
    }

    #[test]
    fn stdin_and_cancel_loopback_return_stable_not_live_result() {
        let stdin = handle_exec_stdin_loopback(&ExecStdinParams {
            invocation_id: "inv_1".to_string(),
            data: b"hello".to_vec(),
            eof: true,
        });
        assert_eq!(stdin.invocation_id, "inv_1");
        assert!(!stdin.accepted);
        assert!(stdin.message.contains("live streaming"));

        let cancel = handle_exec_cancel_loopback(&ExecCancelParams {
            invocation_id: "inv_1".to_string(),
            reason: Some("test".to_string()),
        });
        assert_eq!(cancel.invocation_id, "inv_1");
        assert!(!cancel.accepted);
        assert!(cancel.message.contains("live streaming"));
    }

    #[test]
    fn notification_serializes_with_method_tag() {
        let notification = ExecNotification::Frame(ExecFrame::Finished(ExecFinished {
            invocation_id: "inv_1".to_string(),
            exit_code: Some(0),
            signal: None,
            duration_ms: 1,
            stdout_bytes: 0,
            stderr_bytes: 0,
            truncated: false,
            artifact_mxc: None,
            extra: Default::default(),
        }));
        let value = serde_json::to_value(notification).unwrap();
        assert_eq!(value["method"], "frame");
        assert_eq!(value["params"]["kind"], "finished");
    }

    #[test]
    fn result_round_trips() {
        let result = ExecStartResult {
            invocation_id: "inv_x".to_string(),
            request_id: "req_x".to_string(),
            outcome: ExecOutcome::Ok {
                frames: vec![ExecFrame::Finished(ExecFinished {
                    invocation_id: "inv_x".to_string(),
                    exit_code: Some(2),
                    signal: None,
                    duration_ms: 0,
                    stdout_bytes: 0,
                    stderr_bytes: 0,
                    truncated: false,
                    artifact_mxc: None,
                    extra: Default::default(),
                })],
            },
        };
        let json = serde_json::to_value(&result).unwrap();
        let back: ExecStartResult = serde_json::from_value(json).unwrap();
        assert_eq!(back, result);
    }
}
