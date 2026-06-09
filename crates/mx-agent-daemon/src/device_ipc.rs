//! IPC handlers for device verification and cross-signing (issue #240).
//!
//! These daemon-mediated methods let the stateless CLI inspect and verify peer
//! Matrix devices and manage the daemon's cross-signing identity, without ever
//! seeing key material. The daemon owns the Matrix session and crypto store; the
//! CLI receives only fingerprints, SAS emoji/decimal, and verification status.
//!
//! Single-response methods (`device.list`, `device.show`,
//! `device.verify.manual`, `device.verify.confirm`, `device.verify.cancel`,
//! `cross_signing.bootstrap`, `cross_signing.status`) restore a client from the
//! stored session and call the [`crate::verification`] manager. The interactive
//! `device.verify.start` is streaming (see [`run_device_verify`]), following the
//! `task.watch` convention: one response frame per flow update over a held-open
//! socket.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::matrix::restore_client;
use crate::session::StoredSession;
use crate::verification::{
    self, CrossSigningStatusInfo, DeviceInfo, EmojiPair, SasAdvance, VerificationError,
};
use crate::workspace::WorkspaceError;

/// IPC method name for the streaming interactive verification flow.
pub const METHOD_DEVICE_VERIFY_START: &str = "device.verify.start";

/// Map a non-secret [`VerificationError`] onto a [`WorkspaceError`] for IPC.
fn verr(e: VerificationError) -> WorkspaceError {
    WorkspaceError::Io(std::io::Error::other(e.to_string()))
}

/// Parameters for `device.list`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceListParams {
    /// Workspace room whose joined members' devices to list. When omitted and no
    /// `user` is given, lists the daemon's own user's devices.
    #[serde(default)]
    pub room: Option<String>,
    /// Specific user whose devices to list. Takes precedence over `room`.
    #[serde(default)]
    pub user: Option<String>,
}

/// Parameters for `device.show` and the device-scoped verify methods.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceShowParams {
    /// Owning Matrix user id.
    pub user: String,
    /// Matrix device id.
    pub device: String,
}

/// Parameters for `device.verify.manual` (out-of-band fingerprint verify).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceVerifyManualParams {
    /// Owning Matrix user id.
    pub user: String,
    /// Matrix device id.
    pub device: String,
    /// Expected `ed25519:<base64>` device fingerprint to confirm before
    /// verifying. When omitted, the device is verified without a fingerprint
    /// check (the operator asserts an out-of-band confirmation).
    #[serde(default)]
    pub fingerprint: Option<String>,
}

/// Parameters for the interactive `device.verify.start`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceVerifyStartParams {
    /// Peer user id to verify with.
    pub user: String,
    /// Peer device id to verify.
    pub device: String,
}

/// Parameters for `device.verify.confirm` / `device.verify.cancel`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyFlowParams {
    /// The flow id returned by `device.verify.start`.
    pub flow_id: String,
}

/// Result of a `device.verify.confirm` / `.cancel` action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationActionResult {
    /// The flow id acted on.
    pub flow_id: String,
    /// The resulting state: `confirm_sent` or `cancelled`.
    pub state: String,
}

/// A single streamed update of an interactive `device.verify.start` flow.
///
/// Mirrors the `task.watch` streaming convention: one frame per flow update on
/// the same held-open IPC connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "kebab-case")]
pub enum DeviceVerifyFrame {
    /// The verification request was sent; the operator may now wait for the peer
    /// to accept. Carries the flow id used by `confirm`/`cancel`.
    Started {
        /// Flow id for subsequent `confirm`/`cancel`.
        flow_id: String,
    },
    /// The short-authentication string is ready to compare out-of-band.
    EmojiReady {
        /// Flow id.
        flow_id: String,
        /// Emoji SAS, when both sides support it.
        #[serde(skip_serializing_if = "Option::is_none")]
        emoji: Option<Vec<EmojiPair>>,
        /// Decimal SAS fallback.
        #[serde(skip_serializing_if = "Option::is_none")]
        decimals: Option<(u16, u16, u16)>,
    },
    /// The verification completed successfully; the device is now verified.
    Confirmed {
        /// Flow id.
        flow_id: String,
    },
    /// The verification was cancelled by either side.
    Cancelled {
        /// Flow id.
        flow_id: String,
    },
    /// The flow failed; carries a non-sensitive message.
    Error {
        /// Human-readable, non-secret message.
        message: String,
    },
}

/// Resolve the set of users whose devices `device.list` should report.
async fn resolve_target_users(
    client: &matrix_sdk::Client,
    params: &DeviceListParams,
) -> Result<Vec<String>, WorkspaceError> {
    if let Some(user) = &params.user {
        return Ok(vec![user.clone()]);
    }
    if let Some(room) = &params.room {
        let id = crate::workspace::parse_room_or_alias(room)?;
        let room_id = crate::workspace::resolve_room_id(client, &id).await?;
        let room = client
            .get_room(&room_id)
            .ok_or_else(|| WorkspaceError::RoomNotFound(room.clone()))?;
        let mut users: Vec<String> = room
            .members(matrix_sdk::RoomMemberships::JOIN)
            .await
            .map_err(WorkspaceError::from)?
            .into_iter()
            .map(|m| m.user_id().to_string())
            .collect();
        users.sort();
        users.dedup();
        return Ok(users);
    }
    // Default: the daemon's own user's devices.
    Ok(client
        .user_id()
        .map(|u| vec![u.to_string()])
        .unwrap_or_default())
}

/// Handle `device.list`.
pub async fn list_devices_for_session(
    session: &StoredSession,
    params: &DeviceListParams,
) -> Result<Vec<DeviceInfo>, WorkspaceError> {
    let client = restore_client(session).await?;
    // A freshly restored client must talk to the homeserver once to populate
    // room state and device lists before they can be read.
    client
        .sync_once(matrix_sdk::config::SyncSettings::default())
        .await
        .map_err(WorkspaceError::from)?;
    let users = resolve_target_users(&client, params).await?;
    let mut devices = Vec::new();
    for user in users {
        devices.extend(
            verification::list_devices(&client, &user)
                .await
                .map_err(verr)?,
        );
    }
    Ok(devices)
}

/// Handle `device.show`.
pub async fn show_device_for_session(
    session: &StoredSession,
    params: &DeviceShowParams,
) -> Result<Option<DeviceInfo>, WorkspaceError> {
    let client = restore_client(session).await?;
    client
        .sync_once(matrix_sdk::config::SyncSettings::default())
        .await
        .map_err(WorkspaceError::from)?;
    verification::show_device(&client, &params.user, &params.device)
        .await
        .map_err(verr)
}

/// Handle `device.verify.manual`.
pub async fn manual_verify_for_session(
    session: &StoredSession,
    params: &DeviceVerifyManualParams,
) -> Result<DeviceInfo, WorkspaceError> {
    let client = restore_client(session).await?;
    client
        .sync_once(matrix_sdk::config::SyncSettings::default())
        .await
        .map_err(WorkspaceError::from)?;
    verification::manual_verify(
        &client,
        &params.user,
        &params.device,
        params.fingerprint.as_deref(),
    )
    .await
    .map_err(verr)
}

/// Handle `device.verify.confirm`.
pub async fn confirm_verify(
    params: &VerifyFlowParams,
) -> Result<VerificationActionResult, WorkspaceError> {
    verification::confirm_sas(&params.flow_id)
        .await
        .map_err(verr)?;
    Ok(VerificationActionResult {
        flow_id: params.flow_id.clone(),
        state: "confirm_sent".to_string(),
    })
}

/// Handle `device.verify.cancel`.
pub async fn cancel_verify(
    params: &VerifyFlowParams,
) -> Result<VerificationActionResult, WorkspaceError> {
    verification::cancel_sas(&params.flow_id)
        .await
        .map_err(verr)?;
    Ok(VerificationActionResult {
        flow_id: params.flow_id.clone(),
        state: "cancelled".to_string(),
    })
}

/// Handle `cross_signing.bootstrap`.
pub async fn bootstrap_cross_signing_for_session(
    session: &StoredSession,
) -> Result<CrossSigningStatusInfo, WorkspaceError> {
    let client = restore_client(session).await?;
    client
        .sync_once(matrix_sdk::config::SyncSettings::default())
        .await
        .map_err(WorkspaceError::from)?;
    verification::bootstrap_cross_signing(&client)
        .await
        .map_err(verr)
}

/// Handle `cross_signing.status`.
pub async fn cross_signing_status_for_session(
    session: &StoredSession,
) -> Result<CrossSigningStatusInfo, WorkspaceError> {
    let client = restore_client(session).await?;
    client
        .sync_once(matrix_sdk::config::SyncSettings::default())
        .await
        .map_err(WorkspaceError::from)?;
    Ok(verification::cross_signing_status(&client).await)
}

/// Maximum wall-clock time to wait for an interactive verification step before
/// the streaming handler gives up and tears the flow down.
///
/// This bounds all three phases of an interactive verify: the two `/sync`-driven
/// phases (via [`drive_until`]) and the operator-decision wait (via
/// [`read_verify_decision`]). Without a bound on the decision wait, a stalled
/// operator or hung client would block the single-threaded IPC dispatch
/// indefinitely (issue #258).
pub const VERIFY_DEADLINE: Duration = Duration::from_secs(300);

/// The operator's decision after comparing the short-authentication string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyDecision {
    /// The strings matched — complete the verification.
    Confirm,
    /// The strings did not match, or the operator aborted — cancel.
    Cancel,
}

/// Read the operator's confirm/cancel control frame from `stream`, waiting at
/// most `timeout`.
///
/// Returns [`VerifyDecision::Confirm`] **only** for an explicit, well-formed
/// `confirm` control frame received before the deadline. A `cancel`, any other
/// method, a malformed frame, a clean EOF, a read error, **or the timeout
/// elapsing** all yield [`VerifyDecision::Cancel`]. This is the single
/// fail-safe classification point: the lone path to `Confirm` is a deliberate
/// operator confirmation, so a stalled, abandoned, or hung client can never be
/// mistaken for approval (issue #258).
///
/// The wait is bounded by setting a read timeout on the socket: a blocking read
/// that receives no data returns an error after `timeout`, which the
/// classification above maps to `Cancel`. The stream's prior read timeout is
/// saved and restored (best effort) before returning, because the same
/// connection is reused for the phase-3 result frame and connection teardown.
pub fn read_verify_decision(
    stream: &mut std::os::unix::net::UnixStream,
    timeout: Duration,
) -> VerifyDecision {
    let prior = stream.read_timeout().ok().flatten();
    let _ = stream.set_read_timeout(Some(timeout));
    let decision = match mx_agent_ipc::read_frame(stream) {
        Ok(Some(bytes)) => match serde_json::from_slice::<mx_agent_ipc::Request>(&bytes) {
            Ok(control) if control.method == "confirm" => VerifyDecision::Confirm,
            _ => VerifyDecision::Cancel,
        },
        _ => VerifyDecision::Cancel,
    };
    // Restore the prior timeout (best effort) so phase-3 framing/teardown on
    // this same connection is unaffected.
    let _ = stream.set_read_timeout(prior);
    decision
}

/// Drive an interactive SAS verification over a single held-open connection.
///
/// `frame` writes a flow update to the CLI; `wait_decision` blocks until the
/// operator's confirm/cancel arrives **on the same connection** (the IPC server
/// is single-threaded, so the decision cannot come over a second connection
/// without deadlocking — it is multiplexed onto this socket, like the PTY path).
///
/// The handler restores a client, sends a verification request, drives `/sync`
/// until the SAS can be presented (emitting [`DeviceVerifyFrame::EmojiReady`]),
/// waits for the operator decision, applies it, then drives `/sync` to
/// completion or cancellation. The SAS object lives in this handler's client for
/// the whole flow, so confirm/cancel act on a live verification.
///
/// Note: this drives its own short `/sync` loop, so the operator should treat an
/// interactive verification as the daemon's focus while attended; the
/// headless/out-of-band alternative is `device.verify.manual`.
pub async fn run_device_verify<F, D>(
    session: &StoredSession,
    params: &DeviceVerifyStartParams,
    running: &AtomicBool,
    mut frame: F,
    mut wait_decision: D,
) -> Result<(), WorkspaceError>
where
    F: FnMut(DeviceVerifyFrame),
    D: FnMut() -> VerifyDecision,
{
    let client = restore_client(session).await?;
    // Populate device lists so the peer device is known before requesting.
    client
        .sync_once(matrix_sdk::config::SyncSettings::default())
        .await
        .map_err(WorkspaceError::from)?;

    let flow_id = match verification::start_sas(&client, &params.user, &params.device).await {
        Ok(flow_id) => flow_id,
        Err(e) => {
            frame(DeviceVerifyFrame::Error {
                message: e.to_string(),
            });
            return Ok(());
        }
    };
    frame(DeviceVerifyFrame::Started {
        flow_id: flow_id.clone(),
    });

    // Phase 1: drive `/sync` until the short-auth string can be presented.
    match drive_until(&client, &flow_id, running, |advance| {
        matches!(advance, SasAdvance::Ready { .. })
    })
    .await
    {
        DriveOutcome::Reached(SasAdvance::Ready { emoji, decimals }) => {
            frame(DeviceVerifyFrame::EmojiReady {
                flow_id: flow_id.clone(),
                emoji,
                decimals,
            });
        }
        terminal => {
            frame(terminal.into_frame(&flow_id));
            verification::forget_sas(&flow_id);
            return Ok(());
        }
    }

    // Phase 2: block for the operator's confirm/cancel on the same connection.
    match wait_decision() {
        VerifyDecision::Confirm => {
            if let Err(e) = verification::confirm_sas(&flow_id).await {
                frame(DeviceVerifyFrame::Error {
                    message: e.to_string(),
                });
                verification::forget_sas(&flow_id);
                return Ok(());
            }
        }
        VerifyDecision::Cancel => {
            let _ = verification::cancel_sas(&flow_id).await;
            frame(DeviceVerifyFrame::Cancelled {
                flow_id: flow_id.clone(),
            });
            return Ok(());
        }
    }

    // Phase 3: drive `/sync` until the verification completes (or is cancelled
    // by the peer).
    let outcome = drive_until(&client, &flow_id, running, |advance| {
        matches!(advance, SasAdvance::Done | SasAdvance::Cancelled)
    })
    .await;
    frame(outcome.into_frame(&flow_id));
    verification::forget_sas(&flow_id);
    Ok(())
}

/// Outcome of a [`drive_until`] sync loop.
enum DriveOutcome {
    /// The predicate matched; carries the matching advance.
    Reached(SasAdvance),
    /// The verification was cancelled.
    Cancelled,
    /// The flow timed out or shutdown was requested.
    TimedOut,
    /// A crypto error occurred.
    Errored(String),
}

impl DriveOutcome {
    fn into_frame(self, flow_id: &str) -> DeviceVerifyFrame {
        match self {
            DriveOutcome::Reached(SasAdvance::Done) => DeviceVerifyFrame::Confirmed {
                flow_id: flow_id.to_string(),
            },
            DriveOutcome::Reached(SasAdvance::Cancelled) | DriveOutcome::Cancelled => {
                DeviceVerifyFrame::Cancelled {
                    flow_id: flow_id.to_string(),
                }
            }
            DriveOutcome::Reached(_) => DeviceVerifyFrame::Error {
                message: "unexpected verification state".to_string(),
            },
            DriveOutcome::TimedOut => DeviceVerifyFrame::Error {
                message: "verification timed out".to_string(),
            },
            DriveOutcome::Errored(message) => DeviceVerifyFrame::Error { message },
        }
    }
}

/// Repeatedly `/sync` and advance the flow until `done(advance)` is true, a
/// cancellation/error occurs, or the deadline passes.
async fn drive_until<P>(
    client: &matrix_sdk::Client,
    flow_id: &str,
    running: &AtomicBool,
    done: P,
) -> DriveOutcome
where
    P: Fn(&SasAdvance) -> bool,
{
    let deadline = Instant::now() + VERIFY_DEADLINE;
    loop {
        if !running.load(Ordering::SeqCst) || Instant::now() >= deadline {
            return DriveOutcome::TimedOut;
        }
        // Drive to-device verification traffic with a short-timeout sync.
        let _ = client
            .sync_once(matrix_sdk::config::SyncSettings::default().timeout(Duration::from_secs(3)))
            .await;
        match verification::advance_sas(flow_id).await {
            Ok(advance) => {
                if matches!(advance, SasAdvance::Cancelled) {
                    return DriveOutcome::Cancelled;
                }
                if done(&advance) {
                    return DriveOutcome::Reached(advance);
                }
            }
            Err(e) => return DriveOutcome::Errored(e.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Write a well-formed JSON-RPC request frame with the given method to `stream`.
    fn write_control_frame(stream: &mut std::os::unix::net::UnixStream, method: &str) {
        let req =
            mx_agent_ipc::Request::new(serde_json::json!(1u64), method, serde_json::Value::Null);
        let bytes = serde_json::to_vec(&req).unwrap();
        mx_agent_ipc::write_frame(stream, &bytes).unwrap();
    }

    #[test]
    fn device_verify_frames_serialize_with_event_tag() {
        let started = DeviceVerifyFrame::Started {
            flow_id: "flow_1".to_string(),
        };
        let json = serde_json::to_string(&started).unwrap();
        assert!(json.contains("\"event\":\"started\""), "got {json}");
        assert!(json.contains("flow_1"));

        let ready = DeviceVerifyFrame::EmojiReady {
            flow_id: "flow_1".to_string(),
            emoji: Some(vec![EmojiPair {
                symbol: "🐶".to_string(),
                description: "Dog".to_string(),
            }]),
            decimals: None,
        };
        let json = serde_json::to_string(&ready).unwrap();
        assert!(json.contains("\"event\":\"emoji-ready\""), "got {json}");
        assert!(json.contains("Dog"));
        // Absent decimals are omitted rather than serialized as null.
        assert!(!json.contains("decimals"), "got {json}");
    }

    #[test]
    fn device_list_params_default_is_empty() {
        let params = DeviceListParams::default();
        assert!(params.room.is_none());
        assert!(params.user.is_none());
        // Absent fields parse to None (backward/forward compatible).
        let parsed: DeviceListParams = serde_json::from_str("{}").unwrap();
        assert_eq!(parsed, params);
    }

    // --- DriveOutcome::into_frame mappings (issue #240) ---

    #[test]
    fn drive_outcome_reached_done_maps_to_confirmed() {
        let frame = DriveOutcome::Reached(SasAdvance::Done).into_frame("flow_1");
        match frame {
            DeviceVerifyFrame::Confirmed { flow_id } => assert_eq!(flow_id, "flow_1"),
            other => panic!("expected Confirmed, got {other:?}"),
        }
    }

    #[test]
    fn drive_outcome_reached_cancelled_maps_to_cancelled() {
        let frame = DriveOutcome::Reached(SasAdvance::Cancelled).into_frame("flow_2");
        assert!(
            matches!(frame, DeviceVerifyFrame::Cancelled { .. }),
            "Reached(Cancelled) must map to DeviceVerifyFrame::Cancelled; got {frame:?}"
        );
    }

    #[test]
    fn drive_outcome_cancelled_maps_to_cancelled() {
        let frame = DriveOutcome::Cancelled.into_frame("flow_3");
        assert!(
            matches!(frame, DeviceVerifyFrame::Cancelled { .. }),
            "DriveOutcome::Cancelled must map to DeviceVerifyFrame::Cancelled; got {frame:?}"
        );
    }

    #[test]
    fn drive_outcome_timed_out_maps_to_error() {
        let frame = DriveOutcome::TimedOut.into_frame("flow_4");
        match frame {
            DeviceVerifyFrame::Error { message } => {
                assert!(
                    message.contains("timed out"),
                    "expected 'timed out' in: {message}"
                )
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[test]
    fn drive_outcome_errored_carries_message() {
        let frame = DriveOutcome::Errored("sdk failure".to_string()).into_frame("flow_5");
        match frame {
            DeviceVerifyFrame::Error { message } => assert_eq!(message, "sdk failure"),
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[test]
    fn drive_outcome_unexpected_states_map_to_error() {
        // Reached(Pending) and Reached(Negotiating) are unexpected terminal states
        // for a phase-3 drive; they must map to a non-secret Error frame.
        let frame = DriveOutcome::Reached(SasAdvance::Pending).into_frame("flow_6");
        assert!(
            matches!(frame, DeviceVerifyFrame::Error { .. }),
            "Reached(Pending) must map to Error; got {frame:?}"
        );
        let frame = DriveOutcome::Reached(SasAdvance::Negotiating).into_frame("flow_6");
        assert!(
            matches!(frame, DeviceVerifyFrame::Error { .. }),
            "Reached(Negotiating) must map to Error; got {frame:?}"
        );
        let frame = DriveOutcome::Reached(SasAdvance::Ready {
            emoji: None,
            decimals: None,
        })
        .into_frame("flow_6");
        assert!(
            matches!(frame, DeviceVerifyFrame::Error { .. }),
            "Reached(Ready) must map to Error; got {frame:?}"
        );
    }

    // --- Additional DeviceVerifyFrame serialization tests ---

    #[test]
    fn device_verify_frame_confirmed_serializes_with_event_tag() {
        let frame = DeviceVerifyFrame::Confirmed {
            flow_id: "flow_1".to_string(),
        };
        let json = serde_json::to_string(&frame).unwrap();
        assert!(json.contains("\"event\":\"confirmed\""), "got {json}");
        assert!(json.contains("flow_1"), "got {json}");
    }

    #[test]
    fn device_verify_frame_cancelled_serializes_with_event_tag() {
        let frame = DeviceVerifyFrame::Cancelled {
            flow_id: "flow_2".to_string(),
        };
        let json = serde_json::to_string(&frame).unwrap();
        assert!(json.contains("\"event\":\"cancelled\""), "got {json}");
        assert!(json.contains("flow_2"), "got {json}");
    }

    #[test]
    fn device_verify_frame_error_serializes_with_event_tag() {
        let frame = DeviceVerifyFrame::Error {
            message: "something went wrong".to_string(),
        };
        let json = serde_json::to_string(&frame).unwrap();
        assert!(json.contains("\"event\":\"error\""), "got {json}");
        assert!(json.contains("something went wrong"), "got {json}");
    }

    // --- IPC parameter type round-trips ---

    #[test]
    fn verify_flow_params_round_trips() {
        let params = VerifyFlowParams {
            flow_id: "flow_abc".to_string(),
        };
        let json = serde_json::to_string(&params).unwrap();
        let back: VerifyFlowParams = serde_json::from_str(&json).unwrap();
        assert_eq!(back, params);
    }

    #[test]
    fn verification_action_result_round_trips() {
        let result = VerificationActionResult {
            flow_id: "flow_abc".to_string(),
            state: "confirm_sent".to_string(),
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: VerificationActionResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back, result);
        assert!(json.contains("\"state\":\"confirm_sent\""), "got {json}");
    }

    #[test]
    fn device_show_params_round_trips() {
        let params = DeviceShowParams {
            user: "@user:hs".to_string(),
            device: "DEVID".to_string(),
        };
        let json = serde_json::to_string(&params).unwrap();
        let back: DeviceShowParams = serde_json::from_str(&json).unwrap();
        assert_eq!(back, params);
    }

    #[test]
    fn device_verify_manual_params_round_trips_with_and_without_fingerprint() {
        // With fingerprint.
        let with_fp = DeviceVerifyManualParams {
            user: "@user:hs".to_string(),
            device: "DEVID".to_string(),
            fingerprint: Some("ed25519:AbCd".to_string()),
        };
        let json = serde_json::to_string(&with_fp).unwrap();
        let back: DeviceVerifyManualParams = serde_json::from_str(&json).unwrap();
        assert_eq!(back, with_fp);
        assert!(json.contains("ed25519:AbCd"), "got {json}");

        // Without fingerprint: absent on input must parse to None (backward compat).
        let no_fp: DeviceVerifyManualParams =
            serde_json::from_str(r#"{"user":"@u:hs","device":"D"}"#).unwrap();
        assert!(no_fp.fingerprint.is_none());
    }

    #[test]
    fn device_verify_start_params_round_trips() {
        let params = DeviceVerifyStartParams {
            user: "@peer:hs".to_string(),
            device: "PEERDEV".to_string(),
        };
        let json = serde_json::to_string(&params).unwrap();
        let back: DeviceVerifyStartParams = serde_json::from_str(&json).unwrap();
        assert_eq!(back, params);
    }

    // === Issue #258: read_verify_decision fail-safe semantics ===

    #[test]
    fn verify_deadline_is_300_seconds() {
        // The decision wait must use the same ~300 s budget as the SAS phases.
        assert_eq!(VERIFY_DEADLINE, std::time::Duration::from_secs(300));
    }

    #[test]
    fn read_verify_decision_confirm_returns_confirm() {
        let (mut reader, mut writer) = std::os::unix::net::UnixStream::pair().unwrap();
        write_control_frame(&mut writer, "confirm");
        drop(writer);
        assert_eq!(
            read_verify_decision(&mut reader, std::time::Duration::from_secs(5)),
            VerifyDecision::Confirm,
        );
    }

    #[test]
    fn read_verify_decision_cancel_method_returns_cancel() {
        let (mut reader, mut writer) = std::os::unix::net::UnixStream::pair().unwrap();
        write_control_frame(&mut writer, "cancel");
        drop(writer);
        assert_eq!(
            read_verify_decision(&mut reader, std::time::Duration::from_secs(5)),
            VerifyDecision::Cancel,
        );
    }

    #[test]
    fn read_verify_decision_unknown_method_returns_cancel() {
        // "device.verify.confirm" is not the bare "confirm" control frame.
        let (mut reader, mut writer) = std::os::unix::net::UnixStream::pair().unwrap();
        write_control_frame(&mut writer, "device.verify.confirm");
        drop(writer);
        assert_eq!(
            read_verify_decision(&mut reader, std::time::Duration::from_secs(5)),
            VerifyDecision::Cancel,
        );
    }

    #[test]
    fn read_verify_decision_malformed_json_returns_cancel() {
        let (mut reader, mut writer) = std::os::unix::net::UnixStream::pair().unwrap();
        mx_agent_ipc::write_frame(&mut writer, b"{not valid json}").unwrap();
        drop(writer);
        assert_eq!(
            read_verify_decision(&mut reader, std::time::Duration::from_secs(5)),
            VerifyDecision::Cancel,
        );
    }

    #[test]
    fn read_verify_decision_eof_returns_cancel() {
        let (mut reader, writer) = std::os::unix::net::UnixStream::pair().unwrap();
        drop(writer); // immediate EOF — no frame
        assert_eq!(
            read_verify_decision(&mut reader, std::time::Duration::from_secs(5)),
            VerifyDecision::Cancel,
        );
    }

    #[test]
    fn read_verify_decision_timeout_returns_cancel() {
        let (mut reader, _writer) = std::os::unix::net::UnixStream::pair().unwrap();
        // _writer stays open so the reader never sees EOF; the deadline must fire.
        assert_eq!(
            read_verify_decision(&mut reader, std::time::Duration::from_millis(20)),
            VerifyDecision::Cancel,
        );
    }

    #[test]
    fn read_verify_decision_restores_prior_timeout() {
        let (mut reader, mut writer) = std::os::unix::net::UnixStream::pair().unwrap();
        // Set a recognisable pre-existing timeout that differs from VERIFY_DEADLINE.
        reader
            .set_read_timeout(Some(std::time::Duration::from_secs(42)))
            .unwrap();
        write_control_frame(&mut writer, "confirm");
        drop(writer);
        let _ = read_verify_decision(&mut reader, std::time::Duration::from_secs(5));
        // The original timeout must survive the call (same connection is reused).
        assert_eq!(
            reader.read_timeout().unwrap(),
            Some(std::time::Duration::from_secs(42)),
            "read_verify_decision must restore the prior socket read timeout",
        );
    }

    #[test]
    fn read_verify_decision_only_exact_confirm_is_confirm() {
        // Fail-safe regression (issue #258): only the bare "confirm" method may
        // yield Confirm; all other strings must yield Cancel.
        let non_confirm = [
            "CONFIRM",
            "Confirm",
            "cancel",
            "device.verify.confirm",
            "confirm.sas",
            "",
        ];
        for method in &non_confirm {
            let (mut reader, mut writer) = std::os::unix::net::UnixStream::pair().unwrap();
            write_control_frame(&mut writer, method);
            drop(writer);
            assert_eq!(
                read_verify_decision(&mut reader, std::time::Duration::from_secs(5)),
                VerifyDecision::Cancel,
                "method {:?} must yield Cancel, not Confirm",
                method,
            );
        }
    }
}
