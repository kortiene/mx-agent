//! Device verification, cross-signing, and key-backup/recovery manager
//! (issue #240, architecture §13.1/§13.2).
//!
//! The daemon owns all Matrix E2EE state. This module is the daemon-side
//! manager that wraps [`matrix_sdk`]'s `client.encryption()` surface so the
//! stateless CLI can, over IPC, (a) list peer devices with their verification
//! status and fingerprints, (b) verify a device interactively (emoji/SAS) or
//! out-of-band (fingerprint), (c) bootstrap and observe cross-signing, and (d)
//! enable/inspect/restore server-side key backup.
//!
//! ## Two distinct trust roots
//!
//! Everything here concerns the **Matrix device Ed25519 key** — the *transport*
//! identity that governs who the daemon shares Megolm keys with and who can
//! read/inject encrypted traffic. It is **not** the mx-agent Ed25519 *signing*
//! key (see [`crate::signing`]) that authorizes privileged actions. The two are
//! different keys with different fingerprints; device verification never
//! substitutes for signing + local trust + local policy, which remain the
//! authoritative execution gate (see [`crate::exec::enforce_verified_device`]).
//!
//! ## Secrets
//!
//! No private key material crosses IPC. [`DeviceInfo`] carries only non-secret
//! fields (ids, the public device fingerprint, verification status). The
//! key-backup recovery key is a [`Secret`] surfaced to the operator exactly once
//! and never logged.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Mutex, OnceLock};

use matrix_sdk::encryption::identities::Device;
use matrix_sdk::encryption::recovery::RecoveryState;
use matrix_sdk::encryption::verification::SasVerification;
use matrix_sdk::ruma::{OwnedDeviceId, UserId};
use matrix_sdk::Client;
use serde::{Deserialize, Serialize};

use crate::session::Secret;

/// Non-secret description of a Matrix device, safe to return over IPC and print.
///
/// Carries no private key material. `ed25519_fingerprint` is the device's
/// **public** Ed25519 key (the transport identity), explicitly labelled
/// `ed25519:` to distinguish it from the mx-agent signing-key fingerprint
/// (`SHA256:…`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceInfo {
    /// Owning Matrix user id, e.g. `@peer:hs`.
    pub user_id: String,
    /// Matrix device id.
    pub device_id: String,
    /// Human-readable device display name, if the server has one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// The device's public Ed25519 key as `ed25519:<base64>` — the Matrix
    /// *device* key, distinct from the mx-agent signing key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ed25519_fingerprint: Option<String>,
    /// Whether the device is verified (directly or via cross-signing).
    pub verified: bool,
    /// Whether the device is trusted through the owner's cross-signing identity.
    pub cross_signed: bool,
    /// Whether the device is explicitly blacklisted/blocked.
    pub blacklisted: bool,
    /// Whether the device is locally (manually) trusted.
    pub locally_trusted: bool,
}

/// Cross-signing identity status for the daemon's own user.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossSigningStatusInfo {
    /// Whether the master key is available locally.
    pub has_master: bool,
    /// Whether the self-signing key is available locally.
    pub has_self_signing: bool,
    /// Whether the user-signing key is available locally.
    pub has_user_signing: bool,
    /// Whether all three cross-signing keys are present (identity complete).
    pub complete: bool,
}

/// Server-side key-backup / recovery status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryStatusInfo {
    /// Coarse recovery state: `unknown` | `enabled` | `disabled` | `incomplete`.
    pub state: String,
    /// Whether key backup is enabled (uploading room keys).
    pub backup_enabled: bool,
    /// Whether a key backup version exists on the homeserver.
    pub backup_exists_on_server: bool,
}

/// Result of enabling recovery: the one-time recovery key plus the new status.
///
/// The recovery key is the operator's secret to record. It is wrapped in
/// [`Secret`] so it never appears in logs or `Debug` output; it is surfaced to
/// the human exactly once and never persisted in clear.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryEnableResult {
    /// The generated recovery key, surfaced once (redacted in `Debug`).
    pub recovery_key: Secret,
    /// Recovery/backup status after enabling.
    pub status: RecoveryStatusInfo,
}

/// One emoji of a SAS short-authentication string.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmojiPair {
    /// The emoji symbol, e.g. `🐶`.
    pub symbol: String,
    /// Its description, e.g. `Dog`.
    pub description: String,
}

/// Errors produced by the verification manager.
#[derive(Debug)]
pub enum VerificationError {
    /// A matrix-sdk crypto operation failed (message only; never carries
    /// secrets).
    Sdk(String),
    /// The named user or device was not found.
    NotFound {
        /// The user id queried.
        user_id: String,
        /// The device id queried, if device-specific.
        device_id: Option<String>,
    },
    /// An out-of-band fingerprint did not match the device's actual key.
    FingerprintMismatch {
        /// The fingerprint the operator supplied.
        expected: String,
        /// The device's actual `ed25519:<base64>` fingerprint.
        actual: String,
    },
    /// No in-flight SAS verification exists for the given flow id.
    UnknownFlow {
        /// The flow id that was not found.
        flow_id: String,
    },
}

impl fmt::Display for VerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sdk(msg) => write!(f, "{msg}"),
            Self::NotFound {
                user_id,
                device_id: Some(device_id),
            } => write!(f, "device {device_id:?} for user {user_id:?} not found"),
            Self::NotFound {
                user_id,
                device_id: None,
            } => write!(f, "user {user_id:?} not found"),
            Self::FingerprintMismatch { expected, actual } => write!(
                f,
                "fingerprint mismatch: supplied {expected:?} but device key is {actual:?}"
            ),
            Self::UnknownFlow { flow_id } => {
                write!(f, "no in-flight verification for flow {flow_id:?}")
            }
        }
    }
}

impl std::error::Error for VerificationError {}

/// Parse a Matrix user id, mapping a malformed value to a non-secret error.
fn parse_user(user_id: &str) -> Result<matrix_sdk::ruma::OwnedUserId, VerificationError> {
    UserId::parse(user_id)
        .map_err(|e| VerificationError::Sdk(format!("invalid user id {user_id:?}: {e}")))
}

/// Build a non-secret [`DeviceInfo`] from a matrix-sdk [`Device`].
fn device_info(device: &Device) -> DeviceInfo {
    DeviceInfo {
        user_id: device.user_id().to_string(),
        device_id: device.device_id().to_string(),
        display_name: device.display_name().map(str::to_string),
        ed25519_fingerprint: device
            .ed25519_key()
            .map(|k| format!("ed25519:{}", k.to_base64())),
        verified: device.is_verified(),
        cross_signed: device.is_verified_with_cross_signing(),
        blacklisted: device.is_blacklisted(),
        locally_trusted: device.is_locally_trusted(),
    }
}

/// Normalize a fingerprint for comparison: drop an optional `ed25519:` prefix
/// and surrounding whitespace. Comparison stays case-sensitive on the base64
/// body (base64 is case-significant).
fn normalize_fingerprint(fingerprint: &str) -> &str {
    fingerprint
        .trim()
        .strip_prefix("ed25519:")
        .unwrap_or(fingerprint.trim())
}

/// List the devices of `user_id` with verification status and fingerprints.
///
/// Reads from the daemon's local crypto store; sorted by device id for stable
/// output.
pub async fn list_devices(
    client: &Client,
    user_id: &str,
) -> Result<Vec<DeviceInfo>, VerificationError> {
    let user = parse_user(user_id)?;
    let devices = client
        .encryption()
        .get_user_devices(&user)
        .await
        .map_err(|e| VerificationError::Sdk(e.to_string()))?;
    let mut infos: Vec<DeviceInfo> = devices.devices().map(|d| device_info(&d)).collect();
    infos.sort_by(|a, b| a.device_id.cmp(&b.device_id));
    Ok(infos)
}

/// Show a single device's info, or `None` if the daemon has not seen it.
pub async fn show_device(
    client: &Client,
    user_id: &str,
    device_id: &str,
) -> Result<Option<DeviceInfo>, VerificationError> {
    let user = parse_user(user_id)?;
    let dev_id = OwnedDeviceId::from(device_id);
    let device = client
        .encryption()
        .get_device(&user, &dev_id)
        .await
        .map_err(|e| VerificationError::Sdk(e.to_string()))?;
    Ok(device.as_ref().map(device_info))
}

/// Mark a device verified out-of-band after confirming its fingerprint.
///
/// When `expected_fingerprint` is supplied it must match the device's actual
/// Ed25519 key (an `ed25519:` prefix is optional); a mismatch is refused and the
/// device is **not** verified. When omitted, the operator is asserting they have
/// already confirmed the device by other means.
pub async fn manual_verify(
    client: &Client,
    user_id: &str,
    device_id: &str,
    expected_fingerprint: Option<&str>,
) -> Result<DeviceInfo, VerificationError> {
    let user = parse_user(user_id)?;
    let dev_id = OwnedDeviceId::from(device_id);
    let device = client
        .encryption()
        .get_device(&user, &dev_id)
        .await
        .map_err(|e| VerificationError::Sdk(e.to_string()))?
        .ok_or_else(|| VerificationError::NotFound {
            user_id: user_id.to_string(),
            device_id: Some(device_id.to_string()),
        })?;

    if let Some(expected) = expected_fingerprint {
        let actual = device
            .ed25519_key()
            .map(|k| k.to_base64())
            .unwrap_or_default();
        if normalize_fingerprint(expected) != normalize_fingerprint(&actual) {
            return Err(VerificationError::FingerprintMismatch {
                expected: expected.to_string(),
                actual: format!("ed25519:{actual}"),
            });
        }
    }

    device
        .verify()
        .await
        .map_err(|e| VerificationError::Sdk(e.to_string()))?;
    Ok(device_info(&device))
}

/// Report the daemon's own cross-signing identity status.
pub async fn cross_signing_status(client: &Client) -> CrossSigningStatusInfo {
    match client.encryption().cross_signing_status().await {
        Some(status) => CrossSigningStatusInfo {
            has_master: status.has_master,
            has_self_signing: status.has_self_signing,
            has_user_signing: status.has_user_signing,
            complete: status.has_master && status.has_self_signing && status.has_user_signing,
        },
        None => CrossSigningStatusInfo::default(),
    }
}

/// Bootstrap (create + publish) the daemon's cross-signing identity if needed.
///
/// Idempotent: a no-op when cross-signing is already set up. Returns the
/// resulting status.
pub async fn bootstrap_cross_signing(
    client: &Client,
) -> Result<CrossSigningStatusInfo, VerificationError> {
    client
        .encryption()
        .bootstrap_cross_signing_if_needed(None)
        .await
        .map_err(|e| VerificationError::Sdk(e.to_string()))?;
    Ok(cross_signing_status(client).await)
}

/// Map a [`RecoveryState`] to a stable lowercase string.
fn recovery_state_str(state: RecoveryState) -> String {
    match state {
        RecoveryState::Unknown => "unknown",
        RecoveryState::Enabled => "enabled",
        RecoveryState::Disabled => "disabled",
        RecoveryState::Incomplete => "incomplete",
    }
    .to_string()
}

/// Report server-side key-backup / recovery status.
pub async fn recovery_status(client: &Client) -> RecoveryStatusInfo {
    let encryption = client.encryption();
    let state = recovery_state_str(encryption.recovery().state());
    let backups = encryption.backups();
    let backup_enabled = backups.are_enabled().await;
    let backup_exists_on_server = backups.exists_on_server().await.unwrap_or(false);
    RecoveryStatusInfo {
        state,
        backup_enabled,
        backup_exists_on_server,
    }
}

/// Provision Secure Secret Storage + server-side key backup, returning the
/// one-time recovery key.
///
/// The returned [`RecoveryEnableResult::recovery_key`] is the operator's secret
/// to record; it is surfaced once and never persisted in clear or logged.
pub async fn enable_recovery(client: &Client) -> Result<RecoveryEnableResult, VerificationError> {
    let recovery = client.encryption().recovery();
    let recovery_key = recovery
        .enable()
        .await
        .map_err(|e| VerificationError::Sdk(e.to_string()))?;
    Ok(RecoveryEnableResult {
        recovery_key: Secret::new(recovery_key),
        status: recovery_status(client).await,
    })
}

/// Re-import keys from server-side backup using an operator-supplied recovery
/// key (used after a re-provision onto a fresh host or a wiped crypto store).
pub async fn recover(
    client: &Client,
    recovery_key: &str,
) -> Result<RecoveryStatusInfo, VerificationError> {
    client
        .encryption()
        .recovery()
        .recover(recovery_key)
        .await
        .map_err(|e| VerificationError::Sdk(e.to_string()))?;
    Ok(recovery_status(client).await)
}

/// Best-effort verification status of `user_id`'s devices, for the optional
/// `require_verified_device` transport gate (issue #240).
///
/// Returns `Some(true)` when the user has known devices and **all** of them are
/// verified, `Some(false)` when at least one known device is unverified, and
/// `None` when the status cannot be determined (no devices in the crypto store
/// yet, or a crypto error). The gate treats anything other than `Some(true)` as
/// "not verified" when the knob is on, so an indeterminate status fails safe.
pub async fn sender_verified(client: &Client, user_id: &str) -> Option<bool> {
    let user = UserId::parse(user_id).ok()?;
    let devices = client.encryption().get_user_devices(&user).await.ok()?;
    let mut any = false;
    let mut all_verified = true;
    for device in devices.devices() {
        any = true;
        if !device.is_verified() {
            all_verified = false;
        }
    }
    if any {
        Some(all_verified)
    } else {
        None
    }
}

// --- Interactive SAS verification flow registry ------------------------------
//
// An interactive emoji/SAS verification is long-lived and spans several
// to-device round trips. The streaming `device.verify.start` IPC handler starts
// the flow and drives a sync loop; the operator's `confirm`/`cancel` arrive as
// separate IPC calls that must act on the *same* in-flight verification. We
// therefore register active flows in a process-global map keyed by an mx-agent
// flow id (the SDK's flow id is not exposed on `SasVerification`) so all three
// IPC methods share one object. Both `VerificationRequest` and `SasVerification`
// are `Clone` (cheap, `Arc`-backed), so a flow is cloned out from under the lock
// before any `.await`, never holding the `std::sync::Mutex` across a yield.

/// An in-flight interactive verification.
#[derive(Clone)]
enum SasFlow {
    /// Requested but not yet accepted by the peer (still negotiating methods).
    Requested(matrix_sdk::encryption::verification::VerificationRequest),
    /// An active SAS exchange.
    Active(SasVerification),
}

type SasRegistry = Mutex<HashMap<String, SasFlow>>;

fn sas_flows() -> &'static SasRegistry {
    static FLOWS: OnceLock<SasRegistry> = OnceLock::new();
    FLOWS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn get_flow(flow_id: &str) -> Option<SasFlow> {
    sas_flows()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(flow_id)
        .cloned()
}

fn set_flow(flow_id: &str, flow: SasFlow) {
    sas_flows()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(flow_id.to_string(), flow);
}

/// Drop an in-flight verification from the registry.
pub fn forget_sas(flow_id: &str) {
    sas_flows()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(flow_id);
}

/// A single observation of an interactive verification's progress, returned by
/// [`advance_sas`] so the streaming IPC handler can emit a flow frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SasAdvance {
    /// Requested; the peer has not accepted the verification yet.
    Pending,
    /// SAS is active but the short-auth string cannot be presented yet.
    Negotiating,
    /// The short-auth string is ready for the operator to compare.
    Ready {
        /// Emoji SAS, when both sides support it.
        emoji: Option<Vec<EmojiPair>>,
        /// Decimal SAS fallback.
        decimals: Option<(u16, u16, u16)>,
    },
    /// The verification completed successfully (the device is now verified).
    Done,
    /// The verification was cancelled by either side.
    Cancelled,
}

/// Start an interactive SAS verification against a peer device.
///
/// Uses the request-based verification flow (`request_verification`): the daemon
/// sends a verification request the peer must accept before the SAS begins. The
/// returned flow id is the registry key the operator's `confirm`/`cancel`
/// reference; the caller drives `/sync` and calls [`advance_sas`] to progress
/// and observe the flow.
pub async fn start_sas(
    client: &Client,
    user_id: &str,
    device_id: &str,
) -> Result<String, VerificationError> {
    let user = parse_user(user_id)?;
    let dev_id = OwnedDeviceId::from(device_id);
    let device = client
        .encryption()
        .get_device(&user, &dev_id)
        .await
        .map_err(|e| VerificationError::Sdk(e.to_string()))?
        .ok_or_else(|| VerificationError::NotFound {
            user_id: user_id.to_string(),
            device_id: Some(device_id.to_string()),
        })?;
    let request = device
        .request_verification()
        .await
        .map_err(|e| VerificationError::Sdk(e.to_string()))?;
    let flow_id = mx_agent_protocol::id::generate_request_id();
    set_flow(&flow_id, SasFlow::Requested(request));
    Ok(flow_id)
}

/// Advance and observe an in-flight verification one step.
///
/// Transitions a `Requested` flow to an `Active` SAS once the peer is ready, and
/// reports the current [`SasAdvance`] state. The streaming handler calls this
/// after each `/sync` so it can emit `emoji-ready` / `done` / `cancelled`
/// frames.
pub async fn advance_sas(flow_id: &str) -> Result<SasAdvance, VerificationError> {
    let flow = get_flow(flow_id).ok_or_else(|| VerificationError::UnknownFlow {
        flow_id: flow_id.to_string(),
    })?;
    match flow {
        SasFlow::Requested(request) => {
            if request.is_cancelled() {
                return Ok(SasAdvance::Cancelled);
            }
            if request.is_ready() {
                if let Some(sas) = request
                    .start_sas()
                    .await
                    .map_err(|e| VerificationError::Sdk(e.to_string()))?
                {
                    set_flow(flow_id, SasFlow::Active(sas.clone()));
                    return Ok(advance_for_sas(&sas));
                }
            }
            Ok(SasAdvance::Pending)
        }
        SasFlow::Active(sas) => Ok(advance_for_sas(&sas)),
    }
}

/// Map an active SAS's current state to a [`SasAdvance`].
fn advance_for_sas(sas: &SasVerification) -> SasAdvance {
    if sas.is_cancelled() {
        SasAdvance::Cancelled
    } else if sas.is_done() {
        SasAdvance::Done
    } else if sas.can_be_presented() {
        SasAdvance::Ready {
            emoji: sas_emoji(sas),
            decimals: sas.decimals(),
        }
    } else {
        SasAdvance::Negotiating
    }
}

/// Confirm a presented SAS (the operator compared the emoji and they matched).
pub async fn confirm_sas(flow_id: &str) -> Result<(), VerificationError> {
    match get_flow(flow_id) {
        Some(SasFlow::Active(sas)) => sas
            .confirm()
            .await
            .map_err(|e| VerificationError::Sdk(e.to_string())),
        Some(SasFlow::Requested(_)) => Err(VerificationError::Sdk(
            "verification is not ready to confirm yet".to_string(),
        )),
        None => Err(VerificationError::UnknownFlow {
            flow_id: flow_id.to_string(),
        }),
    }
}

/// Cancel an in-flight verification and forget it.
pub async fn cancel_sas(flow_id: &str) -> Result<(), VerificationError> {
    let flow = get_flow(flow_id).ok_or_else(|| VerificationError::UnknownFlow {
        flow_id: flow_id.to_string(),
    })?;
    let result = match flow {
        SasFlow::Active(sas) => sas.cancel().await,
        SasFlow::Requested(request) => request.cancel().await,
    }
    .map_err(|e| VerificationError::Sdk(e.to_string()));
    forget_sas(flow_id);
    result
}

/// The emoji short-authentication string of a SAS, if it can be presented yet.
fn sas_emoji(sas: &SasVerification) -> Option<Vec<EmojiPair>> {
    sas.emoji().map(|emoji| {
        emoji
            .iter()
            .map(|e| EmojiPair {
                symbol: e.symbol.to_string(),
                description: e.description.to_string(),
            })
            .collect()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_info_serializes_without_private_material() {
        let info = DeviceInfo {
            user_id: "@peer:hs".to_string(),
            device_id: "DEVICEID".to_string(),
            display_name: Some("laptop".to_string()),
            ed25519_fingerprint: Some("ed25519:AbCd".to_string()),
            verified: false,
            cross_signed: false,
            blacklisted: false,
            locally_trusted: false,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("@peer:hs"));
        assert!(json.contains("ed25519:AbCd"));
        // Only the public, non-secret surface is present.
        assert!(!json.contains("private"));
        assert!(!json.contains("secret"));
    }

    #[test]
    fn recovery_key_is_redacted_in_debug() {
        let result = RecoveryEnableResult {
            recovery_key: Secret::new("EsTL 1234 super secret recovery key"),
            status: RecoveryStatusInfo {
                state: "enabled".to_string(),
                backup_enabled: true,
                backup_exists_on_server: true,
            },
        };
        let debug = format!("{result:?}");
        assert!(
            !debug.contains("super secret"),
            "recovery key leaked in debug: {debug}"
        );
    }

    #[test]
    fn normalize_fingerprint_strips_prefix_and_whitespace() {
        assert_eq!(normalize_fingerprint("  ed25519:AbCd  "), "AbCd");
        assert_eq!(normalize_fingerprint("AbCd"), "AbCd");
    }

    #[test]
    fn recovery_state_strings_are_stable() {
        assert_eq!(recovery_state_str(RecoveryState::Enabled), "enabled");
        assert_eq!(recovery_state_str(RecoveryState::Disabled), "disabled");
        assert_eq!(recovery_state_str(RecoveryState::Incomplete), "incomplete");
        assert_eq!(recovery_state_str(RecoveryState::Unknown), "unknown");
    }

    #[test]
    fn verification_error_display_covers_all_variants() {
        // Sdk wraps a non-secret message verbatim.
        let e = VerificationError::Sdk("crypto error".to_string());
        assert_eq!(e.to_string(), "crypto error");

        // NotFound with a specific device id.
        let e = VerificationError::NotFound {
            user_id: "@peer:hs".to_string(),
            device_id: Some("DEVID".to_string()),
        };
        let s = e.to_string();
        assert!(s.contains("DEVID"), "device id missing from: {s}");
        assert!(s.contains("@peer:hs"), "user id missing from: {s}");

        // NotFound without a device id (user-level).
        let e = VerificationError::NotFound {
            user_id: "@peer:hs".to_string(),
            device_id: None,
        };
        let s = e.to_string();
        assert!(s.contains("@peer:hs"), "user id missing from: {s}");

        // FingerprintMismatch names both the supplied and actual fingerprints.
        let e = VerificationError::FingerprintMismatch {
            expected: "ed25519:abc".to_string(),
            actual: "ed25519:xyz".to_string(),
        };
        let s = e.to_string();
        assert!(s.contains("mismatch"), "expected 'mismatch' in: {s}");
        assert!(s.contains("abc"), "expected fingerprint missing from: {s}");
        assert!(s.contains("xyz"), "actual fingerprint missing from: {s}");

        // UnknownFlow names the flow id.
        let e = VerificationError::UnknownFlow {
            flow_id: "flow_42".to_string(),
        };
        let s = e.to_string();
        assert!(s.contains("flow_42"), "flow id missing from: {s}");
    }

    #[test]
    fn cross_signing_status_info_default_is_all_false() {
        let status = CrossSigningStatusInfo::default();
        assert!(!status.has_master);
        assert!(!status.has_self_signing);
        assert!(!status.has_user_signing);
        assert!(!status.complete);
    }

    #[test]
    fn cross_signing_status_info_round_trips_as_json() {
        let status = CrossSigningStatusInfo {
            has_master: true,
            has_self_signing: true,
            has_user_signing: true,
            complete: true,
        };
        let json = serde_json::to_string(&status).unwrap();
        let back: CrossSigningStatusInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(back, status);
        assert!(back.complete);
    }

    #[test]
    fn recovery_status_info_round_trips_as_json() {
        let status = RecoveryStatusInfo {
            state: "enabled".to_string(),
            backup_enabled: true,
            backup_exists_on_server: false,
        };
        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("\"state\":\"enabled\""), "got {json}");
        let back: RecoveryStatusInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(back, status);
    }

    #[test]
    fn device_info_optional_fields_absent_when_none() {
        // display_name and ed25519_fingerprint use skip_serializing_if(Option::is_none)
        // so they must be absent in the JSON when not set.
        let info = DeviceInfo {
            user_id: "@u:hs".to_string(),
            device_id: "DEV".to_string(),
            display_name: None,
            ed25519_fingerprint: None,
            verified: true,
            cross_signed: true,
            blacklisted: false,
            locally_trusted: true,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(
            !json.contains("display_name"),
            "absent field should be omitted: {json}"
        );
        assert!(
            !json.contains("fingerprint"),
            "absent field should be omitted: {json}"
        );
        assert!(json.contains("\"verified\":true"), "got {json}");
        assert!(json.contains("\"cross_signed\":true"), "got {json}");
    }

    #[test]
    fn device_info_blacklisted_flag_serializes_correctly() {
        let info = DeviceInfo {
            user_id: "@bad:hs".to_string(),
            device_id: "BAD".to_string(),
            display_name: None,
            ed25519_fingerprint: None,
            verified: false,
            cross_signed: false,
            blacklisted: true,
            locally_trusted: false,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"blacklisted\":true"), "got {json}");
        assert!(json.contains("\"verified\":false"), "got {json}");
    }

    #[test]
    fn emoji_pair_round_trips_as_json() {
        let pair = EmojiPair {
            symbol: "🐶".to_string(),
            description: "Dog".to_string(),
        };
        let json = serde_json::to_string(&pair).unwrap();
        assert!(json.contains("Dog"), "got {json}");
        let back: EmojiPair = serde_json::from_str(&json).unwrap();
        assert_eq!(back, pair);
    }

    #[test]
    fn forget_sas_on_unknown_flow_is_noop() {
        // Removing a flow id that was never registered must not panic.
        forget_sas("nonexistent-flow-id-abc123xyz-forget");
    }

    #[tokio::test]
    async fn advance_sas_unknown_flow_returns_unknown_flow_error() {
        let result = advance_sas("nonexistent-advance-flow-xyz987").await;
        let err = result.unwrap_err();
        assert!(
            matches!(err, VerificationError::UnknownFlow { .. }),
            "expected UnknownFlow error, got: {err}"
        );
        assert!(
            err.to_string().contains("nonexistent-advance-flow-xyz987"),
            "error should name the flow id; got: {err}"
        );
    }

    #[tokio::test]
    async fn confirm_sas_unknown_flow_returns_unknown_flow_error() {
        let result = confirm_sas("nonexistent-confirm-flow-xyz987").await;
        assert!(
            matches!(result.unwrap_err(), VerificationError::UnknownFlow { .. }),
            "confirm on unknown flow must return UnknownFlow"
        );
    }

    #[tokio::test]
    async fn cancel_sas_unknown_flow_returns_unknown_flow_error() {
        let result = cancel_sas("nonexistent-cancel-flow-xyz987").await;
        assert!(
            matches!(result.unwrap_err(), VerificationError::UnknownFlow { .. }),
            "cancel on unknown flow must return UnknownFlow"
        );
    }
}
