//! IPC handlers for server-side key backup and recovery (issue #240).
//!
//! These daemon-mediated methods provision and inspect Secure Secret Storage +
//! server-side key backup, and re-import keys after a re-provision. The daemon
//! owns all crypto state; the only secret that crosses IPC is the one-time
//! recovery key returned by `recovery.enable`, which is the operator's secret to
//! record (a [`crate::session::Secret`], never logged).

use serde::{Deserialize, Serialize};

use crate::matrix::restore_client;
use crate::session::{Secret, StoredSession};
use crate::verification::{self, RecoveryEnableResult, RecoveryStatusInfo, VerificationError};
use crate::workspace::WorkspaceError;

/// Map a non-secret [`VerificationError`] onto a [`WorkspaceError`] for IPC.
fn verr(e: VerificationError) -> WorkspaceError {
    WorkspaceError::Io(std::io::Error::other(e.to_string()))
}

/// Parameters for `recovery.recover`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoverParams {
    /// The operator-supplied recovery key (or passphrase) recorded when recovery
    /// was enabled. Wrapped in [`Secret`] so it is redacted in `Debug` output
    /// (a stray `tracing::debug!(?params)` cannot leak it) rather than relying on
    /// doc-comment convention. It still round-trips through serde for IPC as a
    /// bare JSON string, because [`Secret`] is `#[serde(transparent)]`.
    pub recovery_key: Secret,
}

/// Handle `recovery.enable`: provision SSSS + key backup and return the
/// generated recovery key once.
pub async fn enable_recovery_for_session(
    session: &StoredSession,
) -> Result<RecoveryEnableResult, WorkspaceError> {
    let client = restore_client(session).await?;
    client
        .sync_once(matrix_sdk::config::SyncSettings::default())
        .await
        .map_err(WorkspaceError::from)?;
    verification::enable_recovery(&client).await.map_err(verr)
}

/// Handle `recovery.status`.
pub async fn recovery_status_for_session(
    session: &StoredSession,
) -> Result<RecoveryStatusInfo, WorkspaceError> {
    let client = restore_client(session).await?;
    client
        .sync_once(matrix_sdk::config::SyncSettings::default())
        .await
        .map_err(WorkspaceError::from)?;
    Ok(verification::recovery_status(&client).await)
}

/// Handle `recovery.recover`: re-import keys from server-side backup using the
/// operator-supplied recovery key (used after a re-provision onto a fresh host
/// or a wiped crypto store).
pub async fn recover_for_session(
    session: &StoredSession,
    params: &RecoverParams,
) -> Result<RecoveryStatusInfo, WorkspaceError> {
    let client = restore_client(session).await?;
    client
        .sync_once(matrix_sdk::config::SyncSettings::default())
        .await
        .map_err(WorkspaceError::from)?;
    verification::recover(&client, params.recovery_key.expose())
        .await
        .map_err(verr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recover_params_round_trip() {
        let params = RecoverParams {
            recovery_key: Secret::new("EsTL test key"),
        };
        let json = serde_json::to_string(&params).unwrap();
        // `Secret` is `#[serde(transparent)]`, so the wire format is unchanged:
        // a JSON object with the bare key string.
        assert_eq!(json, r#"{"recovery_key":"EsTL test key"}"#);
        let parsed: RecoverParams = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, params);
        assert_eq!(parsed.recovery_key.expose(), "EsTL test key");
    }

    #[test]
    fn recover_params_debug_redacts_key() {
        // A stray `tracing::debug!(?params)` must not leak the recovery key:
        // the `Secret` wrapper renders `***redacted***` in `Debug`.
        let params = RecoverParams {
            recovery_key: Secret::new("EsTL super secret key"),
        };
        let debug = format!("{params:?}");
        assert!(
            debug.contains(crate::session::REDACTED),
            "debug must show the placeholder: {debug}"
        );
        assert!(
            !debug.contains("super secret key"),
            "debug leaked the recovery key: {debug}"
        );
    }
}
