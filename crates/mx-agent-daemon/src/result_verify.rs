//! Caller-side verification of the signed **result plane** (issue #348).
//!
//! Result-plane events (`exec.accepted`/`exec.rejected`/`exec.finished`/
//! `exec.cancelled`, `stream.chunk`, `stream.artifact`, `call.response`) are
//! sender-pinned (issue #304) *and* Ed25519-signed by the executing daemon's
//! key (this module's send-side counterpart lives in [`crate::exec`] and
//! [`crate::call`]). On receipt the caller verifies the detached signature
//! against the executor's published, locally-trusted verifying key —
//! defense-in-depth *in series* with the sender-pin — and **fails closed** on
//! the Matrix transport.
//!
//! The verification policy is centralized in [`verify_result_signature`] so the
//! exec/stream verify locus ([`crate::sync::publish_forwarded`]) and the
//! `call.response` wait ([`crate::call::wait_for_call_response`]) apply the
//! exact same rule. A missing, invalid, wrong-key, untrusted, or
//! key-id-mismatched signature is **always** rejected; there is no environment
//! override (issue #381 retired the mixed-fleet `MX_AGENT_ALLOW_UNSIGNED_RESULTS`
//! rollout hatch) (Decision D5).

use ed25519_dalek::VerifyingKey;
use mx_agent_protocol::schema::AgentState;
use mx_agent_protocol::signing::{self, SignatureError};

use crate::call::verifying_key_from_agent_state;
use crate::trust::TrustStore;

/// Why a signed result-plane event was rejected on receipt.
///
/// Stable, non-sensitive reason labels for log lines; never carries key bytes
/// or payloads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResultVerifyError {
    /// The executor's `AgentState` could not be resolved, or its published key
    /// is missing/malformed/does not match its declared `signing_key_id`.
    UnresolvableKey,
    /// The event carried no signature; a missing signature is always rejected.
    Unsigned,
    /// The embedded `signature.key_id` did not match the executor's declared
    /// `AgentState.signing_key_id`.
    KeyIdMismatch,
    /// The signing key is not present and trusted in the local trust store.
    UntrustedKey,
    /// The signature did not verify (forged, tampered, or wrong key), or the
    /// content was not canonicalizable.
    Invalid,
}

impl ResultVerifyError {
    /// A stable, machine-readable reason label safe to log.
    pub fn reason(&self) -> &'static str {
        match self {
            Self::UnresolvableKey => "unresolvable_executor_key",
            Self::Unsigned => "unsigned",
            Self::KeyIdMismatch => "key_id_mismatch",
            Self::UntrustedKey => "untrusted_key",
            Self::Invalid => "invalid_signature",
        }
    }
}

/// Verify a signed result-plane `event` against the executor's `agent_state`,
/// applying the full fail-closed policy (Decision D5).
///
/// Steps, in series with the existing sender-pin (already applied by the
/// caller):
///
/// 1. Resolve the executor's [`VerifyingKey`] from its published `AgentState`
///    (which also asserts the key matches the declared `signing_key_id`).
/// 2. Verify the detached signature over the event's canonical JSON (the
///    `signature` field excluded).
/// 3. Cross-check the embedded `signature.key_id == agent_state.signing_key_id`.
/// 4. Re-check the signing key (by `key_id`) is locally trusted — the same
///    anchor the request plane uses — so a key revoked between request and
///    response drops the result.
///
/// A **missing** signature is always rejected with [`ResultVerifyError::Unsigned`];
/// every other failure (invalid, wrong key, untrusted, key-id mismatch) is
/// likewise always rejected. There is no environment override (issue #381 retired
/// the mixed-fleet `MX_AGENT_ALLOW_UNSIGNED_RESULTS` hatch). Never logs key bytes
/// or payloads.
pub fn verify_result_signature<T: serde::Serialize>(
    event: &T,
    agent_state: &AgentState,
    trust: &TrustStore,
) -> Result<(), ResultVerifyError> {
    // 1. Resolve the executor's published, key-id-matched verifying key.
    let verifying_key: VerifyingKey = verifying_key_from_agent_state(agent_state)
        .map_err(|_| ResultVerifyError::UnresolvableKey)?;

    // 2. Verify the detached signature. A missing signature is rejected as
    //    `Unsigned`; invalid / non-canonical signatures fail closed as `Invalid`.
    match signing::verify_signed(&verifying_key, event) {
        Ok(()) => {}
        Err(SignatureError::MissingSignature) => return Err(ResultVerifyError::Unsigned),
        Err(_) => return Err(ResultVerifyError::Invalid),
    }

    // 3. Cross-check the embedded key id matches the executor's declared key id.
    let key_id = match embedded_key_id(event) {
        Some(id) => id,
        // A valid signature implies a parseable `signature.key_id`; treat its
        // absence as malformed/forged and fail closed.
        None => return Err(ResultVerifyError::Invalid),
    };
    if key_id != agent_state.signing_key_id {
        return Err(ResultVerifyError::KeyIdMismatch);
    }

    // 4. Re-check the signing key is locally trusted now — keyed by `key_id`,
    //    the same anchor the request plane uses (`TrustStore::is_key_trusted`,
    //    exec.rs authorize path), NOT the `(agent_id, key_id)` pair: trust is
    //    approved per key (often recorded under the peer's *requesting* agent_id,
    //    not the executor's), and `key_id` is `SHA256(pubkey)` so trusting it
    //    already binds the exact public key. A key revoked between request and
    //    response is no longer trusted → the result is dropped (value-add over
    //    the sender-pin), and a hostile homeserver's substituted key is untrusted
    //    → rejected.
    if !trust.is_key_trusted(&key_id) {
        return Err(ResultVerifyError::UntrustedKey);
    }

    Ok(())
}

/// Extract the embedded `signature.key_id` from a serializable result event,
/// if present.
fn embedded_key_id<T: serde::Serialize>(event: &T) -> Option<String> {
    let value = serde_json::to_value(event).ok()?;
    value
        .get(signing::SIGNATURE_FIELD)?
        .get("key_id")?
        .as_str()
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing::{encode_verifying_key, key_id_for_verifying_key};
    use ed25519_dalek::SigningKey;
    use mx_agent_protocol::schema::{
        AgentLoad, AgentWorkspace, CallResponse, ExecFinished, ExecRejected,
    };
    use mx_agent_protocol::signing::sign_into;

    const AGENT: &str = "agent:executor";

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[42u8; 32])
    }

    fn agent_state(key: &SigningKey) -> AgentState {
        AgentState {
            agent_id: AGENT.to_string(),
            kind: "pi".to_string(),
            matrix_user_id: "@executor:server".to_string(),
            device_id: "DEV".to_string(),
            signing_key_id: key_id_for_verifying_key(&key.verifying_key()),
            signing_public_key: Some(encode_verifying_key(&key.verifying_key())),
            status: "active".to_string(),
            capabilities: Vec::new(),
            tools: Vec::new(),
            workspace: AgentWorkspace {
                cwd: "/repo".to_string(),
                project_id: String::new(),
                git_commit: String::new(),
            },
            load: AgentLoad {
                running_invocations: 0,
                max_invocations: 1,
            },
            last_seen_ts: 1,
            state_rev: 1,
            extra: Default::default(),
        }
    }

    fn trusted_store(key: &SigningKey) -> TrustStore {
        let mut store = TrustStore::default();
        store.approve(
            AGENT,
            key_id_for_verifying_key(&key.verifying_key()),
            None,
            None,
            None,
        );
        store
    }

    fn finished() -> ExecFinished {
        ExecFinished {
            invocation_id: "inv_1".to_string(),
            exit_code: Some(0),
            signal: None,
            duration_ms: 5,
            stdout_bytes: 0,
            stderr_bytes: 0,
            truncated: false,
            artifact_mxc: None,
            signature: None,
            extra: Default::default(),
        }
    }

    fn signed_finished(key: &SigningKey) -> ExecFinished {
        let mut v = serde_json::to_value(finished()).unwrap();
        sign_into(key, key_id_for_verifying_key(&key.verifying_key()), &mut v).unwrap();
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn verified_when_signed_keyid_matches_and_trusted() {
        let k = key();
        assert_eq!(
            verify_result_signature(&signed_finished(&k), &agent_state(&k), &trusted_store(&k)),
            Ok(())
        );
    }

    #[test]
    fn missing_signature_rejected_by_default() {
        let k = key();
        assert_eq!(
            verify_result_signature(&finished(), &agent_state(&k), &trusted_store(&k)),
            Err(ResultVerifyError::Unsigned)
        );
    }

    #[test]
    fn tampered_result_rejected() {
        let k = key();
        let mut ev = signed_finished(&k);
        ev.exit_code = Some(1); // attacker flips success -> failure
        assert_eq!(
            verify_result_signature(&ev, &agent_state(&k), &trusted_store(&k)),
            Err(ResultVerifyError::Invalid)
        );
    }

    #[test]
    fn signed_by_other_key_rejected() {
        let k = key();
        let other = SigningKey::from_bytes(&[7u8; 32]);
        // signed by `other`, but agent_state/trust are for `k`
        assert_eq!(
            verify_result_signature(
                &signed_finished(&other),
                &agent_state(&k),
                &trusted_store(&k)
            ),
            Err(ResultVerifyError::Invalid)
        );
    }

    #[test]
    fn untrusted_key_rejected() {
        let k = key();
        // valid signature + key-id match, but the key is not in the trust store
        assert_eq!(
            verify_result_signature(
                &signed_finished(&k),
                &agent_state(&k),
                &TrustStore::default()
            ),
            Err(ResultVerifyError::UntrustedKey)
        );
    }

    #[test]
    fn keyid_mismatch_rejected() {
        let k = key();
        // a signature that still verifies against k's key (the signature field is
        // excluded from the signed bytes) but advertises a different key_id.
        let mut v = serde_json::to_value(finished()).unwrap();
        sign_into(&k, key_id_for_verifying_key(&k.verifying_key()), &mut v).unwrap();
        v["signature"]["key_id"] = serde_json::json!("mxagent-ed25519:somethingelse");
        let ev: ExecFinished = serde_json::from_value(v).unwrap();
        assert_eq!(
            verify_result_signature(&ev, &agent_state(&k), &trusted_store(&k)),
            Err(ResultVerifyError::KeyIdMismatch)
        );
    }

    // --- issue #381 regression tests: MX_AGENT_ALLOW_UNSIGNED_RESULTS hatch retired ---

    #[test]
    fn env_override_retired_missing_signature_always_rejected() {
        // issue #381: ALLOW_UNSIGNED_RESULTS_ENV, allow_unsigned_results(), and
        // VerifyOutcome::AcceptedUnsigned are removed. Even if the (now-retired)
        // env var is present in the process environment, verify_result_signature
        // never reads it — a missing signature is always rejected (fail-closed).
        std::env::set_var("MX_AGENT_ALLOW_UNSIGNED_RESULTS", "1");
        let k = key();
        let result = verify_result_signature(&finished(), &agent_state(&k), &trusted_store(&k));
        std::env::remove_var("MX_AGENT_ALLOW_UNSIGNED_RESULTS");
        assert_eq!(result, Err(ResultVerifyError::Unsigned));
    }

    #[test]
    fn error_reason_labels_are_stable() {
        // These strings appear in tracing::warn! log lines and are used as
        // machine-readable reason keys; pin them against accidental rename.
        assert_eq!(
            ResultVerifyError::UnresolvableKey.reason(),
            "unresolvable_executor_key"
        );
        assert_eq!(ResultVerifyError::Unsigned.reason(), "unsigned");
        assert_eq!(ResultVerifyError::KeyIdMismatch.reason(), "key_id_mismatch");
        assert_eq!(ResultVerifyError::UntrustedKey.reason(), "untrusted_key");
        assert_eq!(ResultVerifyError::Invalid.reason(), "invalid_signature");
    }

    #[test]
    fn unresolvable_key_when_signing_public_key_absent() {
        // When the executor's AgentState has no signing_public_key the key
        // cannot be resolved and the event must be rejected.
        let k = key();
        let mut state = agent_state(&k);
        state.signing_public_key = None;
        assert_eq!(
            verify_result_signature(&signed_finished(&k), &state, &trusted_store(&k)),
            Err(ResultVerifyError::UnresolvableKey)
        );
    }

    #[test]
    fn missing_signature_rejected_for_exec_rejected() {
        // The fail-closed policy applies to every result-plane event type, not
        // only ExecFinished. ExecRejected is one of the other covered types.
        let k = key();
        let ev = ExecRejected {
            invocation_id: "inv_rej".to_string(),
            reason: "policy".to_string(),
            signature: None,
            extra: Default::default(),
        };
        assert_eq!(
            verify_result_signature(&ev, &agent_state(&k), &trusted_store(&k)),
            Err(ResultVerifyError::Unsigned)
        );
    }

    #[test]
    fn missing_signature_rejected_for_call_response() {
        // CallResponse is the result-plane type consumed by call.rs; its
        // downgrade warn-and-accept branch was also removed by issue #381.
        let k = key();
        let response = CallResponse {
            request_id: "req_1".to_string(),
            ok: true,
            result: None,
            error: None,
            signature: None,
            extra: Default::default(),
        };
        assert_eq!(
            verify_result_signature(&response, &agent_state(&k), &trusted_store(&k)),
            Err(ResultVerifyError::Unsigned)
        );
    }
}
