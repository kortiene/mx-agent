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
//! exact same rule. The single removable escape hatch
//! ([`MX_AGENT_ALLOW_UNSIGNED_RESULTS`](ALLOW_UNSIGNED_RESULTS_ENV)) downgrades
//! **only** a *missing* signature to a logged-accept (for mixed-fleet rollout);
//! invalid / wrong-key / untrusted signatures are always rejected (Decision
//! D5).

use ed25519_dalek::VerifyingKey;
use mx_agent_protocol::schema::AgentState;
use mx_agent_protocol::signing::{self, SignatureError};

use crate::call::verifying_key_from_agent_state;
use crate::trust::TrustStore;

/// Environment override that downgrades a *missing* result-plane signature to a
/// logged-accept (default off). Mirrors the `MX_AGENT_REQUIRE_BWRAP`
/// explicit-gate convention. Removable at the first stable release; it never
/// accepts an *invalid* signature.
pub const ALLOW_UNSIGNED_RESULTS_ENV: &str = "MX_AGENT_ALLOW_UNSIGNED_RESULTS";

/// Why a signed result-plane event was rejected on receipt.
///
/// Stable, non-sensitive reason labels for log lines; never carries key bytes
/// or payloads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResultVerifyError {
    /// The executor's `AgentState` could not be resolved, or its published key
    /// is missing/malformed/does not match its declared `signing_key_id`.
    UnresolvableKey,
    /// The event carried no signature and the unsigned-results override is off.
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

/// Whether the unsigned-results escape hatch is enabled this run.
fn allow_unsigned_results() -> bool {
    std::env::var(ALLOW_UNSIGNED_RESULTS_ENV)
        .map(|v| v == "1")
        .unwrap_or(false)
}

/// Outcome of a successful result-plane verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyOutcome {
    /// The signature was present, valid, key-id-matched, and trusted.
    Verified,
    /// The signature was *missing* but accepted because the
    /// [`ALLOW_UNSIGNED_RESULTS_ENV`] override is set. The caller should log a
    /// one-per-event warning that an unsigned result was accepted.
    AcceptedUnsigned,
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
/// 4. Re-check the `(agent_id, key_id)` pair is locally trusted, so a key
///    revoked between request and response drops the result.
///
/// On a **missing** signature the [`ALLOW_UNSIGNED_RESULTS_ENV`] override
/// downgrades the result to `Ok(`[`VerifyOutcome::AcceptedUnsigned`]`)` (which
/// the caller logs); every other failure (invalid, wrong key, untrusted, key-id
/// mismatch) is **always** rejected regardless of the override. Never logs key
/// bytes or payloads.
pub fn verify_result_signature<T: serde::Serialize>(
    event: &T,
    agent_state: &AgentState,
    trust: &TrustStore,
) -> Result<VerifyOutcome, ResultVerifyError> {
    verify_result_signature_with_policy(event, agent_state, trust, allow_unsigned_results())
}

/// The result-plane verification policy with the unsigned-results allowance
/// supplied explicitly, so it is deterministically unit-testable.
/// [`verify_result_signature`] wraps this with the value read from the
/// [`ALLOW_UNSIGNED_RESULTS_ENV`] environment override.
fn verify_result_signature_with_policy<T: serde::Serialize>(
    event: &T,
    agent_state: &AgentState,
    trust: &TrustStore,
    allow_unsigned: bool,
) -> Result<VerifyOutcome, ResultVerifyError> {
    // 1. Resolve the executor's published, key-id-matched verifying key.
    let verifying_key: VerifyingKey = verifying_key_from_agent_state(agent_state)
        .map_err(|_| ResultVerifyError::UnresolvableKey)?;

    // 2. Verify the detached signature. A missing signature is the only case the
    //    escape hatch may downgrade; invalid / non-canonical fail closed always.
    match signing::verify_signed(&verifying_key, event) {
        Ok(()) => {}
        Err(SignatureError::MissingSignature) => {
            if allow_unsigned {
                return Ok(VerifyOutcome::AcceptedUnsigned);
            }
            return Err(ResultVerifyError::Unsigned);
        }
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

    // 4. Re-check the (agent, key) pair is locally trusted now (revocation
    //    between request and response drops the result — value-add over the
    //    sender-pin).
    if !trust.is_trusted(&agent_state.agent_id, &key_id) {
        return Err(ResultVerifyError::UntrustedKey);
    }

    Ok(VerifyOutcome::Verified)
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
    use mx_agent_protocol::schema::{AgentLoad, AgentWorkspace, ExecFinished};
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
            verify_result_signature_with_policy(
                &signed_finished(&k),
                &agent_state(&k),
                &trusted_store(&k),
                false
            ),
            Ok(VerifyOutcome::Verified)
        );
    }

    #[test]
    fn missing_signature_rejected_by_default() {
        let k = key();
        assert_eq!(
            verify_result_signature_with_policy(
                &finished(),
                &agent_state(&k),
                &trusted_store(&k),
                false
            ),
            Err(ResultVerifyError::Unsigned)
        );
    }

    #[test]
    fn missing_signature_downgraded_only_when_override_on() {
        let k = key();
        assert_eq!(
            verify_result_signature_with_policy(
                &finished(),
                &agent_state(&k),
                &trusted_store(&k),
                true
            ),
            Ok(VerifyOutcome::AcceptedUnsigned)
        );
    }

    #[test]
    fn tampered_result_rejected_even_with_override() {
        let k = key();
        let mut ev = signed_finished(&k);
        ev.exit_code = Some(1); // attacker flips success -> failure
                                // the override never downgrades an *invalid* signature
        assert_eq!(
            verify_result_signature_with_policy(&ev, &agent_state(&k), &trusted_store(&k), true),
            Err(ResultVerifyError::Invalid)
        );
    }

    #[test]
    fn signed_by_other_key_rejected() {
        let k = key();
        let other = SigningKey::from_bytes(&[7u8; 32]);
        // signed by `other`, but agent_state/trust are for `k`
        assert_eq!(
            verify_result_signature_with_policy(
                &signed_finished(&other),
                &agent_state(&k),
                &trusted_store(&k),
                false
            ),
            Err(ResultVerifyError::Invalid)
        );
    }

    #[test]
    fn untrusted_key_rejected() {
        let k = key();
        // valid signature + key-id match, but the key is not in the trust store
        assert_eq!(
            verify_result_signature_with_policy(
                &signed_finished(&k),
                &agent_state(&k),
                &TrustStore::default(),
                false
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
            verify_result_signature_with_policy(&ev, &agent_state(&k), &trusted_store(&k), false),
            Err(ResultVerifyError::KeyIdMismatch)
        );
    }
}
