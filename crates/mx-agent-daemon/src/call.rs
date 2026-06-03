//! Signed tool-call request/response flow (architecture §7, §13, §17).
//!
//! Named tool calls are the preferred security boundary over raw `exec`. A
//! caller builds a `com.mxagent.call.request.v1` timeline event, signs its
//! content with the daemon's Ed25519 key (see [`crate::signing`]), and sends it
//! into a workspace room. Matrix federates the event to the target agent's
//! daemon, which receives it through `/sync`.
//!
//! Before acting on a request, the receiving daemon runs the verification
//! pipeline in [`authorize_call_request`]:
//!
//! 1. **Signature** — the content must carry a valid detached signature over
//!    its [canonical JSON][mx_agent_protocol::canonical_json] (the `signature`
//!    field excluded). Missing signatures are [`CallRejection::Unsigned`];
//!    invalid ones are [`CallRejection::InvalidSignature`].
//! 2. **Trust** — the signing key must be present and trusted in the daemon's
//!    local [`TrustStore`]. Unknown or revoked keys are
//!    [`CallRejection::UntrustedKey`].
//! 3. **Policy** — the requested tool must be permitted for the requesting
//!    agent in the request's room by the local [`Policy`]. Denials are
//!    [`CallRejection::PolicyDenied`].
//!
//! Only when all three checks pass is the request authorized. The daemon then
//! emits a `com.mxagent.call.response.v1` carrying the result (on success) or a
//! machine-readable error (on rejection or failure).

use ed25519_dalek::{SigningKey, VerifyingKey};
use matrix_sdk::Room;
use serde_json::Value;

use mx_agent_policy::{CallContext, DenyReason, Policy};
use mx_agent_protocol::events::timeline::{CALL_REQUEST, CALL_RESPONSE};
use mx_agent_protocol::schema::{CallRequest, CallResponse, Signature};
use mx_agent_protocol::signing::{self, SignatureError, SIGNATURE_FIELD};

use crate::trust::TrustStore;
use crate::workspace::WorkspaceError;

/// Why an incoming `com.mxagent.call.request.v1` was rejected.
///
/// Every variant maps to a stable, machine-readable reason string via
/// [`CallRejection::reason`], which is what the emitted
/// `com.mxagent.call.response.v1` carries in its `error` field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallRejection {
    /// The request content was not a JSON object, so it cannot be verified.
    Malformed,
    /// The request carried no `signature` field.
    Unsigned,
    /// The signature was present but did not verify against the signing key.
    InvalidSignature,
    /// The signing key is unknown to or revoked in the local trust store.
    UntrustedKey {
        /// The signing key identifier that was rejected.
        key_id: String,
    },
    /// The local policy denied the requested tool for this room/agent.
    PolicyDenied(DenyReason),
}

impl CallRejection {
    /// A stable, machine-readable reason string for use in a [`CallResponse`].
    pub fn reason(&self) -> String {
        match self {
            Self::Malformed => "malformed_request".to_string(),
            Self::Unsigned => "unsigned".to_string(),
            Self::InvalidSignature => "invalid_signature".to_string(),
            Self::UntrustedKey { .. } => "untrusted_key".to_string(),
            Self::PolicyDenied(_) => "policy_denied".to_string(),
        }
    }
}

impl std::fmt::Display for CallRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed => write!(f, "call request content is not a JSON object"),
            Self::Unsigned => write!(f, "call request is unsigned"),
            Self::InvalidSignature => write!(f, "call request signature is invalid"),
            Self::UntrustedKey { key_id } => {
                write!(f, "signing key {key_id:?} is not trusted")
            }
            Self::PolicyDenied(reason) => write!(f, "policy denied call: {reason}"),
        }
    }
}

impl std::error::Error for CallRejection {}

/// Read the detached [`Signature`] embedded in `content`, if present and
/// well-formed. Returns `None` when there is no `signature` field at all
/// (an unsigned request) and an error when the field is malformed.
fn read_signature(content: &Value) -> Result<Option<Signature>, CallRejection> {
    let obj = content.as_object().ok_or(CallRejection::Malformed)?;
    match obj.get(SIGNATURE_FIELD) {
        None => Ok(None),
        Some(Value::Null) => Ok(None),
        Some(value) => serde_json::from_value::<Signature>(value.clone())
            .map(Some)
            .map_err(|_| CallRejection::InvalidSignature),
    }
}

/// Build and sign a `com.mxagent.call.request.v1` content value.
///
/// Constructs a [`CallRequest`] for `tool` with `args`, then signs the content
/// with `signing_key`, embedding the detached signature under the `signature`
/// field. The returned JSON value is ready to be sent as the timeline event's
/// content.
pub fn build_signed_call_request(
    signing_key: &SigningKey,
    key_id: impl Into<String>,
    invocation_id: impl Into<String>,
    request_id: impl Into<String>,
    tool: impl Into<String>,
    args: Value,
) -> Result<Value, SignatureError> {
    // Build the unsigned content with a placeholder signature, then sign it in
    // place. `sign_into` excludes the `signature` field from the signed bytes,
    // so the placeholder does not affect the result.
    let request = CallRequest {
        invocation_id: invocation_id.into(),
        request_id: request_id.into(),
        tool: tool.into(),
        args,
        signature: Signature {
            alg: signing::ALG_ED25519.to_string(),
            key_id: key_id.into(),
            sig: String::new(),
        },
        extra: Default::default(),
    };
    let mut content =
        serde_json::to_value(&request).expect("CallRequest serializes to a JSON object");
    let key_id = request.signature.key_id;
    signing::sign_into(signing_key, key_id, &mut content)?;
    Ok(content)
}

/// Send a signed `com.mxagent.call.request.v1` timeline event into `room`.
///
/// Builds and signs the request with [`build_signed_call_request`], then sends
/// it as a Matrix timeline event. Returns the parsed [`CallRequest`] that was
/// sent (including its embedded signature).
pub async fn send_call_request(
    room: &Room,
    signing_key: &SigningKey,
    key_id: impl Into<String>,
    invocation_id: impl Into<String>,
    request_id: impl Into<String>,
    tool: impl Into<String>,
    args: Value,
) -> Result<CallRequest, WorkspaceError> {
    // Signing only fails when the content is not a JSON object; the content we
    // build here is always an object, so this cannot fail in practice.
    let content =
        build_signed_call_request(signing_key, key_id, invocation_id, request_id, tool, args)
            .expect("CallRequest content is always a JSON object");
    room.send_raw(CALL_REQUEST, content.clone())
        .await
        .map_err(WorkspaceError::from)?;
    serde_json::from_value::<CallRequest>(content)
        .map_err(|e| WorkspaceError::from(matrix_sdk::Error::SerdeJson(e)))
}

/// Verify and authorize an incoming `com.mxagent.call.request.v1`.
///
/// Runs the full receive-side pipeline (architecture §13.1): signature, then
/// trust, then policy. On success the parsed [`CallRequest`] is returned; on
/// failure the first failing check is reported as a [`CallRejection`].
///
/// `verifying_key` is the public key the caller has resolved for the request's
/// signing key (for example from the requesting agent's published key); the
/// trust check confirms that key id is locally trusted, and the policy check
/// confirms the tool is permitted for `requesting_agent` in `room_id`.
pub fn authorize_call_request(
    content: &Value,
    verifying_key: &VerifyingKey,
    trust: &TrustStore,
    policy: &Policy,
    room_id: &str,
    requesting_agent: &str,
) -> Result<CallRequest, CallRejection> {
    // 1. Signature must be present and valid.
    let signature = read_signature(content)?.ok_or(CallRejection::Unsigned)?;
    signing::verify(verifying_key, content).map_err(|e| match e {
        SignatureError::MissingSignature => CallRejection::Unsigned,
        SignatureError::NotAnObject => CallRejection::Malformed,
        _ => CallRejection::InvalidSignature,
    })?;

    let request: CallRequest =
        serde_json::from_value(content.clone()).map_err(|_| CallRejection::Malformed)?;

    // 2. The signing key must be locally trusted.
    if !trust.is_key_trusted(&signature.key_id) {
        return Err(CallRejection::UntrustedKey {
            key_id: signature.key_id,
        });
    }

    // 3. The local policy must permit the tool for this room/agent.
    let outcome = policy.evaluate_call(&CallContext {
        room_id,
        requesting_agent,
        tool: &request.tool,
    });
    if let Some(reason) = outcome.deny_reason() {
        return Err(CallRejection::PolicyDenied(reason));
    }

    Ok(request)
}

/// Build a successful [`CallResponse`] carrying `result` for `request_id`.
pub fn success_response(request_id: impl Into<String>, result: Value) -> CallResponse {
    CallResponse {
        request_id: request_id.into(),
        ok: true,
        result: Some(result),
        error: None,
        extra: Default::default(),
    }
}

/// Build a failed [`CallResponse`] for `request_id` from a [`CallRejection`].
pub fn rejection_response(
    request_id: impl Into<String>,
    rejection: &CallRejection,
) -> CallResponse {
    CallResponse {
        request_id: request_id.into(),
        ok: false,
        result: None,
        error: Some(rejection.reason()),
        extra: Default::default(),
    }
}

/// Emit a `com.mxagent.call.response.v1` timeline event into `room`.
pub async fn emit_call_response(
    room: &Room,
    response: &CallResponse,
) -> Result<(), WorkspaceError> {
    let content = serde_json::to_value(response)
        .map_err(|e| WorkspaceError::from(matrix_sdk::Error::SerdeJson(e)))?;
    room.send_raw(CALL_RESPONSE, content)
        .await
        .map_err(WorkspaceError::from)?;
    Ok(())
}

// `Outcome` does not expose its deny reason directly; provide a small helper.
trait OutcomeExt {
    fn deny_reason(&self) -> Option<DenyReason>;
}

impl OutcomeExt for mx_agent_policy::Outcome {
    fn deny_reason(&self) -> Option<DenyReason> {
        match self {
            mx_agent_policy::Outcome::Allow(_) => None,
            mx_agent_policy::Outcome::Deny(reason) => Some(reason.clone()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use serde_json::json;

    /// Deterministic signing key from a fixed seed (matches the test vector key
    /// used in `mx_agent_protocol::signing`).
    fn test_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn key_id_for(key: &SigningKey) -> String {
        use base64::Engine as _;
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(key.verifying_key().as_bytes());
        let b64 = base64::engine::general_purpose::STANDARD_NO_PAD.encode(digest);
        format!("{}:{b64}", crate::signing::KEY_ID_PREFIX)
    }

    const ROOM: &str = "!abc:matrix.org";
    const AGENT: &str = "@claude:matrix.org";

    fn policy() -> Policy {
        let toml = r#"
[rooms."!abc:matrix.org"]
trusted = true

[rooms."!abc:matrix.org".agents."@claude:matrix.org"]
allow_tools = ["run_tests", "lint"]
"#;
        Policy::parse(toml).expect("policy parses")
    }

    fn trust_with(key_id: &str) -> TrustStore {
        let mut store = TrustStore::default();
        store.approve(AGENT, key_id, None, None, None);
        store
    }

    fn signed_request(key: &SigningKey, tool: &str) -> Value {
        build_signed_call_request(
            key,
            key_id_for(key),
            "inv_01HZ",
            "req_01HZ",
            tool,
            json!({ "package": "api" }),
        )
        .expect("signs")
    }

    #[test]
    fn round_trip_signed_request_authorizes() {
        // The "remote call succeeds" path: a request signed by a trusted key for
        // an allowlisted tool passes the full pipeline.
        let key = test_key();
        let content = signed_request(&key, "run_tests");
        let trust = trust_with(&key_id_for(&key));
        let request = authorize_call_request(
            &content,
            &key.verifying_key(),
            &trust,
            &policy(),
            ROOM,
            AGENT,
        )
        .expect("authorized");
        assert_eq!(request.tool, "run_tests");
        assert_eq!(request.request_id, "req_01HZ");
        assert_eq!(request.args, json!({ "package": "api" }));
    }

    #[test]
    fn unsigned_request_is_rejected() {
        // A request with no signature field at all.
        let key = test_key();
        let mut content = signed_request(&key, "run_tests");
        content
            .as_object_mut()
            .unwrap()
            .remove(SIGNATURE_FIELD)
            .unwrap();
        let trust = trust_with(&key_id_for(&key));
        let err = authorize_call_request(
            &content,
            &key.verifying_key(),
            &trust,
            &policy(),
            ROOM,
            AGENT,
        )
        .unwrap_err();
        assert_eq!(err, CallRejection::Unsigned);
        assert_eq!(err.reason(), "unsigned");
    }

    #[test]
    fn null_signature_is_treated_as_unsigned() {
        let key = test_key();
        let mut content = signed_request(&key, "run_tests");
        content.as_object_mut().unwrap()[SIGNATURE_FIELD] = Value::Null;
        let trust = trust_with(&key_id_for(&key));
        let err = authorize_call_request(
            &content,
            &key.verifying_key(),
            &trust,
            &policy(),
            ROOM,
            AGENT,
        )
        .unwrap_err();
        assert_eq!(err, CallRejection::Unsigned);
    }

    #[test]
    fn tampered_payload_fails_signature_check() {
        let key = test_key();
        let mut content = signed_request(&key, "run_tests");
        // Tamper with a signed field after signing.
        content["args"]["package"] = json!("prod");
        let trust = trust_with(&key_id_for(&key));
        let err = authorize_call_request(
            &content,
            &key.verifying_key(),
            &trust,
            &policy(),
            ROOM,
            AGENT,
        )
        .unwrap_err();
        assert_eq!(err, CallRejection::InvalidSignature);
    }

    #[test]
    fn wrong_verifying_key_fails_signature_check() {
        let key = test_key();
        let content = signed_request(&key, "run_tests");
        let other = SigningKey::from_bytes(&[9u8; 32]);
        // Trust the *claimed* key id so the failure is attributable to the
        // signature, not the trust check.
        let trust = trust_with(&key_id_for(&key));
        let err = authorize_call_request(
            &content,
            &other.verifying_key(),
            &trust,
            &policy(),
            ROOM,
            AGENT,
        )
        .unwrap_err();
        assert_eq!(err, CallRejection::InvalidSignature);
    }

    #[test]
    fn untrusted_key_is_rejected() {
        // Validly signed, but the key is not in the trust store.
        let key = test_key();
        let content = signed_request(&key, "run_tests");
        let trust = TrustStore::default();
        let err = authorize_call_request(
            &content,
            &key.verifying_key(),
            &trust,
            &policy(),
            ROOM,
            AGENT,
        )
        .unwrap_err();
        assert_eq!(
            err,
            CallRejection::UntrustedKey {
                key_id: key_id_for(&key)
            }
        );
        assert_eq!(err.reason(), "untrusted_key");
    }

    #[test]
    fn revoked_key_is_rejected() {
        let key = test_key();
        let content = signed_request(&key, "run_tests");
        let mut trust = trust_with(&key_id_for(&key));
        trust.revoke(AGENT, &key_id_for(&key));
        let err = authorize_call_request(
            &content,
            &key.verifying_key(),
            &trust,
            &policy(),
            ROOM,
            AGENT,
        )
        .unwrap_err();
        assert!(matches!(err, CallRejection::UntrustedKey { .. }));
    }

    #[test]
    fn policy_denied_tool_is_rejected() {
        // Signed and trusted, but the tool is not allowlisted.
        let key = test_key();
        let content = signed_request(&key, "deploy");
        let trust = trust_with(&key_id_for(&key));
        let err = authorize_call_request(
            &content,
            &key.verifying_key(),
            &trust,
            &policy(),
            ROOM,
            AGENT,
        )
        .unwrap_err();
        assert!(matches!(err, CallRejection::PolicyDenied(_)));
        assert_eq!(err.reason(), "policy_denied");
    }

    #[test]
    fn pipeline_order_signature_before_trust() {
        // A tampered request from an untrusted key fails on the signature first,
        // so the rejection does not leak that the key was also untrusted.
        let key = test_key();
        let mut content = signed_request(&key, "run_tests");
        content["args"]["package"] = json!("prod");
        let trust = TrustStore::default();
        let err = authorize_call_request(
            &content,
            &key.verifying_key(),
            &trust,
            &policy(),
            ROOM,
            AGENT,
        )
        .unwrap_err();
        assert_eq!(err, CallRejection::InvalidSignature);
    }

    #[test]
    fn success_response_carries_result() {
        let response = success_response("req_01HZ", json!({ "exit_code": 0 }));
        assert!(response.ok);
        assert_eq!(response.request_id, "req_01HZ");
        assert_eq!(response.result, Some(json!({ "exit_code": 0 })));
        assert!(response.error.is_none());
    }

    #[test]
    fn rejection_response_carries_reason() {
        let response = rejection_response("req_01HZ", &CallRejection::Unsigned);
        assert!(!response.ok);
        assert_eq!(response.request_id, "req_01HZ");
        assert!(response.result.is_none());
        assert_eq!(response.error.as_deref(), Some("unsigned"));
    }

    #[test]
    fn malformed_content_is_rejected() {
        let key = test_key();
        let trust = trust_with(&key_id_for(&key));
        let content = json!([1, 2, 3]);
        let err = authorize_call_request(
            &content,
            &key.verifying_key(),
            &trust,
            &policy(),
            ROOM,
            AGENT,
        )
        .unwrap_err();
        assert_eq!(err, CallRejection::Malformed);
    }
}
