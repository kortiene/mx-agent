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

use std::time::Duration;

use ed25519_dalek::{SigningKey, VerifyingKey};
use matrix_sdk::config::SyncSettings;
use matrix_sdk::Room;
use serde_json::Value;

use mx_agent_policy::{CallContext, DenyReason, Policy};
use mx_agent_protocol::events::timeline::{CALL_REQUEST, CALL_RESPONSE};
use mx_agent_protocol::schema::{AgentState, CallRequest, CallResponse, Signature};
use mx_agent_protocol::signing::{self, SignatureError, SIGNATURE_FIELD};

use crate::call_ipc::{CallErrorKind, CallOutcome, CallStartParams, CallStartResult};
use crate::session::{load_session, SessionPaths};
use crate::signing::{decode_verifying_key, key_id_for_verifying_key, load_or_create_signing_key};
use crate::trust::TrustStore;
use crate::workspace::{parse_room_or_alias, resolve_room_id, WorkspaceError};

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

/// Default validity window for a freshly built call request, matching the
/// `exec.request` 5-minute window. The request's `expires_at` is stamped this
/// far ahead of `created_at`; the target rejects it after that.
pub const CALL_REQUEST_TTL: Duration = Duration::from_secs(300);

/// Build and sign a `com.mxagent.call.request.v1` content value.
///
/// Constructs a [`CallRequest`] for `tool` with `args`, then signs the content
/// with `signing_key`, embedding the detached signature under the `signature`
/// field. The returned JSON value is ready to be sent as the timeline event's
/// content.
///
/// A fresh `nonce` and the `created_at`/`expires_at` timestamps (the latter
/// [`CALL_REQUEST_TTL`] ahead of now) are stamped automatically and covered by
/// the signature, so the target can replay/expiry-check the request just like an
/// `exec.request`.
pub fn build_signed_call_request(
    signing_key: &SigningKey,
    key_id: impl Into<String>,
    invocation_id: impl Into<String>,
    request_id: impl Into<String>,
    tool: impl Into<String>,
    args: Value,
) -> Result<Value, SignatureError> {
    let nonce = mx_agent_protocol::id::generate_request_id();
    let created_at = crate::exec_ipc::rfc3339_after(Duration::ZERO);
    let expires_at = crate::exec_ipc::rfc3339_after(CALL_REQUEST_TTL);
    build_signed_call_request_for_target(
        signing_key,
        key_id,
        invocation_id,
        request_id,
        nonce,
        created_at,
        expires_at,
        tool,
        args,
        CallTargeting::default(),
    )
}

/// Optional live Matrix routing metadata included in signed call requests.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CallTargeting {
    /// Agent identifier that issued the request.
    pub requesting_agent: Option<String>,
    /// Agent identifier expected to execute the request.
    pub target_agent: Option<String>,
}

/// Build and sign a targeted live Matrix call request.
///
/// `nonce`, `created_at`, and `expires_at` are taken explicitly (mirroring
/// [`crate::build_signed_exec_request`]) so callers control replay/expiry timing;
/// they are part of the signed canonical content.
#[allow(clippy::too_many_arguments)]
pub fn build_signed_call_request_for_target(
    signing_key: &SigningKey,
    key_id: impl Into<String>,
    invocation_id: impl Into<String>,
    request_id: impl Into<String>,
    nonce: impl Into<String>,
    created_at: impl Into<String>,
    expires_at: impl Into<String>,
    tool: impl Into<String>,
    args: Value,
    targeting: CallTargeting,
) -> Result<Value, SignatureError> {
    // Build the unsigned content with a placeholder signature, then sign it in
    // place. `sign_into` excludes the `signature` field from the signed bytes,
    // so the placeholder does not affect the result.
    let request = CallRequest {
        invocation_id: invocation_id.into(),
        request_id: request_id.into(),
        tool: tool.into(),
        args,
        created_at: created_at.into(),
        expires_at: expires_at.into(),
        nonce: nonce.into(),
        signature: Signature {
            alg: signing::ALG_ED25519.to_string(),
            key_id: key_id.into(),
            sig: String::new(),
        },
        requesting_agent: targeting.requesting_agent,
        target_agent: targeting.target_agent,
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

/// Execute an authorized [`CallRequest`] and build its [`CallResponse`].
///
/// This is the receive-side bridge from the verification pipeline
/// ([`authorize_call_request`]) to the built-in tool runner
/// ([`crate::tool_exec::execute_tool`]). A tool that runs and reports a nonzero
/// exit code still produces a successful (`ok: true`) response carrying its
/// structured result; only a failure to *invoke* the tool yields `ok: false`.
pub fn execute_authorized_call(request: &CallRequest) -> CallResponse {
    match crate::tool_exec::execute_tool(&request.tool, &request.args) {
        Ok(result) => success_response(request.request_id.clone(), result.to_value()),
        Err(err) => CallResponse {
            request_id: request.request_id.clone(),
            ok: false,
            result: None,
            error: Some(err.to_string()),
            extra: Default::default(),
        },
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

/// Resolve a Matrix-published agent signing public key and verify it matches
/// the agent state's key id.
pub fn verifying_key_from_agent_state(agent: &AgentState) -> Result<VerifyingKey, CallRejection> {
    let Some(public_key) = agent.signing_public_key.as_deref() else {
        return Err(CallRejection::UntrustedKey {
            key_id: agent.signing_key_id.clone(),
        });
    };
    let key = decode_verifying_key(public_key).map_err(|_| CallRejection::InvalidSignature)?;
    if key_id_for_verifying_key(&key) != agent.signing_key_id {
        return Err(CallRejection::InvalidSignature);
    }
    Ok(key)
}

fn policy_for_live_call() -> Policy {
    Policy::default_path()
        .and_then(|path| Policy::load(path).ok())
        .unwrap_or_default()
}

fn response_to_outcome(response: CallResponse) -> CallOutcome {
    if response.ok {
        let result = response.result.unwrap_or(Value::Null);
        let exit_code = result
            .get("exit_code")
            .and_then(|v| v.as_i64())
            .and_then(|n| i32::try_from(n).ok())
            .unwrap_or(0);
        let summary = result
            .get("summary")
            .and_then(|v| v.as_str())
            .unwrap_or("remote call completed")
            .to_string();
        CallOutcome::Ok { exit_code, summary }
    } else {
        CallOutcome::Error {
            kind: CallErrorKind::Remote,
            message: response
                .error
                .unwrap_or_else(|| "remote call failed".to_string()),
        }
    }
}

/// Start a live Matrix-backed call and wait for the matching response.
pub async fn start_call_matrix(params: &CallStartParams) -> CallStartResult {
    use mx_agent_protocol::id::{generate_invocation_id, generate_request_id};

    let invocation_id = params
        .invocation_id
        .clone()
        .unwrap_or_else(generate_invocation_id);
    let request_id = generate_request_id();
    let Some(room_target) = params.room.as_deref() else {
        return crate::start_call_loopback(params);
    };
    let Some(target_agent) = params.agent.clone() else {
        return crate::start_call_loopback(params);
    };

    let outcome = match start_call_matrix_inner(
        params,
        &invocation_id,
        &request_id,
        room_target,
        target_agent,
    )
    .await
    {
        Ok(response) => response_to_outcome(response),
        Err(message) => CallOutcome::Error {
            kind: CallErrorKind::Remote,
            message,
        },
    };

    CallStartResult {
        invocation_id,
        request_id,
        outcome,
    }
}

async fn start_call_matrix_inner(
    params: &CallStartParams,
    invocation_id: &str,
    request_id: &str,
    room_target: &str,
    target_agent: String,
) -> Result<CallResponse, String> {
    let paths = SessionPaths::resolve();
    let session = load_session(&paths)
        .map_err(|e| format!("could not read daemon session: {e}"))?
        .ok_or_else(|| "not logged in; run `mx-agent auth login` first".to_string())?;
    let client = crate::matrix::restore_client(&session)
        .await
        .map_err(|e| e.to_string())?;
    client
        .sync_once(SyncSettings::default())
        .await
        .map_err(|e| e.to_string())?;
    let id = parse_room_or_alias(room_target).map_err(|e| e.to_string())?;
    let room_id = resolve_room_id(&client, &id)
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
        .ok_or_else(|| "local agent is not registered in the target room".to_string())?;

    let signing = load_or_create_signing_key(&paths).map_err(|e| e.to_string())?;
    let nonce = mx_agent_protocol::id::generate_request_id();
    let created_at = crate::exec_ipc::rfc3339_after(Duration::ZERO);
    let expires_at = crate::exec_ipc::rfc3339_after(CALL_REQUEST_TTL);
    let content = build_signed_call_request_for_target(
        signing.signing_key(),
        signing.key_id(),
        invocation_id,
        request_id,
        nonce,
        created_at,
        expires_at,
        params.tool.clone(),
        params.input.clone(),
        CallTargeting {
            requesting_agent: Some(requester.agent_id),
            target_agent: Some(target_agent),
        },
    )
    .map_err(|e| e.to_string())?;
    room.send_raw(CALL_REQUEST, content)
        .await
        .map_err(|e| e.to_string())?;

    wait_for_call_response(&client, request_id, Duration::from_secs(60)).await
}

async fn wait_for_call_response(
    client: &matrix_sdk::Client,
    request_id: &str,
    timeout: Duration,
) -> Result<CallResponse, String> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err("timed out waiting for call response".to_string());
        }
        let settings = SyncSettings::default().timeout(remaining.min(Duration::from_secs(5)));
        let response = client
            .sync_once(settings)
            .await
            .map_err(|e| e.to_string())?;
        for event in crate::event_router::events_from_sync_response(&response) {
            if event.event_type == CALL_RESPONSE {
                if let Ok(response) = serde_json::from_value::<CallResponse>(event.content) {
                    if response.request_id == request_id {
                        return Ok(response);
                    }
                }
            }
        }
    }
}

/// Handle a routed live call request on the target daemon.
pub async fn handle_live_call_request(
    client: &matrix_sdk::Client,
    paths: &SessionPaths,
    meta: &crate::event_router::EventMeta,
    request: &CallRequest,
) {
    let Some(target_agent) = request.target_agent.as_deref() else {
        tracing::debug!(room = %meta.room_id, sender = %meta.sender, "ignoring untargeted call request");
        return;
    };
    let Some(requesting_agent) = request.requesting_agent.as_deref() else {
        tracing::warn!(room = %meta.room_id, sender = %meta.sender, "rejecting call request without requesting_agent");
        return;
    };

    let room_id = match matrix_sdk::ruma::RoomId::parse(&meta.room_id) {
        Ok(id) => id,
        Err(e) => {
            tracing::warn!(error = %e, room = %meta.room_id, "invalid room id in routed call request");
            return;
        }
    };
    let Some(room) = client.get_room(&room_id) else {
        tracing::warn!(room = %meta.room_id, "room for routed call request is unavailable");
        return;
    };

    let local_user = client.user_id().map(|u| u.to_string()).unwrap_or_default();
    let is_local_target = match crate::agent::read_agent_state(&room, target_agent).await {
        Ok(Some(agent)) => agent.matrix_user_id == local_user,
        Ok(None) => false,
        Err(e) => {
            tracing::warn!(error = %e, target_agent, "could not read target agent state");
            false
        }
    };
    if !is_local_target {
        return;
    }

    let content = match serde_json::to_value(request) {
        Ok(value) => value,
        Err(e) => {
            tracing::warn!(error = %e, "could not reserialize call request");
            return;
        }
    };

    let response = match authorize_live_call(
        &room,
        paths,
        &content,
        request,
        requesting_agent,
        &meta.room_id,
    )
    .await
    {
        Ok(authorized) => execute_authorized_call(&authorized),
        Err(rejection) => rejection_response(request.request_id.clone(), &rejection),
    };

    if let Err(e) = emit_call_response(&room, &response).await {
        tracing::warn!(error = %e, request_id = %request.request_id, "failed to emit call response");
    }
}

async fn authorize_live_call(
    room: &Room,
    paths: &SessionPaths,
    content: &Value,
    request: &CallRequest,
    requesting_agent: &str,
    room_id: &str,
) -> Result<CallRequest, CallRejection> {
    let requester = crate::agent::read_agent_state(room, requesting_agent)
        .await
        .map_err(|_| CallRejection::Malformed)?
        .ok_or_else(|| CallRejection::UntrustedKey {
            key_id: request.signature.key_id.clone(),
        })?;
    if requester.signing_key_id != request.signature.key_id {
        return Err(CallRejection::InvalidSignature);
    }
    let verifying_key = verifying_key_from_agent_state(&requester)?;
    let trust = TrustStore::load(paths).unwrap_or_default();
    let policy = policy_for_live_call();
    authorize_call_request(
        content,
        &verifying_key,
        &trust,
        &policy,
        room_id,
        requesting_agent,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use serde_json::json;

    use crate::signing::{encode_verifying_key, key_id_for_verifying_key};

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

    fn agent_state_for(key: &SigningKey) -> AgentState {
        AgentState {
            agent_id: AGENT.to_string(),
            kind: "pi".to_string(),
            matrix_user_id: "@agent:server".to_string(),
            device_id: "DEVICE".to_string(),
            signing_key_id: key_id_for_verifying_key(&key.verifying_key()),
            signing_public_key: Some(encode_verifying_key(&key.verifying_key())),
            status: "active".to_string(),
            capabilities: Vec::new(),
            tools: vec!["run_tests@1.0.0".to_string()],
            workspace: mx_agent_protocol::schema::AgentWorkspace {
                cwd: "/repo".to_string(),
                project_id: String::new(),
                git_commit: String::new(),
            },
            load: mx_agent_protocol::schema::AgentLoad {
                running_invocations: 0,
                max_invocations: 1,
            },
            last_seen_ts: 1,
            state_rev: 1,
            extra: Default::default(),
        }
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
    fn targeted_signed_request_authorizes_and_preserves_target_metadata() {
        let key = test_key();
        let content = build_signed_call_request_for_target(
            &key,
            key_id_for(&key),
            "inv_01HZ",
            "req_01HZ",
            "nonce-1",
            "2026-06-02T12:00:00Z",
            "2026-06-02T12:05:00Z",
            "run_tests",
            json!({ "package": "api" }),
            CallTargeting {
                requesting_agent: Some(AGENT.to_string()),
                target_agent: Some("developer-pi".to_string()),
            },
        )
        .expect("signs");
        let request: CallRequest = serde_json::from_value(content.clone()).unwrap();
        assert_eq!(request.requesting_agent.as_deref(), Some(AGENT));
        assert_eq!(request.target_agent.as_deref(), Some("developer-pi"));
        authorize_call_request(
            &content,
            &key.verifying_key(),
            &trust_with(&key_id_for(&key)),
            &policy(),
            ROOM,
            AGENT,
        )
        .expect("target metadata is covered by a valid signature");
    }

    #[test]
    fn published_public_key_resolves_only_when_it_matches_key_id() {
        let key = test_key();
        let agent = agent_state_for(&key);
        let resolved = verifying_key_from_agent_state(&agent).expect("resolves");
        assert_eq!(resolved, key.verifying_key());

        let mut mismatched = agent_state_for(&key);
        mismatched.signing_key_id = key_id_for(&SigningKey::from_bytes(&[9u8; 32]));
        assert_eq!(
            verifying_key_from_agent_state(&mismatched),
            Err(CallRejection::InvalidSignature)
        );
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
    fn built_request_carries_nonce_and_expiry() {
        // Every built call request must carry replay/expiry fields so the router
        // can guard it like an exec.request.
        let key = test_key();
        let content = signed_request(&key, "run_tests");
        let request: CallRequest = serde_json::from_value(content).unwrap();
        assert!(!request.nonce.is_empty(), "nonce must be populated");
        assert!(
            !request.created_at.is_empty(),
            "created_at must be populated"
        );
        assert!(
            !request.expires_at.is_empty(),
            "expires_at must be populated"
        );
    }

    #[test]
    fn tampered_nonce_fails_signature_check() {
        // The nonce is part of the signed content: replacing it after signing
        // (a replay attempt with a fresh nonce) invalidates the signature.
        let key = test_key();
        let mut content = signed_request(&key, "run_tests");
        content["nonce"] = json!("attacker-supplied-nonce");
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
    fn tampered_expiry_fails_signature_check() {
        // `expires_at` is signed too, so an attacker cannot extend a captured
        // request's validity window without breaking the signature.
        let key = test_key();
        let mut content = signed_request(&key, "run_tests");
        content["expires_at"] = json!("2099-01-01T00:00:00Z");
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
    fn execute_authorized_call_reports_invoke_failure() {
        // An unknown tool cannot be invoked, so the response is ok: false with a
        // machine-readable error rather than a tool result.
        let request = CallRequest {
            invocation_id: "inv".to_string(),
            request_id: "req_01HZ".to_string(),
            tool: "definitely_not_a_tool".to_string(),
            args: json!({}),
            created_at: "2026-06-02T12:00:00Z".to_string(),
            expires_at: "2026-06-02T12:05:00Z".to_string(),
            nonce: "nonce-x".to_string(),
            signature: Signature {
                alg: signing::ALG_ED25519.to_string(),
                key_id: "k".to_string(),
                sig: String::new(),
            },
            requesting_agent: None,
            target_agent: None,
            extra: Default::default(),
        };
        let response = execute_authorized_call(&request);
        assert!(!response.ok);
        assert_eq!(response.request_id, "req_01HZ");
        assert!(response.result.is_none());
        assert!(response.error.is_some());
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
