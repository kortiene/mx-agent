//! Signed `exec` request routing and authorization (architecture §7.2, §13).
//!
//! Raw `exec` is the most privileged remote operation: it runs an arbitrary
//! command on the target agent's host. A caller builds a
//! `com.mxagent.exec.request.v1` timeline event, signs its content with the
//! daemon's Ed25519 key (see [`crate::signing`]), and sends it into a workspace
//! room with [`send_exec_request`]. Matrix federates the event to the target
//! agent's daemon, which receives it through `/sync`.
//!
//! Before spawning anything, the receiving daemon runs the verification
//! pipeline in [`authorize_exec_request`]:
//!
//! 1. **Signature** — the content must carry a valid detached signature over
//!    its [canonical JSON][mx_agent_protocol::canonical_json] (the `signature`
//!    field excluded). Missing signatures are [`ExecRejection::Unsigned`];
//!    invalid ones are [`ExecRejection::InvalidSignature`].
//! 2. **Routing** — the request's `target_agent` must name this daemon's local
//!    agent; misrouted requests are [`ExecRejection::WrongTarget`].
//! 3. **Trust** — the signing key must be present and trusted in the daemon's
//!    local [`TrustStore`]. Unknown or revoked keys are
//!    [`ExecRejection::UntrustedKey`].
//! 4. **Policy** — the requested command must be permitted for the requesting
//!    agent in the request's room by the local [`Policy`]. Denials are
//!    [`ExecRejection::PolicyDenied`].
//!
//! Only when all checks pass is the request authorized. The daemon then emits a
//! `com.mxagent.exec.accepted.v1` and creates an invocation state record; on
//! any rejection it emits a `com.mxagent.exec.rejected.v1` carrying a stable,
//! machine-readable reason and spawns nothing.

use std::collections::BTreeMap;

use ed25519_dalek::{SigningKey, VerifyingKey};
use matrix_sdk::Room;
use serde_json::Value;

use mx_agent_policy::{Allowance, DenyReason, ExecContext, Policy};
use mx_agent_protocol::events::state::INVOCATION;
use mx_agent_protocol::events::timeline::{
    EXEC_ACCEPTED, EXEC_CANCEL, EXEC_CANCELLED, EXEC_REJECTED, EXEC_REQUEST,
};
use mx_agent_protocol::schema::{
    ExecAccepted, ExecCancel, ExecCancelled, ExecRejected, ExecRequest, InvocationState, Signature,
};
use mx_agent_protocol::signing::{self, SignatureError, SIGNATURE_FIELD};

use crate::trust::TrustStore;
use crate::workspace::WorkspaceError;

/// Why an incoming `com.mxagent.exec.request.v1` was rejected.
///
/// Every variant maps to a stable, machine-readable reason string via
/// [`ExecRejection::reason`], which is what the emitted
/// `com.mxagent.exec.rejected.v1` carries in its `reason` field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecRejection {
    /// The request content was not a JSON object, so it cannot be verified.
    Malformed,
    /// The request carried no `signature` field.
    Unsigned,
    /// The signature was present but did not verify against the signing key.
    InvalidSignature,
    /// The request's `target_agent` does not name this daemon's local agent.
    WrongTarget {
        /// The `target_agent` named in the request.
        target: String,
    },
    /// The signing key is unknown to or revoked in the local trust store.
    UntrustedKey {
        /// The signing key identifier that was rejected.
        key_id: String,
    },
    /// The local policy denied the requested command for this room/agent.
    PolicyDenied(DenyReason),
}

impl ExecRejection {
    /// A stable, machine-readable reason string for use in an [`ExecRejected`].
    pub fn reason(&self) -> String {
        match self {
            Self::Malformed => "malformed_request".to_string(),
            Self::Unsigned => "unsigned".to_string(),
            Self::InvalidSignature => "invalid_signature".to_string(),
            Self::WrongTarget { .. } => "wrong_target".to_string(),
            Self::UntrustedKey { .. } => "untrusted_key".to_string(),
            Self::PolicyDenied(_) => "policy_denied".to_string(),
        }
    }
}

impl std::fmt::Display for ExecRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed => write!(f, "exec request content is not a JSON object"),
            Self::Unsigned => write!(f, "exec request is unsigned"),
            Self::InvalidSignature => write!(f, "exec request signature is invalid"),
            Self::WrongTarget { target } => {
                write!(f, "exec request is addressed to {target:?}, not this agent")
            }
            Self::UntrustedKey { key_id } => {
                write!(f, "signing key {key_id:?} is not trusted")
            }
            Self::PolicyDenied(reason) => write!(f, "policy denied exec: {reason}"),
        }
    }
}

impl std::error::Error for ExecRejection {}

/// Read the detached [`Signature`] embedded in `content`, if present and
/// well-formed. Returns `None` when there is no `signature` field at all
/// (an unsigned request) and an error when the field is malformed.
fn read_signature(content: &Value) -> Result<Option<Signature>, ExecRejection> {
    let obj = content.as_object().ok_or(ExecRejection::Malformed)?;
    match obj.get(SIGNATURE_FIELD) {
        None => Ok(None),
        Some(Value::Null) => Ok(None),
        Some(value) => serde_json::from_value::<Signature>(value.clone())
            .map(Some)
            .map_err(|_| ExecRejection::InvalidSignature),
    }
}

/// Options describing the command an [`ExecRequest`] should run.
///
/// These are the request-specific fields a caller chooses; the protocol
/// bookkeeping fields (`invocation_id`, `request_id`, `nonce`, timestamps, and
/// the signature) are filled in by [`build_signed_exec_request`].
#[derive(Debug, Clone)]
pub struct ExecRequestOptions {
    /// Agent expected to run the command.
    pub target_agent: String,
    /// Agent issuing the request.
    pub requesting_agent: String,
    /// Command argv (program followed by arguments).
    pub command: Vec<String>,
    /// Working directory.
    pub cwd: String,
    /// Environment overrides.
    pub env: BTreeMap<String, String>,
    /// Whether stdin will be streamed.
    pub stdin: bool,
    /// Whether output should be streamed.
    pub stream: bool,
    /// Whether to allocate a PTY.
    pub pty: bool,
    /// Timeout in milliseconds.
    pub timeout_ms: u64,
    /// Owning task identifier, if any.
    pub task_id: Option<String>,
}

/// Build and sign a `com.mxagent.exec.request.v1` content value.
///
/// Constructs an [`ExecRequest`] from `options` and the supplied identifiers,
/// then signs the content with `signing_key`, embedding the detached signature
/// under the `signature` field. The returned JSON value is ready to be sent as
/// the timeline event's content.
#[allow(clippy::too_many_arguments)]
pub fn build_signed_exec_request(
    signing_key: &SigningKey,
    key_id: impl Into<String>,
    invocation_id: impl Into<String>,
    request_id: impl Into<String>,
    nonce: impl Into<String>,
    created_at: impl Into<String>,
    expires_at: impl Into<String>,
    options: &ExecRequestOptions,
) -> Result<Value, SignatureError> {
    let invocation_id = invocation_id.into();
    let idempotency_key = format!("exec:{invocation_id}");
    // Build the unsigned content with a placeholder signature, then sign it in
    // place. `sign_into` excludes the `signature` field from the signed bytes,
    // so the placeholder does not affect the result.
    let request = ExecRequest {
        invocation_id,
        request_id: request_id.into(),
        target_agent: options.target_agent.clone(),
        requesting_agent: options.requesting_agent.clone(),
        command: options.command.clone(),
        cwd: options.cwd.clone(),
        env: options.env.clone(),
        stdin: options.stdin,
        stream: options.stream,
        pty: options.pty,
        timeout_ms: options.timeout_ms,
        task_id: options.task_id.clone(),
        created_at: created_at.into(),
        expires_at: expires_at.into(),
        nonce: nonce.into(),
        idempotency_key,
        signature: Signature {
            alg: signing::ALG_ED25519.to_string(),
            key_id: key_id.into(),
            sig: String::new(),
        },
        extra: Default::default(),
    };
    let mut content =
        serde_json::to_value(&request).expect("ExecRequest serializes to a JSON object");
    let key_id = request.signature.key_id;
    signing::sign_into(signing_key, key_id, &mut content)?;
    Ok(content)
}

/// Send a signed `com.mxagent.exec.request.v1` timeline event into `room`.
///
/// Builds and signs the request with [`build_signed_exec_request`], then sends
/// it as a Matrix timeline event so it federates to the target agent. Returns
/// the parsed [`ExecRequest`] that was sent (including its embedded signature).
#[allow(clippy::too_many_arguments)]
pub async fn send_exec_request(
    room: &Room,
    signing_key: &SigningKey,
    key_id: impl Into<String>,
    invocation_id: impl Into<String>,
    request_id: impl Into<String>,
    nonce: impl Into<String>,
    created_at: impl Into<String>,
    expires_at: impl Into<String>,
    options: &ExecRequestOptions,
) -> Result<ExecRequest, WorkspaceError> {
    // Signing only fails when the content is not a JSON object; the content we
    // build here is always an object, so this cannot fail in practice.
    let content = build_signed_exec_request(
        signing_key,
        key_id,
        invocation_id,
        request_id,
        nonce,
        created_at,
        expires_at,
        options,
    )
    .expect("ExecRequest content is always a JSON object");
    room.send_raw(EXEC_REQUEST, content.clone())
        .await
        .map_err(WorkspaceError::from)?;
    serde_json::from_value::<ExecRequest>(content)
        .map_err(|e| WorkspaceError::from(matrix_sdk::Error::SerdeJson(e)))
}

/// Verify and authorize an incoming `com.mxagent.exec.request.v1`.
///
/// Runs the full receive-side pipeline (architecture §13.1): signature, then
/// routing, then trust, then policy. On success the parsed [`ExecRequest`] is
/// returned; on failure the first failing check is reported as an
/// [`ExecRejection`] and **no process is spawned** — the policy engine is a
/// pure function and this routine never starts anything.
///
/// `verifying_key` is the public key the caller has resolved for the request's
/// signing key (for example from the requesting agent's published key);
/// `local_agent` is this daemon's own agent identity, used to confirm the
/// request was routed to us; the trust check confirms the key id is locally
/// trusted; and the policy check confirms the command is permitted for
/// `requesting_agent` in `room_id`.
pub fn authorize_exec_request(
    content: &Value,
    verifying_key: &VerifyingKey,
    trust: &TrustStore,
    policy: &Policy,
    room_id: &str,
    requesting_agent: &str,
    local_agent: &str,
) -> Result<ExecRequest, ExecRejection> {
    authorize_exec_request_with_allowance(
        content,
        verifying_key,
        trust,
        policy,
        room_id,
        requesting_agent,
        local_agent,
    )
    .map(|(request, _allowance)| request)
}

/// Like [`authorize_exec_request`] but also returns the resolved [`Allowance`].
///
/// The allowance carries the limits the runner must enforce — including the
/// `requires_approval` flag the caller consults (via
/// [`crate::approval::disposition_for_exec`]) to decide whether the request may
/// run immediately or must be queued for approval. Authorizing a request never
/// spawns a process.
pub fn authorize_exec_request_with_allowance(
    content: &Value,
    verifying_key: &VerifyingKey,
    trust: &TrustStore,
    policy: &Policy,
    room_id: &str,
    requesting_agent: &str,
    local_agent: &str,
) -> Result<(ExecRequest, Allowance), ExecRejection> {
    // 1. Signature must be present and valid.
    let signature = read_signature(content)?.ok_or(ExecRejection::Unsigned)?;
    signing::verify(verifying_key, content).map_err(|e| match e {
        SignatureError::MissingSignature => ExecRejection::Unsigned,
        SignatureError::NotAnObject => ExecRejection::Malformed,
        _ => ExecRejection::InvalidSignature,
    })?;

    let request: ExecRequest =
        serde_json::from_value(content.clone()).map_err(|_| ExecRejection::Malformed)?;

    // 2. The request must be addressed to this agent.
    if request.target_agent != local_agent {
        return Err(ExecRejection::WrongTarget {
            target: request.target_agent,
        });
    }

    // 3. The signing key must be locally trusted.
    if !trust.is_key_trusted(&signature.key_id) {
        return Err(ExecRejection::UntrustedKey {
            key_id: signature.key_id,
        });
    }

    // 4. The local policy must permit the command for this room/agent.
    let outcome = policy.evaluate_exec(&ExecContext {
        room_id,
        requesting_agent,
        command: &request.command,
        cwd: &request.cwd,
    });
    match outcome.allowance() {
        Some(allowance) => Ok((request, allowance.clone())),
        None => Err(ExecRejection::PolicyDenied(
            outcome.deny_reason().expect("denied outcome has a reason"),
        )),
    }
}

/// Build a `com.mxagent.invocation.v1` state record for an authorized request.
///
/// The invocation starts in the `accepted` state; the runner advances it to
/// `running`, then to a terminal state when the process exits.
pub fn invocation_state_for(request: &ExecRequest, now: impl Into<String>) -> InvocationState {
    let now = now.into();
    InvocationState {
        invocation_id: request.invocation_id.clone(),
        task_id: request.task_id.clone(),
        requester: request.requesting_agent.clone(),
        target: request.target_agent.clone(),
        state: "accepted".to_string(),
        created_at: now.clone(),
        updated_at: now,
        exit_code: None,
        state_rev: 0,
        extra: Default::default(),
    }
}

/// Emit a `com.mxagent.exec.accepted.v1` timeline event into `room`.
pub async fn emit_exec_accepted(
    room: &Room,
    invocation_id: impl Into<String>,
) -> Result<(), WorkspaceError> {
    let accepted = ExecAccepted {
        invocation_id: invocation_id.into(),
        extra: Default::default(),
    };
    let content = serde_json::to_value(&accepted)
        .map_err(|e| WorkspaceError::from(matrix_sdk::Error::SerdeJson(e)))?;
    room.send_raw(EXEC_ACCEPTED, content)
        .await
        .map_err(WorkspaceError::from)?;
    Ok(())
}

/// Emit a `com.mxagent.exec.rejected.v1` timeline event into `room`.
///
/// Carries the stable, machine-readable [`ExecRejection::reason`]. Emitting a
/// rejection never spawns a process.
pub async fn emit_exec_rejected(
    room: &Room,
    invocation_id: impl Into<String>,
    rejection: &ExecRejection,
) -> Result<(), WorkspaceError> {
    let rejected = ExecRejected {
        invocation_id: invocation_id.into(),
        reason: rejection.reason(),
        extra: Default::default(),
    };
    let content = serde_json::to_value(&rejected)
        .map_err(|e| WorkspaceError::from(matrix_sdk::Error::SerdeJson(e)))?;
    room.send_raw(EXEC_REJECTED, content)
        .await
        .map_err(WorkspaceError::from)?;
    Ok(())
}

/// Publish a `com.mxagent.invocation.v1` state event keyed by `invocation_id`.
pub async fn publish_invocation_state(
    room: &Room,
    state: &InvocationState,
) -> Result<(), WorkspaceError> {
    let content = serde_json::to_value(state)
        .map_err(|e| WorkspaceError::from(matrix_sdk::Error::SerdeJson(e)))?;
    room.send_state_event_raw(INVOCATION, &state.invocation_id, content)
        .await
        .map_err(WorkspaceError::from)?;
    Ok(())
}

/// Why an incoming `com.mxagent.exec.cancel.v1` was rejected (architecture §7.5,
/// §13.1).
///
/// Cancellation authorization is narrower than a fresh exec: there is no policy
/// or routing check, but the requester must prove they own the invocation they
/// are cancelling. Every variant maps to a stable, machine-readable reason via
/// [`CancelRejection::reason`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CancelRejection {
    /// The cancel content was not a JSON object, so it cannot be verified.
    Malformed,
    /// The cancel carried no `signature` field.
    Unsigned,
    /// The signature was present but did not verify against the signing key.
    InvalidSignature,
    /// The cancel names a different invocation than the one being authorized.
    InvocationMismatch {
        /// The `invocation_id` named in the cancel request.
        requested: String,
    },
    /// The signing key is unknown to or revoked in the local trust store.
    UntrustedKey {
        /// The signing key identifier that was rejected.
        key_id: String,
    },
    /// The requester does not own the invocation, so may not cancel it.
    Unauthorized {
        /// The agent that owns (requested) the invocation.
        owner: String,
    },
}

impl CancelRejection {
    /// A stable, machine-readable reason string.
    pub fn reason(&self) -> String {
        match self {
            Self::Malformed => "malformed_request".to_string(),
            Self::Unsigned => "unsigned".to_string(),
            Self::InvalidSignature => "invalid_signature".to_string(),
            Self::InvocationMismatch { .. } => "invocation_mismatch".to_string(),
            Self::UntrustedKey { .. } => "untrusted_key".to_string(),
            Self::Unauthorized { .. } => "unauthorized".to_string(),
        }
    }
}

impl std::fmt::Display for CancelRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed => write!(f, "cancel request content is not a JSON object"),
            Self::Unsigned => write!(f, "cancel request is unsigned"),
            Self::InvalidSignature => write!(f, "cancel request signature is invalid"),
            Self::InvocationMismatch { requested } => {
                write!(f, "cancel request names invocation {requested:?}")
            }
            Self::UntrustedKey { key_id } => {
                write!(f, "signing key {key_id:?} is not trusted")
            }
            Self::Unauthorized { owner } => {
                write!(f, "only the requester {owner:?} may cancel this invocation")
            }
        }
    }
}

impl std::error::Error for CancelRejection {}

/// Build and sign a `com.mxagent.exec.cancel.v1` content value.
///
/// Constructs an [`ExecCancel`] for `invocation_id` carrying a human-readable
/// `reason`, then signs the content with `signing_key`, embedding the detached
/// signature under the `signature` field. The returned JSON value is ready to be
/// sent as the timeline event's content.
pub fn build_signed_exec_cancel(
    signing_key: &SigningKey,
    key_id: impl Into<String>,
    invocation_id: impl Into<String>,
    reason: impl Into<String>,
    created_at: impl Into<String>,
    nonce: impl Into<String>,
) -> Result<Value, SignatureError> {
    // Build the unsigned content with a placeholder signature, then sign it in
    // place. `sign_into` excludes the `signature` field from the signed bytes,
    // so the placeholder does not affect the result.
    let cancel = ExecCancel {
        invocation_id: invocation_id.into(),
        reason: reason.into(),
        created_at: created_at.into(),
        nonce: nonce.into(),
        signature: Signature {
            alg: signing::ALG_ED25519.to_string(),
            key_id: key_id.into(),
            sig: String::new(),
        },
        extra: Default::default(),
    };
    let mut content =
        serde_json::to_value(&cancel).expect("ExecCancel serializes to a JSON object");
    let key_id = cancel.signature.key_id;
    signing::sign_into(signing_key, key_id, &mut content)?;
    Ok(content)
}

/// Send a signed `com.mxagent.exec.cancel.v1` timeline event into `room`.
///
/// Builds and signs the cancel with [`build_signed_exec_cancel`], then sends it
/// as a Matrix timeline event so it federates to the target agent. Returns the
/// parsed [`ExecCancel`] that was sent (including its embedded signature).
pub async fn send_exec_cancel(
    room: &Room,
    signing_key: &SigningKey,
    key_id: impl Into<String>,
    invocation_id: impl Into<String>,
    reason: impl Into<String>,
    created_at: impl Into<String>,
    nonce: impl Into<String>,
) -> Result<ExecCancel, WorkspaceError> {
    // Signing only fails when the content is not a JSON object; the content we
    // build here is always an object, so this cannot fail in practice.
    let content = build_signed_exec_cancel(
        signing_key,
        key_id,
        invocation_id,
        reason,
        created_at,
        nonce,
    )
    .expect("ExecCancel content is always a JSON object");
    room.send_raw(EXEC_CANCEL, content.clone())
        .await
        .map_err(WorkspaceError::from)?;
    serde_json::from_value::<ExecCancel>(content)
        .map_err(|e| WorkspaceError::from(matrix_sdk::Error::SerdeJson(e)))
}

/// Verify and authorize an incoming `com.mxagent.exec.cancel.v1` against the
/// `invocation` it targets (architecture §7.5, §13.1).
///
/// Runs the receive-side pipeline: signature, then invocation match, then trust,
/// then ownership. On success the parsed [`ExecCancel`] is returned; on failure
/// the first failing check is reported as a [`CancelRejection`] and **nothing is
/// terminated** — this routine never signals a process.
///
/// `verifying_key` is the public key resolved for the cancel's signing key;
/// `requesting_agent` is the agent identity the cancel was sent from (resolved
/// from the Matrix event sender). Authorization requires that this agent owns
/// the invocation — i.e. it is the invocation's original `requester` — so a peer
/// cannot cancel another agent's running command.
pub fn authorize_exec_cancel(
    content: &Value,
    verifying_key: &VerifyingKey,
    trust: &TrustStore,
    invocation: &InvocationState,
    requesting_agent: &str,
) -> Result<ExecCancel, CancelRejection> {
    // 1. Signature must be present and valid.
    let signature = read_cancel_signature(content)?.ok_or(CancelRejection::Unsigned)?;
    signing::verify(verifying_key, content).map_err(|e| match e {
        SignatureError::MissingSignature => CancelRejection::Unsigned,
        SignatureError::NotAnObject => CancelRejection::Malformed,
        _ => CancelRejection::InvalidSignature,
    })?;

    let cancel: ExecCancel =
        serde_json::from_value(content.clone()).map_err(|_| CancelRejection::Malformed)?;

    // 2. The cancel must name the invocation being authorized.
    if cancel.invocation_id != invocation.invocation_id {
        return Err(CancelRejection::InvocationMismatch {
            requested: cancel.invocation_id,
        });
    }

    // 3. The signing key must be locally trusted.
    if !trust.is_key_trusted(&signature.key_id) {
        return Err(CancelRejection::UntrustedKey {
            key_id: signature.key_id,
        });
    }

    // 4. The requester must own the invocation they are cancelling.
    if requesting_agent != invocation.requester {
        return Err(CancelRejection::Unauthorized {
            owner: invocation.requester.clone(),
        });
    }

    Ok(cancel)
}

/// Read the detached [`Signature`] embedded in a cancel `content`, mirroring
/// [`read_signature`] but mapping failures to [`CancelRejection`].
fn read_cancel_signature(content: &Value) -> Result<Option<Signature>, CancelRejection> {
    let obj = content.as_object().ok_or(CancelRejection::Malformed)?;
    match obj.get(SIGNATURE_FIELD) {
        None => Ok(None),
        Some(Value::Null) => Ok(None),
        Some(value) => serde_json::from_value::<Signature>(value.clone())
            .map(Some)
            .map_err(|_| CancelRejection::InvalidSignature),
    }
}

/// Emit a `com.mxagent.exec.cancelled.v1` timeline event into `room`.
///
/// Confirms that a cancellation tore down the invocation's process group:
/// `signal_sent` names the delivered signal (see [`crate::runner::CANCEL_SIGNAL`])
/// and `killed_process_group` records whether the whole group was signalled.
pub async fn emit_exec_cancelled(
    room: &Room,
    invocation_id: impl Into<String>,
    signal_sent: impl Into<String>,
    killed_process_group: bool,
    finished_at: impl Into<String>,
) -> Result<(), WorkspaceError> {
    let cancelled = ExecCancelled {
        invocation_id: invocation_id.into(),
        signal_sent: signal_sent.into(),
        killed_process_group,
        finished_at: finished_at.into(),
        extra: Default::default(),
    };
    let content = serde_json::to_value(&cancelled)
        .map_err(|e| WorkspaceError::from(matrix_sdk::Error::SerdeJson(e)))?;
    room.send_raw(EXEC_CANCELLED, content)
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

    /// Deterministic signing key from a fixed seed.
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
    const TARGET: &str = "developer-pi";

    fn policy() -> Policy {
        let toml = r#"
[rooms."!abc:matrix.org"]
trusted = true

[rooms."!abc:matrix.org".agents."@claude:matrix.org"]
allow_exec = true
allow_commands = ["cargo"]
allow_cwd = ["/home/me/code/project"]
"#;
        Policy::parse(toml).expect("policy parses")
    }

    fn trust_with(key_id: &str) -> TrustStore {
        let mut store = TrustStore::default();
        store.approve(AGENT, key_id, None, None, None);
        store
    }

    fn options(command: &[&str], cwd: &str) -> ExecRequestOptions {
        ExecRequestOptions {
            target_agent: TARGET.to_string(),
            requesting_agent: AGENT.to_string(),
            command: command.iter().map(|s| s.to_string()).collect(),
            cwd: cwd.to_string(),
            env: BTreeMap::new(),
            stdin: false,
            stream: true,
            pty: false,
            timeout_ms: 600_000,
            task_id: None,
        }
    }

    fn signed_request(key: &SigningKey, opts: &ExecRequestOptions) -> Value {
        build_signed_exec_request(
            key,
            key_id_for(key),
            "inv_01HZ",
            "req_01HZ",
            "base64-nonce",
            "2026-06-02T12:00:00Z",
            "2026-06-02T12:05:00Z",
            opts,
        )
        .expect("signs")
    }

    fn authorize(
        content: &Value,
        key: &SigningKey,
        trust: &TrustStore,
    ) -> Result<ExecRequest, ExecRejection> {
        authorize_exec_request(
            content,
            &key.verifying_key(),
            trust,
            &policy(),
            ROOM,
            AGENT,
            TARGET,
        )
    }

    #[test]
    fn build_sets_idempotency_key_from_invocation() {
        let key = test_key();
        let content = signed_request(&key, &options(&["cargo", "test"], "/home/me/code/project"));
        let request: ExecRequest = serde_json::from_value(content).unwrap();
        assert_eq!(request.idempotency_key, "exec:inv_01HZ");
        assert_eq!(request.target_agent, TARGET);
        assert_eq!(request.command, vec!["cargo", "test"]);
    }

    #[test]
    fn allowed_request_authorizes() {
        // Acceptance: target daemon accepts allowed exec requests.
        let key = test_key();
        let content = signed_request(&key, &options(&["cargo", "test"], "/home/me/code/project"));
        let trust = trust_with(&key_id_for(&key));
        let request = authorize(&content, &key, &trust).expect("authorized");
        assert_eq!(request.invocation_id, "inv_01HZ");
        assert_eq!(request.command, vec!["cargo", "test"]);
    }

    #[test]
    fn unsigned_request_is_rejected() {
        let key = test_key();
        let mut content =
            signed_request(&key, &options(&["cargo", "test"], "/home/me/code/project"));
        content
            .as_object_mut()
            .unwrap()
            .remove(SIGNATURE_FIELD)
            .unwrap();
        let trust = trust_with(&key_id_for(&key));
        let err = authorize(&content, &key, &trust).unwrap_err();
        assert_eq!(err, ExecRejection::Unsigned);
        assert_eq!(err.reason(), "unsigned");
    }

    #[test]
    fn null_signature_is_treated_as_unsigned() {
        let key = test_key();
        let mut content =
            signed_request(&key, &options(&["cargo", "test"], "/home/me/code/project"));
        content.as_object_mut().unwrap()[SIGNATURE_FIELD] = Value::Null;
        let trust = trust_with(&key_id_for(&key));
        let err = authorize(&content, &key, &trust).unwrap_err();
        assert_eq!(err, ExecRejection::Unsigned);
    }

    #[test]
    fn tampered_payload_fails_signature_check() {
        let key = test_key();
        let mut content =
            signed_request(&key, &options(&["cargo", "test"], "/home/me/code/project"));
        content["command"] = json!(["cargo", "publish"]);
        let trust = trust_with(&key_id_for(&key));
        let err = authorize(&content, &key, &trust).unwrap_err();
        assert_eq!(err, ExecRejection::InvalidSignature);
    }

    #[test]
    fn wrong_target_is_rejected() {
        // Routing: a request addressed to another agent is not run here.
        let key = test_key();
        let mut opts = options(&["cargo", "test"], "/home/me/code/project");
        opts.target_agent = "some-other-agent".to_string();
        let content = signed_request(&key, &opts);
        let trust = trust_with(&key_id_for(&key));
        let err = authorize(&content, &key, &trust).unwrap_err();
        assert_eq!(
            err,
            ExecRejection::WrongTarget {
                target: "some-other-agent".to_string()
            }
        );
        assert_eq!(err.reason(), "wrong_target");
    }

    #[test]
    fn untrusted_key_is_rejected() {
        let key = test_key();
        let content = signed_request(&key, &options(&["cargo", "test"], "/home/me/code/project"));
        let trust = TrustStore::default();
        let err = authorize(&content, &key, &trust).unwrap_err();
        assert_eq!(
            err,
            ExecRejection::UntrustedKey {
                key_id: key_id_for(&key)
            }
        );
        assert_eq!(err.reason(), "untrusted_key");
    }

    #[test]
    fn revoked_key_is_rejected() {
        let key = test_key();
        let content = signed_request(&key, &options(&["cargo", "test"], "/home/me/code/project"));
        let mut trust = trust_with(&key_id_for(&key));
        trust.revoke(AGENT, &key_id_for(&key));
        let err = authorize(&content, &key, &trust).unwrap_err();
        assert!(matches!(err, ExecRejection::UntrustedKey { .. }));
    }

    #[test]
    fn policy_denied_command_is_rejected_without_spawning() {
        // Acceptance: disallowed requests emit rejection without spawning. This
        // routine never spawns; a denied command simply yields a rejection.
        let key = test_key();
        let content = signed_request(&key, &options(&["rm", "-rf", "/"], "/home/me/code/project"));
        let trust = trust_with(&key_id_for(&key));
        let err = authorize(&content, &key, &trust).unwrap_err();
        assert!(matches!(err, ExecRejection::PolicyDenied(_)));
        assert_eq!(err.reason(), "policy_denied");
    }

    #[test]
    fn pipeline_order_signature_before_trust() {
        // A tampered request from an untrusted key fails on the signature first.
        let key = test_key();
        let mut content =
            signed_request(&key, &options(&["cargo", "test"], "/home/me/code/project"));
        content["command"] = json!(["cargo", "publish"]);
        let trust = TrustStore::default();
        let err = authorize(&content, &key, &trust).unwrap_err();
        assert_eq!(err, ExecRejection::InvalidSignature);
    }

    #[test]
    fn malformed_content_is_rejected() {
        let key = test_key();
        let trust = trust_with(&key_id_for(&key));
        let content = json!([1, 2, 3]);
        let err = authorize(&content, &key, &trust).unwrap_err();
        assert_eq!(err, ExecRejection::Malformed);
    }

    #[test]
    fn invocation_state_is_built_in_accepted_state() {
        let key = test_key();
        let content = signed_request(&key, &options(&["cargo", "test"], "/home/me/code/project"));
        let request: ExecRequest = serde_json::from_value(content).unwrap();
        let state = invocation_state_for(&request, "2026-06-02T12:00:01Z");
        assert_eq!(state.invocation_id, "inv_01HZ");
        assert_eq!(state.requester, AGENT);
        assert_eq!(state.target, TARGET);
        assert_eq!(state.state, "accepted");
        assert_eq!(state.created_at, "2026-06-02T12:00:01Z");
        assert_eq!(state.updated_at, "2026-06-02T12:00:01Z");
        assert!(state.exit_code.is_none());
    }

    // --- cancellation (#48) ---

    /// A `running` invocation owned by [`AGENT`], the canonical cancel target.
    fn running_invocation() -> InvocationState {
        InvocationState {
            invocation_id: "inv_01HZ".to_string(),
            task_id: None,
            requester: AGENT.to_string(),
            target: TARGET.to_string(),
            state: "running".to_string(),
            created_at: "2026-06-02T12:00:00Z".to_string(),
            updated_at: "2026-06-02T12:00:01Z".to_string(),
            exit_code: None,
            state_rev: 1,
            extra: Default::default(),
        }
    }

    fn signed_cancel(key: &SigningKey, invocation_id: &str) -> Value {
        build_signed_exec_cancel(
            key,
            key_id_for(key),
            invocation_id,
            "user requested",
            "2026-06-02T12:01:00Z",
            "base64-nonce",
        )
        .expect("signs")
    }

    #[test]
    fn owner_can_cancel_running_invocation() {
        // Acceptance: `invocation cancel` is authorized for the running command's
        // own requester.
        let key = test_key();
        let content = signed_cancel(&key, "inv_01HZ");
        let trust = trust_with(&key_id_for(&key));
        let cancel = authorize_exec_cancel(
            &content,
            &key.verifying_key(),
            &trust,
            &running_invocation(),
            AGENT,
        )
        .expect("authorized");
        assert_eq!(cancel.invocation_id, "inv_01HZ");
        assert_eq!(cancel.reason, "user requested");
    }

    #[test]
    fn unsigned_cancel_is_rejected() {
        let key = test_key();
        let mut content = signed_cancel(&key, "inv_01HZ");
        content
            .as_object_mut()
            .unwrap()
            .remove(SIGNATURE_FIELD)
            .unwrap();
        let trust = trust_with(&key_id_for(&key));
        let err = authorize_exec_cancel(
            &content,
            &key.verifying_key(),
            &trust,
            &running_invocation(),
            AGENT,
        )
        .unwrap_err();
        assert_eq!(err, CancelRejection::Unsigned);
        assert_eq!(err.reason(), "unsigned");
    }

    #[test]
    fn tampered_cancel_fails_signature_check() {
        let key = test_key();
        let mut content = signed_cancel(&key, "inv_01HZ");
        content["reason"] = json!("something else");
        let trust = trust_with(&key_id_for(&key));
        let err = authorize_exec_cancel(
            &content,
            &key.verifying_key(),
            &trust,
            &running_invocation(),
            AGENT,
        )
        .unwrap_err();
        assert_eq!(err, CancelRejection::InvalidSignature);
    }

    #[test]
    fn cancel_for_other_invocation_is_rejected() {
        let key = test_key();
        let content = signed_cancel(&key, "inv_other");
        let trust = trust_with(&key_id_for(&key));
        let err = authorize_exec_cancel(
            &content,
            &key.verifying_key(),
            &trust,
            &running_invocation(),
            AGENT,
        )
        .unwrap_err();
        assert_eq!(
            err,
            CancelRejection::InvocationMismatch {
                requested: "inv_other".to_string()
            }
        );
    }

    #[test]
    fn cancel_from_untrusted_key_is_rejected() {
        let key = test_key();
        let content = signed_cancel(&key, "inv_01HZ");
        let trust = TrustStore::default();
        let err = authorize_exec_cancel(
            &content,
            &key.verifying_key(),
            &trust,
            &running_invocation(),
            AGENT,
        )
        .unwrap_err();
        assert_eq!(
            err,
            CancelRejection::UntrustedKey {
                key_id: key_id_for(&key)
            }
        );
    }

    #[test]
    fn cancel_from_non_owner_is_rejected() {
        // Acceptance: unauthorized cancellation is rejected. A trusted peer that
        // does not own the invocation may not cancel it.
        let key = test_key();
        let content = signed_cancel(&key, "inv_01HZ");
        let trust = trust_with(&key_id_for(&key));
        let err = authorize_exec_cancel(
            &content,
            &key.verifying_key(),
            &trust,
            &running_invocation(),
            "@someone-else:matrix.org",
        )
        .unwrap_err();
        assert_eq!(
            err,
            CancelRejection::Unauthorized {
                owner: AGENT.to_string()
            }
        );
        assert_eq!(err.reason(), "unauthorized");
    }

    #[test]
    fn cancel_pipeline_checks_signature_before_ownership() {
        // A tampered cancel from a non-owner fails on the signature first, so the
        // rejection does not leak the ownership relationship.
        let key = test_key();
        let mut content = signed_cancel(&key, "inv_01HZ");
        content["reason"] = json!("tampered");
        let trust = trust_with(&key_id_for(&key));
        let err = authorize_exec_cancel(
            &content,
            &key.verifying_key(),
            &trust,
            &running_invocation(),
            "@someone-else:matrix.org",
        )
        .unwrap_err();
        assert_eq!(err, CancelRejection::InvalidSignature);
    }
}
