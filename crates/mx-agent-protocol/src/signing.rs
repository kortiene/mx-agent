//! Ed25519 signing and verification of privileged request payloads
//! (architecture §13, §15).
//!
//! Privileged events such as `com.mxagent.exec.request.v1` and
//! `com.mxagent.call.request.v1` carry a detached [`Signature`](crate::schema::Signature) in their
//! `content`. The signature covers the [canonical JSON][crate::canonical_json]
//! bytes of the content **with the `signature` field removed**, so that the
//! signature can be embedded back into the content it protects without becoming
//! self-referential.
//!
//! The signing rules are:
//!
//! 1. Take the event content as a JSON object.
//! 2. Remove the top-level [`SIGNATURE_FIELD`] field if present.
//! 3. Encode the remainder as [canonical JSON][crate::canonical_json].
//! 4. Sign those bytes with the daemon's Ed25519 key.
//! 5. Store the base64-encoded signature back under [`SIGNATURE_FIELD`].
//!
//! Verification reverses the process: it reads the embedded signature, removes
//! the field, recomputes the canonical bytes, and checks the signature against
//! a trusted verifying key. Because step 2 is applied identically on both
//! sides, the `signature` field is excluded from the signed bytes consistently.

use base64::Engine as _;
use ed25519_dalek::{Signature as Ed25519Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde_json::Value;

use crate::canonical_json;
use crate::schema::Signature;

/// Top-level content field that carries the detached signature.
pub const SIGNATURE_FIELD: &str = "signature";

/// Signature algorithm label used by mx-agent.
pub const ALG_ED25519: &str = "ed25519";

/// Errors returned while signing or verifying a payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureError {
    /// The content is not a JSON object, so it cannot carry a signature.
    NotAnObject,
    /// The content had no `signature` field to verify.
    MissingSignature,
    /// The signature uses an algorithm other than [`ALG_ED25519`].
    UnsupportedAlg(String),
    /// The base64 signature could not be decoded or had the wrong length.
    MalformedSignature,
    /// The signature did not verify against the provided key and payload.
    Invalid,
}

impl std::fmt::Display for SignatureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAnObject => write!(f, "signable content must be a JSON object"),
            Self::MissingSignature => write!(f, "content has no signature field"),
            Self::UnsupportedAlg(alg) => write!(f, "unsupported signature algorithm: {alg}"),
            Self::MalformedSignature => write!(f, "signature is malformed"),
            Self::Invalid => write!(f, "signature verification failed"),
        }
    }
}

impl std::error::Error for SignatureError {}

fn b64() -> base64::engine::general_purpose::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

/// Compute the exact bytes that are signed for `content`.
///
/// This clones the content, removes the top-level `signature` field, and
/// returns the [canonical JSON][crate::canonical_json] encoding of what remains.
/// The same bytes are produced whether or not `content` currently carries a
/// signature, guaranteeing the field is excluded consistently.
pub fn signing_bytes(content: &Value) -> Result<Vec<u8>, SignatureError> {
    let obj = content.as_object().ok_or(SignatureError::NotAnObject)?;
    let mut unsigned = serde_json::Map::with_capacity(obj.len());
    for (key, value) in obj {
        if key != SIGNATURE_FIELD {
            unsigned.insert(key.clone(), value.clone());
        }
    }
    Ok(canonical_json::to_canonical_bytes(&Value::Object(unsigned)))
}

/// Sign `content` with `signing_key`, returning the detached [`Signature`].
///
/// The returned signature is over [`signing_bytes`] of `content`; any existing
/// `signature` field in `content` is ignored when computing the bytes. Use
/// [`sign_into`] to also embed the signature back into the content.
pub fn sign(
    signing_key: &SigningKey,
    key_id: impl Into<String>,
    content: &Value,
) -> Result<Signature, SignatureError> {
    let bytes = signing_bytes(content)?;
    let sig = signing_key.sign(&bytes);
    Ok(Signature {
        alg: ALG_ED25519.to_string(),
        key_id: key_id.into(),
        sig: b64().encode(sig.to_bytes()),
    })
}

/// Sign `content` and embed the resulting signature under the `signature`
/// field, replacing any existing value.
///
/// Returns an error if `content` is not a JSON object.
pub fn sign_into(
    signing_key: &SigningKey,
    key_id: impl Into<String>,
    content: &mut Value,
) -> Result<(), SignatureError> {
    let signature = sign(signing_key, key_id, content)?;
    let obj = content.as_object_mut().ok_or(SignatureError::NotAnObject)?;
    obj.insert(
        SIGNATURE_FIELD.to_string(),
        serde_json::to_value(&signature).expect("Signature serializes to a JSON object"),
    );
    Ok(())
}

/// Verify a detached [`Signature`] against arbitrary `bytes`.
pub fn verify_signature(
    verifying_key: &VerifyingKey,
    signature: &Signature,
    bytes: &[u8],
) -> Result<(), SignatureError> {
    if signature.alg != ALG_ED25519 {
        return Err(SignatureError::UnsupportedAlg(signature.alg.clone()));
    }
    let raw = b64()
        .decode(signature.sig.as_bytes())
        .map_err(|_| SignatureError::MalformedSignature)?;
    let ed_sig =
        Ed25519Signature::from_slice(&raw).map_err(|_| SignatureError::MalformedSignature)?;
    verifying_key
        .verify(bytes, &ed_sig)
        .map_err(|_| SignatureError::Invalid)
}

/// Verify the signature embedded in `content` against `verifying_key`.
///
/// Reads the `signature` field from `content`, recomputes [`signing_bytes`]
/// (which excludes that field), and checks the signature. Returns
/// [`SignatureError::MissingSignature`] if no signature is present.
pub fn verify(verifying_key: &VerifyingKey, content: &Value) -> Result<(), SignatureError> {
    let obj = content.as_object().ok_or(SignatureError::NotAnObject)?;
    let sig_value = obj
        .get(SIGNATURE_FIELD)
        .ok_or(SignatureError::MissingSignature)?;
    let signature: Signature = serde_json::from_value(sig_value.clone())
        .map_err(|_| SignatureError::MalformedSignature)?;
    let bytes = signing_bytes(content)?;
    verify_signature(verifying_key, &signature, &bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use serde_json::json;

    /// Deterministic signing key from a fixed seed, so tests act as stable
    /// test vectors rather than depending on system randomness.
    fn test_key() -> SigningKey {
        let seed: [u8; 32] = [
            0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec,
            0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03,
            0x1c, 0xae, 0x7f, 0x60,
        ];
        SigningKey::from_bytes(&seed)
    }

    fn sample_content() -> Value {
        json!({
            "invocation_id": "inv_01HZ",
            "request_id": "req_01HZ",
            "tool": "run_tests",
            "args": { "suite": "api", "shards": 4 }
        })
    }

    #[test]
    fn valid_signature_verifies() {
        let key = test_key();
        let mut content = sample_content();
        sign_into(&key, "mxagent-ed25519:test", &mut content).unwrap();
        assert!(verify(&key.verifying_key(), &content).is_ok());
    }

    #[test]
    fn signature_field_is_present_after_signing() {
        let key = test_key();
        let mut content = sample_content();
        sign_into(&key, "mxagent-ed25519:test", &mut content).unwrap();
        let sig = &content[SIGNATURE_FIELD];
        assert_eq!(sig["alg"], json!("ed25519"));
        assert_eq!(sig["key_id"], json!("mxagent-ed25519:test"));
        assert!(sig["sig"].as_str().is_some());
    }

    #[test]
    fn modified_payload_fails_verification() {
        let key = test_key();
        let mut content = sample_content();
        sign_into(&key, "mxagent-ed25519:test", &mut content).unwrap();
        // Tamper with a signed field.
        content["args"]["suite"] = json!("prod");
        assert_eq!(
            verify(&key.verifying_key(), &content),
            Err(SignatureError::Invalid)
        );
    }

    #[test]
    fn added_field_fails_verification() {
        let key = test_key();
        let mut content = sample_content();
        sign_into(&key, "mxagent-ed25519:test", &mut content).unwrap();
        content
            .as_object_mut()
            .unwrap()
            .insert("injected".to_string(), json!("evil"));
        assert_eq!(
            verify(&key.verifying_key(), &content),
            Err(SignatureError::Invalid)
        );
    }

    #[test]
    fn wrong_key_fails_verification() {
        let key = test_key();
        let other = SigningKey::from_bytes(&[7u8; 32]);
        let mut content = sample_content();
        sign_into(&key, "mxagent-ed25519:test", &mut content).unwrap();
        assert_eq!(
            verify(&other.verifying_key(), &content),
            Err(SignatureError::Invalid)
        );
    }

    #[test]
    fn signature_field_is_excluded_from_signed_bytes() {
        // Bytes must be identical whether or not a signature field is present,
        // and regardless of the signature's contents.
        let unsigned = sample_content();
        let bytes_unsigned = signing_bytes(&unsigned).unwrap();

        let mut with_sig = sample_content();
        with_sig.as_object_mut().unwrap().insert(
            SIGNATURE_FIELD.to_string(),
            json!({ "alg": "ed25519", "key_id": "x", "sig": "AAAA" }),
        );
        let bytes_with_sig = signing_bytes(&with_sig).unwrap();

        let mut with_other_sig = sample_content();
        with_other_sig.as_object_mut().unwrap().insert(
            SIGNATURE_FIELD.to_string(),
            json!({ "alg": "ed25519", "key_id": "y", "sig": "BBBB" }),
        );
        let bytes_with_other = signing_bytes(&with_other_sig).unwrap();

        assert_eq!(bytes_unsigned, bytes_with_sig);
        assert_eq!(bytes_unsigned, bytes_with_other);
    }

    #[test]
    fn signing_is_deterministic_and_key_order_independent() {
        let key = test_key();
        let a = json!({ "b": 1, "a": 2, "signature": {"alg":"ed25519","key_id":"k","sig":"z"} });
        let b = json!({ "a": 2, "b": 1 });
        assert_eq!(signing_bytes(&a).unwrap(), signing_bytes(&b).unwrap());
        let sig_a = sign(&key, "k", &a).unwrap();
        let sig_b = sign(&key, "k", &b).unwrap();
        assert_eq!(sig_a.sig, sig_b.sig, "Ed25519 over equal bytes is stable");
    }

    #[test]
    fn known_answer_test_vector() {
        // Fixed key + payload => fixed signature. Guards against accidental
        // changes to the canonical form or signing rules.
        let key = test_key();
        let content = json!({ "request_id": "req_01HZ", "tool": "run_tests" });
        let signature = sign(&key, "mxagent-ed25519:test", &content).unwrap();
        assert_eq!(
            signing_bytes(&content).unwrap(),
            br#"{"request_id":"req_01HZ","tool":"run_tests"}"#.to_vec()
        );
        assert_eq!(
            signature.sig,
            "hdQeD1nA4gKCnjuW3XPKYwqbkLb75e7uhpp47F4UF4bztJ0iogI/RpC037jTjPK3ZLrWABhM/jo4RwGaxzsmCA=="
        );
        assert!(verify(&key.verifying_key(), &{
            let mut c = content.clone();
            sign_into(&key, "mxagent-ed25519:test", &mut c).unwrap();
            c
        })
        .is_ok());
    }

    #[test]
    fn missing_signature_is_reported() {
        let key = test_key();
        let content = sample_content();
        assert_eq!(
            verify(&key.verifying_key(), &content),
            Err(SignatureError::MissingSignature)
        );
    }

    #[test]
    fn unsupported_algorithm_is_rejected() {
        let key = test_key();
        let bytes = signing_bytes(&sample_content()).unwrap();
        let sig = Signature {
            alg: "rsa".to_string(),
            key_id: "k".to_string(),
            sig: "AAAA".to_string(),
        };
        assert_eq!(
            verify_signature(&key.verifying_key(), &sig, &bytes),
            Err(SignatureError::UnsupportedAlg("rsa".to_string()))
        );
    }

    #[test]
    fn malformed_signature_is_rejected() {
        let key = test_key();
        let bytes = signing_bytes(&sample_content()).unwrap();
        let sig = Signature {
            alg: ALG_ED25519.to_string(),
            key_id: "k".to_string(),
            sig: "not-base64!!".to_string(),
        };
        assert_eq!(
            verify_signature(&key.verifying_key(), &sig, &bytes),
            Err(SignatureError::MalformedSignature)
        );
    }

    #[test]
    fn non_object_content_is_rejected() {
        assert_eq!(
            signing_bytes(&json!([1, 2, 3])),
            Err(SignatureError::NotAnObject)
        );
    }
}
