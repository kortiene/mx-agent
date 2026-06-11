//! Daemon signing key storage (architecture §13.2).
//!
//! The daemon owns an Ed25519 signing key used to sign tool-call envelopes and
//! to establish trust with workspace owners. The key is generated on first run
//! and persisted in daemon-owned storage with `0600` permissions so the private
//! key is never world-readable. Its public fingerprint is stable across daemon
//! restarts and is surfaced through `trust fingerprint`.
//!
//! Only the secret key bytes are persisted; the verifying (public) key and the
//! fingerprint are derived deterministically on load, so the fingerprint a
//! workspace owner approves does not change unless the key itself is rotated.

use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use base64::Engine as _;
use ed25519_dalek::{SigningKey, VerifyingKey, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH};
use sha2::{Digest, Sha256};

use crate::session::SessionPaths;

/// Algorithm label used in fingerprints and key identifiers.
pub const KEY_ALG: &str = "ed25519";

/// Prefix for the key identifier (`mxagent-ed25519:<fingerprint>`).
pub const KEY_ID_PREFIX: &str = "mxagent-ed25519";

/// Errors that can occur while managing the daemon signing key.
#[derive(Debug)]
pub enum SigningKeyError {
    /// An I/O error while reading or writing the key file.
    Io(io::Error),
    /// The stored key file is malformed (wrong length).
    Malformed,
    /// Generating randomness for a fresh key failed.
    Random(getrandom::Error),
}

impl fmt::Display for SigningKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "signing key I/O error: {e}"),
            Self::Malformed => write!(f, "stored signing key is malformed"),
            Self::Random(e) => write!(f, "could not generate signing key: {e}"),
        }
    }
}

impl std::error::Error for SigningKeyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Random(e) => Some(e),
            Self::Malformed => None,
        }
    }
}

impl From<io::Error> for SigningKeyError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// The daemon's Ed25519 signing key plus its derived public identity.
///
/// The private key material is held in [`SigningKey`], which zeroizes on drop.
/// `Debug` is implemented manually so the secret bytes are never printed.
pub struct DaemonSigningKey {
    signing_key: SigningKey,
}

impl fmt::Debug for DaemonSigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DaemonSigningKey")
            .field("fingerprint", &self.fingerprint())
            .finish_non_exhaustive()
    }
}

impl DaemonSigningKey {
    /// The verifying (public) key.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Borrow the underlying signing key for signing operations.
    ///
    /// Callers must not log or persist the returned key's secret bytes.
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    /// The public-key fingerprint, formatted `SHA256:<base64>` (OpenSSH style,
    /// using unpadded standard base64 of the SHA-256 of the public key bytes).
    ///
    /// This value is deterministic for a given key and therefore stable across
    /// daemon restarts.
    pub fn fingerprint(&self) -> String {
        fingerprint_of(&self.verifying_key())
    }

    /// The stable key identifier (`mxagent-ed25519:<base64-fingerprint>`).
    pub fn key_id(&self) -> String {
        key_id_for_verifying_key(&self.verifying_key())
    }

    /// Base64-no-pad encoding of the Ed25519 verifying key bytes.
    pub fn public_key_b64(&self) -> String {
        encode_verifying_key(&self.verifying_key())
    }
}

/// Compute the stable key identifier for a verifying key.
pub fn key_id_for_verifying_key(key: &VerifyingKey) -> String {
    let digest = Sha256::digest(key.as_bytes());
    let b64 = base64::engine::general_purpose::STANDARD_NO_PAD.encode(digest);
    format!("{KEY_ID_PREFIX}:{b64}")
}

/// Base64-no-pad encode raw Ed25519 verifying-key bytes for Matrix state.
pub fn encode_verifying_key(key: &VerifyingKey) -> String {
    base64::engine::general_purpose::STANDARD_NO_PAD.encode(key.as_bytes())
}

/// Decode a Matrix-published Ed25519 verifying key.
pub fn decode_verifying_key(encoded: &str) -> Result<VerifyingKey, SigningKeyError> {
    let bytes = base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(encoded.as_bytes())
        .map_err(|_| SigningKeyError::Malformed)?;
    let raw: [u8; PUBLIC_KEY_LENGTH] = bytes.try_into().map_err(|_| SigningKeyError::Malformed)?;
    VerifyingKey::from_bytes(&raw).map_err(|_| SigningKeyError::Malformed)
}

/// Compute the `SHA256:<base64>` fingerprint of a verifying key.
fn fingerprint_of(key: &VerifyingKey) -> String {
    let digest = Sha256::digest(key.as_bytes());
    let b64 = base64::engine::general_purpose::STANDARD_NO_PAD.encode(digest);
    format!("SHA256:{b64}")
}

/// The path to the persisted signing key file.
fn signing_key_file(paths: &SessionPaths) -> PathBuf {
    paths.data_dir.join("signing_key.ed25519")
}

/// Load the daemon signing key, generating and persisting one on first run.
///
/// The key file is created with `0600` permissions inside the daemon-owned data
/// directory (itself `0700`), so the private key is never world-readable. On
/// subsequent calls the same key is loaded from disk, keeping the public
/// fingerprint stable across restarts.
pub fn load_or_create_signing_key(
    paths: &SessionPaths,
) -> Result<DaemonSigningKey, SigningKeyError> {
    let file = signing_key_file(paths);
    match fs::read(&file) {
        Ok(bytes) => {
            let secret: [u8; SECRET_KEY_LENGTH] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| SigningKeyError::Malformed)?;
            Ok(DaemonSigningKey {
                signing_key: SigningKey::from_bytes(&secret),
            })
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => generate_and_store(paths),
        Err(e) => Err(SigningKeyError::Io(e)),
    }
}

/// Generate a fresh Ed25519 key and persist it atomically with `0600` perms.
///
/// Runs under the data-dir cross-process advisory write lock and **re-checks**
/// the key file once the lock is held, so two concurrent creators (e.g. a
/// CLI-local `trust fingerprint` racing a running daemon's first signing
/// operation) converge on a single key instead of one clobbering the other
/// (issue #269). The common reload path in [`load_or_create_signing_key`] stays
/// lock-free.
fn generate_and_store(paths: &SessionPaths) -> Result<DaemonSigningKey, SigningKeyError> {
    crate::session::with_data_dir_write_lock(paths, || {
        let file = signing_key_file(paths);

        // Double-checked under the lock: another process may have generated the
        // key between our caller's lock-free read and our acquiring the lock.
        match fs::read(&file) {
            Ok(bytes) => {
                let secret: [u8; SECRET_KEY_LENGTH] = bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| SigningKeyError::Malformed)?;
                return Ok(DaemonSigningKey {
                    signing_key: SigningKey::from_bytes(&secret),
                });
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(SigningKeyError::Io(e)),
        }

        let mut secret = [0u8; SECRET_KEY_LENGTH];
        getrandom::fill(&mut secret).map_err(SigningKeyError::Random)?;
        let signing_key = SigningKey::from_bytes(&secret);

        let tmp = file.with_extension("ed25519.tmp");
        {
            let mut f = fs::File::create(&tmp)?;
            f.set_permissions(fs::Permissions::from_mode(0o600))?;
            f.write_all(&secret)?;
            f.flush()?;
        }
        fs::rename(&tmp, &file)?;

        tracing::info!(
            fingerprint = %fingerprint_of(&signing_key.verifying_key()),
            "generated daemon signing key"
        );

        Ok(DaemonSigningKey { signing_key })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, MutexGuard, OnceLock};

    fn env_lock() -> MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    struct TempData {
        dir: PathBuf,
        _guard: MutexGuard<'static, ()>,
    }

    impl TempData {
        fn new(tag: &str) -> Self {
            let guard = env_lock();
            let dir = std::env::temp_dir().join(format!(
                "mx-agent-signing-{}-{}-{}",
                tag,
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::env::set_var(crate::session::ENV_DATA_DIR, &dir);
            Self { dir, _guard: guard }
        }
    }

    impl Drop for TempData {
        fn drop(&mut self) {
            std::env::remove_var(crate::session::ENV_DATA_DIR);
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    #[test]
    fn generates_key_on_first_run() {
        let _data = TempData::new("create");
        let paths = SessionPaths::resolve();
        assert!(!signing_key_file(&paths).exists());
        let key = load_or_create_signing_key(&paths).unwrap();
        assert!(signing_key_file(&paths).exists());
        assert!(key.fingerprint().starts_with("SHA256:"));
        assert!(key.key_id().starts_with("mxagent-ed25519:"));
    }

    #[test]
    fn fingerprint_is_stable_across_restarts() {
        let _data = TempData::new("stable");
        let paths = SessionPaths::resolve();
        let first = load_or_create_signing_key(&paths).unwrap().fingerprint();
        // Simulate a restart: reload from disk afresh.
        let second = load_or_create_signing_key(&paths).unwrap().fingerprint();
        assert_eq!(first, second, "fingerprint must be stable across restarts");
    }

    #[test]
    fn private_key_is_not_world_readable() {
        let _data = TempData::new("perms");
        let paths = SessionPaths::resolve();
        load_or_create_signing_key(&paths).unwrap();
        let mode = fs::metadata(signing_key_file(&paths))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "signing key must be private");
        assert_eq!(
            mode & 0o077,
            0,
            "signing key must not be group/world readable"
        );
    }

    #[test]
    fn debug_does_not_leak_secret_bytes() {
        let _data = TempData::new("debug");
        let paths = SessionPaths::resolve();
        let key = load_or_create_signing_key(&paths).unwrap();
        let secret_bytes = key.signing_key().to_bytes();
        let debug = format!("{key:?}");
        // The fingerprint is fine to show; raw secret bytes are not.
        assert!(debug.contains("fingerprint"));
        assert!(!debug.contains(&format!("{:?}", secret_bytes.to_vec())));
    }

    #[test]
    fn malformed_key_file_is_rejected() {
        let _data = TempData::new("malformed");
        let paths = SessionPaths::resolve();
        paths.ensure_data_dir().unwrap();
        fs::write(signing_key_file(&paths), b"too-short").unwrap();
        assert!(matches!(
            load_or_create_signing_key(&paths),
            Err(SigningKeyError::Malformed)
        ));
    }

    #[test]
    fn concurrent_signing_key_creation_converges() {
        // Issue #269: two concurrent creators (e.g. a CLI-local `trust
        // fingerprint` racing the daemon's first signing op) must converge on a
        // single key under the data-dir advisory lock, never clobber each other.
        // Uses `for_data_dir` (no env mutation) so the threads share one dir.
        use std::sync::{Arc, Barrier};

        let dir = std::env::temp_dir().join(format!(
            "mx-agent-signing-race-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let paths = Arc::new(SessionPaths::for_data_dir(dir.clone()));
        paths.ensure_data_dir().unwrap();

        let barrier = Arc::new(Barrier::new(2));
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let paths = Arc::clone(&paths);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    load_or_create_signing_key(&paths).unwrap().fingerprint()
                })
            })
            .collect();
        let prints: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

        assert_eq!(
            prints[0], prints[1],
            "both threads must converge on one signing key fingerprint"
        );
        // Exactly one key file exists and reloads to the same fingerprint.
        let reloaded = load_or_create_signing_key(&paths).unwrap().fingerprint();
        assert_eq!(reloaded, prints[0]);

        let _ = fs::remove_dir_all(&dir);
    }

    // ── Issue #269: signing-key helper regression tests ────────────────────────

    /// `encode_verifying_key` and `decode_verifying_key` must be exact inverses:
    /// encoding a key then decoding it must yield the identical public key bytes.
    /// This exercises the base64-no-pad codec used when publishing and verifying
    /// trust records (issue #269: the helpers are exercised by CLI-local `trust
    /// fingerprint`, which may create the key in-process).
    #[test]
    fn encode_decode_verifying_key_roundtrips() {
        let _data = TempData::new("roundtrip");
        let paths = crate::session::SessionPaths::resolve();
        let key = load_or_create_signing_key(&paths).unwrap();
        let encoded = encode_verifying_key(&key.verifying_key());
        let decoded = decode_verifying_key(&encoded).unwrap();
        assert_eq!(
            decoded.as_bytes(),
            key.verifying_key().as_bytes(),
            "decoded verifying key must match the original"
        );
    }

    /// `decode_verifying_key` must return `Malformed` for clearly invalid input:
    /// non-base64 characters and base64 strings that decode to the wrong number
    /// of bytes. This prevents silent acceptance of corrupt or attacker-supplied
    /// key material in trust records.
    #[test]
    fn decode_verifying_key_rejects_invalid_inputs() {
        // Non-base64 characters.
        assert!(
            matches!(
                decode_verifying_key("!not-base64"),
                Err(SigningKeyError::Malformed)
            ),
            "non-base64 input must be Malformed"
        );
        // Valid base64 but decodes to only 3 bytes, not 32.
        assert!(
            matches!(
                decode_verifying_key("AAAA"),
                Err(SigningKeyError::Malformed)
            ),
            "too-short base64 must be Malformed"
        );
        // Empty string.
        assert!(
            matches!(decode_verifying_key(""), Err(SigningKeyError::Malformed)),
            "empty input must be Malformed"
        );
    }

    /// The key identifier returned by `key_id()` must start with `KEY_ID_PREFIX`
    /// followed by a colon and a non-empty base64 string (SHA-256 of the 32-byte
    /// public key encodes to exactly 43 base64-no-pad characters).
    #[test]
    fn key_id_format_matches_expected_structure() {
        let _data = TempData::new("keyidfmt");
        let paths = crate::session::SessionPaths::resolve();
        let key = load_or_create_signing_key(&paths).unwrap();
        let key_id = key.key_id();
        // Must begin with the well-known prefix constant.
        assert!(
            key_id.starts_with(KEY_ID_PREFIX),
            "key ID must start with {KEY_ID_PREFIX}, got {key_id}"
        );
        // Must contain exactly one colon separating prefix from the fingerprint.
        let parts: Vec<&str> = key_id.splitn(2, ':').collect();
        assert_eq!(parts.len(), 2, "key ID must contain a colon separator");
        let fp_part = parts[1];
        assert!(
            !fp_part.is_empty(),
            "key ID fingerprint part must not be empty"
        );
        // SHA-256 of 32 public-key bytes is 32 bytes, which base64-no-pad encodes
        // to ceil(32 * 4 / 3) = 43 characters.
        assert_eq!(
            fp_part.len(),
            43,
            "key ID fingerprint part must be 43 base64-no-pad characters (SHA-256 of 32 bytes)"
        );
        // The fingerprint must also appear in the full fingerprint string.
        let fingerprint = key.fingerprint();
        assert!(
            fingerprint.starts_with("SHA256:"),
            "fingerprint must start with SHA256:"
        );
        assert_eq!(
            &fingerprint["SHA256:".len()..],
            fp_part,
            "key ID fingerprint component must match the SHA256 fingerprint suffix"
        );
    }

    /// `public_key_b64` must produce a string that `decode_verifying_key` accepts
    /// and that roundtrips back to the same key — validating the end-to-end codec
    /// used for Matrix trust-state publication.
    #[test]
    fn public_key_b64_is_decodable() {
        let _data = TempData::new("pubkeyb64");
        let paths = crate::session::SessionPaths::resolve();
        let key = load_or_create_signing_key(&paths).unwrap();
        let b64 = key.public_key_b64();
        let decoded = decode_verifying_key(&b64)
            .expect("public_key_b64 must produce input that decode_verifying_key accepts");
        assert_eq!(
            decoded.as_bytes(),
            key.verifying_key().as_bytes(),
            "public_key_b64 roundtrip must recover the original verifying key"
        );
    }
}
