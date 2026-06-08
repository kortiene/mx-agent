//! Matrix session persistence in daemon-owned storage.
//!
//! The daemon owns the long-lived Matrix session (see `docs/architecture.md`,
//! sections 10.1 and 13.1). After a successful login the session — including
//! the access token — is written to a private, `0600` file under the user's
//! data directory so that authentication survives a daemon restart.
//!
//! Access and refresh tokens are wrapped in [`Secret`], whose `Debug`/`Display`
//! implementations redact the value. The token is therefore never printed by
//! status output or debug logging; only the user ID, device ID, and homeserver
//! are ever surfaced (see [`AuthStatus`]).

use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Environment variable overriding the data directory (useful for tests).
pub const ENV_DATA_DIR: &str = "MX_AGENT_DATA_DIR";

/// Placeholder rendered in place of a secret value.
pub const REDACTED: &str = "***redacted***";

/// A secret string (e.g. an access token) that never reveals itself through
/// `Debug` or `Display`.
///
/// The inner value is serialized transparently so it can be persisted, but it
/// is redacted in every formatting path to keep it out of logs and output.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Secret(String);

impl Secret {
    /// Wrap a secret value.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Borrow the underlying secret. Callers must not log the result.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Secret({REDACTED})")
    }
}

impl fmt::Display for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

/// A persisted Matrix session.
///
/// `Debug` is derived; because the token fields are [`Secret`], debug output
/// (including via `tracing`) redacts them automatically.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct StoredSession {
    /// Homeserver base URL.
    pub homeserver: String,
    /// Full Matrix user ID, e.g. `@alice:matrix.org`.
    pub user_id: String,
    /// Device ID issued at login.
    pub device_id: String,
    /// Access token (redacted in all formatting).
    pub access_token: Secret,
    /// Refresh token, if the server issued one (redacted in all formatting).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<Secret>,
}

/// Non-sensitive authentication status, safe to print or serialize.
///
/// Deliberately has no token field so it cannot leak credentials.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct AuthStatus {
    /// Whether a persisted session exists.
    pub logged_in: bool,
    /// Homeserver base URL, if logged in.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub homeserver: Option<String>,
    /// Matrix user ID, if logged in.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    /// Device ID, if logged in.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
}

impl AuthStatus {
    /// The status for "no persisted session".
    pub fn logged_out() -> Self {
        Self {
            logged_in: false,
            homeserver: None,
            user_id: None,
            device_id: None,
        }
    }

    /// Build a status snapshot from a stored session (without its tokens).
    pub fn from_session(session: &StoredSession) -> Self {
        Self {
            logged_in: true,
            homeserver: Some(session.homeserver.clone()),
            user_id: Some(session.user_id.clone()),
            device_id: Some(session.device_id.clone()),
        }
    }

    /// Render as a single-line JSON object.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{\"logged_in\":false}".to_string())
    }
}

/// Resolved filesystem locations for persisted session state.
#[derive(Debug, Clone)]
pub struct SessionPaths {
    /// Directory holding daemon-owned data.
    pub data_dir: PathBuf,
    /// JSON file storing the Matrix session.
    pub session_file: PathBuf,
    /// Plain-text file storing the latest Matrix `/sync` batch token.
    pub sync_token_file: PathBuf,
    /// Directory holding the persistent, daemon-owned matrix-sdk crypto/state
    /// store (`0700`). It contains device keys and Megolm sessions and is never
    /// agent-readable (architecture §13.1, issue #240).
    pub crypto_store_dir: PathBuf,
    /// File holding the [`Secret`]-wrapped passphrase that encrypts the crypto
    /// store at rest (`0600`). Generated once on first use and reused across
    /// restarts so the daemon resumes as the same E2EE device.
    pub crypto_store_key_file: PathBuf,
}

impl SessionPaths {
    /// Resolve session paths from the environment.
    ///
    /// Precedence: `MX_AGENT_DATA_DIR`, then `$XDG_DATA_HOME/mx-agent`, then
    /// `$HOME/.local/share/mx-agent`, then a temp-directory fallback.
    pub fn resolve() -> Self {
        let data_dir = if let Ok(dir) = std::env::var(ENV_DATA_DIR) {
            PathBuf::from(dir)
        } else if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
            PathBuf::from(xdg).join("mx-agent")
        } else if let Ok(home) = std::env::var("HOME") {
            PathBuf::from(home).join(".local/share/mx-agent")
        } else {
            std::env::temp_dir().join("mx-agent")
        };
        Self::for_data_dir(data_dir)
    }

    /// Resolve all paths rooted at an explicit `data_dir`.
    ///
    /// [`resolve`](Self::resolve) is this applied to the environment-derived data
    /// directory; tests and tooling can build paths under an arbitrary directory.
    pub fn for_data_dir(data_dir: PathBuf) -> Self {
        Self {
            session_file: data_dir.join("session.json"),
            sync_token_file: data_dir.join("sync_token"),
            crypto_store_dir: data_dir.join("crypto-store"),
            crypto_store_key_file: data_dir.join("crypto-store-key"),
            data_dir,
        }
    }

    /// Ensure the data directory exists with `0700` permissions.
    pub fn ensure_data_dir(&self) -> io::Result<()> {
        if !self.data_dir.exists() {
            fs::create_dir_all(&self.data_dir)?;
            fs::set_permissions(&self.data_dir, fs::Permissions::from_mode(0o700))?;
        }
        Ok(())
    }

    /// Ensure the crypto-store directory exists with `0700` permissions.
    ///
    /// The crypto store holds the daemon's Matrix device keys and Megolm
    /// sessions; it is daemon-owned and never readable by the coding agent
    /// (architecture §13.1, issue #240).
    pub fn ensure_crypto_store_dir(&self) -> io::Result<()> {
        self.ensure_data_dir()?;
        if !self.crypto_store_dir.exists() {
            fs::create_dir_all(&self.crypto_store_dir)?;
            fs::set_permissions(&self.crypto_store_dir, fs::Permissions::from_mode(0o700))?;
        }
        Ok(())
    }

    /// Load the crypto-store passphrase, generating and persisting it once on
    /// first use.
    ///
    /// The passphrase encrypts the SQLite crypto store at rest. It is a daemon
    /// secret: wrapped in [`Secret`] so it never appears in logs, written
    /// `0600`, and reused on every restart so the persistent store (and thus the
    /// daemon's E2EE device identity and Megolm sessions) can be reopened. A
    /// fresh 256-bit key is generated with [`getrandom`] and base64-encoded for
    /// storage.
    pub fn load_or_create_crypto_store_key(&self) -> io::Result<Secret> {
        match fs::read_to_string(&self.crypto_store_key_file) {
            Ok(contents) => {
                let trimmed = contents.trim();
                if trimmed.is_empty() {
                    // An empty key file is unusable; regenerate.
                    self.generate_crypto_store_key()
                } else {
                    Ok(Secret::new(trimmed.to_string()))
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => self.generate_crypto_store_key(),
            Err(e) => Err(e),
        }
    }

    /// Generate, persist (`0600`), and return a fresh crypto-store passphrase.
    fn generate_crypto_store_key(&self) -> io::Result<Secret> {
        use base64::Engine as _;
        self.ensure_data_dir()?;
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes)
            .map_err(|e| io::Error::other(format!("getrandom failed: {e}")))?;
        let key = base64::engine::general_purpose::STANDARD_NO_PAD.encode(bytes);
        let tmp = self.crypto_store_key_file.with_extension("tmp");
        {
            let mut f = fs::File::create(&tmp)?;
            f.set_permissions(fs::Permissions::from_mode(0o600))?;
            f.write_all(key.as_bytes())?;
            f.flush()?;
        }
        fs::rename(&tmp, &self.crypto_store_key_file)?;
        Ok(Secret::new(key))
    }
}

/// Persist `session` to daemon-owned storage with `0600` permissions.
///
/// The write is atomic (write-to-temp then rename) so a crash cannot leave a
/// half-written session file.
pub fn save_session(paths: &SessionPaths, session: &StoredSession) -> io::Result<()> {
    paths.ensure_data_dir()?;
    let bytes = serde_json::to_vec_pretty(session)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let tmp = paths.session_file.with_extension("json.tmp");
    {
        let mut f = fs::File::create(&tmp)?;
        f.set_permissions(fs::Permissions::from_mode(0o600))?;
        f.write_all(&bytes)?;
        f.flush()?;
    }
    fs::rename(&tmp, &paths.session_file)?;
    Ok(())
}

/// Load a persisted session, if one exists.
pub fn load_session(paths: &SessionPaths) -> io::Result<Option<StoredSession>> {
    match fs::read(&paths.session_file) {
        Ok(bytes) => {
            let session = serde_json::from_slice(&bytes)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            Ok(Some(session))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Remove any persisted session (logout). Missing files are not an error.
pub fn clear_session(paths: &SessionPaths) -> io::Result<()> {
    match fs::remove_file(&paths.session_file) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Persist the latest Matrix `/sync` batch token to daemon-owned storage.
///
/// The sync token is not a credential, but it is written atomically with
/// `0600` permissions to stay consistent with the rest of the daemon's private
/// state and to survive a crash mid-write.
pub fn save_sync_token(paths: &SessionPaths, token: &str) -> io::Result<()> {
    paths.ensure_data_dir()?;
    let tmp = paths.sync_token_file.with_extension("tmp");
    {
        let mut f = fs::File::create(&tmp)?;
        f.set_permissions(fs::Permissions::from_mode(0o600))?;
        f.write_all(token.as_bytes())?;
        f.flush()?;
    }
    fs::rename(&tmp, &paths.sync_token_file)?;
    Ok(())
}

/// Load the persisted Matrix `/sync` batch token, if one exists.
///
/// Returns `Ok(None)` when no token has been stored yet, so a fresh daemon
/// performs an initial full sync.
pub fn load_sync_token(paths: &SessionPaths) -> io::Result<Option<String>> {
    match fs::read_to_string(&paths.sync_token_file) {
        Ok(token) if token.trim().is_empty() => Ok(None),
        Ok(token) => Ok(Some(token.trim().to_string())),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Remove any persisted sync token. Missing files are not an error.
pub fn clear_sync_token(paths: &SessionPaths) -> io::Result<()> {
    match fs::remove_file(&paths.sync_token_file) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Report the current authentication status from persisted storage.
pub fn auth_status(paths: &SessionPaths) -> io::Result<AuthStatus> {
    Ok(match load_session(paths)? {
        Some(session) => AuthStatus::from_session(&session),
        None => AuthStatus::logged_out(),
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
                "mx-agent-session-{}-{}-{}",
                tag,
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::env::set_var(ENV_DATA_DIR, &dir);
            Self { dir, _guard: guard }
        }
    }

    impl Drop for TempData {
        fn drop(&mut self) {
            std::env::remove_var(ENV_DATA_DIR);
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    fn sample() -> StoredSession {
        StoredSession {
            homeserver: "https://matrix.org/".to_string(),
            user_id: "@alice:matrix.org".to_string(),
            device_id: "MXAGENTDEVICE01".to_string(),
            access_token: Secret::new("syt_supersecret_token_value"),
            refresh_token: Some(Secret::new("refresh_supersecret")),
        }
    }

    #[test]
    fn secret_is_redacted_in_debug_and_display() {
        let s = Secret::new("syt_supersecret_token_value");
        assert_eq!(format!("{s}"), REDACTED);
        assert_eq!(format!("{s:?}"), format!("Secret({REDACTED})"));
        assert!(!format!("{s:?}").contains("supersecret"));
        // The value is still accessible for legitimate use.
        assert_eq!(s.expose(), "syt_supersecret_token_value");
    }

    #[test]
    fn session_debug_redacts_tokens() {
        let session = sample();
        let debug = format!("{session:?}");
        assert!(
            !debug.contains("supersecret"),
            "debug output leaked a token: {debug}"
        );
        assert!(debug.contains("@alice:matrix.org"));
        assert!(debug.contains("MXAGENTDEVICE01"));
    }

    #[test]
    fn session_survives_save_and_reload() {
        let _data = TempData::new("reload");
        let paths = SessionPaths::resolve();
        let session = sample();
        save_session(&paths, &session).unwrap();

        // Simulate a daemon restart by reloading from disk afresh.
        let reloaded = load_session(&paths)
            .unwrap()
            .expect("session should persist");
        assert_eq!(reloaded, session);
        assert_eq!(
            reloaded.access_token.expose(),
            "syt_supersecret_token_value"
        );
    }

    #[test]
    fn session_file_is_private() {
        let _data = TempData::new("perms");
        let paths = SessionPaths::resolve();
        save_session(&paths, &sample()).unwrap();
        let mode = fs::metadata(&paths.session_file)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "session file must be private");
    }

    #[test]
    fn persisted_file_does_not_label_tokens_as_plaintext_status() {
        // The on-disk file legitimately contains the token, but the status
        // surface must never expose it.
        let _data = TempData::new("status");
        let paths = SessionPaths::resolve();
        save_session(&paths, &sample()).unwrap();

        let status = auth_status(&paths).unwrap();
        assert!(status.logged_in);
        assert_eq!(status.user_id.as_deref(), Some("@alice:matrix.org"));
        assert_eq!(status.device_id.as_deref(), Some("MXAGENTDEVICE01"));

        let json = status.to_json();
        assert!(
            !json.contains("supersecret"),
            "status json leaked token: {json}"
        );
        assert!(
            !json.contains("access_token"),
            "status json exposed token field"
        );
        assert!(json.contains("@alice:matrix.org"));
    }

    #[test]
    fn status_is_logged_out_without_session() {
        let _data = TempData::new("logout");
        let paths = SessionPaths::resolve();
        let status = auth_status(&paths).unwrap();
        assert!(!status.logged_in);
        assert_eq!(status.to_json(), "{\"logged_in\":false}");
    }

    #[test]
    fn sync_token_survives_save_and_reload() {
        let _data = TempData::new("synctoken");
        let paths = SessionPaths::resolve();
        assert!(load_sync_token(&paths).unwrap().is_none());
        save_sync_token(&paths, "s_batch_token_123").unwrap();
        // Simulate a restart by reloading from disk.
        assert_eq!(
            load_sync_token(&paths).unwrap().as_deref(),
            Some("s_batch_token_123")
        );
        // A later sync overwrites the token in place.
        save_sync_token(&paths, "s_batch_token_456").unwrap();
        assert_eq!(
            load_sync_token(&paths).unwrap().as_deref(),
            Some("s_batch_token_456")
        );
    }

    #[test]
    fn sync_token_file_is_private() {
        let _data = TempData::new("synctokenperms");
        let paths = SessionPaths::resolve();
        save_sync_token(&paths, "s_batch_token_123").unwrap();
        let mode = fs::metadata(&paths.sync_token_file)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "sync token file must be private");
    }

    #[test]
    fn clear_sync_token_is_idempotent() {
        let _data = TempData::new("synctokenclear");
        let paths = SessionPaths::resolve();
        clear_sync_token(&paths).unwrap(); // no file yet
        save_sync_token(&paths, "s_batch_token_123").unwrap();
        clear_sync_token(&paths).unwrap();
        assert!(load_sync_token(&paths).unwrap().is_none());
    }

    #[test]
    fn crypto_store_key_is_created_private_and_reused() {
        let _data = TempData::new("cryptokey");
        let paths = SessionPaths::resolve();
        // Resolves under the data dir.
        assert_eq!(paths.crypto_store_dir, paths.data_dir.join("crypto-store"));

        let key = paths.load_or_create_crypto_store_key().unwrap();
        assert!(!key.expose().is_empty(), "a key must be generated");

        let mode = fs::metadata(&paths.crypto_store_key_file)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "crypto store key file must be private");

        // A second load returns the same key (so the persistent store reopens
        // and the daemon resumes as the same device after a restart).
        let again = paths.load_or_create_crypto_store_key().unwrap();
        assert_eq!(again.expose(), key.expose());
    }

    #[test]
    fn crypto_store_dir_is_created_private() {
        let _data = TempData::new("cryptodir");
        let paths = SessionPaths::resolve();
        paths.ensure_crypto_store_dir().unwrap();
        let mode = fs::metadata(&paths.crypto_store_dir)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700, "crypto store dir must be private");
    }

    #[test]
    fn clear_session_is_idempotent() {
        let _data = TempData::new("clear");
        let paths = SessionPaths::resolve();
        clear_session(&paths).unwrap(); // no file yet
        save_session(&paths, &sample()).unwrap();
        clear_session(&paths).unwrap();
        assert!(load_session(&paths).unwrap().is_none());
    }
}
