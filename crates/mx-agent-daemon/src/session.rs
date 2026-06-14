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
use std::path::{Path, PathBuf};

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
    /// Advisory write-lock file (`<data_dir>/.write.lock`, `0600`). Held with
    /// `flock(LOCK_EX)` to serialize cross-process writes to the session,
    /// crypto-store key, and signing key so a CLI-local `auth login` /
    /// `trust fingerprint` cannot lost-update a running daemon's data dir
    /// (issue #269). The file stores no data and is never part of any protocol.
    pub lock_file: PathBuf,
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
            lock_file: data_dir.join(".write.lock"),
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
    ///
    /// Runs under the cross-process advisory write lock and **re-checks** the key
    /// file once the lock is held: if a concurrent writer (e.g. a running daemon
    /// racing a CLI-local `auth login`) created the key first, its passphrase is
    /// returned unchanged instead of being clobbered. This is the damaging race
    /// to avoid — a lost crypto-store passphrase can no longer decrypt a store
    /// already encrypted under it (issue #269). The steady-state read path in
    /// [`load_or_create_crypto_store_key`](Self::load_or_create_crypto_store_key)
    /// stays lock-free.
    fn generate_crypto_store_key(&self) -> io::Result<Secret> {
        use base64::Engine as _;
        with_data_dir_write_lock(self, || {
            // Double-checked under the lock: another process may have created the
            // key between our caller's lock-free read and our acquiring the lock.
            match fs::read_to_string(&self.crypto_store_key_file) {
                Ok(contents) => {
                    let trimmed = contents.trim();
                    if !trimmed.is_empty() {
                        return Ok(Secret::new(trimmed.to_string()));
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
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
        })
    }
}

/// Hold a cross-process advisory exclusive lock for the duration of a write to
/// the daemon-owned data dir (session, crypto-store key, signing key).
///
/// The lock is `flock(LOCK_EX)` on `<data_dir>/.write.lock` (created `0600`). It
/// serializes a CLI-local `auth login` / `trust fingerprint` against a running
/// daemon so two `mx-agent` processes cannot lost-update the same key/session
/// file (issue #269). The lock is **advisory** and Unix-only — it coordinates
/// only mx-agent's own writers — and is released when the guard drops as `f`
/// returns (or errors). Callers must hold it only around infrequent create/write
/// paths, never the hot read path, and must not nest acquisitions.
///
/// Generic over the closure's error type so the same helper guards both the
/// `io::Result` session/crypto-store writers and the [`SigningKeyError`]-typed
/// signing-key writer; any I/O error acquiring the lock is surfaced through
/// `E: From<io::Error>`.
///
/// [`SigningKeyError`]: crate::signing::SigningKeyError
pub(crate) fn with_data_dir_write_lock<T, E>(
    paths: &SessionPaths,
    f: impl FnOnce() -> Result<T, E>,
) -> Result<T, E>
where
    E: From<io::Error>,
{
    use nix::fcntl::{Flock, FlockArg};
    use std::os::unix::fs::OpenOptionsExt;

    paths.ensure_data_dir()?;
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(&paths.lock_file)?;
    let guard = Flock::lock(file, FlockArg::LockExclusive)
        .map_err(|(_file, errno)| io::Error::from_raw_os_error(errno as i32))?;
    let result = f();
    drop(guard); // release the advisory lock before returning
    result
}

/// Persist `session` to daemon-owned storage with `0600` permissions.
///
/// The write is atomic (write-to-temp then rename) so a crash cannot leave a
/// half-written session file, and it runs under the cross-process advisory write
/// lock so a CLI-local `auth login` cannot interleave its session write with a
/// running daemon's (issue #269).
pub fn save_session(paths: &SessionPaths, session: &StoredSession) -> io::Result<()> {
    with_data_dir_write_lock(paths, || write_session_file(paths, session))
}

/// Atomically write `session.json` (`0600`) **without** taking the advisory
/// lock.
///
/// Factored out of [`save_session`] so callers that already hold the data-dir
/// write lock — [`persist_login_session`] — can persist the session without a
/// nested `flock` acquisition (which would self-deadlock against the same
/// process's outer lock). Assumes the data dir already exists (the lock helper
/// ensures it).
fn write_session_file(paths: &SessionPaths, session: &StoredSession) -> io::Result<()> {
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

/// Persist a freshly-minted login session, clearing the stale sync token and
/// reclaiming a superseded same-user device store when the session identity
/// changes (issue #316).
///
/// Runs the whole load-compare-write round trip under the data-dir advisory
/// write lock so it serializes against [`save_session`], [`clear_session`], and
/// crypto-store-key generation. Behaviour:
///
/// - If there is no prior session, or its `(user_id, device_id)` differs from
///   `session`, the persisted `/sync` batch token is cleared so the new device
///   performs an initial full sync rather than resuming from the previous
///   session's batch (which would skip room state and miss invites — and would
///   even carry across a different account on one data dir). Because every real
///   login mints a brand-new `device_id`, this clears the token on essentially
///   every login while staying correct if the identical identity is re-saved.
/// - If a prior session existed for the **same `user_id`** but a **different
///   `device_id`**, that specific superseded device crypto store is removed
///   (guarded by [`is_plain_path_component`]). This reclaims only the previous
///   device of the *same account*; a concurrent *different* user's store (the
///   multi-user integration-test layout) is never touched.
/// - Any other device-store directories that match neither the new device are
///   only **warned** about (count + device-id stems, no secrets) so an operator
///   can reclaim them deliberately rather than risk clobbering another user.
pub fn persist_login_session(paths: &SessionPaths, session: &StoredSession) -> io::Result<()> {
    with_data_dir_write_lock(paths, || {
        let prior = load_session(paths)?;
        let identity_changed = match &prior {
            Some(p) => p.user_id != session.user_id || p.device_id != session.device_id,
            None => true,
        };
        if identity_changed {
            clear_sync_token(paths)?;
        }
        // Reclaim the superseded device store of the *same* user only.
        if let Some(prior) = &prior {
            if prior.user_id == session.user_id
                && prior.device_id != session.device_id
                && is_plain_path_component(&prior.device_id)
            {
                remove_dir_if_present(&paths.data_dir.join(&prior.device_id))?;
            }
        }
        warn_stranded_device_stores(paths, &session.device_id);
        write_session_file(paths, session)
    })
}

/// Log (non-sensitively) about per-device crypto stores that belong to neither
/// the new session's device nor the legacy flat layout, so an operator can
/// reclaim them deliberately (issue #316).
///
/// Deliberately warn-only rather than auto-deleting: device-id subdirectories
/// may belong to *different users* sharing one data dir (the Alice+Bob
/// integration-test layout), and a blanket "remove every dir that is not the new
/// device" would clobber a concurrent user's store. Only the superseded device
/// of the *same* account is auto-reclaimed (see [`persist_login_session`]). The
/// `.login-*` temp dirs, the legacy flat `crypto-store/`, the lock file, and
/// `trust.json` are never reported.
fn warn_stranded_device_stores(paths: &SessionPaths, new_device_id: &str) {
    let Ok(entries) = fs::read_dir(&paths.data_dir) else {
        return;
    };
    let mut stems: Vec<String> = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if name == new_device_id
            || name == "crypto-store"
            || name.starts_with(".login-")
            || !is_plain_path_component(name)
        {
            continue;
        }
        // Only count directories that actually hold a per-device crypto store.
        if entry.path().join("crypto-store").is_dir() {
            stems.push(name.to_string());
        }
    }
    if !stems.is_empty() {
        tracing::warn!(
            count = stems.len(),
            devices = ?stems,
            "stranded per-device crypto stores remain under the data dir; \
             reclaim them deliberately if they belong to no active session"
        );
    }
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

/// Remove the persisted session and the daemon's E2EE crypto store (logout).
///
/// Deletes the access token (`session.json`) **and** the persistent crypto
/// store so logging out actually relinquishes the daemon's E2EE device identity
/// and Megolm sessions instead of leaving them on disk for a later login to
/// reuse (issue #240). The crypto store lives in a subdirectory named by the
/// session's device id (see [`crate::matrix::login_password`] /
/// [`crate::matrix::restore_client`]); the session is read first to locate it,
/// and the legacy flat-layout store (`crypto-store/` directly under the data
/// dir) is cleared too, as is the persisted `/sync` batch token so a later login
/// (a brand-new device) performs an initial full sync rather than resuming from
/// the old session's batch (issue #316). Missing files are not an error, so
/// logout is idempotent.
///
/// The whole removal runs under the data-dir advisory write lock so a logout
/// racing a concurrent `auth login` ([`save_session`] / [`persist_login_session`])
/// cannot interleave and strand a half-written crypto store after a "successful"
/// logout (issue #316).
pub fn clear_session(paths: &SessionPaths) -> io::Result<()> {
    with_data_dir_write_lock(paths, || {
        // Remove the device-specific crypto store before deleting the session
        // that names it. A device id that is not a single path component is
        // ignored so the recursive removal can never escape the data directory
        // (the id is server-assigned and otherwise untrusted).
        if let Ok(Some(session)) = load_session(paths) {
            if is_plain_path_component(&session.device_id) {
                remove_dir_if_present(&paths.data_dir.join(&session.device_id))?;
            }
        }
        // Legacy single-user flat layout (crypto store directly under the data dir).
        remove_dir_if_present(&paths.crypto_store_dir)?;
        remove_file_if_present(&paths.crypto_store_key_file)?;
        remove_file_if_present(&paths.session_file)?;
        // Drop the persisted batch token too (issue #316).
        clear_sync_token(paths)
    })
}

/// Recursively remove a directory, treating "already gone" as success.
fn remove_dir_if_present(dir: &Path) -> io::Result<()> {
    match fs::remove_dir_all(dir) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Remove a file, treating "already gone" as success.
fn remove_file_if_present(file: &Path) -> io::Result<()> {
    match fs::remove_file(file) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Whether `name` is a single, non-escaping path component, safe to `join` onto
/// the data dir and recursively remove. Rejects empty, `.`/`..`, and any value
/// containing a path separator so a hostile device id cannot direct the
/// crypto-store removal outside the data dir.
fn is_plain_path_component(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && !name.contains('/')
        && !name.contains('\\')
        && !name.contains('\0')
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

    #[test]
    fn clear_session_removes_crypto_store() {
        // Issue #240: logout must wipe the persistent crypto store, not just the
        // access token, so the daemon's E2EE device identity and Megolm sessions
        // do not linger on disk for a later login to reuse.
        let _data = TempData::new("clear-crypto");
        let paths = SessionPaths::resolve();
        let session = sample();
        save_session(&paths, &session).unwrap();

        // Device-specific store (current layout) plus a legacy flat-layout store.
        let device_dir = paths.data_dir.join(&session.device_id);
        fs::create_dir_all(device_dir.join("crypto-store")).unwrap();
        fs::write(device_dir.join("crypto-store-key"), b"key").unwrap();
        fs::create_dir_all(&paths.crypto_store_dir).unwrap();
        fs::write(&paths.crypto_store_key_file, b"key").unwrap();

        clear_session(&paths).unwrap();

        assert!(load_session(&paths).unwrap().is_none(), "session cleared");
        assert!(!device_dir.exists(), "device crypto store removed");
        assert!(
            !paths.crypto_store_dir.exists(),
            "legacy crypto store removed"
        );
        assert!(
            !paths.crypto_store_key_file.exists(),
            "legacy crypto store key removed"
        );
    }

    #[test]
    fn clear_session_removes_sync_token() {
        // Issue #316: logout must also drop the persisted /sync batch token so a
        // later login (a brand-new device) performs an initial full sync.
        let paths = SessionPaths::for_data_dir(unique_temp_dir("clear-synctoken"));
        paths.ensure_data_dir().unwrap();
        save_session(&paths, &sample()).unwrap();
        save_sync_token(&paths, "s_batch_token").unwrap();
        clear_session(&paths).unwrap();
        assert!(
            load_sync_token(&paths).unwrap().is_none(),
            "sync token must be cleared on logout"
        );
        assert!(load_session(&paths).unwrap().is_none());
        let _ = fs::remove_dir_all(&paths.data_dir);
    }

    #[test]
    fn persist_login_session_clears_token_on_identity_change() {
        // Issue #316: a re-login with a different device id clears the stale token
        // (forcing an initial full sync); re-saving the identical identity keeps it.
        let paths = SessionPaths::for_data_dir(unique_temp_dir("persist-token"));
        paths.ensure_data_dir().unwrap();
        let mut s1 = sample();
        s1.device_id = "DEV1".to_string();
        persist_login_session(&paths, &s1).unwrap();
        save_sync_token(&paths, "tok").unwrap();
        // Re-saving the same identity preserves the token.
        persist_login_session(&paths, &s1).unwrap();
        assert_eq!(load_sync_token(&paths).unwrap().as_deref(), Some("tok"));
        // A new device (the real-login case) clears it.
        let mut s2 = sample();
        s2.device_id = "DEV2".to_string();
        persist_login_session(&paths, &s2).unwrap();
        assert!(
            load_sync_token(&paths).unwrap().is_none(),
            "identity change must clear the stale sync token"
        );
        let _ = fs::remove_dir_all(&paths.data_dir);
    }

    #[test]
    fn persist_login_session_reclaims_same_user_prior_device_store_only() {
        // Issue #316: re-login as the same user reclaims that user's superseded
        // device store, but a *different* user's store (multi-user test layout)
        // is never touched.
        let paths = SessionPaths::for_data_dir(unique_temp_dir("persist-stores"));
        paths.ensure_data_dir().unwrap();
        let mut alice1 = sample(); // @alice:matrix.org
        alice1.device_id = "ALICEDEV1".to_string();
        persist_login_session(&paths, &alice1).unwrap();
        // Seed alice's current device store and a different user's store.
        fs::create_dir_all(paths.data_dir.join("ALICEDEV1").join("crypto-store")).unwrap();
        let bob_store = paths.data_dir.join("BOBDEV").join("crypto-store");
        fs::create_dir_all(&bob_store).unwrap();
        // Alice logs in on a new device.
        let mut alice2 = sample();
        alice2.device_id = "ALICEDEV2".to_string();
        persist_login_session(&paths, &alice2).unwrap();
        assert!(
            !paths.data_dir.join("ALICEDEV1").exists(),
            "superseded same-user device store must be removed"
        );
        assert!(
            bob_store.exists(),
            "a different user's store must be preserved"
        );
        let _ = fs::remove_dir_all(&paths.data_dir);
    }

    #[test]
    fn is_plain_path_component_rejects_traversal() {
        // A hostile or garbage device id must never escape the data dir when its
        // crypto store is removed on logout (issue #240).
        assert!(is_plain_path_component("MXAGENTDEVICE01"));
        for bad in ["", ".", "..", "../evil", "a/b", "a\\b", "x\0y"] {
            assert!(!is_plain_path_component(bad), "must reject {bad:?}");
        }
    }

    /// A unique, per-call data dir resolved via [`SessionPaths::for_data_dir`].
    ///
    /// The concurrency tests deliberately avoid the `MX_AGENT_DATA_DIR` env var
    /// (and so the `env_lock()`) because they spawn threads that must share one
    /// explicit data dir; mutating process env from multiple threads is the very
    /// thing those tests must not depend on.
    fn unique_temp_dir(tag: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "mx-agent-lock-{}-{}-{}-{}",
            tag,
            std::process::id(),
            n,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    /// `clear_session` racing `save_session` must always leave the store in a
    /// consistent (parseable) state — never a torn partial file — because both
    /// hold the data-dir advisory write lock (issue #316).
    #[test]
    fn concurrent_clear_session_and_save_session_is_consistent() {
        use std::sync::{Arc, Barrier};

        let dir = unique_temp_dir("clear-save-race");
        let paths = SessionPaths::for_data_dir(dir.clone());
        paths.ensure_data_dir().unwrap();

        let session = sample();

        // Seed initial session and token so clear_session has something to remove.
        save_session(&paths, &session).unwrap();
        save_sync_token(&paths, "token_before_race").unwrap();

        let barrier = Arc::new(Barrier::new(2));

        let p_clear = paths.clone();
        let b_clear = Arc::clone(&barrier);
        let clearer = std::thread::spawn(move || {
            b_clear.wait();
            for _ in 0..30 {
                // clear_session is idempotent; safe to call even when no session.
                clear_session(&p_clear).unwrap();
            }
        });

        let p_save = paths.clone();
        let b_save = Arc::clone(&barrier);
        let session_copy = session.clone();
        let saver = std::thread::spawn(move || {
            b_save.wait();
            for _ in 0..30 {
                save_session(&p_save, &session_copy).unwrap();
            }
        });

        clearer.join().unwrap();
        saver.join().unwrap();

        // The final state must be consistent: parseable as either "logged in"
        // or "logged out", never torn JSON, and the two are mutually consistent.
        let status = auth_status(&paths).unwrap();
        if status.logged_in {
            assert!(
                status.user_id.is_some() && status.device_id.is_some(),
                "logged-in status must have user_id and device_id"
            );
        } else {
            assert!(
                status.user_id.is_none() && status.device_id.is_none(),
                "logged-out status must have neither user_id nor device_id"
            );
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn concurrent_crypto_store_key_creation_converges() {
        // Issue #269: two processes that both observe "key absent" must not
        // lost-update the crypto-store passphrase. The advisory lock + the
        // double-checked create make them converge on one key. Each thread opens
        // its own flock fd (the helper opens the lock file per call), so the two
        // in-process callers genuinely serialize.
        use std::sync::{Arc, Barrier};

        let dir = unique_temp_dir("cryptorace");
        let paths = Arc::new(SessionPaths::for_data_dir(dir.clone()));
        paths.ensure_data_dir().unwrap();

        let barrier = Arc::new(Barrier::new(2));
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let paths = Arc::clone(&paths);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    paths.load_or_create_crypto_store_key().unwrap()
                })
            })
            .collect();
        let keys: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

        assert_eq!(
            keys[0].expose(),
            keys[1].expose(),
            "both threads must observe the same passphrase (no lost update)"
        );
        // Exactly one key file, holding exactly the returned passphrase.
        let on_disk = fs::read_to_string(&paths.crypto_store_key_file).unwrap();
        assert_eq!(on_disk.trim(), keys[0].expose());
        let mode = fs::metadata(&paths.crypto_store_key_file)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "crypto store key file must stay private");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn concurrent_save_session_never_tears() {
        // Issue #269: concurrent session writers must serialize so the file
        // always parses to one complete session, never torn JSON (both writers
        // share the same `session.json.tmp` path, which the lock protects).
        use std::sync::{Arc, Barrier};

        let dir = unique_temp_dir("saverace");
        let paths = Arc::new(SessionPaths::for_data_dir(dir.clone()));
        paths.ensure_data_dir().unwrap();

        let mut a = sample();
        a.user_id = "@a:matrix.org".to_string();
        let mut b = sample();
        b.user_id = "@b:matrix.org".to_string();

        let barrier = Arc::new(Barrier::new(2));
        let handles: Vec<_> = [a.clone(), b.clone()]
            .into_iter()
            .map(|session| {
                let paths = Arc::clone(&paths);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    for _ in 0..50 {
                        save_session(&paths, &session).unwrap();
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }

        // The final file must parse to one of the two complete sessions.
        let loaded = load_session(&paths).unwrap().expect("a session persists");
        assert!(
            loaded == a || loaded == b,
            "final session must be one of the two complete writes, got {loaded:?}"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    // ── Issue #269: advisory lock + permissions regression tests ──────────────

    /// `for_data_dir` must include the advisory lock file path inside the
    /// data dir so `with_data_dir_write_lock` writes it to the right location
    /// (issue #269: the lock file was introduced to serialise cross-process
    /// session/key writes).
    #[test]
    fn session_paths_lock_file_is_in_data_dir() {
        let dir = unique_temp_dir("lockpath");
        let paths = SessionPaths::for_data_dir(dir.clone());
        assert_eq!(
            paths.lock_file,
            dir.join(".write.lock"),
            "lock_file must be <data_dir>/.write.lock"
        );
        // The lock file must be distinct from the session and key files so
        // the rename-over-tmp pattern used by save_session /
        // generate_crypto_store_key cannot accidentally clobber it.
        assert_ne!(paths.lock_file, paths.session_file);
        assert_ne!(paths.lock_file, paths.crypto_store_key_file);
    }

    /// After `with_data_dir_write_lock` is called, the advisory lock file must
    /// exist with `0600` permissions — the same restrictive mode as every other
    /// daemon-owned private file (issue #269).
    #[test]
    fn write_lock_file_has_private_permissions() {
        let _data = TempData::new("lockperms");
        let paths = SessionPaths::resolve();
        // Drive the lock helper to ensure the lock file is created on disk.
        with_data_dir_write_lock::<(), io::Error>(&paths, || Ok(())).unwrap();
        assert!(
            paths.lock_file.exists(),
            "lock file must exist after acquiring the lock"
        );
        let mode = fs::metadata(&paths.lock_file).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "advisory lock file must be private (0600)");
    }

    /// `ensure_data_dir` must create the data directory with `0700`
    /// permissions so the entire directory is inaccessible to other users,
    /// matching the daemon-owned storage model (issue #269).
    #[test]
    fn data_dir_has_private_permissions() {
        let _data = TempData::new("datadirperms");
        let paths = SessionPaths::resolve();
        assert!(
            !paths.data_dir.exists(),
            "data dir must not pre-exist in a fresh temp environment"
        );
        paths.ensure_data_dir().unwrap();
        let mode = fs::metadata(&paths.data_dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "data dir must be owner-only (0700)");
    }

    /// If the crypto-store key file exists but is empty (e.g. the process was
    /// killed between `File::create` and the first write), the loader must
    /// detect the empty content and regenerate a valid key rather than
    /// returning an empty `Secret` (issue #269: a zero-length passphrase
    /// cannot decrypt the store encrypted under the real key).
    #[test]
    fn empty_crypto_store_key_file_is_regenerated() {
        let _data = TempData::new("emptykey");
        let paths = SessionPaths::resolve();
        paths.ensure_data_dir().unwrap();
        // Simulate a truncated write by placing an empty file at the key path.
        fs::write(&paths.crypto_store_key_file, b"").unwrap();
        // The loader must detect the empty file and generate a new key.
        let key = paths.load_or_create_crypto_store_key().unwrap();
        assert!(
            !key.expose().is_empty(),
            "must generate a non-empty key when the key file is empty"
        );
        // The on-disk key file must now contain the newly generated passphrase.
        let on_disk = fs::read_to_string(&paths.crypto_store_key_file).unwrap();
        assert_eq!(
            on_disk.trim(),
            key.expose(),
            "regenerated key must match what was written to disk"
        );
        // The key file must have been replaced with the correct private permissions.
        let mode = fs::metadata(&paths.crypto_store_key_file)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "regenerated key file must be private (0600)");
    }
}
