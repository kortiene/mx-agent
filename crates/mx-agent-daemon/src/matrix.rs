//! Matrix client initialization for the daemon.
//!
//! The daemon owns the long-lived Matrix session (see `docs/architecture.md`,
//! section 10.1). This module provides the first step of that ownership:
//! reading the homeserver configuration and constructing a [`matrix_sdk`]
//! [`Client`] from it. No login or network round-trip is performed here; the
//! returned client is unauthenticated and ready for a later auth phase.

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{OnceLock, RwLock};

use matrix_sdk::Client;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::session::{Secret, SessionPaths, StoredSession};

/// Daemon Matrix configuration, typically loaded from `config.toml`.
///
/// ```toml
/// [matrix]
/// homeserver_url = "https://matrix.org"
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatrixConfig {
    /// Base URL of the homeserver, e.g. `https://matrix.org`.
    pub homeserver_url: String,
}

/// Top-level config document wrapper so `[matrix]` tables parse directly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigDocument {
    /// Matrix section.
    pub matrix: MatrixConfig,
}

/// Errors produced while loading or validating Matrix configuration.
#[derive(Debug)]
pub enum ConfigError {
    /// The TOML document could not be parsed.
    Parse(toml::de::Error),
    /// The `homeserver_url` was empty.
    EmptyHomeserverUrl,
    /// The `homeserver_url` was not a valid absolute URL.
    InvalidHomeserverUrl {
        /// The offending value.
        value: String,
        /// The underlying parse error.
        source: url::ParseError,
    },
    /// The `homeserver_url` did not use an `http`/`https` scheme.
    UnsupportedScheme {
        /// The offending value.
        value: String,
        /// The scheme that was found.
        scheme: String,
    },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::Parse(e) => write!(
                f,
                "failed to parse Matrix configuration: {e}; \
                 expected a `[matrix]` table with a `homeserver_url` string"
            ),
            ConfigError::EmptyHomeserverUrl => write!(
                f,
                "`matrix.homeserver_url` is empty; \
                 set it to your homeserver, e.g. homeserver_url = \"https://matrix.org\""
            ),
            ConfigError::InvalidHomeserverUrl { value, source } => write!(
                f,
                "`matrix.homeserver_url` value {value:?} is not a valid URL ({source}); \
                 use an absolute URL such as \"https://matrix.org\""
            ),
            ConfigError::UnsupportedScheme { value, scheme } => write!(
                f,
                "`matrix.homeserver_url` value {value:?} uses unsupported scheme {scheme:?}; \
                 use `https` (or `http` for local testing)"
            ),
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ConfigError::Parse(e) => Some(e),
            ConfigError::InvalidHomeserverUrl { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl MatrixConfig {
    /// Parse a [`MatrixConfig`] from a TOML document containing a `[matrix]`
    /// table, then validate it.
    pub fn from_toml_str(toml_str: &str) -> Result<Self, ConfigError> {
        let doc: ConfigDocument = toml::from_str(toml_str).map_err(ConfigError::Parse)?;
        doc.matrix.validate()?;
        Ok(doc.matrix)
    }

    /// Validate the configuration, returning an actionable error on failure.
    ///
    /// Checks that `homeserver_url` is non-empty, is an absolute URL, and uses
    /// an `http`/`https` scheme.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let trimmed = self.homeserver_url.trim();
        if trimmed.is_empty() {
            return Err(ConfigError::EmptyHomeserverUrl);
        }
        let url = Url::parse(trimmed).map_err(|source| ConfigError::InvalidHomeserverUrl {
            value: trimmed.to_string(),
            source,
        })?;
        match url.scheme() {
            "http" | "https" => Ok(()),
            other => Err(ConfigError::UnsupportedScheme {
                value: trimmed.to_string(),
                scheme: other.to_string(),
            }),
        }
    }
}

/// Error returned when constructing the Matrix client fails.
#[derive(Debug)]
pub enum ClientError {
    /// The configuration was invalid.
    Config(ConfigError),
    /// The matrix-sdk client builder failed.
    Build(matrix_sdk::ClientBuildError),
    /// The persistent crypto store could not be prepared (e.g. the store
    /// directory or its passphrase file could not be created).
    Store(String),
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClientError::Config(e) => write!(f, "{e}"),
            ClientError::Build(e) => write!(f, "failed to build Matrix client: {e}"),
            ClientError::Store(e) => write!(f, "failed to prepare crypto store: {e}"),
        }
    }
}

impl std::error::Error for ClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ClientError::Config(e) => Some(e),
            ClientError::Build(e) => Some(e),
            ClientError::Store(_) => None,
        }
    }
}

impl From<ConfigError> for ClientError {
    fn from(e: ConfigError) -> Self {
        ClientError::Config(e)
    }
}

/// Build an unauthenticated [`Client`] from the given configuration.
///
/// The configuration is validated first, then a client is constructed pointed
/// at the configured homeserver. This performs no login; the returned client
/// has no active session ([`Client::session_meta`] is `None`).
pub async fn build_client(config: &MatrixConfig) -> Result<Client, ClientError> {
    let url = validated_url(config)?;
    Client::builder()
        .homeserver_url(url)
        .build()
        .await
        .map_err(ClientError::Build)
}

/// Build a [`Client`] backed by the persistent, daemon-owned SQLite crypto
/// store (issue #240).
///
/// Unlike [`build_client`], this configures matrix-sdk with a SQLite-backed
/// crypto/state store at [`SessionPaths::crypto_store_dir`] (`0700`), encrypted
/// at rest with the daemon's [`SessionPaths::load_or_create_crypto_store_key`]
/// passphrase (`0600`). The store persists the daemon's Matrix device identity
/// and Megolm sessions, so a restart resumes as the same E2EE device and retains
/// the ability to decrypt history rather than regenerating in-memory state. The
/// passphrase is a [`Secret`] and is never logged.
///
/// This is used by [`login_password`] and [`restore_client`]; the unauthenticated
/// [`build_client`] stays store-less so it has no filesystem side effects.
pub async fn build_client_with_store(
    config: &MatrixConfig,
    paths: &SessionPaths,
) -> Result<Client, ClientError> {
    let url = validated_url(config)?;
    paths
        .ensure_crypto_store_dir()
        .map_err(|e| ClientError::Store(e.to_string()))?;
    let passphrase = paths
        .load_or_create_crypto_store_key()
        .map_err(|e| ClientError::Store(e.to_string()))?;
    Client::builder()
        .homeserver_url(url)
        .sqlite_store(&paths.crypto_store_dir, Some(passphrase.expose()))
        .build()
        .await
        .map_err(ClientError::Build)
}

/// Validate the config and parse its homeserver URL.
///
/// Returns the large `ClientError` for consistency with `build_client` and the
/// other client constructors (the variant carries matrix-sdk's
/// `ClientBuildError`); boxing only this helper's error would make the callers
/// inconsistent for no benefit.
#[allow(clippy::result_large_err)]
fn validated_url(config: &MatrixConfig) -> Result<Url, ClientError> {
    config.validate()?;
    Url::parse(config.homeserver_url.trim()).map_err(|source| {
        ClientError::Config(ConfigError::InvalidHomeserverUrl {
            value: config.homeserver_url.trim().to_string(),
            source,
        })
    })
}

/// Error returned when a Matrix login attempt fails.
#[derive(Debug)]
pub enum LoginError {
    /// The Matrix client could not be constructed.
    Client(ClientError),
    /// The homeserver rejected the login or the request failed.
    Matrix(matrix_sdk::Error),
    /// Login succeeded but the SDK reported no active session.
    NoSession,
}

impl fmt::Display for LoginError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LoginError::Client(e) => write!(f, "{e}"),
            LoginError::Matrix(e) => write!(f, "Matrix login failed: {e}"),
            LoginError::NoSession => {
                write!(
                    f,
                    "login succeeded but no session was returned by the server"
                )
            }
        }
    }
}

impl std::error::Error for LoginError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            LoginError::Client(e) => Some(e),
            LoginError::Matrix(e) => Some(e),
            LoginError::NoSession => None,
        }
    }
}

impl From<ClientError> for LoginError {
    fn from(e: ClientError) -> Self {
        LoginError::Client(e)
    }
}

/// Log in to the configured homeserver with a username and password.
///
/// On success a [`StoredSession`] is returned containing the issued tokens; the
/// caller is responsible for persisting it via
/// [`crate::session::save_session`]. The password is never logged, and the
/// returned token fields are redacting [`Secret`]s.
pub async fn login_password(
    config: &MatrixConfig,
    username: &str,
    password: &str,
) -> Result<StoredSession, LoginError> {
    // Each login creates a new Matrix device with a server-assigned device_id
    // that is not known until the login response arrives. We therefore create
    // the crypto store in a unique temporary subdirectory first, then rename it
    // to the device_id after the login succeeds. This prevents conflicts when
    // multiple users log in within the same process (e.g. Alice and Bob in
    // integration tests), where each user must have its own isolated OlmMachine.
    static LOGIN_SEQ: AtomicU32 = AtomicU32::new(0);
    let base_paths = SessionPaths::resolve();
    let seq = LOGIN_SEQ.fetch_add(1, Ordering::SeqCst);
    let temp_name = format!(".login-{}-{}", std::process::id(), seq);
    let temp_paths = SessionPaths::for_data_dir(base_paths.data_dir.join(&temp_name));

    let client = build_client_with_store(config, &temp_paths).await?;
    client
        .matrix_auth()
        .login_username(username, password)
        .initial_device_display_name("mx-agent")
        .send()
        .await
        .map_err(|e| {
            let _ = std::fs::remove_dir_all(&temp_paths.data_dir);
            LoginError::Matrix(e)
        })?;

    let session = client
        .matrix_auth()
        .session()
        .ok_or(LoginError::NoSession)?;
    let device_id = session.meta.device_id.to_string();

    // Rename the temporary store to the device-specific directory.
    let device_paths = SessionPaths::for_data_dir(base_paths.data_dir.join(&device_id));
    if !device_paths.data_dir.exists() {
        std::fs::rename(&temp_paths.data_dir, &device_paths.data_dir)
            .map_err(|e| LoginError::Client(ClientError::Store(e.to_string())))?;
    } else {
        let _ = std::fs::remove_dir_all(&temp_paths.data_dir);
    }

    Ok(StoredSession {
        homeserver: client.homeserver().to_string(),
        user_id: session.meta.user_id.to_string(),
        device_id,
        access_token: Secret::new(session.tokens.access_token),
        refresh_token: session.tokens.refresh_token.map(Secret::new),
    })
}

/// Per-(user_id, device_id) registry of long-lived Matrix [`Client`]s.
///
/// The sync loop publishes a store-backed client here via [`publish_active_client`]
/// so every per-call IPC handler (exec, approval, etc.) can share the *same*
/// client rather than opening a second store-backed client that would race the
/// sync-loop client on the SQLite OlmMachine (issue #240). Keyed by
/// `(user_id, device_id)` so multi-user integration tests (Alice + Bob) each
/// get their own entry and never collide.
static ACTIVE_CLIENTS: OnceLock<RwLock<HashMap<(String, String), Client>>> = OnceLock::new();

fn active_clients() -> &'static RwLock<HashMap<(String, String), Client>> {
    ACTIVE_CLIENTS.get_or_init(|| RwLock::new(HashMap::new()))
}

/// Publish a long-lived client so per-call IPC handlers share it.
///
/// Keyed by the client's own `(user_id, device_id)`; a later publish for the
/// same session replaces the previous entry (e.g. across an in-process
/// restart). Clients with no active session are silently ignored.
pub fn publish_active_client(client: Client) {
    let Some(meta) = client.session_meta() else {
        return;
    };
    let key = (meta.user_id.to_string(), meta.device_id.to_string());
    active_clients()
        .write()
        .unwrap_or_else(|e| e.into_inner())
        .insert(key, client);
}

/// Remove all published clients. Called on daemon shutdown.
pub fn clear_active_client() {
    active_clients()
        .write()
        .unwrap_or_else(|e| e.into_inner())
        .clear();
}

/// Return the published client for `session` (same user and device), or `None`.
fn active_client_for(session: &StoredSession) -> Option<Client> {
    let key = (session.user_id.clone(), session.device_id.clone());
    active_clients()
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .get(&key)
        .cloned()
}

/// Build a [`Client`] and restore a previously persisted [`StoredSession`].
///
/// When the daemon's long-lived sync loop has already restored and published a
/// client for this session (the normal running case), that *same* client is
/// returned, so every per-call IPC handler shares one `OlmMachine` and one
/// handle to the persistent crypto store rather than opening a second one that
/// would race the sync-loop client on the store (issue #240; see
/// [`ACTIVE_CLIENT`]). Only when no client has been published yet — login
/// bootstrap, tests, or the sync loop's own first restore — is a fresh
/// store-backed client built.
///
/// The client is pointed at the session's homeserver and the stored tokens are
/// re-imported so the daemon resumes as the same device after a restart. No
/// network round-trip is performed by the restore itself; the access token is
/// validated lazily on the next request (e.g. the first `/sync`).
pub async fn restore_client(session: &StoredSession) -> Result<Client, LoginError> {
    use matrix_sdk::authentication::matrix::MatrixSession;
    use matrix_sdk::authentication::SessionTokens;
    use matrix_sdk::ruma::{OwnedDeviceId, OwnedUserId};
    use matrix_sdk::SessionMeta;

    // Reuse the daemon's single long-lived client when one has been published
    // for this session, so the whole daemon drives exactly one OlmMachine.
    if let Some(client) = active_client_for(session) {
        return Ok(client);
    }

    let config = MatrixConfig {
        homeserver_url: session.homeserver.clone(),
    };
    // Restore on a client backed by the same persistent crypto store so the
    // daemon resumes as the same E2EE device and keeps its Megolm sessions
    // (issue #240). The device_id subdirectory isolates each user's OlmMachine
    // so that multiple users within the same process (e.g. integration tests)
    // each get their own crypto store and never see MismatchedAccount errors.
    // A fallback to the legacy flat layout ("crypto-store" in the base dir)
    // keeps existing single-user daemon deployments working without migration.
    let base_paths = SessionPaths::resolve();
    let device_dir = base_paths.data_dir.join(&session.device_id);
    let paths = if device_dir.exists() {
        // Normal path: device-specific subdirectory (created by login_password).
        SessionPaths::for_data_dir(device_dir)
    } else if base_paths.crypto_store_dir.exists() {
        // Legacy layout: single crypto-store at the base path. Keep it as-is.
        base_paths
    } else {
        // No existing store: create it now under the device-specific path.
        SessionPaths::for_data_dir(device_dir)
    };
    let client = build_client_with_store(&config, &paths).await?;

    let user_id = OwnedUserId::try_from(session.user_id.as_str())
        .map_err(|e| LoginError::Matrix(matrix_sdk::Error::from(e)))?;
    let device_id = OwnedDeviceId::from(session.device_id.as_str());
    let matrix_session = MatrixSession {
        meta: SessionMeta { user_id, device_id },
        tokens: SessionTokens {
            access_token: session.access_token.expose().to_string(),
            refresh_token: session
                .refresh_token
                .as_ref()
                .map(|t| t.expose().to_string()),
        },
    };
    client
        .restore_session(matrix_session)
        .await
        .map_err(LoginError::Matrix)?;
    Ok(client)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_config() {
        let cfg = MatrixConfig::from_toml_str(
            r#"
            [matrix]
            homeserver_url = "https://matrix.org"
            "#,
        )
        .expect("valid config should parse");
        assert_eq!(cfg.homeserver_url, "https://matrix.org");
    }

    #[test]
    fn empty_url_is_actionable() {
        let err = MatrixConfig::from_toml_str(
            r#"
            [matrix]
            homeserver_url = ""
            "#,
        )
        .unwrap_err();
        assert!(matches!(err, ConfigError::EmptyHomeserverUrl));
        let msg = err.to_string();
        assert!(msg.contains("homeserver_url"), "message: {msg}");
        assert!(msg.contains("https://matrix.org"), "message: {msg}");
    }

    #[test]
    fn invalid_url_is_actionable() {
        let cfg = MatrixConfig {
            homeserver_url: "not a url".to_string(),
        };
        let err = cfg.validate().unwrap_err();
        match &err {
            ConfigError::InvalidHomeserverUrl { value, .. } => assert_eq!(value, "not a url"),
            other => panic!("expected InvalidHomeserverUrl, got {other:?}"),
        }
        assert!(err.to_string().contains("absolute URL"));
    }

    #[test]
    fn unsupported_scheme_is_actionable() {
        let cfg = MatrixConfig {
            homeserver_url: "ftp://example.org".to_string(),
        };
        let err = cfg.validate().unwrap_err();
        match &err {
            ConfigError::UnsupportedScheme { scheme, .. } => assert_eq!(scheme, "ftp"),
            other => panic!("expected UnsupportedScheme, got {other:?}"),
        }
        assert!(err.to_string().contains("https"));
    }

    #[test]
    fn missing_matrix_table_is_actionable() {
        let err = MatrixConfig::from_toml_str("[other]\nkey = 1\n").unwrap_err();
        assert!(matches!(err, ConfigError::Parse(_)));
        assert!(err.to_string().contains("homeserver_url"));
    }

    #[tokio::test]
    async fn builds_client_without_login() {
        let cfg = MatrixConfig {
            homeserver_url: "https://matrix.org".to_string(),
        };
        let client = build_client(&cfg).await.expect("client should build");
        assert!(
            client.session_meta().is_none(),
            "client must not have an active session (not logged in)"
        );
        assert!(
            !client.matrix_auth().logged_in(),
            "client must not be logged in"
        );
        assert_eq!(client.homeserver().as_str(), "https://matrix.org/");
    }

    #[tokio::test]
    async fn build_client_rejects_invalid_config() {
        let cfg = MatrixConfig {
            homeserver_url: String::new(),
        };
        let err = build_client(&cfg).await.unwrap_err();
        assert!(matches!(
            err,
            ClientError::Config(ConfigError::EmptyHomeserverUrl)
        ));
    }

    fn sample_session() -> StoredSession {
        StoredSession {
            homeserver: "https://matrix.org".to_string(),
            user_id: "@daemon:matrix.org".to_string(),
            device_id: "DAEMONDEV".to_string(),
            access_token: Secret::new("token".to_string()),
            refresh_token: None,
        }
    }

    // The shared-client registry must never hand a handler a client whose
    // session does not match — otherwise a handler could operate on the wrong
    // device. The positive sharing path (a published, session-matching client is
    // reused) is exercised by the `matrix-integration` suite, which needs a live
    // homeserver to mint a real session. Here we lock in the guard: an empty
    // registry, and a published client with no session, both yield `None`
    // (issue #240). Run serially because the registry is process-global.
    #[tokio::test]
    async fn active_client_registry_guards_against_session_mismatch() {
        clear_active_client();
        let session = sample_session();
        assert!(
            active_client_for(&session).is_none(),
            "empty registry must not yield a client"
        );

        // A store-less client has no session_meta, so it can never match a
        // restored session and must not be returned.
        let cfg = MatrixConfig {
            homeserver_url: "https://matrix.org".to_string(),
        };
        let client = build_client(&cfg).await.expect("client should build");
        assert!(client.session_meta().is_none());
        publish_active_client(client);
        assert!(
            active_client_for(&session).is_none(),
            "a published client whose session does not match must not be returned"
        );

        clear_active_client();
        assert!(
            active_client_for(&session).is_none(),
            "cleared registry must not yield a client"
        );
    }
}
