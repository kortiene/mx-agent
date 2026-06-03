//! Matrix client initialization for the daemon.
//!
//! The daemon owns the long-lived Matrix session (see `docs/architecture.md`,
//! section 10.1). This module provides the first step of that ownership:
//! reading the homeserver configuration and constructing a [`matrix_sdk`]
//! [`Client`] from it. No login or network round-trip is performed here; the
//! returned client is unauthenticated and ready for a later auth phase.

use std::fmt;

use matrix_sdk::Client;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::session::{Secret, StoredSession};

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
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClientError::Config(e) => write!(f, "{e}"),
            ClientError::Build(e) => write!(f, "failed to build Matrix client: {e}"),
        }
    }
}

impl std::error::Error for ClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ClientError::Config(e) => Some(e),
            ClientError::Build(e) => Some(e),
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
    config.validate()?;
    let url = Url::parse(config.homeserver_url.trim()).map_err(|source| {
        ClientError::Config(ConfigError::InvalidHomeserverUrl {
            value: config.homeserver_url.trim().to_string(),
            source,
        })
    })?;
    Client::builder()
        .homeserver_url(url)
        .build()
        .await
        .map_err(ClientError::Build)
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
    let client = build_client(config).await?;
    client
        .matrix_auth()
        .login_username(username, password)
        .initial_device_display_name("mx-agent")
        .send()
        .await
        .map_err(LoginError::Matrix)?;

    let session = client
        .matrix_auth()
        .session()
        .ok_or(LoginError::NoSession)?;
    Ok(StoredSession {
        homeserver: client.homeserver().to_string(),
        user_id: session.meta.user_id.to_string(),
        device_id: session.meta.device_id.to_string(),
        access_token: Secret::new(session.tokens.access_token),
        refresh_token: session.tokens.refresh_token.map(Secret::new),
    })
}

/// Build a [`Client`] and restore a previously persisted [`StoredSession`].
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

    let config = MatrixConfig {
        homeserver_url: session.homeserver.clone(),
    };
    let client = build_client(&config).await?;

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
}
