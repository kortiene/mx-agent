//! Structured logging and secret redaction for mx-agent.
//!
//! All mx-agent processes (the CLI and, later, the daemon) emit logs through
//! the [`tracing`] ecosystem. This crate centralizes subscriber setup so every
//! process logs consistently, and provides redaction helpers so credentials are
//! never written to logs (see `docs/architecture.md`, section 13).
//!
//! # Environment variables
//!
//! - `MX_AGENT_LOG`: log filter directive, same syntax as `RUST_LOG`
//!   (e.g. `info`, `mx_agent_daemon=debug,info`). Takes precedence over
//!   `RUST_LOG`.
//! - `RUST_LOG`: fallback log filter directive.
//! - `MX_AGENT_LOG_FORMAT`: `human` (default) or `json`.
//!
//! Logs are written to stderr so machine-readable command output on stdout is
//! never mixed with diagnostics.

use std::borrow::Cow;
use std::fmt;

use tracing_subscriber::filter::EnvFilter;

/// Environment variable selecting the log filter (preferred over `RUST_LOG`).
pub const ENV_FILTER: &str = "MX_AGENT_LOG";

/// Environment variable selecting the log output format.
pub const ENV_FORMAT: &str = "MX_AGENT_LOG_FORMAT";

/// The placeholder written in place of a redacted secret value.
pub const REDACTED: &str = "***redacted***";

/// Log output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LogFormat {
    /// Human-readable, single-line-per-event output.
    #[default]
    Human,
    /// Newline-delimited JSON, one object per event.
    Json,
}

impl LogFormat {
    /// Parse a format name; returns `None` for unrecognized values.
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "human" | "text" | "pretty" => Some(Self::Human),
            "json" => Some(Self::Json),
            _ => None,
        }
    }

    /// Resolve the format from [`ENV_FORMAT`], defaulting to [`LogFormat::Human`].
    pub fn from_env() -> Self {
        std::env::var(ENV_FORMAT)
            .ok()
            .and_then(|v| Self::parse(&v))
            .unwrap_or_default()
    }
}

/// Build the log filter from the environment, falling back to `default_directive`.
fn env_filter(default_directive: &str) -> EnvFilter {
    EnvFilter::try_from_env(ENV_FILTER)
        .or_else(|_| EnvFilter::try_from_default_env())
        .unwrap_or_else(|_| EnvFilter::new(default_directive))
}

/// Initialize the global tracing subscriber for this process.
///
/// `default_directive` is used only when neither `MX_AGENT_LOG` nor `RUST_LOG`
/// is set (for example `"warn"` or `"info"`). Returns an error if a global
/// subscriber has already been installed, so callers may ignore the result when
/// best-effort initialization is acceptable.
pub fn init(default_directive: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let filter = env_filter(default_directive);
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(true);

    match LogFormat::from_env() {
        LogFormat::Json => builder.json().try_init(),
        LogFormat::Human => builder.try_init(),
    }
}

/// Returns true if `key` names an obviously sensitive field.
///
/// Matching is case-insensitive and substring-based so variants like
/// `GITHUB_TOKEN`, `access_token`, or `Authorization` are all caught.
pub fn is_sensitive_key(key: &str) -> bool {
    const NEEDLES: &[&str] = &[
        "token",
        "secret",
        "password",
        "passwd",
        "api_key",
        "apikey",
        "access_key",
        "private_key",
        "credential",
        "authorization",
    ];
    let lower = key.to_ascii_lowercase();
    NEEDLES.iter().any(|needle| lower.contains(needle))
}

/// Redact `value` when `key` is sensitive; otherwise return it unchanged.
pub fn redact<'a>(key: &str, value: &'a str) -> Cow<'a, str> {
    if is_sensitive_key(key) {
        Cow::Borrowed(REDACTED)
    } else {
        Cow::Borrowed(value)
    }
}

/// A wrapper that hides its inner value from `Debug`/`Display` output.
///
/// Use this for tokens, keys, and other credentials so they cannot be leaked
/// through `tracing` fields, `{:?}` formatting, or log lines. The real value is
/// only available via [`Secret::expose`] or [`Secret::into_inner`].
#[derive(Clone, PartialEq, Eq)]
pub struct Secret<T>(T);

impl<T> Secret<T> {
    /// Wrap a value as a secret.
    pub fn new(value: T) -> Self {
        Self(value)
    }

    /// Borrow the underlying secret value.
    pub fn expose(&self) -> &T {
        &self.0
    }

    /// Consume the wrapper and return the underlying value.
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

impl<T> fmt::Display for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

impl<T> From<T> for Secret<T> {
    fn from(value: T) -> Self {
        Self(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_known_formats() {
        assert_eq!(LogFormat::parse("json"), Some(LogFormat::Json));
        assert_eq!(LogFormat::parse("HUMAN"), Some(LogFormat::Human));
        assert_eq!(LogFormat::parse("text"), Some(LogFormat::Human));
        assert_eq!(LogFormat::parse("yaml"), None);
        assert_eq!(LogFormat::default(), LogFormat::Human);
    }

    #[test]
    fn detects_sensitive_keys() {
        for key in [
            "token",
            "GITHUB_TOKEN",
            "access_token",
            "Authorization",
            "api_key",
            "user_password",
            "private_key",
        ] {
            assert!(is_sensitive_key(key), "{key} should be sensitive");
        }
        for key in ["name", "room", "agent", "cwd", "count"] {
            assert!(!is_sensitive_key(key), "{key} should not be sensitive");
        }
    }

    #[test]
    fn redacts_only_sensitive_values() {
        assert_eq!(redact("agent", "developer-pi"), "developer-pi");
        assert_eq!(redact("access_token", "syt_abc123"), REDACTED);
    }

    #[test]
    fn secret_hides_value_in_debug_and_display() {
        let s = Secret::new("syt_super_secret");
        assert_eq!(format!("{s:?}"), REDACTED);
        assert_eq!(format!("{s}"), REDACTED);
        // The real value remains accessible explicitly.
        assert_eq!(*s.expose(), "syt_super_secret");
        assert_eq!(s.into_inner(), "syt_super_secret");
    }

    #[test]
    fn secret_is_hidden_inside_derived_debug() {
        #[derive(Debug)]
        #[allow(dead_code)]
        struct Session {
            user: &'static str,
            token: Secret<&'static str>,
        }
        let dbg = format!(
            "{:?}",
            Session {
                user: "@pi:matrix.org",
                token: Secret::new("syt_leak_me"),
            }
        );
        assert!(dbg.contains("@pi:matrix.org"));
        assert!(dbg.contains(REDACTED));
        assert!(!dbg.contains("syt_leak_me"));
    }
}
