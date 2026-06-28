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

use tracing::field::{Field, Visit};
use tracing::{Event, Subscriber};
use tracing_subscriber::field::{MakeVisitor, VisitFmt, VisitOutput};
use tracing_subscriber::filter::EnvFilter;
use tracing_subscriber::fmt::format::{DefaultFields, JsonFields, JsonVisitor, Writer};
use tracing_subscriber::fmt::time::{FormatTime, SystemTime};
use tracing_subscriber::fmt::{FmtContext, FormatEvent, FormatFields};
use tracing_subscriber::registry::LookupSpan;

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

    // Install a field-redaction backstop so any structured field whose key looks
    // sensitive (see [`is_sensitive_key`]) is written as [`REDACTED`] instead of
    // its real value, in both the human and JSON output formats. This is a
    // backstop *behind* the [`Secret`] wrapper, which is the primary
    // no-secrets-in-logs guarantee: a stray `tracing::debug!(token = …)` can no
    // longer leak a credential in the clear, but code must still wrap secrets in
    // [`Secret`] and must never interpolate one into a format message
    // (`debug!("token={t}")`), which this layer does not scan. See
    // `docs/security-hardening.md`.
    match LogFormat::from_env() {
        // The built-in JSON event formatter serializes an event's own fields
        // with `tracing-serde`, bypassing the configured field formatter, so a
        // redacting field formatter alone cannot reach them. [`RedactingJson`]
        // emits the JSON envelope itself and redacts event fields directly.
        LogFormat::Json => builder
            .fmt_fields(JsonFields::new())
            .event_format(RedactingJson)
            .try_init(),
        // The default (human) event formatter renders an event's own fields
        // through the configured field formatter, so wrapping [`DefaultFields`]
        // in [`Redacting`] is enough to redact event and span fields alike.
        LogFormat::Human => builder
            .fmt_fields(Redacting(DefaultFields::new()))
            .try_init(),
    }
}

/// A field-visitor factory that redacts sensitive field values.
///
/// Wraps another [`MakeVisitor`] (a format's own field visitor) and substitutes
/// only the value of fields whose key satisfies [`is_sensitive_key`], so the
/// same wrapper redacts for both the human ([`DefaultFields`]) and JSON
/// ([`JsonFields`]) field formatters without re-implementing either layout. The
/// inner visitor keeps producing the correct per-format rendering for every
/// other field.
struct Redacting<M>(M);

impl<'a, M> MakeVisitor<Writer<'a>> for Redacting<M>
where
    M: MakeVisitor<Writer<'a>>,
{
    type Visitor = RedactingVisitor<M::Visitor>;

    fn make_visitor(&self, target: Writer<'a>) -> Self::Visitor {
        RedactingVisitor(self.0.make_visitor(target))
    }
}

/// The [`Visit`] wrapper produced by [`Redacting`].
///
/// Forwards every record to the inner visitor unchanged, except that a field
/// whose key is sensitive is recorded as the [`REDACTED`] string regardless of
/// its original value type. Numeric and boolean secrets are coerced to the
/// placeholder string, which renders consistently in both output formats; the
/// `message` pseudo-field is never sensitive by name, so log messages are
/// untouched — meaning a secret interpolated into a format message is **not**
/// redacted here. Wrap it in [`Secret`] instead.
struct RedactingVisitor<V>(V);

/// Generate a `Visit` method that records [`REDACTED`] for a sensitive key and
/// otherwise forwards to the same method on the inner visitor (preserving its
/// per-format rendering for non-sensitive fields).
macro_rules! redact_or_forward {
    ($method:ident, $ty:ty) => {
        fn $method(&mut self, field: &Field, value: $ty) {
            if is_sensitive_key(field.name()) {
                self.0.record_str(field, REDACTED);
            } else {
                self.0.$method(field, value);
            }
        }
    };
}

impl<V: Visit> Visit for RedactingVisitor<V> {
    redact_or_forward!(record_f64, f64);
    redact_or_forward!(record_i64, i64);
    redact_or_forward!(record_u64, u64);
    redact_or_forward!(record_i128, i128);
    redact_or_forward!(record_u128, u128);
    redact_or_forward!(record_bool, bool);
    redact_or_forward!(record_str, &str);
    redact_or_forward!(record_bytes, &[u8]);
    redact_or_forward!(record_error, &(dyn std::error::Error + 'static));
    redact_or_forward!(record_debug, &dyn fmt::Debug);
}

impl<V: VisitOutput<fmt::Result>> VisitOutput<fmt::Result> for RedactingVisitor<V> {
    fn finish(self) -> fmt::Result {
        self.0.finish()
    }
}

impl<V: VisitFmt> VisitFmt for RedactingVisitor<V> {
    fn writer(&mut self) -> &mut dyn fmt::Write {
        self.0.writer()
    }
}

/// A JSON event formatter that redacts sensitive event-field values.
///
/// `tracing-subscriber`'s built-in JSON formatter serializes an event's own
/// fields with `tracing-serde` directly, bypassing the configured field
/// formatter, so [`Redacting`] (a [`MakeVisitor`] wrapper) cannot reach them —
/// and [`JsonFields`] is not a `MakeVisitor` to wrap in the first place. This
/// formatter emits the JSON envelope itself (`timestamp`, `level`, `target`, and
/// a nested `fields` object) and records the event fields through
/// [`RedactingVisitor`] over [`JsonVisitor`], so sensitive event fields are
/// redacted. The output is one JSON object per line.
struct RedactingJson;

impl<S, N> FormatEvent<S, N> for RedactingJson
where
    S: Subscriber + for<'lookup> LookupSpan<'lookup>,
    N: for<'writer> FormatFields<'writer> + 'static,
{
    fn format_event(
        &self,
        _ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        let meta = event.metadata();

        let mut timestamp = String::new();
        if SystemTime
            .format_time(&mut Writer::new(&mut timestamp))
            .is_err()
        {
            timestamp.clear();
        }
        let level = match *meta.level() {
            tracing::Level::ERROR => "ERROR",
            tracing::Level::WARN => "WARN",
            tracing::Level::INFO => "INFO",
            tracing::Level::DEBUG => "DEBUG",
            tracing::Level::TRACE => "TRACE",
        };

        writer.write_str("{\"timestamp\":")?;
        write_json_string(&mut writer, &timestamp)?;
        writer.write_str(",\"level\":")?;
        write_json_string(&mut writer, level)?;
        writer.write_str(",\"target\":")?;
        write_json_string(&mut writer, meta.target())?;
        writer.write_str(",\"fields\":")?;
        // `JsonVisitor` writes a complete `{ ... }` object; wrapping it in
        // `RedactingVisitor` swaps sensitive values for `REDACTED` first.
        {
            let mut visitor = RedactingVisitor(JsonVisitor::new(&mut writer));
            event.record(&mut visitor);
            visitor.finish()?;
        }
        writer.write_str("}")?;
        writeln!(writer)
    }
}

/// Write `value` to `writer` as a JSON string literal (quoted and escaped) so
/// the hand-built envelope in [`RedactingJson`] stays valid JSON for any input.
fn write_json_string(writer: &mut Writer<'_>, value: &str) -> fmt::Result {
    writer.write_char('"')?;
    for ch in value.chars() {
        match ch {
            '"' => writer.write_str("\\\"")?,
            '\\' => writer.write_str("\\\\")?,
            '\n' => writer.write_str("\\n")?,
            '\r' => writer.write_str("\\r")?,
            '\t' => writer.write_str("\\t")?,
            c if (c as u32) < 0x20 => write!(writer, "\\u{:04x}", c as u32)?,
            c => writer.write_char(c)?,
        }
    }
    writer.write_char('"')
}

/// Returns true if `key` names an obviously sensitive field.
///
/// This is a **backstop, not the primary guarantee.** The real no-secrets-in-logs
/// guarantee is the [`Secret`] wrapper (and the daemon's `session::Secret`), whose
/// `Debug`/`Display` always render [`REDACTED`]. Field-name redaction only catches
/// a value recorded under a recognised key; it does **not** scan a format
/// message's interpolated text, nor a secret recorded under an unrecognised key.
/// Never interpolate a secret into a `tracing` message (`debug!("key={k}")`) and
/// rely on this function to catch it — wrap the secret in [`Secret`] instead.
///
/// Matching is case-insensitive. Most needles match as a substring (so
/// `GITHUB_TOKEN`, `access_token`, `Authorization`, `recovery_key`, and
/// `recovery_passphrase` are all caught). A bare `key` matches only on a token
/// boundary — the whole name is `key`, or it ends in `_key` — so `signing_key`
/// and `recovery_key` are redacted while `keyspace`, `monkey`, `key_count`, and
/// `key_id` are not.
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
        "recovery",
        "passphrase",
    ];
    let lower = key.to_ascii_lowercase();
    NEEDLES.iter().any(|needle| lower.contains(needle))
        // Bare `key`, on a token boundary only: the whole name is `key`, or it
        // ends in `_key` (e.g. `signing_key`, `device_key`, `recovery_key`).
        // Deliberately NOT a raw `contains("key")`, which would also redact
        // `keyspace`, `monkey`, `key_count`, and `key_id`.
        || lower == "key"
        || lower.ends_with("_key")
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
    use std::sync::{Arc, Mutex};

    /// A [`MakeWriter`](tracing_subscriber::fmt::MakeWriter) that appends every
    /// byte to a shared buffer, so a scoped subscriber's output can be captured
    /// and inspected by a test.
    #[derive(Clone)]
    struct BufMakeWriter(Arc<Mutex<Vec<u8>>>);

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for BufMakeWriter {
        type Writer = BufWriter;
        fn make_writer(&'a self) -> Self::Writer {
            BufWriter(Arc::clone(&self.0))
        }
    }

    struct BufWriter(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for BufWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn human_subscriber_redacts_sensitive_event_fields() {
        // Wire the same human field formatter `init` installs into a scoped
        // subscriber (a process-global `init` could only run once per process),
        // emit an event with a sensitive `token` field, and confirm the value is
        // redacted while non-sensitive fields and the message survive.
        let buf = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .with_writer(BufMakeWriter(Arc::clone(&buf)))
            .with_ansi(false)
            .fmt_fields(Redacting(DefaultFields::new()))
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(
                token = "syt_leakme",
                recovery_key = "EsTe recovery clear",
                user = "@a:hs",
                "hello world"
            );
        });
        let out = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
        assert!(out.contains(REDACTED), "must redact the token: {out}");
        assert!(!out.contains("syt_leakme"), "secret leaked into log: {out}");
        // The widened needle set (issue #376) redacts `recovery_key` end-to-end
        // through the live visitor, not just the predicate.
        assert!(
            !out.contains("EsTe recovery clear"),
            "recovery key leaked into log: {out}"
        );
        assert!(out.contains("@a:hs"), "non-secret field was dropped: {out}");
        assert!(out.contains("hello world"), "message was dropped: {out}");
    }

    #[test]
    fn json_subscriber_redacts_sensitive_event_fields() {
        // The JSON path uses a custom event formatter; assert it still emits one
        // valid JSON object per line with the sensitive field redacted.
        let buf = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .with_writer(BufMakeWriter(Arc::clone(&buf)))
            .fmt_fields(JsonFields::new())
            .event_format(RedactingJson)
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(
                token = "syt_leakme",
                recovery_key = "EsTe recovery clear",
                user = "@a:hs",
                "hello world"
            );
        });
        let out = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
        assert!(!out.contains("syt_leakme"), "secret leaked into log: {out}");
        assert!(
            !out.contains("EsTe recovery clear"),
            "recovery key leaked into log: {out}"
        );

        let line = out.lines().next().expect("at least one JSON line");
        let v: serde_json::Value = serde_json::from_str(line).expect("output must be valid JSON");
        assert_eq!(
            v["fields"]["token"],
            serde_json::json!(REDACTED),
            "token field must be redacted in JSON: {line}"
        );
        // The widened needle set (issue #376) redacts `recovery_key` through the
        // JSON visitor too.
        assert_eq!(
            v["fields"]["recovery_key"],
            serde_json::json!(REDACTED),
            "recovery_key field must be redacted in JSON: {line}"
        );
        assert_eq!(
            v["fields"]["user"],
            serde_json::json!("@a:hs"),
            "non-secret field must be preserved in JSON: {line}"
        );
        assert_eq!(
            v["fields"]["message"],
            serde_json::json!("hello world"),
            "message must be preserved in JSON: {line}"
        );
        assert_eq!(v["level"], serde_json::json!("INFO"));
    }

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
            // Recovery surface (issue #376): the recovery key/passphrase field
            // names are caught by the widened needle set as a backstop, even
            // though the primary guarantee is the `Secret` wrapper.
            "recovery_key",
            "recovery",
            "passphrase",
            "recovery_passphrase",
            // Bare-`key` token-boundary heuristic.
            "signing_key",
            "key",
            "KEY",
        ] {
            assert!(is_sensitive_key(key), "{key} should be sensitive");
        }
        for key in ["name", "room", "agent", "cwd", "count"] {
            assert!(!is_sensitive_key(key), "{key} should not be sensitive");
        }
    }

    #[test]
    fn bare_key_heuristic_avoids_false_positives() {
        // The bare-`key` rule matches only the exact name `key` or a `_key`
        // suffix, so names that merely contain the letters `key` (or use `key`
        // as a prefix for metadata about a key) are NOT redacted. This pins the
        // chosen boundary so a future broadening to raw `contains("key")` — which
        // would redact all of these — fails the test.
        for key in [
            "keyspace",
            "monkey",
            "key_count",
            "key_id",
            "keyfile",
            "keyring",
        ] {
            assert!(!is_sensitive_key(key), "{key} should not be sensitive");
        }
    }

    #[test]
    fn redacts_only_sensitive_values() {
        assert_eq!(redact("agent", "developer-pi"), "developer-pi");
        assert_eq!(redact("access_token", "syt_abc123"), REDACTED);
        // Issue #376: widened needles flow through `redact()` too.
        assert_eq!(redact("recovery_key", "EsEr cleartext"), REDACTED);
        assert_eq!(redact("passphrase", "my passphrase"), REDACTED);
        assert_eq!(redact("signing_key", "signing material"), REDACTED);
        // `RECOVERY_KEY` is case-insensitive.
        assert_eq!(redact("RECOVERY_KEY", "cleartext"), REDACTED);
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
