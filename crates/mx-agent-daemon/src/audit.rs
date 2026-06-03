//! Local audit log for privileged policy decisions.
//!
//! Every privileged request the daemon evaluates against the policy engine
//! (raw `exec` and named `call`) produces an [`AuditRecord`] that is appended,
//! one JSON object per line, to a local audit file (see `docs/architecture.md`,
//! section 13.6). The audit log is the operator's tamper-evident trail of who
//! asked for what and whether it was allowed or denied.
//!
//! Records never contain secrets: command arguments are passed through
//! [`redact_command`], which masks values of obviously sensitive flags (for
//! example `--token`, `API_KEY=...`, `--password secret`) using the shared
//! redaction rules in [`mx_agent_telemetry`]. The audit log records *what was
//! requested and decided*, not credentials, so it can be retained and shared
//! for review without leaking tokens or private keys.

use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use mx_agent_policy::{DenyReason, Outcome};
use mx_agent_telemetry::{is_sensitive_key, REDACTED};
use serde::Serialize;

/// Default config-relative file name for the audit log.
pub const AUDIT_FILE_NAME: &str = "audit.log";

/// Whether a privileged request was permitted or rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditDecision {
    /// The request was permitted by policy.
    Allowed,
    /// The request was rejected by policy.
    Denied,
}

impl AuditDecision {
    /// Map a policy [`Outcome`] onto an audit decision.
    pub fn from_outcome(outcome: &Outcome) -> Self {
        if outcome.is_allowed() {
            Self::Allowed
        } else {
            Self::Denied
        }
    }
}

/// A single privileged decision recorded in the audit log.
///
/// Field order mirrors the schema in `docs/architecture.md` §13.6. Optional
/// fields are omitted when absent so each line stays compact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuditRecord {
    /// RFC 3339 UTC timestamp of when the decision was made.
    pub ts: String,
    /// Matrix room id the request arrived in.
    pub room: String,
    /// Matrix user id of the requesting agent.
    pub requester: String,
    /// Local target the request was directed at (agent/session name).
    pub target: String,
    /// Invocation id, when the request is part of a tracked invocation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invocation_id: Option<String>,
    /// The kind of request: `"exec"` or `"call"`.
    pub request: &'static str,
    /// Redacted command argv, for raw `exec` requests.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<Vec<String>>,
    /// Tool name, for named `call` requests.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    /// Whether the request was allowed or denied.
    pub decision: AuditDecision,
    /// The policy rule (when allowed) or deny reason (when denied) that
    /// produced the decision.
    pub policy_rule: String,
}

impl AuditRecord {
    /// Build an audit record for a raw `exec` decision.
    ///
    /// The command argv is redacted before being stored so credentials passed
    /// as arguments never reach the log.
    pub fn for_exec(
        room: &str,
        requester: &str,
        target: &str,
        invocation_id: Option<&str>,
        command: &[String],
        outcome: &Outcome,
    ) -> Self {
        Self {
            ts: now_rfc3339(),
            room: room.to_string(),
            requester: requester.to_string(),
            target: target.to_string(),
            invocation_id: invocation_id.map(str::to_string),
            request: "exec",
            command: Some(redact_command(command)),
            tool: None,
            decision: AuditDecision::from_outcome(outcome),
            policy_rule: rule_for(outcome, "allow_commands"),
        }
    }

    /// Build an audit record for a named `call` decision.
    pub fn for_call(
        room: &str,
        requester: &str,
        target: &str,
        invocation_id: Option<&str>,
        tool: &str,
        outcome: &Outcome,
    ) -> Self {
        Self {
            ts: now_rfc3339(),
            room: room.to_string(),
            requester: requester.to_string(),
            target: target.to_string(),
            invocation_id: invocation_id.map(str::to_string),
            request: "call",
            command: None,
            tool: Some(tool.to_string()),
            decision: AuditDecision::from_outcome(outcome),
            policy_rule: rule_for(outcome, "allow_tools"),
        }
    }

    /// Serialize the record to a single-line JSON string.
    pub fn to_json_line(&self) -> String {
        // The record contains only owned strings and enums, so serialization
        // cannot fail; fall back to an empty object defensively.
        serde_json::to_string(self).unwrap_or_else(|_| "{}".to_string())
    }
}

/// An append-only local audit log backed by a file.
///
/// Records are written as newline-delimited JSON. The file is opened in append
/// mode on each write so concurrent daemon components and external log rotation
/// behave predictably.
#[derive(Debug, Clone)]
pub struct AuditLog {
    path: PathBuf,
}

impl AuditLog {
    /// Create a log writing to `path`. The file is created on first append.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Resolve the default audit log path.
    ///
    /// Precedence matches the policy file: `MX_AGENT_CONFIG_DIR`, then
    /// `$XDG_CONFIG_HOME/mx-agent`, then `$HOME/.config/mx-agent`. Returns
    /// `None` if none of these can be determined.
    pub fn default_path() -> Option<PathBuf> {
        let config_dir = if let Ok(dir) = std::env::var(mx_agent_policy::ENV_CONFIG_DIR) {
            PathBuf::from(dir)
        } else if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
            PathBuf::from(xdg).join("mx-agent")
        } else if let Ok(home) = std::env::var("HOME") {
            PathBuf::from(home).join(".config/mx-agent")
        } else {
            return None;
        };
        Some(config_dir.join(AUDIT_FILE_NAME))
    }

    /// The path this log writes to.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append a decision record to the log.
    pub fn append(&self, record: &AuditRecord) -> io::Result<()> {
        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        file.write_all(record.to_json_line().as_bytes())?;
        file.write_all(b"\n")?;
        Ok(())
    }
}

/// Derive the `policy_rule` field for an outcome.
///
/// Allowed requests record the dotted rule family that permitted them (e.g.
/// `allow_commands`/`allow_tools`); denied requests record the machine-readable
/// deny reason so reviewers see exactly which gate rejected the request.
fn rule_for(outcome: &Outcome, allow_rule: &str) -> String {
    match outcome {
        Outcome::Allow(_) => allow_rule.to_string(),
        Outcome::Deny(reason) => deny_rule(reason),
    }
}

/// A stable machine-readable identifier for a [`DenyReason`].
fn deny_rule(reason: &DenyReason) -> String {
    match reason {
        DenyReason::UnknownRoom => "deny:unknown_room".to_string(),
        DenyReason::UntrustedRoom => "deny:untrusted_room".to_string(),
        DenyReason::UnknownAgent => "deny:unknown_agent".to_string(),
        DenyReason::EmptyCommand => "deny:empty_command".to_string(),
        DenyReason::ExecNotAllowed => "deny:exec_not_allowed".to_string(),
        DenyReason::CommandNotAllowed { .. } => "deny:command_not_allowed".to_string(),
        DenyReason::CwdNotAllowed { .. } => "deny:cwd_not_allowed".to_string(),
        DenyReason::DeniedArguments { .. } => "deny:denied_arguments".to_string(),
        DenyReason::ToolNotAllowed { .. } => "deny:tool_not_allowed".to_string(),
    }
}

/// Redact secret-bearing arguments from a command argv.
///
/// Two shapes are masked using the shared sensitive-key rules:
///
/// - inline `KEY=value` / `--key=value`: the value is replaced with the
///   redaction placeholder while the key is preserved;
/// - a sensitive flag (`--token`, `--password`, ...) followed by a separate
///   value: the following argument is replaced.
///
/// Everything else is preserved verbatim so the recorded command stays useful.
pub fn redact_command(args: &[String]) -> Vec<String> {
    let mut out = Vec::with_capacity(args.len());
    let mut redact_next = false;
    for arg in args {
        if redact_next {
            out.push(REDACTED.to_string());
            redact_next = false;
            continue;
        }
        if let Some(eq) = arg.find('=') {
            let (key, _value) = arg.split_at(eq);
            if is_sensitive_key(&normalize_key(key)) {
                out.push(format!("{key}={REDACTED}"));
                continue;
            }
        } else if arg.starts_with('-') && is_sensitive_key(&normalize_key(arg)) {
            out.push(arg.clone());
            redact_next = true;
            continue;
        }
        out.push(arg.clone());
    }
    out
}

/// Normalize a flag/env key for sensitivity matching: strip leading dashes and
/// treat hyphens as underscores so `--api-key` matches the `api_key` rule.
fn normalize_key(key: &str) -> String {
    key.trim_start_matches('-').replace('-', "_")
}

/// Format the current time as an RFC 3339 UTC timestamp.
fn now_rfc3339() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    unix_to_rfc3339(secs)
}

/// Format Unix seconds as an RFC 3339 UTC timestamp (`YYYY-MM-DDTHH:MM:SSZ`).
///
/// Uses Howard Hinnant's civil-from-days algorithm so no date library is
/// required.
fn unix_to_rfc3339(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let tod = (secs % 86_400) as i64;
    let (hour, minute, second) = (tod / 3600, (tod % 3600) / 60, tod % 60);

    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { y + 1 } else { y };

    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

#[cfg(test)]
mod tests {
    use super::*;
    use mx_agent_policy::{Allowance, Outcome};

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    fn allow() -> Outcome {
        Outcome::Allow(Allowance::default())
    }

    #[test]
    fn redacts_inline_secret_values() {
        let cmd = argv(&["deploy", "--api-key=syt_abc123", "--name=prod"]);
        let red = redact_command(&cmd);
        assert_eq!(red[0], "deploy");
        assert_eq!(red[1], format!("--api-key={REDACTED}"));
        // Non-sensitive key=value pairs are preserved.
        assert_eq!(red[2], "--name=prod");
        assert!(!red.join(" ").contains("syt_abc123"));
    }

    #[test]
    fn redacts_separated_secret_flag_value() {
        let cmd = argv(&["login", "--token", "ghp_secretvalue", "--user", "me"]);
        let red = redact_command(&cmd);
        assert_eq!(red, argv(&["login", "--token", REDACTED, "--user", "me"]));
        assert!(!red.join(" ").contains("ghp_secretvalue"));
    }

    #[test]
    fn redacts_env_style_secret_assignment() {
        let cmd = argv(&["env", "GITHUB_TOKEN=ghp_xyz", "PATH=/usr/bin"]);
        let red = redact_command(&cmd);
        assert_eq!(red[1], format!("GITHUB_TOKEN={REDACTED}"));
        assert_eq!(red[2], "PATH=/usr/bin");
        assert!(!red.join(" ").contains("ghp_xyz"));
    }

    #[test]
    fn trailing_secret_flag_does_not_panic() {
        let cmd = argv(&["login", "--password"]);
        let red = redact_command(&cmd);
        assert_eq!(red, argv(&["login", "--password"]));
    }

    #[test]
    fn exec_record_serializes_expected_fields() {
        let cmd = argv(&["cargo", "test"]);
        let record = AuditRecord::for_exec(
            "!abc:matrix.org",
            "@claude:matrix.org",
            "developer-pi",
            Some("inv_01HZ"),
            &cmd,
            &allow(),
        );
        assert_eq!(record.decision, AuditDecision::Allowed);
        assert_eq!(record.policy_rule, "allow_commands");
        let json = record.to_json_line();
        assert!(json.contains("\"room\":\"!abc:matrix.org\""), "got {json}");
        assert!(
            json.contains("\"requester\":\"@claude:matrix.org\""),
            "got {json}"
        );
        assert!(json.contains("\"target\":\"developer-pi\""), "got {json}");
        assert!(
            json.contains("\"invocation_id\":\"inv_01HZ\""),
            "got {json}"
        );
        assert!(json.contains("\"request\":\"exec\""), "got {json}");
        assert!(json.contains("\"decision\":\"allowed\""), "got {json}");
        // Single line.
        assert!(!json.contains('\n'));
    }

    #[test]
    fn deny_record_records_reason_as_rule() {
        let cmd = argv(&["python"]);
        let outcome = Outcome::Deny(DenyReason::CommandNotAllowed {
            command: "python".to_string(),
        });
        let record = AuditRecord::for_exec("!abc", "@a", "t", None, &cmd, &outcome);
        assert_eq!(record.decision, AuditDecision::Denied);
        assert_eq!(record.policy_rule, "deny:command_not_allowed");
        // No invocation id is omitted from the JSON.
        assert!(!record.to_json_line().contains("invocation_id"));
    }

    #[test]
    fn call_record_uses_tool_field() {
        let outcome = Outcome::Deny(DenyReason::ToolNotAllowed {
            tool: "wipe".to_string(),
        });
        let record = AuditRecord::for_call("!abc", "@a", "t", None, "wipe", &outcome);
        let json = record.to_json_line();
        assert!(json.contains("\"request\":\"call\""), "got {json}");
        assert!(json.contains("\"tool\":\"wipe\""), "got {json}");
        assert!(json.contains("\"policy_rule\":\"deny:tool_not_allowed\""));
        assert!(!json.contains("\"command\""), "got {json}");
    }

    #[test]
    fn append_writes_one_line_per_record_and_no_secrets() {
        let dir = std::env::temp_dir().join(format!("mx-audit-{}", std::process::id()));
        let path = dir.join("nested").join(AUDIT_FILE_NAME);
        let log = AuditLog::new(&path);

        let cmd = argv(&["deploy", "--token", "syt_supersecret"]);
        let allowed = AuditRecord::for_exec("!r", "@a", "t", None, &cmd, &allow());
        let denied = AuditRecord::for_call(
            "!r",
            "@a",
            "t",
            None,
            "wipe",
            &Outcome::Deny(DenyReason::ToolNotAllowed {
                tool: "wipe".to_string(),
            }),
        );
        log.append(&allowed).expect("append allowed");
        log.append(&denied).expect("append denied");

        let contents = std::fs::read_to_string(&path).expect("read audit log");
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 2, "one JSON object per line");
        for line in &lines {
            serde_json::from_str::<serde_json::Value>(line).expect("valid JSON line");
        }
        assert!(
            !contents.contains("syt_supersecret"),
            "audit log must not contain secrets: {contents}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn timestamp_is_rfc3339() {
        assert_eq!(unix_to_rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(unix_to_rfc3339(1_700_000_000), "2023-11-14T22:13:20Z");
        let ts = now_rfc3339();
        assert!(ts.ends_with('Z') && ts.len() == 20, "got {ts}");
    }
}
