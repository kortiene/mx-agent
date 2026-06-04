//! Parsing and validation of the mx-agent policy file.
//!
//! The policy file (`~/.config/mx-agent/policy.toml` by default) describes
//! which agents may run which commands or tools in which rooms, together with
//! sandboxing, runtime, and output limits. See `docs/architecture.md` §13.3 for
//! the format.
//!
//! Parsing happens in two stages:
//!
//! 1. Deserialize the TOML into [`Policy`]. The TOML parser reports precise
//!    line/column spans for syntax and type errors, and `deny_unknown_fields`
//!    rejects misspelled keys.
//! 2. [`Policy::validate`] walks the parsed structure and applies semantic
//!    rules (well-formed room/agent identifiers, absolute paths, compilable
//!    `deny_args_regex`, non-zero limits). Each failure carries the dotted
//!    path to the offending field so the operator can find it quickly.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use serde::Deserialize;

/// Default config-relative file name for the policy.
pub const POLICY_FILE_NAME: &str = "policy.toml";

/// Environment variable overriding the config directory used to locate the
/// policy file.
pub const ENV_CONFIG_DIR: &str = "MX_AGENT_CONFIG_DIR";

/// Errors produced while loading, parsing, or validating a policy file.
#[derive(Debug)]
pub enum PolicyError {
    /// The policy file could not be read from disk.
    Io {
        /// Path that was being read.
        path: PathBuf,
        /// Underlying I/O error message.
        source: String,
    },
    /// The policy file is not valid TOML or has a type mismatch. The message
    /// includes the TOML parser's line/column location.
    Parse(String),
    /// The policy parsed but failed a semantic validation rule.
    Validation {
        /// Dotted path to the offending field, e.g.
        /// `rooms."!abc:matrix.org".agents."@a:matrix.org".deny_args_regex[1]`.
        path: String,
        /// Human-readable explanation of what is wrong.
        message: String,
    },
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => {
                write!(f, "failed to read policy file {}: {source}", path.display())
            }
            Self::Parse(msg) => write!(f, "failed to parse policy: {msg}"),
            Self::Validation { path, message } => {
                write!(f, "invalid policy at {path}: {message}")
            }
        }
    }
}

impl std::error::Error for PolicyError {}

/// Whether outbound network access is permitted for an execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkPolicy {
    /// Network access is allowed.
    Allow,
    /// Network access is denied.
    Deny,
}

/// Default behaviour for raw `exec` requests in a room.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RawExecDefault {
    /// Raw exec is allowed unless an agent rule denies it.
    Allow,
    /// Raw exec is denied unless an agent rule allows it.
    Deny,
}

/// Sandbox backend used to isolate executions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Sandbox {
    /// No sandbox (discouraged).
    None,
    /// `bubblewrap` (`bwrap`).
    Bubblewrap,
    /// `firejail`.
    Firejail,
    /// `docker`.
    Docker,
    /// `podman`.
    Podman,
    /// `chroot`.
    Chroot,
}

/// Workspace-wide execution defaults.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionPolicy {
    /// Default sandbox backend applied when an agent does not specify one.
    #[serde(default)]
    pub default_sandbox: Option<Sandbox>,
    /// Default network policy applied when an agent does not specify one.
    #[serde(default)]
    pub network: Option<NetworkPolicy>,
    /// Paths mounted read-only inside the sandbox.
    #[serde(default)]
    pub read_only_paths: Vec<PathBuf>,
    /// Paths the sandboxed process may write to.
    #[serde(default)]
    pub writable_paths: Vec<PathBuf>,
    /// Additional environment variable names a child process may inherit from
    /// the daemon, on top of the built-in safe defaults.
    ///
    /// The child environment is allowlist-based (architecture §13.4): only a
    /// small set of known-safe variables is passed through by default. This
    /// list lets an operator explicitly allow further safe variables (e.g.
    /// `CARGO_HOME`, `RUSTUP_HOME`) without exposing the daemon's secrets. A
    /// name listed here that nonetheless matches a known token variable is
    /// still scrubbed, so the allowlist cannot reintroduce a credential.
    #[serde(default)]
    pub env_allowlist: Vec<String>,
}

/// Per-agent authorization rules within a room.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentPolicy {
    /// Whether raw `exec` is permitted for this agent.
    #[serde(default)]
    pub allow_exec: bool,
    /// Allowlisted `call` tool names.
    #[serde(default)]
    pub allow_tools: Vec<String>,
    /// Allowlisted command basenames for raw `exec`.
    #[serde(default)]
    pub allow_commands: Vec<String>,
    /// Allowlisted working directories (absolute paths).
    #[serde(default)]
    pub allow_cwd: Vec<PathBuf>,
    /// Regular expressions that, if matched against the arguments, deny the
    /// request.
    #[serde(default)]
    pub deny_args_regex: Vec<String>,
    /// Maximum wall-clock runtime in milliseconds.
    #[serde(default)]
    pub max_runtime_ms: Option<u64>,
    /// Maximum captured output in bytes.
    #[serde(default)]
    pub max_output_bytes: Option<u64>,
    /// Whether the request requires interactive approval.
    #[serde(default)]
    pub requires_approval: bool,
    /// Sandbox backend overriding the execution default.
    #[serde(default)]
    pub sandbox: Option<Sandbox>,
    /// Network policy overriding the execution default.
    #[serde(default)]
    pub network: Option<NetworkPolicy>,
}

/// Policy for a single Matrix room.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoomPolicy {
    /// Whether the room is trusted for privileged requests.
    #[serde(default)]
    pub trusted: bool,
    /// Default behaviour for raw `exec` in this room.
    #[serde(default)]
    pub raw_exec_default: Option<RawExecDefault>,
    /// Per-agent rules keyed by Matrix user ID.
    #[serde(default)]
    pub agents: BTreeMap<String, AgentPolicy>,
}

/// A fully parsed and (optionally) validated policy.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// Workspace-wide execution defaults.
    #[serde(default)]
    pub execution: ExecutionPolicy,
    /// Per-room policy keyed by Matrix room ID.
    #[serde(default)]
    pub rooms: BTreeMap<String, RoomPolicy>,
}

impl Policy {
    /// Resolve the default policy file path.
    ///
    /// Precedence: `MX_AGENT_CONFIG_DIR`, then `$XDG_CONFIG_HOME/mx-agent`,
    /// then `$HOME/.config/mx-agent`. Returns `None` if none of these can be
    /// determined.
    pub fn default_path() -> Option<PathBuf> {
        let config_dir = if let Ok(dir) = std::env::var(ENV_CONFIG_DIR) {
            PathBuf::from(dir)
        } else if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
            PathBuf::from(xdg).join("mx-agent")
        } else if let Ok(home) = std::env::var("HOME") {
            PathBuf::from(home).join(".config/mx-agent")
        } else {
            return None;
        };
        Some(config_dir.join(POLICY_FILE_NAME))
    }

    /// Parse a policy from a TOML string and validate it.
    pub fn parse(input: &str) -> Result<Self, PolicyError> {
        let policy: Policy =
            toml::from_str(input).map_err(|e| PolicyError::Parse(e.to_string()))?;
        policy.validate()?;
        Ok(policy)
    }

    /// Load and validate a policy from `path`.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, PolicyError> {
        let path = path.as_ref();
        let input = std::fs::read_to_string(path).map_err(|e| PolicyError::Io {
            path: path.to_path_buf(),
            source: e.to_string(),
        })?;
        Self::parse(&input)
    }

    /// Apply semantic validation rules, returning the first violation with a
    /// precise dotted path.
    pub fn validate(&self) -> Result<(), PolicyError> {
        validate_paths("execution.read_only_paths", &self.execution.read_only_paths)?;
        validate_paths("execution.writable_paths", &self.execution.writable_paths)?;

        if let Some((idx, _)) = self
            .execution
            .env_allowlist
            .iter()
            .enumerate()
            .find(|(_, name)| name.trim().is_empty())
        {
            return Err(PolicyError::Validation {
                path: format!("execution.env_allowlist[{idx}]"),
                message: "environment variable name must not be empty".to_string(),
            });
        }

        for (room_id, room) in &self.rooms {
            let room_path = format!("rooms.{}", quote(room_id));
            if !room_id.starts_with('!') {
                return Err(PolicyError::Validation {
                    path: room_path,
                    message: format!(
                        "room id {room_id:?} must be a Matrix room id starting with '!'"
                    ),
                });
            }

            for (agent_id, agent) in &room.agents {
                let agent_path = format!("{room_path}.agents.{}", quote(agent_id));
                if !agent_id.starts_with('@') {
                    return Err(PolicyError::Validation {
                        path: agent_path,
                        message: format!(
                            "agent id {agent_id:?} must be a Matrix user id starting with '@'"
                        ),
                    });
                }

                validate_agent(&agent_path, agent)?;
            }
        }

        Ok(())
    }
}

fn validate_agent(prefix: &str, agent: &AgentPolicy) -> Result<(), PolicyError> {
    validate_paths(&format!("{prefix}.allow_cwd"), &agent.allow_cwd)?;

    for (idx, pattern) in agent.deny_args_regex.iter().enumerate() {
        if let Err(err) = regex::Regex::new(pattern) {
            return Err(PolicyError::Validation {
                path: format!("{prefix}.deny_args_regex[{idx}]"),
                message: format!("invalid regular expression: {err}"),
            });
        }
    }

    if let Some(name) = agent.allow_tools.iter().find(|name| name.trim().is_empty()) {
        return Err(PolicyError::Validation {
            path: format!("{prefix}.allow_tools"),
            message: format!("tool name {name:?} must not be empty"),
        });
    }

    if let Some(cmd) = agent
        .allow_commands
        .iter()
        .find(|cmd| cmd.trim().is_empty())
    {
        return Err(PolicyError::Validation {
            path: format!("{prefix}.allow_commands"),
            message: format!("command {cmd:?} must not be empty"),
        });
    }

    if agent.max_runtime_ms == Some(0) {
        return Err(PolicyError::Validation {
            path: format!("{prefix}.max_runtime_ms"),
            message: "max_runtime_ms must be greater than zero".to_string(),
        });
    }

    if agent.max_output_bytes == Some(0) {
        return Err(PolicyError::Validation {
            path: format!("{prefix}.max_output_bytes"),
            message: "max_output_bytes must be greater than zero".to_string(),
        });
    }

    Ok(())
}

fn validate_paths(prefix: &str, paths: &[PathBuf]) -> Result<(), PolicyError> {
    for (idx, path) in paths.iter().enumerate() {
        if !path.is_absolute() {
            return Err(PolicyError::Validation {
                path: format!("{prefix}[{idx}]"),
                message: format!("path {} must be absolute", path.display()),
            });
        }
    }
    Ok(())
}

/// Quote a TOML key so the error path matches the file syntax.
fn quote(key: &str) -> String {
    format!("{key:?}")
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
[execution]
default_sandbox = "bubblewrap"
network = "deny"
read_only_paths = ["/usr", "/bin", "/lib"]
writable_paths = ["/home/me/code/project", "/tmp/mx-agent"]

[rooms."!abc:matrix.org"]
trusted = true
raw_exec_default = "deny"

[rooms."!abc:matrix.org".agents."@claude:matrix.org"]
allow_exec = true
allow_tools = ["run_tests", "lint", "read_file"]
allow_commands = ["npm", "pnpm", "pytest", "go", "cargo"]
allow_cwd = ["/home/me/code/project"]
deny_args_regex = [
  "curl\\s+.*\\|\\s*sh",
  "rm\\s+-rf\\s+/",
  "ssh",
  "scp"
]
max_runtime_ms = 900000
max_output_bytes = 5000000
requires_approval = false
sandbox = "bubblewrap"
network = "deny"
"#;

    #[test]
    fn valid_sample_policy_parses() {
        let policy = Policy::parse(SAMPLE).expect("sample policy should parse");

        assert_eq!(policy.execution.network, Some(NetworkPolicy::Deny));
        assert_eq!(policy.execution.default_sandbox, Some(Sandbox::Bubblewrap));
        assert_eq!(policy.execution.read_only_paths.len(), 3);

        let room = policy.rooms.get("!abc:matrix.org").expect("room present");
        assert!(room.trusted);
        assert_eq!(room.raw_exec_default, Some(RawExecDefault::Deny));

        let agent = room
            .agents
            .get("@claude:matrix.org")
            .expect("agent present");
        assert!(agent.allow_exec);
        assert_eq!(agent.allow_tools, ["run_tests", "lint", "read_file"]);
        assert_eq!(agent.allow_commands.len(), 5);
        assert_eq!(agent.deny_args_regex.len(), 4);
        assert_eq!(agent.max_runtime_ms, Some(900_000));
        assert_eq!(agent.max_output_bytes, Some(5_000_000));
        assert!(!agent.requires_approval);
        assert_eq!(agent.sandbox, Some(Sandbox::Bubblewrap));
        assert_eq!(agent.network, Some(NetworkPolicy::Deny));
    }

    #[test]
    fn execution_env_allowlist_parses() {
        let policy =
            Policy::parse("[execution]\nenv_allowlist = [\"CARGO_HOME\", \"RUSTUP_HOME\"]\n")
                .expect("env allowlist parses");
        assert_eq!(
            policy.execution.env_allowlist,
            ["CARGO_HOME", "RUSTUP_HOME"]
        );
    }

    #[test]
    fn empty_env_allowlist_name_reports_precise_path() {
        let err = Policy::parse("[execution]\nenv_allowlist = [\"OK\", \"  \"]\n").unwrap_err();
        match err {
            PolicyError::Validation { path, message } => {
                assert_eq!(path, "execution.env_allowlist[1]");
                assert!(message.contains("must not be empty"), "got {message}");
            }
            other => panic!("expected validation error, got {other:?}"),
        }
    }

    #[test]
    fn empty_policy_is_valid() {
        let policy = Policy::parse("").expect("empty policy parses");
        assert!(policy.rooms.is_empty());
    }

    #[test]
    fn unknown_field_reports_error() {
        let err = Policy::parse("[execution]\nnope = 1\n").unwrap_err();
        assert!(matches!(err, PolicyError::Parse(_)), "got {err:?}");
        assert!(err.to_string().contains("nope"), "got {err}");
    }

    #[test]
    fn invalid_network_value_reports_error() {
        let err = Policy::parse("[execution]\nnetwork = \"maybe\"\n").unwrap_err();
        assert!(matches!(err, PolicyError::Parse(_)), "got {err:?}");
    }

    #[test]
    fn bad_room_id_reports_precise_path() {
        let err = Policy::parse("[rooms.\"not-a-room\"]\ntrusted = true\n").unwrap_err();
        match err {
            PolicyError::Validation { path, message } => {
                assert_eq!(path, "rooms.\"not-a-room\"");
                assert!(
                    message.contains("must be a Matrix room id"),
                    "got {message}"
                );
            }
            other => panic!("expected validation error, got {other:?}"),
        }
    }

    #[test]
    fn bad_agent_id_reports_precise_path() {
        let input = "[rooms.\"!r:matrix.org\".agents.\"nobody\"]\nallow_exec = true\n";
        let err = Policy::parse(input).unwrap_err();
        match err {
            PolicyError::Validation { path, .. } => {
                assert_eq!(path, "rooms.\"!r:matrix.org\".agents.\"nobody\"");
            }
            other => panic!("expected validation error, got {other:?}"),
        }
    }

    #[test]
    fn invalid_regex_reports_precise_path() {
        let input = "[rooms.\"!r:matrix.org\".agents.\"@a:matrix.org\"]\n\
                     deny_args_regex = [\"ok\", \"(unclosed\"]\n";
        let err = Policy::parse(input).unwrap_err();
        match err {
            PolicyError::Validation { path, message } => {
                assert_eq!(
                    path,
                    "rooms.\"!r:matrix.org\".agents.\"@a:matrix.org\".deny_args_regex[1]"
                );
                assert!(
                    message.contains("invalid regular expression"),
                    "got {message}"
                );
            }
            other => panic!("expected validation error, got {other:?}"),
        }
    }

    #[test]
    fn relative_cwd_reports_precise_path() {
        let input = "[rooms.\"!r:matrix.org\".agents.\"@a:matrix.org\"]\n\
                     allow_cwd = [\"/abs\", \"relative/path\"]\n";
        let err = Policy::parse(input).unwrap_err();
        match err {
            PolicyError::Validation { path, message } => {
                assert_eq!(
                    path,
                    "rooms.\"!r:matrix.org\".agents.\"@a:matrix.org\".allow_cwd[1]"
                );
                assert!(message.contains("must be absolute"), "got {message}");
            }
            other => panic!("expected validation error, got {other:?}"),
        }
    }

    #[test]
    fn zero_runtime_reports_precise_path() {
        let input = "[rooms.\"!r:matrix.org\".agents.\"@a:matrix.org\"]\n\
                     max_runtime_ms = 0\n";
        let err = Policy::parse(input).unwrap_err();
        match err {
            PolicyError::Validation { path, .. } => {
                assert_eq!(
                    path,
                    "rooms.\"!r:matrix.org\".agents.\"@a:matrix.org\".max_runtime_ms"
                );
            }
            other => panic!("expected validation error, got {other:?}"),
        }
    }
}
