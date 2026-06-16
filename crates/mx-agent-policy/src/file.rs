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

impl Sandbox {
    /// The stable, lowercase name of this backend, matching the policy
    /// configuration vocabulary. Used to record the selected sandbox in the
    /// audit log (architecture §13.6).
    pub fn name(self) -> &'static str {
        match self {
            Sandbox::None => "none",
            Sandbox::Bubblewrap => "bubblewrap",
            Sandbox::Firejail => "firejail",
            Sandbox::Docker => "docker",
            Sandbox::Podman => "podman",
            Sandbox::Chroot => "chroot",
        }
    }
}

/// The seccomp-bpf syscall-filtering mode applied to a sandboxed command
/// (issue #349).
///
/// Ships **off by default** for the first release so existing deployments do not
/// suddenly start `EPERM`-ing syscalls their commands rely on; the curated
/// `default` profile is opt-in. Only two modes exist — a per-syscall policy DSL
/// or custom profiles are out of scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Seccomp {
    /// No syscall filtering (the default).
    #[default]
    Off,
    /// The built-in curated default-deny allowlist profile.
    Default,
}

impl Seccomp {
    /// The stable, lowercase name of this mode, matching the policy vocabulary.
    pub fn name(self) -> &'static str {
        match self {
            Seccomp::Off => "off",
            Seccomp::Default => "default",
        }
    }
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
    /// Container image the `docker`/`podman` sandbox backends run commands in.
    ///
    /// `None` uses the backend's built-in default (`debian:stable-slim`). The
    /// runtime itself (`docker` vs `podman`) is selected by the `sandbox` value,
    /// not here. Ignored by the `none` and `bubblewrap` backends (issue #310).
    #[serde(default)]
    pub container_image: Option<String>,
    /// Default cap on the sandboxed process count (`RLIMIT_NPROC` on the host
    /// paths, `--pids-limit` for the container backend), unless an agent rule
    /// overrides it. `None` leaves it uncapped (issue #349).
    #[serde(default)]
    pub max_processes: Option<u64>,
    /// Default cap on the sandboxed address space in bytes (`RLIMIT_AS` on the
    /// host paths, `--memory` for the container backend), unless an agent rule
    /// overrides it. `None` leaves it uncapped (issue #349).
    #[serde(default)]
    pub max_memory_bytes: Option<u64>,
    /// Default cap on consumed CPU time in seconds (`RLIMIT_CPU`, distinct from
    /// the wall-clock `max_runtime_ms`), unless an agent rule overrides it. `None`
    /// leaves it uncapped (issue #349).
    #[serde(default)]
    pub max_cpu_seconds: Option<u64>,
    /// Default seccomp-bpf mode applied to sandboxed commands unless an agent rule
    /// overrides it. Defaults to [`Seccomp::Off`] (issue #349).
    #[serde(default)]
    pub seccomp: Seccomp,
    /// Deny an otherwise-allowed execution whose resolved sandbox backend is
    /// `none` (zero isolation), fail-closed (issue #349).
    ///
    /// Execution-scope only (there is no per-agent override). Defaults to `false`,
    /// which preserves backward compatibility: an execution that resolves to the
    /// `none` backend still runs, but the daemon emits a prominent warning. Set to
    /// `true` to turn that warning into a hard `deny:sandbox_required`.
    #[serde(default)]
    pub require_sandbox: bool,
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
    /// Process-count cap overriding `execution.max_processes` (issue #349).
    #[serde(default)]
    pub max_processes: Option<u64>,
    /// Address-space (bytes) cap overriding `execution.max_memory_bytes`
    /// (issue #349).
    #[serde(default)]
    pub max_memory_bytes: Option<u64>,
    /// CPU-seconds cap overriding `execution.max_cpu_seconds` (issue #349).
    #[serde(default)]
    pub max_cpu_seconds: Option<u64>,
    /// Seccomp-bpf mode overriding `execution.seccomp` (issue #349). `None`
    /// inherits the execution default.
    #[serde(default)]
    pub seccomp: Option<Seccomp>,
    /// Require the sending Matrix device to be verified before a privileged
    /// request from this agent executes (issue #240).
    ///
    /// This is an **additive transport check layered after** the authoritative
    /// signature → trust → policy execution gate: when `true`, an otherwise
    /// allowed request is denied (`unverified_device`) unless the originating
    /// Matrix device is verified (directly or via cross-signing). It can only
    /// *deny*, never *grant*; device verification never substitutes for
    /// signing+trust+policy. Default `false`, so existing deployments are
    /// unaffected and older policy files parse unchanged.
    #[serde(default)]
    pub require_verified_device: bool,
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
    /// Require verified sending devices for every agent in this room (issue
    /// #240).
    ///
    /// Room-level default for [`AgentPolicy::require_verified_device`]: when
    /// `true`, the verified-device check applies to every agent in the room even
    /// if their individual rule leaves it `false`. Additive (deny-only) and
    /// default `false`. See [`AgentPolicy::require_verified_device`].
    #[serde(default)]
    pub require_verified_device: bool,
    /// Matrix user ids authorized to decide approvals in this room, in addition
    /// to the daemon's own account (issue #309).
    ///
    /// Empty (the default) preserves the daemon-only behavior: only the host
    /// daemon's own Matrix account may release a held `requires_approval` task. A
    /// configured approver still must publish a decision Ed25519-signed by a key
    /// present in the local trust store; membership here is necessary but never
    /// sufficient. Older policy files without this key parse unchanged.
    #[serde(default)]
    pub approvers: Vec<String>,
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

    /// Load a policy only if the file exists.
    ///
    /// Returns `Ok(None)` when the file is **absent** (the deny-all default
    /// applies — this is the correct, silent fallback), `Ok(Some(policy))` when
    /// the file is present and valid, and `Err(PolicyError)` when the file is
    /// present but cannot be read, parsed, or validated. This lets callers fail
    /// loudly on a malformed policy while still treating a missing file as the
    /// intended deny-all default (issue #350).
    ///
    /// A file that exists but is unreadable (e.g. permission denied) is **not**
    /// "absent" — it is an unusable, present file, so it returns `Err`. Only a
    /// genuine `NotFound` returns `Ok(None)`.
    pub fn load_optional(path: impl AsRef<Path>) -> Result<Option<Self>, PolicyError> {
        let path = path.as_ref();
        match std::fs::read_to_string(path) {
            Ok(input) => Self::parse(&input).map(Some),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(PolicyError::Io {
                path: path.to_path_buf(),
                source: e.to_string(),
            }),
        }
    }

    /// Apply semantic validation rules, returning the first violation with a
    /// precise dotted path.
    pub fn validate(&self) -> Result<(), PolicyError> {
        validate_paths("execution.read_only_paths", &self.execution.read_only_paths)?;
        validate_paths("execution.writable_paths", &self.execution.writable_paths)?;
        validate_sandbox("execution.default_sandbox", self.execution.default_sandbox)?;
        validate_resource_caps(
            "execution",
            self.execution.max_processes,
            self.execution.max_memory_bytes,
            self.execution.max_cpu_seconds,
        )?;

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

            for (idx, approver) in room.approvers.iter().enumerate() {
                if !approver.starts_with('@') {
                    return Err(PolicyError::Validation {
                        path: format!("{room_path}.approvers[{idx}]"),
                        message: format!(
                            "approver id {approver:?} must be a Matrix user id starting with '@'"
                        ),
                    });
                }
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

/// Reject sandbox backends that are named in the policy vocabulary but not
/// implemented, so they can never silently run with zero isolation (issue #310).
///
/// `firejail` and `chroot` parse cleanly but have no backend; mapping them to the
/// `none` backend at dispatch would be a silent downgrade. Failing closed here at
/// load time — with a precise dotted-path error naming the implemented
/// alternatives — surfaces the misconfiguration to the operator instead.
fn validate_sandbox(path: &str, sandbox: Option<Sandbox>) -> Result<(), PolicyError> {
    match sandbox {
        Some(backend @ (Sandbox::Firejail | Sandbox::Chroot)) => Err(PolicyError::Validation {
            path: path.to_string(),
            message: format!(
                "sandbox backend {:?} is not implemented; use \"bubblewrap\", \"docker\", or \"podman\"",
                backend.name()
            ),
        }),
        _ => Ok(()),
    }
}

fn validate_agent(prefix: &str, agent: &AgentPolicy) -> Result<(), PolicyError> {
    validate_paths(&format!("{prefix}.allow_cwd"), &agent.allow_cwd)?;
    validate_sandbox(&format!("{prefix}.sandbox"), agent.sandbox)?;
    validate_resource_caps(
        prefix,
        agent.max_processes,
        agent.max_memory_bytes,
        agent.max_cpu_seconds,
    )?;

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

/// Reject a zero resource cap with a precise dotted path, mirroring the
/// `max_runtime_ms == Some(0)` check: a zero cap is a misconfiguration (it would
/// forbid all work) rather than "uncapped", which is expressed by omitting the
/// key (issue #349).
fn validate_resource_caps(
    prefix: &str,
    max_processes: Option<u64>,
    max_memory_bytes: Option<u64>,
    max_cpu_seconds: Option<u64>,
) -> Result<(), PolicyError> {
    for (value, field) in [
        (max_processes, "max_processes"),
        (max_memory_bytes, "max_memory_bytes"),
        (max_cpu_seconds, "max_cpu_seconds"),
    ] {
        if value == Some(0) {
            return Err(PolicyError::Validation {
                path: format!("{prefix}.{field}"),
                message: format!("{field} must be greater than zero"),
            });
        }
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
    fn execution_container_image_parses() {
        let policy = Policy::parse(
            "[execution]\ndefault_sandbox = \"podman\"\ncontainer_image = \"ghcr.io/acme/ci:1\"\n",
        )
        .expect("policy with container_image parses");
        assert_eq!(
            policy.execution.container_image.as_deref(),
            Some("ghcr.io/acme/ci:1")
        );
        // The image flows into the execution-level confinement floor.
        assert_eq!(
            policy.execution_allowance().container_image.as_deref(),
            Some("ghcr.io/acme/ci:1")
        );
    }

    #[test]
    fn unimplemented_execution_sandbox_is_rejected() {
        // firejail / chroot parse but must fail validation with a precise dotted
        // path, never silently run unsandboxed (issue #310).
        for backend in ["firejail", "chroot"] {
            let err = Policy::parse(&format!("[execution]\ndefault_sandbox = \"{backend}\"\n"))
                .expect_err("unimplemented backend must be rejected");
            match err {
                PolicyError::Validation { path, message } => {
                    assert_eq!(path, "execution.default_sandbox");
                    assert!(message.contains(backend), "message: {message}");
                    assert!(message.contains("not implemented"), "message: {message}");
                }
                other => panic!("expected a Validation error, got {other:?}"),
            }
        }
    }

    #[test]
    fn unimplemented_agent_sandbox_is_rejected() {
        // An agent-level sandbox override must be validated too, with the agent's
        // dotted path (issue #310).
        let toml = "\
[rooms.\"!r:server\"]
trusted = true

[rooms.\"!r:server\".agents.\"@a:server\"]
allow_exec = true
sandbox = \"firejail\"
";
        let err = Policy::parse(toml).expect_err("agent firejail override must be rejected");
        match err {
            PolicyError::Validation { path, message } => {
                assert!(path.ends_with(".sandbox"), "path: {path}");
                assert!(path.contains("@a:server"), "path: {path}");
                assert!(message.contains("firejail"), "message: {message}");
            }
            other => panic!("expected a Validation error, got {other:?}"),
        }
    }

    #[test]
    fn implemented_sandbox_backends_still_validate() {
        for backend in ["none", "bubblewrap", "docker", "podman"] {
            Policy::parse(&format!("[execution]\ndefault_sandbox = \"{backend}\"\n"))
                .unwrap_or_else(|e| panic!("{backend} must validate, got {e:?}"));
        }
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
    fn approvers_parse_and_default_empty() {
        // Configured approvers populate the room field (issue #309).
        let policy = Policy::parse("[rooms.\"!r:s\"]\napprovers = [\"@alice:s\", \"@bob:s\"]\n")
            .expect("approvers parse");
        let room = policy.rooms.get("!r:s").expect("room present");
        assert_eq!(room.approvers, ["@alice:s", "@bob:s"]);

        // Omitting the key keeps the daemon-only default: an empty approver set.
        let bare = Policy::parse("[rooms.\"!r:s\"]\ntrusted = true\n").expect("bare room parses");
        assert!(bare
            .rooms
            .get("!r:s")
            .expect("room present")
            .approvers
            .is_empty());
    }

    #[test]
    fn bad_approver_id_reports_precise_path() {
        let err =
            Policy::parse("[rooms.\"!r:s\"]\napprovers = [\"@ok:s\", \"nope\"]\n").unwrap_err();
        match err {
            PolicyError::Validation { path, message } => {
                assert_eq!(path, "rooms.\"!r:s\".approvers[1]");
                assert!(
                    message.contains("must be a Matrix user id"),
                    "got {message}"
                );
            }
            other => panic!("expected validation error, got {other:?}"),
        }
    }

    #[test]
    fn approvers_empty_string_is_invalid() {
        // An empty string does not start with '@', so it must fail validation
        // with the precise dotted path (issue #309).
        let err = Policy::parse("[rooms.\"!r:s\"]\napprovers = [\"@ok:s\", \"\"]\n").unwrap_err();
        match err {
            PolicyError::Validation { path, message } => {
                assert_eq!(path, "rooms.\"!r:s\".approvers[1]");
                assert!(
                    message.contains("must be a Matrix user id"),
                    "got {message}"
                );
            }
            other => panic!("expected validation error, got {other:?}"),
        }
    }

    #[test]
    fn approvers_default_empty_in_sample_policy() {
        // The SAMPLE policy has no `approvers` key; the field must default to
        // empty, preserving daemon-only behavior for existing policy files (issue
        // #309 backward compat).
        let policy = Policy::parse(SAMPLE).expect("sample policy should parse");
        let room = policy.rooms.get("!abc:matrix.org").expect("room present");
        assert!(
            room.approvers.is_empty(),
            "omitting `approvers` must default to empty (daemon-only behavior)"
        );
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
    fn resource_caps_and_seccomp_parse_at_both_scopes() {
        // Acceptance (issue #349): the new caps + seccomp parse at execution and
        // agent scope, and omitting them keeps the current defaults.
        let toml = r#"
[execution]
max_processes = 256
max_memory_bytes = 2147483648
max_cpu_seconds = 120
seccomp = "default"
require_sandbox = true

[rooms."!r:s"]
trusted = true

[rooms."!r:s".agents."@a:s"]
allow_exec = true
allow_commands = ["cargo"]
allow_cwd = ["/work"]
max_processes = 64
seccomp = "off"
"#;
        let p = Policy::parse(toml).expect("policy parses");
        assert_eq!(p.execution.max_processes, Some(256));
        assert_eq!(p.execution.max_memory_bytes, Some(2_147_483_648));
        assert_eq!(p.execution.max_cpu_seconds, Some(120));
        assert_eq!(p.execution.seccomp, Seccomp::Default);
        assert!(p.execution.require_sandbox);
        let agent = p.rooms["!r:s"].agents["@a:s"].clone();
        assert_eq!(agent.max_processes, Some(64));
        assert_eq!(agent.seccomp, Some(Seccomp::Off));

        // A bare policy keeps the defaults: uncapped, seccomp off, sandbox not
        // required (backward compatible).
        let bare = Policy::parse("[execution]\n").expect("parses");
        assert_eq!(bare.execution.max_processes, None);
        assert_eq!(bare.execution.seccomp, Seccomp::Off);
        assert!(!bare.execution.require_sandbox);
    }

    #[test]
    fn zero_resource_cap_reports_precise_path() {
        for (key, field) in [
            ("max_processes", "execution.max_processes"),
            ("max_memory_bytes", "execution.max_memory_bytes"),
            ("max_cpu_seconds", "execution.max_cpu_seconds"),
        ] {
            let err = Policy::parse(&format!("[execution]\n{key} = 0\n")).unwrap_err();
            match err {
                PolicyError::Validation { path, message } => {
                    assert_eq!(path, field);
                    assert!(message.contains("greater than zero"), "got {message}");
                }
                other => panic!("expected validation error, got {other:?}"),
            }
        }
        // Agent-scope zero caps carry the agent's dotted path. Test all three
        // cap fields at agent scope so the validation loop is fully covered.
        for (key, suffix) in [
            ("max_processes", "max_processes"),
            ("max_memory_bytes", "max_memory_bytes"),
            ("max_cpu_seconds", "max_cpu_seconds"),
        ] {
            let err = Policy::parse(&format!("[rooms.\"!r:s\".agents.\"@a:s\"]\n{key} = 0\n"))
                .unwrap_err();
            match err {
                PolicyError::Validation { path, message } => {
                    assert_eq!(path, format!("rooms.\"!r:s\".agents.\"@a:s\".{suffix}"));
                    assert!(message.contains("greater than zero"), "got {message}");
                }
                other => panic!("expected validation error for {key}, got {other:?}"),
            }
        }
    }

    #[test]
    fn seccomp_name_is_stable() {
        // The policy vocabulary names must match what the engine and docs use.
        assert_eq!(Seccomp::Off.name(), "off");
        assert_eq!(Seccomp::Default.name(), "default");
    }

    #[test]
    fn unknown_seccomp_variant_is_rejected() {
        let err = Policy::parse("[execution]\nseccomp = \"strict\"\n").unwrap_err();
        assert!(matches!(err, PolicyError::Parse(_)), "got {err:?}");
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

    // ── load_optional: absent vs. present-but-broken (issue #350) ────────────

    fn unique_tmp_dir(label: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static CTR: std::sync::atomic::AtomicU64 = AtomicU64::new(0);
        let n = CTR.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "mx-agent-policy-{}-{}-{}",
            label,
            std::process::id(),
            n
        ))
    }

    #[test]
    fn load_optional_absent_file_returns_ok_none() {
        // A path that does not exist must return Ok(None) — the silent deny-all
        // default (absent is fine, issue #350).
        let path = unique_tmp_dir("absent").join("policy.toml");
        let result = Policy::load_optional(&path);
        assert!(
            result.unwrap().is_none(),
            "absent policy file must return Ok(None)"
        );
    }

    #[test]
    fn load_optional_valid_file_returns_ok_some() {
        // A present, well-formed file must return Ok(Some(policy)).
        let dir = unique_tmp_dir("valid");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("policy.toml");
        std::fs::write(&path, "[execution]\nnetwork = \"deny\"\n").unwrap();
        let result = Policy::load_optional(&path);
        let _ = std::fs::remove_dir_all(&dir);
        let policy = result
            .expect("valid file must return Ok")
            .expect("valid file must return Some");
        assert_eq!(policy.execution.network, Some(NetworkPolicy::Deny));
    }

    #[test]
    fn load_optional_malformed_toml_returns_err_parse() {
        // A present file with broken TOML must return Err(Parse) — not Ok(None).
        // This is the "fail loudly" case for issue #350.
        let dir = unique_tmp_dir("malformed-toml");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("policy.toml");
        std::fs::write(&path, "this is not valid toml !! [[[").unwrap();
        let result = Policy::load_optional(&path);
        let _ = std::fs::remove_dir_all(&dir);
        match result.expect_err("malformed TOML must return Err") {
            PolicyError::Parse(_) => {}
            other => panic!("expected Parse error, got {other:?}"),
        }
    }

    #[test]
    fn load_optional_invalid_policy_returns_err_validation() {
        // A present file that is syntactically valid TOML but fails semantic
        // validation (e.g. bad room id) must return Err(Validation), not Ok(None).
        let dir = unique_tmp_dir("invalid-policy");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("policy.toml");
        std::fs::write(&path, "[rooms.\"not-a-room\"]\ntrusted = true\n").unwrap();
        let result = Policy::load_optional(&path);
        let _ = std::fs::remove_dir_all(&dir);
        match result.expect_err("invalid policy must return Err") {
            PolicyError::Validation { .. } => {}
            other => panic!("expected Validation error, got {other:?}"),
        }
    }

    #[test]
    #[cfg(unix)]
    fn load_optional_unreadable_file_returns_err_io() {
        // A present file that cannot be read (permission denied) must return
        // Err(Io) — it is present but unusable, not absent.
        use std::os::unix::fs::PermissionsExt;
        let dir = unique_tmp_dir("unreadable");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("policy.toml");
        std::fs::write(&path, "[execution]\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
        let result = Policy::load_optional(&path);
        // Restore permissions before cleanup.
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644));
        let _ = std::fs::remove_dir_all(&dir);
        match result.expect_err("unreadable file must return Err") {
            PolicyError::Io { .. } => {}
            other => panic!("expected Io error, got {other:?}"),
        }
    }
}
