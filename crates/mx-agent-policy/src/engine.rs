//! Policy decision engine.
//!
//! Given a parsed [`Policy`](crate::Policy) and the context of an incoming
//! `exec`/`call` request, the engine decides whether the request is permitted
//! and, when permitted, returns the resolved runtime/output caps and sandbox
//! settings the caller must enforce before spawning anything.
//!
//! The engine is deny-by-default and purely a pure function over its inputs: it
//! never touches the filesystem, network, or spawns processes. A [`Deny`]
//! outcome therefore guarantees no process is started, because the engine is
//! the gate the runner consults first. See `docs/architecture.md` §13.3.

use std::path::{Path, PathBuf};

use regex::Regex;

use crate::file::{AgentPolicy, NetworkPolicy, Policy, RawExecDefault, RoomPolicy, Sandbox};

/// The outcome of evaluating a request against the policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The request is permitted with the given resolved limits.
    Allow(Allowance),
    /// The request is denied for the given reason.
    Deny(DenyReason),
}

impl Outcome {
    /// Whether this outcome permits the request.
    pub fn is_allowed(&self) -> bool {
        matches!(self, Outcome::Allow(_))
    }

    /// Whether this outcome denies the request.
    pub fn is_denied(&self) -> bool {
        matches!(self, Outcome::Deny(_))
    }

    /// The resolved allowance, if the request was permitted.
    pub fn allowance(&self) -> Option<&Allowance> {
        match self {
            Outcome::Allow(a) => Some(a),
            Outcome::Deny(_) => None,
        }
    }
}

/// Resolved limits and settings for a permitted request.
///
/// The caller (the execution runner) must enforce these before and during the
/// execution: clamp the wall-clock runtime to `max_runtime_ms`, cap captured
/// output at `max_output_bytes`, apply the `sandbox` backend, `network` policy,
/// and filesystem-bind confinement (`read_only_paths` / `writable_paths`), and
/// pause for approval when `requires_approval` is set.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Allowance {
    /// Maximum wall-clock runtime in milliseconds, if capped.
    pub max_runtime_ms: Option<u64>,
    /// Maximum captured output in bytes, if capped.
    pub max_output_bytes: Option<u64>,
    /// Sandbox backend to apply (agent override, else execution default).
    pub sandbox: Option<Sandbox>,
    /// Network policy to apply (agent override, else execution default).
    pub network: Option<NetworkPolicy>,
    /// Whether the request requires interactive approval before running.
    pub requires_approval: bool,
    /// Environment variable names the child may inherit from the daemon beyond
    /// the built-in safe defaults (architecture §13.4). Resolved from
    /// `execution.env_allowlist`; the runner still scrubs any name matching a
    /// known token variable.
    pub env_allowlist: Vec<String>,
    /// Filesystem paths an isolating sandbox binds read-only (architecture
    /// §13.5). Resolved from `execution.read_only_paths`. Ignored by the `none`
    /// backend.
    pub read_only_paths: Vec<PathBuf>,
    /// Filesystem paths an isolating sandbox binds writable (architecture
    /// §13.5). Resolved from `execution.writable_paths`. Ignored by the `none`
    /// backend.
    pub writable_paths: Vec<PathBuf>,
    /// Whether the request additionally requires the sending Matrix device to be
    /// verified before it may execute (issue #240).
    ///
    /// Resolved as the room-level default OR the agent rule. This is an additive
    /// transport check the caller applies *after* the (authoritative) execution
    /// gate; it can only deny, never grant. See
    /// [`AgentPolicy::require_verified_device`](crate::AgentPolicy::require_verified_device).
    pub require_verified_device: bool,
    /// Container image the `docker`/`podman` backend runs the command in, if the
    /// operator configured one (`execution.container_image`). `None` uses the
    /// backend's built-in default image. Ignored by the `none`/`bubblewrap`
    /// backends (issue #310).
    pub container_image: Option<String>,
}

/// Machine-readable reason a request was denied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DenyReason {
    /// No policy entry exists for the requesting room.
    UnknownRoom,
    /// The room is not trusted for privileged (raw `exec`) requests.
    UntrustedRoom,
    /// No policy entry exists for the requesting agent in this room.
    UnknownAgent,
    /// The command argv was empty.
    EmptyCommand,
    /// Raw `exec` is not permitted for this agent/room.
    ExecNotAllowed,
    /// The command basename is not in the allowlist.
    CommandNotAllowed {
        /// The rejected command (as supplied).
        command: String,
    },
    /// The requested working directory is not within an allowed directory.
    CwdNotAllowed {
        /// The rejected working directory.
        cwd: String,
    },
    /// A `deny_args_regex` pattern matched the request arguments.
    DeniedArguments {
        /// The pattern that triggered the denial.
        pattern: String,
    },
    /// The requested tool is not in the allowlist.
    ToolNotAllowed {
        /// The rejected tool name.
        tool: String,
    },
}

impl std::fmt::Display for DenyReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownRoom => write!(f, "no policy for requesting room"),
            Self::UntrustedRoom => write!(f, "room is not trusted for raw exec"),
            Self::UnknownAgent => write!(f, "no policy for requesting agent in this room"),
            Self::EmptyCommand => write!(f, "command argv is empty"),
            Self::ExecNotAllowed => write!(f, "raw exec is not permitted"),
            Self::CommandNotAllowed { command } => {
                write!(f, "command {command:?} is not allowlisted")
            }
            Self::CwdNotAllowed { cwd } => {
                write!(f, "working directory {cwd:?} is not allowlisted")
            }
            Self::DeniedArguments { pattern } => {
                write!(f, "arguments matched deny pattern {pattern:?}")
            }
            Self::ToolNotAllowed { tool } => write!(f, "tool {tool:?} is not allowlisted"),
        }
    }
}

/// Context for evaluating a raw `exec` request.
#[derive(Debug, Clone)]
pub struct ExecContext<'a> {
    /// Matrix room id the request arrived in.
    pub room_id: &'a str,
    /// Matrix user id of the requesting agent.
    pub requesting_agent: &'a str,
    /// Command argv (program followed by arguments).
    pub command: &'a [String],
    /// Requested working directory.
    pub cwd: &'a str,
}

/// Context for evaluating a `call` (named tool) request.
#[derive(Debug, Clone)]
pub struct CallContext<'a> {
    /// Matrix room id the request arrived in.
    pub room_id: &'a str,
    /// Matrix user id of the requesting agent.
    pub requesting_agent: &'a str,
    /// Tool name being invoked.
    pub tool: &'a str,
}

impl Policy {
    /// Evaluate a raw `exec` request.
    ///
    /// Raw exec is privileged: it requires a trusted room, an explicit agent
    /// rule permitting exec, an allowlisted command basename and working
    /// directory, and must not match any `deny_args_regex` pattern.
    pub fn evaluate_exec(&self, ctx: &ExecContext<'_>) -> Outcome {
        let (room, agent) = match self.lookup(ctx.room_id, ctx.requesting_agent) {
            Ok(pair) => pair,
            Err(reason) => return Outcome::Deny(reason),
        };

        if ctx.command.is_empty() {
            return Outcome::Deny(DenyReason::EmptyCommand);
        }

        // Requester permission: raw exec must be explicitly enabled, either by
        // the agent rule or the room's raw_exec_default.
        let exec_allowed =
            agent.allow_exec || matches!(room.raw_exec_default, Some(RawExecDefault::Allow));
        if !exec_allowed {
            return Outcome::Deny(DenyReason::ExecNotAllowed);
        }

        // Room trust gate for privileged execution.
        if !room.trusted {
            return Outcome::Deny(DenyReason::UntrustedRoom);
        }

        // Allowlisted command basename (deny-by-default: empty list allows
        // nothing).
        let program = &ctx.command[0];
        if !command_allowed(program, &agent.allow_commands) {
            return Outcome::Deny(DenyReason::CommandNotAllowed {
                command: program.clone(),
            });
        }

        // Allowlisted working directory (deny-by-default).
        if !cwd_allowed(ctx.cwd, &agent.allow_cwd) {
            return Outcome::Deny(DenyReason::CwdNotAllowed {
                cwd: ctx.cwd.to_string(),
            });
        }

        // Deny patterns against the full argv.
        if let Some(pattern) = matched_deny_pattern(ctx.command, &agent.deny_args_regex) {
            return Outcome::Deny(DenyReason::DeniedArguments { pattern });
        }

        Outcome::Allow(self.allowance_for(room, agent))
    }

    /// Evaluate a `call` (named tool) request.
    ///
    /// A tool is permitted only when it appears in the agent's `allow_tools`
    /// list for the requesting room.
    pub fn evaluate_call(&self, ctx: &CallContext<'_>) -> Outcome {
        let (room, agent) = match self.lookup(ctx.room_id, ctx.requesting_agent) {
            Ok(pair) => pair,
            Err(reason) => return Outcome::Deny(reason),
        };

        if !agent.allow_tools.iter().any(|t| t == ctx.tool) {
            return Outcome::Deny(DenyReason::ToolNotAllowed {
                tool: ctx.tool.to_string(),
            });
        }

        Outcome::Allow(self.allowance_for(room, agent))
    }

    /// Build an [`Allowance`] carrying only the workspace-wide execution-level
    /// defaults — `default_sandbox`, `network`, `env_allowlist`, and the
    /// read-only / writable filesystem binds — with no per-agent gate.
    ///
    /// This is for local, already-trusted execution paths (e.g. the CLI `call`
    /// loopback) that have no remote requester to evaluate but must still apply
    /// the operator's configured confinement and environment scrubbing
    /// (architecture §13.4, §13.5), rather than running with the daemon's full
    /// inherited environment and no sandbox. Per-request limits that only exist
    /// for an agent rule (`max_runtime_ms`, `max_output_bytes`,
    /// `requires_approval`, `require_verified_device`) are left at their
    /// defaults.
    pub fn execution_allowance(&self) -> Allowance {
        Allowance {
            sandbox: self.execution.default_sandbox,
            network: self.execution.network,
            env_allowlist: self.execution.env_allowlist.clone(),
            read_only_paths: self.execution.read_only_paths.clone(),
            writable_paths: self.execution.writable_paths.clone(),
            container_image: self.execution.container_image.clone(),
            ..Allowance::default()
        }
    }

    /// Resolve the room/agent rule pair, mapping missing entries to a deny
    /// reason.
    fn lookup(
        &self,
        room_id: &str,
        agent_id: &str,
    ) -> Result<(&RoomPolicy, &AgentPolicy), DenyReason> {
        let room = self.rooms.get(room_id).ok_or(DenyReason::UnknownRoom)?;
        let agent = room.agents.get(agent_id).ok_or(DenyReason::UnknownAgent)?;
        Ok((room, agent))
    }

    /// Resolve the effective limits for a permitted request, applying execution
    /// defaults where the agent rule does not override them.
    fn allowance_for(&self, room: &RoomPolicy, agent: &AgentPolicy) -> Allowance {
        Allowance {
            max_runtime_ms: agent.max_runtime_ms,
            max_output_bytes: agent.max_output_bytes,
            sandbox: agent.sandbox.or(self.execution.default_sandbox),
            network: agent.network.or(self.execution.network),
            requires_approval: agent.requires_approval,
            env_allowlist: self.execution.env_allowlist.clone(),
            read_only_paths: self.execution.read_only_paths.clone(),
            writable_paths: self.execution.writable_paths.clone(),
            container_image: self.execution.container_image.clone(),
            // The verified-device requirement applies if either the room default
            // or the agent rule sets it (issue #240).
            require_verified_device: room.require_verified_device || agent.require_verified_device,
        }
    }
}

/// Whether `program` is permitted by `allow_commands`.
///
/// A command matches if its full path equals an allowlist entry or its file
/// basename equals an allowlist entry (which may itself be a bare name or a
/// path). An empty allowlist permits nothing.
fn command_allowed(program: &str, allow_commands: &[String]) -> bool {
    let program_base = basename(program);
    allow_commands
        .iter()
        .any(|allowed| allowed == program || basename(allowed) == program_base)
}

/// Whether `cwd` is within one of the allowed directories. An empty allowlist
/// permits nothing.
fn cwd_allowed(cwd: &str, allow_cwd: &[std::path::PathBuf]) -> bool {
    let cwd_path = Path::new(cwd);
    // Only absolute working directories can be safely matched against the
    // absolute allowlist entries.
    if !cwd_path.is_absolute() {
        return false;
    }
    allow_cwd
        .iter()
        .any(|allowed| cwd_path.starts_with(allowed))
}

/// Return the first `deny_args_regex` pattern that matches any token of the
/// command, or the whitespace-joined command line.
fn matched_deny_pattern(command: &[String], deny_args_regex: &[String]) -> Option<String> {
    if deny_args_regex.is_empty() {
        return None;
    }
    let joined = command.join(" ");
    for pattern in deny_args_regex {
        // Patterns are validated at parse time, so compilation should not fail;
        // if it somehow does, fail safe by treating it as a match (deny).
        let re = match Regex::new(pattern) {
            Ok(re) => re,
            Err(_) => return Some(pattern.clone()),
        };
        if re.is_match(&joined) || command.iter().any(|arg| re.is_match(arg)) {
            return Some(pattern.clone());
        }
    }
    None
}

/// Final path component of a path-like string.
fn basename(s: &str) -> &str {
    Path::new(s)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOM: &str = "!abc:matrix.org";
    const AGENT: &str = "@claude:matrix.org";

    fn policy() -> Policy {
        let toml = r#"
[execution]
default_sandbox = "bubblewrap"
network = "deny"

[rooms."!abc:matrix.org"]
trusted = true
raw_exec_default = "deny"

[rooms."!abc:matrix.org".agents."@claude:matrix.org"]
allow_exec = true
allow_tools = ["run_tests", "lint"]
allow_commands = ["cargo", "/usr/bin/git"]
allow_cwd = ["/home/me/code/project"]
deny_args_regex = ["rm\\s+-rf\\s+/", "ssh"]
max_runtime_ms = 900000
max_output_bytes = 5000000
requires_approval = false
"#;
        Policy::parse(toml).expect("policy parses")
    }

    fn exec<'a>(command: &'a [String], cwd: &'a str) -> ExecContext<'a> {
        ExecContext {
            room_id: ROOM,
            requesting_agent: AGENT,
            command,
            cwd,
        }
    }

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn exec_allowed_command_in_allowed_cwd() {
        let p = policy();
        let cmd = argv(&["cargo", "test"]);
        let outcome = p.evaluate_exec(&exec(&cmd, "/home/me/code/project"));
        assert!(outcome.is_allowed(), "got {outcome:?}");
        let a = outcome.allowance().unwrap();
        assert_eq!(a.max_runtime_ms, Some(900_000));
        assert_eq!(a.max_output_bytes, Some(5_000_000));
        assert_eq!(a.sandbox, Some(Sandbox::Bubblewrap));
        assert_eq!(a.network, Some(NetworkPolicy::Deny));
        assert!(!a.requires_approval);
    }

    #[test]
    fn allowance_carries_execution_env_allowlist() {
        // policy() defines no env_allowlist, so the resolved allowance is empty.
        let p = policy();
        let cmd = argv(&["cargo", "test"]);
        let a = p
            .evaluate_exec(&exec(&cmd, "/home/me/code/project"))
            .allowance()
            .unwrap()
            .clone();
        assert!(a.env_allowlist.is_empty());

        // An explicit execution.env_allowlist flows through to the allowance so
        // the runner can pass those safe vars to the child.
        let toml = r#"
[execution]
env_allowlist = ["CARGO_HOME", "RUSTUP_HOME"]

[rooms."!abc:matrix.org"]
trusted = true

[rooms."!abc:matrix.org".agents."@claude:matrix.org"]
allow_exec = true
allow_commands = ["cargo"]
allow_cwd = ["/home/me/code/project"]
"#;
        let p = Policy::parse(toml).expect("policy parses");
        let a = p
            .evaluate_exec(&exec(&cmd, "/home/me/code/project"))
            .allowance()
            .unwrap()
            .clone();
        assert_eq!(a.env_allowlist, ["CARGO_HOME", "RUSTUP_HOME"]);
    }

    #[test]
    fn execution_allowance_carries_execution_defaults_without_agent_gate() {
        let toml = r#"
[execution]
default_sandbox = "bubblewrap"
network = "deny"
env_allowlist = ["CARGO_HOME"]
read_only_paths = ["/usr"]
writable_paths = ["/work"]
"#;
        let p = Policy::parse(toml).expect("policy parses");
        let a = p.execution_allowance();
        assert_eq!(a.sandbox, Some(Sandbox::Bubblewrap));
        assert_eq!(a.network, Some(NetworkPolicy::Deny));
        assert_eq!(a.env_allowlist, vec!["CARGO_HOME".to_string()]);
        assert_eq!(a.read_only_paths, vec![std::path::PathBuf::from("/usr")]);
        assert_eq!(a.writable_paths, vec![std::path::PathBuf::from("/work")]);
        // No per-agent rule means no per-request limits or gates.
        assert_eq!(a.max_runtime_ms, None);
        assert!(!a.requires_approval);
        assert!(!a.require_verified_device);
    }

    #[test]
    fn execution_allowance_defaults_are_empty_and_fail_closed() {
        // An empty policy yields no sandbox/network override; the daemon's
        // `network_for(None)` then fails closed to deny.
        let a = Policy::default().execution_allowance();
        assert_eq!(a.sandbox, None);
        assert_eq!(a.network, None);
        assert!(a.env_allowlist.is_empty());
        assert!(a.read_only_paths.is_empty());
        assert!(a.writable_paths.is_empty());
    }

    #[test]
    fn exec_allows_command_in_subdirectory_of_allowed_cwd() {
        let p = policy();
        let cmd = argv(&["cargo", "build"]);
        let outcome = p.evaluate_exec(&exec(&cmd, "/home/me/code/project/crates/foo"));
        assert!(outcome.is_allowed(), "got {outcome:?}");
    }

    #[test]
    fn exec_allows_command_by_full_path_via_basename() {
        let p = policy();
        let cmd = argv(&["git", "status"]);
        let outcome = p.evaluate_exec(&exec(&cmd, "/home/me/code/project"));
        assert!(outcome.is_allowed(), "got {outcome:?}");
    }

    #[test]
    fn exec_denied_unknown_room() {
        let p = policy();
        let cmd = argv(&["cargo"]);
        let outcome = p.evaluate_exec(&ExecContext {
            room_id: "!other:matrix.org",
            requesting_agent: AGENT,
            command: &cmd,
            cwd: "/home/me/code/project",
        });
        assert_eq!(outcome, Outcome::Deny(DenyReason::UnknownRoom));
    }

    #[test]
    fn exec_denied_unknown_agent() {
        let p = policy();
        let cmd = argv(&["cargo"]);
        let outcome = p.evaluate_exec(&ExecContext {
            room_id: ROOM,
            requesting_agent: "@mallory:matrix.org",
            command: &cmd,
            cwd: "/home/me/code/project",
        });
        assert_eq!(outcome, Outcome::Deny(DenyReason::UnknownAgent));
    }

    #[test]
    fn exec_denied_empty_command() {
        let p = policy();
        let cmd: Vec<String> = Vec::new();
        let outcome = p.evaluate_exec(&exec(&cmd, "/home/me/code/project"));
        assert_eq!(outcome, Outcome::Deny(DenyReason::EmptyCommand));
    }

    #[test]
    fn exec_denied_command_not_allowlisted() {
        let p = policy();
        let cmd = argv(&["python", "evil.py"]);
        let outcome = p.evaluate_exec(&exec(&cmd, "/home/me/code/project"));
        assert_eq!(
            outcome,
            Outcome::Deny(DenyReason::CommandNotAllowed {
                command: "python".to_string()
            })
        );
    }

    #[test]
    fn exec_denied_cwd_not_allowlisted() {
        let p = policy();
        let cmd = argv(&["cargo", "test"]);
        let outcome = p.evaluate_exec(&exec(&cmd, "/etc"));
        assert_eq!(
            outcome,
            Outcome::Deny(DenyReason::CwdNotAllowed {
                cwd: "/etc".to_string()
            })
        );
    }

    #[test]
    fn exec_denied_relative_cwd() {
        let p = policy();
        let cmd = argv(&["cargo", "test"]);
        let outcome = p.evaluate_exec(&exec(&cmd, "relative/dir"));
        assert!(matches!(
            outcome,
            Outcome::Deny(DenyReason::CwdNotAllowed { .. })
        ));
    }

    #[test]
    fn exec_denied_by_args_regex() {
        let p = policy();
        let cmd = argv(&["cargo", "run", "--", "rm", "-rf", "/"]);
        let outcome = p.evaluate_exec(&exec(&cmd, "/home/me/code/project"));
        assert!(matches!(
            outcome,
            Outcome::Deny(DenyReason::DeniedArguments { .. })
        ));
    }

    #[test]
    fn exec_denied_by_args_regex_single_token() {
        let p = policy();
        let cmd = argv(&["cargo", "ssh"]);
        let outcome = p.evaluate_exec(&exec(&cmd, "/home/me/code/project"));
        assert_eq!(
            outcome,
            Outcome::Deny(DenyReason::DeniedArguments {
                pattern: "ssh".to_string()
            })
        );
    }

    #[test]
    fn exec_denied_when_agent_disallows_exec() {
        let toml = r#"
[rooms."!abc:matrix.org"]
trusted = true

[rooms."!abc:matrix.org".agents."@claude:matrix.org"]
allow_exec = false
allow_commands = ["cargo"]
allow_cwd = ["/home/me/code/project"]
"#;
        let p = Policy::parse(toml).unwrap();
        let cmd = argv(&["cargo", "test"]);
        let outcome = p.evaluate_exec(&exec(&cmd, "/home/me/code/project"));
        assert_eq!(outcome, Outcome::Deny(DenyReason::ExecNotAllowed));
    }

    #[test]
    fn exec_allowed_via_room_raw_exec_default() {
        let toml = r#"
[rooms."!abc:matrix.org"]
trusted = true
raw_exec_default = "allow"

[rooms."!abc:matrix.org".agents."@claude:matrix.org"]
allow_exec = false
allow_commands = ["cargo"]
allow_cwd = ["/home/me/code/project"]
"#;
        let p = Policy::parse(toml).unwrap();
        let cmd = argv(&["cargo", "test"]);
        let outcome = p.evaluate_exec(&exec(&cmd, "/home/me/code/project"));
        assert!(outcome.is_allowed(), "got {outcome:?}");
    }

    #[test]
    fn exec_denied_when_room_untrusted() {
        let toml = r#"
[rooms."!abc:matrix.org"]
trusted = false

[rooms."!abc:matrix.org".agents."@claude:matrix.org"]
allow_exec = true
allow_commands = ["cargo"]
allow_cwd = ["/home/me/code/project"]
"#;
        let p = Policy::parse(toml).unwrap();
        let cmd = argv(&["cargo", "test"]);
        let outcome = p.evaluate_exec(&exec(&cmd, "/home/me/code/project"));
        assert_eq!(outcome, Outcome::Deny(DenyReason::UntrustedRoom));
    }

    #[test]
    fn call_allowed_for_allowlisted_tool() {
        let p = policy();
        let outcome = p.evaluate_call(&CallContext {
            room_id: ROOM,
            requesting_agent: AGENT,
            tool: "run_tests",
        });
        assert!(outcome.is_allowed(), "got {outcome:?}");
    }

    #[test]
    fn call_denied_for_unknown_tool() {
        let p = policy();
        let outcome = p.evaluate_call(&CallContext {
            room_id: ROOM,
            requesting_agent: AGENT,
            tool: "delete_everything",
        });
        assert_eq!(
            outcome,
            Outcome::Deny(DenyReason::ToolNotAllowed {
                tool: "delete_everything".to_string()
            })
        );
    }

    #[test]
    fn call_denied_for_unknown_room() {
        let p = policy();
        let outcome = p.evaluate_call(&CallContext {
            room_id: "!nope:matrix.org",
            requesting_agent: AGENT,
            tool: "run_tests",
        });
        assert_eq!(outcome, Outcome::Deny(DenyReason::UnknownRoom));
    }

    #[test]
    fn call_denied_for_unknown_agent() {
        let p = policy();
        let outcome = p.evaluate_call(&CallContext {
            room_id: ROOM,
            requesting_agent: "@mallory:matrix.org",
            tool: "run_tests",
        });
        assert_eq!(outcome, Outcome::Deny(DenyReason::UnknownAgent));
    }

    #[test]
    fn empty_policy_denies_everything() {
        let p = Policy::default();
        let cmd = argv(&["cargo"]);
        assert!(p
            .evaluate_exec(&exec(&cmd, "/home/me/code/project"))
            .is_denied());
        assert!(p
            .evaluate_call(&CallContext {
                room_id: ROOM,
                requesting_agent: AGENT,
                tool: "run_tests",
            })
            .is_denied());
    }

    // --- sandbox path/network wiring (issue #248) ---

    #[test]
    fn allowance_carries_read_only_and_writable_paths() {
        // `execution.read_only_paths`/`writable_paths` parsed in the policy file
        // must appear on the resolved `Allowance` so the runner can bind them.
        let toml = r#"
[execution]
read_only_paths = ["/usr", "/lib"]
writable_paths = ["/work"]

[rooms."!abc:matrix.org"]
trusted = true

[rooms."!abc:matrix.org".agents."@claude:matrix.org"]
allow_exec = true
allow_commands = ["cargo"]
allow_cwd = ["/work"]
"#;
        let p = Policy::parse(toml).expect("policy parses");
        let cmd = argv(&["cargo", "test"]);
        let a = p
            .evaluate_exec(&ExecContext {
                room_id: ROOM,
                requesting_agent: AGENT,
                command: &cmd,
                cwd: "/work",
            })
            .allowance()
            .unwrap()
            .clone();
        assert_eq!(
            a.read_only_paths,
            vec![PathBuf::from("/usr"), PathBuf::from("/lib")],
            "read_only_paths must flow through allowance_for"
        );
        assert_eq!(
            a.writable_paths,
            vec![PathBuf::from("/work")],
            "writable_paths must flow through allowance_for"
        );
    }

    #[test]
    fn allowance_has_empty_paths_when_not_configured() {
        // When the policy omits read_only_paths/writable_paths the allowance must
        // carry empty vectors so the runner applies no bind-mounts.
        let p = policy();
        let cmd = argv(&["cargo", "test"]);
        let a = p
            .evaluate_exec(&exec(&cmd, "/home/me/code/project"))
            .allowance()
            .unwrap()
            .clone();
        assert!(
            a.read_only_paths.is_empty(),
            "read_only_paths must be empty when not configured"
        );
        assert!(
            a.writable_paths.is_empty(),
            "writable_paths must be empty when not configured"
        );
    }

    // --- require_verified_device (issue #240) ---

    #[test]
    fn require_verified_device_defaults_false_and_is_backward_compatible() {
        // policy() sets no require_verified_device anywhere, and the sample is a
        // pre-existing policy file shape, so it must parse and resolve `false`.
        let p = policy();
        let cmd = argv(&["cargo", "test"]);
        let a = p
            .evaluate_exec(&exec(&cmd, "/home/me/code/project"))
            .allowance()
            .unwrap()
            .clone();
        assert!(
            !a.require_verified_device,
            "verified-device requirement must default off"
        );
    }

    #[test]
    fn require_verified_device_resolves_from_agent_or_room() {
        // Agent-level opt-in.
        let agent_toml = r#"
[rooms."!abc:matrix.org"]
trusted = true

[rooms."!abc:matrix.org".agents."@claude:matrix.org"]
allow_exec = true
allow_commands = ["cargo"]
allow_cwd = ["/home/me/code/project"]
require_verified_device = true
"#;
        let p = Policy::parse(agent_toml).expect("policy parses");
        let cmd = argv(&["cargo", "test"]);
        assert!(
            p.evaluate_exec(&exec(&cmd, "/home/me/code/project"))
                .allowance()
                .unwrap()
                .require_verified_device
        );

        // Room-level default applies even when the agent rule omits it.
        let room_toml = r#"
[rooms."!abc:matrix.org"]
trusted = true
require_verified_device = true

[rooms."!abc:matrix.org".agents."@claude:matrix.org"]
allow_exec = true
allow_commands = ["cargo"]
allow_cwd = ["/home/me/code/project"]
"#;
        let p = Policy::parse(room_toml).expect("policy parses");
        assert!(
            p.evaluate_exec(&exec(&cmd, "/home/me/code/project"))
                .allowance()
                .unwrap()
                .require_verified_device
        );
    }

    // --- requires_approval flag on the call surface (issue #263) ---

    #[test]
    fn call_allowance_carries_requires_approval_true_when_policy_demands_it() {
        // The policy engine must propagate `requires_approval = true` from the
        // agent rule through `evaluate_call` → `allowance_for` → returned
        // `Allowance`.  This is the critical glue: the daemon's disposition gate
        // reads `allowance.requires_approval` to decide whether to hold the call;
        // if the flag is lost here the gate can never fire.
        let toml = r#"
[rooms."!abc:matrix.org"]
trusted = true

[rooms."!abc:matrix.org".agents."@claude:matrix.org"]
allow_tools = ["deploy"]
requires_approval = true
"#;
        let p = Policy::parse(toml).expect("policy parses");
        let outcome = p.evaluate_call(&CallContext {
            room_id: ROOM,
            requesting_agent: AGENT,
            tool: "deploy",
        });
        let allowance = outcome
            .allowance()
            .expect("deploy is in allow_tools, so the call must be allowed");
        assert!(
            allowance.requires_approval,
            "evaluate_call must propagate requires_approval = true from the agent rule"
        );
    }

    #[test]
    fn call_allowance_requires_approval_defaults_false() {
        // Regression: when the policy does not set `requires_approval`, the flag
        // must be false so existing calls continue to execute immediately.
        let p = policy(); // policy() sets requires_approval = false explicitly
        let outcome = p.evaluate_call(&CallContext {
            room_id: ROOM,
            requesting_agent: AGENT,
            tool: "run_tests",
        });
        let allowance = outcome.allowance().expect("run_tests is allowed");
        assert!(
            !allowance.requires_approval,
            "requires_approval must default false so ordinary calls are not held"
        );
    }

    #[test]
    fn allowance_network_resolves_agent_override_then_execution_default() {
        // Agent-level `network` overrides the execution-level default.
        let toml = r#"
[execution]
network = "deny"

[rooms."!abc:matrix.org"]
trusted = true

[rooms."!abc:matrix.org".agents."@claude:matrix.org"]
allow_exec = true
allow_commands = ["cargo"]
allow_cwd = ["/home/me/code/project"]
network = "allow"
"#;
        let p = Policy::parse(toml).expect("policy parses");
        let cmd = argv(&["cargo", "test"]);
        let a = p
            .evaluate_exec(&exec(&cmd, "/home/me/code/project"))
            .allowance()
            .unwrap()
            .clone();
        assert_eq!(
            a.network,
            Some(NetworkPolicy::Allow),
            "agent-level network must override the execution default"
        );
    }
}
