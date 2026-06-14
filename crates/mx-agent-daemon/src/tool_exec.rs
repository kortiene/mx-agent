//! Execution of built-in tools (architecture §5.2).
//!
//! [`crate::tools`] defines the *schemas* an agent advertises; this module
//! actually *runs* the built-in tools when a [`CallRequest`] is authorized
//! (see [`crate::call`]). Each tool validates its JSON input against the
//! expectations encoded in its schema, executes a well-known operation, and
//! returns a structured [`ToolResult`] carrying the process exit code and a
//! human-readable summary.
//!
//! Tools are the preferred security boundary over raw `exec`: callers cannot
//! inject arbitrary shell, only the typed arguments each tool declares. They are
//! also confined *at least as strictly as* `exec`: every built-in tool is spawned
//! through the same [`crate::runner`] pipeline (`RunSpec` → `build_command` →
//! `sandbox_for(...).prepare(...)`), so it inherits the policy-resolved sandbox
//! backend, network decision, filesystem binds, and the sanitized environment
//! that strips the daemon's secrets (architecture §5.2, §13.4, §13.5). The
//! resolved [`Allowance`](mx_agent_policy::Allowance) is threaded into execution
//! rather than discarded.

use std::path::PathBuf;
use std::time::Duration;

use serde::Serialize;
use serde_json::{json, Value};

use crate::runner::{RunError, RunSpec, DEFAULT_GRACE_PERIOD};

/// The built-in `run_tests` tool name.
pub const RUN_TESTS: &str = "run_tests";

/// The built-in `lint` tool name.
pub const LINT: &str = "lint";

/// Structured outcome of a successful tool execution.
///
/// This mirrors the `output_schema` advertised by the built-in tools: an
/// integer `exit_code` plus a human-readable `summary`. It serializes directly
/// into the `result` field of a `com.mxagent.call.response.v1`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ToolResult {
    /// The exit code of the underlying process (0 on success).
    pub exit_code: i32,
    /// A short, human-readable summary of what happened.
    pub summary: String,
}

impl ToolResult {
    /// Whether the tool reported success (exit code 0).
    pub fn is_success(&self) -> bool {
        self.exit_code == 0
    }

    /// Serialize the result into the JSON shape advertised by the tool's
    /// `output_schema`.
    pub fn to_value(&self) -> Value {
        json!({ "exit_code": self.exit_code, "summary": self.summary })
    }
}

/// Why a tool could not be executed.
///
/// These describe failures to *invoke* a tool (unknown tool, bad arguments, or
/// a spawn failure), as distinct from a tool that ran and reported a nonzero
/// exit code — that is a successful execution returning a [`ToolResult`].
#[derive(Debug)]
pub enum ToolError {
    /// No built-in tool is registered under this name.
    UnknownTool(String),
    /// The provided arguments did not satisfy the tool's input schema.
    InvalidArgs(String),
    /// The tool's underlying process could not be spawned.
    Spawn(std::io::Error),
}

impl std::fmt::Display for ToolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownTool(name) => write!(f, "unknown tool {name:?}"),
            Self::InvalidArgs(msg) => write!(f, "invalid tool arguments: {msg}"),
            Self::Spawn(err) => write!(f, "could not run tool: {err}"),
        }
    }
}

impl std::error::Error for ToolError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Spawn(err) => Some(err),
            _ => None,
        }
    }
}

/// Build the confined [`RunSpec`] for a built-in tool invocation.
///
/// Validates `args` via the tool's existing command builder, then wraps the
/// resulting `(program, argv)` in a [`RunSpec`] carrying the policy-resolved
/// confinement: the sandbox backend ([`crate::exec::sandbox_backend`]), the
/// network decision ([`crate::exec::network_for`], fail-closed `deny`), the
/// read-only / writable filesystem binds, and the env allowlist that drives
/// `sanitize_env`. The runner spawns this exactly like a raw `exec`, so a named
/// tool is confined at least as strictly as `exec` (architecture §13.5).
///
/// Pure and side-effect-free (the `cwd` is resolved by the caller) so tests can
/// assert the resulting spec without spawning a process. Unknown-tool /
/// invalid-args validation happens here, before any runtime is spun up.
///
/// Under an isolating sandbox the `cwd` must be inside the configured
/// `writable_paths` for the tool to do anything useful — that is an operator
/// configuration concern, not enforced here.
fn tool_run_spec(
    name: &str,
    args: &Value,
    allowance: &mx_agent_policy::Allowance,
    cwd: PathBuf,
) -> Result<RunSpec, ToolError> {
    let (program, argv) = match name {
        RUN_TESTS => run_tests_command(args)?,
        LINT => lint_command(args)?,
        other => return Err(ToolError::UnknownTool(other.to_string())),
    };
    let mut command = Vec::with_capacity(argv.len() + 1);
    command.push(program);
    command.extend(argv);
    Ok(RunSpec {
        command,
        cwd,
        env: Default::default(),
        env_allowlist: allowance.env_allowlist.clone(),
        stdin: None,
        timeout: allowance.max_runtime_ms.map(Duration::from_millis),
        grace_period: DEFAULT_GRACE_PERIOD,
        sandbox: crate::exec::sandbox_backend(allowance.sandbox),
        network: crate::exec::network_for(allowance.network),
        read_only_paths: allowance.read_only_paths.clone(),
        writable_paths: allowance.writable_paths.clone(),
        container_runtime: crate::exec::container_runtime_for(allowance.sandbox),
        container_image: allowance.container_image.clone(),
    })
}

/// The `summarize` label for a built-in tool (e.g. `"cargo test"`), so summaries
/// read identically regardless of how the tool is spawned.
fn tool_label(name: &str) -> &'static str {
    match name {
        RUN_TESTS => "cargo test",
        LINT => "cargo clippy",
        _ => "tool",
    }
}

/// Map a [`RunError`] from the shared runner onto a [`ToolError`].
///
/// All runner failures describe a failure to *invoke* the tool (an empty argv,
/// a missing working directory, or a spawn failure), so they collapse onto
/// [`ToolError::Spawn`] — reusing the existing variant rather than widening the
/// public enum. The `NotFound` io kind is preserved so callers can still map a
/// missing program to a distinct error kind.
fn map_run_error(err: RunError) -> ToolError {
    match err {
        RunError::Spawn(io) => ToolError::Spawn(io),
        RunError::EmptyCommand => ToolError::Spawn(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "tool command argv is empty",
        )),
        RunError::MissingCwd(path) => ToolError::Spawn(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("tool working directory {path:?} does not exist"),
        )),
    }
}

/// Execute a built-in tool by name, confined by `allowance` (async).
///
/// Builds the confined [`RunSpec`] and runs it through the shared
/// [`crate::runner::run`] pipeline, mapping the captured outcome onto a
/// [`ToolResult`]. Used by the live `call` handler, which is already async and
/// must not nest a tokio runtime.
///
/// Returns a [`ToolResult`] when the tool ran (even if it reported a nonzero
/// exit code), or a [`ToolError`] when the tool could not be invoked at all.
pub async fn execute_tool_async(
    name: &str,
    args: &Value,
    allowance: &mx_agent_policy::Allowance,
    cwd: PathBuf,
) -> Result<ToolResult, ToolError> {
    let spec = tool_run_spec(name, args, allowance, cwd)?;
    let output = crate::runner::run(&spec).await.map_err(map_run_error)?;
    let (exit_code, summary) = summarize(tool_label(name), output.exit_code);
    Ok(ToolResult { exit_code, summary })
}

/// Execute a built-in tool by name, confined by `allowance` (sync).
///
/// Validates the request synchronously (so unknown-tool / bad-args never spin a
/// runtime), then runs the confined [`RunSpec`] on a temporary current-thread
/// runtime. Used by the synchronous task orchestrator dispatch and the loopback
/// path, neither of which runs inside a tokio runtime (mirrors
/// [`crate::task_dispatch`]'s exec command runner).
///
/// Returns a [`ToolResult`] when the tool ran (even if it reported a nonzero
/// exit code), or a [`ToolError`] when the tool could not be invoked at all.
pub fn execute_tool(
    name: &str,
    args: &Value,
    allowance: &mx_agent_policy::Allowance,
    cwd: PathBuf,
) -> Result<ToolResult, ToolError> {
    // Validate (and build the spec) synchronously first so an unknown tool or
    // bad arguments never spins up a runtime.
    let spec = tool_run_spec(name, args, allowance, cwd)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(ToolError::Spawn)?;
    let output = runtime
        .block_on(crate::runner::run(&spec))
        .map_err(map_run_error)?;
    let (exit_code, summary) = summarize(tool_label(name), output.exit_code);
    Ok(ToolResult { exit_code, summary })
}

/// Build the program and argument vector for a `run_tests` invocation.
///
/// The built-in test runner shells out to `cargo test`. Supported arguments
/// (all validated against the tool's `input_schema`):
///
/// - `package` (required string): forwarded as `-p <package>`.
/// - `name` (optional string): forwarded as a test-name filter after `--`.
/// - `coverage` (optional bool): currently advisory; accepted for forward
///   compatibility but does not change the command.
///
/// Kept separate from [`run_tests`] so the command construction is unit
/// testable without spawning a process.
fn run_tests_command(args: &Value) -> Result<(String, Vec<String>), ToolError> {
    let obj = args
        .as_object()
        .ok_or_else(|| ToolError::InvalidArgs("expected a JSON object".to_string()))?;

    let package = match obj.get("package") {
        Some(Value::String(s)) if !s.is_empty() => s.clone(),
        Some(Value::String(_)) => {
            return Err(ToolError::InvalidArgs(
                "package must be non-empty".to_string(),
            ))
        }
        Some(_) => {
            return Err(ToolError::InvalidArgs(
                "package must be a string".to_string(),
            ))
        }
        None => return Err(ToolError::InvalidArgs("package is required".to_string())),
    };

    let name = match obj.get("name") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) if !s.is_empty() => Some(s.clone()),
        Some(Value::String(_)) => {
            return Err(ToolError::InvalidArgs("name must be non-empty".to_string()))
        }
        Some(_) => return Err(ToolError::InvalidArgs("name must be a string".to_string())),
    };

    if let Some(value) = obj.get("coverage") {
        if !value.is_boolean() && !value.is_null() {
            return Err(ToolError::InvalidArgs(
                "coverage must be a boolean".to_string(),
            ));
        }
    }

    let mut argv = vec!["test".to_string(), "-p".to_string(), package];
    if let Some(name) = name {
        argv.push("--".to_string());
        argv.push(name);
    }
    Ok(("cargo".to_string(), argv))
}

/// Summarize a process exit code into a short human-readable line.
///
/// `label` names the operation (e.g. `"cargo test"` or `"cargo clippy"`) so the
/// summary reads naturally for whichever built-in tool produced it.
fn summarize(label: &str, code: Option<i32>) -> (i32, String) {
    match code {
        Some(0) => (0, format!("{label} passed")),
        Some(code) => (code, format!("{label} failed (exit code {code})")),
        // Terminated by a signal: report the conventional 128+signal style code
        // is not available here, so use a generic nonzero failure.
        None => (1, format!("{label} terminated by signal")),
    }
}

/// Build the program and argument vector for a `lint` invocation.
///
/// The built-in linter shells out to `cargo clippy`. Supported arguments (all
/// validated against the tool's `input_schema`):
///
/// - `path` (optional string): forwarded as `--manifest-path <path>` so a
///   specific crate's `Cargo.toml` can be linted; omitted to lint the workspace
///   rooted at the daemon's working directory.
/// - `fix` (optional bool): when `true`, forwarded as `--fix` to apply
///   machine-applicable lint fixes. Clippy's own VCS safety check still applies,
///   so the working tree must be clean for `--fix` to take effect.
///
/// Kept separate from [`lint`] so the command construction is unit testable
/// without spawning a process.
fn lint_command(args: &Value) -> Result<(String, Vec<String>), ToolError> {
    let obj = args
        .as_object()
        .ok_or_else(|| ToolError::InvalidArgs("expected a JSON object".to_string()))?;

    let path = match obj.get("path") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) if !s.is_empty() => Some(s.clone()),
        Some(Value::String(_)) => {
            return Err(ToolError::InvalidArgs("path must be non-empty".to_string()))
        }
        Some(_) => return Err(ToolError::InvalidArgs("path must be a string".to_string())),
    };

    let fix = match obj.get("fix") {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(_) => return Err(ToolError::InvalidArgs("fix must be a boolean".to_string())),
    };

    let mut argv = vec!["clippy".to_string()];
    if let Some(path) = path {
        argv.push("--manifest-path".to_string());
        argv.push(path);
    }
    if fix {
        argv.push("--fix".to_string());
    }
    Ok(("cargo".to_string(), argv))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_tests_requires_package() {
        let err = run_tests_command(&json!({})).unwrap_err();
        assert!(matches!(err, ToolError::InvalidArgs(_)));
    }

    #[test]
    fn run_tests_builds_package_command() {
        let (program, argv) = run_tests_command(&json!({ "package": "api" })).unwrap();
        assert_eq!(program, "cargo");
        assert_eq!(argv, vec!["test", "-p", "api"]);
    }

    #[test]
    fn run_tests_adds_name_filter() {
        let (_, argv) = run_tests_command(&json!({ "package": "api", "name": "smoke" })).unwrap();
        assert_eq!(argv, vec!["test", "-p", "api", "--", "smoke"]);
    }

    #[test]
    fn run_tests_accepts_coverage_flag() {
        let (_, argv) = run_tests_command(&json!({ "package": "api", "coverage": true })).unwrap();
        assert_eq!(argv, vec!["test", "-p", "api"]);
    }

    #[test]
    fn run_tests_rejects_bad_types() {
        assert!(matches!(
            run_tests_command(&json!({ "package": 1 })).unwrap_err(),
            ToolError::InvalidArgs(_)
        ));
        assert!(matches!(
            run_tests_command(&json!({ "package": "api", "name": 2 })).unwrap_err(),
            ToolError::InvalidArgs(_)
        ));
        assert!(matches!(
            run_tests_command(&json!({ "package": "api", "coverage": "yes" })).unwrap_err(),
            ToolError::InvalidArgs(_)
        ));
        assert!(matches!(
            run_tests_command(&json!([])).unwrap_err(),
            ToolError::InvalidArgs(_)
        ));
    }

    use mx_agent_policy::{Allowance, NetworkPolicy, Sandbox};
    use std::path::PathBuf;

    fn allowance() -> Allowance {
        Allowance::default()
    }

    #[test]
    fn execute_tool_rejects_unknown_tool() {
        // Validation happens before any runtime is spun up, so an unknown tool
        // returns synchronously.
        let err = execute_tool("nope", &json!({}), &allowance(), PathBuf::from(".")).unwrap_err();
        assert!(matches!(err, ToolError::UnknownTool(_)));
    }

    #[test]
    fn tool_run_spec_carries_policy_sandbox_network_and_paths() {
        // An allowance with Bubblewrap + Allow + paths + allowlist must produce a
        // RunSpec carrying those values for both built-in tools, mirroring the
        // exec confinement coverage (architecture §13.5).
        let allowance = Allowance {
            sandbox: Some(Sandbox::Bubblewrap),
            network: Some(NetworkPolicy::Allow),
            read_only_paths: vec![PathBuf::from("/usr"), PathBuf::from("/lib")],
            writable_paths: vec![PathBuf::from("/work")],
            env_allowlist: vec!["CARGO_HOME".to_string()],
            ..Allowance::default()
        };
        for (name, args) in [(RUN_TESTS, json!({ "package": "api" })), (LINT, json!({}))] {
            let spec = tool_run_spec(name, &args, &allowance, PathBuf::from("/work")).unwrap();
            assert_eq!(spec.sandbox, mx_agent_sandbox::Backend::Bubblewrap);
            assert_eq!(spec.network, mx_agent_sandbox::Network::Allow);
            assert_eq!(
                spec.read_only_paths,
                vec![PathBuf::from("/usr"), PathBuf::from("/lib")]
            );
            assert_eq!(spec.writable_paths, vec![PathBuf::from("/work")]);
            assert_eq!(spec.env_allowlist, vec!["CARGO_HOME".to_string()]);
            assert_eq!(spec.cwd, PathBuf::from("/work"));
            assert_eq!(spec.command.first().map(String::as_str), Some("cargo"));
        }
    }

    #[test]
    fn tool_run_spec_defaults_to_none_backend_and_deny() {
        // A default allowance must yield Backend::None and fail closed to
        // Network::Deny with empty paths, preserving the baseline confinement.
        let spec = tool_run_spec(
            RUN_TESTS,
            &json!({ "package": "x" }),
            &allowance(),
            PathBuf::from("."),
        )
        .unwrap();
        assert_eq!(spec.sandbox, mx_agent_sandbox::Backend::None);
        assert_eq!(spec.network, mx_agent_sandbox::Network::Deny);
        assert!(spec.read_only_paths.is_empty());
        assert!(spec.writable_paths.is_empty());
    }

    #[test]
    fn tool_run_spec_maps_docker_to_container_backend() {
        let allowance = Allowance {
            sandbox: Some(Sandbox::Docker),
            ..Allowance::default()
        };
        let spec = tool_run_spec(LINT, &json!({}), &allowance, PathBuf::from(".")).unwrap();
        assert_eq!(spec.sandbox, mx_agent_sandbox::Backend::Container);
    }

    #[test]
    fn tool_run_spec_env_is_sanitized_dropping_secrets() {
        // The spec's env_allowlist drives sanitize_env, which always drops known
        // token variables (even if allowlisted) while passing the safe defaults
        // through — mirroring sanitize_env_drops_secrets in runner.rs.
        let allowance = Allowance {
            env_allowlist: vec!["GITHUB_TOKEN".to_string()],
            ..Allowance::default()
        };
        let spec = tool_run_spec(
            RUN_TESTS,
            &json!({ "package": "x" }),
            &allowance,
            PathBuf::from("."),
        )
        .unwrap();
        let inherited = vec![
            ("GITHUB_TOKEN".to_string(), "secret".to_string()),
            ("PATH".to_string(), "/usr/bin".to_string()),
        ];
        let env = crate::runner::sanitize_env(inherited, &spec.env, &spec.env_allowlist);
        assert!(
            !env.contains_key("GITHUB_TOKEN"),
            "a known secret must be scrubbed even when allowlisted"
        );
        assert_eq!(env.get("PATH").map(String::as_str), Some("/usr/bin"));
    }

    #[test]
    fn tool_run_spec_rejects_unknown_and_invalid_without_spec() {
        assert!(matches!(
            tool_run_spec("nope", &json!({}), &allowance(), PathBuf::from(".")).unwrap_err(),
            ToolError::UnknownTool(_)
        ));
        assert!(matches!(
            tool_run_spec(RUN_TESTS, &json!({}), &allowance(), PathBuf::from(".")).unwrap_err(),
            ToolError::InvalidArgs(_)
        ));
    }

    #[test]
    fn summarize_maps_exit_codes() {
        assert_eq!(
            summarize("cargo test", Some(0)),
            (0, "cargo test passed".to_string())
        );
        let (code, summary) = summarize("cargo test", Some(101));
        assert_eq!(code, 101);
        assert!(summary.contains("failed"));
        let (code, _) = summarize("cargo test", None);
        assert_eq!(code, 1);
    }

    #[test]
    fn tool_result_serializes_to_output_schema_shape() {
        let result = ToolResult {
            exit_code: 0,
            summary: "ok".to_string(),
        };
        assert!(result.is_success());
        assert_eq!(
            result.to_value(),
            json!({ "exit_code": 0, "summary": "ok" })
        );
    }

    #[test]
    fn run_tests_executes_and_reports_exit_code() {
        // Use a trivially-true/false program rather than cargo to keep the test
        // fast and hermetic while still exercising the spec → runner → summarize
        // path (a default allowance + a real cwd).
        let result = run_program_via("true").unwrap();
        assert_eq!(result.exit_code, 0);
        let result = run_program_via("false").unwrap();
        assert_ne!(result.exit_code, 0);
    }

    /// Run an arbitrary `program` through the same `RunSpec` → runner →
    /// `summarize` path the built-in tools use, substituting the program so the
    /// spawn path can be exercised quickly without invoking `cargo`.
    fn run_program_via(program: &str) -> Result<ToolResult, ToolError> {
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let spec = RunSpec {
            command: vec![program.to_string()],
            cwd,
            ..RunSpec::default()
        };
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(ToolError::Spawn)?;
        let output = runtime
            .block_on(crate::runner::run(&spec))
            .map_err(map_run_error)?;
        let (exit_code, summary) = summarize(program, output.exit_code);
        Ok(ToolResult { exit_code, summary })
    }

    #[test]
    fn lint_builds_default_command() {
        let (program, argv) = lint_command(&json!({})).unwrap();
        assert_eq!(program, "cargo");
        assert_eq!(argv, vec!["clippy"]);
    }

    #[test]
    fn lint_forwards_path_as_manifest_path() {
        let (_, argv) = lint_command(&json!({ "path": "crates/foo/Cargo.toml" })).unwrap();
        assert_eq!(
            argv,
            vec!["clippy", "--manifest-path", "crates/foo/Cargo.toml"]
        );
    }

    #[test]
    fn lint_adds_fix_flag() {
        let (_, argv) = lint_command(&json!({ "fix": true })).unwrap();
        assert_eq!(argv, vec!["clippy", "--fix"]);
        // `fix: false` is the default and must not add the flag.
        let (_, argv) = lint_command(&json!({ "fix": false })).unwrap();
        assert_eq!(argv, vec!["clippy"]);
    }

    #[test]
    fn lint_combines_path_and_fix() {
        let (_, argv) = lint_command(&json!({ "path": "Cargo.toml", "fix": true })).unwrap();
        assert_eq!(
            argv,
            vec!["clippy", "--manifest-path", "Cargo.toml", "--fix"]
        );
    }

    #[test]
    fn lint_rejects_bad_types() {
        assert!(matches!(
            lint_command(&json!({ "path": 1 })).unwrap_err(),
            ToolError::InvalidArgs(_)
        ));
        assert!(matches!(
            lint_command(&json!({ "path": "" })).unwrap_err(),
            ToolError::InvalidArgs(_)
        ));
        assert!(matches!(
            lint_command(&json!({ "fix": "yes" })).unwrap_err(),
            ToolError::InvalidArgs(_)
        ));
        assert!(matches!(
            lint_command(&json!([])).unwrap_err(),
            ToolError::InvalidArgs(_)
        ));
    }

    #[test]
    fn execute_tool_dispatches_lint() {
        // Before this fix `lint` returned `UnknownTool`; it must now be
        // recognized and fail only on bad arguments, never as unknown.
        let err = execute_tool(LINT, &json!([]), &allowance(), PathBuf::from(".")).unwrap_err();
        assert!(matches!(err, ToolError::InvalidArgs(_)));
    }

    #[test]
    fn execute_tool_runs_confined_and_reports_exit_code() {
        // End-to-end through the sync entry point with a default allowance and a
        // real cwd: a missing program surfaces as a Spawn error, while a present
        // tool would run confined. `cargo` may be absent in some CI sandboxes, so
        // assert only the invoke-path contract here.
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        match execute_tool(RUN_TESTS, &json!({ "package": "x" }), &allowance(), cwd) {
            Ok(result) => {
                // cargo present: a real run reports some exit code/summary.
                assert!(result.summary.contains("cargo test"));
            }
            Err(ToolError::Spawn(_)) => {} // cargo absent: invoke failure is fine.
            Err(other) => panic!("unexpected error: {other}"),
        }
    }
}
