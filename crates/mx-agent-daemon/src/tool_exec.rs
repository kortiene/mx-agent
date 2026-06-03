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
//! inject arbitrary shell, only the typed arguments each tool declares.

use std::process::Command;

use serde::Serialize;
use serde_json::{json, Value};

/// The built-in `run_tests` tool name.
pub const RUN_TESTS: &str = "run_tests";

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

/// Execute a built-in tool by name with the given JSON `args`.
///
/// Returns a [`ToolResult`] when the tool ran (even if it reported a nonzero
/// exit code), or a [`ToolError`] when the tool could not be invoked at all.
pub fn execute_tool(name: &str, args: &Value) -> Result<ToolResult, ToolError> {
    match name {
        RUN_TESTS => run_tests(args),
        other => Err(ToolError::UnknownTool(other.to_string())),
    }
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
fn summarize(program: &str, code: Option<i32>) -> (i32, String) {
    match code {
        Some(0) => (0, format!("{program} tests passed")),
        Some(code) => (code, format!("{program} tests failed (exit code {code})")),
        // Terminated by a signal: report the conventional 128+signal style code
        // is not available here, so use a generic nonzero failure.
        None => (1, format!("{program} terminated by signal")),
    }
}

/// Run the built-in `run_tests` tool.
fn run_tests(args: &Value) -> Result<ToolResult, ToolError> {
    let (program, argv) = run_tests_command(args)?;
    let status = Command::new(&program)
        .args(&argv)
        .status()
        .map_err(ToolError::Spawn)?;
    let (exit_code, summary) = summarize(&program, status.code());
    Ok(ToolResult { exit_code, summary })
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

    #[test]
    fn execute_tool_rejects_unknown_tool() {
        let err = execute_tool("nope", &json!({})).unwrap_err();
        assert!(matches!(err, ToolError::UnknownTool(_)));
    }

    #[test]
    fn summarize_maps_exit_codes() {
        assert_eq!(
            summarize("cargo", Some(0)),
            (0, "cargo tests passed".to_string())
        );
        let (code, summary) = summarize("cargo", Some(101));
        assert_eq!(code, 101);
        assert!(summary.contains("failed"));
        let (code, _) = summarize("cargo", None);
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
        // fast and hermetic while still exercising the spawn + summarize path.
        let result = run_tests_via("true", &json!({ "package": "x" })).unwrap();
        assert_eq!(result.exit_code, 0);
        let result = run_tests_via("false", &json!({ "package": "x" })).unwrap();
        assert_ne!(result.exit_code, 0);
    }

    /// Test-only variant of [`run_tests`] that runs an arbitrary `program`
    /// instead of `cargo`, used to exercise the spawn + summarize path quickly.
    fn run_tests_via(program: &str, args: &Value) -> Result<ToolResult, ToolError> {
        // Validate args the same way the real tool does.
        run_tests_command(args)?;
        let status = Command::new(program).status().map_err(ToolError::Spawn)?;
        let (exit_code, summary) = summarize(program, status.code());
        Ok(ToolResult { exit_code, summary })
    }
}
