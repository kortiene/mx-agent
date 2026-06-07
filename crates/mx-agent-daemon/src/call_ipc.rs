//! Local IPC contract and loopback execution for `mx-agent call` (issue #193).
//!
//! The stateless CLI must not execute tools itself: the daemon owns tool
//! execution (and, for the live flow, the Matrix client, signing key, policy,
//! and trust context — see [`crate::call`]). This module defines the
//! `call.start` IPC method's parameters and result, plus a **local-loopback**
//! executor that runs a built-in tool in-process.
//!
//! Loopback is a stepping stone: it lets `call` move onto the IPC path now,
//! before the signed Matrix transport to a remote daemon (#194) is wired in.
//! When the live flow lands it replaces [`start_call_loopback`] behind the same
//! `call.start` method, so the CLI does not change again.
//!
//! # Security
//!
//! - Loopback runs only built-in, schema-validated tools via
//!   [`crate::tool_exec::execute_tool`] — never arbitrary shell.
//! - The raw tool [`input`](CallStartParams::input) can carry secret-looking
//!   arguments, so it is never logged here.

use std::io::ErrorKind;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use mx_agent_protocol::id::{generate_invocation_id, generate_request_id};

use crate::tool_exec::{execute_tool, ToolError};

/// Parameters for the `call.start` IPC method.
///
/// `room` and `agent` identify the remote target for the live Matrix flow
/// (#194); the local-loopback executor accepts them for forward compatibility
/// but does not use them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallStartParams {
    /// Workspace room to target, if any.
    #[serde(default)]
    pub room: Option<String>,
    /// Target agent name, if any.
    #[serde(default)]
    pub agent: Option<String>,
    /// Named tool to invoke.
    pub tool: String,
    /// Tool input as a JSON object/value understood by the tool.
    #[serde(default)]
    pub input: Value,
    /// Preset invocation id to run the call under. `None` mints a fresh id (the
    /// default for direct CLI `call`); task dispatch sets it so the call's
    /// invocation id and the owning task's recorded `invocation_id` are a single
    /// unified id (issue #239).
    #[serde(default)]
    pub invocation_id: Option<String>,
}

/// Stable, machine-readable kind of a tool-invocation failure.
///
/// These distinguish failures to *invoke* a tool from a tool that ran and
/// reported a nonzero exit code (which is a successful [`CallOutcome::Ok`]). The
/// CLI maps each kind to an exit code per architecture §5.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallErrorKind {
    /// No built-in tool is registered under the requested name.
    UnknownTool,
    /// The provided arguments did not satisfy the tool's input schema.
    InvalidArgs,
    /// The tool's underlying program was not found on the daemon host.
    NotFound,
    /// The tool's underlying process could not be spawned for another reason.
    Spawn,
    /// The live Matrix-backed remote call failed or was rejected.
    Remote,
}

/// The outcome of a `call.start` invocation.
///
/// Internally tagged by `status` so the wire form is
/// `{"status":"ok",...}` / `{"status":"error",...}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum CallOutcome {
    /// The tool ran (possibly with a nonzero exit code).
    Ok {
        /// The exit code of the underlying process (0 on success).
        exit_code: i32,
        /// A short, human-readable summary.
        summary: String,
    },
    /// The tool could not be invoked at all.
    Error {
        /// Machine-readable failure kind.
        kind: CallErrorKind,
        /// Human-readable failure message (no secrets).
        message: String,
    },
}

/// The result of the `call.start` IPC method.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallStartResult {
    /// Generated invocation identifier (`inv_...`).
    pub invocation_id: String,
    /// Generated request identifier (`req_...`).
    pub request_id: String,
    /// The execution outcome.
    pub outcome: CallOutcome,
}

/// Execute a `call.start` request locally (loopback), without Matrix.
///
/// Mints fresh `invocation_id`/`request_id`, runs the named built-in tool with
/// the supplied input, and maps any invoke failure to a stable
/// [`CallErrorKind`]. A tool that runs and exits nonzero still yields
/// [`CallOutcome::Ok`]; only a failure to invoke yields [`CallOutcome::Error`].
pub fn start_call_loopback(params: &CallStartParams) -> CallStartResult {
    let invocation_id = params
        .invocation_id
        .clone()
        .unwrap_or_else(generate_invocation_id);
    let request_id = generate_request_id();
    let outcome = match execute_tool(&params.tool, &params.input) {
        Ok(result) => CallOutcome::Ok {
            exit_code: result.exit_code,
            summary: result.summary,
        },
        Err(err) => {
            let kind = match &err {
                ToolError::UnknownTool(_) => CallErrorKind::UnknownTool,
                ToolError::InvalidArgs(_) => CallErrorKind::InvalidArgs,
                ToolError::Spawn(io) if io.kind() == ErrorKind::NotFound => CallErrorKind::NotFound,
                ToolError::Spawn(_) => CallErrorKind::Spawn,
            };
            CallOutcome::Error {
                kind,
                message: err.to_string(),
            }
        }
    };
    CallStartResult {
        invocation_id,
        request_id,
        outcome,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mx_agent_protocol::id::{validate, IdKind};
    use serde_json::json;

    fn params(tool: &str, input: Value) -> CallStartParams {
        CallStartParams {
            room: Some("!room:server".to_string()),
            agent: Some("developer-pi".to_string()),
            tool: tool.to_string(),
            input,
            invocation_id: None,
        }
    }

    #[test]
    fn loopback_mints_well_formed_ids() {
        let result = start_call_loopback(&params("run_tests", json!({ "package": "x" })));
        assert!(validate(IdKind::Invocation, &result.invocation_id).is_ok());
        assert!(validate(IdKind::Request, &result.request_id).is_ok());
    }

    #[test]
    fn loopback_honors_preset_invocation_id() {
        // Task dispatch presets the orchestrator's invocation id so the call runs
        // under the unified id; absence still mints a fresh one (issue #239).
        let mut p = params("run_tests", json!({ "package": "x" }));
        p.invocation_id = Some("inv_preset".to_string());
        let result = start_call_loopback(&p);
        assert_eq!(result.invocation_id, "inv_preset");
    }

    #[test]
    fn unknown_tool_maps_to_error_kind() {
        let result = start_call_loopback(&params("definitely_not_a_tool", json!({})));
        match result.outcome {
            CallOutcome::Error { kind, .. } => assert_eq!(kind, CallErrorKind::UnknownTool),
            other => panic!("expected error, got {other:?}"),
        }
    }

    #[test]
    fn invalid_args_maps_to_error_kind() {
        // run_tests requires a non-empty `package`.
        let result = start_call_loopback(&params("run_tests", json!({})));
        match result.outcome {
            CallOutcome::Error { kind, .. } => assert_eq!(kind, CallErrorKind::InvalidArgs),
            other => panic!("expected error, got {other:?}"),
        }
    }

    #[test]
    fn outcome_serializes_with_status_tag() {
        let ok = CallOutcome::Ok {
            exit_code: 0,
            summary: "ok".to_string(),
        };
        let value = serde_json::to_value(&ok).unwrap();
        assert_eq!(value["status"], "ok");
        assert_eq!(value["exit_code"], 0);

        let err = CallOutcome::Error {
            kind: CallErrorKind::InvalidArgs,
            message: "bad".to_string(),
        };
        let value = serde_json::to_value(&err).unwrap();
        assert_eq!(value["status"], "error");
        assert_eq!(value["kind"], "invalid_args");
    }

    #[test]
    fn result_round_trips() {
        let result = CallStartResult {
            invocation_id: "inv_x".to_string(),
            request_id: "req_x".to_string(),
            outcome: CallOutcome::Ok {
                exit_code: 0,
                summary: "done".to_string(),
            },
        };
        let json = serde_json::to_value(&result).unwrap();
        let back: CallStartResult = serde_json::from_value(json).unwrap();
        assert_eq!(back, result);
    }
}
