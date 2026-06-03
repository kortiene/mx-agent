//! Minimal JSON-RPC 2.0 request/response types used over the IPC transport.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The JSON-RPC protocol version string.
pub const JSONRPC_VERSION: &str = "2.0";

/// Invalid JSON was received.
pub const PARSE_ERROR: i64 = -32700;
/// The request object was not valid.
pub const INVALID_REQUEST: i64 = -32600;
/// The requested method does not exist.
pub const METHOD_NOT_FOUND: i64 = -32601;
/// Invalid method parameters.
pub const INVALID_PARAMS: i64 = -32602;
/// Internal server error.
pub const INTERNAL_ERROR: i64 = -32603;

fn default_version() -> String {
    JSONRPC_VERSION.to_string()
}

/// A JSON-RPC request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    /// Protocol version; defaults to `"2.0"` when absent.
    #[serde(default = "default_version")]
    pub jsonrpc: String,
    /// Correlation id echoed back in the response.
    pub id: Value,
    /// Method name, e.g. `"daemon.status"`.
    pub method: String,
    /// Method parameters; `null` when absent.
    #[serde(default)]
    pub params: Value,
}

impl Request {
    /// Build a request with the given id, method, and params.
    pub fn new(id: Value, method: impl Into<String>, params: Value) -> Self {
        Self {
            jsonrpc: default_version(),
            id,
            method: method.into(),
            params,
        }
    }
}

/// A JSON-RPC error object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcError {
    /// Numeric error code.
    pub code: i64,
    /// Human-readable error message.
    pub message: String,
    /// Optional structured error data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

/// A JSON-RPC response: exactly one of `result` or `error` is set.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    /// Protocol version; defaults to `"2.0"` when absent.
    #[serde(default = "default_version")]
    pub jsonrpc: String,
    /// Correlation id matching the request.
    pub id: Value,
    /// Result payload on success.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    /// Error object on failure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcError>,
}

impl Response {
    /// Build a successful response.
    pub fn result(id: Value, result: Value) -> Self {
        Self {
            jsonrpc: default_version(),
            id,
            result: Some(result),
            error: None,
        }
    }

    /// Build an error response.
    pub fn error(id: Value, code: i64, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: default_version(),
            id,
            result: None,
            error: Some(RpcError {
                code,
                message: message.into(),
                data: None,
            }),
        }
    }

    /// Returns true if this response carries an error.
    pub fn is_error(&self) -> bool {
        self.error.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn request_round_trips() {
        let req = Request::new(json!(1), "daemon.status", Value::Null);
        let bytes = serde_json::to_vec(&req).unwrap();
        let back: Request = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back.method, "daemon.status");
        assert_eq!(back.id, json!(1));
        assert_eq!(back.jsonrpc, "2.0");
    }

    #[test]
    fn request_defaults_version_and_params() {
        let back: Request = serde_json::from_str(r#"{"id":"a","method":"x"}"#).unwrap();
        assert_eq!(back.jsonrpc, "2.0");
        assert_eq!(back.params, Value::Null);
    }

    #[test]
    fn response_serializes_only_one_arm() {
        let ok = serde_json::to_string(&Response::result(json!(1), json!({"a":1}))).unwrap();
        assert!(ok.contains("\"result\""));
        assert!(!ok.contains("\"error\""));

        let err =
            serde_json::to_string(&Response::error(json!(1), METHOD_NOT_FOUND, "nope")).unwrap();
        assert!(err.contains("\"error\""));
        assert!(!err.contains("\"result\""));
    }
}
