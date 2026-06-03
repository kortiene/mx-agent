//! Protocol types and versioning for mx-agent.
//!
//! This crate will hold the Matrix event schemas, IPC message types, and
//! identifier helpers described in `docs/architecture.md`. For now it only
//! exposes the protocol version so other crates can depend on a stable anchor.

/// Wire-format version for mx-agent Matrix event types (`com.mxagent.*.v1`).
pub const PROTOCOL_VERSION: &str = "v1";

/// Returns the protocol version string.
pub fn protocol_version() -> &'static str {
    PROTOCOL_VERSION
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_version_is_v1() {
        assert_eq!(protocol_version(), "v1");
    }
}
