//! Protocol types and versioning for mx-agent.
//!
//! This crate holds the Matrix event schemas, IPC message types, and
//! identifier helpers described in `docs/architecture.md`. It currently exposes
//! the protocol version and the canonical event type constants in [`events`].
//!
//! # Versioning and compatibility
//!
//! mx-agent uses explicit per-event schema versions encoded in the Matrix event
//! type name, e.g. `com.mxagent.exec.request.v1`. The rules are:
//!
//! - **Frozen semantics per version.** Once an event type at a given version is
//!   shipped, the meaning of its fields must not change. [`PROTOCOL_VERSION`]
//!   is the wire-format anchor (`v1`) and matches
//!   [`events::SCHEMA_VERSION_SUFFIX`].
//! - **Breaking changes bump the version.** A change that alters or removes a
//!   field's meaning requires a new versioned event type (e.g. `...v2`) added
//!   alongside the existing one; the old type continues to be honored for
//!   compatibility.
//! - **Additive changes are allowed in place.** New optional fields may be
//!   introduced within the same version as long as older peers can ignore them.
//! - **Use the constants.** Always reference the constants in [`events`] rather
//!   than literal strings so typos are caught at compile time.

pub mod events;

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
