//! The mx-agent daemon.
//!
//! The daemon owns the Matrix sync loop, credentials, crypto state, policy
//! enforcement, and process supervision (see `docs/architecture.md`,
//! section 10). This is a placeholder that wires the supporting crates
//! together so the workspace builds end to end.

use mx_agent_ipc::default_socket_name;
use mx_agent_policy::{default_decision, Decision};
use mx_agent_protocol::protocol_version;
use mx_agent_sandbox::{default_backend, Backend};

/// A snapshot of the daemon's default runtime configuration.
#[derive(Debug, Clone)]
pub struct DaemonInfo {
    /// Protocol version the daemon speaks.
    pub protocol_version: &'static str,
    /// Default IPC socket file name.
    pub socket_name: &'static str,
    /// Default policy decision (deny-by-default).
    pub default_decision: Decision,
    /// Default sandbox backend.
    pub sandbox_backend: Backend,
}

impl DaemonInfo {
    /// Build the default daemon info from the supporting crates.
    pub fn new() -> Self {
        Self {
            protocol_version: protocol_version(),
            socket_name: default_socket_name(),
            default_decision: default_decision(),
            sandbox_backend: default_backend(),
        }
    }
}

impl Default for DaemonInfo {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn info_uses_supporting_crate_defaults() {
        let info = DaemonInfo::new();
        assert_eq!(info.protocol_version, "v1");
        assert_eq!(info.socket_name, "daemon.sock");
        assert_eq!(info.default_decision, Decision::Deny);
        assert_eq!(info.sandbox_backend, Backend::None);
    }
}
