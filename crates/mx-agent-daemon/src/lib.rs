//! The mx-agent daemon.
//!
//! The daemon owns the Matrix sync loop, credentials, crypto state, policy
//! enforcement, and process supervision (see `docs/architecture.md`,
//! section 10). This is a placeholder that wires the supporting crates
//! together so the workspace builds end to end.

pub mod lifecycle;
pub mod matrix;
pub mod session;
pub mod sync;

pub use lifecycle::{
    run_foreground, start_background, status, stop, Paths, RunningStatus, StopOutcome,
};
pub use matrix::{
    build_client, login_password, restore_client, ClientError, ConfigError, LoginError,
    MatrixConfig,
};
pub use session::{
    auth_status, clear_session, clear_sync_token, load_session, load_sync_token, save_session,
    save_sync_token, AuthStatus, Secret, SessionPaths, StoredSession,
};
pub use sync::{
    run_matrix_sync, run_sync_loop, Backoff, BackoffConfig, StepError, SyncHealth, SyncState,
};

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

impl DaemonInfo {
    /// Emit a structured startup log describing the daemon configuration.
    ///
    /// The subscriber is installed by the hosting process (the CLI today, a
    /// dedicated daemon binary later); this method only produces the event.
    pub fn log_summary(&self) {
        tracing::info!(
            protocol_version = self.protocol_version,
            socket_name = self.socket_name,
            default_decision = ?self.default_decision,
            sandbox_backend = ?self.sandbox_backend,
            "daemon configuration"
        );
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

    #[test]
    fn log_summary_emits_a_structured_event() {
        use std::io::Write;
        use std::sync::{Arc, Mutex};
        use tracing_subscriber::fmt::MakeWriter;

        #[derive(Clone, Default)]
        struct Buffer(Arc<Mutex<Vec<u8>>>);
        impl Write for Buffer {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        impl<'a> MakeWriter<'a> for Buffer {
            type Writer = Buffer;
            fn make_writer(&'a self) -> Buffer {
                self.clone()
            }
        }

        let buffer = Buffer::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(buffer.clone())
            .with_max_level(tracing::Level::INFO)
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            DaemonInfo::new().log_summary();
        });

        let output = String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap();
        assert!(output.contains("daemon configuration"), "got: {output}");
        assert!(output.contains("protocol_version"), "got: {output}");
    }
}
