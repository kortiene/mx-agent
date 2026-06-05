//! Local IPC transport between the mx-agent CLI and daemon.
//!
//! The transport will be framed JSON-RPC over a Unix domain socket (see
//! `docs/architecture.md`, section 10). This crate currently only defines the
//! default socket file name.

pub mod client;
pub mod frame;
pub mod peercred;
pub mod rpc;
pub mod server;
pub mod socket;

pub use client::Client;
pub use frame::{read_frame, write_frame, MAX_FRAME_LEN};
pub use peercred::{verify_peer, PeerCredCheck};
pub use rpc::{Request, Response, RpcError};
pub use server::{handle_message, serve, serve_streaming};
pub use socket::{bind, ensure_safe_parent_dir, BindError, SocketGuard, SOCKET_MODE};

/// Default Unix domain socket file name, created under the runtime directory.
pub const DEFAULT_SOCKET_NAME: &str = "daemon.sock";

/// Returns the default socket file name.
pub fn default_socket_name() -> &'static str {
    DEFAULT_SOCKET_NAME
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_socket_name_is_stable() {
        assert_eq!(default_socket_name(), "daemon.sock");
    }
}
