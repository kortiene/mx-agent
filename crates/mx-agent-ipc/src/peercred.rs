//! Verification of local IPC peer credentials.
//!
//! The daemon socket is created with mode `0600` under a user-owned directory
//! (see [`crate::socket`]), which already restricts who can connect. As an
//! additional defence-in-depth check (`docs/architecture.md`, section 10.2)
//! the daemon verifies the connecting peer's credentials where the platform
//! supports it, rejecting any client not owned by the daemon's own UID.
//!
//! On Linux this uses `SO_PEERCRED`. On platforms without a supported peer
//! credential mechanism the check is reported as
//! [`PeerCredCheck::Unsupported`], and callers decide how to proceed; the
//! daemon logs the unsupported platform once and relies on filesystem
//! permissions alone.

use std::os::unix::net::UnixStream;

/// Outcome of a peer credential check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerCredCheck {
    /// The peer's credentials were verified and the peer UID matches the
    /// daemon's effective UID.
    Allowed {
        /// The verified peer UID.
        uid: u32,
    },
    /// The peer's credentials were verified but the peer UID does not match the
    /// daemon's effective UID. The connection must be rejected.
    Denied {
        /// The peer UID reported by the OS.
        peer_uid: u32,
        /// The daemon's effective UID.
        daemon_uid: u32,
    },
    /// The platform does not support retrieving peer credentials, so the check
    /// could not be performed. Filesystem permissions remain the only
    /// protection.
    Unsupported,
}

impl PeerCredCheck {
    /// Returns `true` if the connection is permitted to proceed.
    ///
    /// Both [`PeerCredCheck::Allowed`] and [`PeerCredCheck::Unsupported`] allow
    /// the connection; only [`PeerCredCheck::Denied`] rejects it. Unsupported
    /// platforms fall back to the socket's `0600` permissions.
    pub fn is_allowed(&self) -> bool {
        !matches!(self, PeerCredCheck::Denied { .. })
    }
}

/// Verify that `stream`'s peer is owned by the daemon's effective UID.
///
/// On Linux the peer UID is read via `SO_PEERCRED` and compared against
/// [`nix::unistd::geteuid`]. On platforms without peer credential support the
/// result is [`PeerCredCheck::Unsupported`].
pub fn verify_peer(stream: &UnixStream) -> PeerCredCheck {
    let daemon_uid = nix::unistd::geteuid().as_raw();
    verify_peer_against(stream, daemon_uid)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn verify_peer_against(stream: &UnixStream, daemon_uid: u32) -> PeerCredCheck {
    use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
    use std::os::unix::io::AsFd;

    match getsockopt(&stream.as_fd(), PeerCredentials) {
        Ok(cred) => {
            let peer_uid = cred.uid();
            if peer_uid == daemon_uid {
                PeerCredCheck::Allowed { uid: peer_uid }
            } else {
                PeerCredCheck::Denied {
                    peer_uid,
                    daemon_uid,
                }
            }
        }
        // If the kernel cannot report credentials, treat it as unsupported
        // rather than silently allowing or denying; permissions still apply.
        Err(_) => PeerCredCheck::Unsupported,
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn verify_peer_against(_stream: &UnixStream, _daemon_uid: u32) -> PeerCredCheck {
    PeerCredCheck::Unsupported
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;

    #[test]
    fn allows_same_uid_peer_on_linux() {
        let (a, _b) = UnixStream::pair().unwrap();
        let check = verify_peer(&a);
        // The current process owns both ends of the pair, so on Linux the peer
        // UID must equal our own UID.
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            let me = nix::unistd::geteuid().as_raw();
            assert_eq!(check, PeerCredCheck::Allowed { uid: me });
        }
        assert!(check.is_allowed());
    }

    #[test]
    fn denied_is_not_allowed() {
        let check = PeerCredCheck::Denied {
            peer_uid: 1000,
            daemon_uid: 0,
        };
        assert!(!check.is_allowed());
    }

    #[test]
    fn unsupported_is_allowed_fallback() {
        assert!(PeerCredCheck::Unsupported.is_allowed());
    }

    #[test]
    fn wrong_uid_is_denied() {
        let (a, _b) = UnixStream::pair().unwrap();
        // Compare against an impossible daemon UID to force a mismatch on
        // platforms that support peer credentials.
        let me = nix::unistd::geteuid().as_raw();
        let bogus = me.wrapping_add(1);
        let check = verify_peer_against(&a, bogus);
        #[cfg(any(target_os = "linux", target_os = "android"))]
        assert_eq!(
            check,
            PeerCredCheck::Denied {
                peer_uid: me,
                daemon_uid: bogus,
            }
        );
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        assert_eq!(check, PeerCredCheck::Unsupported);
    }
}
