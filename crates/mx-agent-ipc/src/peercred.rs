//! Verification of local IPC peer credentials.
//!
//! The daemon socket is created with mode `0600` under a user-owned directory
//! (see [`crate::socket`]), which already restricts who can connect. As an
//! additional defence-in-depth check (`docs/architecture.md`, section 10.2)
//! the daemon verifies the connecting peer's credentials where the platform
//! supports it, rejecting any client not owned by the daemon's own UID.
//!
//! On Linux/Android this uses `SO_PEERCRED`; on macOS/iOS and the
//! FreeBSD-family BSDs it uses `LOCAL_PEERCRED`. On platforms without a
//! supported peer credential mechanism (e.g. NetBSD/OpenBSD, Solaris) the check
//! is reported as [`PeerCredCheck::Unsupported`], and callers decide how to
//! proceed; the daemon logs the unsupported platform once and relies on
//! filesystem permissions alone.

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
/// The peer UID is read via `SO_PEERCRED` on Linux/Android and via
/// `LOCAL_PEERCRED` on macOS/iOS and the FreeBSD-family BSDs, then compared
/// against [`nix::unistd::geteuid`]. On platforms without a supported peer
/// credential mechanism the result is [`PeerCredCheck::Unsupported`].
pub fn verify_peer(stream: &UnixStream) -> PeerCredCheck {
    let daemon_uid = nix::unistd::geteuid().as_raw();
    verify_peer_against(stream, daemon_uid)
}

/// Decide the outcome once a peer UID has been obtained from the OS.
///
/// Shared by the per-platform arms so the same-UID comparison stays identical
/// across the `SO_PEERCRED` and `LOCAL_PEERCRED` mechanisms.
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios",
    target_os = "tvos",
    target_os = "watchos",
    target_os = "visionos",
    target_os = "freebsd",
    target_os = "dragonfly"
))]
fn decide(peer_uid: u32, daemon_uid: u32) -> PeerCredCheck {
    if peer_uid == daemon_uid {
        PeerCredCheck::Allowed { uid: peer_uid }
    } else {
        PeerCredCheck::Denied {
            peer_uid,
            daemon_uid,
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn verify_peer_against(stream: &UnixStream, daemon_uid: u32) -> PeerCredCheck {
    use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
    use std::os::unix::io::AsFd;

    match getsockopt(&stream.as_fd(), PeerCredentials) {
        Ok(cred) => decide(cred.uid(), daemon_uid),
        // If the kernel cannot report credentials, treat it as unsupported
        // rather than silently allowing or denying; permissions still apply.
        Err(_) => PeerCredCheck::Unsupported,
    }
}

// macOS/iOS and the FreeBSD-family BSDs expose `LOCAL_PEERCRED`. This cfg set
// matches the platforms `nix` gates `sockopt::LocalPeerCred` to exactly
// (`apple_targets` + `freebsdlike`); NetBSD/OpenBSD lack the option and fall
// through to the `Unsupported` arm below.
#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "tvos",
    target_os = "watchos",
    target_os = "visionos",
    target_os = "freebsd",
    target_os = "dragonfly"
))]
fn verify_peer_against(stream: &UnixStream, daemon_uid: u32) -> PeerCredCheck {
    use nix::sys::socket::{getsockopt, sockopt::LocalPeerCred};
    use std::os::unix::io::AsFd;

    match getsockopt(&stream.as_fd(), LocalPeerCred) {
        Ok(cred) => decide(cred.uid(), daemon_uid),
        // As on Linux, an OS that refuses to report credentials degrades to
        // the filesystem-permission fallback rather than allowing or denying.
        Err(_) => PeerCredCheck::Unsupported,
    }
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios",
    target_os = "tvos",
    target_os = "watchos",
    target_os = "visionos",
    target_os = "freebsd",
    target_os = "dragonfly"
)))]
fn verify_peer_against(_stream: &UnixStream, _daemon_uid: u32) -> PeerCredCheck {
    PeerCredCheck::Unsupported
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;

    #[test]
    fn allows_same_uid_peer() {
        let (a, _b) = UnixStream::pair().unwrap();
        let check = verify_peer(&a);
        // The current process owns both ends of the pair, so on any platform
        // with a peer-credential mechanism the peer UID must equal our own UID.
        #[cfg(any(
            target_os = "linux",
            target_os = "android",
            target_os = "macos",
            target_os = "ios",
            target_os = "tvos",
            target_os = "watchos",
            target_os = "visionos",
            target_os = "freebsd",
            target_os = "dragonfly"
        ))]
        {
            let me = nix::unistd::geteuid().as_raw();
            assert_eq!(check, PeerCredCheck::Allowed { uid: me });
        }
        assert!(check.is_allowed());
    }

    #[test]
    fn allowed_variant_is_allowed() {
        // Every Allowed { uid } value must pass is_allowed(), regardless of uid.
        assert!(PeerCredCheck::Allowed { uid: 0 }.is_allowed());
        assert!(PeerCredCheck::Allowed { uid: 1000 }.is_allowed());
        assert!(PeerCredCheck::Allowed { uid: u32::MAX }.is_allowed());
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

    /// Direct tests for the `decide()` helper, gated to platforms where the
    /// function is compiled. The helper is the comparison kernel shared by both
    /// the `SO_PEERCRED` (Linux/Android) and `LOCAL_PEERCRED` (macOS/BSD) arms.
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "visionos",
        target_os = "freebsd",
        target_os = "dragonfly"
    ))]
    mod decide_tests {
        use super::super::{decide, PeerCredCheck};

        #[test]
        fn same_uid_gives_allowed_with_uid_field() {
            assert_eq!(decide(1000, 1000), PeerCredCheck::Allowed { uid: 1000 });
        }

        #[test]
        fn different_uid_gives_denied_with_correct_fields() {
            assert_eq!(
                decide(999, 1000),
                PeerCredCheck::Denied {
                    peer_uid: 999,
                    daemon_uid: 1000,
                }
            );
        }

        #[test]
        fn zero_uid_same_gives_allowed() {
            assert_eq!(decide(0, 0), PeerCredCheck::Allowed { uid: 0 });
        }

        #[test]
        fn max_peer_uid_mismatch_gives_denied() {
            assert_eq!(
                decide(u32::MAX, 0),
                PeerCredCheck::Denied {
                    peer_uid: u32::MAX,
                    daemon_uid: 0,
                }
            );
        }

        #[test]
        fn uid_is_asymmetric_peer_vs_daemon_are_distinct_fields() {
            // decide(A, B) != decide(B, A) when A != B — peer_uid and daemon_uid
            // must not be swapped in the Denied variant.
            let r1 = decide(10, 20);
            let r2 = decide(20, 10);
            assert_ne!(r1, r2);
            assert_eq!(
                r1,
                PeerCredCheck::Denied {
                    peer_uid: 10,
                    daemon_uid: 20,
                }
            );
            assert_eq!(
                r2,
                PeerCredCheck::Denied {
                    peer_uid: 20,
                    daemon_uid: 10,
                }
            );
        }
    }

    /// Regression test: `verify_peer` must be equivalent to calling
    /// `verify_peer_against` with the current effective UID. If the two ever
    /// diverge the same-UID invariant would be inconsistently applied.
    #[test]
    fn verify_peer_agrees_with_verify_peer_against_geteuid() {
        let (a, _b) = UnixStream::pair().unwrap();
        let me = nix::unistd::geteuid().as_raw();
        // getsockopt is a read-only syscall; calling it twice on the same fd is safe.
        let r1 = verify_peer(&a);
        let r2 = verify_peer_against(&a, me);
        assert_eq!(r1, r2);
    }

    #[test]
    fn wrong_uid_is_denied() {
        let (a, _b) = UnixStream::pair().unwrap();
        // Compare against an impossible daemon UID to force a mismatch on
        // platforms that support peer credentials.
        let me = nix::unistd::geteuid().as_raw();
        let bogus = me.wrapping_add(1);
        let check = verify_peer_against(&a, bogus);
        #[cfg(any(
            target_os = "linux",
            target_os = "android",
            target_os = "macos",
            target_os = "ios",
            target_os = "tvos",
            target_os = "watchos",
            target_os = "visionos",
            target_os = "freebsd",
            target_os = "dragonfly"
        ))]
        assert_eq!(
            check,
            PeerCredCheck::Denied {
                peer_uid: me,
                daemon_uid: bogus,
            }
        );
        #[cfg(not(any(
            target_os = "linux",
            target_os = "android",
            target_os = "macos",
            target_os = "ios",
            target_os = "tvos",
            target_os = "watchos",
            target_os = "visionos",
            target_os = "freebsd",
            target_os = "dragonfly"
        )))]
        assert_eq!(check, PeerCredCheck::Unsupported);
    }
}
