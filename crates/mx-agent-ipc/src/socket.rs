//! Safe creation of the daemon's Unix domain socket.
//!
//! Binding goes through [`bind`], which enforces the security properties from
//! `docs/architecture.md`, section 13.2:
//!
//! - the socket lives under a private, user-owned directory
//!   (`$XDG_RUNTIME_DIR/mx-agent` by default);
//! - the parent directory must not be group- or world-accessible;
//! - the socket file is created with mode `0600`;
//! - stale sockets from a previous run are cleaned up, but only if no daemon is
//!   actually listening and the path is genuinely a socket.

use std::fmt;
use std::fs;
use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};

/// Permission bits that must be unset on the socket's parent directory.
///
/// Any group or world access bit makes the directory unsafe for an IPC socket
/// that grants daemon control.
pub const UNSAFE_DIR_BITS: u32 = 0o077;

/// Mode applied to the bound socket file.
pub const SOCKET_MODE: u32 = 0o600;

/// Errors that can occur while binding the daemon socket.
#[derive(Debug)]
pub enum BindError {
    /// The parent directory is missing or is not a directory.
    ParentMissing(PathBuf),
    /// The parent directory is group- or world-accessible.
    UnsafeParentDir {
        /// Offending directory.
        path: PathBuf,
        /// Its permission bits (masked to `0o777`).
        mode: u32,
    },
    /// The parent directory is not owned by the current user.
    ParentNotOwned {
        /// Offending directory.
        path: PathBuf,
        /// Directory owner UID.
        owner: u32,
        /// Current effective UID.
        euid: u32,
    },
    /// A non-socket file already exists at the socket path.
    PathExistsNotSocket(PathBuf),
    /// Another daemon is already listening on the socket.
    AlreadyInUse(PathBuf),
    /// An underlying I/O error.
    Io(io::Error),
}

impl fmt::Display for BindError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ParentMissing(p) => {
                write!(f, "socket directory {} does not exist", p.display())
            }
            Self::UnsafeParentDir { path, mode } => write!(
                f,
                "socket directory {} has unsafe permissions {:#o}; expected no group/world access",
                path.display(),
                mode
            ),
            Self::ParentNotOwned { path, owner, euid } => write!(
                f,
                "socket directory {} is owned by uid {owner}, not the current user (uid {euid})",
                path.display()
            ),
            Self::PathExistsNotSocket(p) => {
                write!(f, "refusing to remove non-socket file at {}", p.display())
            }
            Self::AlreadyInUse(p) => {
                write!(f, "another daemon is already listening on {}", p.display())
            }
            Self::Io(e) => write!(f, "socket I/O error: {e}"),
        }
    }
}

impl std::error::Error for BindError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for BindError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<BindError> for io::Error {
    fn from(e: BindError) -> Self {
        match e {
            BindError::Io(io) => io,
            other => io::Error::other(other.to_string()),
        }
    }
}

/// An owned, bound Unix socket that unlinks its path on drop.
#[derive(Debug)]
pub struct SocketGuard {
    path: PathBuf,
    listener: UnixListener,
}

impl SocketGuard {
    /// The bound listener.
    pub fn listener(&self) -> &UnixListener {
        &self.listener
    }

    /// The socket's filesystem path.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for SocketGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

/// Validate that `dir` is a safe location for the daemon socket.
///
/// Returns an error if the directory is missing, group/world-accessible, or not
/// owned by the current user.
pub fn ensure_safe_parent_dir(dir: &Path) -> Result<(), BindError> {
    let meta = match fs::metadata(dir) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Err(BindError::ParentMissing(dir.to_path_buf()))
        }
        Err(e) => return Err(BindError::Io(e)),
    };
    if !meta.is_dir() {
        return Err(BindError::ParentMissing(dir.to_path_buf()));
    }
    let mode = meta.permissions().mode() & 0o777;
    if mode & UNSAFE_DIR_BITS != 0 {
        return Err(BindError::UnsafeParentDir {
            path: dir.to_path_buf(),
            mode,
        });
    }
    let euid = nix::unistd::geteuid().as_raw();
    if meta.uid() != euid {
        return Err(BindError::ParentNotOwned {
            path: dir.to_path_buf(),
            owner: meta.uid(),
            euid,
        });
    }
    Ok(())
}

/// Bind a Unix domain socket at `path`, enforcing safe permissions.
///
/// The parent directory is validated, a stale socket is cleaned up if no daemon
/// is listening, and the new socket is created with mode `0600`. The returned
/// [`SocketGuard`] removes the socket file when dropped.
pub fn bind(path: &Path) -> Result<SocketGuard, BindError> {
    let parent = path
        .parent()
        .ok_or_else(|| BindError::ParentMissing(path.to_path_buf()))?;
    ensure_safe_parent_dir(parent)?;

    match fs::symlink_metadata(path) {
        Ok(meta) => {
            if !meta.file_type().is_socket() {
                return Err(BindError::PathExistsNotSocket(path.to_path_buf()));
            }
            // A socket exists: is anything actually listening?
            match UnixStream::connect(path) {
                Ok(_) => return Err(BindError::AlreadyInUse(path.to_path_buf())),
                Err(_) => fs::remove_file(path)?, // stale; safe to remove
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(BindError::Io(e)),
    }

    let listener = UnixListener::bind(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(SOCKET_MODE))?;

    Ok(SocketGuard {
        path: path.to_path_buf(),
        listener,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str, mode: u32) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("mx-agent-sock-{tag}-{nanos}"));
        fs::create_dir_all(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(mode)).unwrap();
        dir
    }

    #[test]
    fn binds_with_restrictive_mode() {
        let dir = temp_dir("ok", 0o700);
        let path = dir.join("daemon.sock");

        let guard = bind(&path).expect("bind should succeed");
        let meta = fs::symlink_metadata(&path).unwrap();
        assert!(meta.file_type().is_socket());
        assert_eq!(meta.permissions().mode() & 0o777, SOCKET_MODE);
        assert_eq!(guard.path(), path);

        drop(guard);
        assert!(!path.exists(), "socket removed on drop");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn refuses_unsafe_parent_dir() {
        let dir = temp_dir("unsafe", 0o755);
        let path = dir.join("daemon.sock");
        match bind(&path) {
            Err(BindError::UnsafeParentDir { mode, .. }) => {
                assert_eq!(mode & UNSAFE_DIR_BITS, 0o055);
            }
            other => panic!("expected UnsafeParentDir, got {other:?}"),
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejects_second_bind_while_listening() {
        let dir = temp_dir("inuse", 0o700);
        let path = dir.join("daemon.sock");
        let _guard = bind(&path).unwrap();
        match bind(&path) {
            Err(BindError::AlreadyInUse(_)) => {}
            other => panic!("expected AlreadyInUse, got {other:?}"),
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn cleans_up_stale_socket() {
        let dir = temp_dir("stale", 0o700);
        let path = dir.join("daemon.sock");
        // Create a socket file, then drop the listener WITHOUT unlinking it
        // (std does not unlink on drop), leaving a stale socket on disk.
        let leaked = UnixListener::bind(&path).unwrap();
        drop(leaked);
        assert!(path.exists());

        let guard = bind(&path).expect("stale socket should be replaced");
        assert!(fs::symlink_metadata(&path).unwrap().file_type().is_socket());
        drop(guard);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn refuses_non_socket_file() {
        let dir = temp_dir("regular", 0o700);
        let path = dir.join("daemon.sock");
        fs::write(&path, b"not a socket").unwrap();
        match bind(&path) {
            Err(BindError::PathExistsNotSocket(_)) => {}
            other => panic!("expected PathExistsNotSocket, got {other:?}"),
        }
        assert!(path.exists(), "non-socket file must not be deleted");
        let _ = fs::remove_dir_all(&dir);
    }
}
