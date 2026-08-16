//! Binding a unix socket the server owns.
//!
//! One contract, two users: the control socket and a `unix` data-plane
//! listener follow exactly the same bind/reclaim/unlink rules, so they share
//! this implementation instead of each growing their own near-copy of it.
//!
//! The bind contract exists because a unix socket outlives the process that
//! made it: the path left behind after a crash is indistinguishable, by
//! looking, from the path of a running server. So the decision is made by
//! *connecting*, not by stat alone:
//!
//! * the path does not exist — bind;
//! * it is a socket and a connection succeeds — another daemon owns it,
//!   startup fails instead of stealing the name;
//! * it is a socket and the connection is refused — it is stale, unlink and
//!   bind;
//! * it is anything else — startup fails; the server never deletes a file it
//!   did not create.
//!
//! **The path is claimed before that decision is made.** No syscall makes
//! "probe, unlink if stale, bind" atomic, and the sequence is not safe to run
//! twice at once: two daemons starting together can both find the same socket
//! stale, and the loser then unlinks the winner's freshly bound socket and
//! binds an unreachable one over it — leaving two live daemons, one of them
//! nameless. So a daemon first claims the path through the sidecar lock (see
//! [`crate::lockfile`]) and *keeps* the claim for the socket's lifetime: the
//! sequence is serialized, and a second daemon is refused by ownership, not
//! by what the path happens to look like at the instant it looks. A
//! crashed daemon's claim dies with it, which is what leaves the stale-socket
//! branch above its job.
//!
//! Permissions are owner-only and established race-safely: the umask is
//! tightened around `bind` so the socket is never momentarily group- or
//! world-accessible, then the resulting mode is verified and corrected. The
//! socket is unlinked when the listener is dropped, which covers both clean
//! shutdown and a panic.

use std::fs::File;
use std::io;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use std::{fs, os::unix::fs::PermissionsExt};

use rustix::fs::{AtFlags, FileType, Mode, OFlags, StatxFlags};

use crate::lockfile;

/// The mode a server-owned socket is created with: owner-only, because
/// anything that can talk to the control socket can reconfigure every
/// namespace, and anything that can talk to a data socket can mount one.
pub const SOCKET_MODE: u32 = 0o600;

/// The umask held across `bind`: everything but owner access is masked off.
const BIND_UMASK: u32 = 0o177;

/// Serializes the process-global umask window across concurrent bind callers.
static UMASK: Mutex<()> = Mutex::new(());

/// A bound unix socket that unlinks itself when dropped.
///
/// The listener is kept in its blocking `std` form so that binding — and
/// therefore the whole bind contract — happens without a running async
/// runtime; [`take`](Self::take) hands it to the reactor when serving starts.
#[derive(Debug)]
pub struct UnixSocket {
    listener: Option<UnixListener>,
    path: PathBuf,
    /// The claim on the path, held solely for its lifetime: closing the file
    /// releases it. `Drop` below unlinks the socket first, so the path is free
    /// before the next daemon can claim it.
    _claim: File,
}

impl UnixSocket {
    /// Binds the socket per the contract above.
    ///
    /// # Errors
    ///
    /// Returns [`BindError::InUse`] if another daemon already owns the path,
    /// [`BindError::NotASocket`] if the path holds something else, and
    /// [`BindError::Io`] for any failing filesystem or socket operation.
    pub fn bind(path: &Path) -> Result<Self, BindError> {
        let claim = claim(path)?;
        reclaim(path)?;
        let listener = bind_owner_only(path)?;
        Self::finish(path, claim, listener, |listener| {
            verify_mode(path)?;
            listener
                .set_nonblocking(true)
                .map_err(|source| BindError::Io {
                    path: path.to_path_buf(),
                    source,
                })
        })
    }

    /// Constructs the unlinking guard before running fallible post-bind setup.
    fn finish(
        path: &Path,
        claim: File,
        listener: UnixListener,
        setup: impl FnOnce(&UnixListener) -> Result<(), BindError>,
    ) -> Result<Self, BindError> {
        let socket = Self {
            listener: Some(listener),
            path: path.to_path_buf(),
            _claim: claim,
        };
        setup(
            socket
                .listener
                .as_ref()
                .expect("newly constructed socket owns its listener"),
        )?;
        Ok(socket)
    }

    /// The socket path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Takes the blocking listener out, for handing to the async reactor.
    ///
    /// Returns `None` if it was already taken; the socket is still unlinked on
    /// drop either way.
    pub fn take(&mut self) -> Option<UnixListener> {
        self.listener.take()
    }
}

impl Drop for UnixSocket {
    /// Unlinks the socket. A path left behind would make the next startup do
    /// the stale-socket dance for no reason.
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

/// Claims the path against every other daemon, for this socket's lifetime.
///
/// The claim is what makes the reclaim-and-bind sequence below safe even when
/// the daemons of two machines race on it; see the module documentation.
fn claim(path: &Path) -> Result<File, BindError> {
    lockfile::claim_sidecar(path)
        .map_err(|source| BindError::Io {
            path: lockfile::sidecar_path(path),
            source,
        })?
        .ok_or_else(|| BindError::InUse {
            path: path.to_path_buf(),
        })
}

/// Decides what to do with whatever already occupies the path.
fn reclaim(path: &Path) -> Result<(), BindError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(source) => {
            return Err(BindError::Io {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    if !is_socket(&metadata) {
        return Err(BindError::NotASocket {
            path: path.to_path_buf(),
        });
    }
    match UnixStream::connect(path) {
        // Someone answered: the path belongs to a running server.
        Ok(_) => Err(BindError::InUse {
            path: path.to_path_buf(),
        }),
        // Nobody is listening: the socket is a leftover.
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {
            match fs::remove_file(path) {
                Ok(()) => Ok(()),
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
                Err(source) => Err(BindError::Io {
                    path: path.to_path_buf(),
                    source,
                }),
            }
        }
        Err(source) => Err(BindError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

/// Whether a directory entry is a unix socket.
fn is_socket(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::FileTypeExt;
    metadata.file_type().is_socket()
}

/// Binds with a tightened umask; the caller verifies the resulting mode after
/// installing the unlinking guard.
fn bind_owner_only(path: &Path) -> Result<UnixListener, BindError> {
    let _umask = umask_lock();
    let previous = rustix::process::umask(Mode::from_bits_truncate(BIND_UMASK));
    let bound = UnixListener::bind(path);
    rustix::process::umask(previous);
    bound.map_err(|source| BindError::Io {
        path: path.to_path_buf(),
        source,
    })
}

/// Verifies the bound directory entry and corrects its mode through a pinned
/// path fd, never following a replacement symlink into chmod.
fn verify_mode(path: &Path) -> Result<(), BindError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| BindError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if !is_socket(&metadata) {
        return Err(BindError::NotASocket {
            path: path.to_path_buf(),
        });
    }
    if metadata.permissions().mode() & 0o777 != SOCKET_MODE {
        set_socket_permissions(path)?;
    }
    Ok(())
}

/// Corrects the socket mode without ever following a replacement symlink.
fn set_socket_permissions(path: &Path) -> Result<(), BindError> {
    use std::os::fd::AsRawFd;

    let pinned = rustix::fs::openat(
        rustix::fs::CWD,
        path,
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|source| BindError::Io {
        path: path.to_path_buf(),
        source: source.into(),
    })?;
    let pinned_metadata = rustix::fs::statx(
        &pinned,
        "",
        AtFlags::EMPTY_PATH | AtFlags::SYMLINK_NOFOLLOW,
        StatxFlags::TYPE,
    )
    .map_err(|source| BindError::Io {
        path: path.to_path_buf(),
        source: source.into(),
    })?;
    if FileType::from_raw_mode(u32::from(pinned_metadata.stx_mode)) != FileType::Socket {
        return Err(BindError::NotASocket {
            path: path.to_path_buf(),
        });
    }
    let pinned_path = format!("/proc/self/fd/{}", pinned.as_raw_fd());
    fs::set_permissions(&pinned_path, fs::Permissions::from_mode(SOCKET_MODE)).map_err(|source| {
        BindError::Io {
            path: path.to_path_buf(),
            source,
        }
    })
}

/// Takes the umask window lock, continuing after a panicking caller restored
/// the mask during unwinding.
fn umask_lock() -> MutexGuard<'static, ()> {
    UMASK.lock().unwrap_or_else(|poison| poison.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    use crate::testing::scratch_root;

    static SEQUENCE: AtomicU64 = AtomicU64::new(0);

    /// A socket path short enough to bind: see [`scratch_root`].
    fn path(label: &str) -> PathBuf {
        scratch_root().join(format!(
            "voidport-socket-{label}-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn a_post_bind_failure_unlinks_the_socket() {
        let path = path("setup-failure.sock");
        let claim = claim(&path).expect("the path is claimable");
        let listener = bind_owner_only(&path).expect("the socket binds");
        let error = UnixSocket::finish(&path, claim, listener, |_| {
            Err(BindError::Io {
                path: path.clone(),
                source: io::Error::other("forced setup failure"),
            })
        })
        .expect_err("setup fails");
        assert!(matches!(error, BindError::Io { .. }));
        assert!(!path.exists(), "the guard must unlink on every error path");
    }

    #[test]
    fn a_vanished_stale_socket_is_already_reclaimed() {
        let path = path("vanished.sock");
        drop(UnixListener::bind(&path).expect("the stale socket binds"));
        fs::remove_file(&path).expect("the socket vanishes");
        reclaim(&path).expect("a vanished path is free");
    }
}

/// Why a server-owned unix socket could not be bound.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BindError {
    /// Another daemon owns this path: it holds the claim on it, or it answers
    /// on the socket.
    #[error("unix socket {path} is already served by another voidportd instance")]
    InUse {
        /// The socket path.
        path: PathBuf,
    },
    /// The path exists and is not a socket, so it is not ours to replace.
    #[error("unix socket path {path} exists and is not a socket")]
    NotASocket {
        /// The offending path.
        path: PathBuf,
    },
    /// A filesystem or socket operation failed.
    #[error("cannot bind unix socket {path}")]
    Io {
        /// The path the failing step touched.
        path: PathBuf,
        /// The underlying failure.
        #[source]
        source: io::Error,
    },
}
