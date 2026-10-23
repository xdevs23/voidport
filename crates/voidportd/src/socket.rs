//! A unix socket outlives the process that made it, so the path left behind by
//! a crash looks like the path of a running server. The bind decides by
//! connecting: a missing path is bound, a socket that accepts is in use, a
//! socket that refuses is stale and replaced, and anything else fails. A file
//! the server did not create is never deleted.
//!
//! The path is claimed through the sidecar lock before that decision, and the
//! claim lasts as long as the socket. Probe, unlink and bind is not atomic: two
//! daemons starting together could both find the socket stale, and the loser
//! would unlink the socket of the winner.
//!
//! The umask is tightened around `bind`, so the socket is never briefly
//! accessible to a group or to the world.

use std::fs::File;
use std::io;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use std::{fs, os::unix::fs::PermissionsExt};

use rustix::fs::{AtFlags, FileType, Mode, OFlags, StatxFlags};

use crate::lockfile;

pub const SOCKET_MODE: u32 = 0o600;

const BIND_UMASK: u32 = 0o177;

/// The umask is process-wide, so concurrent binds take this lock from the
/// change of the umask until its restore.
static UMASK: Mutex<()> = Mutex::new(());

/// The listener is in its blocking `std` form, so binding happens without a
/// running async runtime.
#[derive(Debug)]
pub struct UnixSocket {
    listener: Option<UnixListener>,
    path: PathBuf,
    /// `Drop` unlinks the socket before this file closes, so the path is free
    /// before the next daemon claims it.
    _claim: File,
}

impl UnixSocket {
    /// # Errors
    ///
    /// Returns [`BindError::InUse`] if another daemon already uses the path,
    /// [`BindError::NotASocket`] if something else is at the path, and
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

    fn finish(
        path: &Path,
        claim: File,
        listener: UnixListener,
        setup: impl FnOnce(&UnixListener) -> Result<(), BindError>,
    ) -> Result<Self, BindError> {
        // The socket exists before the fallible setup runs, so a failed setup
        // still unlinks the path in `Drop`.
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

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn take(&mut self) -> Option<UnixListener> {
        self.listener.take()
    }
}

impl Drop for UnixSocket {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

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
        Ok(_) => Err(BindError::InUse {
            path: path.to_path_buf(),
        }),
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

fn is_socket(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::FileTypeExt;
    metadata.file_type().is_socket()
}

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

    use voidport_test_host::scratch_root;

    static SEQUENCE: AtomicU64 = AtomicU64::new(0);

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

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BindError {
    #[error("unix socket {path} is already served by another voidportd instance")]
    InUse { path: PathBuf },
    #[error("unix socket path {path} exists and is not a socket")]
    NotASocket { path: PathBuf },
    #[error("cannot bind unix socket {path}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}
