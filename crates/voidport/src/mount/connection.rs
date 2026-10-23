use std::fs::File;
use std::io::{self, Write as _};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use rustix::fs::{AtFlags, CWD, StatxFlags, statx};

use super::SETTLE_POLL;

/// `waiting` counts the replies the kernel is still owed. The callbacks that
/// the adapter counts do not include a request that the kernel has queued and no
/// dispatch loop has picked up yet.
///
/// `abort` ends the connection while the mountpoint is still mounted, because a
/// successful unmount alone may not end it: a process that copied the mount
/// namespace with private propagation, as a sandboxed build does, has a mount of
/// the connection that the unmount does not affect. The file is opened while the
/// mount goes up and kept open, because the directory is named after the device
/// number of the mount, which the kernel assigns to the next mount once this
/// connection is gone. A write through the descriptor affects this connection
/// or none.
///
/// Where `fusectl` is not mounted, neither file exists.
#[derive(Debug)]
pub(super) struct KernelConnection {
    waiting: Option<PathBuf>,
    abort: Option<Abort>,
}

#[derive(Debug)]
struct Abort {
    path: PathBuf,
    file: Arc<File>,
}

#[derive(Clone, Debug)]
pub struct AbortHandle {
    file: Option<Arc<File>>,
}

impl AbortHandle {
    /// A connection that the kernel already destroyed ignores the write.
    pub fn abort(&self) -> Result<(), AbortError> {
        let file = self.file.as_deref().ok_or(AbortError::Unavailable)?;
        (&*file).write_all(b"1").map_err(AbortError::Write)
    }
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AbortError {
    #[error("the abort file of the kernel connection could not be opened when the mount went up")]
    Unavailable,
    #[error("the write to the abort file of the kernel connection failed")]
    Write(#[source] io::Error),
}

/// A connection without an abort file is not logged again, since that was
/// reported when the mount went up.
pub(super) fn report_unended(aborted: Result<(), AbortError>) {
    if let Err(AbortError::Write(error)) = aborted {
        tracing::warn!(
            %error,
            "the kernel connection used by the mount could not be aborted, so it ends once every descriptor of it is closed"
        );
    }
}

impl KernelConnection {
    /// The directory of each connection in `fusectl` is named after the device
    /// number of the superblock, as `major << 20 | minor`. The `statx` requests
    /// no attributes and passes `AT_STATX_DONT_SYNC`, so the kernel answers from
    /// the superblock without a request through the session, which may be
    /// waiting on a server that does not answer.
    pub(super) fn of(mountpoint: &Path) -> Self {
        let directory = match statx(
            CWD,
            mountpoint,
            AtFlags::STATX_DONT_SYNC,
            StatxFlags::empty(),
        ) {
            Ok(mount) => Path::new("/sys/fs/fuse/connections")
                .join(((mount.stx_dev_major << 20) | mount.stx_dev_minor).to_string()),
            Err(error) => {
                tracing::warn!(
                    %error,
                    mountpoint = %mountpoint.display(),
                    "the device of the mount could not be read, so a teardown cannot abort \
                     the kernel connection, and a teardown on a signal waits for every \
                     copy of the mount in another mount namespace"
                );
                return Self {
                    waiting: None,
                    abort: None,
                };
            }
        };
        let abort = directory.join("abort");
        Self {
            waiting: Some(directory.join("waiting")).filter(|waiting| waiting.exists()),
            abort: match File::options().write(true).open(&abort) {
                Ok(file) => Some(Abort {
                    path: abort,
                    file: Arc::new(file),
                }),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    tracing::warn!(
                        directory = %directory.display(),
                        "fusectl has no directory for the kernel connection of the mount, so a \
                         teardown on a signal waits for every copy of the mount in another \
                         mount namespace, \
                         and an unmount cannot show that the pages of the mount are gone, which \
                         keeps the leases of the session until the window has passed; mount \
                         fusectl on /sys/fs/fuse/connections to avoid both"
                    );
                    None
                }
                Err(error) => {
                    tracing::warn!(
                        %error,
                        file = %abort.display(),
                        "the abort file of the kernel connection could not be opened, so a \
                         teardown on a signal waits for every copy of the mount in another \
                         mount namespace"
                    );
                    None
                }
            },
        }
    }

    pub(super) fn abort(&self) -> Result<(), AbortError> {
        self.abort_handle().abort()
    }

    pub(super) fn abort_handle(&self) -> AbortHandle {
        AbortHandle {
            file: self.abort.as_ref().map(|abort| Arc::clone(&abort.file)),
        }
    }

    /// A kernel that does not publish the number gives `false`, because an
    /// unknown is not a reason to go on waiting.
    pub(super) fn is_waiting(&self) -> bool {
        self.waiting().is_some_and(|waiting| waiting > 0)
    }

    /// The file is opened again on every call, because `fusectl` opens it
    /// without a file position (`nonseekable_open`), and only the first read of
    /// an open file returns the number.
    fn waiting(&self) -> Option<usize> {
        let waiting = self.waiting.as_ref()?;
        std::fs::read_to_string(waiting).ok()?.trim().parse().ok()
    }

    /// The kernel removes the directory of the connection from `fusectl` when
    /// it destroys the connection (`fuse_conn_destroy`). The path of the `abort`
    /// file then names no file, or the file of a later connection with the same
    /// device number, which is another inode than the file opened while the
    /// mount went up. Without `fusectl` the answer is `false`.
    pub(super) fn destroyed(&self) -> bool {
        let Some(abort) = &self.abort else {
            return false;
        };
        match (std::fs::metadata(&abort.path), abort.file.metadata()) {
            (Err(error), _) => error.kind() == io::ErrorKind::NotFound,
            (Ok(named), Ok(opened)) => (named.dev(), named.ino()) != (opened.dev(), opened.ino()),
            (Ok(_), Err(_)) => false,
        }
    }

    pub(super) fn settle(&self, deadline: Instant) {
        while self.is_waiting() {
            if Instant::now() >= deadline {
                return;
            }
            std::thread::sleep(SETTLE_POLL);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn a_path_that_is_not_a_mount_has_no_connection_to_ask() {
        let connection = KernelConnection::of(Path::new("/proc/self"));
        assert!(connection.waiting.is_none());
        assert!(connection.abort.is_none());
        assert_eq!(connection.waiting(), None);
        assert!(
            !connection.is_waiting(),
            "an unknown is not something to wait on"
        );
        assert!(
            !connection.destroyed(),
            "a connection that cannot be seen is not shown destroyed"
        );
        connection.settle(Instant::now() + Duration::from_secs(30));
        assert!(
            matches!(connection.abort(), Err(AbortError::Unavailable)),
            "a connection that cannot be seen cannot be ended"
        );
        assert!(
            matches!(
                connection.abort_handle().abort(),
                Err(AbortError::Unavailable)
            ),
            "nor through a handle"
        );
    }
}
