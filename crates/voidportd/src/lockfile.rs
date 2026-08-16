//! Exclusive advisory locks on sidecar files.
//!
//! Two things the server must own exclusively — the state file and the control
//! socket path — are *names*, not inodes: a durable persist renames a new
//! inode over the state file, and the bind contract unlinks and recreates the
//! socket. `flock` binds to an inode, so a lock taken on either name would be
//! stranded on a replaced inode the first time the name is reused, and the
//! next process would happily lock the new one. The lock is therefore taken on
//! a sidecar `<name>.lock`, created once and never replaced, so it stays valid
//! for its owner's whole lifetime.
//!
//! The lock is advisory and process-scoped: the kernel releases it when the
//! file closes, including when the process dies for any reason, so a crashed
//! server leaves no stale lock behind. The sidecar file itself is left on
//! disk — racing to unlink it is exactly how such locks are lost.

use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use rustix::fs::{FlockOperation, flock};

/// The extension a sidecar lock file adds to the name it guards.
pub const LOCK_EXTENSION: &str = "lock";

/// The mode a sidecar lock file is created with: it says who owns a private
/// resource, so it is nobody else's business either.
const LOCK_FILE_MODE: u32 = 0o600;

/// The sidecar lock file that guards `guarded`.
#[must_use]
pub fn sidecar_path(guarded: &Path) -> PathBuf {
    let mut name = guarded.file_name().unwrap_or_default().to_os_string();
    name.push(".");
    name.push(LOCK_EXTENSION);
    guarded.with_file_name(name)
}

/// Takes the exclusive lock on the sidecar guarding `guarded`.
///
/// Returns `Ok(None)` if another process holds it. The returned file *is* the
/// claim: closing it releases the lock, so the caller must keep it alive for
/// as long as it means to own the guarded name.
///
/// # Errors
///
/// Returns the failure to create or lock [`sidecar_path`] of the guarded name.
pub fn claim_sidecar(guarded: &Path) -> io::Result<Option<File>> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(LOCK_FILE_MODE)
        .open(sidecar_path(guarded))?;
    if lock_exclusive(&file)? {
        Ok(Some(file))
    } else {
        Ok(None)
    }
}

/// Takes the exclusive lock on an already open file.
///
/// Returns `Ok(false)` if another process holds it. The lock lives on the
/// file's *inode*, which is what makes it useful for excluding a second
/// process that reached the same inode through a different name.
///
/// # Errors
///
/// Returns any locking failure other than "someone else holds it".
pub fn lock_exclusive(file: &File) -> io::Result<bool> {
    match flock(file, FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => Ok(true),
        Err(rustix::io::Errno::WOULDBLOCK) => Ok(false),
        Err(errno) => Err(errno.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_sidecar_sits_beside_the_name_it_guards() {
        assert_eq!(
            sidecar_path(Path::new("/srv/voidport/state.toml")),
            PathBuf::from("/srv/voidport/state.toml.lock")
        );
        assert_eq!(
            sidecar_path(Path::new("state.toml")),
            PathBuf::from("state.toml.lock")
        );
        assert_eq!(
            sidecar_path(Path::new("/run/voidport/control.sock")),
            PathBuf::from("/run/voidport/control.sock.lock")
        );
    }
}
