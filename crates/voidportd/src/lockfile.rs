//! `flock` binds to an inode, and the state file and the control socket path are
//! names that get a new inode on every persist or rebind. The lock is therefore
//! taken on a sidecar `<name>.lock` that is created once and never replaced or
//! unlinked.

use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use rustix::fs::{FlockOperation, flock};

pub const LOCK_EXTENSION: &str = "lock";

const LOCK_FILE_MODE: u32 = 0o600;

#[must_use]
pub fn sidecar_path(guarded: &Path) -> PathBuf {
    let mut name = guarded.file_name().unwrap_or_default().to_os_string();
    name.push(".");
    name.push(LOCK_EXTENSION);
    guarded.with_file_name(name)
}

/// The returned file is the claim: closing it releases the lock.
///
/// # Errors
///
/// Returns the failure to create or lock the sidecar.
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

/// The lock lives on the inode, so it also excludes a process that reached the
/// same inode through another name.
///
/// # Errors
///
/// Returns any locking failure except another process holding the lock.
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
