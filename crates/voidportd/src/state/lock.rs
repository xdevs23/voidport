//! The sidecar `<state file>.lock` protects the name: a persist renames a new
//! inode over the state file, so a lock on the file itself would be stranded on
//! the old inode. It belongs to the resolved name, never to the spelling the
//! daemon was started with, because a symbolic link resolves afresh on every
//! open and a sidecar derived from the name of the link would give a second
//! daemon a different lock over the same document.
//!
//! The lock on the inode of the state file protects against a second daemon
//! started through a hard link, whose sidecar is a different file. It is taken
//! at startup and never renewed, so a hard link made after a persist is not
//! covered. Only the persist step could lock each new inode before the rename
//! publishes it.
//!
//! Both locks are advisory and released when the process dies. The sidecar is
//! never unlinked, because racing to unlink it is how such locks are lost.

use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};

use crate::lockfile;

#[derive(Debug)]
pub struct InstanceLock {
    path: PathBuf,
    _sidecar: File,
    /// `None` if the file cannot be opened, which the loader reports.
    _state_inode: Option<File>,
}

impl InstanceLock {
    /// # Errors
    ///
    /// Returns [`LockError::Held`] if another daemon already holds the lock on
    /// the file under this or any other name, and [`LockError::Io`] if the lock
    /// cannot be created or taken.
    pub fn acquire(state_file: &Path) -> Result<Self, LockError> {
        let claimed = resolve(state_file);
        let path = lockfile::sidecar_path(&claimed);
        let sidecar = lockfile::claim_sidecar(&claimed)
            .map_err(|source| LockError::Io {
                path: path.clone(),
                source,
            })?
            .ok_or_else(|| LockError::Held { path: path.clone() })?;
        Ok(Self {
            path,
            _sidecar: sidecar,
            _state_inode: claim_state_inode(&claimed)?,
        })
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// A hard link is the alias that path resolution cannot unify, because it is a
/// second real name for one inode.
///
/// A state file that cannot be opened is an error reported by the loader.
fn claim_state_inode(state_file: &Path) -> Result<Option<File>, LockError> {
    let Ok(file) = File::open(state_file) else {
        return Ok(None);
    };
    let taken = lockfile::lock_exclusive(&file).map_err(|source| LockError::Io {
        path: state_file.to_path_buf(),
        source,
    })?;
    if taken {
        Ok(Some(file))
    } else {
        Err(LockError::Held {
            path: state_file.to_path_buf(),
        })
    }
}

#[must_use]
pub fn lock_path(state_file: &Path) -> PathBuf {
    lockfile::sidecar_path(&resolve(state_file))
}

/// Every symbolic link in the path is followed, so all spellings of one file
/// claim one sidecar. A path that does not resolve is used as written.
fn resolve(state_file: &Path) -> PathBuf {
    if let Ok(resolved) = fs::canonicalize(state_file) {
        return resolved;
    }
    // The file need not exist yet, and then only its directory can be resolved.
    let (Some(parent), Some(name)) = (state_file.parent(), state_file.file_name()) else {
        return state_file.to_path_buf();
    };
    fs::canonicalize(parent).map_or_else(|_| state_file.to_path_buf(), |parent| parent.join(name))
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LockError {
    #[error("another voidportd instance already owns this state file (lock {path})")]
    Held { path: PathBuf },
    #[error("cannot lock {path}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_lock_file_sits_beside_the_state_file() {
        assert_eq!(
            lock_path(Path::new("/voidport-no-such-directory/state.toml")),
            PathBuf::from("/voidport-no-such-directory/state.toml.lock")
        );
        assert_eq!(
            lock_path(Path::new("voidport-no-such-file.toml")),
            PathBuf::from("voidport-no-such-file.toml.lock")
        );
    }

    #[test]
    fn every_spelling_of_one_state_file_names_one_lock_file() {
        let directory = fs::canonicalize(std::env::temp_dir()).expect("a temporary directory");
        assert_eq!(
            lock_path(&directory.join(".").join("voidport-no-such-file.toml")),
            directory.join("voidport-no-such-file.toml.lock")
        );
    }
}
