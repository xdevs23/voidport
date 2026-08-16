//! The single-instance lock.
//!
//! Two servers owning one state file would each hold their own memory image
//! and overwrite the other's persists, so a second daemon on the same file
//! must fail startup, loudly and immediately.
//!
//! The claim has two parts, because a state file is both a *name* and an
//! *inode* and neither on its own identifies it:
//!
//! * **the sidecar** `<state file>.lock` (see [`crate::lockfile`]), which
//!   guards the name. It has to be a sidecar: a durable persist renames a new
//!   inode over the state file, so a lock held on the file itself would be
//!   stranded on the old, unlinked inode at the first mutation and a second
//!   daemon would lock the new one happily.
//!
//!   The sidecar belongs to the *resolved* name (see [`lock_path`]), never to
//!   the spelling the daemon was started with. A symbolic link is a spelling,
//!   not a file: it resolves afresh on every open, so it follows the state
//!   file through that rename. Deriving the sidecar from a link's own name
//!   would hand a second daemon a lock file of its own over the very same
//!   document — and only from the first persist onwards, since until then the
//!   inode claim below still catches it.
//! * **the state file's own inode**, which guards against a second daemon
//!   started through a *hard link* — a second real name for one inode, which
//!   no amount of path resolution can unify, and whose sidecar is a different
//!   file entirely. Without it two daemons would share one file and each
//!   overwrite the other.
//!
//! The inode claim is taken on the file as it stands at startup and never
//! renewed, so it covers the hard links that exist when the server starts; a
//! hard link *made after* a persist names an inode this daemon never locked.
//! Renewing it would mean locking each new inode before the rename publishes
//! it, which only the persist step can do.
//!
//! Both locks are advisory and process-scoped: they are released when the
//! files close, including when the process dies for any reason, so a crashed
//! server leaves no stale lock behind. The sidecar file itself is left on
//! disk — racing to unlink it is exactly how such locks are lost.

use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};

use crate::lockfile;

/// An exclusive claim on one state file, held for the server's lifetime.
#[derive(Debug)]
pub struct InstanceLock {
    path: PathBuf,
    /// Held solely for its lifetime: closing the file releases the lock.
    _sidecar: File,
    /// The state file as it was at startup, locked so no hard link to it can
    /// be served by a second daemon. `None` only if the file is not readable,
    /// which the loader reports far better than this could.
    _state_inode: Option<File>,
}

impl InstanceLock {
    /// Takes the lock on `state_file`.
    ///
    /// # Errors
    ///
    /// Returns [`LockError::Held`] if another daemon already owns the file
    /// under this or any other name, and [`LockError::Io`] if the lock cannot
    /// be created or taken.
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

    /// The lock file's path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Locks the state file's inode, so that no hard link to it can be served.
///
/// Path resolution already unified every symbolic-link spelling into one
/// sidecar; a hard link is the alias it cannot unify, because it is a second
/// real name for one inode.
///
/// A state file that cannot be opened cannot be aliased either, and whatever
/// is wrong with it is the loader's error to report — with a far better
/// message than this step could produce.
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

/// The lock file that belongs to a state file, whatever it was spelled as.
#[must_use]
pub fn lock_path(state_file: &Path) -> PathBuf {
    lockfile::sidecar_path(&resolve(state_file))
}

/// The name the claim is taken under: the state file with every symbolic link
/// in its path followed, so that all spellings of one file claim one sidecar.
///
/// A path that does not resolve is used as written — a file that is not there
/// has nothing aliasing it, and whatever is wrong with it is the loader's
/// error to report.
fn resolve(state_file: &Path) -> PathBuf {
    if let Ok(resolved) = fs::canonicalize(state_file) {
        return resolved;
    }
    // The state file need not exist yet, and then only its directory can be
    // resolved — which is where the links that matter usually sit anyway.
    let (Some(parent), Some(name)) = (state_file.parent(), state_file.file_name()) else {
        return state_file.to_path_buf();
    };
    fs::canonicalize(parent).map_or_else(|_| state_file.to_path_buf(), |parent| parent.join(name))
}

/// Why the single-instance lock could not be taken.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LockError {
    /// Another daemon holds the lock.
    #[error("another voidportd instance already owns this state file (lock {path})")]
    Held {
        /// The lock file, or the state file itself when an alias of it is
        /// already served.
        path: PathBuf,
    },
    /// The lock file could not be created or locked.
    #[error("cannot lock {path}")]
    Io {
        /// The lock file.
        path: PathBuf,
        /// The underlying failure.
        #[source]
        source: io::Error,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_lock_file_sits_beside_the_state_file() {
        // Nothing here resolves, so the paths are used as written.
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
        // Two names for one directory must not become two claims on the state
        // file inside it, whether or not that file exists yet.
        let directory = fs::canonicalize(std::env::temp_dir()).expect("a temporary directory");
        assert_eq!(
            lock_path(&directory.join(".").join("voidport-no-such-file.toml")),
            directory.join("voidport-no-such-file.toml.lock")
        );
    }
}
