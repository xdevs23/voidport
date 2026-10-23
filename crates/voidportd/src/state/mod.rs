pub mod build;
pub mod document;
pub mod lock;
pub mod persist;

mod load;

use std::path::{Path, PathBuf};

pub use build::{NamespaceError, build_namespace};
pub use document::{
    MIN_NODE_DESCRIPTOR_BUDGET, ServerSettings, ServerSettingsError, StateDocument,
};
pub use load::{LoadError, LoadedState, load, load_document, validate};
pub use lock::{InstanceLock, LockError};
pub use persist::{PersistError, create_if_missing, persist, sweep_orphans};
pub use voidport_control::Listener;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Environment {
    pub uid: u32,
    pub gid: u32,
    pub state_dir: PathBuf,
}

impl Environment {
    #[must_use]
    pub fn new(uid: u32, gid: u32, state_dir: impl Into<PathBuf>) -> Self {
        Self {
            uid,
            gid,
            state_dir: state_dir.into(),
        }
    }

    /// Uses the real uid and gid, not the effective ones.
    #[must_use]
    pub fn for_state_file(state_file: &Path) -> Self {
        let state_dir = containing_directory(state_file).to_path_buf();
        Self {
            uid: rustix::process::getuid().as_raw(),
            gid: rustix::process::getgid().as_raw(),
            state_dir,
        }
    }
}

/// The directory containing a state path; bare filenames are in `.`.
#[must_use]
pub fn containing_directory(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_environment_takes_the_state_files_directory() {
        assert_eq!(
            Environment::for_state_file(Path::new("/srv/voidport/state.toml")).state_dir,
            PathBuf::from("/srv/voidport")
        );
        assert_eq!(
            Environment::for_state_file(Path::new("state.toml")).state_dir,
            PathBuf::from(".")
        );
        let injected = Environment::new(7, 8, "/srv");
        assert_eq!((injected.uid, injected.gid), (7, 8));
        assert_eq!(injected.state_dir, PathBuf::from("/srv"));
    }

    #[test]
    fn the_squash_default_agrees_with_the_rule_engine() {
        assert_eq!(
            voidport_control::DEFAULT_SQUASH_ID,
            crate::rules::DEFAULT_SQUASH_ID
        );
    }
}
