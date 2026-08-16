//! The state file: source document, loader, and durable persistence.
//!
//! The design's load-bearing model is a **source/runtime split**:
//!
//! * the [`document`] is the persistent source of truth and holds exactly what
//!   the operator wrote — `"uid"` sentinels and relative host targets stay as
//!   written;
//! * [`build`] turns one namespace of that document into runtime engine state
//!   ([`crate::namespace::Namespace`]), resolving sentinels and relative
//!   targets against an injected [`Environment`];
//! * [`persist`] re-emits the document verbatim, so a mutation can never bake
//!   a sentinel into one machine's uid, and `load(persist(x)) == x` holds.
//!
//! The shared configuration schema lives here too — [`limits::Limits`] is a
//! `[server]` setting, so it sits with the document that holds it and the
//! layers above consume it. [`Listener`] is the same kind of setting but is
//! defined in `voidport-control`, because `listener-add` carries it over the
//! wire as well; it is re-exported here so the state layer reads as one
//! schema.
//!
//! [`load`] joins the two: it reads the file, validates every namespace
//! through the engine's build boundary, and enriches the typed errors with the
//! namespace they came from. [`lock`] keeps a second daemon off the same file.
//!
//! Nothing in this module reads the process environment on its own: the
//! invoking identity and the state file's directory arrive as an
//! [`Environment`], which is what makes sentinel and relative-path tests
//! hermetic.

pub mod build;
pub mod document;
pub mod limits;
pub mod lock;
pub mod persist;

mod load;

use std::path::{Path, PathBuf};

pub use build::{NamespaceError, build_namespace};
pub use document::{ServerSettings, StateDocument};
pub use limits::{Limits, LimitsError};
pub use load::{LoadError, LoadedState, load, load_document, validate};
pub use lock::{InstanceLock, LockError};
pub use persist::{PersistError, create_if_missing, persist, sweep_orphans};
pub use voidport_control::Listener;

/// The environment a state document is interpreted in.
///
/// Both resolutions the source form defers — the `"uid"`/`"gid"` sentinels and
/// relative host targets — happen against this value, and it is injected
/// and not discovered, so a test can pin an identity and a directory
/// without touching the process it runs in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Environment {
    /// The invoking user's uid, what the `"uid"` sentinel resolves to.
    pub uid: u32,
    /// The invoking user's gid, what the `"gid"` sentinel resolves to.
    pub gid: u32,
    /// The state file's directory, which relative host targets resolve
    /// against.
    pub state_dir: PathBuf,
}

impl Environment {
    /// Builds an environment explicitly.
    #[must_use]
    pub fn new(uid: u32, gid: u32, state_dir: impl Into<PathBuf>) -> Self {
        Self {
            uid,
            gid,
            state_dir: state_dir.into(),
        }
    }

    /// The environment of the running process for a given state file.
    ///
    /// The identity is the real (not effective) uid/gid — the operator who
    /// started the server, which is what a portable configuration means by
    /// "the invoking user".
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

/// The directory containing a state path; bare filenames live in `.`.
///
/// One definition, because two callers depend on it: the environment relative
/// host targets resolve against, and the directory a seeded launch places its
/// control socket in.
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
        // A bare filename lives in the working directory.
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
