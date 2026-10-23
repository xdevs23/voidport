//! `DIR` is decided as typed, without canonicalizing. When it is `.`, ends in
//! `/.` or `/`, or has a `..` component, POSIX resolves it through a link, so
//! it is resolved on the host. Otherwise it is made absolute against the
//! working directory without following a link, so `share link` shares the link
//! and `share link/` shares its target.

use std::io;
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Component, Path, PathBuf};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SharedKind {
    Directory,
    Link,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SharedPath {
    path: PathBuf,
    kind: SharedKind,
}

impl SharedPath {
    /// # Errors
    ///
    /// Returns [`SharedPathError::Unreadable`] when the host cannot resolve or
    /// stat the path, and [`SharedPathError::NotShareable`] when it names neither
    /// a directory nor a symbolic link.
    pub fn from_typed(typed: &Path, working_directory: &Path) -> Result<Self, SharedPathError> {
        let unreadable = |source| SharedPathError::Unreadable {
            typed: typed.to_path_buf(),
            source,
        };
        let joined = working_directory.join(typed);
        let path = if typed.as_os_str().is_empty() {
            // The join would turn the empty path into the working directory.
            // The host rejects it, and that error is returned.
            typed.canonicalize().map_err(unreadable)?
        } else if asks_the_host(typed) {
            joined.canonicalize().map_err(unreadable)?
        } else {
            // `components` drops interior `.` components and repeated
            // separators and follows nothing. A leading `.` is the only one it
            // retains, and the join above has made it an interior one.
            joined.components().collect()
        };
        let kind = path.symlink_metadata().map_err(unreadable)?.file_type();
        let kind = if kind.is_dir() {
            SharedKind::Directory
        } else if kind.is_symlink() {
            SharedKind::Link
        } else {
            return Err(SharedPathError::NotShareable { path });
        };
        Ok(Self { path, kind })
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[must_use]
    pub fn kind(&self) -> SharedKind {
        self.kind
    }

    /// A shared link gets a notice, because most people expect the directory
    /// behind it.
    #[must_use]
    pub fn notice(&self) -> Option<String> {
        match self.kind {
            SharedKind::Directory => None,
            SharedKind::Link => Some(format!(
                "{path} is a symbolic link and is shared as a link; share {path}/. to share \
                 the directory it points to",
                path = self.path.display()
            )),
        }
    }
}

fn asks_the_host(typed: &Path) -> bool {
    let text = typed.as_os_str().as_bytes();
    text == b"."
        || text.ends_with(b"/.")
        || text.ends_with(b"/")
        || typed
            .components()
            .any(|component| component == Component::ParentDir)
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SharedPathError {
    #[error("cannot share {typed}")]
    Unreadable {
        typed: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("cannot share {path}: it is not a directory")]
    NotShareable { path: PathBuf },
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use super::*;
    use voidport_test_host::Scratch;

    fn working_directory() -> (Scratch, PathBuf) {
        let scratch = Scratch::new("shared-path");
        scratch.directory("work/real/sub");
        scratch.file("work/file", b"x");
        symlink("real", scratch.join("work/link")).expect("writable");
        symlink("nowhere", scratch.join("work/dangling")).expect("writable");
        symlink("file", scratch.join("work/to-file")).expect("writable");
        // The scratch root may itself sit behind a link, so the expectations are
        // built from this path.
        let work = scratch.join("work");
        (scratch, work)
    }

    fn shared(typed: &str, work: &Path) -> SharedPath {
        SharedPath::from_typed(Path::new(typed), work).expect("shareable")
    }

    #[test]
    fn a_plain_path_to_a_link_shares_the_link_and_says_so() {
        let (_scratch, work) = working_directory();
        for name in ["link", "dangling", "to-file"] {
            for typed in [name.to_owned(), format!("./{name}"), format!(".//./{name}")] {
                let share = shared(&typed, &work);
                assert_eq!(share.path(), work.join(name), "{typed}");
                assert_eq!(share.kind(), SharedKind::Link, "{typed}");
                let notice = share.notice().expect("a shared link is announced");
                assert!(
                    notice.contains(&format!("{}/.", work.join(name).display())),
                    "{notice}"
                );
            }
        }
        let absolute = work.join("link");
        let share = shared(absolute.to_str().expect("a text path"), Path::new("/"));
        assert_eq!(share.path(), absolute);
        assert_eq!(share.kind(), SharedKind::Link);
    }

    #[test]
    fn a_trailing_dot_or_separator_shares_the_resolved_directory() {
        let (_scratch, work) = working_directory();
        let real = work.join("real").canonicalize().expect("resolvable");
        for typed in ["link/.", "link/", "./link/.", "link//"] {
            let share = shared(typed, &work);
            assert_eq!(share.path(), real, "{typed}");
            assert_eq!(share.kind(), SharedKind::Directory, "{typed}");
            assert_eq!(share.notice(), None, "{typed}");
        }
        for typed in ["dangling/.", "dangling/", "to-file/", ""] {
            let error = SharedPath::from_typed(Path::new(typed), &work).expect_err(typed);
            assert!(
                matches!(error, SharedPathError::Unreadable { .. }),
                "{typed}: {error}"
            );
        }
    }

    #[test]
    fn the_working_directory_and_a_parent_component_resolve_on_the_host() {
        let (_scratch, work) = working_directory();
        let real = work.canonicalize().expect("resolvable");
        let inside = work.join("link");
        assert_eq!(shared(".", &inside).path(), real.join("real"));
        // POSIX resolves `..` through the link, so `link/..` is the parent of
        // the target of the link and `link/../real` is `real`.
        assert_eq!(shared("link/..", &work).path(), real);
        assert_eq!(
            shared("link/sub/../../real", &work).path(),
            real.join("real")
        );
    }

    #[test]
    fn a_plain_subdirectory_is_shared_as_typed() {
        let (_scratch, work) = working_directory();
        for typed in ["real/sub", "./real/sub", "real/./sub", "real//sub"] {
            let share = shared(typed, &work);
            assert_eq!(share.path(), work.join("real/sub"), "{typed}");
            assert_eq!(share.kind(), SharedKind::Directory, "{typed}");
        }
        // A link before the last component is left in the path: the host
        // resolves it when the rule is opened, as for any path it is given.
        let share = shared("link/sub", &work);
        assert_eq!(share.path(), work.join("link/sub"));
        assert_eq!(share.kind(), SharedKind::Directory);
    }

    #[test]
    fn anything_else_is_refused() {
        let (_scratch, work) = working_directory();
        let error = SharedPath::from_typed(Path::new("file"), &work).expect_err("a file");
        assert!(
            matches!(&error, SharedPathError::NotShareable { path } if *path == work.join("file")),
            "{error}"
        );
        let error = SharedPath::from_typed(Path::new("absent"), &work).expect_err("absent");
        assert!(
            matches!(error, SharedPathError::Unreadable { .. }),
            "{error}"
        );
    }
}
