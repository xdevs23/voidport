//! Once a graft is opened, its descriptor decides: a host-side rename of a
//! grafted tree does not break the graft, and every resolution below the graft
//! starts from the descriptor, so there is no absolute path to race against.

use std::collections::BTreeMap;
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};

use rustix::fs::{CWD, Mode, OFlags, openat};
use rustix::io::Errno;

use crate::host::attr::{FileKind, HostAttr};
use crate::rules::{HostBacking, HostTarget, RuleTable};

/// With `O_NOFOLLOW`, a target whose last component is a symbolic link as that
/// link, dangling or not.
const GRAFT_FLAGS: OFlags = OFlags::PATH.union(OFlags::NOFOLLOW).union(OFlags::CLOEXEC);

#[derive(Debug, Default)]
pub struct Grafts {
    pinned: BTreeMap<HostTarget, PinnedGraft>,
}

/// The kind is read once when the graft is opened, off the fresh descriptor, so
/// the share subscription reports it without host I/O on the publish path.
/// `None` when the stat failed.
#[derive(Debug)]
struct PinnedGraft {
    fd: OwnedFd,
    kind: Option<FileKind>,
}

impl Grafts {
    /// # Errors
    ///
    /// Returns [`GraftError`] naming the first target that cannot be opened.
    pub fn pin(table: &RuleTable) -> Result<Self, GraftError> {
        let mut pinned = BTreeMap::new();
        for target in table.graft_targets() {
            let fd =
                openat(CWD, target.as_str(), GRAFT_FLAGS, Mode::empty()).map_err(|source| {
                    GraftError {
                        target: target.clone(),
                        source,
                    }
                })?;
            let kind = HostAttr::of(fd.as_fd()).ok().map(|attr| attr.kind());
            pinned.insert(target.clone(), PinnedGraft { fd, kind });
        }
        Ok(Self { pinned })
    }

    #[must_use]
    pub fn get(&self, target: &HostTarget) -> Option<BorrowedFd<'_>> {
        self.pinned.get(target).map(|graft| graft.fd.as_fd())
    }

    /// `None` for a target this namespace does not graft, and for one whose stat
    /// failed when the graft was opened.
    #[must_use]
    pub fn kind(&self, target: &HostTarget) -> Option<FileKind> {
        self.pinned.get(target)?.kind
    }

    #[must_use]
    pub fn graft_of(&self, backing: &HostBacking) -> Option<BorrowedFd<'_>> {
        self.get(backing.graft())
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.pinned.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pinned.is_empty()
    }
}

impl PartialEq for Grafts {
    /// Compares the open targets; descriptor numbers are an accident of the
    /// process, not part of the configuration.
    fn eq(&self, other: &Self) -> bool {
        self.pinned.keys().eq(other.pinned.keys())
    }
}

impl Eq for Grafts {}

#[derive(Debug, thiserror::Error)]
#[error("cannot open graft target {target}")]
pub struct GraftError {
    pub target: HostTarget,
    #[source]
    pub source: Errno,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{RuleSpec, ShareMode};
    use voidport_test_host::Scratch;

    #[test]
    fn every_target_is_pinned_once() {
        let scratch = Scratch::new("grafts");
        let first = scratch.directory("first");
        let second = scratch.directory("second");
        let table = RuleTable::build([
            RuleSpec::new("/a", ShareMode::Rw).with_target(first.as_str()),
            RuleSpec::new("/a/inside", ShareMode::Ro),
            RuleSpec::new("/b", ShareMode::Ro).with_target(second.as_str()),
        ])
        .expect("valid table");

        let grafts = Grafts::pin(&table).expect("both targets exist");
        assert_eq!(grafts.len(), 2);
        assert!(!grafts.is_empty());
        assert!(grafts.get(&HostTarget::new(first.clone())).is_some());
        assert!(grafts.get(&HostTarget::new("/nowhere")).is_none());
        assert_eq!(grafts, Grafts::pin(&table).expect("pins again"));
        assert_eq!(
            grafts.kind(&HostTarget::new(first)),
            Some(crate::host::FileKind::Directory)
        );
        assert_eq!(grafts.kind(&HostTarget::new("/nowhere")), None);
    }

    #[test]
    fn a_target_that_is_a_link_pins_the_link() {
        let scratch = Scratch::new("grafts-link");
        let directory = scratch.directory("real");
        let file = scratch.file("real/file", b"contents");
        let links = [
            ("to-directory", directory.as_str().to_owned()),
            ("to-file", file.display().to_string()),
            ("dangling", "nowhere/at/all".to_owned()),
            ("to-link", "to-directory".to_owned()),
        ];
        for (name, text) in &links {
            std::os::unix::fs::symlink(text, scratch.join(name)).expect("writable");
        }
        let target = |name: &str| scratch.join(name).display().to_string();
        let table = RuleTable::build(links.iter().enumerate().map(|(index, (name, _))| {
            RuleSpec::new(format!("/rule{index}"), ShareMode::Ro).with_target(target(name))
        }))
        .expect("valid table");

        let grafts = Grafts::pin(&table).expect("a link pins, dangling or not");
        for (name, text) in &links {
            let target = HostTarget::new(target(name));
            assert_eq!(grafts.kind(&target), Some(FileKind::Symlink), "{name}");
            let fd = grafts.get(&target).expect("pinned");
            let read = rustix::fs::readlinkat(fd, "", Vec::new()).expect("the fd is the link");
            assert_eq!(read.to_bytes(), text.as_bytes(), "{name}");
        }
    }

    #[test]
    fn a_missing_target_refuses_the_build() {
        let table = RuleTable::build([
            RuleSpec::new("/a", ShareMode::Rw).with_target("/nonexistent/voidport/graft")
        ])
        .expect("valid table");
        let error = Grafts::pin(&table).expect_err("the target is not there");
        assert_eq!(error.source, Errno::NOENT);
        assert!(
            error.to_string().contains("/nonexistent/voidport/graft"),
            "{error}"
        );
    }

    #[test]
    fn a_namespace_with_no_grafts_pins_nothing() {
        let grafts = Grafts::pin(&RuleTable::default()).expect("nothing to pin");
        assert!(grafts.is_empty());
        assert_eq!(grafts, Grafts::default());
    }
}
