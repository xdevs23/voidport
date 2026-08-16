//! Fd-pinned grafts.
//!
//! Grafts are pinned, not path-pinned: when a namespace is built — at load and
//! at every accepted mutation — the server opens each graft target with
//! `O_PATH` and keeps the descriptor for as long as that built namespace lives.
//! Two consequences, both load-bearing:
//!
//! * a host-side rename of a grafted tree does not break the graft, because the
//!   name was only ever used once;
//! * every resolution below the graft starts from the descriptor, which is what
//!   makes `openat2`'s containment (see [`super::open`]) meaningful in the
//!   first place — there is no absolute path to race against.
//!
//! A target that cannot be opened is a typed build error, so a namespace naming
//! a directory that is not there is refused where every other invalid namespace
//! is refused: before anything is published, consistent with
//! validate → persist → swap.

use std::collections::BTreeMap;
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};

use rustix::fs::{CWD, Mode, OFlags, openat};
use rustix::io::Errno;

use crate::host::attr::{FileKind, HostAttr};
use crate::rules::{HostBacking, HostTarget, RuleTable};

/// The flags a graft target is pinned with.
///
/// `O_PATH` names the inode without granting access to its contents, which is
/// all a graft root is for. Symlinks *are* followed here, and only here: the
/// target is what the operator configured, resolved once, at pin time.
const GRAFT_FLAGS: OFlags = OFlags::PATH.union(OFlags::CLOEXEC);

/// The pinned descriptors of one namespace's grafts, keyed by configured
/// target.
///
/// Equality compares the *targets*, not the descriptors: two builds of the same
/// configuration are the same graft set even though their descriptor numbers
/// differ, which is what lets the built state stay comparable in tests and in
/// the snapshot types that carry it.
#[derive(Debug, Default)]
pub struct Grafts {
    pinned: BTreeMap<HostTarget, PinnedGraft>,
}

/// One pinned graft root: its descriptor, and what kind of entry it turned out
/// to be.
///
/// The kind is read **once**, at pin time, off the descriptor that was just
/// opened — no extra resolution, no name, no race. It exists because the share
/// subscription must report a stated target's kind without any fresh host I/O
/// on the publish path, and this is the one moment the server already has the
/// entry in hand. `None` is a target whose stat failed: the graft is pinned, so
/// it is still a graft, and the subscription reports its kind as unknown
/// instead of guessing.
#[derive(Debug)]
struct PinnedGraft {
    fd: OwnedFd,
    kind: Option<FileKind>,
}

impl Grafts {
    /// Pins every graft target of a rule table.
    ///
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

    /// The descriptor pinning `target`, if this namespace grafts it.
    #[must_use]
    pub fn get(&self, target: &HostTarget) -> Option<BorrowedFd<'_>> {
        self.pinned.get(target).map(|graft| graft.fd.as_fd())
    }

    /// What kind of host entry `target` was when it was pinned.
    ///
    /// `None` for a target this namespace does not graft, and for one whose
    /// stat failed at pin time.
    #[must_use]
    pub fn kind(&self, target: &HostTarget) -> Option<FileKind> {
        self.pinned.get(target)?.kind
    }

    /// The descriptor pinning the graft a backing belongs to.
    ///
    /// A backing that names a graft this namespace does not hold cannot arise
    /// from its own rule table; callers that resolve through a foreign table
    /// get `None`, not a descriptor from somewhere else.
    #[must_use]
    pub fn graft_of(&self, backing: &HostBacking) -> Option<BorrowedFd<'_>> {
        self.get(backing.graft())
    }

    /// How many targets are pinned.
    #[must_use]
    pub fn len(&self) -> usize {
        self.pinned.len()
    }

    /// Whether the namespace grafts nothing at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pinned.is_empty()
    }
}

impl PartialEq for Grafts {
    /// Compares the pinned targets; descriptor numbers are an accident of the
    /// process, not part of the configuration.
    fn eq(&self, other: &Self) -> bool {
        self.pinned.keys().eq(other.pinned.keys())
    }
}

impl Eq for Grafts {}

/// A graft target that could not be pinned.
#[derive(Debug, thiserror::Error)]
#[error("cannot open graft target {target}")]
pub struct GraftError {
    /// The target as the rule table resolved it.
    pub target: HostTarget,
    /// Why the open failed.
    #[source]
    pub source: Errno,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{RuleSpec, ShareMode};
    use crate::testing::Scratch;

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
        // The kind is recorded when the target is pinned, so the subscription
        // can report it without touching the host again.
        assert_eq!(
            grafts.kind(&HostTarget::new(first)),
            Some(crate::host::FileKind::Directory)
        );
        assert_eq!(grafts.kind(&HostTarget::new("/nowhere")), None);
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
