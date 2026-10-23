//! Locks belong to the file, not to the handle: a POSIX record lock belongs to
//! its process for the whole file, whichever descriptor placed it, so a file
//! handle joins the lock set of the session for its file
//! ([`crate::data::locks`]). The handle decides whether a request through it
//! may place a lock of its kind, from the access it was opened with.
//!
//! The listing a guest walks is materialized at opendir, so a readdirplus
//! cookie indexes into one stable vector, and cookie 0 rewinds.

use std::collections::HashMap;
use std::sync::Arc;

use rustix::fs::OFlags;
use rustix::io::{Errno, ReadWriteFlags};

use crate::data::cache::{Grant, Unserved};
use crate::data::ids::IdSpace;
use crate::data::locks::{FileLocks, LockAccess, Membership};
use crate::host::lock::LockKind;
use crate::host::{HostIdentity, Io, Transfer};
use crate::rules::{Name, Resolution};

#[derive(Clone, Debug)]
pub struct ListingEntry {
    pub name: Name,
    pub resolution: Resolution,
    /// Makes `readdirplus` cost no `openat2` per entry: a node is keyed by this
    /// identity, so an entry the session has already seen can be named, and its
    /// lookup counted, without opening it again.
    ///
    /// Deliberately not the attributes: attributes as of `opendir` are too old
    /// to hand out, since a listing taken while another writer is working made a
    /// following read of that file return its stale length.
    pub identity: Option<HostIdentity>,
}

#[derive(Debug)]
pub struct DirListing {
    entries: Vec<ListingEntry>,
}

impl DirListing {
    #[must_use]
    pub fn new(entries: Vec<ListingEntry>) -> Self {
        Self { entries }
    }

    /// Cookie 0 is the start of the listing, and entry `i` hands out cookie
    /// `i + 1`.
    #[must_use]
    pub fn from_cookie(&self, cookie: u64) -> &[ListingEntry] {
        let start = usize::try_from(cookie).unwrap_or(usize::MAX);
        self.entries.get(start..).unwrap_or_default()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[derive(Debug)]
pub struct FileHandle {
    backing: Backing,
    locks: Membership,
    access: LockAccess,
    /// A description shared with other handles does not include the `O_APPEND`,
    /// `O_SYNC` and `O_DSYNC` this handle was opened with.
    write_flags: ReadWriteFlags,
}

/// How it moves its bytes is set once, from one `statx` and the flags the
/// handle was opened with, so a posture changed afterwards does not affect it.
#[derive(Debug)]
pub enum Backing {
    Session(Grant),
    Own(Io),
}

impl FileHandle {
    #[must_use]
    pub fn new(backing: Backing, locks: Membership, flags: OFlags) -> Self {
        let mut write_flags = ReadWriteFlags::empty();
        if flags.contains(OFlags::APPEND) {
            write_flags |= ReadWriteFlags::APPEND;
        }
        if flags.contains(OFlags::SYNC) {
            write_flags |= ReadWriteFlags::SYNC;
        } else if flags.contains(OFlags::DSYNC) {
            write_flags |= ReadWriteFlags::DSYNC;
        }
        Self {
            backing,
            locks,
            access: LockAccess::of(flags),
            write_flags,
        }
    }

    #[must_use]
    pub fn grant(&self) -> Option<&Grant> {
        match &self.backing {
            Backing::Session(grant) => Some(grant),
            Backing::Own(_) => None,
        }
    }

    pub fn io(&self) -> Result<Io, Unserved> {
        match &self.backing {
            Backing::Session(grant) => grant.io(),
            Backing::Own(io) => Ok(io.clone()),
        }
    }

    #[must_use]
    pub fn transfer(&self) -> Transfer {
        match &self.backing {
            Backing::Session(grant) => grant.transfer(),
            Backing::Own(io) => io.transfer(),
        }
    }

    pub fn reading(&self) -> Result<Io, Unserved> {
        self.permits(LockKind::Read)?;
        self.io()
    }

    pub fn writing(&self) -> Result<Io, Unserved> {
        self.permits(LockKind::Write)?;
        self.io()
    }

    #[must_use]
    pub fn write_flags(&self) -> ReadWriteFlags {
        self.write_flags
    }

    #[must_use]
    pub fn appends(&self) -> bool {
        self.write_flags.contains(ReadWriteFlags::APPEND)
    }

    #[must_use]
    pub fn locks(&self) -> &Arc<FileLocks> {
        self.locks.locks()
    }

    #[must_use]
    pub fn access(&self) -> LockAccess {
        self.access
    }

    /// The kernel refuses a read lock through a descriptor not open for reading
    /// and a write lock through one not open for writing, with `EBADF`. The
    /// description the lock is placed on is shared with the other handles on the
    /// file, so the handle decides which kinds this request may take.
    pub fn permits(&self, kind: LockKind) -> Result<(), Errno> {
        self.access.permits(kind).then_some(()).ok_or(Errno::BADF)
    }
}

#[derive(Clone, Debug)]
pub enum Handle {
    File(Arc<FileHandle>),
    Directory(Arc<DirListing>),
}

#[derive(Debug)]
pub struct HandleTable {
    handles: HashMap<u64, Entry>,
    ids: IdSpace,
}

#[derive(Clone, Debug)]
struct Entry {
    node_id: u64,
    handle: Handle,
}

impl HandleTable {
    #[must_use]
    pub fn new(ids: IdSpace) -> Self {
        Self {
            handles: HashMap::new(),
            ids,
        }
    }

    /// The table has no size limit: an open handle costs a descriptor, and the
    /// host limits how many the process may have.
    pub fn insert(&mut self, node_id: u64, handle: Handle) -> u64 {
        let id = self.ids.take();
        self.handles.insert(id, Entry { node_id, handle });
        id
    }

    #[must_use]
    pub fn get(&self, id: u64) -> Option<Handle> {
        self.handles.get(&id).map(|entry| entry.handle.clone())
    }

    pub fn file(&self, id: u64) -> Result<Arc<FileHandle>, Errno> {
        match self.get(id) {
            Some(Handle::File(file)) => Ok(file),
            Some(Handle::Directory(_)) => Err(Errno::ISDIR),
            None => Err(Errno::BADF),
        }
    }

    pub fn listing(&self, id: u64) -> Result<Arc<DirListing>, Errno> {
        match self.get(id) {
            Some(Handle::Directory(listing)) => Ok(listing),
            Some(Handle::File(_)) => Err(Errno::NOTDIR),
            None => Err(Errno::BADF),
        }
    }

    #[must_use]
    pub fn node_of(&self, id: u64) -> Option<u64> {
        self.handles.get(&id).map(|entry| entry.node_id)
    }

    /// An operation naming both a node and a handle must name one file with
    /// them. Without this check the enforcement and the attributes would come
    /// from the node while the work would go to whatever file the handle has.
    pub fn owned_by(&self, id: u64, node_id: u64) -> Result<(), Errno> {
        match self.node_of(id) {
            Some(owner) if owner == node_id => Ok(()),
            _ => Err(Errno::BADF),
        }
    }

    pub fn remove(&mut self, id: u64) -> bool {
        self.handles.remove(&id).is_some()
    }

    pub fn clear(&mut self) {
        self.handles.clear();
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.handles.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.handles.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::{AsFd, OwnedFd};

    use crate::data::locks::LockSets;
    use crate::host::lock::LockKind;
    use crate::rules::{EffectiveMode, HostBacking, HostTarget};
    use voidport_test_host::Scratch;

    fn name(raw: &str) -> Name {
        Name::new(raw).expect("valid name")
    }

    fn admitted(target: &str) -> Resolution {
        Resolution::HostBacked {
            backing: HostBacking::graft_root(HostTarget::new(target)),
            mode: EffectiveMode::Rw,
        }
    }

    fn membership(pinned: &OwnedFd) -> Membership {
        let identity = crate::host::attr::HostAttr::of(pinned.as_fd())
            .expect("stattable")
            .node_identity();
        Arc::new(LockSets::default()).join(identity)
    }

    fn handle(scratch: &Scratch) -> FileHandle {
        let path = scratch.file("file", &[0u8; 64]);
        let pinned = Arc::new(
            rustix::fs::openat(
                rustix::fs::CWD,
                &path,
                OFlags::PATH,
                rustix::fs::Mode::empty(),
            )
            .expect("the file pins"),
        );
        let io = Io::reopen(pinned.as_fd(), OFlags::RDWR).expect("the path descriptor reopens");
        FileHandle::new(Backing::Own(io), membership(&pinned), OFlags::RDWR)
    }

    #[test]
    fn a_listing_hands_out_cookies_that_resume_and_rewind() {
        let entries = ["a", "b", "c"]
            .map(|raw| ListingEntry {
                name: name(raw),
                resolution: admitted("/srv"),
                identity: None,
            })
            .to_vec();
        let listing = DirListing::new(entries);
        assert_eq!(listing.len(), 3);
        assert!(!listing.is_empty());
        assert_eq!(listing.from_cookie(0).len(), 3);
        assert_eq!(listing.from_cookie(2).len(), 1);
        assert_eq!(listing.from_cookie(3).len(), 0);
        assert_eq!(listing.from_cookie(u64::MAX).len(), 0);
        assert_eq!(listing.from_cookie(1)[0].name, name("b"));
    }

    #[test]
    fn a_handle_permits_the_lock_kinds_its_access_covers() {
        let scratch = Scratch::new("handle");
        let opened = |flags: OFlags| {
            let path = scratch.file("file", &[0u8; 64]);
            let pinned = Arc::new(
                rustix::fs::openat(
                    rustix::fs::CWD,
                    &path,
                    OFlags::PATH,
                    rustix::fs::Mode::empty(),
                )
                .expect("the file pins"),
            );
            let io = Io::reopen(pinned.as_fd(), flags).expect("the path descriptor reopens");
            FileHandle::new(Backing::Own(io), membership(&pinned), flags)
        };
        let both = opened(OFlags::RDWR);
        assert!(both.permits(LockKind::Read).is_ok());
        assert!(both.permits(LockKind::Write).is_ok());
        let reader = opened(OFlags::RDONLY);
        assert!(reader.permits(LockKind::Read).is_ok());
        assert_eq!(reader.permits(LockKind::Write), Err(Errno::BADF));
        let writer = opened(OFlags::WRONLY);
        assert_eq!(writer.permits(LockKind::Read), Err(Errno::BADF));
        assert!(writer.permits(LockKind::Write).is_ok());
        for handle in [&both, &reader, &writer] {
            assert!(
                handle.permits(LockKind::Unlock).is_ok(),
                "releasing needs no access"
            );
        }
    }

    #[test]
    fn a_handle_records_that_it_appends_and_its_preferred_block() {
        let scratch = Scratch::new("handle");
        let path = scratch.file("log", b"x");
        let pinned = Arc::new(
            rustix::fs::openat(
                rustix::fs::CWD,
                &path,
                OFlags::PATH,
                rustix::fs::Mode::empty(),
            )
            .expect("the file pins"),
        );
        let flags = OFlags::WRONLY | OFlags::APPEND;
        let io = Io::reopen(pinned.as_fd(), flags).expect("reopens");
        let blksize = rustix::fs::fstat(io.fd()).expect("stat").st_blksize as usize;
        let handle = FileHandle::new(Backing::Own(io), membership(&pinned), flags);
        assert!(handle.appends());
        assert_eq!(
            handle.io().expect("its own").transfer().piece_len(),
            blksize
        );
    }

    #[test]
    fn handles_are_typed_and_named_once() {
        let scratch = Scratch::new("handle");
        let mut table = HandleTable::new(crate::data::ids::Generations::shared().space());
        assert!(table.is_empty());

        let file = table.insert(1, Handle::File(Arc::new(handle(&scratch))));
        let listing = table.insert(2, Handle::Directory(Arc::new(DirListing::new(Vec::new()))));
        assert_eq!(table.len(), 2);
        assert_eq!(table.node_of(file), Some(1));
        assert_eq!(table.node_of(listing), Some(2));

        assert!(table.file(file).is_ok());
        assert_eq!(table.file(listing).expect_err("a directory"), Errno::ISDIR);
        assert!(table.listing(listing).is_ok());
        assert_eq!(table.listing(file).expect_err("a file"), Errno::NOTDIR);
        assert_eq!(table.file(99).expect_err("unknown"), Errno::BADF);
        assert_eq!(table.listing(99).expect_err("unknown"), Errno::BADF);

        assert!(table.owned_by(file, 1).is_ok());
        assert_eq!(
            table.owned_by(file, 2).expect_err("another node's handle"),
            Errno::BADF
        );
        assert_eq!(table.owned_by(99, 1).expect_err("unknown"), Errno::BADF);

        assert!(table.remove(file));
        assert!(!table.remove(file));
        table.insert(3, Handle::File(Arc::new(handle(&scratch))));

        table.clear();
        assert!(table.is_empty());
        let after = table.insert(4, Handle::File(Arc::new(handle(&scratch))));
        assert!(after > listing, "handle ids are not reused");
    }
}
