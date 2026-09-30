//! The per-session handle table.
//!
//! An open file or directory is named by a `u64` handle that lives here for as
//! long as the session does; a dropped connection tears the table down, so a
//! handle never outlives its session and the host descriptors it holds are
//! closed with it. Handle ids come from the same generation-disjoint
//! [`IdSpace`] node ids do, so a handle a guest still holds after its server
//! restarted names nothing in the new session and is answered `EBADF` — never
//! another file.
//!
//! Two things in here are subtler than a map of descriptors:
//!
//! * **Locks belong to the file, not to the handle.** A POSIX record lock is
//!   its owner's for the whole file, whichever descriptor placed it, so a file
//!   handle holds no locks of its own: it joins the session's lock set for its
//!   file (see [`crate::data::locks`]), which every handle on that file shares.
//!   What the handle decides is whether a request through it may place a lock
//!   of its kind, from the access it was opened with.
//! * **Directory listings are materialized at opendir.** The listing a guest
//!   walks is not the host's: it is the host children merged with the
//!   directory's literal-rule children, each decided by the rule engine, with
//!   hidden entries removed. Materializing it once buys stable cookies over
//!   that merged view — a readdirplus cookie indexes into this vector, and
//!   cookie 0 rewinds. The memory is the accepted cost: it is the size of the
//!   directory, and a configured listing cap bounds it where an operator wants
//!   a ceiling on directories they did not choose.

use std::collections::HashMap;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::sync::Arc;

use rustix::fs::OFlags;
use rustix::io::Errno;

use crate::data::ids::IdSpace;
use crate::data::locks::{FileLocks, LockAccess, Membership};
use crate::host::lock::LockKind;
use crate::host::{BackingIo, HostIdentity};
use crate::rules::{Name, Resolution};

/// One entry of a materialized directory listing.
#[derive(Clone, Debug)]
pub struct ListingEntry {
    /// The entry's name.
    pub name: Name,
    /// How the rule engine resolved it. Only admitted entries are kept, so a
    /// hidden entry is simply absent.
    pub resolution: Resolution,
    /// The host identity the stat that decided the entry's visibility
    /// reported, or `None` for a synthesized directory, which has no host
    /// entry.
    ///
    /// This is what makes `readdirplus` cost **no `openat2` per entry**: a node
    /// is keyed by this identity, so an entry the session has already seen can
    /// be named — and its lookup counted — without opening it again. The
    /// materialization stat had to be taken anyway, for the ownership filter.
    ///
    /// Deliberately *not* the attributes: an entry reply is what a guest caches
    /// a file's size by, and attributes as of `opendir` are measurably too old
    /// to hand out — a listing taken while another writer is working made a
    /// following read of that file return its stale length. The reply's
    /// attributes are read when the reply is built.
    pub identity: Option<HostIdentity>,
}

/// A directory listing, materialized at opendir.
#[derive(Debug)]
pub struct DirListing {
    entries: Vec<ListingEntry>,
}

impl DirListing {
    /// Materializes a listing, refusing one larger than a configured cap.
    ///
    /// # Errors
    ///
    /// Returns `EOVERFLOW` for a directory with more admitted entries than
    /// `limit` — the design's listing cap, checked where the memory would
    /// actually be spent. A `None` limit is no cap: the listing is as large as
    /// the directory is.
    pub fn new(entries: Vec<ListingEntry>, limit: Option<usize>) -> Result<Self, Errno> {
        if limit.is_some_and(|limit| entries.len() > limit) {
            return Err(Errno::OVERFLOW);
        }
        Ok(Self { entries })
    }

    /// The entries from `cookie` on.
    ///
    /// Cookie 0 is the start of the listing, and entry `i` hands out cookie
    /// `i + 1`; a cookie past the end yields nothing, which is how enumeration
    /// ends.
    #[must_use]
    pub fn from_cookie(&self, cookie: u64) -> &[ListingEntry] {
        let start = usize::try_from(cookie).unwrap_or(usize::MAX);
        self.entries.get(start..).unwrap_or_default()
    }

    /// How many entries the listing holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the directory listed empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// An open host file.
#[derive(Debug)]
pub struct FileHandle {
    /// The descriptor reads and writes go through.
    fd: OwnedFd,
    /// The handle's place in the session's lock set for the file, shared with
    /// every other handle on it.
    locks: Membership,
    /// Which kinds of lock may be placed through the handle: the access it was
    /// opened with.
    access: LockAccess,
    /// Whether the handle was opened for writing.
    writable: bool,
    /// Whether this description reaches its file through the host page cache or
    /// past it, and — where it is uncached — the alignment its transfers must
    /// meet. Decided once, from the flags the description was opened with, so a
    /// posture changed afterwards leaves this handle exactly as it was.
    backing: BackingIo,
}

impl FileHandle {
    /// Wraps an opened descriptor, joining `locks`, the session's lock set for
    /// its file.
    ///
    /// `flags` are the flags the description was opened with, which is what
    /// decides how its reads and writes reach the file and which locks may be
    /// placed through it.
    #[must_use]
    pub fn new(fd: OwnedFd, locks: Membership, writable: bool, flags: OFlags) -> Self {
        let backing = BackingIo::of(fd.as_fd(), flags);
        Self {
            fd,
            locks,
            access: LockAccess::of(flags),
            writable,
            backing,
        }
    }

    /// The descriptor reads and writes go through.
    #[must_use]
    pub fn fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }

    /// How this handle's reads and writes reach the backing file.
    #[must_use]
    pub fn backing_io(&self) -> BackingIo {
        self.backing
    }

    /// Whether the handle may be written.
    #[must_use]
    pub fn is_writable(&self) -> bool {
        self.writable
    }

    /// The session's lock set for this handle's file.
    #[must_use]
    pub fn locks(&self) -> &Arc<FileLocks> {
        self.locks.locks()
    }

    /// The access the handle was opened with, as far as locks are concerned.
    #[must_use]
    pub fn access(&self) -> LockAccess {
        self.access
    }

    /// Checks that a lock of `kind` may be placed through this handle.
    ///
    /// The kernel refuses a read lock through a descriptor not open for reading
    /// and a write lock through one not open for writing, with `EBADF`, and the
    /// same holds through a handle: the description the lock is placed on is
    /// the owner's, shared with the owner's other handles on the file, so the
    /// handle is what says which kinds this request may take.
    ///
    /// # Errors
    ///
    /// Returns `EBADF` where the handle's access does not cover `kind`.
    pub fn permits(&self, kind: LockKind) -> Result<(), Errno> {
        self.access.permits(kind).then_some(()).ok_or(Errno::BADF)
    }
}

/// What a handle names.
#[derive(Clone, Debug)]
pub enum Handle {
    /// An open file.
    File(Arc<FileHandle>),
    /// An open directory, with its listing already materialized.
    Directory(Arc<DirListing>),
}

/// One session's handles.
#[derive(Debug)]
pub struct HandleTable {
    handles: HashMap<u64, Entry>,
    /// The generation-disjoint id space this session names handles from.
    ids: IdSpace,
    /// The configured cap, or `None` where the operator configured none and the
    /// table grows until the process runs out of descriptors.
    limit: Option<usize>,
}

/// A handle and the node it was opened through.
#[derive(Clone, Debug)]
struct Entry {
    node_id: u64,
    handle: Handle,
}

impl HandleTable {
    /// An empty table naming handles from `ids` and bounded by `limit`
    /// handles, or by nothing when it is `None`.
    #[must_use]
    pub fn new(limit: Option<usize>, ids: IdSpace) -> Self {
        Self {
            handles: HashMap::new(),
            ids,
            limit,
        }
    }

    /// Files a handle and returns its id.
    ///
    /// # Errors
    ///
    /// Returns `EMFILE` when a configured table is full; the handle is dropped,
    /// which closes whatever descriptor it held. An unconfigured table never
    /// returns it.
    pub fn insert(&mut self, node_id: u64, handle: Handle) -> Result<u64, Errno> {
        if self.limit.is_some_and(|limit| self.handles.len() >= limit) {
            return Err(Errno::MFILE);
        }
        let id = self.ids.take();
        self.handles.insert(id, Entry { node_id, handle });
        Ok(id)
    }

    /// The handle an id names.
    #[must_use]
    pub fn get(&self, id: u64) -> Option<Handle> {
        self.handles.get(&id).map(|entry| entry.handle.clone())
    }

    /// The open file an id names.
    ///
    /// # Errors
    ///
    /// Returns `EBADF` for an unknown handle and `EISDIR` for a directory
    /// handle, which reads and writes may not go through.
    pub fn file(&self, id: u64) -> Result<Arc<FileHandle>, Errno> {
        match self.get(id) {
            Some(Handle::File(file)) => Ok(file),
            Some(Handle::Directory(_)) => Err(Errno::ISDIR),
            None => Err(Errno::BADF),
        }
    }

    /// The listing an id names.
    ///
    /// # Errors
    ///
    /// Returns `EBADF` for an unknown handle and `ENOTDIR` for a file handle.
    pub fn listing(&self, id: u64) -> Result<Arc<DirListing>, Errno> {
        match self.get(id) {
            Some(Handle::Directory(listing)) => Ok(listing),
            Some(Handle::File(_)) => Err(Errno::NOTDIR),
            None => Err(Errno::BADF),
        }
    }

    /// The node a handle was opened through.
    #[must_use]
    pub fn node_of(&self, id: u64) -> Option<u64> {
        self.handles.get(&id).map(|entry| entry.node_id)
    }

    /// Checks that a handle was opened through `node_id`.
    ///
    /// An operation naming both a node and a handle — readdirplus, a
    /// handle-flagged getattr or setattr — must name *one* file with them.
    /// Without this check the enforcement and the attributes would come from
    /// the node while the work landed on whatever file the handle happens to
    /// hold.
    ///
    /// # Errors
    ///
    /// Returns `EBADF` for an unknown handle and for one belonging to another
    /// node.
    pub fn owned_by(&self, id: u64, node_id: u64) -> Result<(), Errno> {
        match self.node_of(id) {
            Some(owner) if owner == node_id => Ok(()),
            _ => Err(Errno::BADF),
        }
    }

    /// Closes a handle.
    ///
    /// Returns whether it was there; a release of an unknown handle is not an
    /// error the client can act on, but the caller may want to know.
    pub fn remove(&mut self, id: u64) -> bool {
        self.handles.remove(&id).is_some()
    }

    /// Closes every handle the session holds.
    ///
    /// Session teardown, where the descriptors go whether or not the client
    /// released them. Ids are not reused afterwards: the counter only moves
    /// forward.
    pub fn clear(&mut self) {
        self.handles.clear();
    }

    /// How many handles the session holds open.
    #[must_use]
    pub fn len(&self) -> usize {
        self.handles.len()
    }

    /// Whether the session holds no handles.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.handles.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::locks::LockSets;
    use crate::host::open::reopen;
    use crate::rules::{EffectiveMode, HostBacking, HostTarget};
    use crate::testing::Scratch;

    fn name(raw: &str) -> Name {
        Name::new(raw).expect("valid name")
    }

    fn admitted(target: &str) -> Resolution {
        Resolution::HostBacked {
            backing: HostBacking::graft_root(HostTarget::new(target)),
            mode: EffectiveMode::Rw,
        }
    }

    /// A file handle over a real file opened with `flags`, as `open` builds one.
    fn opened(scratch: &Scratch, flags: OFlags) -> FileHandle {
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
        let fd = reopen(pinned.as_fd(), flags).expect("the pin reopens");
        let writable = flags.contains(OFlags::WRONLY) || flags.contains(OFlags::RDWR);
        let identity = crate::host::attr::HostAttr::of(pinned.as_fd())
            .expect("stattable")
            .node_identity();
        let membership = Arc::new(LockSets::default()).join(identity, &pinned);
        FileHandle::new(fd, membership, writable, flags)
    }

    /// A read-write file handle over a real file.
    fn handle(scratch: &Scratch) -> FileHandle {
        opened(scratch, OFlags::RDWR)
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
        let listing = DirListing::new(entries, Some(8)).expect("within the cap");
        assert_eq!(listing.len(), 3);
        assert!(!listing.is_empty());
        assert_eq!(listing.from_cookie(0).len(), 3);
        assert_eq!(listing.from_cookie(2).len(), 1);
        assert_eq!(listing.from_cookie(3).len(), 0);
        assert_eq!(listing.from_cookie(u64::MAX).len(), 0);
        assert_eq!(listing.from_cookie(1)[0].name, name("b"));
    }

    #[test]
    fn a_listing_larger_than_the_cap_is_refused() {
        let entries = || {
            (0..4)
                .map(|index| ListingEntry {
                    name: name(&format!("entry-{index}")),
                    resolution: admitted("/srv"),
                    identity: None,
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(
            DirListing::new(entries(), Some(3)).expect_err("too big"),
            Errno::OVERFLOW
        );
        assert!(
            DirListing::new(Vec::new(), Some(0))
                .expect("empty fits")
                .is_empty()
        );
        // The default posture: no cap, so no size is too big.
        assert_eq!(
            DirListing::new(entries(), None)
                .expect("an unbounded listing takes the directory whole")
                .len(),
            4
        );
    }

    #[test]
    fn a_handle_permits_the_lock_kinds_its_access_covers() {
        let scratch = Scratch::new("handle");
        let both = opened(&scratch, OFlags::RDWR);
        assert!(both.permits(LockKind::Read).is_ok());
        assert!(both.permits(LockKind::Write).is_ok());

        let reader = opened(&scratch, OFlags::RDONLY);
        assert!(reader.permits(LockKind::Read).is_ok());
        assert_eq!(reader.permits(LockKind::Write), Err(Errno::BADF));

        let writer = opened(&scratch, OFlags::WRONLY);
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
    fn handles_are_typed_and_bounded() {
        let scratch = Scratch::new("handle");
        let mut table = HandleTable::new(Some(2), crate::data::ids::Generations::shared().space());
        assert!(table.is_empty());

        let file = table
            .insert(1, Handle::File(Arc::new(handle(&scratch))))
            .expect("room");
        let listing = table
            .insert(
                2,
                Handle::Directory(Arc::new(
                    DirListing::new(Vec::new(), Some(8)).expect("fits"),
                )),
            )
            .expect("room");
        assert_eq!(table.len(), 2);
        assert_eq!(table.node_of(file), Some(1));
        assert_eq!(table.node_of(listing), Some(2));

        assert!(table.file(file).is_ok());
        assert_eq!(table.file(listing).expect_err("a directory"), Errno::ISDIR);
        assert!(table.listing(listing).is_ok());
        assert_eq!(table.listing(file).expect_err("a file"), Errno::NOTDIR);
        assert_eq!(table.file(99).expect_err("unknown"), Errno::BADF);
        assert_eq!(table.listing(99).expect_err("unknown"), Errno::BADF);

        assert_eq!(
            table
                .insert(3, Handle::File(Arc::new(handle(&scratch))))
                .expect_err("the table is full"),
            Errno::MFILE
        );

        // A handle names the node it was opened through, and only that one.
        assert!(table.owned_by(file, 1).is_ok());
        assert_eq!(
            table.owned_by(file, 2).expect_err("another node's handle"),
            Errno::BADF
        );
        assert_eq!(table.owned_by(99, 1).expect_err("unknown"), Errno::BADF);

        assert!(table.remove(file));
        assert!(!table.remove(file));
        assert!(
            table
                .insert(3, Handle::File(Arc::new(handle(&scratch))))
                .is_ok()
        );

        // Teardown closes what is left, and hands out no id twice.
        table.clear();
        assert!(table.is_empty());
        let after = table
            .insert(4, Handle::File(Arc::new(handle(&scratch))))
            .expect("room");
        assert!(after > listing, "handle ids are not reused");
    }

    /// The default posture: a table nobody configured a cap for refuses no
    /// open, however many a guest holds at once.
    #[test]
    fn an_unconfigured_table_never_refuses_an_open() {
        let scratch = Scratch::new("handle");
        let mut table = HandleTable::new(None, crate::data::ids::Generations::shared().space());
        for node in 0..64 {
            table
                .insert(node, Handle::File(Arc::new(handle(&scratch))))
                .expect("an unbounded table admits every open");
        }
        assert_eq!(table.len(), 64);
    }
}
