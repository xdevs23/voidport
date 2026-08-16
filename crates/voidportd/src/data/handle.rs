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
//! * **Locks need one open file description per wire lock owner.** OFD locks
//!   belong to the description, and probing showed that two owners sharing one
//!   description have their locks *coalesce* instead of conflicting. So a file
//!   handle lazily reopens a description per owner — to its own access, never
//!   wider, so a read-only handle cannot take a write lock — and drops it when
//!   that owner's locks are released; closing a description releases exactly
//!   its own locks and nothing else's.
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
use std::sync::{Arc, Mutex};

use rustix::fs::OFlags;
use rustix::io::Errno;

use crate::data::ids::IdSpace;
use crate::host::HostIdentity;
use crate::host::open::reopen;
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
    /// The node's pinned `O_PATH` descriptor, kept so per-owner lock
    /// descriptions can be reopened from the same inode later.
    pinned: Arc<OwnedFd>,
    /// Whether the handle was opened for writing.
    writable: bool,
    /// One open file description per wire lock owner, created on that owner's
    /// first lock and dropped when its locks are released.
    owners: Mutex<HashMap<u64, Arc<OwnedFd>>>,
}

impl FileHandle {
    /// Wraps an opened descriptor.
    #[must_use]
    pub fn new(fd: OwnedFd, pinned: Arc<OwnedFd>, writable: bool) -> Self {
        Self {
            fd,
            pinned,
            writable,
            owners: Mutex::new(HashMap::new()),
        }
    }

    /// The descriptor reads and writes go through.
    #[must_use]
    pub fn fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }

    /// Whether the handle may be written.
    #[must_use]
    pub fn is_writable(&self) -> bool {
        self.writable
    }

    /// The description `owner` already holds locks through, if it has one.
    ///
    /// A query — `getlk` — answers through this and never through
    /// [`Self::lock_description`]: a description is a host descriptor, and a
    /// guest that may name `u64::MAX` owners must not be able to make the
    /// server open one per name. An owner with no description holds no locks,
    /// so any lock-free description of the same inode answers its `getlk`
    /// identically.
    #[must_use]
    pub fn description(&self, owner: u64) -> Option<Arc<OwnedFd>> {
        self.owners().get(&owner).map(Arc::clone)
    }

    /// The open file description that carries `owner`'s locks, reopening one on
    /// first use.
    ///
    /// **The description is never opened wider than the handle itself.** A lock
    /// lives on a description, and the kernel refuses a write lock through one
    /// that cannot be written — `EBADF`, exactly as through a local `O_RDONLY`
    /// descriptor. Reopening read-write regardless would do two things the
    /// design forbids: hand a guest holding a read-only handle an exclusive
    /// lock it could not take locally, and have the server open a read-only
    /// graft's file for writing on its own authority, which is the one thing
    /// share-mode enforcement exists to prevent.
    ///
    /// A writable handle is reopened read-write, because one description must
    /// serve that owner's read locks too; where the file itself cannot be read,
    /// a write-only description is the fallback and a read lock is what fails
    /// on it. Either way the errno is the host's, not an invention.
    ///
    /// # Errors
    ///
    /// Returns the host errno of the reopen.
    pub fn lock_description(&self, owner: u64) -> Result<Arc<OwnedFd>, Errno> {
        let mut owners = self.owners();
        if let Some(description) = owners.get(&owner) {
            return Ok(Arc::clone(description));
        }
        let description = Arc::new(self.reopen_description()?);
        owners.insert(owner, Arc::clone(&description));
        Ok(description)
    }

    /// A fresh open file description, to the handle's own access.
    fn reopen_description(&self) -> Result<OwnedFd, Errno> {
        if !self.writable {
            return reopen(self.pinned.as_fd(), OFlags::RDONLY);
        }
        match reopen(self.pinned.as_fd(), OFlags::RDWR) {
            Ok(description) => Ok(description),
            // A file the server may write but not read: the write-only
            // description still carries this owner's write locks.
            Err(error) => reopen(self.pinned.as_fd(), OFlags::WRONLY).map_err(|_| error),
        }
    }

    /// Drops `owner`'s description, releasing exactly that owner's locks.
    pub fn release_owner(&self, owner: u64) {
        self.owners().remove(&owner);
    }

    /// Drops a description whose lock was refused, so a rejected request costs
    /// no descriptor.
    ///
    /// It is dropped only if it is still the one this owner is filed under and
    /// nothing else holds it: a concurrent request sharing this description may
    /// have placed a lock through it in the meantime, and that lock must
    /// survive.
    pub fn discard_unused(&self, owner: u64, description: &Arc<OwnedFd>) {
        let mut owners = self.owners();
        let unused = owners
            .get(&owner)
            .is_some_and(|held| Arc::ptr_eq(held, description))
            && Arc::strong_count(description) == 2;
        if unused {
            owners.remove(&owner);
        }
    }

    /// How many owners hold a lock description on this handle.
    #[must_use]
    pub fn lock_owners(&self) -> usize {
        self.owners().len()
    }

    /// Takes the owner map, ignoring poisoning: a panicking caller can leave
    /// behind an extra description, which is a closed descriptor at worst.
    fn owners(&self) -> std::sync::MutexGuard<'_, HashMap<u64, Arc<OwnedFd>>> {
        self.owners
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
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
    use crate::host::lock::{LockKind, LockRange, set, test as test_lock};
    use crate::rules::{EffectiveMode, HostBacking, HostTarget};
    use crate::testing::Scratch;
    use std::fs;

    fn name(raw: &str) -> Name {
        Name::new(raw).expect("valid name")
    }

    fn admitted(target: &str) -> Resolution {
        Resolution::HostBacked {
            backing: HostBacking::graft_root(HostTarget::new(target)),
            mode: EffectiveMode::Rw,
        }
    }

    /// A file handle over a real file, as `open` builds one.
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
        let fd = reopen(pinned.as_fd(), OFlags::RDWR).expect("the pin reopens");
        FileHandle::new(fd, pinned, true)
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
    fn each_lock_owner_gets_its_own_description() {
        let scratch = Scratch::new("handle");
        let handle = handle(&scratch);

        let first = handle.lock_description(1).expect("reopens");
        let again = handle.lock_description(1).expect("cached");
        let second = handle.lock_description(2).expect("reopens");
        assert!(Arc::ptr_eq(&first, &again), "one description per owner");
        assert_eq!(handle.lock_owners(), 2);

        // Two owners of one handle genuinely conflict.
        set(first.as_fd(), LockKind::Write, LockRange::new(0, 9)).expect("free");
        assert_eq!(
            set(second.as_fd(), LockKind::Write, LockRange::new(0, 9))
                .expect_err("the first owner holds it"),
            Errno::AGAIN
        );

        // Releasing one owner releases only its locks.
        handle.release_owner(1);
        drop(first);
        drop(again);
        assert_eq!(handle.lock_owners(), 1);
        assert_eq!(
            test_lock(second.as_fd(), LockKind::Write, LockRange::new(0, 9)).expect("testable"),
            None
        );
    }

    #[test]
    fn a_description_is_kept_only_for_an_owner_that_may_hold_a_lock() {
        let scratch = Scratch::new("handle");
        let handle = handle(&scratch);
        assert!(
            handle.description(1).is_none(),
            "an owner that never locked has none, and asking must not make one"
        );

        // A description whose lock the host refused is dropped again.
        let first = handle.lock_description(1).expect("reopens");
        assert!(
            handle
                .description(1)
                .is_some_and(|held| Arc::ptr_eq(&held, &first))
        );
        handle.discard_unused(1, &first);
        assert_eq!(handle.lock_owners(), 0);

        // One a concurrent request is still holding is kept: that request may
        // have placed a lock through it.
        let second = handle.lock_description(2).expect("reopens");
        let shared = handle.description(2).expect("filed");
        handle.discard_unused(2, &second);
        assert_eq!(handle.lock_owners(), 1);
        drop(shared);
        handle.discard_unused(2, &second);
        assert_eq!(handle.lock_owners(), 0);
    }

    #[test]
    fn a_read_only_file_still_gets_a_description() {
        let scratch = Scratch::new("handle");
        let path = scratch.file("readonly", b"x");
        let mut permissions = fs::metadata(&path).expect("stattable").permissions();
        #[allow(
            clippy::permissions_set_readonly_false,
            reason = "the file is made read-only"
        )]
        permissions.set_readonly(true);
        fs::set_permissions(&path, permissions).expect("settable");
        let pinned = Arc::new(
            rustix::fs::openat(
                rustix::fs::CWD,
                &path,
                OFlags::PATH,
                rustix::fs::Mode::empty(),
            )
            .expect("the file pins"),
        );
        let fd = reopen(pinned.as_fd(), OFlags::RDONLY).expect("the pin reopens");
        let handle = FileHandle::new(fd, pinned, false);
        assert!(!handle.is_writable());
        // Read-write is not available, so the fallback description is.
        assert!(handle.lock_description(7).is_ok());
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
