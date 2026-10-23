// SPDX-License-Identifier: GPL-2.0

use kernel::bindings;
use kernel::error::to_result;
use kernel::prelude::*;
use kernel::rbtree::{RBTree, RBTreeNode};
use kernel::sync::atomic::{Atomic, Relaxed};
use kernel::sync::{new_mutex, Mutex};
use voidport_proto::attr::Attr;
use voidport_session::cache::{self, Attributes, Contents, Presented};
use voidport_session::metadata;
use voidport_session::time::{lifetime_ended, Tick, TickSpan};

use crate::cleanup::Cleanup;
use crate::compat::Flag;
use crate::handle::Writers;
use crate::helpers::{
    max_lfs_filesize, voidport_i_size_read, voidport_i_size_write, voidport_inode_is_new,
    voidport_inode_set_times, voidport_inode_uncache_acls, voidport_jiffies,
    voidport_mapping_writeback, voidport_new_decode_dev, Hold, Locked,
};
use crate::inode_kind::SupportedKind;
use crate::mount::Mount;
use crate::session::Session;
use crate::wire::Caller;
use crate::{aops, file_ops, inode_ops};

pub(crate) const ROOT_NODE_ID: u64 = voidport_session::handshake::ROOT_NODE_ID;

#[pin_data]
pub(crate) struct Node {
    node_id: u64,
    generation: u64,
    /// Operation tables are selected once, before the inode is published.
    kind: SupportedKind,
    /// Lookups admitted and not yet forgotten. Decremented in one wire
    /// `forget` at eviction.
    lookup: Atomic<u64>,
    /// The jiffies instant of the last reply that returned the presented
    /// attributes, which their lifetime counts from.
    attr_resolved_at: Atomic<u64>,
    /// Whether a reply changed the attributes on the server without carrying
    /// them, which ends their lifetime before it runs out.
    attr_expired: Flag,
    /// The write count of the mount after the latest write to the file was
    /// applied. It only grows.
    written_at: Atomic<u64>,
    /// The Flush each lock owner owes the file once it placed a record lock
    /// on it, by the wire lock owner. The close of a descriptor by that owner
    /// releases its locks with the Flush, and the cleanup worker sends the
    /// Flush of an owner that died while it closed.
    #[pin]
    flushes: Mutex<RBTree<u64, KBox<Cleanup>>>,
    #[pin]
    writers: Writers,
}

impl Node {
    fn new(node_id: u64, generation: u64, kind: SupportedKind) -> impl PinInit<Self> {
        pin_init!(Self {
            node_id,
            generation,
            kind,
            lookup: Atomic::new(0),
            attr_resolved_at: Atomic::new(0),
            attr_expired: Flag::new(false),
            written_at: Atomic::new(0),
            flushes <- new_mutex!(RBTree::new(), "voidport::flushes"),
            writers <- Writers::new(),
        })
    }

    fn admit(&self) {
        self.lookup.fetch_add(1, Relaxed);
    }

    fn attr_stale(&self, lifetime: c_ulong) -> bool {
        // SAFETY: a read of the kernel's tick counter.
        let now = unsafe { voidport_jiffies() };
        let resolved = self.attr_resolved_at.load(Relaxed) as c_ulong;
        self.attr_expired.load()
            || lifetime_ended(Tick::new(resolved), TickSpan::new(lifetime), Tick::new(now))
    }

    fn attr_refreshed(&self) {
        // SAFETY: a read of the kernel's tick counter.
        let now = unsafe { voidport_jiffies() };
        self.attr_resolved_at.store(now as u64, Relaxed);
        self.attr_expired.store(false);
    }

    fn expire_attr(&self) {
        self.attr_expired.store(true);
    }
}

/// # Safety
///
/// `sb` must be a live voidport superblock whose `s_fs_info` was set by
/// `fill_super` and not yet cleared.
pub(crate) unsafe fn mount_of(sb: *mut bindings::super_block) -> &'static Mount {
    // SAFETY: the caller promises `sb` is a live voidport superblock; its
    // `s_fs_info` is the mount `fill_super` stored, valid for the
    // superblock's life.
    unsafe { &*((*sb).s_fs_info as *const Mount) }
}

/// # Safety
///
/// `inode` must be a live inode of a live voidport superblock.
pub(crate) unsafe fn inode_mount(inode: *mut bindings::inode) -> &'static Mount {
    // SAFETY: the promise of the caller holds.
    unsafe { mount_of((*inode).i_sb) }
}

/// # Safety
///
/// As for [`mount_of`].
pub(crate) unsafe fn session_of(sb: *mut bindings::super_block) -> &'static Session {
    // SAFETY: the promise of the caller holds.
    unsafe { &mount_of(sb).session }
}

/// # Safety
///
/// `inode` must be a live voidport inode whose `i_private` has been set.
unsafe fn node_of(inode: *mut bindings::inode) -> &'static Node {
    // SAFETY: the caller promises `inode` is an initialised voidport inode,
    // whose `i_private` is the `Node` box `admit` stored.
    unsafe { &*((*inode).i_private as *const Node) }
}

/// The full wire identity, never recovered from the displayed inode number.
///
/// # Safety
///
/// `inode` must be a live, initialized voidport inode.
pub(crate) unsafe fn id_of(inode: *mut bindings::inode) -> u64 {
    // SAFETY: the caller promises initialized private state.
    unsafe { node_of(inode).node_id }
}

/// # Safety
///
/// `inode` must be a live, initialized voidport inode.
pub(crate) unsafe fn session_and_id(inode: *mut bindings::inode) -> (&'static Session, u64) {
    // SAFETY: the caller promises a live, initialized inode, whose superblock
    // is live with it.
    unsafe { (session_of((*inode).i_sb), id_of(inode)) }
}

/// # Safety
///
/// `inode` must be a live, initialized voidport inode.
pub(crate) unsafe fn writers(inode: *mut bindings::inode) -> &'static Writers {
    // SAFETY: the caller promises initialized private state.
    unsafe { &node_of(inode).writers }
}

/// # Safety
///
/// `inode` must be a live, initialized voidport inode.
pub(crate) unsafe fn kind_of(inode: *mut bindings::inode) -> SupportedKind {
    // SAFETY: the caller promises initialized private state.
    unsafe { node_of(inode).kind }
}

/// # Safety
/// `inode` must carry initialized voidport private state.
pub(crate) unsafe fn matches_entry(inode: *mut bindings::inode, id: u64, generation: u64) -> bool {
    // SAFETY: the caller promises initialized private state.
    let node = unsafe { node_of(inode) };
    node.node_id == id && node.generation == generation
}

/// Storage is allocated before `iget5_locked`, whose callbacks cannot sleep.
struct Key {
    node_id: u64,
    generation: u64,
    storage: Option<Pin<KBox<Node>>>,
}

unsafe extern "C" fn test(inode: *mut bindings::inode, data: *mut c_void) -> c_int {
    // SAFETY: the key outlives iget; `set` publishes private state before the
    // inode is hashed. `destroy` frees that state only after hash removal.
    unsafe {
        let key = &*data.cast::<Key>();
        c_int::from(matches_entry(inode, key.node_id, key.generation))
    }
}

/// Publishes identity before hashing, without allocating under the inode lock.
unsafe extern "C" fn set(inode: *mut bindings::inode, data: *mut c_void) -> c_int {
    // SAFETY: iget supplies its exclusive fresh inode and our live key.
    unsafe {
        let key = &mut *data.cast::<Key>();
        let Some(storage) = key.storage.take() else {
            return EIO.to_errno();
        };
        // The node remains in place until `destroy` drops it.
        (*inode).i_private = KBox::into_raw(Pin::into_inner_unchecked(storage)).cast::<c_void>();
    }
    0
}

/// The lookup the reply counted on the server is recorded here, to be
/// forgotten at eviction.
///
/// # Safety
///
/// `sb` must be a live voidport superblock.
pub(crate) unsafe fn iget(
    sb: *mut bindings::super_block,
    node_id: u64,
    generation: u64,
    attr: &Attr,
    sent_at: u64,
) -> Result<*mut bindings::inode> {
    let kind = SupportedKind::of_mode(attr.mode.get())
        .ok_or(Error::from_errno(-(bindings::EOPNOTSUPP as c_int)))?;
    let _scope = crate::helpers::NoFsScope::enter();
    let mut key = Key {
        node_id,
        generation,
        storage: Some(KBox::pin_init(
            Node::new(node_id, generation, kind),
            GFP_KERNEL,
        )?),
    };
    // Only the index follows the kernel API's width; matching uses all bits.
    #[allow(clippy::as_underscore)]
    let hash = (node_id ^ generation.rotate_left(32)) as _;
    // SAFETY: `sb` is a live superblock; the callbacks publish and compare the
    // complete identity, and the key outlives the call.
    let inode = unsafe {
        bindings::iget5_locked(
            sb,
            hash,
            Some(test),
            Some(set),
            core::ptr::from_mut(&mut key).cast::<c_void>(),
        )
    };
    if inode.is_null() {
        return Err(ENOMEM);
    }
    // SAFETY: `iget5_locked` returned a valid, referenced inode.
    if unsafe { voidport_inode_is_new(inode) } {
        match init_new(inode, attr, sent_at, kind) {
            Ok(()) => {
                // SAFETY: the inode is the fresh one this call is
                // initialising, now fully set up.
                unsafe { bindings::unlock_new_inode(inode) };
            }
            Err(error) => {
                // SAFETY: undoes the get and marks the inode bad, the standard
                // failure for a fresh inode that could not be initialised.
                // Its lookup count is still zero: the reply's admission is
                // the caller's to give back, not the failed inode's.
                unsafe { bindings::iget_failed(inode) };
                return Err(error);
            }
        }
    } else {
        // SAFETY: iget waited for initialization, which may have failed.
        // Reject a bad inode before touching attributes or private state.
        if unsafe { bindings::is_bad_inode(inode) || (*inode).i_private.is_null() } {
            // SAFETY: return the reference iget supplied; no admission moved.
            unsafe { bindings::iput(inode) };
            return Err(EIO);
        }
        // SAFETY: an initialized existing inode; count this reply's lookup.
        unsafe {
            if let Err(error) = apply_attr(inode, attr, sent_at) {
                bindings::iput(inode);
                return Err(error);
            }
            node_of(inode).admit();
        }
    }
    Ok(inode)
}

/// The server stores the access and change times and the ACLs, so the inode
/// never updates those times itself, and the VFS asks for the ACLs each time.
fn init_new(inode: *mut bindings::inode, attr: &Attr, sent_at: u64, kind: SupportedKind) -> Result {
    // SAFETY: `set` installed private state; the inode remains exclusively
    // ours until unlock. The admission transfers only after setup succeeds.
    unsafe {
        apply_attr(inode, attr, sent_at)?;
        (*inode).i_flags |= bindings::S_NOATIME | bindings::S_NOCMTIME;
        voidport_inode_uncache_acls(inode);
        wire_type(inode, kind);
        node_of(inode).admit();
    }
    Ok(())
}

/// # Safety
///
/// `inode` must be a fresh inode this task exclusively holds, with its mode
/// and device number set.
unsafe fn wire_type(inode: *mut bindings::inode, kind: SupportedKind) {
    // SAFETY: the caller holds the fresh inode exclusively; the operation
    // tables are `'static`. Symlinks have get_link and no open-file operations.
    // A FIFO, a socket or a device opens in the guest, as a local pipe,
    // socket or device, so its file operations are the kernel's own.
    unsafe {
        match kind {
            SupportedKind::Directory => {
                (*inode).i_op = inode_ops::DIR_INODE_OPS.get();
                (*inode).__bindgen_anon_3.i_fop = file_ops::DIR_FILE_OPS.get();
            }
            SupportedKind::Symlink => {
                (*inode).i_op = inode_ops::SYMLINK_INODE_OPS.get();
            }
            SupportedKind::Regular => {
                (*inode).i_op = inode_ops::FILE_INODE_OPS.get();
                (*inode).__bindgen_anon_3.i_fop = file_ops::FILE_FILE_OPS.get();
                (*(*inode).i_mapping).a_ops = aops::DATA_AOPS.get();
            }
            SupportedKind::Fifo
            | SupportedKind::Socket
            | SupportedKind::CharDevice
            | SupportedKind::BlockDevice => {
                (*inode).i_op = inode_ops::SPECIAL_INODE_OPS.get();
                bindings::init_special_inode(inode, (*inode).i_mode, (*inode).i_rdev);
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Mode {
    bits: bindings::umode_t,
}

impl Mode {
    fn new(mode: u32) -> core::result::Result<Self, crate::session::ExtractError> {
        let bits = bindings::umode_t::try_from(mode)
            .map_err(|_| crate::session::ExtractError::Local(EOVERFLOW))?;
        SupportedKind::of_mode(mode).ok_or(crate::session::ExtractError::Local(
            Error::from_errno(-(bindings::EOPNOTSUPP as c_int)),
        ))?;
        Ok(Self { bits })
    }

    fn presented(self, mask_privileged: bool) -> bindings::umode_t {
        // The privileged bits are permission bits, which every umode_t has.
        const PRIVILEGED: bindings::umode_t = metadata::PRIVILEGED as bindings::umode_t;
        if mask_privileged {
            self.bits & !PRIVILEGED
        } else {
            self.bits
        }
    }
}

/// Validate timestamps, mode and identities before inode publication.
/// Unrepresentable attributes are local errors, not malformed timestamps.
pub(crate) fn validate_attr(
    attr: &Attr,
) -> core::result::Result<(Mode, bindings::kuid_t, bindings::kgid_t), crate::session::ExtractError>
{
    let (uid, gid) = validate_times_and_ids(attr)?;
    let mode = Mode::new(attr.mode.get())?;
    Ok((mode, uid, gid))
}

/// Validates the attributes of a listed entry, whose mode may describe no
/// kind: such an entry is still listed, and only a lookup of it fails as
/// unsupported.
pub(crate) fn validate_listed_attr(
    attr: &Attr,
) -> core::result::Result<Option<SupportedKind>, crate::session::ExtractError> {
    validate_times_and_ids(attr)?;
    let mode = attr.mode.get();
    bindings::umode_t::try_from(mode)
        .map_err(|_| crate::session::ExtractError::Local(EOVERFLOW))?;
    Ok(SupportedKind::of_mode(mode))
}

fn validate_times_and_ids(
    attr: &Attr,
) -> core::result::Result<(bindings::kuid_t, bindings::kgid_t), crate::session::ExtractError> {
    attr.atime.validate()?;
    attr.mtime.validate()?;
    attr.ctime.validate()?;
    // SAFETY: the initial namespace has kernel lifetime; conversion only reads
    // its identity mappings and does not change inode or namespace state.
    let (uid, gid) = unsafe {
        (
            bindings::make_kuid(&raw mut bindings::init_user_ns, attr.uid.get()),
            bindings::make_kgid(&raw mut bindings::init_user_ns, attr.gid.get()),
        )
    };
    // uid_valid/gid_valid in linux/uidgid.h compare their unsigned values with
    // the all-ones INVALID_UID/INVALID_GID sentinel.
    if uid.val == u32::MAX || gid.val == u32::MAX {
        return Err(crate::session::ExtractError::Local(EOVERFLOW));
    }
    Ok((uid, gid))
}

/// Applies wire attributes from a request sent at the write count `sent_at`
/// to an inode, as the session core's `cache::after_attributes` returns:
/// ignored when they may show the file before a write of this mount, applied
/// with the attribute lifetime started over, and with the cached data dropped
/// when they show a file changed on the server.
///
/// # Safety
///
/// `inode` must be a live voidport inode whose `i_private` has been set.
pub(crate) unsafe fn apply_attr(inode: *mut bindings::inode, attr: &Attr, sent_at: u64) -> Result {
    // SAFETY: private state is initialized before either initial publication or
    // refresh. A live inode's operation tables cannot follow a changed kind.
    if SupportedKind::of_mode(attr.mode.get()) != Some(unsafe { node_of(inode).kind }) {
        return Err(crate::errno::estale());
    }
    let (mode, uid, gid) = validate_attr(attr).map_err(|error| match error {
        crate::session::ExtractError::Protocol(_) => EIO,
        crate::session::ExtractError::Local(error) => error,
    })?;
    let new_size = bindings::loff_t::try_from(attr.size.get()).map_err(|_| EOVERFLOW)?;
    if new_size > max_lfs_filesize() {
        return Err(EOVERFLOW);
    }
    // Every fallible presentation conversion happens before the attributes or
    // the page cache change. `i_ino` follows the width of the kernel API, so
    // the fallible form refuses a number that cannot be presented where that
    // width is narrower than the wire's, and the lint only sees the identity
    // case.
    #[allow(clippy::useless_conversion)]
    let displayed = attr.ino.get().try_into().map_err(|_| EOVERFLOW)?;
    // SAFETY: the caller holds a live voidport inode whose `i_private` is set.
    unsafe {
        let mapping = (*inode).i_mapping;
        let _invalidate = Locked::invalidate(inode, Hold::Exclusive)?;
        let node = node_of(inode);
        let presented = Presented {
            contents: Contents {
                size: u64::try_from(voidport_i_size_read(inode)).map_err(|_| EOVERFLOW)?,
                mtime_sec: (*inode).i_mtime_sec,
                mtime_nsec: (*inode).i_mtime_nsec,
            },
            written_at: node.written_at.load(Relaxed),
            // A write holds this lock until it has applied its reply. A
            // writeback does not, and its folios remain under writeback until
            // then.
            writing: voidport_mapping_writeback(mapping),
        };
        let reply = Contents {
            size: attr.size.get(),
            mtime_sec: attr.mtime.sec.get(),
            mtime_nsec: attr.mtime.nsec.get(),
        };
        match cache::after_attributes(presented, reply, sent_at) {
            Attributes::Ignore => return Ok(()),
            Attributes::Apply => {}
            Attributes::ApplyAndDrop => {
                // Generic reads, readahead and filemap faults hold the
                // shared invalidate lock while filling pages. The exclusive
                // side waits for those fills and excludes new ones.
                // Invalidation unmaps cached folios before removing them.
                // Busy pages return a local error, leaving attributes and
                // validity intact.
                kernel::error::to_result(bindings::invalidate_inode_pages2(mapping))?;
            }
        }
        (*inode).i_ino = displayed;
        (*inode).i_mode = mode.presented(inode_mount(inode).mask_privileged());
        (*inode).i_uid = uid;
        (*inode).i_gid = gid;
        (*inode).i_rdev = voidport_new_decode_dev(attr.rdev.get());
        bindings::set_nlink(inode, attr.nlink.get());
        (*inode).i_blocks = attr.blocks.get();
        voidport_i_size_write(inode, new_size);
        voidport_inode_set_times(
            inode,
            timespec(attr.atime.sec.get(), attr.atime.nsec.get()),
            timespec(attr.mtime.sec.get(), attr.mtime.nsec.get()),
            timespec(attr.ctime.sec.get(), attr.ctime.nsec.get()),
        );
        node.attr_refreshed();
        Ok(())
    }
}

/// # Safety
///
/// `inode` must be a live, initialised voidport inode.
pub(crate) unsafe fn attr_stale(inode: *mut bindings::inode) -> bool {
    // SAFETY: the caller promises a live, initialised inode of a live
    // voidport superblock.
    unsafe { node_of(inode).attr_stale(inode_mount(inode).attr_timeout()) }
}

/// # Safety
///
/// `inode` must be a live, initialised voidport inode.
pub(crate) unsafe fn refresh_if_stale(inode: *mut bindings::inode, caller: Caller) -> Result {
    // SAFETY: the caller promises a live, initialised inode.
    if !unsafe { attr_stale(inode) } {
        return Ok(());
    }
    // SAFETY: the caller promises a live, initialized inode.
    unsafe { refresh(inode, caller) }
}

/// # Safety
///
/// `inode` must be a live, initialized voidport inode.
pub(crate) unsafe fn refresh(inode: *mut bindings::inode, caller: Caller) -> Result {
    // SAFETY: the caller promises initialized private state on a live inode.
    let (session, node_id) = unsafe { session_and_id(inode) };
    // SAFETY: as above.
    let sent_at = unsafe { inode_mount(inode) }.writes();
    let attr = session.getattr(caller, node_id, None)?;
    // SAFETY: as above. Local representation and invalidation errors do not
    // affect the healthy connection that supplied these attributes.
    unsafe { apply_attr(inode, &attr, sent_at) }
}

/// Counts a write of the mount and records on `inode` that the mount applied
/// it, which makes the presented attributes expire. Returns the count of the
/// write.
///
/// # Safety
///
/// `inode` must be a live, initialised voidport inode.
pub(crate) unsafe fn record_session_write(inode: *mut bindings::inode) -> u64 {
    // SAFETY: the caller promises a live, initialised inode.
    let count = unsafe { inode_mount(inode) }.count_write();
    // SAFETY: as above.
    unsafe { record_write(inode, count) };
    count
}

/// Shows `inode` at `size`, the size the server gave the file, with the page
/// cache cut there, and records the change as a write of the mount. Returns
/// the count of that write.
///
/// # Safety
///
/// `inode` is a live voidport inode, and the caller holds its inode lock and
/// its invalidate lock exclusively.
pub(crate) unsafe fn resize(inode: *mut bindings::inode, size: bindings::loff_t) -> u64 {
    // SAFETY: the promises of the caller hold.
    unsafe {
        bindings::truncate_setsize(inode, size);
        record_session_write(inode)
    }
}

/// # Safety
///
/// `inode` is a live voidport inode.
pub(crate) unsafe fn write_back_all(inode: *mut bindings::inode) -> Result {
    // SAFETY: the inode is live, and its mapping as long.
    to_result(unsafe {
        bindings::filemap_write_and_wait_range((*inode).i_mapping, 0, bindings::loff_t::MAX)
    })
}

/// Records that the mount applied a write to an inode at the write count
/// `count`, which makes the presented attributes expire. A writeback applies
/// its write beside another write to the file, and direct writes to a file
/// apply their replies at the same time, so the recorded count is the highest
/// one, whatever order they record in.
///
/// # Safety
///
/// `inode` must be a live, initialised voidport inode.
unsafe fn record_write(inode: *mut bindings::inode, count: u64) {
    // SAFETY: the caller promises a live, initialised inode.
    let node = unsafe { node_of(inode) };
    let mut latest = node.written_at.load(Relaxed);
    while latest < count {
        match node.written_at.cmpxchg(latest, count, Relaxed) {
            Ok(_) => break,
            Err(current) => latest = current,
        }
    }
    node.expire_attr();
}

/// Reserves the Flush that the wire lock owner `lock_owner` of `caller` owes
/// an inode before it places a record lock on the server for it, unless the
/// owner has one.
///
/// # Safety
///
/// `inode` must be a live, initialised voidport inode.
pub(crate) unsafe fn reserve_flush(
    inode: *mut bindings::inode,
    caller: Caller,
    lock_owner: u64,
) -> Result {
    // SAFETY: the caller promises a live, initialised inode.
    let node = unsafe { node_of(inode) };
    if owes_flush(node, lock_owner) {
        return Ok(());
    }
    let flush = Cleanup::flush(caller, node.node_id, lock_owner)?;
    let entry = RBTreeNode::new(lock_owner, flush, GFP_KERNEL)?;
    let mut flushes = node.flushes.lock();
    if flushes.get(&lock_owner).is_none() {
        flushes.insert(entry);
    }
    Ok(())
}

/// Whether the wire lock owner `lock_owner` placed a record lock on the
/// server for an inode, which the close of a descriptor releases with a
/// Flush.
///
/// # Safety
///
/// `inode` must be a live, initialised voidport inode.
pub(crate) unsafe fn placed_locks(inode: *mut bindings::inode, lock_owner: u64) -> bool {
    // SAFETY: the caller promises a live, initialised inode.
    owes_flush(unsafe { node_of(inode) }, lock_owner)
}

fn owes_flush(node: &Node, lock_owner: u64) -> bool {
    node.flushes.lock().get(&lock_owner).is_some()
}

/// Takes the Flush of the wire lock owner `lock_owner` out of an inode, for
/// the cleanup worker to send.
///
/// # Safety
///
/// `inode` must be a live, initialised voidport inode.
pub(crate) unsafe fn take_flush(
    inode: *mut bindings::inode,
    lock_owner: u64,
) -> Option<KBox<Cleanup>> {
    // SAFETY: the caller promises a live, initialised inode.
    unsafe { node_of(inode) }.flushes.lock().remove(&lock_owner)
}

/// Ends the lifetime of the attributes an inode presents, after a reply that
/// changed them on the server without carrying them, so the next use fetches
/// them from the server.
///
/// # Safety
///
/// `inode` must be a live, initialised voidport inode.
pub(crate) unsafe fn expire(inode: *mut bindings::inode) {
    // SAFETY: the caller promises a live, initialised inode.
    unsafe { node_of(inode).expire_attr() };
}

fn timespec(sec: i64, nsec: u32) -> bindings::timespec64 {
    bindings::timespec64 {
        tv_sec: sec,
        tv_nsec: nsec as isize,
    }
}

/// Eviction allocates nothing and performs no peer I/O. Each lookup moves its
/// preallocated record to the cleanup worker, which retains the connection
/// that admitted the node, also across a reconnect.
///
/// # Safety
///
/// `inode` must be a voidport inode being evicted, past any final page
/// truncation.
pub(crate) unsafe fn evict(inode: *mut bindings::inode) {
    // SAFETY: the evict path passes a live inode this filesystem owns.
    unsafe {
        bindings::truncate_inode_pages_final((*inode).i_mapping);
        bindings::clear_inode(inode);
        let private = (*inode).i_private;
        if private.is_null() {
            return;
        }
        let node = &*private.cast::<Node>();
        // A handle open for dirty folios goes back with the dropped folios,
        // before the server forgets the node.
        node.writers.clear();
        let outstanding = node.lookup.load(Relaxed);
        // Root's local count came from GETATTR, not a server lookup admission.
        // Final session teardown clears any remaining server node state.
        if outstanding > 0 && node.node_id != ROOT_NODE_ID {
            let session = session_of((*inode).i_sb);
            session.forget(Caller::current(), node.node_id, outstanding);
        }
    }
}

/// The generic inode allocation is released separately by `free_inode_nonrcu`.
/// No module callback is retained for the subsequent RCU grace period.
///
/// # Safety
///
/// `inode` must be an unhashed inode being destroyed by the VFS.
pub(crate) unsafe extern "C" fn destroy(inode: *mut bindings::inode) {
    // SAFETY: hash removal excludes cache-match callbacks; no inode reference
    // remains. Allocation failures can reach this callback without private data.
    unsafe {
        let private = (*inode).i_private;
        if !private.is_null() {
            (*inode).i_private = core::ptr::null_mut();
            drop(KBox::from_raw(private.cast::<Node>()));
        }
    }
}
