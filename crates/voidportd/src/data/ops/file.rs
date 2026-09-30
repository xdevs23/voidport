//! File operations: open, create, read, write, release, sync, locking.

use std::os::fd::AsFd;
use std::sync::{Arc, Weak};
use std::time::Duration;

use rustix::fs::{Mode, OFlags};
use rustix::io::Errno;
use voidport_control::HostDirectIo;
use voidport_proto::error::FramingError;
use voidport_proto::frame::FrameWriter;
use voidport_proto::message::Request;
use voidport_proto::opcode::Opcode;
use voidport_proto::ops::file::{
    CreateRequest, CreateResponse, FileLock, FlushRequest, FlushResponse, FsyncRequest,
    FsyncResponse, GetlkRequest, GetlkResponse, OpenRequest, OpenResponse, ReadRequest,
    ReadResponse, ReleaseRequest, ReleaseResponse, SetlkRequest, SetlkResponse, WriteRequest,
    WriteResponse, fsync_flags, lock_type, release_flags, setlk_flags, write_flags,
};
use zerocopy::byteorder::little_endian::{U32, U64};

use super::node::entry_of;
use super::{Context, OpResult, fixed_len, name_of};
use crate::data::handle::{FileHandle, Handle};
use crate::data::locks::{FileLocks, OwnerLocks, Placed};
use crate::host::lock::{Conflict, LockKind, LockRange};
use crate::host::open::{create_child, pin_child, reopen};
use crate::rules::GuestIds;

/// The open flags the server honours on a reopen.
///
/// Everything about *name resolution* is the server's business, not the
/// client's: `O_CREAT`, `O_EXCL`, `O_NOFOLLOW`, `O_DIRECTORY` and `O_PATH` are
/// dropped, because the node has already been resolved under containment and
/// the reopen must not re-decide any of it.
///
/// What survives is everything that describes *how this description behaves*,
/// and `O_APPEND` is the one that carries a guarantee: it is the whole of
/// voidport's atomic append. See [`write`] — the host descriptor carrying the
/// flag is what places a guest's appends at the true end of the file, so
/// removing `O_APPEND` from this set would not merely lose a flag, it would
/// turn concurrent appends from two mounts into silent overwrites.
///
/// `O_DIRECT` is the one flag the guest does not decide. Where the server's
/// backing I/O sits — on the host page cache or past it — is the namespace's
/// [`HostDirectIo`] posture, and this is the single point that derives the flag
/// from it: a guest handle's own `O_DIRECT` is guest-side presentation until a
/// posture says otherwise.
fn open_flags(raw: u32, posture: HostDirectIo) -> OFlags {
    let requested = OFlags::from_bits_truncate(raw);
    let allowed = OFlags::RDONLY
        | OFlags::WRONLY
        | OFlags::RDWR
        | OFlags::APPEND
        | OFlags::TRUNC
        | OFlags::NONBLOCK
        | OFlags::DSYNC
        | OFlags::SYNC
        | OFlags::NOATIME;
    let direct = match posture {
        HostDirectIo::Cached => OFlags::empty(),
        HostDirectIo::Passthrough => requested & OFlags::DIRECT,
        HostDirectIo::Always => OFlags::DIRECT,
    };
    (requested & allowed) | direct
}

/// Whether an open asks for write access.
fn writes(flags: OFlags) -> bool {
    flags.contains(OFlags::WRONLY) || flags.contains(OFlags::RDWR) || flags.contains(OFlags::TRUNC)
}

/// Opens a node.
///
/// A directory open materializes the merged, policy-filtered listing that
/// readdirplus then walks; a file open reopens the pinned descriptor for real
/// I/O. Permission is checked exactly here, once: a graft downgraded to
/// read-only afterwards leaves this handle alone, precisely as a local `chmod`
/// leaves open descriptors alone.
pub fn open(context: &Context<'_>, request: Request<'_, OpenRequest>) -> OpResult {
    let session = context.session;
    let node = session.node(request.head().node_id.get())?;
    let namespace = session.namespace();
    let flags = open_flags(request.body().flags.get(), namespace.direct_io());
    // Enforcement is unconditional, so it happens before the open decides
    // anything else: an open for write through a read-only node is `EROFS`
    // whether that node is a file or a directory.
    if writes(flags) {
        node.require_writable()?;
    }
    if node.is_directory() {
        let listing = session.materialize(&node)?;
        let handle = session
            .handles()
            .insert(node.id, Handle::Directory(Arc::new(listing)))?;
        return context.reply(&OpenResponse {
            handle: U64::new(handle),
            flags: U32::ZERO,
            reserved: U32::ZERO,
        });
    }

    // The handle takes the node's pin with it, which is what keeps an open
    // file working through eviction: the budget bounds what the *cache* holds,
    // and a handle's own reference is its own.
    let pinned = node.descriptor(&namespace)?.ok_or(Errno::STALE)?;
    let fd = reopen(pinned.as_fd(), flags)?;
    let locks = session
        .locks()
        .join(node.identity().ok_or(Errno::STALE)?, &pinned);
    let handle = session.handles().insert(
        node.id,
        Handle::File(Arc::new(FileHandle::new(fd, locks, writes(flags), flags))),
    )?;
    context.reply(&OpenResponse {
        handle: U64::new(handle),
        flags: U32::ZERO,
        reserved: U32::ZERO,
    })
}

/// Creates a file and opens it in one round trip.
pub fn create(context: &Context<'_>, request: Request<'_, CreateRequest>) -> OpResult {
    let session = context.session;
    let parent = session.node(request.head().node_id.get())?;
    let name = name_of(request.name())?;
    let site = session.site(&parent, &name)?;
    let body = request.body();

    let flags = open_flags(body.flags.get(), session.namespace().direct_io());
    let mode = super::dir::permissions(body.mode.get(), body.umask.get());
    let exclusive = OFlags::from_bits_truncate(body.flags.get()).contains(OFlags::EXCL);
    let open = |flags, mode| create_child(site.directory.as_fd(), &site.name, flags, mode);
    // Whether this call *created* the entry decides two things — whose the
    // entry is, and what its mode is — so the exclusive attempt comes first and
    // the plain open is the fallback. A create over something that already
    // exists must not re-own it or re-mode it. The fallback passes no mode at
    // all: `openat2` — unlike `openat` — refuses a nonzero mode on an open that
    // cannot create.
    let (fd, created) = match open(
        flags | OFlags::CREATE | OFlags::EXCL,
        super::dir::host_permissions(mode),
    ) {
        Ok(fd) => (fd, true),
        Err(Errno::EXIST) if !exclusive => (open(flags, Mode::empty())?, false),
        Err(error) => return Err(error),
    };

    if created {
        let caller = GuestIds::new(request.head().uid.get(), request.head().gid.get());
        session.apply_create_ownership(fd.as_fd(), caller);
        apply_mode(fd.as_fd(), mode)?;
        // Before the entry reply below is built, because that reply presents
        // the mode the guest asked for — the recorded bits included.
        record_created_mode(session, fd.as_fd(), &site.recipe, mode)?;
    }

    // The entry becomes a node pinned from the site it was created at, not
    // looked up again through the namespace. A rename that replaces the name
    // between the create and this pin still makes the reply describe the file
    // now at the name. The handle then joins the lock set of the *node's*
    // file, whose per-owner lock descriptions are reopened from the node's pin.
    let pinned = pin_child(site.directory.as_fd(), &site.name)?;
    let resolved = session.admit_pinned(
        parent.path.child(&name),
        pinned,
        site.recipe.clone(),
        site.backing.clone(),
        site.mode,
    )?;
    let node_pin = resolved
        .node
        .descriptor(&session.namespace())?
        .ok_or(Errno::STALE)?;
    let locks = session
        .locks()
        .join(resolved.node.identity().ok_or(Errno::STALE)?, &node_pin);
    // The insert is its own statement so its guard is gone before the error arm
    // touches the node table: a guard produced in a `match` scrutinee outlives
    // the arms, and holding the handle table across the node table here would
    // give the request path a lock order that `Session::summary` — which reads
    // both counts for the operator — could deadlock against.
    let inserted = session.handles().insert(
        resolved.node.id,
        Handle::File(Arc::new(FileHandle::new(fd, locks, true, flags))),
    );
    let handle = match inserted {
        Ok(handle) => handle,
        Err(error) => {
            // No entry reply leaves, so the client never learns the node id
            // this request interned and could never `forget` it. The lookup it
            // counted is released here instead, which is what lets a client
            // that hit the handle cap close a handle and retry. The created
            // host entry stays: it is the file the guest asked for, and
            // unlinking a name that may already have been replaced would
            // destroy data this request did not make.
            session.nodes().forget(resolved.node.id, 1);
            return Err(error);
        }
    };
    context.reply(&CreateResponse {
        entry: entry_of(&resolved),
        handle: U64::new(handle),
        flags: U32::ZERO,
        reserved: U32::ZERO,
    })
}

/// Reads file data.
///
/// The data lands **straight in the frame buffer**: the payload region is read
/// into before the header is written over the bytes in front of it, so a read
/// costs one copy from the kernel and none after. This is the zero-copy hot
/// path the wire format exists for.
///
/// A handle whose backing description is uncached is the one exception, and it
/// is not a choice: direct I/O refuses a buffer that does not sit on the
/// backing file's alignment, and the payload region sits behind a fixed
/// response head. [`BackingIo`](crate::host::BackingIo) is what the handle
/// carries for exactly this —
/// it serves the transfer through an aligned buffer and copies the bytes into
/// place, which is the cost the uncached postures pay per request.
pub fn read(context: &Context<'_>, request: Request<'_, ReadRequest>) -> OpResult {
    let body = request.body();
    let file = context.session.handles().file(body.handle.get())?;
    let size = context
        .payload_budget::<ReadResponse>()
        .min(body.size.get() as usize);

    let fixed = fixed_len::<ReadResponse>();
    let mut buffer = vec![0u8; fixed + size];
    let read = file
        .backing_io()
        .read(file.fd(), &mut buffer[fixed..], body.offset.get())?;

    let response = ReadResponse {
        data_len: U32::new(u32::try_from(read).map_err(|_| Errno::OVERFLOW)?),
    };
    let length = {
        let mut writer = FrameWriter::response(
            &mut buffer,
            context.max_frame_len,
            context.request_id,
            &response,
        )
        .map_err(|_| Errno::OVERFLOW)?;
        // The payload is already in place; claiming it only tells the writer
        // the frame is complete.
        writer.payload_buf(read).map_err(|_| Errno::OVERFLOW)?;
        writer.finish().map_err(|_| Errno::OVERFLOW)?.len()
    };
    buffer.truncate(length);
    Ok(buffer)
}

/// Writes file data.
///
/// Enforcement happened at open: a handle opened read-only cannot be written,
/// and the kernel says so on its own description.
///
/// # Appending is the host's decision, not the offset's
///
/// The offset in the request is the *guest kernel's*, and on an appending
/// handle it is a guess: `generic_write_checks` moves the position to the inode
/// size the guest has cached before FUSE is called at all, and with a second
/// mount writing the same file that size is stale by construction — nothing
/// tells one guest kernel that another client extended the file. A server that
/// placed the bytes at that offset would let two appending clients overwrite
/// each other, which is precisely what a size-caching network filesystem does.
///
/// This one never places them there. The guest's `O_APPEND` rode the wire open
/// into the host open ([`open_flags`]), and Linux's `pwrite(2)` on a
/// description carrying `O_APPEND` ignores the offset and appends under the
/// inode lock — its documented departure from POSIX, which the test below pins
/// instead of trusting it. The position is therefore chosen by the host kernel,
/// atomically with the write, for every client at once: the guarantee two local
/// processes already have.
///
/// The reply stays coherent for the guest kernel even though the data can land
/// somewhere it did not name, and that needs spelling out. A write
/// reply carries a *count*, never a position, and FUSE requires only that the
/// count not exceed what was sent. The mount negotiates no writeback cache and
/// is writethrough, so no dirty pages are being held whose position the kernel
/// must later reconcile: it takes the count, advances its own file position,
/// and updates its cached size, which the next attribute revalidation corrects
/// from the host. An appending guest may briefly believe the file is shorter
/// than it is — a cache being behind, which every attribute timeout already
/// allows, and not data placed wrongly.
///
/// One bound is inherited and cannot be fixed here: atomicity is per write
/// *request*, and a single guest write larger than the negotiated `max_write`
/// is split by the guest kernel into several, which another client's appends
/// may land between. A record written in one write of at most that size is
/// never torn.
///
/// The bytes are the request frame's own, so an uncached handle copies them
/// into an aligned buffer first — see [`read`], and
/// [`BackingIo`](crate::host::BackingIo) for why the server's buffers can never
/// satisfy direct I/O on their own.
pub fn write(context: &Context<'_>, request: Request<'_, WriteRequest>) -> OpResult {
    let session = context.session;
    let body = request.body();
    let file = session.handles().file(body.handle.get())?;
    let written = file
        .backing_io()
        .write(file.fd(), request.data(), body.offset.get())?;
    if body.write_flags.get() & write_flags::PRIVILEGED_STRIP != 0 {
        strip_privileged(context.session, request.head().node_id.get());
    }
    context.reply(&WriteResponse {
        written: U32::new(u32::try_from(written).map_err(|_| Errno::OVERFLOW)?),
    })
}

/// Applies the strip the guest kernel asked for on a write that already
/// happened.
///
/// Never a failure of the write. The bytes are on the host by the time this
/// runs, and answering `EIO` for a bookkeeping step the guest did not ask about
/// would tell it a write failed that did not — so a strip that cannot read the
/// node says so in the log and the write is answered as what it was.
fn strip_privileged(session: &crate::data::session::Session, node_id: u64) {
    let stripped = session.node(node_id).and_then(|node| {
        let namespace = session.namespace();
        let privileged = session.privileged(&namespace);
        session.strip_written(&namespace, &privileged, &node)
    });
    if let Err(error) = stripped {
        tracing::debug!(
            node = node_id,
            %error,
            "a written file's privileged bits could not be stripped"
        );
    }
}

/// Releases a handle, closing the host descriptor it held.
///
/// The file's lock set outlives the handle while another handle on the file is
/// open, because a lock belongs to its owner for the whole file. Once the last
/// handle on the file goes, every description goes with it, so the locks the
/// session held on the file are gone whether or not the client asked for the
/// unlock.
pub fn release(context: &Context<'_>, request: Request<'_, ReleaseRequest>) -> OpResult {
    let body = request.body();
    let handle = body.handle.get();
    if body.release_flags.get() & release_flags::UNLOCK != 0
        && let Ok(file) = context.session.handles().file(handle)
    {
        file.locks().release_owner(body.lock_owner.get());
    }
    context.session.handles().remove(handle);
    context.reply(&ReleaseResponse {})
}

/// Flushes one guest descriptor's close.
///
/// POSIX drops a process's record locks when it closes *any* descriptor for the
/// file, and `flush` is where a client reports that; the owner's description
/// goes with it, and with it every lock the owner placed on the file through
/// any handle. Nothing is synced here — `fsync` is the operation that means
/// durability.
pub fn flush(context: &Context<'_>, request: Request<'_, FlushRequest>) -> OpResult {
    let body = request.body();
    let file = context.session.handles().file(body.handle.get())?;
    file.locks().release_owner(body.lock_owner.get());
    context.reply(&FlushResponse {})
}

/// Flushes a handle to stable storage.
///
/// A directory handle has nothing to sync: its listing is a server-side
/// snapshot, and the host directory it came from was never modified through it.
pub fn fsync(context: &Context<'_>, request: Request<'_, FsyncRequest>) -> OpResult {
    let body = request.body();
    match context.session.handles().get(body.handle.get()) {
        Some(Handle::File(file)) => {
            if body.flags.get() & fsync_flags::DATASYNC != 0 {
                rustix::fs::fdatasync(file.fd())?;
            } else {
                rustix::fs::fsync(file.fd())?;
            }
        }
        Some(Handle::Directory(_)) => {}
        None => return Err(Errno::BADF),
    }
    context.reply(&FsyncResponse {})
}

/// Tests whether a lock could be placed.
///
/// A query never *creates* a description. An owner that already holds one is
/// asked through it, so its own locks answer "unlocked" as POSIX says they
/// must; an owner that holds none is asked through the handle's own descriptor,
/// which is a distinct description that by construction carries no locks — so
/// the answer is identical, and a guest cannot make the server spend a host
/// descriptor per invented owner id.
pub fn getlk(context: &Context<'_>, request: Request<'_, GetlkRequest>) -> OpResult {
    let body = request.body();
    let file = context.session.handles().file(body.handle.get())?;
    let (kind, range) = lock_request(&body.lock)?;
    let conflict = file
        .locks()
        .test(body.lock.owner.get(), kind, range, file.fd())?;
    context.reply(&GetlkResponse {
        lock: conflict_reply(&body.lock, conflict),
    })
}

/// What placing a lock produced: an answer, or a wait the connection drives.
#[derive(Debug)]
pub enum Locked {
    /// The lock was placed or released; here is the encoded reply.
    Answered(Vec<u8>),
    /// The range is held by someone else and the guest asked to wait. The wire
    /// request stays pending until [`LockWait`] settles it.
    Waiting(LockWait),
}

/// Places or releases a lock.
///
/// Each wire owner gets its own open file description per file, because locks
/// held through one description coalesce instead of conflicting, and every
/// handle on the file places that owner's locks through it, because a POSIX
/// lock is its owner's for the whole file (see [`crate::data::locks`]). A lock
/// of a kind the handle's access does not cover is refused with `EBADF`, as
/// through a local descriptor.
///
/// A description exists only while its owner holds a lock through it or a
/// blocking request of the owner waits on it: an unlock from an owner that has
/// none is answered without opening anything, and one that leaves the owner
/// holding nothing — a refused first lock included — closes it again.
///
/// **A blocking request never blocks a thread.** The host call is always the
/// non-blocking one; a conflict on a request that asked to wait becomes a
/// [`LockWait`] the connection polls asynchronously, and the guest sees only
/// what it always saw — no reply until the lock is its own.
pub fn setlk(context: &Context<'_>, request: Request<'_, SetlkRequest>) -> Result<Locked, Errno> {
    let body = request.body();
    let file = context.session.handles().file(body.handle.get())?;
    let (kind, range) = lock_request(&body.lock)?;
    file.permits(kind)?;
    let owner = body.lock.owner.get();
    let wait = body.flags.get() & setlk_flags::WAIT != 0;
    match file
        .locks()
        .place(owner, kind, range, file.access(), wait)?
    {
        Placed::Done => context.reply(&SetlkResponse {}).map(Locked::Answered),
        Placed::Waiting(record) => Ok(Locked::Waiting(LockWait {
            locks: Arc::downgrade(file.locks()),
            record,
            owner,
            kind,
            range,
            request_id: context.request_id,
            max_frame_len: context.max_frame_len,
            attempts: 0,
            settled: false,
        })),
    }
}

/// How long the first retry of a stacked lock waiter sleeps.
///
/// Small enough that a lock released immediately after a conflict is picked up
/// in about a millisecond, which is under the round trip that carried the
/// request in.
const LOCK_RETRY_START: Duration = Duration::from_millis(1);

/// The longest a waiter sleeps between attempts.
///
/// This is the acquisition latency a released lock pays in the worst case, and
/// the design asks for it to stay unobtrusive; it is also what bounds the
/// syscall rate of a storm, at one `fcntl` per waiter per cap.
const LOCK_RETRY_CAP: Duration = Duration::from_millis(8);

/// A guest's blocking lock request, waiting for the range to come free.
///
/// # Why this is a future and not a thread
///
/// `F_OFD_SETLKW` would express the wait in one syscall, and that syscall
/// sleeps: it costs one thread of the blocking pool for as long as the holder
/// holds. The pool is shared by every session's host I/O and is not large, so a
/// few hundred stacked waiters — one file locked by a build across a dozen
/// mounts is enough — would starve every other operation on the server. The
/// design rules waits async for exactly this: a parked future costs bytes, and
/// a million of them are affordable.
///
/// # Fairness
///
/// Best-effort, and deliberately so. Retry order is not a queue: when a holder
/// releases, whichever waiter wakes first takes the range, and the sleeps are
/// jittered so a storm does not converge on one instant. POSIX guarantees no
/// order for `F_SETLKW` either, so nothing a guest may rely on is lost — but a
/// waiter can be overtaken, and under a sustained storm one may wait
/// noticeably longer than its neighbours.
#[derive(Debug)]
pub struct LockWait {
    /// The file's lock set, which a cancelled wait closes an empty record in.
    /// Weak, because the set lives as long as the session's handles on the
    /// file and no longer: a wait does not keep its locks.
    locks: Weak<FileLocks>,
    /// The owner's record on the file, which every attempt goes through.
    record: Arc<OwnerLocks>,
    owner: u64,
    kind: LockKind,
    range: LockRange,
    request_id: u64,
    max_frame_len: u32,
    /// How many attempts have been made, which is what the backoff grows on.
    attempts: u32,
    /// Whether the placement has been resolved, which is what tells the drop
    /// glue a cancelled wait from a finished one.
    settled: bool,
}

impl LockWait {
    /// Waits until the lock is this owner's, and answers the request.
    ///
    /// Dropping the returned future is the cancellation the contract rules: the
    /// connection is gone, so nothing is answered, and the owner's record is
    /// closed if nothing needs it any more. A close of another of the owner's
    /// descriptors releases the owner's locks and leaves this wait waiting, as
    /// it does locally; the session's last handle on the file closing ends it
    /// with `EBADF`, as a waiting lock whose descriptor was closed ends.
    pub async fn settle(mut self) -> Result<Vec<u8>, FramingError> {
        loop {
            tokio::time::sleep(self.backoff()).await;
            match self.record.retry(self.kind, self.range) {
                Ok(true) => {
                    self.settled = true;
                    return self.encode(Ok(()));
                }
                Ok(false) => {}
                Err(error) => {
                    self.settled = true;
                    self.abandon();
                    return self.encode(Err(error));
                }
            }
        }
    }

    /// How long to sleep before the next attempt.
    ///
    /// Exponential from [`LOCK_RETRY_START`] to [`LOCK_RETRY_CAP`], jittered
    /// down by up to a quarter. The jitter is what keeps a storm from
    /// converging: a thousand waiters that all conflicted at the same instant
    /// would otherwise wake at the same instant forever, and every wake but one
    /// is a wasted syscall.
    fn backoff(&mut self) -> Duration {
        let step = LOCK_RETRY_START
            .saturating_mul(1u32 << self.attempts.min(16))
            .min(LOCK_RETRY_CAP);
        self.attempts = self.attempts.saturating_add(1);
        let nanos = u64::from(step.subsec_nanos()) + step.as_secs() * 1_000_000_000;
        Duration::from_nanos(nanos - nanos / 4 * self.jitter() / 255)
    }

    /// A cheap per-waiter pseudorandom byte.
    ///
    /// Seeded from the request id and the owner, so two waiters of one storm
    /// diverge without the server holding a random-number generator.
    fn jitter(&self) -> u64 {
        let mut state = self
            .request_id
            .wrapping_mul(0x9E37_79B9_7F4A_7C15)
            .wrapping_add(self.owner)
            .wrapping_add(u64::from(self.attempts))
            | 1;
        state ^= state >> 33;
        state = state.wrapping_mul(0xFF51_AFD7_ED55_8CCD);
        state ^= state >> 29;
        state & 0xFF
    }

    /// The reply frame this request ends with.
    fn encode(&self, outcome: Result<(), Errno>) -> Result<Vec<u8>, FramingError> {
        super::encode_outcome(
            self.max_frame_len,
            self.request_id,
            Opcode::Setlk,
            outcome.map(|()| SetlkResponse {}),
        )
    }
}

impl LockWait {
    /// Closes the owner's record if it holds nothing, now that this wait will
    /// not place anything through it.
    fn abandon(&self) {
        if let Some(locks) = self.locks.upgrade() {
            locks.abandon(self.owner, &self.record);
        }
    }
}

impl Drop for LockWait {
    /// The connection died while this request was parked. The contract makes
    /// that the end of the wait — nothing is answered — and the owner's record
    /// is closed if it holds nothing.
    fn drop(&mut self) {
        if !self.settled {
            self.abandon();
        }
    }
}

/// Applies the exact permission bits a create asked for.
///
/// The design makes the *caller's* umask the one that applies, and the server
/// has already subtracted it. The server process has a umask of its own, which
/// the kernel would apply on top and which has nothing to do with the guest, so
/// the created entry's mode is set explicitly afterwards.
///
/// # Errors
///
/// Returns the host errno of the mode change.
pub(super) fn apply_mode(fd: std::os::fd::BorrowedFd<'_>, mode: u32) -> Result<(), Errno> {
    rustix::fs::chmodat(
        rustix::fs::CWD,
        crate::host::open::proc_path(fd).as_str(),
        super::dir::host_permissions(mode),
        rustix::fs::AtFlags::empty(),
    )
}

/// Records the privileged bits a create delivered.
///
/// Run **before** the entry reply is built, so the reply presents the mode the
/// guest asked for. A create that delivered none records nothing and stats
/// nothing: the entry is a fresh inode, so there is no record for an absent bit
/// to delete — the assignment rule's delete arm belongs to chmod, where a
/// record can already exist.
///
/// `recipe` is the site's, never its backing: a create under a directory the
/// server itself renamed lands where the host has that directory now, and a
/// locator spelled from the namespace's older description would name nothing
/// for the restart's revalidating stat to find.
///
/// # Errors
///
/// The host errno of the stat that names the created inode.
pub(super) fn record_created_mode(
    session: &crate::data::session::Session,
    fd: std::os::fd::BorrowedFd<'_>,
    recipe: &crate::rules::HostBacking,
    delivered: u32,
) -> Result<(), Errno> {
    if crate::records::PrivilegedBits::of(delivered).is_empty() {
        return Ok(());
    }
    let namespace = session.namespace();
    let privileged = session.privileged(&namespace);
    let identity = crate::host::attr::HostAttr::of(fd)?.node_identity();
    session.record_delivered_mode(&privileged, identity, recipe, delivered);
    Ok(())
}

/// The kind and range a wire lock describes.
fn lock_request(lock: &FileLock) -> Result<(LockKind, LockRange), Errno> {
    let kind = match lock.lock_type.get() {
        lock_type::READ => LockKind::Read,
        lock_type::WRITE => LockKind::Write,
        lock_type::UNLOCK => LockKind::Unlock,
        _ => return Err(Errno::INVAL),
    };
    Ok((kind, LockRange::new(lock.start.get(), lock.end.get())))
}

/// The lock a `getlk` answers with: the conflict, or the request marked
/// unlocked.
fn conflict_reply(request: &FileLock, conflict: Option<Conflict>) -> FileLock {
    let Some(conflict) = conflict else {
        return FileLock {
            start: request.start,
            end: request.end,
            owner: request.owner,
            pid: request.pid,
            lock_type: U32::new(lock_type::UNLOCK),
        };
    };
    FileLock {
        start: U64::new(conflict.range.start),
        end: U64::new(conflict.range.end),
        owner: request.owner,
        // An OFD lock has no owning process, and the kernel says so with -1.
        pid: U32::new(conflict.pid as u32),
        lock_type: U32::new(match conflict.kind {
            LockKind::Read => lock_type::READ,
            LockKind::Write => lock_type::WRITE,
            LockKind::Unlock => lock_type::UNLOCK,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The flags a cached namespace derives, which is every test that is not
    /// about the posture.
    fn cached_flags(raw: u32) -> OFlags {
        open_flags(raw, HostDirectIo::Cached)
    }

    #[test]
    fn resolution_flags_never_survive_a_reopen() {
        let raw = OFlags::RDWR
            | OFlags::CREATE
            | OFlags::EXCL
            | OFlags::NOFOLLOW
            | OFlags::DIRECTORY
            | OFlags::APPEND;
        let flags = cached_flags(raw.bits());
        assert!(flags.contains(OFlags::RDWR));
        assert!(flags.contains(OFlags::APPEND));
        assert!(!flags.contains(OFlags::CREATE));
        assert!(!flags.contains(OFlags::EXCL));
        assert!(!flags.contains(OFlags::DIRECTORY));
    }

    /// `O_APPEND` is not a resolution flag, and dropping it would cost the
    /// atomic-append guarantee, not a convenience — so it is asserted on
    /// its own, in both spellings a guest can ask for it.
    #[test]
    fn an_append_open_keeps_its_flag() {
        for access in [OFlags::WRONLY, OFlags::RDWR] {
            let flags = cached_flags((access | OFlags::APPEND).bits());
            assert!(flags.contains(OFlags::APPEND), "{access:?}");
            assert!(writes(flags), "an appending open is an open for write");
        }
        assert!(!cached_flags(OFlags::WRONLY.bits()).contains(OFlags::APPEND));
    }

    /// The three postures, at the one point that derives the flag from them.
    ///
    /// The guest's own `O_DIRECT` is presentation until a posture says
    /// otherwise: the default namespace rides the host page cache whatever the
    /// handle asked for, passthrough forwards exactly what it asked for, and
    /// always opens uncached whatever it asked for.
    #[test]
    fn the_posture_decides_whether_the_backing_open_is_uncached() {
        let asked = (OFlags::RDWR | OFlags::DIRECT).bits();
        let plain = OFlags::RDWR.bits();

        assert!(!open_flags(asked, HostDirectIo::Cached).contains(OFlags::DIRECT));
        assert!(!open_flags(plain, HostDirectIo::Cached).contains(OFlags::DIRECT));

        assert!(open_flags(asked, HostDirectIo::Passthrough).contains(OFlags::DIRECT));
        assert!(!open_flags(plain, HostDirectIo::Passthrough).contains(OFlags::DIRECT));

        assert!(open_flags(asked, HostDirectIo::Always).contains(OFlags::DIRECT));
        assert!(open_flags(plain, HostDirectIo::Always).contains(OFlags::DIRECT));

        // The posture decides that one flag and nothing else about the
        // description.
        for posture in [
            HostDirectIo::Cached,
            HostDirectIo::Passthrough,
            HostDirectIo::Always,
        ] {
            let flags = open_flags((OFlags::RDWR | OFlags::APPEND).bits(), posture);
            assert!(flags.contains(OFlags::APPEND), "{posture}");
            assert_eq!(flags - OFlags::DIRECT, OFlags::RDWR | OFlags::APPEND);
        }
    }

    /// The host behaviour the whole append story rests on.
    ///
    /// Linux departs from POSIX here — `pwrite(2)` on a description opened
    /// `O_APPEND` ignores its offset and appends — and [`write`] depends on it
    /// on every write of every appending handle. Depending on it silently would
    /// mean discovering a change to it as data loss, so it is asserted against
    /// a real file: an offset that would land inside the file lands at the end
    /// instead, and the earlier bytes are untouched.
    #[test]
    fn a_pwrite_through_an_appending_description_appends() {
        let scratch = crate::testing::Scratch::new("append");
        let path = scratch.file("log", b"0123456789");
        let fd = rustix::fs::open(
            &path,
            cached_flags((OFlags::WRONLY | OFlags::APPEND).bits()),
            Mode::empty(),
        )
        .expect("the file opens for appending");

        // Offset zero: the front of the file, which is where a stale guest
        // kernel would aim a first append.
        assert_eq!(rustix::io::pwrite(&fd, b"AB", 0).expect("writable"), 2);
        // And an offset that is neither the front nor the end.
        assert_eq!(rustix::io::pwrite(&fd, b"CD", 4).expect("writable"), 2);
        drop(fd);

        assert_eq!(
            std::fs::read(&path).expect("readable"),
            b"0123456789ABCD",
            "a pwrite through an appending description did not append"
        );
    }

    #[test]
    fn write_access_is_recognized_in_every_spelling() {
        assert!(writes(cached_flags(OFlags::WRONLY.bits())));
        assert!(writes(cached_flags(OFlags::RDWR.bits())));
        assert!(writes(cached_flags(
            (OFlags::RDONLY | OFlags::TRUNC).bits()
        )));
        assert!(!writes(cached_flags(OFlags::RDONLY.bits())));
    }

    #[test]
    fn a_free_range_is_reported_as_unlocked() {
        let request = FileLock {
            start: U64::new(4),
            end: U64::new(9),
            owner: U64::new(7),
            pid: U32::new(11),
            lock_type: U32::new(lock_type::WRITE),
        };
        let free = conflict_reply(&request, None);
        assert_eq!(free.lock_type.get(), lock_type::UNLOCK);
        assert_eq!(free.start.get(), 4);

        let held = conflict_reply(
            &request,
            Some(Conflict {
                kind: LockKind::Read,
                range: LockRange::new(0, 3),
                pid: -1,
            }),
        );
        assert_eq!(held.lock_type.get(), lock_type::READ);
        assert_eq!((held.start.get(), held.end.get()), (0, 3));
        assert_eq!(held.pid.get() as i32, -1);
    }

    #[test]
    fn a_lock_type_the_wire_does_not_define_is_invalid() {
        let lock = FileLock {
            start: U64::ZERO,
            end: U64::new(u64::MAX),
            owner: U64::ZERO,
            pid: U32::ZERO,
            lock_type: U32::new(99),
        };
        assert_eq!(lock_request(&lock).expect_err("unknown type"), Errno::INVAL);
    }
}
