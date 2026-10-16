//! The FUSE adapter: kernel callbacks in, wire operations out.
//!
//! Two rules shape every callback here.
//!
//! **Nothing blocks a dispatch loop.** A fuser event loop reads and dispatches
//! one request at a time; a callback that waited for the server would stall
//! every other operation that loop is holding, and a blocking `setlk` would
//! stall it for as long as another mount holds the lock. So each callback
//! captures what it needs, hands the work to the mount's async runtime, and
//! replies from there. The mount runs several such loops (see
//! [`mount`](crate::mount)), which raises the ceiling on concurrent guests but
//! does not weaken this rule: with a bounded number of loops, a callback that
//! blocks still stalls its share of the mount.
//!
//! Those loops call into one shared adapter, so nothing here may hold state
//! that a callback mutates: this struct is an `Arc<Client>`, a runtime handle,
//! two durations and the [`DataCaching`] mode, and `init` — the one `&mut self`
//! callback — runs during the handshake, before any loop exists. The caching
//! mode is the one field `init` writes, and every other callback only reads it.
//!
//! **The kernel node id is the server node id.** fuser takes an entry reply's
//! node id from `attr.ino`, so the presented `st_ino` is the node id too — the
//! deliberate, accepted consequence of that coupling (see [`attr`]).
//!
//! **The two cache lifetimes are two lifetimes.** An entry reply carries both
//! an entry validity (how long the name may resolve without another lookup) and
//! an attribute validity (how long the attributes may be believed), and
//! `--entry-timeout` and `--attr-timeout` govern one each. Where fuser 0.18
//! offers a split-TTL reply it is used; `create` and readdirplus entries have
//! only single-TTL forms in the library, so those carry the entry timeout for
//! both — noted at each site.
//!
//! The callback map is the design's, verbatim: `opendir`/`releasedir`/
//! `fsyncdir` ride the generic open, release and fsync operations; `readdir`
//! is served from wire readdirplus with compensating forgets (see [`dir`]);
//! `mknod` creates FIFOs and socket files on the host and answers `EPERM` for
//! device nodes, which stay a privileged decision nobody has made — refusing
//! those is not the same as missing a feature; `poll` answers always-ready,
//! and `ioctl` refuses the terminal
//! ioctls a real workload was seen issuing (both below); everything unmapped
//! keeps fuser's `ENOSYS` **and its per-call warning**, which is what surfaced
//! those two gaps in the first place. `access` is never reached: the mount sets
//! `default_permissions`, so the guest kernel checks the presented bits itself.

pub mod attr;
pub mod dir;

use std::ffi::OsStr;
use std::future::Future;
use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime};

use fuser::{
    BsdFileFlags, Errno, FileHandle, FopenFlags, Generation, INodeNo, IoctlFlags, KernelConfig,
    LockOwner, OpenFlags, PollEvents, PollFlags, PollNotifier, RenameFlags, ReplyAttr, ReplyCreate,
    ReplyData, ReplyDirectory, ReplyDirectoryPlus, ReplyEmpty, ReplyEntry, ReplyIoctl, ReplyLock,
    ReplyOpen, ReplyPoll, ReplyStatfs, ReplyWrite, ReplyXattr, Request, TimeOrNow, WriteFlags,
};
use voidport_proto::ops::dir::rename_flags;
use voidport_proto::ops::xattr::setxattr_flags;

use crate::client::{AttrChange, Caller, Client, Lock, LockKind, Readahead};
use crate::fuse::attr::{
    PRIVILEGED_MASK, Privileged, entry_attr, node_attr, time_change, timespec,
};
use crate::fuse::dir::{DirectoryEntry, DirectoryRead, DirectorySink, read_directory};

/// How the guest kernel caches the data of an open file.
///
/// Metadata is not in scope: the attribute and entry validities are the two
/// TTLs, and they are the same in both modes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DataCaching {
    /// The guest page cache holds file data, as it does for any filesystem: a
    /// re-read is answered from guest RAM, and N guests reading one host file
    /// keep N copies of it in N guests' memory.
    Page,
    /// Reads and writes go straight to the wire — the guest page cache holds no
    /// copy of the data, which is the whole point of the option — while the
    /// kernel still caches the pages of ranges a process has actually **mapped**,
    /// so `mmap` keeps working.
    Direct,
}

impl DataCaching {
    /// Resolves `--direct-io` against what the guest kernel offers.
    ///
    /// `mmap_under_direct_io` is whether the kernel negotiated
    /// `FUSE_DIRECT_IO_ALLOW_MMAP` (Linux 6.7+), which is what makes a shared
    /// mapping of a `FOPEN_DIRECT_IO` file legal instead of `ENODEV`. Without
    /// it, direct I/O would cost `mmap` — and therefore exec-from-mount and
    /// SQLite's WAL — so the mount silently keeps ordinary page caching and
    /// pays the memory instead. It never refuses the mount, and it never runs
    /// direct I/O without `mmap`: breaking `mmap` is excluded in every
    /// configuration.
    ///
    /// **Every mount says which mode it resolved to**, in one vocabulary, so
    /// that reading a mount's log is never a matter of interpreting silence —
    /// the field could not tell a direct mount from a mount whose option had
    /// been lost, because only one of the three cases below said anything. The
    /// level is what differs: a `--direct-io` mount's outcome is news and is
    /// logged at info, while a plain mount got what it asked for and says so at
    /// debug.
    #[must_use]
    pub fn resolve(requested: bool, mmap_under_direct_io: bool) -> Self {
        match (requested, mmap_under_direct_io) {
            (false, _) => {
                tracing::debug!(
                    "data caching: page (the default; file data is cached in the guest, and \
                     --direct-io is what trades that cache away)"
                );
                Self::Page
            }
            (true, true) => {
                tracing::info!(
                    "data caching: direct (FUSE_DIRECT_IO_ALLOW_MMAP negotiated; reads and \
                     writes bypass the guest page cache, mapped ranges still cache)"
                );
                Self::Direct
            }
            (true, false) => {
                tracing::info!(
                    "data caching: page (this kernel does not offer \
                     FUSE_DIRECT_IO_ALLOW_MMAP (Linux 6.7+), so --direct-io would cost mmap, \
                     exec-from-mount and SQLite's WAL; the mount keeps ordinary page caching \
                     and the guest memory it uses)"
                );
                Self::Page
            }
        }
    }

    /// The flags an `open` or `create` reply carries under this mode.
    ///
    /// A direct handle also announces `FOPEN_PARALLEL_DIRECT_WRITES`, and the
    /// announcement is the whole of it: without it the guest kernel takes the
    /// inode's lock **exclusively** around every direct write, so an application
    /// using asynchronous I/O has its writes to one file serialized before they
    /// ever reach a wire that could have overlapped them. With it the kernel
    /// takes the lock shared and the writes overlap — which is safe here for the
    /// reason it is safe at all: each write names its own offset and length, and
    /// the server places it there.
    ///
    /// **Honestly scoped.** The kernel keeps its exclusive lock — and therefore
    /// keeps serializing — for the three cases where a write's placement is not
    /// knowable in advance: `O_APPEND`, where the offset is the eventual end of
    /// file; a write extending past the current end; and a file that has ever
    /// been mapped, whose page cache is the other writer. So this helps in-place
    /// overwrites of an already-sized file, and nothing else claims otherwise.
    ///
    /// Nothing else is added: `FOPEN_KEEP_CACHE` stays off because v1 caching is
    /// writethrough and conservative, in both modes.
    #[must_use]
    fn fopen_flags(self) -> FopenFlags {
        match self {
            Self::Page => FopenFlags::empty(),
            Self::Direct => FopenFlags::FOPEN_DIRECT_IO | FopenFlags::FOPEN_PARALLEL_DIRECT_WRITES,
        }
    }
}

/// The callbacks the kernel is still owed a reply for.
///
/// Every callback hands its work to the runtime and replies from there, so
/// between a dispatch loop taking a request and that reply reaching the kernel
/// there is a window where the mount owes the kernel an answer nobody else can
/// give. A teardown that walks into that window costs twice: the guest is told
/// `EIO` for work that may have completed, and the caller waiting for the
/// answer is a reference the kernel counts against the mountpoint, so the
/// unmount is refused. Both are avoidable by asking what is outstanding and
/// waiting for it, which is what this counts — see
/// [`Mount::serve_until_signalled`](crate::mount::Mount::serve_until_signalled).
///
/// It counts callbacks and not wire requests, because what the kernel is owed
/// is one reply per callback however many round trips it takes.
#[derive(Debug, Default)]
pub struct InFlight {
    owed: Mutex<usize>,
    settled: Condvar,
}

impl InFlight {
    /// Waits until nothing is owed, or until the deadline passes.
    ///
    /// The deadline is what makes it safe to call from a teardown: a callback
    /// whose server never answers may not keep a process that was asked to stop
    /// alive, so the wait ends either way and the caller carries on.
    pub fn settle(&self, deadline: Instant) {
        let owed = self.lock();
        if *owed == 0 {
            return;
        }
        let _held = self
            .settled
            .wait_timeout_while(
                owed,
                deadline.saturating_duration_since(Instant::now()),
                |owed| *owed > 0,
            )
            .unwrap_or_else(|poison| poison.into_inner());
    }

    /// Whether the kernel is owed nothing right now.
    #[must_use]
    pub fn is_settled(&self) -> bool {
        *self.lock() == 0
    }

    /// Takes on one callback, until the ticket it hands back is dropped.
    fn owe(self: &Arc<Self>) -> Ticket {
        *self.lock() += 1;
        Ticket {
            owed: Arc::clone(self),
        }
    }

    fn lock(&self) -> MutexGuard<'_, usize> {
        self.owed
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }
}

/// One callback's place in [`InFlight`], given up when it is dropped.
///
/// Dropping is the whole mechanism, so that a callback whose task is dropped
/// instead of finished — which is what a runtime being released does to it —
/// stops being counted as owed just the same.
#[derive(Debug)]
struct Ticket {
    owed: Arc<InFlight>,
}

impl Drop for Ticket {
    fn drop(&mut self) {
        let mut owed = self.owed.lock();
        *owed = owed.saturating_sub(1);
        if *owed == 0 {
            self.owed.settled.notify_all();
        }
    }
}

/// A mounted voidport namespace, as the kernel sees it.
#[derive(Debug)]
pub struct VoidportFs {
    client: Arc<Client>,
    runtime: tokio::runtime::Handle,
    attr_ttl: Duration,
    entry_ttl: Duration,
    /// What the mount asked for with `--direct-io`.
    direct_io: bool,
    /// Whether this mount shows privileged mode bits at all — the client-side
    /// switch `--no-privileged-bits` sets. Read by every attribute this
    /// adapter hands the kernel, and by the one callback that can change them.
    privileged: Privileged,
    /// What [`direct_io`](Self::direct_io) resolved to once the kernel answered
    /// the handshake. Written by `init` and read by every open thereafter.
    caching: DataCaching,
    /// The mount's readahead engine.
    ///
    /// Dormant until `init` tells it what the handshake settled on: it runs
    /// **only** where the negotiated mode is [`DataCaching::Direct`], because
    /// that is the mode with no kernel readahead in front of it. Shared,
    /// because the callbacks take `&self` and a mount may run several dispatch
    /// loops, and mutated only through its lock.
    readahead: Arc<Readahead>,
    /// The callbacks this adapter has taken and not yet replied to. Held here
    /// as well as by the mount, which is what waits on it when it tears down.
    inflight: Arc<InFlight>,
}

impl VoidportFs {
    /// Builds the adapter over an established session.
    ///
    /// `direct_io` is a *request*: whether it is honoured is decided in `init`,
    /// against the kernel's capabilities, and until then the mount caches the
    /// way every mount always has. `readahead` is the mount's prefetch engine,
    /// which `init` activates on the same answer. `inflight` is where the
    /// callbacks the kernel is owed a reply for are counted, for the teardown
    /// that has to wait them out.
    #[must_use]
    #[allow(
        clippy::too_many_arguments,
        reason = "the adapter is the mount's whole configuration; a struct around it would be the same list under another name"
    )]
    pub fn new(
        client: Arc<Client>,
        runtime: tokio::runtime::Handle,
        attr_ttl: Duration,
        entry_ttl: Duration,
        direct_io: bool,
        privileged: Privileged,
        readahead: Arc<Readahead>,
        inflight: Arc<InFlight>,
    ) -> Self {
        Self {
            client,
            runtime,
            attr_ttl,
            entry_ttl,
            direct_io,
            privileged,
            caching: DataCaching::Page,
            readahead,
            inflight,
        }
    }

    /// How this mount caches file data, as the handshake settled it.
    #[must_use]
    pub fn caching(&self) -> DataCaching {
        self.caching
    }

    /// The session this mount is served by.
    #[must_use]
    pub fn client(&self) -> Arc<Client> {
        Arc::clone(&self.client)
    }

    /// Hands one callback's work to the runtime.
    ///
    /// The callback is counted as owed from here — before the dispatch loop is
    /// let go, so there is no instant where the kernel has handed over a
    /// request that nothing accounts for — until the work is finished or
    /// dropped.
    fn spawn(&self, work: impl Future<Output = ()> + Send + 'static) {
        let owed = self.inflight.owe();
        self.runtime.spawn(async move {
            work.await;
            drop(owed);
        });
    }
}

impl fuser::Filesystem for VoidportFs {
    /// Negotiates the three capabilities the contract requires.
    ///
    /// Each is load-bearing, and each is absent from fuser's defaults:
    /// without `FUSE_DO_READDIRPLUS` the kernel sends plain readdir, for which
    /// it does no `nlookup` accounting; without `FUSE_POSIX_LOCKS` it satisfies
    /// record locks guest-locally and the server never sees them, so a
    /// cross-mount conflict is unobservable; without `FUSE_AUTO_INVAL_DATA` a
    /// same-size overwrite from elsewhere stays invisible to a held-open
    /// descriptor indefinitely instead of being bounded by the attr TTL.
    /// A kernel that cannot offer them cannot keep the guarantees this
    /// filesystem makes, so the mount fails instead of quietly weakening.
    ///
    /// `FUSE_FLOCK_LOCKS` is deliberately not negotiated: fuser drops the
    /// kernel's `lk_flags` and the wire `FileLock` has no lock-namespace field,
    /// so routing `flock(2)` to the server would conflate it with record locks.
    /// `flock` therefore stays guest-local per mount in v1.
    ///
    /// A fourth capability is negotiated only for `--direct-io`, and its absence
    /// is not fatal: see [`DataCaching::resolve`].
    fn init(&mut self, _request: &Request, config: &mut KernelConfig) -> std::io::Result<()> {
        use fuser::InitFlags;

        let required = InitFlags::FUSE_DO_READDIRPLUS
            | InitFlags::FUSE_POSIX_LOCKS
            | InitFlags::FUSE_AUTO_INVAL_DATA;
        config.add_capabilities(required).map_err(|missing| {
            std::io::Error::other(format!(
                "the kernel does not support {missing:?}, which voidport requires"
            ))
        })?;

        // This is the whole of the capability detection: `add_capabilities`
        // fails exactly when the kernel did not advertise the flag in its INIT
        // request, so the answer is the kernel's own, not a guess from
        // its version. It is asked for only when the mount wants direct I/O,
        // because a capability nobody uses should not appear in the reply.
        let mmap_under_direct_io = self.direct_io
            && config
                .add_capabilities(InitFlags::FUSE_DIRECT_IO_ALLOW_MMAP)
                .is_ok();
        self.caching = DataCaching::resolve(self.direct_io, mmap_under_direct_io);
        // The engine keys on the mode that was *resolved*, never on what
        // `--direct-io` asked for: a kernel without the mmap capability keeps
        // the flag and falls back to page caching, and prefetching underneath
        // the kernel's own readahead would buffer the same bytes twice.
        self.readahead.activate(self.caching == DataCaching::Direct);

        // A write has to fit one frame, so the kernel is told how much it may
        // send before it sends it.
        let budget = self.client.write_chunk();
        if let Err(nearest) = config.set_max_write(budget) {
            config.set_max_write(nearest).map_err(|_| {
                std::io::Error::other("the kernel accepts no usable maximum write size")
            })?;
        }
        Ok(())
    }

    fn lookup(&self, request: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        let (client, caller) = (self.client(), caller_of(request));
        let privileged = self.privileged;
        let (attr_ttl, entry_ttl) = (self.attr_ttl, self.entry_ttl);
        let name = name.as_bytes().to_vec();
        self.spawn(async move {
            match client.lookup(caller, parent.0, &name).await {
                Ok(entry) => reply.entry_with_ttls(
                    &attr_ttl,
                    &entry_ttl,
                    &entry_attr(&entry, privileged),
                    Generation(entry.generation),
                ),
                Err(error) => reply.error(errno(error)),
            }
        });
    }

    fn forget(&self, request: &Request, ino: INodeNo, nlookup: u64) {
        let (client, caller) = (self.client(), caller_of(request));
        self.spawn(async move {
            client.forget(caller, ino.0, nlookup).await;
        });
    }

    // `batch_forget` is deliberately not overridden. The wire has no batch
    // form, so a batch must become one FORGET per element — which is exactly
    // what fuser's default does by calling `forget` for each of them. Writing
    // it out here is impossible anyway: the element type is unnameable outside
    // fuser 0.18, which does not re-export it.

    fn getattr(&self, request: &Request, ino: INodeNo, fh: Option<FileHandle>, reply: ReplyAttr) {
        let (client, caller, ttl) = (self.client(), caller_of(request), self.attr_ttl);
        let privileged = self.privileged;
        self.spawn(async move {
            match client.getattr(caller, ino.0, fh.map(|fh| fh.0)).await {
                Ok(attr) => reply.attr(&ttl, &node_attr(ino.0, &attr, privileged)),
                Err(error) => reply.error(errno(error)),
            }
        });
    }

    #[allow(clippy::too_many_arguments, reason = "the callback's shape is fuser's")]
    fn setattr(
        &self,
        request: &Request,
        ino: INodeNo,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        ctime: Option<SystemTime>,
        fh: Option<FileHandle>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<BsdFileFlags>,
        reply: ReplyAttr,
    ) {
        let (client, caller, ttl) = (self.client(), caller_of(request), self.attr_ttl);
        let privileged = self.privileged;
        let change = AttrChange {
            mode,
            uid,
            gid,
            size,
            atime: atime.map(time_change),
            mtime: mtime.map(time_change),
            ctime: ctime.map(timespec),
            handle: fh.map(|fh| fh.0),
        };
        // A change of size or mtime is a change of the file's *data* — a
        // truncate is exactly that — so the prefetched blocks go with it. A
        // chmod or a chown is not, and leaves them alone.
        let readahead = Arc::clone(&self.readahead);
        let changes_data = size.is_some() || mtime.is_some();
        if changes_data {
            readahead.invalidate(ino.0);
        }
        // A mount that shows no privileged bits takes none either — the same
        // refusal the server makes for a namespace whose switch is off.
        if privileged.is_masked() && mode.is_some_and(|mode| mode & PRIVILEGED_MASK != 0) {
            return reply.error(Errno::EPERM);
        }
        self.spawn(async move {
            let change = match preserve_privileged(&client, caller, ino.0, change, privileged).await
            {
                Ok(change) => change,
                Err(error) => return reply.error(errno(error)),
            };
            let settled = client.setattr(caller, ino.0, change).await;
            if changes_data {
                readahead.invalidate(ino.0);
            }
            match settled {
                Ok(attr) => reply.attr(&ttl, &node_attr(ino.0, &attr, privileged)),
                Err(error) => reply.error(errno(error)),
            }
        });
    }

    fn readlink(&self, request: &Request, ino: INodeNo, reply: ReplyData) {
        let (client, caller) = (self.client(), caller_of(request));
        self.spawn(async move {
            match client.readlink(caller, ino.0).await {
                Ok(target) => reply.data(&target),
                Err(error) => reply.error(errno(error)),
            }
        });
    }

    /// Creates a FIFO or a socket file; refuses everything else.
    ///
    /// The two kinds are real host inodes an unprivileged server can make, and
    /// they are all this callback serves. A **device node is refused here**,
    /// before the wire, so `mknod /dev/…` costs no round trip and cannot depend
    /// on the server's posture; the server refuses it again on its own side.
    ///
    /// **The host inode is a marker.** Once this reply says `S_IFIFO`, the guest
    /// kernel installs its own pipe operations and no open, read or write for it
    /// ever reaches the server, so pipe data and `AF_UNIX` rendezvous live in
    /// *this* guest's kernel — never crossing to another guest or to a host-side
    /// peer, however much the two share the host inode.
    ///
    /// A server too old to know the opcode answers `ENOSYS`; that is turned back
    /// into `EPERM` here, so `mkfifo` against such a server fails the same clean
    /// way it did before the opcode existed instead of claiming the syscall is
    /// unimplemented.
    fn mknod(
        &self,
        request: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
        rdev: u32,
        reply: ReplyEntry,
    ) {
        if !is_special_file(mode) {
            reply.error(Errno::EPERM);
            return;
        }
        let (client, caller) = (self.client(), caller_of(request));
        let privileged = self.privileged;
        let (attr_ttl, entry_ttl) = (self.attr_ttl, self.entry_ttl);
        let name = name.as_bytes().to_vec();
        self.spawn(async move {
            match client
                .mknod(caller, parent.0, &name, mode, umask, rdev)
                .await
            {
                Ok(entry) => reply.entry_with_ttls(
                    &attr_ttl,
                    &entry_ttl,
                    &entry_attr(&entry, privileged),
                    Generation(entry.generation),
                ),
                Err(error) => reply.error(mknod_errno(error)),
            }
        });
    }

    fn mkdir(
        &self,
        request: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
        reply: ReplyEntry,
    ) {
        let (client, caller) = (self.client(), caller_of(request));
        let privileged = self.privileged;
        let (attr_ttl, entry_ttl) = (self.attr_ttl, self.entry_ttl);
        let name = name.as_bytes().to_vec();
        self.spawn(async move {
            match client.mkdir(caller, parent.0, &name, mode, umask).await {
                Ok(entry) => reply.entry_with_ttls(
                    &attr_ttl,
                    &entry_ttl,
                    &entry_attr(&entry, privileged),
                    Generation(entry.generation),
                ),
                Err(error) => reply.error(errno(error)),
            }
        });
    }

    fn unlink(&self, request: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        let (client, caller) = (self.client(), caller_of(request));
        let name = name.as_bytes().to_vec();
        self.spawn(async move {
            answer(reply, client.unlink(caller, parent.0, &name).await);
        });
    }

    fn rmdir(&self, request: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        let (client, caller) = (self.client(), caller_of(request));
        let name = name.as_bytes().to_vec();
        self.spawn(async move {
            answer(reply, client.rmdir(caller, parent.0, &name).await);
        });
    }

    fn symlink(
        &self,
        request: &Request,
        parent: INodeNo,
        link_name: &OsStr,
        target: &Path,
        reply: ReplyEntry,
    ) {
        let (client, caller) = (self.client(), caller_of(request));
        let privileged = self.privileged;
        let (attr_ttl, entry_ttl) = (self.attr_ttl, self.entry_ttl);
        let name = link_name.as_bytes().to_vec();
        let target = target.as_os_str().as_bytes().to_vec();
        self.spawn(async move {
            match client.symlink(caller, parent.0, &name, &target).await {
                Ok(entry) => reply.entry_with_ttls(
                    &attr_ttl,
                    &entry_ttl,
                    &entry_attr(&entry, privileged),
                    Generation(entry.generation),
                ),
                Err(error) => reply.error(errno(error)),
            }
        });
    }

    fn rename(
        &self,
        request: &Request,
        parent: INodeNo,
        name: &OsStr,
        newparent: INodeNo,
        newname: &OsStr,
        flags: RenameFlags,
        reply: ReplyEmpty,
    ) {
        let (client, caller) = (self.client(), caller_of(request));
        let name = name.as_bytes().to_vec();
        let newname = newname.as_bytes().to_vec();
        let flags = wire_rename_flags(flags);
        self.spawn(async move {
            answer(
                reply,
                client
                    .rename(caller, parent.0, &name, newparent.0, &newname, flags)
                    .await,
            );
        });
    }

    fn link(
        &self,
        request: &Request,
        ino: INodeNo,
        newparent: INodeNo,
        newname: &OsStr,
        reply: ReplyEntry,
    ) {
        let (client, caller) = (self.client(), caller_of(request));
        let privileged = self.privileged;
        let (attr_ttl, entry_ttl) = (self.attr_ttl, self.entry_ttl);
        let name = newname.as_bytes().to_vec();
        self.spawn(async move {
            match client.link(caller, ino.0, newparent.0, &name).await {
                Ok(entry) => reply.entry_with_ttls(
                    &attr_ttl,
                    &entry_ttl,
                    &entry_attr(&entry, privileged),
                    Generation(entry.generation),
                ),
                Err(error) => reply.error(errno(error)),
            }
        });
    }

    /// Opens a file, forwarding the guest's flags verbatim.
    ///
    /// Verbatim is deliberate and this is the client end of the atomic-append
    /// path: the server decides which flags a reopen may honour, and the one
    /// that matters most — `O_APPEND` — only reaches the host descriptor
    /// because nothing here filters it out first. Interpreting flags on this
    /// side would put the decision in two places.
    ///
    /// The reply's flags are the mount's [`DataCaching`] mode, which is what
    /// `--direct-io` reaches the kernel through.
    fn open(&self, request: &Request, ino: INodeNo, flags: OpenFlags, reply: ReplyOpen) {
        let (client, caller) = (self.client(), caller_of(request));
        let fopen = self.caching.fopen_flags();
        self.spawn(async move {
            match client.open(caller, ino.0, flags.0 as u32).await {
                Ok(handle) => reply.opened(FileHandle(handle), fopen),
                Err(error) => reply.error(errno(error)),
            }
        });
    }

    /// Reads, through the mount's readahead engine.
    ///
    /// The engine answers from its pool where it has the bytes and from the
    /// wire where it does not, looping until the kernel's request is satisfied:
    /// a wire read is bounded by the negotiated frame length, and a short FUSE
    /// read means end of file, so the difference is made up there, not
    /// handed to the kernel as zeroes. On a page-cached mount — and under
    /// `--readahead 0` — the engine holds nothing and this is exactly the wire
    /// read it always was.
    fn read(
        &self,
        request: &Request,
        ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyData,
    ) {
        let (client, caller) = (self.client(), caller_of(request));
        let readahead = Arc::clone(&self.readahead);
        self.spawn(async move {
            match readahead
                .read(&client, caller, ino.0, fh.0, offset, size)
                .await
            {
                Ok(data) => reply.data(data.as_slice()),
                Err(error) => reply.error(errno(error)),
            }
        });
    }

    /// Writes, looping until the whole buffer is placed.
    ///
    /// The kernel is told a maximum write that fits one frame, so this is one
    /// round trip in practice; a short host write is still finished here, not
    /// reported as a short write to the guest.
    ///
    /// Each wire write is nonetheless sliced to the budget of the connection
    /// serving it *now*, exactly as the read path is. `max_write` is negotiated
    /// once, during the initial handshake, and the kernel keeps sending that
    /// much for the life of the mount — but a reconnect can install a
    /// replacement session with a smaller legal frame bound, and an unsliced
    /// write would then exceed it on every attempt and fail for ever instead of
    /// resuming.
    ///
    /// On a handle the guest opened `O_APPEND` the offset is advisory — the
    /// host places the data at the end of the file — and the slices of one
    /// guest write still arrive in order, because each is awaited before the
    /// next is sent.
    ///
    /// The kernel's suid-kill mark rides **every** slice, not the first: the
    /// server's strip is idempotent, and a mark carried on one chunk of a write
    /// the kernel split would leave the rest of the write unstripped if a
    /// reconnect resumed in the middle of it.
    ///
    /// A local write drops the file's prefetched blocks, before and after: the
    /// first bump discards prefetch replies that were read before the write and
    /// arrive after it, and the second drops anything fetched while the write
    /// was in flight. Both are the same one-line invalidation, and together
    /// they leave no window in which a pre-write byte can be served.
    fn write(
        &self,
        request: &Request,
        ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        data: &[u8],
        write_flags: WriteFlags,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyWrite,
    ) {
        let (client, caller) = (self.client(), caller_of(request));
        // The kernel's own delegation, forwarded verbatim: it marks a direct-io
        // write by a caller without the file-mode privilege, and the server
        // strips per the mode-only local rule. Nothing is negotiated for it, so
        // none of the kernel's own stripping is turned off — this is the one
        // case the kernel cannot do itself, because the bits are recorded on
        // the server and its host backing does not carry them.
        let strip = write_flags.contains(WriteFlags::FUSE_WRITE_KILL_SUIDGID);
        let data = data.to_vec();
        let readahead = Arc::clone(&self.readahead);
        readahead.invalidate(ino.0);
        self.spawn(async move {
            let mut written = 0usize;
            while written < data.len() {
                // Read per attempt, not once: the budget belongs to whichever
                // connection is installed when this slice goes out.
                let chunk = client.write_chunk() as usize;
                let end = data.len().min(written.saturating_add(chunk.max(1)));
                match client
                    .write(
                        caller,
                        ino.0,
                        fh.0,
                        offset + written as u64,
                        &data[written..end],
                        strip,
                    )
                    .await
                {
                    Ok(0) => break,
                    Ok(count) => written += count as usize,
                    Err(error) => {
                        readahead.invalidate(ino.0);
                        return reply.error(errno(error));
                    }
                }
            }
            readahead.invalidate(ino.0);
            reply.written(u32::try_from(written).unwrap_or(u32::MAX));
        });
    }

    fn flush(
        &self,
        request: &Request,
        ino: INodeNo,
        fh: FileHandle,
        lock_owner: LockOwner,
        reply: ReplyEmpty,
    ) {
        let (client, caller) = (self.client(), caller_of(request));
        self.spawn(async move {
            answer(reply, client.flush(caller, ino.0, fh.0, lock_owner.0).await);
        });
    }

    /// Releases a handle, and with it whatever the engine was reading ahead for
    /// it.
    ///
    /// Closing is where cancellation is honest: the window closes and the
    /// blocks are freed at once, while chunks already on the wire still cross
    /// it — bounded by the in-flight cap — and are discarded when they land.
    fn release(
        &self,
        request: &Request,
        ino: INodeNo,
        fh: FileHandle,
        flags: OpenFlags,
        lock_owner: Option<LockOwner>,
        flush: bool,
        reply: ReplyEmpty,
    ) {
        let (client, caller) = (self.client(), caller_of(request));
        self.readahead.close(fh.0);
        self.spawn(async move {
            answer(
                reply,
                client
                    .release(
                        caller,
                        ino.0,
                        fh.0,
                        flags.0 as u32,
                        lock_owner.map(|owner| owner.0),
                        flush,
                    )
                    .await,
            );
        });
    }

    fn fsync(
        &self,
        request: &Request,
        ino: INodeNo,
        fh: FileHandle,
        datasync: bool,
        reply: ReplyEmpty,
    ) {
        let (client, caller) = (self.client(), caller_of(request));
        self.spawn(async move {
            answer(reply, client.fsync(caller, ino.0, fh.0, datasync).await);
        });
    }

    /// A directory open is the generic open: the handle it returns is the
    /// directory handle, and the server materializes the listing behind it.
    ///
    /// No [`DataCaching`] flags here, in either mode: `--direct-io` is about
    /// **file data**, and a directory handle carries none — its listing is
    /// served by `readdir`/`readdirplus`, which never read through the page
    /// cache. `FOPEN_CACHE_DIR` is a separate flag and is not set either.
    fn opendir(&self, request: &Request, ino: INodeNo, flags: OpenFlags, reply: ReplyOpen) {
        let (client, caller) = (self.client(), caller_of(request));
        self.spawn(async move {
            match client.open(caller, ino.0, flags.0 as u32).await {
                Ok(handle) => reply.opened(FileHandle(handle), FopenFlags::empty()),
                Err(error) => reply.error(errno(error)),
            }
        });
    }

    /// Plain readdir, served from wire readdirplus.
    ///
    /// The kernel does no `nlookup` accounting for this call, so every entry
    /// returned is given straight back with a compensating `forget`. Once
    /// `FUSE_DO_READDIRPLUS` is negotiated the kernel does not take this path;
    /// it exists so that a kernel which does cannot leak server nodes.
    fn readdir(
        &self,
        request: &Request,
        ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        reply: ReplyDirectory,
    ) {
        let (client, caller) = (self.client(), caller_of(request));
        let privileged = self.privileged;
        self.spawn(async move {
            let mut sink = PlainSink { reply };
            match read_directory(
                &client,
                caller,
                DirectoryRead {
                    node_id: ino.0,
                    handle: fh.0,
                    cookie: offset,
                },
                privileged,
                &mut sink,
            )
            .await
            {
                Ok(()) => sink.reply.ok(),
                Err(error) => sink.reply.error(error),
            }
        });
    }

    fn readdirplus(
        &self,
        request: &Request,
        ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        reply: ReplyDirectoryPlus,
    ) {
        let (client, caller, ttl) = (self.client(), caller_of(request), self.entry_ttl);
        let privileged = self.privileged;
        self.spawn(async move {
            let mut sink = PlusSink { reply, ttl };
            match read_directory(
                &client,
                caller,
                DirectoryRead {
                    node_id: ino.0,
                    handle: fh.0,
                    cookie: offset,
                },
                privileged,
                &mut sink,
            )
            .await
            {
                Ok(()) => sink.reply.ok(),
                Err(error) => sink.reply.error(error),
            }
        });
    }

    fn releasedir(
        &self,
        request: &Request,
        ino: INodeNo,
        fh: FileHandle,
        flags: OpenFlags,
        reply: ReplyEmpty,
    ) {
        let (client, caller) = (self.client(), caller_of(request));
        self.spawn(async move {
            answer(
                reply,
                client
                    .release(caller, ino.0, fh.0, flags.0 as u32, None, false)
                    .await,
            );
        });
    }

    fn fsyncdir(
        &self,
        request: &Request,
        ino: INodeNo,
        fh: FileHandle,
        datasync: bool,
        reply: ReplyEmpty,
    ) {
        let (client, caller) = (self.client(), caller_of(request));
        self.spawn(async move {
            answer(reply, client.fsync(caller, ino.0, fh.0, datasync).await);
        });
    }

    fn statfs(&self, request: &Request, ino: INodeNo, reply: ReplyStatfs) {
        let (client, caller) = (self.client(), caller_of(request));
        self.spawn(async move {
            match client.statfs(caller, ino.0).await {
                Ok(stat) => reply.statfs(
                    stat.blocks.get(),
                    stat.bfree.get(),
                    stat.bavail.get(),
                    stat.files.get(),
                    stat.ffree.get(),
                    stat.bsize.get(),
                    stat.namelen.get(),
                    stat.frsize.get(),
                ),
                Err(error) => reply.error(errno(error)),
            }
        });
    }

    fn setxattr(
        &self,
        request: &Request,
        ino: INodeNo,
        name: &OsStr,
        value: &[u8],
        flags: i32,
        _position: u32,
        reply: ReplyEmpty,
    ) {
        let (client, caller) = (self.client(), caller_of(request));
        let name = name.as_bytes().to_vec();
        let value = value.to_vec();
        let flags = wire_xattr_flags(flags);
        self.spawn(async move {
            answer(
                reply,
                client.setxattr(caller, ino.0, &name, &value, flags).await,
            );
        });
    }

    fn getxattr(
        &self,
        request: &Request,
        ino: INodeNo,
        name: &OsStr,
        size: u32,
        reply: ReplyXattr,
    ) {
        let (client, caller) = (self.client(), caller_of(request));
        let name = name.as_bytes().to_vec();
        self.spawn(async move {
            match client.getxattr(caller, ino.0, &name, size).await {
                Ok(value) if size == 0 => reply.size(value.size),
                Ok(value) => reply.data(&value.value),
                Err(error) => reply.error(errno(error)),
            }
        });
    }

    /// Lists attribute names, rebuilding the kernel's NUL-separated list.
    ///
    /// The wire carries a name stream and sizes the answer in *guest* bytes —
    /// the length of the list built here — so `ERANGE` is decided by the server
    /// against the same number the kernel compares against.
    fn listxattr(&self, request: &Request, ino: INodeNo, size: u32, reply: ReplyXattr) {
        let (client, caller) = (self.client(), caller_of(request));
        self.spawn(async move {
            match client.listxattr(caller, ino.0, size).await {
                Ok(names) if size == 0 => reply.size(names.size),
                Ok(names) => reply.data(&names.to_kernel_list()),
                Err(error) => reply.error(errno(error)),
            }
        });
    }

    fn removexattr(&self, request: &Request, ino: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        let (client, caller) = (self.client(), caller_of(request));
        let name = name.as_bytes().to_vec();
        self.spawn(async move {
            answer(reply, client.removexattr(caller, ino.0, &name).await);
        });
    }

    /// Creates and opens in one call.
    ///
    /// The entry timeout governs both validities here: fuser 0.18's
    /// `ReplyCreate` has no split-TTL form, so the attribute validity of a
    /// created entry cannot be set independently. Both default to one second,
    /// so only a mount that separates the two flags can tell.
    ///
    /// Its open half carries the same [`DataCaching`] flags `open` does: a file
    /// that was created instead of opened is opened all the same, and a mode
    /// that applied to only one of the two would cache the data of every
    /// freshly created file.
    fn create(
        &self,
        request: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
        flags: i32,
        reply: ReplyCreate,
    ) {
        let (client, caller, ttl) = (self.client(), caller_of(request), self.entry_ttl);
        let privileged = self.privileged;
        let name = name.as_bytes().to_vec();
        let fopen = self.caching.fopen_flags();
        self.spawn(async move {
            match client
                .create(caller, parent.0, &name, flags as u32, mode, umask)
                .await
            {
                Ok((entry, handle)) => reply.created(
                    &ttl,
                    &entry_attr(&entry, privileged),
                    Generation(entry.generation),
                    FileHandle(handle),
                    fopen,
                ),
                Err(error) => reply.error(errno(error)),
            }
        });
    }

    /// Tests a record lock.
    ///
    /// The kernel resolves the conflicting pid through its own pid namespace
    /// and finds nothing there — an OFD lock on the host has no owning process
    /// — so a guest sees a conflict pid of 0. The conflict itself is what the
    /// answer is for.
    #[allow(clippy::too_many_arguments, reason = "the callback's shape is fuser's")]
    fn getlk(
        &self,
        request: &Request,
        ino: INodeNo,
        fh: FileHandle,
        lock_owner: LockOwner,
        start: u64,
        end: u64,
        typ: i32,
        pid: u32,
        reply: ReplyLock,
    ) {
        let (client, caller) = (self.client(), caller_of(request));
        let Some(kind) = LockKind::from_raw(typ) else {
            return reply.error(Errno::EINVAL);
        };
        let lock = Lock {
            start,
            end,
            owner: lock_owner.0,
            pid,
            kind,
        };
        self.spawn(async move {
            match client.getlk(caller, ino.0, fh.0, lock).await {
                Ok(conflict) => reply.locked(
                    conflict.start,
                    conflict.end,
                    conflict.kind.as_raw(),
                    conflict.pid,
                ),
                Err(error) => reply.error(errno(error)),
            }
        });
    }

    /// Places or releases a record lock, waiting where the guest asked to.
    ///
    /// A waiting lock parks on the server until the range frees; because this
    /// callback returns immediately and waits on the runtime, the mount keeps
    /// serving everything else meanwhile.
    #[allow(clippy::too_many_arguments, reason = "the callback's shape is fuser's")]
    fn setlk(
        &self,
        request: &Request,
        ino: INodeNo,
        fh: FileHandle,
        lock_owner: LockOwner,
        start: u64,
        end: u64,
        typ: i32,
        pid: u32,
        sleep: bool,
        reply: ReplyEmpty,
    ) {
        let (client, caller) = (self.client(), caller_of(request));
        let Some(kind) = LockKind::from_raw(typ) else {
            return reply.error(Errno::EINVAL);
        };
        let lock = Lock {
            start,
            end,
            owner: lock_owner.0,
            pid,
            kind,
        };
        self.spawn(async move {
            answer(reply, client.setlk(caller, ino.0, fh.0, lock, sleep).await);
        });
    }

    /// Reports readiness, which for these nodes is unconditional.
    ///
    /// A namespace holds regular files, directories and symlinks, and only the
    /// first two are ever open — so every pollable node here is one whose data
    /// is available now and whose writes never block, exactly like a regular
    /// file on the host. That is the standard always-ready answer: the ready
    /// set is the requested set, narrowed to the events such a node can
    /// actually report.
    ///
    /// No notification is ever owed. `FUSE_POLL_SCHEDULE_NOTIFY` asks the
    /// filesystem to register the kernel's poll handle and wake it when the
    /// node *becomes* ready; a node that is ready in the reply has nothing to
    /// wake anybody for, so the handle is dropped. Nothing here waits, so this
    /// replies on the dispatch loop, not through the runtime.
    fn poll(
        &self,
        _request: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _ph: PollNotifier,
        events: PollEvents,
        _flags: PollFlags,
        reply: ReplyPoll,
    ) {
        reply.poll(events.intersection(ALWAYS_READY));
    }

    /// Refused, knowingly: the observed ioctl is a terminal query, and no
    /// namespace node is a terminal.
    ///
    /// The first real workload through a mount issued command `2150388778` =
    /// `0x802C542A` on files it had opened — `_IOR('T', 0x2A, struct
    /// termios2)`, which is `TCGETS2`, the terminal-attribute query modern
    /// `tcgetattr(3)`/`isatty(3)` implementations issue. The host filesystem
    /// answers it with `ENOTTY` (verified by probe on a regular file and on a
    /// directory), because a regular file has no terminal attributes; so does
    /// this, for every ioctl of the terminal type. It is not proxyable and
    /// there is nothing to proxy: the wire has no ioctl operation, and passing
    /// it to the host would produce the same `ENOTTY` after a round trip.
    ///
    /// Any other command keeps the unmapped answer, warning and all: an ioctl
    /// nobody has identified is exactly the kind of gap the warnings exist to
    /// surface. That `ENOSYS` is also what keeps the warning from ever
    /// flooding — the kernel's fuse layer answers it by marking the connection
    /// as having no ioctls at all, translating it to `ENOTTY` for the caller
    /// and never asking again — which is precisely why the identified command
    /// is answered here instead: `ENOSYS` would trade one honest refusal for a
    /// blanket one covering every ioctl this filesystem might later implement.
    fn ioctl(
        &self,
        _request: &Request,
        ino: INodeNo,
        fh: FileHandle,
        flags: IoctlFlags,
        cmd: u32,
        in_data: &[u8],
        out_size: u32,
        reply: ReplyIoctl,
    ) {
        if ioctl_type(cmd) == TERMINAL_IOCTL {
            return reply.error(Errno::ENOTTY);
        }
        tracing::warn!(
            ino = ino.0,
            fh = fh.0,
            %flags,
            cmd = format_args!("{cmd:#x}"),
            in_data = in_data.len(),
            out_size,
            "unimplemented ioctl"
        );
        reply.error(Errno::ENOSYS);
    }
}

/// What a node that is always ready may report: data to read, room to write,
/// and the two `*NORM` spellings of the same, which `poll(2)` reports beside
/// them. `POLLERR`, `POLLHUP` and `POLLPRI` are conditions these nodes never
/// have, and are never invented here.
const ALWAYS_READY: PollEvents = PollEvents::POLLIN
    .union(PollEvents::POLLOUT)
    .union(PollEvents::POLLRDNORM)
    .union(PollEvents::POLLWRNORM);

/// The `_IOC_TYPE` of the terminal ioctls (`'T'`), which every `TC*` command
/// and the `TIOC*` family share.
const TERMINAL_IOCTL: u32 = b'T' as u32;

/// The type field of an ioctl command number, in the Linux encoding: direction,
/// size, type, number — the type is the third byte.
const fn ioctl_type(cmd: u32) -> u32 {
    (cmd >> 8) & 0xff
}

/// Answers a callback that has nothing to return but success.
fn answer(reply: ReplyEmpty, outcome: Result<(), rustix::io::Errno>) {
    match outcome {
        Ok(()) => reply.ok(),
        Err(error) => reply.error(errno(error)),
    }
}

/// The identity of one FUSE request.
///
/// This is the whole of the kernel-to-wire identity translation, and it belongs
/// here, not in the client: the client layer speaks the wire and knows
/// nothing about fuser.
fn caller_of(request: &Request) -> Caller {
    Caller {
        uid: request.uid(),
        gid: request.gid(),
        pid: request.pid(),
    }
}

/// A POSIX errno as a kernel reply wants it.
/// Keeps a chmod through a masked mount from destroying recorded privileged
/// bits.
///
/// The server takes a delivered mode's privileged bits as the record's new
/// value — present record, absent delete — and a mount that opted out was shown
/// a mode without them, so a read-modify-write chmod from it would clear what
/// other mounts still present. Putting the bits the server currently holds back
/// into the mode makes the assignment a no-op instead: nothing is recorded and
/// nothing is deleted, which is exactly what a masked presentation owes.
///
/// The cost is one extra round trip, on a chmod, on a mount that opted out —
/// and nothing at all on every other mount and every other operation.
async fn preserve_privileged(
    client: &Client,
    caller: Caller,
    node_id: u64,
    change: AttrChange,
    privileged: Privileged,
) -> Result<AttrChange, rustix::io::Errno> {
    let (Privileged::Masked, Some(mode)) = (privileged, change.mode) else {
        return Ok(change);
    };
    let held = client.getattr(caller, node_id, None).await?;
    Ok(AttrChange {
        mode: Some(mode | (held.mode.get() & PRIVILEGED_MASK)),
        ..change
    })
}

pub(crate) fn errno(error: rustix::io::Errno) -> Errno {
    Errno::from_i32(error.raw_os_error())
}

/// The errno a failed `mknod` reaches the guest as.
///
/// One translation, and it is the design's: a server too old to know the opcode
/// answers `ENOSYS`, and the guest is told `EPERM` — the refusal this callback
/// gave before the opcode existed. Reporting `ENOSYS` instead would tell a
/// `mkfifo` that its *syscall* is unimplemented, which is a claim about the
/// guest kernel, not about this mount.
fn mknod_errno(error: rustix::io::Errno) -> Errno {
    match error {
        rustix::io::Errno::NOSYS => Errno::EPERM,
        other => errno(other),
    }
}

/// Whether a `mknod` mode asks for one of the two kinds the wire serves.
///
/// A FIFO or a socket file; a device node, and anything else the file-type bits
/// can spell, is not one and is refused without a round trip.
fn is_special_file(mode: u32) -> bool {
    matches!(
        rustix::fs::FileType::from_raw_mode(mode),
        rustix::fs::FileType::Fifo | rustix::fs::FileType::Socket
    )
}

/// The wire rename flags a kernel request asks for.
fn wire_rename_flags(flags: RenameFlags) -> u32 {
    let mut wire = 0;
    if flags.contains(RenameFlags::RENAME_NOREPLACE) {
        wire |= rename_flags::NOREPLACE;
    }
    if flags.contains(RenameFlags::RENAME_EXCHANGE) {
        wire |= rename_flags::EXCHANGE;
    }
    if flags.contains(RenameFlags::RENAME_WHITEOUT) {
        wire |= rename_flags::WHITEOUT;
    }
    wire
}

/// The wire setxattr flags a kernel request asks for.
fn wire_xattr_flags(flags: i32) -> u32 {
    let mut wire = 0;
    if flags & libc_xattr::CREATE != 0 {
        wire |= setxattr_flags::CREATE;
    }
    if flags & libc_xattr::REPLACE != 0 {
        wire |= setxattr_flags::REPLACE;
    }
    wire
}

/// The Linux `XATTR_*` flag values, which the kernel passes through verbatim.
mod libc_xattr {
    /// `XATTR_CREATE`.
    pub const CREATE: i32 = 1;
    /// `XATTR_REPLACE`.
    pub const REPLACE: i32 = 2;
}

/// Delivers entries to a `readdirplus` reply.
///
/// One TTL, not two: fuser 0.18's `ReplyDirectoryPlus::add` writes a single
/// duration into both the entry and the attribute validity of every entry, so a
/// listed entry's attributes are cached for the entry timeout. The entry
/// timeout is the one passed, since it is the validity the call is about.
struct PlusSink {
    reply: ReplyDirectoryPlus,
    ttl: Duration,
}

impl DirectorySink for PlusSink {
    fn offer(&mut self, entry: &DirectoryEntry<'_>) -> bool {
        self.reply.add(
            INodeNo(entry.node_id),
            entry.offset,
            OsStr::from_bytes(entry.name),
            &self.ttl,
            entry.attr,
            Generation(entry.generation),
        )
    }

    fn counts_lookups(&self) -> bool {
        true
    }
}

/// Delivers entries to a plain `readdir` reply.
struct PlainSink {
    reply: ReplyDirectory,
}

impl DirectorySink for PlainSink {
    fn offer(&mut self, entry: &DirectoryEntry<'_>) -> bool {
        self.reply.add(
            INodeNo(entry.node_id),
            entry.offset,
            entry.kind,
            OsStr::from_bytes(entry.name),
        )
    }

    fn counts_lookups(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rename_and_xattr_flags_map_one_for_one() {
        assert_eq!(wire_rename_flags(RenameFlags::empty()), 0);
        assert_eq!(
            wire_rename_flags(RenameFlags::RENAME_NOREPLACE),
            rename_flags::NOREPLACE
        );
        assert_eq!(
            wire_rename_flags(RenameFlags::RENAME_EXCHANGE | RenameFlags::RENAME_WHITEOUT),
            rename_flags::EXCHANGE | rename_flags::WHITEOUT
        );
        assert_eq!(wire_xattr_flags(0), 0);
        assert_eq!(wire_xattr_flags(1), setxattr_flags::CREATE);
        assert_eq!(wire_xattr_flags(2), setxattr_flags::REPLACE);
    }

    /// The command the first real workload issued: `_IOR('T', 0x2A, struct
    /// termios2)`, 44 bytes.
    const TCGETS2: u32 = 2_150_388_778;

    #[test]
    fn the_observed_ioctl_is_the_terminal_query_this_refuses() {
        assert_eq!(TCGETS2, 0x802C_542A);
        // Direction (read), size (`sizeof(struct termios2)`), type and number,
        // as the Linux encoding lays them out — the identification the refusal
        // rests on.
        assert_eq!(TCGETS2 >> 30, 2);
        assert_eq!((TCGETS2 >> 16) & 0x3fff, 44);
        assert_eq!(ioctl_type(TCGETS2), u32::from(b'T'));
        assert_eq!(TCGETS2 & 0xff, 0x2A);

        // The whole terminal family is refused the same way, and nothing else
        // is claimed: `FICLONE` (type `0x94`) stays unmapped.
        assert_eq!(ioctl_type(0x5401), TERMINAL_IOCTL, "TCGETS");
        assert_eq!(ioctl_type(0x5413), TERMINAL_IOCTL, "TIOCGWINSZ");
        assert_ne!(ioctl_type(0x4020_9409), TERMINAL_IOCTL, "FICLONE");
    }

    /// The required fallback, in isolation: a kernel without
    /// `FUSE_DIRECT_IO_ALLOW_MMAP` gets ordinary page caching and the memory
    /// cost, never a mount refusal and never direct I/O without `mmap`. It is
    /// unit-tested because the machine the suite runs on *has* the capability,
    /// so the other arm is unreachable end-to-end here.
    #[test]
    fn direct_io_degrades_to_page_caching_where_mmap_would_be_lost() {
        assert_eq!(DataCaching::resolve(true, true), DataCaching::Direct);
        assert_eq!(DataCaching::resolve(true, false), DataCaching::Page);
        // Off is off, whatever the kernel offers: the default mount is
        // unchanged byte for byte.
        assert_eq!(DataCaching::resolve(false, true), DataCaching::Page);
        assert_eq!(DataCaching::resolve(false, false), DataCaching::Page);
    }

    /// Bits are added only in the direct mode: a page-caching mount replies
    /// exactly what it replied before the option existed.
    #[test]
    fn only_the_direct_mode_sets_a_reply_flag() {
        assert_eq!(DataCaching::Page.fopen_flags(), FopenFlags::empty());
        assert_eq!(
            DataCaching::Direct.fopen_flags(),
            FopenFlags::FOPEN_DIRECT_IO | FopenFlags::FOPEN_PARALLEL_DIRECT_WRITES
        );
        // The kernel's own values for them (`FOPEN_DIRECT_IO` and
        // `FOPEN_PARALLEL_DIRECT_WRITES`, `include/uapi/linux/fuse.h`), so a
        // renamed or re-valued library constant cannot silently change what the
        // kernel is told.
        assert_eq!(FopenFlags::FOPEN_DIRECT_IO.bits(), 1 << 0);
        assert_eq!(FopenFlags::FOPEN_PARALLEL_DIRECT_WRITES.bits(), 1 << 6);
        // `FUSE_DIRECT_IO_ALLOW_MMAP` is an INIT capability, not an open flag:
        // it is negotiated once in `init`, and it is the *pair* of the two that
        // keeps `mmap` working. Its kernel value is `1ULL << 36`.
        assert_eq!(fuser::InitFlags::FUSE_DIRECT_IO_ALLOW_MMAP.bits(), 1 << 36);
    }

    #[test]
    fn only_a_fifo_or_a_socket_reaches_the_wire_as_a_special_file() {
        assert!(is_special_file(0o010_644), "a fifo");
        assert!(is_special_file(0o140_644), "a socket file");
        // Device nodes are refused before a round trip, and so is a mode with
        // no file type in it at all.
        assert!(!is_special_file(0o020_644), "a character device");
        assert!(!is_special_file(0o060_644), "a block device");
        assert!(!is_special_file(0o100_644), "a regular file");
        assert!(!is_special_file(0o644));
    }

    #[test]
    fn an_elder_servers_enosys_reaches_the_guest_as_a_plain_refusal() {
        assert_eq!(mknod_errno(rustix::io::Errno::NOSYS), Errno::EPERM);
        // Every other errno is passed through as itself.
        assert_eq!(mknod_errno(rustix::io::Errno::ROFS), Errno::EROFS);
        assert_eq!(mknod_errno(rustix::io::Errno::EXIST), Errno::EEXIST);
        assert_eq!(mknod_errno(rustix::io::Errno::PERM), Errno::EPERM);
    }

    #[test]
    fn polling_answers_the_requested_events_a_ready_node_has() {
        // A guest polling for readability and writability gets both back: the
        // data is there and a write will not block.
        let asked = PollEvents::POLLIN | PollEvents::POLLOUT;
        assert_eq!(asked.intersection(ALWAYS_READY), asked);
        // Nothing outside the requested set is reported, and no condition these
        // nodes cannot have is invented.
        assert_eq!(
            PollEvents::POLLIN.intersection(ALWAYS_READY),
            PollEvents::POLLIN
        );
        assert_eq!(
            (PollEvents::POLLPRI | PollEvents::POLLHUP).intersection(ALWAYS_READY),
            PollEvents::empty()
        );
        assert_eq!(
            PollEvents::all().intersection(ALWAYS_READY),
            PollEvents::POLLIN
                | PollEvents::POLLOUT
                | PollEvents::POLLRDNORM
                | PollEvents::POLLWRNORM
        );
    }

    /// A mount owing the kernel nothing waits for nothing: a teardown of an
    /// idle mount pays none of this.
    #[test]
    fn a_teardown_that_is_owed_nothing_does_not_wait() {
        let inflight = Arc::<InFlight>::default();
        assert!(inflight.is_settled());
        let started = Instant::now();
        inflight.settle(Instant::now() + Duration::from_secs(30));
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    /// An outstanding callback is waited for until it is answered — and the
    /// wait ends when the answer does, not when the deadline does.
    #[test]
    fn an_outstanding_callback_is_waited_out() {
        let inflight = Arc::<InFlight>::default();
        let owed = inflight.owe();
        assert!(!inflight.is_settled());
        let answering = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            drop(owed);
        });
        let started = Instant::now();
        inflight.settle(Instant::now() + Duration::from_secs(30));
        let waited = started.elapsed();
        answering.join().expect("the answering thread finishes");
        assert!(inflight.is_settled());
        assert!(
            waited >= Duration::from_millis(50) && waited < Duration::from_secs(30),
            "the wait ended after {waited:?}, which is not when the callback was answered"
        );
    }

    /// A callback that is never answered may not hold the teardown: the
    /// deadline is what makes the wait a bounded one.
    #[test]
    fn a_callback_that_never_answers_is_waited_out_only_to_the_deadline() {
        let inflight = Arc::<InFlight>::default();
        let _owed = inflight.owe();
        let started = Instant::now();
        inflight.settle(Instant::now() + Duration::from_millis(100));
        assert!(
            started.elapsed() >= Duration::from_millis(100),
            "the deadline was not waited for"
        );
        assert!(
            !inflight.is_settled(),
            "nothing answered, so it is still owed"
        );
    }

    /// A task dropped instead of finished — which is what releasing the runtime
    /// does to it — stops being counted, so the count is what is really owed.
    #[test]
    fn a_dropped_callback_stops_being_owed() {
        let inflight = Arc::<InFlight>::default();
        let first = inflight.owe();
        let second = inflight.owe();
        assert!(!inflight.is_settled());
        drop(first);
        assert!(!inflight.is_settled());
        drop(second);
        assert!(inflight.is_settled());
    }
}
