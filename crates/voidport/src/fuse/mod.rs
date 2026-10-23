//! Nothing blocks a dispatch loop. A dispatch thread reads and dispatches one
//! request at a time, so a callback that waited for the server would stall every
//! other operation of that loop, and a blocking `setlk` would stall it for as
//! long as another mount holds the lock. Each callback captures what it needs,
//! hands the work to the async runtime of the mount, and replies from there. The
//! loops call into one shared adapter, so the adapter has no state that a
//! callback mutates in place. [`VoidportFs::negotiate`] runs during the
//! FUSE_INIT exchange, before any loop exists.
//!
//! The kernel node id is the server node id, and the presented `st_ino` is the
//! node id too.
//!
//! `access` never arrives, because the mount sets `default_permissions`, so the
//! guest kernel checks the presented bits itself.

pub mod attr;
pub mod dir;
mod inflight;
pub mod pages;

pub use inflight::InFlight;

use std::ffi::OsStr;
use std::future::Future;
use std::os::unix::ffi::OsStrExt as _;
use std::sync::Arc;
use std::time::Duration;

use rustix::io::Errno;
use voidport_fuse::{
    Attributes, Child, Create, Entry, ErrorReply as _, FileLock, FilesystemStats, Flush,
    FopenFlags, Forget, Fsync, Getattr, Getlk, Getxattr, Init, InitFlags, Ioctl, Link, Listxattr,
    LockType, MissingCapabilities, Mkdir, Mknod, Open, Operation, Poll, PollEvents, Read, Readlink,
    Release, Removexattr, Rename, RenameFlags, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory,
    ReplyDirectoryPlus, ReplyEmpty, ReplyEntry, ReplyInterrupt, ReplyIoctl, ReplyLock, ReplyOpen,
    ReplyPoll, ReplyStatfs, ReplyWrite, ReplyXattr, Request, Setattr, Setlk, Setxattr, Statfs,
    Symlink, Write, XattrFlags,
};
use voidport_proto::attr::Attr;
use voidport_proto::ops::dir::rename_flags;
use voidport_proto::ops::xattr::setxattr_flags;
use voidport_session::metadata::{self, MaskedChmod};
use voidport_session::write::{self, Next};

use crate::client::{
    AttrChange, Caller, Client, Data, Interrupt, Lock, LockKind, NewFile, Pages, Placement,
    Streamed,
};
use crate::fuse::attr::{Privileged, entry_attr, node_attr, time_change, timespec};
use crate::fuse::dir::{DirectoryEntry, DirectoryRead, DirectorySink, read_directory};
use crate::fuse::pages::PageCache;
use crate::guardian::Feed;

/// A leased file caches its pages across opens (`FOPEN_KEEP_CACHE`), because the
/// server recalls them before anybody else writes it. A file that others may
/// write unnoticed is read past the page cache (`FOPEN_DIRECT_IO`), and since
/// the mount does not negotiate `FUSE_DIRECT_IO_ALLOW_MMAP`, the guest kernel
/// fails a shared mapping of it with `ENODEV`.
#[must_use]
fn fopen_flags(pages: Pages) -> FopenFlags {
    match pages {
        Pages::Kept => FopenFlags::KEEP_CACHE,
        Pages::UntilClose => FopenFlags::empty(),
        Pages::Uncached => FopenFlags::DIRECT_IO,
    }
}

/// How the guest kernel reads and writes the data of a file.
#[derive(Clone, Copy, Debug)]
pub(crate) enum FileIo {
    /// Through the page cache whenever the server allows it for the open.
    AsServed,
    /// Past the page cache for every open.
    Direct,
}

impl FileIo {
    pub(crate) fn of(direct: bool) -> Self {
        if direct { Self::Direct } else { Self::AsServed }
    }

    /// `Direct` adds `FOPEN_DIRECT_IO` to the flags for what the server
    /// returns. The flags of a leased file still contain `FOPEN_KEEP_CACHE`,
    /// since without it every open drops the pages that private mappings of
    /// the file use, such as those of a program that runs from it.
    #[must_use]
    fn open_flags(self, pages: Pages) -> FopenFlags {
        match self {
            Self::AsServed => fopen_flags(pages),
            Self::Direct => fopen_flags(pages) | FopenFlags::DIRECT_IO,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Presentation {
    pub(crate) attr_ttl: Duration,
    pub(crate) entry_ttl: Duration,
    pub(crate) privileged: Privileged,
}

impl Presentation {
    fn entry(self, entry: &crate::client::Entry) -> Entry {
        self.entry_of(
            entry.node_id,
            entry.generation,
            entry_attr(entry, self.privileged),
        )
    }

    fn entry_of(self, node: u64, generation: u64, attributes: Attributes) -> Entry {
        Entry {
            node,
            generation,
            attributes,
            entry_valid: self.entry_ttl,
            attr_valid: self.attr_ttl,
        }
    }

    fn attributes(self, node_id: u64, attr: &Attr) -> Attributes {
        node_attr(node_id, attr, self.privileged)
    }
}

#[derive(Debug)]
pub struct VoidportFs {
    client: Arc<Client>,
    runtime: tokio::runtime::Handle,
    present: Presentation,
    file_io: FileIo,
    inflight: Arc<InFlight>,
    pages: Arc<PageCache>,
}

impl VoidportFs {
    #[must_use]
    pub(crate) fn new(
        client: Arc<Client>,
        runtime: tokio::runtime::Handle,
        present: Presentation,
        file_io: FileIo,
        inflight: Arc<InFlight>,
        feed: Arc<Feed>,
    ) -> Self {
        Self {
            client,
            runtime,
            present,
            file_io,
            inflight,
            pages: Arc::new(PageCache::new(feed)),
        }
    }

    /// Each capability is required: without `FUSE_DO_READDIRPLUS` the kernel
    /// sends plain readdir, for which it does no `nlookup` accounting; without
    /// `FUSE_POSIX_LOCKS` it satisfies record locks guest-locally and the server
    /// never sees them; without `FUSE_AUTO_INVAL_DATA` a same-size overwrite from
    /// elsewhere stays invisible to a held-open descriptor indefinitely; without
    /// `FUSE_HAS_RESEND` the guardian cannot have the requests a dead client had
    /// read sent again, so a page it cached could outlive the client. A kernel
    /// without them fails the mount.
    ///
    /// `FUSE_FLOCK_LOCKS` is not negotiated: a lock request arrives without the
    /// `lk_flags` of the kernel and the wire `FileLock` has no lock-namespace
    /// field, so routing `flock(2)` to the server would conflate it with record
    /// locks. `flock` is guest-local per mount.
    pub fn negotiate(self, init: &mut Init) -> Result<Self, MissingCapabilities> {
        init.require(
            InitFlags::DO_READDIRPLUS
                | InitFlags::POSIX_LOCKS
                | InitFlags::AUTO_INVAL_DATA
                | InitFlags::HAS_RESEND,
        )?;
        Ok(self)
    }

    #[must_use]
    pub fn pages(&self) -> Arc<PageCache> {
        Arc::clone(&self.pages)
    }

    #[must_use]
    pub fn client(&self) -> Arc<Client> {
        Arc::clone(&self.client)
    }

    fn entry(&self) -> EntryReply {
        EntryReply {
            pages: self.pages(),
            present: self.present,
            file_io: self.file_io,
        }
    }

    /// No interrupt of the request ends the work.
    fn spawn(&self, request: Request, work: impl Future<Output = ()> + Send + 'static) {
        self.spawn_interruptible(request, |_| work);
    }

    /// The callback is counted as owed from here, before the dispatch loop is
    /// let go, so there is no instant where the kernel has handed over a request
    /// that nothing accounts for, until the work is finished or dropped.
    fn spawn_interruptible<F>(&self, request: Request, work: impl FnOnce(Interrupt) -> F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let (owed, interrupt) = self.inflight.owe(request.unique);
        let work = work(interrupt);
        self.runtime.spawn(async move {
            work.await;
            drop(owed);
        });
    }
}

impl voidport_fuse::Filesystem for VoidportFs {
    fn handle(&self, request: Request, operation: Operation<'_>) {
        match operation {
            Operation::Lookup(lookup, reply) => self.lookup(request, lookup, reply),
            Operation::Forget(forget) => self.forget(request, forget),
            Operation::Getattr(getattr, reply) => self.getattr(request, getattr, reply),
            Operation::Setattr(change, reply) => self.setattr(request, change, reply),
            Operation::Readlink(readlink, reply) => self.readlink(request, readlink, reply),
            Operation::Mknod(mknod, reply) => self.mknod(request, mknod, reply),
            Operation::Mkdir(mkdir, reply) => self.mkdir(request, mkdir, reply),
            Operation::Unlink(child, reply) => self.unlink(request, child, reply),
            Operation::Rmdir(child, reply) => self.rmdir(request, child, reply),
            Operation::Symlink(symlink, reply) => self.symlink(request, symlink, reply),
            Operation::Rename(rename, reply) => self.rename(request, rename, reply),
            Operation::Link(link, reply) => self.link(request, link, reply),
            Operation::Open(open, reply) => self.open(request, open, reply),
            Operation::Read(read, reply) => self.read(request, read, reply),
            Operation::Write(write, reply) => self.write(request, write, reply),
            Operation::Flush(flush, reply) => self.flush(request, flush, reply),
            Operation::Release(release, reply) => self.release(request, release, reply),
            Operation::Fsync(fsync, reply) => self.fsync(request, fsync, reply),
            Operation::Fsyncdir(fsync, reply) => self.fsyncdir(request, fsync, reply),
            Operation::Opendir(open, reply) => self.opendir(request, open, reply),
            Operation::Readdir(read, reply) => self.readdir(request, read, reply),
            Operation::Readdirplus(read, reply) => self.readdirplus(request, read, reply),
            Operation::Releasedir(release, reply) => self.releasedir(request, release, reply),
            Operation::Statfs(statfs, reply) => self.statfs(request, statfs, reply),
            Operation::Setxattr(setxattr, reply) => self.setxattr(request, setxattr, reply),
            Operation::Getxattr(getxattr, reply) => self.getxattr(request, getxattr, reply),
            Operation::Listxattr(listxattr, reply) => self.listxattr(request, listxattr, reply),
            Operation::Removexattr(removexattr, reply) => {
                self.removexattr(request, removexattr, reply);
            }
            Operation::Create(create, reply) => self.create(request, create, reply),
            Operation::Getlk(getlk, reply) => self.getlk(request, getlk, reply),
            Operation::Setlk(setlk, reply) => self.setlk(request, setlk, reply),
            Operation::Poll(poll, reply) => poll_ready(&poll, reply),
            Operation::Ioctl(ioctl, reply) => refuse_ioctl(&ioctl, reply),
            Operation::Interrupt(interrupt, reply) => self.interrupt(&interrupt, reply),
        }
    }
}

impl VoidportFs {
    fn lookup(&self, request: Request, lookup: Child<'_>, reply: ReplyEntry) {
        let (client, caller, entry) = (self.client(), caller_of(request), self.entry());
        let name = lookup.name.as_bytes().to_vec();
        self.spawn(request, async move {
            entry.reply(reply, client.lookup(caller, lookup.parent, &name).await);
        });
    }

    /// Sending each forget before the next callback is read keeps the forgets of
    /// a burst, which the kernel sends by the thousand when it prunes its
    /// caches, to one connection at a time. The wire has no batch form, so a
    /// batch becomes one FORGET per node.
    fn forget(&self, request: Request, forget: Forget) {
        self.pages.forget(forget.node, forget.lookups);
        let (client, caller) = (self.client(), caller_of(request));
        self.runtime.block_on(async move {
            client.forget(caller, forget.node, forget.lookups).await;
        });
    }

    /// An interrupt for a request whose callback is not registered yet, because
    /// another dispatch loop is still handing it over, is answered `EAGAIN`, so
    /// the kernel sends it again. Once the request has its reply, the kernel
    /// stops sending interrupts for it.
    fn interrupt(&self, interrupt: &voidport_fuse::Interrupt, reply: ReplyInterrupt) {
        if !self.inflight.interrupt(interrupt.target) {
            reply.retry();
        }
    }

    fn getattr(&self, request: Request, getattr: Getattr, reply: ReplyAttr) {
        let (client, caller, present) = (self.client(), caller_of(request), self.present);
        self.spawn(request, async move {
            match client.getattr(caller, getattr.node, getattr.handle).await {
                Ok(attr) => reply.attr(&present.attributes(getattr.node, &attr), present.attr_ttl),
                Err(error) => reply.error(error),
            }
        });
    }

    fn setattr(&self, request: Request, setattr: Setattr, reply: ReplyAttr) {
        let (client, caller, present) = (self.client(), caller_of(request), self.present);
        let change = AttrChange {
            mode: setattr.mode,
            uid: setattr.uid,
            gid: setattr.gid,
            size: setattr.size,
            atime: setattr.atime.map(time_change),
            mtime: setattr.mtime.map(time_change),
            ctime: setattr.ctime.map(timespec),
            handle: setattr.handle,
        };
        let chmod = match setattr.mode {
            Some(mode) if present.privileged.is_masked() => match metadata::chmod_mode(mode) {
                Some(chmod) => Some(chmod),
                None => return reply.error(Errno::PERM),
            },
            _ => None,
        };
        let node = setattr.node;
        self.spawn_interruptible(request, |interrupt| async move {
            let change = match preserve_privileged(&client, caller, node, change, chmod).await {
                Ok(change) => change,
                Err(error) => return reply.error(error),
            };
            match client.setattr(caller, &interrupt, node, change).await {
                Ok(attr) => reply.attr(&present.attributes(node, &attr), present.attr_ttl),
                Err(error) => reply.error(error),
            }
        });
    }

    fn readlink(&self, request: Request, readlink: Readlink, reply: ReplyData) {
        let (client, caller) = (self.client(), caller_of(request));
        self.spawn(request, async move {
            match client.readlink(caller, readlink.node).await {
                Ok(target) => reply.data(&target),
                Err(error) => reply.error(error),
            }
        });
    }

    /// A device node is refused here, before the wire, so `mknod /dev/…` costs
    /// no round trip and cannot depend on the posture of the server. The host
    /// inode is a marker: once this reply says `S_IFIFO`, the guest kernel
    /// installs its own pipe operations and no open, read or write for it
    /// reaches the server, so pipe data and `AF_UNIX` rendezvous live in this
    /// guest's kernel.
    fn mknod(&self, request: Request, mknod: Mknod<'_>, reply: ReplyEntry) {
        if metadata::mknod_kind(mknod.mode).is_none() {
            reply.error(Errno::PERM);
            return;
        }
        let (client, caller, entry) = (self.client(), caller_of(request), self.entry());
        let name = mknod.name.as_bytes().to_vec();
        self.spawn(request, async move {
            let made = client
                .mknod(
                    caller,
                    mknod.parent,
                    &name,
                    mknod.mode,
                    mknod.umask,
                    mknod.rdev,
                )
                .await;
            entry.reply(reply, made);
        });
    }

    fn mkdir(&self, request: Request, mkdir: Mkdir<'_>, reply: ReplyEntry) {
        let (client, caller, entry) = (self.client(), caller_of(request), self.entry());
        let name = mkdir.name.as_bytes().to_vec();
        self.spawn(request, async move {
            let made = client
                .mkdir(caller, mkdir.parent, &name, mkdir.mode, mkdir.umask)
                .await;
            entry.reply(reply, made);
        });
    }

    fn unlink(&self, request: Request, child: Child<'_>, reply: ReplyEmpty) {
        let (client, caller) = (self.client(), caller_of(request));
        let name = child.name.as_bytes().to_vec();
        self.spawn(request, async move {
            answer(reply, client.unlink(caller, child.parent, &name).await);
        });
    }

    fn rmdir(&self, request: Request, child: Child<'_>, reply: ReplyEmpty) {
        let (client, caller) = (self.client(), caller_of(request));
        let name = child.name.as_bytes().to_vec();
        self.spawn(request, async move {
            answer(reply, client.rmdir(caller, child.parent, &name).await);
        });
    }

    fn symlink(&self, request: Request, symlink: Symlink<'_>, reply: ReplyEntry) {
        let (client, caller, entry) = (self.client(), caller_of(request), self.entry());
        let name = symlink.name.as_bytes().to_vec();
        let target = symlink.target.as_bytes().to_vec();
        self.spawn(request, async move {
            let made = client.symlink(caller, symlink.parent, &name, &target).await;
            entry.reply(reply, made);
        });
    }

    fn rename(&self, request: Request, rename: Rename<'_>, reply: ReplyEmpty) {
        let (client, caller) = (self.client(), caller_of(request));
        let name = rename.name.as_bytes().to_vec();
        let new_name = rename.new_name.as_bytes().to_vec();
        let (parent, new_parent) = (rename.parent, rename.new_parent);
        let flags = wire_rename_flags(rename.flags);
        self.spawn(request, async move {
            answer(
                reply,
                client
                    .rename(caller, parent, &name, new_parent, &new_name, flags)
                    .await,
            );
        });
    }

    fn link(&self, request: Request, link: Link<'_>, reply: ReplyEntry) {
        let (client, caller, entry) = (self.client(), caller_of(request), self.entry());
        let name = link.new_name.as_bytes().to_vec();
        let (node, new_parent) = (link.node, link.new_parent);
        self.spawn(request, async move {
            entry.reply(reply, client.link(caller, node, new_parent, &name).await);
        });
    }

    /// The flags are forwarded verbatim: the server decides which flags a reopen
    /// may honour, and `O_APPEND` reaches the host descriptor only because
    /// nothing here filters it out. Interpreting flags on this side would put
    /// the decision in two places.
    fn open(&self, request: Request, open: Open, reply: ReplyOpen) {
        let (client, caller, file_io) = (self.client(), caller_of(request), self.file_io);
        self.spawn_interruptible(request, |interrupt| async move {
            match client
                .open_file(caller, &interrupt, open.node, open.flags.bits())
                .await
            {
                Ok((handle, pages)) => reply.opened(handle, file_io.open_flags(pages)),
                Err(error) => reply.error(error),
            }
        });
    }

    /// A short FUSE read means end of file, so a short wire answer that is not
    /// the end, one whose closing piece lacks the exhausted bit, is continued
    /// here from where it stopped, into the same buffer.
    fn read(&self, request: Request, read: Read, reply: ReplyData) {
        let (client, caller, pages) = (self.client(), caller_of(request), self.pages());
        self.spawn_interruptible(request, |interrupt| async move {
            let Read {
                node,
                handle,
                offset,
                size,
            } = read;
            // Before the request goes out, so that a recall of the node can
            // hold it back.
            pages.fill(node, offset, u64::from(size)).await;
            match serial_read(&client, caller, &interrupt, node, handle, offset, size).await {
                Ok(data) => reply.data(data.filled()),
                Err(error) => reply.error(error),
            }
        });
    }

    /// On a handle the guest opened `O_APPEND` the offset is advisory, since
    /// the host places the data at the end of the file. The suid-kill mark of
    /// the kernel is sent with the continuation too, because stripping twice
    /// changes nothing.
    fn write(&self, request: Request, write: Write<'_>, reply: ReplyWrite) {
        let (client, caller, pages) = (self.client(), caller_of(request), self.pages());
        // Set by the kernel on a direct-io write by a caller without the
        // file-mode privilege. Nothing is negotiated for it, so the kernel
        // still strips the bits everywhere else. This is the one case the
        // kernel cannot handle itself, because the bits are recorded on the
        // server.
        let strip = write.kill_suid_gid;
        // The data borrows the buffer of the dispatch thread, which reads the
        // next request into it once this callback returns, so the copy lives
        // until the write is settled.
        let data = client.copy_of(write.data);
        let at = Placement {
            node_id: write.node,
            handle: write.handle,
            offset: write.offset,
        };
        self.spawn_interruptible(request, |interrupt| async move {
            // Held back like a read: the kernel stores the bytes of a write
            // in its page cache, and the writeback of a dirty page, which a
            // drop of the pages starts, arrives here.
            pages.fill(at.node_id, at.offset, data.len() as u64).await;
            let placed = serial_write(&client, caller, &interrupt, at, &data, strip).await;
            match placed {
                Ok(written) => reply.written(written),
                Err(error) => reply.error(error),
            }
        });
    }

    /// No interrupt ends it: the kernel has closed the descriptor already, and
    /// the locks of a program that released them must not remain in the server.
    fn flush(&self, request: Request, flush: Flush, reply: ReplyEmpty) {
        let (client, caller) = (self.client(), caller_of(request));
        self.spawn(request, async move {
            let flushed = client
                .flush(caller, flush.node, flush.handle, flush.lock_owner)
                .await;
            answer(reply, flushed);
        });
    }

    /// Releases a handle. No interrupt ends it, as no interrupt ends a flush.
    fn release(&self, request: Request, release: Release, reply: ReplyEmpty) {
        let (client, caller) = (self.client(), caller_of(request));
        self.spawn(request, async move {
            answer(
                reply,
                client
                    .release(
                        caller,
                        release.node,
                        release.handle,
                        release.flags,
                        release.lock_owner,
                        release.flush,
                    )
                    .await,
            );
        });
    }

    fn fsync(&self, request: Request, fsync: Fsync, reply: ReplyEmpty) {
        let (client, caller) = (self.client(), caller_of(request));
        self.spawn_interruptible(request, |interrupt| async move {
            let synced = client
                .fsync(caller, &interrupt, fsync.node, fsync.handle, fsync.datasync)
                .await;
            answer(reply, synced);
        });
    }

    fn fsyncdir(&self, request: Request, fsync: Fsync, reply: ReplyEmpty) {
        let (client, caller) = (self.client(), caller_of(request));
        self.spawn(request, async move {
            let synced = client
                .fsync(
                    caller,
                    &Interrupt::none(),
                    fsync.node,
                    fsync.handle,
                    fsync.datasync,
                )
                .await;
            answer(reply, synced);
        });
    }

    /// No page cache flags here: a directory handle has no file data, and its
    /// listing never reads through the page cache. `FOPEN_CACHE_DIR` is not set
    /// either.
    fn opendir(&self, request: Request, open: Open, reply: ReplyOpen) {
        let (client, caller) = (self.client(), caller_of(request));
        self.spawn(request, async move {
            match client.open(caller, open.node, open.flags.bits()).await {
                Ok(handle) => reply.opened(handle, FopenFlags::empty()),
                Err(error) => reply.error(error),
            }
        });
    }

    /// The kernel does no `nlookup` accounting for this call, so every entry
    /// returned is given straight back with a compensating `forget`. Once
    /// `FUSE_DO_READDIRPLUS` is negotiated the kernel does not take this path; it
    /// exists so that a kernel which does cannot leak server nodes.
    fn readdir(&self, request: Request, read: Read, reply: ReplyDirectory) {
        let (client, caller) = (self.client(), caller_of(request));
        let privileged = self.present.privileged;
        self.spawn(request, async move {
            let read = DirectoryRead {
                node_id: read.node,
                handle: read.handle,
                cookie: read.offset,
            };
            let (sink, outcome) =
                read_directory(&client, caller, read, privileged, PlainSink { reply }).await;
            if let Some(sink) = sink {
                match outcome {
                    Ok(()) => sink.reply.ok(),
                    Err(error) => sink.reply.error(error),
                }
            }
        });
    }

    fn readdirplus(&self, request: Request, read: Read, reply: ReplyDirectoryPlus) {
        let (client, caller, present) = (self.client(), caller_of(request), self.present);
        let pages = self.pages();
        self.spawn(request, async move {
            let read = DirectoryRead {
                node_id: read.node,
                handle: read.handle,
                cookie: read.offset,
            };
            let sink = PlusSink {
                reply,
                present,
                taken: Vec::new(),
            };
            let (sink, outcome) =
                read_directory(&client, caller, read, present.privileged, sink).await;
            if let Some(sink) = sink {
                match outcome {
                    Ok(()) => {
                        for node_id in sink.taken {
                            pages.looked_up(node_id);
                        }
                        sink.reply.ok();
                    }
                    Err(error) => sink.reply.error(error),
                }
            }
        });
    }

    fn releasedir(&self, request: Request, release: Release, reply: ReplyEmpty) {
        let (client, caller) = (self.client(), caller_of(request));
        self.spawn(request, async move {
            answer(
                reply,
                client
                    .release(
                        caller,
                        release.node,
                        release.handle,
                        release.flags,
                        None,
                        false,
                    )
                    .await,
            );
        });
    }

    fn statfs(&self, request: Request, statfs: Statfs, reply: ReplyStatfs) {
        let (client, caller) = (self.client(), caller_of(request));
        self.spawn(request, async move {
            match client.statfs(caller, statfs.node).await {
                Ok(stat) => reply.statfs(&FilesystemStats {
                    blocks: stat.blocks.get(),
                    free_blocks: stat.bfree.get(),
                    available_blocks: stat.bavail.get(),
                    files: stat.files.get(),
                    free_files: stat.ffree.get(),
                    block_size: stat.bsize.get(),
                    name_length: stat.namelen.get(),
                    fragment_size: stat.frsize.get(),
                }),
                Err(error) => reply.error(error),
            }
        });
    }

    fn setxattr(&self, request: Request, setxattr: Setxattr<'_>, reply: ReplyEmpty) {
        let (client, caller) = (self.client(), caller_of(request));
        let name = setxattr.name.as_bytes().to_vec();
        let value = setxattr.value.to_vec();
        let (node, flags) = (setxattr.node, wire_xattr_flags(setxattr.flags));
        self.spawn(request, async move {
            answer(
                reply,
                client.setxattr(caller, node, &name, &value, flags).await,
            );
        });
    }

    fn getxattr(&self, request: Request, getxattr: Getxattr<'_>, reply: ReplyXattr) {
        let (client, caller) = (self.client(), caller_of(request));
        let name = getxattr.name.as_bytes().to_vec();
        let (node, size) = (getxattr.node, getxattr.size);
        self.spawn(request, async move {
            match client.getxattr(caller, node, &name, size).await {
                Ok(value) if size == 0 => reply.size(value.size),
                Ok(value) => reply.data(&value.value),
                Err(error) => reply.error(error),
            }
        });
    }

    /// The wire sizes the answer in guest bytes, the length of the list built
    /// here, so `ERANGE` is decided by the server against the number the kernel
    /// compares against.
    fn listxattr(&self, request: Request, listxattr: Listxattr, reply: ReplyXattr) {
        let (client, caller) = (self.client(), caller_of(request));
        let Listxattr { node, size } = listxattr;
        self.spawn(request, async move {
            match client.listxattr(caller, node, size).await {
                Ok(names) if size == 0 => reply.size(names.size),
                Ok(names) => reply.data(&names.to_kernel_list()),
                Err(error) => reply.error(error),
            }
        });
    }

    fn removexattr(&self, request: Request, removexattr: Removexattr<'_>, reply: ReplyEmpty) {
        let (client, caller) = (self.client(), caller_of(request));
        let name = removexattr.name.as_bytes().to_vec();
        let node = removexattr.node;
        self.spawn(request, async move {
            answer(reply, client.removexattr(caller, node, &name).await);
        });
    }

    fn create(&self, request: Request, create: Create<'_>, reply: ReplyCreate) {
        let (client, caller, entry) = (self.client(), caller_of(request), self.entry());
        let name = create.name.as_bytes().to_vec();
        self.spawn_interruptible(request, |interrupt| async move {
            let file = NewFile {
                parent: create.parent,
                name: &name,
                flags: create.flags.bits(),
                mode: create.mode,
                umask: create.umask,
            };
            entry.created(reply, client.create(caller, &interrupt, file).await);
        });
    }

    /// The kernel resolves the conflicting pid through its own pid namespace and
    /// finds nothing there, because an OFD lock on the host has no owning
    /// process, so a guest sees a conflict pid of 0.
    fn getlk(&self, request: Request, getlk: Getlk, reply: ReplyLock) {
        let (client, caller) = (self.client(), caller_of(request));
        let lock = wire_lock(getlk.owner, &getlk.lock);
        self.spawn_interruptible(request, |interrupt| async move {
            match client
                .getlk(caller, &interrupt, getlk.node, getlk.handle, lock)
                .await
            {
                Ok(conflict) => reply.lock(&FileLock {
                    start: conflict.start,
                    end: conflict.end,
                    lock_type: conflict.kind.into(),
                    pid: conflict.pid,
                }),
                Err(error) => reply.error(error),
            }
        });
    }

    /// A waiting lock parks on the server until the range frees. This callback
    /// returns immediately and waits on the runtime, so the mount keeps serving
    /// everything else meanwhile.
    fn setlk(&self, request: Request, setlk: Setlk, reply: ReplyEmpty) {
        let (client, caller) = (self.client(), caller_of(request));
        let lock = wire_lock(setlk.owner, &setlk.lock);
        self.spawn_interruptible(request, |interrupt| async move {
            let placed = client
                .setlk(
                    caller,
                    &interrupt,
                    setlk.node,
                    setlk.handle,
                    lock,
                    setlk.wait,
                )
                .await;
            answer(reply, placed);
        });
    }
}

fn wire_lock(owner: u64, lock: &FileLock) -> Lock {
    Lock {
        start: lock.start,
        end: lock.end,
        owner,
        pid: lock.pid,
        kind: lock.lock_type.into(),
    }
}

impl From<LockType> for LockKind {
    fn from(lock_type: LockType) -> Self {
        match lock_type {
            LockType::Read => Self::Read,
            LockType::Write => Self::Write,
            LockType::Unlock => Self::Unlock,
        }
    }
}

impl From<LockKind> for LockType {
    fn from(kind: LockKind) -> Self {
        match kind {
            LockKind::Read => Self::Read,
            LockKind::Write => Self::Write,
            LockKind::Unlock => Self::Unlock,
        }
    }
}

/// A namespace contains regular files, directories and symlinks, and only the
/// first two are ever open, so the ready set is the requested set, narrowed to
/// the events such a node can report. No notification is ever owed, so
/// `FUSE_POLL_SCHEDULE_NOTIFY` is ignored. Nothing here waits, so this replies
/// on the dispatch loop, not through the runtime.
fn poll_ready(poll: &Poll, reply: ReplyPoll) {
    reply.ready(poll.events.intersection(ALWAYS_READY));
}

/// A terminal query (`TCGETS2`, issued by `tcgetattr(3)` and `isatty(3)`) gets
/// `ENOTTY`, as the host filesystem answers it. The wire has no ioctl
/// operation, and passing it to the host would produce the same `ENOTTY` after
/// a round trip.
///
/// Any other command gets the unmapped reply, `ENOSYS` with a warning. The
/// kernel turns that `ENOSYS` into `ENOTTY` for the caller and keeps sending
/// `FUSE_IOCTL` for the next command (`fs/fuse/ioctl.c`), so every unmapped
/// ioctl warns again. That is why the terminal query gets its `ENOTTY` here: a program that
/// issues it on every file it opens would otherwise write one warning per call.
fn refuse_ioctl(ioctl: &Ioctl<'_>, reply: ReplyIoctl) {
    if ioctl_type(ioctl.command) == TERMINAL_IOCTL {
        return reply.error(Errno::NOTTY);
    }
    tracing::warn!(
        ino = ioctl.node,
        fh = ioctl.handle,
        flags = format_args!("{:#x}", ioctl.flags),
        cmd = format_args!("{:#x}", ioctl.command),
        in_data = ioctl.input.len(),
        out_size = ioctl.output_size,
        "unimplemented ioctl"
    );
    reply.error(Errno::NOSYS);
}

/// What a node that is always ready may report: data to read, room to write, and
/// the two `*NORM` spellings. `POLLERR`, `POLLHUP` and `POLLPRI` are never
/// invented.
const ALWAYS_READY: PollEvents = PollEvents::POLLIN
    .union(PollEvents::POLLOUT)
    .union(PollEvents::POLLRDNORM)
    .union(PollEvents::POLLWRNORM);

const TERMINAL_IOCTL: u32 = b'T' as u32;

/// The type field of an ioctl command number, in the Linux encoding: direction,
/// size, type, number.
const fn ioctl_type(cmd: u32) -> u32 {
    (cmd >> 8) & 0xff
}

/// A read that received bytes before an errno answers with those bytes, as a
/// local read that fails partway returns what it read. One that received none
/// answers the errno.
async fn serial_read(
    client: &Client,
    caller: Caller,
    interrupt: &Interrupt,
    node_id: u64,
    handle: u64,
    offset: u64,
    size: u32,
) -> Result<Data, rustix::io::Errno> {
    let mut data = Data::new(client.buffer(size as usize).await);
    while data.remaining() > 0 {
        let before = data.filled().len();
        let (returned, outcome) = client
            .read(
                caller,
                interrupt,
                node_id,
                handle,
                offset + before as u64,
                data,
            )
            .await;
        data = returned;
        let received = data.filled().len();
        match outcome {
            Ok(Streamed {
                exhausted,
                failed: None,
            }) if !exhausted && received > before => {}
            Ok(Streamed {
                failed: Some(error),
                ..
            })
            | Err(error)
                if received == 0 =>
            {
                return Err(error);
            }
            Ok(_) | Err(_) => break,
        }
    }
    Ok(data)
}

async fn serial_write(
    client: &Client,
    caller: Caller,
    interrupt: &Interrupt,
    at: Placement,
    data: &[u8],
    strip: bool,
) -> Result<u32, rustix::io::Errno> {
    let length = data.len() as u64;
    let mut next = write::start(length);
    loop {
        match next {
            Next::Send { from } => {
                let from_here = Placement {
                    offset: at.offset + from,
                    ..at
                };
                let reply = client
                    .write(caller, interrupt, from_here, &data[from as usize..], strip)
                    .await;
                next = write::next(length, from, reply);
            }
            Next::Return(written) => return Ok(u32::try_from(written).unwrap_or(u32::MAX)),
            Next::Fail(error) => return Err(error),
            Next::Overrun => return Err(rustix::io::Errno::IO),
        }
    }
}

struct EntryReply {
    pages: Arc<PageCache>,
    present: Presentation,
    file_io: FileIo,
}

impl EntryReply {
    fn reply(self, reply: ReplyEntry, entry: Result<crate::client::Entry, Errno>) {
        match entry {
            Ok(entry) => reply.entry(&self.counted(&entry)),
            Err(error) => reply.error(error),
        }
    }

    fn created(
        self,
        reply: ReplyCreate,
        created: Result<(crate::client::Entry, u64, Pages), Errno>,
    ) {
        match created {
            Ok((entry, handle, pages)) => {
                let flags = self.file_io.open_flags(pages);
                reply.created(&self.counted(&entry), handle, flags);
            }
            Err(error) => reply.error(error),
        }
    }

    /// The lookup is counted before the reply is sent, so that the forget that
    /// gives it back finds it counted.
    fn counted(&self, entry: &crate::client::Entry) -> Entry {
        self.pages.looked_up(entry.node_id);
        self.present.entry(entry)
    }
}

fn answer(reply: ReplyEmpty, outcome: Result<(), Errno>) {
    match outcome {
        Ok(()) => reply.ok(),
        Err(error) => reply.error(error),
    }
}

fn caller_of(request: Request) -> Caller {
    Caller {
        uid: request.uid,
        gid: request.gid,
        pid: request.pid,
    }
}

/// A chmod through a masked mount needs the mode the server has: one extra round
/// trip, on a chmod, on a mount that opted out, and nothing on every other mount
/// and operation.
async fn preserve_privileged(
    client: &Client,
    caller: Caller,
    node_id: u64,
    change: AttrChange,
    chmod: Option<MaskedChmod>,
) -> Result<AttrChange, rustix::io::Errno> {
    let Some(chmod) = chmod else {
        return Ok(change);
    };
    let held = client.getattr(caller, node_id, None).await?;
    Ok(AttrChange {
        mode: Some(chmod.mode(held.mode.get())),
        ..change
    })
}

fn wire_rename_flags(flags: RenameFlags) -> u32 {
    let mut wire = 0;
    if flags.contains(RenameFlags::NOREPLACE) {
        wire |= rename_flags::NOREPLACE;
    }
    if flags.contains(RenameFlags::EXCHANGE) {
        wire |= rename_flags::EXCHANGE;
    }
    if flags.contains(RenameFlags::WHITEOUT) {
        wire |= rename_flags::WHITEOUT;
    }
    wire
}

fn wire_xattr_flags(flags: XattrFlags) -> u32 {
    let mut wire = 0;
    if flags.contains(XattrFlags::CREATE) {
        wire |= setxattr_flags::CREATE;
    }
    if flags.contains(XattrFlags::REPLACE) {
        wire |= setxattr_flags::REPLACE;
    }
    wire
}

struct PlusSink {
    reply: ReplyDirectoryPlus,
    present: Presentation,
    taken: Vec<u64>,
}

impl DirectorySink for PlusSink {
    fn offer(&mut self, listed: &DirectoryEntry<'_>) -> bool {
        let entry = self
            .present
            .entry_of(listed.node_id, listed.generation, *listed.attributes);
        let full = self
            .reply
            .add(OsStr::from_bytes(listed.name), listed.offset, &entry);
        if !full {
            self.taken.push(listed.node_id);
        }
        full
    }

    fn take_back(&mut self, count: usize) {
        self.reply.take_back(count);
        self.taken.truncate(self.taken.len().saturating_sub(count));
    }

    fn counts_lookups(&self) -> bool {
        true
    }
}

struct PlainSink {
    reply: ReplyDirectory,
}

impl DirectorySink for PlainSink {
    fn offer(&mut self, entry: &DirectoryEntry<'_>) -> bool {
        self.reply.add(
            entry.node_id,
            entry.offset,
            entry.kind,
            OsStr::from_bytes(entry.name),
        )
    }

    fn take_back(&mut self, count: usize) {
        self.reply.take_back(count);
    }

    fn counts_lookups(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_direct_io_mount_opens_every_file_past_the_page_cache() {
        for (pages, flags) in [
            (Pages::Kept, FopenFlags::DIRECT_IO | FopenFlags::KEEP_CACHE),
            (Pages::UntilClose, FopenFlags::DIRECT_IO),
            (Pages::Uncached, FopenFlags::DIRECT_IO),
        ] {
            assert_eq!(FileIo::Direct.open_flags(pages), flags, "{pages:?}");
        }
    }

    #[test]
    fn the_terminal_ioctls_are_told_apart_from_the_others() {
        // The rest of the terminal family gets the same error. `FICLONE` (type
        // `0x94`) remains unmapped.
        assert_eq!(ioctl_type(0x802C_542A), TERMINAL_IOCTL, "TCGETS2");
        assert_eq!(ioctl_type(0x5401), TERMINAL_IOCTL, "TCGETS");
        assert_eq!(ioctl_type(0x5413), TERMINAL_IOCTL, "TIOCGWINSZ");
        assert_ne!(ioctl_type(0x4020_9409), TERMINAL_IOCTL, "FICLONE");
    }

    #[test]
    fn polling_answers_the_requested_events_a_ready_node_has() {
        let asked = PollEvents::POLLIN | PollEvents::POLLOUT;
        assert_eq!(asked.intersection(ALWAYS_READY), asked);
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
}
