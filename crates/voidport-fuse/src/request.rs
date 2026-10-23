//! Names and data borrow from the buffer the request was read into, so a
//! filesystem copies what it stores past the call that hands the operation
//! over.

use std::ffi::{CStr, OsStr};
use std::fmt;
use std::os::unix::ffi::OsStrExt as _;

use rustix::fs::{OFlags, RenameFlags, XattrFlags};
use rustix::io::Errno;
use zerocopy::byteorder::native_endian::{U32, U64};
use zerocopy::{FromBytes, Immutable, KnownLayout, Unaligned};

use crate::abi::{self, opcode, setattr};
use crate::attributes::Timestamp;
use crate::flags::PollEvents;
use crate::lock::FileLock;
use crate::reply::{
    ErrorReply as _, Reply, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory, ReplyDirectoryPlus,
    ReplyEmpty, ReplyEntry, ReplyInterrupt, ReplyIoctl, ReplyLock, ReplyOpen, ReplyPoll,
    ReplyStatfs, ReplyWrite, ReplyXattr,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request {
    /// The id of the request, exactly as the kernel sent it. An interrupt
    /// names the request it interrupts by it.
    pub unique: u64,
    pub uid: u32,
    pub gid: u32,
    pub pid: u32,
}

#[derive(Clone, Copy, Debug)]
pub struct Child<'a> {
    pub parent: u64,
    pub name: &'a OsStr,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Forget {
    pub node: u64,
    pub lookups: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct Getattr {
    pub node: u64,
    pub handle: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetTime {
    Now,
    At(Timestamp),
}

/// A change of attributes. Every field left `None` is unchanged.
#[derive(Clone, Copy, Debug)]
pub struct Setattr {
    pub node: u64,
    pub mode: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub size: Option<u64>,
    pub atime: Option<SetTime>,
    pub mtime: Option<SetTime>,
    pub ctime: Option<Timestamp>,
    pub handle: Option<u64>,
}

#[derive(Clone, Copy, Debug)]
pub struct Readlink {
    pub node: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct Symlink<'a> {
    pub parent: u64,
    pub name: &'a OsStr,
    pub target: &'a OsStr,
}

/// A request to create a file that is not a directory, a link or a regular
/// file opened at once.
#[derive(Clone, Copy, Debug)]
pub struct Mknod<'a> {
    pub parent: u64,
    pub name: &'a OsStr,
    pub mode: u32,
    pub umask: u32,
    pub rdev: u32,
}

#[derive(Clone, Copy, Debug)]
pub struct Mkdir<'a> {
    pub parent: u64,
    pub name: &'a OsStr,
    pub mode: u32,
    pub umask: u32,
}

#[derive(Clone, Copy, Debug)]
pub struct Rename<'a> {
    pub parent: u64,
    pub name: &'a OsStr,
    pub new_parent: u64,
    pub new_name: &'a OsStr,
    /// The flags of `renameat2(2)`, empty for a plain rename. A flag of a
    /// newer kernel is passed on.
    pub flags: RenameFlags,
}

#[derive(Clone, Copy, Debug)]
pub struct Link<'a> {
    pub node: u64,
    pub new_parent: u64,
    pub new_name: &'a OsStr,
}

#[derive(Clone, Copy, Debug)]
pub struct Open {
    pub node: u64,
    /// The flags of `open(2)`, every bit as the process gave it.
    pub flags: OFlags,
}

#[derive(Clone, Copy, Debug)]
pub struct Read {
    pub node: u64,
    pub handle: u64,
    /// Where to start: a byte offset in a file, or the offset a directory
    /// entry returned to continue after it.
    pub offset: u64,
    pub size: u32,
}

#[derive(Clone, Copy)]
pub struct Write<'a> {
    pub node: u64,
    pub handle: u64,
    pub offset: u64,
    pub data: &'a [u8],
    /// Whether the write clears setuid and setgid, which the kernel asks for
    /// when the writer may not set them.
    pub kill_suid_gid: bool,
}

/// Shows the length of the data in place of the data, which may be as large
/// as the largest write the kernel sends.
impl fmt::Debug for Write<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Write")
            .field("node", &self.node)
            .field("handle", &self.handle)
            .field("offset", &self.offset)
            .field("length", &self.data.len())
            .field("kill_suid_gid", &self.kill_suid_gid)
            .finish()
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Statfs {
    pub node: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct Release {
    pub node: u64,
    pub handle: u64,
    pub flags: u32,
    /// The lock holder whose `flock(2)` locks to release, where there are any.
    pub lock_owner: Option<u64>,
    pub flush: bool,
}

/// A request to flush an open file, made on every close of a descriptor.
#[derive(Clone, Copy, Debug)]
pub struct Flush {
    pub node: u64,
    pub handle: u64,
    pub lock_owner: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct Fsync {
    pub node: u64,
    pub handle: u64,
    pub datasync: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct Setxattr<'a> {
    pub node: u64,
    pub name: &'a OsStr,
    pub value: &'a [u8],
    /// The flags of `setxattr(2)`, every bit as the process gave it.
    pub flags: XattrFlags,
}

#[derive(Clone, Copy, Debug)]
pub struct Getxattr<'a> {
    pub node: u64,
    pub name: &'a OsStr,
    /// The size of the buffer of the caller, 0 to ask for the size alone.
    pub size: u32,
}

#[derive(Clone, Copy, Debug)]
pub struct Listxattr {
    pub node: u64,
    /// The size of the buffer of the caller, 0 to ask for the size alone.
    pub size: u32,
}

#[derive(Clone, Copy, Debug)]
pub struct Removexattr<'a> {
    pub node: u64,
    pub name: &'a OsStr,
}

#[derive(Clone, Copy, Debug)]
pub struct Create<'a> {
    pub parent: u64,
    pub name: &'a OsStr,
    pub mode: u32,
    pub umask: u32,
    /// The flags of `open(2)`, every bit as the process gave it.
    pub flags: OFlags,
}

#[derive(Clone, Copy, Debug)]
pub struct Getlk {
    pub node: u64,
    pub handle: u64,
    pub owner: u64,
    pub lock: FileLock,
}

#[derive(Clone, Copy, Debug)]
pub struct Setlk {
    pub node: u64,
    pub handle: u64,
    pub owner: u64,
    pub lock: FileLock,
    pub wait: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Interrupt {
    /// The [`Request::unique`] of the request it interrupts.
    pub target: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct Ioctl<'a> {
    pub node: u64,
    pub handle: u64,
    /// The `FUSE_IOCTL_*` flags.
    pub flags: u32,
    pub command: u32,
    pub input: &'a [u8],
    pub output_size: u32,
}

#[derive(Clone, Copy, Debug)]
pub struct Poll {
    pub node: u64,
    pub handle: u64,
    /// The handle the kernel would be woken through.
    pub kernel_handle: u64,
    /// The `FUSE_POLL_*` flags.
    pub flags: u32,
    pub events: PollEvents,
}

macro_rules! operations {
    ($lifetime:lifetime; $($(#[$meta:meta])* $variant:ident($arguments:ty, $reply:ty),)*) => {
        #[derive(Debug)]
        pub enum Operation<$lifetime> {
            /// Give back lookups. The kernel does not expect a reply.
            Forget(Forget),
            Interrupt(Interrupt, ReplyInterrupt),
            $($(#[$meta])* $variant($arguments, $reply),)*
        }

        impl Operation<'_> {
            /// The kernel stops sending some operations for good once they are
            /// answered `ENOSYS`, and falls back to others where it can.
            pub fn unsupported(self) {
                tracing::warn!(operation = ?self, "unsupported FUSE operation, answered ENOSYS");
                match self {
                    Self::Forget(_) => {}
                    Self::Interrupt(_, reply) => reply.unsupported(),
                    $(Self::$variant(_, reply) => reply.error(Errno::NOSYS),)*
                }
            }
        }
    };
}

operations! {
    'a;
    Lookup(Child<'a>, ReplyEntry),
    Getattr(Getattr, ReplyAttr),
    Setattr(Setattr, ReplyAttr),
    Readlink(Readlink, ReplyData),
    Symlink(Symlink<'a>, ReplyEntry),
    Mknod(Mknod<'a>, ReplyEntry),
    Mkdir(Mkdir<'a>, ReplyEntry),
    Unlink(Child<'a>, ReplyEmpty),
    Rmdir(Child<'a>, ReplyEmpty),
    Rename(Rename<'a>, ReplyEmpty),
    Link(Link<'a>, ReplyEntry),
    Open(Open, ReplyOpen),
    Read(Read, ReplyData),
    Write(Write<'a>, ReplyWrite),
    Statfs(Statfs, ReplyStatfs),
    Release(Release, ReplyEmpty),
    Fsync(Fsync, ReplyEmpty),
    Setxattr(Setxattr<'a>, ReplyEmpty),
    Getxattr(Getxattr<'a>, ReplyXattr),
    Listxattr(Listxattr, ReplyXattr),
    Removexattr(Removexattr<'a>, ReplyEmpty),
    Flush(Flush, ReplyEmpty),
    Opendir(Open, ReplyOpen),
    Readdir(Read, ReplyDirectory),
    Releasedir(Release, ReplyEmpty),
    Fsyncdir(Fsync, ReplyEmpty),
    Getlk(Getlk, ReplyLock),
    Setlk(Setlk, ReplyEmpty),
    Create(Create<'a>, ReplyCreate),
    Ioctl(Ioctl<'a>, ReplyIoctl),
    Poll(Poll, ReplyPoll),
    Readdirplus(Read, ReplyDirectoryPlus),
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Message<'a> {
    pub(crate) header: &'a abi::InHeader,
    /// The arguments, without the extensions some requests contain after them.
    pub(crate) arguments: &'a [u8],
}

impl<'a> Message<'a> {
    pub(crate) fn parse(bytes: &'a [u8]) -> Option<Self> {
        let (header, rest) = abi::InHeader::ref_from_prefix(bytes).ok()?;
        let length = usize::try_from(header.len.get()).ok()?;
        let body = rest.get(..length.checked_sub(size_of::<abi::InHeader>())?)?;
        let extensions = usize::from(header.total_extlen.get()) * 8;
        let arguments = body.get(..body.len().checked_sub(extensions)?)?;
        Some(Self { header, arguments })
    }

    pub(crate) fn opcode(&self) -> u32 {
        self.header.opcode.get()
    }

    /// The kernel waits for every request but FUSE_FORGET, FUSE_BATCH_FORGET
    /// and FUSE_INTERRUPT (`fuse_queue_forget` and `queue_interrupt` in
    /// `fs/fuse/dev.c`, Linux 7.3).
    pub(crate) fn expects_reply(&self) -> bool {
        !matches!(
            self.opcode(),
            opcode::FORGET | opcode::BATCH_FORGET | opcode::INTERRUPT
        )
    }

    pub(crate) fn unique(&self) -> u64 {
        self.header.unique.get()
    }

    pub(crate) fn request(&self) -> Request {
        Request {
            unique: self.unique(),
            uid: self.header.uid.get(),
            gid: self.header.gid.get(),
            pid: self.header.pid.get(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Refusal {
    Malformed,
    Unsupported,
    /// The opcode is one this crate does not decode, and the kernel sends it
    /// to find out whether the filesystem has it. Once it is answered
    /// `ENOSYS`, the kernel does without it for the rest of the connection.
    HasFallback,
    OffsetTooLarge,
}

impl Refusal {
    pub(crate) fn errno(self) -> Errno {
        match self {
            Self::Malformed => Errno::IO,
            Self::Unsupported | Self::HasFallback => Errno::NOSYS,
            Self::OffsetTooLarge => Errno::INVAL,
        }
    }
}

struct Arguments<'a>(&'a [u8]);

impl<'a> Arguments<'a> {
    fn fixed<T: FromBytes + KnownLayout + Immutable + Unaligned>(
        &mut self,
    ) -> Result<&'a T, Refusal> {
        let (value, rest) = T::ref_from_prefix(self.0).map_err(|_| Refusal::Malformed)?;
        self.0 = rest;
        Ok(value)
    }

    fn name(&mut self) -> Result<&'a OsStr, Refusal> {
        let name = CStr::from_bytes_until_nul(self.0).map_err(|_| Refusal::Malformed)?;
        self.0 = &self.0[name.to_bytes_with_nul().len()..];
        Ok(OsStr::from_bytes(name.to_bytes()))
    }

    fn bytes(&mut self, length: u32) -> Result<&'a [u8], Refusal> {
        let length = usize::try_from(length).map_err(|_| Refusal::Malformed)?;
        let (bytes, rest) = self.0.split_at_checked(length).ok_or(Refusal::Malformed)?;
        self.0 = rest;
        Ok(bytes)
    }

    fn exactly(&mut self, length: u32) -> Result<&'a [u8], Refusal> {
        let rest = std::mem::take(&mut self.0);
        (usize::try_from(length).ok() == Some(rest.len()))
            .then_some(rest)
            .ok_or(Refusal::Malformed)
    }
}

/// An offset in a file, which cannot pass the largest signed 64-bit value.
fn file_offset(offset: u64) -> Result<u64, Refusal> {
    i64::try_from(offset)
        .map(|_| offset)
        .map_err(|_| Refusal::OffsetTooLarge)
}

fn timestamp(seconds: U64, nanoseconds: U32) -> Timestamp {
    Timestamp {
        seconds: seconds.get().cast_signed(),
        nanoseconds: nanoseconds.get(),
    }
}

impl<'a> Child<'a> {
    fn decode(parent: u64, arguments: &mut Arguments<'a>) -> Result<Self, Refusal> {
        Ok(Self {
            parent,
            name: arguments.name()?,
        })
    }
}

impl Getattr {
    fn decode(node: u64, arguments: &mut Arguments<'_>) -> Result<Self, Refusal> {
        let getattr = arguments.fixed::<abi::GetattrIn>()?;
        let handle = (getattr.getattr_flags.get() & abi::GETATTR_FH != 0).then(|| getattr.fh.get());
        Ok(Self { node, handle })
    }
}

impl Setattr {
    fn decode(node: u64, arguments: &mut Arguments<'_>) -> Result<Self, Refusal> {
        let change = arguments.fixed::<abi::SetattrIn>()?;
        let valid = change.valid.get();
        let has = |bit: u32| valid & bit != 0;
        let time = |set: u32, now: u32, seconds: U64, nanoseconds: U32| {
            if has(now) {
                Some(SetTime::Now)
            } else {
                has(set).then(|| SetTime::At(timestamp(seconds, nanoseconds)))
            }
        };
        Ok(Self {
            node,
            mode: has(setattr::MODE).then(|| change.mode.get()),
            uid: has(setattr::UID).then(|| change.uid.get()),
            gid: has(setattr::GID).then(|| change.gid.get()),
            size: has(setattr::SIZE).then(|| change.size.get()),
            atime: time(
                setattr::ATIME,
                setattr::ATIME_NOW,
                change.atime,
                change.atimensec,
            ),
            mtime: time(
                setattr::MTIME,
                setattr::MTIME_NOW,
                change.mtime,
                change.mtimensec,
            ),
            ctime: has(setattr::CTIME).then(|| timestamp(change.ctime, change.ctimensec)),
            handle: has(setattr::FH).then(|| change.fh.get()),
        })
    }
}

impl<'a> Symlink<'a> {
    fn decode(parent: u64, arguments: &mut Arguments<'a>) -> Result<Self, Refusal> {
        Ok(Self {
            parent,
            name: arguments.name()?,
            target: arguments.name()?,
        })
    }
}

impl<'a> Mknod<'a> {
    fn decode(parent: u64, arguments: &mut Arguments<'a>) -> Result<Self, Refusal> {
        let mknod = arguments.fixed::<abi::MknodIn>()?;
        Ok(Self {
            parent,
            name: arguments.name()?,
            mode: mknod.mode.get(),
            umask: mknod.umask.get(),
            rdev: mknod.rdev.get(),
        })
    }
}

impl<'a> Mkdir<'a> {
    fn decode(parent: u64, arguments: &mut Arguments<'a>) -> Result<Self, Refusal> {
        let mkdir = arguments.fixed::<abi::MkdirIn>()?;
        Ok(Self {
            parent,
            name: arguments.name()?,
            mode: mkdir.mode.get(),
            umask: mkdir.umask.get(),
        })
    }
}

impl<'a> Rename<'a> {
    fn plain(parent: u64, arguments: &mut Arguments<'a>) -> Result<Self, Refusal> {
        let new_parent = arguments.fixed::<abi::RenameIn>()?.newdir.get();
        Self::names(parent, new_parent, RenameFlags::empty(), arguments)
    }

    fn with_flags(parent: u64, arguments: &mut Arguments<'a>) -> Result<Self, Refusal> {
        let rename = arguments.fixed::<abi::Rename2In>()?;
        let flags = RenameFlags::from_bits_retain(rename.flags.get());
        Self::names(parent, rename.newdir.get(), flags, arguments)
    }

    fn names(
        parent: u64,
        new_parent: u64,
        flags: RenameFlags,
        arguments: &mut Arguments<'a>,
    ) -> Result<Self, Refusal> {
        Ok(Self {
            parent,
            name: arguments.name()?,
            new_parent,
            new_name: arguments.name()?,
            flags,
        })
    }
}

impl<'a> Link<'a> {
    fn decode(new_parent: u64, arguments: &mut Arguments<'a>) -> Result<Self, Refusal> {
        let link = arguments.fixed::<abi::LinkIn>()?;
        Ok(Self {
            node: link.oldnodeid.get(),
            new_parent,
            new_name: arguments.name()?,
        })
    }
}

impl Open {
    fn decode(node: u64, arguments: &mut Arguments<'_>) -> Result<Self, Refusal> {
        let open = arguments.fixed::<abi::OpenIn>()?;
        Ok(Self {
            node,
            flags: OFlags::from_bits_retain(open.flags.get()),
        })
    }
}

impl Read {
    fn decode(node: u64, arguments: &mut Arguments<'_>) -> Result<Self, Refusal> {
        let read = arguments.fixed::<abi::ReadIn>()?;
        Ok(Self {
            node,
            handle: read.fh.get(),
            offset: read.offset.get(),
            size: read.size.get(),
        })
    }

    fn of_file(node: u64, arguments: &mut Arguments<'_>) -> Result<Self, Refusal> {
        let read = Self::decode(node, arguments)?;
        file_offset(read.offset)?;
        Ok(read)
    }
}

impl<'a> Write<'a> {
    fn decode(node: u64, arguments: &mut Arguments<'a>) -> Result<Self, Refusal> {
        let write = arguments.fixed::<abi::WriteIn>()?;
        Ok(Self {
            node,
            handle: write.fh.get(),
            offset: file_offset(write.offset.get())?,
            data: arguments.exactly(write.size.get())?,
            kill_suid_gid: write.write_flags.get() & abi::WRITE_KILL_SUIDGID != 0,
        })
    }
}

impl Release {
    fn decode(node: u64, arguments: &mut Arguments<'_>) -> Result<Self, Refusal> {
        let release = arguments.fixed::<abi::ReleaseIn>()?;
        let flags = release.release_flags.get();
        Ok(Self {
            node,
            handle: release.fh.get(),
            flags: release.flags.get(),
            lock_owner: (flags & abi::RELEASE_FLOCK_UNLOCK != 0).then(|| release.lock_owner.get()),
            flush: flags & abi::RELEASE_FLUSH != 0,
        })
    }
}

impl Fsync {
    fn decode(node: u64, arguments: &mut Arguments<'_>) -> Result<Self, Refusal> {
        let fsync = arguments.fixed::<abi::FsyncIn>()?;
        Ok(Self {
            node,
            handle: fsync.fh.get(),
            datasync: fsync.fsync_flags.get() & abi::FSYNC_FDATASYNC != 0,
        })
    }
}

impl<'a> Setxattr<'a> {
    fn decode(node: u64, arguments: &mut Arguments<'a>) -> Result<Self, Refusal> {
        let setxattr = arguments.fixed::<abi::SetxattrIn>()?;
        Ok(Self {
            node,
            name: arguments.name()?,
            value: arguments.exactly(setxattr.size.get())?,
            flags: XattrFlags::from_bits_retain(setxattr.flags.get()),
        })
    }
}

impl<'a> Getxattr<'a> {
    fn decode(node: u64, arguments: &mut Arguments<'a>) -> Result<Self, Refusal> {
        let size = arguments.fixed::<abi::GetxattrIn>()?.size.get();
        Ok(Self {
            node,
            name: arguments.name()?,
            size,
        })
    }
}

impl Listxattr {
    fn decode(node: u64, arguments: &mut Arguments<'_>) -> Result<Self, Refusal> {
        let size = arguments.fixed::<abi::GetxattrIn>()?.size.get();
        Ok(Self { node, size })
    }
}

impl<'a> Removexattr<'a> {
    fn decode(node: u64, arguments: &mut Arguments<'a>) -> Result<Self, Refusal> {
        Ok(Self {
            node,
            name: arguments.name()?,
        })
    }
}

impl Flush {
    fn decode(node: u64, arguments: &mut Arguments<'_>) -> Result<Self, Refusal> {
        let flush = arguments.fixed::<abi::FlushIn>()?;
        Ok(Self {
            node,
            handle: flush.fh.get(),
            lock_owner: flush.lock_owner.get(),
        })
    }
}

fn lock_request(arguments: &mut Arguments<'_>) -> Result<(u64, u64, FileLock), Refusal> {
    let lk = arguments.fixed::<abi::LkIn>()?;
    let lock = FileLock::decode(&lk.lk).ok_or(Refusal::Malformed)?;
    Ok((lk.fh.get(), lk.owner.get(), lock))
}

impl Getlk {
    fn decode(node: u64, arguments: &mut Arguments<'_>) -> Result<Self, Refusal> {
        let (handle, owner, lock) = lock_request(arguments)?;
        Ok(Self {
            node,
            handle,
            owner,
            lock,
        })
    }
}

impl Setlk {
    fn decode(node: u64, arguments: &mut Arguments<'_>, wait: bool) -> Result<Self, Refusal> {
        let (handle, owner, lock) = lock_request(arguments)?;
        Ok(Self {
            node,
            handle,
            owner,
            lock,
            wait,
        })
    }
}

impl<'a> Create<'a> {
    fn decode(parent: u64, arguments: &mut Arguments<'a>) -> Result<Self, Refusal> {
        let create = arguments.fixed::<abi::CreateIn>()?;
        Ok(Self {
            parent,
            name: arguments.name()?,
            mode: create.mode.get(),
            umask: create.umask.get(),
            flags: OFlags::from_bits_retain(create.flags.get()),
        })
    }
}

impl<'a> Ioctl<'a> {
    fn decode(node: u64, arguments: &mut Arguments<'a>) -> Result<Self, Refusal> {
        let ioctl = arguments.fixed::<abi::IoctlIn>()?;
        Ok(Self {
            node,
            handle: ioctl.fh.get(),
            flags: ioctl.flags.get(),
            command: ioctl.cmd.get(),
            input: arguments.bytes(ioctl.in_size.get())?,
            output_size: ioctl.out_size.get(),
        })
    }
}

impl Poll {
    fn decode(node: u64, arguments: &mut Arguments<'_>) -> Result<Self, Refusal> {
        let poll = arguments.fixed::<abi::PollIn>()?;
        Ok(Self {
            node,
            handle: poll.fh.get(),
            kernel_handle: poll.kh.get(),
            flags: poll.flags.get(),
            events: PollEvents::from_bits_retain(poll.events.get()),
        })
    }
}

/// `reply` is called once the arguments decoded, so that a request rejected
/// here is answered by the caller with the errno of its [`Refusal`].
pub(crate) fn decode<'a>(
    message: &Message<'a>,
    reply: impl FnOnce() -> Reply,
) -> Result<Operation<'a>, Refusal> {
    let node = message.header.nodeid.get();
    let arguments = &mut Arguments(message.arguments);
    Ok(match message.opcode() {
        opcode::LOOKUP => Operation::Lookup(Child::decode(node, arguments)?, ReplyEntry(reply())),
        opcode::GETATTR => {
            Operation::Getattr(Getattr::decode(node, arguments)?, ReplyAttr(reply()))
        }
        opcode::SETATTR => {
            Operation::Setattr(Setattr::decode(node, arguments)?, ReplyAttr(reply()))
        }
        opcode::READLINK => Operation::Readlink(Readlink { node }, ReplyData(reply())),
        opcode::SYMLINK => {
            Operation::Symlink(Symlink::decode(node, arguments)?, ReplyEntry(reply()))
        }
        opcode::MKNOD => Operation::Mknod(Mknod::decode(node, arguments)?, ReplyEntry(reply())),
        opcode::MKDIR => Operation::Mkdir(Mkdir::decode(node, arguments)?, ReplyEntry(reply())),
        opcode::UNLINK => Operation::Unlink(Child::decode(node, arguments)?, ReplyEmpty(reply())),
        opcode::RMDIR => Operation::Rmdir(Child::decode(node, arguments)?, ReplyEmpty(reply())),
        opcode::RENAME => Operation::Rename(Rename::plain(node, arguments)?, ReplyEmpty(reply())),
        opcode::RENAME2 => {
            Operation::Rename(Rename::with_flags(node, arguments)?, ReplyEmpty(reply()))
        }
        opcode::LINK => Operation::Link(Link::decode(node, arguments)?, ReplyEntry(reply())),
        opcode::OPEN => Operation::Open(Open::decode(node, arguments)?, ReplyOpen(reply())),
        opcode::OPENDIR => Operation::Opendir(Open::decode(node, arguments)?, ReplyOpen(reply())),
        opcode::READ => Operation::Read(Read::of_file(node, arguments)?, ReplyData(reply())),
        opcode::WRITE => Operation::Write(Write::decode(node, arguments)?, ReplyWrite(reply())),
        opcode::STATFS => Operation::Statfs(Statfs { node }, ReplyStatfs(reply())),
        opcode::RELEASE => {
            Operation::Release(Release::decode(node, arguments)?, ReplyEmpty(reply()))
        }
        opcode::RELEASEDIR => {
            Operation::Releasedir(Release::decode(node, arguments)?, ReplyEmpty(reply()))
        }
        opcode::FSYNC => Operation::Fsync(Fsync::decode(node, arguments)?, ReplyEmpty(reply())),
        opcode::FSYNCDIR => {
            Operation::Fsyncdir(Fsync::decode(node, arguments)?, ReplyEmpty(reply()))
        }
        opcode::SETXATTR => {
            Operation::Setxattr(Setxattr::decode(node, arguments)?, ReplyEmpty(reply()))
        }
        opcode::GETXATTR => {
            Operation::Getxattr(Getxattr::decode(node, arguments)?, ReplyXattr(reply()))
        }
        opcode::LISTXATTR => {
            Operation::Listxattr(Listxattr::decode(node, arguments)?, ReplyXattr(reply()))
        }
        opcode::REMOVEXATTR => {
            Operation::Removexattr(Removexattr::decode(node, arguments)?, ReplyEmpty(reply()))
        }
        opcode::FLUSH => Operation::Flush(Flush::decode(node, arguments)?, ReplyEmpty(reply())),
        opcode::READDIR => {
            let read = Read::decode(node, arguments)?;
            Operation::Readdir(read, ReplyDirectory::new(reply(), read.size))
        }
        opcode::READDIRPLUS => {
            let read = Read::decode(node, arguments)?;
            Operation::Readdirplus(read, ReplyDirectoryPlus::new(reply(), read.size))
        }
        opcode::GETLK => Operation::Getlk(Getlk::decode(node, arguments)?, ReplyLock(reply())),
        opcode::SETLK => {
            Operation::Setlk(Setlk::decode(node, arguments, false)?, ReplyEmpty(reply()))
        }
        opcode::SETLKW => {
            Operation::Setlk(Setlk::decode(node, arguments, true)?, ReplyEmpty(reply()))
        }
        opcode::CREATE => Operation::Create(Create::decode(node, arguments)?, ReplyCreate(reply())),
        opcode::IOCTL => Operation::Ioctl(Ioctl::decode(node, arguments)?, ReplyIoctl(reply())),
        opcode::POLL => Operation::Poll(Poll::decode(node, arguments)?, ReplyPoll(reply())),
        // The kernel sends FUSE_STATX only for a birth time, and asks
        // FUSE_GETATTR for every other attribute once it is answered
        // `ENOSYS` (`fuse_update_get_attr` in `fs/fuse/dir.c`, Linux 7.2.10).
        // The attributes a filesystem returns through this crate contain no
        // birth time, so FUSE_GETATTR returns all of them.
        opcode::STATX => return Err(Refusal::HasFallback),
        _ => return Err(Refusal::Unsupported),
    })
}

pub(crate) fn forget(message: &Message<'_>) -> Result<Forget, Refusal> {
    let forget = Arguments(message.arguments).fixed::<abi::ForgetIn>()?;
    Ok(Forget {
        node: message.header.nodeid.get(),
        lookups: forget.nlookup.get(),
    })
}

pub(crate) fn batch_forget<'a>(
    message: &Message<'a>,
) -> Result<impl Iterator<Item = Forget> + 'a, Refusal> {
    let mut arguments = Arguments(message.arguments);
    let count = arguments.fixed::<abi::BatchForgetIn>()?.count.get();
    let count = usize::try_from(count).map_err(|_| Refusal::Malformed)?;
    let (forgets, _) = <[abi::ForgetOne]>::ref_from_prefix_with_elems(arguments.0, count)
        .map_err(|_| Refusal::Malformed)?;
    Ok(forgets.iter().map(|forget| Forget {
        node: forget.nodeid.get(),
        lookups: forget.nlookup.get(),
    }))
}

pub(crate) fn interrupt(message: &Message<'_>) -> Result<Interrupt, Refusal> {
    let interrupt = Arguments(message.arguments).fixed::<abi::InterruptIn>()?;
    Ok(Interrupt {
        target: interrupt.unique.get(),
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::Arc;

    use zerocopy::IntoBytes as _;
    use zerocopy::byteorder::native_endian::U16;

    use super::*;
    use crate::device::tests::discarding;
    use crate::lock::LockType;

    /// An opcode that no version of Linux defines.
    pub(crate) const UNKNOWN_OPCODE: u32 = 999;

    pub(crate) fn request(opcode: u32, node: u64, unique: u64, arguments: &[&[u8]]) -> Vec<u8> {
        let body: Vec<u8> = arguments.concat();
        let header = abi::InHeader {
            len: U32::new(u32::try_from(size_of::<abi::InHeader>() + body.len()).expect("small")),
            opcode: U32::new(opcode),
            unique: U64::new(unique),
            nodeid: U64::new(node),
            uid: U32::new(1000),
            gid: U32::new(100),
            pid: U32::new(4242),
            total_extlen: U16::ZERO,
            padding: U16::ZERO,
        };
        [header.as_bytes(), &body].concat()
    }

    fn decoded(bytes: &[u8]) -> Result<Operation<'_>, Refusal> {
        let message = Message::parse(bytes).expect("a whole request");
        let device = Arc::new(discarding());
        decode(&message, || Reply::new(device, message.unique()))
    }

    #[test]
    fn a_header_that_promises_more_than_was_read_is_refused() {
        let bytes = request(opcode::LOOKUP, 1, 2, &[b"name\0"]);
        assert!(Message::parse(&bytes).is_some());
        assert!(Message::parse(&bytes[..bytes.len() - 1]).is_none());
        assert!(Message::parse(&bytes[..39]).is_none());
    }

    #[test]
    fn extensions_are_cut_from_the_arguments() {
        let mut bytes = request(opcode::LOOKUP, 1, 2, &[b"name\0", &[7; 8]]);
        let (header, _) = abi::InHeader::mut_from_prefix(&mut bytes).expect("a header");
        header.total_extlen = U16::new(1);
        let message = Message::parse(&bytes).expect("a whole request");
        assert_eq!(message.arguments, b"name\0");
    }

    #[test]
    fn the_identity_of_a_request_is_its_header() {
        let bytes = request(opcode::READLINK, 9, 1 << 63 | 4, &[]);
        let message = Message::parse(&bytes).expect("a whole request");
        assert_eq!(
            message.request(),
            Request {
                unique: 1 << 63 | 4,
                uid: 1000,
                gid: 100,
                pid: 4242,
            },
            "a resent request still has the bit the kernel marked it with"
        );
    }

    #[test]
    fn two_names_follow_each_other() {
        let rename = abi::Rename2In {
            newdir: U64::new(8),
            flags: U32::new(RenameFlags::NOREPLACE.bits()),
            padding: U32::ZERO,
        };
        let bytes = request(opcode::RENAME2, 7, 2, &[rename.as_bytes(), b"old\0new\0"]);
        let Ok(Operation::Rename(rename, _)) = decoded(&bytes) else {
            panic!("a rename");
        };
        assert_eq!((rename.parent, rename.new_parent), (7, 8));
        assert_eq!(
            (rename.name, rename.new_name),
            (OsStr::new("old"), OsStr::new("new"))
        );
        assert_eq!(rename.flags, RenameFlags::NOREPLACE);

        let bytes = request(opcode::SYMLINK, 7, 2, &[b"link\0target\0"]);
        let Ok(Operation::Symlink(symlink, _)) = decoded(&bytes) else {
            panic!("a symlink");
        };
        assert_eq!(
            (symlink.name, symlink.target),
            (OsStr::new("link"), OsStr::new("target"))
        );
    }

    #[test]
    fn a_name_without_its_terminator_is_malformed() {
        let bytes = request(opcode::LOOKUP, 1, 2, &[b"name"]);
        assert_eq!(decoded(&bytes).err(), Some(Refusal::Malformed));
    }

    #[test]
    fn a_write_carries_exactly_its_data() {
        let write = |size: u32, offset: u64| abi::WriteIn {
            fh: U64::new(3),
            offset: U64::new(offset),
            size: U32::new(size),
            write_flags: U32::new(abi::WRITE_KILL_SUIDGID),
            ..abi::WriteIn::default()
        };
        let bytes = request(opcode::WRITE, 5, 2, &[write(4, 10).as_bytes(), b"data"]);
        let Ok(Operation::Write(written, _)) = decoded(&bytes) else {
            panic!("a write");
        };
        assert_eq!((written.node, written.handle, written.offset), (5, 3, 10));
        assert_eq!(written.data, b"data");
        assert!(written.kill_suid_gid);

        let bytes = request(opcode::WRITE, 5, 2, &[write(5, 10).as_bytes(), b"data"]);
        assert_eq!(decoded(&bytes).err(), Some(Refusal::Malformed));
        let bytes = request(
            opcode::WRITE,
            5,
            2,
            &[write(4, 1 << 63).as_bytes(), b"data"],
        );
        assert_eq!(decoded(&bytes).err(), Some(Refusal::OffsetTooLarge));
        assert_eq!(Refusal::OffsetTooLarge.errno(), Errno::INVAL);
    }

    #[test]
    fn a_change_of_attributes_has_only_the_fields_it_marks() {
        let change = abi::SetattrIn {
            valid: U32::new(setattr::MODE | setattr::ATIME | setattr::ATIME_NOW | setattr::MTIME),
            mode: U32::new(0o640),
            uid: U32::new(5),
            mtime: U64::new((-3_i64).cast_unsigned()),
            mtimensec: U32::new(7),
            ..abi::SetattrIn::default()
        };
        let bytes = request(opcode::SETATTR, 5, 2, &[change.as_bytes()]);
        let Ok(Operation::Setattr(change, _)) = decoded(&bytes) else {
            panic!("a setattr");
        };
        assert_eq!(change.mode, Some(0o640));
        assert_eq!(change.uid, None, "the uid is there but not marked");
        assert_eq!(change.atime, Some(SetTime::Now));
        assert_eq!(
            change.mtime,
            Some(SetTime::At(Timestamp {
                seconds: -3,
                nanoseconds: 7
            }))
        );
        assert_eq!(change.size, None);
        assert_eq!(change.handle, None);
    }

    #[test]
    fn an_extended_attribute_has_the_value_of_its_size() {
        let setxattr = abi::SetxattrIn {
            size: U32::new(3),
            flags: U32::new(1),
        };
        let bytes = request(
            opcode::SETXATTR,
            5,
            2,
            &[setxattr.as_bytes(), b"user.a\0abc"],
        );
        let Ok(Operation::Setxattr(set, _)) = decoded(&bytes) else {
            panic!("a setxattr");
        };
        assert_eq!(
            (set.name, set.value, set.flags),
            (OsStr::new("user.a"), &b"abc"[..], XattrFlags::CREATE)
        );

        let long = request(
            opcode::SETXATTR,
            5,
            2,
            &[setxattr.as_bytes(), b"user.a\0abcd"],
        );
        assert_eq!(decoded(&long).err(), Some(Refusal::Malformed));
    }

    #[test]
    fn a_release_has_a_lock_owner_only_where_it_unlocks() {
        let release = |flags: u32| abi::ReleaseIn {
            fh: U64::new(3),
            flags: U32::new(2),
            release_flags: U32::new(flags),
            lock_owner: U64::new(99),
        };
        let bytes = request(
            opcode::RELEASE,
            5,
            2,
            &[release(abi::RELEASE_FLUSH).as_bytes()],
        );
        let Ok(Operation::Release(plain, _)) = decoded(&bytes) else {
            panic!("a release");
        };
        assert_eq!(
            (plain.lock_owner, plain.flush, plain.flags),
            (None, true, 2)
        );
        let bytes = request(
            opcode::RELEASE,
            5,
            2,
            &[release(abi::RELEASE_FLOCK_UNLOCK).as_bytes()],
        );
        let Ok(Operation::Release(unlocking, _)) = decoded(&bytes) else {
            panic!("a release");
        };
        assert_eq!((unlocking.lock_owner, unlocking.flush), (Some(99), false));
    }

    #[test]
    fn a_lock_request_waits_only_as_setlkw() {
        let lk = abi::LkIn {
            fh: U64::new(3),
            owner: U64::new(11),
            lk: FileLock {
                start: 0,
                end: 9,
                lock_type: LockType::Write,
                pid: 77,
            }
            .encode(),
            ..abi::LkIn::default()
        };
        for (opcode, wait) in [(opcode::SETLK, false), (opcode::SETLKW, true)] {
            let bytes = request(opcode, 5, 2, &[lk.as_bytes()]);
            let Ok(Operation::Setlk(setlk, _)) = decoded(&bytes) else {
                panic!("a setlk");
            };
            assert_eq!(setlk.wait, wait);
            assert_eq!((setlk.owner, setlk.lock.end, setlk.lock.pid), (11, 9, 77));
        }
        let bytes = request(opcode::GETLK, 5, 2, &[lk.as_bytes()]);
        assert!(matches!(decoded(&bytes), Ok(Operation::Getlk(..))));

        let mut unknown = lk;
        unknown.lk.lock_type = U32::new(3);
        let bytes = request(opcode::SETLK, 5, 2, &[unknown.as_bytes()]);
        assert_eq!(
            decoded(&bytes).err(),
            Some(Refusal::Malformed),
            "a lock type Linux does not have"
        );
    }

    #[test]
    fn only_forgets_and_interrupts_go_without_a_reply() {
        for (opcode, expects) in [
            (opcode::FORGET, false),
            (opcode::BATCH_FORGET, false),
            (opcode::INTERRUPT, false),
            (opcode::LOOKUP, true),
            (opcode::DESTROY, true),
            (UNKNOWN_OPCODE, true),
        ] {
            let bytes = request(opcode, 1, 2, &[]);
            let message = Message::parse(&bytes).expect("a whole request");
            assert_eq!(message.expects_reply(), expects, "opcode {opcode}");
        }
    }

    #[test]
    fn an_opcode_this_crate_does_not_decode_is_unsupported() {
        let bytes = request(UNKNOWN_OPCODE, 5, 2, &[&[0; 24]]);
        assert_eq!(decoded(&bytes).err(), Some(Refusal::Unsupported));
        assert_eq!(Refusal::Unsupported.errno(), Errno::NOSYS);
    }

    #[test]
    fn statx_is_refused_as_an_opcode_the_kernel_does_without() {
        let bytes = request(opcode::STATX, 5, 2, &[&[0; 24]]);
        assert_eq!(decoded(&bytes).err(), Some(Refusal::HasFallback));
        assert_eq!(Refusal::HasFallback.errno(), Errno::NOSYS);
    }

    #[test]
    fn a_batch_of_forgets_is_one_forget_per_node() {
        let batch = abi::BatchForgetIn {
            count: U32::new(2),
            dummy: U32::ZERO,
        };
        let one = |node: u64, lookups: u64| abi::ForgetOne {
            nodeid: U64::new(node),
            nlookup: U64::new(lookups),
        };
        let bytes = request(
            opcode::BATCH_FORGET,
            0,
            2,
            &[batch.as_bytes(), one(3, 1).as_bytes(), one(4, 7).as_bytes()],
        );
        let message = Message::parse(&bytes).expect("a whole request");
        let forgets: Vec<Forget> = batch_forget(&message).expect("two forgets").collect();
        assert_eq!(
            forgets,
            [
                Forget {
                    node: 3,
                    lookups: 1
                },
                Forget {
                    node: 4,
                    lookups: 7
                }
            ]
        );

        let short = request(
            opcode::BATCH_FORGET,
            0,
            2,
            &[batch.as_bytes(), one(3, 1).as_bytes()],
        );
        let message = Message::parse(&short).expect("a whole request");
        assert!(
            batch_forget(&message).is_err(),
            "a count past the elements sent"
        );
    }

    #[test]
    fn an_interrupt_names_its_request() {
        let interrupt = abi::InterruptIn {
            unique: U64::new(40),
        };
        let bytes = request(opcode::INTERRUPT, 0, 41, &[interrupt.as_bytes()]);
        let message = Message::parse(&bytes).expect("a whole request");
        assert_eq!(super::interrupt(&message), Ok(Interrupt { target: 40 }));
    }
}
