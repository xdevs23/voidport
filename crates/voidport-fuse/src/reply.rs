//! A reply goes back through the descriptor that read the request, because
//! the kernel matches a reply only against the requests read through the
//! descriptor that receives it (`fuse_dev_do_write` in `fs/fuse/dev.c`,
//! Linux 7.3).

use std::ffi::OsStr;
use std::marker::PhantomData;
use std::os::unix::ffi::OsStrExt as _;
use std::sync::Arc;
use std::time::Duration;

use rustix::fs::FileType;
use rustix::io::Errno;
use zerocopy::IntoBytes as _;
use zerocopy::byteorder::native_endian::{I32, U32, U64};

use crate::abi;
use crate::attributes::{self, Attributes, Entry};
use crate::device::Device;
use crate::flags::{FopenFlags, PollEvents};
use crate::lock::FileLock;

#[derive(Debug)]
pub(crate) struct Reply {
    device: Arc<Device>,
    unique: u64,
    answered: bool,
}

impl Reply {
    pub(crate) fn new(device: Arc<Device>, unique: u64) -> Self {
        Self {
            device,
            unique,
            answered: false,
        }
    }

    fn ok(mut self, payload: [&[u8]; 2]) {
        let sent = self.device.reply_ok(self.unique, payload);
        self.sent(sent);
    }

    pub(crate) fn error(mut self, error: Errno) {
        let sent = self.device.reply_error(self.unique, error);
        self.sent(sent);
    }

    fn sent(&mut self, sent: Result<(), Errno>) {
        self.answered = true;
        match sent {
            Ok(()) => {}
            // The descriptor has no such request: it ended before its reply
            // arrived, because the connection was aborted, the request was sent
            // again or it was answered already, or, for an interrupt, another
            // descriptor read the request.
            Err(Errno::NOENT) => {
                tracing::debug!(unique = self.unique, "the request ended before its reply");
            }
            Err(error) => {
                tracing::error!(unique = self.unique, %error, "a reply could not be written");
            }
        }
    }
}

impl Drop for Reply {
    fn drop(&mut self) {
        if !self.answered {
            tracing::warn!(
                unique = self.unique,
                "a request was left without a reply; answering EIO"
            );
            let sent = self.device.reply_error(self.unique, Errno::IO);
            self.sent(sent);
        }
    }
}

pub trait ErrorReply {
    fn error(self, error: Errno);
}

macro_rules! reply_types {
    ($($(#[$meta:meta])* $name:ident;)*) => {$(
        $(#[$meta])*
        #[derive(Debug)]
        pub struct $name(pub(crate) Reply);

        impl ErrorReply for $name {
            fn error(self, error: Errno) {
                self.0.error(error);
            }
        }
    )*};
}

reply_types! {
    ReplyEntry;
    ReplyAttr;
    ReplyData;
    ReplyEmpty;
    ReplyOpen;
    ReplyWrite;
    ReplyStatfs;
    ReplyXattr;
    ReplyCreate;
    ReplyLock;
    ReplyPoll;
    /// The answer to an ioctl, which can only be an error.
    ReplyIoctl;
}

impl ReplyEntry {
    pub fn entry(self, entry: &Entry) {
        self.0.ok([entry.encode().as_bytes(), &[]]);
    }
}

impl ReplyAttr {
    pub fn attr(self, attributes: &Attributes, valid: Duration) {
        let reply = abi::AttrOut {
            attr_valid: U64::new(valid.as_secs()),
            attr_valid_nsec: U32::new(valid.subsec_nanos()),
            dummy: U32::ZERO,
            attr: attributes.encode(),
        };
        self.0.ok([reply.as_bytes(), &[]]);
    }
}

impl ReplyData {
    /// For a read, fewer bytes than were asked for mean the end of the file.
    pub fn data(self, data: &[u8]) {
        self.0.ok([data, &[]]);
    }
}

impl ReplyEmpty {
    pub fn ok(self) {
        self.0.ok([&[], &[]]);
    }
}

impl ReplyOpen {
    pub fn opened(self, handle: u64, flags: FopenFlags) {
        self.0.ok([open_out(handle, flags).as_bytes(), &[]]);
    }
}

fn open_out(handle: u64, flags: FopenFlags) -> abi::OpenOut {
    abi::OpenOut {
        fh: U64::new(handle),
        open_flags: U32::new(flags.bits()),
        backing_id: I32::ZERO,
    }
}

impl ReplyWrite {
    pub fn written(self, size: u32) {
        let reply = abi::WriteOut {
            size: U32::new(size),
            padding: U32::ZERO,
        };
        self.0.ok([reply.as_bytes(), &[]]);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FilesystemStats {
    /// The size in blocks of `fragment_size`.
    pub blocks: u64,
    pub free_blocks: u64,
    /// The free blocks an unprivileged user may use.
    pub available_blocks: u64,
    pub files: u64,
    pub free_files: u64,
    pub block_size: u32,
    pub name_length: u32,
    pub fragment_size: u32,
}

impl ReplyStatfs {
    pub fn statfs(self, stats: &FilesystemStats) {
        let reply = abi::StatfsOut {
            blocks: U64::new(stats.blocks),
            bfree: U64::new(stats.free_blocks),
            bavail: U64::new(stats.available_blocks),
            files: U64::new(stats.files),
            ffree: U64::new(stats.free_files),
            bsize: U32::new(stats.block_size),
            namelen: U32::new(stats.name_length),
            frsize: U32::new(stats.fragment_size),
            padding: U32::ZERO,
            spare: [U32::ZERO; 6],
        };
        self.0.ok([reply.as_bytes(), &[]]);
    }
}

impl ReplyXattr {
    /// Answers a request of size 0 with the size the value or the list has.
    pub fn size(self, size: u32) {
        let reply = abi::GetxattrOut {
            size: U32::new(size),
            padding: U32::ZERO,
        };
        self.0.ok([reply.as_bytes(), &[]]);
    }

    pub fn data(self, data: &[u8]) {
        self.0.ok([data, &[]]);
    }
}

impl ReplyCreate {
    pub fn created(self, entry: &Entry, handle: u64, flags: FopenFlags) {
        let reply = abi::CreateOut {
            entry: entry.encode(),
            open: open_out(handle, flags),
        };
        self.0.ok([reply.as_bytes(), &[]]);
    }
}

impl ReplyLock {
    /// Answers with the lock that conflicts, or with the lock asked about and
    /// the unlock type when none does.
    pub fn lock(self, lock: &FileLock) {
        let reply = abi::LkOut { lk: lock.encode() };
        self.0.ok([reply.as_bytes(), &[]]);
    }
}

impl ReplyPoll {
    pub fn ready(self, events: PollEvents) {
        let reply = abi::PollOut {
            revents: U32::new(events.bits()),
            padding: U32::ZERO,
        };
        self.0.ok([reply.as_bytes(), &[]]);
    }
}

#[derive(Debug)]
pub enum Plain {}

/// The kernel counts a lookup of every entry it receives, as it does for the
/// answer to a lookup (`fuse_direntplus_link` in `fs/fuse/readdir.c`,
/// Linux 7.3).
#[derive(Debug)]
pub enum Plus {}

/// Entries are added up to the size the kernel asked for, and the buffer grows
/// with them.
#[derive(Debug)]
pub struct ReplyListing<Kind> {
    reply: Reply,
    buffer: Vec<u8>,
    limit: usize,
    kind: PhantomData<Kind>,
}

pub type ReplyDirectory = ReplyListing<Plain>;

pub type ReplyDirectoryPlus = ReplyListing<Plus>;

impl<Kind> ReplyListing<Kind> {
    pub(crate) fn new(reply: Reply, size: u32) -> Self {
        Self {
            reply,
            buffer: Vec::new(),
            limit: size as usize,
            kind: PhantomData,
        }
    }

    /// Returns `true` when the record does not fit, in which case nothing was
    /// added. Records are padded to 8 bytes as the kernel reads them.
    fn push(&mut self, head: &[u8], name: &[u8]) -> bool {
        let end = self.buffer.len() + (head.len() + name.len()).next_multiple_of(8);
        if end > self.limit {
            return true;
        }
        self.buffer.extend_from_slice(head);
        self.buffer.extend_from_slice(name);
        self.buffer.resize(end, 0);
        false
    }

    /// Answers with the entries added, where none means the end of the
    /// directory.
    pub fn ok(self) {
        self.reply.ok([&self.buffer, &[]]);
    }
}

impl<Kind> ErrorReply for ReplyListing<Kind> {
    fn error(self, error: Errno) {
        self.reply.error(error);
    }
}

impl ReplyListing<Plain> {
    /// Returns `true` when the entry does not fit into the size the kernel
    /// asked for. Nothing was added then, and the reply is ready to be sent.
    #[must_use]
    pub fn add(&mut self, ino: u64, offset: u64, kind: FileType, name: &OsStr) -> bool {
        let name = name.as_bytes();
        let Some(dirent) = dirent(ino, offset, kind, name) else {
            return true;
        };
        self.push(dirent.as_bytes(), name)
    }
}

impl ReplyListing<Plus> {
    /// Returns `true` when the entry does not fit into the size the kernel
    /// asked for. Nothing was added then, and the reply is ready to be sent.
    #[must_use]
    pub fn add(&mut self, name: &OsStr, offset: u64, entry: &Entry) -> bool {
        let name = name.as_bytes();
        let attributes = &entry.attributes;
        let Some(dirent) = dirent(attributes.ino, offset, attributes.kind, name) else {
            return true;
        };
        let record = abi::Direntplus {
            entry_out: entry.encode(),
            dirent,
        };
        self.push(record.as_bytes(), name)
    }
}

/// The head of the record of `name`, or `None` for a name too long for any
/// reply.
fn dirent(ino: u64, offset: u64, kind: FileType, name: &[u8]) -> Option<abi::Dirent> {
    Some(abi::Dirent {
        ino: U64::new(ino),
        off: U64::new(offset),
        namelen: U32::new(u32::try_from(name.len()).ok()?),
        dirent_type: U32::new(attributes::dirent_type(kind)),
    })
}

/// Dropping it sends nothing, which tells the kernel that the interrupt was
/// taken. The request it names still needs a separate answer.
///
/// An answer is written through every descriptor of the session, because
/// the kernel takes it only through the descriptor that read the request the
/// interrupt names, and rejects it through every other. The kernel reads
/// these answers in `fuse_dev_do_write` (`fs/fuse/dev.c`, Linux 7.3).
#[derive(Debug)]
pub struct ReplyInterrupt {
    devices: Arc<[Arc<Device>]>,
    unique: u64,
}

impl ReplyInterrupt {
    pub(crate) fn new(devices: Arc<[Arc<Device>]>, unique: u64) -> Self {
        Self { devices, unique }
    }

    /// Asks the kernel to send the interrupt again: the request it names has
    /// not been handed to the filesystem yet.
    pub fn retry(self) {
        self.answer(Errno::AGAIN);
    }

    /// Tells the kernel that this filesystem takes no interrupts, which stops
    /// them for the rest of the connection.
    pub fn unsupported(self) {
        self.answer(Errno::NOSYS);
    }

    fn answer(&self, error: Errno) {
        for device in self.devices.iter() {
            Reply::new(Arc::clone(device), self.unique).error(error);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixDatagram;

    use zerocopy::FromBytes as _;

    use super::*;
    use crate::attributes::tests::attributes;
    use crate::device::tests::{answer, kernel};

    fn reply() -> (Reply, UnixDatagram) {
        let (device, kernel) = kernel(&[]);
        (Reply::new(Arc::new(device), 77), kernel)
    }

    fn entry() -> Entry {
        Entry {
            node: 5,
            generation: 0,
            attributes: attributes(),
            entry_valid: Duration::from_secs(1),
            attr_valid: Duration::from_secs(2),
        }
    }

    #[test]
    fn a_dropped_reply_answers_eio() {
        let (reply, kernel) = reply();
        drop(ReplyData(reply));
        let (header, _) = answer(&kernel);
        assert_eq!(header.error.get(), -Errno::IO.raw_os_error());
    }

    #[test]
    fn a_create_is_the_entry_followed_by_the_open() {
        let (reply, kernel) = reply();
        ReplyCreate(reply).created(&entry(), 33, FopenFlags::DIRECT_IO);
        let (header, payload) = answer(&kernel);
        assert_eq!(header.error.get(), 0);
        let created = abi::CreateOut::read_from_bytes(&payload).expect("one create reply");
        assert_eq!(created.entry.nodeid.get(), 5);
        assert_eq!(created.open.fh.get(), 33);
        assert_eq!(created.open.open_flags.get(), 1);
    }

    #[test]
    fn a_listing_stops_at_the_size_the_kernel_asked_for() {
        let (reply, kernel) = reply();
        let mut listing = ReplyDirectory::new(reply, 72);
        assert!(!listing.add(3, 1, FileType::Directory, OsStr::new("a")));
        assert!(!listing.add(4, 2, FileType::RegularFile, OsStr::new("abcdefghij")));
        assert!(listing.add(5, 3, FileType::RegularFile, OsStr::new("b")));
        listing.ok();

        let (_, payload) = answer(&kernel);
        assert_eq!(
            payload.len(),
            32 + 40,
            "a 1-byte name pads to 32, a 10-byte one to 40"
        );
        let (first, rest) = abi::Dirent::read_from_prefix(&payload).expect("a record");
        assert_eq!(
            (first.ino.get(), first.off.get(), first.namelen.get()),
            (3, 1, 1)
        );
        assert_eq!(first.dirent_type.get(), 4);
        assert_eq!(&rest[..8], b"a\0\0\0\0\0\0\0");
        let (second, name) = abi::Dirent::read_from_prefix(&rest[8..]).expect("a record");
        assert_eq!(second.ino.get(), 4);
        assert_eq!(&name[..10], b"abcdefghij");
    }

    #[test]
    fn an_entry_with_attributes_shows_its_ino_in_the_listing() {
        let (reply, kernel) = reply();
        let mut listing = ReplyDirectoryPlus::new(reply, 4096);
        assert!(!listing.add(OsStr::new("file"), 7, &entry()));
        listing.ok();

        let (_, payload) = answer(&kernel);
        assert_eq!(payload.len(), 160);
        let (record, name) = abi::Direntplus::read_from_prefix(&payload).expect("a record");
        assert_eq!(record.entry_out.nodeid.get(), 5);
        assert_eq!(record.dirent.ino.get(), 9);
        assert_eq!(record.dirent.off.get(), 7);
        assert_eq!(record.dirent.dirent_type.get(), 8);
        assert_eq!(&name[..4], b"file");
    }

    #[test]
    fn an_interrupt_answer_goes_through_every_descriptor() {
        let (first, first_kernel) = kernel(&[]);
        let (second, second_kernel) = kernel(&[]);
        let devices: Arc<[Arc<Device>]> = Arc::from([Arc::new(first), Arc::new(second)]);
        ReplyInterrupt::new(devices, 9).retry();
        for kernel in [first_kernel, second_kernel] {
            let (header, _) = answer(&kernel);
            assert_eq!(header.unique.get(), 9);
            assert_eq!(header.error.get(), -Errno::AGAIN.raw_os_error());
        }
    }
}
