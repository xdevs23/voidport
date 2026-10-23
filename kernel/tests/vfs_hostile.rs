// SPDX-License-Identifier: GPL-2.0

use super::guest::{counter, errno, list_past_dots, mount_peer_at};
use super::server::{Behaviour, Flow, Listed, Listing, State, Stream, send};
use crate::{LIMITS, Result, load_module, piece_of, response, unload_module};
use std::ffi::CStr;
use std::fs::{self};
use std::sync::Arc;
use voidport_proto::attr::{Attr, EntryOut};
use voidport_proto::frame::Frame;
use voidport_proto::opcode::Opcode;
use voidport_proto::ops::dir::EntryType;
use voidport_proto::ops::file::{ReadRequest, ReleaseResponse};
use voidport_proto::ops::node::StatfsResponse;
use zerocopy::IntoBytes;
use zerocopy::byteorder::little_endian::{U32, U64};

#[derive(Clone, Copy, Debug)]
enum Fault {
    Link(&'static [u8]),
    Name(&'static [u8]),
    LookupId(u64),
    DirectoryId(u64),
    EntryType(u32),
    Attribute(Attribute),
    Framing(Framing),
    Statfs(StatfsResponse),
    Listed(&'static [u8], u32, EntryType),
}

#[derive(Clone, Copy, Debug)]
enum Attribute {
    AccessNanoseconds(u32),
    ModificationNanoseconds(u32),
    ChangeNanoseconds(u32),
    Uid(u32),
    Gid(u32),
    Mode(u32),
}

impl Attribute {
    fn apply(self, attr: &mut Attr) {
        match self {
            Self::AccessNanoseconds(nsec) => attr.atime.nsec = U32::new(nsec),
            Self::ModificationNanoseconds(nsec) => attr.mtime.nsec = U32::new(nsec),
            Self::ChangeNanoseconds(nsec) => attr.ctime.nsec = U32::new(nsec),
            Self::Uid(uid) => attr.uid = U32::new(uid),
            Self::Gid(gid) => attr.gid = U32::new(gid),
            Self::Mode(mode) => attr.mode = U32::new(mode),
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Framing {
    NotificationFlags,
    NotificationId,
    NotificationResponse,
    Notification,
    StreamedNotification,
    Mismatch,
    Unsent,
    CutBody,
    PieceTooLong,
}

enum Next {
    Reply,
    Request,
    End,
}

impl Framing {
    fn bytes(self, id: u64, size: usize) -> Result<(Vec<u8>, Next)> {
        use voidport_proto::frame::{FLAG_RESPONSE, FLAGS_RESERVED_MASK, FrameHeader, FrameWriter};
        use voidport_proto::opcode::NotificationOpcode;
        use voidport_proto::ops::file::ReadResponse;
        use voidport_proto::ops::share::{
            SHARE_KIND_DIRECTORY, SHARE_MODE_RO, ShareEntryHeader, ShareSnapshotBegin,
            ShareSnapshotPart,
        };
        use voidport_proto::piece::Closing;
        let header = |flags, id| {
            FrameHeader::new(NotificationOpcode::ShareSnapshotBegin.as_u16(), flags, id)
                .as_bytes()
                .to_vec()
        };
        let mut buffer = [0; 128];
        Ok(match self {
            Self::NotificationFlags => (header(FLAGS_RESERVED_MASK, 0), Next::Request),
            Self::NotificationId => (header(0, 1), Next::Request),
            Self::NotificationResponse => (header(FLAG_RESPONSE, 0), Next::Request),
            Self::Notification => {
                let begin = ShareSnapshotBegin {
                    entries: U32::new(2),
                    reserved: U32::ZERO,
                };
                let frame = FrameWriter::notification(&mut buffer, &LIMITS, &begin)?;
                (frame.finish()?.to_vec(), Next::Reply)
            }
            Self::StreamedNotification => {
                let frame = FrameWriter::notification(&mut buffer, &LIMITS, &ShareSnapshotPart)?;
                let mut bytes = frame.finish()?.to_vec();
                for path in [b"/first".as_slice(), &[b'p'; 600]] {
                    let entry = ShareEntryHeader::new(
                        SHARE_MODE_RO,
                        SHARE_KIND_DIRECTORY,
                        path.len() as u32,
                    );
                    bytes.extend(piece_of(&[entry.as_bytes(), path].concat()));
                }
                bytes.extend_from_slice(&Closing::done(false).encode());
                (bytes, Next::Reply)
            }
            Self::Mismatch => (response(id, &ReleaseResponse {}, &[])?, Next::Request),
            Self::Unsent => {
                let error =
                    FrameWriter::error_response(&mut buffer, id + 1000, Opcode::Read, -libc::EIO)?;
                (error.to_vec(), Next::Request)
            }
            Self::CutBody => {
                let mut bytes = response(id, &ReadResponse, &[])?;
                let piece = piece_of(b"old");
                bytes.extend_from_slice(&piece[..piece.len() - 1]);
                (bytes, Next::End)
            }
            Self::PieceTooLong => {
                let mut bytes = response(id, &ReadResponse, &[])?;
                bytes.extend(piece_of(&vec![b'x'; size + 1]));
                (bytes, Next::Request)
            }
        })
    }
}

impl Behaviour for Fault {
    fn entry(&self, _serial: u64, opcode: Opcode, index: u64, entry: &mut EntryOut) {
        match (*self, opcode) {
            (Self::LookupId(id), Opcode::Lookup) => entry.node_id = U64::new(id),
            (Self::Attribute(attribute), Opcode::Lookup) => attribute.apply(&mut entry.attr),
            (Self::DirectoryId(id), Opcode::Readdirplus) if index == 2 => {
                entry.node_id = U64::new(id)
            }
            (Self::Listed(_, mode, _), Opcode::Readdirplus) if index == 2 => {
                entry.attr.mode = U32::new(mode)
            }
            _ => {}
        }
    }

    fn listing(&self, cookie: u64, listing: &mut Listing) {
        let repeated = !matches!(self, Self::Listed(..));
        listing.exhausted = !repeated;
        if cookie != 0 && !repeated {
            return;
        }
        let mut second = Listed::new(2, b"b");
        match *self {
            Self::Name(name) => second.name = name,
            Self::Listed(name, _, entry_type) => {
                second.name = name;
                second.entry_type = entry_type as u32;
            }
            Self::EntryType(word) => second.entry_type = word,
            _ => {}
        }
        listing.entries = vec![Listed::new(1, b"a"), second, Listed::new(3, b"c")];
    }

    fn link(&self, target: &mut &'static [u8]) {
        if let Self::Link(link) = *self {
            *target = link;
        }
    }

    fn statfs(&self, reply: &mut StatfsResponse) {
        if let Self::Statfs(fault) = *self {
            *reply = fault;
        }
    }

    fn deliver(
        &self,
        _state: &State,
        _serial: u64,
        frame: &Frame<'_>,
        reply: Vec<u8>,
        stream: &mut dyn Stream,
    ) -> Result<Flow> {
        let Self::Framing(framing) = *self else {
            return send(stream, &reply);
        };
        if frame.opcode()? != Opcode::Read {
            return send(stream, &reply);
        }
        let size = frame.request::<ReadRequest>()?.body().size.get() as usize;
        let (bytes, next) = framing.bytes(frame.request_id(), size)?;
        stream.write_all(&bytes)?;
        match next {
            Next::Reply => send(stream, &reply),
            Next::Request => Ok(Flow::Next),
            Next::End => Ok(Flow::Close),
        }
    }
}

fn listed_type(name: &[u8]) -> std::io::Result<Option<u8>> {
    let directory = unsafe { libc::opendir(c"/vfs-options".as_ptr()) };
    if directory.is_null() {
        return Err(std::io::Error::last_os_error());
    }
    let mut listed = None;
    let result = loop {
        unsafe { *libc::__errno_location() = 0 };
        let entry = unsafe { libc::readdir(directory) };
        if entry.is_null() {
            break match errno() {
                0 => Ok(listed),
                error => Err(std::io::Error::from_raw_os_error(error)),
            };
        }
        if unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes() == name {
            listed = Some(unsafe { (*entry).d_type });
        }
    };
    unsafe { libc::closedir(directory) };
    result
}

fn observe(fault: Fault) -> std::io::Result<Option<u8>> {
    match fault {
        Fault::Link(_) => fs::read_link("/vfs-options/n3002").map(|_| None),
        Fault::LookupId(_) | Fault::Attribute(_) => {
            fs::symlink_metadata("/vfs-options/a").map(|_| None)
        }
        Fault::Name(_) | Fault::DirectoryId(_) | Fault::EntryType(_) => {
            list_past_dots("/vfs-options", 2).map(|()| None)
        }
        Fault::Listed(name, ..) => listed_type(name),
        Fault::Framing(_) => {
            assert_eq!(fs::read("/vfs-options/a")?, b"old");
            Ok(None)
        }
        Fault::Statfs(_) => {
            let mut stat = unsafe { std::mem::zeroed::<libc::statvfs>() };
            if unsafe { libc::statvfs(c"/vfs-options".as_ptr(), &mut stat) } == 0 {
                Ok(None)
            } else {
                Err(std::io::Error::last_os_error())
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Expect {
    Ended(i32),
    Local(i32),
    Presented(Option<u8>),
}

impl Expect {
    fn observed(self) -> std::result::Result<Option<u8>, i32> {
        match self {
            Self::Ended(errno) | Self::Local(errno) => Err(errno),
            Self::Presented(entry_type) => Ok(entry_type),
        }
    }
}

fn join(peer: std::thread::JoinHandle<Result>) -> Result {
    peer.join().map_err(|_| "hostile peer failed")?
}

pub(super) fn run() -> Result {
    fs::create_dir_all("/vfs-options")?;
    fs::create_dir_all("/vfs-control")?;
    load_module()?;
    let sane = StatfsResponse {
        blocks: U64::new(1000),
        bfree: U64::new(500),
        bavail: U64::new(400),
        files: U64::new(10),
        ffree: U64::new(5),
        bsize: U32::new(4096),
        namelen: U32::new(255),
        frsize: U32::new(512),
        reserved: U32::ZERO,
    };
    let statfs = |change: fn(&mut StatfsResponse)| {
        let mut reply = sane;
        change(&mut reply);
        Fault::Statfs(reply)
    };
    use Attribute::{
        AccessNanoseconds, ChangeNanoseconds, Gid, Mode, ModificationNanoseconds, Uid,
    };
    use EntryType::{Character, Fifo, Regular, Unknown};
    use Expect::{Ended, Local, Presented};
    use libc::{DT_CHR, DT_DIR, DT_FIFO, DT_REG, DT_SOCK, DT_UNKNOWN, EIO, EOVERFLOW};
    let (attribute, framing, listed) = (Fault::Attribute, Fault::Framing, Fault::Listed);
    let regular = libc::S_IFREG | 0o444;
    let fifo = libc::S_IFIFO | 0o644;
    let socket = libc::S_IFSOCK | 0o644;
    let character = libc::S_IFCHR | 0o644;
    let cases = [
        (Fault::Link(b"safe\0hidden"), Ended(EIO)),
        (Fault::Link(b"\0"), Ended(EIO)),
        (Fault::Link(b"safe\0"), Ended(EIO)),
        (Fault::Name(b""), Ended(EIO)),
        (Fault::Name(b"."), Ended(EIO)),
        (Fault::Name(b".."), Ended(EIO)),
        (Fault::Name(b"safe\0hidden"), Ended(EIO)),
        (Fault::Name(b"a/b"), Ended(EIO)),
        (Fault::Name(&[b'x'; 256]), Ended(EIO)),
        (Fault::LookupId(0), Ended(EIO)),
        (Fault::LookupId(1), Ended(EIO)),
        (Fault::DirectoryId(0), Ended(EIO)),
        (Fault::DirectoryId(1), Ended(EIO)),
        (Fault::EntryType(u32::MAX), Ended(EIO)),
        (Fault::EntryType(u32::from(DT_DIR)), Ended(EIO)),
        (attribute(AccessNanoseconds(1_000_000_000)), Ended(EIO)),
        (attribute(ModificationNanoseconds(u32::MAX)), Ended(EIO)),
        (attribute(ChangeNanoseconds(1_000_000_000)), Ended(EIO)),
        (attribute(Uid(u32::MAX)), Local(EOVERFLOW)),
        (attribute(Gid(u32::MAX)), Local(EOVERFLOW)),
        (attribute(Mode(regular | 1 << 16)), Local(EOVERFLOW)),
        (framing(Framing::NotificationFlags), Ended(EIO)),
        (framing(Framing::NotificationId), Ended(EIO)),
        (framing(Framing::NotificationResponse), Ended(EIO)),
        (framing(Framing::Notification), Presented(None)),
        (framing(Framing::StreamedNotification), Presented(None)),
        (framing(Framing::Mismatch), Ended(EIO)),
        (framing(Framing::Unsent), Ended(EIO)),
        (framing(Framing::CutBody), Ended(EIO)),
        (framing(Framing::PieceTooLong), Ended(EIO)),
        (Fault::Statfs(StatfsResponse::default()), Presented(None)),
        (Fault::Statfs(sane), Presented(None)),
        (statfs(|reply| reply.reserved = U32::new(1)), Ended(EIO)),
        (statfs(|reply| reply.bsize = U32::new(4095)), Ended(EIO)),
        (statfs(|reply| reply.frsize = U32::ZERO), Ended(EIO)),
        (statfs(|reply| reply.frsize = U32::new(8192)), Ended(EIO)),
        (statfs(|reply| reply.namelen = U32::new(256)), Ended(EIO)),
        (statfs(|reply| reply.namelen = U32::ZERO), Ended(EIO)),
        (statfs(|reply| reply.bfree = U64::new(1001)), Ended(EIO)),
        (statfs(|reply| reply.bavail = U64::new(501)), Ended(EIO)),
        (listed(b"x", regular, Regular), Presented(Some(DT_REG))),
        (listed(b"...", regular, Unknown), Presented(Some(DT_REG))),
        (
            listed(&[b'x'; 255], regular, Regular),
            Presented(Some(DT_REG)),
        ),
        (listed(b"special", fifo, Unknown), Presented(Some(DT_FIFO))),
        (listed(b"special", fifo, Fifo), Presented(Some(DT_FIFO))),
        (
            listed(b"special", socket, Unknown),
            Presented(Some(DT_SOCK)),
        ),
        (
            listed(b"special", character, Character),
            Presented(Some(DT_CHR)),
        ),
        (
            listed(b"special", 0o644, Unknown),
            Presented(Some(DT_UNKNOWN)),
        ),
        (listed(b"special", fifo, Regular), Ended(EIO)),
    ];
    for (fault, expected) in cases {
        let good = mount_peer_at(
            c"/vfs-control",
            &Arc::new(State::default()),
            "reconnect_stall=0",
        )?;
        let hostile = Arc::new(State::with(Arc::new(fault)));
        let bad = mount_peer_at(c"/vfs-options", &hostile, "reconnect_stall=0")?;
        assert_eq!(fs::read("/vfs-control/a")?, b"old");
        let observed = observe(fault).map_err(|error| error.raw_os_error().unwrap_or(0));
        assert_eq!(observed, expected.observed(), "{fault:?}");
        // The connection of a rejected reply ends before the unmount, which
        // ends every other one: the module ends it, or the peer did when it
        // cut the reply. The session can outlive that connection, since one
        // that joined it meanwhile, such as one the cleanup worker dials to
        // give back the nodes of the rejected reply, lasts until the unmount.
        if let Ended(_) = expected {
            hostile.wait_closed(1)?;
        }
        assert_eq!(fs::read("/vfs-control/b")?, b"old");
        assert_eq!(unsafe { libc::umount(c"/vfs-options".as_ptr()) }, 0);
        join(bad)?;
        assert_eq!(unsafe { libc::umount(c"/vfs-control".as_ptr()) }, 0);
        good.join().map_err(|_| "control peer failed")??;
        println!("vfs acceptance: hostile reply {fault:?} gave {expected:?}; control mount usable");
    }
    assert_eq!(counter("nodes_admitted")?, counter("nodes_forgotten")?);
    unload_module()?;
    Ok(())
}
