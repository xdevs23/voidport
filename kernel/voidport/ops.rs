// SPDX-License-Identifier: GPL-2.0

use kernel::bindings;
use kernel::page::PAGE_SIZE;
use kernel::prelude::*;
use voidport_proto::attr::{Attr, EntryOut};
use voidport_proto::message::{RequestBody, ResponseBody};
use voidport_proto::ops::dir::{DirEntryIter, EntryType, ReaddirplusRequest, ReaddirplusResponse};
use voidport_proto::ops::file::{OpenRequest, OpenResponse, ReadRequest, ReadResponse};
use voidport_proto::ops::node::{
    GetattrRequest, GetattrResponse, LookupRequest, LookupResponse, ReadlinkRequest,
    ReadlinkResponse, SetattrRequest, SetattrResponse, StatfsRequest, StatfsResponse,
};
use voidport_session::owed::{self, Lookups};
use voidport_session::replay::OpenFlags;
use zerocopy::byteorder::little_endian::{U32, U64};

use crate::aops::Read;
use crate::cleanup::{Cleanup, Closing, DecodeId, Retiring};
use crate::connection::{Data, Landing, PageData, ReadRange};
use crate::helpers::NoFsScope;
use crate::session::{peer_error, ExtractError, Session};
use crate::wire::{reply_capacity, Caller, LIMITS};
use voidport_proto::message::ResponseOutcome;

pub(crate) mod file;
pub(crate) mod namespace;
pub(crate) mod xattr;

pub(crate) use file::{LockWait, Privileged, SyncScope, Through};

pub(crate) trait Operation: RequestBody + Copy {
    type Response: ResponseBody;
    type Output;

    /// Reads the node a successful reply gives, which a forget gives back.
    const NODE: Option<DecodeId> = None;
    /// Reads the handle a successful reply opens, which a release gives back.
    const HANDLE: Option<DecodeId> = None;

    /// Reserves, before the request about `node_id` is sent, one record for
    /// each reference a successful reply leaves on the server, as `owed::of`
    /// returns for the opcode. The build checks that the operation reads
    /// exactly those references from its reply.
    fn cleanup(&self, caller: Caller, _node_id: u64) -> Result<Option<KBox<Cleanup>>> {
        const {
            let owed = owed::of(Self::OPCODE);
            let forgets = match owed.forget {
                Lookups::None => false,
                Lookups::One => true,
                Lookups::EveryEntry => panic!("a listing reserves the records of its entries"),
            };
            assert!(forgets == Self::NODE.is_some() && owed.release == Self::HANDLE.is_some());
        }
        let node = Self::NODE
            .map(|decode| Cleanup::node(caller, decode))
            .transpose()?;
        let handle = Self::HANDLE
            .map(|decode| Cleanup::handle(caller, decode))
            .transpose()?;
        Ok(match (node, handle) {
            (Some(node), Some(handle)) => Some(node.paired_with(handle)),
            (node, handle) => node.or(handle),
        })
    }

    fn open_flags(&self) -> OpenFlags {
        OpenFlags::NONE
    }

    fn prepare(self) -> Self {
        self
    }

    /// The buffer the reply message is read into: its fixed body and the
    /// bound of its variable part.
    fn reply_capacity(&self) -> usize {
        reply_capacity::<Self::Response>(0)
    }

    fn extract(
        &self,
        response: &Self::Response,
        payload: &[u8],
        landing: &Landing,
    ) -> core::result::Result<Self::Output, ExtractError>;

    /// What an error reply with the wire status `status` gives: by default,
    /// the error that the status contains.
    fn refused(&self, status: i32) -> core::result::Result<Self::Output, ExtractError> {
        Err(ExtractError::Local(peer_error(status)))
    }
}

/// An operation whose request has data in pages: a write sends its data
/// after the frame, and the reply to a read fills the pages of its range.
pub(crate) trait Paged: Operation {
    /// The request, with no more than `len` bytes of that data, for a link
    /// that sends only a part of the data. The caller asks again for the
    /// rest, as after a short reply.
    fn cut(self, len: usize) -> Self;
}

#[derive(Clone)]
pub(crate) enum Expect {
    Nothing,
    /// The data of a read, straight into the pages of this range.
    Read(ReadRange),
    /// A listing's entries, into a buffer of this many bytes: the size the
    /// request asks for.
    Entries(usize),
    /// Data pieces, into a buffer of this many bytes: the reply the server
    /// stored for a request an outcome request asks about.
    Bytes(usize),
}

pub(crate) struct Request<'a, Q> {
    pub(crate) caller: Caller,
    pub(crate) node_id: u64,
    pub(crate) body: Q,
    pub(crate) payload: &'a [u8],
    pub(crate) data: Option<&'a dyn Data>,
    pub(crate) expect: Expect,
    /// Fits the request to the first bytes of its data in pages, set for a
    /// [`Paged`] operation, which alone has such data.
    pub(crate) cut: Option<fn(Q, usize) -> Q>,
}

impl<'a, Q> Request<'a, Q> {
    pub(crate) fn new(caller: Caller, node_id: u64, body: Q) -> Self {
        Self {
            caller,
            node_id,
            body,
            payload: &[],
            data: None,
            expect: Expect::Nothing,
            cut: None,
        }
    }

    pub(crate) fn payload(self, payload: &'a [u8]) -> Self {
        Self { payload, ..self }
    }

    /// The request whose reply streams its pieces into a buffer, as `expect`
    /// sets. A read uses [`Request::reading`].
    pub(crate) fn expecting(self, expect: Expect) -> Self {
        Self { expect, ..self }
    }

    /// The data of the request that lies in pages: the data of a write, or
    /// the pages of a read.
    pub(crate) fn page_data(&self) -> PageData<'_> {
        match (self.data, &self.expect) {
            (Some(data), _) => PageData::Write(data),
            (None, Expect::Read(range)) => PageData::Read(range),
            _ => PageData::None,
        }
    }
}

impl<'a, Q: Paged> Request<'a, Q> {
    pub(crate) fn data(self, data: &'a dyn Data) -> Self {
        Self {
            data: Some(data),
            cut: Some(Q::cut),
            ..self
        }
    }

    pub(crate) fn reading(self, range: ReadRange) -> Self {
        Self {
            expect: Expect::Read(range),
            cut: Some(Q::cut),
            ..self
        }
    }
}

/// A lookup admission cannot alias the mount root or the absent-node sentinel.
#[derive(Clone, Copy, Debug)]
pub(crate) struct EntryNodeId(u64);

impl EntryNodeId {
    fn new(id: u64) -> core::result::Result<Self, ExtractError> {
        if id == 0 || id == voidport_session::handshake::ROOT_NODE_ID {
            return Err(voidport_proto::error::FramingError::InvalidEntryNodeId.into());
        }
        Ok(Self(id))
    }

    pub(crate) fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Entry {
    pub(crate) node_id: EntryNodeId,
    pub(crate) generation: u64,
    pub(crate) attr: Attr,
}

impl Entry {
    /// A looked-up entry: its mode must name a kind this filesystem
    /// instantiates, which is what the validation decides.
    fn of(entry: &EntryOut) -> core::result::Result<Self, ExtractError> {
        let node_id = EntryNodeId::new(entry.node_id.get())?;
        crate::node::validate_attr(&entry.attr)?;
        Ok(Self {
            node_id,
            generation: entry.generation.get(),
            attr: entry.attr,
        })
    }
}

pub(crate) struct DirItem {
    pub(crate) name: KVec<u8>,
    /// The inode number the listing presents; the entry is not instantiated.
    pub(crate) ino: u64,
    pub(crate) next_cookie: u64,
    pub(crate) entry_type: EntryType,
}

pub(crate) fn open_flags(flags: u32) -> OpenFlags {
    let mut named = OpenFlags::NONE;
    for (bit, flag) in [
        (bindings::O_CREAT, OpenFlags::CREATE),
        (bindings::O_EXCL, OpenFlags::EXCLUSIVE),
        (bindings::O_TRUNC, OpenFlags::TRUNCATE),
        (bindings::O_APPEND, OpenFlags::APPEND),
    ] {
        if flags & bit != 0 {
            named = named.union(flag);
        }
    }
    named
}

/// The [`DecodeId`] that reads the ID at `$field` of the body of a successful
/// reply of type `$response`, and none from an error reply.
macro_rules! decode_on_success {
    ($response:ty, $($field:ident).+) => {
        Some(|frame| match frame.response::<$response>()? {
            voidport_proto::message::ResponseOutcome::Success(reply) => {
                Ok(Some(reply.body().$($field).+.get()))
            }
            voidport_proto::message::ResponseOutcome::Error(_) => Ok(None),
        })
    };
}

pub(crate) use decode_on_success;

macro_rules! entry_operations {
    ($($request:ty => $response:ty),+ $(,)?) => {$(
        impl Operation for $request {
            type Response = $response;
            type Output = Entry;
            const NODE: Option<DecodeId> =
                $crate::ops::decode_on_success!($response, entry.node_id);

            fn extract(
                &self,
                response: &$response,
                _: &[u8],
                _: &Landing,
            ) -> core::result::Result<Entry, ExtractError> {
                Entry::of(&response.entry)
            }
        }
    )+};
}

pub(crate) use entry_operations;

entry_operations!(LookupRequest => LookupResponse);

macro_rules! acknowledged_operations {
    ($($request:ty => $response:ty),+ $(,)?) => {$(
        impl Operation for $request {
            type Response = $response;
            type Output = ();

            fn extract(
                &self,
                _: &$response,
                _: &[u8],
                _: &Landing,
            ) -> core::result::Result<(), ExtractError> {
                Ok(())
            }
        }
    )+};
}

pub(crate) use acknowledged_operations;

impl Operation for GetattrRequest {
    type Response = GetattrResponse;
    type Output = Attr;

    fn extract(
        &self,
        response: &GetattrResponse,
        _: &[u8],
        _: &Landing,
    ) -> core::result::Result<Attr, ExtractError> {
        live_attr(&response.attr)
    }
}

impl Operation for SetattrRequest {
    type Response = SetattrResponse;
    type Output = Attr;

    fn extract(
        &self,
        response: &SetattrResponse,
        _: &[u8],
        _: &Landing,
    ) -> core::result::Result<Attr, ExtractError> {
        live_attr(&response.attr)
    }
}

fn live_attr(attr: &Attr) -> core::result::Result<Attr, ExtractError> {
    crate::node::validate_attr(attr).map_err(|error| match error {
        // Every live inode has a supported kind. A refresh naming another
        // kind remains stale even when that kind has no operation table.
        ExtractError::Local(error) if error.to_errno() == -(bindings::EOPNOTSUPP as c_int) => {
            ExtractError::Local(crate::errno::estale())
        }
        error => error,
    })?;
    Ok(*attr)
}

impl Operation for ReadlinkRequest {
    type Response = ReadlinkResponse;
    type Output = KVec<u8>;

    /// A link target is a path, bounded by the kernel's `PATH_MAX`.
    fn reply_capacity(&self) -> usize {
        reply_capacity::<ReadlinkResponse>(bindings::PATH_MAX as usize)
    }

    fn extract(
        &self,
        _: &ReadlinkResponse,
        payload: &[u8],
        _: &Landing,
    ) -> core::result::Result<KVec<u8>, ExtractError> {
        if payload.contains(&0) {
            return Err(voidport_proto::error::FramingError::InvalidLinkTarget.into());
        }
        copy(payload)
    }
}

impl Operation for StatfsRequest {
    type Response = StatfsResponse;
    type Output = StatfsResponse;

    fn extract(
        &self,
        response: &StatfsResponse,
        _: &[u8],
        _: &Landing,
    ) -> core::result::Result<StatfsResponse, ExtractError> {
        if statfs_is_consistent(response) {
            Ok(*response)
        } else {
            Err(voidport_proto::error::FramingError::InvalidStatfs.into())
        }
    }
}

/// An all-zero reply is the answer of the synthetic directory and passes.
pub(crate) fn statfs_is_consistent(stat: &StatfsResponse) -> bool {
    let zero = [
        u64::from(stat.bsize.get()),
        u64::from(stat.frsize.get()),
        u64::from(stat.namelen.get()),
        u64::from(stat.reserved.get()),
        stat.blocks.get(),
        stat.bfree.get(),
        stat.bavail.get(),
        stat.files.get(),
        stat.ffree.get(),
    ]
    .iter()
    .all(|value| *value == 0);
    if zero {
        return true;
    }
    let bsize = stat.bsize.get();
    let frsize = stat.frsize.get();
    let namelen = stat.namelen.get();
    stat.reserved.get() == 0
        && bsize.is_power_of_two()
        && frsize.is_power_of_two()
        && frsize <= bsize
        && namelen != 0
        && namelen <= LIMITS.name_max
        && stat.bfree.get() <= stat.blocks.get()
        && stat.bavail.get() <= stat.bfree.get()
}

impl Operation for OpenRequest {
    type Response = OpenResponse;
    type Output = u64;
    const HANDLE: Option<DecodeId> = decode_on_success!(OpenResponse, handle);

    fn open_flags(&self) -> OpenFlags {
        open_flags(self.flags.get())
    }

    fn extract(
        &self,
        response: &OpenResponse,
        _: &[u8],
        _: &Landing,
    ) -> core::result::Result<u64, ExtractError> {
        Ok(response.handle.get())
    }
}

impl Paged for ReadRequest {
    fn cut(mut self, len: usize) -> Self {
        let len = u32::try_from(len).unwrap_or(u32::MAX);
        self.size = U32::new(self.size.get().min(len));
        self
    }
}

impl Operation for ReadRequest {
    type Response = ReadResponse;
    type Output = Read;

    /// The data streamed into the caller's folio. A closing piece with an
    /// errno after some pieces is the short read it is, and the caller asks
    /// again from where it stopped; one with an errno before any piece is the
    /// errno.
    fn extract(
        &self,
        _: &ReadResponse,
        _: &[u8],
        landing: &Landing,
    ) -> core::result::Result<Self::Output, ExtractError> {
        let filled = match &landing.pieces {
            crate::connection::Pieces::Read(range) => range.filled(),
            _ => return Err(voidport_proto::error::FramingError::LengthOverflow.into()),
        };
        let closing = landing
            .closing
            .ok_or(voidport_proto::error::FramingError::LengthOverflow)?;
        if closing.status != 0 {
            if filled == 0 {
                return Err(ExtractError::Local(crate::session::peer_error(
                    closing.status,
                )));
            }
            return Ok(Read {
                filled,
                exhausted: false,
            });
        }
        Ok(Read {
            filled,
            exhausted: closing.exhausted,
        })
    }
}

impl Operation for ReaddirplusRequest {
    type Response = ReaddirplusResponse;
    type Output = (KVec<DirItem>, bool);
    fn cleanup(&self, caller: Caller, _node_id: u64) -> Result<Option<KBox<Cleanup>>> {
        Cleanup::directory(caller, |frame, entries, reference| {
            if let ResponseOutcome::Success(_) = frame.response::<ReaddirplusResponse>()? {
                for entry in DirEntryIter::new(entries) {
                    reference(entry?.header.entry.node_id.get());
                }
            }
            Ok(())
        })
        .map(Some)
    }

    /// A page of entry bytes, the size of the buffer the VFS gives a
    /// directory read. It is the stop rule the server streams to, and the
    /// size of the buffer the entries land in.
    fn prepare(mut self) -> Self {
        self.size = U32::new(PAGE_SIZE as u32);
        self
    }

    /// The entries that streamed after the reply, and whether the directory
    /// is exhausted. A closing piece with an errno is the errno; every entry
    /// of the reply is given back by the cleanup either way.
    fn extract(
        &self,
        _: &ReaddirplusResponse,
        _: &[u8],
        landing: &Landing,
    ) -> core::result::Result<Self::Output, ExtractError> {
        let closing = landing
            .closing
            .ok_or(voidport_proto::error::FramingError::LengthOverflow)?;
        if closing.status != 0 {
            return Err(ExtractError::Local(crate::session::peer_error(
                closing.status,
            )));
        }
        let mut items = KVec::new();
        for item in DirEntryIter::new(landing.pieces.entries()) {
            let item = item?;
            // A listing shows every entry the host has, also one whose mode
            // describes no kind, which a lookup rejects; only the identity,
            // the attributes and the type word are checked here.
            EntryNodeId::new(item.header.entry.node_id.get())?;
            crate::node::validate_listed_attr(&item.header.entry.attr)?;
            let mode = item.header.entry.attr.mode.get();
            let entry_type = item.header.entry_type()?;
            let from_mode = EntryType::of_mode(mode);
            if entry_type != EntryType::Unknown && from_mode != Some(entry_type) {
                return Err(voidport_proto::error::FramingError::InvalidEntryType.into());
            }
            // Linux filesystem components exclude separators, string terminators
            // and dot entries. The VFS supplies its own dot entries.
            if item.tail.is_empty()
                || item.tail == b"."
                || item.tail == b".."
                || item.tail.len() > LIMITS.name_max as usize
                || item.tail.iter().any(|byte| *byte == 0 || *byte == b'/')
            {
                return Err(voidport_proto::error::FramingError::InvalidEntryName.into());
            }
            let name = copy(item.tail)?;
            items
                .push(
                    DirItem {
                        name,
                        ino: item.header.entry.attr.ino.get(),
                        next_cookie: item.header.next_cookie.get(),
                        entry_type: if entry_type == EntryType::Unknown {
                            from_mode.unwrap_or(EntryType::Unknown)
                        } else {
                            entry_type
                        },
                    },
                    GFP_KERNEL,
                )
                .map_err(|_| ExtractError::Local(ENOMEM))?;
        }
        Ok((items, closing.exhausted))
    }
}

impl Session {
    /// A successful lookup transfers one admission to the caller.
    pub(crate) fn lookup(&self, caller: Caller, parent: u64, name: &[u8]) -> Result<Entry> {
        let body = LookupRequest {
            name_len: U32::new(len_of(name)?),
        };
        self.call(Request::new(caller, parent, body).payload(name))
    }

    pub(crate) fn getattr(
        &self,
        caller: Caller,
        node_id: u64,
        handle: Option<u64>,
    ) -> Result<Attr> {
        use voidport_proto::ops::node::getattr_flags;
        let body = GetattrRequest {
            handle: U64::new(handle.unwrap_or_default()),
            flags: U32::new(if handle.is_some() {
                getattr_flags::HANDLE
            } else {
                0
            }),
            reserved: U32::ZERO,
        };
        self.call(Request::new(caller, node_id, body))
    }

    pub(crate) fn setattr(
        &self,
        caller: Caller,
        node_id: u64,
        change: SetattrRequest,
    ) -> Result<Attr> {
        self.call(Request::new(caller, node_id, change))
    }

    pub(crate) fn readlink(&self, caller: Caller, node_id: u64) -> Result<KVec<u8>> {
        self.call(Request::new(caller, node_id, ReadlinkRequest {}))
    }

    pub(crate) fn statfs(&self, caller: Caller, node_id: u64) -> Result<StatfsResponse> {
        self.call(Request::new(caller, node_id, StatfsRequest {}))
    }

    pub(crate) fn open_handle(&self, caller: Caller, node_id: u64, flags: u32) -> Result<u64> {
        let body = OpenRequest {
            flags: U32::new(flags),
            reserved: U32::ZERO,
        };
        self.call(Request::new(caller, node_id, body))
    }

    /// # Errors
    ///
    /// The server's errno, [`crate::session::handed`] when the caller left
    /// while the reply was streaming into a folio, or a transport error.
    pub(crate) fn read_into(
        &self,
        caller: Caller,
        node_id: u64,
        handle: u64,
        offset: u64,
        range: ReadRange,
    ) -> Result<Read> {
        let size = u32::try_from(range.remaining()).unwrap_or(u32::MAX);
        if size == 0 {
            return Err(EIO);
        }
        let body = ReadRequest {
            handle: U64::new(handle),
            offset: U64::new(offset),
            size: U32::new(size),
            flags: U32::ZERO,
        };
        self.call(Request::new(caller, node_id, body).reading(range))
    }

    /// Lists a directory from `cookie`: the entries of one page, and whether
    /// the directory is exhausted after them.
    pub(crate) fn readdirplus(
        &self,
        caller: Caller,
        node_id: u64,
        handle: u64,
        cookie: u64,
    ) -> Result<(KVec<DirItem>, bool)> {
        let body = ReaddirplusRequest {
            handle: U64::new(handle),
            cookie: U64::new(cookie),
            size: U32::ZERO,
            reserved: U32::ZERO,
        };
        self.call(Request::new(caller, node_id, body).expecting(Expect::Entries(PAGE_SIZE)))
    }

    pub(crate) fn release(&self, caller: Caller, handle: u64, closing: Closing) {
        self.retire(
            Retiring::Handle {
                id: handle,
                closing,
            },
            caller,
        );
    }

    pub(crate) fn forget(&self, caller: Caller, node_id: u64, nlookup: u64) {
        self.retire(
            Retiring::Nodes {
                id: node_id,
                count: nlookup,
            },
            caller,
        );
    }
}

fn copy<A: kernel::alloc::Allocator>(
    payload: &[u8],
) -> core::result::Result<kernel::alloc::Vec<u8, A>, ExtractError> {
    let mut owned = kernel::alloc::Vec::new();
    owned
        .extend_from_slice(payload, GFP_KERNEL)
        .map_err(|_| ExtractError::Local(ENOMEM))?;
    Ok(owned)
}

/// The payload of a request with two regions: `first`, then `second`. It is
/// allocated before the request enters its reclaim scope, so it enters one of
/// its own.
fn joined(first: &[u8], second: &[u8]) -> Result<KVVec<u8>> {
    let _scope = NoFsScope::enter();
    let mut payload = KVVec::with_capacity(first.len() + second.len(), GFP_KERNEL)?;
    payload.extend_from_slice(first, GFP_KERNEL)?;
    payload.extend_from_slice(second, GFP_KERNEL)?;
    Ok(payload)
}

fn len_of(region: &[u8]) -> Result<u32> {
    u32::try_from(region.len()).map_err(|_| EOVERFLOW)
}
