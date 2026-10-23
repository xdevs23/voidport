// SPDX-License-Identifier: GPL-2.0

use kernel::bindings;
use kernel::prelude::*;
use voidport_proto::ops::dir::{
    rename_flags as wire_rename, LinkRequest, LinkResponse, MkdirRequest, MkdirResponse,
    MknodRequest, MknodResponse, RenameRequest, RenameResponse, RmdirRequest, RmdirResponse,
    SymlinkRequest, SymlinkResponse, UnlinkRequest, UnlinkResponse,
};
use voidport_proto::ops::file::{CreateRequest, CreateResponse};
use zerocopy::byteorder::little_endian::{U32, U64};

use super::{
    acknowledged_operations, decode_on_success, entry_operations, joined, len_of, Entry, Operation,
    Request,
};
use crate::cleanup::DecodeId;
use crate::connection::Landing;
use crate::helpers::current_umask;
use crate::session::{ExtractError, Session};
use crate::wire::Caller;

entry_operations!(
    MkdirRequest => MkdirResponse,
    MknodRequest => MknodResponse,
    SymlinkRequest => SymlinkResponse,
    LinkRequest => LinkResponse,
);

acknowledged_operations!(
    UnlinkRequest => UnlinkResponse,
    RmdirRequest => RmdirResponse,
    RenameRequest => RenameResponse,
);

#[derive(Clone, Copy, Debug)]
pub(crate) struct Created {
    pub(crate) entry: Entry,
    pub(crate) handle: u64,
}

impl Operation for CreateRequest {
    type Response = CreateResponse;
    type Output = Created;
    const NODE: Option<DecodeId> = decode_on_success!(CreateResponse, entry.node_id);
    const HANDLE: Option<DecodeId> = decode_on_success!(CreateResponse, handle);

    fn extract(
        &self,
        response: &CreateResponse,
        _: &[u8],
        _: &Landing,
    ) -> core::result::Result<Created, ExtractError> {
        Ok(Created {
            entry: Entry::of(&response.entry)?,
            handle: response.handle.get(),
        })
    }
}

pub(crate) fn rename_flags(flags: c_uint) -> Result<u32> {
    let mut wire = 0;
    let mut left = flags;
    for (bit, flag) in [
        (bindings::RENAME_NOREPLACE, wire_rename::NOREPLACE),
        (bindings::RENAME_EXCHANGE, wire_rename::EXCHANGE),
        (bindings::RENAME_WHITEOUT, wire_rename::WHITEOUT),
    ] {
        if flags & bit != 0 {
            wire |= flag;
            left &= !bit;
        }
    }
    if left != 0 {
        return Err(EINVAL);
    }
    Ok(wire)
}

impl Session {
    pub(crate) fn create(
        &self,
        caller: Caller,
        parent: u64,
        name: &[u8],
        flags: u32,
        mode: u32,
    ) -> Result<Created> {
        let body = CreateRequest {
            flags: U32::new(flags),
            mode: U32::new(mode),
            umask: U32::new(current_umask()),
            name_len: U32::new(len_of(name)?),
        };
        self.call(Request::new(caller, parent, body).payload(name))
    }

    pub(crate) fn mkdir(
        &self,
        caller: Caller,
        parent: u64,
        name: &[u8],
        mode: u32,
    ) -> Result<Entry> {
        let body = MkdirRequest {
            mode: U32::new(mode),
            umask: U32::new(current_umask()),
            name_len: U32::new(len_of(name)?),
            reserved: U32::ZERO,
        };
        self.call(Request::new(caller, parent, body).payload(name))
    }

    /// Creates the FIFO or the socket `name` in `parent`, the kind and the
    /// permission bits given by `mode`. Neither has a device number.
    pub(crate) fn mknod(
        &self,
        caller: Caller,
        parent: u64,
        name: &[u8],
        mode: u32,
    ) -> Result<Entry> {
        let body = MknodRequest {
            mode: U32::new(mode),
            umask: U32::new(current_umask()),
            rdev: U32::ZERO,
            name_len: U32::new(len_of(name)?),
        };
        self.call(Request::new(caller, parent, body).payload(name))
    }

    pub(crate) fn symlink(
        &self,
        caller: Caller,
        parent: u64,
        name: &[u8],
        target: &[u8],
    ) -> Result<Entry> {
        let body = SymlinkRequest {
            name_len: U32::new(len_of(name)?),
            target_len: U32::new(len_of(target)?),
        };
        let payload = joined(name, target)?;
        self.call(Request::new(caller, parent, body).payload(&payload))
    }

    pub(crate) fn link(
        &self,
        caller: Caller,
        parent: u64,
        target: u64,
        name: &[u8],
    ) -> Result<Entry> {
        let body = LinkRequest {
            target_node_id: U64::new(target),
            name_len: U32::new(len_of(name)?),
            reserved: U32::ZERO,
        };
        self.call(Request::new(caller, parent, body).payload(name))
    }

    pub(crate) fn unlink(&self, caller: Caller, parent: u64, name: &[u8]) -> Result {
        let body = UnlinkRequest {
            name_len: U32::new(len_of(name)?),
        };
        self.call(Request::new(caller, parent, body).payload(name))
    }

    pub(crate) fn rmdir(&self, caller: Caller, parent: u64, name: &[u8]) -> Result {
        let body = RmdirRequest {
            name_len: U32::new(len_of(name)?),
        };
        self.call(Request::new(caller, parent, body).payload(name))
    }

    pub(crate) fn rename(
        &self,
        caller: Caller,
        parent: u64,
        name: &[u8],
        new_parent: u64,
        new_name: &[u8],
        flags: u32,
    ) -> Result {
        let body = RenameRequest {
            new_parent_node_id: U64::new(new_parent),
            flags: U32::new(flags),
            old_name_len: U32::new(len_of(name)?),
            new_name_len: U32::new(len_of(new_name)?),
            reserved: U32::ZERO,
        };
        let payload = joined(name, new_name)?;
        self.call(Request::new(caller, parent, body).payload(&payload))
    }
}
