// SPDX-License-Identifier: GPL-2.0

use kernel::prelude::*;
use voidport_proto::ops::xattr::{
    setxattr_flags, GetxattrRequest, GetxattrResponse, ListxattrRequest, ListxattrResponse,
    RemovexattrRequest, RemovexattrResponse, SetxattrRequest, SetxattrResponse, XattrNameHeader,
    XattrNameIter,
};
use zerocopy::byteorder::little_endian::U32;

use super::{acknowledged_operations, copy, joined, len_of, Operation, Request};
use crate::connection::Landing;
use crate::session::{ExtractError, Session};
use crate::vfs;
use crate::wire::{reply_capacity, Caller, LIMITS};

acknowledged_operations!(
    SetxattrRequest => SetxattrResponse,
    RemovexattrRequest => RemovexattrResponse,
);

pub(crate) struct Xattr {
    /// The full size of the value or of the list, which a request of size
    /// zero asks for.
    pub(crate) size: u32,
    /// The value, or the names each followed by a NUL; empty for a request of
    /// size zero.
    pub(crate) bytes: KVVec<u8>,
}

impl Operation for GetxattrRequest {
    type Response = GetxattrResponse;
    type Output = Xattr;

    /// A value is at most the size the request asks for.
    fn reply_capacity(&self) -> usize {
        reply_capacity::<GetxattrResponse>(self.size.get() as usize)
    }

    /// A size past the bound of the kernel's interface is treated as that
    /// bound, so a read that asks for that many bytes fails with `E2BIG`.
    fn extract(
        &self,
        response: &GetxattrResponse,
        payload: &[u8],
        _: &Landing,
    ) -> core::result::Result<Xattr, ExtractError> {
        Ok(Xattr {
            size: response.size.get().min(LIMITS.xattr_size_max),
            bytes: copy(payload)?,
        })
    }
}

impl Operation for ListxattrRequest {
    type Response = ListxattrResponse;
    type Output = Xattr;

    /// The names of a list of the size the request asks for. Each name takes
    /// at least two bytes of that size, one byte of name and its NUL, and on
    /// the wire its header takes the place of the NUL.
    fn reply_capacity(&self) -> usize {
        let size = self.size.get() as usize;
        reply_capacity::<ListxattrResponse>(size + size / 2 * (size_of::<XattrNameHeader>() - 1))
    }

    /// The names rebuilt into the kernel's list. A size past the bound of the
    /// kernel's interface is treated as that bound, so a listing that asks
    /// for that many bytes fails with `E2BIG`.
    fn extract(
        &self,
        response: &ListxattrResponse,
        payload: &[u8],
        _: &Landing,
    ) -> core::result::Result<Xattr, ExtractError> {
        let mut list = KVVec::new();
        for name in XattrNameIter::new(payload) {
            let name = name?.tail;
            // The list read by the kernel ends each name at a NUL, so it
            // cannot contain a name that is empty or has a NUL.
            if name.is_empty() || name.contains(&0) {
                return Err(ExtractError::Local(EIO));
            }
            list.extend_from_slice(name, GFP_KERNEL)
                .map_err(|_| ExtractError::Local(ENOMEM))?;
            list.push(0, GFP_KERNEL)
                .map_err(|_| ExtractError::Local(ENOMEM))?;
        }
        Ok(Xattr {
            size: response.size.get().min(LIMITS.xattr_list_max),
            bytes: list,
        })
    }
}

fn setxattr_flags_of(flags: c_int) -> u32 {
    let mut wire = 0;
    for (bit, flag) in [
        (vfs::XATTR_CREATE, setxattr_flags::CREATE),
        (vfs::XATTR_REPLACE, setxattr_flags::REPLACE),
    ] {
        if flags & bit as c_int != 0 {
            wire |= flag;
        }
    }
    wire
}

impl Session {
    /// Reads the extended attribute `name` of a node, or only its size when
    /// `size` is zero.
    pub(crate) fn getxattr(
        &self,
        caller: Caller,
        node_id: u64,
        name: &[u8],
        size: u32,
    ) -> Result<Xattr> {
        let body = GetxattrRequest {
            size: U32::new(size),
            name_len: U32::new(len_of(name)?),
        };
        self.call(Request::new(caller, node_id, body).payload(name))
    }

    pub(crate) fn setxattr(
        &self,
        caller: Caller,
        node_id: u64,
        name: &[u8],
        value: &[u8],
        flags: c_int,
    ) -> Result {
        let body = SetxattrRequest {
            flags: U32::new(setxattr_flags_of(flags)),
            name_len: U32::new(len_of(name)?),
            value_len: U32::new(len_of(value)?),
            reserved: U32::ZERO,
        };
        let payload = joined(name, value)?;
        self.call(Request::new(caller, node_id, body).payload(&payload))
    }

    /// Lists the extended attribute names of a node, or only the size of the
    /// list when `size` is zero.
    pub(crate) fn listxattr(&self, caller: Caller, node_id: u64, size: u32) -> Result<Xattr> {
        let body = ListxattrRequest {
            size: U32::new(size),
            reserved: U32::ZERO,
        };
        self.call(Request::new(caller, node_id, body))
    }

    pub(crate) fn removexattr(&self, caller: Caller, node_id: u64, name: &[u8]) -> Result {
        let body = RemovexattrRequest {
            name_len: U32::new(len_of(name)?),
        };
        self.call(Request::new(caller, node_id, body).payload(name))
    }
}
