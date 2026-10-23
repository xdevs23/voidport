//! Each function matches its registry exhaustively, so an opcode added without
//! a body does not compile. The macro that declares a body asserts at compile
//! time that the table lists that body for its opcode.

use core::mem::size_of;

use crate::error::FramingError;
use crate::limits::Limits;
use crate::message::{Follows, WirePayload};
use crate::opcode::{NotificationOpcode, Opcode};
use crate::ops::connection::{
    CancelRequest, OutcomeRequest, OutcomeResponse, RetireRequest, RetireResponse,
};
use crate::ops::dir::{
    LinkRequest, LinkResponse, MkdirRequest, MkdirResponse, MknodRequest, MknodResponse,
    ReaddirplusRequest, ReaddirplusResponse, RenameRequest, RenameResponse, RmdirRequest,
    RmdirResponse, SymlinkRequest, SymlinkResponse, UnlinkRequest, UnlinkResponse,
};
use crate::ops::file::{
    CreateRequest, CreateResponse, FlushRequest, FlushResponse, FsyncRequest, FsyncResponse,
    GetlkRequest, GetlkResponse, OpenRequest, OpenResponse, ReadRequest, ReadResponse,
    ReleaseRequest, ReleaseResponse, SetlkRequest, SetlkResponse, WriteRequest, WriteResponse,
};
use crate::ops::handshake::{HelloReply, HelloRequest};
use crate::ops::node::{
    ForgetRequest, GetattrRequest, GetattrResponse, LookupRequest, LookupResponse, ReadlinkRequest,
    ReadlinkResponse, SetattrRequest, SetattrResponse, StatfsRequest, StatfsResponse,
};
use crate::ops::recall::{
    Recall, RecalledRequest, RecalledResponse, RelinquishRequest, RelinquishResponse, RenewRequest,
    RenewResponse,
};
use crate::ops::share::{
    ShareAdded, ShareChanged, ShareEnded, ShareRemoved, ShareSnapshotBegin, ShareSnapshotEnd,
    ShareSnapshotPart,
};
use crate::ops::subscribe::{
    SubscribeRequest, SubscribeResponse, UnsubscribeRequest, UnsubscribeResponse,
};
use crate::ops::xattr::{
    GetxattrRequest, GetxattrResponse, ListxattrRequest, ListxattrResponse, RemovexattrRequest,
    RemovexattrResponse, SetxattrRequest, SetxattrResponse,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Declared {
    pub regions: u32,
    pub follows: Follows,
}

#[derive(Clone, Copy)]
pub struct Layout {
    pub name: &'static str,
    pub fixed: usize,
    declare: fn(&[u8], &Limits) -> Result<Declared, FramingError>,
}

impl core::fmt::Debug for Layout {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Layout")
            .field("name", &self.name)
            .field("fixed", &self.fixed)
            .finish_non_exhaustive()
    }
}

impl Layout {
    const fn of<M: WirePayload>(name: &'static str) -> Self {
        Self {
            name,
            fixed: size_of::<M>(),
            declare: declare::<M>,
        }
    }

    pub fn declared(&self, fixed: &[u8], limits: &Limits) -> Result<Declared, FramingError> {
        (self.declare)(fixed, limits)
    }
}

fn declare<M: WirePayload>(fixed: &[u8], limits: &Limits) -> Result<Declared, FramingError> {
    let body = M::ref_from_bytes(fixed).map_err(|_| FramingError::BodyTooShort {
        needed: size_of::<M>(),
        found: fixed.len(),
    })?;
    body.validate()?;
    Ok(Declared {
        regions: body.regions().check(limits)?,
        follows: body.follows(),
    })
}

macro_rules! layout {
    ($ty:ident) => {
        Layout::of::<$ty>(stringify!($ty))
    };
}

#[must_use]
pub const fn request(op: Opcode) -> Layout {
    match op {
        Opcode::Hello => layout!(HelloRequest),
        Opcode::Lookup => layout!(LookupRequest),
        Opcode::Forget => layout!(ForgetRequest),
        Opcode::Getattr => layout!(GetattrRequest),
        Opcode::Setattr => layout!(SetattrRequest),
        Opcode::Readlink => layout!(ReadlinkRequest),
        Opcode::Symlink => layout!(SymlinkRequest),
        Opcode::Mkdir => layout!(MkdirRequest),
        Opcode::Unlink => layout!(UnlinkRequest),
        Opcode::Rmdir => layout!(RmdirRequest),
        Opcode::Rename => layout!(RenameRequest),
        Opcode::Link => layout!(LinkRequest),
        Opcode::Open => layout!(OpenRequest),
        Opcode::Read => layout!(ReadRequest),
        Opcode::Write => layout!(WriteRequest),
        Opcode::Statfs => layout!(StatfsRequest),
        Opcode::Release => layout!(ReleaseRequest),
        Opcode::Fsync => layout!(FsyncRequest),
        Opcode::Setxattr => layout!(SetxattrRequest),
        Opcode::Getxattr => layout!(GetxattrRequest),
        Opcode::Listxattr => layout!(ListxattrRequest),
        Opcode::Removexattr => layout!(RemovexattrRequest),
        Opcode::Flush => layout!(FlushRequest),
        Opcode::Readdirplus => layout!(ReaddirplusRequest),
        Opcode::Create => layout!(CreateRequest),
        Opcode::Getlk => layout!(GetlkRequest),
        Opcode::Setlk => layout!(SetlkRequest),
        Opcode::Subscribe => layout!(SubscribeRequest),
        Opcode::Unsubscribe => layout!(UnsubscribeRequest),
        Opcode::Mknod => layout!(MknodRequest),
        Opcode::Outcome => layout!(OutcomeRequest),
        Opcode::Retire => layout!(RetireRequest),
        Opcode::Recalled => layout!(RecalledRequest),
        Opcode::Renew => layout!(RenewRequest),
        Opcode::Cancel => layout!(CancelRequest),
        Opcode::Relinquish => layout!(RelinquishRequest),
    }
}

#[must_use]
pub const fn response(op: Opcode) -> Option<Layout> {
    Some(match op {
        Opcode::Forget | Opcode::Cancel => return None,
        Opcode::Hello => layout!(HelloReply),
        Opcode::Lookup => layout!(LookupResponse),
        Opcode::Getattr => layout!(GetattrResponse),
        Opcode::Setattr => layout!(SetattrResponse),
        Opcode::Readlink => layout!(ReadlinkResponse),
        Opcode::Symlink => layout!(SymlinkResponse),
        Opcode::Mkdir => layout!(MkdirResponse),
        Opcode::Unlink => layout!(UnlinkResponse),
        Opcode::Rmdir => layout!(RmdirResponse),
        Opcode::Rename => layout!(RenameResponse),
        Opcode::Link => layout!(LinkResponse),
        Opcode::Open => layout!(OpenResponse),
        Opcode::Read => layout!(ReadResponse),
        Opcode::Write => layout!(WriteResponse),
        Opcode::Statfs => layout!(StatfsResponse),
        Opcode::Release => layout!(ReleaseResponse),
        Opcode::Fsync => layout!(FsyncResponse),
        Opcode::Setxattr => layout!(SetxattrResponse),
        Opcode::Getxattr => layout!(GetxattrResponse),
        Opcode::Listxattr => layout!(ListxattrResponse),
        Opcode::Removexattr => layout!(RemovexattrResponse),
        Opcode::Flush => layout!(FlushResponse),
        Opcode::Readdirplus => layout!(ReaddirplusResponse),
        Opcode::Create => layout!(CreateResponse),
        Opcode::Getlk => layout!(GetlkResponse),
        Opcode::Setlk => layout!(SetlkResponse),
        Opcode::Subscribe => layout!(SubscribeResponse),
        Opcode::Unsubscribe => layout!(UnsubscribeResponse),
        Opcode::Mknod => layout!(MknodResponse),
        Opcode::Outcome => layout!(OutcomeResponse),
        Opcode::Retire => layout!(RetireResponse),
        Opcode::Recalled => layout!(RecalledResponse),
        Opcode::Renew => layout!(RenewResponse),
        Opcode::Relinquish => layout!(RelinquishResponse),
    })
}

#[must_use]
pub const fn notification(op: NotificationOpcode) -> Layout {
    match op {
        NotificationOpcode::ShareSnapshotBegin => layout!(ShareSnapshotBegin),
        NotificationOpcode::ShareSnapshotPart => layout!(ShareSnapshotPart),
        NotificationOpcode::ShareSnapshotEnd => layout!(ShareSnapshotEnd),
        NotificationOpcode::ShareAdded => layout!(ShareAdded),
        NotificationOpcode::ShareRemoved => layout!(ShareRemoved),
        NotificationOpcode::ShareChanged => layout!(ShareChanged),
        NotificationOpcode::ShareEnded => layout!(ShareEnded),
        NotificationOpcode::Recall => layout!(Recall),
    }
}

#[must_use]
pub const fn names(table: &str, declared: &str) -> bool {
    let (table, declared) = (table.as_bytes(), declared.as_bytes());
    if table.len() != declared.len() {
        return false;
    }
    let mut index = 0;
    while index < table.len() {
        if table[index] != declared[index] {
            return false;
        }
        index += 1;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_forget_and_cancel_have_no_reply_body() {
        for op in Opcode::ALL {
            assert_eq!(response(op).is_none(), !op.has_response(), "{op}");
        }
    }

    #[test]
    fn names_compare_whole_strings() {
        assert!(names("ReadResponse", "ReadResponse"));
        assert!(!names("ReadResponse", "ReadRequest"));
        assert!(!names("Read", "ReadResponse"));
    }
}
