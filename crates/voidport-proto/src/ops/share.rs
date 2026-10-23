//! A subscribed session receives, in this order:
//!
//! ```text
//! ShareSnapshotBegin              the entries that follow supersede everything
//! ShareSnapshotPart               the entries, one per streamed piece
//! ShareSnapshotEnd                the snapshot is complete
//! ShareAdded | ShareRemoved | ShareChanged | ShareEnded   …
//! ```
//!
//! An **unsolicited** `ShareSnapshotBegin` — one the consumer did not just
//! subscribe for — is the lapse signal: the server dropped a notification queue
//! a slow consumer had let fill, and this snapshot replaces everything.

use zerocopy::byteorder::little_endian::{U16, U32};

use crate::macros::{wire_body, wire_struct};
use crate::message::{Notification, split_region};
use crate::opcode::NotificationOpcode;
use crate::stream::StreamEntry;

pub const SHARE_MODE_RW: u16 = 1;
pub const SHARE_MODE_RO: u16 = 2;

/// Target kind on the wire: the build does not know it without host I/O the
/// subscription contract does not allow, so the consumer tries and sees.
pub const SHARE_KIND_UNKNOWN: u16 = 0;
pub const SHARE_KIND_DIRECTORY: u16 = 1;
pub const SHARE_KIND_FILE: u16 = 2;

pub const SHARE_END_NAMESPACE_REMOVED: u32 = 1;

wire_struct! {
    pub struct ShareEntryHeader {
        /// [`SHARE_MODE_RW`] or [`SHARE_MODE_RO`]. Hidden never appears.
        pub mode: U16,
        pub kind: U16,
        pub path_len: U32,
    }
}

impl ShareEntryHeader {
    #[must_use]
    pub fn new(mode: u16, kind: u16, path_len: u32) -> Self {
        Self {
            mode: U16::new(mode),
            kind: U16::new(kind),
            path_len: U32::new(path_len),
        }
    }
}

impl StreamEntry for ShareEntryHeader {
    fn tail_len(&self) -> u32 {
        self.path_len.get()
    }
}

wire_struct! {
    pub struct ShareSnapshotBegin {
        pub entries: U32,
        pub reserved: U32,
    }
}

wire_body!(notification ShareSnapshotBegin => NotificationOpcode::ShareSnapshotBegin);

wire_struct! {
    pub struct ShareSnapshotPart;
}

wire_body!(
    notification ShareSnapshotPart => NotificationOpcode::ShareSnapshotPart,
    pieces = ShareEntries
);

wire_struct! {
    pub struct ShareSnapshotEnd {
        pub reserved: U32,
    }
}

wire_body!(notification ShareSnapshotEnd => NotificationOpcode::ShareSnapshotEnd);

wire_struct! {
    pub struct ShareAdded {
        pub mode: U16,
        pub kind: U16,
        pub path_len: U32,
    }
}

wire_body!(
    notification ShareAdded => NotificationOpcode::ShareAdded,
    regions = [path_len: Path]
);

wire_struct! {
    pub struct ShareChanged {
        pub mode: U16,
        pub kind: U16,
        pub path_len: U32,
    }
}

wire_body!(
    notification ShareChanged => NotificationOpcode::ShareChanged,
    regions = [path_len: Path]
);

wire_struct! {
    pub struct ShareRemoved {
        pub path_len: U32,
    }
}

wire_body!(
    notification ShareRemoved => NotificationOpcode::ShareRemoved,
    regions = [path_len: Path]
);

wire_struct! {
    pub struct ShareEnded {
        pub reason: U32,
    }
}

wire_body!(notification ShareEnded => NotificationOpcode::ShareEnded);

macro_rules! path_accessor {
    ($ty:ty) => {
        impl<'a> Notification<'a, $ty> {
            #[must_use]
            pub fn path(&self) -> &'a [u8] {
                split_region(self.payload(), self.body().path_len.get()).0
            }
        }
    };
}

path_accessor!(ShareAdded);
path_accessor!(ShareChanged);
path_accessor!(ShareRemoved);
