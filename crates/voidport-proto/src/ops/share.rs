//! The share-subscription notifications: the snapshot and the deltas.
//!
//! These are the first activations of the reserved notification range. A
//! subscribed session receives, in this order:
//!
//! ```text
//! ShareSnapshotBegin              the entries that follow supersede everything
//! ShareSnapshotPart × n           the entries, chunked to fit the frame bound
//! ShareSnapshotEnd                the snapshot is complete
//! ShareAdded | ShareRemoved | ShareChanged | ShareEnded   …
//! ```
//!
//! An **unsolicited** `ShareSnapshotBegin` — one the consumer did not just
//! subscribe for — is the lapse signal: the server dropped a notification queue
//! a slow consumer had let fill, and this snapshot replaces everything.
//!
//! One entry always fits one frame by construction: a rule path is capped at
//! 4096 bytes when the rule is added, and the negotiated frame bound is far
//! larger than that plus a fixed header.

use zerocopy::byteorder::little_endian::{U16, U32};

use crate::macros::{wire_body, wire_struct};
use crate::message::{Notification, split_region};
use crate::opcode::NotificationOpcode;
use crate::stream::{StreamEntry, StreamIter, StreamWriter};

/// Share mode on the wire: read-write.
pub const SHARE_MODE_RW: u16 = 1;
/// Share mode on the wire: read-only.
pub const SHARE_MODE_RO: u16 = 2;

/// Target kind on the wire: the build does not know it without host I/O the
/// subscription contract does not allow, so the consumer tries and sees.
pub const SHARE_KIND_UNKNOWN: u16 = 0;
/// Target kind on the wire: a directory.
pub const SHARE_KIND_DIRECTORY: u16 = 1;
/// Target kind on the wire: a regular file.
pub const SHARE_KIND_FILE: u16 = 2;

/// End reason: the namespace was deleted, so the stream is over.
pub const SHARE_END_NAMESPACE_REMOVED: u32 = 1;

wire_struct! {
    /// The fixed header of one entry in a snapshot part; the path follows it.
    ///
    /// A part's payload is a sequence of these, walked exactly as the
    /// readdirplus stream is: a fixed struct parsed by zerocopy prefix parsing,
    /// then the bytes whose length it declares.
    pub struct ShareEntryHeader {
        /// [`SHARE_MODE_RW`] or [`SHARE_MODE_RO`]. Hidden never appears.
        pub mode: U16,
        /// [`SHARE_KIND_UNKNOWN`], [`SHARE_KIND_DIRECTORY`] or
        /// [`SHARE_KIND_FILE`].
        pub kind: U16,
        /// Length of the path that follows this header.
        pub path_len: U32,
    }
}

impl ShareEntryHeader {
    /// Builds an entry header for a path of `path_len` bytes.
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

/// Iterator over a snapshot part's entry stream.
pub type ShareEntryIter<'a> = StreamIter<'a, ShareEntryHeader>;

/// Builder for a snapshot part's entry stream.
pub type ShareEntryWriter<'a> = StreamWriter<'a, ShareEntryHeader>;

wire_struct! {
    /// The snapshot starts. Every delta the consumer saw before it is
    /// superseded.
    pub struct ShareSnapshotBegin {
        /// How many entries the parts that follow carry in total, so a consumer
        /// can size its reconciliation before the first part arrives.
        pub entries: U32,
        /// Reserved; must be zero.
        pub reserved: U32,
    }
}

wire_body!(notification ShareSnapshotBegin => NotificationOpcode::ShareSnapshotBegin);

wire_struct! {
    /// One chunk of the snapshot's entries.
    pub struct ShareSnapshotPart {
        /// How many entries this part's payload holds.
        pub entries: U32,
        /// Length of the entry stream in the payload.
        pub entries_len: U32,
    }
}

wire_body!(
    notification ShareSnapshotPart => NotificationOpcode::ShareSnapshotPart,
    regions = [entries_len]
);

impl<'a> Notification<'a, ShareSnapshotPart> {
    /// Walks the entries this part carries.
    #[must_use]
    pub fn entries(&self) -> ShareEntryIter<'a> {
        ShareEntryIter::new(self.payload())
    }
}

wire_struct! {
    /// The snapshot is complete.
    pub struct ShareSnapshotEnd {
        /// Reserved; must be zero.
        pub reserved: U32,
    }
}

wire_body!(notification ShareSnapshotEnd => NotificationOpcode::ShareSnapshotEnd);

wire_struct! {
    /// An entry the session can now see. Its path follows in the payload.
    pub struct ShareAdded {
        /// [`SHARE_MODE_RW`] or [`SHARE_MODE_RO`].
        pub mode: U16,
        /// The target kind.
        pub kind: U16,
        /// Length of the path in the payload.
        pub path_len: U32,
    }
}

wire_body!(notification ShareAdded => NotificationOpcode::ShareAdded, regions = [path_len]);

wire_struct! {
    /// An entry whose mode or target kind changed. Its path follows in the
    /// payload.
    pub struct ShareChanged {
        /// The mode it now has.
        pub mode: U16,
        /// The target kind it now has.
        pub kind: U16,
        /// Length of the path in the payload.
        pub path_len: U32,
    }
}

wire_body!(notification ShareChanged => NotificationOpcode::ShareChanged, regions = [path_len]);

wire_struct! {
    /// An entry the session can no longer see. Its path follows in the payload;
    /// nothing else is carried, because nothing else is left to say about it.
    pub struct ShareRemoved {
        /// Length of the path in the payload.
        pub path_len: U32,
    }
}

wire_body!(notification ShareRemoved => NotificationOpcode::ShareRemoved, regions = [path_len]);

wire_struct! {
    /// The stream is over; nothing further arrives on it.
    pub struct ShareEnded {
        /// Why, e.g. [`SHARE_END_NAMESPACE_REMOVED`].
        pub reason: U32,
    }
}

wire_body!(notification ShareEnded => NotificationOpcode::ShareEnded);

/// Gives a single-path notification its path accessor.
macro_rules! path_accessor {
    ($ty:ty) => {
        impl<'a> Notification<'a, $ty> {
            /// The entry path, relative to the session's mount root.
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
