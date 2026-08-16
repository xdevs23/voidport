//! The opcode registry.
//!
//! Numeric opcode values are explicitly assigned, stable and documented: they
//! are part of the ABI. Changing an assignment requires a
//! [`PROTOCOL_VERSION`](crate::PROTOCOL_VERSION) bump.
//!
//! The 16-bit opcode space is partitioned:
//!
//! | Range | Meaning |
//! |---|---|
//! | `0x0000` | reserved, never valid on the wire |
//! | [`REQUEST_OPCODE_MIN`]`..=`[`REQUEST_OPCODE_MAX`] | requests, and the responses echoing them |
//! | [`NOTIFICATION_OPCODE_MIN`]`..=`[`NOTIFICATION_OPCODE_MAX`] | server-initiated notifications |
//!
//! The notification range is defined so it is distinguishable from a request
//! by inspecting the header alone (see [`is_notification_opcode`]). v1 first
//! activated it for the share subscription ([`NotificationOpcode`]); adding a
//! request opcode in the unassigned range, or activating a reserved
//! notification opcode, leaves every existing message untouched and is
//! therefore **not** an ABI change — the unknown-opcode `ENOSYS` answer is the
//! discovery mechanism, and older clients never see the new frames.

use core::fmt;

/// Lowest opcode value usable by a request.
pub const REQUEST_OPCODE_MIN: u16 = 0x0001;
/// Highest opcode value usable by a request.
pub const REQUEST_OPCODE_MAX: u16 = 0x7FFF;
/// Lowest opcode value in the server-initiated notification range.
pub const NOTIFICATION_OPCODE_MIN: u16 = 0x8000;
/// Highest opcode value in the server-initiated notification range.
pub const NOTIFICATION_OPCODE_MAX: u16 = 0xFFFF;

/// Returns whether a raw opcode falls in the notification range.
///
/// This is a pure header-level test: it never parses an op-specific body.
#[must_use]
pub const fn is_notification_opcode(raw: u16) -> bool {
    raw >= NOTIFICATION_OPCODE_MIN
}

/// The assigned numeric opcode values.
///
/// These constants are the ABI. [`Opcode`] discriminants are defined from
/// them, so the enum and the constants can never drift apart.
pub mod values {
    /// [`Opcode::Hello`](super::Opcode::Hello).
    pub const HELLO: u16 = 0x0001;
    /// [`Opcode::Lookup`](super::Opcode::Lookup).
    pub const LOOKUP: u16 = 0x0002;
    /// [`Opcode::Forget`](super::Opcode::Forget).
    pub const FORGET: u16 = 0x0003;
    /// [`Opcode::Getattr`](super::Opcode::Getattr).
    pub const GETATTR: u16 = 0x0004;
    /// [`Opcode::Setattr`](super::Opcode::Setattr).
    pub const SETATTR: u16 = 0x0005;
    /// [`Opcode::Readlink`](super::Opcode::Readlink).
    pub const READLINK: u16 = 0x0006;
    /// [`Opcode::Symlink`](super::Opcode::Symlink).
    pub const SYMLINK: u16 = 0x0007;
    /// [`Opcode::Mkdir`](super::Opcode::Mkdir).
    pub const MKDIR: u16 = 0x0008;
    /// [`Opcode::Unlink`](super::Opcode::Unlink).
    pub const UNLINK: u16 = 0x0009;
    /// [`Opcode::Rmdir`](super::Opcode::Rmdir).
    pub const RMDIR: u16 = 0x000A;
    /// [`Opcode::Rename`](super::Opcode::Rename).
    pub const RENAME: u16 = 0x000B;
    /// [`Opcode::Link`](super::Opcode::Link).
    pub const LINK: u16 = 0x000C;
    /// [`Opcode::Open`](super::Opcode::Open).
    pub const OPEN: u16 = 0x000D;
    /// [`Opcode::Read`](super::Opcode::Read).
    pub const READ: u16 = 0x000E;
    /// [`Opcode::Write`](super::Opcode::Write).
    pub const WRITE: u16 = 0x000F;
    /// [`Opcode::Statfs`](super::Opcode::Statfs).
    pub const STATFS: u16 = 0x0010;
    /// [`Opcode::Release`](super::Opcode::Release).
    pub const RELEASE: u16 = 0x0011;
    /// [`Opcode::Fsync`](super::Opcode::Fsync).
    pub const FSYNC: u16 = 0x0012;
    /// [`Opcode::Setxattr`](super::Opcode::Setxattr).
    pub const SETXATTR: u16 = 0x0013;
    /// [`Opcode::Getxattr`](super::Opcode::Getxattr).
    pub const GETXATTR: u16 = 0x0014;
    /// [`Opcode::Listxattr`](super::Opcode::Listxattr).
    pub const LISTXATTR: u16 = 0x0015;
    /// [`Opcode::Removexattr`](super::Opcode::Removexattr).
    pub const REMOVEXATTR: u16 = 0x0016;
    /// [`Opcode::Flush`](super::Opcode::Flush).
    pub const FLUSH: u16 = 0x0017;
    /// [`Opcode::Readdirplus`](super::Opcode::Readdirplus).
    pub const READDIRPLUS: u16 = 0x0018;
    /// [`Opcode::Create`](super::Opcode::Create).
    pub const CREATE: u16 = 0x0019;
    /// [`Opcode::Getlk`](super::Opcode::Getlk).
    pub const GETLK: u16 = 0x001A;
    /// [`Opcode::Setlk`](super::Opcode::Setlk).
    pub const SETLK: u16 = 0x001B;
    /// [`Opcode::Subscribe`](super::Opcode::Subscribe).
    pub const SUBSCRIBE: u16 = 0x001C;
    /// [`Opcode::Unsubscribe`](super::Opcode::Unsubscribe).
    pub const UNSUBSCRIBE: u16 = 0x001D;
    /// [`Opcode::Mknod`](super::Opcode::Mknod).
    pub const MKNOD: u16 = 0x001E;
}

/// The assigned numeric values of the server-initiated notifications.
///
/// These are the first activations of the reserved notification range, and
/// they are the ABI exactly as the request opcodes are.
pub mod notifications {
    /// [`NotificationOpcode::ShareSnapshotBegin`](super::NotificationOpcode::ShareSnapshotBegin).
    pub const SHARE_SNAPSHOT_BEGIN: u16 = 0x8001;
    /// [`NotificationOpcode::ShareSnapshotPart`](super::NotificationOpcode::ShareSnapshotPart).
    pub const SHARE_SNAPSHOT_PART: u16 = 0x8002;
    /// [`NotificationOpcode::ShareSnapshotEnd`](super::NotificationOpcode::ShareSnapshotEnd).
    pub const SHARE_SNAPSHOT_END: u16 = 0x8003;
    /// [`NotificationOpcode::ShareAdded`](super::NotificationOpcode::ShareAdded).
    pub const SHARE_ADDED: u16 = 0x8004;
    /// [`NotificationOpcode::ShareRemoved`](super::NotificationOpcode::ShareRemoved).
    pub const SHARE_REMOVED: u16 = 0x8005;
    /// [`NotificationOpcode::ShareChanged`](super::NotificationOpcode::ShareChanged).
    pub const SHARE_CHANGED: u16 = 0x8006;
    /// [`NotificationOpcode::ShareEnded`](super::NotificationOpcode::ShareEnded).
    pub const SHARE_ENDED: u16 = 0x8007;
}

/// A known request opcode.
///
/// The enum is exhaustive on purpose: a server can match it totally and the
/// compiler flags any operation left unhandled when the set grows. Unknown
/// values are *not* represented here — they are a semantic error
/// ([`UnknownOpcode`], answered with `ENOSYS`), not a framing error.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u16)]
pub enum Opcode {
    /// Session handshake; must be the first frame on a connection.
    Hello = values::HELLO,
    /// Resolve a name in a directory node.
    Lookup = values::LOOKUP,
    /// Drop lookup counts on a node. The only request with no response.
    Forget = values::FORGET,
    /// Fetch attributes.
    Getattr = values::GETATTR,
    /// Change attributes, selected by a validity bitmask.
    Setattr = values::SETATTR,
    /// Read a symlink target.
    Readlink = values::READLINK,
    /// Create a symlink.
    Symlink = values::SYMLINK,
    /// Create a directory.
    Mkdir = values::MKDIR,
    /// Remove a non-directory entry.
    Unlink = values::UNLINK,
    /// Remove a directory.
    Rmdir = values::RMDIR,
    /// Rename an entry, possibly across directories.
    Rename = values::RENAME,
    /// Create a hard link.
    Link = values::LINK,
    /// Open an existing file and obtain a handle.
    Open = values::OPEN,
    /// Read file data.
    Read = values::READ,
    /// Write file data.
    Write = values::WRITE,
    /// Filesystem statistics.
    Statfs = values::STATFS,
    /// Release a handle.
    Release = values::RELEASE,
    /// Flush data (and optionally only data) to stable storage.
    Fsync = values::FSYNC,
    /// Set an extended attribute.
    Setxattr = values::SETXATTR,
    /// Get an extended attribute.
    Getxattr = values::GETXATTR,
    /// List extended attribute names.
    Listxattr = values::LISTXATTR,
    /// Remove an extended attribute.
    Removexattr = values::REMOVEXATTR,
    /// Flush on close of a file descriptor.
    Flush = values::FLUSH,
    /// Enumerate a directory, attributes included.
    Readdirplus = values::READDIRPLUS,
    /// Create and open a file in one round trip.
    Create = values::CREATE,
    /// Test a POSIX file lock.
    Getlk = values::GETLK,
    /// Acquire or release a POSIX file lock.
    Setlk = values::SETLK,
    /// Start — or restart — the session's share subscription. The server
    /// confirms, then sends a snapshot, then deltas.
    Subscribe = values::SUBSCRIBE,
    /// End the session's share subscription. A no-op on a session that has
    /// none, which is what makes it idempotent across a reconnect.
    Unsubscribe = values::UNSUBSCRIBE,
    /// Create a FIFO or a socket file. Device nodes are refused.
    ///
    /// Added after the opcodes above, with every existing message untouched,
    /// which the stability rule says is not an ABI change: a server that does
    /// not know it answers `ENOSYS`, and the client surfaces that as `EPERM`.
    Mknod = values::MKNOD,
}

impl Opcode {
    /// Every opcode, in assignment order.
    pub const ALL: [Self; 30] = [
        Self::Hello,
        Self::Lookup,
        Self::Forget,
        Self::Getattr,
        Self::Setattr,
        Self::Readlink,
        Self::Symlink,
        Self::Mkdir,
        Self::Unlink,
        Self::Rmdir,
        Self::Rename,
        Self::Link,
        Self::Open,
        Self::Read,
        Self::Write,
        Self::Statfs,
        Self::Release,
        Self::Fsync,
        Self::Setxattr,
        Self::Getxattr,
        Self::Listxattr,
        Self::Removexattr,
        Self::Flush,
        Self::Readdirplus,
        Self::Create,
        Self::Getlk,
        Self::Setlk,
        Self::Subscribe,
        Self::Unsubscribe,
        Self::Mknod,
    ];

    /// The assigned numeric value.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self as u16
    }

    /// Whether the peer must answer this request with a response frame.
    ///
    /// False for [`Opcode::Forget`] only, following FUSE semantics.
    #[must_use]
    pub const fn has_response(self) -> bool {
        !matches!(self, Self::Forget)
    }

    /// The opcode's name, for logs and diagnostics.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Hello => "hello",
            Self::Lookup => "lookup",
            Self::Forget => "forget",
            Self::Getattr => "getattr",
            Self::Setattr => "setattr",
            Self::Readlink => "readlink",
            Self::Symlink => "symlink",
            Self::Mkdir => "mkdir",
            Self::Unlink => "unlink",
            Self::Rmdir => "rmdir",
            Self::Rename => "rename",
            Self::Link => "link",
            Self::Open => "open",
            Self::Read => "read",
            Self::Write => "write",
            Self::Statfs => "statfs",
            Self::Release => "release",
            Self::Fsync => "fsync",
            Self::Setxattr => "setxattr",
            Self::Getxattr => "getxattr",
            Self::Listxattr => "listxattr",
            Self::Removexattr => "removexattr",
            Self::Flush => "flush",
            Self::Readdirplus => "readdirplus",
            Self::Create => "create",
            Self::Getlk => "getlk",
            Self::Setlk => "setlk",
            Self::Subscribe => "subscribe",
            Self::Unsubscribe => "unsubscribe",
            Self::Mknod => "mknod",
        }
    }
}

impl From<Opcode> for u16 {
    fn from(opcode: Opcode) -> Self {
        opcode.as_u16()
    }
}

impl TryFrom<u16> for Opcode {
    type Error = UnknownOpcode;

    /// Classifies a raw opcode as known or unknown.
    fn try_from(raw: u16) -> Result<Self, Self::Error> {
        match raw {
            values::HELLO => Ok(Self::Hello),
            values::LOOKUP => Ok(Self::Lookup),
            values::FORGET => Ok(Self::Forget),
            values::GETATTR => Ok(Self::Getattr),
            values::SETATTR => Ok(Self::Setattr),
            values::READLINK => Ok(Self::Readlink),
            values::SYMLINK => Ok(Self::Symlink),
            values::MKDIR => Ok(Self::Mkdir),
            values::UNLINK => Ok(Self::Unlink),
            values::RMDIR => Ok(Self::Rmdir),
            values::RENAME => Ok(Self::Rename),
            values::LINK => Ok(Self::Link),
            values::OPEN => Ok(Self::Open),
            values::READ => Ok(Self::Read),
            values::WRITE => Ok(Self::Write),
            values::STATFS => Ok(Self::Statfs),
            values::RELEASE => Ok(Self::Release),
            values::FSYNC => Ok(Self::Fsync),
            values::SETXATTR => Ok(Self::Setxattr),
            values::GETXATTR => Ok(Self::Getxattr),
            values::LISTXATTR => Ok(Self::Listxattr),
            values::REMOVEXATTR => Ok(Self::Removexattr),
            values::FLUSH => Ok(Self::Flush),
            values::READDIRPLUS => Ok(Self::Readdirplus),
            values::CREATE => Ok(Self::Create),
            values::GETLK => Ok(Self::Getlk),
            values::SETLK => Ok(Self::Setlk),
            values::SUBSCRIBE => Ok(Self::Subscribe),
            values::UNSUBSCRIBE => Ok(Self::Unsubscribe),
            values::MKNOD => Ok(Self::Mknod),
            other => Err(UnknownOpcode(other)),
        }
    }
}

/// A known server-initiated notification opcode.
///
/// A separate registry from [`Opcode`], because the two ranges are different
/// classes of frame: a notification carries request id 0, expects no reply, and
/// can never be echoed by an error response. Keeping them in one enum would
/// make every `has_response` and every error-response echo a special case.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u16)]
pub enum NotificationOpcode {
    /// The share snapshot starts here; every delta before it is superseded.
    ShareSnapshotBegin = notifications::SHARE_SNAPSHOT_BEGIN,
    /// One chunk of the snapshot's entries.
    ShareSnapshotPart = notifications::SHARE_SNAPSHOT_PART,
    /// The share snapshot is complete.
    ShareSnapshotEnd = notifications::SHARE_SNAPSHOT_END,
    /// An entry the session can now see.
    ShareAdded = notifications::SHARE_ADDED,
    /// An entry the session can no longer see.
    ShareRemoved = notifications::SHARE_REMOVED,
    /// An entry whose mode or target kind changed.
    ShareChanged = notifications::SHARE_CHANGED,
    /// The stream is over and nothing further will arrive on it.
    ShareEnded = notifications::SHARE_ENDED,
}

impl NotificationOpcode {
    /// Every notification opcode, in assignment order.
    pub const ALL: [Self; 7] = [
        Self::ShareSnapshotBegin,
        Self::ShareSnapshotPart,
        Self::ShareSnapshotEnd,
        Self::ShareAdded,
        Self::ShareRemoved,
        Self::ShareChanged,
        Self::ShareEnded,
    ];

    /// The assigned numeric value.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self as u16
    }

    /// The opcode's name, for logs and diagnostics.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::ShareSnapshotBegin => "share-snapshot-begin",
            Self::ShareSnapshotPart => "share-snapshot-part",
            Self::ShareSnapshotEnd => "share-snapshot-end",
            Self::ShareAdded => "share-added",
            Self::ShareRemoved => "share-removed",
            Self::ShareChanged => "share-changed",
            Self::ShareEnded => "share-ended",
        }
    }
}

impl From<NotificationOpcode> for u16 {
    fn from(opcode: NotificationOpcode) -> Self {
        opcode.as_u16()
    }
}

impl TryFrom<u16> for NotificationOpcode {
    type Error = UnknownOpcode;

    /// Classifies a raw notification opcode as known or unknown.
    ///
    /// An unknown one is not an error at all for a receiver: the wire contract
    /// has clients ignore notifications they do not understand, which is what
    /// keeps the range extensible.
    fn try_from(raw: u16) -> Result<Self, Self::Error> {
        match raw {
            notifications::SHARE_SNAPSHOT_BEGIN => Ok(Self::ShareSnapshotBegin),
            notifications::SHARE_SNAPSHOT_PART => Ok(Self::ShareSnapshotPart),
            notifications::SHARE_SNAPSHOT_END => Ok(Self::ShareSnapshotEnd),
            notifications::SHARE_ADDED => Ok(Self::ShareAdded),
            notifications::SHARE_REMOVED => Ok(Self::ShareRemoved),
            notifications::SHARE_CHANGED => Ok(Self::ShareChanged),
            notifications::SHARE_ENDED => Ok(Self::ShareEnded),
            other => Err(UnknownOpcode(other)),
        }
    }
}

impl fmt::Display for NotificationOpcode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl fmt::Display for Opcode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// A well-framed message carried an opcode this build does not know.
///
/// This is a *semantic* error, not a framing error: the receiver answers with
/// an error response (`ENOSYS`) and keeps the connection alive, which is what
/// makes protocol extension non-fatal to old peers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnknownOpcode(
    /// The unrecognized raw opcode.
    pub u16,
);

impl fmt::Display for UnknownOpcode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown opcode {:#06x}", self.0)
    }
}

impl core::error::Error for UnknownOpcode {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assignments_are_unique_and_in_the_request_range() {
        for (i, op) in Opcode::ALL.iter().enumerate() {
            assert!(
                (REQUEST_OPCODE_MIN..=REQUEST_OPCODE_MAX).contains(&op.as_u16()),
                "{op} is outside the request range"
            );
            assert!(!is_notification_opcode(op.as_u16()));
            for other in &Opcode::ALL[i + 1..] {
                assert_ne!(op.as_u16(), other.as_u16(), "{op} and {other} collide");
            }
        }
    }

    #[test]
    fn classification_round_trips() {
        for op in Opcode::ALL {
            assert_eq!(Opcode::try_from(op.as_u16()), Ok(op));
        }
        assert_eq!(Opcode::try_from(0), Err(UnknownOpcode(0)));
        assert_eq!(Opcode::try_from(0x7FFF), Err(UnknownOpcode(0x7FFF)));
        assert_eq!(Opcode::try_from(0x8000), Err(UnknownOpcode(0x8000)));
    }

    #[test]
    fn only_forget_has_no_response() {
        for op in Opcode::ALL {
            assert_eq!(op.has_response(), op != Opcode::Forget);
        }
    }

    #[test]
    fn notification_range_is_a_header_level_test() {
        assert!(!is_notification_opcode(REQUEST_OPCODE_MAX));
        assert!(is_notification_opcode(NOTIFICATION_OPCODE_MIN));
        assert!(is_notification_opcode(NOTIFICATION_OPCODE_MAX));
    }

    #[test]
    fn notification_assignments_are_unique_and_in_their_own_range() {
        for (i, op) in NotificationOpcode::ALL.iter().enumerate() {
            assert!(
                is_notification_opcode(op.as_u16()),
                "{op} is outside the notification range"
            );
            assert_eq!(NotificationOpcode::try_from(op.as_u16()), Ok(*op));
            // A notification opcode is never a request opcode, and the two
            // registries never answer for each other.
            assert_eq!(
                Opcode::try_from(op.as_u16()),
                Err(UnknownOpcode(op.as_u16()))
            );
            for other in &NotificationOpcode::ALL[i + 1..] {
                assert_ne!(op.as_u16(), other.as_u16(), "{op} and {other} collide");
            }
        }
        assert_eq!(
            NotificationOpcode::try_from(NOTIFICATION_OPCODE_MIN),
            Err(UnknownOpcode(NOTIFICATION_OPCODE_MIN)),
            "0x8000 is reserved, not assigned"
        );
        for op in Opcode::ALL {
            assert_eq!(
                NotificationOpcode::try_from(op.as_u16()),
                Err(UnknownOpcode(op.as_u16()))
            );
        }
    }
}
