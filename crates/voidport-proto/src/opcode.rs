use core::fmt;

pub const REQUEST_OPCODE_MIN: u16 = 0x0001;
pub const REQUEST_OPCODE_MAX: u16 = 0x7FFF;
pub const NOTIFICATION_OPCODE_MIN: u16 = 0x8000;
pub const NOTIFICATION_OPCODE_MAX: u16 = 0xFFFF;

#[must_use]
pub const fn is_notification_opcode(raw: u16) -> bool {
    raw >= NOTIFICATION_OPCODE_MIN
}

pub mod values {
    pub const HELLO: u16 = 0x0001;
    pub const LOOKUP: u16 = 0x0002;
    pub const FORGET: u16 = 0x0003;
    pub const GETATTR: u16 = 0x0004;
    pub const SETATTR: u16 = 0x0005;
    pub const READLINK: u16 = 0x0006;
    pub const SYMLINK: u16 = 0x0007;
    pub const MKDIR: u16 = 0x0008;
    pub const UNLINK: u16 = 0x0009;
    pub const RMDIR: u16 = 0x000A;
    pub const RENAME: u16 = 0x000B;
    pub const LINK: u16 = 0x000C;
    pub const OPEN: u16 = 0x000D;
    pub const READ: u16 = 0x000E;
    pub const WRITE: u16 = 0x000F;
    pub const STATFS: u16 = 0x0010;
    pub const RELEASE: u16 = 0x0011;
    pub const FSYNC: u16 = 0x0012;
    pub const SETXATTR: u16 = 0x0013;
    pub const GETXATTR: u16 = 0x0014;
    pub const LISTXATTR: u16 = 0x0015;
    pub const REMOVEXATTR: u16 = 0x0016;
    pub const FLUSH: u16 = 0x0017;
    pub const READDIRPLUS: u16 = 0x0018;
    pub const CREATE: u16 = 0x0019;
    pub const GETLK: u16 = 0x001A;
    pub const SETLK: u16 = 0x001B;
    pub const SUBSCRIBE: u16 = 0x001C;
    pub const UNSUBSCRIBE: u16 = 0x001D;
    pub const MKNOD: u16 = 0x001E;
    pub const OUTCOME: u16 = 0x001F;
    pub const RETIRE: u16 = 0x0020;
    pub const RECALLED: u16 = 0x0021;
    pub const RENEW: u16 = 0x0022;
    pub const CANCEL: u16 = 0x0023;
    pub const RELINQUISH: u16 = 0x0024;
}

pub mod notifications {
    pub const SHARE_SNAPSHOT_BEGIN: u16 = 0x8001;
    pub const SHARE_SNAPSHOT_PART: u16 = 0x8002;
    pub const SHARE_SNAPSHOT_END: u16 = 0x8003;
    pub const SHARE_ADDED: u16 = 0x8004;
    pub const SHARE_REMOVED: u16 = 0x8005;
    pub const SHARE_CHANGED: u16 = 0x8006;
    pub const SHARE_ENDED: u16 = 0x8007;
    pub const RECALL: u16 = 0x8008;
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u16)]
/// Exhaustive on purpose, so a total match flags an unhandled operation when
/// the set grows.
pub enum Opcode {
    /// Session handshake; must be the first frame on a connection.
    Hello = values::HELLO,
    Lookup = values::LOOKUP,
    Forget = values::FORGET,
    Getattr = values::GETATTR,
    Setattr = values::SETATTR,
    Readlink = values::READLINK,
    Symlink = values::SYMLINK,
    Mkdir = values::MKDIR,
    Unlink = values::UNLINK,
    Rmdir = values::RMDIR,
    Rename = values::RENAME,
    Link = values::LINK,
    Open = values::OPEN,
    Read = values::READ,
    Write = values::WRITE,
    Statfs = values::STATFS,
    Release = values::RELEASE,
    Fsync = values::FSYNC,
    Setxattr = values::SETXATTR,
    Getxattr = values::GETXATTR,
    Listxattr = values::LISTXATTR,
    Removexattr = values::REMOVEXATTR,
    Flush = values::FLUSH,
    Readdirplus = values::READDIRPLUS,
    Create = values::CREATE,
    Getlk = values::GETLK,
    Setlk = values::SETLK,
    /// Start or restart the share subscription of the session. The server
    /// confirms, then sends a snapshot, then deltas.
    Subscribe = values::SUBSCRIBE,
    /// End the session's share subscription. A no-op on a session that has
    /// none, which is what makes it idempotent across a reconnect.
    Unsubscribe = values::UNSUBSCRIBE,
    /// Create a FIFO or a socket file. A device node is rejected.
    Mknod = values::MKNOD,
    /// What became of a request whose connection was lost while its session
    /// lives on.
    Outcome = values::OUTCOME,
    /// End the records the server keeps for a lost connection.
    Retire = values::RETIRE,
    /// Answer a recall: the guest dropped the pages it was asked to.
    Recalled = values::RECALLED,
    /// Renew the window in which the pages the guest keeps are valid.
    Renew = values::RENEW,
    /// End a request of the same connection that waits in the server. Like a
    /// forget, a cancel gets no reply.
    Cancel = values::CANCEL,
    /// Give every lease of the session up: the guest caches no page of the
    /// session any more, and fills none.
    Relinquish = values::RELINQUISH,
}

impl Opcode {
    pub const ALL: [Self; 36] = [
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
        Self::Outcome,
        Self::Retire,
        Self::Recalled,
        Self::Renew,
        Self::Cancel,
        Self::Relinquish,
    ];

    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self as u16
    }

    #[must_use]
    pub const fn has_response(self) -> bool {
        !matches!(self, Self::Forget | Self::Cancel)
    }

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
            Self::Outcome => "outcome",
            Self::Retire => "retire",
            Self::Recalled => "recalled",
            Self::Renew => "renew",
            Self::Cancel => "cancel",
            Self::Relinquish => "relinquish",
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
            values::OUTCOME => Ok(Self::Outcome),
            values::RETIRE => Ok(Self::Retire),
            values::RECALLED => Ok(Self::Recalled),
            values::RENEW => Ok(Self::Renew),
            values::CANCEL => Ok(Self::Cancel),
            values::RELINQUISH => Ok(Self::Relinquish),
            other => Err(UnknownOpcode(other)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u16)]
/// A separate registry from [`Opcode`]: a notification has request id 0
/// and expects no reply.
pub enum NotificationOpcode {
    /// The share snapshot starts here; every delta before it is superseded.
    ShareSnapshotBegin = notifications::SHARE_SNAPSHOT_BEGIN,
    ShareSnapshotPart = notifications::SHARE_SNAPSHOT_PART,
    ShareSnapshotEnd = notifications::SHARE_SNAPSHOT_END,
    ShareAdded = notifications::SHARE_ADDED,
    ShareRemoved = notifications::SHARE_REMOVED,
    ShareChanged = notifications::SHARE_CHANGED,
    ShareEnded = notifications::SHARE_ENDED,
    /// Drop the pages cached for a file, then reply.
    Recall = notifications::RECALL,
}

impl NotificationOpcode {
    pub const ALL: [Self; 8] = [
        Self::ShareSnapshotBegin,
        Self::ShareSnapshotPart,
        Self::ShareSnapshotEnd,
        Self::ShareAdded,
        Self::ShareRemoved,
        Self::ShareChanged,
        Self::ShareEnded,
        Self::Recall,
    ];

    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self as u16
    }

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
            Self::Recall => "recall",
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

    fn try_from(raw: u16) -> Result<Self, Self::Error> {
        match raw {
            notifications::SHARE_SNAPSHOT_BEGIN => Ok(Self::ShareSnapshotBegin),
            notifications::SHARE_SNAPSHOT_PART => Ok(Self::ShareSnapshotPart),
            notifications::SHARE_SNAPSHOT_END => Ok(Self::ShareSnapshotEnd),
            notifications::SHARE_ADDED => Ok(Self::ShareAdded),
            notifications::SHARE_REMOVED => Ok(Self::ShareRemoved),
            notifications::SHARE_CHANGED => Ok(Self::ShareChanged),
            notifications::SHARE_ENDED => Ok(Self::ShareEnded),
            notifications::RECALL => Ok(Self::Recall),
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnknownOpcode(pub u16);

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
    fn only_forget_and_cancel_have_no_response() {
        for op in Opcode::ALL {
            assert_eq!(
                op.has_response(),
                !matches!(op, Opcode::Forget | Opcode::Cancel)
            );
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
