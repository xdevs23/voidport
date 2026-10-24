//! The FUSE layer of the voidport client: mounting, and the kernel protocol
//! on `/dev/fuse`.
//!
//! This crate unmounts only a mount whose FUSE_INIT failed, and the caller
//! unmounts every other.

#![deny(unreachable_pub)]

mod abi;
mod attributes;
mod device;
mod flags;
mod init;
mod lock;
mod mount;
mod reply;
mod request;
mod session;
mod stop;

pub use abi::ROOT_ID;
pub use attributes::{Attributes, Entry, Permissions, Timestamp};
pub use flags::{FopenFlags, InitFlags, PollEvents};
pub use init::{Init, InitError, LimitError, MissingCapabilities};
pub use lock::{FileLock, LockType};
pub use mount::{
    AutoUnmountCopy, Fusermount, InvalidSource, MountError, MountOptions, MountSource,
    UnmountError, connection_ended, fusermount,
};
pub use reply::{
    ErrorReply, FilesystemStats, Plain, Plus, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory,
    ReplyDirectoryPlus, ReplyEmpty, ReplyEntry, ReplyInterrupt, ReplyIoctl, ReplyListing,
    ReplyLock, ReplyOpen, ReplyPoll, ReplyStatfs, ReplyWrite, ReplyXattr,
};
pub use request::{
    Child, Create, Flush, Forget, Fsync, Getattr, Getlk, Getxattr, Interrupt, Ioctl, Link,
    Listxattr, Mkdir, Mknod, Open, Operation, Poll, Read, Readlink, Release, Removexattr, Rename,
    Request, SetTime, Setattr, Setlk, Setxattr, Statfs, Symlink, Write,
};
pub use rustix::fs::{FileType, OFlags, RenameFlags, XattrFlags};
pub use rustix::io::Errno;
pub use session::{
    ClonedConnection, Connection, Filesystem, Notifier, ReadError, ServeError, Session, StartError,
};
pub use stop::{Stop, Stopper, stop};
