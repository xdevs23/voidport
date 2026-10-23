//! Kernel interface structures of `include/uapi/linux/fuse.h`, in native byte order.
//! The fields are `zerocopy` native-endian types with alignment 1, so a structure
//! can be viewed at any offset of a read buffer.

use zerocopy::byteorder::native_endian::{I32, I64, U16, U32, U64};

macro_rules! layouts {
    ($(
        $(#[$meta:meta])*
        $vis:vis struct $name:ident { $($field:ident: $ty:ty),* $(,)? }
    )*) => {$(
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, Default)]
        #[derive(
            zerocopy::FromBytes,
            zerocopy::Immutable,
            zerocopy::IntoBytes,
            zerocopy::KnownLayout,
            zerocopy::Unaligned
        )]
        #[repr(C)]
        $vis struct $name { $($vis $field: $ty),* }
    )*};
}

pub(crate) const MAJOR: u32 = 7;

/// The minor version whose structures this crate writes: Linux 7.3.
pub(crate) const MINOR: u32 = 46;

/// The oldest minor version whose requests and replies have the layouts of
/// this module. Older kernels send shorter `fuse_write_in`, `fuse_mknod_in`
/// and `fuse_create_in`, and take shorter entry and attribute replies.
pub(crate) const OLDEST_MINOR: u32 = 23;

/// The smallest buffer a read of the device may use, whatever was negotiated.
pub(crate) const MIN_READ_BUFFER: usize = 8192;

/// The size of the oldest `fuse_init_out`: the major and the minor version.
pub(crate) const COMPAT_INIT_OUT_SIZE: usize = 8;

pub const ROOT_ID: u64 = 1;

pub(crate) mod opcode {
    pub(crate) const LOOKUP: u32 = 1;
    pub(crate) const FORGET: u32 = 2;
    pub(crate) const GETATTR: u32 = 3;
    pub(crate) const SETATTR: u32 = 4;
    pub(crate) const READLINK: u32 = 5;
    pub(crate) const SYMLINK: u32 = 6;
    pub(crate) const MKNOD: u32 = 8;
    pub(crate) const MKDIR: u32 = 9;
    pub(crate) const UNLINK: u32 = 10;
    pub(crate) const RMDIR: u32 = 11;
    pub(crate) const RENAME: u32 = 12;
    pub(crate) const LINK: u32 = 13;
    pub(crate) const OPEN: u32 = 14;
    pub(crate) const READ: u32 = 15;
    pub(crate) const WRITE: u32 = 16;
    pub(crate) const STATFS: u32 = 17;
    pub(crate) const RELEASE: u32 = 18;
    pub(crate) const FSYNC: u32 = 20;
    pub(crate) const SETXATTR: u32 = 21;
    pub(crate) const GETXATTR: u32 = 22;
    pub(crate) const LISTXATTR: u32 = 23;
    pub(crate) const REMOVEXATTR: u32 = 24;
    pub(crate) const FLUSH: u32 = 25;
    pub(crate) const INIT: u32 = 26;
    pub(crate) const OPENDIR: u32 = 27;
    pub(crate) const READDIR: u32 = 28;
    pub(crate) const RELEASEDIR: u32 = 29;
    pub(crate) const FSYNCDIR: u32 = 30;
    pub(crate) const GETLK: u32 = 31;
    pub(crate) const SETLK: u32 = 32;
    pub(crate) const SETLKW: u32 = 33;
    pub(crate) const CREATE: u32 = 35;
    pub(crate) const INTERRUPT: u32 = 36;
    pub(crate) const DESTROY: u32 = 38;
    pub(crate) const IOCTL: u32 = 39;
    pub(crate) const POLL: u32 = 40;
    pub(crate) const BATCH_FORGET: u32 = 42;
    pub(crate) const READDIRPLUS: u32 = 44;
    pub(crate) const RENAME2: u32 = 45;
    pub(crate) const STATX: u32 = 52;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NotifyCode {
    InvalInode,
    Resend,
}

impl NotifyCode {
    pub(crate) fn wire(self) -> i32 {
        match self {
            Self::InvalInode => 2,
            Self::Resend => 7,
        }
    }
}

pub(crate) mod setattr {
    pub(crate) const MODE: u32 = 1 << 0;
    pub(crate) const UID: u32 = 1 << 1;
    pub(crate) const GID: u32 = 1 << 2;
    pub(crate) const SIZE: u32 = 1 << 3;
    pub(crate) const ATIME: u32 = 1 << 4;
    pub(crate) const MTIME: u32 = 1 << 5;
    pub(crate) const FH: u32 = 1 << 6;
    pub(crate) const ATIME_NOW: u32 = 1 << 7;
    pub(crate) const MTIME_NOW: u32 = 1 << 8;
    pub(crate) const CTIME: u32 = 1 << 10;
}

pub(crate) const GETATTR_FH: u32 = 1 << 0;

pub(crate) const RELEASE_FLUSH: u32 = 1 << 0;

pub(crate) const RELEASE_FLOCK_UNLOCK: u32 = 1 << 1;

pub(crate) const WRITE_KILL_SUIDGID: u32 = 1 << 2;

pub(crate) const FSYNC_FDATASYNC: u32 = 1 << 0;

layouts! {
    pub(crate) struct InHeader {
        len: U32,
        opcode: U32,
        unique: U64,
        nodeid: U64,
        uid: U32,
        gid: U32,
        pid: U32,
        total_extlen: U16,
        padding: U16,
    }

    pub(crate) struct OutHeader {
        len: U32,
        error: I32,
        unique: U64,
    }

    pub(crate) struct InitIn {
        major: U32,
        minor: U32,
        max_readahead: U32,
        flags: U32,
        flags2: U32,
        unused: [U32; 11],
    }

    pub(crate) struct InitOut {
        major: U32,
        minor: U32,
        max_readahead: U32,
        flags: U32,
        max_background: U16,
        congestion_threshold: U16,
        max_write: U32,
        time_gran: U32,
        max_pages: U16,
        map_alignment: U16,
        flags2: U32,
        max_stack_depth: U32,
        request_timeout: U16,
        unused: [U16; 11],
    }

    pub(crate) struct Attr {
        ino: U64,
        size: U64,
        blocks: U64,
        atime: U64,
        mtime: U64,
        ctime: U64,
        atimensec: U32,
        mtimensec: U32,
        ctimensec: U32,
        mode: U32,
        nlink: U32,
        uid: U32,
        gid: U32,
        rdev: U32,
        blksize: U32,
        flags: U32,
    }

    pub(crate) struct EntryOut {
        nodeid: U64,
        generation: U64,
        entry_valid: U64,
        attr_valid: U64,
        entry_valid_nsec: U32,
        attr_valid_nsec: U32,
        attr: Attr,
    }

    pub(crate) struct AttrOut {
        attr_valid: U64,
        attr_valid_nsec: U32,
        dummy: U32,
        attr: Attr,
    }

    pub(crate) struct ForgetIn {
        nlookup: U64,
    }

    pub(crate) struct ForgetOne {
        nodeid: U64,
        nlookup: U64,
    }

    pub(crate) struct BatchForgetIn {
        count: U32,
        dummy: U32,
    }

    pub(crate) struct GetattrIn {
        getattr_flags: U32,
        dummy: U32,
        fh: U64,
    }

    pub(crate) struct SetattrIn {
        valid: U32,
        padding: U32,
        fh: U64,
        size: U64,
        lock_owner: U64,
        atime: U64,
        mtime: U64,
        ctime: U64,
        atimensec: U32,
        mtimensec: U32,
        ctimensec: U32,
        mode: U32,
        unused4: U32,
        uid: U32,
        gid: U32,
        unused5: U32,
    }

    pub(crate) struct MknodIn {
        mode: U32,
        rdev: U32,
        umask: U32,
        padding: U32,
    }

    pub(crate) struct MkdirIn {
        mode: U32,
        umask: U32,
    }

    pub(crate) struct RenameIn {
        newdir: U64,
    }

    pub(crate) struct Rename2In {
        newdir: U64,
        flags: U32,
        padding: U32,
    }

    pub(crate) struct LinkIn {
        oldnodeid: U64,
    }

    pub(crate) struct OpenIn {
        flags: U32,
        open_flags: U32,
    }

    pub(crate) struct CreateIn {
        flags: U32,
        mode: U32,
        umask: U32,
        open_flags: U32,
    }

    pub(crate) struct OpenOut {
        fh: U64,
        open_flags: U32,
        backing_id: I32,
    }

    pub(crate) struct CreateOut {
        entry: EntryOut,
        open: OpenOut,
    }

    pub(crate) struct ReleaseIn {
        fh: U64,
        flags: U32,
        release_flags: U32,
        lock_owner: U64,
    }

    pub(crate) struct FlushIn {
        fh: U64,
        unused: U32,
        padding: U32,
        lock_owner: U64,
    }

    pub(crate) struct ReadIn {
        fh: U64,
        offset: U64,
        size: U32,
        read_flags: U32,
        lock_owner: U64,
        flags: U32,
        padding: U32,
    }

    pub(crate) struct WriteIn {
        fh: U64,
        offset: U64,
        size: U32,
        write_flags: U32,
        lock_owner: U64,
        flags: U32,
        padding: U32,
    }

    pub(crate) struct WriteOut {
        size: U32,
        padding: U32,
    }

    pub(crate) struct StatfsOut {
        blocks: U64,
        bfree: U64,
        bavail: U64,
        files: U64,
        ffree: U64,
        bsize: U32,
        namelen: U32,
        frsize: U32,
        padding: U32,
        spare: [U32; 6],
    }

    pub(crate) struct FsyncIn {
        fh: U64,
        fsync_flags: U32,
        padding: U32,
    }

    /// The first 8 bytes of `struct fuse_setxattr_in`, which is all a kernel
    /// sends unless FUSE_SETXATTR_EXT was negotiated.
    pub(crate) struct SetxattrIn {
        size: U32,
        flags: U32,
    }

    pub(crate) struct GetxattrIn {
        size: U32,
        padding: U32,
    }

    pub(crate) struct GetxattrOut {
        size: U32,
        padding: U32,
    }

    pub(crate) struct FileLock {
        start: U64,
        end: U64,
        lock_type: U32,
        pid: U32,
    }

    pub(crate) struct LkIn {
        fh: U64,
        owner: U64,
        lk: FileLock,
        lk_flags: U32,
        padding: U32,
    }

    pub(crate) struct LkOut {
        lk: FileLock,
    }

    pub(crate) struct InterruptIn {
        unique: U64,
    }

    pub(crate) struct IoctlIn {
        fh: U64,
        flags: U32,
        cmd: U32,
        arg: U64,
        in_size: U32,
        out_size: U32,
    }

    pub(crate) struct PollIn {
        fh: U64,
        kh: U64,
        flags: U32,
        events: U32,
    }

    pub(crate) struct PollOut {
        revents: U32,
        padding: U32,
    }

    /// `struct fuse_dirent`, without the name that follows it.
    pub(crate) struct Dirent {
        ino: U64,
        off: U64,
        namelen: U32,
        dirent_type: U32,
    }

    /// `struct fuse_direntplus`, without the name that follows it.
    pub(crate) struct Direntplus {
        entry_out: EntryOut,
        dirent: Dirent,
    }

    pub(crate) struct NotifyInvalInodeOut {
        ino: U64,
        off: I64,
        len: I64,
    }
}

#[cfg(test)]
mod tests {
    use core::mem::size_of;

    use super::*;

    #[test]
    fn every_structure_has_the_size_of_its_c_definition() {
        assert_eq!(size_of::<InHeader>(), 40);
        assert_eq!(size_of::<OutHeader>(), 16);
        assert_eq!(size_of::<InitIn>(), 64);
        assert_eq!(size_of::<InitOut>(), 64);
        assert_eq!(size_of::<Attr>(), 88);
        assert_eq!(size_of::<EntryOut>(), 128);
        assert_eq!(size_of::<AttrOut>(), 104);
        assert_eq!(size_of::<SetattrIn>(), 88);
        assert_eq!(size_of::<OpenOut>(), 16);
        assert_eq!(size_of::<CreateOut>(), 144);
        assert_eq!(size_of::<ReadIn>(), 40);
        assert_eq!(size_of::<WriteIn>(), 40);
        assert_eq!(size_of::<StatfsOut>(), 80);
        assert_eq!(size_of::<LkIn>(), 48);
        assert_eq!(size_of::<IoctlIn>(), 32);
        assert_eq!(size_of::<PollIn>(), 24);
        assert_eq!(size_of::<Dirent>(), 24);
        assert_eq!(size_of::<Direntplus>(), 152);
        assert_eq!(size_of::<NotifyInvalInodeOut>(), 24);
        assert_eq!(size_of::<SetxattrIn>(), 8);
    }
}
