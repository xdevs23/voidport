//! Each value is the one `include/uapi/linux/fuse.h` or the poll interface of
//! Linux gives it. The flags of `open(2)`, `renameat2(2)` and `setxattr(2)` are
//! those of rustix.

use linux_raw_sys::general as uapi;

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct InitFlags: u64 {
        /// The reads that fill the page cache are sent in the background.
        const ASYNC_READ = 1 << 0;
        /// POSIX record locks are sent to the filesystem.
        const POSIX_LOCKS = 1 << 1;
        /// Writes larger than a page are sent as one request.
        const BIG_WRITES = 1 << 5;
        /// Cached pages are dropped when the size or modification time of a
        /// file is seen to change.
        const AUTO_INVAL_DATA = 1 << 12;
        /// Directory listings contain entries with attributes.
        const DO_READDIRPLUS = 1 << 13;
        /// `max_pages` of the reply sets the largest request in pages.
        const MAX_PAGES = 1 << 22;
        /// The second word of flags is valid.
        const INIT_EXT = 1 << 30;
        /// The kernel takes FUSE_NOTIFY_RESEND and marks resent requests.
        const HAS_RESEND = 1 << 39;

        // Retains every other bit, so a set is passed on as it was sent.
        const _ = !0;
    }
}

impl InitFlags {
    pub(crate) fn from_words(low: u32, high: u32) -> Self {
        Self::from_bits_retain(u64::from(low) | u64::from(high) << 32)
    }

    pub(crate) fn words(self) -> (u32, u32) {
        let [b0, b1, b2, b3, b4, b5, b6, b7] = self.bits().to_le_bytes();
        (
            u32::from_le_bytes([b0, b1, b2, b3]),
            u32::from_le_bytes([b4, b5, b6, b7]),
        )
    }
}

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct FopenFlags: u32 {
        const DIRECT_IO = 1 << 0;
        /// Pages cached for the file before this open remain valid.
        const KEEP_CACHE = 1 << 1;
    }
}

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct PollEvents: u32 {
        const POLLIN = uapi::POLLIN;
        const POLLPRI = uapi::POLLPRI;
        const POLLOUT = uapi::POLLOUT;
        const POLLERR = uapi::POLLERR;
        const POLLHUP = uapi::POLLHUP;
        const POLLRDNORM = uapi::POLLRDNORM;
        const POLLRDBAND = uapi::POLLRDBAND;
        const POLLWRNORM = uapi::POLLWRNORM;
        const POLLWRBAND = uapi::POLLWRBAND;

        // Retains every other bit, so a set is passed on as it was sent.
        const _ = !0;
    }
}
