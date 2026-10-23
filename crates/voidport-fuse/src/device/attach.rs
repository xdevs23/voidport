use std::io;
use std::os::fd::{AsRawFd as _, BorrowedFd};

use rustix::ioctl::{Opcode, Setter, ioctl, opcode};

/// `FUSE_DEV_IOC_CLONE`: `_IOR(229, 0, uint32_t)`. The argument is a pointer
/// to the number of a descriptor that is attached to a connection already.
const CLONE: Opcode = opcode::read::<u32>(229, 0);

/// The error of the kernel: `EINVAL` when `existing` is not a descriptor of
/// `/dev/fuse` or `new` is attached already, `EPERM` when `existing` is
/// attached to no connection.
pub(crate) fn attach(new: BorrowedFd<'_>, existing: BorrowedFd<'_>) -> io::Result<()> {
    let number = u32::try_from(existing.as_raw_fd())
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: Unavoidable: rustix wraps only the ioctls it names, such as
    // `ioctl_fionread`, and FUSE_DEV_IOC_CLONE is none of them. `CLONE` is the
    // opcode `include/uapi/linux/fuse.h` defines for FUSE_DEV_IOC_CLONE, and
    // the kernel reads exactly one `u32` through the pointer the `Setter`
    // passes (`get_user` of a `__u32` in `fs/fuse/dev.c`, Linux 7.3), which
    // is the `Input` type given here. The pointer refers to the `Setter` itself,
    // which lives for the whole call, and the kernel stores nothing after the
    // call returns. `new` is a live descriptor for the duration of the
    // borrow. The tests below show that the kernel reads the number: it
    // tells a descriptor of another device from an unattached one of
    // `/dev/fuse`.
    unsafe { ioctl(new, Setter::<CLONE, u32>::new(number)) }.map_err(io::Error::from)
}

#[cfg(test)]
mod tests {
    use std::os::fd::{AsFd as _, OwnedFd};

    use rustix::fs::{Mode, OFlags, open};
    use rustix::io::Errno;

    use super::*;

    fn device() -> OwnedFd {
        open("/dev/fuse", OFlags::RDWR | OFlags::CLOEXEC, Mode::empty()).expect("/dev/fuse opens")
    }

    fn errno(error: &io::Error) -> Option<Errno> {
        error.raw_os_error().map(Errno::from_raw_os_error)
    }

    #[test]
    fn a_descriptor_without_a_connection_lends_none() {
        let (new, unattached) = (device(), device());
        let failed = attach(new.as_fd(), unattached.as_fd()).expect_err("nothing to attach to");
        assert_eq!(errno(&failed), Some(Errno::PERM));
    }

    #[test]
    fn a_descriptor_of_another_device_lends_none() {
        let new = device();
        let (pipe, _) = std::io::pipe().expect("a pipe");
        let failed = attach(new.as_fd(), pipe.as_fd()).expect_err("not a FUSE device");
        assert_eq!(errno(&failed), Some(Errno::INVAL));
    }
}
