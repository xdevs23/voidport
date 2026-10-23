//! The syscalls take a path, not a descriptor, because the descriptor of a node
//! is `O_PATH`, which the `f*xattr` calls reject. The path is the
//! `/proc/self/fd` entry of the node, as in [`super::open::reopen`].
//!
//! This layer has no policy: which names a guest may touch is decided in
//! [`crate::rules::xattr`].

use std::os::fd::BorrowedFd;

use rustix::io::Errno;

use super::open::proc_path;

/// Returns the full value, whatever the budget of the caller: the wire contract
/// decides between a size probe, truncating and `ERANGE`.
///
/// # Errors
///
/// Returns the host errno, `ENODATA` for a missing attribute included.
pub fn get(fd: BorrowedFd<'_>, name: &[u8]) -> Result<Vec<u8>, Errno> {
    let path = proc_path(fd);
    read_sized(|buffer| rustix::fs::getxattr(path.as_str(), name, buffer))
}

/// # Errors
///
/// Returns the host errno, including `ENODATA` for an absent attribute. A
/// present empty value returns zero, not `ENODATA`.
pub fn size(fd: BorrowedFd<'_>, name: &[u8]) -> Result<usize, Errno> {
    rustix::fs::getxattr(proc_path(fd).as_str(), name, &mut [0u8; 0][..])
}

/// # Errors
///
/// Returns the host errno, including `EEXIST`/`ENODATA` for the create and
/// replace flags.
pub fn set(
    fd: BorrowedFd<'_>,
    name: &[u8],
    value: &[u8],
    flags: rustix::fs::XattrFlags,
) -> Result<(), Errno> {
    rustix::fs::setxattr(proc_path(fd).as_str(), name, value, flags)
}

/// # Errors
///
/// Returns the host errno.
pub fn remove(fd: BorrowedFd<'_>, name: &[u8]) -> Result<(), Errno> {
    rustix::fs::removexattr(proc_path(fd).as_str(), name)
}

/// # Errors
///
/// Returns the host errno: `ERANGE` for a value longer than `into`, and
/// `ENODATA` for a missing attribute.
pub fn get_into(fd: BorrowedFd<'_>, name: &[u8], into: &mut [u8]) -> Result<usize, Errno> {
    rustix::fs::getxattr(proc_path(fd).as_str(), name, into)
}

/// # Errors
///
/// Returns the host errno: `ERANGE` for a list longer than `into`.
pub fn list_into(fd: BorrowedFd<'_>, into: &mut [u8]) -> Result<usize, Errno> {
    rustix::fs::listxattr(proc_path(fd).as_str(), into)
}

/// Hiding the names that a namespace denies reads to is the job of the
/// operation layer, which knows the namespace.
///
/// # Errors
///
/// Returns the host errno.
pub fn list(fd: BorrowedFd<'_>) -> Result<Vec<Vec<u8>>, Errno> {
    let path = proc_path(fd);
    let blob = read_sized(|buffer| rustix::fs::listxattr(path.as_str(), buffer))?;
    Ok(blob
        .split(|byte| *byte == 0)
        .filter(|name| !name.is_empty())
        .map(<[u8]>::to_vec)
        .collect())
}

/// Both `getxattr` and `listxattr` return the full size when given an empty
/// buffer. Starts over if the value grew in between.
fn read_sized(mut read: impl FnMut(&mut [u8]) -> Result<usize, Errno>) -> Result<Vec<u8>, Errno> {
    let mut size = read(&mut [])?;
    loop {
        let mut buffer = vec![0u8; size];
        match read(&mut buffer) {
            Ok(read_len) => {
                buffer.truncate(read_len);
                return Ok(buffer);
            }
            Err(Errno::RANGE) => size = read(&mut [])?,
            Err(error) => return Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;
    use voidport_test_host::Scratch;

    #[test]
    fn values_round_trip_through_a_pinned_descriptor() {
        let scratch = Scratch::new("xattr");
        let file = scratch.file("file", b"x");
        let pinned = rustix::fs::openat(
            rustix::fs::CWD,
            &file,
            rustix::fs::OFlags::PATH,
            rustix::fs::Mode::empty(),
        )
        .expect("the file pins");
        let fd = pinned.as_fd();

        // Some filesystems (tmpfs before 6.6, for instance) refuse user
        // xattrs; the round trip is only meaningful where they are supported.
        let Ok(()) = set(fd, b"user.first", b"one", rustix::fs::XattrFlags::empty()) else {
            return;
        };
        set(fd, b"user.second", b"two", rustix::fs::XattrFlags::empty()).expect("settable");
        assert_eq!(get(fd, b"user.first").expect("readable"), b"one");

        let mut names = list(fd).expect("listable");
        names.sort();
        assert_eq!(names, vec![b"user.first".to_vec(), b"user.second".to_vec()]);

        remove(fd, b"user.first").expect("removable");
        assert_eq!(get(fd, b"user.first").expect_err("gone"), Errno::NODATA);
        assert_eq!(size(fd, b"user.first"), Err(Errno::NODATA));
        assert_eq!(size(fd, b"user.second"), Ok(3));
        set(fd, b"user.second", b"", rustix::fs::XattrFlags::empty()).expect("empty value");
        assert_eq!(size(fd, b"user.second"), Ok(0));
        assert_eq!(list(fd).expect("listable"), vec![b"user.second".to_vec()]);
    }
}
