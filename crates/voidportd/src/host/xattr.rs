//! Extended attributes.
//!
//! **This layer has no policy of its own.** It reads, writes and lists whatever
//! it is asked to and passes the host kernel's own answer back; which names a
//! guest may touch is the namespace's business
//! ([`crate::rules::xattr`]), and the operation layer
//! ([`crate::data::ops`]) is where the two meet.
//!
//! It used to be otherwise: this module refused every namespace but `user.*`
//! with `EOPNOTSUPP` and filtered the rest out of a listing. That blanket
//! refusal is retired — the mount is supposed to behave like a local
//! filesystem, where a guest can read a `security.*` label and gets the
//! kernel's own refusal writing it back unprivileged, exactly as on ext4.
//!
//! The syscalls take a path, not a descriptor, because a node is pinned
//! with `O_PATH`, which the `f*xattr` calls reject. The path is the node's own
//! `/proc/self/fd` entry — the same reopen idiom, and the same exemption from
//! the magic-link discipline, that [`super::open::reopen`] documents.

use std::os::fd::BorrowedFd;

use rustix::io::Errno;

use super::open::proc_path;

/// Reads an attribute value.
///
/// Returns the full value, whatever the caller's budget: the caller decides
/// between answering a size probe, truncating, or `ERANGE`, because those rules
/// belong to the wire contract, not to the host.
///
/// # Errors
///
/// Returns the host errno, `ENODATA` for a missing attribute included.
pub fn get(fd: BorrowedFd<'_>, name: &[u8]) -> Result<Vec<u8>, Errno> {
    let path = proc_path(fd);
    read_sized(|buffer| rustix::fs::getxattr(path.as_str(), name, buffer))
}

/// Sets an attribute value.
///
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

/// Removes an attribute.
///
/// # Errors
///
/// Returns the host errno.
pub fn remove(fd: BorrowedFd<'_>, name: &[u8]) -> Result<(), Errno> {
    rustix::fs::removexattr(proc_path(fd).as_str(), name)
}

/// Lists an entry's attribute names.
///
/// The kernel answers with a NUL-separated blob; the names come back split and
/// otherwise untouched. Hiding the names a namespace denies reads to is the
/// operation layer's job, because only it knows the namespace.
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

/// Runs one of the kernel's size-probe reads: ask for the length, allocate,
/// read, and start over if the value grew in between.
///
/// Both `getxattr` and `listxattr` take a buffer and answer the full size, so
/// the retry loop is the same for either.
fn read_sized(mut read: impl FnMut(&mut [u8]) -> Result<usize, Errno>) -> Result<Vec<u8>, Errno> {
    let mut size = read(&mut [])?;
    loop {
        let mut buffer = vec![0u8; size];
        match read(&mut buffer) {
            Ok(read_len) => {
                buffer.truncate(read_len);
                return Ok(buffer);
            }
            // The value grew between the probe and the read; ask again.
            Err(Errno::RANGE) => size = read(&mut [])?,
            Err(error) => return Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::Scratch;
    use std::os::fd::AsFd;

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
        assert_eq!(list(fd).expect("listable"), vec![b"user.second".to_vec()]);
    }
}
