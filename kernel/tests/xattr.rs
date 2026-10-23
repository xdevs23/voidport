// SPDX-License-Identifier: GPL-2.0

use std::ffi::{CStr, CString};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

const CHECKSUM_NAME: &CStr = c"user.checksum.sha256";
const CHECKSUM: &[u8; 64] = b"9f2c4e7a1b6d3f8e0a5c2b7d4e9f1a6c3b8d5e2f7a4c1b9e6d3f0a8c5b2e7d4f";
const ACCESS_ACL: &CStr = c"system.posix_acl_access";
const DEFAULT_ACL: &CStr = c"system.posix_acl_default";

/// One entry of an ACL attribute value, in the layout of
/// `struct posix_acl_xattr_entry` in the kernel.
struct AclEntry {
    tag: u16,
    permissions: u16,
    id: u32,
}

impl AclEntry {
    const USER_OBJ: u16 = 0x01;
    const USER: u16 = 0x02;
    const GROUP_OBJ: u16 = 0x04;
    const MASK: u16 = 0x10;
    const OTHER: u16 = 0x20;
    const UNDEFINED_ID: u32 = u32::MAX;

    fn user(id: u32, permissions: u16) -> Self {
        Self {
            tag: Self::USER,
            permissions,
            id,
        }
    }

    fn unnamed(tag: u16, permissions: u16) -> Self {
        Self {
            tag,
            permissions,
            id: Self::UNDEFINED_ID,
        }
    }
}

/// An access ACL that gives user 1000 read and write, as `setfacl -m u:1000:rw`
/// writes one: the version of the attribute format, then the entries in the
/// order the kernel requires.
fn acl_value() -> Vec<u8> {
    const VERSION: u32 = 2;
    let entries = [
        AclEntry::unnamed(AclEntry::USER_OBJ, 6),
        AclEntry::user(1000, 6),
        AclEntry::unnamed(AclEntry::GROUP_OBJ, 4),
        AclEntry::unnamed(AclEntry::MASK, 6),
        AclEntry::unnamed(AclEntry::OTHER, 4),
    ];
    let mut value = VERSION.to_le_bytes().to_vec();
    for entry in entries {
        value.extend(entry.tag.to_le_bytes());
        value.extend(entry.permissions.to_le_bytes());
        value.extend(entry.id.to_le_bytes());
    }
    value
}

fn checked(result: isize) -> io::Result<usize> {
    usize::try_from(result).map_err(|_| io::Error::last_os_error())
}

fn errno(result: io::Result<usize>) -> Option<i32> {
    result.err().and_then(|error| error.raw_os_error())
}

fn set(path: &CStr, name: &CStr, value: &[u8], flags: i32) -> io::Result<usize> {
    // SAFETY: both strings are NUL-terminated, and the value is readable for
    // its length.
    let result = unsafe {
        libc::setxattr(
            path.as_ptr(),
            name.as_ptr(),
            value.as_ptr().cast(),
            value.len(),
            flags,
        )
    };
    checked(result as isize)
}

fn get(path: &CStr, name: &CStr, buffer: &mut [u8]) -> io::Result<usize> {
    // SAFETY: both strings are NUL-terminated, and the buffer is writable for
    // its length.
    checked(unsafe {
        libc::getxattr(
            path.as_ptr(),
            name.as_ptr(),
            buffer.as_mut_ptr().cast(),
            buffer.len(),
        )
    })
}

fn list(path: &CStr, buffer: &mut [u8]) -> io::Result<usize> {
    // SAFETY: the path is NUL-terminated, and the buffer is writable for its
    // length.
    checked(unsafe { libc::listxattr(path.as_ptr(), buffer.as_mut_ptr().cast(), buffer.len()) })
}

fn remove(path: &CStr, name: &CStr) -> io::Result<usize> {
    // SAFETY: both strings are NUL-terminated.
    checked(unsafe { libc::removexattr(path.as_ptr(), name.as_ptr()) } as isize)
}

pub(crate) fn run(file: &Path, directory: &Path) -> io::Result<()> {
    let path = CString::new(file.as_os_str().as_bytes())?;
    let directory = CString::new(directory.as_os_str().as_bytes())?;

    set(&path, CHECKSUM_NAME, CHECKSUM, libc::XATTR_CREATE)?;
    assert_eq!(get(&path, CHECKSUM_NAME, &mut [])?, CHECKSUM.len());
    let mut value = [0; 64];
    assert_eq!(get(&path, CHECKSUM_NAME, &mut value)?, CHECKSUM.len());
    assert_eq!(&value, CHECKSUM);
    assert_eq!(
        errno(get(&path, CHECKSUM_NAME, &mut value[..CHECKSUM.len() - 1])),
        Some(libc::ERANGE)
    );
    assert_eq!(
        errno(set(&path, CHECKSUM_NAME, CHECKSUM, libc::XATTR_CREATE)),
        Some(libc::EEXIST)
    );
    let mut names = vec![0; list(&path, &mut [])?];
    let listed = list(&path, &mut names)?;
    assert!(names[..listed]
        .split(|byte| *byte == 0)
        .any(|name| name == CHECKSUM_NAME.to_bytes()));
    remove(&path, CHECKSUM_NAME)?;
    assert_eq!(
        errno(get(&path, CHECKSUM_NAME, &mut value)),
        Some(libc::ENODATA)
    );
    println!("xattr helper: a user attribute was set, read, listed and removed");

    assert_eq!(
        errno(get(&path, ACCESS_ACL, &mut value)),
        Some(libc::ENODATA)
    );
    let mode = std::fs::metadata(file)?.mode();
    assert_eq!(
        errno(set(&path, ACCESS_ACL, &acl_value(), 0)),
        Some(libc::EPERM)
    );
    assert_eq!(std::fs::metadata(file)?.mode(), mode);
    assert_eq!(errno(remove(&directory, DEFAULT_ACL)), Some(libc::ENODATA));
    println!("xattr helper: the ACL write returned EPERM and the absent default ACL ENODATA");
    Ok(())
}
