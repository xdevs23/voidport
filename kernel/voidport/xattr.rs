// SPDX-License-Identifier: GPL-2.0

use core::ptr::NonNull;

use kernel::bindings;
use kernel::prelude::*;

use crate::helpers::{voidport_posix_acl_to_xattr, voidport_posix_acl_xattr_name, NoFsScope};
use crate::node::{expire, session_and_id};
use crate::ops::xattr::Xattr;
use crate::vfs::{length, posix_acl_from_xattr, status, xattr_handler};
use crate::vtable::Table;
use crate::wire::{Caller, LIMITS};

/// The handler of every name: its prefix is empty, so the VFS hands it each
/// name whole.
static HANDLER: Table<xattr_handler> = Table::new(xattr_handler {
    prefix: c"".as_ptr().cast(),
    get: Some(get),
    set: Some(set),
    ..pin_init::zeroed()
});

pub(crate) static HANDLERS: Table<[*const xattr_handler; 2]> =
    Table::new([HANDLER.get(), core::ptr::null()]);

unsafe extern "C" fn get(
    _handler: *const xattr_handler,
    _dentry: *mut bindings::dentry,
    inode: *mut bindings::inode,
    name: *const c_char,
    buffer: *mut c_void,
    size: usize,
) -> c_int {
    // SAFETY: the VFS passes a live inode of this filesystem and a
    // NUL-terminated name.
    let ((session, node_id), name) = unsafe {
        (
            session_and_id(inode),
            core::ffi::CStr::from_ptr(name.cast()),
        )
    };
    u32::try_from(size)
        .map_err(|_| E2BIG)
        .and_then(|asked| session.getxattr(Caller::current(), node_id, name.to_bytes(), asked))
        // SAFETY: the VFS passes a buffer of `size` writable bytes.
        .and_then(|reply| unsafe { answer(reply, buffer.cast(), size) })
        .and_then(|len| c_int::try_from(len).map_err(|_| EOVERFLOW))
        .unwrap_or_else(|error| error.to_errno())
}

unsafe extern "C" fn set(
    _handler: *const xattr_handler,
    _idmap: *mut bindings::mnt_idmap,
    _dentry: *mut bindings::dentry,
    inode: *mut bindings::inode,
    name: *const c_char,
    value: *const c_void,
    size: usize,
    flags: c_int,
) -> c_int {
    // SAFETY: the VFS passes a NUL-terminated name, and a value of `size`
    // readable bytes unless it is null.
    let (name, value) = unsafe {
        (
            core::ffi::CStr::from_ptr(name.cast()).to_bytes(),
            (!value.is_null()).then(|| core::slice::from_raw_parts(value.cast::<u8>(), size)),
        )
    };
    // SAFETY: the VFS passes a live inode of this filesystem.
    unsafe { change(inode, name, value, flags) }
}

pub(crate) unsafe extern "C" fn listxattr(
    dentry: *mut bindings::dentry,
    list: *mut c_char,
    size: usize,
) -> isize {
    // SAFETY: the VFS passes a live dentry of a live inode of this
    // filesystem.
    let (session, node_id) = unsafe { session_and_id((*dentry).d_inode) };
    length(
        u32::try_from(size)
            .map_err(|_| E2BIG)
            .and_then(|asked| session.listxattr(Caller::current(), node_id, asked))
            // SAFETY: the VFS passes a list buffer of `size` writable bytes.
            .and_then(|reply| unsafe { answer(reply, list.cast(), size) })
            .and_then(|len| isize::try_from(len).map_err(|_| EOVERFLOW)),
    )
}

/// Returns no ACL to the permission checks of the VFS, so they use the mode
/// bits. No inode has an ACL cached, so the VFS calls this on every check,
/// the lock-free path walk included.
pub(crate) unsafe extern "C" fn no_inode_acl(
    _inode: *mut bindings::inode,
    _kind: c_int,
    _rcu: bool,
) -> *mut bindings::posix_acl {
    core::ptr::null_mut()
}

pub(crate) unsafe extern "C" fn get_acl(
    _idmap: *mut bindings::mnt_idmap,
    dentry: *mut bindings::dentry,
    kind: c_int,
) -> *mut bindings::posix_acl {
    // SAFETY: the VFS passes a live dentry of a live inode of this
    // filesystem.
    let (session, node_id) = unsafe { session_and_id((*dentry).d_inode) };
    let value = acl_name(kind)
        .and_then(|name| session.getxattr(Caller::current(), node_id, name, LIMITS.xattr_size_max));
    match value {
        // An absent attribute and an empty one both set no ACL.
        Ok(Xattr { bytes, .. }) if !bytes.is_empty() => posix_acl_from_xattr(&bytes),
        Ok(_) => core::ptr::null_mut(),
        Err(error) if error == crate::errno::enodata() => core::ptr::null_mut(),
        Err(error) => error.to_ptr(),
    }
}

pub(crate) unsafe extern "C" fn set_acl(
    _idmap: *mut bindings::mnt_idmap,
    dentry: *mut bindings::dentry,
    acl: *mut bindings::posix_acl,
    kind: c_int,
) -> c_int {
    let _scope = NoFsScope::enter();
    // SAFETY: the VFS passes a live dentry of a live inode of this
    // filesystem.
    let inode = unsafe { (*dentry).d_inode };
    let name = match acl_name(kind) {
        Ok(name) => name,
        Err(error) => return error.to_errno(),
    };
    if acl.is_null() {
        // SAFETY: as above.
        return unsafe { change(inode, name, None, 0) };
    }
    // SAFETY: the VFS passes a live ACL.
    match unsafe { AclValue::of(acl) } {
        // SAFETY: as above.
        Ok(value) => unsafe { change(inode, name, Some(value.bytes()), 0) },
        Err(error) => error.to_errno(),
    }
}

/// A change makes the attributes of the inode expire, since the server changed
/// its change time.
///
/// # Safety
///
/// `inode` must be a live, initialised voidport inode.
unsafe fn change(
    inode: *mut bindings::inode,
    name: &[u8],
    value: Option<&[u8]>,
    flags: c_int,
) -> c_int {
    // SAFETY: the caller promises a live, initialised inode.
    let (session, node_id) = unsafe { session_and_id(inode) };
    let caller = Caller::current();
    let changed = match value {
        Some(value) => session.setxattr(caller, node_id, name, value, flags),
        None => session.removexattr(caller, node_id, name),
    };
    // SAFETY: as above.
    status(changed.map(|()| unsafe { expire(inode) }))
}

/// Copies a reply into the buffer of the caller and returns how many bytes it
/// copied, or returns the full size when the caller asked for the size.
///
/// # Safety
///
/// `buffer` must have `size` writable bytes.
unsafe fn answer(reply: Xattr, buffer: *mut u8, size: usize) -> Result<usize> {
    if size == 0 {
        return Ok(reply.size as usize);
    }
    let len = reply.bytes.len();
    if len > size {
        return Err(ERANGE);
    }
    // SAFETY: the reply is an allocation apart from the buffer, and the
    // caller promises `size` writable bytes, which is at least `len`.
    unsafe { core::ptr::copy_nonoverlapping(reply.bytes.as_ptr(), buffer, len) };
    Ok(len)
}

fn acl_name(kind: c_int) -> Result<&'static [u8]> {
    // SAFETY: the kernel returns a static NUL-terminated string for every
    // type, the empty one for a type that has no attribute.
    let name = unsafe { core::ffi::CStr::from_ptr(voidport_posix_acl_xattr_name(kind).cast()) };
    match name.to_bytes() {
        [] => Err(EINVAL),
        name => Ok(name),
    }
}

struct AclValue {
    value: NonNull<u8>,
    len: usize,
}

impl AclValue {
    /// # Safety
    ///
    /// `acl` must be a live ACL.
    unsafe fn of(acl: *const bindings::posix_acl) -> Result<Self> {
        let mut len = 0;
        // SAFETY: the caller promises a live ACL, and `len` is writable.
        let value = unsafe { voidport_posix_acl_to_xattr(acl, &mut len) };
        NonNull::new(value.cast())
            .map(|value| Self { value, len })
            .ok_or(ENOMEM)
    }

    fn bytes(&self) -> &[u8] {
        // SAFETY: the encoding allocated `len` initialised bytes, which this
        // value owns until it is dropped.
        unsafe { core::slice::from_raw_parts(self.value.as_ptr(), self.len) }
    }
}

impl Drop for AclValue {
    fn drop(&mut self) {
        // SAFETY: the encoding allocated the value with kmalloc, and nothing
        // else frees it.
        unsafe { bindings::kfree(self.value.as_ptr().cast()) };
    }
}
