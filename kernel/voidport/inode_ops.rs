// SPDX-License-Identifier: GPL-2.0

use kernel::prelude::c_char;

use kernel::bindings;
use kernel::prelude::*;

use crate::helpers::voidport_jiffies;
use crate::namespace;
use crate::node::{iget, inode_mount, refresh_if_stale, session_and_id, session_of};
use crate::ops::Entry;
use crate::splice::stamp_retained;
use crate::vfs::{dentry_bytes, dentry_set_time};
use crate::vtable::Table;
use crate::wire::Caller;
use crate::xattr;

pub(crate) static DIR_INODE_OPS: Table<bindings::inode_operations> =
    Table::new(bindings::inode_operations {
        lookup: Some(lookup),
        create: Some(crate::compat::create::<namespace::Create>),
        atomic_open: Some(namespace::atomic_open),
        mkdir: Some(namespace::mkdir),
        mknod: Some(namespace::mknod),
        symlink: Some(namespace::symlink),
        link: Some(namespace::link),
        unlink: Some(namespace::unlink),
        rmdir: Some(namespace::rmdir),
        rename: Some(namespace::rename),
        getattr: Some(getattr),
        setattr: Some(crate::setattr::setattr),
        permission: Some(permission),
        listxattr: Some(xattr::listxattr),
        get_inode_acl: Some(xattr::no_inode_acl),
        get_acl: Some(xattr::get_acl),
        set_acl: Some(xattr::set_acl),
        ..pin_init::zeroed()
    });

pub(crate) static FILE_INODE_OPS: Table<bindings::inode_operations> =
    Table::new(bindings::inode_operations {
        getattr: Some(getattr),
        setattr: Some(crate::setattr::setattr),
        permission: Some(permission),
        listxattr: Some(xattr::listxattr),
        get_inode_acl: Some(xattr::no_inode_acl),
        get_acl: Some(xattr::get_acl),
        set_acl: Some(xattr::set_acl),
        ..pin_init::zeroed()
    });

pub(crate) static SYMLINK_INODE_OPS: Table<bindings::inode_operations> =
    Table::new(bindings::inode_operations {
        get_link: Some(get_link),
        getattr: Some(getattr),
        setattr: Some(crate::setattr::setattr),
        listxattr: Some(xattr::listxattr),
        get_inode_acl: Some(xattr::no_inode_acl),
        ..pin_init::zeroed()
    });

pub(crate) static SPECIAL_INODE_OPS: Table<bindings::inode_operations> =
    Table::new(bindings::inode_operations {
        getattr: Some(getattr),
        setattr: Some(crate::setattr::setattr),
        permission: Some(permission),
        listxattr: Some(xattr::listxattr),
        get_inode_acl: Some(xattr::no_inode_acl),
        get_acl: Some(xattr::get_acl),
        set_acl: Some(xattr::set_acl),
        ..pin_init::zeroed()
    });

pub(crate) unsafe extern "C" fn lookup(
    dir: *mut bindings::inode,
    dentry: *mut bindings::dentry,
    _flags: c_uint,
) -> *mut bindings::dentry {
    // SAFETY: the VFS passes a live directory inode and a dentry to fill.
    let result = unsafe { resolve(dir, dentry) };
    match result {
        Ok(inode) => {
            // SAFETY: `inode` is a referenced inode for the resolved name (or
            // null for a negative result); `d_splice_alias` consumes the
            // reference and attaches the dentry.
            let spliced = unsafe { bindings::d_splice_alias(inode, dentry) };
            let outcome = kernel::error::from_err_ptr(spliced);
            // SAFETY: the returned value has d_splice_alias's reference and
            // error-pointer semantics. Stamping does not consume references.
            stamp_retained(dentry, outcome, |retained| unsafe {
                dentry_set_time(retained, voidport_jiffies());
            });
            spliced
        }
        Err(error) => Error::from_errno(error.to_errno()).to_ptr(),
    }
}

/// The inode a name resolves to, or null for a name that does not exist.
///
/// # Safety
///
/// `dir` is a live directory inode; `dentry` is the dentry being resolved.
unsafe fn resolve(
    dir: *mut bindings::inode,
    dentry: *mut bindings::dentry,
) -> Result<*mut bindings::inode> {
    // SAFETY: `dir` is a live inode of a live voidport superblock.
    let (session, parent) = unsafe { session_and_id(dir) };
    let caller = Caller::current();
    // SAFETY: as above.
    let sent_at = unsafe { inode_mount(dir) }.writes();
    // SAFETY: `dentry` is live, and its name is stable while it is resolved.
    match session.lookup(caller, parent, unsafe { dentry_bytes(dentry) }) {
        // SAFETY: `dir` is a live inode of a live voidport superblock.
        Ok(entry) => unsafe { inode_of(dir, &entry, sent_at, caller) },
        // A name that does not exist is a negative dentry, not an error.
        Err(error) if error == ENOENT => Ok(core::ptr::null_mut()),
        Err(error) => Err(error),
    }
}

/// The referenced inode of an entry a reply to a request sent at the write
/// count `sent_at` admitted in the directory `dir`, with the lookup counted.
///
/// # Safety
///
/// `dir` is a live inode of a live voidport superblock.
pub(crate) unsafe fn inode_of(
    dir: *mut bindings::inode,
    entry: &Entry,
    sent_at: u64,
    caller: Caller,
) -> Result<*mut bindings::inode> {
    let node_id = entry.node_id.get();
    // SAFETY: `dir->i_sb` is the live superblock the inode belongs to.
    unsafe { iget((*dir).i_sb, node_id, entry.generation, &entry.attr, sent_at) }.inspect_err(
        |_| {
            // The reply counted a lookup on the server that no inode of the
            // guest records, so it is given straight back.
            // SAFETY: as above.
            unsafe { session_of((*dir).i_sb) }.forget(caller, node_id, 1);
        },
    )
}

/// The lock-free walk cannot ask the server, so a stale inode there is
/// answered `ECHILD` and the walk comes back in a context that can sleep.
unsafe extern "C" fn permission(
    idmap: *mut bindings::mnt_idmap,
    inode: *mut bindings::inode,
    mask: c_int,
) -> c_int {
    let may_not_block = mask & bindings::MAY_NOT_BLOCK as c_int != 0;
    // SAFETY: the VFS passes a live, initialised inode of this filesystem.
    let stale = unsafe { crate::node::attr_stale(inode) };
    if stale {
        if may_not_block {
            return ECHILD.to_errno();
        }
        // SAFETY: as above, and this context may sleep.
        if let Err(error) = unsafe { crate::node::refresh(inode, Caller::current()) } {
            return error.to_errno();
        }
    }
    // SAFETY: the kernel's own check over the fields the refresh kept current.
    unsafe { bindings::generic_permission(idmap, inode, mask) }
}

unsafe extern "C" fn get_link(
    dentry: *mut bindings::dentry,
    inode: *mut bindings::inode,
    callback: *mut bindings::delayed_call,
) -> *const c_char {
    // A path walk in its lock-free phase cannot sleep to fetch the target.
    if dentry.is_null() {
        return Error::from_errno(ECHILD.to_errno()).to_ptr();
    }
    // SAFETY: `inode` is a live symlink inode of a live voidport superblock.
    let (session, node_id) = unsafe { session_and_id(inode) };
    match session.readlink(Caller::current(), node_id) {
        Ok(target) => match link_buffer(target) {
            Ok(buffer) => {
                let ptr = buffer.link();
                // SAFETY: `callback` is the delayed call the walk will run to
                // free the link; `kfree_link` frees the boxed buffer, whose
                // raw pointer we hand it.
                unsafe {
                    (*callback).fn_ = Some(free_link);
                    (*callback).arg = KBox::into_raw(buffer).cast::<c_void>();
                }
                ptr.cast::<c_char>()
            }
            Err(error) => Error::from_errno(error.to_errno()).to_ptr(),
        },
        Err(error) => Error::from_errno(error.to_errno()).to_ptr(),
    }
}

struct Link(KVec<u8>);

impl Link {
    fn link(&self) -> *const u8 {
        self.0.as_ptr()
    }
}

/// Boxes `target` with a trailing NUL, as `get_link` must return.
fn link_buffer(target: KVec<u8>) -> Result<KBox<Link>> {
    let _scope = crate::helpers::NoFsScope::enter();
    let mut target = target;
    target.push(0, GFP_KERNEL)?;
    Ok(KBox::new(Link(target), GFP_KERNEL)?)
}

unsafe extern "C" fn free_link(arg: *mut c_void) {
    // SAFETY: `arg` is the `Link` box `get_link` handed the delayed call.
    drop(unsafe { KBox::from_raw(arg.cast::<Link>()) });
}

/// Attributes past their lifetime come from the server, where a changed size
/// or mtime drops the cached data.
unsafe extern "C" fn getattr(
    idmap: *mut bindings::mnt_idmap,
    path: *const bindings::path,
    stat: *mut bindings::kstat,
    request_mask: u32,
    flags: c_uint,
) -> c_int {
    // SAFETY: the VFS passes a live path whose dentry names a live inode.
    let inode = unsafe { (*(*path).dentry).d_inode };
    // SAFETY: `inode` is a live, initialised inode of this filesystem.
    let result = unsafe {
        if flags & bindings::AT_STATX_DONT_SYNC != 0 {
            Ok(())
        } else if flags & bindings::AT_STATX_FORCE_SYNC != 0 {
            crate::node::refresh(inode, Caller::current())
        } else {
            refresh_if_stale(inode, Caller::current())
        }
    };
    if let Err(error) = result {
        return error.to_errno();
    }
    // SAFETY: `inode` is live and its attributes are current; fill the stat.
    unsafe { bindings::generic_fillattr(idmap, request_mask, inode, stat) };
    0
}
