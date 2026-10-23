// SPDX-License-Identifier: GPL-2.0

use core::ffi::CStr;

use kernel::bindings;
use kernel::error::{from_err_ptr, to_result};
use kernel::prelude::*;
use voidport_session::metadata;

use crate::cleanup::Closing;
use crate::handle::{attach, detach, Handle};
use crate::helpers::{voidport_d_in_lookup, voidport_jiffies, NoFsScope};
use crate::inode_kind::SupportedKind;
use crate::inode_ops::{inode_of, lookup};
use crate::node::{expire, id_of, inode_mount, kind_of, session_and_id};
use crate::ops::namespace::rename_flags;
use crate::ops::Entry;
use crate::session::Session;
use crate::splice::stamp_retained;
use crate::vfs::{dentry_bytes, dentry_set_time, file_opened, set_created, status};
use crate::wire::Caller;

/// A directory whose entries the current task changes, under the reclaim
/// scope of the change.
struct Directory {
    _scope: NoFsScope,
    inode: *mut bindings::inode,
    session: &'static Session,
    node_id: u64,
    caller: Caller,
    /// The write count of the mount before the request is sent, which places
    /// the attributes its reply carries.
    sent_at: u64,
}

impl Directory {
    /// # Safety
    ///
    /// `inode` is a live directory inode of a live voidport superblock.
    unsafe fn new(inode: *mut bindings::inode) -> Self {
        // SAFETY: the caller promises a live voidport inode.
        let (session, node_id) = unsafe { session_and_id(inode) };
        Self {
            _scope: NoFsScope::enter(),
            inode,
            session,
            node_id,
            caller: Caller::current(),
            // SAFETY: as above.
            sent_at: unsafe { inode_mount(inode) }.writes(),
        }
    }

    /// Attaches the inode of `entry`, which a reply created as the name of
    /// `dentry` in this directory, and returns the dentry it is attached to in
    /// place of `dentry`, which only a directory inode can have. A reply that
    /// created another kind than `kind`, the kind of the request, is an error.
    ///
    /// # Safety
    ///
    /// `dentry` is a negative dentry of this directory whose name is stable.
    unsafe fn instantiate(
        &self,
        dentry: *mut bindings::dentry,
        entry: &Entry,
        kind: SupportedKind,
    ) -> Result<*mut bindings::dentry> {
        // SAFETY: the directory is live.
        unsafe { expire(self.inode) };
        if SupportedKind::of_mode(entry.attr.mode.get()) != Some(kind) {
            self.session.forget(self.caller, entry.node_id.get(), 1);
            return Err(EIO);
        }
        // SAFETY: the directory is live, and the dentry is negative until the
        // splice, which moves the reference of the inode to the dentry.
        unsafe {
            let inode = inode_of(self.inode, entry, self.sent_at, self.caller)?;
            bindings::d_drop(dentry);
            let spliced = from_err_ptr(bindings::d_splice_alias(inode, dentry));
            stamp_retained(dentry, spliced, |retained| {
                dentry_set_time(retained, voidport_jiffies())
            });
            spliced
        }
    }

    /// As [`Self::instantiate`], for a caller that goes on using `dentry`.
    ///
    /// # Safety
    ///
    /// As [`Self::instantiate`].
    unsafe fn instantiate_name(
        &self,
        dentry: *mut bindings::dentry,
        entry: &Entry,
        kind: SupportedKind,
    ) -> Result {
        // SAFETY: the promises of the caller hold.
        let alias = unsafe { self.instantiate(dentry, entry, kind) }?;
        if !alias.is_null() {
            // SAFETY: the splice returned the alias with a reference.
            unsafe { bindings::dput(alias) };
        }
        Ok(())
    }
}

/// Opens `dentry` in `dir` for `open(2)`. When the open creates and the name
/// is absent, one Create request creates the file and opens it.
pub(crate) unsafe extern "C" fn atomic_open(
    dir: *mut bindings::inode,
    dentry: *mut bindings::dentry,
    file: *mut bindings::file,
    flags: c_uint,
    mode: bindings::umode_t,
) -> c_int {
    let mut alias = core::ptr::null_mut();
    // A name the walk has not resolved yet is resolved first, since only an
    // absent name is created.
    // SAFETY: the VFS passes a live dentry.
    if unsafe { voidport_d_in_lookup(dentry) } {
        // SAFETY: the VFS passes a live directory and a dentry in lookup.
        alias = unsafe { lookup(dir, dentry, 0) };
        if let Err(error) = from_err_ptr(alias) {
            return error.to_errno();
        }
    }
    // An alias is the dentry of an existing directory.
    // SAFETY: the dentry is live.
    if flags & bindings::O_CREAT == 0 || !alias.is_null() || unsafe { !(*dentry).d_inode.is_null() }
    {
        // SAFETY: the reference of the alias, if any, passes to the open.
        return unsafe { bindings::finish_no_open(file, alias) };
    }
    // SAFETY: the VFS passes a live directory, a negative dentry of it whose
    // name cannot change while the directory is locked, and the file it
    // opens.
    status(unsafe { create_open(dir, dentry, file, flags, mode) })
}

///
/// # Safety
///
/// As [`atomic_open`], with `dentry` negative.
unsafe fn create_open(
    dir: *mut bindings::inode,
    dentry: *mut bindings::dentry,
    file: *mut bindings::file,
    flags: c_uint,
    mode: bindings::umode_t,
) -> Result {
    // SAFETY: the promises of the caller hold.
    let dir = unsafe { Directory::new(dir) };
    // SAFETY: as above.
    let name = unsafe { dentry_bytes(dentry) };
    let created = dir
        .session
        .create(dir.caller, dir.node_id, name, flags, mode.into())?;
    // The handle goes back when it drops, also when no file uses it.
    // SAFETY: the open owns the file being opened.
    let handle = unsafe { Handle::of_file(inode_mount(dir.inode), file, created.handle, flags) };
    // SAFETY: as above.
    unsafe { dir.instantiate_name(dentry, &created.entry, SupportedKind::Regular) }?;
    // SAFETY: the open owns the file until it returns, and the dentry is
    // positive now, with the inode the file opens. The release of a file that
    // did not open never runs, so the handle goes back here.
    unsafe {
        let inode = (*dentry).d_inode;
        attach(inode, file, handle)?;
        set_created(file);
        let result = to_result(bindings::finish_open(file, dentry, Some(opened)));
        if result.is_err() && !file_opened(file) {
            detach(inode, file);
        }
        result
    }
}

unsafe extern "C" fn opened(_inode: *mut bindings::inode, file: *mut bindings::file) -> c_int {
    // SAFETY: the VFS passes the file being opened, before it checks
    // `O_DIRECT` against the mode of the file.
    unsafe { crate::vfs::allow_direct(file) };
    0
}

/// Creates a regular file for `mknod(2)`. The Create request opens it, and
/// the handle goes back at once.
pub(crate) struct Create;

impl crate::compat::Create for Create {
    unsafe fn create(
        _idmap: *mut bindings::mnt_idmap,
        dir: *mut bindings::inode,
        dentry: *mut bindings::dentry,
        mode: bindings::umode_t,
    ) -> c_int {
        let flags = bindings::O_CREAT | bindings::O_EXCL;
        // SAFETY: the VFS passes a live directory and a negative dentry of it,
        // whose name cannot change while the directory is locked.
        let (dir, name) = unsafe { (Directory::new(dir), dentry_bytes(dentry)) };
        let created = dir
            .session
            .create(dir.caller, dir.node_id, name, flags, mode.into())
            .inspect(|created| {
                dir.session.release(
                    dir.caller,
                    created.handle,
                    Closing {
                        flags,
                        lock_owner: None,
                    },
                )
            });
        // SAFETY: as above.
        status(created.and_then(|created| unsafe {
            dir.instantiate_name(dentry, &created.entry, SupportedKind::Regular)
        }))
    }
}

pub(crate) unsafe extern "C" fn mkdir(
    _idmap: *mut bindings::mnt_idmap,
    dir: *mut bindings::inode,
    dentry: *mut bindings::dentry,
    mode: bindings::umode_t,
) -> *mut bindings::dentry {
    // SAFETY: the VFS passes a live directory and a negative dentry of it,
    // whose name cannot change while the directory is locked.
    let (dir, name) = unsafe { (Directory::new(dir), dentry_bytes(dentry)) };
    dir.session
        .mkdir(dir.caller, dir.node_id, name, mode.into())
        // SAFETY: as above.
        .and_then(|entry| unsafe { dir.instantiate(dentry, &entry, SupportedKind::Directory) })
        .unwrap_or_else(|error| error.to_ptr())
}

/// Creates a FIFO or a socket. A device node is rejected before any request.
pub(crate) unsafe extern "C" fn mknod(
    _idmap: *mut bindings::mnt_idmap,
    dir: *mut bindings::inode,
    dentry: *mut bindings::dentry,
    mode: bindings::umode_t,
    _device: bindings::dev_t,
) -> c_int {
    let mode = u32::from(mode);
    let Some(kind) = metadata::mknod_kind(mode).and_then(SupportedKind::of_entry_type) else {
        return EPERM.to_errno();
    };
    // SAFETY: the VFS passes a live directory and a negative dentry of it,
    // whose name cannot change while the directory is locked.
    let (dir, name) = unsafe { (Directory::new(dir), dentry_bytes(dentry)) };
    status(
        dir.session
            .mknod(dir.caller, dir.node_id, name, mode)
            // SAFETY: as above.
            .and_then(|entry| unsafe { dir.instantiate_name(dentry, &entry, kind) }),
    )
}

pub(crate) unsafe extern "C" fn symlink(
    _idmap: *mut bindings::mnt_idmap,
    dir: *mut bindings::inode,
    dentry: *mut bindings::dentry,
    target: *const c_char,
) -> c_int {
    // SAFETY: the VFS passes a live directory, a negative dentry of it whose
    // name cannot change while the directory is locked, and a NUL-terminated
    // target.
    let (dir, name, target) = unsafe {
        (
            Directory::new(dir),
            dentry_bytes(dentry),
            CStr::from_ptr(target.cast()).to_bytes(),
        )
    };
    status(
        dir.session
            .symlink(dir.caller, dir.node_id, name, target)
            // SAFETY: as above.
            .and_then(|entry| unsafe {
                dir.instantiate_name(dentry, &entry, SupportedKind::Symlink)
            }),
    )
}

pub(crate) unsafe extern "C" fn link(
    old: *mut bindings::dentry,
    dir: *mut bindings::inode,
    new: *mut bindings::dentry,
) -> c_int {
    // SAFETY: the VFS passes a positive dentry, a live directory and a
    // negative dentry of it, whose name cannot change while the directory is
    // locked.
    let (dir, name, inode) = unsafe { (Directory::new(dir), dentry_bytes(new), (*old).d_inode) };
    // SAFETY: the inode of a positive dentry is live.
    let (target, kind) = unsafe { (id_of(inode), kind_of(inode)) };
    status(
        dir.session
            .link(dir.caller, dir.node_id, target, name)
            // SAFETY: as above. The reply shows the new count of names when it
            // describes the same node, and the server shows it otherwise.
            .and_then(|entry| unsafe {
                expire(inode);
                dir.instantiate_name(new, &entry, kind)
            }),
    )
}

pub(crate) unsafe extern "C" fn unlink(
    dir: *mut bindings::inode,
    dentry: *mut bindings::dentry,
) -> c_int {
    // SAFETY: the VFS passes a live directory and a positive dentry of it,
    // whose name cannot change while the directory is locked.
    unsafe { remove(dir, dentry, Session::unlink) }
}

pub(crate) unsafe extern "C" fn rmdir(
    dir: *mut bindings::inode,
    dentry: *mut bindings::dentry,
) -> c_int {
    // SAFETY: as in unlink.
    unsafe { remove(dir, dentry, Session::rmdir) }
}

/// # Safety
///
/// `dir` is a live directory inode of a live voidport superblock, and
/// `dentry` a positive dentry of it whose name is stable.
unsafe fn remove(
    dir: *mut bindings::inode,
    dentry: *mut bindings::dentry,
    request: fn(&Session, Caller, u64, &[u8]) -> Result,
) -> c_int {
    // SAFETY: the promises of the caller hold.
    let (dir, name) = unsafe { (Directory::new(dir), dentry_bytes(dentry)) };
    // SAFETY: as above.
    status(
        request(dir.session, dir.caller, dir.node_id, name).map(|()| unsafe {
            expire(dir.inode);
            unlinked((*dentry).d_inode);
        }),
    )
}

pub(crate) unsafe extern "C" fn rename(
    _idmap: *mut bindings::mnt_idmap,
    old_dir: *mut bindings::inode,
    old: *mut bindings::dentry,
    new_dir: *mut bindings::inode,
    new: *mut bindings::dentry,
    flags: c_uint,
) -> c_int {
    // SAFETY: the VFS passes two live directories and a dentry of each, whose
    // names cannot change while the rename lock is held.
    let (dir, name, new_parent, new_name) = unsafe {
        (
            Directory::new(old_dir),
            dentry_bytes(old),
            id_of(new_dir),
            dentry_bytes(new),
        )
    };
    let renamed = rename_flags(flags).and_then(|wire| {
        dir.session
            .rename(dir.caller, dir.node_id, name, new_parent, new_name, wire)
    });
    // SAFETY: as above. The dentry `old` is positive, and so is `new` when it
    // has an inode, which an exchange swaps and any other rename replaces.
    status(renamed.map(|()| unsafe {
        expire(old_dir);
        expire(new_dir);
        expire((*old).d_inode);
        let replaced = (*new).d_inode;
        if replaced.is_null() {
            return;
        }
        if flags & bindings::RENAME_EXCHANGE != 0 {
            expire(replaced);
        } else {
            unlinked(replaced);
        }
    }))
}

/// Counts one name fewer for an inode whose name a reply removed, and ends
/// the lifetime of its attributes. A directory has no name left.
///
/// # Safety
///
/// `inode` is a live, initialized voidport inode.
unsafe fn unlinked(inode: *mut bindings::inode) {
    // SAFETY: the caller promises a live inode. The count of names comes from
    // the server, and the kernel warns when it would drop below zero.
    unsafe {
        if kind_of(inode) == SupportedKind::Directory {
            bindings::clear_nlink(inode);
        } else if (*inode).__bindgen_anon_1.i_nlink > 0 {
            bindings::drop_nlink(inode);
        }
        expire(inode);
    }
}
