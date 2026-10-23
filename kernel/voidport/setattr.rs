// SPDX-License-Identifier: GPL-2.0

use kernel::bindings;
use kernel::error::to_result;
use kernel::prelude::*;
use voidport_proto::attr::Timespec;
use voidport_proto::ops::node::{setattr_valid, SetattrRequest};
use voidport_session::metadata;
use zerocopy::byteorder::little_endian::{U32, U64};

use crate::handle::handle_of;
use crate::helpers::{Hold, Locked, NoFsScope};
use crate::mount::Mount;
use crate::node::{apply_attr, inode_mount, resize, session_and_id, write_back_all};
use crate::vfs::status;
use crate::wire::Caller;

pub(crate) unsafe extern "C" fn setattr(
    idmap: *mut bindings::mnt_idmap,
    dentry: *mut bindings::dentry,
    attr: *mut bindings::iattr,
) -> c_int {
    // SAFETY: the VFS passes a live dentry of this filesystem and the change,
    // and holds the inode lock.
    status(unsafe { change(idmap, dentry, attr) })
}

/// # Safety
///
/// As [`setattr`]: `dentry` is a live dentry of a voidport inode, `attr` is
/// the change, and the caller holds the inode lock.
unsafe fn change(
    idmap: *mut bindings::mnt_idmap,
    dentry: *mut bindings::dentry,
    attr: *mut bindings::iattr,
) -> Result {
    let _scope = NoFsScope::enter();
    // SAFETY: the promises of the caller hold.
    to_result(unsafe { bindings::setattr_prepare(idmap, dentry, attr) })?;
    // SAFETY: as above. The inode of the dentry is a live inode of a live
    // superblock.
    let (inode, attr) = unsafe { ((*dentry).d_inode, &*attr) };
    // SAFETY: as above.
    let (session, node_id) = unsafe { session_and_id(inode) };
    let caller = Caller::current();
    let mut given = attr.ia_valid;
    if given & bindings::ATTR_OPEN != 0 {
        // The open truncated the file on the server and cut its page cache,
        // which ended the lifetime of its attributes: the server set the
        // times of the file with the truncation.
        given &= !(bindings::ATTR_OPEN
            | bindings::ATTR_SIZE
            | bindings::ATTR_FILE
            | bindings::ATTR_MTIME
            | bindings::ATTR_CTIME);
    }
    let valid = wire_valid(given);
    if valid == 0 {
        return Ok(());
    }
    let has = |flag: u32| given & flag != 0;
    let mut request = SetattrRequest {
        valid: U32::new(valid),
        ..SetattrRequest::default()
    };
    if has(bindings::ATTR_MODE) {
        let requested = u32::from(attr.ia_mode) & !bindings::S_IFMT;
        // SAFETY: the inode is live and initialised.
        let mount = unsafe { inode_mount(inode) };
        request.mode = U32::new(chmod_mode(mount, caller, node_id, requested)?);
    }
    // SAFETY: the VFS sets the kernel ids of a change on a filesystem that
    // does not allow idmapped mounts, and the conversion only reads the
    // initial namespace, which the mount lives in.
    unsafe {
        if has(bindings::ATTR_UID) {
            let uid = attr.__bindgen_anon_1.ia_uid;
            request.uid = U32::new(bindings::from_kuid(&raw mut bindings::init_user_ns, uid));
        }
        if has(bindings::ATTR_GID) {
            let gid = attr.__bindgen_anon_2.ia_gid;
            request.gid = U32::new(bindings::from_kgid(&raw mut bindings::init_user_ns, gid));
        }
    }
    if has(bindings::ATTR_ATIME_SET) {
        request.atime = timespec(attr.ia_atime)?;
    }
    if has(bindings::ATTR_MTIME_SET) {
        request.mtime = timespec(attr.ia_mtime)?;
    }
    if has(bindings::ATTR_FILE) {
        // SAFETY: the change has a live file of this inode.
        request.handle = U64::new(unsafe { handle_of(attr.ia_file) }.ok_or(EIO)?);
    }
    let (reply, placed_at) = if has(bindings::ATTR_SIZE) {
        request.size = U64::new(u64::try_from(attr.ia_size).map_err(|_| EINVAL)?);
        // SAFETY: the inode is live, and the caller holds its inode lock.
        let _invalidate = unsafe { Locked::invalidate(inode, Hold::Exclusive) }?;
        // A dirty folio is sent to the server before the server cuts the
        // file, and no store dirties another one until the cache is cut too.
        // SAFETY: as above.
        unsafe { write_back_all(inode) }?;
        let reply = session.setattr(caller, node_id, request)?;
        // The reply shows the file after the size change, so it is placed at
        // the count of that change.
        // SAFETY: as above, with the invalidate lock held exclusively.
        (reply, unsafe { resize(inode, attr.ia_size) })
    } else {
        // SAFETY: the inode is live and initialised.
        let sent_at = unsafe { inode_mount(inode) }.writes();
        (session.setattr(caller, node_id, request)?, sent_at)
    };
    // SAFETY: the inode is live and initialised.
    unsafe { apply_attr(inode, &reply, placed_at) }
}

/// The wire fields that a change of the fields `given`, in the `ATTR_` flags
/// of the VFS, sets.
fn wire_valid(given: c_uint) -> u32 {
    let has = |flag: u32| given & flag != 0;
    let mut valid = 0;
    for (flag, field) in [
        (bindings::ATTR_MODE, setattr_valid::MODE),
        (bindings::ATTR_UID, setattr_valid::UID),
        (bindings::ATTR_GID, setattr_valid::GID),
        (bindings::ATTR_SIZE, setattr_valid::SIZE),
        (bindings::ATTR_FILE, setattr_valid::HANDLE),
        (bindings::ATTR_ATIME_SET, setattr_valid::ATIME),
        (bindings::ATTR_MTIME_SET, setattr_valid::MTIME),
    ] {
        if has(flag) {
            valid |= field;
        }
    }
    if has(bindings::ATTR_ATIME) && !has(bindings::ATTR_ATIME_SET) {
        valid |= setattr_valid::ATIME_NOW;
    }
    // A size change sets the modification time on the server.
    if has(bindings::ATTR_MTIME) && !has(bindings::ATTR_MTIME_SET) && !has(bindings::ATTR_SIZE) {
        valid |= setattr_valid::MTIME_NOW;
    }
    valid
}

/// A mount that masks the setuid and setgid bits shows the file without the
/// bits the server has, and the session core returns how the chmod preserves
/// them, which needs the mode the server has.
fn chmod_mode(mount: &Mount, caller: Caller, node_id: u64, requested: u32) -> Result<u32> {
    if !mount.mask_privileged() {
        return Ok(requested);
    }
    let chmod = metadata::chmod_mode(requested).ok_or(EPERM)?;
    Ok(chmod.mode(mount.session.getattr(caller, node_id, None)?.mode.get()))
}

fn timespec(time: bindings::timespec64) -> Result<Timespec> {
    Ok(Timespec::new(
        time.tv_sec,
        u32::try_from(time.tv_nsec).map_err(|_| EINVAL)?,
    ))
}
