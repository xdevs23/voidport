// SPDX-License-Identifier: GPL-2.0

use kernel::bindings;
use kernel::prelude::*;
use kernel::rbtree::{RBTree, RBTreeNode};
use kernel::sync::{new_spinlock, Arc, ArcBorrow, SpinLock};

use crate::cleanup::Closing;
use crate::connection::Data;
use crate::mount::Mount;
use crate::ops::{Privileged, Through};
use crate::session::Session;
use crate::wire::Caller;

pub(crate) struct Handle {
    session: &'static Session,
    caller: Caller,
    id: u64,
    flags: u32,
    /// The lock owner of the open file description, whose record locks on
    /// the file end with the release of the handle.
    lock_owner: u64,
}

impl Handle {
    /// # Safety
    ///
    /// `file` is the file being opened.
    pub(crate) unsafe fn of_file(
        mount: &'static Mount,
        file: *mut bindings::file,
        id: u64,
        flags: u32,
    ) -> Self {
        Self {
            session: &mount.session,
            // SAFETY: the file being opened has its credentials.
            caller: unsafe { Caller::of_file(file) },
            id,
            flags,
            // A lock placed for an open file description has the file as its
            // owner.
            lock_owner: mount.lock_owner(file.cast()),
        }
    }

    pub(crate) fn appends(&self) -> bool {
        self.flags & bindings::O_APPEND != 0
    }

    pub(crate) fn writes_in_place(&self) -> bool {
        matches!(
            self.flags & bindings::O_ACCMODE,
            bindings::O_WRONLY | bindings::O_RDWR
        ) && !self.appends()
    }

    pub(crate) fn write(&self, node_id: u64, offset: u64, data: &dyn Data) -> Result<u32> {
        let through = Through {
            caller: self.caller,
            node_id,
            handle: self.id,
        };
        self.session.write(through, offset, data, Privileged::Keep)
    }

    pub(crate) fn id(&self) -> u64 {
        self.id
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        self.session.release(
            self.caller,
            self.id,
            Closing {
                flags: self.flags,
                lock_owner: Some(self.lock_owner),
            },
        );
    }
}

/// Writeback sends the stores of shared mappings through the first handle.
#[pin_data]
pub(crate) struct Writers {
    #[pin]
    handles: SpinLock<RBTree<u64, Arc<Handle>>>,
}

impl Writers {
    pub(crate) fn new() -> impl PinInit<Self> {
        pin_init!(Self {
            handles <- new_spinlock!(RBTree::new(), "voidport::writers"),
        })
    }

    fn add(&self, handle: &Arc<Handle>) -> Result {
        let entry = RBTreeNode::new(handle.id(), handle.clone(), GFP_KERNEL)?;
        // The server gives every open its own handle, so nothing is replaced.
        let replaced = self.handles.lock().insert(entry);
        drop(replaced);
        Ok(())
    }

    pub(crate) fn first(&self) -> Option<Arc<Handle>> {
        let handles = self.handles.lock();
        let first = handles.values().next().cloned();
        first
    }

    /// The last handle stays while the mapping is `dirty`: a writeback that a
    /// fatal signal ended leaves dirty folios for a later writeback, and the
    /// eviction of the inode gives the handle back.
    fn remove(&self, id: u64, dirty: bool) {
        let removed = {
            let mut handles = self.handles.lock();
            let last = handles.keys().nth(1).is_none();
            if last && dirty {
                None
            } else {
                handles.remove(&id)
            }
        };
        // Giving the handle back acquires a lock that sleeps, so it waits until
        // the spinlock is released.
        drop(removed);
    }

    pub(crate) fn clear(&self) {
        let all = core::mem::take(&mut *self.handles.lock());
        drop(all);
    }
}

/// A handle that cannot be stored drops, which gives it back to the server, so
/// no handle remains open there without a file that uses it.
///
/// # Safety
///
/// `file` is the file being opened, and `inode` its live, initialised inode.
pub(crate) unsafe fn attach(
    inode: *mut bindings::inode,
    file: *mut bindings::file,
    handle: Handle,
) -> Result {
    let handle = Arc::new(handle, GFP_KERNEL)?;
    if handle.writes_in_place() {
        // SAFETY: the caller promises a live, initialised inode.
        unsafe { crate::node::writers(inode) }.add(&handle)?;
    }
    // SAFETY: `file` is the open file; its private data contains the reference
    // to the handle until release removes it.
    unsafe { (*file).private_data = Arc::into_raw(handle).cast_mut().cast::<c_void>() };
    Ok(())
}

/// # Safety
///
/// `file` is a file of the live, initialised `inode` that nothing uses any
/// more.
pub(crate) unsafe fn detach(inode: *mut bindings::inode, file: *mut bindings::file) {
    // SAFETY: the private data of the file is the reference to the handle
    // `attach` stored, or null when it stored none.
    let handle = unsafe {
        let private = (*file).private_data;
        if private.is_null() {
            return;
        }
        (*file).private_data = core::ptr::null_mut();
        Arc::from_raw(private.cast::<Handle>())
    };
    if handle.writes_in_place() {
        // A failed writeback leaves its error on the mapping, for the next
        // fsync of the file.
        // SAFETY: the inode of the file being released is live and
        // initialised.
        unsafe {
            let mapping = (*inode).i_mapping;
            bindings::filemap_fdatawrite(mapping);
            let dirty = crate::helpers::voidport_mapping_dirty(mapping);
            crate::node::writers(inode).remove(handle.id, dirty);
        }
    }
}

/// # Safety
///
/// `file` must be a live file opened by this filesystem.
pub(crate) unsafe fn handle_of(file: *const bindings::file) -> Option<u64> {
    // SAFETY: the promise of the caller holds.
    unsafe { file_handle(file) }.map(Handle::id)
}

/// # Safety
///
/// `file` must be a live file opened by this filesystem.
pub(crate) unsafe fn shared_handle(file: *const bindings::file) -> Option<Arc<Handle>> {
    // SAFETY: the caller promises `file` is a live voidport file; its private
    // data is the reference `attach` stored, or null before it opened.
    let private = unsafe { (*file).private_data.cast::<Handle>() };
    if private.is_null() {
        return None;
    }
    // SAFETY: the reference of the file lasts while the file is live.
    Some(unsafe { ArcBorrow::from_raw(private) }.into())
}

/// # Safety
///
/// `file` must be a live file opened by this filesystem, and outlive the
/// reference.
pub(crate) unsafe fn file_handle<'a>(file: *const bindings::file) -> Option<&'a Handle> {
    // SAFETY: the caller promises `file` is a live voidport file; its private
    // data is the reference to its handle, or null before it opened.
    unsafe { (*file).private_data.cast::<Handle>().as_ref() }
}
