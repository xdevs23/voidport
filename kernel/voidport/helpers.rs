// SPDX-License-Identifier: GPL-2.0

use kernel::bindings;
use kernel::error::to_result;
use kernel::prelude::*;
use kernel::types::NotThreadSafe;
pub(crate) use voidport_transport::helpers::{current_killable, Killable, NoFsScope};

use crate::vfs::RecordLock;

// The records behind many of these pointers, such as a folio, an inode or a
// mapping, contain a `lockdep_map` in one of their members. It is an empty
// struct when lock debugging is off, and so has no FFI-safe layout. The
// module only passes the pointers along and never reads that field.
#[allow(improper_ctypes)]
unsafe extern "C" {
    pub(crate) fn voidport_fc_error(fc: *mut bindings::fs_context, message: *const c_char);
    pub(crate) fn voidport_hz() -> c_uint;
    pub(crate) fn voidport_max_jiffy_offset() -> c_ulong;
    pub(crate) fn voidport_readahead_folio(
        rac: *mut bindings::readahead_control,
    ) -> *mut bindings::folio;
    pub(crate) fn voidport_folio_pos(folio: *const bindings::folio) -> bindings::loff_t;
    pub(crate) fn voidport_folio_size(folio: *const bindings::folio) -> usize;
    pub(crate) fn voidport_kmap_local_folio(
        folio: *mut bindings::folio,
        offset: usize,
    ) -> *mut c_void;
    pub(crate) fn voidport_flush_dcache_folio(folio: *mut bindings::folio);
    pub(crate) fn voidport_write_folio(
        mapping: *mut bindings::address_space,
        index: c_ulong,
        create: bool,
    ) -> *mut bindings::folio;
    pub(crate) fn voidport_folio_test_uptodate(folio: *mut bindings::folio) -> bool;
    pub(crate) fn voidport_folio_mark_uptodate(folio: *mut bindings::folio);
    pub(crate) fn voidport_get_folio(
        mapping: *mut bindings::address_space,
        index: c_ulong,
    ) -> *mut bindings::folio;
    pub(crate) fn voidport_folio_put(folio: *mut bindings::folio);
    pub(crate) fn voidport_mapping_set_error(mapping: *mut bindings::address_space, error: c_int);
    pub(crate) fn voidport_mapping_dirty(mapping: *mut bindings::address_space) -> bool;
    pub(crate) fn voidport_mapping_writeback(mapping: *mut bindings::address_space) -> bool;
    pub(crate) fn voidport_iov_iter_extract_will_pin(iter: *const bindings::iov_iter) -> bool;
    pub(crate) fn voidport_write_sync(iocb: *mut bindings::kiocb, count: isize) -> isize;
    pub(crate) fn voidport_i_size_read(inode: *const bindings::inode) -> bindings::loff_t;
    pub(crate) fn voidport_i_size_write(inode: *mut bindings::inode, size: bindings::loff_t);
    pub(crate) fn voidport_inode_set_times(
        inode: *mut bindings::inode,
        atime: bindings::timespec64,
        mtime: bindings::timespec64,
        ctime: bindings::timespec64,
    );
    pub(crate) fn voidport_inode_is_new(inode: *mut bindings::inode) -> bool;
    pub(crate) fn voidport_new_decode_dev(dev: u32) -> bindings::dev_t;
    pub(crate) fn voidport_d_in_lookup(dentry: *const bindings::dentry) -> bool;
    fn voidport_current_umask() -> c_uint;
    pub(crate) fn voidport_inode_uncache_acls(inode: *mut bindings::inode);
    pub(crate) fn voidport_posix_acl_to_xattr(
        acl: *const bindings::posix_acl,
        size: *mut usize,
    ) -> *mut c_void;
    pub(crate) fn voidport_posix_acl_xattr_name(kind: c_int) -> *const c_char;
    pub(crate) fn voidport_max_lfs_filesize() -> bindings::loff_t;
    pub(crate) fn voidport_dir_emit_dots(
        file: *mut bindings::file,
        ctx: *mut bindings::dir_context,
    ) -> bool;
    pub(crate) fn voidport_dir_emit(
        ctx: *mut bindings::dir_context,
        name: *const c_char,
        len: c_int,
        ino: u64,
        kind: c_uint,
    ) -> bool;
    pub(crate) fn voidport_lock_read(fl: *const bindings::file_lock) -> RecordLock;
    pub(crate) fn voidport_lock_conflict(fl: *mut bindings::file_lock, conflict: RecordLock);
    pub(crate) fn voidport_lock_is_getlk(cmd: c_int) -> bool;
    pub(crate) fn voidport_fatal_signal_pending() -> bool;
    pub(crate) fn voidport_ratelimited(class: c_uint) -> bool;
    fn voidport_block_signals(saved: *mut bindings::sigset_t);
}

/// Read the kernel clock with the volatile access its C declaration requires.
///
/// # Safety
/// The kernel clock must be initialized, as it is for all module callbacks.
pub(crate) unsafe fn voidport_jiffies() -> c_ulong {
    // SAFETY: jiffies is an aligned, kernel-lifetime unsigned long. Volatile
    // access preserves the kernel clock's observable load.
    unsafe { core::ptr::read_volatile(&raw const bindings::jiffies) }
}

/// Blocks every signal but SIGKILL for the current task until it is dropped,
/// which restores the signal mask it found. It cannot be moved to another
/// task.
pub(crate) struct FatalSignalsOnly(bindings::sigset_t, NotThreadSafe);

impl FatalSignalsOnly {
    pub(crate) fn enter() -> Self {
        let mut saved = bindings::sigset_t::default();
        // SAFETY: changes only the signal mask of the current task, and
        // writes the mask it replaces into `saved`.
        unsafe { voidport_block_signals(&mut saved) };
        Self(saved, NotThreadSafe)
    }
}

impl Drop for FatalSignalsOnly {
    fn drop(&mut self) {
        // SAFETY: NotThreadSafe restricts the restore to the task that saved
        // the mask, and `self.0` is that mask.
        unsafe {
            bindings::sigprocmask(
                bindings::SIG_SETMASK as c_int,
                &mut self.0,
                core::ptr::null_mut(),
            )
        };
    }
}

#[derive(Clone, Copy)]
pub(crate) enum Hold {
    Shared,
    Exclusive,
}

/// A read-write semaphore of the kernel, held shared or exclusively until the
/// value is dropped. It cannot be moved to another task.
pub(crate) struct Locked {
    semaphore: *mut bindings::rw_semaphore,
    hold: Hold,
    _task: NotThreadSafe,
}

impl Locked {
    /// Acquires `semaphore`, or fails when a fatal signal ends the wait.
    ///
    /// # Safety
    ///
    /// `semaphore` is live for as long as the value.
    pub(crate) unsafe fn take(semaphore: *mut bindings::rw_semaphore, hold: Hold) -> Result<Self> {
        // SAFETY: the caller promises a live semaphore.
        to_result(unsafe {
            match hold {
                Hold::Shared => bindings::down_read_killable(semaphore),
                Hold::Exclusive => bindings::down_write_killable(semaphore),
            }
        })?;
        Ok(Self {
            semaphore,
            hold,
            _task: NotThreadSafe,
        })
    }

    /// Acquires the invalidate lock of the mapping of `inode`, which page
    /// cache fills hold shared.
    ///
    /// # Safety
    ///
    /// `inode` is live for as long as the value.
    pub(crate) unsafe fn invalidate(inode: *mut bindings::inode, hold: Hold) -> Result<Self> {
        // SAFETY: the caller promises a live inode, whose mapping lives as
        // long.
        unsafe { Self::take(&raw mut (*(*inode).i_mapping).invalidate_lock, hold) }
    }
}

impl Drop for Locked {
    fn drop(&mut self) {
        // SAFETY: this task acquired the semaphore as `hold` records.
        unsafe {
            match self.hold {
                Hold::Shared => bindings::up_read(self.semaphore),
                Hold::Exclusive => bindings::up_write(self.semaphore),
            }
        }
    }
}

/// The classes of diagnostic line, each rate limited on its own so that one
/// noisy class cannot silence another.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub(crate) enum DiagClass {
    /// Connection loss, recovery and refusal.
    Transport = 0,
    /// A frame the protocol does not allow.
    Protocol = 1,
    Cleanup = 2,
    /// Cached pages that may show bytes the file does not have.
    Cache = 3,
}

pub(crate) fn ratelimited(class: DiagClass) -> bool {
    // SAFETY: the forwarder touches only its own static states, which the
    // kernel's rate limit serializes.
    unsafe { voidport_ratelimited(class as c_uint) }
}

/// The umask of the current task, which a server applies to the mode of an
/// entry it creates.
pub(crate) fn current_umask() -> u32 {
    // SAFETY: reads only the filesystem context of the current task.
    unsafe { voidport_current_umask() }
}

pub(crate) fn max_lfs_filesize() -> bindings::loff_t {
    // SAFETY: the forwarder answers a constant.
    unsafe { voidport_max_lfs_filesize() }
}

pub(crate) fn random_seed() -> u64 {
    // SAFETY: a call into the kernel's random source, which needs no context.
    unsafe { bindings::get_random_u64() }
}
