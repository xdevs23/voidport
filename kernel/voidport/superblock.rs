// SPDX-License-Identifier: GPL-2.0

use kernel::bindings;
use kernel::error::to_result;
use kernel::page::{PAGE_SHIFT, PAGE_SIZE};
use kernel::prelude::*;
use voidport_session::time::{lifetime_ended, Tick, TickSpan};

use crate::helpers::{max_lfs_filesize, voidport_jiffies};
use crate::mount::Mount;
use crate::node::{apply_attr, evict as evict_node, iget, mount_of, session_of, ROOT_NODE_ID};
use crate::vfs::{
    dentry_set_time, dentry_time, lookup_distrusts_cache, lookup_rcu, qstr_bytes, statfs_fill,
    Statfs,
};
use crate::vtable::Table;
use crate::wire::Caller;

const VOIDPORT_MAGIC: c_ulong = 0x766f_6964; // "void"

static SUPER_OPS: Table<bindings::super_operations> = Table::new(bindings::super_operations {
    statfs: Some(statfs),
    evict_inode: Some(evict_inode),
    destroy_inode: Some(crate::node::destroy),
    free_inode: Some(bindings::free_inode_nonrcu),
    put_super: Some(put_super),
    ..pin_init::zeroed()
});

static DENTRY_OPS: Table<bindings::dentry_operations> = Table::new(bindings::dentry_operations {
    d_revalidate: Some(d_revalidate),
    ..pin_init::zeroed()
});

pub(crate) unsafe extern "C" fn fill_super(
    sb: *mut bindings::super_block,
    fc: *mut bindings::fs_context,
) -> c_int {
    // SAFETY: `fc`'s private data is the mount `Context`, whose session
    // `get_tree` opened.
    let mount = unsafe {
        let context = &mut *(crate::vfs::fc_private(fc).cast::<crate::fs::Context>());
        match context.mount.take() {
            Some(mount) => mount,
            None => return EINVAL.to_errno(),
        }
    };
    match build(sb, mount) {
        Ok(()) => 0,
        Err(error) => {
            // A superblock without a root is never handed to `put_super`, so
            // what `build` already attached, the mount and the threads it
            // started, is taken down here, on the same path an unmount would
            // run.
            // SAFETY: `sb` is the superblock this fill owns exclusively.
            unsafe { teardown(sb) };
            error.to_errno()
        }
    }
}

fn build(sb: *mut bindings::super_block, mount: KBox<Mount>) -> Result {
    let _scope = crate::helpers::NoFsScope::enter();
    // The superblock owns the mount; `put_super` reclaims it. Set it, and the
    // operations, before the root inode: `iget` refreshes attributes through
    // `session_of(sb)`, which reads this pointer.
    // SAFETY: `sb` is the fresh superblock this fill owns exclusively.
    unsafe {
        (*sb).s_fs_info = KBox::into_raw(mount).cast::<c_void>();
        (*sb).s_magic = VOIDPORT_MAGIC;
        (*sb).s_op = SUPER_OPS.get();
        (*sb).s_blocksize = PAGE_SIZE as c_ulong;
        (*sb).s_blocksize_bits = PAGE_SHIFT as u8;
        (*sb).s_maxbytes = max_lfs_filesize();
        (*sb).s_time_gran = 1;
        (*sb).s_xattr = crate::xattr::HANDLERS.get().cast();
        crate::vfs::sb_offer_acls(sb);
        bindings::set_default_d_op(sb, DENTRY_OPS.get());
    }
    // A superblock starts on a backing device that does no writeback, so the
    // dirty folios of shared mappings need one of its own.
    // SAFETY: as above.
    to_result(unsafe { bindings::super_setup_bdi(sb) })?;

    // Start the thread of the first connection before the first request:
    // every request after the inline handshake, the root's own `getattr`
    // included, is answered by that thread, so it must be reading before
    // anything waits for a reply. A failure to spawn is a mount failure, and
    // the superblock teardown that follows closes the session and joins
    // whatever started.
    // SAFETY: `sb` has its `s_fs_info` set.
    let mount = unsafe { mount_of(sb) };
    let session = &mount.session;
    session.start_reading()?;
    session.start_cleanup()?;

    let sent_at = mount.writes();
    let attr = session.getattr(Caller::current(), ROOT_NODE_ID, None)?;
    // SAFETY: `sb` is live with its `s_fs_info` set, so `iget` can refresh.
    let root = unsafe { iget(sb, ROOT_NODE_ID, 0, &attr, sent_at)? };
    // SAFETY: `root` is the referenced root inode; `d_make_root` consumes the
    // reference and returns the root dentry, or null on failure.
    let root_dentry = unsafe { bindings::d_make_root(root) };
    if root_dentry.is_null() {
        return Err(ENOMEM);
    }
    // SAFETY: `sb` is the fresh superblock; it takes the root dentry.
    unsafe { (*sb).s_root = root_dentry };
    Ok(())
}

unsafe extern "C" fn statfs(dentry: *mut bindings::dentry, buf: *mut bindings::kstatfs) -> c_int {
    // SAFETY: the VFS passes a live dentry naming a live inode, and a buffer.
    let (session, node_id) = unsafe {
        let inode = (*dentry).d_inode;
        (session_of((*inode).i_sb), crate::node::id_of(inode))
    };
    let stat = match session.statfs(Caller::current(), node_id) {
        Ok(stat) => stat,
        Err(error) => return error.to_errno(),
    };
    // A reply the protocol accepts can still exceed what this target's
    // statistics structure holds; that is a local limit, answered before any
    // field is written, and it does not end the connection.
    let (Ok(bsize), Ok(namelen), Ok(frsize)) = (
        c_long::try_from(stat.bsize.get()),
        c_long::try_from(stat.namelen.get()),
        c_long::try_from(stat.frsize.get()),
    ) else {
        return EOVERFLOW.to_errno();
    };
    // SAFETY: `buf` is the live statistics buffer to fill.
    unsafe {
        statfs_fill(
            buf,
            Statfs {
                kind: VOIDPORT_MAGIC as c_long,
                bsize,
                blocks: stat.blocks.get(),
                bfree: stat.bfree.get(),
                bavail: stat.bavail.get(),
                files: stat.files.get(),
                ffree: stat.ffree.get(),
                namelen,
                frsize,
            },
        );
    }
    0
}

/// Private identity survives until destruction, after hash removal.
unsafe extern "C" fn evict_inode(inode: *mut bindings::inode) {
    // SAFETY: the evict path passes a live inode this filesystem owns.
    unsafe { evict_node(inode) };
}

/// Runs after every inode has been evicted.
unsafe extern "C" fn put_super(sb: *mut bindings::super_block) {
    // SAFETY: `sb` is the superblock being destroyed.
    unsafe { teardown(sb) };
}

///
/// # Safety
///
/// `sb` must be a voidport superblock no other task is serving requests
/// through: the one being destroyed, or the one whose fill failed.
unsafe fn teardown(sb: *mut bindings::super_block) {
    // SAFETY: `sb`'s `s_fs_info` is the mount `build` stored, or null if it
    // never got that far; this reclaims it once.
    unsafe {
        let raw = (*sb).s_fs_info.cast::<Mount>();
        if raw.is_null() {
            return;
        }
        (*sb).s_fs_info = core::ptr::null_mut();
        let mount = KBox::from_raw(raw);
        mount.session.close();
        drop(mount);
    }
}

unsafe extern "C" fn d_revalidate(
    dir: *mut bindings::inode,
    name: *const bindings::qstr,
    dentry: *mut bindings::dentry,
    flags: c_uint,
) -> c_int {
    // The lock-free walk phase cannot sleep to ask the server.
    if lookup_rcu(flags) {
        return ECHILD.to_errno();
    }
    // SAFETY: `dentry` is live; a positive one names an inode, a negative one
    // has none.
    let inode = unsafe { (*dentry).d_inode };
    // SAFETY: `dir` is the live parent inode of a live voidport superblock.
    let (mount, parent) = unsafe { (mount_of((*dir).i_sb), crate::node::id_of(dir)) };
    let session = &mount.session;

    // Positive and negative entries share the configured lifetime unless the
    // walk explicitly distrusts the cache.
    // SAFETY: `dentry` is live; its time is the epoch it was resolved in.
    // The kernel's tick counter is initialized for every module callback.
    let fresh = unsafe {
        !lookup_distrusts_cache(flags)
            && !lifetime_ended(
                Tick::new(dentry_time(dentry)),
                TickSpan::new(mount.entry_timeout()),
                Tick::new(voidport_jiffies()),
            )
    };
    if fresh {
        return 1;
    }

    // SAFETY: `name` is the live qstr the walk is resolving, stable for the
    // call.
    let bytes = unsafe { qstr_bytes(name) };
    let caller = Caller::current();
    let sent_at = mount.writes();
    match session.lookup(caller, parent, bytes) {
        Ok(entry) => {
            // The revalidation counted a lookup on the server, and it admits no
            // inode, so it owes a compensating forget either way.
            session.forget(caller, entry.node_id.get(), 1);
            // SAFETY: `dentry` is live.
            unsafe {
                if !inode.is_null()
                    && crate::node::matches_entry(inode, entry.node_id.get(), entry.generation)
                {
                    if let Err(error) = apply_attr(inode, &entry.attr, sent_at) {
                        return error.to_errno();
                    }
                    dentry_set_time(dentry, voidport_jiffies());
                    1
                } else {
                    // The name now names another inode, or a negative entry
                    // became positive: invalid, so the walk retries.
                    0
                }
            }
        }
        Err(error) if error == ENOENT => {
            if inode.is_null() {
                // Still absent: the negative entry is valid.
                // SAFETY: `dentry` is live.
                unsafe { dentry_set_time(dentry, voidport_jiffies()) };
                1
            } else {
                // Was positive, now gone: invalid.
                0
            }
        }
        // Any other failure invalidates safely; the walk re-resolves.
        Err(_) => 0,
    }
}
