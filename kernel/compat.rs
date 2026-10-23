// SPDX-License-Identifier: GPL-2.0

//! The differences between the supported kernel versions.

/// The older duration API constructs microseconds only. Round upward so the
/// attempt never expires prematurely.
pub fn delta_from_nanos(nanos: i64) -> kernel::time::Delta {
    #[cfg(voidport_legacy_kernel)]
    {
        kernel::time::Delta::from_micros(nanos / 1000 + i64::from(nanos % 1000 != 0))
    }
    #[cfg(not(voidport_legacy_kernel))]
    {
        kernel::time::Delta::from_nanos(nanos)
    }
}

/// Borrow a C string through the kernel version's character type.
pub fn kernel_cstr(text: &core::ffi::CStr) -> &kernel::prelude::CStr {
    // SAFETY: both APIs view the same NUL-terminated bytes, with the lifetime
    // of the original borrow. The cast accommodates the older unsigned C char.
    unsafe { kernel::prelude::CStr::from_bytes_with_nul_unchecked(text.to_bytes_with_nul()) }
}

// Longterm's atomic API has fetch_add but no fetch_sub. Unsigned addition
// wraps, so adding the representation of -1 decrements on both kernel APIs.
/// Subtract one using the atomic operations shared by supported kernels.
pub fn decrement(counter: &kernel::sync::atomic::Atomic<u64>) {
    counter.fetch_add(u64::MAX, kernel::sync::atomic::Relaxed);
}

// Longterm's atomic API has no boolean type. One and zero in an unsigned
// integer keep the same flag on both kernel APIs.
/// A boolean read and written atomically with relaxed ordering.
pub struct Flag(kernel::sync::atomic::Atomic<u32>);

impl Flag {
    /// A flag set to `value`.
    pub fn new(value: bool) -> Self {
        Self(kernel::sync::atomic::Atomic::new(u32::from(value)))
    }

    /// Whether the flag is set.
    pub fn load(&self) -> bool {
        self.0.load(kernel::sync::atomic::Relaxed) != 0
    }

    /// Sets the flag to `value`.
    pub fn store(&self, value: bool) {
        self.0
            .store(u32::from(value), kernel::sync::atomic::Relaxed);
    }
}

/// Remove the smallest entry using the available mutable cursor API.
pub fn pop_first<K: Ord, V>(
    tree: &mut kernel::rbtree::RBTree<K, V>,
) -> Option<kernel::rbtree::RBTreeNode<K, V>> {
    #[cfg(voidport_legacy_kernel)]
    let cursor = tree.cursor_front()?;
    #[cfg(not(voidport_legacy_kernel))]
    let cursor = tree.cursor_front_mut()?;
    Some(cursor.remove_current().1)
}

/// The create inode operation of a filesystem that has atomic_open.
pub trait Create {
    /// Creates the regular file `dentry` of `mode` in `dir`, which fails if
    /// the name exists.
    ///
    /// # Safety
    ///
    /// The arguments are the ones the VFS passes to the create inode
    /// operation.
    unsafe fn create(
        idmap: *mut kernel::bindings::mnt_idmap,
        dir: *mut kernel::bindings::inode,
        dentry: *mut kernel::bindings::dentry,
        mode: kernel::bindings::umode_t,
    ) -> core::ffi::c_int;
}

/// The create inode operation of `C` with the arguments of the kernel.
///
/// Kernels before 7.3 also pass whether the create is exclusive. Their VFS
/// passes true to a filesystem that has atomic_open, and 7.3 drops the
/// argument because every create is exclusive.
///
/// # Safety
///
/// The arguments are the ones the VFS passes to the create inode operation.
pub unsafe extern "C" fn create<C: Create>(
    idmap: *mut kernel::bindings::mnt_idmap,
    dir: *mut kernel::bindings::inode,
    dentry: *mut kernel::bindings::dentry,
    mode: kernel::bindings::umode_t,
    #[cfg(not(voidport_exclusive_create))] _exclusive: bool,
) -> core::ffi::c_int {
    // SAFETY: the caller passes the arguments of the create inode operation.
    unsafe { C::create(idmap, dir, dentry, mode) }
}

#[cfg(voidport_legacy_kernel)]
/// Socket address argument type accepted by kernel_connect.
pub type SocketAddress = kernel::bindings::sockaddr;
#[cfg(not(voidport_legacy_kernel))]
/// Socket address argument type accepted by kernel_connect.
pub type SocketAddress = kernel::bindings::sockaddr_unsized;
