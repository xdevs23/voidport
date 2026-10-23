// SPDX-License-Identifier: GPL-2.0

use kernel::bindings;

pub(crate) struct Table<T>(T);

macro_rules! shared_operations {
    ($($table:ty),+ $(,)?) => {
        $(
            // SAFETY: these operation records contain callbacks, raw pointers
            // and scalar values, with no interior mutation. The private field
            // prevents safe access except through the read-only pointer API.
            unsafe impl Sync for Table<$table> {}
        )+
    };
}

shared_operations!(
    bindings::address_space_operations,
    bindings::dentry_operations,
    bindings::file_operations,
    bindings::inode_operations,
    bindings::super_operations,
    bindings::vm_operations_struct,
    crate::vfs::xattr_handler,
    [*const crate::vfs::xattr_handler; 2],
);

impl<T> Table<T> {
    pub(crate) const fn new(operations: T) -> Self {
        Self(operations)
    }

    pub(crate) const fn get(&self) -> *const T {
        &self.0
    }
}
