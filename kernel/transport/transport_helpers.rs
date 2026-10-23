// SPDX-License-Identifier: GPL-2.0
//! Task-local allocation and cancellation for the tasks that use streams.

use kernel::prelude::*;
use kernel::types::NotThreadSafe;

unsafe extern "C" {
    fn voidport_allow_cancel();
    fn voidport_current_killable() -> bool;
    fn voidport_nofs_save() -> c_uint;
    fn voidport_nofs_restore(flags: c_uint);
}

/// Enables kernel-originated cancellation signals for the current I/O worker.
pub fn allow_worker_cancel() {
    // SAFETY: changes only the current task's signal disposition.
    unsafe { voidport_allow_cancel() };
}

/// Proof that a fatal signal can end a killable wait of the task it was made
/// on. It cannot be moved to another task.
pub struct Killable(NotThreadSafe);

/// The proof that a fatal signal can end a killable wait of the current task.
/// `None` for a kernel thread, for a task that is already exiting and for the
/// initial task, since a fatal signal cannot wake them.
pub fn current_killable() -> Option<Killable> {
    // SAFETY: reads only the flags and the identity of the current task.
    unsafe { voidport_current_killable() }.then_some(Killable(NotThreadSafe))
}

/// Prevents filesystem reclaim while this task owns a filesystem operation.
/// The saved task flags cannot be transferred to another task.
pub struct NoFsScope(c_uint, NotThreadSafe);

const _: fn() = || {
    trait NotSend<A> {
        fn check() {}
    }
    impl<T: ?Sized> NotSend<()> for T {}
    impl<T: ?Sized + Send> NotSend<u8> for T {}
    let _ = <NoFsScope as NotSend<_>>::check;
    let _ = <Killable as NotSend<_>>::check;
    trait NotSync<A> {
        fn check() {}
    }
    impl<T: ?Sized> NotSync<()> for T {}
    impl<T: ?Sized + Sync> NotSync<u8> for T {}
    let _ = <NoFsScope as NotSync<_>>::check;
};

impl NoFsScope {
    /// Enter without allowing filesystem reclaim until the scope is dropped.
    pub fn enter() -> Self {
        // SAFETY: the helper changes only the current task's allocation flags.
        Self(unsafe { voidport_nofs_save() }, NotThreadSafe)
    }
}

impl Drop for NoFsScope {
    fn drop(&mut self) {
        // SAFETY: NotThreadSafe keeps restoration on the task that saved flags.
        unsafe { voidport_nofs_restore(self.0) };
    }
}
