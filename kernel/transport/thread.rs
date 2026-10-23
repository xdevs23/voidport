// SPDX-License-Identifier: GPL-2.0
//! An owned kernel thread with cancellation and a mandatory join on drop.
//!
//! Returning from the closure exits the task; it does not park it. The handle
//! takes its own task reference before waking the new thread and retains that
//! reference through `kthread_stop`, including after a natural exit.

use core::ptr::NonNull;

use kernel::bindings;
use kernel::error::{from_err_ptr, to_result};
use kernel::prelude::*;
use kernel::sync::aref::ARef;
use kernel::task::Task;

use crate::helpers::Killable;

/// A kernel thread whose handle holder can cancel all waits performed by its closure.
///
/// Dropping the handle cancels and joins the worker, so it must run in
/// sleepable context, outside locks needed by the worker or its cancellation
/// callback.
///
/// # Invariants
///
/// `task` owns a reference acquired before the created task was woken. `data`
/// is passed only to that task. If kthread_stop skips the trampoline, `discard`
/// releases the unconsumed closure. Otherwise the trampoline releases it.
/// `exited` is the completion the kthread's own storage carries, read once
/// while the task cannot yet run and never reassigned; the owned reference
/// keeps that storage alive, so the pointer stays valid past the task's death.
pub struct Thread {
    task: ARef<Task>,
    /// The kthread exit completion, retained by the owned task reference.
    exited: NonNull<bindings::completion>,
    cancel: KBox<dyn Fn() + Send>,
    data: *mut c_void,
    discard: unsafe fn(*mut c_void),
}

// SAFETY: the closure and cancellation callback are Send. The raw data pointer
// is used only by the worker or, after join proves it never ran, by the handle's holder.
unsafe impl Send for Thread {}

impl Thread {
    /// Starts `f`, retaining `cancel` to end its waits before every join.
    ///
    /// Cancellation must also cover a worker that has not started yet. It must
    /// not join this worker itself or depend on the worker completing first.
    pub fn spawn<F, C>(name: &'static core::ffi::CStr, f: F, cancel: C) -> Result<Self>
    where
        F: FnOnce() + Send + 'static,
        C: Fn() + Send + 'static,
    {
        let cancel = KBox::new(cancel, GFP_KERNEL)? as KBox<dyn Fn() + Send>;
        let data = KBox::into_raw(KBox::new(f, GFP_KERNEL)?).cast::<c_void>();
        // SAFETY: the trampoline has the required signature and owns `data`
        // if invoked. `name` is a NUL-terminated static thread name.
        let task = unsafe {
            from_err_ptr(bindings::kthread_create_on_node(
                Some(trampoline::<F>),
                data,
                bindings::NUMA_NO_NODE,
                name.as_ptr().cast(),
            ))
        };
        let task = match task {
            Ok(task) => task,
            Err(error) => {
                // SAFETY: creation failed, so no worker can consume the box.
                unsafe { discard::<F>(data) };
                return Err(error);
            }
        };
        // SAFETY: successful kthread_create returns a non-null, live task that
        // cannot run its closure until woken. Task is a transparent wrapper of
        // task_struct. ARef::from takes an additional reference, not ownership
        // of the scheduler's reference.
        let task = ARef::from(unsafe { &*NonNull::new_unchecked(task).cast::<Task>().as_ptr() });
        // SAFETY: kthread_create initializes vfork_done to its exit completion
        // before returning. The unwoken task cannot clear that pointer yet.
        // The completion belongs to the kthread storage retained by our ARef.
        let exited = unsafe { NonNull::new_unchecked((*task.as_ptr()).vfork_done) };
        task.wake_up();
        Ok(Self {
            task,
            exited,
            cancel,
            data,
            discard: discard::<F>,
        })
    }

    /// Waits for the exit completion that `kthread_stop` also waits for,
    /// without requesting cancellation. A fatal signal ends the wait early
    /// with `ERESTARTSYS`. Call only after arranging for the worker to exit,
    /// without holding a lock it needs.
    pub fn wait_exited_killable(&self, _killable: &Killable) -> Result {
        // SAFETY: creation captures vfork_done before the task can run. It is
        // the completion in the task's kthread allocation, freed only with the
        // task, which our ARef retains. Thread is not Sync, and this borrow
        // excludes stop/drop, so no other handle consumes this completion. An
        // interrupted wait does not consume the token.
        to_result(unsafe { bindings::wait_for_completion_killable(self.exited.as_ptr()) })?;
        // SAFETY: as above. Restoring the token consumed by the wait lets a
        // later kthread_stop join too.
        unsafe { bindings::complete(self.exited.as_ptr()) };
        Ok(())
    }

    /// Whether the task has exited, so that joining it does not wait.
    pub fn exited(&self) -> bool {
        // SAFETY: as in wait_exited_killable, the completion is in the kthread
        // storage that the task reference of this handle keeps alive.
        // completion_done only reads it, under the lock of the completion.
        unsafe { bindings::completion_done(self.exited.as_ptr()) }
    }

    /// Enable cancellation only on a dedicated I/O kthread. The caller must
    /// then publish its owned task reference under its state mutex and check
    /// the recorded cancellation request before I/O.
    pub fn allow_cancel() {
        crate::helpers::allow_worker_cancel();
    }

    /// Signal a dedicated cancellation-enabled worker. Callers hold the state
    /// mutex that publishes this owned task reference after `allow_cancel`.
    pub fn signal(task: &ARef<Task>) {
        // SAFETY: the owned reference keeps the task allocation alive, even
        // after natural exit. send_sig borrows it for this call only.
        let _ = unsafe { bindings::send_sig(bindings::SIGKILL as c_int, task.as_ptr(), 1) };
    }

    /// Whether the current kthread has been asked to stop.
    pub fn should_stop() -> bool {
        // SAFETY: called on a kthread to read its own stop flag.
        unsafe { bindings::kthread_should_stop() }
    }

    /// Cancels the worker's waits without joining it.
    pub fn cancel(&self) {
        (self.cancel)();
    }

    /// Cancels the worker's waits and joins it, also releasing its task reference.
    pub fn stop(self) {
        drop(self);
    }
}

impl Drop for Thread {
    fn drop(&mut self) {
        (self.cancel)();
        // SAFETY: our ARef keeps both task_struct and its kthread state alive
        // through the join. kthread_stop takes and drops a temporary reference;
        // it does not consume ours, which is released by ARef after this drop.
        let result = unsafe { bindings::kthread_stop(self.task.as_ptr()) };
        if result == -(bindings::EINTR as c_int) {
            // SAFETY: the trampoline always returns zero. -EINTR means the
            // kernel skipped it because stop won before threadfn invocation.
            // The joined task cannot access data, and its box is still ours.
            unsafe { (self.discard)(self.data) };
        }
    }
}

/// Releases a closure that was never invoked.
unsafe fn discard<F>(data: *mut c_void) {
    // SAFETY: the caller owns this unconsumed KBox<F> allocation exclusively.
    drop(unsafe { KBox::from_raw(data.cast::<F>()) });
}

/// Takes ownership of the closure and returns its fixed successful exit code.
unsafe extern "C" fn trampoline<F>(data: *mut c_void) -> c_int
where
    F: FnOnce() + Send + 'static,
{
    // SAFETY: spawn transfers this KBox<F> once, to this trampoline only.
    let f = unsafe { KBox::from_raw(data.cast::<F>()) };
    KBox::into_inner(f)();
    0
}
