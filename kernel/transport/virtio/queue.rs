// SPDX-License-Identifier: GPL-2.0
//! The queues of a device: room on a queue for a chain, making the chain
//! available, and giving each chain the device returns back to the channel
//! it belongs to.

use core::sync::atomic::Ordering::Acquire;

use kernel::bindings;
use kernel::error::to_result;
use kernel::prelude::*;
use kernel::sync::{new_condvar, new_mutex, Arc, CondVar, Mutex, MutexGuard};
use kernel::workqueue::{impl_has_work, new_work, Work, WorkItem};
use voidport_bindings as generated;

use super::chain::{Chain, Flight, Mailbox};
use super::Wait;

#[pin_data]
pub(super) struct Queue {
    vq: *mut generated::virtqueue,
    /// Whether the device is being removed. Every use of the queue is under
    /// this lock.
    #[pin]
    removed: Mutex<bool>,
    /// Notified when the device returns chains, which frees their
    /// descriptors, and when the device is being removed.
    #[pin]
    room: CondVar,
    /// Gives the chains the device returned back to their channels.
    #[pin]
    work: Work<Queue>,
}

// SAFETY: the queue is used under its lock, and the queue callback, which the
// virtio core runs at any time, only reads the private pointer of the queue.
unsafe impl Send for Queue {}
// SAFETY: as above.
unsafe impl Sync for Queue {}

impl_has_work! {
    impl HasWork<Self> for Queue { self.work }
}

impl Queue {
    pub(super) fn new(vq: *mut generated::virtqueue) -> Result<Arc<Self>> {
        Arc::pin_init(
            pin_init!(Self {
                vq,
                removed <- new_mutex!(false, "voidport::queue"),
                room <- new_condvar!("voidport::queue_room"),
                work <- new_work!("voidport::returned"),
            }),
            GFP_KERNEL,
        )
    }

    /// Room for a chain of the channel of `mailbox`, once the queue has
    /// `slots` free descriptors, with the wait given by `wait`. `ENODEV` once
    /// the device is being removed.
    pub(super) fn room<'a>(
        &'a self,
        mailbox: &'a Arc<Mailbox>,
        slots: usize,
        wait: Wait,
    ) -> Result<Room<'a>> {
        let mut held = self.removed.lock();
        loop {
            if *held {
                return Err(ENODEV);
            }
            // SAFETY: the lock is held, and the queue exists until the device
            // is removed.
            if unsafe { (*self.vq).num_free } as usize >= slots {
                return Ok(Room {
                    queue: self,
                    mailbox,
                    held,
                });
            }
            match wait {
                Wait::Interruptible => {
                    if self.room.wait_interruptible(&mut held) {
                        return Err(ERESTARTSYS);
                    }
                }
                Wait::Always => self.room.wait(&mut held),
            }
        }
    }

    /// Makes `chain` of the channel of `mailbox` available to the device.
    /// `ENOTCONN` when the channel is shut and `chain` is not the close chain
    /// of the channel.
    fn add(&self, held: &MutexGuard<'_, bool>, mailbox: &Arc<Mailbox>, chain: Chain) -> Result {
        mailbox.count(&chain)?;
        let Chain(mut flight) = chain;
        flight.mailbox = Some(mailbox.clone());
        let (mut lists, writable) = flight.scatter();
        let token = KBox::into_raw(flight);
        // The indirect table of the chain is allocated without starting I/O:
        // reclaim that writes a page back could wait for a chain that waits
        // for this queue.
        let flags = generated::VOIDPORT_GFP_NOIO;
        // SAFETY: the lock is held, and the queue exists until the device is
        // removed. The lists contain pages that the flight owns or has a
        // reference to until the device returns its token.
        let added = to_result(unsafe {
            generated::virtqueue_add_sgs(
                self.vq,
                lists.as_mut_ptr(),
                1,
                writable,
                token.cast(),
                flags,
            )
        });
        if let Err(error) = added {
            // SAFETY: the queue did not accept the token, which is the box
            // made above.
            let flight = unsafe { KBox::from_raw(token) };
            if let Some(close) = mailbox.uncount(&flight) {
                self.add_close(held, mailbox, close);
            }
            return Err(error);
        }
        // The queue is deleted once its lock is free, so the device is
        // notified under the lock.
        // SAFETY: the lock is held, and the queue exists.
        if unsafe { generated::virtqueue_kick_prepare(self.vq) } {
            // SAFETY: as above.
            unsafe { generated::virtqueue_notify(self.vq) };
        }
        Ok(())
    }

    /// Makes `close`, the close chain of the channel of `mailbox`, available
    /// once it is due. A close chain the queue does not accept is logged:
    /// the session of the channel then remains open on the server until the
    /// next driver resets the device.
    fn add_close(&self, held: &MutexGuard<'_, bool>, mailbox: &Arc<Mailbox>, close: Chain) {
        if let Err(error) = self.add(held, mailbox, close) {
            pr_warn!(
                "the close chain of a channel was not made available: {:?}\n",
                error
            );
        }
    }

    /// Gives every chain the device returned so far back to the channel it
    /// belongs to, and makes each close chain that falls due available,
    /// unless the device is being removed.
    fn reap(&self, held: &MutexGuard<'_, bool>) {
        let mut written = 0;
        loop {
            // SAFETY: the lock is held, and the queue exists until the device
            // is removed.
            let token = unsafe { generated::virtqueue_get_buf(self.vq, &mut written) };
            if token.is_null() {
                return;
            }
            // SAFETY: every token on the queue is a flight that `add` made
            // available, and the device returned this one.
            let Some((mailbox, close)) = (unsafe { give_back(token, written) }) else {
                continue;
            };
            // The chain just returned freed a descriptor for the close
            // chain. A device being removed has no channel left to end.
            if !**held {
                self.add_close(held, &mailbox, close);
            }
        }
    }

    /// Makes no chain available on the queue any more, and ends every wait
    /// for room on it.
    pub(super) fn retire(&self) {
        *self.removed.lock() = true;
        self.room.notify_all();
    }

    /// Gives every chain back to the channel it belongs to once the device is
    /// reset: the chains the device returned with what it wrote, and the
    /// others with nothing written.
    pub(super) fn give_back_all(&self) {
        // SAFETY: the work is part of the queue. The reset ended the queue
        // callbacks, so once the work queued last has run, no other runs.
        unsafe { bindings::flush_work(Work::raw_get(&self.work)) };
        let held = self.removed.lock();
        self.reap(&held);
        loop {
            // SAFETY: the lock is held, and the device is reset.
            let token = unsafe { generated::virtqueue_detach_unused_buf(self.vq) };
            if token.is_null() {
                break;
            }
            // SAFETY: every token on the queue is a flight that `add` made
            // available, and the device will not use this one. The device
            // is being removed, so a close chain that falls due is dropped.
            drop(unsafe { give_back(token, 0) });
        }
        drop(held);
        self.room.notify_all();
    }

    /// Queues the work that gives every chain the device returned back to the
    /// channel it belongs to.
    pub(super) fn schedule(self: &Arc<Self>) {
        // The work uses no state of the CPU that queues it, and reclaim that
        // writes a page back can wait for it, so it runs on the unbound
        // workqueue allocated by the driver, which has a rescuer thread.
        // SAFETY: only the queue callback of a device of the driver calls
        // this, while the driver is registered. `Driver::register` stores the
        // workqueue before it registers the driver, and the drop of the driver
        // destroys it after the removal of every device ended the callbacks.
        let workqueue =
            unsafe { kernel::workqueue::Queue::from_raw(super::WORKQUEUE.load(Acquire)) };
        // Work already pending on the queue also gives back the chains the
        // device returned before this call.
        drop(workqueue.enqueue(self.clone()));
    }
}

impl WorkItem for Queue {
    type Pointer = Arc<Queue>;

    fn run(queue: Arc<Queue>) {
        let held = queue.removed.lock();
        // A device being removed gives its chains back once it is reset.
        if *held {
            return;
        }
        loop {
            // SAFETY: the lock is held, and the queue exists until the device
            // is removed.
            unsafe { generated::virtqueue_disable_cb(queue.vq) };
            queue.reap(&held);
            // SAFETY: as above.
            if unsafe { generated::virtqueue_enable_cb(queue.vq) } {
                break;
            }
        }
        drop(held);
        queue.room.notify_all();
    }
}

/// Gives the flight `token` back to the channel it belongs to, with the
/// `written` bytes the device wrote into it. Returns the close chain of the
/// channel when that is due now, with the mailbox of the channel.
///
/// # Safety
///
/// `token` is a flight that a queue made available, which the device no
/// longer uses.
unsafe fn give_back(token: *mut c_void, written: c_uint) -> Option<(Arc<Mailbox>, Chain)> {
    // SAFETY: the device no longer uses `token`, as the caller promises,
    // and `add` made the box into the token.
    let mut flight = unsafe { KBox::from_raw(token.cast::<Flight>()) };
    flight.written = written;
    let mailbox = flight.mailbox.take()?;
    let close = mailbox.deliver(flight)?;
    Some((mailbox, close))
}

/// Room on a queue for one chain, under the lock of the queue until the chain
/// is made available.
pub struct Room<'a> {
    queue: &'a Queue,
    mailbox: &'a Arc<Mailbox>,
    held: MutexGuard<'a, bool>,
}

impl Room<'_> {
    /// Makes `chain` available to the device, which returns it to the
    /// channel of the room. `ENOTCONN` when the channel is shut and `chain`
    /// is not the close chain of the channel.
    pub fn make_available(self, chain: Chain) -> Result {
        self.queue.add(&self.held, self.mailbox, chain)
    }

    /// Makes `close`, the close chain of the channel of the room, available
    /// to the device.
    pub(super) fn add_close(self, close: Chain) {
        self.queue.add_close(&self.held, self.mailbox, close);
    }
}
