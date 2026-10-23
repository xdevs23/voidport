// SPDX-License-Identifier: GPL-2.0

//! The virtio filesystem devices that speak the voidport protocol, and the
//! channels opened on them by the connections of a mount.
//!
//! The device owns the pages of a chain until it returns the chain. A chain has
//! a reference to every page it lists. The data of a write from kernel memory,
//! whose pages may have no count of references, is copied into pages allocated
//! for the chain. The close chain of a channel is made available once the
//! device has returned the hello of the channel, so the close never overtakes
//! the hello that opens the channel.

use core::mem::offset_of;
use core::num::NonZeroUsize;
use core::ptr::null_mut;
use core::sync::atomic::AtomicPtr;
use core::sync::atomic::Ordering::{Acquire, Release};

use kernel::bindings;
use kernel::error::to_result;
use kernel::prelude::*;
use kernel::sync::atomic::{Atomic, Relaxed};
use kernel::sync::{global_lock, Arc};
use kernel::types::Opaque;
use voidport_bindings as generated;
use voidport_proto::chain::{ChainId, ChainKind, ChannelNumber};

mod chain;
mod queue;

pub use chain::{Chain, Reply, Returned};
pub use queue::Room;

use chain::Mailbox;
use queue::Queue;

/// What else, besides what is waited for, ends a wait on a device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Wait {
    /// A signal, with `ERESTARTSYS`.
    Interruptible,
    /// Nothing but the removal of the device.
    Always,
}

/// How many bytes the configuration of a virtio filesystem device has for its
/// tag.
const TAG_LEN: usize = offset_of!(generated::virtio_fs_config, num_request_queues)
    - offset_of!(generated::virtio_fs_config, tag);

const TAG_PREFIX: &[u8] = b"voidport-";

/// The tag of a virtio filesystem device, by which a mount selects the
/// device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tag {
    bytes: [u8; TAG_LEN],
    len: usize,
}

impl Tag {
    /// The tag `name`, which is not empty, contains no NUL and fits the
    /// configuration of a device.
    pub fn new(name: &[u8]) -> Result<Self> {
        if name.is_empty() || name.len() > TAG_LEN || name.contains(&0) {
            return Err(EINVAL);
        }
        let mut bytes = [0u8; TAG_LEN];
        bytes[..name.len()].copy_from_slice(name);
        Ok(Self {
            bytes,
            len: name.len(),
        })
    }

    /// The bytes of the tag.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    /// The tag of `vdev`, whose configuration pads it with NULs.
    ///
    /// # Safety
    ///
    /// `vdev` is a virtio filesystem device that the bus offers this driver.
    unsafe fn of(vdev: *mut generated::virtio_device) -> Self {
        let mut bytes = [0u8; TAG_LEN];
        // SAFETY: `vdev` is a virtio filesystem device, as the caller
        // promises, and the buffer has room for the tag in its
        // configuration.
        unsafe { generated::voidport_virtio_fs_tag(vdev, bytes.as_mut_ptr()) };
        let len = bytes.iter().position(|&byte| byte == 0).unwrap_or(TAG_LEN);
        Self { bytes, len }
    }

    /// Whether a device with this tag is one for this driver.
    pub fn is_voidport(&self) -> bool {
        self.as_bytes().starts_with(TAG_PREFIX)
    }
}

global_lock! {
    // SAFETY: `Driver::register` initializes the lock once, before it
    // registers the driver, whose callbacks are the only other users.
    unsafe(uninit) static DEVICES: Mutex<KVec<Arc<Device>>> = KVec::new();
}

/// The workqueue on which the queues of every device give returned chains
/// back. `Driver::register` allocates it before it registers the driver, and
/// the drop of the driver destroys it once the driver is unregistered.
static WORKQUEUE: AtomicPtr<bindings::workqueue_struct> = AtomicPtr::new(null_mut());

/// The table ends with an entry of zeros.
static ID_TABLE: [generated::virtio_device_id; 2] = [
    generated::virtio_device_id {
        device: generated::VIRTIO_ID_FS,
        vendor: generated::VIRTIO_DEV_ANY_ID,
    },
    generated::virtio_device_id {
        device: 0,
        vendor: 0,
    },
];

struct Record(Opaque<generated::virtio_driver>);

// SAFETY: the fields are set before registration. Afterwards only the driver
// core changes the bookkeeping of the record, under its own locks.
unsafe impl Sync for Record {}

static RECORD: Record = Record(Opaque::new(generated::virtio_driver {
    driver: bindings::device_driver {
        name: c"voidport".as_ptr().cast(),
        ..pin_init::zeroed()
    },
    id_table: ID_TABLE.as_ptr(),
    validate: Some(validate),
    probe: Some(probe),
    remove: Some(remove),
    ..pin_init::zeroed()
}));

/// The registration of the driver, which ends when it is dropped.
pub struct Driver(());

impl Driver {
    /// Registers the driver for `owner`, the module being loaded.
    ///
    /// # Safety
    ///
    /// Called once per module load.
    pub unsafe fn register(owner: *mut bindings::module) -> Result<Self> {
        // SAFETY: this runs once, before the driver can probe a device.
        unsafe { DEVICES.init() };
        // SAFETY: allocates a workqueue, or returns null.
        let workqueue = unsafe { generated::voidport_virtio_alloc_workqueue() };
        if workqueue.is_null() {
            return Err(ENOMEM);
        }
        WORKQUEUE.store(workqueue, Release);
        // SAFETY: the record is complete and lives as long as the module,
        // which unregisters it before it goes.
        let registered =
            to_result(unsafe { generated::__register_virtio_driver(RECORD.0.get(), owner) });
        if registered.is_err() {
            // SAFETY: the driver has no device, so nothing queues work on the
            // workqueue.
            unsafe { bindings::destroy_workqueue(WORKQUEUE.swap(null_mut(), Acquire)) };
        }
        registered.map(|()| Self(()))
    }
}

impl Drop for Driver {
    fn drop(&mut self) {
        // SAFETY: the driver is registered. Unregistering it removes every
        // device it has.
        unsafe { generated::unregister_virtio_driver(RECORD.0.get()) };
        // SAFETY: the removal reset every device, which ended the queue
        // callbacks, so nothing queues work on the workqueue any more.
        unsafe { bindings::destroy_workqueue(WORKQUEUE.swap(null_mut(), Acquire)) };
    }
}

/// Accepts a device whose tag is one for this driver, and declines any other
/// one, which the next driver for the device ID can then bind.
///
/// # Safety
///
/// `vdev` is a device of the ID table that the bus offers this driver.
unsafe extern "C" fn validate(vdev: *mut generated::virtio_device) -> c_int {
    // SAFETY: the bus passes a device of the ID table.
    if unsafe { Tag::of(vdev) }.is_voidport() {
        0
    } else {
        ENODEV.to_errno()
    }
}

/// # Safety
///
/// `vdev` is a device that `validate` accepted, which the bus is probing.
unsafe extern "C" fn probe(vdev: *mut generated::virtio_device) -> c_int {
    // SAFETY: the bus passes a device that `validate` accepted.
    match unsafe { Device::probe(vdev) } {
        Ok(()) => 0,
        Err(error) => error.to_errno(),
    }
}

/// # Safety
///
/// `vdev` is a device this driver probed, which the bus removes.
unsafe extern "C" fn remove(vdev: *mut generated::virtio_device) {
    let removed = {
        let mut devices = DEVICES.lock();
        let index = devices.iter().position(|device| device.vdev == vdev);
        index.and_then(|index| devices.remove(index).ok())
    };
    if let Some(device) = removed {
        device.remove();
    }
}

/// Runs in interrupt context. The work of the queue gives every returned chain
/// back to the channel it belongs to.
///
/// # Safety
///
/// `vq` is a queue of a device of this driver.
unsafe extern "C" fn returned(vq: *mut generated::virtqueue) {
    // SAFETY: the virtio core passes a queue of a device of this driver.
    let (vdev, index) = unsafe { ((*vq).vdev, (*vq).index) };
    // SAFETY: as above, so `vdev` is a device of this driver.
    let device = unsafe { generated::voidport_virtio_driver_data(vdev) }
        .cast::<Device>()
        .cast_const();
    if device.is_null() {
        return;
    }
    // SAFETY: the driver data of the device points to its `Device` from
    // before the device is ready until after the reset that ends the
    // callbacks, and the driver has a reference to the `Device` for that
    // time.
    let device = unsafe { &*device };
    // The virtio core numbers the queues in the order in which the driver
    // asked for them, which is the order of `queues`.
    let Some(queue) = device.queues.get(index as usize) else {
        return;
    };
    queue.schedule();
}

/// A virtio filesystem device of this driver.
pub struct Device {
    vdev: *mut generated::virtio_device,
    tag: Tag,
    /// The high-priority queue, then every request queue.
    queues: KVec<Arc<Queue>>,
    /// How many queues `queues` has. The count is never zero, so choosing a
    /// queue by the remainder of a division by it cannot divide by zero.
    queue_count: NonZeroUsize,
    /// The most descriptors one chain uses: the size of the smallest queue.
    longest: usize,
    /// Whether the queues add a chain as one indirect descriptor, which
    /// points to a table of the descriptors of the chain.
    indirect: bool,
    /// The number of the last channel opened on the device.
    channels: Atomic<u64>,
    /// Where the device returns the reset chain, which ends the channels
    /// that an earlier driver left open.
    reset: Arc<Mailbox>,
}

// SAFETY: the device record is used only through the virtio core, which
// locks what it changes, and each queue is used under the lock of the queue.
unsafe impl Send for Device {}
// SAFETY: as above.
unsafe impl Sync for Device {}

impl Device {
    /// The device with `tag`, if the driver has one.
    pub fn find(tag: &Tag) -> Option<Arc<Self>> {
        DEVICES
            .lock()
            .iter()
            .find(|device| device.tag == *tag)
            .cloned()
    }

    /// Waits until the device has returned the reset chain: until then a
    /// hello may arrive on a channel that an earlier driver left open. A
    /// signal ends the wait.
    pub fn wait_reset(&self) -> Result {
        self.reset.wait_idle()
    }

    /// Opens a channel with a number no channel of this driver had on the
    /// device.
    pub fn open(self: &Arc<Self>) -> Result<Channel> {
        let channel = Channel {
            device: self.clone(),
            number: ChannelNumber(self.channels.fetch_add(1, Relaxed) + 1),
            mailbox: Mailbox::new()?,
        };
        let close = channel.new_chain(ChainKind::Close, &[], 0)?;
        channel.mailbox.keep_close(close);
        Ok(channel)
    }

    /// How many free descriptors of a queue a chain of `descriptors` needs:
    /// the one that points to its indirect table, on a device that uses
    /// indirect descriptors, and otherwise one for each descriptor of the
    /// chain.
    fn slots(&self, descriptors: usize) -> usize {
        if self.indirect {
            descriptors.min(1)
        } else {
            descriptors
        }
    }

    fn queue_here(&self) -> &Queue {
        // SAFETY: reads the number of the CPU of the current task.
        let cpu = unsafe { bindings::raw_smp_processor_id() } as usize;
        &self.queues[cpu % self.queue_count]
    }

    /// Sets up `vdev`: its queues, the device of the driver, and the reset
    /// chain that ends the channels that an earlier driver left open.
    ///
    /// # Safety
    ///
    /// `vdev` is a device of this driver that the bus is probing.
    unsafe fn probe(vdev: *mut generated::virtio_device) -> Result {
        // SAFETY: the bus is probing `vdev`, as the caller promises.
        let (tag, requests) =
            unsafe { (Tag::of(vdev), generated::voidport_virtio_fs_queues(vdev)) };
        // The high-priority queue comes before the request queues.
        let count = usize::try_from(requests)
            .ok()
            .and_then(|requests| requests.checked_add(1))
            .ok_or(EINVAL)?;
        let mut vqs = KVec::from_elem(core::ptr::null_mut(), count, GFP_KERNEL)?;
        let mut info = KVec::with_capacity(count, GFP_KERNEL)?;
        for _ in 0..count {
            info.push(
                generated::virtqueue_info {
                    name: c"voidport".as_ptr().cast(),
                    callback: Some(returned),
                    ctx: false,
                },
                GFP_KERNEL,
            )?;
        }
        let found = c_uint::try_from(count).map_err(|_| EINVAL)?;
        // SAFETY: the bus is probing `vdev`, as the caller promises, and both
        // arrays have an entry for every queue.
        to_result(unsafe {
            generated::voidport_virtio_find_vqs(vdev, found, vqs.as_mut_ptr(), info.as_mut_ptr())
        })?;
        // SAFETY: the queues were just found on `vdev`.
        let started = unsafe { Self::start(vdev, tag, &vqs) };
        if started.is_err() {
            // SAFETY: nothing of the device has used the queues.
            unsafe { generated::voidport_virtio_del_vqs(vdev) };
        }
        started
    }

    /// Builds the device of the driver over the queues `vqs` of `vdev`,
    /// makes it ready, makes the reset chain available and publishes the
    /// device for dials. A device that fails after it was made ready is
    /// stopped, and the caller deletes the queues.
    ///
    /// # Safety
    ///
    /// `vqs` are the queues just found on `vdev`, which no one uses yet.
    unsafe fn start(
        vdev: *mut generated::virtio_device,
        tag: Tag,
        vqs: &[*mut generated::virtqueue],
    ) -> Result {
        let queue_count = NonZeroUsize::new(vqs.len()).ok_or(EINVAL)?;
        let mut queues = KVec::with_capacity(vqs.len(), GFP_KERNEL)?;
        let mut longest = usize::MAX;
        for &vq in vqs {
            // SAFETY: the queue was found on the device.
            let size = unsafe { generated::virtqueue_get_vring_size(vq) } as usize;
            longest = longest.min(size);
            queues.push(Queue::new(vq)?, GFP_KERNEL)?;
        }
        let device = Arc::new(
            Device {
                vdev,
                tag,
                queues,
                queue_count,
                longest,
                // SAFETY: the bus probes the device after the driver
                // negotiated its features.
                indirect: unsafe { generated::voidport_virtio_indirect(vdev) },
                channels: Atomic::new(0),
                reset: Mailbox::new()?,
            },
            GFP_KERNEL,
        )?;
        // A reset belongs to no channel, and nothing looks for its number.
        let reset = Chain::new(ChainId(0), ChannelNumber(0), ChainKind::Reset, &[], 0)?;
        // The device is published once the reset chain is available, so no
        // dial finds it before.
        let mut devices = DEVICES.lock();
        devices.reserve(1, GFP_KERNEL)?;
        // SAFETY: the device is not ready, so no callback runs yet. From here
        // on, every path stops the device before it drops `device`, and the
        // stop clears the driver data after the reset that ends the
        // callbacks.
        unsafe {
            generated::voidport_virtio_set_driver_data(
                vdev,
                core::ptr::from_ref::<Device>(&device).cast_mut().cast(),
            )
        };
        // SAFETY: the queues are set up and the callbacks find them.
        unsafe { generated::voidport_virtio_device_ready(vdev) };
        let added = device.queues[0]
            .room(
                &device.reset,
                device.slots(reset.descriptors()),
                Wait::Always,
            )
            .and_then(|room| room.make_available(reset));
        // The room for the device was reserved above.
        let published = added.and_then(|()| {
            devices
                .push_within_capacity(device.clone())
                .map_err(|_| ENOMEM)
        });
        if published.is_err() {
            drop(devices);
            device.stop();
        }
        published
    }

    /// Ends the use of the queues: no chain is made available on them any
    /// more, the reset ends the use of every chain by the device, and each
    /// chain goes back to the channel it belongs to.
    fn stop(&self) {
        for queue in &self.queues {
            queue.retire();
        }
        // SAFETY: the device is bound to this driver until it is removed. The
        // reset ends the callbacks, so none reads the driver data after it is
        // cleared.
        unsafe {
            generated::virtio_reset_device(self.vdev);
            generated::voidport_virtio_set_driver_data(self.vdev, core::ptr::null_mut());
        }
        for queue in &self.queues {
            queue.give_back_all();
        }
    }

    fn remove(&self) {
        self.stop();
        // SAFETY: the device uses no chain any more, and no task uses a queue
        // that is retired.
        unsafe { generated::voidport_virtio_del_vqs(self.vdev) };
    }
}

/// One connection of a session on a device: chains of one channel number,
/// and where the device returns them.
pub struct Channel {
    device: Arc<Device>,
    number: ChannelNumber,
    mailbox: Arc<Mailbox>,
}

impl Channel {
    /// A frame chain of this channel that contains `frame`, with `reply_len`
    /// bytes of reply area.
    pub fn frame(&self, frame: &[u8], reply_len: usize) -> Result<Chain> {
        self.new_chain(ChainKind::Frame, frame, reply_len)
    }

    fn new_chain(&self, kind: ChainKind, frame: &[u8], reply_len: usize) -> Result<Chain> {
        let id = self.mailbox.next_id();
        Chain::new(id, self.number, kind, frame, reply_len)
    }

    /// How many parts of data a chain of this channel can list besides a
    /// frame of `frame_len` bytes and a reply area of `reply_len` bytes.
    /// `EIO` when not even those fit a chain of the device.
    pub fn data_room(&self, frame_len: usize, reply_len: usize) -> Result<usize> {
        let fixed = Chain::fixed_descriptors(frame_len, reply_len);
        self.device.longest.checked_sub(fixed).ok_or(EIO)
    }

    /// Room on the queue of this CPU for a chain of `descriptors`, once the
    /// queue has enough free descriptors for it, with the wait given by
    /// `wait`. `EIO` for more descriptors than a chain of the device can use.
    pub fn room(&self, descriptors: usize, wait: Wait) -> Result<Room<'_>> {
        if descriptors > self.device.longest {
            return Err(EIO);
        }
        self.device
            .queue_here()
            .room(&self.mailbox, self.device.slots(descriptors), wait)
    }

    /// The next chain of this channel that the device returned, with the
    /// wait for one given by `wait`. `None` once the channel is shut and the
    /// device has returned every chain of it.
    pub fn next(&self, wait: Wait) -> Result<Option<Returned>> {
        self.mailbox.next(wait)
    }

    /// Ends the channel: no chain is made available on it any more, and
    /// [`Channel::next`] returns `None` once the device has returned every
    /// chain of it. The close chain follows the hello of the channel.
    pub fn shut(&self) {
        let Some(close) = self.mailbox.shut() else {
            return;
        };
        // A device being removed makes no chain available any more, and its
        // reset ends the channel.
        if let Ok(room) = self.room(close.descriptors(), Wait::Always) {
            room.add_close(close);
        }
    }
}

impl Drop for Channel {
    fn drop(&mut self) {
        self.shut();
    }
}
