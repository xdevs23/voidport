use std::sync::atomic::Ordering;

use vhost::vhost_user::VhostUserVirtioFeatures;
use virtio_bindings::virtio_ring::VIRTIO_RING_F_EVENT_IDX;
use virtio_queue::{Queue, QueueT as _};
use vm_memory::{GuestAddress, GuestMemoryMmap};

use crate::Error;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Layout {
    pub descriptors: GuestAddress,
    pub available: GuestAddress,
    pub used: GuestAddress,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Features {
    /// The driver and the device each give the position at which they want
    /// to be signalled (`VIRTIO_RING_F_EVENT_IDX`).
    pub event_index: bool,
    /// A queue handles no chain until the frontend enables it
    /// (`VHOST_USER_F_PROTOCOL_FEATURES`).
    pub enables: bool,
}

impl Features {
    #[must_use]
    pub fn acked(acked: u64) -> Self {
        Self {
            event_index: acked & (1 << VIRTIO_RING_F_EVENT_IDX) != 0,
            enables: acked & VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits() != 0,
        }
    }
}

/// # Errors
///
/// [`Error::Queue`] for a size or an alignment virtio does not allow, and
/// [`Error::QueueOutsideMemory`] for a layout that does not lie in `memory`.
pub fn split(
    memory: &GuestMemoryMmap,
    size: u16,
    layout: Layout,
    features: Features,
    base: u16,
) -> Result<Queue, Error> {
    let mut queue = Queue::new(size).map_err(Error::Queue)?;
    queue
        .try_set_desc_table_address(layout.descriptors)
        .and_then(|()| queue.try_set_avail_ring_address(layout.available))
        .and_then(|()| queue.try_set_used_ring_address(layout.used))
        .map_err(Error::Queue)?;
    queue.set_event_idx(features.event_index);
    queue.set_ready(true);
    if !queue.is_valid(memory) {
        return Err(Error::QueueOutsideMemory);
    }
    queue.set_next_avail(base);
    let used = queue
        .used_idx(memory, Ordering::Acquire)
        .map_err(|_| Error::QueueOutsideMemory)?;
    queue.set_next_used(used.0);
    Ok(queue)
}
