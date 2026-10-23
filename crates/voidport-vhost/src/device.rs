//! What the device offers a frontend: what voidport's protocol needs and
//! nothing else. A queue is whatever index the frontend sets up, and its size is
//! the size the frontend gives.

use vhost::vhost_user::{VhostUserProtocolFeatures, VhostUserVirtioFeatures};
use virtio_bindings::virtio_config::VIRTIO_F_VERSION_1;
use virtio_bindings::virtio_ring::{VIRTIO_RING_F_EVENT_IDX, VIRTIO_RING_F_INDIRECT_DESC};

pub const FEATURES: u64 = (1 << VIRTIO_F_VERSION_1)
    | (1 << VIRTIO_RING_F_INDIRECT_DESC)
    | (1 << VIRTIO_RING_F_EVENT_IDX)
    | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();

pub const PROTOCOL_FEATURES: VhostUserProtocolFeatures =
    VhostUserProtocolFeatures::REPLY_ACK.union(VhostUserProtocolFeatures::INFLIGHT_SHMFD);

/// How many queues a frontend can set up: as many as a kick and a call can be
/// given for, since their messages give the queue in eight bits.
pub const QUEUES: u16 = 1 << u8::BITS;
