//! The test is the frontend and the driver: it maps guest memory from a memfd,
//! sets up queues in it, lays descriptor chains out, kicks, and reads the used
//! ring. No virtual machine is involved.

use std::fs::File;
use std::os::fd::AsRawFd as _;
use std::os::unix::net::UnixStream;
use std::path::Path;

use rustix::fs::{MemfdFlags, OFlags, SealFlags, fcntl_add_seals, memfd_create};
use vhost::vhost_user::{
    Frontend, VhostUserFrontend as _, VhostUserProtocolFeatures, VhostUserVirtioFeatures,
};
use vhost::{VhostBackend as _, VhostUserMemoryRegionInfo, VringConfigData};
use virtio_bindings::virtio_config::VIRTIO_F_VERSION_1;
use virtio_bindings::virtio_ring::{
    VIRTIO_RING_F_EVENT_IDX, VIRTIO_RING_F_INDIRECT_DESC, VRING_DESC_F_INDIRECT, VRING_DESC_F_NEXT,
    VRING_DESC_F_WRITE,
};
use virtio_queue::desc::RawDescriptor;
use virtio_queue::desc::split::Descriptor;
use virtio_queue::mock::{MockSplitQueue, UsedRing};
use vm_memory::{Bytes as _, FileOffset, GuestAddress, GuestMemoryMmap};
use vmm_sys_util::eventfd::{EFD_NONBLOCK, EventFd};
use voidport_proto::chain::{ChainHead, ChainKind, ChannelNumber};
use voidport_proto::frame::{Frame, FrameWriter};
use voidport_proto::limits::LIMITS;
use voidport_proto::message::{Follows, RequestBody, RequestHead, ResponseBody, ResponseOutcome};
use voidport_proto::ops::file::{FileLock, OpenResponse, SetlkRequest, lock_type, setlk_flags};
use voidport_proto::ops::handshake::HelloRequest;
use voidport_proto::ops::node::{LookupRequest, LookupResponse};
use zerocopy::IntoBytes as _;
use zerocopy::byteorder::little_endian::{U32, U64};

use voidport_test_server::wire::{ROOT, open_request};

const MEMORY: usize = 4 << 20;
/// Where the test tells the backend the memory lies for the frontend,
/// which is not where the guest sees it: the device translates one into the
/// other by the region the frontend gave.
const FRONTEND_BASE: u64 = 0x7000_0000_0000;
pub const QUEUE_SIZE: u16 = 16;
const BUFFERS: u64 = 0x10_0000;
pub const REPLY_LEN: usize = 512;

pub const FEATURES: u64 =
    (1 << VIRTIO_F_VERSION_1) | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();
pub const EVENT_INDEX: u64 = 1 << VIRTIO_RING_F_EVENT_IDX;
pub const INDIRECT: u64 = 1 << VIRTIO_RING_F_INDIRECT_DESC;

/// What the device runs on. A wait for the device ends the test once it has
/// stopped.
pub trait Wait {
    fn until(&self, condition: &mut dyn FnMut() -> bool);
}

pub fn state_with_vhost_user(socket: &Path, tree: &Path) -> String {
    let document = serde_json::json!({
        "server": { "listeners": [{ "transport": "vhost-user", "path": socket }] },
        "namespaces": [{
            "name": "plain",
            "rules": [{ "path": "/tree", "mode": "rw", "target": tree }],
        }],
    });
    toml::to_string(&document).expect("a state document")
}

/// The guest memory, mapped from a memfd the frontend hands over, sealed
/// against shrinking as QEMU seals the memory of a guest.
pub fn guest_memory() -> (GuestMemoryMmap, File) {
    let file = File::from(
        memfd_create(
            "voidport-guest",
            MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
        )
        .expect("a memfd"),
    );
    file.set_len(MEMORY as u64)
        .expect("the memfd has its length");
    fcntl_add_seals(&file, SealFlags::SHRINK | SealFlags::GROW | SealFlags::SEAL)
        .expect("the memfd is sealed");
    let mapped = file.try_clone().expect("the memfd duplicates");
    let memory = GuestMemoryMmap::from_ranges_with_files([(
        GuestAddress(0),
        MEMORY,
        Some(FileOffset::new(mapped, 0)),
    )])
    .expect("the memory maps");
    (memory, file)
}

/// Where the position at which the driver wants to be signalled lies in the
/// available ring of `ring`: after the flags, the index and the entries.
fn used_event_address(ring: &MockSplitQueue<'_, GuestMemoryMmap>) -> GuestAddress {
    GuestAddress(ring.avail_addr().0 + 2 + 2 + 2 * u64::from(QUEUE_SIZE))
}

/// Where the used ring of the queue laid out by `ring` starts: past its
/// available ring, aligned as virtio aligns a used ring. The mock places its
/// own used ring as many bytes past the first available entry as the queue
/// has entries, which is over the second half of the available entries.
fn used_address(ring: &MockSplitQueue<'_, GuestMemoryMmap>) -> GuestAddress {
    GuestAddress((used_event_address(ring).0 + 2).next_multiple_of(4))
}

pub struct Queue<'m> {
    pub ring: MockSplitQueue<'m, GuestMemoryMmap>,
    used: UsedRing<'m, GuestMemoryMmap>,
    pub kick: EventFd,
    pub call: EventFd,
    next_descriptor: u16,
    seen: u16,
}

impl Queue<'_> {
    fn make_available(&self, head: u16) {
        let available = self.ring.avail().idx().load();
        self.ring
            .avail()
            .ring()
            .ref_at(usize::from(available % QUEUE_SIZE))
            .expect("the ring has room for it")
            .store(head);
        self.ring.avail().idx().store(available.wrapping_add(1));
        self.kick.write(1).expect("kicked");
    }
}

#[derive(Clone, Copy)]
pub struct Stretch {
    start: GuestAddress,
    len: usize,
}

pub struct Sent {
    pub head: u16,
    pub writable: Vec<Stretch>,
}

pub struct Device<'m> {
    pub frontend: Frontend,
    memory: &'m GuestMemoryMmap,
    pub queues: Vec<Queue<'m>>,
    /// Where the next buffer starts. Nothing frees a buffer, so a test that
    /// sends the same chain until it is answered sets this back.
    pub next_buffer: u64,
}

impl<'m> Device<'m> {
    pub fn set_up(
        stream: UnixStream,
        memory: &'m GuestMemoryMmap,
        file: &File,
        queues: u16,
        features: u64,
    ) -> Self {
        let mut frontend = Frontend::from_stream(stream, u64::from(queues));
        frontend.set_owner().expect("owned");
        let offered = frontend.get_features().expect("features");
        assert_eq!(
            offered & features,
            features,
            "the device offers {offered:#x}"
        );
        frontend.set_features(features).expect("features acked");
        let protocol = frontend.get_protocol_features().expect("protocol features");
        frontend
            .set_protocol_features(protocol & VhostUserProtocolFeatures::REPLY_ACK)
            .expect("protocol features acked");
        frontend
            .set_mem_table(&[VhostUserMemoryRegionInfo {
                guest_phys_addr: 0,
                memory_size: MEMORY as u64,
                userspace_addr: FRONTEND_BASE,
                mmap_offset: 0,
                mmap_handle: file.as_raw_fd(),
            }])
            .expect("the memory is accepted");
        let queues = (0..queues)
            .map(|index| {
                let ring = MockSplitQueue::create(
                    memory,
                    GuestAddress(0x1000 * (u64::from(index) + 1)),
                    QUEUE_SIZE,
                );
                let used = used_address(&ring);
                let queue = Queue {
                    ring,
                    used: UsedRing::new(memory, used, QUEUE_SIZE),
                    kick: EventFd::new(EFD_NONBLOCK).expect("an eventfd"),
                    call: EventFd::new(EFD_NONBLOCK).expect("an eventfd"),
                    next_descriptor: 0,
                    seen: 0,
                };
                let index = usize::from(index);
                frontend.set_vring_num(index, QUEUE_SIZE).expect("size");
                frontend
                    .set_vring_addr(
                        index,
                        &VringConfigData {
                            queue_max_size: QUEUE_SIZE,
                            queue_size: QUEUE_SIZE,
                            flags: 0,
                            desc_table_addr: FRONTEND_BASE + queue.ring.desc_table_addr().0,
                            used_ring_addr: FRONTEND_BASE + used.0,
                            avail_ring_addr: FRONTEND_BASE + queue.ring.avail_addr().0,
                            log_addr: None,
                        },
                    )
                    .expect("layout");
                frontend.set_vring_base(index, 0).expect("base");
                frontend.set_vring_call(index, &queue.call).expect("call");
                frontend.set_vring_kick(index, &queue.kick).expect("kick");
                frontend.set_vring_enable(index, true).expect("enabled");
                queue
            })
            .collect();
        Self {
            frontend,
            memory,
            queues,
            next_buffer: BUFFERS,
        }
    }

    fn buffer(&mut self, len: usize) -> GuestAddress {
        let start = GuestAddress(self.next_buffer);
        self.next_buffer += (len as u64).next_multiple_of(64);
        start
    }

    /// Makes a chain available on `queue` and kicks: `readable` cut into
    /// descriptors at `cuts`, then one write-only descriptor per length of
    /// `writable`.
    pub fn send(
        &mut self,
        queue: usize,
        readable: &[u8],
        cuts: &[usize],
        writable: &[usize],
    ) -> Sent {
        let (parts, writable) = self.parts(readable, cuts, writable);
        let queue = &mut self.queues[queue];
        let head = queue.next_descriptor;
        for (at, &(start, len, flags)) in parts.iter().enumerate() {
            let index = queue.next_descriptor;
            queue.next_descriptor = (index + 1) % QUEUE_SIZE;
            let next = if at + 1 == parts.len() {
                0
            } else {
                VRING_DESC_F_NEXT as u16
            };
            let descriptor = Descriptor::new(
                start.0,
                u32::try_from(len).expect("a short buffer"),
                flags | next,
                queue.next_descriptor,
            );
            queue
                .ring
                .desc_table()
                .store(index, RawDescriptor::from(descriptor))
                .expect("the table has room for it");
        }
        queue.make_available(head);
        Sent { head, writable }
    }

    pub fn send_indirect(
        &mut self,
        queue: usize,
        readable: &[u8],
        cuts: &[usize],
        writable: &[usize],
    ) -> Sent {
        let (parts, writable) = self.parts(readable, cuts, writable);
        let table_len = parts.len() * size_of::<RawDescriptor>();
        let table = self.buffer(table_len);
        for (at, &(start, len, flags)) in parts.iter().enumerate() {
            let next = if at + 1 == parts.len() {
                0
            } else {
                VRING_DESC_F_NEXT as u16
            };
            let descriptor = Descriptor::new(
                start.0,
                u32::try_from(len).expect("a short buffer"),
                flags | next,
                u16::try_from(at + 1).expect("a short table"),
            );
            self.memory
                .write_obj(
                    RawDescriptor::from(descriptor),
                    GuestAddress(table.0 + (at * size_of::<RawDescriptor>()) as u64),
                )
                .expect("the table is guest memory");
        }
        let queue = &mut self.queues[queue];
        let head = queue.next_descriptor;
        queue.next_descriptor = (head + 1) % QUEUE_SIZE;
        let descriptor = Descriptor::new(
            table.0,
            u32::try_from(table_len).expect("a short table"),
            VRING_DESC_F_INDIRECT as u16,
            0,
        );
        queue
            .ring
            .desc_table()
            .store(head, RawDescriptor::from(descriptor))
            .expect("the table has room for it");
        queue.make_available(head);
        Sent { head, writable }
    }

    /// The stretches of a chain, each with its start, its length and its
    /// flags: `readable` written to buffers cut at `cuts`, then one buffer
    /// per length of `writable`.
    fn parts(
        &mut self,
        readable: &[u8],
        cuts: &[usize],
        writable: &[usize],
    ) -> (Vec<(GuestAddress, usize, u16)>, Vec<Stretch>) {
        let mut parts = Vec::new();
        let mut from = 0;
        for &to in cuts.iter().chain([&readable.len()]) {
            let start = self.buffer(to - from);
            self.memory
                .write_slice(&readable[from..to], start)
                .expect("the buffer is guest memory");
            parts.push((start, to - from, 0));
            from = to;
        }
        let writable: Vec<Stretch> = writable
            .iter()
            .map(|&len| Stretch {
                start: self.buffer(len),
                len,
            })
            .collect();
        parts.extend(
            writable
                .iter()
                .map(|stretch| (stretch.start, stretch.len, VRING_DESC_F_WRITE as u16)),
        );
        (parts, writable)
    }

    /// Asks the device of `queue` to signal the driver once the index of the
    /// used ring has passed `position`, which only a device that negotiated
    /// event indices reads.
    pub fn signal_after(&self, queue: usize, position: u16) {
        let ring = &self.queues[queue].ring;
        self.memory
            .write_obj(position, used_event_address(ring))
            .expect("the ring is guest memory");
    }

    /// Stops queue `index` as QEMU stops a queue whose virtual machine
    /// pauses, and starts it again where it stopped, as QEMU does when the
    /// machine resumes. Returns the position the device gave.
    pub fn restart_queue(&mut self, index: usize) -> u16 {
        let position = self
            .frontend
            .get_vring_base(index)
            .expect("the queue stops");
        let position = u16::try_from(position).expect("a position of a split queue");
        let queue = &self.queues[index];
        self.frontend.set_vring_base(index, position).expect("base");
        self.frontend
            .set_vring_call(index, &queue.call)
            .expect("call");
        self.frontend
            .set_vring_kick(index, &queue.kick)
            .expect("kick");
        self.frontend
            .set_vring_enable(index, true)
            .expect("enabled");
        position
    }

    pub fn finished(&mut self, wait: &impl Wait, queue: usize) -> (u16, usize) {
        let queue = &mut self.queues[queue];
        let used = &queue.used;
        wait.until(&mut || used.idx().load() != queue.seen);
        let element = used
            .ring()
            .ref_at(usize::from(queue.seen % QUEUE_SIZE))
            .expect("the ring has room for it")
            .load();
        queue.seen = queue.seen.wrapping_add(1);
        (
            u16::try_from(element.id()).expect("a head"),
            element.len() as usize,
        )
    }

    /// Returns once the device has pulled every chain made available on
    /// `queue` so far. The device pulls the chains of a queue in order, so
    /// the close of a channel that is never opened, made available after
    /// them, finishes only once they have been pulled.
    pub fn fence(&mut self, wait: &impl Wait, queue: usize) {
        let readable = ChainHead::new(ChannelNumber(u64::MAX), ChainKind::Close, 0)
            .as_bytes()
            .to_vec();
        let sent = self.send(queue, &readable, &[], &[]);
        assert_eq!(self.finished(wait, queue), (sent.head, 0));
    }

    pub fn exchange(
        &mut self,
        wait: &impl Wait,
        queue: usize,
        channel: u64,
        frame: &[u8],
        cuts: &[usize],
        writable: &[usize],
    ) -> Vec<u8> {
        let sent = self.send_frame(queue, channel, frame, cuts, writable);
        let (head, written) = self.finished(wait, queue);
        assert_eq!(head, sent.head, "the chain sent is the chain finished");
        self.written(&sent.writable, written)
    }

    pub fn send_frame(
        &mut self,
        queue: usize,
        channel: u64,
        frame: &[u8],
        cuts: &[usize],
        writable: &[usize],
    ) -> Sent {
        let readable = frame_chain(channel, frame, writable[0]);
        self.send(queue, &readable, cuts, writable)
    }

    pub fn written(&self, stretches: &[Stretch], len: usize) -> Vec<u8> {
        let mut bytes = Vec::new();
        for stretch in stretches {
            let take = stretch.len.min(len - bytes.len());
            let mut part = vec![0u8; take];
            self.memory
                .read_slice(&mut part, stretch.start)
                .expect("the buffer is guest memory");
            bytes.extend_from_slice(&part);
        }
        bytes
    }
}

pub fn frame_chain(channel: u64, frame: &[u8], reply_len: usize) -> Vec<u8> {
    let reply_len = u32::try_from(reply_len).expect("a short reply area");
    let mut readable = ChainHead::new(ChannelNumber(channel), ChainKind::Frame, reply_len)
        .as_bytes()
        .to_vec();
    readable.extend_from_slice(frame);
    readable
}

pub fn frame<M: RequestBody>(request_id: u64, node_id: u64, body: &M, payload: &[u8]) -> Vec<u8> {
    let data = matches!(body.follows(), Follows::Data(_));
    let mut buffer = vec![0u8; FrameWriter::request_len::<M>(payload.len())];
    let mut writer = FrameWriter::request(
        &mut buffer,
        &LIMITS,
        request_id,
        &RequestHead::new(node_id, 0, 0, 0),
        body,
    )
    .expect("encodable");
    if !data {
        writer.payload(payload).expect("fits");
    }
    let mut bytes = writer.finish().expect("whole").to_vec();
    if data {
        bytes.extend_from_slice(payload);
    }
    bytes
}

pub fn body<R: ResponseBody + Copy>(bytes: &[u8]) -> R {
    match Frame::parse(bytes, &LIMITS)
        .expect("a well-framed reply")
        .response::<R>()
        .expect("a valid reply")
    {
        ResponseOutcome::Success(response) => *response.body(),
        ResponseOutcome::Error(status) => panic!("the server replied {status}"),
    }
}

pub fn hello(request_id: u64) -> Vec<u8> {
    frame(request_id, 0, &HelloRequest::new(5, 0), b"plain")
}

fn lookup(request_id: u64, parent: u64, name: &str) -> Vec<u8> {
    let name_len = U32::new(u32::try_from(name.len()).expect("a short name"));
    frame(
        request_id,
        parent,
        &LookupRequest { name_len },
        name.as_bytes(),
    )
}

pub fn open(device: &mut Device<'_>, wait: &impl Wait, channel: u64, name: &str) -> (u64, u64) {
    let reply = device.exchange(wait, 0, channel, &hello(1), &[], &[REPLY_LEN]);
    assert_eq!(
        Frame::parse(&reply, &LIMITS).expect("a reply").status(),
        Ok(0)
    );
    let reply = device.exchange(
        wait,
        0,
        channel,
        &lookup(2, ROOT, "tree"),
        &[],
        &[REPLY_LEN],
    );
    let tree = body::<LookupResponse>(&reply).entry.node_id.get();
    let reply = device.exchange(wait, 0, channel, &lookup(3, tree, name), &[], &[REPLY_LEN]);
    let node = body::<LookupResponse>(&reply).entry.node_id.get();
    let open = open_request(OFlags::RDWR);
    let reply = device.exchange(
        wait,
        0,
        channel,
        &frame(4, node, &open, &[]),
        &[],
        &[REPLY_LEN],
    );
    (body::<OpenResponse>(&reply).handle.get(), node)
}

pub fn lock(request_id: u64, node: u64, handle: u64, owner: u64, wait: bool) -> Vec<u8> {
    let flags = if wait { setlk_flags::WAIT } else { 0 };
    let lock = FileLock {
        start: U64::ZERO,
        end: U64::new(u64::MAX),
        owner: U64::new(owner),
        pid: U32::ZERO,
        lock_type: U32::new(lock_type::WRITE),
    };
    frame(
        request_id,
        node,
        &SetlkRequest {
            handle: U64::new(handle),
            lock,
            flags: U32::new(flags),
            reserved: U32::ZERO,
        },
        &[],
    )
}
