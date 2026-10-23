//! One queue of the device, as QEMU set it up, and as the keeper runs it while
//! voidportd is away. The keeper puts every chain back with nothing written into
//! it, which to the driver of the guest is a chain whose channel is not open, so
//! the session on the channel has ended as over a lost connection. The chains
//! voidportd had in flight are put back first, in the order in which it pulled
//! them.

use std::fs::File;
use std::sync::Arc;

use vhost::vhost_user::{Frontend, VhostUserFrontend as _};
use vhost::{VhostBackend as _, VringConfigData};
use virtio_queue::{Queue, QueueOwnedT as _, QueueT as _};
use vm_memory::GuestMemoryMmap;
use voidport_vhost::backend::Address;
use voidport_vhost::eventfd;
use voidport_vhost::inflight::Inflight;
use voidport_vhost::queue::{self, Features};

use crate::memory::Memory;
use crate::server::{HandOverError, eventfd_of};

#[derive(Debug, thiserror::Error)]
pub(crate) enum Broken {
    #[error("the queue does not lie in the guest memory")]
    Setup(#[from] voidport_vhost::Error),
    #[error("the driver broke the rings of the queue")]
    Rings(#[from] virtio_queue::Error),
    #[error("the queue was started before its size and address were set")]
    Unset,
}

#[derive(Debug, Default)]
pub(crate) struct Ring {
    size: Option<u16>,
    address: Option<Address>,
    base: u16,
    kick: Option<File>,
    call: Option<File>,
    err: Option<File>,
    enabled: bool,
    tracked_in: Option<Arc<Inflight>>,
    served: Option<Queue>,
}

impl Ring {
    pub(crate) fn size(&self) -> Option<u16> {
        self.size
    }

    pub(crate) fn set_size(&mut self, size: u16) {
        self.size = Some(size);
    }

    pub(crate) fn set_address(&mut self, address: Address, memory: &Memory) -> bool {
        if address.layout(memory.translations()).is_none() {
            return false;
        }
        self.address = Some(address);
        true
    }

    pub(crate) fn config(&self) -> Option<VringConfigData> {
        let size = self.size.unwrap_or_default();
        self.address.map(|address| VringConfigData {
            queue_max_size: size,
            queue_size: size,
            flags: address.flags,
            desc_table_addr: address.descriptors,
            used_ring_addr: address.used,
            avail_ring_addr: address.available,
            log_addr: Some(address.log),
        })
    }

    pub(crate) fn set_base(&mut self, base: u16) {
        self.base = base;
    }

    pub(crate) fn set_call(&mut self, call: Option<File>) {
        self.call = call;
    }

    pub(crate) fn set_err(&mut self, err: Option<File>) {
        self.err = err;
    }

    pub(crate) fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    pub(crate) fn served_kick(&self) -> Option<&File> {
        self.served.as_ref().and(self.kick.as_ref())
    }

    pub(crate) fn started(&self) -> bool {
        self.kick.is_some()
    }

    /// Starts the queue with `kick`, in `memory`. The keeper runs it from
    /// now on unless `handed` is set, since voidportd runs it then.
    pub(crate) fn start(
        &mut self,
        kick: File,
        memory: &Memory,
        features: Features,
        handed: bool,
    ) -> Result<(), Broken> {
        let queue = self
            .queue(memory, features, self.base)
            .ok_or(Broken::Unset)??;
        self.kick = Some(kick);
        if !handed && self.served.is_none() {
            self.served = Some(queue);
        }
        Ok(())
    }

    pub(crate) fn track_in(&mut self, record: &Arc<Inflight>) {
        self.tracked_in = Some(Arc::clone(record));
    }

    pub(crate) fn release(&mut self, index: u8) {
        if let Some(slot) = self.slot(index) {
            slot.release();
        }
        self.tracked_in = None;
    }

    pub(crate) fn stop(&mut self) -> u16 {
        if let Some(queue) = self.served.take() {
            self.base = queue.next_avail();
        }
        self.kick = None;
        self.call = None;
        self.enabled = false;
        self.base
    }

    pub(crate) fn break_off(&mut self) {
        let _position = self.stop();
    }

    pub(crate) fn replay(
        &mut self,
        index: u8,
        frontend: &mut Frontend,
        record: Option<&Arc<Inflight>>,
    ) -> Result<(), HandOverError> {
        let at = usize::from(index);
        if let Some(size) = self.size {
            frontend.set_vring_num(at, size)?;
            if let Some(config) = self.config() {
                frontend.set_vring_addr(at, &config)?;
            }
        }
        let base = self.served.as_ref().map_or(self.base, Queue::next_avail);
        frontend.set_vring_base(at, base)?;
        if let Some(call) = &self.call {
            frontend.set_vring_call(at, &eventfd_of(call)?)?;
        }
        if let Some(err) = &self.err {
            frontend.set_vring_err(at, &eventfd_of(err)?)?;
        }
        if let Some(kick) = &self.kick {
            frontend.set_vring_kick(at, &eventfd_of(kick)?)?;
            self.tracked_in = record.cloned();
        }
        if self.enabled {
            frontend.set_vring_enable(at, true)?;
        }
        Ok(())
    }

    pub(crate) fn handed_over(&mut self) {
        if let Some(queue) = self.served.take() {
            self.base = queue.next_avail();
        }
    }

    /// Takes the started queue at `index` over from voidportd, which has
    /// gone: puts back with nothing written every chain that the record
    /// shows voidportd pulled and did not put back, and runs the queue from
    /// after them. A queue voidportd did not track goes on from where the
    /// keeper or QEMU left it.
    ///
    /// # Errors
    ///
    /// [`Broken`] when the queue does not lie in `memory` or the driver broke
    /// its rings.
    pub(crate) fn take_over(
        &mut self,
        index: u8,
        memory: &Memory,
        features: Features,
    ) -> Result<(), Broken> {
        if self.kick.is_none() {
            return Ok(());
        }
        let Some(queue) = self.queue(memory, features, self.base) else {
            return Ok(());
        };
        let mut queue = queue?;
        let used = queue.next_used();
        let slot = self.slot(index);
        let Some(heads) = slot.as_ref().and_then(|slot| slot.in_flight(used)) else {
            if self.served.is_none() {
                self.served = Some(queue);
            }
            return Ok(());
        };
        // Every chain voidportd pulled is on the used ring or still in
        // flight, so the next chain to pull follows them.
        queue.set_next_avail(
            heads
                .iter()
                .fold(used, |position, _| position.wrapping_add(1)),
        );
        for &head in &heads {
            queue.add_used(memory.mapped(), head, 0)?;
        }
        if !heads.is_empty() && queue.needs_notification(memory.mapped())? {
            self.signal();
        }
        if let Some(slot) = slot {
            slot.release();
        }
        self.tracked_in = None;
        self.served = Some(queue);
        Ok(())
    }

    pub(crate) fn serve(&mut self, memory: &GuestMemoryMmap, enables: bool) -> Result<(), Broken> {
        let Some(queue) = &mut self.served else {
            return Ok(());
        };
        if enables && !self.enabled {
            return Ok(());
        }
        if let Some(kick) = &self.kick
            && let Err(error) = eventfd::drain(kick)
        {
            tracing::warn!(%error, "the kicks of a queue cannot be read");
        }
        let mut finished = false;
        loop {
            queue.disable_notification(memory)?;
            let heads: Vec<u16> = queue
                .iter(memory)?
                .map(|chain| chain.head_index())
                .collect();
            for &head in &heads {
                queue.add_used(memory, head, 0)?;
            }
            finished |= !heads.is_empty();
            if !queue.enable_notification(memory)? {
                break;
            }
        }
        if finished && queue.needs_notification(memory)? {
            self.signal();
        }
        Ok(())
    }

    fn queue(
        &self,
        memory: &Memory,
        features: Features,
        base: u16,
    ) -> Option<Result<Queue, voidport_vhost::Error>> {
        let size = self.size?;
        let layout = self.address?.layout(memory.translations())?;
        Some(queue::split(memory.mapped(), size, layout, features, base))
    }

    fn slot(&self, index: u8) -> Option<voidport_vhost::inflight::Slot> {
        let record = self.tracked_in.as_ref()?;
        record.slot(u32::from(index), self.size?)
    }

    fn signal(&self) {
        if let Some(call) = &self.call
            && let Err(error) = eventfd::signal(call)
        {
            tracing::warn!(%error, "the driver could not be signalled");
        }
    }
}

#[cfg(test)]
mod tests {
    use rustix::event::{EventfdFlags, eventfd};
    use rustix::fs::{MemfdFlags, SealFlags, fcntl_add_seals, memfd_create};
    use vhost::vhost_user::message::VhostUserMemoryRegion;
    use virtio_bindings::virtio_ring::VRING_DESC_F_WRITE;
    use virtio_queue::desc::RawDescriptor;
    use virtio_queue::desc::split::Descriptor;
    use virtio_queue::mock::{MockSplitQueue, UsedRing};
    use vm_memory::GuestAddress;

    use super::*;
    use crate::record::Record;

    const SIZE: u16 = 8;
    const MEMORY: u64 = 0x10_0000;
    const USED: u64 = 0x1000;

    fn memory() -> Memory {
        let file = File::from(
            memfd_create("voidport-keeper-test", MemfdFlags::ALLOW_SEALING).expect("a memfd"),
        );
        file.set_len(MEMORY).expect("the memfd has its length");
        fcntl_add_seals(&file, SealFlags::SHRINK).expect("the memfd is sealed");
        Memory::map(&[VhostUserMemoryRegion::new(0, MEMORY, 0, 0)], vec![file])
            .expect("the memory maps")
    }

    fn make_available(queue: &MockSplitQueue<'_, GuestMemoryMmap>, heads: &[u16]) {
        for &head in heads {
            let descriptor = Descriptor::new(
                0x2000 + 0x100 * u64::from(head),
                0x100,
                VRING_DESC_F_WRITE as u16,
                0,
            );
            queue
                .desc_table()
                .store(head, RawDescriptor::from(descriptor))
                .expect("the table has room for it");
            let available = queue.avail().idx().load();
            queue
                .avail()
                .ring()
                .ref_at(usize::from(available % SIZE))
                .expect("the ring has room for it")
                .store(head);
            queue.avail().idx().store(available.wrapping_add(1));
        }
    }

    #[test]
    fn a_take_over_puts_back_the_chains_in_flight_and_goes_on_after_them() {
        let memory = memory();
        let queue = MockSplitQueue::create(memory.mapped(), GuestAddress(0), SIZE);
        let used = UsedRing::new(memory.mapped(), GuestAddress(USED), SIZE);
        let record = Record::create(1, SIZE).expect("a record");
        let mut ring = Ring::default();
        ring.set_size(SIZE);
        let address = Address {
            flags: 0,
            descriptors: queue.desc_table_addr().0,
            used: USED,
            available: queue.avail_addr().0,
            log: 0,
        };
        assert!(ring.set_address(address, &memory));
        let kick = File::from(eventfd(0, EventfdFlags::NONBLOCK).expect("an eventfd"));
        ring.start(kick, &memory, Features::default(), true)
            .expect("the queue starts");
        ring.track_in(record.inflight());

        // voidportd pulls 5, 2 and 7, and puts back 2.
        let layout = address
            .layout(memory.translations())
            .expect("the queue lies in the memory");
        let mut voidportd =
            queue::split(memory.mapped(), SIZE, layout, Features::default(), 0).expect("a queue");
        let mut slot = record.inflight().slot(0, SIZE).expect("a slot");
        slot.start(0);
        make_available(&queue, &[5, 2, 7]);
        let pulled: Vec<u16> = voidportd
            .iter(memory.mapped())
            .expect("the rings are intact")
            .map(|chain| chain.head_index())
            .collect();
        for &head in &pulled {
            slot.take(head);
        }
        slot.finishing(2);
        voidportd
            .add_used(memory.mapped(), 2, 0x10)
            .expect("the chain is put back");
        slot.finished(2, voidportd.next_used());

        ring.take_over(0, &memory, Features::default())
            .expect("the queue is taken over");
        make_available(&queue, &[3]);
        ring.serve(memory.mapped(), false)
            .expect("the queue is run");
        ring.serve(memory.mapped(), false)
            .expect("the queue is run");

        let finished: Vec<(u32, u32)> = (0..used.idx().load())
            .map(|at| {
                let element = used
                    .ring()
                    .ref_at(usize::from(at))
                    .expect("an entry")
                    .load();
                (element.id(), element.len())
            })
            .collect();
        assert_eq!(finished, [(2, 0x10), (5, 0), (7, 0), (3, 0)]);
        assert_eq!(slot.in_flight(4), None, "no backend tracks the queue");
    }
}
