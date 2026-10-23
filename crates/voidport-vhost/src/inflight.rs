//! The record of the chains a backend has in flight, in memory shared by the
//! frontend and the backend (`INFLIGHT_SHMFD`): one slot per queue, laid out for
//! split queues as a header, then one entry per descriptor. The record is one
//! memory file sealed against shrinking, and a slot whose header gives no
//! descriptors is one no backend tracks.
//!
//! The backend marks the entry of the head of a chain when it pulls the chain
//! off the available ring. To put a chain back it links the head into the last
//! batch, publishes the chain on the used ring, unmarks the entry and stores the
//! index of the used ring in the header. Whoever reads the slot after the
//! backend is gone first unmarks the last batch when the used ring went further
//! than the header shows. The entries still marked then are the chains the
//! backend pulled and never put back, and their counters give the order in which
//! it pulled them. A chain pulled without being marked yet is pulled again from
//! the available ring, so the position of the reader is the used index plus the
//! chains still marked.

use std::fs::File;
use std::mem::{offset_of, size_of};
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU16, AtomicU64, Ordering};

use rustix::fs::{MemfdFlags, SealFlags, fcntl_add_seals, memfd_create};
use vhost::vhost_user::message::{DescStateSplit, QueueRegionSplit, VhostUserInflight};
use virtio_queue::{Queue, QueueT as _};
use vm_memory::{AtomicInteger, FileOffset, MmapRegion, VolatileMemory as _};

use crate::Error;
use crate::device::QUEUES;
use crate::memory::mappable;

const HEADER: usize = offset_of!(QueueRegionSplit, desc);
const ENTRY: usize = size_of::<DescStateSplit>();
const VERSION: u16 = 1;

fn slot_len(queue_size: u16) -> usize {
    HEADER + ENTRY * usize::from(queue_size)
}

#[derive(Debug)]
pub struct Inflight {
    region: MmapRegion,
    queues: u16,
    queue_size: u16,
}

impl Inflight {
    /// The pages of the file are allocated where they are written, so a slot
    /// costs memory only once a queue uses it.
    ///
    /// # Errors
    ///
    /// [`Error::InflightQueues`] for more queues than a frontend can set up
    /// or a size no split queue can have, [`Error::CreateInflight`] when the
    /// file cannot be made, and [`Error::MapInflight`] when it cannot be
    /// mapped.
    pub fn create(queues: u16, queue_size: u16) -> Result<(Self, VhostUserInflight, File), Error> {
        if queues > QUEUES || Queue::new(queue_size).is_err() {
            return Err(Error::InflightQueues);
        }
        let len = usize::from(queues) * slot_len(queue_size);
        let file = File::from(
            memfd_create(
                "voidport-inflight",
                MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
            )
            .map_err(|errno| Error::CreateInflight(errno.into()))?,
        );
        let size = u64::try_from(len).map_err(|_| Error::InflightPastEnd)?;
        file.set_len(size).map_err(Error::CreateInflight)?;
        fcntl_add_seals(&file, SealFlags::SHRINK | SealFlags::GROW | SealFlags::SEAL)
            .map_err(|errno| Error::CreateInflight(errno.into()))?;
        let description = VhostUserInflight::new(size, 0, queues, queue_size);
        let mapped = file.try_clone().map_err(Error::CreateInflight)?;
        Ok((Self::map(&description, mapped)?, description, file))
    }

    /// # Errors
    ///
    /// [`Error::InflightTooShort`] when the description gives less memory
    /// than its queues need, [`Error::InflightFile`] when that memory runs
    /// past the end of the file or the file can still shrink, and
    /// [`Error::MapInflight`] when the file cannot be mapped.
    pub fn map(description: &VhostUserInflight, file: File) -> Result<Self, Error> {
        let (queues, queue_size) = (description.num_queues, description.queue_size);
        let len = usize::from(queues) * slot_len(queue_size);
        let len_u64 = u64::try_from(len).map_err(|_| Error::InflightPastEnd)?;
        if len_u64 > description.mmap_size {
            return Err(Error::InflightTooShort);
        }
        mappable(&file, description.mmap_offset, len_u64).map_err(Error::InflightFile)?;
        let region = MmapRegion::from_file(FileOffset::new(file, description.mmap_offset), len)
            .map_err(Error::MapInflight)?;
        Ok(Self {
            region,
            queues,
            queue_size,
        })
    }

    #[must_use]
    pub fn slot(self: &Arc<Self>, index: u32, size: u16) -> Option<Slot> {
        if index >= u32::from(self.queues) || size > self.queue_size {
            return None;
        }
        let start = usize::try_from(index).ok()? * slot_len(self.queue_size);
        Some(Slot {
            record: Arc::clone(self),
            start,
            size,
            counter: 0,
        })
    }

    fn field<T: AtomicInteger>(&self, at: usize) -> &T {
        self.region
            .get_atomic_ref::<T>(at)
            .expect("a slot lies inside the record, and its fields are aligned")
    }
}

#[derive(Debug)]
pub struct Slot {
    record: Arc<Inflight>,
    start: usize,
    size: u16,
    counter: u64,
}

impl Slot {
    pub fn start(&mut self, used: u16) {
        for head in 0..self.size {
            self.inflight(head).store(0, Ordering::Relaxed);
        }
        self.counter = 0;
        self.header::<AtomicU64>(offset_of!(QueueRegionSplit, features))
            .store(0, Ordering::Relaxed);
        self.header::<AtomicU16>(offset_of!(QueueRegionSplit, version))
            .store(VERSION, Ordering::Relaxed);
        self.last_batch_head().store(0, Ordering::Relaxed);
        self.used_idx().store(used, Ordering::Relaxed);
        self.descriptors().store(self.size, Ordering::Release);
    }

    pub fn release(&self) {
        self.descriptors().store(0, Ordering::Release);
    }

    /// # Panics
    ///
    /// When `head` is past the queue. The queue checks every head it lets
    /// through.
    pub fn take(&mut self, head: u16) {
        self.check(head);
        self.counter += 1;
        self.entry::<AtomicU64>(head, offset_of!(DescStateSplit, counter))
            .store(self.counter, Ordering::Relaxed);
        self.inflight(head).store(1, Ordering::Release);
    }

    /// Links the chain at `head` into the batch about to be put back, before
    /// the used ring shows the chain.
    ///
    /// # Panics
    ///
    /// As [`Self::take`].
    pub fn finishing(&self, head: u16) {
        self.check(head);
        let last = self.last_batch_head().load(Ordering::Relaxed);
        self.next(head).store(last, Ordering::Relaxed);
        self.last_batch_head().store(head, Ordering::Release);
    }

    /// # Panics
    ///
    /// As [`Self::take`].
    pub fn finished(&self, head: u16, used: u16) {
        self.check(head);
        self.inflight(head).store(0, Ordering::Release);
        self.used_idx().store(used, Ordering::Release);
    }

    /// The chains a backend pulled and did not put back, in the order in which
    /// it pulled them, given that the index of the used ring is at `used`; or
    /// `None` when no backend tracks the queue. A chain the used ring shows
    /// is unmarked first.
    #[must_use]
    pub fn in_flight(&self, used: u16) -> Option<Vec<u16>> {
        let tracked = self.descriptors().load(Ordering::Acquire).min(self.size);
        if tracked == 0 {
            return None;
        }
        let recorded = self.used_idx().load(Ordering::Acquire);
        let mut head = self.last_batch_head().load(Ordering::Acquire);
        for _ in 0..used.wrapping_sub(recorded) {
            if head >= tracked {
                break;
            }
            self.inflight(head).store(0, Ordering::Relaxed);
            head = self.next(head).load(Ordering::Relaxed);
        }
        self.used_idx().store(used, Ordering::Release);
        let mut heads: Vec<(u64, u16)> = (0..tracked)
            .filter(|&head| self.inflight(head).load(Ordering::Acquire) != 0)
            .map(|head| {
                let counter = self.entry::<AtomicU64>(head, offset_of!(DescStateSplit, counter));
                (counter.load(Ordering::Relaxed), head)
            })
            .collect();
        heads.sort_unstable();
        Some(heads.into_iter().map(|(_, head)| head).collect())
    }

    fn check(&self, head: u16) {
        assert!(
            head < self.size,
            "head {head} of a queue of {} descriptors",
            self.size
        );
    }

    fn header<T: AtomicInteger>(&self, field: usize) -> &T {
        self.record.field(self.start + field)
    }

    fn entry<T: AtomicInteger>(&self, head: u16, field: usize) -> &T {
        self.record
            .field(self.start + HEADER + ENTRY * usize::from(head) + field)
    }

    fn descriptors(&self) -> &AtomicU16 {
        self.header(offset_of!(QueueRegionSplit, desc_num))
    }

    fn last_batch_head(&self) -> &AtomicU16 {
        self.header(offset_of!(QueueRegionSplit, last_batch_head))
    }

    fn used_idx(&self) -> &AtomicU16 {
        self.header(offset_of!(QueueRegionSplit, used_idx))
    }

    fn inflight(&self, head: u16) -> &AtomicU8 {
        self.entry(head, offset_of!(DescStateSplit, inflight))
    }

    fn next(&self, head: u16) -> &AtomicU16 {
        self.entry(head, offset_of!(DescStateSplit, next))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Unmappable;

    fn slot(size: u16) -> Slot {
        let (record, _, _) = Inflight::create(2, size).expect("a record");
        Arc::new(record).slot(1, size).expect("a slot")
    }

    #[test]
    fn a_slot_no_backend_tracks_has_nothing_in_flight() {
        let mut slot = slot(8);
        assert_eq!(slot.in_flight(5), None);
        slot.start(5);
        slot.take(3);
        slot.release();
        assert_eq!(slot.in_flight(5), None);
    }

    #[test]
    fn the_chains_in_flight_are_those_pulled_and_not_put_back_in_that_order() {
        let mut slot = slot(8);
        slot.start(10);
        for head in [6, 2, 4, 0] {
            slot.take(head);
        }
        slot.finishing(4);
        slot.finished(4, 11);
        assert_eq!(slot.in_flight(11), Some(vec![6, 2, 0]));
    }

    #[test]
    fn a_chain_published_but_not_unmarked_is_not_in_flight() {
        let mut slot = slot(8);
        slot.start(u16::MAX);
        slot.take(1);
        slot.take(7);
        slot.finishing(7);
        assert_eq!(slot.in_flight(0), Some(vec![1]));
        assert_eq!(slot.in_flight(0), Some(vec![1]));
    }

    #[test]
    fn a_queue_past_the_record_has_no_slot_in_it() {
        let (record, _, _) = Inflight::create(2, 8).expect("a record");
        let record = Arc::new(record);
        assert!(record.slot(2, 8).is_none());
        assert!(record.slot(0, 16).is_none());
        assert!(record.slot(1, 4).is_some());
        for (queues, queue_size) in [(QUEUES + 1, 8), (2, 12), (2, 0)] {
            assert!(matches!(
                Inflight::create(queues, queue_size),
                Err(Error::InflightQueues)
            ));
        }
    }

    #[test]
    #[should_panic(expected = "head 4 of a queue of 4 descriptors")]
    fn a_head_past_the_queue_is_never_marked() {
        let (record, _, _) = Inflight::create(1, 8).expect("a record");
        let mut slot = Arc::new(record).slot(0, 4).expect("a slot");
        slot.start(0);
        slot.take(4);
    }

    #[test]
    fn a_description_that_does_not_fit_its_queues_or_its_file_is_refused() {
        let (_, mut description, file) = Inflight::create(2, 8).expect("a record");
        description.num_queues = 3;
        let duplicate = file.try_clone().expect("the file duplicates");
        assert!(matches!(
            Inflight::map(&description, duplicate),
            Err(Error::InflightTooShort)
        ));
        description.num_queues = 2;
        description.mmap_size += 1;
        description.mmap_offset = 1;
        assert!(matches!(
            Inflight::map(&description, file),
            Err(Error::InflightFile(Unmappable::PastEnd))
        ));
        let unsealed =
            File::from(memfd_create("voidport-test", MemfdFlags::CLOEXEC).expect("a memfd"));
        unsealed.set_len(4096).expect("the memfd takes its length");
        let description = VhostUserInflight::new(4096, 0, 1, 8);
        assert!(matches!(
            Inflight::map(&description, unsealed),
            Err(Error::InflightFile(Unmappable::Shrinkable))
        ));
    }
}
