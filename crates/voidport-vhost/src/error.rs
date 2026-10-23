use std::io;

use vm_memory::GuestRegionCollectionError;
use vm_memory::mmap::MmapRegionError;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{regions} regions of guest memory came with {files} files")]
    UnpairedRegions { regions: usize, files: usize },
    #[error("the file of a region of guest memory cannot be mapped")]
    RegionFile(#[source] Unmappable),
    #[error("a region of guest memory could not be mapped")]
    MapRegion(#[source] MmapRegionError),
    #[error("a region of guest memory lies past the end of the address space")]
    RegionPastEnd,
    #[error("the regions of guest memory overlap")]
    CollectRegions(#[source] GuestRegionCollectionError),
    #[error("the size or the alignment of a queue is not one virtio allows")]
    Queue(#[source] virtio_queue::Error),
    #[error("a part of a queue lies outside the guest memory")]
    QueueOutsideMemory,
    #[error("the record of chains in flight could not be made")]
    CreateInflight(#[source] io::Error),
    #[error("a record of chains in flight was asked for queues the device cannot have")]
    InflightQueues,
    #[error("the record of chains in flight would lie past the end of the address space")]
    InflightPastEnd,
    #[error("the record of chains in flight is shorter than its queues")]
    InflightTooShort,
    #[error("the file of the record of chains in flight cannot be mapped")]
    InflightFile(#[source] Unmappable),
    #[error("the record of chains in flight could not be mapped")]
    MapInflight(#[source] MmapRegionError),
}

/// Why a file handed over by a frontend cannot be mapped safely. A mapping
/// past the end of its file raises `SIGBUS` at the first access there, which
/// ends the whole process.
#[derive(Debug, thiserror::Error)]
pub enum Unmappable {
    #[error("the size or the seals of the file could not be read")]
    Inspect(#[source] io::Error),
    #[error("the part to be mapped runs past the end of the file")]
    PastEnd,
    #[error("the memory file lacks the seal against shrinking")]
    Shrinkable,
}
