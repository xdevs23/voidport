//! The addresses of the queues come as addresses in the frontend, so a region
//! is mapped together with its translation into guest addresses.

use std::fs::File;

use rustix::fs::{SealFlags, fcntl_get_seals};
use rustix::io::Errno;
use vhost::vhost_user::message::VhostUserMemoryRegion;
use vm_memory::{FileOffset, GuestAddress, GuestMemoryMmap, GuestRegionMmap, MmapRegion};

use crate::{Error, Unmappable};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Translation {
    frontend: u64,
    guest: u64,
    size: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Translations(Vec<Translation>);

impl Translations {
    #[must_use]
    pub fn guest_address(&self, frontend: u64) -> Option<GuestAddress> {
        self.0
            .iter()
            .find(|region| {
                frontend
                    .checked_sub(region.frontend)
                    .is_some_and(|into| into < region.size)
            })
            .map(|region| GuestAddress(frontend - region.frontend + region.guest))
    }
}

/// # Errors
///
/// [`Error`] when a region has no file, runs past the end of its file or lies
/// in a memory file that can still shrink, cannot be mapped, or overlaps
/// another.
pub fn map(
    regions: &[VhostUserMemoryRegion],
    files: Vec<File>,
) -> Result<(GuestMemoryMmap, Translations), Error> {
    if regions.len() != files.len() {
        return Err(Error::UnpairedRegions {
            regions: regions.len(),
            files: files.len(),
        });
    }
    // The memory expects its regions in the order of their guest addresses,
    // which the frontend does not promise.
    let mut given: Vec<(&VhostUserMemoryRegion, File)> = regions.iter().zip(files).collect();
    given.sort_by_key(|(region, _)| region.guest_phys_addr);
    let mut mapped = Vec::with_capacity(given.len());
    let mut translations = Vec::with_capacity(given.len());
    for (region, file) in given {
        mappable(&file, region.mmap_offset, region.memory_size).map_err(Error::RegionFile)?;
        let size = usize::try_from(region.memory_size).map_err(|_| Error::RegionPastEnd)?;
        let mapping = MmapRegion::from_file(FileOffset::new(file, region.mmap_offset), size)
            .map_err(Error::MapRegion)?;
        mapped.push(
            GuestRegionMmap::new(mapping, GuestAddress(region.guest_phys_addr))
                .ok_or(Error::RegionPastEnd)?,
        );
        translations.push(Translation {
            frontend: region.user_addr,
            guest: region.guest_phys_addr,
            size: region.memory_size,
        });
    }
    let memory = GuestMemoryMmap::from_regions(mapped).map_err(Error::CollectRegions)?;
    Ok((memory, Translations(translations)))
}

/// Whether the `len` bytes from `offset` on of `file` can be mapped without a
/// later access past the end of the file: the file is that long, and a memory
/// file is sealed against shrinking. A file of a file system without seals has
/// only its length checked.
pub(crate) fn mappable(file: &File, offset: u64, len: u64) -> Result<(), Unmappable> {
    match fcntl_get_seals(file) {
        Ok(seals) if !seals.contains(SealFlags::SHRINK) => return Err(Unmappable::Shrinkable),
        Ok(_) | Err(Errno::INVAL) => {}
        Err(errno) => return Err(Unmappable::Inspect(errno.into())),
    }
    let size = file.metadata().map_err(Unmappable::Inspect)?.len();
    if offset.checked_add(len).is_none_or(|end| end > size) {
        return Err(Unmappable::PastEnd);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use rustix::fs::{MemfdFlags, memfd_create};

    use super::*;

    fn memory_file(len: u64, sealed: bool) -> File {
        let file = File::from(
            memfd_create(
                "voidport-test",
                MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
            )
            .expect("a memfd"),
        );
        file.set_len(len).expect("the memfd takes its length");
        if sealed {
            rustix::fs::fcntl_add_seals(&file, SealFlags::SHRINK).expect("sealed");
        }
        file
    }

    #[test]
    fn only_a_part_inside_a_file_that_cannot_shrink_is_mappable() {
        let sealed = memory_file(0x2000, true);
        assert!(mappable(&sealed, 0x1000, 0x1000).is_ok());
        assert!(matches!(
            mappable(&sealed, 0x1000, 0x1001),
            Err(Unmappable::PastEnd)
        ));
        assert!(matches!(
            mappable(&sealed, u64::MAX, 1),
            Err(Unmappable::PastEnd)
        ));
        assert!(matches!(
            mappable(&memory_file(0x2000, false), 0, 0x1000),
            Err(Unmappable::Shrinkable)
        ));
    }

    #[test]
    fn a_frontend_address_is_translated_by_the_region_it_falls_in() {
        let regions = Translations(vec![
            Translation {
                frontend: 0x7f00_0000_0000,
                guest: 0,
                size: 0x8000_0000,
            },
            Translation {
                frontend: 0x7f80_0000_0000,
                guest: 0x1_0000_0000,
                size: 0x1000,
            },
        ]);
        assert_eq!(
            regions.guest_address(0x7f00_0000_1234),
            Some(GuestAddress(0x1234))
        );
        assert_eq!(
            regions.guest_address(0x7f80_0000_0fff),
            Some(GuestAddress(0x1_0000_0fff))
        );
        assert_eq!(regions.guest_address(0x7f80_0000_1000), None);
        assert_eq!(regions.guest_address(0x7e00_0000_0000), None);
    }
}
