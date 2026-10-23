use std::fs::File;
use std::io;
use std::os::fd::AsRawFd as _;

use vhost::VhostUserMemoryRegionInfo;
use vhost::vhost_user::message::VhostUserMemoryRegion;
use vm_memory::GuestMemoryMmap;
use voidport_vhost::memory::{self, Translations};

pub(crate) struct Memory {
    regions: Vec<VhostUserMemoryRegion>,
    files: Vec<File>,
    mapped: GuestMemoryMmap,
    translations: Translations,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum MemoryError {
    #[error("a file of the guest memory could not be duplicated")]
    Duplicate(#[source] io::Error),
    #[error("the guest memory could not be mapped")]
    Map(#[source] voidport_vhost::Error),
}

impl Memory {
    pub(crate) fn map(
        regions: &[VhostUserMemoryRegion],
        files: Vec<File>,
    ) -> Result<Self, MemoryError> {
        let kept = files
            .iter()
            .map(File::try_clone)
            .collect::<io::Result<Vec<File>>>()
            .map_err(MemoryError::Duplicate)?;
        let (mapped, translations) = memory::map(regions, files).map_err(MemoryError::Map)?;
        Ok(Self {
            regions: regions.to_vec(),
            files: kept,
            mapped,
            translations,
        })
    }

    pub(crate) fn regions(&self) -> Vec<VhostUserMemoryRegionInfo> {
        self.regions
            .iter()
            .zip(&self.files)
            .map(|(region, file)| VhostUserMemoryRegionInfo {
                guest_phys_addr: region.guest_phys_addr,
                memory_size: region.memory_size,
                userspace_addr: region.user_addr,
                mmap_offset: region.mmap_offset,
                mmap_handle: file.as_raw_fd(),
            })
            .collect()
    }

    pub(crate) fn mapped(&self) -> &GuestMemoryMmap {
        &self.mapped
    }

    pub(crate) fn translations(&self) -> &Translations {
        &self.translations
    }
}
