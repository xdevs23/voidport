//! The vhost-user messages a voidport device handles, and the refusal of every
//! other one. The server and the keeper are each the backend of the same
//! device, and the [`Handler`] around either rejects the messages for parts of
//! vhost-user the device does not offer and checks the numbers of a message
//! before the [`Backend`] gets it.

use std::fs::File;

use vhost::vhost_user::message::{
    VhostTransferStateDirection, VhostTransferStatePhase, VhostUserConfigFlags, VhostUserInflight,
    VhostUserLog, VhostUserMemoryRegion, VhostUserShMemConfig, VhostUserSharedMsg,
    VhostUserSingleMemoryRegion, VhostUserVringAddrFlags, VhostUserVringState,
};
use vhost::vhost_user::{
    Error, GpuBackend, VhostUserBackendReqHandlerMut, VhostUserProtocolFeatures,
};

use crate::device::{FEATURES, PROTOCOL_FEATURES};
use crate::memory::Translations;
use crate::queue::Layout;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Address {
    /// The bits of the flags of the message, which the device has no use
    /// for.
    pub flags: u32,
    pub descriptors: u64,
    pub used: u64,
    pub available: u64,
    /// Where the frontend wants writes to guest memory logged, which the
    /// device does not offer.
    pub log: u64,
}

impl Address {
    #[must_use]
    pub fn layout(&self, translations: &Translations) -> Option<Layout> {
        Some(Layout {
            descriptors: translations.guest_address(self.descriptors)?,
            available: translations.guest_address(self.available)?,
            used: translations.guest_address(self.used)?,
        })
    }
}

/// The messages a voidport device handles. Every queue index is one a kick and
/// a call can be given for, and every size and position fits a split queue.
pub trait Backend {
    /// # Errors
    ///
    /// The error the frontend is sent.
    fn set_owner(&mut self) -> Result<()>;

    /// The frontend has let go of the device, which stops every queue.
    ///
    /// # Errors
    ///
    /// The error the frontend is sent.
    fn reset_owner(&mut self) -> Result<()>;

    /// # Errors
    ///
    /// The error the frontend is sent.
    fn set_features(&mut self, features: u64) -> Result<()>;

    /// The guest memory, as `regions` each mapped from the file at the same
    /// position in `files`.
    ///
    /// # Errors
    ///
    /// The error the frontend is sent.
    fn set_mem_table(&mut self, regions: &[VhostUserMemoryRegion], files: Vec<File>) -> Result<()>;

    /// # Errors
    ///
    /// The error the frontend is sent.
    fn set_vring_num(&mut self, index: u8, size: u16) -> Result<()>;

    /// # Errors
    ///
    /// The error the frontend is sent.
    fn set_vring_addr(&mut self, index: u8, address: Address) -> Result<()>;

    /// The next chain the driver makes available on queue `index` is at
    /// position `base` of its available ring.
    ///
    /// # Errors
    ///
    /// The error the frontend is sent.
    fn set_vring_base(&mut self, index: u8, base: u16) -> Result<()>;

    /// Stops queue `index`, and returns the position of the next chain the
    /// driver makes available, which a later start goes on from.
    ///
    /// # Errors
    ///
    /// The error the frontend is sent.
    fn get_vring_base(&mut self, index: u8) -> Result<u16>;

    /// # Errors
    ///
    /// The error the frontend is sent.
    fn set_vring_kick(&mut self, index: u8, kick: File) -> Result<()>;

    /// The device signals the driver of queue `index` through `call`, or
    /// through nothing.
    ///
    /// # Errors
    ///
    /// The error the frontend is sent.
    fn set_vring_call(&mut self, index: u8, call: Option<File>) -> Result<()>;

    /// The device reports an error of queue `index` through `err`, or
    /// through nothing.
    ///
    /// # Errors
    ///
    /// The error the frontend is sent.
    fn set_vring_err(&mut self, index: u8, err: Option<File>) -> Result<()>;

    /// Queue `index` handles the chains of the driver, or stops handling
    /// them without stopping.
    ///
    /// # Errors
    ///
    /// The error the frontend is sent.
    fn set_vring_enable(&mut self, index: u8, enable: bool) -> Result<()>;

    /// A new record of chains in flight for the queues `description` gives,
    /// with the description of it and its file. A backend that makes no
    /// record rejects the message.
    ///
    /// # Errors
    ///
    /// The error the frontend is sent.
    fn get_inflight_fd(
        &mut self,
        _description: &VhostUserInflight,
    ) -> Result<(VhostUserInflight, File)> {
        not_offered()
    }

    /// The record of chains in flight `description` gives, in `file`.
    ///
    /// # Errors
    ///
    /// The error the frontend is sent.
    fn set_inflight_fd(&mut self, description: &VhostUserInflight, file: File) -> Result<()>;
}

/// The reply to a message for a part of vhost-user the device does not
/// offer.
///
/// # Errors
///
/// Always.
pub fn not_offered<T>() -> Result<T> {
    Err(Error::InvalidOperation("not offered by the device"))
}

pub fn failed(error: impl std::error::Error + Send + Sync + 'static) -> Error {
    Error::ReqHandlerError(std::io::Error::other(error))
}

#[derive(Debug)]
pub struct Handler<B> {
    backend: B,
    owned: bool,
}

impl<B> Handler<B> {
    pub fn new(backend: B) -> Self {
        Self {
            backend,
            owned: false,
        }
    }

    pub fn backend(&mut self) -> &mut B {
        &mut self.backend
    }
}

/// The queue `index` of a message, which a kick and a call can be given for.
fn queue(index: u32) -> Result<u8> {
    u8::try_from(index).map_err(|_| Error::InvalidParam)
}

fn sixteen_bits(value: u32) -> Result<u16> {
    u16::try_from(value).map_err(|_| Error::InvalidParam)
}

impl<B: Backend> VhostUserBackendReqHandlerMut for Handler<B> {
    fn set_owner(&mut self) -> Result<()> {
        if self.owned {
            return Err(Error::InvalidOperation("the device already has a frontend"));
        }
        self.owned = true;
        self.backend.set_owner()
    }

    fn reset_owner(&mut self) -> Result<()> {
        self.owned = false;
        self.backend.reset_owner()
    }

    fn reset_device(&mut self) -> Result<()> {
        not_offered()
    }

    fn get_features(&mut self) -> Result<u64> {
        Ok(FEATURES)
    }

    fn set_features(&mut self, features: u64) -> Result<()> {
        if features & !FEATURES != 0 {
            return Err(Error::InvalidParam);
        }
        self.backend.set_features(features)
    }

    fn set_mem_table(&mut self, regions: &[VhostUserMemoryRegion], files: Vec<File>) -> Result<()> {
        self.backend.set_mem_table(regions, files)
    }

    fn set_vring_num(&mut self, index: u32, num: u32) -> Result<()> {
        self.backend
            .set_vring_num(queue(index)?, sixteen_bits(num)?)
    }

    fn set_vring_addr(
        &mut self,
        index: u32,
        flags: VhostUserVringAddrFlags,
        descriptor: u64,
        used: u64,
        available: u64,
        log: u64,
    ) -> Result<()> {
        let address = Address {
            flags: flags.bits(),
            descriptors: descriptor,
            used,
            available,
            log,
        };
        self.backend.set_vring_addr(queue(index)?, address)
    }

    fn set_vring_base(&mut self, index: u32, base: u32) -> Result<()> {
        self.backend
            .set_vring_base(queue(index)?, sixteen_bits(base)?)
    }

    fn get_vring_base(&mut self, index: u32) -> Result<VhostUserVringState> {
        let position = self.backend.get_vring_base(queue(index)?)?;
        Ok(VhostUserVringState::new(index, u32::from(position)))
    }

    fn set_vring_kick(&mut self, index: u8, fd: Option<File>) -> Result<()> {
        // Without a descriptor the frontend asks for kicks in messages, which
        // the device does not offer.
        let kick = fd.ok_or(Error::InvalidParam)?;
        self.backend.set_vring_kick(index, kick)
    }

    fn set_vring_call(&mut self, index: u8, fd: Option<File>) -> Result<()> {
        self.backend.set_vring_call(index, fd)
    }

    fn set_vring_err(&mut self, index: u8, fd: Option<File>) -> Result<()> {
        self.backend.set_vring_err(index, fd)
    }

    fn get_protocol_features(&mut self) -> Result<VhostUserProtocolFeatures> {
        Ok(PROTOCOL_FEATURES)
    }

    fn set_protocol_features(&mut self, features: u64) -> Result<()> {
        if features & !PROTOCOL_FEATURES.bits() != 0 {
            return Err(Error::InvalidParam);
        }
        Ok(())
    }

    fn get_queue_num(&mut self) -> Result<u64> {
        not_offered()
    }

    fn set_vring_enable(&mut self, index: u32, enable: bool) -> Result<()> {
        self.backend.set_vring_enable(queue(index)?, enable)
    }

    fn get_config(
        &mut self,
        _offset: u32,
        _size: u32,
        _flags: VhostUserConfigFlags,
    ) -> Result<Vec<u8>> {
        not_offered()
    }

    fn set_config(
        &mut self,
        _offset: u32,
        _buf: &[u8],
        _flags: VhostUserConfigFlags,
    ) -> Result<()> {
        not_offered()
    }

    fn set_gpu_socket(&mut self, _gpu_backend: GpuBackend) -> Result<()> {
        not_offered()
    }

    fn get_shared_object(&mut self, _uuid: VhostUserSharedMsg) -> Result<File> {
        not_offered()
    }

    fn get_inflight_fd(
        &mut self,
        inflight: &VhostUserInflight,
    ) -> Result<(VhostUserInflight, File)> {
        self.backend.get_inflight_fd(inflight)
    }

    fn set_inflight_fd(&mut self, inflight: &VhostUserInflight, file: File) -> Result<()> {
        self.backend.set_inflight_fd(inflight, file)
    }

    fn get_max_mem_slots(&mut self) -> Result<u64> {
        not_offered()
    }

    fn add_mem_region(&mut self, _region: &VhostUserSingleMemoryRegion, _fd: File) -> Result<()> {
        not_offered()
    }

    fn remove_mem_region(&mut self, _region: &VhostUserSingleMemoryRegion) -> Result<()> {
        not_offered()
    }

    fn set_device_state_fd(
        &mut self,
        _direction: VhostTransferStateDirection,
        _phase: VhostTransferStatePhase,
        _fd: File,
    ) -> Result<Option<File>> {
        not_offered()
    }

    fn check_device_state(&mut self) -> Result<()> {
        not_offered()
    }

    fn get_shmem_config(&mut self) -> Result<VhostUserShMemConfig> {
        not_offered()
    }

    fn set_log_base(&mut self, _log: &VhostUserLog, _file: File) -> Result<()> {
        not_offered()
    }
}
