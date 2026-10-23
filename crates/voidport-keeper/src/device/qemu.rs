use std::fs::File;
use std::sync::Arc;

use vhost::VhostBackend as _;
use vhost::vhost_user::message::{VhostUserInflight, VhostUserMemoryRegion};
use vhost::vhost_user::{Error, VhostUserFrontend as _};
use vmm_sys_util::eventfd::{EFD_CLOEXEC, EventFd};
use voidport_vhost::backend::{Address, Backend, Result, failed};
use voidport_vhost::eventfd;

use super::{Device, Forwarded};
use crate::memory::Memory;
use crate::record::Record;
use crate::server::eventfd_of;

impl Backend for Device {
    fn set_owner(&mut self) -> Result<()> {
        self.owned = true;
        let _forwarded = self.forward(|frontend| frontend.set_owner());
        Ok(())
    }

    fn reset_owner(&mut self) -> Result<()> {
        self.owned = false;
        let _forwarded = self.forward(|frontend| frontend.reset_owner());
        self.reset_rings();
        Ok(())
    }

    fn set_features(&mut self, features: u64) -> Result<()> {
        self.features = Some(features);
        let _forwarded = self.forward(|frontend| frontend.set_features(features));
        Ok(())
    }

    fn set_mem_table(&mut self, regions: &[VhostUserMemoryRegion], files: Vec<File>) -> Result<()> {
        let memory = Memory::map(regions, files).map_err(failed)?;
        let handed = memory.regions();
        self.memory = Some(memory);
        let _forwarded = self.forward(|frontend| frontend.set_mem_table(&handed));
        Ok(())
    }

    fn set_vring_num(&mut self, index: u8, size: u16) -> Result<()> {
        self.ring(index).set_size(size);
        let _forwarded = self.forward(|frontend| frontend.set_vring_num(usize::from(index), size));
        Ok(())
    }

    fn set_vring_addr(&mut self, index: u8, address: Address) -> Result<()> {
        let Self { memory, rings, .. } = self;
        let memory = memory.as_ref().ok_or(Error::InvalidParam)?;
        let ring = rings.entry(index).or_default();
        if !ring.set_address(address, memory) {
            return Err(Error::InvalidParam);
        }
        if let Some(config) = ring.config() {
            let _forwarded =
                self.forward(|frontend| frontend.set_vring_addr(usize::from(index), &config));
        }
        Ok(())
    }

    fn set_vring_base(&mut self, index: u8, base: u16) -> Result<()> {
        self.ring(index).set_base(base);
        let _forwarded = self.forward(|frontend| frontend.set_vring_base(usize::from(index), base));
        Ok(())
    }

    fn get_vring_base(&mut self, index: u8) -> Result<u16> {
        let stopped = self.forward(|frontend| frontend.get_vring_base(usize::from(index)));
        if let Forwarded::Replied(position) = stopped {
            // voidportd stopped the queue at that position, after it put back
            // every chain it had in flight, and accesses the queue no more.
            let ring = self.ring(index);
            ring.release(index);
            ring.set_base(u16::try_from(position).map_err(|_| Error::InvalidParam)?);
        }
        Ok(self.ring(index).stop())
    }

    fn set_vring_kick(&mut self, index: u8, kick: File) -> Result<()> {
        eventfd::read_without_blocking(&kick).map_err(Error::ReqHandlerError)?;
        let handed = eventfd_of(&kick).map_err(Error::ReqHandlerError)?;
        let connected = self.connected();
        if connected && let Some(size) = self.ring(index).size() {
            self.cover(index, size).map_err(failed)?;
        }
        let features = self.features();
        let Self { memory, rings, .. } = self;
        let memory = memory.as_ref().ok_or(Error::InvalidParam)?;
        rings
            .entry(index)
            .or_default()
            .start(kick, memory, features, connected)
            .map_err(failed)?;
        let forwarded =
            self.forward(|frontend| frontend.set_vring_kick(usize::from(index), &handed));
        if let Forwarded::Replied(()) = forwarded
            && let Some(record) = &self.record
        {
            let record = Arc::clone(record.inflight());
            self.ring(index).track_in(&record);
        }
        Ok(())
    }

    fn set_vring_call(&mut self, index: u8, call: Option<File>) -> Result<()> {
        if self.connected() {
            // Without a descriptor nobody is to be signalled, which voidportd
            // learns from an eventfd nobody reads.
            let handed = match &call {
                Some(call) => eventfd_of(call),
                None => EventFd::new(EFD_CLOEXEC),
            }
            .map_err(Error::ReqHandlerError)?;
            let _forwarded =
                self.forward(|frontend| frontend.set_vring_call(usize::from(index), &handed));
        }
        self.ring(index).set_call(call);
        Ok(())
    }

    fn set_vring_err(&mut self, index: u8, err: Option<File>) -> Result<()> {
        if self.connected()
            && let Some(err) = &err
        {
            let handed = eventfd_of(err).map_err(Error::ReqHandlerError)?;
            let _forwarded =
                self.forward(|frontend| frontend.set_vring_err(usize::from(index), &handed));
        }
        self.ring(index).set_err(err);
        Ok(())
    }

    fn set_vring_enable(&mut self, index: u8, enable: bool) -> Result<()> {
        self.ring(index).set_enabled(enable);
        let _forwarded =
            self.forward(|frontend| frontend.set_vring_enable(usize::from(index), enable));
        Ok(())
    }

    fn get_inflight_fd(
        &mut self,
        description: &VhostUserInflight,
    ) -> Result<(VhostUserInflight, File)> {
        let record =
            Record::create(description.num_queues, description.queue_size).map_err(failed)?;
        let reply = (
            *record.description(),
            record.file().try_clone().map_err(Error::ReqHandlerError)?,
        );
        self.hand_record(record);
        Ok(reply)
    }

    fn set_inflight_fd(&mut self, description: &VhostUserInflight, file: File) -> Result<()> {
        let record = Record::map(description, file).map_err(failed)?;
        self.hand_record(record);
        Ok(())
    }
}
