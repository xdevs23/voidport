use std::collections::BTreeMap;
use std::fs::File;
use std::sync::Arc;

use tokio::runtime::Handle;
use vhost::vhost_user::Error;
use vhost::vhost_user::message::{VhostUserInflight, VhostUserMemoryRegion};
use voidport_vhost::backend::{Address, Backend, Result, failed};
use voidport_vhost::inflight::Inflight;
use voidport_vhost::memory::{self, Translations};
use voidport_vhost::queue::Features;

use super::guest::Mapped;
use super::ring::Ring;
use crate::data::conn::Channels;

#[derive(Debug)]
pub(super) struct Device {
    channels: Arc<Channels>,
    runtime: Handle,
    features: Features,
    mapped: Arc<Mapped>,
    translations: Translations,
    in_flight: Option<Arc<Inflight>>,
    rings: BTreeMap<u8, Ring>,
}

impl Device {
    pub(super) fn new(channels: Arc<Channels>, runtime: Handle) -> Self {
        Self {
            channels,
            runtime,
            features: Features::default(),
            mapped: Arc::default(),
            translations: Translations::default(),
            in_flight: None,
            rings: BTreeMap::new(),
        }
    }

    pub(super) fn stop(&mut self) {
        let memory = self.mapped.get();
        for ring in self.rings.values_mut() {
            let _position = ring.stop(&memory);
        }
        self.rings.clear();
    }

    fn ring(&mut self, index: u8) -> &mut Ring {
        self.rings.entry(index).or_default()
    }
}

impl Backend for Device {
    fn set_owner(&mut self) -> Result<()> {
        Ok(())
    }

    fn reset_owner(&mut self) -> Result<()> {
        self.stop();
        Ok(())
    }

    fn set_features(&mut self, features: u64) -> Result<()> {
        self.features = Features::acked(features);
        Ok(())
    }

    fn set_mem_table(&mut self, regions: &[VhostUserMemoryRegion], files: Vec<File>) -> Result<()> {
        let (memory, translations) = memory::map(regions, files).map_err(failed)?;
        self.mapped.replace(memory);
        self.translations = translations;
        Ok(())
    }

    fn set_vring_num(&mut self, index: u8, size: u16) -> Result<()> {
        self.ring(index).set_size(size);
        Ok(())
    }

    fn set_vring_addr(&mut self, index: u8, address: Address) -> Result<()> {
        let layout = address
            .layout(&self.translations)
            .ok_or(Error::InvalidParam)?;
        self.ring(index).set_layout(layout);
        Ok(())
    }

    fn set_vring_base(&mut self, index: u8, base: u16) -> Result<()> {
        self.ring(index).set_base(base);
        Ok(())
    }

    fn get_vring_base(&mut self, index: u8) -> Result<u16> {
        let memory = self.mapped.get();
        Ok(self.ring(index).stop(&memory))
    }

    fn set_vring_kick(&mut self, index: u8, kick: File) -> Result<()> {
        let (mapped, features) = (Arc::clone(&self.mapped), self.features);
        let (channels, runtime) = (Arc::clone(&self.channels), self.runtime.clone());
        let record = self.in_flight.clone();
        let ring = self.ring(index);
        let in_flight = record
            .zip(ring.size())
            .and_then(|(record, size)| record.slot(u32::from(index), size));
        ring.start(kick, &mapped, features, &channels, &runtime, in_flight)
            .map_err(failed)
    }

    fn set_vring_call(&mut self, index: u8, call: Option<File>) -> Result<()> {
        self.ring(index).set_call(call);
        Ok(())
    }

    fn set_vring_err(&mut self, _index: u8, _err: Option<File>) -> Result<()> {
        // The device reports no error through an eventfd.
        Ok(())
    }

    fn set_vring_enable(&mut self, index: u8, enable: bool) -> Result<()> {
        self.ring(index).enable(enable);
        Ok(())
    }

    fn set_inflight_fd(&mut self, inflight: &VhostUserInflight, file: File) -> Result<()> {
        let record = Inflight::map(inflight, file).map_err(failed)?;
        self.in_flight = Some(Arc::new(record));
        Ok(())
    }
}
