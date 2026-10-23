use std::fs::File;
use std::sync::Arc;

use vhost::vhost_user::message::VhostUserInflight;
use voidport_vhost::inflight::Inflight;

pub(crate) struct Record {
    inflight: Arc<Inflight>,
    description: VhostUserInflight,
    file: File,
}

impl Record {
    pub(crate) fn create(queues: u16, queue_size: u16) -> Result<Self, voidport_vhost::Error> {
        let (inflight, description, file) = Inflight::create(queues, queue_size)?;
        Ok(Self {
            inflight: Arc::new(inflight),
            description,
            file,
        })
    }

    pub(crate) fn map(
        description: &VhostUserInflight,
        file: File,
    ) -> Result<Self, voidport_vhost::Error> {
        let mapped = file
            .try_clone()
            .map_err(voidport_vhost::Error::CreateInflight)?;
        Ok(Self {
            inflight: Arc::new(Inflight::map(description, mapped)?),
            description: *description,
            file,
        })
    }

    pub(crate) fn covers(&self, index: u8, size: u16) -> bool {
        u16::from(index) < self.description.num_queues && size <= self.description.queue_size
    }

    pub(crate) fn inflight(&self) -> &Arc<Inflight> {
        &self.inflight
    }

    pub(crate) fn description(&self) -> &VhostUserInflight {
        &self.description
    }

    pub(crate) fn file(&self) -> &File {
        &self.file
    }
}
