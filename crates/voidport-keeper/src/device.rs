//! The device as QEMU set it up, and which process runs its queues. While
//! voidportd is connected, each message is handed on to it as well, and
//! voidportd runs the queues. When voidportd goes away the keeper runs them
//! itself ([`crate::ring`]).
//!
//! The record of chains in flight ([`crate::record`]) is sized for the queues
//! QEMU gives when QEMU asks for one. The `vhost-user-fs-pci` device of QEMU does
//! not ask, so the record is sized for the queues set up so far, and sized again
//! whenever a queue starts that the record has no slot for.

mod qemu;

use std::collections::BTreeMap;
use std::io;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;

use vhost::vhost_user::Frontend;
use voidport_vhost::queue::Features;

use crate::memory::Memory;
use crate::record::Record;
use crate::ring::Ring;
use crate::server::{HandOverError, Server, hand_record};

#[derive(Default)]
pub(crate) struct Device {
    owned: bool,
    features: Option<u64>,
    memory: Option<Memory>,
    rings: BTreeMap<u8, Ring>,
    record: Option<Record>,
    server: Option<Server>,
}

enum Forwarded<T> {
    NotConnected,
    Failed,
    Replied(T),
}

impl Device {
    pub(crate) fn connected(&self) -> bool {
        self.server.is_some()
    }

    pub(crate) fn watched(&self) -> Vec<OwnedFd> {
        let duplicates: Vec<io::Result<OwnedFd>> = match &self.server {
            Some(server) => vec![server.watch()],
            None => self
                .rings
                .values()
                .filter_map(Ring::served_kick)
                .map(|kick| kick.try_clone().map(OwnedFd::from))
                .collect(),
        };
        duplicates
            .into_iter()
            .filter_map(|duplicate| {
                duplicate
                    .inspect_err(|error| tracing::warn!(%error, "a descriptor cannot be watched"))
                    .ok()
            })
            .collect()
    }

    /// # Errors
    ///
    /// [`HandOverError`] when voidportd fails a part of it. The keeper then
    /// goes on running the device.
    pub(crate) fn hand_over(&mut self, stream: UnixStream) -> Result<(), HandOverError> {
        let started: Vec<(u8, u16)> = self
            .rings
            .iter()
            .filter(|(_, ring)| ring.started())
            .filter_map(|(&index, ring)| ring.size().map(|size| (index, size)))
            .collect();
        for (index, size) in started {
            self.cover(index, size).map_err(HandOverError::Record)?;
        }
        let mut server = Server::connect(stream, self.record.as_ref())?;
        if let Err(error) = self.replay(server.frontend()) {
            server.release();
            self.take_over();
            return Err(error);
        }
        for ring in self.rings.values_mut() {
            ring.handed_over();
        }
        self.server = Some(server);
        Ok(())
    }

    pub(crate) fn check(&mut self) {
        if self.server.as_ref().is_some_and(Server::gone) {
            tracing::warn!("voidportd went away, the keeper ends its sessions on the device");
            self.lose();
        }
    }

    pub(crate) fn serve(&mut self) {
        if self.server.is_some() {
            return;
        }
        let Some(memory) = &self.memory else {
            return;
        };
        let enables = self.features().enables;
        for (index, ring) in &mut self.rings {
            if let Err(error) = ring.serve(memory.mapped(), enables) {
                tracing::warn!(index, %error, "a queue the driver broke is not run any more");
                ring.break_off();
            }
        }
    }

    pub(crate) fn end(&mut self) {
        if let Some(server) = self.server.take() {
            server.release();
        }
    }

    /// Sends one message to voidportd while it runs the device. A message
    /// voidportd does not confirm ends the connection, and the keeper takes
    /// the device back.
    fn forward<T>(
        &mut self,
        message: impl FnOnce(&mut Frontend) -> vhost::Result<T>,
    ) -> Forwarded<T> {
        let Some(server) = self.server.as_mut() else {
            return Forwarded::NotConnected;
        };
        match message(server.frontend()) {
            Ok(reply) => Forwarded::Replied(reply),
            Err(error) => {
                tracing::warn!(%error, "voidportd failed a message of the device, the keeper ends its sessions on the device");
                self.lose();
                Forwarded::Failed
            }
        }
    }

    fn lose(&mut self) {
        if let Some(server) = self.server.take() {
            server.release();
        }
        self.take_over();
    }

    fn take_over(&mut self) {
        let features = self.features();
        let Some(memory) = &self.memory else {
            return;
        };
        for (&index, ring) in &mut self.rings {
            if let Err(error) = ring.take_over(index, memory, features) {
                tracing::warn!(index, %error, "a queue of the device cannot be run");
                ring.break_off();
            }
        }
    }

    fn replay(&mut self, frontend: &mut Frontend) -> Result<(), HandOverError> {
        use vhost::VhostBackend as _;

        if self.owned {
            frontend.set_owner()?;
        }
        if let Some(features) = self.features {
            frontend.set_features(features)?;
        }
        if let Some(memory) = &self.memory {
            frontend.set_mem_table(&memory.regions())?;
        }
        let record = self.record.as_ref().map(Record::inflight);
        for (&index, ring) in &mut self.rings {
            ring.replay(index, frontend, record)?;
        }
        Ok(())
    }

    fn features(&self) -> Features {
        Features::acked(self.features.unwrap_or_default())
    }

    fn ring(&mut self, index: u8) -> &mut Ring {
        self.rings.entry(index).or_default()
    }

    /// Makes sure the record has a slot for queue `index` of `size` entries:
    /// a record without one is replaced by one sized for every queue QEMU has
    /// set up, which is handed to voidportd when it runs the device.
    /// voidportd tracks the queues it started before in the record it had
    /// then.
    fn cover(&mut self, index: u8, size: u16) -> Result<(), voidport_vhost::Error> {
        if self
            .record
            .as_ref()
            .is_some_and(|record| record.covers(index, size))
        {
            return Ok(());
        }
        let queues = self
            .rings
            .keys()
            .copied()
            .chain([index])
            .max()
            .map_or(1, |last| u16::from(last) + 1);
        let queue_size = self
            .rings
            .values()
            .filter_map(Ring::size)
            .chain([size])
            .max()
            .unwrap_or(size);
        let record = Record::create(queues, queue_size)?;
        self.hand_record(record);
        Ok(())
    }

    fn hand_record(&mut self, record: Record) {
        let _forwarded = self.forward(|frontend| hand_record(frontend, &record));
        self.record = Some(record);
    }

    fn reset_rings(&mut self) {
        for (&index, ring) in &mut self.rings {
            ring.release(index);
        }
        self.rings.clear();
    }
}
