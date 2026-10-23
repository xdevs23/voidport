//! A queue that stopped is never accessed again. The chains it handed on may
//! still be in flight, so every read and write of guest memory they make first
//! checks the open flag of the queue ([`Started::access`]), and stopping clears
//! it: the stop waits for the accesses already under way, and every later one
//! finds the flag cleared and accesses nothing. The stop then puts back every
//! chain still in flight with nothing written into it, since the frontend has
//! the position of the queue from then on and the driver waits for each chain
//! it made available. A chain that finishes after the stop is not put back a
//! second time.

use std::fs::File;
use std::io;
use std::os::fd::OwnedFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, RwLock, RwLockReadGuard};

use tokio::io::unix::AsyncFd;
use tokio::runtime::Handle;
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use virtio_queue::{Queue, QueueOwnedT as _, QueueT as _};
use vm_memory::GuestMemoryMmap;
use voidport_vhost::eventfd;
use voidport_vhost::inflight::Slot;
use voidport_vhost::queue::{self, Features, Layout};

use super::guest::{Chain, Mapped};
use crate::data::conn::Channels;

#[derive(Debug, thiserror::Error)]
pub(super) enum StartError {
    #[error("the queue was started before its size and layout were set")]
    Unset,
    #[error("the size or the layout of the queue does not make a queue")]
    Invalid(#[source] voidport_vhost::Error),
    #[error("the kick eventfd cannot be read without blocking")]
    Kick(#[source] io::Error),
}

#[derive(Debug, Default)]
pub(super) struct Ring {
    size: Option<u16>,
    base: u16,
    layout: Option<Layout>,
    call: Arc<Call>,
    switch: Arc<Switch>,
    started: Option<Running>,
}

#[derive(Debug)]
struct Running {
    started: Arc<Started>,
    kicks: JoinHandle<()>,
}

impl Ring {
    pub(super) fn set_size(&mut self, size: u16) {
        self.size = Some(size);
    }

    pub(super) fn set_base(&mut self, base: u16) {
        self.base = base;
    }

    pub(super) fn set_layout(&mut self, layout: Layout) {
        self.layout = Some(layout);
    }

    pub(super) fn size(&self) -> Option<u16> {
        self.size
    }

    pub(super) fn set_call(&self, call: Option<File>) {
        self.call.set(call);
    }

    pub(super) fn enable(&self, enabled: bool) {
        self.switch.set(enabled);
    }

    /// The kick eventfd is made to read without blocking: it is the file
    /// description the frontend shares with the notifier of the guest, which
    /// only the device reads. A queue whose frontend did not negotiate the
    /// vhost-user protocol features handles the chains of the driver from its
    /// start, and one whose frontend did waits to be enabled.
    pub(super) fn start(
        &mut self,
        kick: File,
        mapped: &Arc<Mapped>,
        features: Features,
        channels: &Arc<Channels>,
        runtime: &Handle,
        in_flight: Option<Slot>,
    ) -> Result<(), StartError> {
        let kick = OwnedFd::from(kick);
        eventfd::read_without_blocking(&kick).map_err(StartError::Kick)?;
        let started = match self.started.take() {
            Some(running) => {
                running.kicks.abort();
                running.started
            }
            None => Arc::new(Started {
                tracked: Mutex::new(Tracked::new(
                    self.queue(&mapped.get(), features)?,
                    in_flight,
                )),
                open: RwLock::new(true),
                call: Arc::clone(&self.call),
                switch: Arc::clone(&self.switch),
            }),
        };
        if !features.enables {
            self.switch.set(true);
        }
        let _entered = runtime.enter();
        let kick = AsyncFd::new(kick).map_err(StartError::Kick)?;
        let kicks = runtime.spawn(serve_kicks(
            Arc::clone(&started),
            kick,
            Arc::clone(mapped),
            Arc::clone(channels),
        ));
        self.started = Some(Running { started, kicks });
        Ok(())
    }

    pub(super) fn stop(&mut self, memory: &GuestMemoryMmap) -> u16 {
        self.switch.set(false);
        if let Some(running) = self.started.take() {
            running.kicks.abort();
            self.base = running.started.stop(memory);
        }
        self.call.set(None);
        self.base
    }

    fn queue(&self, memory: &GuestMemoryMmap, features: Features) -> Result<Queue, StartError> {
        let (Some(size), Some(layout)) = (self.size, self.layout) else {
            return Err(StartError::Unset);
        };
        queue::split(memory, size, layout, features, self.base).map_err(StartError::Invalid)
    }
}

#[derive(Debug, Default)]
struct Call(Mutex<Option<File>>);

impl Call {
    fn set(&self, call: Option<File>) {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner) = call;
    }

    fn signal(&self) {
        let call = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(call) = call.as_ref()
            && let Err(error) = eventfd::signal(call)
        {
            tracing::warn!(%error, "the driver could not be signalled");
        }
    }
}

#[derive(Debug, Default)]
struct Switch {
    enabled: AtomicBool,
    changed: Notify,
}

impl Switch {
    fn set(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Release);
        self.changed.notify_one();
    }

    fn enabled(&self) -> bool {
        self.enabled.load(Ordering::Acquire)
    }
}

#[derive(Debug)]
struct Tracked {
    queue: Queue,
    pulled: Vec<bool>,
    in_flight: Option<Slot>,
}

impl Tracked {
    fn new(queue: Queue, in_flight: Option<Slot>) -> Self {
        let in_flight = in_flight.map(|mut slot| {
            slot.start(queue.next_used());
            slot
        });
        Self {
            pulled: vec![false; usize::from(queue.size())],
            queue,
            in_flight,
        }
    }

    fn pull(&mut self, head: u16) -> Result<(), virtio_queue::Error> {
        let pulled = self
            .pulled
            .get_mut(usize::from(head))
            .ok_or(virtio_queue::Error::InvalidDescriptorIndex)?;
        *pulled = true;
        if let Some(slot) = &mut self.in_flight {
            slot.take(head);
        }
        Ok(())
    }

    fn put_back(
        &mut self,
        memory: &GuestMemoryMmap,
        head: u16,
        written: u32,
    ) -> Result<(), virtio_queue::Error> {
        if let Some(pulled) = self.pulled.get_mut(usize::from(head)) {
            *pulled = false;
        }
        if let Some(slot) = &self.in_flight {
            slot.finishing(head);
        }
        self.queue.add_used(memory, head, written)?;
        if let Some(slot) = &self.in_flight {
            slot.finished(head, self.queue.next_used());
        }
        Ok(())
    }

    fn in_flight(&self) -> Vec<u16> {
        (0..self.queue.size())
            .filter(|&head| self.pulled[usize::from(head)])
            .collect()
    }
}

#[derive(Debug)]
pub(super) struct Started {
    tracked: Mutex<Tracked>,
    open: RwLock<bool>,
    call: Arc<Call>,
    switch: Arc<Switch>,
}

impl Started {
    pub(super) fn access(&self) -> Option<RwLockReadGuard<'_, bool>> {
        let open = self.open.read().unwrap_or_else(PoisonError::into_inner);
        (*open).then_some(open)
    }

    pub(super) fn finish(&self, memory: &GuestMemoryMmap, head: u16, written: u32) {
        let Some(_open) = self.access() else {
            return;
        };
        let signal = {
            let mut tracked = self.tracked();
            tracked
                .put_back(memory, head, written)
                .and_then(|()| tracked.queue.needs_notification(memory))
        };
        match signal {
            Ok(true) => self.call.signal(),
            Ok(false) => {}
            Err(error) => tracing::warn!(%error, "a finished chain could not be put back"),
        }
    }

    /// The chains are pulled during one access with the queue locked, and
    /// handed on once both are over: a chain that finishes at once puts itself
    /// back through both.
    fn hand_available_chains(
        self: &Arc<Self>,
        memory: &Arc<GuestMemoryMmap>,
        channels: &Arc<Channels>,
    ) -> Result<(), virtio_queue::Error> {
        loop {
            let (pulled, more) = {
                let Some(_open) = self.access() else {
                    return Ok(());
                };
                let mut tracked = self.tracked();
                tracked.queue.disable_notification(&**memory)?;
                let pulled: Vec<_> = tracked.queue.iter(Arc::clone(memory))?.collect();
                for chain in &pulled {
                    tracked.pull(chain.head_index())?;
                }
                (pulled, tracked.queue.enable_notification(&**memory)?)
            };
            for chain in pulled {
                channels.serve(Chain::new(Arc::clone(self), Arc::clone(memory), chain));
            }
            if !more {
                return Ok(());
            }
        }
    }

    fn stop(&self, memory: &GuestMemoryMmap) -> u16 {
        *self.open.write().unwrap_or_else(PoisonError::into_inner) = false;
        let mut tracked = self.tracked();
        let heads = tracked.in_flight();
        let put_back = heads
            .iter()
            .try_for_each(|&head| tracked.put_back(memory, head, 0))
            .and_then(|()| Ok(!heads.is_empty() && tracked.queue.needs_notification(memory)?));
        match put_back {
            Ok(true) => self.call.signal(),
            Ok(false) => {}
            Err(error) => tracing::warn!(%error, "a chain in flight could not be put back"),
        }
        if let Some(slot) = &tracked.in_flight {
            slot.release();
        }
        tracked.queue.next_avail()
    }

    fn tracked(&self) -> MutexGuard<'_, Tracked> {
        self.tracked.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Hands on the chains once at the start too, since chains may be waiting from
/// before it.
async fn serve_kicks(
    started: Arc<Started>,
    kick: AsyncFd<OwnedFd>,
    mapped: Arc<Mapped>,
    channels: Arc<Channels>,
) {
    loop {
        if started.switch.enabled()
            && let Err(error) = started.hand_available_chains(&mapped.get(), &channels)
        {
            tracing::warn!(%error, "a queue the driver broke is not handled any more");
            return;
        }
        tokio::select! {
            readable = kick.readable() => {
                let mut ready = match readable {
                    Ok(ready) => ready,
                    Err(error) => {
                        tracing::warn!(%error, "the kicks of a queue cannot be read");
                        return;
                    }
                };
                // A read resets the count of the eventfd, so the next read
                // finds it at zero and clears the readiness.
                loop {
                    match ready.try_io(|kick| eventfd::read(kick.get_ref())) {
                        Ok(Ok(_)) => {}
                        Ok(Err(error)) => {
                            tracing::warn!(%error, "the kicks of a queue cannot be read");
                            return;
                        }
                        Err(_empty) => break,
                    }
                }
            }
            () = started.switch.changed.notified() => {}
        }
    }
}
