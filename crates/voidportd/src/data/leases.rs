//! A lease is placed on the one description a session reads and writes the
//! file through ([`LeaseFile`]): a read lease on one opened for reading only,
//! and a write lease on one opened for writing. Every lease is one slot of the
//! descriptor budget, so a guest that reads many files cannot make the server
//! open more descriptors than the budget allows.

use std::collections::HashMap;
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, RawFd};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::thread::JoinHandle;

use tokio::io::unix::AsyncFd;
use tokio::sync::oneshot;
use tokio::task::AbortHandle;

use crate::data::cache::FileCache;
use crate::data::descriptor_budget::{DescriptorBudget, LeaseHolder, LeaseSlot};
use crate::host::Description;
use crate::host::attr::NodeIdentity;
use crate::host::closes::{Closed, Closes, WatchId};
use crate::host::lease::{Breaks, Kind};

#[derive(Debug)]
pub struct Leases {
    files: Mutex<HashMap<RawFd, Weak<FileCache>>>,
    budget: Arc<DescriptorBudget>,
    runtime: tokio::runtime::Handle,
    closes: Closes,
    watches: Mutex<Watches>,
    caches: Mutex<HashMap<NodeIdentity, Vec<Weak<FileCache>>>>,
}

#[derive(Debug)]
struct Watches {
    caches: HashMap<WatchId, Vec<Weak<FileCache>>>,
    reading: bool,
}

#[derive(Debug)]
pub struct Watched {
    leases: Arc<Leases>,
    id: WatchId,
    cache: Weak<FileCache>,
}

#[derive(Debug)]
pub struct LeaseFile {
    /// First, so that the descriptor is unregistered before it can close.
    _registered: Registered,
    description: Arc<Description>,
    slot: LeaseSlot,
}

#[derive(Debug)]
struct Registered {
    leases: Arc<Leases>,
    fd: RawFd,
}

#[derive(Debug)]
pub struct LeaseTask(AbortHandle);

impl Drop for LeaseTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[derive(Debug)]
pub struct LeaseThread {
    leases: Arc<Leases>,
    stop: Option<oneshot::Sender<()>>,
    thread: Option<JoinHandle<()>>,
}

impl LeaseThread {
    pub fn start(budget: Arc<DescriptorBudget>) -> io::Result<Self> {
        let breaks = Breaks::install()?;
        let closes = Closes::new()?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let leases = Arc::new(Leases {
            files: Mutex::default(),
            budget,
            runtime: runtime.handle().clone(),
            closes,
            watches: Mutex::new(Watches {
                caches: HashMap::new(),
                reading: true,
            }),
            caches: Mutex::default(),
        });
        let (stop, stopped) = oneshot::channel();
        let dispatching = Arc::clone(&leases);
        let thread = std::thread::Builder::new()
            .name("voidportd-leases".into())
            .spawn(move || {
                runtime.block_on(async {
                    tokio::select! {
                        _ = stopped => {}
                        _ = async {
                            tokio::join!(dispatching.dispatch(&breaks), dispatching.changes())
                        } => {}
                    }
                });
            })?;
        Ok(Self {
            leases,
            stop: Some(stop),
            thread: Some(thread),
        })
    }

    #[must_use]
    pub fn leases(&self) -> &Arc<Leases> {
        &self.leases
    }
}

impl Drop for LeaseThread {
    fn drop(&mut self) {
        drop(self.stop.take());
        if let Some(thread) = self.thread.take()
            && thread.join().is_err()
        {
            tracing::error!("the thread that reads lease breaks panicked");
        }
    }
}

impl Leases {
    /// A full budget returns the lease it asks back, which the caller gives
    /// back outside every lock of its own ([`LeaseHolder::give_back`]), or
    /// `None` when every lease is relied on.
    pub fn slot(&self, cache: &Arc<FileCache>) -> Result<LeaseSlot, Option<Arc<dyn LeaseHolder>>> {
        let holder: Weak<FileCache> = Arc::downgrade(cache);
        self.budget.lease_slot(holder)
    }

    pub fn join(&self, identity: NodeIdentity, cache: &Arc<FileCache>) {
        self.registry()
            .entry(identity)
            .or_default()
            .push(Arc::downgrade(cache));
    }

    pub fn leave(&self, identity: NodeIdentity) {
        let mut registry = self.registry();
        if let Some(caches) = registry.get_mut(&identity) {
            caches.retain(|cache| cache.strong_count() > 0);
            if caches.is_empty() {
                registry.remove(&identity);
            }
        }
    }

    #[must_use]
    pub fn others(&self, identity: NodeIdentity, cache: &FileCache) -> Vec<Arc<FileCache>> {
        self.arbitrate(identity, cache, <[Arc<FileCache>]>::to_vec)
    }

    /// No other cache of the file runs a decision meanwhile, so that two caches
    /// cannot both decide on what the other had before.
    pub fn arbitrate<R>(
        &self,
        identity: NodeIdentity,
        cache: &FileCache,
        decide: impl FnOnce(&[Arc<FileCache>]) -> R,
    ) -> R {
        let registry = self.registry();
        let others: Vec<Arc<FileCache>> = registry
            .get(&identity)
            .into_iter()
            .flatten()
            .filter(|other| !std::ptr::eq(other.as_ptr(), cache))
            .filter_map(Weak::upgrade)
            .collect();
        let decided = decide(&others);
        // A cache whose last reference goes with `others` leaves the
        // registry, which needs the registry lock.
        drop(registry);
        decided
    }

    /// Nothing can recall the pages that guest may still cache, so the next
    /// writer is delayed until `passed`, and a lease broken meanwhile is given
    /// up at that instant too.
    pub fn linger(&self, mut caches: Vec<Arc<FileCache>>, passed: std::time::Instant) {
        caches.retain(|cache| cache.leased());
        if caches.is_empty() {
            return;
        }
        drop(self.runtime.spawn(async move {
            tokio::time::sleep_until(tokio::time::Instant::from_std(passed)).await;
            drop(caches);
        }));
    }

    pub fn spawn(&self, task: impl Future<Output = ()> + Send + 'static) -> LeaseTask {
        LeaseTask(self.runtime.spawn(task).abort_handle())
    }

    async fn dispatch(&self, breaks: &Breaks) {
        let watched = breaks
            .descriptors()
            .try_clone()
            .and_then(|descriptors| {
                descriptors.set_nonblocking(true)?;
                tokio::net::UnixDatagram::from_std(descriptors)
            })
            .and_then(|descriptors| {
                let unknown = breaks.unknown().try_clone_to_owned()?;
                Ok((descriptors, AsyncFd::new(unknown)?))
            });
        let (descriptors, unknown) = match watched {
            Ok(watched) => watched,
            Err(error) => {
                tracing::error!(%error, "lease breaks cannot be read");
                return;
            }
        };
        let mut datagram = [0u8; size_of::<RawFd>()];
        loop {
            let read = tokio::select! {
                received = descriptors.recv(&mut datagram) => received.map(|len| {
                    if len == datagram.len() {
                        self.broken(RawFd::from_ne_bytes(datagram));
                    }
                }),
                ready = unknown.readable() => ready.map(|mut ready| {
                    // Reading the eventfd resets it; it may be empty already
                    // when a second wakeup raced the first.
                    let _ = rustix::io::read(ready.get_inner(), &mut [0u8; 8]);
                    ready.clear_ready();
                    for file in self.all() {
                        self.broken(file);
                    }
                }),
            };
            if let Err(error) = read {
                tracing::error!(%error, "lease breaks cannot be read");
                return;
            }
        }
    }

    pub fn watch(
        self: &Arc<Self>,
        file: BorrowedFd<'_>,
        cache: &Arc<FileCache>,
        kind: Kind,
    ) -> Option<Watched> {
        let mut watches = self.watched();
        if !watches.reading {
            return None;
        }
        match self.closes.watch(file, kind) {
            Ok(id) => {
                watches
                    .caches
                    .entry(id)
                    .or_default()
                    .push(Arc::downgrade(cache));
                Some(Watched {
                    leases: Arc::clone(self),
                    id,
                    cache: Arc::downgrade(cache),
                })
            }
            Err(error) => {
                tracing::warn!(%error, "a file whose writer broke a lease cannot be watched");
                None
            }
        }
    }

    async fn changes(&self) {
        let read = self.closes.read(|closed| {
            let (changed, lost) = self.waiting(&closed);
            for cache in changed {
                cache.opener_changed();
            }
            for cache in lost {
                cache.unwatched();
            }
        });
        if let Err(error) = read.await {
            tracing::error!(%error, "the changes of files cannot be read, so the reads that wait for a writer fail");
        }
        let caches: Vec<Weak<FileCache>> = {
            let mut watches = self.watched();
            watches.reading = false;
            watches.caches.values().flatten().cloned().collect()
        };
        for cache in caches.iter().filter_map(Weak::upgrade) {
            cache.unwatched();
        }
    }

    fn waiting(&self, closed: &Closed) -> (Vec<Arc<FileCache>>, Vec<Arc<FileCache>>) {
        let watches = self.watched();
        let caches = |ids: &[WatchId]| -> Vec<Arc<FileCache>> {
            ids.iter()
                .filter_map(|id| watches.caches.get(id))
                .flatten()
                .filter_map(Weak::upgrade)
                .collect()
        };
        let changed = if closed.overflowed {
            watches
                .caches
                .values()
                .flatten()
                .filter_map(Weak::upgrade)
                .collect()
        } else {
            caches(&closed.changed)
        };
        (changed, caches(&closed.lost))
    }

    fn watched(&self) -> MutexGuard<'_, Watches> {
        self.watches
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    /// The cache asks the lease itself: the signal of a descriptor closed
    /// meanwhile reports nothing, or a lease that is not breaking.
    fn broken(&self, file: RawFd) {
        let cache = self.locked().get(&file).and_then(Weak::upgrade);
        if let Some(cache) = cache {
            cache.broken();
        }
    }

    fn all(&self) -> Vec<RawFd> {
        self.locked().keys().copied().collect()
    }

    fn locked(&self) -> MutexGuard<'_, HashMap<RawFd, Weak<FileCache>>> {
        self.files
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    fn registry(&self) -> MutexGuard<'_, HashMap<NodeIdentity, Vec<Weak<FileCache>>>> {
        self.caches
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }
}

impl LeaseFile {
    #[must_use]
    pub fn new(
        leases: &Arc<Leases>,
        description: Arc<Description>,
        slot: LeaseSlot,
        cache: &Arc<FileCache>,
    ) -> Self {
        let fd = description.fd().as_raw_fd();
        leases.locked().insert(fd, Arc::downgrade(cache));
        Self {
            _registered: Registered {
                leases: Arc::clone(leases),
                fd,
            },
            description,
            slot,
        }
    }

    #[must_use]
    pub fn description(&self) -> &Arc<Description> {
        &self.description
    }

    #[must_use]
    pub fn fd(&self) -> BorrowedFd<'_> {
        self.description.fd()
    }

    #[must_use]
    pub fn kind(&self) -> Kind {
        Kind::of(self.description.access())
    }

    #[must_use]
    pub fn slot(&self) -> &LeaseSlot {
        &self.slot
    }

    #[must_use]
    pub fn into_parts(self) -> (Arc<Description>, LeaseSlot) {
        (self.description, self.slot)
    }
}

impl Drop for Watched {
    fn drop(&mut self) {
        let mut watches = self.leases.watched();
        let Some(caches) = watches.caches.get_mut(&self.id) else {
            return;
        };
        // One cache can have two watches of one file for a moment: the one
        // that replaces this, made before it goes.
        if let Some(at) = caches.iter().position(|cache| cache.ptr_eq(&self.cache)) {
            caches.swap_remove(at);
        }
        if caches.is_empty() {
            watches.caches.remove(&self.id);
            self.leases.closes.unwatch(self.id);
        }
    }
}

impl Drop for Registered {
    /// Unregisters the descriptor before it can close, so that no break of a
    /// later descriptor with the same number is used for the cache of this file.
    fn drop(&mut self) {
        self.leases.locked().remove(&self.fd);
    }
}
