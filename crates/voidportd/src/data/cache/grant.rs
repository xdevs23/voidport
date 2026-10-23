use std::sync::Arc;

use rustix::io::Errno;

use super::lease::{Lease, Pages, Then};
use super::{FileCache, State};
use crate::host::{Io, Transfer};

#[derive(Debug)]
pub struct Grant {
    cache: Arc<FileCache>,
    pages: Pages,
    epoch: u64,
    transfer: Transfer,
}

#[derive(Debug)]
pub struct Postponed {
    cache: Arc<FileCache>,
    until: Until,
    /// Whether the request is an open that waits to read or write the file in
    /// a way the description of the session does not.
    widening: bool,
}

#[derive(Clone, Copy, Debug)]
pub(super) enum Until {
    Settled,
    Usable { through: Pages },
}

#[derive(Debug)]
pub enum Unserved {
    Failed(Errno),
    Postponed(Postponed),
}

impl From<Errno> for Unserved {
    fn from(errno: Errno) -> Self {
        Self::Failed(errno)
    }
}

impl FileCache {
    pub(super) fn grant(self: &Arc<Self>, state: &mut State, transfer: Transfer) -> Grant {
        let pages = state.lease.pages(state.cached, state.widening > 0);
        state.handles += 1;
        if pages != Pages::Uncached {
            state.cached += 1;
            if let Lease::Held { file, .. } = &state.lease {
                file.slot().busy();
            }
        }
        Grant {
            cache: Arc::clone(self),
            pages,
            epoch: state.epoch,
            transfer,
        }
    }

    pub(super) fn postponed(self: &Arc<Self>, until: Until) -> Unserved {
        Unserved::Postponed(Postponed {
            cache: Arc::clone(self),
            until,
            widening: false,
        })
    }

    pub(super) fn widening(self: &Arc<Self>, state: &mut State) -> Unserved {
        state.widening += 1;
        Unserved::Postponed(Postponed {
            cache: Arc::clone(self),
            until: Until::Settled,
            widening: true,
        })
    }
}

impl Grant {
    #[must_use]
    pub fn pages(&self) -> Pages {
        self.pages
    }

    #[must_use]
    pub fn transfer(&self) -> Transfer {
        self.transfer
    }

    pub fn used(&self) {
        self.cache.requested(self.pages == Pages::Taken, self.epoch);
    }

    pub fn io(&self) -> Result<Io, Unserved> {
        let reopened = self.cache.locked().reopens();
        if let Some(access) = reopened {
            self.cache.make_way(access.kind())?;
        }
        let mut state = self.cache.locked();
        state.resume()?;
        match &state.lease {
            Lease::Waiting { .. } => Err(self.cache.postponed(Until::Usable {
                through: self.pages,
            })),
            lease => {
                let description = lease.description().ok_or(Errno::BADF)?;
                Ok(Io::measured(Arc::clone(description), self.transfer))
            }
        }
    }
}

impl Drop for Grant {
    /// When the last handle caching the pages is released, the waiting requests
    /// of uncached handles go on. When the last handle of the node is released,
    /// the description is closed unless a lease needs it, and that lease is
    /// recalled when another cache of the file waits.
    fn drop(&mut self) {
        let cache = &self.cache;
        let mut state = cache.locked();
        state.handles -= 1;
        if self.pages != Pages::Uncached {
            state.cached -= 1;
        }
        if state.cached == 0 {
            match &state.lease {
                Lease::Held { file, .. } | Lease::Recalling { file, .. } => file.slot().idle(),
                Lease::Waiting { kept, .. } => {
                    if let Some(description) = kept.description() {
                        state.lease = Lease::Open(description);
                    }
                    cache.changed.notify_waiters();
                }
                Lease::Open(_) | Lease::Closed => {}
            }
        }
        state.close_if_unused();
        if state.handles == 0 && cache.others_wait() {
            cache.recall(&mut state, Then::Release);
        }
    }
}

impl Postponed {
    /// A request through a handle that caches the pages fails with `EIO` once
    /// nothing would report that the opener it waits for is done. A request
    /// through an uncached handle then waits until no handle caches the pages,
    /// since a page it fills would reach those handles without a lease to recall
    /// it.
    pub async fn ended(&self) -> Result<(), Errno> {
        loop {
            let changed = self.cache.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            {
                let state = self.cache.locked();
                match (self.until, &state.lease) {
                    (Until::Settled, Lease::Recalling { .. }) => {}
                    (Until::Usable { .. }, Lease::Waiting { .. }) if state.cached == 0 => {
                        return Ok(());
                    }
                    (Until::Usable { through }, Lease::Waiting { watch: None, .. })
                        if through != Pages::Uncached =>
                    {
                        return Err(Errno::IO);
                    }
                    (Until::Usable { .. }, Lease::Waiting { .. }) => {}
                    _ => return Ok(()),
                }
            }
            changed.await;
        }
    }
}

impl Drop for Postponed {
    fn drop(&mut self) {
        if !self.widening {
            return;
        }
        let mut state = self.cache.locked();
        state.widening -= 1;
        self.cache.retake(&mut state);
    }
}
