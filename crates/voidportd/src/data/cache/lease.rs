use std::os::fd::BorrowedFd;
use std::sync::{Arc, Weak};

use rustix::fs::OFlags;

use crate::data::descriptor_budget::LeaseSlot;
use crate::data::leases::{LeaseFile, LeaseTask, Watched};
use crate::data::recall::Recalls;
use crate::host::Description;
use crate::host::lease::{self, Kind};

#[derive(Debug, Default)]
pub(super) enum Lease {
    #[default]
    Closed,
    Open(Arc<Description>),
    /// `covered` is set once a request on a handle opened under the lease showed
    /// that the guest kernel finished that open, and with it the drop of the
    /// pages it read before the lease.
    Held {
        file: LeaseFile,
        covered: bool,
    },
    Recalling {
        file: LeaseFile,
        recall: OpenRecall,
        then: Then,
    },
    /// Every request of the session that reads or writes the file waits until
    /// the lease is gained again on a description opened with `access`, or no
    /// handle caches the pages any more. `watch` reports the changes of the
    /// file, and `retrying` tries the lease again since the last change.
    Waiting {
        access: OFlags,
        kept: Kept,
        slot: LeaseSlot,
        watch: Option<Watched>,
        retrying: Option<LeaseTask>,
    },
}

#[derive(Debug)]
pub(super) enum Then {
    /// Another opener broke the lease, and the cached handles wait for that
    /// opener, whose changes the watch reports. With no watch, their requests
    /// fail.
    Break(Option<Watched>),
    /// An open of the session reads or writes the file in a way its description
    /// does not, the budget needs the slot, or the handles of the session are
    /// closed while another cache of the file waits. Cached handles wait
    /// meanwhile.
    Release,
    Settle,
}

#[derive(Debug)]
pub(super) struct OpenRecall {
    pub(super) id: u64,
    pub(super) _deadline: LeaseTask,
}

#[derive(Debug)]
pub(super) enum Kept {
    /// Kept open while no other session of the server has the file open in a
    /// way the lease excludes: the opener the handles wait for is another
    /// process.
    Open(Arc<Description>),
    /// Closed, because another session opens the file. The description lives on
    /// only while the locks of the session are on it.
    Closed(Weak<Description>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Pages {
    /// Across opens: the lease is held, and the guest kernel finished an open
    /// under it.
    Kept,
    /// For the lifetime of the handle, under the lease: the guest kernel drops
    /// the pages it read before at this open.
    Taken,
    /// Not at all: no lease shows that nobody else writes the file.
    Uncached,
}

impl Lease {
    pub(super) fn description(&self) -> Option<&Arc<Description>> {
        match self {
            Self::Open(description) => Some(description),
            Self::Held { file, .. } | Self::Recalling { file, .. } => Some(file.description()),
            Self::Waiting { .. } | Self::Closed => None,
        }
    }

    pub(super) fn access(&self) -> Option<OFlags> {
        match self {
            Self::Waiting { access, .. } => Some(*access),
            _ => self.description().map(|description| description.access()),
        }
    }

    pub(super) fn holds(&self) -> Option<Kind> {
        match self {
            Self::Waiting {
                kept: Kept::Open(description),
                ..
            } => Some(Kind::of(description.access())),
            Self::Waiting { .. } => None,
            _ => self.access().map(Kind::of),
        }
    }

    /// While the lease is lost to another opener, an open caches no pages: a
    /// handle that cached them would make the cached handles wait for as long
    /// as it is open, and that opener may itself wait for a request of the
    /// handle.
    pub(super) fn pages(&self, cached: usize, widen: bool) -> Pages {
        match self {
            Self::Held { covered: true, .. } => Pages::Kept,
            Self::Held { covered: false, .. } => Pages::Taken,
            Self::Recalling {
                then: Then::Settle, ..
            } if cached > 0 => Pages::Taken,
            Self::Recalling {
                then: Then::Release,
                ..
            }
            | Self::Waiting { .. }
                if cached > 0 && widen =>
            {
                Pages::Taken
            }
            _ => Pages::Uncached,
        }
    }

    pub(super) fn after(
        file: LeaseFile,
        then: Then,
        replied: bool,
        (handles, cached): (usize, usize),
        watch: impl FnOnce(BorrowedFd<'_>, Kind) -> Option<Watched>,
    ) -> Self {
        let watched = match then {
            // A recall without a reply may leave pages in place, which the
            // next open that gets no flags drops.
            Then::Settle => {
                return Self::Held {
                    file,
                    covered: replied,
                };
            }
            Then::Break(watched) => Some(watched),
            Then::Release => None,
        };
        lease::give_up(file.fd());
        if cached == 0 {
            let (description, _slot) = file.into_parts();
            return if handles > 0 {
                Self::Open(description)
            } else {
                Self::Closed
            };
        }
        let watch = watched.unwrap_or_else(|| watch(file.fd(), file.kind()));
        let (description, slot) = file.into_parts();
        Self::Waiting {
            access: description.access(),
            kept: Kept::Open(description),
            slot,
            watch,
            retrying: None,
        }
    }
}

impl Kept {
    pub(super) fn description(&self) -> Option<Arc<Description>> {
        match self {
            Self::Open(description) => Some(Arc::clone(description)),
            Self::Closed(description) => description.upgrade(),
        }
    }

    /// The description stored here would block a lease of another session.
    pub(super) fn close(&mut self) {
        if let Self::Open(description) = self {
            *self = Self::Closed(Arc::downgrade(description));
        }
    }
}

impl OpenRecall {
    pub(super) fn close(self, recalls: &Recalls) {
        recalls.close(self.id);
    }
}
