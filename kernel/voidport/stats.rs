// SPDX-License-Identifier: GPL-2.0

use kernel::debugfs::{Dir, File};
use kernel::fmt;
use kernel::prelude::*;
use kernel::sync::atomic::{Atomic, Relaxed};

struct Counter(Atomic<u64>);

impl Counter {
    const fn new() -> Self {
        Self(Atomic::new(0))
    }

    fn add(&self, count: u64) {
        self.0.fetch_add(count, Relaxed);
    }

    fn increment(&self) -> u64 {
        self.0.fetch_add(1, Relaxed) + 1
    }

    fn decrement(&self) {
        crate::compat::decrement(&self.0);
    }

    fn raise(&self, seen: u64) {
        let mut current = self.0.load(Relaxed);
        while seen > current {
            match self.0.cmpxchg(current, seen, Relaxed) {
                Ok(_) => break,
                Err(actual) => current = actual,
            }
        }
    }

    fn get(&self) -> u64 {
        self.0.load(Relaxed)
    }
}

macro_rules! counters {
    ($($(#[$doc:meta])* $name:ident,)+) => {
        struct Stats {
            $($(#[$doc])* $name: Counter,)+
        }

        static STATS: Stats = Stats {
            $($name: Counter::new(),)+
        };

        impl Stats {
            fn files(
                &'static self,
            ) -> impl ExactSizeIterator<Item = (&'static CStr, &'static Counter)> {
                [$((
                    crate::compat::kernel_cstr(const {
                        match core::ffi::CStr::from_bytes_with_nul(
                            concat!(stringify!($name), "\0").as_bytes(),
                        ) {
                            Ok(name) => name,
                            Err(_) => panic!("the name of a counter contains a NUL byte"),
                        }
                    }),
                    &self.$name,
                ),)+]
                .into_iter()
            }
        }
    };
}

counters! {
    requests_in_flight,
    /// The most requests that ever waited at once.
    requests_peak,
    /// The requests in flight that read file data.
    reads_in_flight,
    /// The most reads that ever waited at once.
    reads_peak,
    replies_live,
    connections_live,
    /// Connections that ended by failure.
    connections_lost,
    /// Requests cancelled by a signal before the module sent them.
    cancelled,
    /// Callers taken away by a signal after the request was sent.
    interrupted,
    /// Replies consumed for callers that had left.
    orphans,
    /// Lookup counts granted by entry replies.
    nodes_admitted,
    nodes_forgotten,
    /// Handles granted by open replies.
    handles_opened,
    handles_released,
    /// References given back by a FORGET that was sent or a RELEASE that was
    /// answered.
    cleanup_sent,
    /// References given back because the connection that granted them ended.
    cleanup_teardown,
}

#[derive(Clone, Copy)]
pub(crate) enum Gauge {
    Requests,
    /// A request that reads file data. It is counted in [`Gauge::Requests`] too.
    Reads,
    Replies,
    Connections,
}

impl Gauge {
    fn now(self) -> &'static Counter {
        match self {
            Self::Requests => &STATS.requests_in_flight,
            Self::Reads => &STATS.reads_in_flight,
            Self::Replies => &STATS.replies_live,
            Self::Connections => &STATS.connections_live,
        }
    }

    fn peak(self) -> Option<&'static Counter> {
        match self {
            Self::Requests => Some(&STATS.requests_peak),
            Self::Reads => Some(&STATS.reads_peak),
            Self::Replies | Self::Connections => None,
        }
    }
}

pub(crate) struct Counted(Gauge);

impl Counted {
    pub(crate) fn new(gauge: Gauge) -> Self {
        let now = gauge.now().increment();
        if let Some(peak) = gauge.peak() {
            peak.raise(now);
        }
        Self(gauge)
    }
}

impl Drop for Counted {
    fn drop(&mut self) {
        self.0.now().decrement();
    }
}

/// What the server granted and the module gives back later.
#[derive(Clone, Copy)]
pub(crate) enum Reference {
    Node,
    Handle,
}

#[derive(Clone, Copy)]
pub(crate) enum Discharge {
    /// The server was told: a FORGET was sent, or a RELEASE was answered.
    Sent,
    /// The connection ended first, so no message was sent. The server clears
    /// what a connection granted when it ends.
    Teardown,
}

pub(crate) enum Event {
    Cancelled,
    Interrupted,
    Orphaned,
    ConnectionLost,
    Admitted {
        reference: Reference,
        count: u64,
    },
    Discharged {
        reference: Reference,
        count: u64,
        by: Discharge,
    },
}

pub(crate) fn record(event: Event) {
    match event {
        Event::Cancelled => STATS.cancelled.add(1),
        Event::Interrupted => STATS.interrupted.add(1),
        Event::Orphaned => STATS.orphans.add(1),
        Event::ConnectionLost => STATS.connections_lost.add(1),
        Event::Admitted { reference, count } => match reference {
            Reference::Node => STATS.nodes_admitted.add(count),
            Reference::Handle => STATS.handles_opened.add(count),
        },
        Event::Discharged {
            reference,
            count,
            by,
        } => {
            match reference {
                Reference::Node => STATS.nodes_forgotten.add(count),
                Reference::Handle => STATS.handles_released.add(count),
            }
            match by {
                Discharge::Sent => STATS.cleanup_sent.add(count),
                Discharge::Teardown => STATS.cleanup_teardown.add(count),
            }
        }
    }
}

fn render(counter: &&Counter, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    writeln!(f, "{}", counter.get())
}

pub(crate) struct Published {
    _files: KVec<Pin<KBox<File<&'static Counter>>>>,
    _dir: Dir,
}

pub(crate) fn publish() -> Result<Published> {
    let dir = Dir::new(crate::compat::kernel_cstr(c"voidport"));
    let counters = STATS.files();
    let mut files = KVec::with_capacity(counters.len(), GFP_KERNEL)?;
    for (name, counter) in counters {
        let file = KBox::pin_init(dir.read_callback_file(name, counter, &render), GFP_KERNEL)?;
        files.push(file, GFP_KERNEL)?;
    }
    Ok(Published {
        _files: files,
        _dir: dir,
    })
}
