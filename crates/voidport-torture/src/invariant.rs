//! The invariants, asserted continuously while the load runs.
//!
//! The design's robustness mandate is a statement about *degradation*: under
//! everything at once the software may use every resource it has, and what it
//! may not do is starve, stall or wedge. That distinction is what this module
//! encodes. Nothing here is a performance target — a window that is ten times
//! slower than the last one violates nothing — and everything here is a
//! liveness or boundedness statement:
//!
//! 1. **Throughput never collapses.** Over a trailing window, the harness as a
//!    whole completed *something*. Zero is the only forbidden number.
//! 2. **Per-class latency stays under a stated ceiling.** The 99th percentile
//!    of a window, against the generous per-class bounds in
//!    [`Class::latency_ceiling`](crate::metrics::Class::latency_ceiling).
//! 3. **Every class keeps making progress.** A class that has completed
//!    nothing for the watchdog interval is deadlocked, whatever the aggregate
//!    is doing.
//! 4. **The server's holdings stay bounded** relative to the working set:
//!    descriptors, cache-resident node descriptors, threads, nodes, handles and
//!    resident memory.
//!    *What the working set is* took measuring. A node lives for as long as the
//!    guest kernel holds the lookup it came from, and a kernel with no memory
//!    pressure holds a cold dentry forever. So a run that keeps creating names
//!    (churn, rename) while a walk enumerates them grows the server's node
//!    table linearly with *names ever named*, not with names currently on disk:
//!    measured here at ~75 nodes a second, and measured to fall straight back
//!    to the baseline the instant the guest's caches are dropped. That is the
//!    guest holding, not the server leaking, and the node bound is stated
//!    accordingly — the live working set plus one node per name the run
//!    created.
//!    **Descriptors no longer follow nodes** (2026-08-15: they did, and an
//!    AOSP-scale walk exhausted the table at the rate of names ever resolved).
//!    A node's `O_PATH` pin is a slot in a bounded cache, so the descriptor
//!    bound is the cache's budget plus the handles plus the grafts plus a
//!    constant — a number that does *not* grow with the names the run makes —
//!    and the cache's own resident counter is asserted against its budget
//!    directly, which is the only assertion `/proc/<pid>/fd` cannot make.
//! 5. **And they are all given back.** The bound above is loose by
//!    construction, so the sharp check is at the end: once every mount is down,
//!    the server must hold no session, no node, no handle, and no more
//!    descriptors than it started with. A leak of any rate fails this,
//!    whatever the guest was caching while the run was on.
//! 6. **No transport-level errno appears.** A guest operation may fail — a
//!    racing unlink makes `ENOENT` the correct answer — but `EIO` or
//!    `ENOTCONN` means the mount broke, which is the failure this whole
//!    exercise is looking for.
//! 7. **The shutdown is clean**, which is checked once at the end: no mount,
//!    no loop device and no worker left behind.
//! 8. **What the harness itself proves, it files.** Three classes assert
//!    contracts no counter can see — a mount that healed after a restart, a
//!    name that stopped resolving when its rule landed, a session that kept
//!    serving after its listener was removed — and file a violation the moment
//!    they see otherwise. Those go through [`Findings`], and the run collects
//!    them beside the watcher's own.
//!
//! One deliberate exemption runs through all of this: the [`Outage`] windows in
//! which the harness *itself* took the server away. Inside them the mounts are
//! contractually allowed to stall and then answer `EIO`, so what those windows
//! carry is not judged on throughput, latency or transport errnos.
//!
//! The exemption is scoped to the stretch of the run an outage actually
//! covered, and to nothing else. A judged window is ten seconds of *clean*
//! time, stitched together out of the stretches between the observations no
//! outage overlapped; the stretches an outage did overlap contribute neither
//! their counts nor their time. Standing a whole ten-second window down because
//! an outage touched it would look equivalent and is not: at any restart
//! cadence shorter than the window — which every heavy run has — every window
//! is touched, and all three checks would be switched off for the whole run
//! without a word. The per-class watchdog, the resource bounds and every
//! worker-filed finding stay armed throughout, outage or not, which is where a
//! restart that wedged something would show.

use std::collections::VecDeque;
use std::fmt;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde::Serialize;

use crate::metrics::{Class, ClassSnapshot, Metrics};
use crate::resource::Sample;

/// The errnos that mean the mount itself failed, not the operation.
///
/// Everything else a torture worker meets is a legitimate answer under
/// concurrent churn — `ENOENT` for a name another worker just unlinked,
/// `EEXIST` for one it just created, `EBUSY` for a mountpoint still in use,
/// `EAGAIN` for a lock another owner holds.
const TRANSPORT_ERRNOS: [(i32, &str); 4] = [
    (5, "EIO"),
    (19, "ENODEV"),
    (107, "ENOTCONN"),
    (110, "ETIMEDOUT"),
];

/// What the harness refuses to see.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "violation", rename_all = "kebab-case")]
pub enum Violation {
    /// Nothing at all completed over a whole window.
    ThroughputCollapse {
        /// How long the window that saw nothing was.
        window_ms: u64,
        /// When it ended.
        elapsed_ms: u64,
    },
    /// A class's 99th percentile passed its ceiling.
    Latency {
        /// The class.
        class: Class,
        /// The observed p99, as the bound of the bucket it fell in.
        observed_ms: u64,
        /// The ceiling it passed.
        ceiling_ms: u64,
        /// When the window ended.
        elapsed_ms: u64,
    },
    /// A class stopped completing operations altogether.
    NoProgress {
        /// The class.
        class: Class,
        /// How long it has completed nothing.
        stalled_ms: u64,
        /// When that was noticed.
        elapsed_ms: u64,
    },
    /// The server holds more of something than the working set can explain.
    Resource {
        /// What was sampled: `fds`, `node_descriptors`, `threads`, `nodes`,
        /// `handles`, `rss_kib`.
        quantity: &'static str,
        /// What was observed.
        observed: u64,
        /// The bound it passed.
        ceiling: u64,
        /// When it was sampled.
        elapsed_ms: u64,
    },
    /// A guest operation failed the way a broken mount fails.
    Transport {
        /// The class that met it.
        class: Class,
        /// The errno's name.
        errno: &'static str,
        /// How many times it was met in the window.
        count: u64,
        /// When the window ended.
        elapsed_ms: u64,
    },
    /// Something the run created was still mounted after the teardown.
    LeakedMount {
        /// The mountpoint.
        path: String,
    },
    /// A loop device still backed by the run's work directory.
    LeakedLoopDevice {
        /// The device.
        device: String,
        /// What it was backing.
        backing: String,
    },
    /// The server was still holding something after every mount came down.
    Retained {
        /// What was sampled: `fds`, `sessions`, `nodes`, `handles`.
        quantity: &'static str,
        /// What it still held.
        observed: u64,
        /// What it was allowed to still hold.
        ceiling: u64,
    },
    /// Workers that never finished, so the harness could not shut down
    /// cleanly. This is the join-side face of a deadlock.
    UnfinishedWorkers {
        /// How many did not join.
        count: usize,
    },
    /// A mount did not serve again after the server came back, which is the
    /// reconnect contract's healing failing to happen.
    MountUnhealed {
        /// The mountpoint that never answered.
        mountpoint: String,
        /// How long it was given, in milliseconds.
        patience_ms: u64,
        /// What it answered instead.
        detail: String,
    },
    /// The state file was not what the last persisted mutation left, after the
    /// server was stopped without warning.
    CrashInconsistent {
        /// How the restart arm stopped the server: `graceful` or `hard`.
        stop: &'static str,
        /// What was found instead.
        detail: String,
    },
    /// A class proved one of the contracts it drives wrong.
    ///
    /// This is where the assertions a counter cannot make are reported: a
    /// hidden name that still resolved, an owner the ownership policy does not
    /// allow, a session that stopped serving when its listener was removed, a
    /// control mutation the server refused under load.
    Contract {
        /// The class that proved it.
        class: Class,
        /// What it did, and what it saw.
        detail: String,
        /// When it saw it.
        elapsed_ms: u64,
    },
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ThroughputCollapse {
                window_ms,
                elapsed_ms,
            } => write!(
                f,
                "throughput collapsed to zero: nothing completed in {window_ms} ms, \
                 at {elapsed_ms} ms into the run"
            ),
            Self::Latency {
                class,
                observed_ms,
                ceiling_ms,
                elapsed_ms,
            } => write!(
                f,
                "{}: p99 latency {observed_ms} ms passed its {ceiling_ms} ms ceiling, \
                 at {elapsed_ms} ms into the run",
                class.name()
            ),
            Self::NoProgress {
                class,
                stalled_ms,
                elapsed_ms,
            } => write!(
                f,
                "{}: nothing completed for {stalled_ms} ms, at {elapsed_ms} ms into the run",
                class.name()
            ),
            Self::Resource {
                quantity,
                observed,
                ceiling,
                elapsed_ms,
            } => write!(
                f,
                "the server holds {observed} {quantity}, past its bound of {ceiling}, \
                 at {elapsed_ms} ms into the run"
            ),
            Self::Transport {
                class,
                errno,
                count,
                elapsed_ms,
            } => write!(
                f,
                "{}: {count} operations failed {errno}, at {elapsed_ms} ms into the run",
                class.name()
            ),
            Self::Retained {
                quantity,
                observed,
                ceiling,
            } => write!(
                f,
                "the server still holds {observed} {quantity} with every mount down, \
                 past the {ceiling} it may keep"
            ),
            Self::LeakedMount { path } => write!(f, "{path} is still mounted after the teardown"),
            Self::LeakedLoopDevice { device, backing } => {
                write!(
                    f,
                    "{device} is still backed by {backing} after the teardown"
                )
            }
            Self::UnfinishedWorkers { count } => {
                write!(f, "{count} workers never finished")
            }
            Self::MountUnhealed {
                mountpoint,
                patience_ms,
                detail,
            } => write!(
                f,
                "{mountpoint} did not serve again within {patience_ms} ms of the server \
                 coming back: {detail}"
            ),
            Self::CrashInconsistent { stop, detail } => write!(
                f,
                "after a {stop} stop the state file was not what the last persisted \
                 mutation left: {detail}"
            ),
            Self::Contract {
                class,
                detail,
                elapsed_ms,
            } => write!(
                f,
                "{}: {detail}, at {elapsed_ms} ms into the run",
                class.name()
            ),
        }
    }
}

/// The windows in which the harness itself took the server away.
///
/// A restart is the one thing the load generator does that the server is
/// *allowed* to answer badly for: the reconnect contract says a mount stalls
/// for its window and then answers `EIO` until the server is back. Suppressing
/// those windows by a timer would be a hole; this is not a timer. An outage
/// opens when the restart arm is about to signal and closes only when it has
/// proven every mount serving again, so what the checks stand down for is
/// exactly the interval the harness knows it caused, and the healing that ends
/// it is itself asserted.
#[derive(Debug, Default)]
pub struct Outage {
    /// How many outages are open. More than one at a time cannot happen — the
    /// restart class is a single worker — but the counter is what makes
    /// "currently away" a question with an answer.
    open: AtomicU64,
    /// Every outage as the interval it occupied, `[open_ms, close_ms]`, with
    /// the one still open ending at [`u64::MAX`].
    ///
    /// The intervals and not a single "last closed" mark, because what the
    /// checks ask is whether an outage covered *this* stretch of the run, and
    /// one mark can only answer that about the most recent one.
    windows: Mutex<VecDeque<(u64, u64)>>,
    /// How many outages have closed. A worker that took the server's answer
    /// before the restart and compares it after reads this to know whether the
    /// two answers are even about the same server lifetime.
    generation: AtomicU64,
}

/// How many outage intervals are kept.
///
/// The checks only ever ask about the last few seconds of a run, so this is
/// generous by orders of magnitude; it exists so an hours-long soak's record
/// cannot grow with its restart count.
const REMEMBERED_OUTAGES: usize = 64;

impl Outage {
    /// Opens an outage at `elapsed_ms`: from here the server is deliberately
    /// unavailable.
    pub fn open(&self, elapsed_ms: u64) {
        let mut windows = self
            .windows
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if windows.len() == REMEMBERED_OUTAGES {
            windows.pop_front();
        }
        windows.push_back((elapsed_ms, u64::MAX));
        self.open.fetch_add(1, Ordering::SeqCst);
    }

    /// Closes it, `elapsed_ms` into the run.
    pub fn close(&self, elapsed_ms: u64) {
        if let Some(window) = self
            .windows
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .back_mut()
        {
            window.1 = elapsed_ms;
        }
        self.generation.fetch_add(1, Ordering::SeqCst);
        self.open.fetch_sub(1, Ordering::SeqCst);
    }

    /// How many outages have closed so far.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }

    /// Whether the server is deliberately away right now.
    #[must_use]
    pub fn open_now(&self) -> bool {
        self.open.load(Ordering::SeqCst) > 0
    }

    /// Whether an outage covered any part of `[from_ms, to_ms]`.
    #[must_use]
    pub fn overlaps(&self, from_ms: u64, to_ms: u64) -> bool {
        self.windows
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .iter()
            .any(|(opened, closed)| *opened <= to_ms && *closed >= from_ms)
    }
}

/// Where a worker files a violation it proved itself.
///
/// The watcher's invariants are read off counters, which is why they can be
/// checked once a second from one thread. These cannot: only the worker that
/// added a hidden rule knows the name it is about, and only the arm that
/// restarted the server knows which mounts owed it a recovery. So a worker
/// files what it proved, loudly and at once, and the run collects it beside
/// everything the watcher found.
#[derive(Debug, Default)]
pub struct Findings {
    filed: Mutex<Vec<Violation>>,
}

impl Findings {
    /// Files one violation, and says so on stderr immediately.
    pub fn file(&self, violation: Violation) {
        eprintln!("!!! voidport-torture: {violation}");
        self.filed
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .push(violation);
    }

    /// Takes everything filed since the last call.
    ///
    /// Draining, not copying: the run logs each violation exactly once, and it
    /// drains repeatedly while the load is on so a soak's log carries a finding
    /// at the second it happened.
    #[must_use]
    pub fn drain(&self) -> Vec<Violation> {
        std::mem::take(
            &mut *self
                .filed
                .lock()
                .unwrap_or_else(|poison| poison.into_inner()),
        )
    }
}

/// What the server holds descriptors for besides its node cache and its
/// handles: the listeners, the control socket and its connections, the state
/// file, the pinned graft targets, and the re-pins in flight while the run
/// samples. Generous on purpose — this is a leak check, not an audit.
const DESCRIPTOR_SLACK: u64 = 2048;

/// The largest node descriptor budget a server derives for itself, and so the
/// bound a run is held to when it cannot read the server's own number.
///
/// It mirrors the server's own ceiling (`voidportd`'s `DERIVED_CEILING`); a run
/// against a server whose operator configured something larger has to be told
/// about it through the control socket, which every real run has.
const DERIVED_BUDGET_CEILING: u64 = 262_144;

/// The bounds the run is held to.
///
/// The resource bounds are computed from the run's own shape — the working set,
/// the mounts, the workers — because "bounded relative to working set" is the
/// criterion the design fixed, and an absolute number would mean something
/// different at every intensity.
#[derive(Clone, Copy, Debug)]
pub struct Ceilings {
    /// Descriptors the server may hold.
    pub fds: u64,
    /// Node descriptors its cache may hold resident: the budget itself, which
    /// the server publishes beside the count.
    pub node_descriptors: u64,
    /// Threads the server may run. This is the async-lock-wait property: a
    /// storm of waiters may not become a storm of threads.
    pub threads: u64,
    /// Nodes it may hold across every session.
    pub nodes: u64,
    /// Handles it may hold open across every session.
    pub handles: u64,
    /// Resident kibibytes it may occupy.
    pub rss_kib: u64,
    /// The trailing window the throughput and latency checks read.
    pub window: Duration,
    /// How long a class may complete nothing before it is called deadlocked.
    pub watchdog: Duration,
    /// How long after the start the checks stay quiet, while the mounts come
    /// up and the working set is built.
    pub grace: Duration,
}

impl Ceilings {
    /// The bounds a run of this shape is held to.
    ///
    /// Each term is the working set's own contribution plus a slack that a
    /// correct server cannot need but a leaking one blows through in seconds:
    /// a node per entry per mount, a handle per open file per worker, and a
    /// resident set that may double.
    ///
    /// The descriptor term is the one that is *not* a function of the working
    /// set any more: the node cache's budget, plus the handles, plus the
    /// [`DESCRIPTOR_SLACK`] the grafts, the listeners and the in-flight
    /// re-pins live in. A server that goes back to a descriptor per node fails
    /// this within seconds of the walk starting, which is exactly the field
    /// failure this bound exists to catch.
    #[must_use]
    pub fn for_run(baseline: &Sample, entries: u64, mounts: u64, workers: u64) -> Self {
        let nodes = entries * mounts * 4 + 4096;
        let handles = workers * 64 + 1024;
        // A server that publishes no budget — no control socket to ask — is
        // held to the largest budget it could have derived for itself, which is
        // the honest bound in the absence of the number itself.
        let node_descriptors = baseline
            .node_descriptor_budget
            .unwrap_or(DERIVED_BUDGET_CEILING);
        Self {
            fds: baseline.fds.unwrap_or(0) + node_descriptors + handles + DESCRIPTOR_SLACK,
            node_descriptors,
            // What this catches is *unbounded* thread growth, and the number is
            // chosen so that it catches nothing else. A server's blocking pool
            // grows on demand to its runtime's own maximum — 512 threads, by
            // tokio's default — and how far it grows is a property of the load,
            // not of correctness: measured at 160 threads under one run of this
            // harness and 266 under a heavier one. A bound tight enough to
            // distinguish those would fail honest runs. The shape that would
            // fail here is a thread per parked waiter, which the lock storm
            // stacks in the thousands; the shape that stops *below* the pool
            // maximum and starves instead is caught by the liveness invariants,
            // which is where a starving server actually shows.
            threads: baseline.threads.unwrap_or(0) + 1024,
            nodes,
            handles,
            rss_kib: baseline.rss_kib.unwrap_or(0).max(65_536) * 4 + 1_048_576,
            window: Duration::from_secs(10),
            watchdog: Duration::from_secs(120),
            grace: Duration::from_secs(15),
        }
    }
}

/// What a judged window holds: the counts of the stretches no outage covered.
#[derive(Debug, Default)]
struct WindowCounts {
    /// Per class, the operations and their latencies.
    classes: Vec<(Class, ClassSnapshot)>,
    /// Per class, the transport errnos met.
    errnos: Vec<(Class, [u64; TRANSPORT_ERRNOS.len()])>,
    /// How much clean time they add up to.
    clean_ms: u64,
}

impl WindowCounts {
    /// Adds one clean stretch: what every class did in it, and how long it was.
    fn add(
        &mut self,
        classes: &[(Class, ClassSnapshot)],
        errnos: &[(Class, [u64; TRANSPORT_ERRNOS.len()])],
        clean_ms: u64,
    ) {
        for (class, counts) in classes {
            match self
                .classes
                .iter_mut()
                .find(|(candidate, _)| candidate == class)
            {
                Some((_, held)) => *held = held.plus(counts),
                None => self.classes.push((*class, *counts)),
            }
        }
        for (class, met) in errnos {
            match self
                .errnos
                .iter_mut()
                .find(|(candidate, _)| candidate == class)
            {
                Some((_, held)) => {
                    for (index, count) in met.iter().enumerate() {
                        held[index] = held[index].saturating_add(*count);
                    }
                }
                None => self.errnos.push((*class, *met)),
            }
        }
        self.clean_ms = self.clean_ms.saturating_add(clean_ms);
    }

    /// Starts an empty window.
    fn clear(&mut self) {
        self.classes.clear();
        self.errnos.clear();
        self.clean_ms = 0;
    }
}

/// The continuous check, driven one observation at a time.
#[derive(Debug)]
pub struct Watch {
    ceilings: Ceilings,
    classes: Vec<Class>,
    /// The class counters as of the last observation.
    last_counts: Vec<(Class, ClassSnapshot)>,
    /// The transport-errno counts as of the same observation.
    last_errnos: Vec<(Class, [u64; TRANSPORT_ERRNOS.len()])>,
    /// When that observation was taken.
    last_observed_ms: u64,
    /// What the clean stretches since the last judged window have added up to.
    window: WindowCounts,
    /// Clean milliseconds since the run started, which is the clock the
    /// window-based checks run on.
    clean_ms: u64,
    /// That clock as of the last time the aggregate completion count moved,
    /// and the count it moved to.
    progress_ms: u64,
    completed: u64,
}

impl Watch {
    /// A check over `classes`, held to `ceilings`.
    #[must_use]
    pub fn new(ceilings: Ceilings, classes: &[Class], metrics: &Metrics) -> Self {
        Self {
            ceilings,
            classes: classes.to_vec(),
            last_counts: metrics.snapshot(),
            last_errnos: transport_errnos(classes, metrics),
            last_observed_ms: 0,
            window: WindowCounts::default(),
            clean_ms: 0,
            progress_ms: 0,
            completed: 0,
        }
    }

    /// Observes the run as it stands, and reports what it found wrong.
    ///
    /// Called once a second by the sampler; the window-based checks fire only
    /// when a window has actually elapsed, so the cost of observing is a few
    /// atomic loads.
    ///
    /// `outage` is what the restart arm has done to the server, and it is
    /// scoped to the stretch it covered and no further. The stretch between two
    /// observations that an outage overlapped contributes nothing — not its
    /// latencies, not its transport errnos, not its time — and every other
    /// stretch contributes exactly as it would in a run that never restarted.
    /// A window is therefore ten seconds *of clean time*, stitched across as
    /// many outages as it takes; the alternative, standing a whole window down
    /// because an outage touched it, silently switches these three checks off
    /// altogether at any cadence that restarts more often than the window is
    /// long.
    #[must_use]
    pub fn observe(
        &mut self,
        elapsed: Duration,
        metrics: &Metrics,
        sample: &Sample,
        outage: &Outage,
    ) -> Vec<Violation> {
        let elapsed_ms = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX);
        let mut violations = Vec::new();
        let snapshot = metrics.snapshot();
        let errnos = transport_errnos(&self.classes, metrics);
        let created = created_names(&snapshot);
        let total: u64 = snapshot.iter().map(|(_, class)| class.completed).sum();

        let clean = !outage.overlaps(self.last_observed_ms, elapsed_ms);
        let stretch_ms = elapsed_ms.saturating_sub(self.last_observed_ms);
        if clean {
            self.clean_ms = self.clean_ms.saturating_add(stretch_ms);
            self.window.add(
                &deltas(&snapshot, &self.last_counts),
                &errno_deltas(&errnos, &self.last_errnos),
                stretch_ms,
            );
        }
        if total > self.completed {
            self.completed = total;
            self.progress_ms = self.clean_ms;
        }
        self.last_counts = snapshot;
        self.last_errnos = errnos;
        self.last_observed_ms = elapsed_ms;

        if elapsed < self.ceilings.grace {
            // The mounts are still coming up and the working set is still
            // being written; nothing here is meaningful yet.
            self.window.clear();
            return violations;
        }

        violations.extend(self.throughput(elapsed_ms));
        violations.extend(self.progress(elapsed_ms, metrics));
        violations.extend(self.resources(elapsed_ms, sample, created));
        if self.window.clean_ms
            >= u64::try_from(self.ceilings.window.as_millis()).unwrap_or(u64::MAX)
        {
            violations.extend(self.latencies(elapsed_ms));
            violations.extend(self.transport(elapsed_ms));
            self.window.clear();
        }
        violations
    }

    /// Invariant 1: something completed over the trailing window.
    ///
    /// Measured on the clean clock, so the window is ten seconds in which the
    /// server was there to answer. A completion is progress whenever it
    /// happened, outage or not — work completing is work completing — and what
    /// is forbidden is a whole clean window in which nothing did.
    fn throughput(&self, elapsed_ms: u64) -> Option<Violation> {
        let window_ms = u64::try_from(self.ceilings.window.as_millis()).unwrap_or(u64::MAX);
        (self.clean_ms.saturating_sub(self.progress_ms) >= window_ms).then_some(
            Violation::ThroughputCollapse {
                window_ms,
                elapsed_ms,
            },
        )
    }

    /// Invariant 2: every class's p99 is under its ceiling.
    fn latencies(&self, elapsed_ms: u64) -> Vec<Violation> {
        let mut violations = Vec::new();
        for (class, counts) in &self.window.classes {
            if !self.classes.contains(class) {
                continue;
            }
            let Some(p99) = counts.quantile(0.99) else {
                continue;
            };
            let ceiling = class.latency_ceiling();
            if p99 > ceiling {
                violations.push(Violation::Latency {
                    class: *class,
                    observed_ms: u64::try_from(p99.as_millis()).unwrap_or(u64::MAX),
                    ceiling_ms: u64::try_from(ceiling.as_millis()).unwrap_or(u64::MAX),
                    elapsed_ms,
                });
            }
        }
        violations
    }

    /// Invariant 3: no class has gone quiet.
    fn progress(&self, elapsed_ms: u64, metrics: &Metrics) -> Vec<Violation> {
        let watchdog = u64::try_from(self.ceilings.watchdog.as_millis()).unwrap_or(u64::MAX);
        self.classes
            .iter()
            .filter_map(|class| {
                let stalled = elapsed_ms.saturating_sub(metrics.class(*class).last_completion_ms());
                (stalled > watchdog).then_some(Violation::NoProgress {
                    class: *class,
                    stalled_ms: stalled,
                    elapsed_ms,
                })
            })
            .collect()
    }

    /// Invariant 4: the server's holdings are bounded.
    ///
    /// `created` is how many names the run has made so far, and it is added to
    /// the **node** bound for the reason the module header sets out: a node
    /// lives as long as the *guest kernel* holds its lookup, and a guest under
    /// no memory pressure holds cold dentries indefinitely. One node per name
    /// ever named is therefore the honest ceiling here; what catches a real
    /// leak is the check after the mounts come down.
    ///
    /// It is deliberately **not** added to the descriptor bounds. Descriptors
    /// are no longer a function of names resolved, and a bound that grew with
    /// the names the run makes could never notice them becoming one again.
    fn resources(&self, elapsed_ms: u64, sample: &Sample, created: u64) -> Vec<Violation> {
        [
            ("fds", sample.fds, self.ceilings.fds),
            (
                "node_descriptors",
                sample.node_descriptors,
                // The budget the server itself reports in the same sample; the
                // baseline's is the fallback, and they are the same number
                // because the budget is startup-only.
                sample
                    .node_descriptor_budget
                    .unwrap_or(self.ceilings.node_descriptors),
            ),
            ("threads", sample.threads, self.ceilings.threads),
            ("nodes", sample.nodes, self.ceilings.nodes + created),
            ("handles", sample.handles, self.ceilings.handles),
            ("rss_kib", sample.rss_kib, self.ceilings.rss_kib),
        ]
        .into_iter()
        .filter_map(|(quantity, observed, ceiling)| {
            let observed = observed?;
            (observed > ceiling).then_some(Violation::Resource {
                quantity,
                observed,
                ceiling,
                elapsed_ms,
            })
        })
        .collect()
    }

    /// Invariant 5: no transport errno appeared in the window.
    ///
    /// [`Class::Remount`] is exempt, and only it: its operation *is* taking a
    /// transport down, and the kernel reporting a channel that has gone away as
    /// a mount is unmounted is that operation working. Every other class runs
    /// over a mount that stays up for the whole run, so a transport errno there
    /// means what this check is looking for.
    fn transport(&self, elapsed_ms: u64) -> Vec<Violation> {
        let mut violations = Vec::new();
        for (class, counts) in self
            .window
            .errnos
            .iter()
            .filter(|(class, _)| *class != Class::Remount)
        {
            for (index, (_, name)) in TRANSPORT_ERRNOS.iter().enumerate() {
                let count = counts[index];
                if count > 0 {
                    violations.push(Violation::Transport {
                        class: *class,
                        errno: name,
                        count,
                        elapsed_ms,
                    });
                }
            }
        }
        violations
    }
}

/// What every class did between two observations.
fn deltas(
    now: &[(Class, ClassSnapshot)],
    before: &[(Class, ClassSnapshot)],
) -> Vec<(Class, ClassSnapshot)> {
    now.iter()
        .map(|(class, counts)| {
            let earlier = before
                .iter()
                .find(|(candidate, _)| candidate == class)
                .map_or_else(ClassSnapshot::default, |(_, counts)| *counts);
            (*class, counts.since(&earlier))
        })
        .collect()
}

/// The same for the transport errnos.
fn errno_deltas(
    now: &[(Class, [u64; TRANSPORT_ERRNOS.len()])],
    before: &[(Class, [u64; TRANSPORT_ERRNOS.len()])],
) -> Vec<(Class, [u64; TRANSPORT_ERRNOS.len()])> {
    now.iter()
        .map(|(class, counts)| {
            let earlier = before
                .iter()
                .find(|(candidate, _)| candidate == class)
                .map_or([0; TRANSPORT_ERRNOS.len()], |(_, counts)| *counts);
            (
                *class,
                std::array::from_fn(|index| counts[index].saturating_sub(earlier[index])),
            )
        })
        .collect()
}

/// How many names the run has created so far.
///
/// Only the classes that make new names count: everything else works over
/// names the working set already holds, whose nodes the base bound covers.
fn created_names(snapshot: &[(Class, ClassSnapshot)]) -> u64 {
    snapshot
        .iter()
        .filter(|(class, _)| {
            matches!(
                class,
                Class::Churn | Class::Rename | Class::Special | Class::Rules
            )
        })
        .map(|(_, counts)| counts.completed)
        .sum()
}

/// Invariant 5: what the server may still hold once every mount is down.
///
/// Nothing, is the answer, beyond the descriptors it had before the run: a
/// session that has gone takes its handles, its nodes and their pinned
/// descriptors with it, and that is the whole of the leak check that does not
/// depend on what the guest's caches were doing.
///
/// **Threads are deliberately not checked here**, though they are checked
/// throughout the run. A runtime's worker and blocking pools are grown on
/// demand and retired on their own keep-alive, so a server that has just
/// finished serving a storm legitimately holds a warm pool for a while longer;
/// comparing that against a baseline taken before the load is comparing a warm
/// runtime with a cold one. What matters about threads is that they never
/// tracked the *waiters*, and that is the continuous bound's business.
#[must_use]
pub fn retained(baseline: &Sample, after: &Sample) -> Vec<Violation> {
    [
        ("sessions", after.sessions, 0),
        ("nodes", after.nodes, 0),
        ("handles", after.handles, 0),
        ("fds", after.fds, baseline.fds.unwrap_or(0) + 64),
    ]
    .into_iter()
    .filter_map(|(quantity, observed, ceiling)| {
        let observed = observed?;
        (observed > ceiling).then_some(Violation::Retained {
            quantity,
            observed,
            ceiling,
        })
    })
    .collect()
}

/// Every enabled class's transport-errno counts as they stand.
fn transport_errnos(
    classes: &[Class],
    metrics: &Metrics,
) -> Vec<(Class, [u64; TRANSPORT_ERRNOS.len()])> {
    classes
        .iter()
        .map(|class| {
            let met = metrics.class(*class).errnos();
            let counts = std::array::from_fn(|index| {
                met.iter()
                    .find(|(errno, _)| *errno == TRANSPORT_ERRNOS[index].0)
                    .map_or(0, |(_, count)| *count)
            });
            (*class, counts)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ceilings() -> Ceilings {
        Ceilings {
            fds: 100,
            node_descriptors: 100,
            threads: 100,
            nodes: 100,
            handles: 100,
            rss_kib: 100,
            window: Duration::from_secs(10),
            watchdog: Duration::from_secs(120),
            grace: Duration::from_secs(15),
        }
    }

    fn sample() -> Sample {
        Sample::default()
    }

    /// Nothing is judged while the mounts are still coming up.
    #[test]
    fn the_grace_period_asserts_nothing() {
        let metrics = Metrics::default();
        let mut watch = Watch::new(ceilings(), &Class::ALL, &metrics);
        for second in 0..15 {
            assert!(
                watch
                    .observe(
                        Duration::from_secs(second),
                        &metrics,
                        &sample(),
                        &Outage::default()
                    )
                    .is_empty(),
                "second {second} judged the warmup"
            );
        }
    }

    /// A run that stops completing anything is the one thing the mandate
    /// forbids outright, and it is caught by both the aggregate check and the
    /// per-class watchdog.
    #[test]
    fn a_run_that_stops_completing_anything_is_caught() {
        let metrics = Metrics::default();
        let mut watch = Watch::new(ceilings(), &[Class::Walk], &metrics);
        // Work happens for a while.
        for second in 0..40 {
            metrics.class(Class::Walk).record(
                Duration::from_millis(1),
                None,
                Duration::from_secs(second),
            );
            let found = watch.observe(
                Duration::from_secs(second),
                &metrics,
                &sample(),
                &Outage::default(),
            );
            assert!(found.is_empty(), "second {second}: {found:?}");
        }
        // And then stops. The aggregate window notices first...
        let found = watch.observe(
            Duration::from_secs(60),
            &metrics,
            &sample(),
            &Outage::default(),
        );
        assert!(
            found
                .iter()
                .any(|violation| matches!(violation, Violation::ThroughputCollapse { .. })),
            "{found:?}"
        );
        // ...and the class watchdog notices once its own patience runs out.
        let found = watch.observe(
            Duration::from_secs(200),
            &metrics,
            &sample(),
            &Outage::default(),
        );
        assert!(
            found
                .iter()
                .any(|violation| matches!(violation, Violation::NoProgress { .. })),
            "{found:?}"
        );
    }

    /// A window whose p99 passes the class ceiling is reported, and a window of
    /// fast operations is not.
    #[test]
    fn a_slow_window_is_reported_once_the_window_closes() {
        let metrics = Metrics::default();
        let mut watch = Watch::new(ceilings(), &[Class::Walk], &metrics);
        let walk = metrics.class(Class::Walk);
        for second in 0..16 {
            walk.record(Duration::from_millis(1), None, Duration::from_secs(second));
            let _ = watch.observe(
                Duration::from_secs(second),
                &metrics,
                &sample(),
                &Outage::default(),
            );
        }
        // Walk's ceiling is two seconds; a window of ten-second operations is
        // over it however generous it is.
        for _ in 0..100 {
            walk.record(Duration::from_secs(10), None, Duration::from_secs(20));
        }
        let found = watch.observe(
            Duration::from_secs(30),
            &metrics,
            &sample(),
            &Outage::default(),
        );
        assert!(
            found.iter().any(|violation| matches!(
                violation,
                Violation::Latency {
                    class: Class::Walk,
                    ..
                }
            )),
            "{found:?}"
        );
    }

    /// A leak is a bound passed, and every sampled quantity has one.
    #[test]
    fn holdings_past_their_bound_are_reported_per_quantity() {
        let metrics = Metrics::default();
        let mut watch = Watch::new(ceilings(), &[Class::Walk], &metrics);
        metrics
            .class(Class::Walk)
            .record(Duration::from_millis(1), None, Duration::from_secs(20));
        let leaking = Sample {
            elapsed_ms: 20_000,
            fds: Some(1_000),
            threads: Some(1_000),
            rss_kib: Some(1_000),
            nodes: Some(1_000),
            handles: Some(1_000),
            sessions: Some(1),
            node_descriptors: Some(1_000),
            node_descriptor_budget: Some(100),
        };
        let found = watch.observe(
            Duration::from_secs(20),
            &metrics,
            &leaking,
            &Outage::default(),
        );
        let quantities: Vec<&str> = found
            .iter()
            .filter_map(|violation| match violation {
                Violation::Resource { quantity, .. } => Some(*quantity),
                _ => None,
            })
            .collect();
        assert_eq!(
            quantities,
            [
                "fds",
                "node_descriptors",
                "threads",
                "nodes",
                "handles",
                "rss_kib"
            ]
        );
    }

    /// The bound the field failure asks for: descriptors are held to the
    /// cache's budget plus the handles plus a constant, and **not** to
    /// anything that grows with the names a run resolves.
    #[test]
    fn the_descriptor_bound_is_the_budget_and_not_the_names_resolved() {
        let baseline = Sample {
            fds: Some(64),
            node_descriptor_budget: Some(512),
            ..Sample::default()
        };
        let ceilings = Ceilings::for_run(&baseline, 1_000, 2, 8);
        assert_eq!(ceilings.node_descriptors, 512);
        assert_eq!(ceilings.fds, 64 + 512 + ceilings.handles + DESCRIPTOR_SLACK);
        assert!(
            ceilings.fds < ceilings.nodes,
            "a node no longer costs a descriptor, so the descriptor bound must \
             be far below the node bound of a large working set"
        );

        // A server that cannot be asked is held to the largest budget it could
        // have derived for itself.
        let unknown = Ceilings::for_run(&Sample::default(), 1_000, 2, 8);
        assert_eq!(unknown.node_descriptors, DERIVED_BUDGET_CEILING);
    }

    /// The cache's counter is asserted against the budget the *same sample*
    /// reported, so a run against a server configured differently from the one
    /// the baseline saw is still judged by the right number.
    #[test]
    fn the_resident_pin_counter_is_held_to_the_budget_the_server_publishes() {
        let metrics = Metrics::default();
        let mut watch = Watch::new(ceilings(), &[Class::Walk], &metrics);
        metrics
            .class(Class::Walk)
            .record(Duration::from_millis(1), None, Duration::from_secs(20));
        let full = Sample {
            elapsed_ms: 20_000,
            node_descriptors: Some(64),
            node_descriptor_budget: Some(64),
            ..Sample::default()
        };
        assert!(
            watch
                .observe(Duration::from_secs(20), &metrics, &full, &Outage::default())
                .is_empty(),
            "a cache filled exactly to its budget is the cache working"
        );

        let over = Sample {
            node_descriptors: Some(65),
            ..full
        };
        let found = watch.observe(Duration::from_secs(21), &metrics, &over, &Outage::default());
        assert!(
            found.iter().any(|violation| matches!(
                violation,
                Violation::Resource {
                    quantity: "node_descriptors",
                    observed: 65,
                    ceiling: 64,
                    ..
                }
            )),
            "{found:?}"
        );
    }

    /// `ENOENT` under churn is the filesystem working; `EIO` is it breaking.
    #[test]
    fn only_transport_errnos_are_violations() {
        let metrics = Metrics::default();
        let mut watch = Watch::new(ceilings(), &[Class::Churn], &metrics);
        let churn = metrics.class(Class::Churn);
        for second in 0..16 {
            churn.record(
                Duration::from_millis(1),
                Some(2),
                Duration::from_secs(second),
            );
            let _ = watch.observe(
                Duration::from_secs(second),
                &metrics,
                &sample(),
                &Outage::default(),
            );
        }
        assert!(
            watch
                .observe(
                    Duration::from_secs(30),
                    &metrics,
                    &sample(),
                    &Outage::default()
                )
                .iter()
                .all(|violation| !matches!(violation, Violation::Transport { .. })),
            "a racing ENOENT is not a violation"
        );

        churn.record(Duration::from_millis(1), Some(5), Duration::from_secs(40));
        let found = watch.observe(
            Duration::from_secs(45),
            &metrics,
            &sample(),
            &Outage::default(),
        );
        assert!(
            found.iter().any(|violation| matches!(
                violation,
                Violation::Transport {
                    class: Class::Churn,
                    errno: "EIO",
                    count: 1,
                    ..
                }
            )),
            "{found:?}"
        );
    }

    /// The check that does not care what the guest was caching: with every
    /// mount down, a session, a node or a handle the server still holds is one
    /// it lost, however healthy the run looked while it was on.
    #[test]
    fn nothing_may_be_held_once_the_mounts_are_down() {
        let baseline = Sample {
            fds: Some(3310),
            threads: Some(35),
            ..Sample::default()
        };
        let released = Sample {
            fds: Some(15),
            threads: Some(160),
            sessions: Some(0),
            nodes: Some(0),
            handles: Some(0),
            ..Sample::default()
        };
        assert!(
            retained(&baseline, &released).is_empty(),
            "a warm thread pool is not a holding"
        );

        let leaking = Sample {
            fds: Some(70_000),
            nodes: Some(12),
            handles: Some(1),
            sessions: Some(1),
            ..released
        };
        let quantities: Vec<&str> = retained(&baseline, &leaking)
            .iter()
            .map(|violation| match violation {
                Violation::Retained { quantity, .. } => *quantity,
                other => unreachable!("{other:?}"),
            })
            .collect();
        assert_eq!(quantities, ["sessions", "nodes", "handles", "fds"]);
    }

    /// An outage is remembered as the interval it covered, so the record
    /// answers about any stretch of the run and not only about the last one.
    #[test]
    fn an_outage_is_remembered_as_the_interval_it_covered() {
        let outage = Outage::default();
        outage.open(1_000);
        outage.close(2_000);
        outage.open(9_000);
        outage.close(9_500);
        assert_eq!(outage.generation(), 2);

        assert!(outage.overlaps(1_500, 1_800), "inside the first");
        assert!(outage.overlaps(0, 20_000), "spanning both");
        assert!(outage.overlaps(9_400, 12_000), "half of the second");
        assert!(
            !outage.overlaps(3_000, 8_000),
            "between them, which a record of the last close alone could not say"
        );
        assert!(!outage.overlaps(9_600, 10_000), "after both");

        // One that has not closed covers everything from where it opened.
        outage.open(11_000);
        assert!(outage.open_now());
        assert!(outage.overlaps(50_000, 60_000));
    }

    /// The stretch of a run an outage covered is not judged on the three things
    /// the reconnect contract permits there — and the clean stretches around it
    /// are, in the same ten-second window.
    ///
    /// The window is ten seconds of clean time, so it closes whatever the
    /// restart cadence is; what the outage costs it is the stretch the outage
    /// covered, and the count in the violation is what proves the two were told
    /// apart.
    #[test]
    fn only_the_stretch_an_outage_covered_is_exempt() {
        let metrics = Metrics::default();
        let outage = Outage::default();
        let mut watch = Watch::new(ceilings(), &[Class::Churn], &metrics);
        let churn = metrics.class(Class::Churn);
        for second in 0..16 {
            churn.record(Duration::from_millis(1), None, Duration::from_secs(second));
            let _ = watch.observe(Duration::from_secs(second), &metrics, &sample(), &outage);
        }

        // The server is taken away and comes back between two observations,
        // and what the mounts answered while it was gone is the reconnect
        // contract's: a stalled operation, ending in EIO.
        outage.open(16_200);
        churn.record(
            Duration::from_secs(30),
            Some(5),
            Duration::from_millis(16_500),
        );
        outage.close(16_800);
        assert_eq!(outage.generation(), 1);

        // Nothing is judged on that stretch, and the clean seconds around it
        // keep filling the same window.
        for second in 17..=25 {
            let found = watch.observe(Duration::from_secs(second), &metrics, &sample(), &outage);
            assert!(found.is_empty(), "second {second}: {found:?}");
        }

        // One clean second later the window is ten seconds of clean time, and
        // it is judged. One EIO is reported, not two: the one the outage
        // carried never entered the window.
        churn.record(Duration::from_secs(30), Some(5), Duration::from_secs(26));
        let found = watch.observe(Duration::from_secs(26), &metrics, &sample(), &outage);
        assert!(
            found.iter().any(|violation| matches!(
                violation,
                Violation::Transport {
                    class: Class::Churn,
                    errno: "EIO",
                    count: 1,
                    ..
                }
            )),
            "{found:?}"
        );
        assert!(
            found
                .iter()
                .any(|violation| matches!(violation, Violation::Latency { .. })),
            "{found:?}"
        );
    }

    /// A run that restarts more often than a window is long is still judged.
    ///
    /// This is the shape the whole-window exemption switched off in silence: at
    /// a heavy intensity every ten-second stretch of the run has an outage in
    /// it, so a check that stood a whole window down for one would stand down
    /// for the entire run and report nothing whatever the server did.
    #[test]
    fn a_run_that_restarts_faster_than_its_window_is_still_judged() {
        let metrics = Metrics::default();
        let outage = Outage::default();
        let mut watch = Watch::new(ceilings(), &[Class::Churn], &metrics);
        let churn = metrics.class(Class::Churn);

        let mut found = Vec::new();
        for second in 0..60u64 {
            // A restart every five seconds, each away for well under a second.
            if second.is_multiple_of(5) {
                outage.open(second * 1_000 + 100);
                outage.close(second * 1_000 + 400);
            }
            churn.record(Duration::from_secs(30), None, Duration::from_secs(second));
            found.extend(watch.observe(Duration::from_secs(second), &metrics, &sample(), &outage));
        }
        assert!(
            found
                .iter()
                .any(|violation| matches!(violation, Violation::Latency { .. })),
            "a run whose every window holds an outage is judged on its clean \
             seconds: {found:?}"
        );
    }

    /// A class that has gone quiet is reported whatever the restart arm has
    /// been doing: an outage lasts seconds and the watchdog waits minutes, so
    /// exempting the watchdog would exempt a real deadlock.
    #[test]
    fn the_progress_watchdog_is_not_exempted_by_an_outage() {
        let metrics = Metrics::default();
        let outage = Outage::default();
        let mut watch = Watch::new(ceilings(), &[Class::Walk], &metrics);
        metrics
            .class(Class::Walk)
            .record(Duration::from_millis(1), None, Duration::from_secs(1));
        outage.open(1_000);
        let found = watch.observe(Duration::from_secs(200), &metrics, &sample(), &outage);
        assert!(
            found
                .iter()
                .any(|violation| matches!(violation, Violation::NoProgress { .. })),
            "{found:?}"
        );
    }

    /// What a worker files is collected, once, in the order it was filed.
    #[test]
    fn findings_are_drained_and_not_repeated() {
        let findings = Findings::default();
        assert!(findings.drain().is_empty());

        findings.file(Violation::UnfinishedWorkers { count: 1 });
        findings.file(Violation::UnfinishedWorkers { count: 2 });
        assert_eq!(
            findings.drain(),
            [
                Violation::UnfinishedWorkers { count: 1 },
                Violation::UnfinishedWorkers { count: 2 }
            ]
        );
        assert!(findings.drain().is_empty());
    }

    /// The cycling class takes transports down for a living, so the kernel
    /// telling it the channel is gone is not a defect.
    #[test]
    fn the_remount_class_is_exempt_from_the_transport_check() {
        let metrics = Metrics::default();
        let mut watch = Watch::new(ceilings(), &[Class::Remount], &metrics);
        let remount = metrics.class(Class::Remount);
        for second in 0..16 {
            remount.record(Duration::from_millis(1), None, Duration::from_secs(second));
            let _ = watch.observe(
                Duration::from_secs(second),
                &metrics,
                &sample(),
                &Outage::default(),
            );
        }
        remount.record(Duration::from_millis(1), Some(19), Duration::from_secs(20));
        assert!(
            watch
                .observe(
                    Duration::from_secs(30),
                    &metrics,
                    &sample(),
                    &Outage::default()
                )
                .iter()
                .all(|violation| !matches!(violation, Violation::Transport { .. })),
            "an unmounted channel is not a broken one"
        );
    }
}
