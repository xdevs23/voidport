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

use std::collections::VecDeque;
use std::fmt;
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
        }
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

/// The continuous check, driven one observation at a time.
#[derive(Debug)]
pub struct Watch {
    ceilings: Ceilings,
    classes: Vec<Class>,
    /// The class counters as of the last window boundary.
    window_start: Vec<(Class, ClassSnapshot)>,
    /// The transport-errno counts as of the last window boundary.
    window_errnos: Vec<(Class, [u64; TRANSPORT_ERRNOS.len()])>,
    /// When that boundary was.
    window_started_ms: u64,
    /// The aggregate completion count over time, for the sliding window.
    completions: VecDeque<(u64, u64)>,
}

impl Watch {
    /// A check over `classes`, held to `ceilings`.
    #[must_use]
    pub fn new(ceilings: Ceilings, classes: &[Class], metrics: &Metrics) -> Self {
        Self {
            ceilings,
            classes: classes.to_vec(),
            window_start: metrics.snapshot(),
            window_errnos: transport_errnos(classes, metrics),
            window_started_ms: 0,
            completions: VecDeque::new(),
        }
    }

    /// Observes the run as it stands, and reports what it found wrong.
    ///
    /// Called once a second by the sampler; the window-based checks fire only
    /// when a window has actually elapsed, so the cost of observing is a few
    /// atomic loads.
    #[must_use]
    pub fn observe(
        &mut self,
        elapsed: Duration,
        metrics: &Metrics,
        sample: &Sample,
    ) -> Vec<Violation> {
        let elapsed_ms = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX);
        let mut violations = Vec::new();
        let snapshot = metrics.snapshot();
        let total: u64 = snapshot.iter().map(|(_, class)| class.completed).sum();
        self.completions.push_back((elapsed_ms, total));

        if elapsed < self.ceilings.grace {
            // The mounts are still coming up and the working set is still
            // being written; nothing here is meaningful yet.
            self.reset_window(elapsed_ms, snapshot, metrics);
            return violations;
        }

        violations.extend(self.throughput(elapsed_ms, total));
        violations.extend(self.progress(elapsed_ms, metrics));
        violations.extend(self.resources(elapsed_ms, sample, created_names(&snapshot)));
        if elapsed_ms.saturating_sub(self.window_started_ms)
            >= u64::try_from(self.ceilings.window.as_millis()).unwrap_or(u64::MAX)
        {
            violations.extend(self.latencies(elapsed_ms, &snapshot));
            violations.extend(self.transport(elapsed_ms, metrics));
            self.reset_window(elapsed_ms, snapshot, metrics);
        }
        violations
    }

    /// Starts a new window from the counts as they stand.
    fn reset_window(
        &mut self,
        elapsed_ms: u64,
        snapshot: Vec<(Class, ClassSnapshot)>,
        metrics: &Metrics,
    ) {
        self.window_start = snapshot;
        self.window_errnos = transport_errnos(&self.classes, metrics);
        self.window_started_ms = elapsed_ms;
    }

    /// Invariant 1: something completed over the trailing window.
    ///
    /// The observation kept at the front is the *newest* one that is already a
    /// whole window old — never merely the newest one older than the window —
    /// because the sample that opens the window is the one the count is
    /// compared against, and discarding it would make a gap in the
    /// observations look like a healthy window.
    fn throughput(&mut self, elapsed_ms: u64, total: u64) -> Option<Violation> {
        let window_ms = u64::try_from(self.ceilings.window.as_millis()).unwrap_or(u64::MAX);
        while self
            .completions
            .get(1)
            .is_some_and(|(at, _)| elapsed_ms.saturating_sub(*at) >= window_ms)
        {
            self.completions.pop_front();
        }
        let (at, earlier) = *self.completions.front()?;
        if elapsed_ms.saturating_sub(at) < window_ms || total > earlier {
            return None;
        }
        Some(Violation::ThroughputCollapse {
            window_ms,
            elapsed_ms,
        })
    }

    /// Invariant 2: every class's p99 is under its ceiling.
    fn latencies(&self, elapsed_ms: u64, snapshot: &[(Class, ClassSnapshot)]) -> Vec<Violation> {
        let mut violations = Vec::new();
        for (class, counts) in snapshot {
            if !self.classes.contains(class) {
                continue;
            }
            let started = self
                .window_start
                .iter()
                .find(|(candidate, _)| candidate == class)
                .map(|(_, counts)| *counts)
                .unwrap_or_default();
            let Some(p99) = counts.since(&started).quantile(0.99) else {
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
    fn transport(&self, elapsed_ms: u64, metrics: &Metrics) -> Vec<Violation> {
        let now = transport_errnos(&self.classes, metrics);
        let mut violations = Vec::new();
        for (class, counts) in now.iter().filter(|(class, _)| *class != Class::Remount) {
            let before = self
                .window_errnos
                .iter()
                .find(|(candidate, _)| candidate == class)
                .map(|(_, counts)| *counts)
                .unwrap_or_default();
            for (index, (_, name)) in TRANSPORT_ERRNOS.iter().enumerate() {
                let count = counts[index].saturating_sub(before[index]);
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

/// How many names the run has created so far.
///
/// Only the two classes that make new names count: everything else works over
/// names the working set already holds, whose nodes the base bound covers.
fn created_names(snapshot: &[(Class, ClassSnapshot)]) -> u64 {
    snapshot
        .iter()
        .filter(|(class, _)| matches!(class, Class::Churn | Class::Rename))
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
                    .observe(Duration::from_secs(second), &metrics, &sample())
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
            let found = watch.observe(Duration::from_secs(second), &metrics, &sample());
            assert!(found.is_empty(), "second {second}: {found:?}");
        }
        // And then stops. The aggregate window notices first...
        let found = watch.observe(Duration::from_secs(60), &metrics, &sample());
        assert!(
            found
                .iter()
                .any(|violation| matches!(violation, Violation::ThroughputCollapse { .. })),
            "{found:?}"
        );
        // ...and the class watchdog notices once its own patience runs out.
        let found = watch.observe(Duration::from_secs(200), &metrics, &sample());
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
            let _ = watch.observe(Duration::from_secs(second), &metrics, &sample());
        }
        // Walk's ceiling is two seconds; a window of ten-second operations is
        // over it however generous it is.
        for _ in 0..100 {
            walk.record(Duration::from_secs(10), None, Duration::from_secs(20));
        }
        let found = watch.observe(Duration::from_secs(30), &metrics, &sample());
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
        let found = watch.observe(Duration::from_secs(20), &metrics, &leaking);
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
                .observe(Duration::from_secs(20), &metrics, &full)
                .is_empty(),
            "a cache filled exactly to its budget is the cache working"
        );

        let over = Sample {
            node_descriptors: Some(65),
            ..full
        };
        let found = watch.observe(Duration::from_secs(21), &metrics, &over);
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
            let _ = watch.observe(Duration::from_secs(second), &metrics, &sample());
        }
        assert!(
            watch
                .observe(Duration::from_secs(30), &metrics, &sample())
                .iter()
                .all(|violation| !matches!(violation, Violation::Transport { .. })),
            "a racing ENOENT is not a violation"
        );

        churn.record(Duration::from_millis(1), Some(5), Duration::from_secs(40));
        let found = watch.observe(Duration::from_secs(45), &metrics, &sample());
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

    /// The cycling class takes transports down for a living, so the kernel
    /// telling it the channel is gone is not a defect.
    #[test]
    fn the_remount_class_is_exempt_from_the_transport_check() {
        let metrics = Metrics::default();
        let mut watch = Watch::new(ceilings(), &[Class::Remount], &metrics);
        let remount = metrics.class(Class::Remount);
        for second in 0..16 {
            remount.record(Duration::from_millis(1), None, Duration::from_secs(second));
            let _ = watch.observe(Duration::from_secs(second), &metrics, &sample());
        }
        remount.record(Duration::from_millis(1), Some(19), Duration::from_secs(20));
        assert!(
            watch
                .observe(Duration::from_secs(30), &metrics, &sample())
                .iter()
                .all(|violation| !matches!(violation, Violation::Transport { .. })),
            "an unmounted channel is not a broken one"
        );
    }
}
