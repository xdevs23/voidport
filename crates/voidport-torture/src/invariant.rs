//! The [`Outage`] windows, in which the harness took the server away, are
//! exempt from the throughput and transport errno checks, because under the
//! reconnect contract a mount may stall and then fail with `EIO`. The
//! exemption covers only the stretch an outage covered: a judged window is ten
//! seconds of clean time, stitched from the stretches no outage overlapped.
//! Standing a whole window down because an outage touched it would switch both
//! checks off for the whole run at any restart cadence shorter than the
//! window. The watchdog of each class, the resource bounds and the findings
//! filed by workers stay armed throughout.

use std::collections::VecDeque;
use std::fmt;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde::Serialize;

use crate::metrics::{Class, ClassSnapshot, Metrics};
use crate::reference::Reference;
use crate::resource::Sample;

/// The errnos that mean the mount itself failed, not the operation. Everything
/// else a torture worker meets is a legitimate answer under concurrent churn,
/// such as `ENOENT` for a name another worker just unlinked.
const TRANSPORT_ERRNOS: [(i32, &str); 4] = [
    (5, "EIO"),
    (19, "ENODEV"),
    (107, "ENOTCONN"),
    (110, "ETIMEDOUT"),
];

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "violation", rename_all = "kebab-case")]
pub enum Violation {
    ThroughputCollapse {
        window_ms: u64,
        elapsed_ms: u64,
    },
    Stalled {
        class: Class,
        elapsed_ms: u64,
    },
    NoProgress {
        class: Class,
        stalled_ms: u64,
        elapsed_ms: u64,
    },
    Resource {
        quantity: &'static str,
        observed: u64,
        ceiling: u64,
        elapsed_ms: u64,
    },
    Transport {
        class: Class,
        errno: &'static str,
        count: u64,
        elapsed_ms: u64,
    },
    LeakedMount {
        path: String,
    },
    LeakedLoopDevice {
        device: String,
        backing: String,
    },
    Retained {
        quantity: &'static str,
        observed: u64,
        ceiling: u64,
    },
    UnfinishedWorkers {
        count: usize,
    },
    MountUnhealed {
        mountpoint: String,
        patience_ms: u64,
        detail: String,
    },
    CrashInconsistent {
        stop: &'static str,
        detail: String,
    },
    Contract {
        class: Class,
        detail: String,
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
            Self::Stalled { class, elapsed_ms } => write!(
                f,
                "{}: an operation in flight when the load ended did not complete, \
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

/// An outage opens when the restart arm is about to signal and closes only
/// when it has proven every mount serving again, so the checks stand down for
/// exactly the interval the harness caused, and the healing that ends it is
/// itself asserted.
#[derive(Debug, Default)]
pub struct Outage {
    /// More than one at a time cannot happen, because the restart class is a
    /// single worker.
    open: AtomicU64,
    /// The intervals and not a single last closed mark, because the checks ask
    /// whether an outage covered a given stretch of the run.
    windows: Mutex<VecDeque<(u64, u64)>>,
    /// A worker that took an answer before the restart and compares it after
    /// reads this to know whether both answers are about the same server
    /// lifetime.
    generation: AtomicU64,
}

/// The checks only ask about the last few seconds of a run. The bound keeps
/// the record of an hours-long soak from growing with its restart count.
const REMEMBERED_OUTAGES: usize = 64;

impl Outage {
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

    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }

    #[must_use]
    pub fn open_now(&self) -> bool {
        self.open.load(Ordering::SeqCst) > 0
    }

    #[must_use]
    pub fn overlaps(&self, from_ms: u64, to_ms: u64) -> bool {
        self.windows
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .iter()
            .any(|(opened, closed)| *opened <= to_ms && *closed >= from_ms)
    }
}

/// The invariants of the watcher are read off counters. These cannot be: only
/// the worker that added a hidden rule knows the name it is about, and only
/// the arm that restarted the server knows which mounts owed it a recovery.
#[derive(Debug, Default)]
pub struct Findings {
    filed: Mutex<Vec<Violation>>,
}

impl Findings {
    pub fn file(&self, violation: Violation) {
        eprintln!("!!! voidport-torture: {violation}");
        self.filed
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .push(violation);
    }

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

/// The reference does filesystem work on a plain directory of the host,
/// outside every mount, so a busy machine slows it as much as the mounts and
/// a server that sends no replies does not slow it. An operation is stalled
/// once the reference has completed as many operations again as during the
/// whole load, and at least one. No clock is involved, so every wait for a
/// verdict ends.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Ending {
    during_the_load: u64,
}

impl Ending {
    pub(crate) fn now(reference: &Reference) -> Self {
        Self {
            during_the_load: reference.completed(),
        }
    }

    pub(crate) fn stalled(&self, reference: &Reference) -> bool {
        reference.completed().saturating_sub(self.during_the_load) >= self.during_the_load.max(1)
    }
}

/// The listeners, the control socket and its connections, the state file, the
/// descriptors held open on graft targets and the ones being opened again.
/// Generous on purpose: this is a leak check, not an audit.
const DESCRIPTOR_SLACK: u64 = 2048;

/// Mirrors the ceiling that `voidportd` derives (`DERIVED_CEILING`). A server
/// configured with something larger has to be read through the control
/// socket.
const DERIVED_BUDGET_CEILING: u64 = 262_144;

/// The bounds are computed from the shape of the run, because an absolute
/// number would mean something different at every intensity.
#[derive(Clone, Copy, Debug)]
pub struct Ceilings {
    pub fds: u64,
    pub node_descriptors: u64,
    pub nodes: u64,
    pub handles: u64,
    pub rss_kib: u64,
    pub window: Duration,
    pub watchdog: Duration,
    pub grace: Duration,
}

impl Ceilings {
    /// A node per entry per mount, a handle per open file per worker, and a
    /// resident set that may double. The descriptor term does not depend on the
    /// working set: it is the budget of the node cache plus the handles plus
    /// [`DESCRIPTOR_SLACK`]. A server that goes back to a descriptor per node
    /// fails this within seconds of the walk starting.
    #[must_use]
    pub fn for_run(baseline: &Sample, entries: u64, mounts: u64, workers: u64) -> Self {
        let nodes = entries * mounts * 4 + 4096;
        let handles = workers * 64 + 1024;
        // A server that publishes no budget is held to the largest budget it could
        // have derived.
        let node_descriptors = baseline
            .node_descriptor_budget
            .unwrap_or(DERIVED_BUDGET_CEILING);
        Self {
            fds: baseline.fds.unwrap_or(0) + node_descriptors + handles + DESCRIPTOR_SLACK,
            node_descriptors,
            nodes,
            handles,
            rss_kib: baseline.rss_kib.unwrap_or(0).max(65_536) * 4 + 1_048_576,
            window: Duration::from_secs(10),
            watchdog: Duration::from_secs(120),
            grace: Duration::from_secs(15),
        }
    }
}

#[derive(Debug, Default)]
struct WindowCounts {
    errnos: Vec<(Class, [u64; TRANSPORT_ERRNOS.len()])>,
    clean_ms: u64,
}

impl WindowCounts {
    fn add(&mut self, errnos: &[(Class, [u64; TRANSPORT_ERRNOS.len()])], clean_ms: u64) {
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

    fn clear(&mut self) {
        self.errnos.clear();
        self.clean_ms = 0;
    }
}

#[derive(Debug)]
pub struct Watch {
    ceilings: Ceilings,
    classes: Vec<Class>,
    last_errnos: Vec<(Class, [u64; TRANSPORT_ERRNOS.len()])>,
    last_observed_ms: u64,
    window: WindowCounts,
    clean_ms: u64,
    progress_ms: u64,
    completed: u64,
}

impl Watch {
    #[must_use]
    pub fn new(ceilings: Ceilings, classes: &[Class], metrics: &Metrics) -> Self {
        Self {
            ceilings,
            classes: classes.to_vec(),
            last_errnos: transport_errnos(classes, metrics),
            last_observed_ms: 0,
            window: WindowCounts::default(),
            clean_ms: 0,
            progress_ms: 0,
            completed: 0,
        }
    }

    /// The window-based checks fire only when a window has elapsed. The stretch
    /// between two observations that an outage overlapped contributes neither its
    /// transport errnos nor its time, so a window is ten seconds of clean time
    /// stitched across as many outages as it takes.
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
            self.window
                .add(&errno_deltas(&errnos, &self.last_errnos), stretch_ms);
        }
        if total > self.completed {
            self.completed = total;
            self.progress_ms = self.clean_ms;
        }
        self.last_errnos = errnos;
        self.last_observed_ms = elapsed_ms;

        if elapsed < self.ceilings.grace {
            self.window.clear();
            return violations;
        }

        violations.extend(self.throughput(elapsed_ms));
        violations.extend(self.progress(elapsed_ms, metrics));
        violations.extend(self.resources(elapsed_ms, sample, created));
        if self.window.clean_ms
            >= u64::try_from(self.ceilings.window.as_millis()).unwrap_or(u64::MAX)
        {
            violations.extend(self.transport(elapsed_ms));
            self.window.clear();
        }
        violations
    }

    /// Measured on the clean clock. A completion is progress whenever it
    /// happened, outage or not. What is forbidden is a whole clean window in
    /// which nothing completed.
    fn throughput(&self, elapsed_ms: u64) -> Option<Violation> {
        let window_ms = u64::try_from(self.ceilings.window.as_millis()).unwrap_or(u64::MAX);
        (self.clean_ms.saturating_sub(self.progress_ms) >= window_ms).then_some(
            Violation::ThroughputCollapse {
                window_ms,
                elapsed_ms,
            },
        )
    }

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

    /// `created` is how many names the run has made. It is added to the node
    /// bound, because a node lives as long as the guest kernel holds its lookup
    /// and a guest without memory pressure holds unused dentries indefinitely, so
    /// one node per name ever named is the honest ceiling. It is not added to the
    /// descriptor bounds: a bound that grew with the names could never notice
    /// descriptors following names again.
    fn resources(&self, elapsed_ms: u64, sample: &Sample, created: u64) -> Vec<Violation> {
        [
            ("fds", sample.fds, self.ceilings.fds),
            (
                "node_descriptors",
                sample.node_descriptors,
                // The budget of the same sample, with the baseline as fallback. Both are the
                // same number, because the budget is set at startup.
                sample
                    .node_descriptor_budget
                    .unwrap_or(self.ceilings.node_descriptors),
            ),
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

    /// [`Class::Remount`] is exempt: its operation is taking a transport down,
    /// and the kernel reporting a channel that has gone away is that operation
    /// working.
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

/// Only the classes that make new names count: everything else works over
/// names whose nodes the base bound covers.
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

/// Threads are not checked here: the pool of the server keeps its idle
/// threads, so comparing the pool after a storm against a baseline taken
/// before the load compares a warm pool with a fresh one.
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

    #[test]
    fn a_run_that_stops_completing_anything_is_caught() {
        let metrics = Metrics::default();
        let mut watch = Watch::new(ceilings(), &[Class::Walk], &metrics);
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
            ["fds", "node_descriptors", "nodes", "handles", "rss_kib"]
        );
    }

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
            "a node does not cost a descriptor, so the descriptor bound must \
             be far below the node bound of a large working set"
        );

        let unknown = Ceilings::for_run(&Sample::default(), 1_000, 2, 8);
        assert_eq!(unknown.node_descriptors, DERIVED_BUDGET_CEILING);
    }

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

        outage.open(11_000);
        assert!(outage.open_now());
        assert!(outage.overlaps(50_000, 60_000));
    }

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

        outage.open(16_200);
        churn.record(
            Duration::from_secs(30),
            Some(5),
            Duration::from_millis(16_500),
        );
        outage.close(16_800);
        assert_eq!(outage.generation(), 1);

        for second in 17..=25 {
            let found = watch.observe(Duration::from_secs(second), &metrics, &sample(), &outage);
            assert!(found.is_empty(), "second {second}: {found:?}");
        }

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
    }

    /// At a heavy intensity every ten-second stretch of the run has an outage in
    /// it, so a check that stood a whole window down for one would stand down for
    /// the entire run.
    #[test]
    fn a_run_that_restarts_faster_than_its_window_is_still_judged() {
        let metrics = Metrics::default();
        let outage = Outage::default();
        let mut watch = Watch::new(ceilings(), &[Class::Churn], &metrics);
        let churn = metrics.class(Class::Churn);

        let mut found = Vec::new();
        for second in 0..60u64 {
            if second.is_multiple_of(5) {
                outage.open(second * 1_000 + 100);
                outage.close(second * 1_000 + 400);
            }
            churn.record(
                Duration::from_millis(1),
                Some(5),
                Duration::from_secs(second),
            );
            found.extend(watch.observe(Duration::from_secs(second), &metrics, &sample(), &outage));
        }
        assert!(
            found
                .iter()
                .any(|violation| matches!(violation, Violation::Transport { .. })),
            "a run whose every window holds an outage is judged on its clean \
             seconds: {found:?}"
        );
    }

    /// An outage lasts seconds and the watchdog waits minutes, so exempting the
    /// watchdog would exempt a real deadlock.
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

    #[test]
    fn a_stall_is_judged_by_the_work_of_the_reference() {
        let reference = Reference::new(std::path::PathBuf::new());
        for _ in 0..10 {
            reference.record();
        }
        let ending = Ending::now(&reference);
        assert!(
            !ending.stalled(&reference),
            "nothing happened since the end"
        );
        for _ in 0..9 {
            reference.record();
        }
        assert!(!ending.stalled(&reference), "nine of ten again");
        reference.record();
        assert!(
            ending.stalled(&reference),
            "as much again as during the load"
        );
    }

    #[test]
    fn a_stall_after_a_load_without_reference_work_needs_one_operation() {
        let reference = Reference::new(std::path::PathBuf::new());
        let ending = Ending::now(&reference);
        assert!(!ending.stalled(&reference));
        reference.record();
        assert!(ending.stalled(&reference));
    }

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
