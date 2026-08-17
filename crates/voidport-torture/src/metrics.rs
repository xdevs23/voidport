//! What the harness counts, and how it counts it without becoming the load.
//!
//! Every worker records every operation, so the recording path is on the hot
//! path of a run that is deliberately trying to saturate the machine. It is
//! therefore lock-free: one atomic counter pair per class plus a fixed
//! power-of-two latency histogram of atomics. Quantiles come out of the
//! histogram as *bucket bounds*, which overstates a latency by less than a
//! factor of two — deliberately, because the ceilings this feeds are generous
//! by design and a conservative reading of a latency can only make a violation
//! more honest.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde::Serialize;

/// One class of operation the harness drives.
///
/// The list is the design's: every operation class, driven concurrently in
/// every shape.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Class {
    /// Recursive tree walks: read a directory, stat what it holds, descend.
    Walk,
    /// Listing storms: one crowded directory, listed over and over.
    List,
    /// Create/delete churn: entries appearing and disappearing under a walk.
    Churn,
    /// Lock storms: many blocking waiters stacked on one range.
    Locks,
    /// Append storms: several writers appending to one file at once.
    Append,
    /// Extended-attribute churn — set, get, list, remove, over names the
    /// namespace's rules govern — and special-file creation beside it: a FIFO
    /// and a socket made, stat'd and removed each cycle.
    Xattr,
    /// Rename and unlink of files that are open, and I/O through them after.
    Rename,
    /// Open/close storms over a prepared set of files.
    OpenClose,
    /// Mount and unmount cycling, under everything else's load.
    Remount,
    /// Multi-mount contention: the same files, through different mounts.
    Contend,
    /// Server restarts under the whole load, graceful and hard by turns, each
    /// followed by the reconnect contract's healing and a state-file check.
    Restart,
    /// Special-file churn: FIFOs, socket files and symbolic links made, read,
    /// owner-checked and removed through the mounts.
    Special,
    /// Control-plane policy churn: rules added, re-moded and removed, and
    /// attribute rules toggled, on the namespace the load is using.
    Rules,
    /// Listener churn: data-plane listeners added and removed under load, with
    /// the sessions already on them proven to keep serving.
    Listeners,
}

impl Class {
    /// Every class, in the order a report lists them.
    pub const ALL: [Self; 14] = [
        Self::Walk,
        Self::List,
        Self::Churn,
        Self::Locks,
        Self::Append,
        Self::Xattr,
        Self::Rename,
        Self::OpenClose,
        Self::Remount,
        Self::Contend,
        Self::Restart,
        Self::Special,
        Self::Rules,
        Self::Listeners,
    ];

    /// The name the command line and the report spell it with.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Walk => "walk",
            Self::List => "list",
            Self::Churn => "churn",
            Self::Locks => "locks",
            Self::Append => "append",
            Self::Xattr => "xattr",
            Self::Rename => "rename",
            Self::OpenClose => "open-close",
            Self::Remount => "remount",
            Self::Contend => "contend",
            Self::Restart => "restart",
            Self::Special => "special",
            Self::Rules => "rules",
            Self::Listeners => "listeners",
        }
    }

    /// How many workers drive this class at a given intensity.
    ///
    /// Every class scales with the intensity except the one that owns the
    /// server process: two restart arms would signal the same server at once,
    /// so the restart class is always exactly one worker and scales its
    /// **cadence** instead — which is what intensity means for a controller.
    #[must_use]
    pub fn workers(self, intensity: u64) -> u64 {
        match self {
            Self::Restart => 1,
            _ => intensity,
        }
    }

    /// The class a name selects.
    ///
    /// # Errors
    ///
    /// Returns the unknown name.
    pub fn parse(name: &str) -> Result<Self, String> {
        Self::ALL
            .into_iter()
            .find(|class| class.name() == name)
            .ok_or_else(|| name.to_owned())
    }

    /// How long one operation of this class may take at the 99th percentile
    /// before the harness calls it a violation.
    ///
    /// These are the design's "generous ceilings": they are not performance
    /// targets, they are the line between *slow under brutal load*, which is
    /// conformant, and *stalled*, which is a defect. A lock acquisition is
    /// allowed the most by far, because waiting for another owner to let go is
    /// the operation working correctly.
    ///
    /// The four control classes are allowed what their operation contains: a
    /// rule change is followed by a bounded poll for the policy to bind, a
    /// listener cycle by a handshake on a fresh endpoint, and a restart by a
    /// whole stop, start and heal of every mount.
    #[must_use]
    pub fn latency_ceiling(self) -> Duration {
        Duration::from_millis(match self {
            Self::Walk | Self::Xattr | Self::OpenClose => 2_000,
            Self::List
            | Self::Churn
            | Self::Append
            | Self::Rename
            | Self::Contend
            | Self::Special => 5_000,
            Self::Remount | Self::Rules | Self::Listeners => 30_000,
            Self::Locks => 60_000,
            Self::Restart => 120_000,
        })
    }
}

/// A fixed power-of-two latency histogram.
///
/// Bucket `i` holds the samples whose microsecond count has `i` significant
/// bits, so bucket `i` covers `[2^(i-1), 2^i)` microseconds and its upper bound
/// is `2^i`. Thirty-two buckets reach ~71 minutes, which no ceiling here comes
/// near.
#[derive(Debug, Default)]
pub struct Histogram {
    buckets: [AtomicU64; 32],
}

impl Histogram {
    /// Records one sample.
    pub fn record(&self, latency: Duration) {
        let micros = u64::try_from(latency.as_micros()).unwrap_or(u64::MAX);
        let bucket = (64 - micros.leading_zeros()) as usize;
        self.buckets[bucket.min(31)].fetch_add(1, Ordering::Relaxed);
    }

    /// The bucket counts as they stand.
    #[must_use]
    pub fn snapshot(&self) -> [u64; 32] {
        std::array::from_fn(|index| self.buckets[index].load(Ordering::Relaxed))
    }
}

/// The counts of one class as of one instant.
#[derive(Clone, Copy, Debug, Default)]
pub struct ClassSnapshot {
    /// Operations that completed, however they completed.
    pub completed: u64,
    /// Operations that failed with an errno.
    pub failed: u64,
    /// The latency histogram's buckets.
    pub buckets: [u64; 32],
}

impl ClassSnapshot {
    /// The counts accumulated between an earlier snapshot and this one.
    #[must_use]
    pub fn since(&self, earlier: &Self) -> Self {
        Self {
            completed: self.completed.saturating_sub(earlier.completed),
            failed: self.failed.saturating_sub(earlier.failed),
            buckets: std::array::from_fn(|index| {
                self.buckets[index].saturating_sub(earlier.buckets[index])
            }),
        }
    }

    /// The two sets of counts added together.
    ///
    /// A judged window is stitched out of the stretches of the run an outage
    /// did not cover, so what it holds is a sum of deltas and not one
    /// difference. Adding histograms is exact: a bucket is a count.
    #[must_use]
    pub fn plus(&self, other: &Self) -> Self {
        Self {
            completed: self.completed.saturating_add(other.completed),
            failed: self.failed.saturating_add(other.failed),
            buckets: std::array::from_fn(|index| {
                self.buckets[index].saturating_add(other.buckets[index])
            }),
        }
    }

    /// The upper bound of the bucket the `q`-quantile falls in.
    ///
    /// `None` when nothing was recorded, which is what a window with no
    /// operations of this class must not be mistaken for a fast one.
    #[must_use]
    pub fn quantile(&self, q: f64) -> Option<Duration> {
        let total: u64 = self.buckets.iter().sum();
        if total == 0 {
            return None;
        }
        #[expect(
            clippy::cast_precision_loss,
            reason = "a quantile rank of a sample count; the loss is far below one sample"
        )]
        let wanted = (total as f64 * q).ceil() as u64;
        let mut seen = 0;
        for (index, count) in self.buckets.iter().enumerate() {
            seen += count;
            if seen >= wanted.max(1) {
                return Some(Duration::from_micros(1u64 << index.min(63)));
            }
        }
        Some(Duration::from_micros(1u64 << 32))
    }
}

/// One class's live counters.
#[derive(Debug)]
pub struct ClassMetrics {
    completed: AtomicU64,
    failed: AtomicU64,
    histogram: Histogram,
    /// Milliseconds since the run started, as of the last completed operation.
    /// The progress watchdog reads this and nothing else.
    last_completion_ms: AtomicU64,
    /// Errnos this class met, counted by number. Index 0 is "some errno past
    /// the table", which nothing on Linux reaches.
    errnos: [AtomicU64; 256],
}

impl Default for ClassMetrics {
    /// Written out because an array of 256 atomics is past the arity `Default`
    /// is derived for.
    fn default() -> Self {
        Self {
            completed: AtomicU64::new(0),
            failed: AtomicU64::new(0),
            histogram: Histogram::default(),
            last_completion_ms: AtomicU64::new(0),
            errnos: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }
}

impl ClassMetrics {
    /// Records one completed operation.
    pub fn record(&self, latency: Duration, errno: Option<i32>, elapsed: Duration) {
        self.completed.fetch_add(1, Ordering::Relaxed);
        self.histogram.record(latency);
        if let Some(errno) = errno {
            self.failed.fetch_add(1, Ordering::Relaxed);
            let slot = usize::try_from(errno).unwrap_or(0);
            self.errnos[if slot < 256 { slot } else { 0 }].fetch_add(1, Ordering::Relaxed);
        }
        self.last_completion_ms.store(
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
    }

    /// The counts as they stand.
    #[must_use]
    pub fn snapshot(&self) -> ClassSnapshot {
        ClassSnapshot {
            completed: self.completed.load(Ordering::Relaxed),
            failed: self.failed.load(Ordering::Relaxed),
            buckets: self.histogram.snapshot(),
        }
    }

    /// Milliseconds into the run at which this class last completed anything.
    #[must_use]
    pub fn last_completion_ms(&self) -> u64 {
        self.last_completion_ms.load(Ordering::Relaxed)
    }

    /// The errnos this class met, most frequent first.
    #[must_use]
    pub fn errnos(&self) -> Vec<(i32, u64)> {
        let mut counted: Vec<(i32, u64)> = self
            .errnos
            .iter()
            .enumerate()
            .filter_map(|(errno, count)| {
                let count = count.load(Ordering::Relaxed);
                (count > 0).then(|| (i32::try_from(errno).unwrap_or(0), count))
            })
            .collect();
        counted.sort_unstable_by_key(|(_, count)| std::cmp::Reverse(*count));
        counted
    }
}

/// Every class's counters.
#[derive(Debug, Default)]
pub struct Metrics {
    classes: [ClassMetrics; Class::ALL.len()],
}

impl Metrics {
    /// One class's counters.
    #[must_use]
    pub fn class(&self, class: Class) -> &ClassMetrics {
        &self.classes[Class::ALL
            .iter()
            .position(|candidate| *candidate == class)
            .unwrap_or(0)]
    }

    /// Every class's counts as of now.
    #[must_use]
    pub fn snapshot(&self) -> Vec<(Class, ClassSnapshot)> {
        Class::ALL
            .into_iter()
            .map(|class| (class, self.class(class).snapshot()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_class_names_itself_and_parses_back() {
        for class in Class::ALL {
            assert_eq!(Class::parse(class.name()), Ok(class));
        }
        assert!(Class::parse("nonesuch").is_err());
    }

    /// Intensity is workers everywhere but the arm that owns the server
    /// process, which is one worker at every intensity because a second one
    /// would be signalling the same server.
    #[test]
    fn intensity_is_workers_except_for_the_arm_that_owns_the_server() {
        for class in Class::ALL {
            let expected = if class == Class::Restart { 1 } else { 7 };
            assert_eq!(class.workers(7), expected, "{}", class.name());
        }
    }

    #[test]
    fn a_quantile_is_the_bound_of_the_bucket_it_falls_in() {
        let metrics = ClassMetrics::default();
        for _ in 0..99 {
            metrics.record(Duration::from_micros(10), None, Duration::ZERO);
        }
        metrics.record(Duration::from_secs(30), Some(5), Duration::from_secs(1));
        let snapshot = metrics.snapshot();

        assert_eq!(snapshot.completed, 100);
        assert_eq!(snapshot.failed, 1);
        // Ninety-nine samples at ten microseconds and one at thirty seconds:
        // the median sits in the small bucket and the top percentile in the
        // large one, each reported as its bucket's upper bound.
        assert!(snapshot.quantile(0.5).expect("recorded") <= Duration::from_micros(16));
        assert!(snapshot.quantile(0.99).expect("recorded") <= Duration::from_micros(16));
        assert!(snapshot.quantile(1.0).expect("recorded") >= Duration::from_secs(30));
        assert_eq!(metrics.errnos(), vec![(5, 1)]);
        assert_eq!(metrics.last_completion_ms(), 1000);
    }

    #[test]
    fn an_empty_window_has_no_quantile_at_all() {
        let empty = ClassSnapshot::default();
        assert_eq!(empty.quantile(0.99), None);

        let metrics = ClassMetrics::default();
        metrics.record(Duration::from_millis(1), None, Duration::ZERO);
        let first = metrics.snapshot();
        metrics.record(Duration::from_millis(1), None, Duration::ZERO);
        let second = metrics.snapshot();
        assert_eq!(second.since(&first).completed, 1);
        assert_eq!(second.since(&second).completed, 0);
        assert_eq!(second.since(&second).quantile(0.99), None);
    }
}
