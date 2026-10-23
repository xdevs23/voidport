//! Recording is lock-free, because it is on the hot path of a run that tries
//! to saturate the machine. Quantiles are bucket bounds and overstate a
//! latency by less than a factor of two. No invariant reads latencies,
//! because the duration of an operation depends on the load of the machine.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde::Serialize;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Class {
    Walk,
    List,
    Churn,
    Locks,
    Append,
    Xattr,
    Rename,
    OpenClose,
    Remount,
    Contend,
    Restart,
    Special,
    Rules,
    Listeners,
    Stream,
}

impl Class {
    pub const ALL: [Self; 15] = [
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
        Self::Stream,
    ];

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
            Self::Stream => "stream",
        }
    }

    /// Every class scales with the intensity except the restart class. It is
    /// always one worker and scales its cadence instead, because two restart
    /// arms would signal the same server.
    #[must_use]
    pub fn workers(self, intensity: u64) -> u64 {
        match self {
            Self::Restart => 1,
            _ => intensity,
        }
    }

    pub fn parse(name: &str) -> Result<Self, String> {
        Self::ALL
            .into_iter()
            .find(|class| class.name() == name)
            .ok_or_else(|| name.to_owned())
    }
}

/// Bucket `i` contains the samples whose microsecond count has `i` significant
/// bits, so it covers `[2^(i-1), 2^i)` microseconds. Thirty-two buckets reach
/// ~71 minutes.
#[derive(Debug, Default)]
pub struct Histogram {
    buckets: [AtomicU64; 32],
}

impl Histogram {
    pub fn record(&self, latency: Duration) {
        let micros = u64::try_from(latency.as_micros()).unwrap_or(u64::MAX);
        let bucket = (64 - micros.leading_zeros()) as usize;
        self.buckets[bucket.min(31)].fetch_add(1, Ordering::Relaxed);
    }

    #[must_use]
    pub fn snapshot(&self) -> [u64; 32] {
        std::array::from_fn(|index| self.buckets[index].load(Ordering::Relaxed))
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ClassSnapshot {
    pub completed: u64,
    pub failed: u64,
    pub buckets: [u64; 32],
}

impl ClassSnapshot {
    /// `None` when nothing was recorded, which must not be mistaken for a fast
    /// class.
    #[must_use]
    pub fn percentile(&self, percent: u8) -> Option<Duration> {
        let total: u64 = self.buckets.iter().sum();
        if total == 0 {
            return None;
        }
        let wanted = (u128::from(total) * u128::from(percent))
            .div_ceil(100)
            .max(1);
        let mut seen = 0;
        for (index, count) in self.buckets.iter().enumerate() {
            seen += count;
            if u128::from(seen) >= wanted {
                return Some(Duration::from_micros(1u64 << index.min(63)));
            }
        }
        Some(Duration::from_micros(1u64 << 32))
    }
}

#[derive(Debug)]
pub struct ClassMetrics {
    completed: AtomicU64,
    failed: AtomicU64,
    histogram: Histogram,
    last_completion_ms: AtomicU64,
    /// Index 0 is "some errno past the table", which nothing on Linux reaches.
    errnos: [AtomicU64; 256],
}

impl Default for ClassMetrics {
    /// An array of 256 atomics is past the arity `Default` is derived for.
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

    #[must_use]
    pub fn snapshot(&self) -> ClassSnapshot {
        ClassSnapshot {
            completed: self.completed.load(Ordering::Relaxed),
            failed: self.failed.load(Ordering::Relaxed),
            buckets: self.histogram.snapshot(),
        }
    }

    #[must_use]
    pub fn last_completion_ms(&self) -> u64 {
        self.last_completion_ms.load(Ordering::Relaxed)
    }

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

#[derive(Debug, Default)]
pub struct Metrics {
    classes: [ClassMetrics; Class::ALL.len()],
}

impl Metrics {
    #[must_use]
    pub fn class(&self, class: Class) -> &ClassMetrics {
        &self.classes[Class::ALL
            .iter()
            .position(|candidate| *candidate == class)
            .unwrap_or(0)]
    }

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

    #[test]
    fn intensity_is_workers_except_for_the_arm_that_owns_the_server() {
        for class in Class::ALL {
            let expected = if class == Class::Restart { 1 } else { 7 };
            assert_eq!(class.workers(7), expected, "{}", class.name());
        }
    }

    #[test]
    fn a_percentile_is_the_bound_of_the_bucket_it_falls_in() {
        let metrics = ClassMetrics::default();
        for _ in 0..99 {
            metrics.record(Duration::from_micros(10), None, Duration::ZERO);
        }
        metrics.record(Duration::from_secs(30), Some(5), Duration::from_secs(1));
        let snapshot = metrics.snapshot();

        assert_eq!(snapshot.completed, 100);
        assert_eq!(snapshot.failed, 1);
        assert!(snapshot.percentile(50).expect("recorded") <= Duration::from_micros(16));
        assert!(snapshot.percentile(99).expect("recorded") <= Duration::from_micros(16));
        assert!(snapshot.percentile(100).expect("recorded") >= Duration::from_secs(30));
        assert_eq!(metrics.errnos(), vec![(5, 1)]);
        assert_eq!(metrics.last_completion_ms(), 1000);
    }

    #[test]
    fn nothing_recorded_has_no_percentile_at_all() {
        assert_eq!(ClassSnapshot::default().percentile(99), None);
    }
}
