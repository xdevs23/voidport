//! What a measurement is, and the two shapes it is reported in.
//!
//! A scenario hands [`drive`] a closure that performs one repetition and
//! returns what it timed. Everything else — the warmup, the cache drops, the
//! derived statistics, the JSON line, the human summary — happens here, so
//! every scenario reports the same way and a run record can be compared across
//! backends without knowing which scenario produced it.

use std::fs::OpenOptions;
use std::io::Write as _;
use std::path::Path;
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Context as _, Result};
use serde::Serialize;
use serde_json::{Value, json};

use crate::cli::Common;
use crate::fsutil;

/// What one repetition of a scenario produced.
///
/// `duration` is the window the scenario itself timed — setup and teardown a
/// scenario performs inside its repetition are deliberately outside it.
#[derive(Debug)]
pub struct Rep {
    /// The measured window.
    pub duration: Duration,
    /// Operations performed in that window (the scenario defines "operation").
    pub ops: u64,
    /// Bytes moved in that window; 0 for metadata-only scenarios.
    pub bytes: u64,
    /// Per-operation latencies, when the scenario samples them.
    pub latencies: Vec<Duration>,
    /// Scenario-specific numbers that do not fit the common shape.
    pub extra: Value,
}

impl Rep {
    /// A repetition with no per-operation samples and nothing scenario-specific.
    pub fn new(duration: Duration, ops: u64, bytes: u64) -> Self {
        Self {
            duration,
            ops,
            bytes,
            latencies: Vec::new(),
            extra: Value::Null,
        }
    }

    /// The same, carrying per-operation latency samples.
    #[must_use]
    pub fn with_latencies(mut self, latencies: Vec<Duration>) -> Self {
        self.latencies = latencies;
        self
    }

    /// The same, carrying scenario-specific numbers.
    #[must_use]
    pub fn with_extra(mut self, extra: Value) -> Self {
        self.extra = extra;
        self
    }
}

/// A distribution of samples where larger is worse (latencies, wall times).
#[derive(Debug, Clone, Copy, Serialize)]
pub struct Percentiles {
    /// Arithmetic mean.
    pub mean: f64,
    /// Median (nearest-rank).
    pub p50: f64,
    /// 99th percentile (nearest-rank).
    pub p99: f64,
    /// Largest sample.
    pub max: f64,
}

impl Percentiles {
    /// Summarises samples already expressed in the reported unit.
    ///
    /// Returns `None` for an empty sample set instead of inventing zeros.
    pub fn of(samples: &[f64]) -> Option<Self> {
        if samples.is_empty() {
            return None;
        }
        let mut sorted = samples.to_vec();
        sorted.sort_by(f64::total_cmp);
        Some(Self {
            mean: sorted.iter().sum::<f64>() / sorted.len() as f64,
            p50: nearest_rank(&sorted, 0.50),
            p99: nearest_rank(&sorted, 0.99),
            max: sorted[sorted.len() - 1],
        })
    }

    /// Summarises durations in microseconds.
    pub fn of_micros(samples: &[Duration]) -> Option<Self> {
        let micros: Vec<f64> = samples
            .iter()
            .map(|sample| sample.as_secs_f64() * 1e6)
            .collect();
        Self::of(&micros)
    }
}

/// A distribution of samples where larger is better (throughputs).
#[derive(Debug, Clone, Copy, Serialize)]
pub struct Spread {
    /// Arithmetic mean.
    pub mean: f64,
    /// Median (nearest-rank).
    pub p50: f64,
    /// Smallest sample — the worst repetition.
    pub min: f64,
    /// Largest sample.
    pub max: f64,
}

impl Spread {
    /// Summarises samples, or `None` when there are none.
    pub fn of(samples: &[f64]) -> Option<Self> {
        if samples.is_empty() {
            return None;
        }
        let mut sorted = samples.to_vec();
        sorted.sort_by(f64::total_cmp);
        Some(Self {
            mean: sorted.iter().sum::<f64>() / sorted.len() as f64,
            p50: nearest_rank(&sorted, 0.50),
            min: sorted[0],
            max: sorted[sorted.len() - 1],
        })
    }
}

/// The nearest-rank percentile of an ascending sample set.
fn nearest_rank(sorted: &[f64], quantile: f64) -> f64 {
    debug_assert!(!sorted.is_empty());
    let rank = (quantile * sorted.len() as f64).ceil() as usize;
    sorted[rank.clamp(1, sorted.len()) - 1]
}

/// One measured repetition, as reported.
#[derive(Debug, Serialize)]
pub struct RepReport {
    /// The measured window, in seconds.
    pub seconds: f64,
    /// Operations in that window.
    pub ops: u64,
    /// Bytes in that window.
    pub bytes: u64,
    /// Operations per second over the window.
    pub ops_per_second: f64,
    /// Mebibytes per second over the window; 0 for metadata-only scenarios.
    pub mib_per_second: f64,
    /// Per-operation latency, in microseconds, when sampled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_us: Option<Percentiles>,
    /// Scenario-specific numbers.
    #[serde(skip_serializing_if = "Value::is_null")]
    pub extra: Value,
}

impl RepReport {
    /// Derives the reported numbers from a raw repetition.
    fn of(rep: &Rep) -> Self {
        let seconds = rep.duration.as_secs_f64();
        Self {
            seconds,
            ops: rep.ops,
            bytes: rep.bytes,
            ops_per_second: per_second(rep.ops as f64, seconds),
            mib_per_second: per_second(rep.bytes as f64 / MIB, seconds),
            latency_us: Percentiles::of_micros(&rep.latencies),
            extra: rep.extra.clone(),
        }
    }
}

/// The run's derived statistics across its measured repetitions.
#[derive(Debug, Serialize)]
pub struct Summary {
    /// Wall time per repetition, in seconds.
    pub seconds: Percentiles,
    /// Operations per second, per repetition.
    pub ops_per_second: Spread,
    /// Mebibytes per second, per repetition.
    pub mib_per_second: Spread,
    /// Per-operation latency in microseconds, pooled over every repetition.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_us: Option<Percentiles>,
}

/// One scenario run against one backend: what was asked for and what happened.
#[derive(Debug, Serialize)]
pub struct Run {
    /// The scenario name, as spelled on the command line.
    pub scenario: &'static str,
    /// The backend label the caller assigned.
    pub label: String,
    /// The directory benchmarked.
    pub directory: String,
    /// When the run finished, in seconds since the epoch.
    pub finished_unix: u64,
    /// Unmeasured repetitions performed first.
    pub warmup: u32,
    /// Measured repetitions.
    pub reps: u32,
    /// Whether the page cache was dropped before every repetition.
    pub drop_caches: bool,
    /// The scenario's parameters.
    pub params: Value,
    /// Every measured repetition.
    pub per_rep: Vec<RepReport>,
    /// The derived statistics.
    pub summary: Summary,
}

impl Run {
    /// The JSON line, plus the human summary, to their respective streams.
    pub fn emit(&self, json_file: Option<&Path>) -> Result<()> {
        let line = serde_json::to_string(self).context("the run record serializes")?;
        println!("{line}");
        if let Some(path) = json_file {
            let mut file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .with_context(|| format!("cannot append to {}", path.display()))?;
            writeln!(file, "{line}")
                .with_context(|| format!("cannot append to {}", path.display()))?;
        }
        eprint!("{}", self.human());
        Ok(())
    }

    /// The human summary: what a person reads while a matrix is running.
    fn human(&self) -> String {
        let caches = if self.drop_caches {
            ", caches dropped"
        } else {
            ""
        };
        let mut text = format!(
            "{} [{}] {} ({} reps, {} warmup{caches})\n",
            self.scenario, self.label, self.directory, self.reps, self.warmup
        );
        let wall = &self.summary.seconds;
        text.push_str(&format!(
            "  wall        mean {:.4} s     p50 {:.4} s     p99 {:.4} s\n",
            wall.mean, wall.p50, wall.p99
        ));
        let ops = &self.summary.ops_per_second;
        text.push_str(&format!(
            "  ops/s       mean {:.1}       p50 {:.1}       min {:.1}\n",
            ops.mean, ops.p50, ops.min
        ));
        if self.summary.mib_per_second.max > 0.0 {
            let mib = &self.summary.mib_per_second;
            text.push_str(&format!(
                "  MiB/s       mean {:.1}       p50 {:.1}       min {:.1}\n",
                mib.mean, mib.p50, mib.min
            ));
        }
        if let Some(latency) = self.summary.latency_us {
            text.push_str(&format!(
                "  latency us  mean {:.1}       p50 {:.1}       p99 {:.1}       max {:.1}\n",
                latency.mean, latency.p50, latency.p99, latency.max
            ));
        }
        text
    }
}

/// Bytes in a mebibyte, as a float because every derived rate divides by it.
const MIB: f64 = 1024.0 * 1024.0;

/// A rate, guarding the degenerate window.
fn per_second(quantity: f64, seconds: f64) -> f64 {
    if seconds > 0.0 {
        quantity / seconds
    } else {
        0.0
    }
}

/// Runs a scenario: warmups, then measured repetitions, then the record.
///
/// The page cache is dropped before every repetition including the warmups
/// when asked, so a read scenario must have prepared its files *before*
/// calling this. `repetition` receives the zero-based index of a measured
/// repetition, or `None` for a warmup.
pub fn drive(
    scenario: &'static str,
    common: &Common,
    params: Value,
    mut repetition: impl FnMut(Option<u32>) -> Result<Rep>,
) -> Result<Run> {
    anyhow::ensure!(common.reps > 0, "a run needs at least one repetition");

    for index in 0..common.warmup {
        if common.drop_caches {
            fsutil::drop_caches()?;
        }
        repetition(None).with_context(|| format!("warmup repetition {index} failed"))?;
    }

    let mut reps = Vec::with_capacity(common.reps as usize);
    let mut latencies = Vec::new();
    for index in 0..common.reps {
        if common.drop_caches {
            fsutil::drop_caches()?;
        }
        let started = Instant::now();
        let rep = repetition(Some(index))
            .with_context(|| format!("measured repetition {index} failed"))?;
        anyhow::ensure!(
            rep.duration <= started.elapsed(),
            "repetition {index} reported a window longer than it ran"
        );
        latencies.extend_from_slice(&rep.latencies);
        reps.push(RepReport::of(&rep));
    }

    let seconds: Vec<f64> = reps.iter().map(|rep| rep.seconds).collect();
    let ops: Vec<f64> = reps.iter().map(|rep| rep.ops_per_second).collect();
    let mib: Vec<f64> = reps.iter().map(|rep| rep.mib_per_second).collect();
    let summary = Summary {
        seconds: Percentiles::of(&seconds).expect("at least one repetition"),
        ops_per_second: Spread::of(&ops).expect("at least one repetition"),
        mib_per_second: Spread::of(&mib).expect("at least one repetition"),
        latency_us: Percentiles::of_micros(&latencies),
    };

    Ok(Run {
        scenario,
        label: common.label.clone(),
        directory: common.dir.display().to_string(),
        finished_unix: SystemTime::UNIX_EPOCH
            .elapsed()
            .map_or(0, |elapsed| elapsed.as_secs()),
        warmup: common.warmup,
        reps: common.reps,
        drop_caches: common.drop_caches,
        params,
        per_rep: reps,
        summary,
    })
}

/// Scenario-specific latency statistics, as an `extra` field.
pub fn latency_value(samples: &[Duration]) -> Value {
    match Percentiles::of_micros(samples) {
        Some(percentiles) => json!(percentiles),
        None => Value::Null,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nearest_rank_picks_the_documented_samples() {
        let sorted: Vec<f64> = (1..=100).map(f64::from).collect();
        assert!((nearest_rank(&sorted, 0.50) - 50.0).abs() < f64::EPSILON);
        assert!((nearest_rank(&sorted, 0.99) - 99.0).abs() < f64::EPSILON);
        assert!((nearest_rank(&[7.0], 0.99) - 7.0).abs() < f64::EPSILON);
    }

    #[test]
    fn percentiles_refuse_to_invent_an_empty_distribution() {
        assert!(Percentiles::of(&[]).is_none());
        assert!(Spread::of(&[]).is_none());
    }

    #[test]
    fn a_rate_over_a_zero_window_is_zero_not_infinite() {
        assert!((per_second(10.0, 0.0)).abs() < f64::EPSILON);
        assert!((per_second(10.0, 2.0) - 5.0).abs() < f64::EPSILON);
    }
}
