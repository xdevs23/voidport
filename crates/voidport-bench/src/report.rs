use std::fs::OpenOptions;
use std::io::Write as _;
use std::path::Path;
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Context as _, Result};
use serde::Serialize;
use serde_json::{Value, json};

use crate::cli::Common;
use crate::fsutil;

/// `duration` is the window the scenario timed. Setup and teardown inside its
/// repetition are outside it.
#[derive(Debug)]
pub struct Rep {
    pub duration: Duration,
    pub ops: u64,
    /// Bytes moved in that window; 0 for metadata-only scenarios.
    pub bytes: u64,
    pub latencies: Vec<Duration>,
    pub extra: Value,
}

impl Rep {
    pub fn new(duration: Duration, ops: u64, bytes: u64) -> Self {
        Self {
            duration,
            ops,
            bytes,
            latencies: Vec::new(),
            extra: Value::Null,
        }
    }

    #[must_use]
    pub fn with_latencies(mut self, latencies: Vec<Duration>) -> Self {
        self.latencies = latencies;
        self
    }

    #[must_use]
    pub fn with_extra(mut self, extra: Value) -> Self {
        self.extra = extra;
        self
    }
}

/// A distribution of samples where larger is worse.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct Percentiles {
    pub mean: f64,
    pub p50: f64,
    pub p99: f64,
    pub max: f64,
}

impl Percentiles {
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

    pub fn of_micros(samples: &[Duration]) -> Option<Self> {
        let micros: Vec<f64> = samples
            .iter()
            .map(|sample| sample.as_secs_f64() * 1e6)
            .collect();
        Self::of(&micros)
    }
}

/// A distribution of samples where larger is better.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct Spread {
    pub mean: f64,
    pub p50: f64,
    pub min: f64,
    pub max: f64,
}

impl Spread {
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

fn nearest_rank(sorted: &[f64], quantile: f64) -> f64 {
    debug_assert!(!sorted.is_empty());
    let rank = (quantile * sorted.len() as f64).ceil() as usize;
    sorted[rank.clamp(1, sorted.len()) - 1]
}

#[derive(Debug, Serialize)]
pub struct RepReport {
    pub seconds: f64,
    pub ops: u64,
    pub bytes: u64,
    pub ops_per_second: f64,
    pub mib_per_second: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_us: Option<Percentiles>,
    #[serde(skip_serializing_if = "Value::is_null")]
    pub extra: Value,
}

impl RepReport {
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

#[derive(Debug, Serialize)]
pub struct Summary {
    pub seconds: Percentiles,
    pub ops_per_second: Spread,
    pub mib_per_second: Spread,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_us: Option<Percentiles>,
}

#[derive(Debug, Serialize)]
pub struct Run {
    pub scenario: &'static str,
    pub label: String,
    pub directory: String,
    pub finished_unix: u64,
    pub warmup: u32,
    pub reps: u32,
    pub drop_caches: bool,
    pub params: Value,
    pub per_rep: Vec<RepReport>,
    pub summary: Summary,
}

impl Run {
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

const MIB: f64 = 1024.0 * 1024.0;

fn per_second(quantity: f64, seconds: f64) -> f64 {
    if seconds > 0.0 {
        quantity / seconds
    } else {
        0.0
    }
}

/// The page cache is dropped before every repetition including the warmups,
/// so a read scenario prepares its files before calling this. `repetition`
/// receives the zero-based index of a measured repetition, or `None` for a
/// warmup.
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
