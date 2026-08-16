//! The engine: mount, load, watch, tear down, report.
//!
//! A run is one scoped set of threads — one per worker, plus the watcher — over
//! a fleet of real mounts. The shape is deliberately boring, because the
//! interesting behaviour is supposed to be the server's:
//!
//! * the workers do nothing but perform one operation and record it, so the
//!   harness cannot itself become the bottleneck it is measuring;
//! * the watcher samples once a second and judges what it sees against the
//!   [`Ceilings`], printing every violation the instant it finds one — a run of
//!   hours must not save up its bad news for the end;
//! * the teardown is bounded and checked: workers are given a deadline to
//!   finish, the mounts come down, and what the kernel still knows about the
//!   work directory afterwards is the clean-shutdown invariant.
//!
//! The whole thing is one function so that a smoke test in the suite and an
//! hours-long operator run are the *same* run at different sizes.

use std::io::Write as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::invariant::{Ceilings, Violation, Watch};
use crate::metrics::{Class, ClassSnapshot, Metrics};
use crate::mounts::{Fleet, TortureMount, loop_devices_under, mounted_under};
use crate::resource::{Probe, Sample};
use crate::workload::{self, Seed, Site, State};

/// How often the watcher samples.
const SAMPLE_INTERVAL: Duration = Duration::from_secs(1);

/// How long the workers are given to notice the stop signal and finish the
/// operation they are in.
const JOIN_PATIENCE: Duration = Duration::from_secs(60);

/// How long the teardown waits for the server to notice the mounts are gone
/// before it reads what it is still holding.
const SETTLE_PATIENCE: Duration = Duration::from_secs(20);

/// How long a worker whose operation just failed pauses.
///
/// It bounds nothing but a spin: a class whose every operation fails at once —
/// a mount that has gone away, a namespace that was deleted — would otherwise
/// record millions of failures a second and drown the machine in its own error
/// path.
const FAILURE_PAUSE: Duration = Duration::from_millis(1);

/// What to run.
#[derive(Clone, Debug)]
pub struct Plan {
    /// The voidport URL every mount is made from.
    pub url: String,
    /// Where mountpoints and the run's own files live. Created if absent.
    pub work_dir: PathBuf,
    /// How long to keep the load on.
    pub duration: Duration,
    /// Workers per class.
    pub intensity: u64,
    /// The classes to drive.
    pub classes: Vec<Class>,
    /// How many mounts to hold open for the duration.
    pub mounts: u64,
    /// Where to look for the server's holdings.
    pub probe: Probe,
    /// Where to append the sample and violation log, as JSON lines.
    pub log: Option<PathBuf>,
    /// How large the working set is.
    pub seed: Seed,
}

/// One class's account of the run.
#[derive(Clone, Debug, Serialize)]
pub struct ClassReport {
    /// The class.
    pub class: Class,
    /// How many workers drove it.
    pub workers: u64,
    /// Operations completed.
    pub completed: u64,
    /// How many of them failed with an errno.
    pub failed: u64,
    /// Completed operations per second, over the whole run.
    pub per_second: f64,
    /// Median latency, in milliseconds, as the bound of its bucket.
    pub p50_ms: u64,
    /// The same at the 90th percentile.
    pub p90_ms: u64,
    /// The same at the 99th percentile.
    pub p99_ms: u64,
    /// The slowest bucket anything landed in.
    pub max_ms: u64,
    /// The errnos met, most frequent first, each with what it means.
    pub errnos: Vec<(i32, String, u64)>,
}

/// What a run produced.
#[derive(Clone, Debug, Serialize)]
pub struct Report {
    /// How long the load actually ran.
    pub duration_ms: u64,
    /// Workers per class.
    pub intensity: u64,
    /// Mounts held for the duration.
    pub mounts: u64,
    /// The per-class accounts.
    pub classes: Vec<ClassReport>,
    /// Every resource sample taken.
    pub samples: Vec<Sample>,
    /// Everything the watcher refused to accept. Empty is the only pass.
    pub violations: Vec<Violation>,
    /// The bounds the run was held to, as computed for its shape.
    pub bounds: Bounds,
}

/// The bounds a run was held to, as reported.
#[derive(Clone, Copy, Debug, Serialize)]
pub struct Bounds {
    /// Descriptors.
    pub fds: u64,
    /// Cache-resident node descriptors: the server's own budget.
    pub node_descriptors: u64,
    /// Threads.
    pub threads: u64,
    /// Nodes.
    pub nodes: u64,
    /// Handles.
    pub handles: u64,
    /// Resident kibibytes.
    pub rss_kib: u64,
}

impl Report {
    /// Whether the run held every invariant.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.violations.is_empty()
    }

    /// The human summary, for an operator watching a run end.
    #[must_use]
    pub fn render(&self) -> String {
        use std::fmt::Write as _;
        let mut out = String::new();
        let _ = writeln!(
            out,
            "voidport-torture: {} s, intensity {}, {} mounts",
            self.duration_ms / 1000,
            self.intensity,
            self.mounts
        );
        let _ = writeln!(
            out,
            "{:<12} {:>10} {:>10} {:>10} {:>8} {:>8} {:>8} {:>9}",
            "class", "ops", "ops/s", "failed", "p50 ms", "p90 ms", "p99 ms", "max ms"
        );
        for class in &self.classes {
            let _ = writeln!(
                out,
                "{:<12} {:>10} {:>10.1} {:>10} {:>8} {:>8} {:>8} {:>9}",
                class.class.name(),
                class.completed,
                class.per_second,
                class.failed,
                class.p50_ms,
                class.p90_ms,
                class.p99_ms,
                class.max_ms
            );
            for (errno, meaning, count) in &class.errnos {
                let _ = writeln!(out, "{:<12}   {count} x errno {errno} ({meaning})", "");
            }
        }
        let _ = writeln!(
            out,
            "bounds: fds<={} node_fds<={} threads<={} nodes<={} handles<={} rss<={} KiB",
            self.bounds.fds,
            self.bounds.node_descriptors,
            self.bounds.threads,
            self.bounds.nodes,
            self.bounds.handles,
            self.bounds.rss_kib
        );
        for quantity in [
            "fds",
            "node_descriptors",
            "threads",
            "nodes",
            "handles",
            "rss_kib",
        ] {
            let series: Vec<u64> = self
                .samples
                .iter()
                .filter_map(|sample| match quantity {
                    "fds" => sample.fds,
                    "node_descriptors" => sample.node_descriptors,
                    "threads" => sample.threads,
                    "nodes" => sample.nodes,
                    "handles" => sample.handles,
                    _ => sample.rss_kib,
                })
                .collect();
            if let (Some(first), Some(last), Some(peak)) =
                (series.first(), series.last(), series.iter().max())
            {
                let _ = writeln!(
                    out,
                    "{quantity:>8}: first {first}, peak {peak}, last {last}"
                );
            }
        }
        if self.violations.is_empty() {
            let _ = writeln!(out, "no invariant violations");
        } else {
            let _ = writeln!(out, "{} INVARIANT VIOLATIONS:", self.violations.len());
            for violation in &self.violations {
                let _ = writeln!(out, "  !!! {violation}");
            }
        }
        out
    }
}

/// One line of the run log.
#[derive(Serialize)]
#[serde(tag = "record", rename_all = "kebab-case")]
enum LogLine<'a> {
    /// The run's shape, written first.
    Plan {
        url: &'a str,
        duration_ms: u64,
        intensity: u64,
        mounts: u64,
        classes: Vec<&'static str>,
        bounds: Bounds,
    },
    /// One resource sample.
    Sample(Sample),
    /// One violation, written the instant it is found.
    Violation(Violation),
    /// The final account.
    Report(&'a Report),
}

/// Where violations and samples are written as they happen.
struct Log {
    file: Option<Mutex<std::fs::File>>,
}

impl Log {
    /// Opens the log, or writes nowhere if none was asked for.
    fn open(path: Option<&PathBuf>) -> anyhow::Result<Self> {
        let Some(path) = path else {
            return Ok(Self { file: None });
        };
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        Ok(Self {
            file: Some(Mutex::new(file)),
        })
    }

    /// Appends one line, ignoring a log that cannot be written: the run is the
    /// point, and losing a log line must not end it.
    fn write(&self, line: &LogLine<'_>) {
        let Some(file) = self.file.as_ref() else {
            return;
        };
        let Ok(mut encoded) = serde_json::to_vec(line) else {
            return;
        };
        encoded.push(b'\n');
        let mut file = file.lock().unwrap_or_else(|poison| poison.into_inner());
        let _ = file.write_all(&encoded);
        let _ = file.flush();
    }
}

/// Runs the plan and reports what happened.
///
/// # Errors
///
/// Returns only the failures that make a run impossible: a URL that will not
/// parse, a work directory that cannot be created, a mount that will not mount,
/// a working set that cannot be written. Everything that happens *during* the
/// run is a violation in the report, not an error — a run that found a defect
/// still has to report the numbers around it.
pub fn run(plan: &Plan) -> anyhow::Result<Report> {
    anyhow::ensure!(plan.intensity > 0, "intensity must be at least one worker");
    anyhow::ensure!(plan.mounts > 0, "a run needs at least one mount");
    anyhow::ensure!(!plan.classes.is_empty(), "a run needs at least one class");

    std::fs::create_dir_all(&plan.work_dir)?;
    let log = Log::open(plan.log.as_ref())?;
    let fleet = Fleet::new(&plan.url, &plan.work_dir)?;

    let mounts: Vec<TortureMount> = (0..plan.mounts)
        .map(|index| fleet.mount(&format!("base-{index}")))
        .collect::<anyhow::Result<_>>()?;
    plan.seed.build(mounts[0].root())?;

    let workers = plan.intensity * plan.classes.len() as u64;
    let baseline = plan.probe.sample(0);
    let ceilings = Ceilings::for_run(&baseline, plan.seed.entries(), plan.mounts, workers);
    let bounds = Bounds {
        fds: ceilings.fds,
        node_descriptors: ceilings.node_descriptors,
        threads: ceilings.threads,
        nodes: ceilings.nodes,
        handles: ceilings.handles,
        rss_kib: ceilings.rss_kib,
    };
    log.write(&LogLine::Plan {
        url: &plan.url,
        duration_ms: u64::try_from(plan.duration.as_millis()).unwrap_or(u64::MAX),
        intensity: plan.intensity,
        mounts: plan.mounts,
        classes: plan.classes.iter().map(|class| class.name()).collect(),
        bounds,
    });

    let metrics = Arc::new(Metrics::default());
    let stop = Arc::new(AtomicBool::new(false));
    let finished = Arc::new(AtomicUsize::new(0));
    let violations: Arc<Mutex<Vec<Violation>>> = Arc::new(Mutex::new(Vec::new()));
    let samples: Arc<Mutex<Vec<Sample>>> = Arc::new(Mutex::new(Vec::new()));
    let started = Instant::now();

    std::thread::scope(|scope| {
        for class in &plan.classes {
            for index in 0..plan.intensity {
                let (metrics, stop, finished) = (
                    Arc::clone(&metrics),
                    Arc::clone(&stop),
                    Arc::clone(&finished),
                );
                let (class, mounts, fleet, seed) = (*class, &mounts, &fleet, plan.seed);
                scope.spawn(move || {
                    let site = Site {
                        mounts,
                        fleet,
                        index,
                        seed,
                    };
                    let mut state = State::for_class(class);
                    while !stop.load(Ordering::Relaxed) {
                        let operation = Instant::now();
                        let outcome = workload::step(class, &site, &mut state);
                        let errno = outcome
                            .as_ref()
                            .err()
                            .map(|error| error.raw_os_error().unwrap_or(0));
                        metrics
                            .class(class)
                            .record(operation.elapsed(), errno, started.elapsed());
                        if outcome.is_err() {
                            std::thread::sleep(FAILURE_PAUSE);
                        }
                    }
                    finished.fetch_add(1, Ordering::Relaxed);
                });
            }
        }

        // The watcher. It outlives the load by nothing: it stops when the stop
        // flag is set, having taken a last sample.
        let watcher = {
            let (metrics, stop) = (Arc::clone(&metrics), Arc::clone(&stop));
            let (violations, samples) = (Arc::clone(&violations), Arc::clone(&samples));
            let (probe, classes, log) = (plan.probe.clone(), plan.classes.clone(), &log);
            scope.spawn(move || {
                let mut watch = Watch::new(ceilings, &classes, &metrics);
                while !stop.load(Ordering::Relaxed) {
                    std::thread::sleep(SAMPLE_INTERVAL);
                    let elapsed = started.elapsed();
                    let sample =
                        probe.sample(u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX));
                    log.write(&LogLine::Sample(sample));
                    samples
                        .lock()
                        .unwrap_or_else(|poison| poison.into_inner())
                        .push(sample);
                    for violation in watch.observe(elapsed, &metrics, &sample) {
                        // Loud, immediately, and on stderr: a run of hours must
                        // report a defect when it happens, not when it ends.
                        eprintln!("!!! voidport-torture: {violation}");
                        log.write(&LogLine::Violation(violation.clone()));
                        violations
                            .lock()
                            .unwrap_or_else(|poison| poison.into_inner())
                            .push(violation);
                    }
                }
            })
        };

        std::thread::sleep(plan.duration);
        stop.store(true, Ordering::Relaxed);
        let _ = watcher.join();

        // The workers are given a deadline of their own, so a wedged one is
        // reported as the deadlock it is instead of silently held on to.
        let deadline = Instant::now() + JOIN_PATIENCE;
        while finished.load(Ordering::Relaxed) < workers as usize && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        let unfinished = workers as usize - finished.load(Ordering::Relaxed).min(workers as usize);
        if unfinished > 0 {
            let violation = Violation::UnfinishedWorkers { count: unfinished };
            eprintln!("!!! voidport-torture: {violation}");
            eprintln!(
                "    (the teardown now waits for them; a worker stuck in a filesystem call \
                 cannot be taken back)"
            );
            log.write(&LogLine::Violation(violation.clone()));
            violations
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .push(violation);
        }
    });

    let ran = started.elapsed();
    // Everything the run mounted comes down here, including the cycling class's
    // mounts, which are dropped by their own workers.
    drop(mounts);
    let mut violations = violations
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
        .clone();
    for path in mounted_under(&plan.work_dir) {
        let violation = Violation::LeakedMount { path };
        eprintln!("!!! voidport-torture: {violation}");
        log.write(&LogLine::Violation(violation.clone()));
        violations.push(violation);
    }
    for (device, backing) in loop_devices_under(&plan.work_dir) {
        let violation = Violation::LeakedLoopDevice { device, backing };
        eprintln!("!!! voidport-torture: {violation}");
        log.write(&LogLine::Violation(violation.clone()));
        violations.push(violation);
    }
    let after = settled(&plan.probe, ran);
    log.write(&LogLine::Sample(after));
    for violation in crate::invariant::retained(&baseline, &after) {
        eprintln!("!!! voidport-torture: {violation}");
        log.write(&LogLine::Violation(violation.clone()));
        violations.push(violation);
    }

    let report = Report {
        duration_ms: u64::try_from(ran.as_millis()).unwrap_or(u64::MAX),
        intensity: plan.intensity,
        mounts: plan.mounts,
        classes: plan
            .classes
            .iter()
            .map(|class| class_report(*class, plan.intensity, &metrics, ran))
            .collect(),
        samples: samples
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .clone(),
        violations,
        bounds,
    };
    log.write(&LogLine::Report(&report));
    Ok(report)
}

/// The sample taken once the server has finished letting go.
///
/// A connection closing and the session it named being torn down are one
/// event on the server, but the client's unmount and the server noticing it are
/// two, so the last sample is taken after a short settle, not the
/// instant the mounts come down. It is a settle, not a retry: whatever the
/// server still holds when the sessions are gone, it holds.
fn settled(probe: &Probe, ran: Duration) -> Sample {
    let elapsed_ms = u64::try_from(ran.as_millis()).unwrap_or(u64::MAX);
    let deadline = Instant::now() + SETTLE_PATIENCE;
    loop {
        let sample = probe.sample(elapsed_ms);
        if sample.sessions.is_none_or(|sessions| sessions == 0) || Instant::now() >= deadline {
            return sample;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// One class's account.
fn class_report(class: Class, workers: u64, metrics: &Metrics, ran: Duration) -> ClassReport {
    let counts = metrics.class(class).snapshot();
    let quantile = |q| {
        counts.quantile(q).map_or(0, |latency| {
            u64::try_from(latency.as_millis()).unwrap_or(u64::MAX)
        })
    };
    #[expect(
        clippy::cast_precision_loss,
        reason = "an operation count over a duration; the loss is far below one operation"
    )]
    let per_second = counts.completed as f64 / ran.as_secs_f64().max(f64::EPSILON);
    ClassReport {
        class,
        workers,
        completed: counts.completed,
        failed: counts.failed,
        per_second,
        p50_ms: quantile(0.5),
        p90_ms: quantile(0.9),
        p99_ms: quantile(0.99),
        max_ms: max_bucket_ms(&counts),
        errnos: metrics
            .class(class)
            .errnos()
            .into_iter()
            .map(|(errno, count)| {
                (
                    errno,
                    std::io::Error::from_raw_os_error(errno).to_string(),
                    count,
                )
            })
            .collect(),
    }
}

/// The upper bound of the slowest bucket anything landed in.
fn max_bucket_ms(counts: &ClassSnapshot) -> u64 {
    counts
        .buckets
        .iter()
        .rposition(|count| *count > 0)
        .map_or(0, |index| (1u64 << index.min(63)) / 1000)
}
