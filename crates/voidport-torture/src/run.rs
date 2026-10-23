use std::io::Write as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::Serialize;
use voidport::guardian::Launch;

use crate::connections::Connections;
use crate::invariant::{Ceilings, Ending, Findings, Outage, Violation, Watch};
use crate::metrics::{Class, ClassSnapshot, Metrics};
use crate::mounts::{Fleet, TortureMount, loop_devices_under, mounted_under};
use crate::reference::Reference;
use crate::resource::{Probe, Sample};
use crate::server::{Restarts, Supervisor};
use crate::workload::{self, Seed, Site, State};

const SAMPLE_INTERVAL: Duration = Duration::from_secs(1);

const JOIN_PATIENCE: Duration = Duration::from_secs(60);

const LOOK_AGAIN: Duration = Duration::from_millis(50);

const SETTLE_PATIENCE: Duration = Duration::from_secs(20);

/// It bounds a spin: a class whose every operation fails at once would
/// otherwise record millions of failures a second.
const FAILURE_PAUSE: Duration = Duration::from_millis(1);

const RESTART_CADENCE: Duration = Duration::from_secs(60);

const RESTART_SCALING: u32 = 6;

const RESTART_FLOOR: Duration = Duration::from_secs(5);

/// The restart cadence is capped at a quarter of the duration, so a short run
/// still restarts several times.
const RESTART_SHARE: u32 = 4;

#[derive(Clone, Debug)]
pub struct Plan {
    pub urls: Vec<String>,
    pub work_dir: PathBuf,
    pub duration: Duration,
    pub intensity: u64,
    pub classes: Vec<Class>,
    pub mounts: u64,
    pub probe: Probe,
    pub log: Option<PathBuf>,
    pub seed: Seed,
    /// It must already be started, before anything was mounted. A plan without
    /// one cannot run the restart class.
    pub server: Option<Arc<Supervisor>>,
    pub guardian: Launch,
}

#[derive(Debug)]
struct Worker {
    class: Class,
    index: u64,
    begun: AtomicU64,
    finished: AtomicU64,
}

struct Operation<'a>(&'a Worker);

impl Drop for Operation<'_> {
    fn drop(&mut self) {
        let _ = self.0.finished.fetch_add(1, Ordering::SeqCst);
    }
}

impl Worker {
    fn new(class: Class, index: u64) -> Self {
        Self {
            class,
            index,
            begun: AtomicU64::new(0),
            finished: AtomicU64::new(0),
        }
    }

    fn operation(&self) -> Operation<'_> {
        let _ = self.begun.fetch_add(1, Ordering::SeqCst);
        Operation(self)
    }

    fn in_flight(&self) -> Option<u64> {
        let begun = self.begun.load(Ordering::SeqCst);
        (self.finished.load(Ordering::SeqCst) < begun).then_some(begun)
    }

    fn has_finished(&self, operation: u64) -> bool {
        self.finished.load(Ordering::SeqCst) >= operation
    }
}

fn restart_interval(intensity: u64, duration: Duration) -> Duration {
    let scaling = u32::try_from(intensity.clamp(1, u64::from(RESTART_SCALING))).unwrap_or(1);
    (RESTART_CADENCE / scaling)
        .min(duration / RESTART_SHARE)
        .max(RESTART_FLOOR)
}

#[derive(Clone, Debug, Serialize)]
pub struct ClassReport {
    pub class: Class,
    pub workers: u64,
    pub completed: u64,
    pub failed: u64,
    pub p50_ms: u64,
    pub p90_ms: u64,
    pub p99_ms: u64,
    pub max_ms: u64,
    pub errnos: Vec<(i32, String, u64)>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Report {
    pub duration_ms: u64,
    pub intensity: u64,
    pub mounts: u64,
    pub classes: Vec<ClassReport>,
    pub samples: Vec<Sample>,
    pub violations: Vec<Violation>,
    pub bounds: Bounds,
    pub restarts: Restarts,
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct Bounds {
    pub fds: u64,
    pub node_descriptors: u64,
    pub nodes: u64,
    pub handles: u64,
    pub rss_kib: u64,
}

impl Report {
    #[must_use]
    pub fn passed(&self) -> bool {
        self.violations.is_empty()
    }

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
                "{:<12} {:>10} {:>10} {:>10} {:>8} {:>8} {:>8} {:>9}",
                class.class.name(),
                class.completed,
                per_second(class.completed, self.duration_ms),
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
            "restarts: {} graceful, {} hard, {} of the hard ones inside a control mutation",
            self.restarts.graceful, self.restarts.hard, self.restarts.inside_mutation
        );
        let _ = writeln!(
            out,
            "bounds: fds<={} node_fds<={} nodes<={} handles<={} rss<={} KiB",
            self.bounds.fds,
            self.bounds.node_descriptors,
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

#[derive(Serialize)]
#[serde(tag = "record", rename_all = "kebab-case")]
enum LogLine<'a> {
    Plan {
        urls: &'a [String],
        duration_ms: u64,
        intensity: u64,
        mounts: u64,
        classes: Vec<&'static str>,
        bounds: Bounds,
    },
    Sample(Sample),
    Violation(Violation),
    Report(&'a Report),
}

struct Log {
    file: Option<Mutex<std::fs::File>>,
}

impl Log {
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

    /// Ignores a log that cannot be written: losing a log line must not end the
    /// run.
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

struct Verdicts<'a> {
    log: &'a Log,
    found: Mutex<Vec<Violation>>,
}

impl<'a> Verdicts<'a> {
    fn new(log: &'a Log) -> Self {
        Self {
            log,
            found: Mutex::new(Vec::new()),
        }
    }

    fn report(&self, violation: Violation) {
        eprintln!("!!! voidport-torture: {violation}");
        self.keep(violation);
    }

    fn keep(&self, violation: Violation) {
        self.log.write(&LogLine::Violation(violation.clone()));
        self.found
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .push(violation);
    }

    fn into_found(self) -> Vec<Violation> {
        self.found
            .into_inner()
            .unwrap_or_else(|poison| poison.into_inner())
    }
}

/// Returns only the failures that make a run impossible. Everything that
/// happens during the run is a violation in the report, not an error.
pub fn run(plan: &Plan) -> anyhow::Result<Report> {
    anyhow::ensure!(plan.intensity > 0, "intensity must be at least one worker");
    anyhow::ensure!(plan.mounts > 0, "a run needs at least one mount");
    anyhow::ensure!(!plan.classes.is_empty(), "a run needs at least one class");
    anyhow::ensure!(
        !plan.classes.contains(&Class::Restart) || plan.server.is_some(),
        "the restart class restarts a server the run owns; start one for the plan"
    );
    anyhow::ensure!(
        !plan
            .classes
            .iter()
            .any(|class| matches!(class, Class::Rules | Class::Listeners | Class::Restart))
            || plan.probe.control_socket.is_some(),
        "the rules and listeners classes mutate the server's own state, and the \
         restart class kills it inside a mutation of its own; \
         give the plan its control socket"
    );

    std::fs::create_dir_all(&plan.work_dir)?;
    let log = Log::open(plan.log.as_ref())?;
    let reference = Reference::prepare(&plan.work_dir)?;
    let connections = Arc::new(Connections::default());
    let fleet = Fleet::new(
        &plan.urls,
        &plan.work_dir,
        plan.guardian.clone(),
        Arc::clone(&connections),
    )?;

    let mounts: Vec<TortureMount> = (0..plan.mounts)
        .map(|index| fleet.mount(&format!("base-{index}"), fleet.url(index)))
        .collect::<anyhow::Result<_>>()?;
    plan.seed.build(mounts[0].root())?;

    let workers: u64 = plan
        .classes
        .iter()
        .map(|class| class.workers(plan.intensity))
        .sum();
    let baseline = plan.probe.sample(0);
    let ceilings = Ceilings::for_run(&baseline, plan.seed.entries(), plan.mounts, workers);
    let bounds = Bounds {
        fds: ceilings.fds,
        node_descriptors: ceilings.node_descriptors,
        nodes: ceilings.nodes,
        handles: ceilings.handles,
        rss_kib: ceilings.rss_kib,
    };
    log.write(&LogLine::Plan {
        urls: &plan.urls,
        duration_ms: u64::try_from(plan.duration.as_millis()).unwrap_or(u64::MAX),
        intensity: plan.intensity,
        mounts: plan.mounts,
        classes: plan.classes.iter().map(|class| class.name()).collect(),
        bounds,
    });

    let metrics = Arc::new(Metrics::default());
    let stop = Arc::new(AtomicBool::new(false));
    let finished = Arc::new(AtomicUsize::new(0));
    let verdicts = Verdicts::new(&log);
    let samples: Arc<Mutex<Vec<Sample>>> = Arc::new(Mutex::new(Vec::new()));
    let findings = Findings::default();
    let outage = Outage::default();
    let restart_interval = restart_interval(plan.intensity, plan.duration);
    let crew: Vec<Worker> = plan
        .classes
        .iter()
        .flat_map(|class| {
            (0..class.workers(plan.intensity)).map(|index| Worker::new(*class, index))
        })
        .collect();
    let started = Instant::now();

    std::thread::scope(|scope| {
        for worker in &crew {
            let (metrics, stop, finished) = (
                Arc::clone(&metrics),
                Arc::clone(&stop),
                Arc::clone(&finished),
            );
            let (mounts, fleet, seed) = (&mounts, &fleet, plan.seed);
            let (server, control) = (plan.server.as_deref(), plan.probe.control_socket.as_deref());
            let (findings, connections, outage) = (&findings, &connections, &outage);
            scope.spawn(move || {
                let site = Site {
                    mounts,
                    fleet,
                    index: worker.index,
                    seed,
                    server,
                    control,
                    findings,
                    connections,
                    outage,
                    started,
                    restart_interval,
                };
                let mut state = State::for_class(worker.class);
                while !stop.load(Ordering::Relaxed) {
                    let outcome = {
                        let _operation = worker.operation();
                        let operation = Instant::now();
                        let outcome = workload::step(worker.class, &site, &mut state);
                        let errno = outcome
                            .as_ref()
                            .err()
                            .map(|error| error.raw_os_error().unwrap_or(0));
                        metrics.class(worker.class).record(
                            operation.elapsed(),
                            errno,
                            started.elapsed(),
                        );
                        outcome
                    };
                    if outcome.is_err() {
                        std::thread::sleep(FAILURE_PAUSE);
                    }
                }
                finished.fetch_add(1, Ordering::Relaxed);
            });
        }
        {
            let (reference, stop) = (&reference, Arc::clone(&stop));
            scope.spawn(move || reference.work_until(&stop));
        }

        let watcher = {
            let (metrics, stop, samples) = (
                Arc::clone(&metrics),
                Arc::clone(&stop),
                Arc::clone(&samples),
            );
            let (probe, classes, log) = (plan.probe.clone(), plan.classes.clone(), &log);
            let (findings, outage, verdicts) = (&findings, &outage, &verdicts);
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
                    // Loud and on stderr at once: a run of hours must report a defect when it
                    // happens.
                    for violation in watch.observe(elapsed, &metrics, &sample, outage) {
                        verdicts.report(violation);
                    }
                    for violation in findings.drain() {
                        verdicts.keep(violation);
                    }
                }
            })
        };

        std::thread::sleep(plan.duration);
        let stalled = wait_for_the_operations_in_flight(&crew, &reference);
        stop.store(true, Ordering::Relaxed);
        for class in &stalled {
            verdicts.report(Violation::Stalled {
                class: *class,
                elapsed_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            });
        }
        if !stalled.is_empty() {
            // A stalled worker is inside a request without a reply and the scope cannot
            // end before it returns, so ending every kernel and control connection fails
            // that request.
            connections.end_all();
        }
        let _ = watcher.join();

        let deadline = Instant::now() + JOIN_PATIENCE;
        while finished.load(Ordering::Relaxed) < workers as usize && Instant::now() < deadline {
            std::thread::sleep(LOOK_AGAIN);
        }
        let unfinished = workers as usize - finished.load(Ordering::Relaxed).min(workers as usize);
        if unfinished > 0 {
            verdicts.report(Violation::UnfinishedWorkers { count: unfinished });
            eprintln!(
                "    (the teardown now waits for them; a worker stuck in a filesystem call \
                 cannot be taken back)"
            );
        }
    });

    let ran = started.elapsed();
    reference.remove();
    drop(mounts);
    for violation in findings.drain() {
        verdicts.keep(violation);
    }
    for path in mounted_under(&plan.work_dir) {
        verdicts.report(Violation::LeakedMount { path });
    }
    for (device, backing) in loop_devices_under(&plan.work_dir) {
        verdicts.report(Violation::LeakedLoopDevice { device, backing });
    }
    let after = settled(&plan.probe, ran);
    log.write(&LogLine::Sample(after));
    for violation in crate::invariant::retained(&baseline, &after) {
        verdicts.report(violation);
    }

    let restarts = plan
        .server
        .as_ref()
        .map(|server| server.restarts())
        .unwrap_or_default();
    let report = Report {
        duration_ms: u64::try_from(ran.as_millis()).unwrap_or(u64::MAX),
        intensity: plan.intensity,
        mounts: plan.mounts,
        classes: plan
            .classes
            .iter()
            .map(|class| class_report(*class, class.workers(plan.intensity), &metrics))
            .collect(),
        samples: samples
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .clone(),
        violations: verdicts.into_found(),
        bounds,
        restarts,
    };
    log.write(&LogLine::Report(&report));
    Ok(report)
}

fn wait_for_the_operations_in_flight(crew: &[Worker], reference: &Reference) -> Vec<Class> {
    let ending = Ending::now(reference);
    let in_flight: Vec<(&Worker, u64)> = crew
        .iter()
        .filter_map(|worker| Some((worker, worker.in_flight()?)))
        .collect();
    loop {
        let mut waiting: Vec<Class> = in_flight
            .iter()
            .filter(|(worker, operation)| !worker.has_finished(*operation))
            .map(|(worker, _)| worker.class)
            .collect();
        waiting.sort_unstable();
        waiting.dedup();
        if waiting.is_empty() || ending.stalled(reference) {
            return waiting;
        }
        std::thread::sleep(LOOK_AGAIN);
    }
}

/// The last sample is taken after a short settle, because the unmount of the
/// client and the server noticing it are two events. It is a settle, not a
/// retry.
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

fn class_report(class: Class, workers: u64, metrics: &Metrics) -> ClassReport {
    let counts = metrics.class(class).snapshot();
    let percentile = |percent| {
        counts.percentile(percent).map_or(0, |latency| {
            u64::try_from(latency.as_millis()).unwrap_or(u64::MAX)
        })
    };
    ClassReport {
        class,
        workers,
        completed: counts.completed,
        failed: counts.failed,
        p50_ms: percentile(50),
        p90_ms: percentile(90),
        p99_ms: percentile(99),
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

fn per_second(operations: u64, duration_ms: u64) -> String {
    let duration_ms = u128::from(duration_ms.max(1));
    let tenths = (u128::from(operations) * 10_000 + duration_ms / 2) / duration_ms;
    format!("{}.{}", tenths / 10, tenths % 10)
}

fn max_bucket_ms(counts: &ClassSnapshot) -> u64 {
    counts
        .buckets
        .iter()
        .rposition(|count| *count > 0)
        .map_or(0, |index| (1u64 << index.min(63)) / 1000)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::invariant::Ceilings;

    #[test]
    fn the_restart_cadence_scales_and_stays_inside_its_bounds() {
        let hour = Duration::from_secs(3600);
        assert_eq!(restart_interval(1, hour), RESTART_CADENCE);
        assert_eq!(restart_interval(2, hour), RESTART_CADENCE / 2);
        assert_eq!(
            restart_interval(600, hour),
            RESTART_CADENCE / RESTART_SCALING
        );

        let smoke = Duration::from_secs(90);
        assert_eq!(restart_interval(1, smoke), smoke / RESTART_SHARE);
        assert!(smoke.as_secs_f64() / restart_interval(1, smoke).as_secs_f64() >= 3.0);

        assert_eq!(restart_interval(600, Duration::from_secs(1)), RESTART_FLOOR);
    }

    #[test]
    fn a_rate_is_rounded_to_the_nearest_tenth() {
        assert_eq!(per_second(1, 3000), "0.3");
        assert_eq!(per_second(2, 3000), "0.7");
        assert_eq!(per_second(12_345, 1000), "12345.0");
        assert_eq!(per_second(5, 0), "5000.0");
        assert_eq!(per_second(u64::MAX, 1000), format!("{}.0", u64::MAX));
    }

    fn working_reference(during_the_load: u64) -> Reference {
        let reference = Reference::new(PathBuf::new());
        for _ in 0..during_the_load {
            reference.record();
        }
        reference
    }

    fn judged_while_the_reference_works(crew: &[Worker], reference: &Reference) -> Vec<Class> {
        let done = AtomicBool::new(false);
        std::thread::scope(|scope| {
            let _helper = scope.spawn(|| {
                while !done.load(Ordering::SeqCst) {
                    reference.record();
                    std::thread::yield_now();
                }
            });
            let judged = wait_for_the_operations_in_flight(crew, reference);
            done.store(true, Ordering::SeqCst);
            judged
        })
    }

    #[test]
    fn nothing_in_flight_is_judged_at_once() {
        let crew = [Worker::new(Class::Walk, 0), Worker::new(Class::Xattr, 0)];
        let reference = Reference::new(PathBuf::new());
        assert!(wait_for_the_operations_in_flight(&crew, &reference).is_empty());
    }

    #[test]
    fn an_operation_that_finishes_is_not_stalled() {
        let crew = [Worker::new(Class::Walk, 0)];
        let reference = working_reference(5);
        let operation = crew[0].operation();
        let judged = std::thread::scope(|scope| {
            let _finishing = scope.spawn(move || drop(operation));
            wait_for_the_operations_in_flight(&crew, &reference)
        });
        assert!(judged.is_empty(), "{judged:?}");
    }

    #[test]
    fn a_class_whose_operations_never_finish_is_reported_once() {
        let crew = [
            Worker::new(Class::Xattr, 0),
            Worker::new(Class::Xattr, 1),
            Worker::new(Class::Walk, 0),
        ];
        let reference = working_reference(5);
        let _first = crew[0].operation();
        let _second = crew[1].operation();
        assert_eq!(
            judged_while_the_reference_works(&crew, &reference),
            [Class::Xattr]
        );
        assert!(reference.completed() >= 10, "judged before the measure");
    }

    /// A run in which every class waits on an operation still reaches a verdict,
    /// because the reference works outside every mount.
    #[test]
    fn every_class_waiting_is_still_judged() {
        let crew = [Worker::new(Class::Walk, 0), Worker::new(Class::Xattr, 0)];
        let reference = working_reference(0);
        let _walk = crew[0].operation();
        let _xattr = crew[1].operation();
        assert_eq!(
            judged_while_the_reference_works(&crew, &reference),
            [Class::Walk, Class::Xattr]
        );
    }

    #[test]
    fn an_operation_is_in_flight_until_it_is_dropped() {
        let worker = Worker::new(Class::Walk, 0);
        assert_eq!(worker.in_flight(), None);
        let operation = worker.operation();
        assert_eq!(worker.in_flight(), Some(1));
        assert!(!worker.has_finished(1));
        drop(operation);
        assert_eq!(worker.in_flight(), None);
        assert!(worker.has_finished(1));
    }

    /// The cadence does not enter into this: the restart arm completes an
    /// operation every slice while it waits, so the only interval without a
    /// completion is a restart itself. The mount count does not enter either,
    /// because every mount is waited out at the same time.
    #[test]
    fn a_restarts_own_patience_stays_inside_the_progress_watchdog() {
        let watchdog = Ceilings::for_run(&Sample::default(), 0, 1, 1).watchdog;
        assert!(
            crate::server::PATIENCE * 2 + crate::workload::HEAL_PATIENCE < watchdog,
            "a restart may take {:?} + {:?} + {:?}, against a {watchdog:?} watchdog",
            crate::server::PATIENCE,
            crate::server::PATIENCE,
            crate::workload::HEAL_PATIENCE
        );
    }
}
