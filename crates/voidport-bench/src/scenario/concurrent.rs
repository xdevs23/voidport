//! Concurrent workloads: coherence between a writer and readers, and mixed
//! parallel I/O.
//!
//! These are the two properties the design claims and a single-threaded
//! benchmark cannot show: that the server is the point of truth for several
//! mounts at once, and that it stays parallel under load.

use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::FileExt as _;
use std::sync::Barrier;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result};
use serde_json::json;

use crate::cli::Common;
use crate::fsutil;
use crate::report::{self, Rep, Run};

/// Bytes in a mebibyte.
const MIB: f64 = 1024.0 * 1024.0;

/// One writer appending records while readers poll for them.
///
/// The writer is paced: a record is appended, timestamped, and then nothing
/// happens for `interval`. That is what makes the reported latency a
/// *visibility* latency — how long after a write lands another reader of the
/// same file can see it — not the depth of a queue the readers are
/// draining. On a caching client the number is bounded by the client's
/// revalidation policy, not by the server's round trip, and that is precisely
/// what it is here to show.
///
/// Throughput is reported two ways: the run's own `mib_per_second`, which the
/// pacing bounds, and `writer_active_mib_per_second` in the extras, which is
/// the writer's append rate with the pacing removed.
pub fn one_writer_many_readers(
    common: &Common,
    readers: u64,
    records: u64,
    record_bytes: u64,
    interval: Duration,
    timeout: Duration,
    poll: Duration,
) -> Result<Run> {
    anyhow::ensure!(readers > 0 && records > 0, "the scenario needs both");
    anyhow::ensure!(record_bytes >= 8, "a record carries its sequence number");
    let directory = fsutil::work_directory(&common.dir, "one-writer-many-readers")?;
    let path = directory.join("stream.bin");
    let record_size = record_bytes as usize;
    let params = json!({
        "readers": readers,
        "records": records,
        "record_bytes": record_bytes,
        "interval_ms": interval.as_millis() as u64,
        "timeout_ms": timeout.as_millis() as u64,
        "poll_us": poll.as_micros() as u64,
    });

    report::drive("one-writer-many-readers", common, params, |_| {
        if path.exists() {
            fs::remove_file(&path).context("cannot clear the previous stream")?;
        }
        File::create(&path)
            .context("cannot create the stream")?
            .sync_all()
            .context("cannot fsync the stream")?;

        let stamps: Vec<AtomicU64> = (0..records).map(|_| AtomicU64::new(0)).collect();
        let ready = Barrier::new(readers as usize + 1);
        let base = Instant::now();

        let (visibility, timeouts, appends, active, reader_bytes) = thread::scope(|scope| {
            let polling: Vec<_> = (0..readers)
                .map(|_| {
                    let stamps = &stamps;
                    let ready = &ready;
                    let path = &path;
                    scope.spawn(move || -> Result<(Vec<Duration>, u64, u64)> {
                        let file = File::open(path).context("a reader cannot open the stream")?;
                        let mut buffer = vec![0u8; record_size];
                        let mut seen: Vec<Duration> = Vec::with_capacity(records as usize);
                        let mut missed = 0u64;
                        let mut bytes = 0u64;
                        ready.wait();
                        for index in 0..records {
                            let offset = index * record_bytes;
                            let deadline = Instant::now() + timeout;
                            loop {
                                if file.read_exact_at(&mut buffer, offset).is_ok()
                                    && sequence(&buffer) == index
                                {
                                    let at = base.elapsed();
                                    let written = await_stamp(&stamps[index as usize]);
                                    seen.push(at.saturating_sub(written));
                                    bytes += record_bytes;
                                    break;
                                }
                                if Instant::now() >= deadline {
                                    missed += 1;
                                    break;
                                }
                                thread::sleep(poll);
                            }
                        }
                        Ok((seen, missed, bytes))
                    })
                })
                .collect();

            let writer = scope.spawn(|| -> Result<(Vec<Duration>, Duration)> {
                let mut file = OpenOptions::new()
                    .append(true)
                    .open(&path)
                    .context("the writer cannot open the stream")?;
                let mut record = fsutil::filler(record_size);
                let mut appends: Vec<Duration> = Vec::with_capacity(records as usize);
                let mut active = Duration::ZERO;
                ready.wait();
                for index in 0..records {
                    record[..8].copy_from_slice(&index.to_le_bytes());
                    let at = Instant::now();
                    file.write_all(&record).context("cannot append a record")?;
                    let took = at.elapsed();
                    stamps[index as usize]
                        .store(base.elapsed().as_nanos() as u64 + 1, Ordering::Release);
                    appends.push(took);
                    active += took;
                    if index + 1 < records {
                        thread::sleep(interval);
                    }
                }
                Ok((appends, active))
            });

            let (appends, active) = writer
                .join()
                .map_err(|_| anyhow::anyhow!("the writer panicked"))??;
            let mut visibility = Vec::new();
            let mut timeouts = 0u64;
            let mut bytes = 0u64;
            for handle in polling {
                let (seen, missed, read) = handle
                    .join()
                    .map_err(|_| anyhow::anyhow!("a reader panicked"))??;
                visibility.extend(seen);
                timeouts += missed;
                bytes += read;
            }
            Ok::<_, anyhow::Error>((visibility, timeouts, appends, active, bytes))
        })?;

        let elapsed = base.elapsed();
        let bytes = records * record_bytes;
        let active_rate = if active > Duration::ZERO {
            bytes as f64 / MIB / active.as_secs_f64()
        } else {
            0.0
        };
        Ok(Rep::new(elapsed, records, bytes)
            .with_latencies(visibility)
            .with_extra(json!({
                "readers": readers,
                "visibility_timeouts": timeouts,
                "writer_append_us": report::latency_value(&appends),
                "writer_active_mib_per_second": active_rate,
                "reader_bytes": reader_bytes,
                "reader_mib_per_second": reader_bytes as f64 / MIB / elapsed.as_secs_f64(),
            })))
    })
}

/// The sequence number a record carries in its first eight bytes.
fn sequence(record: &[u8]) -> u64 {
    let mut head = [0u8; 8];
    head.copy_from_slice(&record[..8]);
    u64::from_le_bytes(head)
}

/// Waits for the writer's timestamp of a record the reader has already seen.
///
/// The store follows the write it timestamps, so a reader can in principle
/// observe the data first. The window is a few instructions wide; spinning
/// through it keeps the measurement honest without a lock on the hot path.
fn await_stamp(stamp: &AtomicU64) -> Duration {
    loop {
        let nanos = stamp.load(Ordering::Acquire);
        if nanos != 0 {
            return Duration::from_nanos(nanos - 1);
        }
        std::hint::spin_loop();
    }
}

/// Threads doing mixed reads and writes on their own files at once.
///
/// One operation is a write followed by a read, both at pseudorandom offsets
/// of the thread's own file, so threads contend for the server and the host
/// filesystem but never for each other's bytes.
pub fn parallel_rw(
    common: &Common,
    threads: u64,
    ops_per_thread: u64,
    block_kib: u64,
    file_mib: u64,
) -> Result<Run> {
    anyhow::ensure!(threads > 0 && ops_per_thread > 0, "the scenario needs both");
    let directory = fsutil::work_directory(&common.dir, "parallel-rw")?;
    let block = (block_kib * 1024) as usize;
    let size = file_mib * 1024 * 1024;
    anyhow::ensure!(block > 0 && size >= block as u64, "the block must fit");
    let paths = fsutil::populate(&directory, threads, size)?;
    let blocks = size / block as u64;
    let params = json!({
        "threads": threads,
        "ops_per_thread": ops_per_thread,
        "block_kib": block_kib,
        "file_mib": file_mib,
    });

    report::drive("parallel-rw", common, params, |_| {
        let ready = Barrier::new(threads as usize + 1);
        let latencies = thread::scope(|scope| {
            let workers: Vec<_> = (0..threads)
                .map(|index| {
                    let ready = &ready;
                    let path = &paths[index as usize];
                    scope.spawn(move || -> Result<Vec<Duration>> {
                        let file = OpenOptions::new()
                            .read(true)
                            .write(true)
                            .open(path)
                            .context("a worker cannot open its file")?;
                        let write = fsutil::filler(block);
                        let mut read = vec![0u8; block];
                        let mut rng = fsutil::Rng::new(0xA5A5 + index);
                        let mut samples = Vec::with_capacity(ops_per_thread as usize);
                        ready.wait();
                        for _ in 0..ops_per_thread {
                            let at = Instant::now();
                            file.write_all_at(&write, rng.below(blocks) * block as u64)
                                .context("cannot write")?;
                            file.read_exact_at(&mut read, rng.below(blocks) * block as u64)
                                .context("cannot read")?;
                            samples.push(at.elapsed());
                        }
                        Ok(samples)
                    })
                })
                .collect();

            ready.wait();
            let started = Instant::now();
            let mut samples = Vec::new();
            for worker in workers {
                samples.extend(
                    worker
                        .join()
                        .map_err(|_| anyhow::anyhow!("a worker panicked"))??,
                );
            }
            Ok::<_, anyhow::Error>((samples, started.elapsed()))
        })?;

        let (samples, elapsed) = latencies;
        let ops = threads * ops_per_thread;
        let bytes = ops * 2 * block as u64;
        Ok(Rep::new(elapsed, ops, bytes)
            .with_latencies(samples)
            .with_extra(json!({ "threads": threads })))
    })
}
