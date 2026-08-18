//! Parallel direct writes: what announcing the capability buys, and the bounds
//! it does not cross.
//!
//! A direct-io mount's open reply carries `FOPEN_PARALLEL_DIRECT_WRITES`. That
//! single bit decides which lock the guest kernel takes around a direct write:
//! without it, every write to one file takes the inode's lock **exclusively**,
//! so an application using asynchronous I/O has its writes serialized inside
//! its own kernel before a wire that could have overlapped them ever sees them;
//! with it, an in-place write takes the lock shared and several are outstanding
//! at once.
//!
//! The suite is deliberately two-sided, because the announcement is easy to
//! oversell:
//!
//! * the **gain** is measured, not asserted from the flag's presence — the same
//!   file, the same bytes, the same mount, written by one thread and then by
//!   eight, and the eight have to actually finish sooner;
//! * the **bounds** are pinned by the same census that proves the gain. The
//!   kernel keeps its exclusive lock for `O_APPEND` and for any write that
//!   extends the file, because neither knows where its bytes land until the
//!   size is settled. Those arms must read exactly one write in flight — if
//!   they ever read more, the announcement is doing something nobody decided;
//! * and the **plain sequential writer** — the overwhelmingly common case — has
//!   to be untouched, byte for byte and request for request.
//!
//! Every count here is the guest kernel's own (see [`support::census`]), not
//! voidport's bookkeeping: a client-side counter could happily agree with
//! voidport's intentions while the kernel serialized everything above it, which
//! is the precise failure this increment is about.

mod support;

use std::fs;
use std::io::Write as _;
use std::os::unix::fs::FileExt as _;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use support::census::Census;
use support::{Fixture, preflight};
use voidport::mount::MountOptions;

/// Long enough that no attribute or entry validity expires mid-test, so nothing
/// here is explained by revalidation traffic joining the census.
const NEVER: Duration = Duration::from_secs(3600);

/// One write. Small on purpose: this is the shape of an application updating
/// records in place, where the cost is the round trip and not the bytes, and
/// therefore the shape overlapping writes actually helps.
const BLOCK: usize = 4096;

/// How many writes an arm performs. The same total work in every arm.
const WRITES: usize = 512;

/// How many threads the parallel arm runs.
const WRITERS: usize = 8;

/// How many times each arm is measured; the median is what is compared, so a
/// single scheduling hiccup does not decide the result.
const ROUNDS: usize = 3;

/// The speedup the parallel arm must reach over the serial baseline.
///
/// Far below what the measurement actually shows (recorded in the increment's
/// report) — the gate is here to catch the capability going missing, not to
/// pin a machine's performance, and a gate set at the observed figure would
/// fail on a busier machine while proving nothing more.
const MIN_SPEEDUP: f64 = 1.5;

/// The bytes a write carries; the value is irrelevant, the placement is not.
const FILL: u8 = b'w';

/// A direct mount: the only mode that announces the capability.
///
/// The chunk unit is the run's ([`support::write_stream_bytes`]): zero for
/// every ordinary run, and whatever the run named for the pass that puts this
/// suite through the write-streaming engine — where the census assertions
/// below say something extra, since streaming is below the syscall and must
/// leave what the guest kernel has in flight exactly as it was.
fn direct() -> MountOptions {
    MountOptions {
        attr_timeout: NEVER,
        entry_timeout: NEVER,
        direct_io: true,
        write_stream: support::write_stream_bytes(),
        ..MountOptions::default()
    }
}

/// A host file of `size` bytes, already sized — the precondition of an in-place
/// overwrite, and never mapped by anyone.
fn preallocated(path: &Path, size: usize) {
    fs::write(path, vec![0u8; size]).expect("the host file is created");
}

/// The next block index an arm should write, or `None` when the arm is done.
fn claim(next: &AtomicU64) -> Option<u64> {
    let index = next.fetch_add(1, Ordering::Relaxed);
    (index < WRITES as u64).then_some(index)
}

/// Overwrites the file in place with `writers` threads, and reports how long it
/// took.
///
/// `pwrite`, not `write`: it names its own offset, so the threads share one
/// descriptor without sharing a file position, and every write is in place in a
/// file that is already long enough to hold it. That is exactly the case the
/// kernel takes the shared lock for.
fn overwrite(file: &fs::File, writers: usize) -> Duration {
    let next = AtomicU64::new(0);
    let started = Instant::now();
    thread::scope(|scope| {
        for _ in 0..writers {
            scope.spawn(|| {
                let payload = vec![FILL; BLOCK];
                while let Some(index) = claim(&next) {
                    file.write_all_at(&payload, index * BLOCK as u64)
                        .expect("the write succeeds");
                }
            });
        }
    });
    started.elapsed()
}

/// The median of a set of durations.
fn median(mut samples: Vec<Duration>) -> Duration {
    samples.sort_unstable();
    samples[samples.len() / 2]
}

// ---------------------------------------------------------------------------
// Criterion 1 — the announcement, the overlap, and the speedup
// ---------------------------------------------------------------------------

/// Criterion 1: writes to a preallocated, never-mapped file overlap — the
/// census sees several in flight — and eight writers finish measurably sooner
/// than one doing the same work.
///
/// Both halves are needed and neither is enough. The census alone would prove
/// the kernel let the writes through without proving voidport overlapped them
/// on the wire; the timing alone could in principle come from anywhere. The
/// serial arm is the control for both: it runs on the same mount, the same
/// descriptor and the same bytes, and it must read exactly one in flight, which
/// is what makes the parallel arm's count mean something.
#[test]
fn parallel_writers_overlap_in_place_and_beat_the_serial_baseline() {
    if !preflight() {
        return;
    }
    let fixture = Fixture::start("parallel-writes");
    preallocated(&fixture.host("tree/inplace.bin"), WRITES * BLOCK);
    let guest = fixture.mount_with("parallel", &fixture.tcp_url("plain", "/tree"), &direct());
    let census = Census::of(guest.root());

    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(guest.path("inplace.bin"))
        .expect("the file opens");
    // Warm the path — the first write of a handle pays for a lookup and an open
    // that the measurement is not about.
    overwrite(&file, 1);

    let (mut serial, mut parallel) = (Vec::new(), Vec::new());
    let (mut serial_peak, mut parallel_peak) = (0, 0);
    for _ in 0..ROUNDS {
        let (elapsed, peak) = census.peak_during(|| overwrite(&file, 1));
        serial.push(elapsed);
        serial_peak = serial_peak.max(peak);

        let (elapsed, peak) = census.peak_during(|| overwrite(&file, WRITERS));
        parallel.push(elapsed);
        parallel_peak = parallel_peak.max(peak);
    }
    let (serial, parallel) = (median(serial), median(parallel));
    let speedup = serial.as_secs_f64() / parallel.as_secs_f64();
    println!(
        "parallel-direct-writes: {WRITES} writes of {BLOCK} B on one file — \
         serial {serial:?} (peak {serial_peak} in flight), \
         {WRITERS} writers {parallel:?} (peak {parallel_peak} in flight), \
         speedup {speedup:.2}x"
    );

    assert_eq!(
        serial_peak, 1,
        "the serial baseline had {serial_peak} writes in flight, so it is not a baseline"
    );
    assert!(
        parallel_peak > 1,
        "{WRITERS} writers never had more than {parallel_peak} write in flight: the guest \
         kernel serialized them, which is what announcing the capability is supposed to stop"
    );
    assert!(
        speedup >= MIN_SPEEDUP,
        "{WRITERS} writers took {parallel:?} against a serial {serial:?} — a speedup of \
         {speedup:.2}x, under the {MIN_SPEEDUP}x this increment claims"
    );

    // The bytes are the other half of correctness: overlapping writes must
    // still each land where they were addressed.
    let written = fs::read(fixture.host("tree/inplace.bin")).expect("the host file reads");
    assert_eq!(written, vec![FILL; WRITES * BLOCK], "a write landed wrong");
}

// ---------------------------------------------------------------------------
// Criterion 2 — the honest bounds, and the writer that must not have changed
// ---------------------------------------------------------------------------

/// Criterion 2: `O_APPEND` writes stay serialized by the guest kernel, whatever
/// the open reply announced.
///
/// The kernel keeps its exclusive lock here unconditionally, and it is right
/// to: an append's offset is the file's eventual end, which is not knowable
/// while other appends are outstanding. The census must read exactly one.
#[test]
fn an_appending_writer_stays_kernel_serialized() {
    if !preflight() {
        return;
    }
    let fixture = Fixture::start("parallel-writes-append");
    let host = fixture.host("tree/appended.bin");
    fs::write(&host, b"").expect("the host file is created");
    let guest = fixture.mount_with("append", &fixture.tcp_url("plain", "/tree"), &direct());
    let census = Census::of(guest.root());

    let file = fs::OpenOptions::new()
        .append(true)
        .open(guest.path("appended.bin"))
        .expect("the file opens for appending");

    let next = AtomicU64::new(0);
    let ((), peak) = census.peak_during(|| {
        thread::scope(|scope| {
            for _ in 0..WRITERS {
                scope.spawn(|| {
                    let payload = vec![FILL; BLOCK];
                    while claim(&next).is_some() {
                        (&file).write_all(&payload).expect("the append succeeds");
                    }
                });
            }
        });
    });
    println!("parallel-direct-writes: {WRITERS} appending writers — peak {peak} in flight");

    assert_eq!(
        peak, 1,
        "an appending write overlapped another ({peak} in flight): append is kernel-serialized \
         and this increment never claimed otherwise"
    );
    // Serialized is not the same as lossy: every append is still in the file.
    let size = fs::metadata(&host).expect("the host file stats").len();
    assert_eq!(
        size,
        (WRITES * BLOCK) as u64,
        "the appends did not all land"
    );
}

/// Criterion 2: size-extending writes stay serialized too.
///
/// Every write here is past the end of the file when the kernel weighs it —
/// the offsets are handed out in ascending order and the file only grows — and
/// a write beyond the end is the other case the kernel refuses to parallelize,
/// because the size it would settle is the size the next write depends on.
#[test]
fn a_size_extending_writer_stays_kernel_serialized() {
    if !preflight() {
        return;
    }
    let fixture = Fixture::start("parallel-writes-extend");
    let host = fixture.host("tree/extended.bin");
    fs::write(&host, b"").expect("the host file is created");
    let guest = fixture.mount_with("extend", &fixture.tcp_url("plain", "/tree"), &direct());
    let census = Census::of(guest.root());

    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(guest.path("extended.bin"))
        .expect("the file opens");

    let next = AtomicU64::new(0);
    let ((), peak) = census.peak_during(|| {
        thread::scope(|scope| {
            for _ in 0..WRITERS {
                scope.spawn(|| {
                    let payload = vec![FILL; BLOCK];
                    while let Some(index) = claim(&next) {
                        file.write_all_at(&payload, index * BLOCK as u64)
                            .expect("the write succeeds");
                    }
                });
            }
        });
    });
    println!("parallel-direct-writes: {WRITERS} extending writers — peak {peak} in flight");

    assert_eq!(
        peak, 1,
        "a size-extending write overlapped another ({peak} in flight): writes beyond the end \
         of a file are kernel-serialized and this increment never claimed otherwise"
    );
    let written = fs::read(&host).expect("the host file reads");
    assert_eq!(
        written,
        vec![FILL; WRITES * BLOCK],
        "the extending writes did not all land"
    );
}

/// Criterion 2, the regression arm: announcing the capability changed nothing
/// for the plain sequential writer.
///
/// This is the case almost every program is — one thread, one descriptor,
/// start to finish — and it has one write in flight before the announcement and
/// one after, because a single writer has nothing to overlap with. What must be
/// shown is that the announcement did not perturb it: the same one-at-a-time
/// census, and every byte on the host in the order it was written.
#[test]
fn a_plain_sequential_writer_is_unchanged() {
    if !preflight() {
        return;
    }
    let fixture = Fixture::start("parallel-writes-sequential");
    let guest = fixture.mount_with("sequential", &fixture.tcp_url("plain", "/tree"), &direct());
    let census = Census::of(guest.root());

    // Bytes whose value depends on where they are, so data written out of order
    // fails an assertion instead of looking plausible.
    let expected: Vec<u8> = (0..WRITES * BLOCK).map(|at| (at % 251) as u8).collect();
    let mut file = fs::File::create(guest.path("sequential.bin")).expect("the file is created");

    let ((), peak) = census.peak_during(|| {
        for chunk in expected.chunks(BLOCK) {
            file.write_all(chunk).expect("the write succeeds");
        }
        file.flush().expect("the writer flushes");
    });
    drop(file);
    println!("parallel-direct-writes: one sequential writer — peak {peak} in flight");

    assert_eq!(
        peak, 1,
        "a lone sequential writer had {peak} writes in flight: the announcement changed the \
         one case it was never supposed to touch"
    );
    let written = fs::read(fixture.host("tree/sequential.bin")).expect("the host file reads");
    assert_eq!(written, expected, "the sequential writer's bytes are wrong");
}
