//! Readahead: what the prefetch engine promises, proven against a real mount.
//!
//! Readahead-increment criteria **1 (coverage), 2, 3, 4, 5, 6 and 8**. The two
//! that do not live here are measurements and a non-change: criterion 1's
//! throughput doubling is the `voidport-bench` seq-read scenario and is recorded
//! in `docs/PERFORMANCE.md`, and criterion 7 is that the wire did not move —
//! the golden vectors and the protocol suites prove that by being untouched and
//! green, because the two reply classes are scheduling inside one server and no
//! frame changed.
//!
//! Everything here runs against a **direct** mount, because that is the only
//! mode the engine runs in: a page-cached mount is served by the guest kernel's
//! own readahead and the engine stays dormant behind it. The pools are small on
//! purpose — a few mebibytes, not the shipped 256 — so that a test can
//! actually reach a ceiling the default would never come near.
//!
//! The engine is asked what it is holding through
//! [`Readahead::stats`](voidport::client::Readahead::stats), which is test
//! support and adds no control surface: nothing a test can call changes what
//! the engine does.

mod support;

use std::fs::{self, File};
use std::io::{Read as _, Seek as _, SeekFrom};
use std::os::unix::fs::FileExt as _;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use support::daemon::{Ground, PATIENCE, eventually};
use support::{Fixture, preflight};
use voidport::client::{CHUNK_BYTES, ReadaheadStats};
use voidport::mount::MountOptions;

/// A mebibyte.
const MIB: usize = 1024 * 1024;

/// The pool a test runs with: small enough to reach, large enough to pipeline.
const POOL: usize = 8 * MIB;

/// How long a test's metadata may be cached — and therefore how old a
/// prefetched block may be and still be served.
const TTL: Duration = Duration::from_secs(5);

/// A short TTL, for the tests whose subject is the freshness bound itself.
const SHORT_TTL: Duration = Duration::from_millis(200);

/// Mount options for a direct mount with a pool of `readahead` bytes.
fn direct(readahead: usize, attr_timeout: Duration) -> MountOptions {
    MountOptions {
        attr_timeout,
        entry_timeout: attr_timeout,
        direct_io: true,
        readahead,
        ..MountOptions::default()
    }
}

/// Bytes whose value depends on where they are, so that data served from the
/// wrong offset is data that fails an assertion, not data that looks
/// plausible.
fn pattern(size: usize) -> Vec<u8> {
    (0..size).map(|offset| (offset % 251) as u8).collect()
}

/// The same, from a given offset: what a correct read at `offset` returns.
fn pattern_at(offset: usize, size: usize) -> Vec<u8> {
    (offset..offset + size)
        .map(|byte| (byte % 251) as u8)
        .collect()
}

/// Writes a host file of `size` bytes of [`pattern`].
fn host_file(path: &Path, size: usize) {
    fs::write(path, pattern(size)).expect("the host file is written");
}

/// Reads a whole file through the mount, in `chunk`-sized reads, checking every
/// byte against the pattern as it goes.
fn read_checked(path: &Path, chunk: usize) -> usize {
    let mut file = File::open(path).expect("the file opens");
    let mut buffer = vec![0u8; chunk];
    let mut position = 0usize;
    loop {
        let count = file.read(&mut buffer).expect("the read succeeds");
        if count == 0 {
            return position;
        }
        assert_eq!(
            buffer[..count],
            pattern_at(position, count)[..],
            "bytes at offset {position} came back wrong"
        );
        position += count;
    }
}

/// Samples the engine while `work` runs, and reports what it saw.
///
/// The sampler is what makes an assertion about a *ceiling* mean anything: the
/// numbers a test could read afterwards are the numbers of an idle mount.
fn sampled<T>(
    readahead: &Arc<voidport::client::Readahead>,
    work: impl FnOnce() -> T,
) -> (T, Vec<ReadaheadStats>) {
    let stop = Arc::new(AtomicBool::new(false));
    let sampler = {
        let readahead = Arc::clone(readahead);
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            let mut samples = Vec::new();
            while !stop.load(Ordering::Relaxed) {
                samples.push(readahead.stats());
                std::thread::sleep(Duration::from_micros(200));
            }
            samples.push(readahead.stats());
            samples
        })
    };
    let value = work();
    stop.store(true, Ordering::Relaxed);
    let samples = sampler.join().expect("the sampler finishes");
    (value, samples)
}

/// The median of a set of durations.
fn median(mut samples: Vec<Duration>) -> Duration {
    samples.sort_unstable();
    samples[samples.len() / 2]
}

// ---------------------------------------------------------------------------
// Criteria 1 (coverage) and 2 — the pool, its ceiling, and its reservations
// ---------------------------------------------------------------------------

/// Criterion 2: reading a file set several times the size of the pool never
/// takes the pool over its cap, reservations included — and the mount holds
/// nothing once the reading is over.
///
/// The ceiling is checked *while* the reading happens, and it is checked
/// against `ready + reserved`: a cap that only bound delivered bytes would be
/// crossed by the replies already on the wire, which is exactly why the engine
/// reserves a chunk before it asks for it.
#[test]
fn the_pool_never_crosses_its_ceiling_and_an_idle_mount_holds_nothing() {
    if !preflight() {
        return;
    }
    let fixture = Fixture::start("readahead-pool");
    for index in 0..4 {
        host_file(&fixture.host(&format!("tree/big-{index}.bin")), 8 * MIB);
    }
    let guest = fixture.mount_with(
        "pool",
        &fixture.tcp_url("plain", "/tree"),
        &direct(4 * MIB, TTL),
    );
    let readahead = guest.readahead();
    assert_eq!(
        readahead.stats().pool_bytes(),
        0,
        "an idle mount holds nothing at all"
    );

    let (_, samples) = sampled(&readahead, || {
        for index in 0..4 {
            let read = read_checked(&guest.path(&format!("big-{index}.bin")), 512 * 1024);
            assert_eq!(read, 8 * MIB);
        }
    });

    let peak = samples
        .iter()
        .map(ReadaheadStats::pool_bytes)
        .max()
        .expect("the sampler took samples");
    assert!(
        peak <= 4 * MIB,
        "the pool reached {peak} bytes against a 4 MiB ceiling"
    );
    assert!(
        peak > 0,
        "the pool was never used, so this proved nothing about its ceiling"
    );
    let busiest = samples
        .iter()
        .map(|sample| sample.inflight)
        .max()
        .expect("the sampler took samples");
    assert!(
        busiest <= 16,
        "{busiest} prefetch reads were in flight against a per-mount cap of 16"
    );

    let after = readahead.stats();
    assert!(
        after.issued > 0 && after.hit_bytes > 0,
        "nothing was prefetched, so nothing here was tested: {after:?}"
    );
    // Every handle is closed by now, so the pool owes the process its memory
    // back.
    assert!(
        eventually(PATIENCE, || readahead.stats().ready_bytes == 0),
        "a mount whose readers have all gone is still holding {:?}",
        readahead.stats()
    );
}

/// Criterion 1, the coverage half: reading a whole file reaches its end within
/// the caps, and the engine stops there instead of asking for more.
///
/// The count is the assertion. A window that ran away would issue far more
/// reads than the file has chunks; a window that never opened would issue
/// almost none.
#[test]
fn a_whole_file_read_reaches_the_end_within_the_caps() {
    if !preflight() {
        return;
    }
    let fixture = Fixture::start("readahead-eof");
    let size = 6 * MIB;
    host_file(&fixture.host("tree/whole.bin"), size);
    let guest = fixture.mount_with(
        "eof",
        &fixture.tcp_url("plain", "/tree"),
        &direct(POOL, TTL),
    );
    let readahead = guest.readahead();

    assert_eq!(read_checked(&guest.path("whole.bin"), 512 * 1024), size);
    let stats = readahead.stats();
    let chunks = size / CHUNK_BYTES;
    assert!(
        stats.issued > 0,
        "the sequential detector never opened a window"
    );
    assert!(
        stats.issued as usize <= chunks,
        "{} chunks were prefetched for a file of {chunks}: the window ran past the end",
        stats.issued
    );
    assert!(
        stats.hit_bytes > (size / 2) as u64,
        "only {} of {size} bytes came from the pool, so the window never caught up",
        stats.hit_bytes
    );
}

// ---------------------------------------------------------------------------
// Criterion 3 — random access and seeks
// ---------------------------------------------------------------------------

/// Criterion 3: a seek mid-file resets the window and never serves the position
/// it left behind.
///
/// Every read is checked against the pattern, so a block served at the wrong
/// offset — the failure a window that did not reset would produce — is a failed
/// assertion, not a slow test.
#[test]
fn a_seek_resets_the_window_and_serves_no_stale_position() {
    if !preflight() {
        return;
    }
    let fixture = Fixture::start("readahead-seek");
    let size = 4 * MIB;
    host_file(&fixture.host("tree/seek.bin"), size);
    let guest = fixture.mount_with(
        "seek",
        &fixture.tcp_url("plain", "/tree"),
        &direct(POOL, TTL),
    );

    let mut file = File::open(guest.path("seek.bin")).expect("the file opens");
    let mut buffer = vec![0u8; 256 * 1024];
    // Read sequentially far enough to open the window and let it double.
    for index in 0..4 {
        file.read_exact(&mut buffer).expect("the read succeeds");
        assert_eq!(
            buffer[..],
            pattern_at(index * buffer.len(), buffer.len())[..]
        );
    }
    // Then jump about. Each landing is checked, forwards and backwards, and
    // twice at the same place — a byte already served must be fetched again
    // and not answered from a block that no longer holds it.
    for offset in [3 * MIB, 1024, 2 * MIB + 7, 1024, size - 8192] {
        file.seek(SeekFrom::Start(offset as u64))
            .expect("the seek succeeds");
        let want = buffer.len().min(size - offset);
        file.read_exact(&mut buffer[..want])
            .expect("the read succeeds");
        assert_eq!(
            buffer[..want],
            pattern_at(offset, want)[..],
            "a read after seeking to {offset} came back wrong"
        );
    }
    // And a sequential pass afterwards is still correct end to end.
    assert_eq!(read_checked(&guest.path("seek.bin"), 128 * 1024), size);
}

/// Criterion 3, the other half: a sequential run that begins at an **unaligned**
/// offset is served the bytes that belong there.
///
/// This is the ELF loader's shape — 256 bytes at 0, the program headers at 64,
/// the interpreter name straight after them — and it is what a window opening
/// at offset 848 does to a pool addressed in 128 KiB chunks. Fetching from
/// wherever the reader happened to be would file a block under a chunk index
/// whose bytes it does not hold, and every later read of that chunk would come
/// back shifted. The `directio` suite's exec-from-mount case is the same bug in
/// its user-visible form; this is it in bytes.
#[test]
fn a_window_that_opens_at_an_unaligned_offset_still_serves_the_right_bytes() {
    if !preflight() {
        return;
    }
    let fixture = Fixture::start("readahead-unaligned");
    let size = 4 * MIB;
    host_file(&fixture.host("tree/odd.bin"), size);
    let guest = fixture.mount_with(
        "unaligned",
        &fixture.tcp_url("plain", "/tree"),
        &direct(POOL, TTL),
    );

    let file = File::open(guest.path("odd.bin")).expect("the file opens");
    let read_at = |offset: usize, length: usize| {
        let mut buffer = vec![0u8; length];
        file.read_exact_at(&mut buffer, offset as u64)
            .expect("the read succeeds");
        assert_eq!(
            buffer,
            pattern_at(offset, length),
            "a read of {length} bytes at {offset} came back wrong"
        );
    };
    // The loader's sequence, then a run of reads that keeps going from an
    // offset no chunk boundary is anywhere near.
    read_at(0, 256);
    read_at(64, 784);
    read_at(848, 83);
    let mut position = 931;
    while position + 64 * 1024 < size {
        read_at(position, 64 * 1024);
        position += 64 * 1024;
    }
    assert!(
        guest.readahead().stats().hit_bytes > 0,
        "nothing came out of the pool, so nothing about the pool was tested"
    );
}

// ---------------------------------------------------------------------------
// Criterion 4 — early close
// ---------------------------------------------------------------------------

/// Criterion 4: closing a handle stops the engine dead. Nothing more is issued
/// for it, its blocks are freed, and the replies of the reads already on the
/// wire are discarded, not kept.
#[test]
fn closing_a_handle_stops_the_engine_and_frees_its_blocks() {
    if !preflight() {
        return;
    }
    let fixture = Fixture::start("readahead-close");
    host_file(&fixture.host("tree/early.bin"), 16 * MIB);
    let guest = fixture.mount_with(
        "close",
        &fixture.tcp_url("plain", "/tree"),
        &direct(POOL, TTL),
    );
    let readahead = guest.readahead();

    let mut file = File::open(guest.path("early.bin")).expect("the file opens");
    let mut buffer = vec![0u8; 512 * 1024];
    for _ in 0..3 {
        file.read_exact(&mut buffer).expect("the read succeeds");
    }
    let reading = readahead.stats();
    assert!(reading.issued > 0, "nothing was in flight to cancel");

    drop(file);
    // A FUSE release is asynchronous: the kernel does not wait for the reply,
    // so the test waits for the window to actually be gone.
    assert!(
        eventually(PATIENCE, || readahead.stats().handles == 0),
        "the handle's window outlived the descriptor: {:?}",
        readahead.stats()
    );
    let closed = readahead.stats();
    assert_eq!(closed.ready_bytes, 0, "the blocks are freed on close");
    assert_eq!(closed.blocks, 0);

    // Nothing more is issued once the handle is gone, and whatever was on the
    // wire is discarded on arrival, not inserted for nobody.
    std::thread::sleep(Duration::from_millis(300));
    let settled = readahead.stats();
    assert_eq!(
        settled.issued, closed.issued,
        "a prefetch was issued after the handle closed"
    );
    assert_eq!(settled.ready_bytes, 0);
    assert_eq!(
        settled.inflight, 0,
        "the in-flight reads never released their slots"
    );
    assert_eq!(
        settled.reserved_bytes, 0,
        "a cancelled read's reservation was never given back"
    );
    // Whether a reply was still crossing the wire when the handle closed is a
    // race against a unix socket on the same machine, so this does not assert
    // that one was — it asserts the outcome either way: nothing was inserted
    // for a handle that is gone. That a *discarded* reply takes that path is
    // proven deterministically by the engine's own unit tests.
    assert_eq!(
        settled.blocks, 0,
        "a reply that arrived after the close was kept: {settled:?}"
    );
}

// ---------------------------------------------------------------------------
// Criterion 5 — coherence
// ---------------------------------------------------------------------------

/// Criterion 5: a host-side change lands within the attr-TTL bound, because a
/// block older than the TTL is dropped instead of served.
///
/// The discrimination is the direct-io suite's: the host rewrites the file
/// under a held descriptor, and the guest is asked for those bytes again. What
/// is being proven here is the *bound* — with a 200 ms TTL, a change made after
/// the prefetch is visible once the TTL has passed, without anything else
/// invalidating anything.
#[test]
fn a_host_side_change_lands_within_the_attr_ttl() {
    if !preflight() {
        return;
    }
    let fixture = Fixture::start("readahead-ttl");
    let size = 4 * MIB;
    let host = fixture.host("tree/ttl.bin");
    host_file(&host, size);
    let guest = fixture.mount_with(
        "ttl",
        &fixture.tcp_url("plain", "/tree"),
        &direct(POOL, SHORT_TTL),
    );

    let file = File::open(guest.path("ttl.bin")).expect("the file opens");
    // Read the first two chunks sequentially: that opens the window, so the
    // bytes further on are prefetched and sitting in the pool.
    let mut buffer = vec![0u8; CHUNK_BYTES];
    for index in 0..2u64 {
        file.read_exact_at(&mut buffer, index * CHUNK_BYTES as u64)
            .expect("the read succeeds");
    }
    assert!(
        eventually(PATIENCE, || guest.readahead().stats().ready_bytes > 0),
        "nothing was prefetched, so there is no stale copy to be right about"
    );

    // The host rewrites a page the pool is holding.
    let changed = 3 * CHUNK_BYTES as u64;
    let replacement = vec![b'Z'; 4096];
    fs::OpenOptions::new()
        .write(true)
        .open(&host)
        .expect("the host file is writable")
        .write_all_at(&replacement, changed)
        .expect("the host file is rewritten");

    // Within the TTL bound — and no further — the guest sees it. The bound is
    // the mechanism: blocks fetched before the change are older than the TTL by
    // then, and an expired block is dropped, not served.
    let deadline = SHORT_TTL + Duration::from_secs(2);
    let mut page = vec![0u8; 4096];
    let started = Instant::now();
    let mut seen = false;
    while started.elapsed() < deadline {
        file.read_exact_at(&mut page, changed).expect("the read");
        if page == replacement {
            seen = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        seen,
        "the host's change was not visible within the attr-TTL bound"
    );
}

/// Criterion 5: a local write and a shrinking truncate each drop the file's
/// blocks at once — no TTL waiting, no stale byte.
#[test]
fn a_local_write_and_a_truncate_drop_the_blocks_at_once() {
    if !preflight() {
        return;
    }
    let fixture = Fixture::start("readahead-invalidate");
    let size = 4 * MIB;
    host_file(&fixture.host("tree/local.bin"), size);
    host_file(&fixture.host("tree/cut.bin"), size);
    // An hour-long TTL, so that nothing here can be explained by expiry: what
    // drops the blocks is the write and the truncate themselves.
    let guest = fixture.mount_with(
        "invalidate",
        &fixture.tcp_url("plain", "/tree"),
        &direct(POOL, Duration::from_secs(3600)),
    );
    let readahead = guest.readahead();

    let mut file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(guest.path("local.bin"))
        .expect("the file opens");
    let mut buffer = vec![0u8; CHUNK_BYTES];
    for _ in 0..2 {
        file.read_exact(&mut buffer).expect("the read succeeds");
    }
    assert!(
        eventually(PATIENCE, || readahead.stats().ready_bytes > 0),
        "nothing was prefetched, so there is nothing for the write to drop"
    );

    // A write through this very handle, at an offset the pool is holding.
    let written = 3 * CHUNK_BYTES as u64;
    let replacement = vec![b'W'; 8192];
    file.write_all_at(&replacement, written)
        .expect("the write succeeds");
    let mut back = vec![0u8; 8192];
    file.read_exact_at(&mut back, written)
        .expect("the read succeeds");
    assert_eq!(back, replacement, "a stale block outlived a local write");

    // A shrinking truncate through another handle: the file ends where it was
    // cut, and nothing beyond it is served from the pool.
    let mut cut = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(guest.path("cut.bin"))
        .expect("the file opens");
    for _ in 0..2 {
        cut.read_exact(&mut buffer).expect("the read succeeds");
    }
    assert!(
        eventually(PATIENCE, || readahead.stats().ready_bytes > 0),
        "nothing was prefetched, so there is nothing for the truncate to drop"
    );
    cut.set_len(CHUNK_BYTES as u64).expect("the truncate");
    let mut beyond = vec![0u8; 4096];
    let read = cut
        .read_at(&mut beyond, 2 * CHUNK_BYTES as u64)
        .expect("the read succeeds");
    assert_eq!(read, 0, "the pool answered past a truncated file's end");
}

/// Criterion 5: `--readahead 0` restores per-read freshness.
///
/// Nothing is prefetched, so nothing is held, so every read is the wire read it
/// always was — proven the direct-io suite's way, with an hour-long metadata
/// timeout so that no revalidation can be what makes the change visible.
#[test]
fn readahead_zero_restores_wire_immediate_reads() {
    if !preflight() {
        return;
    }
    let fixture = Fixture::start("readahead-zero");
    let size = 2 * MIB;
    let host = fixture.host("tree/zero.bin");
    host_file(&host, size);
    let guest = fixture.mount_with(
        "zero",
        &fixture.tcp_url("plain", "/tree"),
        &direct(0, Duration::from_secs(3600)),
    );
    let readahead = guest.readahead();
    assert!(!readahead.is_active(), "--readahead 0 disables the engine");

    let file = File::open(guest.path("zero.bin")).expect("the file opens");
    let mut buffer = vec![0u8; CHUNK_BYTES];
    for index in 0..4u64 {
        file.read_exact_at(&mut buffer, index * CHUNK_BYTES as u64)
            .expect("the read succeeds");
    }
    assert_eq!(
        readahead.stats(),
        ReadaheadStats::default(),
        "a disabled engine holds nothing and does nothing"
    );

    let changed = 6 * CHUNK_BYTES as u64;
    let replacement = vec![b'Q'; 4096];
    fs::OpenOptions::new()
        .write(true)
        .open(&host)
        .expect("the host file is writable")
        .write_all_at(&replacement, changed)
        .expect("the host file is rewritten");

    let mut page = vec![0u8; 4096];
    file.read_exact_at(&mut page, changed)
        .expect("the read succeeds");
    assert_eq!(
        page, replacement,
        "with the engine off, a read is answered from the server and nowhere else"
    );
}

// ---------------------------------------------------------------------------
// Criterion 6 — interactive latency under saturated prefetch
// ---------------------------------------------------------------------------

/// Criterion 6: a metadata operation issued while prefetch saturates the same
/// connection completes within its unloaded baseline plus 2 ms, at the median.
///
/// This is the criterion the server's two reply classes exist for: with one
/// FIFO for every reply, the `getattr` below would queue behind whatever
/// 128 KiB read replies the engine had already asked for.
///
/// Each probe stats a file it has never stat'ed before, so the answer comes
/// from the server, not from the kernel's attribute cache.
#[test]
fn a_metadata_operation_stays_responsive_under_saturated_prefetch() {
    if !preflight() {
        return;
    }
    let fixture = Fixture::start("readahead-latency");
    let probes = 200usize;
    for index in 0..probes * 2 {
        fs::write(fixture.host(&format!("tree/p{index}")), b"x").expect("a probe file");
    }
    host_file(&fixture.host("tree/load.bin"), 96 * MIB);
    let guest = fixture.mount_with(
        "latency",
        &fixture.tcp_url("plain", "/tree"),
        &direct(64 * MIB, TTL),
    );

    let stat = |index: usize| {
        let path = guest.path(&format!("p{index}"));
        let started = Instant::now();
        fs::metadata(&path).expect("the probe file stats");
        started.elapsed()
    };

    // The baseline: the same operation on a quiet mount.
    let baseline = median((0..probes).map(stat).collect());

    // And under load: one reader streaming a file far larger than the pool, so
    // the engine is prefetching for the whole measurement.
    let stop = Arc::new(AtomicBool::new(false));
    let reader = {
        let path = guest.path("load.bin");
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                let mut file = File::open(&path).expect("the file opens");
                let mut buffer = vec![0u8; MIB];
                while !stop.load(Ordering::Relaxed) {
                    match file.read(&mut buffer) {
                        Ok(0) => break,
                        Ok(_) => {}
                        Err(error) => panic!("the load reader failed: {error}"),
                    }
                }
            }
        })
    };
    // Let the window open and the pipeline fill before anything is measured.
    std::thread::sleep(Duration::from_millis(300));
    let loaded = median((probes..probes * 2).map(stat).collect());
    stop.store(true, Ordering::Relaxed);
    reader.join().expect("the load reader finishes");

    let allowance = baseline + Duration::from_millis(2);
    assert!(
        loaded <= allowance,
        "a metadata operation took {loaded:?} under saturated prefetch, \
         against a baseline of {baseline:?} plus the 2 ms the contract allows"
    );
}

// ---------------------------------------------------------------------------
// Criterion 8 — reconnect
// ---------------------------------------------------------------------------

/// Criterion 8: a server killed and restarted under active prefetch drops the
/// pool, resets the windows, and never serves a pre-reconnect block afterwards.
///
/// The reader's own surface is the resilience contract's, unchanged: the
/// descriptor it held across the gap fails with a stale errno, and a reopen
/// works. What this adds is that the bytes are right — a pool that survived the
/// gap would answer a read on the *new* session out of the *old* one's memory,
/// and every byte here is checked against its offset.
#[test]
fn a_reconnect_drops_the_pool_and_the_reader_behaves_as_ruled() {
    if !preflight() {
        return;
    }
    let mut ground = Ground::start("readahead-reconnect");
    let size = 8 * MIB;
    host_file(&ground.tree.join("stream.bin"), size);
    let guest = ground.mount_with("readahead", &direct(POOL, TTL));
    let readahead = guest.readahead();

    let mut held = File::open(guest.path("tree/stream.bin")).expect("the file opens");
    let mut buffer = vec![0u8; 512 * 1024];
    for index in 0..2 {
        held.read_exact(&mut buffer).expect("the read succeeds");
        assert_eq!(
            buffer[..],
            pattern_at(index * buffer.len(), buffer.len())[..]
        );
    }
    assert!(
        eventually(PATIENCE, || readahead.stats().ready_bytes > 0),
        "nothing was prefetched, so the gap has nothing to drop"
    );

    ground.server.restart();

    // The descriptor from before the gap names a handle the new session never
    // issued: it fails, exactly as the resilience contract rules for
    // handle-bound I/O — never with bytes from the pool the dead session filled.
    let stale = held.read(&mut buffer);
    assert!(
        stale.is_err(),
        "a read on a pre-restart descriptor was answered ({stale:?}); \
         a pool that outlived its session is the only way that can happen"
    );
    // Not one block survived the gap. The window bookkeeping for a handle that
    // is read again *after* the reconnect is a fresh window on a fresh session —
    // what the contract forbids is a block, and there is none.
    assert!(
        eventually(PATIENCE, || {
            let stats = readahead.stats();
            stats.ready_bytes == 0 && stats.blocks == 0 && stats.inflight == 0
        }),
        "the pool outlived the session that filled it: {:?}",
        readahead.stats()
    );
    let dropped = readahead.stats();

    // Reopening works, and every byte it returns is the byte that belongs at
    // its offset.
    assert!(
        eventually(PATIENCE, || File::open(guest.path("tree/stream.bin"))
            .is_ok()),
        "the file never reopened after the restart"
    );
    assert_eq!(
        read_checked(&guest.path("tree/stream.bin"), 512 * 1024),
        size
    );
    let after = readahead.stats();
    assert!(
        after.hit_bytes > dropped.hit_bytes,
        "the reader after the gap was never served from the pool, so the engine \
         did not come back with the session"
    );
}
