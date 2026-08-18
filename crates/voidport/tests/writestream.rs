//! Write streaming: the window, the failure state it leaves, and the mounts
//! and handles that keep the serial path.
//!
//! The suite has two halves, because the claims have two kinds.
//!
//! The **engine's own** claims are about what the wire carries and what the
//! server ends up holding when a chunk is refused or answered short, so they
//! are driven against a server written for the purpose: it records every write
//! request it is given, applies the bytes it accepts, and refuses or shortens
//! exactly the chunk an arm names. Holding its answers back is what puts a
//! window of chunks on the wire at once, and counting what it has outstanding
//! is how the window's bound is proven from the *server's* side and not from
//! the client's own bookkeeping.
//!
//! The **mount's** claims — a returned write is an answered write, an excluded
//! handle keeps the serial path, a page-cached mount is untouched — are about
//! the product, so they run through a real server, a real mount and the real
//! guest kernel, exactly as the rest of the end-to-end suite does. What the
//! *guest kernel* has in flight while a mount streams is deliberately not
//! measured here: that is the v1 write suite's own subject, and the engine is
//! held to it by running that suite with a chunk unit set
//! ([`support::write_stream_bytes`]) instead of by a second copy of its
//! assertions.
//!
//! The short-answer arm is **probed, then asserted**: the server's apply is one
//! unlooped `pwrite`, so whether a chunk can come back short is the backing
//! filesystem's behaviour and not this client's. Each arm asks the filesystem
//! first — one `pwrite` of a chunk on a real ext4 and a real btrfs — and then
//! asserts what that answer makes true, so neither filesystem's policy is
//! presumed.

mod support;

use std::fs;
use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

use rustix::fs::OFlags;
use rustix::io::Errno;
use support::{Fixture, preflight};
use voidport::client::{
    CHUNKS_PER_HANDLE, Caller, Client, Resilience, WriteStream, WriteStreamStats,
};
use voidport::mount::MountOptions;
use voidport::url::Endpoint;
use voidport_proto::PROTOCOL_VERSION;
use voidport_proto::frame::{
    FRAME_HEADER_LEN, Frame, FrameHeader, FrameWriter, MAX_HELLO_FRAME_LEN,
};
use voidport_proto::opcode::Opcode;
use voidport_proto::ops::file::{WriteRequest, WriteResponse};
use voidport_proto::ops::handshake::HelloReply;
use zerocopy::FromBytes as _;
use zerocopy::byteorder::little_endian::{U32, U64};

/// The frame bound the recording server announces, as the real one does.
const MAX_FRAME_LEN: u32 = 1024 * 1024;

/// The chunk unit every arm here streams in.
///
/// Small, because what is being asserted is where the chunk boundaries fall and
/// what happens at one of them — not throughput, which W2 measures.
const UNIT: usize = 8192;

/// How long the recording server holds an answer back.
///
/// Long enough that the whole window is on the wire before anything comes
/// back, which is what makes "several chunks at once" a fact the server states
/// and not an inference from the client.
const HOLD: Duration = Duration::from_millis(25);

/// Long enough that no attribute or entry validity expires mid-test.
const NEVER: Duration = Duration::from_secs(3600);

/// How much one end-to-end arm writes through a mount.
const WRITE_BYTES: usize = 1024 * 1024;

/// How much of it goes in one write syscall.
///
/// Several chunk units, so every write really is a window of chunks, and far
/// inside the negotiated `max_write`, so the kernel never has to split one of
/// them into two requests of its own.
const WRITE_BLOCK: usize = 128 * 1024;

// ---------------------------------------------------------------------------
// The recording server
// ---------------------------------------------------------------------------

/// What the recording server does with the chunk an arm names.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Shorten {
    /// Every chunk is taken whole.
    #[default]
    Never,
    /// The chunk at this offset takes only this many bytes.
    At(u64, u32),
    /// Every chunk takes only this many bytes.
    Every(u32),
}

/// How the recording server answers.
#[derive(Clone, Copy, Debug, Default)]
struct Policy {
    /// The chunk offset it refuses, and the errno it refuses with. A refusal is
    /// answered at once, whatever `hold` says, so an arm can rely on the
    /// failure being known before the answers behind it arrive.
    refuse: Option<(u64, Errno)>,
    /// The chunk it takes only part of.
    shorten: Shorten,
    /// How long every other answer waits before it goes out.
    hold: Duration,
    /// The chunk offset at which the server drops the connection instead of
    /// answering anything again: the mid-write death the resilience contract
    /// answers with EIO.
    die_at: Option<u64>,
}

impl Policy {
    /// How much of a chunk at `offset` carrying `len` bytes this server takes,
    /// or the errno it refuses with.
    fn answer(self, offset: u64, len: usize) -> Result<usize, Errno> {
        if let Some((refused, errno)) = self.refuse
            && refused == offset
        {
            return Err(errno);
        }
        Ok(match self.shorten {
            Shorten::Never => len,
            Shorten::At(at, keep) if at == offset => len.min(keep as usize),
            Shorten::At(..) => len,
            Shorten::Every(keep) => len.min(keep as usize),
        })
    }
}

/// What the recording server saw and holds.
#[derive(Debug, Default)]
struct Recorded {
    /// The bytes it accepted, at the offsets they were addressed to.
    file: Mutex<Vec<u8>>,
    /// Every write request, in arrival order: offset and length.
    seen: Mutex<Vec<(u64, usize)>>,
    /// Every write request's write_flags, in arrival order.
    flags: Mutex<Vec<u32>>,
    /// Write requests it has read and not yet answered.
    outstanding: AtomicUsize,
    /// The most it ever had outstanding at once, which is the window as the
    /// server sees it.
    peak: AtomicUsize,
}

impl Recorded {
    /// The offsets of the write requests it was given, in arrival order.
    fn offsets(&self) -> Vec<u64> {
        self.seen
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .iter()
            .map(|(offset, _)| *offset)
            .collect()
    }

    /// The write_flags of every write request it was given.
    fn write_flags(&self) -> Vec<u32> {
        self.flags
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .clone()
    }

    /// How many write requests it was given.
    fn requests(&self) -> usize {
        self.seen
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .len()
    }

    /// The bytes it holds.
    fn bytes(&self) -> Vec<u8> {
        self.file
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .clone()
    }

    /// Takes one chunk's bytes at the offset it was addressed to.
    fn apply(&self, offset: u64, data: &[u8]) {
        let mut file = self
            .file
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let at = offset as usize;
        if file.len() < at + data.len() {
            file.resize(at + data.len(), 0);
        }
        file[at..at + data.len()].copy_from_slice(data);
    }
}

/// One answer the reading half handed the answering half.
#[derive(Debug)]
struct Pending {
    request_id: u64,
    /// The offset the request addressed, kept so the read loop can see it.
    offset: u64,
    outcome: Result<usize, Errno>,
    hold: Duration,
}

/// Starts a server that records every write and answers it as `policy` says.
fn recording_server(policy: Policy) -> (SocketAddr, Arc<Recorded>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a free port");
    let address = listener.local_addr().expect("a bound address");
    let recorded = Arc::new(Recorded::default());

    let served = Arc::clone(&recorded);
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("the client connects");
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("a settable timeout");
        handshake(&mut stream);

        let answering = Arc::new(Mutex::new(
            stream.try_clone().expect("the socket duplicates"),
        ));
        let (queue, queued) = mpsc::channel::<Pending>();
        let replier = {
            let (recorded, answering) = (Arc::clone(&served), Arc::clone(&answering));
            std::thread::spawn(move || answer_writes(&answering, &queued, &recorded))
        };

        // Reading and answering are two threads on purpose: a server that
        // answered where it read could never hold more than one request, and
        // the window is exactly the thing being observed.
        while let Some(bytes) = read_frame(&mut stream) {
            let Some(pending) = record(&bytes, &served, policy) else {
                break;
            };
            if policy.die_at == Some(pending.offset) {
                // The mid-write death: the socket is shut down whole, so held
                // answers never go out and the client observes the loss now
                // instead of at a read timeout.
                let _ = stream.shutdown(std::net::Shutdown::Both);
                break;
            }
            if pending.hold.is_zero() {
                // A refusal is answered where it is read, so it cannot queue
                // behind an answer that is being held back. That is what lets
                // an arm say the failure was known before the rest came in —
                // the answers are held in one queue, and a refusal that joined
                // it would come out behind whatever was already waiting.
                if !send_answer(&answering, &pending, &served) {
                    break;
                }
            } else if queue.send(pending).is_err() {
                break;
            }
        }
        drop(queue);
        let _ = replier.join();
    });

    (address, recorded)
}

/// Records one request and says how it is to be answered.
fn record(bytes: &[u8], recorded: &Arc<Recorded>, policy: Policy) -> Option<Pending> {
    let frame = Frame::parse(bytes, MAX_FRAME_LEN).expect("a well-framed request");
    let request_id = frame.request_id();
    let write = frame.request::<WriteRequest>().ok()?;
    let offset = write.body().offset.get();
    let data = write.payload();
    recorded
        .seen
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
        .push((offset, data.len()));
    recorded
        .flags
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
        .push(write.body().write_flags.get());
    let outstanding = recorded.outstanding.fetch_add(1, Ordering::Relaxed) + 1;
    recorded.peak.fetch_max(outstanding, Ordering::Relaxed);

    let outcome = policy.answer(offset, data.len());
    if let Ok(taken) = outcome {
        recorded.apply(offset, &data[..taken]);
    }
    Some(Pending {
        request_id,
        offset,
        outcome,
        // A refusal is never held back: an arm that asserts what happens
        // *after* a failure needs the failure to be the first thing back.
        hold: if outcome.is_err() {
            Duration::ZERO
        } else {
            policy.hold
        },
    })
}

/// Answers queued writes, holding each back for as long as the policy says.
fn answer_writes(
    stream: &Mutex<TcpStream>,
    queued: &mpsc::Receiver<Pending>,
    recorded: &Arc<Recorded>,
) {
    while let Ok(pending) = queued.recv() {
        if !pending.hold.is_zero() {
            std::thread::sleep(pending.hold);
        }
        if !send_answer(stream, &pending, recorded) {
            return;
        }
    }
}

/// Writes one answer, and says whether the socket took it.
fn send_answer(stream: &Mutex<TcpStream>, pending: &Pending, recorded: &Recorded) -> bool {
    let mut buffer = [0u8; 64];
    let frame = match pending.outcome {
        Ok(written) => FrameWriter::response(
            &mut buffer,
            MAX_FRAME_LEN,
            pending.request_id,
            &WriteResponse {
                written: U32::new(u32::try_from(written).unwrap_or(u32::MAX)),
            },
        )
        .and_then(FrameWriter::finish)
        .expect("encodable")
        .to_vec(),
        Err(errno) => FrameWriter::error_response(
            &mut buffer,
            MAX_FRAME_LEN,
            pending.request_id,
            Opcode::Write,
            -errno.raw_os_error(),
        )
        .expect("encodable")
        .to_vec(),
    };
    recorded.outstanding.fetch_sub(1, Ordering::Relaxed);
    stream
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
        .write_all(&frame)
        .is_ok()
}

/// Answers the handshake exactly as a conforming server does.
fn handshake(stream: &mut TcpStream) {
    let hello = read_frame(stream).expect("a hello");
    let request_id = Frame::parse(&hello, MAX_HELLO_FRAME_LEN)
        .expect("a well-framed hello")
        .request_id();
    let mut buffer = [0u8; 64];
    let reply = FrameWriter::response(
        &mut buffer,
        MAX_HELLO_FRAME_LEN,
        request_id,
        &HelloReply {
            root_node_id: U64::new(1),
            protocol_version: U32::new(PROTOCOL_VERSION),
            flags: U32::ZERO,
            max_frame_len: U32::new(MAX_FRAME_LEN),
            reserved: U32::ZERO,
        },
    )
    .and_then(FrameWriter::finish)
    .expect("encodable")
    .to_vec();
    stream.write_all(&reply).expect("the client is listening");
}

/// Reads one whole frame from a blocking stream.
fn read_frame(stream: &mut TcpStream) -> Option<Vec<u8>> {
    let mut header = [0u8; FRAME_HEADER_LEN];
    stream.read_exact(&mut header).ok()?;
    let (parsed, _) = FrameHeader::ref_from_prefix(&header).expect("a header");
    let mut bytes = vec![0u8; parsed.len.get() as usize];
    bytes[..FRAME_HEADER_LEN].copy_from_slice(&header);
    stream.read_exact(&mut bytes[FRAME_HEADER_LEN..]).ok()?;
    Some(bytes)
}

// ---------------------------------------------------------------------------
// Driving one streamed write
// ---------------------------------------------------------------------------

/// What one streamed write left behind, on all three sides of it.
struct Streamed {
    /// What the write answered the caller.
    outcome: Result<u32, Errno>,
    /// What the engine had done when it answered.
    stats: WriteStreamStats,
    /// Write requests the server had been given when the call returned.
    at_return: usize,
    /// The same, a while afterwards: equal, always, because a returned write
    /// has nothing left on the wire.
    afterwards: usize,
    /// The server.
    recorded: Arc<Recorded>,
}

/// Writes `data` through the engine, against a server answering by `policy`.
fn stream(policy: Policy, data: &[u8]) -> Streamed {
    stream_with(policy, data, false)
}

/// As [`stream`], with the privileged-strip mark set as the caller says.
fn stream_with(policy: Policy, data: &[u8], strip: bool) -> Streamed {
    let (address, recorded) = recording_server(policy);
    let endpoint = Endpoint::Tcp {
        host: address.ip().to_string(),
        port: address.port(),
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    let data = Arc::new(data.to_vec());
    let served = Arc::clone(&recorded);

    let (outcome, stats, at_return, afterwards) = runtime.block_on(async move {
        let client = Client::mount_with(
            &endpoint,
            "namespace",
            b"",
            Resilience {
                stall: Duration::ZERO,
            },
        )
        .await
        .expect("the handshake succeeds");
        let engine = WriteStream::new(UNIT);
        engine.activate(true);

        let outcome = engine
            .write(&client, Caller::default(), 1, 7, 0, &data, strip)
            .await;
        let stats = engine.stats();
        let at_return = served.requests();
        // Long enough that a chunk this write had abandoned, or resumed after
        // it had failed, would have reached the server by now.
        tokio::time::sleep(HOLD * 8).await;
        (outcome, stats, at_return, served.requests())
    });

    Streamed {
        outcome,
        stats,
        at_return,
        afterwards,
        recorded,
    }
}

/// Bytes whose value depends on where they are, and none of them zero — so a
/// range the server never took reads as the zeros it was never written.
fn payload(len: usize) -> Vec<u8> {
    (0..len).map(|at| ((at % 251) + 1) as u8).collect()
}

/// Which chunks of `expected` the server holds, by chunk index.
fn placed(file: &[u8], expected: &[u8]) -> Vec<usize> {
    expected
        .chunks(UNIT)
        .enumerate()
        .filter(|(index, chunk)| file.get(index * UNIT..index * UNIT + chunk.len()) == Some(*chunk))
        .map(|(index, _)| index)
        .collect()
}

// ---------------------------------------------------------------------------
// The window
// ---------------------------------------------------------------------------

/// A write is cut into chunks that are on the wire together, and it answers
/// only once every one of them has been answered.
#[test]
fn a_streamed_write_puts_its_chunks_on_the_wire_together() {
    let expected = payload(CHUNKS_PER_HANDLE * UNIT);
    let streamed = stream(
        Policy {
            hold: HOLD,
            ..Policy::default()
        },
        &expected,
    );

    assert_eq!(streamed.outcome, Ok(expected.len() as u32));
    assert_eq!(streamed.recorded.bytes(), expected);
    assert_eq!(
        streamed.stats.chunks, CHUNKS_PER_HANDLE as u64,
        "the write was cut at the mount's chunk unit"
    );
    let peak = streamed.recorded.peak.load(Ordering::Relaxed);
    assert!(
        peak > 1,
        "the server never held more than {peak} chunk at once, so nothing was \
         streamed at all"
    );
    assert!(
        peak <= CHUNKS_PER_HANDLE,
        "the server held {peak} chunks of one handle at once, past the window's \
         bound of {CHUNKS_PER_HANDLE}"
    );
    // A returned write is an answered write, and it leaves nothing behind.
    assert_eq!(streamed.stats.inflight, 0);
    assert_eq!(streamed.at_return, streamed.afterwards);
}

/// A write far larger than the window is bounded by it and finishes anyway: a
/// full window backpressures the writer and never errors.
#[test]
fn a_full_window_backpressures_a_large_write_instead_of_failing_it() {
    let chunks = CHUNKS_PER_HANDLE * 5;
    let expected = payload(chunks * UNIT);
    let streamed = stream(
        Policy {
            hold: Duration::from_millis(2),
            ..Policy::default()
        },
        &expected,
    );

    assert_eq!(streamed.outcome, Ok(expected.len() as u32));
    assert_eq!(streamed.recorded.bytes(), expected);
    assert_eq!(streamed.stats.chunks, chunks as u64);
    let peak = streamed.recorded.peak.load(Ordering::Relaxed);
    assert!(
        peak <= CHUNKS_PER_HANDLE,
        "{chunks} chunks reached {peak} on the wire at once, past the window's \
         bound of {CHUNKS_PER_HANDLE}"
    );
    assert!(
        streamed.stats.peak_inflight <= CHUNKS_PER_HANDLE,
        "the engine's own count agrees with the server's"
    );
}

// ---------------------------------------------------------------------------
// Failure: the documented state, per chunk position
// ---------------------------------------------------------------------------

/// A refused chunk fails the write with its own errno and leaves a **byte-range
/// subset** on the server — not the prefix a serial loop leaves.
///
/// The position is what makes the divergence visible: a chunk refused in the
/// middle leaves the chunks *after* it applied, which is precisely what the
/// serial loop could never do and precisely what this contract says it does.
#[test]
fn a_refused_chunk_leaves_a_byte_range_subset_and_reports_its_errno() {
    let expected = payload(CHUNKS_PER_HANDLE * UNIT);
    for position in [0, 3, CHUNKS_PER_HANDLE - 1] {
        let streamed = stream(
            Policy {
                refuse: Some(((position * UNIT) as u64, Errno::NOSPC)),
                hold: HOLD,
                ..Policy::default()
            },
            &expected,
        );

        assert_eq!(
            streamed.outcome,
            Err(Errno::NOSPC),
            "chunk {position}: the failed chunk's own errno reaches the caller"
        );
        let placed = placed(&streamed.recorded.bytes(), &expected);
        let survivors: Vec<usize> = (0..CHUNKS_PER_HANDLE)
            .filter(|index| *index != position)
            .collect();
        assert_eq!(
            placed, survivors,
            "chunk {position}: the file holds the write's other chunks and not \
             the refused one"
        );
        assert!(
            !placed.contains(&position),
            "chunk {position}: the refused chunk's bytes are on the server"
        );
        // Nothing of the request outlives it: every chunk that was sent was
        // awaited, and none arrived afterwards.
        assert_eq!(streamed.stats.inflight, 0);
        assert_eq!(
            streamed.at_return, streamed.afterwards,
            "chunk {position}: a chunk of this write reached the server after \
             the write had returned"
        );
    }
}

/// The chunks a failure finds unsent are abandoned: a write far larger than the
/// window stops where the window was when the first refusal came back.
#[test]
fn the_chunks_a_failure_finds_unsent_are_abandoned() {
    let chunks = CHUNKS_PER_HANDLE * 5;
    let expected = payload(chunks * UNIT);
    let streamed = stream(
        Policy {
            refuse: Some((0, Errno::IO)),
            hold: HOLD,
            ..Policy::default()
        },
        &expected,
    );

    assert_eq!(streamed.outcome, Err(Errno::IO));
    let sent = streamed.recorded.requests();
    assert!(
        sent < chunks,
        "all {chunks} chunks were sent even though the first was refused"
    );
    assert!(
        sent <= CHUNKS_PER_HANDLE * 2,
        "{sent} chunks were sent after a refusal that arrived while the window \
         held {CHUNKS_PER_HANDLE}"
    );
    assert_eq!(
        streamed.at_return, streamed.afterwards,
        "a chunk was sent after the write had already returned"
    );
    assert_eq!(streamed.stats.inflight, 0);
}

/// Once a chunk has failed, a short answer resumes nothing.
///
/// Every chunk here is answered short and one is refused, and the refusal is
/// the first answer back — so any resume the engine issued would be a request
/// at an offset that is not a chunk boundary. There is none.
#[test]
fn a_short_answer_resumes_nothing_once_a_chunk_has_failed() {
    let expected = payload(CHUNKS_PER_HANDLE * UNIT);
    let streamed = stream(
        Policy {
            refuse: Some((0, Errno::IO)),
            shorten: Shorten::Every(1024),
            hold: HOLD,
            die_at: None,
        },
        &expected,
    );

    assert_eq!(streamed.outcome, Err(Errno::IO));
    assert_eq!(streamed.stats.resumes, 0);
    for offset in streamed.recorded.offsets() {
        assert_eq!(
            offset % UNIT as u64,
            0,
            "a request at {offset} is a resume, and a failed write resumes \
             nothing"
        );
    }
}

/// A chunk answered short while the write is healthy resumes from the byte the
/// server stopped at, and the write still places every byte.
#[test]
fn a_short_chunk_resumes_while_the_write_is_healthy() {
    const KEEP: u32 = 3000;
    let expected = payload(CHUNKS_PER_HANDLE * UNIT);
    let resumed_at = (2 * UNIT + KEEP as usize) as u64;
    let streamed = stream(
        Policy {
            shorten: Shorten::At((2 * UNIT) as u64, KEEP),
            ..Policy::default()
        },
        &expected,
    );

    assert_eq!(streamed.outcome, Ok(expected.len() as u32));
    assert_eq!(
        streamed.recorded.bytes(),
        expected,
        "the resumed tail did not place the bytes the short answer left"
    );
    assert_eq!(streamed.stats.resumes, 1);
    assert!(
        streamed.recorded.offsets().contains(&resumed_at),
        "no chunk resumed from {resumed_at}, where the server stopped"
    );
}

// ---------------------------------------------------------------------------
// Through a real mount
// ---------------------------------------------------------------------------

/// A mount that streams its writes, in the one mode the engine runs in.
fn streaming() -> MountOptions {
    MountOptions {
        attr_timeout: NEVER,
        entry_timeout: NEVER,
        direct_io: true,
        write_stream: UNIT,
        ..MountOptions::default()
    }
}

/// A returned write is an answered write: the host holds every byte before the
/// writer has flushed or synced anything.
///
/// What the *guest kernel* has in flight is not measured here. It is the
/// parallel-writes suite's subject, in the shape that suite controls for, and
/// it is measured against the engine by running that suite with the run's chunk
/// unit set ([`support::write_stream_bytes`]).
#[test]
fn a_streamed_mount_places_every_byte_before_the_write_returns() {
    if !preflight() {
        return;
    }
    let fixture = Fixture::start("write-stream-e2e");
    let guest = fixture.mount_with("stream", &fixture.tcp_url("plain", "/tree"), &streaming());
    let engine = guest.write_stream();
    assert!(engine.is_active(), "a direct mount with a unit streams");

    let expected = payload(WRITE_BYTES);
    let mut file = fs::File::create(guest.path("streamed.bin")).expect("the file is created");
    for block in expected.chunks(WRITE_BLOCK) {
        file.write_all(block).expect("the write succeeds");
    }

    // No flush and no sync: the write returned, so every chunk of it was
    // answered, so the host has the bytes.
    assert_eq!(
        fs::read(fixture.host("tree/streamed.bin")).expect("the host file reads"),
        expected,
        "a returned write left bytes the server had not answered for"
    );
    let stats = engine.stats();
    assert!(
        stats.chunks >= (WRITE_BYTES / UNIT) as u64,
        "{} chunks for {WRITE_BYTES} bytes at a {UNIT}-byte unit: the write was \
         not cut",
        stats.chunks
    );
    assert_eq!(stats.inflight, 0, "the mount is holding nothing");
}

/// The excluded handles keep the serial path, and the engine's own count is
/// what says so: a write it never cut is a write it never touched.
#[test]
fn the_excluded_handles_keep_the_serial_path() {
    if !preflight() {
        return;
    }
    let fixture = Fixture::start("write-stream-excluded");
    let guest = fixture.mount_with("excluded", &fixture.tcp_url("plain", "/tree"), &streaming());
    let engine = guest.write_stream();
    let block = payload(4096);

    // The ordinary handle first, so the counter is known to move at all.
    let mut ordinary = fs::File::create(guest.path("ordinary.bin")).expect("the file is created");
    ordinary.write_all(&block).expect("the write succeeds");
    drop(ordinary);
    let streamed = engine.stats().chunks;
    assert!(streamed > 0, "an ordinary handle streams");

    for (name, flags) in [
        ("appended.bin", OFlags::APPEND),
        ("synced.bin", OFlags::SYNC),
        ("dsynced.bin", OFlags::DSYNC),
        ("direct.bin", OFlags::DIRECT),
    ] {
        let path = guest.path(name);
        fs::write(&path, b"").expect("the file exists before it is opened");
        let before = engine.stats().chunks;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .custom_flags(flags.bits() as i32)
            .open(&path)
            .unwrap_or_else(|error| panic!("{name} opens: {error}"));
        file.write_all(&block)
            .unwrap_or_else(|error| panic!("{name} writes: {error}"));
        file.flush().expect("the writer flushes");
        drop(file);
        assert_eq!(
            engine.stats().chunks,
            before,
            "{name}: a handle opened {flags:?} was streamed, and it is excluded"
        );
        assert_eq!(
            fs::read(fixture.host(&format!("tree/{name}"))).expect("the host file reads"),
            block,
            "{name}: the serial path did not place the bytes"
        );
    }
}

/// A metadata operation stays responsive while a streamed write saturates the
/// same connection.
///
/// Two mechanisms keep it so, and this arm is end to end over both: the window
/// bounds what is on the wire at all, and the send path's class rule bounds
/// what a metadata request queues behind once it is there — one chunk, not the
/// window. That is why the allowance below is a fixed handful of frames and
/// does not grow with the size of the write.
///
/// The class rule *itself* is proven where the frames queue, in the
/// connection's own suite, because the ordering it fixes is only observable
/// when the socket back-pressures and a loopback link at this chunk unit never
/// does. What this arm adds is the product's own answer: the engine really does
/// send its chunks in the bulk class, and a guest stating a file while a mount
/// streams is answered as promptly as on a quiet one.
#[test]
fn a_metadata_operation_stays_responsive_under_a_streamed_write() {
    if !preflight() {
        return;
    }
    let fixture = Fixture::start("write-stream-latency");
    let probes = 200usize;
    for index in 0..probes * 2 {
        fs::write(fixture.host(&format!("tree/p{index}")), b"x").expect("a probe file");
    }
    let guest = fixture.mount_with("latency", &fixture.tcp_url("plain", "/tree"), &streaming());

    let stat = |index: usize| {
        let path = guest.path(&format!("p{index}"));
        let started = Instant::now();
        fs::metadata(&path).expect("the probe file stats");
        started.elapsed()
    };

    // The baseline: the same operation on a quiet mount. Each probe stats a
    // file it has never stat'ed before, so the answer comes from the server and
    // not from the kernel's attribute cache.
    let baseline = median((0..probes).map(stat).collect());

    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let writer = {
        let path = guest.path("saturating.bin");
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            let block = payload(WRITE_BYTES);
            let mut file = fs::File::create(&path).expect("the file is created");
            while !stop.load(Ordering::Relaxed) {
                file.write_all(&block).expect("the write succeeds");
            }
        })
    };
    std::thread::sleep(Duration::from_millis(300));
    let loaded = median((probes..probes * 2).map(stat).collect());
    stop.store(true, Ordering::Relaxed);
    writer.join().expect("the writer finishes");

    // Generous on purpose: the ordering rule itself is proven in the
    // connection's own unit suite; this arm only asserts the product stays
    // responsive, and a tight wall-clock bound under test parallelism would
    // trade that assertion for a flake.
    let allowance = baseline + Duration::from_millis(50);
    assert!(
        loaded <= allowance,
        "a metadata operation took {loaded:?} under a streamed write, against a \
         baseline of {baseline:?} plus a 50 ms allowance for scheduling and \
         the one chunk a prompt frame may wait behind"
    );
}

/// The median of a set of durations.
fn median(mut samples: Vec<Duration>) -> Duration {
    samples.sort_unstable();
    samples[samples.len() / 2]
}

/// A page-cached mount is untouched, whatever unit it was given: the engine
/// keys on the mode the handshake settled, exactly as the readahead engine
/// does.
#[test]
fn a_page_cached_mount_never_streams() {
    if !preflight() {
        return;
    }
    let fixture = Fixture::start("write-stream-paged");
    let options = MountOptions {
        direct_io: false,
        ..streaming()
    };
    let guest = fixture.mount_with("paged", &fixture.tcp_url("plain", "/tree"), &options);
    let engine = guest.write_stream();
    assert!(!engine.is_active());

    let expected = payload(WRITE_BYTES);
    let mut file = fs::File::create(guest.path("paged.bin")).expect("the file is created");
    file.write_all(&expected).expect("the write succeeds");
    file.sync_all().expect("the writer syncs");
    drop(file);

    assert_eq!(engine.stats().chunks, 0, "a page-cached mount cut nothing");
    assert_eq!(
        fs::read(fixture.host("tree/paged.bin")).expect("the host file reads"),
        expected
    );
}

// ---------------------------------------------------------------------------
// Short answers: probed on a real filesystem, then asserted
// ---------------------------------------------------------------------------

/// A filesystem in a file, mounted for the length of one test.
///
/// The image lives in a temporary directory of its own and **not** inside the
/// fixture's, so that removing the fixture's world never walks into a mounted
/// filesystem.
struct HostFilesystem {
    /// Removed after the unmount: it holds the image and the mountpoint.
    /// `None` after a failed unmount, where removing it would recurse into a
    /// filesystem that is still mounted — the directory is leaked instead,
    /// which is the only safe answer a destructor has.
    directory: Option<support::TempDir>,
    mountpoint: PathBuf,
    mounted: bool,
}

impl HostFilesystem {
    /// Creates, formats and mounts an image of `mib` mebibytes as `kind`.
    ///
    /// `None` where the kernel offers no loop devices, which is the one
    /// preflight this is allowed — without `/dev/loop-control` there is no way
    /// to put a block device in front of a file. Missing *tools* are not
    /// skipped: the development shell provides them, and a silent pass would
    /// say a filesystem had been asked something it never was.
    fn create(kind: &str, mib: u64) -> Option<Self> {
        // The capability that actually decides is mounting, which needs root:
        // a usable /dev/loop-control without it would pass this preflight and
        // then panic at mount(8). Both are checked, and the skip names what
        // stays unproven either way.
        if !rustix::process::geteuid().is_root() {
            eprintln!(
                "skipping {kind}: not root, so nothing can be loop-mounted; NOT PROVEN by this \
                 run: what one unlooped pwrite does on {kind}, and therefore what a streamed \
                 write's short-answer path does there"
            );
            return None;
        }
        if let Err(error) = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/loop-control")
        {
            eprintln!(
                "skipping {kind}: /dev/loop-control is unusable ({error}); NOT PROVEN by this \
                 run: what one unlooped pwrite does on {kind}, and therefore what a streamed \
                 write's short-answer path does there"
            );
            return None;
        }
        let directory = support::TempDir::new(&format!("write-stream-{kind}"));
        let image = directory.join("image.bin");
        let file = fs::File::create(&image).expect("the image is creatable");
        file.set_len(mib * 1024 * 1024)
            .expect("the image is sizable");
        drop(file);
        match kind {
            "btrfs" => run(
                "mkfs.btrfs",
                &["-f", "--nodiscard", &image.display().to_string()],
            ),
            _ => run("mkfs.ext4", &["-q", "-F", &image.display().to_string()]),
        }

        let mountpoint = directory.directory("mnt");
        run(
            "mount",
            &[
                "-o",
                "loop",
                &image.display().to_string(),
                &mountpoint.display().to_string(),
            ],
        );
        Some(Self {
            directory: Some(directory),
            mountpoint,
            mounted: true,
        })
    }

    /// The mounted filesystem's root.
    fn root(&self) -> &Path {
        &self.mountpoint
    }
}

impl Drop for HostFilesystem {
    /// A leaked mount outlives the test process and keeps the loop device and
    /// the scratch directory pinned, so this waits out a mountpoint that is
    /// still settling and is as loud as it can be if it never does.
    fn drop(&mut self) {
        if !self.mounted {
            return;
        }
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let status = Command::new("umount").arg(&self.mountpoint).status();
            match status {
                Ok(status) if status.success() => return,
                other if Instant::now() >= deadline => {
                    eprintln!(
                        "!!! {} is still mounted: {other:?}; its directory is \
                         leaked so nothing deletes into a live filesystem",
                        self.mountpoint.display()
                    );
                    if let Some(directory) = self.directory.take() {
                        std::mem::forget(directory);
                    }
                    return;
                }
                _ => std::thread::sleep(Duration::from_millis(50)),
            }
        }
    }
}

/// Runs a command and requires it to succeed.
fn run(program: &str, arguments: &[&str]) {
    let output = Command::new(program)
        .args(arguments)
        .output()
        .unwrap_or_else(|error| {
            panic!(
                "{program} could not be run ({error}); the development shell \
                 (`./check`, or `nix develop`) provides the tools this test needs"
            )
        });
    assert!(
        output.status.success(),
        "{program} {arguments:?} failed ({}):\n{}{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// What one unlooped `pwrite` of `len` bytes does on this filesystem.
///
/// The server's apply is exactly this call, so this is the question the
/// short-answer path hangs on, asked of the filesystem instead of assumed of
/// it.
fn probe_one_pwrite(root: &Path, len: usize) -> usize {
    let path = root.join("pwrite-probe.bin");
    let file = fs::File::create(&path).expect("the probe file is creatable");
    let written = rustix::io::pwrite(&file, &payload(len), 0).expect("the probe write succeeds");
    drop(file);
    let _ = fs::remove_file(&path);
    written
}

/// One streamed write onto a real filesystem, asserted against what that
/// filesystem was just measured doing.
fn short_answers_arm(kind: &str, mib: u64) {
    if !preflight() {
        return;
    }
    // Declared before the fixture, so the server that grafts it is gone before
    // the filesystem is unmounted.
    let Some(image) = HostFilesystem::create(kind, mib) else {
        return;
    };
    // The probe, first and on its own: what the server's single pwrite does
    // here decides what the assertion below is allowed to be.
    let probed = probe_one_pwrite(image.root(), UNIT);
    println!("write-stream: one {UNIT}-byte pwrite on {kind} wrote {probed} bytes");

    let fixture = Fixture::start_over(&format!("write-stream-{kind}"), "", Some(image.root()));
    let guest = fixture.mount_with(kind, &fixture.tcp_url("image", "/fs"), &streaming());
    let engine = guest.write_stream();

    let expected = payload(WRITE_BYTES);
    let mut file = fs::File::create(guest.path("streamed.bin")).expect("the file is created");
    file.write_all(&expected).expect("the write succeeds");
    drop(file);

    let stats = engine.stats();
    assert_eq!(
        fs::read(image.root().join("streamed.bin")).expect("the host file reads"),
        expected,
        "{kind}: the streamed write did not place every byte"
    );
    if probed == UNIT {
        assert_eq!(
            stats.resumes, 0,
            "{kind}: one pwrite of {UNIT} bytes takes all of them here, so no \
             chunk had anything to resume from"
        );
    } else {
        assert!(
            stats.resumes > 0,
            "{kind}: one pwrite of {UNIT} bytes takes only {probed} here, so a \
             chunk had to be resumed and none was"
        );
    }
    assert_eq!(stats.inflight, 0);
}

/// The short-answer arm on ext4.
#[test]
fn a_streamed_write_matches_what_ext4_does_with_one_pwrite() {
    short_answers_arm("ext4", 64);
}

/// The short-answer arm on btrfs, which is a different filesystem with its own
/// policy and is asked the same question separately for exactly that reason.
#[test]
fn a_streamed_write_matches_what_btrfs_does_with_one_pwrite() {
    short_answers_arm("btrfs", 256);
}

// ---------------------------------------------------------------------------
// The privileged-strip mark, on every chunk
// ---------------------------------------------------------------------------

/// The strip mark rides **every** chunk of a streamed write — the shipped rule
/// for a split write, asserted per chunk against what the server actually
/// received, not against what the engine says it sent.
#[test]
fn the_strip_mark_rides_every_chunk_or_none_at_all() {
    use voidport_proto::ops::file::write_flags::PRIVILEGED_STRIP;

    let expected = payload(UNIT * 4);
    let stripped = stream_with(Policy::default(), &expected, true);
    assert_eq!(stripped.outcome, Ok(expected.len() as u32));
    let flags = stripped.recorded.write_flags();
    assert_eq!(flags.len(), 4);
    for (chunk, flag) in flags.iter().enumerate() {
        assert_eq!(
            flag & PRIVILEGED_STRIP,
            PRIVILEGED_STRIP,
            "chunk {chunk} arrived without the strip mark"
        );
    }

    let plain = stream(Policy::default(), &expected);
    assert_eq!(plain.outcome, Ok(expected.len() as u32));
    for (chunk, flag) in plain.recorded.write_flags().iter().enumerate() {
        assert_eq!(
            flag & PRIVILEGED_STRIP,
            0,
            "chunk {chunk} of an unmarked write carried the strip mark"
        );
    }
}

// ---------------------------------------------------------------------------
// Connection loss mid-write
// ---------------------------------------------------------------------------

/// A connection that dies with chunks unanswered fails the write with EIO —
/// the resilience contract's written-but-unanswered rule, applied verbatim and
/// unamended: nothing replays, nothing resumes, and nothing of the write
/// arrives after the call has returned.
#[test]
fn a_connection_lost_mid_write_fails_the_write_with_eio() {
    let chunks = 12;
    let expected = payload(UNIT * chunks);
    let streamed = stream_with(
        Policy {
            hold: Duration::from_millis(50),
            die_at: Some((UNIT * 4) as u64),
            ..Policy::default()
        },
        &expected,
        false,
    );

    assert_eq!(
        streamed.outcome,
        Err(Errno::IO),
        "a mid-write connection loss answers EIO, never a partial success"
    );
    assert!(
        streamed.at_return <= chunks,
        "no chunk was sent twice: {} requests for {chunks} chunks",
        streamed.at_return
    );
    assert_eq!(
        streamed.at_return, streamed.afterwards,
        "nothing of the write reached the wire after the call returned"
    );
}

/// A chunk answered zero bytes without an error ends the write as a short
/// success at the answered prefix — the serial loop's own break — and nothing
/// more is cut or sent, while chunks already in flight may have applied.
#[test]
fn a_zero_answer_ends_the_write_as_a_short_success() {
    let chunks = CHUNKS_PER_HANDLE + 4;
    let expected = payload(chunks * UNIT);
    let streamed = stream(
        Policy {
            shorten: Shorten::At((2 * UNIT) as u64, 0),
            hold: HOLD,
            ..Policy::default()
        },
        &expected,
    );

    assert_eq!(streamed.outcome, Ok((2 * UNIT) as u32));
    assert!(
        streamed.at_return < chunks,
        "cutting stopped at the zero answer: {} of {chunks} chunks sent",
        streamed.at_return
    );
    assert_eq!(
        streamed.at_return, streamed.afterwards,
        "nothing of the write reached the wire after the call returned"
    );
    assert_eq!(streamed.stats.resumes, 0, "a zero answer is never resumed");
}
