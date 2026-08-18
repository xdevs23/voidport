//! Write streaming: sub-frame chunking with a concurrent window.
//!
//! One guest write becomes several wire writes that are on the connection at
//! the same time, and the guest's write returns only when **every** one of them
//! has been answered. Nothing is acknowledged early anywhere: the syscall is
//! held exactly as long as the serial path holds it, and what changes is that
//! the round trips inside one request overlap instead of following one another.
//!
//! ## Why the chunks are smaller than a frame
//!
//! The client announces its write budget to the FUSE kernel as `max_write` and
//! the kernel splits every syscall to that size before this layer sees it, so a
//! mechanism keyed to "writes larger than a frame" would never fire here. The
//! mechanism is therefore the other direction: a request that already fits one
//! frame is cut **below** the frame bound — a 1 MiB request into eight 128 KiB
//! chunks, say — and the chunks are sent together.
//!
//! ## The window
//!
//! In-flight chunks are bounded in count and in bytes, per handle and per
//! mount — both counts are mount options, defaulting to
//! [`DEFAULT_CHUNKS_PER_HANDLE`] and [`DEFAULT_CHUNKS_PER_MOUNT`] — with a
//! per-handle reservation ([`RESERVED_FIRST_CHUNK`]) so one large write cannot
//! take the mount's whole window and hold another handle at nothing in flight.
//! Both levels are sized when the mount is made and fixed for its life. A full
//! window makes the next chunk **wait**; it never errors.
//!
//! ## The send path's two classes
//!
//! The chunks a full window holds back are held **here**, not on the
//! connection: a chunk becomes a frame only once the window admits it. The
//! chunks the window *has* admitted are another matter — a whole window of them
//! is on the connection at once, by design — so they are sent in the send
//! path's **bulk** class ([`Client::write_streamed`]), which queues one chunk at
//! a time at the connection's serialization point. A metadata request is
//! therefore admitted ahead of the window still waiting to be written, and is
//! passed by one chunk at most. Nothing of that rule lives here: it is the
//! connection's, where the frames are, and this engine's part in it is naming
//! the class its chunks belong to.
//!
//! ## Scope, and what stays on the v1 path
//!
//! The engine runs on mounts whose **negotiated** data caching is direct (a
//! page-cached mount's writes go through the guest page cache and keep the v1
//! path byte for byte), and a chunk unit of zero turns it off entirely.
//! Three kinds of handle are excluded on their own semantics and keep
//! the serial path whatever the mount asked for: `O_APPEND` (the offset is not
//! the placement), `O_SYNC` and `O_DSYNC` (per-write durability ordering), and
//! a guest handle opened `O_DIRECT` (which asked for unbuffered, uncoalesced
//! submission and is already served by parallel direct writes).
//!
//! ## Failure, stated without pretense
//!
//! Chunks apply concurrently, so a failed chunk does not stop the chunks
//! already in flight from applying: the bytes on disk after a failed streamed
//! write are *some subset of its chunks' byte ranges*, not the prefix a serial
//! loop leaves. That is the one semantic divergence from v1, it exists only on
//! writes that fail partway, and it is what the fault-injection arms assert.
//! Error delivery is v1's: the syscall reports the **first** failed chunk's
//! errno — first by offset, which is the one the serial loop would have
//! stopped at. Unsent chunks are abandoned, in-flight chunks are awaited before
//! the call returns, and a chunk answered short resumes from the answered byte
//! while the write is otherwise healthy — never once a chunk has failed.
//!
//! Connection loss is the resilience contract's, unamended: a chunk that was
//! written and never answered fails `EIO`, a chunk still queued is sent on the
//! replacement connection and receives its honest stale answer, and either way
//! the write fails. Nothing is replayed.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use rustix::io::Errno;
use tokio::sync::watch;
use tokio::task::JoinSet;

use super::{Caller, Client};

/// How many chunks one handle may have on the wire at once, by default.
///
/// The default of a mount option, **kept at eight by measurement** (the W2
/// matrix): the depth that matters is the one that lets a whole kernel-split
/// request fly at once — a window smaller than the request multiplies its
/// round trips, and the matrix measured that directly (0.42× serial at a
/// quarter of the request, 0.68× at half, even at cover) — while depth beyond
/// cover measured nothing anywhere. Eight covers the 1 MiB request bound at
/// every unit of 128 KiB and above, with margin at the 256 KiB default.
pub const DEFAULT_CHUNKS_PER_HANDLE: NonZeroUsize = NonZeroUsize::new(8).expect("8 is not zero");

/// How many chunks one mount may have on the wire at once, by default.
///
/// **Kept at thirty-two by measurement**: the matrix ran the mount level to
/// sixty-four and measured nothing above thirty-two, and the server's
/// per-connection bound of 64 in-flight requests is a **shared** budget —
/// prefetch reads, metadata traffic and write chunks all draw on it — so this
/// leaves the other classes their measured shares instead of meeting the
/// ceiling, which would stall the connection's read loop for everyone.
pub const DEFAULT_CHUNKS_PER_MOUNT: NonZeroUsize = NonZeroUsize::new(32).expect("32 is not zero");

/// How many of the mount's slots only a handle's **first** chunk may take.
///
/// The anti-starvation slot, named for what it is: one slot of the mount's
/// window that a handle already holding chunks may not take, so a saturated
/// window always has room left for another handle's first chunk and a large
/// write on one handle can never hold another handle at nothing in flight.
/// A handle that gets one chunk moving competes for the rest on equal terms.
pub const RESERVED_FIRST_CHUNK: usize = 1;

/// What a mount's write-streaming engine is doing, for tests to assert on.
///
/// Test support, and deliberately nothing more: the engine has no control
/// surface and this adds none.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WriteStreamStats {
    /// Chunks on the wire right now.
    pub inflight: usize,
    /// The bytes those chunks carry at most: the count times the chunk unit,
    /// which is the byte bound the fixed unit makes true by construction.
    pub inflight_bytes: usize,
    /// Handles with a chunk on the wire.
    pub handles: usize,
    /// Chunks issued since the mount started.
    pub chunks: u64,
    /// Follow-up chunks issued because a chunk was answered short.
    pub resumes: u64,
    /// The most chunks this mount ever had on the wire at once.
    pub peak_inflight: usize,
    /// How many times a chunk waited for the window to make room.
    pub waits: u64,
}

/// One mount's write-streaming engine.
///
/// Created for every mount and dormant until [`WriteStream::activate`] is told
/// what the handshake settled on, exactly as the readahead engine is: a kernel
/// without the mmap capability keeps `--direct-io` and falls back to page
/// caching, where the write path must stay the one it always was.
#[derive(Debug)]
pub struct WriteStream {
    /// The chunk unit in bytes; zero leaves every write on the v1 path.
    chunk: usize,
    /// Whether the negotiated data-caching mode is direct.
    active: AtomicBool,
    window: Mutex<Window>,
    /// Bumped whenever a chunk leaves the window, so a write waiting for room
    /// wakes when there is some instead of polling for it.
    room: watch::Sender<u64>,
    counters: Counters,
}

/// The in-flight accounting, all of it behind one lock.
///
/// The window counts chunks; it does not count bytes, because every chunk is
/// cut at or below the fixed chunk unit, so the count bound times the unit IS
/// the byte bound, by construction — a second live counter could never fire.
#[derive(Debug)]
struct Window {
    /// Chunks on the wire across the mount.
    inflight: usize,
    /// The same, per handle. A handle with nothing in flight holds no entry.
    handles: HashMap<u64, Held>,
    /// The most chunks one handle may have on the wire.
    per_handle: usize,
    /// The most chunks the mount may have on the wire.
    per_mount: usize,
}

/// What one handle holds of the window.
#[derive(Clone, Copy, Debug, Default)]
struct Held {
    inflight: usize,
}

/// The engine's counters, which are test support and not a control surface.
#[derive(Debug, Default)]
struct Counters {
    chunks: AtomicU64,
    resumes: AtomicU64,
    waits: AtomicU64,
    peak: AtomicUsize,
}

/// One chunk of a streamed write, as the engine describes it.
///
/// `start` is an offset **into the guest's buffer**, so the chunk's absolute
/// file offset is the write's offset plus it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Chunk {
    start: usize,
    len: usize,
}

/// One chunk's answer, as its task reports it.
#[derive(Debug)]
struct Answer {
    chunk: Chunk,
    outcome: Result<u32, Errno>,
}

impl WriteStream {
    /// Builds a mount's engine.
    ///
    /// `chunk` is the chunk unit in bytes; zero is the default and leaves every
    /// write on the v1 path. `per_handle` and `per_mount` are the window's two
    /// count bounds, sized here and fixed for the mount's life.
    #[must_use]
    pub fn new(chunk: usize, per_handle: NonZeroUsize, per_mount: NonZeroUsize) -> Arc<Self> {
        let (room, _) = watch::channel(0);
        Arc::new(Self {
            chunk,
            active: AtomicBool::new(false),
            window: Mutex::new(Window::new(per_handle, per_mount)),
            room,
            counters: Counters::default(),
        })
    }

    /// Says whether the mount's negotiated data-caching mode is direct.
    ///
    /// Called once, from the FUSE handshake, with the *resolved* mode. Until
    /// then — and for ever on a page-cached mount — every write takes the v1
    /// path.
    pub fn activate(&self, direct: bool) {
        self.active.store(direct, Ordering::Relaxed);
    }

    /// Whether the engine is running: a chunk unit, and direct data caching.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.chunk > 0 && self.active.load(Ordering::Relaxed)
    }

    /// The chunk unit this mount was made with, in bytes.
    #[must_use]
    pub fn chunk_bytes(&self) -> usize {
        self.chunk
    }

    /// Whether a write through a handle opened with `flags` is streamed.
    ///
    /// The exclusions are the contract's and they are decided here, from the
    /// flags the kernel puts on the write request itself — which carry the
    /// handle's own `O_APPEND` and `O_DIRECT` and the `O_SYNC`/`O_DSYNC` of a
    /// write the caller asked to be durable.
    #[must_use]
    pub fn serves(&self, flags: u32) -> bool {
        self.is_active() && !excluded(flags)
    }

    /// What the engine is holding and what it has done, for tests.
    #[must_use]
    pub fn stats(&self) -> WriteStreamStats {
        let window = self.lock();
        WriteStreamStats {
            inflight: window.inflight,
            inflight_bytes: window.inflight * self.chunk,
            handles: window.handles.len(),
            chunks: self.counters.chunks.load(Ordering::Relaxed),
            resumes: self.counters.resumes.load(Ordering::Relaxed),
            peak_inflight: self.counters.peak.load(Ordering::Relaxed),
            waits: self.counters.waits.load(Ordering::Relaxed),
        }
    }

    /// Writes one guest buffer as a window of chunks, and returns when every
    /// chunk it sent has been answered.
    ///
    /// The count returned is the write's answered **prefix**, which is the
    /// whole buffer on the ordinary path; the serial loop's own answer, for the
    /// same reasons.
    ///
    /// # Errors
    ///
    /// The first failed chunk's errno, by offset, or `EIO` on a degraded mount.
    #[allow(
        clippy::too_many_arguments,
        reason = "one guest write, named exactly as the FUSE callback receives it"
    )]
    pub async fn write(
        self: &Arc<Self>,
        client: &Arc<Client>,
        caller: Caller,
        node_id: u64,
        handle: u64,
        offset: u64,
        data: &Arc<Vec<u8>>,
        strip: bool,
    ) -> Result<u32, Errno> {
        let mut slicing = Slicing::new(data.len());
        let mut answers = Answers::default();
        let mut inflight: JoinSet<Answer> = JoinSet::new();
        loop {
            // Send as much as the window admits. The bound is read per chunk,
            // not once: a reconnect can install a connection with a smaller
            // frame bound, and the chunks that have not been cut yet are cut at
            // the new one.
            let mut held_back = false;
            while answers.sending() {
                let bound = self.bound(client);
                let Some(chunk) = slicing.peek(bound) else {
                    break;
                };
                let Some(permit) = self.reserve(handle) else {
                    held_back = true;
                    break;
                };
                slicing.commit(chunk);
                self.counters.chunks.fetch_add(1, Ordering::Relaxed);
                let (client, data) = (Arc::clone(client), Arc::clone(data));
                inflight.spawn(async move {
                    let outcome = client
                        .write_streamed(
                            caller,
                            node_id,
                            handle,
                            offset + chunk.start as u64,
                            &data[chunk.start..chunk.start + chunk.len],
                            strip,
                        )
                        .await;
                    // Held until the answer is in hand, which is what makes the
                    // window a count of chunks on the wire.
                    drop(permit);
                    Answer { chunk, outcome }
                });
            }

            if inflight.is_empty() {
                if !answers.sending() || !slicing.has_work() || !held_back {
                    break;
                }
                // Nothing of this write is on the wire and there is more to
                // send: the mount's window is full of another handle's chunks.
                // Waiting for room is the backpressure, and it is the only
                // thing a full window ever does.
                self.wait_for_room(handle).await;
                continue;
            }
            // Every chunk that was sent is awaited, so nothing of this request
            // outlives the call — including on the failing path, where the
            // unsent chunks are abandoned and the sent ones are not.
            match inflight.join_next().await {
                Some(Ok(answer)) => answers.take(answer, &mut slicing, &self.counters),
                // A chunk whose task did not run to its end answered nothing,
                // and a write may not report bytes nobody confirmed.
                Some(Err(error)) => {
                    tracing::error!(%error, "a write chunk did not complete");
                    // A chunk that vanished is this engine's own defect, so it
                    // outranks every ordinary failure: offset zero is the one
                    // start the lowest-offset rule can never place behind
                    // another, and the guest hears about it first.
                    answers.fail(0, Errno::IO);
                }
                None => break,
            }
        }

        if let Some((_, error)) = answers.failure {
            return Err(error);
        }
        Ok(u32::try_from(answers.prefix()).unwrap_or(u32::MAX))
    }

    /// How large the next chunk may be: the mount's unit, never above the frame
    /// budget of the connection serving this instant.
    fn bound(&self, client: &Client) -> usize {
        self.chunk.min(client.write_chunk() as usize).max(1)
    }

    /// Takes a place in the window for one chunk, or reports that there is
    /// none.
    fn reserve(self: &Arc<Self>, handle: u64) -> Option<Permit> {
        let mut window = self.lock();
        if !window.admits(handle) {
            return None;
        }
        window.take(handle);
        self.counters
            .peak
            .fetch_max(window.inflight, Ordering::Relaxed);
        Some(Permit {
            engine: Arc::clone(self),
            handle,
        })
    }

    /// Waits until the window would admit a chunk for this handle.
    async fn wait_for_room(&self, handle: u64) {
        self.counters.waits.fetch_add(1, Ordering::Relaxed);
        loop {
            // Subscribed before the window is read, so a chunk that leaves in
            // between is a change this receiver has not seen yet and the wait
            // below returns at once instead of missing it.
            let mut room = self.room.subscribe();
            if self.lock().admits(handle) {
                return;
            }
            if room.changed().await.is_err() {
                return;
            }
        }
    }

    /// Gives a chunk's place back and wakes whoever is waiting for one.
    fn release(&self, handle: u64) {
        self.lock().give_back(handle);
        self.room.send_modify(|tick| *tick = tick.wrapping_add(1));
    }

    fn lock(&self) -> MutexGuard<'_, Window> {
        self.window
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }
}

/// One chunk's place in the window, given up when it is dropped.
///
/// Dropping is the whole mechanism, so a chunk whose task is dropped instead of
/// finished gives its place back just the same.
#[derive(Debug)]
struct Permit {
    engine: Arc<WriteStream>,
    handle: u64,
}

impl Drop for Permit {
    fn drop(&mut self) {
        self.engine.release(self.handle);
    }
}

impl Window {
    /// An empty window with its two count bounds.
    fn new(per_handle: NonZeroUsize, per_mount: NonZeroUsize) -> Self {
        Self {
            inflight: 0,
            handles: HashMap::new(),
            per_handle: per_handle.get(),
            per_mount: per_mount.get(),
        }
    }

    /// Whether a chunk may go out for `handle` right now.
    ///
    /// Two count bounds and the reservation: the handle's count, the mount's
    /// count, and the one slot only a handle's first chunk may take, which
    /// keeps a handle with nothing in flight from being held out by one that
    /// is streaming. Bytes need no bound of their own — every chunk is at or
    /// below the fixed unit, so count times unit is the byte bound already.
    fn admits(&self, handle: u64) -> bool {
        let held = self.handles.get(&handle).copied().unwrap_or_default();
        if held.inflight >= self.per_handle || self.inflight >= self.per_mount {
            return false;
        }
        held.inflight < RESERVED_FIRST_CHUNK
            || self.inflight + RESERVED_FIRST_CHUNK < self.per_mount
    }

    /// Records one chunk as being on the wire.
    fn take(&mut self, handle: u64) {
        self.inflight += 1;
        let held = self.handles.entry(handle).or_default();
        held.inflight += 1;
    }

    /// Records one chunk as answered.
    fn give_back(&mut self, handle: u64) {
        self.inflight = self.inflight.saturating_sub(1);
        if let Some(held) = self.handles.get_mut(&handle) {
            held.inflight = held.inflight.saturating_sub(1);
            if held.inflight == 0 {
                self.handles.remove(&handle);
            }
        }
    }
}

/// How one write's buffer is cut into chunks.
///
/// Two sources, in this order: the tail a short answer left behind, and then
/// the part of the buffer no chunk has been cut for yet. A resume names a range
/// inside a region that was already cut, so no two chunks of one write ever
/// overlap.
#[derive(Debug)]
struct Slicing {
    /// How long the guest's buffer is.
    len: usize,
    /// The first byte no chunk has been cut for.
    cursor: usize,
    /// Tails left by short answers, oldest first.
    resumes: VecDeque<Chunk>,
}

impl Slicing {
    fn new(len: usize) -> Self {
        Self {
            len,
            cursor: 0,
            resumes: VecDeque::new(),
        }
    }

    /// The next chunk to send under `bound`, without cutting it yet.
    ///
    /// Peek and [`Slicing::commit`] are two steps because a chunk is only cut
    /// once the window has a place for it: a chunk cut and then held back would
    /// have to be un-cut, and un-cutting is where an overlap would come from.
    fn peek(&self, bound: usize) -> Option<Chunk> {
        if let Some(chunk) = self.resumes.front() {
            return Some(Chunk {
                start: chunk.start,
                len: chunk.len.min(bound),
            });
        }
        if self.cursor >= self.len {
            return None;
        }
        Some(Chunk {
            start: self.cursor,
            len: bound.min(self.len - self.cursor),
        })
    }

    /// Takes the chunk [`Slicing::peek`] described.
    fn commit(&mut self, chunk: Chunk) {
        match self.resumes.front_mut() {
            Some(head) if chunk.len < head.len => {
                // A tail longer than the bound this attempt is cut at leaves
                // the rest of itself behind, re-sliced at whatever bound the
                // next attempt reads.
                head.start += chunk.len;
                head.len -= chunk.len;
            }
            Some(_) => {
                self.resumes.pop_front();
            }
            None => self.cursor += chunk.len,
        }
    }

    /// Queues the tail a short answer left behind.
    fn resume(&mut self, chunk: Chunk) {
        self.resumes.push_back(chunk);
    }

    /// Whether anything of the write has still to be sent.
    fn has_work(&self) -> bool {
        self.cursor < self.len || !self.resumes.is_empty()
    }
}

/// What the chunks answered, and what the write reports because of it.
#[derive(Debug, Default)]
struct Answers {
    /// How many bytes each chunk placed, by the chunk's start in the buffer.
    applied: BTreeMap<usize, usize>,
    /// The failed chunk with the lowest start, and its errno.
    failure: Option<(usize, Errno)>,
    /// Whether a chunk answered zero bytes without an error — the answer the
    /// serial loop breaks on. The write ends as a short success: nothing more
    /// is cut or sent, in-flight chunks are awaited, and the reported count is
    /// the contiguous prefix exactly as on the failing path.
    ended: bool,
}

impl Answers {
    /// Whether no chunk has failed yet, which is what decides whether a short
    /// answer is resumed.
    fn healthy(&self) -> bool {
        self.failure.is_none()
    }

    /// Whether anything more may be cut and sent: no failure, and no chunk
    /// answered zero — the serial loop's own break condition, kept.
    fn sending(&self) -> bool {
        self.healthy() && !self.ended
    }

    /// Takes one chunk's answer.
    fn take(&mut self, answer: Answer, slicing: &mut Slicing, counters: &Counters) {
        let chunk = answer.chunk;
        match answer.outcome {
            Ok(written) => {
                let written = (written as usize).min(chunk.len);
                self.applied.insert(chunk.start, written);
                if written == 0 {
                    self.ended = true;
                }
                // A short answer resumes from the byte the server stopped at —
                // while the write is healthy. An answer of nothing resumes
                // nowhere: it would ask for the same bytes for ever, and it
                // ends the sending instead.
                if written > 0 && written < chunk.len && self.healthy() {
                    slicing.resume(Chunk {
                        start: chunk.start + written,
                        len: chunk.len - written,
                    });
                    counters.resumes.fetch_add(1, Ordering::Relaxed);
                }
            }
            Err(error) => self.fail(chunk.start, error),
        }
    }

    /// Records a failed chunk, keeping the one with the lowest start.
    ///
    /// That is the chunk the serial loop would have stopped at, so the errno
    /// the guest is told is the errno v1 would have told it.
    fn fail(&mut self, start: usize, error: Errno) {
        match self.failure {
            Some((held, _)) if held <= start => {}
            _ => self.failure = Some((start, error)),
        }
    }

    /// How many bytes of the buffer were placed, contiguously, from its start.
    ///
    /// A chunk that was answered short is followed by the resume that continues
    /// it, so the walk crosses a resumed chunk exactly as it crosses a whole
    /// one, and stops at the first byte nobody confirmed.
    fn prefix(&self) -> usize {
        let mut at = 0;
        while let Some(&written) = self.applied.get(&at) {
            if written == 0 {
                break;
            }
            at += written;
        }
        at
    }
}

/// Whether a handle opened with these flags keeps the v1 write path.
fn excluded(flags: u32) -> bool {
    use rustix::fs::OFlags;

    OFlags::from_bits_retain(flags)
        .intersects(OFlags::APPEND | OFlags::SYNC | OFlags::DSYNC | OFlags::DIRECT)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An engine with a chunk unit, told the mount negotiated direct caching.
    fn engine(chunk: usize) -> Arc<WriteStream> {
        let engine = WriteStream::new(chunk, DEFAULT_CHUNKS_PER_HANDLE, DEFAULT_CHUNKS_PER_MOUNT);
        engine.activate(true);
        engine
    }

    /// The two count bounds are per handle and per mount, spelled as counts.
    const PER_HANDLE: usize = DEFAULT_CHUNKS_PER_HANDLE.get();
    const PER_MOUNT: usize = DEFAULT_CHUNKS_PER_MOUNT.get();

    #[test]
    fn the_engine_runs_only_in_direct_mode_and_only_with_a_chunk_unit() {
        let paged = WriteStream::new(
            128 * 1024,
            DEFAULT_CHUNKS_PER_HANDLE,
            DEFAULT_CHUNKS_PER_MOUNT,
        );
        assert!(
            !paged.is_active(),
            "a mount is page-cached until the handshake says otherwise"
        );
        paged.activate(true);
        assert!(paged.is_active());
        paged.activate(false);
        assert!(
            !paged.is_active(),
            "a kernel without the mmap capability keeps the flag and falls back \
             to page caching, where the write path must not change"
        );

        let off = WriteStream::new(0, DEFAULT_CHUNKS_PER_HANDLE, DEFAULT_CHUNKS_PER_MOUNT);
        off.activate(true);
        assert!(
            !off.is_active(),
            "no chunk unit is the default, and it is off"
        );
        assert!(!off.serves(0), "and it streams nothing");
    }

    /// The exclusions are the contract's, and they are read from the flags the
    /// kernel puts on the write itself.
    #[test]
    fn the_excluded_handles_keep_the_serial_path() {
        use rustix::fs::OFlags;

        let engine = engine(128 * 1024);
        assert!(engine.serves(OFlags::WRONLY.bits()));
        assert!(engine.serves(OFlags::RDWR.bits()));
        for excluded in [OFlags::APPEND, OFlags::SYNC, OFlags::DSYNC, OFlags::DIRECT] {
            assert!(
                !engine.serves((OFlags::WRONLY | excluded).bits()),
                "{excluded:?} is excluded on its own semantics"
            );
        }
        // O_SYNC is O_DSYNC plus one bit on Linux, so a handle carrying either
        // spelling is excluded by either name.
        assert!(OFlags::SYNC.contains(OFlags::DSYNC));
    }

    /// The window bounds the handle and the mount, and the reservation keeps a
    /// handle that has nothing in flight from being held out by one that has.
    #[test]
    fn the_window_bounds_the_handle_the_mount_and_keeps_its_reservation() {
        const UNIT: usize = 1024;
        let engine = engine(UNIT);

        // Three handles fill three quarters of the mount's window, each
        // stopping at its own bound.
        let mut permits: Vec<Permit> = Vec::new();
        for handle in 1..=3 {
            for _ in 0..PER_HANDLE {
                permits.push(engine.reserve(handle).expect("the handle's own window"));
            }
            assert!(
                engine.reserve(handle).is_none(),
                "a handle may hold {PER_HANDLE} chunks and no more"
            );
        }
        let stats = engine.stats();
        assert_eq!(stats.inflight, 3 * PER_HANDLE);
        assert_eq!(stats.inflight_bytes, 3 * PER_HANDLE * UNIT);
        assert_eq!(stats.handles, 3);

        // A fourth streams into what is left and is stopped short of the last
        // slots: those are the reservation, and a handle that already holds
        // chunks may not take them.
        let mut streamed = 0;
        while let Some(permit) = engine.reserve(4) {
            permits.push(permit);
            streamed += 1;
        }
        assert_eq!(streamed, PER_HANDLE - RESERVED_FIRST_CHUNK);
        assert_eq!(engine.stats().inflight, PER_MOUNT - RESERVED_FIRST_CHUNK);

        // And the slot it was refused is exactly the one a handle with nothing
        // in flight is admitted into, which is what the reservation is for.
        let last = engine
            .reserve(5)
            .expect("a handle with nothing in flight is never starved");
        assert_eq!(engine.stats().inflight, PER_MOUNT);
        assert_eq!(engine.stats().peak_inflight, PER_MOUNT);
        assert!(
            engine.reserve(6).is_none(),
            "and the mount's bound is still the mount's bound"
        );

        drop(last);
        permits.clear();
        let stats = engine.stats();
        assert_eq!(stats.inflight, 0);
        assert_eq!(stats.inflight_bytes, 0);
        assert_eq!(stats.handles, 0, "a handle holding nothing holds no entry");
    }

    /// The two count bounds are the mount's own, not the defaults: an engine
    /// sized smaller binds at the size it was given.
    #[test]
    fn the_window_binds_at_the_counts_the_mount_was_sized_with() {
        let sized = |count: usize| NonZeroUsize::new(count).expect("a test count is not zero");
        let engine = WriteStream::new(1024, sized(2), sized(4));
        engine.activate(true);

        let mut permits: Vec<Permit> = Vec::new();
        permits.push(engine.reserve(1).expect("the first chunk"));
        permits.push(engine.reserve(1).expect("the second chunk"));
        assert!(
            engine.reserve(1).is_none(),
            "two per handle was the size given, so two is the bound"
        );
        permits.push(engine.reserve(2).expect("another handle's first chunk"));
        assert!(
            engine.reserve(2).is_none(),
            "the last of four mount slots is the reservation, and a handle \
             already streaming may not take it"
        );
        permits.push(
            engine
                .reserve(3)
                .expect("a first chunk takes the reserved slot"),
        );
        assert_eq!(engine.stats().inflight, 4);
        assert!(
            engine.reserve(4).is_none(),
            "four across the mount was the size given, so four is the bound"
        );
    }

    /// Chunks are cut at the bound, in order, and never overlap — including
    /// when the bound shrinks under a reconnect mid-write.
    #[test]
    fn the_slicing_cuts_at_the_bound_and_re_slices_what_it_has_not_sent() {
        let mut slicing = Slicing::new(1000);
        let mut cut = Vec::new();
        for _ in 0..3 {
            let chunk = slicing.peek(300).expect("more to send");
            slicing.commit(chunk);
            cut.push(chunk);
        }
        assert_eq!(
            cut,
            vec![
                Chunk { start: 0, len: 300 },
                Chunk {
                    start: 300,
                    len: 300
                },
                Chunk {
                    start: 600,
                    len: 300
                },
            ]
        );

        // The bound halves: what is left is cut at the new one, and the last
        // chunk is the remainder and not a full unit.
        let chunk = slicing.peek(150).expect("more to send");
        assert_eq!(
            chunk,
            Chunk {
                start: 900,
                len: 100
            }
        );
        slicing.commit(chunk);
        assert!(!slicing.has_work());
        assert!(slicing.peek(150).is_none());
    }

    /// A short answer resumes from the answered byte, and the resumed chunk is
    /// itself cut at whatever bound is in force when it goes out.
    #[test]
    fn a_short_answer_resumes_from_where_the_server_stopped() {
        let mut slicing = Slicing::new(400);
        let mut answers = Answers::default();
        let counters = Counters::default();

        let first = slicing.peek(200).expect("more to send");
        slicing.commit(first);
        answers.take(
            Answer {
                chunk: first,
                outcome: Ok(80),
            },
            &mut slicing,
            &counters,
        );
        assert_eq!(counters.resumes.load(Ordering::Relaxed), 1);
        // The tail comes before the part of the buffer nobody has cut yet.
        assert_eq!(
            slicing.peek(200),
            Some(Chunk {
                start: 80,
                len: 120
            })
        );
        // And a bound below the tail's length cuts the tail, leaving the rest
        // of it queued — never a chunk that overlaps the one just sent.
        let piece = slicing.peek(50).expect("the tail");
        assert_eq!(piece, Chunk { start: 80, len: 50 });
        slicing.commit(piece);
        assert_eq!(
            slicing.peek(200),
            Some(Chunk {
                start: 130,
                len: 70
            })
        );

        // An answer of nothing at all resumes nowhere: asking for the same
        // bytes again would never end.
        let mut stalled = Slicing::new(400);
        let chunk = stalled.peek(200).expect("more to send");
        stalled.commit(chunk);
        let mut answers = Answers::default();
        answers.take(
            Answer {
                chunk,
                outcome: Ok(0),
            },
            &mut stalled,
            &counters,
        );
        assert_eq!(
            stalled.peek(200),
            Some(Chunk {
                start: 200,
                len: 200
            })
        );
        assert_eq!(answers.prefix(), 0);
    }

    /// Once a chunk has failed, nothing is resumed — the documented rule, and
    /// the one a race would otherwise decide.
    #[test]
    fn nothing_is_resumed_once_a_chunk_has_failed() {
        let mut slicing = Slicing::new(400);
        let mut answers = Answers::default();
        let counters = Counters::default();
        let first = slicing.peek(200).expect("more to send");
        slicing.commit(first);
        let second = slicing.peek(200).expect("more to send");
        slicing.commit(second);

        answers.take(
            Answer {
                chunk: first,
                outcome: Err(Errno::IO),
            },
            &mut slicing,
            &counters,
        );
        answers.take(
            Answer {
                chunk: second,
                outcome: Ok(50),
            },
            &mut slicing,
            &counters,
        );
        assert_eq!(counters.resumes.load(Ordering::Relaxed), 0);
        assert!(!slicing.has_work(), "the tail of a short answer is dropped");
        assert!(!answers.healthy());
    }

    /// The errno the guest is told is the first failed chunk's by offset —
    /// whatever order the answers arrived in — which is the errno the serial
    /// loop would have stopped at.
    #[test]
    fn the_reported_errno_is_the_first_failed_chunks() {
        let mut answers = Answers::default();
        answers.fail(600, Errno::NOSPC);
        assert_eq!(answers.failure, Some((600, Errno::NOSPC)));
        answers.fail(300, Errno::IO);
        assert_eq!(
            answers.failure,
            Some((300, Errno::IO)),
            "a failure at a lower offset is the one the serial loop reports"
        );
        answers.fail(900, Errno::PERM);
        assert_eq!(answers.failure, Some((300, Errno::IO)));
    }

    /// The count a successful write reports is the contiguous prefix the
    /// answers confirmed, resumed chunks crossed exactly like whole ones.
    #[test]
    fn the_answered_prefix_is_what_the_write_reports() {
        let mut answers = Answers::default();
        assert_eq!(answers.prefix(), 0);
        answers.applied.insert(0, 100);
        answers.applied.insert(200, 100);
        assert_eq!(
            answers.prefix(),
            100,
            "a hole stops the prefix, whatever arrived past it"
        );
        answers.applied.insert(100, 100);
        assert_eq!(answers.prefix(), 300);

        // The resumed shape: a chunk answered short, its tail answered whole.
        let mut resumed = Answers::default();
        resumed.applied.insert(0, 60);
        resumed.applied.insert(60, 40);
        resumed.applied.insert(100, 100);
        assert_eq!(resumed.prefix(), 200);
    }

    /// A window that is full makes the next chunk wait, and admits it the
    /// moment a chunk is answered. Backpressure, and never an error.
    #[tokio::test]
    async fn a_full_window_makes_the_next_chunk_wait_instead_of_failing() {
        const UNIT: usize = 512;
        let engine = engine(UNIT);
        let permits: Vec<Permit> = (0..PER_HANDLE)
            .map(|_| engine.reserve(1).expect("the handle's own window"))
            .collect();
        assert!(engine.reserve(1).is_none());

        let waiting = {
            let engine = Arc::clone(&engine);
            tokio::spawn(async move {
                engine.wait_for_room(1).await;
                engine.reserve(1).is_some()
            })
        };
        // Nothing has been answered yet, so the waiter is still waiting.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(!waiting.is_finished());

        drop(permits);
        assert!(waiting.await.expect("the waiter finishes"));
        assert_eq!(engine.stats().waits, 1);
    }
}
