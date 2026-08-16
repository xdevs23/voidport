//! Readahead: windowed prefetch over the ordinary read operation.
//!
//! It exists for one mode. On a **direct** mount the guest page cache holds no
//! file data, so there is no kernel readahead in front of the mount either:
//! every read is wire-immediate, and a sequential reader spends its life
//! waiting out one round trip after another. This engine puts the round trips
//! in flight *ahead* of the reader instead, which is the whole of the
//! throughput it buys. On a page-cached mount it never runs — the kernel's own
//! readahead already saturates that path, and prefetching underneath it would
//! only buffer the same bytes twice.
//!
//! Nothing here changes the wire. A prefetch is an ordinary read of an ordinary
//! handle, idempotent under the required replay discipline, and a server cannot
//! tell one from a read the guest asked for.
//!
//! ## The shape, and the numbers behind it
//!
//! * **Blocks live on a 128 KiB grid** ([`CHUNK_BYTES`]) — the measured
//!   throughput knee. A 128 KiB frame occupies the wire for roughly a tenth of
//!   the time a 1 MiB frame does, so a window of them pipelines where the
//!   larger frame merely queues.
//! * **A per-handle detector opens a window** when a read arrives at exactly
//!   the offset the previous one ended at. The window starts at
//!   [`INITIAL_WINDOW_CHUNKS`] chunks and doubles while the reader keeps pace —
//!   consuming at least half of what has been fetched but not yet read — up to
//!   [`MAX_WINDOW_CHUNKS`] (4 MiB of coverage). A read at any other offset is a
//!   seek: the window closes and the detector starts again.
//! * **Requests in flight are capped** at [`MAX_INFLIGHT_PER_HANDLE`] per
//!   handle and [`MAX_INFLIGHT_PER_MOUNT`] per mount, which is what bounds the
//!   engine's own contribution to the server's reply queue.
//! * **The pool is one per mount**, [`DEFAULT_POOL_BYTES`] by default. Issuing
//!   a prefetch **reserves** its 128 KiB before the request goes out, so
//!   arrivals can never overshoot the cap; a full pool simply stops the
//!   prefetcher instead of evicting blocks a reader is about to reach.
//! * **A byte is served once.** Consumption is tracked per block, a block is
//!   dropped the moment it is fully consumed, and a read that straddles blocks
//!   is answered by copying across them. Bytes that were already served are not
//!   served again — such a read goes to the wire, which is what keeps a re-read
//!   honest, not answered from a stale copy.
//! * **Every block carries its fetch time.** A block older than the mount's
//!   attribute TTL is dropped instead of served, which is the mechanism behind
//!   the coherence bound: prefetched bytes relax freshness to the attr TTL and
//!   no further.
//!
//! ## What invalidates
//!
//! A local write through any handle, and any `setattr` that changes size or
//! mtime, drop the file's blocks at once. Both bump the file's **epoch**, so a
//! prefetch that was already in flight is discarded on arrival, not
//! inserted behind the change. Closing a handle drops its window and — when no
//! other handle is reading the file — its blocks; chunks already on the wire
//! still cross it, bounded by the in-flight cap, and their replies are
//! discarded. A reconnect drops the pool entirely: the session those handles
//! belonged to is gone, and a block fetched under it must never be served
//! afterwards.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use rustix::io::Errno;
use tokio::sync::watch;

use super::{Caller, Client};

/// The grid every prefetched block sits on, and the size of one prefetch read.
///
/// 128 KiB by measurement: it reaches 2.24x the unpipelined throughput where a
/// 1 MiB chunk caps at 1.60x, because the smaller frame occupies the wire
/// ~120 µs against ~1 ms and therefore leaves room for a window of its peers.
pub const CHUNK_BYTES: usize = 128 * 1024;

/// The pool's default ceiling: 256 MiB for the whole mount.
///
/// A ceiling, not an allocation. An idle mount holds nothing at all, and the
/// pool only fills under sequential load.
pub const DEFAULT_POOL_BYTES: usize = 256 * 1024 * 1024;

/// The coverage a freshly opened window asks for, in chunks.
const INITIAL_WINDOW_CHUNKS: usize = 4;

/// The coverage cap, in chunks: 4 MiB per handle.
const MAX_WINDOW_CHUNKS: usize = (4 * 1024 * 1024) / CHUNK_BYTES;

/// How many prefetch reads one handle may have on the wire at once.
const MAX_INFLIGHT_PER_HANDLE: usize = 8;

/// How many prefetch reads one mount may have on the wire at once.
///
/// At most 2 MiB of serialized prefetch replies per mount, which is what bounds
/// the engine's own contribution to an interactive operation's latency.
const MAX_INFLIGHT_PER_MOUNT: usize = 16;

/// What a mount's readahead engine is doing, for tests to assert on.
///
/// Test support, and deliberately nothing more: the engine has no control
/// surface and this adds none. It is a snapshot, taken under the engine's lock.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReadaheadStats {
    /// Bytes of delivered blocks the pool is holding.
    pub ready_bytes: usize,
    /// Bytes reserved by prefetch reads that have not arrived yet.
    pub reserved_bytes: usize,
    /// Blocks the pool is holding.
    pub blocks: usize,
    /// Prefetch reads on the wire right now.
    pub inflight: usize,
    /// Handles with a window open or a position remembered.
    pub handles: usize,
    /// Prefetch reads issued since the mount started.
    pub issued: u64,
    /// Prefetch replies discarded on arrival: the handle closed, the file
    /// changed, or the session behind them died.
    pub discarded: u64,
    /// Bytes answered out of the pool.
    pub hit_bytes: u64,
    /// Bytes answered from the wire.
    pub wire_bytes: u64,
}

impl ReadaheadStats {
    /// Everything the pool is accountable for: delivered blocks plus what is
    /// reserved for requests in flight. This is the number the cap bounds.
    #[must_use]
    pub fn pool_bytes(&self) -> usize {
        self.ready_bytes + self.reserved_bytes
    }
}

/// One mount's readahead engine.
///
/// Created for every mount and dormant until [`Readahead::activate`] is told
/// the handshake settled on direct data caching — the engine keys on the
/// *resolved* mode, never on what `--direct-io` asked for, because a kernel
/// without the mmap capability keeps the flag and falls back to page caching,
/// where prefetching here would double-buffer what the kernel already holds.
#[derive(Debug)]
pub struct Readahead {
    /// The pool ceiling in bytes; zero disables the engine outright.
    budget: usize,
    /// How old a block may be and still be served.
    attr_ttl: Duration,
    /// Whether the negotiated data-caching mode is direct.
    active: AtomicBool,
    state: Mutex<Engine>,
    counters: Counters,
}

/// The engine's mutable state, all of it behind one lock.
#[derive(Debug, Default)]
struct Engine {
    /// The connection generation every block in the pool was fetched under.
    generation: Option<u64>,
    /// Bytes reserved for prefetch reads in flight.
    reserved: usize,
    /// Bytes of delivered blocks.
    ready: usize,
    /// Prefetch reads in flight, across the mount.
    inflight: usize,
    /// The next epoch to hand a file.
    next_epoch: u64,
    /// Blocks, by node id.
    files: HashMap<u64, FileBlocks>,
    /// Windows, by handle id.
    handles: HashMap<u64, Window>,
}

/// The blocks of one file, and the epoch that says which fetches belong to
/// them.
#[derive(Debug)]
struct FileBlocks {
    /// Bumped whenever the file's blocks are dropped. A prefetch reply carrying
    /// an older epoch is discarded, not inserted: it was read before the
    /// change that invalidated it.
    epoch: u64,
    blocks: BTreeMap<u64, Slot>,
}

/// What the grid holds at one chunk index.
#[derive(Debug)]
enum Slot {
    /// Fetched and waiting to be read.
    Ready(Block),
    /// A prefetch read is on the wire for it.
    ///
    /// The sender is never sent on: **dropping it is the signal**, and it is
    /// dropped exactly when the slot stops being pending — replaced by a block,
    /// or removed because the fetch failed or was discarded. A reader that
    /// cloned a receiver under the lock therefore cannot miss the resolution,
    /// and re-plans against whatever the slot became.
    Pending(watch::Sender<()>),
}

/// One prefetched block.
#[derive(Debug)]
struct Block {
    /// The bytes, shared so that serving copies them outside the engine's lock.
    data: Arc<[u8]>,
    /// The ranges of `data` nobody has been given yet, disjoint and ascending.
    unserved: Vec<(usize, usize)>,
    /// When the fetch arrived. A block older than the mount's attr TTL is
    /// dropped instead of served.
    fetched: Instant,
}

impl Block {
    fn new(data: Vec<u8>) -> Self {
        let len = data.len();
        Self {
            data: Arc::from(data),
            unserved: if len == 0 { Vec::new() } else { vec![(0, len)] },
            fetched: Instant::now(),
        }
    }

    /// Takes `[from, to)` if every byte of it is still unserved.
    ///
    /// All-or-nothing on purpose: a partially consumed range must not be
    /// answered half from the pool and half from the wire, and a byte already
    /// handed out is never handed out again.
    fn take(&mut self, from: usize, to: usize) -> bool {
        if from >= to {
            return false;
        }
        let Some(index) = self
            .unserved
            .iter()
            .position(|&(start, end)| start <= from && to <= end)
        else {
            return false;
        };
        let (start, end) = self.unserved[index];
        let mut replacement = Vec::with_capacity(2);
        if start < from {
            replacement.push((start, from));
        }
        if to < end {
            replacement.push((to, end));
        }
        self.unserved.splice(index..=index, replacement);
        true
    }

    /// Whether every byte has been served, which is when the block is dropped.
    fn is_consumed(&self) -> bool {
        self.unserved.is_empty()
    }
}

/// One handle's reading position and the window in front of it.
#[derive(Debug)]
struct Window {
    /// The node the handle is open on.
    node: u64,
    /// Where the next read is expected: the end of the last one.
    next_offset: u64,
    /// Whether a read has actually been served on this handle.
    ///
    /// A window is created *by* its handle's first read, so without this the
    /// creating read would find its own starting offset already expected and
    /// open a window on a single read. The detector wants two consecutive ones.
    served: bool,
    /// The window's coverage in chunks; zero means closed — the detector has
    /// not seen two consecutive reads yet, or a seek reset it.
    chunks: usize,
    /// The first offset no prefetch has been issued for.
    ///
    /// Always a chunk boundary: blocks are addressed by chunk index, so a fetch
    /// that started between two of them could not be filed under either.
    issued_to: u64,
    /// Prefetch reads this handle has on the wire.
    inflight: usize,
    /// Where the file ended, once a short read said so.
    eof: Option<u64>,
}

impl Window {
    fn fresh(node: u64, offset: u64) -> Self {
        Self {
            node,
            next_offset: offset,
            served: false,
            chunks: 0,
            issued_to: floor(offset),
            inflight: 0,
            eof: None,
        }
    }
}

/// The engine's counters, which are test support and not a control surface.
#[derive(Debug, Default)]
struct Counters {
    issued: AtomicU64,
    discarded: AtomicU64,
    hit_bytes: AtomicU64,
    wire_bytes: AtomicU64,
}

/// One prefetch read, as the issuing side describes it.
#[derive(Clone, Copy, Debug)]
struct Issue {
    node: u64,
    handle: u64,
    /// The file offset the chunk starts at; always a multiple of
    /// [`CHUNK_BYTES`].
    offset: u64,
    /// The file epoch the issue was made under.
    epoch: u64,
    /// The connection generation it was made under.
    generation: Option<u64>,
}

impl Readahead {
    /// Builds a mount's engine.
    ///
    /// `budget` is the pool ceiling in bytes; zero disables the engine, which
    /// is what `--readahead 0` reaches. `attr_ttl` is the mount's attribute
    /// timeout, and it bounds how long a prefetched block may be served for.
    #[must_use]
    pub fn new(budget: usize, attr_ttl: Duration) -> Arc<Self> {
        Arc::new(Self {
            budget,
            attr_ttl,
            active: AtomicBool::new(false),
            state: Mutex::new(Engine::default()),
            counters: Counters::default(),
        })
    }

    /// Says whether the mount's negotiated data-caching mode is direct.
    ///
    /// Called once, from the FUSE handshake, with the *resolved* mode. Until
    /// then — and for ever on a page-cached mount — every read goes straight to
    /// the wire and the pool stays empty.
    pub fn activate(&self, direct: bool) {
        self.active.store(direct, Ordering::Relaxed);
    }

    /// Whether the engine is running: direct caching, and a pool to run in.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.budget >= CHUNK_BYTES && self.active.load(Ordering::Relaxed)
    }

    /// The pool ceiling in bytes.
    #[must_use]
    pub fn budget(&self) -> usize {
        self.budget
    }

    /// What the engine is holding and what it has done, for tests.
    #[must_use]
    pub fn stats(&self) -> ReadaheadStats {
        let state = self.lock();
        ReadaheadStats {
            ready_bytes: state.ready,
            reserved_bytes: state.reserved,
            blocks: state
                .files
                .values()
                .map(|file| {
                    file.blocks
                        .values()
                        .filter(|slot| matches!(slot, Slot::Ready(_)))
                        .count()
                })
                .sum(),
            inflight: state.inflight,
            handles: state.handles.len(),
            issued: self.counters.issued.load(Ordering::Relaxed),
            discarded: self.counters.discarded.load(Ordering::Relaxed),
            hit_bytes: self.counters.hit_bytes.load(Ordering::Relaxed),
            wire_bytes: self.counters.wire_bytes.load(Ordering::Relaxed),
        }
    }

    /// Answers one kernel read, from the pool where it can and from the wire
    /// where it cannot.
    ///
    /// A short answer means end of file, exactly as the wire read it replaces
    /// does.
    ///
    /// # Errors
    ///
    /// Whatever the server answered the wire reads with, or `EIO` on a degraded
    /// mount.
    pub async fn read(
        self: &Arc<Self>,
        client: &Arc<Client>,
        caller: Caller,
        node: u64,
        handle: u64,
        offset: u64,
        size: u32,
    ) -> Result<ReadData, Errno> {
        if !self.is_active() {
            return wire_read(client, caller, node, handle, offset, size as usize)
                .await
                .map(ReadData::Owned);
        }
        // The session behind every block in the pool is the one that fetched
        // them. A reconnect installs another, whose handle ids name nothing the
        // old one knew, so the pool goes with it — checked here, on the path
        // that would otherwise serve a stale block.
        self.observe(client.connected_generation());

        self.advance(node, handle, offset, size as usize);
        self.top_up(client, caller, handle);

        // The common case of a sequential reader in flight: one block covers
        // the whole request, and it is answered **without copying it**. At the
        // rates the engine reaches, a 128 KiB memcpy per read is a measurable
        // share of what a read costs, and the kernel is about to copy these
        // bytes out of the reply anyway.
        let mut planned = Some(self.plan(node, offset, size as usize));
        if let Some(Step::Serve { block, from, to }) = &planned
            && to - from == size as usize
        {
            let (block, from, to) = (Arc::clone(block), *from, *to);
            self.counters
                .hit_bytes
                .fetch_add(u64::from(size), Ordering::Relaxed);
            self.top_up(client, caller, handle);
            return Ok(ReadData::Block { block, from, to });
        }

        let mut data: Vec<u8> = Vec::with_capacity(size as usize);
        let mut awaited: Option<u64> = None;
        while data.len() < size as usize {
            let position = offset + data.len() as u64;
            let remaining = size as usize - data.len();
            let step = match planned.take() {
                Some(step) => step,
                None => self.plan(node, position, remaining),
            };
            match step {
                Step::Serve { block, from, to } => {
                    data.extend_from_slice(&block[from..to]);
                    self.counters
                        .hit_bytes
                        .fetch_add((to - from) as u64, Ordering::Relaxed);
                }
                // A chunk this read needs is already on the wire: waiting for
                // it is the whole point of having issued it. Each chunk is
                // waited for at most once, so a slot that is re-issued behind
                // the reader cannot spin it.
                Step::Wait {
                    chunk, mut ready, ..
                } if awaited != Some(chunk) => {
                    awaited = Some(chunk);
                    let _ = ready.changed().await;
                }
                Step::Wait { len: span, .. } | Step::Wire { len: span } => {
                    let fetched = wire_read(client, caller, node, handle, position, span).await?;
                    self.counters
                        .wire_bytes
                        .fetch_add(fetched.len() as u64, Ordering::Relaxed);
                    let short = fetched.len() < span;
                    data.extend_from_slice(&fetched);
                    if short {
                        // A short wire read is end of file, and it is where
                        // this read stops.
                        self.mark_eof(handle, position + fetched.len() as u64);
                        break;
                    }
                }
            }
        }
        // Deliveries that landed while this read was being served may have
        // freed both budget and in-flight slots.
        self.top_up(client, caller, handle);
        Ok(ReadData::Owned(data))
    }

    /// Drops a file's blocks, because something changed them underneath.
    ///
    /// The epoch bump is what makes it complete: a prefetch already on the wire
    /// carries the old epoch and is discarded when it lands, so no pre-change
    /// byte can be inserted behind the change.
    pub fn invalidate(&self, node: u64) {
        if !self.is_active() {
            return;
        }
        let mut state = self.lock();
        let epoch = state.take_epoch();
        let released = state
            .files
            .get_mut(&node)
            .map(|file| {
                file.epoch = epoch;
                drain(&mut file.blocks)
            })
            .unwrap_or_default();
        state.ready -= released;
        for window in state.handles.values_mut() {
            if window.node == node {
                window.issued_to = floor(window.next_offset);
            }
        }
    }

    /// Closes a handle's window: nothing more is issued for it, its blocks are
    /// freed where no other handle is reading the file, and the replies of
    /// chunks already on the wire are discarded when they land.
    pub fn close(&self, handle: u64) {
        if !self.is_active() {
            return;
        }
        let mut state = self.lock();
        let Some(window) = state.handles.remove(&handle) else {
            return;
        };
        if state
            .handles
            .values()
            .any(|other| other.node == window.node)
        {
            return;
        }
        let epoch = state.take_epoch();
        let released = state
            .files
            .get_mut(&window.node)
            .map(|file| {
                file.epoch = epoch;
                drain(&mut file.blocks)
            })
            .unwrap_or_default();
        state.ready -= released;
        state.files.remove(&window.node);
    }

    /// Drops everything the pool holds, whatever it holds it for.
    ///
    /// The reconnect path and the teardown path both come here.
    pub fn clear(&self) {
        let mut state = self.lock();
        state.forget_everything();
    }

    /// Notices a connection generation change and drops the pool over it.
    fn observe(&self, generation: Option<u64>) {
        let mut state = self.lock();
        if state.generation == generation {
            return;
        }
        if state.generation.is_some() {
            tracing::debug!("the readahead pool is dropped: the session behind it ended");
        }
        state.forget_everything();
        state.generation = generation;
    }

    /// Updates the handle's detector and window for a read that is about to be
    /// served.
    fn advance(&self, node: u64, handle: u64, offset: u64, size: usize) {
        let mut state = self.lock();
        let window = state
            .handles
            .entry(handle)
            .or_insert_with(|| Window::fresh(node, offset));
        if window.node != node {
            *window = Window::fresh(node, offset);
        }
        if window.served && offset == window.next_offset {
            if window.chunks == 0 {
                // Two consecutive reads at the expected offset: this is a
                // sequential reader, and the window opens.
                window.chunks = INITIAL_WINDOW_CHUNKS;
            } else {
                // The pace rule: the reader keeps up when one read consumes at
                // least half of what has been fetched but not yet read, and a
                // reader that keeps up is given twice the coverage.
                let unread = window.issued_to.saturating_sub(offset);
                if size as u64 >= unread / 2 {
                    window.chunks = (window.chunks * 2).min(MAX_WINDOW_CHUNKS);
                }
            }
        } else {
            // A seek. The window closes and the detector starts again from
            // here; blocks the old position left behind stay in the pool until
            // they are read, expire, or are pushed out by the ceiling.
            window.chunks = 0;
            window.issued_to = floor(offset);
            window.eof = None;
        }
        window.next_offset = offset + size as u64;
        window.served = true;
    }

    /// Records where the file ended, so nothing is issued past it.
    fn mark_eof(&self, handle: u64, at: u64) {
        let mut state = self.lock();
        if let Some(window) = state.handles.get_mut(&handle) {
            window.eof = Some(window.eof.map_or(at, |known| known.min(at)));
            window.chunks = 0;
        }
    }

    /// What the next slice of a read comes from.
    fn plan(&self, node: u64, position: u64, remaining: usize) -> Step {
        let chunk = position / CHUNK_BYTES as u64;
        let within = (position % CHUNK_BYTES as u64) as usize;
        let want = remaining.min(CHUNK_BYTES - within);
        let mut state = self.lock();
        let ready = state.attr_ttl_floor(self.attr_ttl);
        let Some(file) = state.files.get_mut(&node) else {
            return Step::Wire { len: remaining };
        };
        // A run of chunks the pool has nothing for is **one** wire read, not one
        // per chunk. The grid is the pool's addressing, not a limit on how much
        // may be asked for at once, and splitting a 1 MiB miss into eight round
        // trips would make the engine slower than no engine on exactly the reads
        // it cannot help with.
        if !file.blocks.contains_key(&chunk) {
            return Step::Wire {
                len: missing_span(file, position, remaining),
            };
        }
        match file.blocks.get_mut(&chunk) {
            Some(Slot::Pending(gate)) => Step::Wait {
                chunk,
                ready: gate.subscribe(),
                len: want,
            },
            Some(Slot::Ready(block)) => {
                // A block older than the attr TTL is dropped, not
                // served: that bound is what the coherence criterion rests on.
                if block.fetched < ready {
                    let released = block.data.len();
                    file.blocks.remove(&chunk);
                    state.ready -= released;
                    return Step::Wire { len: want };
                }
                let take = want.min(block.data.len().saturating_sub(within));
                if take == 0 || !block.take(within, within + take) {
                    return Step::Wire { len: want };
                }
                let data = Arc::clone(&block.data);
                if block.is_consumed() {
                    let released = block.data.len();
                    file.blocks.remove(&chunk);
                    state.ready -= released;
                }
                Step::Serve {
                    block: data,
                    from: within,
                    to: within + take,
                }
            }
            // Handled above: the slot is present, so one of the two arms took
            // it.
            None => Step::Wire { len: want },
        }
    }

    /// Issues as much of the handle's window as the caps and the pool allow.
    fn top_up(self: &Arc<Self>, client: &Arc<Client>, caller: Caller, handle: u64) {
        let issues = self.reserve(handle);
        for issue in issues {
            let engine = Arc::clone(self);
            let client = Arc::clone(client);
            tokio::spawn(async move { fetch(engine, client, caller, issue).await });
        }
    }

    /// Reserves pool budget and in-flight slots for the chunks a window still
    /// wants, and describes the reads to make.
    ///
    /// Reserving here — before anything is written to the wire — is what stops
    /// arrivals from overshooting the ceiling.
    fn reserve(&self, handle: u64) -> Vec<Issue> {
        let mut state = self.lock();
        let Some(window) = state.handles.get(&handle) else {
            return Vec::new();
        };
        if window.chunks == 0 {
            return Vec::new();
        }
        let (node, chunks, eof) = (window.node, window.chunks, window.eof);
        // **On the grid, always.** A block is addressed by its chunk index and
        // read out at `offset % CHUNK_BYTES`, so a fetch that began anywhere but
        // a chunk boundary would be filed under an index whose bytes it does not
        // hold — and served, silently shifted. A window opens wherever the
        // reader happens to be (an ELF loader's second read lands at offset 64),
        // so the alignment is imposed here, not assumed.
        let mut issued_to = floor(window.issued_to.max(floor(window.next_offset)));
        let mut handle_inflight = window.inflight;
        // The window covers `chunks` beyond where the reader will be next, and
        // never past a known end of file.
        let mut end = floor(window.next_offset) + (chunks * CHUNK_BYTES) as u64;
        if let Some(eof) = eof {
            end = end.min(eof);
        }
        let generation = state.generation;
        let epoch = state.epoch_of(node);
        let mut issues = Vec::new();
        while issued_to < end
            && handle_inflight < MAX_INFLIGHT_PER_HANDLE
            && state.inflight < MAX_INFLIGHT_PER_MOUNT
            && state.ready + state.reserved + CHUNK_BYTES <= self.budget
        {
            let chunk = issued_to / CHUNK_BYTES as u64;
            let file = state.files.entry(node).or_insert_with(|| FileBlocks {
                epoch,
                blocks: BTreeMap::new(),
            });
            if file.blocks.contains_key(&chunk) {
                issued_to += CHUNK_BYTES as u64;
                continue;
            }
            let (gate, _) = watch::channel(());
            file.blocks.insert(chunk, Slot::Pending(gate));
            state.reserved += CHUNK_BYTES;
            state.inflight += 1;
            handle_inflight += 1;
            issues.push(Issue {
                node,
                handle,
                offset: issued_to,
                epoch,
                generation,
            });
            issued_to += CHUNK_BYTES as u64;
        }
        if let Some(window) = state.handles.get_mut(&handle) {
            window.issued_to = issued_to;
            window.inflight = handle_inflight;
        }
        self.counters
            .issued
            .fetch_add(issues.len() as u64, Ordering::Relaxed);
        issues
    }

    /// Releases what an issued prefetch reserved, whatever became of it.
    fn release(&self, state: &mut MutexGuard<'_, Engine>, issue: &Issue) {
        state.reserved -= CHUNK_BYTES;
        state.inflight -= 1;
        if let Some(window) = state.handles.get_mut(&issue.handle) {
            window.inflight = window.inflight.saturating_sub(1);
        }
    }

    /// Takes a delivered prefetch into the pool, or discards it.
    ///
    /// It is discarded when the handle it was issued for has closed, when the
    /// file changed underneath it, or when the session that fetched it died —
    /// the three ways a reply can outlive what asked for it.
    fn deliver(&self, issue: &Issue, data: Vec<u8>, eof: bool) {
        let mut state = self.lock();
        self.release(&mut state, issue);
        let chunk = issue.offset / CHUNK_BYTES as u64;
        let live = state.generation == issue.generation
            && state.handles.contains_key(&issue.handle)
            && state.epoch_matches(issue.node, issue.epoch);
        if !live {
            self.counters.discarded.fetch_add(1, Ordering::Relaxed);
            state.abandon(issue.node, issue.epoch, chunk);
            return;
        }
        if eof && let Some(window) = state.handles.get_mut(&issue.handle) {
            let end = issue.offset + data.len() as u64;
            window.eof = Some(window.eof.map_or(end, |known| known.min(end)));
        }
        let Some(file) = state.files.get_mut(&issue.node) else {
            return;
        };
        if data.is_empty() {
            file.blocks.remove(&chunk);
            return;
        }
        let length = data.len();
        file.blocks.insert(chunk, Slot::Ready(Block::new(data)));
        state.ready += length;
    }

    /// Gives up on an issued prefetch: the read failed, or the task carrying it
    /// was dropped.
    fn abandon(&self, issue: &Issue) {
        let mut state = self.lock();
        self.release(&mut state, issue);
        state.abandon(issue.node, issue.epoch, issue.offset / CHUNK_BYTES as u64);
    }

    /// Closes a handle's window without touching its blocks.
    ///
    /// What a failed prefetch does: a degraded mount's error stops the engine
    /// asking for more, and the reader's own reads meet the resilience
    /// contract's surface unchanged.
    fn stop(&self, handle: u64) {
        let mut state = self.lock();
        if let Some(window) = state.handles.get_mut(&handle) {
            window.chunks = 0;
            window.issued_to = floor(window.next_offset);
        }
    }

    fn lock(&self) -> MutexGuard<'_, Engine> {
        self.state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }
}

impl Engine {
    /// The next file epoch.
    fn take_epoch(&mut self) -> u64 {
        self.next_epoch += 1;
        self.next_epoch
    }

    /// The epoch a file's blocks are under, allocating one for a file the pool
    /// has never held a block of.
    fn epoch_of(&mut self, node: u64) -> u64 {
        match self.files.get(&node) {
            Some(file) => file.epoch,
            None => self.take_epoch(),
        }
    }

    /// Whether `epoch` is still the epoch of `node`'s blocks.
    fn epoch_matches(&self, node: u64, epoch: u64) -> bool {
        self.files
            .get(&node)
            .is_some_and(|file| file.epoch == epoch)
    }

    /// Removes a pending slot that will never be filled — but only while it is
    /// still the slot the fetch was issued for.
    fn abandon(&mut self, node: u64, epoch: u64, chunk: u64) {
        if let Some(file) = self.files.get_mut(&node)
            && file.epoch == epoch
        {
            file.blocks.remove(&chunk);
        }
    }

    /// The oldest fetch time a block may carry and still be served.
    fn attr_ttl_floor(&self, attr_ttl: Duration) -> Instant {
        Instant::now()
            .checked_sub(attr_ttl)
            .unwrap_or_else(|| Instant::now() - Duration::ZERO)
    }

    /// Drops every block and every window.
    ///
    /// Reservations are left standing: the fetches holding them are still on
    /// the wire and will release them when they land, and their epochs no
    /// longer match anything, so their bytes are discarded, not
    /// inserted.
    fn forget_everything(&mut self) {
        self.files.clear();
        self.handles.clear();
        self.ready = 0;
    }
}

/// The bytes one read is answered with.
///
/// Two shapes, because the fast path deserves not to pay for the general one: a
/// read the pool covers with a single block is handed that block's bytes as
/// they lie, and everything else — a straddle, a miss, a mixture — is assembled
/// into a buffer of its own.
#[derive(Clone, Debug)]
pub enum ReadData {
    /// Bytes assembled for this read.
    Owned(Vec<u8>),
    /// A range of one pooled block, answered without copying it.
    Block {
        /// The block the bytes live in.
        block: Arc<[u8]>,
        /// Where the answer starts in it.
        from: usize,
        /// Where it ends.
        to: usize,
    },
}

impl ReadData {
    /// The bytes, as the reply writes them.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        match self {
            Self::Owned(data) => data,
            Self::Block { block, from, to } => &block[*from..*to],
        }
    }

    /// How many bytes the read answered with. A short answer is end of file.
    #[must_use]
    pub fn len(&self) -> usize {
        self.as_slice().len()
    }

    /// Whether the read answered with nothing at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// What the next slice of a read comes from.
#[derive(Debug)]
enum Step {
    /// The pool has it: these bytes, already claimed.
    Serve {
        block: Arc<[u8]>,
        from: usize,
        to: usize,
    },
    /// A prefetch is on the wire for it.
    Wait {
        chunk: u64,
        ready: watch::Receiver<()>,
        /// What to read from the server instead, for a caller that has already
        /// waited for this chunk once.
        len: usize,
    },
    /// Nothing has it: read this many bytes from the server.
    Wire { len: usize },
}

/// Empties a block map, reporting how many delivered bytes went with it.
fn drain(blocks: &mut BTreeMap<u64, Slot>) -> usize {
    let released = blocks
        .values()
        .map(|slot| match slot {
            Slot::Ready(block) => block.data.len(),
            Slot::Pending(_) => 0,
        })
        .sum();
    blocks.clear();
    released
}

/// How much of a read, from `position`, the pool has nothing at all for.
///
/// It runs forward over whole chunks while the grid is empty, so a read the
/// engine cannot help with costs the round trips it would have cost without the
/// engine — one, in the ordinary case — not one per chunk.
fn missing_span(file: &FileBlocks, position: u64, remaining: usize) -> usize {
    let mut span = remaining.min(CHUNK_BYTES - (position % CHUNK_BYTES as u64) as usize);
    let mut chunk = position / CHUNK_BYTES as u64 + 1;
    while span < remaining && !file.blocks.contains_key(&chunk) {
        span = remaining.min(span + CHUNK_BYTES);
        chunk += 1;
    }
    span
}

/// The start of the chunk an offset falls in.
fn floor(offset: u64) -> u64 {
    offset - offset % CHUNK_BYTES as u64
}

/// Runs one prefetch read and hands the engine what it got.
///
/// Ordinary reads on an ordinary handle: the wire cannot tell these from the
/// guest's own, which is what "no wire change" means in practice. A failure
/// closes the window — a degraded mount is not asked to prefetch — and releases
/// what the issue reserved.
async fn fetch(engine: Arc<Readahead>, client: Arc<Client>, caller: Caller, issue: Issue) {
    let mut data: Vec<u8> = Vec::with_capacity(CHUNK_BYTES);
    while data.len() < CHUNK_BYTES {
        let want = CHUNK_BYTES - data.len();
        let offset = issue.offset + data.len() as u64;
        match wire_read(&client, caller, issue.node, issue.handle, offset, want).await {
            Ok(read) if read.is_empty() => break,
            Ok(read) => data.extend_from_slice(&read),
            Err(error) => {
                tracing::debug!(%error, "a prefetch read failed; the window closes");
                engine.abandon(&issue);
                engine.stop(issue.handle);
                return;
            }
        }
    }
    let eof = data.len() < CHUNK_BYTES;
    engine.deliver(&issue, data, eof);
    // An arrival frees an in-flight slot and turns a reservation into bytes, so
    // this is where the next chunk of the window can go out. Without it the
    // window would only refill when the reader came back for more, and the wire
    // would idle for exactly as long as it takes to hand one read to the
    // kernel. Bounded by the same caps as any other top-up.
    engine.top_up(&client, caller, issue.handle);
}

/// Reads from the server, looping until the request is satisfied.
///
/// A wire read is bounded by the negotiated frame length, and a short answer
/// means end of file — so the difference is made up here instead of handed to
/// the caller as a short read that was not one.
async fn wire_read(
    client: &Arc<Client>,
    caller: Caller,
    node: u64,
    handle: u64,
    offset: u64,
    size: usize,
) -> Result<Vec<u8>, Errno> {
    let mut data: Vec<u8> = Vec::with_capacity(size);
    while data.len() < size {
        let chunk = client.read_chunk() as usize;
        let want = chunk.min(size - data.len());
        let read = client
            .read(
                caller,
                node,
                handle,
                offset + data.len() as u64,
                want as u32,
            )
            .await?;
        if read.is_empty() {
            break;
        }
        data.extend_from_slice(&read);
    }
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An engine with a pool, told the mount negotiated direct caching.
    fn engine(budget: usize) -> Arc<Readahead> {
        let engine = Readahead::new(budget, Duration::from_secs(1));
        engine.activate(true);
        engine
    }

    #[test]
    fn the_engine_runs_only_in_direct_mode_and_only_with_a_pool() {
        let page = Readahead::new(DEFAULT_POOL_BYTES, Duration::from_secs(1));
        assert!(
            !page.is_active(),
            "a mount is page-cached until the handshake says otherwise"
        );
        page.activate(true);
        assert!(page.is_active());
        page.activate(false);
        assert!(
            !page.is_active(),
            "a kernel without the mmap capability keeps the flag and falls back \
             to page caching, where the engine must not run"
        );

        let disabled = Readahead::new(0, Duration::from_secs(1));
        disabled.activate(true);
        assert!(!disabled.is_active(), "--readahead 0 disables the engine");
    }

    #[test]
    fn a_byte_is_served_once_and_a_consumed_block_is_dropped() {
        let mut block = Block::new(vec![7u8; 100]);
        assert!(block.take(0, 40));
        assert!(!block.is_consumed());
        assert!(
            !block.take(30, 50),
            "a range overlapping served bytes is not served again"
        );
        assert!(block.take(40, 100));
        assert!(block.is_consumed(), "a fully consumed block is dropped");
        assert!(!block.take(0, 1), "and nothing is left to serve");

        // Holes are tracked, not rounded away: taking from the middle leaves
        // both sides servable and neither side servable twice.
        let mut holed = Block::new(vec![0u8; 100]);
        assert!(holed.take(40, 60));
        assert!(holed.take(0, 40));
        assert!(!holed.take(50, 70));
        assert!(holed.take(60, 100));
        assert!(holed.is_consumed());
    }

    #[test]
    fn an_idle_mount_holds_nothing() {
        let engine = engine(DEFAULT_POOL_BYTES);
        let stats = engine.stats();
        assert_eq!(stats.pool_bytes(), 0);
        assert_eq!(stats.blocks, 0);
        assert_eq!(stats.inflight, 0);
        assert_eq!(stats.issued, 0);
    }

    /// The reservation is the cap's mechanism: the pool cannot overshoot,
    /// because the budget is taken before the read is written, not when it
    /// arrives.
    #[test]
    fn issuing_reserves_and_the_ceiling_is_never_crossed() {
        // Room for exactly three chunks.
        let engine = engine(3 * CHUNK_BYTES + 1);
        engine.advance(1, 10, 0, CHUNK_BYTES);
        engine.advance(1, 10, CHUNK_BYTES as u64, CHUNK_BYTES);
        let issues = engine.reserve(10);
        assert_eq!(issues.len(), 3, "the ceiling stops the fourth chunk");
        let stats = engine.stats();
        assert_eq!(stats.reserved_bytes, 3 * CHUNK_BYTES);
        assert!(stats.pool_bytes() <= engine.budget());
        assert_eq!(stats.inflight, 3);

        // A full pool idles the prefetcher instead of evicting.
        assert!(engine.reserve(10).is_empty());

        // Delivering trades the reservation for the bytes themselves; the total
        // never rises above the ceiling.
        engine.deliver(&issues[0], vec![0u8; CHUNK_BYTES], false);
        let stats = engine.stats();
        assert_eq!(stats.ready_bytes, CHUNK_BYTES);
        assert_eq!(stats.reserved_bytes, 2 * CHUNK_BYTES);
        assert!(stats.pool_bytes() <= engine.budget());
        assert_eq!(stats.inflight, 2);
    }

    /// The window opens on the second consecutive read, doubles while the
    /// reader keeps pace, stops at the coverage cap, and closes on a seek.
    #[test]
    fn the_detector_opens_doubles_and_resets() {
        let engine = engine(DEFAULT_POOL_BYTES);
        let read = |offset: u64| engine.advance(1, 10, offset, CHUNK_BYTES);
        // Read out of the engine and let the lock go before the next call: the
        // guard would otherwise still be alive inside `advance`.
        let chunks = || engine.lock().handles[&10].chunks;
        let next = || engine.lock().handles[&10].next_offset;

        read(0);
        assert_eq!(chunks(), 0, "one read is not a run");
        read(CHUNK_BYTES as u64);
        assert_eq!(
            chunks(),
            INITIAL_WINDOW_CHUNKS,
            "two consecutive reads open the window"
        );
        // Nothing was issued, so nothing is unread: a reader with nothing ahead
        // of it is keeping pace by definition.
        for expected in [8, 16, 32, 32] {
            let position = next();
            read(position);
            assert_eq!(chunks(), expected);
        }
        assert_eq!(
            MAX_WINDOW_CHUNKS * CHUNK_BYTES,
            4 * 1024 * 1024,
            "the coverage cap is 4 MiB"
        );

        // A seek closes the window and the detector starts again.
        read(9_000_000);
        assert_eq!(chunks(), 0);
        assert_eq!(
            engine.lock().handles[&10].issued_to,
            floor(9_000_000),
            "the window starts again from the reader's chunk, on the grid"
        );
    }

    /// Every prefetch starts on a chunk boundary, wherever the reader was when
    /// the window opened.
    ///
    /// The regression this pins is not theoretical: an ELF loader reads 256
    /// bytes at 0, the program headers at 64, and the interpreter name straight
    /// after them — so the window opens at an offset like 848. A fetch issued
    /// from there would be filed under chunk 0 while holding the bytes from 64
    /// onwards, and the next reader of chunk 0 would be handed data shifted by
    /// 64 bytes. It cost an unexecutable binary to find; it costs one assertion
    /// to keep.
    #[test]
    fn every_prefetch_starts_on_the_grid_however_the_window_opened() {
        let engine = engine(DEFAULT_POOL_BYTES);
        // The loader's shape, verbatim: a header read, a seek to the program
        // headers, and then a read that continues from exactly where that one
        // ended — which is what opens the window.
        engine.advance(1, 10, 0, 256);
        engine.advance(1, 10, 64, 784);
        engine.advance(1, 10, 848, 83);
        let issues = engine.reserve(10);
        assert!(
            !issues.is_empty(),
            "the window opened, so it asks for chunks"
        );
        for issue in &issues {
            assert_eq!(
                issue.offset % CHUNK_BYTES as u64,
                0,
                "a prefetch from {} is not on the 128 KiB grid",
                issue.offset
            );
        }
        assert_eq!(issues[0].offset, 0, "and it starts at the reader's chunk");

        // The block it delivers is read back at the offset it was fetched from.
        engine.deliver(&issues[0], pattern_block(0), false);
        let Step::Serve { block, from, to } = engine.plan(1, 848, 83) else {
            panic!("the block covering 848 is in the pool");
        };
        assert_eq!(
            &block[from..to],
            &pattern_block(0)[848..931],
            "the pool answered with bytes from the wrong file offset"
        );
    }

    /// A block of bytes that say where in the file they came from.
    fn pattern_block(start: u64) -> Vec<u8> {
        (0..CHUNK_BYTES)
            .map(|index| ((start as usize + index) % 251) as u8)
            .collect()
    }

    /// The in-flight caps bound both one handle and the mount, which is what
    /// bounds the engine's share of the server's reply queue.
    #[test]
    fn the_in_flight_caps_bound_the_handle_and_the_mount() {
        let engine = engine(DEFAULT_POOL_BYTES);
        for handle in [10, 11, 12] {
            engine.advance(handle, handle, 0, CHUNK_BYTES);
            engine.advance(handle, handle, CHUNK_BYTES as u64, CHUNK_BYTES);
            // A window wide enough to want more than the caps allow.
            engine.lock().handles.get_mut(&handle).unwrap().chunks = MAX_WINDOW_CHUNKS;
        }
        assert_eq!(engine.reserve(10).len(), MAX_INFLIGHT_PER_HANDLE);
        assert_eq!(engine.reserve(11).len(), MAX_INFLIGHT_PER_HANDLE);
        assert!(
            engine.reserve(12).is_empty(),
            "the mount's cap holds once its handles have filled it"
        );
        assert_eq!(engine.stats().inflight, MAX_INFLIGHT_PER_MOUNT);
    }

    /// The blocks a write invalidates go at once, and the prefetch that was
    /// already on the wire is discarded, not inserted behind the change.
    #[test]
    fn a_write_drops_the_blocks_and_the_replies_in_flight() {
        let engine = engine(DEFAULT_POOL_BYTES);
        engine.advance(1, 10, 0, CHUNK_BYTES);
        engine.advance(1, 10, CHUNK_BYTES as u64, CHUNK_BYTES);
        let issues = engine.reserve(10);
        assert!(!issues.is_empty());
        engine.deliver(&issues[0], vec![0u8; CHUNK_BYTES], false);
        assert_eq!(engine.stats().ready_bytes, CHUNK_BYTES);

        engine.invalidate(1);
        assert_eq!(engine.stats().ready_bytes, 0, "the file's blocks are gone");

        engine.deliver(&issues[1], vec![0u8; CHUNK_BYTES], false);
        assert_eq!(
            engine.stats().ready_bytes,
            0,
            "a reply read before the write is not inserted after it"
        );
        assert_eq!(engine.stats().discarded, 1);
        assert_eq!(
            engine.stats().reserved_bytes,
            (issues.len() - 2) * CHUNK_BYTES
        );
    }

    /// Closing a handle stops the engine issuing for it, frees its blocks, and
    /// discards whatever was already on the wire.
    #[test]
    fn closing_a_handle_stops_issuing_and_discards_what_is_in_flight() {
        let engine = engine(DEFAULT_POOL_BYTES);
        engine.advance(1, 10, 0, CHUNK_BYTES);
        engine.advance(1, 10, CHUNK_BYTES as u64, CHUNK_BYTES);
        let issues = engine.reserve(10);
        engine.deliver(&issues[0], vec![0u8; CHUNK_BYTES], false);
        let issued = engine.stats().issued;

        engine.close(10);
        assert_eq!(engine.stats().ready_bytes, 0, "its blocks are freed");
        assert_eq!(engine.stats().handles, 0);
        assert!(
            engine.reserve(10).is_empty(),
            "nothing is issued for a closed handle"
        );
        assert_eq!(engine.stats().issued, issued, "and the counter proves it");

        engine.deliver(&issues[1], vec![0u8; CHUNK_BYTES], false);
        assert_eq!(engine.stats().ready_bytes, 0);
        assert_eq!(engine.stats().discarded, 1);
    }

    /// A reconnect drops the pool entirely, and a block fetched under the dead
    /// session is never served afterwards.
    #[test]
    fn a_reconnect_drops_the_pool_and_never_serves_across_it() {
        let engine = engine(DEFAULT_POOL_BYTES);
        engine.observe(Some(1));
        engine.advance(1, 10, 0, CHUNK_BYTES);
        engine.advance(1, 10, CHUNK_BYTES as u64, CHUNK_BYTES);
        let issues = engine.reserve(10);
        engine.deliver(&issues[0], vec![b'o'; CHUNK_BYTES], false);
        assert_eq!(engine.stats().blocks, 1);

        engine.observe(Some(2));
        let stats = engine.stats();
        assert_eq!(stats.ready_bytes, 0);
        assert_eq!(stats.blocks, 0);
        assert_eq!(stats.handles, 0, "and every window resets");
        assert!(matches!(engine.plan(1, 0, CHUNK_BYTES), Step::Wire { .. }));

        // The replies of the dead session's reads are discarded when they land.
        engine.deliver(&issues[1], vec![b'o'; CHUNK_BYTES], false);
        assert_eq!(engine.stats().ready_bytes, 0);
        assert_eq!(engine.stats().discarded, 1);
    }

    /// A block older than the mount's attr TTL is dropped instead of served:
    /// the mechanism the coherence bound rests on.
    #[test]
    fn a_block_older_than_the_attr_ttl_is_dropped_rather_than_served() {
        let engine = Readahead::new(DEFAULT_POOL_BYTES, Duration::from_millis(30));
        engine.activate(true);
        engine.advance(1, 10, 0, CHUNK_BYTES);
        engine.advance(1, 10, CHUNK_BYTES as u64, CHUNK_BYTES);
        let issues = engine.reserve(10);
        engine.deliver(&issues[0], vec![b'x'; CHUNK_BYTES], false);
        assert!(matches!(
            engine.plan(1, issues[0].offset, 4096),
            Step::Serve { .. }
        ));

        engine.deliver(&issues[1], vec![b'x'; CHUNK_BYTES], false);
        assert_eq!(engine.stats().blocks, 2);
        std::thread::sleep(Duration::from_millis(60));
        for issue in &issues[..2] {
            assert!(
                matches!(engine.plan(1, issue.offset, 4096), Step::Wire { .. }),
                "a block past the TTL is not served"
            );
        }
        assert_eq!(engine.stats().ready_bytes, 0, "they are dropped, not kept");
        assert_eq!(engine.stats().blocks, 0);
    }

    /// A read straddling two blocks is answered by copying across them, one
    /// slice per pass, and every byte leaves the pool exactly once.
    #[test]
    fn a_straddling_read_is_served_across_blocks() {
        let engine = engine(DEFAULT_POOL_BYTES);
        engine.advance(1, 10, 0, CHUNK_BYTES);
        engine.advance(1, 10, CHUNK_BYTES as u64, CHUNK_BYTES);
        let issues = engine.reserve(10);
        engine.deliver(&issues[0], vec![b'a'; CHUNK_BYTES], false);
        engine.deliver(&issues[1], vec![b'b'; CHUNK_BYTES], false);

        // A read of the last 4 KiB of one chunk and the first 4 KiB of the
        // next, planned as the serve loop plans it.
        assert_eq!(issues[1].offset, issues[0].offset + CHUNK_BYTES as u64);
        let position = issues[1].offset - 4096;
        let Step::Serve { block, from, to } = engine.plan(1, position, 8192) else {
            panic!("the first half comes from the first block");
        };
        assert_eq!(&block[from..to], vec![b'a'; 4096].as_slice());
        let Step::Serve { block, from, to } = engine.plan(1, position + 4096, 4096) else {
            panic!("the second half comes from the next block");
        };
        assert_eq!(&block[from..to], vec![b'b'; 4096].as_slice());

        // Both blocks are partly consumed and still held; the served bytes are
        // not served again.
        assert!(matches!(
            engine.plan(1, position, 4096),
            Step::Wire { len: 4096 }
        ));
        assert_eq!(engine.stats().blocks, 2);
    }

    /// The pool holds nothing for a mount that never enters direct mode, and a
    /// page-cached mount's reads never touch the engine's state.
    #[test]
    fn a_page_cached_mount_holds_nothing() {
        let engine = Readahead::new(DEFAULT_POOL_BYTES, Duration::from_secs(1));
        engine.invalidate(1);
        engine.close(10);
        assert_eq!(engine.stats(), ReadaheadStats::default());
    }
}
