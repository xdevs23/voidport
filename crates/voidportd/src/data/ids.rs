//! Generation-disjoint node and handle ids.
//!
//! A mount that survives its server being restarted holds ids the kernel took
//! from the *previous* session — a cached directory node, an open descriptor's
//! handle. With plain per-session counters those ids are handed out again by the
//! new session, so a stale id silently names a **different file**, and a read
//! through it returns the wrong bytes. The reconnect spec review demonstrated
//! exactly that end to end, which is why ids are allocated here instead of from
//! a bare counter per table.
//!
//! The rule the design pins: **no node or handle id is ever reused across
//! sessions of one server lifetime, or across server restarts.** The single
//! eternal exemption is node id 1, the mount root, which every session names
//! and which this allocator therefore never hands out.
//!
//! ## The layout
//!
//! An id is a generation joined to a counter:
//!
//! ```text
//!  63                              24 23             0
//! ┌──────────────────────────────────┬────────────────┐
//! │ generation (40 bits)             │ counter (24)   │
//! └──────────────────────────────────┴────────────────┘
//! ```
//!
//! * the **counter** is per generation, starts at 1 and only moves forward;
//! * the **generation** comes from one process-wide monotonic counter
//!   ([`GENERATIONS`]), which every server raises at startup to a coarse
//!   wall-clock epoch. A table takes a generation when it is created, and takes
//!   another if it ever exhausts its counter — so no table is ever forced to
//!   reuse a number.
//!
//! Because a generation is never zero and a counter is never zero, the smallest
//! id this allocator can produce is `1 << 24`. Node id 1 is therefore
//! unreachable by construction, not by a special case.
//!
//! ## Why this cannot collide (the reasoning, stated once)
//!
//! * **Two sessions of one server.** Their generations come from one monotonic
//!   counter, so they differ; two ids with different generations differ. This
//!   is absolute, not probabilistic.
//! * **Two lifetimes inside one process.** They draw from that *same* counter:
//!   [`GENERATIONS`] is process-wide, so a server built while another one's ids
//!   are still held — which is what an in-process restart under a live mount
//!   is — can only ever take numbers the other one did not. No timing
//!   assumption is involved. A per-server counter merely *floored* at
//!   construction would not do: two servers built inside one millisecond read
//!   the same floor before either allocates and then hand out the same
//!   generations, which is a collision, not a race
//!   (`two_servers_built_before_either_allocates_still_share_no_id` is that
//!   case as a test).
//! * **Two lifetimes in two processes.** The later one seeds from [`epoch`],
//!   the startup time in milliseconds scaled by [`GENERATIONS_PER_TICK`]. For
//!   its range to re-enter the earlier one's, the earlier server would have had
//!   to consume more than [`GENERATIONS_PER_TICK`] generations per millisecond
//!   of its uptime, sustained — 256,000 mounts (or counter exhaustions) per
//!   second, several orders of magnitude beyond what a FUSE mount plus a
//!   handshake per session can reach.
//! * **The epoch wrapping.** Only the low 32 bits of the millisecond clock are
//!   used, so the epoch repeats every ~49.7 days. Two lifetimes seeded from the
//!   same epoch value must therefore start exactly 49.7 days apart *to the
//!   millisecond*.
//! * **The generation field wrapping.** [`seed`] can reach
//!   `0xFF_FFFF_FF00` — a server started in the last millisecond of an epoch
//!   window — which leaves only 255 generations below the 40-bit field's end,
//!   so a server that takes 256 of them wraps. A wrap is a *generation reuse*,
//!   the same class as the two points above; what it is not, and must never be,
//!   is a reuse of generation zero, whose first id is the root node id itself.
//!   [`Generations::take`] therefore skips zero, which is what makes the
//!   "never zero" below true by construction, not by the epoch's floor.
//!
//! Accepted v1 limitation, stated plainly: the last two points are
//! probabilistic arguments about two *different* processes, not proofs. A
//! persisted epoch would make them proofs, at the cost of a file the server
//! must own and keep durable across crashes; the design prefers the
//! time-derived epoch, and this is the trade it buys.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// How many low bits of an id count within one generation.
pub const COUNTER_BITS: u32 = 24;

/// The largest counter one generation carries.
const COUNTER_MASK: u64 = (1 << COUNTER_BITS) - 1;

/// The generation field's width, and therefore what the epoch must fit in.
const GENERATION_BITS: u32 = u64::BITS - COUNTER_BITS;

/// The largest generation the layout can express.
const GENERATION_MASK: u64 = (1 << GENERATION_BITS) - 1;

/// How many generations one millisecond of the epoch clock buys.
///
/// This is the headroom a server has to take generations without borrowing from
/// the future: one per session table, plus the rare counter exhaustion.
pub const GENERATIONS_PER_TICK: u64 = 1 << 8;

/// Every generation this process hands out, from one counter.
///
/// Two servers built inside one process — which the test suites do, restarting
/// a server under a live mount — can start inside one millisecond of each
/// other, so their wall-clock seeds can be equal. Handing both of them numbers
/// from this one counter is what makes them disjoint regardless: the seed only
/// ever *raises* it, and a generation is only ever taken by `fetch_add`, so no
/// two takers anywhere in the process can obtain the same number however their
/// constructions and allocations interleave.
static GENERATIONS: AtomicU64 = AtomicU64::new(0);

/// The source of generations for one server.
///
/// One per server lifetime; every session's tables draw from it, which is what
/// makes two sessions' ids disjoint by construction. The numbers themselves
/// come from [`GENERATIONS`]; what a server owns is the epoch it raised that
/// counter to when it started.
pub struct Generations {
    /// The generation this server raised the process counter to at startup.
    ///
    /// Carried for the `Debug` rendering: the range a server's sessions name
    /// their nodes and handles in is the first thing an id complaint needs.
    seeded: u64,
}

impl Default for Generations {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for Generations {
    /// Rendered as the epoch this server seeded the counter with, because that
    /// is the only thing about a source that matters in a log: where its
    /// sessions' ids begin.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Generations(seeded at {})", self.seeded)
    }
}

impl Generations {
    /// A fresh source, which raises the process counter to this server's
    /// startup epoch and never lowers it.
    #[must_use]
    pub fn new() -> Self {
        let seeded = seed();
        GENERATIONS.fetch_max(seeded, Ordering::Relaxed);
        Self { seeded }
    }

    /// A source shared by every session of one server.
    #[must_use]
    pub fn shared() -> Arc<Self> {
        Arc::new(Self::new())
    }

    /// An id space of its own, for one table.
    #[must_use]
    pub fn space(self: &Arc<Self>) -> IdSpace {
        IdSpace {
            generations: Arc::clone(self),
            generation: self.take(),
            counter: 0,
        }
    }

    /// The next generation. Monotonic across the whole process, never handed
    /// out twice, and **never zero**.
    ///
    /// Masked into the field the layout gives it: the epoch itself already
    /// wraps, and an id whose generation ran off the end of the word would be
    /// worse than one that wrapped with it. Zero is then skipped, not
    /// returned, because zero is not merely another wrapped number: a
    /// generation-0 space hands out `(0 << COUNTER_BITS) | 1`, which *is*
    /// [`ROOT_NODE_ID`](crate::data::node::ROOT_NODE_ID), and a node table that
    /// took it would overwrite its own session root. Skipping it costs one
    /// number out of 2^40 and keeps the root exemption absolute — which is what
    /// the module's "never zero" claim above rests on, since the epoch's own
    /// floor does not survive the wrap.
    fn take(&self) -> u64 {
        loop {
            if let Some(generation) = generation_of(GENERATIONS.fetch_add(1, Ordering::Relaxed)) {
                return generation;
            }
        }
    }
}

/// One table's slice of the id space.
///
/// Not `Clone` on purpose: two clones would hand out the same numbers, which is
/// precisely what this type exists to make impossible.
#[derive(Debug)]
pub struct IdSpace {
    generations: Arc<Generations>,
    generation: u64,
    counter: u64,
}

impl IdSpace {
    /// The next id: generation-tagged, monotonic within the generation, and
    /// never equal to the root node id.
    pub fn take(&mut self) -> u64 {
        if self.counter >= COUNTER_MASK {
            // Exhaustion takes another generation instead of reusing a number:
            // a session that has named sixteen million entries is a long build,
            // not a reason to hand out a stale id.
            self.generation = self.generations.take();
            self.counter = 0;
        }
        self.counter += 1;
        (self.generation << COUNTER_BITS) | self.counter
    }

    /// The generation ids currently carry.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation
    }
}

/// The generation a raw counter reading names, or `None` for the one reading
/// that names none.
///
/// The reading is masked into the field the layout gives it, and a masked
/// reading of zero is refused. Zero is not merely another wrapped number: a
/// generation-zero space hands out `(0 << COUNTER_BITS) | 1`, which is the
/// mount root's own id, so the caller takes the next number instead.
fn generation_of(raw: u64) -> Option<u64> {
    let generation = raw & GENERATION_MASK;
    (generation != 0).then_some(generation)
}

/// The generation counter's seed: the epoch scaled by the per-tick headroom.
fn seed() -> u64 {
    seed_of(epoch())
}

/// The same, for a given epoch, so the headroom it leaves can be stated as an
/// assertion, not as prose.
fn seed_of(epoch: u64) -> u64 {
    (epoch * GENERATIONS_PER_TICK) & GENERATION_MASK
}

/// The coarse startup epoch: the wall clock in milliseconds, low 32 bits.
///
/// One is the floor, so that no generation is ever zero — that is what keeps
/// every allocated id above the root node id even on a machine whose clock
/// reads the start of an epoch window.
fn epoch() -> u64 {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| {
            u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
        });
    (millis & u64::from(u32::MAX)).max(1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    use crate::data::node::ROOT_NODE_ID;

    #[test]
    fn ids_are_monotonic_within_a_space_and_never_name_the_root() {
        let generations = Generations::shared();
        let mut space = generations.space();
        let mut previous = 0;
        for _ in 0..1000 {
            let id = space.take();
            assert!(id > previous, "ids only move forward");
            assert_ne!(id, ROOT_NODE_ID, "the mount root is nobody else's id");
            assert!(id > COUNTER_MASK, "every id carries a generation");
            previous = id;
        }
    }

    #[test]
    fn two_spaces_of_one_server_never_share_an_id() {
        let generations = Generations::shared();
        let mut first = generations.space();
        let mut second = generations.space();
        let mine: HashSet<u64> = (0..500).map(|_| first.take()).collect();
        for _ in 0..500 {
            assert!(!mine.contains(&second.take()), "sessions are disjoint");
        }
        assert_ne!(first.generation(), second.generation());
    }

    /// The blocker the spec review proved: a stale id from the previous
    /// lifetime must not be a valid id in the next one. Two servers built back
    /// to back inside one process is the hardest version of that case, because
    /// their wall clocks can read the same millisecond.
    #[test]
    fn a_restarted_server_hands_out_none_of_the_previous_lifetimes_ids() {
        let take = |generations: &Arc<Generations>| {
            let mut nodes = generations.space();
            let mut handles = generations.space();
            (0..2000)
                .map(|index| {
                    if index % 2 == 0 {
                        nodes.take()
                    } else {
                        handles.take()
                    }
                })
                .collect::<HashSet<u64>>()
        };
        let before = take(&Generations::shared());
        for id in take(&Generations::shared()) {
            assert!(
                !before.contains(&id),
                "a restarted server handed out {id}, which the previous lifetime had used"
            );
        }
    }

    #[test]
    fn an_exhausted_counter_takes_another_generation_instead_of_reusing_ids() {
        let generations = Generations::shared();
        let mut space = generations.space();
        let first = space.generation();
        // Walk the counter to its last value without allocating sixteen
        // million ids for a unit test.
        space.counter = COUNTER_MASK - 1;
        let last = space.take();
        assert_eq!(last, (first << COUNTER_BITS) | COUNTER_MASK);
        let rolled = space.take();
        assert_ne!(space.generation(), first, "a fresh generation carries on");
        assert!(rolled > last, "and its ids are still further along");
    }

    /// The order a restart under a live mount actually takes: the replacement
    /// server is built while the outgoing one still holds its ids, so both
    /// sources exist before either of them allocates. A floor raised at
    /// construction cannot separate these two — both read the same value —
    /// which is why the generations come from one process-wide counter.
    #[test]
    fn two_servers_built_before_either_allocates_still_share_no_id() {
        let first = Generations::shared();
        let second = Generations::shared();
        let mut mine = first.space();
        let mut theirs = second.space();
        let taken: HashSet<u64> = (0..500).map(|_| mine.take()).collect();
        for _ in 0..500 {
            let id = theirs.take();
            assert!(
                !taken.contains(&id),
                "a second server handed out {id}, which the first one had used"
            );
        }
    }

    /// The 40-bit generation field wrapping past its end, which is the one
    /// place the allocator could name the mount root.
    ///
    /// A server started in the last millisecond of an epoch window seeds the
    /// counter to its highest value and has only 255 generations left below the
    /// field's end, so its 256th wraps. Were the wrapped generation used, the
    /// space's first id would be `(0 << COUNTER_BITS) | 1` — the mount root,
    /// which the design makes the single eternal exemption and which a node
    /// table taking it would overwrite. This is the arithmetic of that path,
    /// stated directly: driving the process-wide counter to the wrap instead
    /// would leave every other test in this process on the far side of it.
    #[test]
    fn the_generation_field_never_wraps_onto_the_root() {
        assert_eq!(
            seed_of(u64::from(u32::MAX)),
            GENERATION_MASK - (GENERATIONS_PER_TICK - 1),
            "the highest epoch leaves one tick of headroom below the field's end"
        );
        assert_eq!(
            (0 << COUNTER_BITS) | 1,
            ROOT_NODE_ID,
            "a generation-zero space would name the mount root first"
        );
        assert_eq!(generation_of(GENERATION_MASK), Some(GENERATION_MASK));
        assert_eq!(
            generation_of(GENERATION_MASK + 1),
            None,
            "the wrapped reading is skipped, not handed out"
        );
        assert_eq!(generation_of(GENERATION_MASK + 2), Some(1));
    }

    /// The in-process guarantee the restart case rests on: a server built after
    /// another one starts past every generation that one handed out, whatever
    /// the two wall clocks read.
    #[test]
    fn a_new_server_starts_above_everything_this_process_has_allocated() {
        let first = Generations::shared();
        let mut space = first.space();
        let highest = (0..64).map(|_| space.take()).last().expect("allocated");
        let second = Generations::shared();
        let mut fresh = second.space();
        assert!(
            fresh.take() > highest,
            "a fresh server re-entered the previous one's range"
        );
    }
}
