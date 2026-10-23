//! An id is a 40-bit generation above a 24-bit counter. The counter is per
//! generation, starts at 1 and only moves forward. The generation comes from one
//! process-wide monotonic counter ([`GENERATIONS`]), which every server raises
//! at startup to a wall-clock epoch, so two sessions of one server and two
//! server lifetimes in one process never share an id. Neither part is ever
//! zero, so node id 1, the mount root, is never handed out.
//!
//! Two lifetimes in two processes are kept apart only by [`epoch`]: the later
//! one seeds from the startup time in milliseconds scaled by
//! [`GENERATIONS_PER_TICK`], so the earlier one would have to consume more than
//! that many generations per millisecond of its uptime to collide. The epoch is
//! the low 32 bits of the clock and repeats every ~49.7 days.
//!
//! [`seed`] can reach `0xFF_FFFF_FF00`, which leaves 255 generations below the
//! end of the 40-bit field, so [`Generations::take`] skips a wrapped zero.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

pub const COUNTER_BITS: u32 = 24;

const COUNTER_MASK: u64 = (1 << COUNTER_BITS) - 1;

const GENERATION_BITS: u32 = u64::BITS - COUNTER_BITS;

const GENERATION_MASK: u64 = (1 << GENERATION_BITS) - 1;

pub const GENERATIONS_PER_TICK: u64 = 1 << 8;

/// Two servers built inside one process can start inside one millisecond, so
/// their seeds can be equal. Both take numbers from this one counter by
/// `fetch_add`, and the seed only raises it.
static GENERATIONS: AtomicU64 = AtomicU64::new(0);

pub struct Generations {
    seeded: u64,
}

impl Default for Generations {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for Generations {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Generations(seeded at {})", self.seeded)
    }
}

impl Generations {
    #[must_use]
    pub fn new() -> Self {
        let seeded = seed();
        GENERATIONS.fetch_max(seeded, Ordering::Relaxed);
        Self { seeded }
    }

    #[must_use]
    pub fn shared() -> Arc<Self> {
        Arc::new(Self::new())
    }

    #[must_use]
    pub fn space(self: &Arc<Self>) -> IdSpace {
        IdSpace {
            generations: Arc::clone(self),
            generation: self.take(),
            counter: 0,
        }
    }

    /// Zero is skipped, not returned: a generation-0 space hands out
    /// `(0 << COUNTER_BITS) | 1`, which is
    /// [`ROOT_NODE_ID`](crate::data::node::ROOT_NODE_ID), and a node table that
    /// took it would overwrite its own session root.
    fn take(&self) -> u64 {
        loop {
            if let Some(generation) = generation_of(GENERATIONS.fetch_add(1, Ordering::Relaxed)) {
                return generation;
            }
        }
    }
}

/// Not `Clone`: two clones would hand out the same numbers.
#[derive(Debug)]
pub struct IdSpace {
    generations: Arc<Generations>,
    generation: u64,
    counter: u64,
}

impl IdSpace {
    pub fn take(&mut self) -> u64 {
        if self.counter >= COUNTER_MASK {
            // Exhaustion takes another generation instead of reusing a number.
            self.generation = self.generations.take();
            self.counter = 0;
        }
        self.counter += 1;
        (self.generation << COUNTER_BITS) | self.counter
    }

    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation
    }
}

fn generation_of(raw: u64) -> Option<u64> {
    let generation = raw & GENERATION_MASK;
    (generation != 0).then_some(generation)
}

fn seed() -> u64 {
    seed_of(epoch())
}

fn seed_of(epoch: u64) -> u64 {
    (epoch * GENERATIONS_PER_TICK) & GENERATION_MASK
}

/// One is the floor, so that no generation is ever zero.
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

    /// A server started in the last millisecond of an epoch window has only 255
    /// generations below the end of the field, so its 256th wraps. Moving the
    /// process-wide counter to the wrap would leave every other test in this
    /// process on the far side of it, so the arithmetic is asserted directly.
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
