//! Giving the host back the memory a drained node table freed.
//!
//! A guest that forgets is the server's only way to shrink its node table, and
//! it works: a `drop_caches` in the guest drains a session from 800 000 nodes to
//! one within seconds, every pin closed. What it did **not** do, measured at
//! that scale on 2026-08-15, is give the host any RAM back — the process kept
//! ~1.4 GiB of resident memory for its whole life, past the drain and past the
//! unmount. Nothing leaked: the entries are freed correctly, and glibc simply
//! keeps freed memory in its arenas instead of returning it to the kernel.
//! "The guest forgot it" has to mean "the host got the memory back", and this
//! module is what makes it mean that.
//!
//! Two mechanisms, and both are needed — measured, not assumed (the arms are in
//! `docs/PERFORMANCE.md`, 2026-08-15):
//!
//! * **Confined arenas.** glibc grows up to `8 x cores` allocation arenas (256
//!   on a 32-core host) and requests are served on a thread pool, so a table's
//!   entries end up scattered across dozens of arenas — each left holding live
//!   fragments that pin whole heaps. A trim in that state returned only ~21% of
//!   a drained 467 MiB; with the arenas confined it returns ~99%. The bound is
//!   set once, at startup, before the pool exists.
//! * **A debounced trim.** [`malloc_trim`](libc::malloc_trim) is what actually
//!   hands the free pages back. It is called from a thread of this module's own
//!   — never on the request path, and never once per FORGET: a drain arrives as
//!   a flood of single-node forgets, and the trigger below fires on the *shape*
//!   of the drain, not on each of its steps. Twice per drain, because a
//!   drain becomes returnable in two stages: see [`AFTERGLOW`].
//!
//! **The trigger**: a trim is due once the live entry count has fallen to half
//! of its peak since the last trim, and by at least [`FLOOR`] entries. Both
//! halves earn their place. The fraction makes churn free — a session that
//! keeps its working set resident never crosses it, however many lookups and
//! forgets it does — and it is self-debouncing, because the peak is reset to
//! the live count at every trim, so the next one needs another halving. The
//! floor keeps small tables out of it entirely: at the measured ~1.5 KiB per
//! entry there is under 6 MiB behind 4096 of them, which does not pay for a
//! syscall.
//!
//! The counters are advisory, and deliberately not synchronized against each
//! other: they steer a heuristic, not a bound. Miscounting one trim early or
//! late costs nothing; a lock on the lookup path would cost the hot path, which
//! the design forbids.
//!
//! # Why this module has `unsafe`
//!
//! `mallopt` and `malloc_trim` are the allocator's own interface and have no
//! safe binding: neither `rustix` nor `std` exposes the C library's heap at
//! all. The two calls are confined here, take no pointers, and each carries its
//! safety argument — the same posture as [`crate::host::lock`], which is the
//! other place in the shipped code that has to reach past a safe binding.
#![allow(
    unsafe_code,
    reason = "glibc's arena bound and heap trim have no safe binding"
)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex, Once};
use std::time::Duration;

/// How many allocation arenas the server confines glibc to.
///
/// Two, not one: one arena serializes every allocation in the process,
/// which cost 2.3x the fill time of two in the sweep, while two returned the
/// same ~99% of a drained table.
#[cfg(target_env = "gnu")]
const ARENAS: libc::c_int = 2;

/// How far the live entry count must fall, in entries, before a halving
/// justifies a trim.
const FLOOR: usize = 4096;

/// How long the reclaimer waits after the first drop that qualifies for a trim before
/// trimming.
///
/// A guest drain is a cascade: 800 000 nodes fall to one over several seconds,
/// crossing the halving trigger once per halving. Settling first collapses that
/// cascade into a couple of trims near the end of it, where the memory to
/// return is greatest and the arenas are quietest.
const SETTLE: Duration = Duration::from_millis(250);

/// How long after a trim the reclaimer trims once more.
///
/// A drain does not become returnable all at once. The threads that freed the
/// entries keep a per-thread cache of what they freed, and a page under one
/// cached chunk cannot be handed back however free the rest of it is; those
/// caches go back to the arena when the thread retires, and the request pool
/// retires an idle thread after ten seconds. Measured on a 60 000-entry drain
/// that had grown the process by 70 MiB: the trim at [`SETTLE`] left 43 MiB of
/// it resident, and a second trim once the pool had gone quiet took that to
/// 6 MiB — the same walk, the same table, six times the memory back, for one
/// extra syscall per drain.
const AFTERGLOW: Duration = Duration::from_secs(15);

/// The process-wide view of how much of the node tables is live.
///
/// Process-wide because the heap is: entries of every session are freed into
/// the same arenas, and it is the arenas that are trimmed.
static LEDGER: Ledger = Ledger::new();

/// The entry counters, and the reclaimer's doorbell.
struct Ledger {
    /// Node table entries alive across every session.
    live: AtomicUsize,
    /// The highest [`Self::live`] has been since the last trim.
    peak: AtomicUsize,
    /// Whether a trim is owed.
    due: Mutex<bool>,
    /// Rung when it becomes owed.
    wake: Condvar,
}

impl Ledger {
    /// An empty ledger: no entries, nothing owed.
    const fn new() -> Self {
        Self {
            live: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
            due: Mutex::new(false),
            wake: Condvar::new(),
        }
    }

    /// Counts `count` entries in.
    fn admitted(&self, count: usize) {
        let live = self.live.fetch_add(count, Ordering::Relaxed) + count;
        self.peak.fetch_max(live, Ordering::Relaxed);
    }

    /// Counts `count` entries out, and answers whether that leaves enough freed
    /// memory to justify a trim.
    ///
    /// Saturating, not wrapping: the counters are advisory, and an
    /// undercount that reached zero must not become an enormous live count.
    fn released(&self, count: usize) -> bool {
        let live = self
            .live
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |live| {
                Some(live.saturating_sub(count))
            })
            .unwrap_or(0)
            .saturating_sub(count);
        let peak = self.peak.load(Ordering::Relaxed);
        if !trim_due(live, peak) {
            return false;
        }
        // Whoever wins this owes the one trim, and resets the peak that decides
        // the next one. A loser has nothing left to report: the winner's trim
        // covers its release too.
        self.peak
            .compare_exchange(peak, live, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    }
}

/// Confines the allocator's arenas and starts the reclaimer.
///
/// Called once, from the daemon's startup, beside the descriptor-limit raise
/// and for the same reason: both are process-wide properties the server sets
/// before it serves anything. Repeated calls — a test process starts many
/// servers — do nothing.
pub fn start() {
    static STARTED: Once = Once::new();
    STARTED.call_once(|| {
        confine_arenas();
        spawn_reclaimer();
    });
}

/// Counts `count` entries into the tables.
pub fn admitted(count: usize) {
    LEDGER.admitted(count);
}

/// Counts `count` entries out of the tables, and rings the reclaimer if that
/// leaves enough freed memory to justify returning it.
pub fn released(count: usize) {
    if count > 0 && LEDGER.released(count) {
        ring();
    }
}

/// Whether a table that peaked at `peak` entries and now holds `live` has
/// freed enough to justify a trim: half of the peak, and at least [`FLOOR`]
/// entries of it.
const fn trim_due(live: usize, peak: usize) -> bool {
    peak >= live.saturating_add(FLOOR) && live <= peak / 2
}

/// Tells the reclaimer a trim is owed.
fn ring() {
    let mut due = LEDGER
        .due
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    *due = true;
    LEDGER.wake.notify_one();
}

/// Waits for the doorbell, settles, and trims — twice, forever.
fn reclaim() {
    loop {
        wait_for_the_doorbell();
        // Settle first, then take the flag down: everything the drain rings
        // while this sleeps is answered by the trim below.
        std::thread::sleep(SETTLE);
        *LEDGER
            .due
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = false;
        trim();
        // And again once the request pool has had time to retire the threads
        // that did the freeing, which is when the rest of it becomes
        // returnable at all. A drain that is still running rings again on its
        // own, so this sleep costs a late trim at worst.
        std::thread::sleep(AFTERGLOW);
        trim();
    }
}

/// Blocks until a trim is owed.
fn wait_for_the_doorbell() {
    let mut due = LEDGER
        .due
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    while !*due {
        due = LEDGER
            .wake
            .wait(due)
            .unwrap_or_else(|poisoned| poisoned.into_inner());
    }
}

/// The reclaimer thread, where the platform has anything to trim.
#[cfg(target_env = "gnu")]
fn spawn_reclaimer() {
    if let Err(error) = std::thread::Builder::new()
        .name("voidportd-reclaim".to_owned())
        .spawn(reclaim)
    {
        tracing::warn!(%error, "no memory reclaimer: freed entries will not return to the OS");
    }
}

/// Bounds how many arenas glibc may create, so that a trim can reach the memory
/// a drained table freed.
#[cfg(target_env = "gnu")]
fn confine_arenas() {
    // SAFETY: `mallopt` is thread-safe, takes no pointers, and this runs before
    // the server's thread pools exist.
    let accepted = unsafe { libc::mallopt(libc::M_ARENA_MAX, ARENAS) };
    if accepted == 0 {
        tracing::warn!(
            "the allocator refused an arena bound; freed entry memory may not return to the OS"
        );
        return;
    }
    tracing::debug!(arenas = ARENAS, "confined the allocator's arenas");
}

/// Returns every free page the allocator is sitting on to the kernel.
#[cfg(target_env = "gnu")]
fn trim() {
    // SAFETY: `malloc_trim` is thread-safe and takes no pointers. A pad of 0
    // asks for everything: the server has no allocation burst to keep headroom
    // for, and what it just freed is a drained node table.
    let returned = unsafe { libc::malloc_trim(0) } == 1;
    tracing::debug!(returned, "trimmed the allocator");
}

/// glibc's arena controls are glibc's: on another libc the tables still drain
/// correctly and the allocator returns what it returns.
#[cfg(not(target_env = "gnu"))]
fn spawn_reclaimer() {}

/// See [`spawn_reclaimer`].
#[cfg(not(target_env = "gnu"))]
fn confine_arenas() {}

/// See [`spawn_reclaimer`].
#[cfg(not(target_env = "gnu"))]
fn trim() {}

#[cfg(test)]
mod tests {
    use super::*;

    /// Churn is free: a table that keeps its working set never crosses the
    /// trigger, however much it looks up and forgets.
    #[test]
    fn a_table_that_holds_its_working_set_is_never_trimmed() {
        for live in [1_000_000, 500_001, 100_000] {
            assert!(!trim_due(live, live));
            assert!(!trim_due(live, live + FLOOR - 1));
        }
        // A million entries down to half a million plus one is not a halving.
        assert!(!trim_due(500_001, 1_000_000));
    }

    /// A drain justifies a trim: half the peak gone, and enough of it to pay
    /// for the syscall.
    #[test]
    fn a_drained_table_is_due_a_trim() {
        assert!(trim_due(500_000, 1_000_000));
        assert!(trim_due(1, 800_809));
        assert!(trim_due(0, FLOOR));
    }

    /// Small tables are not: an empty one that never held [`FLOOR`] entries has
    /// under 6 MiB behind it at the measured per-entry cost.
    #[test]
    fn a_small_table_is_never_trimmed_however_completely_it_drains() {
        assert!(!trim_due(0, FLOOR - 1));
        assert!(!trim_due(0, 0));
        assert!(!trim_due(16, 32));
    }

    /// A drain rings once, not once per forget: the peak follows the live count
    /// down, so the next trim needs another halving.
    #[test]
    fn one_drain_owes_one_trim_per_halving() {
        let ledger = Ledger::new();
        ledger.admitted(100_000);
        // Forgetting the first half owes a trim.
        assert!(ledger.released(50_000));
        // The rest of that half owes nothing more, however many forgets it is.
        for _ in 0..1_000 {
            assert!(!ledger.released(10));
        }
        // Halving what is left owes the next one.
        assert!(ledger.released(15_000));
    }

    /// The counters survive an imbalance instead of wrapping into a live count
    /// no table could hold.
    #[test]
    fn releasing_more_than_was_admitted_saturates_at_empty() {
        let ledger = Ledger::new();
        ledger.admitted(4);
        ledger.released(usize::MAX);
        assert_eq!(ledger.live.load(Ordering::Relaxed), 0);
    }
}
