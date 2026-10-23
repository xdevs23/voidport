//! glibc retains freed memory in its arenas, so a drained node table gives no
//! memory back to the host without help. The binary confines the allocation
//! arenas through [`confine_arenas`] before it starts any thread, because
//! entries scattered across many arenas leave live fragments that keep whole
//! heaps in use. A thread started by [`start`] then calls `malloc_trim` once
//! the live entry count has fallen to half of its peak since the last trim, and
//! by at least [`FLOOR`] entries. It never runs on the request path or once per
//! FORGET.
//!
//! The counters are advisory and not synchronized against each other: they
//! steer a heuristic, and a lock on the lookup path would cost the hot path.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex, Once};
use std::time::Duration;

/// Two, not one: one arena serializes every allocation in the process.
#[cfg(target_env = "gnu")]
const ARENAS: libc::c_int = 2;

const FLOOR: usize = 4096;

/// Waiting first collapses the cascade of a drain into a couple of trims near
/// its end.
const SETTLE: Duration = Duration::from_millis(250);

/// A drain becomes returnable in two stages. A page under a chunk in a
/// per-thread cache cannot be handed back, and those caches go back to the
/// arena when the request pool retires an idle thread after ten seconds.
const AFTERGLOW: Duration = Duration::from_secs(15);

/// Process-wide because the heap is: the entries of every session are freed
/// into the same arenas.
static LEDGER: Ledger = Ledger::new();

struct Ledger {
    live: AtomicUsize,
    peak: AtomicUsize,
    due: Mutex<bool>,
    wake: Condvar,
}

impl Ledger {
    const fn new() -> Self {
        Self {
            live: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
            due: Mutex::new(false),
            wake: Condvar::new(),
        }
    }

    fn admitted(&self, count: usize) {
        let live = self.live.fetch_add(count, Ordering::Relaxed) + count;
        self.peak.fetch_max(live, Ordering::Relaxed);
    }

    /// Saturating, so an undercount that reached zero cannot become an
    /// enormous live count.
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
        // The thread that wins this runs the one trim and resets the peak that
        // decides the next one. A losing thread has nothing left to report: the
        // trim of the winner covers its release too.
        self.peak
            .compare_exchange(peak, live, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    }
}

pub fn start() {
    static STARTED: Once = Once::new();
    STARTED.call_once(spawn_reclaimer);
}

pub fn admitted(count: usize) {
    LEDGER.admitted(count);
}

pub fn released(count: usize) {
    if count > 0 && LEDGER.released(count) {
        ring();
    }
}

const fn trim_due(live: usize, peak: usize) -> bool {
    peak >= live.saturating_add(FLOOR) && live <= peak / 2
}

fn ring() {
    let mut due = LEDGER
        .due
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    *due = true;
    LEDGER.wake.notify_one();
}

fn reclaim() {
    loop {
        wait_for_the_doorbell();
        reclaim_cycle(&LEDGER, std::thread::sleep, trim);
    }
}

fn reclaim_cycle(ledger: &Ledger, mut wait: impl FnMut(Duration), mut trim: impl FnMut()) {
    // Clear the flag after the first wait so releases during that wait are
    // included in this trim. Releases after it go to the next cycle.
    wait(SETTLE);
    *ledger
        .due
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = false;
    trim();
    wait(AFTERGLOW);
    trim();
}

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

#[cfg(target_env = "gnu")]
fn spawn_reclaimer() {
    if let Err(error) = std::thread::Builder::new()
        .name("voidportd-reclaim".to_owned())
        .spawn(reclaim)
    {
        tracing::warn!(%error, "no memory reclaimer: freed entries will not return to the OS");
    }
}

/// glibc fixes its arena limit the first time the process needs more arenas
/// than its initial allowance, and ignores a bound set after that.
#[cfg(target_env = "gnu")]
pub fn confine_arenas() {
    match threads_started() {
        Ok(false) => {}
        Ok(true) => tracing::warn!(
            "the arena bound comes after the process started other threads and may have no effect"
        ),
        Err(error) => tracing::warn!(
            %error,
            "cannot count the threads of the process; the arena bound may come too late"
        ),
    }
    // SAFETY: Unavoidable: neither std nor rustix binds the allocator of the C
    // library, so there is no safe form. `mallopt` is thread-safe and takes no
    // pointers.
    let accepted = unsafe { libc::mallopt(libc::M_ARENA_MAX, ARENAS) };
    if accepted == 0 {
        tracing::warn!(
            "the allocator refused an arena bound; freed entry memory may not return to the OS"
        );
        return;
    }
    tracing::debug!(arenas = ARENAS, "confined the allocator's arenas");
}

#[cfg(target_env = "gnu")]
fn threads_started() -> std::io::Result<bool> {
    Ok(std::fs::read_dir("/proc/self/task")?.count() > 1)
}

#[cfg(target_env = "gnu")]
fn trim() {
    // SAFETY: Unavoidable: neither std nor rustix binds the allocator of the C
    // library, so there is no safe form. `malloc_trim` is thread-safe and takes
    // no pointers. A pad of 0 asks for everything: the server has no
    // allocation burst to keep headroom for, and what it just freed is a
    // drained node table.
    let returned = unsafe { libc::malloc_trim(0) } == 1;
    tracing::debug!(returned, "trimmed the allocator");
}

/// The arena controls belong to glibc; another libc returns what it returns.
#[cfg(not(target_env = "gnu"))]
fn spawn_reclaimer() {}

#[cfg(not(target_env = "gnu"))]
pub fn confine_arenas() {}

#[cfg(not(target_env = "gnu"))]
fn trim() {}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_env = "gnu")]
    #[test]
    fn a_second_thread_makes_the_arena_bound_too_late() {
        let (release, released) = std::sync::mpsc::channel::<()>();
        std::thread::scope(|scope| {
            scope.spawn(move || released.recv());
            assert!(threads_started().expect("/proc/self/task can be listed"));
            release.send(()).expect("the second thread waits");
        });
    }

    #[test]
    fn a_reclaim_cycle_waits_before_each_trim_and_retains_later_releases() {
        use std::cell::RefCell;
        let ledger = Ledger::new();
        *ledger.due.lock().expect("ledger") = true;
        let events = RefCell::new(Vec::new());
        reclaim_cycle(
            &ledger,
            |delay| {
                events.borrow_mut().push(Some(delay));
                if delay == AFTERGLOW {
                    assert!(!*ledger.due.lock().expect("first trim cleared its request"));
                    *ledger.due.lock().expect("later release") = true;
                }
            },
            || events.borrow_mut().push(None),
        );
        assert_eq!(
            *events.borrow(),
            vec![Some(SETTLE), None, Some(AFTERGLOW), None]
        );
        assert!(*ledger.due.lock().expect("later release remains owed"));
    }

    #[test]
    fn a_table_that_holds_its_working_set_is_never_trimmed() {
        for live in [1_000_000, 500_001, 100_000] {
            assert!(!trim_due(live, live));
            assert!(!trim_due(live, live + FLOOR - 1));
        }
        assert!(!trim_due(500_001, 1_000_000));
    }

    #[test]
    fn a_drained_table_is_due_a_trim() {
        assert!(trim_due(500_000, 1_000_000));
        assert!(trim_due(1, 800_809));
        assert!(trim_due(0, FLOOR));
    }

    #[test]
    fn a_small_table_is_never_trimmed_however_completely_it_drains() {
        assert!(!trim_due(0, FLOOR - 1));
        assert!(!trim_due(0, 0));
        assert!(!trim_due(16, 32));
    }

    #[test]
    fn one_drain_owes_one_trim_per_halving() {
        let ledger = Ledger::new();
        ledger.admitted(100_000);
        assert!(ledger.released(50_000));
        for _ in 0..1_000 {
            assert!(!ledger.released(10));
        }
        assert!(ledger.released(15_000));
    }

    #[test]
    fn releasing_more_than_was_admitted_saturates_at_empty() {
        let ledger = Ledger::new();
        ledger.admitted(4);
        ledger.released(usize::MAX);
        assert_eq!(ledger.live.load(Ordering::Relaxed), 0);
    }
}
