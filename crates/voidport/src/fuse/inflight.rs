use std::collections::HashMap;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use crate::client::{Interrupt, Raise};

/// A teardown during the window between a callback and its reply fails the
/// unmount, because the waiting caller is a reference the kernel counts against
/// the mountpoint, and the guest is told `EIO` for work that may have
/// completed.
#[derive(Debug, Default)]
pub struct InFlight {
    owed: Mutex<HashMap<u64, Raise>>,
    settled: Condvar,
}

impl InFlight {
    /// The deadline stops a callback whose server never answers from holding up
    /// a process that was asked to stop.
    pub fn settle(&self, deadline: Instant) {
        let mut owed = self.lock();
        while let Some(remaining) = wait_left(owed.len(), deadline, Instant::now()) {
            owed = self
                .settled
                .wait_timeout(owed, remaining)
                .unwrap_or_else(|poison| poison.into_inner())
                .0;
        }
    }

    #[must_use]
    pub fn is_settled(&self) -> bool {
        self.lock().is_empty()
    }

    pub(super) fn owe(self: &Arc<Self>, unique: u64) -> (Ticket, Interrupt) {
        let (raise, interrupt) = Interrupt::new();
        self.lock().insert(unique, raise);
        let ticket = Ticket {
            owed: Arc::clone(self),
            unique,
        };
        (ticket, interrupt)
    }

    pub(super) fn interrupt(&self, unique: u64) -> bool {
        match self.lock().get(&unique) {
            Some(raise) => {
                raise.raise();
                true
            }
            None => false,
        }
    }

    pub fn interrupt_all(&self) {
        self.lock().values().for_each(Raise::raise);
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<u64, Raise>> {
        self.owed
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }
}

fn wait_left(owed: usize, deadline: Instant, now: Instant) -> Option<Duration> {
    let remaining = deadline.saturating_duration_since(now);
    (owed > 0 && !remaining.is_zero()).then_some(remaining)
}

/// Dropping a ticket is how a callback whose task is dropped instead of
/// finished, as a released runtime does, stops being counted.
#[derive(Debug)]
pub(super) struct Ticket {
    owed: Arc<InFlight>,
    unique: u64,
}

impl Drop for Ticket {
    fn drop(&mut self) {
        let mut owed = self.owed.lock();
        owed.remove(&self.unique);
        if owed.is_empty() {
            self.owed.settled.notify_all();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_teardown_that_is_owed_nothing_does_not_wait() {
        let inflight = Arc::<InFlight>::default();
        assert!(inflight.is_settled());
        let now = Instant::now();
        assert_eq!(wait_left(0, now + Duration::from_secs(30), now), None);
        inflight.settle(now + Duration::from_secs(30));
    }

    #[test]
    fn a_callback_still_owed_is_waited_for_until_the_deadline() {
        let now = Instant::now();
        let deadline = now + Duration::from_millis(100);
        assert_eq!(
            wait_left(1, deadline, now),
            Some(Duration::from_millis(100))
        );
        assert_eq!(
            wait_left(1, deadline, now + Duration::from_millis(50)),
            Some(Duration::from_millis(50))
        );
        assert_eq!(wait_left(1, deadline, deadline), None);
        assert_eq!(
            wait_left(1, deadline, deadline + Duration::from_secs(1)),
            None
        );
    }

    #[test]
    fn an_outstanding_callback_is_waited_out() {
        let inflight = Arc::<InFlight>::default();
        let (owed, _) = inflight.owe(1);
        assert!(!inflight.is_settled());
        let answering = std::thread::spawn(move || drop(owed));
        inflight.settle(Instant::now() + Duration::from_secs(30));
        answering.join().expect("the answering thread finishes");
        assert!(inflight.is_settled());
    }

    #[test]
    fn a_callback_that_never_answers_is_waited_out_only_to_the_deadline() {
        let inflight = Arc::<InFlight>::default();
        let _owed = inflight.owe(1);
        inflight.settle(Instant::now());
        assert!(
            !inflight.is_settled(),
            "nothing answered, so it is still owed"
        );
    }

    #[test]
    fn a_dropped_callback_stops_being_owed() {
        let inflight = Arc::<InFlight>::default();
        let (first, _) = inflight.owe(1);
        let (second, _) = inflight.owe(2);
        assert!(!inflight.is_settled());
        drop(first);
        assert!(!inflight.is_settled());
        drop(second);
        assert!(inflight.is_settled());
    }

    #[test]
    fn an_interrupt_arrives_at_the_callback_of_its_request() {
        let inflight = Arc::<InFlight>::default();
        let (_first, first) = inflight.owe(1);
        let (_second, second) = inflight.owe(2);
        assert!(inflight.interrupt(2));
        assert!(!inflight.interrupt(3), "request 3 has no callback");
        assert!(!first.raised());
        assert!(second.raised());
    }
}
