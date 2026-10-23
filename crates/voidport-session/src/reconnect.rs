//! The adapter has the sockets, tasks and clock: instants arrive as arguments,
//! and the deadline comparisons, above all the tie-break, are made here, never
//! by an adapter. The connection is the opaque value `C` of the adapter, so
//! whether a connection is installed and which one it is are one fact under
//! one lock.

use core::time::Duration;

use crate::backoff::{DEGRADED_ATTEMPT_BOUND, Schedule};
use crate::time::{DeadlineVerdict, Instant, deadline_verdict};

pub const FIRST_GENERATION: u64 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Connected,
    Reconnecting,
    Degraded,
    Closed,
}

/// The barrier of a teardown: aborting a task is not synchronous, and a
/// connection dying during a teardown would otherwise start a fresh one behind
/// it. Anything but [`Recovery::Running`] means nothing dials and nothing is
/// installed, whatever the phase is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recovery {
    Running,
    /// A teardown is under way and may yet be refused. Nothing dials, but a
    /// death still opens the window a refused teardown is owed when
    /// [`Machine::resume_recovery`] hands the probe back.
    Paused,
    /// A teardown that never comes back. Nothing dials, and a death arriving
    /// now ends the mount instead of opening a window nobody will wait out.
    Ended,
}

#[derive(Debug)]
enum State<C> {
    Connected { generation: u64, connection: C },
    Reconnecting { deadline: Instant },
    Degraded,
    Closed,
}

/// The connection is lent and stays installed, so a caller takes a reference of
/// its own while it holds the lock that the machine changes under.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Serve<'a, C> {
    Now { connection: &'a C },
    Stall { deadline: Instant },
    Fail,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Woke {
    /// The window of the caller closed, whatever else happened in that instant.
    /// `degraded` is true for the call that closed the window.
    Expired {
        degraded: bool,
    },
    Retry,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lost {
    /// An older generation, or a recovery already under way.
    Ignored,
    Stalling {
        deadline: Instant,
    },
    /// The mount is failing requests at once and wants a probe: either it is
    /// fail-fast, or its window is zero.
    Degraded,
    /// A teardown that never comes back was already under way.
    Closed,
}

impl Lost {
    #[must_use]
    pub fn wants_probe(self) -> bool {
        matches!(self, Self::Stalling { .. } | Self::Degraded)
    }
}

#[derive(Debug)]
pub struct Machine<C> {
    state: State<C>,
    recovery: Recovery,
    next_generation: u64,
    next_probe: u64,
    probe: Option<u64>,
}

impl<C> Machine<C> {
    /// Starts Connected over `connection` as generation 1, because a mount that
    /// could not be established is a mount error, never one that starts degraded.
    #[must_use]
    pub fn connected(connection: C) -> Self {
        Self {
            state: State::Connected {
                generation: FIRST_GENERATION,
                connection,
            },
            recovery: Recovery::Running,
            next_generation: FIRST_GENERATION + 1,
            next_probe: 1,
            probe: None,
        }
    }

    #[must_use]
    pub fn phase(&self) -> Phase {
        match &self.state {
            State::Connected { .. } => Phase::Connected,
            State::Reconnecting { .. } => Phase::Reconnecting,
            State::Degraded => Phase::Degraded,
            State::Closed => Phase::Closed,
        }
    }

    /// The phase alone cannot tell "never left Connected" from "died and came
    /// back", and the monotonic generation can.
    #[must_use]
    pub fn connected_generation(&self) -> Option<u64> {
        match self.state {
            State::Connected { generation, .. } => Some(generation),
            _ => None,
        }
    }

    /// A FORGET or a RELEASE goes out only within the session that admitted the
    /// reference: once that session ended, the server has dropped it, and a newer
    /// session never counted it.
    #[must_use]
    pub fn serving(&self, generation: u64) -> Option<&C> {
        match &self.state {
            State::Connected {
                generation: installed,
                connection,
            } if *installed == generation => Some(connection),
            _ => None,
        }
    }

    #[must_use]
    pub fn recovery(&self) -> Recovery {
        self.recovery
    }

    #[must_use]
    pub fn schedule(&self) -> Schedule {
        match self.state {
            State::Degraded => Schedule::Degraded,
            _ => Schedule::Stalling,
        }
    }

    #[must_use]
    pub fn serve(&self) -> Serve<'_, C> {
        match &self.state {
            State::Connected { connection, .. } => Serve::Now { connection },
            State::Reconnecting { deadline } => Serve::Stall {
                deadline: *deadline,
            },
            State::Degraded | State::Closed => Serve::Fail,
        }
    }

    /// The deadline wins every tie. A wakeup and the end of the window can fall
    /// in the same instant, and a caller sent round the loop would then be
    /// served after its window. So the instant read after the wait, never
    /// before it, sets what the wait meant.
    pub fn woke(&mut self, deadline: Instant, now: Instant) -> Woke {
        if let DeadlineVerdict::Wait(_) = deadline_verdict(deadline, now) {
            return Woke::Retry;
        }
        Woke::Expired {
            degraded: self.expire(now),
        }
    }

    /// Called by whoever notices first, a stalled caller or the probe between
    /// attempts. It reads the instant against the window the mount is in right
    /// now, so a late caller cannot end a window it did not wait on.
    pub fn expire(&mut self, now: Instant) -> bool {
        match self.state {
            State::Reconnecting { deadline }
                if deadline_verdict(deadline, now) == DeadlineVerdict::Proceed =>
            {
                self.state = State::Degraded;
                true
            }
            _ => false,
        }
    }

    /// Death observations coalesce here, and only the one for the generation
    /// installed in the mount has an effect.
    ///
    /// A `stall` of [`Duration::ZERO`] is fail-fast: the window closes the instant
    /// the server breaks away, and the probe still runs.
    ///
    /// The dead connection is not handed back, because whoever reports a death
    /// has it and buries it next.
    pub fn lost(&mut self, generation: u64, now: Instant, stall: Duration) -> Lost {
        if self.connected_generation() != Some(generation) {
            return Lost::Ignored;
        }
        if self.recovery == Recovery::Ended {
            self.state = State::Closed;
            return Lost::Closed;
        }
        if stall.is_zero() {
            self.state = State::Degraded;
            return Lost::Degraded;
        }
        let deadline = now.saturating_add(stall);
        self.state = State::Reconnecting { deadline };
        Lost::Stalling { deadline }
    }

    /// A server that rejects the handshake is reachable, so waiting out the
    /// window would only delay the failure. The probe keeps running.
    ///
    /// Only the current probe may cut a window short this way. The outcome of an
    /// old attempt is discarded like the frames of an old connection.
    pub fn degrade(&mut self, probe: u64) -> bool {
        if self.owns(probe) && matches!(self.state, State::Reconnecting { .. }) {
            self.state = State::Degraded;
            return true;
        }
        false
    }

    /// Only a mount that waits for a connection, and only its current probe,
    /// may install one. Cancelling an attempt is not synchronous, so a
    /// handshake can arrive after the mount was torn down, after a teardown
    /// paused the recovery, or after a replacement attempt took the place.
    /// `Err(connection)` hands the connection back for the adapter to bury, so
    /// a mount never has two live sessions.
    pub fn install(&mut self, probe: u64, generation: u64, connection: C) -> Result<(), C> {
        let wanted = matches!(self.state, State::Reconnecting { .. } | State::Degraded);
        if self.recovery != Recovery::Running || !wanted || !self.owns(probe) {
            return Err(connection);
        }
        self.state = State::Connected {
            generation,
            connection,
        };
        self.probe = None;
        Ok(())
    }

    pub fn take_generation(&mut self) -> u64 {
        let generation = self.next_generation;
        self.next_generation += 1;
        generation
    }

    /// A teardown has the bar and an ended mount is past recovering, so neither
    /// gets a task here. `Some(token)` is the token that the adapter spawns the
    /// attempt under.
    pub fn start_probe(&mut self) -> Option<u64> {
        if self.recovery != Recovery::Running
            || self.probe.is_some()
            || matches!(self.state, State::Closed)
        {
            return None;
        }
        let token = self.next_probe;
        self.next_probe += 1;
        self.probe = Some(token);
        Some(token)
    }

    /// A cancellation takes effect at the next suspension, so a task already past
    /// its last one runs to its end. A refused teardown leaves such a task behind
    /// ([`Machine::pause_recovery`] retires it and [`Machine::resume_recovery`]
    /// starts its replacement), and the survivor must not install a connection,
    /// end a window, or clear the handle of its replacement. Every transition of a
    /// probe checks this first.
    #[must_use]
    pub fn owns(&self, probe: u64) -> bool {
        self.probe == Some(probe)
    }

    /// Inside the window the remainder of the window is the bound, so a peer that
    /// never finishes the handshake cannot hold the mount past its deadline.
    #[must_use]
    pub fn attempt_bound(&self, probe: u64, now: Instant) -> Option<Duration> {
        if !self.owns(probe) {
            return None;
        }
        match self.state {
            State::Reconnecting { deadline } => Some(deadline.saturating_duration_since(now)),
            State::Degraded => Some(DEGRADED_ATTEMPT_BOUND),
            State::Connected { .. } | State::Closed => None,
        }
    }

    pub fn close(&mut self) -> Option<C> {
        self.recovery = Recovery::Ended;
        self.probe = None;
        match core::mem::replace(&mut self.state, State::Closed) {
            State::Connected { connection, .. } => Some(connection),
            State::Reconnecting { .. } | State::Degraded | State::Closed => None,
        }
    }

    /// Cancels the reconnect attempt and stops stalling, as the first step of a
    /// teardown that finds the mount Reconnecting or Degraded. Recovery ends from
    /// here on from every phase, because this teardown never comes back: a server
    /// breaking away afterwards must neither start a probe behind it nor open a
    /// window. A Connected mount keeps its connection, which the required teardown
    /// order closes after the kernel unmount. Returns whether the mount closed
    /// here.
    pub fn stop_reconnecting(&mut self) -> bool {
        self.recovery = Recovery::Ended;
        self.probe = None;
        let closed = matches!(self.state, State::Reconnecting { .. } | State::Degraded);
        if closed {
            self.state = State::Closed;
        }
        closed
    }

    /// Cancels the reconnect attempt and its backoff without ending the mount, as
    /// the first step of an ordinary unmount. The bar is up until the pause is
    /// lifted, so a connection dying mid-unmount cannot start a probe and an
    /// attempt past its last suspension cannot install itself. The phase is left as
    /// it was, because the teardown may yet be refused.
    pub fn pause_recovery(&mut self) {
        // An ended recovery is never handed back, so it is never taken away either.
        if self.recovery == Recovery::Running {
            self.recovery = Recovery::Paused;
        }
        self.probe = None;
    }

    /// Starts the recovery again after a refused teardown. Only a pause is lifted:
    /// a Connected or Closed mount has nothing to recover, and an ended recovery is
    /// never resumed. `Some(token)` is the replacement attempt to spawn.
    pub fn resume_recovery(&mut self) -> Option<u64> {
        if self.recovery != Recovery::Paused {
            return None;
        }
        self.recovery = Recovery::Running;
        if matches!(self.state, State::Reconnecting { .. } | State::Degraded) {
            return self.start_probe();
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const STALL: Duration = Duration::from_secs(5);
    const START: Instant = Instant::ORIGIN;
    const FIRST: &str = "the first connection";
    const NEXT: &str = "the replacement connection";

    fn at(secs: u64) -> Instant {
        Instant::from_nanos(secs * 1_000_000_000)
    }

    fn machine() -> Machine<&'static str> {
        Machine::connected(FIRST)
    }

    #[test]
    fn a_mount_starts_connected_over_the_first_generation() {
        let machine = machine();
        assert_eq!(machine.phase(), Phase::Connected);
        assert_eq!(machine.connected_generation(), Some(FIRST_GENERATION));
        assert_eq!(
            machine.serve(),
            Serve::Now { connection: &FIRST },
            "and the request it serves goes over the connection it was given"
        );
    }

    #[test]
    fn cleanup_for_a_reference_goes_out_only_within_its_session() {
        let mut machine = machine();
        assert_eq!(machine.serving(FIRST_GENERATION), Some(&FIRST));
        assert_eq!(machine.serving(2), None, "a session the mount never had");

        assert!(matches!(
            machine.lost(FIRST_GENERATION, START, STALL),
            Lost::Stalling { .. }
        ));
        assert_eq!(machine.serving(FIRST_GENERATION), None);
        let probe = machine.start_probe().expect("a probe");
        let next = machine.take_generation();
        assert!(machine.install(probe, next, NEXT).is_ok());
        assert_eq!(machine.serving(next), Some(&NEXT));
        assert_eq!(
            machine.serving(FIRST_GENERATION),
            None,
            "the next session never counted a reference of the first"
        );

        assert_eq!(machine.close(), Some(NEXT));
        assert_eq!(machine.serving(next), None);
    }

    #[test]
    fn only_the_generation_the_mount_holds_can_lose_it() {
        let mut machine = machine();
        assert_eq!(machine.lost(7, START, STALL), Lost::Ignored);
        assert_eq!(machine.phase(), Phase::Connected);
        assert_eq!(
            machine.lost(1, START, STALL),
            Lost::Stalling { deadline: at(5) }
        );
        assert_eq!(machine.lost(1, at(1), STALL), Lost::Ignored);
    }

    #[test]
    fn a_zero_window_is_fail_fast_and_still_wants_a_probe() {
        let mut machine = machine();
        let lost = machine.lost(1, START, Duration::ZERO);
        assert_eq!(lost, Lost::Degraded);
        assert!(lost.wants_probe(), "what zero removes is the waiting");
        assert_eq!(machine.phase(), Phase::Degraded);
        assert_eq!(machine.serve(), Serve::Fail);
        assert_eq!(machine.start_probe(), Some(1));
    }

    #[test]
    fn the_deadline_wins_every_tie() {
        let mut machine = machine();
        let Lost::Stalling { deadline } = machine.lost(1, START, STALL) else {
            panic!("the mount stalls");
        };
        assert_eq!(machine.serve(), Serve::Stall { deadline });
        assert_eq!(machine.woke(deadline, at(4)), Woke::Retry);
        assert_eq!(machine.phase(), Phase::Reconnecting);

        // A handshake completing in the very instant the window closes does not
        // save the caller that waited it out.
        let probe = machine.start_probe().expect("a probe");
        assert!(machine.install(probe, 2, NEXT).is_ok());
        assert_eq!(machine.phase(), Phase::Connected);
        assert_eq!(
            machine.woke(deadline, deadline),
            Woke::Expired { degraded: false },
            "the caller's window closed, whatever else happened in that instant"
        );
        assert_eq!(
            machine.phase(),
            Phase::Connected,
            "and a mount that is serving again is not degraded by that caller"
        );
    }

    #[test]
    fn the_first_caller_past_the_deadline_degrades_the_mount() {
        let mut machine = machine();
        let Lost::Stalling { deadline } = machine.lost(1, START, STALL) else {
            panic!("the mount stalls");
        };
        assert_eq!(
            machine.woke(deadline, at(5)),
            Woke::Expired { degraded: true }
        );
        assert_eq!(machine.phase(), Phase::Degraded);
        assert_eq!(
            machine.woke(deadline, at(6)),
            Woke::Expired { degraded: false },
            "the window closes once, and the callers behind it are simply failed"
        );
        assert_eq!(machine.serve(), Serve::Fail);
    }

    #[test]
    fn the_window_bounds_an_attempt_and_the_degraded_schedule_takes_over() {
        let mut machine = machine();
        machine.lost(1, START, STALL);
        let probe = machine.start_probe().expect("a probe");
        assert_eq!(machine.schedule(), Schedule::Stalling);
        assert_eq!(
            machine.attempt_bound(probe, at(1)),
            Some(Duration::from_secs(4))
        );
        assert_eq!(
            machine.attempt_bound(probe + 1, at(1)),
            None,
            "a superseded attempt has nothing left to do"
        );
        assert_eq!(
            machine.attempt_bound(probe, at(9)),
            Some(Duration::ZERO),
            "an attempt with no window left dials for no time at all"
        );
        assert!(machine.expire(at(9)));
        assert_eq!(machine.schedule(), Schedule::Degraded);
        assert_eq!(
            machine.attempt_bound(probe, at(9)),
            Some(DEGRADED_ATTEMPT_BOUND)
        );
        assert!(!machine.expire(at(10)), "a window closes once");
    }

    #[test]
    fn only_the_current_probe_owns_the_recovery() {
        let mut machine = machine();
        assert!(!machine.owns(1), "a mount with no probe running owns none");
        machine.lost(1, START, STALL);
        let first = machine.start_probe().expect("a probe");
        assert!(machine.owns(first));
        assert_eq!(machine.start_probe(), None, "one attempt at a time");

        // A refused teardown leaves a cancelled attempt that may still be running.
        // Only the replacement may transition the mount.
        machine.pause_recovery();
        assert!(!machine.owns(first), "the cancelled attempt is retired");
        assert_eq!(machine.recovery(), Recovery::Paused);
        assert_eq!(
            machine.install(first, 2, NEXT),
            Err(NEXT),
            "a paused mount installs nothing, and hands the connection back"
        );
        let second = machine.resume_recovery().expect("the replacement attempt");
        assert_ne!(second, first);
        assert!(!machine.owns(first));
        assert!(!machine.degrade(first));
        assert_eq!(machine.install(first, 2, NEXT), Err(NEXT));
        assert!(machine.install(second, 2, NEXT).is_ok());
        assert_eq!(machine.connected_generation(), Some(2));
        assert_eq!(machine.serve(), Serve::Now { connection: &NEXT });
    }

    #[test]
    fn a_refusal_cuts_the_window_short_and_the_probe_runs_on() {
        let mut machine = machine();
        machine.lost(1, START, STALL);
        let probe = machine.start_probe().expect("a probe");
        assert!(machine.degrade(probe));
        assert_eq!(machine.phase(), Phase::Degraded);
        assert!(!machine.degrade(probe), "a window is cut short once");
        assert!(
            machine.attempt_bound(probe, at(1)).is_some(),
            "the configuration may come back, so the probe keeps running"
        );
        assert!(machine.install(probe, 2, NEXT).is_ok());
    }

    #[test]
    fn a_teardown_that_never_comes_back_stops_everything() {
        let mut machine = machine();
        machine.lost(1, START, STALL);
        let probe = machine.start_probe().expect("a probe");
        assert!(
            machine.stop_reconnecting(),
            "the mount closed here and its phase change is owed an announcement"
        );
        assert!(!machine.owns(probe), "the attempt in flight is retired");
        assert_eq!(machine.phase(), Phase::Closed);
        assert_eq!(machine.recovery(), Recovery::Ended);
        assert_eq!(machine.start_probe(), None);
        assert_eq!(
            machine.resume_recovery(),
            None,
            "an ended recovery is final"
        );
        assert_eq!(machine.serve(), Serve::Fail);
    }

    #[test]
    fn a_death_behind_a_teardown_ends_the_mount_instead_of_stalling() {
        let mut machine = machine();
        assert!(
            !machine.stop_reconnecting(),
            "a connected mount unmounts the ordinary way"
        );
        assert_eq!(machine.phase(), Phase::Connected);
        assert_eq!(
            machine.serve(),
            Serve::Now { connection: &FIRST },
            "and it keeps serving over the connection it holds"
        );
        assert_eq!(machine.lost(1, START, STALL), Lost::Closed);
        assert_eq!(machine.phase(), Phase::Closed);
    }

    #[test]
    fn closing_retires_the_probe_and_nothing_reconnects() {
        let mut machine = machine();
        machine.lost(1, START, STALL);
        let probe = machine.start_probe().expect("a probe");
        assert_eq!(
            machine.close(),
            None,
            "a mount that lost its connection has none to bury"
        );
        assert!(!machine.owns(probe), "the attempt in flight is retired");
        assert_eq!(machine.phase(), Phase::Closed);
        assert_eq!(machine.install(probe, 2, NEXT), Err(NEXT));
        assert_eq!(machine.close(), None);
    }

    #[test]
    fn closing_a_connected_mount_hands_its_connection_back_to_be_buried() {
        let mut machine = machine();
        assert_eq!(machine.close(), Some(FIRST));
        assert_eq!(machine.phase(), Phase::Closed);
        assert_eq!(
            machine.close(),
            None,
            "a connection is handed back once, and only to whoever closed the mount"
        );
        assert_eq!(machine.serve(), Serve::Fail);
    }

    #[test]
    fn generations_are_monotonic_across_every_attempt() {
        let mut machine = machine();
        assert_eq!(machine.take_generation(), 2);
        assert_eq!(machine.take_generation(), 3);
        assert_eq!(machine.take_generation(), 4);
    }
}
