//! The reconnect state machine: what a mount does when its server breaks away.
//!
//! Every transition is a method here and a verdict for the adapter to perform.
//! The machine owns the phase, the one monotonic stall deadline, the
//! generations connections are known by, the connection the mount is installed
//! over, the probe tokens attempts are known by, and the bar a teardown raises.
//! It owns no socket, no task and no clock: instants arrive as arguments, and
//! the deadline comparisons — the tie-break above all — are made here on those
//! arguments, never by an adapter.
//!
//! The connection is the adapter's own object, held as the opaque value `C` —
//! the machine never looks inside it, exactly as the request table never looks
//! inside a wakeup. Holding it is what keeps "whether a connection is
//! installed" and "which connection that is" one fact under one lock: the
//! machine hands it out to serve a request over, and hands it back when the
//! mount gives it up.
//!
//! The adapter keeps beside it what a value cannot carry: the handle the probe
//! token names, and the prose reason a phase carries.

use core::time::Duration;

use crate::backoff::{DEGRADED_ATTEMPT_BOUND, Schedule};
use crate::time::Instant;

/// The generation the *first* connection carries, which
/// [`Machine::connected`] has already handed out.
///
/// A plain number and not an accessor, because it is the same for every mount
/// and says nothing about what a mount is connected over.
pub const FIRST_GENERATION: u64 = 1;

/// What a mount is doing right now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    /// A connection is installed; requests flow.
    Connected,
    /// The server broke away; requests stall until the window closes.
    Reconnecting,
    /// The window closed; requests fail at once and the probe runs on.
    Degraded,
    /// The mount was torn down.
    Closed,
}

/// Whether a mount is allowed to recover, and for how long it is not.
///
/// The barrier a teardown needs, and the reason cancelling the probe is not
/// enough on its own: aborting a task is not synchronous, and a connection
/// dying *during* a teardown would otherwise start a fresh one behind it.
/// Anything but [`Recovery::Running`] means nothing dials and nothing is
/// installed, whatever the phase says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recovery {
    /// The ordinary state: a death opens the stall window and starts a probe.
    Running,
    /// A teardown is under way and may yet be refused. Nothing dials, but a
    /// death still opens the window a refused teardown is owed when
    /// [`Machine::resume_recovery`] hands the probe back.
    Paused,
    /// A teardown that never comes back. Nothing dials, and a death arriving
    /// now ends the mount instead of opening a window nobody will wait out.
    Ended,
}

/// What a mount is doing, with what the phase carries.
#[derive(Debug)]
enum State<C> {
    Connected {
        /// The generation the installed connection is known by.
        generation: u64,
        /// The connection itself, as the adapter handed it over.
        connection: C,
    },
    Reconnecting {
        /// The one deadline every stalled request shares.
        deadline: Instant,
    },
    Degraded,
    Closed,
}

/// What a request that wants a connection is owed.
///
/// The connection is lent, not given: it stays installed, so a caller takes
/// whatever reference of its own it needs while it still holds the lock the
/// machine changes under.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Serve<'a, C> {
    /// Serve it over this connection, which is the one installed.
    Now {
        /// The connection the adapter must serve it over.
        connection: &'a C,
    },
    /// Stall it: wait for a phase change, and no later than this instant.
    Stall {
        /// The window's end, shared by every stalled request.
        deadline: Instant,
    },
    /// Fail it: the window has closed, or the mount has.
    Fail,
}

/// What a stalled caller's wait meant, decided on the instant after it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Woke {
    /// The caller's window closed: it is owed its failure, whatever else
    /// happened in that instant. `degraded` says whether this is the call that
    /// closed the window, which is what the adapter publishes and logs.
    Expired {
        /// Whether the mount moved to [`Phase::Degraded`] here.
        degraded: bool,
    },
    /// Short of the deadline: look at the phase again.
    Retry,
}

/// What a connection's death did to the mount.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lost {
    /// Nothing: an older generation, or a recovery already under way. Whatever
    /// that frame or error was, it cannot touch the replacement.
    Ignored,
    /// The mount is stalling until this instant, and wants a probe.
    Stalling {
        /// The window every request that arrives now shares.
        deadline: Instant,
    },
    /// The mount is failing requests at once and wants a probe: either it is
    /// fail-fast, or its window is zero.
    Degraded,
    /// The mount ended here: a teardown that never comes back was already under
    /// way, so there is nothing to stall for and nothing will dial again.
    Closed,
}

impl Lost {
    /// Whether this death leaves a mount that still wants a reconnect task.
    #[must_use]
    pub fn wants_probe(self) -> bool {
        matches!(self, Self::Stalling { .. } | Self::Degraded)
    }
}

/// The mount's phase, and the bookkeeping around it.
///
/// `C` is whatever the adapter serves a request over — a connection object in
/// userspace, whatever names a session in kernel space. The machine never looks
/// inside it.
#[derive(Debug)]
pub struct Machine<C> {
    state: State<C>,
    recovery: Recovery,
    /// The generation the next connection will carry. Monotonic.
    next_generation: u64,
    /// The token the next reconnect task will carry. Monotonic.
    next_probe: u64,
    /// The single reconnect task's token, if one is running.
    probe: Option<u64>,
}

impl<C> Machine<C> {
    /// The machine of a mount whose first handshake has just completed, over
    /// `connection`.
    ///
    /// That connection is generation 1 — the first the machine hands out — and
    /// the mount starts Connected over it, because a mount that could not be
    /// established is a mount error and never a mount that starts out degraded.
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

    /// What the mount is doing right now.
    #[must_use]
    pub fn phase(&self) -> Phase {
        match &self.state {
            State::Connected { .. } => Phase::Connected,
            State::Reconnecting { .. } => Phase::Reconnecting,
            State::Degraded => Phase::Degraded,
            State::Closed => Phase::Closed,
        }
    }

    /// The generation of the connection installed right now, if one is.
    ///
    /// The phase word alone cannot tell "never left Connected" from "died and
    /// came back": an observer that coalesces wakeups sees one `Connected` with
    /// nothing apparently changed. The generation is monotonic, so it makes
    /// that flap visible.
    #[must_use]
    pub fn connected_generation(&self) -> Option<u64> {
        match self.state {
            State::Connected { generation, .. } => Some(generation),
            _ => None,
        }
    }

    /// Whether recovery may run at all.
    #[must_use]
    pub fn recovery(&self) -> Recovery {
        self.recovery
    }

    /// Which schedule the probe's next backoff comes from.
    #[must_use]
    pub fn schedule(&self) -> Schedule {
        match self.state {
            State::Degraded => Schedule::Degraded,
            _ => Schedule::Stalling,
        }
    }

    /// What a request that wants a connection is owed right now.
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

    /// What a caller that stalled until `deadline` is owed, on the instant
    /// `now` its wait ended.
    ///
    /// **The deadline wins every tie.** A wakeup and the window's end can land
    /// in the same instant — a phase change published exactly as the timer
    /// fires — and a caller sent round the loop then would be served *after*
    /// its window, under scheduler delay arbitrarily long after it. So the
    /// clock, not the wakeup, decides what the wait meant, and it is read after
    /// the wait and never before, so nothing is failed early.
    pub fn woke(&mut self, deadline: Instant, now: Instant) -> Woke {
        if now < deadline {
            return Woke::Retry;
        }
        Woke::Expired {
            degraded: self.expire(now),
        }
    }

    /// Ends the stall if its deadline has passed, answering whether it did.
    ///
    /// Called by whoever notices first — a stalled caller whose wait ran out,
    /// or the probe between attempts — so the window's edge is the deadline
    /// itself, not whenever a task happened to be scheduled. It needs no probe
    /// identity for that reason: it reads the instant against the window the
    /// mount is in right now, so a late caller cannot end a window that is not
    /// the one it waited on.
    pub fn expire(&mut self, now: Instant) -> bool {
        match self.state {
            State::Reconnecting { deadline } if now >= deadline => {
                self.state = State::Degraded;
                true
            }
            _ => false,
        }
    }

    /// Records that the connection of `generation` is dead, and says what the
    /// mount does about it.
    ///
    /// This is where death observations coalesce: a reader task, a failed write
    /// and a caller that found a protocol fault all arrive here, and only the
    /// one naming the generation the mount currently holds does anything.
    ///
    /// `stall` of [`Duration::ZERO`] is fail-fast: the window closes the
    /// instant the server breaks away. The probe still runs, so a server that
    /// comes back is still picked up — what zero removes is the waiting, not
    /// the recovery.
    ///
    /// The mount lets the dead connection go here. It is not handed back,
    /// because whoever reports a death is holding the connection it is
    /// reporting — that is where the generation came from — and burying it is
    /// that caller's own next step.
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

    /// Ends the stall now, whatever the deadline says, answering whether it
    /// did.
    ///
    /// A server that answers the handshake with a refusal is reachable and says
    /// no: waiting out the window would only delay the failure a guest is owed.
    /// The probe keeps running, because the configuration may return.
    ///
    /// Only the mount's current probe may cut a window short this way: a
    /// refusal a cancelled attempt observed says nothing about the window a
    /// later death opened, and an old attempt's outcomes are discarded exactly
    /// as an old connection's frames are.
    pub fn degrade(&mut self, probe: u64) -> bool {
        if self.owns(probe) && matches!(self.state, State::Reconnecting { .. }) {
            self.state = State::Degraded;
            return true;
        }
        false
    }

    /// Installs a freshly handshaken connection, returning the mount to
    /// Connected.
    ///
    /// Only a mount that is *waiting* for a connection, and only the probe it
    /// currently owns, may install one. Cancelling an attempt is not
    /// synchronous — an aborted probe can already be past its last suspension —
    /// so a handshake can arrive here after the mount was torn down, after a
    /// teardown paused the recovery, or after a replacement attempt took this
    /// one's place. `Err(connection)` hands the connection straight back for
    /// the adapter to bury, which is what keeps a mount from ever holding two
    /// live sessions and splitting its callbacks across them, and what stops a
    /// superseded attempt from clearing the handle its replacement is cancelled
    /// through.
    ///
    /// # Errors
    ///
    /// The connection itself, when the mount would not take it.
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

    /// The generation the next connection carries.
    pub fn take_generation(&mut self) -> u64 {
        let generation = self.next_generation;
        self.next_generation += 1;
        generation
    }

    /// Starts the single reconnect task, if one is not already running and the
    /// mount is still in a position to want one.
    ///
    /// A teardown holds the bar and an ended mount is past recovering, so
    /// neither gets a task here — which is what stops a connection dying
    /// mid-teardown from putting a dialler behind it. `Some(token)` is the
    /// token the adapter must spawn the attempt under.
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

    /// Whether `probe` is the reconnect task the mount owns right now.
    ///
    /// Cancelling a task is not cancelling it *now*: a cancellation takes
    /// effect at the next suspension, so a task already past its last one runs
    /// to its end regardless. A refused teardown leaves exactly such a task
    /// behind — [`Machine::pause_recovery`] retires it and
    /// [`Machine::resume_recovery`] starts its replacement — and the survivor
    /// must not install a connection, end a window, or clear the handle
    /// belonging to the task that replaced it. Every transition a probe makes
    /// is therefore gated on this.
    #[must_use]
    pub fn owns(&self, probe: u64) -> bool {
        self.probe == Some(probe)
    }

    /// How long `probe`'s next attempt may take, or `None` when there is
    /// nothing left for it to do: the mount is serving again, it has ended, a
    /// teardown took the recovery away, or this attempt has been superseded.
    ///
    /// Inside the window the window's remainder is the bound, so a peer that
    /// accepts the socket and never finishes the handshake cannot hold the
    /// mount past its deadline; afterwards it is the degraded bound.
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

    /// Tears the mount down: nothing is ever written or reconnected again.
    ///
    /// Answers the connection the adapter must bury, if one was installed. The
    /// reconnect attempt is retired here too, and the adapter cancels the task
    /// its token named.
    pub fn close(&mut self) -> Option<C> {
        self.recovery = Recovery::Ended;
        self.probe = None;
        match core::mem::replace(&mut self.state, State::Closed) {
            State::Connected { connection, .. } => Some(connection),
            State::Reconnecting { .. } | State::Degraded | State::Closed => None,
        }
    }

    /// Cancels the reconnect attempt and its backoff, and stops stalling.
    ///
    /// The first step of a teardown that finds the mount Reconnecting or
    /// Degraded: nothing should be dialling or sleeping while the mountpoint is
    /// coming down, and every stalled caller is owed its failure now and not at
    /// the end of a window nobody is waiting out any more. A mount that is
    /// Connected keeps its connection — it is unmounted the ordinary way, and
    /// the required teardown order closes the connection only after the kernel
    /// unmount — but recovery *ends* from here on either way, because this
    /// teardown never comes back. That is what makes this terminal from every
    /// phase and not only from the two with an attempt in flight: a server
    /// breaking away in the moment after this call must neither start a probe
    /// behind the teardown nor open a window for callbacks the teardown is
    /// about to fail anyway.
    ///
    /// Answers whether the mount closed here, which is the phase change the
    /// adapter is owed an announcement of. A mount that was Connected keeps its
    /// connection, so there is never one to bury from here; the reconnect
    /// attempt is retired, and the adapter cancels the task its token named.
    pub fn stop_reconnecting(&mut self) -> bool {
        self.recovery = Recovery::Ended;
        self.probe = None;
        let closed = matches!(self.state, State::Reconnecting { .. } | State::Degraded);
        if closed {
            self.state = State::Closed;
        }
        closed
    }

    /// Cancels the reconnect attempt in flight and the backoff behind it,
    /// without ending the mount.
    ///
    /// The first step of an ordinary unmount, per the resilience contract:
    /// nothing may be dialling a server or sleeping out a backoff while the
    /// mountpoint is coming down. That bar holds until the pause is lifted, so
    /// a connection dying mid-unmount cannot start a probe either, and an
    /// attempt already past its last suspension cannot install itself. The
    /// phase is left exactly as it was, because the teardown may yet be
    /// refused.
    ///
    /// Retiring the cancelled task's token is what stops the attempt the
    /// cancellation cannot reach in time from transitioning the mount or
    /// displacing its replacement. The adapter cancels the task that token
    /// named; a mount that was Connected keeps its connection, so there is
    /// nothing to bury from here.
    pub fn pause_recovery(&mut self) {
        // A recovery that has already ended is never handed back, so it is
        // never taken away either: pausing lowers the bar it raised.
        if self.recovery == Recovery::Running {
            self.recovery = Recovery::Paused;
        }
        self.probe = None;
    }

    /// Starts the recovery again after a teardown that was refused.
    ///
    /// A mount left live, still ours, and still disconnected if it was, is owed
    /// the probe [`Machine::pause_recovery`] cancelled, and the bar that pause
    /// put up is lifted. A mount that is Connected or Closed has nothing to
    /// recover, and a recovery that *ended* is never resumed: only a pause is
    /// lifted here. `Some(token)` is the replacement attempt to spawn.
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
    /// What a mount is connected over, in these tests. The machine never looks
    /// inside a connection, so a name it can hand back is connection enough.
    const FIRST: &str = "the first connection";
    /// What a probe brings back.
    const NEXT: &str = "the replacement connection";

    fn at(secs: u64) -> Instant {
        Instant::from_nanos(secs * 1_000_000_000)
    }

    /// A mount whose first handshake has just completed.
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
    fn only_the_generation_the_mount_holds_can_lose_it() {
        let mut machine = machine();
        assert_eq!(machine.lost(7, START, STALL), Lost::Ignored);
        assert_eq!(machine.phase(), Phase::Connected);
        assert_eq!(
            machine.lost(1, START, STALL),
            Lost::Stalling { deadline: at(5) }
        );
        // A second observation of the same death, from another task, changes
        // nothing: the mount already moved on.
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
        // Short of the deadline, the caller looks again.
        assert_eq!(machine.woke(deadline, at(4)), Woke::Retry);
        assert_eq!(machine.phase(), Phase::Reconnecting);

        // A handshake that completes in the very instant the window closes
        // does not save the caller that waited it out.
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

        // What a refused teardown leaves behind: the attempt was cancelled and
        // its token retired, but a cancellation is not synchronous, so the task
        // may still be running. Only the replacement may transition the mount.
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
        // And it is the ordinary return to Connected from there.
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
        // A teardown from Connected keeps the connection but ends recovery.
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
