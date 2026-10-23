//! Expiry is recorded before preparing a successful dial for installation and
//! again after any failed attempt. A zero remaining bound expires the window
//! and resets backoff before another generation is allocated. Whether a new
//! probe starts its schedule over is set by the adapter before the probe runs.
//! The probe itself resets it only at the edge of the window.

use core::time::Duration;

use crate::backoff::Backoff;
use crate::handshake::Disposition;
use crate::reconnect::Machine;
use crate::time::Instant;

#[derive(Clone, Copy, Debug)]
pub enum Event {
    Continue,
    Dialed(Result<(), Disposition>),
    Prepared(bool),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Degraded {
    Expired,
    Refused,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Dial { generation: u64, bound: Duration },
    Publish(Degraded),
    Prepare,
    Install,
    Sleep(Duration),
    Stop,
}

#[derive(Clone, Copy, Debug)]
enum Step {
    Start,
    Attempt,
    Dialing,
    Succeeded,
    Preparing,
    Install,
    Failed(Disposition),
    Expire,
    Backoff,
    Done,
}

#[derive(Debug)]
pub struct Driver {
    token: u64,
    step: Step,
}

impl Driver {
    #[must_use]
    pub fn new(token: u64) -> Self {
        Self {
            token,
            step: Step::Start,
        }
    }

    /// Connection construction can fail after a successful handshake. That is
    /// still an attempt failure and must reach backoff without abandoning the
    /// probe token. Installation itself still requires the current probe token.
    pub fn advance<C>(
        &mut self,
        event: Event,
        machine: &mut Machine<C>,
        backoff: &mut Backoff,
        now: Instant,
    ) -> Action {
        self.step = match (self.step, event) {
            (Step::Dialing, Event::Dialed(Ok(()))) => Step::Succeeded,
            (Step::Dialing, Event::Dialed(Err(disposition))) => Step::Failed(disposition),
            (Step::Preparing, Event::Prepared(true)) => Step::Install,
            (Step::Preparing, Event::Prepared(false)) => Step::Expire,
            (step, Event::Continue) => step,
            _ => Step::Done,
        };
        loop {
            match self.step {
                Step::Start => {
                    if !machine.owns(self.token) {
                        self.step = Step::Done;
                        return Action::Stop;
                    }
                    self.step = Step::Attempt;
                }
                Step::Attempt => {
                    let Some(bound) = machine.attempt_bound(self.token, now) else {
                        self.step = Step::Done;
                        return Action::Stop;
                    };
                    if bound.is_zero() {
                        let expired = machine.expire(now);
                        backoff.restart();
                        if expired {
                            return Action::Publish(Degraded::Expired);
                        }
                        continue;
                    }
                    let generation = machine.take_generation();
                    self.step = Step::Dialing;
                    return Action::Dial { generation, bound };
                }
                Step::Succeeded => {
                    self.step = Step::Preparing;
                    if machine.expire(now) {
                        return Action::Publish(Degraded::Expired);
                    }
                    return Action::Prepare;
                }
                Step::Preparing => return Action::Prepare,
                Step::Install => {
                    self.step = Step::Done;
                    return Action::Install;
                }
                Step::Failed(disposition) => {
                    self.step = Step::Expire;
                    if disposition == Disposition::Degrade && machine.degrade(self.token) {
                        return Action::Publish(Degraded::Refused);
                    }
                }
                Step::Expire => {
                    self.step = Step::Backoff;
                    if machine.expire(now) {
                        return Action::Publish(Degraded::Expired);
                    }
                }
                Step::Backoff => {
                    self.step = Step::Attempt;
                    return Action::Sleep(backoff.next(machine.schedule()));
                }
                Step::Dialing | Step::Done => return Action::Stop,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reconnect::Phase;

    fn at(seconds: u64) -> Instant {
        Instant::from_nanos(seconds * 1_000_000_000)
    }

    fn setup() -> (Machine<()>, Backoff, Driver) {
        let mut machine = Machine::connected(());
        machine.lost(1, at(0), Duration::from_secs(5));
        let token = machine.start_probe().unwrap();
        (machine, Backoff::seeded(1), Driver::new(token))
    }

    #[test]
    fn deadline_precedes_preparation_and_installation() {
        let (mut machine, mut backoff, mut driver) = setup();
        assert!(matches!(
            driver.advance(Event::Continue, &mut machine, &mut backoff, at(0)),
            Action::Dial { generation: 2, .. }
        ));
        assert_eq!(
            driver.advance(Event::Dialed(Ok(())), &mut machine, &mut backoff, at(5)),
            Action::Publish(Degraded::Expired)
        );
        assert_eq!(machine.phase(), Phase::Degraded);
        assert_eq!(
            driver.advance(Event::Continue, &mut machine, &mut backoff, at(5)),
            Action::Prepare
        );
        assert_eq!(
            driver.advance(Event::Prepared(true), &mut machine, &mut backoff, at(5)),
            Action::Install
        );
        assert_eq!(
            driver.advance(Event::Continue, &mut machine, &mut backoff, at(5)),
            Action::Stop
        );
    }

    #[test]
    fn refusal_precedes_expiry_and_backoff() {
        let (mut machine, mut backoff, mut driver) = setup();
        driver.advance(Event::Continue, &mut machine, &mut backoff, at(0));
        assert_eq!(
            driver.advance(
                Event::Dialed(Err(Disposition::Degrade)),
                &mut machine,
                &mut backoff,
                at(5)
            ),
            Action::Publish(Degraded::Refused)
        );
        assert!(matches!(
            driver.advance(Event::Continue, &mut machine, &mut backoff, at(5)),
            Action::Sleep(_)
        ));
        assert_eq!(machine.phase(), Phase::Degraded);
    }

    #[test]
    fn allocation_failure_keeps_probe_and_retries_after_expiry() {
        let (mut machine, mut backoff, mut driver) = setup();
        driver.advance(Event::Continue, &mut machine, &mut backoff, at(0));
        assert_eq!(
            driver.advance(Event::Dialed(Ok(())), &mut machine, &mut backoff, at(1)),
            Action::Prepare
        );
        assert_eq!(
            driver.advance(Event::Prepared(false), &mut machine, &mut backoff, at(5)),
            Action::Publish(Degraded::Expired)
        );
        assert!(matches!(
            driver.advance(Event::Continue, &mut machine, &mut backoff, at(5)),
            Action::Sleep(_)
        ));
        assert!(matches!(
            driver.advance(Event::Continue, &mut machine, &mut backoff, at(6)),
            Action::Dial { generation: 3, .. }
        ));
    }

    #[test]
    fn zero_bound_resets_backoff_without_consuming_a_generation() {
        let (mut machine, mut backoff, mut driver) = setup();
        assert_eq!(
            driver.advance(Event::Continue, &mut machine, &mut backoff, at(5)),
            Action::Publish(Degraded::Expired)
        );
        assert!(matches!(
            driver.advance(Event::Continue, &mut machine, &mut backoff, at(5)),
            Action::Dial { generation: 2, .. }
        ));
        machine.close();
        driver.advance(
            Event::Dialed(Err(Disposition::Retry)),
            &mut machine,
            &mut backoff,
            at(5),
        );
        assert_eq!(
            driver.advance(Event::Continue, &mut machine, &mut backoff, at(6)),
            Action::Stop
        );
    }
}
