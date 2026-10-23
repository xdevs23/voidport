// SPDX-License-Identifier: GPL-2.0

use kernel::sync::Arc;
use voidport_session::probe::{Action as ProbeAction, Degraded, Driver, Event};

use super::{serve, Session, State};
use crate::clock::now;
use crate::connection::Death;
use crate::diag::{info_limited, warn_limited};
use crate::pool::{Member, Pool};
use crate::thread::Thread;

impl Session {
    fn start_probe(&self) -> Option<u64> {
        self.state.lock().machine.start_probe()
    }

    fn probe_action(
        &self,
        driver: &mut Driver,
        event: Event,
        reason: Option<Death>,
    ) -> ProbeAction {
        let mut state = self.state.lock();
        let State {
            machine, backoff, ..
        } = &mut *state;
        let action = driver.advance(event, machine, backoff, now());
        if let ProbeAction::Publish(cause) = action {
            match cause {
                Degraded::Expired => {
                    warn_limited!(
                        Transport,
                        "the server did not come back within the stall window"
                    )
                }
                Degraded::Refused => {
                    warn_limited!(Transport, "the server refuses to serve this mount");
                    state.reason = reason;
                }
            }
            state.bump();
            drop(state);
            self.changes.notify_all();
        }
        action
    }

    /// `Err` hands the pool back to be closed.
    fn install(&self, probe: u64, pool: Arc<Pool>) -> core::result::Result<(), Arc<Pool>> {
        let mut state = self.state.lock();
        let generation = pool.generation();
        state.machine.install(probe, generation, pool)?;
        state.reason = None;
        state.bump();
        drop(state);
        self.changes.notify_all();
        Ok(())
    }

    /// Installation either transfers ownership to the core or explicitly
    /// closes the rejected session, and returns whether it installed. It
    /// never changes the accepted generation's loss accounting when the probe
    /// was superseded.
    fn install_or_bury(&self, probe: u64, pool: Arc<Pool>) -> bool {
        match self.install(probe, pool) {
            Ok(()) => {
                info_limited!(Transport, "the connection is back");
                true
            }
            Err(pool) => {
                pool.end(|connection| connection.bury(Death::Closed));
                false
            }
        }
    }

    /// A thread that cannot be started is tried again after the backoff of the
    /// core, until the probe is no longer wanted.
    pub(super) fn start_probe_thread(self: &Arc<Self>) {
        let Some(probe) = self.start_probe() else {
            return;
        };
        loop {
            match self.spawn(
                c"voidport-probe",
                move |session| probe_thread(session, probe),
                || {},
            ) {
                Ok(()) => return,
                Err(error) => {
                    warn_limited!(
                        Transport,
                        "cannot start the reconnect thread ({error:?}); trying again"
                    )
                }
            }
            let delay = {
                let mut state = self.state.lock();
                if !state.machine.owns(probe) {
                    return;
                }
                let schedule = state.machine.schedule();
                state.backoff.next(schedule)
            };
            self.wait_backoff(delay);
        }
    }
}

fn probe_thread(session: Arc<Session>, probe: u64) {
    let _scope = crate::helpers::NoFsScope::enter();
    if let Some((pool, member)) = reconnect(&session, probe) {
        serve(session, pool, member);
    }
}

fn reconnect(session: &Arc<Session>, probe: u64) -> Option<(Arc<Pool>, Member)> {
    let mut driver = Driver::new(probe);
    let mut event = Event::Continue;
    let mut reason = None;
    let mut handshake = None;
    let mut opened = None;
    let mut generation = 0;
    loop {
        if Thread::should_stop() {
            return None;
        }
        match session.probe_action(&mut driver, event, reason.take()) {
            ProbeAction::Dial {
                generation: next,
                bound,
            } => {
                generation = next;
                event = match session.dialer.dial(Some(bound)) {
                    Ok(result) => {
                        handshake = Some(result);
                        Event::Dialed(Ok(()))
                    }
                    Err(error) => {
                        reason = Some(Death::Transport(error.errno()));
                        Event::Dialed(Err(error.disposition()))
                    }
                };
            }
            ProbeAction::Publish(_) => event = Event::Continue,
            ProbeAction::Prepare => {
                opened = handshake
                    .take()
                    .and_then(|dialed| Pool::open(generation, dialed).ok());
                event = Event::Prepared(opened.is_some());
            }
            ProbeAction::Install => {
                let (pool, member) = opened.take()?;
                return session
                    .install_or_bury(probe, pool.clone())
                    .then_some((pool, member));
            }
            ProbeAction::Sleep(wait) => {
                session.wait_backoff(wait);
                event = Event::Continue;
            }
            ProbeAction::Stop => return None,
        }
    }
}
