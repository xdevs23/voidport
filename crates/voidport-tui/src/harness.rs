//! The app loop with the terminal removed, for suites that drive the interface
//! against a real server.
//!
//! Three suites in this workspace need exactly this — this crate's own
//! client/reducer proofs, `voidport-ctl`'s two-operator freshness proof, and
//! `voidport`'s proofs against a real mount — and each of them used to carry its
//! own copy of the plumbing. A copy that drifts weakens whatever it proves
//! without failing: an [`Effect`] a copy forgets to run is a fetch that never
//! happens, and the freshness assertion above it then passes for the wrong
//! reason. So the plumbing lives here, beside the loop it mirrors, and there is
//! one of it.
//!
//! What this is **not** is a second interface: it owns no behaviour. It runs
//! [`update`](crate::update::update) and dispatches the effects exactly as
//! [`app`](crate::app) does, minus the two that need a terminal
//! ([`Effect::Suspend`]) or an exit ([`Effect::Quit`]) — both of which are
//! asserted through the model instead.
//!
//! It ships in the library instead of behind a feature because the consumers
//! are three separate crates' dev-dependencies: a feature they each enable
//! would be on for the whole workspace build anyway, and a module that is
//! sometimes there is worse to reason about than one that always is.

use std::path::Path;
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, channel};
use std::time::{Duration, Instant};

use voidport_control::client::{ClientError, Timeouts};

use crate::client::{Backoff, Command, Session, Worker};
use crate::event::{Effect, Event};
use crate::model::{LaunchNotes, Mode, Model, Screen};
use crate::tail::Tail;
use crate::update::update;

/// How long [`Harness::until`] waits by default.
pub const PATIENCE: Duration = Duration::from_secs(10);

/// How long the harness waits for an event before treating the quiet as a tick.
const QUIET: Duration = Duration::from_millis(100);

/// The interface's model, its worker and its events: the app loop without a
/// terminal.
#[derive(Debug)]
pub struct Harness {
    /// The model the tests assert on.
    pub model: Model,
    worker: Worker,
    events: Receiver<Event>,
    /// The log reader, exactly as the app loop owns it.
    tail: Tail,
    /// Kept so the channel stays open even once the worker has stopped, and so
    /// a log read has somewhere to post its answer.
    sender: Sender<Event>,
}

impl Harness {
    /// Attaches to a control socket with the product's own defaults.
    ///
    /// # Errors
    ///
    /// Propagates the connection failure, which is the same one the real
    /// launch reports before it takes the terminal over.
    pub fn attach(socket: &Path) -> Result<Self, ClientError> {
        Self::with(socket, Timeouts::default(), Backoff::default())
    }

    /// Attaches with explicit timeouts and backoff, for the cases that are
    /// about those.
    ///
    /// # Errors
    ///
    /// Propagates the connection failure.
    pub fn with(socket: &Path, timeouts: Timeouts, backoff: Backoff) -> Result<Self, ClientError> {
        let session = Session::connect_with(socket, timeouts)?;
        let (sender, events) = channel();
        let worker = Worker::spawn(session, timeouts, backoff, sender.clone());
        Ok(Self {
            model: Model::new(
                Mode::Attach,
                socket.display().to_string(),
                None::<LaunchNotes>,
            ),
            worker,
            events,
            tail: Tail::new(),
            sender,
        })
    }

    /// Feeds one event and runs the effects it produces.
    pub fn feed(&mut self, event: Event) {
        for effect in update(&mut self.model, event) {
            match effect {
                Effect::Fetch(fetch) => self.worker.send(Command::Fetch(fetch)),
                Effect::Mutate {
                    correlation,
                    request,
                } => self.worker.send(Command::Mutate {
                    correlation,
                    request,
                }),
                Effect::ReadLog { path } => {
                    let read = self.tail.read(&path);
                    let _ = self.sender.send(Event::LogRead(read));
                }
                // A test has no terminal to suspend and does not quit by
                // effect; both are asserted through the model.
                Effect::Suspend | Effect::Quit => {}
            }
        }
    }

    /// Focuses a screen, which re-reads what it shows.
    pub fn focus(&mut self, screen: Screen) {
        self.model.screen = screen;
        self.feed(Event::Tick);
    }

    /// Pumps events (and ticks) until `predicate` holds, or `patience` runs
    /// out.
    pub fn until(&mut self, patience: Duration, predicate: impl Fn(&Model) -> bool) -> bool {
        let deadline = Instant::now() + patience;
        loop {
            if predicate(&self.model) {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            match self.events.recv_timeout(QUIET) {
                Ok(event) => self.feed(event),
                // A quiet moment is a tick: the interface's own freshness
                // clock, driven by the test, not by the wall.
                Err(RecvTimeoutError::Timeout) => self.feed(Event::Tick),
                Err(RecvTimeoutError::Disconnected) => return predicate(&self.model),
            }
        }
    }

    /// [`Self::until`] with the shared [`PATIENCE`].
    pub fn settle(&mut self, predicate: impl Fn(&Model) -> bool) -> bool {
        self.until(PATIENCE, predicate)
    }

    /// Stops the worker, as quitting does.
    pub fn stop(&mut self) {
        self.worker.stop();
    }
}
