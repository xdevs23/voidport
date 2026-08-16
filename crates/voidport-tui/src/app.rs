//! The event loop: effects at the edge, the reducer in the middle.
//!
//! The loop owns everything impure — the terminal, the worker thread, the
//! clock — and does nothing else with them: it turns what arrives into an
//! [`Event`], hands it to [`update`](crate::update::update), and runs the
//! [`Effect`]s that come back. Nothing decides anything here.
//!
//! Two launches share it:
//!
//! * **attach** — connect to a running server; quitting disconnects and leaves
//!   it serving;
//! * **serve-and-present** — a server this process launched is presented in
//!   the foreground; quitting shuts it down, and a server that dies on its own
//!   takes the interface down the failure path.
//!
//! The failure path is one path, in one order (design: "Serve-and-present
//! supervision"): restore the terminal, initiate shutdown, cancel the client
//! worker, join the daemon, and report. The caller prints and exits nonzero.

use std::path::PathBuf;
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, channel};
use std::time::{Duration, Instant};

use voidport_control::client::{ClientError, Timeouts};

use crate::client::{Backoff, Command, Session, Worker};
use crate::event::{Effect, Event};
use crate::model::{LaunchNotes, Mode, Model};
use crate::tail::Tail;
use crate::terminal::{Input, Terminal};
use crate::update::update;

/// The shared freshness tick: every visible view re-reads this often.
pub const TICK: Duration = Duration::from_secs(1);

/// How long the interface waits for a presented server to stop before giving
/// up on it.
pub const SHUTDOWN_GRACE: Duration = Duration::from_secs(30);

/// How the interface was launched, and everything it needs.
#[derive(Clone, Debug)]
pub struct Options {
    /// The control socket to talk to.
    pub socket: PathBuf,
    /// The client's finite waits.
    pub timeouts: Timeouts,
    /// The reconnection schedule.
    pub backoff: Backoff,
    /// The freshness tick.
    pub tick: Duration,
}

impl Options {
    /// Options for one control socket, everything else at its default.
    #[must_use]
    pub fn new(socket: impl Into<PathBuf>) -> Self {
        Self {
            socket: socket.into(),
            timeouts: Timeouts::default(),
            backoff: Backoff::default(),
            tick: TICK,
        }
    }
}

/// A server this process launched and is presenting.
///
/// The daemon itself is the caller's: this crate cannot depend on the server
/// crate (the server's binary depends on *this* one), so supervision is
/// expressed as three plain capabilities.
pub struct Serving {
    /// What a seeded launch has to tell its operator.
    pub notes: Option<LaunchNotes>,
    /// Asks the server to shut down cleanly. Called once.
    pub shutdown: Box<dyn FnOnce() + Send>,
    /// Resolves exactly once, when the server has stopped, with the failure it
    /// stopped of.
    pub stopped: Receiver<Result<(), String>>,
}

impl std::fmt::Debug for Serving {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Serving")
            .field("notes", &self.notes)
            .finish_non_exhaustive()
    }
}

/// What the interface is presenting.
#[derive(Debug)]
pub enum Presentation {
    /// A server somebody else launched.
    Attach,
    /// A server this process launched.
    Serving(Serving),
}

/// A handle that asks the interface to stop from outside — a signal handler,
/// typically.
#[derive(Clone, Debug)]
pub struct Stopper(Sender<Event>);

impl Stopper {
    /// Asks the interface to stop, as if the operator had quit.
    pub fn stop(&self) {
        let _ = self.0.send(Event::Stop);
    }
}

/// Why the interface ended other than by quitting.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The control socket could not be reached. Raised before the terminal is
    /// touched.
    #[error(transparent)]
    Connect(#[from] ClientError),
    /// The terminal could not be taken over, or drawn to.
    #[error("the terminal could not be used")]
    Terminal(#[source] std::io::Error),
    /// The presented server failed.
    #[error("the server stopped: {0}")]
    Server(String),
}

/// Runs the interface until the operator quits, the server dies, or something
/// outside asks it to stop.
///
/// `ready` is called with a [`Stopper`] once the event channel exists and
/// before the terminal is taken over: that is where a caller wires SIGTERM.
///
/// # Errors
///
/// Returns [`Error::Connect`] for a socket that cannot be reached — before the
/// terminal is touched, so the caller may simply print it — [`Error::Terminal`]
/// if the terminal cannot be used, and [`Error::Server`] if a presented server
/// failed.
pub fn run(
    options: &Options,
    presentation: Presentation,
    ready: impl FnOnce(Stopper),
) -> Result<(), Error> {
    // Before anything is taken over: a socket that is not there is a plain
    // message on an ordinary terminal.
    let session = Session::connect_with(&options.socket, options.timeouts)?;

    let (sender, events) = channel();
    ready(Stopper(sender.clone()));

    let (mode, notes, supervision) = match presentation {
        Presentation::Attach => (Mode::Attach, None, None),
        Presentation::Serving(serving) => {
            let Serving {
                notes,
                shutdown,
                stopped,
            } = serving;
            // One relay thread turns "the server stopped" into an event, so
            // the loop learns about it the same way it learns about anything.
            std::thread::spawn({
                let sender = sender.clone();
                move || {
                    let reason = match stopped.recv() {
                        Ok(Ok(())) => None,
                        Ok(Err(reason)) => Some(reason),
                        Err(_) => Some("the server thread ended unexpectedly".to_owned()),
                    };
                    let _ = sender.send(Event::ServerStopped { reason });
                }
            });
            (Mode::Serving, notes, Some(shutdown))
        }
    };

    let mut model = Model::new(mode, options.socket.display().to_string(), notes);
    let mut worker = Worker::spawn(session, options.timeouts, options.backoff, sender.clone());
    let mut input = Input::spawn(sender.clone());
    let mut terminal = Terminal::acquire().map_err(Error::Terminal)?;
    if let Ok(size) = terminal.size() {
        model.size = size;
    }

    let outcome = pump(
        &mut model,
        &mut terminal,
        &worker,
        &events,
        &sender,
        options.tick,
    );
    // The loop is over, so nothing here posts events any more: the handle it
    // kept for the log reader goes, leaving the channel to the threads that
    // are still being wound down.
    drop(sender);

    // The failure order, and the quit order, are the same order: the terminal
    // comes back first, whatever else is about to happen.
    let _ = terminal.restore();
    drop(terminal);
    input.stop();

    let server = match supervision {
        None => Ok(()),
        Some(shutdown) => {
            let stopped = matches!(outcome, Ok(Stopped::ServerStopped(_)));
            if !stopped {
                shutdown();
            }
            worker.stop();
            join_server(&events, outcome.as_ref().ok())
        }
    };
    worker.stop();

    match outcome {
        Err(error) => Err(error),
        Ok(_) => server,
    }
}

/// Why the loop ended.
#[derive(Debug)]
enum Stopped {
    /// The operator quit, or something outside asked us to.
    Quit,
    /// The presented server stopped while the interface was running.
    ServerStopped(Option<String>),
}

/// The loop itself: draw, wait, reduce, run effects.
fn pump(
    model: &mut Model,
    terminal: &mut Terminal,
    worker: &Worker,
    events: &Receiver<Event>,
    sender: &Sender<Event>,
    tick: Duration,
) -> Result<Stopped, Error> {
    let mut deadline = Instant::now() + tick;
    let mut stopped = Stopped::Quit;
    // The one file the interface reads. It lives here, with the socket and the
    // clock, because the reducer may not read anything.
    let mut tail = Tail::new();
    terminal.draw(model).map_err(Error::Terminal)?;
    while !model.finished {
        let event = match events.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(event) => event,
            Err(RecvTimeoutError::Timeout) => {
                deadline = Instant::now() + tick;
                Event::Tick
            }
            // Every sender is gone: nothing can arrive any more.
            Err(RecvTimeoutError::Disconnected) => break,
        };
        if let Event::ServerStopped { reason } = &event {
            stopped = Stopped::ServerStopped(reason.clone());
        }
        for effect in update(model, event) {
            match effect {
                Effect::Fetch(fetch) => worker.send(Command::Fetch(fetch)),
                Effect::Mutate {
                    correlation,
                    request,
                } => worker.send(Command::Mutate {
                    correlation,
                    request,
                }),
                // Posted instead of folded in place: a read is an answer from
                // outside, and it reaches the reducer the way every other
                // answer does.
                Effect::ReadLog { path } => {
                    let _ = sender.send(Event::LogRead(tail.read(&path)));
                }
                Effect::Suspend => terminal.suspend(model).map_err(Error::Terminal)?,
                Effect::Quit => model.finished = true,
            }
        }
        terminal.draw(model).map_err(Error::Terminal)?;
    }
    Ok(stopped)
}

/// Waits for a presented server to finish stopping.
fn join_server(events: &Receiver<Event>, outcome: Option<&Stopped>) -> Result<(), Error> {
    // The loop may already have seen it stop; then there is nothing to wait
    // for and the reason is the one it carried.
    if let Some(Stopped::ServerStopped(reason)) = outcome {
        return match reason {
            Some(reason) => Err(Error::Server(reason.clone())),
            None => Err(Error::Server(
                "the server stopped while the interface was running".to_owned(),
            )),
        };
    }
    let deadline = Instant::now() + SHUTDOWN_GRACE;
    loop {
        match events.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(Event::ServerStopped { reason: None }) => return Ok(()),
            Ok(Event::ServerStopped { reason: Some(why) }) => return Err(Error::Server(why)),
            Ok(_) => {}
            Err(RecvTimeoutError::Timeout) => {
                return Err(Error::Server(format!(
                    "it did not stop within {SHUTDOWN_GRACE:?}"
                )));
            }
            Err(RecvTimeoutError::Disconnected) => {
                return Err(Error::Server(
                    "the server thread ended unexpectedly".to_owned(),
                ));
            }
        }
    }
}
