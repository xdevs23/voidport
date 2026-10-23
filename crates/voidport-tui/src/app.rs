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

pub const TICK: Duration = Duration::from_secs(1);

pub const SHUTDOWN_GRACE: Duration = Duration::from_secs(30);

#[derive(Clone, Debug)]
pub struct Options {
    pub socket: PathBuf,
    pub timeouts: Timeouts,
    pub backoff: Backoff,
    pub tick: Duration,
}

impl Options {
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

/// The server crate depends on this one, so supervision of the daemon is
/// expressed as three plain capabilities.
pub struct Serving {
    pub notes: Option<LaunchNotes>,
    pub shutdown: Box<dyn FnOnce() + Send>,
    pub stopped: Receiver<Result<(), String>>,
}

impl std::fmt::Debug for Serving {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Serving")
            .field("notes", &self.notes)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub enum Presentation {
    Attach,
    Serving(Serving),
}

#[derive(Clone, Debug)]
pub struct Stopper(Sender<Event>);

impl Stopper {
    pub fn stop(&self) {
        let _ = self.0.send(Event::Stop);
    }
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Raised before the terminal is touched.
    #[error(transparent)]
    Connect(#[from] ClientError),
    #[error("the terminal could not be used")]
    Terminal(#[source] std::io::Error),
    #[error("the server stopped: {0}")]
    Server(String),
}

/// `ready` is called with a [`Stopper`] once the event channel exists and
/// before the terminal is taken over.
pub fn run(
    options: &Options,
    presentation: Presentation,
    ready: impl FnOnce(Stopper),
) -> Result<(), Error> {
    // A socket that is not there is a plain message on an ordinary terminal.
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
    drop(sender);

    // A quit and a failure end in one order: restore the terminal, shut the
    // server down unless it already stopped, cancel the client worker, join
    // the server, and report.
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

#[derive(Debug)]
enum Stopped {
    Quit,
    ServerStopped(Option<String>),
}

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
    let mut tail = Tail::new();
    terminal.draw(model).map_err(Error::Terminal)?;
    while !model.finished {
        let event = match events.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(event) => event,
            Err(RecvTimeoutError::Timeout) => {
                deadline = Instant::now() + tick;
                Event::Tick
            }
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

fn join_server(events: &Receiver<Event>, outcome: Option<&Stopped>) -> Result<(), Error> {
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
