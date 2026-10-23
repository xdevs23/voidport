use std::path::Path;
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, channel};
use std::time::{Duration, Instant};

use voidport_control::client::{ClientError, Timeouts};

use voidport_tui::client::{Backoff, Command, Session, Worker};
use voidport_tui::event::{Effect, Event};
use voidport_tui::model::{LaunchNotes, Mode, Model, Screen};
use voidport_tui::tail::Tail;
use voidport_tui::update::update;

pub const PATIENCE: Duration = Duration::from_secs(10);

const QUIET: Duration = Duration::from_millis(100);

#[derive(Debug)]
pub struct Harness {
    pub model: Model,
    worker: Worker,
    events: Receiver<Event>,
    tail: Tail,
    /// With this sender in place, the channel is open also once the worker has
    /// stopped.
    sender: Sender<Event>,
}

impl Harness {
    pub fn attach(socket: &Path) -> Result<Self, ClientError> {
        Self::with(socket, Timeouts::default(), Backoff::default())
    }

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
                Effect::Suspend | Effect::Quit => {}
            }
        }
    }

    pub fn focus(&mut self, screen: Screen) {
        self.model.screen = screen;
        self.feed(Event::Tick);
    }

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
                Err(RecvTimeoutError::Timeout) => self.feed(Event::Tick),
                Err(RecvTimeoutError::Disconnected) => return predicate(&self.model),
            }
        }
    }

    pub fn settle(&mut self, predicate: impl Fn(&Model) -> bool) -> bool {
        self.until(PATIENCE, predicate)
    }

    pub fn stop(&mut self) {
        self.worker.stop();
    }
}
