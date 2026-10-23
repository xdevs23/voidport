use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, channel};
use std::thread::JoinHandle;
use std::time::Duration;

use voidport_control::Request;
use voidport_control::client::{ClientError, Timeouts};

use super::Session;
use crate::event::{Correlation, Event, Failure, Fetch};

pub const SLICE: Duration = Duration::from_millis(50);

pub const INITIAL_BACKOFF: Duration = Duration::from_millis(500);

pub const MAX_BACKOFF: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Backoff {
    pub initial: Duration,
    pub max: Duration,
}

impl Default for Backoff {
    fn default() -> Self {
        Self {
            initial: INITIAL_BACKOFF,
            max: MAX_BACKOFF,
        }
    }
}

impl Backoff {
    fn next(self, previous: Option<Duration>) -> Duration {
        match previous {
            None => self.initial,
            Some(previous) => (previous * 2).min(self.max),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Command {
    Fetch(Fetch),
    Mutate {
        correlation: Correlation,
        request: Request,
    },
}

#[derive(Debug)]
pub struct Worker {
    commands: Option<Sender<Command>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Worker {
    #[must_use]
    pub fn spawn(
        session: Session,
        timeouts: Timeouts,
        backoff: Backoff,
        events: Sender<Event>,
    ) -> Self {
        let socket = session.socket().to_path_buf();
        let (sender, commands) = channel();
        let stop = Arc::new(AtomicBool::new(false));
        let thread = std::thread::spawn({
            let stop = Arc::clone(&stop);
            move || {
                run(Run {
                    session,
                    socket,
                    timeouts,
                    backoff,
                    commands,
                    events,
                    stop,
                });
            }
        });
        Self {
            commands: Some(sender),
            stop,
            thread: Some(thread),
        }
    }

    /// A command issued while the socket is down waits for the reconnection.
    pub fn send(&self, command: Command) {
        if let Some(commands) = &self.commands {
            let _ = commands.send(command);
        }
    }

    pub fn stop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.commands = None;
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        self.stop();
    }
}

struct Run {
    session: Session,
    socket: PathBuf,
    timeouts: Timeouts,
    backoff: Backoff,
    commands: Receiver<Command>,
    events: Sender<Event>,
    stop: Arc<AtomicBool>,
}

impl Run {
    fn stopped(&self) -> bool {
        self.stop.load(Ordering::Relaxed)
    }

    fn emit(&self, event: Event) -> bool {
        self.events.send(event).is_ok()
    }

    fn nap(&self, total: Duration) {
        let mut slept = Duration::ZERO;
        while slept < total && !self.stopped() {
            let slice = SLICE.min(total - slept);
            std::thread::sleep(slice);
            slept += slice;
        }
    }
}

fn run(mut state: Run) {
    if !state.emit(Event::Connected) {
        return;
    }
    loop {
        if !serve(&mut state) {
            return;
        }
        match reconnect(&state) {
            Some(session) => {
                state.session = session;
                if !state.emit(Event::Connected) {
                    return;
                }
            }
            None => return,
        }
    }
}

fn serve(state: &mut Run) -> bool {
    loop {
        if state.stopped() {
            return false;
        }
        let command = match state.commands.recv_timeout(SLICE) {
            Ok(command) => command,
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => return false,
        };
        let (event, failure) = answer(&mut state.session, command);
        if !state.emit(event) {
            return false;
        }
        if let Some(failure) = failure {
            return state.emit(Event::Disconnected {
                reason: failure,
                attempt: 1,
            });
        }
    }
}

/// A reply that this client cannot read, or a request it cannot encode, is a
/// fault of that one exchange: it is reported to the view and the connection
/// stays. Dropping a healthy connection would loop on reconnecting to the
/// server whose answers cannot be read.
fn answer(session: &mut Session, command: Command) -> (Event, Option<String>) {
    let request = match &command {
        Command::Fetch(fetch) => fetch.request(),
        Command::Mutate { request, .. } => request.clone(),
    };
    let (result, failure) = match session.call(&request) {
        Ok(Ok(reply)) => (Ok(reply), None),
        Ok(Err(error)) => (Err(Failure::Rejected(error)), None),
        Err(error) if error.is_disconnect() => {
            let reason = describe(&error);
            (Err(Failure::Transport(reason.clone())), Some(reason))
        }
        Err(error) => (Err(Failure::Unexpected(describe(&error))), None),
    };
    let event = match command {
        Command::Fetch(fetch) => Event::Fetched { fetch, result },
        Command::Mutate { correlation, .. } => Event::Answered {
            correlation,
            result,
        },
    };
    (event, failure)
}

fn reconnect(state: &Run) -> Option<Session> {
    let mut delay = None;
    let mut attempt = 1;
    loop {
        if state.stopped() {
            return None;
        }
        let wait = state.backoff.next(delay);
        delay = Some(wait);
        state.nap(wait);
        if state.stopped() {
            return None;
        }
        match Session::connect_with(&state.socket, state.timeouts) {
            Ok(session) => return Some(session),
            Err(error) => {
                attempt += 1;
                if !state.emit(Event::Disconnected {
                    reason: describe(&error),
                    attempt,
                }) {
                    return None;
                }
            }
        }
    }
}

fn describe(error: &ClientError) -> String {
    let mut message = error.to_string();
    let mut source = std::error::Error::source(error);
    while let Some(cause) = source {
        message.push_str(": ");
        message.push_str(&cause.to_string());
        source = cause.source();
    }
    message
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_backoff_doubles_up_to_its_cap() {
        let backoff = Backoff::default();
        assert_eq!(backoff.next(None), INITIAL_BACKOFF);
        assert_eq!(backoff.next(Some(INITIAL_BACKOFF)), Duration::from_secs(1));
        assert_eq!(backoff.next(Some(Duration::from_secs(4))), MAX_BACKOFF);
        assert_eq!(backoff.next(Some(MAX_BACKOFF)), MAX_BACKOFF);
    }

    #[test]
    fn a_failure_is_described_with_its_whole_chain() {
        let error = ClientError::Connect {
            socket: PathBuf::from("/run/nope.sock"),
            source: std::io::Error::from(std::io::ErrorKind::NotFound),
        };
        let described = describe(&error);
        assert!(described.contains("/run/nope.sock"), "{described}");
        assert!(described.contains("not found"), "{described}");
    }
}
