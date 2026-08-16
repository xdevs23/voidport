//! The worker thread that drives the control socket.
//!
//! The UI loop must never block on I/O — a wedged server would otherwise
//! freeze the keyboard, and quitting is exactly what an operator wants when a
//! server is wedged. So every request leaves through this thread and every
//! answer comes back as an [`Event`].
//!
//! Reconnection lives here too, because it is the same concern: when the
//! socket dies the worker retries with capped backoff (500 ms doubling to 5 s,
//! indefinitely) and announces each attempt, so the interface can show a
//! banner while staying fully responsive. A successful reconnect is announced
//! as [`Event::Connected`], which is what makes the reducer invalidate every
//! cached view — the server on the other end may be a *different* one.
//!
//! Stopping is prompt by construction: every wait in this thread is a slice of
//! at most [`SLICE`], and each slice checks the stop flag.

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

/// The longest the worker sleeps without checking whether it should stop.
pub const SLICE: Duration = Duration::from_millis(50);

/// The first reconnection delay.
pub const INITIAL_BACKOFF: Duration = Duration::from_millis(500);

/// The longest reconnection delay.
pub const MAX_BACKOFF: Duration = Duration::from_secs(5);

/// The capped-backoff schedule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Backoff {
    /// The first delay.
    pub initial: Duration,
    /// The ceiling the delay doubles up to.
    pub max: Duration,
}

impl Default for Backoff {
    /// [`INITIAL_BACKOFF`] doubling to [`MAX_BACKOFF`], the schedule the design set.
    fn default() -> Self {
        Self {
            initial: INITIAL_BACKOFF,
            max: MAX_BACKOFF,
        }
    }
}

impl Backoff {
    /// The delay after `previous`, capped.
    fn next(self, previous: Option<Duration>) -> Duration {
        match previous {
            None => self.initial,
            Some(previous) => (previous * 2).min(self.max),
        }
    }
}

/// What the reducer asks the worker to do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Command {
    /// Re-read one view.
    Fetch(Fetch),
    /// Issue one mutation.
    Mutate {
        /// The id its answer must carry.
        correlation: Correlation,
        /// The operation.
        request: Request,
    },
}

/// A control-socket worker.
#[derive(Debug)]
pub struct Worker {
    commands: Option<Sender<Command>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Worker {
    /// Starts a worker around an already-connected session.
    ///
    /// The first connection is made by the caller, before the terminal is
    /// taken over, so that a missing socket is a plain message on a normal
    /// terminal, not a banner in an interface nobody asked for.
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

    /// Queues a command.
    ///
    /// A command issued while the socket is down waits for the reconnection:
    /// the operator's submit is judged by the server, whenever the server is
    /// reachable again.
    pub fn send(&self, command: Command) {
        if let Some(commands) = &self.commands {
            let _ = commands.send(command);
        }
    }

    /// Stops the worker and waits for the thread, promptly.
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

/// Everything the worker thread owns.
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
    /// Whether the worker has been asked to stop.
    fn stopped(&self) -> bool {
        self.stop.load(Ordering::Relaxed)
    }

    /// Announces an event; a closed channel means the interface is gone.
    fn emit(&self, event: Event) -> bool {
        self.events.send(event).is_ok()
    }

    /// Sleeps in slices, giving up early when asked to stop.
    fn nap(&self, total: Duration) {
        let mut slept = Duration::ZERO;
        while slept < total && !self.stopped() {
            let slice = SLICE.min(total - slept);
            std::thread::sleep(slice);
            slept += slice;
        }
    }
}

/// The worker thread.
fn run(mut state: Run) {
    if !state.emit(Event::Connected) {
        return;
    }
    loop {
        if !serve(&mut state) {
            return;
        }
        // The connection died; retry until it comes back or we are stopped.
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

/// Serves commands until the connection dies.
///
/// Returns `false` when the worker should exit entirely (stopped, or the
/// interface is gone).
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
            // The socket is unusable; say so once, then reconnect.
            return state.emit(Event::Disconnected {
                reason: failure,
                attempt: 1,
            });
        }
    }
}

/// Runs one command, returning the event it produced and, if the connection
/// died doing it, why.
///
/// Not every client failure is a dead socket, and the difference matters:
/// [`ClientError::is_disconnect`] separates the socket's health from one
/// message's fate. A reply this client cannot read (a version skew, say) and a
/// request it cannot encode are faults of that one exchange — reported to the
/// view, connection kept. Dropping a healthy connection over them would put the
/// interface in a reconnect loop that reconnects to the very server whose
/// answers it cannot read.
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

/// Reconnects with capped backoff, announcing every attempt.
///
/// `None` means the worker was stopped, which is what keeps quit instant while
/// a retry is pending.
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

/// The client's own words for a failure, which is what the banner shows.
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
