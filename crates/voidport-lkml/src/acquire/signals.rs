use super::error::AttemptFailure;
use crate::{
    error::error_text,
    staging::AttemptHandle,
    storage::{StorageError, Writer},
};
use std::{
    fmt,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::signal::unix::{Signal, SignalKind};

pub(super) struct Signals {
    interrupt: Signal,
    terminate: Signal,
    latched: Arc<AtomicBool>,
    registrations: Vec<signal_hook::SigId>,
}
impl Signals {
    pub(super) fn new() -> std::io::Result<Self> {
        let mut signals = Self {
            interrupt: tokio::signal::unix::signal(SignalKind::interrupt())?,
            terminate: tokio::signal::unix::signal(SignalKind::terminate())?,
            latched: Arc::new(AtomicBool::new(false)),
            registrations: Vec::new(),
        };
        // The flag also observes signals during synchronous ingestion/publication,
        // when the async reactor cannot dispatch its wakeup yet.
        for number in [signal_hook::consts::SIGINT, signal_hook::consts::SIGTERM] {
            signals.registrations.push(signal_hook::flag::register(
                number,
                signals.latched.clone(),
            )?);
        }
        Ok(signals)
    }
    pub(super) fn is_cancelled(&self) -> bool {
        self.latched.load(Ordering::SeqCst)
    }
    pub(super) async fn cancelled(&mut self) {
        if !self.is_cancelled() {
            tokio::select! { _ = self.interrupt.recv() => {}, _ = self.terminate.recv() => {} }
        }
        self.latched.store(true, Ordering::SeqCst);
    }
}
impl Drop for Signals {
    fn drop(&mut self) {
        for registration in &self.registrations {
            signal_hook::low_level::unregister(*registration);
        }
    }
}

pub(super) const INTERRUPTION: &str = "acquisition interrupted by signal";

/// A signal that ended the collection. Its message contains the failure to
/// publish the signal in the attempt ended by the signal. That failure is
/// not its source, so the message is one line.
#[derive(Debug)]
pub struct Cancelled {
    pub publication: Option<UnconfirmedPublication>,
}
impl fmt::Display for Cancelled {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(INTERRUPTION)?;
        if let Some(publication) = &self.publication {
            write!(formatter, "; {}", error_text(publication))?;
        }
        Ok(())
    }
}
impl std::error::Error for Cancelled {}

#[derive(Debug, thiserror::Error)]
#[error("cancellation publication not confirmed")]
pub struct UnconfirmedPublication(#[source] pub StorageError);

pub(super) fn check_cancellation(
    corpus: &mut Writer,
    signals: &Signals,
    attempt: Option<(AttemptHandle, &mut Vec<AttemptFailure>)>,
) -> Result<(), Cancelled> {
    if !signals.is_cancelled() {
        return Ok(());
    }
    let mut publication = None;
    if let Some((attempt, failures)) = attempt
        && !failures.iter().any(AttemptFailure::is_cancellation)
    {
        let cancelled = AttemptFailure::Cancelled;
        publication = match corpus.fail(attempt, cancelled.to_string()) {
            Ok(()) => {
                failures.push(cancelled);
                corpus.publish().err()
            }
            Err(error) => Some(error),
        }
        .map(UnconfirmedPublication);
    }
    Err(Cancelled { publication })
}
