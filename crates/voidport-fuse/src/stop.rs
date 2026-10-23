use std::io::{self, PipeReader, PipeWriter};
use std::os::fd::{AsFd as _, BorrowedFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// # Errors
///
/// The error of the pipe that wakes a loop waiting for a request.
pub fn stop() -> io::Result<(Stop, Stopper)> {
    let (reader, writer) = io::pipe()?;
    let requested = Arc::new(AtomicBool::new(false));
    Ok((
        Stop {
            requested: Arc::clone(&requested),
            pipe: reader,
        },
        Stopper {
            requested,
            _pipe: writer,
        },
    ))
}

#[derive(Debug)]
pub struct Stop {
    requested: Arc<AtomicBool>,
    /// The read end of a pipe whose write end the stopper closes.
    pipe: PipeReader,
}

impl Stop {
    pub(crate) fn is_requested(&self) -> bool {
        self.requested.load(Ordering::Acquire)
    }

    pub(crate) fn pipe(&self) -> BorrowedFd<'_> {
        self.pipe.as_fd()
    }
}

#[derive(Debug)]
pub struct Stopper {
    requested: Arc<AtomicBool>,
    /// The write end of the pipe, closed after the stop is requested.
    _pipe: PipeWriter,
}

impl Drop for Stopper {
    fn drop(&mut self) {
        // Set before the write end closes, so that a loop woken by the close
        // finds the stop requested.
        self.requested.store(true, Ordering::Release);
    }
}
