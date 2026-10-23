//! voidport-keeper: the voidport device of a virtual machine, kept connected
//! across restarts of voidportd.
//!
//! QEMU does not reconnect a device whose backend went away, so the keeper
//! accepts the connection of QEMU in place of voidportd and connects to
//! voidportd itself. While voidportd runs, the keeper hands on every setup
//! message QEMU sends, and the requests of the guest go straight to voidportd.
//! When voidportd goes away, the keeper puts back every chain voidportd had in
//! flight and every chain the driver makes available after that, with nothing
//! written into it, so the sessions end as over a lost connection. Meanwhile the
//! keeper tries to connect again, and hands voidportd the guest memory, each
//! queue at the position the keeper reached, and the eventfds.
//!
//! voidportd tells the keeper which chains it had in flight through the record
//! both of them map ([`voidport_vhost::inflight`]).

mod device;
mod memory;
mod record;
mod ring;
mod server;

use std::hash::{BuildHasher as _, Hasher as _, RandomState};
use std::io;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Instant;

use rustix::event::{EventfdFlags, PollFd, PollFlags, Timespec, poll};
use rustix::io::Errno;
use vhost::vhost_user::{BackendReqHandler, Error as VhostUserError};
use voidport_session::{Backoff, Schedule};
use voidport_vhost::backend::Handler;
use voidport_vhost::eventfd;

use self::device::Device;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("the eventfd that wakes the connection to voidportd could not be made")]
    Wake(#[source] io::Error),
    #[error("the thread that connects to voidportd could not start")]
    Thread(#[source] io::Error),
    #[error("the connection to QEMU failed")]
    Qemu(#[source] VhostUserError),
}

/// # Errors
///
/// [`Error`] when the keeper cannot start, or QEMU breaks its connection.
/// QEMU closing its connection ends the keeper without an error.
pub fn serve(qemu: UnixStream, server: &Path) -> Result<(), Error> {
    let device = Arc::new(Mutex::new(Handler::new(Device::default())));
    let wake = Arc::new(
        rustix::event::eventfd(0, EventfdFlags::CLOEXEC | EventfdFlags::NONBLOCK)
            .map_err(|errno| Error::Wake(errno.into()))?,
    );
    let ended = Arc::new(AtomicBool::new(false));
    let link = {
        let (device, wake, ended) = (Arc::clone(&device), Arc::clone(&wake), Arc::clone(&ended));
        let server = server.to_path_buf();
        std::thread::Builder::new()
            .name("voidport-keeper-link".to_owned())
            .spawn(move || stay_connected(&device, &server, &wake, &ended))
            .map_err(Error::Thread)?
    };
    let mut handler = BackendReqHandler::from_stream(qemu, Arc::clone(&device));
    let ended_by = loop {
        match handler.handle_request() {
            // A message can change what the connection to voidportd watches.
            Ok(()) => signal(&wake),
            Err(VhostUserError::Disconnected) => break Ok(()),
            Err(error) => break Err(Error::Qemu(error)),
        }
    };
    ended.store(true, Ordering::Release);
    signal(&wake);
    if link.join().is_err() {
        tracing::error!("the thread that connected to voidportd panicked");
    }
    lock(&device).backend().end();
    ended_by
}

/// Runs until `ended` shows that QEMU has gone. `wake` is signalled whenever
/// QEMU changed the device.
fn stay_connected(
    device: &Mutex<Handler<Device>>,
    server: &Path,
    wake: &OwnedFd,
    ended: &AtomicBool,
) {
    let mut backoff = Backoff::seeded(seed());
    let mut next_attempt = Some(Instant::now());
    while !ended.load(Ordering::Acquire) {
        let watched = lock(device).backend().watched();
        let timeout = next_attempt.map(|at| {
            Timespec::try_from(at.saturating_duration_since(Instant::now())).unwrap_or(Timespec {
                tv_sec: 0,
                tv_nsec: 0,
            })
        });
        let mut ready: Vec<PollFd<'_>> = std::iter::once(wake)
            .chain(&watched)
            .map(|descriptor| PollFd::new(descriptor, PollFlags::IN))
            .collect();
        if let Err(errno) = poll(&mut ready, timeout.as_ref())
            && errno != Errno::INTR
        {
            tracing::warn!(%errno, "the keeper cannot wait for the device");
        }
        let woken = ready
            .iter()
            .skip(1)
            .any(|ready| !ready.revents().is_empty());
        drop(ready);
        if let Err(error) = eventfd::drain(wake) {
            tracing::warn!(%error, "the wake-up of the connection to voidportd cannot be read");
        }
        {
            let mut locked = lock(device);
            let device = locked.backend();
            if woken {
                device.check();
            }
            device.serve();
            if !device.connected() && next_attempt.is_none() {
                backoff.restart();
                next_attempt = Some(Instant::now());
            }
        }
        if next_attempt.is_some_and(|at| at <= Instant::now()) {
            next_attempt = if connect(device, server) {
                None
            } else {
                Some(Instant::now() + backoff.next(Schedule::Stalling))
            };
        }
    }
}

fn connect(device: &Mutex<Handler<Device>>, server: &Path) -> bool {
    let stream = match UnixStream::connect(server) {
        Ok(stream) => stream,
        Err(error) => {
            tracing::debug!(%error, server = %server.display(), "voidportd cannot be connected to");
            return false;
        }
    };
    match lock(device).backend().hand_over(stream) {
        Ok(()) => {
            tracing::info!(server = %server.display(), "voidportd runs the device");
            true
        }
        Err(error) => {
            tracing::warn!(%error, server = %server.display(), "voidportd did not take the device over");
            false
        }
    }
}

/// Locks the device, which the QEMU messages and the connection to voidportd
/// share. A thread that panicked while it had the lock left the device as
/// consistent as any message does.
fn lock(device: &Mutex<Handler<Device>>) -> MutexGuard<'_, Handler<Device>> {
    device.lock().unwrap_or_else(PoisonError::into_inner)
}

fn signal(wake: &OwnedFd) {
    if let Err(error) = eventfd::signal(wake) {
        tracing::warn!(%error, "the connection to voidportd could not be woken");
    }
}

fn seed() -> u64 {
    RandomState::new().build_hasher().finish()
}
