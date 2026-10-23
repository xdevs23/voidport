// SPDX-License-Identifier: GPL-2.0

use super::Result;
use std::fs;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::mpsc::{Receiver, Sender};
use voidport_proto::frame::FrameHeader;
use voidport_proto::opcode::Opcode;
use zerocopy::IntoBytes;

pub(super) fn clear_socket_path(path: &str) -> Result {
    let path = std::path::Path::new(path);
    fs::create_dir_all(path.parent().ok_or("a socket path without a directory")?)?;
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

pub(super) fn unix_listener(path: &str) -> Result<UnixListener> {
    clear_socket_path(path)?;
    Ok(UnixListener::bind(path)?)
}

enum Event {
    Exited(Option<libc::c_int>),
    Failed(Failure),
}

#[derive(Debug, PartialEq)]
pub(super) enum Failure {
    DecoyReached(&'static str),
    DecoyFailed(&'static str, String),
    PeerFailed(String),
}

impl std::fmt::Display for Failure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DecoyReached(decoy) => write!(formatter, "a connection reached {decoy}"),
            Self::DecoyFailed(decoy, reason) => {
                write!(formatter, "the watcher of {decoy} failed: {reason}")
            }
            Self::PeerFailed(reason) => write!(formatter, "the peer failed: {reason}"),
        }
    }
}

impl std::error::Error for Failure {}

pub(super) fn failure_of<T>(outcome: Result<T>) -> Option<Failure> {
    let failure = outcome.err()?.downcast::<Failure>().ok()?;
    Some(*failure)
}

pub(super) trait Listener: Send + Sync + 'static {
    type Stream: Connection;

    fn next(&self) -> std::io::Result<Self::Stream>;

    fn set_nonblocking(&self, nonblocking: bool) -> std::io::Result<()>;

    fn stop(&self) -> std::io::Result<()>;

    fn next_unless_stopped(&self) -> std::io::Result<Option<Self::Stream>> {
        match self.next() {
            Ok(stream) => Ok(Some(stream)),
            Err(error) if error.kind() == std::io::ErrorKind::InvalidInput => Ok(None),
            Err(error) => Err(error),
        }
    }
}

pub(super) trait Connection: Read + Write + Send + Sized + 'static {
    fn duplicate(&self) -> std::io::Result<Self>;

    fn end_sending(&self) -> std::io::Result<()>;

    fn close(&self) -> std::io::Result<()>;
}

macro_rules! socket_family {
    ($listener:ty, $stream:ty) => {
        impl Listener for $listener {
            type Stream = $stream;

            fn next(&self) -> std::io::Result<$stream> {
                Ok(self.accept()?.0)
            }

            fn set_nonblocking(&self, nonblocking: bool) -> std::io::Result<()> {
                <$listener>::set_nonblocking(self, nonblocking)
            }

            fn stop(&self) -> std::io::Result<()> {
                // Linux wakes an accept on a listening socket that is shut
                // down for reading, and fails it with EINVAL.
                let fd = std::os::fd::AsRawFd::as_raw_fd(self);
                if unsafe { libc::shutdown(fd, libc::SHUT_RD) } == 0 {
                    Ok(())
                } else {
                    Err(std::io::Error::last_os_error())
                }
            }
        }

        impl Connection for $stream {
            fn duplicate(&self) -> std::io::Result<Self> {
                self.try_clone()
            }

            fn end_sending(&self) -> std::io::Result<()> {
                self.shutdown(std::net::Shutdown::Write)
            }

            fn close(&self) -> std::io::Result<()> {
                self.shutdown(std::net::Shutdown::Both)
            }
        }
    };
}

socket_family!(UnixListener, UnixStream);
socket_family!(TcpListener, TcpStream);

pub(super) struct Supervision {
    sender: Sender<Event>,
    events: Receiver<Event>,
}

impl Supervision {
    pub(super) fn new() -> Self {
        let (sender, events) = std::sync::mpsc::channel();
        Self { sender, events }
    }

    pub(super) fn reap(&self, child: libc::pid_t) -> Result<libc::c_int> {
        assert!(child > 0, "{}", std::io::Error::last_os_error());
        let exited = self.sender.clone();
        let waiter = std::thread::spawn(move || {
            let mut status = 0;
            let reaped = unsafe { libc::waitpid(child, &mut status, 0) } == child;
            let _ = exited.send(Event::Exited(reaped.then_some(status)));
        });
        let mut failure = None;
        let status = loop {
            match self.events.recv()? {
                Event::Exited(status) => break status,
                Event::Failed(reason) => {
                    if failure.is_none() {
                        failure = Some(reason);
                        unsafe { libc::kill(child, libc::SIGKILL) };
                    }
                }
            }
        };
        waiter.join().map_err(|_| "the child's waiter failed")?;
        if let Some(failure) = failure {
            return Err(failure.into());
        }
        Ok(status.ok_or("the child could not be reaped")?)
    }

    pub(super) fn kill_and_reap(&self, child: libc::pid_t, what: &str) -> Result {
        assert_eq!(unsafe { libc::kill(child, libc::SIGKILL) }, 0);
        let status = self.reap(child)?;
        if libc::WIFSIGNALED(status) && libc::WTERMSIG(status) == libc::SIGKILL {
            return Ok(());
        }
        Err(format!("{what} returned before the kill: {status:#x}").into())
    }

    fn settled(&self) -> Result {
        let failure = self.events.try_iter().find_map(|event| match event {
            Event::Exited(_) => None,
            Event::Failed(failure) => Some(failure),
        });
        failure.map_or(Ok(()), |failure| Err(failure.into()))
    }
}

/// Runs a peer on a thread of its own with `serve`. It gets the means to
/// report a failure of the peer to the case as an event, which it reports
/// before it closes a connection over that failure, so the case sees the
/// failure before anything the closed connection causes.
pub(super) fn spawn_peer(
    supervision: &Supervision,
    serve: impl FnOnce(&(dyn Fn(&str) + Sync)) -> Result + Send + 'static,
) -> std::thread::JoinHandle<Result> {
    let failures = supervision.sender.clone();
    std::thread::spawn(move || {
        serve(&|failure: &str| {
            let _ = failures.send(Event::Failed(Failure::PeerFailed(failure.to_owned())));
        })
    })
}

const DECOY_WAKEUP: &[u8] = b"voidport case: the decoy watcher stops\n";

pub(super) struct Decoy {
    watcher: std::thread::JoinHandle<()>,
}

impl Decoy {
    pub(super) fn watch<L: Listener>(
        listener: L,
        name: &'static str,
        supervision: &Supervision,
    ) -> Self {
        let reporter = supervision.sender.clone();
        let watcher = std::thread::spawn(move || {
            let report = |failure| {
                let _ = reporter.send(Event::Failed(failure));
            };
            if let Err(error) = watch_connections(&listener, || report(Failure::DecoyReached(name)))
            {
                report(Failure::DecoyFailed(name, error.to_string()));
            }
        });
        Self { watcher }
    }

    pub(super) fn stop(self, mut wakeup: impl Write, supervision: &Supervision) -> Result {
        wakeup.write_all(DECOY_WAKEUP)?;
        self.watcher
            .join()
            .map_err(|_| "the decoy watcher failed")?;
        supervision.settled()
    }
}

fn watch_connections(listener: &impl Listener, mut report: impl FnMut()) -> Result {
    while !is_wakeup(&mut listener.next()?) {
        report();
    }
    take_queued(listener, |_| {
        report();
        Ok(())
    })
}

pub(super) fn take_queued<L: Listener>(
    listener: &L,
    mut take: impl FnMut(L::Stream) -> Result,
) -> Result {
    listener.set_nonblocking(true)?;
    loop {
        match listener.next() {
            Ok(stream) => take(stream)?,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(error) => return Err(error.into()),
        }
    }
    listener.set_nonblocking(false)?;
    Ok(())
}

/// Whether `stream` is the case's wakeup: it sends [`DECOY_WAKEUP`] first.
/// Reading stops at the first byte that differs from it, at the end of the
/// connection or at a failure, so any other connection is told apart by what
/// it has sent, without waiting for more.
fn is_wakeup(stream: &mut impl Read) -> bool {
    let mut byte = [0];
    DECOY_WAKEUP
        .iter()
        .all(|expected| stream.read_exact(&mut byte).is_ok() && byte[0] == *expected)
}

const DECOY_UNDER_TEST: &str = "the decoy under test";

fn decoy_reached_while_waiting<S: Write>(
    listener: impl Listener,
    connect: impl Fn() -> std::io::Result<S>,
) -> Result {
    let supervision = Supervision::new();
    let mut connection = connect()?;
    connection.write_all(FrameHeader::new(Opcode::Hello.as_u16(), 0, 1).as_bytes())?;
    let decoy = Decoy::watch(listener, DECOY_UNDER_TEST, &supervision);
    let blocked = fork_child(|| {
        unsafe { libc::pause() };
        0
    });
    assert_eq!(
        failure_of(supervision.reap(blocked)),
        Some(Failure::DecoyReached(DECOY_UNDER_TEST)),
        "a connection to a running decoy passed the case",
    );
    decoy.stop(connect()?, &supervision)
}

fn decoy_at_shutdown(path: &str) -> Result {
    let supervision = Supervision::new();
    let decoy = Decoy::watch(unix_listener(path)?, DECOY_UNDER_TEST, &supervision);
    decoy.stop(UnixStream::connect(path)?, &supervision)?;
    let header = FrameHeader::new(Opcode::Hello.as_u16(), 0, 1);
    let sends: [(&[u8], bool); 3] = [
        (&[], false),
        (&DECOY_WAKEUP[..DECOY_WAKEUP.len() - 1], false),
        (header.as_bytes(), true),
    ];
    for (sent, remains_open) in sends {
        for behind in [false, true] {
            let supervision = Supervision::new();
            let listener = unix_listener(path)?;
            let queued_first = UnixStream::connect(path)?;
            let connection = UnixStream::connect(path)?;
            let (mut placed, wakeup) = if behind {
                (connection, queued_first)
            } else {
                (queued_first, connection)
            };
            placed.write_all(sent)?;
            if !remains_open {
                placed.close()?;
            }
            let decoy = Decoy::watch(listener, DECOY_UNDER_TEST, &supervision);
            assert_eq!(
                failure_of(decoy.stop(wakeup, &supervision)),
                Some(Failure::DecoyReached(DECOY_UNDER_TEST)),
                "a connection that sent {sent:?} {} the wakeup passed the decoy",
                if behind { "behind" } else { "ahead of" },
            );
        }
    }
    Ok(())
}

/// Runs `body` in a child process and answers with the child's process ID,
/// which the case reaps. `body` answers with the child's exit status. It runs
/// only system calls on memory prepared before the fork, so the other threads
/// of this process cannot leave the child holding a lock.
pub(super) fn fork_child(body: impl FnOnce() -> libc::c_int) -> libc::pid_t {
    let child = unsafe { libc::fork() };
    if child == 0 {
        let status = body();
        unsafe { libc::_exit(status) };
    }
    child
}

pub(super) fn decoy_failure() -> Result {
    let path = "/vfs-unix/decoy.sock";
    decoy_reached_while_waiting(unix_listener(path)?, || UnixStream::connect(path))?;
    let tcp = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let address = tcp.local_addr()?;
    decoy_reached_while_waiting(tcp, || TcpStream::connect(address))?;
    println!("vfs acceptance: a connection to a running decoy failed its case, its child reaped");
    decoy_at_shutdown(path)?;
    println!(
        "vfs acceptance: a connection queued at a decoy's stop, ahead of the wakeup or behind it, failed its case"
    );
    Ok(())
}
