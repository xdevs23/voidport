// SPDX-License-Identifier: GPL-2.0

use super::guest::{
    Endpoint, SIGUSR1_HANDLED, count_sigusr1, errno, mount_with, require_mount, require_zero,
    tcp_endpoint,
};
use super::server::{
    Behaviour, Flow, Rendezvous, State, Stream, next_request, send, serve, serve_one,
};
use crate::supervision::{Connection, Listener, Supervision, fork_child};
use crate::{Result, eof, load_module, unload_module};
use std::ffi::{CStr, CString};
use std::fs::{self};
use std::io::Read;
use std::net::{Ipv4Addr, TcpListener};
use std::sync::Arc;
use std::sync::atomic::Ordering;

fn mount_once(options: &CStr) -> libc::c_int {
    if !count_sigusr1() {
        return 1;
    }
    if mount_with(options) == 0 {
        return 0;
    }
    let error = errno();
    let handled = SIGUSR1_HANDLED.load(Ordering::Relaxed) == usize::from(error == libc::EINTR);
    if handled { error } else { error + 100 }
}

#[derive(Clone, Copy, Debug)]
enum Hello {
    Reply,
    Await,
    Close,
}

#[derive(Default)]
struct HeldReply {
    sent: bool,
    decided: Option<Hello>,
}

struct HeldHello {
    prefix: usize,
    reply: Rendezvous<HeldReply>,
}

impl HeldHello {
    fn new(prefix: usize) -> Self {
        Self {
            prefix,
            reply: Rendezvous::default(),
        }
    }

    fn wait_sent(&self) -> Result {
        self.reply.wait(|reply| reply.sent)
    }

    fn decide(&self, decided: Hello) {
        self.reply.update(|reply| reply.decided = Some(decided));
    }
}

impl Behaviour for HeldHello {
    fn hello(
        &self,
        _state: &State,
        serial: u64,
        reply: &[u8],
        stream: &mut dyn Stream,
    ) -> Result<Flow> {
        let prefix = self.prefix;
        stream.write_all(&reply[..prefix])?;
        self.reply.update(|reply| reply.sent = true);
        self.reply.wait(|reply| reply.decided.is_some())?;
        let decided = self
            .reply
            .read(|reply| reply.decided)
            .ok_or("the case decided nothing")?;
        println!(
            "vfs peer: session={serial} hello reply withheld after {prefix} bytes, then {decided:?}"
        );
        match decided {
            Hello::Reply => send(stream, &reply[prefix..]),
            Hello::Await => {
                eof(stream)?;
                Ok(Flow::Close)
            }
            Hello::Close => Ok(Flow::Close),
        }
    }

    fn ended(&self) {
        self.reply.end();
    }
}

fn held_handshake(prefix: usize, finish: Hello) -> Result {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let endpoint = tcp_endpoint(listener.local_addr()?);
    let held = Arc::new(HeldHello::new(prefix));
    let state = Arc::new(State::with(held.clone()));
    let peer = serve_one(listener, &state);
    let options = CString::new(format!("{endpoint},reconnect_stall=0"))?;
    let child = fork_child(|| mount_once(&options));
    held.wait_sent()?;
    held.decide(finish);
    let expected = match finish {
        Hello::Reply => 0,
        Hello::Await => {
            assert_eq!(unsafe { libc::kill(child, libc::SIGUSR1) }, 0);
            libc::EINTR
        }
        Hello::Close => libc::ECONNRESET,
    };
    let status = Supervision::new().reap(child)?;
    assert!(libc::WIFEXITED(status), "{status:#x}");
    assert_eq!(libc::WEXITSTATUS(status), expected, "{finish:?}");
    if expected == 0 {
        assert_eq!(fs::read("/vfs-options/a")?, b"old");
        assert_eq!(unsafe { libc::umount(c"/vfs-options".as_ptr()) }, 0);
    }
    peer.join().map_err(|_| "handshake peer failed")??;
    println!(
        "vfs acceptance: a handshake withheld after {prefix} reply bytes ended by {finish:?} with status {expected}, its socket closed"
    );
    Ok(())
}

#[derive(Clone, Copy, Debug)]
pub(super) enum Attempt {
    Dropped,
    Silent,
}

#[derive(Default)]
struct Attempts {
    record: Rendezvous<Record>,
}

#[derive(Default)]
struct Record {
    dropped: usize,
    unanswered: usize,
    closed: usize,
    failed: Option<String>,
}

impl Attempts {
    fn wait(&self, reached: impl Fn(&Record) -> bool) -> Result {
        self.record
            .wait(|record| record.failed.is_some() || reached(record))?;
        self.record
            .read(|record| record.failed.clone())
            .map_or(Ok(()), |failed| Err(failed.into()))
    }

    fn handle(&self, attempt: Attempt, mut stream: impl Read) {
        match attempt {
            Attempt::Dropped => {
                drop(stream);
                self.record.update(|record| record.dropped += 1);
            }
            Attempt::Silent => {
                let outcome = next_request(&mut stream).and_then(|hello| match hello {
                    Some(_) => {
                        self.record.update(|record| record.unanswered += 1);
                        eof(&mut stream).map(|()| self.record.update(|record| record.closed += 1))
                    }
                    None => Ok(()),
                });
                if let Err(error) = outcome {
                    self.record
                        .update(|record| record.failed = Some(error.to_string()));
                }
            }
        }
    }
}

/// The window ends on its own and the mount is degraded after it, so a
/// stalled request fails with EIO and an attempt is closed at its bound.
const WINDOW: u64 = 1;

pub(super) struct Reconnecting<L> {
    listener: Arc<L>,
    attempts: Arc<Attempts>,
    peer: std::thread::JoinHandle<Result>,
}

impl Reconnecting<TcpListener> {
    fn on_loopback(attempt: Attempt) -> Result<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        Self::start(listener, attempt, |options| {
            require_mount(options);
            Ok(())
        })
    }
}

impl<L: Listener + Endpoint> Reconnecting<L> {
    /// The peer has the only reference to `listener` until it accepts the
    /// first connection. A peer that fails before then closes the listener,
    /// which ends the connection the mount waits on, so the mount fails.
    pub(super) fn start(
        listener: L,
        attempt: Attempt,
        mount: impl FnOnce(&str) -> Result,
    ) -> Result<Self> {
        let options = format!("{},reconnect_stall={WINDOW}", listener.endpoint_options()?);
        let state = Arc::new(State::default());
        let attempts = Arc::new(Attempts::default());
        let (first, accepted) = std::sync::mpsc::channel();
        let peer = {
            let attempts = attempts.clone();
            std::thread::spawn(move || -> Result {
                let stream = listener.next()?;
                let listener = Arc::new(listener);
                first
                    .send((stream.duplicate()?, listener.clone()))
                    .map_err(|_| "the case stopped waiting for the first connection")?;
                let session = std::thread::spawn(move || serve(stream, 1, state));
                while let Some(stream) = listener.next_unless_stopped()? {
                    attempts.handle(attempt, stream);
                }
                session.join().map_err(|_| "the first session panicked")?
            })
        };
        mount(&options)?;
        assert_eq!(fs::read("/vfs-options/a")?, b"old");
        let (connection, listener) = accepted.recv()?;
        // The peer cuts the connection by ending what it sends. The RELEASE
        // that closing the file sends can arrive after the cut, and a socket
        // that no longer reads answers it with a reset, which would fail the
        // session of the peer.
        connection.end_sending()?;
        Ok(Self {
            listener,
            attempts,
            peer,
        })
    }

    pub(super) fn wait_expired(&self) -> Result {
        self.attempts.wait(|record| record.closed > 0)
    }

    pub(super) fn unmount(self) -> Result {
        assert_eq!(unsafe { libc::umount(c"/vfs-options".as_ptr()) }, 0);
        self.attempts
            .wait(|record| record.closed == record.unanswered)?;
        require_zero(&["connections_live", "requests_in_flight"])?;
        self.listener.stop()?;
        self.peer.join().map_err(|_| "reconnect peer failed")?
    }
}

fn unmount_while_reconnecting(attempt: Attempt) -> Result {
    load_module()?;
    let reconnecting = Reconnecting::on_loopback(attempt)?;
    let attempts = &reconnecting.attempts;
    match attempt {
        Attempt::Dropped => attempts.wait(|record| record.dropped > 0)?,
        Attempt::Silent => {
            reconnecting.wait_expired()?;
            require_zero(&["connections_live"])?;
            attempts.wait(|record| record.unanswered > record.closed)?;
        }
    }
    reconnecting.unmount()?;
    unload_module()?;
    println!(
        "vfs acceptance: an unmount at a reconnect with {attempt:?} attempts returned and freed the session"
    );
    Ok(())
}

pub(crate) fn stall_expiry() -> Result {
    fs::create_dir_all("/vfs-options")?;
    load_module()?;
    let reconnecting = Reconnecting::on_loopback(Attempt::Dropped)?;
    // A request made before the module has read the end of the first
    // connection goes out on that connection, and the peer's reply to it
    // fails with EPIPE on the direction the peer ended. The first attempt
    // shows that the module has read that end.
    reconnecting.attempts.wait(|record| record.dropped > 0)?;
    for name in ["b", "n5"] {
        let error = fs::metadata(format!("/vfs-options/{name}")).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EIO), "{name}");
    }
    let dropped = reconnecting.attempts.record.read(|record| record.dropped);
    reconnecting
        .attempts
        .wait(|record| record.dropped > dropped)?;
    reconnecting.unmount()?;
    unload_module()?;
    println!(
        "vfs acceptance: a stalled request failed with EIO, and the degraded mount kept reconnecting"
    );
    Ok(())
}

pub(crate) fn run() -> Result {
    fs::create_dir_all("/vfs-options")?;
    load_module()?;
    for prefix in [0, 1] {
        for finish in [Hello::Reply, Hello::Await, Hello::Close] {
            held_handshake(prefix, finish)?;
        }
    }
    unload_module()?;
    for attempt in [Attempt::Dropped, Attempt::Silent] {
        unmount_while_reconnecting(attempt)?;
    }
    Ok(())
}
