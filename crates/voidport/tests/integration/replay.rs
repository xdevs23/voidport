//! A lost reply cannot be proven by timing: "the reply was lost" and "the
//! request never arrived" look the same from the client. A test-harness relay
//! forwards the request, watches the server answer it, discards that answer
//! and kills the server, so whether a mutation was applied twice is a count of
//! the request frames the relay carried.

use voidport_test_client as support;

use std::io;
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::Duration;

use rustix::io::Errno;
use support::daemon::{Ground, reconnected_after, runtime, state_is};
use voidport::client::{Caller, MountState};
use voidport::fuse::attr::Privileged;
use voidport::fuse::dir::{DirectoryEntry, DirectoryRead, DirectorySink, read_directory};
use voidport::url::Endpoint;
use voidport_proto::frame::{FLAG_RESPONSE, FrameHeader};
use voidport_proto::opcode::Opcode;
use voidport_session::reconnect::FIRST_GENERATION;
use zerocopy::FromBytes as _;

/// Never closes: the subject is which requests are re-sent, not when a mount
/// gives up.
const STALL: Duration = Duration::MAX;

struct Relay {
    address: SocketAddr,
    state: Arc<RelayState>,
}

struct RelayState {
    server: PathBuf,
    forwarded: Mutex<Vec<u16>>,
    /// Armed once; the first matching reply disarms it, so a re-sent request is
    /// answered normally.
    trap: Mutex<Option<Trap>>,
    connections: AtomicUsize,
}

struct Trap {
    opcode: u16,
    sprung: mpsc::Sender<()>,
}

impl Relay {
    fn start(server: &std::path::Path) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("a free port");
        let address = listener.local_addr().expect("a bound address");
        let state = Arc::new(RelayState {
            server: server.to_path_buf(),
            forwarded: Mutex::new(Vec::new()),
            trap: Mutex::new(None),
            connections: AtomicUsize::new(0),
        });
        let accepting = Arc::clone(&state);
        thread::spawn(move || {
            while let Ok((client, _)) = listener.accept() {
                accepting.connections.fetch_add(1, Ordering::Relaxed);
                let state = Arc::clone(&accepting);
                thread::spawn(move || state.serve(client));
            }
        });
        Self { address, state }
    }

    fn endpoint(&self) -> Endpoint {
        Endpoint::Tcp {
            host: self.address.ip().to_string(),
            port: self.address.port(),
        }
    }

    fn discard_next_reply(&self, opcode: Opcode) -> mpsc::Receiver<()> {
        let (sprung, waiter) = mpsc::channel();
        *self.state.trap.lock().expect("unpoisoned") = Some(Trap {
            opcode: opcode.as_u16(),
            sprung,
        });
        waiter
    }

    fn forwarded(&self, opcode: Opcode) -> usize {
        self.state
            .forwarded
            .lock()
            .expect("unpoisoned")
            .iter()
            .filter(|carried| **carried == opcode.as_u16())
            .count()
    }

    fn connections(&self) -> usize {
        self.state.connections.load(Ordering::Relaxed)
    }
}

impl RelayState {
    /// Whichever direction ends first ends the other: each pump shuts both
    /// sockets down as it returns. Otherwise the return of the reply pump on a
    /// sprung trap would leave the request pump parked in `read_exact` on a
    /// client waiting for the answer the trap ate, with no `FIN` either way.
    fn serve(self: Arc<Self>, client: TcpStream) {
        let Ok(server) = UnixStream::connect(&self.server) else {
            let _ = client.shutdown(Shutdown::Both);
            return;
        };
        let (Ok(client_out), Ok(server_out)) = (client.try_clone(), server.try_clone()) else {
            return;
        };
        let (Ok(client_end), Ok(server_end)) = (client.try_clone(), server.try_clone()) else {
            return;
        };

        let upstream = {
            let state = Arc::clone(&self);
            let ends = (client.try_clone(), server.try_clone());
            thread::spawn(move || {
                let _ = pump(client, server, |frame| {
                    state.record(frame);
                    Verdict::Forward
                });
                if let (Ok(client), Ok(server)) = ends {
                    let _ = client.shutdown(Shutdown::Both);
                    let _ = server.shutdown(Shutdown::Both);
                }
            })
        };

        let _ = pump(server_out, client_out, |frame| self.judge(frame));
        let _ = client_end.shutdown(Shutdown::Both);
        let _ = server_end.shutdown(Shutdown::Both);
        let _ = upstream.join();
    }

    fn record(&self, frame: &[u8]) {
        if let Some(header) = header_of(frame)
            && header.flags.get() & FLAG_RESPONSE == 0
        {
            self.forwarded
                .lock()
                .expect("unpoisoned")
                .push(header.opcode.get());
        }
    }

    fn judge(&self, frame: &[u8]) -> Verdict {
        let Some(header) = header_of(frame) else {
            return Verdict::Forward;
        };
        if header.flags.get() & FLAG_RESPONSE == 0 {
            return Verdict::Forward;
        }
        let mut trap = self.trap.lock().expect("unpoisoned");
        if trap
            .as_ref()
            .is_none_or(|armed| armed.opcode != header.opcode.get())
        {
            return Verdict::Forward;
        }
        let armed = trap.take().expect("just matched");
        let _ = armed.sprung.send(());
        Verdict::Discard
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Verdict {
    Forward,
    Discard,
}

fn header_of(frame: &[u8]) -> Option<&FrameHeader> {
    FrameHeader::ref_from_prefix(frame)
        .ok()
        .map(|(header, _)| header)
}

fn pump(
    mut from: impl io::Read,
    mut to: impl io::Write,
    verdict: impl Fn(&[u8]) -> Verdict,
) -> io::Result<()> {
    loop {
        let Ok(frame) = support::read_message(&mut from) else {
            return Ok(());
        };
        match verdict(&frame) {
            Verdict::Forward => to.write_all(&frame)?,
            Verdict::Discard => return Ok(()),
        }
    }
}

#[test]
fn a_written_mutation_that_lost_its_answer_fails_and_is_not_applied_twice() {
    let mut ground = Ground::start("double-apply");
    let relay = Relay::start(ground.server.data_socket());
    let runtime = runtime();
    let client = ground.connect_to(&runtime, &relay.endpoint(), STALL);
    let caller = Caller::default();
    let root = client.root_node_id();

    let tree = runtime
        .block_on(client.lookup(caller, root, b"tree"))
        .expect("the graft resolves");

    reconnected_after(&client, || {
        let sprung = relay.discard_next_reply(Opcode::Mkdir);
        let refused = runtime
            .block_on(client.mkdir(caller, tree.node_id, b"made", 0o755, 0))
            .expect_err("a mutation that may already have been applied must not be re-sent");
        assert_eq!(refused, Errno::IO);
        sprung
            .recv()
            .expect("the relay discarded the server's answer");
    });

    reconnected_after(&client, || {
        ground.server.kill();
        assert!(
            ground.tree.join("made").is_dir(),
            "the server applied the mkdir once, and that is what makes the count meaningful"
        );
        ground.server.start_again();
    });
    assert_eq!(
        relay.forwarded(Opcode::Mkdir),
        1,
        "the mount re-sent a mutation whose answer it never saw"
    );
    runtime
        .block_on(client.lookup(caller, root, b"tree"))
        .expect("the mount serves after the refusal");
}

#[test]
fn a_written_idempotent_request_that_lost_its_answer_is_resent_and_completes() {
    let mut ground = Ground::start("resend");
    let relay = Relay::start(ground.server.data_socket());
    let runtime = runtime();
    let client = ground.connect_to(&runtime, &relay.endpoint(), STALL);
    let caller = Caller::default();
    let root = client.root_node_id();
    runtime
        .block_on(client.getattr(caller, root, None))
        .expect("the mount serves");
    let before = relay.forwarded(Opcode::Getattr);

    let sprung = relay.discard_next_reply(Opcode::Getattr);
    let asking = {
        let client = Arc::clone(&client);
        runtime.spawn(async move { client.getattr(caller, root, None).await })
    };
    sprung
        .recv()
        .expect("the relay discarded the server's answer");
    ground.server.kill();
    ground.server.start_again();

    let attr = runtime
        .block_on(asking)
        .expect("the task finished")
        .expect("an idempotent request survives the gap");
    assert!(attr.ino.get() != 0, "and it really was answered");
    // At least twice: once for the discarded answer, and once more over a
    // replacement connection. Not exactly twice: a replacement connection that
    // dies in its turn earns another attempt.
    assert!(
        relay.forwarded(Opcode::Getattr) - before >= 2,
        "an idempotent request whose answer was discarded must be sent again"
    );
    assert!(
        relay.connections() >= 2,
        "the answer must have come over a replacement connection"
    );
}

/// `flush` is not on the idempotent list because the server handler drops the
/// record-lock owner of the caller. Re-sending one whose answer was lost would
/// either re-apply that on a session that never saw the lock, or after a
/// restart surface an `EBADF` for a handle the guest never asked about.
#[test]
fn a_written_flush_that_lost_its_answer_fails_and_is_not_resent() {
    let mut ground = Ground::start("flush-once");
    let relay = Relay::start(ground.server.data_socket());
    let runtime = runtime();
    let client = ground.connect_to(&runtime, &relay.endpoint(), STALL);
    let caller = Caller::default();
    let root = client.root_node_id();

    let tree = runtime
        .block_on(client.lookup(caller, root, b"tree"))
        .expect("the graft resolves");
    let alpha = runtime
        .block_on(client.lookup(caller, tree.node_id, b"alpha"))
        .expect("the file resolves");
    let handle = runtime
        .block_on(client.open(caller, alpha.node_id, 0))
        .expect("the file opens");

    reconnected_after(&client, || {
        let sprung = relay.discard_next_reply(Opcode::Flush);
        let refused = runtime
            .block_on(client.flush(caller, alpha.node_id, handle, 0))
            .expect_err("a flush that may already have been applied must not be re-sent");
        assert_eq!(refused, Errno::IO);
        sprung
            .recv()
            .expect("the relay discarded the server's answer");
    });

    reconnected_after(&client, || {
        ground.server.kill();
        ground.server.start_again();
    });
    assert_eq!(
        relay.forwarded(Opcode::Flush),
        1,
        "the mount re-sent a flush whose answer it never saw"
    );
}

/// Every handle a guest can name was opened on a connection that is gone, so
/// the release is dropped as moot: it must neither wait out the stall window
/// nor fail `EIO` for a resource that no longer exists.
#[test]
fn a_release_with_no_connection_is_moot_at_once() {
    let mut ground = Ground::start("moot-release");
    let runtime = runtime();
    let endpoint = ground.server.endpoint();
    let client = ground.connect_to(&runtime, &endpoint, STALL);
    let caller = Caller::default();
    let root = client.root_node_id();

    let tree = runtime
        .block_on(client.lookup(caller, root, b"tree"))
        .expect("the graft resolves");
    let alpha = runtime
        .block_on(client.lookup(caller, tree.node_id, b"alpha"))
        .expect("the file resolves");
    let handle = runtime
        .block_on(client.open(caller, alpha.node_id, 0))
        .expect("the file opens");

    ground.server.kill();
    state_is(&client, |state| state != MountState::Connected);

    runtime.block_on(async {
        let mut release =
            std::pin::pin!(client.release(caller, alpha.node_id, handle, 0, None, false));
        let result =
            std::future::poll_fn(|cx| std::task::Poll::Ready(release.as_mut().poll(cx))).await;
        assert!(
            matches!(result, std::task::Poll::Ready(Ok(()))),
            "a moot release must complete without entering a wait: {result:?}"
        );
    });
}

/// It needs no relay: a request that arrives while the mount is reconnecting
/// never reaches a socket.
#[test]
fn a_queued_request_is_sent_after_the_re_handshake() {
    let mut ground = Ground::start("queued");
    let runtime = runtime();
    let endpoint = ground.server.endpoint();
    let client = ground.connect_to(&runtime, &endpoint, STALL);
    let caller = Caller::default();
    let root = client.root_node_id();
    runtime
        .block_on(client.lookup(caller, root, b"tree"))
        .expect("the mount serves");

    ground.server.kill();
    state_is(&client, |state| state != MountState::Connected);

    let (lookup, mutation) = runtime.block_on(async {
        let mut lookup = std::pin::pin!(client.lookup(caller, root, b"tree"));
        let mut mutation = std::pin::pin!(client.mkdir(caller, root, b"unreachable", 0o755, 0));
        std::future::poll_fn(|cx| {
            assert!(
                lookup.as_mut().poll(cx).is_pending(),
                "lookup waits for a connection"
            );
            assert!(
                mutation.as_mut().poll(cx).is_pending(),
                "mutation waits for a connection"
            );
            std::task::Poll::Ready(())
        })
        .await;
        ground.server.start_again();
        let (lookup, mutation) = tokio::join!(lookup, mutation);
        (lookup, mutation.err())
    });
    lookup.expect("a queued request is sent as it is once the handshake is back");
    // A queued mutation is sent too, since it never reached a server. This one
    // is refused on its merits (the namespace root is synthesized), which is an
    // answer from the server and not the gap.
    assert_eq!(
        mutation,
        Some(Errno::ROFS),
        "a queued mutation must reach the server and be judged by it"
    );
}

/// The first reply is already through the relay when its first entry is
/// offered, so the reply the trap takes is the one to the listing's next
/// request.
struct Tripwire {
    arm: Option<(Arc<RelayState>, mpsc::Sender<()>)>,
    taken: usize,
}

impl DirectorySink for Tripwire {
    fn offer(&mut self, _entry: &DirectoryEntry<'_>) -> bool {
        if let Some((state, sprung)) = self.arm.take() {
            *state.trap.lock().expect("unpoisoned") = Some(Trap {
                opcode: Opcode::Readdirplus.as_u16(),
                sprung,
            });
        }
        self.taken += 1;
        false
    }

    fn counts_lookups(&self) -> bool {
        true
    }
}

#[test]
fn a_listing_that_fails_after_a_reconnect_forgets_nothing_of_the_ended_connection() {
    // Far more entries than one page of a listing reply holds, so the
    // listing needs a second request.
    const ENTRIES: usize = 200;

    let ground = Ground::start("listing-across-reconnect");
    let wide = ground.directory.directory("tree/wide");
    for index in 0..ENTRIES {
        std::fs::write(wide.join(format!("f{index:04}")), b"x").expect("a writable tree");
    }
    let relay = Relay::start(ground.server.data_socket());
    let runtime = runtime();
    let client = ground.connect_to(&runtime, &relay.endpoint(), STALL);
    let caller = Caller::default();
    let root = client.root_node_id();

    let tree = runtime
        .block_on(client.lookup(caller, root, b"tree"))
        .expect("the graft resolves");
    let directory = runtime
        .block_on(client.lookup(caller, tree.node_id, b"wide"))
        .expect("the directory resolves");
    let handle = runtime
        .block_on(client.open(caller, directory.node_id, 0))
        .expect("the directory opens");

    let (sprung_tx, sprung) = mpsc::channel();
    let sink = Tripwire {
        arm: Some((Arc::clone(&relay.state), sprung_tx)),
        taken: 0,
    };
    let read = DirectoryRead {
        node_id: directory.node_id,
        handle,
        cookie: 0,
    };
    let (sink, outcome) = runtime.block_on(read_directory(
        &client,
        caller,
        read,
        Privileged::Present,
        sink,
    ));
    sprung
        .recv()
        .expect("the relay discarded the reply to the second request");
    assert!(
        outcome.is_err(),
        "the handle of the ended session names nothing on the replacement"
    );
    let sink = sink.expect("the sink comes back");
    assert!(sink.taken > 0, "the first request's entries were taken");
    assert!(relay.connections() >= 2, "the listing crossed a reconnect");

    // A reply on the replacement connection comes after every frame sent on
    // it before its request, a `forget` included.
    runtime
        .block_on(client.getattr(caller, root, None))
        .expect("the mount serves");
    assert_eq!(
        relay.forwarded(Opcode::Forget),
        0,
        "a lookup counted by the ended session was given back to the new one"
    );
}

#[test]
fn a_forget_of_an_ended_generation_never_reaches_the_newer_connection() {
    let mut ground = Ground::start("forget-of-ended-generation");
    let relay = Relay::start(ground.server.data_socket());
    let runtime = runtime();
    let client = ground.connect_to(&runtime, &relay.endpoint(), STALL);
    let caller = Caller::default();
    let root = client.root_node_id();

    let tree = runtime
        .block_on(client.lookup(caller, root, b"tree"))
        .expect("the graft resolves");
    runtime.block_on(client.forget_on(caller, FIRST_GENERATION, tree.node_id, 1));
    // A reply comes after every frame sent before its request, a `forget`
    // included.
    runtime
        .block_on(client.getattr(caller, root, None))
        .expect("the mount serves");
    assert_eq!(
        relay.forwarded(Opcode::Forget),
        1,
        "a forget of the installed connection's generation is sent"
    );

    reconnected_after(&client, || {
        ground.server.kill();
        ground.server.start_again();
    });
    assert!(relay.connections() >= 2, "a newer connection is installed");

    runtime.block_on(client.forget_on(caller, FIRST_GENERATION, tree.node_id, 1));
    runtime
        .block_on(client.getattr(caller, root, None))
        .expect("the mount serves on the newer connection");
    assert_eq!(
        relay.forwarded(Opcode::Forget),
        1,
        "a forget of the ended connection reached the newer one"
    );
}
