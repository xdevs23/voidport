//! Replay discipline at its linearization points.
//!
//! Reconnect-increment criterion **6**. A request is *queued* (never fully
//! written), *written*, or *answered*, and what the mount does with it after a
//! re-handshake follows from which of the three it was:
//!
//! * queued — sent as it is, because the server's socket was shut down before
//!   anything was retried, so it provably never reached a dispatcher;
//! * written and idempotent — sent again;
//! * written and not idempotent — failed `EIO`, because a second application
//!   would be a second application.
//!
//! The third case cannot be proven by timing: "the reply was lost" and "the
//! request never arrived" look the same from the client, and a test that races
//! the server's death against its own request would be asserting on luck. So
//! the design rules a **test-harness relay** instead — it forwards the request,
//! watches the server answer it, **discards that answer**, and kills the
//! server. Whether the mutation was applied twice is then not a question about
//! timing at all: it is a count of the request frames the relay carried.

mod support;

use std::io;
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::Duration;

use rustix::io::Errno;
use support::daemon::{Ground, PATIENCE, eventually, runtime, settle};
use voidport::client::{Caller, MountState};
use voidport::url::Endpoint;
use voidport_proto::frame::{FLAG_RESPONSE, FRAME_HEADER_LEN, FrameHeader};
use voidport_proto::opcode::Opcode;
use zerocopy::FromBytes as _;

/// The window these tests run with.
///
/// Long enough that a restart never closes it: the subject here is *which*
/// requests are re-sent, not when a mount gives up.
const STALL: Duration = Duration::from_secs(30);

// ---------------------------------------------------------------------------
// The relay
// ---------------------------------------------------------------------------

/// A tcp front for the server's unix socket that can discard one reply.
///
/// It is frame-aware because it has to be: discarding *a reply* means knowing
/// where one frame ends, and counting *requests of one opcode* means reading
/// the header. It reads that header with the protocol crate's own type, so
/// there is no hand-written parsing here either.
struct Relay {
    address: SocketAddr,
    state: Arc<RelayState>,
}

/// What the relay's threads share.
struct RelayState {
    /// The unix socket every accepted connection is forwarded to.
    server: PathBuf,
    /// How many request frames of each opcode have been carried to the server.
    forwarded: Mutex<Vec<u16>>,
    /// The response opcode to discard, and who to tell when it happens.
    ///
    /// Armed once; the first matching reply disarms it, so a re-sent request is
    /// answered normally.
    trap: Mutex<Option<Trap>>,
    /// How many connections have been accepted, for tests that need to know a
    /// reconnect really happened.
    connections: AtomicUsize,
}

/// One armed discard.
struct Trap {
    opcode: u16,
    sprung: mpsc::Sender<()>,
}

impl Relay {
    /// Starts a relay in front of `server`.
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

    /// The endpoint a client dials to reach the server through this relay.
    fn endpoint(&self) -> Endpoint {
        Endpoint::Tcp {
            host: self.address.ip().to_string(),
            port: self.address.port(),
        }
    }

    /// Arms the relay to discard the next reply carrying `opcode`.
    fn discard_next_reply(&self, opcode: Opcode) -> mpsc::Receiver<()> {
        let (sprung, waiter) = mpsc::channel();
        *self.state.trap.lock().expect("unpoisoned") = Some(Trap {
            opcode: opcode.as_u16(),
            sprung,
        });
        waiter
    }

    /// How many request frames of `opcode` have reached the server.
    fn forwarded(&self, opcode: Opcode) -> usize {
        self.state
            .forwarded
            .lock()
            .expect("unpoisoned")
            .iter()
            .filter(|carried| **carried == opcode.as_u16())
            .count()
    }

    /// How many connections the relay has accepted.
    fn connections(&self) -> usize {
        self.state.connections.load(Ordering::Relaxed)
    }
}

impl RelayState {
    /// Pumps one accepted connection in both directions until either end stops.
    ///
    /// The two directions are one connection, so whichever of them ends first
    /// ends the other: each pump shuts **both** sockets down as it returns.
    /// Without that, the reply pump's return on a sprung trap would leave the
    /// request pump parked in `read_exact` on a client that is waiting for the
    /// answer the trap just ate — no `FIN` either way, and both sides waiting
    /// forever. Shutting them down is also what makes the discarded reply
    /// *mean* something to the client: the connection dies where it stood.
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

        // Requests: forwarded always, counted always.
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

        // Replies: forwarded unless the trap is armed for this one.
        let _ = pump(server_out, client_out, |frame| self.judge(frame));
        let _ = client_end.shutdown(Shutdown::Both);
        let _ = server_end.shutdown(Shutdown::Both);
        let _ = upstream.join();
    }

    /// Counts a request frame on its way to the server.
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

    /// Decides whether one reply reaches the client.
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
        // Sprung: the server answered, the client never hears it, and the
        // connection dies where it stood.
        let armed = trap.take().expect("just matched");
        let _ = armed.sprung.send(());
        Verdict::Discard
    }
}

/// What the relay does with one frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Verdict {
    /// Pass it on unchanged.
    Forward,
    /// Drop it and end the connection.
    Discard,
}

/// The frame header at the front of a buffer.
fn header_of(frame: &[u8]) -> Option<&FrameHeader> {
    FrameHeader::ref_from_prefix(frame)
        .ok()
        .map(|(header, _)| header)
}

/// Copies whole frames from one stream to another until a verdict stops it.
fn pump(
    mut from: impl io::Read,
    mut to: impl io::Write,
    verdict: impl Fn(&[u8]) -> Verdict,
) -> io::Result<()> {
    loop {
        let mut header = [0u8; FRAME_HEADER_LEN];
        if from.read_exact(&mut header).is_err() {
            // End of stream, or the peer went away: either way this direction
            // is over.
            return Ok(());
        }
        let len = header_of(&header)
            .map(|header| header.len.get() as usize)
            .filter(|len| *len >= FRAME_HEADER_LEN)
            .ok_or_else(|| io::Error::other("a frame with an impossible length"))?;
        let mut frame = vec![0u8; len];
        frame[..FRAME_HEADER_LEN].copy_from_slice(&header);
        from.read_exact(&mut frame[FRAME_HEADER_LEN..])?;
        match verdict(&frame) {
            Verdict::Forward => to.write_all(&frame)?,
            Verdict::Discard => return Ok(()),
        }
    }
}

// ---------------------------------------------------------------------------
// Criterion 6 — the three linearization points
// ---------------------------------------------------------------------------

/// A written-but-unanswered **mutation** fails `EIO` and is provably not
/// applied twice.
///
/// The relay carries the `mkdir` to the server, the server applies it, the
/// relay discards the answer and the connection dies. The directory is on the
/// host — it was applied once — the client is told `EIO`, and the count of
/// `mkdir` frames the relay ever carried is one. No timing is involved in any
/// of those three facts.
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

    let sprung = relay.discard_next_reply(Opcode::Mkdir);
    let refused = runtime
        .block_on(client.mkdir(caller, tree.node_id, b"made", 0o755, 0))
        .expect_err("a mutation that may already have been applied must not be re-sent");
    assert_eq!(refused, Errno::IO);
    sprung
        .recv_timeout(PATIENCE)
        .expect("the relay discarded the server's answer");

    // The server dies with its answer undelivered, exactly as the harness
    // rules; the effect it already had is on the host filesystem.
    ground.server.kill();
    assert!(
        ground.tree.join("made").is_dir(),
        "the server applied the mkdir once, and that is what makes the count meaningful"
    );

    ground.server.start_again();
    settle(&client);
    assert_eq!(
        relay.forwarded(Opcode::Mkdir),
        1,
        "the mount re-sent a mutation whose answer it never saw"
    );
    // And the mount is serving again, so nothing about the refusal was fatal.
    runtime
        .block_on(client.lookup(caller, root, b"tree"))
        .expect("the mount serves after the refusal");
}

/// A written-but-unanswered **idempotent** request is re-sent and completes.
///
/// Same machinery, opposite verdict: applying a `getattr` twice is applying it
/// once, so the mount owes the caller an answer, not an error. The relay
/// counts two of them, and the caller sees one success.
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
        .recv_timeout(PATIENCE)
        .expect("the relay discarded the server's answer");
    ground.server.kill();
    ground.server.start_again();

    let attr = runtime
        .block_on(asking)
        .expect("the task finished")
        .expect("an idempotent request survives the gap");
    assert!(attr.ino.get() != 0, "and it really was answered");
    // At least twice: once for the answer that was discarded, and once more
    // over a replacement connection. Not *exactly* twice, and deliberately so —
    // a replacement connection that dies in its turn earns another attempt, and
    // that is the whole point of calling this class idempotent. The count that
    // has to be exact is the mutation's, in the test above.
    assert!(
        relay.forwarded(Opcode::Getattr) - before >= 2,
        "an idempotent request whose answer was discarded must be sent again"
    );
    assert!(
        relay.connections() >= 2,
        "the answer must have come over a replacement connection"
    );
}

/// A written-but-unanswered **flush** fails `EIO` and is not re-sent.
///
/// `flush` is not on the design's idempotent list, and the server's own handler
/// is why: it drops the caller's record-lock owner. Re-sending one whose answer
/// was lost would either re-apply that on a session that never saw the lock, or
/// — after a restart — surface an `EBADF` for a handle the guest never asked
/// about. So it takes the mutation's verdict, proven the same way: the relay
/// carries exactly one `flush` frame.
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

    let sprung = relay.discard_next_reply(Opcode::Flush);
    let refused = runtime
        .block_on(client.flush(caller, alpha.node_id, handle, 0))
        .expect_err("a flush that may already have been applied must not be re-sent");
    assert_eq!(refused, Errno::IO);
    sprung
        .recv_timeout(PATIENCE)
        .expect("the relay discarded the server's answer");

    ground.server.kill();
    ground.server.start_again();
    settle(&client);
    assert_eq!(
        relay.forwarded(Opcode::Flush),
        1,
        "the mount re-sent a flush whose answer it never saw"
    );
}

/// A **release** issued while the mount has no connection is moot at once.
///
/// Every handle a guest can name was opened on a connection that is gone, so
/// the handle this names died with its session whatever the mount does next.
/// The contract drops such a release as moot — so it must neither wait out the
/// stall window (a `close(2)` blocking for seconds on a server that is not
/// coming back) nor fail `EIO` for a resource that no longer exists.
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
    assert!(
        eventually(PATIENCE, || client.state() != MountState::Connected),
        "the mount never noticed its server had gone"
    );

    let started = std::time::Instant::now();
    runtime
        .block_on(client.release(caller, alpha.node_id, handle, 0, None, false))
        .expect("a release whose session is gone answers as though it had succeeded");
    let waited = started.elapsed();
    assert!(
        waited < STALL / 2,
        "a moot release waited {waited:?} of a {STALL:?} stall window"
    );
}

/// A **queued** request — one issued while there is no connection at all — is
/// sent after the re-handshake and completes.
///
/// It needs no relay: a request that arrives while the mount is reconnecting
/// never reaches a socket, which is the definition of queued, and the mount's
/// own stall is what holds it until there is somewhere to send it.
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
    assert!(
        eventually(PATIENCE, || client.state() != MountState::Connected),
        "the mount never noticed its server had gone"
    );

    // Issued with nothing to send it on: it stalls instead of failing.
    let queued = {
        let client = Arc::clone(&client);
        runtime.spawn(async move {
            (
                client.lookup(caller, root, b"tree").await,
                client
                    .mkdir(caller, root, b"unreachable", 0o755, 0)
                    .await
                    .err(),
            )
        })
    };
    thread::sleep(Duration::from_millis(200));
    ground.server.start_again();

    let (lookup, mutation) = runtime.block_on(queued).expect("the task finished");
    lookup.expect("a queued request is sent as it is once the handshake is back");
    // A queued *mutation* is sent too — it provably never reached a server, so
    // there is nothing to apply twice. This one is refused on its merits (the
    // namespace root is synthesized), which is an answer from the server and
    // not the gap.
    assert_eq!(
        mutation,
        Some(Errno::ROFS),
        "a queued mutation must reach the server and be judged by it"
    );
}
