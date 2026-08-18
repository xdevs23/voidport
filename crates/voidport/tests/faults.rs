//! Protocol faults on the response side.
//!
//! Criterion 14. The server here is wrong on purpose: it completes a real
//! handshake and then answers with something the protocol does not allow. The
//! contract rules that any such fault is treated exactly like connection loss —
//! outstanding and subsequent operations fail with `EIO`, and nothing further is
//! ever written to the socket — so each case checks all three, the last one
//! from the server's side of the wire.
//!
//! The frames below are hand-assembled precisely because they must be
//! malformed: the protocol crate's encoder refuses to produce a frame its own
//! parser would reject, which is the property being relied on everywhere else.
//!
//! The last group is the handshake's own side of this: a well-framed
//! `HelloReply` that announces something no session can be served under. Those
//! are refusals, not poisonings — nothing is mounted yet — and each one
//! exists because the alternative is silent breakage: a frame bound of zero
//! reads every file as empty, and a root node id the kernel cannot name would
//! address the wrong node from the first lookup onwards.
//!
//! The poisoning cases run **fail-fast** ([`Resilience::stall`] of zero). The
//! subject here is the fault, not the recovery: a mount that reconnected would
//! be reconnecting to the very server whose answers it cannot read, and every
//! assertion below would be measuring a stall window instead of a taxonomy.
//! What happens *after* a connection dies is the resilience suites' subject.

use std::io::{Read as _, Write as _};
use std::net::{Shutdown, SocketAddr, TcpListener};
use std::sync::mpsc;
use std::time::Duration;

use rustix::io::Errno;
use voidport::client::{Caller, Client, Concurrency, ConnectError, Resilience};
use voidport::url::Endpoint;
use voidport_proto::PROTOCOL_VERSION;
use voidport_proto::frame::{
    FLAG_RESPONSE, FRAME_HEADER_LEN, Frame, FrameHeader, FrameWriter, MAX_HELLO_FRAME_LEN,
};
use voidport_proto::message::{RESPONSE_HEAD_LEN, ResponseHead};
use voidport_proto::ops::handshake::HelloReply;
use zerocopy::byteorder::little_endian::{U32, U64};
use zerocopy::{FromBytes as _, IntoBytes as _};

/// The frame bound the fault server announces, as the real one does.
const MAX_FRAME_LEN: u32 = 1024 * 1024;

/// How long the test waits for the server thread to report.
const PATIENCE: Duration = Duration::from_secs(20);

/// What the server does instead of answering.
#[derive(Clone, Copy, Debug)]
enum Fault {
    /// A response whose opcode is not the one the outstanding request carried.
    WrongOpcode,
    /// A status that is neither success nor a negated errno.
    InvalidStatus,
    /// A frame header announcing a length the server then does not deliver.
    MidFrameEof,
}

impl Fault {
    /// The bytes this fault puts on the wire, answering `request_id` for a
    /// request that carried `opcode`.
    fn frame(self, opcode: u16, request_id: u64) -> Vec<u8> {
        let mut bytes = Vec::new();
        match self {
            Self::WrongOpcode => {
                // Any opcode but the one asked for; the client matches the
                // response against the request it is still waiting on.
                let header = FrameHeader::new(
                    (FRAME_HEADER_LEN + RESPONSE_HEAD_LEN) as u32,
                    opcode.wrapping_add(1),
                    FLAG_RESPONSE,
                    request_id,
                );
                bytes.extend_from_slice(header.as_bytes());
                bytes.extend_from_slice(ResponseHead::new(0).as_bytes());
            }
            Self::InvalidStatus => {
                let header = FrameHeader::new(
                    (FRAME_HEADER_LEN + RESPONSE_HEAD_LEN) as u32,
                    opcode,
                    FLAG_RESPONSE,
                    request_id,
                );
                bytes.extend_from_slice(header.as_bytes());
                // Positive: no conforming peer can produce it, and it is not an
                // errno the caller could be handed.
                bytes.extend_from_slice(ResponseHead::new(7).as_bytes());
            }
            Self::MidFrameEof => {
                let header = FrameHeader::new(64, opcode, FLAG_RESPONSE, request_id);
                bytes.extend_from_slice(header.as_bytes());
                bytes.extend_from_slice(&[0u8; 8]);
            }
        }
        bytes
    }

    /// Whether the fault ends the server's half of the stream.
    fn closes(self) -> bool {
        matches!(self, Self::MidFrameEof)
    }
}

/// Starts a server that handshakes and then misbehaves.
///
/// It waits for **two** requests before answering, so the fault lands while
/// both are outstanding. The channel reports how many bytes the client sent
/// after the fault — which must be none.
fn fault_server(fault: Fault) -> (SocketAddr, mpsc::Receiver<usize>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a free port");
    let address = listener.local_addr().expect("a bound address");
    let (report, observed) = mpsc::channel();

    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("the client connects");
        stream
            .set_read_timeout(Some(Duration::from_secs(20)))
            .expect("a settable timeout");

        // A real handshake, so everything after it is the fault under test.
        let hello = read_frame(&mut stream).expect("a hello");
        let request_id = Frame::parse(&hello, MAX_HELLO_FRAME_LEN)
            .expect("a well-framed hello")
            .request_id();
        let mut buffer = [0u8; 64];
        let reply = FrameWriter::response(
            &mut buffer,
            MAX_HELLO_FRAME_LEN,
            request_id,
            &HelloReply {
                root_node_id: U64::new(1),
                protocol_version: U32::new(PROTOCOL_VERSION),
                flags: U32::ZERO,
                max_frame_len: U32::new(MAX_FRAME_LEN),
                reserved: U32::ZERO,
            },
        )
        .and_then(FrameWriter::finish)
        .expect("encodable")
        .to_vec();
        stream.write_all(&reply).expect("the client is listening");

        let first = read_frame(&mut stream).expect("a request");
        let _second = read_frame(&mut stream).expect("a second request");
        let (header, _) = FrameHeader::ref_from_prefix(&first).expect("a header");
        let bytes = fault.frame(header.opcode.get(), header.request_id.get());
        stream.write_all(&bytes).expect("the client is listening");
        if fault.closes() {
            stream
                .shutdown(Shutdown::Write)
                .expect("the write half closes");
        }

        // Whatever the client does next, it must not be to send anything.
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("a settable timeout");
        let mut after = 0;
        let mut scratch = [0u8; 4096];
        loop {
            match stream.read(&mut scratch) {
                Ok(0) | Err(_) => break,
                Ok(read) => after += read,
            }
        }
        let _ = report.send(after);
    });

    (address, observed)
}

/// Reads one whole frame from a blocking stream.
fn read_frame(stream: &mut std::net::TcpStream) -> Option<Vec<u8>> {
    let mut header = [0u8; FRAME_HEADER_LEN];
    stream.read_exact(&mut header).ok()?;
    let (parsed, _) = FrameHeader::ref_from_prefix(&header).expect("a header");
    let mut bytes = vec![0u8; parsed.len.get() as usize];
    bytes[..FRAME_HEADER_LEN].copy_from_slice(&header);
    stream.read_exact(&mut bytes[FRAME_HEADER_LEN..]).ok()?;
    Some(bytes)
}

/// Runs one fault to its conclusion.
fn assert_poisons(fault: Fault) {
    let (address, observed) = fault_server(fault);
    let endpoint = Endpoint::Tcp {
        host: address.ip().to_string(),
        port: address.port(),
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");

    runtime.block_on(async move {
        let client = Client::mount_with(
            &endpoint,
            "namespace",
            b"",
            Resilience {
                stall: Duration::ZERO,
            },
            Concurrency::default(),
        )
        .await
        .expect("the handshake succeeds");
        let caller = Caller::default();

        // Two requests outstanding when the fault lands.
        let (lookup, getattr) = tokio::join!(
            client.lookup(caller, client.root_node_id(), b"anything"),
            client.getattr(caller, client.root_node_id(), None),
        );
        assert_eq!(
            lookup.err(),
            Some(Errno::IO),
            "{fault:?}: outstanding lookup"
        );
        assert_eq!(
            getattr.err(),
            Some(Errno::IO),
            "{fault:?}: outstanding getattr"
        );

        // And everything after it.
        for round in 0..3 {
            assert_eq!(
                client
                    .getattr(caller, client.root_node_id(), None)
                    .await
                    .err(),
                Some(Errno::IO),
                "{fault:?}: request {round} after the fault"
            );
        }
        assert!(
            client.death().is_some(),
            "{fault:?}: the connection should be marked dead"
        );
    });

    let after = observed
        .recv_timeout(PATIENCE)
        .expect("the fault server reports");
    assert_eq!(
        after, 0,
        "{fault:?}: the client sent {after} bytes on a dead connection"
    );
}

#[test]
fn a_response_with_the_wrong_opcode_poisons_the_connection() {
    assert_poisons(Fault::WrongOpcode);
}

#[test]
fn a_response_with_an_impossible_status_poisons_the_connection() {
    assert_poisons(Fault::InvalidStatus);
}

#[test]
fn a_frame_that_stops_half_way_poisons_the_connection() {
    assert_poisons(Fault::MidFrameEof);
}

/// A `HelloReply` a conforming server would send.
fn hello_reply(max_frame_len: u32, root_node_id: u64) -> HelloReply {
    HelloReply {
        root_node_id: U64::new(root_node_id),
        protocol_version: U32::new(PROTOCOL_VERSION),
        flags: U32::ZERO,
        max_frame_len: U32::new(max_frame_len),
        reserved: U32::ZERO,
    }
}

/// Starts a server that answers the handshake with exactly what it is given.
///
/// `answered_id` is the request id it echoes, which a conforming server takes
/// from the `Hello` it just read.
fn announcing_server(reply: HelloReply, answered_id: Option<u64>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a free port");
    let address = listener.local_addr().expect("a bound address");
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("the client connects");
        stream
            .set_read_timeout(Some(Duration::from_secs(20)))
            .expect("a settable timeout");
        let hello = read_frame(&mut stream).expect("a hello");
        let request_id = Frame::parse(&hello, MAX_HELLO_FRAME_LEN)
            .expect("a well-framed hello")
            .request_id();
        let mut buffer = [0u8; 64];
        let bytes = FrameWriter::response(
            &mut buffer,
            MAX_HELLO_FRAME_LEN,
            answered_id.unwrap_or(request_id),
            &reply,
        )
        .and_then(FrameWriter::finish)
        .expect("encodable")
        .to_vec();
        let _ = stream.write_all(&bytes);
        // Held open so the refusal is the client's decision, not an EOF.
        std::thread::sleep(Duration::from_secs(2));
    });
    address
}

/// Attempts a mount against a server announcing `reply`.
fn refusal(reply: HelloReply, answered_id: Option<u64>) -> ConnectError {
    let address = announcing_server(reply, answered_id);
    let endpoint = Endpoint::Tcp {
        host: address.ip().to_string(),
        port: address.port(),
    };
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime")
        .block_on(async move {
            Client::mount(&endpoint, "namespace", b"")
                .await
                .expect_err("the mount is refused")
        })
}

#[test]
fn a_frame_bound_too_small_to_serve_refuses_the_mount() {
    // Below this the payload budget saturates to zero: reads would return
    // nothing and report success, which is worse than any error.
    for announced in [0, 8, MAX_HELLO_FRAME_LEN - 1] {
        let error = refusal(hello_reply(announced, 1), None);
        assert!(
            matches!(error, ConnectError::FrameBound { announced: a, .. } if a == announced),
            "{announced}: {error:?}"
        );
    }
    // The pre-handshake bound itself is enough to serve under.
    assert!(matches!(
        refusal(hello_reply(MAX_HELLO_FRAME_LEN, 2), None),
        ConnectError::RootNodeId { .. }
    ));
}

#[test]
fn a_root_node_id_the_kernel_cannot_name_refuses_the_mount() {
    let error = refusal(hello_reply(1024 * 1024, 7), None);
    assert!(
        matches!(error, ConnectError::RootNodeId { announced: 7, .. }),
        "{error:?}"
    );
}

#[test]
fn a_handshake_reply_answering_another_request_refuses_the_mount() {
    let error = refusal(hello_reply(1024 * 1024, 1), Some(99));
    assert!(matches!(error, ConnectError::Protocol { .. }), "{error:?}");
}
