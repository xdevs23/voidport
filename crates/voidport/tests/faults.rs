//! The frames are hand-assembled because they must be malformed: the protocol
//! encoder refuses to produce a frame its own parser would reject.
//!
//! The poisoning cases run fail-fast ([`Resilience::stall`] of zero): a mount
//! that reconnected would reconnect to the very server whose answers it cannot
//! read, and every assertion would measure a stall window.

#![forbid(unsafe_code)]

use std::io::{Read as _, Write as _};
use std::net::{Shutdown, SocketAddr, TcpListener};
use std::thread::JoinHandle;
use std::time::Duration;

use rustix::io::Errno;
use voidport::client::{Caller, Client, ConnectError, Resilience};
use voidport::url::Endpoint;
use voidport_proto::PROTOCOL_VERSION;
use voidport_proto::frame::{
    FLAG_RESPONSE, FRAME_HEADER_LEN, Frame, FrameHeader, FrameWriter, Parsed,
};
use voidport_proto::limits::LIMITS;
use voidport_proto::message::ResponseHead;
use voidport_proto::ops::handshake::HelloReply;
use zerocopy::byteorder::little_endian::{U32, U64};
use zerocopy::{FromBytes as _, IntoBytes as _};

#[derive(Clone, Copy, Debug)]
enum Fault {
    WrongOpcode,
    InvalidStatus,
    MidFrameEof,
}

impl Fault {
    fn frame(self, opcode: u16, request_id: u64) -> Vec<u8> {
        let mut bytes = Vec::new();
        match self {
            Self::WrongOpcode => {
                // Any opcode but the one asked for, with an error status so
                // nothing follows it.
                let header = FrameHeader::new(opcode.wrapping_add(1), FLAG_RESPONSE, request_id);
                bytes.extend_from_slice(header.as_bytes());
                bytes.extend_from_slice(ResponseHead::new(-2).as_bytes());
            }
            Self::InvalidStatus => {
                let header = FrameHeader::new(opcode, FLAG_RESPONSE, request_id);
                bytes.extend_from_slice(header.as_bytes());
                // Positive: no conforming peer can produce it, and it is not an
                // errno the caller could be handed.
                bytes.extend_from_slice(ResponseHead::new(7).as_bytes());
            }
            Self::MidFrameEof => {
                let header = FrameHeader::new(opcode, FLAG_RESPONSE, request_id);
                bytes.extend_from_slice(header.as_bytes());
                bytes.extend_from_slice(ResponseHead::new(0).as_bytes());
                bytes.extend_from_slice(&[0u8; 4]);
            }
        }
        bytes
    }

    fn closes(self) -> bool {
        matches!(self, Self::MidFrameEof)
    }
}

/// It waits for the request before answering, so the fault arrives while it is
/// outstanding. The joined peer reports every byte up to stream closure after
/// the fault, which must be none.
fn fault_server(fault: Fault) -> (SocketAddr, JoinHandle<usize>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a free port");
    let address = listener.local_addr().expect("a bound address");
    let peer = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("the client connects");

        let hello = read_frame(&mut stream).expect("a hello");
        let request_id = Frame::parse(&hello, &LIMITS)
            .expect("a well-framed hello")
            .request_id();
        let token = b"token";
        let mut buffer = [0u8; 64];
        let reply = hello_reply(1);
        let mut writer = FrameWriter::response(
            &mut buffer,
            &LIMITS,
            request_id,
            &HelloReply {
                token_len: U32::new(token.len() as u32),
                ..reply
            },
        )
        .expect("encodable");
        writer.payload(token).expect("fits");
        let reply = writer.finish().expect("whole").to_vec();
        stream.write_all(&reply).expect("the client is listening");

        let first = read_frame(&mut stream).expect("a request");
        let (header, _) = FrameHeader::ref_from_prefix(&first).expect("a header");
        let bytes = fault.frame(header.opcode.get(), header.request_id.get());
        stream.write_all(&bytes).expect("the client is listening");
        if fault.closes() {
            stream
                .shutdown(Shutdown::Write)
                .expect("the write half closes");
        }

        // EOF fences the complete send stream. Silence for any duration
        // cannot establish that the connection has stopped transmitting.
        let mut after = Vec::new();
        stream
            .read_to_end(&mut after)
            .expect("the poisoned connection closes");
        after.len()
    });

    (address, peer)
}

fn read_frame(stream: &mut std::net::TcpStream) -> Option<Vec<u8>> {
    let mut bytes = vec![0u8; FRAME_HEADER_LEN];
    stream.read_exact(&mut bytes).ok()?;
    loop {
        match Frame::parse_prefix(&bytes, &LIMITS).expect("a well-framed message") {
            Parsed::Frame(_) => return Some(bytes),
            Parsed::Need(needed) => {
                let have = bytes.len();
                bytes.resize(needed, 0);
                stream.read_exact(&mut bytes[have..]).ok()?;
            }
        }
    }
}

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
        )
        .await
        .expect("the handshake succeeds");
        let caller = Caller::default();

        // The request outstanding when the fault arrives. The connection was
        // the session's only one, so its loss is the session's.
        let lookup = client
            .lookup(caller, client.root_node_id(), b"anything")
            .await;
        assert_eq!(
            lookup.err(),
            Some(Errno::IO),
            "{fault:?}: outstanding lookup"
        );

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

    drop(runtime);
    let after = observed.join().expect("the fault server completed");
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

fn hello_reply(root_node_id: u64) -> HelloReply {
    HelloReply {
        root_node_id: U64::new(root_node_id),
        protocol_version: U32::new(PROTOCOL_VERSION),
        flags: U32::ZERO,
        connection_id: U64::new(1),
        token_len: U32::ZERO,
        reserved: U32::ZERO,
    }
}

/// `answered_id` is the request id it echoes, which a conforming server takes
/// from the `Hello` it just read.
fn announcing_server(reply: HelloReply, answered_id: Option<u64>) -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a free port");
    let address = listener.local_addr().expect("a bound address");
    let peer = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("the client connects");
        let hello = read_frame(&mut stream).expect("a hello");
        let request_id = Frame::parse(&hello, &LIMITS)
            .expect("a well-framed hello")
            .request_id();
        let mut buffer = [0u8; 64];
        let bytes = FrameWriter::response(
            &mut buffer,
            &LIMITS,
            answered_id.unwrap_or(request_id),
            &reply,
        )
        .and_then(FrameWriter::finish)
        .expect("encodable")
        .to_vec();
        stream.write_all(&bytes).expect("the hello reply is sent");
        // Keep the peer alive until the client closes after its own refusal.
        let mut after = Vec::new();
        stream
            .read_to_end(&mut after)
            .expect("the refused connection closes");
        assert!(after.is_empty(), "a refused mount sends no operations");
    });
    (address, peer)
}

fn refusal(reply: HelloReply, answered_id: Option<u64>) -> ConnectError {
    let (address, peer) = announcing_server(reply, answered_id);
    let endpoint = Endpoint::Tcp {
        host: address.ip().to_string(),
        port: address.port(),
    };
    let error = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime")
        .block_on(async move {
            Client::mount(&endpoint, "namespace", b"")
                .await
                .expect_err("the mount is refused")
        });
    peer.join().expect("the announcing server completed");
    error
}

#[test]
fn a_root_node_id_the_kernel_cannot_name_refuses_the_mount() {
    let error = refusal(hello_reply(7), None);
    assert!(
        matches!(error, ConnectError::RootNodeId { announced: 7, .. }),
        "{error:?}"
    );
}

#[test]
fn a_handshake_reply_answering_another_request_refuses_the_mount() {
    let error = refusal(hello_reply(1), Some(99));
    assert!(matches!(error, ConnectError::Protocol { .. }), "{error:?}");
}
