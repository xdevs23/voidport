#![forbid(unsafe_code)]

mod frontend;

use voidport_test_server as support;

use std::fs;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

use frontend::{
    Device, EVENT_INDEX, FEATURES, INDIRECT, QUEUE_SIZE, REPLY_LEN, Wait, body, frame, frame_chain,
    guest_memory, hello, lock, open, state_with_vhost_user,
};
use support::wire::ROOT;
use support::{RunningServer, TempDir, daemon_config};
use vm_memory::GuestMemoryMmap;
use voidport_control::SessionSummary;
use voidport_proto::chain::{ChainHead, ChainKind, ChannelNumber};
use voidport_proto::frame::{Frame, Parsed};
use voidport_proto::limits::LIMITS;
use voidport_proto::ops::file::{ReadRequest, SetlkResponse, WriteRequest, WriteResponse};
use voidport_proto::ops::node::GetattrRequest;
use voidport_proto::piece::{self, ClosingBody};
use zerocopy::IntoBytes as _;
use zerocopy::byteorder::little_endian::{U32, U64};

struct Server {
    directory: TempDir,
    server: RunningServer,
    socket: PathBuf,
}

impl Server {
    fn start(label: &str) -> Self {
        let directory = TempDir::new(label);
        let tree = directory.directory("tree");
        let socket = directory.join("vhost-user.sock");
        let state = directory.write("state.toml", &state_with_vhost_user(&socket, &tree));
        let server = RunningServer::start(&daemon_config(&state)).expect("the server starts");
        Self {
            directory,
            server,
            socket,
        }
    }

    fn device<'m>(
        &self,
        memory: &'m GuestMemoryMmap,
        file: &fs::File,
        queues: u16,
        features: u64,
    ) -> Device<'m> {
        let stream = UnixStream::connect(&self.socket).expect("the listener accepts");
        Device::set_up(stream, memory, file, queues, features)
    }

    fn sessions(&self) -> Vec<SessionSummary> {
        self.server.service().sessions().list()
    }

    fn host_file(&self, name: &str) -> PathBuf {
        self.directory.join("tree").join(name)
    }
}

impl Wait for Server {
    fn until(&self, condition: &mut dyn FnMut() -> bool) {
        self.server.until(condition);
    }
}

impl Device<'_> {
    fn disconnect(self) {
        drop(self.frontend);
    }

    fn end(&mut self, server: &Server, queue: usize, channel: u64, kind: ChainKind) -> usize {
        let readable = ChainHead::new(ChannelNumber(channel), kind, 0)
            .as_bytes()
            .to_vec();
        let sent = self.send(queue, &readable, &[], &[]);
        let (head, written) = self.finished(server, queue);
        assert_eq!(head, sent.head);
        written
    }
}

fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len).map(|at| (at % 251) as u8 ^ seed).collect()
}

#[test]
fn a_session_on_a_channel_moves_file_data_in_guest_memory() {
    session_moves_file_data_in_guest_memory("virtio-data", FEATURES);
}

#[test]
fn a_session_on_a_channel_moves_file_data_with_event_indices() {
    session_moves_file_data_in_guest_memory("virtio-data-event-index", FEATURES | EVENT_INDEX);
}

fn session_moves_file_data_in_guest_memory(label: &str, features: u64) {
    let server = Server::start(label);
    let contents = pattern(3 * 4096 + 100, 0);
    fs::write(server.host_file("data.bin"), &contents).expect("a host file");
    let (memory, file) = guest_memory();
    let mut device = server.device(&memory, &file, 1, features);

    let (handle, node) = open(&mut device, &server, 1, "data.bin");
    let sessions = server.sessions();
    assert_eq!(sessions.len(), 1, "{sessions:?}");
    assert_eq!(sessions[0].transport, "vhost-user");
    server.server.until(|| device.queues[0].call.read().is_ok());

    let read = ReadRequest {
        handle: U64::new(handle),
        offset: U64::ZERO,
        size: U32::new(u32::try_from(contents.len()).expect("a short file")),
        flags: U32::ZERO,
    };
    let readable = frame_chain(1, &frame(5, node, &read, &[]), REPLY_LEN);
    let sent = device.send(0, &readable, &[], &[REPLY_LEN, 5000, 10_000]);
    let (head, written) = device.finished(&server, 0);
    assert_eq!(head, sent.head);
    let reply = device.written(&sent.writable[..1], REPLY_LEN);
    let Ok(Parsed::Frame(reply_head)) = Frame::parse_prefix(&reply, &LIMITS) else {
        panic!("a reply head");
    };
    assert_eq!(reply_head.status(), Ok(0));
    let rest = &reply[reply_head.len()..];
    let piece_len = piece::read_length(rest[..4].try_into().expect("a length")) as usize;
    assert_eq!(piece_len, contents.len(), "one piece, as long as the file");
    assert_eq!(
        piece::read_length(rest[4..8].try_into().expect("a length")),
        0
    );
    let closing = ClosingBody::parse(rest[8..16].try_into().expect("a closing")).expect("legal");
    assert_eq!(closing.status, 0);
    let reply_bytes = reply_head.len() + 16;
    assert_eq!(
        written,
        reply_bytes + contents.len(),
        "the reply and the data"
    );
    assert_eq!(
        device.written(&sent.writable[1..], contents.len()),
        contents,
        "the file, in the data area"
    );

    let replacement = pattern(6000, 0x5a);
    let write = WriteRequest {
        handle: U64::new(handle),
        offset: U64::ZERO,
        data_len: U32::new(6000),
        flags: U32::ZERO,
        write_flags: U32::ZERO,
        reserved: U32::ZERO,
    };
    let request = frame(6, node, &write, &replacement);
    let reply = device.exchange(&server, 0, 1, &request, &[40, 2000, 5000], &[REPLY_LEN]);
    assert_eq!(body::<WriteResponse>(&reply).written.get(), 6000);
    let host = fs::read(server.host_file("data.bin")).expect("the host file");
    assert_eq!(&host[..6000], &replacement[..]);
    assert_eq!(&host[6000..], &contents[6000..]);
}

#[test]
fn a_chain_that_does_not_belong_to_an_open_session_gets_nothing_written() {
    let server = Server::start("virtio-refused");
    let (memory, file) = guest_memory();
    let mut device = server.device(&memory, &file, 1, FEATURES);
    let getattr = GetattrRequest {
        handle: U64::ZERO,
        flags: U32::ZERO,
        reserved: U32::ZERO,
    };

    let reply = device.exchange(
        &server,
        0,
        7,
        &frame(1, ROOT, &getattr, &[]),
        &[],
        &[REPLY_LEN],
    );
    assert!(reply.is_empty(), "a frame on a channel that is not open");
    assert!(server.sessions().is_empty());

    let reply = device.exchange(&server, 0, 1, &hello(1), &[], &[REPLY_LEN]);
    assert_eq!(
        Frame::parse(&reply, &LIMITS).expect("a reply").status(),
        Ok(0)
    );
    assert_eq!(server.sessions().len(), 1);
    let mut trailing = frame(2, ROOT, &getattr, &[]);
    trailing.push(0);
    let reply = device.exchange(&server, 0, 1, &trailing, &[], &[REPLY_LEN]);
    assert!(reply.is_empty(), "a frame with a byte after it");
    server.server.until(|| server.sessions().is_empty());
}

#[test]
fn a_close_ends_its_channel_and_a_reset_ends_every_channel() {
    let server = Server::start("virtio-close");
    let (memory, file) = guest_memory();
    let mut device = server.device(&memory, &file, 2, FEATURES);

    for (queue, channel) in [(0, 1), (1, 2), (0, 3)] {
        let reply = device.exchange(&server, queue, channel, &hello(1), &[], &[REPLY_LEN]);
        assert_eq!(
            Frame::parse(&reply, &LIMITS).expect("a reply").status(),
            Ok(0)
        );
    }
    assert_eq!(server.sessions().len(), 3);

    assert_eq!(device.end(&server, 1, 2, ChainKind::Close), 0);
    assert_eq!(
        server.sessions().len(),
        2,
        "the close finished once its session ended"
    );
    assert_eq!(device.end(&server, 0, 0, ChainKind::Reset), 0);
    assert!(
        server.sessions().is_empty(),
        "the reset finished once every session ended"
    );
}

#[test]
fn a_frontend_that_goes_away_ends_the_sessions_of_its_device() {
    let server = Server::start("virtio-gone");
    let (memory, file) = guest_memory();
    let mut device = server.device(&memory, &file, 1, FEATURES);
    let reply = device.exchange(&server, 0, 1, &hello(1), &[], &[REPLY_LEN]);
    assert_eq!(
        Frame::parse(&reply, &LIMITS).expect("a reply").status(),
        Ok(0)
    );
    assert_eq!(server.sessions().len(), 1);

    device.disconnect();
    server.server.until(|| server.sessions().is_empty());
}

#[test]
fn a_queue_whose_driver_makes_more_chains_available_than_it_holds_breaks_alone() {
    let server = Server::start("virtio-broken");
    let (memory, file) = guest_memory();
    let mut device = server.device(&memory, &file, 2, FEATURES);

    let broken = &device.queues[0];
    broken.ring.avail().idx().store(QUEUE_SIZE + 1);
    broken.kick.write(1).expect("kicked");

    let reply = device.exchange(&server, 1, 1, &hello(1), &[], &[REPLY_LEN]);
    assert_eq!(
        Frame::parse(&reply, &LIMITS).expect("a reply").status(),
        Ok(0)
    );
}

#[test]
fn the_device_signals_the_driver_at_the_position_it_asked_for() {
    let server = Server::start("virtio-event-index");
    let (memory, file) = guest_memory();
    let mut device = server.device(&memory, &file, 1, FEATURES | EVENT_INDEX);

    device.signal_after(0, 10);
    for request_id in [1, 2] {
        let sent = device.send_frame(0, request_id, &hello(request_id), &[], &[REPLY_LEN]);
        let (head, written) = device.finished(&server, 0);
        assert_eq!(head, sent.head);
        assert_ne!(written, 0, "the hello is answered");
    }
    device.signal_after(0, 2);
    let sent = device.send_frame(0, 3, &hello(3), &[], &[REPLY_LEN]);
    assert_eq!(device.finished(&server, 0).0, sent.head);
    let call = &device.queues[0].call;
    server.server.until(|| {
        call.read()
            .map(|signals| assert_eq!(signals, 1, "only the third chain signals"))
            .is_ok()
    });
}

#[test]
fn a_chain_listed_through_a_table_of_its_own_is_served() {
    let server = Server::start("virtio-indirect");
    let (memory, file) = guest_memory();
    let mut device = server.device(&memory, &file, 1, FEATURES | INDIRECT);

    let readable = frame_chain(1, &hello(1), REPLY_LEN);
    let sent = device.send_indirect(0, &readable, &[8, 20], &[REPLY_LEN]);
    let (head, written) = device.finished(&server, 0);
    assert_eq!(head, sent.head);
    // The reply parses only when nothing was written after it.
    let reply = device.written(&sent.writable, written);
    assert_eq!(
        Frame::parse(&reply, &LIMITS).expect("a reply").status(),
        Ok(0)
    );
    assert_eq!(server.sessions().len(), 1);
}

#[test]
fn a_stopped_queue_puts_back_the_chains_in_flight() {
    let server = Server::start("virtio-stop");
    let path = server.host_file("data.bin");
    fs::write(&path, b"held").expect("a host file");
    let (memory, file) = guest_memory();
    let mut device = server.device(&memory, &file, 1, FEATURES);

    let (holding, node) = open(&mut device, &server, 1, "data.bin");
    let reply = device.exchange(
        &server,
        0,
        1,
        &lock(5, node, holding, 1, false),
        &[],
        &[REPLY_LEN],
    );
    let _locked: SetlkResponse = body(&reply);
    let (waiting, node) = open(&mut device, &server, 2, "data.bin");
    let in_flight = device.send_frame(0, 2, &lock(5, node, waiting, 2, true), &[], &[REPLY_LEN]);
    device.fence(&server, 0);

    let position = device.restart_queue(0);
    assert_eq!(
        device.finished(&server, 0),
        (in_flight.head, 0),
        "the request in flight ends with nothing written"
    );
    assert_eq!(
        device.queues[0].ring.avail().idx().load(),
        position,
        "the position follows every chain made available"
    );
    let reply = device.exchange(&server, 0, 3, &hello(1), &[], &[REPLY_LEN]);
    assert_eq!(
        Frame::parse(&reply, &LIMITS).expect("a reply").status(),
        Ok(0)
    );
}
