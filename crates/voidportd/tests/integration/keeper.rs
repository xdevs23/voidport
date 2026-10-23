#![forbid(unsafe_code)]

use voidport_test_server as support;

use std::fs::{self, File};
use std::os::fd::AsFd as _;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::Child;
use std::thread::JoinHandle;

use crate::frontend::{
    Device, EVENT_INDEX, FEATURES, INDIRECT, REPLY_LEN, Wait, body, frame, frame_chain,
    guest_memory, hello, lock, open, state_with_vhost_user,
};
use support::TempDir;
use support::wire::ROOT;
use vhost::VhostBackend as _;
use voidport_proto::frame::Frame;
use voidport_proto::limits::LIMITS;
use voidport_proto::ops::file::SetlkResponse;
use voidport_proto::ops::node::GetattrRequest;
use voidport_spawn::{Program, Stream};
use voidport_test_support::{ReadinessSocket, Startup, until};
use zerocopy::byteorder::little_endian::{U32, U64};

struct Fixture {
    directory: TempDir,
    readiness: ReadinessSocket,
    voidportd: Option<Child>,
    keeper: Option<JoinHandle<Result<(), voidport_keeper::Error>>>,
}

impl Fixture {
    fn start(label: &str) -> (Self, UnixStream) {
        let directory = TempDir::new(label);
        let tree = directory.directory("tree");
        let socket = directory.join("vhost-user.sock");
        let _state = directory.write("state.toml", &state_with_vhost_user(&socket, &tree));
        let readiness = ReadinessSocket::bind(directory.join("notify.sock"));
        let mut fixture = Self {
            directory,
            readiness,
            voidportd: None,
            keeper: None,
        };
        fixture.start_voidportd();
        let (qemu, keeper) = UnixStream::pair().expect("a socket pair");
        fixture.keeper = Some(std::thread::spawn(move || {
            voidport_keeper::serve(keeper, &socket)
        }));
        (fixture, qemu)
    }

    fn start_voidportd(&mut self) {
        let log = File::options()
            .create(true)
            .append(true)
            .open(self.directory.join("voidportd.log"))
            .expect("a log file");
        let voidportd = Program::new(env!("CARGO_BIN_EXE_voidportd"))
            .arg("--state")
            .arg(self.directory.join("state.toml"))
            .arg("--control-socket")
            .arg(self.directory.join("control.sock"))
            .env("NOTIFY_SOCKET", self.readiness.path())
            .stderr(Stream::Descriptor(log.as_fd()))
            .spawn()
            .expect("the daemon binary runs");
        assert_eq!(
            self.readiness.wait_for(&voidportd),
            Startup::Ready,
            "{}",
            fs::read_to_string(self.directory.join("voidportd.log")).unwrap_or_default()
        );
        self.voidportd = Some(voidportd);
    }

    fn kill_voidportd(&mut self) {
        if let Some(mut voidportd) = self.voidportd.take() {
            voidportd.kill().expect("voidportd is killed");
            let _status = voidportd.wait().expect("voidportd is reaped");
        }
    }

    fn host_file(&self, name: &str) -> PathBuf {
        self.directory.join("tree").join(name)
    }

    fn end_keeper(&mut self) {
        let keeper = self.keeper.take().expect("the keeper runs");
        keeper
            .join()
            .expect("the keeper does not panic")
            .expect("the keeper ends without an error");
    }
}

impl Wait for Fixture {
    fn until(&self, condition: &mut dyn FnMut() -> bool) {
        until(
            || self.keeper.as_ref().is_none_or(JoinHandle::is_finished),
            condition,
        );
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.kill_voidportd();
    }
}

/// Until the keeper has handed voidportd the device, it puts every chain back
/// with nothing written, so the hello is sent again.
fn hello_once_served(device: &mut Device<'_>, fixture: &Fixture, channel: u64) {
    let buffers = device.next_buffer;
    loop {
        let reply = device.exchange(fixture, 0, channel, &hello(1), &[], &[REPLY_LEN]);
        if !reply.is_empty() {
            assert_eq!(
                Frame::parse(&reply, &LIMITS).expect("a reply").status(),
                Ok(0)
            );
            return;
        }
        device.next_buffer = buffers;
    }
}

fn getattr(request_id: u64) -> Vec<u8> {
    frame(
        request_id,
        ROOT,
        &GetattrRequest {
            handle: U64::ZERO,
            flags: U32::ZERO,
            reserved: U32::ZERO,
        },
        &[],
    )
}

#[test]
fn a_restart_of_voidportd_ends_the_sessions_of_the_device_and_new_ones_open_after() {
    let (mut fixture, qemu) = Fixture::start("keeper-restart");
    let path = fixture.host_file("data.bin");
    fs::write(&path, b"held").expect("a host file");
    let (memory, file) = guest_memory();
    let mut device = Device::set_up(qemu, &memory, &file, 1, FEATURES);

    hello_once_served(&mut device, &fixture, 1);
    let (holding, node) = open(&mut device, &fixture, 2, "data.bin");
    let reply = device.exchange(
        &fixture,
        0,
        2,
        &lock(5, node, holding, 1, false),
        &[],
        &[REPLY_LEN],
    );
    let _locked: SetlkResponse = body(&reply);
    let (waiting, node) = open(&mut device, &fixture, 3, "data.bin");
    let in_flight = device.send_frame(0, 3, &lock(5, node, waiting, 2, true), &[], &[REPLY_LEN]);
    device.fence(&fixture, 0);

    fixture.kill_voidportd();
    assert_eq!(
        device.finished(&fixture, 0),
        (in_flight.head, 0),
        "the request in flight ends with nothing written"
    );
    let reply = device.exchange(&fixture, 0, 2, &getattr(6), &[], &[REPLY_LEN]);
    assert!(reply.is_empty(), "a request while voidportd is away");
    let reply = device.exchange(&fixture, 0, 4, &hello(1), &[], &[REPLY_LEN]);
    assert!(reply.is_empty(), "a new session while voidportd is away");

    fixture.start_voidportd();
    hello_once_served(&mut device, &fixture, 5);
    let (handle, node) = open(&mut device, &fixture, 6, "data.bin");
    let reply = device.exchange(
        &fixture,
        0,
        6,
        &lock(5, node, handle, 3, false),
        &[],
        &[REPLY_LEN],
    );
    let _locked: SetlkResponse = body(&reply);
    let reply = device.exchange(&fixture, 0, 2, &getattr(7), &[], &[REPLY_LEN]);
    assert!(
        reply.is_empty(),
        "a channel of the old voidportd is not open"
    );

    let _features = device
        .frontend
        .get_features()
        .expect("the keeper still answers QEMU");
    drop(device);
    fixture.end_keeper();
}

fn wait_for_lock(
    device: &mut Device<'_>,
    fixture: &Fixture,
    name: &str,
    channels: &[(usize, u64)],
) -> Vec<u16> {
    let opened: Vec<(u64, u64)> = channels
        .iter()
        .map(|&(_, channel)| open(device, fixture, channel, name))
        .collect();
    let heads: Vec<u16> = channels
        .iter()
        .zip(opened)
        .map(|(&(queue, channel), (handle, node))| {
            let request = lock(5, node, handle, channel, true);
            device
                .send_frame(queue, channel, &request, &[], &[REPLY_LEN])
                .head
        })
        .collect();
    for queue in 0..device.queues.len() {
        device.fence(fixture, queue);
    }
    heads
}

fn hold_lock(device: &mut Device<'_>, fixture: &Fixture, channel: u64, name: &str) {
    let (handle, node) = open(device, fixture, channel, name);
    let reply = device.exchange(
        fixture,
        0,
        channel,
        &lock(5, node, handle, channel, false),
        &[],
        &[REPLY_LEN],
    );
    let _locked: SetlkResponse = body(&reply);
}

#[test]
fn a_kill_puts_back_the_chains_in_flight_on_every_queue_in_order() {
    let (mut fixture, qemu) = Fixture::start("keeper-in-flight");
    fs::write(fixture.host_file("data.bin"), b"held").expect("a host file");
    let (memory, file) = guest_memory();
    let mut device = Device::set_up(qemu, &memory, &file, 2, FEATURES | EVENT_INDEX);
    hello_once_served(&mut device, &fixture, 1);
    hold_lock(&mut device, &fixture, 2, "data.bin");
    let heads = wait_for_lock(&mut device, &fixture, "data.bin", &[(0, 3), (1, 4), (0, 5)]);

    let finished = device.queues[0].ring.avail().idx().load() - 2;
    device.signal_after(0, finished);
    device.signal_after(1, u16::MAX / 2);
    for queue in &device.queues {
        let _earlier = queue.call.read();
    }

    fixture.kill_voidportd();
    assert_eq!(device.finished(&fixture, 0), (heads[0], 0));
    assert_eq!(device.finished(&fixture, 0), (heads[2], 0));
    assert_eq!(device.finished(&fixture, 1), (heads[1], 0));
    let call = &device.queues[0].call;
    fixture.until(&mut || {
        call.read()
            .map(|signals| assert_eq!(signals, 1, "one signal for both chains"))
            .is_ok()
    });
    for (queue, request_id) in [(0, 6), (0, 7), (1, 8)] {
        // `exchange` checks that the chain finished is the one just sent.
        let reply = device.exchange(&fixture, queue, 2, &getattr(request_id), &[], &[REPLY_LEN]);
        assert!(reply.is_empty(), "a request while voidportd is away");
    }
    for queue in &device.queues {
        assert!(
            queue.call.read().is_err(),
            "no signal the driver did not ask for"
        );
    }
    drop(device);
    fixture.end_keeper();
}

#[test]
fn a_queue_stopped_while_voidportd_runs_it_goes_on_from_its_position() {
    let (mut fixture, qemu) = Fixture::start("keeper-stop");
    fs::write(fixture.host_file("data.bin"), b"held").expect("a host file");
    let (memory, file) = guest_memory();
    let mut device = Device::set_up(qemu, &memory, &file, 1, FEATURES | INDIRECT);
    hello_once_served(&mut device, &fixture, 1);
    hold_lock(&mut device, &fixture, 2, "data.bin");
    let heads = wait_for_lock(&mut device, &fixture, "data.bin", &[(0, 3)]);

    let position = device.restart_queue(0);
    assert_eq!(device.finished(&fixture, 0), (heads[0], 0));
    assert_eq!(position, device.queues[0].ring.avail().idx().load());
    let sent = device.send_indirect(0, &frame_chain(4, &hello(1), REPLY_LEN), &[], &[REPLY_LEN]);
    let (head, written) = device.finished(&fixture, 0);
    assert_eq!(head, sent.head);
    let reply = device.written(&sent.writable, written);
    assert_eq!(
        Frame::parse(&reply, &LIMITS).expect("a reply").status(),
        Ok(0)
    );

    fixture.kill_voidportd();
    let reply = device.exchange(&fixture, 0, 4, &getattr(2), &[], &[REPLY_LEN]);
    assert!(reply.is_empty(), "a request while voidportd is away");
    drop(device);
    fixture.end_keeper();
}
