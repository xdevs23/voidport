#![forbid(unsafe_code)]

use voidport_test_server as support;

use std::fs;
use std::os::unix::fs::MetadataExt as _;

use rustix::fs::OFlags;
use support::Dial as _;
use support::fixture::Fixture;
use support::wire::{ROOT, ShareNotification, status};
use voidport_control::{Reply, Request, Rule, ShareMode};
use voidport_proto::message::ResponseOutcome;
use voidport_proto::ops::file::{FileLock, ReadRequest, SetlkResponse, WriteRequest, lock_type};
use voidport_proto::ops::node::{GetattrRequest, GetattrResponse};
use zerocopy::byteorder::little_endian::{U32, U64};

const APPENDING: OFlags = OFlags::RDWR.union(OFlags::APPEND);

fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|at| seed.wrapping_add((at % 251) as u8))
        .collect()
}

fn getattr() -> GetattrRequest {
    GetattrRequest {
        handle: U64::ZERO,
        flags: U32::ZERO,
        reserved: U32::ZERO,
    }
}

#[test]
fn a_write_waiting_for_its_data_does_not_stop_another_connection() {
    let fixture = Fixture::start("inline-held-write");
    let path = fixture.tree("held.bin");
    fs::write(&path, b"").expect("writable");
    let block = fs::metadata(&path).expect("stat").blksize() as usize;
    let data = pattern(3 * block + 17, 3);

    let mut writer = fixture.server.mount("plain", "/tree");
    let file = writer.lookup(ROOT, "held.bin").expect("resolves");
    let handle = writer.open(file.node_id, OFlags::RDWR).expect("opens");
    let (id, bytes) = writer.write_request(handle, 0, &data);
    let frame = bytes.len() - data.len();
    writer.send_bytes(&bytes[..frame]);

    let mut other = fixture.server.mount("plain", "/tree");
    assert!(
        other.getattr(ROOT).is_ok(),
        "another connection is answered while the write waits for its data"
    );

    writer.send_bytes(&bytes[frame..]);
    let (answered, written) = writer.receive_written();
    assert_eq!(answered, id);
    assert_eq!(written, Ok(data.len() as u32));
    assert_eq!(fs::read(&path).expect("host bytes"), data);
}

#[test]
fn a_refused_write_is_drained_and_the_next_request_is_answered() {
    let fixture = Fixture::start("inline-refused-write");
    let mut client = fixture.server.mount("plain", "/tree");
    let data = pattern(10_000, 7);
    let (write, mut bytes) = client.write_request(987_654, 0, &data);
    let (next, request) = client.encoded(ROOT, &getattr(), &[]);
    bytes.extend_from_slice(&request);
    client.send_bytes(&bytes);

    let (answered, written) = client.receive_written();
    assert_eq!((answered, written), (write, Err(status::BADF)));
    assert_eq!(
        client.receive_status::<GetattrResponse>(),
        (next, 0),
        "the request behind the refused write is read in step"
    );
}

#[test]
fn a_client_that_stops_reading_costs_no_other_connection() {
    const READS: usize = 8;
    const SIZE: usize = 1024 * 1024;

    let fixture = Fixture::start("inline-stalled-reader");
    let path = fixture.tree("large.bin");
    let contents = pattern(READS * SIZE, 11);
    fs::write(&path, &contents).expect("writable");

    let mut stalled = fixture.server.mount("plain", "/tree");
    let file = stalled.lookup(ROOT, "large.bin").expect("resolves");
    let handle = stalled.open(file.node_id, OFlags::RDWR).expect("opens");
    let mut asked = Vec::new();
    for index in 0..READS {
        let body = ReadRequest {
            handle: U64::new(handle),
            offset: U64::new((index * SIZE) as u64),
            size: U32::new(SIZE as u32),
            flags: U32::ZERO,
        };
        let (id, bytes) = stalled.encoded(file.node_id, &body, &[]);
        stalled.send_bytes(&bytes);
        asked.push((id, index));
    }

    let mut other = fixture.server.mount("plain", "/tree");
    let entry = other.lookup(ROOT, "data.bin").expect("resolves");
    let other_handle = other.open(entry.node_id, OFlags::RDWR).expect("opens");
    assert_eq!(
        other.read(other_handle, 0, 64).expect("reads"),
        b"0123456789",
        "another connection is served while this one does not read"
    );

    let mut answered = Vec::new();
    for _ in 0..READS {
        let received = stalled.receive_message().expect("the server answers");
        let id = received.parsed().request_id();
        let closing = received.closing.expect("a streamed reply");
        assert_eq!(closing.status, 0);
        let (_, index) = asked
            .iter()
            .copied()
            .find(|(asked, _)| *asked == id)
            .expect("a reply to a read that was sent");
        assert_eq!(
            received.pieces.concat(),
            contents[index * SIZE..(index + 1) * SIZE],
            "read {index} arrives whole"
        );
        answered.push(id);
    }
    answered.sort_unstable();
    let mut expected: Vec<u64> = asked.iter().map(|(id, _)| *id).collect();
    expected.sort_unstable();
    assert_eq!(answered, expected, "every reply arrives once");
}

#[test]
fn appends_from_two_connections_stay_whole() {
    const RECORD: usize = 256 * 1024;

    let fixture = Fixture::start("inline-appends");
    let path = fixture.tree("log.bin");
    fs::write(&path, b"").expect("writable");
    let records = [vec![b'a'; RECORD], vec![b'b'; RECORD]];

    let mut clients: Vec<_> = (0..2)
        .map(|_| {
            let mut client = fixture.server.mount("plain", "/tree");
            let file = client.lookup(ROOT, "log.bin").expect("resolves");
            let handle = client.open(file.node_id, APPENDING).expect("opens");
            (client, handle)
        })
        .collect();
    std::thread::scope(|scope| {
        for ((client, handle), record) in clients.iter_mut().zip(&records) {
            scope.spawn(move || {
                assert_eq!(
                    client.write(*handle, 0, record),
                    Ok(RECORD as u32),
                    "an append is written whole"
                );
            });
        }
    });

    let written = fs::read(&path).expect("host bytes");
    assert_eq!(written.len(), 2 * RECORD);
    let (first, second) = written.split_at(RECORD);
    assert!(
        (first == records[0] && second == records[1])
            || (first == records[1] && second == records[0]),
        "each record is whole and apart from the other"
    );
}

#[test]
fn a_write_cut_off_mid_data_leaves_the_pieces_that_arrived() {
    let fixture = Fixture::start("inline-cut-write");
    let path = fixture.tree("cut.bin");
    fs::write(&path, b"").expect("writable");
    let block = fs::metadata(&path).expect("stat").blksize() as usize;
    let data = pattern(3 * block, 5);

    let mut client = fixture.server.mount("plain", "/tree");
    let file = client.lookup(ROOT, "cut.bin").expect("resolves");
    let handle = client.open(file.node_id, OFlags::RDWR).expect("opens");
    let (_, bytes) = client.write_request(handle, 0, &data);
    let frame = bytes.len() - data.len();
    client.send_bytes(&bytes[..frame + block + block / 2]);
    client.disconnect(&fixture.server);

    assert_eq!(
        fs::read(&path).expect("host bytes"),
        data[..block],
        "the piece that arrived is written, and nothing else"
    );
}

#[test]
fn an_append_longer_than_one_write_call_ends_the_connection() {
    let fixture = Fixture::start("inline-long-append");
    fs::write(fixture.tree("long.bin"), b"").expect("writable");
    let mut client = fixture.server.mount("plain", "/tree");
    let file = client.lookup(ROOT, "long.bin").expect("resolves");
    let handle = client.open(file.node_id, APPENDING).expect("opens");
    let body = WriteRequest {
        handle: U64::new(handle),
        offset: U64::ZERO,
        data_len: U32::new(0x7fff_f001),
        flags: U32::ZERO,
        write_flags: U32::ZERO,
        reserved: U32::ZERO,
    };
    let (_, frame) = client.encoded(file.node_id, &body, &[]);
    client.send_bytes(&frame);
    assert!(
        client.receive().is_none(),
        "the connection ends instead of collecting the append"
    );
    assert_eq!(fs::read(fixture.tree("long.bin")).expect("host bytes"), b"");
}

#[test]
fn every_writer_of_a_connection_writes_whole_messages() {
    const REQUESTS: usize = 16;
    const RULES: usize = 16;

    let fixture = Fixture::start("inline-three-writers");
    let mut client = fixture.server.mount("plain", "");
    client.subscribe().expect("subscribed");
    client.share_snapshot();

    let mut holder = fixture.server.mount("plain", "/tree");
    let held = holder.lookup(ROOT, "data.bin").expect("resolves");
    let held_handle = holder.open(held.node_id, OFlags::RDWR).expect("opens");
    holder
        .setlk(held_handle, lock(1, lock_type::WRITE), false)
        .expect("the range is free");

    let tree = client.lookup(ROOT, "tree").expect("resolves");
    let file = client.lookup(tree.node_id, "data.bin").expect("resolves");
    let handle = client.open(file.node_id, OFlags::RDWR).expect("opens");
    let locking = client.send(
        0,
        &voidport_proto::ops::file::SetlkRequest {
            handle: U64::new(handle),
            lock: lock(2, lock_type::WRITE),
            flags: U32::new(1),
            reserved: U32::ZERO,
        },
        &[],
    );
    // A reply to a later request shows the server has read the lock request.
    client.fence();

    let mut asked = Vec::new();
    std::thread::scope(|scope| {
        scope.spawn(|| {
            for index in 0..RULES {
                let mut control = fixture.server.connect();
                assert_eq!(
                    control.expect_ok(&Request::RuleAdd {
                        namespace: voidport_control::NamespaceName::new("plain")
                            .expect("a valid name"),
                        rule: Rule::new(format!("/tree/written{index}"), ShareMode::Ro),
                    }),
                    Reply::Done {}
                );
            }
        });
        scope.spawn(|| {
            holder
                .setlk(held_handle, lock(1, lock_type::UNLOCK), false)
                .expect("releases");
        });
        for _ in 0..REQUESTS {
            asked.push(client.send(ROOT, &getattr(), &[]));
        }
    });

    let (mut replies, mut settled, mut notices) = (0, false, 0);
    while replies < REQUESTS || !settled || notices < RULES {
        let received = client.receive_message().expect("the server writes");
        let frame = received.parsed();
        match frame.kind() {
            voidport_proto::frame::FrameKind::Notification => {
                notices += 1;
            }
            _ if frame.request_id() == locking => {
                assert!(matches!(
                    frame.response::<SetlkResponse>().expect("a lock reply"),
                    ResponseOutcome::Success(_)
                ));
                settled = true;
            }
            _ => {
                assert!(asked.contains(&frame.request_id()));
                assert!(matches!(
                    frame
                        .response::<GetattrResponse>()
                        .expect("a getattr reply"),
                    ResponseOutcome::Success(_)
                ));
                replies += 1;
            }
        }
    }
    assert_eq!(
        fixture.share_events_before("plain", "/tree", &mut [&mut client]),
        vec![Vec::<ShareNotification>::new()],
        "every notification arrived once"
    );
}

fn lock(owner: u64, kind: u32) -> FileLock {
    FileLock {
        start: U64::ZERO,
        end: U64::new(u64::MAX),
        owner: U64::new(owner),
        pid: U32::new(7),
        lock_type: U32::new(kind),
    }
}
