#![forbid(unsafe_code)]

use voidport_proto::error::FramingError;
use voidport_proto::frame::{FLAG_RESPONSE, Frame, FrameHeader, FrameKind, FrameWriter, Parsed};
use voidport_proto::limits::Limits;
use voidport_proto::message::{Follows, RequestHead, ResponseOutcome};
use voidport_proto::opcode::{NotificationOpcode, Opcode};
use voidport_proto::ops::connection::{
    CancelRequest, OutcomeRequest, OutcomeResponse, RetireRequest, RetireResponse,
};
use voidport_proto::ops::dir::DirEntryHeader;
use voidport_proto::ops::dir::{
    LinkRequest, LinkResponse, MkdirRequest, MkdirResponse, MknodRequest, MknodResponse,
    ReaddirplusRequest, ReaddirplusResponse, RenameRequest, RenameResponse, RmdirRequest,
    RmdirResponse, SymlinkRequest, SymlinkResponse, UnlinkRequest, UnlinkResponse,
};
use voidport_proto::ops::file::{
    CreateRequest, CreateResponse, FlushRequest, FlushResponse, FsyncRequest, FsyncResponse,
    GetlkRequest, GetlkResponse, OpenRequest, OpenResponse, ReadRequest, ReadResponse,
    ReleaseRequest, ReleaseResponse, SetlkRequest, SetlkResponse, WriteRequest, WriteResponse,
};
use voidport_proto::ops::handshake::{HelloReply, HelloRequest};
use voidport_proto::ops::node::{
    ForgetRequest, GetattrRequest, GetattrResponse, LookupRequest, LookupResponse, ReadlinkRequest,
    ReadlinkResponse, SetattrRequest, SetattrResponse, StatfsRequest, StatfsResponse,
};
use voidport_proto::ops::recall::{
    Recall, RecalledRequest, RecalledResponse, RelinquishRequest, RelinquishResponse, RenewRequest,
    RenewResponse,
};
use voidport_proto::ops::share::ShareEntryHeader;
use voidport_proto::ops::share::{
    ShareAdded, ShareChanged, ShareEnded, ShareRemoved, ShareSnapshotBegin, ShareSnapshotEnd,
    ShareSnapshotPart,
};
use voidport_proto::ops::subscribe::{
    SubscribeRequest, SubscribeResponse, UnsubscribeRequest, UnsubscribeResponse,
};
use voidport_proto::ops::xattr::{
    GetxattrRequest, GetxattrResponse, ListxattrRequest, ListxattrResponse, RemovexattrRequest,
    RemovexattrResponse, SetxattrRequest, SetxattrResponse, guest_list_size,
};
use voidport_proto::piece::{self, ClosingBody, PIECE_LEN_LEN, Stream};
use zerocopy::IntoBytes;
use zerocopy::byteorder::little_endian::U32;

const LIMITS: Limits = Limits {
    name_max: linux_raw_sys::general::NAME_MAX,
    path_max: linux_raw_sys::general::PATH_MAX,
    xattr_name_max: linux_raw_sys::general::XATTR_NAME_MAX,
    xattr_size_max: linux_raw_sys::general::XATTR_SIZE_MAX,
    xattr_list_max: linux_raw_sys::general::XATTR_LIST_MAX,
};

struct Rng(u64);

impl Rng {
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn next_u8(&mut self) -> u8 {
        self.next_u64() as u8
    }

    fn below(&mut self, bound: usize) -> usize {
        (self.next_u64() % bound as u64) as usize
    }
}

fn exercise(buf: &[u8]) {
    let _ = FrameHeader::parse(buf);
    let _ = Frame::parse(buf, &LIMITS);
    let Ok(Parsed::Frame(frame)) = Frame::parse_prefix(buf, &LIMITS) else {
        return;
    };
    let _ = frame.kind();
    let _ = frame.request_id();
    let _ = frame.body();
    let _ = frame.status();
    if let Follows::Pieces(stream) = frame.follows() {
        exercise_pieces(&buf[frame.len()..], stream);
    }
    if frame.kind() == FrameKind::Notification {
        exercise_notification(&frame);
        return;
    }
    let Ok(opcode) = frame.opcode() else {
        return;
    };
    match opcode {
        Opcode::Hello => {
            if let Ok(request) = frame.request::<HelloRequest>() {
                let _ = (
                    request.namespace(),
                    request.subpath(),
                    request.auth(),
                    request.token(),
                );
            }
            if let Ok(ResponseOutcome::Success(reply)) = frame.response::<HelloReply>() {
                let _ = reply.token();
            }
        }
        Opcode::Lookup => {
            if let Ok(request) = frame.request::<LookupRequest>() {
                let _ = request.name();
            }
            let _ = frame.response::<LookupResponse>();
        }
        Opcode::Forget => {
            let _ = frame.request::<ForgetRequest>();
        }
        Opcode::Getattr => {
            let _ = frame.request::<GetattrRequest>();
            let _ = frame.response::<GetattrResponse>();
        }
        Opcode::Setattr => {
            let _ = frame.request::<SetattrRequest>();
            let _ = frame.response::<SetattrResponse>();
        }
        Opcode::Readlink => {
            let _ = frame.request::<ReadlinkRequest>();
            if let Ok(Some(response)) = frame.response::<ReadlinkResponse>().map(|r| r.success()) {
                let _ = response.target();
            }
        }
        Opcode::Symlink => {
            if let Ok(request) = frame.request::<SymlinkRequest>() {
                let _ = (request.name(), request.target());
            }
            let _ = frame.response::<SymlinkResponse>();
        }
        Opcode::Mkdir => {
            if let Ok(request) = frame.request::<MkdirRequest>() {
                let _ = request.name();
            }
            let _ = frame.response::<MkdirResponse>();
        }
        Opcode::Mknod => {
            if let Ok(request) = frame.request::<MknodRequest>() {
                let _ = request.name();
            }
            let _ = frame.response::<MknodResponse>();
        }
        Opcode::Unlink => {
            if let Ok(request) = frame.request::<UnlinkRequest>() {
                let _ = request.name();
            }
            let _ = frame.response::<UnlinkResponse>();
        }
        Opcode::Rmdir => {
            if let Ok(request) = frame.request::<RmdirRequest>() {
                let _ = request.name();
            }
            let _ = frame.response::<RmdirResponse>();
        }
        Opcode::Rename => {
            if let Ok(request) = frame.request::<RenameRequest>() {
                let _ = (request.old_name(), request.new_name());
            }
            let _ = frame.response::<RenameResponse>();
        }
        Opcode::Link => {
            if let Ok(request) = frame.request::<LinkRequest>() {
                let _ = request.name();
            }
            let _ = frame.response::<LinkResponse>();
        }
        Opcode::Open => {
            let _ = frame.request::<OpenRequest>();
            let _ = frame.response::<OpenResponse>();
        }
        Opcode::Read => {
            let _ = frame.request::<ReadRequest>();
            let _ = frame.response::<ReadResponse>();
        }
        Opcode::Write => {
            let _ = frame.request::<WriteRequest>();
            let _ = frame.response::<WriteResponse>();
        }
        Opcode::Statfs => {
            let _ = frame.request::<StatfsRequest>();
            let _ = frame.response::<StatfsResponse>();
        }
        Opcode::Release => {
            let _ = frame.request::<ReleaseRequest>();
            let _ = frame.response::<ReleaseResponse>();
        }
        Opcode::Fsync => {
            let _ = frame.request::<FsyncRequest>();
            let _ = frame.response::<FsyncResponse>();
        }
        Opcode::Setxattr => {
            if let Ok(request) = frame.request::<SetxattrRequest>() {
                let _ = (request.name(), request.value());
            }
            let _ = frame.response::<SetxattrResponse>();
        }
        Opcode::Getxattr => {
            if let Ok(request) = frame.request::<GetxattrRequest>() {
                let _ = request.name();
            }
            if let Ok(Some(response)) = frame.response::<GetxattrResponse>().map(|r| r.success()) {
                let _ = response.value();
            }
        }
        Opcode::Listxattr => {
            let _ = frame.request::<ListxattrRequest>();
            if let Ok(Some(response)) = frame.response::<ListxattrResponse>().map(|r| r.success()) {
                for name in response.names() {
                    let _ = name;
                }
                let _ = guest_list_size(response.names());
            }
        }
        Opcode::Removexattr => {
            if let Ok(request) = frame.request::<RemovexattrRequest>() {
                let _ = request.name();
            }
            let _ = frame.response::<RemovexattrResponse>();
        }
        Opcode::Flush => {
            let _ = frame.request::<FlushRequest>();
            let _ = frame.response::<FlushResponse>();
        }
        Opcode::Readdirplus => {
            let _ = frame.request::<ReaddirplusRequest>();
            let _ = frame.response::<ReaddirplusResponse>();
        }
        Opcode::Create => {
            if let Ok(request) = frame.request::<CreateRequest>() {
                let _ = request.name();
            }
            let _ = frame.response::<CreateResponse>();
        }
        Opcode::Getlk => {
            let _ = frame.request::<GetlkRequest>();
            let _ = frame.response::<GetlkResponse>();
        }
        Opcode::Setlk => {
            let _ = frame.request::<SetlkRequest>();
            let _ = frame.response::<SetlkResponse>();
        }
        Opcode::Subscribe => {
            let _ = frame.request::<SubscribeRequest>();
            let _ = frame.response::<SubscribeResponse>();
        }
        Opcode::Unsubscribe => {
            let _ = frame.request::<UnsubscribeRequest>();
            let _ = frame.response::<UnsubscribeResponse>();
        }
        Opcode::Outcome => {
            let _ = frame.request::<OutcomeRequest>();
            let _ = frame.response::<OutcomeResponse>();
        }
        Opcode::Retire => {
            let _ = frame.request::<RetireRequest>();
            let _ = frame.response::<RetireResponse>();
        }
        Opcode::Recalled => {
            let _ = frame.request::<RecalledRequest>();
            let _ = frame.response::<RecalledResponse>();
        }
        Opcode::Renew => {
            let _ = frame.request::<RenewRequest>();
            let _ = frame.response::<RenewResponse>();
        }
        Opcode::Cancel => {
            let _ = frame.request::<CancelRequest>();
        }
        Opcode::Relinquish => {
            let _ = frame.request::<RelinquishRequest>();
            let _ = frame.response::<RelinquishResponse>();
        }
    }
}

fn exercise_pieces(mut rest: &[u8], stream: Stream) {
    let bound = stream.piece_bound(&LIMITS).map_or(u64::MAX, u64::from);
    while let Some((length, tail)) = rest.split_first_chunk::<PIECE_LEN_LEN>() {
        let len = piece::read_length(length);
        if len == 0 {
            if let Some((closing, _)) = tail.split_first_chunk::<8>() {
                let _ = ClosingBody::parse(closing);
            }
            return;
        }
        if piece::check(len, bound).is_err() {
            return;
        }
        let Some(bytes) = tail.get(..len as usize) else {
            return;
        };
        match stream {
            Stream::Data => {}
            Stream::DirEntries => {
                let _ = piece::entry::<DirEntryHeader>(bytes, LIMITS.name_max);
            }
            Stream::ShareEntries => {
                let _ = piece::entry::<ShareEntryHeader>(bytes, LIMITS.path_max - 1);
            }
        }
        rest = &tail[len as usize..];
    }
}

fn exercise_notification(frame: &Frame<'_>) {
    let Ok(opcode) = frame.notification_opcode() else {
        return;
    };
    match opcode {
        NotificationOpcode::ShareSnapshotBegin => {
            let _ = frame.notification::<ShareSnapshotBegin>();
        }
        NotificationOpcode::ShareSnapshotPart => {
            let _ = frame.notification::<ShareSnapshotPart>();
        }
        NotificationOpcode::ShareSnapshotEnd => {
            let _ = frame.notification::<ShareSnapshotEnd>();
        }
        NotificationOpcode::ShareAdded => {
            if let Ok(event) = frame.notification::<ShareAdded>() {
                let _ = event.path();
            }
        }
        NotificationOpcode::ShareRemoved => {
            if let Ok(event) = frame.notification::<ShareRemoved>() {
                let _ = event.path();
            }
        }
        NotificationOpcode::ShareChanged => {
            if let Ok(event) = frame.notification::<ShareChanged>() {
                let _ = event.path();
            }
        }
        NotificationOpcode::ShareEnded => {
            let _ = frame.notification::<ShareEnded>();
        }
        NotificationOpcode::Recall => {
            let _ = frame.notification::<Recall>();
        }
    }
}

#[test]
fn arbitrary_bytes_never_panic() {
    let mut rng = Rng(0x5EED_1234_ABCD_0001);
    for _ in 0..20_000 {
        let len = rng.below(160);
        let buf: Vec<u8> = (0..len).map(|_| rng.next_u8()).collect();
        exercise(&buf);
    }
}

#[test]
fn plausible_headers_never_panic() {
    let mut rng = Rng(0x5EED_1234_ABCD_0002);
    for _ in 0..20_000 {
        let body_len = rng.below(256);
        let opcode = match rng.below(4) {
            0 => (rng.below(32)) as u16,
            1 => 0x8000 + rng.below(12) as u16,
            2 => 0x8000 | (rng.next_u64() as u16 & 0x7FFF),
            _ => rng.next_u64() as u16,
        };
        let flags = (rng.next_u64() as u16) & 0b11;
        let request_id = if rng.below(4) == 0 { 0 } else { rng.next_u64() };

        let mut buf = FrameHeader::new(opcode, flags, request_id)
            .as_bytes()
            .to_vec();
        buf.extend((0..body_len).map(|_| rng.next_u8()));
        exercise(&buf);
    }
}

#[test]
fn mutations_and_truncations_of_valid_frames_never_panic() {
    let name = b"a-name";
    let body = LookupRequest {
        name_len: U32::new(name.len() as u32),
    };
    let mut scratch = [0u8; 128];
    let mut writer = FrameWriter::request(
        &mut scratch,
        &LIMITS,
        3,
        &RequestHead::new(1, 7, 7, 7),
        &body,
    )
    .unwrap();
    writer.payload(name).unwrap();
    let valid = writer.finish().unwrap().to_vec();

    for cut in 0..=valid.len() {
        exercise(&valid[..cut]);
    }

    let mut rng = Rng(0x5EED_1234_ABCD_0003);
    for _ in 0..20_000 {
        let mut mutated = valid.clone();
        for _ in 0..=rng.below(3) {
            let at = rng.below(mutated.len());
            mutated[at] = rng.next_u8();
        }
        exercise(&mutated);
    }
}

#[test]
fn a_response_flagged_frame_at_the_server_is_detectable() {
    // The server-side rule "a RESPONSE-flagged frame arriving at the server is
    // a framing error" needs no body parsing: the class is in the header.
    let bytes = {
        let mut out = FrameHeader::new(Opcode::Lookup.as_u16(), FLAG_RESPONSE, 1)
            .as_bytes()
            .to_vec();
        out.extend_from_slice(&(-2i32).to_le_bytes());
        out
    };
    let frame = Frame::parse(&bytes, &LIMITS).unwrap();
    assert!(matches!(
        frame.request::<LookupRequest>(),
        Err(FramingError::UnexpectedFrameKind { .. })
    ));
}
