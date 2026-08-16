//! Fuzz-style no-panic test.
//!
//! Frame parsing must be total: every byte sequence either parses or comes
//! back as a typed [`FramingError`], and nothing in between panics. The
//! generator is a deterministic xorshift so a failure is reproducible from the
//! seed alone.

use voidport_proto::error::FramingError;
use voidport_proto::frame::{
    FLAG_RESPONSE, Frame, FrameHeader, FrameKind, FrameWriter, MAX_HELLO_FRAME_LEN,
};
use voidport_proto::message::RequestHead;
use voidport_proto::opcode::{NotificationOpcode, Opcode};
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
use zerocopy::IntoBytes;
use zerocopy::byteorder::little_endian::U32;

/// Deterministic xorshift64* generator.
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

/// Parses `buf` every way the crate offers. Any panic fails the test; the
/// results themselves are irrelevant, only that they are results.
fn exercise(buf: &[u8], max_frame_len: u32) {
    let _ = Frame::peek_len(buf, max_frame_len);
    let _ = Frame::parse(buf, max_frame_len);
    let Ok((frame, _tail)) = Frame::parse_prefix(buf, max_frame_len) else {
        return;
    };
    let _ = frame.kind();
    let _ = frame.request_id();
    let _ = frame.body();
    let _ = frame.request_head();
    if frame.kind() == FrameKind::Notification {
        exercise_notification(&frame);
        return;
    }
    let Ok(opcode) = frame.opcode() else {
        // The unknown-opcode route: validate the envelope, answer ENOSYS.
        if frame.request_head().is_ok() {
            let mut buf = [0u8; 32];
            let _ = FrameWriter::error_response_raw(
                &mut buf,
                max_frame_len,
                frame.request_id(),
                frame.raw_opcode(),
                -38,
            );
        }
        return;
    };
    match opcode {
        Opcode::Hello => {
            if let Ok(request) = frame.request::<HelloRequest>() {
                let _ = (request.namespace(), request.subpath(), request.auth());
            }
            let _ = frame.response::<HelloReply>();
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
            if let Ok(Some(response)) = frame.response::<ReadResponse>().map(|r| r.success()) {
                let _ = response.data();
            }
        }
        Opcode::Write => {
            if let Ok(request) = frame.request::<WriteRequest>() {
                let _ = request.data();
            }
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
            if let Ok(Some(response)) = frame.response::<ReaddirplusResponse>().map(|r| r.success())
            {
                for entry in response.entries() {
                    let _ = entry;
                }
            }
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
    }
}

/// Every notification body, exercised on arbitrary bytes.
///
/// The notification range is a second parse surface with its own registry, so
/// it gets the same treatment the request range does: nothing here may panic on
/// bytes a hostile server could send.
fn exercise_notification(frame: &Frame<'_>) {
    let Ok(opcode) = frame.notification_opcode() else {
        // An unknown notification is ignored, which is what keeps the range
        // extensible; nothing is parsed out of it.
        return;
    };
    match opcode {
        NotificationOpcode::ShareSnapshotBegin => {
            let _ = frame.notification::<ShareSnapshotBegin>();
        }
        NotificationOpcode::ShareSnapshotPart => {
            if let Ok(part) = frame.notification::<ShareSnapshotPart>() {
                for entry in part.entries() {
                    let _ = entry;
                }
            }
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
    }
}

#[test]
fn arbitrary_bytes_never_panic() {
    let mut rng = Rng(0x5EED_1234_ABCD_0001);
    for _ in 0..20_000 {
        let len = rng.below(160);
        let buf: Vec<u8> = (0..len).map(|_| rng.next_u8()).collect();
        exercise(&buf, MAX_HELLO_FRAME_LEN);
        exercise(&buf, u32::MAX);
    }
}

#[test]
fn plausible_headers_never_panic() {
    let mut rng = Rng(0x5EED_1234_ABCD_0002);
    for _ in 0..20_000 {
        let body_len = rng.below(96);
        let declared = match rng.below(4) {
            0 => (16 + body_len) as u32,
            1 => rng.next_u64() as u32,
            2 => u32::MAX,
            _ => rng.below(64) as u32,
        };
        let opcode = match rng.below(4) {
            0 => (rng.below(32)) as u16,
            // The assigned notification opcodes, plus the unassigned ones
            // around them: an unknown notification must be ignored, not
            // stumbled over.
            1 => 0x8000 + rng.below(12) as u16,
            2 => 0x8000 | (rng.next_u64() as u16 & 0x7FFF),
            _ => rng.next_u64() as u16,
        };
        let flags = (rng.next_u64() as u16) & 0b11;
        let request_id = if rng.below(4) == 0 { 0 } else { rng.next_u64() };

        let mut buf = FrameHeader::new(declared, opcode, flags, request_id)
            .as_bytes()
            .to_vec();
        buf.extend((0..body_len).map(|_| rng.next_u8()));
        exercise(&buf, MAX_HELLO_FRAME_LEN);
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
        MAX_HELLO_FRAME_LEN,
        3,
        &RequestHead::new(1, 7, 7, 7),
        &body,
    )
    .unwrap();
    writer.payload(name).unwrap();
    let valid = writer.finish().unwrap().to_vec();

    for cut in 0..=valid.len() {
        exercise(&valid[..cut], MAX_HELLO_FRAME_LEN);
    }

    let mut rng = Rng(0x5EED_1234_ABCD_0003);
    for _ in 0..20_000 {
        let mut mutated = valid.clone();
        for _ in 0..=rng.below(3) {
            let at = rng.below(mutated.len());
            mutated[at] = rng.next_u8();
        }
        exercise(&mutated, MAX_HELLO_FRAME_LEN);
    }
}

#[test]
fn a_response_flagged_frame_at_the_server_is_detectable() {
    // The server-side rule "a RESPONSE-flagged frame arriving at the server is
    // a framing error" needs no body parsing: the class is in the header.
    let bytes = {
        let mut out = FrameHeader::new(20, Opcode::Lookup.as_u16(), FLAG_RESPONSE, 1)
            .as_bytes()
            .to_vec();
        out.extend_from_slice(&[0, 0, 0, 0]);
        out
    };
    let frame = Frame::parse(&bytes, MAX_HELLO_FRAME_LEN).unwrap();
    assert!(matches!(
        frame.request::<LookupRequest>(),
        Err(FramingError::UnexpectedFrameKind { .. })
    ));
}
