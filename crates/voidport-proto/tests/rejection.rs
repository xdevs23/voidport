//! Rejection tests: everything malformed must come back as a typed framing
//! error, and everything merely unknown must stay a semantic matter.

use voidport_proto::attr::EntryOut;
use voidport_proto::error::FramingError;
use voidport_proto::frame::{
    FLAG_RESPONSE, Frame, FrameHeader, FrameKind, FrameWriter, MAX_HELLO_FRAME_LEN,
};
use voidport_proto::message::{MAX_ERRNO, RequestHead, ResponseHead};
use voidport_proto::opcode::{Opcode, UnknownOpcode, values};
use voidport_proto::ops::dir::{
    DirEntryHeader, DirEntryIter, DirEntryWriter, MkdirRequest, RenameRequest,
};
use voidport_proto::ops::file::{OpenRequest, OpenResponse};
use voidport_proto::ops::handshake::{HelloReply, HelloRequest};
use voidport_proto::ops::node::{GetattrRequest, LookupRequest, LookupResponse, SetattrRequest};
use voidport_proto::ops::xattr::SetxattrRequest;
use zerocopy::IntoBytes;
use zerocopy::byteorder::little_endian::{U32, U64};

const MAX: u32 = MAX_HELLO_FRAME_LEN;

/// `ENOSYS`, negated as a response status.
const ENOSYS: i32 = -38;

/// Builds a frame with a `len` field that matches the body.
fn frame(opcode: u16, flags: u16, request_id: u64, body: &[u8]) -> Vec<u8> {
    let len = (16 + body.len()) as u32;
    let mut out = FrameHeader::new(len, opcode, flags, request_id)
        .as_bytes()
        .to_vec();
    out.extend_from_slice(body);
    out
}

/// Builds a request body: head, op struct, payload.
fn request_body(head: &RequestHead, message: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut out = head.as_bytes().to_vec();
    out.extend_from_slice(message);
    out.extend_from_slice(payload);
    out
}

/// Builds a response body: status, op struct, payload.
fn response_body(status: i32, message: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut out = ResponseHead::new(status).as_bytes().to_vec();
    out.extend_from_slice(message);
    out.extend_from_slice(payload);
    out
}

/// A well-formed lookup request frame for `name`.
fn lookup_frame(name: &[u8]) -> Vec<u8> {
    let message = LookupRequest {
        name_len: U32::new(name.len() as u32),
    };
    frame(
        values::LOOKUP,
        0,
        1,
        &request_body(&RequestHead::new(1, 0, 0, 0), message.as_bytes(), name),
    )
}

#[test]
fn truncated_frames_are_incomplete() {
    let full = lookup_frame(b"project");
    for cut in 0..full.len() {
        let needed = if cut < 16 { 16 } else { full.len() };
        assert_eq!(
            Frame::parse(&full[..cut], MAX),
            Err(FramingError::Incomplete { needed }),
            "truncation to {cut} bytes must report an incomplete frame"
        );
    }
    assert!(Frame::parse(&full, MAX).is_ok());
}

#[test]
fn declared_length_must_agree_with_the_buffer() {
    let mut short_len = lookup_frame(b"project");
    short_len[0] = 40;
    assert_eq!(
        Frame::parse(&short_len, MAX),
        Err(FramingError::TrailingBytes { extra: 11 })
    );

    let mut long_len = lookup_frame(b"project");
    long_len[0] = 100;
    assert_eq!(
        Frame::parse(&long_len, MAX),
        Err(FramingError::Incomplete { needed: 100 })
    );

    let mut tiny_len = lookup_frame(b"project");
    tiny_len[0] = 15;
    assert_eq!(
        Frame::parse(&tiny_len, MAX),
        Err(FramingError::FrameTooShort { len: 15 })
    );
}

#[test]
fn frames_beyond_the_size_bound_are_rejected() {
    let mut buf = vec![0u8; 6000];
    buf[..16].copy_from_slice(FrameHeader::new(5000, values::LOOKUP, 0, 1).as_bytes());
    assert_eq!(
        Frame::parse_prefix(&buf, MAX),
        Err(FramingError::FrameTooLong {
            len: 5000,
            max: MAX
        })
    );
    assert!(Frame::parse_prefix(&buf, 6000).is_ok());
}

#[test]
fn unknown_opcodes_are_semantic_not_fatal() {
    // Parse, classify, answer: a well-framed request with an unknown opcode is
    // answered with ENOSYS echoing that opcode, and the stream survives.
    let head = RequestHead::new(3, 0, 0, 0);
    let bytes = frame(0x0100, 0, 9, head.as_bytes());
    let parsed = Frame::parse(&bytes, MAX).expect("an unknown opcode is still a well-formed frame");
    assert_eq!(parsed.kind(), FrameKind::Request);
    assert_eq!(parsed.opcode(), Err(UnknownOpcode(0x0100)));
    assert_eq!(parsed.request_head(), Ok(&head));

    let mut buf = [0u8; 32];
    let reply = FrameWriter::error_response_raw(
        &mut buf,
        MAX,
        parsed.request_id(),
        parsed.raw_opcode(),
        ENOSYS,
    )
    .expect("an unknown opcode must be answerable");
    let reply = Frame::parse(reply, MAX).unwrap();
    assert_eq!(reply.kind(), FrameKind::Response);
    assert_eq!(reply.raw_opcode(), 0x0100);
    assert_eq!(reply.request_id(), 9);
    assert_eq!(reply.body(), ResponseHead::new(ENOSYS).as_bytes());

    // Opcode 0 belongs to no range at all, so it is a framing error.
    assert_eq!(
        Frame::parse(&frame(0x0000, 0, 1, &[]), MAX),
        Err(FramingError::ReservedOpcode)
    );

    // Neither the reserved opcode nor a notification can be echoed by a
    // response: they never name a request.
    assert_eq!(
        FrameWriter::error_response_raw(&mut buf, MAX, 1, 0x0000, ENOSYS).err(),
        Some(FramingError::ReservedOpcode)
    );
    assert_eq!(
        FrameWriter::error_response_raw(&mut buf, MAX, 1, 0x8001, ENOSYS).err(),
        Some(FramingError::UnexpectedFrameKind {
            expected: FrameKind::Request,
            found: FrameKind::Notification,
        })
    );
}

#[test]
fn unknown_requests_must_still_carry_the_common_head() {
    // No 24-byte head at all: a framing error that closes the connection, not
    // a semantic ENOSYS case.
    let headless = frame(0x0100, 0, 1, &[]);
    assert_eq!(
        Frame::parse(&headless, MAX).unwrap().request_head(),
        Err(FramingError::BodyTooShort {
            needed: 24,
            found: 0
        })
    );

    // A nonzero common reserved field is a framing error whatever the opcode.
    let head = RequestHead {
        node_id: U64::new(1),
        uid: U32::ZERO,
        gid: U32::ZERO,
        pid: U32::ZERO,
        reserved: U32::new(1),
    };
    let nonzero = frame(0x0100, 0, 1, head.as_bytes());
    assert_eq!(
        Frame::parse(&nonzero, MAX).unwrap().request_head(),
        Err(FramingError::ReservedFieldNonZero)
    );

    // Only requests carry the head.
    let response = frame(0x0100, FLAG_RESPONSE, 1, &[0u8; 24]);
    assert_eq!(
        Frame::parse(&response, MAX).unwrap().request_head(),
        Err(FramingError::UnexpectedFrameKind {
            expected: FrameKind::Request,
            found: FrameKind::Response,
        })
    );
}

#[test]
fn peeked_lengths_are_bounded_before_a_read_is_sized() {
    let full = lookup_frame(b"project");
    assert_eq!(Frame::peek_len(&full[..8], MAX), Ok(None));
    assert_eq!(Frame::peek_len(&full, MAX), Ok(Some(full.len() as u32)));

    // A peer declaring u32::MAX must not make a reader size a buffer from it.
    let mut huge = full.clone();
    huge[..4].copy_from_slice(&[0xFF; 4]);
    assert_eq!(
        Frame::peek_len(&huge, MAX),
        Err(FramingError::FrameTooLong {
            len: u32::MAX,
            max: MAX
        })
    );
}

#[test]
fn reserved_flag_bits_are_rejected() {
    assert_eq!(
        Frame::parse(&frame(values::LOOKUP, 0b10, 1, &[]), MAX),
        Err(FramingError::ReservedFlags { flags: 0b10 })
    );
    assert_eq!(
        Frame::parse(&frame(values::LOOKUP, 0xFFFF, 1, &[]), MAX),
        Err(FramingError::ReservedFlags { flags: 0xFFFF })
    );
}

#[test]
fn request_id_zero_is_reserved() {
    assert_eq!(
        Frame::parse(&frame(values::LOOKUP, 0, 0, &[]), MAX),
        Err(FramingError::ZeroRequestId)
    );
    assert_eq!(
        Frame::parse(&frame(values::LOOKUP, FLAG_RESPONSE, 0, &[]), MAX),
        Err(FramingError::ZeroRequestId)
    );
    let mut buf = [0u8; 64];
    assert_eq!(
        FrameWriter::request(
            &mut buf,
            MAX,
            0,
            &RequestHead::default(),
            &LookupRequest {
                name_len: U32::ZERO
            }
        )
        .err(),
        Some(FramingError::ZeroRequestId)
    );
}

#[test]
fn notifications_are_distinguishable_and_validated() {
    let bytes = frame(0x8001, 0, 0, &[]);
    let parsed = Frame::parse(&bytes, MAX).unwrap();
    assert_eq!(parsed.kind(), FrameKind::Notification);
    assert_eq!(
        parsed.request::<LookupRequest>(),
        Err(FramingError::UnexpectedFrameKind {
            expected: FrameKind::Request,
            found: FrameKind::Notification,
        })
    );

    assert_eq!(
        Frame::parse(&frame(0x8001, 0, 5, &[]), MAX),
        Err(FramingError::NotificationRequestId { request_id: 5 })
    );
    assert_eq!(
        Frame::parse(&frame(0x8001, FLAG_RESPONSE, 0, &[]), MAX),
        Err(FramingError::NotificationResponseFlag)
    );
}

#[test]
fn the_reserved_request_head_field_must_be_zero() {
    let head = RequestHead {
        node_id: U64::new(1),
        uid: U32::ZERO,
        gid: U32::ZERO,
        pid: U32::ZERO,
        reserved: U32::new(1),
    };
    let message = LookupRequest {
        name_len: U32::ZERO,
    };
    let bytes = frame(
        values::LOOKUP,
        0,
        1,
        &request_body(&head, message.as_bytes(), &[]),
    );
    assert_eq!(
        Frame::parse(&bytes, MAX)
            .unwrap()
            .request::<LookupRequest>(),
        Err(FramingError::ReservedFieldNonZero)
    );
}

#[test]
fn reserved_body_fields_are_rejected_per_struct_class() {
    macro_rules! reject_request {
        ($opcode:expr, $body:expr, $ty:ty) => {{
            let body = $body;
            let bytes = frame(
                $opcode,
                0,
                1,
                &request_body(&RequestHead::default(), body.as_bytes(), &[]),
            );
            assert_eq!(
                Frame::parse(&bytes, MAX).unwrap().request::<$ty>(),
                Err(FramingError::ReservedFieldNonZero)
            );
        }};
    }

    reject_request!(
        values::OPEN,
        OpenRequest {
            flags: U32::ZERO,
            reserved: U32::new(1),
        },
        OpenRequest
    );
    reject_request!(
        values::GETATTR,
        GetattrRequest {
            handle: U64::ZERO,
            flags: U32::ZERO,
            reserved: U32::new(1),
        },
        GetattrRequest
    );
    reject_request!(
        values::SETATTR,
        SetattrRequest {
            reserved2: U32::new(1),
            ..SetattrRequest::default()
        },
        SetattrRequest
    );
    reject_request!(
        values::MKDIR,
        MkdirRequest {
            reserved: U32::new(1),
            ..MkdirRequest::default()
        },
        MkdirRequest
    );
    reject_request!(
        values::SETXATTR,
        SetxattrRequest {
            reserved: U32::new(1),
            ..SetxattrRequest::default()
        },
        SetxattrRequest
    );

    let body = HelloReply {
        reserved: U32::new(1),
        ..HelloReply::default()
    };
    let bytes = frame(
        values::HELLO,
        FLAG_RESPONSE,
        1,
        &response_body(0, body.as_bytes(), &[]),
    );
    assert_eq!(
        Frame::parse(&bytes, MAX).unwrap().response::<HelloReply>(),
        Err(FramingError::ReservedFieldNonZero)
    );
}

#[test]
fn handshake_negotiation_flags_are_ignored_on_parse() {
    let request = HelloRequest {
        flags: U32::new(0x8000_0000),
        ..HelloRequest::default()
    };
    let bytes = frame(
        values::HELLO,
        0,
        1,
        &request_body(&RequestHead::default(), request.as_bytes(), &[]),
    );
    assert!(
        Frame::parse(&bytes, MAX)
            .unwrap()
            .request::<HelloRequest>()
            .is_ok()
    );

    let response = HelloReply {
        flags: U32::new(0x8000_0000),
        ..HelloReply::default()
    };
    let bytes = frame(
        values::HELLO,
        FLAG_RESPONSE,
        1,
        &response_body(0, response.as_bytes(), &[]),
    );
    assert!(
        Frame::parse(&bytes, MAX)
            .unwrap()
            .response::<HelloReply>()
            .is_ok()
    );
}

#[test]
fn bodies_shorter_than_their_fixed_structs_are_rejected() {
    let bytes = frame(values::LOOKUP, 0, 1, &[0u8; 20]);
    assert_eq!(
        Frame::parse(&bytes, MAX)
            .unwrap()
            .request::<LookupRequest>(),
        Err(FramingError::BodyTooShort {
            needed: 24,
            found: 20
        })
    );

    let bytes = frame(values::LOOKUP, 0, 1, &[0u8; 26]);
    assert_eq!(
        Frame::parse(&bytes, MAX)
            .unwrap()
            .request::<LookupRequest>(),
        Err(FramingError::BodyTooShort {
            needed: 28,
            found: 26
        })
    );

    let bytes = frame(values::LOOKUP, FLAG_RESPONSE, 1, &[0u8; 2]);
    assert_eq!(
        Frame::parse(&bytes, MAX)
            .unwrap()
            .response::<LookupResponse>(),
        Err(FramingError::BodyTooShort {
            needed: 4,
            found: 2
        })
    );
}

#[test]
fn declared_lengths_must_account_for_the_payload_exactly() {
    // Declared longer than the payload.
    let message = LookupRequest {
        name_len: U32::new(10),
    };
    let bytes = frame(
        values::LOOKUP,
        0,
        1,
        &request_body(&RequestHead::default(), message.as_bytes(), b"abc"),
    );
    assert_eq!(
        Frame::parse(&bytes, MAX)
            .unwrap()
            .request::<LookupRequest>(),
        Err(FramingError::PayloadLengthMismatch {
            declared: 10,
            found: 3
        })
    );

    // Declared shorter: the remaining bytes are unaccounted for.
    let message = LookupRequest {
        name_len: U32::new(3),
    };
    let bytes = frame(
        values::LOOKUP,
        0,
        1,
        &request_body(&RequestHead::default(), message.as_bytes(), b"abcde"),
    );
    assert_eq!(
        Frame::parse(&bytes, MAX)
            .unwrap()
            .request::<LookupRequest>(),
        Err(FramingError::PayloadLengthMismatch {
            declared: 3,
            found: 5
        })
    );

    // Two regions that between them claim more than the payload holds — the
    // overlapping-regions case.
    let message = RenameRequest {
        new_parent_node_id: U64::ZERO,
        flags: U32::ZERO,
        old_name_len: U32::new(4),
        new_name_len: U32::new(4),
        reserved: U32::ZERO,
    };
    let bytes = frame(
        values::RENAME,
        0,
        1,
        &request_body(&RequestHead::default(), message.as_bytes(), b"abcdef"),
    );
    assert_eq!(
        Frame::parse(&bytes, MAX)
            .unwrap()
            .request::<RenameRequest>(),
        Err(FramingError::PayloadLengthMismatch {
            declared: 8,
            found: 6
        })
    );

    // A sum that overflows the 32-bit length space.
    let message = RenameRequest {
        new_parent_node_id: U64::ZERO,
        flags: U32::ZERO,
        old_name_len: U32::new(u32::MAX),
        new_name_len: U32::new(1),
        reserved: U32::ZERO,
    };
    let bytes = frame(
        values::RENAME,
        0,
        1,
        &request_body(&RequestHead::default(), message.as_bytes(), &[]),
    );
    assert_eq!(
        Frame::parse(&bytes, MAX)
            .unwrap()
            .request::<RenameRequest>(),
        Err(FramingError::LengthOverflow)
    );
}

#[test]
fn error_responses_carry_nothing_after_their_status() {
    let bytes = frame(
        values::LOOKUP,
        FLAG_RESPONSE,
        1,
        &response_body(-2, EntryOut::default().as_bytes(), &[]),
    );
    assert_eq!(
        Frame::parse(&bytes, MAX)
            .unwrap()
            .response::<LookupResponse>(),
        Err(FramingError::ErrorResponseBody { extra: 100 })
    );

    // A positive status is neither success nor a negated errno.
    let bytes = frame(
        values::LOOKUP,
        FLAG_RESPONSE,
        1,
        &response_body(2, &[], &[]),
    );
    assert_eq!(
        Frame::parse(&bytes, MAX)
            .unwrap()
            .response::<LookupResponse>(),
        Err(FramingError::InvalidStatus { status: 2 })
    );

    let mut buf = [0u8; 32];
    assert_eq!(
        FrameWriter::error_response(&mut buf, MAX, 1, Opcode::Lookup, 0).err(),
        Some(FramingError::InvalidStatus { status: 0 })
    );
}

/// Parses a response frame carrying `status` and no body, reporting the errno
/// it yields.
fn parse_error_status(status: i32) -> Result<i32, FramingError> {
    let bytes = frame(
        values::LOOKUP,
        FLAG_RESPONSE,
        1,
        &response_body(status, &[], &[]),
    );
    Frame::parse(&bytes, MAX)
        .unwrap()
        .response::<LookupResponse>()
        .map(|outcome| outcome.error().expect("a nonzero status is an error"))
}

#[test]
fn statuses_outside_the_errno_range_are_rejected() {
    // Linux caps errnos at MAX_ERRNO, so -4095 is the last valid status and
    // -4096 is not an errno at all.
    assert_eq!(parse_error_status(-1), Ok(-1));
    assert_eq!(parse_error_status(-MAX_ERRNO), Ok(-4095));
    assert_eq!(
        parse_error_status(-MAX_ERRNO - 1),
        Err(FramingError::InvalidStatus { status: -4096 })
    );
    assert_eq!(
        parse_error_status(i32::MIN),
        Err(FramingError::InvalidStatus { status: i32::MIN })
    );

    // The encoder holds the same bound, so neither value can be emitted.
    let mut buf = [0u8; 32];
    assert!(FrameWriter::error_response(&mut buf, MAX, 1, Opcode::Lookup, -MAX_ERRNO).is_ok());
    assert_eq!(
        FrameWriter::error_response(&mut buf, MAX, 1, Opcode::Lookup, -MAX_ERRNO - 1).err(),
        Some(FramingError::InvalidStatus { status: -4096 })
    );
    assert_eq!(
        FrameWriter::error_response_raw(&mut buf, MAX, 1, values::LOOKUP, i32::MIN).err(),
        Some(FramingError::InvalidStatus { status: i32::MIN })
    );
}

#[test]
fn frames_of_the_wrong_class_or_opcode_are_rejected() {
    let request = lookup_frame(b"x");
    let parsed = Frame::parse(&request, MAX).unwrap();
    assert_eq!(
        parsed.response::<LookupResponse>(),
        Err(FramingError::UnexpectedFrameKind {
            expected: FrameKind::Response,
            found: FrameKind::Request,
        })
    );
    assert_eq!(
        parsed.request::<GetattrRequest>(),
        Err(FramingError::OpcodeMismatch {
            expected: values::GETATTR,
            found: values::LOOKUP,
        })
    );

    let response = frame(
        values::LOOKUP,
        FLAG_RESPONSE,
        1,
        &response_body(0, EntryOut::default().as_bytes(), &[]),
    );
    let parsed = Frame::parse(&response, MAX).unwrap();
    assert_eq!(
        parsed.request::<LookupRequest>(),
        Err(FramingError::UnexpectedFrameKind {
            expected: FrameKind::Request,
            found: FrameKind::Response,
        })
    );
}

#[test]
fn encoding_enforces_strict_framing_too() {
    let message = LookupRequest {
        name_len: U32::new(4),
    };

    // The buffer is the frame bound: an oversized frame never goes out.
    let mut small = [0u8; 40];
    assert_eq!(
        FrameWriter::request(&mut small, MAX, 1, &RequestHead::default(), &message).err(),
        Some(FramingError::BufferTooSmall {
            needed: 48,
            found: 40
        })
    );

    let mut buf = [0u8; 64];
    let writer = FrameWriter::request(&mut buf, MAX, 1, &RequestHead::default(), &message).unwrap();
    assert_eq!(
        writer.finish().err(),
        Some(FramingError::IncompletePayload { missing: 4 })
    );

    let mut writer =
        FrameWriter::request(&mut buf, MAX, 1, &RequestHead::default(), &message).unwrap();
    assert_eq!(
        writer.payload(b"toolong").err(),
        Some(FramingError::PayloadLengthMismatch {
            declared: 4,
            found: 7
        })
    );
    writer.payload(b"name").unwrap();
    assert_eq!(
        writer.payload(b"x").err(),
        Some(FramingError::PayloadLengthMismatch {
            declared: 0,
            found: 1
        })
    );
    assert_eq!(writer.finish().unwrap().len(), 48);
}

#[test]
fn encoding_rejects_reserved_fields_and_handshake_flags() {
    let mut buf = [0u8; 128];
    let head = RequestHead {
        reserved: U32::new(1),
        ..RequestHead::default()
    };
    assert_eq!(
        FrameWriter::request(&mut buf, MAX, 1, &head, &LookupRequest::default()).err(),
        Some(FramingError::ReservedFieldNonZero)
    );

    let request = OpenRequest {
        reserved: U32::new(1),
        ..OpenRequest::default()
    };
    assert_eq!(
        FrameWriter::request(&mut buf, MAX, 1, &RequestHead::default(), &request).err(),
        Some(FramingError::ReservedFieldNonZero)
    );

    let response = OpenResponse {
        reserved: U32::new(1),
        ..OpenResponse::default()
    };
    assert_eq!(
        FrameWriter::response(&mut buf, MAX, 1, &response).err(),
        Some(FramingError::ReservedFieldNonZero)
    );

    let hello = HelloRequest {
        flags: U32::new(1),
        ..HelloRequest::default()
    };
    assert_eq!(
        FrameWriter::request(&mut buf, MAX, 1, &RequestHead::default(), &hello).err(),
        Some(FramingError::NegotiationFlagsNonZero { flags: 1 })
    );

    let reply = HelloReply {
        flags: U32::new(1),
        ..HelloReply::default()
    };
    assert_eq!(
        FrameWriter::response(&mut buf, MAX, 1, &reply).err(),
        Some(FramingError::NegotiationFlagsNonZero { flags: 1 })
    );
}

#[test]
fn encoding_uses_the_smaller_of_buffer_and_frame_bound() {
    let body = LookupRequest {
        name_len: U32::new(4),
    };
    let mut large = [0u8; 64];
    assert_eq!(
        FrameWriter::request(&mut large, 47, 1, &RequestHead::default(), &body).err(),
        Some(FramingError::FrameTooLong { len: 48, max: 47 })
    );

    let mut small = [0u8; 47];
    assert_eq!(
        FrameWriter::request(&mut small, MAX, 1, &RequestHead::default(), &body).err(),
        Some(FramingError::BufferTooSmall {
            needed: 48,
            found: 47
        })
    );

    let mut error = [0u8; 32];
    assert_eq!(
        FrameWriter::error_response(&mut error, 19, 1, Opcode::Lookup, -2).err(),
        Some(FramingError::FrameTooLong { len: 20, max: 19 })
    );
}

#[test]
fn entry_streams_reject_malformed_entries() {
    let mut buf = [0u8; 256];
    let mut writer = DirEntryWriter::new(&mut buf);
    writer
        .push(&DirEntryHeader::new(EntryOut::default(), 1, 8, 5), b"three")
        .unwrap();
    assert_eq!(
        writer
            .push(&DirEntryHeader::new(EntryOut::default(), 2, 8, 9), b"three")
            .err(),
        Some(FramingError::TailLengthMismatch {
            declared: 9,
            found: 5
        })
    );
    let stream_len = writer.written();
    let stream = writer.finish().to_vec();

    // A stream whose last entry is cut short of its declared name.
    let items: Vec<_> = DirEntryIter::new(&stream[..stream_len - 3]).collect();
    assert_eq!(items.len(), 1);
    assert!(matches!(
        items[0],
        Err(FramingError::PayloadLengthMismatch { .. })
    ));

    // A name length that runs past the end of the stream.
    let mut lying = DirEntryHeader::new(EntryOut::default(), 1, 8, 9999)
        .as_bytes()
        .to_vec();
    lying.extend_from_slice(b"three");
    let items: Vec<_> = DirEntryIter::new(&lying).collect();
    assert_eq!(items.len(), 1);
    assert!(matches!(
        items[0],
        Err(FramingError::PayloadLengthMismatch { declared: 9999, .. })
    ));

    // A buffer too small for the entry stops enumeration cleanly.
    let mut tiny = [0u8; 32];
    let mut writer = DirEntryWriter::new(&mut tiny);
    assert!(matches!(
        writer.push(&DirEntryHeader::new(EntryOut::default(), 1, 8, 1), b"a"),
        Err(FramingError::BufferTooSmall { .. })
    ));
}
