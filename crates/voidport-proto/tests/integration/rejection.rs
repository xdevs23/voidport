use voidport_proto::PROTOCOL_VERSION;
use voidport_proto::attr::EntryOut;
use voidport_proto::error::FramingError;
use voidport_proto::frame::{FLAG_RESPONSE, Frame, FrameHeader, FrameKind, FrameWriter, Parsed};
use voidport_proto::limits::{Limits, Part};
use voidport_proto::message::{MAX_ERRNO, RequestHead, ResponseHead};
use voidport_proto::opcode::{Opcode, values};
use voidport_proto::ops::dir::{
    DirEntryHeader, DirEntryIter, DirEntryWriter, EntryType, MkdirRequest, RenameRequest,
    SymlinkRequest,
};
use voidport_proto::ops::file::{OpenRequest, OpenResponse};
use voidport_proto::ops::handshake::{HelloReply, HelloRequest};
use voidport_proto::ops::node::{GetattrRequest, LookupRequest, LookupResponse, SetattrRequest};
use voidport_proto::ops::xattr::{
    GetxattrRequest, ListxattrResponse, SetxattrRequest, XattrNameHeader,
};
use voidport_proto::piece::{self, ClosingBody, Stream};
use zerocopy::IntoBytes;
use zerocopy::byteorder::little_endian::{U32, U64};

const LIMITS: Limits = Limits {
    name_max: linux_raw_sys::general::NAME_MAX,
    path_max: linux_raw_sys::general::PATH_MAX,
    xattr_name_max: linux_raw_sys::general::XATTR_NAME_MAX,
    xattr_size_max: linux_raw_sys::general::XATTR_SIZE_MAX,
    xattr_list_max: linux_raw_sys::general::XATTR_LIST_MAX,
};

fn frame(opcode: u16, flags: u16, request_id: u64, body: &[u8]) -> Vec<u8> {
    let mut out = FrameHeader::new(opcode, flags, request_id)
        .as_bytes()
        .to_vec();
    out.extend_from_slice(body);
    out
}

fn request_body(head: &RequestHead, message: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut out = head.as_bytes().to_vec();
    out.extend_from_slice(message);
    out.extend_from_slice(payload);
    out
}

fn response_body(status: i32, message: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut out = ResponseHead::new(status).as_bytes().to_vec();
    out.extend_from_slice(message);
    out.extend_from_slice(payload);
    out
}

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

fn parse(bytes: &[u8]) -> Result<Parsed<'_>, FramingError> {
    Frame::parse_prefix(bytes, &LIMITS)
}

#[test]
fn a_reader_is_asked_for_each_part_in_turn() {
    let full = lookup_frame(b"project");
    assert_eq!(full.len(), 12 + 24 + 4 + 7);
    for cut in 0..full.len() {
        let needed = match cut {
            0..12 => 12,
            12..40 => 40,
            _ => full.len(),
        };
        assert_eq!(
            parse(&full[..cut]),
            Ok(Parsed::Need(needed)),
            "a truncation to {cut} bytes asks for the next part"
        );
        assert_eq!(
            Frame::parse(&full[..cut], &LIMITS),
            Err(FramingError::Incomplete { needed })
        );
    }
    assert!(Frame::parse(&full, &LIMITS).is_ok());
}

#[test]
fn the_message_ends_where_its_own_fields_say() {
    let mut longer = lookup_frame(b"project");
    longer.extend_from_slice(b"next");
    let Ok(Parsed::Frame(message)) = parse(&longer) else {
        panic!("the message is all there");
    };
    assert_eq!(message.len(), longer.len() - 4);
    assert_eq!(
        Frame::parse(&longer, &LIMITS),
        Err(FramingError::TrailingBytes { extra: 4 })
    );

    // The status of a reply sets how much fixed body follows: nothing after
    // an error.
    let mut error = frame(
        values::LOOKUP,
        FLAG_RESPONSE,
        1,
        &response_body(-2, &[], &[]),
    );
    error.extend_from_slice(EntryOut::default().as_bytes());
    assert_eq!(
        Frame::parse(&error, &LIMITS),
        Err(FramingError::TrailingBytes { extra: 100 })
    );
}

/// A frame that has its length first, as a length-prefixed layout does,
/// puts the low half of that length in the opcode field of this layout. A
/// hello is longer than the highest opcode, so it ends the connection.
#[test]
fn a_frame_of_the_old_layout_ends_the_connection() {
    let namespace = b"project";
    let body = HelloRequest {
        protocol_version: U32::new(1),
        flags: U32::ZERO,
        namespace_len: U32::new(namespace.len() as u32),
        subpath_len: U32::ZERO,
        auth_len: U32::ZERO,
        token_len: U32::ZERO,
    };
    let mut old = Vec::new();
    let len = 16 + 24 + size_of::<HelloRequest>() + namespace.len();
    old.extend_from_slice(&(len as u32).to_le_bytes());
    old.extend_from_slice(&values::HELLO.to_le_bytes());
    old.extend_from_slice(&0u16.to_le_bytes());
    old.extend_from_slice(&1u64.to_le_bytes());
    old.extend_from_slice(RequestHead::default().as_bytes());
    old.extend_from_slice(body.as_bytes());
    old.extend_from_slice(namespace);
    assert!(
        len > usize::from(values::RELINQUISH),
        "longer than any opcode"
    );
    assert_eq!(
        parse(&old),
        Err(FramingError::UnknownOpcode { opcode: len as u16 })
    );
    assert_eq!(PROTOCOL_VERSION, 4);
}

#[test]
fn an_opcode_the_table_does_not_hold_ends_the_connection() {
    let head = RequestHead::new(3, 0, 0, 0);
    assert_eq!(
        parse(&frame(0x0100, 0, 9, head.as_bytes())),
        Err(FramingError::UnknownOpcode { opcode: 0x0100 })
    );
    assert_eq!(
        parse(&frame(0x0100, FLAG_RESPONSE, 9, &[0, 0, 0, 0])),
        Err(FramingError::UnknownOpcode { opcode: 0x0100 })
    );
    assert_eq!(
        parse(&frame(0x8000, 0, 0, &[])),
        Err(FramingError::UnknownOpcode { opcode: 0x8000 })
    );
    assert_eq!(
        parse(&frame(0x0000, 0, 1, &[])),
        Err(FramingError::ReservedOpcode)
    );
}

#[test]
fn a_reply_to_the_request_nothing_answers_ends_the_connection() {
    assert_eq!(
        parse(&frame(values::FORGET, FLAG_RESPONSE, 1, &[0, 0, 0, 0])),
        Err(FramingError::NoBody {
            opcode: values::FORGET,
            kind: FrameKind::Response,
        })
    );
    let mut buf = [0u8; 32];
    assert_eq!(
        FrameWriter::error_response(&mut buf, 1, Opcode::Forget, -2).err(),
        Some(FramingError::NoBody {
            opcode: values::FORGET,
            kind: FrameKind::Response,
        })
    );
}

#[test]
fn every_part_one_byte_over_its_bound_is_a_framing_error() {
    let head = RequestHead::new(1, 0, 0, 0);

    let name = LookupRequest {
        name_len: U32::new(LIMITS.name_max + 1),
    };
    let target = SymlinkRequest {
        name_len: U32::new(1),
        target_len: U32::new(LIMITS.path_max),
    };
    let attribute = GetxattrRequest {
        size: U32::ZERO,
        name_len: U32::new(LIMITS.xattr_name_max + 1),
    };
    let value = SetxattrRequest {
        flags: U32::ZERO,
        name_len: U32::new(1),
        value_len: U32::new(LIMITS.xattr_size_max + 1),
        reserved: U32::ZERO,
    };
    let list_bound = LIMITS.bound(Part::XattrList).expect("a bound");
    let list = ListxattrResponse {
        size: U32::new(LIMITS.xattr_list_max),
        list_len: U32::new(list_bound + 1),
    };
    let cases = [
        (
            frame(
                values::LOOKUP,
                0,
                1,
                &request_body(&head, name.as_bytes(), &[]),
            ),
            Part::Name,
            LIMITS.name_max,
        ),
        (
            frame(
                values::SYMLINK,
                0,
                1,
                &request_body(&head, target.as_bytes(), &[]),
            ),
            Part::Path,
            LIMITS.path_max - 1,
        ),
        (
            frame(
                values::GETXATTR,
                0,
                1,
                &request_body(&head, attribute.as_bytes(), &[]),
            ),
            Part::XattrName,
            LIMITS.xattr_name_max,
        ),
        (
            frame(
                values::SETXATTR,
                0,
                1,
                &request_body(&head, value.as_bytes(), &[]),
            ),
            Part::XattrValue,
            LIMITS.xattr_size_max,
        ),
        (
            frame(
                values::LISTXATTR,
                FLAG_RESPONSE,
                1,
                &response_body(0, list.as_bytes(), &[]),
            ),
            Part::XattrList,
            list_bound,
        ),
    ];
    for (bytes, part, bound) in cases {
        assert_eq!(
            parse(&bytes),
            Err(FramingError::RegionTooLong {
                part,
                declared: bound + 1,
                bound,
            }),
            "{part:?}"
        );
    }

    let at = LookupRequest {
        name_len: U32::new(LIMITS.name_max),
    };
    let bytes = frame(
        values::LOOKUP,
        0,
        1,
        &request_body(&head, at.as_bytes(), &[]),
    );
    assert_eq!(
        parse(&bytes),
        Ok(Parsed::Need(bytes.len() + LIMITS.name_max as usize))
    );

    let mut buf = [0u8; 64];
    assert!(matches!(
        FrameWriter::request(&mut buf, &LIMITS, 1, &head, &name),
        Err(FramingError::RegionTooLong {
            part: Part::Name,
            ..
        })
    ));
}

#[test]
fn handshake_parts_are_left_to_the_handshake_but_cannot_overflow() {
    let hello = HelloRequest {
        protocol_version: U32::new(PROTOCOL_VERSION),
        flags: U32::ZERO,
        namespace_len: U32::new(u32::MAX),
        subpath_len: U32::ZERO,
        auth_len: U32::new(1),
        token_len: U32::ZERO,
    };
    let bytes = frame(
        values::HELLO,
        0,
        1,
        &request_body(&RequestHead::default(), hello.as_bytes(), &[]),
    );
    assert_eq!(parse(&bytes), Err(FramingError::LengthOverflow));
}

#[test]
fn reserved_flag_bits_are_rejected() {
    assert_eq!(
        parse(&frame(values::LOOKUP, 0b10, 1, &[])),
        Err(FramingError::ReservedFlags { flags: 0b10 })
    );
    assert_eq!(
        parse(&frame(values::LOOKUP, 0xFFFF, 1, &[])),
        Err(FramingError::ReservedFlags { flags: 0xFFFF })
    );
}

#[test]
fn request_id_zero_is_reserved() {
    assert_eq!(
        parse(&frame(values::LOOKUP, 0, 0, &[])),
        Err(FramingError::ZeroRequestId)
    );
    assert_eq!(
        parse(&frame(values::LOOKUP, FLAG_RESPONSE, 0, &[])),
        Err(FramingError::ZeroRequestId)
    );
    let mut buf = [0u8; 64];
    assert_eq!(
        FrameWriter::request(
            &mut buf,
            &LIMITS,
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
    let begin = frame(0x8001, 0, 0, &[0u8; 8]);
    let parsed = Frame::parse(&begin, &LIMITS).unwrap();
    assert_eq!(parsed.kind(), FrameKind::Notification);
    assert_eq!(
        parsed.request::<LookupRequest>(),
        Err(FramingError::UnexpectedFrameKind {
            expected: FrameKind::Request,
            found: FrameKind::Notification,
        })
    );
    assert_eq!(
        parse(&frame(0x8001, 0, 5, &[])),
        Err(FramingError::NotificationRequestId { request_id: 5 })
    );
    assert_eq!(
        parse(&frame(0x8001, FLAG_RESPONSE, 0, &[])),
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
    assert_eq!(parse(&bytes), Err(FramingError::ReservedFieldNonZero));
}

#[test]
fn reserved_body_fields_are_rejected_by_the_parser() {
    fn reject(opcode: u16, body: &[u8]) {
        let bytes = frame(
            opcode,
            0,
            1,
            &request_body(&RequestHead::default(), body, &[]),
        );
        assert_eq!(
            parse(&bytes),
            Err(FramingError::ReservedFieldNonZero),
            "{opcode:#06x}"
        );
    }
    reject(
        values::OPEN,
        OpenRequest {
            flags: U32::ZERO,
            reserved: U32::new(1),
        }
        .as_bytes(),
    );
    reject(
        values::GETATTR,
        GetattrRequest {
            handle: U64::ZERO,
            flags: U32::ZERO,
            reserved: U32::new(1),
        }
        .as_bytes(),
    );
    reject(
        values::SETATTR,
        SetattrRequest {
            reserved2: U32::new(1),
            ..SetattrRequest::default()
        }
        .as_bytes(),
    );
    reject(
        values::MKDIR,
        MkdirRequest {
            reserved: U32::new(1),
            ..MkdirRequest::default()
        }
        .as_bytes(),
    );
    reject(
        values::SETXATTR,
        SetxattrRequest {
            reserved: U32::new(1),
            ..SetxattrRequest::default()
        }
        .as_bytes(),
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
    assert_eq!(parse(&bytes), Err(FramingError::ReservedFieldNonZero));
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
        Frame::parse(&bytes, &LIMITS)
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
        Frame::parse(&bytes, &LIMITS)
            .unwrap()
            .response::<HelloReply>()
            .is_ok()
    );
}

#[test]
fn two_regions_are_read_as_the_sum_they_declare() {
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
    assert_eq!(parse(&bytes), Ok(Parsed::Need(bytes.len() + 2)));
}

fn parse_error_status(status: i32) -> Result<i32, FramingError> {
    let bytes = frame(
        values::LOOKUP,
        FLAG_RESPONSE,
        1,
        &response_body(status, &[], &[]),
    );
    Frame::parse(&bytes, &LIMITS)?
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
    assert_eq!(
        parse_error_status(2),
        Err(FramingError::InvalidStatus { status: 2 })
    );

    let mut buf = [0u8; 32];
    assert!(FrameWriter::error_response(&mut buf, 1, Opcode::Lookup, -MAX_ERRNO).is_ok());
    assert_eq!(
        FrameWriter::error_response(&mut buf, 1, Opcode::Lookup, -MAX_ERRNO - 1).err(),
        Some(FramingError::InvalidStatus { status: -4096 })
    );
    assert_eq!(
        FrameWriter::error_response(&mut buf, 1, Opcode::Lookup, 0).err(),
        Some(FramingError::InvalidStatus { status: 0 })
    );
}

#[test]
fn frames_of_the_wrong_class_or_opcode_are_rejected() {
    let request = lookup_frame(b"x");
    let parsed = Frame::parse(&request, &LIMITS).unwrap();
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
    let parsed = Frame::parse(&response, &LIMITS).unwrap();
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

    let mut small = [0u8; 40];
    assert_eq!(
        FrameWriter::request(&mut small, &LIMITS, 1, &RequestHead::default(), &message).err(),
        Some(FramingError::BufferTooSmall {
            needed: 44,
            found: 40
        })
    );

    let mut buf = [0u8; 64];
    let writer =
        FrameWriter::request(&mut buf, &LIMITS, 1, &RequestHead::default(), &message).unwrap();
    assert_eq!(
        writer.finish().err(),
        Some(FramingError::IncompletePayload { missing: 4 })
    );

    let mut writer =
        FrameWriter::request(&mut buf, &LIMITS, 1, &RequestHead::default(), &message).unwrap();
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
    assert_eq!(writer.finish().unwrap().len(), 44);
}

#[test]
fn encoding_rejects_reserved_fields_and_handshake_flags() {
    let mut buf = [0u8; 128];
    let head = RequestHead {
        reserved: U32::new(1),
        ..RequestHead::default()
    };
    assert_eq!(
        FrameWriter::request(&mut buf, &LIMITS, 1, &head, &LookupRequest::default()).err(),
        Some(FramingError::ReservedFieldNonZero)
    );

    let request = OpenRequest {
        reserved: U32::new(1),
        ..OpenRequest::default()
    };
    assert_eq!(
        FrameWriter::request(&mut buf, &LIMITS, 1, &RequestHead::default(), &request).err(),
        Some(FramingError::ReservedFieldNonZero)
    );

    let response = OpenResponse {
        reserved: U32::new(1),
        ..OpenResponse::default()
    };
    assert_eq!(
        FrameWriter::response(&mut buf, &LIMITS, 1, &response).err(),
        Some(FramingError::ReservedFieldNonZero)
    );

    let join = HelloRequest::join(0);
    assert!(FrameWriter::request(&mut buf, &LIMITS, 1, &RequestHead::default(), &join).is_ok());
    let hello = HelloRequest {
        flags: U32::new(2),
        ..HelloRequest::default()
    };
    assert_eq!(
        FrameWriter::request(&mut buf, &LIMITS, 1, &RequestHead::default(), &hello).err(),
        Some(FramingError::NegotiationFlagsNonZero { flags: 2 })
    );

    let reply = HelloReply {
        flags: U32::new(1),
        ..HelloReply::default()
    };
    assert_eq!(
        FrameWriter::response(&mut buf, &LIMITS, 1, &reply).err(),
        Some(FramingError::NegotiationFlagsNonZero { flags: 1 })
    );
}

#[test]
fn a_closing_piece_with_a_reserved_flag_bit_is_a_framing_error() {
    assert_eq!(
        ClosingBody::parse(&[0, 0, 0, 0, 2, 0, 0, 0]),
        Err(FramingError::ReservedPieceFlags { flags: 2 })
    );
    assert_eq!(
        ClosingBody::parse(&[0, 0, 0, 0, 0, 0, 0, 0x80]),
        Err(FramingError::ReservedPieceFlags { flags: 0x8000_0000 })
    );
    assert!(ClosingBody::parse(&[0, 0, 0, 0, 1, 0, 0, 0]).is_ok());
}

#[test]
fn a_piece_longer_than_its_receiver_can_take_is_a_framing_error() {
    assert_eq!(piece::check(4096, 4096), Ok(()));
    assert_eq!(
        piece::check(4097, 4096),
        Err(FramingError::PieceTooLong {
            declared: 4097,
            remaining: 4096,
        })
    );

    let bound = Stream::DirEntries.piece_bound(&LIMITS).expect("a bound");
    assert_eq!(
        bound as usize,
        size_of::<DirEntryHeader>() + LIMITS.name_max as usize
    );
    assert!(piece::check(bound + 1, u64::from(bound)).is_err());
    let mut long = DirEntryHeader::new(
        EntryOut::default(),
        1,
        EntryType::Regular,
        LIMITS.name_max + 1,
    )
    .as_bytes()
    .to_vec();
    long.extend(std::iter::repeat_n(b'a', LIMITS.name_max as usize + 1));
    assert!(matches!(
        piece::entry::<DirEntryHeader>(&long, LIMITS.name_max),
        Err(FramingError::PieceTooLong { .. })
    ));
    let mut two = DirEntryHeader::new(EntryOut::default(), 1, EntryType::Regular, 1)
        .as_bytes()
        .to_vec();
    two.extend_from_slice(b"ab");
    assert!(matches!(
        piece::entry::<DirEntryHeader>(&two, LIMITS.name_max),
        Err(FramingError::PayloadLengthMismatch { .. })
    ));
    let bound = Stream::ShareEntries.piece_bound(&LIMITS).expect("a bound");
    assert_eq!(bound, 8 + LIMITS.path_max - 1);
    assert_eq!(Stream::Data.piece_bound(&LIMITS), None);
}

#[test]
fn entry_streams_reject_malformed_entries() {
    let mut buf = [0u8; 256];
    let mut writer = DirEntryWriter::new(&mut buf);
    writer
        .push(
            &DirEntryHeader::new(EntryOut::default(), 1, EntryType::Regular, 5),
            b"three",
        )
        .unwrap();
    assert_eq!(
        writer
            .push(
                &DirEntryHeader::new(EntryOut::default(), 2, EntryType::Regular, 9),
                b"three"
            )
            .err(),
        Some(FramingError::TailLengthMismatch {
            declared: 9,
            found: 5
        })
    );
    let stream_len = writer.written();
    let stream = writer.finish().to_vec();

    let items: Vec<_> = DirEntryIter::new(&stream[..stream_len - 3]).collect();
    assert_eq!(items.len(), 1);
    assert!(matches!(
        items[0],
        Err(FramingError::PayloadLengthMismatch { .. })
    ));

    let mut tiny = [0u8; 32];
    let mut writer = DirEntryWriter::new(&mut tiny);
    assert!(matches!(
        writer.push(
            &DirEntryHeader::new(EntryOut::default(), 1, EntryType::Regular, 1),
            b"a"
        ),
        Err(FramingError::BufferTooSmall { .. })
    ));

    assert_eq!(size_of::<XattrNameHeader>(), 4);
}
