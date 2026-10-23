//! A completed handshake is the probe of the reconnect machine, so an adapter
//! may install the connection the moment this module accepts its reply.

use core::fmt;

use voidport_proto::PROTOCOL_VERSION;
use voidport_proto::error::FramingError;
use voidport_proto::frame::{Frame, FrameWriter};
use voidport_proto::limits::Limits;
use voidport_proto::message::{RequestHead, ResponseOutcome};
use voidport_proto::ops::handshake::{HelloReply, HelloRequest};

/// The first id of every connection. The data-request counter starts after
/// it, so request ids are allocated monotonically and never reused across the
/// whole connection, not only after the handshake. Request ids are
/// per-connection by the wire contract, so a replacement connection starts them
/// over.
pub const HELLO_REQUEST_ID: u64 = 1;

/// The root of a FUSE mount is `FUSE_ROOT_ID` in the kernel, which is 1. It is
/// also the one node id that the generation-disjoint allocator of the server
/// never hands out, which lets a stale mount heal by walking from the root.
pub const ROOT_NODE_ID: u64 = 1;

/// No flag bit is assigned, so every bit of the word is reserved.
pub const ACCEPTED_REPLY_FLAGS: u32 = 0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Negotiated {
    pub root_node_id: u64,
    pub connection_id: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Accepted<'a> {
    pub negotiated: Negotiated,
    pub token: &'a [u8],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum HandshakeError {
    ProtocolVersion {
        announced: u32,
        expected: u32,
    },
    /// The flag word of the reply. A nonzero reserved field arrives as
    /// [`HandshakeError::Malformed`] instead.
    ReservedFlags {
        flags: u32,
    },
    RootNodeId {
        announced: u64,
        expected: u64,
    },
    Refused {
        status: i32,
    },
    AnsweredAnother {
        request_id: u64,
        expected: u64,
    },
    Malformed {
        fault: FramingError,
    },
    MissingToken,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Disposition {
    Retry,
    Degrade,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    Interrupted,
    Unavailable,
    Busy,
    Memory,
    ProcessFiles,
    SystemFiles,
    Other,
}

impl Refusal {
    #[must_use]
    pub const fn from_linux_errno(errno: i32) -> Self {
        match errno {
            4 => Self::Interrupted,
            11 => Self::Unavailable,
            16 => Self::Busy,
            12 => Self::Memory,
            24 => Self::ProcessFiles,
            23 => Self::SystemFiles,
            _ => Self::Other,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    Transport,
    Local,
    InvalidHandshake,
    Refused(Refusal),
}

impl Failure {
    #[must_use]
    pub fn disposition(self) -> Disposition {
        match self {
            Self::Transport
            | Self::Local
            | Self::Refused(
                Refusal::Interrupted
                | Refusal::Unavailable
                | Refusal::Busy
                | Refusal::Memory
                | Refusal::ProcessFiles
                | Refusal::SystemFiles,
            ) => Disposition::Retry,
            Self::InvalidHandshake | Self::Refused(Refusal::Other) => Disposition::Degrade,
        }
    }

    /// What a failed join of one more connection into a session means for
    /// that session. Only a transport failure leaves the session in place.
    #[must_use]
    pub fn join(self) -> Join {
        match self {
            Self::Transport => Join::Unreachable,
            Self::Local | Self::InvalidHandshake | Self::Refused(_) => Join::Refused,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Join {
    Unreachable,
    Refused,
}

impl HandshakeError {
    pub fn failure(self, classify: impl FnOnce(i32) -> Refusal) -> Failure {
        match self {
            Self::Refused { status } => Failure::Refused(classify(status)),
            Self::ProtocolVersion { .. }
            | Self::ReservedFlags { .. }
            | Self::RootNodeId { .. }
            | Self::AnsweredAnother { .. }
            | Self::Malformed { .. }
            | Self::MissingToken => Failure::InvalidHandshake,
        }
    }
}

impl fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProtocolVersion {
                announced,
                expected,
            } => write!(
                f,
                "it speaks protocol version {announced}, and this client speaks {expected}"
            ),
            Self::ReservedFlags { flags } => {
                write!(f, "it sets reserved feature flags {flags:#x}")
            }
            Self::RootNodeId {
                announced,
                expected,
            } => write!(
                f,
                "it announces root node id {announced}, and a mount root is {expected}"
            ),
            Self::Refused { status } => write!(f, "it refuses the mount with status {status}"),
            Self::AnsweredAnother {
                request_id,
                expected,
            } => write!(
                f,
                "it answers request {request_id}, and the handshake is request {expected}"
            ),
            Self::Malformed { fault } => write!(f, "{fault}"),
            Self::MissingToken => f.write_str("it answers without a session token"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TooLong;

impl fmt::Display for TooLong {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the namespace or the subpath is longer than a handshake can carry")
    }
}

#[must_use]
pub fn request_len(namespace: &[u8], subpath: &[u8]) -> usize {
    FrameWriter::request_len::<HelloRequest>(namespace.len() + subpath.len())
}

pub fn request<'a>(
    buffer: &'a mut [u8],
    limits: &Limits,
    namespace: &[u8],
    subpath: &[u8],
) -> Result<&'a [u8], TooLong> {
    let body = HelloRequest::new(len_of(namespace)?, len_of(subpath)?);
    // The handshake sends a zeroed request head, because it addresses no node
    // and no caller.
    let head = RequestHead::new(0, 0, 0, 0);
    let mut writer = FrameWriter::request(buffer, limits, HELLO_REQUEST_ID, &head, &body)
        .map_err(|_| TooLong)?;
    writer.payload(namespace).map_err(|_| TooLong)?;
    writer.payload(subpath).map_err(|_| TooLong)?;
    writer.finish().map_err(|_| TooLong)
}

#[must_use]
pub fn join_request_len(token: &[u8]) -> usize {
    FrameWriter::request_len::<HelloRequest>(token.len())
}

pub fn join_request<'a>(
    buffer: &'a mut [u8],
    limits: &Limits,
    token: &[u8],
) -> Result<&'a [u8], TooLong> {
    let body = HelloRequest::join(len_of(token)?);
    let head = RequestHead::new(0, 0, 0, 0);
    let mut writer = FrameWriter::request(buffer, limits, HELLO_REQUEST_ID, &head, &body)
        .map_err(|_| TooLong)?;
    writer.payload(token).map_err(|_| TooLong)?;
    writer.finish().map_err(|_| TooLong)
}

/// The frame is matched to its request exactly like every later reply, not as
/// the one frame exempt from that discipline. A reply without a token opens a
/// session no other connection can join, and the core fails it.
pub fn session<'a>(bytes: &'a [u8], limits: &Limits) -> Result<Accepted<'a>, HandshakeError> {
    let frame = Frame::parse(bytes, limits).map_err(|fault| HandshakeError::Malformed { fault })?;
    if frame.request_id() != HELLO_REQUEST_ID {
        return Err(HandshakeError::AnsweredAnother {
            request_id: frame.request_id(),
            expected: HELLO_REQUEST_ID,
        });
    }
    let reply = match frame
        .response::<HelloReply>()
        .map_err(|fault| HandshakeError::Malformed { fault })?
    {
        ResponseOutcome::Success(reply) => reply,
        ResponseOutcome::Error(status) => return Err(HandshakeError::Refused { status }),
    };
    let negotiated = accept(reply.body())?;
    if reply.token().is_empty() {
        return Err(HandshakeError::MissingToken);
    }
    Ok(Accepted {
        negotiated,
        token: reply.token(),
    })
}

fn accept(reply: &HelloReply) -> Result<Negotiated, HandshakeError> {
    let announced = reply.protocol_version.get();
    if announced != PROTOCOL_VERSION {
        return Err(HandshakeError::ProtocolVersion {
            announced,
            expected: PROTOCOL_VERSION,
        });
    }
    let flags = reply.flags.get();
    if flags & !ACCEPTED_REPLY_FLAGS != 0 {
        return Err(HandshakeError::ReservedFlags { flags });
    }
    let root_node_id = reply.root_node_id.get();
    if root_node_id != ROOT_NODE_ID {
        return Err(HandshakeError::RootNodeId {
            announced: root_node_id,
            expected: ROOT_NODE_ID,
        });
    }
    Ok(Negotiated {
        root_node_id,
        connection_id: reply.connection_id.get(),
    })
}

fn len_of(field: &[u8]) -> Result<u32, TooLong> {
    u32::try_from(field.len()).map_err(|_| TooLong)
}

#[cfg(test)]
mod tests {
    use super::*;
    use voidport_proto::limits::LIMITS;
    use voidport_proto::opcode::Opcode;
    use zerocopy::byteorder::little_endian::{U32, U64};

    const TOKEN: &[u8] = b"header.claims.signature";

    fn conforming() -> HelloReply {
        HelloReply {
            root_node_id: U64::new(ROOT_NODE_ID),
            protocol_version: U32::new(PROTOCOL_VERSION),
            flags: U32::ZERO,
            connection_id: U64::new(3),
            token_len: U32::new(TOKEN.len() as u32),
            reserved: U32::ZERO,
        }
    }

    fn framed(reply: &HelloReply, token: &[u8], request_id: u64) -> std::vec::Vec<u8> {
        let mut buffer = std::vec![0u8; FrameWriter::response_len::<HelloReply>(token.len())];
        let mut writer =
            FrameWriter::response(&mut buffer, &LIMITS, request_id, reply).expect("encodable");
        writer.payload(token).expect("it fits");
        writer.finish().expect("whole").to_vec()
    }

    #[test]
    fn linux_refusal_mapping_covers_every_errno() {
        let retryable = [
            (4, Refusal::Interrupted),
            (11, Refusal::Unavailable),
            (16, Refusal::Busy),
            (12, Refusal::Memory),
            (24, Refusal::ProcessFiles),
            (23, Refusal::SystemFiles),
        ];
        for errno in 1..=4095 {
            let expected = retryable
                .iter()
                .find_map(|&(number, class)| (number == errno).then_some(class))
                .unwrap_or(Refusal::Other);
            assert_eq!(Refusal::from_linux_errno(errno), expected, "errno {errno}");
            assert_eq!(
                Failure::Refused(expected).disposition(),
                if expected == Refusal::Other {
                    Disposition::Degrade
                } else {
                    Disposition::Retry
                },
            );
        }
        for invalid in [i32::MIN, -1, 0, 4096, i32::MAX] {
            assert_eq!(Refusal::from_linux_errno(invalid), Refusal::Other);
        }
    }

    #[test]
    fn reconnect_disposition_covers_every_failure_class() {
        for refusal in [
            Refusal::Interrupted,
            Refusal::Unavailable,
            Refusal::Busy,
            Refusal::Memory,
            Refusal::ProcessFiles,
            Refusal::SystemFiles,
        ] {
            assert_eq!(Failure::Refused(refusal).disposition(), Disposition::Retry);
        }
        assert_eq!(
            Failure::Refused(Refusal::Other).disposition(),
            Disposition::Degrade
        );
        assert_eq!(Failure::Transport.disposition(), Disposition::Retry);
        assert_eq!(Failure::Local.disposition(), Disposition::Retry);
        for error in [
            HandshakeError::ProtocolVersion {
                announced: 2,
                expected: 1,
            },
            HandshakeError::ReservedFlags { flags: 1 },
            HandshakeError::RootNodeId {
                announced: 7,
                expected: 1,
            },
            HandshakeError::AnsweredAnother {
                request_id: 2,
                expected: 1,
            },
            HandshakeError::Malformed {
                fault: FramingError::LengthOverflow,
            },
            HandshakeError::MissingToken,
        ] {
            assert_eq!(
                error
                    .failure(|_| panic!("invalid replies have no refusal errno"))
                    .disposition(),
                Disposition::Degrade,
            );
        }
        assert_eq!(
            HandshakeError::Refused { status: -4 }
                .failure(|status| {
                    assert_eq!(status, -4);
                    Refusal::Interrupted
                })
                .disposition(),
            Disposition::Retry,
        );
    }

    #[test]
    fn the_session_token_travels_from_the_reply_to_a_joining_hello() {
        let bytes = framed(&conforming(), TOKEN, HELLO_REQUEST_ID);
        assert_eq!(
            session(&bytes, &LIMITS),
            Ok(Accepted {
                negotiated: Negotiated {
                    root_node_id: ROOT_NODE_ID,
                    connection_id: 3,
                },
                token: TOKEN,
            })
        );

        let mut buffer = std::vec![0u8; join_request_len(TOKEN)];
        let hello = join_request(&mut buffer, &LIMITS, TOKEN).expect("it fits");
        let frame = Frame::parse(hello, &LIMITS).expect("a well-framed hello");
        assert_eq!(frame.request_id(), HELLO_REQUEST_ID);
        let hello = frame.request::<HelloRequest>().expect("a hello");
        assert!(hello.body().joins());
        assert_eq!(hello.token(), TOKEN);
        assert_eq!(hello.namespace(), b"");
        assert_eq!(hello.subpath(), b"");
        assert_eq!(hello.body().protocol_version.get(), PROTOCOL_VERSION);

        let mut short = [0u8; 8];
        assert_eq!(join_request(&mut short, &LIMITS, TOKEN), Err(TooLong));
    }

    #[test]
    fn the_request_is_one_frame_the_server_can_read() {
        let (namespace, subpath) = (b"namespace".as_slice(), b"/sub".as_slice());
        let mut buffer = std::vec![0u8; request_len(namespace, subpath)];
        let bytes = request(&mut buffer, &LIMITS, namespace, subpath).expect("it fits");
        assert_eq!(bytes.len(), request_len(namespace, subpath));
        let frame = Frame::parse(bytes, &LIMITS).expect("a well-framed hello");
        assert_eq!(frame.request_id(), HELLO_REQUEST_ID);
        let hello = frame.request::<HelloRequest>().expect("a hello");
        assert_eq!(hello.namespace(), namespace);
        assert_eq!(hello.subpath(), subpath);
        assert_eq!(hello.auth(), b"");
        assert_eq!(hello.token(), b"");
        assert!(!hello.body().joins());
        assert_eq!(hello.body().protocol_version.get(), PROTOCOL_VERSION);
    }

    #[test]
    fn only_what_a_handshake_cannot_carry_is_refused() {
        let namespace = std::vec![b'n'; 3 * LIMITS.path_max as usize];
        let mut buffer = std::vec![0u8; request_len(&namespace, b"")];
        assert!(request(&mut buffer, &LIMITS, &namespace, b"").is_ok());

        let subpath = std::vec![b's'; LIMITS.path_max as usize];
        let mut buffer = std::vec![0u8; request_len(b"ns", &subpath)];
        assert_eq!(request(&mut buffer, &LIMITS, b"ns", &subpath), Err(TooLong));

        let mut short = [0u8; 8];
        assert_eq!(request(&mut short, &LIMITS, b"ns", b""), Err(TooLong));
    }

    #[test]
    fn every_handshake_error_class_has_its_own_reply() {
        let mut wrong_version = conforming();
        wrong_version.protocol_version = U32::new(PROTOCOL_VERSION + 1);
        assert_eq!(
            session(&framed(&wrong_version, TOKEN, HELLO_REQUEST_ID), &LIMITS),
            Err(HandshakeError::ProtocolVersion {
                announced: PROTOCOL_VERSION + 1,
                expected: PROTOCOL_VERSION,
            })
        );

        // The wire crate does not encode a reply that breaks these checks, so
        // the frame is built by hand from a conforming one, as a peer that
        // ignores the rule would put it on the wire.
        let mut bytes = framed(&conforming(), TOKEN, HELLO_REQUEST_ID);
        let flags = body_offset() + core::mem::offset_of!(HelloReply, flags);
        bytes[flags..flags + 4].copy_from_slice(&1u32.to_le_bytes());
        assert_eq!(
            session(&bytes, &LIMITS),
            Err(HandshakeError::ReservedFlags { flags: 1 })
        );

        // The wire crate checks the reserved field of the reply, so it arrives
        // as a malformed reply and not as an error class of this crate.
        let mut bytes = framed(&conforming(), TOKEN, HELLO_REQUEST_ID);
        let reserved = body_offset() + core::mem::offset_of!(HelloReply, reserved);
        bytes[reserved..reserved + 4].copy_from_slice(&7u32.to_le_bytes());
        assert!(matches!(
            session(&bytes, &LIMITS),
            Err(HandshakeError::Malformed { .. })
        ));

        let mut elsewhere = conforming();
        elsewhere.root_node_id = U64::new(7);
        assert_eq!(
            session(&framed(&elsewhere, TOKEN, HELLO_REQUEST_ID), &LIMITS),
            Err(HandshakeError::RootNodeId {
                announced: 7,
                expected: ROOT_NODE_ID,
            })
        );

        let mut tokenless = conforming();
        tokenless.token_len = U32::ZERO;
        assert_eq!(
            session(&framed(&tokenless, b"", HELLO_REQUEST_ID), &LIMITS),
            Err(HandshakeError::MissingToken)
        );

        let mut refused = [0u8; FrameWriter::ERROR_RESPONSE_LEN];
        let refusal =
            FrameWriter::error_response(&mut refused, HELLO_REQUEST_ID, Opcode::Hello, -2)
                .expect("encodable");
        assert_eq!(
            session(refusal, &LIMITS),
            Err(HandshakeError::Refused { status: -2 })
        );

        assert_eq!(
            session(&framed(&conforming(), TOKEN, 99), &LIMITS),
            Err(HandshakeError::AnsweredAnother {
                request_id: 99,
                expected: HELLO_REQUEST_ID,
            })
        );

        assert!(matches!(
            session(b"not a frame at all", &LIMITS),
            Err(HandshakeError::Malformed { .. })
        ));
        // A well-framed answer to another operation is malformed as a
        // handshake, whatever else it is.
        let mut other = [0u8; FrameWriter::ERROR_RESPONSE_LEN];
        let wrong_opcode =
            FrameWriter::error_response(&mut other, HELLO_REQUEST_ID, Opcode::Lookup, -2)
                .expect("encodable");
        assert!(matches!(
            session(wrong_opcode, &LIMITS),
            Err(HandshakeError::Malformed { .. })
        ));
    }

    fn body_offset() -> usize {
        voidport_proto::frame::FRAME_HEADER_LEN + voidport_proto::message::RESPONSE_HEAD_LEN
    }
}
