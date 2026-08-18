//! The handshake: the frame that opens a session, and every way a reply can
//! fail to open one.
//!
//! One frame out, one frame in, under the pre-handshake size bound. Both halves
//! are decided here — the request is encoded into a buffer the adapter owns,
//! and the reply is validated into either the session's negotiated terms
//! ([`Negotiated`]) or one of the enumerated error classes ([`HandshakeError`]).
//! A completed handshake **is** the reconnection contract's probe: there is
//! nothing more to test, so an adapter may install the connection the moment
//! this module accepts its reply.
//!
//! Dial-time transport failures — a refused connect, a broken stream, an
//! oversized pre-handshake frame arriving from the peer — are not here and
//! cannot be: a core with no I/O cannot produce them, and they are the
//! adapter's to classify.
//!
//! **The reply is checked against the version and flag rules the request obeys**
//! (protocol version, reserved flag bits). v1 checked neither on the way back,
//! trusting a server that had just been sent both; the extraction corrects
//! that deliberately, and it is the one strictening in this crate. The
//! negotiation space is unchanged: a later version widens
//! [`ACCEPTED_REPLY_FLAGS`] and the check narrows accordingly.

use core::fmt;

use voidport_proto::PROTOCOL_VERSION;
use voidport_proto::error::FramingError;
use voidport_proto::frame::{Frame, FrameWriter, MAX_HELLO_FRAME_LEN};
use voidport_proto::message::{RequestHead, ResponseOutcome};
use voidport_proto::ops::handshake::{HelloReply, HelloRequest};

/// The request id the handshake carries.
///
/// It is the first id of every connection, and the data-request counter starts
/// after it, so "allocated monotonically and never reused" holds across the
/// whole connection, not only after the handshake. Request ids are
/// per-connection by the wire contract, so a replacement connection starts them
/// over.
pub const HELLO_REQUEST_ID: u64 = 1;

/// The smallest frame bound a session can be served under.
///
/// `max_frame_len` is the server's announcement, and everything a client
/// sizes — a read chunk, a write chunk, a directory batch — is derived from it.
/// A bound below the pre-handshake one leaves no room for a request plus a
/// usable payload: the read chunk saturates to zero and every nonempty file
/// would read as empty with no error anywhere. A mount is refused instead.
pub const MIN_MAX_FRAME_LEN: u32 = MAX_HELLO_FRAME_LEN;

/// The node id the mount root must have.
///
/// The kernel names the root of a FUSE mount `FUSE_ROOT_ID`, which is 1, and
/// nothing can change that; a server announcing another root node id is
/// describing a mount a client cannot serve. It is also the one node id the
/// server's generation-disjoint allocator never hands out, which is what lets a
/// stale mount heal by walking from the root.
pub const ROOT_NODE_ID: u64 = 1;

/// The reply feature flags this version of the protocol accepts.
///
/// None: v1 assigns no flag bit, so every bit of the word is reserved and a
/// reply setting one is describing a session this client cannot serve.
pub const ACCEPTED_REPLY_FLAGS: u32 = 0;

/// The most bytes a handshake frame may occupy, in either direction.
///
/// The size of the buffer an adapter hands [`request`], and the bound the
/// reply is read under.
pub const MAX_FRAME_LEN: u32 = MAX_HELLO_FRAME_LEN;

/// What a session negotiated, once its reply was accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Negotiated {
    /// The frame bound the server announced, in both directions.
    pub max_frame_len: u32,
    /// The node id of this session's mount root.
    pub root_node_id: u64,
}

/// Why a handshake did not open a session.
///
/// Every class is distinct because every class maps to a distinct mount error:
/// a server that refuses this mount and a server that speaks another protocol
/// are not the same answer, and neither is a peer sending nonsense.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum HandshakeError {
    /// The server answered a version this client does not speak.
    ProtocolVersion {
        /// The version the reply announced.
        announced: u32,
        /// The one this client speaks.
        expected: u32,
    },
    /// The reply set feature-flag bits this version of the protocol reserves.
    ///
    /// The reply's *reserved field* is the wire crate's own rule and arrives as
    /// [`HandshakeError::Malformed`]; this class is the flag word, which no
    /// version has assigned a bit of yet.
    ReservedFlags {
        /// The feature flags the reply carried.
        flags: u32,
    },
    /// The server announced a frame bound too small to serve a session with.
    FrameBound {
        /// The bound the server announced.
        announced: u32,
        /// The smallest one a mount can be served under.
        minimum: u32,
    },
    /// The server announced a root node id the client cannot name.
    RootNodeId {
        /// The node id the server announced.
        announced: u64,
        /// The only one a mount root can have.
        expected: u64,
    },
    /// The server is reachable and refuses this mount, with a reason.
    Refused {
        /// The negated errno the server answered with.
        status: i32,
    },
    /// The reply answered a request that was never sent.
    AnsweredAnother {
        /// The request id the reply echoed.
        request_id: u64,
        /// The one the handshake was sent under.
        expected: u64,
    },
    /// The reply was not a legal handshake response at all.
    Malformed {
        /// What was wrong with it.
        fault: FramingError,
    },
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
            Self::FrameBound { announced, minimum } => write!(
                f,
                "it announces a maximum frame length of {announced} bytes, \
                 below the {minimum} a session needs"
            ),
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
        }
    }
}

/// The namespace or subpath does not fit a handshake frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TooLong {
    /// The pre-handshake frame bound the request had to fit.
    pub max: u32,
}

impl fmt::Display for TooLong {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "the namespace and subpath do not fit a {}-byte handshake",
            self.max
        )
    }
}

/// Encodes the handshake request into `buffer`, returning the frame's bytes.
///
/// The buffer is the adapter's, and [`MAX_FRAME_LEN`] bytes are always enough
/// for one: nothing here allocates.
///
/// # Errors
///
/// Returns [`TooLong`] when the namespace and subpath do not fit the
/// pre-handshake bound.
pub fn request<'a>(
    buffer: &'a mut [u8],
    namespace: &[u8],
    subpath: &[u8],
) -> Result<&'a [u8], TooLong> {
    let body = HelloRequest::new(len_of(namespace)?, len_of(subpath)?);
    // The handshake carries the request head zeroed: it names no node and no
    // caller, and uniformity beats a special case.
    let head = RequestHead::new(0, 0, 0, 0);
    let too_long = || TooLong { max: MAX_FRAME_LEN };
    let mut writer = FrameWriter::request(buffer, MAX_FRAME_LEN, HELLO_REQUEST_ID, &head, &body)
        .map_err(|_| too_long())?;
    writer.payload(namespace).map_err(|_| too_long())?;
    writer.payload(subpath).map_err(|_| too_long())?;
    writer.finish().map_err(|_| too_long())
}

/// Validates a handshake reply frame, yielding what the session negotiated.
///
/// The frame is matched to its request exactly like every later reply, not as
/// the one frame exempt from that discipline.
///
/// # Errors
///
/// Returns the [`HandshakeError`] class the reply falls into.
pub fn reply(bytes: &[u8]) -> Result<Negotiated, HandshakeError> {
    let frame =
        Frame::parse(bytes, MAX_FRAME_LEN).map_err(|fault| HandshakeError::Malformed { fault })?;
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
        ResponseOutcome::Success(reply) => *reply.body(),
        ResponseOutcome::Error(status) => return Err(HandshakeError::Refused { status }),
    };
    accept(&reply)
}

/// The rules a `HelloReply` body has to satisfy, in the order a session needs
/// them: what protocol this is, then what it may say, then what it announced.
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
    let max_frame_len = reply.max_frame_len.get();
    if max_frame_len < MIN_MAX_FRAME_LEN {
        return Err(HandshakeError::FrameBound {
            announced: max_frame_len,
            minimum: MIN_MAX_FRAME_LEN,
        });
    }
    let root_node_id = reply.root_node_id.get();
    if root_node_id != ROOT_NODE_ID {
        return Err(HandshakeError::RootNodeId {
            announced: root_node_id,
            expected: ROOT_NODE_ID,
        });
    }
    Ok(Negotiated {
        max_frame_len,
        root_node_id,
    })
}

/// The length of a handshake field, refused if it cannot be one.
fn len_of(field: &[u8]) -> Result<u32, TooLong> {
    u32::try_from(field.len()).map_err(|_| TooLong { max: MAX_FRAME_LEN })
}

#[cfg(test)]
mod tests {
    use super::*;
    use voidport_proto::opcode::Opcode;
    use zerocopy::byteorder::little_endian::{U32, U64};

    /// A `HelloReply` a conforming server would send.
    fn conforming() -> HelloReply {
        HelloReply {
            root_node_id: U64::new(ROOT_NODE_ID),
            protocol_version: U32::new(PROTOCOL_VERSION),
            flags: U32::ZERO,
            max_frame_len: U32::new(1024 * 1024),
            reserved: U32::ZERO,
        }
    }

    /// That reply, framed as an answer to `request_id`.
    fn framed(reply: &HelloReply, request_id: u64) -> std::vec::Vec<u8> {
        let mut buffer = [0u8; MAX_HELLO_FRAME_LEN as usize];
        FrameWriter::response(&mut buffer, MAX_FRAME_LEN, request_id, reply)
            .and_then(FrameWriter::finish)
            .expect("encodable")
            .to_vec()
    }

    #[test]
    fn a_conforming_reply_opens_the_session() {
        assert_eq!(
            reply(&framed(&conforming(), HELLO_REQUEST_ID)),
            Ok(Negotiated {
                max_frame_len: 1024 * 1024,
                root_node_id: ROOT_NODE_ID,
            })
        );
    }

    #[test]
    fn the_request_is_one_frame_the_server_can_read() {
        let mut buffer = [0u8; MAX_HELLO_FRAME_LEN as usize];
        let bytes = request(&mut buffer, b"namespace", b"/sub").expect("it fits");
        let frame = Frame::parse(bytes, MAX_FRAME_LEN).expect("a well-framed hello");
        assert_eq!(frame.request_id(), HELLO_REQUEST_ID);
        let hello = frame.request::<HelloRequest>().expect("a hello");
        assert_eq!(hello.namespace(), b"namespace");
        assert_eq!(hello.subpath(), b"/sub");
        assert_eq!(hello.auth(), b"");
        assert_eq!(hello.body().protocol_version.get(), PROTOCOL_VERSION);
    }

    #[test]
    fn a_namespace_that_cannot_fit_a_handshake_is_refused() {
        let mut buffer = [0u8; MAX_HELLO_FRAME_LEN as usize];
        let huge = [b'n'; MAX_HELLO_FRAME_LEN as usize];
        assert_eq!(
            request(&mut buffer, &huge, b""),
            Err(TooLong { max: MAX_FRAME_LEN })
        );
    }

    /// Every class the core owns, one reply each.
    #[test]
    fn every_handshake_error_class_has_its_own_reply() {
        let mut wrong_version = conforming();
        wrong_version.protocol_version = U32::new(PROTOCOL_VERSION + 1);
        assert_eq!(
            reply(&framed(&wrong_version, HELLO_REQUEST_ID)),
            Err(HandshakeError::ProtocolVersion {
                announced: PROTOCOL_VERSION + 1,
                expected: PROTOCOL_VERSION,
            })
        );

        // The reply-side checks v1 did not make. The wire crate refuses to
        // *encode* a reply with either word set, so these are built by hand
        // from a conforming frame — which is exactly the shape a peer that
        // does not obey the rule would put on the wire.
        let mut bytes = framed(&conforming(), HELLO_REQUEST_ID);
        let flags = body_offset() + core::mem::offset_of!(HelloReply, flags);
        bytes[flags..flags + 4].copy_from_slice(&1u32.to_le_bytes());
        assert_eq!(
            reply(&bytes),
            Err(HandshakeError::ReservedFlags { flags: 1 })
        );

        // The reply's reserved field is the wire crate's rule: it arrives as a
        // malformed reply, not as a class of this crate's own.
        let mut bytes = framed(&conforming(), HELLO_REQUEST_ID);
        let reserved = body_offset() + core::mem::offset_of!(HelloReply, reserved);
        bytes[reserved..reserved + 4].copy_from_slice(&7u32.to_le_bytes());
        assert!(matches!(
            reply(&bytes),
            Err(HandshakeError::Malformed { .. })
        ));

        for announced in [0, 8, MIN_MAX_FRAME_LEN - 1] {
            let mut small = conforming();
            small.max_frame_len = U32::new(announced);
            assert_eq!(
                reply(&framed(&small, HELLO_REQUEST_ID)),
                Err(HandshakeError::FrameBound {
                    announced,
                    minimum: MIN_MAX_FRAME_LEN,
                })
            );
        }
        // The pre-handshake bound itself is enough to serve under.
        let mut smallest = conforming();
        smallest.max_frame_len = U32::new(MIN_MAX_FRAME_LEN);
        assert!(reply(&framed(&smallest, HELLO_REQUEST_ID)).is_ok());

        let mut elsewhere = conforming();
        elsewhere.root_node_id = U64::new(7);
        assert_eq!(
            reply(&framed(&elsewhere, HELLO_REQUEST_ID)),
            Err(HandshakeError::RootNodeId {
                announced: 7,
                expected: ROOT_NODE_ID,
            })
        );

        let mut refused = [0u8; 64];
        let refusal = FrameWriter::error_response(
            &mut refused,
            MAX_FRAME_LEN,
            HELLO_REQUEST_ID,
            Opcode::Hello,
            -2,
        )
        .expect("encodable");
        assert_eq!(reply(refusal), Err(HandshakeError::Refused { status: -2 }));

        assert_eq!(
            reply(&framed(&conforming(), 99)),
            Err(HandshakeError::AnsweredAnother {
                request_id: 99,
                expected: HELLO_REQUEST_ID,
            })
        );

        assert!(matches!(
            reply(b"not a frame at all"),
            Err(HandshakeError::Malformed { .. })
        ));
        // A well-framed answer to another operation is malformed as a
        // handshake, whatever else it is.
        let mut other = [0u8; 64];
        let wrong_opcode = FrameWriter::error_response(
            &mut other,
            MAX_FRAME_LEN,
            HELLO_REQUEST_ID,
            Opcode::Lookup,
            -2,
        )
        .expect("encodable");
        assert!(matches!(
            reply(wrong_opcode),
            Err(HandshakeError::Malformed { .. })
        ));
    }

    /// Where a `HelloReply` body starts inside its frame.
    fn body_offset() -> usize {
        voidport_proto::frame::FRAME_HEADER_LEN + voidport_proto::message::RESPONSE_HEAD_LEN
    }
}
