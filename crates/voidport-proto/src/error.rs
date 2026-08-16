//! Protocol error taxonomy.
//!
//! The wire contract splits protocol errors into two classes:
//!
//! * **Framing errors** ([`FramingError`]) poison the byte stream. A server
//!   that hits one closes the connection (tearing down handles and the node
//!   table as on disconnect); there is no way to resynchronize a stream whose
//!   length fields cannot be trusted.
//! * **Semantic errors** — a well-framed request the peer cannot satisfy —
//!   are answered with an error response and the connection lives on. An
//!   unknown opcode ([`UnknownOpcode`](crate::opcode::UnknownOpcode)) is the
//!   canonical case: answering `ENOSYS` instead of hanging up is what keeps
//!   future protocol extensions non-fatal to old peers.

use core::fmt;

use crate::frame::FrameKind;

/// A malformed frame: the byte stream cannot be trusted any further.
///
/// Every variant is produced by parsing or encoding without allocating and
/// without panicking; arbitrary input bytes can only ever yield one of these.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum FramingError {
    /// The buffer does not hold a complete frame yet; `needed` is the total
    /// number of bytes the frame requires, header included.
    Incomplete {
        /// Total bytes the caller must buffer before retrying.
        needed: usize,
    },
    /// The declared frame length is smaller than the frame header.
    FrameTooShort {
        /// The declared length.
        len: u32,
    },
    /// The declared frame length exceeds the negotiated maximum.
    FrameTooLong {
        /// The declared length.
        len: u32,
        /// The maximum accepted length.
        max: u32,
    },
    /// Bytes remained after the frame in a buffer that had to hold exactly one.
    TrailingBytes {
        /// Number of unaccounted bytes.
        extra: usize,
    },
    /// Reserved bits are set in the frame header `flags` field.
    ReservedFlags {
        /// The offending flags word.
        flags: u16,
    },
    /// Opcode `0x0000`, which belongs to no defined opcode range.
    ReservedOpcode,
    /// A `reserved` field that the contract requires to be zero was not zero.
    ReservedFieldNonZero,
    /// A handshake negotiation flags field was nonzero on encode.
    NegotiationFlagsNonZero {
        /// The offending flags word.
        flags: u32,
    },
    /// The frame is of a different class than the parse asked for.
    UnexpectedFrameKind {
        /// The class the caller asked to parse.
        expected: FrameKind,
        /// The class the frame actually is.
        found: FrameKind,
    },
    /// A notification-range opcode illegally carried the response flag.
    NotificationResponseFlag,
    /// The frame opcode does not match the message type being parsed.
    OpcodeMismatch {
        /// Opcode of the message type being parsed.
        expected: u16,
        /// Opcode carried by the frame.
        found: u16,
    },
    /// A request or response used request id 0, which is reserved for
    /// notifications.
    ZeroRequestId,
    /// A notification carried a nonzero request id.
    NotificationRequestId {
        /// The offending request id.
        request_id: u64,
    },
    /// A request reused an id that is still outstanding.
    ///
    /// Ids must be unique among a client's outstanding *response-expecting*
    /// requests; a reused one would make two replies indistinguishable, so the
    /// receiver cannot keep serving the stream. A no-response request
    /// (`forget`) retires its id the moment its frame is accepted and is never
    /// outstanding.
    DuplicateRequestId {
        /// The offending request id.
        request_id: u64,
    },
    /// A `Hello` arrived on a connection whose handshake is already complete.
    ///
    /// The contract gives a session exactly one handshake, and lists a repeated
    /// `Hello` among the framing errors that poison the stream: the peer is
    /// negotiating something that has already been settled, so nothing after it
    /// can be trusted to mean what it says.
    RepeatedHandshake,
    /// The frame body is too short for the fixed structs it must contain.
    BodyTooShort {
        /// Bytes required.
        needed: usize,
        /// Bytes present.
        found: usize,
    },
    /// The variable-length regions declared by the fixed struct do not exactly
    /// account for the trailing payload (strict framing).
    PayloadLengthMismatch {
        /// Sum of the declared region lengths.
        declared: u32,
        /// Actual payload length.
        found: usize,
    },
    /// Encoding finished with declared payload bytes still unwritten.
    IncompletePayload {
        /// Bytes still owed.
        missing: u32,
    },
    /// A sum of declared lengths overflowed the 32-bit wire length space.
    LengthOverflow,
    /// A response status was neither 0 (success) nor a negated Linux errno in
    /// `-MAX_ERRNO..=-1` (see
    /// [`is_error_status`](crate::message::is_error_status)).
    InvalidStatus {
        /// The offending status.
        status: i32,
    },
    /// An error response carried bytes after its status field.
    ErrorResponseBody {
        /// Number of bytes after the status field.
        extra: usize,
    },
    /// The caller-provided output buffer cannot hold the frame.
    BufferTooSmall {
        /// Bytes required.
        needed: usize,
        /// Bytes available.
        found: usize,
    },
    /// A stream entry's declared tail length disagrees with the tail supplied.
    TailLengthMismatch {
        /// Tail length declared in the entry header.
        declared: u32,
        /// Length of the supplied tail.
        found: usize,
    },
}

impl fmt::Display for FramingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Incomplete { needed } => write!(f, "incomplete frame, needs {needed} bytes"),
            Self::FrameTooShort { len } => write!(f, "frame length {len} is below the header size"),
            Self::FrameTooLong { len, max } => {
                write!(f, "frame length {len} exceeds the maximum of {max}")
            }
            Self::TrailingBytes { extra } => write!(f, "{extra} trailing bytes after the frame"),
            Self::ReservedFlags { flags } => write!(f, "reserved flag bits set in {flags:#06x}"),
            Self::ReservedOpcode => f.write_str("opcode 0x0000 is reserved"),
            Self::ReservedFieldNonZero => f.write_str("a reserved field was not zero"),
            Self::NegotiationFlagsNonZero { flags } => {
                write!(
                    f,
                    "handshake negotiation flags were not zero: {flags:#010x}"
                )
            }
            Self::UnexpectedFrameKind { expected, found } => {
                write!(f, "expected a {expected} frame, found a {found} frame")
            }
            Self::NotificationResponseFlag => {
                f.write_str("notification-range opcode carried the response flag")
            }
            Self::OpcodeMismatch { expected, found } => {
                write!(f, "expected opcode {expected:#06x}, found {found:#06x}")
            }
            Self::ZeroRequestId => f.write_str("request id 0 is reserved for notifications"),
            Self::NotificationRequestId { request_id } => {
                write!(f, "notification carried request id {request_id}")
            }
            Self::DuplicateRequestId { request_id } => {
                write!(f, "request id {request_id} is already outstanding")
            }
            Self::RepeatedHandshake => {
                f.write_str("a second handshake arrived on an established session")
            }
            Self::BodyTooShort { needed, found } => {
                write!(f, "frame body needs {needed} bytes, found {found}")
            }
            Self::PayloadLengthMismatch { declared, found } => {
                write!(f, "declared payload of {declared} bytes, found {found}")
            }
            Self::IncompletePayload { missing } => {
                write!(f, "{missing} declared payload bytes were never written")
            }
            Self::LengthOverflow => {
                f.write_str("declared lengths overflow the 32-bit length space")
            }
            Self::InvalidStatus { status } => {
                write!(
                    f,
                    "response status {status} is neither 0 nor a negated errno"
                )
            }
            Self::ErrorResponseBody { extra } => {
                write!(f, "error response carried {extra} bytes after its status")
            }
            Self::BufferTooSmall { needed, found } => {
                write!(f, "output buffer needs {needed} bytes, has {found}")
            }
            Self::TailLengthMismatch { declared, found } => {
                write!(
                    f,
                    "entry declares a {declared}-byte tail, got {found} bytes"
                )
            }
        }
    }
}

impl core::error::Error for FramingError {}
