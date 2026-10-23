//! A framing error poisons the byte stream, since the length fields of the
//! stream cannot be trusted any further. This includes a frame with an unknown
//! opcode, because the header has no total length to skip the frame by. A
//! well-framed request that cannot be satisfied gets an error response.

use core::fmt;

use crate::frame::FrameKind;
use crate::limits::Part;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum FramingError {
    /// `needed` is the total number of bytes the frame requires, header included.
    Incomplete {
        needed: usize,
    },
    RegionTooLong {
        part: Part,
        declared: u32,
        bound: u32,
    },
    UnknownOpcode {
        opcode: u16,
    },
    NoBody {
        opcode: u16,
        kind: FrameKind,
    },
    PieceTooLong {
        declared: u32,
        remaining: u64,
    },
    ReservedPieceFlags {
        flags: u32,
    },
    TrailingBytes {
        extra: usize,
    },
    ReservedFlags {
        flags: u16,
    },
    ReservedOpcode,
    ReservedFieldNonZero,
    InvalidEntryNodeId,
    InvalidEntryName,
    InvalidEntryType,
    InvalidLinkTarget,
    InvalidStatfs,
    InvalidNanoseconds {
        nsec: u32,
    },
    NegotiationFlagsNonZero {
        flags: u32,
    },
    UnexpectedFrameKind {
        expected: FrameKind,
        found: FrameKind,
    },
    NotificationResponseFlag,
    OpcodeMismatch {
        expected: u16,
        found: u16,
    },
    ZeroRequestId,
    NotificationRequestId {
        request_id: u64,
    },
    /// Ids are unique among the outstanding requests that expect a response. A
    /// request without a response (`forget`, `cancel`) retires its id when its
    /// frame is accepted.
    DuplicateRequestId {
        request_id: u64,
    },
    RepeatedHandshake,
    BodyTooShort {
        needed: usize,
        found: usize,
    },
    PayloadLengthMismatch {
        declared: u32,
        found: usize,
    },
    IncompletePayload {
        missing: u32,
    },
    LengthOverflow,
    InvalidStatus {
        status: i32,
    },
    ErrorResponseBody {
        extra: usize,
    },
    BufferTooSmall {
        needed: usize,
        found: usize,
    },
    TailLengthMismatch {
        declared: u32,
        found: usize,
    },
    UnknownChainKind {
        kind: u32,
    },
}

impl fmt::Display for FramingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Incomplete { needed } => write!(f, "incomplete frame, needs {needed} bytes"),
            Self::RegionTooLong {
                part,
                declared,
                bound,
            } => write!(
                f,
                "a {part:?} part of {declared} bytes exceeds the {bound} the interface takes"
            ),
            Self::UnknownOpcode { opcode } => write!(f, "unknown opcode {opcode:#06x}"),
            Self::NoBody { opcode, kind } => {
                write!(f, "no {kind} body is declared for opcode {opcode:#06x}")
            }
            Self::PieceTooLong {
                declared,
                remaining,
            } => write!(
                f,
                "a piece of {declared} bytes exceeds the {remaining} the receiver can take"
            ),
            Self::ReservedPieceFlags { flags } => {
                write!(f, "reserved closing flag bits set in {flags:#010x}")
            }
            Self::TrailingBytes { extra } => write!(f, "{extra} trailing bytes after the frame"),
            Self::ReservedFlags { flags } => write!(f, "reserved flag bits set in {flags:#06x}"),
            Self::ReservedOpcode => f.write_str("opcode 0x0000 is reserved"),
            Self::ReservedFieldNonZero => f.write_str("a reserved field was not zero"),
            Self::InvalidEntryNodeId => f.write_str("an entry names a reserved node id"),
            Self::InvalidEntryType => f.write_str("invalid or contradictory directory entry type"),
            Self::InvalidEntryName => f.write_str("an entry has an invalid filesystem name"),
            Self::InvalidLinkTarget => f.write_str("a symlink target contains a NUL byte"),
            Self::InvalidStatfs => f.write_str("filesystem statistics contradict each other"),
            Self::InvalidNanoseconds { nsec } => write!(f, "invalid nanoseconds: {nsec}"),
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
            Self::UnknownChainKind { kind } => write!(f, "unknown chain kind {kind}"),
        }
    }
}

impl core::error::Error for FramingError {}
