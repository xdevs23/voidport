//! ```text
//! piece   := [len u32 != 0][len bytes]
//! closing := [0 u32][status i32][flags u32]
//! ```
//!
//! The status is zero when the source gave what it had, and a negated errno
//! when a later piece failed. Flag bit 0 shows that the source is exhausted,
//! and every other bit is reserved.

use core::mem::size_of;

use zerocopy::byteorder::little_endian::{I32, U32};
use zerocopy::{FromBytes as _, IntoBytes as _};

use crate::error::FramingError;
use crate::limits::Limits;
use crate::macros::wire_struct;
use crate::message::{WireStruct, is_error_status};
use crate::ops::dir::DirEntryHeader;
use crate::ops::share::ShareEntryHeader;
use crate::stream::{StreamEntry, StreamItem};

/// A directory with no more entries, or a file whose host gave zero bytes
/// before the request was filled.
pub const CLOSING_EXHAUSTED: u32 = 1 << 0;

pub const CLOSING_RESERVED_MASK: u32 = !CLOSING_EXHAUSTED;

pub const PIECE_LEN_LEN: usize = 4;

pub const CLOSING_LEN: usize = 8;

wire_struct! {
    pub struct PieceLength {
        pub len: U32,
    }
}

wire_struct! {
    pub struct ClosingBody {
        pub status: I32,
        pub flags: U32,
    }
}

/// A validated closing piece.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Closing {
    pub status: i32,
    pub exhausted: bool,
}

impl Closing {
    #[must_use]
    pub fn done(exhausted: bool) -> Self {
        Self {
            status: 0,
            exhausted,
        }
    }

    #[must_use]
    pub fn encode(&self) -> [u8; PIECE_LEN_LEN + CLOSING_LEN] {
        let mut bytes = [0u8; PIECE_LEN_LEN + CLOSING_LEN];
        let body = ClosingBody {
            status: I32::new(self.status),
            flags: U32::new(if self.exhausted { CLOSING_EXHAUSTED } else { 0 }),
        };
        bytes[PIECE_LEN_LEN..].copy_from_slice(body.as_bytes());
        bytes
    }
}

impl ClosingBody {
    pub fn closing(&self) -> Result<Closing, FramingError> {
        let status = self.status.get();
        if status != 0 && !is_error_status(status) {
            return Err(FramingError::InvalidStatus { status });
        }
        let flags = self.flags.get();
        if flags & CLOSING_RESERVED_MASK != 0 {
            return Err(FramingError::ReservedPieceFlags { flags });
        }
        Ok(Closing {
            status,
            exhausted: flags & CLOSING_EXHAUSTED != 0,
        })
    }

    pub fn parse(bytes: &[u8; CLOSING_LEN]) -> Result<Closing, FramingError> {
        let body = ClosingBody::read_from_bytes(bytes).map_err(|_| FramingError::BodyTooShort {
            needed: CLOSING_LEN,
            found: bytes.len(),
        })?;
        body.closing()
    }
}

pub fn length(len: usize) -> Result<[u8; PIECE_LEN_LEN], FramingError> {
    let len = u32::try_from(len).map_err(|_| FramingError::LengthOverflow)?;
    Ok(len.to_le_bytes())
}

#[must_use]
pub const fn stream_len(pieces: usize, bytes: usize) -> usize {
    PIECE_LEN_LEN * pieces + bytes + PIECE_LEN_LEN + CLOSING_LEN
}

#[must_use]
pub fn read_length(bytes: &[u8; PIECE_LEN_LEN]) -> u32 {
    u32::from_le_bytes(*bytes)
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Stream {
    Data,
    DirEntries,
    ShareEntries,
}

impl Stream {
    #[must_use]
    /// `None` for file data, whose pieces are bounded by what remains of the
    /// request.
    pub fn piece_bound(self, limits: &Limits) -> Option<u32> {
        let (header, tail) = match self {
            Self::Data => return None,
            Self::DirEntries => (size_of::<DirEntryHeader>(), limits.name_max),
            Self::ShareEntries => (
                size_of::<ShareEntryHeader>(),
                limits.path_max.saturating_sub(1),
            ),
        };
        Some((header as u32).saturating_add(tail))
    }
}

/// `remaining` is what is left of the request for a data piece, and the room
/// that the receiver has for one entry for an entry piece.
pub fn check(declared: u32, remaining: u64) -> Result<(), FramingError> {
    if u64::from(declared) > remaining {
        return Err(FramingError::PieceTooLong {
            declared,
            remaining,
        });
    }
    Ok(())
}

pub fn entry<H: StreamEntry + WireStruct>(
    piece: &[u8],
    tail_bound: u32,
) -> Result<StreamItem<'_, H>, FramingError> {
    let (header, tail) = H::ref_from_prefix(piece).map_err(|_| FramingError::BodyTooShort {
        needed: size_of::<H>(),
        found: piece.len(),
    })?;
    let declared = header.tail_len();
    if declared > tail_bound {
        return Err(FramingError::PieceTooLong {
            declared,
            remaining: u64::from(tail_bound),
        });
    }
    if declared as usize != tail.len() {
        return Err(FramingError::PayloadLengthMismatch {
            declared,
            found: tail.len(),
        });
    }
    Ok(StreamItem { header, tail })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_closing_piece_is_a_zero_length_a_status_and_the_flags() {
        assert_eq!(
            Closing::done(true).encode(),
            [0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0]
        );
        assert_eq!(
            Closing {
                status: -5,
                exhausted: false,
            }
            .encode(),
            [0, 0, 0, 0, 0xFB, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0]
        );
    }

    #[test]
    fn a_stream_takes_the_length_of_each_piece_its_bytes_and_the_closing_piece() {
        let mut stream = std::vec::Vec::new();
        for piece in [&b"first"[..], &b"second piece"[..]] {
            stream.extend_from_slice(&length(piece.len()).expect("it fits"));
            stream.extend_from_slice(piece);
        }
        stream.extend_from_slice(&Closing::done(false).encode());
        assert_eq!(stream.len(), stream_len(2, 17));
        assert_eq!(Closing::done(true).encode().len(), stream_len(0, 0));
    }

    #[test]
    fn a_closing_piece_is_read_by_the_status_predicate_and_its_reserved_bits() {
        let done = [0u8, 0, 0, 0, 1, 0, 0, 0];
        assert_eq!(ClosingBody::parse(&done), Ok(Closing::done(true)));
        let reserved = [0u8, 0, 0, 0, 3, 0, 0, 0];
        assert_eq!(
            ClosingBody::parse(&reserved),
            Err(FramingError::ReservedPieceFlags { flags: 3 })
        );
        let positive = [7u8, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(
            ClosingBody::parse(&positive),
            Err(FramingError::InvalidStatus { status: 7 })
        );
    }

    #[test]
    fn a_piece_longer_than_what_remains_is_refused() {
        assert_eq!(check(4, 4), Ok(()));
        assert_eq!(
            check(5, 4),
            Err(FramingError::PieceTooLong {
                declared: 5,
                remaining: 4,
            })
        );
        assert_eq!(length(9), Ok([9, 0, 0, 0]));
        assert_eq!(read_length(&[9, 0, 0, 0]), 9);
    }
}
