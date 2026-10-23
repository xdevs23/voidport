//! A descriptor chain contains one message and the room for its reply.
//!
//! ```text
//! readable := [ChainHead 16][frame][data of a write]
//! writable := [reply area: reply_len bytes][data area]
//! ```
//!
//! A chain belongs to a channel, a number the driver chooses. A channel is one
//! connection of a session. A `Hello` on a channel that is not open opens it,
//! and a chain made available before the reply to that `Hello` finds the
//! channel not open. The chains of one channel are handled at the same time
//! and finish in any order, so a driver that needs two requests ordered makes
//! the second available once the first has finished.
//!
//! The bytes of the data pieces of a read reply go to the data area, one piece
//! after the other, and only the length in front of each piece remains in the
//! reply area. A `forget` has no reply, and nothing is written for it. Share
//! notifications have no chain to travel in, so a `Subscribe` fails with
//! `EOPNOTSUPP`.
//!
//! A close chain ends the channel given in its head, and a reset chain ends
//! every channel of the device. A driver that has just taken over the device
//! sends a reset first. Nothing is written for either.
//!
//! The length reported for a finished chain is the number of bytes written into
//! both areas. Nothing is written for a chain on a channel that is not open,
//! for a chain that cannot be read or replied to whole, or for a chain with a
//! malformed frame. The last two end the channel, so a request that finishes
//! with nothing written shows the driver that its channel is closed.

use zerocopy::IntoBytes as _;
use zerocopy::byteorder::little_endian::{U32, U64};

use crate::error::FramingError;
use crate::macros::wire_struct;

pub const CHAIN_HEAD_LEN: usize = size_of::<ChainHead>();

#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ChannelNumber(pub u64);

#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ChainId(pub u64);

mod chain_kinds {
    pub(super) const FRAME: u32 = 0;
    pub(super) const CLOSE: u32 = 1;
    pub(super) const RESET: u32 = 2;
}

wire_struct! {
    pub struct ChainHead {
        /// A reset belongs to no channel and has zero here.
        pub channel: U64,
        pub kind: U32,
        pub reply_len: U32,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChainKind {
    Frame,
    Close,
    Reset,
}

impl ChainHead {
    #[must_use]
    pub fn new(channel: ChannelNumber, kind: ChainKind, reply_len: u32) -> Self {
        let kind = match kind {
            ChainKind::Frame => chain_kinds::FRAME,
            ChainKind::Close => chain_kinds::CLOSE,
            ChainKind::Reset => chain_kinds::RESET,
        };
        Self {
            channel: U64::new(channel.0),
            kind: U32::new(kind),
            reply_len: U32::new(reply_len),
        }
    }

    #[must_use]
    pub fn channel(&self) -> ChannelNumber {
        ChannelNumber(self.channel.get())
    }

    #[must_use]
    pub fn encode(&self) -> [u8; CHAIN_HEAD_LEN] {
        let mut bytes = [0u8; CHAIN_HEAD_LEN];
        bytes.copy_from_slice(self.as_bytes());
        bytes
    }

    pub fn kind(&self) -> Result<ChainKind, FramingError> {
        let kind = match self.kind.get() {
            chain_kinds::FRAME => ChainKind::Frame,
            chain_kinds::CLOSE => ChainKind::Close,
            chain_kinds::RESET => ChainKind::Reset,
            kind => return Err(FramingError::UnknownChainKind { kind }),
        };
        if kind == ChainKind::Reset && self.channel.get() != 0 {
            return Err(FramingError::ReservedFieldNonZero);
        }
        Ok(kind)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::offset_of;
    use zerocopy::FromBytes as _;

    const GOLDEN: [u8; CHAIN_HEAD_LEN] = [
        0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00,
        0x00,
    ];

    #[test]
    fn the_chain_head_is_laid_out_as_the_golden_bytes() {
        assert_eq!(offset_of!(ChainHead, channel), 0);
        assert_eq!(offset_of!(ChainHead, kind), 8);
        assert_eq!(offset_of!(ChainHead, reply_len), 12);
        let head = ChainHead::new(ChannelNumber(0x0102_0304_0506_0708), ChainKind::Close, 0x40);
        assert_eq!(head.encode(), GOLDEN);
        assert_eq!(ChainHead::read_from_bytes(&GOLDEN), Ok(head));
    }

    #[test]
    fn a_kind_is_read_back_and_an_unknown_one_or_a_reset_on_a_channel_is_refused() {
        for kind in [ChainKind::Frame, ChainKind::Close, ChainKind::Reset] {
            assert_eq!(ChainHead::new(ChannelNumber(0), kind, 0).kind(), Ok(kind));
        }
        let mut unknown = ChainHead::new(ChannelNumber(7), ChainKind::Frame, 0);
        unknown.kind = U32::new(3);
        assert_eq!(
            unknown.kind(),
            Err(FramingError::UnknownChainKind { kind: 3 })
        );
        assert_eq!(
            ChainHead::new(ChannelNumber(7), ChainKind::Reset, 0).kind(),
            Err(FramingError::ReservedFieldNonZero)
        );
    }
}
