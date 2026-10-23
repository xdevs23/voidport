//! A request in flight on a lost connection is settled on another connection
//! of the same session. `Outcome` asks what became of it, and `Retire` ends
//! what the server kept for the lost connection. Either can be sent again after
//! its reply is lost.
//!
//! The pieces after an `Outcome` answer are the reply the server kept for the
//! request, exactly as it appeared on the lost connection. An answer without a
//! kept reply is followed by the closing piece alone.
//!
//! `Cancel` ends a request of the same connection that waits in the server.
//! That request gets `-EINTR` and was not applied. A request that does not wait
//! gets its normal reply.

use zerocopy::byteorder::little_endian::{U32, U64};

use crate::macros::{wire_body, wire_struct};
use crate::opcode::Opcode;

pub mod outcome_state {
    /// The request never started and never will. The client sends it again.
    pub const NOT_STARTED: u32 = 0;
    /// The request was applied and has no reply: a forget.
    pub const APPLIED: u32 = 1;
    pub const REPLIED: u32 = 2;
}

wire_struct! {
    /// The server replies only once that connection is closed and every
    /// request read from it has ended, closing it first if it is still open,
    /// so an answer of "not started" remains true.
    pub struct OutcomeRequest {
        pub connection_id: U64,
        pub request_id: U64,
    }
}

wire_body!(request OutcomeRequest => Opcode::Outcome);

wire_struct! {
    pub struct OutcomeResponse {
        pub state: U32,
        pub reserved: U32,
    }
}

wire_body!(response OutcomeResponse => Opcode::Outcome, pieces = Data);

wire_struct! {
    /// The server closes that connection first if it is still open, lets every
    /// request read from it end, and drops everything it kept for it.
    pub struct RetireRequest {
        pub connection_id: U64,
    }
}

wire_body!(request RetireRequest => Opcode::Retire);

wire_struct! {
    pub struct RetireResponse {
        pub reserved: U32,
    }
}

wire_body!(response RetireResponse => Opcode::Retire);

wire_struct! {
    /// No response: the effect shows in the reply to the request it ends.
    pub struct CancelRequest {
        pub request_id: U64,
    }
}

wire_body!(request CancelRequest => Opcode::Cancel);
