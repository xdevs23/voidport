//! The share subscription: the two request ops that open and close the stream.
//!
//! `Subscribe` is idempotent by contract — on an already-subscribed session it
//! is the consumer's **resync**, answering a fresh snapshot on the same
//! stream — and `Unsubscribe` on a session that has no subscription is a plain
//! success. That is what puts both on the reconnect contract's idempotent
//! replay list: re-issuing either across a gap is harmless by construction.
//!
//! Both bodies are deliberately empty but for a reserved word: the subscription
//! has no parameters, because what a session may see is already fixed by the
//! namespace and subpath it handshook with. The reserved field is the space a
//! later filter would take, and it is validated zero in both directions.

use zerocopy::byteorder::little_endian::U32;

use crate::macros::{wire_body, wire_struct};
use crate::opcode::Opcode;

wire_struct! {
    /// Request: start or restart the session's share subscription.
    pub struct SubscribeRequest {
        /// Reserved; must be zero.
        pub reserved: U32,
    }
}

wire_body!(request SubscribeRequest => Opcode::Subscribe);

wire_struct! {
    /// Response: the subscription is on. Every snapshot part follows this
    /// frame, never precedes it.
    pub struct SubscribeResponse {
        /// Reserved; must be zero.
        pub reserved: U32,
    }
}

wire_body!(response SubscribeResponse => Opcode::Subscribe);

wire_struct! {
    /// Request: end the session's share subscription.
    pub struct UnsubscribeRequest {
        /// Reserved; must be zero.
        pub reserved: U32,
    }
}

wire_body!(request UnsubscribeRequest => Opcode::Unsubscribe);

wire_struct! {
    /// Response: the session has no subscription — whether or not it had one.
    pub struct UnsubscribeResponse {
        /// Reserved; must be zero.
        pub reserved: U32,
    }
}

wire_body!(response UnsubscribeResponse => Opcode::Unsubscribe);
