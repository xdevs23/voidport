use zerocopy::byteorder::little_endian::U32;

use crate::macros::{wire_body, wire_struct};
use crate::opcode::Opcode;

wire_struct! {
    /// On a session that already has a subscription, a `Subscribe` starts it
    /// again and returns a fresh snapshot on the same stream. An `Unsubscribe`
    /// on a session without a subscription succeeds. Both are therefore safe
    /// to send again after a reconnect.
    pub struct SubscribeRequest {
        pub reserved: U32,
    }
}

wire_body!(request SubscribeRequest => Opcode::Subscribe);

wire_struct! {
    /// Every snapshot part follows this frame.
    pub struct SubscribeResponse {
        pub reserved: U32,
    }
}

wire_body!(response SubscribeResponse => Opcode::Subscribe);

wire_struct! {
    pub struct UnsubscribeRequest {
        pub reserved: U32,
    }
}

wire_body!(request UnsubscribeRequest => Opcode::Unsubscribe);

wire_struct! {
    pub struct UnsubscribeResponse {
        pub reserved: U32,
    }
}

wire_body!(response UnsubscribeResponse => Opcode::Unsubscribe);
