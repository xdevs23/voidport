//! The server sends `Recall` before another writer goes ahead of a file whose
//! pages a guest may cache after its handles close. The guest drops the pages
//! and replies with `Recalled`. A recall without a reply is sent again on the
//! connection of a later subscription, and a second `Recalled` of one recall
//! gets the same reply.
//!
//! The pages that a guest caches are valid only within the window granted by
//! `Renew`. `Relinquish` gives every lease of the session up at once, without a
//! recall.

use zerocopy::byteorder::little_endian::{U32, U64};

use crate::macros::{wire_body, wire_struct};
use crate::opcode::{NotificationOpcode, Opcode};

wire_struct! {
    pub struct Recall {
        pub node_id: U64,
        pub recall: U64,
    }
}

wire_body!(notification Recall => NotificationOpcode::Recall);

wire_struct! {
    pub struct RecalledRequest {
        pub recall: U64,
    }
}

wire_body!(request RecalledRequest => Opcode::Recalled);

wire_struct! {
    pub struct RecalledResponse {
        pub reserved: U32,
    }
}

wire_body!(response RecalledResponse => Opcode::Recalled);

wire_struct! {
    pub struct RenewRequest {
        pub reserved: U32,
    }
}

wire_body!(request RenewRequest => Opcode::Renew);

wire_struct! {
    /// Response: the window, counted from the moment the guest sent the
    /// request, and the period after that moment at which it renews again. A
    /// zero window grants none, and the guest caches no page under a lease.
    pub struct RenewResponse {
        pub window_ns: U64,
        pub period_ns: U64,
    }
}

wire_body!(response RenewResponse => Opcode::Renew);

wire_struct! {
    pub struct RelinquishRequest {
        pub reserved: U32,
    }
}

wire_body!(request RelinquishRequest => Opcode::Relinquish);

wire_struct! {
    pub struct RelinquishResponse {
        pub reserved: U32,
    }
}

wire_body!(response RelinquishResponse => Opcode::Relinquish);
