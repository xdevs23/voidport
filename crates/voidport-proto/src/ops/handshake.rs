//! Session handshake.
//!
//! `Hello` must be the first frame on a connection and a session accepts
//! exactly one of them; a second `Hello`, or any other frame before the
//! handshake completes, is a framing error that closes the connection.
//!
//! Pre-handshake the server accepts a `Hello` of at most
//! [`MAX_HELLO_FRAME_LEN`](crate::frame::MAX_HELLO_FRAME_LEN) bytes. From
//! `HelloReply` on, [`HelloReply::max_frame_len`] bounds the total frame
//! length — header included — in both directions.

use zerocopy::byteorder::little_endian::{U32, U64};

use crate::macros::{wire_body, wire_struct};
use crate::message::{Request, WireValidate, split_region};
use crate::opcode::Opcode;

wire_struct! {
    /// Handshake request: `Hello`.
    ///
    /// The payload carries the namespace name, the mount subpath and the auth
    /// blob, in that order. Under `auth.mode: none` — the only v1 mode — a
    /// nonempty auth blob is a handshake error (`EINVAL`), answered as a response
    /// before the server closes.
    #[doc(alias = "Hello")]
    pub struct HelloRequest {
        /// Protocol version the client speaks. v1 servers accept exactly
        /// [`PROTOCOL_VERSION`](crate::PROTOCOL_VERSION); anything else is a
        /// handshake error response followed by a close.
        pub protocol_version: U32,
        /// Client feature flags. Must be zero on send; unknown bits are ignored on
        /// receive, which is the negotiation space for later versions.
        pub flags: U32,
        /// Length of the namespace name in the payload.
        pub namespace_len: U32,
        /// Length of the mount subpath in the payload.
        pub subpath_len: U32,
        /// Length of the auth blob in the payload.
        pub auth_len: U32,
    }
}

impl HelloRequest {
    /// Builds the handshake a client sends: this crate's protocol version, no
    /// feature flags, no auth blob, and the two payload regions the caller is
    /// about to write.
    ///
    /// The one place a client states which protocol it speaks, so no client
    /// states it a second time.
    #[must_use]
    pub fn new(namespace_len: u32, subpath_len: u32) -> Self {
        Self {
            protocol_version: U32::new(crate::PROTOCOL_VERSION),
            flags: U32::ZERO,
            namespace_len: U32::new(namespace_len),
            subpath_len: U32::new(subpath_len),
            auth_len: U32::ZERO,
        }
    }
}

wire_body!(
    request HelloRequest => Opcode::Hello,
    encode_validate = |message: &HelloRequest| {
        if message.flags.get() != 0 {
            return Err(crate::error::FramingError::NegotiationFlagsNonZero {
                flags: message.flags.get(),
            });
        }
        Ok(())
    },
    regions = [namespace_len, subpath_len, auth_len]
);

impl<'a> Request<'a, HelloRequest> {
    /// The namespace name.
    #[must_use]
    pub fn namespace(&self) -> &'a [u8] {
        self.hello_fields().0
    }

    /// The subpath within the namespace to mount. The server resolves it
    /// through the rule table like any other lookup.
    #[must_use]
    pub fn subpath(&self) -> &'a [u8] {
        self.hello_fields().1
    }

    /// The auth blob; empty under `auth.mode: none`.
    #[must_use]
    pub fn auth(&self) -> &'a [u8] {
        self.hello_fields().2
    }

    fn hello_fields(&self) -> (&'a [u8], &'a [u8], &'a [u8]) {
        let body = self.body();
        let (namespace, rest) = split_region(self.payload(), body.namespace_len.get());
        let (subpath, rest) = split_region(rest, body.subpath_len.get());
        let (auth, _) = split_region(rest, body.auth_len.get());
        (namespace, subpath, auth)
    }
}

wire_struct! {
    /// Handshake response: `HelloReply`.
    ///
    /// The status lives in the response head; this struct follows only on
    /// success.
    pub struct HelloReply {
        /// Node id of the session's mount root. Every session's root is its own
        /// node id, which is what lets one server serve many roots.
        pub root_node_id: U64,
        /// Protocol version the server accepted.
        pub protocol_version: U32,
        /// Server feature flags. Must be zero on send; unknown bits are ignored on
        /// receive.
        pub flags: U32,
        /// Maximum total frame length, header included, accepted in either
        /// direction for the rest of the session.
        pub max_frame_len: U32,
        /// Reserved; zero.
        pub reserved: U32,
    }
}

wire_body!(
    response HelloReply => Opcode::Hello,
    encode_validate = |message: &HelloReply| {
        message.validate()?;
        if message.flags.get() != 0 {
            return Err(crate::error::FramingError::NegotiationFlagsNonZero {
                flags: message.flags.get(),
            });
        }
        Ok(())
    }
);
