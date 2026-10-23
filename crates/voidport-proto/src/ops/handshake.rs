//! `Hello` must be the first frame on a connection, and a connection accepts
//! exactly one of them. A second `Hello`, or any other frame before the
//! handshake completes, is a framing error.
//!
//! The first `Hello` of a session opens it, and its reply contains the session
//! token that every connection of the session shares. A `Hello` with the
//! [`hello_flags::JOIN`] flag joins the session given by its token instead.
//! Every reply has the id of the connection it belongs to, an id the session
//! never gives to another connection.
//!
//! The server checks the variable parts of a `Hello` by their declared lengths
//! before it reads them, so the parser puts no bound on the namespace name, the
//! authentication blob and the token
//! ([`Part::Handshake`](crate::limits::Part::Handshake)).
//!
//! A session token is at most [`TOKEN_LEN_MAX`] bytes long, so a client can
//! size the room for the reply to a `Hello` before it sends it.

use zerocopy::byteorder::little_endian::{U32, U64};

use crate::macros::{wire_body, wire_struct};
use crate::message::{Request, Response, WireValidate, split_region};
use crate::opcode::Opcode;

/// The most bytes a session token has. A server whose tokens could be longer
/// does not start.
pub const TOKEN_LEN_MAX: usize = 1024;

pub mod hello_flags {
    pub const JOIN: u32 = 1 << 0;
    pub const ASSIGNED: u32 = JOIN;
}

wire_struct! {
    /// The token is not the auth blob: it identifies the session that a joining
    /// connection belongs to.
    #[doc(alias = "Hello")]
    pub struct HelloRequest {
        pub protocol_version: U32,
        /// A bit that this version does not assign must be zero on send, and
        /// is ignored on receive.
        pub flags: U32,
        pub namespace_len: U32,
        pub subpath_len: U32,
        pub auth_len: U32,
        /// Length of the session token in the payload: zero for a hello that
        /// opens a session, the whole token for one that joins.
        pub token_len: U32,
    }
}

impl HelloRequest {
    /// Builds the handshake that opens a session. Together with [`Self::join`],
    /// the one place a client states which protocol it speaks.
    #[must_use]
    pub fn new(namespace_len: u32, subpath_len: u32) -> Self {
        Self {
            protocol_version: U32::new(crate::PROTOCOL_VERSION),
            flags: U32::ZERO,
            namespace_len: U32::new(namespace_len),
            subpath_len: U32::new(subpath_len),
            auth_len: U32::ZERO,
            token_len: U32::ZERO,
        }
    }

    #[must_use]
    pub fn join(token_len: u32) -> Self {
        Self {
            flags: U32::new(hello_flags::JOIN),
            token_len: U32::new(token_len),
            ..Self::new(0, 0)
        }
    }

    #[must_use]
    pub fn joins(&self) -> bool {
        self.flags.get() & hello_flags::JOIN != 0
    }
}

wire_body!(
    request HelloRequest => Opcode::Hello,
    encode_validate = |message: &HelloRequest| {
        if message.flags.get() & !hello_flags::ASSIGNED != 0 {
            return Err(crate::error::FramingError::NegotiationFlagsNonZero {
                flags: message.flags.get(),
            });
        }
        Ok(())
    },
    regions = [
        namespace_len: Handshake,
        subpath_len: Path,
        auth_len: Handshake,
        token_len: Handshake,
    ]
);

impl<'a> Request<'a, HelloRequest> {
    #[must_use]
    pub fn namespace(&self) -> &'a [u8] {
        self.hello_fields().0
    }

    #[must_use]
    pub fn subpath(&self) -> &'a [u8] {
        self.hello_fields().1
    }

    #[must_use]
    pub fn auth(&self) -> &'a [u8] {
        self.hello_fields().2
    }

    #[must_use]
    pub fn token(&self) -> &'a [u8] {
        self.hello_fields().3
    }

    fn hello_fields(&self) -> (&'a [u8], &'a [u8], &'a [u8], &'a [u8]) {
        let body = self.body();
        let (namespace, rest) = split_region(self.payload(), body.namespace_len.get());
        let (subpath, rest) = split_region(rest, body.subpath_len.get());
        let (auth, rest) = split_region(rest, body.auth_len.get());
        let (token, _) = split_region(rest, body.token_len.get());
        (namespace, subpath, auth, token)
    }
}

wire_struct! {
    pub struct HelloReply {
        /// Every session has a root node id of its own, so one server can
        /// present many roots.
        pub root_node_id: U64,
        pub protocol_version: U32,
        /// Must be zero on send, and unknown bits are ignored on receive.
        pub flags: U32,
        pub connection_id: U64,
        pub token_len: U32,
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
    },
    regions = [token_len: Handshake]
);

impl<'a> Response<'a, HelloReply> {
    #[must_use]
    pub fn token(&self) -> &'a [u8] {
        split_region(self.payload(), self.body().token_len.get()).0
    }
}
