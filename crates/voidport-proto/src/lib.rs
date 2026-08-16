//! Wire protocol for voidport.
//!
//! Shared by the server (`voidportd`), the FUSE client (`voidport`), and — by
//! design — a future in-kernel client: every message is a little-endian,
//! fixed-layout struct (via `zerocopy`) followed by an optional raw payload,
//! so the protocol stays consumable without a userspace serialization stack.
//!
//! See `docs/DESIGN.md` ("Wire protocol") for the framing and session model.
//!
//! # Shape of the protocol
//!
//! ```text
//! frame    := [FrameHeader 16][body]
//! request  := [RequestHead 24][op struct][payload regions]
//! response := [ResponseHead 4][op struct][payload regions]   status == 0
//!           | [ResponseHead 4]                               status != 0
//! ```
//!
//! * [`frame`] carries the header, the request/response/notification taxonomy
//!   and strict parse/encode over caller-provided buffers.
//! * [`opcode`] is the opcode registry: assigned numeric constants and a
//!   fallible known/unknown classification.
//! * [`message`] holds the two fixed heads, the message traits, and the parsed
//!   views handed back by [`frame::Frame::request`] and
//!   [`frame::Frame::response`].
//! * [`ops`] holds every operation's request and response body.
//! * [`attr`] holds attributes and entry replies; [`stream`] walks and builds
//!   the readdirplus and listxattr entry streams.
//!
//! # Discipline
//!
//! The crate is `#![no_std]`, allocation-free, and free of hand-written
//! integer encoding: every multi-byte field is a `zerocopy` little-endian
//! byteorder type, which makes every wire struct alignment-1 and therefore
//! viewable at any offset of a byte buffer. Parsing borrows from the caller's
//! buffer and never panics on arbitrary input — malformed frames come back as
//! [`error::FramingError`].
//!
//! # ABI stability
//!
//! Any change to an opcode assignment, a struct layout, or a field's meaning
//! requires a [`PROTOCOL_VERSION`] bump. The golden byte-vector tests pin the
//! encoding of every message type, so such a change cannot land quietly.
//!
//! # Example
//!
//! ```
//! use voidport_proto::frame::{Frame, FrameWriter, MAX_HELLO_FRAME_LEN};
//! use voidport_proto::message::RequestHead;
//! use voidport_proto::ops::node::LookupRequest;
//! use zerocopy::byteorder::little_endian::U32;
//!
//! let name = b"project";
//! let body = LookupRequest {
//!     name_len: U32::new(name.len() as u32),
//! };
//!
//! let head = RequestHead::new(1, 1000, 1000, 42);
//! let mut buf = [0u8; 64];
//! let mut writer = FrameWriter::request(&mut buf, MAX_HELLO_FRAME_LEN, 7, &head, &body)?;
//! writer.payload(name)?;
//! let bytes = writer.finish()?;
//!
//! let frame = Frame::parse(bytes, MAX_HELLO_FRAME_LEN)?;
//! let request = frame.request::<LookupRequest>()?;
//! assert_eq!(request.head().node_id.get(), 1);
//! assert_eq!(request.name(), name);
//! # Ok::<(), voidport_proto::error::FramingError>(())
//! ```

#![no_std]
#![deny(missing_docs)]

#[cfg(test)]
extern crate std;

pub mod attr;
pub mod error;
pub mod frame;
mod macros;
pub mod message;
pub mod opcode;
pub mod ops;
pub mod stream;

/// Protocol version negotiated in the session handshake.
///
/// A v1 server accepts exactly this version; anything else is a handshake
/// error response followed by a close.
pub const PROTOCOL_VERSION: u32 = 1;
