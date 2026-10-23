//! ```text
//! frame    := [FrameHeader 12][body]
//! request  := [RequestHead 24][op struct][payload regions]
//! response := [ResponseHead 4][op struct][payload regions]   status == 0
//!           | [ResponseHead 4]                               status != 0
//! ```
//!
//! The header has no length field. A reader learns where a message ends from
//! its opcode, which sets a fixed body ([`table`]), from the status of a reply,
//! and from the length fields inside the body. A few messages are followed by
//! bytes outside the framed message: the data of a write request and the
//! streamed pieces ([`piece`]).
//!
//! # Example
//!
//! ```
//! use voidport_proto::frame::{Frame, FrameWriter};
//! use voidport_proto::limits::Limits;
//! use voidport_proto::message::RequestHead;
//! use voidport_proto::ops::node::LookupRequest;
//! use zerocopy::byteorder::little_endian::U32;
//!
//! // The bounds of the kernel, from the uapi bindings used by the build.
//! use linux_raw_sys::general as uapi;
//! let limits = Limits {
//!     name_max: uapi::NAME_MAX,
//!     path_max: uapi::PATH_MAX,
//!     xattr_name_max: uapi::XATTR_NAME_MAX,
//!     xattr_size_max: uapi::XATTR_SIZE_MAX,
//!     xattr_list_max: uapi::XATTR_LIST_MAX,
//! };
//! let name = b"project";
//! let body = LookupRequest {
//!     name_len: U32::new(name.len() as u32),
//! };
//!
//! let head = RequestHead::new(1, 1000, 1000, 42);
//! let mut buf = [0u8; 64];
//! let mut writer = FrameWriter::request(&mut buf, &limits, 7, &head, &body)?;
//! writer.payload(name)?;
//! let bytes = writer.finish()?;
//!
//! let frame = Frame::parse(bytes, &limits)?;
//! let request = frame.request::<LookupRequest>()?;
//! assert_eq!(request.head().node_id.get(), 1);
//! assert_eq!(request.name(), name);
//! # Ok::<(), voidport_proto::error::FramingError>(())
//! ```

#![forbid(unsafe_code)]
#![no_std]

#[cfg(test)]
extern crate std;

pub mod attr;
pub mod chain;
pub mod error;
pub mod frame;
pub mod limits;
mod macros;
pub mod message;
pub mod opcode;
pub mod ops;
pub mod piece;
pub mod stream;
pub mod table;

/// A server accepts exactly this version in the handshake. Any change to an
/// opcode, a struct layout or the meaning of a field requires a bump.
pub const PROTOCOL_VERSION: u32 = 4;
