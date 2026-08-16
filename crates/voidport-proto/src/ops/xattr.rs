//! Extended attribute operations.
//!
//! `getxattr` and `listxattr` follow the Linux size-probe protocol: a request
//! with `size == 0` returns the byte size the answer needs and no payload, so
//! the caller can size its buffer and ask again.
//!
//! For `listxattr` that size is the **guest-visible** one — the length of the
//! kernel's NUL-separated name list, which is what the guest buffer must hold
//! and what `ERANGE` is decided against. It is not the length of the wire name
//! stream, where every name carries a 4-byte [`XattrNameHeader`] instead of a
//! terminating NUL. [`guest_list_size`] converts a walked stream to it.

use zerocopy::byteorder::little_endian::U32;

use crate::error::FramingError;
use crate::macros::{wire_body, wire_struct};
use crate::message::{Request, Response, split_region};
use crate::opcode::Opcode;
use crate::stream::{StreamEntry, StreamIter, StreamWriter};

/// Bit values for [`SetxattrRequest::flags`], matching the Linux `XATTR_*`
/// flags.
pub mod setxattr_flags {
    /// Fail with `EEXIST` if the attribute already exists.
    pub const CREATE: u32 = 1;
    /// Fail with `ENODATA` if the attribute does not exist.
    pub const REPLACE: u32 = 2;
}

wire_struct! {
    /// Set an extended attribute on the node named by the request head.
    ///
    /// The payload carries the attribute name followed by its value.
    pub struct SetxattrRequest {
        /// See [`setxattr_flags`].
        pub flags: U32,
        /// Length of the attribute name in the payload.
        pub name_len: U32,
        /// Length of the attribute value in the payload.
        pub value_len: U32,
        /// Reserved; zero.
        pub reserved: U32,
    }
}

wire_body!(request SetxattrRequest => Opcode::Setxattr, regions = [name_len, value_len]);

impl<'a> Request<'a, SetxattrRequest> {
    /// The attribute name.
    #[must_use]
    pub fn name(&self) -> &'a [u8] {
        split_region(self.payload(), self.body().name_len.get()).0
    }

    /// The attribute value; may be empty.
    #[must_use]
    pub fn value(&self) -> &'a [u8] {
        let rest = split_region(self.payload(), self.body().name_len.get()).1;
        split_region(rest, self.body().value_len.get()).0
    }
}

wire_struct! {
    /// Acknowledgement of a setxattr.
    pub struct SetxattrResponse;
}

wire_body!(response SetxattrResponse => Opcode::Setxattr);

wire_struct! {
    /// Read an extended attribute of the node named by the request head.
    ///
    /// The payload carries the attribute name.
    pub struct GetxattrRequest {
        /// Maximum number of value bytes to return; 0 probes for the size.
        pub size: U32,
        /// Length of the attribute name in the payload.
        pub name_len: U32,
    }
}

wire_body!(request GetxattrRequest => Opcode::Getxattr, regions = [name_len]);

impl<'a> Request<'a, GetxattrRequest> {
    /// The attribute name.
    #[must_use]
    pub fn name(&self) -> &'a [u8] {
        self.payload()
    }
}

wire_struct! {
    /// An extended attribute value, or its size.
    pub struct GetxattrResponse {
        /// Full size of the attribute value, whether or not it was returned.
        pub size: U32,
        /// Length of the value in the payload; 0 answers a size probe.
        pub value_len: U32,
    }
}

wire_body!(response GetxattrResponse => Opcode::Getxattr, regions = [value_len]);

impl<'a> Response<'a, GetxattrResponse> {
    /// The attribute value; empty for a size probe.
    #[must_use]
    pub fn value(&self) -> &'a [u8] {
        self.payload()
    }
}

wire_struct! {
    /// List the extended attribute names of the node named by the request head.
    pub struct ListxattrRequest {
        /// Capacity of the caller's buffer for the rebuilt NUL-separated name
        /// list, in guest bytes (see [`guest_list_size`]); 0 probes for the
        /// size. A list that does not fit is answered with `ERANGE`, so this
        /// budget is compared against the guest size and never against the
        /// wire payload length.
        pub size: U32,
        /// Reserved; zero.
        pub reserved: U32,
    }
}

wire_body!(request ListxattrRequest => Opcode::Listxattr);

wire_struct! {
    /// The attribute names, or the size of the name list.
    ///
    /// The payload is an [`XattrNameHeader`] stream, not the kernel's
    /// NUL-separated blob: no byte string on this wire is NUL-terminated, and a
    /// client rebuilds the kernel format from the walked names. The two length
    /// fields therefore measure different things and routinely disagree.
    pub struct ListxattrResponse {
        /// Full size of the rebuilt NUL-separated name list in guest bytes
        /// (see [`guest_list_size`]), whether or not the names were returned.
        /// This is the value a size probe reports to the guest.
        pub size: U32,
        /// Length of the name stream in the payload, in wire bytes; 0 answers a
        /// size probe.
        pub list_len: U32,
    }
}

wire_body!(response ListxattrResponse => Opcode::Listxattr, regions = [list_len]);

impl<'a> Response<'a, ListxattrResponse> {
    /// Walks the attribute names.
    #[must_use]
    pub fn names(&self) -> XattrNameIter<'a> {
        XattrNameIter::new(self.payload())
    }
}

wire_struct! {
    /// The fixed header of one entry in an attribute name stream; the name
    /// follows it.
    pub struct XattrNameHeader {
        /// Length of the name that follows this header.
        pub name_len: U32,
    }
}

impl XattrNameHeader {
    /// Builds a header for a name of `name_len` bytes.
    #[must_use]
    pub fn new(name_len: u32) -> Self {
        Self {
            name_len: U32::new(name_len),
        }
    }
}

impl StreamEntry for XattrNameHeader {
    fn tail_len(&self) -> u32 {
        self.name_len.get()
    }
}

/// Iterator over an attribute name stream.
pub type XattrNameIter<'a> = StreamIter<'a, XattrNameHeader>;

/// Builder for an attribute name stream.
pub type XattrNameWriter<'a> = StreamWriter<'a, XattrNameHeader>;

/// The size the names in a `listxattr` stream occupy once rebuilt into the
/// kernel's NUL-separated list: every name costs its length plus one
/// terminating NUL, where on this wire it costs its length plus a 4-byte
/// [`XattrNameHeader`].
///
/// This is the single definition of [`ListxattrRequest::size`] and
/// [`ListxattrResponse::size`]. A server sizes its answer and decides `ERANGE`
/// with this value, never with the payload length: a guest buffer that is
/// exactly large enough for the rebuilt list is smaller than the wire stream
/// whenever there is at least one name, and comparing against the wire length
/// would reject it.
///
/// # Errors
///
/// Returns the stream error of a malformed name stream, or
/// [`FramingError::LengthOverflow`] when the rebuilt list would not fit the
/// 32-bit length space.
pub fn guest_list_size(names: XattrNameIter<'_>) -> Result<u32, FramingError> {
    let mut total: u32 = 0;
    for item in names {
        let name_len = item?.header.name_len.get();
        total = total
            .checked_add(name_len)
            .and_then(|sum| sum.checked_add(1))
            .ok_or(FramingError::LengthOverflow)?;
    }
    Ok(total)
}

wire_struct! {
    /// Remove an extended attribute from the node named by the request head.
    ///
    /// The payload carries the attribute name.
    pub struct RemovexattrRequest {
        /// Length of the attribute name in the payload.
        pub name_len: U32,
    }
}

wire_body!(request RemovexattrRequest => Opcode::Removexattr, regions = [name_len]);

impl<'a> Request<'a, RemovexattrRequest> {
    /// The attribute name.
    #[must_use]
    pub fn name(&self) -> &'a [u8] {
        self.payload()
    }
}

wire_struct! {
    /// Acknowledgement of a removexattr.
    pub struct RemovexattrResponse;
}

wire_body!(response RemovexattrResponse => Opcode::Removexattr);

#[cfg(test)]
mod tests {
    use super::*;
    use zerocopy::IntoBytes;

    #[test]
    fn guest_list_size_counts_nuls_not_wire_headers() {
        let mut buf = [0u8; 64];
        let mut stream = XattrNameWriter::new(&mut buf);
        stream.push(&XattrNameHeader::new(8), b"user.foo").unwrap();
        stream
            .push(&XattrNameHeader::new(10), b"user.other")
            .unwrap();
        let list = stream.finish();

        // 8 + 10 names: 20 guest bytes (one NUL each), 26 wire bytes (a
        // 4-byte header each). A guest buffer of 20 is sufficient.
        assert_eq!(list.len(), 26);
        assert_eq!(guest_list_size(XattrNameIter::new(list)), Ok(20));
    }

    #[test]
    fn guest_list_size_of_an_empty_list_is_zero() {
        assert_eq!(guest_list_size(XattrNameIter::new(&[])), Ok(0));
    }

    #[test]
    fn guest_list_size_reports_a_malformed_stream() {
        // A name length that runs past the end of the stream.
        let mut list = [0u8; 9];
        list[..4].copy_from_slice(XattrNameHeader::new(9).as_bytes());
        list[4..].copy_from_slice(b"short");
        assert_eq!(
            guest_list_size(XattrNameIter::new(&list)),
            Err(FramingError::PayloadLengthMismatch {
                declared: 9,
                found: 5,
            })
        );
    }
}
