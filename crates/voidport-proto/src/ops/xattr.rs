//! `getxattr` and `listxattr` follow the Linux size-probe protocol: a request
//! with `size == 0` returns the size that the answer needs and no payload.
//!
//! For `listxattr` that size is the length of the NUL-separated name list of
//! the kernel, against which `ERANGE` is checked. The wire name stream has a
//! 4-byte [`XattrNameHeader`] in place of a terminating NUL for every name.
//! [`guest_list_size`] converts a walked stream to that size.

use zerocopy::byteorder::little_endian::U32;

use crate::error::FramingError;
use crate::macros::{wire_body, wire_struct};
use crate::message::{Request, Response, split_region};
use crate::opcode::Opcode;
use crate::stream::{StreamEntry, StreamIter, StreamWriter};

pub mod setxattr_flags {
    pub const CREATE: u32 = 1;
    pub const REPLACE: u32 = 2;
}

wire_struct! {
    pub struct SetxattrRequest {
        pub flags: U32,
        pub name_len: U32,
        pub value_len: U32,
        pub reserved: U32,
    }
}

wire_body!(
    request SetxattrRequest => Opcode::Setxattr,
    regions = [name_len: XattrName, value_len: XattrValue]
);

impl<'a> Request<'a, SetxattrRequest> {
    #[must_use]
    pub fn name(&self) -> &'a [u8] {
        split_region(self.payload(), self.body().name_len.get()).0
    }

    #[must_use]
    pub fn value(&self) -> &'a [u8] {
        let rest = split_region(self.payload(), self.body().name_len.get()).1;
        split_region(rest, self.body().value_len.get()).0
    }
}

wire_struct! {
    pub struct SetxattrResponse;
}

wire_body!(response SetxattrResponse => Opcode::Setxattr);

wire_struct! {
    pub struct GetxattrRequest {
        /// Maximum number of value bytes to return; 0 probes for the size.
        pub size: U32,
        pub name_len: U32,
    }
}

wire_body!(request GetxattrRequest => Opcode::Getxattr, regions = [name_len: XattrName]);

impl<'a> Request<'a, GetxattrRequest> {
    #[must_use]
    pub fn name(&self) -> &'a [u8] {
        self.payload()
    }
}

wire_struct! {
    pub struct GetxattrResponse {
        /// Full size of the attribute value, whether or not it was returned.
        pub size: U32,
        /// Length of the value in the payload; 0 in the reply to a size probe.
        pub value_len: U32,
    }
}

wire_body!(
    response GetxattrResponse => Opcode::Getxattr,
    regions = [value_len: XattrValue]
);

impl<'a> Response<'a, GetxattrResponse> {
    #[must_use]
    pub fn value(&self) -> &'a [u8] {
        self.payload()
    }
}

wire_struct! {
    pub struct ListxattrRequest {
        /// Capacity of the buffer for the rebuilt NUL-separated name list, in
        /// guest bytes (see [`guest_list_size`]); 0 probes for the size. A list
        /// that does not fit is answered with `ERANGE`, so this is compared
        /// against the guest size and never against the wire payload length.
        pub size: U32,
        pub reserved: U32,
    }
}

wire_body!(request ListxattrRequest => Opcode::Listxattr);

wire_struct! {
    /// The payload is an [`XattrNameHeader`] stream, and a client rebuilds the
    /// NUL-separated list from the walked names. The two length fields measure
    /// different things and routinely disagree.
    pub struct ListxattrResponse {
        /// Full size of the rebuilt NUL-separated name list in guest bytes
        /// (see [`guest_list_size`]), whether or not the names were returned.
        pub size: U32,
        pub list_len: U32,
    }
}

wire_body!(
    response ListxattrResponse => Opcode::Listxattr,
    regions = [list_len: XattrList]
);

impl<'a> Response<'a, ListxattrResponse> {
    #[must_use]
    pub fn names(&self) -> XattrNameIter<'a> {
        XattrNameIter::new(self.payload())
    }
}

wire_struct! {
    pub struct XattrNameHeader {
        pub name_len: U32,
    }
}

impl XattrNameHeader {
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

pub type XattrNameIter<'a> = StreamIter<'a, XattrNameHeader>;

pub type XattrNameWriter<'a> = StreamWriter<'a, XattrNameHeader>;

/// The size of the names of a `listxattr` stream once rebuilt into the
/// NUL-separated list: every name costs its length plus one NUL, where on this
/// wire it costs its length plus a 4-byte [`XattrNameHeader`].
///
/// A server sizes its reply with this value and returns `ERANGE` when the guest
/// buffer is smaller than it. The payload length does not work for this: a
/// guest buffer exactly large enough for the rebuilt list is smaller than the
/// wire stream, and comparing against the wire length would reject it.
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
    pub struct RemovexattrRequest {
        pub name_len: U32,
    }
}

wire_body!(
    request RemovexattrRequest => Opcode::Removexattr,
    regions = [name_len: XattrName]
);

impl<'a> Request<'a, RemovexattrRequest> {
    #[must_use]
    pub fn name(&self) -> &'a [u8] {
        self.payload()
    }
}

wire_struct! {
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

        assert_eq!(list.len(), 26);
        assert_eq!(guest_list_size(XattrNameIter::new(list)), Ok(20));
    }

    #[test]
    fn guest_list_size_of_an_empty_list_is_zero() {
        assert_eq!(guest_list_size(XattrNameIter::new(&[])), Ok(0));
    }

    #[test]
    fn guest_list_size_reports_a_malformed_stream() {
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
