use zerocopy::byteorder::little_endian::{I32, U32, U64};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::error::FramingError;
use crate::limits::Regions;
use crate::macros::wire_struct;
use crate::opcode::{NotificationOpcode, Opcode};
use crate::piece::Stream;

pub const REQUEST_HEAD_LEN: usize = 24;

pub const RESPONSE_HEAD_LEN: usize = 4;

pub trait WireStruct: FromBytes + IntoBytes + KnownLayout + Immutable + Unaligned {}

impl<T> WireStruct for T where T: FromBytes + IntoBytes + KnownLayout + Immutable + Unaligned {}

wire_struct! {
    /// Every request carries the caller identity, since one mount is used by
    /// many guest processes.
    pub struct RequestHead {
        /// Session-scoped node id the operation targets; 0 where meaningless.
        pub node_id: U64,
        pub uid: U32,
        pub gid: U32,
        /// Guest caller pid; informational only.
        pub pid: U32,
        pub reserved: U32,
    }
}

impl RequestHead {
    #[must_use]
    pub fn new(node_id: u64, uid: u32, gid: u32, pid: u32) -> Self {
        Self {
            node_id: U64::new(node_id),
            uid: U32::new(uid),
            gid: U32::new(gid),
            pid: U32::new(pid),
            reserved: U32::ZERO,
        }
    }
}

/// `MAX_ERRNO` of `include/linux/err.h`: a negated errno lies in
/// `-MAX_ERRNO..=-1`.
pub const MAX_ERRNO: i32 = 4095;

#[must_use]
/// Success, a positive value and a negative value beyond [`MAX_ERRNO`] are not
/// error statuses, so a caller never gets a number that is not an errno.
pub fn is_error_status(status: i32) -> bool {
    (-MAX_ERRNO..0).contains(&status)
}

wire_struct! {
    pub struct ResponseHead {
        /// Nothing follows a nonzero status.
        pub status: I32,
    }
}

impl ResponseHead {
    pub const SUCCESS: Self = Self { status: I32::ZERO };

    #[must_use]
    pub fn new(status: i32) -> Self {
        Self {
            status: I32::new(status),
        }
    }

    #[must_use]
    pub fn is_success(&self) -> bool {
        self.status.get() == 0
    }
}

pub trait WireValidate {
    fn validate(&self) -> Result<(), FramingError> {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Follows {
    Nothing,
    Data(u32),
    Pieces(Stream),
}

pub trait WirePayload: WireStruct + WireValidate {
    fn validate_encode(&self) -> Result<(), FramingError> {
        self.validate()
    }

    fn regions(&self) -> Regions {
        Regions::NONE
    }

    fn payload_len(&self) -> Result<u32, FramingError> {
        self.regions().total()
    }

    fn follows(&self) -> Follows {
        Follows::Nothing
    }
}

pub trait WireMessage: WirePayload {
    const OPCODE: Opcode;
}

pub trait RequestBody: WireMessage {}

pub trait ResponseBody: WireMessage {}

pub trait NotificationBody: WirePayload {
    const OPCODE: NotificationOpcode;
}

/// Strict framing guarantees that the payload is long enough. If a region list
/// and its accessors drift apart, the short remainder shows the mismatch
/// instead of turning real bytes into empty data.
pub(crate) fn split_region(payload: &[u8], len: u32) -> (&[u8], &[u8]) {
    let len = len as usize;
    match payload.get(len..) {
        Some(tail) => (&payload[..len], tail),
        None => (payload, &[]),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Request<'a, M: RequestBody> {
    head: &'a RequestHead,
    body: &'a M,
    payload: &'a [u8],
}

impl<'a, M: RequestBody> Request<'a, M> {
    pub(crate) fn new(head: &'a RequestHead, body: &'a M, payload: &'a [u8]) -> Self {
        Self {
            head,
            body,
            payload,
        }
    }

    #[must_use]
    pub fn head(&self) -> &'a RequestHead {
        self.head
    }

    #[must_use]
    pub fn body(&self) -> &'a M {
        self.body
    }

    #[must_use]
    pub fn payload(&self) -> &'a [u8] {
        self.payload
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Response<'a, M: ResponseBody> {
    body: &'a M,
    payload: &'a [u8],
}

impl<'a, M: ResponseBody> Response<'a, M> {
    pub(crate) fn new(body: &'a M, payload: &'a [u8]) -> Self {
        Self { body, payload }
    }

    #[must_use]
    pub fn body(&self) -> &'a M {
        self.body
    }

    #[must_use]
    pub fn payload(&self) -> &'a [u8] {
        self.payload
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Notification<'a, M: NotificationBody> {
    body: &'a M,
    payload: &'a [u8],
}

impl<'a, M: NotificationBody> Notification<'a, M> {
    pub(crate) fn new(body: &'a M, payload: &'a [u8]) -> Self {
        Self { body, payload }
    }

    #[must_use]
    pub fn body(&self) -> &'a M {
        self.body
    }

    #[must_use]
    pub fn payload(&self) -> &'a [u8] {
        self.payload
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResponseOutcome<'a, M: ResponseBody> {
    Success(Response<'a, M>),
    Error(i32),
}

impl<'a, M: ResponseBody> ResponseOutcome<'a, M> {
    #[must_use]
    pub fn success(self) -> Option<Response<'a, M>> {
        match self {
            Self::Success(response) => Some(response),
            Self::Error(_) => None,
        }
    }

    #[must_use]
    pub fn error(self) -> Option<i32> {
        match self {
            Self::Success(_) => None,
            Self::Error(status) => Some(status),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{align_of, offset_of, size_of};

    #[test]
    fn head_layouts() {
        assert_eq!(size_of::<RequestHead>(), REQUEST_HEAD_LEN);
        assert_eq!(align_of::<RequestHead>(), 1);
        assert_eq!(offset_of!(RequestHead, node_id), 0);
        assert_eq!(offset_of!(RequestHead, uid), 8);
        assert_eq!(offset_of!(RequestHead, gid), 12);
        assert_eq!(offset_of!(RequestHead, pid), 16);
        assert_eq!(offset_of!(RequestHead, reserved), 20);

        assert_eq!(size_of::<ResponseHead>(), RESPONSE_HEAD_LEN);
        assert_eq!(align_of::<ResponseHead>(), 1);
        assert_eq!(offset_of!(ResponseHead, status), 0);
    }

    #[test]
    fn only_negated_errnos_are_error_statuses() {
        assert!(is_error_status(-1));
        assert!(is_error_status(-MAX_ERRNO));
        assert!(!is_error_status(0));
        assert!(!is_error_status(1));
        assert!(!is_error_status(-MAX_ERRNO - 1));
        assert!(!is_error_status(i32::MIN));
    }

    #[test]
    fn short_region_splits_keep_the_mismatch_visible() {
        assert_eq!(split_region(&[1, 2, 3], 9), (&[1, 2, 3][..], &[][..]));
        assert_eq!(split_region(&[1, 2, 3], 2), (&[1, 2][..], &[3][..]));
    }
}
