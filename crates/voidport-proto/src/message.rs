//! Message heads, the wire-message traits, and parsed message views.
//!
//! A frame body is laid out as:
//!
//! ```text
//! request:      [RequestHead 24][op-specific struct][payload regions]
//! response:     [ResponseHead 4][op-specific struct][payload regions]   (status == 0)
//! response:     [ResponseHead 4]                                        (status != 0)
//! notification: [op-specific struct][payload regions]
//! ```
//!
//! A notification has **no head at all**: it answers nothing, so it carries no
//! status, and it is server-initiated, so it carries no caller identity.
//!
//! The op-specific struct declares the length of every payload region it
//! carries; strict framing requires those declared lengths to account for the
//! trailing payload exactly.

use zerocopy::byteorder::little_endian::{I32, U32, U64};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::error::FramingError;
use crate::macros::wire_struct;
use crate::opcode::{NotificationOpcode, Opcode};

/// Byte length of [`RequestHead`].
pub const REQUEST_HEAD_LEN: usize = 24;

/// Byte length of [`ResponseHead`].
pub const RESPONSE_HEAD_LEN: usize = 4;

/// A fixed-layout, alignment-1, little-endian wire struct.
///
/// Every wire type in this crate satisfies this blanket bound, which is what
/// lets any of them be viewed at an arbitrary offset of a byte buffer without
/// copying or realignment.
pub trait WireStruct: FromBytes + IntoBytes + KnownLayout + Immutable + Unaligned {}

impl<T> WireStruct for T where T: FromBytes + IntoBytes + KnownLayout + Immutable + Unaligned {}

wire_struct! {
    /// The fixed 24-byte head at the start of every request body.
    ///
    /// Caller identity rides on every request, not on the handshake: one
    /// mount serves many guest processes, and both ownership mapping and
    /// server-side permission enforcement key on the identity of the process that
    /// issued the operation.
    pub struct RequestHead {
        /// Session-scoped node id the operation targets; 0 where meaningless.
        pub node_id: U64,
        /// Guest caller uid.
        pub uid: U32,
        /// Guest caller gid.
        pub gid: U32,
        /// Guest caller pid; informational only.
        pub pid: U32,
        /// Reserved. Must be zero; a receiver rejects a nonzero value as a
        /// framing error.
        pub reserved: U32,
    }
}

impl RequestHead {
    /// Builds a head with the reserved field zeroed.
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

/// The largest Linux errno, and so the bound on an error status: Linux caps
/// error codes at this value (`MAX_ERRNO`, `include/linux/err.h`), so a
/// negated errno always lies in `-MAX_ERRNO..=-1`.
pub const MAX_ERRNO: i32 = 4095;

/// Whether `status` is a valid error status, i.e. a negated Linux errno.
///
/// Success (0) is not an error status, and neither is a positive value nor a
/// negative value beyond [`MAX_ERRNO`] — no conforming peer can produce one,
/// and letting one through would hand a caller a number that is not an errno.
/// This is the single place the status contract is applied, shared by response
/// parsing and error-response encoding.
#[must_use]
pub fn is_error_status(status: i32) -> bool {
    (-MAX_ERRNO..0).contains(&status)
}

wire_struct! {
    /// The fixed 4-byte head at the start of every response body.
    pub struct ResponseHead {
        /// 0 on success, a negated Linux errno ([`is_error_status`])
        /// otherwise. Nothing follows a nonzero status.
        pub status: I32,
    }
}

impl ResponseHead {
    /// The success head.
    pub const SUCCESS: Self = Self { status: I32::ZERO };

    /// Builds a head carrying `status`.
    #[must_use]
    pub fn new(status: i32) -> Self {
        Self {
            status: I32::new(status),
        }
    }

    /// Whether the response carries an op-specific body.
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.status.get() == 0
    }
}

/// Common validation for a fixed wire struct.
///
/// The crate's wire-struct macro implements this structurally: fields named
/// `reserved` or `reserved2` must be zero, while structs without reserved
/// fields use the no-op default.
pub trait WireValidate {
    /// Checks invariants that make the fixed struct legal on the wire.
    ///
    /// # Errors
    ///
    /// Returns [`FramingError::ReservedFieldNonZero`] when any reserved field is
    /// nonzero.
    fn validate(&self) -> Result<(), FramingError> {
        Ok(())
    }
}

/// A fixed body that describes its own trailing payload.
///
/// Implementors are plain fixed-layout structs; everything variable-length
/// lives in the trailing payload and is described by length fields inside the
/// struct. This is the half of a message body that does not depend on which
/// opcode registry names it, which is what lets requests, responses and
/// notifications share one strict-framing implementation.
pub trait WirePayload: WireStruct + WireValidate {
    /// Checks invariants that apply when emitting this message.
    ///
    /// The default applies the same fixed-struct validation as parsing.
    /// Handshake messages additionally reject nonzero negotiation flags on send
    /// while continuing to ignore them on receive.
    ///
    /// # Errors
    ///
    /// Returns a framing error when the message may not be emitted.
    fn validate_encode(&self) -> Result<(), FramingError> {
        self.validate()
    }

    /// Total length of the trailing payload regions this body declares.
    ///
    /// The default is "no payload". Overriding implementations sum their
    /// length fields with [`sum_regions`], so an overflowing sum is a framing
    /// error, not a wrap-around.
    fn payload_len(&self) -> Result<u32, FramingError> {
        Ok(0)
    }
}

/// An op-specific message body: a [`WirePayload`] bound to a request opcode.
pub trait WireMessage: WirePayload {
    /// The opcode this body belongs to.
    const OPCODE: Opcode;
}

/// A message body that appears in request frames.
pub trait RequestBody: WireMessage {}

/// A message body that appears in response frames.
pub trait ResponseBody: WireMessage {}

/// A message body that appears in server-initiated notification frames.
///
/// Its opcode comes from the [`NotificationOpcode`] registry, not the request
/// one: a notification is never echoed, never answered, and never named by an
/// error response.
pub trait NotificationBody: WirePayload {
    /// The notification opcode this body belongs to.
    const OPCODE: NotificationOpcode;
}

/// Sums declared payload region lengths, rejecting arithmetic overflow.
///
/// Frame lengths are 32-bit on the wire, so the sum is checked in 32-bit
/// arithmetic on every platform.
pub fn sum_regions(regions: &[u32]) -> Result<u32, FramingError> {
    let mut total: u32 = 0;
    for region in regions {
        total = total
            .checked_add(*region)
            .ok_or(FramingError::LengthOverflow)?;
    }
    Ok(total)
}

/// Splits the leading `len` bytes off a payload region.
///
/// Strict framing guarantees the payload is long enough by the time an
/// accessor calls this. If a region list and its accessors ever drift apart,
/// returning the short remainder as the region keeps the mismatch visible
/// instead of silently turning real bytes into empty data.
pub(crate) fn split_region(payload: &[u8], len: u32) -> (&[u8], &[u8]) {
    let len = len as usize;
    match payload.get(len..) {
        Some(tail) => (&payload[..len], tail),
        None => (payload, &[]),
    }
}

/// A parsed request frame: caller identity, op-specific body, and payload.
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

    /// The caller identity and target node id.
    #[must_use]
    pub fn head(&self) -> &'a RequestHead {
        self.head
    }

    /// The op-specific request struct.
    #[must_use]
    pub fn body(&self) -> &'a M {
        self.body
    }

    /// The trailing payload, exactly as long as the body declared.
    #[must_use]
    pub fn payload(&self) -> &'a [u8] {
        self.payload
    }
}

/// A parsed successful response frame: op-specific body and payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Response<'a, M: ResponseBody> {
    body: &'a M,
    payload: &'a [u8],
}

impl<'a, M: ResponseBody> Response<'a, M> {
    pub(crate) fn new(body: &'a M, payload: &'a [u8]) -> Self {
        Self { body, payload }
    }

    /// The op-specific response struct.
    #[must_use]
    pub fn body(&self) -> &'a M {
        self.body
    }

    /// The trailing payload, exactly as long as the body declared.
    #[must_use]
    pub fn payload(&self) -> &'a [u8] {
        self.payload
    }
}

/// A parsed notification frame: op-specific body and payload.
///
/// There is no outcome type beside it: a notification cannot fail, because it
/// answers nothing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Notification<'a, M: NotificationBody> {
    body: &'a M,
    payload: &'a [u8],
}

impl<'a, M: NotificationBody> Notification<'a, M> {
    pub(crate) fn new(body: &'a M, payload: &'a [u8]) -> Self {
        Self { body, payload }
    }

    /// The op-specific notification struct.
    #[must_use]
    pub fn body(&self) -> &'a M {
        self.body
    }

    /// The trailing payload, exactly as long as the body declared.
    #[must_use]
    pub fn payload(&self) -> &'a [u8] {
        self.payload
    }
}

/// The outcome of parsing a response frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResponseOutcome<'a, M: ResponseBody> {
    /// Status 0: the op-specific body and its payload follow.
    Success(Response<'a, M>),
    /// A negated Linux errno, in `-MAX_ERRNO..=-1` ([`is_error_status`]).
    /// Nothing follows the status on the wire.
    Error(i32),
}

impl<'a, M: ResponseBody> ResponseOutcome<'a, M> {
    /// The successful response, if this outcome is one.
    #[must_use]
    pub fn success(self) -> Option<Response<'a, M>> {
        match self {
            Self::Success(response) => Some(response),
            Self::Error(_) => None,
        }
    }

    /// The negated errno, if this outcome is an error.
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
    fn region_sums_reject_overflow() {
        assert_eq!(sum_regions(&[]), Ok(0));
        assert_eq!(sum_regions(&[1, 2, 3]), Ok(6));
        assert_eq!(
            sum_regions(&[u32::MAX, 1]),
            Err(FramingError::LengthOverflow)
        );
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
