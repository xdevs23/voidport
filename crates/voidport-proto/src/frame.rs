use core::fmt;
use core::mem::size_of;

use zerocopy::byteorder::little_endian::{U16, U64};
use zerocopy::{FromBytes, IntoBytes};

use crate::error::FramingError;
use crate::limits::Limits;
use crate::macros::wire_struct;
use crate::message::{
    Follows, Notification, NotificationBody, REQUEST_HEAD_LEN, RESPONSE_HEAD_LEN, Request,
    RequestBody, RequestHead, Response, ResponseBody, ResponseHead, ResponseOutcome, WirePayload,
    WireValidate, is_error_status,
};
use crate::opcode::{NotificationOpcode, Opcode, UnknownOpcode, is_notification_opcode};
use crate::table;

pub const FRAME_HEADER_LEN: usize = 12;

pub const FLAG_RESPONSE: u16 = 1 << 0;

pub const FLAGS_RESERVED_MASK: u16 = !FLAG_RESPONSE;

wire_struct! {
    pub struct FrameHeader {
        pub opcode: U16,
        pub flags: U16,
        pub request_id: U64,
    }
}

impl FrameHeader {
    #[must_use]
    pub fn new(opcode: u16, flags: u16, request_id: u64) -> Self {
        Self {
            opcode: U16::new(opcode),
            flags: U16::new(flags),
            request_id: U64::new(request_id),
        }
    }

    pub fn parse(buf: &[u8]) -> Result<&Self, FramingError> {
        let (header, _) = Self::ref_from_prefix(buf).map_err(|_| FramingError::Incomplete {
            needed: FRAME_HEADER_LEN,
        })?;
        header.validate()?;
        Ok(header)
    }

    #[must_use]
    pub fn kind(&self) -> FrameKind {
        if is_notification_opcode(self.opcode.get()) {
            FrameKind::Notification
        } else if self.flags.get() & FLAG_RESPONSE != 0 {
            FrameKind::Response
        } else {
            FrameKind::Request
        }
    }

    pub fn opcode(&self) -> Result<Opcode, UnknownOpcode> {
        Opcode::try_from(self.opcode.get())
    }

    pub fn notification_opcode(&self) -> Result<NotificationOpcode, UnknownOpcode> {
        NotificationOpcode::try_from(self.opcode.get())
    }

    pub fn validate(&self) -> Result<(), FramingError> {
        let flags = self.flags.get();
        if flags & FLAGS_RESERVED_MASK != 0 {
            return Err(FramingError::ReservedFlags { flags });
        }
        let opcode = self.opcode.get();
        if opcode == 0 {
            return Err(FramingError::ReservedOpcode);
        }
        let request_id = self.request_id.get();
        if is_notification_opcode(opcode) {
            if flags & FLAG_RESPONSE != 0 {
                return Err(FramingError::NotificationResponseFlag);
            }
            if request_id != 0 {
                return Err(FramingError::NotificationRequestId { request_id });
            }
        } else if request_id == 0 {
            return Err(FramingError::ZeroRequestId);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum FrameKind {
    Request,
    Response,
    Notification,
}

impl fmt::Display for FrameKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Request => "request",
            Self::Response => "response",
            Self::Notification => "notification",
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Parsed<'a> {
    /// The total number of bytes needed, header included. Always more than the
    /// buffer contains.
    Need(usize),
    Frame(Frame<'a>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Frame<'a> {
    header: &'a FrameHeader,
    body: &'a [u8],
    follows: Follows,
}

impl<'a> Frame<'a> {
    /// Every declared length is checked against `limits` before the parser asks
    /// for the bytes of that part.
    pub fn parse_prefix(buf: &'a [u8], limits: &Limits) -> Result<Parsed<'a>, FramingError> {
        let Ok((header, rest)) = FrameHeader::ref_from_prefix(buf) else {
            return Ok(Parsed::Need(FRAME_HEADER_LEN));
        };
        header.validate()?;
        let raw = header.opcode.get();
        let unknown = |_| FramingError::UnknownOpcode { opcode: raw };
        let (head_len, layout) = match header.kind() {
            FrameKind::Request => (
                REQUEST_HEAD_LEN,
                table::request(Opcode::try_from(raw).map_err(unknown)?),
            ),
            FrameKind::Response => {
                let opcode = Opcode::try_from(raw).map_err(unknown)?;
                let layout = table::response(opcode).ok_or(FramingError::NoBody {
                    opcode: raw,
                    kind: FrameKind::Response,
                })?;
                let Ok((head, _)) = ResponseHead::ref_from_prefix(rest) else {
                    return Ok(Parsed::Need(FRAME_HEADER_LEN + RESPONSE_HEAD_LEN));
                };
                let status = head.status.get();
                if status != 0 {
                    // Nothing follows a nonzero status.
                    if !is_error_status(status) {
                        return Err(FramingError::InvalidStatus { status });
                    }
                    return Ok(Parsed::Frame(Self {
                        header,
                        body: &rest[..RESPONSE_HEAD_LEN],
                        follows: Follows::Nothing,
                    }));
                }
                (RESPONSE_HEAD_LEN, layout)
            }
            FrameKind::Notification => (
                0,
                table::notification(NotificationOpcode::try_from(raw).map_err(unknown)?),
            ),
        };
        let fixed_end = head_len + layout.fixed;
        let Some(fixed) = rest.get(..fixed_end) else {
            return Ok(Parsed::Need(FRAME_HEADER_LEN + fixed_end));
        };
        if header.kind() == FrameKind::Request {
            let (head, _) =
                RequestHead::ref_from_prefix(fixed).map_err(|_| FramingError::BodyTooShort {
                    needed: REQUEST_HEAD_LEN,
                    found: fixed.len(),
                })?;
            head.validate()?;
        }
        let declared = layout.declared(&fixed[head_len..], limits)?;
        let end = fixed_end
            .checked_add(declared.regions as usize)
            .ok_or(FramingError::LengthOverflow)?;
        let Some(body) = rest.get(..end) else {
            return Ok(Parsed::Need(FRAME_HEADER_LEN + end));
        };
        Ok(Parsed::Frame(Self {
            header,
            body,
            follows: declared.follows,
        }))
    }

    pub fn parse(buf: &'a [u8], limits: &Limits) -> Result<Self, FramingError> {
        match Self::parse_prefix(buf, limits)? {
            Parsed::Need(needed) => Err(FramingError::Incomplete { needed }),
            Parsed::Frame(frame) => {
                let extra = buf.len() - frame.len();
                if extra != 0 {
                    return Err(FramingError::TrailingBytes { extra });
                }
                Ok(frame)
            }
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        FRAME_HEADER_LEN + self.body.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.body.is_empty()
    }

    #[must_use]
    pub fn follows(&self) -> Follows {
        self.follows
    }

    #[must_use]
    pub fn header(&self) -> &'a FrameHeader {
        self.header
    }

    #[must_use]
    pub fn body(&self) -> &'a [u8] {
        self.body
    }

    #[must_use]
    pub fn kind(&self) -> FrameKind {
        self.header.kind()
    }

    #[must_use]
    pub fn raw_opcode(&self) -> u16 {
        self.header.opcode.get()
    }

    #[must_use]
    pub fn request_id(&self) -> u64 {
        self.header.request_id.get()
    }

    pub fn opcode(&self) -> Result<Opcode, UnknownOpcode> {
        self.header.opcode()
    }

    pub fn notification_opcode(&self) -> Result<NotificationOpcode, UnknownOpcode> {
        self.header.notification_opcode()
    }

    pub fn status(&self) -> Result<i32, FramingError> {
        self.expect_kind(FrameKind::Response)?;
        let (head, _) =
            ResponseHead::ref_from_prefix(self.body).map_err(|_| FramingError::BodyTooShort {
                needed: RESPONSE_HEAD_LEN,
                found: self.body.len(),
            })?;
        Ok(head.status.get())
    }

    pub fn notification<M: NotificationBody>(&self) -> Result<Notification<'a, M>, FramingError> {
        self.expect_kind(FrameKind::Notification)?;
        self.expect_raw_opcode(M::OPCODE.as_u16())?;
        let (body, payload) = Self::split_body::<M>(self.body, 0, self.body.len())?;
        Ok(Notification::new(body, payload))
    }

    pub fn request<M: RequestBody>(&self) -> Result<Request<'a, M>, FramingError> {
        self.expect_kind(FrameKind::Request)?;
        self.expect_raw_opcode(M::OPCODE.as_u16())?;
        let (head, rest) =
            RequestHead::ref_from_prefix(self.body).map_err(|_| FramingError::BodyTooShort {
                needed: REQUEST_HEAD_LEN,
                found: self.body.len(),
            })?;
        head.validate()?;
        let (body, payload) = Self::split_body::<M>(rest, REQUEST_HEAD_LEN, self.body.len())?;
        Ok(Request::new(head, body, payload))
    }

    pub fn response<M: ResponseBody>(&self) -> Result<ResponseOutcome<'a, M>, FramingError> {
        self.expect_kind(FrameKind::Response)?;
        self.expect_raw_opcode(M::OPCODE.as_u16())?;
        let (head, rest) =
            ResponseHead::ref_from_prefix(self.body).map_err(|_| FramingError::BodyTooShort {
                needed: RESPONSE_HEAD_LEN,
                found: self.body.len(),
            })?;
        let status = head.status.get();
        if status != 0 {
            if !is_error_status(status) {
                return Err(FramingError::InvalidStatus { status });
            }
            if !rest.is_empty() {
                return Err(FramingError::ErrorResponseBody { extra: rest.len() });
            }
            return Ok(ResponseOutcome::Error(status));
        }
        let (body, payload) = Self::split_body::<M>(rest, RESPONSE_HEAD_LEN, self.body.len())?;
        Ok(ResponseOutcome::Success(Response::new(body, payload)))
    }

    fn expect_kind(&self, expected: FrameKind) -> Result<(), FramingError> {
        let found = self.kind();
        if found == expected {
            Ok(())
        } else {
            Err(FramingError::UnexpectedFrameKind { expected, found })
        }
    }

    fn expect_raw_opcode(&self, expected: u16) -> Result<(), FramingError> {
        let found = self.raw_opcode();
        if found == expected {
            Ok(())
        } else {
            Err(FramingError::OpcodeMismatch { expected, found })
        }
    }

    fn split_body<M: WirePayload>(
        rest: &'a [u8],
        head_len: usize,
        body_len: usize,
    ) -> Result<(&'a M, &'a [u8]), FramingError> {
        let (body, payload) = M::ref_from_prefix(rest).map_err(|_| FramingError::BodyTooShort {
            needed: head_len + size_of::<M>(),
            found: body_len,
        })?;
        body.validate()?;
        let declared = body.payload_len()?;
        if declared as usize != payload.len() {
            return Err(FramingError::PayloadLengthMismatch {
                declared,
                found: payload.len(),
            });
        }
        Ok((body, payload))
    }
}

/// [`FrameWriter::finish`] does not produce a frame until the payload that
/// the body declared is written.
#[derive(Debug)]
pub struct FrameWriter<'a> {
    buf: &'a mut [u8],
    written: usize,
    payload_owed: u32,
}

impl<'a> FrameWriter<'a> {
    #[must_use]
    pub const fn request_len<M: RequestBody>(payload: usize) -> usize {
        FRAME_HEADER_LEN + REQUEST_HEAD_LEN + size_of::<M>() + payload
    }

    #[must_use]
    pub const fn response_len<M: ResponseBody>(payload: usize) -> usize {
        FRAME_HEADER_LEN + RESPONSE_HEAD_LEN + size_of::<M>() + payload
    }

    #[must_use]
    pub const fn notification_len<M: NotificationBody>(payload: usize) -> usize {
        FRAME_HEADER_LEN + size_of::<M>() + payload
    }

    pub const ERROR_RESPONSE_LEN: usize = FRAME_HEADER_LEN + RESPONSE_HEAD_LEN;

    pub fn request<M: RequestBody>(
        buf: &'a mut [u8],
        limits: &Limits,
        request_id: u64,
        head: &RequestHead,
        body: &M,
    ) -> Result<Self, FramingError> {
        if request_id == 0 {
            return Err(FramingError::ZeroRequestId);
        }
        head.validate()?;
        body.validate_encode()?;
        let payload_len = body.regions().check(limits)?;
        let fixed = FRAME_HEADER_LEN + REQUEST_HEAD_LEN + size_of::<M>();
        let mut writer = Self::open(buf, M::OPCODE.as_u16(), 0, request_id, fixed, payload_len)?;
        writer.put(FRAME_HEADER_LEN, head.as_bytes())?;
        writer.put(FRAME_HEADER_LEN + REQUEST_HEAD_LEN, body.as_bytes())?;
        Ok(writer)
    }

    pub fn response<M: ResponseBody>(
        buf: &'a mut [u8],
        limits: &Limits,
        request_id: u64,
        body: &M,
    ) -> Result<Self, FramingError> {
        if request_id == 0 {
            return Err(FramingError::ZeroRequestId);
        }
        body.validate_encode()?;
        let payload_len = body.regions().check(limits)?;
        let fixed = FRAME_HEADER_LEN + RESPONSE_HEAD_LEN + size_of::<M>();
        let mut writer = Self::open(
            buf,
            M::OPCODE.as_u16(),
            FLAG_RESPONSE,
            request_id,
            fixed,
            payload_len,
        )?;
        writer.put(FRAME_HEADER_LEN, ResponseHead::SUCCESS.as_bytes())?;
        writer.put(FRAME_HEADER_LEN + RESPONSE_HEAD_LEN, body.as_bytes())?;
        Ok(writer)
    }

    pub fn notification<M: NotificationBody>(
        buf: &'a mut [u8],
        limits: &Limits,
        body: &M,
    ) -> Result<Self, FramingError> {
        body.validate_encode()?;
        let payload_len = body.regions().check(limits)?;
        let fixed = FRAME_HEADER_LEN + size_of::<M>();
        let mut writer = Self::open(buf, M::OPCODE.as_u16(), 0, 0, fixed, payload_len)?;
        writer.put(FRAME_HEADER_LEN, body.as_bytes())?;
        Ok(writer)
    }

    pub fn error_response(
        buf: &'a mut [u8],
        request_id: u64,
        opcode: Opcode,
        status: i32,
    ) -> Result<&'a [u8], FramingError> {
        if !opcode.has_response() {
            return Err(FramingError::NoBody {
                opcode: opcode.as_u16(),
                kind: FrameKind::Response,
            });
        }
        if !is_error_status(status) {
            return Err(FramingError::InvalidStatus { status });
        }
        if request_id == 0 {
            return Err(FramingError::ZeroRequestId);
        }
        let fixed = FRAME_HEADER_LEN + RESPONSE_HEAD_LEN;
        let mut writer = Self::open(buf, opcode.as_u16(), FLAG_RESPONSE, request_id, fixed, 0)?;
        writer.put(FRAME_HEADER_LEN, ResponseHead::new(status).as_bytes())?;
        writer.finish()
    }

    pub fn payload(&mut self, bytes: &[u8]) -> Result<(), FramingError> {
        let slot = self.payload_buf(bytes.len())?;
        slot.copy_from_slice(bytes);
        Ok(())
    }

    /// Reserves `len` payload bytes for direct filling.
    pub fn payload_buf(&mut self, len: usize) -> Result<&mut [u8], FramingError> {
        let wanted = u32::try_from(len).map_err(|_| FramingError::LengthOverflow)?;
        if wanted > self.payload_owed {
            return Err(FramingError::PayloadLengthMismatch {
                declared: self.payload_owed,
                found: len,
            });
        }
        let end = self.written + len;
        let capacity = self.buf.len();
        let slot = self
            .buf
            .get_mut(self.written..end)
            .ok_or(FramingError::BufferTooSmall {
                needed: end,
                found: capacity,
            })?;
        self.written = end;
        self.payload_owed -= wanted;
        Ok(slot)
    }

    pub fn finish(self) -> Result<&'a [u8], FramingError> {
        if self.payload_owed != 0 {
            return Err(FramingError::IncompletePayload {
                missing: self.payload_owed,
            });
        }
        let Self { buf, written, .. } = self;
        Ok(&buf[..written])
    }

    fn open(
        buf: &'a mut [u8],
        opcode: u16,
        flags: u16,
        request_id: u64,
        fixed: usize,
        payload_len: u32,
    ) -> Result<Self, FramingError> {
        let total = fixed
            .checked_add(payload_len as usize)
            .ok_or(FramingError::LengthOverflow)?;
        if buf.len() < total {
            return Err(FramingError::BufferTooSmall {
                needed: total,
                found: buf.len(),
            });
        }
        let mut writer = Self {
            buf,
            written: fixed,
            payload_owed: payload_len,
        };
        let header = FrameHeader::new(opcode, flags, request_id);
        writer.put(0, header.as_bytes())?;
        Ok(writer)
    }

    fn put(&mut self, offset: usize, bytes: &[u8]) -> Result<(), FramingError> {
        let end = offset + bytes.len();
        let capacity = self.buf.len();
        let slot = self
            .buf
            .get_mut(offset..end)
            .ok_or(FramingError::BufferTooSmall {
                needed: end,
                found: capacity,
            })?;
        slot.copy_from_slice(bytes);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{align_of, offset_of};

    const HEADER_GOLDEN: [u8; FRAME_HEADER_LEN] = [
        0x66, 0x55, 0x88, 0x77, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
    ];

    #[test]
    fn header_layout_is_pinned() {
        assert_eq!(size_of::<FrameHeader>(), FRAME_HEADER_LEN);
        assert_eq!(align_of::<FrameHeader>(), 1);
        assert_eq!(offset_of!(FrameHeader, opcode), 0);
        assert_eq!(offset_of!(FrameHeader, flags), 2);
        assert_eq!(offset_of!(FrameHeader, request_id), 4);

        let header = FrameHeader::new(0x5566, 0x7788, 0x0102_0304_0506_0708);
        assert_eq!(header.as_bytes(), &HEADER_GOLDEN);
        assert_eq!(FrameHeader::read_from_bytes(&HEADER_GOLDEN), Ok(header));
    }

    #[test]
    fn header_is_viewable_at_any_offset() {
        let mut buf = [0xAAu8; FRAME_HEADER_LEN + 1];
        buf[1..].copy_from_slice(&HEADER_GOLDEN);
        let (header, rest) = FrameHeader::ref_from_prefix(&buf[1..]).unwrap();
        assert!(rest.is_empty());
        assert_eq!(header.opcode.get(), 0x5566);
    }

    #[test]
    fn taxonomy_is_header_only() {
        assert_eq!(FrameHeader::new(0x0002, 0, 1).kind(), FrameKind::Request);
        assert_eq!(
            FrameHeader::new(0x0002, FLAG_RESPONSE, 1).kind(),
            FrameKind::Response
        );
        assert_eq!(
            FrameHeader::new(0x8000, 0, 0).kind(),
            FrameKind::Notification
        );
    }

    #[test]
    fn notifications_validate_on_the_header_alone() {
        assert_eq!(FrameHeader::new(0x8001, 0, 0).validate(), Ok(()));
        assert_eq!(
            FrameHeader::new(0x8001, 0, 7).validate(),
            Err(FramingError::NotificationRequestId { request_id: 7 })
        );
        assert_eq!(
            FrameHeader::new(0x8001, FLAG_RESPONSE, 0).validate(),
            Err(FramingError::NotificationResponseFlag)
        );
    }
}
