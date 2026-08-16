//! Framing: the 16-byte frame header, the frame taxonomy, and strict
//! parse/encode over caller-provided buffers.
//!
//! A frame is `[FrameHeader 16][body]`, and `len` counts the header. Parsing
//! borrows from the caller's buffer and encoding fills the caller's buffer, so
//! nothing here allocates and payload bytes are never re-serialized.
//!
//! **Strict framing.** Every byte of a frame is accounted for: the fixed
//! structs plus the payload regions the body declares must sum to `len`
//! exactly. Trailing unaccounted bytes, declared lengths that exceed the
//! payload, and overflowing length sums are all framing errors — on parse and
//! on encode alike.

use core::fmt;
use core::mem::size_of;

use zerocopy::byteorder::little_endian::{U16, U32, U64};
use zerocopy::{FromBytes, IntoBytes};

use crate::error::FramingError;
use crate::macros::wire_struct;
use crate::message::{
    Notification, NotificationBody, REQUEST_HEAD_LEN, RESPONSE_HEAD_LEN, Request, RequestBody,
    RequestHead, Response, ResponseBody, ResponseHead, ResponseOutcome, WirePayload, WireValidate,
    is_error_status,
};
use crate::opcode::{NotificationOpcode, Opcode, UnknownOpcode, is_notification_opcode};

/// Byte length of [`FrameHeader`], and the smallest legal frame.
pub const FRAME_HEADER_LEN: usize = 16;

/// Maximum size of a `Hello` frame, enforced before a session has negotiated
/// `max_frame_len`. A larger pre-handshake frame closes the connection.
pub const MAX_HELLO_FRAME_LEN: u32 = 4096;

/// Frame header flag: the frame is a response to the request with the same
/// `request_id`.
pub const FLAG_RESPONSE: u16 = 1 << 0;

/// Mask of the frame header flag bits that are reserved. They must be zero;
/// a receiver rejects a frame that sets any of them.
pub const FLAGS_RESERVED_MASK: u16 = !FLAG_RESPONSE;

wire_struct! {
    /// The fixed 16-byte frame header.
    pub struct FrameHeader {
        /// Total frame length in bytes, this header included.
        pub len: U32,
        /// The operation this frame belongs to.
        pub opcode: U16,
        /// Frame flags; bit 0 is [`FLAG_RESPONSE`], all other bits are reserved.
        pub flags: U16,
        /// Client-chosen id, echoed verbatim in the response. 0 is reserved for
        /// notifications.
        pub request_id: U64,
    }
}

impl FrameHeader {
    /// Builds a header from raw field values.
    #[must_use]
    pub fn new(len: u32, opcode: u16, flags: u16, request_id: u64) -> Self {
        Self {
            len: U32::new(len),
            opcode: U16::new(opcode),
            flags: U16::new(flags),
            request_id: U64::new(request_id),
        }
    }

    /// The frame class, derived from the opcode range and the response flag
    /// alone — no op-specific body is parsed.
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

    /// Classifies the opcode as known or unknown.
    ///
    /// # Errors
    ///
    /// Returns [`UnknownOpcode`] for any value outside the registry, which the
    /// receiver answers with `ENOSYS` instead of closing the connection.
    pub fn opcode(&self) -> Result<Opcode, UnknownOpcode> {
        Opcode::try_from(self.opcode.get())
    }

    /// Classifies a notification opcode as known or unknown.
    ///
    /// # Errors
    ///
    /// Returns [`UnknownOpcode`] for a value outside the notification
    /// registry — including every request opcode. A receiver *ignores* such a
    /// frame instead of failing on it, which is what keeps the range
    /// extensible.
    pub fn notification_opcode(&self) -> Result<NotificationOpcode, UnknownOpcode> {
        NotificationOpcode::try_from(self.opcode.get())
    }

    /// Validates the header against the frame taxonomy and the size bound.
    ///
    /// # Errors
    ///
    /// Returns a [`FramingError`] for a length below the header size or above
    /// `max_frame_len`, reserved flag bits, the reserved opcode `0x0000`, a
    /// request or response with id 0, or a notification that carries a
    /// nonzero id or the response flag.
    pub fn validate(&self, max_frame_len: u32) -> Result<(), FramingError> {
        self.checked_len(max_frame_len)?;
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

    /// The declared frame length, checked against the header size and the
    /// active maximum. The single place those two bounds are applied.
    fn checked_len(&self, max_frame_len: u32) -> Result<u32, FramingError> {
        let len = self.len.get();
        if (len as usize) < FRAME_HEADER_LEN {
            return Err(FramingError::FrameTooShort { len });
        }
        if len > max_frame_len {
            return Err(FramingError::FrameTooLong {
                len,
                max: max_frame_len,
            });
        }
        Ok(len)
    }
}

/// The class of a frame, decided by its header alone.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum FrameKind {
    /// Client to server; expects a response (except `forget`).
    Request,
    /// Server to client; echoes the request opcode and id.
    Response,
    /// Server to client, unsolicited: `request_id` 0, no reply, and no
    /// bookkeeping against the request-id table.
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

/// A validated frame borrowed from a caller-provided buffer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Frame<'a> {
    header: &'a FrameHeader,
    body: &'a [u8],
}

impl<'a> Frame<'a> {
    /// Reads the declared frame length from the front of a stream buffer,
    /// bounded by `max_frame_len`.
    ///
    /// Returns `Ok(None)` while fewer than [`FRAME_HEADER_LEN`] bytes are
    /// buffered. Stream readers size the next read from this value, so the
    /// bound is applied here, not after the whole frame is buffered: a
    /// peer can declare `u32::MAX`, and no reader may be asked to hold that.
    ///
    /// `max_frame_len` is the pre-handshake [`MAX_HELLO_FRAME_LEN`] or, once a
    /// session is established, the value the server announced in `HelloReply`.
    ///
    /// # Errors
    ///
    /// Returns [`FramingError::FrameTooShort`] for a length below the header
    /// size and [`FramingError::FrameTooLong`] for one above `max_frame_len`;
    /// both are framing errors that poison the stream.
    pub fn peek_len(buf: &[u8], max_frame_len: u32) -> Result<Option<u32>, FramingError> {
        let Ok((header, _)) = FrameHeader::ref_from_prefix(buf) else {
            return Ok(None);
        };
        header.checked_len(max_frame_len).map(Some)
    }

    /// Parses the frame at the front of `buf`, returning it and the bytes that
    /// follow it.
    ///
    /// `max_frame_len` is the pre-handshake [`MAX_HELLO_FRAME_LEN`] or, once a
    /// session is established, the value the server announced in `HelloReply`.
    ///
    /// # Errors
    ///
    /// Returns [`FramingError::Incomplete`] when the buffer holds only part of
    /// the frame, or any header validation error from
    /// [`FrameHeader::validate`].
    pub fn parse_prefix(
        buf: &'a [u8],
        max_frame_len: u32,
    ) -> Result<(Self, &'a [u8]), FramingError> {
        let (header, rest) =
            FrameHeader::ref_from_prefix(buf).map_err(|_| FramingError::Incomplete {
                needed: FRAME_HEADER_LEN,
            })?;
        header.validate(max_frame_len)?;
        let len = header.len.get() as usize;
        let body_len = len - FRAME_HEADER_LEN;
        if rest.len() < body_len {
            return Err(FramingError::Incomplete { needed: len });
        }
        let (body, tail) = rest.split_at(body_len);
        Ok((Self { header, body }, tail))
    }

    /// Parses a buffer that must hold exactly one frame.
    ///
    /// # Errors
    ///
    /// As [`Frame::parse_prefix`], plus [`FramingError::TrailingBytes`] when
    /// the buffer extends past the frame.
    pub fn parse(buf: &'a [u8], max_frame_len: u32) -> Result<Self, FramingError> {
        let (frame, tail) = Self::parse_prefix(buf, max_frame_len)?;
        if !tail.is_empty() {
            return Err(FramingError::TrailingBytes { extra: tail.len() });
        }
        Ok(frame)
    }

    /// The frame header.
    #[must_use]
    pub fn header(&self) -> &'a FrameHeader {
        self.header
    }

    /// The frame body: everything after the header.
    #[must_use]
    pub fn body(&self) -> &'a [u8] {
        self.body
    }

    /// The frame class.
    #[must_use]
    pub fn kind(&self) -> FrameKind {
        self.header.kind()
    }

    /// The raw opcode, whether or not it is known.
    #[must_use]
    pub fn raw_opcode(&self) -> u16 {
        self.header.opcode.get()
    }

    /// The request id; 0 for notifications.
    #[must_use]
    pub fn request_id(&self) -> u64 {
        self.header.request_id.get()
    }

    /// Classifies the opcode as known or unknown.
    ///
    /// # Errors
    ///
    /// Returns [`UnknownOpcode`] for unregistered values.
    pub fn opcode(&self) -> Result<Opcode, UnknownOpcode> {
        self.header.opcode()
    }

    /// Classifies the opcode against the notification registry.
    ///
    /// # Errors
    ///
    /// Returns [`UnknownOpcode`] for unregistered values.
    pub fn notification_opcode(&self) -> Result<NotificationOpcode, UnknownOpcode> {
        self.header.notification_opcode()
    }

    /// Parses this frame as a notification of type `M`.
    ///
    /// A notification body starts at the frame body directly: there is no head
    /// to skip, because a notification answers nothing and names no caller.
    ///
    /// # Errors
    ///
    /// Returns a [`FramingError`] when the frame is not a notification, carries
    /// a different opcode, is too short for the fixed struct, or violates
    /// strict framing.
    pub fn notification<M: NotificationBody>(&self) -> Result<Notification<'a, M>, FramingError> {
        self.expect_kind(FrameKind::Notification)?;
        self.expect_raw_opcode(M::OPCODE.as_u16())?;
        let (body, payload) = Self::split_body::<M>(self.body, 0, self.body.len())?;
        Ok(Notification::new(body, payload))
    }

    /// Validates the common request envelope — the 24-byte head every request
    /// body starts with — without knowing the operation.
    ///
    /// This is the check the unknown-opcode path owes: an unknown opcode is a
    /// *semantic* error answered with `ENOSYS`
    /// ([`FrameWriter::error_response_raw`]) only once the frame is well framed
    /// as a request. A frame too short for the head, or one whose reserved
    /// field is nonzero, is a *framing* error whatever the opcode, and the
    /// receiver closes the connection.
    ///
    /// # Errors
    ///
    /// Returns [`FramingError::UnexpectedFrameKind`] when the frame is not a
    /// request, [`FramingError::BodyTooShort`] when the body cannot hold the
    /// head, and [`FramingError::ReservedFieldNonZero`] for a nonzero reserved
    /// field.
    pub fn request_head(&self) -> Result<&'a RequestHead, FramingError> {
        self.expect_kind(FrameKind::Request)?;
        let (head, _) = self.split_request_head()?;
        Ok(head)
    }

    /// Parses this frame as a request of type `M`.
    ///
    /// # Errors
    ///
    /// Returns a [`FramingError`] when the frame is not a request, carries a
    /// different opcode, is too short for the fixed structs, sets the reserved
    /// field of the request head, or violates strict framing.
    pub fn request<M: RequestBody>(&self) -> Result<Request<'a, M>, FramingError> {
        self.expect_kind(FrameKind::Request)?;
        self.expect_opcode(M::OPCODE)?;
        let (head, rest) = self.split_request_head()?;
        let (body, payload) = Self::split_body::<M>(rest, REQUEST_HEAD_LEN, self.body.len())?;
        Ok(Request::new(head, body, payload))
    }

    /// Splits the common request head off the body. The single validation path
    /// for that head, shared by the typed and unknown-opcode routes.
    fn split_request_head(&self) -> Result<(&'a RequestHead, &'a [u8]), FramingError> {
        let (head, rest) =
            RequestHead::ref_from_prefix(self.body).map_err(|_| FramingError::BodyTooShort {
                needed: REQUEST_HEAD_LEN,
                found: self.body.len(),
            })?;
        head.validate()?;
        Ok((head, rest))
    }

    /// Parses this frame as a response of type `M`.
    ///
    /// A nonzero status must be a negated Linux errno ([`is_error_status`])
    /// and must be the entire body; an error response carrying anything after
    /// its status is a framing error.
    ///
    /// # Errors
    ///
    /// Returns a [`FramingError`] when the frame is not a response, carries a
    /// different opcode, is too short, carries an invalid status, or violates
    /// strict framing.
    pub fn response<M: ResponseBody>(&self) -> Result<ResponseOutcome<'a, M>, FramingError> {
        self.expect_kind(FrameKind::Response)?;
        self.expect_opcode(M::OPCODE)?;
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

    fn expect_opcode(&self, expected: Opcode) -> Result<(), FramingError> {
        self.expect_raw_opcode(expected.as_u16())
    }

    fn expect_raw_opcode(&self, expected: u16) -> Result<(), FramingError> {
        let found = self.raw_opcode();
        if found == expected {
            Ok(())
        } else {
            Err(FramingError::OpcodeMismatch { expected, found })
        }
    }

    /// Splits the op-specific struct and the payload off `rest`, enforcing
    /// strict framing.
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

/// Encodes one frame into a caller-provided buffer.
///
/// The caller supplies the active `max_frame_len` to each constructor. The
/// effective bound is the smaller of that value and the output buffer length,
/// so neither an oversized buffer nor an oversized negotiated value can weaken
/// the other limit.
///
/// The writer owes exactly as many payload bytes as the message body declared;
/// [`FrameWriter::finish`] refuses to produce a frame until they are written,
/// which is strict framing enforced on the encode side.
#[derive(Debug)]
pub struct FrameWriter<'a> {
    buf: &'a mut [u8],
    written: usize,
    payload_owed: u32,
}

impl<'a> FrameWriter<'a> {
    /// Starts a request frame.
    ///
    /// # Errors
    ///
    /// Returns [`FramingError::ZeroRequestId`] for the reserved id 0,
    /// [`FramingError::ReservedFieldNonZero`] for a reserved field,
    /// [`FramingError::NegotiationFlagsNonZero`] for handshake flags on send,
    /// [`FramingError::LengthOverflow`] when the declared lengths do not fit the
    /// 32-bit length space,
    /// [`FramingError::FrameTooLong`] above `max_frame_len`, and
    /// [`FramingError::BufferTooSmall`] when the buffer cannot hold the frame.
    pub fn request<M: RequestBody>(
        buf: &'a mut [u8],
        max_frame_len: u32,
        request_id: u64,
        head: &RequestHead,
        body: &M,
    ) -> Result<Self, FramingError> {
        if request_id == 0 {
            return Err(FramingError::ZeroRequestId);
        }
        head.validate()?;
        body.validate_encode()?;
        let payload_len = body.payload_len()?;
        let fixed = FRAME_HEADER_LEN + REQUEST_HEAD_LEN + size_of::<M>();
        let mut writer = Self::open(
            buf,
            max_frame_len,
            M::OPCODE.as_u16(),
            0,
            request_id,
            fixed,
            payload_len,
        )?;
        writer.put(FRAME_HEADER_LEN, head.as_bytes())?;
        writer.put(FRAME_HEADER_LEN + REQUEST_HEAD_LEN, body.as_bytes())?;
        Ok(writer)
    }

    /// Starts a successful response frame.
    ///
    /// # Errors
    ///
    /// As [`FrameWriter::request`].
    pub fn response<M: ResponseBody>(
        buf: &'a mut [u8],
        max_frame_len: u32,
        request_id: u64,
        body: &M,
    ) -> Result<Self, FramingError> {
        if request_id == 0 {
            return Err(FramingError::ZeroRequestId);
        }
        body.validate_encode()?;
        let payload_len = body.payload_len()?;
        let fixed = FRAME_HEADER_LEN + RESPONSE_HEAD_LEN + size_of::<M>();
        let mut writer = Self::open(
            buf,
            max_frame_len,
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

    /// Starts a server-initiated notification frame.
    ///
    /// Notifications carry `request_id` 0 and never set the response flag, so
    /// neither is a parameter: both are fixed by the frame taxonomy. Nothing
    /// answers a notification, which is also why it bypasses the writer's
    /// request-id retirement bookkeeping on the way out.
    ///
    /// # Errors
    ///
    /// As [`FrameWriter::request`], minus the id checks a notification has no
    /// id to fail.
    pub fn notification<M: NotificationBody>(
        buf: &'a mut [u8],
        max_frame_len: u32,
        body: &M,
    ) -> Result<Self, FramingError> {
        body.validate_encode()?;
        let payload_len = body.payload_len()?;
        let fixed = FRAME_HEADER_LEN + size_of::<M>();
        let mut writer = Self::open(
            buf,
            max_frame_len,
            M::OPCODE.as_u16(),
            0,
            0,
            fixed,
            payload_len,
        )?;
        writer.put(FRAME_HEADER_LEN, body.as_bytes())?;
        Ok(writer)
    }

    /// Encodes a complete error response: header, status, nothing else.
    ///
    /// # Errors
    ///
    /// Returns [`FramingError::InvalidStatus`] unless `status` is a negated
    /// Linux errno ([`is_error_status`]), and the errors of
    /// [`FrameWriter::request`].
    pub fn error_response(
        buf: &'a mut [u8],
        max_frame_len: u32,
        request_id: u64,
        opcode: Opcode,
        status: i32,
    ) -> Result<&'a [u8], FramingError> {
        Self::error_response_raw(buf, max_frame_len, request_id, opcode.as_u16(), status)
    }

    /// Encodes an error response echoing a raw request opcode, registered or
    /// not.
    ///
    /// This is the encode side of the semantic-error path: a well-framed
    /// request carrying an opcode this build does not know
    /// ([`UnknownOpcode`]) is answered with `ENOSYS` echoing that opcode
    /// verbatim, and the connection lives on — which is what keeps future
    /// protocol extensions non-fatal to old peers. Use
    /// [`FrameWriter::error_response`] when the opcode is in the registry.
    ///
    /// # Errors
    ///
    /// Returns [`FramingError::ReservedOpcode`] for opcode `0x0000` and
    /// [`FramingError::UnexpectedFrameKind`] for one in the notification range
    /// — neither can name a request, so neither can be echoed by a response —
    /// plus [`FramingError::InvalidStatus`] unless `status` is a negated Linux
    /// errno ([`is_error_status`]) and the errors of
    /// [`FrameWriter::request`].
    pub fn error_response_raw(
        buf: &'a mut [u8],
        max_frame_len: u32,
        request_id: u64,
        opcode: u16,
        status: i32,
    ) -> Result<&'a [u8], FramingError> {
        if opcode == 0 {
            return Err(FramingError::ReservedOpcode);
        }
        if is_notification_opcode(opcode) {
            return Err(FramingError::UnexpectedFrameKind {
                expected: FrameKind::Request,
                found: FrameKind::Notification,
            });
        }
        if !is_error_status(status) {
            return Err(FramingError::InvalidStatus { status });
        }
        if request_id == 0 {
            return Err(FramingError::ZeroRequestId);
        }
        let fixed = FRAME_HEADER_LEN + RESPONSE_HEAD_LEN;
        let mut writer = Self::open(
            buf,
            max_frame_len,
            opcode,
            FLAG_RESPONSE,
            request_id,
            fixed,
            0,
        )?;
        writer.put(FRAME_HEADER_LEN, ResponseHead::new(status).as_bytes())?;
        writer.finish()
    }

    /// Appends payload bytes.
    ///
    /// # Errors
    ///
    /// Returns [`FramingError::PayloadLengthMismatch`] when the write would
    /// exceed the payload length the body declared.
    pub fn payload(&mut self, bytes: &[u8]) -> Result<(), FramingError> {
        let slot = self.payload_buf(bytes.len())?;
        slot.copy_from_slice(bytes);
        Ok(())
    }

    /// Reserves `len` payload bytes and returns them for direct filling, so a
    /// read can land straight in the frame buffer.
    ///
    /// # Errors
    ///
    /// As [`FrameWriter::payload`].
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

    /// Finishes the frame and returns its bytes.
    ///
    /// # Errors
    ///
    /// Returns [`FramingError::IncompletePayload`] when declared payload bytes
    /// were never written.
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
        max_frame_len: u32,
        opcode: u16,
        flags: u16,
        request_id: u64,
        fixed: usize,
        payload_len: u32,
    ) -> Result<Self, FramingError> {
        let fixed_len = u32::try_from(fixed).map_err(|_| FramingError::LengthOverflow)?;
        let total = fixed_len
            .checked_add(payload_len)
            .ok_or(FramingError::LengthOverflow)?;
        if total > max_frame_len {
            return Err(FramingError::FrameTooLong {
                len: total,
                max: max_frame_len,
            });
        }
        let total_usize = total as usize;
        if buf.len() < total_usize {
            return Err(FramingError::BufferTooSmall {
                needed: total_usize,
                found: buf.len(),
            });
        }
        let mut writer = Self {
            buf,
            written: fixed,
            payload_owed: payload_len,
        };
        let header = FrameHeader::new(total, opcode, flags, request_id);
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

    /// `len = 0x11223344`, `opcode = 0x5566`, `flags = 0x7788`,
    /// `request_id = 0x0102030405060708`.
    const HEADER_GOLDEN: [u8; FRAME_HEADER_LEN] = [
        0x44, 0x33, 0x22, 0x11, 0x66, 0x55, 0x88, 0x77, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02,
        0x01,
    ];

    #[test]
    fn header_layout_is_pinned() {
        assert_eq!(size_of::<FrameHeader>(), FRAME_HEADER_LEN);
        assert_eq!(align_of::<FrameHeader>(), 1);
        assert_eq!(offset_of!(FrameHeader, len), 0);
        assert_eq!(offset_of!(FrameHeader, opcode), 4);
        assert_eq!(offset_of!(FrameHeader, flags), 6);
        assert_eq!(offset_of!(FrameHeader, request_id), 8);

        let header = FrameHeader::new(0x1122_3344, 0x5566, 0x7788, 0x0102_0304_0506_0708);
        assert_eq!(header.as_bytes(), &HEADER_GOLDEN);
        assert_eq!(FrameHeader::read_from_bytes(&HEADER_GOLDEN), Ok(header));
    }

    #[test]
    fn header_is_viewable_at_any_offset() {
        let mut buf = [0xAAu8; FRAME_HEADER_LEN + 1];
        buf[1..].copy_from_slice(&HEADER_GOLDEN);
        let (header, rest) = FrameHeader::ref_from_prefix(&buf[1..]).unwrap();
        assert!(rest.is_empty());
        assert_eq!(header.len.get(), 0x1122_3344);
    }

    #[test]
    fn taxonomy_is_header_only() {
        assert_eq!(
            FrameHeader::new(16, 0x0002, 0, 1).kind(),
            FrameKind::Request
        );
        assert_eq!(
            FrameHeader::new(16, 0x0002, FLAG_RESPONSE, 1).kind(),
            FrameKind::Response
        );
        assert_eq!(
            FrameHeader::new(16, 0x8000, 0, 0).kind(),
            FrameKind::Notification
        );
    }

    #[test]
    fn peek_len_needs_a_full_header_and_stays_within_the_bound() {
        assert_eq!(Frame::peek_len(&HEADER_GOLDEN[..15], 4096), Ok(None));

        let header = FrameHeader::new(64, 0x0002, 0, 1);
        assert_eq!(Frame::peek_len(header.as_bytes(), 4096), Ok(Some(64)));

        // A read must never be sized from an unbounded declared length.
        assert_eq!(
            Frame::peek_len(&HEADER_GOLDEN, 4096),
            Err(FramingError::FrameTooLong {
                len: 0x1122_3344,
                max: 4096,
            })
        );
        assert_eq!(
            Frame::peek_len(FrameHeader::new(15, 0x0002, 0, 1).as_bytes(), 4096),
            Err(FramingError::FrameTooShort { len: 15 })
        );
    }

    #[test]
    fn notifications_validate_on_the_header_alone() {
        assert_eq!(FrameHeader::new(16, 0x8001, 0, 0).validate(4096), Ok(()));
        assert_eq!(
            FrameHeader::new(16, 0x8001, 0, 7).validate(4096),
            Err(FramingError::NotificationRequestId { request_id: 7 })
        );
        assert_eq!(
            FrameHeader::new(16, 0x8001, FLAG_RESPONSE, 0).validate(4096),
            Err(FramingError::NotificationResponseFlag)
        );
    }
}
