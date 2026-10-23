// SPDX-License-Identifier: GPL-2.0
//! Messages on a stream: how one is read exactly, how one is encoded into a
//! buffer the request owns, and the identity every request carries.
//!
//! The frame header carries no length, so a reader learns the size of a
//! message from the parser of the wire crate: the header first, then the
//! fixed body its opcode names, then the parts whose lengths that body gives.
//! Every declared length is checked against [`LIMITS`], the bounds the
//! kernel's own interface takes, before a byte of that part is read.
//!
//! A message is read from a [`Source`]: the stream of a connection, or the
//! bytes of a reply the server stored for a request of a lost connection.

use kernel::bindings;
use kernel::prelude::*;
use kernel::time::Delta;
use voidport_proto::error::FramingError;
use voidport_proto::frame::{Frame, FrameWriter, Parsed, FRAME_HEADER_LEN};
use voidport_proto::limits::Limits;
use voidport_proto::message::{Follows, RequestBody, RequestHead, ResponseBody, RESPONSE_HEAD_LEN};
use voidport_proto::piece::{self, Closing, ClosingBody, CLOSING_LEN, PIECE_LEN_LEN};

use crate::socket::{Stream, SCRATCH_LEN};

/// The guest identity a request is made on behalf of. It is captured on the
/// task that enters the filesystem, before any work moves to a worker, because
/// the identity of a worker is never the identity of the requesting task.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Caller {
    /// Guest uid, in the initial user namespace.
    pub uid: u32,
    /// Guest gid, in the initial user namespace.
    pub gid: u32,
    /// Guest pid; informational.
    pub pid: u32,
}

impl Caller {
    /// The identity a set of credentials names: what an asynchronous read
    /// runs as, never the identity of the worker that performs the I/O. The
    /// ids are read in the initial user namespace, which the mount lives in.
    ///
    /// # Safety
    ///
    /// `cred` must point at a live `struct cred`.
    pub unsafe fn of_cred(cred: *const bindings::cred) -> Self {
        // SAFETY: the caller promises `cred` is live; its id fields are stable
        // for reads while it is held.
        unsafe {
            let fsuid = core::ptr::addr_of!((*cred).fsuid).read();
            let fsgid = core::ptr::addr_of!((*cred).fsgid).read();
            Self {
                uid: bindings::from_kuid(&raw mut bindings::init_user_ns, fsuid),
                gid: bindings::from_kgid(&raw mut bindings::init_user_ns, fsgid),
                pid: 0,
            }
        }
    }

    /// The identity an open file authorizes reads under.
    ///
    /// # Safety
    ///
    /// `file` must point at a live `struct file`.
    pub unsafe fn of_file(file: *const bindings::file) -> Self {
        // SAFETY: the caller promises `file` is live; `f_cred` is stable for
        // the file's life.
        unsafe { Self::of_cred((*file).f_cred) }
    }

    /// The filesystem uid and gid of the current task, which the kernel checks
    /// filesystem permission with.
    pub fn current() -> Self {
        let task = kernel::current!().as_ptr();
        // SAFETY: `task` is the current task, whose credentials pointer is
        // stable for the task's own reads; the credential it names lives as
        // long as the task holds it, which it does for the whole of this call.
        let mut caller = unsafe { Self::of_cred(core::ptr::addr_of!((*task).cred).read()) };
        caller.pid = u32::try_from(kernel::current!().pid()).unwrap_or(0);
        caller
    }
}

/// What the kernel's interface takes for each variable part of a message,
/// from this kernel's own headers.
pub const LIMITS: Limits = Limits {
    name_max: bindings::NAME_MAX,
    path_max: bindings::PATH_MAX,
    xattr_name_max: bindings::XATTR_NAME_MAX,
    xattr_size_max: bindings::XATTR_SIZE_MAX,
    xattr_list_max: bindings::XATTR_LIST_MAX,
};

/// The bytes a request frame of body `Q` with `payload` bytes of payload takes.
pub const fn request_len<Q: RequestBody>(payload: usize) -> usize {
    FrameWriter::request_len::<Q>(payload)
}

/// The bytes a successful reply of body `R` with at most `payload` bytes of
/// payload takes, which is what a reply buffer is sized to.
///
/// An error reply is shorter than any success, so a buffer that holds the
/// largest success holds every legal answer.
pub fn reply_capacity<R: ResponseBody>(payload: usize) -> usize {
    FRAME_HEADER_LEN + RESPONSE_HEAD_LEN + size_of::<R>() + payload
}

/// Encodes one request frame into `buffer`, and returns the bytes of the frame.
pub fn encode<'a, Q: RequestBody>(
    buffer: &'a mut [u8],
    request_id: u64,
    caller: Caller,
    node_id: u64,
    body: &Q,
    payload: &[u8],
) -> core::result::Result<&'a [u8], FramingError> {
    let head = RequestHead::new(node_id, caller.uid, caller.gid, caller.pid);
    let mut writer = FrameWriter::request(buffer, &LIMITS, request_id, &head, body)?;
    writer.payload(payload)?;
    writer.finish()
}

/// How reading one message off a stream ended.
#[derive(Debug)]
pub enum ReadFrame {
    /// The length of the message, whose bytes are at the front of the buffer,
    /// and what follows it on the stream.
    Whole(usize, Follows),
    /// The stream closed before a complete header arrived. The transport
    /// intentionally unifies zero-byte and partial-header closure: neither
    /// supplies a usable message, and both end this connection.
    HeaderClosed,
    /// The message needs more bytes than the caller's buffer holds. What was
    /// read is in the buffer; nothing more was read.
    BufferTooSmall {
        /// The length the parser asked for.
        declared: usize,
        /// How much of it is in the buffer.
        have: usize,
    },
}

/// What a message read can run into.
#[derive(Debug)]
pub enum ReadError {
    /// The transport failed, or the stream ended inside a message.
    Transport(Error),
    /// The bytes were not a message this connection may accept.
    Framing(FramingError),
}

/// Where messages are read from.
pub trait Source {
    /// Fills `buf` whole, or fails with `EPIPE` when the source ends first.
    fn receive_exact(&self, buf: &mut [u8]) -> Result;

    /// Reads and drops `len` bytes.
    fn discard(&self, len: usize) -> Result;
}

impl Source for Stream {
    fn receive_exact(&self, buf: &mut [u8]) -> Result {
        Stream::receive_exact(self, buf)
    }

    fn discard(&self, len: usize) -> Result {
        Stream::discard(self, len)
    }
}

/// The bytes of a reply the server stored, read from the front.
pub struct Kept<'a>(core::cell::Cell<&'a [u8]>);

impl<'a> Kept<'a> {
    /// A source of the bytes `kept`.
    pub fn new(kept: &'a [u8]) -> Self {
        Self(core::cell::Cell::new(kept))
    }

    /// Whether every byte was read.
    pub fn is_empty(&self) -> bool {
        self.0.get().is_empty()
    }

    fn take(&self, len: usize) -> Result<&'a [u8]> {
        let rest = self.0.get();
        let front = rest.get(..len).ok_or(EPIPE)?;
        self.0.set(&rest[len..]);
        Ok(front)
    }
}

impl Source for Kept<'_> {
    fn receive_exact(&self, buf: &mut [u8]) -> Result {
        buf.copy_from_slice(self.take(buf.len())?);
        Ok(())
    }

    fn discard(&self, len: usize) -> Result {
        self.take(len).map(|_| ())
    }
}

/// Reads the header of the next message into `header`.
pub fn read_header(
    source: &impl Source,
    header: &mut [u8; FRAME_HEADER_LEN],
) -> core::result::Result<bool, ReadError> {
    match source.receive_exact(header) {
        Ok(()) => Ok(true),
        // receive_exact does not retain progress on failure. A close before
        // or during the header ends the connection without a usable message.
        Err(error) if error == EPIPE => Ok(false),
        Err(error) => Err(ReadError::Transport(error)),
    }
}

/// Reads the rest of a message whose first `have` bytes are already at the
/// front of `buffer`, asking the parser each time how much it needs.
///
/// Nothing after the message is read.
pub fn read_rest(
    source: &impl Source,
    buffer: &mut [u8],
    mut have: usize,
) -> core::result::Result<ReadFrame, ReadError> {
    loop {
        let needed =
            match Frame::parse_prefix(&buffer[..have], &LIMITS).map_err(ReadError::Framing)? {
                Parsed::Frame(frame) => return Ok(ReadFrame::Whole(frame.len(), frame.follows())),
                Parsed::Need(needed) => needed,
            };
        let Some(rest) = buffer.get_mut(have..needed) else {
            return Ok(ReadFrame::BufferTooSmall {
                declared: needed,
                have,
            });
        };
        source.receive_exact(rest).map_err(ReadError::Transport)?;
        have = needed;
    }
}

/// What a length word opened.
pub enum Piece {
    /// A piece of this many bytes.
    Of(u32),
    /// The closing piece.
    Closing(Closing),
}

/// Reads one length word, and the closing piece when it opens one.
pub fn read_piece(source: &impl Source) -> core::result::Result<Piece, ReadError> {
    let mut len = [0u8; PIECE_LEN_LEN];
    source
        .receive_exact(&mut len)
        .map_err(ReadError::Transport)?;
    match piece::read_length(&len) {
        0 => {
            let mut body = [0u8; CLOSING_LEN];
            source
                .receive_exact(&mut body)
                .map_err(ReadError::Transport)?;
            ClosingBody::parse(&body)
                .map(Piece::Closing)
                .map_err(ReadError::Framing)
        }
        len => Ok(Piece::Of(len)),
    }
}

/// Reads and drops the pieces of a streamed message up to and including its
/// closing piece, each through [`Stream::discard`]. `bound` is the most one
/// piece may declare; nothing is sized by what a piece declares.
pub fn drain_pieces(stream: &Stream, bound: u64) -> core::result::Result<Closing, ReadError> {
    loop {
        match read_piece(stream)? {
            Piece::Closing(closing) => return Ok(closing),
            Piece::Of(len) => {
                piece::check(len, bound).map_err(ReadError::Framing)?;
                stream.discard(len as usize).map_err(ReadError::Transport)?;
            }
        }
    }
}

/// Reads and drops a whole message the reader will not keep, whose header is
/// already read, and whatever streams after it.
///
/// The message is understood, not skipped by a total: its fixed part is read
/// through a stack buffer, its variable parts are dropped by the lengths the
/// parser asks for, and its pieces are dropped one by one. Nothing is
/// allocated, so dropping a message cannot fail for memory.
pub fn drain_message(
    stream: &Stream,
    header: &[u8; FRAME_HEADER_LEN],
) -> core::result::Result<(), ReadError> {
    let mut scratch = [0u8; SCRATCH_LEN];
    scratch[..FRAME_HEADER_LEN].copy_from_slice(header);
    let follows = match read_rest(stream, &mut scratch, FRAME_HEADER_LEN)? {
        ReadFrame::Whole(_, follows) => follows,
        ReadFrame::HeaderClosed => Follows::Nothing,
        // A fixed part the stack buffer cannot hold is one no notification
        // has, and the stream cannot be read past it.
        ReadFrame::BufferTooSmall { have, .. } if have == FRAME_HEADER_LEN => {
            return Err(ReadError::Framing(FramingError::LengthOverflow));
        }
        // The fixed part is read, so what the parser still asks for is the
        // variable parts, which only a message that streams nothing carries.
        ReadFrame::BufferTooSmall { declared, have } => {
            stream
                .discard(declared - have)
                .map_err(ReadError::Transport)?;
            Follows::Nothing
        }
    };
    match follows {
        Follows::Nothing => Ok(()),
        Follows::Data(len) => stream.discard(len as usize).map_err(ReadError::Transport),
        Follows::Pieces(kind) => {
            let bound = kind.piece_bound(&LIMITS).map_or(u64::MAX, u64::from);
            drain_pieces(stream, bound).map(|_| ())
        }
    }
}

/// A bounded wait for one transfer, as a jiffies count the wait primitives
/// take.
pub fn jiffies_of(delta: Delta) -> kernel::time::Jiffies {
    let millis = delta.as_millis().max(1);
    kernel::time::msecs_to_jiffies(u32::try_from(millis).unwrap_or(u32::MAX))
}
