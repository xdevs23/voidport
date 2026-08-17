//! Serving one request.
//!
//! Dispatch is total over the opcode registry, so an operation added to the
//! protocol cannot be forgotten here: the compiler names it. The two error
//! classes of the wire contract are kept strictly apart, because they have
//! opposite consequences:
//!
//! * a **framing error** poisons the byte stream — the caller closes the
//!   connection, and the session's handles and nodes tear down as on
//!   disconnect;
//! * a **semantic error** is an errno in a well-formed response, and the
//!   session lives on. An unknown opcode is the canonical case (`ENOSYS`), and
//!   so is every host errno a guest's request runs into.
//!
//! Every operation is a plain function of the session and the parsed request,
//! which is what lets the connection layer run them on the blocking pool, out
//! of order, without any of them knowing.
//!
//! One operation is not finished when its function returns: a blocking `setlk`
//! whose range is held answers [`Served::Waiting`] with a [`LockWait`], which
//! the connection layer drives as a future. That is the design's
//! waits-are-async rule — the wire request stays pending exactly as it always
//! did, but what waits is a future, not a pool thread.

mod dir;
mod file;
mod node;
mod xattr;

use rustix::io::Errno;
use voidport_proto::error::FramingError;
use voidport_proto::frame::{FRAME_HEADER_LEN, Frame, FrameWriter};
use voidport_proto::message::{RESPONSE_HEAD_LEN, ResponseBody};
use voidport_proto::opcode::Opcode;
use voidport_proto::ops::subscribe::{
    SubscribeRequest, SubscribeResponse, UnsubscribeRequest, UnsubscribeResponse,
};
use zerocopy::byteorder::little_endian::U32;

pub use file::LockWait;

use super::session::Session;
use crate::rules::Name;

/// What serving a request produced.
#[derive(Debug)]
pub enum Served {
    /// A response frame to write back.
    Reply(Vec<u8>),
    /// Nothing: `forget` is the one request with no response.
    Silent,
    /// The request is parked on a lock another owner holds. The caller drives
    /// the wait and writes whatever it produces; dropping it cancels the wait,
    /// which is what a dead connection does.
    Waiting(LockWait),
    /// A confirm frame to write back, **and then** register the session's share
    /// subscription.
    ///
    /// The order is the contract: "the confirm reply always precedes the first
    /// snapshot part". Registration is what queues the snapshot, so it happens
    /// after the confirm is on the reply queue — which the connection layer
    /// does, because it is the only place that owns that queue.
    Subscribed(Vec<u8>),
}

/// The outcome of one operation: an encoded response frame, or the errno to
/// answer with.
type OpResult = Result<Vec<u8>, Errno>;

/// Serves one request frame.
///
/// # Errors
///
/// Returns a [`FramingError`] for anything that poisons the stream: a
/// malformed frame, a response arriving at the server, a repeated `Hello`.
/// Everything else is answered.
pub fn serve(session: &Session, bytes: &[u8], max_frame_len: u32) -> Result<Served, FramingError> {
    let frame = Frame::parse(bytes, max_frame_len)?;
    let request_id = frame.request_id();
    let opcode = match frame.opcode() {
        Ok(opcode) => opcode,
        Err(unknown) => {
            // The envelope must still be well framed before an unknown opcode
            // can be called a *semantic* error, not a framing one.
            frame.request_head()?;
            let mut buffer = error_buffer();
            let frame = FrameWriter::error_response_raw(
                &mut buffer,
                max_frame_len,
                request_id,
                unknown.0,
                status(Errno::NOSYS),
            )?;
            return Ok(Served::Reply(frame.to_vec()));
        }
    };
    if opcode == Opcode::Hello {
        // A session accepts exactly one handshake, and the connection layer has
        // already consumed it. The contract makes a repeated one a framing
        // error of its own, and the operator log says exactly that.
        return Err(FramingError::RepeatedHandshake);
    }
    if opcode == Opcode::Forget {
        node::forget(session, &frame)?;
        return Ok(Served::Silent);
    }

    let context = Context {
        session,
        max_frame_len,
        request_id,
    };
    if opcode == Opcode::Subscribe {
        // Handled before dispatch because the confirm and the registration are
        // ordered against each other, and only the connection layer can order
        // them: it owns the reply queue the confirm goes on.
        frame.request::<SubscribeRequest>()?;
        let outcome = if session.is_tombstoned() {
            // The namespace is gone and a tombstone can never change again, so
            // a stream over it could only ever say nothing.
            Err(Errno::NOENT)
        } else {
            context.reply(&SubscribeResponse {
                reserved: U32::ZERO,
            })
        };
        return Ok(match outcome {
            Ok(bytes) => Served::Subscribed(bytes),
            Err(errno) => Served::Reply(error_reply(max_frame_len, request_id, opcode, errno)?),
        });
    }
    if opcode == Opcode::Unsubscribe {
        // Nothing to order here: unsubscribing enqueues nothing, so it is done
        // where it is decided. A session that is not subscribed answers plain
        // success — that is what makes the op idempotent, replay included.
        frame.request::<UnsubscribeRequest>()?;
        session.unsubscribe();
        let outcome = context.reply(&UnsubscribeResponse {
            reserved: U32::ZERO,
        });
        return Ok(Served::Reply(match outcome {
            Ok(bytes) => bytes,
            Err(errno) => error_reply(max_frame_len, request_id, opcode, errno)?,
        }));
    }
    if opcode == Opcode::Setlk {
        // Handled before dispatch because it is the one operation that may not
        // be finished when its function returns: a blocking request whose range
        // is held hands back a wait instead of a frame.
        return Ok(match file::setlk(&context, frame.request()?) {
            Ok(file::Locked::Answered(bytes)) => Served::Reply(bytes),
            Ok(file::Locked::Waiting(wait)) => Served::Waiting(wait),
            Err(errno) => Served::Reply(error_reply(max_frame_len, request_id, opcode, errno)?),
        });
    }
    let outcome = dispatch(&context, opcode, &frame)?;
    let bytes = match outcome {
        Ok(bytes) => bytes,
        Err(errno) => error_reply(max_frame_len, request_id, opcode, errno)?,
    };
    Ok(Served::Reply(bytes))
}

/// Routes one known opcode to its operation.
fn dispatch(
    context: &Context<'_>,
    opcode: Opcode,
    frame: &Frame<'_>,
) -> Result<OpResult, FramingError> {
    Ok(match opcode {
        // Handled before dispatch: the handshake is the connection's business,
        // `forget` has no response, `setlk` may answer with a wait, and the two
        // subscription ops are ordered against the connection's queues.
        Opcode::Hello
        | Opcode::Forget
        | Opcode::Setlk
        | Opcode::Subscribe
        | Opcode::Unsubscribe => {
            unreachable!("handled before dispatch")
        }
        Opcode::Lookup => node::lookup(context, frame.request()?),
        Opcode::Getattr => node::getattr(context, frame.request()?),
        Opcode::Setattr => node::setattr(context, frame.request()?),
        Opcode::Readlink => node::readlink(context, frame.request()?),
        Opcode::Statfs => node::statfs(context, frame.request()?),
        Opcode::Mkdir => dir::mkdir(context, frame.request()?),
        Opcode::Mknod => dir::mknod(context, frame.request()?),
        Opcode::Unlink => dir::unlink(context, frame.request()?),
        Opcode::Rmdir => dir::rmdir(context, frame.request()?),
        Opcode::Rename => dir::rename(context, frame.request()?),
        Opcode::Link => dir::link(context, frame.request()?),
        Opcode::Symlink => dir::symlink(context, frame.request()?),
        Opcode::Readdirplus => dir::readdirplus(context, frame.request()?),
        Opcode::Open => file::open(context, frame.request()?),
        Opcode::Create => file::create(context, frame.request()?),
        Opcode::Read => file::read(context, frame.request()?),
        Opcode::Write => file::write(context, frame.request()?),
        Opcode::Release => file::release(context, frame.request()?),
        Opcode::Flush => file::flush(context, frame.request()?),
        Opcode::Fsync => file::fsync(context, frame.request()?),
        Opcode::Getlk => file::getlk(context, frame.request()?),
        Opcode::Getxattr => xattr::getxattr(context, frame.request()?),
        Opcode::Setxattr => xattr::setxattr(context, frame.request()?),
        Opcode::Listxattr => xattr::listxattr(context, frame.request()?),
        Opcode::Removexattr => xattr::removexattr(context, frame.request()?),
    })
}

/// What every operation needs besides its own request.
#[derive(Clone, Copy)]
pub struct Context<'a> {
    /// The session serving the request.
    pub session: &'a Session,
    /// The negotiated frame bound, which also bounds every reply.
    pub max_frame_len: u32,
    /// The id the reply must echo.
    pub request_id: u64,
}

impl Context<'_> {
    /// Encodes a successful response with no payload.
    fn reply<M: ResponseBody>(&self, body: &M) -> OpResult {
        self.reply_with(body, &[])
    }

    /// Encodes a successful response carrying `payload`.
    ///
    /// The frame is built **once**, in the buffer that is handed back: the
    /// writer borrows it, and only the finished length is taken out of that
    /// borrow, so the reply is never copied into a second allocation of its own
    /// size. [`file::read`] builds its frame the same way, for the same reason.
    ///
    /// An encoding failure becomes `EOVERFLOW`, not a closed
    /// connection: the request was well framed, so the client is owed an
    /// answer, and a reply that does not fit is exactly what that errno means.
    fn reply_with<M: ResponseBody>(&self, body: &M, payload: &[u8]) -> OpResult {
        let mut buffer = vec![0u8; fixed_len::<M>() + payload.len()];
        let length = {
            let mut encode = || -> Result<usize, FramingError> {
                let mut writer =
                    FrameWriter::response(&mut buffer, self.max_frame_len, self.request_id, body)?;
                writer.payload(payload)?;
                Ok(writer.finish()?.len())
            };
            encode().map_err(|error| {
                tracing::warn!(%error, "a reply could not be encoded");
                Errno::OVERFLOW
            })?
        };
        buffer.truncate(length);
        Ok(buffer)
    }

    /// The largest payload a response of type `M` can carry on this session.
    fn payload_budget<M: ResponseBody>(&self) -> usize {
        (self.max_frame_len as usize).saturating_sub(fixed_len::<M>())
    }
}

/// The fixed size of a response frame of type `M`, payload excluded.
pub(super) fn fixed_len<M: ResponseBody>() -> usize {
    FRAME_HEADER_LEN + RESPONSE_HEAD_LEN + size_of::<M>()
}

/// Encodes an operation's outcome as a payload-free response frame.
///
/// [`Context`] is the usual way to reach this, and it is the only way while a
/// request is being served. An operation that finishes *after* its function
/// returned — a lock wait — no longer has a session to borrow, so it encodes
/// its own reply through here.
pub(super) fn encode_outcome<M: ResponseBody>(
    max_frame_len: u32,
    request_id: u64,
    opcode: Opcode,
    outcome: Result<M, Errno>,
) -> Result<Vec<u8>, FramingError> {
    match outcome {
        Ok(body) => {
            let mut buffer = vec![0u8; fixed_len::<M>()];
            Ok(
                FrameWriter::response(&mut buffer, max_frame_len, request_id, &body)
                    .and_then(FrameWriter::finish)?
                    .to_vec(),
            )
        }
        Err(errno) => error_reply(max_frame_len, request_id, opcode, errno),
    }
}

/// Encodes the error response an errno answers a well-framed request with.
fn error_reply(
    max_frame_len: u32,
    request_id: u64,
    opcode: Opcode,
    errno: Errno,
) -> Result<Vec<u8>, FramingError> {
    let mut buffer = error_buffer();
    Ok(FrameWriter::error_response(
        &mut buffer,
        max_frame_len,
        request_id,
        opcode,
        status(errno),
    )?
    .to_vec())
}

/// A buffer large enough for any error response, which carries only a status.
fn error_buffer() -> [u8; FRAME_HEADER_LEN + RESPONSE_HEAD_LEN] {
    [0u8; FRAME_HEADER_LEN + RESPONSE_HEAD_LEN]
}

/// The wire status of a host errno: negated, as the response contract says.
fn status(errno: Errno) -> i32 {
    -errno.raw_os_error()
}

/// Validates a name a request carries.
///
/// The engine may assume components are single names, so the server rejects
/// `/`, `.`, `..`, the empty name and embedded NULs before resolution ever sees
/// them.
///
/// # Errors
///
/// Returns `EINVAL` for anything that is not a single path component.
fn name_of(bytes: &[u8]) -> Result<Name, Errno> {
    Name::new(bytes).map_err(|_| Errno::INVAL)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statuses_are_negated_errnos() {
        assert_eq!(status(Errno::NOENT), -2);
        assert_eq!(status(Errno::ROFS), -30);
        assert!(voidport_proto::message::is_error_status(status(
            Errno::OPNOTSUPP
        )));
    }

    #[test]
    fn only_single_components_are_accepted_as_names() {
        assert!(name_of(b"file").is_ok());
        for rejected in [&b""[..], b".", b"..", b"a/b", b"a\0b"] {
            assert_eq!(name_of(rejected), Err(Errno::INVAL));
        }
    }
}
