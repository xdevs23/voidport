//! A framing error poisons the byte stream, so the caller closes the
//! connection. A semantic error is an errno in a well-formed response, and the
//! session lives on.

pub mod dir;
pub mod file;
mod node;
mod xattr;

use rustix::io::Errno;
use voidport_memory::Buffer;
use voidport_proto::error::FramingError;
use voidport_proto::frame::{Frame, FrameWriter};
use voidport_proto::limits::LIMITS;
use voidport_proto::message::ResponseBody;
use voidport_proto::opcode::Opcode;
use voidport_proto::ops::subscribe::{
    SubscribeRequest, SubscribeResponse, UnsubscribeRequest, UnsubscribeResponse,
};
use zerocopy::byteorder::little_endian::U32;

pub use file::LockWait;

use super::cache::{Postponed, Unserved};
use super::session::Session;
use crate::rules::Name;

#[derive(Debug)]
pub enum Reply {
    Frame(Vec<u8>),
    Buffer(Buffer),
}

impl Reply {
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        match self {
            Self::Frame(bytes) => bytes,
            Self::Buffer(buffer) => buffer,
        }
    }
}

#[derive(Debug)]
pub enum Served {
    Reply(Reply),
    Silent,
    /// The request is parked on a lock of another holder. Dropping the wait
    /// cancels it, which is what a dead connection does.
    Waiting(LockWait),
    /// Nothing ran: the cache of the file delays the request. The caller waits
    /// until it may go ahead and runs it again.
    Postponed(Postponed),
    /// A confirm to write back, and then register the share subscription of the
    /// session. The confirm reply must precede the first snapshot part, and
    /// registration queues the snapshot, so the connection layer registers after
    /// the confirm is written: it has the sink.
    Subscribed(Reply),
}

#[derive(Debug, Default)]
pub struct Buffers {
    pub reply: Option<Buffer>,
    pub list: Option<Buffer>,
}

type OpResult = Result<Reply, Errno>;

pub fn serve(session: &Session, bytes: &[u8], buffers: Buffers) -> Result<Served, FramingError> {
    let frame = Frame::parse(bytes, &LIMITS)?;
    let request_id = frame.request_id();
    let opcode = frame
        .opcode()
        .map_err(|unknown| FramingError::UnknownOpcode { opcode: unknown.0 })?;
    match serve_request(session, &frame, opcode, buffers)? {
        Ok(served) => Ok(served),
        Err(errno) => Ok(Served::Reply(Reply::Frame(error_reply(
            request_id, opcode, errno,
        )?))),
    }
}

fn serve_request(
    session: &Session,
    frame: &Frame<'_>,
    opcode: Opcode,
    buffers: Buffers,
) -> Result<Result<Served, Errno>, FramingError> {
    let request_id = frame.request_id();
    if opcode == Opcode::Hello {
        // A session accepts exactly one handshake, and the connection layer has
        // already consumed it.
        return Err(FramingError::RepeatedHandshake);
    }
    if opcode == Opcode::Forget {
        node::forget(session, frame)?;
        return Ok(Ok(Served::Silent));
    }

    let context = Context {
        session,
        request_id,
    };
    if opcode == Opcode::Subscribe {
        // Handled before dispatch because the confirm and the registration are
        // ordered against each other, and only the connection layer can order
        // them: it has the sink the confirm goes through.
        frame.request::<SubscribeRequest>()?;
        let outcome = if session.is_tombstoned() {
            // The namespace is gone and a tombstone can never change again, so
            // a stream over it could only say nothing.
            Err(Errno::NOENT)
        } else {
            context.reply(&SubscribeResponse {
                reserved: U32::ZERO,
            })
        };
        return Ok(outcome.map(Served::Subscribed));
    }
    if opcode == Opcode::Unsubscribe {
        // Unsubscribing enqueues nothing, so it is done where it is decided. A
        // session that is not subscribed gets plain success, which makes the
        // operation idempotent, replay included.
        frame.request::<UnsubscribeRequest>()?;
        session.unsubscribe();
        let outcome = context.reply(&UnsubscribeResponse {
            reserved: U32::ZERO,
        });
        return Ok(outcome.map(Served::Reply));
    }
    if matches!(
        opcode,
        Opcode::Open | Opcode::Create | Opcode::Setattr | Opcode::Fsync | Opcode::Getlk
    ) {
        // Handled before dispatch because the cache of the file may delay the
        // request, which hands back a wait instead of a frame.
        let served = match opcode {
            Opcode::Open => file::open(&context, frame.request()?),
            Opcode::Create => file::create(&context, frame.request()?),
            Opcode::Fsync => file::fsync(&context, frame.request()?),
            Opcode::Getlk => file::getlk(&context, frame.request()?),
            _ => node::setattr(&context, frame.request()?),
        };
        return Ok(unserved(served.map(Served::Reply)));
    }
    if opcode == Opcode::Setlk {
        // Handled before dispatch because it may not be finished when its
        // function returns: a blocking request whose range is held hands back a
        // wait instead of a frame, and so does the cache of the file.
        let locked = file::setlk(&context, frame.request()?).map(|locked| match locked {
            file::Locked::Answered(reply) => Served::Reply(reply),
            file::Locked::Waiting(wait) => Served::Waiting(wait),
        });
        return Ok(unserved(locked));
    }
    Ok(dispatch(&context, opcode, frame, buffers)?.map(Served::Reply))
}

fn dispatch(
    context: &Context<'_>,
    opcode: Opcode,
    frame: &Frame<'_>,
    buffers: Buffers,
) -> Result<OpResult, FramingError> {
    Ok(match opcode {
        Opcode::Hello
        | Opcode::Forget
        | Opcode::Setlk
        | Opcode::Open
        | Opcode::Create
        | Opcode::Setattr
        | Opcode::Fsync
        | Opcode::Getlk
        | Opcode::Subscribe
        | Opcode::Unsubscribe => {
            unreachable!("handled before dispatch")
        }
        Opcode::Read | Opcode::Write | Opcode::Readdirplus => {
            unreachable!("served by the connection's wire")
        }
        // They name another connection of the session, wait for the recalls of
        // the session, or end a request of the connection, which only the
        // connection layer can do.
        Opcode::Outcome | Opcode::Retire | Opcode::Renew | Opcode::Cancel => {
            unreachable!("served by the connection")
        }
        Opcode::Lookup => node::lookup(context, frame.request()?),
        Opcode::Getattr => node::getattr(context, frame.request()?),
        Opcode::Readlink => node::readlink(context, frame.request()?, buffers.reply),
        Opcode::Statfs => node::statfs(context, frame.request()?),
        Opcode::Mkdir => dir::mkdir(context, frame.request()?),
        Opcode::Mknod => dir::mknod(context, frame.request()?),
        Opcode::Unlink => dir::unlink(context, frame.request()?),
        Opcode::Rmdir => dir::rmdir(context, frame.request()?),
        Opcode::Rename => dir::rename(context, frame.request()?),
        Opcode::Link => dir::link(context, frame.request()?),
        Opcode::Symlink => dir::symlink(context, frame.request()?),
        Opcode::Release => file::release(context, frame.request()?),
        Opcode::Flush => file::flush(context, frame.request()?),
        Opcode::Recalled => file::recalled(context, frame.request()?),
        Opcode::Relinquish => file::relinquish(context, frame.request()?),
        Opcode::Getxattr => xattr::getxattr(context, frame.request()?, buffers.reply),
        Opcode::Setxattr => xattr::setxattr(context, frame.request()?),
        Opcode::Listxattr => xattr::listxattr(context, frame.request()?, buffers),
        Opcode::Removexattr => xattr::removexattr(context, frame.request()?),
    })
}

fn unserved(served: Result<Served, Unserved>) -> Result<Served, Errno> {
    match served {
        Ok(served) => Ok(served),
        Err(Unserved::Failed(errno)) => Err(errno),
        Err(Unserved::Postponed(postponed)) => Ok(Served::Postponed(postponed)),
    }
}

#[derive(Clone, Copy)]
pub struct Context<'a> {
    pub session: &'a Session,
    pub request_id: u64,
}

impl Context<'_> {
    fn reply<M: ResponseBody>(&self, body: &M) -> OpResult {
        self.reply_with(body, &[])
    }

    /// The frame is built once, in the buffer that is handed back, so the reply
    /// is never copied into a second allocation.
    ///
    /// An encoding failure becomes `EOVERFLOW`, not a closed connection: the
    /// request was well framed, so the client gets an answer.
    fn reply_with<M: ResponseBody>(&self, body: &M, payload: &[u8]) -> OpResult {
        let mut buffer = vec![0u8; FrameWriter::response_len::<M>(payload.len())];
        let length = {
            let mut encode = || -> Result<usize, FramingError> {
                let mut writer =
                    FrameWriter::response(&mut buffer, &LIMITS, self.request_id, body)?;
                writer.payload(payload)?;
                Ok(writer.finish()?.len())
            };
            encode().map_err(|error| {
                tracing::warn!(%error, "a reply could not be encoded");
                Errno::OVERFLOW
            })?
        };
        buffer.truncate(length);
        Ok(Reply::Frame(buffer))
    }

    fn reply_in<M: ResponseBody>(
        &self,
        mut buffer: Buffer,
        body: &M,
        payload_len: usize,
    ) -> OpResult {
        let length = {
            let mut encode = || -> Result<usize, FramingError> {
                let mut writer =
                    FrameWriter::response(&mut buffer, &LIMITS, self.request_id, body)?;
                writer.payload_buf(payload_len)?;
                Ok(writer.finish()?.len())
            };
            encode().map_err(|error| {
                tracing::warn!(%error, "a reply could not be encoded");
                Errno::OVERFLOW
            })?
        };
        buffer.truncate(length);
        Ok(Reply::Buffer(buffer))
    }
}

/// An operation that finishes after its function returned, a lock wait, no
/// longer has a session to borrow, so it encodes its own reply through here.
pub(super) fn encode_outcome<M: ResponseBody>(
    request_id: u64,
    opcode: Opcode,
    outcome: Result<M, Errno>,
) -> Result<Vec<u8>, FramingError> {
    match outcome {
        Ok(body) => {
            let mut buffer = vec![0u8; FrameWriter::response_len::<M>(0)];
            Ok(
                FrameWriter::response(&mut buffer, &LIMITS, request_id, &body)
                    .and_then(FrameWriter::finish)?
                    .to_vec(),
            )
        }
        Err(errno) => error_reply(request_id, opcode, errno),
    }
}

pub fn error_reply(request_id: u64, opcode: Opcode, errno: Errno) -> Result<Vec<u8>, FramingError> {
    let mut buffer = [0u8; FrameWriter::ERROR_RESPONSE_LEN];
    Ok(FrameWriter::error_response(&mut buffer, request_id, opcode, status(errno))?.to_vec())
}

fn status(errno: Errno) -> i32 {
    -errno.raw_os_error()
}

/// The engine may assume components are single names, so `/`, `.`, `..`, the
/// empty name and embedded NULs are rejected before resolution.
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
