// SPDX-License-Identifier: GPL-2.0

//! The voidport session handshake, encoded and validated by the workspace's
//! own wire crate.
//!
//! Nothing here knows about the transport, and nothing outside it knows about
//! the wire: the frame bytes are produced and checked by exactly the code the
//! userspace client uses, consumed by path from the workspace. That is what
//! makes this probe a measurement of the wire and not of a second
//! implementation of it. What this module keeps of the kernel is its error
//! type and its log, where a framing fault is reported while the detail
//! carrying it is still in hand.

use kernel::prelude::*;
use voidport_proto::frame::{Frame, FrameWriter, FRAME_HEADER_LEN, MAX_HELLO_FRAME_LEN};
use voidport_proto::message::{RequestHead, ResponseOutcome};
use voidport_proto::ops::handshake::{HelloReply, HelloRequest};
use voidport_proto::PROTOCOL_VERSION;
use zerocopy::byteorder::little_endian::U32;

/// The handshake is a connection's first request, and request ids start at one
/// per connection.
const HELLO_REQUEST_ID: u64 = 1;

/// What the server answered the handshake with.
pub(crate) enum Outcome {
    /// The session is open, and these are its terms.
    Accepted {
        /// Node id of the session's mount root.
        root_node_id: u64,
        /// The protocol version the server accepted.
        protocol_version: u32,
        /// The frame bound for the rest of the session.
        max_frame_len: u32,
    },
    /// A negated errno: the refusal classes the handshake defines, answered as
    /// a response before the server closes.
    Refused(i32),
}

/// The buffer size both directions of the handshake are bounded by.
///
/// Before a session exists there is no negotiated bound, so the pre-handshake
/// one is the only bound there is, and both buffers are sized to it.
pub(crate) const BUFFER_LEN: usize = MAX_HELLO_FRAME_LEN as usize;

/// Encodes the `Hello` naming `namespace` into `buf`, returning the frame.
pub(crate) fn encode_hello<'a>(buf: &'a mut [u8], namespace: &[u8]) -> Result<&'a [u8]> {
    let body = HelloRequest {
        protocol_version: U32::new(PROTOCOL_VERSION),
        flags: U32::ZERO,
        namespace_len: U32::new(u32::try_from(namespace.len()).map_err(|_| EINVAL)?),
        subpath_len: U32::ZERO,
        auth_len: U32::ZERO,
    };
    // The handshake names no node and no caller, so its request head is zero:
    // uniformity beats a special case.
    let head = RequestHead::new(0, 0, 0, 0);
    let mut writer = FrameWriter::request(buf, MAX_HELLO_FRAME_LEN, HELLO_REQUEST_ID, &head, &body)
        .map_err(framing)?;
    writer.payload(namespace).map_err(framing)?;
    writer.finish().map_err(framing)
}

/// Reads one reply frame into `buf` through `fill` and answers what it says.
///
/// The read is split the way a stream demands — the header first, then the
/// body the header sizes — and that split is the reason this lives here: the
/// frame's shape is this module's alone. `fill` moves exactly as many bytes as
/// the slice it is handed, and the frame's own length is answered with the
/// outcome because it is the only count a caller can report.
pub(crate) fn read_reply(
    buf: &mut [u8],
    mut fill: impl FnMut(&mut [u8]) -> Result,
) -> Result<(Outcome, usize)> {
    // The bound a peer is held to is the smaller of the handshake's maximum
    // and what this buffer can hold, applied by the wire crate before any read
    // is sized from it: a peer cannot ask this module to hold what it has not
    // got, and cannot ask it for more than the handshake allows either.
    let bound = u32::try_from(buf.len())
        .unwrap_or(u32::MAX)
        .min(MAX_HELLO_FRAME_LEN);
    fill(buf.get_mut(..FRAME_HEADER_LEN).ok_or(EINVAL)?)?;
    let total = declared_len(&buf[..FRAME_HEADER_LEN], bound)?;
    fill(buf.get_mut(FRAME_HEADER_LEN..total).ok_or(EINVAL)?)?;
    Ok((parse_reply(&buf[..total])?, total))
}

/// The total length of the frame whose header fills `header`, bounded.
fn declared_len(header: &[u8], bound: u32) -> Result<usize> {
    let len = Frame::peek_len(header, bound)
        .map_err(framing)?
        .ok_or(EINVAL)?;
    usize::try_from(len).map_err(|_| EINVAL)
}

/// Validates a complete `HelloReply` frame against the request it answers.
fn parse_reply(bytes: &[u8]) -> Result<Outcome> {
    let frame = Frame::parse(bytes, MAX_HELLO_FRAME_LEN).map_err(framing)?;
    if frame.request_id() != HELLO_REQUEST_ID {
        pr_err!(
            "voidport probe: the reply answers request {}, and the handshake is request {}\n",
            frame.request_id(),
            HELLO_REQUEST_ID
        );
        return Err(EINVAL);
    }
    match frame.response::<HelloReply>().map_err(framing)? {
        ResponseOutcome::Success(reply) => {
            let body = reply.body();
            Ok(Outcome::Accepted {
                root_node_id: body.root_node_id.get(),
                protocol_version: body.protocol_version.get(),
                max_frame_len: body.max_frame_len.get(),
            })
        }
        ResponseOutcome::Error(status) => Ok(Outcome::Refused(status)),
    }
}

/// Reports a framing fault to the kernel log and answers the caller's error.
///
/// The wire crate's fault type carries which rule was broken; the kernel's
/// error type cannot, so the detail is logged where it is still known.
fn framing(error: voidport_proto::error::FramingError) -> Error {
    pr_err!(
        "voidport probe: the frame breaks the wire's framing rules: {:?}\n",
        error
    );
    EINVAL
}
