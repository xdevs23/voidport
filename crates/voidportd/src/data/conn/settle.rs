use std::sync::Arc;

use rustix::io::Errno;
use voidport_proto::frame::{Frame, FrameWriter};
use voidport_proto::limits::LIMITS;
use voidport_proto::opcode::Opcode;
use voidport_proto::ops::connection::{
    OutcomeRequest, OutcomeResponse, RetireRequest, RetireResponse, outcome_state,
};
use voidport_proto::piece::{self, Closing};
use zerocopy::byteorder::little_endian::U32;

use super::super::ops;
use super::super::session::Outcome;
use super::super::wire::Out as _;
use super::{Connection, Replies};

/// Closes the named connection if it is still open and waits until every
/// request read from it has ended, so what the session kept about it is final.
///
/// When the connection this request arrived on closes during the wait, the
/// request is cancelled and counts as never started, and the client sends it
/// again. Two requests that name the connections of each other both end that
/// way, because each closes the connection of the other before it waits.
pub(super) async fn settle<P: Replies>(
    connection: Arc<Connection<P>>,
    bytes: Vec<u8>,
    opcode: Opcode,
) {
    let Ok(frame) = Frame::parse(&bytes, &LIMITS) else {
        return connection.stop();
    };
    let request_id = frame.request_id();
    let named = match opcode {
        Opcode::Outcome => frame
            .request::<OutcomeRequest>()
            .map(|request| request.body().connection_id.get()),
        _ => frame
            .request::<RetireRequest>()
            .map(|request| request.body().connection_id.get()),
    };
    let named = match named {
        Ok(named) => named,
        Err(error) => return connection.poison(&error),
    };
    if named == connection.link.id() {
        return connection.refuse(request_id, opcode, Errno::INVAL).await;
    }
    match connection.session.link(named) {
        Ok(link) => {
            link.stop();
            let mut own = connection.stopped();
            tokio::select! {
                biased;
                _ = own.wait_for(|stopped| *stopped) => return,
                () = link.ended() => {}
            }
        }
        Err(Errno::STALE) => {}
        Err(errno) => return connection.refuse(request_id, opcode, errno).await,
    }
    // Asked again after the connection has ended: one from which nothing was
    // read is no longer held.
    match (opcode, connection.session.link(named)) {
        (Opcode::Retire, Ok(link)) => {
            connection.session.retire(&link);
            retired(&connection, request_id).await;
        }
        // Retiring an already retired connection returns what the first time did.
        (Opcode::Retire, Err(Errno::STALE)) => retired(&connection, request_id).await,
        (_, Ok(link)) => {
            let asked = match frame.request::<OutcomeRequest>() {
                Ok(request) => request.body().request_id.get(),
                Err(error) => return connection.poison(&error),
            };
            answer_outcome(&connection, request_id, link.outcome(asked)).await;
        }
        (_, Err(errno)) => connection.refuse(request_id, opcode, errno).await,
    }
}

async fn retired<P: Replies>(connection: &Connection<P>, request_id: u64) {
    match ops::encode_outcome(
        request_id,
        Opcode::Retire,
        Ok(RetireResponse {
            reserved: U32::ZERO,
        }),
    ) {
        Ok(reply) => connection.answer(request_id, &reply).await,
        Err(error) => connection.poison(&error),
    }
}

async fn answer_outcome<P: Replies>(connection: &Connection<P>, request_id: u64, outcome: Outcome) {
    let (state, kept) = match outcome {
        Outcome::NotStarted => (outcome_state::NOT_STARTED, None),
        Outcome::Applied => (outcome_state::APPLIED, None),
        Outcome::Replied(kept) => (outcome_state::REPLIED, Some(kept)),
    };
    let mut head = [0u8; FrameWriter::response_len::<OutcomeResponse>(0)];
    let head = match FrameWriter::response(
        &mut head,
        &LIMITS,
        request_id,
        &OutcomeResponse {
            state: U32::new(state),
            reserved: U32::ZERO,
        },
    )
    .and_then(FrameWriter::finish)
    {
        Ok(head) => head,
        Err(error) => return connection.poison(&error),
    };
    let length = match kept
        .as_deref()
        .map(|kept| piece::length(kept.len()))
        .transpose()
    {
        Ok(length) => length,
        Err(error) => return connection.poison(&error),
    };
    let Ok(mut sink) = connection.sink(request_id).await else {
        return;
    };
    connection.retire(request_id);
    let mut written = sink.put(head).await;
    if let (Ok(()), Some(length), Some(kept)) = (&written, length, &kept) {
        written = match sink.put(&length).await {
            Ok(()) => sink.put(kept).await,
            Err(error) => Err(error),
        };
    }
    if written.is_err()
        || sink.put(&Closing::done(false).encode()).await.is_err()
        || sink.flush().await.is_err()
    {
        connection.stop();
    }
}
