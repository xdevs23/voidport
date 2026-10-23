use std::sync::Arc;

use voidport_proto::error::FramingError;
use voidport_proto::frame::Frame;
use voidport_proto::limits::LIMITS;
use voidport_proto::message::{RequestBody, ResponseOutcome};
use voidport_proto::opcode::Opcode;
use voidport_proto::ops::connection::{OutcomeRequest, OutcomeResponse, RetireRequest};
use voidport_proto::ops::node::ForgetRequest;
use voidport_proto::piece::Closing;
use voidport_session::pool::Retire;
use voidport_session::replay::OpenFlags;
use voidport_session::settling::{
    Attempted, Fate, ForgetSent, ForgetSettled, OutcomeAnswer, Unsettled, attempted, forget_sent,
    forget_settled, read_outcome,
};
use zerocopy::byteorder::little_endian::U64;

use super::{Checkout, Pool};
use crate::client::Caller;
use crate::client::connection::{
    Answer, Data, Destination, Forget, Forgotten, Nothing, Unsent, encode,
};

/// A forget has no reply.
const NO_REPLY: usize = 0;

enum Uncarried {
    Unsent(Unsent),
    Ended,
}

impl Pool {
    /// `bound` is the most bytes the reply that the server kept for that request
    /// can take.
    pub async fn ask(self: &Arc<Self>, question: OutcomeRequest, bound: usize) -> Fate<Data> {
        let destination = Data::new(self.memory.buffer(bound, 1).await);
        let (connection, reply, answer) = match self
            .call_until_answered(Opcode::Outcome, &question, destination)
            .await
        {
            Ok(answered) => answered,
            Err(Uncarried::Ended) => return Fate::Ended,
            Err(Uncarried::Unsent(_)) => return Fate::Unsettled(Unsettled::Unanswerable),
        };
        let fate = match outcome_answer(&answer.frame, answer.closing) {
            Ok(outcome) => read_outcome(outcome, reply),
            Err(fault) => {
                connection.poison(fault);
                Fate::Unsettled(Unsettled::Unanswerable)
            }
        };
        connection.give_back();
        fate
    }

    /// Any answer ends the retire and is not read.
    async fn retire(self: Arc<Self>, retire: Retire) {
        let body = RetireRequest {
            connection_id: U64::new(retire.connection_id),
        };
        match self
            .call_until_answered(Opcode::Retire, &body, Nothing)
            .await
        {
            Ok((connection, Nothing, _)) => {
                connection.give_back();
            }
            Err(Uncarried::Ended) => {}
            Err(Uncarried::Unsent(unsent)) => tracing::error!(
                ?unsent,
                connection_id = retire.connection_id,
                "a retire request could not be sent"
            ),
        }
    }

    pub(super) fn spawn_retire(self: &Arc<Self>, retire: Retire) {
        let pool = Arc::clone(self);
        self.runtime.spawn(pool.retire(retire));
    }

    /// `destination` is always [`Destination::restartable`], and is made ready
    /// again before each resend.
    async fn call_until_answered<Q: RequestBody, D: Destination>(
        self: &Arc<Self>,
        opcode: Opcode,
        body: &Q,
        mut destination: D,
    ) -> Result<(Checkout, D, Answer), Uncarried> {
        loop {
            let connection = self.take().await.map_err(|_| Uncarried::Ended)?;
            let (ticket, frame) = match connection.compose(
                opcode,
                OpenFlags::NONE,
                Caller::default(),
                0,
                body,
                &[],
            ) {
                Ok(composed) => composed,
                Err(unsent) => {
                    connection.give_back();
                    return Err(Uncarried::Unsent(unsent));
                }
            };
            let (returned, attempt) = connection.call(ticket, &frame, &[], destination).await;
            destination = returned;
            match attempted(attempt) {
                Attempted::Answered(answer) => return Ok((connection, destination, answer)),
                Attempted::SendAgain => {
                    connection.lost();
                    connection.give_back();
                    destination.restart();
                }
            }
        }
    }

    pub(super) async fn settle_forgets(self: &Arc<Self>, lost_id: u64, forgets: Vec<Forgotten>) {
        for forgotten in forgets {
            let question = OutcomeRequest {
                connection_id: U64::new(lost_id),
                request_id: U64::new(forgotten.request_id),
            };
            match forget_settled(self.ask(question, NO_REPLY).await) {
                ForgetSettled::Done | ForgetSettled::Unknown(_) => {}
                ForgetSettled::SendAgain => self.forget(&[forgotten.forget]).await,
                ForgetSettled::SessionEnded => return,
            }
        }
    }

    /// Sends `forgets` in order, back to back on one connection, and moves the
    /// rest to another connection only when that one is lost.
    pub async fn forget(self: &Arc<Self>, forgets: &[Forget]) {
        let mut unsent = forgets;
        while !unsent.is_empty() {
            let Ok(connection) = self.take().await else {
                // The session ended: its nodes went with it.
                return;
            };
            unsent = write_forgets(&connection, unsent).await;
            connection.give_back();
        }
    }
}

/// Each forget is recorded on `connection` before it is written, so the loss of
/// that connection settles it. Returns the forgets that follow a loss.
async fn write_forgets<'f>(connection: &Checkout, forgets: &'f [Forget]) -> &'f [Forget] {
    for (at, &forget) in forgets.iter().enumerate() {
        let Ok(request_id) = connection.take_request_id() else {
            return &forgets[at + 1..];
        };
        let body = ForgetRequest {
            nlookup: U64::new(forget.nlookup),
        };
        let Ok(frame) = encode(request_id, forget.caller, forget.node_id, &body, &[]) else {
            tracing::error!("a forget could not be encoded");
            continue;
        };
        connection.wrote_forget(Forgotten { request_id, forget });
        if let ForgetSent::Lost = forget_sent(connection.send(&frame).await) {
            let send_again = connection.withdraw_forget(request_id);
            connection.lost();
            return if send_again {
                &forgets[at..]
            } else {
                &forgets[at + 1..]
            };
        }
    }
    &[]
}

fn outcome_answer(frame: &[u8], closing: Option<Closing>) -> Result<OutcomeAnswer, FramingError> {
    let stale = rustix::io::Errno::STALE.raw_os_error();
    match Frame::parse(frame, &LIMITS)?.response::<OutcomeResponse>()? {
        ResponseOutcome::Success(response) => {
            OutcomeAnswer::of_state(response.body().state.get(), closing, stale)
        }
        ResponseOutcome::Error(status) => OutcomeAnswer::of_refusal(status, stale),
    }
}
