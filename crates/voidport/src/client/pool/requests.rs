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
use crate::client::connection::{Answer, Data, Destination, Forgotten, Nothing, Unsent, encode};

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
                ForgetSettled::SendAgain => {
                    self.forget(forgotten.caller, forgotten.node_id, forgotten.nlookup)
                        .await;
                }
                ForgetSettled::SessionEnded => return,
            }
        }
    }

    /// The forget is recorded on its connection before it is written, so the
    /// loss of that connection settles it.
    pub async fn forget(self: &Arc<Self>, caller: Caller, node_id: u64, nlookup: u64) {
        loop {
            let Ok(connection) = self.take().await else {
                // The session ended: its nodes went with it.
                return;
            };
            let Ok(request_id) = connection.take_request_id() else {
                connection.give_back();
                return;
            };
            let body = ForgetRequest {
                nlookup: U64::new(nlookup),
            };
            let Ok(frame) = encode(request_id, caller, node_id, &body, &[]) else {
                tracing::error!("a forget could not be encoded");
                connection.give_back();
                return;
            };
            connection.wrote_forget(Forgotten {
                request_id,
                caller,
                node_id,
                nlookup,
            });
            let sent = connection.send(&frame).await;
            match forget_sent(sent) {
                ForgetSent::Written => {
                    connection.give_back();
                    return;
                }
                ForgetSent::Lost => {
                    let send_again = connection.withdraw_forget(request_id);
                    connection.lost();
                    connection.give_back();
                    if !send_again {
                        return;
                    }
                }
            }
        }
    }
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
