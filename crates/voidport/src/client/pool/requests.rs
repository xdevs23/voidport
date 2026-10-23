use std::sync::Arc;

use voidport_proto::error::FramingError;
use voidport_proto::frame::Frame;
use voidport_proto::limits::LIMITS;
use voidport_proto::message::{RequestBody, ResponseOutcome};
use voidport_proto::opcode::Opcode;
use voidport_proto::ops::connection::{OutcomeRequest, OutcomeResponse, RetireRequest};
use voidport_proto::ops::file::ReleaseResponse;
use voidport_proto::ops::node::ForgetRequest;
use voidport_proto::piece::Closing;
use voidport_session::owed::{Lookups, Owed};
use voidport_session::pool::Retire;
use voidport_session::replay::OpenFlags;
use voidport_session::settling::{
    Attempted, Fate, ForgetSent, ForgetSettled, OutcomeAnswer, Unsettled, attempted, forget_sent,
    forget_settled, read_outcome,
};
use zerocopy::byteorder::little_endian::U64;

use super::{Checkout, Pool};
use crate::client::connection::{
    Answer, Data, Destination, Forget, Forgotten, Nothing, Unsent, encode,
};
use crate::client::ops::release_request;
use crate::client::{Caller, Entry, reply_value};

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

    async fn retire(self: Arc<Self>, retire: Retire) {
        let body = RetireRequest {
            connection_id: U64::new(retire.connection_id),
        };
        if let Err(unsent) = self.deliver(Opcode::Retire, &body).await {
            tracing::error!(
                ?unsent,
                connection_id = retire.connection_id,
                "a retire request could not be sent"
            );
        }
    }

    /// Forgets the lookups and releases the handle that a reply counted on the
    /// server, for a reply the kernel never learned of.
    pub(crate) async fn undo_counted(self: &Arc<Self>, caller: Caller, counted: Counted) {
        self.forget_each(caller, &counted.lookups).await;
        if let Some(handle) = counted.handle {
            self.release(handle).await;
        }
    }

    /// One lookup of each node.
    pub(crate) async fn forget_each(self: &Arc<Self>, caller: Caller, nodes: &[u64]) {
        let forgets: Vec<Forget> = nodes
            .iter()
            .map(|&node_id| Forget {
                caller,
                node_id,
                nlookup: 1,
            })
            .collect();
        self.forget(&forgets).await;
    }

    /// Sent again after a loss, it closes nothing more: the server returns
    /// `EBADF` for a handle it no longer has.
    async fn release(self: &Arc<Self>, handle: u64) {
        let body = release_request(handle, 0, None, false);
        let answer = match self.deliver(Opcode::Release, &body).await {
            Ok(Some(answer)) => answer,
            Ok(None) => return,
            Err(unsent) => {
                tracing::error!(?unsent, handle, "a release could not be sent");
                return;
            }
        };
        match reply_value::<ReleaseResponse, ()>(&answer.frame, |_, _| Ok(())) {
            Ok(Ok(())) => {}
            Ok(Err(errno)) => {
                tracing::warn!(%errno, handle, "a handle the kernel never learned of stays open");
            }
            Err(fault) => tracing::error!(%fault, handle, "the answer to a release is unreadable"),
        }
    }

    /// `None` when the session ended first. A session that ends first ends what
    /// the request refers to along with it.
    async fn deliver<Q: RequestBody>(
        self: &Arc<Self>,
        opcode: Opcode,
        body: &Q,
    ) -> Result<Option<Answer>, Unsent> {
        match self.call_until_answered(opcode, body, Nothing).await {
            Ok((connection, Nothing, answer)) => {
                connection.give_back();
                Ok(Some(answer))
            }
            Err(Uncarried::Ended) => Ok(None),
            Err(Uncarried::Unsent(unsent)) => Err(unsent),
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

/// What a reply counted on the server, which the kernel learns of only
/// through that reply.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Counted {
    pub(crate) lookups: Vec<u64>,
    pub(crate) handle: Option<u64>,
}

impl Counted {
    pub(crate) fn nothing<T>(_: &T) -> Self {
        Self::default()
    }

    pub(crate) fn lookup(entry: &Entry) -> Self {
        Self {
            lookups: vec![entry.node_id],
            handle: None,
        }
    }

    /// Whether these are the references that `owed` names for the opcode.
    pub(crate) fn fits(&self, owed: Owed) -> bool {
        let lookups = match owed.forget {
            Lookups::None => self.lookups.is_empty(),
            Lookups::One => self.lookups.len() == 1,
            Lookups::EveryEntry => true,
        };
        lookups && self.handle.is_some() == owed.release
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
