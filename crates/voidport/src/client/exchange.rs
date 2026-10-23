//! Sending a request and receiving its answer, across the losses of the
//! connections of its session and an interrupt of its caller.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use rustix::io::Errno;
use voidport_proto::error::FramingError;
use voidport_proto::message::RequestBody;
use voidport_proto::opcode::Opcode;
use voidport_proto::ops::connection::OutcomeRequest;
use voidport_session::interrupt::{Ending, InterruptClass};
use voidport_session::owed::{self, Owed};
use voidport_session::replay::OpenFlags;
use voidport_session::settling::{
    AfterLoss, Concluded, Fate, Settled, Unsettled, conclude, settled,
};
use voidport_session::table::Ticket;
use zerocopy::byteorder::little_endian::U64;

use super::connection::{Answer, Connection, Data, Destination, Unsent, kept_answer};
use super::pool::{Checkout, Counted, Placed, Pool};
use super::{Caller, Client, Interrupt, Origin, Outgoing, unencodable};

/// The caller of a request left on an interrupt, before the answer came.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Interrupted;

pub(super) enum Reply {
    Answered(Arc<Connection>, Answer),
    /// Only an operation that the session core classifies as moot is answered
    /// so.
    Moot,
}

pub(super) enum Exchanged<D> {
    /// The destination comes back with every outcome, an error before any
    /// attempt included.
    Finished(D, Result<Reply, Errno>),
    Interrupted(Late<D>),
}

impl<D: Send + 'static> Exchanged<D> {
    /// A late answer is received by a task of the session, which gives back
    /// what `counted` reads off it.
    ///
    /// # Errors
    ///
    /// [`Interrupted`] for a request whose caller left.
    pub(super) fn or_hand_over(
        self,
        counted: impl FnOnce(D, &Answer) -> Result<Counted, FramingError> + Send + 'static,
    ) -> Result<(D, Result<Reply, Errno>), Interrupted> {
        match self {
            Self::Finished(destination, outcome) => Ok((destination, outcome)),
            Self::Interrupted(late) => {
                let pool = Arc::clone(&late.pool);
                pool.finish_after_caller(late.finish(counted));
                Err(Interrupted)
            }
        }
    }
}

/// A request whose caller left on an interrupt, with the cancel sent after it.
pub(super) struct Late<D> {
    pool: Arc<Pool>,
    caller: Caller,
    opcode: Opcode,
    request_id: u64,
    attempt: Pin<Box<dyn Future<Output = (D, AttemptOutcome)> + Send>>,
}

impl<D> Late<D> {
    async fn finish(self, counted: impl FnOnce(D, &Answer) -> Result<Counted, FramingError>) {
        let (destination, outcome) = self.attempt.await;
        match outcome {
            AttemptOutcome::Finished(Ok(Reply::Answered(connection, answer))) => {
                match counted(destination, &answer) {
                    Ok(counted) => self.pool.undo_counted(self.caller, counted).await,
                    Err(fault) => {
                        tracing::error!(
                            %fault,
                            opcode = %self.opcode,
                            request_id = self.request_id,
                            "a late answer is unreadable"
                        );
                        connection.poison(fault);
                    }
                }
            }
            AttemptOutcome::Finished(Err(errno)) if owed::of(self.opcode) != Owed::NOTHING => {
                tracing::warn!(
                    %errno,
                    opcode = %self.opcode,
                    request_id = self.request_id,
                    "what an interrupted request counted on the server is unknown"
                );
            }
            // The request was not applied, or it counts nothing, or its session
            // ended. It is not sent again for a caller that left.
            AttemptOutcome::Finished(Ok(Reply::Moot) | Err(_)) | AttemptOutcome::SendAgain => {}
        }
    }
}

/// The interrupt of a request that an interrupt can cut short.
struct Cutoff(Option<(Interrupt, Ending)>);

impl Cutoff {
    fn of(interrupt: &Interrupt, opcode: Opcode, open: OpenFlags) -> Self {
        match voidport_session::interrupt::of(opcode, open) {
            InterruptClass::NeverCutShort => Self(None),
            InterruptClass::CutShort(ending) => Self(Some((interrupt.clone(), ending))),
        }
    }

    fn ending(&self) -> Option<Ending> {
        self.0.as_ref().map(|&(_, ending)| ending)
    }

    fn raised(&self) -> bool {
        self.0
            .as_ref()
            .is_some_and(|(interrupt, _)| interrupt.raised())
    }

    async fn wait(&mut self) {
        match &mut self.0 {
            Some((interrupt, _)) => interrupt.wait().await,
            None => std::future::pending().await,
        }
    }

    /// Polls `attempt` first, so a request is on its way, or queued for the
    /// writer of its connection, before an interrupt raised already ends the
    /// wait. `Err` returns the attempt once the interrupt came first.
    async fn race<F: Future + Unpin>(&mut self, mut attempt: F) -> Result<F::Output, F> {
        tokio::select! {
            biased;
            done = &mut attempt => Ok(done),
            () = self.wait() => Err(attempt),
        }
    }
}

/// A cancel of a request, sent on the connection that carries the request.
struct Cancel {
    carrier: Placed,
    request_id: u64,
}

impl Cancel {
    /// The lock on the writer of a connection is fair, and the attempt was
    /// polled first, so the cancel is written after the request, on the
    /// connection the request uses. Joined, so that the answer is still
    /// received.
    async fn joined<F: Future>(self, attempt: F) -> F::Output {
        let ((), outcome) = tokio::join!(self.carrier.cancel(self.request_id), attempt);
        outcome
    }
}

/// What became of one attempt of a request, in the session it was sent in.
enum AttemptOutcome {
    Finished(Result<Reply, Errno>),
    SendAgain,
}

/// One attempt of a request on one connection. It owns all it waits on, so a
/// task can receive its answer after its caller left.
struct Attempt {
    pool: Arc<Pool>,
    connection: Checkout,
    opcode: Opcode,
    kept: usize,
}

impl Attempt {
    async fn run<D: Destination>(
        self,
        ticket: Ticket,
        frame: Vec<u8>,
        data: &[u8],
        destination: D,
    ) -> (D, AttemptOutcome) {
        let Self {
            pool,
            connection,
            opcode,
            kept,
        } = self;
        let request_id = ticket.request_id();
        let (mut destination, outcome) = connection
            .send_request(ticket, &frame, data, destination)
            .await
            .answer()
            .await;
        let decision = match outcome {
            Ok(answer) => {
                let reply = Reply::Answered(connection.give_back(), answer);
                return (destination, AttemptOutcome::Finished(Ok(reply)));
            }
            Err(decision) => decision,
        };
        connection.lost();
        let settled = match pool.after_loss(opcode) {
            AfterLoss::Settled(unasked) => unasked.into(),
            AfterLoss::Ask => {
                let question = OutcomeRequest {
                    connection_id: U64::new(connection.id()),
                    request_id: U64::new(request_id),
                };
                settle(&pool, question, opcode, kept).await
            }
        };
        // Given back after it is settled, because the lost connection is retired
        // only once its request is.
        let connection = connection.give_back();
        let outcome = match conclude(settled, decision, destination.restartable()) {
            Concluded::Answer(reply) => {
                let answer = read_kept(&reply, request_id, opcode, &mut destination).await;
                AttemptOutcome::Finished(answer.map(|answer| Reply::Answered(connection, answer)))
            }
            Concluded::SendAgain => AttemptOutcome::SendAgain,
            Concluded::Fail => AttemptOutcome::Finished(Err(Errno::IO)),
            Concluded::Moot => AttemptOutcome::Finished(Ok(Reply::Moot)),
        };
        (destination, outcome)
    }
}

impl Client {
    /// When the connection is lost while the session lives, the request is
    /// settled on another connection of the same session as the session core
    /// decides ([`voidport_session::pool`]). When the session ends first, the
    /// replay decision of the session core for the attempt stands.
    ///
    /// A destination that cannot be restarted while its session lives, one that
    /// already received entries, fails the request instead of being sent again
    /// in that session.
    ///
    /// `kept` is the most bytes the kept reply of the server to this request can
    /// take.
    ///
    /// The interrupt of `origin` ends the request with `EINTR` wherever it would
    /// otherwise be sent, or sent again. While the request is in flight, a
    /// cancel of it follows it on the connection it uses, and
    /// [`voidport_session::interrupt::of`] sets whether the caller waits for the
    /// answer.
    pub(super) async fn exchange<Q: RequestBody, D: Destination + 'static>(
        &self,
        origin: Origin<'_>,
        opcode: Opcode,
        request: &Outgoing<'_, Q>,
        mut destination: D,
        kept: usize,
    ) -> Exchanged<D> {
        let Outgoing {
            node_id,
            open,
            body,
            payload,
            data,
        } = *request;
        let mut cutoff = Cutoff::of(origin.interrupt, opcode, open);
        loop {
            if cutoff.raised() {
                return Exchanged::Finished(destination, Err(Errno::INTR));
            }
            let pool = tokio::select! {
                biased;
                () = cutoff.wait() => continue,
                connected = self.connected() => match connected {
                    Ok(pool) => pool,
                    Err(errno) => return Exchanged::Finished(destination, Err(errno)),
                },
            };
            let taken = tokio::select! {
                biased;
                () = cutoff.wait() => continue,
                taken = pool.take() => taken,
            };
            let Ok(connection) = taken else {
                // The session ended while this request waited for a connection, so
                // the request takes the reconnect path once the mount has moved on
                // from the session, unless it is interrupted first.
                tokio::select! {
                    biased;
                    () = cutoff.wait() => {}
                    () = self.moved_on_from(&pool) => {}
                }
                continue;
            };
            let (ticket, frame) =
                match connection.compose(opcode, open, origin.caller, node_id, body, payload) {
                    Ok(composed) => composed,
                    Err(unsent) => {
                        connection.give_back();
                        return Exchanged::Finished(destination, Err(unsent_errno(unsent)));
                    }
                };
            let cancel = Cancel {
                carrier: Placed::clone(&connection),
                request_id: ticket.request_id(),
            };
            let attempt = Attempt {
                pool: Arc::clone(&pool),
                connection,
                opcode,
                kept,
            };
            let (returned, outcome) = if cutoff.ending() == Some(Ending::AnswerNow) {
                let data = data.to_vec();
                let attempt =
                    Box::pin(async move { attempt.run(ticket, frame, &data, destination).await });
                match cutoff.race(attempt).await {
                    Ok(done) => done,
                    Err(attempt) => {
                        return Exchanged::Interrupted(Late {
                            pool,
                            caller: origin.caller,
                            opcode,
                            request_id: cancel.request_id,
                            attempt: Box::pin(cancel.joined(attempt)),
                        });
                    }
                }
            } else {
                let attempt = attempt.run(ticket, frame, data, destination);
                tokio::pin!(attempt);
                match cutoff.race(attempt.as_mut()).await {
                    Ok(done) => done,
                    Err(attempt) => cancel.joined(attempt).await,
                }
            };
            destination = returned;
            match outcome {
                AttemptOutcome::Finished(outcome) => {
                    return Exchanged::Finished(destination, outcome);
                }
                AttemptOutcome::SendAgain => destination.restart(),
            }
        }
    }
}

async fn settle(
    pool: &Arc<Pool>,
    question: OutcomeRequest,
    opcode: Opcode,
    bound: usize,
) -> Settled<Data> {
    let fate = pool.ask(question, bound).await;
    if let Fate::Unsettled(unsettled) = &fate {
        let errno = match unsettled {
            Unsettled::Refused(errno) => Errno::from_raw_os_error(errno.get()),
            Unsettled::Unanswerable => Errno::IO,
        };
        tracing::warn!(%errno, %opcode, "the server refused to say what became of a request");
    }
    settled(fate)
}

async fn read_kept<D: Destination>(
    reply: &Data,
    request_id: u64,
    opcode: Opcode,
    destination: &mut D,
) -> Result<Answer, Errno> {
    kept_answer(reply.filled(), request_id, opcode, destination)
        .await
        .map_err(|reason| {
            tracing::warn!(%reason, %opcode, "a kept reply could not be read");
            Errno::IO
        })
}

fn unsent_errno(unsent: Unsent) -> Errno {
    match unsent {
        Unsent::Claim(voidport_session::table::ClaimError::Allocation) => Errno::NOMEM,
        Unsent::Claim(voidport_session::table::ClaimError::Invariant(_)) => Errno::IO,
        Unsent::Encode(error) => unencodable(error),
    }
}
