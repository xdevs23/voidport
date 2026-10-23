// SPDX-License-Identifier: GPL-2.0

use kernel::prelude::*;
use kernel::sync::Arc;
use voidport_proto::opcode::Opcode;
use voidport_proto::ops::connection::{
    OutcomeRequest, OutcomeResponse, RetireRequest, RetireResponse,
};
use voidport_session::cleanup::{Disposition, RETRY_DELAY};
use voidport_session::pool::{Loss, Retire};
use voidport_session::replay::Decision;
use voidport_session::settling::{
    attempted, forget_settled, read_outcome, settled, AfterLoss, Attempted, Fate, ForgetSettled,
    OutcomeAnswer, Settled, Unsettled,
};
use zerocopy::byteorder::little_endian::U64;

use crate::cleanup::{Callerless, Connections, Written};
use crate::connection::{Connection, Death, Forgotten, Landing, Owed, Pending, Pieces, Reply};
use crate::ops::{Expect, Operation, Request};
use crate::pool::{Member, Pool};
use crate::session::{Attempt, ExtractError, Owned, Session};
use crate::wire::Caller;

impl Operation for OutcomeRequest {
    type Response = OutcomeResponse;
    type Output = OutcomeAnswer;

    fn extract(
        &self,
        response: &OutcomeResponse,
        _: &[u8],
        landing: &Landing,
    ) -> core::result::Result<OutcomeAnswer, ExtractError> {
        Ok(OutcomeAnswer::of_state(
            response.state.get(),
            landing.closing,
            stale(),
        )?)
    }

    fn refused(&self, status: i32) -> core::result::Result<OutcomeAnswer, ExtractError> {
        Ok(OutcomeAnswer::of_refusal(status, stale())?)
    }
}

impl Operation for RetireRequest {
    type Response = RetireResponse;
    type Output = ();

    fn extract(
        &self,
        _: &RetireResponse,
        _: &[u8],
        _: &Landing,
    ) -> core::result::Result<(), ExtractError> {
        Ok(())
    }

    /// A refusal ends the retire as a success does.
    fn refused(&self, _: i32) -> core::result::Result<(), ExtractError> {
        Ok(())
    }
}

impl Session {
    /// Reports the loss of `lost`, the connection of the calling thread, and
    /// finishes what the loss left while the session lives: the forgets
    /// written on the connection since the last reply on it, the request on
    /// it that no caller waits for, a request whose caller left while the
    /// caller settled the loss, and then the retire request of the
    /// connection. A loss that ends the session is reported to the mount with
    /// `death`.
    pub(crate) fn settle_loss(&self, pool: &Arc<Pool>, lost: &Member, death: Death) {
        let forgets = lost.connection.take_forgets();
        let owed = lost.connection.take_owed();
        match pool.lost(lost, forgets.len()) {
            Loss::Left { .. } | Loss::SubscriptionEnded { .. } => {}
            Loss::Handled | Loss::SessionEnds => {
                if let Some(owed) = owed {
                    owed.end();
                }
                if pool.is_ended() {
                    self.session_ended(pool, death);
                }
                return;
            }
        }
        if !forgets.is_empty() {
            for forgotten in forgets.iter() {
                self.settle_forget(pool, &lost.connection, forgotten);
            }
            pool.forgets_settled(lost);
        }
        // The request that no caller waits for is this thread's to give back.
        if let Some(owed) = owed {
            self.settle_owed(pool, &lost.connection, owed);
            pool.give_back(lost);
        }
        let retire = pool.retire_of(lost);
        // A caller that left while it settled its request left the request
        // here before it gave the connection back.
        if let Some(left) = lost.connection.take_left() {
            self.settle_owed(pool, &lost.connection, left);
        }
        if let Some(retire) = retire {
            self.send_retire(pool, retire);
        }
    }

    /// Sends `retire` on connections of `pool`, again after each delay while
    /// none answers it, until one does or the session ends.
    fn send_retire(&self, pool: &Arc<Pool>, retire: Retire) {
        let body = RetireRequest {
            connection_id: U64::new(retire.connection_id),
        };
        let retire = request(body, Expect::Nothing);
        loop {
            match self.on_pool(pool, &retire) {
                Ok(Some((owned, body))) => {
                    // A refusal ends the retire as a success does.
                    let _ = self.interpret(&owned, &body);
                    return;
                }
                Ok(None) => return,
                Err(_) => self.wait_backoff(RETRY_DELAY),
            }
        }
    }

    fn settle_forget(&self, pool: &Arc<Pool>, lost: &Connection, forgotten: &Forgotten) {
        let fate = self
            .fate_after_loss(pool, lost, Opcode::Forget, forgotten.request_id, 0)
            .unwrap_or(Fate::Unsettled(Unsettled::Unanswerable));
        if forget_settled(fate) == ForgetSettled::SendAgain {
            // Its lookups were counted as given back when it was first
            // written.
            self.write_until_settled(pool, &mut |on| {
                on.forget(forgotten.caller, forgotten.node_id, forgotten.nlookup)
                    .map(|()| false)
            });
        }
    }

    /// Settles `owed`, a request no caller waits for, in flight on the lost
    /// connection `lost`: the references a stored reply admitted go to the
    /// cleanup records, and a request of the cleanup worker that never
    /// started is sent again.
    fn settle_owed(&self, pool: &Arc<Pool>, lost: &Arc<Connection>, owed: Owed) {
        let ask = |landing: &Landing| {
            let fate = self.fate_after_loss(
                pool,
                lost,
                owed.opcode,
                owed.request_id,
                landing.kept_bound(),
            );
            settled(fate.unwrap_or(Fate::Unsettled(Unsettled::Unanswerable)))
        };
        match owed.reply.take_unsettled() {
            Some(Pending::Admitting {
                mut landing,
                mut orphan,
            }) => {
                // One that never started, or of an unknown fate, admitted
                // nothing that can be given back.
                if let Settled::Answered(kept) = ask(&landing) {
                    if landing.read_kept(&kept, owed.request_id).is_ok() {
                        orphan.carry(landing);
                        self.record(lost.clone(), orphan, Disposition::GiveBack);
                    }
                }
            }
            Some(Pending::Callerless {
                landing,
                completion,
            }) => match ask(&landing) {
                Settled::Again => self.send_again(pool, &owed.reply, landing, completion),
                // It ran, or may have: it is not sent again.
                Settled::Answered(_) | Settled::Failed(_) => completion.finish(true),
                Settled::Ended => completion.finish(false),
            },
            Some(Pending::Other) | None => {}
        }
    }

    fn send_again(
        &self,
        pool: &Pool,
        reply: &Arc<Reply>,
        landing: Landing,
        completion: Callerless,
    ) {
        let notice = completion.notice();
        reply.rearm(landing, completion);
        let written = self.write_until_settled(pool, &mut |connection| {
            notice.send(connection, reply.clone()).map(|()| true)
        });
        if written == Written::Ended {
            if let Some(completion) = reply.withdraw_callerless() {
                completion.finish(false);
            }
        }
    }

    /// Writes one cleanup frame with `write` on a connection of `pool`, as
    /// [`Connections::write_cleanup`] does, again after each delay while no
    /// connection accepts it, until one does or the session ends.
    fn write_until_settled(
        &self,
        pool: &Pool,
        write: &mut dyn FnMut(&Arc<Connection>) -> Result<bool>,
    ) -> Written {
        loop {
            match self.write_cleanup(pool.generation(), write) {
                Written::Later => self.wait_backoff(RETRY_DELAY),
                written => return written,
            }
        }
    }

    /// Sends `request` on connections of `pool` until one answers it, and
    /// returns the answer. `None` once the session ended.
    fn on_pool<Q: Operation>(
        &self,
        pool: &Arc<Pool>,
        request: &Request<'_, Q>,
    ) -> Result<Option<(Owned, Q)>> {
        loop {
            let Some(lent) = pool.take(self)? else {
                return Ok(None);
            };
            let attempt = self.attempt(lent.connection(), request);
            // A sender that left while the reply is owed leaves the
            // connection to its thread, which gives it back after the reply.
            if let Attempt::Left(_) = attempt {
                lent.leave_to_thread();
            }
            if let Attempted::Answered(answered) = attempted(answer_of(attempt)?) {
                return Ok(Some(answered));
            }
        }
    }

    /// What became of request `request_id` of `opcode` on the lost connection
    /// `lost`: what the session core settles without a question, or else the
    /// answer to an outcome request on another connection of `pool`. `kept`
    /// is the most bytes the reply the server stored for it can take. An
    /// error when the question could not be asked.
    pub(crate) fn fate_after_loss(
        &self,
        pool: &Arc<Pool>,
        lost: &Connection,
        opcode: Opcode,
        request_id: u64,
        kept: usize,
    ) -> Result<Fate<KVVec<u8>>> {
        match pool.after_loss(opcode) {
            AfterLoss::Settled(unasked) => Ok(unasked.into()),
            AfterLoss::Ask => self.ask_pool(pool, lost, request_id, kept),
        }
    }

    /// What became of request `request_id` of the lost connection `lost`, by
    /// the answer to an outcome request on a connection of `pool`. `kept` is
    /// the most bytes the reply the server stored for it can take. An error
    /// when the question could not be asked.
    fn ask_pool(
        &self,
        pool: &Arc<Pool>,
        lost: &Connection,
        request_id: u64,
        kept: usize,
    ) -> Result<Fate<KVVec<u8>>> {
        let question = OutcomeRequest {
            connection_id: U64::new(lost.id()),
            request_id: U64::new(request_id),
        };
        let Some((owned, question)) =
            self.on_pool(pool, &request(question, Expect::Bytes(kept)))?
        else {
            return Ok(Fate::Ended);
        };
        let answer = self.interpret(&owned, &question);
        let Pieces::Bytes { mut buffer, len } = owned.into_pieces() else {
            return Err(EIO);
        };
        buffer.truncate(len);
        Ok(match answer {
            Ok(answer) => read_outcome(answer, buffer),
            // The connection the answer arrived on was ended over it.
            Err(_) => Fate::Unsettled(Unsettled::Unanswerable),
        })
    }
}

/// The answer an attempt of a request the session sends itself returned, or
/// the decision for it when its connection was lost first.
fn answer_of<Q>(attempt: Attempt<Q>) -> Result<core::result::Result<(Owned, Q), Decision>> {
    match attempt {
        Attempt::Answered(owned, body) => Ok(Ok((owned, body))),
        // Nothing was claimed, so nothing of it reached the server.
        Attempt::Dead => Ok(Err(Decision::Resend)),
        Attempt::Lost(lost) => Ok(Err(lost.decision)),
        Attempt::Failed(error) | Attempt::Left(error) => Err(error),
    }
}

/// A request the session sends itself, which has no caller and refers to no
/// node.
fn request<Q>(body: Q, expect: Expect) -> Request<'static, Q> {
    Request::new(Caller::default(), 0, body).expecting(expect)
}

/// The number of `ESTALE` in this kernel, which has a meaning of its own in
/// the answer to an outcome request.
fn stale() -> i32 {
    -crate::errno::estale().to_errno()
}
