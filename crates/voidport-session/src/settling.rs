use core::num::NonZeroI32;

use voidport_proto::error::FramingError;
use voidport_proto::message::is_error_status;
use voidport_proto::ops::connection::outcome_state;
use voidport_proto::piece::Closing;

use crate::replay::{Decision, Sent};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Errno(NonZeroI32);

impl Errno {
    #[must_use]
    pub fn of_status(status: i32) -> Option<Self> {
        if !is_error_status(status) {
            return None;
        }
        NonZeroI32::new(status.checked_neg()?).map(Self)
    }

    #[must_use]
    pub fn get(self) -> i32 {
        self.0.get()
    }
}

/// The number of `ESTALE` differs between architectures, so the adapter maps
/// its constant onto [`ServerErrno::Stale`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServerErrno {
    Stale,
    Other(Errno),
}

impl ServerErrno {
    pub fn of_status(status: i32, stale: i32) -> Result<Self, FramingError> {
        let errno = Errno::of_status(status).ok_or(FramingError::InvalidStatus { status })?;
        Ok(if errno.get() == stale {
            Self::Stale
        } else {
            Self::Other(errno)
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PiecesEnded {
    Missing,
    Clean,
    Refused(ServerErrno),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutcomeAnswer {
    Refused(ServerErrno),
    State { state: u32, closing: PiecesEnded },
}

impl OutcomeAnswer {
    pub fn of_state(
        state: u32,
        closing: Option<Closing>,
        stale: i32,
    ) -> Result<Self, FramingError> {
        let closing = match closing {
            None => PiecesEnded::Missing,
            Some(closing) if closing.status == 0 => PiecesEnded::Clean,
            Some(closing) => PiecesEnded::Refused(ServerErrno::of_status(closing.status, stale)?),
        };
        Ok(Self::State { state, closing })
    }

    pub fn of_refusal(status: i32, stale: i32) -> Result<Self, FramingError> {
        Ok(Self::Refused(ServerErrno::of_status(status, stale)?))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unsettled {
    Refused(Errno),
    Unanswerable,
}

/// `R` is the copy that the adapter made of the reply kept by the server.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub enum Fate<R> {
    NotStarted,
    Applied,
    Replied(R),
    Unsettled(Unsettled),
    Ended,
}

/// The pool asks only about a connection it has not retired, because it
/// retires one only once everything of it is settled. So `ESTALE`, which
/// refers to a connection that the session no longer has, means the server
/// read no request from it and dropped it when it closed: none of its
/// requests started. A state word this protocol does not define, and an
/// answer whose pieces never ended, cannot be acted on.
pub fn read_outcome<R>(answer: OutcomeAnswer, reply: R) -> Fate<R> {
    let state = match answer {
        OutcomeAnswer::Refused(refused)
        | OutcomeAnswer::State {
            closing: PiecesEnded::Refused(refused),
            ..
        } => {
            return match refused {
                ServerErrno::Stale => Fate::NotStarted,
                ServerErrno::Other(errno) => Fate::Unsettled(Unsettled::Refused(errno)),
            };
        }
        OutcomeAnswer::State {
            closing: PiecesEnded::Missing,
            ..
        } => return Fate::Unsettled(Unsettled::Unanswerable),
        OutcomeAnswer::State {
            state,
            closing: PiecesEnded::Clean,
        } => state,
    };
    match state {
        outcome_state::NOT_STARTED => Fate::NotStarted,
        outcome_state::APPLIED => Fate::Applied,
        outcome_state::REPLIED => Fate::Replied(reply),
        _ => Fate::Unsettled(Unsettled::Unanswerable),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub enum AfterLoss {
    Settled(Unasked),
    /// Ask the server what became of it with an outcome request on another
    /// connection of the session, read the answer with [`read_outcome`], and
    /// settle it with [`settled`].
    Ask,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unasked {
    Again,
    Ended,
}

impl<R> From<Unasked> for Fate<R> {
    fn from(unasked: Unasked) -> Self {
        match unasked {
            Unasked::Again => Self::NotStarted,
            Unasked::Ended => Self::Ended,
        }
    }
}

impl<R> From<Unasked> for Settled<R> {
    fn from(unasked: Unasked) -> Self {
        match unasked {
            Unasked::Again => Self::Again,
            Unasked::Ended => Self::Ended,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub enum Settled<R> {
    Answered(R),
    Again,
    Failed(Unsettled),
    Ended,
}

/// A request with a reply is never answered "applied", so that answer cannot
/// be acted on, as an answer that cannot be read cannot.
pub fn settled<R>(fate: Fate<R>) -> Settled<R> {
    match fate {
        Fate::NotStarted => Settled::Again,
        Fate::Replied(kept) => Settled::Answered(kept),
        Fate::Applied => Settled::Failed(Unsettled::Unanswerable),
        Fate::Unsettled(unsettled) => Settled::Failed(unsettled),
        Fate::Ended => Settled::Ended,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub enum Concluded<R> {
    /// With the reply the server kept, which the adapter reads as the answer
    /// to the request. A kept reply that cannot be read fails the request
    /// with `EIO`.
    Answer(R),
    SendAgain,
    Fail,
    Moot,
}

/// `restartable` is whether the destination of the request can be made ready
/// to be sent again while its session lives. A request whose destination
/// cannot, such as a listing whose entries already reached the caller, fails
/// in place of being sent again in that session, because what the destination
/// took is still owed to it.
///
/// A request of a session that ended is sent again whatever its destination
/// took. The session took its lookups and handles with it, so the destination
/// drops what it took, and the next session answers the request anew: a
/// request that contains an identifier of the ended session gets the stale
/// errno of that identifier.
pub fn conclude<R>(settled: Settled<R>, ended: Decision, restartable: bool) -> Concluded<R> {
    match settled {
        Settled::Answered(kept) => Concluded::Answer(kept),
        Settled::Failed(_) => Concluded::Fail,
        Settled::Again if restartable => Concluded::SendAgain,
        Settled::Again => Concluded::Fail,
        Settled::Ended => match ended {
            Decision::Resend => Concluded::SendAgain,
            Decision::Fail => Concluded::Fail,
            Decision::Moot => Concluded::Moot,
        },
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub enum ForgetSettled {
    Done,
    SendAgain,
    /// What became of it remains unknown, for this reason. It is not sent
    /// again, because a forget applied twice drops the lookups twice.
    Unknown(Unsettled),
    SessionEnded,
}

pub fn forget_settled<R>(fate: Fate<R>) -> ForgetSettled {
    match fate {
        Fate::NotStarted => ForgetSettled::SendAgain,
        Fate::Applied | Fate::Replied(_) => ForgetSettled::Done,
        Fate::Unsettled(unsettled) => ForgetSettled::Unknown(unsettled),
        Fate::Ended => ForgetSettled::SessionEnded,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub enum ForgetSent {
    /// It remains recorded on its connection until a reply there shows the server
    /// read it, or a loss of the connection settles it.
    Written,
    /// Its connection was lost first. The adapter withdraws it from the
    /// record of its connection and reports the loss. It sends the forget
    /// again on another connection only when the withdrawal found it there:
    /// a loss handled meanwhile has already taken it to settle, so exactly
    /// one of the two sends it again.
    Lost,
}

/// A forget is recorded on its connection before it is written, so a loss of
/// that connection settles it by asking.
pub fn forget_sent(sent: Sent) -> ForgetSent {
    match sent {
        Sent::Written => ForgetSent::Written,
        Sent::Queued => ForgetSent::Lost,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub enum Attempted<A> {
    Answered(A),
    SendAgain,
}

/// An outcome or a retire request is sent again after every loss of its
/// connection, whatever that decision is, until a reply arrives or the session
/// ends. An outcome request changes nothing on the server, and a second retire
/// of a connection whose records the first one dropped gets an answer as well.
pub fn attempted<A>(attempt: Result<A, Decision>) -> Attempted<A> {
    match attempt {
        Ok(answer) => Attempted::Answered(answer),
        Err(_) => Attempted::SendAgain,
    }
}

#[cfg(test)]
mod tests;
