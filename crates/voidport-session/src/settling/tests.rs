use super::*;

fn errno(number: i32) -> Errno {
    Errno::of_status(-number).expect("an errno")
}

#[test]
fn an_errno_is_read_only_from_a_status_that_carries_one() {
    assert_eq!(Errno::of_status(-22).map(Errno::get), Some(22));
    assert_eq!(Errno::of_status(-4095).map(Errno::get), Some(4095));
    for status in [0, 22, -4096, i32::MIN] {
        assert_eq!(Errno::of_status(status), None, "{status}");
    }
}

#[test]
fn an_outcome_answer_is_read_by_its_state_and_its_refusals() {
    let state = |state, closing| OutcomeAnswer::State { state, closing };
    let undefined = u32::MAX;
    let cases = [
        (
            state(outcome_state::NOT_STARTED, PiecesEnded::Clean),
            Fate::NotStarted,
        ),
        (
            state(outcome_state::APPLIED, PiecesEnded::Clean),
            Fate::Applied,
        ),
        (
            state(outcome_state::REPLIED, PiecesEnded::Clean),
            Fate::Replied("kept"),
        ),
        (
            state(undefined, PiecesEnded::Clean),
            Fate::Unsettled(Unsettled::Unanswerable),
        ),
        (
            state(outcome_state::REPLIED, PiecesEnded::Missing),
            Fate::Unsettled(Unsettled::Unanswerable),
        ),
        (
            state(
                outcome_state::REPLIED,
                PiecesEnded::Refused(ServerErrno::Other(errno(5))),
            ),
            Fate::Unsettled(Unsettled::Refused(errno(5))),
        ),
        (
            state(
                outcome_state::REPLIED,
                PiecesEnded::Refused(ServerErrno::Stale),
            ),
            Fate::NotStarted,
        ),
        (OutcomeAnswer::Refused(ServerErrno::Stale), Fate::NotStarted),
        (
            OutcomeAnswer::Refused(ServerErrno::Other(errno(22))),
            Fate::Unsettled(Unsettled::Refused(errno(22))),
        ),
    ];
    for (answer, fate) in cases {
        assert_eq!(read_outcome(answer, "kept"), fate, "{answer:?}");
    }
}

const STALE: i32 = 116;

#[test]
fn the_reply_to_an_outcome_request_is_decoded_with_the_estale_of_the_adapter() {
    let closing = |status| {
        Some(Closing {
            status,
            exhausted: false,
        })
    };
    let state = |state, closing| OutcomeAnswer::State { state, closing };
    let replied = outcome_state::REPLIED;
    let cases = [
        (None, state(replied, PiecesEnded::Missing)),
        (closing(0), state(replied, PiecesEnded::Clean)),
        (
            closing(-STALE),
            state(replied, PiecesEnded::Refused(ServerErrno::Stale)),
        ),
        (
            closing(-5),
            state(replied, PiecesEnded::Refused(ServerErrno::Other(errno(5)))),
        ),
    ];
    for (closing, answer) in cases {
        assert_eq!(
            OutcomeAnswer::of_state(replied, closing, STALE),
            Ok(answer),
            "{closing:?}"
        );
    }
    assert_eq!(
        OutcomeAnswer::of_refusal(-STALE, STALE),
        Ok(OutcomeAnswer::Refused(ServerErrno::Stale))
    );
    assert_eq!(
        OutcomeAnswer::of_refusal(-22, STALE),
        Ok(OutcomeAnswer::Refused(ServerErrno::Other(errno(22))))
    );
    assert_eq!(
        OutcomeAnswer::of_refusal(22, STALE),
        Err(FramingError::InvalidStatus { status: 22 })
    );
    assert_eq!(
        OutcomeAnswer::of_state(replied, closing(22), STALE),
        Err(FramingError::InvalidStatus { status: 22 })
    );
}

#[test]
fn a_request_settled_without_asking_is_sent_again_or_left_to_the_ended_session() {
    assert_eq!(Settled::<&str>::from(Unasked::Again), Settled::Again);
    assert_eq!(Settled::<&str>::from(Unasked::Ended), Settled::Ended);
    assert_eq!(Fate::<&str>::from(Unasked::Again), Fate::NotStarted);
    assert_eq!(Fate::<&str>::from(Unasked::Ended), Fate::Ended);
}

#[test]
fn a_request_with_a_reply_is_settled_by_the_answer_about_it() {
    assert_eq!(settled::<&str>(Fate::NotStarted), Settled::Again);
    assert_eq!(settled(Fate::Replied("kept")), Settled::Answered("kept"));
    assert_eq!(
        settled::<&str>(Fate::Applied),
        Settled::Failed(Unsettled::Unanswerable),
        "a request with a reply is never applied"
    );
    for unsettled in [Unsettled::Refused(errno(22)), Unsettled::Unanswerable] {
        assert_eq!(
            settled::<&str>(Fate::Unsettled(unsettled)),
            Settled::Failed(unsettled)
        );
    }
    assert_eq!(settled::<&str>(Fate::Ended), Settled::Ended);
}

#[test]
fn a_settled_request_is_answered_sent_again_failed_or_decided_by_the_ended_session() {
    let failed = Settled::Failed(Unsettled::Unanswerable);
    let cases = [
        (
            Settled::Answered("kept"),
            Decision::Fail,
            false,
            Concluded::Answer("kept"),
        ),
        (failed, Decision::Resend, true, Concluded::Fail),
        (Settled::Again, Decision::Fail, true, Concluded::SendAgain),
        (Settled::Again, Decision::Resend, false, Concluded::Fail),
        (Settled::Ended, Decision::Resend, true, Concluded::SendAgain),
        (
            Settled::Ended,
            Decision::Resend,
            false,
            Concluded::SendAgain,
        ),
        (Settled::Ended, Decision::Fail, true, Concluded::Fail),
        (Settled::Ended, Decision::Moot, true, Concluded::Moot),
    ];
    for (settled, ended, restartable, expected) in cases {
        assert_eq!(
            conclude(settled, ended, restartable),
            expected,
            "{settled:?} {ended:?} {restartable}"
        );
    }
}

#[test]
fn a_forget_of_a_lost_connection_is_sent_again_only_when_it_never_started() {
    assert_eq!(
        forget_settled::<()>(Fate::NotStarted),
        ForgetSettled::SendAgain
    );
    for done in [Fate::Applied, Fate::Replied(())] {
        assert_eq!(forget_settled(done), ForgetSettled::Done, "{done:?}");
    }
    assert_eq!(
        forget_settled::<()>(Fate::Ended),
        ForgetSettled::SessionEnded
    );
}

#[test]
fn a_forget_whose_fate_remains_unknown_is_reported_with_its_reason_and_not_sent_again() {
    for unsettled in [Unsettled::Refused(errno(22)), Unsettled::Unanswerable] {
        assert_eq!(
            forget_settled::<()>(Fate::Unsettled(unsettled)),
            ForgetSettled::Unknown(unsettled)
        );
    }
}

#[test]
fn a_forget_is_done_with_once_written_and_lost_with_its_connection_otherwise() {
    assert_eq!(forget_sent(Sent::Written), ForgetSent::Written);
    assert_eq!(forget_sent(Sent::Queued), ForgetSent::Lost);
}

#[test]
fn an_outcome_or_retire_request_ends_with_any_answer_and_is_sent_again_after_every_loss() {
    assert_eq!(
        attempted::<&str>(Ok("refused")),
        Attempted::Answered("refused")
    );
    for decision in [Decision::Resend, Decision::Fail, Decision::Moot] {
        assert_eq!(
            attempted::<&str>(Err(decision)),
            Attempted::SendAgain,
            "{decision:?}"
        );
    }
}
