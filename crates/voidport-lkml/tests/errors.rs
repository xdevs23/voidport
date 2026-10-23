#![forbid(unsafe_code)]
use std::io;
use voidport_lkml::{
    acquire::{
        AcquisitionError, AttemptFailure, IngestAborted, IngestFailure, MaildirFailure, StopError,
        StopReason, Stopped,
    },
    error::{error_text, list_text},
    storage::StorageError,
};

#[derive(Debug, thiserror::Error)]
#[error("outer")]
struct Outer(#[source] Middle);
#[derive(Debug, thiserror::Error)]
#[error("middle")]
struct Middle(#[source] Inner);
#[derive(Debug, thiserror::Error)]
#[error("inner")]
struct Inner;

fn stopped(reason: StopReason, failures: Vec<StopError>) -> AcquisitionError {
    AcquisitionError::Stopped(Stopped { reason, failures })
}

#[test]
fn error_text_joins_the_chain_of_sources() {
    assert_eq!(error_text(&Inner), "inner");
    assert_eq!(error_text(&Outer(Middle(Inner))), "outer: middle: inner");
    assert_eq!(list_text(["a".into(), "b: c".into()]), "a; b: c");
}

#[test]
fn a_stopped_query_records_its_reason_and_every_failure_to_stop_it() {
    let stop_failures = || {
        vec![
            StopError::Kill(io::Error::other("kill failed")),
            StopError::Wait(io::Error::other("wait failed")),
        ]
    };
    let failures = "stop lei query: kill failed; wait for lei query termination: wait failed";
    for (reason, recorded) in [
        (StopReason::Timeout, "acquisition timeout"),
        (StopReason::Cancelled, "acquisition interrupted by signal"),
        (
            StopReason::Wait(io::Error::other(Middle(Inner))),
            "middle: inner",
        ),
    ] {
        let error = stopped(reason, stop_failures());
        assert_eq!(
            AttemptFailure::Acquisition(error).to_string(),
            format!("{recorded}; {failures}")
        );
    }
    let cancelled = stopped(StopReason::Cancelled, vec![]);
    assert!(cancelled.is_cancellation());
    assert_eq!(
        AttemptFailure::Acquisition(cancelled).to_string(),
        "acquisition interrupted by signal"
    );
    assert!(!stopped(StopReason::Timeout, vec![]).is_cancellation());
}

#[test]
fn ingestion_records_the_entry_failures_before_the_error_that_ended_it() {
    let failure = IngestFailure {
        failures: vec![MaildirFailure::InvalidMail {
            digest: "digest".into(),
        }],
        aborted: Some(IngestAborted::Deliver(StorageError::UnknownAttempt {
            id: 1,
        })),
    };
    assert_eq!(
        AttemptFailure::Ingestion(failure).to_string(),
        "ingestion failed: invalid delivered mail artifact digest; no attempt 1 in the corpus"
    );
}
