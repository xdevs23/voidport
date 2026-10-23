use super::{
    AttemptLog, Session,
    error::{AttemptFailure, CollectError, IncompleteAttempt, ReplayError},
    query_arguments,
    signals::{Cancelled, Signals, UnconfirmedPublication, check_cancellation},
};
use crate::{
    cli::Collect,
    model::{self, Attempt, AttemptState, Outcome, Tool, Unit},
    storage::{DataDirectory, Directory, Writer, attempt_name},
};
use std::{io::Write as _, time::Duration};
use tokio::time::Instant;

pub(super) async fn run_attempt(
    corpus: &mut Writer,
    signals: &mut Signals,
    tool: &Tool,
    options: &Collect,
    unit: Unit,
) -> Result<(), CollectError> {
    let mut id = corpus
        .state()
        .records
        .attempts
        .iter()
        .map(|attempt| attempt.id)
        .max()
        .unwrap_or(0)
        .checked_add(1)
        .ok_or(CollectError::AttemptIdsExhausted)?;
    let attempts = corpus.data_dir(DataDirectory::Attempts)?;
    while attempts
        .exists(&attempt_name(id))
        .map_err(CollectError::AttemptDirectory)?
    {
        id = id.checked_add(1).ok_or(CollectError::AttemptIdsExhausted)?;
    }
    let directory = attempts
        .mkdir(&attempt_name(id))
        .map_err(CollectError::AttemptDirectory)?;
    for name in ["home", "config", "data", "cache", "state", "temporary"] {
        directory
            .create(name)
            .map_err(CollectError::AttemptDirectory)?;
    }
    let runtime = tempfile::Builder::new()
        .prefix("vpl-")
        .tempdir()
        .map_err(CollectError::Runtime)?;
    let arguments = query_arguments(
        &corpus.state().configuration.sources[unit.source],
        &corpus.state().configuration.queries[unit.query],
    );
    let attempt = corpus.add_attempt(Attempt {
        id,
        unit,
        directory: DataDirectory::Attempts.path(&attempt_name(id)),
        runtime: runtime
            .path()
            .to_str()
            .ok_or(CollectError::RuntimePath)?
            .into(),
        tool: tool.clone(),
        arguments: arguments.clone(),
        timeout_seconds: options.timeout_seconds.get(),
        delay_seconds: options.delay_seconds.get(),
        started: model::now(),
        finished: None,
        state: AttemptState::Running,
        exit_code: None,
        cleanup: "not established".into(),
        errors: vec![],
        deliveries: vec![],
    })?;
    corpus.publish()?;
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(options.timeout_seconds.get()))
        .ok_or(CollectError::Deadline)?;
    let mut session = Session {
        directory,
        runtime,
        tool: tool.clone(),
        daemon: None,
    };
    let (exit_code, mut failures) = session
        .acquire(corpus, attempt, &arguments, deadline, signals)
        .await;
    corpus.record_outcome(attempt, outcome(exit_code, &failures))?;
    if let Err(error) = corpus.publish() {
        if failures.iter().any(AttemptFailure::is_cancellation) {
            return Err(CollectError::Cancelled(Cancelled {
                publication: Some(UnconfirmedPublication(error)),
            }));
        }
        return Err(error.into());
    }
    if !failures.is_empty() {
        let replay_failures = [AttemptLog::Setup, AttemptLog::Query, AttemptLog::Cleanup]
            .into_iter()
            .filter_map(|log| replay(&session.directory, log).err())
            .collect();
        let cancellation =
            check_cancellation(corpus, signals, Some((attempt, &mut failures))).err();
        return Err(CollectError::Incomplete(Box::new(IncompleteAttempt {
            id,
            failures,
            cancellation,
            replay: replay_failures,
        })));
    }
    check_cancellation(corpus, signals, Some((attempt, &mut failures)))?;
    Ok(())
}

fn replay(directory: &Directory, log: AttemptLog) -> Result<(), ReplayError> {
    let name = log.stderr();
    if directory
        .exists(&name)
        .map_err(|source| ReplayError::Find { log, source })?
    {
        let bytes = directory
            .read(&name)
            .map_err(|source| ReplayError::Read { log, source })?;
        std::io::stderr()
            .write_all(&bytes)
            .map_err(|source| ReplayError::Write { log, source })?;
    }
    Ok(())
}

/// The daemon is recorded as terminated when no failure of the cleanup is among
/// `failures`.
fn outcome(exit_code: Option<i32>, failures: &[AttemptFailure]) -> Outcome {
    Outcome {
        state: if failures.is_empty() {
            AttemptState::Complete
        } else {
            AttemptState::Failed
        },
        exit_code,
        finished: model::now(),
        cleanup: failures
            .iter()
            .find(|failure| matches!(failure, AttemptFailure::Cleanup(_)))
            .map_or_else(|| "terminated".into(), ToString::to_string),
        errors: failures.iter().map(ToString::to_string).collect(),
    }
}
