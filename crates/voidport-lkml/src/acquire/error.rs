use super::{
    AttemptLog,
    ingest::ScannedFolder,
    signals::{Cancelled, INTERRUPTION},
};
use crate::{
    error::{error_text, list_text},
    mail::AuthorError,
    model::{MaildirFolder, SourceListError, TimestampError},
    storage::{DirectoryError, StorageError},
};
use rustix::io::Errno;
use std::{
    ffi::OsString,
    fmt,
    num::{ParseIntError, TryFromIntError},
    process::ExitStatus,
    str::Utf8Error,
};
use voidport_spawn::SpawnError;

#[derive(Debug, thiserror::Error)]
pub enum CollectError {
    #[error(transparent)]
    Tool(#[from] ToolError),
    #[error(transparent)]
    Signals(std::io::Error),
    #[error(transparent)]
    Sources(SourceListError),
    #[error(transparent)]
    Authors(AuthorError),
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error("source configuration differs; use a new corpus")]
    SourcesDiffer,
    #[error("query configuration differs; use a new corpus")]
    QueriesDiffer,
    #[error("author configuration differs; use a new corpus")]
    AuthorsDiffer,
    #[error(transparent)]
    FinishTime(TimestampError),
    #[error("persisted delay exceeds timer range")]
    Delay(#[source] TryFromIntError),
    #[error("attempt IDs exhausted")]
    AttemptIdsExhausted,
    #[error(transparent)]
    AttemptDirectory(DirectoryError),
    #[error(transparent)]
    Runtime(std::io::Error),
    #[error("non-UTF8 runtime path; attempt directory retained without starting lei")]
    RuntimePath,
    #[error("deadline exceeds clock range")]
    Deadline,
    #[error(transparent)]
    Cancelled(#[from] Cancelled),
    #[error(transparent)]
    Incomplete(Box<IncompleteAttempt>),
}

/// Its message contains the text of every failure, joined by `; `. None of the
/// failures is its source, so the message is one line.
#[derive(Debug)]
pub struct IncompleteAttempt {
    pub id: u64,
    pub failures: Vec<AttemptFailure>,
    pub cancellation: Option<Cancelled>,
    pub replay: Vec<ReplayError>,
}
impl fmt::Display for IncompleteAttempt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let publication = self
            .cancellation
            .as_ref()
            .and_then(|cancelled| cancelled.publication.as_ref());
        let texts = self
            .failures
            .iter()
            .map(ToString::to_string)
            .chain(publication.map(|failure| error_text(failure)))
            .chain(self.replay.iter().map(|failure| error_text(failure)));
        write!(
            formatter,
            "attempt {} incomplete: {}",
            self.id,
            list_text(texts)
        )
    }
}
impl std::error::Error for IncompleteAttempt {}

#[derive(Debug)]
pub enum AttemptFailure {
    QueryExit(ExitStatus),
    Acquisition(AcquisitionError),
    Cleanup(CleanupError),
    Ingestion(IngestFailure),
    Cancelled,
}
impl AttemptFailure {
    pub(super) fn is_cancellation(&self) -> bool {
        match self {
            Self::Acquisition(error) => error.is_cancellation(),
            Self::Cancelled => true,
            Self::QueryExit(_) | Self::Cleanup(_) | Self::Ingestion(_) => false,
        }
    }
}
impl fmt::Display for AttemptFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::QueryExit(status) => write!(formatter, "lei query failed: {status}"),
            Self::Acquisition(error) => {
                let stop_failures = match error {
                    AcquisitionError::Stopped(stopped) => stopped.failures.as_slice(),
                    _ => &[],
                };
                let texts = std::iter::once(error_text(error))
                    .chain(stop_failures.iter().map(|failure| error_text(failure)));
                formatter.write_str(&list_text(texts))
            }
            Self::Cleanup(error) => write!(formatter, "cleanup unconfirmed: {}", error_text(error)),
            Self::Ingestion(failure) => write!(formatter, "ingestion failed: {failure}"),
            Self::Cancelled => formatter.write_str(INTERRUPTION),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ToolError {
    #[error("lei executable is missing or not executable")]
    Missing,
    #[error(transparent)]
    Canonicalize(std::io::Error),
    #[error("non-UTF8 lei executable path")]
    NonUtf8Path,
}

#[derive(Debug, thiserror::Error)]
pub enum ReplayError {
    #[error("replay {} failed", .log.stderr())]
    Find {
        log: AttemptLog,
        #[source]
        source: DirectoryError,
    },
    #[error("replay {} failed", .log.stderr())]
    Read {
        log: AttemptLog,
        #[source]
        source: DirectoryError,
    },
    #[error("replay {} failed", .log.stderr())]
    Write {
        log: AttemptLog,
        #[source]
        source: std::io::Error,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum StartError {
    #[error(transparent)]
    Log(DirectoryError),
    #[error("spawn lei")]
    Spawn(#[source] SpawnError),
    #[error("watch lei")]
    Watch(#[source] std::io::Error),
}

#[derive(Debug, thiserror::Error)]
pub enum AcquisitionError {
    #[error(transparent)]
    Start(#[from] StartError),
    #[error(transparent)]
    Stopped(Stopped),
    #[error("lei daemon setup failed: {0}")]
    SetupFailed(ExitStatus),
    #[error(transparent)]
    ReadPid(DirectoryError),
    #[error("decode lei daemon-pid result in setup.stdout")]
    DecodePid(#[source] Utf8Error),
    #[error("parse lei daemon-pid result in setup.stdout")]
    ParsePid(#[source] ParseIntError),
    #[error("invalid daemon PID")]
    InvalidPid,
    #[error(transparent)]
    OpenDaemon(Errno),
}
impl AcquisitionError {
    pub fn is_cancellation(&self) -> bool {
        matches!(
            self,
            Self::Stopped(Stopped {
                reason: StopReason::Cancelled,
                ..
            })
        )
    }
}

#[derive(Debug)]
pub struct Stopped {
    pub reason: StopReason,
    pub failures: Vec<StopError>,
}
impl fmt::Display for Stopped {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.reason.fmt(formatter)
    }
}
impl std::error::Error for Stopped {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.reason.source()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StopReason {
    #[error(transparent)]
    Wait(std::io::Error),
    #[error("acquisition timeout")]
    Timeout,
    #[error("{}", INTERRUPTION)]
    Cancelled,
}

#[derive(Debug, thiserror::Error)]
pub enum StopError {
    #[error("stop lei query")]
    Kill(#[source] std::io::Error),
    #[error("wait for lei query termination")]
    Wait(#[source] std::io::Error),
}

#[derive(Debug, thiserror::Error)]
pub enum CleanupError {
    #[error(transparent)]
    Start(#[from] StartError),
    #[error("wait for lei daemon-pid")]
    WaitIdentify(#[source] std::io::Error),
    #[error(transparent)]
    ReadPid(DirectoryError),
    #[error("wait for lei daemon-kill")]
    WaitKill(#[source] std::io::Error),
    #[error("lei daemon-kill failed: {0}")]
    KillFailed(ExitStatus),
    #[error("daemon identity was not established; termination cannot be confirmed")]
    Unidentified,
    #[error("send SIGKILL to the owned daemon")]
    Signal(#[source] Errno),
    #[error("watch the owned daemon")]
    Watch(#[source] std::io::Error),
    #[error("wait for the owned daemon to exit")]
    WaitExit(#[source] std::io::Error),
}

/// The message contains the text of every failure, joined by `; `. None of the
/// failures is its source.
#[derive(Debug)]
pub struct IngestFailure {
    pub failures: Vec<MaildirFailure>,
    pub aborted: Option<IngestAborted>,
}
impl fmt::Display for IngestFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let texts = self
            .failures
            .iter()
            .map(|failure| error_text(failure))
            .chain(self.aborted.iter().map(|error| error_text(error)));
        formatter.write_str(&list_text(texts))
    }
}
impl std::error::Error for IngestFailure {}

#[derive(Debug, thiserror::Error)]
pub enum IngestAborted {
    #[error(transparent)]
    OpenMaildir(DirectoryError),
    #[error(transparent)]
    ListMaildir(DirectoryError),
    #[error("unexpected Maildir entry {name:?}")]
    UnexpectedEntry { name: OsString },
    #[error("store Maildir input {}/{name:?}", .folder.name())]
    Store {
        folder: MaildirFolder,
        name: OsString,
        #[source]
        source: StorageError,
    },
    #[error(transparent)]
    Deliver(StorageError),
}

#[derive(Debug, thiserror::Error)]
pub enum MaildirFailure {
    #[error("missing or invalid {folder}")]
    Folder {
        folder: ScannedFolder,
        #[source]
        source: DirectoryError,
    },
    #[error("enumerate Maildir directory {folder}")]
    List {
        folder: ScannedFolder,
        #[source]
        source: DirectoryError,
    },
    #[error("invalid Maildir entry {name:?}")]
    Open {
        name: OsString,
        #[source]
        source: DirectoryError,
    },
    #[error("invalid Maildir entry {name:?}")]
    Read {
        name: OsString,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid delivered mail artifact {digest}")]
    InvalidMail { digest: String },
}
