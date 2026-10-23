use super::DataDirectory;
use crate::{
    mail::AuthorError,
    model::{FORMAT_VERSION, SourceListError, TimestampError},
};
use rustix::io::Errno;
use std::{ffi::OsString, num::TryFromIntError};
use voidport_spawn::SpawnError;

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error(transparent)]
    Directory(#[from] DirectoryError),
    #[error(transparent)]
    CreateCorpus(std::io::Error),
    #[error(transparent)]
    SyncCorpusParent(std::io::Error),
    #[error("open corpus directory without following a symlink")]
    OpenCorpus(#[source] DirectoryError),
    #[error("corpus must be owned by caller")]
    ForeignUser,
    #[error("missing corpus or incomplete initialization")]
    Missing,
    #[error("foreign nonempty directory")]
    ForeignEntries,
    #[error("foreign initialization state")]
    ForeignInitialization,
    #[error("cannot lock the corpus")]
    Launcher(#[source] SpawnError),
    #[error("corpus busy")]
    Busy(#[source] Errno),
    #[error("unsupported manifest version {version}")]
    UnsupportedVersion { version: u32 },
    #[error("corpus format version {version} has to be converted to version {FORMAT_VERSION}")]
    NeedsCarryOver { version: u32 },
    #[error("unreadable manifest")]
    RootParse(#[source] serde_json::Error),
    #[error("invalid segment name {name:?}")]
    SegmentName { name: String },
    #[error("cannot read segment {name}")]
    SegmentRead {
        name: String,
        #[source]
        source: DirectoryError,
    },
    #[error("segment integrity mismatch: {name}")]
    SegmentIntegrity { name: String },
    #[error("unreadable segment {name}")]
    SegmentParse {
        name: String,
        #[source]
        source: serde_json::Error,
    },
    #[error("segment out of order: {name}")]
    SegmentOrder { name: String },
    #[error(transparent)]
    Invalid(#[from] ValidationError),
    #[error("unexpected corpus entry: {name:?}")]
    UnexpectedEntry { name: OsString },
    #[error("invalid attempt directory name")]
    AttemptDirectoryName,
    #[error("non-UTF8 {} filename", directory.name())]
    NonUtf8DataFile { directory: DataDirectory },
    #[error("invalid {} path", directory.name())]
    DataFileName { directory: DataDirectory },
    #[error("raw integrity mismatch: {key}")]
    RawIntegrity { key: String },
    #[error("derived metadata, links or observations differ from recomputed corpus")]
    DerivedRecords,
    #[error(transparent)]
    ArtifactLength(TryFromIntError),
    #[error("existing blob differs from delivered bytes")]
    RawDiffers,
    #[error("existing segment {name} differs from the bytes of its publication")]
    SegmentDiffers { name: String },
    #[error(transparent)]
    Remove(Errno),
    #[error(transparent)]
    Write(std::io::Error),
    #[error(transparent)]
    Rename(Errno),
    #[error(transparent)]
    Encode(serde_json::Error),
    #[error("generation exhausted")]
    GenerationExhausted,
    #[error("uncertain manifest commit: rename succeeded but directory synchronization did not")]
    UncertainCommit(#[source] DirectoryError),
    #[error("attempt {id} does not follow attempt {last}")]
    AttemptOrder { id: u64, last: u64 },
    #[error("no attempt {id} in the corpus")]
    UnknownAttempt { id: u64 },
    #[error("thread without members")]
    ThreadWithoutMembers,
    #[error("thread {key} listed twice")]
    ThreadListedTwice { key: String },
}

#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    #[error("invalid corpus configuration")]
    NoQueries,
    #[error(transparent)]
    Sources(SourceListError),
    #[error(transparent)]
    Authors(AuthorError),
    #[error("invalid author policy")]
    AuthorPolicy,
    #[error("invalid attempt identity")]
    AttemptIdentity,
    #[error("invalid attempt path")]
    AttemptPath,
    #[error("invalid attempt durations")]
    AttemptDurations,
    #[error("invalid query receipt")]
    QueryReceipt,
    #[error(transparent)]
    Timestamp(TimestampError),
    #[error("invalid completion timestamp")]
    CompletionTimestamp,
    #[error("invalid completed attempt")]
    CompletedAttempt,
    #[error(transparent)]
    FilenameHex(hex::FromHexError),
    #[error(transparent)]
    Filename(InvalidComponent),
    #[error("duplicate delivery")]
    DuplicateDelivery,
    #[error("delivery references missing artifact")]
    MissingArtifact,
    #[error("invalid artifact in completed attempt")]
    InvalidArtifact,
    #[error("invalid artifact identity or path")]
    ArtifactIdentity,
    #[error("artifact without acquisition observation")]
    UnobservedArtifact,
}

#[derive(Debug, thiserror::Error)]
pub enum DirectoryError {
    #[error(transparent)]
    Component(#[from] InvalidComponent),
    #[error(transparent)]
    Open(Errno),
    #[error(transparent)]
    Create(Errno),
    #[error(transparent)]
    Stat(Errno),
    #[error("expected an unlinked-from-other-paths regular file")]
    LinkedOrIrregularFile,
    #[error("expected a regular Maildir input file")]
    IrregularMaildirInput,
    #[error(transparent)]
    Read(std::io::Error),
    #[error(transparent)]
    List(Errno),
    #[error(transparent)]
    Sync(std::io::Error),
}

#[derive(Debug, thiserror::Error)]
#[error("invalid path component")]
pub struct InvalidComponent;
