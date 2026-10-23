use crate::{
    mail,
    model::{
        Artifact, Attempt, Configuration, CorpusState, FORMAT_VERSION, MaildirFolder, Outcome,
        Records, Root, Segment,
    },
    staging::{AttemptHandle, Staging},
};
use directory::valid_digest;
pub use directory::{Directory, digest};
pub use error::{DirectoryError, InvalidComponent, StorageError, ValidationError};
pub use read::{Stored, read};
use rustix::{
    fs::{self, OFlags},
    io::Errno,
};
use std::{collections::BTreeSet, ffi::OsStr, fs::File, io::Write, path::Path, str::FromStr};
pub use version3::FORMAT_VERSION_3;

mod directory;
mod error;
mod read;
mod validate;
mod version3;

pub fn attempt_name(id: u64) -> String {
    format!("{id:020}")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataDirectory {
    Raw,
    Segments,
    Attempts,
}
impl DataDirectory {
    pub fn name(self) -> &'static str {
        match self {
            Self::Raw => "raw",
            Self::Segments => "segments",
            Self::Attempts => "attempts",
        }
    }
    pub fn path(self, name: &str) -> String {
        format!("{}/{name}", self.name())
    }
}
impl FromStr for DataDirectory {
    type Err = StorageError;
    fn from_str(name: &str) -> Result<Self, StorageError> {
        [Self::Raw, Self::Segments, Self::Attempts]
            .into_iter()
            .find(|directory| directory.name() == name)
            .ok_or_else(|| StorageError::UnexpectedEntry { name: name.into() })
    }
}

fn initialization_entry(entry: &OsStr) -> bool {
    entry == ".lock" || entry == ".manifest.tmp" || entry == DataDirectory::Segments.name()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Access {
    Read,
    Write,
}

fn lock(path: &Path, access: Access) -> Result<(Directory, File), StorageError> {
    // Starting the launcher copies the descriptors of the process. A lock
    // released by another thread meanwhile is busy until the copy is closed,
    // and closing a copied file of a FUSE mount waits for the FUSE server, so
    // the launcher starts before the corpus is created, opened or locked.
    voidport_spawn::start_launcher().map_err(StorageError::Launcher)?;
    let writable = access == Access::Write;
    if writable {
        match std::fs::create_dir(path) {
            Ok(()) => {
                let parent = path
                    .parent()
                    .filter(|p| !p.as_os_str().is_empty())
                    .unwrap_or(Path::new("."));
                File::open(parent)
                    .and_then(|parent| parent.sync_all())
                    .map_err(StorageError::SyncCorpusParent)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(StorageError::CreateCorpus(error)),
        }
    }
    let root = Directory::open(path).map_err(StorageError::OpenCorpus)?;
    let uid = fs::fstat(&root.0).map_err(DirectoryError::Stat)?.st_uid;
    if uid != rustix::process::geteuid().as_raw() {
        return Err(StorageError::ForeignUser);
    }
    let entries = root.entries()?;
    let has_manifest = root.exists("manifest.json")?;
    if !has_manifest {
        if !writable {
            return Err(StorageError::Missing);
        }
        if !entries.iter().all(|entry| initialization_entry(entry)) {
            return Err(StorageError::ForeignEntries);
        }
    }
    // All contenders open the same permanent inode. EXCL only sets which of
    // them creates it.
    let lock = if writable && !has_manifest && !root.exists(".lock")? {
        match root.file(".lock", OFlags::RDWR | OFlags::CREATE | OFlags::EXCL) {
            Ok(file) => file,
            Err(DirectoryError::Open(Errno::EXIST)) => root.file(".lock", OFlags::RDWR)?,
            Err(error) => return Err(error.into()),
        }
    } else {
        root.file(
            ".lock",
            if writable {
                OFlags::RDWR
            } else {
                OFlags::RDONLY
            },
        )?
    };
    fs::flock(
        &lock,
        if writable {
            fs::FlockOperation::NonBlockingLockExclusive
        } else {
            fs::FlockOperation::NonBlockingLockShared
        },
    )
    .map_err(StorageError::Busy)?;
    Ok((root, lock))
}

pub struct Corpus {
    root: Directory,
    _lock: File,
    state: CorpusState,
    segments: BTreeSet<String>,
}
impl Corpus {
    /// A corpus of format version 3 is rejected, as only a writer converts it.
    pub fn open(path: &Path) -> Result<Self, StorageError> {
        let (root, lock) = lock(path, Access::Read)?;
        match read(&root)? {
            Stored::Current { state, segments } => Ok(Self {
                root,
                _lock: lock,
                state,
                segments,
            }),
            Stored::Version3(_) => Err(StorageError::NeedsCarryOver {
                version: FORMAT_VERSION_3,
            }),
            Stored::Missing => Err(StorageError::Missing),
        }
    }
    pub fn state(&self) -> &CorpusState {
        &self.state
    }
    pub fn inventory(&self) -> Result<(Vec<String>, Vec<String>), StorageError> {
        let mut partial = Vec::new();
        let mut attempts = Vec::new();
        for entry in self.root.entries()? {
            match entry.to_str() {
                Some(".lock" | "manifest.json") => self.root.check_file(&entry)?,
                Some(".manifest.tmp") => {
                    self.root.check_file(&entry)?;
                    partial.push(".manifest.tmp".into());
                }
                Some(name) => match name.parse()? {
                    DataDirectory::Raw => {
                        partial.extend(self.unreferenced(DataDirectory::Raw, |key| {
                            self.state.records.artifacts.contains_key(key)
                        })?);
                    }
                    DataDirectory::Segments => {
                        partial.extend(self.unreferenced(DataDirectory::Segments, |key| {
                            self.segments.contains(key)
                        })?);
                    }
                    DataDirectory::Attempts => {
                        let directory = self.root.child(name)?;
                        for name in directory.entries()? {
                            let text = name.to_str().ok_or(StorageError::AttemptDirectoryName)?;
                            if !text
                                .parse::<u64>()
                                .is_ok_and(|id| id > 0 && attempt_name(id) == text)
                            {
                                return Err(StorageError::AttemptDirectoryName);
                            }
                            let _checked_directory = directory.child(&name)?;
                            attempts.push(DataDirectory::Attempts.path(text));
                        }
                    }
                },
                None => return Err(StorageError::UnexpectedEntry { name: entry }),
            }
        }
        Ok((partial, attempts))
    }
    fn unreferenced(
        &self,
        directory: DataDirectory,
        referenced: impl Fn(&str) -> bool,
    ) -> Result<Vec<String>, StorageError> {
        let files = self.root.child(directory.name())?;
        let mut paths = Vec::new();
        for entry in files.entries()? {
            files.check_file(&entry)?;
            let key = entry
                .to_str()
                .ok_or(StorageError::NonUtf8DataFile { directory })?;
            if !valid_digest(key) && !key.strip_suffix(".partial").is_some_and(valid_digest) {
                return Err(StorageError::DataFileName { directory });
            }
            if !referenced(key) {
                paths.push(directory.path(key));
            }
        }
        Ok(paths)
    }
    pub fn verify(&self) -> Result<(), StorageError> {
        self.state.validate()?;
        let _entries_checked = self.inventory()?;
        let mut recomputed = self.state.clone();
        if !recomputed.records.artifacts.is_empty() {
            let raw = self.root.child(DataDirectory::Raw.name())?;
            for (key, artifact) in &mut recomputed.records.artifacts {
                let bytes = raw.read(key)?;
                if digest(&bytes) != *key
                    || !u64::try_from(bytes.len()).is_ok_and(|length| length == artifact.length)
                {
                    return Err(StorageError::RawIntegrity { key: key.clone() });
                }
                artifact.metadata = mail::interpret(&bytes, &recomputed.configuration.authors);
            }
        }
        recomputed.rebuild();
        if recomputed != self.state {
            return Err(StorageError::DerivedRecords);
        }
        Ok(())
    }
}

pub struct Writer {
    corpus: Corpus,
    staging: Staging,
}
impl Writer {
    /// A corpus of format version 3 is opened as it is stored, and `carry_over`
    /// converts it.
    pub fn open(path: &Path, configuration: Configuration) -> Result<Self, StorageError> {
        let (root, lock) = lock(path, Access::Write)?;
        let stored = read(&root)?;
        let created = matches!(stored, Stored::Missing);
        let (state, segments) = match stored {
            Stored::Current { state, segments } => (state, segments),
            Stored::Version3(state) => (state, BTreeSet::new()),
            Stored::Missing => {
                if !root
                    .entries()?
                    .iter()
                    .all(|entry| initialization_entry(entry))
                {
                    return Err(StorageError::ForeignInitialization);
                }
                (CorpusState::new(configuration), BTreeSet::new())
            }
        };
        let mut writer = Self {
            staging: Staging::new(&state),
            corpus: Corpus {
                root,
                _lock: lock,
                state,
                segments,
            },
        };
        if created {
            writer.publish()?;
        }
        Ok(writer)
    }
    pub fn state(&self) -> &CorpusState {
        self.corpus.state()
    }
    pub fn inventory(&self) -> Result<(Vec<String>, Vec<String>), StorageError> {
        self.corpus.inventory()
    }
    pub fn verify(&self) -> Result<(), StorageError> {
        self.corpus.verify()
    }
    pub fn carry_over(&mut self) -> Result<(), StorageError> {
        if self.corpus.state.head.is_some() {
            return Ok(());
        }
        self.publish()
    }
    pub fn data_dir(&self, directory: DataDirectory) -> Result<Directory, StorageError> {
        let root = &self.corpus.root;
        let name = directory.name();
        if root.exists(name)? {
            Ok(root.child(name)?)
        } else {
            Ok(root.mkdir(name)?)
        }
    }
    pub fn store(&self, bytes: &[u8]) -> Result<Artifact, StorageError> {
        let key = self.retain(DataDirectory::Raw, bytes, |_| StorageError::RawDiffers)?;
        // Interpretation runs only after the bytes are durably stored.
        Ok(Artifact {
            digest: key.clone(),
            length: u64::try_from(bytes.len()).map_err(StorageError::ArtifactLength)?,
            path: DataDirectory::Raw.path(&key),
            metadata: mail::interpret(bytes, &self.corpus.state.configuration.authors),
        })
    }
    fn retain(
        &self,
        directory: DataDirectory,
        bytes: &[u8],
        differs: impl FnOnce(String) -> StorageError,
    ) -> Result<String, StorageError> {
        let key = digest(bytes);
        let files = self.data_dir(directory)?;
        if files.exists(&key)? {
            if files.read(&key)? != bytes {
                return Err(differs(key));
            }
            files
                .file(&key, OFlags::RDONLY)?
                .sync_all()
                .map_err(DirectoryError::Sync)?;
        } else {
            let staging = format!("{key}.partial");
            if files.exists(&staging)? {
                files.check_file(&staging)?;
                fs::unlinkat(&files.0, &staging, fs::AtFlags::empty())
                    .map_err(StorageError::Remove)?;
            }
            let mut file = files.file(&staging, OFlags::CREATE | OFlags::EXCL | OFlags::WRONLY)?;
            file.write_all(bytes).map_err(StorageError::Write)?;
            file.sync_all().map_err(DirectoryError::Sync)?;
            fs::renameat_with(
                &files.0,
                &staging,
                &files.0,
                &key,
                fs::RenameFlags::NOREPLACE,
            )
            .map_err(StorageError::Rename)?;
        }
        files.sync()?;
        Ok(key)
    }
    pub fn add_attempt(&mut self, attempt: Attempt) -> Result<AttemptHandle, StorageError> {
        self.staging.add_attempt(&self.corpus.state, attempt)
    }
    pub fn attempt(&self, attempt: AttemptHandle) -> Result<&Attempt, StorageError> {
        self.staging.attempt(&self.corpus.state, attempt)
    }
    pub fn running_attempts(&self) -> Vec<AttemptHandle> {
        self.staging.running(&self.corpus.state)
    }
    pub fn record_outcome(
        &mut self,
        attempt: AttemptHandle,
        outcome: Outcome,
    ) -> Result<(), StorageError> {
        self.staging
            .record_outcome(&self.corpus.state, attempt, outcome)
    }
    pub fn fail(&mut self, attempt: AttemptHandle, error: String) -> Result<(), StorageError> {
        self.staging.fail(&self.corpus.state, attempt, error)
    }
    pub fn deliver(
        &mut self,
        attempt: AttemptHandle,
        folder: MaildirFolder,
        filename: &OsStr,
        artifact: Artifact,
    ) -> Result<(), StorageError> {
        self.staging
            .deliver(&self.corpus.state, attempt, folder, filename, artifact)
    }
    pub fn publish(&mut self) -> Result<(), StorageError> {
        let records = self.staging.records(&self.corpus.state);
        self.commit(records)
    }
    /// The segment and its directory are synced before the root that contains
    /// its name replaces `manifest.json`.
    fn commit(&mut self, records: Records) -> Result<(), StorageError> {
        let state = &self.corpus.state;
        let generation = state
            .generation
            .checked_add(1)
            .ok_or(StorageError::GenerationExhausted)?;
        let segment = match &state.head {
            Some(previous) => Segment {
                generation,
                previous: Some(previous.clone()),
                records,
            },
            // The first segment contains every record of the corpus, such as
            // those of a corpus of format version 3.
            None => {
                let mut whole = state.records.clone();
                whole.fold(records);
                Segment {
                    generation,
                    previous: None,
                    records: whole,
                }
            }
        };
        let encoded = segment.encode().map_err(StorageError::Encode)?;
        let name = self.retain(DataDirectory::Segments, &encoded, |name| {
            StorageError::SegmentDiffers { name }
        })?;
        let root = Root {
            format_version: FORMAT_VERSION,
            generation,
            configuration: state.configuration.clone(),
            head: name.clone(),
        };
        let directory = &self.corpus.root;
        if directory.exists(".manifest.tmp")? {
            directory.check_file(".manifest.tmp")?;
            fs::unlinkat(&directory.0, ".manifest.tmp", fs::AtFlags::empty())
                .map_err(StorageError::Remove)?;
        }
        let mut temporary = directory.file(
            ".manifest.tmp",
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL,
        )?;
        let encoded = root.encode().map_err(StorageError::Encode)?;
        temporary.write_all(&encoded).map_err(StorageError::Write)?;
        temporary.sync_all().map_err(DirectoryError::Sync)?;
        fs::renameat(&directory.0, ".manifest.tmp", &directory.0, "manifest.json")
            .map_err(StorageError::Rename)?;
        self.corpus.segments.extend([name.clone()]);
        self.corpus.state.advance(name, segment);
        self.staging.clear();
        self.corpus
            .root
            .sync()
            .map_err(StorageError::UncertainCommit)
    }
}
