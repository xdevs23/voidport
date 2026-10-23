use crate::{
    mail::{self, Mentions},
    model::{
        Artifact, Attempt, AttemptState, CorpusState, Delivery, MaildirFolder, Observation,
        Outcome, Records,
    },
    storage::StorageError,
};
use std::{
    collections::{BTreeMap, btree_map::Entry},
    ffi::OsStr,
    os::unix::ffi::OsStrExt,
};

/// The ID of an attempt, taken by the operations of a writer that change the
/// attempt. A handle is valid for every later writer of the same corpus.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct AttemptHandle {
    id: u64,
}

#[derive(Debug)]
pub(crate) struct Staging {
    attempts: BTreeMap<u64, Attempt>,
    artifacts: BTreeMap<String, Artifact>,
    observations: Vec<Observation>,
    mentions: Mentions,
}
impl Staging {
    pub(crate) fn new(committed: &CorpusState) -> Self {
        Self {
            attempts: BTreeMap::new(),
            artifacts: BTreeMap::new(),
            observations: Vec::new(),
            mentions: committed
                .records
                .artifacts
                .iter()
                .map(|(digest, artifact)| (digest, &artifact.metadata))
                .collect(),
        }
    }
    pub(crate) fn add_attempt(
        &mut self,
        committed: &CorpusState,
        attempt: Attempt,
    ) -> Result<AttemptHandle, StorageError> {
        let last = committed
            .records
            .attempts
            .last()
            .map(|last| last.id)
            .max(self.attempts.keys().next_back().copied());
        if let Some(last) = last.filter(|last| *last >= attempt.id) {
            return Err(StorageError::AttemptOrder {
                id: attempt.id,
                last,
            });
        }
        let handle = AttemptHandle { id: attempt.id };
        self.attempts.extend([(attempt.id, attempt)]);
        Ok(handle)
    }
    pub(crate) fn attempt<'a>(
        &'a self,
        committed: &'a CorpusState,
        handle: AttemptHandle,
    ) -> Result<&'a Attempt, StorageError> {
        self.attempts
            .get(&handle.id)
            .or_else(|| published(committed, handle.id))
            .ok_or(StorageError::UnknownAttempt { id: handle.id })
    }
    /// Returns the staged copy of the attempt, recorded by the next
    /// publication. A published attempt is copied into the staging first.
    fn staged_attempt(
        &mut self,
        committed: &CorpusState,
        handle: AttemptHandle,
    ) -> Result<&mut Attempt, StorageError> {
        match self.attempts.entry(handle.id) {
            Entry::Occupied(entry) => Ok(entry.into_mut()),
            Entry::Vacant(entry) => {
                let attempt = published(committed, handle.id)
                    .ok_or(StorageError::UnknownAttempt { id: handle.id })?;
                Ok(entry.insert(attempt.clone()))
            }
        }
    }
    pub(crate) fn running(&self, committed: &CorpusState) -> Vec<AttemptHandle> {
        let unchanged = committed
            .records
            .attempts
            .iter()
            .filter(|attempt| !self.attempts.contains_key(&attempt.id));
        let mut running: Vec<_> = unchanged
            .chain(self.attempts.values())
            .filter(|attempt| attempt.state == AttemptState::Running)
            .map(|attempt| AttemptHandle { id: attempt.id })
            .collect();
        running.sort_unstable();
        running
    }
    pub(crate) fn record_outcome(
        &mut self,
        committed: &CorpusState,
        handle: AttemptHandle,
        outcome: Outcome,
    ) -> Result<(), StorageError> {
        let attempt = self.staged_attempt(committed, handle)?;
        let Outcome {
            state,
            exit_code,
            finished,
            cleanup,
            errors,
        } = outcome;
        attempt.state = state;
        attempt.exit_code = exit_code;
        attempt.finished = Some(finished);
        attempt.cleanup = cleanup;
        attempt.errors = errors;
        Ok(())
    }
    pub(crate) fn fail(
        &mut self,
        committed: &CorpusState,
        handle: AttemptHandle,
        error: String,
    ) -> Result<(), StorageError> {
        let attempt = self.staged_attempt(committed, handle)?;
        attempt.state = AttemptState::Failed;
        attempt.errors.push(error);
        Ok(())
    }
    pub(crate) fn deliver(
        &mut self,
        committed: &CorpusState,
        handle: AttemptHandle,
        folder: MaildirFolder,
        filename: &OsStr,
        artifact: Artifact,
    ) -> Result<(), StorageError> {
        let attempt = self.staged_attempt(committed, handle)?;
        let delivery = Delivery {
            directory: folder,
            filename_hex: hex::encode(filename.as_bytes()),
            digest: artifact.digest.clone(),
        };
        let observation = committed
            .configuration
            .observation(attempt, &delivery, Some(&artifact));
        attempt.deliveries.push(delivery);
        self.observations.push(observation);
        let digest = &artifact.digest;
        if !committed.records.artifacts.contains_key(digest) && !self.artifacts.contains_key(digest)
        {
            self.mentions.add(digest, &artifact.metadata);
            self.artifacts.extend([(digest.clone(), artifact)]);
        }
        Ok(())
    }
    pub(crate) fn records(&self, committed: &CorpusState) -> Records {
        let metadata = |digest: &String| {
            &self
                .artifacts
                .get(digest)
                .or_else(|| committed.records.artifacts.get(digest))
                .expect("the thread index contains only artifacts of the corpus")
                .metadata
        };
        let members = self.mentions.thread_members(self.artifacts.keys());
        let recomputed = mail::links(members.into_iter().map(|digest| (digest, metadata(digest))));
        Records {
            attempts: self.attempts.values().cloned().collect(),
            artifacts: self.artifacts.clone(),
            observations: self.observations.clone(),
            links: committed.records.links.changes(recomputed),
        }
    }
    /// Drops the staged records once they are published. The thread index is
    /// not cleared, as it covers the published artifacts too.
    pub(crate) fn clear(&mut self) {
        self.attempts.clear();
        self.artifacts.clear();
        self.observations.clear();
    }
}

fn published(committed: &CorpusState, id: u64) -> Option<&Attempt> {
    let attempts = &committed.records.attempts;
    attempts
        .binary_search_by_key(&id, |attempt| attempt.id)
        .ok()
        .map(|index| &attempts[index])
}
