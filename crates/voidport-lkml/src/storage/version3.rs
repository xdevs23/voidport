use super::StorageError;
use crate::{
    mail::{Links, Mailbox, Relationship, Thread},
    model::{Artifact, Attempt, Configuration, CorpusState, Observation, Records, Source},
};
use serde::Deserialize;
use std::collections::BTreeMap;

pub const FORMAT_VERSION_3: u32 = 3;

#[derive(Debug, Deserialize)]
pub(super) struct ManifestV3 {
    generation: u64,
    sources: Vec<Source>,
    queries: Vec<String>,
    authors: Vec<Mailbox>,
    attempts: Vec<Attempt>,
    artifacts: BTreeMap<String, Artifact>,
    observations: Vec<Observation>,
    links: LinksV3,
}
#[derive(Debug, Deserialize)]
struct LinksV3 {
    message_ids: BTreeMap<String, Vec<String>>,
    relationships: BTreeMap<String, Relationship>,
    threads: Vec<Thread>,
}
impl TryFrom<ManifestV3> for CorpusState {
    type Error = StorageError;
    /// Converts every record unchanged. Only the list of threads becomes a
    /// map keyed by their smallest members. The state has no segment until a
    /// writer converts the corpus.
    fn try_from(manifest: ManifestV3) -> Result<Self, StorageError> {
        let mut threads = BTreeMap::new();
        for thread in manifest.links.threads {
            let key = thread
                .members
                .first()
                .ok_or(StorageError::ThreadWithoutMembers)?
                .clone();
            if threads.insert(key.clone(), thread).is_some() {
                return Err(StorageError::ThreadListedTwice { key });
            }
        }
        Ok(Self {
            generation: manifest.generation,
            configuration: Configuration {
                sources: manifest.sources,
                queries: manifest.queries,
                authors: manifest.authors,
            },
            head: None,
            records: Records {
                attempts: manifest.attempts,
                artifacts: manifest.artifacts,
                observations: manifest.observations,
                links: Links {
                    message_ids: manifest.links.message_ids,
                    relationships: manifest.links.relationships,
                    threads,
                },
            },
        })
    }
}
