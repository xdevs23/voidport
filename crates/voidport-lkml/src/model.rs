use crate::mail::{self, Class, Links, Mailbox, Metadata};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const DEFAULT_SOURCE: &str = "https://lore.kernel.org/lkml/";
pub const FORMAT_VERSION: u32 = 4;
pub const STATUS_VERSION: u32 = 2;
pub const LIMITATIONS: &[&str] = &[
    "Header attribution is not authentication or a complete alias inventory.",
    "Successful queries do not prove historical completeness or availability of every variant or ancestor.",
    "Exact bytes are those delivered by lei; variants not exposed by the client or archive cannot be preserved.",
    "A zero-exit valid empty Maildir is indistinguishable from an upstream refusal hidden by the client.",
    "Thread membership is acquisition provenance, not proof of delivery to every list named in headers.",
    "Client diagnostics are retained verbatim; an unexposed server retry interval cannot be enforced.",
    "Hard termination may leave client processes and private runtime state; stale process IDs are never signaled.",
];
/// A public-inbox archive queried through lei, such as one list on lore. The
/// path of a source ends in one `/`, so two spellings of one archive are equal.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Source(url::Url);
#[derive(Debug, thiserror::Error)]
pub enum SourceError {
    #[error("archive source {value} is not a URL")]
    NotUrl {
        value: String,
        #[source]
        source: url::ParseError,
    },
    #[error("archive source {value} is not a hierarchical URL; use one such as {DEFAULT_SOURCE}")]
    NotHierarchical { value: String },
}
#[derive(Debug, thiserror::Error)]
pub enum SourceListError {
    #[error(transparent)]
    Source(#[from] SourceError),
    #[error("empty source list")]
    Empty,
    #[error("archive source {} is listed twice", .0.as_str())]
    Repeated(Source),
}
impl TryFrom<String> for Source {
    type Error = SourceError;
    fn try_from(value: String) -> Result<Self, SourceError> {
        let mut url = match url::Url::parse(&value) {
            Ok(url) => url,
            Err(source) => return Err(SourceError::NotUrl { value, source }),
        };
        if url.cannot_be_a_base() {
            return Err(SourceError::NotHierarchical { value });
        }
        url.set_path(&format!("{}/", url.path().trim_end_matches('/')));
        Ok(Self(url))
    }
}
impl From<Source> for String {
    fn from(source: Source) -> Self {
        source.0.into()
    }
}
impl Source {
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
    fn archive_link(&self, id: &str) -> String {
        let mut url = self.0.clone();
        url.path_segments_mut()
            .expect("a source can be a base")
            .pop_if_empty()
            .push(id)
            .push("");
        url.into()
    }
}
pub fn sources(values: &[String]) -> Result<Vec<Source>, SourceListError> {
    let sources: Vec<Source> = values
        .iter()
        .cloned()
        .map(Source::try_from)
        .collect::<Result<_, _>>()?;
    check_sources(&sources)?;
    Ok(sources)
}
pub fn check_sources(sources: &[Source]) -> Result<(), SourceListError> {
    if sources.is_empty() {
        return Err(SourceListError::Empty);
    }
    let mut seen = BTreeSet::new();
    if let Some(repeated) = sources.iter().find(|source| !seen.insert(*source)) {
        return Err(SourceListError::Repeated(repeated.clone()));
    }
    Ok(())
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Unit {
    pub source: usize,
    pub query: usize,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Artifact {
    pub digest: String,
    pub length: u64,
    pub path: String,
    pub metadata: Metadata,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tool {
    pub executable: String,
    pub version: String,
    pub version_provenance: String,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttemptState {
    Running,
    Complete,
    Failed,
    Interrupted,
}
impl std::fmt::Display for AttemptState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Running => "running",
            Self::Complete => "complete",
            Self::Failed => "failed",
            Self::Interrupted => "interrupted",
        })
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MaildirFolder {
    New,
    Cur,
}
impl MaildirFolder {
    pub const ALL: [Self; 2] = [Self::New, Self::Cur];
    pub fn name(self) -> &'static str {
        match self {
            Self::New => "new",
            Self::Cur => "cur",
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Delivery {
    pub directory: MaildirFolder,
    pub filename_hex: String,
    pub digest: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attempt {
    pub id: u64,
    pub unit: Unit,
    pub directory: String,
    pub runtime: String,
    pub tool: Tool,
    pub arguments: Vec<String>,
    pub timeout_seconds: u64,
    pub delay_seconds: u64,
    pub started: String,
    pub finished: Option<String>,
    pub state: AttemptState,
    pub exit_code: Option<i32>,
    pub cleanup: String,
    pub errors: Vec<String>,
    pub deliveries: Vec<Delivery>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Observation {
    pub attempt: u64,
    pub unit: Unit,
    pub source: Source,
    pub membership: String,
    pub delivery: Delivery,
    pub archive_link: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub state: AttemptState,
    pub exit_code: Option<i32>,
    pub finished: String,
    pub cleanup: String,
    pub errors: Vec<String>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Configuration {
    pub sources: Vec<Source>,
    pub queries: Vec<String>,
    pub authors: Vec<Mailbox>,
}
impl Configuration {
    pub(crate) fn observation(
        &self,
        attempt: &Attempt,
        delivery: &Delivery,
        artifact: Option<&Artifact>,
    ) -> Observation {
        let source = &self.sources[attempt.unit.source];
        let archive_link = artifact
            .and_then(|artifact| artifact.metadata.primary_id.as_ref())
            .map(|id| source.archive_link(id));
        Observation {
            attempt: attempt.id,
            unit: attempt.unit,
            source: source.clone(),
            membership: "query_with_thread_expansion".into(),
            delivery: delivery.clone(),
            archive_link,
        }
    }
}
/// The root of a generation, `manifest.json`: the configuration of the corpus
/// and the segment published by the generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Root {
    pub format_version: u32,
    pub generation: u64,
    pub configuration: Configuration,
    pub head: String,
}
impl Root {
    pub fn encode(&self) -> serde_json::Result<Vec<u8>> {
        let mut bytes = serde_json::to_vec_pretty(self)?;
        bytes.push(b'\n');
        Ok(bytes)
    }
}
/// The records added by one publication, stored in an immutable file named by
/// the digest of its bytes. The first segment of a corpus contains every
/// record of the corpus at its generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Segment {
    /// The generation that published the segment, one more than the
    /// generation of the previous segment.
    pub generation: u64,
    /// The segment published by the generation before, absent in the first
    /// segment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous: Option<String>,
    pub records: Records,
}
impl Segment {
    pub fn encode(&self) -> serde_json::Result<Vec<u8>> {
        serde_json::to_vec(self)
    }
}
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Records {
    pub attempts: Vec<Attempt>,
    pub artifacts: BTreeMap<String, Artifact>,
    pub observations: Vec<Observation>,
    pub links: Links,
}
impl Records {
    /// Adds `later`, the records published after these. An attempt record
    /// replaces the earlier record with its ID, and the attempts remain
    /// ordered by ID. Link entries replace the earlier entries changed by them.
    pub(crate) fn fold(&mut self, later: Records) {
        for attempt in later.attempts {
            match self
                .attempts
                .binary_search_by_key(&attempt.id, |known| known.id)
            {
                Ok(index) => self.attempts[index] = attempt,
                Err(index) => self.attempts.insert(index, attempt),
            }
        }
        self.artifacts.extend(later.artifacts);
        self.observations.extend(later.observations);
        self.links.fold(later.links);
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorpusState {
    pub generation: u64,
    pub configuration: Configuration,
    /// None before the first publication, and in a corpus of format version
    /// 3, whose records are in no segment until they are converted.
    pub head: Option<String>,
    pub records: Records,
}
impl CorpusState {
    pub fn new(configuration: Configuration) -> Self {
        Self {
            generation: 0,
            configuration,
            head: None,
            records: Records::default(),
        }
    }
    /// Moves to the generation of `segment`, published as `name` by the next
    /// generation. A segment without a previous one contains every record, so
    /// it replaces the records instead of adding to them.
    pub(crate) fn advance(&mut self, name: String, segment: Segment) {
        self.generation = segment.generation;
        self.head = Some(name);
        match segment.previous {
            Some(_) => self.records.fold(segment.records),
            None => self.records = segment.records,
        }
    }
    pub fn units(&self) -> Vec<Unit> {
        let configuration = &self.configuration;
        (0..configuration.sources.len())
            .flat_map(|source| {
                (0..configuration.queries.len()).map(move |query| Unit { source, query })
            })
            .collect()
    }
    pub fn complete(&self, unit: Unit) -> bool {
        self.records
            .attempts
            .iter()
            .rev()
            .find(|attempt| attempt.unit == unit)
            .is_some_and(|attempt| attempt.state == AttemptState::Complete)
    }
    pub(crate) fn rebuild(&mut self) {
        let configuration = &self.configuration;
        let records = &self.records;
        let links = mail::links(
            records
                .artifacts
                .iter()
                .map(|(digest, artifact)| (digest, &artifact.metadata)),
        );
        let observations = records
            .attempts
            .iter()
            .flat_map(|attempt| {
                attempt.deliveries.iter().map(move |delivery| {
                    configuration.observation(
                        attempt,
                        delivery,
                        records.artifacts.get(&delivery.digest),
                    )
                })
            })
            .collect();
        self.records.links = links;
        self.records.observations = observations;
    }
}
pub fn now() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .expect("UTC timestamp")
}
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct TimestampError(time::error::Parse);
pub fn timestamp(value: &str) -> Result<time::OffsetDateTime, TimestampError> {
    time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339)
        .map_err(TimestampError)
}
pub(crate) fn check_timestamp(value: &str) -> Result<(), TimestampError> {
    let _checked = timestamp(value)?;
    Ok(())
}

#[derive(Debug, Serialize)]
pub struct Status<'a> {
    pub status_version: u32,
    pub format_version: u32,
    pub generation: u64,
    pub sources: &'a [Source],
    pub counts: BTreeMap<&'static str, usize>,
    pub missing_context: Vec<MissingContext<'a>>,
    pub units: Vec<UnitStatus<'a>>,
    pub attempts: &'a [Attempt],
    pub partial_files: Vec<String>,
    pub retained_attempt_directories: Vec<String>,
    pub limitations: &'static [&'static str],
}
#[derive(Debug, Serialize)]
pub struct MissingContext<'a> {
    pub source_digest: &'a str,
    pub target_message_id: &'a str,
}
#[derive(Debug, Serialize)]
pub struct UnitStatus<'a> {
    pub source: &'a Source,
    pub query: &'a str,
    pub complete: bool,
}
pub fn status<'a>(
    state: &'a CorpusState,
    partial_files: Vec<String>,
    retained_attempt_directories: Vec<String>,
) -> Status<'a> {
    let mut counts = BTreeMap::new();
    for (name, class) in [
        ("invalid", Class::Invalid),
        ("ambiguous_from", Class::AmbiguousFrom),
        ("context", Class::Context),
        ("unlinked_author", Class::UnlinkedAuthor),
        ("ambiguous_reply", Class::AmbiguousReply),
        ("response", Class::Response),
    ] {
        counts.insert(
            name,
            state
                .records
                .artifacts
                .values()
                .filter(|artifact| artifact.metadata.class == class)
                .count(),
        );
    }
    let units: Vec<_> = state
        .units()
        .into_iter()
        .map(|unit| UnitStatus {
            source: &state.configuration.sources[unit.source],
            query: &state.configuration.queries[unit.query],
            complete: state.complete(unit),
        })
        .collect();
    let complete = units.iter().filter(|unit| unit.complete).count();
    let missing_context: Vec<_> = state
        .records
        .links
        .relationships
        .iter()
        .filter(|(_, relation)| relation.targets.is_empty())
        .map(|(digest, relation)| MissingContext {
            source_digest: digest,
            target_message_id: &relation.candidate.id,
        })
        .collect();
    counts.extend([
        ("artifacts", state.records.artifacts.len()),
        ("observations", state.records.observations.len()),
        ("message_ids", state.records.links.message_ids.len()),
        (
            "variant_ids",
            state
                .records
                .links
                .message_ids
                .values()
                .filter(|values| values.len() > 1)
                .count(),
        ),
        ("missing_parents", missing_context.len()),
        ("complete_units", complete),
        ("unfinished_units", units.len() - complete),
        ("partial_files", partial_files.len()),
    ]);
    Status {
        status_version: STATUS_VERSION,
        format_version: FORMAT_VERSION,
        generation: state.generation,
        sources: &state.configuration.sources,
        counts,
        missing_context,
        units,
        attempts: &state.records.attempts,
        partial_files,
        retained_attempt_directories,
        limitations: LIMITATIONS,
    }
}
