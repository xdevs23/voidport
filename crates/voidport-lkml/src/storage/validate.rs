use super::{
    DataDirectory, ValidationError, attempt_name,
    directory::{component, valid_digest},
};
use crate::{
    mail,
    model::{self, AttemptState, CorpusState},
};
use std::{collections::BTreeSet, ffi::OsStr, os::unix::ffi::OsStrExt};

impl CorpusState {
    pub(crate) fn validate(&self) -> Result<(), ValidationError> {
        let configuration = &self.configuration;
        let records = &self.records;
        if configuration.queries.is_empty() {
            return Err(ValidationError::NoQueries);
        }
        model::check_sources(&configuration.sources).map_err(ValidationError::Sources)?;
        let spellings: Vec<_> = configuration
            .authors
            .iter()
            .map(|a| a.spelling.clone())
            .collect();
        if mail::authors(&spellings).map_err(ValidationError::Authors)? != configuration.authors {
            return Err(ValidationError::AuthorPolicy);
        }
        let mut previous_id = 0;
        let mut delivered = BTreeSet::new();
        for attempt in &records.attempts {
            // Attempts ascend by ID, which is how a later record of an
            // attempt finds the earlier one.
            if attempt.id <= previous_id
                || attempt.unit.source >= configuration.sources.len()
                || attempt.unit.query >= configuration.queries.len()
            {
                return Err(ValidationError::AttemptIdentity);
            }
            previous_id = attempt.id;
            if attempt.directory != DataDirectory::Attempts.path(&attempt_name(attempt.id)) {
                return Err(ValidationError::AttemptPath);
            }
            if attempt.timeout_seconds == 0 || attempt.delay_seconds == 0 {
                return Err(ValidationError::AttemptDurations);
            }
            // Arguments record the execution as it ran, so the option spelling
            // and ordering are not checked. The command and final opaque query
            // remain structural.
            let receipt = attempt.arguments.len() >= 3
                && attempt.arguments.first().map(String::as_str) == Some("q")
                && attempt.arguments[attempt.arguments.len() - 2] == "--"
                && attempt.arguments.last() == Some(&configuration.queries[attempt.unit.query])
                && attempt.arguments.windows(2).any(|pair| {
                    pair[0] == "--only"
                        && pair[1] == configuration.sources[attempt.unit.source].as_str()
                })
                && attempt
                    .arguments
                    .iter()
                    .all(|argument| !argument.contains('\0'));
            if !receipt {
                return Err(ValidationError::QueryReceipt);
            }
            model::check_timestamp(&attempt.started).map_err(ValidationError::Timestamp)?;
            if let Some(finished) = &attempt.finished {
                model::check_timestamp(finished).map_err(ValidationError::Timestamp)?;
            }
            if (attempt.state == AttemptState::Running) != attempt.finished.is_none() {
                return Err(ValidationError::CompletionTimestamp);
            }
            if attempt.state == AttemptState::Complete
                && (attempt.exit_code != Some(0)
                    || !attempt.errors.is_empty()
                    || attempt.cleanup != "terminated")
            {
                return Err(ValidationError::CompletedAttempt);
            }
            let mut deliveries = BTreeSet::new();
            for delivery in &attempt.deliveries {
                let name =
                    hex::decode(&delivery.filename_hex).map_err(ValidationError::FilenameHex)?;
                component(OsStr::from_bytes(&name)).map_err(ValidationError::Filename)?;
                if !deliveries.insert((delivery.directory, &delivery.filename_hex)) {
                    return Err(ValidationError::DuplicateDelivery);
                }
                let Some(artifact) = records.artifacts.get(&delivery.digest) else {
                    return Err(ValidationError::MissingArtifact);
                };
                if attempt.state == AttemptState::Complete
                    && artifact.metadata.class == mail::Class::Invalid
                {
                    return Err(ValidationError::InvalidArtifact);
                }
                delivered.extend([&delivery.digest]);
            }
        }
        for (key, artifact) in &records.artifacts {
            if !valid_digest(key)
                || artifact.digest != *key
                || artifact.path != DataDirectory::Raw.path(key)
            {
                return Err(ValidationError::ArtifactIdentity);
            }
            if !delivered.contains(key) {
                return Err(ValidationError::UnobservedArtifact);
            }
        }
        Ok(())
    }
}
