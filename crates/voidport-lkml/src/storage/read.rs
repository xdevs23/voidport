use super::{
    DataDirectory, Directory, FORMAT_VERSION_3, StorageError,
    directory::{digest, valid_digest},
    version3::ManifestV3,
};
use crate::model::{CorpusState, FORMAT_VERSION, Records, Root, Segment};
use serde::Deserialize;
use std::collections::BTreeSet;

#[derive(Deserialize)]
struct FormatHeader {
    format_version: u32,
}

#[derive(Debug)]
pub enum Stored {
    Missing,
    Current {
        state: CorpusState,
        segments: BTreeSet<String>,
    },
    Version3(CorpusState),
}

/// Reads the corpus in `directory` without taking its lock. A segment is
/// written before the root that contains its name and never changes, so the
/// corpus read is one complete generation, also while a writer publishes.
pub fn read(directory: &Directory) -> Result<Stored, StorageError> {
    if !directory.exists("manifest.json")? {
        return Ok(Stored::Missing);
    }
    let bytes = directory.read("manifest.json")?;
    let header: FormatHeader = serde_json::from_slice(&bytes).map_err(StorageError::RootParse)?;
    let stored = match header.format_version {
        FORMAT_VERSION => {
            let root = serde_json::from_slice(&bytes).map_err(StorageError::RootParse)?;
            let (state, segments) = load(directory, root)?;
            state.validate()?;
            Stored::Current { state, segments }
        }
        FORMAT_VERSION_3 => {
            let manifest: ManifestV3 =
                serde_json::from_slice(&bytes).map_err(StorageError::RootParse)?;
            let state = CorpusState::try_from(manifest)?;
            state.validate()?;
            Stored::Version3(state)
        }
        version => return Err(StorageError::UnsupportedVersion { version }),
    };
    Ok(stored)
}

fn load(
    directory: &Directory,
    root: Root,
) -> Result<(CorpusState, BTreeSet<String>), StorageError> {
    let segments = directory.child(DataDirectory::Segments.name())?;
    let mut chain = Vec::new();
    let mut next = Some((root.head.clone(), root.generation));
    while let Some((name, generation)) = next {
        let segment = read_segment(&segments, &name)?;
        if generation == 0 || segment.generation != generation {
            return Err(StorageError::SegmentOrder { name });
        }
        next = segment
            .previous
            .clone()
            .map(|previous| (previous, generation - 1));
        chain.push((name, segment));
    }
    let mut records = Records::default();
    let mut names = BTreeSet::new();
    for (name, segment) in chain.into_iter().rev() {
        records.fold(segment.records);
        names.extend([name]);
    }
    let state = CorpusState {
        generation: root.generation,
        configuration: root.configuration,
        head: Some(root.head),
        records,
    };
    Ok((state, names))
}

fn read_segment(segments: &Directory, name: &str) -> Result<Segment, StorageError> {
    if !valid_digest(name) {
        return Err(StorageError::SegmentName { name: name.into() });
    }
    let bytes = segments
        .read(name)
        .map_err(|source| StorageError::SegmentRead {
            name: name.into(),
            source,
        })?;
    if digest(&bytes) != name {
        return Err(StorageError::SegmentIntegrity { name: name.into() });
    }
    serde_json::from_slice(&bytes).map_err(|source| StorageError::SegmentParse {
        name: name.into(),
        source,
    })
}
