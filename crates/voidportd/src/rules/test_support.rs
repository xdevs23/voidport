//! Shared support for the rule engine's cross-cutting tests.

use super::name::Name;
use super::path::NamespacePath;
use super::resolve::{DirContext, DirEntry, Resolution};
use super::table::{HostBacking, RuleSpec, RuleTable};

pub(crate) fn name(raw: &str) -> Name {
    Name::new(raw).expect("valid name")
}

pub(crate) fn path(raw: &str) -> NamespacePath {
    NamespacePath::parse(raw).expect("valid namespace path")
}

pub(crate) fn table(rules: impl IntoIterator<Item = RuleSpec>) -> RuleTable {
    RuleTable::build(rules).expect("valid table")
}

/// The directory context at a namespace path, which must resolve.
pub(crate) fn dir(table: &RuleTable, raw: &str) -> DirContext {
    table.walk(&path(raw)).expect("reachable directory")
}

/// A backing rendered as its graft and relative components, never as an
/// absolute host path assembled from the two.
pub(crate) fn describe_backing(backing: &HostBacking) -> String {
    let relative = backing
        .relative()
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("/");
    format!("graft={:?} relative={relative:?}", backing.graft().as_str())
}

/// A resolution rendered compactly: the mode and split host backing, or the
/// kind of non-host-backed outcome.
pub(crate) fn describe(resolution: &Resolution) -> String {
    match resolution {
        Resolution::HostBacked { backing, mode } => {
            format!("{mode:?} {}", describe_backing(backing))
        }
        Resolution::SynthesizedDir => "SynthesizedDir".to_owned(),
        Resolution::Nonexistent => "Nonexistent".to_owned(),
    }
}

/// An unbounded enumeration keeping everything the rules admit: what a test
/// means when it asks what a directory looks like.
pub(crate) fn enumerate(
    table: &RuleTable,
    directory: &DirContext,
    host_names: impl IntoIterator<Item = Name>,
) -> Vec<DirEntry> {
    table
        .enumerate(directory, host_names, None, |_, _| Some(()))
        .expect("no cap to exceed")
}

/// The names an enumeration admitted, with their modes.
pub(crate) fn listing(entries: &[DirEntry]) -> Vec<String> {
    entries
        .iter()
        .map(|entry| format!("{} {}", entry.name, describe(&entry.resolution)))
        .collect()
}
