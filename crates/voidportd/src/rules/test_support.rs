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

pub(crate) fn dir(table: &RuleTable, raw: &str) -> DirContext {
    table.walk(&path(raw)).expect("reachable directory")
}

/// Rendered as its graft and relative components, never as an assembled
/// absolute host path.
pub(crate) fn describe_backing(backing: &HostBacking) -> String {
    let relative = backing
        .relative()
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("/");
    format!("graft={:?} relative={relative:?}", backing.graft().as_str())
}

pub(crate) fn describe(resolution: &Resolution) -> String {
    match resolution {
        Resolution::HostBacked { backing, mode } => {
            format!("{mode:?} {}", describe_backing(backing))
        }
        Resolution::SynthesizedDir => "SynthesizedDir".to_owned(),
        Resolution::Nonexistent => "Nonexistent".to_owned(),
    }
}

pub(crate) fn enumerate(
    table: &RuleTable,
    directory: &DirContext,
    host_names: impl IntoIterator<Item = Name>,
) -> Vec<DirEntry> {
    table.enumerate(directory, host_names, |_, _| Some(()))
}

pub(crate) fn listing(entries: &[DirEntry]) -> Vec<String> {
    entries
        .iter()
        .map(|entry| format!("{} {}", entry.name, describe(&entry.resolution)))
        .collect()
}
