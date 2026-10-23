//! The share set is a pure function of the published namespace and the subpath
//! of the session, so it runs under the publish lock without a host syscall. A
//! host-side `chown` or `mkdir` therefore produces no event.
//!
//! A wildcard is never enumerated, because the engine cannot name its children
//! without a host `readdir`. A hidden rule is dropped first, so it appears
//! neither as an entry nor as an event. A session mounted inside a share
//! reports the innermost enclosing share as the entry `/`, see [`root_entry`].

use std::collections::BTreeMap;

use crate::host::FileKind;
use crate::namespace::Namespace;
use crate::rules::{EffectiveMode, HostBacking, NamespacePath};

/// `Unknown` for a targetless mode-override island, whose derived path is never
/// opened, so no host I/O is needed to report a kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShareKind {
    Unknown,
    Directory,
    File,
}

impl ShareKind {
    /// A symlink or a device is `Unknown`, because the contract fixes only
    /// directory, file and unknown.
    #[must_use]
    fn of(kind: FileKind) -> Self {
        match kind {
            FileKind::Directory => Self::Directory,
            FileKind::Regular => Self::File,
            FileKind::Symlink | FileKind::Other => Self::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShareEntry {
    pub mode: EffectiveMode,
    pub kind: ShareKind,
}

/// Ordered, because a snapshot arrives in path order and a diff over two
/// ordered maps is a merge.
pub type ShareSet = BTreeMap<String, ShareEntry>;

#[must_use]
pub fn share_set(namespace: &Namespace, subpath: &NamespacePath) -> ShareSet {
    let mut entries = ShareSet::new();

    for (path, rule) in namespace.rules().literal_rules() {
        let Some(mode) = rule.mode.effective() else {
            continue;
        };
        if path.depth() <= subpath.depth() {
            // At or above the mount root: the session sees its own root as the
            // `/` entry.
            continue;
        }
        if path.prefix(subpath.depth()) != *subpath {
            // Outside the subtree: a session may not learn about rules its scope
            // excludes.
            continue;
        }
        entries.insert(
            relative(path, subpath.depth()),
            ShareEntry {
                mode,
                kind: kind_of(namespace, rule.backing.as_ref()),
            },
        );
    }

    if let Some(entry) = root_entry(namespace, subpath) {
        entries.insert("/".to_owned(), entry);
    }
    entries
}

/// Resolves the mount root as the data plane does, not through the innermost
/// enclosing literal rule: a wildcard such as `/tree/*` decides the mode of a
/// session mounted at `/tree/sub` although no literal rule names that path.
///
/// `None` for a mount on the namespace root or on a synthesized directory, and
/// for a mount root that resolves to nothing. The kind is `Directory` without
/// host I/O, because a session over anything else was refused with `ENOTDIR`
/// at the handshake.
fn root_entry(namespace: &Namespace, subpath: &NamespacePath) -> Option<ShareEntry> {
    let mode = namespace.rules().walk(subpath)?.mode()?;
    Some(ShareEntry {
        mode,
        kind: ShareKind::Directory,
    })
}

/// A rule that sets a target is a graft root, whose kind was recorded when it
/// was opened. A mode-override island names a path nothing opened, so its kind
/// is unknown.
fn kind_of(namespace: &Namespace, backing: Option<&HostBacking>) -> ShareKind {
    let Some(backing) = backing.filter(|backing| backing.is_graft_root()) else {
        return ShareKind::Unknown;
    };
    namespace
        .grafts()
        .kind(backing.graft())
        .map_or(ShareKind::Unknown, ShareKind::of)
}

fn relative(path: &NamespacePath, depth: usize) -> String {
    NamespacePath::from_components(path.components()[depth..].iter().cloned()).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::namespace::PolicyModes;
    use crate::rules::{
        Ownership, OwnershipMode, RuleSpec, RuleTable, ServerIdentity, ShareMode, SquashIds,
    };
    use voidport_control::NamespaceName;
    use voidport_test_host::Scratch;

    fn namespace(rules: Vec<RuleSpec>) -> Namespace {
        let table = RuleTable::build(rules).expect("valid table");
        let grafts = crate::host::Grafts::pin(&table).expect("every target exists");
        Namespace::new(
            NamespaceName::new("test").expect("valid name"),
            PolicyModes::default(),
            Ownership::new(
                OwnershipMode::Passthrough,
                ServerIdentity::new(1000, 100),
                SquashIds::default(),
            )
            .expect("valid ownership"),
            table,
            crate::rules::XattrRules::default(),
            true,
            grafts,
        )
    }

    fn path(raw: &str) -> NamespacePath {
        NamespacePath::parse(raw).expect("valid path")
    }

    fn described(set: &ShareSet) -> Vec<(String, EffectiveMode, ShareKind)> {
        set.iter()
            .map(|(path, entry)| (path.clone(), entry.mode, entry.kind))
            .collect()
    }

    #[test]
    fn literal_rules_are_entries_and_wildcards_and_hidden_are_not() {
        let scratch = Scratch::new("share-set");
        let root = scratch.directory("tree");
        let _ = scratch.directory("tree/docs");
        let file = scratch.file("tree/read.txt", b"x").display().to_string();
        let namespace = namespace(vec![
            RuleSpec::new("/project", ShareMode::Rw).with_target(root.as_str()),
            RuleSpec::new("/project/*", ShareMode::Hidden),
            RuleSpec::new("/project/read", ShareMode::Ro).with_target(file.as_str()),
            RuleSpec::new("/project/docs", ShareMode::Ro),
            RuleSpec::new("/project/secret", ShareMode::Hidden),
        ]);

        assert_eq!(
            described(&share_set(&namespace, &NamespacePath::root())),
            vec![
                (
                    "/project".to_owned(),
                    EffectiveMode::Rw,
                    ShareKind::Directory
                ),
                (
                    "/project/docs".to_owned(),
                    EffectiveMode::Ro,
                    ShareKind::Unknown
                ),
                (
                    "/project/read".to_owned(),
                    EffectiveMode::Ro,
                    ShareKind::File
                ),
            ]
        );
    }

    #[test]
    fn a_session_inside_a_share_sees_the_innermost_enclosing_rule_as_the_root() {
        let scratch = Scratch::new("share-scope");
        let root = scratch.directory("tree");
        let _ = scratch.directory("tree/inner");
        let _ = scratch.directory("tree/inner/deep");
        let namespace = namespace(vec![
            RuleSpec::new("/project", ShareMode::Rw).with_target(root.as_str()),
            RuleSpec::new("/project/inner", ShareMode::Ro),
            RuleSpec::new("/project/inner/deep", ShareMode::Rw),
            RuleSpec::new("/elsewhere", ShareMode::Rw).with_target(root.as_str()),
        ]);

        assert_eq!(
            described(&share_set(&namespace, &path("/project/inner"))),
            vec![
                ("/".to_owned(), EffectiveMode::Ro, ShareKind::Directory),
                ("/deep".to_owned(), EffectiveMode::Rw, ShareKind::Unknown),
            ]
        );

        assert_eq!(
            described(&share_set(&namespace, &path("/project/inner/deep"))),
            vec![("/".to_owned(), EffectiveMode::Rw, ShareKind::Directory)]
        );
    }

    #[test]
    fn a_wildcard_over_the_mount_roots_component_decides_the_root_entry() {
        let scratch = Scratch::new("share-wildcard-root");
        let root = scratch.directory("tree");
        let _ = scratch.directory("tree/sub");
        let _ = scratch.directory("tree/sub/deeper");
        let namespace = namespace(vec![
            RuleSpec::new("/tree", ShareMode::Rw).with_target(root.as_str()),
            // No literal rule names `/tree/sub`, yet the data plane resolves it
            // with this.
            RuleSpec::new("/tree/*", ShareMode::Ro),
        ]);

        assert_eq!(
            described(&share_set(&namespace, &path("/tree/sub"))),
            vec![("/".to_owned(), EffectiveMode::Ro, ShareKind::Directory)]
        );
        assert_eq!(
            described(&share_set(&namespace, &path("/tree/sub/deeper"))),
            vec![("/".to_owned(), EffectiveMode::Ro, ShareKind::Directory)]
        );
        assert_eq!(
            described(&share_set(&namespace, &path("/tree"))),
            vec![("/".to_owned(), EffectiveMode::Rw, ShareKind::Directory)]
        );
    }

    #[test]
    fn a_hidden_mount_root_has_no_root_entry() {
        let scratch = Scratch::new("share-hidden-root");
        let root = scratch.directory("tree");
        let _ = scratch.directory("tree/sub");
        let namespace = namespace(vec![
            RuleSpec::new("/tree", ShareMode::Rw).with_target(root.as_str()),
            RuleSpec::new("/tree/sub", ShareMode::Hidden),
        ]);
        assert!(share_set(&namespace, &path("/tree/sub")).is_empty());
    }

    #[test]
    fn a_namespace_root_mount_has_no_root_entry_of_its_own() {
        let scratch = Scratch::new("share-root");
        let root = scratch.directory("tree");
        let namespace = namespace(vec![
            RuleSpec::new("/a/b", ShareMode::Rw).with_target(root.as_str()),
        ]);
        assert_eq!(
            described(&share_set(&namespace, &NamespacePath::root())),
            vec![("/a/b".to_owned(), EffectiveMode::Rw, ShareKind::Directory)]
        );
        assert_eq!(
            described(&share_set(&namespace, &path("/a"))),
            vec![("/b".to_owned(), EffectiveMode::Rw, ShareKind::Directory)]
        );
    }
}
