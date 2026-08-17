//! What a session's share subscription reports: the entry set, and nothing
//! else.
//!
//! The subscription stream carries a namespace's **literal, non-hidden rules
//! that the session's scope and visibility admit** — one entry per rule,
//! carrying the namespace path relative to the session's mount root, the mode,
//! and the target kind. That sentence is implemented here, once, so the
//! snapshot and every delta are computed by the same function and cannot drift:
//! a delta is the difference between two runs of [`share_set`].
//!
//! Three properties are load-bearing, and each one is a rule of the design:
//!
//! * **It is a pure function** of the published namespace and the session's
//!   subpath. No host syscall runs here, which is what lets it run under the
//!   publish lock without the mutation path ever waiting on a disk. The
//!   consequence is stated plainly in the contract: the stream tracks
//!   control-plane changes only, and a host-side `chown` or `mkdir` produces no
//!   event.
//! * **Wildcards are not shares.** A wildcard is a per-directory default, and
//!   the engine cannot name its children without a host `readdir` — so the
//!   enclosing entry covers the subtree and the wildcard is never enumerated.
//! * **Hidden never leaks.** A hidden rule is dropped before anything else
//!   happens to it, so it can appear neither as an entry nor, since every event
//!   is a difference of two entry sets, as an event.
//!
//! A session mounted *inside* a share reports the **innermost** enclosing share
//! as the entry `/` — its own mount root, with that mount root's effective
//! mode. Only the innermost reading makes the contract's sentence true under
//! nesting: an outer ancestor re-moded while an inner rule overrides it changes
//! nothing the session can observe, and computing the diff on this
//! session-scoped set is what keeps that event silent. That entry is derived
//! from the **resolution of the mount root itself**, not from the innermost
//! enclosing literal rule — see [`root_entry`], where the difference between
//! the two is a wildcard.

use std::collections::BTreeMap;

use crate::host::FileKind;
use crate::namespace::Namespace;
use crate::rules::{EffectiveMode, HostBacking, NamespacePath};

/// What kind of thing a subscription entry's target is.
///
/// A kind is reported **only where the build already knows it without fresh
/// host I/O**: a stated target's kind is recorded when the graft pins it, and a
/// targetless mode-override island — whose derived path is never pinned and
/// never checked — is [`ShareKind::Unknown`]. Consumers treat `Unknown` as
/// try-and-see; the mount attempt is what meets reality.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShareKind {
    /// The build does not know, and will not perform I/O to find out.
    Unknown,
    /// A directory.
    Directory,
    /// A regular file.
    File,
}

impl ShareKind {
    /// The kind of a pinned host entry, as the subscription spells it.
    ///
    /// A symlink or a device is reported as `Unknown`, not invented into
    /// one of the two named kinds: the vocabulary the contract fixes is
    /// directory, file and unknown, and "unknown" is the honest answer for
    /// everything else.
    #[must_use]
    fn of(kind: FileKind) -> Self {
        match kind {
            FileKind::Directory => Self::Directory,
            FileKind::Regular => Self::File,
            FileKind::Symlink | FileKind::Other => Self::Unknown,
        }
    }
}

/// One entry of a session's share set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShareEntry {
    /// The mode the session sees the entry with.
    pub mode: EffectiveMode,
    /// What kind of thing the entry's target is, where the build knows.
    pub kind: ShareKind,
}

/// A session's share set: entry path relative to its mount root, in path order.
///
/// Ordered, not hashed, because the order is part of the product: a
/// snapshot arrives in it, and a diff walked over two ordered maps is a merge
/// and not a double lookup.
pub type ShareSet = BTreeMap<String, ShareEntry>;

/// The entries a session mounted at `subpath` of `namespace` can see.
///
/// See the module documentation for the rules this implements; every branch
/// below is one of them.
#[must_use]
pub fn share_set(namespace: &Namespace, subpath: &NamespacePath) -> ShareSet {
    let mut entries = ShareSet::new();

    for (path, rule) in namespace.rules().literal_rules() {
        // Hidden is dropped first and unconditionally: nothing below may see
        // it, so nothing below may be reached with it.
        let Some(mode) = rule.mode.effective() else {
            continue;
        };
        if path.depth() <= subpath.depth() {
            // At or above the mount root, so not an entry of its own: what the
            // session sees of its own root is the `/` entry, and a rule above
            // the mount root is outside the session's scope entirely.
            continue;
        }
        if path.prefix(subpath.depth()) != *subpath {
            // Strictly outside the session's subtree: omitted, because a
            // session may not learn about rules its scope excludes.
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

/// The `/` entry: the session's own mount root, or `None` when nothing encloses
/// it.
///
/// It is computed by **resolving the mount root exactly as the data plane
/// resolves it**, not by looking for the innermost enclosing literal
/// rule, because those two answers differ. Resolution gives a wildcard the last
/// word over the subtree it sits in (step 3 before step 4), so a `/tree/*` rule
/// decides the effective mode of a session mounted at `/tree/sub` even though
/// no literal rule names that path — and the contract says the `/` entry
/// carries the mount root's *effective* mode. Enumerating literal rules alone
/// would report the enclosing graft's mode and stay silent when the wildcard
/// changed it, which is a share reported as writable that the server enforces
/// read-only.
///
/// `None` covers both cases with no enclosing share: a mount on the namespace
/// root, and a mount on a synthesized directory, neither of which any rule
/// backs. A mount root that resolves to nothing at all — hidden, or gone since
/// the handshake — has no entry either; the session serves what it pinned, but
/// there is no share left to report.
///
/// The kind is [`ShareKind::Directory`] and needs no host I/O to say so: a
/// host-backed mount root was stat'ed at handshake time and a session over
/// anything but a directory was refused with `ENOTDIR`, so the build already
/// knows the answer for every session that exists to be told it.
fn root_entry(namespace: &Namespace, subpath: &NamespacePath) -> Option<ShareEntry> {
    let mode = namespace.rules().walk(subpath)?.mode()?;
    Some(ShareEntry {
        mode,
        kind: ShareKind::Directory,
    })
}

/// The kind a rule's target has, where the build knows it without host I/O.
///
/// A rule that **states** a target is a graft root, and a graft's kind was
/// recorded when it was pinned. A rule that derives its backing from an
/// enclosing graft names a path nothing ever opened — a mode-override island —
/// and the contract says its kind is unknown instead of having the publish path
/// go and look.
fn kind_of(namespace: &Namespace, backing: Option<&HostBacking>) -> ShareKind {
    let Some(backing) = backing.filter(|backing| backing.is_graft_root()) else {
        return ShareKind::Unknown;
    };
    namespace
        .grafts()
        .kind(backing.graft())
        .map_or(ShareKind::Unknown, ShareKind::of)
}

/// A rule path expressed relative to a mount root `depth` components deep.
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
    use crate::testing::Scratch;
    use voidport_control::NamespaceName;

    /// A namespace over a real host tree, so the pinned graft kinds are real.
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
            // A wildcard is a policy default, not a share.
            RuleSpec::new("/project/*", ShareMode::Hidden),
            // A stated target: its kind was recorded at pin time.
            RuleSpec::new("/project/read", ShareMode::Ro).with_target(file.as_str()),
            // A targetless island: the derived path is never pinned.
            RuleSpec::new("/project/docs", ShareMode::Ro),
            // Hidden never appears.
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
            // The inner rule overrides the outer one for anything below it.
            RuleSpec::new("/project/inner", ShareMode::Ro),
            RuleSpec::new("/project/inner/deep", ShareMode::Rw),
            RuleSpec::new("/elsewhere", ShareMode::Rw).with_target(root.as_str()),
        ]);

        // Mounted at the inner rule: it is `/`, with *its* mode, and the rule
        // beneath it is relative to the mount root. The outer rule and the
        // unrelated one are both absent. A mount root is a directory or the
        // handshake refused the mount, so `/` says so.
        assert_eq!(
            described(&share_set(&namespace, &path("/project/inner"))),
            vec![
                ("/".to_owned(), EffectiveMode::Ro, ShareKind::Directory),
                ("/deep".to_owned(), EffectiveMode::Rw, ShareKind::Unknown),
            ]
        );

        // Mounted *below* every rule but the outer graft: the innermost
        // enclosing rule is still the one that decides `/`.
        assert_eq!(
            described(&share_set(&namespace, &path("/project/inner/deep"))),
            vec![("/".to_owned(), EffectiveMode::Rw, ShareKind::Directory)]
        );
    }

    /// The mount root's mode is the one **resolution** gives it, and a wildcard
    /// governing the mount root's own component is exactly where that differs
    /// from the innermost enclosing literal rule.
    #[test]
    fn a_wildcard_over_the_mount_roots_component_decides_the_root_entry() {
        let scratch = Scratch::new("share-wildcard-root");
        let root = scratch.directory("tree");
        let _ = scratch.directory("tree/sub");
        let _ = scratch.directory("tree/sub/deeper");
        let namespace = namespace(vec![
            RuleSpec::new("/tree", ShareMode::Rw).with_target(root.as_str()),
            // A per-directory default over `/tree`'s children: no literal rule
            // names `/tree/sub`, and yet this is what the data plane resolves
            // it with.
            RuleSpec::new("/tree/*", ShareMode::Ro),
        ]);

        // Mounted on a wildcard-governed child: `/` carries the wildcard's
        // mode, not the enclosing graft's.
        assert_eq!(
            described(&share_set(&namespace, &path("/tree/sub"))),
            vec![("/".to_owned(), EffectiveMode::Ro, ShareKind::Directory)]
        );
        // And below it, where the wildcard-admitted mode is the subtree mode.
        assert_eq!(
            described(&share_set(&namespace, &path("/tree/sub/deeper"))),
            vec![("/".to_owned(), EffectiveMode::Ro, ShareKind::Directory)]
        );
        // The graft root itself is still the graft's own mode: the wildcard
        // governs its children, not itself.
        assert_eq!(
            described(&share_set(&namespace, &path("/tree"))),
            vec![("/".to_owned(), EffectiveMode::Rw, ShareKind::Directory)]
        );
    }

    /// A mount root nothing resolves — hidden, or hidden since the handshake —
    /// has no `/` entry: the session serves what it pinned, but there is no
    /// share left to report.
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
        // The namespace root is synthesized by definition and carries no rule,
        // so nothing encloses the mount and there is no `/` entry — only the
        // rule itself, at its own path.
        assert_eq!(
            described(&share_set(&namespace, &NamespacePath::root())),
            vec![("/a/b".to_owned(), EffectiveMode::Rw, ShareKind::Directory)]
        );
        // A mount on the synthesized intermediate directory sees the rule
        // beneath it and still has no root entry.
        assert_eq!(
            described(&share_set(&namespace, &path("/a"))),
            vec![("/b".to_owned(), EffectiveMode::Rw, ShareKind::Directory)]
        );
    }
}
