//! A pattern or a wildcard is the per-directory default for entries without a
//! literal rule, so it beats subtree inheritance. A deeper literal rule
//! overrides the subtree it sits in. `hidden` terminates the walk, because a
//! nonexistent directory has no context to resolve children against.
//!
//! Evaluation is live: nothing is precomputed per host entry, so a host
//! directory created after a rule was written is covered at its next lookup.

use std::collections::BTreeSet;

use super::mode::EffectiveMode;
use super::name::Name;
use super::path::NamespacePath;
use super::table::{HostBacking, RuleTable};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DirState {
    Synthesized,
    HostBacked {
        backing: HostBacking,
        mode: EffectiveMode,
    },
}

/// One host directory grafted at two namespace paths is two distinct
/// directories, because their children may differ by policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirContext {
    path: NamespacePath,
    state: DirState,
}

impl DirContext {
    #[must_use]
    pub fn root() -> Self {
        Self {
            path: NamespacePath::root(),
            state: DirState::Synthesized,
        }
    }

    #[must_use]
    pub fn new(path: NamespacePath, state: DirState) -> Self {
        Self { path, state }
    }

    #[must_use]
    pub fn path(&self) -> &NamespacePath {
        &self.path
    }

    #[must_use]
    pub fn state(&self) -> &DirState {
        &self.state
    }

    #[must_use]
    pub fn backing(&self) -> Option<&HostBacking> {
        match &self.state {
            DirState::Synthesized => None,
            DirState::HostBacked { backing, .. } => Some(backing),
        }
    }

    #[must_use]
    pub fn mode(&self) -> Option<EffectiveMode> {
        match &self.state {
            DirState::Synthesized => None,
            DirState::HostBacked { mode, .. } => Some(*mode),
        }
    }

    /// Returns `None` when the entry does not exist, which is also how a hidden
    /// entry terminates a walk.
    #[must_use]
    pub fn child(&self, name: &Name, resolution: &Resolution) -> Option<Self> {
        Some(Self {
            path: self.path.child(name),
            state: resolution.dir_state()?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Resolution {
    HostBacked {
        backing: HostBacking,
        mode: EffectiveMode,
    },
    SynthesizedDir,
    /// `hidden` is indistinguishable from absence: no resolve, no stat, no
    /// listing.
    Nonexistent,
}

impl Resolution {
    #[must_use]
    pub fn is_admitted(&self) -> bool {
        !matches!(self, Self::Nonexistent)
    }

    #[must_use]
    pub fn mode(&self) -> Option<EffectiveMode> {
        match self {
            Self::HostBacked { mode, .. } => Some(*mode),
            Self::SynthesizedDir | Self::Nonexistent => None,
        }
    }

    #[must_use]
    pub fn backing(&self) -> Option<&HostBacking> {
        match self {
            Self::HostBacked { backing, .. } => Some(backing),
            Self::SynthesizedDir | Self::Nonexistent => None,
        }
    }

    #[must_use]
    pub fn dir_state(&self) -> Option<DirState> {
        match self {
            Self::HostBacked { backing, mode } => Some(DirState::HostBacked {
                backing: backing.clone(),
                mode: *mode,
            }),
            Self::SynthesizedDir => Some(DirState::Synthesized),
            Self::Nonexistent => None,
        }
    }
}

/// `V` is whatever the filter of the caller attached when it kept the entry.
/// The engine never looks at it, so host-side facts travel out of an
/// enumeration without the engine performing I/O.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirEntry<V = ()> {
    pub name: Name,
    pub resolution: Resolution,
    pub kept: V,
}

impl RuleTable {
    /// The name must be a single component, which [`Name`] enforces.
    #[must_use]
    pub fn resolve(&self, directory: &DirContext, name: &Name) -> Resolution {
        if let Some(rule) = self.literal_child(directory.path(), name) {
            return match (rule.mode.effective(), &rule.backing) {
                (Some(mode), Some(backing)) => Resolution::HostBacked {
                    backing: backing.clone(),
                    mode,
                },
                // Hidden is the only mode a validated table leaves without a backing.
                _ => Resolution::Nonexistent,
            };
        }

        if let Some(pattern) = self.pattern(directory.path(), name) {
            match (pattern.effective(), directory.backing()) {
                (None, _) => return Resolution::Nonexistent,
                (Some(mode), Some(backing)) => {
                    return Resolution::HostBacked {
                        backing: backing.child(name),
                        mode,
                    };
                }
                // A pattern on a directory with no backing has nothing to match against. The
                // table build rejects that configuration.
                (Some(_), None) => {}
            }
        }

        if let Some(wildcard) = self.wildcard(directory.path()) {
            match (wildcard.effective(), directory.backing()) {
                (None, _) => return Resolution::Nonexistent,
                (Some(mode), Some(backing)) => {
                    return Resolution::HostBacked {
                        backing: backing.child(name),
                        mode,
                    };
                }
                // A wildcard on a directory with no backing has nothing to enumerate. The
                // table build rejects it.
                (Some(_), None) => {}
            }
        }

        if let DirState::HostBacked { backing, mode } = directory.state() {
            return Resolution::HostBacked {
                backing: backing.child(name),
                mode: *mode,
            };
        }

        if self.is_intermediate_child(directory.path(), name) {
            return Resolution::SynthesizedDir;
        }

        Resolution::Nonexistent
    }

    /// A synthesized directory ignores `host_names` and lists its visible
    /// structural children. A host-backed directory returns the union of the host
    /// names, each resolved, and the literal-rule child names
    /// absent from that listing, so re-targeted grafts agree between lookup and
    /// readdir.
    ///
    /// Nothing sorts: host entries keep the order of `host_names`, followed by the
    /// children that exist only because a rule names them, in key order of the
    /// table.
    ///
    /// `keep` is the filter of the caller, asked about every entry the rules admit,
    /// because the engine performs no I/O. `None` drops the entry like a hidden
    /// one, and what it returns rides along on the entry.
    ///
    /// `host_names` is consumed lazily, and only kept entries are held.
    pub fn enumerate<V>(
        &self,
        directory: &DirContext,
        host_names: impl IntoIterator<Item = Name>,
        keep: impl FnMut(&Name, &Resolution) -> Option<V>,
    ) -> Vec<DirEntry<V>> {
        let mut listing = Listing {
            entries: Vec::new(),
            kept: BTreeSet::new(),
            keep,
        };
        match directory.state() {
            DirState::Synthesized => {
                for name in self.structural_children(directory.path()) {
                    listing.offer(self, directory, name);
                }
            }
            DirState::HostBacked { .. } => {
                for name in host_names {
                    listing.offer(self, directory, name);
                }
                // A literal rule pointing somewhere else has no host child among those names
                // and must still be listed.
                for name in self.literal_child_names(directory.path()) {
                    if !listing.holds(name) {
                        listing.offer(self, directory, name.clone());
                    }
                }
            }
        }
        listing.finish()
    }

    #[must_use]
    pub fn walk(&self, path: &NamespacePath) -> Option<DirContext> {
        let mut directory = DirContext::root();
        for name in path.components() {
            let resolution = self.resolve(&directory, name);
            directory = directory.child(name, &resolution)?;
        }
        Some(directory)
    }

    /// Combines [`walk`](Self::walk) and [`resolve`](Self::resolve) over a whole
    /// path: the root is the synthesized directory every walk starts from.
    #[must_use]
    pub fn resolve_path(&self, path: &NamespacePath) -> Resolution {
        let (Some(parent), Some(name)) = (path.parent(), path.last()) else {
            return Resolution::SynthesizedDir;
        };
        self.walk(&parent)
            .map_or(Resolution::Nonexistent, |directory| {
                self.resolve(&directory, name)
            })
    }
}

struct Listing<V, K> {
    entries: Vec<DirEntry<V>>,
    kept: BTreeSet<Name>,
    keep: K,
}

impl<V, K: FnMut(&Name, &Resolution) -> Option<V>> Listing<V, K> {
    fn offer(&mut self, table: &RuleTable, directory: &DirContext, name: Name) {
        let resolution = table.resolve(directory, &name);
        if !resolution.is_admitted() {
            return;
        }
        let Some(kept) = (self.keep)(&name, &resolution) else {
            return;
        };
        self.kept.insert(name.clone());
        self.entries.push(DirEntry {
            name,
            resolution,
            kept,
        });
    }

    fn holds(&self, name: &Name) -> bool {
        self.kept.contains(name)
    }

    fn finish(self) -> Vec<DirEntry<V>> {
        self.entries
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::mode::ShareMode;
    use crate::rules::table::RuleSpec;
    use crate::rules::test_support::{
        describe, describe_backing, dir, enumerate, listing, name, path, table,
    };

    fn resolve(table: &RuleTable, directory: &str, entry: &str) -> String {
        describe(&table.resolve(&dir(table, directory), &name(entry)))
    }

    fn project_table() -> RuleTable {
        table([
            RuleSpec::new("/project", ShareMode::Rw).with_target("/srv/project"),
            RuleSpec::new("/project/*", ShareMode::Hidden),
            RuleSpec::new("/project/notes.txt", ShareMode::Ro),
        ])
    }

    #[test]
    fn step_1_a_literal_rule_wins() {
        let table = table([
            RuleSpec::new("/a", ShareMode::Rw).with_target("/srv/a"),
            RuleSpec::new("/a/ro", ShareMode::Ro),
            RuleSpec::new("/a/secret", ShareMode::Hidden),
        ]);
        assert_eq!(
            resolve(&table, "/", "a"),
            "Rw graft=\"/srv/a\" relative=\"\""
        );
        assert_eq!(
            resolve(&table, "/a", "ro"),
            "Ro graft=\"/srv/a\" relative=\"ro\""
        );
        assert_eq!(resolve(&table, "/a", "secret"), "Nonexistent");
    }

    /// The parent is grafted `rw`, its children are hidden by a bare `*`, and one
    /// family is un-hidden by a pattern. The second directory has no wildcard, the
    /// only place where the enclosing default is observable.
    fn family_table() -> RuleTable {
        table([
            RuleSpec::new("/a", ShareMode::Rw).with_target("/srv/a"),
            RuleSpec::new("/a/*", ShareMode::Hidden),
            RuleSpec::new("/a", ShareMode::Ro).with_match("project-*"),
            RuleSpec::new("/a/project-pinned", ShareMode::Rw),
            RuleSpec::new("/plain", ShareMode::Rw).with_target("/srv/plain"),
            RuleSpec::new("/plain", ShareMode::Ro).with_match("keep-*"),
        ])
    }

    #[test]
    fn step_2_a_pattern_governs_the_names_it_covers() {
        let table = family_table();
        assert_eq!(
            resolve(&table, "/a", "project-one"),
            "Ro graft=\"/srv/a\" relative=\"project-one\""
        );
        assert_eq!(
            resolve(&table, "/a", "project-"),
            "Ro graft=\"/srv/a\" relative=\"project-\""
        );
        assert_eq!(resolve(&table, "/a", "project"), "Nonexistent");
    }

    #[test]
    fn the_specificity_chain_runs_literal_then_pattern_then_wildcard() {
        let table = family_table();
        assert_eq!(
            resolve(&table, "/a", "project-pinned"),
            "Rw graft=\"/srv/a\" relative=\"project-pinned\"",
            "a literal rule beats the pattern covering the same name"
        );
        assert_eq!(
            resolve(&table, "/a", "project-two"),
            "Ro graft=\"/srv/a\" relative=\"project-two\"",
            "a pattern beats the bare `*`"
        );
        assert_eq!(
            resolve(&table, "/a", "unrelated"),
            "Nonexistent",
            "and the bare `*` decides what nothing else claims"
        );

        assert_eq!(
            resolve(&table, "/plain", "keep-one"),
            "Ro graft=\"/srv/plain\" relative=\"keep-one\"",
            "a pattern beats the enclosing default"
        );
        assert_eq!(
            resolve(&table, "/plain", "misc"),
            "Rw graft=\"/srv/plain\" relative=\"misc\"",
            "and the enclosing default is what decides the rest"
        );
    }

    #[test]
    fn a_hidden_pattern_makes_its_matches_nonexistent() {
        let table = table([
            RuleSpec::new("/a", ShareMode::Rw).with_target("/srv/a"),
            RuleSpec::new("/a", ShareMode::Hidden).with_match(".*"),
        ]);
        assert_eq!(resolve(&table, "/a", ".git"), "Nonexistent");
        assert_eq!(table.walk(&path("/a/.git")), None);
        assert_eq!(table.walk(&path("/a/.git/config")), None);
        assert_eq!(
            listing(&enumerate(
                &table,
                &dir(&table, "/a"),
                [name(".git"), name("src")]
            )),
            [r#"src Rw graft="/srv/a" relative="src""#.to_owned()]
        );
    }

    #[test]
    fn the_leading_dot_rule_holds_at_resolution() {
        let table = table([
            RuleSpec::new("/a", ShareMode::Rw).with_target("/srv/a"),
            RuleSpec::new("/a/*", ShareMode::Hidden),
            RuleSpec::new("/a", ShareMode::Ro).with_match("*-a"),
            RuleSpec::new("/a", ShareMode::Rw).with_match(".b-*"),
        ]);
        assert_eq!(
            resolve(&table, "/a", ".b-a"),
            "Rw graft=\"/srv/a\" relative=\".b-a\""
        );
        assert_eq!(resolve(&table, "/a", ".x-a"), "Nonexistent");
        assert_eq!(
            resolve(&table, "/a", "x-a"),
            "Ro graft=\"/srv/a\" relative=\"x-a\""
        );
    }

    #[test]
    fn descent_into_a_pattern_admitted_directory_inherits_the_pattern_mode() {
        let table = family_table();
        let child = dir(&table, "/a/project-one");
        assert_eq!(child.mode(), Some(EffectiveMode::Ro));
        assert_eq!(
            child.backing().map(describe_backing).as_deref(),
            Some("graft=\"/srv/a\" relative=\"project-one\"")
        );
        assert_eq!(
            resolve(&table, "/a/project-one", "deeper"),
            "Ro graft=\"/srv/a\" relative=\"project-one/deeper\""
        );
    }

    #[test]
    fn step_3_a_wildcard_governs_the_host_children() {
        let table = table([
            RuleSpec::new("/a", ShareMode::Rw).with_target("/srv/a"),
            RuleSpec::new("/a/*", ShareMode::Ro),
        ]);
        assert_eq!(
            resolve(&table, "/a", "anything"),
            "Ro graft=\"/srv/a\" relative=\"anything\""
        );
    }

    #[test]
    fn step_4_a_graft_is_a_subtree() {
        let table = table([RuleSpec::new("/a", ShareMode::Ro).with_target("/srv/a")]);
        assert_eq!(
            resolve(&table, "/a", "child"),
            "Ro graft=\"/srv/a\" relative=\"child\""
        );
        assert_eq!(
            resolve(&table, "/a/child", "grandchild"),
            "Ro graft=\"/srv/a\" relative=\"child/grandchild\""
        );
    }

    #[test]
    fn step_5_intermediate_components_are_synthesized_directories() {
        let table =
            table([RuleSpec::new("/deep/inside/graft", ShareMode::Rw).with_target("/srv/graft")]);
        assert_eq!(resolve(&table, "/", "deep"), "SynthesizedDir");
        assert_eq!(resolve(&table, "/deep", "inside"), "SynthesizedDir");
        assert_eq!(
            resolve(&table, "/deep/inside", "graft"),
            "Rw graft=\"/srv/graft\" relative=\"\""
        );
        assert!(!dir(&table, "/deep").backing().is_some());
        assert_eq!(dir(&table, "/deep").mode(), None);
    }

    #[test]
    fn step_6_a_namespace_is_empty_by_default() {
        let empty = table([]);
        assert_eq!(resolve(&empty, "/", "anything"), "Nonexistent");

        let table = table([RuleSpec::new("/a", ShareMode::Rw).with_target("/srv/a")]);
        assert_eq!(resolve(&table, "/", "b"), "Nonexistent");
    }

    #[test]
    fn a_wildcard_beats_subtree_inheritance() {
        let table = table([
            RuleSpec::new("/a", ShareMode::Rw).with_target("/srv/a"),
            RuleSpec::new("/a/*", ShareMode::Hidden),
        ]);
        assert_eq!(resolve(&table, "/a", "child"), "Nonexistent");
    }

    #[test]
    fn a_literal_rule_beats_a_wildcard() {
        let table = project_table();
        assert_eq!(
            resolve(&table, "/project", "notes.txt"),
            "Ro graft=\"/srv/project\" relative=\"notes.txt\""
        );
        assert_eq!(resolve(&table, "/project", "other"), "Nonexistent");
    }

    #[test]
    fn a_deeper_literal_rule_upgrades_the_subtree_it_sits_in() {
        let table = table([
            RuleSpec::new("/a", ShareMode::Ro).with_target("/srv/a"),
            RuleSpec::new("/a/writable", ShareMode::Rw),
        ]);
        assert_eq!(
            resolve(&table, "/a", "writable"),
            "Rw graft=\"/srv/a\" relative=\"writable\""
        );
        assert_eq!(
            resolve(&table, "/a", "other"),
            "Ro graft=\"/srv/a\" relative=\"other\""
        );
        assert_eq!(
            resolve(&table, "/a/writable", "inner"),
            "Rw graft=\"/srv/a\" relative=\"writable/inner\""
        );
    }

    #[test]
    fn a_deeper_literal_rule_hides_inside_the_subtree_it_sits_in() {
        let table = table([
            RuleSpec::new("/a", ShareMode::Rw).with_target("/srv/a"),
            RuleSpec::new("/a/secret", ShareMode::Hidden),
        ]);
        assert_eq!(resolve(&table, "/a", "secret"), "Nonexistent");
        assert_eq!(
            resolve(&table, "/a", "public"),
            "Rw graft=\"/srv/a\" relative=\"public\""
        );
    }

    #[test]
    fn hidden_terminates_the_walk() {
        let table = table([
            RuleSpec::new("/a", ShareMode::Rw).with_target("/srv/a"),
            RuleSpec::new("/a/secret", ShareMode::Hidden),
        ]);
        let a = dir(&table, "/a");
        let resolution = table.resolve(&a, &name("secret"));
        assert_eq!(a.child(&name("secret"), &resolution), None);
        assert_eq!(table.walk(&path("/a/secret")), None);
        assert_eq!(table.walk(&path("/a/secret/key")), None);
    }

    #[test]
    fn descent_into_a_wildcard_admitted_directory_inherits_the_wildcard_mode() {
        let table = table([
            RuleSpec::new("/a", ShareMode::Rw).with_target("/srv/a"),
            RuleSpec::new("/a/*", ShareMode::Ro),
        ]);
        let child = dir(&table, "/a/sub");
        assert_eq!(child.mode(), Some(EffectiveMode::Ro));
        assert_eq!(
            child.backing().map(describe_backing).as_deref(),
            Some("graft=\"/srv/a\" relative=\"sub\"")
        );
        assert_eq!(
            resolve(&table, "/a/sub", "deeper"),
            "Ro graft=\"/srv/a\" relative=\"sub/deeper\""
        );
    }

    #[test]
    fn walking_starts_at_a_synthesized_root() {
        let table = table([]);
        let root = table
            .walk(&NamespacePath::root())
            .expect("the root always exists");
        assert_eq!(root, DirContext::root());
        assert_eq!(root.path(), &NamespacePath::root());
        assert_eq!(root.state(), &DirState::Synthesized);
        assert_eq!(root.backing(), None);
        assert!(!root.backing().is_some());
    }

    #[test]
    fn walking_carries_the_namespace_path() {
        let table = table([RuleSpec::new("/a", ShareMode::Rw).with_target("/srv/a")]);
        let directory = dir(&table, "/a/b/c");
        assert_eq!(directory.path(), &path("/a/b/c"));
        assert_eq!(
            directory.state(),
            &DirState::HostBacked {
                backing: HostBacking::graft_root("/srv/a".into()).extend(&[name("b"), name("c")]),
                mode: EffectiveMode::Rw,
            }
        );
    }

    #[test]
    fn enumerating_a_synthesized_directory_lists_exactly_its_visible_children() {
        let table = table([
            RuleSpec::new("/deep/graft", ShareMode::Rw).with_target("/srv/graft"),
            RuleSpec::new("/other", ShareMode::Ro).with_target("/srv/other"),
            RuleSpec::new("/nope", ShareMode::Hidden),
        ]);
        let root = DirContext::root();
        assert_eq!(
            listing(&enumerate(&table, &root, [])),
            [
                "deep SynthesizedDir".to_owned(),
                r#"other Ro graft="/srv/other" relative="""#.to_owned(),
            ]
        );
        assert_eq!(
            listing(&enumerate(&table, &dir(&table, "/deep"), [])),
            [r#"graft Rw graft="/srv/graft" relative="""#.to_owned()]
        );
    }

    #[test]
    fn enumerating_a_host_backed_directory_decides_per_entry() {
        let table = project_table();
        let project = dir(&table, "/project");
        let names = [name("notes.txt"), name("secret"), name("build")];
        assert_eq!(
            listing(&enumerate(&table, &project, names)),
            [r#"notes.txt Ro graft="/srv/project" relative="notes.txt""#.to_owned()]
        );
    }

    #[test]
    fn host_backed_enumeration_includes_a_retargeted_literal_absent_from_host() {
        let table = table([
            RuleSpec::new("/project", ShareMode::Rw).with_target("/srv/project"),
            RuleSpec::new("/project/*", ShareMode::Hidden),
            RuleSpec::new("/project/external", ShareMode::Ro).with_target("/srv/external"),
        ]);
        let project = dir(&table, "/project");

        assert_eq!(
            listing(&enumerate(&table, &project, [name("unlisted-host-child")])),
            [r#"external Ro graft="/srv/external" relative="""#.to_owned()]
        );
    }

    #[test]
    fn entries_the_rules_or_the_caller_drop_are_not_listed() {
        let table = project_table();
        let directory = dir(&table, "/project");
        let mut names: Vec<Name> = (0..1000)
            .map(|index| name(&format!("entry-{index:04}")))
            .collect();
        names.push(name("notes.txt"));

        let listed = table.enumerate(&directory, names.clone(), |_, _| Some(()));
        assert_eq!(
            listing(&listed),
            [r#"notes.txt Ro graft="/srv/project" relative="notes.txt""#.to_owned()]
        );

        let empty = table.enumerate(&directory, names, |name, _| {
            (name != &self::name("notes.txt")).then_some(())
        });
        assert!(empty.is_empty());
    }

    #[test]
    fn a_listing_keeps_the_host_order_and_appends_rule_only_children() {
        let table = table([
            RuleSpec::new("/a", ShareMode::Rw).with_target("/srv/a"),
            RuleSpec::new("/a/ro", ShareMode::Ro),
            // These exist only because a rule does, and follow in the key order of the
            // table.
            RuleSpec::new("/a/zeta", ShareMode::Ro).with_target("/srv/zeta"),
            RuleSpec::new("/a/beta", ShareMode::Ro).with_target("/srv/beta"),
        ]);
        let directory = dir(&table, "/a");
        let names = |listed: &[DirEntry]| -> Vec<String> {
            listed.iter().map(|entry| entry.name.to_string()).collect()
        };
        for host in [["alpha", "ro", "zulu"], ["zulu", "ro", "alpha"]] {
            let listed = enumerate(&table, &directory, host.map(name));
            let mut expected = host.map(str::to_owned).to_vec();
            expected.extend(["beta".to_owned(), "zeta".to_owned()]);
            assert_eq!(names(&listed), expected);
        }
        let listed = enumerate(&table, &directory, ["zeta", "alpha"].map(name));
        assert_eq!(names(&listed), ["zeta", "alpha", "beta", "ro"]);
    }

    #[test]
    fn a_synthesized_directory_lists_in_the_tables_order() {
        let table = table([
            RuleSpec::new("/zulu", ShareMode::Rw).with_target("/srv/zulu"),
            RuleSpec::new("/mid/inner", ShareMode::Rw).with_target("/srv/inner"),
            RuleSpec::new("/alpha", ShareMode::Rw).with_target("/srv/alpha"),
        ]);
        let listed = enumerate(&table, &dir(&table, "/"), [name("ignored")]);
        let expected: Vec<Name> = table
            .structural_children(&crate::rules::path::NamespacePath::root())
            .into_iter()
            .collect();
        assert_eq!(
            listed
                .into_iter()
                .map(|entry| entry.name)
                .collect::<Vec<_>>(),
            expected
        );
    }

    #[test]
    fn resolutions_report_what_they_admitted() {
        let table = project_table();
        let project = dir(&table, "/project");
        let notes = table.resolve(&project, &name("notes.txt"));
        assert!(notes.is_admitted());
        assert_eq!(notes.mode(), Some(EffectiveMode::Ro));
        assert_eq!(
            notes.backing().map(describe_backing).as_deref(),
            Some("graft=\"/srv/project\" relative=\"notes.txt\"")
        );

        let synthesized = Resolution::SynthesizedDir;
        assert!(synthesized.is_admitted());
        assert_eq!(synthesized.mode(), None);
        assert_eq!(synthesized.backing(), None);
        assert_eq!(synthesized.dir_state(), Some(DirState::Synthesized));

        let hidden = table.resolve(&project, &name("secret"));
        assert!(!hidden.is_admitted());
        assert_eq!(hidden.mode(), None);
        assert_eq!(hidden.backing(), None);
        assert_eq!(hidden.dir_state(), None);
    }

    #[test]
    fn a_context_can_be_built_without_walking_to_it() {
        let built = DirContext::new(
            path("/a"),
            DirState::HostBacked {
                backing: HostBacking::graft_root("/srv/a".into()),
                mode: EffectiveMode::Rw,
            },
        );
        let table = table([RuleSpec::new("/a", ShareMode::Rw).with_target("/srv/a")]);
        assert_eq!(built, dir(&table, "/a"));
    }
}
