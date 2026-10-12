//! Component-wise resolution and enumeration.
//!
//! Resolution is component-wise, and policy context lives in the parent
//! directory. Every directory a walk reaches is either *host-backed* (at or
//! inside a graft, with a host directory behind it) or *synthesized* (it
//! exists only because reachable grafts lie beneath it); the namespace root
//! starts synthesized. That state, plus the directory's namespace path and
//! effective mode, is a [`DirContext`].
//!
//! Resolving name `N` under directory `D` runs the six steps of the design's
//! "Rule table and resolution", in order:
//!
//! 1. A **literal rule** at `D/N` wins: `rw`/`ro` admits `N` with that mode
//!    and its host target; `hidden` makes `N` nonexistent.
//! 2. Otherwise a **pattern rule** on `D` whose match covers `N` applies to
//!    the host child `N` of `D`'s backing: `rw`/`ro` admits it with that mode,
//!    `hidden` makes it nonexistent. At most one pattern can cover `N`,
//!    because overlapping patterns at one level are refused at the table
//!    boundary.
//! 3. Otherwise a **wildcard rule** `D/*` applies to the host child `N` of
//!    `D`'s backing: `rw`/`ro` admits it with that mode, `hidden` makes it
//!    nonexistent.
//! 4. Otherwise, if `D` is **host-backed** with effective mode `M`, the child
//!    exists per the host with inherited mode `M` — a graft is a subtree.
//! 5. Otherwise, if `N` is the next component of some reachable non-hidden
//!    literal rule beneath `D`, it is a **synthesized directory**.
//! 6. Otherwise `N` does not exist. Empty-by-default falls out here.
//!
//! The consequences are deliberate: patterns and wildcards are the
//! per-directory defaults for entries with no literal rule and therefore beat
//! subtree inheritance (steps 2 and 3 before step 4), with the more specific
//! pattern ahead of the catch-all `*`; a deeper literal rule overrides the
//! subtree it sits in, including upgrading and hiding (step 1 before step 4);
//! and `hidden` terminates the walk, because a nonexistent directory has no
//! context to resolve children against.
//!
//! Evaluation is **live**: nothing here is precomputed per host entry, so a
//! host directory created after a rule was written is covered at its next
//! lookup, TTL-bounded like every other answer.
//!
//! Because the table rejects duplicates and precedence is structural, every
//! decision here is a pure function of the table, `D` and `N` — deterministic
//! and independent of the order rules were configured in.

use std::collections::BTreeSet;

use super::mode::EffectiveMode;
use super::name::Name;
use super::path::NamespacePath;
use super::table::{HostBacking, RuleTable};

/// What a directory is backed by, and under what policy its children are
/// resolved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DirState {
    /// The directory exists only to make reachable grafts beneath it
    /// reachable. It has no host backing and no host children.
    Synthesized,
    /// The directory is at or inside a graft.
    HostBacked {
        /// Where the directory lives on the host.
        backing: HostBacking,
        /// The mode children inherit through subtree inheritance.
        mode: EffectiveMode,
    },
}

/// A directory the walk has reached: the parent context resolution needs.
///
/// A directory node carries its namespace path, not just its host identity:
/// one host directory grafted at two namespace paths is two distinct
/// directories, because their children may differ by policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirContext {
    path: NamespacePath,
    state: DirState,
}

impl DirContext {
    /// The namespace root: synthesized, at `/`.
    #[must_use]
    pub fn root() -> Self {
        Self {
            path: NamespacePath::root(),
            state: DirState::Synthesized,
        }
    }

    /// Builds a context from a namespace path and a directory state.
    #[must_use]
    pub fn new(path: NamespacePath, state: DirState) -> Self {
        Self { path, state }
    }

    /// The directory's namespace path.
    #[must_use]
    pub fn path(&self) -> &NamespacePath {
        &self.path
    }

    /// The directory's state.
    #[must_use]
    pub fn state(&self) -> &DirState {
        &self.state
    }

    /// The directory's host backing, or `None` if it is synthesized.
    #[must_use]
    pub fn backing(&self) -> Option<&HostBacking> {
        match &self.state {
            DirState::Synthesized => None,
            DirState::HostBacked { backing, .. } => Some(backing),
        }
    }

    /// The mode children inherit, or `None` if the directory is synthesized.
    #[must_use]
    pub fn mode(&self) -> Option<EffectiveMode> {
        match &self.state {
            DirState::Synthesized => None,
            DirState::HostBacked { mode, .. } => Some(*mode),
        }
    }

    /// Whether the directory has a host directory behind it.
    #[must_use]
    pub fn is_host_backed(&self) -> bool {
        self.backing().is_some()
    }

    /// The context for descending into `name`, given how it resolved.
    ///
    /// Returns `None` when the entry does not exist — which is also how a
    /// hidden entry terminates a walk. Whether an admitted host-backed entry
    /// really is a directory is a host question, answered in increment 5; the
    /// engine only supplies the policy context it would have.
    #[must_use]
    pub fn child(&self, name: &Name, resolution: &Resolution) -> Option<Self> {
        Some(Self {
            path: self.path.child(name),
            state: resolution.dir_state()?,
        })
    }
}

/// The outcome of resolving one name under a directory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Resolution {
    /// The entry is admitted and lives on the host.
    HostBacked {
        /// Where the entry lives: the enclosing graft plus the relative path
        /// beneath it.
        backing: HostBacking,
        /// The effective share mode the admitting rule gives it. Enforcement
        /// and presented bits both use this mode.
        mode: EffectiveMode,
    },
    /// The entry is a synthesized directory: it exists only because reachable
    /// rules lie beneath it, and it has no host backing.
    SynthesizedDir,
    /// The entry does not exist. This covers `hidden`, which is
    /// indistinguishable from absence by design: no resolve, no stat, no
    /// listing.
    Nonexistent,
}

impl Resolution {
    /// Whether the entry surfaced at all.
    #[must_use]
    pub fn is_admitted(&self) -> bool {
        !matches!(self, Self::Nonexistent)
    }

    /// The effective mode of an admitted host-backed entry.
    #[must_use]
    pub fn mode(&self) -> Option<EffectiveMode> {
        match self {
            Self::HostBacked { mode, .. } => Some(*mode),
            Self::SynthesizedDir | Self::Nonexistent => None,
        }
    }

    /// The host backing of an admitted host-backed entry.
    #[must_use]
    pub fn backing(&self) -> Option<&HostBacking> {
        match self {
            Self::HostBacked { backing, .. } => Some(backing),
            Self::SynthesizedDir | Self::Nonexistent => None,
        }
    }

    /// The directory state this entry would have when descended into, or
    /// `None` if it does not exist.
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

/// One admitted entry of a directory listing.
///
/// `V` is whatever the caller's own filter attached to the entry when it kept
/// it — the engine never looks at it. That is how the host-side facts a listing
/// needs (the stat the visibility decision was made on, above all) travel out
/// of an enumeration without the engine performing any I/O or knowing what a
/// host is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirEntry<V = ()> {
    /// The entry's name.
    pub name: Name,
    /// How the entry resolved. Enumeration only ever yields admitted
    /// resolutions; hidden entries are filtered out.
    pub resolution: Resolution,
    /// What the caller's filter attached when it kept the entry.
    pub kept: V,
}

impl RuleTable {
    /// Resolves one name under a directory, per the six steps above.
    ///
    /// The name must be a single component — the server rejects anything
    /// containing `/`, `.` or `..` before the engine sees it, which [`Name`]
    /// enforces.
    #[must_use]
    pub fn resolve(&self, directory: &DirContext, name: &Name) -> Resolution {
        // Step 1: a literal rule at `D/N` wins outright.
        if let Some(rule) = self.literal_child(directory.path(), name) {
            return match (rule.mode.effective(), &rule.backing) {
                (Some(mode), Some(backing)) => Resolution::HostBacked {
                    backing: backing.clone(),
                    mode,
                },
                // Hidden, which is the only mode a validated table leaves
                // without a backing.
                _ => Resolution::Nonexistent,
            };
        }

        // Step 2: a pattern covering the name is the more specific of the two
        // per-directory defaults, so it is consulted before the bare `*`.
        if let Some(pattern) = self.pattern(directory.path(), name) {
            match (pattern.effective(), directory.backing()) {
                (None, _) => return Resolution::Nonexistent,
                (Some(mode), Some(backing)) => {
                    return Resolution::HostBacked {
                        backing: backing.child(name),
                        mode,
                    };
                }
                // A pattern on a directory with no backing has nothing to match
                // against; the table build rejects that configuration, so this
                // arm falls through to the remaining steps.
                (Some(_), None) => {}
            }
        }

        // Step 3: the directory's wildcard is the default for every entry no
        // literal or pattern rule claims, and beats the subtree inheritance of
        // step 4.
        if let Some(wildcard) = self.wildcard(directory.path()) {
            match (wildcard.effective(), directory.backing()) {
                (None, _) => return Resolution::Nonexistent,
                (Some(mode), Some(backing)) => {
                    return Resolution::HostBacked {
                        backing: backing.child(name),
                        mode,
                    };
                }
                // As above: a wildcard on a directory with no backing has
                // nothing to enumerate, and the table build rejects it.
                (Some(_), None) => {}
            }
        }

        // Step 4: inside a graft, the child exists per the host and inherits
        // the subtree's mode.
        if let DirState::HostBacked { backing, mode } = directory.state() {
            return Resolution::HostBacked {
                backing: backing.child(name),
                mode: *mode,
            };
        }

        // Step 5: the name is on the way to a reachable rule.
        if self.is_intermediate_child(directory.path(), name) {
            return Resolution::SynthesizedDir;
        }

        // Step 6: deny by default.
        Resolution::Nonexistent
    }

    /// Enumerates a directory according to its state, keeping at most `limit`
    /// entries.
    ///
    /// A synthesized directory ignores `host_names` and lists its visible
    /// structural children. A host-backed directory returns the union of the
    /// supplied host names (steps 1–4 applied per entry) and literal-rule child
    /// names absent from that listing, so re-targeted grafts agree between
    /// lookup and readdir. Entries come back in name order with hidden entries
    /// removed.
    ///
    /// `keep` is the caller's own filter, asked about every entry the rules
    /// admit — it is where the host-side checks a listing needs live, since the
    /// engine performs no I/O. `None` drops the entry exactly like a hidden
    /// one; what it returns instead rides along on the entry, so the caller
    /// need not repeat the work its decision was made on.
    ///
    /// **`host_names` is consumed lazily and nothing but the kept entries is
    /// ever held.** `None` means the directory has more admitted entries than
    /// `limit`, decided the moment the cap would be passed, not after a
    /// hostile directory has already been materialized — which is what makes
    /// the listing cap a bound on memory instead of a report about it. A `None`
    /// limit is no cap at all: the enumeration then always completes, and the
    /// memory it costs is the size of the directory the operator grafted.
    pub fn enumerate<V>(
        &self,
        directory: &DirContext,
        host_names: impl IntoIterator<Item = Name>,
        limit: Option<usize>,
        keep: impl FnMut(&Name, &Resolution) -> Option<V>,
    ) -> Option<Vec<DirEntry<V>>> {
        let mut listing = Listing {
            entries: Vec::new(),
            kept: BTreeSet::new(),
            limit,
            keep,
        };
        match directory.state() {
            DirState::Synthesized => {
                for name in self.structural_children(directory.path()) {
                    listing.offer(self, directory, name)?;
                }
            }
            DirState::HostBacked { .. } => {
                for name in host_names {
                    listing.offer(self, directory, name)?;
                }
                // A literal rule pointing somewhere else has no host child to
                // be found among those names, and must still be listed.
                for name in self.literal_child_names(directory.path()) {
                    if !listing.holds(name) {
                        listing.offer(self, directory, name.clone())?;
                    }
                }
            }
        }
        Some(listing.finish())
    }

    /// Walks an absolute namespace path from the root, one component at a
    /// time, and returns the context of the directory it names.
    ///
    /// This is what mounting a namespace subpath does at handshake time.
    /// `None` means some component did not resolve — including because it, or
    /// something above it, is hidden.
    #[must_use]
    pub fn walk(&self, path: &NamespacePath) -> Option<DirContext> {
        let mut directory = DirContext::root();
        for name in path.components() {
            let resolution = self.resolve(&directory, name);
            directory = directory.child(name, &resolution)?;
        }
        Some(directory)
    }

    /// Resolves an absolute namespace path as a lookup of its last component
    /// would, after walking its parent. The root is the synthesized directory
    /// every walk starts from.
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

/// One enumeration in progress: the entries kept so far, and the cap they are
/// kept under.
///
/// Only kept entries are stored, so the memory an enumeration costs is the size
/// of its *result* — never the size of the directory it walked.
struct Listing<V, K> {
    entries: Vec<DirEntry<V>>,
    /// The names already kept, so a literal-rule child that the host listing
    /// also named is not offered twice.
    kept: BTreeSet<Name>,
    /// The configured listing cap, or `None` for an uncapped enumeration.
    limit: Option<usize>,
    keep: K,
}

impl<V, K: FnMut(&Name, &Resolution) -> Option<V>> Listing<V, K> {
    /// Resolves one candidate name and keeps it if it survives both the rules
    /// and the caller's filter.
    ///
    /// `None` means the cap would have been passed: the entry is not stored,
    /// and the enumeration is over.
    fn offer(&mut self, table: &RuleTable, directory: &DirContext, name: Name) -> Option<()> {
        let resolution = table.resolve(directory, &name);
        if !resolution.is_admitted() {
            return Some(());
        }
        let Some(kept) = (self.keep)(&name, &resolution) else {
            return Some(());
        };
        if self.limit.is_some_and(|limit| self.entries.len() >= limit) {
            return None;
        }
        self.kept.insert(name.clone());
        self.entries.push(DirEntry {
            name,
            resolution,
            kept,
        });
        Some(())
    }

    /// Whether this name has already been kept.
    fn holds(&self, name: &Name) -> bool {
        self.kept.contains(name)
    }

    /// The listing, in name order.
    fn finish(mut self) -> Vec<DirEntry<V>> {
        self.entries
            .sort_by(|left, right| left.name.cmp(&right.name));
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

    /// Resolves one name under the directory at `directory`.
    fn resolve(table: &RuleTable, directory: &str, entry: &str) -> String {
        describe(&table.resolve(&dir(table, directory), &name(entry)))
    }

    /// A project graft with a hidden default and one explicitly admitted entry.
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

    /// The design's motivating composition: the parent grafted `rw`, its
    /// children hidden by a bare `*`, one family un-hidden by a pattern. The
    /// second directory carries no wildcard, which is the only place the
    /// enclosing default is observable.
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
        // The empty run is a run: `project-*` covers a child named exactly
        // `project-`.
        assert_eq!(
            resolve(&table, "/a", "project-"),
            "Ro graft=\"/srv/a\" relative=\"project-\""
        );
        assert_eq!(resolve(&table, "/a", "project"), "Nonexistent");
    }

    #[test]
    fn the_specificity_chain_runs_literal_then_pattern_then_wildcard() {
        let table = family_table();
        // Three names at one directory, one winner each: the literal rule beats
        // the pattern, the pattern beats the bare `*`, and the `*` decides
        // everything else.
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

        // The fourth tier is observable only where no bare `*` shadows it, so
        // it takes a second directory: a pattern beats subtree inheritance,
        // and inheritance is what everything else gets.
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
        // Full invisibility: no resolution, no descent, no listing.
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
        // A match starting with `*` does not reach a dotfile...
        assert_eq!(
            resolve(&table, "/a", ".b-a"),
            "Rw graft=\"/srv/a\" relative=\".b-a\""
        );
        assert_eq!(resolve(&table, "/a", ".x-a"), "Nonexistent");
        // ...while it covers the same name without the dot.
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
        // The pattern governs `/a`'s children only; below that its mode is the
        // subtree mode, exactly as a wildcard-admitted directory's is.
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
        assert!(!dir(&table, "/deep").is_host_backed());
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
        // Without the wildcard this would inherit `Rw` from the graft.
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
        // The upgrade is a subtree of its own.
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
        // The wildcard governs `/a`'s children only; below that the
        // wildcard-admitted mode is the subtree mode.
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
        assert!(!root.is_host_backed());
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
    fn enumeration_refuses_the_entry_that_would_pass_the_cap_and_reads_no_further() {
        let table = table([RuleSpec::new("/a", ShareMode::Rw).with_target("/srv/a")]);
        let directory = dir(&table, "/a");
        let offered = std::cell::Cell::new(0usize);
        let names = (0..1000).map(|index| name(&format!("entry-{index:04}")));

        let refused = table.enumerate(
            &directory,
            names.inspect(|_| offered.set(offered.get() + 1)),
            Some(4),
            |_, _| Some(()),
        );
        assert!(refused.is_none(), "a directory past the cap is refused");
        assert_eq!(
            offered.get(),
            5,
            "and the enumeration ends there — the cap bounds the work and the \
             memory, not just the answer"
        );
    }

    #[test]
    fn entries_the_rules_or_the_caller_drop_do_not_count_against_the_cap() {
        let table = project_table();
        let directory = dir(&table, "/project");
        let mut names: Vec<Name> = (0..1000)
            .map(|index| name(&format!("entry-{index:04}")))
            .collect();
        names.push(name("notes.txt"));

        // A wildcard hides all thousand of them, so the listing is one entry
        // and fits a cap of one. This is why the host listing itself cannot
        // simply be truncated at the cap: what counts is what is *admitted*.
        let listed = table
            .enumerate(&directory, names.clone(), Some(1), |_, _| Some(()))
            .expect("one admitted entry fits");
        assert_eq!(
            listing(&listed),
            [r#"notes.txt Ro graft="/srv/project" relative="notes.txt""#.to_owned()]
        );

        // The caller's own filter drops entries the same way.
        let empty = table
            .enumerate(&directory, names, Some(1), |name, _| {
                (name != &self::name("notes.txt")).then_some(())
            })
            .expect("nothing is kept");
        assert!(empty.is_empty());
    }

    #[test]
    fn enumeration_order_does_not_depend_on_the_host_listing_order() {
        let table = table([
            RuleSpec::new("/a", ShareMode::Rw).with_target("/srv/a"),
            RuleSpec::new("/a/ro", ShareMode::Ro),
        ]);
        let directory = dir(&table, "/a");
        let forwards = [name("alpha"), name("ro"), name("zulu")];
        let backwards = [name("zulu"), name("ro"), name("alpha")];
        let expected = [
            r#"alpha Rw graft="/srv/a" relative="alpha""#.to_owned(),
            r#"ro Ro graft="/srv/a" relative="ro""#.to_owned(),
            r#"zulu Rw graft="/srv/a" relative="zulu""#.to_owned(),
        ];
        assert_eq!(listing(&enumerate(&table, &directory, forwards)), expected);
        assert_eq!(listing(&enumerate(&table, &directory, backwards)), expected);
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
