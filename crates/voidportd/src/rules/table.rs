use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;

use super::mode::ShareMode;
use super::name::Name;
use super::path::{NamespacePath, PathError, RulePath};
use super::pattern::Pattern;

/// The engine treats it as opaque: it never resolves, canonicalizes or opens it.
/// A relative target is resolved against the directory of the state file at
/// load and opened as an `O_PATH` descriptor at graft time.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HostTarget(String);

impl HostTarget {
    #[must_use]
    pub fn new(path: impl Into<String>) -> Self {
        Self(path.into())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&str> for HostTarget {
    fn from(path: &str) -> Self {
        Self::new(path)
    }
}

impl From<String> for HostTarget {
    fn from(path: String) -> Self {
        Self::new(path)
    }
}

impl fmt::Display for HostTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Each graft is an open descriptor, and resolution below one runs `openat2`
/// with `RESOLVE_BENEATH` from it, so the consumer needs the graft and the
/// relative components, never a reassembled absolute path.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HostBacking {
    graft: Arc<HostTarget>,
    relative: Arc<[Name]>,
}

impl HostBacking {
    #[must_use]
    pub fn graft_root(graft: HostTarget) -> Self {
        Self {
            graft: Arc::new(graft),
            relative: Arc::from([]),
        }
    }

    #[must_use]
    pub fn graft(&self) -> &HostTarget {
        &self.graft
    }

    #[must_use]
    pub fn relative(&self) -> &[Name] {
        &self.relative
    }

    #[must_use]
    pub fn is_graft_root(&self) -> bool {
        self.relative.is_empty()
    }

    #[must_use]
    pub fn child(&self, name: &Name) -> Self {
        self.extend(std::slice::from_ref(name))
    }

    /// The subtree test of the rewrite after a rename: swapping the old prefix
    /// for the new one re-points everything recorded beneath a moved directory.
    #[must_use]
    pub fn strip_prefix(&self, prefix: &Self) -> Option<&[Name]> {
        if self.graft != prefix.graft || !self.relative.starts_with(&prefix.relative) {
            return None;
        }
        Some(&self.relative[prefix.relative.len()..])
    }

    #[must_use]
    pub fn extend(&self, components: &[Name]) -> Self {
        Self {
            graft: self.graft.clone(),
            relative: self.relative.iter().chain(components).cloned().collect(),
        }
    }
}

/// Parsing and validation happen at the [`RuleTable::build`] boundary, so no
/// partially validated rule escapes into the engine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleSpec {
    /// The rule path: a namespace path, one ending in `/*` for a wildcard, or the
    /// directory whose children the match covers.
    pub path: String,
    pub mode: ShareMode,
    /// The glob over child names, for a pattern rule, which is mode-only.
    pub matches: Option<String>,
    pub target: Option<HostTarget>,
}

impl RuleSpec {
    #[must_use]
    pub fn new(path: impl Into<String>, mode: ShareMode) -> Self {
        Self {
            path: path.into(),
            mode,
            matches: None,
            target: None,
        }
    }

    #[must_use]
    pub fn with_target(mut self, target: impl Into<HostTarget>) -> Self {
        self.target = Some(target.into());
        self
    }

    #[must_use]
    pub fn with_match(mut self, matches: impl Into<String>) -> Self {
        self.matches = Some(matches.into());
        self
    }

    fn key(&self) -> Result<RulePath, PathError> {
        match &self.matches {
            Some(matches) => RulePath::parse_match(&self.path, matches),
            None => RulePath::parse(&self.path),
        }
    }
}

type KeyedLiterals = BTreeMap<NamespacePath, (ShareMode, Option<HostTarget>)>;

type KeyedWildcards = BTreeMap<NamespacePath, ShareMode>;

type KeyedPatterns = BTreeMap<NamespacePath, BTreeMap<Pattern, ShareMode>>;

type LiteralChildIndex = BTreeMap<NamespacePath, BTreeMap<Name, NamespacePath>>;

type ChildIndex = BTreeMap<NamespacePath, BTreeSet<Name>>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiteralRule {
    pub mode: ShareMode,
    /// `None` exactly when the rule is [`ShareMode::Hidden`].
    pub backing: Option<HostBacking>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RuleTable {
    literals: BTreeMap<NamespacePath, LiteralRule>,
    wildcards: KeyedWildcards,
    patterns: KeyedPatterns,
    literal_children: LiteralChildIndex,
    intermediate_children: ChildIndex,
}

impl RuleTable {
    /// The result does not depend on the order the rules arrive in.
    ///
    /// # Errors
    ///
    /// Returns the first [`TableError`] found. Rules are examined in path order
    /// within each check, so the error is a function of the rule set.
    pub fn build(rules: impl IntoIterator<Item = RuleSpec>) -> Result<Self, TableError> {
        let (literals, wildcards, patterns) = Self::key_rules(rules)?;
        // A component decision is only well defined once at most one pattern can cover
        // any name.
        Self::check_pattern_overlap(&patterns)?;
        Self::check_reachability(&literals, &wildcards, &patterns)?;
        Self::check_default_backing(&literals, &wildcards, &patterns)?;
        let literals = Self::derive_backings(literals)?;
        let (literal_children, intermediate_children) = Self::index_children(&literals);
        Ok(Self {
            literals,
            wildcards,
            patterns,
            literal_children,
            intermediate_children,
        })
    }

    #[must_use]
    pub fn literal(&self, path: &NamespacePath) -> Option<&LiteralRule> {
        self.literals.get(path)
    }

    /// The share subscription enumerates these: a wildcard is a per-directory
    /// default, not a share, and the engine cannot name its children without a
    /// `readdir`. Hidden rules are yielded, and the caller filters them.
    pub fn literal_rules(&self) -> impl Iterator<Item = (&NamespacePath, &LiteralRule)> {
        self.literals.iter()
    }

    /// Resolution uses this child index so that a component lookup does not
    /// allocate an owned namespace path.
    #[must_use]
    pub(crate) fn literal_child(
        &self,
        directory: &NamespacePath,
        name: &Name,
    ) -> Option<&LiteralRule> {
        let path = self.literal_children.get(directory)?.get(name)?;
        self.literals.get(path)
    }

    #[must_use]
    pub fn wildcard(&self, directory: &NamespacePath) -> Option<ShareMode> {
        self.wildcards.get(directory).copied()
    }

    /// At most one pattern can cover `name`, because overlapping patterns are
    /// refused at build.
    #[must_use]
    pub fn pattern(&self, directory: &NamespacePath, name: &Name) -> Option<ShareMode> {
        self.patterns_at(directory)
            .find(|(matches, _)| matches.covers(name))
            .map(|(_, mode)| mode)
    }

    pub fn patterns_at(
        &self,
        directory: &NamespacePath,
    ) -> impl Iterator<Item = (&Pattern, ShareMode)> {
        self.patterns
            .get(directory)
            .into_iter()
            .flat_map(|at_level| at_level.iter().map(|(matches, mode)| (matches, *mode)))
    }

    #[must_use]
    pub fn is_intermediate_child(&self, directory: &NamespacePath, name: &Name) -> bool {
        self.intermediate_children
            .get(directory)
            .is_some_and(|names| names.contains(name))
    }

    /// The candidate set for enumerating a synthesized directory. The caller still
    /// resolves each name, which filters hidden entries.
    #[must_use]
    pub fn structural_children(&self, directory: &NamespacePath) -> BTreeSet<Name> {
        let mut names: BTreeSet<Name> = self
            .literal_children
            .get(directory)
            .map(|children| children.keys().cloned().collect())
            .unwrap_or_default();
        if let Some(children) = self.intermediate_children.get(directory) {
            names.extend(children.iter().cloned());
        }
        names
    }

    /// The server opens these as `O_PATH` descriptors when it builds a namespace.
    #[must_use]
    pub fn graft_targets(&self) -> BTreeSet<&HostTarget> {
        self.literals
            .values()
            .filter_map(|rule| rule.backing.as_ref())
            .map(HostBacking::graft)
            .collect()
    }

    pub(crate) fn literal_child_names(
        &self,
        directory: &NamespacePath,
    ) -> impl Iterator<Item = &Name> {
        self.literal_children
            .get(directory)
            .into_iter()
            .flat_map(|children| children.keys())
    }

    /// Rules are sorted by key before inspection, so the defect reported for a
    /// broken rule set does not depend on its order.
    fn key_rules(
        rules: impl IntoIterator<Item = RuleSpec>,
    ) -> Result<(KeyedLiterals, KeyedWildcards, KeyedPatterns), TableError> {
        let mut sorted: Vec<RuleSpec> = rules.into_iter().collect();
        sorted
            .sort_by(|left, right| (&left.path, &left.matches).cmp(&(&right.path, &right.matches)));
        let mut literals = KeyedLiterals::new();
        let mut wildcards = KeyedWildcards::new();
        let mut patterns = KeyedPatterns::new();
        for rule in sorted {
            let path = rule.key().map_err(|source| TableError::InvalidPath {
                path: rule.path.clone(),
                source,
            })?;
            // A pattern rule is mode-only: the backing of the enclosing rule already
            // supplies what it refines.
            if rule.target.is_some()
                && (path.is_wildcard() || path.is_pattern() || rule.mode == ShareMode::Hidden)
            {
                return Err(TableError::UnexpectedTarget { path });
            }
            let occupied = match &path {
                RulePath::Literal(entry) => literals
                    .insert(entry.clone(), (rule.mode, rule.target))
                    .is_some(),
                RulePath::Wildcard(directory) => {
                    wildcards.insert(directory.clone(), rule.mode).is_some()
                }
                RulePath::Pattern(key) => patterns
                    .entry(key.directory.clone())
                    .or_default()
                    .insert(key.matches.clone(), rule.mode)
                    .is_some(),
            };
            if occupied {
                return Err(TableError::DuplicatePath { path });
            }
        }
        Ok((literals, wildcards, patterns))
    }

    /// Refused at the boundary and never adjudicated at lookup: two rules claiming
    /// one name have no precedence between them.
    fn check_pattern_overlap(patterns: &KeyedPatterns) -> Result<(), TableError> {
        for (directory, at_level) in patterns {
            let matches: Vec<&Pattern> = at_level.keys().collect();
            for (index, left) in matches.iter().enumerate() {
                for right in &matches[index + 1..] {
                    if left.overlaps(right) {
                        return Err(TableError::OverlappingPatterns {
                            path: pattern_rule(directory, left),
                            other: pattern_rule(directory, right),
                        });
                    }
                }
            }
        }
        Ok(())
    }

    /// Each component is decided as resolution decides it (literal, then
    /// pattern, then wildcard), so an admitting pattern makes a deeper rule
    /// reachable and a hidden pattern cuts the chain like a hidden wildcard.
    fn check_reachability(
        literals: &KeyedLiterals,
        wildcards: &KeyedWildcards,
        patterns: &KeyedPatterns,
    ) -> Result<(), TableError> {
        // A literal rule governs its own last component, so only its ancestors have
        // to admit it. A wildcard or pattern rule needs its whole directory path
        // admitted.
        let literal_paths = literals
            .keys()
            .map(|path| (RulePath::Literal(path.clone()), path.depth() - 1));
        let wildcard_paths = wildcards
            .keys()
            .map(|directory| (RulePath::Wildcard(directory.clone()), directory.depth()));
        let pattern_paths = patterns.iter().flat_map(|(directory, at_level)| {
            at_level
                .keys()
                .map(move |matches| (pattern_rule(directory, matches), directory.depth()))
        });
        for (rule, admitted_components) in literal_paths.chain(wildcard_paths).chain(pattern_paths)
        {
            let path = rule.path().clone();
            for depth in 0..admitted_components {
                let directory = path.prefix(depth);
                let entry = path.prefix(depth + 1);
                let name = &path.components()[depth];
                let hidden_by = match literals.get(&entry) {
                    Some((ShareMode::Hidden, _)) => Some(RulePath::Literal(entry)),
                    // A literal rule beats both defaults.
                    Some(_) => None,
                    None => match covering_pattern(patterns, &directory, name) {
                        Some((matches, ShareMode::Hidden)) => {
                            Some(pattern_rule(&directory, matches))
                        }
                        // An admitting pattern beats the wildcard beneath it.
                        Some(_) => None,
                        None => match wildcards.get(&directory) {
                            Some(ShareMode::Hidden) => Some(RulePath::Wildcard(directory)),
                            _ => None,
                        },
                    },
                };
                if let Some(hidden_by) = hidden_by {
                    return Err(TableError::Unreachable {
                        path: rule,
                        hidden_by,
                    });
                }
            }
        }
        Ok(())
    }

    fn check_default_backing(
        literals: &KeyedLiterals,
        wildcards: &KeyedWildcards,
        patterns: &KeyedPatterns,
    ) -> Result<(), TableError> {
        let wildcard_rules = wildcards
            .keys()
            .map(|directory| (directory, RulePath::Wildcard(directory.clone())));
        let pattern_rules = patterns.iter().flat_map(|(directory, at_level)| {
            at_level
                .keys()
                .map(move |matches| (directory, pattern_rule(directory, matches)))
        });
        for (directory, rule) in wildcard_rules.chain(pattern_rules) {
            let grafted = (0..=directory.depth())
                .any(|depth| matches!(literals.get(&directory.prefix(depth)), Some((mode, _)) if mode.admits()));
            if !grafted {
                return Err(TableError::NotHostBacked { path: rule });
            }
        }
        Ok(())
    }

    /// Rules are processed by increasing depth, so the backing of an enclosing
    /// graft is known before a rule derives from it.
    fn derive_backings(
        keyed: KeyedLiterals,
    ) -> Result<BTreeMap<NamespacePath, LiteralRule>, TableError> {
        let mut by_depth: Vec<_> = keyed.into_iter().collect();
        by_depth.sort_by_key(|(path, _)| path.depth());
        let mut literals: BTreeMap<NamespacePath, LiteralRule> = BTreeMap::new();
        for (path, (mode, target)) in by_depth {
            let backing = match (mode.admits(), target) {
                (false, _) => None,
                (true, Some(target)) => Some(HostBacking::graft_root(target)),
                (true, None) => Some(Self::derive_backing(&literals, &path).ok_or_else(|| {
                    TableError::MissingTarget {
                        path: RulePath::Literal(path.clone()),
                    }
                })?),
            };
            literals.insert(path, LiteralRule { mode, backing });
        }
        Ok(literals)
    }

    fn derive_backing(
        resolved: &BTreeMap<NamespacePath, LiteralRule>,
        path: &NamespacePath,
    ) -> Option<HostBacking> {
        (1..path.depth()).rev().find_map(|depth| {
            resolved
                .get(&path.prefix(depth))?
                .backing
                .as_ref()
                .map(|backing| backing.extend(&path.components()[depth..]))
        })
    }

    fn index_children(
        literals: &BTreeMap<NamespacePath, LiteralRule>,
    ) -> (LiteralChildIndex, ChildIndex) {
        let mut literal_children = LiteralChildIndex::new();
        let mut intermediate_children = ChildIndex::new();
        for (path, rule) in literals {
            let (directory, name) = (
                path.prefix(path.depth() - 1),
                path.components()[path.depth() - 1].clone(),
            );
            literal_children
                .entry(directory)
                .or_default()
                .insert(name, path.clone());
            if !rule.mode.admits() {
                // Nothing is reachable beneath a hidden rule.
                continue;
            }
            for depth in 0..path.depth() - 1 {
                intermediate_children
                    .entry(path.prefix(depth))
                    .or_default()
                    .insert(path.components()[depth].clone());
            }
        }
        (literal_children, intermediate_children)
    }
}

fn pattern_rule(directory: &NamespacePath, matches: &Pattern) -> RulePath {
    RulePath::pattern(directory.clone(), matches.clone())
}

/// Keyed lookup over the not-yet-built table, so validation resolves a
/// component as [`RuleTable::pattern`] does over the built one.
fn covering_pattern<'a>(
    patterns: &'a KeyedPatterns,
    directory: &NamespacePath,
    name: &Name,
) -> Option<(&'a Pattern, ShareMode)> {
    patterns
        .get(directory)?
        .iter()
        .find(|(matches, _)| matches.covers(name))
        .map(|(matches, mode)| (matches, *mode))
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TableError {
    #[error("invalid rule path {path:?}: {source}")]
    InvalidPath { path: String, source: PathError },
    #[error("duplicate rule for {path}")]
    DuplicatePath { path: RulePath },
    #[error("rule {path} must not carry a host target")]
    UnexpectedTarget { path: RulePath },
    #[error("pattern rule {path} overlaps {other}: both cover a name, and no rule may")]
    OverlappingPatterns { path: RulePath, other: RulePath },
    #[error("rule {path} is unreachable: {hidden_by} hides the path to it")]
    Unreachable { path: RulePath, hidden_by: RulePath },
    #[error("rule {path} applies to a directory that is not host-backed")]
    NotHostBacked { path: RulePath },
    #[error("rule {path} needs a host target: no enclosing graft supplies one")]
    MissingTarget { path: RulePath },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::name::NameError;
    use crate::rules::test_support::describe_backing;

    fn path(raw: &str) -> NamespacePath {
        NamespacePath::parse(raw).expect("valid namespace path")
    }

    fn rule_path(raw: &str) -> RulePath {
        RulePath::parse(raw).expect("valid rule path")
    }

    fn name(raw: &str) -> Name {
        Name::new(raw).expect("valid name")
    }

    fn backing_of(table: &RuleTable, raw: &str) -> Option<String> {
        table
            .literal(&path(raw))
            .and_then(|rule| rule.backing.as_ref())
            .map(describe_backing)
    }

    #[test]
    fn a_graft_root_takes_its_stated_target() {
        let table =
            RuleTable::build(
                [RuleSpec::new("/project", ShareMode::Rw).with_target("/srv/project")],
            )
            .expect("valid table");
        let rule = table.literal(&path("/project")).expect("rule kept");
        assert_eq!(rule.mode, ShareMode::Rw);
        let backing = rule.backing.as_ref().expect("admitting rule is backed");
        assert_eq!(backing.graft(), &HostTarget::new("/srv/project"));
        assert!(backing.relative().is_empty());
        assert!(backing.is_graft_root());
    }

    #[test]
    fn a_deeper_rule_derives_its_backing_from_the_enclosing_graft() {
        let table = RuleTable::build([
            RuleSpec::new("/project", ShareMode::Rw).with_target("/srv/project"),
            RuleSpec::new("/project/docs/notes.txt", ShareMode::Ro),
        ])
        .expect("valid table");
        let rule = table
            .literal(&path("/project/docs/notes.txt"))
            .expect("rule kept");
        let backing = rule.backing.as_ref().expect("admitting rule is backed");
        assert_eq!(backing.graft(), &HostTarget::new("/srv/project"));
        assert_eq!(backing.relative(), [name("docs"), name("notes.txt")]);
        assert_eq!(
            describe_backing(backing),
            "graft=\"/srv/project\" relative=\"docs/notes.txt\""
        );
        assert!(!backing.is_graft_root());
    }

    #[test]
    fn a_deeper_rule_may_re_target_itself() {
        let table = RuleTable::build([
            RuleSpec::new("/project", ShareMode::Rw).with_target("/srv/project"),
            RuleSpec::new("/project/docs", ShareMode::Ro).with_target("/srv/elsewhere/docs"),
            RuleSpec::new("/project/docs/notes.txt", ShareMode::Rw),
        ])
        .expect("valid table");
        assert_eq!(
            backing_of(&table, "/project/docs").as_deref(),
            Some("graft=\"/srv/elsewhere/docs\" relative=\"\"")
        );
        // The re-target becomes the enclosing graft for what sits beneath it.
        assert_eq!(
            backing_of(&table, "/project/docs/notes.txt").as_deref(),
            Some("graft=\"/srv/elsewhere/docs\" relative=\"notes.txt\"")
        );
    }

    #[test]
    fn hidden_rules_carry_no_backing() {
        let table = RuleTable::build([
            RuleSpec::new("/project", ShareMode::Rw).with_target("/srv/project"),
            RuleSpec::new("/project/secret", ShareMode::Hidden),
        ])
        .expect("valid table");
        let rule = table.literal(&path("/project/secret")).expect("rule kept");
        assert_eq!(rule.mode, ShareMode::Hidden);
        assert_eq!(rule.backing, None);
    }

    #[test]
    fn wildcards_are_keyed_by_the_directory_they_govern() {
        let table = RuleTable::build([
            RuleSpec::new("/project", ShareMode::Rw).with_target("/srv/project"),
            RuleSpec::new("/project/*", ShareMode::Hidden),
        ])
        .expect("valid table");
        assert_eq!(table.wildcard(&path("/project")), Some(ShareMode::Hidden));
        assert_eq!(table.wildcard(&path("/other")), None);
        assert_eq!(
            table.literal(&path("/project")).map(|rule| rule.mode),
            Some(ShareMode::Rw)
        );
    }

    fn family_rules() -> [RuleSpec; 3] {
        [
            RuleSpec::new("/a", ShareMode::Rw).with_target("/srv/a"),
            RuleSpec::new("/a/*", ShareMode::Hidden),
            RuleSpec::new("/a", ShareMode::Rw).with_match("project-*"),
        ]
    }

    #[test]
    fn pattern_rules_are_keyed_by_their_directory_and_their_match() {
        let table = RuleTable::build(
            family_rules()
                .into_iter()
                .chain([RuleSpec::new("/a", ShareMode::Ro).with_match("docs-*")]),
        )
        .expect("two disjoint matches on one directory coexist");

        assert_eq!(
            table.pattern(&path("/a"), &name("project-one")),
            Some(ShareMode::Rw)
        );
        assert_eq!(
            table.pattern(&path("/a"), &name("docs-one")),
            Some(ShareMode::Ro)
        );
        assert_eq!(table.pattern(&path("/a"), &name("other")), None);
        assert_eq!(table.pattern(&path("/other"), &name("project-one")), None);

        assert_eq!(
            table.literal(&path("/a")).map(|rule| rule.mode),
            Some(ShareMode::Rw)
        );
        assert_eq!(table.wildcard(&path("/a")), Some(ShareMode::Hidden));
        let listed: Vec<String> = table
            .patterns_at(&path("/a"))
            .map(|(matches, mode)| format!("{matches} {mode:?}"))
            .collect();
        assert_eq!(listed, ["docs-* Ro".to_owned(), "project-* Rw".to_owned()]);
    }

    #[test]
    fn duplicate_pattern_keys_are_rejected() {
        let error = RuleTable::build(
            family_rules()
                .into_iter()
                .chain([RuleSpec::new("//a/", ShareMode::Ro).with_match("project-*")]),
        )
        .expect_err("the same directory and the same match");
        assert_eq!(
            error,
            TableError::DuplicatePath {
                path: RulePath::parse_match("/a", "project-*").expect("valid pattern rule"),
            }
        );
    }

    #[test]
    fn a_pattern_rule_is_mode_only() {
        let error = RuleTable::build(
            family_rules()
                .into_iter()
                .map(|rule| match rule.matches {
                    Some(_) => rule.with_target("/srv/anything"),
                    None => rule,
                })
                .collect::<Vec<_>>(),
        )
        .expect_err("a pattern refines what the enclosing backing supplies");
        assert_eq!(
            error,
            TableError::UnexpectedTarget {
                path: RulePath::parse_match("/a", "project-*").expect("valid pattern rule"),
            }
        );
    }

    #[test]
    fn a_match_the_pattern_syntax_refuses_is_refused_at_build() {
        for (matches, expected) in [
            ("*", crate::rules::pattern::PatternError::MatchesEverything),
            ("", crate::rules::pattern::PatternError::Empty),
        ] {
            let error = RuleTable::build([
                RuleSpec::new("/a", ShareMode::Rw).with_target("/srv/a"),
                RuleSpec::new("/a", ShareMode::Rw).with_match(matches),
            ])
            .expect_err("the match is not a pattern");
            assert_eq!(
                error,
                TableError::InvalidPath {
                    path: "/a".to_owned(),
                    source: PathError::InvalidMatch { source: expected },
                }
            );
        }
    }

    #[test]
    fn a_pattern_needs_a_host_backed_directory() {
        // The root is synthesized, so a pattern on it has nothing to match against.
        let root = RuleTable::build([RuleSpec::new("/", ShareMode::Ro).with_match("x-*")])
            .expect_err("nothing to match against");
        assert_eq!(
            root,
            TableError::NotHostBacked {
                path: RulePath::parse_match("/", "x-*").expect("valid pattern rule"),
            }
        );

        // `/a` here is synthesized: only `/a/b` is grafted.
        let synthesized = RuleTable::build([
            RuleSpec::new("/a/b", ShareMode::Rw).with_target("/srv/b"),
            RuleSpec::new("/a", ShareMode::Ro).with_match("x-*"),
        ])
        .expect_err("nothing to match against");
        assert_eq!(
            synthesized,
            TableError::NotHostBacked {
                path: RulePath::parse_match("/a", "x-*").expect("valid pattern rule"),
            }
        );
    }

    #[test]
    fn overlapping_patterns_at_one_level_are_refused_naming_both_rules() {
        for (left, right) in [("ab*", "*ba"), ("a*b*c", "*d*")] {
            let error = RuleTable::build([
                RuleSpec::new("/a", ShareMode::Rw).with_target("/srv/a"),
                RuleSpec::new("/a", ShareMode::Rw).with_match(left),
                RuleSpec::new("/a", ShareMode::Ro).with_match(right),
            ])
            .expect_err("both cover a name");
            let TableError::OverlappingPatterns { path, other } = &error else {
                panic!("expected an overlap refusal, got {error}");
            };
            let named = format!("{path} {other}");
            assert!(named.contains(left), "{named} names both rules");
            assert!(named.contains(right), "{named} names both rules");
            assert!(named.contains("/a"), "{named} names the directory");
        }

        // Includes the pair that is disjoint only because a leading `*` never covers a
        // dotfile.
        for (left, right) in [("a*b", "b*a"), ("proj-*", "project-*"), ("*x", ".x*")] {
            RuleTable::build([
                RuleSpec::new("/a", ShareMode::Rw).with_target("/srv/a"),
                RuleSpec::new("/a", ShareMode::Rw).with_match(left),
                RuleSpec::new("/a", ShareMode::Ro).with_match(right),
            ])
            .unwrap_or_else(|error| panic!("{left} and {right} are disjoint: {error}"));
        }

        RuleTable::build([
            RuleSpec::new("/a", ShareMode::Rw).with_target("/srv/a"),
            RuleSpec::new("/a", ShareMode::Rw).with_match("ab*"),
            RuleSpec::new("/a/sub", ShareMode::Ro).with_match("*ba"),
        ])
        .expect("one match per level, and these are two levels");
    }

    #[test]
    fn an_admitting_pattern_keeps_a_deeper_rule_alive() {
        // The pattern admits `project-one`, so the deeper rule is reachable.
        let table = RuleTable::build(
            family_rules()
                .into_iter()
                .chain([RuleSpec::new("/a/project-one/inner", ShareMode::Ro)]),
        )
        .expect("the pattern admits the name on the way");
        assert_eq!(
            backing_of(&table, "/a/project-one/inner").as_deref(),
            Some("graft=\"/srv/a\" relative=\"project-one/inner\"")
        );
    }

    #[test]
    fn a_rule_beneath_a_hidden_pattern_is_dead_configuration() {
        let error = RuleTable::build([
            RuleSpec::new("/a", ShareMode::Rw).with_target("/srv/a"),
            RuleSpec::new("/a", ShareMode::Hidden).with_match("secret-*"),
            RuleSpec::new("/a/secret-one/key", ShareMode::Ro),
        ])
        .expect_err("a hidden pattern cuts the chain like a hidden wildcard");
        assert_eq!(
            error,
            TableError::Unreachable {
                path: rule_path("/a/secret-one/key"),
                hidden_by: RulePath::parse_match("/a", "secret-*").expect("valid pattern rule"),
            }
        );
    }

    #[test]
    fn a_pattern_beneath_a_hidden_literal_is_dead_configuration() {
        let error = RuleTable::build([
            RuleSpec::new("/a", ShareMode::Rw).with_target("/srv/a"),
            RuleSpec::new("/a/secret", ShareMode::Hidden),
            RuleSpec::new("/a/secret", ShareMode::Ro).with_match("x-*"),
        ])
        .expect_err("nothing beneath a hidden entry is reachable");
        assert_eq!(
            error,
            TableError::Unreachable {
                path: RulePath::parse_match("/a/secret", "x-*").expect("valid pattern rule"),
                hidden_by: rule_path("/a/secret"),
            }
        );
    }

    #[test]
    fn duplicate_literal_paths_are_rejected() {
        let error = RuleTable::build([
            RuleSpec::new("/a", ShareMode::Rw).with_target("/srv/a"),
            RuleSpec::new("//a/", ShareMode::Ro).with_target("/srv/other"),
        ])
        .expect_err("duplicate");
        assert_eq!(
            error,
            TableError::DuplicatePath {
                path: rule_path("/a")
            }
        );
    }

    #[test]
    fn duplicate_wildcard_paths_are_rejected() {
        let error = RuleTable::build([
            RuleSpec::new("/a", ShareMode::Rw).with_target("/srv/a"),
            RuleSpec::new("/a/*", ShareMode::Ro),
            RuleSpec::new("/a/*", ShareMode::Hidden),
        ])
        .expect_err("duplicate");
        assert_eq!(
            error,
            TableError::DuplicatePath {
                path: rule_path("/a/*")
            }
        );
    }

    #[test]
    fn a_literal_rule_and_a_wildcard_on_the_same_directory_coexist() {
        let table = RuleTable::build([
            RuleSpec::new("/a", ShareMode::Rw).with_target("/srv/a"),
            RuleSpec::new("/a/*", ShareMode::Ro),
        ])
        .expect("distinct keyspaces");
        assert_eq!(
            table.literal(&path("/a")).map(|rule| rule.mode),
            Some(ShareMode::Rw)
        );
        assert_eq!(table.wildcard(&path("/a")), Some(ShareMode::Ro));
    }

    #[test]
    fn non_canonical_paths_are_rejected() {
        let cases = [
            ("a/b", PathError::NotAbsolute),
            (
                "/a/./b",
                PathError::Component {
                    index: 1,
                    source: NameError::CurrentDir,
                },
            ),
            (
                "/a/../b",
                PathError::Component {
                    index: 1,
                    source: NameError::ParentDir,
                },
            ),
            ("/a/*/b", PathError::MisplacedWildcard),
            ("/", PathError::RootLiteral),
        ];
        for (raw, source) in cases {
            let error = RuleTable::build([RuleSpec::new(raw, ShareMode::Rw).with_target("/srv/a")])
                .expect_err("non-canonical path");
            assert_eq!(
                error,
                TableError::InvalidPath {
                    path: raw.to_owned(),
                    source
                }
            );
        }
    }

    #[test]
    fn rules_that_take_no_target_are_rejected_when_given_one() {
        let wildcard = RuleTable::build([
            RuleSpec::new("/a", ShareMode::Rw).with_target("/srv/a"),
            RuleSpec::new("/a/*", ShareMode::Ro).with_target("/srv/anything"),
        ])
        .expect_err("wildcards take their backing from the parent");
        assert_eq!(
            wildcard,
            TableError::UnexpectedTarget {
                path: rule_path("/a/*")
            }
        );

        let hidden = RuleTable::build([
            RuleSpec::new("/a", ShareMode::Rw).with_target("/srv/a"),
            RuleSpec::new("/a/secret", ShareMode::Hidden).with_target("/srv/a/secret"),
        ])
        .expect_err("hidden rules need no backing");
        assert_eq!(
            hidden,
            TableError::UnexpectedTarget {
                path: rule_path("/a/secret")
            }
        );
    }

    #[test]
    fn a_rule_beneath_a_hidden_literal_rule_is_dead_configuration() {
        let error = RuleTable::build([
            RuleSpec::new("/a", ShareMode::Rw).with_target("/srv/a"),
            RuleSpec::new("/a/secret", ShareMode::Hidden),
            RuleSpec::new("/a/secret/key", ShareMode::Ro),
        ])
        .expect_err("unreachable");
        assert_eq!(
            error,
            TableError::Unreachable {
                path: rule_path("/a/secret/key"),
                hidden_by: rule_path("/a/secret"),
            }
        );
    }

    #[test]
    fn a_rule_beneath_a_hidden_wildcard_is_dead_configuration() {
        let error = RuleTable::build([
            RuleSpec::new("/a", ShareMode::Rw).with_target("/srv/a"),
            RuleSpec::new("/a/*", ShareMode::Hidden),
            RuleSpec::new("/a/sub/file", ShareMode::Ro),
        ])
        .expect_err("unreachable");
        assert_eq!(
            error,
            TableError::Unreachable {
                path: rule_path("/a/sub/file"),
                hidden_by: rule_path("/a/*"),
            }
        );
    }

    #[test]
    fn an_admitting_literal_chain_rescues_a_rule_under_a_hidden_wildcard() {
        let table = RuleTable::build([
            RuleSpec::new("/a", ShareMode::Rw).with_target("/srv/a"),
            RuleSpec::new("/a/*", ShareMode::Hidden),
            RuleSpec::new("/a/sub", ShareMode::Ro),
            RuleSpec::new("/a/sub/file", ShareMode::Rw),
        ])
        .expect("reachable through the literal chain");
        assert_eq!(
            backing_of(&table, "/a/sub/file").as_deref(),
            Some("graft=\"/srv/a\" relative=\"sub/file\"")
        );
    }

    #[test]
    fn a_wildcard_on_a_hidden_directory_is_dead_configuration() {
        let error = RuleTable::build([
            RuleSpec::new("/a", ShareMode::Rw).with_target("/srv/a"),
            RuleSpec::new("/a/secret", ShareMode::Hidden),
            RuleSpec::new("/a/secret/*", ShareMode::Ro),
        ])
        .expect_err("unreachable");
        assert_eq!(
            error,
            TableError::Unreachable {
                path: rule_path("/a/secret/*"),
                hidden_by: rule_path("/a/secret"),
            }
        );
    }

    #[test]
    fn a_wildcard_needs_a_host_backed_directory() {
        // The root is synthesized, so a root wildcard has nothing to enumerate.
        let root = RuleTable::build([RuleSpec::new("/*", ShareMode::Ro)])
            .expect_err("nothing to enumerate");
        assert_eq!(
            root,
            TableError::NotHostBacked {
                path: rule_path("/*")
            }
        );

        // `/a` here is synthesized: only `/a/b` is grafted.
        let synthesized = RuleTable::build([
            RuleSpec::new("/a/b", ShareMode::Rw).with_target("/srv/b"),
            RuleSpec::new("/a/*", ShareMode::Ro),
        ])
        .expect_err("nothing to enumerate");
        assert_eq!(
            synthesized,
            TableError::NotHostBacked {
                path: rule_path("/a/*")
            }
        );
    }

    #[test]
    fn a_wildcard_inside_a_graft_is_host_backed_by_inheritance() {
        let table = RuleTable::build([
            RuleSpec::new("/a", ShareMode::Rw).with_target("/srv/a"),
            RuleSpec::new("/a/deep/nested/*", ShareMode::Ro),
        ])
        .expect("the graft backs every directory beneath it");
        assert_eq!(table.wildcard(&path("/a/deep/nested")), Some(ShareMode::Ro));
    }

    #[test]
    fn a_targetless_graft_root_is_rejected() {
        let error = RuleTable::build([RuleSpec::new("/a", ShareMode::Rw)])
            .expect_err("nothing says where it lives");
        assert_eq!(
            error,
            TableError::MissingTarget {
                path: rule_path("/a")
            }
        );

        let orphan = RuleTable::build([
            RuleSpec::new("/a", ShareMode::Rw).with_target("/srv/a"),
            RuleSpec::new("/b/c", ShareMode::Ro),
        ])
        .expect_err("no enclosing graft");
        assert_eq!(
            orphan,
            TableError::MissingTarget {
                path: rule_path("/b/c")
            }
        );
    }

    #[test]
    fn a_targetless_hidden_root_is_fine() {
        let table = RuleTable::build([RuleSpec::new("/a", ShareMode::Hidden)])
            .expect("hidden needs no target");
        assert_eq!(
            table.literal(&path("/a")).map(|rule| rule.mode),
            Some(ShareMode::Hidden)
        );
    }

    #[test]
    fn structural_children_index_literals_and_intermediate_components() {
        let table = RuleTable::build([
            RuleSpec::new("/a/b/c", ShareMode::Rw).with_target("/srv/c"),
            RuleSpec::new("/hidden", ShareMode::Hidden),
        ])
        .expect("valid table");

        assert_eq!(
            table.structural_children(&NamespacePath::root()),
            BTreeSet::from([name("a"), name("hidden")])
        );
        assert_eq!(
            table.structural_children(&path("/a")),
            BTreeSet::from([name("b")])
        );
        assert_eq!(
            table.structural_children(&path("/a/b")),
            BTreeSet::from([name("c")])
        );
        assert!(table.structural_children(&path("/a/b/c")).is_empty());

        assert!(table.is_intermediate_child(&NamespacePath::root(), &name("a")));
        assert!(table.is_intermediate_child(&path("/a"), &name("b")));
        assert!(!table.is_intermediate_child(&path("/a/b"), &name("c")));
        assert!(!table.is_intermediate_child(&NamespacePath::root(), &name("hidden")));
    }

    #[test]
    fn graft_targets_are_the_distinct_pinnable_paths() {
        let table = RuleTable::build([
            RuleSpec::new("/a", ShareMode::Rw).with_target("/srv/a"),
            RuleSpec::new("/a/inherited", ShareMode::Ro),
            RuleSpec::new("/a/elsewhere", ShareMode::Ro).with_target("/srv/elsewhere"),
            RuleSpec::new("/b", ShareMode::Rw).with_target("/srv/a"),
            RuleSpec::new("/hidden", ShareMode::Hidden),
        ])
        .expect("valid table");
        let targets: Vec<&str> = table
            .graft_targets()
            .into_iter()
            .map(HostTarget::as_str)
            .collect();
        assert_eq!(targets, ["/srv/a", "/srv/elsewhere"]);
        assert!(RuleTable::default().graft_targets().is_empty());
    }

    #[test]
    fn an_empty_table_is_a_namespace_with_nothing_in_it() {
        let table = RuleTable::build([]).expect("valid table");
        assert_eq!(table, RuleTable::default());
        assert!(table.structural_children(&NamespacePath::root()).is_empty());
    }
}
