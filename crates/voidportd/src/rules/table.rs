//! The rule table: domain types, build-time validation, and the structural
//! indexes resolution reads.
//!
//! A table is built once from configuration and is immutable afterwards;
//! runtime reconfiguration builds a new table. Everything that can make a
//! configuration meaningless is rejected here, with a typed error, so that
//! resolution is total and never has to guess (design: "Table validation").
//!
//! Build-time work, in order:
//!
//! 1. **Parse and key** every rule. Literal rules are keyed by their entry
//!    path, wildcard rules by their directory, pattern rules by the pair of
//!    their directory and their match; duplicates in any of the three
//!    keyspaces are rejected. Wildcard, pattern and hidden rules must not
//!    carry a host target.
//! 2. **Pattern overlap.** Two patterns at one directory level may not both
//!    cover any name, so that resolution never has to adjudicate between them.
//!    The check is a product construction over the two matches' automata.
//! 3. **Reachability.** Walk each rule's ancestors, resolving each component
//!    exactly as resolution does: a rule beneath a name only hidden rules
//!    cover is dead configuration and is rejected, while an admitting literal
//!    or pattern on the way keeps it alive.
//! 4. **Default backing.** A wildcard or pattern needs something to enumerate
//!    and match against, so its directory must be structurally host-backed —
//!    some ancestor-or-self literal rule must graft it.
//! 5. **Host backing.** Every admitting literal rule gets its [`HostBacking`]
//!    resolved: its own target if it states one (a re-target), otherwise the
//!    enclosing graft plus the relative path beneath it. A rule with neither
//!    is a targetless graft root and is rejected.
//! 6. **Structural indexes** for resolution steps 5 and 6: which child names
//!    of a directory are literal-rule entries, and which are intermediate
//!    components of a deeper admitting rule (and therefore synthesized
//!    directories).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;

use super::mode::ShareMode;
use super::name::Name;
use super::path::{NamespacePath, PathError, RulePath};
use super::pattern::Pattern;

/// A host path as configuration states it.
///
/// The engine treats it as opaque: it never resolves, canonicalizes or opens
/// it. A relative target is resolved against the state file's directory at
/// load time (increment 4) and pinned as an `O_PATH` descriptor at graft time
/// (increment 5); from then on the descriptor is the truth.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HostTarget(String);

impl HostTarget {
    /// Wraps a configured host path.
    #[must_use]
    pub fn new(path: impl Into<String>) -> Self {
        Self(path.into())
    }

    /// The path as configured.
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

/// Where a namespace entry lives on the host: a graft plus a path relative to
/// it.
///
/// The split is not cosmetic. Grafts are fd-pinned, and all resolution below
/// one runs `openat2` with `RESOLVE_BENEATH` from the pinned descriptor, so
/// the consumer needs the graft it belongs to and the relative components
/// beneath it — never a reassembled absolute path.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HostBacking {
    graft: Arc<HostTarget>,
    relative: Arc<[Name]>,
}

impl HostBacking {
    /// The backing of a graft root itself.
    #[must_use]
    pub fn graft_root(graft: HostTarget) -> Self {
        Self {
            graft: Arc::new(graft),
            relative: Arc::from([]),
        }
    }

    /// The host target of the graft this entry belongs to.
    #[must_use]
    pub fn graft(&self) -> &HostTarget {
        &self.graft
    }

    /// The components below the graft; empty at the graft root.
    #[must_use]
    pub fn relative(&self) -> &[Name] {
        &self.relative
    }

    /// Whether this backing is the graft root.
    #[must_use]
    pub fn is_graft_root(&self) -> bool {
        self.relative.is_empty()
    }

    /// The backing of the host child `name` of this directory.
    #[must_use]
    pub fn child(&self, name: &Name) -> Self {
        self.extend(std::slice::from_ref(name))
    }

    /// The components of this entry below `prefix`, or `None` where it is
    /// neither `prefix` itself nor anything under it.
    ///
    /// The subtree test a rename's rewrite runs: a moved directory's old host
    /// path is a prefix of every path recorded beneath it, and swapping that
    /// prefix for the new one re-points the whole subtree.
    #[must_use]
    pub fn strip_prefix(&self, prefix: &Self) -> Option<&[Name]> {
        if self.graft != prefix.graft || !self.relative.starts_with(&prefix.relative) {
            return None;
        }
        Some(&self.relative[prefix.relative.len()..])
    }

    /// The backing reached by descending `components` from here.
    #[must_use]
    pub fn extend(&self, components: &[Name]) -> Self {
        let mut relative = Vec::with_capacity(self.relative.len() + components.len());
        relative.extend_from_slice(&self.relative);
        relative.extend_from_slice(components);
        Self {
            graft: self.graft.clone(),
            relative: relative.into(),
        }
    }
}

/// One rule as configuration states it: an unparsed namespace path, a share
/// mode, an optional match, and an optional host target.
///
/// This is the shape the state file binds to in increment 4; parsing and every
/// validation happen at the [`RuleTable::build`] boundary, so no partially
/// validated rule can escape into the engine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleSpec {
    /// The rule path: a namespace path, one ending in `/*` for a wildcard, or —
    /// when a match is stated — the directory whose children the match covers.
    pub path: String,
    /// The share mode the rule states.
    pub mode: ShareMode,
    /// The glob over child names, for a pattern rule. A rule that states one is
    /// keyed by `(path, match)` and is mode-only.
    pub matches: Option<String>,
    /// The host path to graft, where the rule takes one.
    pub target: Option<HostTarget>,
}

impl RuleSpec {
    /// A rule with neither a match nor a host target — a wildcard, a hidden
    /// rule, or a literal rule whose backing is derived from the graft
    /// enclosing it.
    #[must_use]
    pub fn new(path: impl Into<String>, mode: ShareMode) -> Self {
        Self {
            path: path.into(),
            mode,
            matches: None,
            target: None,
        }
    }

    /// The same rule with an explicit host target.
    #[must_use]
    pub fn with_target(mut self, target: impl Into<HostTarget>) -> Self {
        self.target = Some(target.into());
        self
    }

    /// The same rule as a pattern over the children of its path.
    #[must_use]
    pub fn with_match(mut self, matches: impl Into<String>) -> Self {
        self.matches = Some(matches.into());
        self
    }

    /// The rule's key, parsed and validated.
    fn key(&self) -> Result<RulePath, PathError> {
        match &self.matches {
            Some(matches) => RulePath::parse_match(&self.path, matches),
            None => RulePath::parse(&self.path),
        }
    }
}

/// Literal rules keyed by entry path, before their backings are derived.
type KeyedLiterals = BTreeMap<NamespacePath, (ShareMode, Option<HostTarget>)>;

/// Wildcard rules keyed by the directory whose children they govern.
type KeyedWildcards = BTreeMap<NamespacePath, ShareMode>;

/// Pattern rules keyed first by the directory whose children they govern, then
/// by their match — the `(path, match)` identity the design gives them.
type KeyedPatterns = BTreeMap<NamespacePath, BTreeMap<Pattern, ShareMode>>;

/// Literal child paths keyed first by their containing directory, then name.
type LiteralChildIndex = BTreeMap<NamespacePath, BTreeMap<Name, NamespacePath>>;

/// Child names of a directory, indexed by that directory's path.
type ChildIndex = BTreeMap<NamespacePath, BTreeSet<Name>>;

/// A validated literal rule, with its host backing already derived.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiteralRule {
    /// The share mode the rule states.
    pub mode: ShareMode,
    /// Where the entry lives on the host; `None` exactly when the rule is
    /// [`ShareMode::Hidden`], which needs no backing.
    pub backing: Option<HostBacking>,
}

/// An immutable, validated rule table.
///
/// The table holds no interior mutability and no I/O: it is a decision
/// structure. Resolution against it (see [`super::resolve`]) is a pure
/// function of the table, the parent directory context, and a name.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RuleTable {
    literals: BTreeMap<NamespacePath, LiteralRule>,
    wildcards: KeyedWildcards,
    patterns: KeyedPatterns,
    literal_children: LiteralChildIndex,
    intermediate_children: ChildIndex,
}

impl RuleTable {
    /// Validates a set of configured rules and builds the table.
    ///
    /// The result does not depend on the order the rules arrive in: rules are
    /// keyed by path, duplicates are rejected, and precedence is structural.
    ///
    /// # Errors
    ///
    /// Returns the first [`TableError`] the validation finds. Rules are
    /// examined in path order within each check, so the error is a function of
    /// the rule set, not of its insertion order.
    pub fn build(rules: impl IntoIterator<Item = RuleSpec>) -> Result<Self, TableError> {
        let (literals, wildcards, patterns) = Self::key_rules(rules)?;
        // Before reachability, because reachability resolves per component and
        // a component's decision is only well defined once at most one pattern
        // can cover any name.
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

    /// The literal rule at a namespace path, if any.
    #[must_use]
    pub fn literal(&self, path: &NamespacePath) -> Option<&LiteralRule> {
        self.literals.get(path)
    }

    /// Every literal rule, in path order.
    ///
    /// This is what the share subscription enumerates: the stream reports a
    /// namespace's **literal** rules, because those are the ones the table can
    /// name without asking the host anything. A wildcard is a per-directory
    /// default, not a share — the engine cannot name a wildcard's
    /// children without a `readdir`, and the enclosing entry already covers the
    /// subtree — so wildcards are deliberately absent here.
    ///
    /// Hidden rules *are* yielded: they are literal rules. Filtering them is
    /// the caller's job, and the subscription does it, because a hidden rule
    /// must never appear as an entry or as an event.
    pub fn literal_rules(&self) -> impl Iterator<Item = (&NamespacePath, &LiteralRule)> {
        self.literals.iter()
    }

    /// The literal rule on `name` immediately inside `directory`, if any.
    ///
    /// Resolution uses this child index so a component lookup does not allocate
    /// an owned whole namespace path merely to probe step 1.
    #[must_use]
    pub(crate) fn literal_child(
        &self,
        directory: &NamespacePath,
        name: &Name,
    ) -> Option<&LiteralRule> {
        let path = self.literal_children.get(directory)?.get(name)?;
        self.literals.get(path)
    }

    /// The wildcard rule governing the children of a directory, if any.
    #[must_use]
    pub fn wildcard(&self, directory: &NamespacePath) -> Option<ShareMode> {
        self.wildcards.get(directory).copied()
    }

    /// The mode of the pattern rule covering `name` inside `directory`, if one
    /// covers it.
    ///
    /// At most one can: overlapping patterns at one directory level are refused
    /// at the build boundary, so this is a decision and not a choice.
    #[must_use]
    pub fn pattern(&self, directory: &NamespacePath, name: &Name) -> Option<ShareMode> {
        self.patterns_at(directory)
            .find(|(matches, _)| matches.covers(name))
            .map(|(_, mode)| mode)
    }

    /// The pattern rules on a directory, in match order.
    pub fn patterns_at(
        &self,
        directory: &NamespacePath,
    ) -> impl Iterator<Item = (&Pattern, ShareMode)> {
        self.patterns
            .get(directory)
            .into_iter()
            .flat_map(|at_level| at_level.iter().map(|(matches, mode)| (matches, *mode)))
    }

    /// Whether `name` is an intermediate component of an admitting literal
    /// rule beneath `directory` — resolution step 5, the synthesized-directory
    /// test.
    #[must_use]
    pub fn is_intermediate_child(&self, directory: &NamespacePath, name: &Name) -> bool {
        self.intermediate_children
            .get(directory)
            .is_some_and(|names| names.contains(name))
    }

    /// Every child name of `directory` that the table itself makes relevant:
    /// literal-rule entries plus intermediate components of deeper rules.
    ///
    /// This is the candidate set for enumerating a synthesized directory; the
    /// caller still resolves each name, which is what filters hidden entries.
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

    /// Every distinct host target the table grafts, in target order.
    ///
    /// This is what the server pins as `O_PATH` descriptors when it builds a
    /// namespace: a graft is fd-pinned, and every resolution below one starts
    /// from the descriptor of the target named here.
    #[must_use]
    pub fn graft_targets(&self) -> BTreeSet<&HostTarget> {
        self.literals
            .values()
            .filter_map(|rule| rule.backing.as_ref())
            .map(HostBacking::graft)
            .collect()
    }

    /// Literal-rule child names of `directory`, in name order.
    pub(crate) fn literal_child_names(
        &self,
        directory: &NamespacePath,
    ) -> impl Iterator<Item = &Name> {
        self.literal_children
            .get(directory)
            .into_iter()
            .flat_map(|children| children.keys())
    }

    /// Step 1: parse every rule and key it, rejecting duplicates and targets
    /// on rules that take none.
    ///
    /// The configured rules are sorted by their key before anything is
    /// inspected, so which defect a broken rule set reports is a function of
    /// the set and not of the order it arrived in.
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
            // A pattern rule is mode-only: it refines the visibility and mode
            // of children the enclosing rule's backing already supplies, so a
            // target on one is as meaningless as a target on a wildcard.
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

    /// Step 2: at most one pattern may cover any name at one directory level.
    ///
    /// Refused here, at the boundary, and never adjudicated at lookup: two
    /// rules claiming one name have no precedence between them, and inventing
    /// one would make resolution depend on something other than structure.
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

    /// Step 3: every rule must be reachable — no hidden decision on the way
    /// down to it.
    ///
    /// Each component is decided exactly as resolution decides it (literal,
    /// then pattern, then wildcard), so an admitting pattern keeps a deeper
    /// rule alive and a hidden pattern cuts the chain exactly as a hidden
    /// wildcard does.
    fn check_reachability(
        literals: &KeyedLiterals,
        wildcards: &KeyedWildcards,
        patterns: &KeyedPatterns,
    ) -> Result<(), TableError> {
        // A literal rule governs its own last component, so only its ancestors
        // have to admit it. A wildcard or pattern rule needs its whole
        // directory path admitted, including the last component.
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
                    // A literal rule beats both defaults, so an admitting
                    // literal keeps a hidden one from cutting the chain.
                    Some(_) => None,
                    None => match covering_pattern(patterns, &directory, name) {
                        Some((matches, ShareMode::Hidden)) => {
                            Some(pattern_rule(&directory, matches))
                        }
                        // An admitting pattern beats the wildcard beneath it,
                        // exactly as it does at resolution.
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

    /// Step 4: a wildcard has nothing to enumerate, and a pattern nothing to
    /// match against, unless the directory is structurally host-backed.
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

    /// Step 5: resolve every admitting literal rule's host backing, stated or
    /// derived.
    ///
    /// Rules are processed by increasing depth so an enclosing graft's backing
    /// is always known before a rule that derives from it.
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

    /// The backing a targetless literal rule inherits: the nearest enclosing
    /// literal rule's backing, extended by the components between them.
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

    /// Step 6: index the child names resolution needs — literal-rule entries
    /// per directory, and intermediate components of admitting rules (the
    /// synthesized directories they imply).
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
                // Nothing is reachable beneath a hidden rule, so it implies no
                // synthesized directories.
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

/// The rule key of the pattern `matches` on `directory`, for diagnostics.
fn pattern_rule(directory: &NamespacePath, matches: &Pattern) -> RulePath {
    RulePath::pattern(directory.clone(), matches.clone())
}

/// The pattern covering `name` inside `directory`, if one does.
///
/// Keyed lookup over the not-yet-built table, so validation resolves a
/// component exactly as [`RuleTable::pattern`] does over the built one.
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

/// Why a set of configured rules is not a valid table.
///
/// Every variant is a configuration defect the design requires to be rejected
/// at build time instead of surfacing as a surprising resolution later.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TableError {
    /// A rule path could not be parsed: not absolute, not canonical, a
    /// misplaced `*`, or a literal rule on the root.
    #[error("invalid rule path {path:?}: {source}")]
    InvalidPath {
        /// The path as configured.
        path: String,
        /// Why it was rejected.
        source: PathError,
    },
    /// Two rules key the same path.
    #[error("duplicate rule for {path}")]
    DuplicatePath {
        /// The duplicated rule path.
        path: RulePath,
    },
    /// A rule that carries no host target was given one. Wildcard and pattern
    /// rules take their backing from the parent plus the entry name, and hidden
    /// rules need none.
    #[error("rule {path} must not carry a host target")]
    UnexpectedTarget {
        /// The offending rule path.
        path: RulePath,
    },
    /// Two pattern rules on one directory both cover some name, so no
    /// structural precedence decides which of them governs it.
    #[error("pattern rule {path} overlaps {other}: both cover a name, and no rule may")]
    OverlappingPatterns {
        /// One of the two overlapping rules.
        path: RulePath,
        /// The other.
        other: RulePath,
    },
    /// A rule is dead configuration: something hidden sits between the root
    /// and it, so nothing can ever reach it.
    #[error("rule {path} is unreachable: {hidden_by} hides the path to it")]
    Unreachable {
        /// The unreachable rule.
        path: RulePath,
        /// The hidden rule that cuts the path.
        hidden_by: RulePath,
    },
    /// A wildcard or pattern rule sits on a directory no graft backs, so it has
    /// nothing to enumerate or match against.
    #[error("rule {path} applies to a directory that is not host-backed")]
    NotHostBacked {
        /// The offending wildcard or pattern rule.
        path: RulePath,
    },
    /// An admitting literal rule states no host target and sits inside no
    /// graft, so nothing tells the server where it lives.
    #[error("rule {path} needs a host target: no enclosing graft supplies one")]
    MissingTarget {
        /// The offending rule.
        path: RulePath,
    },
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

    /// The split backing of a rule that the table admitted.
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
        // A wildcard is not a literal rule on the directory itself.
        assert_eq!(
            table.literal(&path("/project")).map(|rule| rule.mode),
            Some(ShareMode::Rw)
        );
    }

    /// The rule set the pattern tests below key off: a graft, its hidden
    /// default, and one family un-hidden by a match.
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

        // All four keyspaces are distinct: the literal rule on `/a`, the
        // wildcard over its children, and the two patterns.
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
        // The namespace root is synthesized by definition, so a pattern on it
        // has nothing to match against — the same refusal a `/*` rule gets.
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
        // The pinned witness cases: a naive literal-run comparison gets each of
        // these wrong in one direction or the other.
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

        // Disjoint matches coexist — including the pair that is disjoint only
        // because a leading `*` never covers a dotfile.
        for (left, right) in [("a*b", "b*a"), ("proj-*", "project-*"), ("*x", ".x*")] {
            RuleTable::build([
                RuleSpec::new("/a", ShareMode::Rw).with_target("/srv/a"),
                RuleSpec::new("/a", ShareMode::Rw).with_match(left),
                RuleSpec::new("/a", ShareMode::Ro).with_match(right),
            ])
            .unwrap_or_else(|error| panic!("{left} and {right} are disjoint: {error}"));
        }

        // Two patterns on *different* directories never overlap, whatever
        // they say: the refusal is per level.
        RuleTable::build([
            RuleSpec::new("/a", ShareMode::Rw).with_target("/srv/a"),
            RuleSpec::new("/a", ShareMode::Rw).with_match("ab*"),
            RuleSpec::new("/a/sub", ShareMode::Ro).with_match("*ba"),
        ])
        .expect("one match per level, and these are two levels");
    }

    #[test]
    fn an_admitting_pattern_keeps_a_deeper_rule_alive() {
        // The hidden wildcard would cut `/a/project-one/inner` off, but the
        // pattern admits `project-one`, so the deeper rule is reachable —
        // reachability resolves per component, exactly as lookup does.
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
        // The literal rule on `/a/sub` beats the hidden wildcard, so the walk
        // reaches `/a/sub/file` and the configuration is alive.
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
        // The namespace root is synthesized by definition, so a root wildcard
        // never has anything to enumerate.
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
        // `c` is a literal-rule entry, not an intermediate component.
        assert!(!table.is_intermediate_child(&path("/a/b"), &name("c")));
        // A hidden rule implies no synthesized directories on the way to it.
        assert!(!table.is_intermediate_child(&NamespacePath::root(), &name("hidden")));
    }

    #[test]
    fn graft_targets_are_the_distinct_pinnable_paths() {
        let table = RuleTable::build([
            RuleSpec::new("/a", ShareMode::Rw).with_target("/srv/a"),
            // Derived backings share their enclosing graft instead of adding
            // one, and a re-target adds its own.
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
