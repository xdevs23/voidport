//! Namespace paths and rule paths.
//!
//! A [`NamespacePath`] is an absolute, canonical sequence of [`Name`]
//! components: `/` (the namespace root) or `/a/b/c`. A [`RulePath`] is what a
//! rule is keyed by — a literal path, a single-level wildcard covering the
//! children of one directory, or a **pattern**: a directory plus the [match]
//! that selects which of its children the rule governs.
//!
//! Parsing canonicalizes separators (`//a//b/` is the same path as `/a/b`) and
//! rejects everything the design calls non-canonical: relative paths and `.`
//! or `..` components.
//!
//! [match]: Pattern

use std::fmt;

use super::name::{Name, NameError};
use super::pattern::{Pattern, PatternError};

/// The component that turns a rule path into a single-level wildcard.
pub const WILDCARD: &str = "*";

/// The longest a rule path may be, in bytes.
///
/// Aligned with the host's own `PATH_MAX`: a longer path can never resolve
/// against a host anyway, so nothing legal is lost. What the cap buys is the
/// share subscription's encodability invariant — one subscription entry always
/// fits one notification frame **by construction**, because the path it carries
/// is bounded here, not checked when it is already too late to refuse.
/// Canonicalization only ever removes bytes, so a path that passes here has a
/// canonical form no longer than it.
pub const MAX_RULE_PATH_LEN: usize = 4096;

/// An absolute, canonical namespace path.
///
/// The empty component list is the namespace root, which is where every walk
/// starts and which is synthesized unless rules make it otherwise.
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NamespacePath(Vec<Name>);

impl NamespacePath {
    /// The namespace root, `/`.
    #[must_use]
    pub fn root() -> Self {
        Self(Vec::new())
    }

    /// Parses an absolute namespace path.
    ///
    /// Duplicate and trailing separators are canonicalized away; `.` and `..`
    /// components and relative paths are rejected.
    ///
    /// # Errors
    ///
    /// Returns [`PathError::NotAbsolute`] if the path does not start with `/`,
    /// and [`PathError::Component`] if a component is not a valid [`Name`].
    pub fn parse(path: &str) -> Result<Self, PathError> {
        Self::parse_bytes(path.as_bytes())
    }

    /// Parses an absolute namespace path from bytes.
    ///
    /// The wire carries paths as byte strings, because host entry names are
    /// byte strings; text is the special case, not the rule. Parsing is
    /// otherwise identical to [`Self::parse`].
    ///
    /// # Errors
    ///
    /// As [`Self::parse`].
    pub fn parse_bytes(path: &[u8]) -> Result<Self, PathError> {
        let Some(rest) = path.strip_prefix(b"/") else {
            return Err(PathError::NotAbsolute);
        };
        let mut components = Vec::new();
        for raw in rest
            .split(|byte| *byte == b'/')
            .filter(|segment| !segment.is_empty())
        {
            let index = components.len();
            components
                .push(Name::new(raw).map_err(|source| PathError::Component { index, source })?);
        }
        Ok(Self(components))
    }

    /// Builds a path from components.
    #[must_use]
    pub fn from_components(components: impl IntoIterator<Item = Name>) -> Self {
        Self(components.into_iter().collect())
    }

    /// The path's components, root first.
    #[must_use]
    pub fn components(&self) -> &[Name] {
        &self.0
    }

    /// Whether this is the namespace root.
    #[must_use]
    pub fn is_root(&self) -> bool {
        self.0.is_empty()
    }

    /// Number of components; the root has depth 0.
    #[must_use]
    pub fn depth(&self) -> usize {
        self.0.len()
    }

    /// The path's last component, or `None` at the root.
    #[must_use]
    pub fn last(&self) -> Option<&Name> {
        self.0.last()
    }

    /// The path of the entry `name` inside this directory.
    #[must_use]
    pub fn child(&self, name: &Name) -> Self {
        let mut components = self.0.clone();
        components.push(name.clone());
        Self(components)
    }

    /// The containing directory, or `None` at the root.
    #[must_use]
    pub fn parent(&self) -> Option<Self> {
        if self.is_root() {
            None
        } else {
            Some(self.prefix(self.depth() - 1))
        }
    }

    /// The prefix holding the first `depth` components.
    ///
    /// `prefix(0)` is the root and `prefix(self.depth())` is the path itself;
    /// a larger `depth` is clamped to the whole path.
    #[must_use]
    pub fn prefix(&self, depth: usize) -> Self {
        Self(self.0[..depth.min(self.depth())].to_vec())
    }
}

impl fmt::Display for NamespacePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_root() {
            return f.write_str("/");
        }
        for component in &self.0 {
            write!(f, "/{component}")?;
        }
        Ok(())
    }
}

/// The path a rule is keyed by.
///
/// The three kinds are disjoint keys: a literal rule at `/a`, a wildcard rule
/// `/a/*` and a pattern rule on `/a` with a match coexist — the first governs
/// the entry `a` itself, the second the children of `a` that nothing more
/// specific claims, and the third the children of `a` whose names its match
/// covers. A pattern is keyed by the pair `(directory, match)`, so one
/// directory carries as many pattern rules as have disjoint matches.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RulePath {
    /// A rule on one namespace entry. Never the root: the root is an entry of
    /// nothing.
    Literal(NamespacePath),
    /// A single-level `*` rule: the per-directory default for the children of
    /// the wrapped directory path.
    Wildcard(NamespacePath),
    /// A pattern rule: the children of a directory whose names a match covers.
    ///
    /// Boxed so that a rule key stays as wide as a namespace path. Keys travel
    /// inside every table error, those errors are returned by value from load
    /// and from every control-plane mutation, and a variant twice the size of
    /// the others would make every one of those `Result`s pay for the rarest
    /// rule kind.
    Pattern(Box<PatternKey>),
}

/// What identifies a pattern rule: the directory it governs, and the match
/// that selects which of its children.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PatternKey {
    /// The directory whose children the rule governs.
    pub directory: NamespacePath,
    /// The glob over those children's names.
    pub matches: Pattern,
}

impl RulePath {
    /// Parses a rule path that carries no match.
    ///
    /// A trailing `*` component makes the rule a wildcard over the preceding
    /// directory; `*` anywhere else is rejected (v1 has no recursive `**` and
    /// no glob syntax). A component that merely *contains* a `*` is an
    /// ordinary literal name, exactly as it has always been — the match is a
    /// field of its own, never a path spelling, so no configured path ever
    /// changes meaning.
    ///
    /// # Errors
    ///
    /// Returns [`PathError`] for a path over [`MAX_RULE_PATH_LEN`] bytes, a
    /// non-absolute path, an invalid component, a misplaced `*`, or a literal
    /// rule on the root.
    pub fn parse(path: &str) -> Result<Self, PathError> {
        let parsed = Self::parse_path(path)?;
        let wildcards = parsed
            .components()
            .iter()
            .filter(|component| component.as_bytes() == WILDCARD.as_bytes())
            .count();
        let trailing = parsed
            .last()
            .is_some_and(|last| last.as_bytes() == WILDCARD.as_bytes());
        match (wildcards, trailing) {
            (0, _) if parsed.is_root() => Err(PathError::RootLiteral),
            (0, _) => Ok(Self::Literal(parsed)),
            (1, true) => Ok(Self::Wildcard(parsed.prefix(parsed.depth() - 1))),
            _ => Err(PathError::MisplacedWildcard),
        }
    }

    /// Parses the path of a rule that carries a match.
    ///
    /// The path names the **directory** whose children the match selects, so it
    /// is a plain path: the namespace root is allowed (the host-backing check
    /// is what refuses a pattern with nothing to match against), and a `*`
    /// component is refused, since a rule cannot be a wildcard and a pattern at
    /// once.
    ///
    /// # Errors
    ///
    /// As [`Self::parse`], plus [`PathError::WildcardWithMatch`] for a `*`
    /// component and [`PathError::InvalidMatch`] for a match the pattern syntax
    /// rejects.
    pub fn parse_match(path: &str, matches: &str) -> Result<Self, PathError> {
        let directory = Self::parse_path(path)?;
        if directory
            .components()
            .iter()
            .any(|component| component.as_bytes() == WILDCARD.as_bytes())
        {
            return Err(PathError::WildcardWithMatch);
        }
        let matches =
            Pattern::parse(matches).map_err(|source| PathError::InvalidMatch { source })?;
        Ok(Self::pattern(directory, matches))
    }

    /// The length check and the path parse both rule kinds share.
    ///
    /// The cap runs before anything else, so an oversized path is refused as
    /// what it is, not as whatever its first bad component happens to
    /// be. This is the single boundary both the control plane's rule-add and
    /// the state file's load run through, which is what makes one check cover
    /// both.
    fn parse_path(path: &str) -> Result<NamespacePath, PathError> {
        if path.len() > MAX_RULE_PATH_LEN {
            return Err(PathError::TooLong {
                len: path.len(),
                max: MAX_RULE_PATH_LEN,
            });
        }
        NamespacePath::parse(path)
    }

    /// The key of the pattern `matches` on `directory`.
    #[must_use]
    pub fn pattern(directory: NamespacePath, matches: Pattern) -> Self {
        Self::Pattern(Box::new(PatternKey { directory, matches }))
    }

    /// The namespace path the rule is attached to: the entry itself for a
    /// literal rule, the parent directory for a wildcard or pattern rule.
    #[must_use]
    pub fn path(&self) -> &NamespacePath {
        match self {
            Self::Literal(path) | Self::Wildcard(path) => path,
            Self::Pattern(key) => &key.directory,
        }
    }

    /// Whether this is a wildcard rule.
    #[must_use]
    pub fn is_wildcard(&self) -> bool {
        matches!(self, Self::Wildcard(_))
    }

    /// Whether this is a pattern rule.
    #[must_use]
    pub fn is_pattern(&self) -> bool {
        matches!(self, Self::Pattern(_))
    }

    /// The match a pattern rule carries.
    #[must_use]
    pub fn matches(&self) -> Option<&Pattern> {
        match self {
            Self::Pattern(key) => Some(&key.matches),
            Self::Literal(_) | Self::Wildcard(_) => None,
        }
    }
}

impl fmt::Display for RulePath {
    /// As the operator wrote it: a pattern rule shows the two fields that key
    /// it, spelled the way the CLI takes them, so an error naming a rule names
    /// the command that removes it.
    ///
    /// The operator surfaces spell that same pair through
    /// `voidport_control::RuleKey`, which is the one spelling *they* share. This
    /// is a second one, and it cannot currently be the same code: the engine is
    /// pure logic that owns its domain types and may not import the protocol
    /// crate (`rules::tests::the_engine_imports_nothing_that_can_touch_the_world`
    /// enforces that boundary, and the protocol crate is compiled here with its
    /// socket client), while the protocol crate cannot depend on this one.
    /// Collapsing the two needs a home both may reach.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Literal(path) => write!(f, "{path}"),
            Self::Wildcard(dir) if dir.is_root() => write!(f, "/{WILDCARD}"),
            Self::Wildcard(dir) => write!(f, "{dir}/{WILDCARD}"),
            Self::Pattern(key) => write!(f, "{} --match '{}'", key.directory, key.matches),
        }
    }
}

/// Why a string is not a valid namespace or rule path.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PathError {
    /// The path did not start with `/`.
    #[error("a namespace path must be absolute (start with `/`)")]
    NotAbsolute,
    /// A component was not a valid [`Name`]; `index` counts from the root.
    #[error("invalid component at index {index}: {source}")]
    Component {
        /// Zero-based index of the offending component.
        index: usize,
        /// Why the component was rejected.
        source: NameError,
    },
    /// A `*` component appeared anywhere but at the end.
    #[error("`{WILDCARD}` is only valid as the final component of a rule path")]
    MisplacedWildcard,
    /// A literal rule named the namespace root.
    #[error("the namespace root cannot carry a literal rule; it is synthesized by definition")]
    RootLiteral,
    /// A rule path was longer than [`MAX_RULE_PATH_LEN`] bytes.
    #[error("a rule path may be at most {max} bytes, and this one is {len}")]
    TooLong {
        /// How long the path was.
        len: usize,
        /// The cap it exceeded.
        max: usize,
    },
    /// A rule carried both a `*` path component and a match.
    #[error(
        "a rule with a match names the directory whose children it covers, so \
         its path must not contain a `{WILDCARD}` component"
    )]
    WildcardWithMatch,
    /// A rule's match was not a valid pattern.
    #[error("invalid match: {source}")]
    InvalidMatch {
        /// Why the match was rejected.
        source: PatternError,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(raw: &str) -> Name {
        Name::new(raw).expect("valid name")
    }

    #[test]
    fn parsing_canonicalizes_separators() {
        let expected = NamespacePath::from_components([name("a"), name("b")]);
        assert_eq!(NamespacePath::parse("/a/b").unwrap(), expected);
        assert_eq!(NamespacePath::parse("//a//b/").unwrap(), expected);
        assert_eq!(NamespacePath::parse("/").unwrap(), NamespacePath::root());
        assert_eq!(NamespacePath::parse("///").unwrap(), NamespacePath::root());
    }

    #[test]
    fn parsing_rejects_non_canonical_paths() {
        assert_eq!(NamespacePath::parse("a/b"), Err(PathError::NotAbsolute));
        assert_eq!(NamespacePath::parse(""), Err(PathError::NotAbsolute));
        assert_eq!(
            NamespacePath::parse("/a/./b"),
            Err(PathError::Component {
                index: 1,
                source: NameError::CurrentDir,
            })
        );
        assert_eq!(
            NamespacePath::parse("/a/../b"),
            Err(PathError::Component {
                index: 1,
                source: NameError::ParentDir,
            })
        );
    }

    #[test]
    fn rule_paths_are_capped_at_the_hosts_own_path_max() {
        let longest = format!("/{}", "a".repeat(MAX_RULE_PATH_LEN - 1));
        assert_eq!(longest.len(), MAX_RULE_PATH_LEN);
        assert!(RulePath::parse(&longest).is_ok(), "the cap itself is legal");

        let over = format!("/{}", "a".repeat(MAX_RULE_PATH_LEN));
        assert_eq!(
            RulePath::parse(&over),
            Err(PathError::TooLong {
                len: MAX_RULE_PATH_LEN + 1,
                max: MAX_RULE_PATH_LEN,
            })
        );
        // A wildcard rule is a rule path too, and it is capped the same way.
        assert!(matches!(
            RulePath::parse(&format!("{over}/*")),
            Err(PathError::TooLong { .. })
        ));
        // A mount subpath is not a rule path and keeps its own rules: the cap
        // exists to bound what a *subscription entry* can carry.
        assert!(NamespacePath::parse(&over).is_ok());
    }

    #[test]
    fn byte_paths_parse_like_text_ones() {
        assert_eq!(
            NamespacePath::parse_bytes(b"/a/b").unwrap(),
            NamespacePath::parse("/a/b").unwrap()
        );
        // A component need not be valid UTF-8: host names are byte strings.
        let raw = NamespacePath::parse_bytes(b"/a/\xff\xfe").unwrap();
        assert_eq!(raw.components()[1].as_bytes(), &[0xff, 0xfe]);
        assert_eq!(
            NamespacePath::parse_bytes(b"a/b"),
            Err(PathError::NotAbsolute)
        );
        assert_eq!(
            NamespacePath::parse_bytes(b"/a/.."),
            Err(PathError::Component {
                index: 1,
                source: NameError::ParentDir,
            })
        );
    }

    #[test]
    fn paths_display_canonically() {
        assert_eq!(NamespacePath::root().to_string(), "/");
        assert_eq!(NamespacePath::parse("//a//b/").unwrap().to_string(), "/a/b");
    }

    #[test]
    fn prefixes_and_parents_walk_the_path() {
        let path = NamespacePath::parse("/a/b/c").unwrap();
        assert_eq!(path.prefix(0), NamespacePath::root());
        assert_eq!(path.prefix(2), NamespacePath::parse("/a/b").unwrap());
        assert_eq!(path.prefix(99), path);
        assert_eq!(path.parent(), Some(NamespacePath::parse("/a/b").unwrap()));
        assert_eq!(NamespacePath::root().parent(), None);
        assert_eq!(
            path.child(&name("d")),
            NamespacePath::parse("/a/b/c/d").unwrap()
        );
    }

    #[test]
    fn rule_paths_split_literals_from_wildcards() {
        assert_eq!(
            RulePath::parse("/a/b").unwrap(),
            RulePath::Literal(NamespacePath::parse("/a/b").unwrap())
        );
        assert_eq!(
            RulePath::parse("/a/*").unwrap(),
            RulePath::Wildcard(NamespacePath::parse("/a").unwrap())
        );
        assert_eq!(
            RulePath::parse("/*").unwrap(),
            RulePath::Wildcard(NamespacePath::root())
        );
        assert_eq!(
            RulePath::parse("/a/b*").unwrap(),
            RulePath::Literal(NamespacePath::parse("/a/b*").unwrap())
        );
    }

    #[test]
    fn a_star_inside_a_component_stays_the_literal_name_it_has_always_been() {
        // The match is a field of its own, so nothing about this spelling
        // changed when pattern rules landed: `/a/b*` is the entry literally
        // named `b*`, and it is still nameable.
        assert_eq!(
            RulePath::parse("/a/b*").unwrap(),
            RulePath::Literal(NamespacePath::parse("/a/b*").unwrap())
        );
        assert_eq!(RulePath::parse("/a/b*").unwrap().to_string(), "/a/b*");
        assert!(!RulePath::parse("/a/b*").unwrap().is_pattern());
    }

    #[test]
    fn a_match_keys_a_pattern_rule_by_directory_and_glob() {
        let rule = RulePath::parse_match("/a", "project-*").unwrap();
        assert_eq!(
            rule,
            RulePath::pattern(
                NamespacePath::parse("/a").unwrap(),
                Pattern::parse("project-*").unwrap(),
            )
        );
        assert_eq!(rule.path(), &NamespacePath::parse("/a").unwrap());
        assert!(rule.is_pattern());
        assert!(!rule.is_wildcard());
        assert_eq!(rule.matches().map(Pattern::as_str), Some("project-*"));
        assert_eq!(rule.to_string(), "/a --match 'project-*'");

        // The root is a legal pattern directory to *parse*: whether anything
        // backs it is the table's question, exactly as for a `/*` rule.
        let root = RulePath::parse_match("/", "x*").unwrap();
        assert_eq!(root.path(), &NamespacePath::root());
        assert_eq!(root.to_string(), "/ --match 'x*'");
    }

    #[test]
    fn a_match_is_refused_on_a_wildcard_path_and_when_it_is_not_a_pattern() {
        assert_eq!(
            RulePath::parse_match("/a/*", "x*"),
            Err(PathError::WildcardWithMatch)
        );
        assert_eq!(
            RulePath::parse_match("/*", "x*"),
            Err(PathError::WildcardWithMatch)
        );
        assert_eq!(
            RulePath::parse_match("/a", "*"),
            Err(PathError::InvalidMatch {
                source: crate::rules::pattern::PatternError::MatchesEverything,
            })
        );
        assert_eq!(
            RulePath::parse_match("/a", ""),
            Err(PathError::InvalidMatch {
                source: crate::rules::pattern::PatternError::Empty,
            })
        );
        // The path itself is validated exactly as it is without a match.
        assert_eq!(
            RulePath::parse_match("a/b", "x*"),
            Err(PathError::NotAbsolute)
        );
        let over = format!("/{}", "a".repeat(MAX_RULE_PATH_LEN));
        assert!(matches!(
            RulePath::parse_match(&over, "x*"),
            Err(PathError::TooLong { .. })
        ));
    }

    #[test]
    fn rule_paths_reject_misplaced_wildcards_and_the_root() {
        assert_eq!(RulePath::parse("/a/*/b"), Err(PathError::MisplacedWildcard));
        assert_eq!(RulePath::parse("/*/*"), Err(PathError::MisplacedWildcard));
        assert_eq!(RulePath::parse("/"), Err(PathError::RootLiteral));
    }

    #[test]
    fn rule_paths_display_as_written() {
        assert_eq!(RulePath::parse("/a/b").unwrap().to_string(), "/a/b");
        assert_eq!(RulePath::parse("/a/*").unwrap().to_string(), "/a/*");
        assert_eq!(RulePath::parse("/*").unwrap().to_string(), "/*");
    }
}
