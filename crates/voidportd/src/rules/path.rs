use std::fmt;
use std::sync::Arc;

use super::name::{Name, NameError};
use super::pattern::{Pattern, PatternError};

pub const WILDCARD: &str = "*";

/// Aligned with `PATH_MAX`. The cap guarantees that one subscription entry fits
/// one notification frame. Canonicalization only removes bytes, so a path that
/// passes has a canonical form no longer than it.
pub const MAX_RULE_PATH_LEN: usize = 4096;

/// The empty component list is the namespace root. A clone shares the
/// components.
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NamespacePath(Arc<[Name]>);

impl NamespacePath {
    #[must_use]
    pub fn root() -> Self {
        Self(Arc::from([]))
    }

    /// # Errors
    ///
    /// Returns [`PathError::NotAbsolute`] if the path does not start with `/`,
    /// and [`PathError::Component`] if a component is not a valid [`Name`].
    pub fn parse(path: &str) -> Result<Self, PathError> {
        Self::parse_bytes(path.as_bytes())
    }

    /// The length check runs first, so an oversized path is refused for its length.
    ///
    /// # Errors
    ///
    /// Returns [`PathError::TooLong`] for a longer path, and otherwise as
    /// [`Self::parse`].
    pub fn parse_bounded(path: &str) -> Result<Self, PathError> {
        if path.len() > MAX_RULE_PATH_LEN {
            return Err(PathError::TooLong {
                len: path.len(),
                max: MAX_RULE_PATH_LEN,
            });
        }
        Self::parse(path)
    }

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
        Ok(Self(components.into()))
    }

    #[must_use]
    pub fn from_components(components: impl IntoIterator<Item = Name>) -> Self {
        Self(components.into_iter().collect())
    }

    #[must_use]
    pub fn components(&self) -> &[Name] {
        &self.0
    }

    #[must_use]
    pub fn is_root(&self) -> bool {
        self.0.is_empty()
    }

    #[must_use]
    pub fn depth(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub fn last(&self) -> Option<&Name> {
        self.0.last()
    }

    #[must_use]
    pub fn child(&self, name: &Name) -> Self {
        Self(self.0.iter().chain([name]).cloned().collect())
    }

    #[must_use]
    pub fn parent(&self) -> Option<Self> {
        if self.is_root() {
            None
        } else {
            Some(self.prefix(self.depth() - 1))
        }
    }

    /// A larger `depth` is clamped to the whole path.
    #[must_use]
    pub fn prefix(&self, depth: usize) -> Self {
        Self(self.0[..depth.min(self.depth())].into())
    }
}

impl fmt::Display for NamespacePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_root() {
            return f.write_str("/");
        }
        for component in self.components() {
            write!(f, "/{component}")?;
        }
        Ok(())
    }
}

/// The three kinds are disjoint keys: a literal rule at `/a`, a wildcard rule
/// `/a/*` and a pattern rule on `/a` coexist. A pattern is keyed by `(directory,
/// match)`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RulePath {
    Literal(NamespacePath),
    Wildcard(NamespacePath),
    /// Boxed so that a rule key is as wide as a namespace path: keys travel
    /// inside every table error, which is returned by value.
    Pattern(Box<PatternKey>),
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PatternKey {
    pub directory: NamespacePath,
    pub matches: Pattern,
}

impl RulePath {
    /// A trailing `*` component makes the rule a wildcard over the preceding
    /// directory, and `*` anywhere else is rejected. A component that contains a
    /// `*` is an ordinary literal name.
    ///
    /// # Errors
    ///
    /// Returns [`PathError`] for a path over [`MAX_RULE_PATH_LEN`] bytes, a
    /// non-absolute path, an invalid component, a misplaced `*`, or a literal
    /// rule on the root.
    pub fn parse(path: &str) -> Result<Self, PathError> {
        let parsed = NamespacePath::parse_bounded(path)?;
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

    /// The path names the directory whose children the match selects. The root is
    /// allowed, and a `*` component is refused.
    ///
    /// # Errors
    ///
    /// As [`Self::parse`], plus [`PathError::WildcardWithMatch`] for a `*`
    /// component and [`PathError::InvalidMatch`] for a match the pattern syntax
    /// rejects.
    pub fn parse_match(path: &str, matches: &str) -> Result<Self, PathError> {
        let directory = NamespacePath::parse_bounded(path)?;
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

    #[must_use]
    pub fn is_wildcard(&self) -> bool {
        matches!(self, Self::Wildcard(_))
    }

    #[must_use]
    pub fn is_pattern(&self) -> bool {
        matches!(self, Self::Pattern(_))
    }

    #[must_use]
    pub fn matches(&self) -> Option<&Pattern> {
        match self {
            Self::Pattern(key) => Some(&key.matches),
            Self::Literal(_) | Self::Wildcard(_) => None,
        }
    }
}

impl fmt::Display for RulePath {
    /// The path of a literal rule, `<directory>/*` for a wildcard, and
    /// `<directory> --match '<glob>'` for a pattern. This is a second spelling of
    /// `voidport_control::RuleKey`: the engine may not import the protocol crate
    /// (enforced by `rules::tests::the_engine_imports_nothing_that_can_touch_the_world`),
    /// and the protocol crate cannot depend on this one.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Literal(path) => write!(f, "{path}"),
            Self::Wildcard(dir) if dir.is_root() => write!(f, "/{WILDCARD}"),
            Self::Wildcard(dir) => write!(f, "{dir}/{WILDCARD}"),
            Self::Pattern(key) => write!(f, "{} --match '{}'", key.directory, key.matches),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PathError {
    #[error("a namespace path must be absolute (start with `/`)")]
    NotAbsolute,
    #[error("invalid component at index {index}: {source}")]
    Component { index: usize, source: NameError },
    #[error("`{WILDCARD}` is only valid as the final component of a rule path")]
    MisplacedWildcard,
    #[error("the namespace root cannot carry a literal rule; it is synthesized by definition")]
    RootLiteral,
    #[error("a rule path may be at most {max} bytes, and this one is {len}")]
    TooLong { len: usize, max: usize },
    #[error(
        "a rule with a match names the directory whose children it covers, so \
         its path must not contain a `{WILDCARD}` component"
    )]
    WildcardWithMatch,
    #[error("invalid match: {source}")]
    InvalidMatch { source: PatternError },
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
        assert!(matches!(
            RulePath::parse(&format!("{over}/*")),
            Err(PathError::TooLong { .. })
        ));
        // A mount subpath is not a rule path and has separate rules: the cap
        // exists to bound what a *subscription entry* can carry.
        assert!(NamespacePath::parse(&over).is_ok());
    }

    #[test]
    fn byte_paths_parse_like_text_ones() {
        assert_eq!(
            NamespacePath::parse_bytes(b"/a/b").unwrap(),
            NamespacePath::parse("/a/b").unwrap()
        );
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
    fn clones_and_children_share_the_components_they_were_built_from() {
        let path = NamespacePath::parse("/a/b").unwrap();
        assert!(std::ptr::eq(path.components(), path.clone().components()));
        let child = path.child(&name("c"));
        for (parent, inherited) in path.components().iter().zip(child.components()) {
            assert!(std::ptr::eq(parent.as_bytes(), inherited.as_bytes()));
        }
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

        // Whether anything backs the root is the question of the table.
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
