//! The glob uses the `*` engine of [`super::glob`] but a separate parser, because
//! attribute names are not directory entries. A catch-all `*` is legal, `/` is
//! an ordinary byte, the leading-dot rule never fires because the kernel demands
//! a namespace prefix, and globs are TOML strings, so a non-UTF-8 attribute name
//! cannot be spelled by a rule and receives the defaults.
//!
//! A write to `system.posix_acl_*` is refused whatever the rules say, because a
//! valid ACL blob written by the user that owns a file rewrites its mode bits
//! behind the presented-bits and share-mode machinery. The removal of an ACL
//! name that the host does not have, or whose read the rules hide, returns
//! `ENODATA` in the operations layer (`data::ops::xattr`), because removing
//! what is not there is not a write.

use std::collections::HashSet;
use std::fmt;

use super::glob::covers_bytes;

const STAR: u8 = b'*';

pub const USER_PREFIX: &[u8] = b"user.";

const ACL_PREFIX: &[u8] = b"system.posix_acl_";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum XattrVerdict {
    /// Attempt it, and pass the result of the host back unchanged.
    Allow,
    /// Refuse it in the namespace, before the host is called at all.
    Deny,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum XattrAccess {
    Read,
    Write,
}

/// Stored as the operator wrote it, because the state file contains that form and
/// errors name it.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct XattrGlob(String);

impl XattrGlob {
    /// # Errors
    ///
    /// Returns [`XattrGlobError`] for an empty glob or one carrying a NUL, which
    /// could never cover a name.
    pub fn parse(raw: &str) -> Result<Self, XattrGlobError> {
        if raw.is_empty() {
            return Err(XattrGlobError::Empty);
        }
        if raw.contains('\0') {
            return Err(XattrGlobError::Nul);
        }
        Ok(Self(raw.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn covers(&self, name: &[u8]) -> bool {
        covers_bytes(self.0.as_bytes(), name)
    }

    /// `user.selinux` (12) beats `user.*` (5), and a bare `*` (0) is the least
    /// specific.
    #[must_use]
    pub fn specificity(&self) -> usize {
        self.0
            .as_bytes()
            .iter()
            .position(|byte| *byte == STAR)
            .unwrap_or(self.0.len())
    }
}

impl fmt::Display for XattrGlob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XattrSpec {
    pub matches: String,
    pub read: Option<XattrVerdict>,
    pub write: Option<XattrVerdict>,
}

impl XattrSpec {
    #[must_use]
    pub fn new(matches: impl Into<String>) -> Self {
        Self {
            matches: matches.into(),
            read: None,
            write: None,
        }
    }

    #[must_use]
    pub fn with_read(mut self, verdict: XattrVerdict) -> Self {
        self.read = Some(verdict);
        self
    }

    #[must_use]
    pub fn with_write(mut self, verdict: XattrVerdict) -> Self {
        self.write = Some(verdict);
        self
    }
}

/// A rule silent about an axis is not in its list, which is what makes the
/// per-verdict fall-through.
#[derive(Clone, Debug, PartialEq, Eq)]
struct XattrRule {
    glob: XattrGlob,
    verdict: XattrVerdict,
}

/// Most specific first, and deny before allow on a tie, so the answer does not
/// depend on the order the rules were written in.
fn order(rules: &mut [XattrRule]) {
    rules.sort_by_key(|rule| {
        (
            std::cmp::Reverse(rule.glob.specificity()),
            std::cmp::Reverse(rule.verdict),
        )
    });
}

/// Immutable, so an operation that took a namespace snapshot resolves every
/// name against one policy.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct XattrRules {
    read: Vec<XattrRule>,
    write: Vec<XattrRule>,
}

impl XattrRules {
    /// # Errors
    ///
    /// Returns [`XattrRulesError`] naming the offending rule. Load and `xattr add`
    /// build through this boundary, so both refuse identically.
    pub fn build(specs: impl IntoIterator<Item = XattrSpec>) -> Result<Self, XattrRulesError> {
        // Membership only: hash iteration order cannot affect rule ordering.
        let mut claimed = HashSet::new();
        let mut read: Vec<XattrRule> = Vec::new();
        let mut write: Vec<XattrRule> = Vec::new();
        for spec in specs {
            let glob = XattrGlob::parse(&spec.matches).map_err(|source| XattrRulesError::Glob {
                matches: spec.matches.clone(),
                source,
            })?;
            // A rule stating neither axis decides nothing, and would squat a glob that no
            // second rule could then claim.
            if spec.read.is_none() && spec.write.is_none() {
                return Err(XattrRulesError::NoVerdict {
                    matches: spec.matches,
                });
            }
            if !claimed.insert(glob.clone()) {
                return Err(XattrRulesError::DuplicateMatch {
                    matches: spec.matches,
                });
            }
            if let Some(verdict) = spec.read {
                read.push(XattrRule {
                    glob: glob.clone(),
                    verdict,
                });
            }
            if let Some(verdict) = spec.write {
                write.push(XattrRule { glob, verdict });
            }
        }
        order(&mut read);
        order(&mut write);
        Ok(Self { read, write })
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.read.is_empty() && self.write.is_empty()
    }

    /// The ACL check runs first and is unconditional. Then the first rule of the
    /// axis covering the name decides, as the axis is ordered most specific first.
    /// Nothing covering leaves the defaults.
    #[must_use]
    pub fn verdict(&self, name: &[u8], access: XattrAccess) -> XattrVerdict {
        if access == XattrAccess::Write && name.starts_with(ACL_PREFIX) {
            return XattrVerdict::Deny;
        }
        self.axis(access)
            .iter()
            .find(|rule| rule.glob.covers(name))
            .map_or_else(|| default_verdict(name, access), |rule| rule.verdict)
    }

    fn axis(&self, access: XattrAccess) -> &[XattrRule] {
        match access {
            XattrAccess::Read => &self.read,
            XattrAccess::Write => &self.write,
        }
    }

    /// Whether an attribute name may be read. Where it may not, the name is absent
    /// from a listing and a get returns `ENODATA`.
    #[must_use]
    pub fn readable(&self, name: &[u8]) -> bool {
        self.verdict(name, XattrAccess::Read) == XattrVerdict::Allow
    }

    #[must_use]
    pub fn writable(&self, name: &[u8]) -> bool {
        self.verdict(name, XattrAccess::Write) == XattrVerdict::Allow
    }
}

/// Reads are allowed, because the mount is supposed to look like a filesystem.
/// Writes are allowed for `user.*` and denied otherwise.
fn default_verdict(name: &[u8], access: XattrAccess) -> XattrVerdict {
    match access {
        XattrAccess::Read => XattrVerdict::Allow,
        XattrAccess::Write if name.starts_with(USER_PREFIX) => XattrVerdict::Allow,
        XattrAccess::Write => XattrVerdict::Deny,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum XattrGlobError {
    #[error("an attribute match must not be empty")]
    Empty,
    #[error("an attribute match must not contain a NUL byte")]
    Nul,
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum XattrRulesError {
    #[error("attribute rule {matches:?}: {source}")]
    Glob {
        matches: String,
        #[source]
        source: XattrGlobError,
    },
    #[error(
        "attribute rule {matches:?} is already configured: a rule is keyed by its \
         match, so change one by removing it and adding it back"
    )]
    DuplicateMatch { matches: String },
    #[error(
        "attribute rule {matches:?} states no verdict: give it a read verdict, a \
         write verdict, or both — a rule that states neither decides nothing and \
         holds the match against any rule that would"
    )]
    NoVerdict { matches: String },
}

#[cfg(test)]
mod tests {
    use super::XattrAccess::{Read, Write};
    use super::XattrVerdict::{Allow, Deny};
    use super::*;

    fn rules(specs: impl IntoIterator<Item = XattrSpec>) -> XattrRules {
        XattrRules::build(specs).expect("valid rules")
    }

    fn read(table: &XattrRules, name: &str) -> XattrVerdict {
        table.verdict(name.as_bytes(), Read)
    }

    fn write(table: &XattrRules, name: &str) -> XattrVerdict {
        table.verdict(name.as_bytes(), Write)
    }

    #[test]
    fn the_defaults_are_read_everything_and_write_only_the_user_namespace() {
        let none = rules([]);
        assert!(none.is_empty());
        for name in [
            "user.thing",
            "security.selinux",
            "trusted.overlay.opaque",
            "system.nfs4_acl",
            "nonsense",
        ] {
            assert_eq!(read(&none, name), Allow, "{name} reads by default");
        }
        assert_eq!(write(&none, "user.thing"), Allow);
        assert_eq!(write(&none, "user."), Allow);
        assert_eq!(write(&none, "security.selinux"), Deny);
        assert_eq!(write(&none, "trusted.thing"), Deny);
        assert_eq!(write(&none, "system.nfs4_acl"), Deny);
        assert_eq!(write(&none, "nonsense"), Deny);
        assert_eq!(write(&none, "user"), Deny);
    }

    #[test]
    fn the_acl_guard_refuses_writes_whatever_a_rule_says() {
        let permissive = rules([XattrSpec::new("*").with_read(Allow).with_write(Allow)]);
        for name in ["system.posix_acl_access", "system.posix_acl_default"] {
            assert_eq!(
                write(&permissive, name),
                Deny,
                "{name} may never be written: a valid blob rewrites the mode bits"
            );
            assert_eq!(read(&permissive, name), Allow);
        }
        // The check covers exactly the ACL names, not the whole `system.` prefix.
        assert_eq!(write(&permissive, "system.nfs4_acl"), Allow);
    }

    #[test]
    fn the_longest_literal_prefix_wins_per_axis() {
        let table = rules([
            XattrSpec::new("user.*").with_write(Deny),
            XattrSpec::new("user.selinux").with_write(Allow),
        ]);
        assert_eq!(write(&table, "user.selinux"), Allow, "the longer prefix");
        assert_eq!(write(&table, "user.other"), Deny);
        assert_eq!(read(&table, "user.selinux"), Allow);
        assert_eq!(read(&table, "user.other"), Allow);

        let reversed = rules([
            XattrSpec::new("security.selinux").with_read(Allow),
            XattrSpec::new("security.*").with_read(Deny),
        ]);
        assert_eq!(read(&reversed, "security.selinux"), Allow);
        assert_eq!(read(&reversed, "security.capability"), Deny);
    }

    #[test]
    fn deny_wins_an_exact_tie() {
        let table = rules([
            XattrSpec::new("user.*secret*").with_read(Deny),
            XattrSpec::new("user.*public*").with_read(Allow),
        ]);
        assert_eq!(read(&table, "user.secret-public"), Deny);
        assert_eq!(read(&table, "user.public-secret"), Deny);
        assert_eq!(read(&table, "user.public-note"), Allow);
        assert_eq!(read(&table, "user.secret-note"), Deny);

        let swapped = rules([
            XattrSpec::new("user.*public*").with_read(Allow),
            XattrSpec::new("user.*secret*").with_read(Deny),
        ]);
        assert_eq!(read(&swapped, "user.secret-public"), Deny);
    }

    #[test]
    fn an_unstated_verdict_falls_through_to_the_next_match_and_then_the_defaults() {
        let table = rules([
            XattrSpec::new("user.build.*").with_write(Deny),
            XattrSpec::new("user.*").with_read(Deny),
        ]);
        assert_eq!(write(&table, "user.build.id"), Deny);
        assert_eq!(
            read(&table, "user.build.id"),
            Deny,
            "the write-only rule leaves reads to the next match"
        );
        assert_eq!(read(&table, "user.other"), Deny);
        assert_eq!(
            write(&table, "user.other"),
            Allow,
            "and the read-only rule leaves writes to the defaults"
        );
    }

    #[test]
    fn a_catch_all_is_legal_and_a_separator_is_an_ordinary_byte() {
        let table = rules([
            XattrSpec::new("*").with_read(Deny).with_write(Deny),
            XattrSpec::new("user.a/b").with_read(Allow),
        ]);
        assert_eq!(read(&table, "user.anything"), Deny);
        assert_eq!(write(&table, "user.anything"), Deny);
        assert_eq!(read(&table, "user.a/b"), Allow, "`/` is a literal byte");
        assert_eq!(write(&table, "user.a/b"), Deny);
        assert_eq!(XattrGlob::parse("*").expect("legal").specificity(), 0);
    }

    #[test]
    fn a_glob_matches_bytes_and_never_forces_a_name_through_utf8() {
        let table = rules([XattrSpec::new("user.*").with_read(Deny)]);
        assert_eq!(table.verdict(b"user.\xff\xfe", Read), Deny);
        assert_eq!(table.verdict(b"security.\xff", Read), Allow);
        assert_eq!(table.verdict(b"security.\xff", Write), Deny);
    }

    #[test]
    fn a_glob_is_refused_when_it_is_empty_or_holds_a_nul() {
        assert_eq!(XattrGlob::parse(""), Err(XattrGlobError::Empty));
        assert_eq!(XattrGlob::parse("a\0b"), Err(XattrGlobError::Nul));
    }

    #[test]
    fn a_glob_longer_than_255_bytes_can_cover_a_short_name() {
        let long = format!("user.{}id", "*".repeat(256));
        let glob = XattrGlob::parse(&long).expect("a long glob is valid");
        assert_eq!(glob.as_str(), long);
        assert!(glob.covers(b"user.id"));
        assert!(glob.covers(b"user.build.id"));
        assert!(!glob.covers(b"user.other"));
        let table = rules([XattrSpec::new(long).with_read(Deny)]);
        assert_eq!(read(&table, "user.id"), Deny);
        assert_eq!(read(&table, "user.other"), Allow);
    }

    #[test]
    fn a_duplicate_glob_is_the_one_table_refusal() {
        let refused = XattrRules::build([
            XattrSpec::new("user.*").with_read(Allow),
            XattrSpec::new("user.*").with_write(Deny),
        ])
        .expect_err("duplicate");
        assert_eq!(
            refused,
            XattrRulesError::DuplicateMatch {
                matches: "user.*".to_owned()
            }
        );
        assert!(refused.to_string().contains("user.*"), "{refused}");

        assert!(
            XattrRules::build([
                XattrSpec::new("user.*secret*").with_read(Deny),
                XattrSpec::new("user.*public*").with_read(Allow),
            ])
            .is_ok()
        );
    }

    #[test]
    fn a_rule_stating_no_verdict_is_refused() {
        let refused =
            XattrRules::build([XattrSpec::new("user.*")]).expect_err("it decides nothing");
        assert_eq!(
            refused,
            XattrRulesError::NoVerdict {
                matches: "user.*".to_owned()
            }
        );
        assert!(refused.to_string().contains("user.*"), "{refused}");

        assert!(XattrRules::build([XattrSpec::new("user.*").with_read(Deny)]).is_ok());
        assert!(XattrRules::build([XattrSpec::new("user.*").with_write(Deny)]).is_ok());

        // The glob is validated first, so a rule with both mistakes names the glob.
        assert!(matches!(
            XattrRules::build([XattrSpec::new("a\0b")]).expect_err("NUL in glob"),
            XattrRulesError::Glob { .. }
        ));
    }

    #[test]
    fn specificity_is_the_literal_prefix() {
        for (glob, expected) in [
            ("*", 0),
            ("*.thing", 0),
            ("user.*", 5),
            ("user.selinux", 12),
            ("u*ser", 1),
        ] {
            assert_eq!(
                XattrGlob::parse(glob).expect("legal").specificity(),
                expected,
                "{glob}"
            );
        }
    }
}
