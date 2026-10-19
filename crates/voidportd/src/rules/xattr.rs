//! Extended-attribute rules: which attribute names a guest may read and write.
//!
//! A namespace carries these beside its ownership, permission and auth policy —
//! **per namespace, never a server global**. Each rule is a glob over attribute
//! *names* with a `read` and/or a `write` verdict, and the whole of the decision
//! is here as pure logic: no syscalls, no descriptors, no host.
//!
//! # The glob is its own parse over the shared automaton
//!
//! The `*` engine is [`super::pattern`]'s ([`covers_bytes`]) and is reused
//! verbatim, so one `*` means one thing everywhere. The **parser** is not
//! reused, because attribute names are not directory entries:
//!
//! * a catch-all `*` is **legal** — there is no enclosing directory to point an
//!   operator at instead, so match-everything has exactly one spelling here;
//! * `/` is an ordinary literal byte, because the kernel accepts one inside an
//!   attribute name;
//! * the engine's leading-dot rule never fires: the kernel demands a namespace
//!   prefix, so no attribute name can begin with a `.`;
//! * a glob longer than [`MAX_XATTR_GLOB_LEN`] is refused as a boundary choice
//!   — names are capped at 255 bytes by the kernel, and while `*` matches the
//!   empty run so a longer glob *could* still cover a short name, a rule that
//!   long is a mistake to name, not a policy to honor;
//! * globs are TOML strings, so a non-UTF-8 attribute name cannot be spelled by
//!   any rule and simply receives the defaults.
//!
//! # Precedence: specificity, with deny-wins ties
//!
//! Among the rules covering a name, the **longest literal prefix wins, per
//! verdict axis**. Where two covering rules tie, **deny wins** — which makes the
//! answer order-independent and safe by default. An axis a rule leaves unstated
//! falls through to the next-most-specific rule that states it, and then to the
//! defaults: that per-verdict fall-through is what makes layering work.
//!
//! The table is therefore kept as **one list per axis**, sorted at the boundary
//! into exactly that order — most specific first, deny before allow on a tie —
//! and a rule silent about an axis is simply absent from that list. Answering is
//! then the first covering rule of one list, and the fall-through needs no
//! machinery at all.
//!
//! Validation is linear: there is no overlap computation for xattr rules at all.
//! Two refusals — a duplicate glob (a rule is keyed by its glob; changing one is
//! a remove followed by an add), and a rule stating no verdict, which would
//! decide nothing while holding its glob against a rule that would.
//!
//! # Defaults, and the one unconditional refusal
//!
//! With no rule covering a name: reads are allowed, and writes are allowed for
//! `user.*` and denied otherwise. The mount then behaves like a local
//! filesystem — a guest reads a `security.*` label and gets the host kernel's
//! own refusal writing it back unprivileged, exactly as on ext4.
//!
//! The exception is the **ACL guard**: a write to `system.posix_acl_*` is
//! refused whatever the rules say. A valid ACL blob written by a file's owner
//! silently rewrites its mode bits, a permission change the namespace's
//! share-mode machinery does not check. An operator therefore cannot skip the
//! permission model with a glob. The check is inside [`XattrRules::verdict`],
//! not at the call site, so no caller can forget it.

use std::fmt;

use super::pattern::covers_bytes;

/// The one metacharacter, shared with the child-name pattern language.
const STAR: u8 = b'*';

/// The longest an attribute-name glob may be, in bytes.
pub const MAX_XATTR_GLOB_LEN: usize = 255;

/// The attribute namespace whose writes are allowed by default.
pub const USER_PREFIX: &[u8] = b"user.";

/// The names the ACL guard refuses writes to, whatever the rules say.
const ACL_PREFIX: &[u8] = b"system.posix_acl_";

/// What a rule says about one way of touching an attribute.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum XattrVerdict {
    /// Attempt it, and pass the host's own answer back untouched.
    Allow,
    /// Refuse it in the namespace, before the host is touched at all.
    Deny,
}

/// Which way an attribute is being touched.
///
/// Two axes, because a rule states them separately: hiding a name from a guest
/// and letting it write one are different decisions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum XattrAccess {
    /// `getxattr` and `listxattr`.
    Read,
    /// `setxattr` and `removexattr`.
    Write,
}

/// A validated glob over attribute names.
///
/// Stored as the operator wrote it — the source form is what the state file
/// keeps, what the control plane echoes and what an error names — and matched
/// over its bytes.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct XattrGlob(String);

impl XattrGlob {
    /// Validates a glob.
    ///
    /// # Errors
    ///
    /// Returns [`XattrGlobError`] for an empty glob, one longer than
    /// [`MAX_XATTR_GLOB_LEN`], and one carrying a NUL — attribute names cross
    /// the syscall boundary as C strings, so a glob holding one could never
    /// cover any name.
    pub fn parse(raw: &str) -> Result<Self, XattrGlobError> {
        if raw.is_empty() {
            return Err(XattrGlobError::Empty);
        }
        if raw.len() > MAX_XATTR_GLOB_LEN {
            return Err(XattrGlobError::TooLong { len: raw.len() });
        }
        if raw.contains('\0') {
            return Err(XattrGlobError::Nul);
        }
        Ok(Self(raw.to_owned()))
    }

    /// The glob as the operator wrote it.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether this glob covers an attribute name.
    #[must_use]
    pub fn covers(&self, name: &[u8]) -> bool {
        covers_bytes(self.0.as_bytes(), name)
    }

    /// How specific this glob is: the length of its literal prefix, the run of
    /// bytes before its first `*`.
    ///
    /// `user.selinux` (12) therefore beats `user.*` (5), which is exactly the
    /// layering the design asks for, and a bare `*` (0) is the least specific
    /// thing anyone can write.
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

/// One xattr rule in source form, as the build boundary takes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XattrSpec {
    /// The glob over attribute names, unparsed.
    pub matches: String,
    /// What reading a covered attribute does; `None` falls through.
    pub read: Option<XattrVerdict>,
    /// What writing a covered attribute does; `None` falls through.
    pub write: Option<XattrVerdict>,
}

impl XattrSpec {
    /// A spec stating neither verdict.
    #[must_use]
    pub fn new(matches: impl Into<String>) -> Self {
        Self {
            matches: matches.into(),
            read: None,
            write: None,
        }
    }

    /// The same spec, stating what reads do.
    #[must_use]
    pub fn with_read(mut self, verdict: XattrVerdict) -> Self {
        self.read = Some(verdict);
        self
    }

    /// The same spec, stating what writes do.
    #[must_use]
    pub fn with_write(mut self, verdict: XattrVerdict) -> Self {
        self.write = Some(verdict);
        self
    }
}

/// One validated rule's verdict on one axis.
///
/// A source rule states up to two axes and becomes an entry in each list it
/// speaks about — never in the one it does not, which is the whole of the
/// per-verdict fall-through: a rule silent about reads is simply not among the
/// rules a read consults.
#[derive(Clone, Debug, PartialEq, Eq)]
struct XattrRule {
    /// The glob.
    glob: XattrGlob,
    /// What this axis does for a name the glob covers.
    verdict: XattrVerdict,
}

/// Puts one axis in the order [`XattrRules::verdict`] reads it: most specific
/// first, and deny before allow where two rules are equally specific.
///
/// This is the design's precedence, sorted once at the boundary and not
/// re-derived per attribute name: the most specific cover wins, and a tie goes
/// to deny — which is what makes the answer independent of the order an
/// operator wrote the rules in. The sort is stable, so equally specific rules
/// of the same verdict keep that written order; nothing depends on it, but a
/// deterministic table is easier to reason about.
fn order(rules: &mut [XattrRule]) {
    rules.sort_by_key(|rule| {
        (
            std::cmp::Reverse(rule.glob.specificity()),
            std::cmp::Reverse(rule.verdict),
        )
    });
}

/// A namespace's validated xattr rules.
///
/// Immutable by construction, like the rule table beside it: a control-plane
/// mutation builds a new one and publishes it, so an operation that took a
/// namespace snapshot resolves every name of that operation against one policy.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct XattrRules {
    /// The rules stating what reads do, in the order [`Self::verdict`] answers
    /// from.
    read: Vec<XattrRule>,
    /// The rules stating what writes do, in the same order.
    write: Vec<XattrRule>,
}

impl XattrRules {
    /// Validates a namespace's xattr rules.
    ///
    /// # Errors
    ///
    /// Returns [`XattrRulesError`] naming the offending rule: an unparsable
    /// glob, a glob a second rule already claims, or a rule stating no verdict
    /// at all. All three are refused here and therefore refused identically at
    /// load and at `xattr add`, because both paths build through this one
    /// boundary.
    pub fn build(specs: impl IntoIterator<Item = XattrSpec>) -> Result<Self, XattrRulesError> {
        let mut claimed: Vec<XattrGlob> = Vec::new();
        let mut read: Vec<XattrRule> = Vec::new();
        let mut write: Vec<XattrRule> = Vec::new();
        for spec in specs {
            let glob = XattrGlob::parse(&spec.matches).map_err(|source| XattrRulesError::Glob {
                matches: spec.matches.clone(),
                source,
            })?;
            // A rule that states neither axis decides nothing and cannot even
            // be layered under: it would sit in the table looking like policy
            // while every name it covers fell through it. It is a mistake at
            // the moment it is written, and it also squats a glob no second
            // rule may then claim.
            if spec.read.is_none() && spec.write.is_none() {
                return Err(XattrRulesError::NoVerdict {
                    matches: spec.matches,
                });
            }
            if claimed.contains(&glob) {
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
                write.push(XattrRule {
                    glob: glob.clone(),
                    verdict,
                });
            }
            claimed.push(glob);
        }
        order(&mut read);
        order(&mut write);
        Ok(Self { read, write })
    }

    /// Whether the namespace states any xattr rule at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.read.is_empty() && self.write.is_empty()
    }

    /// What the namespace answers for one access to one attribute name.
    ///
    /// The ACL guard runs first and is unconditional: a write to
    /// `system.posix_acl_*` is denied whatever any rule says, because a valid
    /// ACL blob rewrites the file's mode bits behind the namespace's back.
    ///
    /// Then the first rule of that axis covering the name, which is the whole
    /// of the precedence: the axis is ordered so that the first cover is the
    /// most specific one, and deny before allow where two are equally specific.
    /// A rule that states the other axis is not in this list at all, which is
    /// what makes the per-verdict fall-through nothing more than looking in one
    /// list. Nothing covering leaves the defaults.
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

    /// The rules of one axis.
    fn axis(&self, access: XattrAccess) -> &[XattrRule] {
        match access {
            XattrAccess::Read => &self.read,
            XattrAccess::Write => &self.write,
        }
    }

    /// Whether an attribute name may be read: absent from a listing and
    /// `ENODATA` on a get where it may not.
    #[must_use]
    pub fn readable(&self, name: &[u8]) -> bool {
        self.verdict(name, XattrAccess::Read) == XattrVerdict::Allow
    }

    /// Whether an attribute name may be written.
    #[must_use]
    pub fn writable(&self, name: &[u8]) -> bool {
        self.verdict(name, XattrAccess::Write) == XattrVerdict::Allow
    }
}

/// The answer where no rule states the axis.
///
/// Reads are allowed: refusing them was the old blanket `EOPNOTSUPP`, and the
/// mount is supposed to look like a filesystem. Writes are allowed for `user.*`
/// and denied otherwise, which is the posture the design set — bounded, in
/// either case, by what the server's own host user can do.
fn default_verdict(name: &[u8], access: XattrAccess) -> XattrVerdict {
    match access {
        XattrAccess::Read => XattrVerdict::Allow,
        XattrAccess::Write if name.starts_with(USER_PREFIX) => XattrVerdict::Allow,
        XattrAccess::Write => XattrVerdict::Deny,
    }
}

/// Why a string is not a valid attribute-name glob.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum XattrGlobError {
    /// The glob was empty.
    #[error("an attribute match must not be empty")]
    Empty,
    /// The glob exceeded [`MAX_XATTR_GLOB_LEN`] bytes.
    #[error(
        "an attribute match must be at most {MAX_XATTR_GLOB_LEN} bytes, got {len}: \
         the kernel caps attribute names at that length"
    )]
    TooLong {
        /// The offending length, in bytes.
        len: usize,
    },
    /// The glob contained a NUL byte.
    #[error("an attribute match must not contain a NUL byte")]
    Nul,
}

/// Why a namespace's xattr rules are invalid.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum XattrRulesError {
    /// One rule's glob does not parse.
    #[error("attribute rule {matches:?}: {source}")]
    Glob {
        /// The glob as written.
        matches: String,
        /// Why it was rejected.
        #[source]
        source: XattrGlobError,
    },
    /// Two rules claim the same glob.
    #[error(
        "attribute rule {matches:?} is already configured: a rule is keyed by its \
         match, so change one by removing it and adding it back"
    )]
    DuplicateMatch {
        /// The repeated glob.
        matches: String,
    },
    /// A rule states neither verdict.
    #[error(
        "attribute rule {matches:?} states no verdict: give it a read verdict, a \
         write verdict, or both — a rule that states neither decides nothing and \
         holds the match against any rule that would"
    )]
    NoVerdict {
        /// The glob of the rule that decides nothing.
        matches: String,
    },
}

#[cfg(test)]
mod tests {
    use super::XattrAccess::{Read, Write};
    use super::XattrVerdict::{Allow, Deny};
    use super::*;

    fn rules(specs: impl IntoIterator<Item = XattrSpec>) -> XattrRules {
        XattrRules::build(specs).expect("valid rules")
    }

    /// The verdict for a name, spelled the way the criteria read.
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
        // `user` without its dot is not the `user.` namespace.
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
            // Reads follow policy: the guard is about the write side only.
            assert_eq!(read(&permissive, name), Allow);
        }
        // The guard is exactly the ACL names, not the whole `system.` prefix.
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
        // The read axis is untouched by write-only rules: it falls through to
        // the defaults.
        assert_eq!(read(&table, "user.selinux"), Allow);
        assert_eq!(read(&table, "user.other"), Allow);

        // The same shape on the read axis, and the order rules are written in
        // makes no difference at all.
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
        // A name both cover: the tie goes to deny, whichever way round the two
        // rules are written.
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
            // The most specific rule speaks only about writes.
            XattrSpec::new("user.build.*").with_write(Deny),
            // The next one speaks only about reads.
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
        // A name no rule can spell simply receives the defaults.
        assert_eq!(table.verdict(b"security.\xff", Read), Allow);
        assert_eq!(table.verdict(b"security.\xff", Write), Deny);
    }

    #[test]
    fn a_glob_is_refused_when_it_is_empty_too_long_or_holds_a_nul() {
        assert_eq!(XattrGlob::parse(""), Err(XattrGlobError::Empty));
        assert_eq!(XattrGlob::parse("a\0b"), Err(XattrGlobError::Nul));
        let long = "u".repeat(MAX_XATTR_GLOB_LEN + 1);
        assert_eq!(
            XattrGlob::parse(&long),
            Err(XattrGlobError::TooLong {
                len: MAX_XATTR_GLOB_LEN + 1
            })
        );
        assert!(XattrGlob::parse(&"u".repeat(MAX_XATTR_GLOB_LEN)).is_ok());

        // And the table refuses it, naming the rule.
        let refused = XattrRules::build([XattrSpec::new(long.clone())]).expect_err("too long");
        assert!(refused.to_string().contains(&long), "{refused}");
        assert!(matches!(refused, XattrRulesError::Glob { .. }), "{refused}");
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

        // Two globs that *overlap* are not a refusal: nothing is adjudicated at
        // validation time, because deny wins at resolution.
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

        // Either axis alone is a rule; the refusal is for stating neither.
        assert!(XattrRules::build([XattrSpec::new("user.*").with_read(Deny)]).is_ok());
        assert!(XattrRules::build([XattrSpec::new("user.*").with_write(Deny)]).is_ok());

        // An unparsable glob is still named as one: the glob is validated
        // first, so an operator who wrote both mistakes hears about the glob.
        let long = "u".repeat(MAX_XATTR_GLOB_LEN + 1);
        assert!(matches!(
            XattrRules::build([XattrSpec::new(long)]).expect_err("too long"),
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
