//! The source form of namespace policy.
//!
//! These types are the persistent source of truth: they retain exactly what
//! the operator wrote. A host id written as the sentinel `"uid"` stays the
//! sentinel; a host target written relative to the state file stays relative.
//! Engine state (the rule table, the ownership algebra) is *built from* this
//! form with the environment injected, and persisting re-emits this form
//! verbatim — so `load(persist(x)) == x` holds on the source model and a
//! mutation can never freeze a sentinel into one machine's uid.
//!
//! Every struct denies unknown fields: a misspelled policy key must fail the
//! load, not silently default to something the operator did not ask for.

use std::fmt;

use serde::{Deserialize, Serialize};

/// The default squash target: the conventional `nobody`/`nogroup` id, used
/// numerically and never resolved through NSS.
///
/// The rule engine carries the same constant; a test in `voidportd` pins the
/// two together.
pub const DEFAULT_SQUASH_ID: u32 = 65534;

/// The longest a namespace name may be, in bytes.
pub const MAX_NAMESPACE_NAME_LEN: usize = 255;

/// A validated namespace name.
///
/// Nonempty UTF-8, at most [`MAX_NAMESPACE_NAME_LEN`] bytes, and free of `/`,
/// NUL and control characters — a namespace name appears in a mount URL and
/// keys the registry, so anything that could be mistaken for a path separator
/// or truncate a C string is rejected at the boundary.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct NamespaceName(String);

impl NamespaceName {
    /// Validates a namespace name.
    ///
    /// # Errors
    ///
    /// Returns [`NamespaceNameError`] if the name is empty, too long, or
    /// contains a separator, a NUL, or any other control character.
    pub fn new(name: impl Into<String>) -> Result<Self, NamespaceNameError> {
        let name = name.into();
        if name.is_empty() {
            return Err(NamespaceNameError::Empty);
        }
        if name.len() > MAX_NAMESPACE_NAME_LEN {
            return Err(NamespaceNameError::TooLong { len: name.len() });
        }
        if name.contains('/') {
            return Err(NamespaceNameError::Separator);
        }
        if let Some(character) = name.chars().find(|character| character.is_control()) {
            return Err(NamespaceNameError::Control { character });
        }
        Ok(Self(name))
    }

    /// The name as a string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for NamespaceName {
    type Error = NamespaceNameError;

    fn try_from(name: String) -> Result<Self, Self::Error> {
        Self::new(name)
    }
}

impl From<NamespaceName> for String {
    fn from(name: NamespaceName) -> Self {
        name.0
    }
}

impl fmt::Display for NamespaceName {
    /// Honors width and alignment, so a name can head a column.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(&self.0)
    }
}

/// Why a string is not a valid namespace name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum NamespaceNameError {
    /// The name was empty.
    #[error("a namespace name must not be empty")]
    Empty,
    /// The name exceeded [`MAX_NAMESPACE_NAME_LEN`] bytes.
    #[error("a namespace name must be at most {MAX_NAMESPACE_NAME_LEN} bytes, got {len}")]
    TooLong {
        /// The offending length, in bytes.
        len: usize,
    },
    /// The name contained a `/`.
    #[error("a namespace name must not contain a `/` separator")]
    Separator,
    /// The name contained a control character (NUL included).
    #[error("a namespace name must not contain the control character {character:?}")]
    Control {
        /// The offending character.
        character: char,
    },
}

/// The share mode a rule states.
///
/// Mirrors the rule engine's own mode type; this is its serde-facing source
/// form, spelled in lowercase.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ShareMode {
    /// Read-write.
    Rw,
    /// Read-only.
    Ro,
    /// Hidden: the entry does not resolve, stat or list.
    Hidden,
}

impl fmt::Display for ShareMode {
    /// Honors width and alignment, so modes can be tabulated.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(match self {
            Self::Rw => "rw",
            Self::Ro => "ro",
            Self::Hidden => "hidden",
        })
    }
}

/// How host permission bits are presented.
///
/// v1 has one mode; the field exists so masking and synthetic modes can be
/// added without a schema break.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum PermissionMode {
    /// Host bits as-is, less the write bits on a read-only graft.
    #[default]
    Passthrough,
}

impl fmt::Display for PermissionMode {
    /// Honors width and alignment, so modes can be tabulated.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad("passthrough")
    }
}

impl std::str::FromStr for PermissionMode {
    type Err = UnknownMode;

    /// The inverse of [`Display`](fmt::Display), so a surface that offers the
    /// mode by name sends the mode it showed.
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        match text {
            "passthrough" => Ok(Self::Passthrough),
            _ => Err(UnknownMode {
                kind: "permission",
                value: text.to_owned(),
            }),
        }
    }
}

/// Where the server's backing I/O sits with respect to the host page cache.
///
/// A mount's own direct-io option is guest-side presentation: it keeps the
/// guest from holding a page cache so the host's is the one cache in the
/// system, and the server's backing I/O rides that cache as any local
/// program's would. This setting is the per-namespace decision to reach past
/// it, and it is the only thing that puts `O_DIRECT` on a backing description.
///
/// Uncached backing I/O carries the backing filesystem's alignment demands
/// with it: under [`Passthrough`](Self::Passthrough) and [`Always`](Self::Always)
/// the server serves through buffers aligned to what the backing file asks for,
/// so an aligned guest request round-trips its data — and a request that
/// filesystem itself calls misaligned is answered with the errno it gives
/// locally, unchanged.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum HostDirectIo {
    /// Backing I/O rides the host page cache, whatever the guest handle asked
    /// for.
    #[default]
    Cached,
    /// A guest handle opened `O_DIRECT` opens the backing file `O_DIRECT`; a
    /// handle that did not rides the host cache.
    Passthrough,
    /// Every backing open is uncached, whatever the guest handle asked for.
    Always,
}

impl fmt::Display for HostDirectIo {
    /// Honors width and alignment, so postures can be tabulated.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(match self {
            Self::Cached => "cached",
            Self::Passthrough => "passthrough",
            Self::Always => "always",
        })
    }
}

impl std::str::FromStr for HostDirectIo {
    type Err = UnknownMode;

    /// The inverse of [`Display`](fmt::Display), so a surface that offers the
    /// posture by name sends the posture it showed.
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        match text {
            "cached" => Ok(Self::Cached),
            "passthrough" => Ok(Self::Passthrough),
            "always" => Ok(Self::Always),
            _ => Err(UnknownMode {
                kind: "direct-io",
                value: text.to_owned(),
            }),
        }
    }
}

/// How a client authenticates.
///
/// v1 has one mode; the field exists so modes can be added without a protocol
/// break.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum AuthMode {
    /// No authentication.
    #[default]
    None,
}

impl fmt::Display for AuthMode {
    /// Honors width and alignment, so modes can be tabulated.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad("none")
    }
}

impl std::str::FromStr for AuthMode {
    type Err = UnknownMode;

    /// The inverse of [`Display`](fmt::Display), so a surface that offers the
    /// mode by name sends the mode it showed.
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        match text {
            "none" => Ok(Self::None),
            _ => Err(UnknownMode {
                kind: "auth",
                value: text.to_owned(),
            }),
        }
    }
}

/// A mode name the schema does not define.
///
/// The permission and auth enums have exactly one variant in v1, so an operator
/// surface that offers a *list* of names and sends a *hardcoded* variant looks
/// correct and stops being correct the day a second variant is added. Parsing
/// back through [`FromStr`](std::str::FromStr) is what keeps the value shown
/// and the value sent the same value, and this is what parsing an unknown name
/// says.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{value:?} is not a {kind} mode this version defines")]
pub struct UnknownMode {
    /// Which setting the name was offered for (`permission`, `auth`,
    /// `direct-io`).
    pub kind: &'static str,
    /// The name that did not parse.
    pub value: String,
}

/// What to do with a host id no map entry covers.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum UnmappedPolicy {
    /// Present the configured squash id in place of the unmapped component.
    #[default]
    Squash,
    /// Hide the file entirely, triggered by either component being unmapped.
    Hide,
    /// Present the raw host id.
    Passthrough,
}

impl fmt::Display for UnmappedPolicy {
    /// Honors width and alignment, so policies can be tabulated.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(match self {
            Self::Squash => "squash",
            Self::Hide => "hide",
            Self::Passthrough => "passthrough",
        })
    }
}

/// The stand-in for an id of the invoking user, kept unresolved in the source
/// form so a configuration stays portable between users.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IdSentinel {
    /// The invoking user's uid.
    Uid,
    /// The invoking user's gid.
    Gid,
}

impl fmt::Display for IdSentinel {
    /// Honors width and alignment.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(match self {
            Self::Uid => "uid",
            Self::Gid => "gid",
        })
    }
}

/// The host side of a map entry: a literal number or an [`IdSentinel`].
///
/// The type accepts nothing else — an arbitrary string is a typed
/// deserialization error, not a silently ignored value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum HostId {
    /// `"uid"` or `"gid"`, resolved against the invoking identity at build
    /// time and never written back resolved.
    Sentinel(IdSentinel),
    /// A literal host id.
    Numeric(u32),
}

impl From<u32> for HostId {
    fn from(id: u32) -> Self {
        Self::Numeric(id)
    }
}

impl From<IdSentinel> for HostId {
    fn from(sentinel: IdSentinel) -> Self {
        Self::Sentinel(sentinel)
    }
}

impl fmt::Display for HostId {
    /// Honors width and alignment, whichever side of the enum it is.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sentinel(sentinel) => sentinel.fmt(f),
            Self::Numeric(id) => id.fmt(f),
        }
    }
}

/// One entry of an id map table.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdMapping {
    /// The id on the host, possibly a sentinel.
    pub host: HostId,
    /// The id the guest sees.
    pub guest: u32,
}

impl IdMapping {
    /// Builds a mapping.
    #[must_use]
    pub fn new(host: impl Into<HostId>, guest: u32) -> Self {
        Self {
            host: host.into(),
            guest,
        }
    }
}

/// Which ownership mode a namespace is in, without what the mode configures.
///
/// [`OwnershipSpec`] carries the mode *and* its tables and ids; this is the
/// mode alone, which is all a summary shows. Both spell a mode the same way
/// because both take their names from the same variants, so a name shown in a
/// listing is the name the schema tags a policy with.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OwnershipMode {
    /// Host ids translated through explicit tables.
    Map,
    /// Host ids shown as-is.
    Passthrough,
    /// Every file presented as one configured owner.
    Static,
}

impl fmt::Display for OwnershipMode {
    /// Honors width and alignment, so modes can be tabulated.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(match self {
            Self::Map => "map",
            Self::Passthrough => "passthrough",
            Self::Static => "static",
        })
    }
}

/// Ownership policy in source form, one shape per mode.
///
/// The per-mode shapes are the schema: `map` requires its tables, `static`
/// requires its ids, `passthrough` requires nothing, and a field belonging to
/// another mode is rejected, not ignored.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "lowercase", deny_unknown_fields)]
pub enum OwnershipSpec {
    /// Translate host ids to guest ids through explicit tables.
    Map {
        /// The fate of host ids no table entry covers.
        #[serde(default)]
        unmapped: UnmappedPolicy,
        /// The uid presented for an unmapped host uid under
        /// [`UnmappedPolicy::Squash`].
        #[serde(default = "default_squash_id")]
        squash_uid: u32,
        /// The gid presented for an unmapped host gid under
        /// [`UnmappedPolicy::Squash`].
        #[serde(default = "default_squash_id")]
        squash_gid: u32,
        /// The uid table; must be injective in both directions.
        uid_map: Vec<IdMapping>,
        /// The gid table; must be injective in both directions.
        gid_map: Vec<IdMapping>,
    },
    /// Show host ids as-is in both directions.
    Passthrough {},
    /// Present every file as one configured owner.
    Static {
        /// The uid every file presents.
        uid: u32,
        /// The gid every file presents.
        gid: u32,
    },
}

impl OwnershipSpec {
    /// The mode this policy is in, without its configuration.
    #[must_use]
    pub fn mode(&self) -> OwnershipMode {
        match self {
            Self::Map { .. } => OwnershipMode::Map,
            Self::Passthrough {} => OwnershipMode::Passthrough,
            Self::Static { .. } => OwnershipMode::Static,
        }
    }
}

impl Default for OwnershipSpec {
    /// Host ids as-is: the mode that needs no configuration.
    fn default() -> Self {
        Self::Passthrough {}
    }
}

/// The default both squash ids take.
fn default_squash_id() -> u32 {
    DEFAULT_SQUASH_ID
}

/// One rule in source form.
///
/// `path` is a rule path (`/a/b`, or `/a/*` for the per-directory fallback),
/// `match` — where the rule states one — is a glob over the child names of
/// `path`, and `target` — where the mode takes one — is a host path, absolute
/// or relative to the state file's directory. All three are validated by the
/// rule engine's build boundary, not here.
///
/// A rule stating a `match` is a **pattern rule**: it is keyed by the pair
/// `(path, match)`, so one directory carries several, and it is mode-only —
/// carrying a target is a build error. A path component containing `*` remains
/// the literal name it always was; the match is a field, never a path spelling.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    /// The namespace path the rule is keyed by.
    pub path: String,
    /// The share mode the rule states.
    pub mode: ShareMode,
    /// The glob over `path`'s child names, for a pattern rule.
    #[serde(default, rename = "match", skip_serializing_if = "Option::is_none")]
    pub r#match: Option<String>,
    /// The host path to graft, for a rule that takes one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
}

impl Rule {
    /// A rule with neither a match nor a host target.
    #[must_use]
    pub fn new(path: impl Into<String>, mode: ShareMode) -> Self {
        Self {
            path: path.into(),
            mode,
            r#match: None,
            target: None,
        }
    }

    /// The same rule with an explicit host target.
    #[must_use]
    pub fn with_target(mut self, target: impl Into<String>) -> Self {
        self.target = Some(target.into());
        self
    }

    /// The same rule as a pattern over the child names of its path.
    #[must_use]
    pub fn with_match(mut self, matches: impl Into<String>) -> Self {
        self.r#match = Some(matches.into());
        self
    }

    /// Whether this rule keys the same rule as `path` and `matches` name.
    ///
    /// The identity of a rule is its path *and* its match: two pattern rules on
    /// one directory differ only in the match, so removal names both.
    #[must_use]
    pub fn keyed_by(&self, path: &str, matches: Option<&str>) -> bool {
        self.path == path && self.r#match.as_deref() == matches
    }

    /// What identifies this rule, as a person reads it and as `rule remove`
    /// takes it.
    #[must_use]
    pub fn key(&self) -> RuleKey<'_> {
        RuleKey::new(
            &self.path,
            self.r#match
                .as_ref()
                .map(|matches| matches as &dyn fmt::Display),
        )
    }
}

/// A rule's identity, spelled for a person: the path, and — where the rule is a
/// pattern — the match beside it.
///
/// This is the **one** spelling of that pair in the system. `voidport-ctl` lists
/// rules with it, the terminal interface keys and shows its rule rows with it,
/// and the daemon's own rule paths render through it, so what an operator reads
/// anywhere is the `path --match 'glob'` pair `rule remove` takes — one code
/// path, so the surfaces cannot drift into two dialects of the same key.
///
/// It borrows whatever spells the two halves ([`str`] on this side of the
/// protocol, parsed path and pattern types on the daemon's), because the pair is
/// a way of *writing* a key, not a second copy of one.
pub struct RuleKey<'a> {
    /// The rule path.
    path: &'a dyn fmt::Display,
    /// The glob over the path's children, for a pattern rule.
    matches: Option<&'a dyn fmt::Display>,
}

impl<'a> RuleKey<'a> {
    /// The key of `path`, with `matches` where the rule is a pattern.
    #[must_use]
    pub fn new(path: &'a dyn fmt::Display, matches: Option<&'a dyn fmt::Display>) -> Self {
        Self { path, matches }
    }
}

impl fmt::Display for RuleKey<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.matches {
            Some(matches) => write!(f, "{} --match '{matches}'", self.path),
            None => write!(f, "{}", self.path),
        }
    }
}

impl fmt::Debug for RuleKey<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

/// What a rule says about one way of touching an extended attribute.
///
/// A rule may state one verdict, both, or — for the axis it leaves out —
/// neither: an unstated verdict falls through to the next-most-specific rule
/// that does state it, and then to the defaults.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum XattrVerdict {
    /// The operation is attempted, and the host's own answer is passed back.
    Allow,
    /// The operation is refused by the namespace, before the host is touched.
    Deny,
}

impl fmt::Display for XattrVerdict {
    /// Honors width and alignment, so verdicts can be tabulated.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        })
    }
}

/// One extended-attribute rule in source form.
///
/// `match` is a glob over attribute *names* — its own syntax, never a path
/// spelling: `*` covers any run of bytes including none, a bare `*` is a legal
/// catch-all, and `/` is an ordinary literal byte because the kernel accepts one
/// in an attribute name. A rule is keyed by its match alone, so a second rule
/// with the same match is refused; changing a verdict is a remove followed by an
/// add, as everywhere else.
///
/// The match is validated by the engine's build boundary, not here.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XattrRule {
    /// The glob over attribute names this rule governs.
    #[serde(rename = "match")]
    pub r#match: String,
    /// What reading a covered attribute does; absent falls through.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read: Option<XattrVerdict>,
    /// What writing a covered attribute does; absent falls through.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub write: Option<XattrVerdict>,
}

impl XattrRule {
    /// A rule stating neither verdict, which every builder below adds to.
    #[must_use]
    pub fn new(matches: impl Into<String>) -> Self {
        Self {
            r#match: matches.into(),
            read: None,
            write: None,
        }
    }

    /// The same rule, stating what reads do.
    #[must_use]
    pub fn with_read(mut self, verdict: XattrVerdict) -> Self {
        self.read = Some(verdict);
        self
    }

    /// The same rule, stating what writes do.
    #[must_use]
    pub fn with_write(mut self, verdict: XattrVerdict) -> Self {
        self.write = Some(verdict);
        self
    }
}

/// One namespace in source form: its name and its whole policy.
///
/// This is both the state file's namespace entry and the payload the control
/// plane creates and shows, so the operator reads one schema.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamespaceSpec {
    /// The namespace name; unique across the server.
    pub name: NamespaceName,
    /// How host permission bits present.
    #[serde(default)]
    pub permission: PermissionMode,
    /// Where the server's backing I/O sits with respect to the host page
    /// cache.
    #[serde(default)]
    pub direct_io: HostDirectIo,
    /// How clients authenticate.
    #[serde(default)]
    pub auth: AuthMode,
    /// How host ownership maps into guest id space.
    #[serde(default)]
    pub ownership: OwnershipSpec,
    /// The rule table.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<Rule>,
    /// The extended-attribute rules. Per namespace, never a server global.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub xattr: Vec<XattrRule>,
}

impl NamespaceSpec {
    /// An empty namespace: no rules, default policy — a root that resolves
    /// nothing at all.
    #[must_use]
    pub fn new(name: NamespaceName) -> Self {
        Self {
            name,
            permission: PermissionMode::default(),
            direct_io: HostDirectIo::default(),
            auth: AuthMode::default(),
            ownership: OwnershipSpec::default(),
            rules: Vec::new(),
            xattr: Vec::new(),
        }
    }

    /// The extended-attribute rule with that match, if the namespace has one.
    #[must_use]
    pub fn xattr_rule(&self, matches: &str) -> Option<&XattrRule> {
        self.xattr.iter().find(|rule| rule.r#match == matches)
    }

    /// The first rule at `path`, if the namespace has one.
    ///
    /// A directory may carry several pattern rules at one path; use
    /// [`Rule::keyed_by`] where the match matters.
    #[must_use]
    pub fn rule(&self, path: &str) -> Option<&Rule> {
        self.rules.iter().find(|rule| rule.path == path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deserializes JSON in a test, panicking with the serde error on failure.
    fn parse<T: serde::de::DeserializeOwned>(json: &str) -> T {
        serde_json::from_str(json).expect("valid json for the target type")
    }

    /// Serializes to JSON in a test.
    fn json<T: Serialize>(value: &T) -> String {
        serde_json::to_string(value).expect("serializable")
    }

    #[test]
    fn namespace_names_are_validated() {
        assert_eq!(
            NamespaceName::new("project").expect("valid").as_str(),
            "project"
        );
        assert_eq!(NamespaceName::new(""), Err(NamespaceNameError::Empty));
        assert_eq!(
            NamespaceName::new("a/b"),
            Err(NamespaceNameError::Separator)
        );
        assert_eq!(
            NamespaceName::new("a\0b"),
            Err(NamespaceNameError::Control { character: '\0' })
        );
        assert_eq!(
            NamespaceName::new("a\nb"),
            Err(NamespaceNameError::Control { character: '\n' })
        );
        assert_eq!(
            NamespaceName::new("x".repeat(MAX_NAMESPACE_NAME_LEN + 1)),
            Err(NamespaceNameError::TooLong {
                len: MAX_NAMESPACE_NAME_LEN + 1
            })
        );
        assert!(NamespaceName::new("x".repeat(MAX_NAMESPACE_NAME_LEN)).is_ok());
    }

    #[test]
    fn namespace_names_validate_through_serde_too() {
        let name: NamespaceName = parse(r#""project""#);
        assert_eq!(name.as_str(), "project");
        assert_eq!(json(&name), r#""project""#);
        let rejected = serde_json::from_str::<NamespaceName>(r#""a/b""#).expect_err("separator");
        assert!(rejected.to_string().contains("separator"), "{rejected}");
    }

    #[test]
    fn host_ids_accept_numbers_and_sentinels_and_nothing_else() {
        assert_eq!(parse::<HostId>("1000"), HostId::Numeric(1000));
        assert_eq!(
            parse::<HostId>(r#""uid""#),
            HostId::Sentinel(IdSentinel::Uid)
        );
        assert_eq!(
            parse::<HostId>(r#""gid""#),
            HostId::Sentinel(IdSentinel::Gid)
        );
        assert!(serde_json::from_str::<HostId>(r#""root""#).is_err());
        assert!(serde_json::from_str::<HostId>("-1").is_err());
        assert!(serde_json::from_str::<HostId>("true").is_err());
        // Sentinels survive serialization unresolved.
        assert_eq!(json(&HostId::Sentinel(IdSentinel::Uid)), r#""uid""#);
    }

    #[test]
    fn ownership_shapes_are_per_mode() {
        let map: OwnershipSpec =
            parse(r#"{"mode":"map","uid_map":[{"host":"uid","guest":0}],"gid_map":[]}"#);
        assert_eq!(
            map,
            OwnershipSpec::Map {
                unmapped: UnmappedPolicy::Squash,
                squash_uid: DEFAULT_SQUASH_ID,
                squash_gid: DEFAULT_SQUASH_ID,
                uid_map: vec![IdMapping::new(IdSentinel::Uid, 0)],
                gid_map: Vec::new(),
            }
        );

        // A map without its tables, a static without its ids, and a
        // passthrough carrying another mode's field are all typed errors.
        assert!(serde_json::from_str::<OwnershipSpec>(r#"{"mode":"map"}"#).is_err());
        assert!(serde_json::from_str::<OwnershipSpec>(r#"{"mode":"static","uid":0}"#).is_err());
        assert!(
            serde_json::from_str::<OwnershipSpec>(r#"{"mode":"passthrough","uid":0}"#).is_err()
        );
        assert!(
            serde_json::from_str::<OwnershipSpec>(r#"{"mode":"static","uid":0,"gid":0,"x":1}"#)
                .is_err()
        );
        assert!(serde_json::from_str::<OwnershipSpec>(r#"{"mode":"Map"}"#).is_err());
        assert_eq!(
            OwnershipSpec::default(),
            parse::<OwnershipSpec>(r#"{"mode":"passthrough"}"#)
        );
    }

    /// The mode alone is spelled exactly as the policy it came from tags
    /// itself, on the wire and on an operator's screen alike: three names, one
    /// spelling each, and a summary that carries the mode says what the schema
    /// says.
    #[test]
    fn an_ownership_mode_is_spelled_the_way_the_policy_tags_itself() {
        let cases = [
            (
                OwnershipSpec::Map {
                    unmapped: UnmappedPolicy::Squash,
                    squash_uid: DEFAULT_SQUASH_ID,
                    squash_gid: DEFAULT_SQUASH_ID,
                    uid_map: Vec::new(),
                    gid_map: Vec::new(),
                },
                OwnershipMode::Map,
                "map",
            ),
            (
                OwnershipSpec::Passthrough {},
                OwnershipMode::Passthrough,
                "passthrough",
            ),
            (
                OwnershipSpec::Static { uid: 0, gid: 0 },
                OwnershipMode::Static,
                "static",
            ),
        ];
        for (spec, mode, name) in cases {
            assert_eq!(spec.mode(), mode);
            assert_eq!(json(&mode), format!(r#""{name}""#));
            assert_eq!(mode.to_string(), name);
            assert_eq!(parse::<OwnershipMode>(&format!(r#""{name}""#)), mode);
            // The tag the whole policy serializes under is the same name.
            assert!(
                json(&spec).starts_with(&format!(r#"{{"mode":"{name}""#)),
                "{spec:?}"
            );
        }
    }

    #[test]
    fn namespace_specs_deny_unknown_fields_and_default_their_policy() {
        let spec: NamespaceSpec = parse(r#"{"name":"project"}"#);
        assert_eq!(
            spec,
            NamespaceSpec::new(NamespaceName::new("project").expect("valid"))
        );
        assert_eq!(spec.ownership.mode(), OwnershipMode::Passthrough);
        assert_eq!(spec.permission, PermissionMode::Passthrough);
        assert_eq!(spec.direct_io, HostDirectIo::Cached);
        assert_eq!(spec.auth, AuthMode::None);
        assert!(spec.rules.is_empty());
        assert!(spec.rule("/a").is_none());

        let misspelled = serde_json::from_str::<NamespaceSpec>(
            r#"{"name":"project","permisson":"passthrough"}"#,
        )
        .expect_err("unknown field");
        assert!(misspelled.to_string().contains("permisson"), "{misspelled}");
    }

    #[test]
    fn rules_round_trip_with_and_without_a_target() {
        let targeted = Rule::new("/project", ShareMode::Rw).with_target("project");
        assert_eq!(
            json(&targeted),
            r#"{"path":"/project","mode":"rw","target":"project"}"#
        );
        let bare = Rule::new("/project/*", ShareMode::Hidden);
        assert_eq!(json(&bare), r#"{"path":"/project/*","mode":"hidden"}"#);
        assert_eq!(
            parse::<Rule>(r#"{"path":"/a","mode":"ro"}"#),
            Rule::new("/a", ShareMode::Ro)
        );
    }

    #[test]
    fn a_pattern_rule_carries_its_match_and_nothing_else_changes() {
        let pattern = Rule::new("/a", ShareMode::Rw).with_match("project-*");
        assert_eq!(
            json(&pattern),
            r#"{"path":"/a","mode":"rw","match":"project-*"}"#,
            "the field is spelled `match`, as the state file and the CLI do"
        );
        assert_eq!(
            parse::<Rule>(r#"{"path":"/a","mode":"rw","match":"project-*"}"#),
            pattern
        );
        // A rule without one is byte-identical to what it always was: the
        // field is skipped, so no deployed state file changes when re-emitted.
        assert_eq!(
            json(&Rule::new("/a", ShareMode::Ro)),
            r#"{"path":"/a","mode":"ro"}"#
        );

        // Identity is the pair, which is what `rule remove --match` needs.
        assert!(pattern.keyed_by("/a", Some("project-*")));
        assert!(!pattern.keyed_by("/a", Some("proj-*")));
        assert!(!pattern.keyed_by("/a", None));
        assert!(Rule::new("/a", ShareMode::Ro).keyed_by("/a", None));
    }

    #[test]
    fn an_xattr_rule_carries_a_match_and_the_verdicts_it_states() {
        let both = XattrRule::new("user.*")
            .with_read(XattrVerdict::Allow)
            .with_write(XattrVerdict::Deny);
        assert_eq!(
            json(&both),
            r#"{"match":"user.*","read":"allow","write":"deny"}"#
        );
        assert_eq!(
            parse::<XattrRule>(r#"{"match":"user.*","read":"allow","write":"deny"}"#),
            both
        );

        // An unstated verdict is absent from the wire, which is what makes
        // per-verdict fall-through a fact of the schema, not a default
        // written into it.
        let one = XattrRule::new("*").with_write(XattrVerdict::Deny);
        assert_eq!(json(&one), r#"{"match":"*","write":"deny"}"#);
        assert_eq!(one.read, None);
        assert_eq!(
            parse::<XattrRule>(r#"{"match":"security.*"}"#),
            XattrRule::new("security.*")
        );

        // A misspelled key or verdict is a typed error, never a silent default.
        assert!(serde_json::from_str::<XattrRule>(r#"{"match":"*","raed":"allow"}"#).is_err());
        assert!(serde_json::from_str::<XattrRule>(r#"{"match":"*","read":"maybe"}"#).is_err());
        assert!(serde_json::from_str::<XattrRule>(r#"{"read":"allow"}"#).is_err());
    }

    #[test]
    fn xattr_rules_live_on_the_namespace_and_stay_out_of_a_spec_that_has_none() {
        let spec: NamespaceSpec = parse(r#"{"name":"project"}"#);
        assert!(spec.xattr.is_empty());
        assert_eq!(
            json(&spec),
            r#"{"name":"project","permission":"passthrough","direct_io":"cached","auth":"none","ownership":{"mode":"passthrough"}}"#
        );
        assert!(spec.xattr_rule("user.*").is_none());

        let configured: NamespaceSpec =
            parse(r#"{"name":"p","xattr":[{"match":"user.*","write":"allow"}]}"#);
        assert_eq!(
            configured.xattr_rule("user.*").and_then(|rule| rule.write),
            Some(XattrVerdict::Allow)
        );
        assert_eq!(configured.xattr_rule("system.*"), None);
    }

    #[test]
    fn a_rule_key_reads_as_the_command_that_removes_it() {
        assert_eq!(
            Rule::new("/a", ShareMode::Rw)
                .with_match("project-*")
                .key()
                .to_string(),
            "/a --match 'project-*'"
        );
        // Without a match there is no second half to show: the key is the path.
        assert_eq!(Rule::new("/a/*", ShareMode::Ro).key().to_string(), "/a/*");
        // Two pattern rules on one directory are two keys, which is what makes
        // the pair usable as a list key.
        assert_ne!(
            Rule::new("/a", ShareMode::Ro)
                .with_match("docs-*")
                .key()
                .to_string(),
            Rule::new("/a", ShareMode::Ro).key().to_string()
        );
    }

    #[test]
    fn the_source_form_displays_readably() {
        assert_eq!(ShareMode::Hidden.to_string(), "hidden");
        assert_eq!(PermissionMode::Passthrough.to_string(), "passthrough");
        assert_eq!(HostDirectIo::Cached.to_string(), "cached");
        assert_eq!(HostDirectIo::Always.to_string(), "always");
        assert_eq!(AuthMode::None.to_string(), "none");
        assert_eq!(UnmappedPolicy::Hide.to_string(), "hide");
        assert_eq!(HostId::from(1000u32).to_string(), "1000");
        assert_eq!(HostId::from(IdSentinel::Gid).to_string(), "gid");
        assert_eq!(
            NamespaceName::new("project").expect("valid").to_string(),
            "project"
        );
    }

    #[test]
    fn every_mode_parses_back_from_the_name_it_displays() {
        // One variant each in v1; the loops are what a second one is added to.
        for mode in [PermissionMode::Passthrough].iter().copied() {
            assert_eq!(mode.to_string().parse(), Ok(mode));
        }
        for mode in [AuthMode::None].iter().copied() {
            assert_eq!(mode.to_string().parse(), Ok(mode));
        }
        for posture in [
            HostDirectIo::Cached,
            HostDirectIo::Passthrough,
            HostDirectIo::Always,
        ] {
            assert_eq!(posture.to_string().parse(), Ok(posture));
        }
        assert_eq!(
            "quantum"
                .parse::<HostDirectIo>()
                .expect_err("no such posture")
                .kind,
            "direct-io"
        );
        let refused = "quantum"
            .parse::<PermissionMode>()
            .expect_err("no such mode");
        assert_eq!(refused.kind, "permission");
        assert!(refused.to_string().contains("quantum"), "{refused}");
        assert_eq!(
            "quantum"
                .parse::<AuthMode>()
                .expect_err("no such mode")
                .kind,
            "auth"
        );
    }
}
