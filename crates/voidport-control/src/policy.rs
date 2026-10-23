//! The source form of namespace policy: exactly what the operator wrote. A
//! host id written as the sentinel `"uid"` stays the sentinel, and a host
//! target written relative to the state file stays relative, so persisting
//! re-emits the source and a mutation never freezes a sentinel into one
//! machine's uid. Every struct denies unknown fields, so a misspelled key
//! fails the load.

use std::fmt;

use serde::{Deserialize, Serialize};

/// The default squash target: the conventional `nobody`/`nogroup` id, used
/// numerically and never resolved through NSS. The rule engine has the same
/// constant, and a test in `voidportd` checks that the two agree.
pub const DEFAULT_SQUASH_ID: u32 = 65534;

pub const MAX_NAMESPACE_NAME_LEN: usize = 255;

/// Nonempty UTF-8, at most [`MAX_NAMESPACE_NAME_LEN`] bytes, and free of `/`,
/// NUL and control characters, which could be mistaken for a path separator or
/// truncate a C string in a mount URL or the registry.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct NamespaceName(String);

impl NamespaceName {
    /// # Errors
    ///
    /// [`NamespaceNameError`] for an empty or too long name, or one that
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
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(&self.0)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum NamespaceNameError {
    #[error("a namespace name must not be empty")]
    Empty,
    #[error("a namespace name must be at most {MAX_NAMESPACE_NAME_LEN} bytes, got {len}")]
    TooLong { len: usize },
    #[error("a namespace name must not contain a `/` separator")]
    Separator,
    #[error("a namespace name must not contain the control character {character:?}")]
    Control { character: char },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ShareMode {
    Rw,
    Ro,
    /// Hidden: the entry does not resolve, stat or list.
    Hidden,
}

impl fmt::Display for ShareMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(match self {
            Self::Rw => "rw",
            Self::Ro => "ro",
            Self::Hidden => "hidden",
        })
    }
}

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
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad("passthrough")
    }
}

impl std::str::FromStr for PermissionMode {
    type Err = UnknownMode;

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

/// By default backing I/O goes through the host page cache. This setting is the
/// only thing that puts `O_DIRECT` on a backing description.
///
/// Uncached backing I/O needs buffers aligned to what the backing file asks
/// for, so the server serves through such buffers under
/// [`Passthrough`](Self::Passthrough) and [`Always`](Self::Always). A request
/// that the backing filesystem calls misaligned is answered with the errno it
/// gives locally.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum HostDirectIo {
    #[default]
    Cached,
    Passthrough,
    Always,
}

impl fmt::Display for HostDirectIo {
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

#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum AuthMode {
    #[default]
    None,
}

impl fmt::Display for AuthMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad("none")
    }
}

impl std::str::FromStr for AuthMode {
    type Err = UnknownMode;

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

/// Parsing through [`FromStr`](std::str::FromStr) makes the value an operator
/// surface shows and the value it sends the same, once a second variant is
/// added.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{value:?} is not a {kind} mode this version defines")]
pub struct UnknownMode {
    pub kind: &'static str,
    pub value: String,
}

#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum UnmappedPolicy {
    #[default]
    Squash,
    /// Hide the file entirely, triggered by either component being unmapped.
    Hide,
    Passthrough,
}

impl fmt::Display for UnmappedPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(match self {
            Self::Squash => "squash",
            Self::Hide => "hide",
            Self::Passthrough => "passthrough",
        })
    }
}

/// The stand-in for an id of the invoking user, unresolved in the source form
/// so a configuration stays portable between users.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IdSentinel {
    Uid,
    Gid,
}

impl fmt::Display for IdSentinel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(match self {
            Self::Uid => "uid",
            Self::Gid => "gid",
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum HostId {
    /// `"uid"` or `"gid"`, resolved against the invoking identity at build
    /// time and never written back resolved.
    Sentinel(IdSentinel),
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
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sentinel(sentinel) => sentinel.fmt(f),
            Self::Numeric(id) => id.fmt(f),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdMapping {
    pub host: HostId,
    pub guest: u32,
}

impl IdMapping {
    #[must_use]
    pub fn new(host: impl Into<HostId>, guest: u32) -> Self {
        Self {
            host: host.into(),
            guest,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OwnershipMode {
    Map,
    Passthrough,
    Static,
}

impl fmt::Display for OwnershipMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(match self {
            Self::Map => "map",
            Self::Passthrough => "passthrough",
            Self::Static => "static",
        })
    }
}

/// `map` requires its tables, `static` requires its ids, and a field of another
/// mode is rejected.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "lowercase", deny_unknown_fields)]
pub enum OwnershipSpec {
    Map {
        #[serde(default)]
        unmapped: UnmappedPolicy,
        #[serde(default = "default_squash_id")]
        squash_uid: u32,
        #[serde(default = "default_squash_id")]
        squash_gid: u32,
        uid_map: Vec<IdMapping>,
        gid_map: Vec<IdMapping>,
    },
    Passthrough {},
    Static {
        uid: u32,
        gid: u32,
    },
}

impl OwnershipSpec {
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
    fn default() -> Self {
        Self::Passthrough {}
    }
}

fn default_squash_id() -> u32 {
    DEFAULT_SQUASH_ID
}

fn enabled() -> bool {
    true
}

/// `path` is a rule path (`/a/b`, or `/a/*` for the per-directory fallback),
/// `match` is a glob over the child names of `path`, and `target` is a host
/// path, absolute or relative to the directory of the state file. The rule
/// engine validates all three when it builds.
///
/// A rule with a `match` is a pattern rule keyed by `(path, match)`, and takes
/// no target. A path component containing `*` stays the literal name.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub path: String,
    pub mode: ShareMode,
    #[serde(default, rename = "match", skip_serializing_if = "Option::is_none")]
    pub r#match: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
}

impl Rule {
    #[must_use]
    pub fn new(path: impl Into<String>, mode: ShareMode) -> Self {
        Self {
            path: path.into(),
            mode,
            r#match: None,
            target: None,
        }
    }

    #[must_use]
    pub fn with_target(mut self, target: impl Into<String>) -> Self {
        self.target = Some(target.into());
        self
    }

    #[must_use]
    pub fn with_match(mut self, matches: impl Into<String>) -> Self {
        self.r#match = Some(matches.into());
        self
    }

    #[must_use]
    pub fn keyed_by(&self, path: &str, matches: Option<&str>) -> bool {
        self.path == path && self.r#match.as_deref() == matches
    }

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

/// The one spelling of the pair of path and match, used by `voidport-ctl`, the
/// terminal interface and the daemon: the `path --match 'glob'` form that
/// `rule remove` takes. It borrows whatever spells the two halves.
pub struct RuleKey<'a> {
    path: &'a dyn fmt::Display,
    matches: Option<&'a dyn fmt::Display>,
}

impl<'a> RuleKey<'a> {
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

/// A rule may set one verdict, both, or neither: an unstated verdict falls
/// through to the next-most-specific rule that sets it, and then to the
/// defaults.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum XattrVerdict {
    Allow,
    Deny,
}

impl fmt::Display for XattrVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        })
    }
}

/// `match` is a glob over attribute names: `*` covers any run of bytes
/// including none, and `/` is an ordinary byte. A rule is keyed by its match
/// alone, so a second rule with the same match is refused. The engine validates
/// the match when it builds.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XattrRule {
    #[serde(rename = "match")]
    pub r#match: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read: Option<XattrVerdict>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub write: Option<XattrVerdict>,
}

impl XattrRule {
    #[must_use]
    pub fn new(matches: impl Into<String>) -> Self {
        Self {
            r#match: matches.into(),
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamespaceSpec {
    pub name: NamespaceName,
    #[serde(default)]
    pub permission: PermissionMode,
    #[serde(default)]
    pub direct_io: HostDirectIo,
    #[serde(default)]
    pub auth: AuthMode,
    #[serde(default)]
    pub ownership: OwnershipSpec,
    /// Enabled by default. Disabled, presentation masks the bits, recorded and
    /// host-real alike, and a chmod attempting to set them is refused.
    /// Enforcement of what the bits mean is the guest kernel's.
    #[serde(default = "enabled")]
    pub privileged_bits: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<Rule>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub xattr: Vec<XattrRule>,
}

impl NamespaceSpec {
    #[must_use]
    pub fn new(name: NamespaceName) -> Self {
        Self {
            name,
            permission: PermissionMode::default(),
            direct_io: HostDirectIo::default(),
            auth: AuthMode::default(),
            ownership: OwnershipSpec::default(),
            privileged_bits: enabled(),
            rules: Vec::new(),
            xattr: Vec::new(),
        }
    }

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

    fn parse<T: serde::de::DeserializeOwned>(json: &str) -> T {
        serde_json::from_str(json).expect("valid json for the target type")
    }

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
        assert!(
            spec.privileged_bits,
            "a namespace that says nothing records and presents privileged bits"
        );
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
        // The field is skipped without a match, so a re-emitted state file is
        // unchanged.
        assert_eq!(
            json(&Rule::new("/a", ShareMode::Ro)),
            r#"{"path":"/a","mode":"ro"}"#
        );

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

        // An unstated verdict is absent from the wire.
        let one = XattrRule::new("*").with_write(XattrVerdict::Deny);
        assert_eq!(json(&one), r#"{"match":"*","write":"deny"}"#);
        assert_eq!(one.read, None);
        assert_eq!(
            parse::<XattrRule>(r#"{"match":"security.*"}"#),
            XattrRule::new("security.*")
        );

        assert!(serde_json::from_str::<XattrRule>(r#"{"match":"*","raed":"allow"}"#).is_err());
        assert!(serde_json::from_str::<XattrRule>(r#"{"match":"*","read":"maybe"}"#).is_err());
        assert!(serde_json::from_str::<XattrRule>(r#"{"read":"allow"}"#).is_err());
    }

    fn xattr_rule<'a>(spec: &'a NamespaceSpec, matches: &str) -> Option<&'a XattrRule> {
        spec.xattr.iter().find(|rule| rule.r#match == matches)
    }

    #[test]
    fn xattr_rules_live_on_the_namespace_and_stay_out_of_a_spec_that_has_none() {
        let spec: NamespaceSpec = parse(r#"{"name":"project"}"#);
        assert!(spec.xattr.is_empty());
        assert_eq!(
            json(&spec),
            r#"{"name":"project","permission":"passthrough","direct_io":"cached","auth":"none","ownership":{"mode":"passthrough"},"privileged_bits":true}"#
        );
        assert!(xattr_rule(&spec, "user.*").is_none());

        let configured: NamespaceSpec =
            parse(r#"{"name":"p","xattr":[{"match":"user.*","write":"allow"}]}"#);
        assert_eq!(
            xattr_rule(&configured, "user.*").and_then(|rule| rule.write),
            Some(XattrVerdict::Allow)
        );
        assert_eq!(xattr_rule(&configured, "system.*"), None);
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
        assert_eq!(Rule::new("/a/*", ShareMode::Ro).key().to_string(), "/a/*");
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
