use std::path::Path;

use voidport_control::{
    HostId, IdSentinel, NamespaceSpec, OwnershipSpec, Rule, ShareMode, UnmappedPolicy, XattrRule,
    XattrVerdict,
};

use super::Environment;
use crate::host::{GraftError, Grafts};
use crate::namespace::{Namespace, PolicyModes};
use crate::rules::{
    self, HostTarget, IdMap, IdMapError, IdMapping, Ownership, OwnershipError, OwnershipMode,
    RuleSpec, RuleTable, ServerIdentity, SquashIds, TableError, XattrRules, XattrRulesError,
    XattrSpec,
};

/// # Errors
///
/// Returns a [`NamespaceError`] naming the offending rule or id table. The
/// loader adds the namespace name.
pub fn build_namespace(
    spec: &NamespaceSpec,
    environment: &Environment,
) -> Result<Namespace, NamespaceError> {
    let ownership = build_ownership(&spec.ownership, environment)?;
    let rules = build_rules(&spec.rules, environment)?;
    let xattr = build_xattr_rules(&spec.xattr)?;
    let grafts = Grafts::pin(&rules).map_err(NamespaceError::Graft)?;
    Ok(Namespace::new(
        spec.name.clone(),
        PolicyModes {
            permission: spec.permission,
            direct_io: spec.direct_io,
            auth: spec.auth,
        },
        ownership,
        rules,
        xattr,
        spec.privileged_bits,
        grafts,
    ))
}

/// # Errors
///
/// Returns [`NamespaceError::XattrRules`] naming the offending rule.
pub fn build_xattr_rules(rules: &[XattrRule]) -> Result<XattrRules, NamespaceError> {
    XattrRules::build(rules.iter().map(|rule| XattrSpec {
        matches: rule.r#match.clone(),
        read: rule.read.map(verdict),
        write: rule.write.map(verdict),
    }))
    .map_err(NamespaceError::XattrRules)
}

fn verdict(verdict: XattrVerdict) -> rules::XattrVerdict {
    match verdict {
        XattrVerdict::Allow => rules::XattrVerdict::Allow,
        XattrVerdict::Deny => rules::XattrVerdict::Deny,
    }
}

/// # Errors
///
/// Returns [`NamespaceError::IdMap`] for a non-injective table and
/// [`NamespaceError::Ownership`] for a mapped guest id colliding with the
/// squash id.
pub fn build_ownership(
    spec: &OwnershipSpec,
    environment: &Environment,
) -> Result<Ownership, NamespaceError> {
    let (mode, squash) = match spec {
        OwnershipSpec::Passthrough {} => (OwnershipMode::Passthrough, SquashIds::default()),
        OwnershipSpec::Static { uid, gid } => (
            OwnershipMode::Static {
                uid: *uid,
                gid: *gid,
            },
            SquashIds::default(),
        ),
        OwnershipSpec::Map {
            unmapped,
            squash_uid,
            squash_gid,
            uid_map,
            gid_map,
        } => (
            OwnershipMode::Map {
                uid: build_id_map(uid_map, IdTable::Uid, environment)?,
                gid: build_id_map(gid_map, IdTable::Gid, environment)?,
                unmapped: match unmapped {
                    UnmappedPolicy::Squash => rules::UnmappedPolicy::Squash,
                    UnmappedPolicy::Hide => rules::UnmappedPolicy::Hide,
                    UnmappedPolicy::Passthrough => rules::UnmappedPolicy::Passthrough,
                },
            },
            SquashIds::new(*squash_uid, *squash_gid),
        ),
    };
    let identity = ServerIdentity::new(environment.uid, environment.gid);
    Ownership::new(mode, identity, squash).map_err(NamespaceError::Ownership)
}

/// # Errors
///
/// Returns [`NamespaceError::Rules`] for anything the build of the engine
/// rejects, and [`NamespaceError::NonUtf8Target`] if joining a relative target
/// onto the state directory produces a path the rule table cannot hold.
pub fn build_rules(rules: &[Rule], environment: &Environment) -> Result<RuleTable, NamespaceError> {
    let specs = rules
        .iter()
        .map(|rule| {
            let target = rule
                .target
                .as_deref()
                .map(|target| resolve_target(target, environment))
                .transpose()?;
            Ok(RuleSpec {
                path: rule.path.clone(),
                mode: share_mode(rule.mode),
                matches: rule.r#match.clone(),
                target,
            })
        })
        .collect::<Result<Vec<_>, NamespaceError>>()?;
    RuleTable::build(specs).map_err(NamespaceError::Rules)
}

fn share_mode(mode: ShareMode) -> rules::ShareMode {
    match mode {
        ShareMode::Rw => rules::ShareMode::Rw,
        ShareMode::Ro => rules::ShareMode::Ro,
        ShareMode::Hidden => rules::ShareMode::Hidden,
    }
}

/// An absolute target is taken as written, and a relative one is joined onto
/// the state directory once, at build time.
fn resolve_target(target: &str, environment: &Environment) -> Result<HostTarget, NamespaceError> {
    if Path::new(target).is_absolute() {
        return Ok(HostTarget::new(target));
    }
    let joined = environment.state_dir.join(target);
    joined
        .into_os_string()
        .into_string()
        .map(HostTarget::new)
        .map_err(|joined| NamespaceError::NonUtf8Target {
            target: target.to_owned(),
            state_dir: joined.to_string_lossy().into_owned(),
        })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IdTable {
    Uid,
    Gid,
}

impl IdTable {
    fn as_str(self) -> &'static str {
        match self {
            Self::Uid => "uid_map",
            Self::Gid => "gid_map",
        }
    }
}

fn build_id_map(
    mappings: &[voidport_control::IdMapping],
    table: IdTable,
    environment: &Environment,
) -> Result<IdMap, NamespaceError> {
    let resolved = mappings.iter().map(|mapping| {
        let host = match mapping.host {
            HostId::Numeric(id) => id,
            HostId::Sentinel(IdSentinel::Uid) => environment.uid,
            HostId::Sentinel(IdSentinel::Gid) => environment.gid,
        };
        IdMapping::new(host, mapping.guest)
    });
    IdMap::new(resolved).map_err(|source| NamespaceError::IdMap {
        table: table.as_str(),
        source,
    })
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum NamespaceError {
    #[error("rule table: {0}")]
    Rules(#[source] TableError),
    #[error("{0}")]
    XattrRules(#[source] XattrRulesError),
    #[error("ownership {table}: {source}")]
    IdMap {
        table: &'static str,
        #[source]
        source: IdMapError,
    },
    #[error("ownership: {0}")]
    Ownership(#[source] OwnershipError),
    #[error("{0}")]
    Graft(#[source] GraftError),
    #[error("host target {target:?} resolves to the non-UTF-8 path {state_dir:?}")]
    NonUtf8Target { target: String, state_dir: String },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{EffectiveMode, GuestIds, HostIds, NamespacePath, OwnerPresentation};
    use voidport_control::{IdMapping as SpecMapping, NamespaceName};
    use voidport_test_host::Scratch;

    fn environment() -> Environment {
        Environment::new(1000, 100, "/srv/state")
    }

    fn rooted(scratch: &Scratch) -> Environment {
        Environment::new(1000, 100, scratch.path())
    }

    fn spec(rules: Vec<Rule>, ownership: OwnershipSpec) -> NamespaceSpec {
        NamespaceSpec {
            name: NamespaceName::new("project").expect("valid namespace name"),
            ownership,
            rules,
            ..NamespaceSpec::new(NamespaceName::new("project").expect("valid namespace name"))
        }
    }

    #[test]
    fn xattr_rules_build_and_their_refusals_name_the_rule() {
        let namespace = build_namespace(
            &NamespaceSpec {
                xattr: vec![
                    XattrRule::new("user.*").with_write(XattrVerdict::Deny),
                    XattrRule::new("user.selinux").with_write(XattrVerdict::Allow),
                ],
                ..spec(Vec::new(), OwnershipSpec::default())
            },
            &environment(),
        )
        .expect("valid namespace");
        assert!(namespace.xattr().writable(b"user.selinux"));
        assert!(!namespace.xattr().writable(b"user.other"));
        assert!(
            build_namespace(&spec(Vec::new(), OwnershipSpec::default()), &environment())
                .expect("valid namespace")
                .xattr()
                .is_empty()
        );

        let duplicate = build_namespace(
            &NamespaceSpec {
                xattr: vec![
                    XattrRule::new("user.*").with_read(XattrVerdict::Allow),
                    XattrRule::new("user.*").with_write(XattrVerdict::Deny),
                ],
                ..spec(Vec::new(), OwnershipSpec::default())
            },
            &environment(),
        )
        .expect_err("a rule is keyed by its match");
        assert!(
            matches!(
                duplicate,
                NamespaceError::XattrRules(XattrRulesError::DuplicateMatch { .. })
            ),
            "{duplicate}"
        );
        assert!(duplicate.to_string().contains("user.*"), "{duplicate}");

        let long = format!("user.{}id", "*".repeat(256));
        let namespace = build_namespace(
            &NamespaceSpec {
                xattr: vec![XattrRule::new(long).with_read(XattrVerdict::Deny)],
                ..spec(Vec::new(), OwnershipSpec::default())
            },
            &environment(),
        )
        .expect("a long glob is valid");
        assert!(!namespace.xattr().readable(b"user.id"));
        assert!(namespace.xattr().readable(b"user.other"));
    }

    #[test]
    fn relative_targets_resolve_against_the_state_directory() {
        let scratch = Scratch::new("build");
        let relative = scratch.directory("project");
        let absolute_target = scratch.directory("elsewhere");
        let namespace = build_namespace(
            &spec(
                vec![
                    Rule::new("/project", ShareMode::Rw).with_target("project"),
                    Rule::new("/elsewhere", ShareMode::Ro).with_target(absolute_target.as_str()),
                ],
                OwnershipSpec::default(),
            ),
            &rooted(&scratch),
        )
        .expect("valid namespace");

        let path = NamespacePath::parse("/project").expect("valid path");
        let backing = namespace
            .rules()
            .literal(&path)
            .and_then(|rule| rule.backing.as_ref())
            .expect("admitting rule is backed");
        assert_eq!(backing.graft().as_str(), relative);

        let absolute = NamespacePath::parse("/elsewhere").expect("valid path");
        let backing = namespace
            .rules()
            .literal(&absolute)
            .and_then(|rule| rule.backing.as_ref())
            .expect("admitting rule is backed");
        assert_eq!(backing.graft().as_str(), absolute_target);

        assert_eq!(namespace.grafts().len(), 2);
    }

    #[test]
    fn a_graft_target_that_cannot_be_opened_refuses_the_build() {
        let error = build_namespace(
            &spec(
                vec![Rule::new("/a", ShareMode::Rw).with_target("/nonexistent/voidport/graft")],
                OwnershipSpec::default(),
            ),
            &environment(),
        )
        .expect_err("the target is not there");
        assert!(matches!(error, NamespaceError::Graft(_)), "{error}");
        assert!(
            error.to_string().contains("/nonexistent/voidport/graft"),
            "{error}"
        );
    }

    #[test]
    fn id_sentinels_resolve_against_the_injected_identity() {
        let namespace = build_namespace(
            &spec(
                Vec::new(),
                OwnershipSpec::Map {
                    unmapped: UnmappedPolicy::Squash,
                    squash_uid: voidport_control::DEFAULT_SQUASH_ID,
                    squash_gid: voidport_control::DEFAULT_SQUASH_ID,
                    uid_map: vec![SpecMapping::new(IdSentinel::Uid, 0)],
                    gid_map: vec![SpecMapping::new(IdSentinel::Gid, 0)],
                },
            ),
            &environment(),
        )
        .expect("valid namespace");
        assert_eq!(
            namespace.ownership().forward(HostIds::new(1000, 100)),
            OwnerPresentation::Visible(GuestIds::new(0, 0))
        );
        assert_eq!(
            namespace
                .ownership()
                .reverse_for_create(GuestIds::new(0, 0)),
            HostIds::new(1000, 100)
        );
    }

    #[test]
    fn numeric_host_ids_are_taken_as_written() {
        let namespace = build_namespace(
            &spec(
                Vec::new(),
                OwnershipSpec::Map {
                    unmapped: UnmappedPolicy::Hide,
                    squash_uid: 7,
                    squash_gid: 8,
                    uid_map: vec![SpecMapping::new(4242u32, 0)],
                    gid_map: vec![SpecMapping::new(4243u32, 0)],
                },
            ),
            &environment(),
        )
        .expect("valid namespace");
        assert_eq!(
            namespace.ownership().forward(HostIds::new(4242, 4243)),
            OwnerPresentation::Visible(GuestIds::new(0, 0))
        );
        assert_eq!(namespace.ownership().squash(), SquashIds::new(7, 8));
    }

    #[test]
    fn every_ownership_mode_builds() {
        for ownership in [
            OwnershipSpec::Passthrough {},
            OwnershipSpec::Static { uid: 1, gid: 2 },
            OwnershipSpec::Map {
                unmapped: UnmappedPolicy::Passthrough,
                squash_uid: voidport_control::DEFAULT_SQUASH_ID,
                squash_gid: voidport_control::DEFAULT_SQUASH_ID,
                uid_map: Vec::new(),
                gid_map: Vec::new(),
            },
        ] {
            let namespace = build_namespace(&spec(Vec::new(), ownership.clone()), &environment())
                .expect("valid namespace");
            assert_eq!(namespace.name().as_str(), "project");
            assert_eq!(
                namespace.permission(),
                voidport_control::PermissionMode::Passthrough
            );
            assert_eq!(namespace.auth(), voidport_control::AuthMode::None);
        }
    }

    #[test]
    fn share_modes_survive_the_translation() {
        let scratch = Scratch::new("build");
        let target = scratch.directory("a");
        let namespace = build_namespace(
            &spec(
                vec![
                    Rule::new("/a", ShareMode::Rw).with_target(target.as_str()),
                    Rule::new("/a/ro", ShareMode::Ro),
                    Rule::new("/a/secret", ShareMode::Hidden),
                    Rule::new("/a/*", ShareMode::Ro),
                ],
                OwnershipSpec::default(),
            ),
            &rooted(&scratch),
        )
        .expect("valid namespace");
        let table = namespace.rules();
        let path = |raw: &str| NamespacePath::parse(raw).expect("valid path");
        assert_eq!(
            table.literal(&path("/a")).map(|rule| rule.mode),
            Some(rules::ShareMode::Rw)
        );
        assert_eq!(
            table.literal(&path("/a/ro")).map(|rule| rule.mode),
            Some(rules::ShareMode::Ro)
        );
        assert_eq!(
            table.literal(&path("/a/secret")).map(|rule| rule.mode),
            Some(rules::ShareMode::Hidden)
        );
        assert_eq!(table.wildcard(&path("/a")), Some(rules::ShareMode::Ro));
        assert_eq!(
            table
                .literal(&path("/a/ro"))
                .and_then(|rule| rule.mode.effective()),
            Some(EffectiveMode::Ro)
        );
    }

    #[test]
    fn engine_rejections_surface_as_typed_errors() {
        let dead = build_namespace(
            &spec(
                vec![
                    Rule::new("/a", ShareMode::Rw).with_target("/srv/a"),
                    Rule::new("/a/secret", ShareMode::Hidden),
                    Rule::new("/a/secret/key", ShareMode::Ro),
                ],
                OwnershipSpec::default(),
            ),
            &environment(),
        )
        .expect_err("dead configuration");
        assert!(matches!(
            dead,
            NamespaceError::Rules(TableError::Unreachable { .. })
        ));
        assert!(
            dead.to_string().contains("/a/secret/key"),
            "the error must name the offending rule: {dead}"
        );

        let collision = build_namespace(
            &spec(
                Vec::new(),
                OwnershipSpec::Map {
                    unmapped: UnmappedPolicy::Squash,
                    squash_uid: voidport_control::DEFAULT_SQUASH_ID,
                    squash_gid: voidport_control::DEFAULT_SQUASH_ID,
                    uid_map: vec![SpecMapping::new(1000u32, 0), SpecMapping::new(1001u32, 0)],
                    gid_map: Vec::new(),
                },
            ),
            &environment(),
        )
        .expect_err("non-injective table");
        assert!(
            matches!(
                collision,
                NamespaceError::IdMap {
                    table: "uid_map",
                    source: IdMapError::DuplicateGuestId { id: 0 },
                }
            ),
            "{collision}"
        );
        assert!(collision.to_string().contains("uid_map"), "{collision}");

        let squash_collision = build_namespace(
            &spec(
                Vec::new(),
                OwnershipSpec::Map {
                    unmapped: UnmappedPolicy::Squash,
                    squash_uid: 0,
                    squash_gid: voidport_control::DEFAULT_SQUASH_ID,
                    uid_map: vec![SpecMapping::new(1000u32, 0)],
                    gid_map: Vec::new(),
                },
            ),
            &environment(),
        )
        .expect_err("a mapped guest id must not equal the squash id");
        assert!(
            matches!(
                squash_collision,
                NamespaceError::Ownership(OwnershipError::GuestUidEqualsSquash { id: 0 })
            ),
            "{squash_collision}"
        );
    }
}
