//! The seed is applied to a document additively: a piece that is already there
//! with exactly the seeded content is left alone, so a relaunch changes
//! nothing, and a namespace or rule of the same name or path with different
//! content is refused. Nothing in the file is overwritten.
//!
//! The directory is shared at its absolute host path, so shares of two host
//! paths compose into their host hierarchy instead of colliding on a name.
//!
//! A document that already names a control socket is not a collision: its value
//! wins and nothing is seeded.

pub mod shared_path;

use std::path::{Path, PathBuf};

use voidport_control::{NamespaceName, NamespaceSpec, OwnershipSpec, Rule, ShareMode};

use crate::rules::{PathError, RulePath};
use crate::state::{Listener, StateDocument};

pub const DEFAULT_NAMESPACE: &str = "share";

/// The directory must be absolute and spell a literal rule path, and at least
/// one listener is needed, because there is no default bind.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Seed {
    directory: PathBuf,
    path: String,
    namespace: NamespaceName,
    mode: ShareMode,
    listeners: Vec<Listener>,
}

impl Seed {
    /// # Errors
    ///
    /// Returns a [`SeedError`] if the directory cannot be a rule path as written
    /// or no listener would serve it.
    pub fn new(
        directory: impl Into<PathBuf>,
        namespace: NamespaceName,
        mode: ShareMode,
        listeners: Vec<Listener>,
    ) -> Result<Self, SeedError> {
        let directory = directory.into();
        if !directory.is_absolute() {
            return Err(SeedError::RelativeDirectory { path: directory });
        }
        let path = shared_rule_path(&directory)?;
        if listeners.is_empty() {
            return Err(SeedError::NoListener);
        }
        Ok(Self {
            directory,
            path,
            namespace,
            mode,
            listeners,
        })
    }

    #[must_use]
    pub fn directory(&self) -> &Path {
        &self.directory
    }

    #[must_use]
    pub fn namespace(&self) -> &NamespaceName {
        &self.namespace
    }

    #[must_use]
    pub fn listeners(&self) -> &[Listener] {
        &self.listeners
    }

    #[must_use]
    pub fn rule_path(&self) -> &str {
        &self.path
    }

    #[must_use]
    pub fn rule(&self) -> Rule {
        Rule::new(self.rule_path(), self.mode).with_target(self.directory.display().to_string())
    }

    #[must_use]
    pub fn namespace_spec(&self) -> NamespaceSpec {
        let mut spec = NamespaceSpec::new(self.namespace.clone());
        spec.rules.push(self.rule());
        spec
    }

    /// `control_socket` is the socket path this launch would seed, or `None` when
    /// the command line named one. `Ok(false)` means every piece was already
    /// there, so there is nothing to persist.
    ///
    /// # Errors
    ///
    /// Returns [`SeedError::NamespaceConflict`] or [`SeedError::RuleConflict`]
    /// naming the collision. The document is left unchanged on either.
    pub fn apply(
        &self,
        document: &mut StateDocument,
        control_socket: Option<&Path>,
    ) -> Result<bool, SeedError> {
        let seeded = self.namespace_spec();
        if let Some(existing) = document.namespace(&self.namespace) {
            self.check_policy(existing)?;
            self.check_rule(existing)?;
        }

        let mut changed = false;
        // A document that already names a socket is left as it is, which is not a
        // collision.
        if let Some(path) = control_socket
            && document.server.control_socket.is_none()
        {
            document.server.control_socket = Some(path.to_path_buf());
            changed = true;
        }
        for listener in &self.listeners {
            if !document.server.listeners.contains(listener) {
                document.server.listeners.push(listener.clone());
                changed = true;
            }
        }
        match document.namespace_mut(&self.namespace) {
            Some(existing) => {
                // A pattern rule on the seeded directory coexists with this rule, so
                // ask by path and no match.
                if !existing
                    .rules
                    .iter()
                    .any(|rule| rule.keyed_by(self.rule_path(), None))
                {
                    existing.rules.push(self.rule());
                    changed = true;
                }
            }
            None => {
                document.namespaces.push(seeded);
                changed = true;
            }
        }
        Ok(changed)
    }

    fn check_policy(&self, existing: &NamespaceSpec) -> Result<(), SeedError> {
        let seeded = NamespaceSpec::new(self.namespace.clone());
        let mismatch = if existing.permission != seeded.permission {
            Some((
                "permission mode",
                existing.permission.to_string(),
                seeded.permission.to_string(),
            ))
        } else if existing.direct_io != seeded.direct_io {
            Some((
                "direct-io posture",
                existing.direct_io.to_string(),
                seeded.direct_io.to_string(),
            ))
        } else if existing.auth != seeded.auth {
            Some((
                "auth mode",
                existing.auth.to_string(),
                seeded.auth.to_string(),
            ))
        } else if existing.ownership != seeded.ownership {
            Some((
                "ownership mode",
                existing.ownership.mode().to_string(),
                OwnershipSpec::default().mode().to_string(),
            ))
        } else {
            None
        };
        match mismatch {
            None => Ok(()),
            Some((field, found, wanted)) => Err(SeedError::NamespaceConflict {
                namespace: self.namespace.clone(),
                field,
                found,
                seeded: wanted,
            }),
        }
    }

    /// A pattern rule on the same directory is a different rule, not a collision.
    fn check_rule(&self, existing: &NamespaceSpec) -> Result<(), SeedError> {
        let path = self.rule_path();
        let Some(rule) = existing.rules.iter().find(|rule| rule.keyed_by(path, None)) else {
            return Ok(());
        };
        let seeded = self.rule();
        if *rule == seeded {
            return Ok(());
        }
        Err(SeedError::RuleConflict {
            namespace: self.namespace.clone(),
            path: path.to_owned(),
            found: describe(rule),
            seeded: describe(&seeded),
        })
    }
}

/// Refuses here what the engine would refuse to parse, and a final component
/// `*`, which parses as the wildcard rule for the directory above.
fn shared_rule_path(directory: &Path) -> Result<String, SeedError> {
    let Some(text) = directory.to_str() else {
        return Err(SeedError::NonUnicodeDirectory {
            path: directory.to_path_buf(),
        });
    };
    match RulePath::parse(text) {
        Ok(RulePath::Literal(_)) => Ok(text.to_owned()),
        Ok(RulePath::Wildcard(_) | RulePath::Pattern(_)) => Err(SeedError::WildcardDirectory {
            path: directory.to_path_buf(),
        }),
        Err(source) => Err(SeedError::UnshareableDirectory {
            path: directory.to_path_buf(),
            source,
        }),
    }
}

fn describe(rule: &Rule) -> String {
    match &rule.target {
        Some(target) => format!("mode = \"{}\", target = {target:?}", rule.mode),
        None => format!("mode = \"{}\"", rule.mode),
    }
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SeedError {
    #[error("cannot share {path}: the directory must be an absolute path")]
    RelativeDirectory { path: PathBuf },
    #[error("cannot share {path}: its path is not valid UTF-8, and a rule path is text")]
    NonUnicodeDirectory { path: PathBuf },
    #[error(
        "cannot share {path}: a rule path ending in `*` is the wildcard rule for the \
         directory above it, so this directory cannot be shared at its own path"
    )]
    WildcardDirectory { path: PathBuf },
    #[error("cannot share {path}: it cannot be a namespace path ({source})")]
    UnshareableDirectory {
        path: PathBuf,
        #[source]
        source: PathError,
    },
    #[error(
        "share needs at least one listener: pass --addr HOST:PORT, --unix PATH \
         and/or --vsock PORT (there is no default bind)"
    )]
    NoListener,
    #[error(
        "namespace {namespace:?} already exists with a different {field}: \
         the state file says {found}, this share would seed {seeded}"
    )]
    NamespaceConflict {
        namespace: NamespaceName,
        field: &'static str,
        found: String,
        seeded: String,
    },
    #[error(
        "namespace {namespace:?} already has a rule at {path}: \
         the state file says {found}, this share would seed {seeded}"
    )]
    RuleConflict {
        namespace: NamespaceName,
        path: String,
        found: String,
        seeded: String,
    },
}

#[cfg(test)]
mod tests {
    use std::os::unix::ffi::OsStringExt as _;

    use super::*;

    fn name(raw: &str) -> NamespaceName {
        NamespaceName::new(raw).expect("valid namespace name")
    }

    fn tcp(addr: &str) -> Listener {
        Listener::Tcp {
            addr: addr.parse().expect("valid address"),
        }
    }

    fn seed() -> Seed {
        Seed::new(
            "/srv/project",
            name(DEFAULT_NAMESPACE),
            ShareMode::Rw,
            vec![tcp("127.0.0.1:9000")],
        )
        .expect("a valid seed")
    }

    #[test]
    fn a_seed_shares_the_directory_at_its_own_host_path() {
        let seed = seed();
        assert_eq!(seed.rule_path(), "/srv/project");
        assert_eq!(
            seed.rule(),
            Rule::new("/srv/project", ShareMode::Rw).with_target("/srv/project")
        );
        let spec = seed.namespace_spec();
        assert_eq!(spec.name, name("share"));
        assert_eq!(
            spec.permission,
            voidport_control::PermissionMode::Passthrough
        );
        assert_eq!(spec.auth, voidport_control::AuthMode::None);
        assert_eq!(spec.direct_io, voidport_control::HostDirectIo::Cached);
        assert_eq!(spec.ownership, OwnershipSpec::Passthrough {});
        assert_eq!(spec.rules, vec![seed.rule()]);
    }

    #[test]
    fn a_launch_that_could_not_be_served_is_refused() {
        let listeners = vec![tcp("127.0.0.1:9000")];
        assert_eq!(
            Seed::new("project", name("share"), ShareMode::Rw, listeners.clone()),
            Err(SeedError::RelativeDirectory {
                path: PathBuf::from("project")
            })
        );
        assert_eq!(
            Seed::new("/", name("share"), ShareMode::Rw, listeners.clone()),
            Err(SeedError::UnshareableDirectory {
                path: PathBuf::from("/"),
                source: PathError::RootLiteral,
            })
        );
        assert_eq!(
            Seed::new("/srv/project", name("share"), ShareMode::Rw, Vec::new()),
            Err(SeedError::NoListener)
        );
    }

    #[test]
    fn a_directory_whose_path_is_not_a_rule_path_is_refused() {
        let listeners = vec![tcp("127.0.0.1:9000")];
        assert_eq!(
            Seed::new("/srv/*", name("share"), ShareMode::Rw, listeners.clone()),
            Err(SeedError::WildcardDirectory {
                path: PathBuf::from("/srv/*")
            })
        );
        assert_eq!(
            Seed::new(
                "/srv/*/here",
                name("share"),
                ShareMode::Rw,
                listeners.clone()
            ),
            Err(SeedError::UnshareableDirectory {
                path: PathBuf::from("/srv/*/here"),
                source: PathError::MisplacedWildcard,
            })
        );
        let raw = PathBuf::from(std::ffi::OsString::from_vec(b"/srv/\xffname".to_vec()));
        assert_eq!(
            Seed::new(raw.clone(), name("share"), ShareMode::Rw, listeners),
            Err(SeedError::NonUnicodeDirectory { path: raw })
        );
    }

    #[test]
    fn seeding_an_empty_document_adds_the_listener_the_namespace_and_the_rule() {
        let mut document = StateDocument::default();
        assert!(seed().apply(&mut document, None).expect("seeds"));
        assert_eq!(document.server.listeners, vec![tcp("127.0.0.1:9000")]);
        assert_eq!(document.namespaces, vec![seed().namespace_spec()]);
    }

    #[test]
    fn relaunching_the_same_share_changes_nothing() {
        let mut document = StateDocument::default();
        assert!(seed().apply(&mut document, None).expect("seeds"));
        let after_first = document.clone();

        assert!(
            !seed().apply(&mut document, None).expect("seeds again"),
            "an identical relaunch has nothing to change"
        );
        assert_eq!(document, after_first);
    }

    #[test]
    fn the_control_socket_is_seeded_only_into_a_document_that_names_none() {
        let socket = Path::new("/state/control.sock");

        let mut document = StateDocument::default();
        assert!(seed().apply(&mut document, Some(socket)).expect("seeds"));
        assert_eq!(document.server.control_socket, Some(socket.to_path_buf()));
        let after_first = document.clone();
        assert!(
            !seed()
                .apply(&mut document, Some(socket))
                .expect("seeds again"),
            "the seeded socket is idempotent like the rest of the seed"
        );
        assert_eq!(document, after_first);

        let mut document = StateDocument::default();
        document.server.control_socket = Some(PathBuf::from("/elsewhere/ctl.sock"));
        assert!(seed().apply(&mut document, Some(socket)).expect("seeds"));
        assert_eq!(
            document.server.control_socket,
            Some(PathBuf::from("/elsewhere/ctl.sock"))
        );

        let mut document = StateDocument::default();
        assert!(seed().apply(&mut document, None).expect("seeds"));
        assert_eq!(document.server.control_socket, None);
    }

    #[test]
    fn seeding_is_additive_beside_configuration_it_did_not_write() {
        let mut document = StateDocument::default();
        document.server.listeners.push(tcp("0.0.0.0:1"));
        document.namespaces.push(NamespaceSpec::new(name("other")));
        seed().apply(&mut document, None).expect("seeds");

        assert_eq!(
            document.server.listeners,
            vec![tcp("0.0.0.0:1"), tcp("127.0.0.1:9000")]
        );
        assert_eq!(document.namespaces.len(), 2);
        assert_eq!(document.namespaces[0].name, name("other"));

        let second = Seed::new(
            "/srv/docs",
            name(DEFAULT_NAMESPACE),
            ShareMode::Ro,
            vec![tcp("127.0.0.1:9000")],
        )
        .expect("a valid seed");
        assert!(second.apply(&mut document, None).expect("seeds"));
        let share = document.namespace(&name("share")).expect("seeded");
        assert_eq!(share.rules, vec![seed().rule(), second.rule()]);
        assert_eq!(
            document.server.listeners.len(),
            2,
            "the listener it shares with the first launch is not duplicated"
        );
    }

    #[test]
    fn repeated_shares_compose_into_the_hierarchy_the_host_has() {
        let mut document = StateDocument::default();
        let mut seeded = Vec::new();
        for directory in [
            "/srv/media/example-project",
            "/srv/other/example-project",
            "/srv/media/example-project/vendor",
        ] {
            let seed = Seed::new(
                directory,
                name(DEFAULT_NAMESPACE),
                ShareMode::Rw,
                vec![tcp("127.0.0.1:9000")],
            )
            .expect("a valid seed");
            assert_eq!(seed.rule_path(), directory);
            assert!(
                seed.apply(&mut document, None).expect("seeds"),
                "{directory} is a rule of its own"
            );
            seeded.push(seed.rule());
        }
        assert_eq!(
            document.namespace(&name("share")).expect("seeded").rules,
            seeded
        );
    }

    #[test]
    fn a_rule_of_the_same_path_with_different_content_refuses_the_launch() {
        let mut document = StateDocument::default();
        seed().apply(&mut document, None).expect("seeds");

        let colliding = Seed::new(
            "/srv/project",
            name(DEFAULT_NAMESPACE),
            ShareMode::Ro,
            vec![tcp("127.0.0.1:9000")],
        )
        .expect("a valid seed");
        let mut occupied = StateDocument::default();
        let mut spec = NamespaceSpec::new(name(DEFAULT_NAMESPACE));
        spec.rules
            .push(Rule::new("/srv/project", ShareMode::Rw).with_target("/elsewhere"));
        occupied.namespaces.push(spec);

        for (document, seed) in [(&mut document, colliding), (&mut occupied, seed())] {
            let before = document.clone();
            let error = seed.apply(document, None).expect_err("the rule collides");
            assert!(
                matches!(&error, SeedError::RuleConflict { path, .. } if path == "/srv/project"),
                "{error}"
            );
            assert!(error.to_string().contains("/srv/project"), "{error}");
            assert_eq!(*document, before, "a refusal must not half-apply");
        }
    }

    #[test]
    fn a_namespace_of_the_same_name_with_different_policy_refuses_the_launch() {
        let mut document = StateDocument::default();
        let mut occupied = NamespaceSpec::new(name(DEFAULT_NAMESPACE));
        occupied.ownership = OwnershipSpec::Static { uid: 0, gid: 0 };
        document.namespaces.push(occupied);
        let before = document.clone();

        let error = seed()
            .apply(&mut document, None)
            .expect_err("the namespace collides");
        assert!(
            matches!(
                &error,
                SeedError::NamespaceConflict {
                    field: "ownership mode",
                    ..
                }
            ),
            "{error}"
        );
        assert!(error.to_string().contains("static"), "{error}");
        assert_eq!(document, before, "a refusal must not half-apply");

        let mut document = StateDocument::default();
        let mut occupied = NamespaceSpec::new(name(DEFAULT_NAMESPACE));
        occupied.direct_io = voidport_control::HostDirectIo::Always;
        document.namespaces.push(occupied);
        let error = seed()
            .apply(&mut document, None)
            .expect_err("the namespace collides");
        assert!(
            matches!(
                &error,
                SeedError::NamespaceConflict {
                    field: "direct-io posture",
                    ..
                }
            ),
            "{error}"
        );
        assert!(error.to_string().contains("always"), "{error}");
    }

    #[test]
    fn a_pattern_rule_on_the_seeded_directory_does_not_stand_in_for_the_seed() {
        let mut document = StateDocument::default();
        let mut spec = NamespaceSpec::new(name(DEFAULT_NAMESPACE));
        let pattern = Rule::new("/srv/project", ShareMode::Ro).with_match("build-*");
        spec.rules.push(pattern.clone());
        document.namespaces.push(spec);

        assert!(seed().apply(&mut document, None).expect("seeds"));
        assert_eq!(
            document.namespace(&name("share")).expect("seeded").rules,
            vec![pattern, seed().rule()],
            "the seeded rule joins the pattern rule instead of being skipped by it"
        );
        assert!(!seed().apply(&mut document, None).expect("seeds again"));
    }

    #[test]
    fn a_namespace_of_the_same_name_and_policy_is_shared_with() {
        let mut document = StateDocument::default();
        document
            .namespaces
            .push(NamespaceSpec::new(name(DEFAULT_NAMESPACE)));
        assert!(seed().apply(&mut document, None).expect("seeds"));
        assert_eq!(
            document.namespace(&name("share")).expect("seeded").rules,
            vec![seed().rule()]
        );
    }
}
