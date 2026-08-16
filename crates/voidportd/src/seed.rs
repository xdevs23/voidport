//! Seeding a state document from a `voidportd share <DIR>` launch.
//!
//! Quick sharing is **not a separate mode**: `voidportd share` is the ordinary
//! launch against the ordinary state file, with one step inserted before the
//! server serves — the configuration the operator described on the command line
//! is written into the document first. Everything after that point is the plain
//! startup path, which is why a shared directory is reconfigurable through
//! `voidport-ctl` like anything else and survives a restart without the
//! `share` command.
//!
//! The one rule it writes shares the directory at **its own absolute host
//! path**, replicated as the namespace path:
//! `share /srv/media/example-project` becomes the rule
//! `/srv/media/example-project`, and the guest — which mounts the namespace
//! root — sees `srv/media/example-project/…` below its mountpoint, the
//! intermediate directories synthesized by the engine as for any deep rule.
//! The quickstart's use case is host-hierarchy replication, so two shares of
//! two host paths compose into the hierarchy they have on the host instead of
//! flattening into two sibling names that could collide.
//!
//! The seed is therefore a *value*, applied to a document:
//!
//! * **additive** — it adds the listeners, the namespace and the one rule it
//!   describes, and touches nothing else in the file;
//! * **idempotent** — a piece that is already there with exactly the seeded
//!   content is left alone, so relaunching the same `share` command against the
//!   same file changes nothing at all (and, because [`Seed::apply`] reports
//!   that, is not even rewritten);
//! * **conflict-refusing** — a namespace or rule of the same name or path with
//!   *different* content refuses startup, naming the collision. Nothing is ever
//!   overwritten: the state file is the operator's, and a convenience command
//!   that silently rewrote it would be the worst possible surprise.
//!
//! The control socket is seeded through that same machinery: a launch that was
//! given none writes one beside its state file (see
//! [`daemon::seeded_control_socket`](crate::daemon), which decides the path) so
//! that quick sharing never needs the root-owned compiled default. A document
//! that already names a socket is *not* a collision — the operator's own value
//! simply wins, and nothing is seeded.

use std::path::{Path, PathBuf};

use voidport_control::{NamespaceName, NamespaceSpec, OwnershipSpec, Rule, ShareMode};

use crate::rules::{PathError, RulePath};
use crate::state::{Listener, StateDocument};

/// The namespace a seeded launch creates when `--name` is absent.
pub const DEFAULT_NAMESPACE: &str = "share";

/// The configuration a `voidportd share <DIR>` launch seeds before serving.
///
/// Built through [`Seed::new`], which is where the launch's own rules live: the
/// directory must be absolute and must spell a literal rule path, because the
/// path *is* the rule path, and there must be at least one listener — there is
/// no default bind anywhere in this system, and a share nobody can reach is not
/// a share.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Seed {
    directory: PathBuf,
    /// The directory as the state file spells the rule path: the same path,
    /// validated once here so that everything downstream can rely on it.
    path: String,
    namespace: NamespaceName,
    mode: ShareMode,
    listeners: Vec<Listener>,
}

impl Seed {
    /// Describes a seeded launch.
    ///
    /// # Errors
    ///
    /// Returns [`SeedError::RelativeDirectory`],
    /// [`SeedError::NonUnicodeDirectory`], [`SeedError::WildcardDirectory`] or
    /// [`SeedError::UnshareableDirectory`] if the directory cannot be a rule
    /// path as written, and [`SeedError::NoListener`] if nothing would serve
    /// it.
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

    /// The host directory being shared.
    #[must_use]
    pub fn directory(&self) -> &Path {
        &self.directory
    }

    /// The namespace the directory is shared in.
    #[must_use]
    pub fn namespace(&self) -> &NamespaceName {
        &self.namespace
    }

    /// The listeners the launch asked for.
    #[must_use]
    pub fn listeners(&self) -> &[Listener] {
        &self.listeners
    }

    /// The namespace path the directory is shared at: its own absolute host
    /// path, replicated.
    #[must_use]
    pub fn rule_path(&self) -> &str {
        &self.path
    }

    /// The one rule the seed adds: the absolute directory shared at its own
    /// path, rw or ro.
    #[must_use]
    pub fn rule(&self) -> Rule {
        Rule::new(self.rule_path(), self.mode).with_target(self.directory.display().to_string())
    }

    /// The namespace the seed creates: passthrough permissions, no auth,
    /// passthrough ownership, and the one rule.
    #[must_use]
    pub fn namespace_spec(&self) -> NamespaceSpec {
        let mut spec = NamespaceSpec::new(self.namespace.clone());
        spec.rules.push(self.rule());
        spec
    }

    /// Applies the seed to `document`, reporting whether anything changed.
    ///
    /// `control_socket` is the socket path this launch would seed, or `None`
    /// when the launch named its own on the command line and the document must
    /// not be told otherwise.
    ///
    /// `Ok(false)` is the idempotent relaunch: every piece was already there,
    /// spelled exactly as this seed spells it, so the caller has nothing to
    /// persist.
    ///
    /// # Errors
    ///
    /// Returns [`SeedError::NamespaceConflict`] or [`SeedError::RuleConflict`]
    /// naming the collision. The document is left unchanged on either — a
    /// refusal must not half-apply.
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
        // Additive like everything else: a document that already names a socket
        // keeps it, and that is not a collision — the operator's own value is
        // what the server binds, and this launch simply seeds nothing.
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
                // Keyed by the pair `check_rule` checked, path *and* no match:
                // a pattern rule on the seeded directory is another rule that
                // coexists with this one, and asking by path alone would let it
                // stand in for the literal rule the launch exists to guarantee.
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

    /// Refuses a namespace of this name whose policy is not the seeded one.
    fn check_policy(&self, existing: &NamespaceSpec) -> Result<(), SeedError> {
        let seeded = NamespaceSpec::new(self.namespace.clone());
        let mismatch = if existing.permission != seeded.permission {
            Some((
                "permission mode",
                existing.permission.to_string(),
                seeded.permission.to_string(),
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
                existing.ownership.mode_name().to_owned(),
                OwnershipSpec::default().mode_name().to_owned(),
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

    /// Refuses a rule at this path that is not the seeded one.
    ///
    /// The seeded rule carries no match, and a rule is keyed by its path *and*
    /// its match — so a pattern rule on the same directory is a different rule
    /// that coexists with this one, not a collision with it.
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

/// The rule path a host directory is shared at: the directory itself.
///
/// The path is the rule path, so every rule the engine will refuse to parse has
/// to be refused here instead, where the operator is still looking at their own
/// command line: a path that is not text (a rule path is a TOML string), a path
/// the engine cannot key a rule by, and a path whose final component is
/// literally `*` — that one *parses*, as the wildcard rule for the directory
/// above it, which is emphatically not what sharing a directory named `*`
/// means.
fn shared_rule_path(directory: &Path) -> Result<String, SeedError> {
    let Some(text) = directory.to_str() else {
        return Err(SeedError::NonUnicodeDirectory {
            path: directory.to_path_buf(),
        });
    };
    match RulePath::parse(text) {
        Ok(RulePath::Literal(_)) => Ok(text.to_owned()),
        // A pattern is unreachable here — a match is a field of its own and
        // this path carries none — and a directory named `*` is refused.
        Ok(RulePath::Wildcard(_) | RulePath::Pattern(_)) => Err(SeedError::WildcardDirectory {
            path: directory.to_path_buf(),
        }),
        Err(source) => Err(SeedError::UnshareableDirectory {
            path: directory.to_path_buf(),
            source,
        }),
    }
}

/// A rule as the state file spells it, for an error message.
fn describe(rule: &Rule) -> String {
    match &rule.target {
        Some(target) => format!("mode = \"{}\", target = {target:?}", rule.mode),
        None => format!("mode = \"{}\"", rule.mode),
    }
}

/// Why a launch cannot be seeded.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SeedError {
    /// The directory to share was not absolute.
    #[error("cannot share {path}: the directory must be an absolute path")]
    RelativeDirectory {
        /// The directory as given.
        path: PathBuf,
    },
    /// The directory's path is not text, and a rule path is.
    #[error("cannot share {path}: its path is not valid UTF-8, and a rule path is text")]
    NonUnicodeDirectory {
        /// The directory as given, lossily.
        path: PathBuf,
    },
    /// The directory's final component is `*`, which a rule path spells a
    /// wildcard with.
    #[error(
        "cannot share {path}: a rule path ending in `*` is the wildcard rule for the \
         directory above it, so this directory cannot be shared at its own path"
    )]
    WildcardDirectory {
        /// The directory as given.
        path: PathBuf,
    },
    /// The directory's path cannot be a rule path — the host root, or a
    /// component the engine refuses.
    #[error("cannot share {path}: it cannot be a namespace path ({source})")]
    UnshareableDirectory {
        /// The directory as given.
        path: PathBuf,
        /// Why the engine would refuse the rule path.
        #[source]
        source: PathError,
    },
    /// No listener was asked for, and there is no default bind.
    #[error(
        "share needs at least one listener: pass --addr HOST:PORT, --unix PATH \
         and/or --vsock PORT (there is no default bind)"
    )]
    NoListener,
    /// A namespace of the seeded name is configured with a different policy.
    #[error(
        "namespace {namespace:?} already exists with a different {field}: \
         the state file says {found}, this share would seed {seeded}"
    )]
    NamespaceConflict {
        /// The namespace at fault.
        namespace: NamespaceName,
        /// Which part of the policy differs.
        field: &'static str,
        /// What the state file holds.
        found: String,
        /// What the launch would have seeded.
        seeded: String,
    },
    /// A rule at the seeded path is configured differently.
    #[error(
        "namespace {namespace:?} already has a rule at {path}: \
         the state file says {found}, this share would seed {seeded}"
    )]
    RuleConflict {
        /// The namespace at fault.
        namespace: NamespaceName,
        /// The colliding rule path.
        path: String,
        /// What the state file holds.
        found: String,
        /// What the launch would have seeded.
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
        // The host root would have to be a rule at the namespace root, which
        // is synthesized by definition and carries no rule.
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
        // `*` is the wildcard spelling: as the last component it would seed the
        // per-directory default for `/srv`, and anywhere else it does not parse
        // at all. Either way the operator hears it now, not from the loader.
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
        // Host names are bytes; a rule path is a TOML string.
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

        // The whole point: an operator repeating the command must not grow a
        // second listener, a second rule, or a rewritten file.
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

        // Not a conflict: the operator's own value is what the server binds, so
        // it stays and nothing is seeded over it.
        let mut document = StateDocument::default();
        document.server.control_socket = Some(PathBuf::from("/elsewhere/ctl.sock"));
        assert!(seed().apply(&mut document, Some(socket)).expect("seeds"));
        assert_eq!(
            document.server.control_socket,
            Some(PathBuf::from("/elsewhere/ctl.sock"))
        );

        // A launch that named its own socket on the command line seeds none:
        // the flag wins the precedence, and the document must not claim
        // otherwise.
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

        // A second share of another directory into the same namespace adds its
        // rule beside the first one.
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
        // The point of replicating the host path: two directories that share a
        // final component do not collide, and one nested inside another lands
        // inside it — the namespace is the host's shape, not a flat list of
        // basenames.
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

        // Same directory, other mode: `/srv/project` cannot be rw and ro at
        // once.
        let colliding = Seed::new(
            "/srv/project",
            name(DEFAULT_NAMESPACE),
            ShareMode::Ro,
            vec![tcp("127.0.0.1:9000")],
        )
        .expect("a valid seed");
        // And a rule the operator wrote at that path, targeting elsewhere: the
        // state file is theirs, so it is a refusal and never an overwrite.
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
    }

    #[test]
    fn a_pattern_rule_on_the_seeded_directory_does_not_stand_in_for_the_seed() {
        // A rule is keyed by its path *and* its match, so a pattern rule on
        // `/srv/project` governs that directory's children and says nothing
        // about the directory itself. The launch must still seed its own rule:
        // reporting success while the share it guarantees does not exist is the
        // one outcome quick sharing cannot have.
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
        // And it stays idempotent from there.
        assert!(!seed().apply(&mut document, None).expect("seeds again"));
    }

    #[test]
    fn a_namespace_of_the_same_name_and_policy_is_shared_with() {
        // Not a conflict: `share` exists with the policy this launch would have
        // created, so the rule simply joins it.
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
