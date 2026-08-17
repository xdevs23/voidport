//! The state file's source document.
//!
//! The document is the persistent source of truth. It holds exactly what the
//! operator wrote — sentinels unresolved, relative host targets relative — and
//! nothing derived: engine state is *built from* it (see [`super::build`]) and
//! never written back into it. Persisting re-emits this document verbatim, so
//! `load(persist(x)) == x` holds and no mutation can freeze a portable
//! configuration into one machine's ids and paths.
//!
//! The namespace schema itself lives in `voidport-control`
//! ([`NamespaceSpec`]), and so does the listener schema ([`Listener`]): the
//! state file and the control plane speak one shape, so `namespace show`
//! returns literally what the file holds and `listener add` writes literally
//! what the operator sent.

use std::collections::BTreeSet;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use voidport_control::{Listener, NamespaceName, NamespaceSpec};

use super::limits::{Limits, LimitsError, MIN_NODE_DESCRIPTOR_BUDGET};

/// A whole state file.
///
/// Field order is also emission order, and TOML requires a table's scalar
/// values before its sub-tables — hence server settings first, then the two
/// arrays of tables.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateDocument {
    /// Server-wide settings.
    #[serde(default)]
    pub server: ServerSettings,
    /// The namespaces this server serves.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub namespaces: Vec<NamespaceSpec>,
}

impl StateDocument {
    /// Parses a state document from TOML text.
    ///
    /// # Errors
    ///
    /// Returns the `toml` error, which carries the offending line and column.
    pub fn from_toml(text: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(text)
    }

    /// Renders the document as TOML text.
    ///
    /// # Errors
    ///
    /// Returns the `toml` error if the document cannot be represented, which
    /// the schema is built to make impossible.
    pub fn to_toml(&self) -> Result<String, toml::ser::Error> {
        toml::to_string_pretty(self)
    }

    /// The namespace of that name, if the document holds it.
    #[must_use]
    pub fn namespace(&self, name: &NamespaceName) -> Option<&NamespaceSpec> {
        self.namespaces
            .iter()
            .find(|namespace| &namespace.name == name)
    }

    /// The namespace of that name, mutably.
    #[must_use]
    pub fn namespace_mut(&mut self, name: &NamespaceName) -> Option<&mut NamespaceSpec> {
        self.namespaces
            .iter_mut()
            .find(|namespace| &namespace.name == name)
    }

    /// The first namespace name the document repeats, if any.
    ///
    /// Namespace names key the registry, so a duplicate is a configuration
    /// defect, not a last-one-wins merge.
    #[must_use]
    pub fn duplicate_namespace(&self) -> Option<&NamespaceName> {
        let mut seen = BTreeSet::new();
        self.namespaces
            .iter()
            .find(|namespace| !seen.insert(&namespace.name))
            .map(|namespace| &namespace.name)
    }
}

/// Server-wide settings.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerSettings {
    /// Where the control-plane unix socket lives, interpreted as configured by
    /// the process. A command-line path overrides it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_socket: Option<PathBuf>,
    /// How many node descriptors the server's cache may hold resident at once,
    /// across every session.
    ///
    /// Taken as written — no floor is applied to a number an operator chose —
    /// and refused below
    /// [`MIN_NODE_DESCRIPTOR_BUDGET`],
    /// which is one operation's simultaneous working set. Absent means the
    /// server derives one from the descriptor limit it reached at startup
    /// ([`DescriptorBudget::sized`](crate::data::pin::DescriptorBudget::sized)).
    /// Startup-only: nothing in the control protocol changes it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_descriptor_budget: Option<usize>,
    /// Data-plane listeners.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub listeners: Vec<Listener>,
    /// The data plane's resource caps. Omitted from the file while they are
    /// the defaults, so a configuration that never mentioned them does not
    /// grow a block of numbers nobody wrote.
    #[serde(default, skip_serializing_if = "Limits::is_default")]
    pub limits: Limits,
}

impl ServerSettings {
    /// Checks that every server setting can mean what it says.
    ///
    /// This is the *only* listener validation there is, and it is the one both
    /// paths run: a state file runs it at load, and `listener-add` runs it on
    /// the document the addition would make, before anything is bound. (The
    /// unix-path rules are not checks at all — they *are* the bind, and the
    /// mutation path exercises them by binding.)
    ///
    /// # Errors
    ///
    /// Returns [`LimitsError`] naming the offending setting, or the listener
    /// whose port no mount URL could name.
    pub fn validate(&self) -> Result<(), LimitsError> {
        self.limits.validate()?;
        if let Some(budget) = self.node_descriptor_budget
            && budget < MIN_NODE_DESCRIPTOR_BUDGET
        {
            return Err(LimitsError::TooSmall {
                setting: "node_descriptor_budget",
                minimum: MIN_NODE_DESCRIPTOR_BUDGET,
            });
        }
        for listener in &self.listeners {
            if let Listener::Vsock { cid, port } = listener
                && !VSOCK_PORTS.contains(port)
            {
                return Err(LimitsError::VsockPort {
                    cid: *cid,
                    port: *port,
                });
            }
        }
        Ok(())
    }
}

/// The vsock ports a listener may be configured on.
///
/// Vsock ports are 32-bit at the kernel, but the mount grammar's port is the
/// URL standard's and therefore 16-bit — and a bespoke authority parser to
/// widen it is exactly the wheel this project does not reinvent. A listener
/// outside this range would be a listener no guest could name, so it is refused
/// at load with the listener in the message, not bound and unreachable.
/// Port 0 is excluded because it is not an address a client can dial either.
pub const VSOCK_PORTS: std::ops::RangeInclusive<u32> = 1..=u16::MAX as u32;

/// The wildcard cid the protocol crate states and this crate binds are the same
/// number: `voidport-control` restates it so that it stays at serde and nothing
/// else, and this is where the restatement is checked.
const _: () = assert!(voidport_control::ANY_CID == vsock::VMADDR_CID_ANY);

#[cfg(test)]
mod tests {
    use super::*;
    use voidport_control::{
        AuthMode, DEFAULT_SQUASH_ID, HostDirectIo, HostId, IdMapping, IdSentinel, OwnershipSpec,
        PermissionMode, Rule, ShareMode, XattrRule, XattrVerdict,
    };

    fn name(raw: &str) -> NamespaceName {
        NamespaceName::new(raw).expect("valid namespace name")
    }

    /// A document exercising every corner of the schema.
    fn full_document() -> StateDocument {
        StateDocument {
            server: ServerSettings {
                control_socket: Some(PathBuf::from("/run/voidport/control.sock")),
                node_descriptor_budget: None,
                listeners: vec![
                    Listener::Tcp {
                        addr: "0.0.0.0:9000".parse().expect("valid address"),
                    },
                    Listener::Unix {
                        path: PathBuf::from("/run/voidport/data.sock"),
                    },
                    Listener::Vsock { cid: 3, port: 1024 },
                ],
                limits: Limits::default(),
            },
            namespaces: vec![
                NamespaceSpec {
                    name: name("project"),
                    permission: PermissionMode::Passthrough,
                    direct_io: HostDirectIo::Cached,
                    auth: AuthMode::None,
                    ownership: OwnershipSpec::Map {
                        unmapped: voidport_control::UnmappedPolicy::Hide,
                        squash_uid: DEFAULT_SQUASH_ID,
                        squash_gid: DEFAULT_SQUASH_ID,
                        uid_map: vec![IdMapping::new(IdSentinel::Uid, 0)],
                        gid_map: vec![IdMapping::new(IdSentinel::Gid, 0)],
                    },
                    privileged_bits: true,
                    rules: vec![
                        Rule::new("/project", ShareMode::Rw).with_target("project"),
                        Rule::new("/project/*", ShareMode::Hidden),
                        Rule::new("/project/notes.txt", ShareMode::Ro),
                    ],
                    xattr: vec![
                        XattrRule::new("user.*").with_write(XattrVerdict::Deny),
                        XattrRule::new("user.build.id").with_write(XattrVerdict::Allow),
                    ],
                },
                NamespaceSpec {
                    name: name("scratch"),
                    permission: PermissionMode::Passthrough,
                    direct_io: HostDirectIo::Cached,
                    auth: AuthMode::None,
                    ownership: OwnershipSpec::Static { uid: 0, gid: 0 },
                    privileged_bits: true,
                    rules: Vec::new(),
                    xattr: Vec::new(),
                },
            ],
        }
    }

    #[test]
    fn a_document_round_trips_through_toml() {
        let document = full_document();
        let text = document.to_toml().expect("serializable");
        assert_eq!(
            StateDocument::from_toml(&text).expect("parses"),
            document,
            "round trip of:\n{text}"
        );
        // The source form survives verbatim: no sentinel resolved, no target
        // made absolute.
        assert!(text.contains("host = \"uid\""), "{text}");
        assert!(text.contains("target = \"project\""), "{text}");
        // The attribute rules ride the same round trip, verdicts and all, and
        // an unstated verdict stays out of the file.
        assert!(text.contains("[[namespaces.xattr]]"), "{text}");
        assert!(text.contains("match = \"user.*\""), "{text}");
        assert!(text.contains("write = \"deny\""), "{text}");
        assert!(!text.contains("read ="), "{text}");
    }

    #[test]
    fn an_empty_document_is_a_server_with_nothing_configured() {
        let document = StateDocument::from_toml("").expect("parses");
        assert_eq!(document, StateDocument::default());
        assert!(document.namespaces.is_empty());
        assert_eq!(document.server.control_socket, None);
        assert!(document.server.listeners.is_empty());
        assert_eq!(document.to_toml().expect("serializable"), "[server]\n");
    }

    #[test]
    fn unknown_keys_are_rejected_everywhere() {
        let cases = [
            "srever = {}",
            "[server]\nsocket = \"/tmp/x\"\n",
            "[[server.listeners]]\ntransport = \"tcp\"\naddr = \"0.0.0.0:1\"\nbacklog = 5\n",
            "[[listener]]\ntransport = \"tcp\"\naddr = \"0.0.0.0:1\"\n",
            "[[server.listener]]\ntransport = \"tcp\"\naddr = \"0.0.0.0:1\"\n",
            "[[listeners]]\ntransport = \"tcp\"\naddr = \"0.0.0.0:1\"\n",
            "[[namespaces]]\nname = \"p\"\npermisson = \"passthrough\"\n",
            "[[namespaces]]\nname = \"p\"\n[namespaces.ownership]\nmode = \"passthrough\"\nuid = 0\n",
            "[[namespaces]]\nname = \"p\"\n[[namespaces.rules]]\npath = \"/a\"\nmode = \"rw\"\nhost = \"/srv/a\"\n",
        ];
        for case in cases {
            assert!(
                StateDocument::from_toml(case).is_err(),
                "expected rejection of:\n{case}"
            );
        }
    }

    #[test]
    fn resource_caps_are_optional_and_persist_only_when_set() {
        let document =
            StateDocument::from_toml("[server.limits]\nmax_nodes = 8\n").expect("parses");
        assert_eq!(document.server.limits.max_nodes, Some(8));
        assert!(!document.server.limits.is_default());
        let text = document.to_toml().expect("serializable");
        assert!(text.contains("max_nodes = 8"), "{text}");
        assert_eq!(StateDocument::from_toml(&text).expect("parses"), document);

        // Defaults stay out of the file entirely.
        let bare = StateDocument::default();
        assert!(bare.server.limits.is_default());
        assert!(!bare.to_toml().expect("serializable").contains("limits"));
        assert!(StateDocument::from_toml("[server.limits]\nmax_node = 8\n").is_err());
    }

    /// The descriptor budget is a `[server]` scalar, absent by default, and
    /// refused where it is too small to hold one operation's working set.
    #[test]
    fn the_node_descriptor_budget_is_optional_and_has_a_floor() {
        let bare = StateDocument::default();
        assert_eq!(bare.server.node_descriptor_budget, None);
        assert_eq!(bare.server.validate(), Ok(()));
        assert!(
            !bare
                .to_toml()
                .expect("serializable")
                .contains("node_descriptor_budget")
        );

        let configured =
            StateDocument::from_toml("[server]\nnode_descriptor_budget = 512\n").expect("parses");
        assert_eq!(configured.server.node_descriptor_budget, Some(512));
        assert_eq!(configured.server.validate(), Ok(()));
        assert_eq!(
            StateDocument::from_toml(&configured.to_toml().expect("serializable")).expect("parses"),
            configured
        );

        let tiny =
            StateDocument::from_toml("[server]\nnode_descriptor_budget = 4\n").expect("parses");
        assert_eq!(
            tiny.server.validate().expect_err("below the floor"),
            LimitsError::TooSmall {
                setting: "node_descriptor_budget",
                minimum: MIN_NODE_DESCRIPTOR_BUDGET,
            }
        );
    }

    #[test]
    fn listeners_cover_all_three_transports() {
        let text = "
            [[server.listeners]]
            transport = \"tcp\"
            addr = \"127.0.0.1:9000\"

            [[server.listeners]]
            transport = \"unix\"
            path = \"/run/voidport/data.sock\"

            [[server.listeners]]
            transport = \"vsock\"
            cid = 3
            port = 1024
        ";
        let document = StateDocument::from_toml(text).expect("parses");
        assert_eq!(
            document.server.listeners,
            vec![
                Listener::Tcp {
                    addr: "127.0.0.1:9000".parse().expect("valid address")
                },
                Listener::Unix {
                    path: PathBuf::from("/run/voidport/data.sock")
                },
                Listener::Vsock { cid: 3, port: 1024 },
            ]
        );
        // A malformed address is a load error, not a runtime surprise.
        assert!(
            StateDocument::from_toml(
                "[[server.listeners]]\ntransport = \"tcp\"\naddr = \"not-an-address\"\n"
            )
            .is_err()
        );
        assert!(
            StateDocument::from_toml("[[server.listeners]]\ntransport = \"pigeon\"\n").is_err()
        );
    }

    #[test]
    fn per_mode_ownership_shapes_are_enforced_in_toml() {
        let map = "
            [[namespaces]]
            name = \"p\"
            [namespaces.ownership]
            mode = \"map\"
            unmapped = \"passthrough\"
            uid_map = [{ host = 1000, guest = 0 }]
            gid_map = [{ host = \"gid\", guest = 0 }]
        ";
        let document = StateDocument::from_toml(map).expect("parses");
        assert_eq!(
            document.namespaces[0].ownership,
            OwnershipSpec::Map {
                unmapped: voidport_control::UnmappedPolicy::Passthrough,
                squash_uid: DEFAULT_SQUASH_ID,
                squash_gid: DEFAULT_SQUASH_ID,
                uid_map: vec![IdMapping::new(HostId::Numeric(1000), 0)],
                gid_map: vec![IdMapping::new(IdSentinel::Gid, 0)],
            }
        );

        let rejected = [
            // map without its tables
            "[[namespaces]]\nname = \"p\"\n[namespaces.ownership]\nmode = \"map\"\n",
            // static without its ids
            "[[namespaces]]\nname = \"p\"\n[namespaces.ownership]\nmode = \"static\"\nuid = 0\n",
            // a host id that is neither a number nor a sentinel
            "[[namespaces]]\nname = \"p\"\n[namespaces.ownership]\nmode = \"map\"\nuid_map = [{ host = \"root\", guest = 0 }]\ngid_map = []\n",
            // an unknown mode, and a capitalized one
            "[[namespaces]]\nname = \"p\"\n[namespaces.ownership]\nmode = \"Map\"\n",
        ];
        for case in rejected {
            assert!(
                StateDocument::from_toml(case).is_err(),
                "expected rejection of:\n{case}"
            );
        }
    }

    #[test]
    fn namespace_names_are_validated_and_duplicates_are_visible() {
        assert!(StateDocument::from_toml("[[namespaces]]\nname = \"a/b\"\n").is_err());
        assert!(StateDocument::from_toml("[[namespaces]]\nname = \"\"\n").is_err());

        let duplicated = StateDocument::from_toml(
            "[[namespaces]]\nname = \"p\"\n[[namespaces]]\nname = \"p\"\n",
        )
        .expect("parses");
        assert_eq!(duplicated.duplicate_namespace(), Some(&name("p")));
        assert_eq!(full_document().duplicate_namespace(), None);
    }

    #[test]
    fn namespaces_are_addressable_by_name() {
        let mut document = full_document();
        assert_eq!(
            document.namespace(&name("project")).map(|n| n.rules.len()),
            Some(3)
        );
        assert_eq!(document.namespace(&name("absent")), None);
        document
            .namespace_mut(&name("scratch"))
            .expect("present")
            .rules
            .push(Rule::new("/a", ShareMode::Hidden));
        assert_eq!(
            document.namespace(&name("scratch")).map(|n| n.rules.len()),
            Some(1)
        );
        assert!(document.namespace_mut(&name("absent")).is_none());
    }
}
