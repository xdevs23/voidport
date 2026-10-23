use std::collections::BTreeSet;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use voidport_control::{Listener, NamespaceName, NamespaceSpec, VSOCK_PORTS};

/// The descriptors one operation uses at once: a rename uses both parents and
/// both entries.
pub const MIN_NODE_DESCRIPTOR_BUDGET: usize = 16;

/// Field order is emission order, and TOML requires the scalar values of a
/// table before its sub-tables.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateDocument {
    #[serde(default)]
    pub server: ServerSettings,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub namespaces: Vec<NamespaceSpec>,
}

impl StateDocument {
    /// # Errors
    ///
    /// Returns the `toml` error, which contains the offending line and column.
    pub fn from_toml(text: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(text)
    }

    /// # Errors
    ///
    /// Returns the `toml` error if the document cannot be represented, which
    /// the schema is built to make impossible.
    pub fn to_toml(&self) -> Result<String, toml::ser::Error> {
        toml::to_string_pretty(self)
    }

    #[must_use]
    pub fn namespace(&self, name: &NamespaceName) -> Option<&NamespaceSpec> {
        self.namespaces
            .iter()
            .find(|namespace| &namespace.name == name)
    }

    #[must_use]
    pub fn namespace_mut(&mut self, name: &NamespaceName) -> Option<&mut NamespaceSpec> {
        self.namespaces
            .iter_mut()
            .find(|namespace| &namespace.name == name)
    }

    /// Namespace names key the registry, so a duplicate is a defect, not a
    /// last-one-wins merge.
    #[must_use]
    pub fn duplicate_namespace(&self) -> Option<&NamespaceName> {
        let mut seen = BTreeSet::new();
        self.namespaces
            .iter()
            .find(|namespace| !seen.insert(&namespace.name))
            .map(|namespace| &namespace.name)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerSettings {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_socket: Option<PathBuf>,
    /// Refused below [`MIN_NODE_DESCRIPTOR_BUDGET`]. Absent means the server
    /// derives one from the descriptor limit reached at startup. Startup-only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_descriptor_budget: Option<usize>,
    /// Absent means the server generates a key at startup and has it in
    /// memory only. Servers given the same file verify the tokens of each other.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_key: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub listeners: Vec<Listener>,
}

impl ServerSettings {
    /// The one listener validation both paths run: a state file at load, and
    /// `listener-add` on the document the addition would make, before anything
    /// is bound.
    ///
    /// # Errors
    ///
    /// Returns [`ServerSettingsError`] naming the offending setting, or the
    /// listener whose port no mount URL could name.
    pub fn validate(&self) -> Result<(), ServerSettingsError> {
        if let Some(budget) = self.node_descriptor_budget
            && budget < MIN_NODE_DESCRIPTOR_BUDGET
        {
            return Err(ServerSettingsError::TooSmall {
                setting: "node_descriptor_budget",
                minimum: MIN_NODE_DESCRIPTOR_BUDGET,
            });
        }
        for listener in &self.listeners {
            if let Listener::Vsock { cid, port } = listener
                && !port.fits_mount_url()
            {
                return Err(ServerSettingsError::VsockPort {
                    cid: *cid,
                    port: u32::from(*port),
                });
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ServerSettingsError {
    #[error("server.{setting} must be at least {minimum}")]
    TooSmall {
        setting: &'static str,
        minimum: usize,
    },
    #[error(
        "vsock listener cid {cid} port {port}: a vsock port must be 0 (any free port) or \
         {}..={}, because a mount URL's port is the URL standard's 16-bit one",
        VSOCK_PORTS.start(),
        VSOCK_PORTS.end()
    )]
    VsockPort { cid: u32, port: u32 },
}

/// `voidport-control` restates the wildcard cid so that it does not depend on
/// `vsock`. This checks that both are the same number.
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

    fn full_document() -> StateDocument {
        StateDocument {
            server: ServerSettings {
                control_socket: Some(PathBuf::from("/run/voidport/control.sock")),
                node_descriptor_budget: None,
                signing_key: Some(PathBuf::from("/etc/voidport/signing.pem")),
                listeners: vec![
                    Listener::Tcp {
                        addr: "0.0.0.0:9000".parse().expect("valid address"),
                    },
                    Listener::Unix {
                        path: PathBuf::from("/run/voidport/data.sock"),
                    },
                    Listener::Vsock {
                        cid: 3,
                        port: 1024.into(),
                    },
                    Listener::VhostUser {
                        path: PathBuf::from("/run/voidport/vhost-user.sock"),
                    },
                ],
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
        assert!(text.contains("host = \"uid\""), "{text}");
        assert!(
            text.contains("signing_key = \"/etc/voidport/signing.pem\""),
            "{text}"
        );
        assert!(text.contains("target = \"project\""), "{text}");
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
            ServerSettingsError::TooSmall {
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
                Listener::Vsock {
                    cid: 3,
                    port: 1024.into()
                },
            ]
        );
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
    fn a_vsock_port_is_in_the_range_a_mount_url_accepts_or_is_any() {
        let settings = |port| ServerSettings {
            listeners: vec![Listener::vsock(port)],
            ..ServerSettings::default()
        };
        for port in [0, 1, u32::from(u16::MAX)] {
            assert_eq!(settings(port).validate(), Ok(()), "{port}");
        }
        let too_wide = u32::from(u16::MAX) + 1;
        assert_eq!(
            settings(too_wide).validate(),
            Err(ServerSettingsError::VsockPort {
                cid: voidport_control::ANY_CID,
                port: too_wide,
            })
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
            "[[namespaces]]\nname = \"p\"\n[namespaces.ownership]\nmode = \"map\"\n",
            "[[namespaces]]\nname = \"p\"\n[namespaces.ownership]\nmode = \"static\"\nuid = 0\n",
            "[[namespaces]]\nname = \"p\"\n[namespaces.ownership]\nmode = \"map\"\nuid_map = [{ host = \"root\", guest = 0 }]\ngid_map = []\n",
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
