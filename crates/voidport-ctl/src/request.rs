//! The local checks of a parsed command line, before contacting the server:
//! name syntax, required ownership modes and flags used with their own mode.
//! The server stays the authority on validity.

use anyhow::{Result, bail};
use voidport_control::{
    Listener, NamespaceName, NamespaceSpec, OwnershipSpec, Request, Rule, XattrRule,
};

use crate::cli::{
    AuthCommand, Command, DirectIoCommand, ListenerArgs, ListenerCommand, NamespaceCommand,
    OwnershipArgs, OwnershipCommand, OwnershipModeArg, PermissionCommand, PrivilegedBitsCommand,
    RuleCommand, SessionCommand, XattrCommand,
};

impl ListenerArgs {
    pub fn to_listener(&self) -> Result<Listener> {
        match (self.addr, &self.unix, self.vsock, &self.vhost_user) {
            (Some(addr), None, None, None) => Ok(Listener::Tcp { addr }),
            (None, Some(path), None, None) => Ok(Listener::Unix { path: path.clone() }),
            (None, None, Some(port), None) => Ok(Listener::vsock(port)),
            (None, None, None, Some(path)) => Ok(Listener::VhostUser { path: path.clone() }),
            // clap's argument group makes this unreachable; it is answered
            // instead of asserted because a CLI never panics at an operator.
            _ => bail!("listener add takes exactly one of --addr, --unix, --vsock or --vhost-user"),
        }
    }
}

impl OwnershipArgs {
    /// # Errors
    ///
    /// Fails if a per-mode flag is used with another mode, or if `static` is
    /// missing its ids.
    pub fn to_spec(&self, required: bool) -> Result<OwnershipSpec> {
        let Some(mode) = self.mode else {
            if required {
                bail!("--ownership is required: one of map, passthrough, static");
            }
            self.reject_map_flags()?;
            self.reject_static_flags()?;
            return Ok(OwnershipSpec::default());
        };
        match mode {
            OwnershipModeArg::Map => {
                self.reject_static_flags()?;
                Ok(OwnershipSpec::Map {
                    unmapped: self.unmapped.unwrap_or_default().into(),
                    squash_uid: self
                        .squash_uid
                        .unwrap_or(voidport_control::DEFAULT_SQUASH_ID),
                    squash_gid: self
                        .squash_gid
                        .unwrap_or(voidport_control::DEFAULT_SQUASH_ID),
                    uid_map: self.uid_map.clone(),
                    gid_map: self.gid_map.clone(),
                })
            }
            OwnershipModeArg::Passthrough => {
                self.reject_map_flags()?;
                self.reject_static_flags()?;
                Ok(OwnershipSpec::Passthrough {})
            }
            OwnershipModeArg::Static => {
                self.reject_map_flags()?;
                match (self.static_uid, self.static_gid) {
                    (Some(uid), Some(gid)) => Ok(OwnershipSpec::Static { uid, gid }),
                    _ => bail!("--ownership static requires --static-uid and --static-gid"),
                }
            }
        }
    }

    fn reject_map_flags(&self) -> Result<()> {
        if !self.uid_map.is_empty()
            || !self.gid_map.is_empty()
            || self.unmapped.is_some()
            || self.squash_uid.is_some()
            || self.squash_gid.is_some()
        {
            bail!("--uid-map, --gid-map, --unmapped and --squash-* apply only to --ownership map");
        }
        Ok(())
    }

    fn reject_static_flags(&self) -> Result<()> {
        if self.static_uid.is_some() || self.static_gid.is_some() {
            bail!("--static-uid and --static-gid apply only to --ownership static");
        }
        Ok(())
    }
}

fn namespace_name(name: &str) -> Result<NamespaceName> {
    Ok(NamespaceName::new(name)?)
}

impl Command {
    /// # Errors
    ///
    /// Fails on a name the protocol cannot carry, on an inconsistent
    /// combination of ownership flags, and on an `xattr add` stating no
    /// verdict at all.
    pub fn to_request(&self) -> Result<Request> {
        Ok(match self {
            Self::Info => Request::ServerInfo {},
            Self::Namespace(NamespaceCommand::List) => Request::NamespaceList {},
            Self::Namespace(NamespaceCommand::Show { name }) => Request::NamespaceShow {
                name: namespace_name(name)?,
            },
            Self::Namespace(NamespaceCommand::Create {
                name,
                ownership,
                permission,
                direct_io,
                auth,
            }) => Request::NamespaceCreate {
                namespace: NamespaceSpec {
                    name: namespace_name(name)?,
                    permission: (*permission).into(),
                    direct_io: (*direct_io).into(),
                    auth: (*auth).into(),
                    ownership: ownership.to_spec(false)?,
                    privileged_bits: true,
                    rules: Vec::new(),
                    xattr: Vec::new(),
                },
            },
            Self::Namespace(NamespaceCommand::Delete { name }) => Request::NamespaceDelete {
                name: namespace_name(name)?,
            },
            Self::Rule(RuleCommand::Add {
                namespace,
                path,
                mode,
                r#match,
                target,
            }) => Request::RuleAdd {
                namespace: namespace_name(namespace)?,
                rule: Rule {
                    path: path.clone(),
                    mode: (*mode).into(),
                    r#match: r#match.clone(),
                    target: target.clone(),
                },
            },
            Self::Rule(RuleCommand::Remove {
                namespace,
                path,
                r#match,
            }) => Request::RuleRemove {
                namespace: namespace_name(namespace)?,
                path: path.clone(),
                r#match: r#match.clone(),
            },
            Self::Xattr(XattrCommand::Add {
                namespace,
                r#match,
                read,
                write,
            }) => {
                if read.is_none() && write.is_none() {
                    bail!("xattr add requires --read, --write, or both: a rule states a verdict");
                }
                Request::XattrAdd {
                    namespace: namespace_name(namespace)?,
                    rule: XattrRule {
                        r#match: r#match.clone(),
                        read: read.map(Into::into),
                        write: write.map(Into::into),
                    },
                }
            }
            Self::Xattr(XattrCommand::Remove { namespace, r#match }) => Request::XattrRemove {
                namespace: namespace_name(namespace)?,
                r#match: r#match.clone(),
            },
            Self::Xattr(XattrCommand::List { namespace }) => Request::NamespaceShow {
                name: namespace_name(namespace)?,
            },
            Self::Ownership(OwnershipCommand::Set {
                namespace,
                ownership,
            }) => Request::OwnershipSet {
                namespace: namespace_name(namespace)?,
                ownership: ownership.to_spec(true)?,
            },
            Self::Permission(PermissionCommand::Set { namespace, mode }) => {
                Request::PermissionSet {
                    namespace: namespace_name(namespace)?,
                    mode: (*mode).into(),
                }
            }
            Self::DirectIo(DirectIoCommand::Set { namespace, posture }) => Request::DirectIoSet {
                namespace: namespace_name(namespace)?,
                posture: (*posture).into(),
            },
            Self::PrivilegedBits(PrivilegedBitsCommand::Enable { namespace }) => {
                Request::PrivilegedBitsSet {
                    namespace: namespace_name(namespace)?,
                    enabled: true,
                }
            }
            Self::PrivilegedBits(PrivilegedBitsCommand::Disable { namespace }) => {
                Request::PrivilegedBitsSet {
                    namespace: namespace_name(namespace)?,
                    enabled: false,
                }
            }
            Self::Auth(AuthCommand::Set { namespace, mode }) => Request::AuthSet {
                namespace: namespace_name(namespace)?,
                mode: (*mode).into(),
            },
            Self::Session(SessionCommand::List) => Request::SessionList {},
            Self::Listener(ListenerCommand::List) => Request::ServerInfo {},
            Self::Listener(ListenerCommand::Add { endpoint }) => Request::ListenerAdd {
                listener: endpoint.to_listener()?,
            },
            Self::Listener(ListenerCommand::Remove { endpoint }) => Request::ListenerRemove {
                endpoint: endpoint.clone(),
            },
            Self::Resolve { namespace, path } => Request::Resolve {
                namespace: namespace_name(namespace)?,
                path: path.clone(),
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use clap::Parser as _;
    use voidport_control::{
        IdMapping, IdSentinel, Listener, NamespaceName, NamespaceSpec, OwnershipSpec, Request,
        Rule, ShareMode, UnmappedPolicy, XattrRule, XattrVerdict,
    };

    use crate::cli::Cli;

    fn parse(arguments: &[&str]) -> Cli {
        Cli::try_parse_from(arguments).expect("valid command line")
    }

    #[test]
    fn every_operation_has_a_subcommand() {
        let commands: Vec<&[&str]> = vec![
            &["voidport-ctl", "info"],
            &["voidport-ctl", "namespace", "list"],
            &["voidport-ctl", "namespace", "show", "p"],
            &["voidport-ctl", "namespace", "create", "p"],
            &["voidport-ctl", "namespace", "delete", "p"],
            &["voidport-ctl", "rule", "add", "p", "/a", "--mode", "rw"],
            &["voidport-ctl", "rule", "remove", "p", "/a"],
            &[
                "voidport-ctl",
                "xattr",
                "add",
                "p",
                "user.*",
                "--write",
                "deny",
            ],
            &["voidport-ctl", "xattr", "remove", "p", "user.*"],
            &[
                "voidport-ctl",
                "ownership",
                "set",
                "p",
                "--ownership",
                "passthrough",
            ],
            &[
                "voidport-ctl",
                "permission",
                "set",
                "p",
                "--mode",
                "passthrough",
            ],
            &[
                "voidport-ctl",
                "direct-io",
                "set",
                "p",
                "--posture",
                "passthrough",
            ],
            &["voidport-ctl", "privileged-bits", "enable", "p"],
            &["voidport-ctl", "auth", "set", "p", "--mode", "none"],
            &["voidport-ctl", "session", "list"],
            &[
                "voidport-ctl",
                "listener",
                "add",
                "--addr",
                "127.0.0.1:9000",
            ],
            &["voidport-ctl", "listener", "remove", "127.0.0.1:9000"],
            &["voidport-ctl", "resolve", "p", "/a"],
        ];
        let operations: Vec<&str> = commands
            .iter()
            .map(|arguments| {
                parse(arguments)
                    .command
                    .to_request()
                    .expect("valid request")
                    .operation()
            })
            .collect();
        assert_eq!(operations, voidport_control::OPERATIONS);
    }

    #[test]
    fn the_privileged_bits_commands_are_one_operation_with_two_values() {
        for (command, enabled) in [("enable", true), ("disable", false)] {
            let request = parse(&["voidport-ctl", "privileged-bits", command, "p"])
                .command
                .to_request()
                .expect("valid request");
            assert_eq!(request.operation(), "privileged-bits-set");
            let voidport_control::Request::PrivilegedBitsSet { enabled: sent, .. } = request else {
                panic!("{command} does not set the switch");
            };
            assert_eq!(sent, enabled);
        }
    }

    #[test]
    fn listener_add_carries_one_transport_and_listing_reuses_server_info() {
        let cases: [(&[&str], Listener); 4] = [
            (
                &["voidport-ctl", "listener", "add", "--addr", "0.0.0.0:9000"],
                Listener::Tcp {
                    addr: "0.0.0.0:9000".parse().expect("valid address"),
                },
            ),
            (
                &[
                    "voidport-ctl",
                    "listener",
                    "add",
                    "--unix",
                    "/run/data.sock",
                ],
                Listener::Unix {
                    path: PathBuf::from("/run/data.sock"),
                },
            ),
            (
                &["voidport-ctl", "listener", "add", "--vsock", "1024"],
                Listener::vsock(1024),
            ),
            (
                &[
                    "voidport-ctl",
                    "listener",
                    "add",
                    "--vhost-user",
                    "/run/vhost-user.sock",
                ],
                Listener::VhostUser {
                    path: PathBuf::from("/run/vhost-user.sock"),
                },
            ),
        ];
        for (arguments, expected) in cases {
            let request = parse(arguments)
                .command
                .to_request()
                .expect("valid request");
            assert_eq!(request, Request::ListenerAdd { listener: expected });
        }

        assert_eq!(
            parse(&["voidport-ctl", "listener", "list"])
                .command
                .to_request()
                .expect("valid request"),
            Request::ServerInfo {}
        );

        assert!(
            Cli::try_parse_from([
                "voidport-ctl",
                "listener",
                "add",
                "--addr",
                "0.0.0.0:1",
                "--vsock",
                "1024",
            ])
            .is_err()
        );
        assert!(Cli::try_parse_from(["voidport-ctl", "listener", "add"]).is_err());
    }

    #[test]
    fn xattr_rules_are_keyed_by_their_match_and_state_the_verdicts_given() {
        let both = parse(&[
            "voidport-ctl",
            "xattr",
            "add",
            "p",
            "user.*",
            "--read",
            "allow",
            "--write",
            "deny",
        ])
        .command
        .to_request()
        .expect("valid request");
        assert_eq!(
            both,
            Request::XattrAdd {
                namespace: NamespaceName::new("p").expect("valid"),
                rule: XattrRule::new("user.*")
                    .with_read(XattrVerdict::Allow)
                    .with_write(XattrVerdict::Deny),
            }
        );

        let one = parse(&["voidport-ctl", "xattr", "add", "p", "*", "--write", "deny"])
            .command
            .to_request()
            .expect("valid request");
        assert_eq!(
            one,
            Request::XattrAdd {
                namespace: NamespaceName::new("p").expect("valid"),
                rule: XattrRule::new("*").with_write(XattrVerdict::Deny),
            }
        );

        let refused = parse(&["voidport-ctl", "xattr", "add", "p", "user.*"])
            .command
            .to_request()
            .expect_err("a rule states a verdict");
        assert!(refused.to_string().contains("--read"), "{refused}");
        assert!(refused.to_string().contains("--write"), "{refused}");

        assert_eq!(
            parse(&["voidport-ctl", "xattr", "remove", "p", "user.*"])
                .command
                .to_request()
                .expect("valid request"),
            Request::XattrRemove {
                namespace: NamespaceName::new("p").expect("valid"),
                r#match: "user.*".to_owned(),
            }
        );

        assert_eq!(
            parse(&["voidport-ctl", "xattr", "list", "p"])
                .command
                .to_request()
                .expect("valid request"),
            Request::NamespaceShow {
                name: NamespaceName::new("p").expect("valid"),
            }
        );

        assert!(
            Cli::try_parse_from(["voidport-ctl", "xattr", "add", "p", "*", "--read", "maybe"])
                .is_err(),
            "a verdict the schema does not define is refused at the command line"
        );
    }

    #[test]
    fn rules_carry_their_mode_and_optional_target() {
        let request = parse(&[
            "voidport-ctl",
            "rule",
            "add",
            "p",
            "/project",
            "--mode",
            "rw",
            "--target",
            "project",
        ])
        .command
        .to_request()
        .expect("valid request");
        assert_eq!(
            request,
            Request::RuleAdd {
                namespace: NamespaceName::new("p").expect("valid"),
                rule: Rule::new("/project", ShareMode::Rw).with_target("project"),
            }
        );

        let hidden = parse(&[
            "voidport-ctl",
            "rule",
            "add",
            "p",
            "/a/*",
            "--mode",
            "hidden",
        ])
        .command
        .to_request()
        .expect("valid request");
        assert_eq!(
            hidden,
            Request::RuleAdd {
                namespace: NamespaceName::new("p").expect("valid"),
                rule: Rule::new("/a/*", ShareMode::Hidden),
            }
        );
    }

    #[test]
    fn a_pattern_rule_is_a_path_and_a_match_on_both_commands() {
        let added = parse(&[
            "voidport-ctl",
            "rule",
            "add",
            "p",
            "/a",
            "--mode",
            "rw",
            "--match",
            "project-*",
        ])
        .command
        .to_request()
        .expect("valid request");
        assert_eq!(
            added,
            Request::RuleAdd {
                namespace: NamespaceName::new("p").expect("valid"),
                rule: Rule::new("/a", ShareMode::Rw).with_match("project-*"),
            }
        );

        let removed = parse(&[
            "voidport-ctl",
            "rule",
            "remove",
            "p",
            "/a",
            "--match",
            "project-*",
        ])
        .command
        .to_request()
        .expect("valid request");
        assert_eq!(
            removed,
            Request::RuleRemove {
                namespace: NamespaceName::new("p").expect("valid"),
                path: "/a".to_owned(),
                r#match: Some("project-*".to_owned()),
            }
        );

        let plain = parse(&["voidport-ctl", "rule", "remove", "p", "/a"])
            .command
            .to_request()
            .expect("valid request");
        assert_eq!(
            plain,
            Request::RuleRemove {
                namespace: NamespaceName::new("p").expect("valid"),
                path: "/a".to_owned(),
                r#match: None,
            }
        );
    }

    #[test]
    fn ownership_flags_build_each_mode() {
        let mapped = parse(&[
            "voidport-ctl",
            "ownership",
            "set",
            "p",
            "--ownership",
            "map",
            "--uid-map",
            "uid:0",
            "--uid-map",
            "1001:1",
            "--gid-map",
            "gid:0",
            "--unmapped",
            "hide",
            "--squash-uid",
            "7",
            "--squash-gid",
            "8",
        ])
        .command
        .to_request()
        .expect("valid request");
        assert_eq!(
            mapped,
            Request::OwnershipSet {
                namespace: NamespaceName::new("p").expect("valid"),
                ownership: OwnershipSpec::Map {
                    unmapped: UnmappedPolicy::Hide,
                    squash_uid: 7,
                    squash_gid: 8,
                    uid_map: vec![
                        IdMapping::new(IdSentinel::Uid, 0),
                        IdMapping::new(1001u32, 1),
                    ],
                    gid_map: vec![IdMapping::new(IdSentinel::Gid, 0)],
                },
            }
        );

        let fixed = parse(&[
            "voidport-ctl",
            "ownership",
            "set",
            "p",
            "--ownership",
            "static",
            "--static-uid",
            "0",
            "--static-gid",
            "0",
        ])
        .command
        .to_request()
        .expect("valid request");
        assert_eq!(
            fixed,
            Request::OwnershipSet {
                namespace: NamespaceName::new("p").expect("valid"),
                ownership: OwnershipSpec::Static { uid: 0, gid: 0 },
            }
        );
    }

    #[test]
    fn inconsistent_ownership_flags_are_refused_before_a_round_trip() {
        let cases: Vec<&[&str]> = vec![
            &[
                "voidport-ctl",
                "ownership",
                "set",
                "p",
                "--ownership",
                "static",
            ],
            &[
                "voidport-ctl",
                "ownership",
                "set",
                "p",
                "--ownership",
                "passthrough",
                "--unmapped",
                "hide",
            ],
            &[
                "voidport-ctl",
                "ownership",
                "set",
                "p",
                "--ownership",
                "map",
                "--static-uid",
                "0",
            ],
            &["voidport-ctl", "ownership", "set", "p"],
            &[
                "voidport-ctl",
                "namespace",
                "create",
                "p",
                "--uid-map",
                "uid:0",
            ],
        ];
        for arguments in cases {
            assert!(
                parse(arguments).command.to_request().is_err(),
                "expected {arguments:?} to be refused"
            );
        }
    }

    #[test]
    fn a_create_without_ownership_flags_defaults_to_passthrough() {
        let request = parse(&["voidport-ctl", "namespace", "create", "p"])
            .command
            .to_request()
            .expect("valid request");
        assert_eq!(
            request,
            Request::NamespaceCreate {
                namespace: NamespaceSpec::new(NamespaceName::new("p").expect("valid")),
            }
        );
    }

    #[test]
    fn an_invalid_namespace_name_is_caught_locally() {
        let error = parse(&["voidport-ctl", "namespace", "show", "a/b"])
            .command
            .to_request()
            .expect_err("invalid name");
        assert!(error.to_string().contains("separator"), "{error}");
    }
}
