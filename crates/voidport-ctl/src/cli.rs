//! The command line: one subcommand per control operation.
//!
//! The whole of this module is a translation from operator ergonomics to the
//! typed [`Request`] — flags to a source-form policy value, nothing more. It
//! deliberately performs no validation the server would repeat: the server is
//! the authority on whether a rule table is valid, and a CLI that guessed
//! could disagree with it.
//!
//! Two things *are* checked here, because they are about the command line,
//! not about policy: that an ownership mode was given where one is
//! required, and that per-mode flags are used with their own mode.

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{Result, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use voidport_control::{
    AuthMode, HostDirectIo, HostId, IdMapping, IdSentinel, Listener, NamespaceName, NamespaceSpec,
    OwnershipSpec, PermissionMode, Request, Rule, ShareMode, UnmappedPolicy, XattrRule,
    XattrVerdict,
};

/// The voidport operator CLI.
#[derive(Debug, Parser)]
#[command(name = "voidport-ctl", version, about)]
pub struct Cli {
    /// The control socket of the running server. Without it, a local instance
    /// is looked for: `$XDG_STATE_HOME/voidport/control.sock` (the socket a
    /// `voidportd share` launch seeds, `~/.local/state/…` when the variable is
    /// unset) and then `/run/voidport/control.sock` — the first that answers is
    /// used, and an error naming both is printed if neither does.
    #[arg(long, short = 's', value_name = "PATH")]
    pub socket: Option<PathBuf>,
    /// Print the response envelope verbatim, as JSON.
    #[arg(long, global = true)]
    pub json: bool,
    /// What to do.
    #[command(subcommand)]
    pub command: Command,
}

/// The operations, grouped the way an operator thinks about them.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Show server version, state file and control socket.
    Info,
    /// Namespace operations.
    #[command(subcommand)]
    Namespace(NamespaceCommand),
    /// Rule operations. A rule is changed by removing and re-adding it.
    #[command(subcommand)]
    Rule(RuleCommand),
    /// Extended-attribute rules: which attribute names a guest may read and
    /// write. Per namespace, and changed by removing and re-adding.
    #[command(subcommand)]
    Xattr(XattrCommand),
    /// Ownership policy operations.
    #[command(subcommand)]
    Ownership(OwnershipCommand),
    /// Permission mode operations.
    #[command(subcommand)]
    Permission(PermissionCommand),
    /// Host-side direct-I/O operations: whether the server's backing reads and
    /// writes ride the host page cache.
    #[command(subcommand)]
    DirectIo(DirectIoCommand),
    /// Privileged mode bits (setuid, setgid): whether a namespace records and
    /// presents them.
    #[command(subcommand)]
    PrivilegedBits(PrivilegedBitsCommand),
    /// Auth mode operations.
    #[command(subcommand)]
    Auth(AuthCommand),
    /// Data-plane session inspection.
    #[command(subcommand)]
    Session(SessionCommand),
    /// Data-plane listener operations: where the server accepts mounts.
    #[command(subcommand)]
    Listener(ListenerCommand),
    /// Show how a path resolves in a namespace: the mode and host path a
    /// guest would get, a synthesized directory, or absent. Hidden and
    /// absent answer alike, as they do to a guest. Changes nothing.
    Resolve {
        /// The namespace.
        namespace: String,
        /// The absolute namespace path.
        path: String,
    },
}

/// `voidport-ctl listener …`
#[derive(Debug, Subcommand)]
pub enum ListenerCommand {
    /// List the endpoints the server is serving on right now.
    List,
    /// Bind a listener and serve it, now and after a restart.
    ///
    /// Exactly one transport per invocation. The endpoint printed is the one
    /// that actually bound, which for `--addr HOST:0` is the only place the
    /// port the kernel chose is ever stated — and it is the name `listener
    /// remove` takes.
    Add {
        /// The transport to bind.
        #[command(flatten)]
        endpoint: ListenerArgs,
    },
    /// Close a listener, now and after a restart.
    ///
    /// No new connection lands on it once this returns. Sessions already
    /// mounted through it keep serving until their connections end: removing a
    /// listener is not an eviction.
    Remove {
        /// The endpoint exactly as `listener list` shows it.
        endpoint: String,
    },
}

/// Which transport `listener add` binds. Exactly one of the three.
#[derive(Args, Debug)]
#[group(required = true, multiple = false)]
pub struct ListenerArgs {
    /// A tcp endpoint, `HOST:PORT`. Port 0 asks the kernel for a free one.
    #[arg(long, value_name = "HOST:PORT")]
    pub addr: Option<SocketAddr>,
    /// A unix socket path. The server creates it owner-only and unlinks it
    /// when the listener goes away.
    #[arg(long, value_name = "PATH")]
    pub unix: Option<PathBuf>,
    /// A vsock port, for guests of this machine's hypervisor. The range is
    /// 1..=65535, because a mount URL's port is the URL standard's 16-bit one.
    #[arg(long, value_name = "PORT")]
    pub vsock: Option<u32>,
}

impl ListenerArgs {
    /// The listener these flags describe.
    ///
    /// The cid is not offered: a listener bound to the wildcard is reachable
    /// from every guest of this machine, which is the bind an operator wants,
    /// and the state file remains the way to name a specific one.
    fn to_listener(&self) -> Result<Listener> {
        match (self.addr, &self.unix, self.vsock) {
            (Some(addr), None, None) => Ok(Listener::Tcp { addr }),
            (None, Some(path), None) => Ok(Listener::Unix { path: path.clone() }),
            (None, None, Some(port)) => Ok(Listener::vsock(port)),
            // clap's argument group makes this unreachable; it is answered
            // instead of asserted because a CLI never panics at an operator.
            _ => bail!("listener add takes exactly one of --addr, --unix or --vsock"),
        }
    }
}

/// `voidport-ctl namespace …`
#[derive(Debug, Subcommand)]
pub enum NamespaceCommand {
    /// List every namespace.
    List,
    /// Show one namespace in the form the state file holds it.
    Show {
        /// The namespace.
        name: String,
    },
    /// Create a namespace. It starts empty: nothing resolves until rules are
    /// added.
    Create {
        /// The namespace name.
        name: String,
        /// Its ownership policy; defaults to `passthrough`.
        #[command(flatten)]
        ownership: OwnershipArgs,
        /// Its permission mode.
        #[arg(long, value_enum, default_value_t = PermissionModeArg::Passthrough)]
        permission: PermissionModeArg,
        /// Where its backing I/O sits with respect to the host page cache.
        #[arg(long, value_enum, default_value_t = DirectIoArg::Cached)]
        direct_io: DirectIoArg,
        /// Its auth mode.
        #[arg(long, value_enum, default_value_t = AuthModeArg::None)]
        auth: AuthModeArg,
    },
    /// Delete a namespace. Sessions already mounted keep serving their
    /// snapshot; new mounts fail.
    Delete {
        /// The namespace.
        name: String,
    },
}

/// `voidport-ctl rule …`
#[derive(Debug, Subcommand)]
pub enum RuleCommand {
    /// Add one rule.
    Add {
        /// The namespace.
        namespace: String,
        /// The rule path: `/a/b`, `/a/*` for the per-directory default, or —
        /// with `--match` — the directory whose children the match covers.
        path: String,
        /// The share mode.
        #[arg(long, value_enum)]
        mode: ShareModeArg,
        /// A glob over the child names of PATH, making this a pattern rule:
        /// `--match 'project-*'` governs every child of PATH whose name it
        /// covers. `*` matches any run of bytes, including none; a leading `*`
        /// does not cover names starting with `.`. Mode-only: never combined
        /// with --target.
        #[arg(long, value_name = "GLOB")]
        r#match: Option<String>,
        /// The host path: absolute, or relative to the state file's directory.
        /// Required on a rule that attaches a directory, omitted where the
        /// enclosing rule supplies it, and never given for a wildcard,
        /// pattern or hidden rule.
        #[arg(long, value_name = "PATH")]
        target: Option<String>,
    },
    /// Remove the rule at a path.
    Remove {
        /// The namespace.
        namespace: String,
        /// The rule path, exactly as it was added.
        path: String,
        /// The match of the pattern rule to remove, exactly as it was added:
        /// a pattern rule is keyed by its path and its match together.
        #[arg(long, value_name = "GLOB")]
        r#match: Option<String>,
    },
}

/// `voidport-ctl xattr …`
#[derive(Debug, Subcommand)]
pub enum XattrCommand {
    /// Add one extended-attribute rule. It must state at least one of --read
    /// and --write.
    ///
    /// With no rules at all a namespace reads every attribute and writes only
    /// `user.*`; writes to `system.posix_acl_*` are refused whatever any rule
    /// says, because a valid ACL blob rewrites a file's permission bits.
    Add {
        /// The namespace.
        namespace: String,
        /// A glob over attribute NAMES: `*` covers any run of bytes including
        /// none, every other byte is literal, and a bare `*` covers everything.
        /// At most 255 bytes. Among the rules covering a name the longest
        /// literal prefix wins, and a tie is decided by deny.
        #[arg(value_name = "GLOB")]
        r#match: String,
        /// What reading a covered attribute does. Unstated falls through to the
        /// next matching rule, and then to the defaults.
        #[arg(long, value_enum)]
        read: Option<XattrVerdictArg>,
        /// What writing a covered attribute does, on the same fall-through.
        #[arg(long, value_enum)]
        write: Option<XattrVerdictArg>,
    },
    /// Remove the extended-attribute rule with that match.
    Remove {
        /// The namespace.
        namespace: String,
        /// The match, exactly as it was added: a rule is keyed by it.
        #[arg(value_name = "GLOB")]
        r#match: String,
    },
    /// List a namespace's extended-attribute rules.
    List {
        /// The namespace.
        namespace: String,
    },
}

/// The verdicts a rule states.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum XattrVerdictArg {
    /// Let the operation through to the host, whose own answer comes back.
    Allow,
    /// Refuse it in the namespace, before the host is touched.
    Deny,
}

impl From<XattrVerdictArg> for XattrVerdict {
    fn from(verdict: XattrVerdictArg) -> Self {
        match verdict {
            XattrVerdictArg::Allow => Self::Allow,
            XattrVerdictArg::Deny => Self::Deny,
        }
    }
}

/// `voidport-ctl ownership …`
#[derive(Debug, Subcommand)]
pub enum OwnershipCommand {
    /// Replace a namespace's ownership policy, whole.
    Set {
        /// The namespace.
        namespace: String,
        /// The new policy.
        #[command(flatten)]
        ownership: OwnershipArgs,
    },
}

/// `voidport-ctl permission …`
#[derive(Debug, Subcommand)]
pub enum PermissionCommand {
    /// Set a namespace's permission mode.
    Set {
        /// The namespace.
        namespace: String,
        /// The mode.
        #[arg(long, value_enum)]
        mode: PermissionModeArg,
    },
}

/// `voidport-ctl direct-io …`
#[derive(Debug, Subcommand)]
pub enum DirectIoCommand {
    /// Set where a namespace's backing I/O sits: on the host page cache, or
    /// past it. Live at the next open; handles already open keep the posture
    /// they were opened under.
    Set {
        /// The namespace.
        namespace: String,
        /// The posture.
        #[arg(long, value_enum)]
        posture: DirectIoArg,
    },
}

/// `voidport-ctl privileged-bits …`
#[derive(Debug, Subcommand)]
pub enum PrivilegedBitsCommand {
    /// Record and present setuid and setgid on this namespace.
    ///
    /// The default. The server's own host backing never carries the bits — it
    /// records them and merges them into what a guest is shown — and what they
    /// mean is the guest kernel's decision, in its own trust domain.
    Enable {
        /// The namespace.
        namespace: String,
    },
    /// Mask setuid and setgid on this namespace.
    ///
    /// Recorded and host-real bits alike stop being shown, and a chmod that
    /// would set one is refused. Recorded truth is kept, not discarded:
    /// enabling the switch again presents it.
    Disable {
        /// The namespace.
        namespace: String,
    },
}

/// `voidport-ctl auth …`
#[derive(Debug, Subcommand)]
pub enum AuthCommand {
    /// Set a namespace's auth mode.
    Set {
        /// The namespace.
        namespace: String,
        /// The mode.
        #[arg(long, value_enum)]
        mode: AuthModeArg,
    },
}

/// `voidport-ctl session …`
#[derive(Debug, Subcommand)]
pub enum SessionCommand {
    /// List the sessions the server is currently serving.
    List,
}

/// The flags that describe an ownership policy.
#[derive(Debug, Args)]
pub struct OwnershipArgs {
    /// The ownership mode.
    #[arg(long = "ownership", value_enum, value_name = "MODE")]
    pub mode: Option<OwnershipModeArg>,
    /// A uid mapping, `HOST:GUEST`, where `HOST` is a number or the sentinel
    /// `uid`/`gid`. Repeatable. Only with `--ownership map`.
    #[arg(long = "uid-map", value_name = "HOST:GUEST", value_parser = parse_mapping)]
    pub uid_map: Vec<IdMapping>,
    /// A gid mapping, as `--uid-map`.
    #[arg(long = "gid-map", value_name = "HOST:GUEST", value_parser = parse_mapping)]
    pub gid_map: Vec<IdMapping>,
    /// What to do with host ids no mapping covers. Only with
    /// `--ownership map`.
    #[arg(long, value_enum)]
    pub unmapped: Option<UnmappedArg>,
    /// The uid unmapped host uids present as. Only with `--ownership map`.
    #[arg(long, value_name = "UID")]
    pub squash_uid: Option<u32>,
    /// The gid unmapped host gids present as. Only with `--ownership map`.
    #[arg(long, value_name = "GID")]
    pub squash_gid: Option<u32>,
    /// The uid everything presents as. Required with `--ownership static`.
    #[arg(long, value_name = "UID")]
    pub static_uid: Option<u32>,
    /// The gid everything presents as. Required with `--ownership static`.
    #[arg(long, value_name = "GID")]
    pub static_gid: Option<u32>,
}

impl OwnershipArgs {
    /// The policy these flags describe, or the default when no mode is given.
    ///
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

    /// Refuses the map-only flags.
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

    /// Refuses the static-only flags.
    fn reject_static_flags(&self) -> Result<()> {
        if self.static_uid.is_some() || self.static_gid.is_some() {
            bail!("--static-uid and --static-gid apply only to --ownership static");
        }
        Ok(())
    }
}

/// The ownership modes, as the command line spells them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum OwnershipModeArg {
    /// Explicit translation tables.
    Map,
    /// Host ids as-is.
    Passthrough,
    /// One owner for everything.
    Static,
}

/// The unmapped-id policies.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
pub enum UnmappedArg {
    /// Present the squash id.
    #[default]
    Squash,
    /// Hide the file.
    Hide,
    /// Present the raw id.
    Passthrough,
}

impl From<UnmappedArg> for UnmappedPolicy {
    fn from(policy: UnmappedArg) -> Self {
        match policy {
            UnmappedArg::Squash => Self::Squash,
            UnmappedArg::Hide => Self::Hide,
            UnmappedArg::Passthrough => Self::Passthrough,
        }
    }
}

/// The share modes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum ShareModeArg {
    /// Read-write.
    Rw,
    /// Read-only.
    Ro,
    /// Hidden.
    Hidden,
}

impl From<ShareModeArg> for ShareMode {
    fn from(mode: ShareModeArg) -> Self {
        match mode {
            ShareModeArg::Rw => Self::Rw,
            ShareModeArg::Ro => Self::Ro,
            ShareModeArg::Hidden => Self::Hidden,
        }
    }
}

/// The permission modes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum PermissionModeArg {
    /// Host bits as-is.
    Passthrough,
}

impl From<PermissionModeArg> for PermissionMode {
    fn from(PermissionModeArg::Passthrough: PermissionModeArg) -> Self {
        Self::Passthrough
    }
}

/// The host-side direct-I/O postures.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum DirectIoArg {
    /// Backing I/O rides the host page cache.
    Cached,
    /// A guest handle opened `O_DIRECT` opens the backing file `O_DIRECT`,
    /// alignment demands and all.
    Passthrough,
    /// Every backing open is uncached.
    Always,
}

impl From<DirectIoArg> for HostDirectIo {
    fn from(posture: DirectIoArg) -> Self {
        match posture {
            DirectIoArg::Cached => Self::Cached,
            DirectIoArg::Passthrough => Self::Passthrough,
            DirectIoArg::Always => Self::Always,
        }
    }
}

/// The auth modes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum AuthModeArg {
    /// No authentication.
    None,
}

impl From<AuthModeArg> for AuthMode {
    fn from(AuthModeArg::None: AuthModeArg) -> Self {
        Self::None
    }
}

/// Parses a `HOST:GUEST` mapping, where `HOST` may be a sentinel.
fn parse_mapping(value: &str) -> Result<IdMapping, String> {
    let Some((host, guest)) = value.rsplit_once(':') else {
        return Err(format!("expected HOST:GUEST, got {value:?}"));
    };
    let host = match host {
        "uid" => HostId::Sentinel(IdSentinel::Uid),
        "gid" => HostId::Sentinel(IdSentinel::Gid),
        number => HostId::Numeric(
            number
                .parse()
                .map_err(|_| format!("{number:?} is neither an id nor the sentinel uid/gid"))?,
        ),
    };
    let guest = guest
        .parse()
        .map_err(|_| format!("{guest:?} is not a guest id"))?;
    Ok(IdMapping { host, guest })
}

/// Validates a namespace name on this side too, so a typo is reported before a
/// round trip.
fn namespace_name(name: &str) -> Result<NamespaceName> {
    Ok(NamespaceName::new(name)?)
}

impl Command {
    /// The request this command sends.
    ///
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
                    // A create takes the default; the switch has an
                    // operation of its own.
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
                // A rule that states neither verdict decides nothing while
                // holding its match against a rule that would; the server
                // refuses it, and there is no reason to make an operator wait
                // for the round trip to hear so.
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
            // Listing is `namespace show` narrowed to one table: the server
            // already answers the whole source form, so a second read operation
            // would be a second way to ask one question.
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
            // Listing reuses `server-info`'s bound-listener field: the server
            // already answers where it is serving, and a second read operation
            // would be a second way to ask one question.
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
    use super::*;
    use clap::CommandFactory;

    fn parse(arguments: &[&str]) -> Cli {
        Cli::try_parse_from(arguments).expect("valid command line")
    }

    #[test]
    fn the_command_line_is_well_formed() {
        Cli::command().debug_assert();
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

    /// The two spellings of the one switch: `enable` and `disable` are the same
    /// operation carrying opposite values, which is why only one of them
    /// appears in the coverage list above.
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

    /// Each transport builds the listener the state file would hold, and
    /// listing asks the one read operation the server already has.
    #[test]
    fn listener_add_carries_one_transport_and_listing_reuses_server_info() {
        let cases: [(&[&str], Listener); 3] = [
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

        // Two transports at once is a command line the CLI never sends.
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

        // A verdict nobody stated stays unstated, which is what makes the
        // per-verdict fall-through reachable from the command line at all.
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

        // Neither verdict is not a rule, and the refusal is here, not a
        // round trip away.
        let refused = parse(&["voidport-ctl", "xattr", "add", "p", "user.*"])
            .command
            .to_request()
            .expect_err("a rule states a verdict");
        assert!(refused.to_string().contains("--read"), "{refused}");

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

        // Listing asks the one read operation the server already has.
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

        // Without the flag, removal names the rule that has no match — the
        // literal or wildcard rule at that path.
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
            // static without its ids
            &[
                "voidport-ctl",
                "ownership",
                "set",
                "p",
                "--ownership",
                "static",
            ],
            // map-only flags on another mode
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
            // static-only flags on another mode
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
            // no mode at all, where one is required
            &["voidport-ctl", "ownership", "set", "p"],
            // map flags on a create that did not ask for map
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
    fn mappings_parse_sentinels_and_numbers() {
        assert_eq!(
            parse_mapping("uid:0"),
            Ok(IdMapping::new(IdSentinel::Uid, 0))
        );
        assert_eq!(
            parse_mapping("gid:65534"),
            Ok(IdMapping::new(IdSentinel::Gid, 65534))
        );
        assert_eq!(parse_mapping("1000:0"), Ok(IdMapping::new(1000u32, 0)));
        assert!(parse_mapping("root:0").is_err());
        assert!(parse_mapping("1000").is_err());
        assert!(parse_mapping("1000:root").is_err());
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
