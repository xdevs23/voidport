use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};
use voidport_control::{
    AuthMode, HostDirectIo, HostId, IdMapping, IdSentinel, PermissionMode, ShareMode,
    UnmappedPolicy, XattrVerdict,
};

/// The voidport operator CLI.
#[derive(Debug, Parser)]
#[command(name = "voidport-ctl", version, about)]
pub struct Cli {
    /// The control socket of the running server. Without it, a local instance
    /// is looked for: `$XDG_STATE_HOME/voidport/control.sock` (the socket a
    /// `voidportd share` launch seeds, `~/.local/state/…` when the variable is
    /// unset) and then `/run/voidport/control.sock`. The first that answers is
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
    /// Show how a path resolves under the rules of a namespace: the mode and
    /// host path the rules admit, a synthesized directory, or absent. Hidden
    /// and absent give the same result. Neither the host nor the ownership
    /// policy is consulted. Changes nothing.
    Resolve {
        /// The namespace.
        namespace: String,
        /// The absolute namespace path.
        path: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum ListenerCommand {
    /// List the endpoints the server is serving on right now.
    List,
    /// Bind a listener and serve it, now and after a restart.
    ///
    /// Exactly one transport per invocation. The endpoint printed is the one
    /// that actually bound, which for `--addr HOST:0` is the only place the
    /// port the kernel chose is ever shown. It is the name `listener remove`
    /// takes.
    Add {
        /// The transport to bind.
        #[command(flatten)]
        endpoint: ListenerArgs,
    },
    /// Close a listener, now and after a restart.
    ///
    /// No new connection arrives on it once this returns. Sessions already
    /// mounted through it keep serving until their connections end: removing a
    /// listener is not an eviction.
    Remove {
        /// The endpoint exactly as `listener list` shows it.
        endpoint: String,
    },
}

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
    /// Port 0 asks the server for a free one.
    #[arg(long, value_name = "PORT")]
    pub vsock: Option<u32>,
    /// A vhost-user socket path, where the frontend of a virtio device sets
    /// the device up. The server creates it readable and writable by the
    /// account that runs the server only, and unlinks it when the listener
    /// goes away.
    #[arg(long, value_name = "PATH")]
    pub vhost_user: Option<PathBuf>,
}

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

#[derive(Debug, Subcommand)]
pub enum RuleCommand {
    /// Add one rule.
    Add {
        /// The namespace.
        namespace: String,
        /// The rule path: `/a/b`, `/a/*` for the per-directory default, or,
        /// with `--match`, the directory whose children the match covers.
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

#[derive(Debug, Subcommand)]
pub enum XattrCommand {
    /// Add one extended-attribute rule. It must state at least one of --read
    /// and --write.
    ///
    /// With no rules at all a namespace reads every attribute and writes only
    /// `user.*`. Setting `system.posix_acl_*` always answers EPERM regardless
    /// of rules, because a valid ACL blob rewrites permission bits. Removing
    /// either exact name `system.posix_acl_access` or `system.posix_acl_default`
    /// answers ENODATA when absent or hidden by read policy, and EPERM when
    /// present and readable. Read-only shares answer EROFS first.
    Add {
        /// The namespace.
        namespace: String,
        /// A glob over attribute NAMES: `*` covers any run of bytes including
        /// none, every other byte is literal, and a bare `*` covers everything.
        /// Among the rules covering a name the longest literal prefix wins,
        /// and a tie is decided by deny.
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

#[derive(Debug, Subcommand)]
pub enum PrivilegedBitsCommand {
    /// Record and present setuid and setgid on this namespace.
    ///
    /// The default. The files on the host never have the bits: the server
    /// records them and merges them into what a guest is shown. What they mean
    /// is decided by the guest kernel, in its own trust domain.
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

#[derive(Debug, Subcommand)]
pub enum SessionCommand {
    /// List the sessions the server is currently serving.
    List,
}

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

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum OwnershipModeArg {
    /// Explicit translation tables.
    Map,
    /// Host ids as-is.
    Passthrough,
    /// One owner for everything.
    Static,
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn the_command_line_is_well_formed() {
        Cli::command().debug_assert();
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
}
