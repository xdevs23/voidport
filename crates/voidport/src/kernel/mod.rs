//! The module reads typed options and parses no URL. Every value goes to the
//! kernel as one parameter of its own through the filesystem context API, so no
//! byte of a value is read as option syntax. The mount source is the URL as it
//! was written, so that a tool such as `mount -a`, which compares the mount
//! table with fstab, finds the mount.

mod log;
mod options;
#[cfg(test)]
mod tests;

use std::borrow::Cow;
use std::fmt;
use std::io;
use std::net::{SocketAddr, ToSocketAddrs as _};
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};

use rustix::fs::{CWD, Mode, OFlags, openat};
use rustix::io::Errno;
use rustix::mount::{
    FsMountFlags, FsOpenFlags, FsPickFlags, MoveMountFlags, fsconfig_create, fsconfig_reconfigure,
    fsconfig_set_binary, fsconfig_set_flag, fsconfig_set_string, fsmount, fsopen, fspick,
    mount_remount, move_mount,
};
use voidport_session::options::{MountOption, ValueKind};

pub use self::log::KernelLog;
pub use self::options::KernelMountOptions;
use self::options::{Given, option_name};
use crate::url::{Endpoint, MountUrl, UrlError, VSOCK_SCHEME};

const FILESYSTEM_TYPE: &str = "voidport";

/// `fsconfig(2)` copies at most 256 bytes of a string value, the terminating NUL
/// included (the `FSCONFIG_SET_STRING` case of `fsconfig` in `fs/fsopen.c`,
/// <https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/fs/fsopen.c?h=v6.18.56>). A value of [`ValueKind::Bytes`] goes as a blob and
/// has no such bound.
const STRING_MAX: usize = 255;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Availability {
    Usable,
    /// The module is not loaded, or the kernel has no filesystem context API.
    NoModule,
    NotPermitted,
}

pub fn availability() -> Result<Availability, KernelError> {
    match open_context() {
        Ok(_) => Ok(Availability::Usable),
        Err(KernelError::NoModule) => Ok(Availability::NoModule),
        Err(KernelError::NotPermitted) => Ok(Availability::NotPermitted),
        Err(error) => Err(error),
    }
}

pub fn can_dial(endpoint: &Endpoint) -> bool {
    Route::of(endpoint).is_ok()
}

fn open_context() -> Result<OwnedFd, KernelError> {
    fsopen(FILESYSTEM_TYPE, FsOpenFlags::FSOPEN_CLOEXEC).map_err(|error| match error {
        // A kernel without fsopen has no filesystem context API, and the
        // module cannot be loaded there.
        Errno::NODEV | Errno::NOSYS => KernelError::NoModule,
        Errno::PERM => KernelError::NotPermitted,
        error => KernelError::Context {
            source: error.into(),
        },
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Server(Address);

#[derive(Clone, Debug, PartialEq, Eq)]
enum Address {
    Tcp(SocketAddr),
    Unix(PathBuf),
}

impl fmt::Display for Server {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            Address::Tcp(address) => write!(f, "{address}"),
            Address::Unix(path) => write!(f, "{}", path.display()),
        }
    }
}

enum Route<'a> {
    Tcp { host: &'a str, port: u16 },
    Unix(&'a Path),
}

impl<'a> Route<'a> {
    fn of(endpoint: &'a Endpoint) -> Result<Self, KernelError> {
        match endpoint {
            Endpoint::Tcp { host, port } => Ok(Self::Tcp { host, port: *port }),
            Endpoint::Unix { path } => Ok(Self::Unix(path)),
            Endpoint::Vsock { .. } => Err(KernelError::Vsock),
        }
    }

    fn servers(&self) -> Result<Servers, KernelError> {
        match *self {
            Self::Tcp { host, port } => {
                let mut servers = (host, port)
                    .to_socket_addrs()
                    .map_err(|source| KernelError::Lookup {
                        host: host.to_owned(),
                        source,
                    })?
                    .map(|address| Server(Address::Tcp(address)));
                let first = servers.next().ok_or_else(|| KernelError::NoAddress {
                    host: host.to_owned(),
                })?;
                Ok(Servers {
                    first,
                    rest: servers.collect(),
                })
            }
            Self::Unix(path) => Ok(Servers {
                first: Server(Address::Unix(path.to_owned())),
                rest: Vec::new(),
            }),
        }
    }
}

struct Servers {
    first: Server,
    rest: Vec<Server>,
}

impl Servers {
    fn iter(&self) -> impl Iterator<Item = &Server> {
        std::iter::once(&self.first).chain(&self.rest)
    }
}

/// Tries `attempt` on each server in order until one mounts. A refusal from a
/// server lets the next one be tried, and any other failure, or a refusal
/// from the last server, ends the attempt with it.
fn first_mounted(
    servers: &Servers,
    mut attempt: impl FnMut(&Server) -> Result<(), KernelError>,
) -> Result<(), KernelError> {
    let mut result = attempt(&servers.first);
    for server in &servers.rest {
        if !matches!(result, Err(KernelError::Refused { .. })) {
            break;
        }
        result = attempt(server);
    }
    result
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SharePart {
    option: MountOption,
    value: Vec<u8>,
}

impl SharePart {
    fn new(option: MountOption, value: impl Into<Vec<u8>>) -> Self {
        Self {
            option,
            value: value.into(),
        }
    }

    fn set(&self, context: &OwnedFd) -> rustix::io::Result<()> {
        let name = self.option.name();
        match self.option.value_kind() {
            ValueKind::Bytes => fsconfig_set_binary(context, name, &self.value),
            ValueKind::String | ValueKind::U32 => {
                fsconfig_set_string(context, name, self.value.as_slice())
            }
            ValueKind::Flag => fsconfig_set_flag(context, name),
        }
    }
}

fn share(written: &str, url: &MountUrl, server: &Server) -> Vec<SharePart> {
    let mut parts = vec![
        SharePart::new(MountOption::Source, written),
        SharePart::new(MountOption::Namespace, url.namespace.as_str()),
    ];
    match &server.0 {
        Address::Tcp(address) => {
            parts.push(SharePart::new(MountOption::Addr, address.ip().to_string()));
            parts.push(SharePart::new(
                MountOption::Port,
                address.port().to_string(),
            ));
        }
        Address::Unix(path) => {
            parts.push(SharePart::new(
                MountOption::Unix,
                path.as_os_str().as_bytes(),
            ));
        }
    }
    if !url.subpath.is_empty() {
        parts.push(SharePart::new(MountOption::Path, url.subpath.clone()));
    }
    parts
}

struct Target {
    path: PathBuf,
    directory: OwnedFd,
}

impl Target {
    fn open(path: &Path) -> Result<Self, KernelError> {
        let directory = openat(
            CWD,
            path,
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|source| KernelError::Target {
            target: path.to_owned(),
            source: source.into(),
        })?;
        Ok(Self {
            path: path.to_owned(),
            directory,
        })
    }
}

pub struct PendingMount<'a> {
    written: &'a str,
    url: MountUrl,
    options: &'a KernelMountOptions,
    target: Target,
    servers: Servers,
}

impl<'a> PendingMount<'a> {
    pub fn new(
        written: &'a str,
        target: &Path,
        options: &'a KernelMountOptions,
    ) -> Result<Self, KernelError> {
        let url = MountUrl::parse(written)?;
        let route = Route::of(&url.endpoint)?;
        if let Some(given) = options.given.iter().find(|given| given.selects_the_share()) {
            return Err(KernelError::ShareOption {
                name: given.name().to_owned(),
            });
        }
        let target = Target::open(target)?;
        let servers = route.servers()?;
        let parts = servers
            .iter()
            .flat_map(|server| share(written, &url, server))
            .collect::<Vec<_>>();
        let strings = parts
            .iter()
            .filter(|part| part.option.value_kind() != ValueKind::Bytes)
            .map(|part| (option_name(part.option), part.value.len()))
            .chain(options.given.iter().filter_map(|given| match given {
                Given::Value { name, value } => Some((Cow::from(name.as_str()), value.len())),
                Given::Flag(_) => None,
            }));
        for (key, len) in strings {
            if len > STRING_MAX {
                return Err(KernelError::TooLong {
                    key: key.into_owned(),
                });
            }
        }
        Ok(Self {
            written,
            url,
            options,
            target,
            servers,
        })
    }

    pub fn make(self) -> Result<(), KernelError> {
        first_mounted(&self.servers, |server| {
            mount_share(
                &share(self.written, &self.url, server),
                server,
                self.options,
                &self.target,
            )
        })
    }
}

fn mount_share(
    parts: &[SharePart],
    server: &Server,
    options: &KernelMountOptions,
    target: &Target,
) -> Result<(), KernelError> {
    let context = open_context()?;
    let rejected = |source: Errno| KernelError::Configure {
        log: KernelLog::read(&context),
        source: source.into(),
    };
    parts
        .iter()
        .try_for_each(|part| part.set(&context))
        .and_then(|()| options.configure(&context))
        .map_err(rejected)?;
    fsconfig_create(&context).map_err(|source| KernelError::Refused {
        server: server.clone(),
        log: KernelLog::read(&context),
        source: source.into(),
    })?;
    let mount = fsmount(
        &context,
        FsMountFlags::FSMOUNT_CLOEXEC,
        options.flags.attributes(),
    )
    .map_err(rejected)?;
    move_mount(
        &mount,
        "",
        &target.directory,
        "",
        MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH | MoveMountFlags::MOVE_MOUNT_T_EMPTY_PATH,
    )
    .map_err(|source| KernelError::Target {
        target: target.path.clone(),
        source: source.into(),
    })
}

/// The options of the module and read-only go through a reconfiguration of its
/// filesystem, and then the attributes of the mount itself.
pub fn remount(target: &Path, options: &KernelMountOptions) -> Result<(), KernelError> {
    let at_target = |source: Errno| KernelError::Target {
        target: target.to_owned(),
        source: source.into(),
    };
    let context = fspick(CWD, target, FsPickFlags::FSPICK_CLOEXEC).map_err(at_target)?;
    options
        .configure(&context)
        .and_then(|()| fsconfig_reconfigure(&context))
        .map_err(|source| KernelError::Configure {
            log: KernelLog::read(&context),
            source: source.into(),
        })?;
    mount_remount(target, options.flags.remount_flags(), "").map_err(at_target)
}

#[derive(Debug, thiserror::Error)]
pub enum KernelError {
    #[error(transparent)]
    Url(#[from] UrlError),
    #[error("the voidport kernel module dials only TCP and unix sockets, not a {VSOCK_SCHEME} URL")]
    Vsock,
    #[error("the URL sets the server, the namespace and the path: {name} is not an option")]
    ShareOption { name: String },
    #[error("cannot mount on {}", target.display())]
    Target {
        target: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("cannot look up {host}")]
    Lookup {
        host: String,
        #[source]
        source: io::Error,
    },
    #[error("{host} resolves to no address")]
    NoAddress { host: String },
    #[error(
        "the value of {key} is longer than the {STRING_MAX} bytes that a kernel mount option accepts"
    )]
    TooLong { key: String },
    #[error("the kernel has no {FILESYSTEM_TYPE} filesystem")]
    NoModule,
    #[error("this process may not mount")]
    NotPermitted,
    #[error("the kernel cannot open a {FILESYSTEM_TYPE} filesystem context")]
    Context {
        #[source]
        source: io::Error,
    },
    #[error("the kernel did not accept the mount options{log}")]
    Configure {
        log: KernelLog,
        #[source]
        source: io::Error,
    },
    #[error("the kernel failed the mount from {server}{log}")]
    Refused {
        server: Server,
        log: KernelLog,
        #[source]
        source: io::Error,
    },
}
