use std::borrow::Cow;
use std::os::fd::OwnedFd;

use rustix::mount::{MountAttrFlags, MountFlags, fsconfig_set_flag, fsconfig_set_string};
use voidport_session::options::{MountOption, Seconds};

use crate::mount::MountOptions;

const READ_ONLY: &str = "ro";

const READ_WRITE: &str = "rw";

const REMOUNT: &str = "remount";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KernelMountOptions {
    pub(super) flags: GenericFlags,
    pub(super) given: Vec<Given>,
    remount: bool,
}

impl KernelMountOptions {
    /// The options mount(8) and fstab act on are listed under
    /// "FILESYSTEM-INDEPENDENT MOUNT OPTIONS" and "EXTERNAL HELPERS" of
    /// mount(8), <https://man7.org/linux/man-pages/man8/mount.8.html>.
    pub fn from_mount_options<'a>(options: impl IntoIterator<Item = &'a str>) -> Self {
        let mut flags = GenericFlags::default();
        let mut given = Vec::new();
        let mut remount = false;
        for option in options {
            let (name, value) = match option.split_once('=') {
                Some((name, value)) => (name, Some(value)),
                None => (option, None),
            };
            match (name, value) {
                ("", None) => {}
                (REMOUNT, None) => remount = true,
                (READ_ONLY, None) => flags.read_only = true,
                (READ_WRITE, None) => flags.read_only = false,
                ("nosuid", None) => flags.nosuid = true,
                ("suid", None) => flags.nosuid = false,
                ("nodev", None) => flags.nodev = true,
                ("dev", None) => flags.nodev = false,
                ("noexec", None) => flags.noexec = true,
                ("exec", None) => flags.noexec = false,
                ("nosymfollow", None) => flags.nosymfollow = true,
                ("symfollow", None) => flags.nosymfollow = false,
                ("noatime", None) => flags.noatime = true,
                ("atime", None) => flags.noatime = false,
                ("strictatime", None) => flags.strictatime = true,
                ("nostrictatime", None) => flags.strictatime = false,
                // Relative atime is what a mount has unless noatime or
                // strictatime is given, so neither spelling changes it.
                ("relatime" | "norelatime", None) => {}
                ("nodiratime", None) => flags.nodiratime = true,
                ("diratime", None) => flags.nodiratime = false,
                // What mount(8) and fstab act on, before a helper runs.
                (
                    "defaults" | "auto" | "noauto" | "nofail" | "_netdev" | "user" | "nouser"
                    | "users" | "nousers" | "owner" | "noowner" | "group" | "nogroup",
                    None,
                )
                | ("user" | "comment" | "helper" | "uhelper", Some(_)) => {}
                (name, _) if name.starts_with("x-") || name.starts_with("X-") => {}
                (name, None) => given.push(Given::Flag(name.to_owned())),
                (name, Some(value)) => given.push(Given::Value {
                    name: name.to_owned(),
                    value: value.to_owned(),
                }),
            }
        }
        Self {
            flags,
            given,
            remount,
        }
    }

    /// The other fields of `options` shape only the FUSE client.
    pub fn for_client(options: &MountOptions) -> Self {
        let mut given = [
            (MountOption::AttrTimeout, options.attr_timeout),
            (MountOption::EntryTimeout, options.entry_timeout),
            (MountOption::ReconnectStall, options.reconnect_stall),
        ]
        .map(|(option, duration)| Given::Value {
            name: option_name(option).into_owned(),
            value: Seconds(duration).to_string(),
        })
        .to_vec();
        if !options.privileged_bits {
            given.push(Given::Flag(
                option_name(MountOption::NoPrivilegedBits).into_owned(),
            ));
        }
        Self {
            flags: GenericFlags {
                read_only: options.read_only,
                ..GenericFlags::default()
            },
            given,
            remount: false,
        }
    }

    pub fn remounts(&self) -> bool {
        self.remount
    }

    pub(super) fn configure(&self, context: &OwnedFd) -> rustix::io::Result<()> {
        for given in &self.given {
            match given {
                Given::Flag(name) => fsconfig_set_flag(context, name.as_str()),
                Given::Value { name, value } => {
                    fsconfig_set_string(context, name.as_str(), value.as_str())
                }
            }?;
        }
        fsconfig_set_flag(
            context,
            if self.flags.read_only {
                READ_ONLY
            } else {
                READ_WRITE
            },
        )
    }
}

/// Module option names are ASCII, so the lossy conversion loses nothing.
pub(super) fn option_name(option: MountOption) -> Cow<'static, str> {
    option.name().to_string_lossy()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Given {
    Flag(String),
    Value { name: String, value: String },
}

impl Given {
    pub(super) fn name(&self) -> &str {
        match self {
            Self::Flag(name) | Self::Value { name, .. } => name,
        }
    }

    pub(super) fn selects_the_share(&self) -> bool {
        MountOption::named(self.name().as_bytes()).is_some_and(MountOption::selects_the_share)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct GenericFlags {
    read_only: bool,
    nosuid: bool,
    nodev: bool,
    noexec: bool,
    nosymfollow: bool,
    noatime: bool,
    strictatime: bool,
    nodiratime: bool,
}

impl GenericFlags {
    pub(super) fn attributes(self) -> MountAttrFlags {
        let mut attributes = MountAttrFlags::empty();
        attributes.set(MountAttrFlags::MOUNT_ATTR_RDONLY, self.read_only);
        attributes.set(MountAttrFlags::MOUNT_ATTR_NOSUID, self.nosuid);
        attributes.set(MountAttrFlags::MOUNT_ATTR_NODEV, self.nodev);
        attributes.set(MountAttrFlags::MOUNT_ATTR_NOEXEC, self.noexec);
        attributes.set(MountAttrFlags::MOUNT_ATTR_NOSYMFOLLOW, self.nosymfollow);
        attributes.set(MountAttrFlags::MOUNT_ATTR_NODIRATIME, self.nodiratime);
        attributes
            | if self.strictatime {
                MountAttrFlags::MOUNT_ATTR_STRICTATIME
            } else if self.noatime {
                MountAttrFlags::MOUNT_ATTR_NOATIME
            } else {
                MountAttrFlags::MOUNT_ATTR_RELATIME
            }
    }

    /// A `mount(2)` remount sets every attribute of the mount at once.
    pub(super) fn remount_flags(self) -> MountFlags {
        let attributes = self.attributes();
        [
            (MountAttrFlags::MOUNT_ATTR_RDONLY, MountFlags::RDONLY),
            (MountAttrFlags::MOUNT_ATTR_NOSUID, MountFlags::NOSUID),
            (MountAttrFlags::MOUNT_ATTR_NODEV, MountFlags::NODEV),
            (MountAttrFlags::MOUNT_ATTR_NOEXEC, MountFlags::NOEXEC),
            (
                MountAttrFlags::MOUNT_ATTR_NOSYMFOLLOW,
                MountFlags::NOSYMFOLLOW,
            ),
            (
                MountAttrFlags::MOUNT_ATTR_NODIRATIME,
                MountFlags::NODIRATIME,
            ),
            (MountAttrFlags::MOUNT_ATTR_RELATIME, MountFlags::RELATIME),
            (MountAttrFlags::MOUNT_ATTR_NOATIME, MountFlags::NOATIME),
            (
                MountAttrFlags::MOUNT_ATTR_STRICTATIME,
                MountFlags::STRICTATIME,
            ),
        ]
        .into_iter()
        .filter(|(attribute, _)| attributes.contains(*attribute))
        .fold(MountFlags::BIND, |flags, (_, flag)| flags | flag)
    }
}
