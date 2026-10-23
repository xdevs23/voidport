mod helper;

use std::ffi::CString;
use std::io;
use std::os::fd::{AsFd as _, AsRawFd as _};
use std::path::Path;
use std::process::ExitStatus;

use rustix::io::Errno;
use rustix::mount::{MountFlags, UnmountFlags};
use rustix::process::{getgid, getuid};
use voidport_spawn::SpawnError;

use crate::device::Device;
pub(crate) use helper::AutoUnmount;
pub use helper::{AutoUnmountCopy, Fusermount, fusermount};

/// The source `/proc/mounts` shows for a mount: text without a comma or a NUL
/// byte, which the option list of the helper and the kernel cannot take.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MountSource(String);

#[derive(Debug, thiserror::Error)]
#[error("the mount source {0:?} contains a comma or a NUL byte")]
pub struct InvalidSource(pub String);

impl MountSource {
    /// # Errors
    ///
    /// A `source` with a comma or a NUL byte.
    pub fn new(source: impl Into<String>) -> Result<Self, InvalidSource> {
        let source = source.into();
        if source.contains([',', '\0']) {
            return Err(InvalidSource(source));
        }
        Ok(Self(source))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MountOptions {
    pub source: MountSource,
    pub default_permissions: bool,
    /// Let every user access the mount. Without it, the kernel lets only the
    /// mounting user in.
    pub allow_other: bool,
    pub read_only: bool,
    /// Unmount once this process is gone, and every process that has a copy
    /// made with [`Session::clone_connection`](crate::Session::clone_connection),
    /// through this helper. Only the helper can do that, so the mount always
    /// goes through it then.
    pub auto_unmount: Option<Fusermount>,
}

#[derive(Debug, thiserror::Error)]
pub enum MountError {
    #[error("/dev/fuse could not be opened")]
    Device(#[source] io::Error),
    #[error("the mountpoint could not be read")]
    Mountpoint(#[source] Errno),
    #[error("the mountpoint could not be made absolute")]
    AbsoluteMountpoint(#[source] io::Error),
    #[error("the kernel rejected the mount")]
    Mount(#[source] Errno),
    #[error("the fusermount3 helper was not found")]
    NoHelper,
    #[error("the child processes of this process cannot be started")]
    Launcher(#[source] SpawnError),
    #[error("the fusermount3 helper could not be started")]
    Start(#[source] SpawnError),
    #[error("the fusermount3 helper could not be talked to")]
    Helper(#[source] io::Error),
    #[error("the fusermount3 helper did not mount ({status}): {message}")]
    Refused {
        status: ExitStatus,
        /// What the helper wrote to its standard error. The helper of an
        /// auto-unmount writes to the standard error of this process instead.
        message: String,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum UnmountError {
    #[error("the kernel rejected the unmount")]
    Unmount(#[source] Errno),
    #[error("the fusermount3 helper could not be started")]
    Start(#[source] SpawnError),
    #[error("the fusermount3 helper could not be waited for")]
    Helper(#[source] io::Error),
    #[error("the fusermount3 helper did not unmount ({status}): {message}")]
    Refused { status: ExitStatus, message: String },
}

#[derive(Debug)]
pub(crate) struct Mounted {
    pub(crate) device: Device,
    pub(crate) unmount: Unmount,
}

#[derive(Debug)]
pub(crate) enum Unmount {
    Direct,
    Helper(Fusermount),
    Auto,
}

impl Mounted {
    pub(crate) fn unmount(self, mountpoint: &Path) -> Result<(), UnmountError> {
        let Self { device, unmount } = self;
        // The helper of an auto-unmount unmounts once the device is dropped,
        // and the drop waits for it.
        drop(device);
        match unmount {
            Unmount::Direct => rustix::mount::unmount(mountpoint, UnmountFlags::DETACH)
                .map_err(UnmountError::Unmount),
            Unmount::Helper(helper) => helper.unmount(mountpoint),
            Unmount::Auto => Ok(()),
        }
    }
}

pub(crate) fn mount(mountpoint: &Path, options: &MountOptions) -> Result<Mounted, MountError> {
    // The launcher closes the copy of every file of the process on its first
    // start, so it starts before the process can have a file of this mount
    // open.
    voidport_spawn::start_launcher().map_err(MountError::Launcher)?;
    if let Some(helper) = &options.auto_unmount {
        return helper.mount(mountpoint, options);
    }
    let device = Device::open().map_err(MountError::Device)?;
    match mount_directly(&device, mountpoint, options) {
        Ok(()) => {
            return Ok(Mounted {
                device,
                unmount: Unmount::Direct,
            });
        }
        Err(MountError::Mount(Errno::PERM)) => {}
        Err(error) => return Err(error),
    }
    fusermount()
        .ok_or(MountError::NoHelper)?
        .mount(mountpoint, options)
}

fn mount_directly(
    device: &Device,
    mountpoint: &Path,
    options: &MountOptions,
) -> Result<(), MountError> {
    let root = rustix::fs::stat(mountpoint).map_err(MountError::Mountpoint)?;
    let mut data = format!(
        "fd={},rootmode={:o},user_id={},group_id={}",
        device.as_fd().as_raw_fd(),
        root.st_mode,
        getuid().as_raw(),
        getgid().as_raw(),
    );
    if options.default_permissions {
        data.push_str(",default_permissions");
    }
    if options.allow_other {
        data.push_str(",allow_other");
    }
    let mut flags = MountFlags::NOSUID | MountFlags::NODEV;
    if options.read_only {
        flags |= MountFlags::RDONLY;
    }
    let data = CString::new(data).expect("the option list is numbers and option names");
    rustix::mount::mount(options.source.as_str(), mountpoint, "fuse", flags, &*data)
        .map_err(MountError::Mount)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_source_with_a_comma_or_a_nul_byte_is_invalid() {
        for source in ["a,b", "a\0b"] {
            assert!(MountSource::new(source).is_err(), "{source:?}");
        }
    }
}
