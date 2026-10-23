use std::ffi::{OsStr, OsString};
use std::io::{self, IoSliceMut};
use std::mem::MaybeUninit;
use std::os::fd::{AsFd as _, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::process::Child;

use rustix::event::{PollFd, PollFlags, poll};
use rustix::io::Errno;
use rustix::net::{
    AddressFamily, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, SocketFlags, SocketType,
    recvmsg, socketpair,
};
use rustix::process::{Pid, PidfdFlags, pidfd_open};
use voidport_spawn::{Program, Stream};

use super::{MountError, MountOptions, Mounted, Unmount, UnmountError};
use crate::device::Device;

const COMMAND_SOCKET: &str = "_FUSE_COMMFD";

const HELPER_SOCKET: RawFd = 3;

const HELPER_VARIABLE: &str = "FUSERMOUNT_PATH";

/// Where the helper is looked for, in order: by name on `PATH`, then where
/// distributions install it when `PATH` misses those directories.
const HELPERS: [&str; 6] = [
    "fusermount3",
    "fusermount",
    "/sbin/fusermount3",
    "/sbin/fusermount",
    "/bin/fusermount3",
    "/bin/fusermount",
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fusermount(OsString);

/// `FUSERMOUNT_PATH` names the only helper to use where it is set.
/// Otherwise the first of `fusermount3` and `fusermount` found on `PATH`,
/// in `/sbin` or in `/bin` is used. A helper counts as found when it can be
/// started.
#[must_use]
pub fn fusermount() -> Option<Fusermount> {
    if let Some(named) = std::env::var_os(HELPER_VARIABLE) {
        return starts(&named).then_some(Fusermount(named));
    }
    HELPERS
        .into_iter()
        .map(OsString::from)
        .find(|helper| starts(helper))
        .map(Fusermount)
}

/// Whether `helper` can be started; what it answers does not matter.
fn starts(helper: &OsStr) -> bool {
    Program::new(helper)
        .arg("-h")
        .spawn()
        .is_ok_and(|mut helper| helper.wait().is_ok())
}

fn helper_options(options: &MountOptions) -> String {
    let mut list = vec![format!("fsname={}", options.source.as_str())];
    for (option, set) in [
        ("default_permissions", options.default_permissions),
        ("allow_other", options.allow_other),
        ("ro", options.read_only),
        ("auto_unmount", options.auto_unmount.is_some()),
    ] {
        if set {
            list.push(option.to_owned());
        }
    }
    list.join(",")
}

impl Fusermount {
    #[must_use]
    pub fn new(path: impl Into<OsString>) -> Self {
        Self(path.into())
    }

    #[must_use]
    pub fn path(&self) -> &OsStr {
        &self.0
    }

    /// The helper of an auto-unmount writes to the standard error of this
    /// process, because it lives as long as the mount and nothing would read
    /// a pipe of it.
    pub(crate) fn mount(
        &self,
        mountpoint: &Path,
        options: &MountOptions,
    ) -> Result<Mounted, MountError> {
        let (ours, theirs) = socketpair(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::CLOEXEC,
            None,
        )
        .map_err(|error| MountError::Helper(error.into()))?;
        // The helper of an auto-unmount is handed on with the mountpoint, to
        // a process that may have another working directory.
        let unmounted_at = options
            .auto_unmount
            .as_ref()
            .map(|_| std::path::absolute(mountpoint))
            .transpose()
            .map_err(MountError::AbsoluteMountpoint)?;
        let auto_unmount = unmounted_at.is_some();
        let spawned = Program::new(&self.0)
            .arg("-o")
            .arg(helper_options(options))
            .arg("--")
            .arg(mountpoint)
            .env(COMMAND_SOCKET, HELPER_SOCKET.to_string())
            .descriptor(HELPER_SOCKET, theirs.as_fd())
            .stderr(if auto_unmount {
                Stream::Inherit
            } else {
                Stream::Piped
            })
            .spawn();
        // The socket shows that the helper has ended only once no copy of its
        // end is open here.
        drop(theirs);
        let helper = spawned.map_err(MountError::Start)?;

        let descriptor = match receive_descriptor(&ours, &helper) {
            Ok(Some(descriptor)) => descriptor,
            Ok(None) => return Err(refused(ours, helper)),
            Err(error) => {
                end(ours, helper);
                return Err(MountError::Helper(error));
            }
        };
        let device = match Device::new(descriptor) {
            Ok(device) => device,
            Err(error) => {
                end(ours, helper);
                return Err(MountError::Device(error));
            }
        };
        if let Some(mountpoint) = unmounted_at {
            return Ok(Mounted {
                device: device.unmounted_by(AutoUnmount {
                    socket: ours,
                    mountpoint,
                    program: self.clone(),
                    _helper: Helper(helper),
                }),
                unmount: Unmount::Auto,
            });
        }
        end(ours, helper);
        Ok(Mounted {
            device,
            unmount: Unmount::Helper(self.clone()),
        })
    }

    /// # Errors
    ///
    /// The error of the start of the helper or of the wait for it, and
    /// [`UnmountError::Refused`] where the helper did not unmount, also where
    /// nothing is mounted on `mountpoint`.
    pub fn unmount(&self, mountpoint: &Path) -> Result<(), UnmountError> {
        let output = Program::new(&self.0)
            .args(["-u", "-q", "-z", "--"])
            .arg(mountpoint)
            .stderr(Stream::Piped)
            .spawn()
            .map_err(UnmountError::Start)?
            .wait_with_output()
            .map_err(UnmountError::Helper)?;
        if output.status.success() {
            return Ok(());
        }
        Err(UnmountError::Refused {
            status: output.status,
            message: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        })
    }
}

/// The helper unmounts once every copy of the end of its socket is closed, in
/// every process that has one: when this is dropped, or when this process
/// ends, and when each [`AutoUnmountCopy`] is dropped.
///
/// Before it unmounts, the helper checks that the mountpoint still has the
/// same FUSE mount and that an open of it fails because the connection has
/// ended, so this is dropped after the descriptor of the connection is
/// closed (see [`Device`]). A check that sends a request to a connection that
/// no process reads would wait for a reply, and a check that a process still
/// serving the connection replies to finds the mount alive and leaves it.
#[derive(Debug)]
pub(crate) struct AutoUnmount {
    /// The end of the socket. It comes before the helper, so that it is
    /// closed before the drop waits for the helper.
    socket: OwnedFd,
    mountpoint: PathBuf,
    program: Fusermount,
    _helper: Helper,
}

impl AutoUnmount {
    pub(crate) fn copy(&self) -> io::Result<AutoUnmountCopy> {
        Ok(AutoUnmountCopy {
            socket: self.socket.try_clone()?,
            mountpoint: self.mountpoint.clone(),
            helper: self.program.clone(),
        })
    }
}

/// The helper checks the mountpoint only once the socket in here is closed
/// as well, and `helper` and `mountpoint` let a process unmount itself first,
/// with [`Fusermount::unmount`].
#[derive(Debug)]
pub struct AutoUnmountCopy {
    pub socket: OwnedFd,
    pub mountpoint: PathBuf,
    pub helper: Fusermount,
}

/// The helper of an auto-unmount. The drop waits for the helper, which ends
/// once it has unmounted, or found the mount gone. The helper starts its
/// check only once every copy of the end of its socket is closed, so the drop
/// waits for the copies in other processes as well.
#[derive(Debug)]
struct Helper(Child);

impl Drop for Helper {
    fn drop(&mut self) {
        match self.0.wait() {
            Ok(status) if status.success() => {}
            Ok(status) => {
                tracing::warn!(%status, "the fusermount3 helper of the auto-unmount ended with an error");
            }
            Err(error) => {
                tracing::warn!(%error, "the fusermount3 helper of the auto-unmount could not be waited for");
            }
        }
    }
}

fn end(socket: OwnedFd, helper: Child) {
    drop(socket);
    match helper.wait_with_output() {
        Ok(output) => log_helper_output(&output.stderr),
        Err(error) => tracing::warn!(%error, "the fusermount3 helper could not be waited for"),
    }
}

/// A copy of the end of the helper may live on in another process, such as
/// one started by the helper, so the socket alone does not show that the
/// helper ended: its process is watched as well, where the kernel gives out a
/// descriptor for it.
fn receive_descriptor(socket: &OwnedFd, helper: &Child) -> io::Result<Option<OwnedFd>> {
    let Ok(ended) = pidfd_open(Pid::from_child(helper), PidfdFlags::empty()) else {
        return receive(socket, RecvFlags::empty());
    };
    loop {
        let mut events = [
            PollFd::new(socket, PollFlags::IN),
            PollFd::new(&ended, PollFlags::IN),
        ];
        match poll(&mut events, None) {
            Ok(_) => {}
            Err(Errno::INTR) => continue,
            Err(error) => return Err(error.into()),
        }
        if !events[0].revents().is_empty() {
            return receive(socket, RecvFlags::empty());
        }
        if !events[1].revents().is_empty() {
            return receive(socket, RecvFlags::DONTWAIT);
        }
    }
}

fn receive(socket: &OwnedFd, flags: RecvFlags) -> io::Result<Option<OwnedFd>> {
    let mut byte = [0];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut control = RecvAncillaryBuffer::new(&mut space);
    let received = loop {
        match recvmsg(
            socket,
            &mut [IoSliceMut::new(&mut byte)],
            &mut control,
            flags | RecvFlags::CMSG_CLOEXEC,
        ) {
            Err(Errno::INTR) => {}
            Err(Errno::AGAIN) => return Ok(None),
            received => break received?,
        }
    };
    if received.bytes == 0 {
        return Ok(None);
    }
    Ok(control.drain().find_map(|message| match message {
        RecvAncillaryMessage::ScmRights(mut descriptors) => descriptors.next(),
        _ => None,
    }))
}

fn refused(socket: OwnedFd, helper: Child) -> MountError {
    // A helper that waits for this end to close never ends otherwise.
    drop(socket);
    match helper.wait_with_output() {
        Ok(output) => MountError::Refused {
            status: output.status,
            message: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        },
        Err(error) => MountError::Helper(error),
    }
}

fn log_helper_output(said: &[u8]) {
    let said = String::from_utf8_lossy(said);
    if !said.trim().is_empty() {
        tracing::warn!(said = %said.trim(), "the fusermount3 helper wrote to its standard error");
    }
}

#[cfg(test)]
mod tests {
    use std::io::Read as _;

    use super::*;
    use crate::mount::MountSource;

    fn options() -> MountOptions {
        MountOptions {
            source: MountSource::new("voidport").expect("a plain source"),
            default_permissions: true,
            allow_other: false,
            read_only: false,
            auto_unmount: None,
        }
    }

    #[test]
    fn the_helper_gets_one_comma_separated_list_of_what_is_set() {
        assert_eq!(
            helper_options(&options()),
            "fsname=voidport,default_permissions"
        );
        let everything = MountOptions {
            allow_other: true,
            read_only: true,
            auto_unmount: Some(Fusermount("fusermount3".into())),
            ..options()
        };
        assert_eq!(
            helper_options(&everything),
            "fsname=voidport,default_permissions,allow_other,ro,auto_unmount"
        );
    }

    #[test]
    fn a_helper_that_sends_nothing_is_a_refusal_with_its_message() {
        let (ours, theirs) = socketpair(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::CLOEXEC,
            None,
        )
        .expect("a socket pair");
        let helper = Program::new("sh")
            .args(["-c", "echo 'user_allow_other is not set' >&2; exit 1"])
            .stderr(Stream::Piped)
            .spawn()
            .expect("sh starts");
        assert!(
            receive_descriptor(&ours, &helper)
                .expect("received")
                .is_none()
        );
        drop(theirs);
        let MountError::Refused { status, message } = refused(ours, helper) else {
            panic!("a refusal");
        };
        assert_eq!(status.code(), Some(1));
        assert_eq!(message, "user_allow_other is not set");
    }

    #[test]
    fn a_helper_that_ends_with_an_error_did_not_unmount() {
        let mountpoint = Path::new("/mountpoint");
        assert!(Fusermount("true".into()).unmount(mountpoint).is_ok());
        let Err(UnmountError::Refused { status, .. }) =
            Fusermount("false".into()).unmount(mountpoint)
        else {
            panic!("a refusal");
        };
        assert_eq!(status.code(), Some(1));
    }

    #[test]
    fn the_last_drop_of_the_device_ends_the_helper_and_waits_for_it() {
        use std::sync::Arc;

        use rustix::event::Timespec;

        let (ours, theirs) = socketpair(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::CLOEXEC,
            None,
        )
        .expect("a socket pair");
        // `cat` stands in for the helper: it reads its end until the socket
        // closes, and then ends.
        let helper = Program::new("cat")
            .stdin(Stream::Descriptor(theirs.as_fd()))
            .stderr(Stream::Inherit)
            .spawn()
            .expect("cat starts");
        drop(theirs);
        let ended = pidfd_open(Pid::from_child(&helper), PidfdFlags::empty()).expect("a pidfd");
        let has_ended = || {
            let mut events = [PollFd::new(&ended, PollFlags::IN)];
            poll(&mut events, Some(&Timespec::default())).expect("polled") == 1
        };
        let device = Arc::new(
            crate::device::tests::discarding().unmounted_by(AutoUnmount {
                socket: ours,
                mountpoint: PathBuf::from("/"),
                program: Fusermount::new("cat"),
                _helper: Helper(helper),
            }),
        );
        let notifier = Arc::clone(&device);
        drop(device);
        assert!(!has_ended(), "a copy of the device is left");
        drop(notifier);
        assert!(has_ended());
    }

    #[test]
    fn the_descriptor_sent_is_received() {
        use rustix::net::{SendAncillaryBuffer, SendAncillaryMessage, SendFlags, sendmsg};

        let (ours, theirs) = socketpair(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::CLOEXEC,
            None,
        )
        .expect("a socket pair");
        let (reader, writer) = std::io::pipe().expect("a pipe");
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut control = SendAncillaryBuffer::new(&mut space);
        let sent = [writer.as_fd()];
        assert!(control.push(SendAncillaryMessage::ScmRights(&sent)));
        sendmsg(
            &theirs,
            &[std::io::IoSlice::new(b"\0")],
            &mut control,
            SendFlags::empty(),
        )
        .expect("sent");
        drop(writer);

        let received = receive(&ours, RecvFlags::empty())
            .expect("received")
            .expect("a descriptor");
        rustix::io::write(&received, b"x").expect("the descriptor received is the pipe");
        drop(received);
        let mut read = Vec::new();
        let mut reader = reader;
        reader.read_to_end(&mut read).expect("read");
        assert_eq!(read, b"x");
    }
}
