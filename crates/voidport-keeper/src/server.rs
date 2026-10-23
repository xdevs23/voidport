use std::fs::File;
use std::io;
use std::net::Shutdown;
use std::os::fd::{AsRawFd as _, FromRawFd as _, IntoRawFd as _, OwnedFd};
use std::os::unix::net::UnixStream;

use rustix::event::{PollFd, PollFlags, Timespec, poll};
use vhost::VhostBackend as _;
use vhost::vhost_user::message::VhostUserHeaderFlag;
use vhost::vhost_user::{Frontend, VhostUserFrontend as _};
use vmm_sys_util::eventfd::EventFd;
use voidport_vhost::device::{PROTOCOL_FEATURES, QUEUES};

use crate::record::Record;

#[derive(Debug, thiserror::Error)]
pub(crate) enum HandOverError {
    #[error("voidportd refused a message of the device")]
    Message(#[from] vhost::Error),
    #[error("voidportd does not offer {missing:?}")]
    Offer {
        missing: vhost::vhost_user::VhostUserProtocolFeatures,
    },
    #[error("a descriptor of the device could not be handed on")]
    Descriptor(#[from] io::Error),
    #[error("the record of chains in flight could not be made")]
    Record(#[source] voidport_vhost::Error),
}

pub(crate) struct Server {
    frontend: Frontend,
    /// The socket of the connection, on which the keeper sees voidportd go
    /// away and waits for it to let go of the device.
    socket: UnixStream,
}

impl Server {
    pub(crate) fn connect(
        stream: UnixStream,
        record: Option<&Record>,
    ) -> Result<Self, HandOverError> {
        let socket = stream.try_clone()?;
        let mut frontend = Frontend::from_stream(stream, u64::from(QUEUES));
        // The library learns from the virtio features whether it may ask for
        // the protocol features.
        let _features = frontend.get_features()?;
        let offered = frontend.get_protocol_features()?;
        if !offered.contains(PROTOCOL_FEATURES) {
            return Err(HandOverError::Offer {
                missing: PROTOCOL_FEATURES.difference(offered),
            });
        }
        frontend.set_protocol_features(PROTOCOL_FEATURES)?;
        frontend.set_hdr_flags(VhostUserHeaderFlag::NEED_REPLY);
        if let Some(record) = record {
            hand_record(&mut frontend, record)?;
        }
        Ok(Self { frontend, socket })
    }

    pub(crate) fn frontend(&mut self) -> &mut Frontend {
        &mut self.frontend
    }

    pub(crate) fn watch(&self) -> io::Result<OwnedFd> {
        self.socket.try_clone().map(OwnedFd::from)
    }

    /// Whether voidportd has gone. voidportd sends nothing the keeper did
    /// not ask for, and the keeper reads every reply while it has the lock
    /// of the device, so a socket that is readable then is at its end.
    pub(crate) fn gone(&self) -> bool {
        let mut socket = [PollFd::new(&self.socket, PollFlags::IN)];
        let now = Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        poll(&mut socket, Some(&now)).map_or(true, |ready| ready > 0)
    }

    /// Ends the connection and waits until voidportd has let go of the
    /// device: voidportd stops every queue once it reads the end of the
    /// connection, and closes its side after that.
    pub(crate) fn release(self) {
        let Self { frontend, socket } = self;
        drop(frontend);
        if let Err(error) = socket.shutdown(Shutdown::Write) {
            tracing::debug!(%error, "the connection to voidportd ended already");
        }
        if let Err(error) = io::copy(&mut &socket, &mut io::sink()) {
            tracing::debug!(%error, "the connection to voidportd ended");
        }
    }
}

pub(crate) fn hand_record(frontend: &mut Frontend, record: &Record) -> vhost::Result<()> {
    frontend.set_inflight_fd(record.description(), record.file().as_raw_fd())
}

pub(crate) fn eventfd_of(file: &File) -> io::Result<EventFd> {
    let owned = OwnedFd::from(file.try_clone()?);
    // SAFETY: the conversion is unavoidable, since the frontend library
    // accepts the eventfds of a queue only as `EventFd`, and vmm-sys-util
    // 0.15.0 builds one only by creating a new eventfd or from a raw
    // descriptor. The safe forms are a `From<OwnedFd>` conversion and
    // handing on a new eventfd; the first does not exist in that version
    // while the second is not the eventfd QEMU signals. `into_raw_fd` gives
    // up the sole ownership of the descriptor duplicated just above, so it
    // is open and owned by nothing else, which is all `from_raw_fd` requires;
    // the `EventFd` closes it when it is dropped.
    Ok(unsafe { EventFd::from_raw_fd(owned.into_raw_fd()) })
}
