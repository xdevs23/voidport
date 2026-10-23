//! The source form of a data-plane listener: the state file's
//! `[[server.listeners]]` entry and the payload of `listener-add`. A tcp
//! listener configured on port 0 is written as `:0` here, because a restart
//! must bind that same form. The address it was bound to is in
//! [`ListenerInfo`](crate::response::ListenerInfo).

use std::fmt;
use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::ops::RangeInclusive;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// The vsock context id for every guest of this machine. Restated from the
/// kernel's `VMADDR_CID_ANY` so that this crate stays at serde and nothing
/// else; `voidportd` asserts the two agree at compile time.
pub const ANY_CID: u32 = u32::MAX;

/// Vsock ports are 32-bit in the kernel, but the port of the mount grammar is
/// the one of the URL standard and therefore 16-bit.
pub const VSOCK_PORTS: RangeInclusive<u32> = 1..=u16::MAX as u32;

/// The state file and the wire spell it as a number, and 0 asks the server for
/// a free port as it does for a tcp listener.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "u32", into = "u32")]
pub enum VsockPort {
    /// A free port, chosen by the server when it binds.
    Any,
    Number(NonZeroU32),
}

impl VsockPort {
    #[must_use]
    pub fn fits_mount_url(self) -> bool {
        match self {
            Self::Any => true,
            Self::Number(port) => VSOCK_PORTS.contains(&port.get()),
        }
    }
}

impl From<u32> for VsockPort {
    fn from(port: u32) -> Self {
        NonZeroU32::new(port).map_or(Self::Any, Self::Number)
    }
}

impl From<VsockPort> for u32 {
    fn from(port: VsockPort) -> Self {
        match port {
            VsockPort::Any => 0,
            VsockPort::Number(port) => port.get(),
        }
    }
}

impl fmt::Display for VsockPort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", u32::from(*self))
    }
}

/// The byte-stream transports differ only in how they are addressed. On a
/// vhost-user listener the same protocol goes on the queues of a virtio device.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "transport", rename_all = "lowercase", deny_unknown_fields)]
pub enum Listener {
    Tcp {
        addr: SocketAddr,
    },
    Unix {
        path: PathBuf,
    },
    Vsock {
        /// The context id to bind. Absent means [`ANY_CID`].
        #[serde(default = "any_cid")]
        cid: u32,
        /// The port, or [`VsockPort::Any`] for a free one. The server limits
        /// any other port to [`VSOCK_PORTS`].
        port: VsockPort,
    },
    #[serde(rename = "vhost-user")]
    VhostUser {
        path: PathBuf,
    },
}

impl Listener {
    /// A vsock listener on `port`, bound to the wildcard cid, so that the
    /// default is taken from one place.
    #[must_use]
    pub fn vsock(port: u32) -> Self {
        Self::Vsock {
            cid: any_cid(),
            port: port.into(),
        }
    }

    #[must_use]
    pub fn transport(&self) -> &'static str {
        match self {
            Self::Tcp { .. } => "tcp",
            Self::Unix { .. } => "unix",
            Self::Vsock { .. } => "vsock",
            Self::VhostUser { .. } => "vhost-user",
        }
    }
}

const fn any_cid() -> u32 {
    ANY_CID
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_listener_is_one_shape_on_the_wire_and_in_the_file() {
        let cases = [
            (
                Listener::Tcp {
                    addr: "127.0.0.1:9000".parse().expect("valid address"),
                },
                r#"{"transport":"tcp","addr":"127.0.0.1:9000"}"#,
            ),
            (
                Listener::Unix {
                    path: PathBuf::from("/run/voidport/data.sock"),
                },
                r#"{"transport":"unix","path":"/run/voidport/data.sock"}"#,
            ),
            (
                Listener::Vsock {
                    cid: 3,
                    port: 1024.into(),
                },
                r#"{"transport":"vsock","cid":3,"port":1024}"#,
            ),
            (
                Listener::vsock(0),
                r#"{"transport":"vsock","cid":4294967295,"port":0}"#,
            ),
            (
                Listener::VhostUser {
                    path: PathBuf::from("/run/voidport/vhost-user.sock"),
                },
                r#"{"transport":"vhost-user","path":"/run/voidport/vhost-user.sock"}"#,
            ),
        ];
        for (listener, encoded) in cases {
            assert_eq!(
                serde_json::to_string(&listener).expect("serializable"),
                encoded
            );
            assert_eq!(
                serde_json::from_str::<Listener>(encoded).expect("parses"),
                listener
            );
        }
    }

    #[test]
    fn port_0_is_any_and_only_the_range_of_a_mount_url_fits() {
        assert_eq!(VsockPort::from(0), VsockPort::Any);
        assert_eq!(u32::from(VsockPort::Any), 0);
        for number in [1, 65_535, 65_536, u32::MAX] {
            let port = VsockPort::from(number);
            assert_ne!(port, VsockPort::Any, "{number}");
            assert_eq!(u32::from(port), number);
            assert_eq!(port.to_string(), number.to_string());
            assert_eq!(port.fits_mount_url(), number <= 65_535, "{number}");
        }
        assert!(VsockPort::Any.fits_mount_url());
    }

    #[test]
    fn an_unnamed_cid_is_the_wildcard_and_a_misspelled_field_is_refused() {
        assert_eq!(
            serde_json::from_str::<Listener>(r#"{"transport":"vsock","port":1024}"#)
                .expect("parses"),
            Listener::vsock(1024)
        );
        assert_eq!(Listener::vsock(1024).transport(), "vsock");
        assert!(
            serde_json::from_str::<Listener>(r#"{"transport":"tcp","address":"127.0.0.1:1"}"#)
                .is_err()
        );
        assert!(serde_json::from_str::<Listener>(r#"{"transport":"pigeon"}"#).is_err());
    }
}
