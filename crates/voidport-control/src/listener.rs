//! The source form of a data-plane listener.
//!
//! One shape serves two places, exactly as [`NamespaceSpec`](crate::policy::NamespaceSpec)
//! does: it is the state file's `[[server.listeners]]` entry *and* the payload
//! of `listener-add`. A listener an operator adds at runtime is therefore
//! spelled the same way as one they wrote in the file, and the server persists
//! what it was given, not a re-rendered equivalent.
//!
//! What this type is **not** is the endpoint a listener bound: a tcp listener
//! configured on port 0 keeps saying `:0` here for as long as it lives, because
//! that is what the operator wrote and what a restart must serve. Where it
//! actually landed is [`ListenerInfo`](crate::response::ListenerInfo), which is
//! also how `listener-remove` names it.

use std::net::SocketAddr;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// The vsock context id meaning "every guest of this machine", which is what an
/// operator naming no cid wants.
///
/// It is the kernel's `VMADDR_CID_ANY`, restated here so that this crate stays
/// at serde and nothing else; `voidportd` asserts the two agree at compile time.
pub const ANY_CID: u32 = u32::MAX;

/// One data-plane listener, in the form the operator wrote it.
///
/// The framing is byte-stream-agnostic, so the transports differ only in how
/// they are addressed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "transport", rename_all = "lowercase", deny_unknown_fields)]
pub enum Listener {
    /// A TCP socket. The address is validated as it is parsed.
    Tcp {
        /// The address to listen on, `host:port`.
        addr: SocketAddr,
    },
    /// A unix socket.
    Unix {
        /// The socket path.
        path: PathBuf,
    },
    /// A vsock endpoint, for guests on a VMM.
    Vsock {
        /// The context id to bind. Absent means [`ANY_CID`], the wildcard,
        /// which on a host means "reachable from every guest of this machine" —
        /// the bind an operator almost always wants, so it is the default
        /// and not a number to look up.
        #[serde(default = "any_cid")]
        cid: u32,
        /// The port. The server constrains it to the range a mount URL can
        /// name, at load and at `listener-add` alike.
        port: u32,
    },
}

impl Listener {
    /// A vsock listener on `port`, bound to the wildcard cid.
    ///
    /// A command line that names no cid must mean the same listener as a state
    /// file that names none, so the default is taken from one place instead of
    /// being restated by whoever builds the value.
    #[must_use]
    pub fn vsock(port: u32) -> Self {
        Self::Vsock {
            cid: any_cid(),
            port,
        }
    }

    /// The transport name, as the state file and the wire spell it.
    #[must_use]
    pub fn transport(&self) -> &'static str {
        match self {
            Self::Tcp { .. } => "tcp",
            Self::Unix { .. } => "unix",
            Self::Vsock { .. } => "vsock",
        }
    }
}

/// The wildcard cid, as a function so serde can default with it.
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
                Listener::Vsock { cid: 3, port: 1024 },
                r#"{"transport":"vsock","cid":3,"port":1024}"#,
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
