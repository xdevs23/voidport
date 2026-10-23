use std::fmt;
use std::path::{Path, PathBuf};

use percent_encoding::{AsciiSet, CONTROLS, percent_encode};
use voidport_control::NamespaceName;

use crate::data::listener::{Endpoint, Transport};

/// Where the plain-transport note sends the reader.
pub const SECURITY_SECTION: &str = "the Security section of README.md";

/// Mirrors the client authority set in `voidport::url`, which cannot be a
/// dependency here. An end-to-end test parses this line with the real client
/// parser.
const AUTHORITY: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'/')
    .add(b':')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'@')
    .add(b'[')
    .add(b'\\')
    .add(b']')
    .add(b'^')
    .add(b'|');

/// The client segment set, for the same reason as [`AUTHORITY`].
const SEGMENT: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'/')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'`')
    .add(b'{')
    .add(b'}');

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MountCommand {
    pub transport: Transport,
    pub url: String,
    pub mountpoint: PathBuf,
}

impl fmt::Display for MountCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "voidport mount {} {}",
            self.url,
            self.mountpoint.display()
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LaunchSummary {
    pub namespace: NamespaceName,
    pub mounts: Vec<MountCommand>,
    pub control_socket: PathBuf,
    pub plaintext_tcp: bool,
}

impl LaunchSummary {
    #[must_use]
    pub fn new(namespace: &NamespaceName, endpoints: &[Endpoint], control_socket: &Path) -> Self {
        let mountpoint = PathBuf::from("/mnt").join(namespace.as_str());
        let mounts: Vec<MountCommand> = endpoints
            .iter()
            .filter_map(|endpoint| mount_command(namespace, endpoint, &mountpoint))
            .collect();
        Self {
            namespace: namespace.clone(),
            control_socket: control_socket.to_path_buf(),
            plaintext_tcp: mounts.iter().any(|mount| mount.transport == Transport::Tcp),
            mounts,
        }
    }

    #[must_use]
    pub fn auth_note(&self) -> Option<String> {
        self.plaintext_tcp.then(|| {
            format!(
                "auth is \"none\": anything that can connect to the tcp listener can mount \
                 this namespace. See {SECURITY_SECTION}."
            )
        })
    }

    #[must_use]
    pub fn control_command(&self) -> String {
        format!(
            "voidport-ctl --socket {} info",
            self.control_socket.display()
        )
    }
}

/// `None` for a vhost-user socket: its guest mounts by the tag of the virtio
/// device, which the server never learns.
fn mount_command(
    namespace: &NamespaceName,
    endpoint: &Endpoint,
    mountpoint: &Path,
) -> Option<MountCommand> {
    use std::os::unix::ffi::OsStrExt as _;

    let (transport, authority) = match endpoint {
        // `SocketAddr` renders an IPv6 literal bracketed, as the URL grammar needs.
        // A wildcard address is printed as configured: which address of the
        // machine a guest can reach depends on the network of the guest, which
        // the server does not know.
        Endpoint::Tcp(address) => (Transport::Tcp, format!("voidport://{address}")),
        Endpoint::Unix(path) => (
            Transport::Unix,
            format!(
                "voidport+unix://{}",
                percent_encode(path.as_os_str().as_bytes(), AUTHORITY)
            ),
        ),
        // A wildcard bind has no address a guest can dial, so the command names
        // `VMADDR_CID_HOST`. A listener bound to one cid prints that cid.
        Endpoint::Vsock { cid, port } => {
            let dialled = if *cid == vsock::VMADDR_CID_ANY {
                vsock::VMADDR_CID_HOST
            } else {
                *cid
            };
            (
                Transport::Vsock,
                format!("voidport+vsock://{dialled}:{port}"),
            )
        }
        Endpoint::VhostUser(_) => return None,
    };
    Some(MountCommand {
        transport,
        url: format!(
            "{authority}/@{}",
            percent_encode(namespace.as_str().as_bytes(), SEGMENT)
        ),
        mountpoint: mountpoint.to_path_buf(),
    })
}

impl fmt::Display for LaunchSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "namespace \"{}\" is being served.", self.namespace)?;
        writeln!(f)?;
        writeln!(f, "Mount it from the guest:")?;
        for mount in &self.mounts {
            writeln!(f, "    {mount}")?;
        }
        writeln!(f)?;
        writeln!(f, "Reconfigure it from this machine:")?;
        writeln!(f, "    {}", self.control_command())?;
        if let Some(note) = self.auth_note() {
            writeln!(f)?;
            write!(f, "{note}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::listener::BoundListener;
    use crate::state::Listener;
    use voidport_control::VsockPort;
    use voidport_test_host::Scratch;

    fn name(raw: &str) -> NamespaceName {
        NamespaceName::new(raw).expect("valid namespace name")
    }

    fn bind(listeners: &[Listener]) -> (Vec<BoundListener>, Vec<Endpoint>) {
        let bound = BoundListener::bind_all(listeners).expect("binds");
        let endpoints = bound.iter().map(BoundListener::endpoint).collect();
        (bound, endpoints)
    }

    #[test]
    fn a_tcp_listener_prints_the_port_it_actually_bound() {
        let (_bound, endpoints) = bind(&[Listener::Tcp {
            addr: "127.0.0.1:0".parse().expect("valid address"),
        }]);
        let Endpoint::Tcp(address) = endpoints[0] else {
            panic!("a tcp listener");
        };
        let port = address.port();
        assert_ne!(port, 0);

        let summary =
            LaunchSummary::new(&name("share"), &endpoints, Path::new("/state/control.sock"));
        assert_eq!(
            summary.mounts,
            vec![MountCommand {
                transport: Transport::Tcp,
                url: format!("voidport://127.0.0.1:{port}/@share"),
                mountpoint: PathBuf::from("/mnt/share"),
            }]
        );
        assert_eq!(
            summary.mounts[0].to_string(),
            format!("voidport mount voidport://127.0.0.1:{port}/@share /mnt/share")
        );
        assert!(summary.plaintext_tcp);
        let rendered = summary.to_string();
        assert!(
            rendered.contains(&summary.mounts[0].to_string()),
            "{rendered}"
        );
        let note = summary.auth_note().expect("a tcp listener has a note");
        assert!(rendered.contains(&note), "{rendered}");
        assert_eq!(
            summary.control_command(),
            "voidport-ctl --socket /state/control.sock info"
        );
        assert!(rendered.contains(&summary.control_command()), "{rendered}");
    }

    #[test]
    fn a_unix_listener_percent_encodes_its_socket_into_the_authority() {
        let scratch = Scratch::new("launch-unix");
        let path = scratch.join("data.sock");
        let (_bound, endpoints) = bind(&[Listener::Unix { path: path.clone() }]);

        let summary = LaunchSummary::new(&name("share"), &endpoints, &scratch.join("control.sock"));
        let encoded = path.display().to_string().replace('/', "%2F");
        assert_eq!(
            summary.mounts,
            vec![MountCommand {
                transport: Transport::Unix,
                url: format!("voidport+unix://{encoded}/@share"),
                mountpoint: PathBuf::from("/mnt/share"),
            }]
        );
        assert!(
            !summary.plaintext_tcp,
            "a unix socket is not reachable off the machine, so it carries no plain-transport note"
        );
        assert_eq!(summary.auth_note(), None);
        let rendered = summary.to_string();
        assert!(rendered.contains(&encoded), "{rendered}");
    }

    #[test]
    fn a_vsock_listener_prints_the_cid_a_guest_dials() {
        if !voidport_test_host::vsock::preflight() {
            return;
        }
        let (_wildcard, endpoints) = bind(&[Listener::Vsock {
            cid: vsock::VMADDR_CID_ANY,
            port: VsockPort::Any,
        }]);
        let Endpoint::Vsock { port, .. } = endpoints[0] else {
            panic!("a vsock listener");
        };

        let summary =
            LaunchSummary::new(&name("share"), &endpoints, Path::new("/state/control.sock"));
        assert_eq!(
            summary.mounts,
            vec![MountCommand {
                transport: Transport::Vsock,
                url: format!("voidport+vsock://{}:{port}/@share", vsock::VMADDR_CID_HOST),
                mountpoint: PathBuf::from("/mnt/share"),
            }]
        );
        assert!(
            !summary.plaintext_tcp,
            "a vsock listener cannot be reached off the machine, so it carries no plain-transport note"
        );
        assert_eq!(summary.auth_note(), None);

        // The local cid is the only specific one a machine without guests can bind.
        let (_local, endpoints) = bind(&[Listener::Vsock {
            cid: vsock::VMADDR_CID_LOCAL,
            port: VsockPort::Any,
        }]);
        let Endpoint::Vsock { port, .. } = endpoints[0] else {
            panic!("a vsock listener");
        };
        let summary =
            LaunchSummary::new(&name("share"), &endpoints, Path::new("/state/control.sock"));
        assert_eq!(
            summary.mounts[0].url,
            format!("voidport+vsock://{}:{port}/@share", vsock::VMADDR_CID_LOCAL)
        );
    }

    #[test]
    fn every_listener_gets_its_own_line_in_configuration_order() {
        let scratch = Scratch::new("launch-both");
        let (_bound, endpoints) = bind(&[
            Listener::Tcp {
                addr: "127.0.0.1:0".parse().expect("valid address"),
            },
            Listener::Unix {
                path: scratch.join("data.sock"),
            },
        ]);

        let summary = LaunchSummary::new(&name("a b"), &endpoints, &scratch.join("control.sock"));
        assert_eq!(summary.mounts.len(), 2);
        assert_eq!(summary.mounts[0].transport, Transport::Tcp);
        assert_eq!(summary.mounts[1].transport, Transport::Unix);
        assert!(summary.plaintext_tcp);
        assert!(summary.mounts[0].url.ends_with("/@a%20b"), "{summary}");
        assert!(summary.mounts[1].url.ends_with("/@a%20b"), "{summary}");
    }

    #[test]
    fn a_vhost_user_listener_gets_no_mount_line() {
        let scratch = Scratch::new("launch-vhost-user");
        let (_bound, endpoints) = bind(&[
            Listener::VhostUser {
                path: scratch.join("vhost-user.sock"),
            },
            Listener::Unix {
                path: scratch.join("data.sock"),
            },
        ]);

        let summary = LaunchSummary::new(&name("share"), &endpoints, &scratch.join("control.sock"));
        assert_eq!(summary.mounts.len(), 1);
        assert_eq!(summary.mounts[0].transport, Transport::Unix);
    }
}
