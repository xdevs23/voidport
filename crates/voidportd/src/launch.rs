//! What a seeded launch has to tell its operator.
//!
//! `voidportd share <DIR>` exists so that sharing a directory is two commands,
//! and the second one is the client's. That only works if the server hands the
//! operator the exact line to paste — which means the summary is **derived
//! after binding**, from the listeners as they actually came up: a listener
//! configured on port 0 has a real port by then, and printing the configured
//! `0` would hand the operator a URL that cannot connect.
//!
//! The control socket is in the same position: a seeded launch may have placed
//! it beside the state file instead of at the compiled default, so the summary
//! carries the `voidport-ctl --socket` line for the socket that was actually
//! bound.
//!
//! What is *not* resolved is the host: a `0.0.0.0` bind is printed verbatim,
//! because which of the machine's addresses a guest can reach is a fact about
//! the guest's network and not one the server can invent (design: "the printed
//! line uses the configured address verbatim").
//!
//! The summary is a **value**, not a sequence of prints: the binary renders it
//! to stdout, and the operator TUI renders the same value in its Overview
//! screen. Anything that formats it lives with the surface doing the
//! formatting; nothing here writes anywhere.

use std::fmt;
use std::path::{Path, PathBuf};

use percent_encoding::{AsciiSet, CONTROLS, percent_encode};
use voidport_control::NamespaceName;

use crate::data::listener::{Endpoint, Transport};

/// The document the plain-transport note points at.
pub const THREAT_MODEL: &str = "docs/THREAT-MODEL.md";

/// What a unix socket path must not carry literally when it is written as a
/// URL authority.
///
/// This mirrors the client's own authority set (`voidport::url`): the URL
/// standard's forbidden host code points plus `%`, so an encoded byte is never
/// re-read as somebody else's escape. The client crate cannot be a dependency
/// here — it depends on this one — so the guard against the two drifting apart
/// is the end-to-end test that parses this line with the real client parser.
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

/// What a path segment — the `@namespace` component — must not carry
/// literally: the separator itself, the delimiters that would end the path, and
/// `%`. The client's segment set, for the same reason as [`AUTHORITY`].
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

/// One listener's copy-paste mount command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MountCommand {
    /// The transport the listener serves.
    pub transport: Transport,
    /// The mount URL, in the client's grammar.
    pub url: String,
    /// The mountpoint the line suggests. The guest picks its own; this one only
    /// makes the line runnable as printed.
    pub mountpoint: PathBuf,
}

impl fmt::Display for MountCommand {
    /// The line an operator pastes into the guest.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "voidport mount {} {}",
            self.url,
            self.mountpoint.display()
        )
    }
}

/// Everything a seeded launch reports once both planes are bound.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LaunchSummary {
    /// The namespace the launch seeded.
    pub namespace: NamespaceName,
    /// One mount command per bound listener, in the order they were
    /// configured.
    pub mounts: Vec<MountCommand>,
    /// The control socket the server bound, which a seeded launch may have
    /// placed beside the state file, not at the compiled default.
    pub control_socket: PathBuf,
    /// Whether a tcp listener is bound, which is what makes `auth = "none"`
    /// reachable from off the machine.
    pub plaintext_tcp: bool,
}

impl LaunchSummary {
    /// Derives the summary from the listeners and the control socket as they
    /// actually bound.
    #[must_use]
    pub fn new(namespace: &NamespaceName, endpoints: &[Endpoint], control_socket: &Path) -> Self {
        let mountpoint = PathBuf::from("/mnt").join(namespace.as_str());
        let mounts: Vec<MountCommand> = endpoints
            .iter()
            .map(|endpoint| mount_command(namespace, endpoint, &mountpoint))
            .collect();
        Self {
            namespace: namespace.clone(),
            control_socket: control_socket.to_path_buf(),
            plaintext_tcp: mounts.iter().any(|mount| mount.transport == Transport::Tcp),
            mounts,
        }
    }

    /// The plain-transport warning, when a tcp listener is bound.
    ///
    /// One wording, two surfaces: the block this type prints and the operator
    /// TUI's Overview both say it, and neither may say it differently.
    #[must_use]
    pub fn auth_note(&self) -> Option<String> {
        self.plaintext_tcp.then(|| {
            format!(
                "Note: auth is \"none\" — anything that can reach the tcp listener can mount \
                 this namespace. See {THREAT_MODEL}."
            )
        })
    }

    /// The copy-paste `voidport-ctl` line for this server.
    ///
    /// A seeded launch's socket is not the one `voidport-ctl` assumes by
    /// default — it lives beside the state file so that sharing needs no root —
    /// so the operator is handed the `--socket` spelling of the socket the
    /// server really bound, the same way they are handed the mount lines.
    #[must_use]
    pub fn control_command(&self) -> String {
        format!(
            "voidport-ctl --socket {} info",
            self.control_socket.display()
        )
    }
}

/// The mount command for one bound endpoint.
fn mount_command(
    namespace: &NamespaceName,
    endpoint: &Endpoint,
    mountpoint: &Path,
) -> MountCommand {
    use std::os::unix::ffi::OsStrExt as _;

    let (transport, authority) = match endpoint {
        // `SocketAddr`'s own rendering is the URL grammar's: an IPv6 literal
        // comes out bracketed, and the port is the one that was bound.
        Endpoint::Tcp(address) => (Transport::Tcp, format!("voidport://{address}")),
        Endpoint::Unix(path) => (
            Transport::Unix,
            format!(
                "voidport+unix://{}",
                percent_encode(path.as_os_str().as_bytes(), AUTHORITY)
            ),
        ),
        // The cid printed is the one a *guest* dials, which is not the one the
        // server bound: a wildcard bind has no address of its own, and the cid
        // a guest reaches its host at is the vsock convention `VMADDR_CID_HOST`.
        // A listener bound to one specific cid is printed as that cid, because
        // then there is a real address and it is the only one that works.
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
    };
    MountCommand {
        transport,
        url: format!(
            "{authority}/@{}",
            percent_encode(namespace.as_str().as_bytes(), SEGMENT)
        ),
        mountpoint: mountpoint.to_path_buf(),
    }
}

impl fmt::Display for LaunchSummary {
    /// The block the daemon prints, and the TUI shows.
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
    use crate::testing::Scratch;

    fn name(raw: &str) -> NamespaceName {
        NamespaceName::new(raw).expect("valid namespace name")
    }

    /// Binds listeners and reports the endpoints they bound, keeping the
    /// sockets alive so the ports and paths under test stay taken.
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
        let port = endpoints[0].tcp_address().expect("a tcp listener").port();
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
        assert!(rendered.contains(THREAT_MODEL), "{rendered}");
        // The operator is handed the socket the server bound, not the default
        // `voidport-ctl` would otherwise assume.
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
        let rendered = summary.to_string();
        assert!(!rendered.contains(THREAT_MODEL), "{rendered}");
        assert!(rendered.contains(&encoded), "{rendered}");
    }

    /// The cid a guest is told to dial is not always the cid the server bound:
    /// a wildcard bind has no address of its own, so the command names the cid
    /// a guest reaches its host at, and a listener bound to one context id
    /// names that one because it is the only one that works.
    #[test]
    fn a_vsock_listener_prints_the_cid_a_guest_dials() {
        if !crate::testing::vsock::preflight() {
            return;
        }
        let (_wildcard, endpoints) = bind(&[Listener::Vsock {
            cid: vsock::VMADDR_CID_ANY,
            port: crate::testing::vsock::free_port().expect("a free vsock port"),
        }]);
        let (_, port) = endpoints[0].vsock_address().expect("a vsock listener");

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
        let rendered = summary.to_string();
        assert!(!rendered.contains(THREAT_MODEL), "{rendered}");

        // A listener bound to one cid is printed as that cid. The local one is
        // the only specific cid a machine without guests can bind.
        let (_local, endpoints) = bind(&[Listener::Vsock {
            cid: vsock::VMADDR_CID_LOCAL,
            port: crate::testing::vsock::free_port().expect("a free vsock port"),
        }]);
        let (_, port) = endpoints[0].vsock_address().expect("a vsock listener");
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
        // The namespace rides in a path segment, so a name the grammar reserves
        // characters of is encoded, not printed raw.
        assert!(summary.mounts[0].url.ends_with("/@a%20b"), "{summary}");
        assert!(summary.mounts[1].url.ends_with("/@a%20b"), "{summary}");
    }
}
