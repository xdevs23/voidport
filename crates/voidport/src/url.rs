//! The mount URL grammar.
//!
//! ```text
//! voidport://host:port/@namespace[/subpath…]        tcp
//! voidport+unix://<socket>/@namespace[/subpath…]    unix socket
//! voidport+vsock://cid:port/@namespace[/subpath…]   vsock
//! ```
//!
//! Parsing is done by the `url` crate and then *validated* here: the crate
//! answers "is this a URL", this module answers "is this a mount". Every rule
//! below has its own error, because a mount that will not parse is the first
//! thing an operator sees.
//!
//! * The tcp port is **required** — there is no default port. IPv6 hosts take
//!   the bracketed form.
//! * For `voidport+unix` the socket path is the **authority** component,
//!   percent-decoded exactly once to OS bytes, and must be absolute. A path
//!   contains `/`, which is not a legal host character, so it is always written
//!   percent-encoded (`%2Fvar%2Frun%2Fvoidport.sock`).
//! * For `voidport+vsock` the authority is `cid:port`: the context id is a
//!   32-bit number and the port is the URL standard's 16-bit one, which is what
//!   bounds the server's own vsock ports. A guest reaches its host at cid 2 by
//!   the vsock convention (`VMADDR_CID_HOST`), and a machine reaches itself at
//!   cid 1 (`VMADDR_CID_LOCAL`) where the kernel's loopback transport is
//!   loaded; neither is a default here, because the cid a mount names is the
//!   operator's fact and not the client's.
//! * The first path segment must begin with `@`; its remainder is the
//!   namespace name and must satisfy the server's own name rules — the very
//!   type the server validates with.
//! * The remaining segments are percent-decoded exactly once to bytes, joined
//!   with `/` and rooted absolute. No segments means the namespace root, which
//!   the wire spells as an empty subpath. One trailing empty segment (a
//!   trailing slash) is the same thing; an empty segment anywhere else is a
//!   typo, not a path, and is rejected.
//! * userinfo, query and fragment components are rejected: none of them mean
//!   anything to a mount, so accepting them would silently ignore what the
//!   operator wrote.

use std::ffi::OsString;
use std::fmt;
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::path::PathBuf;

use percent_encoding::{AsciiSet, CONTROLS, percent_decode, percent_encode};
use voidport_control::{NamespaceName, NamespaceNameError};
// The crate root has a module of this name, so the extern crate is named
// explicitly.
use ::url::{Host, Url};

/// The scheme of a tcp mount.
pub const TCP_SCHEME: &str = "voidport";

/// The scheme of a unix-socket mount.
pub const UNIX_SCHEME: &str = "voidport+unix";

/// The scheme of a vsock mount.
pub const VSOCK_SCHEME: &str = "voidport+vsock";

/// What an authority component must not carry literally: the URL standard's
/// forbidden host code points, plus `%` so an encoded byte is never re-read as
/// the start of somebody else's escape. Everything non-ASCII is encoded by the
/// encoder itself.
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

/// What a path component must not carry literally: the separator itself, the
/// delimiters that would end the path, and `%`.
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

/// Where a mount's data connection goes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Endpoint {
    /// A tcp server. The host is unbracketed, as a resolver wants it.
    Tcp {
        /// Host name or IP literal.
        host: String,
        /// Port; always explicit.
        port: u16,
    },
    /// A unix socket on this machine.
    Unix {
        /// The socket path, absolute.
        path: PathBuf,
    },
    /// A vsock server: this machine's host, or one of its guests.
    Vsock {
        /// The context id to dial.
        cid: u32,
        /// Port; always explicit, and 16-bit because the URL grammar's port is.
        port: u16,
    },
}

/// Renders the scheme and authority an endpoint was written as.
///
/// A rendered endpoint is the head of the grammar above, not a description of
/// it: an IPv6 literal is re-bracketed and a socket path is percent-encoded
/// back into the authority component, so appending `/@namespace` to this yields
/// a URL that parses to what it came from.
impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp { host, port } if host.contains(':') => {
                write!(f, "{TCP_SCHEME}://[{host}]:{port}")
            }
            Self::Tcp { host, port } => write!(f, "{TCP_SCHEME}://{host}:{port}"),
            Self::Unix { path } => write!(
                f,
                "{UNIX_SCHEME}://{}",
                percent_encode(path.as_os_str().as_bytes(), AUTHORITY)
            ),
            Self::Vsock { cid, port } => write!(f, "{VSOCK_SCHEME}://{cid}:{port}"),
        }
    }
}

/// A parsed mount URL: an endpoint, a namespace, and the subpath to mount.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MountUrl {
    /// Where to connect.
    pub endpoint: Endpoint,
    /// The namespace to ask the server for.
    pub namespace: NamespaceName,
    /// The subpath within the namespace, as the handshake carries it: absolute
    /// bytes, or empty for the namespace root.
    pub subpath: Vec<u8>,
}

impl MountUrl {
    /// Parses and validates a mount URL.
    ///
    /// # Errors
    ///
    /// Returns the [`UrlError`] naming exactly which rule the URL broke.
    pub fn parse(raw: &str) -> Result<Self, UrlError> {
        let url = Url::parse(raw).map_err(|error| UrlError::Syntax {
            reason: error.to_string(),
        })?;

        if !url.username().is_empty() || url.password().is_some() {
            return Err(UrlError::Userinfo);
        }
        if url.query().is_some() {
            return Err(UrlError::Query);
        }
        if url.fragment().is_some() {
            return Err(UrlError::Fragment);
        }

        let endpoint = match url.scheme() {
            TCP_SCHEME => tcp_endpoint(&url)?,
            UNIX_SCHEME => unix_endpoint(&url)?,
            VSOCK_SCHEME => vsock_endpoint(&url)?,
            scheme => {
                return Err(UrlError::Scheme {
                    scheme: scheme.to_owned(),
                });
            }
        };

        let mut segments = url
            .path_segments()
            .ok_or(UrlError::MissingNamespace)?
            .collect::<Vec<_>>();
        // A trailing slash is a spelling of "the thing itself", not an empty
        // final component.
        if segments.last().is_some_and(|segment| segment.is_empty()) {
            segments.pop();
        }
        let mut segments = segments.into_iter();

        let first = segments.next().ok_or(UrlError::MissingNamespace)?;
        let name = first.strip_prefix('@').ok_or(UrlError::MissingNamespace)?;
        // The server's namespace names are UTF-8, so anything else cannot be
        // one whatever the rest of the rules say.
        let name = String::from_utf8(decode(name)?).map_err(|_| UrlError::NamespaceNotUtf8)?;
        let namespace =
            NamespaceName::new(name).map_err(|source| UrlError::NamespaceName { source })?;

        let mut subpath = Vec::new();
        for segment in segments {
            if segment.is_empty() {
                return Err(UrlError::EmptySegment);
            }
            subpath.push(b'/');
            subpath.extend_from_slice(&decode(segment)?);
        }

        Ok(Self {
            endpoint,
            namespace,
            subpath,
        })
    }
}

/// Renders the URL back into the grammar it was parsed from.
///
/// Every component is percent-encoded again, so a logged URL is one an operator
/// can paste back: the subpath is bytes, and a byte that would end the path — or
/// that is not text at all — must not be printed raw.
impl fmt::Display for MountUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}/@{}",
            self.endpoint,
            percent_encode(self.namespace.as_str().as_bytes(), SEGMENT)
        )?;
        for segment in self.subpath.split(|byte| *byte == b'/').skip(1) {
            write!(f, "/{}", percent_encode(segment, SEGMENT))?;
        }
        Ok(())
    }
}

/// The endpoint of a `voidport://host:port/…` URL.
fn tcp_endpoint(url: &Url) -> Result<Endpoint, UrlError> {
    let host = match url.host().ok_or(UrlError::MissingHost)? {
        Host::Domain(domain) => domain.to_owned(),
        Host::Ipv4(address) => address.to_string(),
        Host::Ipv6(address) => address.to_string(),
    };
    if host.is_empty() {
        return Err(UrlError::MissingHost);
    }
    let port = url.port().ok_or(UrlError::MissingPort)?;
    Ok(Endpoint::Tcp { host, port })
}

/// The endpoint of a `voidport+unix://<socket>/…` URL.
fn unix_endpoint(url: &Url) -> Result<Endpoint, UrlError> {
    if url.port().is_some() {
        return Err(UrlError::SocketPort);
    }
    let host = url.host_str().unwrap_or_default();
    if host.is_empty() {
        return Err(UrlError::MissingSocketPath);
    }
    let path = PathBuf::from(OsString::from_vec(decode(host)?));
    if !path.is_absolute() {
        return Err(UrlError::RelativeSocketPath {
            path: path.display().to_string(),
        });
    }
    Ok(Endpoint::Unix { path })
}

/// The endpoint of a `voidport+vsock://cid:port/…` URL.
///
/// The scheme is not a special one, so the URL crate treats the authority's
/// host as an opaque string and hands the port back already parsed as the
/// 16-bit number the grammar allows — which is exactly the range the server's
/// own vsock listeners are constrained to. What is left to check here is the
/// cid, and a cid is a 32-bit number and nothing else: no name resolution, no
/// literal address, no percent-encoding to undo.
fn vsock_endpoint(url: &Url) -> Result<Endpoint, UrlError> {
    let host = url.host_str().unwrap_or_default();
    if host.is_empty() {
        return Err(UrlError::MissingCid);
    }
    let cid = host.parse().map_err(|_| UrlError::Cid {
        cid: host.to_owned(),
    })?;
    let port = url.port().ok_or(UrlError::MissingVsockPort)?;
    Ok(Endpoint::Vsock { cid, port })
}

/// Percent-decodes one component, exactly once, into bytes.
fn decode(component: &str) -> Result<Vec<u8>, UrlError> {
    let bytes = percent_decode(component.as_bytes()).collect::<Vec<u8>>();
    if bytes.contains(&0) {
        return Err(UrlError::NulByte);
    }
    Ok(bytes)
}

/// Why a string is not a mount URL.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum UrlError {
    /// The string is not a URL at all.
    #[error("not a URL: {reason}")]
    Syntax {
        /// What the URL parser said.
        reason: String,
    },
    /// The scheme names no transport this client speaks.
    #[error("unknown scheme {scheme:?}: expected {TCP_SCHEME}, {UNIX_SCHEME} or {VSOCK_SCHEME}")]
    Scheme {
        /// The scheme found.
        scheme: String,
    },
    /// A tcp URL named no host.
    #[error("no host: a {TCP_SCHEME} URL is {TCP_SCHEME}://host:port/@namespace")]
    MissingHost,
    /// A tcp URL named no port, and there is no default one.
    #[error("no port: a {TCP_SCHEME} URL must state the server's port explicitly")]
    MissingPort,
    /// A unix URL named no socket.
    #[error(
        "no socket path: a {UNIX_SCHEME} URL carries the socket path as its authority, \
         percent-encoded (for example {UNIX_SCHEME}://%2Frun%2Fvoidport%2Fdata.sock/@namespace)"
    )]
    MissingSocketPath,
    /// A unix URL's socket path was relative.
    #[error("socket path {path:?} is relative: it must be absolute")]
    RelativeSocketPath {
        /// The path as decoded.
        path: String,
    },
    /// A unix URL carried a port, which names nothing.
    #[error("a {UNIX_SCHEME} URL has no port")]
    SocketPort,
    /// A vsock URL named no context id.
    #[error("no cid: a {VSOCK_SCHEME} URL is {VSOCK_SCHEME}://cid:port/@namespace")]
    MissingCid,
    /// A vsock URL's context id is not a 32-bit number.
    #[error("invalid cid {cid:?}: a vsock context id is a number in 0..=4294967295")]
    Cid {
        /// The authority's host component, as written.
        cid: String,
    },
    /// A vsock URL named no port, and there is no default one.
    #[error("no port: a {VSOCK_SCHEME} URL must state the server's port explicitly")]
    MissingVsockPort,
    /// The first path segment did not name a namespace.
    #[error("no namespace: the first path segment must be @namespace")]
    MissingNamespace,
    /// The namespace name is not one the server would accept.
    #[error("invalid namespace name: {source}")]
    NamespaceName {
        /// Which rule it broke.
        #[source]
        source: NamespaceNameError,
    },
    /// The namespace name decoded to bytes that are not UTF-8.
    #[error("invalid namespace name: it must be UTF-8")]
    NamespaceNotUtf8,
    /// A subpath segment was empty.
    #[error("empty path segment: a subpath component must name something")]
    EmptySegment,
    /// A decoded component contained a NUL byte.
    #[error("NUL byte in the URL: no path component may contain one")]
    NulByte,
    /// The URL carried a userinfo component.
    #[error("userinfo is not accepted: v1 serves auth mode none")]
    Userinfo,
    /// The URL carried a query component.
    #[error("query strings are not accepted")]
    Query,
    /// The URL carried a fragment component.
    #[error("fragments are not accepted")]
    Fragment,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(raw: &str) -> MountUrl {
        MountUrl::parse(raw).unwrap_or_else(|error| panic!("{raw} should parse: {error}"))
    }

    fn error(raw: &str) -> UrlError {
        MountUrl::parse(raw).expect_err(&format!("{raw} should be rejected"))
    }

    #[test]
    fn a_tcp_url_names_an_endpoint_a_namespace_and_a_subpath() {
        let url = parse("voidport://10.0.2.2:1234/@my-namespace/path/to/project");
        assert_eq!(
            url.endpoint,
            Endpoint::Tcp {
                host: "10.0.2.2".to_owned(),
                port: 1234,
            }
        );
        assert_eq!(url.namespace.as_str(), "my-namespace");
        assert_eq!(url.subpath, b"/path/to/project");
    }

    #[test]
    fn a_host_name_and_an_ipv6_literal_both_resolve() {
        assert_eq!(
            parse("voidport://host.example:1/@ns").endpoint,
            Endpoint::Tcp {
                host: "host.example".to_owned(),
                port: 1,
            }
        );
        // The brackets are grammar, not part of the host.
        assert_eq!(
            parse("voidport://[::1]:1234/@ns").endpoint,
            Endpoint::Tcp {
                host: "::1".to_owned(),
                port: 1234,
            }
        );
    }

    #[test]
    fn no_segments_means_the_namespace_root() {
        assert_eq!(parse("voidport://h:1/@ns").subpath, b"");
        assert_eq!(parse("voidport://h:1/@ns/").subpath, b"");
    }

    #[test]
    fn a_unix_url_carries_the_socket_path_as_its_authority() {
        let url = parse("voidport+unix://%2Frun%2Fvoidport%2Fdata.sock/@ns/sub");
        assert_eq!(
            url.endpoint,
            Endpoint::Unix {
                path: PathBuf::from("/run/voidport/data.sock"),
            }
        );
        assert_eq!(url.subpath, b"/sub");
    }

    #[test]
    fn a_vsock_url_carries_a_cid_and_a_port_as_its_authority() {
        let url = parse("voidport+vsock://2:9000/@ns/sub/deeper");
        assert_eq!(url.endpoint, Endpoint::Vsock { cid: 2, port: 9000 });
        assert_eq!(url.namespace.as_str(), "ns");
        assert_eq!(url.subpath, b"/sub/deeper");
        // The whole 32-bit cid range is nameable, and the whole 16-bit port
        // range with it.
        assert_eq!(
            parse("voidport+vsock://4294967295:65535/@ns").endpoint,
            Endpoint::Vsock {
                cid: u32::MAX,
                port: u16::MAX,
            }
        );
        // Every other rule of the grammar applies unchanged.
        assert_eq!(parse("voidport+vsock://1:1/@ns/").subpath, b"");
        assert_eq!(
            parse("voidport+vsock://1:1/@a%20b").namespace.as_str(),
            "a b"
        );
    }

    #[test]
    fn a_vsock_url_answers_the_same_typed_errors_as_the_other_schemes() {
        assert_eq!(error("voidport+vsock://2/@ns"), UrlError::MissingVsockPort);
        assert_eq!(error("voidport+vsock:///@ns"), UrlError::MissingCid);
        assert_eq!(
            error("voidport+vsock://host.example:1/@ns"),
            UrlError::Cid {
                cid: "host.example".to_owned(),
            }
        );
        assert_eq!(
            error("voidport+vsock://-1:1/@ns"),
            UrlError::Cid {
                cid: "-1".to_owned(),
            }
        );
        // A cid past 32 bits is a cid, syntactically, and refused as one.
        assert_eq!(
            error("voidport+vsock://4294967296:1/@ns"),
            UrlError::Cid {
                cid: "4294967296".to_owned(),
            }
        );
        // A port past 16 bits is refused by the URL grammar itself, which is
        // the same refusal the tcp scheme gets and the reason the server's own
        // vsock ports are bounded the same way.
        assert!(matches!(
            error("voidport+vsock://2:65536/@ns"),
            UrlError::Syntax { .. }
        ));
        assert_eq!(error("voidport+vsock://2:1/ns"), UrlError::MissingNamespace);
        assert_eq!(
            error("voidport+vsock://2:1/@ns/a//b"),
            UrlError::EmptySegment
        );
        assert_eq!(error("voidport+vsock://user@2:1/@ns"), UrlError::Userinfo);
    }

    #[test]
    fn components_are_percent_decoded_exactly_once() {
        // The subpath decodes to a space and a literal percent sign, not to a
        // second round of escapes.
        let url = parse("voidport://h:1/@ns/a%20b/100%2525");
        assert_eq!(url.subpath, b"/a b/100%25");
        // A namespace name may be encoded too.
        assert_eq!(parse("voidport://h:1/@a%20b").namespace.as_str(), "a b");
    }

    #[test]
    fn every_rejection_has_its_own_error() {
        assert!(matches!(error("not-a-url"), UrlError::Syntax { .. }));
        assert!(matches!(error("http://h:1/@ns"), UrlError::Scheme { .. }));
        assert_eq!(error("voidport://h/@ns"), UrlError::MissingPort);
        assert_eq!(error("voidport:///@ns"), UrlError::MissingHost);
        // A port with nothing in front of it does not even parse as a URL,
        // which is a distinct, and equally clear, refusal.
        assert!(matches!(
            error("voidport://:1/@ns"),
            UrlError::Syntax { .. }
        ));
        assert_eq!(error("voidport://h:1/ns"), UrlError::MissingNamespace);
        assert_eq!(error("voidport://h:1/"), UrlError::MissingNamespace);
        assert_eq!(error("voidport://h:1/@ns/a//b"), UrlError::EmptySegment);
        assert_eq!(error("voidport://h:1/@ns/a%00b"), UrlError::NulByte);
        assert_eq!(error("voidport://user@h:1/@ns"), UrlError::Userinfo);
        assert_eq!(error("voidport://h:1/@ns?x=1"), UrlError::Query);
        assert_eq!(error("voidport://h:1/@ns#top"), UrlError::Fragment);
        assert_eq!(error("voidport+unix:///@ns"), UrlError::MissingSocketPath);
        assert_eq!(
            error("voidport+unix://relative.sock/@ns"),
            UrlError::RelativeSocketPath {
                path: "relative.sock".to_owned(),
            }
        );
        assert_eq!(
            error("voidport+unix://%2Fa.sock:7/@ns"),
            UrlError::SocketPort
        );
    }

    #[test]
    fn an_invalid_namespace_name_is_refused_before_any_server_sees_it() {
        assert!(matches!(
            error("voidport://h:1/@"),
            UrlError::NamespaceName { .. }
        ));
        // A separator inside the name: it would name two path components.
        assert!(matches!(
            error("voidport://h:1/@a%2Fb"),
            UrlError::NamespaceName { .. }
        ));
        // A control character: it could truncate a C string.
        assert!(matches!(
            error("voidport://h:1/@a%01b"),
            UrlError::NamespaceName { .. }
        ));
    }

    #[test]
    fn a_mount_url_renders_back_into_its_own_grammar() {
        for raw in [
            "voidport://10.0.2.2:1234/@ns/a/b",
            "voidport://[::1]:1234/@ns",
            "voidport://host.example:1/@a%20b/a%20b/100%2525",
            "voidport+unix://%2Frun%2Fvoidport%2Fdata.sock/@ns/sub/deeper",
            "voidport+unix://%2Ftmp%2Fa%20b.sock/@ns",
            "voidport+vsock://2:9000/@ns/a/b",
            "voidport+vsock://1:65535/@a%20b",
        ] {
            let url = parse(raw);
            let rendered = url.to_string();
            assert_eq!(MountUrl::parse(&rendered).as_ref(), Ok(&url), "{rendered}");
        }
    }

    #[test]
    fn a_rendered_url_states_its_scheme_and_encodes_what_the_grammar_reserves() {
        assert_eq!(
            parse("voidport://10.0.2.2:1234/@ns/a/b").to_string(),
            "voidport://10.0.2.2:1234/@ns/a/b"
        );
        assert_eq!(
            parse("voidport://[::1]:1234/@ns").to_string(),
            "voidport://[::1]:1234/@ns"
        );
        assert_eq!(
            parse("voidport+unix://%2Frun%2Fdata.sock/@ns/a%20b").to_string(),
            "voidport+unix://%2Frun%2Fdata.sock/@ns/a%20b"
        );
        assert_eq!(
            parse("voidport+vsock://2:9000/@ns/a/b").to_string(),
            "voidport+vsock://2:9000/@ns/a/b"
        );
    }
}
