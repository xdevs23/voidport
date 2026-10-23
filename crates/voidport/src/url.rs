//! ```text
//! voidport://host:port/@namespace[/subpath…]
//! voidport+unix://<socket>/@namespace[/subpath…]
//! voidport+vsock://cid:port/@namespace[/subpath…]
//! ```
//!
//! The `url` crate answers whether a string is a URL, and this module answers
//! whether it is a mount. A socket path is the authority, so it is written
//! percent-encoded: a path contains `/`, which is not a legal host character.
//! A vsock mount has no default cid, because the cid is a fact about the
//! machine and not about the client. One trailing empty path segment is the same
//! as none and names the namespace root, and an empty segment anywhere else is
//! rejected. Userinfo, query and fragment are rejected, because accepting them
//! would silently ignore what was written.

use std::ffi::OsString;
use std::fmt;
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::path::PathBuf;

use percent_encoding::{AsciiSet, CONTROLS, percent_decode, percent_encode};
use voidport_control::{NamespaceName, NamespaceNameError};
// The crate root has a module of this name, so the extern crate is named
// explicitly.
use ::url::{Host, Url};

pub const TCP_SCHEME: &str = "voidport";

pub const UNIX_SCHEME: &str = "voidport+unix";

pub const VSOCK_SCHEME: &str = "voidport+vsock";

/// What an authority component must not carry literally: the forbidden host
/// code points of the URL standard, plus `%`, so that an encoded byte is never
/// read again as the start of another escape.
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
pub enum Endpoint {
    /// A tcp server. The host is unbracketed, as a resolver wants it.
    Tcp { host: String, port: u16 },
    /// A unix socket on this machine.
    Unix { path: PathBuf },
    Vsock {
        cid: u32,
        /// Port; always explicit, and 16-bit because the URL grammar's port is.
        port: u16,
    },
}

/// An IPv6 literal is re-bracketed and a socket path is percent-encoded, so
/// appending `/@namespace` yields a URL that parses to what it came from.
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MountUrl {
    pub endpoint: Endpoint,
    pub namespace: NamespaceName,
    /// The subpath within the namespace, as the handshake carries it: absolute
    /// bytes, or empty for the namespace root.
    pub subpath: Vec<u8>,
}

impl MountUrl {
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

/// Every component is percent-encoded again, so a logged URL can be pasted
/// back, and a byte that is not text is never printed raw.
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

/// The scheme is not a special one, so the URL crate treats the host as an
/// opaque string and returns the port already parsed as a 16-bit number, which
/// is the range of the vsock listeners of the server. What is left to check is
/// the cid, a plain 32-bit number.
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

fn decode(component: &str) -> Result<Vec<u8>, UrlError> {
    let bytes = percent_decode(component.as_bytes()).collect::<Vec<u8>>();
    if bytes.contains(&0) {
        return Err(UrlError::NulByte);
    }
    Ok(bytes)
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum UrlError {
    #[error("not a URL: {reason}")]
    Syntax { reason: String },
    #[error("unknown scheme {scheme:?}: expected {TCP_SCHEME}, {UNIX_SCHEME} or {VSOCK_SCHEME}")]
    Scheme { scheme: String },
    #[error("no host: a {TCP_SCHEME} URL is {TCP_SCHEME}://host:port/@namespace")]
    MissingHost,
    #[error("no port: a {TCP_SCHEME} URL must state the server's port explicitly")]
    MissingPort,
    #[error(
        "no socket path: a {UNIX_SCHEME} URL carries the socket path as its authority, \
         percent-encoded (for example {UNIX_SCHEME}://%2Frun%2Fvoidport%2Fdata.sock/@namespace)"
    )]
    MissingSocketPath,
    #[error("socket path {path:?} is relative: it must be absolute")]
    RelativeSocketPath { path: String },
    #[error("a {UNIX_SCHEME} URL has no port")]
    SocketPort,
    #[error("no cid: a {VSOCK_SCHEME} URL is {VSOCK_SCHEME}://cid:port/@namespace")]
    MissingCid,
    #[error("invalid cid {cid:?}: a vsock context id is a number in 0..=4294967295")]
    Cid { cid: String },
    #[error("no port: a {VSOCK_SCHEME} URL must state the server's port explicitly")]
    MissingVsockPort,
    #[error("no namespace: the first path segment must be @namespace")]
    MissingNamespace,
    #[error("invalid namespace name: {source}")]
    NamespaceName {
        #[source]
        source: NamespaceNameError,
    },
    #[error("invalid namespace name: it must be UTF-8")]
    NamespaceNotUtf8,
    #[error("empty path segment: a subpath component must name something")]
    EmptySegment,
    #[error("NUL byte in the URL: no path component may contain one")]
    NulByte,
    #[error("userinfo is not accepted: v1 serves auth mode none")]
    Userinfo,
    #[error("query strings are not accepted")]
    Query,
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
