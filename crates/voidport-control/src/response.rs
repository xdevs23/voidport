//! Every request is answered with exactly one [`Response`] line. The envelope
//! is the script interface: `voidport-ctl --json` prints the line verbatim.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::policy::{
    AuthMode, HostDirectIo, NamespaceName, NamespaceSpec, OwnershipMode, PermissionMode,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "lowercase", deny_unknown_fields)]
pub enum Response {
    Ok {
        result: Reply,
    },
    /// The operation failed and changed nothing.
    Error {
        error: ControlError,
    },
}

impl Response {
    #[must_use]
    pub fn ok(result: Reply) -> Self {
        Self::Ok { result }
    }

    #[must_use]
    pub fn error(error: ControlError) -> Self {
        Self::Error { error }
    }

    #[must_use]
    pub fn as_error(&self) -> Option<&ControlError> {
        match self {
            Self::Ok { .. } => None,
            Self::Error { error } => Some(error),
        }
    }
}

impl From<ControlError> for Response {
    fn from(error: ControlError) -> Self {
        Self::error(error)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reply", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Reply {
    Done {},
    ServerInfo {
        version: String,
        state_file: String,
        control_socket: String,
        namespaces: usize,
        /// Live: `listener-add` and `listener-remove` change this set while the
        /// server runs, and a listener configured on port 0 does not name its
        /// real port in the state file.
        #[serde(default)]
        listeners: Vec<ListenerInfo>,
        /// Read-only. A node's `O_PATH` descriptor is a slot in a bounded cache,
        /// and `/proc/<pid>/fd` cannot tell a cache slot from an open handle or
        /// a graft.
        #[serde(default)]
        node_descriptors: usize,
        /// Startup-only, from `[server] node_descriptor_budget` or derived from
        /// the descriptor limit the server reached.
        #[serde(default)]
        node_descriptor_budget: usize,
        /// `None` when the server logs to its own stderr. The path is the
        /// server's: a reader that does not share its filesystem can only name
        /// it.
        #[serde(default)]
        log_file: Option<String>,
    },
    NamespaceList {
        namespaces: Vec<NamespaceSummary>,
    },
    Namespace {
        namespace: NamespaceSpec,
    },
    Listener {
        listener: ListenerInfo,
    },
    SessionList {
        sessions: Vec<SessionSummary>,
    },
    Resolution {
        resolution: PathResolution,
    },
}

/// Only the rules are applied. The walk does not read the host, so it does not
/// check that the host path behind an admitted entry exists, and the ownership
/// policy is not applied either.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum PathResolution {
    Host {
        mode: AdmittedMode,
        host_path: String,
    },
    Synthesized {},
    /// The path does not resolve. A hidden path and a path that no rule
    /// admits give the same result, as they do for a guest lookup.
    Absent {},
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AdmittedMode {
    Rw,
    Ro,
}

impl fmt::Display for AdmittedMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(match self {
            Self::Rw => "rw",
            Self::Ro => "ro",
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamespaceSummary {
    pub name: NamespaceName,
    pub ownership: OwnershipMode,
    pub permission: PermissionMode,
    pub direct_io: HostDirectIo,
    pub auth: AuthMode,
    pub rules: usize,
}

/// The endpoint is the address as bound, not as configured: a tcp listener
/// configured on port 0 reports the port the kernel gave it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListenerInfo {
    pub transport: String,
    pub endpoint: String,
}

impl ListenerInfo {
    #[must_use]
    pub fn new(transport: impl Into<String>, endpoint: impl Into<String>) -> Self {
        Self {
            transport: transport.into(),
            endpoint: endpoint.into(),
        }
    }
}

impl fmt::Display for ListenerInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.transport, self.endpoint)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionSummary {
    pub id: u64,
    pub namespace: NamespaceName,
    pub subpath: String,
    pub transport: String,
    pub peer: String,
    pub connections: usize,
    pub nodes: usize,
    pub handles: usize,
    #[serde(default)]
    pub subscribed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(deny_unknown_fields)]
#[error("{code}: {message}")]
pub struct ControlError {
    pub code: ErrorCode,
    pub message: String,
}

impl ControlError {
    #[must_use]
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ErrorCode {
    MalformedRequest,
    UnknownOperation,
    InvalidRequest,
    /// The request line exceeded the size bound. The connection closes after
    /// this response.
    RequestTooLarge,
    NotFound,
    AlreadyExists,
    InvalidConfiguration,
    /// The message carries the operating system's own answer. Nothing was
    /// persisted and every other listener keeps serving.
    BindFailed,
    /// Nothing was published: neither memory nor the state file changed.
    PersistFailed,
    Internal,
}

impl ErrorCode {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MalformedRequest => "malformed-request",
            Self::UnknownOperation => "unknown-operation",
            Self::InvalidRequest => "invalid-request",
            Self::RequestTooLarge => "request-too-large",
            Self::NotFound => "not-found",
            Self::AlreadyExists => "already-exists",
            Self::InvalidConfiguration => "invalid-configuration",
            Self::BindFailed => "bind-failed",
            Self::PersistFailed => "persist-failed",
            Self::Internal => "internal",
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_envelope_round_trips() {
        let cases = [
            (
                Response::ok(Reply::Done {}),
                r#"{"status":"ok","result":{"reply":"done"}}"#,
            ),
            (
                Response::ok(Reply::NamespaceList {
                    namespaces: Vec::new(),
                }),
                r#"{"status":"ok","result":{"reply":"namespace-list","namespaces":[]}}"#,
            ),
            (
                Response::error(ControlError::new(ErrorCode::NotFound, "no such namespace")),
                r#"{"status":"error","error":{"code":"not-found","message":"no such namespace"}}"#,
            ),
        ];
        for (response, encoded) in cases {
            assert_eq!(
                serde_json::to_string(&response).expect("serializable"),
                encoded
            );
            assert_eq!(
                serde_json::from_str::<Response>(encoded).expect("parses"),
                response
            );
        }
    }

    #[test]
    fn errors_carry_a_code_and_a_message() {
        let error = ControlError::new(ErrorCode::InvalidConfiguration, "namespace \"p\": bad rule");
        assert_eq!(
            error.to_string(),
            "invalid-configuration: namespace \"p\": bad rule"
        );
        let response = Response::from(error.clone());
        assert_eq!(response.as_error(), Some(&error));
        assert_eq!(Response::ok(Reply::Done {}).as_error(), None);
    }

    #[test]
    fn every_error_code_has_a_stable_wire_spelling() {
        let codes = [
            ErrorCode::MalformedRequest,
            ErrorCode::UnknownOperation,
            ErrorCode::InvalidRequest,
            ErrorCode::RequestTooLarge,
            ErrorCode::NotFound,
            ErrorCode::AlreadyExists,
            ErrorCode::InvalidConfiguration,
            ErrorCode::BindFailed,
            ErrorCode::PersistFailed,
            ErrorCode::Internal,
        ];
        for code in codes {
            let encoded = serde_json::to_string(&code).expect("serializable");
            assert_eq!(encoded, format!("\"{}\"", code.as_str()));
            assert_eq!(
                serde_json::from_str::<ErrorCode>(&encoded).expect("parses"),
                code
            );
        }
    }

    #[test]
    fn server_info_carries_the_bound_listeners() {
        let reply = Reply::ServerInfo {
            version: "0.1.0".to_owned(),
            state_file: "/srv/state.toml".to_owned(),
            control_socket: "/run/control.sock".to_owned(),
            namespaces: 1,
            listeners: vec![
                ListenerInfo::new("tcp", "127.0.0.1:40404"),
                ListenerInfo::new("unix", "/srv/data.sock"),
            ],
            node_descriptors: 17,
            node_descriptor_budget: 4096,
            log_file: Some("/srv/voidportd.log".to_owned()),
        };
        let encoded = serde_json::to_string(&reply).expect("serializable");
        assert!(
            encoded.contains(r#""listeners":[{"transport":"tcp","endpoint":"127.0.0.1:40404"}"#),
            "{encoded}"
        );
        assert!(
            encoded.contains(r#""node_descriptors":17,"node_descriptor_budget":4096"#),
            "{encoded}"
        );
        assert!(
            encoded.contains(r#""log_file":"/srv/voidportd.log""#),
            "{encoded}"
        );
        assert_eq!(
            serde_json::from_str::<Reply>(&encoded).expect("parses"),
            reply
        );
        assert_eq!(
            ListenerInfo::new("tcp", "127.0.0.1:40404").to_string(),
            "tcp 127.0.0.1:40404"
        );

        // A reply written before the field existed still reads.
        let older = r#"{"reply":"server-info","version":"0.1.0","state_file":"s","control_socket":"c","namespaces":0}"#;
        assert_eq!(
            serde_json::from_str::<Reply>(older).expect("parses"),
            Reply::ServerInfo {
                version: "0.1.0".to_owned(),
                state_file: "s".to_owned(),
                control_socket: "c".to_owned(),
                namespaces: 0,
                listeners: Vec::new(),
                node_descriptors: 0,
                node_descriptor_budget: 0,
                log_file: None,
            }
        );
    }

    #[test]
    fn a_bound_listener_is_a_reply_of_its_own() {
        let reply = Reply::Listener {
            listener: ListenerInfo::new("tcp", "127.0.0.1:40404"),
        };
        let encoded = serde_json::to_string(&reply).expect("serializable");
        assert_eq!(
            encoded,
            r#"{"reply":"listener","listener":{"transport":"tcp","endpoint":"127.0.0.1:40404"}}"#
        );
        assert_eq!(
            serde_json::from_str::<Reply>(&encoded).expect("parses"),
            reply
        );
    }

    #[test]
    fn session_summaries_describe_one_mount() {
        let summary = SessionSummary {
            id: 7,
            namespace: NamespaceName::new("project").expect("valid"),
            subpath: "/project".to_owned(),
            transport: "tcp".to_owned(),
            peer: "127.0.0.1:34000".to_owned(),
            connections: 2,
            nodes: 3,
            handles: 1,
            subscribed: true,
        };
        let encoded = serde_json::to_string(&summary).expect("serializable");
        assert_eq!(
            encoded,
            r#"{"id":7,"namespace":"project","subpath":"/project","transport":"tcp","peer":"127.0.0.1:34000","connections":2,"nodes":3,"handles":1,"subscribed":true}"#
        );
        assert_eq!(
            serde_json::from_str::<SessionSummary>(&encoded).expect("parses"),
            summary
        );
        let envelope = serde_json::to_string(&Response::ok(Reply::SessionList {
            sessions: vec![summary],
        }))
        .expect("serializable");
        assert!(
            envelope.starts_with(r#"{"status":"ok","result":{"reply":"session-list""#),
            "{envelope}"
        );
    }

    #[test]
    fn summaries_describe_a_namespace_at_a_glance() {
        let summary = NamespaceSummary {
            name: NamespaceName::new("project").expect("valid"),
            ownership: OwnershipMode::Map,
            permission: PermissionMode::Passthrough,
            direct_io: HostDirectIo::Cached,
            auth: AuthMode::None,
            rules: 3,
        };
        let encoded = serde_json::to_string(&summary).expect("serializable");
        assert_eq!(
            encoded,
            r#"{"name":"project","ownership":"map","permission":"passthrough","direct_io":"cached","auth":"none","rules":3}"#
        );
        assert_eq!(
            serde_json::from_str::<NamespaceSummary>(&encoded).expect("parses"),
            summary
        );
    }
}
