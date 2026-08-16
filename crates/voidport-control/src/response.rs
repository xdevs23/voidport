//! Control-plane responses.
//!
//! Every request is answered with exactly one [`Response`] line: either
//! `{"status":"ok","result":{...}}` or
//! `{"status":"error","error":{"code":...,"message":...}}`. The envelope is
//! the stable script interface — `voidport-ctl --json` prints the line
//! verbatim — so the shape is deliberately boring and totally classified: an
//! error always carries a machine-readable [`ErrorCode`] alongside its human
//! message.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::policy::{AuthMode, NamespaceName, NamespaceSpec, PermissionMode};

/// The response envelope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "lowercase", deny_unknown_fields)]
pub enum Response {
    /// The operation succeeded.
    Ok {
        /// What the operation produced.
        result: Reply,
    },
    /// The operation failed and changed nothing.
    Error {
        /// Why it failed.
        error: ControlError,
    },
}

impl Response {
    /// A successful response.
    #[must_use]
    pub fn ok(result: Reply) -> Self {
        Self::Ok { result }
    }

    /// A failed response.
    #[must_use]
    pub fn error(error: ControlError) -> Self {
        Self::Error { error }
    }

    /// The error, if this is a failure.
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

/// What a successful operation produced.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reply", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Reply {
    /// A mutation that produced nothing beyond its own success.
    Done {},
    /// Facts about the running server.
    ServerInfo {
        /// The server's package version.
        version: String,
        /// The state file the server owns, as configured.
        state_file: String,
        /// The control socket the server bound, as configured.
        control_socket: String,
        /// How many namespaces the server currently serves.
        namespaces: usize,
        /// The data-plane endpoints the server is bound to right now.
        ///
        /// Live, not a startup snapshot: `listener-add` and `listener-remove`
        /// change this set while the server runs, so an operator surface that
        /// re-reads `server-info` follows them on its own cadence. It is
        /// reported because an operator attached to a server they did not
        /// launch cannot otherwise learn where its guests connect — the state
        /// file is the server's own, and a listener configured on port 0 does
        /// not name its real port there anyway.
        #[serde(default)]
        listeners: Vec<ListenerInfo>,
        /// How many node descriptors the server's cache holds resident right
        /// now, across every session.
        ///
        /// Read-only, and the only honest view there is: a node's `O_PATH` pin
        /// is a slot in a bounded cache, and `/proc/<pid>/fd` counts
        /// descriptors without being able to say which of them is a cache slot,
        /// which is an open handle's, and which is a graft's.
        #[serde(default)]
        node_descriptors: usize,
        /// The bound that count is held under. Startup-only, from
        /// `[server] node_descriptor_budget` or derived from the descriptor
        /// limit the server reached.
        #[serde(default)]
        node_descriptor_budget: usize,
        /// Where the server writes its own tracing, when it writes it to a
        /// file at all.
        ///
        /// Read-only, and reported for the same reason the listeners are: an
        /// operator attached to a server they did not launch cannot otherwise
        /// learn where its diagnostics land. `None` is the ordinary launch —
        /// a server logging to its own stderr — which is a fact about that
        /// server, not a missing answer. The path is the *server's*: a reader
        /// that does not share its filesystem can only name it.
        #[serde(default)]
        log_file: Option<String>,
    },
    /// A summary of every namespace.
    NamespaceList {
        /// The namespaces, in name order.
        namespaces: Vec<NamespaceSummary>,
    },
    /// One namespace in source form.
    Namespace {
        /// The namespace exactly as the state file holds it.
        namespace: NamespaceSpec,
    },
    /// One data-plane listener, as it bound.
    ///
    /// `listener-add`'s answer: the endpoint here is the one a guest connects
    /// to and the one `listener-remove` takes, which for a listener configured
    /// on port 0 is the only place the real port is ever stated.
    Listener {
        /// The endpoint the listener bound.
        listener: ListenerInfo,
    },
    /// The data-plane sessions the server is serving.
    SessionList {
        /// The live sessions, in session-id order.
        sessions: Vec<SessionSummary>,
    },
}

/// One line of `namespace list`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamespaceSummary {
    /// The namespace name.
    pub name: NamespaceName,
    /// Its ownership mode, as the schema spells it.
    pub ownership: String,
    /// Its permission mode.
    pub permission: PermissionMode,
    /// Its auth mode.
    pub auth: AuthMode,
    /// How many rules its table holds.
    pub rules: usize,
}

/// One data-plane endpoint the server bound.
///
/// The endpoint is the address **as bound**, not as configured: a tcp listener
/// configured on port 0 reports the port the kernel gave it, which is the only
/// spelling a guest can connect to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListenerInfo {
    /// The transport, as the state file spells it (`tcp`, `unix`).
    pub transport: String,
    /// The bound endpoint: a socket address, or a unix socket path.
    pub endpoint: String,
}

impl ListenerInfo {
    /// Describes one bound endpoint.
    #[must_use]
    pub fn new(transport: impl Into<String>, endpoint: impl Into<String>) -> Self {
        Self {
            transport: transport.into(),
            endpoint: endpoint.into(),
        }
    }
}

impl fmt::Display for ListenerInfo {
    /// `tcp 127.0.0.1:9000` — the form both operator surfaces list.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.transport, self.endpoint)
    }
}

/// One line of `session list`.
///
/// A session is one mount: one client's connection to one namespace subpath.
/// The counts are what an operator needs to see whether a guest is holding
/// resources — and, with the caps, how close it is to its limits.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionSummary {
    /// The server-assigned session id.
    pub id: u64,
    /// The namespace the session mounted.
    pub namespace: NamespaceName,
    /// The subpath within it, as the mount resolved it.
    pub subpath: String,
    /// The transport the client arrived on.
    pub transport: String,
    /// The peer address, as the transport describes it.
    pub peer: String,
    /// How many nodes the session holds.
    pub nodes: usize,
    /// How many handles it holds open.
    pub handles: usize,
    /// Whether the session is listening to share changes.
    ///
    /// The operator's window onto the subscription: a consumer that keeps
    /// lapsing is diagnosable from the control plane without touching the data
    /// plane at all.
    #[serde(default)]
    pub subscribed: bool,
}

/// A structured failure.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(deny_unknown_fields)]
#[error("{code}: {message}")]
pub struct ControlError {
    /// The machine-readable class of failure.
    pub code: ErrorCode,
    /// The human-readable detail, including the namespace and rule at fault
    /// where the server knows them.
    pub message: String,
}

impl ControlError {
    /// Builds a structured failure.
    #[must_use]
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

/// The machine-readable class of a control-plane failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ErrorCode {
    /// The request line was not valid JSON.
    MalformedRequest,
    /// The request named an operation the server does not implement.
    UnknownOperation,
    /// The request was JSON but not a valid request: a missing, unknown or
    /// ill-typed field.
    InvalidRequest,
    /// The request line exceeded the size bound. The connection closes after
    /// this response.
    RequestTooLarge,
    /// The named namespace, or the named rule, does not exist.
    NotFound,
    /// The namespace or rule already exists; creation would be ambiguous.
    AlreadyExists,
    /// The resulting configuration is invalid — the rule table or the
    /// ownership algebra rejected it. Nothing changed.
    InvalidConfiguration,
    /// A listener could not be bound: the message carries the operating
    /// system's own answer. Nothing was persisted and every other listener
    /// keeps serving.
    BindFailed,
    /// The new state could not be persisted. Nothing was published: neither
    /// memory nor the state file changed.
    PersistFailed,
    /// The server hit an unexpected condition.
    Internal,
}

impl ErrorCode {
    /// The wire spelling of the code.
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

        // A server with nothing bound reports an empty list, and a reply
        // written before the field existed still reads.
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

    /// `listener-add` answers where the listener landed, which for a port-0
    /// configuration is the only statement of the real port anywhere.
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
            nodes: 3,
            handles: 1,
            subscribed: true,
        };
        let encoded = serde_json::to_string(&summary).expect("serializable");
        assert_eq!(
            encoded,
            r#"{"id":7,"namespace":"project","subpath":"/project","transport":"tcp","peer":"127.0.0.1:34000","nodes":3,"handles":1,"subscribed":true}"#
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
            ownership: "map".to_owned(),
            permission: PermissionMode::Passthrough,
            auth: AuthMode::None,
            rules: 3,
        };
        let encoded = serde_json::to_string(&summary).expect("serializable");
        assert_eq!(
            encoded,
            r#"{"name":"project","ownership":"map","permission":"passthrough","auth":"none","rules":3}"#
        );
        assert_eq!(
            serde_json::from_str::<NamespaceSummary>(&encoded).expect("parses"),
            summary
        );
    }
}
