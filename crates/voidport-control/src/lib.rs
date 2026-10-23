//! The typed shape of the newline-delimited JSON control channel between
//! `voidportd` and `voidport-ctl`, shared by both ends. The `client` feature
//! adds the blocking connection used by the operator surfaces.
//!
//! ```
//! use voidport_control::{Request, Response, Reply};
//!
//! let request = Request::NamespaceList {};
//! assert_eq!(serde_json::to_string(&request)?, r#"{"op":"namespace-list"}"#);
//!
//! let line = r#"{"status":"ok","result":{"reply":"done"}}"#;
//! assert_eq!(
//!     serde_json::from_str::<Response>(line)?,
//!     Response::Ok { result: Reply::Done {} }
//! );
//! # Ok::<(), serde_json::Error>(())
//! ```

#![forbid(unsafe_code)]

#[cfg(feature = "client")]
pub mod client;
pub mod listener;
pub mod policy;
pub mod request;
pub mod response;
pub mod socket;

pub use socket::{
    DEFAULT_CONTROL_SOCKET, default_control_sockets, user_control_socket, user_state_directory,
};
#[cfg(feature = "client")]
pub use socket::{NoControlSocket, find_control_socket};

pub use listener::{ANY_CID, Listener, VSOCK_PORTS, VsockPort};
pub use policy::{
    AuthMode, DEFAULT_SQUASH_ID, HostDirectIo, HostId, IdMapping, IdSentinel, NamespaceName,
    NamespaceNameError, NamespaceSpec, OwnershipMode, OwnershipSpec, PermissionMode, Rule, RuleKey,
    ShareMode, UnknownMode, UnmappedPolicy, XattrRule, XattrVerdict,
};
pub use request::{OPERATIONS, Request, parse_request};
pub use response::{
    AdmittedMode, ControlError, ErrorCode, ListenerInfo, NamespaceSummary, PathResolution, Reply,
    Response, SessionSummary,
};

#[cfg(feature = "client")]
pub use client::{Answer, Client, ClientError, Timeouts};
