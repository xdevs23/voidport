//! The voidport control-plane protocol.
//!
//! The control plane is a unix-socket, newline-delimited JSON channel between
//! `voidportd` and the operator CLI (`voidport-ctl`): one request object per
//! line, one response object per line, in order per connection. This crate is
//! the *typed* shape of that channel, shared by both sides so neither can
//! drift from the other — the server never hand-builds a response string and
//! the CLI never hand-parses one.
//!
//! Three layers live here:
//!
//! * [`policy`] — the **source form** of namespace policy: exactly what an
//!   operator wrote, with id sentinels still sentinels and relative host
//!   targets still relative. The same types are the state file's namespace
//!   schema (`voidportd` parses them from TOML) and the payload of the
//!   mutating control operations, which is what makes
//!   "a mutation never bakes a sentinel into a machine-specific number"
//!   structurally true, not a convention.
//! * [`listener`] — the source form of a data-plane listener, shared for the
//!   same reason: it is the state file's `[[server.listeners]]` entry and the
//!   payload of `listener-add`, so a listener added at runtime and one written
//!   in the file are the same value.
//! * [`request`] — the tagged [`Request`] enum, one variant per operation.
//! * [`response`] — the [`Response`] envelope: a [`Reply`] on success, a
//!   [`ControlError`] with an [`ErrorCode`] on failure.
//!
//! * [`socket`] — where the control socket lives: the compiled default, the
//!   per-user path a seeded launch binds, and the order an operator surface
//!   with no `--socket` tries them in. Both ends share it so the server's
//!   fallback and the operator surfaces' search cannot drift apart.
//!
//! Behind the off-by-default `client` cargo feature there is a fourth:
//! [`client`] — the blocking, timeout-bounded connection every operator
//! surface talks through. It is optional so that a consumer wanting only the
//! typed shapes keeps this crate at serde and nothing else.
//!
//! # Wire shape
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
//!
//! The envelope is the stable script interface: `voidport-ctl --json` prints
//! the response line verbatim.

#![deny(missing_docs)]

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

pub use listener::{ANY_CID, Listener};
pub use policy::{
    AuthMode, DEFAULT_SQUASH_ID, HostId, IdMapping, IdSentinel, NamespaceName, NamespaceNameError,
    NamespaceSpec, OwnershipSpec, PermissionMode, Rule, RuleKey, ShareMode, UnknownMode,
    UnmappedPolicy, XattrRule, XattrVerdict,
};
pub use request::{OPERATIONS, Request, parse_request};
pub use response::{
    ControlError, ErrorCode, ListenerInfo, NamespaceSummary, Reply, Response, SessionSummary,
};

#[cfg(feature = "client")]
pub use client::{Answer, Client, ClientError, Timeouts};
