//! The control plane.
//!
//! A completely separate listener from the data plane: unix socket only, never
//! exposed on a data-plane transport, speaking newline-delimited JSON through
//! the shared `voidport-control` types.
//!
//! The three modules split cleanly by concern, which is what makes the whole
//! thing testable:
//!
//! * [`socket`] — the bind/reclaim/unlink contract, entirely synchronous;
//! * [`listener`] — framing, connection lifecycle and the request bound;
//! * [`service`] — what a request *means*, including the serialized
//!   validate → persist → swap mutation sequence.

pub mod listener;
pub mod service;
pub mod socket;

pub use listener::{MAX_REQUEST_LINE, serve};
pub use service::{Service, Snapshot};
pub use socket::{BindError, CONTROL_SOCKET_MODE, ControlSocket};
