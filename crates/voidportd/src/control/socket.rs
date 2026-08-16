//! The control socket.
//!
//! Binding it is the general server-owned unix-socket contract, implemented
//! once in [`crate::socket`] and shared with the `unix` data-plane listener —
//! the design gives both sockets the same bind/reclaim/unlink rules, so they
//! must not drift apart. This module is the control plane's name for it.

pub use crate::socket::{
    BindError, SOCKET_MODE as CONTROL_SOCKET_MODE, UnixSocket as ControlSocket,
};
