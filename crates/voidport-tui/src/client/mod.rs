//! The client layer: the TUI's side of the control socket.
//!
//! The connection itself is the shared one — `voidport_control::Client`, the
//! same blocking, timeout-bounded client `voidport-ctl` drives — so the TUI
//! cannot develop its own idea of the protocol. What this layer adds is the
//! separation the interface reasons in: a **rejection** (the server answered,
//! and refused) is a normal outcome the operator must read, while a
//! **transport failure** (no answer, or an unreadable one) means the
//! connection is gone and the whole model has to be re-read once it comes
//! back.
//!
//! [`worker`] runs a [`Session`] on its own thread, so the UI loop never
//! blocks on a socket and quitting stays instant even mid-retry.

pub mod worker;

use std::path::Path;

use voidport_control::client::{Client, ClientError, Timeouts};
use voidport_control::{ControlError, Reply, Request, Response};

pub use worker::{Backoff, Command, Worker};

/// One connection to a control socket, in the terms the model reasons in.
#[derive(Debug)]
pub struct Session {
    client: Client,
}

impl Session {
    /// Connects, with the client's default timeouts.
    ///
    /// # Errors
    ///
    /// Propagates the connection failure. In attach mode this is what a
    /// mistyped socket path looks like, and it happens *before* the terminal
    /// is taken over.
    pub fn connect(socket: &Path) -> Result<Self, ClientError> {
        Self::connect_with(socket, Timeouts::default())
    }

    /// Connects with explicit timeouts.
    ///
    /// # Errors
    ///
    /// Propagates the connection failure.
    pub fn connect_with(socket: &Path, timeouts: Timeouts) -> Result<Self, ClientError> {
        Client::connect_with(socket, timeouts).map(|client| Self { client })
    }

    /// Issues one operation.
    ///
    /// The two nested results are the two different things that can go wrong,
    /// and they are deliberately not flattened: the inner one is the server's
    /// verdict, the outer one is the connection's health.
    ///
    /// # Errors
    ///
    /// The outer error is a transport failure or a timeout; the connection is
    /// unusable afterwards.
    pub fn call(&mut self, request: &Request) -> Result<Result<Reply, ControlError>, ClientError> {
        let answer = self.client.call(request)?;
        Ok(match answer.response {
            Response::Ok { result } => Ok(result),
            Response::Error { error } => Err(error),
        })
    }

    /// The socket this session talks to.
    #[must_use]
    pub fn socket(&self) -> &Path {
        self.client.socket()
    }
}
