pub mod worker;

use std::path::Path;

use voidport_control::client::{Client, ClientError, Timeouts};
use voidport_control::{ControlError, Reply, Request, Response};

pub use worker::{Backoff, Command, Worker};

#[derive(Debug)]
pub struct Session {
    client: Client,
}

impl Session {
    pub fn connect(socket: &Path) -> Result<Self, ClientError> {
        Self::connect_with(socket, Timeouts::default())
    }

    pub fn connect_with(socket: &Path, timeouts: Timeouts) -> Result<Self, ClientError> {
        Client::connect_with(socket, timeouts).map(|client| Self { client })
    }

    /// The inner result is the verdict of the server, the outer one is the health
    /// of the connection.
    pub fn call(&mut self, request: &Request) -> Result<Result<Reply, ControlError>, ClientError> {
        let answer = self.client.call(request)?;
        Ok(match answer.response {
            Response::Ok { result } => Ok(result),
            Response::Error { error } => Err(error),
        })
    }

    #[must_use]
    pub fn socket(&self) -> &Path {
        self.client.socket()
    }
}
