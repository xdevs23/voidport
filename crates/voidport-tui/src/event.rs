//! What reaches the reducer, and what the reducer asks for.
//!
//! The whole interface is one function of these two types: `(model, Event) ->
//! (model, [Effect])`. Everything that touches the world — the socket, the
//! terminal, the clock — sits on one side or the other of that boundary and
//! never inside it, which is what makes the behaviour rules unit-testable
//! without a server or a terminal.

use std::path::PathBuf;

use crossterm::event::KeyEvent;
use voidport_control::{ControlError, NamespaceName, Reply, Request};

use crate::tail::LogRead;

/// The id a mutation's answer is matched against.
///
/// Answers are correlated, not assumed in order: the reducer knows
/// which mutation an answer belongs to, so a stale answer — one whose issuing
/// view has moved on — is discarded instead of being reported as the outcome
/// of something else.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Correlation(pub u64);

/// One read view the interface keeps fresh.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Fetch {
    /// `server-info`.
    ServerInfo,
    /// `namespace-list`.
    Namespaces,
    /// `namespace-show` of one namespace.
    Namespace(NamespaceName),
    /// `session-list`.
    Sessions,
}

impl Fetch {
    /// The request that answers it.
    #[must_use]
    pub fn request(&self) -> Request {
        match self {
            Self::ServerInfo => Request::ServerInfo {},
            Self::Namespaces => Request::NamespaceList {},
            Self::Namespace(name) => Request::NamespaceShow { name: name.clone() },
            Self::Sessions => Request::SessionList {},
        }
    }
}

/// Why an exchange did not produce a usable answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Failure {
    /// The server answered, and refused.
    Rejected(ControlError),
    /// The conversation itself failed: no answer, or an unreadable one.
    Transport(String),
    /// The server answered something this view cannot use — a reply of the
    /// wrong shape for the request.
    Unexpected(String),
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rejected(error) => write!(f, "{error}"),
            Self::Transport(message) | Self::Unexpected(message) => f.write_str(message),
        }
    }
}

/// Everything that can happen to the interface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// A key was pressed.
    Key(KeyEvent),
    /// The terminal was resized.
    Resize {
        /// Columns.
        width: u16,
        /// Rows.
        height: u16,
    },
    /// The shared freshness tick (default one second).
    Tick,
    /// A read view was answered.
    Fetched {
        /// Which view.
        fetch: Fetch,
        /// What came back.
        result: Result<Reply, Failure>,
    },
    /// The server's log file was read, on the Logs screen's behalf.
    LogRead(LogRead),
    /// A mutation was answered.
    Answered {
        /// Which mutation.
        correlation: Correlation,
        /// What came back.
        result: Result<Reply, Failure>,
    },
    /// The client connected, or reconnected.
    Connected,
    /// The client lost the connection and is retrying.
    Disconnected {
        /// Why, in the client's own words.
        reason: String,
        /// Which retry is in flight, counting from one.
        attempt: u32,
    },
    /// The presented server stopped, cleanly or not (serve-and-present only).
    ServerStopped {
        /// The failure, if it died of one.
        reason: Option<String>,
    },
    /// Something outside asked the interface to stop — a SIGTERM, say.
    Stop,
}

/// What the reducer asks the outside world to do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Effect {
    /// Re-read one view.
    Fetch(Fetch),
    /// Issue one mutation, answered under this correlation id.
    Mutate {
        /// The id the answer will carry.
        correlation: Correlation,
        /// The operation.
        request: Request,
    },
    /// Read whatever the server's log file has gained since the last read.
    ///
    /// The path is carried, not remembered at the edge: it is the
    /// server's answer, and a server that names a different file — or a
    /// different server after a reconnect — must be followed to it, not
    /// into the old one.
    ReadLog {
        /// The log file the server named.
        path: PathBuf,
    },
    /// Restore the terminal, stop, and resume with a full redraw.
    Suspend,
    /// Leave: disconnect (attach) or shut the server down (serve-and-present).
    Quit,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_view_names_the_request_that_answers_it() {
        let name = NamespaceName::new("p").expect("valid namespace name");
        assert_eq!(Fetch::ServerInfo.request(), Request::ServerInfo {});
        assert_eq!(Fetch::Namespaces.request(), Request::NamespaceList {});
        assert_eq!(
            Fetch::Namespace(name.clone()).request(),
            Request::NamespaceShow { name }
        );
        assert_eq!(Fetch::Sessions.request(), Request::SessionList {});
    }

    #[test]
    fn a_failure_renders_as_what_it_is() {
        let rejected = Failure::Rejected(ControlError::new(
            voidport_control::ErrorCode::NotFound,
            "no namespace \"p\"",
        ));
        assert_eq!(rejected.to_string(), "not-found: no namespace \"p\"");
        assert_eq!(
            Failure::Transport("the socket died".to_owned()).to_string(),
            "the socket died"
        );
    }
}
