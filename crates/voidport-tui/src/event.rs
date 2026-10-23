use std::path::PathBuf;

use crossterm::event::KeyEvent;
use voidport_control::{ControlError, NamespaceName, Reply, Request};

use crate::tail::LogRead;

/// A stale answer, from a view that has moved on, is discarded instead of
/// being reported as the outcome of something else.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Correlation(pub u64);

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Fetch {
    ServerInfo,
    Namespaces,
    Namespace(NamespaceName),
    Sessions,
}

impl Fetch {
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Failure {
    Rejected(ControlError),
    Transport(String),
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    Key(KeyEvent),
    Resize {
        width: u16,
        height: u16,
    },
    Tick,
    Fetched {
        fetch: Fetch,
        result: Result<Reply, Failure>,
    },
    LogRead(LogRead),
    Answered {
        correlation: Correlation,
        result: Result<Reply, Failure>,
    },
    Connected,
    Disconnected {
        reason: String,
        attempt: u32,
    },
    ServerStopped {
        reason: Option<String>,
    },
    Stop,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Effect {
    Fetch(Fetch),
    Mutate {
        correlation: Correlation,
        request: Request,
    },
    /// The path comes from the answer of the server, so a different file, or a
    /// different server after a reconnect, is followed.
    ReadLog {
        path: PathBuf,
    },
    Suspend,
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
