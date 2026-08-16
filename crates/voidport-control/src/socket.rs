//! Where the control socket lives, and how an operator surface with no
//! `--socket` finds one.
//!
//! Two paths exist in practice and the difference is who may bind them: the
//! compiled default under `/run/voidport` belongs to a system service, and a
//! non-root operator running `voidportd share` gets a socket beside the per-user
//! state file instead. An operator should not have to know which of the two
//! their server chose, so a surface that was given no socket **tries both, in
//! order, and takes the first that answers** (decided 2026-08-14).
//!
//! The lookup lives here, in the crate both ends already share, because two
//! surfaces need exactly it — `voidport-ctl <command>` and `voidportd --tui` in
//! attach mode — and two copies of a search order would drift into two
//! different answers on the same machine.

use std::path::PathBuf;

/// Where the control socket lives when nothing says otherwise.
///
/// It is compiled into both ends on purpose: the server falls back to it when
/// neither the state file nor the command line names a socket, and the operator
/// surfaces try it when `--socket` is absent. One constant in the crate they
/// already share is what keeps "start a server, run `voidport-ctl`" working with
/// no configuration at all — two independently spelled defaults would drift and
/// the drift would only show up as "connection refused" on somebody's machine.
pub const DEFAULT_CONTROL_SOCKET: &str = "/run/voidport/control.sock";

/// The directory voidport keeps per-user state in, under the XDG convention.
///
/// `$XDG_STATE_HOME/voidport`, or `$HOME/.local/state/voidport` when the variable
/// is unset. `None` when neither variable says anything, which is a process
/// that has to be told a path explicitly.
///
/// This is the one place the rule is written: `voidportd share` seeds its state
/// file here, and the socket below sits beside that state file.
#[must_use]
pub fn user_state_directory() -> Option<PathBuf> {
    let base = match environment_path("XDG_STATE_HOME") {
        Some(base) => base,
        None => environment_path("HOME")?.join(".local").join("state"),
    };
    Some(base.join("voidport"))
}

/// The per-user control socket: `control.sock` in [`user_state_directory`].
///
/// This is exactly what a seeded launch writes into a document that names no
/// socket — the seed puts `control.sock` beside the state file, and the state
/// file a flagless `share` picks is in that same directory — so a local
/// instance started with `voidportd share <DIR>` is found here with no flags.
#[must_use]
pub fn user_control_socket() -> Option<PathBuf> {
    Some(user_state_directory()?.join(CONTROL_SOCKET_NAME))
}

/// Every control socket an operator surface tries when nothing names one, in
/// the order it tries them: the per-user one first, then the system one.
///
/// The per-user path comes first because it is the one an unprivileged operator
/// can actually have bound: a machine running both a system service and a
/// personal `share` has two servers, and the one the operator started is the
/// one they meant.
#[must_use]
pub fn default_control_sockets() -> Vec<PathBuf> {
    user_control_socket()
        .into_iter()
        .chain(std::iter::once(PathBuf::from(DEFAULT_CONTROL_SOCKET)))
        .collect()
}

/// The control socket of a running server, for a surface that was given none.
///
/// Membership is decided by **connecting**, not by the path existing: a socket
/// file left behind by a server that died is a path with nothing behind it, and
/// stopping at it would hide the running server on the next path.
///
/// # Errors
///
/// [`NoControlSocket`] when nothing answered, naming every path tried so the
/// operator can see which two were looked at.
#[cfg(feature = "client")]
pub fn find_control_socket() -> Result<PathBuf, NoControlSocket> {
    let tried = default_control_sockets();
    match first_connectable(&tried) {
        Some(socket) => Ok(socket),
        None => Err(NoControlSocket { tried }),
    }
}

/// The first of `candidates` a server answers on.
///
/// The connection is dropped again at once: this asks a question about the
/// socket, and the caller opens its own connection to ask questions about the
/// server. The connect bound is the client's ordinary one, so a wedged socket
/// early in the list cannot hold the search up indefinitely.
#[cfg(feature = "client")]
fn first_connectable(candidates: &[PathBuf]) -> Option<PathBuf> {
    candidates
        .iter()
        .find(|candidate| {
            crate::client::dial(candidate, crate::client::DEFAULT_CONNECT_TIMEOUT).is_ok()
        })
        .cloned()
}

/// Nothing answered on any of the default control sockets.
#[cfg(feature = "client")]
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("no voidport server answered on {}", listed(.tried))]
pub struct NoControlSocket {
    /// The paths that were tried, in order.
    pub tried: Vec<PathBuf>,
}

/// The tried paths as one readable list.
#[cfg(feature = "client")]
fn listed(tried: &[PathBuf]) -> String {
    tried
        .iter()
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>()
        .join(" or ")
}

/// The file name a control socket has when it is placed beside a state file.
///
/// The server spells the same name when a seeded launch writes one; it is
/// restated here instead of imported because the dependency runs the other way
/// — the server depends on this crate.
const CONTROL_SOCKET_NAME: &str = "control.sock";

/// A path from the environment, treating an empty value as unset.
fn environment_path(variable: &str) -> Option<PathBuf> {
    std::env::var_os(variable)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_system_socket_is_tried_last_and_the_per_user_one_first() {
        let candidates = default_control_sockets();
        assert_eq!(
            candidates.last(),
            Some(&PathBuf::from(DEFAULT_CONTROL_SOCKET)),
            "the system socket is the fallback, so it is tried last"
        );
        // The per-user candidate is present exactly when the environment says
        // where the user's state lives — a process with neither variable set
        // has only the system path to try.
        assert_eq!(
            candidates.len(),
            1 + usize::from(user_state_directory().is_some())
        );
        if let Some(user) = candidates.first().filter(|_| candidates.len() == 2) {
            assert!(user.is_absolute(), "{}", user.display());
            assert!(
                user.ends_with("voidport/control.sock"),
                "{}",
                user.display()
            );
        }
    }

    /// The property the decision is about: a dead candidate is not an answer.
    #[cfg(feature = "client")]
    #[test]
    fn the_first_socket_that_connects_wins_and_a_dead_one_is_skipped() {
        use std::os::unix::net::UnixListener;

        let directory = std::path::PathBuf::from(format!(
            "/tmp/voidport-control-lookup-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).expect("a scratch directory");

        let missing = directory.join("missing.sock");
        let stale = directory.join("stale.sock");
        let live = directory.join("live.sock");
        // A socket file with nothing behind it: bound, then closed.
        drop(UnixListener::bind(&stale).expect("bindable"));
        let listener = UnixListener::bind(&live).expect("bindable");

        assert_eq!(first_connectable(&[]), None);
        assert_eq!(
            first_connectable(&[missing.clone(), live.clone()]),
            Some(live.clone()),
            "a path with nothing there falls through to the next candidate"
        );
        assert_eq!(
            first_connectable(&[stale, live.clone()]),
            Some(live.clone()),
            "a socket file a dead server left behind is not a server"
        );
        assert_eq!(
            first_connectable(&[live.clone(), missing]),
            Some(live),
            "the first that connects wins"
        );

        drop(listener);
        let _ = std::fs::remove_dir_all(&directory);
    }
}
