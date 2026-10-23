//! Where the control socket lives, and how an operator surface with no
//! `--socket` finds one.

use std::path::PathBuf;

/// Compiled into both ends: the server falls back to it when nothing names a
/// socket, and the operator surfaces try it when `--socket` is absent.
pub const DEFAULT_CONTROL_SOCKET: &str = "/run/voidport/control.sock";

/// `$XDG_STATE_HOME/voidport`, or `$HOME/.local/state/voidport` when the variable
/// is unset. `None` when neither variable is set.
#[must_use]
pub fn user_state_directory() -> Option<PathBuf> {
    let base = match environment_path("XDG_STATE_HOME") {
        Some(base) => base,
        None => environment_path("HOME")?.join(".local").join("state"),
    };
    Some(base.join("voidport"))
}

/// The per-user control socket: `control.sock` in [`user_state_directory`].
#[must_use]
pub fn user_control_socket() -> Option<PathBuf> {
    Some(user_state_directory()?.join(CONTROL_SOCKET_NAME))
}

/// Every control socket an operator surface tries when nothing names one, in
/// the order it tries them: the per-user one first, then the system one.
#[must_use]
pub fn default_control_sockets() -> Vec<PathBuf> {
    user_control_socket()
        .into_iter()
        .chain(std::iter::once(PathBuf::from(DEFAULT_CONTROL_SOCKET)))
        .collect()
}

/// The control socket of a running server.
///
/// A candidate counts when a connect succeeds, not when the path exists: a
/// socket file left behind by a server that died would hide the running
/// server on the next path.
///
/// # Errors
///
/// [`NoControlSocket`], naming every path tried, when nothing answered.
#[cfg(feature = "client")]
pub fn find_control_socket() -> Result<PathBuf, NoControlSocket> {
    let tried = default_control_sockets();
    match first_connectable(&tried) {
        Some(socket) => Ok(socket),
        None => Err(NoControlSocket { tried }),
    }
}

/// The first of `candidates` a server answers on. The connect bound is the
/// ordinary one of the client, so a wedged socket cannot hold the search up.
#[cfg(feature = "client")]
fn first_connectable(candidates: &[PathBuf]) -> Option<PathBuf> {
    candidates
        .iter()
        .find(|candidate| {
            crate::client::dial(candidate, Some(crate::client::DEFAULT_CONNECT_TIMEOUT)).is_ok()
        })
        .cloned()
}

#[cfg(feature = "client")]
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("no voidport server answered on {}", listed(.tried))]
pub struct NoControlSocket {
    pub tried: Vec<PathBuf>,
}

#[cfg(feature = "client")]
fn listed(tried: &[PathBuf]) -> String {
    tried
        .iter()
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>()
        .join(" or ")
}

/// Restated from the server, which depends on this crate.
const CONTROL_SOCKET_NAME: &str = "control.sock";

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
