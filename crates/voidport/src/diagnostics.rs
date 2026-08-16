//! Where this process's diagnostics go, and the one line kept out of them.
//!
//! **stderr**, not the default stdout. `voidport subscribe` writes one JSON
//! object per line on stdout and a consumer parses every one of them; a log
//! line landing in that stream would be a parse failure in someone's shell
//! pipeline. Diagnostics belong on stderr for every subcommand, and the one
//! that makes it load-bearing is enough reason to state it once here.
//!
//! ## fuser's second unmount
//!
//! A mount's kernel unmount is this client's own, and it is a plain one: a busy
//! mountpoint surfaces `EBUSY` and v1 has no lazy or forced mode
//! ([`voidport::mount`]). fuser 0.18 keeps a mount handle of its own inside the
//! session and unmounts from it once more when that handle drops as the session
//! ends. That second unmount is not this client's to remove: the handle is
//! private to the session and the only way to release it is to unmount
//! *through* it, which takes fuser's own path — and that path answers a kernel
//! `EPERM` by detaching lazily and reporting success, which is the one thing the
//! contract forbids.
//!
//! By the time it runs, the mountpoint is gone — whether this process unmounted
//! it or another `voidport umount` did — so fuser's `umount(2)` lands on a path
//! that is no longer a mountpoint and fails `EINVAL`. fuser's own guard against
//! that (`is_mounted`, which polls the FUSE device for `POLLERR`) reads the
//! answer the wrong way round in 0.18 and lets the call through, so the warning
//! is emitted on every teardown: a line that reads like a failed unmount while
//! describing one that succeeded.
//!
//! [`UnmountRetry`] keeps that line out, and only where it cannot be hiding
//! anything: an unmount that really failed leaves the mountpoint mounted, and
//! while the mountpoint is still there the warning goes through untouched.

use std::fs;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use tracing::subscriber::Interest;
use tracing::{Level, Metadata, Subscriber};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::{Context, Layer, SubscriberExt as _};
use tracing_subscriber::util::SubscriberInitExt as _;

/// Installs this process's diagnostics.
///
/// `mountpoint` is the one this invocation mounts, where it mounts one. It is
/// the only thing [`UnmountRetry`] consults, and an invocation that hands over
/// none is one where nothing is ever held back.
pub fn install(mountpoint: Option<&Path>) {
    tracing_subscriber::fmt()
        .with_env_filter(filter())
        .with_writer(std::io::stderr)
        .finish()
        .with(UnmountRetry::watching(mountpoint))
        .init();
}

/// What `RUST_LOG` asks for, or `info`.
///
/// An **empty** `RUST_LOG` is treated as an absent one, which
/// `EnvFilter::try_from_default_env` does not do: an empty value parses into a
/// filter with no directives, and that enables nothing at all — a mount whose
/// diagnostics vanish because something in the environment exported `RUST_LOG=`
/// is silent exactly when it is being debugged. A value that is set but
/// unparseable falls back the same way instead of refusing to mount over a log
/// filter.
fn filter() -> EnvFilter {
    let default = || EnvFilter::new("info");
    match std::env::var(EnvFilter::DEFAULT_ENV) {
        Ok(directives) if !directives.trim().is_empty() => {
            EnvFilter::try_new(directives).unwrap_or_else(|_| default())
        }
        _ => default(),
    }
}

/// fuser's unmount of an already-unmounted mountpoint, kept out of the
/// diagnostics — and only while there is provably nothing left to unmount.
#[derive(Debug)]
struct UnmountRetry {
    /// The mountpoint this invocation mounts, resolved once so that a relative
    /// path or a symlink cannot throw the probe below off. `None` for an
    /// invocation that mounts nothing, which is also one that runs no FUSE
    /// session and so has no unmount of fuser's to answer for.
    mountpoint: Option<PathBuf>,
}

impl UnmountRetry {
    /// Watches one mountpoint, or none.
    fn watching(mountpoint: Option<&Path>) -> Self {
        Self {
            mountpoint: mountpoint
                .map(|path| path.canonicalize().unwrap_or_else(|_| path.to_path_buf())),
        }
    }

    /// Whether an event of this target and level may be written.
    ///
    /// Everything but fuser's own unmount complaint passes without a syscall.
    /// That one is measured against the mountpoint every time it is written,
    /// because what makes it spurious is the state of the mountpoint at that
    /// moment: gone, and there was nothing left for fuser to unmount.
    fn allows(&self, target: &str, level: Level) -> bool {
        !is_unmount_retry(target, level) || self.mountpoint.as_deref().is_none_or(still_mounted)
    }
}

impl<S: Subscriber> Layer<S> for UnmountRetry {
    /// The retry's callsite is never cached, because what decides it is the
    /// state of the mountpoint at the moment the warning is written, not the
    /// callsite. Every other callsite is left entirely to the layers below.
    fn register_callsite(&self, metadata: &'static Metadata<'static>) -> Interest {
        if is_unmount_retry(metadata.target(), *metadata.level()) {
            Interest::sometimes()
        } else {
            Interest::always()
        }
    }

    fn enabled(&self, metadata: &Metadata<'_>, _context: Context<'_, S>) -> bool {
        self.allows(metadata.target(), *metadata.level())
    }
}

/// Whether an event is fuser reporting that an unmount of its own failed.
///
/// By callsite, not by text: fuser 0.18 complains about an unmount from exactly
/// two places — `fuser::mnt`, when a session's mount handle is dropped, and
/// `fuser::session`, when a session is unmounted through its own — and in both
/// modules that complaint is the only `WARN` there is. Every other level from
/// those two, every other fuser module, and everything the client says itself,
/// is untouched.
fn is_unmount_retry(target: &str, level: Level) -> bool {
    level == Level::WARN && matches!(target, "fuser::mnt" | "fuser::session")
}

/// Whether a mountpoint still has a filesystem on it.
///
/// A mount and the directory it covers are on different devices; once it is
/// unmounted the path is back on its parent's. A mount whose server is gone
/// answers `ENOTCONN` instead of a device and is still very much mounted — the
/// dead endpoint a killed client leaves is exactly that state — so anything the
/// probe cannot measure counts as mounted. This decides whether a warning is
/// allowed out, and a probe that cannot answer is no reason to silence one.
fn still_mounted(mountpoint: &Path) -> bool {
    let Some(parent) = mountpoint.parent() else {
        return true;
    };
    match (fs::metadata(mountpoint), fs::metadata(parent)) {
        (Ok(here), Ok(under)) => here.dev() != under.dev(),
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_fusers_own_unmount_complaint_is_ever_a_candidate() {
        assert!(is_unmount_retry("fuser::mnt", Level::WARN));
        assert!(is_unmount_retry("fuser::session", Level::WARN));
        // Everything else fuser and the client can say, including the errors
        // those same two modules report, is nobody's to hold back.
        assert!(!is_unmount_retry("fuser::mnt", Level::ERROR));
        assert!(!is_unmount_retry("fuser::session", Level::ERROR));
        assert!(!is_unmount_retry("fuser::mnt", Level::INFO));
        assert!(!is_unmount_retry("fuser::mnt::fuse_pure", Level::WARN));
        assert!(!is_unmount_retry("fuser::request", Level::WARN));
        assert!(!is_unmount_retry("voidport::mount", Level::WARN));
    }

    #[test]
    fn a_mountpoint_that_is_still_there_is_told_from_one_that_is_not() {
        // `/proc` is mounted on every machine this client runs on, and this
        // crate's own source directory is mounted on none.
        assert!(still_mounted(Path::new("/proc")));
        assert!(!still_mounted(Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src"
        ))));
    }

    /// The warning is held back only where the mountpoint is provably gone: a
    /// mountpoint that is still there is the state a real unmount failure
    /// leaves behind, and an invocation that mounts nothing has nothing to
    /// prove anything about.
    #[test]
    fn a_warning_is_only_held_back_over_a_mountpoint_that_is_gone() {
        let gone =
            UnmountRetry::watching(Some(Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/src"))));
        let live = UnmountRetry::watching(Some(Path::new("/proc")));
        let none = UnmountRetry::watching(None);

        assert!(!gone.allows("fuser::mnt", Level::WARN));
        assert!(live.allows("fuser::mnt", Level::WARN));
        assert!(none.allows("fuser::mnt", Level::WARN));
        // The one line it holds back is the only line it touches.
        assert!(gone.allows("fuser::mnt", Level::ERROR));
        assert!(gone.allows("voidport::mount", Level::WARN));
    }
}
