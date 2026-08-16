//! Contained descent below a pinned graft.
//!
//! Every host path the server reaches is reached from a descriptor it already
//! holds, with `openat2` under [`CONTAINMENT`]
//! (`RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS`). Nothing here ever hands the
//! kernel a reassembled absolute path, so there is no window in which a
//! guest-created symlink could redirect the server out of a graft: the kernel
//! itself refuses the escape with `EXDEV`.
//!
//! Two further rules, both decided by the design after kernel probes:
//!
//! * **The final component is pinned with `O_NOFOLLOW`.** A symlink resolves to
//!   a symlink node; following it is the client kernel's job (it reads the
//!   target and re-walks), which is the correct FUSE model and keeps an
//!   absolute target inside the *guest's* namespace.
//! * **The handshake subpath walk follows no symlink at all**
//!   ([`pin_relative_no_symlinks`]): a symlink component of a mount subpath is
//!   a mount error, not a silent redirection.
//!
//! [`reopen`] is the one deliberate exemption from the magic-link discipline:
//! turning an `O_PATH` descriptor into a readable or writable one goes through
//! `/proc/self/fd`, which *is* a magic link. It is safe precisely because the
//! descriptor being reopened was obtained under containment — the reopen adds
//! no new name resolution, it re-derives a descriptor for an inode the server
//! already legitimately holds.

use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};

use rustix::fs::{Mode, OFlags, ResolveFlags, openat2};
use rustix::io::Errno;

use crate::rules::Name;

/// The containment flags every descent below a graft runs under.
///
/// `RESOLVE_BENEATH` refuses absolute paths, `..` escapes and symlinks that
/// leave the starting descriptor; `RESOLVE_NO_MAGICLINKS` refuses `/proc`-style
/// links, which are not filesystem contents and would otherwise be a way out.
pub const CONTAINMENT: ResolveFlags = ResolveFlags::BENEATH.union(ResolveFlags::NO_MAGICLINKS);

/// The flags a pinning open uses: a descriptor that names an inode without
/// granting access to its contents, and never follows the final component.
const PIN_FLAGS: OFlags = OFlags::PATH.union(OFlags::NOFOLLOW).union(OFlags::CLOEXEC);

/// Pins the entry `name` inside the directory `parent`.
///
/// The result is an `O_PATH` descriptor for the entry itself — a symlink comes
/// back as a symlink, never as its target.
///
/// # Errors
///
/// Returns the host errno: `ENOENT` for a missing entry, `EXDEV` for an escape
/// the containment flags refused, and anything else the filesystem reports.
pub fn pin_child(parent: BorrowedFd<'_>, name: &Name) -> Result<OwnedFd, Errno> {
    openat2(
        parent,
        name.as_bytes(),
        PIN_FLAGS,
        Mode::empty(),
        CONTAINMENT,
    )
}

/// Opens — and optionally creates — a single child of a directory descriptor.
///
/// This is the one call in the server that opens a host entry for real I/O by
/// *name*, so it belongs here with the rest of the descent: it is the same
/// contained `openat2` [`pin_child`] uses, with the caller's own flags instead
/// of the pinning ones. `O_NOFOLLOW` is added unconditionally — a create must
/// never land on whatever a guest-planted symlink names, not even inside the
/// graft — and the containment flags refuse everything that leaves it.
///
/// # Errors
///
/// Returns the host errno: `EEXIST` for an exclusive create over an existing
/// entry, `ELOOP` for a symlink at the final component, `EXDEV` for an escape
/// the containment flags refused, and anything else the filesystem reports.
pub fn create_child(
    parent: BorrowedFd<'_>,
    name: &Name,
    flags: OFlags,
    mode: Mode,
) -> Result<OwnedFd, Errno> {
    openat2(
        parent,
        name.as_bytes(),
        flags | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        mode,
        CONTAINMENT,
    )
}

/// Pins the entry `relative` names below the graft descriptor `graft`.
///
/// An empty `relative` names the graft root itself, which is [`dup`]ed, not
/// re-resolved: the pinned descriptor already *is* that entry, and
/// re-opening it through `.` would fail for a graft that is not a directory.
///
/// # Errors
///
/// As [`pin_child`].
pub fn pin_relative(graft: BorrowedFd<'_>, relative: &[Name]) -> Result<OwnedFd, Errno> {
    pin_relative_with(graft, relative, CONTAINMENT)
}

/// Pins `relative` below `graft` without following a single symlink.
///
/// This is the handshake subpath walk: `RESOLVE_NO_SYMLINKS` makes a symlink
/// anywhere in the mount subpath — including as its final component — a hard
/// error, which is exactly the "a symlink component is a mount error" rule.
///
/// # Errors
///
/// As [`pin_child`], plus `ELOOP` for a symlink component.
pub fn pin_relative_no_symlinks(
    graft: BorrowedFd<'_>,
    relative: &[Name],
) -> Result<OwnedFd, Errno> {
    pin_relative_with(
        graft,
        relative,
        CONTAINMENT.union(ResolveFlags::NO_SYMLINKS),
    )
}

/// The shared body of the two relative-pinning walks.
fn pin_relative_with(
    graft: BorrowedFd<'_>,
    relative: &[Name],
    resolve: ResolveFlags,
) -> Result<OwnedFd, Errno> {
    if relative.is_empty() {
        return dup(graft);
    }
    openat2(graft, join(relative), PIN_FLAGS, Mode::empty(), resolve)
}

/// Joins path components with separators.
///
/// A [`Name`] can be neither empty nor contain a separator, `.` or `..`, so the
/// join is unambiguous and stays canonical by construction.
fn join(components: &[Name]) -> Vec<u8> {
    let mut path = Vec::new();
    for (index, component) in components.iter().enumerate() {
        if index > 0 {
            path.push(b'/');
        }
        path.extend_from_slice(component.as_bytes());
    }
    path
}

/// Duplicates a descriptor, sharing its open file description.
///
/// # Errors
///
/// Returns the host errno, which in practice means the process descriptor
/// limit.
pub fn dup(fd: BorrowedFd<'_>) -> Result<OwnedFd, Errno> {
    rustix::io::dup(fd)
}

/// Reopens a pinned `O_PATH` descriptor for actual I/O.
///
/// This is the standard `/proc/self/fd` reopen idiom, and it is the deliberate
/// exemption from the magic-link discipline documented at the top of this
/// module. Probe-verified by the design: the magic link preserves the *pinned*
/// inode across a rename-over and after an unlink, and reopening a pinned
/// symlink fails `ELOOP` instead of following it out.
///
/// # Errors
///
/// Returns the host errno — `EACCES` when the mode is not permitted, `ELOOP`
/// for a symlink, `EISDIR` for a directory opened for writing.
pub fn reopen(pinned: BorrowedFd<'_>, flags: OFlags) -> Result<OwnedFd, Errno> {
    rustix::fs::open(proc_path(pinned), flags | OFlags::CLOEXEC, Mode::empty())
}

/// The `/proc/self/fd` path naming an open descriptor.
///
/// Used by [`reopen`] and by the operations whose syscall has no `f*` form for
/// an `O_PATH` descriptor (the extended-attribute calls).
#[must_use]
pub fn proc_path(fd: BorrowedFd<'_>) -> String {
    format!("/proc/self/fd/{}", fd.as_fd().as_raw_fd())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::path::Path;

    use rustix::fs::{CWD, openat};

    use crate::testing::Scratch;

    /// Pins a path the way a graft target is pinned.
    fn pin(path: &Path) -> OwnedFd {
        openat(CWD, path, PIN_FLAGS, Mode::empty()).expect("the entry pins")
    }

    fn scratch() -> Scratch {
        Scratch::new("open")
    }

    fn name(raw: &str) -> Name {
        Name::new(raw).expect("valid name")
    }

    #[test]
    fn a_child_pins_and_a_missing_one_does_not() {
        let scratch = scratch();
        scratch.file("file", b"contents");
        let graft = pin(scratch.path());

        let pinned = pin_child(graft.as_fd(), &name("file")).expect("the child pins");
        let reopened = reopen(pinned.as_fd(), OFlags::RDONLY).expect("the pin reopens");
        let mut buffer = [0u8; 8];
        let read = rustix::io::read(&reopened, &mut buffer[..]).expect("readable");
        assert_eq!(&buffer[..read], b"contents");

        assert_eq!(
            pin_child(graft.as_fd(), &name("absent")).expect_err("no such entry"),
            Errno::NOENT
        );
    }

    #[test]
    fn containment_refuses_every_escape() {
        let scratch = scratch();
        let inside = scratch.join("inside");
        crate::testing::create_directory(&inside);
        symlink("/etc", inside.join("absolute")).expect("writable");
        symlink("../..", inside.join("dotdot")).expect("writable");
        symlink("/etc/hostname", scratch.path().join("escape")).expect("writable");
        let graft = pin(&inside);

        // The symlinks themselves pin — they are entries like any other.
        for target in ["absolute", "dotdot"] {
            let pinned = pin_child(graft.as_fd(), &name(target)).expect("the symlink pins");
            // Reopening a pinned symlink fails instead of following it out.
            assert!(reopen(pinned.as_fd(), OFlags::RDONLY).is_err());
        }
        // Following one as an intermediate component is refused by the kernel.
        assert_eq!(
            pin_relative(graft.as_fd(), &[name("absolute"), name("hostname")])
                .expect_err("an absolute symlink cannot be followed out"),
            Errno::XDEV
        );
        assert_eq!(
            pin_relative(graft.as_fd(), &[name("dotdot"), name("escape")])
                .expect_err("a dot-dot symlink cannot be followed out"),
            Errno::XDEV
        );
    }

    #[test]
    fn the_graft_root_pins_without_re_resolution() {
        let scratch = scratch();
        // A graft may be a single file, which has no `.` to re-resolve through.
        let graft = pin(&scratch.file("solo", b"x"));
        let pinned = pin_relative(graft.as_fd(), &[]).expect("the graft root pins");
        assert!(reopen(pinned.as_fd(), OFlags::RDONLY).is_ok());
    }

    #[test]
    fn the_handshake_walk_refuses_symlink_components() {
        let scratch = scratch();
        scratch.file("real/file", b"x");
        symlink("real", scratch.join("link")).expect("writable");
        let graft = pin(scratch.path());

        // The ordinary walk follows an internal symlink; the handshake walk
        // does not.
        assert!(pin_relative(graft.as_fd(), &[name("link"), name("file")]).is_ok());
        assert_eq!(
            pin_relative_no_symlinks(graft.as_fd(), &[name("link"), name("file")])
                .expect_err("a symlink component is a mount error"),
            Errno::LOOP
        );
        assert!(pin_relative_no_symlinks(graft.as_fd(), &[name("real"), name("file")]).is_ok());
    }

    #[test]
    fn components_join_canonically() {
        assert_eq!(join(&[name("a")]), b"a");
        assert_eq!(join(&[name("a"), name("b"), name("c")]), b"a/b/c");
    }
}
