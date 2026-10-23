//! Every host path is reached from a descriptor the server already has, with
//! `openat2` under [`CONTAINMENT`]. No reassembled absolute path exists for a
//! symlink created by a guest to redirect, and the kernel refuses the escape
//! with `EXDEV`. The final component is opened with `O_NOFOLLOW`: a symlink
//! resolves to a symlink node, and the client kernel follows it, so an absolute
//! target resolves inside the namespace of the guest. The
//! handshake walk of the subpath follows no symlink at all
//! ([`pin_relative_no_symlinks`]), because a symlink component of a mount
//! subpath is a mount error.
//!
//! [`reopen`] is the one exemption from the magic-link discipline: it turns an
//! `O_PATH` descriptor into a readable or writable one through `/proc/self/fd`,
//! which is a magic link. It is safe because the descriptor was obtained under
//! containment, so the reopen resolves no new name.

use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};

use rustix::fs::{FileType, Mode, OFlags, ResolveFlags, openat2, readlinkat};
use rustix::io::Errno;

use super::attr::HostAttr;
use crate::rules::Name;

/// `RESOLVE_NO_MAGICLINKS` refuses `/proc`-style links, which are not filesystem
/// contents and would otherwise be a way out.
pub const CONTAINMENT: ResolveFlags = ResolveFlags::BENEATH.union(ResolveFlags::NO_MAGICLINKS);

const PIN_FLAGS: OFlags = OFlags::PATH.union(OFlags::NOFOLLOW).union(OFlags::CLOEXEC);

/// A symlink comes back as a symlink, never as its target.
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MadeEntry<'a> {
    Directory,
    Fifo,
    Socket,
    Symlink(&'a [u8]),
}

impl MadeEntry<'_> {
    /// `found` must show the file type made, owned by `made_by` (the uid that
    /// the host filesystem records on an entry made by this process), with the
    /// link count of a new entry and, for a symlink, the target made. A new
    /// directory has two links, or one on a filesystem that does not count
    /// subdirectories, such as btrfs.
    ///
    /// # Errors
    ///
    /// Returns the host errno of the read of the symlink target.
    pub fn matches(
        self,
        pinned: BorrowedFd<'_>,
        found: &HostAttr,
        made_by: u32,
    ) -> Result<bool, Errno> {
        let new_links = match self {
            Self::Directory => 1..=2,
            Self::Fifo | Self::Socket | Self::Symlink(_) => 1..=1,
        };
        let made_here = FileType::from_raw_mode(found.host_mode()) == self.file_type()
            && found.owner().uid == made_by
            && new_links.contains(&found.link_count());
        match self {
            Self::Symlink(target) if made_here => {
                Ok(readlinkat(pinned, "", Vec::new())?.as_bytes() == target)
            }
            _ => Ok(made_here),
        }
    }

    #[must_use]
    pub fn file_type(self) -> FileType {
        match self {
            Self::Directory => FileType::Directory,
            Self::Fifo => FileType::Fifo,
            Self::Socket => FileType::Socket,
            Self::Symlink(_) => FileType::Symlink,
        }
    }
}

/// The one call that opens a host entry for real I/O by name. `O_NOFOLLOW` is
/// added unconditionally, so a create never writes through a symlink planted
/// by a guest.
///
/// # Errors
///
/// Returns the host errno: `EEXIST` for an exclusive create over an existing
/// entry, `ELOOP` for a symlink at the final component, `EXDEV` for an escape
/// the containment flags refused, and anything else the filesystem reports.
fn create_child(
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

#[derive(Clone, Copy)]
pub enum IfExists {
    Refuse,
    Open,
}

pub struct Opened {
    pub pinned: OwnedFd,
    /// The read-write descriptor used to make the file, where this create made
    /// it.
    pub created: Option<OwnedFd>,
}

/// The exclusive attempt comes first, because only it tells a file made by this
/// call apart from one that was there before. The `O_PATH` descriptor of a
/// created file comes from the descriptor of the create, so a rename that puts
/// another file at the name afterwards does not change which file it refers to.
/// Where the file found is gone by the time it is opened, the name is free, and
/// the create starts over.
///
/// # Errors
///
/// The errno returned by the host, `EEXIST` included for
/// [`IfExists::Refuse`].
pub fn create_or_pin(
    parent: BorrowedFd<'_>,
    name: &Name,
    mode: Mode,
    if_exists: IfExists,
) -> Result<Opened, Errno> {
    create_or_open(parent, name, mode, if_exists, pin_existing)
}

/// `open_existing` is a parameter so that a test can remove the file between
/// the failed exclusive attempt and the open.
fn create_or_open(
    parent: BorrowedFd<'_>,
    name: &Name,
    mode: Mode,
    if_exists: IfExists,
    mut open_existing: impl FnMut(BorrowedFd<'_>, &Name) -> Result<Option<OwnedFd>, Errno>,
) -> Result<Opened, Errno> {
    let flags = OFlags::RDWR | OFlags::CREATE | OFlags::EXCL;
    loop {
        match (create_child(parent, name, flags, mode), if_exists) {
            (Ok(fd), _) => {
                return Ok(Opened {
                    pinned: pin_opened(fd.as_fd())?,
                    created: Some(fd),
                });
            }
            (Err(Errno::EXIST), IfExists::Open) => {
                if let Some(pinned) = open_existing(parent, name)? {
                    return Ok(Opened {
                        pinned,
                        created: None,
                    });
                }
            }
            (Err(error), _) => return Err(error),
        }
    }
}

fn pin_existing(parent: BorrowedFd<'_>, name: &Name) -> Result<Option<OwnedFd>, Errno> {
    match pin_child(parent, name) {
        Ok(pinned) => Ok(Some(pinned)),
        Err(Errno::NOENT) => Ok(None),
        Err(error) => Err(error),
    }
}

/// An empty `relative` names the graft root itself, which is [`dup`]ed:
/// re-opening it through `.` would fail for a graft that is not a directory.
///
/// # Errors
///
/// As [`pin_child`].
pub fn pin_relative(graft: BorrowedFd<'_>, relative: &[Name]) -> Result<OwnedFd, Errno> {
    pin_relative_with(graft, relative, CONTAINMENT)
}

/// `RESOLVE_NO_SYMLINKS` makes a symlink anywhere in the mount subpath, the
/// final component included, a hard error.
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

/// A [`Name`] contains no separator, `.` or `..`, so the join is unambiguous.
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

/// # Errors
///
/// Returns the host errno, which in practice means the process descriptor
/// limit.
pub fn dup(fd: BorrowedFd<'_>) -> Result<OwnedFd, Errno> {
    rustix::io::dup(fd)
}

/// The magic link refers to the same inode across a rename-over and after an
/// unlink, and reopening an `O_PATH` symlink fails with `ELOOP` instead of
/// following it out.
///
/// # Errors
///
/// Returns the host errno — `EACCES` when the mode is not permitted, `ELOOP`
/// for a symlink, `EISDIR` for a directory opened for writing.
pub fn reopen(pinned: BorrowedFd<'_>, flags: OFlags) -> Result<OwnedFd, Errno> {
    rustix::fs::open(proc_path(pinned), flags | OFlags::CLOEXEC, Mode::empty())
}

/// Looks up no name: the descriptor refers to the file behind `fd` even where a
/// rename has since put another file at the name used to open `fd`.
///
/// # Errors
///
/// As [`reopen`].
fn pin_opened(fd: BorrowedFd<'_>) -> Result<OwnedFd, Errno> {
    reopen(fd, OFlags::PATH)
}

/// The `/proc/self/fd` path naming an open descriptor. [`reopen`] uses it, and so
/// do the operations whose syscall has no `f*` form for an `O_PATH` descriptor,
/// such as the extended-attribute calls.
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
    use rustix::process::geteuid;

    use voidport_test_host::Scratch;

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
        voidport_test_host::create_directory(&inside);
        symlink("/etc", inside.join("absolute")).expect("writable");
        symlink("../..", inside.join("dotdot")).expect("writable");
        symlink("/etc/hostname", scratch.path().join("escape")).expect("writable");
        let graft = pin(&inside);

        for target in ["absolute", "dotdot"] {
            let pinned = pin_child(graft.as_fd(), &name(target)).expect("the symlink pins");
            assert!(reopen(pinned.as_fd(), OFlags::RDONLY).is_err());
        }
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

        assert!(pin_relative(graft.as_fd(), &[name("link"), name("file")]).is_ok());
        assert_eq!(
            pin_relative_no_symlinks(graft.as_fd(), &[name("link"), name("file")])
                .expect_err("a symlink component is a mount error"),
            Errno::LOOP
        );
        assert!(pin_relative_no_symlinks(graft.as_fd(), &[name("real"), name("file")]).is_ok());
    }

    #[test]
    fn pin_opened_ignores_a_rename_over_the_name() {
        let scratch = scratch();
        let path = scratch.file("file", b"opened");
        let opened = openat(CWD, &path, OFlags::RDONLY, Mode::empty()).expect("the file opens");
        std::fs::rename(scratch.file("other", b"other"), &path).expect("the rename succeeds");

        let pinned = pin_opened(opened.as_fd()).expect("the open file gets a descriptor");
        assert_eq!(contents(pinned.as_fd()), b"opened");
    }

    #[test]
    fn create_or_pin_tells_a_created_file_from_an_existing_one() {
        let scratch = scratch();
        let directory = pin(scratch.path());
        let mode = Mode::from_bits_truncate(0o600);

        let made = create_or_pin(directory.as_fd(), &name("new"), mode, IfExists::Refuse)
            .expect("a free name is created");
        assert!(made.created.is_some());

        scratch.file("old", b"old");
        let found = create_or_pin(directory.as_fd(), &name("old"), mode, IfExists::Open)
            .expect("an existing file is opened");
        assert!(found.created.is_none());
        assert_eq!(contents(found.pinned.as_fd()), b"old");

        assert_eq!(
            create_or_pin(directory.as_fd(), &name("old"), mode, IfExists::Refuse).err(),
            Some(Errno::EXIST)
        );
    }

    #[test]
    fn a_create_makes_a_file_when_the_existing_one_vanishes() {
        let scratch = scratch();
        let path = scratch.file("file", b"vanished");
        let directory = pin(scratch.path());
        let mut removals = 0;

        let opened = create_or_open(
            directory.as_fd(),
            &name("file"),
            Mode::from_bits_truncate(0o600),
            IfExists::Open,
            |parent, name| {
                if removals == 0 {
                    std::fs::remove_file(&path).expect("the file is removed");
                }
                removals += 1;
                pin_existing(parent, name)
            },
        )
        .expect("the create succeeds");

        assert_eq!(removals, 1, "the file vanished once");
        assert!(opened.created.is_some(), "the create made a file");
        assert!(contents(opened.pinned.as_fd()).is_empty());
    }

    fn fifo(directory: BorrowedFd<'_>, name: &str) {
        rustix::fs::mknodat(
            directory,
            name,
            FileType::Fifo,
            Mode::from_bits_truncate(0o600),
            0,
        )
        .expect("the FIFO is made");
    }

    fn matches(directory: BorrowedFd<'_>, entry: &str, made: MadeEntry<'_>) -> bool {
        matches_made_by(directory, entry, made, geteuid().as_raw())
    }

    fn matches_made_by(
        directory: BorrowedFd<'_>,
        entry: &str,
        made: MadeEntry<'_>,
        made_by: u32,
    ) -> bool {
        let pinned = pin_child(directory, &name(entry)).expect("the entry opens");
        let found = HostAttr::of(pinned.as_fd()).expect("the entry is readable");
        made.matches(pinned.as_fd(), &found, made_by)
            .expect("the target is readable")
    }

    #[test]
    fn a_made_entry_matches_what_was_made() {
        let scratch = scratch();
        let directory = pin(scratch.path());
        voidport_test_host::create_directory(&scratch.join("dir"));
        fifo(directory.as_fd(), "fifo");
        symlink("target", scratch.join("link")).expect("writable");

        assert!(matches(directory.as_fd(), "dir", MadeEntry::Directory));
        assert!(matches(directory.as_fd(), "fifo", MadeEntry::Fifo));
        assert!(matches(
            directory.as_fd(),
            "link",
            MadeEntry::Symlink(b"target")
        ));
    }

    #[test]
    fn an_entry_of_another_type_does_not_match() {
        let scratch = scratch();
        let directory = pin(scratch.path());
        voidport_test_host::create_directory(&scratch.join("dir"));
        fifo(directory.as_fd(), "fifo");

        assert!(!matches(directory.as_fd(), "dir", MadeEntry::Fifo));
        assert!(!matches(directory.as_fd(), "fifo", MadeEntry::Directory));
        assert!(!matches(directory.as_fd(), "fifo", MadeEntry::Socket));
    }

    #[test]
    fn an_entry_of_another_user_does_not_match() {
        let scratch = scratch();
        let directory = pin(scratch.path());
        fifo(directory.as_fd(), "fifo");
        let another_user = geteuid().as_raw().wrapping_add(1);

        assert!(!matches_made_by(
            directory.as_fd(),
            "fifo",
            MadeEntry::Fifo,
            another_user
        ));
    }

    #[test]
    fn an_entry_with_a_second_link_does_not_match() {
        let scratch = scratch();
        let directory = pin(scratch.path());
        fifo(directory.as_fd(), "fifo");
        std::fs::hard_link(scratch.join("fifo"), scratch.join("second")).expect("writable");

        assert!(!matches(directory.as_fd(), "fifo", MadeEntry::Fifo));
    }

    #[test]
    fn a_symlink_with_another_target_does_not_match() {
        let scratch = scratch();
        let directory = pin(scratch.path());
        symlink("elsewhere", scratch.join("link")).expect("writable");

        assert!(!matches(
            directory.as_fd(),
            "link",
            MadeEntry::Symlink(b"target")
        ));
    }

    fn contents(pinned: BorrowedFd<'_>) -> Vec<u8> {
        let reopened = reopen(pinned, OFlags::RDONLY).expect("the descriptor reopens");
        let mut buffer = [0u8; 8];
        let read = rustix::io::read(&reopened, &mut buffer[..]).expect("readable");
        buffer[..read].to_vec()
    }

    #[test]
    fn components_join_canonically() {
        assert_eq!(join(&[name("a")]), b"a");
        assert_eq!(join(&[name("a"), name("b"), name("c")]), b"a/b/c");
    }
}
