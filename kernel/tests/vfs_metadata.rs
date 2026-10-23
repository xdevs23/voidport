// SPDX-License-Identifier: GPL-2.0

use super::writable::{Change, FIRST_FILE, Held, Peer, Received, mount, path, pattern, unmount};
use crate::supervision::{Supervision, fork_child};
use crate::{Result, load_module, unload_module};
use std::ffi::CString;
use std::fs::{OpenOptions, Permissions};
use std::os::unix::fs::{FileExt, PermissionsExt};
use voidport_proto::opcode::Opcode;
use voidport_proto::ops::node::setattr_valid;

const FILE: u64 = FIRST_FILE;
const FIFO: u64 = FIRST_FILE + 1;
const BEFORE: u64 = 12_000;
const AFTER: u64 = 5000;

fn changes(received: &[Received]) -> Vec<(u64, Change)> {
    received
        .iter()
        .filter_map(|request| match *request {
            Received::Setattr { node, change } => Some((node, change)),
            _ => None,
        })
        .collect()
}

fn mode(name: &str) -> Result<u32> {
    Ok(std::fs::symlink_metadata(path(name))?.permissions().mode() & 0o7777)
}

pub(crate) fn setattr() -> Result {
    load_module()?;
    let peer = Peer::new(vec![
        Held::new(
            "file",
            libc::S_IFREG | libc::S_ISUID | 0o644,
            pattern(0, 0..BEFORE),
        ),
        Held::new("fifo", libc::S_IFIFO | 0o644, vec![]),
    ]);
    let session = mount(&peer, "no_privileged_bits")?;

    assert_eq!(mode("file")?, 0o644);
    std::fs::set_permissions(path("file"), Permissions::from_mode(0o755))?;
    assert_eq!(mode("file")?, 0o755);
    let chmod = changes(&peer.take());
    assert_eq!(chmod.len(), 1);
    let (node, change) = chmod[0];
    assert_eq!(
        (node, change.valid, change.mode),
        (FILE, setattr_valid::MODE, libc::S_ISUID | 0o755)
    );

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path("file"))?;
    let mut whole = vec![0; BEFORE as usize];
    file.read_exact_at(&mut whole, 0)?;
    assert!(whole == pattern(0, 0..BEFORE), "the file reads other bytes");
    file.set_len(AFTER)?;
    assert_eq!(file.metadata()?.len(), AFTER);
    let truncation = changes(&peer.take());
    assert_eq!(truncation.len(), 1);
    let (node, change) = truncation[0];
    assert_eq!(
        (node, change.valid, change.size),
        (FILE, setattr_valid::SIZE | setattr_valid::HANDLE, AFTER)
    );
    let mut page = vec![0; 4096];
    assert_eq!(file.read_at(&mut page, AFTER)?, 0);
    let start = AFTER - AFTER % 4096;
    let read = file.read_at(&mut page, start)?;
    assert!(
        page[..read] == pattern(0, start..AFTER),
        "the cut page reads other bytes"
    );
    drop(file);

    std::fs::set_permissions(path("fifo"), Permissions::from_mode(0o600))?;
    let fifo = CString::new(path("fifo"))?;
    let times = [
        libc::timespec {
            tv_sec: 1_000_000,
            tv_nsec: 0,
        },
        libc::timespec {
            tv_sec: 2_000_000,
            tv_nsec: 0,
        },
    ];
    assert_eq!(
        unsafe { libc::utimensat(libc::AT_FDCWD, fifo.as_ptr(), times.as_ptr(), 0) },
        0,
        "{}",
        std::io::Error::last_os_error()
    );
    let fifo_changes = changes(&peer.take());
    assert_eq!(fifo_changes.len(), 2, "{fifo_changes:?}");
    let (node, change) = fifo_changes[0];
    assert_eq!(
        (node, change.valid, change.mode),
        (FIFO, setattr_valid::MODE, 0o600)
    );
    let (node, change) = fifo_changes[1];
    let times_set = setattr_valid::ATIME | setattr_valid::MTIME;
    assert_eq!(node, FIFO);
    assert_eq!(change.valid & times_set, times_set);
    assert_eq!((change.atime, change.mtime), (1_000_000, 2_000_000));
    assert_eq!(mode("fifo")?, 0o600);

    unmount(session)?;
    println!(
        "setattr acceptance: a masked chmod keeps the setuid bit of the peer, ftruncate sends the size through its handle, and a FIFO's chmod and utimensat reach the peer"
    );
    unload_module()
}

fn create(path: &CString) -> libc::c_int {
    let file = unsafe { libc::open(path.as_ptr(), libc::O_CREAT | libc::O_WRONLY, 0o600) };
    if file < 0 { 1 } else { 0 }
}

pub(crate) fn orphaned_create() -> Result {
    load_module()?;
    let peer = Peer::new(vec![]);
    let session = mount(&peer, "")?;

    let directory = CString::new(super::writable::MOUNT)?;
    let unnamed = unsafe { libc::open(directory.as_ptr(), libc::O_TMPFILE | libc::O_RDWR, 0o600) };
    assert_eq!(unnamed, -1);
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::EOPNOTSUPP)
    );
    let device = CString::new(path("device"))?;
    let made = unsafe { libc::mknod(device.as_ptr(), libc::S_IFCHR | 0o600, libc::makedev(1, 3)) };
    assert_eq!(made, -1);
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::EPERM)
    );
    assert_eq!(peer.take(), [], "a refused entry reached the peer");

    peer.withhold(&[Opcode::Create]);
    let created = CString::new(path("created"))?;
    let creator = fork_child(|| create(&created));
    peer.wait_for(&Received::Create {
        name: b"created".to_vec(),
    })?;
    Supervision::new().kill_and_reap(creator, "the create")?;
    peer.send_withheld();
    let node = FIRST_FILE;
    let forget = Received::Forget { node, count: 1 };
    let release = Received::Release { node };
    peer.wait(|fresh| fresh.contains(&forget) && fresh.contains(&release))?;

    unmount(session)?;
    println!(
        "namespace acceptance: no request for an unnamed file or a device node, and a killed creator's node and handle given back"
    );
    unload_module()
}
