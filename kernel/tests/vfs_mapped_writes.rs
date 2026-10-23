// SPDX-License-Identifier: GPL-2.0

use super::writable::{
    FIRST_FILE, Held, Mapping, Peer, Received, mount, path, pattern, unmount,
};
use crate::{Result, load_module, unload_module};
use std::fs::OpenOptions;
use std::ops::Range;
use std::os::fd::IntoRawFd;
use std::os::unix::fs::FileExt;

const FILE: u64 = FIRST_FILE;

const WRITEBACK_PERIOD: &str = "/proc/sys/vm/dirty_writeback_centisecs";

struct NoPeriodicWriteback(String);

impl NoPeriodicWriteback {
    fn new() -> Result<Self> {
        let period = std::fs::read_to_string(WRITEBACK_PERIOD)?;
        std::fs::write(WRITEBACK_PERIOD, "0")?;
        Ok(Self(period))
    }
}

impl Drop for NoPeriodicWriteback {
    fn drop(&mut self) {
        let restored = std::fs::write(WRITEBACK_PERIOD, &self.0);
        // A panic while the case unwinds from a failed assertion would abort
        // the run before that assertion is reported.
        if !std::thread::panicking() {
            restored.expect("the writeback period is restored");
        }
    }
}

fn write(range: Range<u64>) -> Received {
    Received::Write {
        node: FILE,
        offset: range.start,
        len: (range.end - range.start) as u32,
    }
}

fn place(bytes: &mut [u8], seed: u8, range: Range<u64>) {
    bytes[range.start as usize..range.end as usize].copy_from_slice(&pattern(seed, range));
}

pub(crate) fn run() -> Result {
    load_module()?;
    let page = u64::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) })?;
    let size = 4 * page - 100;
    let peer = Peer::new(vec![Held::new(
        "file",
        libc::S_IFREG | 0o644,
        pattern(0, 0..size),
    )]);
    let session = mount(&peer, "")?;
    let periodic = NoPeriodicWriteback::new()?;
    let open = || OpenOptions::new().read(true).write(true).open(path("file"));

    let file = open()?;
    // The file is read into the page cache first, so the stores below fault
    // in pages that are already there, and reach the peer only as writes.
    let mut content = vec![0; usize::try_from(size)?];
    file.read_exact_at(&mut content, 0)?;
    let mapping = Mapping::new(&file, usize::try_from(size)?)?;
    peer.take();

    mapping.store(1, 0..2 * page);
    mapping.store(1, 3 * page..size);
    mapping.sync()?;
    assert_eq!(
        peer.take(),
        [
            write(0..2 * page),
            write(3 * page..size),
            Received::Fsync {
                node: FILE,
                datasync: true
            },
        ]
    );

    peer.answer_writes(&[super::writable::Answer::Failed(libc::EIO)]);
    mapping.store(2, 2 * page..3 * page);
    assert_eq!(mapping.sync().unwrap_err().raw_os_error(), Some(libc::EIO));
    file.sync_all()?;
    assert_eq!(
        peer.take(),
        [
            write(2 * page..3 * page),
            Received::Fsync {
                node: FILE,
                datasync: false
            },
        ]
    );

    // The close sends nothing, since the file has no record lock on the
    // server. A store after it goes to the peer when the mapping releases
    // the file, before the handle goes back.
    if unsafe { libc::close(file.into_raw_fd()) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    assert_eq!(peer.take(), []);
    mapping.store(3, 0..page);
    drop(mapping);
    let release = Received::Release { node: FILE };
    peer.wait_for(&release)?;
    assert_eq!(peer.take(), [write(0..page), release]);
    let mut expected = pattern(0, 0..size);
    place(&mut expected, 1, 0..2 * page);
    place(&mut expected, 1, 3 * page..size);
    place(&mut expected, 3, 0..page);
    assert!(peer.content(FILE) == expected, "the peer has other bytes");

    let file = open()?;
    let mapping = Mapping::new(&file, usize::try_from(size)?)?;
    mapping.store(4, page..2 * page);
    peer.take();
    let truncating = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path("file"))?;
    let received = peer.take();
    assert_eq!(received.len(), 2, "{received:?}");
    assert_eq!(received[0], write(page..2 * page));
    assert!(
        matches!(received[1], Received::Open { node: FILE, flags } if flags & libc::O_TRUNC as u32 != 0),
        "{received:?}"
    );
    assert!(peer.content(FILE).is_empty());
    let mut bytes = [0; 16];
    assert_eq!(file.read_at(&mut bytes, 0)?, 0);
    drop(truncating);
    drop(mapping);
    drop(file);

    drop(periodic);
    unmount(session)?;
    println!(
        "mapped write acceptance: one write request per run at msync, a failed writeback fails msync once, the release writes back before the handle goes, and a truncating open writes back first"
    );
    unload_module()
}
