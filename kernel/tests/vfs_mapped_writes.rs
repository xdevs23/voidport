// SPDX-License-Identifier: GPL-2.0

use super::writable::{FIRST_FILE, Held, Peer, Received, mount, path, pattern, unmount};
use crate::{Result, load_module, unload_module};
use std::fs::OpenOptions;
use std::ops::Range;
use std::os::fd::{AsRawFd, IntoRawFd};
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
        // A failure to restore the period cannot fail a case that already
        // ended, and the guest powers off after its run.
        let _ = std::fs::write(WRITEBACK_PERIOD, &self.0);
    }
}

struct Mapping {
    address: *mut u8,
    len: usize,
}

impl Mapping {
    fn new(file: &std::fs::File, len: usize) -> Result<Self> {
        let address = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                file.as_raw_fd(),
                0,
            )
        };
        if address == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(Self {
            address: address.cast(),
            len,
        })
    }

    fn store(&self, seed: u8, range: Range<u64>) {
        let bytes = pattern(seed, range.clone());
        assert!(range.end as usize <= self.len);
        unsafe {
            std::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                self.address.add(range.start as usize),
                bytes.len(),
            )
        };
    }

    fn sync(&self) -> std::io::Result<()> {
        if unsafe { libc::msync(self.address.cast(), self.len, libc::MS_SYNC) } == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        unsafe { libc::munmap(self.address.cast(), self.len) };
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
