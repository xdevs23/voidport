// SPDX-License-Identifier: GPL-2.0

use super::writable::{
    Answer, FIRST_FILE, Held, Mapping, Peer, Received, mount, path, pattern, remount, unmount,
};
use crate::{Result, load_module, unload_module};
use std::fs::{File, OpenOptions};
use std::io::{Seek, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileExt, OpenOptionsExt};
use std::sync::{Arc, mpsc};
use voidport_proto::opcode::Opcode;

const FILE: u64 = FIRST_FILE;
const WHOLE: u32 = 41_943_040;
const DIRECT: u32 = 1 << 20;

fn writes(received: &[Received]) -> Vec<(u64, u32)> {
    received
        .iter()
        .filter_map(|request| match *request {
            Received::Write { offset, len, .. } => Some((offset, len)),
            _ => None,
        })
        .collect()
}

fn reads(received: &[Received]) -> Vec<(u64, u32)> {
    received
        .iter()
        .filter_map(|request| match *request {
            Received::Read { offset, size, .. } => Some((offset, size)),
            _ => None,
        })
        .collect()
}

fn read_at(file: &File, offset: u64, len: usize) -> Result<Vec<u8>> {
    let mut bytes = vec![0; len];
    let read = file.read_at(&mut bytes, offset)?;
    bytes.truncate(read);
    Ok(bytes)
}

/// The bytes `0..size` of `file`, copied by `sendfile(2)`, which splices them.
fn sent(file: &File, size: u64) -> Result<Vec<u8>> {
    let copy_path = "/vfs-writable-copy";
    let copy = File::create(copy_path)?;
    let end = libc::off_t::try_from(size)?;
    let mut offset: libc::off_t = 0;
    while offset < end {
        let left = usize::try_from(end - offset)?;
        let sent = unsafe { libc::sendfile(copy.as_raw_fd(), file.as_raw_fd(), &mut offset, left) };
        assert!(sent > 0, "{}", std::io::Error::last_os_error());
    }
    drop(copy);
    let copied = std::fs::read(copy_path)?;
    std::fs::remove_file(copy_path)?;
    Ok(copied)
}

pub(crate) fn run() -> Result {
    load_module()?;
    let peer = Peer::new(vec![Held::new("file", libc::S_IFREG | 0o644, vec![])]);
    let session = mount(&peer, "")?;
    let file = Arc::new(
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(path("file"))?,
    );
    peer.take();

    peer.withhold(&[Opcode::Write]);
    let writing = file.clone();
    let writer = std::thread::spawn(move || writing.write_at(&pattern(1, 0..u64::from(WHOLE)), 0));
    peer.wait_for(&Received::Write {
        node: FILE,
        offset: 0,
        len: WHOLE,
    })?;
    assert_eq!(remount(true).unwrap_err().raw_os_error(), Some(libc::EBUSY));
    assert!(!writer.is_finished(), "write(2) returned before its reply");
    peer.send_withheld();
    let written = writer.join().map_err(|_| "the writer panicked")?;
    assert_eq!(written?, WHOLE as usize);
    assert_eq!(writes(&peer.take()), [(0, WHOLE)]);

    peer.answer_writes(&[Answer::Took(1000), Answer::Took(7192)]);
    assert_eq!(file.write_at(&pattern(2, 0..8192), 0)?, 8192);
    assert_eq!(writes(&peer.take()), [(0, 8192), (1000, 7192)]);

    peer.answer_writes(&[Answer::Took(3000), Answer::Failed(libc::ENOSPC)]);
    assert_eq!(file.write_at(&pattern(3, 8192..16_384), 8192)?, 3000);
    assert_eq!(writes(&peer.take()), [(8192, 8192), (11_192, 5192)]);
    let mut expected = pattern(1, 0..u64::from(WHOLE));
    expected[..8192].copy_from_slice(&pattern(2, 0..8192));
    expected[8192..11_192].copy_from_slice(&pattern(3, 8192..11_192));
    assert!(peer.content(FILE) == expected, "the peer has other bytes");
    assert!(
        read_at(&file, 0, 16_384)? == expected[..16_384],
        "the file reads other bytes than the peer took"
    );

    let mut appending = OpenOptions::new().append(true).open(path("file"))?;
    let appended = pattern(4, u64::from(WHOLE)..u64::from(WHOLE) + 5000);
    appending.write_all(&appended)?;
    let end = u64::from(WHOLE) + 5000;
    assert_eq!(appending.metadata()?.len(), end);
    assert_eq!(appending.stream_position()?, end);
    expected.extend(&appended);
    assert!(peer.content(FILE) == expected, "the append went elsewhere");
    let received = peer.take();
    assert_eq!(writes(&received), [(u64::from(WHOLE), 5000)]);
    drop(appending);
    drop(file);
    assert!(
        !peer
            .received()
            .iter()
            .any(|request| matches!(request, Received::Flush { .. }))
    );

    remount(true)?;
    remount(false)?;
    unmount(session)?;
    println!(
        "write acceptance: one request per write(2) answered after its reply, short and failed replies read back as taken, an append, and remounts ok"
    );
    unload_module()
}

pub(crate) fn direct() -> Result {
    load_module()?;
    let size = 2 * u64::from(DIRECT);
    let peer = Peer::new(vec![Held::new(
        "file",
        libc::S_IFREG | 0o644,
        pattern(0, 0..size),
    )]);
    let session = mount(&peer, "")?;
    let file = Arc::new(
        OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_DIRECT)
            .open(path("file"))?,
    );
    peer.take();

    peer.withhold(&[Opcode::Write]);
    let write = |seed: u8, offset: u64| {
        let file = file.clone();
        let data = pattern(seed, offset..offset + u64::from(DIRECT));
        std::thread::spawn(move || file.write_at(&data, offset))
    };
    let first = write(4, 0);
    peer.wait_for(&Received::Write {
        node: FILE,
        offset: 0,
        len: DIRECT,
    })?;
    let second = write(5, u64::from(DIRECT));
    peer.wait_for(&Received::Write {
        node: FILE,
        offset: u64::from(DIRECT),
        len: DIRECT,
    })?;
    peer.send_withheld();
    for writer in [first, second] {
        let written = writer.join().map_err(|_| "a direct writer panicked")?;
        assert_eq!(written?, DIRECT as usize);
    }
    let mut expected = pattern(4, 0..u64::from(DIRECT));
    expected.extend(pattern(5, u64::from(DIRECT)..size));
    assert!(peer.content(FILE) == expected, "the peer has other bytes");
    peer.take();

    // A read through the page cache would ask for pages, and would find them
    // cached the second time.
    for _ in 0..2 {
        assert!(
            read_at(&file, 0, DIRECT as usize)? == expected[..DIRECT as usize],
            "the direct read returned other bytes"
        );
    }
    assert_eq!(reads(&peer.take()), [(0, DIRECT); 2]);

    // The writes ended the lifetime of the attributes of the file, and their
    // refresh drops the cached pages, since the modification time changed. The
    // refresh happens here, so that the read after the splice finds the pages
    // that a splice through the page cache would leave.
    file.metadata()?;
    assert!(sent(&file, size)? == expected, "the splice copied other bytes");
    peer.take();
    let cached = File::open(path("file"))?;
    assert!(read_at(&cached, 0, usize::try_from(size)?)? == expected);
    assert!(
        !reads(&peer.take()).is_empty(),
        "the splice left the file in the page cache"
    );
    drop(cached);
    drop(file);

    unmount(session)?;
    println!(
        "direct I/O: a direct write is sent while another waits for its reply, each direct read is one request, and a splice reads past the page cache"
    );
    unload_module()
}

/// A mount with `direct_io` reads, splices and writes a file opened without
/// `O_DIRECT` as `direct` does, with the inode lock taken exclusively for a
/// write, and maps it through the page cache as a mount without the option
/// does.
pub(crate) fn direct_mount() -> Result {
    load_module()?;
    let page = u32::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) })?;
    let (page_end, page_len) = (u64::from(page), usize::try_from(page)?);
    let size = u64::from(DIRECT);
    let peer = Peer::new(vec![Held::new(
        "file",
        libc::S_IFREG | 0o644,
        pattern(0, 0..size),
    )]);
    let session = mount(&peer, "direct_io")?;
    let file = Arc::new(
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(path("file"))?,
    );
    peer.take();

    // A read or a splice through the page cache would find the pages cached
    // the second time.
    for _ in 0..2 {
        assert!(
            read_at(&file, 0, usize::try_from(DIRECT)?)? == pattern(0, 0..size),
            "the read returned other bytes"
        );
    }
    assert_eq!(reads(&peer.take()), [(0, DIRECT); 2]);
    for _ in 0..2 {
        assert!(
            sent(&file, size)? == pattern(0, 0..size),
            "the splice copied other bytes"
        );
        assert!(
            !reads(&peer.take()).is_empty(),
            "the splice read from the page cache"
        );
    }

    // A write through the page cache would leave the whole page cached.
    let written = pattern(6, 0..page_end);
    assert_eq!(file.write_at(&written, 0)?, page_len);
    assert_eq!(writes(&peer.take()), [(0, page)]);
    assert!(read_at(&file, 0, page_len)? == written);
    assert_eq!(reads(&peer.take()), [(0, page)]);

    // Without `O_DIRECT`, a write waits for the inode lock while another
    // write waits for the reply to it.
    peer.withhold(&[Opcode::Write]);
    let first = {
        let file = file.clone();
        std::thread::spawn(move || file.write_at(&pattern(7, 0..page_end), 0))
    };
    peer.wait_for(&Received::Write {
        node: FILE,
        offset: 0,
        len: page,
    })?;
    let (task, started) = mpsc::channel();
    let second = {
        let file = file.clone();
        std::thread::spawn(move || {
            task.send(unsafe { libc::gettid() })
                .expect("the case receives the task of the writer");
            file.write_at(&pattern(8, page_end..2 * page_end), page_end)
        })
    };
    let status = format!("/proc/self/task/{}/status", started.recv()?);
    while !std::fs::read_to_string(&status)?
        .lines()
        .any(|line| line.starts_with("State:\tD"))
    {
        assert!(!second.is_finished(), "the second write did not wait");
        std::thread::yield_now();
    }
    assert!(
        !peer.received().contains(&Received::Write {
            node: FILE,
            offset: page_end,
            len: page,
        }),
        "the second write was sent while the first one held the inode lock"
    );
    peer.send_withheld();
    for writer in [first, second] {
        let written = writer.join().map_err(|_| "a writer panicked")?;
        assert_eq!(written?, page_len);
    }
    assert_eq!(writes(&peer.take()), [(0, page), (page_end, page)]);

    let mapping = Mapping::new(&file, page_len)?;
    mapping.store(9, 0..page_end);
    mapping.sync()?;
    assert!(
        peer.content(FILE)[..page_len] == pattern(9, 0..page_end),
        "the content of the peer does not show the stores through the mapping"
    );
    peer.take();
    assert!(read_at(&file, 0, page_len)? == pattern(9, 0..page_end));
    assert_eq!(reads(&peer.take()), [(0, page)]);
    drop(mapping);
    drop(file);

    unmount(session)?;
    println!(
        "direct I/O mount: a file opened without O_DIRECT is read, spliced and written past the page cache, a write waits for the inode lock held by another, and a shared mapping stores through the page cache"
    );
    unload_module()
}
