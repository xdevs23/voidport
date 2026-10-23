// SPDX-License-Identifier: GPL-2.0

use super::writable::{FIRST_FILE, Held, Peer, Received, mount, path, unmount};
use crate::supervision::{Supervision, fork_child};
use crate::{Result, load_module, unload_module};
use std::ffi::CString;
use voidport_proto::opcode::Opcode;
use voidport_proto::ops::file::{FileLock, lock_type};
use zerocopy::byteorder::little_endian::U32;

const FILE: u64 = FIRST_FILE;

fn wait_for_lock(path: &CString) -> libc::c_int {
    let file = unsafe { libc::open(path.as_ptr(), libc::O_RDWR) };
    let mut lock: libc::flock = unsafe { std::mem::zeroed() };
    lock.l_type = libc::F_WRLCK as libc::c_short;
    lock.l_whence = libc::SEEK_SET as libc::c_short;
    if file >= 0 && unsafe { libc::fcntl(file, libc::F_SETLKW, &mut lock) } == 0 {
        0
    } else {
        1
    }
}

fn waiting(received: &[Received]) -> Option<(u64, FileLock)> {
    received.iter().find_map(|request| match *request {
        Received::Setlk {
            node: FILE,
            handle,
            lock,
            wait: true,
        } if lock.lock_type.get() == lock_type::WRITE => Some((handle, lock)),
        _ => None,
    })
}

fn start_waiter(peer: &Peer, path: &CString) -> Result<(libc::pid_t, u64, FileLock)> {
    peer.withhold(&[Opcode::Setlk]);
    let waiter = fork_child(|| wait_for_lock(path));
    peer.wait(|fresh| waiting(fresh).is_some())?;
    let (handle, lock) = waiting(&peer.take()).ok_or("the Setlk went missing")?;
    Ok((waiter, handle, lock))
}

fn hold_lock(path: &CString, ready: libc::c_int) -> libc::c_int {
    let file = unsafe { libc::open(path.as_ptr(), libc::O_RDWR) };
    let mut lock: libc::flock = unsafe { std::mem::zeroed() };
    lock.l_type = libc::F_WRLCK as libc::c_short;
    lock.l_whence = libc::SEEK_SET as libc::c_short;
    if file < 0 || unsafe { libc::fcntl(file, libc::F_SETLK, &mut lock) } != 0 {
        return 1;
    }
    if unsafe { libc::write(ready, [1u8].as_ptr().cast(), 1) } != 1 {
        return 1;
    }
    loop {
        unsafe { libc::pause() };
    }
}

fn unlock_of(handle: u64, lock: FileLock) -> Received {
    let mut unlock = lock;
    unlock.lock_type = U32::new(lock_type::UNLOCK);
    Received::Setlk {
        node: FILE,
        handle,
        lock: unlock,
        wait: false,
    }
}

fn kill_waiter(peer: &Peer, path: &CString, supervision: &Supervision) -> Result {
    let (killed, handle, lock) = start_waiter(peer, path)?;
    supervision.kill_and_reap(killed, "the waiter")?;
    peer.send_withheld_and_withhold(&[Opcode::Setlk]);
    let sent = [
        unlock_of(handle, lock),
        Received::Flush {
            node: FILE,
            owner: lock.owner.get(),
        },
        Received::Release { node: FILE },
    ];
    peer.wait(|fresh| sent.iter().all(|request| fresh.contains(request)))?;
    peer.take();
    Ok(())
}

pub(crate) fn run() -> Result {
    load_module()?;
    let peer = Peer::new(vec![Held::new("lock", libc::S_IFREG | 0o644, vec![])]);
    let session = mount(&peer, "")?;
    let file = CString::new(path("lock"))?;
    let supervision = Supervision::new();

    let (waiter, _, lock) = start_waiter(&peer, &file)?;
    let exited = unsafe { libc::waitpid(waiter, std::ptr::null_mut(), libc::WNOHANG) };
    assert_eq!(exited, 0, "F_SETLKW returned before the grant");
    peer.send_withheld();
    assert_eq!(supervision.reap(waiter)?, 0, "the granted waiter");
    let closed = [
        Received::Flush {
            node: FILE,
            owner: lock.owner.get(),
        },
        Received::Release { node: FILE },
    ];
    peer.wait(|fresh| closed.iter().all(|request| fresh.contains(request)))?;
    peer.take();

    // A connection that its unlock kept busy would have no retire.
    kill_waiter(&peer, &file, &supervision)?;
    peer.send_withheld_and_cut()?;
    peer.wait_retired(1)?;
    kill_waiter(&peer, &file, &supervision)?;
    peer.cut_withheld()?;
    peer.withhold(&[]);
    peer.wait_retired(2)?;

    let mut ready = [0; 2];
    assert_eq!(unsafe { libc::pipe(ready.as_mut_ptr()) }, 0);
    let holder = fork_child(|| hold_lock(&file, ready[1]));
    unsafe { libc::close(ready[1]) };
    let mut placed = 0u8;
    let read = unsafe { libc::read(ready[0], (&raw mut placed).cast(), 1) };
    unsafe { libc::close(ready[0]) };
    assert_eq!(read, 1, "the holder did not place its lock");
    // The second handle opens after the fork, so the holder has one descriptor
    // of the file. A descriptor it inherited would close first at its death
    // and carry the Flush, which the release of its own handle does not wait
    // for.
    let other = std::fs::File::open(path("lock"))?;
    let held = peer.take();
    let owner = held
        .iter()
        .find_map(|request| match request {
            Received::Setlk { lock, .. } if lock.lock_type.get() == lock_type::WRITE => {
                Some(lock.owner.get())
            }
            _ => None,
        })
        .ok_or("the Setlk of the holder went missing")?;
    supervision.kill_and_reap(holder, "the holder")?;
    let flush = Received::Flush { node: FILE, owner };
    let release = Received::Release { node: FILE };
    peer.wait(|fresh| fresh.contains(&flush) && fresh.contains(&release))?;
    let fresh = peer.take();
    let at = |request: &Received| fresh.iter().position(|seen| seen == request);
    assert!(
        at(&flush) < at(&release),
        "the holder's handle went back before its Flush"
    );
    drop(other);

    unmount(session)?;
    let unlocks = peer
        .received()
        .iter()
        .filter(|request| matches!(request, Received::Setlk { lock, .. } if lock.lock_type.get() == lock_type::UNLOCK))
        .count();
    assert_eq!(unlocks, 2, "the lock of each killed waiter went back once");
    println!(
        "record lock acceptance: F_SETLKW returns at the grant, the close releases the locks, a lock granted after a kill goes back once on a connection that comes back, and a killed holder's locks are flushed"
    );
    unload_module()
}
