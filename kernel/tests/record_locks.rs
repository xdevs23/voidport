// SPDX-License-Identifier: GPL-2.0

use std::ffi::CString;
use std::fs::OpenOptions;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use crate::host;

fn whole_file() -> libc::flock {
    // SAFETY: flock contains only integers, for which zero is a valid value.
    let mut lock: libc::flock = unsafe { std::mem::zeroed() };
    lock.l_type = libc::F_WRLCK as libc::c_short;
    lock.l_whence = libc::SEEK_SET as libc::c_short;
    lock
}

fn start_waiter(path: &CString) -> io::Result<libc::pid_t> {
    let mut lock = whole_file();
    // SAFETY: this helper runs no other thread, and the child calls only
    // open, fcntl and _exit.
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        // SAFETY: the path is NUL-terminated, and the lock is the child's own
        // copy of writable storage.
        unsafe {
            let fd = libc::open(path.as_ptr(), libc::O_RDWR);
            let locked = fd >= 0 && libc::fcntl(fd, libc::F_SETLKW, &mut lock) == 0;
            libc::_exit(if locked { 0 } else { 1 });
        }
    }
    if pid < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(pid)
}

fn reap(pid: libc::pid_t) -> io::Result<libc::c_int> {
    let mut status = 0;
    // SAFETY: the status is writable storage.
    if unsafe { libc::waitpid(pid, &mut status, 0) } != pid {
        return Err(io::Error::last_os_error());
    }
    Ok(status)
}

pub(super) fn run(path: &Path) -> io::Result<()> {
    host("lock-hold")?;

    let file = OpenOptions::new().read(true).write(true).open(path)?;
    let mut probe = whole_file();
    // SAFETY: the descriptor is open, and the lock is writable storage.
    assert_eq!(
        unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETLK, &mut probe) },
        0
    );
    assert_eq!(probe.l_type, libc::F_WRLCK as libc::c_short);
    // SAFETY: as above.
    let refused = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETLK, &mut whole_file()) };
    assert_eq!(refused, -1);
    assert_eq!(
        io::Error::last_os_error().raw_os_error(),
        Some(libc::EAGAIN)
    );
    drop(file);

    // The waiter's lock cannot be granted while the host process holds its
    // own, whenever the Setlk of the waiter reaches the server. Its exit
    // closes the file, and the close releases the lock on the server before
    // the exit completes.
    let waiter = start_waiter(&CString::new(path.as_os_str().as_bytes())?)?;
    host("lock-release")?;
    let status = reap(waiter)?;
    assert!(libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0);

    host("lock-free")?;
    println!("record locks: the host's lock was reported, refused, and waited for");
    Ok(())
}
