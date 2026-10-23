// SPDX-License-Identifier: GPL-2.0

mod namespace;
mod ownership;
mod record_locks;
mod transports;
mod xattr;

use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileExt;

struct Mapping {
    address: *mut libc::c_void,
    len: usize,
    protection: i32,
}

impl Mapping {
    fn new(file: &File, len: usize, protection: i32, flags: i32) -> io::Result<Self> {
        // SAFETY: mmap receives a live descriptor and no fixed address. Its
        // result is checked before access and remains owned until munmap.
        let address = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                protection,
                flags,
                file.as_raw_fd(),
                0,
            )
        };
        if address == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            address,
            len,
            protection,
        })
    }

    fn bytes(&self) -> &[u8] {
        // SAFETY: every mapping this test creates has PROT_READ, and the
        // fixture is neither truncated nor modified by the host during it.
        unsafe { std::slice::from_raw_parts(self.address.cast(), self.len) }
    }

    fn bytes_mut(&mut self) -> &mut [u8] {
        assert_ne!(
            self.protection & libc::PROT_WRITE,
            0,
            "a mapping without PROT_WRITE"
        );
        // SAFETY: the mapping is writable, as just checked, and the exclusive
        // borrow of this object makes the slice the only access to it.
        unsafe { std::slice::from_raw_parts_mut(self.address.cast(), self.len) }
    }

    fn sync(&self) -> io::Result<()> {
        // SAFETY: the range is the live mapping this object owns.
        if unsafe { libc::msync(self.address, self.len, libc::MS_SYNC) } == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        // SAFETY: this object exclusively owns the live mapping.
        assert_eq!(unsafe { libc::munmap(self.address, self.len) }, 0);
    }
}

fn unchanged(file: &File, expected: &[u8]) -> io::Result<()> {
    let mut bytes = vec![0; expected.len()];
    file.read_exact_at(&mut bytes, 0)?;
    assert_eq!(bytes, expected, "backing bytes changed");
    Ok(())
}

fn acknowledged(program: &str, arguments: &[&str]) -> io::Result<()> {
    if std::process::Command::new(program)
        .args(arguments)
        .status()?
        .success()
    {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "the host did not acknowledge {program} {arguments:?}"
        )))
    }
}

fn host(operation: &str) -> io::Result<()> {
    acknowledged("/bin/guest-event", &[operation])
}

fn verdict(name: &str) -> io::Result<()> {
    acknowledged("/bin/guest-verdict", &[name, "ok"])
}

fn negative_zero() -> io::Result<()> {
    assert_eq!(
        std::fs::metadata("/fresh/tree/appeared")
            .unwrap_err()
            .raw_os_error(),
        Some(libc::ENOENT)
    );
    host("mutate")?;
    assert_eq!(std::fs::read("/fresh/tree/appeared")?, b"now here");
    verdict("negative-zero")
}

fn child_open(path: &std::ffi::OsStr) -> ! {
    let Ok(mut child) = std::process::Command::new("/bin/true").spawn() else {
        std::process::exit(2);
    };
    let opened = File::open(path).is_ok();
    match child.wait() {
        Ok(status) if status.success() => std::process::exit(if opened { 0 } else { 1 }),
        _ => std::process::exit(2),
    }
}

fn main() -> io::Result<()> {
    let mut args = std::env::args_os().skip(1);
    let first = args.next().expect("fixture path or mount case");
    if first == "--guest-init" {
        use std::os::unix::process::CommandExt;
        // Child completion must not interrupt init's ordinary filesystem
        // operations. A blocking waitpid still reaps children with SIGCHLD
        // blocked, and the explicit signal tests use their unblocked SIGUSR1
        // handler. The wait builtin of the shell sleeps until SIGCHLD arrives,
        // so the guest scripts reap a background child only through a helper.
        // SAFETY: sigset_t is integer storage, so zero is a valid value. The
        // signal-set API initializes its contents before the mask is installed.
        let mut signals = unsafe { std::mem::zeroed::<libc::sigset_t>() };
        // SAFETY: signals is writable storage for the libc signal-set API.
        unsafe {
            libc::sigemptyset(&mut signals);
            libc::sigaddset(&mut signals, libc::SIGCHLD);
        }
        // SAFETY: changes only this single-threaded launcher's signal mask.
        if unsafe { libc::sigprocmask(libc::SIG_BLOCK, &signals, std::ptr::null_mut()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        return Err(std::process::Command::new("/bin/sh")
            .arg("/mount-init")
            .exec());
    }
    if first == "--child-open" {
        child_open(&args.next().expect("path to open"));
    }
    if first == "--local-denial" {
        // SAFETY: these calls take numeric IDs and change only this
        // single-threaded helper's filesystem credentials, with no pointers.
        unsafe {
            libc::setfsgid(65534);
            libc::setfsuid(65534);
        }
        let error =
            File::open("/mnt/tree/secret.txt").expect_err("0600 file opened by unrelated identity");
        assert_eq!(error.raw_os_error(), Some(libc::EACCES));
        println!("credential helper: local 0600 denial returned EACCES");
        return Ok(());
    }
    if first == "--credentials" {
        // fsuid/fsgid change only this helper's requesting identity. Opening
        // under one identity and faulting under another distinguishes retained
        // file credentials from both the worker and faulting task identities.
        // SAFETY: numeric IDs affect only this single-threaded helper's
        // filesystem credentials. Neither call accesses memory through pointers.
        unsafe {
            libc::setfsgid(2222);
            libc::setfsuid(1111);
        }
        let file = File::open("/vfs-options/n20")?;
        // SAFETY: these pointer-free calls change only this single-threaded
        // helper's filesystem identity, not the credentials retained by file.
        unsafe {
            libc::setfsuid(0);
            libc::setfsgid(4444);
            libc::setfsuid(3333);
        }
        assert_eq!(std::fs::metadata("/vfs-options/n21")?.len(), 3);
        let map = Mapping::new(&file, 3, libc::PROT_READ, libc::MAP_SHARED)?;
        assert_eq!(map.bytes(), b"old");
        drop(map);
        // SAFETY: these pointer-free calls restore only this single-threaded
        // helper's filesystem credentials after the mapping has been released.
        unsafe {
            libc::setfsuid(0);
            libc::setfsgid(0);
        }
        println!(
            "credential helper: two synchronous identities and retained-file mmap identity exercised"
        );
        return Ok(());
    }
    if first == "--negative-zero" {
        return negative_zero();
    }
    if first == "--ownership" {
        return ownership::run();
    }
    if first == "--namespace" {
        return namespace::run();
    }
    if first == "--xattr" {
        let file = args.next().expect("file path");
        let directory = args.next().expect("directory path");
        return xattr::run(file.as_ref(), directory.as_ref());
    }
    if first == "--handover" {
        return transports::handover();
    }
    if first == "--absent-tag" {
        return transports::absent_tag();
    }
    if first == "--read-write" {
        return transports::read_write(&transports::Mount::from_args(args));
    }
    if first == "--mapping" {
        return transports::mapping(&transports::Mount::from_args(args));
    }
    if first == "--restart" {
        return transports::restart(&transports::Mount::from_args(args));
    }
    if first == "--record-locks" {
        let path = args.next().expect("path of the locked file");
        return record_locks::run(std::path::Path::new(&path));
    }
    // A shared writable mapping needs a writable descriptor. On a read-only
    // mount the strongest reachable prerequisite is O_RDWR, which must fail
    // with EROFS even for root.
    let error = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&first)
        .expect_err("read-only mount accepted O_RDWR");
    assert_eq!(error.raw_os_error(), Some(libc::EROFS));
    let file = File::open(first)?;
    let len = usize::try_from(file.metadata()?.len()).expect("addressable fixture");
    assert!(len > 0);
    let mut expected = vec![0; len];
    file.read_exact_at(&mut expected, 0)?;

    let shared = Mapping::new(&file, len, libc::PROT_READ, libc::MAP_SHARED)?;
    assert_eq!(shared.bytes(), expected);
    drop(shared);
    unchanged(&file, &expected)?;

    let private = Mapping::new(
        &file,
        len,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_PRIVATE,
    )?;
    // SAFETY: this nonempty private mapping is writable, with no live slice
    // borrow or concurrent access. Modifying it must not modify the file.
    unsafe { *private.address.cast::<u8>() ^= 0xff };
    assert_ne!(private.bytes()[0], expected[0]);
    unchanged(&file, &expected)?;
    drop(private);
    unchanged(&file, &expected)?;

    match Mapping::new(
        &file,
        len,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_SHARED,
    ) {
        Ok(_) => panic!("shared writable mapping was accepted"),
        Err(error) => assert_eq!(error.raw_os_error(), Some(libc::EACCES)),
    }
    unchanged(&file, &expected)?;
    println!("shared read-only, private COW and shared writable EACCES verified");
    Ok(())
}
