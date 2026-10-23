// SPDX-License-Identifier: GPL-2.0

use super::guest::{
    CLEANUP_TASK, counter, list_past_dots, mount, mount_peer, require_zero, task_named,
    unmount_balanced, withholding_mount,
};
use super::server::{
    Behaviour, DISTINCT, Readers, State, flush_readers, serve_sessions, spawn_readers,
};
use crate::{Result, load_module, unload_module};
use std::ffi::CString;
use std::fs::{self, File};
use std::net::{Ipv4Addr, TcpListener};
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileExt;
use std::sync::Arc;
use voidport_proto::opcode::Opcode;

/// Limits the failures to allocations with module code among their callers, so
/// they never hit the module loader or the system call paths around the module,
/// whose failures the kernel may report as warnings. x86_64, the only
/// architecture the guests run on, maps every module above the kernel's own
/// text, and no other module is on the paths a sweep follows. Allocations that
/// may sleep (ignore-gfp-wait N) and page allocations of every order
/// (min-order 0) count as well, and the kernel stays silent about a failure it
/// injects (verbose 0).
fn limit_injection_to_the_module() -> Result {
    let modules = kernel_text_end()?;
    for injection in ["failslab", "fail_page_alloc"] {
        let settings = format!("/sys/kernel/debug/{injection}");
        fs::write(format!("{settings}/require-start"), format!("{modules:#x}"))?;
        fs::write(
            format!("{settings}/require-end"),
            format!("{:#x}", u64::MAX),
        )?;
        fs::write(format!("{settings}/ignore-gfp-wait"), "N")?;
        fs::write(format!("{settings}/verbose"), "0")?;
    }
    fs::write("/sys/kernel/debug/fail_page_alloc/min-order", "0")?;
    Ok(())
}

struct FailNth(File);

impl FailNth {
    fn at(path: &str) -> Result<Self> {
        let file = fs::OpenOptions::new().read(true).write(true).open(path)?;
        Ok(Self(file))
    }

    fn thread() -> Result<Self> {
        Self::at("/proc/thread-self/fail-nth")
    }

    fn duplicate(&self) -> Result<Self> {
        Ok(Self(self.0.try_clone()?))
    }

    fn arm(&self, nth: usize) -> Result {
        self.0.write_at(nth.to_string().as_bytes(), 0)?;
        Ok(())
    }

    fn fired(&self) -> Result<bool> {
        let mut text = [0u8; 24];
        let len = self.0.read_at(&mut text, 0)?;
        let left: u64 = std::str::from_utf8(&text[..len])?.trim().parse()?;
        if left != 0 {
            self.0.write_at(b"0", 0)?;
        }
        Ok(left == 0)
    }
}

fn kernel_text_end() -> Result<u64> {
    let symbols = fs::read_to_string("/proc/kallsyms")?;
    let address = symbols
        .lines()
        .find_map(|line| {
            let mut fields = line.split_whitespace();
            let address = fields.next()?;
            (fields.nth(1)? == "_etext").then_some(address)
        })
        .ok_or("the kernel symbols lack _etext")?;
    let address = u64::from_str_radix(address, 16)?;
    assert_ne!(address, 0, "the kernel hides the addresses of its symbols");
    Ok(address)
}

fn outcome(result: libc::c_long) -> std::io::Result<()> {
    if result == -1 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// The run in which no allocation fails must succeed, and at least one run must
/// fail an allocation. The call makes system calls only, on memory prepared
/// before, so nothing but the kernel allocates while the countdown runs.
fn sweep(
    name: &str,
    injection: &FailNth,
    mut call: impl FnMut(usize) -> std::io::Result<()>,
    mut after: impl FnMut(std::io::Result<()>) -> Result,
) -> Result {
    sweep_prepared(
        name,
        || Ok(((), injection.duplicate()?)),
        |(), nth| call(nth),
        |(), outcome| after(outcome),
    )
}

/// Setting up allocates in the calling thread, so it runs before the countdown
/// is armed.
fn sweep_prepared<T>(
    name: &str,
    mut prepare: impl FnMut() -> Result<(T, FailNth)>,
    mut call: impl FnMut(&mut T, usize) -> std::io::Result<()>,
    mut after: impl FnMut(T, std::io::Result<()>) -> Result,
) -> Result {
    let mut failed = 0;
    for nth in 1.. {
        let (mut prepared, countdown) = prepare()?;
        countdown.arm(nth)?;
        let outcome = call(&mut prepared, nth);
        if !countdown.fired()? {
            assert!(outcome.is_ok(), "{name} failed with no failed allocation");
            assert!(nth > 1, "{name} made no allocation from module code");
            after(prepared, outcome)?;
            println!(
                "vfs acceptance: {name} with each of its {} allocations failing, {failed} of those runs failed",
                nth - 1
            );
            return Ok(());
        }
        failed += usize::from(outcome.is_err());
        after(prepared, outcome)?;
    }
    unreachable!("the countdown outgrew its counter")
}

fn module_load(injection: &FailNth) -> Result {
    let module = File::open("/voidport.ko")?;
    let load = |_| {
        outcome(unsafe {
            libc::syscall(libc::SYS_finit_module, module.as_raw_fd(), c"".as_ptr(), 0)
        })
    };
    sweep("the module load", injection, load, |loaded| {
        if loaded.is_ok() {
            unload_module()
        } else {
            assert!(!std::path::Path::new("/sys/module/voidport").exists());
            Ok(())
        }
    })
}

struct Severable;

impl Behaviour for Severable {
    fn severed(&self, error: &(dyn std::error::Error + 'static)) -> bool {
        use std::io::ErrorKind::{BrokenPipe, ConnectionReset, UnexpectedEof};
        error.downcast_ref::<std::io::Error>().is_some_and(|error| {
            matches!(error.kind(), UnexpectedEof | ConnectionReset | BrokenPipe)
        })
    }
}

fn mount_attempts(injection: &FailNth) -> Result {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let port = listener.local_addr()?.port();
    let stop = listener.try_clone()?;
    let peer = std::thread::spawn(move || -> Result {
        let state = Arc::new(State::with(Arc::new(Severable)));
        // The peer serves sessions until the case shuts the listener down.
        serve_sessions(&listener, u64::MAX, &state, |_| Ok(()), &|_| {})
    });
    let options = format!("addr=127.0.0.1,port={port}");
    let attempt = |_| outcome(mount(&options, false).into());
    sweep("a mount", injection, attempt, |mounted| {
        if mounted.is_ok() {
            assert_eq!(fs::read("/vfs-options/a")?, b"old");
            assert_eq!(unsafe { libc::umount(c"/vfs-options".as_ptr()) }, 0);
        }
        require_zero(&["connections_live", "requests_in_flight"])?;
        Ok(())
    })?;
    assert_eq!(
        unsafe { libc::shutdown(stop.as_raw_fd(), libc::SHUT_RD) },
        0
    );
    peer.join().map_err(|_| "the mount peer failed")?
}

fn operations(injection: &FailNth) -> Result {
    let state = Arc::new(State::default());
    let peer = mount_peer(&state, "attr_timeout=0,entry_timeout=0")?;
    let lost = counter("connections_lost")?;
    let usable = |_| {
        assert_eq!(fs::read("/vfs-options/b")?, b"old");
        assert_eq!(counter("connections_lost")?, lost);
        Ok(())
    };
    let names: Vec<CString> = (1000..3000)
        .map(|index| CString::new(format!("/vfs-options/n{index}")))
        .collect::<std::result::Result<_, _>>()?;
    let mut status: libc::stat = unsafe { std::mem::zeroed() };
    let look_up =
        |nth: usize| outcome(unsafe { libc::stat(names[nth].as_ptr(), &mut status) }.into());
    sweep("a lookup", injection, look_up, usable)?;
    let open = |_| {
        let file = unsafe { libc::open(c"/vfs-options/a".as_ptr(), libc::O_RDONLY) };
        outcome(file.into())?;
        outcome(unsafe { libc::close(file) }.into())
    };
    sweep("an open", injection, open, usable)?;
    let mut target = [0u8; 64];
    let read_link = |_| {
        let link = c"/vfs-options/n3002".as_ptr();
        outcome(unsafe { libc::readlink(link, target.as_mut_ptr().cast(), target.len()) } as _)
    };
    sweep("a symbolic link", injection, read_link, usable)?;
    let list = |_| list_past_dots("/vfs-options", 2);
    sweep("a listing", injection, list, usable)?;
    unmount_balanced(peer)?;
    assert_eq!(counter("nodes_admitted")?, counter("nodes_forgotten")?);
    Ok(())
}

struct BusySession {
    state: Arc<State>,
    peer: std::thread::JoinHandle<Result>,
    readers: Readers,
    lost: u64,
    file: Option<File>,
}

impl BusySession {
    fn mount(holding: Option<&str>) -> Result<Self> {
        let (withhold, state, peer) = withholding_mount()?;
        let file = holding.map(File::open).transpose()?;
        withhold.set(&[Opcode::Read]);
        let readers = spawn_readers(DISTINCT.start..DISTINCT.start + 1);
        withhold.wait(Opcode::Read, 1)?;
        assert_eq!(counter("requests_in_flight")?, 1);
        assert_eq!(counter("connections_live")?, 1);
        Ok(Self {
            state,
            peer,
            readers,
            lost: counter("connections_lost")?,
            file,
        })
    }

    fn finish(self) -> Result {
        flush_readers(self.readers)?;
        assert_eq!(counter("connections_lost")?, self.lost);
        drop(self.file);
        unmount_balanced(self.peer)?;
        assert_eq!(counter("nodes_admitted")?, counter("nodes_forgotten")?);
        Ok(())
    }
}

fn growth(injection: &FailNth) -> Result {
    let name = c"/vfs-options/n1000";
    let mut status: libc::stat = unsafe { std::mem::zeroed() };
    sweep_prepared(
        "a lookup that opens a connection",
        || Ok((BusySession::mount(None)?, injection.duplicate()?)),
        |_, _| outcome(unsafe { libc::stat(name.as_ptr(), &mut status) }.into()),
        |table, lookup| {
            if let Err(error) = lookup {
                assert_eq!(error.raw_os_error(), Some(libc::ENOMEM));
            }
            table.finish()
        },
    )
}

fn cleanup_growth() -> Result {
    sweep_prepared(
        "the release of a handle that opens a connection",
        || {
            let table = BusySession::mount(Some("/vfs-options/a"))?;
            let worker = task_named(CLEANUP_TASK)?;
            Ok((table, FailNth::at(&format!("/proc/{worker}/fail-nth"))?))
        },
        |table, _| {
            drop(table.file.take());
            table
                .state
                .wait(1, |events| events.released == 1)
                .map_err(std::io::Error::other)
        },
        |table, release| {
            release?;
            table.finish()
        },
    )
}

pub(crate) fn run() -> Result {
    fs::create_dir_all("/vfs-options")?;
    limit_injection_to_the_module()?;
    let injection = FailNth::thread()?;
    module_load(&injection)?;
    load_module()?;
    mount_attempts(&injection)?;
    operations(&injection)?;
    growth(&injection)?;
    cleanup_growth()?;
    unload_module()
}
