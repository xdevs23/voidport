// SPDX-License-Identifier: GPL-2.0

use super::guest::{
    SIGUSR1_HANDLED, count_sigusr1, counter, errno, list_past_dots, look_up, read_back,
    unmount_balanced, withholding_mount,
};
use super::server::FLUSH;
use crate::supervision::{Supervision, fork_child};
use crate::{Result, load_module, unload_module};
use std::fs::{self};
use std::sync::atomic::Ordering;
use voidport_proto::opcode::Opcode;

#[derive(Clone, Copy, Debug)]
pub(crate) enum Case {
    Queued,
    Transmitted,
    Killed(Operation),
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum Operation {
    Node,
    Open,
    Directory,
}

impl Operation {
    fn opcode(self) -> Opcode {
        match self {
            Self::Node => Opcode::Lookup,
            Self::Open => Opcode::Open,
            Self::Directory => Opcode::Readdirplus,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Outcome {
    Interrupted,
    Answered,
}

pub(super) fn signalled_open(expected: Outcome, before: impl FnOnce() -> bool) -> libc::c_int {
    if !count_sigusr1() || !before() {
        return 1;
    }
    // One system call, so EINTR cannot turn into a second request.
    let opened = unsafe { libc::open(c"/vfs-options/a".as_ptr(), libc::O_RDONLY) };
    let outcome = if opened >= 0 {
        Some(Outcome::Answered)
    } else {
        (errno() == libc::EINTR).then_some(Outcome::Interrupted)
    };
    if opened >= 0 {
        unsafe { libc::close(opened) };
    }
    if outcome == Some(expected) && SIGUSR1_HANDLED.load(Ordering::Relaxed) == 1 {
        0
    } else {
        1
    }
}

fn blocked(operation: Operation) -> libc::c_int {
    match operation {
        Operation::Node => look_up(c"/vfs-options/n9"),
        Operation::Open => read_back(c"/vfs-options/a", b"old"),
        Operation::Directory => list_past_dots("/vfs-options", 2).map_or(1, |()| 0),
    }
}

fn trace(request: libc::c_uint, child: libc::pid_t, address: usize, data: usize) -> Result<i64> {
    let result = unsafe {
        libc::ptrace(
            request,
            child,
            address as *mut libc::c_void,
            data as *mut libc::c_void,
        )
    };
    if result < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(result)
}

fn signal_at_open_entry(child: libc::pid_t) -> Result {
    let mut status = 0;
    assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
    assert!(libc::WIFSTOPPED(status) && libc::WSTOPSIG(status) == libc::SIGSTOP);
    let options = libc::PTRACE_O_TRACESYSGOOD as usize;
    trace(libc::PTRACE_SETOPTIONS, child, 0, options)?;
    loop {
        trace(libc::PTRACE_SYSCALL, child, 0, 0)?;
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        if !libc::WIFSTOPPED(status) || libc::WSTOPSIG(status) != libc::SIGTRAP | 0x80 {
            return Err(format!("the child stopped with {status:#x}").into());
        }
        let mut info: libc::ptrace_syscall_info = unsafe { std::mem::zeroed() };
        let size = size_of::<libc::ptrace_syscall_info>();
        trace(
            libc::PTRACE_GET_SYSCALL_INFO,
            child,
            size,
            (&raw mut info) as usize,
        )?;
        let entry = info.op == libc::PTRACE_SYSCALL_INFO_ENTRY;
        if entry && unsafe { info.u.entry.nr } == libc::SYS_openat as u64 {
            break;
        }
    }
    assert_eq!(unsafe { libc::kill(child, libc::SIGUSR1) }, 0);
    trace(libc::PTRACE_DETACH, child, 0, 0)?;
    Ok(())
}

#[derive(Debug, PartialEq)]
pub(super) struct Counters {
    pub(super) cancelled: u64,
    pub(super) interrupted: u64,
    pub(super) handles_opened: u64,
    pub(super) orphans: u64,
}

impl Counters {
    pub(super) fn read() -> Result<Self> {
        Ok(Self {
            cancelled: counter("cancelled")?,
            interrupted: counter("interrupted")?,
            handles_opened: counter("handles_opened")?,
            orphans: counter("orphans")?,
        })
    }

    pub(super) fn since(&self, before: &Self) -> Self {
        Self {
            cancelled: self.cancelled - before.cancelled,
            interrupted: self.interrupted - before.interrupted,
            handles_opened: self.handles_opened - before.handles_opened,
            orphans: self.orphans - before.orphans,
        }
    }
}

pub(crate) fn run(case: Case) -> Result {
    fs::create_dir_all("/vfs-options")?;
    load_module()?;
    let (withhold, state, peer) = withholding_mount()?;
    let before = Counters::read()?;
    let supervision = Supervision::new();
    match case {
        Case::Queued => {
            // The lookup of `a` is cached, so the open is the only request.
            fs::metadata("/vfs-options/a")?;
            let child = fork_child(|| {
                signalled_open(Outcome::Interrupted, || {
                    trace(libc::PTRACE_TRACEME, 0, 0, 0).is_ok()
                        && unsafe { libc::raise(libc::SIGSTOP) } == 0
                })
            });
            signal_at_open_entry(child)?;
            assert_eq!(supervision.reap(child)?, 0, "the queued open");
        }
        Case::Transmitted => {
            withhold.set(&[Opcode::Open]);
            let child = fork_child(|| signalled_open(Outcome::Interrupted, || true));
            withhold.wait(Opcode::Open, 1)?;
            assert_eq!(unsafe { libc::kill(child, libc::SIGUSR1) }, 0);
            assert_eq!(supervision.reap(child)?, 0, "the transmitted open");
        }
        Case::Killed(operation) => {
            withhold.set(&[operation.opcode()]);
            let child = fork_child(|| blocked(operation));
            withhold.wait(operation.opcode(), 1)?;
            assert_eq!(unsafe { libc::kill(child, libc::SIGTERM) }, 0);
            let status = supervision.reap(child)?;
            assert!(
                libc::WIFSIGNALED(status) && libc::WTERMSIG(status) == libc::SIGTERM,
                "{operation:?} returned before the kill: {status:#x}"
            );
        }
    }
    let flushed = fs::metadata(format!("/vfs-options/{FLUSH}"));
    assert_eq!(flushed.unwrap_err().raw_os_error(), Some(libc::ENOENT));
    match case {
        Case::Queued => {}
        Case::Transmitted | Case::Killed(Operation::Open) => {
            state.wait(1, |events| events.released == 1)?;
        }
        Case::Killed(Operation::Node) => state.wait_forgotten(1, &[(9, 1)])?,
        Case::Killed(Operation::Directory) => state.wait_forgotten(1, &[(1, 1), (2, 1)])?,
    }
    unmount_balanced(peer)?;
    let grown = Counters::read()?.since(&before);
    let expected = match case {
        Case::Queued => Counters {
            cancelled: 1,
            interrupted: 0,
            handles_opened: 0,
            orphans: 0,
        },
        Case::Transmitted => Counters {
            cancelled: 0,
            interrupted: 1,
            handles_opened: 1,
            orphans: 1,
        },
        // The handles opened depend on the operation, so they are not
        // compared.
        Case::Killed(_) => Counters {
            cancelled: 0,
            interrupted: 1,
            handles_opened: grown.handles_opened,
            orphans: 1,
        },
    };
    assert_eq!(grown, expected, "{case:?}");
    unload_module()?;
    println!(
        "vfs acceptance: a signal at {case:?} ended its caller once, and a late reply gave back what it contained"
    );
    Ok(())
}
