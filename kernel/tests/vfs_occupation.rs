// SPDX-License-Identifier: GPL-2.0

//! Blocking a task on a processor. A task that a wake-up has made runnable
//! cannot run while a task of the real-time class occupies the processor it
//! would run on, so nothing outside the kernel needs a signal or a delay to
//! block it there. The kernel gives the starved tasks a share of the processor
//! in two ways, a limit on how long real-time tasks may run and a server for
//! ordinary tasks, and an occupation turns both off for the processor it
//! occupies.

use crate::Result;
use crate::supervision::{Supervision, fork_child};
use std::fs;
use std::io::Error;

const REAL_TIME_LIMIT: &str = "/proc/sys/kernel/sched_rt_runtime_us";

fn server_runtime(cpu: usize) -> String {
    format!("/sys/kernel/debug/sched/fair_server/cpu{cpu}/runtime")
}

const HIGHEST_REAL_TIME_PRIORITY: libc::c_int = 99;

pub(super) struct Processors {
    pub(super) shared: usize,
    pub(super) occupied: usize,
}

pub(super) fn processors() -> Result<Processors> {
    let mut allowed: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    if unsafe { libc::sched_getaffinity(0, size_of::<libc::cpu_set_t>(), &mut allowed) } != 0 {
        return Err(Error::last_os_error().into());
    }
    let cpus: Vec<usize> = (0..libc::CPU_SETSIZE as usize)
        .filter(|cpu| unsafe { libc::CPU_ISSET(*cpu, &allowed) })
        .collect();
    match (cpus.first(), cpus.last()) {
        (Some(&shared), Some(&occupied)) if shared != occupied => {
            Ok(Processors { shared, occupied })
        }
        _ => Err("the case needs two processors".into()),
    }
}

pub(super) fn run_only_on(task: libc::pid_t, cpu: usize) -> std::io::Result<()> {
    let mut allowed: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    unsafe { libc::CPU_SET(cpu, &mut allowed) };
    if unsafe { libc::sched_setaffinity(task, size_of::<libc::cpu_set_t>(), &allowed) } == 0 {
        Ok(())
    } else {
        Err(Error::last_os_error())
    }
}

struct Setting {
    path: String,
    original: Option<String>,
}

impl Setting {
    fn change(path: String, value: &str) -> Result<Self> {
        let original = fs::read_to_string(&path)?.trim().to_owned();
        fs::write(&path, value)?;
        Ok(Self {
            path,
            original: Some(original),
        })
    }

    fn restore(&mut self) -> Result {
        if let Some(original) = &self.original {
            fs::write(&self.path, original)?;
            self.original = None;
        }
        Ok(())
    }
}

impl Drop for Setting {
    fn drop(&mut self) {
        if let Err(error) = self.restore() {
            eprintln!("could not restore {}: {error}", self.path);
        }
    }
}

pub(super) struct Occupation {
    occupier: Option<libc::pid_t>,
    settings: [Setting; 2],
}

impl Occupation {
    pub(super) fn start(cpu: usize) -> Result<Self> {
        let settings = [
            Setting::change(REAL_TIME_LIMIT.to_owned(), "-1")?,
            Setting::change(server_runtime(cpu), "0")?,
        ];
        let mut ends = [0; 2];
        if unsafe { libc::pipe2(ends.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
            return Err(Error::last_os_error().into());
        }
        let [started, announce] = ends;
        let occupier = fork_child(|| {
            let parameter = libc::sched_param {
                sched_priority: HIGHEST_REAL_TIME_PRIORITY,
            };
            if run_only_on(0, cpu).is_err()
                || unsafe { libc::sched_setscheduler(0, libc::SCHED_FIFO, &parameter) } != 0
                || unsafe { libc::write(announce, b"x".as_ptr().cast(), 1) } != 1
            {
                return 1;
            }
            loop {
                std::hint::spin_loop();
            }
        });
        assert!(occupier > 0, "{}", Error::last_os_error());
        // The occupation exists from here on, so a failure below kills the
        // occupying task when the occupation is dropped.
        let occupation = Self {
            occupier: Some(occupier),
            settings,
        };
        // The child has the only other end, so its exit ends the read.
        unsafe { libc::close(announce) };
        let mut byte = 0u8;
        let read = unsafe { libc::read(started, (&raw mut byte).cast(), 1) };
        unsafe { libc::close(started) };
        if read != 1 {
            return Err("the occupying task did not start".into());
        }
        Ok(occupation)
    }

    pub(super) fn end(mut self, supervision: &Supervision) -> Result {
        let occupier = self.occupier.take().expect("the occupation ends once");
        assert_eq!(unsafe { libc::kill(occupier, libc::SIGKILL) }, 0);
        let status = supervision.reap(occupier)?;
        assert!(
            libc::WIFSIGNALED(status) && libc::WTERMSIG(status) == libc::SIGKILL,
            "the occupying task ended by itself: {status:#x}"
        );
        self.settings.iter_mut().try_for_each(Setting::restore)
    }
}

impl Drop for Occupation {
    fn drop(&mut self) {
        if let Some(occupier) = self.occupier.take() {
            unsafe {
                libc::kill(occupier, libc::SIGKILL);
                libc::waitpid(occupier, std::ptr::null_mut(), 0);
            }
        }
    }
}
