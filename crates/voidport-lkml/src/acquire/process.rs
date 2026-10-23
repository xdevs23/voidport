use rustix::process::{Pid, PidfdFlags, pidfd_open};
use std::{
    io,
    os::fd::OwnedFd,
    process::{Child, ExitStatus},
};
use tokio::io::{Interest, unix::AsyncFd};

pub(super) struct Process {
    child: Child,
    /// Becomes readable once the child has exited.
    exited: AsyncFd<OwnedFd>,
}
impl Process {
    pub(super) fn new(mut child: Child) -> io::Result<Self> {
        match watch(&child) {
            Ok(exited) => Ok(Self { child, exited }),
            Err(error) => {
                let _killed = child.kill();
                let _reaped = child.wait();
                Err(error)
            }
        }
    }
    pub(super) async fn wait(&mut self) -> io::Result<ExitStatus> {
        let _ready = self.exited.readable().await?;
        self.child.wait()
    }
    pub(super) fn kill(&mut self) -> io::Result<()> {
        self.child.kill()
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        // Both succeed without effect for a child that was already waited for.
        let _killed = self.child.kill();
        let _reaped = self.child.wait();
    }
}

fn watch(child: &Child) -> io::Result<AsyncFd<OwnedFd>> {
    let pidfd = pidfd_open(Pid::from_child(child), PidfdFlags::empty())?;
    AsyncFd::with_interest(pidfd, Interest::READABLE)
}
