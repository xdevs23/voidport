use std::os::fd::AsFd;
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::process::Child;

use rustix::event::{PollFd, PollFlags, poll};
use rustix::net::RecvFlags;
use rustix::process::{Pid, PidfdFlags, pidfd_open};
use sd_notify::NotifyState;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Startup {
    Ready,
    Exited,
}

#[derive(Debug)]
pub struct ReadinessSocket {
    path: PathBuf,
    socket: UnixDatagram,
}

impl ReadinessSocket {
    #[must_use]
    pub fn bind(path: PathBuf) -> Self {
        let socket = UnixDatagram::bind(&path)
            .unwrap_or_else(|error| panic!("binding {}: {error}", path.display()));
        Self { path, socket }
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[must_use]
    pub fn wait_for(&self, child: &Child) -> Startup {
        let exited = pidfd_open(Pid::from_child(child), PidfdFlags::empty())
            .expect("a pidfd of the started child");
        self.wait(exited)
    }

    /// A report sent before the exit is received first.
    #[must_use]
    pub fn wait(&self, exited: impl AsFd) -> Startup {
        loop {
            let mut events = [
                PollFd::new(&self.socket, PollFlags::IN),
                PollFd::new(&exited, PollFlags::IN),
            ];
            poll(&mut events, None).expect("waiting on readiness and exit");
            if events[0].revents().contains(PollFlags::IN) {
                if self.receive_ready() {
                    return Startup::Ready;
                }
            } else {
                return Startup::Exited;
            }
        }
    }

    /// The length of the datagram is read before the datagram, so a report of any
    /// length is received whole.
    fn receive_ready(&self) -> bool {
        let (_, length) = rustix::net::recv(
            &self.socket,
            &mut [0_u8; 0],
            RecvFlags::PEEK | RecvFlags::TRUNC,
        )
        .expect("the length of a readiness report");
        let mut report = vec![0_u8; length];
        rustix::net::recv(&self.socket, report.as_mut_slice(), RecvFlags::empty())
            .expect("a readiness report");
        let ready = NotifyState::Ready.to_string();
        report
            .split(|byte| *byte == b'\n')
            .any(|line| line == ready.as_bytes())
    }
}
