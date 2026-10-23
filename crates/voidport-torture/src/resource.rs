//! A sample that could not be taken is `None`, and an invariant over a
//! quantity that was never sampled is skipped, not failed.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use voidport_control::{Client, Reply, Request, Response};

/// A run that restarts the server watches a different process after every
/// restart, so the pid is a shared cell. Zero means there is no server right
/// now: a sample taken during a restart reports nothing, where a stale pid
/// would report a dead or reused process.
#[derive(Clone, Debug, Default)]
pub struct ServerPid(Arc<AtomicU32>);

impl ServerPid {
    #[must_use]
    pub fn new(pid: u32) -> Self {
        Self(Arc::new(AtomicU32::new(pid)))
    }

    pub fn set(&self, pid: u32) {
        self.0.store(pid, Ordering::Relaxed);
    }

    pub fn clear(&self) {
        self.0.store(0, Ordering::Relaxed);
    }

    #[must_use]
    pub fn get(&self) -> Option<u32> {
        match self.0.load(Ordering::Relaxed) {
            0 => None,
            pid => Some(pid),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct Sample {
    pub elapsed_ms: u64,
    pub fds: Option<u64>,
    pub threads: Option<u64>,
    pub rss_kib: Option<u64>,
    pub sessions: Option<u64>,
    pub nodes: Option<u64>,
    pub handles: Option<u64>,
    pub node_descriptors: Option<u64>,
    pub node_descriptor_budget: Option<u64>,
}

#[derive(Clone, Debug, Default)]
pub struct Probe {
    pub pid: Option<ServerPid>,
    pub control_socket: Option<PathBuf>,
}

impl Probe {
    #[must_use]
    pub fn sample(&self, elapsed_ms: u64) -> Sample {
        let process = self
            .pid
            .as_ref()
            .and_then(ServerPid::get)
            .map(|pid| PathBuf::from(format!("/proc/{pid}")));
        let (sessions, nodes, handles) = self.sessions().unwrap_or((None, None, None));
        let (node_descriptors, node_descriptor_budget) =
            self.descriptor_cache().unwrap_or((None, None));
        Sample {
            elapsed_ms,
            fds: process.as_deref().and_then(descriptors),
            threads: process.as_deref().and_then(|path| status(path, "Threads:")),
            rss_kib: process.as_deref().and_then(|path| status(path, "VmRSS:")),
            sessions,
            nodes,
            handles,
            node_descriptors,
            node_descriptor_budget,
        }
    }

    /// `/proc/<pid>/fd` does not show which descriptor is a node cache slot, so
    /// the counter of the server is the only view that can assert the budget.
    fn descriptor_cache(&self) -> Option<(Option<u64>, Option<u64>)> {
        let socket = self.control_socket.as_deref()?;
        let mut client = Client::connect(socket).ok()?;
        let answer = client.call(&Request::ServerInfo {}).ok()?;
        let Response::Ok {
            result:
                Reply::ServerInfo {
                    node_descriptors,
                    node_descriptor_budget,
                    ..
                },
        } = answer.response
        else {
            return None;
        };
        Some((
            Some(node_descriptors as u64),
            Some(node_descriptor_budget as u64),
        ))
    }

    fn sessions(&self) -> Option<(Option<u64>, Option<u64>, Option<u64>)> {
        let socket = self.control_socket.as_deref()?;
        let mut client = Client::connect(socket).ok()?;
        let answer = client.call(&Request::SessionList {}).ok()?;
        let Response::Ok {
            result: Reply::SessionList { sessions },
        } = answer.response
        else {
            return None;
        };
        let nodes = sessions.iter().map(|session| session.nodes as u64).sum();
        let handles = sessions.iter().map(|session| session.handles as u64).sum();
        Some((Some(sessions.len() as u64), Some(nodes), Some(handles)))
    }
}

fn descriptors(process: &Path) -> Option<u64> {
    Some(fs::read_dir(process.join("fd")).ok()?.count() as u64)
}

fn status(process: &Path, field: &str) -> Option<u64> {
    fs::read_to_string(process.join("status"))
        .ok()?
        .lines()
        .find_map(|line| {
            line.strip_prefix(field)?
                .split_whitespace()
                .next()?
                .parse()
                .ok()
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_probe_reads_the_process_it_is_pointed_at() {
        let probe = Probe {
            pid: Some(ServerPid::new(std::process::id())),
            control_socket: None,
        };
        let sample = probe.sample(1234);
        assert_eq!(sample.elapsed_ms, 1234);
        assert!(sample.fds.is_some_and(|fds| fds > 0));
        assert!(sample.threads.is_some_and(|threads| threads > 0));
        assert!(sample.rss_kib.is_some_and(|rss| rss > 0));
        assert_eq!(sample.nodes, None, "no control socket, no session view");
        assert_eq!(
            (sample.node_descriptors, sample.node_descriptor_budget),
            (None, None),
            "no control socket, no view of the descriptor cache"
        );
    }

    #[test]
    fn a_probe_with_nothing_to_look_at_samples_nothing() {
        let sample = Probe::default().sample(0);
        assert_eq!(sample, Sample::default());
        assert_eq!(descriptors(Path::new("/proc/nonexistent-pid")), None);
        assert_eq!(status(Path::new("/proc/nonexistent-pid"), "VmRSS:"), None);
    }

    #[test]
    fn a_cleared_pid_samples_no_process_quantities() {
        let pid = ServerPid::new(std::process::id());
        let probe = Probe {
            pid: Some(pid.clone()),
            control_socket: None,
        };
        assert!(probe.sample(0).fds.is_some());

        pid.clear();
        assert_eq!(pid.get(), None);
        let during = probe.sample(1);
        assert_eq!(
            (during.fds, during.threads, during.rss_kib),
            (None, None, None)
        );

        pid.set(std::process::id());
        assert!(probe.sample(2).fds.is_some());
    }
}
