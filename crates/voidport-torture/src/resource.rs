//! What the server is holding, sampled once a second.
//!
//! A leak is the failure mode a load generator is uniquely able to find, and it
//! is invisible in throughput: the run looks healthy right up to the point
//! where the process runs out of descriptors or memory. So five quantities are
//! sampled throughout and bounded relative to the working set:
//!
//! * **descriptors** — the server holds one per open handle, one per graft, and
//!   at most its budget for the node cache, so this is where an unreleased
//!   handle or a slot the cache never gave back shows;
//! * **cache-resident node descriptors** — the server's own counter, read from
//!   the control plane beside its budget. `/proc/<pid>/fd` counts descriptors
//!   but cannot say which of them is a node's cache slot and which is a
//!   handle's, so this is the only view that can assert the budget at all;
//! * **threads** — the property the async lock waits bought. Hundreds of
//!   stacked waiters must cost bytes, and a thread count that tracks the
//!   waiter count is the shape of the hole they closed;
//! * **nodes and handles** — the server's own accounting, read from the
//!   control plane's session view, which is the only view that distinguishes
//!   "the guest is holding a lot" from "the server forgot to let go";
//! * **resident memory** — the coarse backstop under all of it.
//!
//! Everything here reads `/proc` and the control socket, and everything here
//! tolerates being unable to: a sample that could not be taken is `None`, and
//! an invariant over a quantity that was never sampled is skipped, not
//! failed.

use std::fs;
use std::path::{Path, PathBuf};

use voidport_control::{Client, Reply, Request, Response};

/// One sample of what the server holds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct Sample {
    /// Milliseconds since the run started.
    pub elapsed_ms: u64,
    /// Open descriptors in the server process.
    pub fds: Option<u64>,
    /// Threads in the server process.
    pub threads: Option<u64>,
    /// Resident set size, in kibibytes.
    pub rss_kib: Option<u64>,
    /// Live data-plane sessions.
    pub sessions: Option<u64>,
    /// Nodes held across every session.
    pub nodes: Option<u64>,
    /// Handles held open across every session.
    pub handles: Option<u64>,
    /// Node descriptors the server's cache holds resident, server-wide.
    pub node_descriptors: Option<u64>,
    /// The bound that count is held under. Startup-only, so it is the same
    /// number in every sample of a run.
    pub node_descriptor_budget: Option<u64>,
}

/// Where the sampler looks.
#[derive(Clone, Debug, Default)]
pub struct Probe {
    /// The server process, if the harness was told which it is. Absent means
    /// the process-level quantities are simply not sampled.
    pub pid: Option<u32>,
    /// The server's control socket, for the session view.
    pub control_socket: Option<PathBuf>,
}

impl Probe {
    /// Takes one sample.
    #[must_use]
    pub fn sample(&self, elapsed_ms: u64) -> Sample {
        let process = self.pid.map(|pid| PathBuf::from(format!("/proc/{pid}")));
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

    /// The server's own view of its node descriptor cache: what it holds, and
    /// the bound it holds it under.
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

    /// The control plane's session view, as three totals.
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

/// How many descriptors a process holds.
fn descriptors(process: &Path) -> Option<u64> {
    Some(fs::read_dir(process.join("fd")).ok()?.count() as u64)
}

/// A numeric field of `/proc/<pid>/status`, in whatever unit it states.
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

    /// The sampler is pointed at this very process, which is a real one: it has
    /// descriptors, threads and a resident set, and no control socket.
    #[test]
    fn a_probe_reads_the_process_it_is_pointed_at() {
        let probe = Probe {
            pid: Some(std::process::id()),
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

    /// A sampler pointed at nothing samples nothing, instead of inventing a
    /// zero an invariant would then compare against.
    #[test]
    fn a_probe_with_nothing_to_look_at_samples_nothing() {
        let sample = Probe::default().sample(0);
        assert_eq!(sample, Sample::default());
        assert_eq!(descriptors(Path::new("/proc/nonexistent-pid")), None);
        assert_eq!(status(Path::new("/proc/nonexistent-pid"), "VmRSS:"), None);
    }
}
