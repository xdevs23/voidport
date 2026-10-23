// SPDX-License-Identifier: GPL-2.0

use super::guest::{
    CLEANUP_TASK, Probe, SIGUSR1_HANDLED, TRACING, count_sigusr1, counter, endless_stall, field,
    lasting, require_balanced, require_mount, require_zero, unmount_balanced,
    unmount_without_peer_end,
};
use super::server::{Behaviour, Flow, Rendezvous, State, Stream, send, serve_one};
use super::writable::{FIRST_FILE, Held, Peer, mount, path, pattern, unmount};
use crate::supervision::{Supervision, fork_child};
use crate::{Result, load_module, unload_module};
use std::ffi::{CStr, CString};
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::net::{Ipv4Addr, TcpListener};
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use voidport_proto::frame::Frame;
use voidport_proto::opcode::Opcode;
use voidport_proto::ops::node::LookupRequest;

#[derive(Clone, Copy, Debug)]
pub(crate) enum Case {
    SignalPartial,
    KillPartial,
    FrameInParts,
    CloseFrame,
}

const STOP: &str = "stop-reading";

#[derive(Default)]
struct Stop {
    resumed: Rendezvous<bool>,
}

impl Stop {
    fn resume(&self) {
        self.resumed.update(|resumed| *resumed = true);
    }
}

impl Behaviour for Stop {
    fn deliver(
        &self,
        _state: &State,
        _serial: u64,
        frame: &Frame<'_>,
        reply: Vec<u8>,
        stream: &mut dyn Stream,
    ) -> Result<Flow> {
        send(stream, &reply)?;
        let stops = frame.opcode()? == Opcode::Lookup
            && frame.request::<LookupRequest>()?.name() == STOP.as_bytes();
        if stops {
            self.resumed.wait(|resumed| *resumed)?;
        }
        Ok(Flow::Next)
    }

    fn ended(&self) {
        self.resumed.end();
    }
}

const TCP_WMEM: &str = "/proc/sys/net/ipv4/tcp_wmem";

/// One send buffer size for the TCP sockets of a case. It is several times
/// the size of the least receive buffer of the peer, so a send that waits for
/// room goes on waiting until the peer reads, and a small part of what the
/// forgets of a case need.
const SEND_BUFFER: &str = "16384 16384 16384";

const FORGETS: u64 = 2048;

const FIRST_NODE: u64 = 6000;

const UNMOUNT_TASK: &str = "unmounting";

const WRITE_TASK: &str = "partial-write";

/// The bytes the signal case writes: many times the size of the send buffer
/// of the module and the receive buffer of the peer together, so the send of
/// the write waits for room inside its frame.
const WRITTEN: u64 = 1 << 20;

/// A loopback TCP listener whose connections receive into the least buffer
/// the kernel allows, so the requests to a peer that stops reading remain in
/// the send buffer of the module.
fn small_listener() -> Result<TcpListener> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    // The kernel raises the size to its least, and the connections the
    // listener accepts inherit it.
    let size: libc::c_int = 1;
    let set = unsafe {
        libc::setsockopt(
            listener.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            (&raw const size).cast(),
            size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    assert_eq!(set, 0, "{}", std::io::Error::last_os_error());
    Ok(listener)
}

const SEND_WAIT: &str = "vfs_options/send_wait";

const DRAIN_WAIT: &str = "vfs_options/drain_wait";

struct Waits {
    // The pipe is dropped before the probe, which cannot be removed while the
    // pipe is open.
    pipe: BufReader<File>,
    _probe: Probe,
}

impl Waits {
    fn record(name: &'static str, definition: &str) -> Result<Self> {
        let probe = Probe::define(name, definition)?;
        let pipe = File::open(format!("{TRACING}/trace_pipe"))?;
        Ok(Self {
            pipe: BufReader::new(pipe),
            _probe: probe,
        })
    }

    fn next(&mut self, prefix: &str) -> Result<String> {
        loop {
            let mut line = String::new();
            if self.pipe.read_line(&mut line)? == 0 {
                return Err("the trace pipe ended".into());
            }
            let task = field(&line, "task")?;
            if task.starts_with(prefix) {
                return Ok(task.to_owned());
            }
        }
    }
}

fn named_write(task: &CStr, path: &CStr, data: &[u8]) -> libc::c_int {
    if unsafe { libc::prctl(libc::PR_SET_NAME, task.as_ptr()) } != 0 || !count_sigusr1() {
        return 1;
    }
    let file = unsafe { libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC) };
    if file < 0 {
        return 1;
    }
    let written = unsafe { libc::write(file, data.as_ptr().cast(), data.len()) };
    let whole = usize::try_from(written).is_ok_and(|written| written == data.len());
    if whole && SIGUSR1_HANDLED.load(Ordering::Relaxed) == 1 {
        0
    } else {
        1
    }
}

fn named_unmount(task: &CStr) -> libc::c_int {
    if unsafe { libc::prctl(libc::PR_SET_NAME, task.as_ptr()) } != 0 {
        return 1;
    }
    unmount_without_peer_end()
}

fn look_up_and_stop() -> Result {
    for index in 0..FORGETS {
        fs::metadata(format!("/vfs-options/n{}", FIRST_NODE + index))?;
    }
    let stopped = fs::metadata(format!("/vfs-options/{STOP}"));
    assert_eq!(stopped.unwrap_err().raw_os_error(), Some(libc::ENOENT));
    Ok(())
}

fn reclaim_until_a_send_waits() -> Result {
    let mut waits = Waits::record(SEND_WAIT, "sk_stream_wait_memory task=$comm")?;
    fs::write("/proc/sys/vm/drop_caches", "3")?;
    let waiting = waits.next(CLEANUP_TASK)?;
    println!("vfs acceptance: the send of a forget by {waiting} waits for room");
    Ok(())
}

fn frame_in_parts(stop: &Stop, state: &State, peer: std::thread::JoinHandle<Result>) -> Result {
    let lost = counter("connections_lost")?;
    stop.resume();
    state.wait(1, |events| events.forgotten.len() == FORGETS as usize)?;
    assert_eq!(counter("connections_lost")?, lost);
    unmount_balanced(peer)
}

fn close_frame(stop: &Stop, peer: std::thread::JoinHandle<Result>) -> Result {
    let mut drains = Waits::record(DRAIN_WAIT, "wait_for_completion_killable task=$comm")?;
    let task = CString::new(UNMOUNT_TASK)?;
    let child = fork_child(|| named_unmount(&task));
    // The close records the end of the connection, and the unmount then waits
    // for the thread of the connection, which waits for the peer.
    drains.next(UNMOUNT_TASK)?;
    drop(drains);
    let exited = unsafe { libc::waitpid(child, std::ptr::null_mut(), libc::WNOHANG) };
    assert_eq!(exited, 0, "the unmount returned before its close");
    stop.resume();
    assert_eq!(Supervision::new().reap(child)?, 0, "the unmount");
    peer.join().map_err(|_| "the peer panicked")??;
    require_zero(&["connections_live"])?;
    require_balanced()
}

fn signal_partial() -> Result {
    let lost = counter("connections_lost")?;
    let cancelled = counter("cancelled")?;
    let peer = Peer::new(vec![Held::new("file", libc::S_IFREG | 0o644, vec![])]);
    // The peer receives into the default buffer. The window of the least one
    // is smaller than the segments the module builds, and the kernel then
    // sends the bytes one window at a time, each when its probe timer fires.
    let session = mount(&peer, "")?;
    let task = CString::new(WRITE_TASK)?;
    let file = CString::new(path("file"))?;
    let data = pattern(1, 0..WRITTEN);
    peer.stop_at_data();
    let mut waits = Waits::record(SEND_WAIT, "sk_stream_wait_memory task=$comm")?;
    let writer = fork_child(|| named_write(&task, &file, &data));
    peer.wait_stopped()?;
    waits.next(WRITE_TASK)?;
    drop(waits);
    assert_eq!(unsafe { libc::kill(writer, libc::SIGUSR1) }, 0);
    peer.resume();
    assert_eq!(
        Supervision::new().reap(writer)?,
        0,
        "the write after the signal"
    );
    assert!(peer.content(FIRST_FILE) == data, "the peer has other bytes");
    let absent = fs::metadata(path("absent"));
    assert_eq!(absent.unwrap_err().raw_os_error(), Some(libc::ENOENT));
    assert_eq!(counter("connections_lost")?, lost);
    assert_eq!(counter("cancelled")?, cancelled);
    unmount(session)
}

fn kill_partial() -> Result {
    let cancelled = counter("cancelled")?;
    let peer = Peer::new(vec![Held::new("file", libc::S_IFREG | 0o644, vec![])]);
    let session = mount(&peer, "")?;
    let task = CString::new(WRITE_TASK)?;
    let file = CString::new(path("file"))?;
    let data = pattern(1, 0..WRITTEN);
    peer.stop_at_data();
    let mut waits = Waits::record(SEND_WAIT, "sk_stream_wait_memory task=$comm")?;
    let writer = fork_child(|| named_write(&task, &file, &data));
    peer.wait_stopped()?;
    waits.next(WRITE_TASK)?;
    drop(waits);
    Supervision::new().kill_and_reap(writer, "the write")?;
    assert_eq!(counter("cancelled")?, cancelled + 1);
    peer.resume();
    unmount(session)?;
    assert!(
        peer.content(FIRST_FILE).is_empty(),
        "the peer applied a cut write"
    );
    Ok(())
}

fn stopped_forgets(case: Case) -> Result {
    let stop = Arc::new(Stop::default());
    let state = Arc::new(State::with(stop.clone()));
    let listener = small_listener()?;
    let port = listener.local_addr()?.port();
    let peer = serve_one(listener, &state);
    require_mount(&format!(
        "addr=127.0.0.1,port={port},{},{}",
        lasting(),
        endless_stall()
    ));
    look_up_and_stop()?;
    reclaim_until_a_send_waits()?;
    if let Case::CloseFrame = case {
        close_frame(&stop, peer)
    } else {
        frame_in_parts(&stop, &state, peer)
    }
}

pub(crate) fn run(case: Case) -> Result {
    fs::create_dir_all("/vfs-options")?;
    load_module()?;
    let send_buffer = fs::read_to_string(TCP_WMEM)?;
    fs::write(TCP_WMEM, SEND_BUFFER)?;
    match case {
        Case::SignalPartial => signal_partial()?,
        Case::KillPartial => kill_partial()?,
        Case::FrameInParts | Case::CloseFrame => stopped_forgets(case)?,
    }
    fs::write(TCP_WMEM, send_buffer)?;
    unload_module()?;
    println!("vfs acceptance: {case:?} against a peer that stopped reading");
    Ok(())
}
