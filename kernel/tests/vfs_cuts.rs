// SPDX-License-Identifier: GPL-2.0

use super::guest::{
    UNIX_SOCKET, counter, lasting, look_up, require_mount, require_zero, task_named, tasks_named,
    unix_options, unmount_balanced,
};
use super::server::{Behaviour, State, spawn_vfs_peer, wire_node};
use crate::supervision::{Supervision, fork_child, unix_listener};
use crate::{Result, load_module, unload_module};
use std::ffi::CString;
use std::fs::{self, File};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use voidport_proto::attr::EntryOut;
use voidport_proto::opcode::Opcode;
use zerocopy::byteorder::little_endian::U64;

const FLAPS: u64 = 8;

fn flap_node(serial: u64) -> u64 {
    100 + serial
}

/// Mount options for the unix socket, with a stall window that never ends and
/// entries and attributes that never expire, so a request reaches the peer
/// only when its name is new to the mount.
fn lasting_options() -> Result<String> {
    Ok(format!(
        "{},{}",
        unix_options(UNIX_SOCKET)?.to_str()?,
        lasting()
    ))
}

pub(crate) fn flaps() -> Result {
    fs::create_dir_all("/vfs-options")?;
    load_module()?;
    let last = FLAPS + 1;
    let state = Arc::new(State::default());
    let supervision = Supervision::new();
    let (peer, connections) =
        spawn_vfs_peer(unix_listener(UNIX_SOCKET)?, &state, last, &supervision);
    require_mount(&lasting_options()?);
    let mut files = Vec::new();
    for serial in 1..=last {
        let node = flap_node(serial);
        // Each lookup runs in a child the case reaps, so a failure of the
        // peer ends the case while a lookup waits for the reconnect.
        for name in [format!("n{node}"), format!("n0{node}")] {
            let path = CString::new(format!("/vfs-options/{name}"))?;
            let status = supervision.reap(fork_child(|| look_up(&path)))?;
            assert_eq!(status, 0, "the lookup of {name} failed");
            assert_eq!(state.lookups(serial, &name), 1, "{name}");
        }
        files.push(File::open(format!("/vfs-options/n{node}"))?);
        if serial < last {
            connections.recv()?.cut()?;
        }
    }
    assert_eq!(
        counter("connections_live")?,
        1,
        "a connection the peer cut outlived the reconnect"
    );
    assert_eq!(counter("cleanup_teardown")?, 3 * FLAPS);
    drop(files);
    state.wait(last, |events| events.released == 1)?;
    fs::write("/proc/sys/vm/drop_caches", "3")?;
    state.wait_forgotten(last, &[(flap_node(last), 2)])?;
    assert_eq!(
        counter("cleanup_teardown")?,
        3 * FLAPS,
        "a retirement ended a reference of a cut session again"
    );
    unmount_balanced(peer)?;
    assert_eq!(state.released(), 1);
    require_zero(&["connections_live"])?;
    assert_eq!(counter("nodes_admitted")?, 2 * last);
    assert_eq!(counter("handles_opened")?, last);
    assert_eq!(counter("nodes_forgotten")?, counter("nodes_admitted")?);
    // Every reference of a cut session ended with that session. The handle of
    // the last session counts as sent or as ended with its connection,
    // depending on whether its reply was read before the unmount closed the
    // connection, and the balance above counts each reference once.
    assert!(counter("cleanup_teardown")? >= 3 * FLAPS);
    assert!(counter("cleanup_sent")? >= 2);
    unload_module()?;
    println!(
        "vfs acceptance: {FLAPS} cut connections were gone after the reconnect, and only the last gave its node and handle back"
    );
    Ok(())
}

const SHARED_NODE: u64 = 42;

struct SharedNode;

impl Behaviour for SharedNode {
    fn entry(&self, _serial: u64, _opcode: Opcode, index: u64, entry: &mut EntryOut) {
        if index == SHARED_NODE {
            entry.node_id = U64::new(wire_node(1, SHARED_NODE));
        }
    }
}

pub(crate) fn shared_node() -> Result {
    fs::create_dir_all("/vfs-options")?;
    load_module()?;
    let state = Arc::new(State::with(Arc::new(SharedNode)));
    let supervision = Supervision::new();
    let (peer, connections) = spawn_vfs_peer(unix_listener(UNIX_SOCKET)?, &state, 2, &supervision);
    require_mount(&lasting_options()?);
    for (serial, names) in [(1, ["n42", "n042"]), (2, ["n0042", "n00042"])] {
        for name in names {
            let path = CString::new(format!("/vfs-options/{name}"))?;
            let status = supervision.reap(fork_child(|| look_up(&path)))?;
            assert_eq!(status, 0, "the lookup of {name} failed");
            assert_eq!(state.lookups(serial, name), 1, "{name}");
        }
        if serial == 1 {
            connections.recv()?.cut()?;
        }
    }
    assert_eq!(counter("cleanup_teardown")?, 2);
    fs::write("/proc/sys/vm/drop_caches", "3")?;
    let wire = wire_node(1, SHARED_NODE);
    state.wait(2, |events| events.forgotten.contains_key(&(2, wire)))?;
    unmount_balanced(peer)?;
    assert_eq!(counter("nodes_admitted")?, 4);
    assert_eq!(counter("nodes_forgotten")?, 4);
    assert_eq!(counter("cleanup_teardown")?, 2);
    assert_eq!(counter("cleanup_sent")?, 2);
    unload_module()?;
    println!(
        "vfs acceptance: a node admitted in two sessions gave back only the lookups of the session that lasted"
    );
    Ok(())
}

const CONNECTION_TASK: &str = "voidport-conn";

const PROBE_TASK: &str = "voidport-probe";

fn exit_of(task: libc::pid_t) -> Result<OwnedFd> {
    let descriptor = unsafe { libc::syscall(libc::SYS_pidfd_open, task, 0) };
    if descriptor < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(descriptor as i32) })
}

fn await_exit(exit: &OwnedFd) -> Result {
    let mut polled = libc::pollfd {
        fd: exit.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    if unsafe { libc::poll(&mut polled, 1, -1) } < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    assert_eq!(polled.revents & libc::POLLIN, libc::POLLIN);
    Ok(())
}

pub(crate) fn connection_threads() -> Result {
    fs::create_dir_all("/vfs-options")?;
    load_module()?;
    let state = Arc::new(State::default());
    let supervision = Supervision::new();
    let (peer, connections) = spawn_vfs_peer(unix_listener(UNIX_SOCKET)?, &state, 2, &supervision);
    require_mount(&lasting_options()?);
    let first = task_named(CONNECTION_TASK)?;
    let first_exit = exit_of(first)?;
    connections.recv()?.cut()?;
    await_exit(&first_exit)?;
    let path = CString::new("/vfs-options/a")?;
    let status = supervision.reap(fork_child(|| look_up(&path)))?;
    assert_eq!(status, 0, "the lookup over the second connection failed");
    assert_eq!(
        state.lookups(2, "a"),
        1,
        "the second connection looked a up"
    );
    task_named(PROBE_TASK)?;
    assert!(
        tasks_named(CONNECTION_TASK)?
            .iter()
            .all(|task| *task == first),
        "a thread other than the probe thread reads the second connection"
    );
    unmount_balanced(peer)?;
    require_zero(&["connections_live"])?;
    unload_module()?;
    println!(
        "vfs acceptance: the thread of the cut connection exited, and the probe thread read the next one"
    );
    Ok(())
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum Cleanup {
    Forget,
    Release,
}

fn await_hang_up(connection: &UnixStream) -> Result {
    let mut polled = libc::pollfd {
        fd: connection.as_raw_fd(),
        events: 0,
        revents: 0,
    };
    if unsafe { libc::poll(&mut polled, 1, -1) } < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    assert_eq!(polled.revents, libc::POLLHUP);
    Ok(())
}

pub(crate) fn cleanup_send_failure(cleanup: Cleanup) -> Result {
    fs::create_dir_all("/vfs-options")?;
    load_module()?;
    let state = Arc::new(State::default());
    let supervision = Supervision::new();
    let (peer, connections) = spawn_vfs_peer(unix_listener(UNIX_SOCKET)?, &state, 2, &supervision);
    require_mount(&lasting_options()?);
    let file = match cleanup {
        Cleanup::Forget => {
            fs::metadata("/vfs-options/a")?;
            None
        }
        Cleanup::Release => Some(File::open("/vfs-options/a")?),
    };
    let first = connections.recv()?.stream;
    let lost = counter("connections_lost")?;
    let teardowns = counter("cleanup_teardown")?;
    first.shutdown(std::net::Shutdown::Read)?;
    match cleanup {
        Cleanup::Forget => fs::write("/proc/sys/vm/drop_caches", "3")?,
        Cleanup::Release => drop(file),
    }
    await_hang_up(&first)?;
    let other = CString::new("/vfs-options/b")?;
    let status = supervision.reap(fork_child(|| look_up(&other)))?;
    assert_eq!(status, 0, "the lookup over the second connection failed");
    assert_eq!(
        state.lookups(2, "b"),
        1,
        "the second connection looked up b"
    );
    // The lookup over the second connection has waited until the first
    // connection was lost, which the module counts once.
    assert_eq!(counter("connections_lost")?, lost + 1);
    drop(first);
    unmount_balanced(peer)?;
    require_zero(&["connections_live"])?;
    assert!(counter("cleanup_teardown")? > teardowns);
    assert_eq!(state.released(), 0, "a connection received the RELEASE");
    assert_eq!(state.forgotten(1, 1), 0, "a connection received the FORGET");
    unload_module()?;
    println!(
        "vfs acceptance: a {cleanup:?} whose send failed ended its connection, and the next one was in use"
    );
    Ok(())
}
