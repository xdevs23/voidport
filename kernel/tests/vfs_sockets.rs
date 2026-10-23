// SPDX-License-Identifier: GPL-2.0

use super::guest::{
    UNIX_SOCKET, count_sigusr1, endless_stall, errno, look_up, mount, mount_with, read_back,
    require_mount, require_zero, unix_options, unmount_without_peer_end,
};
use super::server::{
    Behaviour, Flow, LateRelease, Opened, State, Stream, serve, serve_one, spawn_vfs_peer,
};
use crate::supervision::{
    Connection, Decoy, Failure, Listener, Supervision, clear_socket_path, failure_of, fork_child,
    unix_listener,
};
use crate::{Result, eof, load_module, unload_module};
use std::ffi::{CStr, CString};
use std::fs::{self, File};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::process::Command;
use std::sync::Arc;
use std::sync::mpsc::Receiver;

const JAIL: &str = "/vfs-jail";

fn unix_path_max() -> usize {
    unsafe { std::mem::zeroed::<libc::sockaddr_un>() }
        .sun_path
        .len()
}

/// A listener at a path that fills a unix socket address, with no byte left
/// for a terminator. The standard library rejects such a path, so the address
/// is passed in socket address storage, as the kernel's own system calls pass
/// it, which leaves the kernel the byte after the path to terminate it in.
fn full_unix_listener(path: &str) -> Result<UnixListener> {
    clear_socket_path(path)?;
    let raw = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if raw < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let listener = unsafe { UnixListener::from_raw_fd(raw) };
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    storage.ss_family = libc::AF_UNIX as libc::sa_family_t;
    let offset = std::mem::offset_of!(libc::sockaddr_un, sun_path);
    let bytes = path.as_bytes();
    assert!(offset + bytes.len() < size_of::<libc::sockaddr_storage>());
    unsafe {
        std::ptr::copy_nonoverlapping(
            bytes.as_ptr(),
            (&raw mut storage).cast::<u8>().add(offset),
            bytes.len(),
        )
    };
    let len = libc::socklen_t::try_from(offset + bytes.len())?;
    if unsafe { libc::bind(raw, (&raw const storage).cast(), len) } != 0
        || unsafe { libc::listen(raw, libc::SOMAXCONN) } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(listener)
}

fn unix_full_path() -> Result {
    let directory = "/vfs-unix/";
    let path = format!(
        "{directory}{}",
        "f".repeat(unix_path_max() - directory.len())
    );
    let listener = full_unix_listener(&path)?;
    let late = Arc::new(LateRelease::default());
    let state = Arc::new(State::with(late.clone()));
    let serving = state.clone();
    let (freed, socket_freed) = std::sync::mpsc::channel();
    let peer = std::thread::spawn(move || -> Result {
        let (stream, _) = listener.accept()?;
        let mut end = stream.try_clone()?;
        serve(stream, 1, serving)?;
        // The peer reads the end of file only after the module freed its
        // socket. A unix socket freed with the RELEASE reply unread would reset
        // instead, so the module must read the reply first.
        end.shutdown(std::net::Shutdown::Write)?;
        socket_freed.recv()?;
        eof(&mut end)
    });
    require_mount(&format!("unix={path},reconnect_stall=0"));
    assert_eq!(fs::read("/vfs-options/a")?, b"old");
    late.wait_releases(1)?;
    assert_eq!(unsafe { libc::umount(c"/vfs-options".as_ptr()) }, 0);
    require_zero(&["connections_live"])?;
    freed.send(())?;
    peer.join().map_err(|_| "unix socket peer failed")??;
    assert_eq!(mount(&format!("unix={path}f"), false), -1);
    assert_eq!(errno(), libc::EINVAL);
    println!(
        "vfs acceptance: mount over a unix socket path of {} bytes served, one more failed",
        path.len()
    );
    Ok(())
}

pub(crate) fn unix() -> Result {
    fs::create_dir_all("/vfs-options")?;
    load_module()?;
    let listener = unix_listener(UNIX_SOCKET)?;
    let state = Arc::new(State::default());
    let peer = serve_one(listener, &state);
    mount_unix();
    assert_eq!(fs::read("/vfs-options/a")?, b"old");
    assert_eq!(mount(&format!("unix={UNIX_SOCKET}"), true), 0);
    for change in ["unix=/vfs-unix/other.sock", "addr=127.0.0.1", "port=1234"] {
        assert_eq!(mount(change, true), -1, "{change}");
        assert_eq!(errno(), libc::EINVAL, "{change}");
    }
    assert_eq!(unsafe { libc::umount(c"/vfs-options".as_ptr()) }, 0);
    peer.join().map_err(|_| "unix socket peer failed")??;
    println!(
        "vfs acceptance: mount over the unix socket {UNIX_SOCKET} served with the same endpoint"
    );
    unix_full_path()?;
    unload_module()
}

pub(crate) fn unmount_wait() -> Result {
    fs::create_dir_all("/vfs-options")?;
    unmount_fatal_signal()?;
    unmount_handled_signal()?;
    unmount_reset()?;
    unmount_exiting_task()
}

fn holding_peer(
    listener: impl Listener,
) -> Result<(Arc<LateRelease>, std::thread::JoinHandle<Result>)> {
    load_module()?;
    let late = Arc::new(LateRelease::holding());
    let state = Arc::new(State::with(late.clone()));
    let peer = serve_one(listener, &state);
    Ok((late, peer))
}

fn release_peer(late: &LateRelease, peer: std::thread::JoinHandle<Result>) -> Result {
    late.release_end();
    peer.join().map_err(|_| "unix socket peer failed")?
}

fn mount_unix() {
    require_mount(&format!("unix={UNIX_SOCKET},reconnect_stall=0"));
}

fn unmount_fatal_signal() -> Result {
    let (late, peer) = holding_peer(unix_listener(UNIX_SOCKET)?)?;
    mount_unix();
    let child = fork_child(unmount_without_peer_end);
    late.wait_end()?;
    // A killed task does not return to user space, so the unmount cannot
    // have returned to the child before the kill.
    Supervision::new().kill_and_reap(child, "the unmount")?;
    require_zero(&["connections_live", "requests_in_flight", "replies_live"])?;
    release_peer(&late, peer)?;
    unload_module()?;
    println!("vfs acceptance: a fatal signal ended the unmount while the peer left its end open");
    Ok(())
}

fn unmount_handled_signal() -> Result {
    let (late, peer) = holding_peer(unix_listener(UNIX_SOCKET)?)?;
    mount_unix();
    assert_eq!(fs::read("/vfs-options/a")?, b"old");
    late.wait_releases(1)?;
    let child = fork_child(|| {
        if !count_sigusr1() {
            return 1;
        }
        unmount_without_peer_end()
    });
    late.wait_end()?;
    assert_eq!(unsafe { libc::kill(child, libc::SIGUSR1) }, 0);
    release_peer(&late, peer)?;
    assert_eq!(
        Supervision::new().reap(child)?,
        0,
        "the unmount with a handled signal failed"
    );
    unload_module()?;
    println!("vfs acceptance: a handled signal left the unmount waiting for the server");
    Ok(())
}

fn unmount_reset() -> Result {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let port = listener.local_addr()?.port();
    // The connection the listener accepts inherits its linger time.
    let linger = libc::linger {
        l_onoff: 1,
        l_linger: 0,
    };
    let set = unsafe {
        libc::setsockopt(
            listener.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_LINGER,
            (&raw const linger).cast(),
            size_of::<libc::linger>() as libc::socklen_t,
        )
    };
    assert_eq!(set, 0, "{}", std::io::Error::last_os_error());
    let (late, peer) = holding_peer(listener)?;
    require_mount(&format!("addr=127.0.0.1,port={port},reconnect_stall=0"));
    let child = fork_child(unmount_without_peer_end);
    late.wait_end()?;
    release_peer(&late, peer)?;
    assert_eq!(
        Supervision::new().reap(child)?,
        0,
        "the unmount at a reset failed"
    );
    require_zero(&["connections_live"])?;
    unload_module()?;
    println!("vfs acceptance: a reset by the peer ended the wait of the unmount");
    Ok(())
}

fn unmount_exiting_task() -> Result {
    let (late, peer) = holding_peer(unix_listener(UNIX_SOCKET)?)?;
    let options = CString::new(format!("unix={UNIX_SOCKET},reconnect_stall=0"))?;
    let child = fork_child(|| {
        if unsafe { libc::unshare(libc::CLONE_NEWNS) } != 0
            || unsafe {
                libc::mount(
                    std::ptr::null(),
                    c"/".as_ptr(),
                    std::ptr::null(),
                    libc::MS_REC | libc::MS_PRIVATE,
                    std::ptr::null(),
                )
            } != 0
        {
            return 1;
        }
        mount_with(&options)
    });
    assert_eq!(
        Supervision::new().reap(child)?,
        0,
        "the mount in a new mount namespace failed"
    );
    require_zero(&["connections_live", "requests_in_flight", "replies_live"])?;
    release_peer(&late, peer)?;
    unload_module()?;
    println!("vfs acceptance: the exit of the last task of a mount namespace closed at once");
    Ok(())
}

pub(super) fn read_across_reconnect(
    mounted: &str,
    first: &Receiver<Opened<impl Connection>>,
    state: &State,
    supervision: &Supervision,
) -> Result {
    let looked_up = CString::new(format!("{mounted}/a"))?;
    let status = supervision.reap(fork_child(|| look_up(&looked_up)))?;
    assert_eq!(status, 0, "the lookup over the first connection failed");
    assert_eq!(state.lookups(1, "a"), 1);
    first.recv()?.cut()?;
    let reread = CString::new(format!("{mounted}/b"))?;
    let status = supervision.reap(fork_child(|| read_back(&reread, b"old")))?;
    assert_eq!(status, 0, "the read after the reconnect failed");
    assert_eq!(state.lookups(2, "b"), 1, "the reconnect served the read");
    Ok(())
}

pub(crate) fn unix_chroot() -> Result {
    load_module()?;
    let listener = unix_listener(UNIX_SOCKET)?;
    let decoy_path = format!("{JAIL}{UNIX_SOCKET}");
    let decoy = unix_listener(&decoy_path)?;
    let mounted = format!("{JAIL}/vfs-options");
    fs::create_dir_all(&mounted)?;
    let state = Arc::new(State::default());
    let supervision = Supervision::new();
    let (peer, first) = spawn_vfs_peer(listener, &state, 2, &supervision);
    let decoy = Decoy::watch(decoy, "the socket inside the changed root", &supervision);
    // A child makes the mount from the changed root.
    let jail = CString::new(JAIL)?;
    let options = unix_options(UNIX_SOCKET)?;
    let child = fork_child(|| {
        if unsafe { libc::chroot(jail.as_ptr()) } != 0 || unsafe { libc::chdir(c"/".as_ptr()) } != 0
        {
            1
        } else {
            mount_with(&options)
        }
    });
    let status = supervision.reap(child)?;
    assert_eq!(status, 0, "the mount from the changed root failed");
    read_across_reconnect(&mounted, &first, &state, &supervision)?;
    assert_eq!(unsafe { libc::umount(CString::new(mounted)?.as_ptr()) }, 0);
    peer.join().map_err(|_| "unix socket peer failed")??;
    unload_module()?;
    decoy.stop(UnixStream::connect(&decoy_path)?, &supervision)?;
    println!(
        "vfs acceptance: mount from a changed root reached {UNIX_SOCKET} in the kernel's root on the first dial and the reconnect"
    );
    Ok(())
}

/// Runs `setup` on a thread that has moved into a new network namespace, and
/// returns what `setup` returns with a file that refers to the namespace. The
/// namespace exists while that file or a socket that `setup` made is open, so
/// it exists after the thread has exited too.
pub(super) fn in_new_network<T: Send + 'static>(
    setup: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<(T, File)> {
    std::thread::spawn(move || {
        if unsafe { libc::unshare(libc::CLONE_NEWNET) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok((setup()?, File::open("/proc/thread-self/ns/net")?))
    })
    .join()
    .map_err(|_| "the thread that made the namespace failed")?
}

fn listen_on_loopback(port: u16) -> Result<TcpListener> {
    if !Command::new("/bin/ip")
        .args(["link", "set", "lo", "up"])
        .status()?
        .success()
    {
        return Err("the new namespace's loopback did not come up".into());
    }
    Ok(TcpListener::bind((Ipv4Addr::LOCALHOST, port))?)
}

pub(super) fn mount_in_network(
    network: &File,
    options: &CStr,
    supervision: &Supervision,
) -> Result<libc::c_int> {
    let namespace = network.as_raw_fd();
    let child = fork_child(|| {
        if unsafe { libc::setns(namespace, libc::CLONE_NEWNET) } != 0 {
            1
        } else {
            mount_with(options)
        }
    });
    supervision.reap(child)
}

pub(super) fn require_mount_in_network(
    network: &File,
    options: &CStr,
    supervision: &Supervision,
) -> Result {
    let status = mount_in_network(network, options, supervision)?;
    assert_eq!(status, 0, "the mount from the new network namespace failed");
    Ok(())
}

pub(crate) fn netns() -> Result {
    fs::create_dir_all("/vfs-options")?;
    load_module()?;
    let decoy = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let port = decoy.local_addr()?.port();
    let (listener, network) = in_new_network(move || listen_on_loopback(port))?;
    let state = Arc::new(State::default());
    let supervision = Supervision::new();
    let (peer, first) = spawn_vfs_peer(listener, &state, 2, &supervision);
    let decoy = Decoy::watch(
        decoy,
        "the decoy in the initial network namespace",
        &supervision,
    );
    let options = CString::new(format!("addr=127.0.0.1,port={port},{}", endless_stall()))?;
    require_mount_in_network(&network, &options, &supervision)?;
    drop(network);
    read_across_reconnect("/vfs-options", &first, &state, &supervision)?;
    assert_eq!(unsafe { libc::umount(c"/vfs-options".as_ptr()) }, 0);
    peer.join().map_err(|_| "network namespace peer failed")??;
    unload_module()?;
    decoy.stop(
        TcpStream::connect((Ipv4Addr::LOCALHOST, port))?,
        &supervision,
    )?;
    println!(
        "vfs acceptance: mount from a new network namespace reached its loopback peer on the first dial and the reconnect"
    );
    Ok(())
}

#[derive(Clone, Copy, Debug)]
pub(super) enum Fault {
    Error,
    Panic,
}

struct Failing {
    serial: u64,
    fault: Fault,
}

impl Behaviour for Failing {
    fn hello(
        &self,
        _state: &State,
        serial: u64,
        reply: &[u8],
        stream: &mut dyn Stream,
    ) -> Result<Flow> {
        if serial == self.serial {
            match self.fault {
                Fault::Error => return Err("an injected failure".into()),
                Fault::Panic => panic!("an injected panic"),
            }
        }
        super::server::send(stream, reply)
    }
}

pub(crate) fn peer_failure() -> Result {
    fs::create_dir_all("/vfs-options")?;
    load_module()?;
    for (failing, fault) in [(1, Fault::Error), (2, Fault::Error), (2, Fault::Panic)] {
        let listener = unix_listener(UNIX_SOCKET)?;
        let failing_peer = Failing {
            serial: failing,
            fault,
        };
        let state = Arc::new(State::with(Arc::new(failing_peer)));
        let supervision = Supervision::new();
        let (peer, first) = spawn_vfs_peer(listener, &state, 2, &supervision);
        let options = unix_options(UNIX_SOCKET)?;
        let outcome = supervision
            .reap(fork_child(|| mount_with(&options)))
            .and_then(|status| {
                assert_eq!(status, 0, "the mount failed");
                read_across_reconnect("/vfs-options", &first, &state, &supervision)
            });
        let reason = match fault {
            Fault::Error => "an injected failure",
            Fault::Panic => "a panic",
        };
        assert_eq!(
            failure_of(outcome),
            Some(Failure::PeerFailed(format!(
                "serving session {failing}: {reason}"
            ))),
        );
        assert!(
            peer.join().map_err(|_| "the peer thread failed")?.is_err(),
            "the failing peer passed"
        );
        // A mount whose first session failed is never made.
        if failing == 2 {
            assert_eq!(unsafe { libc::umount(c"/vfs-options".as_ptr()) }, 0);
        }
        println!(
            "vfs acceptance: a peer failing in session {failing} by {fault:?} failed its case by an event, its child reaped"
        );
    }
    unload_module()
}
