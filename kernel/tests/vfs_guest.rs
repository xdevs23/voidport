// SPDX-License-Identifier: GPL-2.0

use super::server::{State, Withhold, serve_one};
use crate::Result;
use std::ffi::{CStr, CString};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::net::UnixListener;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

pub(super) fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap()
}

pub(super) const CLEANUP_TASK: &str = "voidport-clean";

pub(super) const CONNECTION_TASK: &str = "voidport-conn";

pub(super) fn task_named(prefix: &str) -> Result<libc::pid_t> {
    match tasks_named(prefix)?[..] {
        [task] => Ok(task),
        [] => Err(format!("task not found: {prefix}").into()),
        _ => Err(format!("several tasks match {prefix}").into()),
    }
}

pub(super) fn tasks_named(prefix: &str) -> Result<Vec<libc::pid_t>> {
    let mut found = Vec::new();
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let Some(task) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<libc::pid_t>().ok())
        else {
            continue;
        };
        // A task that exited since the listing cannot be read.
        let Ok(name) = fs::read_to_string(entry.path().join("comm")) else {
            continue;
        };
        if name.starts_with(prefix) {
            found.push(task);
        }
    }
    Ok(found)
}

/// Lists `directory` from `start`, a position past the dots the module
/// generates locally, so an error cannot hide behind a successful call that
/// returns only those. A listing that fails must have published no entry.
pub(super) fn list_past_dots(directory: &str, start: libc::off_t) -> std::io::Result<()> {
    let directory = File::open(directory)?;
    let position = unsafe { libc::lseek(directory.as_raw_fd(), start, libc::SEEK_SET) };
    if position < 0 {
        return Err(std::io::Error::last_os_error());
    }
    assert_eq!(position, start);
    let mut buffer = [0xa5u8; 4096];
    let listed = unsafe {
        libc::syscall(
            libc::SYS_getdents64,
            directory.as_raw_fd(),
            buffer.as_mut_ptr(),
            buffer.len(),
        )
    };
    if listed >= 0 {
        return Ok(());
    }
    let error = std::io::Error::last_os_error();
    assert!(
        buffer.iter().all(|byte| *byte == 0xa5),
        "a failed listing published entries"
    );
    Err(error)
}

const STATS: &str = "/sys/kernel/debug/voidport";

/// The longest lifetime, in seconds, that the mount options accept for cached
/// entries, cached attributes and stall windows. The module saturates it at
/// the longest span that the kernel's tick clock can compare, so nothing
/// cached with it expires while a guest runs, and a stall window with it never
/// ends. The guest script mounts with the same value.
pub(super) const FOREVER: u64 = match u64::from_str_radix(env!("VOIDPORT_FOREVER"), 10) {
    Ok(forever) => forever,
    Err(_) => panic!("VOIDPORT_FOREVER is not a number"),
};

pub(super) fn lasting() -> String {
    format!("attr_timeout={FOREVER},entry_timeout={FOREVER}")
}

pub(super) fn endless_stall() -> String {
    format!("reconnect_stall={FOREVER}")
}

pub(super) fn counter(name: &str) -> Result<u64> {
    let value = fs::read_to_string(format!("{STATS}/{name}"))
        .map_err(|error| format!("the statistic {name} cannot be read: {error}"))?;
    Ok(value.trim_end().parse()?)
}

pub(super) const TRACING: &str = "/sys/kernel/tracing";

fn define_probe(line: &str) -> Result {
    let path = format!("{TRACING}/kprobe_events");
    fs::OpenOptions::new()
        .append(true)
        .open(path)?
        .write_all(line.as_bytes())?;
    Ok(())
}

fn mount_tracing() -> Result {
    if fs::metadata(format!("{TRACING}/kprobe_events")).is_err() {
        let mounted = unsafe {
            libc::mount(
                c"tracefs".as_ptr(),
                c"/sys/kernel/tracing".as_ptr(),
                c"tracefs".as_ptr(),
                0,
                std::ptr::null(),
            )
        };
        assert_eq!(mounted, 0, "{}", std::io::Error::last_os_error());
    }
    Ok(())
}

/// Dropping the probe disables and removes it, so a failing case does not
/// leave it defined for the next case.
pub(super) struct Probe {
    pub(super) name: &'static str,
}

impl Probe {
    pub(super) fn define(name: &'static str, definition: &str) -> Result<Self> {
        mount_tracing()?;
        define_probe(&format!("p:{name} {definition}"))?;
        let probe = Self { name };
        // Opening the trace for writing with truncation empties it.
        fs::write(format!("{TRACING}/trace"), "")?;
        probe.enable("1")?;
        Ok(probe)
    }

    fn enable(&self, switch: &str) -> Result {
        fs::write(format!("{TRACING}/events/{}/enable", self.name), switch)?;
        Ok(())
    }

    pub(super) fn finish(self) -> Result<Vec<String>> {
        self.enable("0")?;
        let trace = fs::read_to_string(format!("{TRACING}/trace"))?;
        Ok(trace.lines().map(str::to_owned).collect())
    }
}

impl Drop for Probe {
    fn drop(&mut self) {
        let _ = self.enable("0");
        let _ = define_probe(&format!("-:{}", self.name));
    }
}

pub(super) fn field<'a>(record: &'a str, name: &str) -> Result<&'a str> {
    let (_, value) = record
        .split_once(&format!(" {name}="))
        .ok_or_else(|| format!("a record without {name}"))?;
    Ok(match value.strip_prefix('"') {
        Some(quoted) => quoted.split('"').next().unwrap_or_default(),
        None => value.split(' ').next().unwrap_or_default(),
    })
}

const NAMESPACE: &CStr = c"vfs-options";

pub(super) fn raw_mount(
    namespace: &CStr,
    target: &CStr,
    options: &CStr,
    flags: libc::c_ulong,
) -> libc::c_int {
    // SAFETY: every pointer is a live NUL-terminated string.
    unsafe {
        libc::mount(
            namespace.as_ptr(),
            target.as_ptr(),
            c"voidport".as_ptr(),
            flags,
            options.as_ptr().cast(),
        )
    }
}

pub(super) fn mount(options: &str, remount: bool) -> i32 {
    let options = CString::new(options).unwrap();
    let remount = if remount { libc::MS_REMOUNT } else { 0 };
    raw_mount(
        NAMESPACE,
        c"/vfs-options",
        &options,
        libc::MS_RDONLY | remount,
    )
}

pub(super) fn stat(file: &File, flags: i32) -> std::io::Result<libc::statx> {
    let mut value = unsafe { std::mem::zeroed() };
    let result = unsafe {
        libc::statx(
            file.as_raw_fd(),
            c"".as_ptr(),
            libc::AT_EMPTY_PATH | flags,
            libc::STATX_BASIC_STATS,
            &mut value,
        )
    };
    if result == 0 {
        Ok(value)
    } else {
        Err(std::io::Error::last_os_error())
    }
}

pub(super) fn fs_context() -> File {
    let raw = unsafe { libc::syscall(libc::SYS_fsopen, c"voidport".as_ptr(), 0) };
    assert!(raw >= 0);
    unsafe { File::from_raw_fd(raw as i32) }
}

pub(super) fn set_string(context: &File, key: &CStr, value: &CStr) -> libc::c_long {
    unsafe {
        libc::syscall(
            libc::SYS_fsconfig,
            context.as_raw_fd(),
            libc::FSCONFIG_SET_STRING,
            key.as_ptr(),
            value.as_ptr(),
            0,
        )
    }
}

pub(super) fn set_binary(context: &File, key: &CStr, value: &[u8]) -> libc::c_long {
    unsafe {
        libc::syscall(
            libc::SYS_fsconfig,
            context.as_raw_fd(),
            libc::FSCONFIG_SET_BINARY,
            key.as_ptr(),
            value.as_ptr(),
            value.len(),
        )
    }
}

pub(super) fn set_flag(context: &File, key: &CStr) -> libc::c_long {
    unsafe {
        libc::syscall(
            libc::SYS_fsconfig,
            context.as_raw_fd(),
            libc::FSCONFIG_SET_FLAG,
            key.as_ptr(),
            std::ptr::null::<u8>(),
            0,
        )
    }
}

pub(super) fn command_create(context: &File) -> libc::c_long {
    unsafe {
        libc::syscall(
            libc::SYS_fsconfig,
            context.as_raw_fd(),
            libc::FSCONFIG_CMD_CREATE,
            std::ptr::null::<u8>(),
            std::ptr::null::<u8>(),
            0,
        )
    }
}

pub(super) fn create(context: &File) -> libc::c_long {
    assert_eq!(set_flag(context, c"ro"), 0);
    command_create(context)
}

pub(super) fn logged(mut context: &File) -> Result<String> {
    let mut message = [0; 512];
    let size = context.read(&mut message)?;
    Ok(std::str::from_utf8(&message[..size])?.to_owned())
}

pub(super) const UNIX_SOCKET: &str = "/vfs-unix/voidport.sock";

pub(super) const ABSENT_SOCKET: &str = "/vfs-unix/absent.sock";

fn require_mount_at(target: &CStr, options: &str) {
    let options = CString::new(options).unwrap();
    assert_eq!(
        raw_mount(NAMESPACE, target, &options, libc::MS_RDONLY),
        0,
        "{}",
        std::io::Error::last_os_error()
    );
}

pub(super) fn require_mount(options: &str) {
    require_mount_at(c"/vfs-options", options);
}

pub(super) fn mount_peer_at(
    target: &CStr,
    state: &Arc<State>,
    options: &str,
) -> Result<std::thread::JoinHandle<Result>> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let port = listener.local_addr()?.port();
    let peer = serve_one(listener, state);
    require_mount_at(target, &format!("addr=127.0.0.1,port={port},{options}"));
    Ok(peer)
}

pub(super) fn mount_peer(
    state: &Arc<State>,
    options: &str,
) -> Result<std::thread::JoinHandle<Result>> {
    mount_peer_at(c"/vfs-options", state, options)
}

pub(super) fn withholding_mount()
-> Result<(Arc<Withhold>, Arc<State>, std::thread::JoinHandle<Result>)> {
    let withhold = Arc::new(Withhold::default());
    let state = Arc::new(State::with(withhold.clone()));
    let peer = mount_peer(&state, &lasting())?;
    Ok((withhold, state, peer))
}

pub(super) fn unmount_balanced(peer: std::thread::JoinHandle<Result>) -> Result {
    assert_eq!(unsafe { libc::umount(c"/vfs-options".as_ptr()) }, 0);
    peer.join().map_err(|_| "the peer panicked")??;
    require_balanced()
}

pub(super) fn require_balanced() -> Result {
    require_zero(&["requests_in_flight", "replies_live"])?;
    assert_eq!(counter("handles_released")?, counter("handles_opened")?);
    assert_eq!(
        counter("cleanup_sent")? + counter("cleanup_teardown")?,
        counter("nodes_forgotten")? + counter("handles_released")?
    );
    Ok(())
}

/// Requires each of the counters `names` to be zero. The teardown of a mount
/// runs before the unmount, the last close or the exit that ends the mount
/// returns, so the counters show it once that call has returned.
pub(super) fn require_zero(names: &[&str]) -> Result {
    for name in names {
        assert_eq!(counter(name)?, 0, "{name} after the teardown");
    }
    Ok(())
}

/// A child's body: closes every descriptor inherited past the standard
/// streams, then unmounts `/vfs-options`. The fork copies the socket end of
/// the peer thread into the child. An unmounting child that kept that copy
/// would hold the connection open after the peer closes its end, and the
/// unmount would wait for the child itself.
pub(super) fn unmount_without_peer_end() -> libc::c_int {
    if unsafe { libc::close_range(3, libc::c_uint::MAX, 0) } != 0 {
        return 1;
    }
    unsafe { libc::umount(c"/vfs-options".as_ptr()) }
}

pub(super) static SIGUSR1_HANDLED: AtomicUsize = AtomicUsize::new(0);

extern "C" fn count_signal(_: libc::c_int) {
    SIGUSR1_HANDLED.fetch_add(1, Ordering::Relaxed);
}

pub(super) fn count_sigusr1() -> bool {
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = count_signal as *const () as usize;
    unsafe { libc::sigaction(libc::SIGUSR1, &action, std::ptr::null_mut()) == 0 }
}

pub(super) fn mount_with(options: &CStr) -> libc::c_int {
    raw_mount(NAMESPACE, c"/vfs-options", options, libc::MS_RDONLY)
}

pub(super) fn look_up(path: &CStr) -> libc::c_int {
    let mut status: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::stat(path.as_ptr(), &mut status) } == 0 {
        0
    } else {
        1
    }
}

pub(super) fn read_back(path: &CStr, expected: &[u8]) -> libc::c_int {
    let mut content = [0u8; 8];
    let mut filled = 0;
    let file = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if file < 0 {
        return 1;
    }
    while filled < content.len() {
        let room = &mut content[filled..];
        let read = unsafe { libc::read(file, room.as_mut_ptr().cast(), room.len()) };
        if read <= 0 {
            break;
        }
        filled += read as usize;
    }
    if content[..filled] == *expected { 0 } else { 2 }
}

pub(super) fn unix_endpoint(path: &str) -> String {
    format!("unix={path}")
}

pub(super) fn tcp_endpoint(address: SocketAddr) -> String {
    format!("addr={},port={}", address.ip(), address.port())
}

pub(super) trait Endpoint {
    fn endpoint_options(&self) -> Result<String>;
}

impl Endpoint for UnixListener {
    fn endpoint_options(&self) -> Result<String> {
        let address = self.local_addr()?;
        let path = address
            .as_pathname()
            .and_then(std::path::Path::to_str)
            .ok_or("a unix listener without a UTF-8 path")?;
        Ok(unix_endpoint(path))
    }
}

impl Endpoint for TcpListener {
    fn endpoint_options(&self) -> Result<String> {
        Ok(tcp_endpoint(self.local_addr()?))
    }
}

pub(super) fn unix_options(path: &str) -> Result<CString> {
    Ok(CString::new(format!(
        "{},{}",
        unix_endpoint(path),
        endless_stall()
    ))?)
}
