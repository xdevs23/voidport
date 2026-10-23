// SPDX-License-Identifier: GPL-2.0

use crate::{LIMITS, Result, hello_reply, load_module, read_frame, unload_module};
use guest::{FOREVER, create, errno, fs_context, logged, mount_peer, require_zero, set_string};
use server::{Behaviour, Flow, Rendezvous, State, Stream, send};
use std::ffi::{CStr, CString};
use std::fs::{self, File};
use std::io::Write;
use std::net::{Ipv4Addr, TcpListener};
use std::os::unix::fs::MetadataExt;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use voidport_proto::frame::Frame;
use voidport_proto::opcode::Opcode;

#[path = "vfs_allocation.rs"]
mod allocation;
#[path = "vfs_answered.rs"]
mod answered;
#[path = "vfs_concurrency.rs"]
mod concurrency;
#[path = "vfs_cuts.rs"]
mod cuts;
#[path = "vfs_guest.rs"]
mod guest;
#[path = "vfs_hostile.rs"]
mod hostile;
#[path = "vfs_joins.rs"]
mod joins;
#[path = "vfs_links.rs"]
mod links;
#[path = "vfs_mapped_writes.rs"]
mod mapped_writes;
#[path = "vfs_metadata.rs"]
mod metadata;
#[path = "vfs_network_reference.rs"]
mod network_reference;
#[path = "vfs_occupation.rs"]
mod occupation;
#[path = "vfs_options.rs"]
mod options;
#[path = "vfs_pool.rs"]
mod pool;
#[path = "vfs_record_locks.rs"]
mod record_locks;
#[path = "vfs_server.rs"]
mod server;
#[path = "vfs_settle.rs"]
mod settle;
#[path = "vfs_signals.rs"]
mod signals;
#[path = "vfs_sockets.rs"]
mod sockets;
#[path = "vfs_stopped_peer.rs"]
mod stopped_peer;
#[path = "vfs_transitions.rs"]
mod transitions;
#[path = "vfs_writable.rs"]
mod writable;
#[path = "vfs_writes.rs"]
mod writes;

pub(super) use allocation::run as allocation_faults;
pub(super) use answered::run as signal_answered;
pub(super) use concurrency::run as concurrency;
pub(super) use cuts::{Cleanup, cleanup_send_failure, connection_threads, flaps, shared_node};
pub(super) use joins::{Case as JoinCase, run as joins};
pub(super) use mapped_writes::run as mapped_writes;
pub(super) use metadata::{orphaned_create, setattr};
pub(super) use network_reference::run as netns_reference;
pub(super) use options::run;
pub(super) use pool::parallel as connections_parallel;
pub(super) use record_locks::run as record_locks;
pub(super) use settle::{Case as SettleCase, run as settle};
pub(super) use signals::{Case as SignalCase, Operation as SignalOperation, run as signals};
pub(super) use sockets::{netns, peer_failure, unix, unix_chroot, unmount_wait};
pub(super) use stopped_peer::{Case as StoppedPeerCase, run as stopped_peer};
pub(super) use transitions::{run as transitions, stall_expiry};
pub(super) use writes::{direct, direct_mount, run as writes};

#[derive(Clone, Copy, Debug)]
enum Answer {
    Close,
    Refuse,
    NextVersion,
}

impl Answer {
    pub(super) fn serve(self, listener: TcpListener) -> Result {
        let (mut stream, _) = listener.accept()?;
        let bytes = read_frame(&mut stream)?;
        let id = Frame::parse(&bytes, &LIMITS)?.request_id();
        match self {
            Self::Close => {}
            Self::Refuse => {
                let mut bytes = [0; 128];
                stream.write_all(voidport_proto::frame::FrameWriter::error_response(
                    &mut bytes,
                    id,
                    Opcode::Hello,
                    -libc::ENOENT,
                )?)?;
            }
            Self::NextVersion => {
                stream.write_all(&hello_reply(id, voidport_proto::PROTOCOL_VERSION + 1)?)?;
            }
        }
        Ok(())
    }
}

fn failed_mount(addr: &CStr, port: &CStr) -> Result<(i32, String)> {
    let context = fs_context();
    for (key, value) in [
        (c"source", c"vfs-options"),
        (c"addr", addr),
        (c"port", port),
    ] {
        assert_eq!(set_string(&context, key, value), 0);
    }
    assert_eq!(create(&context), -1);
    Ok((errno(), logged(&context)?))
}

pub(super) fn diagnostics() -> Result {
    load_module()?;
    for (answer, expected, diagnostic) in [
        (None, libc::ECONNREFUSED, "cannot connect to the endpoint"),
        (
            Some(Answer::Close),
            libc::ECONNRESET,
            "transport I/O failed during the handshake",
        ),
        (
            Some(Answer::Refuse),
            libc::ENOENT,
            "the server refused the mount",
        ),
        (
            Some(Answer::NextVersion),
            libc::EPROTO,
            "the server sent an invalid handshake",
        ),
    ] {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let port = CString::new(listener.local_addr()?.port().to_string())?;
        let peer = match answer {
            Some(answer) => Some(std::thread::spawn(move || answer.serve(listener))),
            None => {
                drop(listener);
                None
            }
        };
        let (error, message) = failed_mount(c"127.0.0.1", port.as_c_str())?;
        assert_eq!(error, expected, "{answer:?}");
        assert!(
            message.contains(diagnostic),
            "{message:?} lacks {diagnostic:?}"
        );
        if let Some(peer) = peer {
            peer.join().map_err(|_| "the diagnostics peer failed")??;
        }
        println!("vfs acceptance: mount with {answer:?} errno={expected} context={message:?}");
    }
    unload_module()
}

pub(super) fn address_family() -> Result {
    load_module()?;
    let (error, message) = failed_mount(c"::1", c"1234")?;
    assert_eq!(error, libc::ENODEV);
    let diagnostic = "the endpoint's address family is unavailable";
    assert!(
        message.contains(diagnostic),
        "{message:?} lacks {diagnostic:?}"
    );
    println!("vfs acceptance: mount to an IPv6 address errno={error} context={message:?}");
    unload_module()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Boundary {
    /// Before the reply, which it then sends, and the session goes on.
    Before,
    Inside,
    After,
    Instead,
}

#[derive(Default)]
struct ReadProgress {
    entered: Option<(u64, u64)>,
    pub(super) released: bool,
    reader_finished: bool,
}

struct ReadStop {
    pub(super) boundary: Boundary,
    pub(super) progress: Rendezvous<ReadProgress>,
}

impl ReadStop {
    pub(super) fn new(boundary: Boundary) -> Self {
        Self {
            boundary,
            progress: Rendezvous::default(),
        }
    }

    fn wait_entered(&self) -> Result<(u64, u64)> {
        self.progress
            .wait(|progress| progress.entered.is_some() || progress.reader_finished)?;
        self.progress
            .read(|progress| progress.entered)
            .ok_or_else(|| "reader completed before the peer observed its READ".into())
    }

    fn go_on(&self) {
        self.progress.update(|progress| progress.released = true);
    }
}

impl Behaviour for ReadStop {
    fn deliver(
        &self,
        _state: &State,
        serial: u64,
        frame: &Frame<'_>,
        reply: Vec<u8>,
        stream: &mut dyn Stream,
    ) -> Result<Flow> {
        if frame.opcode()? != Opcode::Read {
            return send(stream, &reply);
        }
        let mut written = Ok(());
        // Publish the completed write before a reader woken by that reply can
        // publish its own completion event.
        self.progress.update(|progress| {
            written = match self.boundary {
                Boundary::Inside => {
                    stream.write_all(&reply[..voidport_proto::frame::FRAME_HEADER_LEN + 1])
                }
                Boundary::After => stream.write_all(&reply),
                Boundary::Before | Boundary::Instead => Ok(()),
            };
            progress.entered = Some((serial, frame.request_id()));
        });
        written?;
        self.progress.wait(|progress| progress.released)?;
        match self.boundary {
            Boundary::Before => send(stream, &reply),
            Boundary::Inside | Boundary::After | Boundary::Instead => Ok(Flow::End),
        }
    }

    fn ended(&self) {
        self.progress.end();
    }
}

struct Reading<'a>(&'a ReadStop);

impl Drop for Reading<'_> {
    fn drop(&mut self) {
        self.0
            .progress
            .update(|progress| progress.reader_finished = true);
    }
}

pub(super) fn lifecycle() -> Result {
    fs::create_dir_all("/vfs-options")?;
    use Boundary::{After, Before, Inside, Instead};
    for boundary in [Before, Inside, After, Instead] {
        load_module()?;
        let stop = Arc::new(ReadStop::new(boundary));
        let state = Arc::new(State::with(stop.clone()));
        let peer = mount_peer(&state, "reconnect_stall=0")?;
        let file = File::open("/vfs-options/n40")?;
        // Keep the final file reference on this task. Closing it after the
        // reader joins starts the lazy-detach teardown from an observed
        // syscall.
        let mut reading = file.try_clone()?;
        let completion = stop.clone();
        let reader = std::thread::spawn(move || {
            let _completion = Reading(&completion);
            let mut bytes = Vec::new();
            std::io::Read::read_to_end(&mut reading, &mut bytes).map(|_| bytes)
        });
        let identity = stop.wait_entered()?;
        assert_eq!(identity.0, 1);
        assert_ne!(identity.1, 0);
        println!(
            "vfs acceptance: READ session={} request={} boundary={boundary:?}",
            identity.0, identity.1
        );
        if boundary == Before {
            assert_eq!(unsafe { libc::umount(c"/vfs-options".as_ptr()) }, -1);
            assert_eq!(errno(), libc::EBUSY);
            assert_eq!(
                unsafe { libc::umount2(c"/vfs-options".as_ptr(), libc::MNT_DETACH) },
                0
            );
            assert_eq!(
                unsafe {
                    libc::syscall(
                        libc::SYS_delete_module,
                        c"voidport".as_ptr(),
                        libc::O_NONBLOCK,
                    )
                },
                -1
            );
            assert_eq!(errno(), libc::EWOULDBLOCK);
            assert!(!reader.is_finished(), "read was not live during unmount");
        }
        stop.go_on();
        let result = reader.join().map_err(|_| "I/O reader panicked")?;
        if [Before, After].contains(&boundary) {
            assert_eq!(result?, b"old");
        } else {
            assert_eq!(result.unwrap_err().raw_os_error(), Some(libc::EIO));
        }
        drop(file);
        if boundary != Before {
            assert_eq!(unsafe { libc::umount(c"/vfs-options".as_ptr()) }, 0);
        }
        peer.join().map_err(|_| "lifecycle peer failed")??;
        require_zero(&[
            "requests_in_flight",
            "replies_live",
            "reads_in_flight",
            "connections_live",
        ])?;
        unload_module()?;
        println!(
            "vfs acceptance: I/O boundary={boundary:?} result verified, workers joined, module unloaded"
        );
    }
    Ok(())
}

pub(super) fn retry() -> Result {
    fs::create_dir_all("/vfs-options")?;
    for name in ["retry-absent", "retry-replaced", "retry-generation"] {
        retry_case(name)?;
    }
    Ok(())
}

/// A name the peer changes after its first lookup: from absent to present,
/// to another node, or to the same node in another generation. The mount
/// caches entries for zero seconds, so the next walk asks the peer again,
/// finds the entry stale, and looks the name up once more.
fn retry_case(name: &str) -> Result {
    let (state, peer) = mount_entry_lifetime(0)?;
    let path = format!("/vfs-options/{name}");
    let old = if name == "retry-absent" {
        let initial = fs::metadata(&path);
        assert_eq!(initial.unwrap_err().raw_os_error(), Some(libc::ENOENT));
        None
    } else {
        let old = File::open(&path)?;
        assert!(old.metadata()?.is_file());
        Some(old)
    };
    assert_eq!(state.lookups(1, name), 1);
    state.version.store(1, Ordering::SeqCst);
    let resolved = fs::metadata(&path)?;
    if name == "retry-absent" {
        assert!(resolved.is_file());
    } else {
        assert!(
            resolved.is_dir(),
            "retry did not resolve the replacement directory"
        );
    }
    if name == "retry-generation" {
        assert_eq!(resolved.ino(), old.as_ref().unwrap().metadata()?.ino());
    }
    if let Some(old) = old {
        assert!(old.metadata()?.is_file(), "held inode changed identity");
    }
    assert_eq!(
        state.lookups(1, name),
        3,
        "the path walk must issue a distinct lookup after rejecting the stale entry"
    );
    unmount_entry_lifetime(peer)?;
    println!("vfs acceptance: name={name} exact retry observed");
    Ok(())
}

pub(super) fn negative_lifetime() -> Result {
    fs::create_dir_all("/vfs-options")?;
    let (state, peer) = mount_entry_lifetime(FOREVER)?;
    let name = "retry-absent";
    let path = format!("/vfs-options/{name}");
    let initial = fs::metadata(&path);
    assert_eq!(initial.unwrap_err().raw_os_error(), Some(libc::ENOENT));
    assert_eq!(state.lookups(1, name), 1);
    state.version.store(1, Ordering::SeqCst);
    let lookups = match fs::metadata(&path) {
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => 1,
        Ok(found) if found.is_file() => 2,
        other => return Err(format!("the cached absence resolved to {other:?}").into()),
    };
    assert_eq!(
        state.lookups(1, name),
        lookups,
        "the walk revalidated the cached absence within its lifetime"
    );
    unmount_entry_lifetime(peer)?;
    println!("vfs acceptance: lookups={lookups} absence cached for its lifetime");
    Ok(())
}

fn mount_entry_lifetime(seconds: u64) -> Result<(Arc<State>, std::thread::JoinHandle<Result>)> {
    load_module()?;
    let state = Arc::new(State::default());
    let peer = mount_peer(
        &state,
        &format!("entry_timeout={seconds},attr_timeout={FOREVER}"),
    )?;
    Ok((state, peer))
}

fn unmount_entry_lifetime(peer: std::thread::JoinHandle<Result>) -> Result {
    assert_eq!(unsafe { libc::umount(c"/vfs-options".as_ptr()) }, 0);
    peer.join().map_err(|_| "entry lifetime peer failed")??;
    unload_module()
}
