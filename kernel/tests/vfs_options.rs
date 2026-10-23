// SPDX-License-Identifier: GPL-2.0

use super::guest::{
    FOREVER, Probe, command_create, create, errno, field, fs_context, lasting, list_past_dots,
    mount, raw_mount, require_mount, set_binary, set_flag, set_string, stat,
};
use super::server::{
    Behaviour, Flow, Listed, Listing, State, Stream, check_large, send, serve_sessions, wire_node,
};
use crate::{Result, load_module, unload_module};
use std::collections::BTreeSet;
use std::ffi::CString;
use std::fs::{self, File};
use std::net::{Ipv6Addr, TcpListener};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirEntryExt, MetadataExt};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use voidport_proto::attr::{Attr, EntryOut};
use voidport_proto::frame::Frame;
use voidport_proto::opcode::Opcode;
use voidport_proto::ops::file::{OpenRequest, ReadRequest, fsync_flags};
use voidport_proto::ops::node::LookupRequest;
use zerocopy::byteorder::little_endian::{U32, U64};

const HASHED: &str = "vfs_options/hashed";

fn record_hashes() -> Result<Probe> {
    Probe::define(HASHED, "iget5_locked hash=$arg2:u64 test=$arg3:symbol")
}

fn module_hashes(recording: Probe) -> Result<Vec<u64>> {
    recording
        .finish()?
        .iter()
        .filter(|line| line.ends_with("[voidport]"))
        .map(|line| Ok(field(line, "hash")?.parse()?))
        .collect()
}

fn parser_contexts() -> Result {
    let longest_path = CString::new(format!("/{}", "p".repeat(107)))?;
    let too_long_path = CString::new(format!("/{}", "p".repeat(108)))?;
    for (key, first, second) in [
        (c"source", c"vfs-options", c"other"),
        (c"namespace", c"vfs-options", c"other"),
        (c"port", c"1234", c"1235"),
        (c"addr", c"127.0.0.1", c"::1"),
        (c"unix", c"/run/one.sock", c"/run/two.sock"),
        (c"path", c"/one", c"/two"),
        (c"tag", c"voidport-one", c"voidport-two"),
    ] {
        let context = fs_context();
        assert_eq!(set_string(&context, key, first), 0);
        assert_eq!(set_string(&context, key, second), -1);
        assert_eq!(errno(), libc::EINVAL);
        println!("vfs acceptance: duplicate {} EINVAL", key.to_str()?);
    }
    for (key, value) in [
        (c"addr", c"localhost"),
        (c"addr", c"127.0.0.1:1234"),
        (c"addr", c"127.0.0.1.1"),
        (c"addr", c"127.0.0"),
        (c"addr", c"256.0.0.1"),
        (c"addr", c"fe80::1%eth0"),
        (c"addr", c"[::1]"),
        (c"addr", c"::1 "),
        (c"port", c"0"),
        (c"port", c"65536"),
        (c"port", c"4294967295"),
        (c"unix", c"run/voidport.sock"),
        (c"unix", too_long_path.as_c_str()),
        (c"path", c"tree"),
        (c"tag", c"virtiofs-0"),
    ] {
        let context = fs_context();
        assert_eq!(set_string(&context, key, value), -1, "{value:?}");
        assert_eq!(errno(), libc::EINVAL, "{value:?}");
        println!("vfs acceptance: invalid {value:?} EINVAL");
    }
    for (key, value) in [
        (c"addr", c"127.0.0.1"),
        (c"addr", c"::1"),
        (c"addr", c"::ffff:127.0.0.1"),
        (c"addr", c"fd00:0:0:0:0:0:0:1"),
        (c"port", c"1"),
        (c"port", c"65535"),
        (c"unix", c"/"),
        (c"unix", longest_path.as_c_str()),
        (c"path", c"/"),
        (c"path", c"/tree/"),
        (c"tag", c"voidport-0"),
    ] {
        assert_eq!(set_string(&fs_context(), key, value), 0, "{value:?}");
    }
    let deep = format!("/{}", "p".repeat(300));
    for key in [c"path", c"source", c"namespace"] {
        assert_eq!(
            set_binary(&fs_context(), key, deep.as_bytes()),
            0,
            "{key:?}"
        );
    }
    let context = fs_context();
    assert_eq!(set_binary(&context, c"path", &deep.as_bytes()[1..]), -1);
    assert_eq!(errno(), libc::EINVAL);
    for options in [
        &[][..],
        &[(c"namespace", c"vfs-options"), (c"addr", c"127.0.0.1")][..],
        &[(c"addr", c"127.0.0.1")][..],
        &[(c"port", c"1234")][..],
    ] {
        let context = fs_context();
        assert_eq!(set_string(&context, c"source", c"vfs-options"), 0);
        for (key, value) in options {
            assert_eq!(set_string(&context, key, value), 0);
        }
        assert_eq!(create(&context), -1);
        assert_eq!(errno(), libc::EINVAL);
        println!("vfs acceptance: incomplete endpoint EINVAL");
    }
    let unix = (c"unix", c"/run/voidport.sock");
    let (addr, port, tag) = (
        (c"addr", c"127.0.0.1"),
        (c"port", c"1234"),
        (c"tag", c"voidport-0"),
    );
    for (given, (key, value)) in [
        (&[unix][..], port),
        (&[unix][..], addr),
        (&[addr, port][..], unix),
        (&[tag][..], unix),
        (&[tag][..], addr),
        (&[addr, port][..], tag),
    ] {
        let context = fs_context();
        for (key, value) in given {
            assert_eq!(set_string(&context, key, value), 0);
        }
        assert_eq!(set_string(&context, key, value), -1, "{value:?}");
        assert_eq!(errno(), libc::EINVAL, "{value:?}");
        println!("vfs acceptance: second endpoint {} EINVAL", key.to_str()?);
    }
    let longest = FOREVER.to_string();
    for text in [
        "0",
        "0.125",
        "1.000000001",
        "1e-100",
        "4294967.296",
        longest.as_str(),
    ] {
        let context = fs_context();
        let text = CString::new(text)?;
        for option in [c"attr_timeout", c"entry_timeout", c"reconnect_stall"] {
            assert_eq!(set_string(&context, option, &text), 0);
        }
    }
    let context = fs_context();
    assert_eq!(set_flag(&context, c"ro"), 0);
    assert_eq!(set_string(&context, c"source", c"vfs-options"), 0);
    for _ in 0..2 {
        assert_eq!(command_create(&context), -1);
        assert!([libc::EINVAL, libc::EBUSY].contains(&errno()));
    }
    println!("vfs acceptance: typed duration domain and repeated contexts ok");
    Ok(())
}

#[derive(Clone, Copy, Debug)]
enum CookieFault {
    Repeat = 1,
    Regress = 2,
    Largest = 3,
}

impl CookieFault {
    const ALL: [Self; 3] = [Self::Repeat, Self::Regress, Self::Largest];

    pub(super) fn next_cookie(self, cookie: u64) -> u64 {
        match self {
            Self::Repeat => cookie,
            Self::Regress => cookie.saturating_sub(1),
            Self::Largest => u64::MAX,
        }
    }

    fn expected_errno(self) -> i32 {
        match self {
            Self::Repeat | Self::Regress => libc::EIO,
            Self::Largest => libc::EOVERFLOW,
        }
    }

    pub(super) fn node(self, entry: u64) -> u64 {
        self as u64 * 100 + entry
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Credential {
    LookupN20,
    LookupN21,
    Open,
    Read,
}

impl Credential {
    const ALL: [Self; 4] = [Self::LookupN20, Self::LookupN21, Self::Open, Self::Read];
}

#[derive(Default)]
struct Replies {
    oversized: AtomicBool,
    refreshed_mode: Mutex<Option<u32>>,
    cookie_fault: Mutex<Option<CookieFault>>,
    credentials: AtomicBool,
    credentials_seen: Mutex<BTreeSet<Credential>>,
    path: Mutex<&'static [u8]>,
}

impl Replies {
    fn check_credentials(&self, serial: u64, frame: &Frame<'_>) -> Result {
        let opener = (1111, 2222);
        let (head, credential, expected) = match frame.opcode()? {
            Opcode::Lookup => {
                let request = frame.request::<LookupRequest>()?;
                match request.name() {
                    b"n20" => (request.head(), Credential::LookupN20, opener),
                    b"n21" => (request.head(), Credential::LookupN21, (3333, 4444)),
                    _ => return Err("unexpected credential lookup".into()),
                }
            }
            Opcode::Open => (
                frame.request::<OpenRequest>()?.head(),
                Credential::Open,
                opener,
            ),
            Opcode::Read => (
                frame.request::<ReadRequest>()?.head(),
                Credential::Read,
                opener,
            ),
            _ => return Ok(()),
        };
        if matches!(credential, Credential::Open | Credential::Read) {
            assert_eq!(head.node_id.get(), wire_node(serial, 20));
        }
        let credentials = (head.uid.get(), head.gid.get());
        assert_eq!(credentials, expected);
        self.credentials_seen.lock().unwrap().insert(credential);
        println!(
            "vfs peer: {:?} request={} uid={} gid={}",
            frame.opcode()?,
            frame.request_id(),
            credentials.0,
            credentials.1
        );
        Ok(())
    }
}

impl Behaviour for Replies {
    fn path(&self) -> &'static [u8] {
        *self.path.lock().unwrap()
    }

    fn attributes(&self, index: u64, attr: &mut Attr) {
        if index != 0 && self.oversized.load(Ordering::SeqCst) {
            attr.size = U64::new(u64::MAX);
        }
        if let Some(mode) = *self.refreshed_mode.lock().unwrap()
            && (3000..=3002).contains(&index)
        {
            attr.mode = U32::new(mode);
        }
    }

    fn entry(&self, _serial: u64, _opcode: Opcode, _index: u64, entry: &mut EntryOut) {
        // The module hashes a node by its ID with the generation turned by
        // half a word. This generation cancels every bit of the ID, so every
        // node hashes to 7, which the case checks in the hashes the kernel
        // records.
        entry.generation = U64::new((entry.node_id.get() ^ 7).rotate_right(32));
    }

    fn listing(&self, cookie: u64, listing: &mut Listing) {
        let Some(fault) = *self.cookie_fault.lock().unwrap() else {
            return;
        };
        listing.entries = [(1, b"a"), (2, b"b")]
            .map(|(entry, name)| Listed {
                next_cookie: fault.next_cookie(cookie),
                ..Listed::new(fault.node(entry), name)
            })
            .into();
        listing.exhausted = false;
    }

    fn deliver(
        &self,
        _state: &State,
        serial: u64,
        frame: &Frame<'_>,
        reply: Vec<u8>,
        stream: &mut dyn Stream,
    ) -> Result<Flow> {
        if self.credentials.load(Ordering::SeqCst) {
            self.check_credentials(serial, frame)?;
        }
        send(stream, &reply)
    }
}

fn exercise(port: u16, state: &State, replies: &Replies) -> Result {
    fs::create_dir_all("/vfs-options")?;
    parser_contexts()?;
    for text in ["-1", "NaN", "1.2.3", "18446744073709551616"] {
        assert_eq!(
            mount(
                &format!("addr=127.0.0.1,port={port},attr_timeout={text}"),
                false
            ),
            -1
        );
        assert!([libc::EINVAL, libc::EOVERFLOW].contains(&errno()));
    }
    *replies.path.lock().unwrap() = b"/vfs-options";
    let options = format!(
        "addr=127.0.0.1,port={port},path=/vfs-options/,{}",
        lasting()
    );
    require_mount(&options);
    assert_eq!(mount("", true), 0);
    assert_eq!(mount(&options, true), 0);
    assert_eq!(mount("addr=127.000.000.001", true), 0);
    assert_eq!(mount("path=/vfs-options", true), 0);
    for change in [
        "addr=127.0.0.2",
        "addr=::1",
        "unix=/vfs-unix/voidport.sock",
        "port=1",
        "path=/",
        "path=/vfs-options/sub",
        "attr_timeout=1",
        "entry_timeout=0",
        "reconnect_stall=0",
        "no_privileged_bits",
        "direct_io",
    ] {
        assert_eq!(mount(change, true), -1, "{change}");
        assert_eq!(errno(), libc::EINVAL, "{change}");
    }
    for index in 3000..=3002 {
        use std::os::unix::fs::OpenOptionsExt;
        let file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_NOFOLLOW)
            .open(format!("/vfs-options/n{index}"))?;
        let original = stat(&file, libc::AT_STATX_FORCE_SYNC)?.stx_mode;
        for class in 0..16 {
            let mode = (class << 12) | 0o600;
            if mode & libc::S_IFMT == u32::from(original) & libc::S_IFMT {
                continue;
            }
            *replies.refreshed_mode.lock().unwrap() = Some(mode);
            assert_eq!(
                stat(&file, libc::AT_STATX_FORCE_SYNC)
                    .unwrap_err()
                    .raw_os_error(),
                Some(libc::ESTALE)
            );
            assert_eq!(stat(&file, libc::AT_STATX_DONT_SYNC)?.stx_mode, original);
        }
        *replies.refreshed_mode.lock().unwrap() = None;
        assert_eq!(stat(&file, libc::AT_STATX_FORCE_SYNC)?.stx_mode, original);
    }
    println!("vfs acceptance: inode kind changes are local ESTALE with unchanged modes ok");
    replies.credentials.store(true, Ordering::SeqCst);
    assert!(
        Command::new("/bin/mapping-test")
            .arg("--credentials")
            .status()?
            .success()
    );
    assert_eq!(
        *replies.credentials_seen.lock().unwrap(),
        Credential::ALL.into_iter().collect()
    );
    replies.credentials.store(false, Ordering::SeqCst);
    {
        let large = File::open("/vfs-options/n4")?;
        let directory = File::open("/vfs-options")?;
        for file in [&large, &directory] {
            file.sync_all()?;
            file.sync_data()?;
        }
        assert_eq!(
            state.fsyncs(),
            [0, fsync_flags::DATASYNC, 0, fsync_flags::DATASYNC]
        );
        check_large(&large, state)?;
        println!("vfs acceptance: file and directory fsync and fdatasync reach the peer ok");
    }
    for fault in CookieFault::ALL {
        let expected_forgets: Vec<_> = (1..=2)
            .map(|entry| {
                let index = fault.node(entry);
                (index, state.forgotten(1, index) + 1)
            })
            .collect();
        *replies.cookie_fault.lock().unwrap() = Some(fault);
        // A positive previous cookie past the dots makes regression and
        // repetition distinct, so they do not both degenerate to zero.
        let listed = list_past_dots("/vfs-options", 10);
        assert_eq!(
            listed.unwrap_err().raw_os_error(),
            Some(fault.expected_errno()),
            "cookie fault {fault:?}"
        );
        *replies.cookie_fault.lock().unwrap() = None;
        state.wait_forgotten(1, &expected_forgets)?;
        println!(
            "vfs acceptance: cookie fault={fault:?} errno={} both exact-ID admissions forgotten",
            fault.expected_errno()
        );
    }
    let recording = record_hashes()?;
    for name in ["n7000", "n7001"] {
        fs::metadata(format!("/vfs-options/{name}"))?;
    }
    let hashes = module_hashes(recording)?;
    assert!(
        hashes.len() >= 2 && hashes.iter().all(|&hash| hash == 7),
        "the nodes did not share one inode hash: {hashes:?}"
    );
    let a = File::open("/vfs-options/a")?;
    let b = File::open("/vfs-options/b")?;
    assert_eq!(a.metadata()?.ino(), 42);
    assert_eq!(b.metadata()?.ino(), 42);
    for entry in fs::read_dir("/vfs-options")? {
        let entry = entry?;
        assert_eq!(entry.ino(), 42);
    }
    // The attributes are valid for the lifetime of the mount, so only the
    // forced synchronization asks the peer for them.
    let before = state.gets.load(Ordering::SeqCst);
    stat(&a, libc::AT_STATX_FORCE_SYNC)?;
    stat(&a, 0)?;
    stat(&a, libc::AT_STATX_DONT_SYNC)?;
    assert_eq!(state.gets.load(Ordering::SeqCst), before + 1);
    replies.oversized.store(true, Ordering::SeqCst);
    assert_eq!(
        stat(&a, libc::AT_STATX_FORCE_SYNC)
            .unwrap_err()
            .raw_os_error(),
        Some(libc::EOVERFLOW)
    );
    assert_eq!(stat(&a, libc::AT_STATX_DONT_SYNC)?.stx_size, 3);
    assert_eq!(
        fs::metadata("/vfs-options/oversized")
            .unwrap_err()
            .raw_os_error(),
        Some(libc::EOVERFLOW)
    );
    replies.oversized.store(false, Ordering::SeqCst);
    stat(&a, libc::AT_STATX_FORCE_SYNC)?;
    let page = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_READ,
            libc::MAP_SHARED,
            a.as_raw_fd(),
            0,
        )
    };
    assert_ne!(page, libc::MAP_FAILED);
    assert_eq!(
        unsafe { std::slice::from_raw_parts(page.cast::<u8>(), 3) },
        b"old"
    );
    assert_eq!(unsafe { libc::mlock(page, 4096) }, 0);
    state.version.store(1, Ordering::SeqCst);
    let gets = state.gets.load(Ordering::SeqCst);
    stat(&a, libc::AT_STATX_FORCE_SYNC)?;
    assert_eq!(state.gets.load(Ordering::SeqCst), gets + 1);
    assert_eq!(
        unsafe { std::slice::from_raw_parts(page.cast::<u8>(), 3) },
        b"new"
    );
    assert_eq!(unsafe { libc::munlock(page, 4096) }, 0);
    assert_eq!(unsafe { libc::munmap(page, 4096) }, 0);
    // FIFOs, sockets and device nodes appear with their kind. A mode whose
    // file type bits name no kind cannot become an inode.
    for (index, kind) in [
        (4000, libc::S_IFIFO),
        (4001, libc::S_IFCHR),
        (4002, libc::S_IFBLK),
        (4003, libc::S_IFSOCK),
    ] {
        let mode = fs::metadata(format!("/vfs-options/n{index}"))?.mode();
        assert_eq!(mode & libc::S_IFMT, kind, "n{index}");
    }
    assert_eq!(
        fs::metadata("/vfs-options/n4004")
            .unwrap_err()
            .raw_os_error(),
        Some(libc::EOPNOTSUPP)
    );
    drop(a);
    drop(b);
    let mut workers = Vec::new();
    for _ in 0..8 {
        workers.push(std::thread::spawn(|| -> Result {
            for _ in 0..64 {
                for name in ["a", "b"] {
                    assert_eq!(fs::read(format!("/vfs-options/{name}"))?, b"new");
                }
            }
            Ok(())
        }));
    }
    for _ in 0..64 {
        fs::write("/proc/sys/vm/drop_caches", b"3")?;
    }
    for worker in workers {
        worker.join().map_err(|_| "concurrent lookup failed")??;
    }
    for index in 900..2948 {
        assert_eq!(fs::metadata(format!("/vfs-options/n{index}"))?.len(), 3);
    }
    fs::write("/proc/sys/vm/drop_caches", b"3")?;
    let expected: Vec<_> = (900..2948).map(|index| (index, 1)).collect();
    state.wait_forgotten(1, &expected)?;
    assert_eq!(unsafe { libc::umount(c"/vfs-options".as_ptr()) }, 0);
    *replies.path.lock().unwrap() = b"";
    let source = CString::new(format!("voidport://[::1]:{port}/@vfs-options"))?;
    let options = CString::new(format!(
        "namespace=vfs-options,addr=::1,port={port},attr_timeout=0,entry_timeout={FOREVER}"
    ))?;
    assert_eq!(
        raw_mount(&source, c"/vfs-options", &options, libc::MS_RDONLY),
        0,
        "{}",
        std::io::Error::last_os_error()
    );
    let shown = format!(" - voidport {} ", source.to_str()?);
    assert!(
        fs::read_to_string("/proc/self/mountinfo")?
            .lines()
            .any(|line| line.contains(" /vfs-options ") && line.contains(&shown)),
        "the mount table lacks {shown:?}"
    );
    for repeat in ["path=/", "namespace=vfs-options"] {
        assert_eq!(mount(repeat, true), 0, "{repeat}");
    }
    for change in ["path=/vfs-options", "namespace=other"] {
        assert_eq!(mount(change, true), -1, "{change}");
        assert_eq!(errno(), libc::EINVAL, "{change}");
    }
    assert_eq!(
        fs::metadata("/vfs-options/a")?.ino(),
        42,
        "display identity changed across sessions"
    );
    let gets = state.gets.load(Ordering::SeqCst);
    fs::metadata("/vfs-options/a")?;
    fs::metadata("/vfs-options/a")?;
    assert_eq!(state.gets.load(Ordering::SeqCst), gets + 4);
    assert_eq!(unsafe { libc::umount(c"/vfs-options".as_ptr()) }, 0);
    println!(
        "vfs acceptance: distinct wire IDs with colliding displayed inode numbers and inode hashes, statx sync flags, attribute lifetimes, overflow, mapped coherence, indexed retirement and remounts ok"
    );
    Ok(())
}

pub(crate) fn run() -> Result {
    load_module()?;
    // The unspecified IPv6 address also accepts IPv4 connections, so the one
    // listener serves the IPv4 session and the IPv6 one.
    let listener = TcpListener::bind((Ipv6Addr::UNSPECIFIED, 0))?;
    let port = listener.local_addr()?.port();
    let replies = Arc::new(Replies::default());
    let state = Arc::new(State::with(replies.clone()));
    let serving = state.clone();
    let peer =
        std::thread::spawn(move || serve_sessions(&listener, 2, &serving, |_| Ok(()), &|_| {}));
    exercise(port, &state, &replies)?;
    peer.join().map_err(|_| "VFS peer assertion failed")??;
    unload_module()?;
    super::hostile::run()
}
