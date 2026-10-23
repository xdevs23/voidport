// SPDX-License-Identifier: GPL-2.0

use super::guest::{
    SIGUSR1_HANDLED, count_sigusr1, errno, lasting, look_up, mount_peer, raw_mount,
    unmount_balanced,
};
use super::server::{
    Behaviour, Flow, MADE, Settled, State, Stream, Withhold, busy, join_readers, serve_one,
};
use crate::supervision::{Supervision, fork_child};
use crate::{Result, load_module, unload_module};
use std::ffi::CString;
use std::fs::{self, File};
use std::net::{Ipv4Addr, TcpListener};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use voidport_proto::frame::Frame;
use voidport_proto::opcode::Opcode;
use voidport_proto::ops::connection::outcome_state;

#[derive(Clone, Copy, Debug)]
pub(crate) enum Case {
    NotStarted,
    AppliedForget,
    DepartedLookup,
    SignalledOutcome,
    SignalledMkdir,
}

#[derive(Default)]
struct Cutting {
    withhold: Withhold,
    before: Mutex<Vec<Opcode>>,
    after: Mutex<Vec<Opcode>>,
}

fn cut(cuts: &Mutex<Vec<Opcode>>, frame: &Frame<'_>) -> Result<Flow> {
    let opcode = frame.opcode()?;
    let mut cuts = cuts.lock().unwrap();
    let Some(at) = cuts.iter().position(|cut| *cut == opcode) else {
        return Ok(Flow::Next);
    };
    cuts.remove(at);
    println!(
        "vfs peer: the connection of {opcode:?} request={} is cut",
        frame.request_id()
    );
    Ok(Flow::Sever)
}

impl Behaviour for Cutting {
    fn arrived(&self, _state: &State, _serial: u64, frame: &Frame<'_>) -> Result<Flow> {
        cut(&self.before, frame)
    }

    fn applied(&self, _state: &State, _serial: u64, frame: &Frame<'_>) -> Result<Flow> {
        cut(&self.after, frame)
    }

    fn deliver(
        &self,
        state: &State,
        serial: u64,
        frame: &Frame<'_>,
        reply: Vec<u8>,
        stream: &mut dyn Stream,
    ) -> Result<Flow> {
        self.withhold.deliver(state, serial, frame, reply, stream)
    }

    fn ended(&self) {
        self.withhold.ended();
    }
}

fn require_settled(settled: &[Settled], state: u32, count: usize) {
    assert_eq!(settled.len(), 2 * count, "{settled:?}");
    for pair in settled.chunks(2) {
        let [
            Settled::Asked {
                connection,
                state: answered,
                ..
            },
            Settled::Retired {
                connection: retired,
            },
        ] = pair
        else {
            panic!("an outcome request and a retire out of order: {settled:?}");
        };
        assert_eq!((*answered, *retired), (state, *connection), "{settled:?}");
    }
}

fn not_started(cutting: &Cutting, state: &State) -> Result {
    let file = File::open("/vfs-options/a")?;
    fs::metadata("/vfs-options/n9")?;
    let readers = busy(&cutting.withhold)?;
    *cutting.before.lock().unwrap() = vec![Opcode::Forget, Opcode::Release];
    fs::write("/proc/sys/vm/drop_caches", "3")?;
    state.wait_forgotten(1, &[(9, 1)])?;
    state.wait_retired(1, 1)?;
    drop(file);
    state.wait(1, |events| events.released == 1)?;
    let settled = state.wait_retired(1, 2)?;
    require_settled(&settled, outcome_state::NOT_STARTED, 2);
    cutting.withhold.flush()?;
    join_readers(readers)
}

fn applied_forget(cutting: &Cutting, state: &State) -> Result {
    fs::metadata("/vfs-options/n9")?;
    let readers = busy(&cutting.withhold)?;
    *cutting.after.lock().unwrap() = vec![Opcode::Forget];
    fs::write("/proc/sys/vm/drop_caches", "3")?;
    let settled = state.wait_retired(1, 1)?;
    require_settled(&settled, outcome_state::APPLIED, 1);
    // A second forget of the node would fail the peer.
    assert_eq!(state.forgotten(1, 9), 1);
    cutting.withhold.flush()?;
    join_readers(readers)
}

fn departed_lookup(withhold: &Withhold, state: &State) -> Result {
    let readers = busy(withhold)?;
    withhold.set(&[Opcode::Read, Opcode::Lookup]);
    let child = fork_child(|| look_up(c"/vfs-options/n9"));
    withhold.wait(Opcode::Lookup, 1)?;
    Supervision::new().kill_and_reap(child, "the lookup")?;
    withhold.sever(Opcode::Lookup)?;
    state.wait_forgotten(1, &[(9, 1)])?;
    let settled = state.wait_retired(1, 1)?;
    require_settled(&settled, outcome_state::REPLIED, 1);
    withhold.flush()?;
    join_readers(readers)
}

fn interrupted_lookup() -> libc::c_int {
    if !count_sigusr1() {
        return 1;
    }
    let mut status: libc::stat = unsafe { std::mem::zeroed() };
    let looked_up = unsafe { libc::stat(c"/vfs-options/n9".as_ptr(), &mut status) };
    let interrupted = looked_up == -1 && errno() == libc::EINTR;
    if interrupted && SIGUSR1_HANDLED.load(Ordering::Relaxed) == 1 {
        0
    } else {
        1
    }
}

fn signalled_outcome(withhold: &Withhold, state: &State) -> Result {
    let readers = busy(withhold)?;
    withhold.set(&[Opcode::Read, Opcode::Lookup, Opcode::Outcome]);
    let child = fork_child(interrupted_lookup);
    withhold.wait(Opcode::Lookup, 1)?;
    withhold.sever(Opcode::Lookup)?;
    withhold.wait(Opcode::Outcome, 1)?;
    assert_eq!(unsafe { libc::kill(child, libc::SIGUSR1) }, 0);
    assert_eq!(
        Supervision::new().reap(child)?,
        0,
        "the lookup whose caller the signal took away"
    );
    withhold.wait(Opcode::Outcome, 2)?;
    withhold.flush()?;
    state.wait_forgotten(1, &[(9, 1)])?;
    let settled = state.wait_retired(1, 1)?;
    let [first, second, Settled::Retired { connection }] = settled[..] else {
        panic!("not two outcome requests and a retire: {settled:?}");
    };
    assert_eq!(
        first, second,
        "the second outcome request asks about another request"
    );
    assert!(
        matches!(first, Settled::Asked { connection: asked, state, .. }
            if asked == connection && state == outcome_state::REPLIED),
        "{settled:?}"
    );
    join_readers(readers)
}

fn signalled_mkdir_child() -> libc::c_int {
    if !count_sigusr1() {
        return 1;
    }
    let path = CString::new(format!("/vfs-options/{MADE}")).unwrap();
    let made = unsafe { libc::mkdir(path.as_ptr(), 0o755) };
    if made == 0 && SIGUSR1_HANDLED.load(Ordering::Relaxed) == 1 {
        0
    } else {
        1
    }
}

fn blocks(pid: libc::pid_t, signal: libc::c_int) -> Result<bool> {
    let status = fs::read_to_string(format!("/proc/{pid}/status"))?;
    let blocked = status
        .lines()
        .find_map(|line| line.strip_prefix("SigBlk:"))
        .ok_or("a status without SigBlk")?;
    Ok(u64::from_str_radix(blocked.trim(), 16)? & (1 << (signal - 1)) != 0)
}

fn signalled_mkdir(withhold: &Withhold, state: &State) -> Result {
    let readers = busy(withhold)?;
    withhold.set(&[Opcode::Read, Opcode::Mkdir, Opcode::Outcome]);
    let child = fork_child(signalled_mkdir_child);
    withhold.wait(Opcode::Mkdir, 1)?;
    withhold.sever(Opcode::Mkdir)?;
    withhold.wait(Opcode::Outcome, 1)?;
    assert!(
        blocks(child, libc::SIGUSR1)?,
        "the caller does not block SIGUSR1 while it asks"
    );
    assert_eq!(unsafe { libc::kill(child, libc::SIGUSR1) }, 0);
    withhold.flush()?;
    assert_eq!(
        Supervision::new().reap(child)?,
        0,
        "the mkdir that the signal reached while it asked"
    );
    let settled = state.wait_retired(1, 1)?;
    require_settled(&settled, outcome_state::REPLIED, 1);
    join_readers(readers)
}

fn mount_writable_peer(state: &Arc<State>) -> Result<std::thread::JoinHandle<Result>> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let port = listener.local_addr()?.port();
    let peer = serve_one(listener, state);
    let options = CString::new(format!("addr=127.0.0.1,port={port},{}", lasting()))?;
    if raw_mount(c"vfs-options", c"/vfs-options", &options, 0) != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(peer)
}

pub(crate) fn run(case: Case) -> Result {
    fs::create_dir_all("/vfs-options")?;
    load_module()?;
    let cutting = Arc::new(Cutting::default());
    let state = Arc::new(State::with(cutting.clone()));
    let peer = match case {
        Case::SignalledMkdir => mount_writable_peer(&state)?,
        _ => mount_peer(&state, &lasting())?,
    };
    match case {
        Case::NotStarted => not_started(&cutting, &state)?,
        Case::AppliedForget => applied_forget(&cutting, &state)?,
        Case::DepartedLookup => departed_lookup(&cutting.withhold, &state)?,
        Case::SignalledOutcome => signalled_outcome(&cutting.withhold, &state)?,
        Case::SignalledMkdir => signalled_mkdir(&cutting.withhold, &state)?,
    }
    unmount_balanced(peer)?;
    unload_module()?;
    println!("vfs acceptance: {case:?} was settled after the loss of one connection");
    Ok(())
}
