// SPDX-License-Identifier: GPL-2.0

use super::guest::{
    counter, endless_stall, lasting, look_up, mount_peer, require_mount, unmount_balanced,
};
use super::server::{
    Behaviour, Flow, Rendezvous, State, Stream, Withhold, busy, join_readers, refused_join, send,
    serve_sessions,
};
use crate::supervision::{Supervision, fork_child};
use crate::{Result, eof, load_module, unload_module};
use std::fs::{self, File};
use std::net::{Ipv4Addr, TcpListener};
use std::os::fd::AsRawFd;
use std::sync::Arc;
use voidport_proto::frame::Frame;
use voidport_proto::opcode::Opcode;

#[derive(Clone, Copy, Debug)]
pub(crate) enum Case {
    Silent,
    Teardown,
    Refused,
}

#[derive(Default)]
struct Joins {
    arrived: usize,
    closed: usize,
}

#[derive(Default)]
struct Joining {
    withhold: Withhold,
    refuses: bool,
    joins: Rendezvous<Joins>,
}

impl Behaviour for Joining {
    fn join(
        &self,
        _state: &State,
        _serial: u64,
        id: u64,
        reply: &[u8],
        stream: &mut dyn Stream,
    ) -> Result<Flow> {
        let mut first = false;
        self.joins.update(|joins| {
            first = joins.arrived == 0;
            joins.arrived += 1;
        });
        if !first {
            return send(stream, reply);
        }
        if self.refuses {
            return send(stream, &refused_join(id)?);
        }
        eof(stream)?;
        self.joins.update(|joins| joins.closed += 1);
        Ok(Flow::Next)
    }

    fn deliver(
        &self,
        state: &State,
        serial: u64,
        frame: &Frame<'_>,
        reply: Vec<u8>,
        stream: &mut dyn Stream,
    ) -> Result<Flow> {
        if serial == 1 {
            self.withhold.deliver(state, serial, frame, reply, stream)
        } else {
            send(stream, &reply)
        }
    }

    fn ended(&self) {
        self.withhold.ended();
        self.joins.end();
    }
}

fn silent(joining: &Joining, state: &State) -> Result {
    let readers = busy(&joining.withhold)?;
    let lost = counter("connections_lost")?;
    let child = fork_child(|| look_up(c"/vfs-options/n9"));
    joining.joins.wait(|joins| joins.closed == 1)?;
    assert_eq!(state.connections(1), 2, "the lookup opened a second join");
    assert_eq!(
        state.lookups(1, "n9"),
        0,
        "the lookup went on before a give-back"
    );
    joining.withhold.flush()?;
    assert_eq!(Supervision::new().reap(child)?, 0, "the lookup");
    assert_eq!(state.lookups(1, "n9"), 1);
    join_readers(readers)?;
    assert_eq!(counter("connections_lost")?, lost);
    Ok(())
}

fn teardown(joining: &Joining) -> Result {
    let file = File::open("/vfs-options/a")?;
    joining.withhold.set(&[Opcode::Lookup]);
    // The child closes the descriptor of the file that it inherits, so that
    // the close in this process releases the file.
    let descriptor = file.as_raw_fd();
    let child = fork_child(|| {
        unsafe { libc::close(descriptor) };
        look_up(c"/vfs-options/n9")
    });
    joining.withhold.wait(Opcode::Lookup, 1)?;
    drop(file);
    joining.joins.wait(|joins| joins.arrived == 1)?;
    Supervision::new().kill_and_reap(child, "the lookup")?;
    // The reply that no caller waits for any more goes out, so the peer holds
    // no copy of its connection, which would keep the end of the peer open
    // through the unmount.
    joining.withhold.flush()
}

fn refused(joining: &Joining, state: &State) -> Result {
    joining.withhold.set(&[Opcode::Lookup]);
    let lost = counter("connections_lost")?;
    let supervision = Supervision::new();
    let busy = fork_child(|| look_up(c"/vfs-options/n8"));
    joining.withhold.wait(Opcode::Lookup, 1)?;
    let joined = fork_child(|| look_up(c"/vfs-options/n9"));
    for (child, name) in [(joined, "n9"), (busy, "n8")] {
        assert_eq!(supervision.reap(child)?, 0, "the lookup of {name}");
        assert_eq!(state.lookups(2, name), 1, "{name}");
    }
    assert_eq!(state.lookups(1, "n9"), 0);
    assert_eq!(counter("connections_lost")?, lost + 1);
    Ok(())
}

pub(crate) fn run(case: Case) -> Result {
    fs::create_dir_all("/vfs-options")?;
    load_module()?;
    let joining = Arc::new(Joining {
        refuses: matches!(case, Case::Refused),
        ..Joining::default()
    });
    let state = Arc::new(State::with(joining.clone()));
    let peer = match case {
        Case::Silent | Case::Teardown => mount_peer(&state, &lasting())?,
        Case::Refused => {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
            let port = listener.local_addr()?.port();
            let serving = state.clone();
            let peer = std::thread::spawn(move || {
                serve_sessions(&listener, 2, &serving, |_| Ok(()), &|_| {})
            });
            require_mount(&format!(
                "addr=127.0.0.1,port={port},{},{}",
                lasting(),
                endless_stall()
            ));
            peer
        }
    };
    match case {
        Case::Silent => silent(&joining, &state)?,
        Case::Teardown => teardown(&joining)?,
        Case::Refused => refused(&joining, &state)?,
    }
    unmount_balanced(peer)?;
    if let Case::Teardown = case {
        joining.joins.wait(|joins| joins.closed == 1)?;
    }
    unload_module()?;
    println!("vfs acceptance: the join of {case:?} ended as the module requires");
    Ok(())
}
