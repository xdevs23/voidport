// SPDX-License-Identifier: GPL-2.0

use super::guest::{
    CONNECTION_TASK, UNIX_SOCKET, lasting, require_mount, task_named, unix_options,
    unmount_balanced,
};
use super::occupation::{Occupation, processors, run_only_on};
use super::server::{Handle, State, Withhold, serve_one};
use super::signals::{Counters, Outcome, signalled_open};
use crate::supervision::{Supervision, fork_child, unix_listener};
use crate::{LIMITS, Result, load_module, piece_of, unload_module};
use std::fs;
use std::sync::Arc;
use voidport_proto::frame::FrameWriter;
use voidport_proto::opcode::Opcode;
use voidport_proto::ops::share::{
    SHARE_KIND_DIRECTORY, SHARE_MODE_RO, ShareEntryHeader, ShareSnapshotPart,
};
use voidport_proto::piece::Closing;
use zerocopy::IntoBytes;

const SEND_BUFFER: &str = "/proc/sys/net/core/wmem_default";

/// Writes a notification of twice the send buffer of a unix socket to
/// `connection`, the socket of the peer, whose send buffer nothing changes.
/// A unix socket holds less than that of what the module has not read, so the
/// write returns only once the module has read part of the notification. The
/// thread that reads the connection reads it only after it has handed the
/// reply before it over and woken its caller.
fn read_past(connection: &mut dyn Handle) -> Result {
    let send_buffer: usize = fs::read_to_string(SEND_BUFFER)?.trim().parse()?;
    let mut buffer = [0; 128];
    let frame = FrameWriter::notification(&mut buffer, &LIMITS, &ShareSnapshotPart)?;
    let mut notification = frame.finish()?.to_vec();
    let path = [b'p'; 600];
    let entry = ShareEntryHeader::new(SHARE_MODE_RO, SHARE_KIND_DIRECTORY, path.len() as u32);
    let piece = piece_of(&[entry.as_bytes(), path.as_slice()].concat());
    while notification.len() < 2 * send_buffer {
        notification.extend_from_slice(&piece);
    }
    notification.extend_from_slice(&Closing::done(false).encode());
    connection.write_all(&notification)?;
    Ok(())
}

pub(crate) fn run() -> Result {
    fs::create_dir_all("/vfs-options")?;
    load_module()?;
    let processors = processors()?;
    run_only_on(0, processors.shared)
        .map_err(|error| format!("the case could not move to the shared processor: {error}"))?;
    let withhold = Arc::new(Withhold::default());
    let state = Arc::new(State::with(withhold.clone()));
    let peer = serve_one(unix_listener(UNIX_SOCKET)?, &state);
    require_mount(&format!(
        "{},{}",
        unix_options(UNIX_SOCKET)?.to_str()?,
        lasting()
    ));
    run_only_on(task_named(CONNECTION_TASK)?, processors.shared).map_err(|error| {
        format!("the connection thread could not move to the shared processor: {error}")
    })?;
    // The lookup is cached, so the open is the only request of the caller,
    // and it goes on the one connection, which is idle.
    fs::metadata("/vfs-options/a")?;
    withhold.set(&[Opcode::Open]);
    let before = Counters::read()?;
    let supervision = Supervision::new();
    let caller = fork_child(|| {
        signalled_open(Outcome::Answered, || {
            run_only_on(0, processors.occupied).is_ok()
        })
    });
    withhold.wait(Opcode::Open, 1)?;
    let occupation = Occupation::start(processors.occupied)?;
    withhold.flush_with(read_past)?;
    assert_eq!(unsafe { libc::kill(caller, libc::SIGUSR1) }, 0);
    occupation.end(&supervision)?;
    assert_eq!(supervision.reap(caller)?, 0, "the answered open");
    state.wait(1, |events| events.released == 1)?;
    unmount_balanced(peer)?;
    assert_eq!(
        Counters::read()?.since(&before),
        Counters {
            cancelled: 0,
            interrupted: 0,
            handles_opened: 1,
            orphans: 0,
        },
        "the signal ended a request whose reply had arrived"
    );
    unload_module()?;
    println!(
        "vfs acceptance: a signal that found the reply arrived left the caller with the reply"
    );
    Ok(())
}
