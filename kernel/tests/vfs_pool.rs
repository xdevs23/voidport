// SPDX-License-Identifier: GPL-2.0

use super::guest::{counter, require_zero, unmount_balanced, withholding_mount};
use super::server::{DISTINCT, join_readers, spawn_readers};
use crate::{Result, load_module, unload_module};
use std::fs;
use voidport_proto::opcode::Opcode;

const LOOKUPS: usize = 8;

fn start_lookups(first: u64) -> Vec<std::thread::JoinHandle<std::io::Result<fs::Metadata>>> {
    (first..first + LOOKUPS as u64)
        .map(|index| std::thread::spawn(move || fs::metadata(format!("/vfs-options/n{index}"))))
        .collect()
}

fn join_lookups(lookups: Vec<std::thread::JoinHandle<std::io::Result<fs::Metadata>>>) -> Result {
    for lookup in lookups {
        assert!(lookup.join().map_err(|_| "a lookup panicked")??.is_file());
    }
    Ok(())
}

pub(crate) fn parallel() -> Result {
    fs::create_dir_all("/vfs-options")?;
    load_module()?;
    let (withhold, state, peer) = withholding_mount()?;
    withhold.set(&[Opcode::Read]);
    let readers = spawn_readers(DISTINCT.start..DISTINCT.start + 1);
    withhold.wait(Opcode::Read, 1)?;
    withhold.set(&[Opcode::Read, Opcode::Lookup]);
    let lookups = start_lookups(100);
    withhold.wait(Opcode::Lookup, LOOKUPS)?;
    let connections = LOOKUPS as u64 + 1;
    assert_eq!(state.connections(1), connections, "the first run");
    assert_eq!(counter("connections_live")?, connections);
    withhold.flush()?;
    join_readers(readers)?;
    join_lookups(lookups)?;
    withhold.set(&[Opcode::Lookup]);
    let lookups = start_lookups(200);
    withhold.wait(Opcode::Lookup, 2 * LOOKUPS)?;
    assert_eq!(state.connections(1), connections, "the second run");
    withhold.flush()?;
    join_lookups(lookups)?;
    unmount_balanced(peer)?;
    assert_eq!(state.closed(1), connections);
    require_zero(&["connections_live"])?;
    unload_module()?;
    println!(
        "vfs acceptance: a read and {LOOKUPS} lookups each waited on a connection of their own, and the next {LOOKUPS} lookups reused them"
    );
    Ok(())
}
