// SPDX-License-Identifier: GPL-2.0

use super::guest::{counter, require_zero, stat, unmount_balanced, withholding_mount};
use super::server::{DISTINCT, flush_readers, spawn_readers};
use crate::{Result, load_module, unload_module};
use std::fs::{self, File};
use std::sync::atomic::Ordering;
use voidport_proto::opcode::Opcode;

const READ_REQUESTS: usize = DISTINCT.end as usize - DISTINCT.start as usize;

const RELEASES: u64 = 32;

pub(crate) fn run() -> Result {
    fs::create_dir_all("/vfs-options")?;
    load_module()?;
    let (withhold, state, peer) = withholding_mount()?;
    let metadata = File::open("/vfs-options/a")?;
    let released = (0..RELEASES)
        .map(|index| File::open(format!("/vfs-options/n{}", 6000 + index)))
        .collect::<std::io::Result<Vec<_>>>()?;
    withhold.set(&[Opcode::Read, Opcode::Release]);
    let readers = spawn_readers(DISTINCT);
    withhold.wait(Opcode::Read, READ_REQUESTS)?;
    assert_eq!(counter("reads_in_flight")?, READ_REQUESTS as u64);
    assert_eq!(counter("requests_in_flight")?, READ_REQUESTS as u64);
    assert!(counter("reads_peak")? >= READ_REQUESTS as u64);
    // Metadata needs no slot set aside for it while every request waits.
    let gets = state.gets.load(Ordering::SeqCst);
    stat(&metadata, libc::AT_STATX_FORCE_SYNC)?;
    drop(released);
    withhold.wait(Opcode::Release, RELEASES as usize)?;
    assert_eq!(
        counter("requests_in_flight")?,
        READ_REQUESTS as u64 + RELEASES
    );
    assert!(counter("requests_peak")? >= READ_REQUESTS as u64 + RELEASES);
    // A connection carries one request at a time.
    assert!(counter("connections_live")? >= READ_REQUESTS as u64 + RELEASES);
    assert_eq!(counter("handles_released")?, 0);
    stat(&metadata, libc::AT_STATX_FORCE_SYNC)?;
    assert_eq!(state.gets.load(Ordering::SeqCst), gets + 2);
    flush_readers(readers)?;
    drop(metadata);
    unmount_balanced(peer)?;
    require_zero(&["reads_in_flight"])?;
    unload_module()?;
    println!(
        "vfs acceptance: {READ_REQUESTS} withheld requests each got their own reply on a connection of their own; metadata and {RELEASES} releases went on beside them"
    );
    Ok(())
}
