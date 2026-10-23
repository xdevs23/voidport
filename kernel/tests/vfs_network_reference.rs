// SPDX-License-Identifier: GPL-2.0

use super::guest::{ABSENT_SOCKET, UNIX_SOCKET, unix_options};
use super::links::{LinkRemovals, link_pair};
use super::server::{State, spawn_vfs_peer};
use super::sockets::{
    in_new_network, mount_in_network, read_across_reconnect, require_mount_in_network,
};
use super::transitions::{Attempt, Reconnecting};
use crate::supervision::{Supervision, clear_socket_path, unix_listener};
use crate::{Result, load_module, unload_module};
use std::ffi::CString;
use std::fs::{self, File};
use std::sync::Arc;

fn new_network(name: &str) -> Result<(File, u32)> {
    let ((), network) = in_new_network(|| Ok(()))?;
    let link = link_pair(&network, name)?;
    Ok((network, link))
}

/// Requires the namespace with the link `link` in the initial namespace to
/// exist once the kernel has destroyed every network namespace that nothing
/// referred to when this was called, and has announced the removal of their
/// links. Fails with `message` otherwise.
///
/// The kernel destroys such namespaces on a work queue, in batches that do not
/// overlap. A sentinel namespace that is made now and let go of is queued
/// behind them, so its removal is announced in their batch or after it. A
/// batch announces its removals under the lock that creating a link needs, so
/// a pair created after the removal of the sentinel waits for the batch to
/// end, and then every announcement of the batch is in the socket.
fn require_namespace_exists(removals: &mut LinkRemovals, link: u32, message: &str) -> Result {
    let (sentinel, sentinel_link) = new_network("vp-sentinel")?;
    drop(sentinel);
    removals.wait_removed(sentinel_link)?;
    new_network("vp-after")?;
    assert!(!removals.removed(link)?, "{message}");
    Ok(())
}

fn held_by_mount(removals: &mut LinkRemovals) -> Result {
    let (network, link) = new_network("vp-held")?;
    let state = Arc::new(State::default());
    let supervision = Supervision::new();
    let (peer, first) = spawn_vfs_peer(unix_listener(UNIX_SOCKET)?, &state, 2, &supervision);
    require_mount_in_network(&network, &unix_options(UNIX_SOCKET)?, &supervision)?;
    drop(network);
    read_across_reconnect("/vfs-options", &first, &state, &supervision)?;
    require_namespace_exists(
        removals,
        link,
        "the namespace was destroyed while the mount lasted",
    )?;
    assert_eq!(unsafe { libc::umount(c"/vfs-options".as_ptr()) }, 0);
    peer.join().map_err(|_| "unix socket peer failed")??;
    removals.wait_removed(link)
}

fn released_by_failed_connect(removals: &mut LinkRemovals) -> Result {
    let (network, link) = new_network("vp-failed")?;
    clear_socket_path(ABSENT_SOCKET)?;
    let options = unix_options(ABSENT_SOCKET)?;
    let status = mount_in_network(&network, &options, &Supervision::new())?;
    assert_ne!(
        status, 0,
        "the mount to a path where nothing listens succeeded"
    );
    drop(network);
    removals.wait_removed(link)
}

fn released_by_expired_attempt(removals: &mut LinkRemovals) -> Result {
    let (network, link) = new_network("vp-expired")?;
    let reconnecting =
        Reconnecting::start(unix_listener(UNIX_SOCKET)?, Attempt::Silent, |options| {
            require_mount_in_network(&network, &CString::new(options)?, &Supervision::new())
        })?;
    drop(network);
    reconnecting.wait_expired()?;
    require_namespace_exists(
        removals,
        link,
        "the namespace was destroyed after an attempt expired",
    )?;
    reconnecting.unmount()?;
    removals.wait_removed(link)
}

pub(crate) fn run() -> Result {
    fs::create_dir_all("/vfs-options")?;
    load_module()?;
    let mut removals = LinkRemovals::subscribe()?;
    held_by_mount(&mut removals)?;
    released_by_failed_connect(&mut removals)?;
    released_by_expired_attempt(&mut removals)?;
    unload_module()?;
    println!(
        "vfs acceptance: the network namespace a mount was made in existed until the unmount, also after a reconnect attempt expired, and was destroyed after a mount failed to connect"
    );
    Ok(())
}
