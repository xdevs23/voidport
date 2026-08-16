//! Directory reads: the batch a listing is fetched in, and the lookup
//! accounting it owes.
//!
//! Every readdirplus entry the server sends is an entry reply: it counts a
//! lookup on the server, and the server expects the client to balance it. The
//! kernel does that accounting itself **only** for entries it actually receives
//! through `readdirplus`. Three cases therefore owe a compensating `forget`:
//!
//! * an entry the kernel's reply buffer refuses (it is full) and that this
//!   client does not keep for the next call — it was counted on the server but
//!   never reached the kernel;
//! * **every** entry of a plain `readdir` — the kernel does no `nlookup`
//!   accounting for that call at all, so an uncompensated one would leak a
//!   server node per listed entry;
//! * every entry still held for a directory handle when the enumeration is
//!   abandoned — the handle is released, the kernel seeks somewhere else in the
//!   listing, or another read of the same handle displaces what this one held.
//!
//! Plain `readdir` is a defensive path: once `FUSE_DO_READDIRPLUS` is
//! negotiated without `FUSE_READDIRPLUS_AUTO`, the kernel always uses
//! readdirplus. The accounting is written once, here, and applies to both.
//!
//! **The wire batch is not the kernel's buffer.** The server materializes the
//! whole listing at `opendir`, so what a listing costs in round trips is set by
//! how much of it one reply may carry — and the kernel hands FUSE a small
//! buffer per call. Asking the wire for one kernel buffer at a time made a
//! thousand-entry directory 32 round trips. This client asks for as much as the
//! negotiated frame bound allows (capped at [`BATCH_LIMIT`]) and **holds the
//! surplus per directory handle**, serving the kernel's later calls from it
//! without touching the wire. Held entries are entry replies like any other, so
//! they are given back with a `forget` the moment they are dropped, not
//! delivered. The batch size is entirely client-internal: it is the `size`
//! field the wire has always carried.
//!
//! **Held surplus expires with the attributes it carries.** An entry reply
//! carries attributes read when the server built it, and a mount promises a
//! guest that what it is told about a file is no older than the attribute
//! timeout. A walker slow enough to outlive that timeout — a build system
//! stat-ing each entry as it goes — would otherwise be served entries from a
//! batch fetched minutes ago, which is the very staleness the server side of
//! this pass removed. So surplus is usable only within the attr TTL of **its
//! own fetch**, timed from the wire reply and never refreshed by being carried
//! forward; older surplus is given back with its compensating `forget`s and the
//! listing is fetched again. Fast consumers keep the round-trip win; slow ones
//! pay a refetch instead of reading stale attributes (design: the 2026-08-14
//! optimisation-boundary disposition, "The client's held readdirplus surplus is
//! TTL-bounded").

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use fuser::{Errno, FileAttr, FileType};
use voidport_proto::ops::dir::ReaddirplusResponse;

use crate::client::{Caller, Client, DirEntry};
use crate::fuse::attr::{dirent_kind, entry_attr};
use crate::fuse::errno;

/// The most entry-stream bytes one wire readdirplus asks for.
///
/// The frame bound is a megabyte and the server sizes its reply buffer to what
/// the client asks for, so the ask is capped well below it: at ~130 bytes per
/// wire entry this is some five hundred entries a trip, which takes a
/// thousand-entry listing from 32 round trips to 2.
const BATCH_LIMIT: u32 = 64 * 1024;

/// One entry on its way to the kernel.
#[derive(Clone, Copy, Debug)]
pub struct DirectoryEntry<'a> {
    /// The server node id, which is also the presented inode number.
    pub node_id: u64,
    /// The entry's name.
    pub name: &'a [u8],
    /// The cookie that resumes enumeration after this entry.
    pub offset: u64,
    /// What kind of entry it is.
    pub kind: FileType,
    /// Its attributes.
    pub attr: &'a FileAttr,
    /// Its generation; 0 by contract.
    pub generation: u64,
}

/// Where directory entries are delivered.
///
/// The two implementations are the kernel's two directory replies; the trait
/// exists so the accounting above is written once and can be exercised without
/// a kernel — which matters for plain `readdir`, a path the kernel never takes
/// once readdirplus is negotiated.
pub trait DirectorySink {
    /// Offers one entry. Returns `true` when the buffer refused it because it
    /// is full — the entry was *not* delivered.
    fn offer(&mut self, entry: &DirectoryEntry<'_>) -> bool;

    /// Whether the kernel counts a lookup for every entry this sink accepts.
    ///
    /// False for plain `readdir`, whose entries the kernel does not account
    /// for, so the client must give every one of them back.
    fn counts_lookups(&self) -> bool;
}

/// One wire fetch: the entries it brought back, and when it happened.
///
/// Every entry carries a lookup the server counted when it sent it, so this is
/// a debt as much as a cache: nothing may drop it silently. The instant is the
/// age of the attributes in it, and it belongs to the *fetch* — a batch carried
/// forward across several kernel calls keeps the instant it was fetched at, or
/// a walk slow enough to matter would refresh its own staleness away.
#[derive(Debug)]
struct Batch {
    entries: Vec<DirEntry>,
    fetched: Instant,
}

impl Batch {
    /// Whether the attributes in it are still within `ttl`.
    fn fresh(&self, ttl: Duration) -> bool {
        self.fetched.elapsed() <= ttl
    }
}

/// The entries fetched for one directory handle and not yet delivered.
#[derive(Debug)]
struct Held {
    /// The cookie the first held entry resumes from.
    ///
    /// The kernel resumes an enumeration from the offset of the last entry it
    /// accepted, so held entries are usable only for exactly that cookie; a
    /// rewind or a seek anywhere else is a different position in the listing
    /// and the held entries are given back.
    cookie: u64,
    batch: Batch,
}

/// What each open directory handle is holding.
///
/// Everything for one mount: the adapter owns it, and a handle appears here only
/// between the call that over-fetched for it and the call that consumes or
/// abandons the surplus.
#[derive(Debug, Default)]
pub struct Directories {
    held: Mutex<HashMap<u64, Held>>,
}

impl Directories {
    /// Takes the entries held for `handle` at `cookie`, if they may still be
    /// served.
    ///
    /// Anything held at another cookie — or fetched longer than `ttl` ago — is
    /// not this call's, and comes back as [`Taken::Abandoned`] for the caller to
    /// give back.
    fn take(&self, handle: u64, cookie: u64, ttl: Duration) -> Taken {
        match self.lock().remove(&handle) {
            None => Taken::Nothing,
            Some(held) if held.cookie == cookie && held.batch.fresh(ttl) => {
                Taken::Resumed(held.batch)
            }
            Some(held) => Taken::Abandoned(held.batch.entries),
        }
    }

    /// Holds the rest of `batch` for the next call on `handle`, which will
    /// arrive at `cookie`, and hands back whatever it displaced.
    ///
    /// Held entries are lookup debt, so replacing them may not drop them. The
    /// call that fetched these took the handle's surplus first, so normally
    /// nothing is there and the answer is empty; two reads of one handle that
    /// overlap would each have found nothing and fetched, and the loser's
    /// entries would otherwise vanish having been counted on the server and
    /// never delivered to anyone. The caller gives back what comes out of here.
    #[must_use]
    fn keep(&self, handle: u64, cookie: u64, batch: Batch) -> Vec<DirEntry> {
        let mut held = self.lock();
        let displaced = if batch.entries.is_empty() {
            held.remove(&handle)
        } else {
            held.insert(handle, Held { cookie, batch })
        };
        displaced.map(|held| held.batch.entries).unwrap_or_default()
    }

    /// Drops everything held for `handle` and reports what it was.
    ///
    /// The caller owes a `forget` for each: the entries were counted on the
    /// server and never reached the kernel.
    #[must_use]
    fn abandon(&self, handle: u64) -> Vec<DirEntry> {
        self.lock()
            .remove(&handle)
            .map(|held| held.batch.entries)
            .unwrap_or_default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<u64, Held>> {
        self.held
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }
}

/// What a handle was holding when a call asked for its entries.
enum Taken {
    /// Nothing: the enumeration starts here, or the last call delivered
    /// everything it fetched.
    Nothing,
    /// A batch that resumes exactly at the requested cookie and is still inside
    /// the attribute timeout.
    Resumed(Batch),
    /// Entries this call may not serve — somewhere else in the listing, or
    /// fetched too long ago for their attributes to be told to a guest. They
    /// are owed back.
    Abandoned(Vec<DirEntry>),
}

/// Releases every entry a directory handle still holds.
///
/// Called when the handle is released: the enumeration is over, and entries
/// that were counted on the server but never delivered to the kernel are given
/// back here or not at all.
pub async fn release_directory(
    directories: &Directories,
    client: &Client,
    caller: Caller,
    handle: u64,
) {
    forget_all(client, caller, directories.abandon(handle)).await;
}

/// One call of the kernel's into a directory: which listing, and where in it.
#[derive(Clone, Copy, Debug)]
pub struct DirectoryRead {
    /// The directory node being enumerated.
    pub node_id: u64,
    /// The open directory handle the enumeration belongs to. The surplus is
    /// held per handle, so this is what names it.
    pub handle: u64,
    /// Where to resume: the offset of the last entry the kernel accepted, or
    /// zero at the start of the listing.
    pub cookie: u64,
}

/// Reads one batch of a directory into `sink`, giving back every lookup the
/// kernel will not account for.
///
/// A short fill is not the end of the directory: the kernel resumes from the
/// last offset it received, and only an empty reply ends the enumeration.
///
/// `attr_ttl` is the mount's attribute timeout: held surplus older than that is
/// dropped and refetched, not served, so no entry reply this returns
/// describes a file by attributes the guest may not believe.
///
/// # Errors
///
/// The server's errno, or `EIO` on a dead connection.
pub async fn read_directory<S: DirectorySink>(
    directories: &Directories,
    client: &Client,
    caller: Caller,
    read: DirectoryRead,
    attr_ttl: Duration,
    sink: &mut S,
) -> Result<(), Errno> {
    let DirectoryRead { handle, cookie, .. } = read;
    let batch = match directories.take(handle, cookie, attr_ttl) {
        Taken::Resumed(batch) => batch,
        Taken::Nothing => fetch(client, caller, read).await?,
        Taken::Abandoned(entries) => {
            // The kernel is enumerating from somewhere else — a rewind, or a
            // seek — or the surplus has aged past the attribute timeout. What
            // was held is owed back before anything new is counted.
            forget_all(client, caller, entries).await;
            fetch(client, caller, read).await?
        }
    };

    let mut delivered = 0;
    for item in &batch.entries {
        let attr = entry_attr(&item.entry);
        let refused = sink.offer(&DirectoryEntry {
            node_id: item.entry.node_id,
            name: &item.name,
            offset: item.next_cookie,
            kind: dirent_kind(item.entry_type, item.entry.attr.mode.get()),
            attr: &attr,
            generation: item.entry.generation,
        });
        if refused {
            break;
        }
        delivered += 1;
    }

    // Whatever the reply had no room for was counted on the server the moment
    // it was sent. It is kept for the call that resumes where the kernel
    // stopped — which is the offset of the last entry it accepted — instead of
    // being given back and fetched all over again. It keeps the instant of the
    // fetch it came from, so carrying it forward cannot outlive the timeout.
    let mut batch = batch;
    let surplus = Batch {
        entries: batch.entries.split_off(delivered),
        fetched: batch.fetched,
    };
    let resume = match delivered.checked_sub(1) {
        Some(last) => batch.entries[last].next_cookie,
        None => cookie,
    };
    // A surplus this displaced belongs to a read of the same handle that
    // overlapped this one. It was counted on the server and reached no kernel
    // buffer, so it is given back here, not dropped.
    forget_all(client, caller, directories.keep(handle, resume, surplus)).await;

    // One `forget` per entry reply the kernel will not account for, because one
    // lookup was counted per entry reply — including when two entries name the
    // same node, as hardlinks in one directory do.
    if !sink.counts_lookups() {
        forget_all(client, caller, batch.entries).await;
    }
    Ok(())
}

/// Fetches one wire batch of the listing, timed from the reply.
async fn fetch(client: &Client, caller: Caller, read: DirectoryRead) -> Result<Batch, Errno> {
    let entries = client
        .readdirplus(
            caller,
            read.node_id,
            read.handle,
            read.cookie,
            batch_bytes(client),
        )
        .await
        .map_err(errno)?;
    Ok(Batch {
        entries,
        fetched: Instant::now(),
    })
}

/// The entry-stream budget one wire readdirplus asks for on this session.
fn batch_bytes(client: &Client) -> u32 {
    let budget = client.payload_budget::<ReaddirplusResponse>();
    u32::try_from(budget).unwrap_or(u32::MAX).min(BATCH_LIMIT)
}

/// Gives back one lookup per entry.
async fn forget_all(client: &Client, caller: Caller, entries: Vec<DirEntry>) {
    for entry in entries {
        client.forget(caller, entry.entry.node_id, 1).await;
    }
}
