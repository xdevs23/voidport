//! Directory reads: one wire request per kernel call, and the lookups each
//! call gives back to the server.
//!
//! Every readdirplus entry the server sends is an entry reply: it counts a
//! lookup on the server, and the server expects the client to balance it. The
//! kernel does that accounting itself **only** for entries it actually receives
//! through `readdirplus`. Two cases therefore need a compensating `forget`:
//!
//! * an entry left over when the reply buffer is full: it was counted on the
//!   server, but the kernel never receives it;
//! * **every** entry of a plain `readdir` — the kernel does no `nlookup`
//!   accounting for that call at all, so an uncompensated one would leak a
//!   server node per listed entry.
//!
//! Plain `readdir` is a defensive path: once `FUSE_DO_READDIRPLUS` is
//! negotiated without `FUSE_READDIRPLUS_AUTO`, the kernel always uses
//! readdirplus. The accounting is written once, here, and applies to both.
//!
//! **Each wire request asks for one page of entries** (see
//! [`entry_bytes_per_request`]), and the client stores nothing for a later
//! call. The kernel uses the attributes in a reply over any write that finished
//! before it asked, so every entry it receives must be read from the server
//! after the kernel call that receives it.

use fuser::{Errno, FileAttr, FileType};
use voidport_proto::ops::dir::ReaddirplusResponse;

use crate::client::{Caller, Client, DirEntry};
use crate::fuse::attr::{Privileged, dirent_kind, entry_attr};
use crate::fuse::errno;

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

/// One call of the kernel's into a directory: which listing, and where in it.
#[derive(Clone, Copy, Debug)]
pub struct DirectoryRead {
    /// The directory node being enumerated.
    pub node_id: u64,
    /// The open directory handle the enumeration belongs to.
    pub handle: u64,
    /// Where to resume: the offset of the last entry the kernel accepted, or
    /// zero at the start of the listing.
    pub cookie: u64,
}

/// Reads one page of a directory into `sink`, giving back every lookup the
/// kernel will not account for.
///
/// A short fill is not the end of the directory: the kernel resumes from the
/// last offset it received, and only an empty reply ends the enumeration.
///
/// `privileged` is the mount's own presentation of setuid and setgid, applied
/// here for the same reason it is applied to every other entry reply: a mount
/// that opted out shows the bits nowhere, a listing included.
///
/// # Errors
///
/// The server's errno, or `EIO` on a dead connection.
pub async fn read_directory<S: DirectorySink>(
    client: &Client,
    caller: Caller,
    read: DirectoryRead,
    privileged: Privileged,
    sink: &mut S,
) -> Result<(), Errno> {
    let mut entries = client
        .readdirplus(
            caller,
            read.node_id,
            read.handle,
            read.cookie,
            entry_bytes_per_request(client),
        )
        .await
        .map_err(errno)?;

    let mut delivered = 0;
    for item in &entries {
        let attr = entry_attr(&item.entry, privileged);
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

    // Whatever does not fit into the reply was counted on the server the moment
    // it was sent, and the kernel never receives it.
    forget_all(client, caller, entries.split_off(delivered)).await;

    // One `forget` per entry reply the kernel will not account for, because one
    // lookup was counted per entry reply — including when two entries name the
    // same node, as hardlinks in one directory do.
    if !sink.counts_lookups() {
        forget_all(client, caller, entries).await;
    }
    Ok(())
}

/// How many bytes of wire entries one readdirplus request asks for: one page,
/// or less where the frame bound of the session cannot carry a page.
///
/// One page is the smallest buffer that the kernel allocates for a FUSE call
/// that reads a directory. Since Linux 6.16 the kernel sizes that buffer by the
/// `getdents64` buffer of the caller, between one page and `max_pages`, and
/// before that it was always one page. The kernel sends that size with the
/// request, but `fuser` does not pass it to the callback. A wire entry is
/// shorter than the readdirplus record the kernel builds from it, so a page of
/// wire entries can have a few more entries than a buffer of one page takes.
fn entry_bytes_per_request(client: &Client) -> u32 {
    let page = u32::try_from(rustix::param::page_size())
        .expect("a page size fits into the u32 size of a readdirplus request");
    let budget = client.payload_budget::<ReaddirplusResponse>();
    u32::try_from(budget).map_or(page, |budget| page.min(budget))
}

/// Gives back one lookup per entry.
async fn forget_all(client: &Client, caller: Caller, entries: Vec<DirEntry>) {
    for entry in entries {
        client.forget(caller, entry.entry.node_id, 1).await;
    }
}
