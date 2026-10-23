//! Every readdirplus entry the server sends counts a lookup on the server, which
//! the client balances with a `forget`. The kernel balances only the entries it
//! receives through `readdirplus`, so three cases owe a `forget`: an entry that
//! the reply of the kernel refuses because it is full, every entry of a plain
//! `readdir`, and every entry of a listing that ends in an errno. A lookup is
//! owed back only to the session that counted it, so each is given back stamped
//! with the generation of that session, and the entries of a session that has
//! ended went with it.
//!
//! A short batch is not the end of the directory. Only the exhausted bit of the
//! closing piece of a reply is.

use std::any::Any;

use rustix::io::Errno;
use voidport_fuse::{Attributes, FileType};

use crate::client::{Caller, Client, DirEntry, EntrySink};
use crate::fuse::attr::{Privileged, dirent_kind, entry_attr};

#[derive(Clone, Copy, Debug)]
pub struct DirectoryEntry<'a> {
    pub node_id: u64,
    pub name: &'a [u8],
    pub offset: u64,
    pub kind: FileType,
    pub attributes: &'a Attributes,
    pub generation: u64,
}

pub trait DirectorySink: Send + 'static {
    /// Returns `true` when the buffer refused the entry because it is full.
    fn offer(&mut self, entry: &DirectoryEntry<'_>) -> bool;

    /// False for plain `readdir`, whose entries the kernel does not account for.
    fn counts_lookups(&self) -> bool;
}

#[derive(Clone, Copy, Debug)]
pub struct DirectoryRead {
    pub node_id: u64,
    pub handle: u64,
    pub cookie: u64,
}

struct Offer<S> {
    sink: S,
    privileged: Privileged,
    /// The cookie after the last entry the sink took.
    cookie: u64,
    full: bool,
}

impl<S: DirectorySink> EntrySink for Offer<S> {
    fn offer(&mut self, entry: &DirEntry) -> bool {
        let attributes = entry_attr(&entry.entry, self.privileged);
        let refused = self.sink.offer(&DirectoryEntry {
            node_id: entry.entry.node_id,
            name: &entry.name,
            offset: entry.next_cookie,
            kind: dirent_kind(entry.entry_type, entry.entry.attr.mode.get()),
            attributes: &attributes,
            generation: entry.entry.generation,
        });
        if refused {
            self.full = true;
        } else {
            self.cookie = entry.next_cookie;
        }
        refused
    }
}

/// The sink comes back with the outcome. An errno means the kernel must be
/// answered that errno, and the entries the sink took were given back.
pub async fn read_directory<S: DirectorySink>(
    client: &Client,
    caller: Caller,
    read: DirectoryRead,
    privileged: Privileged,
    sink: S,
) -> (Option<S>, Result<(), Errno>) {
    let counts_lookups = sink.counts_lookups();
    let mut offer = Box::new(Offer {
        sink,
        privileged,
        cookie: read.cookie,
        full: false,
    });
    // A later request that ends in an errno answers the kernel that errno, so
    // what the sink took over the earlier requests is owed back too, each batch
    // to the session that answered it.
    let mut taken: Vec<Taken> = Vec::new();
    let page = u32::try_from(rustix::param::page_size()).unwrap_or(u32::MAX);
    let outcome = loop {
        let listing = client
            .readdirplus(caller, read.node_id, read.handle, offer.cookie, page, offer)
            .await;
        let any: Box<dyn Any> = listing.sink;
        offer = match any.downcast::<Offer<S>>() {
            Ok(offer) => offer,
            Err(_) => return (None, Err(Errno::IO)),
        };
        match listing.outcome {
            Ok(exhausted) => {
                // A batch that brought nothing and is not the end would be
                // asked again from the same cookie for ever; the server never
                // sends one, since a first entry too large is refused.
                let progressed = !listing.accepted.is_empty();
                if let Some(generation) = listing.generation {
                    taken.push(Taken {
                        generation,
                        node_ids: listing.accepted,
                    });
                }
                if exhausted || offer.full || !progressed {
                    break Ok(());
                }
            }
            Err(error) => {
                forget_all(client, caller, std::mem::take(&mut taken)).await;
                break Err(error);
            }
        }
    };
    // One lookup was counted per entry reply, including when two entries name
    // the same node, as hardlinks in one directory do.
    if outcome.is_ok() && !counts_lookups {
        forget_all(client, caller, taken).await;
    }
    (Some(offer.sink), outcome)
}

struct Taken {
    generation: u64,
    node_ids: Vec<u64>,
}

/// A batch answered by a session that has since ended owes nothing: its lookups
/// went with it.
async fn forget_all(client: &Client, caller: Caller, taken: Vec<Taken>) {
    for batch in taken {
        for node_id in batch.node_ids {
            client.forget_on(caller, batch.generation, node_id, 1).await;
        }
    }
}
