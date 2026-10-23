use std::sync::Arc;

use rustix::io::Errno;
use voidport_memory::Buffer;
use voidport_proto::frame::{Frame, FrameWriter};
use voidport_proto::limits::LIMITS;
use voidport_proto::opcode::Opcode;
use voidport_proto::ops::dir::{
    DirEntryHeader, ReaddirplusRequest, ReaddirplusResponse, listing_reply_bound,
};
use voidport_proto::piece::{self, Closing};

use super::super::ops;
use super::super::ops::dir::Admit;
use super::super::pool::Thread;
use super::super::session::{Kept, Link};
use super::super::wire::{Out as _, ReplySink};
use super::{Connection, Counted, Replies};

/// The size the request asks for is the sum of entry bytes the reply will not
/// exceed. An entry that is still there is admitted only when it fits in what
/// the reply has left, so an entry that does not fit is never counted: a first
/// one is refused with `EOVERFLOW`, and a later one ends the reply. An entry
/// that is part of the reply counts as a lookup and is still counted when a later
/// one fails.
///
/// The first entry is admitted before the sink is taken, so a listing refused
/// whole is a reply of one frame, and the host work of that first admission
/// does not hold the other replies of the connection.
///
/// A listing counts lookups on the server, so once it has started it runs to
/// its end whether or not the connection stops, and the session stores its whole
/// reply: a client that loses the connection takes that reply instead of
/// listing again and counting every entry twice. The kept reply is built in a
/// buffer made before the first entry is admitted, of the most bytes a reply to
/// the request takes, so building it has no failure of its own. An admission
/// that unwinds once an entry may have been counted ends the session, so the
/// listing is never answered as never started after it counted entries.
///
/// Until its first admission a listing has counted nothing, so the waits for
/// its two buffers end when the connection closes, and the listing then never
/// started.
pub(super) async fn list<P: Replies>(
    connection: Arc<Connection<P>>,
    bytes: Vec<u8>,
    named: Result<ops::dir::Listing, Errno>,
    waiting: Counted,
) {
    let (request_id, size) = {
        let Ok(frame) = Frame::parse(&bytes, &LIMITS) else {
            return connection.stop();
        };
        match frame.request::<ReaddirplusRequest>() {
            Ok(request) => (frame.request_id(), request.body().size.get()),
            Err(error) => return connection.poison(&error),
        }
    };
    let listing = match named {
        Ok(listing) => Arc::new(listing),
        Err(errno) => {
            drop(waiting);
            return refuse_listing(&connection, request_id, errno).await;
        }
    };
    let Ok(piece) = connection
        .buffer(size_of::<DirEntryHeader>() + LIMITS.name_max as usize, 1)
        .await
    else {
        return;
    };
    let Ok(buffer) = connection.buffer(listing_reply_bound(size), 1).await else {
        return;
    };
    let Ok(mut kept) = KeptListing::within(buffer, request_id) else {
        return connection.unkept();
    };
    // A listing runs to its end once read: its first thread is waited for
    // whether or not the connection stops meanwhile.
    let thread = connection.plane.pool().acquire().await;
    drop(waiting);
    let Ok(thread) = thread else {
        return;
    };
    let mut entries = Admission {
        connection: &connection,
        listing,
        piece: Some(piece),
        thread: Some(thread),
        index: 0,
    };

    let size = u64::from(size);
    let first = match entries.next(room(size)).await {
        Ok(Next::Entry(entry)) => Ok(Some(entry)),
        Ok(Next::Exhausted) => Ok(None),
        Ok(Next::Unfit) => Err(Errno::OVERFLOW),
        Ok(Next::Failed) => return,
        Err(errno) => Err(errno),
    };
    let first = match first {
        Ok(first) => first,
        Err(errno) => {
            drop((entries, kept));
            return refuse_listing(&connection, request_id, errno).await;
        }
    };

    // The sink while the connection can take the reply; without it, the
    // listing goes on into the kept reply alone.
    let mut sink = connection.sink(request_id).await.ok();
    let mut reply = match sink.as_mut() {
        Some(sink) => match ReplySink::new::<ReaddirplusResponse>(sink, request_id) {
            Ok(reply) => Some(reply),
            Err(_) => {
                connection.stop();
                None
            }
        },
        None => None,
    };
    let mut sent = 0u64;
    let mut next = first.map(Next::Entry).map_or(Ok(Next::Exhausted), Ok);
    let (status, exhausted) = loop {
        match next {
            Ok(Next::Exhausted) => break (Ok(()), true),
            Ok(Next::Unfit) => break (Ok(()), false),
            Ok(Next::Failed) => return connection.unkept(),
            Err(errno) => break (Err(errno), false),
            Ok(Next::Entry(entry)) => {
                let bytes = entries.piece(entry.len);
                if kept.piece(bytes).is_err() {
                    connection.session.nodes().forget(entry.node_id, 1);
                    return connection.unkept();
                }
                if let Some(live) = reply.as_mut()
                    && live.piece(bytes).await.is_err()
                {
                    reply = None;
                    connection.stop();
                }
                sent += entry.len as u64;
            }
        }
        next = entries.next(room(size - sent)).await;
    };
    drop(entries);
    if kept.keep(&connection.link, status, exhausted).is_err() {
        return connection.unkept();
    }
    connection.retire(request_id);
    if let Some(mut live) = reply
        && live.close(status, exhausted).await.is_ok()
    {
        drop(live);
        if let Some(sink) = sink.as_mut()
            && sink.flush().await.is_err()
        {
            connection.stop();
        }
    } else {
        connection.stop();
    }
}

fn room(left: u64) -> usize {
    usize::try_from(left).unwrap_or(usize::MAX)
}

async fn refuse_listing<P: Replies>(connection: &Connection<P>, request_id: u64, errno: Errno) {
    match ops::error_reply(request_id, Opcode::Readdirplus, errno) {
        Ok(reply) => {
            connection.keep_reply(request_id, &reply).await;
            connection.answer(request_id, &reply).await;
        }
        Err(error) => connection.poison(&error),
    }
}

struct KeptListing {
    buffer: Buffer,
    len: usize,
    request_id: u64,
}

/// A listing makes its buffer of the most bytes its reply takes and admits only
/// entries that fit, so this is a defect when it happens.
#[derive(Debug)]
struct Unbuilt;

impl KeptListing {
    fn within(buffer: Buffer, request_id: u64) -> Result<Self, Unbuilt> {
        let mut kept = Self {
            buffer,
            len: 0,
            request_id,
        };
        let mut head = [0u8; FrameWriter::response_len::<ReaddirplusResponse>(0)];
        let head = FrameWriter::response(&mut head, &LIMITS, request_id, &ReaddirplusResponse)
            .and_then(FrameWriter::finish)
            .map_err(|_| Unbuilt)?;
        kept.put(head)?;
        Ok(kept)
    }

    fn put(&mut self, bytes: &[u8]) -> Result<(), Unbuilt> {
        let end = self.len.checked_add(bytes.len()).ok_or(Unbuilt)?;
        let room = self.buffer.get_mut(self.len..end).ok_or(Unbuilt)?;
        room.copy_from_slice(bytes);
        self.len = end;
        Ok(())
    }

    fn piece(&mut self, entry: &[u8]) -> Result<(), Unbuilt> {
        let length = piece::length(entry.len()).map_err(|_| Unbuilt)?;
        self.put(&length)?;
        self.put(entry)
    }

    fn keep(
        mut self,
        link: &Link,
        status: Result<(), Errno>,
        exhausted: bool,
    ) -> Result<(), Unbuilt> {
        let closing = Closing {
            status: status.err().map_or(0, |errno| -errno.raw_os_error()),
            exhausted,
        };
        self.put(&closing.encode())?;
        let Self {
            mut buffer,
            len,
            request_id,
        } = self;
        buffer.truncate(len);
        link.keep(request_id, Kept::Replied(Arc::new(buffer)));
        Ok(())
    }
}

struct Admission<'a, P: Replies> {
    connection: &'a Arc<Connection<P>>,
    listing: Arc<ops::dir::Listing>,
    piece: Option<Buffer>,
    thread: Option<Thread>,
    index: usize,
}

enum Next {
    Entry(ops::dir::Admitted),
    Exhausted,
    Unfit,
    Failed,
}

impl<P: Replies> Admission<'_, P> {
    /// The first admission runs on the first thread of the listing, and every
    /// other on a thread from the pool, whether or not the connection is
    /// stopping: a listing that has started runs to its end.
    async fn next(&mut self, room: usize) -> Result<Next, Errno> {
        loop {
            if self.index >= self.listing.remaining() {
                return Ok(Next::Exhausted);
            }
            let Some(mut piece) = self.piece.take() else {
                return Ok(Next::Failed);
            };
            let mut thread = match self.thread.take() {
                Some(thread) => thread,
                None => match self.connection.plane.pool().acquire().await {
                    Ok(thread) => thread,
                    Err(_) => return Ok(Next::Failed),
                },
            };
            let (session, listing, index) = (
                Arc::clone(&self.connection.session),
                Arc::clone(&self.listing),
                self.index,
            );
            // An admission that unwinds may have counted its entry, and the
            // reply of the listing cannot be kept whole without it, so it ends
            // the session.
            let Ok((returned, admitted)) = thread
                .run(move || {
                    let admitted = listing.admit(&session, index, &mut piece, room);
                    (piece, admitted)
                })
                .await
            else {
                tracing::error!("a directory listing entry failed");
                self.connection.unkept();
                return Ok(Next::Failed);
            };
            drop(thread);
            self.piece = Some(returned);
            match admitted? {
                Admit::Entry(entry) => {
                    self.index += 1;
                    return Ok(Next::Entry(entry));
                }
                Admit::Gone => self.index += 1,
                Admit::Unfit => return Ok(Next::Unfit),
            }
        }
    }

    fn piece(&self, len: usize) -> &[u8] {
        self.piece.as_ref().map_or(&[], |piece| &piece[..len])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::session::Outcome;

    #[tokio::test]
    async fn a_kept_listing_that_cannot_be_built_whole_is_never_recorded() {
        let memory = voidport_memory::Memory::host();
        let head = FrameWriter::response_len::<ReaddirplusResponse>(0);
        let entry = [7u8; 24];
        let closing = Closing {
            status: 0,
            exhausted: true,
        }
        .encode()
        .len();
        let whole = head + piece::PIECE_LEN_LEN + entry.len() + closing;

        assert!(
            KeptListing::within(memory.buffer(head - 1, 1).await, 1).is_err(),
            "no room for the message"
        );
        let mut kept = KeptListing::within(memory.buffer(head + piece::PIECE_LEN_LEN, 1).await, 1)
            .expect("the message fits");
        assert!(kept.piece(&entry).is_err(), "no room for the entry");

        let link = Link::new(1);
        link.read(2, true);
        let mut kept =
            KeptListing::within(memory.buffer(whole - 1, 1).await, 2).expect("the message fits");
        kept.piece(&entry).expect("the entry fits");
        assert!(
            kept.keep(&link, Ok(()), true).is_err(),
            "no room for the closing piece"
        );
        assert!(
            matches!(link.outcome(2), Outcome::NotStarted),
            "the partial reply is not the listing's outcome"
        );

        link.read(3, true);
        let mut kept =
            KeptListing::within(memory.buffer(whole, 1).await, 3).expect("the message fits");
        kept.piece(&entry).expect("the entry fits");
        kept.keep(&link, Ok(()), true)
            .expect("the closing piece fits");
        let Outcome::Replied(reply) = link.outcome(3) else {
            panic!("the whole reply is the listing's outcome");
        };
        assert_eq!(reply.len(), whole);
    }
}
