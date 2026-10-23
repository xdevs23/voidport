use std::io;
use std::sync::Arc;

use rustix::io::{Errno, ReadWriteFlags};
use voidport_proto::frame::Frame;
use voidport_proto::limits::LIMITS;
use voidport_proto::opcode::Opcode;
use voidport_proto::ops::file::{ReadRequest, ReadResponse, WriteRequest};

use super::super::{
    Connection, Reading, Source, WRITE_CALL_MAX, ahead, answer_write, go_ahead, refusal, writing,
};
use super::reply::{Chains, Framed};
use crate::data::ops;
use crate::data::session::Kept;
use crate::data::virtio::guest::{Areas, Chain, Failed, Unreached};
use crate::data::wire::{self, Carried, End, Ending, Out as _, ReplySink, Then, Threads as _};
use crate::host::Io;

pub(super) struct ChainRequest {
    pub(super) framed: Arc<Framed>,
    pub(super) payload: Areas,
}

impl Source<Chains> for ChainRequest {
    const SPAWNS: bool = false;

    async fn write(self, connection: &Arc<Connection<Chains>>, bytes: &[u8]) -> io::Result<bool> {
        write(connection, &self.framed, bytes, self.payload).await;
        Ok(true)
    }

    fn read(
        &self,
        connection: &Arc<Connection<Chains>>,
        bytes: Vec<u8>,
        reading: Reading,
    ) -> impl Future<Output = ()> + Send + 'static {
        read_into(
            Arc::clone(connection),
            Arc::clone(&self.framed),
            bytes,
            reading,
        )
    }
}

async fn read_into(
    connection: Arc<Connection<Chains>>,
    framed: Arc<Framed>,
    bytes: Vec<u8>,
    reading: Reading,
) {
    let parsed = Frame::parse(&bytes, &LIMITS).and_then(|frame| {
        let body = *frame.request::<ReadRequest>()?.body();
        Ok((frame.request_id(), body))
    });
    let (request_id, body) = match parsed {
        Ok(parsed) => parsed,
        Err(error) => return connection.poison(&error),
    };
    let Some((file, waiting)) = reading.ahead(&connection, request_id).await else {
        return;
    };
    let file = match file {
        Ok(file) => file,
        Err(errno) => {
            drop(waiting);
            return connection.refuse(request_id, Opcode::Read, errno).await;
        }
    };
    let Ok(mut thread) = connection.acquire(waiting).await else {
        return;
    };
    let reading = Arc::clone(&framed);
    let (offset, size) = (body.offset.get(), body.size.get() as usize);
    let read = thread
        .run(move || {
            let data = reading.data.slice(0, size);
            read_file(&reading.chain, &file, offset, &data)
        })
        .await;
    drop(thread);
    let carried = match read {
        Ok(Ok(carried)) => carried,
        Ok(Err(Unreached::Stopped)) => return,
        Ok(Err(Unreached::Outside)) => return connection.stop(),
        Err(_) => Carried {
            moved: 0,
            ending: Ending::Failed(End::File(Errno::IO)),
            buffer: None,
        },
    };
    let Ok(mut sink) = connection.sink(request_id).await else {
        return;
    };
    let Ok(mut reply) = ReplySink::new::<ReadResponse>(&mut sink, request_id) else {
        return connection.stop();
    };
    connection.retire(request_id);
    let placed = match usize::try_from(carried.moved) {
        Ok(0) => Ok(()),
        Ok(moved) => reply.placed(moved).await,
        Err(_) => Err(io::Error::other("a read longer than the address space")),
    };
    let written = match placed {
        Ok(()) => reply.finish(carried).await,
        Err(error) => Err(error),
    };
    drop(reply);
    if written.is_err() || sink.flush().await.is_err() {
        connection.stop();
    }
}

fn read_file(chain: &Chain, file: &Io, offset: u64, data: &Areas) -> Result<Carried, Unreached> {
    let transfer = file.transfer();
    let want = data.len();
    let mut moved = 0usize;
    let ending = loop {
        if moved == want {
            break Ending::Delivered;
        }
        let rest = want - moved;
        let piece = wire::cut(rest, rest as u64, transfer.offset_alignment());
        let at = offset + moved as u64;
        let area = data.slice(moved, piece);
        match file
            .call(|fd| Ok(chain.read_file(fd, at, &area)))
            .unwrap_or_else(|errno| Err(Failed::Host(errno)))
        {
            Ok((read, asked)) => {
                moved += read;
                match wire::after_read(file, at, asked, read) {
                    Ok(Then::More) => {}
                    Ok(Then::Exhausted) => break Ending::Exhausted,
                    Ok(Then::Stop) => break Ending::Stopped,
                    Err(errno) => break Ending::Failed(End::File(errno)),
                }
            }
            Err(Failed::Host(errno)) => break Ending::Failed(End::File(errno)),
            Err(Failed::Guest(unreached)) => return Err(unreached),
        }
    };
    Ok(Carried {
        moved: moved as u64,
        ending,
        buffer: None,
    })
}

/// A write on an appending handle goes to the host as one call, so an append
/// longer than one write call accepts, or over more stretches of guest memory
/// than one call covers, ends the channel as a malformed frame does.
async fn write(
    connection: &Arc<Connection<Chains>>,
    framed: &Arc<Framed>,
    bytes: &[u8],
    data: Areas,
) {
    let parsed = Frame::parse(bytes, &LIMITS).and_then(|frame| {
        let request = frame.request::<WriteRequest>()?;
        Ok((
            frame.request_id(),
            request.head().node_id.get(),
            *request.body(),
        ))
    });
    let (request_id, node_id, body) = match parsed {
        Ok(parsed) => parsed,
        Err(error) => return connection.poison(&error),
    };
    let file = ops::file::file_of(&connection.session, body.handle.get());
    let io = ahead(writing(&file));
    match refusal(connection, &body, node_id, &io).await {
        Err(_) => return,
        Ok(Some(errno)) => return answer_write(connection, request_id, Err(errno), None).await,
        Ok(None) => {}
    }
    let Ok(file) = file else {
        return;
    };
    if file.appends()
        && (body.data_len.get() > WRITE_CALL_MAX || !framed.chain.fits_one_call(&data))
    {
        tracing::debug!(
            data_len = body.data_len.get(),
            "closing a channel on an append that cannot go to the host as one write call"
        );
        return connection.stop();
    }
    let (io, thread) = match io {
        Ok(Ok(io)) => (io, connection.thread().await),
        Ok(Err(_)) => return,
        Err(postponed) => {
            let Some(io) = go_ahead(connection, request_id, postponed, || file.writing()).await
            else {
                return connection.link.keep(request_id, Kept::NotStarted);
            };
            let thread = connection.thread_to_end().await;
            if thread.is_err() {
                return connection.link.keep(request_id, Kept::NotStarted);
            }
            match io {
                Ok(io) => (io, thread),
                Err(errno) => {
                    return answer_write(connection, request_id, Err(errno), None).await;
                }
            }
        }
    };
    let Ok(mut thread) = thread else {
        return;
    };
    let chain = Arc::clone(framed);
    let (offset, flags) = (body.offset.get(), file.write_flags());
    let written = thread
        .run(move || write_file(&chain.chain, &io, flags, offset, &data))
        .await;
    drop(thread);
    let outcome = match written {
        Ok(Ok(outcome)) => outcome,
        Ok(Err(Unreached::Stopped)) => return,
        Ok(Err(Unreached::Outside)) => return connection.stop(),
        Err(_) => Err(Errno::IO),
    };
    answer_write(connection, request_id, outcome, None).await;
}

fn write_file(
    chain: &Chain,
    file: &Io,
    flags: ReadWriteFlags,
    offset: u64,
    data: &Areas,
) -> Result<Result<u64, Errno>, Unreached> {
    let call = |at, area: &Areas| {
        file.call(|fd| Ok(chain.write_file(fd, at, area, flags)))
            .unwrap_or_else(|errno| Err(Failed::Host(errno)))
    };
    if flags.contains(ReadWriteFlags::APPEND) {
        return match call(offset, data) {
            Ok((written, _)) => Ok(Ok(written as u64)),
            Err(Failed::Host(errno)) => Ok(Err(errno)),
            Err(Failed::Guest(unreached)) => Err(unreached),
        };
    }
    let transfer = file.transfer();
    let mut moved = 0usize;
    while moved < data.len() {
        let rest = data.len() - moved;
        let piece = wire::cut(rest, rest as u64, transfer.offset_alignment());
        let written = wire::write_at(
            transfer.is_direct(),
            piece,
            offset + moved as u64,
            |done, at| call(at, &data.slice(moved + done, piece - done)),
        );
        match written {
            Ok(written) => {
                moved += written;
                if written < piece {
                    break;
                }
            }
            Err(_) if moved > 0 => break,
            Err(Failed::Host(errno)) => return Ok(Err(errno)),
            Err(Failed::Guest(unreached)) => return Err(unreached),
        }
    }
    Ok(Ok(moved as u64))
}
