//! Data moves from a source to a sink a piece at a time, and at most one piece
//! is held at a time. The operation that decides which bytes move names the
//! source and the sink and never uses a socket.
//!
//! The wire is backpressured: the next piece is read from the source only once
//! the sink has taken the last one. A stage sees every piece on its way and
//! neither adds nor drops bytes.
//!
//! The two ends fail differently ([`End`]): an error of the file end is an
//! errno sent to the client, and an error of the socket end ends the
//! connection.
//!
//! A piece is an owned [`Buffer`] that travels to the end that fills or empties
//! it and comes back, because an end that makes a host call makes it on a pool
//! thread, which cannot borrow from the task of the request.

use std::future::Future;
use std::io::{self, IoSlice};

use rustix::io::{Errno, ReadWriteFlags};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use voidport_memory::Buffer;
use voidport_proto::frame::FrameWriter;
use voidport_proto::limits::LIMITS;
use voidport_proto::message::ResponseBody;
use voidport_proto::opcode::Opcode;
use voidport_proto::piece::{self, Closing};

use super::pool::Thread;
use crate::host::Io;

#[derive(Debug)]
pub enum End {
    File(Errno),
    Socket(io::Error),
}

impl End {
    #[must_use]
    pub fn stopping() -> Self {
        Self::Socket(io::Error::other("the connection is stopping"))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Then {
    More,
    Exhausted,
    Stop,
}

#[derive(Debug)]
pub struct Filled {
    pub buffer: Buffer,
    pub len: usize,
    pub then: Then,
}

#[derive(Debug)]
pub struct Taken {
    pub buffer: Buffer,
    pub len: usize,
}

pub trait Source: Send {
    fn read(
        &mut self,
        buffer: Buffer,
        len: usize,
    ) -> impl Future<Output = Result<Filled, End>> + Send;
}

pub trait Sink: Send {
    fn write(
        &mut self,
        buffer: Buffer,
        len: usize,
    ) -> impl Future<Output = Result<Taken, End>> + Send;
}

pub trait Stage: Send {
    fn pass(&mut self, piece: &[u8]);
}

#[derive(Debug)]
pub enum Ending {
    Delivered,
    Exhausted,
    Stopped,
    Short,
    Failed(End),
}

#[derive(Debug)]
pub struct Carried {
    pub moved: u64,
    pub ending: Ending,
    pub buffer: Option<Buffer>,
}

/// `cut` sizes each piece from what has moved and what remains; it is never
/// asked for more than the buffer has room for.
pub async fn carry<S: Source, K: Sink>(
    source: &mut S,
    stages: &mut [&mut dyn Stage],
    sink: &mut K,
    buffer: Buffer,
    want: u64,
    mut cut: impl FnMut(u64, u64) -> usize + Send,
) -> Carried {
    let mut moved = 0u64;
    let mut buffer = buffer;
    loop {
        if moved >= want {
            return Carried {
                moved,
                ending: Ending::Delivered,
                buffer: Some(buffer),
            };
        }
        let len = cut(moved, want - moved).clamp(1, buffer.len().max(1));
        let Filled {
            buffer: filled,
            len,
            then,
        } = match source.read(buffer, len).await {
            Ok(filled) => filled,
            Err(end) => {
                return Carried {
                    moved,
                    ending: Ending::Failed(end),
                    buffer: None,
                };
            }
        };
        if len == 0 {
            return Carried {
                moved,
                ending: Ending::Exhausted,
                buffer: Some(filled),
            };
        }
        for stage in stages.iter_mut() {
            stage.pass(&filled[..len]);
        }
        let Taken {
            buffer: taken_back,
            len: taken,
        } = match sink.write(filled, len).await {
            Ok(taken) => taken,
            Err(end) => {
                return Carried {
                    moved,
                    ending: Ending::Failed(end),
                    buffer: None,
                };
            }
        };
        moved += taken as u64;
        buffer = taken_back;
        let ending = if taken < len {
            Ending::Short
        } else {
            match then {
                Then::More => continue,
                Then::Exhausted => Ending::Exhausted,
                Then::Stop => Ending::Stopped,
            }
        };
        return Carried {
            moved,
            ending,
            buffer: Some(buffer),
        };
    }
}

/// A cached handle takes whole pieces and a remainder. An uncached one cuts its
/// pieces at multiples of the offset alignment direct I/O demands.
#[must_use]
pub fn cut(piece: usize, remaining: u64, alignment: Option<usize>) -> usize {
    let len = usize::try_from(remaining).unwrap_or(usize::MAX).min(piece);
    if let Some(alignment) = alignment {
        let tail = len % alignment.max(1);
        if tail != 0 && len > tail {
            return len - tail;
        }
    }
    len
}

pub trait Out: Send {
    fn put(&mut self, bytes: &[u8]) -> impl Future<Output = io::Result<()>> + Send;

    fn flush(&mut self) -> impl Future<Output = io::Result<()>> + Send;
}

#[derive(Debug)]
pub struct Plain<W>(pub W);

impl<W: AsyncWrite + Unpin + Send> Out for Plain<W> {
    async fn put(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.0.write_all(bytes).await
    }

    async fn flush(&mut self) -> io::Result<()> {
        self.0.flush().await
    }
}

#[derive(Debug)]
pub struct ReplySink<'o, O> {
    out: &'o mut O,
    head: Vec<u8>,
    started: bool,
    request_id: u64,
    opcode: Opcode,
}

impl<'o, O: Out> ReplySink<'o, O> {
    pub fn new<M: ResponseBody + Default>(
        out: &'o mut O,
        request_id: u64,
    ) -> Result<Self, voidport_proto::error::FramingError> {
        let mut head = vec![0u8; FrameWriter::response_len::<M>(0)];
        let len = FrameWriter::response(&mut head, &LIMITS, request_id, &M::default())?
            .finish()?
            .len();
        head.truncate(len);
        Ok(Self {
            out,
            head,
            started: false,
            request_id,
            opcode: M::OPCODE,
        })
    }

    #[must_use]
    pub fn started(&self) -> bool {
        self.started
    }

    pub async fn start(&mut self) -> io::Result<()> {
        if !self.started {
            self.out.put(&self.head).await?;
            self.started = true;
        }
        Ok(())
    }

    pub async fn piece(&mut self, piece: &[u8]) -> io::Result<()> {
        self.placed(piece.len()).await?;
        self.out.put(piece).await
    }

    pub async fn placed(&mut self, len: usize) -> io::Result<()> {
        self.start().await?;
        let length = piece::length(len).map_err(|error| io::Error::other(error.to_string()))?;
        self.out.put(&length).await
    }

    pub async fn close(&mut self, status: Result<(), Errno>, exhausted: bool) -> io::Result<()> {
        match status {
            Err(errno) if !self.started => {
                let mut bytes = [0u8; FrameWriter::ERROR_RESPONSE_LEN];
                let reply = FrameWriter::error_response(
                    &mut bytes,
                    self.request_id,
                    self.opcode,
                    -errno.raw_os_error(),
                )
                .map_err(|error| io::Error::other(error.to_string()))?;
                self.out.put(reply).await?;
                self.started = true;
                Ok(())
            }
            status => {
                self.start().await?;
                let closing = Closing {
                    status: status.err().map_or(0, |errno| -errno.raw_os_error()),
                    exhausted,
                };
                self.out.put(&closing.encode()).await
            }
        }
    }

    pub async fn finish(&mut self, carried: Carried) -> io::Result<()> {
        match carried.ending {
            Ending::Failed(End::Socket(error)) => Err(error),
            Ending::Failed(End::File(errno)) => self.close(Err(errno), false).await,
            Ending::Exhausted => self.close(Ok(()), true).await,
            Ending::Delivered | Ending::Stopped | Ending::Short => self.close(Ok(()), false).await,
        }
    }
}

impl<O: Out> Sink for ReplySink<'_, O> {
    async fn write(&mut self, buffer: Buffer, len: usize) -> Result<Taken, End> {
        self.piece(&buffer[..len]).await.map_err(End::Socket)?;
        Ok(Taken { buffer, len })
    }
}

pub trait Threads: Send + Sync {
    fn thread(&self) -> impl Future<Output = Result<Thread, End>> + Send;
}

/// A cached handle reads again after a short read, and a read of zero bytes is
/// the end of the file. An uncached handle cannot continue from inside a piece,
/// because the next read would start at an offset direct I/O refuses, so a
/// short piece stops the reply; the size of the file on the host, asked for on
/// the same thread, shows whether that was the end.
#[derive(Debug)]
pub struct FileSource<'t, T> {
    threads: &'t T,
    first: Option<Thread>,
    file: Io,
    offset: u64,
}

impl<'t, T: Threads> FileSource<'t, T> {
    #[must_use]
    pub fn new(threads: &'t T, first: Thread, file: Io, offset: u64) -> Self {
        Self {
            threads,
            first: Some(first),
            file,
            offset,
        }
    }
}

impl<T: Threads> Source for FileSource<'_, T> {
    async fn read(&mut self, buffer: Buffer, len: usize) -> Result<Filled, End> {
        let mut thread = match self.first.take() {
            Some(first) => first,
            None => self.threads.thread().await?,
        };
        let file = self.file.clone();
        let offset = self.offset;
        let (buffer, read) = thread
            .run(move || {
                let mut buffer = buffer;
                let read = file
                    .read(&mut buffer[..len], offset)
                    .and_then(|read| Ok((read, after_read(&file, offset, len, read)?)));
                (buffer, read)
            })
            .await
            .map_err(|_| End::File(Errno::IO))?;
        drop(thread);
        let (len, then) = read.map_err(End::File)?;
        self.offset += len as u64;
        Ok(Filled { buffer, len, then })
    }
}

pub fn after_read(file: &Io, offset: u64, len: usize, read: usize) -> Result<Then, Errno> {
    if read == 0 {
        return Ok(Then::Exhausted);
    }
    if read == len || !file.transfer().is_direct() {
        return Ok(Then::More);
    }
    let stat = rustix::fs::fstat(file.fd())?;
    Ok(if offset + read as u64 >= stat.st_size as u64 {
        Then::Exhausted
    } else {
        Then::Stop
    })
}

/// A host write that takes less than its piece without an errno is followed by
/// another for the rest, on a cached handle. An uncached handle makes no
/// continuation from inside a piece, since it would start at an offset direct
/// I/O refuses. An errno after progress inside a piece returns that
/// progress, as a local write that fails partway does.
#[derive(Debug)]
pub struct FileSink<'t, T> {
    threads: &'t T,
    file: Io,
    flags: ReadWriteFlags,
    offset: u64,
}

impl<'t, T: Threads> FileSink<'t, T> {
    #[must_use]
    pub fn new(threads: &'t T, file: Io, flags: ReadWriteFlags, offset: u64) -> Self {
        Self {
            threads,
            file,
            flags,
            offset,
        }
    }
}

impl<T: Threads> Sink for FileSink<'_, T> {
    async fn write(&mut self, buffer: Buffer, len: usize) -> Result<Taken, End> {
        let mut thread = self.threads.thread().await?;
        let file = self.file.clone();
        let (offset, flags) = (self.offset, self.flags);
        let (buffer, written) = thread
            .run(move || {
                let written = write_piece(&file, &buffer[..len], offset, flags);
                (buffer, written)
            })
            .await
            .map_err(|_| End::File(Errno::IO))?;
        drop(thread);
        let written = written.map_err(End::File)?;
        self.offset += written as u64;
        Ok(Taken {
            buffer,
            len: written,
        })
    }
}

fn write_piece(
    file: &Io,
    piece: &[u8],
    offset: u64,
    flags: ReadWriteFlags,
) -> Result<usize, Errno> {
    write_at(
        file.transfer().is_direct(),
        piece.len(),
        offset,
        |done, at| {
            let rest = &piece[done..];
            file.write(&[IoSlice::new(rest)], at, flags)
                .map(|count| (count, rest.len()))
        },
    )
}

/// A call that wrote less than it offered is followed by another for the rest
/// on a cached handle; an `uncached` handle makes no continuation. Each call
/// either makes progress or ends the write, and a call that writes nothing ends
/// it with the count so far. An error after progress returns that progress.
pub fn write_at<E>(
    uncached: bool,
    len: usize,
    offset: u64,
    mut call: impl FnMut(usize, u64) -> Result<(usize, usize), E>,
) -> Result<usize, E> {
    let mut written = 0usize;
    while written < len {
        match call(written, offset + written as u64) {
            Ok((0, _)) => break,
            Ok((count, offered)) => {
                written += count;
                if count < offered && uncached {
                    break;
                }
            }
            Err(error) if written == 0 => return Err(error),
            Err(_) => break,
        }
    }
    Ok(written)
}

/// An append is the one host call the kernel leaves whole, which places it at
/// the end of the file whatever `offset` is. Any other write goes a piece
/// after the other, up to the first that is written short.
pub fn write_collected(
    file: &Io,
    pieces: &[Buffer],
    offset: u64,
    flags: ReadWriteFlags,
) -> Result<usize, Errno> {
    if flags.contains(ReadWriteFlags::APPEND) {
        let slices: Vec<IoSlice<'_>> = pieces.iter().map(|piece| IoSlice::new(piece)).collect();
        return file.write(&slices, offset, flags);
    }
    let mut written = 0usize;
    for piece in pieces {
        match write_piece(file, piece, offset + written as u64, flags) {
            Ok(count) => {
                written += count;
                if count < piece.len() {
                    break;
                }
            }
            Err(errno) if written == 0 => return Err(errno),
            Err(_) => break,
        }
    }
    Ok(written)
}

#[derive(Debug)]
pub struct SocketSource<'r, R> {
    reader: &'r mut R,
    stop: tokio::sync::watch::Receiver<bool>,
}

impl<'r, R: AsyncRead + Unpin + Send> SocketSource<'r, R> {
    #[must_use]
    pub fn new(reader: &'r mut R, stop: tokio::sync::watch::Receiver<bool>) -> Self {
        Self { reader, stop }
    }
}

impl<R: AsyncRead + Unpin + Send> Source for SocketSource<'_, R> {
    async fn read(&mut self, buffer: Buffer, len: usize) -> Result<Filled, End> {
        let mut buffer = buffer;
        tokio::select! {
            biased;
            _ = self.stop.wait_for(|stopped| *stopped) => Err(End::stopping()),
            read = self.reader.read_exact(&mut buffer[..len]) => match read {
                Ok(_) => Ok(Filled {
                    buffer,
                    len,
                    then: Then::More,
                }),
                Err(error) => Err(End::Socket(error)),
            },
        }
    }
}

pub fn written_or_errno(carried: &Carried) -> Result<u64, Errno> {
    match &carried.ending {
        Ending::Failed(End::File(errno)) if carried.moved == 0 => Err(*errno),
        _ => Ok(carried.moved),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tokio::sync::{Semaphore, watch};
    use voidport_memory::Memory;
    use voidport_proto::frame::{Frame, Parsed};
    use voidport_proto::ops::file::ReadResponse;
    use voidport_proto::piece::ClosingBody;

    struct Recording {
        data: Vec<u8>,
        at: usize,
        reads: Arc<Mutex<Vec<usize>>>,
        fails_at: Option<usize>,
    }

    impl Source for Recording {
        async fn read(&mut self, mut buffer: Buffer, len: usize) -> Result<Filled, End> {
            let mut reads = self.reads.lock().expect("reads");
            if self.fails_at == Some(reads.len()) {
                return Err(End::File(Errno::IO));
            }
            reads.push(len);
            let len = len.min(self.data.len() - self.at);
            buffer[..len].copy_from_slice(&self.data[self.at..self.at + len]);
            self.at += len;
            Ok(Filled {
                buffer,
                len,
                then: Then::More,
            })
        }
    }

    struct Gated {
        permits: Arc<Semaphore>,
        taken: Arc<Mutex<Vec<u8>>>,
        pieces: Arc<Mutex<usize>>,
    }

    impl Sink for Gated {
        async fn write(&mut self, buffer: Buffer, len: usize) -> Result<Taken, End> {
            self.permits.acquire().await.expect("open").forget();
            self.taken
                .lock()
                .expect("taken")
                .extend_from_slice(&buffer[..len]);
            *self.pieces.lock().expect("pieces") += 1;
            Ok(Taken { buffer, len })
        }
    }

    #[derive(Default)]
    struct Counting(usize, usize);

    impl Stage for Counting {
        fn pass(&mut self, piece: &[u8]) {
            self.0 += 1;
            self.1 += piece.len();
        }
    }

    fn recording(len: usize, fails_at: Option<usize>) -> (Recording, Arc<Mutex<Vec<usize>>>) {
        let reads = Arc::new(Mutex::new(Vec::new()));
        (
            Recording {
                data: (0..len).map(|at| (at % 251) as u8).collect(),
                at: 0,
                reads: Arc::clone(&reads),
                fails_at,
            },
            reads,
        )
    }

    async fn settle() {
        for _ in 0..16 {
            tokio::task::yield_now().await;
        }
    }

    #[tokio::test]
    async fn the_source_is_read_only_as_the_sink_takes() {
        let (mut source, reads) = recording(10 * 64, None);
        let permits = Arc::new(Semaphore::new(0));
        let taken = Arc::new(Mutex::new(Vec::new()));
        let pieces = Arc::new(Mutex::new(0));
        let mut sink = Gated {
            permits: Arc::clone(&permits),
            taken: Arc::clone(&taken),
            pieces: Arc::clone(&pieces),
        };
        let buffer = Memory::host().buffer(64, 1).await;
        let carrying = tokio::spawn(async move {
            carry(
                &mut source,
                &mut [],
                &mut sink,
                buffer,
                10 * 64,
                |_, rest| cut(64, rest, None),
            )
            .await
        });
        settle().await;
        assert_eq!(reads.lock().expect("reads").len(), 1, "one piece, waiting");
        for piece in 1..=10 {
            permits.add_permits(1);
            settle().await;
            let read = reads.lock().expect("reads").len();
            let written = *pieces.lock().expect("pieces");
            assert_eq!(written, piece, "the sink took one more piece");
            assert!(read <= written + 1, "at most one piece is held");
        }
        let carried = carrying.await.expect("joined");
        assert_eq!(carried.moved, 640);
        assert!(matches!(carried.ending, Ending::Delivered));
        assert_eq!(taken.lock().expect("taken").len(), 640);
    }

    #[tokio::test]
    async fn a_stage_is_inserted_and_removed_without_changing_the_ends() {
        let mut arrived = Vec::new();
        for with_stage in [false, true] {
            let (mut source, _reads) = recording(1000, None);
            let permits = Arc::new(Semaphore::new(usize::MAX >> 4));
            let taken = Arc::new(Mutex::new(Vec::new()));
            let mut sink = Gated {
                permits,
                taken: Arc::clone(&taken),
                pieces: Arc::default(),
            };
            let mut counting = Counting::default();
            let buffer = Memory::host().buffer(64, 1).await;
            let mut stages: Vec<&mut dyn Stage> = Vec::new();
            if with_stage {
                stages.push(&mut counting);
            }
            let carried = carry(
                &mut source,
                &mut stages,
                &mut sink,
                buffer,
                1000,
                |_, rest| cut(64, rest, None),
            )
            .await;
            assert_eq!(carried.moved, 1000);
            if with_stage {
                assert_eq!((counting.0, counting.1), (16, 1000));
            }
            arrived.push(taken.lock().expect("taken").clone());
        }
        assert_eq!(arrived[0], arrived[1], "the same bytes arrive either way");
    }

    #[tokio::test]
    async fn a_source_that_fails_after_a_piece_closes_the_reply_with_its_errno() {
        let (mut source, _reads) = recording(1000, Some(1));
        let mut out = Plain(Vec::new());
        let mut reply = ReplySink::new::<ReadResponse>(&mut out, 5).expect("a head");
        let buffer = Memory::host().buffer(64, 1).await;
        let carried = carry(&mut source, &mut [], &mut reply, buffer, 1000, |_, rest| {
            cut(64, rest, None)
        })
        .await;
        assert_eq!(carried.moved, 64);
        reply.finish(carried).await.expect("written");
        let bytes = out.0;
        let Ok(Parsed::Frame(head)) = Frame::parse_prefix(&bytes, &LIMITS) else {
            panic!("a reply head");
        };
        assert_eq!(head.status(), Ok(0));
        let rest = &bytes[head.len()..];
        assert_eq!(
            piece::read_length(rest[..4].try_into().expect("a length")),
            64
        );
        let rest = &rest[4 + 64..];
        assert_eq!(
            piece::read_length(rest[..4].try_into().expect("a length")),
            0
        );
        let closing = ClosingBody::parse(rest[4..12].try_into().expect("a closing"))
            .expect("a legal closing piece");
        assert_eq!(closing.status, -Errno::IO.raw_os_error());
        assert!(!closing.exhausted);
    }

    #[tokio::test]
    async fn a_source_that_fails_first_answers_with_the_errno_alone() {
        let (mut source, _reads) = recording(1000, Some(0));
        let mut out = Plain(Vec::new());
        let mut reply = ReplySink::new::<ReadResponse>(&mut out, 5).expect("a head");
        let buffer = Memory::host().buffer(64, 1).await;
        let carried = carry(&mut source, &mut [], &mut reply, buffer, 1000, |_, rest| {
            cut(64, rest, None)
        })
        .await;
        reply.finish(carried).await.expect("written");
        let frame = Frame::parse(&out.0, &LIMITS).expect("one error reply and nothing after");
        assert_eq!(frame.status(), Ok(-Errno::IO.raw_os_error()));
    }

    #[tokio::test]
    async fn a_file_that_fails_on_the_second_piece_answers_the_first_pieces_count() {
        struct Failing(usize);
        impl Sink for Failing {
            async fn write(&mut self, buffer: Buffer, len: usize) -> Result<Taken, End> {
                self.0 += 1;
                if self.0 == 2 {
                    return Err(End::File(Errno::NOSPC));
                }
                Ok(Taken { buffer, len })
            }
        }
        let (mut source, _reads) = recording(200, None);
        let buffer = Memory::host().buffer(64, 1).await;
        let carried = carry(
            &mut source,
            &mut [],
            &mut Failing(0),
            buffer,
            200,
            |_, rest| cut(64, rest, None),
        )
        .await;
        assert_eq!(carried.moved, 64);
        assert!(matches!(
            carried.ending,
            Ending::Failed(End::File(Errno::NOSPC))
        ));
        assert_eq!(written_or_errno(&carried), Ok(64));
    }

    #[test]
    fn a_write_goes_on_after_a_short_call_only_on_a_cached_handle() {
        let short = |done: usize, at: u64| -> Result<(usize, usize), Errno> {
            assert_eq!(
                at,
                100 + done as u64,
                "a call starts where the last stopped"
            );
            Ok(((10 - done).min(4), 10 - done))
        };
        assert_eq!(write_at(false, 10, 100, short), Ok(10));
        assert_eq!(write_at(true, 10, 100, short), Ok(4));
        assert_eq!(
            write_at(false, 10, 0, |_, _| Ok::<_, Errno>((0, 10))),
            Ok(0)
        );
        let mut calls = 0;
        let failing = |_: usize, _: u64| {
            calls += 1;
            if calls == 1 {
                Ok((4, 4))
            } else {
                Err(Errno::NOSPC)
            }
        };
        assert_eq!(write_at(true, 10, 0, failing), Ok(4));
        assert_eq!(
            write_at(false, 10, 0, |_, _| Err::<(usize, usize), _>(Errno::NOSPC)),
            Err(Errno::NOSPC)
        );
    }

    #[test]
    fn uncached_pieces_are_cut_at_the_alignment() {
        assert_eq!(cut(4096, 10_000, None), 4096);
        assert_eq!(cut(4096, 1000, None), 1000);
        assert_eq!(cut(4096, 1000, Some(512)), 512, "the aligned part first");
        assert_eq!(cut(4096, 488, Some(512)), 488, "then the tail alone");
        assert_eq!(cut(4096, 1024, Some(512)), 1024);
    }

    #[tokio::test]
    async fn a_stop_ends_a_socket_source() {
        let (stop, stopped) = watch::channel(false);
        let (mut near, _far) = tokio::io::duplex(64);
        let mut source = SocketSource::new(&mut near, stopped);
        let buffer = Memory::host().buffer(8, 1).await;
        let reading = source.read(buffer, 8);
        let mut reading = std::pin::pin!(reading);
        assert!(
            std::future::poll_fn(|cx| std::task::Poll::Ready(
                reading.as_mut().poll(cx).is_pending()
            ))
            .await
        );
        stop.send(true).expect("a receiver");
        assert!(matches!(reading.await, Err(End::Socket(_))));
    }
}
