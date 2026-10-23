//! The guardian of a mount: the process that drops the pages the guest kernel
//! caches of the files of the mount once the client has died.
//!
//! * The mount starts the guardian by running the program given in a
//!   [`Launch`], so that no process with threads forks, and through
//!   [`voidport_spawn`], so that the guardian has no copy of a file of the
//!   process while its `execve` runs.
//! * A read or write of a node goes ahead only once the [`Event::Cached`]
//!   message of the node is in the socket. One writer sends the messages in
//!   the order the page cache queued them, and no runtime worker or dispatch
//!   thread waits for the socket.
//! * The descriptor of the session is close-on-exec, so the guardian has none
//!   of the descriptors of the client. A request the client had read and not
//!   replied to remains with the descriptor that read it, which closes only
//!   once the last thread of the client has exited, and a thread of the
//!   client that waits for the reply never exits. When the guardian takes
//!   over, it has the kernel send such requests again (`FUSE_NOTIFY_RESEND`,
//!   `fuse_chan_resend` in `fs/fuse/dev.c`), and replies to them
//!   with the rest.
//! * The guardian replies to requests while it drops the pages, because a drop
//!   waits for the lock of every page, and a read in flight has its page
//!   locked until it gets a reply.
//! * The guardian replies to requests only once the client can no longer
//!   reply to them, which the lifeline of the mount tells it once every
//!   dispatch thread has ended, before the exit of the client closes a file.
//!   From then on no thread of the client reads a request, so one resend
//!   covers every request the client had read. Closing a file the client has
//!   open on its own mount sends a flush, which the exit waits for and only
//!   the guardian can reply to then.
//! * The guardian of a mount with auto-unmount has a copy of the end of the
//!   socket of the `fusermount3` helper, the mountpoint and the helper
//!   program that mounted. Once it has ended the connection used by a client
//!   that died, it unmounts the mountpoint through that helper where the
//!   connection on it has ended, and closes the copy only after that. The
//!   helper waits for every copy to close before it checks the mountpoint,
//!   so it checks only once the guardian has released the mountpoint.

mod lifeline;
mod release;

use std::collections::HashSet;
use std::convert::Infallible;
use std::ffi::{OsStr, OsString};
use std::future::Future;
use std::io::{self, IoSlice, IoSliceMut};
use std::mem::MaybeUninit;
use std::num::NonZeroUsize;
use std::ops::ControlFlow;
use std::os::fd::{AsFd as _, OwnedFd};
use std::os::unix::ffi::OsStrExt as _;
use std::path::PathBuf;
use std::process::Child;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::io::{Errno, retry_on_intr};
use rustix::net::{
    AddressFamily, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags,
    SendAncillaryBuffer, SendAncillaryMessage, SendFlags, SocketFlags, SocketType, recv, recvmsg,
    send, sendmsg, socketpair,
};
use rustix::process::{Pid, PidfdFlags, pidfd_open};
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;
use tokio::runtime::Handle;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use voidport_fuse::{
    AutoUnmountCopy, ClonedConnection, Connection, Filesystem, Fusermount, ServeError, Session,
    Stopper, UnmountError,
};
use voidport_proto::limits::{LIMITS, Part};
use voidport_spawn::{Program, SpawnError, Stream};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, TryFromBytes};

pub use self::lifeline::LifelineError;
use self::lifeline::{Lifeline, Waiting};

pub const COMMAND: &str = "guardian";

/// The program runs [`serve`] in the PID namespace of the mount, since the
/// lifeline of the mount identifies its dispatch threads by thread ID.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Launch {
    pub program: PathBuf,
    pub arguments: Vec<OsString>,
}

/// Dropping it closes the socket without [`Event::End`] and does not wait for
/// the guardian, which then drops the pages once the client can no longer
/// answer.
#[derive(Debug)]
pub struct Guardian {
    process: Child,
    feed: Arc<Feed>,
    watch: JoinHandle<()>,
}

#[derive(Debug)]
pub struct Feed {
    /// The writer owns the socket, and closes it once it has sent what was
    /// queued before the close.
    queue: Mutex<Option<Queue>>,
    written: watch::Receiver<u64>,
}

#[derive(Debug)]
struct Queue {
    messages: mpsc::UnboundedSender<Event>,
    queued: u64,
}

#[derive(Debug)]
pub struct Unstarted {
    pub feed: Arc<Feed>,
    pub(crate) writer: Writer,
    pub(crate) theirs: OwnedFd,
}

#[derive(Debug)]
pub(crate) struct Writer {
    socket: OwnedFd,
    messages: mpsc::UnboundedReceiver<Event>,
    written: watch::Sender<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    Cached(u64),
    Forgot(u64),
    End,
    /// The one message the guardian sends.
    Ready,
}

#[derive(TryFromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
struct Wire {
    kind: Kind,
    node_id: u64,
}

#[derive(Clone, Copy, TryFromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(u64)]
enum Kind {
    Cached = 1,
    Forgot = 2,
    End = 3,
    Ready = 4,
}

impl From<Event> for Wire {
    fn from(event: Event) -> Self {
        let (kind, node_id) = match event {
            Event::Cached(node_id) => (Kind::Cached, node_id),
            Event::Forgot(node_id) => (Kind::Forgot, node_id),
            Event::End => (Kind::End, 0),
            Event::Ready => (Kind::Ready, 0),
        };
        Self { kind, node_id }
    }
}

impl From<Wire> for Event {
    fn from(wire: Wire) -> Self {
        match wire.kind {
            Kind::Cached => Self::Cached(wire.node_id),
            Kind::Forgot => Self::Forgot(wire.node_id),
            Kind::End => Self::End,
            Kind::Ready => Self::Ready,
        }
    }
}

/// Dropping it stops the dispatch threads and does not wait for them.
#[derive(Debug)]
pub struct Serving {
    thread: std::thread::JoinHandle<Result<(), ServeError<Infallible>>>,
    stopper: Stopper,
}

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("the thread of the session could not be started")]
    Spawn(#[source] io::Error),
    #[error("the pipe that stops the dispatch threads could not be made")]
    Stop(#[source] io::Error),
    #[error("the session ended before its dispatch threads read")]
    Ended,
    #[error(transparent)]
    Serve(#[from] ServeError<Infallible>),
    #[error("the thread of the session panicked")]
    Panicked,
}

#[derive(Debug, thiserror::Error)]
pub enum GuardianError {
    #[error("the socket between the mount and its guardian failed")]
    Socket(#[source] Errno),
    #[error("a descriptor of the kernel connection could not be made")]
    Connection(#[source] io::Error),
    #[error("the lifeline of the mount failed")]
    Lifeline(#[from] LifelineError),
    #[error("the mount has {0} descriptors to hand its guardian, more than one message takes")]
    TooManyDescriptors(usize),
    #[error("the guardian could not be started")]
    Spawn(#[source] SpawnError),
    #[error("the exit of the guardian cannot be followed")]
    Pidfd(#[source] Errno),
    #[error("the exit of the guardian cannot be awaited on the runtime")]
    Runtime(#[source] io::Error),
    #[error("the guardian exited before it reported that it follows the dispatch threads")]
    NotReady,
    #[error("the path of the mountpoint or of the fusermount3 helper is too long to hand over")]
    PathTooLong,
    #[error("the mountpoint used by the client that died could not be unmounted")]
    Release(#[source] UnmountError),
    #[error("the first message of the mount does not describe what it hands the guardian")]
    MalformedHandOver,
    #[error("the mount handed the guardian fewer descriptors than it describes")]
    MissingDescriptors,
    #[error("a message between a mount and its guardian is of an unknown kind")]
    UnknownMessage,
    #[error("the mount sent its guardian a message that only a guardian sends")]
    MisplacedReady,
    #[error("the standard input of the guardian could not be taken")]
    Stdin(#[source] io::Error),
    #[error("the watch of the dispatch threads panicked")]
    WatchPanicked,
    #[error("the end of the kernel connection could not be read")]
    Poll(#[source] Errno),
    #[error(
        "the pipe that ends the thread that answers the requests of the mount could not be made"
    )]
    Stop(#[source] io::Error),
    #[error("the thread that answers the requests of the mount could not be started")]
    Thread(#[source] io::Error),
    #[error("the thread that answers the requests of the mount panicked")]
    ThreadPanicked,
}

#[derive(Debug, thiserror::Error)]
pub enum Unserved {
    #[error(transparent)]
    Session(SessionError),
    #[error(transparent)]
    Guardian(GuardianError),
}

#[derive(Debug)]
struct Held {
    lifeline: Arc<Lifeline>,
    threads: Vec<OwnedFd>,
    /// Set once the guardian follows the lifeline, or once the session is stopped
    /// because the guardian could not be started. The dispatch threads wait for
    /// it before they read.
    reads: Arc<OnceLock<()>>,
    session: Serving,
}

enum Start {
    Held(usize, Result<OwnedFd, LifelineError>),
    Ended,
}

#[derive(Debug)]
struct HandOver {
    max_write: u32,
    device: OwnedFd,
    lifeline: OwnedFd,
    auto_unmount: Option<AutoUnmountCopy>,
    threads: Vec<OwnedFd>,
}

#[derive(FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
struct HandOverData {
    max_write: u32,
    mountpoint_length: u32,
}

/// The most descriptors one `SCM_RIGHTS` message carries (`SCM_MAX_FD` in
/// `include/net/scm.h`).
const MOST_DESCRIPTORS: usize = 253;

fn longest_path() -> u32 {
    LIMITS
        .bound(Part::Path)
        .expect("a path part always has a bound")
}

fn path_length(path: &[u8]) -> Result<u32, GuardianError> {
    u32::try_from(path.len())
        .ok()
        .filter(|&length| length <= longest_path())
        .ok_or(GuardianError::PathTooLong)
}

impl HandOver {
    fn send(&self, socket: &OwnedFd) -> Result<(), GuardianError> {
        let descriptors: Vec<_> = [&self.device, &self.lifeline]
            .into_iter()
            .chain(
                self.auto_unmount
                    .as_ref()
                    .map(|auto_unmount| &auto_unmount.socket),
            )
            .chain(&self.threads)
            .map(|descriptor| descriptor.as_fd())
            .collect();
        if descriptors.len() > MOST_DESCRIPTORS {
            return Err(GuardianError::TooManyDescriptors(descriptors.len()));
        }
        let mut space =
            vec![MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(descriptors.len()))];
        let mut control = SendAncillaryBuffer::new(&mut space);
        let fits = control.push(SendAncillaryMessage::ScmRights(&descriptors));
        debug_assert!(fits, "the space has room for every descriptor");
        let (mountpoint, helper) = match &self.auto_unmount {
            Some(auto_unmount) => (
                auto_unmount.mountpoint.as_os_str().as_bytes(),
                auto_unmount.helper.path().as_bytes(),
            ),
            None => (&[][..], &[][..]),
        };
        path_length(helper)?;
        let data = HandOverData {
            max_write: self.max_write,
            mountpoint_length: path_length(mountpoint)?,
        };
        // The message has a header, so it is never empty, which a receive could
        // not tell from the end of the socket.
        sendmsg(
            socket,
            &[
                IoSlice::new(data.as_bytes()),
                IoSlice::new(mountpoint),
                IoSlice::new(helper),
            ],
            &mut control,
            SendFlags::NOSIGNAL,
        )
        .map_err(GuardianError::Socket)?;
        Ok(())
    }

    fn receive(socket: &OwnedFd) -> Result<Self, GuardianError> {
        let longest = usize::try_from(longest_path()).expect("a path length fits in memory");
        let mut payload = vec![0; size_of::<HandOverData>() + 2 * longest];
        let mut space =
            vec![MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(MOST_DESCRIPTORS))];
        let mut control = RecvAncillaryBuffer::new(&mut space);
        let received = retry_on_intr(|| {
            recvmsg(
                socket,
                &mut [IoSliceMut::new(&mut payload)],
                &mut control,
                RecvFlags::CMSG_CLOEXEC,
            )
        })
        .map_err(GuardianError::Socket)?;
        if received.flags.contains(ReturnFlags::TRUNC) {
            return Err(GuardianError::MalformedHandOver);
        }
        let (data, paths) = HandOverData::read_from_prefix(&payload[..received.bytes])
            .map_err(|_| GuardianError::MalformedHandOver)?;
        // Only the hand-over of a mount with auto-unmount has paths, and each of
        // its two paths has at least one byte.
        let paths = if paths.is_empty() {
            None
        } else {
            let (mountpoint, helper) = usize::try_from(data.mountpoint_length)
                .ok()
                .and_then(|length| paths.split_at_checked(length))
                .filter(|(mountpoint, helper)| !mountpoint.is_empty() && !helper.is_empty())
                .ok_or(GuardianError::MalformedHandOver)?;
            Some((OsStr::from_bytes(mountpoint), OsStr::from_bytes(helper)))
        };
        let mut descriptors = control
            .drain()
            .filter_map(|message| match message {
                RecvAncillaryMessage::ScmRights(descriptors) => Some(descriptors),
                _ => None,
            })
            .flatten();
        let (Some(device), Some(lifeline)) = (descriptors.next(), descriptors.next()) else {
            return Err(GuardianError::MissingDescriptors);
        };
        let auto_unmount = match paths {
            None => None,
            Some((mountpoint, helper)) => Some(AutoUnmountCopy {
                socket: descriptors
                    .next()
                    .ok_or(GuardianError::MissingDescriptors)?,
                mountpoint: PathBuf::from(mountpoint),
                helper: Fusermount::new(helper),
            }),
        };
        Ok(Self {
            max_write: data.max_write,
            device,
            lifeline,
            auto_unmount,
            threads: descriptors.collect(),
        })
    }
}

impl Guardian {
    /// The dispatch threads hold the lifeline of the mount first, then the
    /// guardian starts with a descriptor of the connection and the lifeline, and
    /// the dispatch threads read only once it reports that it follows them. From
    /// then on the writer of the feed runs on `runtime`, and so does a task that
    /// runs `lost` when the guardian exits without [`Event::End`] or a message
    /// cannot be sent to it. The guardian runs in a process group of its own, so
    /// that a signal sent to the process group of the client, such as a Ctrl-C in
    /// the terminal of the client, does not reach it.
    ///
    /// # Errors
    ///
    /// [`Unserved::Session`] for a session that could not start its dispatch
    /// threads, and [`Unserved::Guardian`] for every other failure to start the
    /// guardian. The session has ended then.
    pub fn start<FS: Filesystem + Send + 'static>(
        launch: &Launch,
        session: Session<FS>,
        threads: NonZeroUsize,
        unstarted: Unstarted,
        runtime: &Handle,
        lost: impl Future<Output = ()> + Send + 'static,
    ) -> Result<(Self, Serving), Unserved> {
        // Every descriptor of the session is close-on-exec, so the guardian has
        // only the clone it is handed.
        let ClonedConnection {
            connection: device,
            auto_unmount,
        } = session
            .clone_connection()
            .map_err(|error| Unserved::Guardian(GuardianError::Connection(error)))?;
        let max_write = session.max_write();
        let mut held = Held::start(session, threads)?;
        let threads = std::mem::take(&mut held.threads);
        let launched = held
            .lifeline
            .memory()
            .map_err(GuardianError::from)
            .and_then(|lifeline| {
                Self::launch(
                    launch,
                    &HandOver {
                        max_write,
                        device,
                        lifeline,
                        auto_unmount,
                        threads,
                    },
                    unstarted,
                    runtime,
                    lost,
                )
            });
        match launched {
            Ok(guardian) => Ok((guardian, held.serve())),
            Err(error) => {
                held.stop();
                Err(Unserved::Guardian(error))
            }
        }
    }

    fn launch(
        launch: &Launch,
        hand_over: &HandOver,
        unstarted: Unstarted,
        runtime: &Handle,
        lost: impl Future<Output = ()> + Send + 'static,
    ) -> Result<Self, GuardianError> {
        let Unstarted {
            feed,
            writer,
            theirs,
        } = unstarted;
        hand_over.send(&writer.socket)?;
        let spawned = Program::new(&launch.program)
            .args(&launch.arguments)
            .stdin(Stream::Descriptor(theirs.as_fd()))
            .stderr(Stream::Inherit)
            .in_new_process_group()
            .spawn()
            .map_err(GuardianError::Spawn);
        // The writer sees the guardian go only once no other copy of its end of
        // the socket is open.
        drop(theirs);
        let mut process = spawned?;
        let exited = match ready(&process, &writer.socket, runtime) {
            Ok(exited) => exited,
            Err(error) => {
                // A guardian that did not report is ended here, so that a mount
                // that fails leaves no process behind.
                if let Err(error) = process.kill() {
                    tracing::warn!(%error, "the guardian that did not report could not be ended");
                }
                if let Err(error) = process.wait() {
                    tracing::warn!(%error, "the exit of the guardian that did not report could not be awaited");
                }
                return Err(error);
            }
        };
        let stopped = writer.stopped();
        writer.start(runtime);
        let watch = runtime.spawn(async move {
            tokio::select! {
                _ = exited.readable() => {}
                () = stopped => {}
            }
            tracing::error!(
                "the guardian of the mount is gone, so the mount no longer caches leased files"
            );
            lost.await;
        });
        Ok(Self {
            process,
            feed,
            watch,
        })
    }

    pub(crate) fn id(&self) -> u32 {
        self.process.id()
    }

    /// Ends the guardian of a mount whose pages are shown gone, and returns
    /// once it has exited, which it does without dropping anything.
    pub fn end(mut self) {
        self.watch.abort();
        self.feed.tell(Event::End);
        self.feed.close();
        if let Err(error) = self.process.wait() {
            tracing::warn!(%error, "the exit of the guardian of the mount could not be awaited");
        }
    }
}

impl Drop for Guardian {
    fn drop(&mut self) {
        self.watch.abort();
        self.feed.close();
    }
}

impl Serving {
    pub fn join(self) -> Result<(), SessionError> {
        let Self { thread, stopper } = self;
        let ended = join_session(thread);
        drop(stopper);
        ended
    }

    pub fn stop(self) -> Result<(), SessionError> {
        let Self { thread, stopper } = self;
        drop(stopper);
        join_session(thread)
    }
}

fn join_session(
    thread: std::thread::JoinHandle<Result<(), ServeError<Infallible>>>,
) -> Result<(), SessionError> {
    thread.join().map_err(|_| SessionError::Panicked)??;
    Ok(())
}

impl Held {
    fn start<FS: Filesystem + Send + 'static>(
        session: Session<FS>,
        threads: NonZeroUsize,
    ) -> Result<Self, Unserved> {
        let lifeline =
            Arc::new(Lifeline::new(threads).map_err(|error| Unserved::Guardian(error.into()))?);
        let reads = Arc::new(OnceLock::new());
        let (started, starts) = std::sync::mpsc::channel();
        let hold = {
            let (lifeline, reads, started) =
                (Arc::clone(&lifeline), Arc::clone(&reads), started.clone());
            move |index| {
                // The start waits for one message of every dispatch thread, and
                // stops the session before it drops its receiver.
                let _start_waits = started.send(Start::Held(index, lifeline.hold(index)));
                reads.wait();
                Ok::<(), Infallible>(())
            }
        };
        let (stop, stopper) =
            voidport_fuse::stop().map_err(|error| Unserved::Session(SessionError::Stop(error)))?;
        // A session that cannot start every dispatch thread ends before any of
        // them has locked its futex, so the end of the session is told too.
        let thread = std::thread::Builder::new()
            .name("voidport-fuse".to_owned())
            .spawn(move || {
                let served = session.serve(threads, &stop, hold);
                // Once the start is over, nothing receives this, and the join of
                // the session tells its end.
                let _start_over = started.send(Start::Ended);
                served
            })
            .map_err(|error| Unserved::Session(SessionError::Spawn(error)))?;
        let mut held = Self {
            lifeline,
            threads: Vec::new(),
            reads,
            session: Serving { thread, stopper },
        };
        let mut pidfds: Vec<Option<OwnedFd>> = std::iter::repeat_with(|| None)
            .take(threads.get())
            .collect();
        for _ in 0..threads.get() {
            match starts.recv() {
                Ok(Start::Held(index, Ok(pidfd))) => pidfds[index] = Some(pidfd),
                Ok(Start::Held(_, Err(error))) => {
                    held.stop();
                    return Err(Unserved::Guardian(error.into()));
                }
                Ok(Start::Ended) | Err(_) => {
                    let ended = match held.session.join() {
                        Ok(()) => SessionError::Ended,
                        Err(error) => error,
                    };
                    return Err(Unserved::Session(ended));
                }
            }
        }
        held.threads = pidfds.into_iter().flatten().collect();
        Ok(held)
    }

    fn serve(self) -> Serving {
        self.reads.get_or_init(|| ());
        self.session
    }

    fn stop(self) {
        let Serving { thread, stopper } = self.session;
        // Requested before the dispatch threads are let go, so that none of them
        // reads a request that no guardian follows.
        drop(stopper);
        self.reads.get_or_init(|| ());
        if let Err(error) = join_session(thread) {
            tracing::warn!(%error, "the session of a mount whose guardian did not start ended with an error");
        }
    }
}

fn ready(
    process: &Child,
    socket: &OwnedFd,
    runtime: &Handle,
) -> Result<AsyncFd<OwnedFd>, GuardianError> {
    let exited =
        pidfd_open(Pid::from_child(process), PidfdFlags::empty()).map_err(GuardianError::Pidfd)?;
    match receive(socket)? {
        Some(Event::Ready) => {
            let _runtime = runtime.enter();
            AsyncFd::with_interest(exited, Interest::READABLE).map_err(GuardianError::Runtime)
        }
        _ => Err(GuardianError::NotReady),
    }
}

impl Unstarted {
    pub fn new() -> Result<Self, GuardianError> {
        let (socket, theirs) = socketpair(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC,
            None,
        )
        .map_err(GuardianError::Socket)?;
        let (queue, messages) = mpsc::unbounded_channel();
        let (written, sent) = watch::channel(0);
        let feed = Arc::new(Feed {
            queue: Mutex::new(Some(Queue {
                messages: queue,
                queued: 0,
            })),
            written: sent,
        });
        Ok(Self {
            feed,
            writer: Writer {
                socket,
                messages,
                written,
            },
            theirs,
        })
    }
}

impl Feed {
    pub fn tell(&self, event: Event) -> u64 {
        let mut queue = self.queue();
        let Some(queue) = queue.as_mut() else {
            return 0;
        };
        // The queue rejects a message only once the writer has stopped, and the
        // task that watches the guardian treats that as its loss.
        let _writer_stopped = queue.messages.send(event);
        queue.queued += 1;
        queue.queued
    }

    pub async fn written(&self, count: u64) {
        let mut written = self.written.clone();
        if written.wait_for(|written| *written >= count).await.is_err() {
            tracing::debug!("the writer of the feed stopped before the message was sent");
        }
    }

    pub(crate) fn close(&self) {
        self.queue().take();
    }

    fn queue(&self) -> MutexGuard<'_, Option<Queue>> {
        self.queue
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }
}

impl Writer {
    fn stopped(&self) -> impl Future<Output = ()> + Send + 'static {
        let mut written = self.written.subscribe();
        async move { while written.changed().await.is_ok() {} }
    }

    pub(crate) fn start(self, runtime: &Handle) {
        runtime.spawn(async move {
            if let Err(error) = self.write().await {
                tracing::error!(%error, "a message could not be sent to the guardian of the mount");
            }
        });
    }

    async fn write(self) -> io::Result<()> {
        let Self {
            socket,
            mut messages,
            written,
        } = self;
        let socket = AsyncFd::with_interest(socket, Interest::WRITABLE)?;
        while let Some(event) = messages.recv().await {
            let wire = Wire::from(event);
            loop {
                let mut writable = socket.writable().await?;
                let sent = writable.try_io(|socket| {
                    retry_on_intr(|| {
                        send(
                            socket.get_ref(),
                            wire.as_bytes(),
                            SendFlags::NOSIGNAL | SendFlags::DONTWAIT,
                        )
                    })
                    .map_err(io::Error::from)
                });
                if let Ok(sent) = sent {
                    sent?;
                    break;
                }
            }
            written.send_modify(|count| *count += 1);
        }
        Ok(())
    }
}

/// A guardian that took over replies to the requests of the mount until it has
/// dropped the pages, and then closes the last descriptor of the connection,
/// which ends the connection and leaves the mountpoint a dead endpoint. The
/// guardian of a mount with auto-unmount then unmounts the mountpoint through
/// the `fusermount3` helper that mounted, and its exit closes the copy of the
/// socket of the helper.
pub fn serve() -> Result<(), GuardianError> {
    let socket = io::stdin()
        .as_fd()
        .try_clone_to_owned()
        .map_err(GuardianError::Stdin)?;
    serve_over(&socket)
}

fn serve_over(socket: &OwnedFd) -> Result<(), GuardianError> {
    let HandOver {
        max_write,
        device,
        lifeline,
        auto_unmount,
        threads,
    } = HandOver::receive(socket)?;
    // The copy of the socket of the helper in `auto_unmount` is closed when this
    // returns, after the descriptor of the connection and the release.
    let device = Connection::new(device, max_write).map_err(GuardianError::Connection)?;
    let outcome = serve_connection(socket, device, lifeline, threads)?;
    if let (Outcome::ClientDied(_), Some(auto_unmount)) = (outcome, &auto_unmount) {
        release::release(auto_unmount)?;
    }
    Ok(())
}

fn serve_connection(
    socket: &OwnedFd,
    device: Connection,
    lifeline: OwnedFd,
    threads: Vec<OwnedFd>,
) -> Result<Outcome, GuardianError> {
    let Waiting { gone, watcher } = lifeline::follow(lifeline, threads)?;
    let ready = Wire::from(Event::Ready);
    match retry_on_intr(|| send(socket, ready.as_bytes(), SendFlags::NOSIGNAL)) {
        // The client exited before its dispatch threads read, so the guardian
        // takes over at once.
        Ok(_) | Err(Errno::PIPE | Errno::CONNRESET) => {}
        Err(errno) => return Err(GuardianError::Socket(errno)),
    }
    let notifier = device.notifier();
    let (stop, stopper) = voidport_fuse::stop().map_err(GuardianError::Stop)?;
    std::thread::scope(|scope| {
        // Dropping this ends the thread that replies to the requests, which the
        // scope waits for, also on every early return below.
        let stopper = stopper;
        let mut answering = None;
        let take_over = || {
            watcher.join().map_err(|_| GuardianError::WatchPanicked)??;
            // The unmount of a mount that ends cleanly ends the connection before
            // its dispatch threads end, and the kernel ended every request of the
            // connection then, so nothing is left to answer.
            if ended(&device)? {
                return Ok(());
            }
            // The requests the client had read and not answered come again, to
            // the thread below. Sent before that thread reads, the notification
            // takes no request away from it between its read and its reply.
            if let Err(error) = notifier.resend() {
                tracing::warn!(%error, "the kernel did not send the requests the client had read again");
            }
            let refusing = std::thread::Builder::new()
                .name("voidport-guardian".to_owned())
                .spawn_scoped(scope, || device.refuse_requests(Errno::IO, &stop))
                .map_err(GuardianError::Thread)?;
            answering = Some(refusing);
            Ok(())
        };
        let outcome = follow(socket, &gone, take_over)?;
        if let Outcome::ClientDied(nodes) = &outcome {
            // A drop the kernel rejects is rejected because the connection is no
            // longer connected, and so is every drop after it.
            if let Err(error) = nodes
                .iter()
                .try_for_each(|&node_id| notifier.invalidate_pages(node_id, 0, None))
            {
                tracing::warn!(%error, "the kernel connection ended before the guardian dropped every page");
            }
        }
        drop(stopper);
        if let Some(answering) = answering {
            let answered = answering
                .join()
                .map_err(|_| GuardianError::ThreadPanicked)?;
            if let Err(error) = answered {
                tracing::error!(%error, "the guardian stopped replying to the requests of the mount");
            }
        }
        Ok(outcome)
    })
}

#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    EndedCleanly,
    ClientDied(HashSet<u64>),
}

fn follow(
    socket: &OwnedFd,
    gone: &OwnedFd,
    take_over: impl FnOnce() -> Result<(), GuardianError>,
) -> Result<Outcome, GuardianError> {
    let mut nodes = HashSet::new();
    loop {
        let mut ready = [
            PollFd::new(gone, PollFlags::IN),
            PollFd::new(socket, PollFlags::IN),
        ];
        retry_on_intr(|| poll(&mut ready, None)).map_err(GuardianError::Socket)?;
        if !ready[0].revents().is_empty() {
            break;
        }
        let Some(event) = receive(socket)? else {
            // The mount closed the socket without an end, so the pages are
            // dropped once the client can no longer reply.
            retry_on_intr(|| poll(&mut [PollFd::new(gone, PollFlags::IN)], None))
                .map_err(GuardianError::Socket)?;
            break;
        };
        if let ControlFlow::Break(outcome) = apply(&mut nodes, event)? {
            return Ok(outcome);
        }
    }
    // What the mount sent before is still in the socket, and so may be an end,
    // which a mount that ends cleanly sends after its dispatch threads ended. The
    // socket of a client that exits ends once the exit has closed its files.
    // Closing a file of the mount waits for the answer to its flush, and a thread
    // of the client may wait for the answer to a request the client had read, so
    // the guardian takes over first.
    take_over()?;
    while let Some(event) = receive(socket)? {
        if let ControlFlow::Break(outcome) = apply(&mut nodes, event)? {
            return Ok(outcome);
        }
    }
    Ok(Outcome::ClientDied(nodes))
}

/// A descriptor of a connection that is no longer connected polls as an error
/// (`fuse_dev_poll`, `fs/fuse/dev.c`).
fn ended(device: &Connection) -> Result<bool, GuardianError> {
    let mut polled = [PollFd::new(device, PollFlags::empty())];
    retry_on_intr(|| poll(&mut polled, Some(&Timespec::default()))).map_err(GuardianError::Poll)?;
    Ok(polled[0].revents().contains(PollFlags::ERR))
}

fn apply(nodes: &mut HashSet<u64>, event: Event) -> Result<ControlFlow<Outcome>, GuardianError> {
    match event {
        Event::Cached(node_id) => {
            nodes.insert(node_id);
        }
        Event::Forgot(node_id) => {
            nodes.remove(&node_id);
        }
        Event::End => return Ok(ControlFlow::Break(Outcome::EndedCleanly)),
        Event::Ready => return Err(GuardianError::MisplacedReady),
    }
    Ok(ControlFlow::Continue(()))
}

pub(crate) fn receive(socket: &OwnedFd) -> Result<Option<Event>, GuardianError> {
    let mut buffer = [0; size_of::<Wire>()];
    // A peer that closed its end reports the end of the stream, or a reset when
    // it closed with data it had not read.
    let received = match retry_on_intr(|| recv(socket, &mut buffer, RecvFlags::empty())) {
        Ok((0, _)) | Err(Errno::CONNRESET) => return Ok(None),
        Ok((received, _)) => received,
        Err(errno) => return Err(GuardianError::Socket(errno)),
    };
    Wire::try_read_from_bytes(&buffer[..received])
        .map(|wire| Some(Event::from(wire)))
        .map_err(|_| GuardianError::UnknownMessage)
}

#[cfg(test)]
mod tests {
    use rustix::event::{EventfdFlags, eventfd};
    use rustix::fs::fstat;

    use super::*;

    fn socket_pair() -> (OwnedFd, OwnedFd) {
        socketpair(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC,
            None,
        )
        .expect("a socket pair")
    }

    fn tell(socket: &OwnedFd, events: &[Event]) {
        for &event in events {
            send(socket, Wire::from(event).as_bytes(), SendFlags::NOSIGNAL).expect("a message");
        }
    }

    fn client() -> OwnedFd {
        eventfd(0, EventfdFlags::CLOEXEC).expect("an eventfd")
    }

    fn die(client: &OwnedFd) {
        rustix::io::write(client, &1_u64.to_ne_bytes()).expect("the client died");
    }

    #[test]
    fn the_descriptors_arrive_as_themselves() {
        let (mount, guardian) = socket_pair();
        let (device, client) = socket_pair();
        let (first, last) = socket_pair();
        let (helper, _) = socket_pair();
        let sent = HandOver {
            max_write: 1 << 20,
            device,
            lifeline: client,
            auto_unmount: Some(AutoUnmountCopy {
                socket: helper,
                mountpoint: PathBuf::from("/mnt/a mountpoint"),
                helper: Fusermount::new("/bin/fusermount3"),
            }),
            threads: vec![first, last],
        };
        sent.send(&mount).expect("handed over");

        let received = HandOver::receive(&guardian).expect("received");
        assert_eq!(received.max_write, sent.max_write);
        let inode = |descriptor: &OwnedFd| {
            let stat = fstat(descriptor).expect("a stat");
            (stat.st_dev, stat.st_ino)
        };
        assert_eq!(inode(&received.device), inode(&sent.device));
        assert_eq!(inode(&received.lifeline), inode(&sent.lifeline));
        let auto_unmount = |hand_over: &HandOver| {
            hand_over.auto_unmount.as_ref().map(|auto_unmount| {
                (
                    inode(&auto_unmount.socket),
                    auto_unmount.mountpoint.clone(),
                    auto_unmount.helper.clone(),
                )
            })
        };
        assert_eq!(auto_unmount(&received), auto_unmount(&sent));
        assert_eq!(
            received.threads.iter().map(inode).collect::<Vec<_>>(),
            sent.threads.iter().map(inode).collect::<Vec<_>>(),
        );
    }

    #[test]
    fn a_path_longer_than_the_kernel_accepts_is_not_handed_over() {
        let (mount, _guardian) = socket_pair();
        let (device, lifeline) = socket_pair();
        let (socket, _) = socket_pair();
        let longest = usize::try_from(longest_path()).expect("a path length fits in memory");
        let hand_over = HandOver {
            max_write: 1 << 20,
            device,
            lifeline,
            auto_unmount: Some(AutoUnmountCopy {
                socket,
                mountpoint: PathBuf::from(format!("/{}", "a".repeat(longest))),
                helper: Fusermount::new("/bin/fusermount3"),
            }),
            threads: Vec::new(),
        };
        assert!(matches!(
            hand_over.send(&mount),
            Err(GuardianError::PathTooLong)
        ));
    }

    fn receive(payload: &[u8], descriptors: &[&OwnedFd]) -> Result<HandOver, GuardianError> {
        let (mount, guardian) = socket_pair();
        let descriptors: Vec<_> = descriptors
            .iter()
            .map(|descriptor| descriptor.as_fd())
            .collect();
        let mut space =
            vec![MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(descriptors.len()))];
        let mut control = SendAncillaryBuffer::new(&mut space);
        assert!(control.push(SendAncillaryMessage::ScmRights(&descriptors)));
        sendmsg(
            &mount,
            &[IoSlice::new(payload)],
            &mut control,
            SendFlags::NOSIGNAL,
        )
        .expect("sent");
        HandOver::receive(&guardian)
    }

    fn payload(mountpoint_length: u32, paths: &[u8]) -> Vec<u8> {
        let header = HandOverData {
            max_write: 1 << 20,
            mountpoint_length,
        };
        [header.as_bytes(), paths].concat()
    }

    #[test]
    fn a_first_message_that_does_not_describe_its_descriptors_is_refused() {
        let (device, lifeline) = socket_pair();
        let (socket, _) = socket_pair();
        let all = [&device, &lifeline, &socket];
        let longest = usize::try_from(longest_path()).expect("a path length fits in memory");
        let truncated = payload(1, &vec![b'a'; 2 * longest + 1]);
        let malformed: [(&str, &[u8]); 5] = [
            ("shorter than the header", &[0; 4]),
            ("an empty mountpoint", &payload(0, b"/bin/fusermount3")),
            ("an empty path of the helper", &payload(4, b"/mnt")),
            (
                "a mountpoint past the end",
                &payload(40, b"/mnt/bin/fusermount3"),
            ),
            ("longer than the guardian reads", &truncated),
        ];
        for (case, payload) in malformed {
            assert!(
                matches!(
                    receive(payload, &all),
                    Err(GuardianError::MalformedHandOver)
                ),
                "{case}"
            );
        }
        assert!(matches!(
            receive(&payload(4, b"/mnt/bin/fusermount3"), &[&device, &lifeline]),
            Err(GuardianError::MissingDescriptors)
        ));
        assert!(matches!(
            receive(&payload(0, &[]), &[&device]),
            Err(GuardianError::MissingDescriptors)
        ));
    }

    #[test]
    fn a_mount_that_ends_cleanly_leaves_its_guardian_nothing_to_drop() {
        let (mount, guardian) = socket_pair();
        let client = client();
        tell(
            &mount,
            &[
                Event::Cached(7),
                Event::Forgot(7),
                Event::Cached(8),
                Event::End,
            ],
        );

        assert_eq!(
            follow(&guardian, &client, || Ok(())).expect("followed"),
            Outcome::EndedCleanly
        );
    }

    #[test]
    fn a_mount_that_ends_cleanly_after_its_dispatch_threads_ended_leaves_its_guardian_nothing_to_drop()
     {
        let (mount, guardian) = socket_pair();
        let client = client();
        tell(&mount, &[Event::Cached(7)]);
        // The unmount ended the session, and with it the dispatch threads, before
        // the mount sends its end.
        die(&client);

        let take_over = || {
            tell(&mount, &[Event::End]);
            Ok(())
        };
        assert_eq!(
            follow(&guardian, &client, take_over).expect("followed"),
            Outcome::EndedCleanly
        );
    }

    #[test]
    fn the_guardian_reads_what_a_dead_client_sent_and_keeps_every_node_not_forgotten() {
        let (mount, guardian) = socket_pair();
        let client = client();
        tell(
            &mount,
            &[
                Event::Cached(7),
                Event::Cached(8),
                Event::Forgot(8),
                Event::Cached(9),
            ],
        );
        drop(mount);
        die(&client);

        assert_eq!(
            follow(&guardian, &client, || Ok(())).expect("followed"),
            Outcome::ClientDied(HashSet::from([7, 9]))
        );
    }

    #[test]
    fn the_guardian_takes_over_before_it_reads_the_socket_of_a_dying_client_to_its_end() {
        let (mount, guardian) = socket_pair();
        let client = client();
        tell(&mount, &[Event::Cached(7)]);
        die(&client);

        // The socket of a dying client ends only once its exit got the answers it
        // waits for, which the guardian gives once it took over.
        let mut exiting = Some(mount);
        let take_over = || {
            drop(exiting.take());
            Ok(())
        };
        assert_eq!(
            follow(&guardian, &client, take_over).expect("followed"),
            Outcome::ClientDied(HashSet::from([7]))
        );
    }

    #[test]
    fn a_guardian_whose_client_exited_before_it_reported_takes_over_and_ends() {
        let (mount, guardian) = socket_pair();
        // A datagram socket in place of the kernel connection, which has no
        // request to answer.
        let (device, _kernel) = socketpair(
            AddressFamily::UNIX,
            SocketType::DGRAM,
            SocketFlags::CLOEXEC,
            None,
        )
        .expect("a socket pair");
        let lifeline = Lifeline::new(NonZeroUsize::MIN).expect("a lifeline");
        let thread = std::thread::scope(|scope| {
            scope
                .spawn(|| lifeline.hold(0))
                .join()
                .expect("the dispatch thread ends")
        })
        .expect("the dispatch thread holds its futex");
        HandOver {
            max_write: 1 << 20,
            device,
            lifeline: lifeline.memory().expect("the memory"),
            auto_unmount: None,
            threads: vec![thread],
        }
        .send(&mount)
        .expect("handed over");
        drop(mount);

        serve_over(&guardian).expect("the guardian takes over and ends");
    }

    #[tokio::test]
    async fn a_feed_whose_guardian_is_gone_stops_its_writer() {
        let Unstarted {
            feed,
            writer,
            theirs,
        } = Unstarted::new().expect("a feed");
        let stopped = writer.stopped();
        drop(theirs);
        writer.start(&Handle::current());

        let sent = feed.tell(Event::Cached(1));
        stopped.await;
        feed.written(sent).await;
    }
}
