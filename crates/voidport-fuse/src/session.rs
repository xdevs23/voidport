use std::io;
use std::num::NonZeroUsize;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::Path;
use std::sync::{Arc, OnceLock};
use std::thread;

use rustix::io::Errno;
use zerocopy::IntoBytes as _;
use zerocopy::byteorder::native_endian::{I64, U64};

use crate::abi::{self, NotifyCode, opcode};
use crate::device::Device;
use crate::init::{self, Init, InitError, LimitError, Limits, MissingCapabilities};
use crate::mount::{self, AutoUnmountCopy, MountError, MountOptions, UnmountError};
use crate::reply::{Reply, ReplyEmpty, ReplyInterrupt};
use crate::request::{self, Message, Operation, Refusal, Request};
use crate::stop::Stop;

/// One value answers every dispatch thread, so it is shared between them.
pub trait Filesystem: Sync {
    /// The dispatch thread reads the next request once this returns, so an
    /// operation that takes time moves its reply to another thread and
    /// answers there. Names and data in the operation borrow from the buffer
    /// of the dispatch thread and are gone once this returns.
    fn handle(&self, request: Request, operation: Operation<'_>);
}

#[derive(Debug, thiserror::Error)]
pub enum StartError {
    /// The limits of this host on one request do not fit the protocol.
    /// Nothing was mounted.
    #[error(transparent)]
    Limits(#[from] LimitError),
    #[error(transparent)]
    Mount(#[from] MountError),
    /// The FUSE_INIT exchange failed, and the mount was unmounted again.
    #[error(transparent)]
    Init(InitError),
    /// The FUSE_INIT exchange failed, and the mount could not be unmounted
    /// again: the one start error that leaves a mount. Every request to it
    /// fails.
    #[error("FUSE_INIT failed ({init}), and the mount could not be unmounted again")]
    Unmount {
        init: InitError,
        #[source]
        source: UnmountError,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum ReadError {
    #[error("a request could not be read from /dev/fuse")]
    Read(#[source] Errno),
    #[error("the kernel sent a request whose header does not describe the bytes read")]
    Malformed,
}

/// Why a session ended with an error. `E` is the error of the code run
/// before the first read of a dispatch thread.
#[derive(Debug, thiserror::Error)]
pub enum ServeError<E = io::Error> {
    #[error("the connection could not be cloned for a further dispatch thread")]
    Clone(#[source] io::Error),
    /// A dispatch thread could not be started. No thread read a request.
    #[error("a dispatch thread could not be started")]
    Spawn(#[source] io::Error),
    /// The code run before the first read of a dispatch thread failed, and
    /// that thread read nothing.
    #[error("the code run before dispatch thread {thread} reads failed")]
    Prepare {
        thread: usize,
        #[source]
        source: E,
    },
    #[error("dispatch thread {thread} stopped reading")]
    Read {
        thread: usize,
        #[source]
        source: ReadError,
    },
    #[error("dispatch thread {thread} panicked")]
    Panicked { thread: usize },
}

/// The session never unmounts. A mount made with
/// [`auto_unmount`](MountOptions::auto_unmount) is unmounted by its helper
/// once the session and every [`Notifier`] of it are dropped, which waits
/// for the helper, or once this process is gone, and in either case only
/// once every copy made with [`Session::clone_connection`] is closed.
#[derive(Debug)]
pub struct Session<F> {
    device: Arc<Device>,
    max_write: u32,
    filesystem: F,
}

impl<F> Session<F> {
    /// `negotiate` sees the capabilities the kernel offers, asks for those
    /// the filesystem needs, and returns the filesystem. It runs before this
    /// returns, on the calling thread.
    ///
    /// # Errors
    ///
    /// [`StartError::Limits`] when the limits of this host do not fit the
    /// protocol, [`StartError::Mount`] when the mount failed, and
    /// [`StartError::Init`] when the exchange failed or `negotiate` rejected
    /// what the kernel offers. The mount made for the exchange is unmounted
    /// again then, and [`StartError::Unmount`] says that it could not be.
    pub fn mount(
        mountpoint: &Path,
        options: &MountOptions,
        negotiate: impl FnOnce(&mut Init) -> Result<F, MissingCapabilities>,
    ) -> Result<Self, StartError> {
        let limits = Limits::of_host()?;
        let mounted = mount::mount(mountpoint, options)?;
        match init::exchange(&mounted.device, limits, negotiate) {
            Ok((filesystem, max_write)) => Ok(Self {
                device: Arc::new(mounted.device),
                max_write,
                filesystem,
            }),
            Err(init) => match mounted.unmount(mountpoint) {
                Ok(()) => Err(StartError::Init(init)),
                Err(source) => Err(StartError::Unmount { init, source }),
            },
        }
    }

    /// The most bytes of data one write request contains, as negotiated.
    /// A [`Connection`] made from a clone of this session needs it.
    #[must_use]
    pub fn max_write(&self) -> u32 {
        self.max_write
    }

    #[must_use]
    pub fn notifier(&self) -> Notifier {
        Notifier {
            device: Arc::clone(&self.device),
        }
    }

    /// # Errors
    ///
    /// The error of opening `/dev/fuse`, of attaching the new descriptor, or
    /// of duplicating the socket of the helper of the auto-unmount.
    pub fn clone_connection(&self) -> io::Result<ClonedConnection> {
        Ok(ClonedConnection {
            connection: self.device.clone_connection()?.into(),
            auto_unmount: self.device.copy_auto_unmount()?,
        })
    }
}

#[derive(Debug)]
pub struct ClonedConnection {
    /// The new descriptor. While it is open, the connection lives on.
    pub connection: OwnedFd,
    /// For a mount made with [`auto_unmount`](MountOptions::auto_unmount),
    /// a copy of the auto-unmount. The helper checks whether to unmount only
    /// once every copy of the end of its socket is closed, so the process
    /// that reads the connection closes the copy only after `connection`.
    pub auto_unmount: Option<AutoUnmountCopy>,
}

impl<F: Filesystem> Session<F> {
    /// The first thread reads the descriptor of the session, and each
    /// further one a clone of it. Each thread runs `prepare` with its index,
    /// from 0, before it reads its first request. A thread whose `prepare`
    /// fails reads nothing and ends with that error, of a type the caller
    /// chooses, and the other threads go on.
    ///
    /// The connection ends when the last mount of it is gone, when it is
    /// aborted, or when its last descriptor is closed. A stop ends each
    /// thread before its next read, and the requests the kernel has queued
    /// are still queued on the connection. This returns once every thread
    /// has ended, so that nothing uses the filesystem afterwards.
    ///
    /// # Errors
    ///
    /// The error of the first thread, in the order of their indices, that
    /// ended with one, or the error that stopped the threads from starting.
    pub fn serve<P, E>(
        self,
        threads: NonZeroUsize,
        stop: &Stop,
        prepare: P,
    ) -> Result<(), ServeError<E>>
    where
        P: Fn(usize) -> Result<(), E> + Sync,
        E: Send,
    {
        let mut devices = vec![Arc::clone(&self.device)];
        for _ in 1..threads.get() {
            let clone = self.device.clone_connection().map_err(ServeError::Clone)?;
            devices.push(Arc::new(clone));
        }
        let devices: Arc<[Arc<Device>]> = devices.into();
        // Set once every thread is started: `true` lets them read, and `false`
        // ends those already started when one could not be.
        let start = OnceLock::<bool>::new();
        thread::scope(|scope| {
            let mut handles = Vec::with_capacity(devices.len());
            for (index, device) in devices.iter().enumerate() {
                let dispatcher = Dispatcher {
                    filesystem: &self.filesystem,
                    device: Arc::clone(device),
                    devices: Arc::clone(&devices),
                    stop,
                    read_size: init::read_size(self.max_write),
                };
                let (start, prepare) = (&start, &prepare);
                let spawned = thread::Builder::new()
                    .name(format!("fuse-dispatch-{index}"))
                    .spawn_scoped(scope, move || {
                        if !*start.wait() {
                            return Ok(());
                        }
                        prepare(index).map_err(|source| ServeError::Prepare {
                            thread: index,
                            source,
                        })?;
                        dispatcher.run().map_err(|source| ServeError::Read {
                            thread: index,
                            source,
                        })
                    });
                match spawned {
                    Ok(handle) => handles.push(handle),
                    Err(error) => {
                        // The threads started so far end without reading,
                        // and the scope waits for them.
                        start.get_or_init(|| false);
                        return Err(ServeError::Spawn(error));
                    }
                }
            }
            start.get_or_init(|| true);
            join(handles)
        })
    }
}

fn join<E>(
    handles: Vec<thread::ScopedJoinHandle<'_, Result<(), ServeError<E>>>>,
) -> Result<(), ServeError<E>> {
    handles
        .into_iter()
        .enumerate()
        .map(|(thread, handle)| {
            handle
                .join()
                .unwrap_or(Err(ServeError::Panicked { thread }))
        })
        .fold(Ok(()), Result::and)
}

struct Dispatcher<'a, F> {
    filesystem: &'a F,
    device: Arc<Device>,
    /// Every descriptor of the session, which an interrupt is answered
    /// through.
    devices: Arc<[Arc<Device>]>,
    stop: &'a Stop,
    read_size: usize,
}

impl<F: Filesystem> Dispatcher<'_, F> {
    /// Dispatches until the connection ends, the kernel sends FUSE_DESTROY,
    /// or the session stops.
    fn run(&self) -> Result<(), ReadError> {
        let mut buffer = vec![0; self.read_size];
        while let Some(message) = read_request(&self.device, &mut buffer, self.stop)? {
            if message.opcode() == opcode::DESTROY {
                ReplyEmpty(self.reply(&message)).ok();
                return Ok(());
            }
            self.dispatch(&message);
        }
        Ok(())
    }

    fn reply(&self, message: &Message<'_>) -> Reply {
        Reply::new(Arc::clone(&self.device), message.unique())
    }

    fn dispatch(&self, message: &Message<'_>) {
        let request = message.request();
        let hand_over = |operation| self.filesystem.handle(request, operation);
        let handed = match message.opcode() {
            opcode::FORGET => {
                request::forget(message).map(|forget| hand_over(Operation::Forget(forget)))
            }
            opcode::BATCH_FORGET => request::batch_forget(message)
                .map(|forgets| forgets.for_each(|forget| hand_over(Operation::Forget(forget)))),
            opcode::INTERRUPT => request::interrupt(message).map(|interrupt| {
                let reply = ReplyInterrupt::new(Arc::clone(&self.devices), message.unique());
                hand_over(Operation::Interrupt(interrupt, reply));
            }),
            opcode::INIT => {
                tracing::warn!(
                    unique = message.unique(),
                    "FUSE_INIT arrived again, answered EIO"
                );
                self.reply(message).error(Errno::IO);
                Ok(())
            }
            _ => request::decode(message, || self.reply(message)).map(hand_over),
        };
        if let Err(refusal) = handed {
            if message.expects_reply() {
                log_refusal(message, refusal);
                self.reply(message).error(refusal.errno());
            } else {
                ignore(message, refusal);
            }
        }
    }
}

fn ignore(message: &Message<'_>, refusal: Refusal) {
    tracing::warn!(
        opcode = message.opcode(),
        unique = message.unique(),
        ?refusal,
        "a FUSE request without a reply does not decode and is dropped"
    );
}

fn log_refusal(message: &Message<'_>, refusal: Refusal) {
    let (opcode, unique) = (message.opcode(), message.unique());
    match refusal {
        Refusal::Unsupported => {
            tracing::warn!(
                opcode,
                unique,
                "unsupported FUSE operation, answered ENOSYS"
            );
        }
        Refusal::HasFallback => {
            tracing::debug!(
                opcode,
                unique,
                "a FUSE operation the kernel does without, answered ENOSYS"
            );
        }
        Refusal::Malformed => {
            tracing::warn!(
                opcode,
                unique,
                "a FUSE request does not decode, answered EIO"
            );
        }
        Refusal::OffsetTooLarge => {
            tracing::debug!(
                opcode,
                unique,
                "a FUSE request names an offset past any file, answered EINVAL"
            );
        }
    }
}

fn read_request<'b>(
    device: &Device,
    buffer: &'b mut [u8],
    stop: &Stop,
) -> Result<Option<Message<'b>>, ReadError> {
    let Some(read) = device.read_unless_stopped(buffer, stop).transpose() else {
        return Ok(None);
    };
    message_in(read, buffer)
}

/// A read of a connection that ended fails with `ENODEV`, or with
/// `ECONNABORTED` where the connection was aborted with an error
/// (`fuse_dev_do_read` in `fs/fuse/dev.c`, Linux 7.3).
fn message_in(read: Result<usize, Errno>, buffer: &[u8]) -> Result<Option<Message<'_>>, ReadError> {
    let length = match read {
        Ok(length) => length,
        Err(Errno::NODEV | Errno::CONNABORTED) => return Ok(None),
        Err(error) => return Err(ReadError::Read(error)),
    };
    Message::parse(&buffer[..length])
        .map(Some)
        .ok_or(ReadError::Malformed)
}

#[derive(Clone, Debug)]
pub struct Notifier {
    device: Arc<Device>,
}

impl Notifier {
    /// Drops the cached attributes of `node`, and its cached pages from
    /// `offset` on, for `length` bytes or to the end of the file for none.
    ///
    /// This returns once the kernel has dropped them. The kernel waits for
    /// every page under a read in progress, so the thread that calls this
    /// must not be one that the reply to such a read depends on.
    ///
    /// # Errors
    ///
    /// `EINVAL` for an `offset` or a `length` past the largest file offset,
    /// and otherwise the error of the kernel. A node the kernel no longer
    /// knows has nothing cached and counts as success.
    pub fn invalidate_pages(
        &self,
        node: u64,
        offset: u64,
        length: Option<u64>,
    ) -> Result<(), Errno> {
        let offset = i64::try_from(offset).map_err(|_| Errno::INVAL)?;
        let length = match length {
            // The wire reads a length of 0 as the end of the file.
            None => 0,
            Some(0) => return self.invalidate_attributes(node),
            Some(length) => i64::try_from(length).map_err(|_| Errno::INVAL)?,
        };
        self.invalidate_inode(node, offset, length)
    }

    /// # Errors
    ///
    /// The error of the kernel. A node the kernel no longer knows has
    /// nothing cached and counts as success.
    pub fn invalidate_attributes(&self, node: u64) -> Result<(), Errno> {
        // A negative offset leaves the pages in place.
        self.invalidate_inode(node, -1, 0)
    }

    fn invalidate_inode(&self, node: u64, offset: i64, length: i64) -> Result<(), Errno> {
        let notification = abi::NotifyInvalInodeOut {
            ino: U64::new(node),
            off: I64::new(offset),
            len: I64::new(length),
        };
        match self
            .device
            .notify(NotifyCode::InvalInode, notification.as_bytes())
        {
            Ok(()) | Err(Errno::NOENT) => Ok(()),
            Err(error) => Err(error),
        }
    }

    /// # Errors
    ///
    /// The error of the kernel: `EINVAL` from a kernel without
    /// FUSE_NOTIFY_RESEND, and before FUSE_INIT is answered.
    pub fn resend(&self) -> Result<(), Errno> {
        self.device.notify(NotifyCode::Resend, &[])
    }
}

#[derive(Debug)]
pub struct Connection {
    device: Arc<Device>,
    max_write: u32,
}

impl Connection {
    /// Takes a descriptor attached to a connection whose writes contain at
    /// most `max_write` bytes, as [`Session::max_write`] returns it.
    ///
    /// # Errors
    ///
    /// The error of moving a descriptor numbered like a standard stream to a
    /// higher number, or of making its reads return at once.
    pub fn new(descriptor: OwnedFd, max_write: u32) -> io::Result<Self> {
        Ok(Self {
            device: Arc::new(Device::new(descriptor)?),
            max_write,
        })
    }

    #[must_use]
    pub fn notifier(&self) -> Notifier {
        Notifier {
            device: Arc::clone(&self.device),
        }
    }

    /// Answers every request read through this descriptor with `error`,
    /// except FUSE_FORGET, FUSE_BATCH_FORGET and FUSE_INTERRUPT, which the
    /// kernel does not expect a reply to. It returns once the connection
    /// ends, or once `stop` is requested.
    ///
    /// # Errors
    ///
    /// A read error other than the end of the connection, or a request
    /// whose header does not describe the bytes read.
    pub fn refuse_requests(&self, error: Errno, stop: &Stop) -> Result<(), ReadError> {
        let mut buffer = vec![0; init::read_size(self.max_write)];
        while let Some(message) = read_request(&self.device, &mut buffer, stop)? {
            if message.expects_reply() {
                Reply::new(Arc::clone(&self.device), message.unique()).error(error);
            }
        }
        Ok(())
    }
}

impl AsFd for Connection {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.device.as_fd()
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixDatagram;
    use std::sync::Mutex;

    use zerocopy::FromBytes as _;
    use zerocopy::byteorder::native_endian::U32;

    use super::*;
    use crate::device::tests::{answer, kernel};
    use crate::reply::ErrorReply as _;
    use crate::request::tests::{UNKNOWN_OPCODE, request};

    #[derive(Default)]
    struct Recorder(Mutex<Vec<String>>);

    impl Filesystem for Recorder {
        fn handle(&self, request: Request, operation: Operation<'_>) {
            let recorded = match operation {
                Operation::Forget(forget) => format!("forget {} {}", forget.node, forget.lookups),
                Operation::Interrupt(interrupt, reply) => {
                    reply.retry();
                    format!("interrupt {}", interrupt.target)
                }
                Operation::Lookup(lookup, reply) => {
                    reply.error(Errno::NOENT);
                    format!(
                        "lookup {} {:?} by {}",
                        lookup.parent, lookup.name, request.uid
                    )
                }
                other => {
                    other.unsupported();
                    "other".to_owned()
                }
            };
            self.0.lock().expect("not poisoned").push(recorded);
        }
    }

    const DESTROY_UNIQUE: u64 = 1000;

    fn dispatch(requests: &[Vec<u8>]) -> (Vec<String>, Result<(), ReadError>, UnixDatagram) {
        let mut requests = requests.to_vec();
        requests.push(request(opcode::DESTROY, 0, DESTROY_UNIQUE, &[]));
        let (device, kernel) = kernel(&requests);
        let device = Arc::new(device);
        let recorder = Recorder::default();
        let (stop, _running) = crate::stop().expect("a stop");
        let dispatcher = Dispatcher {
            filesystem: &recorder,
            device: Arc::clone(&device),
            devices: Arc::from([device]),
            stop: &stop,
            read_size: init::read_size(4096),
        };
        let ended = dispatcher.run();
        (
            recorder.0.into_inner().expect("not poisoned"),
            ended,
            kernel,
        )
    }

    fn header(kernel: &UnixDatagram) -> abi::OutHeader {
        answer(kernel).0
    }

    #[test]
    fn each_request_reaches_the_filesystem_with_its_identity_and_its_reply() {
        let (recorded, ended, kernel) = dispatch(&[request(opcode::LOOKUP, 1, 6, &[b"a\0"])]);
        assert!(ended.is_ok());
        assert_eq!(recorded, ["lookup 1 \"a\" by 1000"]);
        let reply = header(&kernel);
        assert_eq!(
            (reply.unique.get(), reply.error.get()),
            (6, -Errno::NOENT.raw_os_error())
        );
    }

    #[test]
    fn forgets_are_handed_over_one_node_at_a_time_without_an_answer() {
        let batch = abi::BatchForgetIn {
            count: U32::new(2),
            dummy: U32::ZERO,
        };
        let one = |node: u64| abi::ForgetOne {
            nodeid: U64::new(node),
            nlookup: U64::new(1),
        };
        let forget = abi::ForgetIn {
            nlookup: U64::new(4),
        };
        let (recorded, _, kernel) = dispatch(&[
            request(opcode::FORGET, 9, 2, &[forget.as_bytes()]),
            request(
                opcode::BATCH_FORGET,
                0,
                4,
                &[batch.as_bytes(), one(3).as_bytes(), one(5).as_bytes()],
            ),
        ]);
        assert_eq!(recorded, ["forget 9 4", "forget 3 1", "forget 5 1"]);
        assert_eq!(
            header(&kernel).unique.get(),
            DESTROY_UNIQUE,
            "the first answer is the last one"
        );
    }

    #[test]
    fn an_interrupt_reaches_the_filesystem_with_the_request_it_names() {
        let interrupt = abi::InterruptIn {
            unique: U64::new(40),
        };
        let (recorded, _, kernel) =
            dispatch(&[request(opcode::INTERRUPT, 0, 41, &[interrupt.as_bytes()])]);
        assert_eq!(recorded, ["interrupt 40"]);
        let reply = header(&kernel);
        assert_eq!(
            (reply.unique.get(), reply.error.get()),
            (41, -Errno::AGAIN.raw_os_error())
        );
    }

    #[test]
    fn a_request_the_filesystem_cannot_take_is_answered_and_the_dispatch_goes_on() {
        let (recorded, _, kernel) = dispatch(&[
            request(opcode::LOOKUP, 1, 2, &[b"no terminator"]),
            request(UNKNOWN_OPCODE, 1, 4, &[]),
            request(opcode::INIT, 0, 6, &[]),
            request(opcode::LOOKUP, 1, 8, &[b"b\0"]),
        ]);
        assert_eq!(recorded, ["lookup 1 \"b\" by 1000"]);
        let errors: Vec<(u64, i32)> = (0..4)
            .map(|_| header(&kernel))
            .map(|reply| (reply.unique.get(), -reply.error.get()))
            .collect();
        assert_eq!(
            errors,
            [
                (2, Errno::IO.raw_os_error()),
                (4, Errno::NOSYS.raw_os_error()),
                (6, Errno::IO.raw_os_error()),
                (8, Errno::NOENT.raw_os_error()),
            ]
        );
    }

    #[test]
    fn a_forget_that_does_not_decode_gets_no_reply() {
        let (recorded, _, kernel) = dispatch(&[
            request(opcode::FORGET, 9, 2, &[]),
            request(opcode::LOOKUP, 1, 4, &[b"a\0"]),
        ]);
        assert_eq!(recorded, ["lookup 1 \"a\" by 1000"]);
        assert_eq!(
            header(&kernel).unique.get(),
            4,
            "the first reply is the one to the lookup"
        );
    }

    #[test]
    fn destroy_is_answered_and_ends_the_thread() {
        let (recorded, ended, kernel) = dispatch(&[
            request(opcode::DESTROY, 0, 2, &[]),
            request(opcode::LOOKUP, 1, 4, &[b"a\0"]),
        ]);
        assert!(ended.is_ok());
        assert!(recorded.is_empty());
        let (reply, payload) = answer(&kernel);
        assert_eq!((reply.unique.get(), reply.error.get()), (2, 0));
        assert!(payload.is_empty());
        kernel.set_nonblocking(true).expect("non-blocking");
        assert!(
            kernel.recv(&mut [0; 64]).is_err(),
            "nothing after FUSE_DESTROY is answered"
        );
    }

    #[test]
    fn a_header_longer_than_the_request_ends_the_thread() {
        let mut short = request(opcode::LOOKUP, 1, 2, &[b"a\0"]);
        short.truncate(short.len() - 1);
        let (_, ended, kernel) = dispatch(&[short]);
        assert!(matches!(ended, Err(ReadError::Malformed)));
        kernel.set_nonblocking(true).expect("non-blocking");
        assert!(
            kernel.recv(&mut [0; 64]).is_err(),
            "the FUSE_DESTROY after it is not read"
        );
    }

    #[test]
    fn a_bare_connection_refuses_every_request_that_waits_for_an_answer() {
        let interrupt = abi::InterruptIn {
            unique: U64::new(40),
        };
        let forget = abi::ForgetIn {
            nlookup: U64::new(1),
        };
        let (device, kernel) = kernel(&[
            request(opcode::FORGET, 9, 2, &[forget.as_bytes()]),
            request(opcode::INTERRUPT, 0, 41, &[interrupt.as_bytes()]),
            request(opcode::READ, 5, 6, &[abi::ReadIn::default().as_bytes()]),
            request(opcode::DESTROY, 0, 8, &[]),
        ]);
        let connection = Connection {
            device: Arc::new(device),
            max_write: 4096,
        };
        let (stop, _running) = crate::stop().expect("a stop");
        // The end of the input reads as a request of no bytes.
        assert!(matches!(
            connection.refuse_requests(Errno::IO, &stop),
            Err(ReadError::Malformed)
        ));
        for unique in [6, 8] {
            let reply = header(&kernel);
            assert_eq!(
                (reply.unique.get(), reply.error.get()),
                (unique, -Errno::IO.raw_os_error())
            );
        }
    }

    #[test]
    fn a_stopped_bare_connection_returns_without_reading() {
        let (device, kernel) = kernel(&[request(
            opcode::READ,
            5,
            6,
            &[abi::ReadIn::default().as_bytes()],
        )]);
        let connection = Connection {
            device: Arc::new(device),
            max_write: 4096,
        };
        let (stop, stopper) = crate::stop().expect("a stop");
        drop(stopper);
        assert!(connection.refuse_requests(Errno::IO, &stop).is_ok());
        kernel.set_nonblocking(true).expect("non-blocking");
        assert!(kernel.recv(&mut [0; 64]).is_err(), "nothing is answered");
    }

    #[test]
    fn an_inode_invalidation_is_a_notification_with_its_range() {
        let (device, kernel) = kernel(&[]);
        let notifier = Notifier {
            device: Arc::new(device),
        };
        notifier.invalidate_pages(5, 4096, None).expect("sent");
        notifier.invalidate_pages(5, 0, Some(8192)).expect("sent");
        notifier.invalidate_pages(5, 4096, Some(0)).expect("sent");
        notifier.invalidate_attributes(6).expect("sent");
        assert_eq!(
            notifier.invalidate_pages(5, 1 << 63, None),
            Err(Errno::INVAL),
            "an offset past the largest file offset"
        );
        notifier.resend().expect("sent");

        for (node, offset, length) in [(5, 4096, 0), (5, 0, 8192), (5, -1, 0), (6, -1, 0)] {
            let (header, payload) = answer(&kernel);
            assert_eq!(
                (header.unique.get(), header.error.get()),
                (0, NotifyCode::InvalInode.wire())
            );
            let range = abi::NotifyInvalInodeOut::read_from_bytes(&payload).expect("one range");
            assert_eq!(
                (range.ino.get(), range.off.get(), range.len.get()),
                (node, offset, length)
            );
        }
        let (header, payload) = answer(&kernel);
        assert_eq!(
            (header.unique.get(), header.error.get()),
            (0, NotifyCode::Resend.wire())
        );
        assert!(payload.is_empty());
    }

    struct Threads(Arc<Mutex<Vec<thread::ThreadId>>>);

    impl Filesystem for Threads {
        fn handle(&self, _request: Request, operation: Operation<'_>) {
            operation.unsupported();
            self.0
                .lock()
                .expect("not poisoned")
                .push(thread::current().id());
        }
    }

    fn session(
        requests: &[Vec<u8>],
    ) -> (
        Session<Threads>,
        Arc<Mutex<Vec<thread::ThreadId>>>,
        UnixDatagram,
    ) {
        let mut requests = requests.to_vec();
        requests.push(request(opcode::DESTROY, 0, DESTROY_UNIQUE, &[]));
        let (device, kernel) = kernel(&requests);
        let handled = Arc::new(Mutex::new(Vec::new()));
        let session = Session {
            device: Arc::new(device),
            max_write: 4096,
            filesystem: Threads(Arc::clone(&handled)),
        };
        (session, handled, kernel)
    }

    #[test]
    fn prepare_runs_on_the_thread_that_dispatches() {
        let (session, handled, _kernel) = session(&[request(opcode::LOOKUP, 1, 2, &[b"a\0"])]);
        let prepared = Mutex::new(Vec::new());
        let (stop, _running) = crate::stop().expect("a stop");
        session
            .serve(NonZeroUsize::MIN, &stop, |index| {
                prepared
                    .lock()
                    .expect("not poisoned")
                    .push((index, thread::current().id()));
                Ok::<(), io::Error>(())
            })
            .expect("served");
        let prepared = prepared.into_inner().expect("not poisoned");
        let handled = handled.lock().expect("not poisoned");
        assert_eq!(prepared.len(), 1);
        assert_eq!(prepared[0].0, 0);
        assert_eq!(*handled, [prepared[0].1]);
    }

    #[test]
    fn a_thread_whose_prepare_fails_reads_nothing() {
        let (session, handled, kernel) = session(&[request(opcode::LOOKUP, 1, 2, &[b"a\0"])]);
        let (stop, _running) = crate::stop().expect("a stop");
        let served = session.serve(NonZeroUsize::MIN, &stop, |_| {
            Err(io::Error::from(io::ErrorKind::PermissionDenied))
        });
        assert!(matches!(served, Err(ServeError::Prepare { thread: 0, .. })));
        assert!(handled.lock().expect("not poisoned").is_empty());
        kernel.set_nonblocking(true).expect("non-blocking");
        assert!(kernel.recv(&mut [0; 64]).is_err(), "nothing is answered");
    }

    #[test]
    fn a_waiting_session_ends_once_the_stop_is_requested() {
        let (ours, _theirs) = UnixDatagram::pair().expect("a socket pair");
        let handled = Arc::new(Mutex::new(Vec::new()));
        let session = Session {
            device: Arc::new(Device::new(OwnedFd::from(ours)).expect("a device")),
            max_write: 4096,
            filesystem: Threads(Arc::clone(&handled)),
        };
        let (stop, stopper) = crate::stop().expect("a stop");
        thread::scope(|scope| {
            let serving = scope
                .spawn(|| session.serve(NonZeroUsize::MIN, &stop, |_| Ok::<(), io::Error>(())));
            drop(stopper);
            assert!(
                serving.join().expect("the session does not panic").is_ok(),
                "a stop ends the session without an error"
            );
        });
        assert!(handled.lock().expect("not poisoned").is_empty());
    }

    #[test]
    fn the_result_of_the_threads_is_the_first_error_in_their_order() {
        thread::scope(|scope| {
            let handles = vec![
                scope.spawn(|| Ok(())),
                scope.spawn(|| -> Result<(), ServeError> { panic!("a dispatch thread panics") }),
                scope.spawn(|| {
                    Err(ServeError::Read {
                        thread: 2,
                        source: ReadError::Malformed,
                    })
                }),
            ];
            assert!(matches!(
                join(handles),
                Err(ServeError::Panicked { thread: 1 })
            ));
        });
    }
}
