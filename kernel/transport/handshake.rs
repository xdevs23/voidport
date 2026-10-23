// SPDX-License-Identifier: GPL-2.0
//! Dialling the server: one connection, one handshake, with an optional
//! whole-attempt bound supplied by the core for background probes and joins.
//! The handshake opens a session, or joins one with the token from the reply
//! that opened it. A connection is a stream socket to an endpoint, or a
//! channel of the virtio filesystem device with the tag given by the mount.
//!
//! A completed handshake is the probe of the reconnection contract, so a caller
//! may install the connection the moment this returns.

use core::time::Duration;

use kernel::prelude::*;
use kernel::sync::aref::ARef;
use kernel::sync::{new_condvar, new_mutex, Arc, CondVar, CondVarTimeoutResult, Mutex};
use kernel::task::Task;

use crate::clock::{now, timeout_of};
use crate::thread::Thread;
use voidport_proto::error::FramingError;
use voidport_proto::frame::{FrameWriter, FRAME_HEADER_LEN};
use voidport_proto::ops::handshake::{HelloReply, TOKEN_LEN_MAX};
use voidport_session::backoff::JOIN_ATTEMPT_BOUND;
use voidport_session::handshake::{self, HandshakeError, Negotiated};
use voidport_session::time::{attempt_verdict, AttemptStatus, AttemptVerdict};

use crate::socket::{Endpoint, Network, Stream, Unconnected};
use crate::virtio::{Channel, Device, Tag, Wait};
use crate::wire::{read_header, read_rest, ReadError, ReadFrame, Source, LIMITS};

/// Where the sessions of a mount are.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Server {
    /// A server at a network or unix endpoint, connected to over stream
    /// sockets.
    Socket(Endpoint),
    /// The server behind the virtio filesystem device with this tag,
    /// connected to over channels of the device.
    Device(Tag),
}

/// What one connection of a session travels on.
pub enum Link {
    /// A stream socket.
    Stream(Stream),
    /// A channel of a virtio filesystem device.
    Channel(Channel),
}

/// Why a dial did not open a session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dial {
    /// The endpoint's address family is not available in this kernel.
    FamilyUnavailable,
    /// The endpoint could not be connected to.
    Connect(Error),
    /// The stream failed during the handshake.
    Transport(Error),
    /// The server is reachable and refuses this mount, with its own errno.
    Refused(Error),
    /// The server's reply was not one this client can open a session on.
    Handshake(HandshakeError),
    /// The namespace, the path or the token is longer than a handshake can
    /// fit.
    TooLong,
    /// No virtio filesystem device of this module has the tag.
    NoDevice,
}

impl Dial {
    /// The errno a caller answers with.
    pub fn errno(self) -> Error {
        match self {
            Self::FamilyUnavailable | Self::NoDevice => ENODEV,
            Self::Connect(error) | Self::Transport(error) | Self::Refused(error) => error,
            Self::Handshake(_) => crate::errno::eproto(),
            Self::TooLong => crate::errno::enametoolong(),
        }
    }

    /// The failure class the session core judges a failed dial by.
    pub fn failure(self) -> handshake::Failure {
        use handshake::Failure;
        match self {
            Self::Refused(error) => Failure::Refused(refusal(error)),
            Self::Handshake(error) => error.failure(|status| refusal(Error::from_errno(status))),
            // A device may come back, as a server behind an endpoint may.
            Self::Connect(_) | Self::Transport(_) | Self::NoDevice => Failure::Transport,
            Self::FamilyUnavailable | Self::TooLong => Failure::Local,
        }
    }

    /// Translate I/O outcomes into the shared reconnect policy.
    pub fn disposition(self) -> handshake::Disposition {
        self.failure().disposition()
    }
}

fn refusal(error: Error) -> handshake::Refusal {
    handshake::Refusal::from_linux_errno(-error.to_errno())
}

/// The session token of a session this mount opened, with which every
/// further connection joins it.
pub type Token = Arc<KVec<u8>>;

/// A connection the server accepted, and what its reply contained.
pub struct Dialed<Kept = Token> {
    /// The connection.
    pub link: Link,
    /// What the session negotiated, and the id it gave this connection.
    pub negotiated: Negotiated,
    /// What the dial saved of the session token: the token itself for a
    /// dial that opens a session, and nothing for one that joins, since the
    /// session already has the token.
    pub token: Kept,
}

type Outcome<Kept = Token> = core::result::Result<Dialed<Kept>, Dial>;

/// The hello a dial sends.
#[derive(Clone, Copy)]
enum Hello<'a> {
    Open { namespace: &'a [u8], path: &'a [u8] },
    Join(&'a [u8]),
}

impl Hello<'_> {
    fn len(self) -> usize {
        match self {
            Self::Open { namespace, path } => handshake::request_len(namespace, path),
            Self::Join(token) => handshake::join_request_len(token),
        }
    }

    /// Encodes the frame into `buffer`, sized by [`Hello::len`].
    fn encode(self, buffer: &mut [u8]) -> core::result::Result<&[u8], handshake::TooLong> {
        match self {
            Self::Open { namespace, path } => handshake::request(buffer, &LIMITS, namespace, path),
            Self::Join(token) => handshake::join_request(buffer, &LIMITS, token),
        }
    }

    /// The length of the reply area of a chain that contains the hello: the
    /// reply to a join contains the token sent with it, and the reply to an
    /// open contains a token of at most [`TOKEN_LEN_MAX`] bytes.
    fn reply_len(self) -> usize {
        let token_len = match self {
            Self::Open { .. } => TOKEN_LEN_MAX,
            Self::Join(token) => token.len(),
        };
        FrameWriter::response_len::<HelloReply>(token_len)
    }

    /// The frame, encoded into memory the size of what it contains.
    fn frame(self) -> core::result::Result<KVVec<u8>, Dial> {
        let mut request =
            KVVec::from_elem(0u8, self.len(), GFP_KERNEL).map_err(|_| Dial::Transport(ENOMEM))?;
        let len = self.encode(&mut request).map_err(|_| Dial::TooLong)?.len();
        request.truncate(len);
        Ok(request)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Availability {
    Open,
    Closed,
}

enum AttemptState<Kept> {
    Idle,
    Running,
    Joined,
    Complete(Outcome<Kept>),
    /// Cancellation may precede worker startup or follow its result.
    Cancelled(Option<Outcome<Kept>>),
}

impl<Kept> AttemptState<Kept> {
    fn complete(&self) -> bool {
        matches!(
            self,
            Self::Complete(_) | Self::Cancelled(Some(_)) | Self::Joined
        )
    }

    fn cancelled(&self) -> bool {
        matches!(self, Self::Cancelled(_))
    }

    fn finish(&mut self, result: Outcome<Kept>) {
        *self = if self.cancelled() {
            Self::Cancelled(Some(result))
        } else {
            Self::Complete(result)
        };
    }

    fn cancel(&mut self) {
        *self = match core::mem::replace(self, Self::Idle) {
            Self::Complete(result) => Self::Cancelled(Some(result)),
            cancelled @ Self::Cancelled(_) => cancelled,
            Self::Idle | Self::Running | Self::Joined => Self::Cancelled(None),
        };
    }

    fn take_result(&mut self) -> Option<Outcome<Kept>> {
        match core::mem::replace(self, Self::Joined) {
            Self::Complete(result) | Self::Cancelled(Some(result)) => Some(result),
            Self::Idle | Self::Running | Self::Cancelled(None) | Self::Joined => None,
        }
    }
}

struct Progress<Kept> {
    availability: Availability,
    state: AttemptState<Kept>,
    // Published after enabling cancellation, for interrupting in-flight I/O.
    // Thread independently retains the reference needed for joining.
    task: Option<ARef<Task>>,
}

impl<Kept> Progress<Kept> {
    /// Only the sole caller of an attempt starts it, after joining the last
    /// worker.
    fn begin(&mut self) -> Result {
        if self.availability == Availability::Closed {
            return Err(EIO);
        }
        self.state = AttemptState::Running;
        self.task = None;
        Ok(())
    }
}

/// Dials one at a time, each on a worker thread of its own that the waiting
/// task interrupts: when the bound of the dial passes, when a signal reaches
/// the waiting task, and when the attempt is closed.
#[pin_data]
struct Attempt<Kept> {
    #[pin]
    progress: Mutex<Progress<Kept>>,
    #[pin]
    changed: CondVar,
}

impl<Kept: Send + Unpin + 'static> Attempt<Kept> {
    fn new() -> Result<Arc<Self>> {
        Arc::pin_init(
            pin_init!(Self {
                progress <- new_mutex!(Progress {
                    availability: Availability::Open,
                    state: AttemptState::Idle,
                    task: None,
                }, "voidport::attempt"),
                changed <- new_condvar!("voidport::attempt_changed"),
            }),
            GFP_KERNEL,
        )
    }

    /// Cancel a current dial and refuse subsequent dials.
    fn close(&self) {
        self.progress.lock().availability = Availability::Closed;
        self.changed.notify_all();
    }

    /// Record cancellation even before the worker publishes its owned task
    /// reference under the attempt mutex after enabling cancellation.
    fn cancel(&self) {
        let mut progress = self.progress.lock();
        progress.state.cancel();
        if !progress.state.complete() {
            if let Some(task) = &progress.task {
                Thread::signal(task);
            }
        }
        drop(progress);
        self.changed.notify_all();
    }

    /// Runs `dial` on a new worker and waits for it. The optional `bound`
    /// covers the whole dial. Cancellation interrupts the dedicated task as
    /// well as closing its stream on return: shutdown alone does not end a
    /// pending connect.
    fn run(
        self: &Arc<Self>,
        bound: Option<Duration>,
        dial: impl FnOnce() -> Outcome<Kept> + Send + 'static,
    ) -> Outcome<Kept> {
        let started = now();
        self.progress.lock().begin().map_err(Dial::Transport)?;
        let (worker, cancellation) = (self.clone(), self.clone());
        let thread = match Thread::spawn(
            c"voidport-hello",
            move || worker.work(dial),
            move || cancellation.cancel(),
        ) {
            Ok(thread) => thread,
            Err(error) => {
                self.progress.lock().state = AttemptState::Joined;
                self.changed.notify_all();
                return Err(Dial::Transport(error));
            }
        };
        let mut progress = self.progress.lock();
        let failure = loop {
            let remaining = match attempt_verdict(
                started,
                now(),
                bound,
                AttemptStatus {
                    closed: progress.availability == Availability::Closed,
                    complete: progress.state.complete(),
                },
            ) {
                AttemptVerdict::Expired => break Some(ETIMEDOUT),
                AttemptVerdict::Closed => break Some(EIO),
                AttemptVerdict::Complete => break None,
                AttemptVerdict::Wait(remaining) => remaining,
            };
            let signalled = match remaining {
                Some(remaining) => matches!(
                    self.changed
                        .wait_interruptible_timeout(&mut progress, timeout_of(remaining)),
                    CondVarTimeoutResult::Signal { .. }
                ),
                None => self.changed.wait_interruptible(&mut progress),
            };
            if signalled {
                break Some(ERESTARTSYS);
            }
        };
        drop(progress);
        // Thread owns both cancellation and the unstarted closure. Stop may
        // precede owned task publication without losing captured ownership.
        thread.stop();
        let mut progress = self.progress.lock();
        progress.task = None;
        let result = progress.state.take_result();
        drop(progress);
        self.changed.notify_all();
        match failure {
            Some(error) => Err(Dial::Transport(error)),
            None => result.unwrap_or(Err(Dial::Transport(EIO))),
        }
    }

    /// The body of the worker: publishes its task for cancellation, then
    /// runs `dial` unless the attempt was cancelled or closed first.
    fn work(&self, dial: impl FnOnce() -> Outcome<Kept>) {
        let _scope = crate::helpers::NoFsScope::enter();
        Thread::allow_cancel();
        {
            let mut progress = self.progress.lock();
            progress.task = Some(ARef::from(&**kernel::current!()));
            if progress.state.cancelled() || progress.availability == Availability::Closed {
                progress.state.finish(Err(Dial::Transport(EIO)));
                drop(progress);
                self.changed.notify_all();
                return;
            }
        }
        let result = dial();
        let mut progress = self.progress.lock();
        progress.state.finish(result);
        drop(progress);
        self.changed.notify_all();
    }
}

/// One `Dialer` per mount.
///
/// A dial that opens a session runs on the attempt of the dialer, one at a
/// time: the mounting task, then one probe at a time. Each is joined before
/// the next can begin, so there is at most one such worker per mount, and
/// close cancels it. A join runs on an attempt of its own, so several can
/// run at once. A join ends when its bound passes or a signal reaches the
/// task that waits for it, and close does not end it.
///
/// The dialer has the network namespace the mount was made in, and every
/// dial creates its socket there.
pub struct Dialer {
    network: Network,
    server: Server,
    namespace: KVec<u8>,
    path: KVec<u8>,
    attempt: Arc<Attempt<Token>>,
}

impl Dialer {
    /// Reserve a cancellable handshake attempt for this server and for
    /// `path` inside `namespace`, an empty path being its root, dialled from
    /// the network namespace `network`.
    pub fn new(
        network: Network,
        server: Server,
        namespace: KVec<u8>,
        path: KVec<u8>,
    ) -> Result<Arc<Self>> {
        Ok(Arc::new(
            Self {
                network,
                server,
                namespace,
                path,
                attempt: Attempt::new()?,
            },
            GFP_KERNEL,
        )?)
    }

    /// The namespace that every session it opens mounts.
    pub fn namespace(&self) -> &[u8] {
        &self.namespace
    }

    /// The path inside the namespace that every session it opens mounts.
    pub fn path(&self) -> &[u8] {
        &self.path
    }

    /// Cancel a current dial that opens a session, and refuse subsequent
    /// ones.
    pub fn close(&self) {
        self.attempt.close();
    }

    /// Opens a session. The optional bound covers connect and both hello
    /// directions. Mount setup supplies no bound, and background probes supply
    /// the bound of the core.
    pub fn dial(self: &Arc<Self>, bound: Option<Duration>) -> Outcome {
        let owner = self.clone();
        self.attempt.run(bound, move || {
            dial(
                &owner.network,
                &owner.server,
                Hello::Open {
                    namespace: &owner.namespace,
                    path: &owner.path,
                },
                |token| {
                    let mut kept = KVec::new();
                    kept.extend_from_slice(token, GFP_KERNEL)?;
                    Ok(Arc::new(kept, GFP_KERNEL)?)
                },
            )
        })
    }

    /// Dials one more connection into the session with `token`, within the
    /// bound the session core gives a join. A signal to the calling task
    /// ends the join as well.
    pub fn join(self: &Arc<Self>, token: &Token) -> Outcome<()> {
        let (owner, token) = (self.clone(), token.clone());
        Attempt::new()
            .map_err(Dial::Transport)?
            .run(Some(JOIN_ATTEMPT_BOUND), move || {
                dial(&owner.network, &owner.server, Hello::Join(&token), |_| {
                    Ok(())
                })
            })
    }
}

/// Dials `server`, sends `hello`, and saves what `keep` makes of the session
/// token of the reply. A socket is created in the network namespace
/// `network`.
///
/// Runs on the worker thread of an attempt, which the waiting task can
/// interrupt. A bound covers the whole attempt, never an individual transfer.
fn dial<Kept>(
    network: &Network,
    server: &Server,
    hello: Hello<'_>,
    keep: impl FnOnce(&[u8]) -> Result<Kept>,
) -> Outcome<Kept> {
    match server {
        Server::Socket(endpoint) => dial_stream(network, endpoint, hello, keep),
        Server::Device(tag) => dial_device(tag, hello, keep),
    }
}

/// Dials `endpoint` from the network namespace `network` and sends `hello` on
/// the stream.
fn dial_stream<Kept>(
    network: &Network,
    endpoint: &Endpoint,
    hello: Hello<'_>,
    keep: impl FnOnce(&[u8]) -> Result<Kept>,
) -> Outcome<Kept> {
    let socket = Unconnected::open(network, endpoint).map_err(|error| {
        if error == crate::errno::eafnosupport() {
            Dial::FamilyUnavailable
        } else {
            Dial::Connect(error)
        }
    })?;
    let stream = socket.connect().map_err(Dial::Connect)?;
    stream
        .send_interruptibly(&hello.frame()?)
        .map_err(Dial::Transport)?;
    let (negotiated, token) = accept(&stream, keep)?;
    Ok(Dialed {
        link: Link::Stream(stream),
        negotiated,
        token,
    })
}

/// Opens a channel on the device with `tag` and sends `hello` on it, in a
/// chain whose reply area is sized for the reply.
fn dial_device<Kept>(
    tag: &Tag,
    hello: Hello<'_>,
    keep: impl FnOnce(&[u8]) -> Result<Kept>,
) -> Outcome<Kept> {
    let device = Device::find(tag).ok_or(Dial::NoDevice)?;
    // Before the device has returned the reset chain, a hello could arrive
    // on a channel that an earlier driver left open.
    device.wait_reset().map_err(Dial::Transport)?;
    let channel = device.open().map_err(Dial::Transport)?;
    let chain = channel
        .frame(&hello.frame()?, hello.reply_len())
        .map_err(Dial::Transport)?;
    channel
        .room(chain.descriptors(), Wait::Interruptible)
        .and_then(|room| room.make_available(chain))
        .map_err(Dial::Transport)?;
    // A chain that the device returns with nothing written shows that the
    // channel did not open.
    let returned = channel
        .next(Wait::Interruptible)
        .map_err(Dial::Transport)?
        .ok_or(Dial::Transport(crate::errno::econnreset()))?;
    let reply = returned.reply();
    let (negotiated, token) = accept(&reply, keep)?;
    // The chain contains the reply and nothing after it.
    let extra = returned.written() - reply.consumed();
    if extra != 0 {
        let fault = FramingError::TrailingBytes { extra };
        return Err(Dial::Handshake(HandshakeError::Malformed { fault }));
    }
    Ok(Dialed {
        link: Link::Channel(channel),
        negotiated,
        token,
    })
}

/// Reads the reply to a hello from `source` and opens the session on it: what
/// the session negotiated, and what `keep` makes of its token.
///
/// The reply is read header first, then into memory the kernel gives for the
/// rest the parser asks for, so no constant sizes either.
fn accept<Kept>(
    source: &impl Source,
    keep: impl FnOnce(&[u8]) -> Result<Kept>,
) -> core::result::Result<(Negotiated, Kept), Dial> {
    let mut header = [0u8; FRAME_HEADER_LEN];
    if !read_header(source, &mut header).map_err(read_failure)? {
        return Err(Dial::Transport(crate::errno::econnreset()));
    }
    let mut reply = KVVec::new();
    reply
        .extend_from_slice(&header, GFP_KERNEL)
        .map_err(|_| Dial::Transport(ENOMEM))?;
    let mut have = FRAME_HEADER_LEN;
    let len = loop {
        match read_rest(source, &mut reply, have).map_err(read_failure)? {
            ReadFrame::Whole(len, _) => break len,
            ReadFrame::HeaderClosed => return Err(Dial::Transport(crate::errno::econnreset())),
            ReadFrame::BufferTooSmall {
                declared,
                have: read,
            } => {
                reply
                    .resize(declared, 0, GFP_KERNEL)
                    .map_err(|_| Dial::Transport(ENOMEM))?;
                have = read;
            }
        }
    };
    // Every judgement about the reply is the session core's, including the
    // version and the flag bits it answers with.
    let accepted = match handshake::session(&reply[..len], &LIMITS) {
        Ok(accepted) => accepted,
        Err(HandshakeError::Refused { status }) => {
            return Err(Dial::Refused(Error::from_errno(status)))
        }
        Err(error) => return Err(Dial::Handshake(error)),
    };
    let token = keep(accepted.token).map_err(Dial::Transport)?;
    Ok((accepted.negotiated, token))
}

/// What a failed read of the handshake reply is, as a dial outcome.
fn read_failure(error: ReadError) -> Dial {
    match error {
        ReadError::Transport(error) => Dial::Transport(error),
        ReadError::Framing(fault) => Dial::Handshake(HandshakeError::Malformed { fault }),
    }
}
