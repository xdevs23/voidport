//! A mount is torn down in this order: unmount, close the connection, end the
//! kernel connection, join the FUSE session.
//!
//! 1. The kernel unmount takes the mountpoint away, so nothing in this mount
//!    namespace can send a callback any more. Every read and write is then
//!    blocked, and once the pages are shown gone the server is told that the
//!    guest caches no page of the session, so that it gives every lease of the
//!    session up at once (`Mount::give_up_leases`).
//! 2. Closing the connection fails every outstanding wire request, including a
//!    blocking `setlk` parked on the server, which nothing else would wake. The
//!    callbacks that the adapter still owns answer `EIO` instead of waiting
//!    forever.
//! 3. Ending the kernel connection lets the session loop finish where the
//!    unmount alone does not (`KernelConnection`). A session loop whose kernel
//!    connection could not be ended is stopped (`Mount::end_session`), and the
//!    guardian of the mount ends once the pages are shown gone and the kernel
//!    connection has ended (`Mount::stop_serving`).
//! 4. Joining completes, and only afterwards is the runtime that the callbacks
//!    reply from released, so that the join cannot wait on cancelled tasks.
//!
//! A signal can arrive between a dispatch loop taking a request and the reply
//! going back. Unmounting then returns `EIO` for work that may have completed,
//! and the caller waiting for the reply counts against the mountpoint, so the
//! unmount fails with `EBUSY`. The signalled teardown therefore waits for that
//! work first (`Mount::unmount_when_settled`).
//!
//! A mount that is reconnecting or degraded cancels its recovery before any of
//! the four steps, so that nothing dials a server or sleeps out a backoff while
//! the mountpoint comes down. The signalled teardown ends the recovery for good
//! ([`Client::stop_reconnecting`]). [`Mount::unmount`] only pauses it
//! ([`Client::pause_recovery`]), because the kernel may still fail the unmount
//! with `EBUSY`, and the mount that is still live then resumes it
//! ([`Client::resume_recovery`]).
//!
//! The FUSE layer never unmounts, so the end of the session unmounts nothing.
//! After a `SIGKILL`, only the `auto_unmount` option of the `fusermount3`
//! helper removes the mountpoint ([`MountOptions::auto_unmount`]).

mod connection;

use std::io;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use rustix::io::Errno;
use rustix::mount::UnmountFlags;
use voidport_fuse::{Fusermount, Session, StartError};

pub use self::connection::{AbortError, AbortHandle};
use self::connection::{KernelConnection, report_unended};
use crate::client::{Caller, Client, ConnectError, DEFAULT_RECONNECT_STALL, Resilience};
use crate::fuse::pages::{Lapse, PageCache, answer_recalls, relinquish, renew_window};
use crate::fuse::{InFlight, VoidportFs};
use crate::guardian::{
    Guardian, GuardianError, Launch, Serving, SessionError, Unserved, Unstarted,
};
use crate::subscribe::Subscription;
use crate::url::MountUrl;

pub const DEFAULT_TIMEOUT: Duration = voidport_session::options::DEFAULT_CACHE_LIFETIME;

pub const FSNAME: &str = "voidport";

pub const DEFAULT_DISPATCH_THREADS: NonZeroUsize = NonZeroUsize::new(1).expect("1 is not zero");

/// A server that never answers may not keep this process alive, so the teardown
/// waits this long for the callbacks the kernel is owed and then goes on with
/// one unmount attempt.
const SETTLE_PATIENCE: Duration = Duration::from_secs(2);

/// The count of what is outstanding falls when a reply is sent, and the guest
/// side unwinds a moment later. Until the caller has left the syscall, its
/// reference against the mountpoint is still there and the unmount is still
/// refused.
const SETTLE_TAIL: Duration = Duration::from_millis(100);

const SETTLE_STEP: Duration = Duration::from_millis(5);

const SETTLE_POLL: Duration = Duration::from_micros(500);

/// A kernel that never finishes the session may not keep the process alive.
const JOIN_PATIENCE: Duration = Duration::from_secs(30);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MountOptions {
    pub attr_timeout: Duration,
    pub entry_timeout: Duration,
    pub allow_other: bool,
    pub read_only: bool,
    pub dispatch_threads: NonZeroUsize,
    pub reconnect_stall: Duration,
    pub auto_unmount: bool,
    /// Off, every attribute this mount presents has the bits masked and a chmod
    /// that would set one fails. A chmod through such a mount sends the bits
    /// stored on the server back unchanged, so mounts that show them are
    /// unaffected.
    pub privileged_bits: bool,
}

impl Default for MountOptions {
    fn default() -> Self {
        Self {
            attr_timeout: DEFAULT_TIMEOUT,
            entry_timeout: DEFAULT_TIMEOUT,
            allow_other: false,
            read_only: false,
            dispatch_threads: DEFAULT_DISPATCH_THREADS,
            reconnect_stall: DEFAULT_RECONNECT_STALL,
            auto_unmount: true,
            privileged_bits: true,
        }
    }
}

impl MountOptions {
    #[must_use]
    fn fuse_options(&self, auto_unmount: Option<Fusermount>) -> voidport_fuse::MountOptions {
        voidport_fuse::MountOptions {
            source: voidport_fuse::MountSource::new(FSNAME).expect("the name is a plain word"),
            default_permissions: true,
            allow_other: self.allow_other,
            read_only: self.read_only,
            auto_unmount,
        }
    }

    /// The helper found here is the one that mounts.
    fn auto_unmount_helper(&self) -> Option<Fusermount> {
        (self.auto_unmount && self.allow_other)
            .then(voidport_fuse::fusermount)
            .flatten()
    }

    #[must_use]
    pub fn auto_unmounts(&self) -> bool {
        self.auto_unmount_helper().is_some()
    }

    fn resilience(&self) -> Resilience {
        Resilience {
            stall: self.reconnect_stall,
        }
    }
}

#[derive(Debug)]
pub struct Mount {
    mountpoint: PathBuf,
    client: Arc<Client>,
    pages: Arc<PageCache>,
    /// Released when the mount is dropped, after the client is closed.
    held: Option<Lapse>,
    inflight: Arc<InFlight>,
    connection: KernelConnection,
    unmounts_itself: bool,
    guardian: Option<Guardian>,
    session: Option<Serving>,
    runtime: Option<tokio::runtime::Runtime>,
}

impl Mount {
    pub fn new(
        url: &MountUrl,
        mountpoint: &Path,
        options: &MountOptions,
        guardian: &Launch,
    ) -> Result<Self, MountError> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .thread_name("voidport-client")
            .build()
            .map_err(MountError::Runtime)?;
        let client = runtime.block_on(Client::mount_with(
            &url.endpoint,
            url.namespace.as_str(),
            &url.subpath,
            options.resilience(),
        ))?;

        // The server lets a session without a subscription cache no pages, and
        // recalls them on the subscription.
        let (recalls, recalled) = tokio::sync::mpsc::unbounded_channel();
        let shares = runtime
            .block_on(Subscription::open_recalling(Arc::clone(&client), recalls))
            .inspect_err(|errno| {
                tracing::warn!(%errno, "the mount could not subscribe, so it caches no pages of the files it reads");
            })
            .ok();

        let inflight = Arc::<InFlight>::default();
        let feed = Unstarted::new().map_err(MountError::Guardian)?;
        let filesystem = VoidportFs::new(
            Arc::clone(&client),
            runtime.handle().clone(),
            options.attr_timeout,
            options.entry_timeout,
            crate::fuse::attr::Privileged::of(!options.privileged_bits),
            Arc::clone(&inflight),
            Arc::clone(&feed.feed),
        );
        let pages = filesystem.pages();
        if shares.is_some() {
            // The server leases a file only within the window the mount renews,
            // so the first renewal is answered before the mount serves.
            let (renewed, first) = tokio::sync::oneshot::channel();
            runtime.spawn(renew_window(
                Arc::clone(&pages),
                Arc::clone(&client),
                renewed,
            ));
            if runtime.block_on(first).is_err() {
                tracing::warn!(
                    "the first renewal of the window ended without an answer, so the mount serves before the server leased it a window"
                );
            }
        }
        let auto_unmount = options.auto_unmount_helper();
        let unmounts_itself = auto_unmount.is_some();
        let started = Session::mount(mountpoint, &options.fuse_options(auto_unmount), |init| {
            filesystem.negotiate(init)
        });
        let session = started.map_err(|source| MountError::Mount {
            mountpoint: mountpoint.display().to_string(),
            source,
        })?;
        pages.attach(session.notifier());
        let connection = KernelConnection::of(mountpoint);
        let lost = relinquish(Arc::clone(&pages), Arc::clone(&client));
        let started = Guardian::start(
            guardian,
            session,
            options.dispatch_threads,
            feed,
            runtime.handle(),
            lost,
        );
        let (guardian, session) = match started {
            Ok(started) => started,
            Err(unserved) => {
                // The session has ended while the page cache still has a
                // descriptor of it, so no request to the mount is answered.
                // Ending the connection fails every request, so that no caller
                // waiting on the mount keeps it busy for the unmount.
                report_unended(connection.abort());
                if !unmounts_itself {
                    discard(mountpoint);
                }
                return Err(match unserved {
                    Unserved::Session(source) => MountError::Serve(source),
                    Unserved::Guardian(source) => MountError::Guardian(source),
                });
            }
        };

        if let Some(mut shares) = shares {
            runtime.spawn(async move { while shares.next().await.is_some() {} });
            runtime.spawn(answer_recalls(
                Arc::clone(&pages),
                Arc::clone(&client),
                recalled,
            ));
        }

        if options.auto_unmount {
            if unmounts_itself {
                tracing::info!("the mount will be released by the kernel if this client dies");
            } else {
                tracing::info!(
                    "auto-unmount is unavailable here (it needs the fusermount helper and \
                     --allow-other); a killed client leaves a dead mountpoint that \
                     `voidport umount` recovers"
                );
            }
        }
        tracing::info!(
            mountpoint = %mountpoint.display(),
            url = %url,
            "voidport mounted"
        );
        Ok(Self {
            mountpoint: mountpoint.to_path_buf(),
            client,
            pages,
            held: None,
            inflight,
            connection,
            unmounts_itself,
            guardian: Some(guardian),
            session: Some(session),
            runtime: Some(runtime),
        })
    }

    #[must_use]
    pub fn mountpoint(&self) -> &Path {
        &self.mountpoint
    }

    #[must_use]
    pub fn abort_handle(&self) -> AbortHandle {
        self.connection.abort_handle()
    }

    #[must_use]
    pub fn guardian_id(&self) -> Option<u32> {
        self.guardian.as_ref().map(Guardian::id)
    }

    #[must_use]
    pub fn client(&self) -> Arc<Client> {
        Arc::clone(&self.client)
    }

    /// A signal that arrives before [`Self::serve_until_signalled`] runs waits in
    /// the returned [`Signals`] and ends the mount as soon as that function runs.
    /// Dropping the [`Signals`] ends the wait for them.
    ///
    /// # Errors
    ///
    /// [`SignalError::Ended`] for a mount that has ended, and the error of the
    /// runtime when it cannot install the signal handlers.
    pub fn catch_signals(&self) -> Result<Signals, SignalError> {
        use tokio::signal::unix::{SignalKind, signal};

        let runtime = self.runtime.as_ref().ok_or(SignalError::Ended)?;
        let _guard = runtime.enter();
        let mut interrupt = signal(SignalKind::interrupt()).map_err(SignalError::Handler)?;
        let mut terminate = signal(SignalKind::terminate()).map_err(SignalError::Handler)?;
        let (ended, endings) = channel();
        let (cancel, cancelled) = tokio::sync::oneshot::channel();
        let raised = ended.clone();
        // The handlers live on the runtime of the mount, the only reactor this
        // process has. The teardown they trigger runs on the thread that calls
        // `serve_until_signalled`.
        runtime.spawn(async move {
            let signal = tokio::select! {
                _ = cancelled => return,
                _ = interrupt.recv() => "SIGINT",
                _ = terminate.recv() => "SIGTERM",
            };
            // Nothing receives this once the mount has ended.
            let _mount_ended = raised.send(Ending::Signal(signal));
        });
        Ok(Signals {
            ended,
            endings,
            cancel,
        })
    }

    /// `SIGINT` and `SIGTERM` run the same teardown as a clean unmount, so that a
    /// Ctrl-C leaves no mountpoint behind. They are caught by
    /// [`Self::catch_signals`], which has to run first.
    ///
    /// A busy mountpoint still fails to unmount. The process then exits anyway,
    /// reporting the `EBUSY` of the kernel, and `voidport umount` recovers the
    /// mountpoint once it is idle.
    ///
    /// A session that ended with an error leaves the mount in place, and its
    /// guardian answers the requests to it. The connection is ended then, and
    /// the mountpoint unmounted, or left to the helper of an auto-unmount.
    ///
    /// # Errors
    ///
    /// Whatever ended the FUSE session, or the refusal of the kernel to unmount.
    pub fn serve_until_signalled(mut self, signals: Signals) -> Result<(), TeardownError> {
        let Some(session) = self.session.take() else {
            return Ok(());
        };
        let Signals {
            ended,
            endings,
            cancel,
        } = signals;
        // The join runs off this thread so a signal can be noticed while it is
        // still waiting.
        let joining = std::thread::Builder::new()
            .name("voidport-session".to_owned())
            .spawn(move || {
                // Nothing receives this once a signalled teardown gave up on
                // the session.
                let _teardown_over = ended.send(Ending::Session(session.join()));
            })
            .map_err(TeardownError::Join)?;

        let ending = endings.recv().unwrap_or(Ending::Session(Ok(())));
        drop(cancel);
        match ending {
            // The session ended under us. Without an error, somebody unmounted
            // the mountpoint and the kernel side is over. With one, the mount is
            // still there, so its connection is ended and the mountpoint
            // unmounted here, or by the helper of an auto-unmount once the mount
            // is dropped. Nothing shows that the pages are gone, so the guardian
            // gets no end, and drops them, since the dispatch threads have
            // ended.
            Ending::Session(served) => {
                join(joining);
                if served.is_err() {
                    report_unended(self.connection.abort());
                    if !self.unmounts_itself {
                        discard(&self.mountpoint);
                    }
                }
                drop(self.guardian.take());
                self.client.close();
                self.runtime.take();
                served.map_err(TeardownError::Session)
            }
            Ending::Signal(signal) => {
                tracing::info!(signal, "unmounting on signal");
                self.teardown_on_signal(&endings, joining)
            }
        }
    }

    fn teardown_on_signal(
        &mut self,
        endings: &Receiver<Ending>,
        joining: JoinHandle<()>,
    ) -> Result<(), TeardownError> {
        // A callback parked in a stall window would never settle, so the
        // recovery is cancelled before the wait below, and a stalled callback is
        // owed its answer now.
        self.client.stop_reconnecting();
        if let Err(error) = self.unmount_when_settled() {
            self.client.close();
            tracing::error!(
                mountpoint = %self.mountpoint.display(),
                %error,
                "the mountpoint could not be unmounted; `voidport umount` recovers it once it is idle"
            );
            // The session loop still serves a mountpoint that is still there, so
            // there is nothing to join. The tasks of the runtime and the thread
            // that waits for the session end with the process.
            if let Some(runtime) = self.runtime.take() {
                runtime.shutdown_background();
            }
            return Err(TeardownError::Unmount(error));
        }
        report_unended(self.stop_serving());
        let joined = match endings.recv_timeout(JOIN_PATIENCE) {
            Ok(Ending::Session(served)) => {
                join(joining);
                served.map_err(TeardownError::Session)
            }
            Ok(Ending::Signal(_)) | Err(_) => Ok(()),
        };
        self.runtime.take();
        joined
    }

    /// Both halves of what the kernel is owed are waited for: the callbacks
    /// that the adapter holds ([`InFlight`]) and what the kernel has queued
    /// behind them ([`KernelConnection`]). The unmount is retried while either is
    /// settling, because the caller a reply has just reached takes a moment to
    /// leave the mount behind it.
    ///
    /// [`SETTLE_PATIENCE`] bounds the wait for outstanding work, so that a server
    /// that never answers cannot keep this process alive. [`SETTLE_TAIL`] bounds
    /// the retry once nothing is outstanding.
    fn unmount_when_settled(&self) -> io::Result<()> {
        let started = Instant::now();
        let (deadline, tail) = (started + SETTLE_PATIENCE, started + SETTLE_TAIL);
        loop {
            self.inflight.settle(deadline);
            self.connection.settle(deadline);
            let unmounted = unmount(&self.mountpoint);
            let busy = matches!(
                &unmounted,
                Err(error) if error.raw_os_error() == Some(Errno::BUSY.raw_os_error())
            );
            let owes = !self.inflight.is_settled() || self.connection.is_waiting();
            let now = Instant::now();
            if !busy || now >= deadline || (!owes && now >= tail) {
                return unmounted;
            }
            std::thread::sleep(SETTLE_STEP);
        }
    }

    /// Every read and write is blocked first, until the mount is dropped, and
    /// every request in flight is cancelled, so that a request waiting in the
    /// server ends and the pages it has locked unlock. The server is told only
    /// once the pages are shown gone: the kernel destroyed the connection, which
    /// it does with the superblock and every page of it once the last mount of
    /// the connection is gone, or else every page was dropped. A drop the kernel
    /// rejects for another reason, such as on a connection another process
    /// aborted, does not show that, and neither does a kernel without `fusectl`,
    /// where a destroyed connection cannot be told from a live one. The leases
    /// then remain until the window has passed. Without the runtime this returns
    /// `false`.
    fn give_up_leases(&mut self) -> bool {
        let (held, nodes) = self.pages.hold();
        self.held = Some(held);
        self.inflight.interrupt_all();
        let destroyed = self.connection.destroyed();
        let (pages, client) = (&self.pages, &self.client);
        let Some(runtime) = &self.runtime else {
            return false;
        };
        runtime.block_on(async {
            let gone = pages.shown_gone(nodes, destroyed).await;
            if gone && let Err(errno) = client.relinquish(Caller::default()).await {
                tracing::warn!(%errno, "the server was not told that the mount caches no page, so the leases of the session remain until the window has passed");
            }
            gone
        })
    }

    pub fn unmount(&mut self) -> Result<(), TeardownError> {
        let Some(session) = self.session.take() else {
            return Ok(());
        };
        self.client.pause_recovery();
        if let Err(error) = unmount(&self.mountpoint) {
            // The mount is still live, so the recovery it was in the middle of
            // is handed back, not lost.
            self.client.resume_recovery();
            self.session = Some(session);
            return Err(TeardownError::Unmount(error));
        }
        // Ending the session waits for the replies of `stop_serving` to arrive at
        // the kernel, so the runtime that the replying tasks run on is released
        // last.
        let ended = self.end_session(session);
        self.runtime.take();
        ended.map_err(TeardownError::Session)
    }

    /// The session loop ends by itself once the abort of the kernel connection
    /// has ended the connection. Where the connection could not be aborted, the
    /// session loop is stopped instead, so that it does not wait for a copy of
    /// the mount in another mount namespace, and the kernel ends the connection
    /// once the guardian and this process have closed every descriptor of it.
    fn end_session(&mut self, session: Serving) -> Result<(), SessionError> {
        match self.stop_serving() {
            Ok(()) => session.join(),
            unended => {
                report_unended(unended);
                session.stop()
            }
        }
    }

    /// The leases are given up over the connection before it closes. The
    /// guardian replies, once this process exits, to the requests that the
    /// session loop read and left without a reply. It ends only once the pages
    /// are shown gone, and the abort ended the connection or the connection has
    /// no abort file. Without one, the kernel unmount ended the connection, or
    /// [`Self::end_session`] stops the session loop, whose callbacks reply to
    /// every request it read, and closes the descriptors of the connection in
    /// this process. Otherwise the guardian is dropped without an end, and drops
    /// the pages once the client can no longer reply.
    ///
    /// # Errors
    ///
    /// The [`AbortError`] of a kernel connection that could not be ended.
    fn stop_serving(&mut self) -> Result<(), AbortError> {
        let gone = self.give_up_leases();
        let guardian = self.guardian.take();
        self.client.close();
        let aborted = self.connection.abort();
        if gone
            && !matches!(aborted, Err(AbortError::Write(_)))
            && let Some(guardian) = guardian
        {
            guardian.end();
        }
        aborted
    }
}

fn join(joining: JoinHandle<()>) {
    if joining.join().is_err() {
        tracing::error!("the thread that waited for the session panicked");
    }
}

fn discard(mountpoint: &Path) {
    match unmount(mountpoint) {
        Ok(()) => {}
        Err(error) if error.raw_os_error() == Some(Errno::INVAL.raw_os_error()) => {}
        Err(error) => tracing::warn!(
            mountpoint = %mountpoint.display(),
            %error,
            "the mountpoint of a failed start could not be unmounted"
        ),
    }
}

#[derive(Debug)]
pub struct Signals {
    ended: Sender<Ending>,
    endings: Receiver<Ending>,
    cancel: tokio::sync::oneshot::Sender<()>,
}

#[derive(Debug)]
enum Ending {
    Session(Result<(), SessionError>),
    Signal(&'static str),
}

impl Drop for Mount {
    /// Nothing handles requests for the mount once this value is gone, so a
    /// mount whose kernel unmount fails is ended all the same: recovery stops
    /// for good, its pages are dropped, and the kernel connection ends, so every
    /// request to it fails. A thread of this process that waited for a reply
    /// instead would leave the descriptors of the connection open in this
    /// process, so the connection would never end, and neither would the thread
    /// or the process.
    ///
    /// The connection is aborted through its abort file in `fusectl`, because
    /// that ends it at once, whichever descriptors of it are open. Where that
    /// fails, the session loop is stopped instead, and the kernel aborts the
    /// connection once its last descriptor is closed (`fuse_dev_release`,
    /// `fs/fuse/dev.c`). The guardian closes its copy when it exits, and this
    /// process closes the others when the fields of the mount are dropped after
    /// this function.
    fn drop(&mut self) {
        if let Err(error) = self.unmount() {
            tracing::error!(
                mountpoint = %self.mountpoint.display(),
                %error,
                "the mount could not be unmounted and is still in place"
            );
        }
        let Some(session) = self.session.take() else {
            return;
        };
        self.client.stop_reconnecting();
        if let Err(error) = self.end_session(session) {
            tracing::error!(
                mountpoint = %self.mountpoint.display(),
                %error,
                "the session of a mount left in place ended with an error"
            );
        }
    }
}

/// A busy mountpoint surfaces the `EBUSY` of the kernel instead of being
/// detached behind the back of the guest.
pub fn unmount(mountpoint: &Path) -> io::Result<()> {
    rustix::mount::unmount(mountpoint, UnmountFlags::empty()).map_err(io::Error::from)
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MountError {
    #[error("the client runtime could not be started")]
    Runtime(#[source] io::Error),
    #[error(transparent)]
    Connect(#[from] ConnectError),
    #[error(
        "the guardian of the mount could not be started; check that the program \
         that runs it can be started from here and runs the guardian, and that the \
         kernel has pidfds (Linux 5.3 or later)"
    )]
    Guardian(#[source] GuardianError),
    #[error("cannot mount on {mountpoint}")]
    Mount {
        mountpoint: String,
        #[source]
        source: StartError,
    },
    /// The connection was ended, and the mountpoint unmounted again, by the
    /// helper of an auto-unmount where the mount has one.
    #[error("the FUSE session could not be started")]
    Serve(#[source] SessionError),
}

#[derive(Debug, thiserror::Error)]
pub enum TeardownError {
    #[error("the mountpoint could not be unmounted")]
    Unmount(#[source] io::Error),
    #[error("the thread that waits for the session could not be started")]
    Join(#[source] io::Error),
    #[error("the session of the mount ended with an error")]
    Session(#[source] SessionError),
}

#[derive(Debug, thiserror::Error)]
pub enum SignalError {
    #[error("the mount has ended")]
    Ended,
    #[error("the signal handlers could not be installed")]
    Handler(#[source] io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_only_and_allow_other_are_passed_to_the_kernel() {
        let mounted = MountOptions {
            read_only: true,
            allow_other: true,
            ..MountOptions::default()
        }
        .fuse_options(None);
        assert!(mounted.read_only);
        assert!(mounted.allow_other);
    }

    /// Asking for it anywhere other than on a mount with `--allow-other` and the
    /// helper would turn a convenience into a mount failure.
    #[test]
    fn auto_unmount_is_only_asked_for_where_the_platform_takes_it() {
        let user_only = MountOptions::default();
        assert!(!user_only.auto_unmounts());

        let opted_out = MountOptions {
            allow_other: true,
            auto_unmount: false,
            ..MountOptions::default()
        };
        assert!(!opted_out.auto_unmounts(), "--no-auto-unmount opts out");

        let widened = MountOptions {
            allow_other: true,
            ..MountOptions::default()
        };
        let helper = voidport_fuse::fusermount();
        assert_eq!(widened.auto_unmount_helper(), helper);
    }

    #[test]
    fn the_stall_window_is_passed_to_the_client() {
        assert_eq!(
            MountOptions::default().resilience().stall,
            DEFAULT_RECONNECT_STALL
        );
        assert_eq!(
            MountOptions {
                reconnect_stall: Duration::ZERO,
                ..MountOptions::default()
            }
            .resilience()
            .stall,
            Duration::ZERO,
            "zero is the fail-fast the contract keeps"
        );
    }
}
