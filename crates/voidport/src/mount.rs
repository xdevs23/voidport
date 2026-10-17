//! Mounting and unmounting.
//!
//! A mount owns three things that must be torn down in one particular order:
//! the kernel mount, the data connection, and the runtime the callbacks reply
//! from. The required order is **unmount, then close the connection, then join the
//! FUSE session**:
//!
//! 1. the kernel unmount stops new callbacks arriving and lets the session loop
//!    finish;
//! 2. closing the connection fails every outstanding wire request — including a
//!    blocking `setlk` parked on the server, which nothing else would ever wake
//!    — so the callbacks the adapter still owns answer `EIO` instead of waiting
//!    forever;
//! 3. joining then completes, and the runtime — which is what those callbacks
//!    reply from — is released only afterwards, so the join cannot be waiting
//!    on tasks that have already been cancelled.
//!
//! A busy mountpoint fails at step 1 with the kernel's own `EBUSY` and nothing
//! is torn down: the mount is still live and still usable. There is no lazy or
//! forced unmount in v1.
//!
//! The **signalled** teardown has one step in front of those three: it answers
//! what the kernel is already owed. A callback replies from the runtime, so a
//! signal can land between a dispatch loop taking a request and the reply for
//! it going back, and unmounting there costs twice — the guest is told `EIO`
//! for work that may have completed, and the caller waiting for that answer is
//! a reference the kernel counts against the mountpoint, so the unmount is
//! refused `EBUSY` and the mountpoint is left behind. So the teardown waits for
//! that work to settle and keeps trying the unmount while it does, for at most
//! [`SETTLE_PATIENCE`], and for [`SETTLE_TAIL`] beyond it while the callers of
//! the answers it has just given unwind out of the mount. Past those it
//! proceeds exactly as it did before: one refusal, reported, and the process
//! leaves.
//!
//! "What the kernel is owed" is two counts, not one. [`InFlight`] is the
//! callbacks this mount's adapter has been handed and not yet answered, which
//! is the part it can see; [`KernelQueue`] is what the kernel says it is still
//! waiting for, which is the part it cannot — a request queued for a dispatch
//! loop that has not picked it up yet belongs to no callback at all, and the
//! measured window between the two is a fraction of a millisecond wide and is
//! exactly where the flake lived.
//!
//! A mount that is **reconnecting** or **degraded** cancels its recovery before
//! any of the three, which is what the resilience contract requires: nothing may
//! be dialling a server or sleeping out a backoff while its mountpoint comes
//! down. The two teardowns differ only in what they do afterwards. The
//! **signalled** one ends the mount outright
//! ([`Client::stop_reconnecting`]) — the process is leaving whatever the
//! mountpoint says, and every stalled callback is owed its `EIO` now. The
//! ordinary [`Mount::unmount`] only pauses the recovery
//! ([`Client::pause_recovery`]), because the kernel may still refuse the
//! mountpoint: an `EBUSY` leaves a mount that is live, usable, and handed back
//! its probe ([`Client::resume_recovery`]) exactly as it was found.
//!
//! ## fuser unmounts a second time, and it cannot be talked out of it
//!
//! The kernel unmount above is this client's own ([`unmount`]), because v1's is
//! a plain unmount: `EBUSY` surfaces and there is no lazy or forced mode. fuser
//! 0.18 holds a mount handle of its own inside the session and unmounts from it
//! once more when that handle drops as the session ends. The handle is private
//! to the session and the only way to release it is to unmount *through* it,
//! which takes fuser's path — and that path answers a kernel `EPERM` by
//! detaching lazily and reporting success, which is exactly what the contract
//! forbids. So the second unmount stays; it lands on a mountpoint that is
//! already gone, whoever took it down, and fails there. Keeping that failure
//! out of a process's diagnostics is the binary's business, and it is done only
//! while the mountpoint is provably gone.
//!
//! ## Auto-unmount is opportunistic, not guaranteed
//!
//! A `SIGKILL` is the one exit the client cannot run a teardown for, and FUSE's
//! answer to it is the `auto_unmount` mount option — which fuser 0.18 accepts
//! **only** through the `fusermount3` helper and **only** when the session ACL
//! is wider than owner-only. So the honest split the design rules: signal
//! teardown is the primary mechanism, and auto-unmount is set where the
//! platform allows it and logged where it does not (see
//! [`MountOptions::auto_unmount`]). Where it is unavailable, a `SIGKILL` leaves
//! a dead endpoint that `voidport umount` recovers.
//!
//! ## Parallel dispatch
//!
//! [`MountOptions::dispatch_threads`] sets how many FUSE event loops the
//! session runs; above one, each gets its own `/dev/fuse` descriptor
//! (`clone_fd`) and they take requests from the connection's shared queue in
//! parallel. The default is one, and it is one *because it measures best* —
//! see [`DEFAULT_DISPATCH_THREADS`] — not because parallel dispatch is
//! unsupported.
//!
//! Running several is sound because `fuser::Filesystem` is declared `Send + Sync +
//! 'static` and fuser shares one `Arc` of the filesystem across the loops. The
//! two `&mut self` callbacks are outside the parallel window by construction:
//! `init` runs during `Session::new`'s handshake, before any loop is spawned,
//! and `destroy` runs after every loop has been joined. Every other callback
//! takes `&self`, and [`VoidportFs`](crate::fuse::VoidportFs) holds no state a
//! callback mutates in place: an `Arc<Client>`, a runtime handle, two durations
//! and the caching mode `init` settled — the one field `init` writes, and it is
//! only ever read once the loops exist. Each callback clones the handle and
//! spawns; the shared state that does mutate — the [`Client`]'s, the open
//! directories, the readahead pool and the count of callbacks the kernel is
//! owed a reply for — is each behind its own lock, and all of it was already
//! reached concurrently by the runtime's tasks under a single loop.

use std::io;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::mpsc::{Sender, channel};
use std::time::{Duration, Instant};

use fuser::{BackgroundSession, Config, MountOption, Session, SessionACL};
use rustix::io::Errno;
use rustix::mount::UnmountFlags;

use crate::client::{
    Client, ConnectError, DEFAULT_POOL_BYTES, DEFAULT_RECONNECT_STALL, Readahead, Resilience,
};
use crate::fuse::{InFlight, VoidportFs};
use crate::url::MountUrl;

/// The default entry and attribute cache lifetime.
///
/// v1 caching is deliberately conservative: writethrough, short timeouts, and
/// staleness across mounts bounded by this number.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(1);

/// The `fsname` every voidport mount reports.
pub const FSNAME: &str = "voidport";

/// How many FUSE event loops a mount runs by default.
///
/// **One, by measurement.** The sweep in `docs/PERFORMANCE.md` (2026-08-13)
/// ran 1, 4, 8 and 16 loops over the concurrent scenarios and over 8, 16 and
/// 32 client processes on one mount, on a 32-vCPU guest: every extra loop was
/// neutral to 12% *worse* on throughput and worse on the tail. A mount's
/// ceiling is not the loop — the same probe over four mounts reached 1.6× the
/// aggregate of one mount with one loop each — so extra loops only add
/// cross-loop wakeups to a queue that was never the constraint.
///
/// The knob exists because that ceiling is a property of this client's
/// per-connection path, not of FUSE: a future client that lifts it, or a
/// deployment whose per-operation cost is far lower than voidport's 75–95 µs,
/// can reach the point where a single loop binds. Nothing here assumes one.
pub const DEFAULT_DISPATCH_THREADS: NonZeroUsize = NonZeroUsize::new(1).expect("1 is not zero");

/// How long a signalled teardown gives the callbacks the kernel is owed.
///
/// The teardown answers what it owes before it takes the mountpoint down, and
/// retries the unmount while it is doing so, because the guest side of an
/// answer takes a moment to unwind after the answer reaches it. The bound is
/// what keeps that from becoming a wait without an end: a server that never
/// answers may not keep this process alive, so past the bound the teardown goes
/// on exactly as it did before it — one unmount attempt, and the kernel's own
/// refusal reported if it refuses.
///
/// **Two seconds.** What is being waited for is the rest of one wire round
/// trip, which is tens of microseconds on an idle machine and single-figure
/// milliseconds on a loaded one; two seconds is three orders of magnitude of
/// room and still an order of magnitude inside the exit the contract promises.
const SETTLE_PATIENCE: Duration = Duration::from_secs(2);

/// How long a refused unmount keeps being retried after the mount owes
/// nothing.
///
/// The count of what is outstanding falls the moment a reply is *sent*, and the
/// guest side of it unwinds a moment later: until the caller has left the
/// syscall it was in, its reference against the mountpoint is still there and
/// the unmount is still refused, and that has been measured happening in the
/// microseconds between one read of the count and the next. So the last word on
/// an `EBUSY` is only taken after this long — a tenth of a second, which is
/// four orders of magnitude more than the unwinding needs and short enough that
/// a mountpoint genuinely held by a guest is still reported, and the process
/// still leaves, at once.
const SETTLE_TAIL: Duration = Duration::from_millis(100);

/// How long the teardown pauses between unmount attempts while it settles.
///
/// Only ever waited when the kernel refused the unmount inside one of the two
/// windows above, so it is the resolution of that retry and nothing else.
const SETTLE_STEP: Duration = Duration::from_millis(5);

/// How often the teardown asks the kernel what it is still waiting for.
///
/// The window being waited out is a fraction of a millisecond, so the question
/// is asked often enough to answer inside it and rarely enough that waiting out
/// a server that never answers costs a few thousand reads of one small file,
/// not a spin.
const SETTLE_POLL: Duration = Duration::from_micros(500);

/// How long a signalled teardown waits for the FUSE session to finish.
///
/// The unmount has already succeeded by the time this is waited on, so the
/// session loop is ending; the bound exists so that a kernel that never
/// finishes cannot keep the process alive, which the contract's "the process
/// still exits" requires.
const JOIN_PATIENCE: Duration = Duration::from_secs(30);

/// What a mount may be told to do differently.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MountOptions {
    /// How long the kernel may cache attributes.
    pub attr_timeout: Duration,
    /// How long the kernel may cache name resolutions.
    pub entry_timeout: Duration,
    /// Let users other than the mounting one reach the mount.
    pub allow_other: bool,
    /// Ask the kernel to refuse write-class operations itself, in addition to
    /// — never instead of — the server's share modes.
    pub read_only: bool,
    /// How many FUSE event loops read and dispatch in parallel.
    pub dispatch_threads: NonZeroUsize,
    /// How long requests stall when the server breaks away, before the mount
    /// starts answering `EIO` immediately.
    ///
    /// Zero is fail-fast.
    pub reconnect_stall: Duration,
    /// Ask the kernel to unmount this mountpoint if the client dies without
    /// running a teardown.
    ///
    /// Opportunistic by design: the option is only offered where the platform
    /// takes it — `fusermount3` present **and** an ACL wider than owner-only,
    /// which means [`allow_other`](Self::allow_other) — and the decision is
    /// logged either way. Setting this false opts out entirely.
    pub auto_unmount: bool,
    /// Keep no copy of file data in the guest page cache.
    ///
    /// Off by default. On, reads and writes go straight to the wire, so many
    /// guests reading one host file stop each holding their own copy of it in
    /// their own memory — which is the whole point — while `mmap` keeps working,
    /// with the kernel caching pages only for ranges a process actually mapped.
    /// Metadata caching is untouched: the two TTLs above are what governs it.
    ///
    /// The cost is that unmapped reads become wire-immediate: re-read
    /// throughput is wire speed, not RAM speed, and freshness tightens
    /// to per-read.
    ///
    /// It degrades *downwards*, never sideways: a guest kernel too old to allow
    /// `mmap` under direct I/O keeps ordinary page caching and the memory it
    /// costs, with a logged notice, because breaking `mmap` — and with it
    /// exec-from-mount and SQLite's WAL — is excluded in every configuration.
    /// See [`DataCaching::resolve`](crate::fuse::DataCaching::resolve).
    pub direct_io: bool,
    /// Whether this mount shows privileged mode bits (setuid, setgid).
    ///
    /// On by default. Off, every attribute this mount presents has them masked
    /// and a chmod that would set one is refused — the client-side half of the
    /// two switches recorded metadata always has, and stronger than the classic
    /// `nosuid`, which honors nothing but still shows the bits.
    ///
    /// Opting one mount out never destroys recorded truth: a chmod through such
    /// a mount carries the bits the server holds back to it unchanged, so
    /// mounts that do present them are unaffected.
    pub privileged_bits: bool,
    /// The ceiling, in bytes, of the readahead pool this mount may hold.
    ///
    /// A ceiling and not an allocation: an idle mount holds nothing, and the
    /// pool fills only while something reads sequentially. Zero disables the
    /// engine, which restores strict wire-immediate reads.
    ///
    /// It only ever matters on a mount whose negotiated data caching is
    /// **direct**: that is the mode with no kernel page cache and therefore no
    /// kernel readahead in front of the wire. A page-cached mount is already
    /// served by the kernel's own readahead and the engine does not run there.
    pub readahead: usize,
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
            direct_io: false,
            privileged_bits: true,
            readahead: DEFAULT_POOL_BYTES,
        }
    }
}

impl MountOptions {
    /// The fuser configuration these options describe.
    ///
    /// `default_permissions` and `fsname=voidport` are not optional: the first
    /// is what makes the guest kernel enforce the presented bits, and the
    /// second is how the mount identifies itself in `/proc/mounts`.
    ///
    /// `clone_fd` always accompanies the thread count: without it every loop
    /// reads the one descriptor and contends on the kernel's per-connection
    /// lock, which is most of what the extra loops were added to avoid. It has
    /// no effect at one loop, where fuser clones nothing.
    #[must_use]
    fn config(&self) -> Config {
        let mut mount_options = vec![
            MountOption::DefaultPermissions,
            MountOption::FSName(FSNAME.to_owned()),
        ];
        if self.read_only {
            mount_options.push(MountOption::RO);
        }
        if self.auto_unmounts() {
            mount_options.push(MountOption::AutoUnmount);
        }
        let mut config = Config::default();
        config.mount_options = mount_options;
        config.acl = if self.allow_other {
            SessionACL::All
        } else {
            SessionACL::Owner
        };
        config.n_threads = Some(self.dispatch_threads.get());
        config.clone_fd = true;
        config
    }

    /// Whether this mount can actually carry `auto_unmount`.
    ///
    /// Both conditions are fuser 0.18's, not preferences: `Session::new`
    /// **refuses** the option outright under `SessionACL::Owner`, and the
    /// option itself is implemented only on the `fusermount` path, so a machine
    /// without the helper cannot mount with it at all. Asking anyway would turn
    /// an opportunistic convenience into a mount failure.
    ///
    /// Public because it is the honest answer to "will a `SIGKILL` of this
    /// process leave a mountpoint behind?", which is a property of the platform,
    /// not of the client: an operator tool — and the teardown suite's
    /// gate on the auto-unmount arm — needs to ask it without mounting.
    #[must_use]
    pub fn auto_unmounts(&self) -> bool {
        self.auto_unmount && self.allow_other && fusermount_helper().is_some()
    }

    /// The resilience a mount built from these options runs with.
    fn resilience(&self) -> Resilience {
        Resilience {
            stall: self.reconnect_stall,
        }
    }
}

/// The candidates fuser 0.18 looks for, in its order.
///
/// Copied from `fuser::mnt::fuse_pure::detect_fusermount_bin`, absolute
/// fallbacks included: a machine whose helper lives in `/sbin` but not on
/// `PATH` is one fuser mounts on and a `PATH`-only lookup would wrongly give up
/// on. `mount_fusefs` is the BSD spelling and is in the list for the same
/// reason — it is in fuser's.
const FUSERMOUNT_CANDIDATES: [&str; 8] = [
    "fusermount3",
    "fusermount",
    "mount_fusefs",
    "/sbin/fusermount3",
    "/sbin/fusermount",
    "/sbin/mount_fusefs",
    "/bin/fusermount3",
    "/bin/fusermount",
];

/// The `fusermount` helper on this machine, if there is one.
///
/// The lookup mirrors fuser's own, because the question it answers is fuser's:
/// *will the helper fuser is about to run be there?* An explicit
/// `FUSERMOUNT_PATH` wins outright and with no fallback, exactly as it does in
/// fuser — a machine that names a helper has named the only one that will be
/// tried — and otherwise the candidates are tried in fuser's order.
///
/// Every candidate, `FUSERMOUNT_PATH` included, has to actually spawn. That is
/// fuser's own test (`Command::new(name).arg("-h").output().is_ok()`, whose
/// exit status it ignores too: this is a presence probe, not a version check),
/// and applying it to `FUSERMOUNT_PATH` as well is what stops a stale variable
/// from turning `auto_unmount` into a mount failure. A `FUSERMOUNT_PATH` that
/// is not UTF-8 is treated as absent, not followed, because fuser
/// *panics* on one and an opportunistic convenience may not abort a mount.
///
/// It is only ever consulted once per mount.
fn fusermount_helper() -> Option<String> {
    if let Some(path) = std::env::var_os("FUSERMOUNT_PATH") {
        return path.into_string().ok().filter(|named| spawns(named));
    }
    FUSERMOUNT_CANDIDATES
        .into_iter()
        .find(|name| spawns(name))
        .map(str::to_owned)
}

/// Whether a helper of that name can be run at all.
fn spawns(name: &str) -> bool {
    Command::new(name)
        .arg("-h")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

/// A live mount: the kernel session, the connection behind it, and the runtime
/// its callbacks run on.
#[derive(Debug)]
pub struct Mount {
    mountpoint: PathBuf,
    client: Arc<Client>,
    /// The mount's readahead engine, held here as well as inside the FUSE
    /// adapter so that what it is holding can be asked about without going
    /// through the kernel.
    readahead: Arc<Readahead>,
    /// The callbacks the kernel is owed a reply for, held here as well as
    /// inside the FUSE adapter because the teardown is what waits on them.
    inflight: Arc<InFlight>,
    /// What the kernel says it is still waiting for, which is the part of the
    /// same question the adapter cannot answer.
    queue: KernelQueue,
    /// Taken by the teardown; `None` afterwards.
    session: Option<BackgroundSession>,
    /// Dropped after the session is joined, never before.
    runtime: Option<tokio::runtime::Runtime>,
}

impl Mount {
    /// Connects to the server, mounts the namespace, and returns once the
    /// filesystem is serving.
    ///
    /// # Errors
    ///
    /// Returns [`MountError`] for a connection that could not be established, a
    /// mountpoint the kernel would not take, or a kernel that cannot offer the
    /// capabilities the client requires.
    pub fn new(
        url: &MountUrl,
        mountpoint: &Path,
        options: &MountOptions,
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

        // The engine's freshness bound is the mount's attribute TTL: a
        // prefetched block older than that is dropped, not served, which
        // is what keeps prefetching inside the coherence the mount already
        // promises.
        let readahead = Readahead::new(options.readahead, options.attr_timeout);
        let inflight = Arc::<InFlight>::default();
        let filesystem = VoidportFs::new(
            Arc::clone(&client),
            runtime.handle().clone(),
            options.attr_timeout,
            options.entry_timeout,
            options.direct_io,
            crate::fuse::attr::Privileged::of(!options.privileged_bits),
            Arc::clone(&readahead),
            Arc::clone(&inflight),
        );
        let invalidator = filesystem.invalidator();
        let session = Session::new(filesystem, mountpoint, &options.config())
            .inspect(|session| invalidator.attach(session.notifier()))
            .and_then(Session::spawn)
            .map_err(|source| MountError::Mount {
                mountpoint: mountpoint.display().to_string(),
                source,
            })?;

        if options.auto_unmount {
            if options.auto_unmounts() {
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
        // Looked up here, while the mount is going up, so that no teardown ever
        // has to ask the mountpoint anything.
        let queue = KernelQueue::of(mountpoint);
        Ok(Self {
            mountpoint: mountpoint.to_path_buf(),
            client,
            readahead,
            inflight,
            queue,
            session: Some(session),
            runtime: Some(runtime),
        })
    }

    /// The mountpoint.
    #[must_use]
    pub fn mountpoint(&self) -> &Path {
        &self.mountpoint
    }

    /// The session this mount is served by, for callers that need to speak to
    /// the server directly.
    #[must_use]
    pub fn client(&self) -> Arc<Client> {
        Arc::clone(&self.client)
    }

    /// The mount's readahead engine.
    ///
    /// Test support: it is how a suite asks what the pool is holding and what
    /// the engine has done, and it adds no control surface — nothing here can
    /// change what the engine does.
    #[must_use]
    pub fn readahead(&self) -> Arc<Readahead> {
        Arc::clone(&self.readahead)
    }

    /// Serves until the mountpoint is unmounted **or** this process is asked to
    /// terminate, then tears down in the required order.
    ///
    /// This is what the foreground `voidport mount` does. `SIGINT` and `SIGTERM`
    /// both run the same teardown as a clean unmount would, which is the whole
    /// point: a Ctrl-C on a mount must not leave a mountpoint behind for the
    /// operator to clean up.
    ///
    /// The FUSE session is joined on a helper thread, not on this one,
    /// because the two things that end a mount — the session loop finishing and
    /// a signal arriving — have to be waited for *together*. A busy mountpoint
    /// still refuses to unmount; the process then exits anyway, reporting the
    /// kernel's `EBUSY`, and `voidport umount` recovers the mountpoint once it
    /// is idle. That is the contract's "the process still exits and the
    /// mountpoint is recoverable".
    ///
    /// # Errors
    ///
    /// Whatever ended the FUSE session, or the kernel's refusal to unmount.
    pub fn serve_until_signalled(mut self) -> io::Result<()> {
        let Some(session) = self.session.take() else {
            return Ok(());
        };
        let (ended, endings) = channel();
        let signals = self.watch_signals(ended.clone())?;
        // The join runs off this thread so a signal can be noticed while it is
        // still waiting; nothing else touches the session, so it is moved whole.
        std::thread::Builder::new()
            .name("voidport-session".to_owned())
            .spawn(move || {
                let _ = ended.send(Ending::Session(session.join()));
            })?;

        let ending = endings.recv().unwrap_or(Ending::Session(Ok(())));
        drop(signals);
        match ending {
            // Somebody unmounted the mountpoint under us: the kernel side is
            // already over, so only the connection and the runtime are left.
            Ending::Session(served) => {
                self.client.close();
                self.runtime.take();
                served
            }
            Ending::Signal(signal) => {
                tracing::info!(signal, "unmounting on signal");
                self.teardown_on_signal(&endings)
            }
        }
    }

    /// The ordered teardown a termination signal runs.
    fn teardown_on_signal(
        &mut self,
        endings: &std::sync::mpsc::Receiver<Ending>,
    ) -> io::Result<()> {
        // First, per the resilience contract: nothing may be dialling a server
        // or sleeping out a backoff while the mountpoint comes down, and a
        // stalled callback is owed its answer now. It has to come before the
        // wait below, because a callback parked in a stall window is one that
        // would otherwise never settle.
        self.client.stop_reconnecting();
        let unmounted = self.unmount_when_settled();
        // Then the required order: the connection fails what it still owes, and
        // the session loop is joined before the runtime those replies ran on is
        // released.
        self.client.close();
        if let Err(error) = unmounted {
            tracing::error!(
                mountpoint = %self.mountpoint.display(),
                %error,
                "the mountpoint could not be unmounted; `voidport umount` recovers it once it is idle"
            );
            // The session loop is still serving a mountpoint that is still
            // there, so there is nothing to join: leave without waiting, and
            // let the runtime's tasks die with the process.
            if let Some(runtime) = self.runtime.take() {
                runtime.shutdown_background();
            }
            return Err(error);
        }
        let joined = match endings.recv_timeout(JOIN_PATIENCE) {
            Ok(Ending::Session(served)) => served,
            Ok(Ending::Signal(_)) | Err(_) => Ok(()),
        };
        self.runtime.take();
        joined
    }

    /// Unmounts, once the callbacks the kernel is owed a reply for have been
    /// answered.
    ///
    /// A request the kernel is waiting on is work the guest asked for and is
    /// entitled to the answer to, and — while whoever asked is still inside the
    /// call — a reference the kernel counts against the mountpoint. Both halves
    /// of it are waited for: the callbacks this adapter is holding
    /// ([`InFlight`]) and what the kernel says it has queued behind them
    /// ([`KernelQueue`]), which is the half a filesystem cannot see for itself.
    /// The unmount is then retried while either is still settling, because the
    /// caller a reply has just reached takes a moment to leave the mount behind
    /// it.
    ///
    /// It is bounded twice over. [`SETTLE_PATIENCE`] bounds the wait for work
    /// that is outstanding, so a server that never answers cannot keep this
    /// process alive; [`SETTLE_TAIL`] bounds the retry once nothing is, which is
    /// the tail of a caller unwinding out of the mount. A mountpoint genuinely
    /// held by a guest — the `EBUSY` the contract keeps — is refused, reported
    /// and left in place a tenth of a second later, which is the whole of what
    /// this costs it.
    fn unmount_when_settled(&self) -> io::Result<()> {
        let started = Instant::now();
        let (deadline, tail) = (started + SETTLE_PATIENCE, started + SETTLE_TAIL);
        loop {
            // The callbacks this adapter is holding, and then the requests the
            // kernel has queued behind them: the second is what the first
            // cannot see, and the unmount has to be clear of both.
            self.inflight.settle(deadline);
            self.queue.settle(deadline);
            let unmounted = unmount(&self.mountpoint);
            let busy = matches!(
                &unmounted,
                Err(error) if error.raw_os_error() == Some(Errno::BUSY.raw_os_error())
            );
            let owes = !self.inflight.is_settled() || self.queue.is_waiting();
            let now = Instant::now();
            if !busy || now >= deadline || (!owes && now >= tail) {
                return unmounted;
            }
            std::thread::sleep(SETTLE_STEP);
        }
    }

    /// Watches for the two termination signals, reporting the first one.
    ///
    /// The handlers live on the mount's runtime because that is the only
    /// reactor this process has; the *teardown* they trigger runs on the thread
    /// that called [`Self::serve_until_signalled`], which is what the contract
    /// means by the main thread owning the teardown.
    fn watch_signals(&self, ended: Sender<Ending>) -> io::Result<tokio::sync::oneshot::Sender<()>> {
        use tokio::signal::unix::{SignalKind, signal};

        let runtime = self
            .runtime
            .as_ref()
            .ok_or_else(|| io::Error::other("the mount has no runtime"))?;
        let _guard = runtime.enter();
        let mut interrupt = signal(SignalKind::interrupt())?;
        let mut terminate = signal(SignalKind::terminate())?;
        let (cancel, cancelled) = tokio::sync::oneshot::channel();
        runtime.spawn(async move {
            let signal = tokio::select! {
                _ = cancelled => return,
                _ = interrupt.recv() => "SIGINT",
                _ = terminate.recv() => "SIGTERM",
            };
            let _ = ended.send(Ending::Signal(signal));
        });
        Ok(cancel)
    }

    /// Unmounts and tears down, in the required order.
    ///
    /// # Errors
    ///
    /// Returns the kernel's error — `EBUSY` for a mountpoint still in use — in
    /// which case **nothing** is torn down and the mount is still usable: still
    /// mounted, and still recovering if it was.
    pub fn unmount(&mut self) -> io::Result<()> {
        let Some(session) = self.session.take() else {
            return Ok(());
        };
        // First, per the resilience contract: a teardown from Reconnecting or
        // Degraded cancels the in-flight attempt and its backoff, so nothing is
        // dialling a server or sleeping while the mountpoint comes down.
        self.client.pause_recovery();
        if let Err(error) = unmount(&self.mountpoint) {
            // Nothing happened: the mount is still live and still ours, so the
            // recovery it was in the middle of is handed back, not lost.
            self.client.resume_recovery();
            self.session = Some(session);
            return Err(error);
        }
        // The required order, and the reason for each step: closing the connection
        // ends the mount and fails every outstanding wire request, so the
        // callbacks still owed a reply — including any stalled in a reconnect
        // window — answer EIO instead of waiting; joining waits
        // for those replies to actually reach the kernel; releasing the runtime
        // last is what makes that wait meaningful, because the tasks replying
        // run on it.
        self.client.close();
        // Whatever the pool was holding for a mount that is coming down is
        // owed back to the process now, not at the last `Arc`.
        self.readahead.clear();
        let joined = session.join();
        self.runtime.take();
        joined
    }
}

/// What ended a foreground mount.
#[derive(Debug)]
enum Ending {
    /// The FUSE session loop finished — somebody unmounted the mountpoint.
    Session(io::Result<()>),
    /// A termination signal arrived.
    Signal(&'static str),
}

impl Drop for Mount {
    /// Best-effort teardown, so a dropped mount never leaves a stale one
    /// behind. A mountpoint that is busy at this point is reported and left to
    /// the operator: v1 has no forced unmount.
    fn drop(&mut self) {
        if self.session.is_none() {
            return;
        }
        if let Err(error) = self.unmount() {
            tracing::error!(
                mountpoint = %self.mountpoint.display(),
                %error,
                "the mount could not be unmounted and is still in place"
            );
        }
    }
}

/// What the kernel is still waiting for from one mount's connection.
///
/// The adapter can only count the callbacks it has been handed, and that is not
/// all of what a mount owes: a request the kernel has queued and no dispatch
/// loop has picked up yet is invisible to it. The window is short — a fraction
/// of a millisecond, measured — and both ends of it hurt. An unmount inside it
/// is refused `EBUSY`, because the kernel holds the mountpoint for the request
/// it is waiting on; an unmount just before it leaves the answer that follows
/// with nowhere to go, which is an error in the log of a teardown that
/// otherwise went perfectly.
///
/// The kernel publishes the number itself, per connection, in `fusectl`:
/// `waiting` is how many replies it is still owed. Reading it is a courtesy and
/// not a requirement — where `fusectl` is not mounted there is nothing to read,
/// and the teardown keeps the adapter's own count alone and behaves exactly as
/// it did before.
#[derive(Debug)]
struct KernelQueue {
    /// The connection's `waiting` file, where this kernel publishes one.
    waiting: Option<PathBuf>,
}

impl KernelQueue {
    /// The connection serving a mountpoint, found without asking the mount
    /// anything.
    ///
    /// A FUSE mount carries an anonymous device and `fusectl` names each
    /// connection's directory after that device's minor, so the lookup is the
    /// mountpoint's own line in `/proc/self/mountinfo`: `id parent major:minor
    /// root mountpoint …`, whose mountpoint field is the path with the only
    /// four characters that file escapes written in octal. Matching the escaped
    /// spelling of the path this mount was given is therefore the whole of it —
    /// and it costs no operation on the mount, which a `stat` of the mountpoint
    /// would, on a server that may not be answering.
    ///
    /// Done once, at mount time. A teardown never asks.
    fn of(mountpoint: &Path) -> Self {
        let escaped = mountpoint
            .display()
            .to_string()
            .replace('\\', "\\134")
            .replace(' ', "\\040")
            .replace('\t', "\\011")
            .replace('\n', "\\012");
        let waiting = std::fs::read_to_string("/proc/self/mountinfo")
            .ok()
            .and_then(|mountinfo| {
                mountinfo
                    .lines()
                    .filter(|line| line.split(' ').nth(4) == Some(escaped.as_str()))
                    .filter_map(|line| line.split(' ').nth(2))
                    .filter_map(|device| device.split(':').nth(1))
                    .next_back()
                    .map(|connection| {
                        PathBuf::from(format!("/sys/fs/fuse/connections/{connection}/waiting"))
                    })
            })
            .filter(|waiting| waiting.exists());
        Self { waiting }
    }

    /// Whether the kernel is waiting for anything from this mount right now.
    ///
    /// A kernel that does not publish the number answers `false`, because an
    /// unknown is not a reason to keep waiting.
    fn is_waiting(&self) -> bool {
        self.waiting().is_some_and(|waiting| waiting > 0)
    }

    /// How many replies the kernel is still waiting for, where it says.
    fn waiting(&self) -> Option<usize> {
        let waiting = self.waiting.as_ref()?;
        std::fs::read_to_string(waiting).ok()?.trim().parse().ok()
    }

    /// Waits until the kernel is waiting for nothing, or until the deadline
    /// passes, and answers whether it was waiting for anything at all.
    fn settle(&self, deadline: Instant) {
        while self.is_waiting() {
            if Instant::now() >= deadline {
                return;
            }
            std::thread::sleep(SETTLE_POLL);
        }
    }
}

/// Unmounts a voidport mountpoint.
///
/// A plain kernel unmount, with no lazy or forced mode: a busy mountpoint
/// surfaces the kernel's `EBUSY` instead of being detached behind the guest's
/// back.
///
/// # Errors
///
/// Returns the kernel's error: `EBUSY` when the mountpoint is in use,
/// `EINVAL` when it is not a mountpoint, `EPERM` without the privilege to
/// unmount it.
pub fn unmount(mountpoint: &Path) -> io::Result<()> {
    rustix::mount::unmount(mountpoint, UnmountFlags::empty()).map_err(io::Error::from)
}

/// Why a mount could not be established.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MountError {
    /// The client runtime could not be started.
    #[error("the client runtime could not be started")]
    Runtime(#[source] io::Error),
    /// The session could not be established.
    #[error(transparent)]
    Connect(#[from] ConnectError),
    /// The kernel would not take the mountpoint, or would not negotiate what
    /// the client requires.
    #[error("cannot mount on {mountpoint}")]
    Mount {
        /// The mountpoint asked for.
        mountpoint: String,
        /// Why not.
        #[source]
        source: io::Error,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_mount_always_carries_default_permissions_and_its_fsname() {
        let config = MountOptions::default().config();
        assert!(
            config
                .mount_options
                .contains(&MountOption::DefaultPermissions)
        );
        assert!(
            config
                .mount_options
                .contains(&MountOption::FSName(FSNAME.to_owned()))
        );
        assert!(!config.mount_options.contains(&MountOption::RO));
        assert_eq!(config.acl, SessionACL::Owner);
    }

    #[test]
    fn read_only_and_allow_other_reach_the_kernel() {
        let config = MountOptions {
            read_only: true,
            allow_other: true,
            ..MountOptions::default()
        }
        .config();
        assert!(config.mount_options.contains(&MountOption::RO));
        assert_eq!(config.acl, SessionACL::All);
    }

    #[test]
    fn the_event_loop_count_reaches_the_session_with_its_own_descriptors() {
        let config = MountOptions {
            dispatch_threads: NonZeroUsize::new(3).expect("3 is not zero"),
            ..MountOptions::default()
        }
        .config();
        assert_eq!(config.n_threads, Some(3));
        assert!(
            config.clone_fd,
            "extra event loops without their own descriptor contend on the one"
        );
    }

    #[test]
    fn the_default_is_the_measured_one() {
        let config = MountOptions::default().config();
        assert_eq!(config.n_threads, Some(DEFAULT_DISPATCH_THREADS.get()));
    }

    /// Auto-unmount is opportunistic: it is asked for only where fuser would
    /// accept it, because asking anywhere else turns a convenience into a mount
    /// failure. The owner-only ACL is the case that made the original
    /// guaranteed-default unbuildable.
    #[test]
    fn auto_unmount_is_only_asked_for_where_the_platform_takes_it() {
        let owner_only = MountOptions::default();
        assert!(
            !owner_only.auto_unmounts(),
            "fuser refuses auto_unmount under the owner-only ACL"
        );
        assert!(
            !owner_only
                .config()
                .mount_options
                .contains(&MountOption::AutoUnmount)
        );

        let opted_out = MountOptions {
            allow_other: true,
            auto_unmount: false,
            ..MountOptions::default()
        };
        assert!(!opted_out.auto_unmounts(), "--no-auto-unmount opts out");

        // With the ACL widened, the helper is the only remaining condition —
        // and it is the same lookup fuser itself would perform.
        let widened = MountOptions {
            allow_other: true,
            ..MountOptions::default()
        };
        assert_eq!(widened.auto_unmounts(), fusermount_helper().is_some());
        assert_eq!(
            widened
                .config()
                .mount_options
                .contains(&MountOption::AutoUnmount),
            fusermount_helper().is_some()
        );
    }

    /// Direct I/O is off unless asked for, and it changes nothing the kernel is
    /// told at mount time: it is negotiated in the FUSE handshake and applied
    /// per open, not through a mount option.
    #[test]
    fn direct_io_is_off_by_default_and_is_not_a_mount_option() {
        assert!(!MountOptions::default().direct_io);
        let asked = MountOptions {
            direct_io: true,
            ..MountOptions::default()
        };
        assert_eq!(
            asked.config().mount_options,
            MountOptions::default().config().mount_options
        );
    }

    /// A path that is not a mountpoint has no connection, and asking about one
    /// answers nothing — which is also what a machine without `fusectl` gets,
    /// and the case the teardown falls back from.
    #[test]
    fn a_path_that_is_not_a_mount_has_no_connection_to_ask() {
        let queue = KernelQueue::of(Path::new("/proc/self"));
        assert!(queue.waiting.is_none());
        assert_eq!(queue.waiting(), None);
        assert!(
            !queue.is_waiting(),
            "an unknown is not something to wait on"
        );
        let started = Instant::now();
        queue.settle(Instant::now() + Duration::from_secs(30));
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "nothing to wait for, so nothing is waited for"
        );
    }

    #[test]
    fn the_stall_window_reaches_the_client() {
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
