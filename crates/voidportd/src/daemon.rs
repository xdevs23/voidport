//! Daemon assembly: startup, serving, clean shutdown.
//!
//! Startup is synchronous and ordered so that a failure costs nothing:
//!
//! 1. take the single-instance lock — before reading or writing anything, so
//!    two daemons racing on one state file cannot both parse it, nor both
//!    create it;
//! 2. create the state file if it is *cleanly* missing (see
//!    [`create_if_missing`]); anything else on the path is left for the loader
//!    to refuse;
//! 3. sweep temporary files left by an interrupted persist;
//! 4. load and build the whole state — an invalid file, or a graft target that
//!    cannot be pinned, refuses startup;
//! 5. seed a `voidportd share` launch's configuration into the document, through
//!    the same validate → persist → swap ordering every control-plane mutation
//!    uses;
//! 6. bind the control socket per its contract;
//! 7. bind every data listener, all or nothing.
//!
//! Zero listeners is a legal outcome of step 7: such a server serves only its
//! control socket, and everything else — listeners included — is added through
//! `voidport-ctl` while it runs.
//!
//! Only then does anything asynchronous happen. Because [`Daemon::start`]
//! returns after everything is bound, a caller (the binary, or a test) knows
//! both planes are reachable the moment it gets a `Daemon` — there is no "wait
//! for the server to come up" race anywhere. Shutdown is the mirror image: both
//! planes stop accepting, in-flight work finishes, and every socket the server
//! created is unlinked.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::sync::watch;

use crate::control::service::Service;
use crate::control::socket::{BindError, ControlSocket};
use crate::data::listener::{DataListeners, ListenerError};
use crate::data::pin::{DESCRIPTOR_RESERVE, DescriptorLimit};
use crate::data::server::DataPlane;
use crate::launch::LaunchSummary;
use crate::seed::{Seed, SeedError};
use crate::state::{
    Environment, InstanceLock, LoadError, LoadedState, LockError, PersistError, StateDocument,
    containing_directory, create_if_missing, load, persist, sweep_orphans, validate,
};

/// The name a seeded launch gives the control socket it places beside the state
/// file.
pub const SEEDED_CONTROL_SOCKET: &str = "control.sock";

/// What a daemon needs to start.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DaemonConfig {
    /// The state file the server owns.
    pub state_file: PathBuf,
    /// The control socket path from the command line, which wins over the one
    /// the state file names.
    pub control_socket: Option<PathBuf>,
    /// The environment the state document is interpreted in. Defaults to the
    /// running process and the state file's directory.
    pub environment: Option<Environment>,
    /// The configuration a `voidportd share` launch seeds before serving.
    pub seed: Option<Seed>,
    /// The file this process's tracing is being written to, when it is written
    /// to one.
    ///
    /// The daemon does not open it and does not log through it — the binary
    /// installs the subscriber and chooses the destination long before a daemon
    /// exists. It is told the path solely so `server-info` can report it, which
    /// is the only way an operator attached to a server they did not launch can
    /// learn where its diagnostics land.
    pub log_file: Option<PathBuf>,
}

impl DaemonConfig {
    /// A configuration for a state file, taking everything else from it.
    #[must_use]
    pub fn new(state_file: impl Into<PathBuf>) -> Self {
        Self {
            state_file: state_file.into(),
            control_socket: None,
            environment: None,
            seed: None,
            log_file: None,
        }
    }

    /// Names the control socket to bind, overriding whatever the state file
    /// names.
    #[must_use]
    pub fn with_control_socket(mut self, path: impl Into<PathBuf>) -> Self {
        self.control_socket = Some(path.into());
        self
    }

    /// Injects the environment, instead of reading the process for it.
    #[must_use]
    pub fn with_environment(mut self, environment: Environment) -> Self {
        self.environment = Some(environment);
        self
    }

    /// Makes this a seeded launch: the seed is applied to the state file before
    /// anything is served.
    #[must_use]
    pub fn with_seed(mut self, seed: Seed) -> Self {
        self.seed = Some(seed);
        self
    }

    /// Tells the server where this process's tracing is being written, so
    /// `server-info` can report it.
    #[must_use]
    pub fn with_log_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.log_file = Some(path.into());
        self
    }
}

/// A started server: state loaded, lock held, both planes bound.
#[derive(Debug)]
pub struct Daemon {
    service: Arc<Service>,
    socket: ControlSocket,
    data: Arc<DataListeners>,
    /// The seed this launch was started with, kept solely so the launch summary
    /// can name the namespace it created.
    seed: Option<Seed>,
    /// Held for the daemon's lifetime; dropping it releases the state file.
    _lock: InstanceLock,
}

impl Daemon {
    /// Starts a server.
    ///
    /// # Errors
    ///
    /// Returns a [`StartupError`] if another instance holds the state file, the
    /// state file cannot be created or does not load, a seed collides with what
    /// the file already holds, or a socket cannot be bound.
    pub fn start(config: &DaemonConfig) -> Result<Self, StartupError> {
        let lock = InstanceLock::acquire(&config.state_file)?;
        if create_if_missing(&config.state_file)? {
            tracing::info!(
                state_file = %config.state_file.display(),
                "created the state file: a server with nothing configured"
            );
        }
        sweep_orphans(&config.state_file)?;
        let environment = config
            .environment
            .clone()
            .unwrap_or_else(|| Environment::for_state_file(&config.state_file));
        let mut loaded = load(&config.state_file, &environment)?;
        if let Some(seed) = &config.seed {
            let socket = seeded_control_socket(config)?;
            loaded = apply_seed(
                seed,
                socket.as_deref(),
                loaded,
                &config.state_file,
                &environment,
            )?;
        }

        // The raise comes first: an unconfigured node descriptor budget is
        // derived from the soft limit this reaches, not from the one the
        // process started with.
        let soft = raise_descriptor_limit();
        // The other process-wide property a server sets before it serves: how
        // the memory of a drained node table finds its way back to the host.
        crate::reclaim::start();

        let control_socket = control_socket(config, &loaded.document);
        let socket = ControlSocket::bind(&control_socket)?;

        let listeners = loaded.document.server.listeners.clone();
        let service = Arc::new(Service::new(
            &config.state_file,
            &control_socket,
            environment,
            loaded,
            DescriptorLimit::reached(soft),
            config.log_file.clone(),
        ));
        log_descriptor_budget(&service.descriptor_budget(), &service.limits(), soft);
        // All or nothing: a server that starts is reachable on every endpoint
        // its operator configured. None of them is legal too — that server
        // serves its control socket and waits to be given listeners.
        let data = DataListeners::bind(DataPlane::new(Arc::clone(&service)), &listeners)?;
        // The registry, not a snapshot of it: `server info` reports where a
        // guest connects *right now*, ephemeral ports resolved and runtime
        // additions included.
        service.attach_listeners(Arc::clone(&data));

        Ok(Self {
            service,
            socket,
            data,
            seed: config.seed.clone(),
            _lock: lock,
        })
    }

    /// What a seeded launch has to tell its operator, derived from the
    /// listeners and the control socket as they actually bound.
    ///
    /// `None` for a plain launch: there is nothing to say that the operator did
    /// not already write in the state file. The binary prints this; the
    /// operator TUI renders the same value.
    #[must_use]
    pub fn launch_summary(&self) -> Option<LaunchSummary> {
        let seed = self.seed.as_ref()?;
        Some(LaunchSummary::new(
            seed.namespace(),
            &self.data.endpoints(),
            self.socket.path(),
        ))
    }

    /// The live data listeners, for tests that need the endpoint an ephemeral
    /// port resolved to.
    #[must_use]
    pub fn data_listeners(&self) -> &Arc<DataListeners> {
        &self.data
    }

    /// The control-plane service, shareable with anything that needs to answer
    /// requests.
    #[must_use]
    pub fn service(&self) -> Arc<Service> {
        Arc::clone(&self.service)
    }

    /// The control socket path actually bound.
    #[must_use]
    pub fn control_socket(&self) -> &Path {
        self.socket.path()
    }

    /// Serves both planes until `shutdown` resolves, then shuts down cleanly:
    /// in-flight mutations complete, sessions end, and every socket the server
    /// created is unlinked.
    ///
    /// # Errors
    ///
    /// Returns an error only if the bound control socket cannot be handed to
    /// the async reactor.
    pub async fn serve(self, shutdown: impl Future<Output = ()> + Send) -> io::Result<()> {
        let Self {
            service,
            socket,
            data,
            seed: _,
            _lock,
        } = self;
        // One signal, two planes: whichever way shutdown arrives, both stop
        // accepting at the same moment.
        let (stop, _) = watch::channel(false);
        let control_stop = stop.subscribe();
        let data_stop = stop.subscribe();

        let signal = async move {
            shutdown.await;
            let _ = stop.send(true);
        };
        let control = crate::control::serve(socket, service, stopped(control_stop));
        let data = data.serve(stopped(data_stop));

        let (control, (), ()) = tokio::join!(control, data, signal);
        control
        // `_lock` is dropped here: the state file is free for the next daemon.
    }
}

/// Applies a seeded launch's configuration to the loaded state.
///
/// This is the control plane's mutation sequence, in the same order and for the
/// same reason: **validate → persist → swap**. The seed edits a copy of the
/// source document, the edited document is validated through the engine's build
/// boundary, and only a document that is durably on disk becomes the state the
/// server goes on to serve. A refusal at either step publishes nothing and
/// leaves the file exactly as it was.
///
/// An identical relaunch changes nothing, so nothing is written: the file is not
/// even rewritten, which is the strongest form the idempotence rule can take.
///
/// `control_socket` is the socket this launch would seed, from
/// [`seeded_control_socket`]; the seed writes it only into a document that names
/// none.
fn apply_seed(
    seed: &Seed,
    control_socket: Option<&Path>,
    loaded: LoadedState,
    state_file: &Path,
    environment: &Environment,
) -> Result<LoadedState, StartupError> {
    let mut document = loaded.document.clone();
    if !seed.apply(&mut document, control_socket)? {
        tracing::info!(
            namespace = seed.namespace().as_str(),
            directory = %seed.directory().display(),
            "the state file already holds this share",
        );
        return Ok(loaded);
    }
    let registry = validate(&document, environment)?;
    match persist(&document, state_file) {
        Ok(()) => {}
        // The rename is the commit point: the file already holds the seed, so
        // serving it is the only reading that keeps memory and disk together.
        Err(PersistError::Committed { path, source }) => tracing::warn!(
            directory = %path.display(),
            %source,
            "the seeded state was written, but directory durability could not be confirmed",
        ),
        Err(source) => return Err(source.into()),
    }
    tracing::info!(
        namespace = seed.namespace().as_str(),
        directory = %seed.directory().display(),
        "seeded the state file",
    );
    Ok(LoadedState { document, registry })
}

/// Where the kernel publishes the highest descriptor limit a process may be
/// given.
const NR_OPEN: &str = "/proc/sys/fs/nr_open";

/// How many open descriptors the running server may need, when that is a
/// number at all.
///
/// `budget` is the node descriptor cache's ceiling — the bound that replaced
/// the retracted per-node arithmetic. A node no longer holds a descriptor for
/// its lifetime (2026-08-15: it did, and an AOSP walk exhausted the table at
/// the rate of names ever resolved), so `max_nodes` no longer implies
/// descriptors at all; it bounds table entries.
///
/// A **handle** still holds an open file for as long as the guest keeps it
/// open, so a configured `max_handles` still implies descriptors, and
/// `None` — the default posture — implies no number to check: an unbounded
/// handle cap is bounded by the machine, which is what
/// [`raise_descriptor_limit`] asks the OS for regardless.
#[must_use]
pub fn descriptor_demand(budget: u64, limits: &crate::state::Limits) -> Option<u64> {
    let handles = limits.max_handles? as u64;
    Some(
        budget
            .saturating_add(handles)
            .saturating_add(DESCRIPTOR_RESERVE),
    )
}

/// Raises `RLIMIT_NOFILE` to the OS maximum at startup.
///
/// The caps do not size this. With every per-session cap defaulting to
/// unbounded, the descriptor table is what a session's handles are bounded by,
/// so the server takes as much of it as the OS will give — `fs.nr_open`, the
/// kernel's own ceiling on a descriptor limit — and logs what it got. It is
/// also what the node descriptor budget is derived from when the operator
/// configured none, which is why the raise happens before the budget is sized.
///
/// The hard limit is raised along with the soft one where this process is
/// allowed to (that needs `CAP_SYS_RESOURCE`; a server without it settles for
/// the ceiling it was given).
///
/// Never a startup failure, and never a *lowering*: a server that cannot reach
/// the OS maximum still runs with everything it already had.
///
/// It reports the soft limit it reached, so the caller can size the node
/// descriptor budget from the same number this call produced.
fn raise_descriptor_limit() -> u64 {
    use rustix::process::{Resource, Rlimit, getrlimit, setrlimit};

    let before = getrlimit(Resource::Nofile);
    // No soft limit at all: this process may already open anything it likes.
    let Some(soft) = before.current else {
        return u64::MAX;
    };
    let ceiling = before.maximum;
    // The OS maximum, or — where the kernel does not publish it — the hard
    // limit this process was given, which is the most it could reach anyway.
    let wanted = os_maximum().unwrap_or_else(|| ceiling.unwrap_or(soft));

    let mut now = soft;
    if soft < wanted {
        // Two attempts, most-wanted first: raise the ceiling along with the
        // limit, and settle for the ceiling if this process may not move it.
        let raised = Rlimit {
            current: Some(wanted),
            maximum: Some(ceiling.map_or(wanted, |hard| hard.max(wanted))),
        };
        if setrlimit(Resource::Nofile, raised).is_err() {
            let capped = ceiling.map_or(wanted, |hard| hard.min(wanted));
            if let Err(error) = setrlimit(
                Resource::Nofile,
                Rlimit {
                    current: Some(capped),
                    maximum: ceiling,
                },
            ) {
                tracing::warn!(soft, wanted, %error, "cannot raise the open-file limit");
            }
        }
        let after = getrlimit(Resource::Nofile);
        now = after.current.unwrap_or(u64::MAX);
        tracing::info!(
            soft = now,
            hard = after.maximum.unwrap_or(u64::MAX),
            was = soft,
            wanted,
            "raised the open-file limit towards the OS maximum"
        );
    } else {
        tracing::info!(
            soft,
            wanted,
            "the open-file limit is already the OS maximum"
        );
    }

    now
}

/// Logs the node descriptor budget the server runs with, and warns where the
/// descriptor limit cannot back it together with a configured handle cap.
///
/// The cache closes descriptors instead of refusing lookups, so a budget the
/// machine cannot back is not the silent `EMFILE` the old per-node arithmetic
/// risked — but an operator who capped handles as well is describing a total
/// this process may not be able to hold, and the log says so once.
fn log_descriptor_budget(
    budget: &crate::data::DescriptorBudget,
    limits: &crate::state::Limits,
    soft: u64,
) {
    let budget = budget.budget() as u64;
    tracing::info!(
        node_descriptor_budget = budget,
        soft,
        "the node descriptor cache is bounded"
    );
    if let Some(needed) = descriptor_demand(budget, limits)
        && soft < needed
    {
        tracing::warn!(
            soft,
            needed,
            node_descriptor_budget = budget,
            max_handles = ?limits.max_handles,
            "the open-file limit is below what the budget and the configured handle cap \
             need together: raise the hard limit, or lower server.node_descriptor_budget"
        );
    }
}

/// The highest descriptor limit this OS allows a process, `fs.nr_open`.
///
/// `None` where the kernel does not publish it — a container without `/proc`,
/// say — which is not a failure: startup then settles for the hard limit it was
/// given.
fn os_maximum() -> Option<u64> {
    std::fs::read_to_string(NR_OPEN).ok()?.trim().parse().ok()
}

/// The control socket to bind, in the fixed order of precedence: the
/// `--control-socket` flag, then the state file's setting, then the compiled
/// default.
///
/// The flag wins because an explicit instruction losing to a configuration file
/// surprises every operator: a launch that names a socket binds that socket.
/// Neither spelling is a host target, so a relative one is interpreted exactly
/// as the process would interpret it, wherever the daemon was started.
fn control_socket(config: &DaemonConfig, document: &StateDocument) -> PathBuf {
    config
        .control_socket
        .clone()
        .or_else(|| document.server.control_socket.clone())
        .unwrap_or_else(|| PathBuf::from(voidport_control::DEFAULT_CONTROL_SOCKET))
}

/// Where a seeded launch would put its control socket: `control.sock` beside
/// the state file, absolute.
///
/// `None` when the launch named a socket on the command line — the flag wins
/// the precedence above, so seeding anything else would write into the document
/// a path this server does not bind. The document's own value, when it has one,
/// is left alone by [`Seed::apply`] itself.
///
/// The compiled default lives under `/run/voidport`, which a non-root operator
/// cannot bind, and the two-command flow must not require root. The path is
/// made absolute even when `--state` was relative, because the document is
/// persistent configuration: a relative socket path in it would mean "wherever
/// the next launch happens to be started from".
fn seeded_control_socket(config: &DaemonConfig) -> Result<Option<PathBuf>, StartupError> {
    if config.control_socket.is_some() {
        return Ok(None);
    }
    let directory = containing_directory(&config.state_file);
    let directory =
        std::path::absolute(directory).map_err(|source| StartupError::SeededSocket {
            directory: directory.to_path_buf(),
            source,
        })?;
    Ok(Some(directory.join(SEEDED_CONTROL_SOCKET)))
}

/// Why a server could not start.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StartupError {
    /// Another daemon owns the state file.
    #[error(transparent)]
    Lock(#[from] LockError),
    /// Startup cleanup of an interrupted persist failed.
    #[error(transparent)]
    Persist(#[from] PersistError),
    /// The state file does not load.
    #[error(transparent)]
    Load(#[from] LoadError),
    /// A seeded launch collides with what the state file already holds.
    #[error(transparent)]
    Seed(#[from] SeedError),
    /// A seeded launch could not resolve where to put its control socket.
    #[error("cannot resolve {directory} to place the seeded control socket beside the state file")]
    SeededSocket {
        /// The state file's directory, as it was given.
        directory: PathBuf,
        /// Why it could not be made absolute.
        #[source]
        source: io::Error,
    },
    /// The control socket could not be bound.
    #[error(transparent)]
    Bind(#[from] BindError),
    /// A data listener could not be bound.
    #[error(transparent)]
    Listener(#[from] ListenerError),
}

/// Resolves when the shutdown signal is set.
async fn stopped(mut stop: watch::Receiver<bool>) {
    let _ = stop.wait_for(|stopped| *stopped).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn document(configured: Option<&str>) -> StateDocument {
        let mut document = StateDocument::default();
        document.server.control_socket = configured.map(PathBuf::from);
        document
    }

    #[test]
    fn the_command_line_names_the_control_socket_before_the_state_file_does() {
        let config = DaemonConfig::new("state.toml").with_control_socket("/run/flag.sock");
        assert_eq!(
            control_socket(&config, &document(Some("/run/configured.sock"))),
            PathBuf::from("/run/flag.sock"),
            "an explicit flag binds what it names"
        );
        assert_eq!(
            control_socket(
                &DaemonConfig::new("state.toml"),
                &document(Some("/run/configured.sock"))
            ),
            PathBuf::from("/run/configured.sock")
        );
        assert_eq!(
            control_socket(&config, &document(None)),
            PathBuf::from("/run/flag.sock")
        );
    }

    #[test]
    fn a_seeded_launch_places_its_control_socket_beside_the_state_file() {
        assert_eq!(
            seeded_control_socket(&DaemonConfig::new("/srv/voidport/state.toml"))
                .expect("an absolute state file resolves"),
            Some(PathBuf::from("/srv/voidport/control.sock"))
        );
        // A relative state file still seeds an absolute path: the document is
        // read again by launches started from elsewhere.
        let relative = seeded_control_socket(&DaemonConfig::new("state.toml"))
            .expect("the working directory resolves")
            .expect("a launch with no flag seeds a socket");
        assert!(relative.is_absolute(), "{}", relative.display());
        assert_eq!(
            relative,
            std::env::current_dir()
                .expect("a working directory")
                .join(SEEDED_CONTROL_SOCKET)
        );
        // The flag wins the precedence, so a launch that named a socket seeds
        // nothing: the document would otherwise name a path nothing binds.
        assert_eq!(
            seeded_control_socket(
                &DaemonConfig::new("/srv/voidport/state.toml")
                    .with_control_socket("/run/flag.sock")
            )
            .expect("resolves"),
            None
        );
    }

    /// The retracted arithmetic was one descriptor per node; what implies
    /// descriptors now is the cache's budget and a configured handle cap.
    #[test]
    fn the_descriptor_demand_is_the_budget_plus_the_handle_cap() {
        use crate::state::Limits;

        // The default posture: handles are unbounded, so there is no number to
        // check the machine against.
        assert_eq!(descriptor_demand(4096, &Limits::default()), None);
        // A node cap no longer implies descriptors at all.
        assert_eq!(
            descriptor_demand(
                4096,
                &Limits {
                    max_nodes: Some(1_000_000),
                    ..Limits::default()
                }
            ),
            None
        );
        assert_eq!(
            descriptor_demand(
                4096,
                &Limits {
                    max_nodes: Some(1_000_000),
                    max_handles: Some(8),
                    ..Limits::default()
                }
            ),
            Some(DESCRIPTOR_RESERVE + 4096 + 8)
        );
    }

    #[test]
    fn raising_the_descriptor_limit_never_lowers_it_and_asks_for_the_os_maximum() {
        use rustix::process::{Resource, getrlimit};

        let before = getrlimit(Resource::Nofile);
        // The raise is about the machine, and it never takes away descriptors
        // the process already has.
        let reached = raise_descriptor_limit();
        let after = getrlimit(Resource::Nofile);
        assert!(after.current >= before.current, "{after:?} {before:?}");
        assert_eq!(after.current.unwrap_or(u64::MAX), reached);

        raise_descriptor_limit();
        let raised = getrlimit(Resource::Nofile);
        assert!(raised.current >= before.current, "{raised:?} {before:?}");
        if let (Some(now), Some(maximum)) = (raised.current, os_maximum()) {
            assert!(
                now >= maximum.min(raised.maximum.unwrap_or(maximum)),
                "the soft limit stopped short of what this process may have: {raised:?}"
            );
        }
    }

    /// The kernel publishes it, and it is a real number: the raise above is
    /// sized from this file and from nothing else.
    #[test]
    fn the_os_maximum_is_read_from_the_kernel() {
        let maximum = os_maximum().expect("Linux publishes fs.nr_open");
        assert!(maximum >= 1024, "fs.nr_open reads as {maximum}");
    }

    #[test]
    fn a_server_nothing_named_a_socket_for_uses_the_compiled_default() {
        // The default `voidport-ctl` assumes: a server started with nothing but
        // a state file is still reachable by an operator who typed nothing but
        // `voidport-ctl`.
        assert_eq!(
            control_socket(&DaemonConfig::new("state.toml"), &document(None)),
            PathBuf::from(voidport_control::DEFAULT_CONTROL_SOCKET)
        );
    }
}
