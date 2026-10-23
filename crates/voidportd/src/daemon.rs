use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::sync::watch;

use crate::control::service::Service;
use crate::control::socket::{BindError, ControlSocket};
use crate::data::descriptor_budget::DescriptorLimit;
use crate::data::listener::{DataListeners, ListenerError};
use crate::data::server::{DataPlane, PlaneError};
use crate::data::token::{KeyError, Signer};
use crate::launch::LaunchSummary;
use crate::records::RecordHome;
use crate::seed::{Seed, SeedError};
use crate::state::{
    Environment, InstanceLock, LoadError, LoadedState, LockError, PersistError, StateDocument,
    containing_directory, create_if_missing, load, persist, sweep_orphans, validate,
};

pub const SEEDED_CONTROL_SOCKET: &str = "control.sock";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DaemonConfig {
    pub state_file: PathBuf,
    pub control_socket: Option<PathBuf>,
    pub seed: Option<Seed>,
    /// Only reported by `server-info`: the binary installs the subscriber.
    pub log_file: Option<PathBuf>,
}

impl DaemonConfig {
    #[must_use]
    pub fn new(state_file: impl Into<PathBuf>) -> Self {
        Self {
            state_file: state_file.into(),
            control_socket: None,
            seed: None,
            log_file: None,
        }
    }

    #[must_use]
    pub fn with_control_socket(mut self, path: impl Into<PathBuf>) -> Self {
        self.control_socket = Some(path.into());
        self
    }

    #[must_use]
    pub fn with_seed(mut self, seed: Seed) -> Self {
        self.seed = Some(seed);
        self
    }

    #[must_use]
    pub fn with_log_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.log_file = Some(path.into());
        self
    }
}

#[derive(Debug)]
pub struct Daemon {
    service: Arc<Service>,
    socket: ControlSocket,
    data: Arc<DataListeners>,
    seed: Option<Seed>,
    /// Held for the lifetime of the daemon; dropping it releases the state file.
    _lock: InstanceLock,
}

impl Daemon {
    /// # Errors
    ///
    /// Returns a [`StartupError`] naming the step that failed.
    pub fn start(config: &DaemonConfig) -> Result<Self, StartupError> {
        // The lock comes before anything reads or creates the state file, so
        // two daemons on one state file cannot both parse or both create it.
        // `create_if_missing` and `sweep_orphans` are safe only under it.
        let lock = InstanceLock::acquire(&config.state_file)?;
        if create_if_missing(&config.state_file)? {
            tracing::info!(
                state_file = %config.state_file.display(),
                "created the state file: a server with nothing configured"
            );
        }
        sweep_orphans(&config.state_file)?;
        let environment = Environment::for_state_file(&config.state_file);
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
        // derived from the soft limit it reaches.
        let soft = raise_descriptor_limit();
        crate::reclaim::start();

        let control_socket = control_socket(config, &loaded.document);
        let socket = ControlSocket::bind(&control_socket)?;

        let listeners = loaded.document.server.listeners.clone();
        // Read once: a key the server cannot use stops it before any listener
        // is bound.
        let signer = Signer::load(loaded.document.server.signing_key.as_deref())?;
        let service = Arc::new(Service::new(
            &config.state_file,
            &control_socket,
            environment,
            loaded,
            DescriptorLimit::reached(soft),
            config.log_file.clone(),
        ));
        log_descriptor_budget(&service.descriptor_budget(), soft);
        let plane = DataPlane::new(Arc::clone(&service), signer)?;
        let data = DataListeners::bind(plane, &listeners)?;
        // The registry, not a snapshot: `server info` reports runtime additions
        // and resolved ephemeral ports.
        service.attach_listeners(Arc::clone(&data));

        Ok(Self {
            service,
            socket,
            data,
            seed: config.seed.clone(),
            _lock: lock,
        })
    }

    #[must_use]
    pub fn launch_summary(&self) -> Option<LaunchSummary> {
        let seed = self.seed.as_ref()?;
        Some(LaunchSummary::new(
            seed.namespace(),
            &self.data.endpoints(),
            self.socket.path(),
        ))
    }

    #[must_use]
    pub fn service(&self) -> Arc<Service> {
        Arc::clone(&self.service)
    }

    #[must_use]
    pub fn control_socket(&self) -> &Path {
        self.socket.path()
    }

    /// # Errors
    ///
    /// Returns an error if the bound control socket cannot be handed to the
    /// async reactor.
    pub async fn serve(self, shutdown: impl Future<Output = ()> + Send) -> io::Result<()> {
        let Self {
            service,
            socket,
            data,
            seed: _,
            _lock,
        } = self;
        let (stop, _) = watch::channel(false);
        let control_stop = stop.subscribe();
        let data_stop = stop.subscribe();

        let signal = async move {
            shutdown.await;
            let _ = stop.send(true);
        };
        let records = Arc::clone(&service);
        let control = crate::control::serve(socket, service, stopped(control_stop));
        let data = data.serve(stopped(data_stop));

        let (control, (), ()) = tokio::join!(control, data, signal);
        flush_records(&records);
        control
    }
}

/// Runs after both planes stop and before the instance lock drops, so nothing
/// records meanwhile and no second daemon writes the same sidecars.
fn flush_records(service: &Service) {
    for store in service.snapshot().registry.stores() {
        if let Err(source) = store.flush() {
            tracing::warn!(
                namespace = store.name().as_str(),
                %source,
                "the recorded metadata of a namespace could not be written at shutdown"
            );
        }
    }
}

/// The same validate, persist, swap order as every control-plane mutation: a
/// refusal at either step leaves the file as it was. An identical relaunch
/// writes nothing.
///
/// `control_socket` is written only into a document that names none.
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
    let registry = validate(
        &document,
        environment,
        &RecordHome::for_state_file(state_file),
    )?;
    match persist(&document, state_file) {
        Ok(()) => {}
        // The rename is the commit point: the file already contains the seed,
        // so serving it makes memory match the disk.
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

const NR_OPEN: &str = "/proc/sys/fs/nr_open";

/// Raises `RLIMIT_NOFILE` to `fs.nr_open`, and the hard limit too where
/// `CAP_SYS_RESOURCE` allows. A failure only logs, and the limit is never
/// lowered. Returns the soft limit reached, which sizes the node descriptor
/// budget.
fn raise_descriptor_limit() -> u64 {
    use rustix::process::{Resource, Rlimit, getrlimit, setrlimit};

    let before = getrlimit(Resource::Nofile);
    let Some(soft) = before.current else {
        return u64::MAX;
    };
    let ceiling = before.maximum;
    // The OS maximum, or, where the kernel does not publish it, the hard limit
    // this process was given, which is the most it could reach anyway.
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

fn log_descriptor_budget(budget: &crate::data::DescriptorBudget, soft: u64) {
    tracing::info!(
        node_descriptor_budget = budget.budget() as u64,
        soft,
        "the node descriptor cache is bounded"
    );
}

/// `None` where the kernel does not publish it, such as in a container without
/// `/proc`.
fn os_maximum() -> Option<u64> {
    std::fs::read_to_string(NR_OPEN).ok()?.trim().parse().ok()
}

fn control_socket(config: &DaemonConfig, document: &StateDocument) -> PathBuf {
    config
        .control_socket
        .clone()
        .or_else(|| document.server.control_socket.clone())
        .unwrap_or_else(|| PathBuf::from(voidport_control::DEFAULT_CONTROL_SOCKET))
}

/// `None` when the launch named a socket: the flag wins, so the document would
/// name a path nothing binds.
///
/// The compiled default is under `/run/voidport`, which a non-root user
/// cannot bind. The path is made absolute because a relative path in the
/// persistent document would depend on the working directory of the next
/// launch.
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

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StartupError {
    #[error(transparent)]
    Lock(#[from] LockError),
    #[error(transparent)]
    Persist(#[from] PersistError),
    #[error(transparent)]
    Load(#[from] LoadError),
    #[error(transparent)]
    Seed(#[from] SeedError),
    #[error("cannot resolve {directory} to place the seeded control socket beside the state file")]
    SeededSocket {
        directory: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error(transparent)]
    SigningKey(#[from] KeyError),
    #[error(transparent)]
    DataPlane(#[from] PlaneError),
    #[error(transparent)]
    Bind(#[from] BindError),
    #[error(transparent)]
    Listener(#[from] ListenerError),
}

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
        // The document is read again by launches started from elsewhere.
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
        assert_eq!(
            seeded_control_socket(
                &DaemonConfig::new("/srv/voidport/state.toml")
                    .with_control_socket("/run/flag.sock")
            )
            .expect("resolves"),
            None
        );
    }

    #[test]
    fn raising_the_descriptor_limit_never_lowers_it_and_asks_for_the_os_maximum() {
        use rustix::process::{Resource, getrlimit};

        let before = getrlimit(Resource::Nofile);
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

    #[test]
    fn the_os_maximum_is_read_from_the_kernel() {
        let maximum = os_maximum().expect("Linux publishes fs.nr_open");
        assert!(maximum >= 1024, "fs.nr_open reads as {maximum}");
    }

    #[test]
    fn a_server_nothing_named_a_socket_for_uses_the_compiled_default() {
        assert_eq!(
            control_socket(&DaemonConfig::new("state.toml"), &document(None)),
            PathBuf::from(voidport_control::DEFAULT_CONTROL_SOCKET)
        );
    }
}
