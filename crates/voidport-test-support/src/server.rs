use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread::JoinHandle;

use voidportd::control::service::Service;
use voidportd::daemon::{Daemon, DaemonConfig, StartupError};
use voidportd::data::Transport;
use voidportd::state::Environment;

use crate::{ControlClient, until};

/// The server runs in the test process, so a test can read its descriptor table
/// through `/proc/self/fd`.
#[derive(Debug)]
pub struct RunningServer {
    socket: PathBuf,
    data_tcp: Option<SocketAddr>,
    data_unix: Option<PathBuf>,
    service: Arc<Service>,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<JoinHandle<()>>,
}

impl RunningServer {
    pub fn start(config: &DaemonConfig) -> Result<Self, StartupError> {
        let daemon = Daemon::start(config)?;
        let socket = daemon.control_socket().to_path_buf();
        let service = daemon.service();
        // The endpoints as reported by the control plane, where a configured
        // port 0 is resolved.
        let listeners = service.listeners();
        let bound = |transport: Transport| {
            listeners
                .iter()
                .find(|listener| listener.transport == transport.as_str())
                .map(|listener| listener.endpoint.as_str())
        };
        let data_tcp = bound(Transport::Tcp).map(|endpoint| {
            endpoint
                .parse()
                .expect("a tcp listener reports a socket address")
        });
        let data_unix = bound(Transport::Unix).map(PathBuf::from);
        let (shutdown, shutdown_signal) = tokio::sync::oneshot::channel();
        let thread = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("a tokio runtime");
            runtime.block_on(async move {
                daemon
                    .serve(async {
                        let _ = shutdown_signal.await;
                    })
                    .await
                    .expect("the control plane serves");
            });
        });
        Ok(Self {
            socket,
            data_tcp,
            data_unix,
            service,
            shutdown: Some(shutdown),
            thread: Some(thread),
        })
    }

    #[must_use]
    pub fn socket(&self) -> &Path {
        &self.socket
    }

    #[must_use]
    pub fn service(&self) -> &Arc<Service> {
        &self.service
    }

    #[must_use]
    pub fn data_tcp(&self) -> SocketAddr {
        self.data_tcp.expect("a tcp data listener is configured")
    }

    #[must_use]
    pub fn data_unix(&self) -> &Path {
        self.data_unix
            .as_deref()
            .expect("a unix data listener is configured")
    }

    #[must_use]
    pub fn connect(&self) -> ControlClient {
        ControlClient::connect(&self.socket).expect("the control socket accepts connections")
    }

    pub fn until(&self, condition: impl FnMut() -> bool) {
        until(
            || self.thread.as_ref().is_none_or(JoinHandle::is_finished),
            condition,
        );
    }

    pub fn signal_stop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
    }

    pub fn stop(&mut self) {
        self.signal_stop();
        if let Some(thread) = self.thread.take() {
            thread.join().expect("the server thread exits cleanly");
        }
    }
}

impl Drop for RunningServer {
    fn drop(&mut self) {
        self.stop();
    }
}

#[must_use]
pub fn daemon_config(state_file: &Path) -> DaemonConfig {
    let directory = state_file.parent().unwrap_or_else(|| Path::new("."));
    DaemonConfig::new(state_file).with_control_socket(directory.join("control.sock"))
}

/// The real invoking identity, because only the identity of the server can be
/// applied without `CAP_CHOWN`.
#[must_use]
pub fn invoking_environment(state_dir: &Path) -> Environment {
    Environment::new(
        rustix::process::getuid().as_raw(),
        rustix::process::getgid().as_raw(),
        state_dir,
    )
}

#[must_use]
pub fn open_descriptors(path: &Path) -> usize {
    let Ok(entries) = fs::read_dir("/proc/self/fd") else {
        return 0;
    };
    entries
        .filter_map(Result::ok)
        .filter(|entry| fs::read_link(entry.path()).is_ok_and(|target| target == path))
        .count()
}

/// The flags a descriptor was opened with are in `/proc/self/fdinfo`. The
/// request that asked for them cannot be read back.
#[must_use]
pub fn descriptor_flags(path: &Path) -> Vec<u32> {
    let Ok(entries) = fs::read_dir("/proc/self/fd") else {
        return Vec::new();
    };
    entries
        .filter_map(Result::ok)
        .filter(|entry| fs::read_link(entry.path()).is_ok_and(|target| target == path))
        .filter_map(|entry| {
            let info = fs::read_to_string(
                Path::new("/proc/self/fdinfo").join(entry.file_name().as_os_str()),
            )
            .ok()?;
            let flags = info.lines().find_map(|line| line.strip_prefix("flags:"))?;
            u32::from_str_radix(flags.trim(), 8).ok()
        })
        .collect()
}
