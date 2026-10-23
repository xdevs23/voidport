use crate::{
    cli::Collect,
    mail,
    model::{self, AttemptState, Configuration, Outcome, Source, Tool},
    staging::AttemptHandle,
    storage::{Directory, Writer},
};
use attempt::run_attempt;
pub use error::{
    AcquisitionError, AttemptFailure, CleanupError, CollectError, IncompleteAttempt, IngestAborted,
    IngestFailure, MaildirFailure, ReplayError, StartError, StopError, StopReason, Stopped,
    ToolError,
};
pub use ingest::ScannedFolder;
use ingest::ingest;
use process::Process;
use rustix::{
    fs::OFlags,
    io::Errno,
    process::{Pid, PidfdFlags, Signal},
};
pub use signals::{Cancelled, UnconfirmedPublication};
use signals::{Signals, check_cancellation};
use std::{
    os::fd::AsFd,
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::{
    io::{Interest, unix::AsyncFd},
    time::{Instant, timeout_at},
};
use voidport_spawn::{Program, Stream};

mod attempt;
mod error;
mod ingest;
mod process;
mod signals;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttemptLog {
    Setup,
    Query,
    CleanupIdentify,
    Cleanup,
}
impl AttemptLog {
    fn name(self) -> &'static str {
        match self {
            Self::Setup => "setup",
            Self::Query => "query",
            Self::CleanupIdentify => "cleanup-identify",
            Self::Cleanup => "cleanup",
        }
    }
    fn stdout(self) -> String {
        format!("{}.stdout", self.name())
    }
    fn stderr(self) -> String {
        format!("{}.stderr", self.name())
    }
}

pub fn tool() -> Result<Tool, ToolError> {
    let supplied = std::env::var_os("VOIDPORT_LKML_LEI");
    let requested = supplied.unwrap_or_else(|| "lei".into());
    let candidates: Vec<PathBuf> = if Path::new(&requested).components().count() > 1 {
        vec![PathBuf::from(&requested)]
    } else {
        std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
            .map(|path| path.join(&requested))
            .collect()
    };
    let executable = candidates
        .into_iter()
        .find(|path| {
            path.is_file() && rustix::fs::access(path, rustix::fs::Access::EXEC_OK).is_ok()
        })
        .ok_or(ToolError::Missing)?;
    let version = std::env::var("VOIDPORT_LKML_LEI_VERSION")
        .ok()
        .filter(|value| !value.is_empty());
    Ok(Tool {
        executable: std::fs::canonicalize(executable)
            .map_err(ToolError::Canonicalize)?
            .to_str()
            .ok_or(ToolError::NonUtf8Path)?
            .into(),
        version_provenance: if version.is_some() {
            "supplied_package_metadata"
        } else {
            "unknown"
        }
        .into(),
        version: version.unwrap_or_else(|| "unknown".into()),
    })
}
pub fn query_arguments(source: &Source, query: &str) -> Vec<String> {
    [
        "q",
        "--threads",
        "--no-local",
        "--remote",
        "--no-save",
        "--dedupe=none",
        "--only",
        source.as_str(),
        "--output",
        "maildir:maildir",
        "--",
        query,
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}
struct Session {
    directory: Directory,
    runtime: tempfile::TempDir,
    tool: Tool,
    daemon: Option<std::os::fd::OwnedFd>,
}
impl Session {
    fn start_lei(&self, arguments: &[String], log: AttemptLog) -> Result<Process, StartError> {
        let base = self.directory.process_path();
        let create = OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL;
        let stdout = self
            .directory
            .file(log.stdout(), create)
            .map_err(StartError::Log)?;
        let stderr = self
            .directory
            .file(log.stderr(), create)
            .map_err(StartError::Log)?;
        let mut program = Program::new(&self.tool.executable);
        program.args(arguments).current_dir(&base).env_clear();
        for name in ["PATH", "SSL_CERT_FILE", "SSL_CERT_DIR", "NIX_SSL_CERT_FILE"] {
            if let Some(value) = std::env::var_os(name) {
                program.env(name, value);
            }
        }
        for (name, subdir) in [
            ("HOME", "home"),
            ("XDG_CONFIG_HOME", "config"),
            ("XDG_DATA_HOME", "data"),
            ("XDG_CACHE_HOME", "cache"),
            ("XDG_STATE_HOME", "state"),
        ] {
            program.env(name, format!("{base}/{subdir}"));
        }
        let child = program
            .env("XDG_RUNTIME_DIR", self.runtime.path())
            .env("TMPDIR", format!("{base}/temporary"))
            .stdout(Stream::Descriptor(stdout.as_fd()))
            .stderr(Stream::Descriptor(stderr.as_fd()))
            .spawn()
            .map_err(StartError::Spawn)?;
        Process::new(child).map_err(StartError::Watch)
    }
    async fn run(
        &self,
        arguments: &[String],
        log: AttemptLog,
        deadline: Instant,
        signals: &mut Signals,
    ) -> Result<std::process::ExitStatus, AcquisitionError> {
        if signals.is_cancelled() {
            return Err(AcquisitionError::Stopped(Stopped {
                reason: StopReason::Cancelled,
                failures: vec![],
            }));
        }
        let mut child = self.start_lei(arguments, log)?;
        let reason = tokio::select! {
            result = timeout_at(deadline, child.wait()) => match result {
                Ok(Ok(status)) => return Ok(status),
                Ok(Err(error)) => StopReason::Wait(error),
                Err(_elapsed) => StopReason::Timeout,
            },
            () = signals.cancelled() => StopReason::Cancelled,
        };
        let failures = [
            child.kill().err().map(StopError::Kill),
            child.wait().await.err().map(StopError::Wait),
        ]
        .into_iter()
        .flatten()
        .collect();
        Err(AcquisitionError::Stopped(Stopped { reason, failures }))
    }
    async fn start(
        &mut self,
        deadline: Instant,
        signals: &mut Signals,
    ) -> Result<(), AcquisitionError> {
        let status = self
            .run(&["daemon-pid".into()], AttemptLog::Setup, deadline, signals)
            .await?;
        if !status.success() {
            return Err(AcquisitionError::SetupFailed(status));
        }
        // The documented command returns one numeric PID, not human diagnostics.
        let bytes = self
            .directory
            .read(AttemptLog::Setup.stdout())
            .map_err(AcquisitionError::ReadPid)?;
        let number: i32 = std::str::from_utf8(&bytes)
            .map_err(AcquisitionError::DecodePid)?
            .trim()
            .parse()
            .map_err(AcquisitionError::ParsePid)?;
        let pid = Pid::from_raw(number).ok_or(AcquisitionError::InvalidPid)?;
        let daemon = rustix::process::pidfd_open(pid, PidfdFlags::empty())
            .map_err(AcquisitionError::OpenDaemon)?;
        self.daemon = Some(daemon);
        Ok(())
    }
    /// SIGKILL is enough: the daemon is started for this attempt only and writes
    /// state only to the private directories of the attempt, so a graceful
    /// shutdown would preserve nothing.
    async fn cleanup(&mut self) -> Result<(), CleanupError> {
        // Setup can end before the PID reply arrives. daemon-pid then runs only
        // inside the private client state of this attempt, and starts a daemon
        // there when none is running, which the kill below stops as well.
        if self.daemon.is_none() {
            let mut identify =
                self.start_lei(&["daemon-pid".into()], AttemptLog::CleanupIdentify)?;
            if identify
                .wait()
                .await
                .map_err(CleanupError::WaitIdentify)?
                .success()
            {
                let bytes = self
                    .directory
                    .read(AttemptLog::CleanupIdentify.stdout())
                    .map_err(CleanupError::ReadPid)?;
                if let Ok(number) = std::str::from_utf8(&bytes)
                    .unwrap_or_default()
                    .trim()
                    .parse::<i32>()
                    && let Some(pid) = Pid::from_raw(number)
                {
                    self.daemon = rustix::process::pidfd_open(pid, PidfdFlags::empty()).ok();
                }
            }
        }
        let Some(daemon) = self.daemon.as_ref() else {
            // Without a PID only the daemon itself can be asked to stop.
            let status = self
                .start_lei(
                    &["daemon-kill".into(), "--signal".into(), "KILL".into()],
                    AttemptLog::Cleanup,
                )?
                .wait()
                .await
                .map_err(CleanupError::WaitKill)?;
            if !status.success() {
                return Err(CleanupError::KillFailed(status));
            }
            return Err(CleanupError::Unidentified);
        };
        match rustix::process::pidfd_send_signal(daemon, Signal::KILL) {
            // ESRCH means that the daemon has already exited and been reaped.
            Ok(()) | Err(Errno::SRCH) => {}
            Err(error) => return Err(CleanupError::Signal(error)),
        }
        // The process descriptor becomes readable once the daemon has exited.
        AsyncFd::with_interest(daemon.as_fd(), Interest::READABLE)
            .map_err(CleanupError::Watch)?
            .readable()
            .await
            .map(|_ready_guard| ())
            .map_err(CleanupError::WaitExit)
    }
    async fn acquire(
        &mut self,
        corpus: &mut Writer,
        attempt: AttemptHandle,
        arguments: &[String],
        deadline: Instant,
        signals: &mut Signals,
    ) -> (Option<i32>, Vec<AttemptFailure>) {
        let acquisition = match self.start(deadline, signals).await {
            Ok(()) => {
                self.run(arguments, AttemptLog::Query, deadline, signals)
                    .await
            }
            Err(error) => Err(error),
        };
        let cleanup = self.cleanup().await;
        let mut failures = Vec::new();
        let mut exit_code = None;
        match acquisition {
            Ok(status) => {
                exit_code = status.code();
                if !status.success() {
                    failures.push(AttemptFailure::QueryExit(status));
                }
            }
            Err(error) => failures.push(AttemptFailure::Acquisition(error)),
        }
        if let Err(error) = cleanup {
            failures.push(AttemptFailure::Cleanup(error));
        }
        // Mail already delivered is retained even when the client exits nonzero.
        if let Err(failure) = ingest(corpus, attempt, &self.directory) {
            failures.push(AttemptFailure::Ingestion(*failure));
        }
        if signals.is_cancelled() && !failures.iter().any(AttemptFailure::is_cancellation) {
            failures.push(AttemptFailure::Cancelled);
        }
        (exit_code, failures)
    }
}

pub async fn collect(options: Collect) -> Result<(), CollectError> {
    let tool = tool()?;
    let mut signals = Signals::new().map_err(CollectError::Signals)?;
    let sources = model::sources(&if options.source.is_empty() {
        vec![model::DEFAULT_SOURCE.into()]
    } else {
        options.source.clone()
    })
    .map_err(CollectError::Sources)?;
    let queries = if options.query.is_empty() {
        vec!["f:torvalds".into()]
    } else {
        options.query.clone()
    };
    let author_values = if options.author.is_empty() {
        mail::DEFAULT_AUTHORS.iter().map(|a| (*a).into()).collect()
    } else {
        options.author.clone()
    };
    let configuration = Configuration {
        sources: sources.clone(),
        queries,
        authors: mail::authors(&author_values).map_err(CollectError::Authors)?,
    };
    let mut corpus = Writer::open(&options.output, configuration)?;
    let stored = &corpus.state().configuration;
    if !options.source.is_empty() && sources != stored.sources {
        return Err(CollectError::SourcesDiffer);
    }
    if !options.query.is_empty() && options.query != stored.queries {
        return Err(CollectError::QueriesDiffer);
    }
    if !options.author.is_empty()
        && mail::authors(&options.author).map_err(CollectError::Authors)? != stored.authors
    {
        return Err(CollectError::AuthorsDiffer);
    }
    corpus.verify()?;
    corpus.carry_over()?;
    let running = corpus.running_attempts();
    for &attempt in &running {
        let unfinished = corpus.attempt(attempt)?;
        let mut errors = unfinished.errors.clone();
        errors.push("previous invocation ended before attempt completion".into());
        let outcome = Outcome {
            state: AttemptState::Interrupted,
            exit_code: unfinished.exit_code,
            finished: model::now(),
            cleanup: "unknown after interruption; possible leftover client state; no stale PID or runtime is reused".into(),
            errors,
        };
        eprintln!(
            "unfinished attempt {}: {}; retained {}",
            unfinished.id, outcome.cleanup, unfinished.directory
        );
        corpus.record_outcome(attempt, outcome)?;
    }
    if !running.is_empty() {
        corpus.publish()?;
    }
    for unit in corpus.state().units() {
        check_cancellation(&mut corpus, &signals, None)?;
        if !options.refresh && corpus.state().complete(unit) {
            continue;
        }
        if let Some(finished) = corpus
            .state()
            .records
            .attempts
            .iter()
            .filter_map(|attempt| attempt.finished.as_ref())
            .next_back()
        {
            let elapsed = time::OffsetDateTime::now_utc()
                - model::timestamp(finished).map_err(CollectError::FinishTime)?;
            let remaining = i128::from(options.delay_seconds.get()) * 1_000_000_000
                - elapsed.whole_nanoseconds();
            if remaining > 0 {
                let delay =
                    Duration::from_nanos(u64::try_from(remaining).map_err(CollectError::Delay)?);
                tokio::select! { _ = tokio::time::sleep(delay) => {}, _ = signals.cancelled() => {} }
                check_cancellation(&mut corpus, &signals, None)?;
            }
        }
        run_attempt(&mut corpus, &mut signals, &tool, &options, unit).await?;
    }
    check_cancellation(&mut corpus, &signals, None)?;
    Ok(())
}
