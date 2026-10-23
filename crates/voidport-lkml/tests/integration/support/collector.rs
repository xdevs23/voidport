use crate::corpus::temporary;
use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    fs::inotify::{self, WatchFlags},
    io::Errno,
    process::{Pid, PidfdFlags, pidfd_open},
};
use serde::Deserialize;
use serde_json::Value;
use std::{
    fs,
    os::{
        fd::OwnedFd,
        unix::fs::{MetadataExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    process::{Child, Output},
};
use voidport_lkml::{
    model::CorpusState,
    storage::{self, DataDirectory, Directory, Stored, attempt_name},
};
use voidport_spawn::Program;

pub const INTERRUPTION: &str = "acquisition interrupted by signal";
const INOTIFY_READ_BYTES: usize = 4096;

fn replaced(manifest: Option<&fs::File>, path: &Path) -> bool {
    match manifest {
        Some(file) => file.metadata().is_ok_and(|metadata| metadata.nlink() == 0),
        None => path.exists(),
    }
}

fn program(name: &str) -> PathBuf {
    std::env::split_paths(&std::env::var_os("PATH").unwrap())
        .map(|directory| directory.join(name))
        .find(|path| path.is_file())
        .unwrap_or_else(|| panic!("{name} is supplied by the development shell and Nix checks"))
}
pub struct Fixture {
    pub temp: tempfile::TempDir,
    pub output: PathBuf,
    pub client: PathBuf,
}
impl Fixture {
    pub fn new() -> Self {
        let temp = temporary();
        let client = temp.path().join("fake-lei");
        // The collector clears the environment of the client. The shebang line
        // therefore sets the id of the test process, whose end also ends every
        // wait of the fixture.
        fs::write(
            &client,
            format!(
                "#!{} -S VOIDPORT_LKML_TEST_PROCESS={} {}\n{}",
                program("env").display(),
                std::process::id(),
                program("python3").display(),
                include_str!("../fake_lei.py")
            ),
        )
        .unwrap();
        fs::set_permissions(&client, fs::Permissions::from_mode(0o700)).unwrap();
        let output = temp.path().join("corpus");
        Self {
            temp,
            output,
            client,
        }
    }
    pub fn replace_in_client(&self, original: &str, replacement: &str) {
        let script = fs::read_to_string(&self.client).unwrap();
        assert_eq!(script.matches(original).count(), 1, "{original}");
        fs::write(&self.client, script.replace(original, replacement)).unwrap();
    }
    pub fn command(&self, operation: &str) -> Program<'static> {
        let mut command = Program::new(env!("CARGO_BIN_EXE_voidport-lkml"));
        command
            .arg(operation)
            .arg("--output")
            .arg(&self.output)
            .env("VOIDPORT_LKML_LEI", &self.client)
            .env("VOIDPORT_LKML_LEI_VERSION", "fixture-1")
            .env("UNRELATED_SECRET", "must-not-reach-client");
        command
    }
    pub fn collect(&self, queries: &[&str], extra: &[&str]) -> Output {
        let mut command = self.command("collect");
        command.args(["--delay-seconds", "1"]);
        for query in queries {
            command.args(["--query", query]);
        }
        command.args(extra).output().unwrap()
    }
    pub fn state(&self) -> CorpusState {
        self.published().unwrap()
    }
    /// Returns the published generation, or None before the first
    /// publication. It reads the corpus without taking its lock, so a test
    /// can watch a running collector: a read that fails while a publication
    /// replaces the manifest is read again.
    pub fn published(&self) -> Option<CorpusState> {
        let directory = Directory::open(&self.output).ok()?;
        let path = self.output.join("manifest.json");
        loop {
            // Holding the manifest open stops its inode from being reused, so
            // a link count of zero proves a publication replaced it.
            let manifest = fs::File::open(&path).ok();
            match storage::read(&directory) {
                Ok(Stored::Missing) => return None,
                Ok(Stored::Current { state, .. }) => return Some(state),
                Ok(Stored::Version3(_)) => panic!("a corpus of format version 3"),
                Err(_) if replaced(manifest.as_ref(), &path) => {}
                Err(error) => panic!("reading the published corpus: {error}"),
            }
        }
    }
    pub fn attempt(&self, id: u64) -> PathBuf {
        self.output
            .join(DataDirectory::Attempts.name())
            .join(attempt_name(id))
    }
    pub fn status(&self) -> Value {
        let output = self.command("status").arg("--json").output().unwrap();
        success(&output);
        serde_json::from_slice(&output.stdout).unwrap()
    }
    pub fn verify(&self) {
        success(&self.command("verify").output().unwrap());
    }
}
pub fn success(output: &Output) {
    assert!(
        output.status.success(),
        "{}\n{}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
pub fn wait_file(path: &Path, child: &mut Child) {
    let directory = path.parent().unwrap();
    wait_until(child, &path.display().to_string(), &[directory], || {
        path.exists()
    });
}
fn watch_chain(changes: &OwnedFd, directory: &Path) {
    let flags = WatchFlags::CREATE | WatchFlags::DELETE | WatchFlags::MOVE;
    let mut chain: Vec<_> = directory.ancestors().collect();
    chain.reverse();
    for ancestor in chain {
        match inotify::add_watch(changes, ancestor, flags) {
            Ok(_) => {}
            Err(Errno::NOENT) => return,
            Err(error) => panic!("cannot watch {}: {error}", ancestor.display()),
        }
    }
}
pub fn wait_until(child: &mut Child, what: &str, watched: &[&Path], ready: impl Fn() -> bool) {
    let changes = inotify::init(inotify::CreateFlags::CLOEXEC).unwrap();
    let exit = pidfd_open(Pid::from_child(child), PidfdFlags::empty()).unwrap();
    let mut exited = false;
    loop {
        // Every change after the watches exist is reported, so `ready` cannot
        // miss one between its check and the wait below.
        for directory in watched {
            watch_chain(&changes, directory);
        }
        if ready() {
            return;
        }
        if exited {
            let status = child.wait().unwrap();
            panic!("collector exited with {status} before {what}");
        }
        let mut events = [
            PollFd::new(&exit, PollFlags::IN),
            PollFd::new(&changes, PollFlags::IN),
        ];
        let _revents_show_which_are_ready = poll(&mut events, None).unwrap();
        exited = events[0].revents().contains(PollFlags::IN);
        if events[1].revents().contains(PollFlags::IN) {
            let _events_only_wake_the_loop =
                rustix::io::read(&changes, &mut [0; INOTIFY_READ_BYTES]).unwrap();
        }
    }
}
pub fn release(fifo: &Path) {
    drop(fs::OpenOptions::new().write(true).open(fifo).unwrap());
}
#[derive(Deserialize)]
struct ProcessRecord {
    pid: i32,
}
pub fn pidfd_of_record(path: &Path) -> OwnedFd {
    let record: ProcessRecord = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    pidfd_open(Pid::from_raw(record.pid).unwrap(), PidfdFlags::empty()).unwrap()
}
/// Returns whether the fixture process whose id is in the record at `path` no
/// longer exists. A test calls it only right after the collector waited for
/// that process, before its id can be reused.
pub fn is_gone(path: &Path) -> bool {
    let record: ProcessRecord = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    match pidfd_open(Pid::from_raw(record.pid).unwrap(), PidfdFlags::empty()) {
        Ok(pidfd) => has_exited(&pidfd),
        Err(error) => {
            assert_eq!(error, Errno::SRCH);
            true
        }
    }
}
pub fn has_exited(pidfd: &OwnedFd) -> bool {
    let mut events = [PollFd::new(pidfd, PollFlags::IN)];
    let no_wait = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    poll(&mut events, Some(&no_wait)).unwrap() == 1
}
pub fn wait_exit(pidfd: &OwnedFd) {
    let mut events = [PollFd::new(pidfd, PollFlags::IN)];
    assert_eq!(poll(&mut events, None).unwrap(), 1);
}
pub fn json(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}
