#![forbid(unsafe_code)]

use std::ffi::OsStr;
use std::fs::File;
use std::io::{Read as _, Write as _};
use std::os::fd::{AsFd as _, OwnedFd};
use std::path::Path;
use std::process::{Child, ExitStatus};
use std::sync::{Arc, Condvar, Mutex};

use rustix::pty::{OpenptFlags, ioctl_tiocgptpeer, openpt, unlockpt};
use rustix::termios::{LocalModes, Winsize, tcgetattr, tcsetwinsize};
use voidport_spawn::{Program, Stream};

pub const ENTER_ALTERNATE: &str = "\u{1b}[?1049h";
pub const LEAVE_ALTERNATE: &str = "\u{1b}[?1049l";
pub const CTRL_Z: u8 = 0x1a;

const COLUMNS: u16 = 120;
const ROWS: u16 = 40;

#[derive(Clone, Debug)]
pub struct Spawn<'a> {
    pub program: &'a OsStr,
    pub arguments: Vec<&'a OsStr>,
    pub directory: &'a Path,
    pub environment: Vec<(&'a str, &'a str)>,
}

impl<'a> Spawn<'a> {
    #[must_use]
    pub fn new(program: &'a (impl AsRef<OsStr> + ?Sized), directory: &'a Path) -> Self {
        Self {
            program: program.as_ref(),
            arguments: Vec::new(),
            directory,
            environment: Vec::new(),
        }
    }

    #[must_use]
    pub fn args<I, S>(mut self, arguments: I) -> Self
    where
        I: IntoIterator<Item = &'a S>,
        S: AsRef<OsStr> + ?Sized + 'a,
    {
        self.arguments
            .extend(arguments.into_iter().map(AsRef::as_ref));
        self
    }

    #[must_use]
    pub fn env(mut self, key: &'a str, value: &'a str) -> Self {
        self.environment.push((key, value));
        self
    }
}

pub struct Pty {
    master: OwnedFd,
    child: Child,
    writer: File,
    state: Arc<(Mutex<Screen>, Condvar)>,
    reader: Option<std::thread::JoinHandle<()>>,
}

struct Screen {
    raw: String,
    parser: vt100::Parser,
    revision: u64,
    ended: bool,
}

impl Pty {
    /// # Panics
    ///
    /// If the pty cannot be created or the program cannot be started in the
    /// working directory.
    #[must_use]
    pub fn spawn(spawn: &Spawn<'_>) -> Self {
        let flags = OpenptFlags::RDWR | OpenptFlags::NOCTTY | OpenptFlags::CLOEXEC;
        let master = openpt(flags).expect("a pty");
        unlockpt(&master).expect("the pty is unlocked");
        tcsetwinsize(
            &master,
            Winsize {
                ws_row: ROWS,
                ws_col: COLUMNS,
                ws_xpixel: 0,
                ws_ypixel: 0,
            },
        )
        .expect("the pty size is set");
        let slave = ioctl_tiocgptpeer(&master, flags).expect("the slave of the pty");

        let mut program = Program::new(spawn.program);
        program
            .args(&spawn.arguments)
            .current_dir(spawn.directory)
            .stdin(Stream::Descriptor(slave.as_fd()))
            .stdout(Stream::Descriptor(slave.as_fd()))
            .stderr(Stream::Descriptor(slave.as_fd()))
            .in_new_session_on_terminal();
        for (key, value) in &spawn.environment {
            program.env(key, value);
        }
        let child = program.spawn().unwrap_or_else(|error| {
            panic!(
                "the child {} starts in {}: {error:?}",
                spawn.program.display(),
                spawn.directory.display()
            )
        });
        // While a slave is open, the pty is alive after the child exits, and its
        // EOF is hidden.
        drop(slave);

        let state = Arc::new((
            Mutex::new(Screen {
                raw: String::new(),
                parser: vt100::Parser::new(ROWS, COLUMNS, 0),
                revision: 0,
                ended: false,
            }),
            Condvar::new(),
        ));
        let mut reader = File::from(master.try_clone().expect("a pty reader"));
        let reader = std::thread::spawn({
            let state = Arc::clone(&state);
            move || {
                let mut buffer = [0_u8; 4096];
                while let Ok(read) = reader.read(&mut buffer) {
                    if read == 0 {
                        break;
                    }
                    let mut screen = state.0.lock().expect("the screen");
                    screen
                        .raw
                        .push_str(&String::from_utf8_lossy(&buffer[..read]));
                    screen.parser.process(&buffer[..read]);
                    screen.revision += 1;
                    state.1.notify_all();
                }
                state.0.lock().expect("the screen").ended = true;
                state.1.notify_all();
            }
        });
        let writer = File::from(master.try_clone().expect("a pty writer"));
        Self {
            master,
            child,
            writer,
            state,
            reader: Some(reader),
        }
    }

    #[must_use]
    pub fn output(&self) -> String {
        self.state.0.lock().expect("the screen").raw.clone()
    }

    /// A full-screen interface places every word with a separate cursor move,
    /// so the raw output never contains a phrase contiguously. The emulator
    /// does.
    #[must_use]
    pub fn text(&self) -> String {
        self.state
            .0
            .lock()
            .expect("the screen")
            .parser
            .screen()
            .contents()
    }

    #[must_use]
    pub fn shows(&self, phrase: &str) -> bool {
        let screen = self.text();
        screen.contains(phrase) || collapsed(&screen).contains(&collapsed(phrase))
    }

    pub fn wait_for_text(&self, phrase: &str) -> bool {
        self.wait_until(|pty| pty.shows(phrase))
    }

    pub fn wait_for(&self, needle: &str) -> bool {
        self.wait_until(|pty| pty.output().contains(needle))
    }

    pub fn wait_until(&self, predicate: impl Fn(&Self) -> bool) -> bool {
        loop {
            let (revision, ended) = {
                let screen = self.state.0.lock().expect("the screen");
                (screen.revision, screen.ended)
            };
            if predicate(self) {
                return true;
            }
            if ended {
                return false;
            }
            let screen = self.state.0.lock().expect("the screen");
            drop(
                self.state
                    .1
                    .wait_while(screen, |screen| {
                        screen.revision == revision && !screen.ended
                    })
                    .expect("the screen"),
            );
        }
    }

    pub fn send(&mut self, bytes: &[u8]) {
        self.writer.write_all(bytes).expect("the pty accepts input");
        self.writer.flush().expect("the pty accepts input");
    }

    #[must_use]
    pub fn is_raw(&self) -> bool {
        !self.local_modes().contains(LocalModes::ICANON)
    }

    #[must_use]
    pub fn is_cooked(&self) -> bool {
        self.local_modes()
            .contains(LocalModes::ICANON | LocalModes::ECHO)
    }

    /// On Linux the master end reports the termios of the line.
    fn local_modes(&self) -> LocalModes {
        tcgetattr(&self.master)
            .expect("the pty has line settings")
            .local_modes
    }

    #[must_use]
    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    pub fn wait(&mut self) -> ExitStatus {
        let status = self.child.wait().expect("the child exits");
        if let Some(reader) = self.reader.take() {
            reader.join().expect("the terminal output is drained");
        }
        status
    }
}

impl std::fmt::Debug for Pty {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pty").finish_non_exhaustive()
    }
}

impl Drop for Pty {
    /// A failed assertion unwinds the test thread, and the child would outlive
    /// the test run.
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(None)) {
            let ended = self.child.kill().and_then(|()| self.child.wait());
            if let Err(error) = ended {
                eprintln!("the pty child {} is not ended: {error}", self.child.id());
            }
        }
    }
}

fn collapsed(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}
