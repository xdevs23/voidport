//! One process, running under a pty this crate creates.
//!
//! The terminal-lifecycle rules are only meaningful against a real terminal:
//! raw mode, the alternate screen and the restore path are all invisible to a
//! pipe. Two suites need that terminal — `voidport-tui` re-executes its own test
//! binary in one, `voidportd` runs the real daemon in one — and a pty harness
//! per suite is a harness per suite to keep correct. This is the one of them.
//!
//! It is a **workspace member of its own**, not a module of `voidportd::testing`,
//! for one blunt reason: `voidportd::testing` compiles into the product library,
//! and everything it depends on becomes a dependency of the server. A pty and a
//! terminal parser have no business in a file server.
//!
//! What a case can assert on is what an operator would have:
//!
//! * the **line settings**, read with `tcgetattr` on the master end (on Linux
//!   the master reports the line's termios, which is how raw mode is observed
//!   from outside the process under test);
//! * the **byte stream** the process writes ([`Pty::output`]), in which
//!   entering and leaving the alternate screen are explicit sequences;
//! * the **screen** those bytes produce ([`Pty::text`]), which is the readable
//!   text of the frame — a full-screen interface places every word with its own
//!   cursor move, so the raw stream never contains a phrase contiguously. That
//!   is a terminal emulator's job and it is done by one (`vt100`), not
//!   by a scanner written here.
//!
//! Nothing in this crate is a hook into any product: a case spawns a program
//! and reads a terminal.

#![deny(missing_docs)]

use std::ffi::OsStr;
use std::io::{Read as _, Write as _};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use portable_pty::{Child, CommandBuilder, ExitStatus, MasterPty, PtySize, native_pty_system};

/// What a terminal writes when it takes the alternate screen.
pub const ENTER_ALTERNATE: &str = "\u{1b}[?1049h";

/// What it writes when it gives it back.
pub const LEAVE_ALTERNATE: &str = "\u{1b}[?1049l";

/// Ctrl-Z, as the byte a terminal in raw mode delivers.
pub const CTRL_Z: u8 = 0x1a;

/// How long a pty case waits for the process to reach a state.
pub const PATIENCE: Duration = Duration::from_secs(20);

/// How wide the pty is. Wide enough that a mount command is not wrapped.
const COLUMNS: u16 = 120;

/// How tall the pty is.
const ROWS: u16 = 40;

/// How the process under a pty is started.
///
/// The working directory is **required**, and that is the whole reason this is
/// a struct, not two arguments: `portable-pty` falls back to `$HOME`
/// when a command names no directory, and a build sandbox points `$HOME` at a
/// directory that does not exist — the spawn then fails with `ENOENT` naming
/// nothing an author would connect to a home directory. Naming a directory the
/// case knows exists removes the whole class.
#[derive(Clone, Debug)]
pub struct Spawn<'a> {
    /// The program to run.
    pub program: &'a OsStr,
    /// Its arguments.
    pub arguments: Vec<&'a OsStr>,
    /// The directory to run it in. Must exist.
    pub directory: &'a Path,
    /// Environment entries to set on top of this process's own.
    pub environment: Vec<(&'a str, &'a str)>,
}

impl<'a> Spawn<'a> {
    /// A program in a directory, with no arguments and no extra environment.
    #[must_use]
    pub fn new(program: &'a (impl AsRef<OsStr> + ?Sized), directory: &'a Path) -> Self {
        Self {
            program: program.as_ref(),
            arguments: Vec::new(),
            directory,
            environment: Vec::new(),
        }
    }

    /// Adds arguments, in order.
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

    /// Adds one environment entry.
    #[must_use]
    pub fn env(mut self, key: &'a str, value: &'a str) -> Self {
        self.environment.push((key, value));
        self
    }
}

/// A process running under a pty this crate created.
pub struct Pty {
    master: Box<dyn MasterPty + Send>,
    child: Box<dyn Child + Send + Sync>,
    writer: Box<dyn std::io::Write + Send>,
    state: Arc<Mutex<Screen>>,
}

/// Everything the reader thread accumulates: the bytes, and the terminal they
/// drove.
struct Screen {
    raw: String,
    parser: vt100::Parser,
}

impl Pty {
    /// Runs one program in a fresh pty.
    ///
    /// # Panics
    ///
    /// If the pty cannot be created or the program cannot be started — both are
    /// failures of the case's own scaffolding, and a case that cannot start
    /// what it is about has nothing to report.
    #[must_use]
    pub fn spawn(spawn: &Spawn<'_>) -> Self {
        assert!(
            spawn.directory.is_dir(),
            "a pty command needs a working directory that exists: {}",
            spawn.directory.display()
        );
        let pair = native_pty_system()
            .openpty(PtySize {
                rows: ROWS,
                cols: COLUMNS,
                pixel_width: 0,
                pixel_height: 0,
            })
            .expect("a pty");

        let mut command = CommandBuilder::new(spawn.program);
        for argument in &spawn.arguments {
            command.arg(argument);
        }
        command.cwd(spawn.directory);
        for (key, value) in &spawn.environment {
            command.env(key, value);
        }
        let child = pair.slave.spawn_command(command).expect("the child starts");
        // The slave is the child's terminal now; holding it open here would
        // keep the pty alive after the child exits and hide its EOF.
        drop(pair.slave);

        let state = Arc::new(Mutex::new(Screen {
            raw: String::new(),
            parser: vt100::Parser::new(ROWS, COLUMNS, 0),
        }));
        let mut reader = pair.master.try_clone_reader().expect("a pty reader");
        std::thread::spawn({
            let state = Arc::clone(&state);
            move || {
                let mut buffer = [0_u8; 4096];
                while let Ok(read) = reader.read(&mut buffer) {
                    if read == 0 {
                        return;
                    }
                    let mut state = state.lock().expect("the screen");
                    state
                        .raw
                        .push_str(&String::from_utf8_lossy(&buffer[..read]));
                    state.parser.process(&buffer[..read]);
                }
            }
        });
        let writer = pair.master.take_writer().expect("a pty writer");
        Self {
            master: pair.master,
            child,
            writer,
            state,
        }
    }

    /// Everything the process has written to the terminal, escapes and all.
    #[must_use]
    pub fn output(&self) -> String {
        self.state.lock().expect("the screen").raw.clone()
    }

    /// The readable text of the screen as it stands, one line per row.
    ///
    /// This is the emulator's answer, not a stripped byte stream: a phrase an
    /// operator would read is a phrase on the screen, wherever the sequences
    /// that placed it were.
    #[must_use]
    pub fn text(&self) -> String {
        self.state
            .lock()
            .expect("the screen")
            .parser
            .screen()
            .contents()
    }

    /// Whether the screen shows `phrase`, ignoring how it is spread across
    /// columns and rows.
    #[must_use]
    pub fn shows(&self, phrase: &str) -> bool {
        let screen = self.text();
        screen.contains(phrase) || collapsed(&screen).contains(&collapsed(phrase))
    }

    /// Waits until the screen shows `phrase`.
    pub fn wait_for_text(&self, phrase: &str) -> bool {
        self.wait_until(|pty| pty.shows(phrase))
    }

    /// Waits until the raw output contains `needle`.
    pub fn wait_for(&self, needle: &str) -> bool {
        self.wait_until(|pty| pty.output().contains(needle))
    }

    /// Waits until `predicate` holds.
    pub fn wait_until(&self, predicate: impl Fn(&Self) -> bool) -> bool {
        let deadline = Instant::now() + PATIENCE;
        while Instant::now() < deadline {
            if predicate(self) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        predicate(self)
    }

    /// Sends bytes to the process as if typed.
    pub fn send(&mut self, bytes: &[u8]) {
        self.writer.write_all(bytes).expect("the pty accepts input");
        self.writer.flush().expect("the pty accepts input");
    }

    /// Whether the line is in raw mode — the interface has the terminal.
    #[must_use]
    pub fn is_raw(&self) -> bool {
        self.local_flags() & libc::ICANON == 0
    }

    /// Whether the line is in its ordinary cooked mode — the operator has it
    /// back.
    #[must_use]
    pub fn is_cooked(&self) -> bool {
        let flags = self.local_flags();
        flags & libc::ICANON != 0 && flags & libc::ECHO != 0
    }

    /// The line settings, read from the master end.
    ///
    /// On Linux the master reports the line's termios, so this is the child's
    /// raw mode seen from outside the child.
    fn local_flags(&self) -> libc::tcflag_t {
        self.master
            .get_termios()
            .expect("the pty has line settings")
            .local_flags
            .bits()
    }

    /// The process's id.
    #[must_use]
    pub fn pid(&self) -> u32 {
        self.child.process_id().expect("a running child")
    }

    /// Waits for the process to exit.
    pub fn wait(&mut self) -> ExitStatus {
        self.child.wait().expect("the child exits")
    }
}

impl std::fmt::Debug for Pty {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pty").finish_non_exhaustive()
    }
}

impl Drop for Pty {
    /// A failed assertion must not leave an interface running on a terminal
    /// nobody is reading any more: the case's thread is unwinding, and the
    /// child would otherwise outlive the whole test run.
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(None)) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

/// Runs of whitespace as single spaces, so a phrase can be looked for without
/// counting the columns a screen padded it with.
fn collapsed(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}
