//! Taking the terminal over, and giving it back.
//!
//! Raw mode changes what may be assumed, so every consequence is handled in
//! one place:
//!
//! * **Restore on every exit path.** [`Terminal`] restores on drop, and a
//!   panic hook restores before the panic message is printed — a terminal left
//!   in raw mode with the alternate screen up is unusable, and the operator
//!   would have no way to read the panic that caused it.
//! * **Ctrl-C is a key, not a signal.** In raw mode the terminal does not
//!   generate SIGINT, so the reducer binds Ctrl-C to quit like any other key.
//! * **Ctrl-Z suspends properly.** [`Terminal::suspend`] gives the terminal
//!   back, raises `SIGTSTP` on this process so the shell really gets it, and
//!   on resume re-enters raw mode and redraws from scratch.
//! * **Resize redraws.** Crossterm reports resizes as events; the model
//!   carries the size, and below the minimum the interface draws a
//!   placeholder, not a mangled layout.
//!
//! Input is pumped by [`Input`], a thread that polls in short slices so that
//! stopping is prompt.

use std::io::{self, Stdout, Write, stdout};
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::thread::JoinHandle;
use std::time::Duration;

use crossterm::cursor::{Hide, Show};
use crossterm::event::{self as terminal_event, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::backend::CrosstermBackend;

use crate::event::Event;
use crate::model::Model;
use crate::render;

/// How long the input thread waits for a key before checking whether it should
/// stop.
const POLL: Duration = Duration::from_millis(50);

/// The terminal, taken over for the interface's lifetime.
#[derive(Debug)]
pub struct Terminal {
    inner: ratatui::Terminal<CrosstermBackend<Stdout>>,
    /// Whether the terminal is currently in raw mode with the alternate screen
    /// up. Restoring twice is harmless but pointless; suspending flips it.
    taken: bool,
}

impl Terminal {
    /// Takes the terminal over.
    ///
    /// # Errors
    ///
    /// Propagates the failure of raw mode or of the alternate screen. Nothing
    /// is left half-taken: the caller can report plainly and exit.
    pub fn acquire() -> io::Result<Self> {
        install_panic_hook();
        // Everything fallible that does *not* change the terminal happens
        // first. A fullscreen ratatui terminal only asks for the size, so a
        // failure here leaves the operator's terminal untouched — and the
        // takeover below is the last step, with no fallible one after it that
        // could return while the terminal is raw.
        let inner = ratatui::Terminal::new(CrosstermBackend::new(stdout()))?;
        enable()?;
        Ok(Self { inner, taken: true })
    }

    /// The terminal's current size, in columns and rows.
    ///
    /// # Errors
    ///
    /// Propagates the failure to ask.
    pub fn size(&self) -> io::Result<(u16, u16)> {
        let size = self.inner.size()?;
        Ok((size.width, size.height))
    }

    /// Draws one frame from the model.
    ///
    /// # Errors
    ///
    /// Propagates a write failure to the terminal.
    pub fn draw(&mut self, model: &Model) -> io::Result<()> {
        self.inner.draw(|frame| render::draw(frame, model))?;
        Ok(())
    }

    /// Suspends: restore, stop, and come back with a full redraw.
    ///
    /// # Errors
    ///
    /// Propagates a terminal failure on the way out or the way back in.
    pub fn suspend(&mut self, model: &Model) -> io::Result<()> {
        self.restore()?;
        // The default disposition is what an operator's shell expects; raising
        // it on ourselves is what makes Ctrl-Z in raw mode behave like Ctrl-Z
        // anywhere else.
        rustix::process::kill_process(rustix::process::getpid(), rustix::process::Signal::TSTP)
            .map_err(io::Error::from)?;
        // Reached on SIGCONT.
        enable()?;
        self.taken = true;
        // A fresh terminal instead of `clear()`: ratatui's clear preserves the
        // cursor by *asking* the terminal where it is, and that answer would be
        // read by the input thread, not by the query. Starting over has
        // the effect that matters here anyway — an empty previous buffer, so
        // the next draw writes the whole screen.
        self.inner = ratatui::Terminal::new(CrosstermBackend::new(stdout()))?;
        self.draw(model)
    }

    /// Gives the terminal back.
    ///
    /// # Errors
    ///
    /// Propagates the failure to leave raw mode or the alternate screen.
    pub fn restore(&mut self) -> io::Result<()> {
        if !self.taken {
            return Ok(());
        }
        self.taken = false;
        restore_terminal()
    }
}

impl Drop for Terminal {
    /// The last line of defence: whatever happened, the operator gets their
    /// terminal back.
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

/// Enters raw mode with the alternate screen and no cursor.
///
/// All or nothing: raw mode is entered first, and if the alternate screen or
/// the cursor cannot be written the terminal is given straight back before the
/// failure is returned. Otherwise a caller that reports and exits — there is no
/// [`Terminal`] to drop yet — would leave the operator in a raw terminal with
/// no interface in it.
fn enable() -> io::Result<()> {
    enable_raw_mode()?;
    execute!(stdout(), EnterAlternateScreen, Hide).inspect_err(|_| {
        let _ = restore_terminal();
    })
}

/// Leaves raw mode and the alternate screen, cursor shown.
fn restore_terminal() -> io::Result<()> {
    let mut out = stdout();
    let _ = execute!(out, LeaveAlternateScreen, Show);
    let result = disable_raw_mode();
    let _ = out.flush();
    result
}

/// Installs the panic hook once per process.
fn install_panic_hook() {
    static INSTALLED: OnceLock<()> = OnceLock::new();
    INSTALLED.get_or_init(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            // Restore first: the panic message is about to be printed, and it
            // has to be readable.
            let _ = restore_terminal();
            previous(info);
        }));
    });
}

/// The thread that turns terminal input into events.
#[derive(Debug)]
pub struct Input {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Input {
    /// Starts pumping input into `events`.
    #[must_use]
    pub fn spawn(events: Sender<Event>) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let thread = std::thread::spawn({
            let stop = Arc::clone(&stop);
            move || pump(&events, &stop)
        });
        Self {
            stop,
            thread: Some(thread),
        }
    }

    /// Stops pumping and waits for the thread.
    pub fn stop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for Input {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Reads terminal events until asked to stop.
fn pump(events: &Sender<Event>, stop: &AtomicBool) {
    while !stop.load(Ordering::Relaxed) {
        match terminal_event::poll(POLL) {
            Ok(false) => continue,
            Ok(true) => {}
            Err(_) => return,
        }
        let event = match terminal_event::read() {
            Ok(event) => event,
            Err(_) => return,
        };
        let translated = match event {
            // Release events reach us only where the terminal supports the
            // kitty protocol; acting on them would double every keystroke.
            terminal_event::Event::Key(key)
                if matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat) =>
            {
                Some(Event::Key(key))
            }
            terminal_event::Event::Resize(width, height) => Some(Event::Resize { width, height }),
            _ => None,
        };
        if let Some(event) = translated
            && events.send(event).is_err()
        {
            return;
        }
    }
}
