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

const POLL: Duration = Duration::from_millis(50);

#[derive(Debug)]
pub struct Terminal {
    inner: ratatui::Terminal<CrosstermBackend<Stdout>>,
    taken: bool,
}

impl Terminal {
    /// Nothing is left half-taken when this fails.
    pub fn acquire() -> io::Result<Self> {
        install_panic_hook();
        // The takeover below is the last step. A failure before it leaves the
        // terminal untouched, and no fallible step follows it that could return
        // while the terminal is raw.
        let inner = ratatui::Terminal::new(CrosstermBackend::new(stdout()))?;
        enable()?;
        Ok(Self { inner, taken: true })
    }

    pub fn size(&self) -> io::Result<(u16, u16)> {
        let size = self.inner.size()?;
        Ok((size.width, size.height))
    }

    pub fn draw(&mut self, model: &Model) -> io::Result<()> {
        self.inner.draw(|frame| render::draw(frame, model))?;
        Ok(())
    }

    pub fn suspend(&mut self, model: &Model) -> io::Result<()> {
        self.restore()?;
        // Raising the signal on this process makes Ctrl-Z in raw mode behave like
        // Ctrl-Z anywhere else.
        rustix::process::kill_process(rustix::process::getpid(), rustix::process::Signal::TSTP)
            .map_err(io::Error::from)?;
        enable()?;
        self.taken = true;
        // A fresh terminal instead of `clear()`: ratatui's clear asks the terminal
        // where the cursor is, and the input thread would read that answer.
        self.inner = ratatui::Terminal::new(CrosstermBackend::new(stdout()))?;
        self.draw(model)
    }

    pub fn restore(&mut self) -> io::Result<()> {
        if !self.taken {
            return Ok(());
        }
        self.taken = false;
        restore_terminal()
    }
}

impl Drop for Terminal {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

/// If the alternate screen or the cursor cannot be written, raw mode is left
/// again before the failure is returned, because no [`Terminal`] exists yet
/// to restore it on drop.
fn enable() -> io::Result<()> {
    enable_raw_mode()?;
    execute!(stdout(), EnterAlternateScreen, Hide).inspect_err(|_| {
        let _ = restore_terminal();
    })
}

fn restore_terminal() -> io::Result<()> {
    let mut out = stdout();
    let _ = execute!(out, LeaveAlternateScreen, Show);
    let result = disable_raw_mode();
    let _ = out.flush();
    result
}

fn install_panic_hook() {
    static INSTALLED: OnceLock<()> = OnceLock::new();
    INSTALLED.get_or_init(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            // The panic message is printed next and must be readable.
            let _ = restore_terminal();
            previous(info);
        }));
    });
}

#[derive(Debug)]
pub struct Input {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Input {
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
