//! The tail of the server's log file, as the Logs screen holds it.
//!
//! The screen is a window onto a file that only ever grows, so the model holds
//! a **bounded** piece of it: the last [`RING`] lines, newest last. Nothing
//! here reads a file — the reading happens at the edge ([`crate::tail`]) and
//! arrives as an event, exactly like a server reply does, so every rule below
//! is a reducer test.
//!
//! Two things are deliberately *not* separate state. Following is not a flag
//! beside the scroll position but the position itself: the view sits
//! [`Logs::offset`] lines above the newest one, and following is that offset
//! being zero. A flag would allow "following, and 40 lines up", which is not a
//! state the screen can draw. And the level of a line is decided once, when it
//! arrives, not at every frame: a continuation line — a panic
//! backtrace, a multi-line message — carries no level of its own and belongs
//! to the record above it, which is only knowable in arrival order.

use std::collections::VecDeque;

/// How many lines the screen keeps.
///
/// Thousands, not millions: enough that scrolling back reaches what an
/// operator was just told about, small enough that the tail of a log nobody is
/// reading cannot grow the interface's memory without bound.
pub const RING: usize = 2000;

/// A tracing level, ordered from least to most severe.
///
/// The order is the filter: the screen shows every line at or above the
/// selected level, which is what `RUST_LOG` means by a level and therefore
/// what an operator already expects it to mean.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    /// `TRACE`.
    Trace,
    /// `DEBUG`.
    Debug,
    /// `INFO`.
    Info,
    /// `WARN`.
    Warn,
    /// `ERROR`.
    Error,
}

/// Every level, least severe first — the order the filter cycles in.
pub const LEVELS: &[Level] = &[
    Level::Trace,
    Level::Debug,
    Level::Info,
    Level::Warn,
    Level::Error,
];

impl Level {
    /// How the filter names the level.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Trace => "trace",
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
        }
    }

    /// The level a token names, if it names one.
    fn parse(token: &str) -> Option<Self> {
        match token {
            "TRACE" => Some(Self::Trace),
            "DEBUG" => Some(Self::Debug),
            "INFO" => Some(Self::Info),
            "WARN" => Some(Self::Warn),
            "ERROR" => Some(Self::Error),
            _ => None,
        }
    }

    /// The next level, wrapping back to the least severe.
    #[must_use]
    pub fn next(self) -> Self {
        let index = LEVELS.iter().position(|level| *level == self).unwrap_or(0);
        LEVELS[(index + 1) % LEVELS.len()]
    }

    /// The level a fresh record announces, if it announces one.
    ///
    /// The subscriber writes `<timestamp> <LEVEL> <target>: <message>`, so the
    /// level is one of the first tokens; only those are looked at, because the
    /// word `ERROR` inside somebody's message is not a level.
    fn of(line: &str) -> Option<Self> {
        line.split_whitespace().take(3).find_map(Self::parse)
    }
}

/// One line of the log, classified once.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogLine {
    /// The line as the file holds it, without its newline.
    pub text: String,
    /// The level it belongs to.
    pub level: Level,
}

/// The tail of one log file.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Logs {
    /// The last [`RING`] lines, newest last.
    lines: VecDeque<LogLine>,
    /// How many shown lines the bottom of the view sits above the newest one.
    /// Zero is following.
    offset: usize,
    /// The least severe level shown.
    level: Option<Level>,
    /// The file the lines came from, so a change of file is not silently a
    /// continuation of a different server's history.
    pub source: Option<String>,
    /// Why the last read produced nothing, in the reader's own words.
    pub trouble: Option<String>,
}

impl Logs {
    /// The least severe level the screen shows.
    #[must_use]
    pub fn level(&self) -> Level {
        self.level.unwrap_or(Level::Trace)
    }

    /// Whether the view is pinned to the newest line.
    #[must_use]
    pub fn following(&self) -> bool {
        self.offset == 0
    }

    /// How many lines the view is above the newest one.
    #[must_use]
    pub fn offset(&self) -> usize {
        self.offset
    }

    /// Every line the ring holds, oldest first, filter ignored.
    pub fn lines(&self) -> impl ExactSizeIterator<Item = &LogLine> {
        self.lines.iter()
    }

    /// The lines the level filter shows, oldest first.
    pub fn shown(&self) -> impl Iterator<Item = &LogLine> {
        let level = self.level();
        self.lines.iter().filter(move |line| line.level >= level)
    }

    /// Starts following a different file: the lines the ring holds described
    /// the old one and describe nothing now.
    pub fn restart(&mut self, source: String) {
        self.lines.clear();
        self.offset = 0;
        self.trouble = None;
        self.source = Some(source);
    }

    /// Takes the lines a read produced, oldest first.
    ///
    /// The ring drops from the front to stay within [`RING`]. A view that is
    /// scrolled back keeps looking at the same lines, so its distance from the
    /// newest one grows by what arrived; a view that is following stays at the
    /// bottom, which is the whole point of following.
    pub fn append(&mut self, lines: Vec<String>) {
        let mut arrived = 0;
        for text in lines {
            let level = Level::of(&text)
                // A line that announces no level continues the record above
                // it; the first line of an empty ring has nothing to continue
                // and is taken at the subscriber's own default.
                .or_else(|| self.lines.back().map(|line| line.level))
                .unwrap_or(Level::Info);
            if level >= self.level() {
                arrived += 1;
            }
            self.lines.push_back(LogLine { text, level });
            if self.lines.len() > RING {
                self.lines.pop_front();
            }
        }
        if !self.following() {
            self.offset += arrived;
        }
        self.clamp();
    }

    /// Scrolls `back` lines towards the oldest; a negative `back` moves
    /// towards the newest, and reaching it resumes following.
    pub fn scroll(&mut self, back: isize) {
        self.offset = self.offset.saturating_add_signed(back);
        self.clamp();
    }

    /// Pins the view to the newest line again.
    pub fn follow(&mut self) {
        self.offset = 0;
    }

    /// Scrolls to the oldest line the ring still holds.
    pub fn to_oldest(&mut self) {
        self.offset = usize::MAX;
        self.clamp();
    }

    /// Shows the next level up, wrapping.
    ///
    /// The offset is in shown lines, so a filter that hides lines can leave it
    /// past the end; it is clamped, not reset, so cycling through the
    /// levels and back leaves the operator roughly where they were.
    pub fn cycle_level(&mut self) {
        self.level = Some(self.level().next());
        self.clamp();
    }

    /// The lines to draw in a view `height` rows tall, oldest first.
    #[must_use]
    pub fn window(&self, height: usize) -> Vec<&LogLine> {
        let shown: Vec<&LogLine> = self.shown().collect();
        let end = shown.len().saturating_sub(self.offset);
        let start = end.saturating_sub(height);
        shown[start..end].to_vec()
    }

    /// Keeps the view over a line that exists.
    fn clamp(&mut self) {
        let last = self.shown().count().saturating_sub(1);
        self.offset = self.offset.min(last);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(level: &str, message: &str) -> String {
        format!("2026-08-16T10:11:12.345678Z {level} voidportd: {message}")
    }

    fn logs(records: &[(&str, &str)]) -> Logs {
        let mut logs = Logs::default();
        logs.append(
            records
                .iter()
                .map(|(level, message)| record(level, message))
                .collect(),
        );
        logs
    }

    #[test]
    fn the_ring_is_bounded_and_drops_the_oldest_first() {
        let mut logs = Logs::default();
        logs.append(
            (0..RING + 500)
                .map(|n| record("INFO", &n.to_string()))
                .collect(),
        );
        assert_eq!(logs.lines().len(), RING, "the ring grew past its bound");
        assert!(
            logs.lines().next().expect("a line").text.ends_with(" 500"),
            "the oldest lines were not the ones dropped"
        );
        assert!(
            logs.lines()
                .last()
                .expect("a line")
                .text
                .ends_with(&format!(" {}", RING + 499))
        );

        // And it stays bounded however many reads it takes to get there.
        for _ in 0..10 {
            logs.append(vec![record("INFO", "more")]);
            assert_eq!(logs.lines().len(), RING);
        }
    }

    #[test]
    fn a_line_is_classified_once_and_a_continuation_joins_the_record_above_it() {
        let mut logs = logs(&[("ERROR", "the mount failed")]);
        logs.append(vec!["    at src/main.rs:12".to_owned()]);
        let levels: Vec<Level> = logs.lines().map(|line| line.level).collect();
        assert_eq!(levels, vec![Level::Error, Level::Error]);

        // A first line with nothing above it is taken at the subscriber's own
        // default instead of invented as something louder.
        let mut orphan = Logs::default();
        orphan.append(vec!["a line from the middle of a record".to_owned()]);
        assert_eq!(orphan.lines().next().expect("a line").level, Level::Info);

        // The word is only a level where a level goes.
        let mut message = Logs::default();
        message.append(vec![record("INFO", "an ERROR is not a level here")]);
        assert_eq!(message.lines().next().expect("a line").level, Level::Info);
    }

    #[test]
    fn the_level_filter_shows_exactly_the_selected_levels() {
        let mut logs = logs(&[
            ("TRACE", "t"),
            ("DEBUG", "d"),
            ("INFO", "i"),
            ("WARN", "w"),
            ("ERROR", "e"),
        ]);
        assert_eq!(logs.level(), Level::Trace);
        assert_eq!(logs.shown().count(), 5);

        for (level, count) in [
            (Level::Debug, 4),
            (Level::Info, 3),
            (Level::Warn, 2),
            (Level::Error, 1),
            (Level::Trace, 5),
        ] {
            logs.cycle_level();
            assert_eq!(logs.level(), level);
            assert_eq!(logs.shown().count(), count, "at {}", level.label());
            assert!(
                logs.shown().all(|line| line.level >= level),
                "a line below {} is shown",
                level.label()
            );
        }
    }

    #[test]
    fn following_is_the_scroll_position_and_scrollback_holds_still() {
        let mut logs = logs(&[("INFO", "1"), ("INFO", "2"), ("INFO", "3")]);
        assert!(logs.following());
        assert_eq!(
            logs.window(2)
                .iter()
                .map(|line| line.text.clone())
                .collect::<Vec<_>>(),
            vec![record("INFO", "2"), record("INFO", "3")]
        );

        logs.scroll(1);
        assert!(!logs.following());
        assert_eq!(logs.window(1)[0].text, record("INFO", "2"));

        // New lines do not drag a scrolled-back view along.
        logs.append(vec![record("INFO", "4"), record("INFO", "5")]);
        assert_eq!(logs.window(1)[0].text, record("INFO", "2"));
        assert_eq!(logs.offset(), 3);

        logs.follow();
        assert!(logs.following());
        assert_eq!(logs.window(1)[0].text, record("INFO", "5"));

        // Neither end can be scrolled past.
        logs.to_oldest();
        assert_eq!(logs.window(1)[0].text, record("INFO", "1"));
        logs.scroll(100);
        assert_eq!(logs.window(1)[0].text, record("INFO", "1"));
        logs.scroll(-100);
        assert!(logs.following());
    }

    #[test]
    fn a_different_file_is_not_a_continuation_of_the_old_one() {
        let mut logs = logs(&[("INFO", "the old server")]);
        logs.trouble = Some("gone".to_owned());
        logs.restart("/srv/other.log".to_owned());
        assert_eq!(logs.lines().len(), 0);
        assert_eq!(logs.trouble, None);
        assert_eq!(logs.source.as_deref(), Some("/srv/other.log"));
    }
}
