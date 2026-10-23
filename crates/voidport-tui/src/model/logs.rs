use std::collections::VecDeque;

/// Small enough that the tail of a log nobody reads cannot grow the memory
/// without bound.
pub const RING: usize = 2000;

/// The order is the filter: the screen shows every line at or above the
/// selected level.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

pub const LEVELS: &[Level] = &[
    Level::Trace,
    Level::Debug,
    Level::Info,
    Level::Warn,
    Level::Error,
];

impl Level {
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

    #[must_use]
    pub fn next(self) -> Self {
        let index = LEVELS.iter().position(|level| *level == self).unwrap_or(0);
        LEVELS[(index + 1) % LEVELS.len()]
    }

    /// The subscriber writes `<timestamp> <LEVEL> <target>: <message>`, so only
    /// the first tokens are looked at: the word `ERROR` inside a message is not
    /// a level.
    fn of(line: &str) -> Option<Self> {
        line.split_whitespace().take(3).find_map(Self::parse)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogLine {
    pub text: String,
    pub level: Level,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Logs {
    lines: VecDeque<LogLine>,
    /// How many shown lines the bottom of the view sits above the newest one.
    /// Zero is following.
    offset: usize,
    level: Option<Level>,
    pub source: Option<String>,
    pub trouble: Option<String>,
}

impl Logs {
    #[must_use]
    pub fn level(&self) -> Level {
        self.level.unwrap_or(Level::Trace)
    }

    #[must_use]
    pub fn following(&self) -> bool {
        self.offset == 0
    }

    #[must_use]
    pub fn offset(&self) -> usize {
        self.offset
    }

    pub fn lines(&self) -> impl ExactSizeIterator<Item = &LogLine> {
        self.lines.iter()
    }

    pub fn shown(&self) -> impl Iterator<Item = &LogLine> {
        let level = self.level();
        self.lines.iter().filter(move |line| line.level >= level)
    }

    pub fn restart(&mut self, source: String) {
        self.lines.clear();
        self.offset = 0;
        self.trouble = None;
        self.source = Some(source);
    }

    /// The ring drops from the front to stay within [`RING`]. A view that is
    /// scrolled back shows the same lines, and a view that is following is at
    /// the bottom.
    pub fn append(&mut self, lines: Vec<String>) {
        let mut arrived = 0;
        for text in lines {
            let level = Level::of(&text)
                // A line that announces no level continues the record above
                // it; the first line of an empty ring has nothing to continue
                // and gets the default level of the subscriber.
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

    /// A negative `back` moves towards the newest line, and reaching it resumes
    /// following.
    pub fn scroll(&mut self, back: isize) {
        self.offset = self.offset.saturating_add_signed(back);
        self.clamp();
    }

    pub fn follow(&mut self) {
        self.offset = 0;
    }

    pub fn to_oldest(&mut self) {
        self.offset = usize::MAX;
        self.clamp();
    }

    /// The offset is in shown lines, so a filter can leave it past the end. It is
    /// clamped, not reset.
    pub fn cycle_level(&mut self) {
        self.level = Some(self.level().next());
        self.clamp();
    }

    #[must_use]
    pub fn window(&self, height: usize) -> Vec<&LogLine> {
        let shown: Vec<&LogLine> = self.shown().collect();
        let end = shown.len().saturating_sub(self.offset);
        let start = end.saturating_sub(height);
        shown[start..end].to_vec()
    }

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

        let mut orphan = Logs::default();
        orphan.append(vec!["a line from the middle of a record".to_owned()]);
        assert_eq!(orphan.lines().next().expect("a line").level, Level::Info);

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

        logs.append(vec![record("INFO", "4"), record("INFO", "5")]);
        assert_eq!(logs.window(1)[0].text, record("INFO", "2"));
        assert_eq!(logs.offset(), 3);

        logs.follow();
        assert!(logs.following());
        assert_eq!(logs.window(1)[0].text, record("INFO", "5"));

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
