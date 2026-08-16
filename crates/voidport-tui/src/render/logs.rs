//! The tail of the server's log file.
//!
//! Two lines of preamble and then the window the model holds: where the file
//! is, how the view is positioned in it, and what the tail last managed to
//! read. The preamble is not decoration — an empty log screen has to say
//! *why* it is empty, and the three reasons (no file named, a file that cannot
//! be read, a file with nothing in it yet) are three different facts about the
//! server.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use super::{panel, placeholder};
use crate::model::Model;
use crate::model::logs::Level;

/// Draws the log tail.
pub(super) fn draw(frame: &mut Frame, model: &Model, area: Rect) {
    let mut lines = placeholder(&model.server).unwrap_or_default();
    let path = model.log_file();
    if model.server.ready().is_some() {
        lines.push(source_line(model, path));
        lines.push(position_line(model));
    }

    // The borders, and whatever the preamble took.
    let height = usize::from(area.height).saturating_sub(2 + lines.len());
    let window = model.logs.window(height);
    if window.is_empty() && path.is_some() && model.logs.trouble.is_none() {
        lines.push(Line::from("  nothing has been logged yet"));
    }
    lines.extend(
        window
            .into_iter()
            .map(|line| Line::from(Span::styled(line.text.clone(), style(line.level)))),
    );

    frame.render_widget(
        Paragraph::new(lines).block(panel(" Logs — the server's own tracing ")),
        area,
    );
}

/// Where the lines come from, or the honest reason there are none.
///
/// A path that cannot be read is **named**, not worked around: an attach to a
/// server on another machine, or one whose log file is not this user's to read,
/// reads its logs elsewhere, and the only useful thing this screen can do is
/// say where.
fn source_line(model: &Model, path: Option<&str>) -> Line<'static> {
    let Some(path) = path else {
        return Line::from(Span::styled(
            "this server names no log file: it writes its tracing to its own stderr".to_owned(),
            Style::default().fg(Color::Yellow),
        ));
    };
    match &model.logs.trouble {
        Some(trouble) => Line::from(Span::styled(
            format!("cannot read {path}: {trouble}"),
            Style::default().fg(Color::Red),
        )),
        None => Line::from(format!("tailing {path}")),
    }
}

/// How the view sits in the file, and what it is filtering out.
fn position_line(model: &Model) -> Line<'static> {
    let position = if model.logs.following() {
        "following".to_owned()
    } else {
        format!("{} lines back (f: follow)", model.logs.offset())
    };
    Line::from(Span::styled(
        format!(
            "{position} · level >= {} (l: cycle) · {} of {} lines",
            model.logs.level().label(),
            model.logs.shown().count(),
            model.logs.lines().len(),
        ),
        Style::default().fg(Color::Gray),
    ))
}

/// How loud a line reads.
fn style(level: Level) -> Style {
    match level {
        Level::Error => Style::default().fg(Color::Red),
        Level::Warn => Style::default().fg(Color::Yellow),
        Level::Info => Style::default(),
        Level::Debug | Level::Trace => Style::default().fg(Color::DarkGray),
    }
}
