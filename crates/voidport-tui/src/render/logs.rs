use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use super::{panel, placeholder};
use crate::model::Model;
use crate::model::logs::Level;

pub(super) fn draw(frame: &mut Frame, model: &Model, area: Rect) {
    let mut lines = placeholder(&model.server).unwrap_or_default();
    let path = model.log_file();
    if model.server.ready().is_some() {
        lines.push(source_line(model, path));
        lines.push(position_line(model));
    }

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

/// A path that cannot be read is shown, not worked around: for an attach to
/// another machine the logs are elsewhere, and the only useful thing to do is
/// to show where.
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

fn style(level: Level) -> Style {
    match level {
        Level::Error => Style::default().fg(Color::Red),
        Level::Warn => Style::default().fg(Color::Yellow),
        Level::Info => Style::default(),
        Level::Debug | Level::Trace => Style::default().fg(Color::DarkGray),
    }
}
