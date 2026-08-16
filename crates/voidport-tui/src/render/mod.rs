//! Drawing, from the model and from nothing else.
//!
//! Every function here takes `&Model` and a [`Rect`]. None of them mutates
//! anything, none of them talks to the server, and none of them keeps state
//! between frames — a screen is a pure function of what the model holds, which
//! is what lets every one of them be asserted against a `TestBackend` buffer
//! with no terminal in sight.
//!
//! The frame is always the same three bands — the tab bar, the body, the
//! status line — plus a connection banner when the socket is down and an
//! overlay (Help, or a dialog) on top. Below [`MIN_WIDTH`] × [`MIN_HEIGHT`]
//! nothing is drawn but the placeholder: a degraded layout that silently
//! truncates a mount command or a rule path would be worse than an honest
//! refusal.

mod logs;
mod modes;
mod namespaces;
mod overlay;
mod overview;
mod ownership;
mod rules;
mod sessions;

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph, Wrap};

use crate::model::view::View;
use crate::model::{Connection, MIN_HEIGHT, MIN_WIDTH, Model, SCREENS, Screen, Tone};

/// Draws one frame.
///
/// Whether the terminal is big enough is [`Model::fits`]'s answer, not a
/// second measurement of the frame: the size arrives as a resize event, the
/// model carries it, and everything that reasons about it reasons about the one
/// value. A frame measured here and a size carried there could disagree, and
/// then the interface would be deciding by one and describing the other.
pub fn draw(frame: &mut Frame, model: &Model) {
    let area = frame.area();
    if !model.fits() {
        frame.render_widget(too_small(model), area);
        return;
    }

    let banner = u16::from(!model.connection.is_connected());
    let [tabs, banner_area, body, status] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(banner),
        Constraint::Min(1),
        Constraint::Length(1),
    ])
    .areas(area);

    frame.render_widget(tab_bar(model), tabs);
    if banner > 0 {
        frame.render_widget(connection_banner(model), banner_area);
    }
    match model.screen {
        Screen::Overview => overview::draw(frame, model, body),
        Screen::Namespaces => namespaces::draw(frame, model, body),
        Screen::Rules => rules::draw(frame, model, body),
        Screen::Ownership => ownership::draw(frame, model, body),
        Screen::Modes => modes::draw(frame, model, body),
        Screen::Sessions => sessions::draw(frame, model, body),
        Screen::Logs => logs::draw(frame, model, body),
    }
    frame.render_widget(status_line(model), status);

    overlay::draw(frame, model, area);
}

/// The placeholder for a terminal too small to draw in.
fn too_small(model: &Model) -> Paragraph<'static> {
    Paragraph::new(vec![
        Line::from("terminal too small"),
        Line::from(format!(
            "voidport-tui needs at least {MIN_WIDTH}x{MIN_HEIGHT}"
        )),
        Line::from(format!("this one is {}x{}", model.size.0, model.size.1)),
    ])
    .wrap(Wrap { trim: true })
}

/// The tab bar: every screen, with the focused one marked.
fn tab_bar(model: &Model) -> Paragraph<'static> {
    let mut spans = vec![Span::raw("voidport ")];
    for (index, screen) in SCREENS.iter().enumerate() {
        let label = format!(" {}:{} ", index + 1, screen.title());
        spans.push(if *screen == model.screen {
            Span::styled(
                label,
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )
        } else {
            Span::raw(label)
        });
    }
    Paragraph::new(Line::from(spans))
}

/// The banner shown while the socket is down.
fn connection_banner(model: &Model) -> Paragraph<'static> {
    let text = match &model.connection {
        Connection::Connecting => "connecting to the control socket…".to_owned(),
        Connection::Connected => String::new(),
        Connection::Lost { reason, attempt } => {
            format!("disconnected: {reason} — reconnecting (attempt {attempt})")
        }
    };
    Paragraph::new(Line::from(Span::styled(
        text,
        Style::default().fg(Color::Black).bg(Color::Red),
    )))
}

/// The persistent status line: the socket, the server version, the last
/// outcome.
fn status_line(model: &Model) -> Paragraph<'static> {
    let version = model.version.clone().unwrap_or_else(|| "?".to_owned());
    let tone = match model.status.tone {
        Tone::Info => Style::default().fg(Color::Gray),
        Tone::Success => Style::default().fg(Color::Green),
        Tone::Failure => Style::default().fg(Color::Red),
        Tone::Pending => Style::default().fg(Color::Yellow),
    };
    Paragraph::new(Line::from(vec![
        Span::raw(format!("{} ", model.socket)),
        Span::raw(format!("· voidportd {version} · ")),
        Span::styled(model.status.message.clone(), tone),
        Span::raw("  (? for help)"),
    ]))
}

/// A bordered panel with a title.
fn panel(title: impl Into<String>) -> Block<'static> {
    Block::bordered().title(title.into())
}

/// Renders a view's non-ready states, so every screen says the same thing
/// about a view it has not got.
fn placeholder<T>(view: &View<T>) -> Option<Vec<Line<'static>>> {
    match view {
        View::Ready(_) => None,
        View::Idle => Some(vec![Line::from("…")]),
        View::Loading => Some(vec![Line::from("reading…")]),
        View::Failed(message) => Some(vec![
            Line::from(Span::styled(
                "cannot read this view",
                Style::default().fg(Color::Red),
            )),
            Line::from(message.clone()),
        ]),
    }
}

/// A row of a table, padded to fixed columns.
fn row(columns: &[(&str, usize)]) -> String {
    columns
        .iter()
        .map(|(text, width)| format!("{text:<width$}"))
        .collect::<Vec<_>>()
        .join(" ")
        .trim_end()
        .to_owned()
}

/// Styles a header row.
fn header(text: String) -> Line<'static> {
    Line::from(Span::styled(
        text,
        Style::default().add_modifier(Modifier::BOLD),
    ))
}

/// Styles the selected row of a list.
fn selected(text: String) -> Line<'static> {
    Line::from(Span::styled(
        text,
        Style::default().add_modifier(Modifier::REVERSED),
    ))
}

/// The filter line a list shows while one is in force.
fn filter_line(filter: Option<&str>, editing: bool) -> Option<Line<'static>> {
    let filter = filter?;
    Some(Line::from(Span::styled(
        if editing {
            format!("/{filter}_")
        } else {
            format!("/{filter}")
        },
        Style::default().fg(Color::Yellow),
    )))
}
