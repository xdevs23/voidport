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

/// The size comes from [`Model::fits`], the value in the resize
/// event, and not from a second measurement of the frame.
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

fn panel(title: impl Into<String>) -> Block<'static> {
    Block::bordered().title(title.into())
}

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

fn row(columns: &[(&str, usize)]) -> String {
    columns
        .iter()
        .map(|(text, width)| format!("{text:<width$}"))
        .collect::<Vec<_>>()
        .join(" ")
        .trim_end()
        .to_owned()
}

fn header(text: String) -> Line<'static> {
    Line::from(Span::styled(
        text,
        Style::default().add_modifier(Modifier::BOLD),
    ))
}

fn selected(text: String) -> Line<'static> {
    Line::from(Span::styled(
        text,
        Style::default().add_modifier(Modifier::REVERSED),
    ))
}

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
