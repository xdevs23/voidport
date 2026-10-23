pub mod form;
pub mod list;
pub mod logs;
pub mod view;

use voidport_control::{
    ListenerInfo, NamespaceName, NamespaceSpec, NamespaceSummary, Rule, SessionSummary,
};

pub use form::{Form, FormKind};
pub use list::{Reconciled, Selection};
pub use logs::Logs;
pub use view::View;

use crate::event::Correlation;

pub const MIN_WIDTH: u16 = 64;

pub const MIN_HEIGHT: u16 = 16;

pub const SCREENS: &[Screen] = &[
    Screen::Overview,
    Screen::Namespaces,
    Screen::Rules,
    Screen::Ownership,
    Screen::Modes,
    Screen::Sessions,
    Screen::Logs,
];

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Screen {
    #[default]
    Overview,
    Namespaces,
    Rules,
    Ownership,
    Modes,
    Sessions,
    Logs,
}

impl Screen {
    #[must_use]
    pub fn title(self) -> &'static str {
        match self {
            Self::Overview => "Overview",
            Self::Namespaces => "Namespaces",
            Self::Rules => "Rules",
            Self::Ownership => "Ownership",
            Self::Modes => "Permission/Auth",
            Self::Sessions => "Sessions",
            Self::Logs => "Logs",
        }
    }

    #[must_use]
    pub fn is_list(self) -> bool {
        matches!(self, Self::Namespaces | Self::Rules | Self::Sessions)
    }

    #[must_use]
    pub fn step(self, forward: bool) -> Self {
        let index = SCREENS
            .iter()
            .position(|screen| *screen == self)
            .unwrap_or(0);
        let len = SCREENS.len();
        SCREENS[if forward {
            (index + 1) % len
        } else {
            (index + len - 1) % len
        }]
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Attach,
    Serving,
}

/// The daemon derives this from its launch summary and hands it over already
/// worded, because the daemon crate depends on this one and a mount URL is
/// the grammar of the daemon.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LaunchNotes {
    pub namespace: String,
    pub mounts: Vec<String>,
    pub control_command: String,
    pub auth_note: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Connection {
    Connecting,
    Connected,
    Lost { reason: String, attempt: u32 },
}

impl Connection {
    #[must_use]
    pub fn is_connected(&self) -> bool {
        matches!(self, Self::Connected)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Tone {
    #[default]
    Info,
    Success,
    Failure,
    Pending,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Status {
    pub message: String,
    pub tone: Tone,
}

impl Status {
    fn new(tone: Tone, message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            tone,
        }
    }

    #[must_use]
    pub fn info(message: impl Into<String>) -> Self {
        Self::new(Tone::Info, message)
    }

    #[must_use]
    pub fn success(message: impl Into<String>) -> Self {
        Self::new(Tone::Success, message)
    }

    #[must_use]
    pub fn failure(message: impl Into<String>) -> Self {
        Self::new(Tone::Failure, message)
    }

    #[must_use]
    pub fn pending(message: impl Into<String>) -> Self {
        Self::new(Tone::Pending, message)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pending {
    pub correlation: Correlation,
    pub description: String,
    pub origin: Screen,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Confirm {
    pub prompt: String,
    pub description: String,
    pub request: voidport_control::Request,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Dialog {
    Form(Form),
    Confirm(Confirm),
}

/// The values are edited locally and applied whole. They are re-synced from
/// the namespace of the server whenever a different namespace comes into
/// focus.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Modes {
    pub row: usize,
    pub permission: String,
    pub auth: String,
    pub namespace: Option<NamespaceName>,
    /// Without it a mode changed by another operator would refresh the server
    /// column while "TO APPLY" shows a value nobody chose, and Enter would
    /// apply it. An untouched buffer follows the server, and a touched one is
    /// left alone until it is applied or the subject changes.
    pub edited: bool,
}

impl Modes {
    /// A different namespace always resyncs. The same namespace resyncs only
    /// while the buffer is the value of the server.
    fn sync(&mut self, spec: &NamespaceSpec) {
        if self.namespace.as_ref() != Some(&spec.name) {
            self.namespace = Some(spec.name.clone());
            self.edited = false;
        }
        if !self.edited {
            self.permission = spec.permission.to_string();
            self.auth = spec.auth.to_string();
        }
    }

    pub(crate) fn edit(&mut self) {
        self.edited = true;
    }

    pub(crate) fn applied(&mut self) {
        self.edited = false;
    }
}

#[derive(Clone, Debug)]
pub struct Model {
    pub screen: Screen,
    pub help: bool,
    /// The offset lives here because rendering is a pure function of the model
    /// and keeps nothing between frames.
    pub help_scroll: usize,
    pub finished: bool,
    pub mode: Mode,
    pub socket: String,
    pub notes: Option<LaunchNotes>,
    pub connection: Connection,
    pub version: Option<String>,
    pub status: Status,
    pub size: (u16, u16),
    pub server: View<ServerFacts>,
    pub namespaces: View<Vec<NamespaceSummary>>,
    pub namespace_selection: Selection,
    pub namespace: View<NamespaceSpec>,
    pub rule_selection: Selection,
    pub modes: Modes,
    pub sessions: View<Vec<SessionSummary>>,
    pub session_selection: Selection,
    /// Not a [`View`]: it accumulates the pieces of a file read by this process
    /// instead of replacing one answer of the server.
    pub logs: Logs,
    pub dialog: Option<Dialog>,
    pub pending: Option<Pending>,
    pub next_correlation: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerFacts {
    pub version: String,
    pub state_file: String,
    pub control_socket: String,
    pub namespaces: usize,
    pub listeners: Vec<ListenerInfo>,
    /// The path on the server, not on this process: the Logs screen tails it
    /// where the two share a filesystem and shows it where they do not.
    pub log_file: Option<String>,
}

impl Model {
    #[must_use]
    pub fn new(mode: Mode, socket: impl Into<String>, notes: Option<LaunchNotes>) -> Self {
        Self {
            screen: Screen::default(),
            help: false,
            help_scroll: 0,
            finished: false,
            mode,
            socket: socket.into(),
            notes,
            connection: Connection::Connecting,
            version: None,
            status: Status::info("connecting"),
            size: (MIN_WIDTH, MIN_HEIGHT),
            server: View::Idle,
            namespaces: View::Idle,
            namespace_selection: Selection::default(),
            namespace: View::Idle,
            rule_selection: Selection::default(),
            modes: Modes::default(),
            sessions: View::Idle,
            session_selection: Selection::default(),
            logs: Logs::default(),
            dialog: None,
            pending: None,
            next_correlation: 1,
        }
    }

    /// [`render`](crate::render) asks this instead of measuring the frame, so the
    /// size that is reasoned about and the size decided by are the same value.
    #[must_use]
    pub fn fits(&self) -> bool {
        self.size.0 >= MIN_WIDTH && self.size.1 >= MIN_HEIGHT
    }

    /// The bound is [`keys::help_rows`](crate::keys::help_rows) less one, so the
    /// last binding can be reached and the overlay is never scrolled into
    /// emptiness.
    pub(crate) fn scroll_help(&mut self, delta: isize) {
        let last = crate::keys::help_rows().saturating_sub(1);
        self.help_scroll = self.help_scroll.saturating_add_signed(delta).min(last);
    }

    #[must_use]
    pub fn log_file(&self) -> Option<&str> {
        self.server.ready()?.log_file.as_deref()
    }

    #[must_use]
    pub fn selected_namespace(&self) -> Option<NamespaceName> {
        NamespaceName::new(self.namespace_selection.selected()?).ok()
    }

    #[must_use]
    pub fn namespace_spec(&self) -> Option<&NamespaceSpec> {
        let spec = self.namespace.ready()?;
        (Some(spec.name.as_str()) == self.namespace_selection.selected()).then_some(spec)
    }

    #[must_use]
    pub fn namespace_keys(&self) -> Vec<String> {
        self.namespaces
            .ready()
            .map(|namespaces| {
                namespaces
                    .iter()
                    .map(|summary| summary.name.as_str().to_owned())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// A rule is keyed by its path and its match, because the path alone would
    /// make a pattern rule and a literal rule on one directory the same row.
    #[must_use]
    pub fn rule_keys(&self) -> Vec<String> {
        self.namespace_spec()
            .map(|spec| {
                spec.rules
                    .iter()
                    .map(|rule| rule.key().to_string())
                    .collect()
            })
            .unwrap_or_default()
    }

    #[must_use]
    pub fn selected_rule(&self) -> Option<&Rule> {
        let key = self.rule_selection.selected()?;
        self.namespace_spec()?
            .rules
            .iter()
            .find(|rule| rule.key().to_string() == key)
    }

    #[must_use]
    pub fn session_keys(&self) -> Vec<String> {
        self.sessions
            .ready()
            .map(|sessions| {
                sessions
                    .iter()
                    .map(|session| session.id.to_string())
                    .collect()
            })
            .unwrap_or_default()
    }

    #[must_use]
    pub fn keys(&self) -> Vec<String> {
        match self.screen {
            Screen::Namespaces => self.namespace_keys(),
            Screen::Rules => self.rule_keys(),
            Screen::Sessions => self.session_keys(),
            _ => Vec::new(),
        }
    }

    #[must_use]
    pub fn selection(&self) -> Option<&Selection> {
        match self.screen {
            Screen::Namespaces => Some(&self.namespace_selection),
            Screen::Rules => Some(&self.rule_selection),
            Screen::Sessions => Some(&self.session_selection),
            _ => None,
        }
    }

    pub fn selection_mut(&mut self) -> Option<&mut Selection> {
        match self.screen {
            Screen::Namespaces => Some(&mut self.namespace_selection),
            Screen::Rules => Some(&mut self.rule_selection),
            Screen::Sessions => Some(&mut self.session_selection),
            _ => None,
        }
    }

    pub(crate) fn adopt_namespace(&mut self, spec: NamespaceSpec) {
        self.modes.sync(&spec);
        self.namespace = View::Ready(spec);
    }

    pub(crate) fn correlate(&mut self) -> Correlation {
        let correlation = Correlation(self.next_correlation);
        self.next_correlation += 1;
        correlation
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn model() -> Model {
        Model::new(Mode::Attach, "/run/voidport/control.sock", None)
    }

    #[test]
    fn screens_cycle_both_ways() {
        assert_eq!(Screen::Overview.step(true), Screen::Namespaces);
        assert_eq!(Screen::Overview.step(false), Screen::Logs);
        assert_eq!(Screen::Logs.step(true), Screen::Overview);
        for screen in SCREENS {
            assert!(!screen.title().is_empty());
        }
        assert!(Screen::Namespaces.is_list());
        assert!(!Screen::Overview.is_list());
    }

    #[test]
    fn a_new_model_knows_only_how_it_was_launched() {
        let model = model();
        assert_eq!(model.screen, Screen::Overview);
        assert_eq!(model.connection, Connection::Connecting);
        assert!(!model.connection.is_connected());
        assert!(model.server.ready().is_none());
        assert!(model.selected_namespace().is_none());
        assert!(model.keys().is_empty());
        assert!(model.selection().is_none());
    }

    #[test]
    fn a_terminal_below_the_minimum_does_not_fit() {
        let mut model = model();
        model.size = (MIN_WIDTH, MIN_HEIGHT);
        assert!(model.fits());
        model.size = (MIN_WIDTH - 1, MIN_HEIGHT);
        assert!(!model.fits());
        model.size = (MIN_WIDTH, MIN_HEIGHT - 1);
        assert!(!model.fits());
    }

    #[test]
    fn correlation_ids_are_handed_out_once_each() {
        let mut model = model();
        assert_eq!(model.correlate(), Correlation(1));
        assert_eq!(model.correlate(), Correlation(2));
    }
}
