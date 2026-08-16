//! The model: everything the interface knows, and nothing it guesses.
//!
//! The model is a plain value. It holds what the server last said (in
//! [`View`]s), what the operator is doing (a selection, a filter, a form), and
//! how the conversation is going (the connection state, the pending mutation,
//! the status line) — and it holds no derived copy of any of that. Rendering
//! reads it; the reducer writes it; nothing else touches it. That is what
//! makes every rule in the design's "Behavior rules" a unit test, not a
//! convention.
//!
//! Deliberately absent: any optimistic result. A created namespace appears
//! because the server listed it on the next fetch, never because the TUI
//! assumed it would.

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

/// The narrowest terminal the interface will draw in.
pub const MIN_WIDTH: u16 = 64;

/// The shortest terminal the interface will draw in.
pub const MIN_HEIGHT: u16 = 16;

/// The screens, in the order they are cycled.
pub const SCREENS: &[Screen] = &[
    Screen::Overview,
    Screen::Namespaces,
    Screen::Rules,
    Screen::Ownership,
    Screen::Modes,
    Screen::Sessions,
    Screen::Logs,
];

/// One screen of the interface.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Screen {
    /// The server, its endpoints, and what a seeded launch has to say.
    #[default]
    Overview,
    /// Every namespace.
    Namespaces,
    /// The selected namespace's rules.
    Rules,
    /// The selected namespace's ownership policy.
    Ownership,
    /// The selected namespace's permission and auth modes.
    Modes,
    /// The live data-plane sessions.
    Sessions,
    /// The tail of the server's own log file.
    Logs,
}

impl Screen {
    /// The name on the tab bar.
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

    /// Whether the screen's body is a list the list bindings apply to.
    #[must_use]
    pub fn is_list(self) -> bool {
        matches!(self, Self::Namespaces | Self::Rules | Self::Sessions)
    }

    /// The next or previous screen, wrapping.
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

/// How the TUI was launched, which decides what quitting means.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Attached to a server somebody else launched. Quitting disconnects.
    Attach,
    /// Serving and presenting one launch. Quitting shuts that server down.
    Serving,
}

/// The copy-paste block a seeded launch owes its operator, as the Overview
/// shows it.
///
/// The daemon derives this from its own launch summary — the same value it
/// would otherwise print to stdout — and hands it over already worded. The TUI
/// crate cannot depend on the daemon crate (the daemon's binary depends on
/// *this* one), and a mount URL is the daemon's grammar to spell, not the
/// terminal's.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LaunchNotes {
    /// The namespace the launch seeded.
    pub namespace: String,
    /// One ready-to-paste `voidport mount …` line per bound listener.
    pub mounts: Vec<String>,
    /// The `voidport-ctl --socket …` line for the socket this server bound.
    pub control_command: String,
    /// The plain-transport warning, when a tcp listener is bound.
    pub auth_note: Option<String>,
}

/// How the conversation with the server is going.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Connection {
    /// The first connection has not landed yet.
    Connecting,
    /// Connected and answering.
    Connected,
    /// Lost, and being retried.
    Lost {
        /// Why it dropped, in the client's own words.
        reason: String,
        /// Which retry is in flight, counting from one.
        attempt: u32,
    },
}

impl Connection {
    /// Whether the server is currently reachable.
    #[must_use]
    pub fn is_connected(&self) -> bool {
        matches!(self, Self::Connected)
    }
}

/// How a status message reads.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Tone {
    /// Ordinary information.
    #[default]
    Info,
    /// Something the operator asked for succeeded.
    Success,
    /// Something failed, or was refused.
    Failure,
    /// Something is in flight.
    Pending,
}

/// The last thing to say, on the status line.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Status {
    /// The message.
    pub message: String,
    /// How it reads.
    pub tone: Tone,
}

impl Status {
    /// A status of a given tone.
    fn new(tone: Tone, message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            tone,
        }
    }

    /// Plain information.
    #[must_use]
    pub fn info(message: impl Into<String>) -> Self {
        Self::new(Tone::Info, message)
    }

    /// A success.
    #[must_use]
    pub fn success(message: impl Into<String>) -> Self {
        Self::new(Tone::Success, message)
    }

    /// A failure or a refusal.
    #[must_use]
    pub fn failure(message: impl Into<String>) -> Self {
        Self::new(Tone::Failure, message)
    }

    /// Something in flight.
    #[must_use]
    pub fn pending(message: impl Into<String>) -> Self {
        Self::new(Tone::Pending, message)
    }
}

/// The mutation the server has not answered yet.
///
/// One at a time, deliberately: an operator issuing a second mutation before
/// the first is answered would be reasoning about a state neither they nor the
/// server can name. The view shows pending until the answer arrives.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pending {
    /// What the answer will be matched against.
    pub correlation: Correlation,
    /// What it was, for the status line.
    pub description: String,
    /// The screen that issued it, which is what gets re-fetched on success.
    pub origin: Screen,
}

/// A confirmation the operator has to give before a destructive operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Confirm {
    /// The question.
    pub prompt: String,
    /// What it does, for the status line once it is answered.
    pub description: String,
    /// The operation to issue on confirmation.
    pub request: voidport_control::Request,
}

/// Whatever is on top of the screen.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Dialog {
    /// A form being filled in.
    Form(Form),
    /// A confirmation being answered.
    Confirm(Confirm),
}

/// The two mode setters, and which of them the cursor is on.
///
/// The values are edited locally and applied whole, so the screen can show
/// what would be sent before it is sent. They are re-synced from the server's
/// namespace whenever a different namespace comes into focus.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Modes {
    /// 0 = permission, 1 = auth.
    pub row: usize,
    /// The permission mode as the operator has it.
    pub permission: String,
    /// The auth mode as the operator has it.
    pub auth: String,
    /// Which namespace the two values came from.
    pub namespace: Option<NamespaceName>,
    /// Whether the operator has cycled either value since it was last read
    /// from the server.
    ///
    /// Without it the buffer is an untracked copy: a mode changed by another
    /// operator refreshes the server column while "TO APPLY" keeps showing a
    /// value nobody chose — and Enter would then apply it. An untouched buffer
    /// follows the server; a touched one is the operator's and is left alone
    /// until it is applied or the subject changes.
    pub edited: bool,
}

impl Modes {
    /// Adopts a namespace's modes.
    ///
    /// A different namespace is a change of subject and always resyncs; the
    /// same namespace resyncs only while the buffer is the server's own value.
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

    /// Marks the buffer as the operator's own.
    pub(crate) fn edit(&mut self) {
        self.edited = true;
    }

    /// Gives the buffer back to the server, after an application landed.
    pub(crate) fn applied(&mut self) {
        self.edited = false;
    }
}

/// Everything the interface knows.
#[derive(Clone, Debug)]
pub struct Model {
    /// The focused screen.
    pub screen: Screen,
    /// Whether the Help overlay is up.
    pub help: bool,
    /// The first row of the Help overlay that is drawn.
    ///
    /// The overlay is the canonical binding list and is longer than the
    /// terminal it is read in, so it scrolls; the offset lives here because
    /// rendering is a pure function of the model and keeps nothing between
    /// frames.
    pub help_scroll: usize,
    /// Set once the interface should stop.
    pub finished: bool,
    /// How the TUI was launched.
    pub mode: Mode,
    /// The control socket, for the status line.
    pub socket: String,
    /// What a seeded launch has to say, in serve-and-present.
    pub notes: Option<LaunchNotes>,
    /// How the conversation is going.
    pub connection: Connection,
    /// The server's version, once it has said.
    pub version: Option<String>,
    /// The last thing to say.
    pub status: Status,
    /// The terminal size, which decides whether anything is drawn at all.
    pub size: (u16, u16),
    /// `server-info`.
    pub server: View<ServerFacts>,
    /// `namespace-list`.
    pub namespaces: View<Vec<NamespaceSummary>>,
    /// The namespace list's selection and filter.
    pub namespace_selection: Selection,
    /// `namespace-show` of the selected namespace.
    pub namespace: View<NamespaceSpec>,
    /// The rule list's selection and filter.
    pub rule_selection: Selection,
    /// The two mode setters.
    pub modes: Modes,
    /// `session-list`.
    pub sessions: View<Vec<SessionSummary>>,
    /// The session list's selection and filter.
    pub session_selection: Selection,
    /// The tail of the server's log file.
    ///
    /// Not a [`View`]: it is not one answer the server gives and replaces, but
    /// a file this process reads a piece at a time, so it accumulates instead
    /// of being replaced. What the *server* contributes is only the path, which
    /// is a field of [`ServerFacts`].
    pub logs: Logs,
    /// Whatever is on top.
    pub dialog: Option<Dialog>,
    /// The mutation the server has not answered.
    pub pending: Option<Pending>,
    /// The next correlation id to hand out.
    pub next_correlation: u64,
}

/// The parts of `server-info` the Overview shows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerFacts {
    /// The server's package version.
    pub version: String,
    /// The state file it owns.
    pub state_file: String,
    /// The control socket it serves.
    pub control_socket: String,
    /// How many namespaces it serves.
    pub namespaces: usize,
    /// The data-plane endpoints it bound.
    pub listeners: Vec<ListenerInfo>,
    /// The file it writes its own tracing to, if it writes it to one.
    ///
    /// The server's path, not this process's: the Logs screen tails it where
    /// the two share a filesystem and names it where they do not.
    pub log_file: Option<String>,
}

impl Model {
    /// A model that knows only how it was launched.
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

    /// Whether the terminal is big enough to draw the interface.
    ///
    /// The one place the question is answered: [`render`](crate::render) asks
    /// this instead of measuring the frame, so the size the interface reasons
    /// about and the size it decides by are the same value — the one the resize
    /// event carried.
    #[must_use]
    pub fn fits(&self) -> bool {
        self.size.0 >= MIN_WIDTH && self.size.1 >= MIN_HEIGHT
    }

    /// Scrolls the Help overlay by `delta` rows, clamped to the list.
    ///
    /// The bound is [`keys::help_rows`](crate::keys::help_rows) less one, so
    /// the last binding can always be reached and the overlay can never be
    /// scrolled into emptiness.
    pub(crate) fn scroll_help(&mut self, delta: isize) {
        let last = crate::keys::help_rows().saturating_sub(1);
        self.help_scroll = self.help_scroll.saturating_add_signed(delta).min(last);
    }

    /// The log file the server named, if it named one.
    ///
    /// Derived from `server-info` and held nowhere else: the Logs screen tails
    /// the file the server says it writes to, so a server that starts naming a
    /// different one is followed within a tick.
    #[must_use]
    pub fn log_file(&self) -> Option<&str> {
        self.server.ready()?.log_file.as_deref()
    }

    /// The selected namespace, if one is selected.
    #[must_use]
    pub fn selected_namespace(&self) -> Option<NamespaceName> {
        NamespaceName::new(self.namespace_selection.selected()?).ok()
    }

    /// The namespace the per-namespace screens are showing, if the server has
    /// sent it and it is still the selected one.
    #[must_use]
    pub fn namespace_spec(&self) -> Option<&NamespaceSpec> {
        let spec = self.namespace.ready()?;
        (Some(spec.name.as_str()) == self.namespace_selection.selected()).then_some(spec)
    }

    /// The namespace list's keys, in the order the server sent them.
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

    /// The selected namespace's rule keys.
    ///
    /// A rule is keyed by its path *and* its match, so the key is
    /// [`Rule::key`] — the same pair `rule-remove` names, spelled the way every
    /// operator surface spells it. Keying by the path alone would make a
    /// pattern rule and a literal rule on one directory the same row, and the
    /// removal aimed at either of them would name whichever the server found
    /// first.
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

    /// The rule the rule list has selected, found by that key.
    #[must_use]
    pub fn selected_rule(&self) -> Option<&Rule> {
        let key = self.rule_selection.selected()?;
        self.namespace_spec()?
            .rules
            .iter()
            .find(|rule| rule.key().to_string() == key)
    }

    /// The session list's keys: the session ids, as text.
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

    /// The keys of whichever list the focused screen shows.
    #[must_use]
    pub fn keys(&self) -> Vec<String> {
        match self.screen {
            Screen::Namespaces => self.namespace_keys(),
            Screen::Rules => self.rule_keys(),
            Screen::Sessions => self.session_keys(),
            _ => Vec::new(),
        }
    }

    /// The selection of whichever list the focused screen shows.
    #[must_use]
    pub fn selection(&self) -> Option<&Selection> {
        match self.screen {
            Screen::Namespaces => Some(&self.namespace_selection),
            Screen::Rules => Some(&self.rule_selection),
            Screen::Sessions => Some(&self.session_selection),
            _ => None,
        }
    }

    /// The selection of the focused screen, mutably.
    pub fn selection_mut(&mut self) -> Option<&mut Selection> {
        match self.screen {
            Screen::Namespaces => Some(&mut self.namespace_selection),
            Screen::Rules => Some(&mut self.rule_selection),
            Screen::Sessions => Some(&mut self.session_selection),
            _ => None,
        }
    }

    /// Adopts a freshly fetched namespace, keeping the mode setters in step.
    pub(crate) fn adopt_namespace(&mut self, spec: NamespaceSpec) {
        self.modes.sync(&spec);
        self.namespace = View::Ready(spec);
    }

    /// Hands out the next correlation id.
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
