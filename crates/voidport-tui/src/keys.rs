use std::fmt;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::model::Screen;

/// The reducer asks for contexts in priority order: an overlay, then the
/// focused screen, then the bindings every screen shares.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Context {
    /// The terminal generates no signal in raw mode, so Ctrl-C and Ctrl-Z are
    /// control chords that dialogs and forms do not override and that are never
    /// text.
    Anywhere,
    /// Not available inside a dialog, a filter or an overlay, where plain
    /// characters are typed.
    Global,
    List,
    Namespaces,
    Rules,
    Ownership,
    Modes,
    Sessions,
    Logs,
    Form,
    Confirm,
    Filter,
    Help,
}

impl Context {
    #[must_use]
    pub fn title(self) -> &'static str {
        match self {
            Self::Anywhere => "Anywhere, dialogs included",
            Self::Global => "Any screen",
            Self::List => "Lists",
            Self::Namespaces => "Namespaces",
            Self::Rules => "Rules",
            Self::Ownership => "Ownership",
            Self::Modes => "Permission / auth",
            Self::Sessions => "Sessions",
            Self::Logs => "Logs",
            Self::Form => "Forms",
            Self::Confirm => "Confirmations",
            Self::Filter => "Filtering",
            Self::Help => "This overlay",
        }
    }

    #[must_use]
    pub fn of(screen: Screen) -> Self {
        match screen {
            Screen::Overview => Self::Global,
            Screen::Namespaces => Self::Namespaces,
            Screen::Rules => Self::Rules,
            Screen::Ownership => Self::Ownership,
            Screen::Modes => Self::Modes,
            Screen::Sessions => Self::Sessions,
            Screen::Logs => Self::Logs,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Quit,
    ToggleHelp,
    NextScreen,
    PreviousScreen,
    Focus(Screen),
    Refresh,
    Suspend,
    SelectNext,
    SelectPrevious,
    SelectFirst,
    SelectLast,
    PageDown,
    PageUp,
    StartFilter,
    OpenNamespace,
    CreateNamespace,
    DeleteNamespace,
    AddRule,
    RemoveRule,
    EditOwnership,
    CycleValue,
    ApplyMode,
    Follow,
    CycleLevel,
    Confirm,
    Cancel,
    NextField,
    PreviousField,
    Submit,
    Backspace,
    TypeText,
}

impl Action {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Quit => "quit",
            Self::ToggleHelp => "help",
            Self::NextScreen => "next screen",
            Self::PreviousScreen => "previous screen",
            Self::Focus(screen) => screen.title(),
            Self::Refresh => "refresh now",
            Self::Suspend => "suspend to the shell",
            Self::SelectNext => "down",
            Self::SelectPrevious => "up",
            Self::SelectFirst => "first",
            Self::SelectLast => "last",
            Self::PageDown => "page down",
            Self::PageUp => "page up",
            Self::StartFilter => "filter",
            Self::OpenNamespace => "open its rules",
            Self::CreateNamespace => "create a namespace",
            Self::DeleteNamespace => "delete the namespace",
            Self::AddRule => "add a rule",
            Self::RemoveRule => "remove the rule",
            Self::EditOwnership => "edit the policy",
            Self::CycleValue => "change the value",
            Self::ApplyMode => "apply it",
            Self::Follow => "follow the newest line",
            Self::CycleLevel => "cycle the level filter",
            Self::Confirm => "confirm",
            Self::Cancel => "cancel",
            Self::NextField => "next field",
            Self::PreviousField => "previous field",
            Self::Submit => "submit",
            Self::Backspace => "erase",
            Self::TypeText => "type to edit",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Chord {
    pub code: KeyCode,
    pub modifiers: KeyModifiers,
}

impl Chord {
    #[must_use]
    pub const fn plain(code: KeyCode) -> Self {
        Self {
            code,
            modifiers: KeyModifiers::NONE,
        }
    }

    #[must_use]
    pub const fn control(code: KeyCode) -> Self {
        Self {
            code,
            modifiers: KeyModifiers::CONTROL,
        }
    }

    /// Shift is ignored: a terminal reports `G` as `Char('G')` with shift.
    #[must_use]
    pub fn matches(self, event: KeyEvent) -> bool {
        let significant = KeyModifiers::CONTROL | KeyModifiers::ALT;
        self.code == event.code && (self.modifiers & significant) == (event.modifiers & significant)
    }
}

impl fmt::Display for Chord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.modifiers.contains(KeyModifiers::CONTROL) {
            write!(f, "Ctrl-")?;
        }
        if self.modifiers.contains(KeyModifiers::ALT) {
            write!(f, "Alt-")?;
        }
        match self.code {
            KeyCode::Char(' ') => f.write_str("Space"),
            // `Ctrl-C`, not `Ctrl-c`: the conventional spelling, and the one an
            // operator scanning Help expects to find.
            KeyCode::Char(character) if self.modifiers.contains(KeyModifiers::CONTROL) => {
                write!(f, "{}", character.to_ascii_uppercase())
            }
            KeyCode::Char(character) => write!(f, "{character}"),
            KeyCode::Enter => f.write_str("Enter"),
            KeyCode::Esc => f.write_str("Esc"),
            KeyCode::Tab => f.write_str("Tab"),
            KeyCode::BackTab => f.write_str("Shift-Tab"),
            KeyCode::Backspace => f.write_str("Backspace"),
            KeyCode::Up => f.write_str("Up"),
            KeyCode::Down => f.write_str("Down"),
            KeyCode::Left => f.write_str("Left"),
            KeyCode::Right => f.write_str("Right"),
            KeyCode::Home => f.write_str("Home"),
            KeyCode::End => f.write_str("End"),
            KeyCode::PageUp => f.write_str("PgUp"),
            KeyCode::PageDown => f.write_str("PgDn"),
            other => write!(f, "{other:?}"),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Binding {
    pub context: Context,
    pub keys: &'static [Chord],
    pub action: Action,
}

pub const BINDINGS: &[Binding] = &[
    Binding {
        context: Context::Anywhere,
        keys: &[Chord::control(KeyCode::Char('c'))],
        action: Action::Quit,
    },
    Binding {
        context: Context::Anywhere,
        keys: &[Chord::control(KeyCode::Char('z'))],
        action: Action::Suspend,
    },
    Binding {
        context: Context::Global,
        keys: &[Chord::plain(KeyCode::Char('q'))],
        action: Action::Quit,
    },
    Binding {
        context: Context::Global,
        keys: &[Chord::plain(KeyCode::Char('?'))],
        action: Action::ToggleHelp,
    },
    Binding {
        context: Context::Global,
        keys: &[Chord::plain(KeyCode::Tab)],
        action: Action::NextScreen,
    },
    Binding {
        context: Context::Global,
        keys: &[Chord::plain(KeyCode::BackTab)],
        action: Action::PreviousScreen,
    },
    Binding {
        context: Context::Global,
        keys: &[Chord::plain(KeyCode::Char('1'))],
        action: Action::Focus(Screen::Overview),
    },
    Binding {
        context: Context::Global,
        keys: &[Chord::plain(KeyCode::Char('2'))],
        action: Action::Focus(Screen::Namespaces),
    },
    Binding {
        context: Context::Global,
        keys: &[Chord::plain(KeyCode::Char('3'))],
        action: Action::Focus(Screen::Rules),
    },
    Binding {
        context: Context::Global,
        keys: &[Chord::plain(KeyCode::Char('4'))],
        action: Action::Focus(Screen::Ownership),
    },
    Binding {
        context: Context::Global,
        keys: &[Chord::plain(KeyCode::Char('5'))],
        action: Action::Focus(Screen::Modes),
    },
    Binding {
        context: Context::Global,
        keys: &[Chord::plain(KeyCode::Char('6'))],
        action: Action::Focus(Screen::Sessions),
    },
    Binding {
        context: Context::Global,
        keys: &[Chord::plain(KeyCode::Char('7'))],
        action: Action::Focus(Screen::Logs),
    },
    Binding {
        context: Context::Global,
        keys: &[Chord::plain(KeyCode::Char('r'))],
        action: Action::Refresh,
    },
    Binding {
        context: Context::List,
        keys: &[
            Chord::plain(KeyCode::Char('j')),
            Chord::plain(KeyCode::Down),
        ],
        action: Action::SelectNext,
    },
    Binding {
        context: Context::List,
        keys: &[Chord::plain(KeyCode::Char('k')), Chord::plain(KeyCode::Up)],
        action: Action::SelectPrevious,
    },
    Binding {
        context: Context::List,
        keys: &[
            Chord::plain(KeyCode::Char('g')),
            Chord::plain(KeyCode::Home),
        ],
        action: Action::SelectFirst,
    },
    Binding {
        context: Context::List,
        keys: &[Chord::plain(KeyCode::Char('G')), Chord::plain(KeyCode::End)],
        action: Action::SelectLast,
    },
    Binding {
        context: Context::List,
        keys: &[Chord::plain(KeyCode::PageDown)],
        action: Action::PageDown,
    },
    Binding {
        context: Context::List,
        keys: &[Chord::plain(KeyCode::PageUp)],
        action: Action::PageUp,
    },
    Binding {
        context: Context::List,
        keys: &[Chord::plain(KeyCode::Char('/'))],
        action: Action::StartFilter,
    },
    Binding {
        context: Context::List,
        keys: &[Chord::plain(KeyCode::Esc)],
        action: Action::Cancel,
    },
    Binding {
        context: Context::Namespaces,
        keys: &[Chord::plain(KeyCode::Enter)],
        action: Action::OpenNamespace,
    },
    Binding {
        context: Context::Namespaces,
        keys: &[Chord::plain(KeyCode::Char('n'))],
        action: Action::CreateNamespace,
    },
    Binding {
        context: Context::Namespaces,
        keys: &[Chord::plain(KeyCode::Char('d'))],
        action: Action::DeleteNamespace,
    },
    Binding {
        context: Context::Rules,
        keys: &[Chord::plain(KeyCode::Char('a'))],
        action: Action::AddRule,
    },
    Binding {
        context: Context::Rules,
        keys: &[Chord::plain(KeyCode::Char('d'))],
        action: Action::RemoveRule,
    },
    Binding {
        context: Context::Ownership,
        keys: &[Chord::plain(KeyCode::Char('e'))],
        action: Action::EditOwnership,
    },
    Binding {
        context: Context::Modes,
        keys: &[
            Chord::plain(KeyCode::Char('j')),
            Chord::plain(KeyCode::Down),
        ],
        action: Action::SelectNext,
    },
    Binding {
        context: Context::Modes,
        keys: &[Chord::plain(KeyCode::Char('k')), Chord::plain(KeyCode::Up)],
        action: Action::SelectPrevious,
    },
    Binding {
        context: Context::Modes,
        keys: &[
            Chord::plain(KeyCode::Char(' ')),
            Chord::plain(KeyCode::Right),
        ],
        action: Action::CycleValue,
    },
    Binding {
        context: Context::Modes,
        keys: &[Chord::plain(KeyCode::Enter)],
        action: Action::ApplyMode,
    },
    Binding {
        context: Context::Logs,
        keys: &[
            Chord::plain(KeyCode::Char('j')),
            Chord::plain(KeyCode::Down),
        ],
        action: Action::SelectNext,
    },
    Binding {
        context: Context::Logs,
        keys: &[Chord::plain(KeyCode::Char('k')), Chord::plain(KeyCode::Up)],
        action: Action::SelectPrevious,
    },
    Binding {
        context: Context::Logs,
        keys: &[Chord::plain(KeyCode::PageDown)],
        action: Action::PageDown,
    },
    Binding {
        context: Context::Logs,
        keys: &[Chord::plain(KeyCode::PageUp)],
        action: Action::PageUp,
    },
    Binding {
        context: Context::Logs,
        keys: &[
            Chord::plain(KeyCode::Char('g')),
            Chord::plain(KeyCode::Home),
        ],
        action: Action::SelectFirst,
    },
    Binding {
        context: Context::Logs,
        keys: &[Chord::plain(KeyCode::Char('G')), Chord::plain(KeyCode::End)],
        action: Action::SelectLast,
    },
    Binding {
        context: Context::Logs,
        keys: &[Chord::plain(KeyCode::Char('f'))],
        action: Action::Follow,
    },
    Binding {
        context: Context::Logs,
        keys: &[Chord::plain(KeyCode::Char('l'))],
        action: Action::CycleLevel,
    },
    Binding {
        context: Context::Confirm,
        keys: &[
            Chord::plain(KeyCode::Char('y')),
            Chord::plain(KeyCode::Enter),
        ],
        action: Action::Confirm,
    },
    Binding {
        context: Context::Confirm,
        keys: &[Chord::plain(KeyCode::Char('n')), Chord::plain(KeyCode::Esc)],
        action: Action::Cancel,
    },
    Binding {
        context: Context::Form,
        keys: &[
            Chord::plain(KeyCode::Tab),
            Chord::plain(KeyCode::Down),
            Chord::control(KeyCode::Char('n')),
        ],
        action: Action::NextField,
    },
    Binding {
        context: Context::Form,
        keys: &[
            Chord::plain(KeyCode::BackTab),
            Chord::plain(KeyCode::Up),
            Chord::control(KeyCode::Char('p')),
        ],
        action: Action::PreviousField,
    },
    Binding {
        context: Context::Form,
        keys: &[Chord::plain(KeyCode::Right), Chord::plain(KeyCode::Left)],
        action: Action::CycleValue,
    },
    Binding {
        context: Context::Form,
        keys: &[Chord::plain(KeyCode::Enter)],
        action: Action::Submit,
    },
    Binding {
        context: Context::Form,
        keys: &[Chord::plain(KeyCode::Backspace)],
        action: Action::Backspace,
    },
    Binding {
        context: Context::Form,
        keys: &[Chord::plain(KeyCode::Esc)],
        action: Action::Cancel,
    },
    Binding {
        context: Context::Form,
        keys: &[],
        action: Action::TypeText,
    },
    Binding {
        context: Context::Filter,
        keys: &[Chord::plain(KeyCode::Backspace)],
        action: Action::Backspace,
    },
    Binding {
        context: Context::Filter,
        keys: &[Chord::plain(KeyCode::Enter)],
        action: Action::Confirm,
    },
    Binding {
        context: Context::Filter,
        keys: &[Chord::plain(KeyCode::Esc)],
        action: Action::Cancel,
    },
    Binding {
        context: Context::Filter,
        keys: &[],
        action: Action::TypeText,
    },
    Binding {
        context: Context::Help,
        keys: &[
            Chord::plain(KeyCode::Char('?')),
            Chord::plain(KeyCode::Esc),
            Chord::plain(KeyCode::Enter),
        ],
        action: Action::Cancel,
    },
    // At the supported minimum size the overlay shows about a fifth of itself,
    // so the list of bindings scrolls.
    Binding {
        context: Context::Help,
        keys: &[
            Chord::plain(KeyCode::Char('j')),
            Chord::plain(KeyCode::Down),
        ],
        action: Action::SelectNext,
    },
    Binding {
        context: Context::Help,
        keys: &[Chord::plain(KeyCode::Char('k')), Chord::plain(KeyCode::Up)],
        action: Action::SelectPrevious,
    },
    Binding {
        context: Context::Help,
        keys: &[Chord::plain(KeyCode::PageDown)],
        action: Action::PageDown,
    },
    Binding {
        context: Context::Help,
        keys: &[Chord::plain(KeyCode::PageUp)],
        action: Action::PageUp,
    },
    Binding {
        context: Context::Help,
        keys: &[
            Chord::plain(KeyCode::Char('g')),
            Chord::plain(KeyCode::Home),
        ],
        action: Action::SelectFirst,
    },
    Binding {
        context: Context::Help,
        keys: &[Chord::plain(KeyCode::Char('G')), Chord::plain(KeyCode::End)],
        action: Action::SelectLast,
    },
];

pub const ACTIONS: &[Action] = &[
    Action::Quit,
    Action::ToggleHelp,
    Action::NextScreen,
    Action::PreviousScreen,
    Action::Focus(Screen::Overview),
    Action::Focus(Screen::Namespaces),
    Action::Focus(Screen::Rules),
    Action::Focus(Screen::Ownership),
    Action::Focus(Screen::Modes),
    Action::Focus(Screen::Sessions),
    Action::Focus(Screen::Logs),
    Action::Refresh,
    Action::Suspend,
    Action::SelectNext,
    Action::SelectPrevious,
    Action::SelectFirst,
    Action::SelectLast,
    Action::PageDown,
    Action::PageUp,
    Action::StartFilter,
    Action::OpenNamespace,
    Action::CreateNamespace,
    Action::DeleteNamespace,
    Action::AddRule,
    Action::RemoveRule,
    Action::EditOwnership,
    Action::CycleValue,
    Action::ApplyMode,
    Action::Follow,
    Action::CycleLevel,
    Action::Confirm,
    Action::Cancel,
    Action::NextField,
    Action::PreviousField,
    Action::Submit,
    Action::Backspace,
    Action::TypeText,
];

/// [`Action::TypeText`] is never returned here: the reducer recognizes text
/// entry from the key itself.
#[must_use]
pub fn action(context: Context, key: KeyEvent) -> Option<Action> {
    BINDINGS
        .iter()
        .filter(|binding| binding.context == context)
        .find(|binding| binding.keys.iter().any(|chord| chord.matches(key)))
        .map(|binding| binding.action)
}

pub fn bindings(context: Context) -> impl Iterator<Item = &'static Binding> {
    BINDINGS
        .iter()
        .filter(move |binding| binding.context == context)
}

/// The overlay lays out exactly this many lines and the model bounds its
/// scroll by it.
#[must_use]
pub fn help_rows() -> usize {
    HELP_ORDER
        .iter()
        .map(|context| 1 + bindings(*context).count())
        .sum()
}

pub const HELP_ORDER: &[Context] = &[
    Context::Anywhere,
    Context::Global,
    Context::List,
    Context::Namespaces,
    Context::Rules,
    Context::Ownership,
    Context::Modes,
    Context::Sessions,
    Context::Logs,
    Context::Form,
    Context::Confirm,
    Context::Filter,
    Context::Help,
];

#[cfg(test)]
mod tests {
    use super::*;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    #[test]
    fn every_action_is_reachable_and_every_binding_is_listed() {
        for action in ACTIONS {
            assert!(
                BINDINGS.iter().any(|binding| binding.action == *action),
                "{action:?} has no binding, so Help could never mention it"
            );
            assert!(!action.label().is_empty());
        }
        for binding in BINDINGS {
            assert!(
                ACTIONS.contains(&binding.action),
                "{:?} is bound but missing from ACTIONS",
                binding.action
            );
            assert!(
                HELP_ORDER.contains(&binding.context),
                "{:?} is in no Help section",
                binding.context
            );
        }
    }

    #[test]
    fn a_bound_key_resolves_to_its_action_in_its_own_context() {
        for binding in BINDINGS {
            for chord in binding.keys {
                let event = KeyEvent::new(chord.code, chord.modifiers);
                assert_eq!(
                    action(binding.context, event),
                    Some(binding.action),
                    "{chord} does not resolve in {:?}",
                    binding.context
                );
            }
        }
    }

    #[test]
    fn shift_is_ignored_but_control_is_not() {
        let shifted = KeyEvent::new(KeyCode::Char('G'), KeyModifiers::SHIFT);
        assert_eq!(action(Context::List, shifted), Some(Action::SelectLast));

        let controlled = KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL);
        assert_eq!(action(Context::Anywhere, controlled), Some(Action::Quit));
        assert_eq!(action(Context::Anywhere, key(KeyCode::Char('c'))), None);
    }

    #[test]
    fn the_anywhere_bindings_are_control_chords_only() {
        for binding in bindings(Context::Anywhere) {
            for chord in binding.keys {
                assert!(
                    chord.modifiers.contains(KeyModifiers::CONTROL),
                    "{chord} would swallow a keystroke a form was being given"
                );
            }
        }
        assert_eq!(
            bindings(Context::Anywhere)
                .map(|binding| binding.action)
                .collect::<Vec<_>>(),
            vec![Action::Quit, Action::Suspend],
        );
    }

    #[test]
    fn help_counts_the_rows_it_will_draw() {
        assert_eq!(
            help_rows(),
            HELP_ORDER.len() + BINDINGS.len(),
            "every binding is in a listed context, so every one of them is a row"
        );
    }

    #[test]
    fn chords_spell_themselves_for_help() {
        assert_eq!(Chord::control(KeyCode::Char('c')).to_string(), "Ctrl-C");
        assert_eq!(Chord::plain(KeyCode::BackTab).to_string(), "Shift-Tab");
        assert_eq!(Chord::plain(KeyCode::Char(' ')).to_string(), "Space");
        assert_eq!(Chord::plain(KeyCode::PageDown).to_string(), "PgDn");
    }

    #[test]
    fn a_screens_context_is_its_own() {
        assert_eq!(Context::of(Screen::Rules), Context::Rules);
        assert_eq!(Context::of(Screen::Overview), Context::Global);
    }
}
