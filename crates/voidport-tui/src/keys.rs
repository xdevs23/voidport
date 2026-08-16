//! The canonical keybinding table.
//!
//! One table is the whole keyboard: the reducer resolves every key through
//! [`action`], and the Help overlay renders the same [`BINDINGS`] slice. A
//! binding an operator can reach but cannot read about in Help is therefore
//! not a discipline anybody has to keep — it cannot be written, because the
//! only way to reach an action is to put it in this table.
//!
//! Text entry is the one exception, and it is deliberate: inside a form field
//! or a filter, ordinary characters type themselves instead of acting. The
//! table says so ([`Action::TypeText`]), so Help says so too.

use std::fmt;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::model::Screen;

/// Which part of the interface a binding belongs to.
///
/// The reducer asks for contexts in priority order — an overlay first, then
/// the focused screen, then the bindings every screen shares — so a key can
/// mean one thing in a dialog and another on a list without either binding
/// knowing about the other.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Context {
    /// Available everywhere, overlays and dialogs included.
    ///
    /// Separate from [`Self::Global`] because "everywhere" has to be true: the
    /// terminal-lifecycle contract maps Ctrl-C to quit and Ctrl-Z to suspend in
    /// raw mode, and a form or a confirmation is not an exception to that — the
    /// operator who cannot leave a dialog has no other way out, since in raw
    /// mode the terminal generates no signal of its own. These are control
    /// chords precisely so that they can never be a character somebody meant to
    /// type.
    Anywhere,
    /// Available on any screen, but not inside a dialog, a filter or an
    /// overlay, because these are plain characters and a form is being typed
    /// into.
    Global,
    /// Any screen whose body is a list.
    List,
    /// The namespace list.
    Namespaces,
    /// The rule list of the selected namespace.
    Rules,
    /// The ownership policy of the selected namespace.
    Ownership,
    /// The permission and auth setters.
    Modes,
    /// The live session list.
    Sessions,
    /// The tail of the server's log file.
    Logs,
    /// A form dialog.
    Form,
    /// A confirmation dialog.
    Confirm,
    /// An active list filter.
    Filter,
    /// The Help overlay itself.
    Help,
}

impl Context {
    /// The heading this context carries in the Help overlay.
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

    /// The context a screen's own bindings live in.
    #[must_use]
    pub fn of(screen: Screen) -> Self {
        match screen {
            // The overview is not a list and has no bindings of its own; it
            // answers to the global set.
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

/// What a key does.
///
/// Every variant is reachable from [`BINDINGS`]; [`ACTIONS`] lists them all and
/// a test holds the two together.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    /// Leave the TUI (and, in serve-and-present, shut the server down).
    Quit,
    /// Show or hide the Help overlay.
    ToggleHelp,
    /// Focus the next screen.
    NextScreen,
    /// Focus the previous screen.
    PreviousScreen,
    /// Focus one screen directly.
    Focus(Screen),
    /// Re-fetch the focused screen now, without waiting for the tick.
    Refresh,
    /// Suspend to the shell, restoring the terminal first.
    Suspend,
    /// Move the selection down.
    SelectNext,
    /// Move the selection up.
    SelectPrevious,
    /// Select the first item.
    SelectFirst,
    /// Select the last item.
    SelectLast,
    /// Move the selection a page down.
    PageDown,
    /// Move the selection a page up.
    PageUp,
    /// Start filtering the focused list.
    StartFilter,
    /// Open the selected namespace's rules.
    OpenNamespace,
    /// Create a namespace.
    CreateNamespace,
    /// Delete the selected namespace.
    DeleteNamespace,
    /// Add a rule to the selected namespace.
    AddRule,
    /// Remove the selected rule.
    RemoveRule,
    /// Edit the whole ownership policy.
    EditOwnership,
    /// Change the value of the selected mode setter.
    CycleValue,
    /// Apply the selected mode setter.
    ApplyMode,
    /// Pin the log view back to the newest line.
    Follow,
    /// Show the next level up in the log's level filter.
    CycleLevel,
    /// Accept a dialog.
    Confirm,
    /// Dismiss a dialog, a filter, or the Help overlay.
    Cancel,
    /// Move to the next form field.
    NextField,
    /// Move to the previous form field.
    PreviousField,
    /// Submit a form.
    Submit,
    /// Delete the character before the cursor.
    Backspace,
    /// Ordinary characters type themselves.
    TypeText,
}

impl Action {
    /// What Help says this action does.
    ///
    /// The exhaustive match is deliberate: a new action cannot be added
    /// without giving it a description, and the [`ACTIONS`] completeness test
    /// then forces it into the table.
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

/// One key, with the modifiers that matter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Chord {
    /// The key itself.
    pub code: KeyCode,
    /// The modifiers that must be held.
    pub modifiers: KeyModifiers,
}

impl Chord {
    /// A key with no modifier.
    #[must_use]
    pub const fn plain(code: KeyCode) -> Self {
        Self {
            code,
            modifiers: KeyModifiers::NONE,
        }
    }

    /// A key held with control.
    #[must_use]
    pub const fn control(code: KeyCode) -> Self {
        Self {
            code,
            modifiers: KeyModifiers::CONTROL,
        }
    }

    /// Whether a key event is this chord.
    ///
    /// Shift is ignored: a terminal reports `G` as `Char('G')` *with* shift,
    /// and a binding written as `G` means exactly that key.
    #[must_use]
    pub fn matches(self, event: KeyEvent) -> bool {
        let significant = KeyModifiers::CONTROL | KeyModifiers::ALT;
        self.code == event.code && (self.modifiers & significant) == (event.modifiers & significant)
    }
}

impl fmt::Display for Chord {
    /// How Help spells the chord.
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

/// One row of the table: the keys, what they do, and where they do it.
#[derive(Clone, Copy, Debug)]
pub struct Binding {
    /// Where the binding applies.
    pub context: Context,
    /// Every chord that triggers it.
    pub keys: &'static [Chord],
    /// What it triggers.
    pub action: Action,
}

/// The keyboard, whole.
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
    // The log view scrolls like every other body, and scrolling it away from
    // the newest line is what leaves follow mode — there is no separate
    // "stop following" key, because there is no state in which one would be
    // needed.
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
    // The overlay is longer than the terminal it is read in — at the supported
    // minimum size it shows about a fifth of itself — so the canonical binding
    // list has to be scrollable, and the bindings that scroll it are in the
    // list like everything else.
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

/// Every action, for the completeness check Help rests on.
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

/// The action a key triggers in one context, if any.
///
/// [`Action::TypeText`] is never returned here: text entry is decided by the
/// reducer from the key itself (a printable character with no control
/// modifier), and the table carries it only so Help can say so.
#[must_use]
pub fn action(context: Context, key: KeyEvent) -> Option<Action> {
    BINDINGS
        .iter()
        .filter(|binding| binding.context == context)
        .find(|binding| binding.keys.iter().any(|chord| chord.matches(key)))
        .map(|binding| binding.action)
}

/// Every binding of one context, in table order — the Help overlay's rows.
pub fn bindings(context: Context) -> impl Iterator<Item = &'static Binding> {
    BINDINGS
        .iter()
        .filter(move |binding| binding.context == context)
}

/// How many rows the Help overlay draws: one heading per listed context plus
/// one per binding in it.
///
/// The overlay lays out exactly this many lines and the model bounds its scroll
/// by it, so the two cannot disagree about how far down the list goes; a test
/// in `render::overlay` holds the count against the lines actually built.
#[must_use]
pub fn help_rows() -> usize {
    HELP_ORDER
        .iter()
        .map(|context| 1 + bindings(*context).count())
        .sum()
}

/// The contexts Help lists, in the order it lists them.
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

    /// What separates the two "everywhere" contexts, in the table itself: a
    /// binding that wins inside a form must be a chord a form can never receive
    /// as text.
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
