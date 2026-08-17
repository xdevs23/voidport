//! Forms: the only place the operator composes a value instead of picking one.
//!
//! A form is a list of [`Field`]s and a focus, nothing more. Two kinds of
//! field exist — free text, and a choice cycled through a fixed list — because
//! the protocol's own types are exactly those two shapes: a path or an id
//! table is text, a share mode or an ownership mode is a closed set, and
//! offering a closed set as free text would invent an error the operator
//! should never have been able to make.
//!
//! Validation is deliberately split. What the **shared types** can decide is
//! decided here ([`Form::request`]): namespace names through
//! [`NamespaceName`], id maps and squash ids through their numeric parses,
//! modes through their own enums. Everything else — whether a rule table stays
//! valid, whether a target can be pinned — is the server's verdict, and the
//! form does not guess at it.

use voidport_control::{
    AuthMode, HostDirectIo, HostId, IdMapping, IdSentinel, NamespaceName, NamespaceSpec,
    OwnershipSpec, PermissionMode, Request, Rule, ShareMode, UnmappedPolicy,
};

/// One editable field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Field {
    /// What the field is called on screen.
    pub label: &'static str,
    /// A one-line explanation, rendered beside the focused field.
    pub hint: &'static str,
    /// What the operator has typed, or the chosen value.
    pub value: String,
    /// The closed set this field cycles through; empty for free text.
    pub choices: &'static [&'static str],
}

impl Field {
    /// A free-text field.
    fn text(label: &'static str, hint: &'static str, value: impl Into<String>) -> Self {
        Self {
            label,
            hint,
            value: value.into(),
            choices: &[],
        }
    }

    /// A field cycling through a closed set, starting at `value`.
    fn choice(
        label: &'static str,
        hint: &'static str,
        choices: &'static [&'static str],
        value: impl Into<String>,
    ) -> Self {
        Self {
            label,
            hint,
            value: value.into(),
            choices,
        }
    }

    /// Whether the field is a closed set.
    #[must_use]
    pub fn is_choice(&self) -> bool {
        !self.choices.is_empty()
    }

    /// Moves a choice field to its next value; a text field is untouched.
    fn cycle(&mut self, forward: bool) {
        if self.choices.is_empty() {
            return;
        }
        let current = self
            .choices
            .iter()
            .position(|choice| *choice == self.value)
            .unwrap_or(0);
        let len = self.choices.len();
        let next = if forward {
            (current + 1) % len
        } else {
            (current + len - 1) % len
        };
        self.value = self.choices[next].to_owned();
    }
}

/// Which operation a form composes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FormKind {
    /// `namespace-create`.
    NamespaceCreate,
    /// `rule-add` into one namespace.
    RuleAdd(NamespaceName),
    /// `ownership-set` on one namespace.
    Ownership(NamespaceName),
}

/// Every share mode a rule may state.
const SHARE_MODES: &[&str] = &["rw", "ro", "hidden"];
/// Every ownership mode the schema has.
const OWNERSHIP_MODES: &[&str] = &["passthrough", "map", "static"];
/// Every unmapped-id policy.
const UNMAPPED: &[&str] = &["squash", "hide", "passthrough"];
/// Every permission mode v1 defines.
pub const PERMISSION_MODES: &[&str] = &["passthrough"];
/// Every auth mode v1 defines.
pub const AUTH_MODES: &[&str] = &["none"];

/// A form in progress.
///
/// It survives a reconnect on purpose (design: "a form in progress is kept,
/// and its eventual submit is judged by the server like any mutation"): the
/// operator's typing is theirs, and a dropped connection is not a reason to
/// throw it away.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Form {
    /// What it will submit.
    pub kind: FormKind,
    /// Its fields, in tab order.
    pub fields: Vec<Field>,
    /// Which field has the cursor.
    pub focus: usize,
    /// The last local validation failure, if any.
    pub error: Option<String>,
}

impl Form {
    /// The form that creates a namespace.
    ///
    /// Ownership beyond the mode — the id tables, the unmapped policy, the
    /// squash ids — is the Ownership screen's business: a namespace is created
    /// with the minimum its mode requires, and refined there.
    #[must_use]
    pub fn namespace_create() -> Self {
        Self::new(
            FormKind::NamespaceCreate,
            vec![
                Field::text("name", "nonempty, no `/`, at most 255 bytes", ""),
                Field::choice(
                    "permission",
                    "how host permission bits present",
                    PERMISSION_MODES,
                    "passthrough",
                ),
                Field::choice("auth", "how clients authenticate", AUTH_MODES, "none"),
                Field::choice(
                    "ownership",
                    "id mapping mode; tables are edited on the Ownership screen",
                    OWNERSHIP_MODES,
                    "passthrough",
                ),
                Field::text("static uid", "used by the `static` mode only", "0"),
                Field::text("static gid", "used by the `static` mode only", "0"),
            ],
        )
    }

    /// The form that adds a rule to `namespace`.
    #[must_use]
    pub fn rule_add(namespace: NamespaceName) -> Self {
        Self::new(
            FormKind::RuleAdd(namespace),
            vec![
                Field::text("path", "namespace path, e.g. /project or /project/*", "/"),
                Field::choice("mode", "share mode", SHARE_MODES, "rw"),
                Field::text(
                    "target",
                    "host path; empty to derive it, absolute or relative to the state file",
                    "",
                ),
            ],
        )
    }

    /// The form that replaces `namespace`'s ownership policy, pre-filled with
    /// the policy the server currently holds.
    ///
    /// Pre-filling is what makes it an editor, not a re-entry: the
    /// operation replaces the policy whole, exactly as the protocol applies
    /// it, so the operator must see what they are replacing.
    #[must_use]
    pub fn ownership(namespace: NamespaceName, current: &OwnershipSpec) -> Self {
        let (unmapped, squash_uid, squash_gid, uid_map, gid_map) = match current {
            OwnershipSpec::Map {
                unmapped,
                squash_uid,
                squash_gid,
                uid_map,
                gid_map,
            } => (
                unmapped.to_string(),
                squash_uid.to_string(),
                squash_gid.to_string(),
                render_mappings(uid_map),
                render_mappings(gid_map),
            ),
            _ => (
                UnmappedPolicy::default().to_string(),
                voidport_control::DEFAULT_SQUASH_ID.to_string(),
                voidport_control::DEFAULT_SQUASH_ID.to_string(),
                String::new(),
                String::new(),
            ),
        };
        let (static_uid, static_gid) = match current {
            OwnershipSpec::Static { uid, gid } => (uid.to_string(), gid.to_string()),
            _ => ("0".to_owned(), "0".to_owned()),
        };
        Self::new(
            FormKind::Ownership(namespace),
            vec![
                Field::choice(
                    "mode",
                    "map | passthrough | static",
                    OWNERSHIP_MODES,
                    current.mode().to_string(),
                ),
                Field::choice(
                    "unmapped",
                    "the fate of a host id no table entry covers (`map` only)",
                    UNMAPPED,
                    unmapped,
                ),
                Field::text(
                    "squash uid",
                    "presented for an unmapped host uid",
                    squash_uid,
                ),
                Field::text(
                    "squash gid",
                    "presented for an unmapped host gid",
                    squash_gid,
                ),
                Field::text(
                    "uid map",
                    "host->guest pairs, comma separated; host may be the sentinel `uid`",
                    uid_map,
                ),
                Field::text(
                    "gid map",
                    "host->guest pairs, comma separated; host may be the sentinel `gid`",
                    gid_map,
                ),
                Field::text("static uid", "used by the `static` mode only", static_uid),
                Field::text("static gid", "used by the `static` mode only", static_gid),
            ],
        )
    }

    /// Builds a form around its fields.
    fn new(kind: FormKind, fields: Vec<Field>) -> Self {
        Self {
            kind,
            fields,
            focus: 0,
            error: None,
        }
    }

    /// The title the dialog carries.
    #[must_use]
    pub fn title(&self) -> String {
        match &self.kind {
            FormKind::NamespaceCreate => "Create namespace".to_owned(),
            FormKind::RuleAdd(namespace) => format!("Add rule to \"{namespace}\""),
            FormKind::Ownership(namespace) => format!("Ownership of \"{namespace}\""),
        }
    }

    /// Moves the cursor one field on, wrapping.
    pub fn focus_next(&mut self, forward: bool) {
        let len = self.fields.len();
        if len == 0 {
            return;
        }
        self.focus = if forward {
            (self.focus + 1) % len
        } else {
            (self.focus + len - 1) % len
        };
    }

    /// The focused field.
    #[must_use]
    pub fn focused(&self) -> &Field {
        &self.fields[self.focus]
    }

    /// Types a character into the focused field.
    ///
    /// A choice field is not typed into: its value is one of a closed set, and
    /// the same key cycles it instead, so a stray keystroke cannot produce a
    /// value the schema has no name for.
    pub fn type_character(&mut self, character: char) {
        let field = &mut self.fields[self.focus];
        if field.is_choice() {
            field.cycle(true);
        } else {
            field.value.push(character);
        }
    }

    /// Erases the last character of the focused text field.
    pub fn backspace(&mut self) {
        let field = &mut self.fields[self.focus];
        if !field.is_choice() {
            field.value.pop();
        }
    }

    /// Cycles the focused choice field.
    pub fn cycle(&mut self, forward: bool) {
        self.fields[self.focus].cycle(forward);
    }

    /// One field's value.
    fn value(&self, index: usize) -> &str {
        self.fields[index].value.trim()
    }

    /// The request this form submits, or why it is not one yet.
    ///
    /// # Errors
    ///
    /// Returns the operator-facing reason the fields do not compose a request:
    /// an invalid namespace name, an unparseable id, a malformed map entry.
    pub fn request(&self) -> Result<Request, String> {
        match &self.kind {
            FormKind::NamespaceCreate => {
                let name = NamespaceName::new(self.value(0)).map_err(|error| error.to_string())?;
                let ownership = match self.value(3) {
                    "passthrough" => OwnershipSpec::Passthrough {},
                    "static" => OwnershipSpec::Static {
                        uid: number(self.value(4), "static uid")?,
                        gid: number(self.value(5), "static gid")?,
                    },
                    _ => OwnershipSpec::Map {
                        unmapped: UnmappedPolicy::default(),
                        squash_uid: voidport_control::DEFAULT_SQUASH_ID,
                        squash_gid: voidport_control::DEFAULT_SQUASH_ID,
                        uid_map: Vec::new(),
                        gid_map: Vec::new(),
                    },
                };
                // Parsed back from what the choice fields are showing, not
                // assumed: the two enums have one variant each in v1, and a
                // hardcoded variant would silently stop matching the screen the
                // day a second one is defined.
                let permission = self
                    .value(1)
                    .parse::<PermissionMode>()
                    .map_err(|error| error.to_string())?;
                let auth = self
                    .value(2)
                    .parse::<AuthMode>()
                    .map_err(|error| error.to_string())?;
                Ok(Request::NamespaceCreate {
                    namespace: NamespaceSpec {
                        name,
                        permission,
                        // A namespace is created with the minimum its policy
                        // requires, so its backing I/O starts on the host page
                        // cache like every other default.
                        direct_io: HostDirectIo::default(),
                        auth,
                        ownership,
                        // A create takes the default; the switch has an
                        // operation of its own.
                        privileged_bits: true,
                        rules: Vec::new(),
                        xattr: Vec::new(),
                    },
                })
            }
            FormKind::RuleAdd(namespace) => {
                let path = self.value(0);
                if path.is_empty() {
                    return Err("a rule needs a path".to_owned());
                }
                let mode = match self.value(1) {
                    "rw" => ShareMode::Rw,
                    "ro" => ShareMode::Ro,
                    _ => ShareMode::Hidden,
                };
                let mut rule = Rule::new(path, mode);
                let target = self.value(2);
                if !target.is_empty() {
                    rule = rule.with_target(target);
                }
                Ok(Request::RuleAdd {
                    namespace: namespace.clone(),
                    rule,
                })
            }
            FormKind::Ownership(namespace) => {
                let ownership = match self.value(0) {
                    "passthrough" => OwnershipSpec::Passthrough {},
                    "static" => OwnershipSpec::Static {
                        uid: number(self.value(6), "static uid")?,
                        gid: number(self.value(7), "static gid")?,
                    },
                    _ => OwnershipSpec::Map {
                        unmapped: match self.value(1) {
                            "hide" => UnmappedPolicy::Hide,
                            "passthrough" => UnmappedPolicy::Passthrough,
                            _ => UnmappedPolicy::Squash,
                        },
                        squash_uid: number(self.value(2), "squash uid")?,
                        squash_gid: number(self.value(3), "squash gid")?,
                        uid_map: mappings(self.value(4), "uid map")?,
                        gid_map: mappings(self.value(5), "gid map")?,
                    },
                };
                Ok(Request::OwnershipSet {
                    namespace: namespace.clone(),
                    ownership,
                })
            }
        }
    }
}

/// Parses one unsigned id, naming the field when it does not parse.
fn number(value: &str, field: &str) -> Result<u32, String> {
    value
        .parse()
        .map_err(|_| format!("{field}: {value:?} is not a number"))
}

/// Parses `host->guest` pairs, the spelling the same fields render.
fn mappings(value: &str, field: &str) -> Result<Vec<IdMapping>, String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(|entry| {
            let (host, guest) = entry
                .split_once("->")
                .ok_or_else(|| format!("{field}: {entry:?} is not `host->guest`"))?;
            let host = match host.trim() {
                "uid" => HostId::Sentinel(IdSentinel::Uid),
                "gid" => HostId::Sentinel(IdSentinel::Gid),
                literal => HostId::Numeric(number(literal, field)?),
            };
            Ok(IdMapping::new(host, number(guest.trim(), field)?))
        })
        .collect()
}

/// Renders id mappings the way the map fields parse them.
fn render_mappings(mappings: &[IdMapping]) -> String {
    mappings
        .iter()
        .map(|mapping| format!("{}->{}", mapping.host, mapping.guest))
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(raw: &str) -> NamespaceName {
        NamespaceName::new(raw).expect("valid namespace name")
    }

    fn set(form: &mut Form, index: usize, value: &str) {
        form.fields[index].value = value.to_owned();
    }

    #[test]
    fn a_choice_field_cycles_and_never_takes_typed_text() {
        let mut form = Form::rule_add(name("p"));
        form.focus = 1;
        assert!(form.focused().is_choice());
        assert_eq!(form.focused().value, "rw");
        form.type_character('x');
        assert_eq!(form.focused().value, "ro", "typing cycles a closed set");
        form.cycle(true);
        assert_eq!(form.focused().value, "hidden");
        form.cycle(true);
        assert_eq!(form.focused().value, "rw", "the set wraps");
        form.cycle(false);
        assert_eq!(form.focused().value, "hidden");
        form.backspace();
        assert_eq!(form.focused().value, "hidden", "a choice cannot be erased");
    }

    #[test]
    fn a_text_field_types_and_erases() {
        let mut form = Form::namespace_create();
        for character in "proj".chars() {
            form.type_character(character);
        }
        form.backspace();
        assert_eq!(form.fields[0].value, "pro");
        form.focus_next(true);
        assert_eq!(form.focus, 1);
        form.focus_next(false);
        assert_eq!(form.focus, 0);
        form.focus_next(false);
        assert_eq!(form.focus, form.fields.len() - 1, "the focus wraps");
    }

    #[test]
    fn namespace_creation_validates_the_name_with_the_shared_type() {
        let mut form = Form::namespace_create();
        set(&mut form, 0, "a/b");
        let error = form.request().expect_err("a name with a separator");
        assert!(error.contains("separator"), "{error}");

        set(&mut form, 0, "project");
        let request = form.request().expect("a valid namespace");
        assert_eq!(
            request,
            Request::NamespaceCreate {
                namespace: NamespaceSpec::new(name("project"))
            }
        );
    }

    #[test]
    fn namespace_creation_carries_the_ownership_mode_it_was_given() {
        let mut form = Form::namespace_create();
        set(&mut form, 0, "project");
        set(&mut form, 3, "static");
        set(&mut form, 4, "1000");
        set(&mut form, 5, "1001");
        let Request::NamespaceCreate { namespace } = form.request().expect("valid") else {
            panic!("expected a create");
        };
        assert_eq!(
            namespace.ownership,
            OwnershipSpec::Static {
                uid: 1000,
                gid: 1001
            }
        );

        set(&mut form, 4, "root");
        let error = form.request().expect_err("an id that is not a number");
        assert!(error.contains("static uid"), "{error}");
    }

    #[test]
    fn a_rule_carries_its_target_only_when_one_was_typed() {
        let mut form = Form::rule_add(name("p"));
        set(&mut form, 0, "/project");
        assert_eq!(
            form.request().expect("valid"),
            Request::RuleAdd {
                namespace: name("p"),
                rule: Rule::new("/project", ShareMode::Rw),
            }
        );
        set(&mut form, 2, "  /srv/project  ");
        assert_eq!(
            form.request().expect("valid"),
            Request::RuleAdd {
                namespace: name("p"),
                rule: Rule::new("/project", ShareMode::Rw).with_target("/srv/project"),
            }
        );
        set(&mut form, 0, "");
        assert!(form.request().is_err(), "a rule needs a path");
    }

    #[test]
    fn the_ownership_editor_round_trips_a_map_policy_through_its_fields() {
        let policy = OwnershipSpec::Map {
            unmapped: UnmappedPolicy::Hide,
            squash_uid: 65534,
            squash_gid: 65533,
            uid_map: vec![
                IdMapping::new(IdSentinel::Uid, 0),
                IdMapping::new(1001, 1000),
            ],
            gid_map: vec![IdMapping::new(IdSentinel::Gid, 0)],
        };
        let form = Form::ownership(name("p"), &policy);
        assert_eq!(form.fields[4].value, "uid->0, 1001->1000");
        assert_eq!(
            form.request().expect("the pre-filled policy is valid"),
            Request::OwnershipSet {
                namespace: name("p"),
                ownership: policy,
            }
        );
    }

    #[test]
    fn a_malformed_map_entry_is_refused_before_the_server_sees_it() {
        let mut form = Form::ownership(name("p"), &OwnershipSpec::default());
        set(&mut form, 0, "map");
        set(&mut form, 4, "uid=0");
        let error = form.request().expect_err("not a pair");
        assert!(error.contains("uid map"), "{error}");

        set(&mut form, 4, "uid->zero");
        let error = form.request().expect_err("not a number");
        assert!(error.contains("uid map"), "{error}");

        set(&mut form, 4, "uid->0,");
        assert!(
            form.request().is_ok(),
            "a trailing separator is not an error"
        );
    }

    #[test]
    fn the_ownership_editor_switches_shape_with_its_mode() {
        let mut form = Form::ownership(name("p"), &OwnershipSpec::default());
        assert_eq!(
            form.request().expect("valid"),
            Request::OwnershipSet {
                namespace: name("p"),
                ownership: OwnershipSpec::Passthrough {},
            }
        );
        set(&mut form, 0, "static");
        set(&mut form, 6, "7");
        set(&mut form, 7, "8");
        assert_eq!(
            form.request().expect("valid"),
            Request::OwnershipSet {
                namespace: name("p"),
                ownership: OwnershipSpec::Static { uid: 7, gid: 8 },
            }
        );
    }

    /// The choice lists and the protocol's own types have to name the same
    /// values, because the form shows a name and sends the type it parses from
    /// it.
    #[test]
    fn every_offered_mode_is_a_mode_the_protocol_defines() {
        for choice in PERMISSION_MODES {
            assert!(
                choice.parse::<PermissionMode>().is_ok(),
                "the create form offers {choice:?}, which the protocol has no mode for"
            );
        }
        for choice in AUTH_MODES {
            assert!(
                choice.parse::<AuthMode>().is_ok(),
                "the create form offers {choice:?}, which the protocol has no mode for"
            );
        }

        let mut form = Form::namespace_create();
        set(&mut form, 0, "project");
        let Request::NamespaceCreate { namespace } = form.request().expect("valid") else {
            panic!("expected a create");
        };
        assert_eq!(namespace.permission.to_string(), form.fields[1].value);
        assert_eq!(namespace.auth.to_string(), form.fields[2].value);

        set(&mut form, 1, "quantum");
        let error = form.request().expect_err("a mode the protocol has not got");
        assert!(error.contains("quantum"), "{error}");
    }

    #[test]
    fn a_form_says_what_it_is() {
        assert_eq!(Form::namespace_create().title(), "Create namespace");
        assert_eq!(Form::rule_add(name("p")).title(), "Add rule to \"p\"");
        assert_eq!(
            Form::ownership(name("p"), &OwnershipSpec::default()).title(),
            "Ownership of \"p\""
        );
    }
}
