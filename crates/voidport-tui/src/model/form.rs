use voidport_control::{
    AuthMode, HostDirectIo, HostId, IdMapping, IdSentinel, NamespaceName, NamespaceSpec,
    OwnershipSpec, PermissionMode, Request, Rule, ShareMode, UnmappedPolicy,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Field {
    pub label: &'static str,
    pub hint: &'static str,
    pub value: String,
    pub choices: &'static [&'static str],
}

impl Field {
    fn text(label: &'static str, hint: &'static str, value: impl Into<String>) -> Self {
        Self {
            label,
            hint,
            value: value.into(),
            choices: &[],
        }
    }

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

    #[must_use]
    pub fn is_choice(&self) -> bool {
        !self.choices.is_empty()
    }

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

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FormKind {
    NamespaceCreate,
    RuleAdd(NamespaceName),
    Ownership(NamespaceName),
}

const SHARE_MODES: &[&str] = &["rw", "ro", "hidden"];
const OWNERSHIP_MODES: &[&str] = &["passthrough", "map", "static"];
const UNMAPPED: &[&str] = &["squash", "hide", "passthrough"];
pub const PERMISSION_MODES: &[&str] = &["passthrough"];
pub const AUTH_MODES: &[&str] = &["none"];

/// A form in progress survives a reconnect. Its eventual submit is judged by
/// the server like any mutation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Form {
    pub kind: FormKind,
    pub fields: Vec<Field>,
    pub focus: usize,
    pub error: Option<String>,
}

impl Form {
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

    /// Pre-filled with the policy of the server: the operation replaces the
    /// policy whole, so the operator must see what is replaced.
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

    fn new(kind: FormKind, fields: Vec<Field>) -> Self {
        Self {
            kind,
            fields,
            focus: 0,
            error: None,
        }
    }

    #[must_use]
    pub fn title(&self) -> String {
        match &self.kind {
            FormKind::NamespaceCreate => "Create namespace".to_owned(),
            FormKind::RuleAdd(namespace) => format!("Add rule to \"{namespace}\""),
            FormKind::Ownership(namespace) => format!("Ownership of \"{namespace}\""),
        }
    }

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

    #[must_use]
    pub fn focused(&self) -> &Field {
        &self.fields[self.focus]
    }

    pub fn type_character(&mut self, character: char) {
        let field = &mut self.fields[self.focus];
        if field.is_choice() {
            field.cycle(true);
        } else {
            field.value.push(character);
        }
    }

    pub fn backspace(&mut self) {
        let field = &mut self.fields[self.focus];
        if !field.is_choice() {
            field.value.pop();
        }
    }

    pub fn cycle(&mut self, forward: bool) {
        self.fields[self.focus].cycle(forward);
    }

    fn value(&self, index: usize) -> &str {
        self.fields[index].value.trim()
    }

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
                // Parsed back from what the choice fields show, because a hardcoded variant
                // would stop matching the screen once a second one is defined.
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
                        direct_io: HostDirectIo::default(),
                        auth,
                        ownership,
                        // A create takes the default; the switch has an operation of its own.
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

fn number(value: &str, field: &str) -> Result<u32, String> {
    value
        .parse()
        .map_err(|_| format!("{field}: {value:?} is not a number"))
}

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

    /// The choice lists and the protocol types must list the same values,
    /// because the form sends the type parsed from the shown name.
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
