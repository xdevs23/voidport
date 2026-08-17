//! Human-readable rendering of a response.
//!
//! `--json` is the machine interface and prints the server's line verbatim;
//! this module is the other one, for a person at a terminal. It renders the
//! *source form* of a namespace the way the state file spells it, so what an
//! operator reads here and what they would write in the file are the same
//! vocabulary.

use voidport_control::{
    IdMapping, ListenerInfo, NamespaceSpec, OwnershipSpec, Reply, Response, Rule, SessionSummary,
    XattrRule, XattrVerdict,
};

/// Renders a response envelope for a terminal.
#[must_use]
pub fn render(response: &Response) -> String {
    match response {
        Response::Ok { result } => render_reply(result),
        Response::Error { error } => format!("error [{}]: {}", error.code, error.message),
    }
}

/// Renders a successful reply.
fn render_reply(reply: &Reply) -> String {
    match reply {
        Reply::Done {} => "ok".to_owned(),
        Reply::ServerInfo {
            version,
            state_file,
            control_socket,
            namespaces,
            listeners,
            node_descriptors,
            node_descriptor_budget,
            log_file,
        } => [
            format!("version:        {version}"),
            format!("state file:     {state_file}"),
            format!("control socket: {control_socket}"),
            format!("namespaces:     {namespaces}"),
            format!("listeners:      {}", render_listeners(listeners)),
            format!("node fd cache:  {node_descriptors} / {node_descriptor_budget}"),
            // A server logging to its own stderr names no file, which is a
            // fact about that server, not a blank.
            format!(
                "log file:       {}",
                log_file.as_deref().unwrap_or("none (stderr)")
            ),
        ]
        .join("\n"),
        Reply::NamespaceList { namespaces } => {
            if namespaces.is_empty() {
                return "no namespaces".to_owned();
            }
            let mut lines = vec![format!(
                "{:<24} {:<12} {:<12} {:<12} {:<6} {}",
                "NAME", "OWNERSHIP", "PERMISSION", "DIRECT-IO", "AUTH", "RULES"
            )];
            lines.extend(namespaces.iter().map(|namespace| {
                format!(
                    "{:<24} {:<12} {:<12} {:<12} {:<6} {}",
                    namespace.name,
                    namespace.ownership,
                    namespace.permission,
                    namespace.direct_io,
                    namespace.auth,
                    namespace.rules
                )
            }));
            lines.join("\n")
        }
        Reply::Namespace { namespace } => render_namespace(namespace),
        Reply::SessionList { sessions } => render_sessions(sessions),
        // The endpoint as bound, which is also the name `listener remove`
        // takes — for a `:0` configuration this is the only statement of the
        // port anywhere.
        Reply::Listener { listener } => format!("listening on {listener}"),
    }
}

/// Renders `listener list`, which asks `server-info` and reports one line per
/// endpoint.
///
/// It is a rendering, not an operation of its own: the server already
/// answers where it is serving, so listing reuses that answer and shows only
/// the part the operator asked about.
#[must_use]
pub fn render_listener_list(response: &Response) -> String {
    let Response::Ok {
        result: Reply::ServerInfo { listeners, .. },
    } = response
    else {
        return render(response);
    };
    if listeners.is_empty() {
        return "no listeners — this server serves only its control socket".to_owned();
    }
    listeners
        .iter()
        .map(ListenerInfo::to_string)
        .collect::<Vec<_>>()
        .join("\n")
}

/// Renders the bound data-plane endpoints as one line of `info`.
fn render_listeners(listeners: &[ListenerInfo]) -> String {
    if listeners.is_empty() {
        return "none".to_owned();
    }
    listeners
        .iter()
        .map(ListenerInfo::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// Renders the live data-plane sessions, one per line.
fn render_sessions(sessions: &[SessionSummary]) -> String {
    if sessions.is_empty() {
        return "no sessions".to_owned();
    }
    let mut lines = vec![format!(
        "{:<6} {:<24} {:<24} {:<6} {:<24} {:>7} {:>8} {:>10}",
        "ID", "NAMESPACE", "SUBPATH", "VIA", "PEER", "NODES", "HANDLES", "SUBSCRIBED"
    )];
    lines.extend(sessions.iter().map(|session| {
        format!(
            "{:<6} {:<24} {:<24} {:<6} {:<24} {:>7} {:>8} {:>10}",
            session.id,
            session.namespace,
            session.subpath,
            session.transport,
            session.peer,
            session.nodes,
            session.handles,
            if session.subscribed { "yes" } else { "no" }
        )
    }));
    lines.join("\n")
}

/// Renders one namespace in its source form.
fn render_namespace(namespace: &NamespaceSpec) -> String {
    let mut lines = vec![
        format!("namespace:  {}", namespace.name),
        format!("permission: {}", namespace.permission),
        format!("direct-io:  {}", namespace.direct_io),
        format!("auth:       {}", namespace.auth),
    ];
    lines.extend(render_ownership(&namespace.ownership));
    if namespace.rules.is_empty() {
        lines.push("rules:      none".to_owned());
    } else {
        lines.push("rules:".to_owned());
        lines.extend(namespace.rules.iter().map(render_rule));
    }
    if namespace.xattr.is_empty() {
        // What "none" means needs one word: the defaults are not "nothing
        // is allowed", they are read everything and write `user.*`.
        lines.push("attributes: none (read all, write user.*)".to_owned());
    } else {
        lines.push("attributes:".to_owned());
        lines.extend(namespace.xattr.iter().map(render_xattr_rule));
    }
    lines.join("\n")
}

/// Renders one extended-attribute rule: its match, and the verdicts it states.
///
/// An unstated verdict is shown as `-`, not as a value, because the
/// difference is the whole of the fall-through rule — a rule that says nothing
/// about reads is not a rule that allows them.
fn render_xattr_rule(rule: &XattrRule) -> String {
    let verdict = |stated: Option<XattrVerdict>| {
        stated.map_or_else(|| "-".to_owned(), |verdict| verdict.to_string())
    };
    format!(
        "  {:<32} read {:<6} write {}",
        rule.r#match,
        verdict(rule.read),
        verdict(rule.write)
    )
}

/// Renders the ownership policy, one line per configured fact.
fn render_ownership(ownership: &OwnershipSpec) -> Vec<String> {
    let mut lines = vec![format!("ownership:  {}", ownership.mode())];
    match ownership {
        OwnershipSpec::Passthrough {} => {}
        OwnershipSpec::Static { uid, gid } => {
            lines.push(format!("  static:   uid {uid}, gid {gid}"));
        }
        OwnershipSpec::Map {
            unmapped,
            squash_uid,
            squash_gid,
            uid_map,
            gid_map,
        } => {
            lines.push(format!("  unmapped: {unmapped}"));
            lines.push(format!("  squash:   uid {squash_uid}, gid {squash_gid}"));
            lines.push(format!("  uid map:  {}", render_mappings(uid_map)));
            lines.push(format!("  gid map:  {}", render_mappings(gid_map)));
        }
    }
    lines
}

/// Renders an id table as `host -> guest` pairs.
fn render_mappings(mappings: &[IdMapping]) -> String {
    if mappings.is_empty() {
        return "empty".to_owned();
    }
    mappings
        .iter()
        .map(|mapping| format!("{} -> {}", mapping.host, mapping.guest))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Renders one rule, showing a match and a target only where one is
/// configured.
///
/// The key is [`Rule::key`], the protocol's own spelling of the pair that
/// identifies a rule, so what is listed is what removes it.
fn render_rule(rule: &Rule) -> String {
    let key = rule.key().to_string();
    match &rule.target {
        Some(target) => format!("  {:<6} {key:<32} -> {target}", rule.mode),
        None => format!("  {:<6} {key}", rule.mode),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use voidport_control::{
        AuthMode, ControlError, ErrorCode, HostDirectIo, IdSentinel, NamespaceName,
        NamespaceSummary, OwnershipMode, PermissionMode, ShareMode, UnmappedPolicy,
    };

    fn name(raw: &str) -> NamespaceName {
        NamespaceName::new(raw).expect("valid namespace name")
    }

    #[test]
    fn an_error_names_its_code_and_message() {
        let rendered = render(&Response::error(ControlError::new(
            ErrorCode::NotFound,
            "no namespace \"p\"",
        )));
        assert_eq!(rendered, "error [not-found]: no namespace \"p\"");
    }

    #[test]
    fn a_mutation_renders_as_ok() {
        assert_eq!(render(&Response::ok(Reply::Done {})), "ok");
    }

    #[test]
    fn server_info_lists_the_facts() {
        let rendered = render(&Response::ok(Reply::ServerInfo {
            version: "0.1.0".to_owned(),
            state_file: "/srv/state.toml".to_owned(),
            control_socket: "/run/control.sock".to_owned(),
            namespaces: 2,
            listeners: vec![ListenerInfo::new("tcp", "127.0.0.1:9000")],
            node_descriptors: 12,
            node_descriptor_budget: 4096,
            log_file: Some("/srv/voidportd.log".to_owned()),
        }));
        assert!(rendered.contains("version:        0.1.0"), "{rendered}");
        assert!(rendered.contains("/srv/state.toml"), "{rendered}");
        assert!(rendered.contains("/run/control.sock"), "{rendered}");
        assert!(rendered.contains("namespaces:     2"), "{rendered}");
        assert!(
            rendered.contains("listeners:      tcp 127.0.0.1:9000"),
            "{rendered}"
        );
        assert!(rendered.contains("node fd cache:  12 / 4096"), "{rendered}");
        assert!(
            rendered.contains("log file:       /srv/voidportd.log"),
            "{rendered}"
        );

        let quiet = render(&Response::ok(Reply::ServerInfo {
            version: "0.1.0".to_owned(),
            state_file: "/srv/state.toml".to_owned(),
            control_socket: "/run/control.sock".to_owned(),
            namespaces: 0,
            listeners: Vec::new(),
            node_descriptors: 0,
            node_descriptor_budget: 4096,
            log_file: None,
        }));
        assert!(quiet.contains("listeners:      none"), "{quiet}");
        assert!(quiet.contains("log file:       none (stderr)"), "{quiet}");
    }

    #[test]
    fn a_list_has_a_header_and_a_line_per_namespace() {
        let empty = render(&Response::ok(Reply::NamespaceList {
            namespaces: Vec::new(),
        }));
        assert_eq!(empty, "no namespaces");

        let rendered = render(&Response::ok(Reply::NamespaceList {
            namespaces: vec![NamespaceSummary {
                name: name("project"),
                ownership: OwnershipMode::Map,
                permission: PermissionMode::Passthrough,
                direct_io: HostDirectIo::Passthrough,
                auth: AuthMode::None,
                rules: 3,
            }],
        }));
        let lines: Vec<&str> = rendered.lines().collect();
        assert!(lines[0].starts_with("NAME"), "{rendered}");
        assert!(lines[0].contains("DIRECT-IO"), "{rendered}");
        assert!(lines[1].starts_with("project"), "{rendered}");
        assert!(lines[1].contains("map"), "{rendered}");
        assert!(lines[1].contains("passthrough"), "{rendered}");
        assert!(lines[1].ends_with('3'), "{rendered}");
    }

    #[test]
    fn sessions_render_one_line_each() {
        let empty = render(&Response::ok(Reply::SessionList {
            sessions: Vec::new(),
        }));
        assert_eq!(empty, "no sessions");

        let rendered = render(&Response::ok(Reply::SessionList {
            sessions: vec![SessionSummary {
                id: 3,
                namespace: name("project"),
                subpath: "/project".to_owned(),
                transport: "tcp".to_owned(),
                peer: "127.0.0.1:40404".to_owned(),
                nodes: 12,
                handles: 2,
                subscribed: true,
            }],
        }));
        let lines: Vec<&str> = rendered.lines().collect();
        assert!(lines[0].starts_with("ID"), "{rendered}");
        assert!(lines[1].contains("project"), "{rendered}");
        assert!(lines[1].contains("127.0.0.1:40404"), "{rendered}");
        assert!(lines[0].contains("SUBSCRIBED"), "{rendered}");
        assert!(lines[1].ends_with("yes"), "{rendered}");
    }

    #[test]
    fn a_namespace_renders_its_whole_source_form() {
        let rendered = render(&Response::ok(Reply::Namespace {
            namespace: NamespaceSpec {
                name: name("project"),
                permission: PermissionMode::Passthrough,
                direct_io: HostDirectIo::Always,
                auth: AuthMode::None,
                ownership: OwnershipSpec::Map {
                    unmapped: UnmappedPolicy::Hide,
                    squash_uid: 65534,
                    squash_gid: 65534,
                    uid_map: vec![IdMapping::new(IdSentinel::Uid, 0)],
                    gid_map: Vec::new(),
                },
                rules: vec![
                    Rule::new("/project", ShareMode::Rw).with_target("project"),
                    Rule::new("/project/*", ShareMode::Hidden),
                ],
                xattr: vec![
                    XattrRule::new("user.*")
                        .with_read(XattrVerdict::Allow)
                        .with_write(XattrVerdict::Deny),
                    XattrRule::new("security.*").with_read(XattrVerdict::Deny),
                ],
            },
        }));
        assert!(rendered.contains("namespace:  project"), "{rendered}");
        assert!(rendered.contains("direct-io:  always"), "{rendered}");
        assert!(rendered.contains("ownership:  map"), "{rendered}");
        assert!(rendered.contains("unmapped: hide"), "{rendered}");
        // The sentinel is shown as written, never resolved.
        assert!(rendered.contains("uid -> 0"), "{rendered}");
        assert!(rendered.contains("gid map:  empty"), "{rendered}");
        assert!(rendered.contains("-> project"), "{rendered}");
        assert!(rendered.contains("hidden /project/*"), "{rendered}");
        assert!(rendered.contains("attributes:"), "{rendered}");
        assert!(
            rendered.contains("user.*                           read allow  write deny"),
            "{rendered}"
        );
        // An unstated verdict reads as unstated, not as a value.
        assert!(
            rendered.contains("security.*                       read deny   write -"),
            "{rendered}"
        );
    }

    #[test]
    fn the_simpler_ownership_modes_render_too() {
        let passthrough = render(&Response::ok(Reply::Namespace {
            namespace: NamespaceSpec::new(name("p")),
        }));
        assert!(
            passthrough.contains("ownership:  passthrough"),
            "{passthrough}"
        );
        assert!(passthrough.contains("rules:      none"), "{passthrough}");
        assert!(
            passthrough.contains("attributes: none (read all, write user.*)"),
            "{passthrough}"
        );

        let fixed = render(&Response::ok(Reply::Namespace {
            namespace: NamespaceSpec {
                ownership: OwnershipSpec::Static { uid: 1, gid: 2 },
                ..NamespaceSpec::new(name("p"))
            },
        }));
        assert!(fixed.contains("static:   uid 1, gid 2"), "{fixed}");
    }
}
