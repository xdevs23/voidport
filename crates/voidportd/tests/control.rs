//! The control plane against a live server: every operation over a real unix
//! socket, the protocol's error behaviour, the mutation contract, and the
//! socket bind/unlink contract.

mod support;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::time::Duration;

use support::{RunningServer, TempDir, daemon_config, environment};
use voidport_control::{
    AuthMode, ErrorCode, IdMapping, IdSentinel, NamespaceName, NamespaceSpec, OwnershipSpec,
    PermissionMode, Reply, Request, Response, Rule, ShareMode, UnmappedPolicy, XattrRule,
    XattrVerdict,
};
use voidportd::control::{CONTROL_SOCKET_MODE, ControlSocket, MAX_REQUEST_LINE, socket::BindError};
use voidportd::daemon::{DaemonConfig, StartupError};
use voidportd::state::load_document;
use voidportd::testing::create_directory;

/// A state file with one namespace, ready to be mutated.
const STATE: &str = r#"
[[namespaces]]
name = "project"

[[namespaces.rules]]
path = "/project"
mode = "rw"
target = "project"
"#;

/// A temporary directory holding the graft targets the state file and the
/// mutations below name. Graft targets are pinned when a namespace is built,
/// so they exist before the server does.
fn temp(label: &str) -> TempDir {
    let directory = TempDir::new(label);
    for target in ["project", "data", "elsewhere"] {
        directory.directory(target);
    }
    directory
}

fn name(raw: &str) -> NamespaceName {
    NamespaceName::new(raw).expect("valid namespace name")
}

/// A state file whose one namespace is far too big to answer in one socket
/// buffer, so that a client which stops reading blocks the server mid-write.
fn state_with_many_rules(count: usize) -> String {
    let mut state = String::from(STATE);
    for index in 0..count {
        state.push_str(&format!(
            "\n[[namespaces.rules]]\npath = \"/project/file-{index:05}\"\nmode = \"ro\"\n"
        ));
    }
    state
}

/// Starts a server on a state file inside a fresh temporary directory.
fn server(directory: &TempDir, state: &str) -> RunningServer {
    let state_file = directory.write("state.toml", state);
    let config = daemon_config(&state_file, environment(directory.path()));
    RunningServer::start(&config).expect("the server starts")
}

/// A server launched with its tracing pointed at a file reports that file.
///
/// It is the only way an operator attached to a server they did not launch can
/// learn where its diagnostics land — the state file does not say, and the
/// destination was chosen by the process, not by the configuration.
#[test]
fn a_server_reports_the_log_file_it_was_launched_with() {
    let directory = temp("log-file");
    let state_file = directory.write("state.toml", STATE);
    let log = directory.join("voidportd.log");
    let config = daemon_config(&state_file, environment(directory.path())).with_log_file(&log);
    let server = RunningServer::start(&config).expect("the server starts");

    let Reply::ServerInfo { log_file, .. } = server.connect().expect_ok(&Request::ServerInfo {})
    else {
        panic!("expected server info");
    };
    assert_eq!(
        log_file.as_deref(),
        Some(log.display().to_string().as_str())
    );
}

#[test]
fn every_operation_works_over_the_socket() {
    let directory = temp("operations");
    let server = server(&directory, STATE);
    let mut client = server.connect();

    // server-info
    let Reply::ServerInfo {
        version,
        state_file,
        control_socket,
        namespaces,
        listeners,
        node_descriptors,
        node_descriptor_budget,
        log_file,
    } = client.expect_ok(&Request::ServerInfo {})
    else {
        panic!("expected server info");
    };
    assert_eq!(version, env!("CARGO_PKG_VERSION"));
    assert_eq!(Path::new(&state_file), directory.join("state.toml"));
    assert_eq!(Path::new(&control_socket), server.socket());
    assert_eq!(namespaces, 1);
    // This state file configures no data listener, and a server with none is
    // legal: it serves its control socket and waits to be given one.
    assert!(listeners.is_empty(), "{listeners:?}");
    // The descriptor cache is reported read-only, and a server with no session
    // holds nothing in it.
    assert_eq!(node_descriptors, 0);
    assert!(node_descriptor_budget >= 4096, "{node_descriptor_budget}");
    // This launch was not told a log file, so it names none: a server logging
    // to its own stderr is a fact about that server, not a blank field.
    assert_eq!(log_file, None);

    // namespace-create
    client.expect_ok(&Request::NamespaceCreate {
        namespace: NamespaceSpec::new(name("scratch")),
    });

    // namespace-list
    let Reply::NamespaceList { namespaces } = client.expect_ok(&Request::NamespaceList {}) else {
        panic!("expected a namespace list");
    };
    let listed: Vec<&str> = namespaces
        .iter()
        .map(|namespace| namespace.name.as_str())
        .collect();
    assert_eq!(listed, ["project", "scratch"]);

    // rule-add, twice: a graft and a per-directory default
    client.expect_ok(&Request::RuleAdd {
        namespace: name("scratch"),
        rule: Rule::new("/data", ShareMode::Ro).with_target("data"),
    });
    client.expect_ok(&Request::RuleAdd {
        namespace: name("scratch"),
        rule: Rule::new("/data/*", ShareMode::Hidden),
    });

    // xattr-add, twice: the layering pair the design's precedence rests on
    client.expect_ok(&Request::XattrAdd {
        namespace: name("scratch"),
        rule: XattrRule::new("user.*").with_write(XattrVerdict::Deny),
    });
    client.expect_ok(&Request::XattrAdd {
        namespace: name("scratch"),
        rule: XattrRule::new("user.build.id").with_write(XattrVerdict::Allow),
    });
    // A rule is keyed by its match, so the same match twice is refused, not
    // merged — at the boundary, before anything is persisted.
    let duplicate = client.expect_error(&Request::XattrAdd {
        namespace: name("scratch"),
        rule: XattrRule::new("user.*").with_read(XattrVerdict::Deny),
    });
    assert_eq!(duplicate.code, ErrorCode::AlreadyExists);
    assert!(duplicate.message.contains("user.*"), "{duplicate}");
    // And so is a match longer than an attribute name can be.
    let oversized = client.expect_error(&Request::XattrAdd {
        namespace: name("scratch"),
        rule: XattrRule::new("u".repeat(256)),
    });
    assert_eq!(oversized.code, ErrorCode::InvalidConfiguration);
    assert!(oversized.message.contains("255"), "{oversized}");
    // A rule stating neither verdict decides nothing and would hold its match
    // against a rule that does; it is refused at the same boundary.
    let silent = client.expect_error(&Request::XattrAdd {
        namespace: name("scratch"),
        rule: XattrRule::new("user.silent"),
    });
    assert_eq!(silent.code, ErrorCode::InvalidConfiguration);
    assert!(silent.message.contains("user.silent"), "{silent}");

    // ownership-set
    client.expect_ok(&Request::OwnershipSet {
        namespace: name("scratch"),
        ownership: OwnershipSpec::Map {
            unmapped: UnmappedPolicy::Hide,
            squash_uid: 65534,
            squash_gid: 65534,
            uid_map: vec![IdMapping::new(IdSentinel::Uid, 0)],
            gid_map: vec![IdMapping::new(IdSentinel::Gid, 0)],
        },
    });

    // permission-set and auth-set
    client.expect_ok(&Request::PermissionSet {
        namespace: name("scratch"),
        mode: PermissionMode::Passthrough,
    });
    client.expect_ok(&Request::AuthSet {
        namespace: name("scratch"),
        mode: AuthMode::None,
    });

    // namespace-show returns the source form, sentinels intact
    let Reply::Namespace { namespace } = client.expect_ok(&Request::NamespaceShow {
        name: name("scratch"),
    }) else {
        panic!("expected a namespace");
    };
    assert_eq!(namespace.rules.len(), 2);
    assert_eq!(
        namespace.xattr,
        vec![
            XattrRule::new("user.*").with_write(XattrVerdict::Deny),
            XattrRule::new("user.build.id").with_write(XattrVerdict::Allow),
        ],
        "the refused rules touched neither memory nor file"
    );
    assert_eq!(
        namespace.ownership,
        OwnershipSpec::Map {
            unmapped: UnmappedPolicy::Hide,
            squash_uid: 65534,
            squash_gid: 65534,
            uid_map: vec![IdMapping::new(IdSentinel::Uid, 0)],
            gid_map: vec![IdMapping::new(IdSentinel::Gid, 0)],
        }
    );

    // rule-remove
    client.expect_ok(&Request::RuleRemove {
        namespace: name("scratch"),
        path: "/data/*".to_owned(),
        r#match: None,
    });
    let Reply::Namespace { namespace } = client.expect_ok(&Request::NamespaceShow {
        name: name("scratch"),
    }) else {
        panic!("expected a namespace");
    };
    assert_eq!(namespace.rules.len(), 1);

    // xattr-remove, keyed by the match alone
    client.expect_ok(&Request::XattrRemove {
        namespace: name("scratch"),
        r#match: "user.build.id".to_owned(),
    });
    let gone = client.expect_error(&Request::XattrRemove {
        namespace: name("scratch"),
        r#match: "user.build.id".to_owned(),
    });
    assert_eq!(gone.code, ErrorCode::NotFound);
    let Reply::Namespace { namespace } = client.expect_ok(&Request::NamespaceShow {
        name: name("scratch"),
    }) else {
        panic!("expected a namespace");
    };
    assert_eq!(
        namespace.xattr,
        vec![XattrRule::new("user.*").with_write(XattrVerdict::Deny)]
    );

    // namespace-delete
    client.expect_ok(&Request::NamespaceDelete {
        name: name("scratch"),
    });
    let error = client.expect_error(&Request::NamespaceShow {
        name: name("scratch"),
    });
    assert_eq!(error.code, ErrorCode::NotFound);

    // Everything above is on disk, in the source form.
    let document = load_document(&directory.join("state.toml")).expect("the file parses");
    assert_eq!(document.namespaces.len(), 1);
    assert_eq!(document, server.service().snapshot().document);
}

#[test]
fn operations_naming_absent_things_are_refused() {
    let directory = temp("absent");
    let server = server(&directory, STATE);
    let mut client = server.connect();

    for request in [
        Request::NamespaceShow { name: name("nope") },
        Request::NamespaceDelete { name: name("nope") },
        Request::RuleAdd {
            namespace: name("nope"),
            rule: Rule::new("/a", ShareMode::Hidden),
        },
        Request::RuleRemove {
            namespace: name("nope"),
            path: "/a".to_owned(),
            r#match: None,
        },
        Request::PermissionSet {
            namespace: name("nope"),
            mode: PermissionMode::Passthrough,
        },
        Request::AuthSet {
            namespace: name("nope"),
            mode: AuthMode::None,
        },
        Request::OwnershipSet {
            namespace: name("nope"),
            ownership: OwnershipSpec::default(),
        },
        Request::RuleRemove {
            namespace: name("project"),
            path: "/absent".to_owned(),
            r#match: None,
        },
    ] {
        assert_eq!(client.expect_error(&request).code, ErrorCode::NotFound);
    }

    assert_eq!(
        client
            .expect_error(&Request::NamespaceCreate {
                namespace: NamespaceSpec::new(name("project")),
            })
            .code,
        ErrorCode::AlreadyExists
    );
    for duplicate in ["/project", "//project/"] {
        assert_eq!(
            client
                .expect_error(&Request::RuleAdd {
                    namespace: name("project"),
                    rule: Rule::new(duplicate, ShareMode::Ro).with_target("elsewhere"),
                })
                .code,
            ErrorCode::AlreadyExists
        );
    }
}

#[test]
fn malformed_json_and_unknown_operations_leave_the_connection_alive() {
    let directory = temp("protocol-errors");
    let server = server(&directory, STATE);
    let mut client = server.connect();

    let malformed: Response =
        serde_json::from_str(&client.send_line(b"not json at all").expect("an answer"))
            .expect("an envelope");
    assert_eq!(
        malformed.as_error().map(|error| error.code),
        Some(ErrorCode::MalformedRequest)
    );

    let unknown: Response = serde_json::from_str(
        &client
            .send_line(br#"{"op":"do-the-thing"}"#)
            .expect("an answer"),
    )
    .expect("an envelope");
    assert_eq!(
        unknown.as_error().map(|error| error.code),
        Some(ErrorCode::UnknownOperation)
    );

    let invalid: Response = serde_json::from_str(
        &client
            .send_line(br#"{"op":"namespace-show","nmae":"project"}"#)
            .expect("an answer"),
    )
    .expect("an envelope");
    assert_eq!(
        invalid.as_error().map(|error| error.code),
        Some(ErrorCode::InvalidRequest)
    );

    // The connection survived all three, and still works.
    let Reply::ServerInfo { namespaces, .. } = client.expect_ok(&Request::ServerInfo {}) else {
        panic!("expected server info");
    };
    assert_eq!(namespaces, 1);
}

#[test]
fn an_empty_line_is_answered_like_any_other_malformed_input() {
    let directory = temp("empty-line");
    let server = server(&directory, STATE);
    let mut client = server.connect();

    // One line in, one line out — a client that pipelines must never have to
    // guess which request an answer belongs to.
    for _ in 0..2 {
        let empty: Response =
            serde_json::from_str(&client.send_line(b"").expect("an answer")).expect("an envelope");
        assert_eq!(
            empty.as_error().map(|error| error.code),
            Some(ErrorCode::MalformedRequest)
        );
    }

    let Reply::ServerInfo { namespaces, .. } = client.expect_ok(&Request::ServerInfo {}) else {
        panic!("expected server info");
    };
    assert_eq!(namespaces, 1);
}

#[test]
fn an_oversized_line_is_answered_and_then_the_connection_closes() {
    let directory = temp("oversized");
    let server = server(&directory, STATE);
    let mut client = server.connect();

    let mut line = Vec::with_capacity(MAX_REQUEST_LINE + 32);
    line.extend_from_slice(br#"{"op":"namespace-show","name":""#);
    line.resize(MAX_REQUEST_LINE + 16, b'x');
    let answer = client.send_raw(&line).expect("an answer before the close");
    let response: Response = serde_json::from_str(&answer).expect("an envelope");
    assert_eq!(
        response.as_error().map(|error| error.code),
        Some(ErrorCode::RequestTooLarge)
    );
    assert_eq!(client.read_line(), None, "the connection must close");

    // The server itself is unharmed: a new connection works.
    let mut next = server.connect();
    next.expect_ok(&Request::NamespaceList {});
}

#[test]
fn a_line_at_the_bound_is_still_served_with_lf_or_crlf() {
    for crlf in [false, true] {
        let directory = temp("at-the-bound");
        let server = server(&directory, STATE);
        let mut client = server.connect();

        // A syntactically valid request padded with spaces to exactly the
        // content bound. The terminator is framing, not content.
        let mut line = br#"{"op":"namespace-list"}"#.to_vec();
        line.resize(MAX_REQUEST_LINE, b' ');
        let answer = if crlf {
            line.extend_from_slice(b"\r\n");
            client.send_raw(&line).expect("an answer")
        } else {
            client.send_line(&line).expect("an answer")
        };
        let response: Response = serde_json::from_str(&answer).expect("an envelope");
        assert!(response.as_error().is_none(), "{response:?}");
    }
}

#[test]
fn a_rejected_mutation_changes_neither_memory_nor_file() {
    let directory = temp("rejected");
    let server = server(&directory, STATE);
    let mut client = server.connect();
    let before = fs::read_to_string(directory.join("state.toml")).expect("readable");

    client.expect_ok(&Request::RuleAdd {
        namespace: name("project"),
        rule: Rule::new("/project/secret", ShareMode::Hidden),
    });
    let after_valid = fs::read_to_string(directory.join("state.toml")).expect("readable");

    // Dead configuration: a rule beneath a hidden rule can never be reached.
    let error = client.expect_error(&Request::RuleAdd {
        namespace: name("project"),
        rule: Rule::new("/project/secret/key", ShareMode::Ro),
    });
    assert_eq!(error.code, ErrorCode::InvalidConfiguration);
    assert!(error.message.contains("project"), "{error}");
    assert!(error.message.contains("/project/secret/key"), "{error}");

    // Neither the file nor memory moved.
    assert_eq!(
        fs::read_to_string(directory.join("state.toml")).expect("readable"),
        after_valid
    );
    assert_ne!(after_valid, before, "the accepted mutation did land");
    let Reply::Namespace { namespace } = client.expect_ok(&Request::NamespaceShow {
        name: name("project"),
    }) else {
        panic!("expected a namespace");
    };
    assert!(namespace.rule("/project/secret/key").is_none());
    assert!(namespace.rule("/project/secret").is_some());
}

/// Criterion 1 and 3 at the control-plane boundary: a pattern rule adds,
/// persists, shows and removes by its `(path, match)` key, and every refusal
/// the design lists is answered as a typed error that changes nothing.
#[test]
fn pattern_rules_add_persist_and_remove_by_path_and_match() {
    let directory = temp("patterns");
    let server = server(&directory, STATE);
    let mut client = server.connect();

    // The motivating composition: hide the graft's children, un-hide a family.
    client.expect_ok(&Request::RuleAdd {
        namespace: name("project"),
        rule: Rule::new("/project/*", ShareMode::Hidden),
    });
    client.expect_ok(&Request::RuleAdd {
        namespace: name("project"),
        rule: Rule::new("/project", ShareMode::Rw).with_match("project-*"),
    });
    // A second, disjoint match on the same directory is a second rule.
    client.expect_ok(&Request::RuleAdd {
        namespace: name("project"),
        rule: Rule::new("/project", ShareMode::Ro).with_match("docs-*"),
    });

    // Both are on disk in source form, keyed by the pair.
    let document = load_document(&directory.join("state.toml")).expect("the file parses");
    let namespace = document.namespace(&name("project")).expect("the namespace");
    let patterns: Vec<(&str, String)> = namespace
        .rules
        .iter()
        .filter_map(|rule| {
            rule.r#match
                .as_deref()
                .map(|matches| (matches, rule.mode.to_string()))
        })
        .collect();
    assert_eq!(
        patterns,
        [("project-*", "rw".to_owned()), ("docs-*", "ro".to_owned())]
    );

    // Every refusal the design lists, at add time.
    let refusals = [
        (
            "a target",
            Rule::new("/project", ShareMode::Rw)
                .with_match("build-*")
                .with_target("elsewhere"),
        ),
        (
            "only stars",
            Rule::new("/project", ShareMode::Rw).with_match("**"),
        ),
        (
            "an overlapping match",
            Rule::new("/project", ShareMode::Ro).with_match("*-one"),
        ),
        (
            "a directory nothing grafts",
            Rule::new("/elsewhere", ShareMode::Ro).with_match("x-*"),
        ),
        (
            "a hidden literal above it",
            Rule::new("/project/vanished", ShareMode::Ro).with_match("x-*"),
        ),
    ];
    client.expect_ok(&Request::RuleAdd {
        namespace: name("project"),
        rule: Rule::new("/project/vanished", ShareMode::Hidden),
    });
    for (why, rule) in refusals {
        let error = client.expect_error(&Request::RuleAdd {
            namespace: name("project"),
            rule,
        });
        assert_eq!(
            error.code,
            ErrorCode::InvalidConfiguration,
            "{why}: nothing exists twice, so this is not an already-exists"
        );
    }
    // The overlap refusal names both rules, which is what tells an operator
    // which pair to reconcile.
    let overlap = client.expect_error(&Request::RuleAdd {
        namespace: name("project"),
        rule: Rule::new("/project", ShareMode::Ro).with_match("project-a*"),
    });
    assert!(overlap.message.contains("project-*"), "{overlap}");
    assert!(overlap.message.contains("project-a*"), "{overlap}");
    assert!(overlap.message.contains("/project"), "{overlap}");

    // Re-adding the same `(path, match)` is the duplicate it is.
    assert_eq!(
        client
            .expect_error(&Request::RuleAdd {
                namespace: name("project"),
                rule: Rule::new("//project/", ShareMode::Ro).with_match("project-*"),
            })
            .code,
        ErrorCode::AlreadyExists
    );

    // Removal names both fields: the match picks which of the two it is, and
    // omitting it names no pattern rule at all.
    assert_eq!(
        client
            .expect_error(&Request::RuleRemove {
                namespace: name("project"),
                path: "/project".to_owned(),
                r#match: Some("absent-*".to_owned()),
            })
            .code,
        ErrorCode::NotFound
    );
    client.expect_ok(&Request::RuleRemove {
        namespace: name("project"),
        path: "/project".to_owned(),
        r#match: Some("project-*".to_owned()),
    });
    let Reply::Namespace { namespace } = client.expect_ok(&Request::NamespaceShow {
        name: name("project"),
    }) else {
        panic!("expected a namespace");
    };
    let left: Vec<Option<&str>> = namespace
        .rules
        .iter()
        .map(|rule| rule.r#match.as_deref())
        .collect();
    assert_eq!(
        left,
        [None, None, Some("docs-*"), None],
        "exactly the named pattern rule went, and the literal rule at the same \
         path stayed"
    );
    assert!(
        namespace
            .rule("/project")
            .is_some_and(|rule| rule.keyed_by("/project", None)),
        "the literal rule at that path is untouched: {:?}",
        namespace.rules
    );
}

#[test]
fn a_persist_failure_publishes_nothing() {
    let directory = temp("persist-failure");
    // The state file lives in its own directory so it can be taken away
    // without disturbing the control socket.
    let state_file = directory.write("state/state.toml", STATE);
    // Not the shared assembly: that one puts the socket beside the state file,
    // and this test takes the state file's whole directory away.
    let config = DaemonConfig::new(&state_file)
        .with_control_socket(directory.join("control.sock"))
        .with_environment(environment(directory.path()));
    let server = RunningServer::start(&config).expect("the server starts");
    let mut client = server.connect();

    fs::remove_file(&state_file).expect("removable");
    fs::remove_file(directory.join("state/state.toml.lock")).expect("removable");
    fs::remove_dir(directory.join("state")).expect("removable");

    let error = client.expect_error(&Request::NamespaceCreate {
        namespace: NamespaceSpec::new(name("doomed")),
    });
    assert_eq!(error.code, ErrorCode::PersistFailed);

    // Nothing was published: the namespace does not exist in memory either.
    assert_eq!(
        client
            .expect_error(&Request::NamespaceShow {
                name: name("doomed"),
            })
            .code,
        ErrorCode::NotFound
    );
    let Reply::NamespaceList { namespaces } = client.expect_ok(&Request::NamespaceList {}) else {
        panic!("expected a namespace list");
    };
    assert_eq!(namespaces.len(), 1);
    assert!(
        !server
            .service()
            .snapshot()
            .registry
            .contains(&name("doomed"))
    );
}

#[test]
fn a_deleted_namespace_leaves_an_existing_holder_with_its_snapshot() {
    let directory = temp("delete");
    let server = server(&directory, STATE);
    let mut client = server.connect();

    let held = server
        .service()
        .snapshot()
        .registry
        .get(&name("project"))
        .expect("published");
    client.expect_ok(&Request::NamespaceDelete {
        name: name("project"),
    });

    assert!(
        !server
            .service()
            .snapshot()
            .registry
            .contains(&name("project"))
    );
    // The holder keeps serving the policy it resolved against.
    assert_eq!(held.name().as_str(), "project");
    assert!(
        held.rules()
            .literal(&voidportd::rules::NamespacePath::parse("/project").expect("valid"))
            .is_some()
    );
}

#[test]
fn the_control_socket_is_owner_only_and_unlinked_on_shutdown() {
    let directory = temp("socket-lifecycle");
    let mut server = server(&directory, STATE);
    let socket = server.socket().to_path_buf();
    assert_eq!(
        fs::metadata(&socket).expect("bound").permissions().mode() & 0o777,
        CONTROL_SOCKET_MODE
    );

    server.stop();
    assert!(
        support::wait_for_removal(&socket, Duration::from_secs(5)),
        "a clean shutdown must unlink the control socket"
    );
}

#[test]
fn an_idle_connection_does_not_hold_shutdown_open() {
    let directory = temp("shutdown-with-clients");
    let mut server = server(&directory, STATE);
    let socket = server.socket().to_path_buf();

    // Shutdown waits for its connections instead of aborting them, so a client
    // that connects and then says nothing must not be able to stall it.
    let mut idle = server.connect();
    let mut busy = server.connect();
    busy.expect_ok(&Request::NamespaceList {});

    server.stop();
    assert!(
        support::wait_for_removal(&socket, Duration::from_secs(5)),
        "a clean shutdown must unlink the control socket"
    );
    assert_eq!(idle.read_line(), None, "the connection must close");
    assert_eq!(busy.read_line(), None, "the connection must close");
}

#[test]
fn a_client_that_stops_reading_does_not_hold_shutdown_open() {
    let directory = temp("shutdown-backpressure");
    let mut server = server(&directory, &state_with_many_rules(500));
    let socket = server.socket().to_path_buf();

    // Answers this large do not fit in the socket buffer, and this client
    // never reads them, so the server ends up blocked in the middle of writing
    // one — which is exactly where a shutdown must still reach it.
    let mut stubborn = server.connect();
    for _ in 0..120 {
        stubborn.send_unread(&Request::NamespaceShow {
            name: name("project"),
        });
    }
    let queued = stubborn.wait_for_a_blocked_server(Duration::from_secs(10));
    assert!(queued > 0, "the server must have answers nobody is reading");

    server.signal_stop();
    let unlinked = support::wait_for_removal(&socket, Duration::from_secs(10));
    // Release the blocked write whatever happened, so a regression fails this
    // assertion instead of hanging the suite in the join below.
    drop(stubborn);
    server.stop();
    assert!(
        unlinked,
        "a client that stops reading must not hold shutdown open"
    );
}

#[test]
fn a_bound_path_stays_owned_when_the_socket_file_is_removed() {
    let directory = temp("socket-claim");
    let path = directory.join("control.sock");
    let socket = ControlSocket::bind(&path).expect("binds");

    // Ownership of the path cannot be decided by looking at the path: between
    // a daemon's unlink of a stale socket and its own bind there is nothing
    // there to see, and a second daemon that binds into that window leaves two
    // servers up, one of them nameless. So the path is claimed, and the claim
    // outlives what the path looks like.
    fs::remove_file(&path).expect("removable");
    let error = ControlSocket::bind(&path).expect_err("the path is still owned");
    assert!(matches!(error, BindError::InUse { .. }), "{error}");

    drop(socket);
    ControlSocket::bind(&path).expect("a released path is free again");
}

#[test]
fn a_stale_socket_is_reclaimed() {
    let directory = temp("stale-socket");
    let path = directory.join("control.sock");
    // A listener that is dropped without unlinking leaves exactly what a
    // crashed server leaves behind.
    drop(UnixListener::bind(&path).expect("binds"));
    assert!(path.exists());

    let socket = ControlSocket::bind(&path).expect("a stale socket is reclaimed");
    assert_eq!(socket.path(), path);
    drop(socket);
    assert!(!path.exists(), "dropping the listener unlinks the socket");
}

#[test]
fn a_live_socket_is_refused() {
    let directory = temp("live-socket");
    let server = server(&directory, STATE);

    let error = ControlSocket::bind(server.socket()).expect_err("a live socket is not ours");
    assert!(matches!(error, BindError::InUse { .. }), "{error}");
    // The refusal did not disturb the running server.
    let mut client = server.connect();
    client.expect_ok(&Request::NamespaceList {});
}

#[test]
fn a_path_that_is_not_a_socket_is_refused() {
    let directory = temp("not-a-socket");
    let path = directory.write("control.sock", "definitely a regular file");
    let error = ControlSocket::bind(&path).expect_err("not a socket");
    assert!(matches!(error, BindError::NotASocket { .. }), "{error}");
    // The file is left exactly as it was: the server deletes nothing it did
    // not create.
    assert_eq!(
        fs::read_to_string(&path).expect("readable"),
        "definitely a regular file"
    );

    let directory_path = directory.join("a-directory");
    create_directory(&directory_path);
    assert!(matches!(
        ControlSocket::bind(&directory_path).expect_err("not a socket"),
        BindError::NotASocket { .. }
    ));
}

#[test]
fn a_second_daemon_on_the_same_state_file_is_refused() {
    let directory = temp("second-daemon");
    let _server = server(&directory, STATE);

    let config = DaemonConfig::new(directory.join("state.toml"))
        .with_control_socket(directory.join("second.sock"))
        .with_environment(environment(directory.path()));
    let error = RunningServer::start(&config).expect_err("the state file is taken");
    assert!(matches!(error, StartupError::Lock(_)), "{error}");
    assert!(
        !directory.join("second.sock").exists(),
        "a refused startup must not leave a socket behind"
    );
}

#[test]
fn the_command_lines_control_socket_wins_over_the_state_file() {
    // The decided precedence: the flag first, then the state file, then the compiled
    // default. An explicit instruction losing to a configuration file would
    // surprise every operator, so a launch that names a socket binds that
    // socket and no other.
    let directory = temp("socket-precedence");
    let configured = directory.join("configured.sock");
    let state = format!(
        "[server]\ncontrol_socket = {:?}\n{STATE}",
        configured.display().to_string()
    );
    let state_file = directory.write("state.toml", &state);
    let flag = directory.join("flag.sock");
    let config = DaemonConfig::new(state_file)
        .with_control_socket(&flag)
        .with_environment(environment(directory.path()));

    let server = RunningServer::start(&config).expect("the server starts");
    assert_eq!(server.socket(), flag);
    assert!(!configured.exists());
    server.connect().expect_ok(&Request::NamespaceList {});
}

#[test]
fn the_state_files_control_socket_is_used_when_the_command_line_is_silent() {
    let directory = temp("configured-socket");
    let configured = directory.join("configured.sock");
    let state = format!(
        "[server]\ncontrol_socket = {:?}\n{STATE}",
        configured.display().to_string()
    );
    let state_file = directory.write("state.toml", &state);
    let config = DaemonConfig::new(state_file).with_environment(environment(directory.path()));
    let server = RunningServer::start(&config).expect("the server starts");
    assert_eq!(server.socket(), configured);
    let mut client = server.connect();
    client.expect_ok(&Request::NamespaceList {});
}
