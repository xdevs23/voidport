#![forbid(unsafe_code)]

use voidport_test_server as support;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::Path;

use support::{RunningServer, TempDir, daemon_config};
use voidport_control::{
    AdmittedMode, AuthMode, ErrorCode, HostDirectIo, IdMapping, IdSentinel, NamespaceName,
    NamespaceSpec, OwnershipSpec, PathResolution, PermissionMode, Reply, Request, Response, Rule,
    ShareMode, UnmappedPolicy, XattrRule, XattrVerdict,
};
use voidport_test_support::create_directory;
use voidportd::control::{CONTROL_SOCKET_MODE, ControlSocket, MAX_REQUEST_LINE, socket::BindError};
use voidportd::daemon::{DaemonConfig, StartupError};
use voidportd::rules::MAX_RULE_PATH_LEN;
use voidportd::state::load_document;

const STATE: &str = r#"
[[namespaces]]
name = "project"

[[namespaces.rules]]
path = "/project"
mode = "rw"
target = "project"
"#;

/// Graft targets are opened when a namespace is built, so they exist before the
/// server does.
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

/// The namespace is too big to answer in one socket buffer, so a client that
/// stops reading blocks the server mid-write.
fn state_with_many_rules(count: usize) -> String {
    let mut state = String::from(STATE);
    for index in 0..count {
        state.push_str(&format!(
            "\n[[namespaces.rules]]\npath = \"/project/file-{index:05}\"\nmode = \"ro\"\n"
        ));
    }
    state
}

fn server(directory: &TempDir, state: &str) -> RunningServer {
    let state_file = directory.write("state.toml", state);
    let config = daemon_config(&state_file);
    RunningServer::start(&config).expect("the server starts")
}

#[test]
fn a_server_reports_the_log_file_it_was_launched_with() {
    let directory = temp("log-file");
    let state_file = directory.write("state.toml", STATE);
    let log = directory.join("voidportd.log");
    let config = daemon_config(&state_file).with_log_file(&log);
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
    assert!(listeners.is_empty(), "{listeners:?}");
    assert_eq!(node_descriptors, 0);
    assert!(node_descriptor_budget >= 4096, "{node_descriptor_budget}");
    assert_eq!(log_file, None);

    client.expect_ok(&Request::NamespaceCreate {
        namespace: NamespaceSpec::new(name("scratch")),
    });

    let Reply::NamespaceList { namespaces } = client.expect_ok(&Request::NamespaceList {}) else {
        panic!("expected a namespace list");
    };
    let listed: Vec<&str> = namespaces
        .iter()
        .map(|namespace| namespace.name.as_str())
        .collect();
    assert_eq!(listed, ["project", "scratch"]);

    client.expect_ok(&Request::RuleAdd {
        namespace: name("scratch"),
        rule: Rule::new("/data", ShareMode::Ro).with_target("data"),
    });
    client.expect_ok(&Request::RuleAdd {
        namespace: name("scratch"),
        rule: Rule::new("/data/*", ShareMode::Hidden),
    });

    client.expect_ok(&Request::XattrAdd {
        namespace: name("scratch"),
        rule: XattrRule::new("user.*").with_write(XattrVerdict::Deny),
    });
    client.expect_ok(&Request::XattrAdd {
        namespace: name("scratch"),
        rule: XattrRule::new("user.build.id").with_write(XattrVerdict::Allow),
    });
    let duplicate = client.expect_error(&Request::XattrAdd {
        namespace: name("scratch"),
        rule: XattrRule::new("user.*").with_read(XattrVerdict::Deny),
    });
    assert_eq!(duplicate.code, ErrorCode::AlreadyExists);
    assert!(duplicate.message.contains("user.*"), "{duplicate}");
    let long = format!("user.long.{}id", "*".repeat(256));
    client.expect_ok(&Request::XattrAdd {
        namespace: name("scratch"),
        rule: XattrRule::new(&long).with_write(XattrVerdict::Allow),
    });
    assert!(
        server
            .service()
            .snapshot()
            .registry
            .get(&name("scratch"))
            .expect("namespace exists")
            .xattr()
            .writable(b"user.long.id")
    );
    client.expect_ok(&Request::XattrRemove {
        namespace: name("scratch"),
        r#match: long,
    });
    let silent = client.expect_error(&Request::XattrAdd {
        namespace: name("scratch"),
        rule: XattrRule::new("user.silent"),
    });
    assert_eq!(silent.code, ErrorCode::InvalidConfiguration);
    assert!(silent.message.contains("user.silent"), "{silent}");

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

    client.expect_ok(&Request::PermissionSet {
        namespace: name("scratch"),
        mode: PermissionMode::Passthrough,
    });
    client.expect_ok(&Request::DirectIoSet {
        namespace: name("scratch"),
        posture: HostDirectIo::Always,
    });
    client.expect_ok(&Request::AuthSet {
        namespace: name("scratch"),
        mode: AuthMode::None,
    });

    let Reply::Namespace { namespace } = client.expect_ok(&Request::NamespaceShow {
        name: name("scratch"),
    }) else {
        panic!("expected a namespace");
    };
    assert_eq!(namespace.rules.len(), 2);
    assert_eq!(namespace.direct_io, HostDirectIo::Always);
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

    client.expect_ok(&Request::NamespaceDelete {
        name: name("scratch"),
    });
    let error = client.expect_error(&Request::NamespaceShow {
        name: name("scratch"),
    });
    assert_eq!(error.code, ErrorCode::NotFound);

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
        Request::DirectIoSet {
            namespace: name("nope"),
            posture: HostDirectIo::Always,
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

/// Resolution reads rules only, so the paths named by the rules need not exist
/// on the host.
fn server_with_resolvable_rules(directory: &TempDir) -> RunningServer {
    server(
        directory,
        &format!(
            r#"
[[namespaces]]
name = "project"

[[namespaces.rules]]
path = "/project"
mode = "rw"
target = "{graft}"

[[namespaces.rules]]
path = "/project/docs"
mode = "ro"

[[namespaces.rules]]
path = "/project/secret"
mode = "hidden"
"#,
            graft = directory.join("project").display()
        ),
    )
}

#[test]
fn resolve_reports_how_a_lookup_of_each_path_would_end() {
    let directory = temp("resolve");
    let server = server_with_resolvable_rules(&directory);
    let mut client = server.connect();
    let mut resolve = |path: &str| {
        client.expect_ok(&Request::Resolve {
            namespace: name("project"),
            path: path.to_owned(),
        })
    };
    let host = |mode, path: &str| Reply::Resolution {
        resolution: PathResolution::Host {
            mode,
            host_path: directory.join(path).display().to_string(),
        },
    };
    let resolution = |resolution| Reply::Resolution { resolution };

    assert_eq!(resolve("/"), resolution(PathResolution::Synthesized {}));
    assert_eq!(resolve("/project"), host(AdmittedMode::Rw, "project"));
    assert_eq!(
        resolve("/project/docs"),
        host(AdmittedMode::Ro, "project/docs")
    );
    for hidden in ["/project/secret", "/project/secret/key"] {
        assert_eq!(resolve(hidden), resolution(PathResolution::Absent {}));
    }

    let refused = client.expect_error(&Request::Resolve {
        namespace: name("project"),
        path: "docs/x".to_owned(),
    });
    assert_eq!(refused.code, ErrorCode::InvalidRequest);

    let too_long = client.expect_error(&Request::Resolve {
        namespace: name("project"),
        path: "/a".repeat(MAX_RULE_PATH_LEN / 2 + 1),
    });
    assert_eq!(too_long.code, ErrorCode::InvalidRequest);
}

/// An outside program parses this reply, so its spelling is part of the protocol.
#[test]
fn a_resolution_reply_has_the_documented_json_form() {
    let directory = temp("resolve-json");
    let server = server_with_resolvable_rules(&directory);
    let mut client = server.connect();
    let mut reply = |path: &str| -> serde_json::Value {
        let request = serde_json::json!({"op": "resolve", "namespace": "project", "path": path});
        let line = client
            .send_line(request.to_string().as_bytes())
            .expect("an answer");
        serde_json::from_str(&line).expect("a JSON reply")
    };
    let ok = |resolution| {
        serde_json::json!({
            "status": "ok",
            "result": {
                "reply": "resolution",
                "resolution": resolution,
            },
        })
    };

    assert_eq!(
        reply("/project/docs"),
        ok(serde_json::json!({
            "kind": "host",
            "mode": "ro",
            "host_path": directory.join("project/docs").display().to_string(),
        }))
    );
    assert_eq!(reply("/"), ok(serde_json::json!({"kind": "synthesized"})));
    assert_eq!(
        reply("/project/secret"),
        ok(serde_json::json!({"kind": "absent"}))
    );
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

    let error = client.expect_error(&Request::RuleAdd {
        namespace: name("project"),
        rule: Rule::new("/project/secret/key", ShareMode::Ro),
    });
    assert_eq!(error.code, ErrorCode::InvalidConfiguration);
    assert!(error.message.contains("project"), "{error}");
    assert!(error.message.contains("/project/secret/key"), "{error}");

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

#[test]
fn pattern_rules_add_persist_and_remove_by_path_and_match() {
    let directory = temp("patterns");
    let server = server(&directory, STATE);
    let mut client = server.connect();

    client.expect_ok(&Request::RuleAdd {
        namespace: name("project"),
        rule: Rule::new("/project/*", ShareMode::Hidden),
    });
    client.expect_ok(&Request::RuleAdd {
        namespace: name("project"),
        rule: Rule::new("/project", ShareMode::Rw).with_match("project-*"),
    });
    client.expect_ok(&Request::RuleAdd {
        namespace: name("project"),
        rule: Rule::new("/project", ShareMode::Ro).with_match("docs-*"),
    });

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
    let overlap = client.expect_error(&Request::RuleAdd {
        namespace: name("project"),
        rule: Rule::new("/project", ShareMode::Ro).with_match("project-a*"),
    });
    assert!(overlap.message.contains("project-*"), "{overlap}");
    assert!(overlap.message.contains("project-a*"), "{overlap}");
    assert!(overlap.message.contains("/project"), "{overlap}");

    assert_eq!(
        client
            .expect_error(&Request::RuleAdd {
                namespace: name("project"),
                rule: Rule::new("//project/", ShareMode::Ro).with_match("project-*"),
            })
            .code,
        ErrorCode::AlreadyExists
    );

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
    // The state file sits in a directory of its own so the test can take it away
    // without disturbing the control socket, and names its graft target by full
    // path because a relative target resolves beside the state file.
    let target = directory.join("project");
    let state = STATE.replace(
        "target = \"project\"",
        &format!("target = \"{}\"", target.display()),
    );
    let state_file = directory.write("state/state.toml", &state);
    // Not the shared assembly: that one puts the socket beside the state file,
    // and this test takes the directory of the state file away.
    let config = DaemonConfig::new(&state_file).with_control_socket(directory.join("control.sock"));
    let server = RunningServer::start(&config).expect("the server starts");
    let mut client = server.connect();

    fs::remove_file(&state_file).expect("removable");
    fs::remove_file(directory.join("state/state.toml.lock")).expect("removable");
    fs::remove_dir(directory.join("state")).expect("removable");

    let error = client.expect_error(&Request::NamespaceCreate {
        namespace: NamespaceSpec::new(name("doomed")),
    });
    assert_eq!(error.code, ErrorCode::PersistFailed);

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
        !socket.exists(),
        "a clean shutdown must unlink the control socket"
    );
}

#[test]
fn an_idle_connection_does_not_hold_shutdown_open() {
    let directory = temp("shutdown-with-clients");
    let mut server = server(&directory, STATE);
    let socket = server.socket().to_path_buf();

    // Shutdown waits for its connections, so a client that connects and then
    // sends nothing must not stall it.
    let mut idle = server.connect();
    let mut busy = server.connect();
    busy.expect_ok(&Request::NamespaceList {});

    server.stop();
    assert!(
        !socket.exists(),
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

    // Replies this large do not fit in the socket buffer, and this client never
    // reads them. Shutdown completes whether the server is still reading requests
    // or waits in the middle of writing an answer.
    let mut stubborn = server.connect();
    for _ in 0..120 {
        stubborn.send_unread(&Request::NamespaceShow {
            name: name("project"),
        });
    }
    server.stop();
    assert!(
        !socket.exists(),
        "shutdown completed while the client remained unread"
    );
    drop(stubborn);
}

#[test]
fn a_bound_path_stays_owned_when_the_socket_file_is_removed() {
    let directory = temp("socket-claim");
    let path = directory.join("control.sock");
    let socket = ControlSocket::bind(&path).expect("binds");

    // The path cannot be claimed by looking at it: between the unlink of a stale
    // socket by a daemon and its bind there is nothing to see, and a second daemon
    // that binds in that window leaves two servers up. So the claim outlives what
    // the path looks like.
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
    let mut client = server.connect();
    client.expect_ok(&Request::NamespaceList {});
}

#[test]
fn a_path_that_is_not_a_socket_is_refused() {
    let directory = temp("not-a-socket");
    let path = directory.write("control.sock", "definitely a regular file");
    let error = ControlSocket::bind(&path).expect_err("not a socket");
    assert!(matches!(error, BindError::NotASocket { .. }), "{error}");
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
        .with_control_socket(directory.join("second.sock"));
    let error = RunningServer::start(&config).expect_err("the state file is taken");
    assert!(matches!(error, StartupError::Lock(_)), "{error}");
    assert!(
        !directory.join("second.sock").exists(),
        "a refused startup must not leave a socket behind"
    );
}

#[test]
fn the_command_lines_control_socket_wins_over_the_state_file() {
    let directory = temp("socket-precedence");
    let configured = directory.join("configured.sock");
    let state = format!(
        "[server]\ncontrol_socket = {:?}\n{STATE}",
        configured.display().to_string()
    );
    let state_file = directory.write("state.toml", &state);
    let flag = directory.join("flag.sock");
    let config = DaemonConfig::new(state_file).with_control_socket(&flag);

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
    let config = DaemonConfig::new(state_file);
    let server = RunningServer::start(&config).expect("the server starts");
    assert_eq!(server.socket(), configured);
    let mut client = server.connect();
    client.expect_ok(&Request::NamespaceList {});
}
