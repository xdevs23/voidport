//! The state file against a real filesystem: the source/runtime split, the
//! loader's error enrichment, durable persistence, and the single-instance
//! lock.

mod support;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use support::{TempDir, daemon_config, environment};
use voidport_control::{NamespaceName, NamespaceSpec, Request, Response, Rule, ShareMode};
use voidportd::control::service::Service;
use voidportd::data::pin::DescriptorLimit;
use voidportd::error::render;
use voidportd::rules::{GuestIds, HostIds, NamespacePath, OwnerPresentation};
use voidportd::state::{
    InstanceLock, LoadError, LockError, StateDocument, load, load_document, persist,
};
use voidportd::testing::create_directory;

/// A portable state file: an id sentinel and a relative host target, which are
/// exactly the two things a mutation must not resolve.
const PORTABLE: &str = r#"
[[namespaces]]
name = "portable"

[namespaces.ownership]
mode = "map"
unmapped = "squash"
uid_map = [{ host = "uid", guest = 0 }]
gid_map = [{ host = "gid", guest = 0 }]

[[namespaces.rules]]
path = "/project"
mode = "rw"
target = "project"
"#;

/// A temporary directory holding the graft target `PORTABLE` names, which
/// building pins.
fn temp(label: &str) -> TempDir {
    let directory = TempDir::new(label);
    directory.directory("project");
    directory
}

fn name(raw: &str) -> NamespaceName {
    NamespaceName::new(raw).expect("valid namespace name")
}

/// The service the mutation tests drive, with no socket in the way.
fn service(directory: &Path, state_file: &Path) -> Service {
    let environment = environment(directory);
    let loaded = load(state_file, &environment).expect("the state file loads");
    Service::new(
        state_file,
        directory.join("control.sock"),
        environment,
        loaded,
        DescriptorLimit::current(),
        None,
    )
}

#[test]
fn the_source_document_round_trips_through_the_file() {
    let directory = temp("round-trip");
    let path = directory.write("state.toml", PORTABLE);
    let document = load_document(&path).expect("the state file parses");

    let copy = directory.join("copy.toml");
    persist(&document, &copy).expect("persists");
    assert_eq!(
        load_document(&copy).expect("the copy parses"),
        document,
        "load(persist(x)) must equal x on the source form"
    );

    // Persisting the reloaded document a second time is byte-identical: the
    // emission is a function of the document alone.
    persist(&document, &copy).expect("persists");
    assert_eq!(load_document(&copy).expect("the copy parses"), document);
}

#[test]
fn an_unrelated_mutation_leaves_sentinels_and_relative_targets_unresolved() {
    let directory = temp("portability");
    let path = directory.write("state.toml", PORTABLE);
    let service = service(directory.path(), &path);

    // Touch a different namespace entirely.
    let response = service.handle(Request::NamespaceCreate {
        namespace: NamespaceSpec::new(name("other")),
    });
    assert!(matches!(response, Response::Ok { .. }), "{response:?}");

    let text = fs::read_to_string(&path).expect("the state file is readable");
    assert!(
        text.contains("host = \"uid\""),
        "the uid sentinel must survive a mutation:\n{text}"
    );
    assert!(
        text.contains("host = \"gid\""),
        "the gid sentinel must survive a mutation:\n{text}"
    );
    assert!(
        text.contains("target = \"project\""),
        "the relative target must survive a mutation:\n{text}"
    );
    assert!(
        !text.contains("4242"),
        "no machine-specific id may be baked in:\n{text}"
    );

    // And the file still equals what the server holds in memory.
    assert_eq!(
        load_document(&path).expect("the state file parses"),
        service.snapshot().document
    );
}

#[test]
fn the_commented_example_state_file_loads() {
    // The shipped file, byte for byte, put beside the trees it grafts. Its
    // targets are relative — the portability the file itself documents — so a
    // full `load`, graft pinning included, is what a reader gets by copying it
    // next to their own trees.
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/state.example.toml");
    let example = fs::read_to_string(&source).expect("the example state file is readable");
    let directory = TempDir::new("example");
    directory.directory("project");
    directory.directory("vendor-snapshot");
    directory.write("logs/app.log", "");
    let path = directory.write("state.toml", &example);

    let loaded = load(&path, &environment(directory.path())).expect("the example state file loads");
    assert_eq!(loaded.registry.len(), 2);
    assert!(loaded.registry.contains(&name("project")));
    assert_eq!(loaded.document.server.listeners.len(), 3);

    // The attribute rules it documents are the ones it builds: the longer
    // literal prefix wins, and the unstated read verdict falls to the default.
    let project = loaded.registry.get(&name("project")).expect("built");
    assert!(project.xattr().writable(b"user.build.id"));
    assert!(!project.xattr().writable(b"user.other"));
    assert!(project.xattr().readable(b"user.other"));
    assert!(!project.xattr().writable(b"system.posix_acl_access"));

    // It documents the schema, so it must also round-trip like any other.
    let text = loaded.document.to_toml().expect("serializable");
    assert_eq!(
        StateDocument::from_toml(&text).expect("parses"),
        loaded.document
    );
}

#[test]
fn a_sentinel_resolves_against_the_injected_identity() {
    let directory = temp("sentinel");
    let path = directory.write("state.toml", PORTABLE);
    let loaded = load(&path, &environment(directory.path())).expect("the state file loads");
    let namespace = loaded.registry.get(&name("portable")).expect("built");
    // 4242/4243 is the injected identity, not this process's.
    assert_eq!(
        namespace.ownership().forward(HostIds::new(4242, 4243)),
        OwnerPresentation::Visible(GuestIds::new(0, 0))
    );
}

#[test]
fn a_relative_target_resolves_against_the_state_files_directory() {
    let directory = temp("relative");
    let path = directory.write("state.toml", PORTABLE);
    let loaded = load(&path, &environment(directory.path())).expect("the state file loads");
    let namespace = loaded.registry.get(&name("portable")).expect("built");
    let rule = namespace
        .rules()
        .literal(&NamespacePath::parse("/project").expect("valid path"))
        .expect("the rule is kept");
    let backing = rule.backing.as_ref().expect("an admitting rule is backed");
    assert_eq!(
        backing.graft().as_str(),
        directory.join("project").display().to_string()
    );
}

#[test]
fn a_dead_configuration_refuses_startup_naming_namespace_and_rule() {
    let directory = temp("dead-config");
    let path = directory.write(
        "state.toml",
        r#"
        [[namespaces]]
        name = "project"
        [[namespaces.rules]]
        path = "/a"
        mode = "rw"
        target = "/srv/a"
        [[namespaces.rules]]
        path = "/a/secret"
        mode = "hidden"
        [[namespaces.rules]]
        path = "/a/secret/key"
        mode = "ro"
        "#,
    );
    let error = load(&path, &environment(directory.path())).expect_err("dead configuration");
    let rendered = render(&error);
    assert!(rendered.contains("\"project\""), "{rendered}");
    assert!(rendered.contains("/a/secret/key"), "{rendered}");
    assert!(matches!(error, LoadError::Namespace { .. }));
}

/// Every attribute-rule refusal is the **loader's** as well as the control
/// plane's.
///
/// A state file states xattr rules in the very source form `xattr add` sends,
/// and both go through one validation boundary; a file that could load what the
/// control plane refuses would be a second, quieter policy language. Each case
/// here has an `xattr add` twin in `tests/control.rs`.
#[test]
fn a_state_file_is_refused_for_every_attribute_rule_the_control_plane_refuses() {
    let oversized = "u".repeat(256);
    let cases = [
        (
            "a duplicate match",
            "\n[[namespaces.xattr]]\nmatch = \"user.*\"\nread = \"deny\"\n\n\
             [[namespaces.xattr]]\nmatch = \"user.*\"\nwrite = \"allow\"\n"
                .to_owned(),
            "user.*",
        ),
        (
            "a match longer than an attribute name",
            format!("\n[[namespaces.xattr]]\nmatch = \"{oversized}\"\nread = \"deny\"\n"),
            "255",
        ),
        (
            "a rule stating no verdict",
            "\n[[namespaces.xattr]]\nmatch = \"user.silent\"\n".to_owned(),
            "user.silent",
        ),
    ];
    for (label, xattr, expected) in cases {
        let directory = temp("xattr-load");
        let path = directory.write("state.toml", &format!("{PORTABLE}{xattr}"));
        let error = load(&path, &environment(directory.path())).expect_err(label);
        let rendered = render(&error);
        assert!(rendered.contains(expected), "{label}: {rendered}");
        assert!(rendered.contains("\"portable\""), "{label}: {rendered}");
        assert!(matches!(error, LoadError::Namespace { .. }), "{label}");
    }
}

/// A state file whose namespace grafts a parent, hides its children and
/// un-hides one family by match — the design's motivating composition.
fn family_state(extra: &str) -> String {
    format!(
        r#"
[[namespaces]]
name = "family"

[[namespaces.rules]]
path = "/project"
mode = "rw"
target = "project"

[[namespaces.rules]]
path = "/project/*"
mode = "hidden"

[[namespaces.rules]]
path = "/project"
mode = "rw"
match = "project-*"
{extra}
"#
    )
}

#[test]
fn a_pattern_rule_loads_round_trips_and_resolves() {
    let directory = temp("pattern-load");
    let path = directory.write("state.toml", &family_state(""));
    let loaded = load(&path, &environment(directory.path())).expect("the state file loads");

    // It reaches the engine as a pattern rule, keyed by directory and match.
    let namespace = loaded.registry.get(&name("family")).expect("built");
    let project = NamespacePath::parse("/project").expect("valid path");
    let covered = voidportd::rules::Name::new("project-one").expect("valid name");
    let uncovered = voidportd::rules::Name::new("other").expect("valid name");
    assert_eq!(
        namespace.rules().pattern(&project, &covered),
        Some(voidportd::rules::ShareMode::Rw)
    );
    assert_eq!(namespace.rules().pattern(&project, &uncovered), None);

    // And it survives the file in source form: `match` is a field, so the
    // document that comes back is the document that went in.
    let copy = directory.join("copy.toml");
    persist(&loaded.document, &copy).expect("persists");
    let reloaded = load_document(&copy).expect("the copy parses");
    assert_eq!(reloaded, loaded.document);
    let rule = reloaded.namespaces[0]
        .rules
        .iter()
        .find(|rule| rule.r#match.is_some())
        .expect("the pattern rule is kept");
    assert_eq!(rule.r#match.as_deref(), Some("project-*"));
    assert_eq!(rule.path, "/project");
    assert!(rule.target.is_none());
}

#[test]
fn a_pattern_rule_the_engine_refuses_refuses_startup() {
    let cases = [
        // A pattern rule carrying a target is not mode-only.
        ("target = \"project\"", "must not carry a host target"),
        // Two patterns at one level covering one name.
        (
            "[[namespaces.rules]]\npath = \"/project\"\nmode = \"ro\"\nmatch = \"*-one\"",
            "overlaps",
        ),
        // A rule beneath a name only hidden rules cover.
        (
            "[[namespaces.rules]]\npath = \"/project/other/deep\"\nmode = \"ro\"",
            "unreachable",
        ),
        // A match that is only `*`s, on a second directory so the family rule
        // above stays valid.
        (
            "[[namespaces.rules]]\npath = \"/project/sub\"\nmode = \"ro\"\nmatch = \"**\"",
            "match",
        ),
        // A pattern on a directory nothing grafts.
        (
            "[[namespaces.rules]]\npath = \"/elsewhere\"\nmode = \"ro\"\nmatch = \"x-*\"",
            "not host-backed",
        ),
    ];
    for (extra, expected) in cases {
        let directory = temp("pattern-refusal");
        let path = directory.write("state.toml", &family_state(extra));
        let error = match load(&path, &environment(directory.path())) {
            Ok(_) => panic!("{extra} must refuse startup"),
            Err(error) => render(&error),
        };
        assert!(
            error.contains(expected),
            "{extra}: expected {expected:?} in {error}"
        );
        assert!(error.contains("\"family\""), "{error} names the namespace");
    }
}

#[test]
fn duplicate_namespaces_refuse_startup() {
    let directory = temp("duplicate");
    let path = directory.write(
        "state.toml",
        "[[namespaces]]\nname = \"p\"\n[[namespaces]]\nname = \"p\"\n",
    );
    let error = load(&path, &environment(directory.path())).expect_err("duplicate namespace");
    assert!(matches!(error, LoadError::DuplicateNamespace { .. }));
}

#[test]
fn a_misspelled_key_refuses_startup_with_a_line_number() {
    let directory = temp("misspelled");
    let path = directory.write(
        "state.toml",
        "[[namespaces]]\nname = \"p\"\npermisson = \"passthrough\"\n",
    );
    let error = load(&path, &environment(directory.path())).expect_err("unknown key");
    let rendered = render(&error);
    assert!(matches!(error, LoadError::Parse { .. }));
    assert!(rendered.contains("permisson"), "{rendered}");
}

#[test]
fn a_new_state_file_is_created_owner_only() {
    let directory = temp("mode");
    let path = directory.join("state.toml");
    persist(&StateDocument::default(), &path).expect("persists");
    assert_eq!(mode_of(&path), 0o600);
}

#[test]
fn persisting_preserves_the_state_files_mode() {
    let directory = temp("preserve-mode");
    let path = directory.write("state.toml", PORTABLE);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).expect("chmod");
    let document = load_document(&path).expect("parses");

    persist(&document, &path).expect("persists");
    assert_eq!(mode_of(&path), 0o640);
    assert_eq!(load_document(&path).expect("parses"), document);
}

#[test]
fn persisting_leaves_no_temporary_files_behind() {
    let directory = TempDir::new("temporaries");
    let path = directory.write("state.toml", PORTABLE);
    let document = load_document(&path).expect("parses");
    for _ in 0..3 {
        persist(&document, &path).expect("persists");
    }
    let entries: Vec<String> = fs::read_dir(directory.path())
        .expect("readable")
        .map(|entry| {
            entry
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    assert_eq!(entries, ["state.toml"], "only the state file may remain");
}

#[test]
fn startup_sweeps_an_orphaned_persist_temporary() {
    let directory = temp("orphaned-temporary");
    let path = directory.write("state.toml", PORTABLE);
    let orphan = directory.write(
        &format!(".state.toml.{}.0.tmp", std::process::id()),
        "interrupted persist",
    );
    let config = daemon_config(&path, environment(directory.path()));
    let daemon = voidportd::daemon::Daemon::start(&config).expect("startup sweeps the orphan");
    assert!(!orphan.exists());

    let response = daemon.service().handle(Request::NamespaceCreate {
        namespace: NamespaceSpec::new(name("after-sweep")),
    });
    assert!(matches!(response, Response::Ok { .. }), "{response:?}");
    assert!(
        load_document(&path)
            .expect("the post-sweep persist loads")
            .namespace(&name("after-sweep"))
            .is_some()
    );
}

#[test]
fn a_failing_persist_reports_the_path_it_could_not_write() {
    let directory = temp("persist-failure");
    let state_dir = directory.join("state");
    create_directory(&state_dir);
    let path = state_dir.join("state.toml");
    persist(&StateDocument::default(), &path).expect("persists");
    let document = load_document(&path).expect("parses");

    // A directory that has gone away is the one persist failure a test can
    // force whatever it runs as.
    fs::remove_file(&path).expect("removable");
    fs::remove_dir(&state_dir).expect("removable");
    let error = persist(&document, &path).expect_err("the directory is gone");
    let rendered = render(&error);
    assert!(rendered.contains("state.toml"), "{rendered}");
}

#[test]
fn a_second_instance_is_refused_while_the_first_holds_the_lock() {
    let directory = temp("lock");
    let path = directory.write("state.toml", PORTABLE);

    let first = InstanceLock::acquire(&path).expect("the first instance takes the lock");
    assert!(first.path().ends_with("state.toml.lock"));
    let error = InstanceLock::acquire(&path).expect_err("the second instance is refused");
    assert!(matches!(error, LockError::Held { .. }));
    assert!(error.to_string().contains("already owns"), "{error}");

    // The lock lives on a sibling file, so it survives the rename a durable
    // persist performs — the point of not locking the state file itself.
    let document = load_document(&path).expect("parses");
    persist(&document, &path).expect("persists");
    assert!(matches!(
        InstanceLock::acquire(&path).expect_err("still held"),
        LockError::Held { .. }
    ));

    drop(first);
    InstanceLock::acquire(&path).expect("the lock is released with the instance");
}

#[test]
fn a_second_instance_reaching_the_same_file_by_another_name_is_refused() {
    let directory = temp("lock-alias");
    let path = directory.write("state.toml", PORTABLE);
    let alias = directory.join("alias.toml");
    fs::hard_link(&path, &alias).expect("a second name for the same file");

    let _first = InstanceLock::acquire(&path).expect("the first instance takes the lock");
    // Each name has a sidecar of its own, so the sidecar alone would let two
    // daemons serve — and overwrite — one file. The state file's own inode is
    // what makes the claim about the file, not about the name.
    let error = InstanceLock::acquire(&alias).expect_err("the same file, under another name");
    assert!(matches!(error, LockError::Held { .. }), "{error}");
    assert!(error.to_string().contains("already owns"), "{error}");
}

#[test]
fn a_second_instance_reaching_the_same_file_through_a_symlink_is_refused() {
    let directory = temp("lock-symlink");
    let path = directory.write("state.toml", PORTABLE);
    let alias = directory.join("alias.toml");
    std::os::unix::fs::symlink(&path, &alias).expect("a symbolic link to the state file");

    let _first = InstanceLock::acquire(&path).expect("the first instance takes the lock");

    // A symlink resolves afresh every time, so it follows the state file
    // through the rename a durable persist performs: the inode locked at
    // startup is gone and the alias names the new one. The claim has to
    // survive that, or a second daemon walks in after the first mutation.
    let document = load_document(&path).expect("parses");
    persist(&document, &path).expect("persists");

    let error = InstanceLock::acquire(&alias).expect_err("the same file, through a symlink");
    assert!(matches!(error, LockError::Held { .. }), "{error}");
    assert!(error.to_string().contains("already owns"), "{error}");
}

#[test]
fn an_accepted_mutation_reaches_both_memory_and_the_file() {
    let directory = temp("mutation");
    let path = directory.write("state.toml", PORTABLE);
    let service = service(directory.path(), &path);

    let response = service.handle(Request::RuleAdd {
        namespace: name("portable"),
        rule: Rule::new("/project/notes.txt", ShareMode::Ro),
    });
    assert!(matches!(response, Response::Ok { .. }), "{response:?}");

    let persisted = load_document(&path).expect("parses");
    assert_eq!(
        persisted
            .namespace(&name("portable"))
            .expect("present")
            .rule("/project/notes.txt")
            .map(|rule| rule.mode),
        Some(ShareMode::Ro)
    );
    assert_eq!(persisted, service.snapshot().document);
    // The rebuilt namespace is what the registry now publishes.
    let namespace = service
        .snapshot()
        .registry
        .get(&name("portable"))
        .expect("published");
    assert_eq!(
        namespace
            .rules()
            .literal(&voidportd::rules::NamespacePath::parse("/project/notes.txt").expect("valid"))
            .map(|rule| rule.mode),
        Some(voidportd::rules::ShareMode::Ro)
    );
}

/// The permission bits of a path.
fn mode_of(path: &Path) -> u32 {
    fs::metadata(path)
        .expect("the file exists")
        .permissions()
        .mode()
        & 0o777
}
