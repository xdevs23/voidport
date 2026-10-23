use voidport_test_client as support;

use std::fs;
use std::os::fd::AsFd as _;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::Path;

use rustix::io::Errno;
use support::{Fixture, errno, presented_mode};
use voidport_control::{NamespaceName, NamespaceSpec, Reply, Request, Response, Rule, ShareMode};

fn namespace(fixture: &Fixture) -> NamespaceSpec {
    NamespaceSpec {
        rules: vec![
            Rule::new("/family", ShareMode::Rw).with_target(host(fixture, "family")),
            Rule::new("/family/*", ShareMode::Hidden),
            Rule::new("/family", ShareMode::Rw).with_match("project-*"),
            Rule::new("/family/project-pinned", ShareMode::Ro),
            Rule::new("/plain", ShareMode::Rw).with_target(host(fixture, "plain")),
            Rule::new("/plain", ShareMode::Ro).with_match("keep-*"),
            Rule::new("/plain/b*", ShareMode::Ro),
            Rule::new("/dots", ShareMode::Rw).with_target(host(fixture, "dots")),
            Rule::new("/dots", ShareMode::Ro).with_match("*-a"),
            Rule::new("/dots", ShareMode::Hidden).with_match(".b-*"),
        ],
        ..NamespaceSpec::new(family())
    }
}

fn family() -> NamespaceName {
    NamespaceName::new("family").expect("valid namespace name")
}

fn host(fixture: &Fixture, relative: &str) -> String {
    fixture.host(relative).display().to_string()
}

/// The host directories exist before the namespace is built, because a graft
/// target is bound then.
fn start(label: &str) -> Fixture {
    let fixture = Fixture::start(label);
    for relative in [
        "family/project-a",
        "family/project-b",
        "family/project-",
        "family/project-pinned",
        "family/other",
        "family/.project-dot",
        "plain/keep-one",
        "plain/misc",
        "plain/b*",
        "plain/bx",
        // The dot probe: `*-a` covers `x-a` and cannot reach either dotfile;
        // `.b-*` covers `.b-a`, because it begins with a literal dot.
        "dots/x-a",
        "dots/.b-a",
        "dots/.c-a",
    ] {
        make(&fixture.host(relative));
    }
    fs::write(fixture.host("family/project-b/note.txt"), b"family member")
        .expect("the host is writable");

    let response = fixture.control(&Request::NamespaceCreate {
        namespace: namespace(&fixture),
    });
    assert_eq!(
        response,
        Response::Ok {
            result: Reply::Done {}
        },
        "the namespace must build"
    );
    fixture
}

fn make(path: &Path) {
    fs::create_dir_all(path).expect("the host is writable");
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("a settable mode");
}

fn names(path: &Path) -> Vec<String> {
    let mut listed: Vec<String> = fs::read_dir(path)
        .unwrap_or_else(|error| panic!("{} should list: {error}", path.display()))
        .map(|entry| {
            entry
                .expect("a readable entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    listed.sort();
    listed
}

#[test]
fn the_family_composition_shows_exactly_the_family_and_takes_new_members() {
    support::preflight();
    let fixture = start("pattern-family");
    let guest = fixture.mount("family", "family", "/family");

    assert_eq!(
        names(guest.root()),
        [
            "project-".to_owned(),
            "project-a".to_owned(),
            "project-b".to_owned(),
            "project-pinned".to_owned(),
        ]
    );
    assert_eq!(
        fs::read(guest.path("project-b/note.txt")).expect("readable"),
        b"family member"
    );
    let hidden = fs::metadata(guest.path("other")).expect_err("hidden by the bare `*`");
    assert_eq!(errno(&hidden), Errno::NOENT.raw_os_error(), "{hidden}");

    fs::create_dir(guest.path("project-new")).expect("the match admits the name");
    assert!(
        fixture.host("family/project-new").is_dir(),
        "the new member landed on the host"
    );
    let again = fs::create_dir(guest.path("project-new")).expect_err("it exists now");
    assert_eq!(errno(&again), Errno::EXIST.raw_os_error(), "{again}");

    // A name only hidden rules cover is refused with EACCES, not created and
    // hidden.
    let refused = fs::create_dir(guest.path("other-new")).expect_err("hidden names take no create");
    assert_eq!(errno(&refused), Errno::ACCESS.raw_os_error(), "{refused}");
    assert!(
        !fixture.host("family/other-new").exists(),
        "a refused create must not have touched the host"
    );
}

#[test]
fn a_member_created_on_the_host_appears_without_any_control_plane_operation() {
    support::preflight();
    let fixture = start("pattern-live");
    let guest = fixture.mount_fresh("family", "family", "/family");
    assert!(!guest.path("project-late").exists());

    make(&fixture.host("family/project-late"));
    // A name the match does not cover must stay invisible.
    make(&fixture.host("family/late"));

    assert!(
        guest.path("project-late").is_dir(),
        "a new family member is covered at its next uncached lookup"
    );
    assert!(!guest.path("late").exists(), "and nothing else is");

    assert!(guest.path("project-").is_dir());
}

#[test]
fn the_specificity_chain_holds_through_a_real_mount() {
    support::preflight();
    let fixture = start("pattern-specificity");
    let guest = fixture.mount("family", "family", "");

    assert_eq!(
        presented_mode(&guest.path("family/project-pinned")),
        "r-x------",
        "a literal rule beats the pattern covering the same name"
    );
    assert_eq!(
        presented_mode(&guest.path("family/project-a")),
        "rwx------",
        "the pattern beats the bare `*`"
    );
    assert!(
        !guest.path("family/other").exists(),
        "and the bare `*` decides what nothing else claims"
    );

    // The fourth tier is observable only where no bare `*` shadows it, which
    // takes a second directory.
    assert_eq!(
        presented_mode(&guest.path("plain/keep-one")),
        "r-x------",
        "the pattern beats the enclosing default"
    );
    assert_eq!(
        presented_mode(&guest.path("plain/misc")),
        "rwx------",
        "and the enclosing default decides the rest"
    );
}

#[test]
fn a_host_entry_named_with_a_star_is_still_a_literal_name() {
    support::preflight();
    let fixture = start("pattern-literal-star");
    let guest = fixture.mount("family", "family", "/plain");

    assert_eq!(
        presented_mode(&guest.path("b*")),
        "r-x------",
        "the rule `/plain/b*` governs the entry really called `b*`"
    );
    assert_eq!(
        presented_mode(&guest.path("bx")),
        "rwx------",
        "and it governs nothing else: a path component is never a glob"
    );
    assert!(names(guest.root()).contains(&"b*".to_owned()));
}

#[test]
fn a_match_reaches_a_dotfile_only_when_it_begins_with_a_dot() {
    support::preflight();
    let fixture = start("pattern-dots");
    let guest = fixture.mount("family", "family", "/dots");

    assert_eq!(presented_mode(&guest.path("x-a")), "r-x------");
    // `*-a` cannot reach `.c-a`, which inherits the read-write mode of the graft.
    assert_eq!(
        presented_mode(&guest.path(".c-a")),
        "rwx------",
        "a match starting with `*` never covers a name starting with `.`"
    );
    let hidden = fs::metadata(guest.path(".b-a")).expect_err("hidden by `.b-*`");
    assert_eq!(errno(&hidden), Errno::NOENT.raw_os_error(), "{hidden}");
    assert!(!names(guest.root()).contains(&".b-a".to_owned()));
}

/// A handle opened before the match is removed keeps working, because a node's
/// mode binds at the lookup that admitted it.
#[test]
fn removing_a_pattern_hides_its_family_at_the_next_lookup_and_spares_an_open_handle() {
    support::preflight();
    let fixture = start("pattern-removal");
    let guest = fixture.mount_fresh("family", "family", "/family");

    let held = fs::File::open(guest.path("project-b/note.txt")).expect("openable");

    let response = fixture.control(&Request::RuleRemove {
        namespace: family(),
        path: "/family".to_owned(),
        r#match: Some("project-*".to_owned()),
    });
    assert!(matches!(response, Response::Ok { .. }), "{response:?}");

    // This mount retains neither attributes nor entries. The control reply
    // precedes the fresh listing and lookup being asserted.
    assert!(
        names(guest.root()) == ["project-pinned".to_owned()]
            && fs::metadata(guest.path("project-b")).is_err(),
        "the family never went away: {:?}",
        names(guest.root())
    );
    let hidden = fs::metadata(guest.path("project-b")).expect_err("hidden by the bare `*`");
    assert_eq!(errno(&hidden), Errno::NOENT.raw_os_error(), "{hidden}");

    let mut buffer = [0u8; 13];
    let read = rustix::io::pread(held.as_fd(), &mut buffer, 0).expect("still readable");
    assert_eq!((read, &buffer), (13, b"family member"));
    let refused = fs::File::open(guest.path("project-b/note.txt")).expect_err("hidden now");
    assert_eq!(errno(&refused), Errno::NOENT.raw_os_error(), "{refused}");
}

#[test]
fn a_pattern_admitted_child_presents_like_a_wildcard_admitted_one() {
    support::preflight();
    let fixture = start("pattern-ownership");
    for rule in [
        Rule::new("/mirror", ShareMode::Rw).with_target(host(&fixture, "plain")),
        Rule::new("/mirror/*", ShareMode::Ro),
    ] {
        let response = fixture.control(&Request::RuleAdd {
            namespace: family(),
            rule,
        });
        assert!(matches!(response, Response::Ok { .. }), "{response:?}");
    }

    let guest = fixture.mount("family", "family", "");
    let by_pattern = fs::metadata(guest.path("plain/keep-one")).expect("admitted by the match");
    let by_wildcard = fs::metadata(guest.path("mirror/keep-one")).expect("admitted by the `*`");
    assert_eq!(
        by_pattern.permissions().mode(),
        by_wildcard.permissions().mode()
    );
    assert_eq!(
        (by_pattern.uid(), by_pattern.gid()),
        (by_wildcard.uid(), by_wildcard.gid()),
        "ownership presentation does not know which rule admitted the entry"
    );
}
