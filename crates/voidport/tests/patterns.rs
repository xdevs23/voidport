//! Pattern rules through a real mount: the specificity chain, live matching,
//! the leading-dot rule, and the motivating composition end to end.
//!
//! The field need this increment answers is a *changing family* of sibling
//! directories — `project-*` beside a shared project directory — appearing
//! live and with guest-created members landing durably on the host. Every
//! assertion below is what a guest process sees: `ls`, `stat`, `mkdir`, and
//! the errno the kernel returned.

mod support;

use std::fs;
use std::os::fd::AsFd as _;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::Path;
use std::time::Duration;

use rustix::io::Errno;
use support::{Fixture, errno, eventually, presented_mode};
use voidport_control::{NamespaceName, NamespaceSpec, Reply, Request, Response, Rule, ShareMode};

/// How long a test waits for something the cache timeouts bound.
const PATIENCE: Duration = Duration::from_secs(10);

/// The namespace the whole file mounts: three grafts, each one a shape the
/// design distinguishes.
///
/// * `/family` — the motivating composition: the parent shared `rw`, its
///   children hidden by a bare `*`, one family un-hidden by a match, and one
///   member pinned read-only by a literal rule that beats the match.
/// * `/plain` — the same family shape with **no** wildcard, which is the only
///   place the enclosing default is observable at all.
/// * `/dots` — the leading-dot probe: a match starting with `*`, and one
///   starting with a literal `.`.
fn namespace(fixture: &Fixture) -> NamespaceSpec {
    NamespaceSpec {
        rules: vec![
            Rule::new("/family", ShareMode::Rw).with_target(host(fixture, "family")),
            Rule::new("/family/*", ShareMode::Hidden),
            Rule::new("/family", ShareMode::Rw).with_match("project-*"),
            Rule::new("/family/project-pinned", ShareMode::Ro),
            Rule::new("/plain", ShareMode::Rw).with_target(host(fixture, "plain")),
            Rule::new("/plain", ShareMode::Ro).with_match("keep-*"),
            // A path component containing `*` is the literal name it always
            // was: this rule governs the host entry really called `b*`.
            Rule::new("/plain/b*", ShareMode::Ro),
            Rule::new("/dots", ShareMode::Rw).with_target(host(fixture, "dots")),
            Rule::new("/dots", ShareMode::Ro).with_match("*-a"),
            Rule::new("/dots", ShareMode::Hidden).with_match(".b-*"),
        ],
        ..NamespaceSpec::new(family())
    }
}

/// The namespace these tests configure.
fn family() -> NamespaceName {
    NamespaceName::new("family").expect("valid namespace name")
}

/// A host path inside the fixture, as a string the control plane takes.
fn host(fixture: &Fixture, relative: &str) -> String {
    fixture.host(relative).display().to_string()
}

/// Builds the host tree the namespace grafts and registers the namespace.
///
/// The host directories exist before the namespace does, because a graft
/// target is pinned when the namespace is built.
fn start(label: &str) -> Fixture {
    let fixture = Fixture::start(label);
    for relative in [
        // The family, plus a member named exactly `project-` — the empty run
        // is a run — and two names the match does not cover.
        "family/project-a",
        "family/project-b",
        "family/project-",
        "family/project-pinned",
        "family/other",
        "family/.project-dot",
        // The wildcard-free directory: one covered name, one not, plus a host
        // entry literally named `b*` and one that a glob reading of that name
        // would have swallowed.
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

/// Creates a host directory with a mode the presented bits can be read off.
fn make(path: &Path) {
    fs::create_dir_all(path).expect("the host is writable");
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("a settable mode");
}

/// The names a directory lists, sorted.
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

/// Criterion 5: the motivating composition, end to end.
#[test]
fn the_family_composition_shows_exactly_the_family_and_takes_new_members() {
    if !support::preflight() {
        return;
    }
    let fixture = start("pattern-family");
    let guest = fixture.mount("family", "family", "/family");

    // Exactly the family — plus the literal rule's own entry — and nothing
    // else: `other` is hidden by the bare `*`, and the dotfile is not covered
    // by a match that starts with `project`.
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

    // A guest `mkdir` of a name the match admits creates the real host
    // directory — durable across relaunches, which is the whole point.
    fs::create_dir(guest.path("project-new")).expect("the match admits the name");
    assert!(
        fixture.host("family/project-new").is_dir(),
        "the new member landed on the host"
    );
    // A second one answers the host's own EEXIST, not an invented errno.
    let again = fs::create_dir(guest.path("project-new")).expect_err("it exists now");
    assert_eq!(errno(&again), Errno::EXIST.raw_os_error(), "{again}");

    // A name only hidden rules cover is refused, not created and
    // hidden: EACCES, as the design requires.
    let refused = fs::create_dir(guest.path("other-new")).expect_err("hidden names take no create");
    assert_eq!(errno(&refused), Errno::ACCESS.raw_os_error(), "{refused}");
    assert!(
        !fixture.host("family/other-new").exists(),
        "a refused create must not have touched the host"
    );
}

/// Criterion 4: evaluation is live — a host directory created after the rules
/// exist is covered at its next lookup, with no control-plane operation.
#[test]
fn a_member_created_on_the_host_appears_without_any_control_plane_operation() {
    if !support::preflight() {
        return;
    }
    let fixture = start("pattern-live");
    let guest = fixture.mount("family", "family", "/family");
    assert!(!guest.path("project-late").exists());

    make(&fixture.host("family/project-late"));
    // Also a name the match does not cover, which must stay invisible however
    // long the test waits.
    make(&fixture.host("family/late"));

    assert!(
        eventually(PATIENCE, || guest.path("project-late").is_dir()),
        "a new family member is covered at its next lookup, TTL-bounded"
    );
    assert!(!guest.path("late").exists(), "and nothing else is");

    // The empty run is a run: `project-*` covers a child named exactly
    // `project-`.
    assert!(guest.path("project-").is_dir());
}

/// Criterion 2: the specificity chain holds at resolution through a real
/// mount — literal over pattern over `*`, and pattern over the enclosing
/// default where no `*` shadows it.
#[test]
fn the_specificity_chain_holds_through_a_real_mount() {
    if !support::preflight() {
        return;
    }
    let fixture = start("pattern-specificity");
    let guest = fixture.mount("family", "family", "");

    // At one directory, three names, one winner each.
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

/// Criterion 1's compatibility half: a rule path component containing `*` still
/// names the host entry that is literally called that, and nothing about the
/// match syntax reaches into a path.
#[test]
fn a_host_entry_named_with_a_star_is_still_a_literal_name() {
    if !support::preflight() {
        return;
    }
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

/// Criterion 3's resolution half: the leading-dot rule, at a real mount.
#[test]
fn a_match_reaches_a_dotfile_only_when_it_begins_with_a_dot() {
    if !support::preflight() {
        return;
    }
    let fixture = start("pattern-dots");
    let guest = fixture.mount("family", "family", "/dots");

    // `*-a` covers `x-a`...
    assert_eq!(presented_mode(&guest.path("x-a")), "r-x------");
    // ...and cannot reach `.c-a`, which therefore inherits the graft's own
    // read-write mode instead of the match's read-only one.
    assert_eq!(
        presented_mode(&guest.path(".c-a")),
        "rwx------",
        "a match starting with `*` never covers a name starting with `.`"
    );
    // A match that begins with a literal `.` does cover dotfiles: this one is
    // hidden, with full invisibility.
    let hidden = fs::metadata(guest.path(".b-a")).expect_err("hidden by `.b-*`");
    assert_eq!(errno(&hidden), Errno::NOENT.raw_os_error(), "{hidden}");
    assert!(!names(guest.root()).contains(&".b-a".to_owned()));
}

/// Policy binds at lookup, and a pattern is policy like every other rule.
///
/// The pattern criteria prove a match appearing and admitting; this is the
/// other direction, and it is the one an operator reaches for when a family
/// must stop being shared. Taking the match away drops its members back onto
/// the bare `*` that hides them — at the next lookup, TTL-bounded, with no
/// remount — while a handle opened before the removal keeps working, because a
/// node's mode binds at the lookup that admitted it and open handles are
/// grandfathered.
#[test]
fn removing_a_pattern_hides_its_family_at_the_next_lookup_and_spares_an_open_handle() {
    if !support::preflight() {
        return;
    }
    let fixture = start("pattern-removal");
    let guest = fixture.mount("family", "family", "/family");

    // Opened while the match still admits the name.
    let held = fs::File::open(guest.path("project-b/note.txt")).expect("openable");

    let response = fixture.control(&Request::RuleRemove {
        namespace: family(),
        path: "/family".to_owned(),
        r#match: Some("project-*".to_owned()),
    });
    assert!(matches!(response, Response::Ok { .. }), "{response:?}");

    // Nothing claims the family now, so the bare `*` decides it — and the one
    // member a literal rule names outlives the match that used to cover it.
    // The listing and the cached entry are bounded separately — a name already
    // resolved keeps its dentry for the entry timeout — so both are waited for.
    assert!(
        eventually(PATIENCE, || names(guest.root())
            == ["project-pinned".to_owned()]
            && fs::metadata(guest.path("project-b")).is_err()),
        "the family never went away: {:?}",
        names(guest.root())
    );
    let hidden = fs::metadata(guest.path("project-b")).expect_err("hidden by the bare `*`");
    assert_eq!(errno(&hidden), Errno::NOENT.raw_os_error(), "{hidden}");

    // The handle from before is untouched, and a fresh look at the same path is
    // refused — which is exactly the split the design draws.
    let mut buffer = [0u8; 13];
    let read = rustix::io::pread(held.as_fd(), &mut buffer, 0).expect("still readable");
    assert_eq!((read, &buffer), (13, b"family member"));
    let refused = fs::File::open(guest.path("project-b/note.txt")).expect_err("hidden now");
    assert_eq!(errno(&refused), Errno::NOENT.raw_os_error(), "{refused}");
}

/// Criterion 8: a pattern-admitted child composes with ownership and
/// permissions exactly as a wildcard-admitted one does.
#[test]
fn a_pattern_admitted_child_presents_like_a_wildcard_admitted_one() {
    if !support::preflight() {
        return;
    }
    let fixture = start("pattern-ownership");
    // The same host directory, admitted read-only two ways: by a match under
    // `/plain`, and by a bare `*` under a second graft of it.
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
