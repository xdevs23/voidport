//! Extended-attribute rules through a real mount, configured through the real
//! operator CLI.
//!
//! Everything here is what a guest process sees — the errno the kernel returned,
//! the names `listxattr` reported, the mode bits after a refused write — against
//! a namespace whose rules were added by running `voidport-ctl xattr add` as an
//! operator would.

mod support;

use std::fs;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::Path;

use rustix::fs::XattrFlags;
use rustix::io::Errno;
use support::Fixture;
use voidport_control::{NamespaceName, NamespaceSpec, Reply, Request, Response, Rule, ShareMode};

/// The namespace these tests configure: one host tree, shared read-write at
/// `/tree` and read-only at `/readonly`, so the `EROFS`-before-policy order is
/// observable on the very same file.
fn namespace(fixture: &Fixture) -> NamespaceSpec {
    let target = fixture.host("attrs").display().to_string();
    NamespaceSpec {
        rules: vec![
            Rule::new("/tree", ShareMode::Rw).with_target(target.clone()),
            Rule::new("/readonly", ShareMode::Ro).with_target(target),
        ],
        ..NamespaceSpec::new(NamespaceName::new("attrs").expect("valid namespace name"))
    }
}

/// Starts a fixture with the namespace and its rules in place.
///
/// The rules go in through the real CLI binary, because "round-trips through
/// `voidport-ctl`" is the criterion and a request built in-process would not
/// prove it.
fn start(label: &str) -> (Fixture, String) {
    let fixture = Fixture::start(label);
    fs::create_dir_all(fixture.host("attrs")).expect("the host is writable");
    fs::write(fixture.host("attrs/file.bin"), b"contents").expect("the host is writable");
    fs::set_permissions(
        fixture.host("attrs/file.bin"),
        fs::Permissions::from_mode(0o644),
    )
    .expect("a settable mode");

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

    // The layering pair, the hiding rule, and the exact tie.
    for arguments in [
        vec!["xattr", "add", "attrs", "user.*", "--write", "deny"],
        vec!["xattr", "add", "attrs", "user.build.id", "--write", "allow"],
        vec!["xattr", "add", "attrs", "user.hidden.*", "--read", "deny"],
        vec!["xattr", "add", "attrs", "user.*secret*", "--read", "deny"],
        vec!["xattr", "add", "attrs", "user.*public*", "--read", "allow"],
        vec!["xattr", "add", "attrs", "system.*", "--write", "allow"],
    ] {
        fixture.expect_ctl(&arguments);
    }

    let listed = fixture.expect_ctl(&["xattr", "list", "attrs"]);
    (fixture, listed)
}

#[test]
fn xattr_rules_round_trip_through_the_operator_cli() {
    if !support::preflight() {
        return;
    }
    let (fixture, listed) = start("xattr-cli");

    // Every rule added is a rule listed, with the verdicts it stated and the
    // ones it did not.
    assert!(listed.contains("attributes:"), "{listed}");
    for expected in [
        "user.*",
        "user.build.id",
        "user.hidden.*",
        "user.*secret*",
        "user.*public*",
        "system.*",
    ] {
        assert!(
            listed.contains(expected),
            "{expected} missing from:\n{listed}"
        );
    }
    assert!(
        listed.contains("read -"),
        "an unstated verdict reads as unstated:\n{listed}"
    );

    // A second rule with the same match is refused: a rule is keyed by it.
    let duplicate = fixture.ctl(&["xattr", "add", "attrs", "user.*", "--read", "deny"]);
    assert!(
        !duplicate.status.success(),
        "a duplicate match must be refused"
    );
    let message = String::from_utf8_lossy(&duplicate.stdout).into_owned()
        + &String::from_utf8_lossy(&duplicate.stderr);
    assert!(
        message.contains("user.*"),
        "the refusal names the rule: {message}"
    );

    // And so is a match longer than an attribute name can be.
    let long = "u".repeat(256);
    let oversized = fixture.ctl(&["xattr", "add", "attrs", &long]);
    assert!(!oversized.status.success(), "255 bytes is the cap");

    // Removal is keyed by the match alone, and a second removal says so.
    fixture.expect_ctl(&["xattr", "remove", "attrs", "system.*"]);
    let gone = fixture.ctl(&["xattr", "remove", "attrs", "system.*"]);
    assert!(!gone.status.success(), "it is already gone");
    let after = fixture.expect_ctl(&["xattr", "list", "attrs"]);
    assert!(!after.contains("system.*"), "{after}");

    // The state file holds exactly what was configured, so a restart keeps it.
    let document = fs::read_to_string(fixture.host("state.toml")).expect("the state file is there");
    assert!(document.contains("[[namespaces.xattr]]"), "{document}");
    assert!(document.contains("match = \"user.build.id\""), "{document}");
}

#[test]
fn precedence_hiding_and_the_acl_guard_hold_through_a_mount() {
    if !support::preflight() {
        return;
    }
    let (fixture, _) = start("xattr-policy");
    let guest = fixture.mount("xattr-policy", "attrs", "/tree");
    let path = guest.path("file.bin");
    let host = fixture.host("attrs/file.bin");
    if !host_stores_user_xattrs(&host) {
        eprintln!(
            "skipping: {} does not store user extended attributes",
            host.display()
        );
        return;
    }

    // Specificity: `user.*` is write-denied, and the longer literal prefix wins
    // its own name back.
    assert_eq!(
        rustix::fs::setxattr(&path, "user.other", b"x", XattrFlags::empty())
            .expect_err("denied by user.*"),
        Errno::PERM
    );
    rustix::fs::setxattr(&path, "user.build.id", b"7", XattrFlags::empty())
        .expect("the longer literal prefix wins");
    // The denied write left the host untouched.
    assert_eq!(
        rustix::fs::getxattr(&host, "user.other", &mut [0u8; 8][..]).expect_err("never written"),
        Errno::NODATA
    );
    // Removal takes the write verdict too.
    assert_eq!(
        rustix::fs::removexattr(&path, "user.other").expect_err("removal is a write"),
        Errno::PERM
    );
    // Reads were never stated on those rules, so they fall to the default.
    let mut value = [0u8; 8];
    let read = rustix::fs::getxattr(&path, "user.build.id", &mut value[..]).expect("readable");
    assert_eq!(&value[..read], b"7");

    // Hiding: an attribute that really is on the host, whose read is denied, is
    // absent from the listing and answers `ENODATA` — the same invisibility the
    // hidden-rule probes ask of a hidden name.
    for (name, hidden) in [
        ("user.hidden.key", true),
        ("user.only-secret", true),
        ("user.secret-public", true),
        ("user.only-public", false),
    ] {
        rustix::fs::setxattr(&host, name, b"v", XattrFlags::empty()).expect("the host stores it");
        let outcome = rustix::fs::getxattr(&path, name, &mut value[..]);
        assert_eq!(
            outcome.err(),
            hidden.then_some(Errno::NODATA),
            "{name}: a denied read must look exactly like an absent one"
        );
        assert_eq!(
            listed(&path).iter().any(|listed| listed == name),
            !hidden,
            "{name}: a denial must not advertise what it denies"
        );
    }

    // The ACL guard overrules the explicit `system.*` write allow, and the mode
    // bits are unchanged afterwards — the measured bypass, blocked.
    let before = fs::metadata(&host).expect("stat").mode();
    assert_eq!(
        rustix::fs::setxattr(
            &path,
            "system.posix_acl_access",
            &acl_blob(),
            XattrFlags::empty()
        )
        .expect_err("the guard is unconditional"),
        Errno::PERM
    );
    assert_eq!(
        fs::metadata(&host).expect("stat").mode(),
        before,
        "a refused ACL write may not change the permission bits"
    );

    // Passthrough honesty, asserted against this machine, not against a
    // guessed posture. No rule covers `security.*` here, so a write of one is
    // denied by the defaults — while the *reads* the retired blanket filter
    // used to swallow now reach the host, and what the guest gets back is
    // exactly what the server gets asking the host itself.
    let unruled = rustix::fs::setxattr(&path, "security.voidport", b"label", XattrFlags::empty())
        .expect_err("no rule allows it, so the defaults deny the write");
    assert_eq!(unruled, Errno::PERM);
    let directly = rustix::fs::getxattr(&host, "security.voidport", &mut value[..]).err();
    let through = rustix::fs::getxattr(&path, "security.voidport", &mut value[..]).err();
    assert_eq!(
        through, directly,
        "a read the rules allow carries the host's own answer, whatever it is"
    );

    // The filter retirement itself: a non-`user.*` attribute the host already
    // carries is visible through the mount, where this machine's filesystem can
    // hold one at all. The old code answered `EOPNOTSUPP` for the get and left
    // the name out of every listing.
    let preexisting = "trusted.voidport-probe";
    if rustix::fs::setxattr(&host, preexisting, b"host", XattrFlags::empty()).is_ok() {
        let read = rustix::fs::getxattr(&path, preexisting, &mut value[..])
            .expect("a pre-existing host attribute reads through the mount");
        assert_eq!(&value[..read], b"host");
        assert!(
            listed(&path).iter().any(|name| name == preexisting),
            "and it is listed: the namespace filter is gone"
        );
    } else {
        eprintln!(
            "not pinning the listing half of the filter retirement: {} cannot store a \
             trusted.* attribute even for this process",
            host.display()
        );
    }

    // And the share mode comes first: `EROFS` before any of the above.
    let readonly = fixture.mount("xattr-ro", "attrs", "/readonly");
    for name in ["user.build.id", "user.other"] {
        assert_eq!(
            rustix::fs::setxattr(readonly.path("file.bin"), name, b"9", XattrFlags::empty())
                .expect_err("read-only"),
            Errno::ROFS,
            "{name}"
        );
    }
}

/// The attribute names a path lists, as the guest kernel reports them.
fn listed(path: &Path) -> Vec<String> {
    let size = rustix::fs::listxattr(path, &mut [][..] as &mut [u8]).expect("a size probe");
    let mut blob = vec![0u8; size];
    let read = rustix::fs::listxattr(path, &mut blob[..]).expect("listable");
    blob[..read]
        .split(|byte| *byte == 0)
        .filter(|name| !name.is_empty())
        .map(|name| String::from_utf8_lossy(name).into_owned())
        .collect()
}

/// Whether the host filesystem under a file stores `user.*` attributes at all.
///
/// tmpfs could not before Linux 6.6, and this suite has to run on both.
fn host_stores_user_xattrs(host: &Path) -> bool {
    let supported = rustix::fs::setxattr(host, "user.probe", b"1", XattrFlags::empty()).is_ok();
    let _ = rustix::fs::removexattr(host, "user.probe");
    supported
}

/// A minimal `system.posix_acl_access` value: version 2, then one entry each for
/// the owner, the owning group and others, the owner granted `rwx`.
///
/// A blob like this one is what rewrites the file's mode when it lands, which is
/// the bypass the guard exists to block.
fn acl_blob() -> Vec<u8> {
    let mut blob = vec![2u8, 0, 0, 0];
    for (tag, permissions) in [(0x0001u16, 0x0007u16), (0x0004, 0x0007), (0x0020, 0x0007)] {
        blob.extend_from_slice(&tag.to_le_bytes());
        blob.extend_from_slice(&permissions.to_le_bytes());
        blob.extend_from_slice(&u32::MAX.to_le_bytes());
    }
    blob
}
