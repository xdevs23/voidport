#![forbid(unsafe_code)]

use voidport_test_client as support;

use std::fs;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::Path;

use rustix::fs::XattrFlags;
use rustix::io::Errno;
use support::Fixture;
use voidport_control::{NamespaceName, NamespaceSpec, Reply, Request, Response, Rule, ShareMode};
use voidport_spawn::Program;

/// One host tree, shared read-write at `/tree` and read-only at `/readonly`, so
/// the `EROFS`-before-policy order is observable on the same file.
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
fn verdictless_cli_add_is_refused_without_a_reachable_server() {
    let directory = support::TempDir::new("xattr-no-server");
    let socket = directory.path().join("missing.sock");
    let output = Program::new(support::ctl_binary())
        .arg("--socket")
        .arg(&socket)
        .args(["xattr", "add", "attrs", "user.no-verdict"])
        .output()
        .expect("CLI runs");
    assert!(!output.status.success());
    let diagnostic = String::from_utf8_lossy(&output.stderr);
    assert!(
        diagnostic.contains("xattr add requires --read, --write, or both: a rule states a verdict"),
        "{diagnostic}"
    );
}

fn has_obsolete_glob_limit(help: &str) -> bool {
    help.to_ascii_lowercase().contains("at most 255 bytes")
}

#[test]
fn help_check_targets_the_obsolete_glob_restriction() {
    assert!(has_obsolete_glob_limit("Name glob. At most 255 bytes."));
    assert!(!has_obsolete_glob_limit(
        "Name glob. The kernel limits attribute names to 255 bytes."
    ));
}

#[test]
fn xattr_rules_round_trip_through_the_operator_cli() {
    support::preflight();
    let (fixture, listed) = start("xattr-cli");

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

    let no_verdict = fixture.control(&Request::XattrAdd {
        namespace: NamespaceName::new("attrs").expect("valid namespace"),
        rule: voidport_control::XattrRule::new("user.no-verdict"),
    });
    let diagnostic = &no_verdict
        .as_error()
        .expect("server refuses no verdict")
        .message;
    let expected = voidportd::rules::xattr::XattrRulesError::NoVerdict {
        matches: "user.no-verdict".to_owned(),
    }
    .to_string();
    assert!(diagnostic.contains(&expected), "{diagnostic}");

    let help = fixture.expect_ctl(&["xattr", "add", "--help"]);
    let normalized = help.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        !has_obsolete_glob_limit(&normalized),
        "help states a glob length limit: {help}"
    );
    for expected in [
        "Setting `system.posix_acl_*` always answers EPERM",
        "system.posix_acl_access",
        "system.posix_acl_default",
        "ENODATA when absent or hidden",
        "EPERM when present and readable",
    ] {
        assert!(normalized.contains(expected), "{help}");
    }

    let long = format!("user.long.{}id", "*".repeat(256));
    fixture.expect_ctl(&["xattr", "add", "attrs", &long, "--write", "allow"]);
    let with_long = fixture.expect_ctl(&["xattr", "list", "attrs"]);
    assert!(with_long.contains(&long), "{with_long}");
    let host = fixture.host("attrs/file.bin");
    rustix::fs::setxattr(&host, "user.long.id", b"probe", XattrFlags::empty())
        .expect("backing must store the attribute to test long-glob matching");
    rustix::fs::removexattr(&host, "user.long.id").expect("remove host probe");
    let guest = fixture.mount("xattr-long", "attrs", "/tree");
    rustix::fs::setxattr(
        guest.path("file.bin"),
        "user.long.id",
        b"long glob",
        XattrFlags::empty(),
    )
    .expect("the long glob overrides the write denial");
    let mut value = [0u8; 16];
    let length = rustix::fs::getxattr(&host, "user.long.id", &mut value[..])
        .expect("the matched write reaches the host");
    assert_eq!(&value[..length], b"long glob");
    eprintln!("mounted long-glob matching: host probe and allowed write passed");

    fixture.expect_ctl(&["xattr", "remove", "attrs", "system.*"]);
    let gone = fixture.ctl(&["xattr", "remove", "attrs", "system.*"]);
    assert!(!gone.status.success(), "it is already gone");
    let after = fixture.expect_ctl(&["xattr", "list", "attrs"]);
    assert!(!after.contains("system.*"), "{after}");

    let document = fs::read_to_string(fixture.host("state.toml")).expect("the state file is there");
    assert!(document.contains("[[namespaces.xattr]]"), "{document}");
    assert!(document.contains("match = \"user.build.id\""), "{document}");
    assert!(document.contains(&long), "the full glob persists");
    let loaded = voidportd::state::load(
        &fixture.host("state.toml"),
        &voidport_test_support::invoking_environment(fixture.directory.path()),
    )
    .expect("the persisted rules load");
    let name = NamespaceName::new("attrs").expect("valid namespace");
    assert!(
        loaded
            .registry
            .get(&name)
            .expect("loaded namespace")
            .xattr()
            .writable(b"user.long.id")
    );
    fixture.expect_ctl(&["xattr", "remove", "attrs", &long]);
    assert!(
        !fixture
            .expect_ctl(&["xattr", "list", "attrs"])
            .contains(&long)
    );
}

#[test]
fn precedence_hiding_and_the_acl_guard_hold_through_a_mount() {
    support::preflight();
    let (fixture, _) = start("xattr-policy");
    let guest = fixture.mount("xattr-policy", "attrs", "/tree");
    let path = guest.path("file.bin");
    let host = fixture.host("attrs/file.bin");
    // Only the sections that store a `user.*` attribute on the host need the
    // backing to hold one; every other section runs whatever the backing is.
    let user_xattrs = host_stores_user_xattrs(&host);
    if !user_xattrs {
        eprintln!(
            "not pinning the user.* specificity and hiding sections: {} does not store user \
             extended attributes",
            host.display()
        );
    }
    if user_xattrs {
        user_namespace_specificity_and_hiding(&path, &host);
    }
    let mut value = [0u8; 8];
    // The ACL check overrules the explicit `system.*` write allow, and the mode
    // bits are unchanged afterwards.
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

    // No rule covers `security.*` here, so a write of one is denied by the
    // defaults, while reads reach the host and the guest gets back exactly what
    // the server gets asking the host itself.
    let unruled = rustix::fs::setxattr(&path, "security.voidport", b"label", XattrFlags::empty())
        .expect_err("no rule allows it, so the defaults deny the write");
    assert_eq!(unruled, Errno::PERM);
    let directly = rustix::fs::getxattr(&host, "security.voidport", &mut value[..]).err();
    let through = rustix::fs::getxattr(&path, "security.voidport", &mut value[..]).err();
    assert_eq!(
        through, directly,
        "a read the rules allow carries the host's own answer, whatever it is"
    );

    // A non-`user.*` attribute the host already carries is visible through the
    // mount, where the host filesystem can hold one at all.
    let preexisting = "trusted.voidport-probe";
    if rustix::fs::setxattr(&host, preexisting, b"host", XattrFlags::empty()).is_ok() {
        let read = rustix::fs::getxattr(&path, preexisting, &mut value[..])
            .expect("a pre-existing host attribute reads through the mount");
        assert_eq!(&value[..read], b"host");
        assert!(
            listed(&path).iter().any(|name| name == preexisting),
            "and it is listed: no namespace filter hides it"
        );
    } else {
        eprintln!(
            "skipping the pass-through check for non-user attributes: {} cannot store a \
             trusted.* attribute even for this process",
            host.display()
        );
    }

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

#[test]
fn posix_acl_default_proves_absence_present_eperm_and_value_and_mode_preservation() {
    acl_removal_distinguishes_absent_present_and_hidden_attributes(
        "directory",
        "system.posix_acl_default",
    );
}

#[test]
fn posix_acl_access_proves_absence_present_eperm_and_value_and_mode_preservation() {
    acl_removal_distinguishes_absent_present_and_hidden_attributes(
        "file.bin",
        "system.posix_acl_access",
    );
}

fn acl_removal_distinguishes_absent_present_and_hidden_attributes(entry: &str, name: &str) {
    support::preflight();
    let (fixture, _) = start("acl-remove");
    let acl = acl_blob();
    rustix::fs::setxattr(
        fixture.host("attrs"),
        "system.posix_acl_default",
        &acl,
        XattrFlags::empty(),
    )
    .expect("backing must store a parent default ACL for inheritance");
    fs::remove_file(fixture.host("attrs/file.bin")).expect("replace fixture file");
    fs::write(fixture.host("attrs/file.bin"), b"contents").expect("create fresh file");
    fs::create_dir(fixture.host("attrs/directory")).expect("create fresh directory");
    let host = fixture.host(&format!("attrs/{entry}"));
    assert!(
        rustix::fs::getxattr(&host, name, &mut [0u8; 0][..]).is_ok(),
        "{name} must be inherited before normalization"
    );
    arrange_absent_acl(&host, name);
    let guest = fixture.mount("acl-remove", "attrs", "/tree");
    let readonly = fixture.mount("acl-remove-ro", "attrs", "/readonly");
    let path = guest.path(entry);
    let mut value = vec![0u8; acl.len()];
    assert_eq!(rustix::fs::removexattr(&path, name), Err(Errno::NODATA));
    assert_eq!(
        rustix::fs::removexattr(readonly.path(entry), name),
        Err(Errno::ROFS)
    );

    rustix::fs::setxattr(&host, name, &acl, XattrFlags::empty())
        .unwrap_or_else(|error| panic!("backing refused to store {name}: {error:?} ({error})"));
    let read = rustix::fs::getxattr(&host, name, &mut value[..]).expect("ACL is present");
    assert_eq!(&value[..read], acl);
    let before = fs::metadata(&host).expect("host metadata").mode();
    assert_eq!(rustix::fs::removexattr(&path, name), Err(Errno::PERM));
    let read = rustix::fs::getxattr(&host, name, &mut value[..]).expect("ACL remains");
    assert_eq!(&value[..read], acl);
    assert_eq!(fs::metadata(&host).expect("host metadata").mode(), before);

    fixture.expect_ctl(&[
        "xattr",
        "add",
        "attrs",
        "system.posix_acl_*",
        "--read",
        "deny",
    ]);
    assert_eq!(
        rustix::fs::removexattr(guest.path(entry), name),
        Err(Errno::NODATA)
    );
    assert_eq!(
        rustix::fs::removexattr(readonly.path(entry), name),
        Err(Errno::ROFS)
    );
    let read =
        rustix::fs::getxattr(&host, name, &mut value[..]).expect("a hidden ACL is unchanged");
    assert_eq!(&value[..read], acl);
    assert_eq!(fs::metadata(&host).expect("host metadata").mode(), before);
    eprintln!("{name}: host storage, present refusal and value and mode preservation passed");
}

#[test]
fn ordinary_xattr_removal_relays_the_probed_host_outcome() {
    support::preflight();
    let (fixture, _) = start("ordinary-remove");
    let host = fixture.host("attrs/file.bin");
    let direct_set = rustix::fs::setxattr(&host, "user.build.id", b"7", XattrFlags::empty());
    let direct_remove = rustix::fs::removexattr(&host, "user.build.id");
    let direct_absent = rustix::fs::removexattr(&host, "user.build.id");
    let guest = fixture.mount("ordinary-remove", "attrs", "/tree");
    let path = guest.path("file.bin");
    assert_eq!(
        rustix::fs::setxattr(&path, "user.build.id", b"7", XattrFlags::empty()),
        direct_set,
        "allowed setting relays the host answer"
    );
    assert_eq!(
        rustix::fs::removexattr(&path, "user.build.id"),
        direct_remove
    );
    assert_eq!(
        rustix::fs::removexattr(&path, "user.build.id"),
        direct_absent
    );
    assert_eq!(
        rustix::fs::removexattr(&path, "user.other"),
        Err(Errno::PERM)
    );
}

#[test]
fn acl_blob_stores_both_names_with_the_effective_identity() {
    support::preflight();
    let directory = support::TempDir::new("acl-identity");
    let file = directory.write("file", "contents");
    let acl = acl_blob();
    for (path, name) in [
        (directory.path(), "system.posix_acl_default"),
        (file.as_path(), "system.posix_acl_access"),
    ] {
        rustix::fs::setxattr(path, name, &acl, XattrFlags::empty())
            .expect("backing must store the ACL with the effective identity");
        let mut value = vec![0; acl.len()];
        let read = rustix::fs::getxattr(path, name, &mut value[..])
            .expect("the named entry keeps the ACL stored");
        assert_eq!(&value[..read], acl);
    }
}

fn user_namespace_specificity_and_hiding(path: &Path, host: &Path) {
    let mut value = [0u8; 8];
    assert_eq!(
        rustix::fs::setxattr(path, "user.other", b"x", XattrFlags::empty())
            .expect_err("denied by user.*"),
        Errno::PERM
    );
    rustix::fs::setxattr(path, "user.build.id", b"7", XattrFlags::empty())
        .expect("the longer literal prefix wins");
    assert_eq!(
        rustix::fs::getxattr(host, "user.other", &mut [0u8; 8][..]).expect_err("never written"),
        Errno::NODATA
    );
    assert_eq!(
        rustix::fs::removexattr(path, "user.other").expect_err("removal is a write"),
        Errno::PERM
    );
    // Reads were never stated on those rules, so they fall to the default.
    let read = rustix::fs::getxattr(path, "user.build.id", &mut value[..]).expect("readable");
    assert_eq!(&value[..read], b"7");

    for (name, hidden) in [
        ("user.hidden.key", true),
        ("user.only-secret", true),
        ("user.secret-public", true),
        ("user.only-public", false),
    ] {
        rustix::fs::setxattr(host, name, b"v", XattrFlags::empty()).expect("the host stores it");
        let outcome = rustix::fs::getxattr(path, name, &mut value[..]);
        assert_eq!(
            outcome.err(),
            hidden.then_some(Errno::NODATA),
            "{name}: a denied read must look exactly like an absent one"
        );
        assert_eq!(
            listed(path).iter().any(|listed| listed == name),
            !hidden,
            "{name}: a denial must not advertise what it denies"
        );
    }
}
fn arrange_absent_acl(host: &Path, name: &str) {
    match rustix::fs::getxattr(host, name, &mut [0u8; 0][..]) {
        Ok(_) => rustix::fs::removexattr(host, name)
            .expect("inherited ACL must be removable on the host"),
        Err(Errno::NODATA) => {}
        Err(error) => panic!("cannot query {name}: {error:?} ({error})"),
    }
    assert_eq!(
        rustix::fs::getxattr(host, name, &mut [0u8; 0][..]),
        Err(Errno::NODATA),
        "{name} must be absent on the host before mounted removal"
    );
}

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

/// Whether the host filesystem stores `user.*` attributes at all. tmpfs does so only from Linux 6.6.
fn host_stores_user_xattrs(host: &Path) -> bool {
    let supported = rustix::fs::setxattr(host, "user.probe", b"1", XattrFlags::empty()).is_ok();
    let _ = rustix::fs::removexattr(host, "user.probe");
    supported
}

/// A version-2 POSIX ACL with five entries: owning user (0x0001), named user
/// (0x0002), owning group (0x0004), mask (0x0010), and other (0x0020). The
/// named user requires the mask, so the access attribute stays stored instead
/// of reduced to mode bits.
fn acl_blob() -> Vec<u8> {
    let mut blob = vec![2u8, 0, 0, 0];
    for (tag, permissions, id) in [
        (0x0001u16, 0x0007u16, u32::MAX),
        (0x0002, 0x0004, rustix::process::geteuid().as_raw()),
        (0x0004, 0x0007, u32::MAX),
        (0x0010, 0x0007, u32::MAX),
        (0x0020, 0x0007, u32::MAX),
    ] {
        blob.extend_from_slice(&tag.to_le_bytes());
        blob.extend_from_slice(&permissions.to_le_bytes());
        blob.extend_from_slice(&id.to_le_bytes());
    }
    blob
}
