use std::cell::RefCell;
use std::time::Duration;

use rustix::mount::{MountAttrFlags, MountFlags};

use super::log::Logged;
use super::options::Given;
use super::*;
use crate::mount::MountOptions;

fn url(raw: &str) -> MountUrl {
    MountUrl::parse(raw).unwrap_or_else(|error| panic!("{raw} should parse: {error}"))
}

fn options(raw: &[&str]) -> KernelMountOptions {
    KernelMountOptions::from_mount_options(raw.iter().copied())
}

fn servers(raw: &str) -> Servers {
    Route::of(&url(raw).endpoint)
        .and_then(|route| route.servers())
        .unwrap_or_else(|error| panic!("{raw} should have servers: {error}"))
}

fn tcp(address: &str) -> Server {
    Server(Address::Tcp(address.parse().expect("an address")))
}

fn refused(server: &Server) -> KernelError {
    KernelError::Refused {
        server: server.clone(),
        log: KernelLog::default(),
        source: io::Error::from(io::ErrorKind::ConnectionRefused),
    }
}

#[test]
fn a_tcp_share_gives_the_url_the_namespace_the_address_the_port_and_the_path() {
    let written = "voidport://build-host.example:9000/@my-namespace/path/to/project";
    assert_eq!(
        share(written, &url(written), &tcp("10.0.2.2:9000")),
        [
            SharePart::new(MountOption::Source, written),
            SharePart::new(MountOption::Namespace, "my-namespace"),
            SharePart::new(MountOption::Addr, "10.0.2.2"),
            SharePart::new(MountOption::Port, "9000"),
            SharePart::new(MountOption::Path, "/path/to/project"),
        ]
    );
}

#[test]
fn an_ipv6_address_goes_to_the_module_without_brackets() {
    let written = "voidport://[::1]:9000/@ns";
    let servers = servers(written);
    assert!(servers.rest.is_empty());
    assert_eq!(
        share(written, &url(written), &servers.first)[2..],
        [
            SharePart::new(MountOption::Addr, "::1"),
            SharePart::new(MountOption::Port, "9000"),
        ]
    );
}

#[test]
fn a_unix_share_gives_its_socket_and_path_byte_for_byte() {
    // A comma, a quote and an equals sign are bytes of the values, not
    // option syntax.
    let written = "voidport+unix://%2Frun%2Fa%2Cb%3D%22.sock/@ns/x%2Cy%3Dz%22/%FF";
    let servers = servers(written);
    assert_eq!(
        share(written, &url(written), &servers.first)[2..],
        [
            SharePart::new(MountOption::Unix, "/run/a,b=\".sock"),
            SharePart::new(MountOption::Path, b"/x,y=z\"/\xff".as_slice()),
        ]
    );
}

#[test]
fn the_namespace_root_needs_no_path() {
    let written = "voidport+unix://%2Frun%2Fdata.sock/@ns/";
    let server = Server(Address::Unix(PathBuf::from("/run/data.sock")));
    assert!(
        share(written, &url(written), &server)
            .iter()
            .all(|part| part.option != MountOption::Path)
    );
}

#[test]
fn a_vsock_url_has_no_server_the_module_can_dial() {
    let vsock = url("voidport+vsock://2:9000/@ns");
    assert!(!can_dial(&vsock.endpoint));
    assert!(matches!(
        Route::of(&vsock.endpoint),
        Err(KernelError::Vsock)
    ));
    assert!(can_dial(&url("voidport://h:1/@ns").endpoint));
}

#[test]
fn generic_options_become_the_attributes_of_the_mount() {
    let read = options(&[
        "ro",
        "nosuid",
        "nodev",
        "noexec",
        "nosymfollow",
        "nodiratime",
    ]);
    assert_eq!(
        read.flags.attributes(),
        MountAttrFlags::MOUNT_ATTR_RDONLY
            | MountAttrFlags::MOUNT_ATTR_NOSUID
            | MountAttrFlags::MOUNT_ATTR_NODEV
            | MountAttrFlags::MOUNT_ATTR_NOEXEC
            | MountAttrFlags::MOUNT_ATTR_NOSYMFOLLOW
            | MountAttrFlags::MOUNT_ATTR_NODIRATIME
            | MountAttrFlags::MOUNT_ATTR_RELATIME
    );
    assert_eq!(
        read.flags.remount_flags(),
        MountFlags::BIND
            | MountFlags::RDONLY
            | MountFlags::NOSUID
            | MountFlags::NODEV
            | MountFlags::NOEXEC
            | MountFlags::NOSYMFOLLOW
            | MountFlags::NODIRATIME
            | MountFlags::RELATIME
    );
    assert!(read.given.is_empty());
    assert_eq!(
        options(&["ro", "nosuid", "nosymfollow", "rw", "suid", "symfollow"])
            .flags
            .attributes(),
        MountAttrFlags::MOUNT_ATTR_RELATIME
    );
}

#[test]
fn the_atime_family_combines_as_mount_does() {
    let atime = |raw: &[&str]| options(raw).flags.attributes() & MountAttrFlags::MOUNT_ATTR__ATIME;
    assert_eq!(atime(&[]), MountAttrFlags::MOUNT_ATTR_RELATIME);
    assert_eq!(atime(&["noatime"]), MountAttrFlags::MOUNT_ATTR_NOATIME);
    assert_eq!(
        atime(&["noatime", "relatime"]),
        MountAttrFlags::MOUNT_ATTR_NOATIME
    );
    assert_eq!(
        atime(&["noatime", "atime"]),
        MountAttrFlags::MOUNT_ATTR_RELATIME
    );
    assert_eq!(
        atime(&["strictatime", "noatime"]),
        MountAttrFlags::MOUNT_ATTR_STRICTATIME
    );
    assert_eq!(
        atime(&["strictatime", "nostrictatime"]),
        MountAttrFlags::MOUNT_ATTR_RELATIME
    );
}

#[test]
fn module_options_go_to_the_module_and_mount_options_stay_behind() {
    let read = options(&[
        "",
        "attr_timeout=0",
        "no_privileged_bits",
        "sync",
        "_netdev",
        "nofail",
        "defaults",
        "user=someone",
        "x-systemd.automount",
        "comment=fstab",
    ]);
    assert_eq!(
        read.given,
        [
            Given::Value {
                name: "attr_timeout".to_owned(),
                value: "0".to_owned(),
            },
            Given::Flag("no_privileged_bits".to_owned()),
            Given::Flag("sync".to_owned()),
        ]
    );
    assert!(!read.remounts());
    assert!(options(&["rw", "remount", "ro"]).remounts());
}

#[test]
fn a_mount_takes_its_share_from_the_url_alone() {
    for raw in [
        "addr=10.0.0.1",
        "port=1",
        "unix=/s",
        "path=/p",
        "source=ns",
        "namespace=ns",
    ] {
        let share_option = options(&[raw]);
        assert!(
            matches!(
                PendingMount::new("voidport://h:1/@ns", Path::new("/"), &share_option),
                Err(KernelError::ShareOption { .. })
            ),
            "{raw}"
        );
    }
}

#[test]
fn a_value_longer_than_a_string_option_accepts_is_refused_before_the_kernel() {
    let long = format!("attr_timeout={}", "1".repeat(STRING_MAX + 1));
    let too_long = options(&[long.as_str()]);
    assert!(matches!(
        PendingMount::new("voidport+unix://%2Fs/@ns", Path::new("/"), &too_long),
        Err(KernelError::TooLong { key }) if key == "attr_timeout"
    ));
    let deep = format!("voidport+unix://%2Fs/@ns/{}", "p".repeat(STRING_MAX + 1));
    assert!(PendingMount::new(&deep, Path::new("/"), &options(&[])).is_ok());
}

#[test]
fn a_missing_mountpoint_is_reported_before_any_server_is_tried() {
    assert!(matches!(
        PendingMount::new("voidport+unix://%2Fs/@ns", Path::new("/nonexistent"), &options(&[])),
        Err(KernelError::Target { target, .. }) if target == Path::new("/nonexistent")
    ));
}

#[test]
fn servers_are_tried_in_order_until_one_mounts() {
    let servers = Servers {
        first: tcp("10.0.0.1:1"),
        rest: vec![tcp("10.0.0.2:1"), tcp("10.0.0.3:1"), tcp("10.0.0.4:1")],
    };
    let tried = RefCell::new(Vec::new());
    let result = first_mounted(&servers, |server| {
        tried.borrow_mut().push(server.clone());
        if tried.borrow().len() < 3 {
            Err(refused(server))
        } else {
            Ok(())
        }
    });
    assert!(result.is_ok());
    assert_eq!(
        *tried.borrow(),
        servers.iter().take(3).cloned().collect::<Vec<_>>()
    );
}

#[test]
fn the_last_refusal_is_returned_and_any_other_failure_ends_the_attempt() {
    let servers = Servers {
        first: tcp("10.0.0.1:1"),
        rest: vec![tcp("10.0.0.2:1")],
    };
    assert!(matches!(
        first_mounted(&servers, |server| Err(refused(server))),
        Err(KernelError::Refused { server, .. }) if server == servers.rest[0]
    ));
    let mut tried = 0;
    assert!(matches!(
        first_mounted(&servers, |_| {
            tried += 1;
            Err(KernelError::NoModule)
        }),
        Err(KernelError::NoModule)
    ));
    assert_eq!(tried, 1);
}

#[test]
fn a_logged_record_is_read_with_its_level() {
    let log = KernelLog(vec![
        Logged::message("e voidport: path must be an absolute path inside the namespace\n"),
        Logged::message("w voidport: slow\n"),
        Logged::message("unmarked"),
    ]);
    assert_eq!(
        log.to_string(),
        ": voidport: path must be an absolute path inside the namespace\
         : warning: voidport: slow: unmarked"
    );
}

#[test]
fn the_client_options_are_the_modules_own() {
    let options = KernelMountOptions::for_client(&MountOptions {
        attr_timeout: Duration::from_millis(1500),
        privileged_bits: false,
        read_only: true,
        ..MountOptions::default()
    });
    assert_eq!(
        options.given.iter().map(Given::name).collect::<Vec<_>>(),
        [
            "attr_timeout",
            "entry_timeout",
            "reconnect_stall",
            "no_privileged_bits"
        ]
    );
    assert_eq!(
        options.given[0],
        Given::Value {
            name: "attr_timeout".to_owned(),
            value: "1.500000000".to_owned(),
        }
    );
    assert!(
        options
            .flags
            .attributes()
            .contains(MountAttrFlags::MOUNT_ATTR_RDONLY)
    );
}
