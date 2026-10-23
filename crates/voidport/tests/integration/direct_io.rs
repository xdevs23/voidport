//! The host filesystem grants the leases the server needs, so a mount without
//! the option would cache the pages of these files.

use voidport_test_client as support;

use std::fs::{self, File};

use rustix::io::Errno;
use support::Fixture;
use support::mapping::SharedMapping;
use support::relay::Relay;
use voidport::mount::MountOptions;
use voidport_proto::opcode::Opcode;

use crate::page_cache::{PAGE, cached_for_an_hour, page_at_zero, require_leases};

fn direct_io() -> MountOptions {
    MountOptions {
        direct_io: true,
        ..cached_for_an_hour()
    }
}

#[test]
fn every_read_is_sent_to_the_server_while_the_attributes_are_cached() {
    support::preflight();
    let fixture = Fixture::start("direct-io-reads");
    fs::write(fixture.host("tree/read.bin"), vec![b'a'; PAGE]).expect("the host file is created");
    require_leases(&fixture);

    let relay = Relay::start(fixture.server.data_unix());
    let guest = fixture.mount_with("direct-io", &relay.url("plain", "/tree"), &direct_io());
    let path = guest.path("read.bin");
    let held = File::open(&path).expect("readable");

    let attributes = || relay.carried(Opcode::Getattr) + relay.carried(Opcode::Lookup);
    let size = u64::try_from(PAGE).expect("a page fits a size");
    let before = attributes();
    for _ in 0..3 {
        assert_eq!(fs::metadata(&path).expect("stat").len(), size);
    }
    assert_eq!(attributes(), before, "the attributes came from the cache");

    let lookups = relay.carried(Opcode::Lookup);
    for _ in 0..3 {
        for file in [&held, &File::open(&path).expect("readable")] {
            let before = relay.carried(Opcode::Read);
            assert_eq!(page_at_zero(file), vec![b'a'; PAGE]);
            assert!(
                relay.carried(Opcode::Read) > before,
                "the read was sent to the server"
            );
        }
    }
    assert_eq!(
        relay.carried(Opcode::Lookup),
        lookups,
        "the opens found the name in the cache"
    );
}

#[test]
fn a_shared_mapping_fails_with_enodev() {
    support::preflight();
    let fixture = Fixture::start("direct-io-mappings");
    require_leases(&fixture);
    let guest = fixture.mount_with(
        "direct-io",
        &fixture.unix_url("plain", "/tree"),
        &direct_io(),
    );

    let mapped = guest.path("mapped.bin");
    fs::write(&mapped, vec![b'.'; PAGE]).expect("the file is created through the mount");
    let refused = SharedMapping::open(&mapped, PAGE).expect_err("a shared mapping fails");
    assert_eq!(refused.raw_os_error(), Some(Errno::NODEV.raw_os_error()));
}
