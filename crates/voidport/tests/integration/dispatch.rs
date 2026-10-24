use voidport_test_client as support;

use std::fs;
use std::io::{IsTerminal as _, Read as _};
use std::num::NonZeroUsize;
use std::thread;

use rustix::fs::{Mode, OFlags};
use rustix::io::Errno;
use support::daemon::Ground;
use support::preflight;
use support::relay::{Cut, Latch, Relay};
use voidport::mount::MountOptions;
use voidport_proto::opcode::Opcode;

/// Every connection that a request can use has a read whose reply the relay
/// withholds, and the relay closes every new connection, so the forget of a
/// pruned node waits for a connection until the reads are answered. The pool
/// tries to open a connection for the forget only once the forget has left the
/// kernel, and the mount returns the result of a terminal query on an open file
/// after that, which needs no connection. The pruned node stays in the kernel
/// through a path descriptor until then, since a dentry cache drop by any other
/// process would otherwise send its forget while a connection is still free.
#[test]
fn a_forget_that_waits_for_a_connection_leaves_the_mount_reading_requests() {
    preflight();
    let label = "forget-waits";
    let ground = Ground::start(label);
    let relay = Relay::start(&ground.socket());
    let guest = ground.mount_with_url(
        label,
        &relay.url("work", ""),
        &MountOptions {
            dispatch_threads: NonZeroUsize::MIN,
            ..MountOptions::default()
        },
    );
    let asked = fs::File::open(guest.path("tree/beta")).expect("the file opens");
    let pruned = rustix::fs::open(
        guest.path("tree/alpha"),
        OFlags::PATH | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .expect("the kernel looks the file up");

    relay.refuse_new(true);
    let busy = guest.client().connections().expect("a session").pooled;
    let latch = Latch::default();
    let reads: Vec<_> = (0..busy)
        .map(|index| {
            let name = format!("held-{index}");
            fs::write(ground.tree.join(&name), b"held").expect("a writable tree");
            let mut file =
                fs::File::open(guest.path(&format!("tree/{name}"))).expect("the held file opens");
            let held = relay.arm(Opcode::Read, Cut::HoldReply(latch.clone()));
            let reading = thread::spawn(move || file.read_to_end(&mut Vec::new()));
            held.recv().expect("the reply of the read is withheld");
            reading
        })
        .collect();

    let (forgets, refused) = (relay.carried(Opcode::Forget), relay.refused());
    drop(pruned);
    support::drop_dentry_cache();
    ground.server.until(|| relay.refused() > refused);
    assert!(!asked.is_terminal(), "a shared file is not a terminal");
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(Errno::NOTTY.raw_os_error()),
        "the terminal query returns while the forget waits"
    );
    assert_eq!(
        relay.carried(Opcode::Forget),
        forgets,
        "a forget went out while every connection was busy"
    );

    relay.refuse_new(false);
    latch.release();
    for reading in reads {
        reading
            .join()
            .expect("the reading thread ends")
            .expect("the held read is answered");
    }
    ground
        .server
        .until(|| relay.carried(Opcode::Forget) > forgets);
}
