use std::io::{Read as _, Write as _};
use std::path::Path;
use std::{io, thread};

/// A machine where this path exists reports vsock support.
pub const LOOPBACK_MODULE: &str = "/sys/module/vsock_loopback";

#[must_use]
pub fn claims_support() -> bool {
    Path::new(LOOPBACK_MODULE).exists()
}

pub fn probe() -> io::Result<()> {
    // The kernel picks the port as part of the bind, so no other process can take it first.
    let listener =
        vsock::VsockListener::bind_with_cid_port(vsock::VMADDR_CID_ANY, libc::VMADDR_PORT_ANY)?;
    let port = listener.local_addr()?.port();
    let echoing = thread::spawn(move || -> io::Result<()> {
        let (mut accepted, _) = listener.accept()?;
        let mut received = [0u8; 4];
        accepted.read_exact(&mut received)?;
        accepted.write_all(&received)
    });

    let mut client = vsock::VsockStream::connect_with_cid_port(vsock::VMADDR_CID_LOCAL, port)?;
    client.write_all(b"ping")?;
    let mut echoed = [0u8; 4];
    client.read_exact(&mut echoed)?;
    echoing
        .join()
        .map_err(|_| io::Error::other("the echo thread panicked"))??;
    if echoed == *b"ping" {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "the loopback echoed {echoed:?}, not the bytes sent"
        )))
    }
}

/// On a machine that reports vsock support, a failing probe panics. `false` is
/// returned only where the kernel has no loopback transport.
#[must_use]
pub fn preflight() -> bool {
    decide(claims_support(), probe())
}

/// Separate from `preflight`, so a test can check the results on a machine that
/// reports support.
fn decide(claims: bool, probe: io::Result<()>) -> bool {
    match probe {
        Ok(()) => true,
        Err(error) => {
            assert!(
                !claims,
                "this machine claims vsock support ({LOOPBACK_MODULE} exists) but the \
                 loopback probe failed: {error}. On a machine that claims support this is \
                 a failure, never a skip."
            );
            eprintln!("skipping: vsock loopback is unusable ({error})");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_working_probe_runs_the_suite() {
        assert!(decide(true, Ok(())));
        assert!(decide(false, Ok(())));
    }

    #[test]
    fn a_machine_without_the_module_skips() {
        assert!(!decide(false, Err(io::Error::other("no transport"))));
    }

    #[test]
    #[should_panic(expected = "claims vsock support")]
    fn a_machine_that_claims_support_cannot_skip() {
        decide(true, Err(io::Error::other("no transport")));
    }
}
