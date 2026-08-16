//! Vsock scaffolding: the capability rule, and a port nobody is on.
//!
//! **A skip is not a pass, and this machine says which one it is.** The design
//! rules the suites' one allowance: a machine whose kernel has the loopback
//! transport module *claims* vsock support, and on such a machine anything that
//! fails is a failure — never a skip. Only a machine with no such module may
//! skip, and it must say so out loud. That is why the probe below is a real
//! bind, dial and echo, not a check for the module: the module's
//! presence decides what a probe failure *means*, and the probe decides whether
//! the transport works.
//!
//! It lives in the library beside the rest of the shared scaffolding because
//! three suites need it — the server's own tests, the client's end-to-end
//! suite, and the vsock suite itself — and an integration test's `support`
//! module cannot be imported by another crate.

use std::io::{Read as _, Write as _};
use std::path::Path;
use std::sync::atomic::{AtomicU32, Ordering};
use std::{io, thread};

/// Where the kernel records the loopback vsock transport.
///
/// Its presence is the whole of "this machine claims vsock support": the module
/// is what gives the machine a local cid to talk to itself on.
pub const LOOPBACK_MODULE: &str = "/sys/module/vsock_loopback";

/// The first port [`free_port`] considers.
///
/// Above every port a test fixture would write by hand, and inside the
/// 1..=65535 range a mount URL can name.
const FIRST_PORT: u32 = 20_000;

/// The last port [`free_port`] considers: the largest a mount URL can carry.
const LAST_PORT: u32 = u16::MAX as u32;

/// Whether this machine claims vsock support.
#[must_use]
pub fn claims_support() -> bool {
    Path::new(LOOPBACK_MODULE).exists()
}

/// Whether vsock loopback actually works here: bind, dial, echo, in that order.
///
/// # Errors
///
/// Returns the first syscall failure. On a machine that claims support, this
/// error is a test failure, not a reason to skip — see [`preflight`].
pub fn probe() -> io::Result<()> {
    let listener = bind_free_port()?;
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

/// Whether a vsock suite may run here — and, where it may not, why.
///
/// The FUSE preflight's shape, with one required difference: a machine that claims
/// support has no way to skip. `false` is returned only where the kernel has no
/// loopback transport at all, and it is printed loudly, because a suite that
/// says nothing and passes is the failure mode this rule exists to prevent.
///
/// # Panics
///
/// If the machine claims support ([`LOOPBACK_MODULE`] exists) and the probe
/// nevertheless fails.
#[must_use]
pub fn preflight() -> bool {
    decide(claims_support(), probe())
}

/// The rule itself, with the machine's two answers as arguments.
///
/// Separated from [`preflight`] because a rule about when a suite may skip is
/// exactly the kind of thing that must be *proven*, not asserted: this
/// function has its own tests below, which a machine that claims support cannot
/// otherwise reach.
///
/// # Panics
///
/// If `claims` and the probe failed.
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

/// How many times [`bind_free_port`] re-picks a port before giving up.
///
/// [`free_port`] binds a candidate and lets go, so between its answer and the
/// caller's own bind there is a window another suite can take the port in. That
/// window is what made the probe report `EADDRINUSE` under concurrent suites —
/// and on a machine that claims support, a probe failure is a test failure, so
/// the flake was a red run, not a retry. Losing the race twice running
/// is already vanishingly unlikely; four attempts is the belt to that braces.
const BIND_ATTEMPTS: usize = 4;

/// Binds a port nothing is on, re-picking where another process took it first.
///
/// # Errors
///
/// Returns the last bind failure. Anything that is not "already in use" is
/// returned at once: a kernel with no vsock transport must not be retried into
/// a timeout.
fn bind_free_port() -> io::Result<vsock::VsockListener> {
    let mut last = None;
    for _ in 0..BIND_ATTEMPTS {
        let port = free_port()?;
        match vsock::VsockListener::bind_with_cid_port(vsock::VMADDR_CID_ANY, port) {
            Ok(listener) => return Ok(listener),
            Err(error) if error.kind() == io::ErrorKind::AddrInUse => last = Some(error),
            Err(error) => return Err(error),
        }
    }
    Err(last.unwrap_or_else(|| io::Error::other("no vsock port could be bound")))
}

/// A vsock port nothing is listening on, inside the range a mount URL can name.
///
/// Found by binding it and letting go, which is the same small race every
/// ephemeral-port fixture in this workspace runs: the caller binds it again
/// immediately. The search starts at a different place per process and per
/// call, so concurrent suites do not walk the same candidates in the same
/// order.
///
/// # Errors
///
/// Returns the bind failure. A port already served is skipped over; anything
/// else — a kernel with no vsock transport says `EAFNOSUPPORT` on the first
/// candidate — is returned at once instead of repeated tens of thousands of
/// times.
pub fn free_port() -> io::Result<u32> {
    /// How far the search has already been advanced within this process.
    static ADVANCED: AtomicU32 = AtomicU32::new(0);

    let span = LAST_PORT - FIRST_PORT + 1;
    let start = (std::process::id().wrapping_add(ADVANCED.fetch_add(1, Ordering::Relaxed))) % span;
    for offset in 0..span {
        let port = FIRST_PORT + (start + offset) % span;
        match vsock::VsockListener::bind_with_cid_port(vsock::VMADDR_CID_ANY, port) {
            Ok(listener) => {
                drop(listener);
                return Ok(port);
            }
            Err(error) if error.kind() == io::ErrorKind::AddrInUse => continue,
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::other(format!(
        "every vsock port in {FIRST_PORT}..={LAST_PORT} is in use"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A working transport runs the suite, whatever the machine claims.
    #[test]
    fn a_working_probe_runs_the_suite() {
        assert!(decide(true, Ok(())));
        assert!(decide(false, Ok(())));
    }

    /// A machine that claims nothing may skip, loudly.
    #[test]
    fn a_machine_without_the_module_skips() {
        assert!(!decide(false, Err(io::Error::other("no transport"))));
    }

    /// A machine that claims support may not: a probe that fails there is a
    /// failure, which is the whole of the rule.
    #[test]
    #[should_panic(expected = "claims vsock support")]
    fn a_machine_that_claims_support_cannot_skip() {
        decide(true, Err(io::Error::other("no transport")));
    }
}
