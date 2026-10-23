//! An eventfd adds every native-endian 64-bit number written to it to its
//! count, and a read returns the count and resets it to zero.

use std::io;
use std::os::fd::AsFd;

use rustix::fs::{OFlags, fcntl_getfl, fcntl_setfl};

/// # Errors
///
/// The errno of the host when the flags cannot be read or set.
pub fn read_without_blocking(eventfd: impl AsFd) -> io::Result<()> {
    let flags = fcntl_getfl(&eventfd)?;
    fcntl_setfl(&eventfd, flags | OFlags::NONBLOCK)?;
    Ok(())
}

/// # Errors
///
/// The errno of the host when the write fails.
pub fn signal(eventfd: impl AsFd) -> io::Result<()> {
    rustix::io::write(eventfd, &1u64.to_ne_bytes())?;
    Ok(())
}

/// # Errors
///
/// The errno of the host, `EAGAIN` included when the count is zero and the
/// eventfd reads without blocking.
pub fn read(eventfd: impl AsFd) -> io::Result<u64> {
    let mut count = [0u8; 8];
    rustix::io::read(eventfd, &mut count)?;
    Ok(u64::from_ne_bytes(count))
}

/// The eventfd must read without blocking (see [`read_without_blocking`]), or a
/// drain of a zero count blocks. It succeeds whether or not anything signalled
/// it.
///
/// # Errors
///
/// The errno of the host for a read that fails for another reason than a
/// count of zero.
pub fn drain(eventfd: impl AsFd) -> io::Result<()> {
    match read(eventfd) {
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use rustix::event::{EventfdFlags, eventfd};

    use super::*;

    #[test]
    fn the_signals_add_up_until_a_read_resets_them() {
        let eventfd = eventfd(0, EventfdFlags::CLOEXEC).expect("an eventfd");
        read_without_blocking(&eventfd).expect("it reads without blocking");
        drain(&eventfd).expect("nothing signalled it");
        signal(&eventfd).expect("signalled");
        signal(&eventfd).expect("signalled");
        assert_eq!(read(&eventfd).expect("a count"), 2);
        assert_eq!(
            read(&eventfd).map_err(|error| error.kind()),
            Err(io::ErrorKind::WouldBlock)
        );
        signal(&eventfd).expect("signalled");
        drain(&eventfd).expect("drained");
        drain(&eventfd).expect("nothing left");
    }
}
