use std::path::Path;

use rustix::io::Errno;
use voidport_fuse::AutoUnmountCopy;

use super::GuardianError;

/// A mountpoint whose connection has not ended is left alone, because a later
/// mount there is not the mount of the client that died. A failing helper counts
/// as success where the mountpoint no longer has an ended connection, since
/// another process unmounted it.
pub(super) fn release(auto_unmount: &AutoUnmountCopy) -> Result<(), GuardianError> {
    let mountpoint = &auto_unmount.mountpoint;
    if !disconnected(mountpoint) {
        return Ok(());
    }
    match auto_unmount.helper.unmount(mountpoint) {
        Err(error) if disconnected(mountpoint) => Err(GuardianError::Release(error)),
        Ok(()) | Err(_) => Ok(()),
    }
}

/// A `statfs` on the mount fails with `ENOTCONN` once its connection has ended
/// (`fuse_statfs` in `fs/fuse/inode.c`). The exit of a client that died can close
/// its descriptor of the connection after the guardian closed its own, and a
/// request sent before that fails with `ECONNABORTED` once the connection ends,
/// so it is sent again.
fn disconnected(mountpoint: &Path) -> bool {
    loop {
        match rustix::fs::statfs(mountpoint) {
            Err(Errno::NOTCONN) => return true,
            Err(Errno::CONNABORTED | Errno::INTR) => {}
            Ok(_) | Err(_) => return false,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use voidport_fuse::Fusermount;

    use super::*;

    #[test]
    fn a_mountpoint_without_an_ended_connection_is_left_alone() {
        let (socket, _) = std::os::unix::net::UnixStream::pair().expect("a socket pair");
        let auto_unmount = AutoUnmountCopy {
            socket: socket.into(),
            mountpoint: PathBuf::from("/"),
            helper: Fusermount::new("/nonexistent/fusermount3"),
        };
        assert!(release(&auto_unmount).is_ok());
    }
}
