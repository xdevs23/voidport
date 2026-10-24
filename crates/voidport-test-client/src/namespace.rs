use std::ffi::OsStr;
use std::io::{BufRead as _, BufReader};
use std::process::Child;

use rustix::thread::CapabilitySet;
use voidport_spawn::{Program, Stream};

/// The arguments added to the returned program go to `program`.
#[must_use]
pub fn in_copy<'fd>(program: impl AsRef<OsStr>) -> Program<'fd> {
    let mut unshare = Program::new("unshare");
    unshare
        .args(["--mount", "--propagation", "private"])
        .arg(program);
    unshare
}

/// A copy with private propagation has a mount of every filesystem mounted at
/// that moment, and the kernel does not release a filesystem, a FUSE connection
/// included, while any mount of it exists. An unmount in the test process does not
/// affect the copy.
#[derive(Debug)]
pub struct NamespaceCopy {
    child: Child,
}

impl NamespaceCopy {
    #[must_use]
    pub fn start() -> Self {
        let capabilities =
            rustix::thread::capabilities(None).expect("the capabilities of the test are readable");
        assert!(
            capabilities.effective.contains(CapabilitySet::SYS_ADMIN),
            "copying the mount namespace with `unshare --mount` needs CAP_SYS_ADMIN"
        );
        let mut copy = Self {
            child: in_copy("sh")
                .args(["-c", "echo copied; exec cat"])
                .stdin(Stream::Piped)
                .stdout(Stream::Piped)
                .stderr(Stream::Inherit)
                .spawn()
                .expect("unshare runs"),
        };
        let mut copied = String::new();
        BufReader::new(copy.child.stdout.take().expect("a piped stdout"))
            .read_line(&mut copied)
            .expect("the copy reports");
        assert_eq!(
            copied.trim(),
            "copied",
            "unshare did not copy the namespace"
        );
        copy
    }

    pub fn exists(&mut self) -> bool {
        self.child
            .try_wait()
            .expect("the copy can be asked")
            .is_none()
    }

    pub fn release(mut self) {
        drop(self.child.stdin.take());
        self.child.wait().expect("the copy exits");
    }
}

impl Drop for NamespaceCopy {
    fn drop(&mut self) {
        let ended = self.child.kill().and_then(|()| self.child.wait());
        if let Err(error) = ended {
            eprintln!("the namespace copy is not ended: {error}");
        }
    }
}
