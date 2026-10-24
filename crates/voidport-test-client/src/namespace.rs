use std::collections::HashSet;
use std::fs;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

use procfs::process::{MountInfo, Process};
use rustix::fs::Dev;
use rustix::io::retry_on_intr;
use rustix::process::{Pid, Signal, WaitId, WaitIdOptions, kill_process, waitid};
use rustix::thread::CapabilitySet;
use voidport_spawn::{Program, Stream};

use crate::{KilledOnDrop, is_in_temp_dir};

const STOP_BEFORE_PROGRAM: &str = r#"kill -STOP "$$"; exec "$@""#;

/// The copy has a mount of every filesystem mounted at that moment, and the
/// kernel does not end a FUSE connection while any mount of it exists, so the
/// mounts of other tests are detached in the copy before `program` starts.
/// The mounts below `kept` are not detached.
pub fn spawn_in_copy(mut program: Program<'_>, kept: &[&Path]) -> KilledOnDrop {
    let copy = KilledOnDrop(
        program
            .run_through(
                "unshare",
                [
                    "--mount",
                    "--propagation",
                    "private",
                    "sh",
                    "-c",
                    STOP_BEFORE_PROGRAM,
                    "sh",
                ],
            )
            .spawn()
            .expect("unshare runs"),
    );
    let pid = Pid::from_child(&copy.0);
    let options = WaitIdOptions::STOPPED | WaitIdOptions::EXITED | WaitIdOptions::NOWAIT;
    let status = retry_on_intr(|| waitid(WaitId::Pid(pid), options))
        .expect("the copy can be waited for")
        .expect("a wait without NOHANG returns a status");
    assert!(
        status.stopped(),
        "unshare did not copy the mount namespace, and ended with {status:?}"
    );
    detach_other_tests(pid, kept);
    kill_process(pid, Signal::CONT).expect("the copy continues");
    copy
}

fn detach_other_tests(copy: Pid, kept: &[&Path]) {
    let table = mounts_of(copy);
    let detached = mounts_of_other_tests(&table, kept);
    if detached.is_empty() {
        return;
    }
    // Without `--no-canonicalize`, `umount` looks the mountpoint up, which
    // waits on a FUSE server that does not answer. `umount` fails on a mount
    // removed from the copy by the kernel meanwhile, because another test
    // removed its mountpoint, so only the mounts left afterwards count.
    let unmounted = Program::new("nsenter")
        .arg(format!("--target={copy}"))
        .args(["--mount", "umount", "--lazy", "--no-canonicalize", "--"])
        .args(detached.iter().map(|mounted| &mounted.mount_point))
        .output()
        .expect("nsenter runs");
    let remaining: HashSet<i32> = mounts_of(copy)
        .iter()
        .map(|mounted| mounted.mnt_id)
        .collect();
    let left: Vec<&Path> = detached
        .iter()
        .filter(|mounted| remaining.contains(&mounted.mnt_id))
        .map(|mounted| mounted.mount_point.as_path())
        .collect();
    assert!(
        left.is_empty(),
        "umount left {left:?} in the copy ({}): {}",
        unmounted.status,
        String::from_utf8_lossy(&unmounted.stderr)
    );
}

fn mounts_of(process: Pid) -> Vec<MountInfo> {
    Process::new(process.as_raw_nonzero().get())
        .and_then(|process| process.mountinfo())
        .expect("the mounts of the copy are readable")
        .0
}

#[derive(PartialEq, Eq, Hash)]
struct Filesystem<'table> {
    device: Dev,
    root: &'table str,
}

impl<'table> Filesystem<'table> {
    fn of(mounted: &'table MountInfo) -> Self {
        Self {
            device: device(mounted),
            root: &mounted.root,
        }
    }
}

fn device(mounted: &MountInfo) -> Dev {
    let (major, minor) = mounted
        .majmin
        .split_once(':')
        .and_then(|(major, minor)| Some((major.parse().ok()?, minor.parse().ok()?)))
        .unwrap_or_else(|| panic!("the device {} is not major:minor", mounted.majmin));
    rustix::fs::makedev(major, minor)
}

/// A filesystem mounted in the directory of a test also appears wherever a
/// peer of the mount containing that directory is, such as at the source of
/// `/tmp` where `/tmp` is a bind mount with shared propagation. That mount has
/// the device and the root of the one in the directory of the test.
fn mounts_of_other_tests<'table>(
    table: &'table [MountInfo],
    kept: &[&Path],
) -> Vec<&'table MountInfo> {
    let of_other_tests: HashSet<Filesystem<'_>> = table
        .iter()
        .filter(|mounted| {
            is_in_temp_dir(&mounted.mount_point)
                && !kept
                    .iter()
                    .any(|directory| mounted.mount_point.starts_with(directory))
        })
        .map(Filesystem::of)
        .collect();
    table
        .iter()
        .filter(|mounted| of_other_tests.contains(&Filesystem::of(mounted)))
        .collect()
}

/// An unmount in the test process does not affect the copy, so the copy still
/// has every filesystem mounted below `kept` until it ends.
#[derive(Debug)]
pub struct NamespaceCopy {
    child: KilledOnDrop,
}

impl NamespaceCopy {
    #[must_use]
    pub fn start(kept: &[&Path]) -> Self {
        let capabilities =
            rustix::thread::capabilities(None).expect("the capabilities of the test are readable");
        assert!(
            capabilities.effective.contains(CapabilitySet::SYS_ADMIN),
            "copying the mount namespace with `unshare --mount` needs CAP_SYS_ADMIN"
        );
        let mut cat = Program::new("cat");
        cat.stdin(Stream::Piped)
            .stdout(Stream::Null)
            .stderr(Stream::Inherit);
        Self {
            child: spawn_in_copy(cat, kept),
        }
    }

    #[must_use]
    pub fn has_mount_of(&self, mountpoint: &Path) -> bool {
        let mounted = fs::metadata(mountpoint).expect("the mount serves").dev();
        mounts_of(Pid::from_child(&self.child.0))
            .iter()
            .any(|copied| device(copied) == mounted)
    }

    pub fn exists(&mut self) -> bool {
        self.child
            .0
            .try_wait()
            .expect("the copy can be asked")
            .is_none()
    }

    pub fn release(mut self) {
        drop(self.child.0.stdin.take());
        let _ = self.child.0.wait();
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::TempDir;

    fn mounted(id: i32, device: &str, root: &Path, target: &Path) -> MountInfo {
        let line = format!(
            "{id} 1 {device} {} {} rw shared:1 - fuse.voidport voidport rw",
            root.display(),
            target.display()
        );
        MountInfo::from_line(&line).expect("a line of a mount table")
    }

    #[test]
    fn the_mounts_of_other_tests_and_their_peers_are_detached() {
        let kept = TempDir::unique_path("kept");
        let other = TempDir::unique_path("other");
        let scratch = kept.parent().expect("the scratch root");
        let backing = Path::new("/srv/backing");
        let peer_of = |path: &Path| backing.join(path.strip_prefix("/").expect("an absolute path"));
        let root = Path::new("/");
        let table = [
            mounted(1, "0:30", root, root),
            mounted(2, "254:16", root, backing),
            mounted(3, "254:16", scratch, scratch),
            mounted(4, "0:60", root, &kept.join("mnt")),
            mounted(5, "0:61", root, &other.join("mnt")),
            mounted(6, "0:62", root, &other.join("mnt/tree")),
            mounted(7, "0:61", root, &peer_of(&other.join("mnt"))),
            mounted(8, "0:62", root, &peer_of(&other.join("mnt/tree"))),
            mounted(9, "0:63", root, &scratch.join("unrelated/mnt")),
            mounted(10, "0:64", root, &other),
            mounted(11, "0:60", root, &peer_of(&kept.join("mnt"))),
        ];
        let detached: Vec<PathBuf> = mounts_of_other_tests(&table, &[&kept])
            .into_iter()
            .map(|mounted| mounted.mount_point.clone())
            .collect();
        assert_eq!(
            detached,
            [
                other.join("mnt"),
                other.join("mnt/tree"),
                peer_of(&other.join("mnt")),
                peer_of(&other.join("mnt/tree")),
                other,
            ]
        );
    }
}
