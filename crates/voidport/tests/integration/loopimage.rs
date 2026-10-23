//! The filesystem in the image is mounted in a mount namespace of its own, by
//! this test binary run again under `unshare`. A sandboxed build on the same
//! machine runs in a copy of the mount namespace, made when the build starts. A
//! copy made while the image is mounted in the namespace of the test keeps the
//! filesystem alive after the test unmounts it, and the last writes of the
//! filesystem then reach the image later, while the test compares the guest
//! copy with the host copy. The test makes such a copy itself while the image
//! is mounted, and ends it between reading the guest copy and reading the host
//! copy.

use voidport_test_client as support;

use std::fs;
use std::io::{BufRead as _, BufReader, Lines, Read as _};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdout};

use sha2::{Digest as _, Sha256};
use support::Fixture;
use support::namespace::{NamespaceCopy, in_copy};
use voidport_spawn::{Program, Stream};

const IMAGE_BYTES: u64 = 256 * 1024 * 1024;

const FILES: usize = 48;

const FILE_BYTES: usize = 64 * 1024;

const TEST: &str = "loopimage::a_btrfs_image_on_the_mount_formats_mounts_and_checks_clean";

const IMAGE_DEVICE: &str = "VOIDPORT_TEST_IMAGE_DEVICE";

const IMAGE_MOUNTPOINT: &str = "VOIDPORT_TEST_IMAGE_MOUNTPOINT";

const FILLED: &str = "the image is mounted and filled";

fn loop_preflight() {
    if let Err(error) = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/loop-control")
    {
        panic!("/dev/loop-control is unusable, so no loop device can hold the image: {error}");
    }
}

fn run(program: &str, arguments: &[&str]) -> String {
    let output = Program::new(program)
        .args(arguments)
        .output()
        .unwrap_or_else(|error| {
            panic!(
                "{program} could not be run ({error:?}); the development shell \
                 (`./check`, or `nix develop`) provides the tools this test needs"
            )
        });
    assert!(
        output.status.success(),
        "{program} {arguments:?} failed ({}):\n{}{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

struct Loopback {
    device: String,
}

impl Loopback {
    fn attach(image: &Path) -> Self {
        let device = run(
            "losetup",
            &["--find", "--show", &image.display().to_string()],
        );
        Self {
            device: device.trim().to_owned(),
        }
    }

    fn device(&self) -> &str {
        &self.device
    }
}

impl Drop for Loopback {
    /// A leaked loop device outlives the test process and blocks removal of the
    /// image file and the mount under it.
    fn drop(&mut self) {
        let detached = Program::new("losetup")
            .args(["-d", &self.device])
            .stderr(Stream::Inherit)
            .status();
        match detached {
            Ok(status) if status.success() => {}
            other => eprintln!("!!! {} is still attached: {other:?}", self.device),
        }
    }
}

/// Only that namespace has a mount of the filesystem in the image, and it ends
/// with the process, so a filler that fails or is killed leaves no mount of it
/// behind.
struct Filler {
    process: Child,
    output: Lines<BufReader<ChildStdout>>,
}

impl Filler {
    fn start(device: &str, mountpoint: &Path) -> Self {
        let mut process = in_copy(std::env::current_exe().expect("the test binary"))
            .args(["--exact", TEST, "--nocapture"])
            .env(IMAGE_DEVICE, device)
            .env(IMAGE_MOUNTPOINT, mountpoint)
            .stdin(Stream::Piped)
            .stdout(Stream::Piped)
            .stderr(Stream::Inherit)
            .spawn()
            .expect("unshare runs");
        let output = BufReader::new(process.stdout.take().expect("a piped stdout")).lines();
        let mut filler = Self { process, output };
        assert!(
            filler
                .output
                .by_ref()
                .map_while(Result::ok)
                .any(|line| line == FILLED),
            "the filler of the image ended before it filled the image"
        );
        filler
    }

    fn unmount(mut self) {
        drop(self.process.stdin.take());
        // The rest of the output of the filler, read to its end so that the
        // filler never writes into a closed pipe.
        for line in self.output.by_ref().map_while(Result::ok) {
            println!("{line}");
        }
        let status = self.process.wait().expect("the filler is waited for");
        assert!(
            status.success(),
            "the filler of the image failed ({status})"
        );
    }
}

impl Drop for Filler {
    /// A test that fails before [`Self::unmount`] ends the filler, and with
    /// it the only mount of the filesystem in the image.
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}

fn image_to_fill() -> Option<(String, PathBuf)> {
    Some((
        std::env::var(IMAGE_DEVICE).ok()?,
        std::env::var_os(IMAGE_MOUNTPOINT)?.into(),
    ))
}

fn fill(device: &str, mountpoint: &Path) {
    run(
        "mount",
        &["-t", "btrfs", device, &mountpoint.display().to_string()],
    );
    let path = |name: &str| mountpoint.join(name);
    fs::create_dir(path("nested")).expect("the image is writable");
    for index in 0..FILES {
        let name = format!("nested/file-{index:03}");
        fs::write(path(&name), payload(index)).expect("the image is writable");
    }
    for index in 0..FILES {
        let name = format!("nested/file-{index:03}");
        assert_eq!(
            fs::read(path(&name)).expect("the image is readable"),
            payload(index),
            "{name} read back differently inside the image"
        );
    }
    println!("{FILLED}");
    std::io::stdin()
        .read_to_end(&mut Vec::new())
        .expect("the test tells the filler to unmount");
    run("umount", &[&mountpoint.display().to_string()]);
}

fn payload(index: usize) -> Vec<u8> {
    let seed = (index as u8).wrapping_mul(31).wrapping_add(7);
    (0..FILE_BYTES)
        .map(|offset| seed.wrapping_add((offset % 251) as u8))
        .collect()
}

#[test]
fn a_btrfs_image_on_the_mount_formats_mounts_and_checks_clean() {
    if let Some((device, mountpoint)) = image_to_fill() {
        fill(&device, &mountpoint);
        return;
    }
    support::preflight();
    loop_preflight();
    let fixture = Fixture::start("loop-image");
    // Declared first, so it is dropped *last*: the loop device and the
    // filesystem on it must be gone before the mount holding the image can be
    // unmounted.
    let guest = fixture.mount("image", "plain", "/tree");
    let image = guest.path("disk.img");

    let file = fs::File::create(&image).expect("the image is creatable");
    file.set_len(IMAGE_BYTES).expect("the image is sizable");
    drop(file);
    assert_eq!(
        fs::metadata(fixture.host("tree/disk.img"))
            .expect("the host has the image")
            .len(),
        IMAGE_BYTES
    );

    let loopback = Loopback::attach(&image);
    // `--nodiscard`: a discard on the loop device becomes a hole punch on the
    // backing file, which voidport does not implement, and an image that is
    // never discarded is exactly as valid.
    run(
        "mkfs.btrfs",
        &["-f", "--nodiscard", "-L", "voidport", loopback.device()],
    );

    let inside = support::TempDir::new("image-mnt");
    let filler = Filler::start(loopback.device(), inside.path());
    // A copy of the mount namespace of this test, as a sandboxed build makes
    // one, made while the image is mounted in the namespace of the filler.
    let copy = NamespaceCopy::start();
    filler.unmount();
    drop(loopback);

    // Compared by chunk digests. The copy ends between the two readings, so a
    // filesystem kept alive past the unmount would write its last blocks into
    // the image then.
    assert_identical(&image, &fixture.host("tree/disk.img"), || copy.release());

    let report = run(
        "btrfs",
        &[
            "check",
            "--readonly",
            "--check-data-csum",
            &fixture.host("tree/disk.img").display().to_string(),
        ],
    );
    assert!(
        !report.contains("ERROR"),
        "btrfs check reported errors:\n{report}"
    );
}

const CHUNK: usize = 1024 * 1024;

/// The guest copy is read to its end and closed before the host copy is
/// opened. The guest caches a file it wrote under a write lease, and a host
/// reader of the file makes the reads of the guest wait until it closes the
/// file, so a test that kept the host copy open while it read the guest copy
/// would wait for itself.
fn assert_identical(guest: &Path, host: &Path, between: impl FnOnce()) {
    let guest_digests = digests(guest);
    between();
    let host_digests = digests(host);
    assert_eq!(
        guest_digests.len(),
        host_digests.len(),
        "{} and {} are different lengths",
        guest.display(),
        host.display()
    );
    if let Some(chunk) = guest_digests
        .iter()
        .zip(&host_digests)
        .position(|(guest, host)| guest != host)
    {
        panic!(
            "{} and {} differ in the chunk of {CHUNK} bytes at byte {}",
            guest.display(),
            host.display(),
            chunk * CHUNK
        );
    }
}

fn digests(path: &Path) -> Vec<[u8; 32]> {
    let mut file = fs::File::open(path).expect("readable");
    let mut buffer = vec![0u8; CHUNK];
    let mut digests = Vec::new();
    loop {
        let read = read_fully(&mut file, &mut buffer);
        if read == 0 {
            return digests;
        }
        digests.push(Sha256::digest(&buffer[..read]).into());
    }
}

fn read_fully(file: &mut fs::File, buffer: &mut [u8]) -> usize {
    let mut filled = 0;
    while filled < buffer.len() {
        match file.read(&mut buffer[filled..]).expect("readable") {
            0 => break,
            count => filled += count,
        }
    }
    filled
}
