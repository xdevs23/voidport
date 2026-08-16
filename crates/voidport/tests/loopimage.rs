//! A real filesystem, in a file, on a voidport mount.
//!
//! Everything else in the suite exercises the mount with file operations. This
//! one hands the mount to the kernel itself: a disk image is created through
//! voidport, a loop device is pointed at it, `mkfs.btrfs` formats it, the guest
//! kernel mounts *that* and does ordinary filesystem work inside it, and then
//! `btrfs check` audits the result against the bytes that reached the host.
//!
//! It is the most unforgiving read/write test available, because a block layer
//! makes no allowances: every write is at an exact offset with an exact length,
//! the reads that follow must return precisely those bytes, and a filesystem
//! that is one byte wrong anywhere fails its own consistency check. The audit
//! is run on the **host** copy of the image, so what is checked is what voidport
//! stored — not what the guest's cache remembers.
//!
//! Single client, by intent: two clients through one block device would be two
//! kernels owning one filesystem's metadata, which is not a thing any
//! filesystem allows and not a property voidport could give them.

mod support;

use std::fs;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use support::Fixture;

/// How big the image is.
///
/// Above btrfs's own minimum with room for its metadata, and small enough that
/// formatting and checking it is a second of work.
const IMAGE_BYTES: u64 = 256 * 1024 * 1024;

/// How many files are written inside the mounted image.
const FILES: usize = 48;

/// How big each of them is.
const FILE_BYTES: usize = 64 * 1024;

/// Whether the kernel offers loop devices at all.
///
/// The one preflight this test is allowed: without `/dev/loop-control` there is
/// no way to put a block device in front of a file, and nothing here can run.
/// Missing *tools* are not skipped — the development shell provides them, and a
/// silent pass would be a lie.
fn loop_devices_available() -> bool {
    match fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/loop-control")
    {
        Ok(_) => true,
        Err(error) => {
            eprintln!("skipping: /dev/loop-control is unusable ({error})");
            false
        }
    }
}

/// Runs a command and requires it to succeed.
fn run(program: &str, arguments: &[&str]) -> String {
    let output = Command::new(program)
        .args(arguments)
        .output()
        .unwrap_or_else(|error| {
            panic!(
                "{program} could not be run ({error}); the development shell \
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

/// A loop device bound to a file, detached however the test ends.
struct Loopback {
    device: String,
}

impl Loopback {
    /// Binds the next free loop device to `image`.
    fn attach(image: &Path) -> Self {
        let device = run(
            "losetup",
            &["--find", "--show", &image.display().to_string()],
        );
        Self {
            device: device.trim().to_owned(),
        }
    }

    /// The device node.
    fn device(&self) -> &str {
        &self.device
    }
}

impl Drop for Loopback {
    /// A leaked loop device outlives the test process and keeps the image file
    /// — and the mount under it — pinned, so this is as loud as it can be when
    /// it fails.
    fn drop(&mut self) {
        let detached = Command::new("losetup").args(["-d", &self.device]).status();
        match detached {
            Ok(status) if status.success() => {}
            other => eprintln!("!!! {} is still attached: {other:?}", self.device),
        }
    }
}

/// A mounted filesystem, unmounted however the test ends.
struct MountedImage {
    at: PathBuf,
    mounted: bool,
}

impl MountedImage {
    /// Mounts a formatted device.
    fn mount(device: &str, at: &Path) -> Self {
        run("mount", &["-t", "btrfs", device, &at.display().to_string()]);
        Self {
            at: at.to_owned(),
            mounted: true,
        }
    }

    /// A path inside the mounted image.
    fn path(&self, name: &str) -> PathBuf {
        self.at.join(name)
    }

    /// Unmounts, reporting the kernel's answer.
    fn unmount(&mut self) -> std::io::Result<()> {
        let status = Command::new("umount").arg(&self.at).status()?;
        if !status.success() {
            return Err(std::io::Error::other(format!("umount said {status}")));
        }
        self.mounted = false;
        Ok(())
    }
}

impl Drop for MountedImage {
    fn drop(&mut self) {
        // The test unmounts explicitly in the ordinary path; this is the panic
        // path, where leaving a btrfs mounted on a loop device on a FUSE mount
        // would wedge every teardown behind it.
        if self.mounted
            && let Err(error) = self.unmount()
        {
            eprintln!("!!! {} is still mounted: {error}", self.at.display());
        }
    }
}

/// The contents of the file at one index inside the image.
fn payload(index: usize) -> Vec<u8> {
    let seed = (index as u8).wrapping_mul(31).wrapping_add(7);
    (0..FILE_BYTES)
        .map(|offset| seed.wrapping_add((offset % 251) as u8))
        .collect()
}

/// A whole filesystem lives in a file on the mount, and the host holds it.
///
/// The sequence is the point, and every step is a real one: format, mount,
/// write, read back, unmount, detach, audit. `btrfs check` at the end reads the
/// host's copy of the image directly — if a single write had landed at the
/// wrong offset, been truncated, or been served back from a stale cache, the
/// filesystem inside would not survive its own check.
#[test]
fn a_btrfs_image_on_the_mount_formats_mounts_and_checks_clean() {
    if !support::preflight() || !loop_devices_available() {
        return;
    }
    let fixture = Fixture::start("loop-image");
    // Declared first, so it is dropped *last*: the loop device and the
    // filesystem on it must be gone before the mount holding the image can be
    // unmounted.
    let guest = fixture.mount("image", "plain", "/tree");
    let image = guest.path("disk.img");

    // The image is created through the mount, and sized through it: a
    // `set_len` is a `setattr` the server applies to the host file.
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
    // backing file, which voidport does not implement — and an image that is
    // never discarded is exactly as valid.
    run(
        "mkfs.btrfs",
        &["-f", "--nodiscard", "-L", "voidport", loopback.device()],
    );

    let inside = support::TempDir::new("image-mnt");
    let mut mounted = MountedImage::mount(loopback.device(), inside.path());

    // Ordinary filesystem work inside the image: files, a subdirectory, and a
    // read-back of everything before anything is unmounted.
    fs::create_dir(mounted.path("nested")).expect("the image is writable");
    for index in 0..FILES {
        let name = format!("nested/file-{index:03}");
        fs::write(mounted.path(&name), payload(index)).expect("the image is writable");
    }
    for index in 0..FILES {
        let name = format!("nested/file-{index:03}");
        assert_eq!(
            fs::read(mounted.path(&name)).expect("the image is readable"),
            payload(index),
            "{name} read back differently inside the image"
        );
    }

    mounted.unmount().expect("the image unmounts");
    drop(mounted);
    drop(loopback);

    // What the guest wrote is what the host has, byte for byte — compared in
    // chunks, not by reading a quarter-gigabyte twice into memory.
    assert_identical(&image, &fixture.host("tree/disk.img"));

    // And the host's copy is a filesystem that passes its own audit —
    // structure and data checksums both. This is the whole claim: not "the
    // writes were accepted" but "the writes were stored, exactly, at the
    // offsets and in the order a block device demands".
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

/// Fails unless two files hold the same bytes, naming where they first differ.
fn assert_identical(left: &Path, right: &Path) {
    const CHUNK: usize = 1024 * 1024;

    let mut left_file = fs::File::open(left).expect("readable");
    let mut right_file = fs::File::open(right).expect("readable");
    let mut left_buffer = vec![0u8; CHUNK];
    let mut right_buffer = vec![0u8; CHUNK];
    let mut at = 0u64;
    loop {
        let read = read_fully(&mut left_file, &mut left_buffer);
        let mirrored = read_fully(&mut right_file, &mut right_buffer);
        assert_eq!(
            read,
            mirrored,
            "{} and {} are different lengths",
            left.display(),
            right.display()
        );
        if read == 0 {
            return;
        }
        if left_buffer[..read] != right_buffer[..read] {
            let offset = (0..read)
                .find(|index| left_buffer[*index] != right_buffer[*index])
                .expect("the slices differ somewhere");
            panic!(
                "{} and {} differ at byte {}",
                left.display(),
                right.display(),
                at + offset as u64
            );
        }
        at += read as u64;
    }
}

/// Fills a buffer, stopping only at end of file.
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
