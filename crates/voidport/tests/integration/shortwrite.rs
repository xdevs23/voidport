use voidport_test_client as support;

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use support::{Fixture, preflight};
use voidport::mount::MountOptions;
use voidport_spawn::{Program, Stream};

const WRITE_BYTES: usize = 1024 * 1024;

const WRITE_BLOCK: usize = 128 * 1024;

const NEVER: Duration = Duration::from_secs(3600);

/// Bytes that differ by position and are never zero, so a range the server
/// never took reads as zeros.
fn payload(len: usize) -> Vec<u8> {
    (0..len).map(|at| ((at % 251) + 1) as u8).collect()
}

fn options() -> MountOptions {
    MountOptions {
        attr_timeout: NEVER,
        entry_timeout: NEVER,
        ..MountOptions::default()
    }
}

/// The image lives in a temporary directory outside the one of the fixture, so
/// removing the fixture directory never recurses into a mounted filesystem.
pub struct HostFilesystem {
    /// Removed after the unmount. `None` after a failed unmount, where removing
    /// it would recurse into a filesystem that is still mounted; the directory
    /// is leaked instead.
    directory: Option<support::TempDir>,
    mountpoint: PathBuf,
}

impl HostFilesystem {
    /// Returns `None` where nothing can be loop-mounted. Missing tools fail
    /// instead, so a filesystem is never reported as checked when it was not.
    pub fn create(kind: &str, mib: u64) -> Option<Self> {
        if !rustix::process::geteuid().is_root() {
            eprintln!(
                "skipping {kind}: not root, so nothing can be loop-mounted; what one host \
                 write does on {kind} was not checked"
            );
            return None;
        }
        if let Err(error) = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/loop-control")
        {
            eprintln!(
                "skipping {kind}: /dev/loop-control is unusable ({error}); what one host \
                 write does on {kind} was not checked"
            );
            return None;
        }
        let directory = support::TempDir::new(&format!("short-write-{kind}"));
        let image = directory.join("image.bin");
        let file = fs::File::create(&image).expect("the image is creatable");
        file.set_len(mib * 1024 * 1024)
            .expect("the image is sizable");
        drop(file);
        match kind {
            "btrfs" => run(
                "mkfs.btrfs",
                &["-f", "--nodiscard", &image.display().to_string()],
            ),
            _ => run("mkfs.ext4", &["-q", "-F", &image.display().to_string()]),
        }
        let mountpoint = directory.directory("mnt");
        run(
            "mount",
            &[
                "-o",
                "loop",
                &image.display().to_string(),
                &mountpoint.display().to_string(),
            ],
        );
        Some(Self {
            directory: Some(directory),
            mountpoint,
        })
    }

    pub fn root(&self) -> &Path {
        &self.mountpoint
    }
}

impl Drop for HostFilesystem {
    /// A leaked mount outlives the test process and blocks removal of the loop
    /// device and the scratch directory, so this waits out a mountpoint that
    /// is still settling and is loud if it never settles.
    fn drop(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let status = Program::new("umount")
                .arg(&self.mountpoint)
                .stderr(Stream::Inherit)
                .status();
            match status {
                Ok(status) if status.success() => return,
                other if Instant::now() >= deadline => {
                    eprintln!(
                        "{} is still mounted: {other:?}; its directory is \
                         leaked so that no removal recurses into a mounted filesystem",
                        self.mountpoint.display()
                    );
                    if let Some(directory) = self.directory.take() {
                        std::mem::forget(directory);
                    }
                    return;
                }
                _ => std::thread::sleep(Duration::from_millis(50)),
            }
        }
    }
}

fn run(program: &str, arguments: &[&str]) {
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
}

fn probe_one_pwrite(root: &Path, len: usize) -> usize {
    let path = root.join("pwrite-probe.bin");
    let file = fs::File::create(&path).expect("the probe file is creatable");
    let written = rustix::io::pwrite(&file, &payload(len), 0).expect("the probe write succeeds");
    drop(file);
    fs::remove_file(&path).expect("the probe file is removed");
    written
}

fn short_answers_arm(kind: &str, mib: u64) {
    preflight();
    // Declared before the fixture, so the server that grafts it is gone before
    // the filesystem is unmounted.
    let Some(image) = HostFilesystem::create(kind, mib) else {
        return;
    };
    let probed = probe_one_pwrite(image.root(), WRITE_BLOCK);
    println!("short-write: one {WRITE_BLOCK}-byte pwrite on {kind} wrote {probed} bytes");

    let fixture = Fixture::start_over(&format!("short-write-{kind}"), "", Some(image.root()));
    let guest = fixture.mount_with(kind, &fixture.tcp_url("image", "/fs"), &options());

    let expected = payload(WRITE_BYTES);
    let mut file = fs::File::create(guest.path("written.bin")).expect("the file is created");
    for block in expected.chunks(WRITE_BLOCK) {
        file.write_all(block).expect("the write succeeds");
    }
    drop(file);

    assert_eq!(
        fs::read(image.root().join("written.bin")).expect("the host file reads"),
        expected,
        "{kind}: the write did not place every byte (one {WRITE_BLOCK}-byte pwrite \
         took {probed} here)"
    );
}

#[test]
fn a_write_places_every_byte_whatever_one_ext4_pwrite_takes() {
    short_answers_arm("ext4", 64);
}

#[test]
fn a_write_places_every_byte_whatever_one_btrfs_pwrite_takes() {
    short_answers_arm("btrfs", 256);
}
