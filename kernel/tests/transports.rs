// SPDX-License-Identifier: GPL-2.0

use std::ffi::{CString, OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead as _, BufReader, Lines};
use std::os::unix::fs::{FileExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdout, Command, Stdio};

use crate::{host, Mapping};

const NAMESPACE: &std::ffi::CStr = c"share";

/// The copy of `tree/pattern.bin` on the host that the image contains. Each
/// of its lines contains its line number, so bytes read from or written to
/// the wrong place do not compare equal.
const PATTERN: &str = "/fixture-pattern";

const VIEW: &str = "/view";

const FILESYSTEM_DEVICE: &str = "0x001a";

fn in_tree(point: &Path, name: &str) -> PathBuf {
    point.join("tree").join(name)
}

pub struct Mount {
    point: PathBuf,
    options: String,
}

impl Mount {
    pub fn from_args(mut args: impl Iterator<Item = OsString>) -> Self {
        let point = args.next().expect("the mount point").into();
        let options = args
            .next()
            .and_then(|options| options.into_string().ok())
            .expect("the options of the mount, in UTF-8");
        assert!(args.next().is_none(), "more arguments than one mount");
        Self { point, options }
    }

    fn file(&self, name: &str) -> PathBuf {
        in_tree(&self.point, name)
    }

    fn view(&self) -> io::Result<View> {
        View::mount(&self.options)
    }
}

/// The namespace mounted at [`VIEW`], and unmounted when this is dropped. A
/// separate mount has a separate session and nothing cached, so it reads
/// what the server has.
struct View;

impl View {
    fn mount(options: &str) -> io::Result<Self> {
        fs::create_dir_all(VIEW)?;
        let target = CString::new(VIEW)?;
        let options = CString::new(options)?;
        // SAFETY: every argument is a NUL-terminated string that lives
        // across the call.
        let mounted = unsafe {
            libc::mount(
                NAMESPACE.as_ptr(),
                target.as_ptr(),
                c"voidport".as_ptr(),
                0,
                options.as_ptr().cast(),
            )
        };
        if mounted == 0 {
            Ok(Self)
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn file(&self, name: &str) -> PathBuf {
        in_tree(Path::new(VIEW), name)
    }
}

impl Drop for View {
    fn drop(&mut self) {
        let target = CString::new(VIEW).expect("a path without NUL");
        // SAFETY: the target is a NUL-terminated string that lives across the
        // call.
        assert_eq!(unsafe { libc::umount(target.as_ptr()) }, 0);
    }
}

const MONITORING: &str = "UDEV - the event which udev sends out after rule processing";

struct Processed {
    monitor: Child,
    lines: Lines<BufReader<ChildStdout>>,
}

struct Event(Vec<String>);

impl Event {
    fn has(&self, property: &str) -> bool {
        self.0.iter().any(|given| given == property)
    }
}

impl Processed {
    fn open(subsystems: &[&str]) -> io::Result<Self> {
        let mut monitor = Command::new("/bin/udevadm")
            .args(["monitor", "--udev", "--property"])
            .args(
                subsystems
                    .iter()
                    .map(|subsystem| format!("--subsystem-match={subsystem}")),
            )
            .stdout(Stdio::piped())
            .spawn()?;
        let output = monitor.stdout.take().expect("the output of the monitor");
        let mut processed = Self {
            monitor,
            lines: BufReader::new(output).lines(),
        };
        while processed.line()? != MONITORING {}
        Ok(processed)
    }

    fn line(&mut self) -> io::Result<String> {
        self.lines
            .next()
            .unwrap_or_else(|| Err(io::Error::other("the monitor of udev ended")))
    }

    fn next(&mut self) -> io::Result<Event> {
        while self.line()?.is_empty() {}
        let mut properties = Vec::new();
        loop {
            let line = self.line()?;
            if line.is_empty() {
                return Ok(Event(properties));
            }
            properties.push(line);
        }
    }
}

impl Drop for Processed {
    fn drop(&mut self) {
        // The monitor runs until it is killed, and a monitor that ended
        // already cannot be killed again.
        drop(self.monitor.kill());
        drop(self.monitor.wait());
    }
}

fn filesystem_device() -> io::Result<PathBuf> {
    let mut found = Vec::new();
    for entry in fs::read_dir("/sys/bus/virtio/devices")? {
        let device = entry?.path();
        if fs::read_to_string(device.join("device"))?.trim_end() == FILESYSTEM_DEVICE {
            found.push(device);
        }
    }
    match <[PathBuf; 1]>::try_from(found) {
        Ok([device]) => Ok(device),
        Err(found) => panic!("the guest has {} virtio filesystem devices", found.len()),
    }
}

fn driver_of(device: &Path) -> io::Result<Option<OsString>> {
    match fs::read_link(device.join("driver")) {
        Ok(driver) => Ok(driver.file_name().map(OsStr::to_os_string)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

pub fn handover() -> io::Result<()> {
    let mut processed = Processed::open(&["virtio", "virtiofs"])?;
    let device = filesystem_device()?;
    let canonical = fs::canonicalize(&device)?;
    let in_sysfs = canonical.strip_prefix("/sys").expect("a device under /sys");
    let devpath = format!(
        "DEVPATH={}",
        in_sysfs.to_str().expect("a device path in UTF-8")
    );
    let triggered = Command::new("/bin/udevadm")
        .args(["trigger", "--action=add", "--subsystem-match=virtio"])
        .status()?;
    assert!(triggered.success(), "udevadm trigger failed: {triggered}");
    loop {
        let event = processed.next()?;
        if !event.has("ACTION=add") {
            continue;
        }
        let rule_ran = event.has("SUBSYSTEM=virtiofs");
        if !rule_ran && !event.has(&devpath) {
            continue;
        }
        let driver = driver_of(&device)?;
        match driver.as_deref().and_then(OsStr::to_str) {
            Some("voidport") => return Ok(()),
            // The uevent of the virtiofs driver for the device is still on its
            // way through udev: virtiofs binds the device first, and the rule
            // of the module runs for that uevent.
            Some("virtiofs") if !rule_ran => {}
            _ => panic!("udev processed the device, which is bound to {driver:?}"),
        }
    }
}

pub fn absent_tag() -> io::Result<()> {
    let error = View::mount("tag=voidport-absent")
        .map(drop)
        .expect_err("a mount by a tag no device has succeeded");
    assert_eq!(error.raw_os_error(), Some(libc::ENODEV), "{error}");
    Ok(())
}

fn page_size() -> usize {
    // SAFETY: the call takes no pointers.
    let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    usize::try_from(size).expect("the page size")
}

fn require_same(actual: &[u8], expected: &[u8], what: &str) {
    if let Some(at) = actual.iter().zip(expected).position(|(a, e)| a != e) {
        panic!("{what}: byte {at} differs");
    }
    assert_eq!(actual.len(), expected.len(), "{what}: the lengths differ");
}

fn open_direct(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECT)
        .open(path)
}

fn read_direct(path: &Path) -> io::Result<Vec<u8>> {
    let file = open_direct(path)?;
    let len = usize::try_from(file.metadata()?.len()).expect("an addressable file");
    let mut bytes = vec![0; len];
    file.read_exact_at(&mut bytes, 0)?;
    Ok(bytes)
}

pub fn read_write(mount: &Mount) -> io::Result<()> {
    let pattern = fs::read(PATTERN)?;
    let served = mount.file("pattern.bin");
    require_same(
        &fs::read(&served)?,
        &pattern,
        "a read through the page cache",
    );
    require_same(&read_direct(&served)?, &pattern, "a direct read");

    let name = "written";
    let offset = page_size() + 1;
    let mut expected = vec![0; offset + pattern.len()];
    let file = File::create(mount.file(name))?;
    file.write_all_at(&pattern, u64::try_from(offset).expect("an offset"))?;
    expected[offset..].copy_from_slice(&pattern);
    let head = &pattern[..=pattern.len() / 2];
    OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_DIRECT)
        .open(mount.file(name))?
        .write_all_at(head, 0)?;
    expected[..head.len()].copy_from_slice(head);
    file.sync_all()?;
    drop(file);

    let view = mount.view()?;
    require_same(&fs::read(view.file(name))?, &expected, "the written file");
    Ok(())
}

pub fn mapping(mount: &Mount) -> io::Result<()> {
    let pattern = fs::read(PATTERN)?;
    fs::write("/proc/sys/vm/drop_caches", "3")?;
    let served = File::open(mount.file("pattern.bin"))?;
    let shared = Mapping::new(&served, pattern.len(), libc::PROT_READ, libc::MAP_SHARED)?;
    require_same(shared.bytes(), &pattern, "a shared mapping");
    drop(shared);

    let name = "mapped";
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(mount.file(name))?;
    file.set_len(u64::try_from(pattern.len()).expect("a length"))?;
    let mut stores = Mapping::new(
        &file,
        pattern.len(),
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_SHARED,
    )?;
    stores.bytes_mut().copy_from_slice(&pattern);
    stores.sync()?;
    drop(stores);
    drop(file);

    let view = mount.view()?;
    require_same(&fs::read(view.file(name))?, &pattern, "the mapped file");
    Ok(())
}

pub fn restart(mount: &Mount) -> io::Result<()> {
    let pattern = fs::read(PATTERN)?;
    let old = open_direct(&mount.file("pattern.bin"))?;
    let mut start = vec![0; page_size()];
    old.read_exact_at(&mut start, 0)?;
    require_same(
        &start,
        &pattern[..start.len()],
        "a direct read before the restart",
    );
    host("restart-server")?;
    let mut byte = [0];
    let error = old
        .read_exact_at(&mut byte, 0)
        .expect_err("a handle of the session before the restart read");
    assert!(
        matches!(error.raw_os_error(), Some(libc::EBADF | libc::ESTALE)),
        "{error}"
    );
    require_same(
        &read_direct(&mount.file("pattern.bin"))?,
        &pattern,
        "a direct read after the restart",
    );
    let name = "restarted";
    fs::write(mount.file(name), &pattern)?;
    let view = mount.view()?;
    require_same(
        &fs::read(view.file(name))?,
        &pattern,
        "a file written after the restart",
    );
    Ok(())
}
