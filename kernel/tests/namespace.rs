// SPDX-License-Identifier: GPL-2.0

use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};

const CACHED: &str = "/mnt/tree/made";
const SERVER: &str = "/fresh/tree/made";

fn both(name: &str) -> [String; 2] {
    [format!("{CACHED}/{name}"), format!("{SERVER}/{name}")]
}

fn errno<T>(result: io::Result<T>) -> Option<i32> {
    result.err().and_then(|error| error.raw_os_error())
}

fn c_path(path: &str) -> CString {
    CString::new(path).expect("a path without NUL")
}

fn status(result: libc::c_int) -> io::Result<()> {
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn mknod(path: &str, mode: libc::mode_t, device: libc::dev_t) -> io::Result<()> {
    // SAFETY: the path is a live NUL-terminated string.
    status(unsafe { libc::mknod(c_path(path).as_ptr(), mode, device) })
}

fn rename(from: &str, to: &str, flags: libc::c_uint) -> io::Result<()> {
    let (from, to) = (c_path(from), c_path(to));
    // SAFETY: both paths are live NUL-terminated strings.
    status(unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            from.as_ptr(),
            libc::AT_FDCWD,
            to.as_ptr(),
            flags,
        )
    })
}

pub(crate) fn run() -> io::Result<()> {
    let [jar, server_jar] = both("jar");
    let [hard, _] = both("hard");
    let [link, _] = both("link");

    // A name looked up before it exists is cached as absent for the hour.
    assert_eq!(errno(fs::metadata(CACHED)), Some(libc::ENOENT));
    fs::create_dir(CACHED)?;
    for path in [CACHED, SERVER] {
        assert!(fs::metadata(path)?.is_dir(), "{path}");
    }

    fs::write(&jar, b"old jar")?;
    let reader = File::open(&jar)?;
    fs::write(format!("{CACHED}/jar.tmp"), b"new jar")?;
    fs::rename(format!("{CACHED}/jar.tmp"), &jar)?;
    for path in [&jar, &server_jar] {
        assert_eq!(fs::read(path)?, b"new jar", "{path}");
    }
    for path in both("jar.tmp") {
        assert_eq!(errno(fs::metadata(&path)), Some(libc::ENOENT), "{path}");
    }
    let mut old = Vec::new();
    (&reader).read_to_end(&mut old)?;
    assert_eq!(old, b"old jar");
    assert_eq!(reader.metadata()?.nlink(), 0);
    drop(reader);

    fs::hard_link(&jar, &hard)?;
    for path in [both("jar"), both("hard")].concat() {
        assert_eq!(fs::metadata(&path)?.nlink(), 2, "{path}");
    }
    fs::remove_file(&hard)?;
    for path in both("hard") {
        assert_eq!(errno(fs::metadata(&path)), Some(libc::ENOENT), "{path}");
    }
    for path in [&jar, &server_jar] {
        assert_eq!(fs::metadata(path)?.nlink(), 1, "{path}");
    }

    std::os::unix::fs::symlink("jar", &link)?;
    for path in both("link") {
        assert_eq!(fs::read_link(&path)?.as_os_str(), "jar", "{path}");
        assert_eq!(fs::read(&path)?, b"new jar", "{path}");
    }

    let [fifo, _] = both("fifo");
    let [socket, _] = both("socket");
    let [plain, _] = both("plain");
    let [device, _] = both("device");
    mknod(&fifo, libc::S_IFIFO | 0o644, 0)?;
    mknod(&socket, libc::S_IFSOCK | 0o644, 0)?;
    mknod(&plain, libc::S_IFREG | 0o644, 0)?;
    assert_eq!(
        errno(mknod(&device, libc::S_IFCHR | 0o644, libc::makedev(1, 3))),
        Some(libc::EPERM)
    );
    for path in both("fifo") {
        assert!(fs::metadata(&path)?.file_type().is_fifo(), "{path}");
    }
    for path in both("socket") {
        assert!(fs::metadata(&path)?.file_type().is_socket(), "{path}");
    }
    for path in both("plain") {
        let metadata = fs::metadata(&path)?;
        assert!(metadata.is_file() && metadata.len() == 0, "{path}");
    }
    for path in both("device") {
        assert_eq!(errno(fs::metadata(&path)), Some(libc::ENOENT), "{path}");
    }

    assert_eq!(
        errno(rename(&link, &jar, libc::RENAME_NOREPLACE)),
        Some(libc::EEXIST)
    );
    let [a, server_a] = both("a");
    let [b, server_b] = both("b");
    fs::write(&a, b"a")?;
    fs::write(&b, b"b")?;
    rename(&a, &b, libc::RENAME_EXCHANGE)?;
    for (path, bytes) in [(&a, b"b"), (&server_a, b"b"), (&b, b"a"), (&server_b, b"a")] {
        assert_eq!(fs::read(path)?, bytes, "{path}");
    }

    let [empty, _] = both("empty");
    fs::create_dir(&empty)?;
    fs::remove_dir(&empty)?;
    for path in both("empty") {
        assert_eq!(errno(fs::metadata(&path)), Some(libc::ENOENT), "{path}");
    }
    assert_eq!(errno(fs::remove_dir(CACHED)), Some(libc::ENOTEMPTY));

    // The wire defines no request that creates a file without a name.
    let unnamed = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_TMPFILE)
        .open(CACHED);
    assert_eq!(errno(unnamed), Some(libc::EOPNOTSUPP));

    for name in ["jar", "link", "fifo", "socket", "plain", "a", "b"] {
        fs::remove_file(format!("{CACHED}/{name}"))?;
    }
    fs::remove_dir(CACHED)?;
    for path in [CACHED, SERVER] {
        assert_eq!(errno(fs::metadata(path)), Some(libc::ENOENT), "{path}");
    }
    println!("namespace operations: every result shown at once and held by the server");
    Ok(())
}
