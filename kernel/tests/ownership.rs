// SPDX-License-Identifier: GPL-2.0

use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;

fn getdents(file: &File, bytes: &mut [u8]) -> io::Result<usize> {
    // SAFETY: the descriptor and writable buffer remain live for the syscall.
    let result = unsafe {
        libc::syscall(
            libc::SYS_getdents64,
            file.as_raw_fd(),
            bytes.as_mut_ptr(),
            bytes.len(),
        )
    };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result as usize)
    }
}

pub fn run() -> io::Result<()> {
    let file = File::open("/mnt/tree/note.txt")?;
    // Attribute replies do not need a payload allocation. With zero attribute
    // lifetime this is an unrelated wire call, not a cached answer.
    assert!(file.metadata()?.len() > 0);
    let directory = File::open("/mnt/tree")?;
    let mut bytes = [0u8; 64];
    // A short userspace buffer accepts only a prefix of the returned wire
    // batch. Closing now leaves the rest for the complete-frame obligation.
    assert!(getdents(&directory, &mut bytes)? > 0);
    assert!(getdents(&directory, &mut bytes)? > 0);
    for _ in 0..32 {
        assert!(std::fs::metadata("/mnt/tree/note.txt")?.len() > 0);
    }
    drop(directory);
    drop(file);
    // Repeating the eviction with fresh admissions catches lost and duplicate
    // retirements.
    for _ in 0..16 {
        drop(File::open("/mnt/tree/note.txt")?);
        std::fs::write("/proc/sys/vm/drop_caches", "3")?;
    }
    println!("ownership: foreground progress verified");
    Ok(())
}
