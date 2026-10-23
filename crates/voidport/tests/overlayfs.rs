#![forbid(unsafe_code)]

use voidport_test_client as support;

use std::ffi::CString;
use std::fs;
use std::path::PathBuf;

use rustix::io::Errno;
use rustix::mount::{MountFlags, UnmountFlags};
use support::Fixture;
use voidport_spawn::Program;

fn report_kernel_diagnostics() {
    match Program::new("dmesg").args(["--level", "err,warn"]).output() {
        Ok(output) => eprintln!(
            "kernel diagnostics ({}):\n{}{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        ),
        Err(error) => eprintln!("kernel diagnostics unavailable: {error}"),
    }
}

/// The overlay must be removed before the FUSE mount that holds its upper
/// directory, including when an assertion panics.
struct Overlay {
    at: PathBuf,
    mounted: bool,
}

impl Overlay {
    fn unmount(&mut self) -> Result<(), Errno> {
        rustix::mount::unmount(&self.at, UnmountFlags::empty())?;
        self.mounted = false;
        Ok(())
    }
}

impl Drop for Overlay {
    fn drop(&mut self) {
        if self.mounted
            && let Err(error) = self.unmount()
        {
            eprintln!("{} remains mounted: {error}", self.at.display());
        }
    }
}

#[test]
fn overlayfs_proves_writes_if_accepted_or_records_refusal_or_readonly() {
    match rustix::thread::capabilities(None) {
        Ok(sets)
            if sets
                .effective
                .contains(rustix::thread::CapabilitySet::SYS_ADMIN) => {}
        Ok(_) => {
            eprintln!("skipping privileged overlayfs probe: CAP_SYS_ADMIN is not effective");
            return;
        }
        Err(error) => {
            eprintln!("skipping privileged overlayfs probe: capabilities unreadable: {error}");
            return;
        }
    }
    support::preflight();
    let fixture = Fixture::start("overlay");
    let guest = fixture.mount("overlay", "plain", "/tree");
    let lower = fixture.directory.directory("lower");
    let merged = fixture.directory.directory("merged");
    let upper = guest.path("upper");
    let work = guest.path("work");
    fs::create_dir(&upper).expect("create upper directory");
    fs::create_dir(&work).expect("create work directory");
    let options = CString::new(format!(
        "lowerdir={},upperdir={},workdir={},userxattr",
        lower.display(),
        upper.display(),
        work.display(),
    ))
    .expect("fixture paths have no NULs");
    let result = rustix::mount::mount(
        "overlay",
        &merged,
        "overlay",
        MountFlags::empty(),
        options.as_c_str(),
    );
    if let Err(error) = result {
        eprintln!("overlayfs mount refused: {error:?} ({error})");
        report_kernel_diagnostics();
        return;
    }
    let mut overlay = Overlay {
        at: merged,
        mounted: true,
    };
    let status = rustix::fs::statvfs(&overlay.at).expect("overlay mount status");
    if status
        .f_flag
        .contains(rustix::fs::StatVfsMountFlags::RDONLY)
    {
        let error = fs::write(overlay.at.join("read-only-probe"), b"probe")
            .expect_err("read-only overlay must refuse a write");
        eprintln!("overlayfs mount succeeded read-only");
        eprintln!(
            "overlayfs write-probe errno: {:?} ({error})",
            error.raw_os_error()
        );
        assert_eq!(error.raw_os_error(), Some(Errno::ROFS.raw_os_error()));
        report_kernel_diagnostics();
        overlay.unmount().expect("read-only overlayfs unmounts");
        return;
    }
    assert!(
        work.join("work").is_dir(),
        "overlayfs prepared its work directory"
    );
    eprintln!("overlayfs verdict: accepted writable mount");
    let path = overlay.at.join("created");
    fs::write(&path, b"overlay contents").expect("the merged tree is writable");
    assert_eq!(
        fs::read(&path).expect("read merged file"),
        b"overlay contents"
    );
    assert_eq!(
        fs::read(fixture.host("tree/upper/created")).expect("read host file"),
        b"overlay contents"
    );
    overlay.unmount().expect("overlayfs unmounts");
}
