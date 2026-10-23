use std::ffi::OsStr;
use std::fs::File;
use std::io;
use std::os::fd::AsFd as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Parser as _;
use rustix::thread::{LinkNameSpaceType, move_into_link_name_space};
use voidport::kernel::{self, KernelError, KernelMountOptions, PendingMount};

pub const NAME: &str = "mount.voidport";

/// The exit status mount(8) reads as an incorrect invocation. From "EXIT
/// STATUS" of mount(8),
/// <https://man7.org/linux/man-pages/man8/mount.8.html#EXIT_STATUS>.
const USAGE: u8 = 1;

/// The exit status mount(8) reads as a failed mount, from the same section.
const MOUNT_FAILURE: u8 = 32;

/// Mounts a voidport share through the kernel module, the way mount(8) runs a
/// helper.
///
/// The arguments are those of "EXTERNAL HELPERS" in mount(8),
/// <https://man7.org/linux/man-pages/man8/mount.8.html#EXTERNAL_HELPERS>,
/// checked on 2026-10-22.
#[derive(Debug, clap::Parser)]
#[command(name = NAME, version)]
pub struct Helper {
    /// The mount URL, as `voidport mount` takes it, or for a remount the
    /// source the mount table shows.
    url: String,
    /// Where to mount it.
    mountpoint: PathBuf,
    /// Accepted for mount(8). An option the module does not define fails the
    /// mount all the same.
    #[arg(short = 's')]
    _sloppy_has_no_effect: bool,
    /// Do everything but the mount itself.
    #[arg(short = 'f')]
    fake: bool,
    /// Accepted for mount(8). The helper writes no mtab.
    #[arg(short = 'n')]
    _mtab_is_never_written: bool,
    /// Report the mount once it is made.
    #[arg(short = 'v')]
    verbose: bool,
    /// The mount options, separated by commas.
    #[arg(short = 'o', value_name = "OPTIONS", value_delimiter = ',')]
    options: Vec<String>,
    /// Mount in the mount namespace this file refers to.
    #[arg(short = 'N', value_name = "NAMESPACE")]
    namespace: Option<PathBuf>,
}

pub fn invoked(argument: Option<&OsStr>) -> bool {
    argument.map(Path::new).and_then(Path::file_name) == Some(OsStr::new(NAME))
}

pub fn main() -> ExitCode {
    let helper = match Helper::try_parse() {
        Ok(helper) => helper,
        Err(error) => {
            // A help or version request is not an error.
            let status = if error.use_stderr() { USAGE } else { 0 };
            // A report that cannot be written has nowhere else to go, and the
            // exit status still reaches mount(8).
            let _standard_error_is_gone = error.print();
            return ExitCode::from(status);
        }
    };
    match helper.run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            crate::report::report(NAME, &error);
            ExitCode::from(MOUNT_FAILURE)
        }
    }
}

impl Helper {
    fn run(self) -> Result<(), HelperError> {
        if let Some(namespace) = &self.namespace {
            enter(namespace).map_err(|source| HelperError::Namespace {
                namespace: namespace.clone(),
                source,
            })?;
        }
        let options =
            KernelMountOptions::from_mount_options(self.options.iter().map(String::as_str));
        if options.remounts() {
            // The source is the mount table's, which a remount does not read.
            if !self.fake {
                kernel::remount(&self.mountpoint, &options).map_err(|source| {
                    HelperError::Remount {
                        target: self.mountpoint.clone(),
                        source,
                    }
                })?;
            }
            if self.verbose {
                eprintln!("{NAME}: {} remounted", self.mountpoint.display());
            }
        } else {
            let failed = |source| HelperError::Mount {
                url: self.url.clone(),
                target: self.mountpoint.clone(),
                source,
            };
            let mount = PendingMount::new(&self.url, &self.mountpoint, &options).map_err(failed)?;
            if !self.fake {
                mount.make().map_err(failed)?;
            }
            if self.verbose {
                eprintln!(
                    "{NAME}: {} mounted on {}",
                    self.url,
                    self.mountpoint.display()
                );
            }
        }
        Ok(())
    }
}

fn enter(namespace: &Path) -> io::Result<()> {
    let file = File::open(namespace)?;
    move_into_link_name_space(file.as_fd(), Some(LinkNameSpaceType::Mount))?;
    Ok(())
}

#[derive(Debug, thiserror::Error)]
enum HelperError {
    #[error("cannot enter the mount namespace {}", namespace.display())]
    Namespace {
        namespace: PathBuf,
        source: io::Error,
    },
    #[error("cannot mount {url} on {}", target.display())]
    Mount {
        url: String,
        target: PathBuf,
        source: KernelError,
    },
    #[error("cannot remount {}", target.display())]
    Remount {
        target: PathBuf,
        source: KernelError,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(arguments: &[&str]) -> Helper {
        Helper::try_parse_from(arguments)
            .unwrap_or_else(|error| panic!("{arguments:?} should parse: {error}"))
    }

    #[test]
    fn the_helper_is_known_by_the_name_it_was_started_under() {
        for started in [
            "mount.voidport",
            "/run/current-system/sw/bin/mount.voidport",
        ] {
            assert!(invoked(Some(OsStr::new(started))), "{started}");
        }
        for started in ["voidport", "/usr/bin/voidport", "mount.voidport.old"] {
            assert!(!invoked(Some(OsStr::new(started))), "{started}");
        }
        assert!(!invoked(None));
    }

    #[test]
    fn the_helper_reads_what_util_linux_passes_it() {
        let helper = parse(&[
            NAME,
            "voidport://build-host.example:9000/@ns/sub",
            "/mnt/project",
            "-s",
            "-f",
            "-n",
            "-v",
            "-o",
            "ro,nosuid,attr_timeout=0",
            "-N",
            "/proc/1/fd/3",
        ]);
        assert_eq!(helper.url, "voidport://build-host.example:9000/@ns/sub");
        assert_eq!(helper.mountpoint, Path::new("/mnt/project"));
        assert!(helper.fake && helper.verbose);
        assert_eq!(helper.options, ["ro", "nosuid", "attr_timeout=0"]);
        assert_eq!(helper.namespace.as_deref(), Some(Path::new("/proc/1/fd/3")));
    }

    #[test]
    fn the_helper_reads_what_busybox_passes_it() {
        // Busybox puts its flags before the source and the target, and passes
        // only the options that are not flags of mount(2).
        let helper = parse(&[
            NAME,
            "-n",
            "voidport://h:1/@ns",
            "/mnt",
            "-o",
            "attr_timeout=0",
        ]);
        assert_eq!(helper.url, "voidport://h:1/@ns");
        assert_eq!(helper.mountpoint, Path::new("/mnt"));
        assert_eq!(helper.options, ["attr_timeout=0"]);
        assert!(
            parse(&[NAME, "voidport://h:1/@ns", "/mnt"])
                .options
                .is_empty()
        );
    }

    #[test]
    fn a_remount_changes_the_mount_without_reading_its_source_as_a_url() {
        // util-linux passes the source the mount table shows, which a mount
        // made by the module from options alone has as a namespace name.
        let remount = parse(&[NAME, "project", "/mnt/src", "-f", "-o", "rw,remount,ro"]);
        assert!(remount.run().is_ok());
        let mount = parse(&[NAME, "project", "/mnt/src", "-f", "-o", "ro"]);
        assert!(matches!(
            mount.run(),
            Err(HelperError::Mount {
                source: KernelError::Url(_),
                ..
            })
        ));
    }

    #[test]
    fn the_command_line_is_a_valid_clap_definition() {
        use clap::CommandFactory as _;

        Helper::command().debug_assert();
    }
}
