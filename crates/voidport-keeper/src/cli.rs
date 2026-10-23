use std::path::PathBuf;

/// Connects the voidport device of a virtual machine to voidportd across
/// restarts of voidportd.
//
// The fields are public because the build script compiles this module too and
// reads none of them.
#[derive(Debug, clap::Parser)]
#[command(name = "voidport-keeper", version, about)]
pub struct Args {
    /// The socket QEMU connects to: the path of the `-chardev socket` used by
    /// the `vhost-user-fs-pci` device of the machine. It is created readable
    /// and writable by the account that runs the process only, and one left
    /// behind by a keeper that no longer runs is replaced.
    #[arg(long, value_name = "PATH")]
    pub vm: PathBuf,
    /// The vhost-user listener of voidportd, as added by `voidport-ctl
    /// listener add --vhost-user PATH`.
    #[arg(long, value_name = "PATH")]
    pub server: PathBuf,
}
