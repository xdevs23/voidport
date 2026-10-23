use std::error::Error;
use std::iter;

use voidport::kernel::KernelError;

use crate::{KernelMountError, ReadyError};

pub fn report(program: &str, error: &(dyn Error + 'static)) {
    let mut causes = iter::successors(Some(error), |&error| error.source());
    let line = causes
        .clone()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(": ");
    eprintln!("{program}: {line}");
    if let Some(step) = causes.find_map(next_step) {
        eprintln!("{program}: next step: {step}");
    }
}

fn next_step(error: &(dyn Error + 'static)) -> Option<&'static str> {
    if let Some(error) = error.downcast_ref::<KernelError>() {
        return Some(kernel_step(error));
    }
    if let Some(error) = error.downcast_ref::<KernelMountError>() {
        return Some(match error {
            KernelMountError::FuseOnly { .. } => {
                "leave that flag out, because a mount through the kernel module runs no FUSE client"
            }
            KernelMountError::Kernel(error) => kernel_step(error),
        });
    }
    error
        .is::<ReadyError>()
        .then_some("mount with NOTIFY_SOCKET unset, or naming a socket that receives datagrams")
}

fn kernel_step(error: &KernelError) -> &'static str {
    match error {
        KernelError::Url(_) => "write the URL in one of the forms that voidport mount --help shows",
        KernelError::Vsock => "mount a vsock URL with voidport mount, which mounts it over FUSE",
        KernelError::ShareOption { .. } => "remove that option, because the URL already sets it",
        KernelError::Target { .. } => "check that the mountpoint is an existing directory",
        KernelError::Lookup { .. } | KernelError::NoAddress { .. } => {
            "check the host name, or write the address of the server in the URL"
        }
        KernelError::TooLong { .. } => "shorten the value of that option",
        KernelError::NoModule => {
            "load the voidport kernel module, for example with modprobe voidport"
        }
        KernelError::NotPermitted => "mount as root, or with the CAP_SYS_ADMIN capability",
        KernelError::Context { .. } => {
            "check what stops this process from opening a filesystem context, such as a seccomp filter"
        }
        KernelError::Configure { .. } => "correct the mount options the kernel names above",
        KernelError::Refused { .. } => {
            "check that voidportd runs at that address and shares the namespace and the path of the URL"
        }
    }
}
