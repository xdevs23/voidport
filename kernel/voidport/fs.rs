// SPDX-License-Identifier: GPL-2.0

use core::ffi::CStr;
use core::num::NonZeroU16;
use core::time::Duration;

use kernel::bindings;
use kernel::prelude::*;

use crate::handshake::Server;
use crate::helpers::{self, voidport_fc_error};
use crate::mount::{Mount, Options};
use crate::session::Session;
use crate::socket::{Address, Endpoint, Network, UnixPath};
use crate::vfs::{
    fc_net, fc_private, fc_readonly, fc_set_private, fc_source, fs_parse, get_tree_nodev,
    sb_readonly, Parameter, Parameters,
};
use crate::virtio::Tag;
use voidport_session::options::{
    MountOption, ValueKind, DEFAULT_CACHE_LIFETIME, DEFAULT_RECONNECT_STALL,
};

/// The parser returns a negative errno in place of a number when it fails.
fn parsed_option(parsed: c_int) -> Result<MountOption> {
    MountOption::ALL
        .into_iter()
        .find(|option| *option as c_int == parsed)
        .ok_or_else(|| Error::from_errno(parsed))
}

/// The source is read as bytes as well, by the module itself, because the
/// VFS reads only a string as one.
const fn parameter(option: MountOption) -> Parameter {
    let (name, number) = (option.name(), option as u8);
    match option.value_kind() {
        ValueKind::Bytes => Parameter::bytes(name, number),
        ValueKind::String => Parameter::string(name, number),
        ValueKind::U32 => Parameter::u32(name, number),
        ValueKind::Flag => Parameter::flag(name, number),
    }
}

static PARAMETERS: Parameters<{ MountOption::ALL.len() }> = Parameters::new([
    parameter(MountOption::Source),
    parameter(MountOption::Namespace),
    parameter(MountOption::Addr),
    parameter(MountOption::Port),
    parameter(MountOption::Unix),
    parameter(MountOption::Path),
    parameter(MountOption::AttrTimeout),
    parameter(MountOption::EntryTimeout),
    parameter(MountOption::ReconnectStall),
    parameter(MountOption::NoPrivilegedBits),
    parameter(MountOption::DirectIo),
    parameter(MountOption::Tag),
]);

#[derive(Clone, Copy)]
enum ServerOption {
    /// The address of a TCP server, whose port is not given yet.
    Address(Address),
    /// The port of a TCP server, whose address is not given yet.
    Port(NonZeroU16),
    Tcp(Address, NonZeroU16),
    Unix(UnixPath),
    Tag(Tag),
}

impl ServerOption {
    /// This value with `given`, which an option after it gives, or the
    /// diagnostic of an option that gives a part twice or gives the server
    /// in a second way.
    fn merge(self, given: Self) -> core::result::Result<Self, &'static CStr> {
        match (self, given) {
            (Self::Address(address), Self::Port(port)) | (Self::Port(port), Self::Address(address)) => {
                Ok(Self::Tcp(address, port))
            }
            (Self::Address(_) | Self::Tcp(..), Self::Address(_)) => Err(c"addr given twice"),
            (Self::Port(_) | Self::Tcp(..), Self::Port(_)) => Err(c"port given twice"),
            (Self::Unix(_), Self::Unix(_)) => Err(c"unix given twice"),
            (Self::Tag(_), Self::Tag(_)) => Err(c"tag given twice"),
            _ => Err(c"the server is given by addr and port, by unix, or by tag, and only by one of them"),
        }
    }

    fn server(self) -> core::result::Result<Server, &'static CStr> {
        match self {
            Self::Tcp(address, port) => Ok(Server::Socket(Endpoint::Tcp { address, port })),
            Self::Unix(path) => Ok(Server::Socket(Endpoint::Unix(path))),
            Self::Tag(tag) => Ok(Server::Device(tag)),
            Self::Address(_) => Err(c"addr needs port"),
            Self::Port(_) => Err(c"port needs addr"),
        }
    }

    /// Whether this value gives a server other than `current`. A part of a
    /// TCP server is compared with that part of `current`.
    fn differs_from(self, current: Server) -> bool {
        match (self, current) {
            (Self::Address(given), Server::Socket(Endpoint::Tcp { address, .. })) => {
                given != address
            }
            (Self::Port(given), Server::Socket(Endpoint::Tcp { port, .. })) => given != port,
            (Self::Tcp(given, given_port), Server::Socket(Endpoint::Tcp { address, port })) => {
                given != address || given_port != port
            }
            (Self::Unix(given), Server::Socket(Endpoint::Unix(path))) => given != path,
            (Self::Tag(given), Server::Device(tag)) => given != tag,
            _ => true,
        }
    }
}

/// An option left out is `None`, and the mount uses its default.
pub(crate) struct Context {
    server: Option<ServerOption>,
    path: Option<KVec<u8>>,
    namespace: Option<KVec<u8>>,
    attr: Option<Duration>,
    entry: Option<Duration>,
    stall: Option<Duration>,
    mask_privileged: bool,
    direct_io: bool,
    tree_attempted: bool,
    /// The mount whose session `get_tree` opened, moved into the superblock
    /// by `fill_super`.
    pub(crate) mount: Option<KBox<Mount>>,
}

impl Context {
    fn new() -> Self {
        Self {
            server: None,
            path: None,
            namespace: None,
            attr: None,
            entry: None,
            stall: None,
            mask_privileged: false,
            direct_io: false,
            tree_attempted: false,
            mount: None,
        }
    }
}

fn diag(fc: *mut bindings::fs_context, message: &CStr) {
    // SAFETY: `fc` is a live context; `message` is NUL-terminated.
    unsafe { voidport_fc_error(fc, message.as_ptr().cast()) };
}

/// Sets `slot` to the value of an option that may be given once. `parsed` is
/// the value, or `None` when it is invalid, which is logged as `invalid`. A
/// second value is logged as `twice`.
fn set_once<T>(
    fc: *mut bindings::fs_context,
    slot: &mut Option<T>,
    parsed: Option<T>,
    invalid: &CStr,
    twice: &CStr,
) -> c_int {
    let Some(value) = parsed else {
        diag(fc, invalid);
        return EINVAL.to_errno();
    };
    if slot.replace(value).is_some() {
        diag(fc, twice);
        return EINVAL.to_errno();
    }
    0
}

/// Adds `given`, what an option gives of the server, to `slot`. `given` is
/// `None` when the value of the option is invalid, which is logged as
/// `invalid`. A part given twice and a second way to give the server fail
/// here, when their option arrives.
fn set_server(
    fc: *mut bindings::fs_context,
    slot: &mut Option<ServerOption>,
    given: Option<ServerOption>,
    invalid: &CStr,
) -> c_int {
    let Some(given) = given else {
        diag(fc, invalid);
        return EINVAL.to_errno();
    };
    match slot.map_or(Ok(given), |set| set.merge(given)) {
        Ok(server) => {
            *slot = Some(server);
            0
        }
        Err(clash) => {
            diag(fc, clash);
            EINVAL.to_errno()
        }
    }
}

/// Sets `slot` to the seconds in `text`. A later value of the option replaces
/// an earlier one.
fn set_seconds(fc: *mut bindings::fs_context, slot: &mut Option<Duration>, text: &CStr) -> c_int {
    let duration = text.to_str().map_err(|_| EINVAL).and_then(|text| {
        voidport_kernel_options::seconds(text).map_err(|error| match error {
            voidport_kernel_options::Error::Invalid => EINVAL,
            voidport_kernel_options::Error::Overflow => EOVERFLOW,
        })
    });
    match duration {
        Ok(duration) => {
            *slot = Some(duration);
            0
        }
        Err(error) => {
            diag(fc, c"expected representable nonnegative seconds");
            error.to_errno()
        }
    }
}

pub(crate) unsafe extern "C" fn voidport_rs_init_fs_context(
    fc: *mut bindings::fs_context,
) -> c_int {
    // SAFETY: the VFS exclusively owns this newly created context.
    unsafe { crate::vfs::init_context(fc) };
    let context = match KBox::new(Context::new(), GFP_KERNEL) {
        Ok(context) => context,
        Err(_) => return ENOMEM.to_errno(),
    };
    // SAFETY: `fc` is a live context; it takes ownership of the box, which
    // `free` reclaims. This callback also runs for remounts.
    unsafe {
        fc_set_private(fc, KBox::into_raw(context).cast::<c_void>());
    }
    0
}

pub(crate) unsafe extern "C" fn voidport_rs_free_fs_context(fc: *mut bindings::fs_context) {
    // SAFETY: `fc` is a live context whose private data is the `Context` box,
    // or null if init failed.
    let private = unsafe { fc_private(fc) };
    if private.is_null() {
        return;
    }
    // SAFETY: the callback exclusively owns the context and removes its pointer
    // before reclaiming the allocation.
    unsafe { fc_set_private(fc, core::ptr::null_mut()) };
    // SAFETY: reclaims the box init created; a session still inside it (the
    // mount failed after `get_tree`) is closed as it drops.
    let mut context = unsafe { KBox::from_raw(private.cast::<Context>()) };
    if let Some(mount) = context.mount.take() {
        mount.session.close();
    }
}

pub(crate) unsafe extern "C" fn voidport_rs_parse_param(
    fc: *mut bindings::fs_context,
    param: *mut bindings::fs_parameter,
) -> c_int {
    let mut value: c_uint = 0;
    // SAFETY: `fc` and `param` are live; the output is local.
    let parsed = unsafe { fs_parse(fc, param, &PARAMETERS, &mut value) };
    let option = match parsed_option(parsed) {
        Ok(option) => option,
        Err(error) => return error.to_errno(),
    };
    // SAFETY: `fc`'s private data is the `Context` box.
    let context = unsafe { &mut *(fc_private(fc).cast::<Context>()) };
    // SAFETY: only the arms of string options read the text, whose storage
    // remains valid until this callback returns.
    let text = || unsafe { crate::vfs::param_text(param) };
    match option {
        MountOption::Addr => set_server(
            fc,
            &mut context.server,
            Address::parse(text().to_bytes())
                .ok()
                .map(ServerOption::Address),
            c"addr must be a numeric IPv4 or IPv6 address",
        ),
        MountOption::Port => set_server(
            fc,
            &mut context.server,
            u16::try_from(value)
                .ok()
                .and_then(NonZeroU16::new)
                .map(ServerOption::Port),
            c"port must be 1 to 65535",
        ),
        MountOption::Unix => set_server(
            fc,
            &mut context.server,
            UnixPath::new(text().to_bytes())
                .ok()
                .map(ServerOption::Unix),
            c"unix must be an absolute path that fits a unix socket address",
        ),
        MountOption::Tag => set_server(
            fc,
            &mut context.server,
            Tag::new(text().to_bytes())
                .ok()
                .filter(Tag::is_voidport)
                .map(ServerOption::Tag),
            c"tag must be the tag of a virtio filesystem device, starting with voidport-",
        ),
        MountOption::Path => {
            // SAFETY: the parser accepted the value as bytes, which remain
            // valid until this callback returns.
            let given = unsafe { crate::vfs::param_bytes(param) };
            let Ok(path) = path_inside_namespace(given).map(clone_bytes).transpose() else {
                return ENOMEM.to_errno();
            };
            set_once(
                fc,
                &mut context.path,
                path,
                c"path must be an absolute path inside the namespace",
                c"path given twice",
            )
        }
        MountOption::Namespace => {
            // SAFETY: the parser accepted the value as bytes, which remain
            // valid until this callback returns.
            let given = unsafe { crate::vfs::param_bytes(param) };
            let Ok(namespace) = clone_bytes(given) else {
                return ENOMEM.to_errno();
            };
            set_once(
                fc,
                &mut context.namespace,
                Some(namespace).filter(|namespace| !namespace.is_empty()),
                c"the namespace is empty",
                c"namespace given twice",
            )
        }
        MountOption::Source => {
            // SAFETY: `fc` is live.
            if !unsafe { fc_source(fc) }.is_null() {
                diag(fc, c"source given twice");
                return EINVAL.to_errno();
            }
            // SAFETY: `fc` and `param` are live, `fc` has no source, and the
            // parser accepted the value as bytes.
            unsafe { crate::vfs::fc_take_source(fc, param) };
            0
        }
        MountOption::AttrTimeout => set_seconds(fc, &mut context.attr, text()),
        MountOption::EntryTimeout => set_seconds(fc, &mut context.entry, text()),
        MountOption::ReconnectStall => set_seconds(fc, &mut context.stall, text()),
        MountOption::NoPrivilegedBits => {
            context.mask_privileged = true;
            0
        }
        MountOption::DirectIo => {
            context.direct_io = true;
            0
        }
    }
}

pub(crate) unsafe extern "C" fn voidport_rs_get_tree(fc: *mut bindings::fs_context) -> c_int {
    // SAFETY: `fc`'s private data is the `Context` box.
    let context = unsafe { &mut *(fc_private(fc).cast::<Context>()) };

    if context.tree_attempted {
        diag(fc, c"this context already attempted tree construction");
        return EBUSY.to_errno();
    }

    // The namespace option, or else the mount source, taken verbatim.
    let namespace = match context.namespace.as_deref() {
        Some(namespace) => namespace,
        None => {
            // SAFETY: `fc` is live; the source, if present, is a
            // NUL-terminated string valid for this call.
            let source = unsafe { fc_source(fc) };
            if source.is_null() {
                diag(fc, c"the mount needs a source or a namespace");
                return EINVAL.to_errno();
            }
            // SAFETY: `source` is a live NUL-terminated string.
            unsafe { CStr::from_ptr(source.cast()) }.to_bytes()
        }
    };
    if namespace.is_empty() {
        diag(fc, c"the namespace is empty");
        return EINVAL.to_errno();
    }

    let server = match context.server.map(ServerOption::server) {
        Some(Ok(server)) => server,
        Some(Err(missing)) => {
            diag(fc, missing);
            return EINVAL.to_errno();
        }
        None => {
            diag(fc, c"the mount needs addr and port, unix, or tag");
            return EINVAL.to_errno();
        }
    };

    let options = Options {
        server,
        attr_timeout: duration_to_jiffies(context.attr.unwrap_or(DEFAULT_CACHE_LIFETIME)),
        entry_timeout: duration_to_jiffies(context.entry.unwrap_or(DEFAULT_CACHE_LIFETIME)),
        stall: context.stall.unwrap_or(DEFAULT_RECONNECT_STALL),
        mask_privileged: context.mask_privileged,
        direct_io: context.direct_io,
    };
    // Copies, because a failed connection attempt leaves the context
    // retryable.
    let (namespace, path) = match (
        clone_bytes(namespace),
        clone_bytes(context.path.as_deref().unwrap_or_default()),
    ) {
        (Ok(namespace), Ok(path)) => (namespace, path),
        _ => return ENOMEM.to_errno(),
    };
    // The mount dials from the network namespace it was made in, which the
    // context carries, as the kernel's own network filesystems do.
    // SAFETY: `fc` is live and has a reference to its namespace.
    let network = unsafe { Network::get(fc_net(fc)) };
    let session = match Session::open(options.server, options.stall, namespace, path, network) {
        Ok(session) => session,
        Err(error) => {
            diag(fc, error.diagnostic());
            return error.errno().to_errno();
        }
    };
    let mount = match KBox::new(Mount::new(session.clone(), options), GFP_KERNEL) {
        Ok(mount) => mount,
        Err(_) => {
            session.close();
            return ENOMEM.to_errno();
        }
    };
    context.mount = Some(mount);
    // A dial failure leaves the context retryable. Once the VFS starts tree
    // construction, fill_super may consume the session even on an error.
    context.tree_attempted = true;

    // SAFETY: `fc` is live; `fill_super` is this module's filler with the
    // matching signature.
    unsafe { get_tree_nodev(fc, crate::superblock::fill_super) }
}

/// Remount cannot change a live session's endpoint or filesystem options. A
/// remount to read-only writes back what the mount still holds first.
pub(crate) unsafe extern "C" fn voidport_rs_reconfigure(fc: *mut bindings::fs_context) -> c_int {
    // SAFETY: reconfiguration holds the mounted root and its live superblock;
    // this context's private allocation was installed at initialization.
    let (context, sb) = unsafe {
        let root = crate::vfs::fc_root(fc);
        if root.is_null() {
            return EINVAL.to_errno();
        }
        (&*fc_private(fc).cast::<Context>(), (*root).d_sb)
    };
    // SAFETY: the superblock is live for the whole reconfiguration.
    let mount = unsafe { crate::node::mount_of(sb) };
    let options = mount.options();
    let changed = context
        .server
        .is_some_and(|given| given.differs_from(options.server))
        || context
            .namespace
            .as_deref()
            .is_some_and(|namespace| namespace != mount.session.namespace())
        || context
            .path
            .as_deref()
            .is_some_and(|path| path != mount.session.path())
        || context
            .attr
            .is_some_and(|attr| duration_to_jiffies(attr) != options.attr_timeout)
        || context
            .entry
            .is_some_and(|entry| duration_to_jiffies(entry) != options.entry_timeout)
        || context.stall.is_some_and(|stall| stall != options.stall)
        || (context.mask_privileged && !options.mask_privileged)
        || (context.direct_io && !options.direct_io);
    if changed {
        diag(fc, c"filesystem option changes require a new mount");
        return EINVAL.to_errno();
    }
    // SAFETY: the context and the superblock are live for the whole
    // reconfiguration.
    if unsafe { fc_readonly(fc) && !sb_readonly(sb) } {
        // SAFETY: as above.
        if let Err(error) = kernel::error::to_result(unsafe { bindings::sync_filesystem(sb) }) {
            return error.to_errno();
        }
    }
    0
}

fn duration_to_jiffies(duration: Duration) -> c_ulong {
    // SAFETY: both helpers return compile-time kernel constants.
    let (hz, max) = unsafe { (helpers::voidport_hz(), helpers::voidport_max_jiffy_offset()) };
    voidport_kernel_options::ticks(duration, hz, max as u64) as c_ulong
}

/// The path inside the namespace that `given` sets, as the handshake sends
/// it: without a trailing slash, and empty for the namespace root, so a mount
/// and a remount that spell one path differently agree. `None` for a path that
/// is not absolute.
fn path_inside_namespace(given: &[u8]) -> Option<&[u8]> {
    if given.first() != Some(&b'/') {
        return None;
    }
    let end = given
        .iter()
        .rposition(|byte| *byte != b'/')
        .map_or(0, |last| last + 1);
    Some(&given[..end])
}

fn clone_bytes(bytes: &[u8]) -> Result<KVec<u8>> {
    let mut owned = KVec::new();
    owned.extend_from_slice(bytes, GFP_KERNEL)?;
    Ok(owned)
}

struct FilesystemType(kernel::types::Opaque<bindings::file_system_type>);
// SAFETY: fields are initialized before registration. Afterwards only the VFS
// mutates registration bookkeeping under its filesystem locks. Unload requires
// all mounts to have released their module references.
unsafe impl Sync for FilesystemType {}
static FS_TYPE: FilesystemType =
    FilesystemType(kernel::types::Opaque::new(bindings::file_system_type {
        name: c"voidport".as_ptr().cast(),
        // No user-namespace mounting: the mount lives in the initial
        // namespace, which is where credentials are read.
        fs_flags: 0,
        kill_sb: Some(bindings::kill_anon_super),
        init_fs_context: Some(voidport_rs_init_fs_context),
        parameters: PARAMETERS.as_kernel_ptr(),
        ..pin_init::zeroed()
    }));

/// # Safety
///
/// Must be called once, before any mount, with `owner` the module being
/// loaded.
pub(crate) unsafe fn register(owner: *mut bindings::module) -> Result {
    // SAFETY: this initializer runs exactly once per module load, before
    // registration makes any callback or mount possible. No other thread can
    // read the module pointer until register_filesystem publishes the type.
    unsafe {
        (*FS_TYPE.0.get()).owner = owner;
        kernel::error::to_result(bindings::register_filesystem(FS_TYPE.0.get()))
    }
}

/// # Safety
///
/// Must be called once, at unload, after [`register`] succeeded.
pub(crate) unsafe fn unregister() {
    // SAFETY: `FS_TYPE` was registered by `register` and no mount remains.
    unsafe {
        let _ = kernel::error::to_result(bindings::unregister_filesystem(FS_TYPE.0.get()));
    }
}
