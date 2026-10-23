// SPDX-License-Identifier: GPL-2.0

// Only what bindgen's output trips, measured against this tree's lint set:
// its names, its missing documentation, the items this module never reads,
// the opaque kernel records its externs name, and the bitfield and union
// accessors it writes with bare unsafe operations, transmutes, pointer casts
// and offsets. Hand-written code in this module stays fully linted.
#[allow(
    dead_code,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    missing_docs,
    unreachable_pub,
    unsafe_op_in_unsafe_fn,
    improper_ctypes,
    unnecessary_transmutes,
    clippy::undocumented_unsafe_blocks,
    clippy::ptr_offset_with_cast,
    clippy::ptr_as_ptr,
    clippy::cast_lossless,
    clippy::useless_transmute,
    clippy::transmute_int_to_bool
)]
mod generated {
    use kernel::bindings::*;
    include!(env!("VOIDPORT_VFS_BINDINGS"));
}

use kernel::bindings;
use kernel::prelude::*;

/// The fields of a record lock that the server sees, as the C forwarders copy
/// them out of and into a `struct file_lock`.
pub(crate) use generated::voidport_record_lock as RecordLock;

// SAFETY: these generated C records contain only integers, nullable pointers
// and nullable callbacks, all of which permit an all-zero representation.
unsafe impl pin_init::Zeroable for generated::fs_parameter_spec {}
// SAFETY: every operations field is a nullable function pointer.
unsafe impl pin_init::Zeroable for generated::fs_context_operations {}
// SAFETY: parser output is a boolean plus a union of integer representations.
unsafe impl pin_init::Zeroable for generated::fs_parse_result {}
// SAFETY: every field is a nullable string, an integer or a nullable callback.
unsafe impl pin_init::Zeroable for generated::xattr_handler {}

/// The extended attribute handler record, which the upstream bindings do not
/// define.
pub(crate) use generated::xattr_handler;

/// The setxattr flags, which the bindings of longterm kernels do not define.
pub(crate) use generated::{XATTR_CREATE, XATTR_REPLACE};

pub(crate) type FillSuper =
    unsafe extern "C" fn(*mut bindings::super_block, *mut bindings::fs_context) -> c_int;
pub(crate) type FcOp = unsafe extern "C" fn(*mut bindings::fs_context) -> c_int;
pub(crate) type FcFree = unsafe extern "C" fn(*mut bindings::fs_context);
pub(crate) type FcParse =
    unsafe extern "C" fn(*mut bindings::fs_context, *mut bindings::fs_parameter) -> c_int;

#[repr(transparent)]
pub(crate) struct Parameter(generated::fs_parameter_spec);

impl Parameter {
    pub(crate) const fn string(name: &'static core::ffi::CStr, option: u8) -> Self {
        Self::of(name, option, Some(generated::fs_param_is_string))
    }

    /// An option whose value is bytes: a string, as `mount(2)` and
    /// `fsconfig(2)` give one, or a blob, as `fsconfig(2)` gives a value
    /// longer than its strings can be.
    pub(crate) const fn bytes(name: &'static core::ffi::CStr, option: u8) -> Self {
        Self::of(name, option, Some(param_is_bytes))
    }

    pub(crate) const fn u32(name: &'static core::ffi::CStr, option: u8) -> Self {
        Self::of(name, option, Some(generated::fs_param_is_u32))
    }

    pub(crate) const fn flag(name: &'static core::ffi::CStr, option: u8) -> Self {
        Self::of(name, option, None)
    }

    const fn of(
        name: &'static core::ffi::CStr,
        option: u8,
        type_: generated::fs_param_type,
    ) -> Self {
        Self(generated::fs_parameter_spec {
            name: name.as_ptr().cast(),
            opt: option,
            type_,
            ..pin_init::zeroed()
        })
    }
}

/// The parser's check of a [`Parameter::bytes`] value: a blob is accepted as
/// it is, and anything else goes through the kernel's check of a string. The
/// kernel has no check of its own for a blob.
///
/// # Safety
/// The kernel's parser calls it with live arguments, as it calls its own
/// checks.
unsafe extern "C" fn param_is_bytes(
    log: *mut generated::p_log,
    spec: *const generated::fs_parameter_spec,
    param: *mut generated::fs_parameter,
    result: *mut generated::fs_parse_result,
) -> c_int {
    // SAFETY: the parser hands over live arguments, which the string check
    // takes as they are.
    unsafe {
        if (*param).type_() == generated::fs_value_type_fs_value_is_blob {
            0
        } else {
            generated::fs_param_is_string(log, spec, param, result)
        }
    }
}

/// A filesystem's parameter table: its options, followed by the empty entry
/// that ends the table for the kernel's parser.
#[repr(C)]
pub(crate) struct Parameters<const N: usize> {
    options: [Parameter; N],
    end: generated::fs_parameter_spec,
}

// SAFETY: immutable descriptors and string literals, with no interior writes.
// The VFS reads these tables only. Its API predates const-qualified pointers.
unsafe impl<const N: usize> Sync for Parameters<N> {}

impl<const N: usize> Parameters<N> {
    pub(crate) const fn new(options: [Parameter; N]) -> Self {
        Self {
            options,
            end: pin_init::zeroed(),
        }
    }

    /// The table as the kernel reads it. A C layout places `end` right after
    /// the last option, and each option is the kernel's own descriptor.
    const fn as_ptr(&'static self) -> *const generated::fs_parameter_spec {
        core::ptr::from_ref(self).cast()
    }

    /// The generated and upstream parameter pointers refer to the same kernel
    /// layout.
    pub(crate) const fn as_kernel_ptr(&'static self) -> *const bindings::fs_parameter_spec {
        self.as_ptr().cast()
    }
}

struct ContextOps(kernel::types::Opaque<generated::fs_context_operations>);
// SAFETY: the callback table is constant and the VFS only reads it. Every
// context holds the filesystem's module reference for the table's lifetime.
unsafe impl Sync for ContextOps {}
static CONTEXT_OPS: ContextOps = ContextOps(kernel::types::Opaque::new(
    generated::fs_context_operations {
        // SAFETY: generated and upstream pointers name identical kernel types.
        // The callback ABIs differ only in header visibility to bindgen.
        free: Some(unsafe {
            core::mem::transmute::<FcFree, unsafe extern "C" fn(*mut generated::fs_context)>(
                crate::fs::voidport_rs_free_fs_context,
            )
        }),
        // SAFETY: identical kernel context and parameter layouts and callback ABI.
        parse_param: Some(unsafe {
            core::mem::transmute::<
                FcParse,
                unsafe extern "C" fn(
                    *mut generated::fs_context,
                    *mut generated::fs_parameter,
                ) -> c_int,
            >(crate::fs::voidport_rs_parse_param)
        }),
        // SAFETY: identical kernel context layout and callback ABI.
        get_tree: Some(unsafe {
            core::mem::transmute::<FcOp, unsafe extern "C" fn(*mut generated::fs_context) -> c_int>(
                crate::fs::voidport_rs_get_tree,
            )
        }),
        // SAFETY: identical kernel context layout and callback ABI.
        reconfigure: Some(unsafe {
            core::mem::transmute::<FcOp, unsafe extern "C" fn(*mut generated::fs_context) -> c_int>(
                crate::fs::voidport_rs_reconfigure,
            )
        }),
        ..pin_init::zeroed()
    },
));

/// # Safety
/// `fc` is the exclusively borrowed context in its initialization callback.
pub(crate) unsafe fn init_context(fc: *mut bindings::fs_context) {
    // SAFETY: the context is live and the callbacks were installed at registration.
    unsafe { (*fc.cast::<generated::fs_context>()).ops = CONTEXT_OPS.0.get() };
}

///
/// # Safety
/// Context and parameter remain live for the parser callback. Outputs are writable.
pub(crate) unsafe fn fs_parse<const N: usize>(
    fc: *mut bindings::fs_context,
    param: *mut bindings::fs_parameter,
    parameters: &'static Parameters<N>,
    value: *mut c_uint,
) -> c_int {
    let mut result: generated::fs_parse_result = pin_init::zeroed();
    // SAFETY: all storage is live and the parser table ends in its empty entry.
    unsafe {
        let option = generated::__fs_parse(
            &mut (*fc.cast::<generated::fs_context>()).log,
            parameters.as_ptr(),
            param.cast(),
            &mut result,
        );
        if option >= 0 {
            *value = *result.__bindgen_anon_1.uint_32.as_ref();
        }
        option
    }
}

/// # Safety
/// The parser accepted a string, and the parameter remains live for `'a`.
pub(crate) unsafe fn param_text<'a>(param: *const bindings::fs_parameter) -> &'a core::ffi::CStr {
    // SAFETY: the accepted string selects this union member, a NUL-terminated
    // string as long-lived as the parameter.
    unsafe {
        core::ffi::CStr::from_ptr(
            (*param.cast::<generated::fs_parameter>())
                .__bindgen_anon_1
                .string
                .cast(),
        )
    }
}

/// # Safety
/// The parser accepted the value, and the parameter remains live for `'a`.
pub(crate) unsafe fn param_bytes<'a>(param: *const bindings::fs_parameter) -> &'a [u8] {
    // SAFETY: the accepted value is a string, whose text is NUL-terminated,
    // or a blob, whose `size` bytes the union's pointer points to, each as
    // long-lived as the parameter.
    unsafe {
        let param = &*param.cast::<generated::fs_parameter>();
        if param.type_() == generated::fs_value_type_fs_value_is_blob {
            core::slice::from_raw_parts(param.__bindgen_anon_1.blob.cast::<u8>(), param.size)
        } else {
            core::ffi::CStr::from_ptr(param.__bindgen_anon_1.string.cast()).to_bytes()
        }
    }
}

/// # Safety
/// `fc` is live for this access.
pub(crate) unsafe fn fc_root(fc: *const bindings::fs_context) -> *mut bindings::dentry {
    // SAFETY: layout generated from the exact kernel headers.
    unsafe { (*fc.cast::<generated::fs_context>()).root }
}
/// # Safety
/// `fc` is live for this access.
pub(crate) unsafe fn fc_private(fc: *const bindings::fs_context) -> *mut c_void {
    // SAFETY: layout generated from the exact kernel headers.
    unsafe { (*fc.cast::<generated::fs_context>()).fs_private }
}
/// # Safety
/// `fc` is exclusively borrowed and `private` follows its callback lifetime.
pub(crate) unsafe fn fc_set_private(fc: *mut bindings::fs_context, private: *mut c_void) {
    // SAFETY: the callback owns this field.
    unsafe { (*fc.cast::<generated::fs_context>()).fs_private = private };
}
/// # Safety
/// `fc` is live for this access.
pub(crate) unsafe fn fc_source(fc: *const bindings::fs_context) -> *const c_char {
    // SAFETY: the VFS owns the source string until the callback returns.
    unsafe { (*fc.cast::<generated::fs_context>()).source }
}
/// Makes the value of `param` the source of `fc`, as the VFS does with the
/// string of its own `source` option. A blob is NUL-terminated as a string is,
/// so either can be the source.
///
/// # Safety
/// `fc` and `param` are live, `fc` has no source yet, and the parser accepted
/// `param` as a [`Parameter::bytes`] value.
pub(crate) unsafe fn fc_take_source(
    fc: *mut bindings::fs_context,
    param: *mut bindings::fs_parameter,
) {
    // SAFETY: the context takes the allocation of the value, which the VFS
    // frees with the context, and the parameter lets go of it, so the VFS
    // does not free it with the parameter.
    unsafe {
        let param = &mut *param.cast::<generated::fs_parameter>();
        (*fc.cast::<generated::fs_context>()).source = param.__bindgen_anon_1.string;
        param.__bindgen_anon_1.string = core::ptr::null_mut();
    }
}
/// The network namespace of the task that made the context, which the context
/// has a reference to for as long as it lives.
///
/// # Safety
/// `fc` is live for this access.
pub(crate) unsafe fn fc_net(fc: *const bindings::fs_context) -> *mut bindings::net {
    // SAFETY: layout generated from the exact kernel headers.
    unsafe { (*fc.cast::<generated::fs_context>()).net_ns }
}
/// # Safety
/// `fc` is live for this access.
pub(crate) unsafe fn fc_readonly(fc: *const bindings::fs_context) -> bool {
    // SAFETY: the VFS owns the context throughout this access.
    unsafe { (*fc.cast::<generated::fs_context>()).sb_flags & generated::VOIDPORT_SB_RDONLY != 0 }
}
/// # Safety
/// `sb` is live for this access.
pub(crate) unsafe fn sb_readonly(sb: *const bindings::super_block) -> bool {
    // SAFETY: the caller keeps the superblock live.
    unsafe { (*sb).s_flags & generated::VOIDPORT_SB_RDONLY as c_ulong != 0 }
}
/// Marks a file as one its open created, which the VFS reads to skip the
/// checks and the truncation that an open of an existing file has.
///
/// # Safety
/// `file` is the file an atomic open is opening.
pub(crate) unsafe fn set_created(file: *mut bindings::file) {
    // SAFETY: the open owns the file until it returns.
    unsafe { (*file).f_mode |= generated::VOIDPORT_FMODE_CREATED };
}
/// Whether a file opened, which makes its release run once it is closed.
///
/// # Safety
/// `file` is live for this access.
pub(crate) unsafe fn file_opened(file: *const bindings::file) -> bool {
    // SAFETY: the caller keeps the file live.
    unsafe { (*file).f_mode & generated::VOIDPORT_FMODE_OPENED != 0 }
}
/// # Safety
/// `sb` is the fresh superblock its fill owns exclusively.
pub(crate) unsafe fn sb_offer_acls(sb: *mut bindings::super_block) {
    // SAFETY: the caller owns the superblock while it is filled.
    unsafe { (*sb).s_flags |= generated::VOIDPORT_SB_POSIXACL as c_ulong };
}
/// The ACL that an ACL attribute value encodes, null for an empty ACL, or an
/// error pointer for a value that encodes none.
pub(crate) fn posix_acl_from_xattr(value: &[u8]) -> *mut bindings::posix_acl {
    // SAFETY: the initial user namespace, which the mount lives in, lives as
    // long as the kernel, and the value is readable for the whole call.
    unsafe {
        generated::posix_acl_from_xattr(
            &raw mut bindings::init_user_ns,
            value.as_ptr().cast(),
            value.len(),
        )
    }
}
/// # Safety
/// `iocb` is live for this access.
pub(crate) unsafe fn direct(iocb: *const bindings::kiocb) -> bool {
    // SAFETY: the caller keeps the request live.
    unsafe { (*iocb).ki_flags & bindings::IOCB_DIRECT as c_int != 0 }
}
/// # Safety
/// `file` is the file being opened.
pub(crate) unsafe fn allow_direct(file: *mut bindings::file) {
    // SAFETY: the open callback owns the mode of the file it opens.
    unsafe { (*file).f_mode |= generated::VOIDPORT_FMODE_CAN_ODIRECT };
}
/// # Safety
/// Called from get_tree with a live context and a matching fill callback.
pub(crate) unsafe fn get_tree_nodev(fc: *mut bindings::fs_context, fill: FillSuper) -> c_int {
    // SAFETY: both generated context pointers represent the same kernel ABI.
    unsafe {
        generated::get_tree_nodev(
            fc.cast(),
            Some(core::mem::transmute::<
                FillSuper,
                unsafe extern "C" fn(
                    *mut bindings::super_block,
                    *mut generated::fs_context,
                ) -> c_int,
            >(fill)),
        )
    }
}

pub(crate) struct Statfs {
    pub(crate) kind: c_long,
    pub(crate) bsize: c_long,
    pub(crate) blocks: u64,
    pub(crate) bfree: u64,
    pub(crate) bavail: u64,
    pub(crate) files: u64,
    pub(crate) ffree: u64,
    pub(crate) namelen: c_long,
    pub(crate) frsize: c_long,
}

/// # Safety
/// `st` is writable output storage from the VFS statfs callback.
pub(crate) unsafe fn statfs_fill(st: *mut bindings::kstatfs, statfs: Statfs) {
    // SAFETY: the generated type is the kernel's output structure.
    let st = unsafe { &mut *st.cast::<generated::kstatfs>() };
    st.f_type = statfs.kind;
    st.f_bsize = statfs.bsize;
    st.f_blocks = statfs.blocks;
    st.f_bfree = statfs.bfree;
    st.f_bavail = statfs.bavail;
    st.f_files = statfs.files;
    st.f_ffree = statfs.ffree;
    st.f_namelen = statfs.namelen;
    st.f_frsize = statfs.frsize;
}

pub(crate) fn lookup_rcu(flags: c_uint) -> bool {
    flags & generated::VOIDPORT_LOOKUP_RCU != 0
}
pub(crate) fn lookup_distrusts_cache(flags: c_uint) -> bool {
    flags
        & (generated::VOIDPORT_LOOKUP_EXCL
            | generated::VOIDPORT_LOOKUP_REVAL
            | generated::VOIDPORT_LOOKUP_RENAME_TARGET)
        != 0
}

pub(crate) fn status(result: Result) -> c_int {
    match result {
        Ok(()) => 0,
        Err(error) => error.to_errno(),
    }
}
pub(crate) fn length(result: Result<isize>) -> isize {
    result.unwrap_or_else(|error| error.to_errno() as isize)
}
/// # Safety
/// The dentry is live and its name is stable for `'a`.
pub(crate) unsafe fn dentry_bytes<'a>(dentry: *const bindings::dentry) -> &'a [u8] {
    // SAFETY: the name has the lifetime the caller promises.
    unsafe { qstr_bytes(&raw const (*dentry).__bindgen_anon_1.d_name) }
}
/// # Safety
/// The qstr is live and its name is stable for `'a`.
pub(crate) unsafe fn qstr_bytes<'a>(name: *const bindings::qstr) -> &'a [u8] {
    // SAFETY: the kernel stores both hash and length in this union member, and
    // the name has the lifetime the caller promises.
    unsafe {
        let len = (*name).__bindgen_anon_1.__bindgen_anon_1.len;
        core::slice::from_raw_parts((*name).name, len as usize)
    }
}
/// # Safety
/// The caller holds the dentry's revalidation lifetime and serializes updates.
pub(crate) unsafe fn dentry_set_time(dentry: *mut bindings::dentry, time: c_ulong) {
    // SAFETY: the field is this filesystem's cached resolution epoch.
    unsafe { (*dentry).d_time = time };
}
/// # Safety
/// The dentry is live for revalidation.
pub(crate) unsafe fn dentry_time(dentry: *const bindings::dentry) -> c_ulong {
    // SAFETY: this filesystem stores d_time in the union member.
    unsafe { (*dentry).d_time }
}
