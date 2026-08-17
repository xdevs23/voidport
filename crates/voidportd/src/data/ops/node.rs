//! Node operations: lookup, forget, attributes, symlink targets, statfs.

use std::os::fd::AsFd;

use rustix::fs::{AtFlags, CWD, Mode, Timespec as HostTimespec, Timestamps, UTIME_NOW, UTIME_OMIT};
use rustix::io::Errno;
use voidport_proto::attr::EntryOut;
use voidport_proto::error::FramingError;
use voidport_proto::frame::Frame;
use voidport_proto::message::Request;
use voidport_proto::ops::node::{
    ForgetRequest, GetattrRequest, GetattrResponse, LookupRequest, LookupResponse, ReadlinkRequest,
    ReadlinkResponse, SetattrRequest, SetattrResponse, StatfsRequest, StatfsResponse,
    getattr_flags, setattr_valid,
};
use zerocopy::FromZeros as _;
use zerocopy::byteorder::little_endian::{U32, U64};

use super::{Context, OpResult, name_of};
use crate::data::node::{GENERATION, Node};
use crate::data::session::{Resolved, Session};
use crate::host::open::proc_path;
use crate::records::PrivilegedBits;

/// The entry reply a resolved node produces.
///
/// The generation is 0 by contract: node ids are never reused within a
/// session, so there is nothing for it to distinguish.
pub fn entry_of(resolved: &Resolved) -> EntryOut {
    EntryOut {
        node_id: U64::new(resolved.node.id),
        generation: U64::new(GENERATION),
        attr: resolved.attr,
    }
}

/// Resolves a name in a directory node.
pub fn lookup(context: &Context<'_>, request: Request<'_, LookupRequest>) -> OpResult {
    let parent = context.session.node(request.head().node_id.get())?;
    let name = name_of(request.name())?;
    let resolved = context.session.lookup(&parent, &name)?;
    context.reply(&LookupResponse {
        entry: entry_of(&resolved),
    })
}

/// Drops lookup counts from a node.
///
/// The one request with no response: nothing is written back, and the request
/// id retires the moment the frame is accepted.
///
/// # Errors
///
/// Returns a framing error only if the frame is malformed.
pub fn forget(session: &Session, frame: &Frame<'_>) -> Result<(), FramingError> {
    let request: Request<'_, ForgetRequest> = frame.request()?;
    session
        .nodes()
        .forget(request.head().node_id.get(), request.body().nlookup.get());
    Ok(())
}

/// Reads a node's attributes, fresh from the host.
///
/// A handle-flagged getattr is answered from the node all the same: a handle is
/// a reopen of that node's own pin, so it names the same inode and would report
/// the same attributes. What the flag buys is the check that the handle really
/// is this node's — a getattr describing one file because of the node and
/// naming another through the handle answers nobody's question.
pub fn getattr(context: &Context<'_>, request: Request<'_, GetattrRequest>) -> OpResult {
    let session = context.session;
    let node = session.node(request.head().node_id.get())?;
    if request.body().flags.get() & getattr_flags::HANDLE != 0 {
        session
            .handles()
            .owned_by(request.body().handle.get(), node.id)?;
    }
    let attr = session.attr(&node)?;
    context.reply(&GetattrResponse { attr })
}

/// Changes a node's attributes.
///
/// Every field is applied through the node's own pinned descriptor, so a change
/// lands on the inode the session resolved even if the name has since been
/// replaced. Ownership goes through the reverse mapping, which is what makes an
/// unexpressible chown an honest `EPERM` instead of a silent no-op.
pub fn setattr(context: &Context<'_>, request: Request<'_, SetattrRequest>) -> OpResult {
    let session = context.session;
    let node = session.node(request.head().node_id.get())?;
    node.require_writable()?;
    let body = request.body();
    let valid = body.valid.get();
    // One namespace snapshot for the whole operation, so the re-pin that may
    // stand behind this descriptor and the ownership algebra below cannot come
    // from two different published states.
    let namespace = session.namespace();
    let fd = node.descriptor(&namespace)?.ok_or(Errno::ROFS)?;
    let path = proc_path(fd.as_fd());

    if valid & setattr_valid::MODE != 0 {
        let delivered = body.mode.get();
        let privileged = session.privileged(&namespace);
        // Disabled, the namespace shows no privileged bits and refuses to take
        // any: a guest that cannot see them must not be able to set them.
        if privileged.is_masked() && !PrivilegedBits::of(delivered).is_empty() {
            return Err(Errno::PERM);
        }
        // The host mode never carries a privileged bit this server set — the
        // one shared masking rule, the same one every create goes through.
        let mode = Mode::from_bits_truncate(crate::records::host_mode(delivered));
        rustix::fs::chmodat(CWD, path.as_str(), mode, AtFlags::empty())?;
        // The host took the change, so the record takes the delivered bits as
        // its new value: present record, absent delete. A masked presentation
        // does neither.
        if let (Some(identity), Some(recipe)) = (node.identity(), node.host_recipe()) {
            session.record_delivered_mode(&privileged, identity, &recipe, delivered);
        }
    }
    if valid & (setattr_valid::UID | setattr_valid::GID) != 0 {
        // One snapshot for both halves of the chown, so a mutation landing
        // between them cannot map the uid and the gid through different
        // ownership algebras.
        let ownership = namespace.ownership();
        let uid = (valid & setattr_valid::UID != 0)
            .then(|| ownership.reverse_uid_for_chown(body.uid.get()))
            .transpose()
            .map_err(|_| Errno::PERM)?
            .map(rustix::process::Uid::from_raw);
        let gid = (valid & setattr_valid::GID != 0)
            .then(|| ownership.reverse_gid_for_chown(body.gid.get()))
            .transpose()
            .map_err(|_| Errno::PERM)?
            .map(rustix::process::Gid::from_raw);
        rustix::fs::chownat(CWD, path.as_str(), uid, gid, AtFlags::empty())?;
    }
    if valid
        & (setattr_valid::ATIME
            | setattr_valid::MTIME
            | setattr_valid::ATIME_NOW
            | setattr_valid::MTIME_NOW)
        != 0
    {
        let times = Timestamps {
            last_access: timestamp(
                valid,
                setattr_valid::ATIME,
                setattr_valid::ATIME_NOW,
                body.atime.sec.get(),
                body.atime.nsec.get(),
            ),
            last_modification: timestamp(
                valid,
                setattr_valid::MTIME,
                setattr_valid::MTIME_NOW,
                body.mtime.sec.get(),
                body.mtime.nsec.get(),
            ),
        };
        rustix::fs::utimensat(CWD, path.as_str(), &times, AtFlags::empty())?;
    }
    if valid & setattr_valid::SIZE != 0 {
        truncate(session, &node, body.handle.get(), valid, body.size.get())?;
    }

    let attr = session.attr(&node)?;
    context.reply(&SetattrResponse { attr })
}

/// Reads a symlink's target.
///
/// The empty-path form reads the *pinned* symlink, not the `/proc` magic
/// link that names it — reading the magic link would answer with the link's own
/// target path instead of the guest's symlink content. The target comes back
/// verbatim, escaping or not: reading a symlink is not following it, and
/// following it is the client kernel's job.
pub fn readlink(context: &Context<'_>, request: Request<'_, ReadlinkRequest>) -> OpResult {
    let session = context.session;
    let node = session.node(request.head().node_id.get())?;
    let fd = node.descriptor(&session.namespace())?.ok_or(Errno::INVAL)?;
    let target = rustix::fs::readlinkat(fd.as_fd(), "", Vec::new())?.into_bytes();
    let target_len = u32::try_from(target.len()).map_err(|_| Errno::OVERFLOW)?;
    if target.len() > context.payload_budget::<ReadlinkResponse>() {
        return Err(Errno::OVERFLOW);
    }
    context.reply_with(
        &ReadlinkResponse {
            target_len: U32::new(target_len),
        },
        &target,
    )
}

/// Reports filesystem statistics.
///
/// A host-backed node reports its backing filesystem. A synthesized directory
/// has no filesystem to report, so it answers with zeroes: it holds nothing,
/// and nothing can be created in it.
#[allow(
    clippy::unnecessary_cast,
    reason = "the field widths of `struct statfs` differ by architecture"
)]
pub fn statfs(context: &Context<'_>, request: Request<'_, StatfsRequest>) -> OpResult {
    let session = context.session;
    let node = session.node(request.head().node_id.get())?;
    let response = match node.descriptor(&session.namespace())? {
        None => StatfsResponse::new_zeroed(),
        Some(fd) => {
            let stat = rustix::fs::fstatfs(fd.as_fd())?;
            StatfsResponse {
                blocks: U64::new(stat.f_blocks),
                bfree: U64::new(stat.f_bfree),
                bavail: U64::new(stat.f_bavail),
                files: U64::new(stat.f_files),
                ffree: U64::new(stat.f_ffree),
                bsize: U32::new(stat.f_bsize as u32),
                namelen: U32::new(stat.f_namelen as u32),
                frsize: U32::new(stat.f_frsize as u32),
                reserved: U32::ZERO,
            }
        }
    };
    context.reply(&response)
}

/// The timestamp one `utimensat` field takes, given the validity mask.
fn timestamp(valid: u32, explicit: u32, now: u32, sec: i64, nsec: u32) -> HostTimespec {
    if valid & now != 0 {
        return HostTimespec {
            tv_sec: 0,
            tv_nsec: UTIME_NOW,
        };
    }
    if valid & explicit != 0 {
        return HostTimespec {
            tv_sec: sec,
            tv_nsec: i64::from(nsec),
        };
    }
    HostTimespec {
        tv_sec: 0,
        tv_nsec: UTIME_OMIT,
    }
}

/// Applies a size change, through the handle when the request names one.
///
/// A truncate needs a writable description; the node's pin is `O_PATH`, so
/// without a handle one is reopened for the call and closed again.
///
/// The handle must belong to the node the request named. The enforcement above
/// — and the attributes the reply carries — are the node's, so a truncate
/// through some other node's handle would cut a file this request never
/// checked.
fn truncate(
    session: &Session,
    node: &Node,
    handle: u64,
    valid: u32,
    size: u64,
) -> Result<(), Errno> {
    if valid & setattr_valid::HANDLE != 0 {
        let file = {
            let handles = session.handles();
            handles.owned_by(handle, node.id)?;
            handles.file(handle)?
        };
        return rustix::fs::ftruncate(file.fd(), size);
    }
    let fd = node.descriptor(&session.namespace())?.ok_or(Errno::ROFS)?;
    let writable = crate::host::open::reopen(fd.as_fd(), rustix::fs::OFlags::WRONLY)?;
    rustix::fs::ftruncate(writable.as_fd(), size)
}
