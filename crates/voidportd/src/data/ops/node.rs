use std::os::fd::{AsFd, OwnedFd};
use std::sync::Arc;

use rustix::fs::{AtFlags, CWD, Mode, Timespec as HostTimespec, Timestamps, UTIME_NOW, UTIME_OMIT};
use rustix::io::Errno;
use voidport_memory::Buffer;
use voidport_proto::attr::EntryOut;
use voidport_proto::error::FramingError;
use voidport_proto::frame::{Frame, FrameWriter};
use voidport_proto::message::Request;
use voidport_proto::ops::node::{
    ForgetRequest, GetattrRequest, GetattrResponse, LookupRequest, LookupResponse, ReadlinkRequest,
    ReadlinkResponse, SetattrRequest, SetattrResponse, StatfsRequest, StatfsResponse,
    getattr_flags, setattr_valid,
};
use zerocopy::FromZeros as _;
use zerocopy::byteorder::little_endian::{U32, U64};

use super::{Context, OpResult, Reply, name_of};
use crate::data::cache::Unserved;
use crate::data::handle::FileHandle;
use crate::data::node::{GENERATION, Node};
use crate::data::session::{Resolved, Session};
use crate::host::Io;
use crate::host::lock::LockKind;
use crate::host::open::proc_path;
use crate::records::PrivilegedBits;

/// The generation is 0 by contract: node ids are never reused within a session.
pub fn entry_of(resolved: &Resolved) -> EntryOut {
    EntryOut {
        node_id: U64::new(resolved.node.id),
        generation: U64::new(GENERATION),
        attr: resolved.attr,
    }
}

pub fn lookup(context: &Context<'_>, request: Request<'_, LookupRequest>) -> OpResult {
    let parent = context.session.node(request.head().node_id.get())?;
    let name = name_of(request.name())?;
    let resolved = context.session.lookup(&parent, &name)?;
    context.reply(&LookupResponse {
        entry: entry_of(&resolved),
    })
}

pub fn forget(session: &Session, frame: &Frame<'_>) -> Result<(), FramingError> {
    let request: Request<'_, ForgetRequest> = frame.request()?;
    session
        .nodes()
        .forget(request.head().node_id.get(), request.body().nlookup.get());
    Ok(())
}

/// A handle-flagged getattr is answered from the node all the same: a handle is
/// a reopen of the cached descriptor of that node, so it names the same inode.
/// The flag only adds the check that the handle belongs to this node.
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

/// Every field is applied through the cached descriptor of the node, so a change
/// applies to the inode the session resolved even if the name has since been
/// replaced. Ownership goes through the reverse mapping, which makes an
/// unexpressible chown an honest `EPERM` instead of a silent no-op.
pub fn setattr(
    context: &Context<'_>,
    request: Request<'_, SetattrRequest>,
) -> Result<Reply, Unserved> {
    let session = context.session;
    let node = session.node(request.head().node_id.get())?;
    node.require_writable()?;
    let body = request.body();
    let valid = body.valid.get();
    // One namespace snapshot for the whole operation, so the reopen that may
    // produce this descriptor and the ownership algebra below cannot come
    // from two different published states.
    let namespace = session.namespace();
    let fd = node.descriptor(&namespace)?.ok_or(Errno::ROFS)?;
    let path = proc_path(fd.as_fd());
    // A truncate obtains the description it writes through before anything
    // else changes, because it may wait and serve the request again.
    let truncating = if valid & setattr_valid::SIZE != 0 {
        let handle = (valid & setattr_valid::HANDLE != 0).then(|| body.handle.get());
        Some(truncation(session, &node, &fd, handle)?)
    } else {
        None
    };

    if valid & setattr_valid::MODE != 0 {
        let delivered = body.mode.get();
        let privileged = session.privileged(&namespace);
        // Disabled, the namespace shows no privileged bits and rejects
        // any: a guest that cannot see them must not be able to set them.
        if privileged.is_masked() && !PrivilegedBits::of(delivered).is_empty() {
            return Err(Errno::PERM.into());
        }
        // The host mode never has a privileged bit this server set: the one
        // shared masking rule, the same one every create goes through.
        let mode = Mode::from_bits_truncate(crate::records::host_mode(delivered));
        rustix::fs::chmodat(CWD, path.as_str(), mode, AtFlags::empty())?;
        // The host accepted the change, so the record takes the delivered bits as
        // its new value: present record, absent delete. A masked presentation
        // does neither.
        if let (Some(identity), Some(recipe)) = (node.identity(), node.host_recipe()) {
            session.record_delivered_mode(&privileged, identity, &recipe, delivered);
        }
    }
    if valid & (setattr_valid::UID | setattr_valid::GID) != 0 {
        // One snapshot for both halves of the chown, so a mutation arriving
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
    if let Some((io, _handle)) = &truncating {
        rustix::fs::ftruncate(io.fd(), body.size.get())?;
    }

    let attr = session.attr(&node)?;
    Ok(context.reply(&SetattrResponse { attr })?)
}

/// The empty-path form reads the `O_PATH` symlink, not the `/proc` magic link
/// that names it, which would return the target path of the magic link. The
/// target comes back verbatim: reading a symlink is not following it.
pub fn readlink(
    context: &Context<'_>,
    request: Request<'_, ReadlinkRequest>,
    buffer: Option<Buffer>,
) -> OpResult {
    let session = context.session;
    let node = session.node(request.head().node_id.get())?;
    let fd = node.descriptor(&session.namespace())?.ok_or(Errno::INVAL)?;
    let mut buffer = buffer.ok_or(Errno::NOMEM)?;
    let fixed = FrameWriter::response_len::<ReadlinkResponse>(0);
    let target_len = rustix::fs::readlinkat_raw(fd.as_fd(), "", &mut buffer[fixed..])?;
    context.reply_in(
        buffer,
        &ReadlinkResponse {
            target_len: U32::new(u32::try_from(target_len).map_err(|_| Errno::OVERFLOW)?),
        },
        target_len,
    )
}

/// A synthesized directory has no filesystem to report, so it returns zeroes.
pub fn statfs(context: &Context<'_>, request: Request<'_, StatfsRequest>) -> OpResult {
    let session = context.session;
    let node = session.node(request.head().node_id.get())?;
    let response = match node.descriptor(&session.namespace())? {
        None => StatfsResponse::new_zeroed(),
        Some(fd) => {
            let stat = rustix::fs::fstatfs(fd.as_fd())?;
            let to_u32 = |value| u32::try_from(value).map_err(|_| Errno::OVERFLOW);
            StatfsResponse {
                blocks: U64::new(stat.f_blocks),
                bfree: U64::new(stat.f_bfree),
                bavail: U64::new(stat.f_bavail),
                files: U64::new(stat.f_files),
                ffree: U64::new(stat.f_ffree),
                bsize: U32::new(to_u32(stat.f_bsize)?),
                namelen: U32::new(to_u32(stat.f_namelen)?),
                frsize: U32::new(to_u32(stat.f_frsize)?),
                reserved: U32::ZERO,
            }
        }
    };
    context.reply(&response)
}

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

/// The path descriptor of the node is `O_PATH`, and a truncate needs a writable
/// description. The handle must belong to the node of the request: the
/// enforcement above and the attributes in the reply belong to the node, so a
/// truncate through a handle of another node would cut a file this request
/// never checked.
fn truncation(
    session: &Session,
    node: &Node,
    pinned: &Arc<OwnedFd>,
    handle: Option<u64>,
) -> Result<(Io, Option<FileHandle>), Unserved> {
    let Some(handle) = handle else {
        let file = super::file::handle(session, node, pinned, rustix::fs::OFlags::WRONLY, None)?;
        return Ok((file.io()?, Some(file)));
    };
    let file = {
        let handles = session.handles();
        handles.owned_by(handle, node.id)?;
        handles.file(handle)?
    };
    file.permits(LockKind::Write).map_err(|_| Errno::INVAL)?;
    Ok((file.io()?, None))
}
