//! A denied read hides: the name is absent from `listxattr` and `getxattr`
//! returns `ENODATA`, because a denial must not advertise what it denies.
//!
//! For `listxattr` the size is the guest-visible one, the length of the
//! NUL-separated list the client rebuilds, not the length of the name stream on
//! this wire.

use std::os::fd::AsFd as _;

use rustix::io::Errno;
use voidport_memory::Buffer;
use voidport_proto::frame::FrameWriter;
use voidport_proto::message::Request;
use voidport_proto::ops::xattr::{
    GetxattrRequest, GetxattrResponse, ListxattrRequest, ListxattrResponse, RemovexattrRequest,
    RemovexattrResponse, SetxattrRequest, SetxattrResponse, XattrNameHeader, XattrNameWriter,
    setxattr_flags,
};
use zerocopy::byteorder::little_endian::U32;

use super::{Buffers, Context, OpResult};
use crate::host::xattr;
use crate::rules::XattrRules;

pub fn getxattr(
    context: &Context<'_>,
    request: Request<'_, GetxattrRequest>,
    buffer: Option<Buffer>,
) -> OpResult {
    let session = context.session;
    let node = session.node(request.head().node_id.get())?;
    let namespace = session.namespace();
    let fd = node.descriptor(&namespace)?.ok_or(Errno::OPNOTSUPP)?;
    let name = request.name();
    // A denied read is indistinguishable from an attribute that is not there:
    // answering anything else would advertise the very name the rule hides.
    require_readable(namespace.xattr(), name)?;

    if request.body().size.get() == 0 {
        let size = xattr::size(fd.as_fd(), name)?;
        return context.reply(&GetxattrResponse {
            size: U32::new(u32::try_from(size).map_err(|_| Errno::OVERFLOW)?),
            value_len: U32::ZERO,
        });
    }
    let mut buffer = buffer.ok_or(Errno::NOMEM)?;
    let fixed = FrameWriter::response_len::<GetxattrResponse>(0);
    // The buffer has the size the request asked for, so a larger value is an
    // `ERANGE` from the host.
    let read = xattr::get_into(fd.as_fd(), name, &mut buffer[fixed..])?;
    let size = u32::try_from(read).map_err(|_| Errno::OVERFLOW)?;
    context.reply_in(
        buffer,
        &GetxattrResponse {
            size: U32::new(size),
            value_len: U32::new(size),
        },
        read,
    )
}

pub fn setxattr(context: &Context<'_>, request: Request<'_, SetxattrRequest>) -> OpResult {
    let session = context.session;
    let node = session.node(request.head().node_id.get())?;
    // The share mode first: `EROFS` precedes attribute policy, always.
    node.require_writable()?;
    let namespace = session.namespace();
    let fd = node.descriptor(&namespace)?.ok_or(Errno::OPNOTSUPP)?;
    let name = request.name();
    require_writable(namespace.xattr(), name)?;
    xattr::set(
        fd.as_fd(),
        name,
        request.value(),
        flags_of(request.body().flags.get()),
    )?;
    context.reply(&SetxattrResponse {})
}

/// Removal takes the write verdict, so readable does not imply removable.
pub fn removexattr(context: &Context<'_>, request: Request<'_, RemovexattrRequest>) -> OpResult {
    let session = context.session;
    let node = session.node(request.head().node_id.get())?;
    node.require_writable()?;
    let namespace = session.namespace();
    let fd = node.descriptor(&namespace)?.ok_or(Errno::OPNOTSUPP)?;
    let name = request.name();
    require_removable(namespace.xattr(), name, || xattr::size(fd.as_fd(), name))?;
    xattr::remove(fd.as_fd(), name)?;
    context.reply(&RemovexattrResponse {})
}

/// The list from the host is read whole, hidden names included, and filtered
/// here: a list the guest could take once the hidden names are gone must not be
/// refused because the list from the host was longer.
pub fn listxattr(
    context: &Context<'_>,
    request: Request<'_, ListxattrRequest>,
    buffers: Buffers,
) -> OpResult {
    let session = context.session;
    let node = session.node(request.head().node_id.get())?;
    let namespace = session.namespace();
    let fd = node.descriptor(&namespace)?.ok_or(Errno::OPNOTSUPP)?;
    let rules = namespace.xattr();
    let mut list = buffers.list.ok_or(Errno::NOMEM)?;
    let listed = xattr::list_into(fd.as_fd(), &mut list)?;
    // A name whose read is denied is simply not there, in the sizes as well as
    // in the stream: a size that counted hidden names would leak how many.
    let names = || {
        list[..listed]
            .split(|byte| *byte == 0)
            .filter(|name| !name.is_empty() && rules.readable(name))
    };

    // The guest size counts a NUL per name; the wire stream has a 4-byte
    // header per name instead, so the two routinely differ.
    let mut guest_size: u32 = 0;
    let mut stream_len = 0usize;
    for name in names() {
        let len = u32::try_from(name.len()).map_err(|_| Errno::OVERFLOW)?;
        guest_size = guest_size
            .checked_add(len)
            .and_then(|size| size.checked_add(1))
            .ok_or(Errno::OVERFLOW)?;
        stream_len += size_of::<XattrNameHeader>() + name.len();
    }

    let budget = request.body().size.get();
    if budget == 0 {
        return context.reply(&ListxattrResponse {
            size: U32::new(guest_size),
            list_len: U32::ZERO,
        });
    }
    if guest_size > budget {
        return Err(Errno::RANGE);
    }
    let mut reply = buffers.reply.ok_or(Errno::NOMEM)?;
    let fixed = FrameWriter::response_len::<ListxattrResponse>(0);
    let written = {
        let mut stream = XattrNameWriter::new(
            reply
                .get_mut(fixed..fixed + stream_len)
                .ok_or(Errno::RANGE)?,
        );
        for name in names() {
            let header =
                XattrNameHeader::new(u32::try_from(name.len()).map_err(|_| Errno::OVERFLOW)?);
            stream.push(&header, name).map_err(|_| Errno::OVERFLOW)?;
        }
        stream.written()
    };
    context.reply_in(
        reply,
        &ListxattrResponse {
            size: U32::new(guest_size),
            list_len: U32::new(u32::try_from(written).map_err(|_| Errno::OVERFLOW)?),
        },
        written,
    )
}

fn require_readable(rules: &XattrRules, name: &[u8]) -> Result<(), Errno> {
    if rules.readable(name) {
        Ok(())
    } else {
        Err(Errno::NODATA)
    }
}

fn require_writable(rules: &XattrRules, name: &[u8]) -> Result<(), Errno> {
    if rules.writable(name) {
        Ok(())
    } else {
        Err(Errno::PERM)
    }
}

/// An absent ACL has nothing to remove. Only these two names use a read to
/// distinguish that case from a refused mutation; other names keep their write
/// verdict even when absent or hidden.
fn require_removable(
    rules: &XattrRules,
    name: &[u8],
    read: impl FnOnce() -> Result<usize, Errno>,
) -> Result<(), Errno> {
    let verdict = require_writable(rules, name);
    if verdict.is_err()
        && matches!(
            name,
            b"system.posix_acl_access" | b"system.posix_acl_default"
        )
    {
        require_readable(rules, name)?;
        read()?;
    }
    verdict
}

fn flags_of(flags: u32) -> rustix::fs::XattrFlags {
    let mut host = rustix::fs::XattrFlags::empty();
    if flags & setxattr_flags::CREATE != 0 {
        host |= rustix::fs::XattrFlags::CREATE;
    }
    if flags & setxattr_flags::REPLACE != 0 {
        host |= rustix::fs::XattrFlags::REPLACE;
    }
    host
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{XattrSpec, XattrVerdict};

    #[test]
    fn the_two_guards_answer_the_errnos_the_design_pins() {
        let rules = XattrRules::build([
            XattrSpec::new("user.hidden.*").with_read(XattrVerdict::Deny),
            XattrSpec::new("security.*").with_write(XattrVerdict::Allow),
        ])
        .expect("valid rules");

        assert_eq!(
            require_readable(&rules, b"user.hidden.x"),
            Err(Errno::NODATA)
        );
        assert_eq!(require_readable(&rules, b"user.plain"), Ok(()));
        assert_eq!(require_writable(&rules, b"user.plain"), Ok(()));
        assert_eq!(require_writable(&rules, b"trusted.thing"), Err(Errno::PERM));
        assert_eq!(require_writable(&rules, b"security.selinux"), Ok(()));
        assert_eq!(
            require_writable(&rules, b"system.posix_acl_access"),
            Err(Errno::PERM)
        );
    }

    #[test]
    fn absent_acls_answer_nodata_and_present_acls_remain_refused() {
        let rules = XattrRules::build([XattrSpec::new("*").with_write(XattrVerdict::Allow)])
            .expect("valid rules");
        for name in [
            b"system.posix_acl_access".as_slice(),
            b"system.posix_acl_default",
        ] {
            assert_eq!(
                require_removable(&rules, name, || Err(Errno::NODATA)),
                Err(Errno::NODATA)
            );
            for size in [0, 4] {
                assert_eq!(
                    require_removable(&rules, name, || Ok(size)),
                    Err(Errno::PERM)
                );
            }
            assert_eq!(
                require_removable(&rules, name, || Err(Errno::ACCESS)),
                Err(Errno::ACCESS)
            );
        }
    }

    #[test]
    fn hidden_acls_answer_nodata_without_reading_the_host() {
        let rules =
            XattrRules::build([XattrSpec::new("system.posix_acl_*").with_read(XattrVerdict::Deny)])
                .expect("valid rules");
        for name in [
            b"system.posix_acl_access".as_slice(),
            b"system.posix_acl_default",
        ] {
            assert_eq!(
                require_removable(&rules, name, || panic!("a hidden ACL must not be read")),
                Err(Errno::NODATA)
            );
        }
    }

    #[test]
    fn other_names_keep_the_write_verdict_without_a_presence_read() {
        let rules = XattrRules::default();
        for (name, expected) in [
            (b"user.plain".as_slice(), Ok(())),
            (b"trusted.absent", Err(Errno::PERM)),
            (b"system.posix_acl_other", Err(Errno::PERM)),
        ] {
            assert_eq!(
                require_removable(&rules, name, || panic!("only ACL names probe presence")),
                expected
            );
        }
    }

    #[test]
    fn create_and_replace_map_one_for_one() {
        assert_eq!(flags_of(0), rustix::fs::XattrFlags::empty());
        assert_eq!(
            flags_of(setxattr_flags::CREATE),
            rustix::fs::XattrFlags::CREATE
        );
        assert_eq!(
            flags_of(setxattr_flags::REPLACE),
            rustix::fs::XattrFlags::REPLACE
        );
    }
}
