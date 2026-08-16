//! Extended-attribute operations: where the namespace's rules meet the host.
//!
//! **The order is pinned, and it is the design's:**
//!
//! 1. the share mode runs first — a write to a node inside a read-only share
//!    answers `EROFS` before any attribute policy is consulted at all;
//! 2. then the namespace's xattr rules ([`crate::rules::xattr`]), including the
//!    unconditional `system.posix_acl_*` write guard;
//! 3. and only then the host, whose own errno is passed back untouched — a
//!    `user.*` write on a FIFO answers the kernel's `EPERM` because the kernel
//!    permits `user.*` on regular files and directories only, which is a
//!    legitimate outcome, not a policy denial.
//!
//! A **denied read hides**: the name is absent from `listxattr` and `getxattr`
//! answers `ENODATA`, because a denial must not advertise what it denies. A
//! denied write answers `EPERM` with the host untouched.
//!
//! Sizes follow the Linux probe protocol — a request with `size == 0` reports
//! the size and returns no data — with one deliberate asymmetry for
//! `listxattr`: the size reported is the **guest-visible** one, the length of
//! the NUL-separated list the client rebuilds, not the length of this wire's
//! name stream.

use std::os::fd::AsFd as _;

use rustix::io::Errno;
use voidport_proto::message::Request;
use voidport_proto::ops::xattr::{
    GetxattrRequest, GetxattrResponse, ListxattrRequest, ListxattrResponse, RemovexattrRequest,
    RemovexattrResponse, SetxattrRequest, SetxattrResponse, XattrNameHeader, XattrNameWriter,
    setxattr_flags,
};
use zerocopy::byteorder::little_endian::U32;

use super::{Context, OpResult};
use crate::host::xattr;
use crate::rules::XattrRules;

/// Reads one attribute, or reports its size.
pub fn getxattr(context: &Context<'_>, request: Request<'_, GetxattrRequest>) -> OpResult {
    let session = context.session;
    let node = session.node(request.head().node_id.get())?;
    let namespace = session.namespace();
    let fd = node.descriptor(&namespace)?.ok_or(Errno::OPNOTSUPP)?;
    let name = request.name();
    // A denied read is indistinguishable from an attribute that is not there:
    // answering anything else would advertise the very name the rule hides.
    require_readable(namespace.xattr(), name)?;

    let value = xattr::get(fd.as_fd(), name)?;
    let size = u32::try_from(value.len()).map_err(|_| Errno::OVERFLOW)?;
    let budget = request.body().size.get();
    if budget == 0 {
        return context.reply(&GetxattrResponse {
            size: U32::new(size),
            value_len: U32::ZERO,
        });
    }
    if size > budget || value.len() > context.payload_budget::<GetxattrResponse>() {
        return Err(Errno::RANGE);
    }
    context.reply_with(
        &GetxattrResponse {
            size: U32::new(size),
            value_len: U32::new(size),
        },
        &value,
    )
}

/// Sets one attribute.
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

/// Removes one attribute.
///
/// Removal is a write: it takes the write verdict, not the read one, so a name
/// a guest may read is not thereby a name it may delete.
pub fn removexattr(context: &Context<'_>, request: Request<'_, RemovexattrRequest>) -> OpResult {
    let session = context.session;
    let node = session.node(request.head().node_id.get())?;
    node.require_writable()?;
    let namespace = session.namespace();
    let fd = node.descriptor(&namespace)?.ok_or(Errno::OPNOTSUPP)?;
    let name = request.name();
    require_writable(namespace.xattr(), name)?;
    xattr::remove(fd.as_fd(), name)?;
    context.reply(&RemovexattrResponse {})
}

/// Lists the attribute names, or reports the size of the list.
pub fn listxattr(context: &Context<'_>, request: Request<'_, ListxattrRequest>) -> OpResult {
    let session = context.session;
    let node = session.node(request.head().node_id.get())?;
    let namespace = session.namespace();
    let fd = node.descriptor(&namespace)?.ok_or(Errno::OPNOTSUPP)?;
    let rules = namespace.xattr();
    // A name whose read is denied is simply not there, in the sizes as well as
    // in the stream: a size that counted hidden names would leak how many.
    let names: Vec<Vec<u8>> = xattr::list(fd.as_fd())?
        .into_iter()
        .filter(|name| rules.readable(name))
        .collect();

    // The guest size counts a NUL per name; the wire stream carries a 4-byte
    // header per name instead, so the two routinely differ.
    let mut guest_size: u32 = 0;
    let mut stream_len = 0usize;
    for name in &names {
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
    if guest_size > budget || stream_len > context.payload_budget::<ListxattrResponse>() {
        return Err(Errno::RANGE);
    }

    let mut buffer = vec![0u8; stream_len];
    let mut stream = XattrNameWriter::new(&mut buffer);
    for name in &names {
        let header = XattrNameHeader::new(u32::try_from(name.len()).map_err(|_| Errno::OVERFLOW)?);
        stream.push(&header, name).map_err(|_| Errno::OVERFLOW)?;
    }
    let list = stream.finish().to_vec();
    context.reply_with(
        &ListxattrResponse {
            size: U32::new(guest_size),
            list_len: U32::new(u32::try_from(list.len()).map_err(|_| Errno::OVERFLOW)?),
        },
        &list,
    )
}

/// Checks that the namespace lets this attribute be read.
///
/// # Errors
///
/// Returns `ENODATA`, which is what a name that is not there answers: denial
/// must not advertise what it denies.
fn require_readable(rules: &XattrRules, name: &[u8]) -> Result<(), Errno> {
    if rules.readable(name) {
        Ok(())
    } else {
        Err(Errno::NODATA)
    }
}

/// Checks that the namespace lets this attribute be written.
///
/// # Errors
///
/// Returns `EPERM`, with the host untouched — including for every
/// `system.posix_acl_*` write, which the rules can never permit.
fn require_writable(rules: &XattrRules, name: &[u8]) -> Result<(), Errno> {
    if rules.writable(name) {
        Ok(())
    } else {
        Err(Errno::PERM)
    }
}

/// The host flags a `setxattr` request asks for.
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
        // The defaults: `user.*` writes land, everything else is refused.
        assert_eq!(require_writable(&rules, b"user.plain"), Ok(()));
        assert_eq!(require_writable(&rules, b"trusted.thing"), Err(Errno::PERM));
        // An explicit allow lets the attempt through to the host's own answer.
        assert_eq!(require_writable(&rules, b"security.selinux"), Ok(()));
        // And the ACL guard refuses regardless.
        assert_eq!(
            require_writable(&rules, b"system.posix_acl_access"),
            Err(Errno::PERM)
        );
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
