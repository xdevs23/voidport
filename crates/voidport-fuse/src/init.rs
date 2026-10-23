//! The kernel delays every request until FUSE_INIT is answered
//! (`fuse_block_alloc` in `fs/fuse/dev.c`, Linux 7.3), so the exchange runs
//! before any dispatch thread exists.

use std::io;
use std::mem::offset_of;

use rustix::io::Errno;
use zerocopy::byteorder::native_endian::{U16, U32};
use zerocopy::{FromZeros as _, IntoBytes as _};

use crate::abi::{self, opcode};
use crate::device::Device;
use crate::flags::InitFlags;
use crate::request::Message;

/// [`InitFlags::ASYNC_READ`] is not asked for. With it the kernel sends the
/// reads that fill the page cache in the background, and the program waiting
/// for one waits on the lock of the page, which only a fatal signal ends. As a
/// result, the kernel never interrupts that read (`fuse_send_readpages` in
/// `fs/fuse/file.c` and `filemap_update_page` in `mm/filemap.c`, Linux 7.2).
/// Without it the program sends those reads itself, and a signal interrupts
/// them as it interrupts any other request.
const ASKED_ALWAYS: InitFlags = InitFlags::BIG_WRITES.union(InitFlags::MAX_PAGES);

/// The most pages one request may contain on kernels without the
/// `fs.fuse.max_pages_limit` setting, which fix it at this value
/// (`FUSE_MAX_MAX_PAGES` in `fs/fuse/fuse_i.h` before Linux 6.13).
const FIXED_MAX_PAGES: u16 = 256;

const MAX_PAGES_LIMIT: &str = "/proc/sys/fs/fuse/max_pages_limit";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Limits {
    max_pages: u16,
    max_write: u32,
}

#[derive(Debug, thiserror::Error)]
pub enum LimitError {
    #[error("fs.fuse.max_pages_limit is {0}, more than FUSE_INIT can announce")]
    MaxPages(u64),
    #[error("{max_pages} pages of {page_size} bytes are more than FUSE_INIT can announce")]
    MaxWrite { max_pages: u16, page_size: usize },
}

impl Limits {
    pub(crate) fn of_host() -> Result<Self, LimitError> {
        let max_pages = match std::fs::read_to_string(MAX_PAGES_LIMIT) {
            Ok(limit) => match limit.trim().parse::<u64>() {
                Ok(limit) => u16::try_from(limit).map_err(|_| LimitError::MaxPages(limit))?,
                Err(error) => {
                    tracing::warn!(%error, limit = limit.trim(), "fs.fuse.max_pages_limit is not a number; announcing {FIXED_MAX_PAGES} pages");
                    FIXED_MAX_PAGES
                }
            },
            Err(error) if error.kind() == io::ErrorKind::NotFound => FIXED_MAX_PAGES,
            Err(error) => {
                tracing::warn!(%error, "fs.fuse.max_pages_limit could not be read; announcing {FIXED_MAX_PAGES} pages");
                FIXED_MAX_PAGES
            }
        };
        Self::new(max_pages, rustix::param::page_size())
    }

    fn new(max_pages: u16, page_size: usize) -> Result<Self, LimitError> {
        let max_write = u32::try_from(page_size)
            .ok()
            .and_then(|page_size| u32::from(max_pages).checked_mul(page_size))
            .ok_or(LimitError::MaxWrite {
                max_pages,
                page_size,
            })?;
        Ok(Self {
            max_pages,
            max_write,
        })
    }
}

#[derive(Debug)]
pub struct Init {
    offered: InitFlags,
    asked: InitFlags,
}

#[derive(Debug, thiserror::Error)]
#[error("the kernel does not offer {0:?}")]
pub struct MissingCapabilities(pub InitFlags);

impl Init {
    /// # Errors
    ///
    /// The capabilities the kernel did not offer, in which case none of
    /// `capabilities` is asked for.
    pub fn require(&mut self, capabilities: InitFlags) -> Result<(), MissingCapabilities> {
        let missing = capabilities.difference(self.offered);
        if !missing.is_empty() {
            return Err(MissingCapabilities(missing));
        }
        self.asked |= capabilities;
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum InitError {
    #[error("the first request of the connection could not be read")]
    Read(#[source] Errno),
    #[error("the first request of the connection does not decode")]
    Malformed,
    #[error("the kernel sent opcode {0} before FUSE_INIT")]
    NotInit(u32),
    #[error(
        "the kernel speaks FUSE {major}.{minor}; this crate speaks 7.{} and later",
        abi::OLDEST_MINOR
    )]
    Version { major: u32, minor: u32 },
    #[error(transparent)]
    Refused(#[from] MissingCapabilities),
    #[error("the answer to FUSE_INIT could not be written")]
    Reply(#[source] Errno),
}

/// The size of a buffer that takes every request a connection may send
/// when it writes at most `max_write` bytes at once: the kernel rejects
/// every read into a smaller one (`fuse_dev_do_read` in `fs/fuse/dev.c`,
/// Linux 7.3).
pub(crate) fn read_size(max_write: u32) -> usize {
    let write = size_of::<abi::InHeader>() + size_of::<abi::WriteIn>() + max_write as usize;
    write.max(abi::MIN_READ_BUFFER)
}

pub(crate) fn exchange<F>(
    device: &Device,
    limits: Limits,
    negotiate: impl FnOnce(&mut Init) -> Result<F, MissingCapabilities>,
) -> Result<(F, u32), InitError> {
    let mut buffer = vec![0; abi::MIN_READ_BUFFER];
    let message = loop {
        let length = device.read(&mut buffer).map_err(InitError::Read)?;
        let message = Message::parse(&buffer[..length]).ok_or(InitError::Malformed)?;
        if message.opcode() != opcode::INIT {
            answer(device, message.unique(), Errno::IO);
            return Err(InitError::NotInit(message.opcode()));
        }
        let kernel = init_in(message.arguments)?;
        // A kernel of a newer major version waits for the version this side
        // speaks and then sends FUSE_INIT again in it.
        if kernel.major.get() > abi::MAJOR {
            let version = init_out(&kernel, InitFlags::empty(), None);
            write(
                device,
                message.unique(),
                &version.as_bytes()[..abi::COMPAT_INIT_OUT_SIZE],
            )?;
            continue;
        }
        break (message.unique(), kernel);
    };
    let (unique, kernel) = message;
    let (major, minor) = (kernel.major.get(), kernel.minor.get());
    if major < abi::MAJOR || minor < abi::OLDEST_MINOR {
        answer(device, unique, Errno::PROTO);
        return Err(InitError::Version { major, minor });
    }

    let offered = offered(&kernel);
    let mut init = Init {
        offered,
        asked: ASKED_ALWAYS.intersection(offered),
    };
    let filesystem = match negotiate(&mut init) {
        Ok(filesystem) => filesystem,
        Err(missing) => {
            answer(device, unique, Errno::IO);
            return Err(InitError::Refused(missing));
        }
    };
    let flags = init.asked | offered.intersection(InitFlags::INIT_EXT);
    write(
        device,
        unique,
        init_out(&kernel, flags, Some(limits)).as_bytes(),
    )?;
    Ok((filesystem, limits.max_write))
}

fn write(device: &Device, unique: u64, reply: &[u8]) -> Result<(), InitError> {
    device
        .reply_ok(unique, [reply, &[]])
        .map_err(InitError::Reply)
}

/// A failure to write the error ends the connection as well, so it is only
/// logged.
fn answer(device: &Device, unique: u64, error: Errno) {
    if let Err(failure) = device.reply_error(unique, error) {
        tracing::debug!(%failure, "the refusal of FUSE_INIT could not be written");
    }
}

/// The arguments of FUSE_INIT. Kernels before 7.36 send only the first four
/// fields, and every field they do not send is zero.
fn init_in(arguments: &[u8]) -> Result<abi::InitIn, InitError> {
    if arguments.len() < offset_of!(abi::InitIn, flags2) {
        return Err(InitError::Malformed);
    }
    let mut init = abi::InitIn::new_zeroed();
    let length = arguments.len().min(size_of::<abi::InitIn>());
    init.as_mut_bytes()[..length].copy_from_slice(&arguments[..length]);
    Ok(init)
}

fn offered(kernel: &abi::InitIn) -> InitFlags {
    let low = kernel.flags.get();
    let extended = InitFlags::from_words(low, 0).contains(InitFlags::INIT_EXT);
    InitFlags::from_words(low, if extended { kernel.flags2.get() } else { 0 })
}

/// The kernel uses its default for every field left at zero, such as how many
/// requests may wait in the background and the time granularity
/// (`process_init_limits` and `process_init_reply` in `fs/fuse/inode.c`,
/// Linux 7.3).
fn init_out(kernel: &abi::InitIn, flags: InitFlags, limits: Option<Limits>) -> abi::InitOut {
    let (low, high) = flags.words();
    let mut reply = abi::InitOut::new_zeroed();
    reply.major = U32::new(abi::MAJOR);
    reply.minor = U32::new(abi::MINOR);
    reply.max_readahead = kernel.max_readahead;
    reply.flags = U32::new(low);
    reply.flags2 = U32::new(high);
    if let Some(limits) = limits {
        reply.max_write = U32::new(limits.max_write);
        reply.max_pages = U16::new(limits.max_pages);
    }
    reply
}

#[cfg(test)]
mod tests {
    use zerocopy::FromBytes as _;

    use super::*;
    use crate::device::tests::{answer as reply_of, kernel};
    use crate::request::tests::request;

    const KERNEL_OFFERS: InitFlags = InitFlags::ASYNC_READ
        .union(InitFlags::POSIX_LOCKS)
        .union(InitFlags::BIG_WRITES)
        .union(InitFlags::DO_READDIRPLUS)
        .union(InitFlags::MAX_PAGES)
        .union(InitFlags::INIT_EXT)
        .union(InitFlags::HAS_RESEND);

    const LIMITS: Limits = Limits {
        max_pages: 256,
        max_write: 1 << 20,
    };

    fn init_request(major: u32, minor: u32, offered: InitFlags) -> Vec<u8> {
        let (low, high) = offered.words();
        let mut init = abi::InitIn::new_zeroed();
        init.major = U32::new(major);
        init.minor = U32::new(minor);
        init.max_readahead = U32::new(131_072);
        init.flags = U32::new(low);
        init.flags2 = U32::new(high);
        request(opcode::INIT, 0, 2, &[init.as_bytes()])
    }

    fn reply_flags(reply: &abi::InitOut) -> InitFlags {
        InitFlags::from_words(reply.flags.get(), reply.flags2.get())
    }

    #[test]
    fn the_answer_asks_for_what_the_filesystem_wants_and_announces_the_limits() {
        let (device, kernel) = kernel(&[init_request(7, 46, KERNEL_OFFERS)]);
        let ((), max_write) = exchange(&device, LIMITS, |init| {
            init.require(InitFlags::POSIX_LOCKS | InitFlags::DO_READDIRPLUS)?;
            init.require(InitFlags::HAS_RESEND)
        })
        .expect("the exchange succeeds");

        let (header, payload) = reply_of(&kernel);
        assert_eq!((header.error.get(), header.unique.get()), (0, 2));
        let reply = abi::InitOut::read_from_bytes(&payload).expect("a whole answer");
        assert_eq!((reply.major.get(), reply.minor.get()), (7, abi::MINOR));
        assert_eq!(reply.max_readahead.get(), 131_072);
        assert!(
            reply_flags(&reply).contains(
                InitFlags::POSIX_LOCKS | InitFlags::DO_READDIRPLUS | InitFlags::HAS_RESEND
            ),
            "what the filesystem asked for was asked for"
        );
        assert_eq!(
            (reply.max_pages.get(), reply.max_write.get()),
            (256, 1 << 20)
        );
        assert_eq!(max_write, 1 << 20);
        assert_eq!(reply.max_background.get(), 0, "the kernel uses its default");
    }

    #[test]
    fn a_capability_the_kernel_does_not_offer_fails_the_exchange() {
        let (device, kernel) = kernel(&[init_request(7, 46, KERNEL_OFFERS)]);
        let refused = exchange(&device, LIMITS, |init| {
            init.require(InitFlags::AUTO_INVAL_DATA | InitFlags::POSIX_LOCKS)
        });
        let Err(InitError::Refused(MissingCapabilities(missing))) = refused else {
            panic!("the exchange fails");
        };
        assert_eq!(
            missing,
            InitFlags::AUTO_INVAL_DATA,
            "only what is missing is named"
        );
        assert_eq!(reply_of(&kernel).0.error.get(), -Errno::IO.raw_os_error());
    }

    #[test]
    fn a_first_request_that_is_not_init_fails_the_exchange() {
        let (device, kernel) = kernel(&[request(opcode::LOOKUP, 1, 4, &[b"name\0"])]);
        let refused = exchange(&device, LIMITS, |_| Ok(()));
        assert!(matches!(refused, Err(InitError::NotInit(opcode::LOOKUP))));
        let (header, _) = reply_of(&kernel);
        assert_eq!(
            (header.error.get(), header.unique.get()),
            (-Errno::IO.raw_os_error(), 4)
        );
    }

    #[test]
    fn a_newer_major_version_is_answered_with_the_version_alone() {
        let (device, kernel) = kernel(&[
            init_request(8, 0, KERNEL_OFFERS),
            init_request(7, 46, KERNEL_OFFERS),
        ]);
        exchange(&device, LIMITS, |_| Ok(())).expect("the second exchange succeeds");
        let (_, version) = reply_of(&kernel);
        assert_eq!(version.len(), abi::COMPAT_INIT_OUT_SIZE);
        assert_eq!(&version[..4], 7_u32.to_ne_bytes());
        let (_, answer) = reply_of(&kernel);
        assert_eq!(answer.len(), size_of::<abi::InitOut>());
    }

    #[test]
    fn a_kernel_older_than_the_layouts_of_this_crate_is_refused() {
        let (device, kernel) = kernel(&[init_request(7, 22, KERNEL_OFFERS)]);
        let refused = exchange(&device, LIMITS, |_| Ok(()));
        assert!(matches!(
            refused,
            Err(InitError::Version {
                major: 7,
                minor: 22
            })
        ));
        assert_eq!(
            reply_of(&kernel).0.error.get(),
            -Errno::PROTO.raw_os_error()
        );
    }

    #[test]
    fn a_short_init_has_no_second_word_of_flags() {
        let mut short = init_request(7, 31, KERNEL_OFFERS.difference(InitFlags::INIT_EXT));
        let length = size_of::<abi::InHeader>() + offset_of!(abi::InitIn, flags2);
        short.truncate(length);
        let (header, _) = abi::InHeader::mut_from_prefix(&mut short).expect("a header");
        header.len = U32::new(u32::try_from(length).expect("small"));

        let (device, _kernel) = kernel(&[short]);
        exchange(&device, LIMITS, |init| {
            let missing = init
                .require(InitFlags::HAS_RESEND)
                .expect_err("the second word is not offered");
            assert_eq!(missing.0, InitFlags::HAS_RESEND);
            init.require(InitFlags::DO_READDIRPLUS)
        })
        .expect("the exchange succeeds");
    }

    #[test]
    fn the_flag_word_splits_into_its_two_halves() {
        let flags = InitFlags::ASYNC_READ | InitFlags::HAS_RESEND;
        assert_eq!(flags.words(), (1, 1 << 7));
        assert_eq!(InitFlags::from_words(1, 1 << 7), flags);
    }

    #[test]
    fn the_largest_write_is_the_pages_of_a_request() {
        assert_eq!(Limits::new(256, 4096).expect("fits"), LIMITS);
        assert!(matches!(
            Limits::new(u16::MAX, 1 << 20),
            Err(LimitError::MaxWrite { .. })
        ));
    }

    #[test]
    fn a_read_buffer_takes_the_largest_write_and_never_less_than_the_minimum() {
        assert_eq!(read_size(1 << 20), 80 + (1 << 20));
        assert_eq!(read_size(4096), abi::MIN_READ_BUFFER);
    }
}
